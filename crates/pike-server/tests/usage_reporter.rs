use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use pike_core::types::TunnelId;
use pike_server::connection::{ClientConnection, ConnectionState, ValidatedUser};
use pike_server::registry::ClientRegistry;
use pike_server::tunnel_metrics::TunnelMetricsStore;
use pike_server::usage_reporter::UsageReporter;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

fn build_registry_with_validated_tunnel(
    user_id: &str,
    subdomain: &str,
) -> (Arc<ClientRegistry>, TunnelId) {
    let registry = Arc::new(ClientRegistry::new());

    let conn_id = uuid::Uuid::new_v4();
    let mut client = ClientConnection::new(conn_id, None);
    client
        .transition_to(ConnectionState::Handshaking)
        .expect("transition to handshaking");
    client
        .authenticate("pk_test_key_1234", true)
        .expect("authenticate in dev mode");
    client.set_validated_user(ValidatedUser {
        user_id: user_id.to_string(),
        email: "test@example.test".to_string(),
        plan: "pro".to_string(),
        plan_expires_at: None,
    });

    registry.register_client(client).ok();

    let tunnel_id = TunnelId::new();
    registry
        .register_tunnel(conn_id, subdomain.to_string(), tunnel_id)
        .expect("register tunnel");

    (registry, tunnel_id)
}

fn build_reporter(
    workers_api_url: String,
    server_token: String,
    tunnel_metrics_store: Arc<TunnelMetricsStore>,
    registry: Arc<ClientRegistry>,
) -> Arc<UsageReporter> {
    Arc::new(UsageReporter::new(
        workers_api_url,
        server_token,
        tunnel_metrics_store,
        registry,
    ))
}

async fn record_requests(store: &TunnelMetricsStore, tunnel_id: &TunnelId, count: u64) {
    for _ in 0..count {
        store.record(&tunnel_id.to_string(), 200, 10, 3, 7).await;
    }
}

fn extract_single_report(req: &Request) -> serde_json::Value {
    let json: serde_json::Value =
        serde_json::from_slice(&req.body).expect("request body should be JSON");
    let reports = json
        .get("reports")
        .and_then(|v| v.as_array())
        .expect("reports should be an array");
    assert_eq!(reports.len(), 1, "expected 1 report, got: {json}");
    reports[0].clone()
}

async fn wait_for_request_count(server: &MockServer, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let requests = server.received_requests().await.expect("received requests");
        if requests.len() >= expected {
            return;
        }

        assert!(
            Instant::now() < deadline,
            "timed out waiting for {expected} requests, saw {}",
            requests.len()
        );

        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn delta_computation_reports_correct_count() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/usage/internal/report"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let (registry, tunnel_id) = build_registry_with_validated_tunnel("u1", "t1.pike.life");
    let metrics = Arc::new(TunnelMetricsStore::new());
    record_requests(&metrics, &tunnel_id, 10).await;

    let reporter = build_reporter(
        mock_server.uri(),
        "test-token".to_string(),
        metrics,
        registry,
    );
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    reporter.spawn_flush_loop(shutdown_rx);
    wait_for_request_count(&mock_server, 1).await;

    let requests = mock_server
        .received_requests()
        .await
        .expect("received requests");
    assert_eq!(requests.len(), 1, "expected 1 POST request");

    let report = extract_single_report(&requests[0]);
    assert_eq!(report["tunnel_id"], tunnel_id.to_string());
    assert_eq!(report["user_id"], "u1");
    assert_eq!(report["request_count"], 10);
}

#[tokio::test]
async fn second_flush_reports_delta_not_cumulative() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/usage/internal/report"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let (registry, tunnel_id) = build_registry_with_validated_tunnel("u1", "t2.pike.life");
    let metrics = Arc::new(TunnelMetricsStore::new());

    record_requests(&metrics, &tunnel_id, 10).await;
    let reporter = build_reporter(
        mock_server.uri(),
        "test-token".to_string(),
        metrics.clone(),
        registry,
    );

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    reporter.spawn_flush_loop(shutdown_rx);
    wait_for_request_count(&mock_server, 1).await;

    record_requests(&metrics, &tunnel_id, 5).await;
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    reporter.spawn_flush_loop(shutdown_rx);
    wait_for_request_count(&mock_server, 2).await;

    let requests = mock_server
        .received_requests()
        .await
        .expect("received requests");
    assert_eq!(requests.len(), 2, "expected 2 POST requests");

    let report_1 = extract_single_report(&requests[0]);
    assert_eq!(report_1["request_count"], 10);

    let report_2 = extract_single_report(&requests[1]);
    assert_eq!(
        report_2["request_count"], 5,
        "expected delta of 5; got request_count={} (req1={}, req2={})",
        report_2["request_count"], report_1["request_count"], report_2["request_count"]
    );
}

#[derive(Debug)]
struct FailThenSucceed {
    calls: AtomicUsize,
}

impl FailThenSucceed {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }
}

impl Respond for FailThenSucceed {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let idx = self.calls.fetch_add(1, Ordering::SeqCst);
        if idx == 0 {
            ResponseTemplate::new(500)
        } else {
            ResponseTemplate::new(200)
        }
    }
}

#[tokio::test]
async fn failed_post_retains_deltas_for_next_flush() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/usage/internal/report"))
        .respond_with(FailThenSucceed::new())
        .mount(&mock_server)
        .await;

    let (registry, tunnel_id) = build_registry_with_validated_tunnel("u1", "t3.pike.life");
    let metrics = Arc::new(TunnelMetricsStore::new());
    let reporter = build_reporter(
        mock_server.uri(),
        "test-token".to_string(),
        metrics.clone(),
        registry,
    );

    record_requests(&metrics, &tunnel_id, 10).await;
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    reporter.spawn_flush_loop(shutdown_rx);
    wait_for_request_count(&mock_server, 1).await;

    record_requests(&metrics, &tunnel_id, 5).await;
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    reporter.spawn_flush_loop(shutdown_rx);
    wait_for_request_count(&mock_server, 2).await;

    let requests = mock_server
        .received_requests()
        .await
        .expect("received requests");
    assert_eq!(requests.len(), 2, "expected 2 POST requests");

    let report_2 = extract_single_report(&requests[1]);
    assert_eq!(report_2["request_count"], 15);
}

#[tokio::test]
async fn empty_delta_produces_no_http_call() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/usage/internal/report"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let (registry, _tunnel_id) = build_registry_with_validated_tunnel("u1", "t4.pike.life");
    let metrics = Arc::new(TunnelMetricsStore::new());
    let reporter = build_reporter(
        mock_server.uri(),
        "test-token".to_string(),
        metrics,
        registry,
    );

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    reporter.spawn_flush_loop(shutdown_rx);
    tokio::time::sleep(Duration::from_millis(50)).await;

    let requests = mock_server
        .received_requests()
        .await
        .expect("received requests");
    assert!(requests.is_empty(), "expected 0 POST requests");
}

#[tokio::test]
async fn payload_format_matches_workers_api_contract() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/usage/internal/report"))
        .and(header("Authorization", "Bearer test-token"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock_server)
        .await;

    let (registry, tunnel_id) = build_registry_with_validated_tunnel("u123", "t5.pike.life");
    let metrics = Arc::new(TunnelMetricsStore::new());
    record_requests(&metrics, &tunnel_id, 2).await;

    let reporter = build_reporter(
        mock_server.uri(),
        "test-token".to_string(),
        metrics,
        registry,
    );
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    reporter.spawn_flush_loop(shutdown_rx);
    wait_for_request_count(&mock_server, 1).await;

    let requests = mock_server
        .received_requests()
        .await
        .expect("received requests");
    assert_eq!(requests.len(), 1, "expected 1 POST request");

    let report = extract_single_report(&requests[0]);
    assert_eq!(report["tunnel_id"], tunnel_id.to_string());
    assert_eq!(report["user_id"], "u123");
    assert!(
        report
            .get("bytes_in")
            .and_then(serde_json::Value::as_u64)
            .is_some(),
        "bytes_in should be a u64"
    );
    assert!(
        report
            .get("bytes_out")
            .and_then(serde_json::Value::as_u64)
            .is_some(),
        "bytes_out should be a u64"
    );
    assert_eq!(report["request_count"], 2);
    assert!(
        report
            .get("timestamp")
            .and_then(serde_json::Value::as_u64)
            .is_some(),
        "timestamp should be a u64"
    );

    let auth = requests[0]
        .headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .expect("authorization header present");
    assert_eq!(auth, "Bearer test-token");
}
