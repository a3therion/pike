use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pike_server::{
    config::TrafficInspectionConfig, dashboard_ws::DashboardBroadcaster, http::run_http_server,
    ingest::RequestBuffer, registry::ClientRegistry, request_log::RequestLogStore,
    router::VhostRouter, tunnel_metrics::TunnelMetricsStore,
};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn start_test_server() -> SocketAddr {
    start_test_server_custom(None, None, true, None).await
}

async fn start_test_server_with(control_plane_url: Option<String>, dev_mode: bool) -> SocketAddr {
    start_test_server_custom(control_plane_url, None, dev_mode, None).await
}

async fn start_test_server_custom(
    control_plane_url: Option<String>,
    local_api_keys: Option<Vec<String>>,
    dev_mode: bool,
    remembered_owner: Option<(&str, &str)>,
) -> SocketAddr {
    let router = Arc::new(VhostRouter::new());
    let registry = Arc::new(ClientRegistry::new());
    let broadcaster = Arc::new(DashboardBroadcaster::new());
    let ingest_buffer = Arc::new(RequestBuffer::new(
        "http://unused".to_string(),
        "token".to_string(),
    ));
    let request_log_store = Arc::new(RequestLogStore::new());
    let tunnel_metrics_store = Arc::new(TunnelMetricsStore::new());
    if let Some((tunnel_id, owner_user_id)) = remembered_owner {
        tunnel_metrics_store
            .remember_tunnel(tunnel_id, owner_user_id)
            .await;
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let _shutdown_tx = Box::leak(Box::new(shutdown_tx));

    let server_handle = tokio::spawn(run_http_server(
        addr,
        router,
        registry,
        broadcaster,
        ingest_buffer,
        request_log_store,
        tunnel_metrics_store,
        control_plane_url,
        local_api_keys,
        dev_mode,
        TrafficInspectionConfig::default(),
        "pike.life".to_string(),
        shutdown_rx,
    ));

    tokio::spawn(async move {
        match server_handle.await {
            Ok(Ok(())) => eprintln!("Server exited successfully"),
            Ok(Err(e)) => eprintln!("Server error: {e}"),
            Err(e) => eprintln!("Server task panicked: {e}"),
        }
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    addr
}

async fn create_sse_token(addr: SocketAddr, tunnel_id: &str, auth_token: &str) -> String {
    let resp = http_client()
        .post(format!("http://{addr}/api/v1/sse-token"))
        .header("Host", "pike.life")
        .header("Authorization", format!("Bearer {auth_token}"))
        .json(&serde_json::json!({ "tunnel_id": tunnel_id }))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    body["token"].as_str().unwrap_or_default().to_string()
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap()
}

fn local_user_id(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("local-{:x}", hasher.finalize())
}

#[tokio::test]
async fn health_on_platform_host_pike_life_returns_200() {
    let addr = start_test_server().await;
    let resp = http_client()
        .get(format!("http://{addr}/health"))
        .header("Host", "pike.life")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "healthy");
    assert_eq!(body["service"], "pike-server");
}

#[tokio::test]
async fn health_on_tunnel_subdomain_not_intercepted() {
    let addr = start_test_server().await;
    let resp = http_client()
        .get(format!("http://{addr}/health"))
        .header("Host", "test.pike.life")
        .send()
        .await
        .unwrap();

    // Tunnel subdomain bypasses platform health check.
    // No tunnel registered → proxy returns 307 redirect.
    assert_eq!(resp.status(), 307);
}

#[tokio::test]
async fn health_on_ip_address_returns_200() {
    let addr = start_test_server().await;
    let resp = http_client()
        .get(format!("http://{addr}/health"))
        .header("Host", "127.0.0.1")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "healthy");
}

#[tokio::test]
async fn health_on_localhost_returns_200() {
    let addr = start_test_server().await;
    let resp = http_client()
        .get(format!("http://{addr}/health"))
        .header("Host", "localhost")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "healthy");
}

#[tokio::test]
async fn health_on_host_with_port_returns_200() {
    let addr = start_test_server().await;
    let resp = http_client()
        .get(format!("http://{addr}/health"))
        .header("Host", "pike.life:8080")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "healthy");
}

#[tokio::test]
async fn cors_allows_app_pike_life_origin() {
    let addr = start_test_server().await;
    let resp = http_client()
        .request(
            reqwest::Method::OPTIONS,
            format!("http://{addr}/api/v1/tunnels/test-id/requests/stream"),
        )
        .header("Host", "pike.life")
        .header("Origin", "https://app.pike.life")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();

    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(acao, "https://app.pike.life");
}

#[tokio::test]
async fn cors_rejects_unknown_origin() {
    let addr = start_test_server().await;
    let resp = http_client()
        .request(
            reqwest::Method::OPTIONS,
            format!("http://{addr}/api/v1/tunnels/test-id/requests/stream"),
        )
        .header("Host", "pike.life")
        .header("Origin", "https://evil.com")
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await
        .unwrap();

    let acao = resp.headers().get("access-control-allow-origin");
    assert!(
        acao.is_none(),
        "expected no access-control-allow-origin header, got: {acao:?}"
    );
}

#[tokio::test]
async fn sse_stream_without_token_returns_401() {
    let addr = start_test_server().await;
    let resp = http_client()
        .get(format!(
            "http://{addr}/api/v1/tunnels/test-id/requests/stream"
        ))
        .header("Host", "pike.life")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn sse_stream_with_dev_token_returns_200() {
    let addr = start_test_server().await;
    let exchange_token = create_sse_token(addr, "test-id", "dev-jwt").await;

    let resp = http_client()
        .get(format!(
            "http://{addr}/api/v1/tunnels/test-id/requests/stream?token={exchange_token}"
        ))
        .header("Host", "pike.life")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        ct.contains("text/event-stream"),
        "expected SSE content-type, got: {ct}"
    );
}

#[tokio::test]
async fn sse_exchange_token_single_use() {
    let control_plane = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/validate"))
        .and(header("authorization", "Bearer valid-jwt"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "user_id": "user-1"
        })))
        .mount(&control_plane)
        .await;

    let addr = start_test_server_custom(
        Some(control_plane.uri()),
        None,
        false,
        Some(("test-id", "user-1")),
    )
    .await;
    let exchange_token = create_sse_token(addr, "test-id", "valid-jwt").await;

    let first = http_client()
        .get(format!(
            "http://{addr}/api/v1/tunnels/test-id/requests/stream?token={exchange_token}"
        ))
        .header("Host", "pike.life")
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 200);

    let second = http_client()
        .get(format!(
            "http://{addr}/api/v1/tunnels/test-id/requests/stream?token={exchange_token}"
        ))
        .header("Host", "pike.life")
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 401);
}

#[tokio::test]
async fn sse_exchange_token_without_post_fails() {
    let addr = start_test_server_with(Some("http://127.0.0.1:9".to_string()), false).await;
    let resp = http_client()
        .get(format!(
            "http://{addr}/api/v1/tunnels/test-id/requests/stream?token=random-token"
        ))
        .header("Host", "pike.life")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn platform_metrics_without_token_returns_401() {
    let tunnel_id = "00000000-0000-0000-0000-000000000001";
    let owner_user_id = local_user_id("local-key");
    let addr = start_test_server_custom(
        None,
        Some(vec!["local-key".to_string()]),
        false,
        Some((tunnel_id, &owner_user_id)),
    )
    .await;

    let resp = http_client()
        .get(format!("http://{addr}/api/v1/tunnels/{tunnel_id}/metrics"))
        .header("Host", "pike.life")
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 401);
}

#[tokio::test]
async fn platform_metrics_owner_with_local_api_key_returns_200() {
    let token = "local-key";
    let tunnel_id = "00000000-0000-0000-0000-000000000002";
    let owner_user_id = local_user_id(token);
    let addr = start_test_server_custom(
        None,
        Some(vec![token.to_string()]),
        false,
        Some((tunnel_id, &owner_user_id)),
    )
    .await;

    let resp = http_client()
        .get(format!("http://{addr}/api/v1/tunnels/{tunnel_id}/metrics"))
        .header("Host", "pike.life")
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn platform_metrics_non_owner_with_local_api_key_returns_404() {
    let owner_token = "owner-key";
    let other_token = "other-key";
    let tunnel_id = "00000000-0000-0000-0000-000000000003";
    let owner_user_id = local_user_id(owner_token);
    let addr = start_test_server_custom(
        None,
        Some(vec![owner_token.to_string(), other_token.to_string()]),
        false,
        Some((tunnel_id, &owner_user_id)),
    )
    .await;

    let resp = http_client()
        .get(format!("http://{addr}/api/v1/tunnels/{tunnel_id}/metrics"))
        .header("Host", "pike.life")
        .header("Authorization", format!("Bearer {other_token}"))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}
