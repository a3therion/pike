use pike_server::{usage_journal::UsageJournal, usage_reporter::UsageReporter};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
const OWNER: &str = "12345678-1234-1234-1234-123456789abc";
const TUNNEL: &str = "87654321-1234-1234-1234-123456789abc";
fn reports(request: &Request) -> Vec<Value> {
    serde_json::from_slice::<Value>(&request.body).unwrap()["reports"]
        .as_array()
        .unwrap()
        .clone()
}
fn total(request: &Request, field: &str) -> u64 {
    reports(request)
        .iter()
        .map(|report| report[field].as_u64().unwrap())
        .sum()
}
#[derive(Clone)]
struct Ack;
impl Respond for Ack {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({"processed":reports(request).len()}))
    }
}
fn setup(server: &MockServer) -> (Arc<UsageJournal>, Arc<UsageReporter>) {
    let journal = Arc::new(UsageJournal::memory(&server.uri()).unwrap());
    let reporter = Arc::new(UsageReporter::new(
        server.uri(),
        "relay-secret".into(),
        journal.clone(),
    ));
    (journal, reporter)
}
async fn record(journal: &UsageJournal, n: usize) {
    for _ in 0..n {
        journal
            .record(TUNNEL.into(), OWNER.into(), 3, 7)
            .await
            .unwrap();
    }
}
async fn ack(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/v1/usage/internal/report"))
        .and(header("Authorization", "Bearer relay-secret"))
        .respond_with(Ack)
        .mount(server)
        .await;
}
#[tokio::test]
async fn seconds_canonical_ids_and_exact_committed_deltas_match_worker_contract() {
    let server = MockServer::start().await;
    ack(&server).await;
    let (journal, reporter) = setup(&server);
    record(&journal, 10).await;
    reporter.flush().await;
    record(&journal, 5).await;
    reporter.flush().await;
    reporter.flush().await;
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let first = &reports(&requests[0])[0];
    let second = &reports(&requests[1])[0];
    assert_eq!(first["tunnel_id"], TUNNEL);
    assert_eq!(first["user_id"], OWNER);
    assert_eq!(total(&requests[0], "request_count"), 10);
    assert_eq!(total(&requests[0], "bytes_in"), 30);
    assert_eq!(total(&requests[0], "bytes_out"), 70);
    assert_eq!(total(&requests[1], "request_count"), 5);
    assert_ne!(first["report_id"], second["report_id"]);
    assert!(uuid::Uuid::parse_str(first["report_id"].as_str().unwrap()).is_ok());
    assert!(
        first["timestamp"]
            .as_u64()
            .unwrap()
            .abs_diff(chrono::Utc::now().timestamp().unsigned_abs())
            < 120
    );
}
struct Ambiguous {
    calls: AtomicUsize,
    status: u16,
    body: Option<String>,
}
impl Respond for Ambiguous {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            let response = ResponseTemplate::new(self.status);
            return self
                .body
                .as_ref()
                .map_or(response.clone(), |body| response.set_body_string(body));
        }
        Ack.respond(request)
    }
}
#[tokio::test]
async fn malformed_short_or_oversized_ack_retries_identical_frozen_batch() {
    for (status, body) in [
        (500, None),
        (200, None),
        (200, Some("{\"processed\":0}".into())),
        (200, Some("x".repeat(2048))),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(Ambiguous {
                calls: AtomicUsize::new(0),
                status,
                body,
            })
            .mount(&server)
            .await;
        let (journal, reporter) = setup(&server);
        record(&journal, 10).await;
        reporter.flush().await;
        record(&journal, 5).await;
        reporter.flush().await;
        let requests = server.received_requests().await.unwrap();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests[0].body, requests[1].body);
        assert_eq!(total(&requests[2], "request_count"), 5);
    }
}
#[tokio::test]
async fn concurrent_flushes_do_not_double_report() {
    let server = MockServer::start().await;
    ack(&server).await;
    let (journal, reporter) = setup(&server);
    record(&journal, 6).await;
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let reporter = reporter.clone();
        tasks.push(tokio::spawn(async move {
            reporter.flush().await;
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
#[tokio::test]
async fn chunks_large_flushes_to_worker_batch_limit() {
    let server = MockServer::start().await;
    ack(&server).await;
    let (journal, reporter) = setup(&server);
    for _ in 0..501 {
        journal
            .record(uuid::Uuid::new_v4().to_string(), OWNER.into(), 1, 2)
            .await
            .unwrap();
    }
    reporter.flush().await;
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(reports(&requests[0]).len(), 500);
    assert_eq!(reports(&requests[1]).len(), 1);
}
#[tokio::test]
async fn empty_journal_does_not_invent_reports() {
    let server = MockServer::start().await;
    let (_, reporter) = setup(&server);
    reporter.flush().await;
    assert!(server.received_requests().await.unwrap().is_empty());
}
