use super::*;
use std::collections::HashMap;
use std::sync::Mutex as SyncMutex;
use wiremock::{
    matchers::{header, method, path},
    Mock, MockServer, ResponseTemplate,
};

struct Ledger {
    bytes: u64,
    requests: u64,
    chunk: u64,
    ttl_ms: i64,
    grants: HashMap<String, Grant>,
    lose_reserve_ack: bool,
    lose_release_ack: bool,
    offline: bool,
}

impl Ledger {
    fn reply(&mut self, request: &wiremock::Request, reserve: bool) -> ResponseTemplate {
        let now = chrono::Utc::now().timestamp_millis();
        if self.offline {
            return ResponseTemplate::new(503)
                .set_body_json(serde_json::json!({"error":"offline"}));
        }
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
        let id = body["id"].as_str().unwrap();
        if reserve {
            let request: Reservation = serde_json::from_value(body.clone()).unwrap();
            if !self.grants.contains_key(id) {
                if self.bytes < request.minimum_bytes || self.requests < request.minimum_requests {
                    return ResponseTemplate::new(429).set_body_json(serde_json::json!({
                        "quota_protocol":1,"server_time_ms":now,"retry_at":now+60_000,"error":"quota exhausted"}));
                }
                let bytes = self.bytes.min(self.chunk.max(request.minimum_bytes));
                let requests = if request.minimum_requests > 0 {
                    self.requests.min(16)
                } else {
                    0
                };
                self.bytes -= bytes;
                self.requests -= requests;
                self.grants.insert(
                    id.into(),
                    Grant {
                        request,
                        bytes,
                        requests,
                        expires_at: now + self.ttl_ms,
                        month_start: chrono::Utc::now()
                            .format("%Y-%m-01T00:00:00.000Z")
                            .to_string(),
                        day_start: chrono::Utc::now()
                            .format("%Y-%m-%dT00:00:00.000Z")
                            .to_string(),
                        closed_at: None,
                        unused_bytes: None,
                        unused_requests: None,
                    },
                );
                if std::mem::take(&mut self.lose_reserve_ack) {
                    return ResponseTemplate::new(503).set_body_json(
                        serde_json::json!({"error":"lost reserve acknowledgement"}),
                    );
                }
            }
        } else {
            let grant = self.grants.get_mut(id).unwrap();
            let bytes = body["unused_bytes"].as_u64().unwrap();
            let requests = body["unused_requests"].as_u64().unwrap();
            if grant.closed_at.is_none() {
                assert!(bytes <= grant.bytes && requests <= grant.requests);
                self.bytes += bytes;
                self.requests += requests;
                grant.closed_at = Some(now);
                grant.unused_bytes = Some(bytes);
                grant.unused_requests = Some(requests);
            } else {
                assert_eq!(grant.unused_bytes, Some(bytes));
                assert_eq!(grant.unused_requests, Some(requests));
            }
            if std::mem::take(&mut self.lose_release_ack) {
                return ResponseTemplate::new(503)
                    .set_body_json(serde_json::json!({"error":"lost release acknowledgement"}));
            }
        }
        ResponseTemplate::new(200).set_body_json(
            serde_json::json!({"quota_protocol":1,"server_time_ms":now,"grant":self.grants[id]}),
        )
    }
}

struct Fixture {
    server: MockServer,
    ledger: Arc<SyncMutex<Ledger>>,
    journal: Arc<UsageJournal>,
    manager: Arc<QuotaManager>,
    context: QuotaContext,
    directory: std::path::PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
impl Fixture {
    async fn new(bytes: u64, requests: u64) -> Self {
        let server = MockServer::start().await;
        let ledger = Arc::new(SyncMutex::new(Ledger {
            bytes,
            requests,
            chunk: CREDIT_BYTES,
            ttl_ms: 60_000,
            grants: HashMap::new(),
            lose_reserve_ack: false,
            lose_release_ack: false,
            offline: false,
        }));
        for (action, reserve) in [("reserve", true), ("release", false)] {
            let state = ledger.clone();
            Mock::given(method("POST"))
                .and(path(format!("/api/v1/quotas/internal/{action}")))
                .and(header("authorization", "Bearer test-server"))
                .respond_with(move |request: &wiremock::Request| {
                    state.lock().unwrap().reply(request, reserve)
                })
                .mount(&server)
                .await;
        }
        let directory = std::env::temp_dir().join(format!("pike-quota-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let journal =
            Arc::new(UsageJournal::open(&directory.join("usage.sqlite"), &server.uri()).unwrap());
        let manager = Arc::new(
            QuotaManager::new(journal.clone(), server.uri(), "test-server".into())
                .await
                .unwrap(),
        );
        let context = QuotaContext {
            user_id: uuid::Uuid::new_v4().to_string(),
            tunnel_id: uuid::Uuid::new_v4().to_string(),
            lease_id: uuid::Uuid::new_v4().to_string(),
        };
        Self {
            server,
            ledger,
            journal,
            manager,
            context,
            directory,
        }
    }
    async fn observe(&self, incoming: u64, outgoing: u64, requests: u64) -> Result<()> {
        self.manager
            .observe(&self.context, incoming, outgoing, requests)
            .await
    }
    fn connection(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.directory.join("usage.sqlite")).unwrap()
    }
}

#[tokio::test]
async fn exact_credit_exhaustion_rejects_even_empty_new_admissions() {
    let fixture = Fixture::new(19, 2).await;
    fixture.observe(0, 0, 1).await.unwrap();
    fixture.observe(7, 12, 0).await.unwrap();
    let error = fixture.observe(0, 0, 1).await.unwrap_err();
    assert!(error.downcast_ref::<QuotaExceeded>().is_some());
    assert_eq!(error_response(&error).status(), 429);
    let rows = fixture.journal.batch().await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].request_count, 1);
    assert_eq!((rows[0].bytes_in, rows[0].bytes_out), (7, 12));
    assert!(rows[0].quota_accounted);
}

#[tokio::test]
async fn concurrent_admissions_share_credit_and_daily_exhaustion_keeps_existing_byte_flow() {
    let fixture = Fixture::new(100, 3).await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let manager = fixture.manager.clone();
        let context = fixture.context.clone();
        tasks.spawn(async move { manager.observe(&context, 0, 0, 1).await });
    }
    let mut accepted = 0;
    while let Some(result) = tasks.join_next().await {
        if result.unwrap().is_ok() {
            accepted += 1;
        }
    }
    assert_eq!(accepted, 3);
    fixture.observe(11, 13, 0).await.unwrap();
    let rows = fixture.journal.batch().await.unwrap();
    assert_eq!(rows[0].request_count, 3);
    assert_eq!(rows[0].bytes_in + rows[0].bytes_out, 24);
}

#[tokio::test]
async fn ambiguous_reservation_retries_same_durable_id_without_replenishing_credit() {
    let fixture = Fixture::new(100, 2).await;
    fixture.ledger.lock().unwrap().lose_reserve_ack = true;
    assert!(fixture.observe(7, 0, 1).await.is_err());
    assert!(fixture.journal.batch().await.unwrap().is_empty());
    fixture.observe(7, 0, 1).await.unwrap();
    assert_eq!(fixture.ledger.lock().unwrap().grants.len(), 1);
    assert_eq!(fixture.journal.batch().await.unwrap()[0].bytes_in, 7);
}

#[tokio::test]
async fn ambiguous_refund_retries_immutable_seal_without_double_return() {
    let fixture = Fixture::new(100, 2).await;
    fixture.ledger.lock().unwrap().chunk = 10;
    fixture.observe(8, 0, 1).await.unwrap();
    fixture.ledger.lock().unwrap().lose_release_ack = true;
    assert!(fixture.observe(5, 0, 0).await.is_err());
    assert!(matches!(
        fixture
            .journal
            .quota_state(fixture.context.user_id.clone())
            .await
            .unwrap(),
        Some(State::Sealed { bytes: 2, .. })
    ));
    fixture.observe(5, 0, 0).await.unwrap();
    fixture.manager.maintain(true).await.unwrap();
    let ledger = fixture.ledger.lock().unwrap();
    assert_eq!((ledger.bytes, ledger.requests), (87, 1));
    assert_eq!(ledger.grants.len(), 2);
}

#[tokio::test]
async fn restart_returns_only_persisted_unused_credit_and_preserves_relay_identity() {
    let fixture = Fixture::new(100, 2).await;
    fixture.observe(40, 0, 1).await.unwrap();
    let reopened = Arc::new(
        UsageJournal::open(
            &fixture.directory.join("usage.sqlite"),
            &fixture.server.uri(),
        )
        .unwrap(),
    );
    let recovered = QuotaManager::new(reopened.clone(), fixture.server.uri(), "test-server".into())
        .await
        .unwrap();
    assert_eq!(recovered.relay_id, fixture.manager.relay_id);
    recovered.observe(&fixture.context, 60, 0, 1).await.unwrap();
    assert!(recovered
        .observe(&fixture.context, 1, 0, 0)
        .await
        .unwrap_err()
        .downcast_ref::<QuotaExceeded>()
        .is_some());
    let rows = reopened.batch().await.unwrap();
    assert_eq!(rows[0].request_count, 2);
    assert_eq!(rows[0].bytes_in, 100);
}

#[tokio::test]
async fn observation_failure_rolls_back_credit_and_usage_together() {
    let fixture = Fixture::new(100, 2).await;
    let db = fixture.connection();
    db.execute_batch("CREATE TRIGGER reject_observation BEFORE INSERT ON counters BEGIN SELECT RAISE(ABORT, 'injected disk failure'); END;").unwrap();
    assert!(fixture.observe(40, 0, 1).await.is_err());
    assert!(fixture.journal.batch().await.unwrap().is_empty());
    match fixture
        .journal
        .quota_state(fixture.context.user_id.clone())
        .await
        .unwrap()
        .unwrap()
    {
        State::Active {
            bytes, requests, ..
        } => assert_eq!((bytes, requests), (100, 2)),
        _ => panic!("expected allocated credit"),
    }
    db.execute_batch("DROP TRIGGER reject_observation").unwrap();
    fixture.observe(40, 0, 1).await.unwrap();
    fixture.manager.maintain(true).await.unwrap();
    assert_eq!(fixture.ledger.lock().unwrap().bytes, 60);
}

#[tokio::test]
async fn expired_credit_cannot_forward_during_control_plane_outage() {
    let fixture = Fixture::new(100, 3).await;
    fixture.observe(10, 0, 1).await.unwrap();
    fixture.ledger.lock().unwrap().offline = true;
    fixture
        .manager
        .clocks
        .get_mut(&fixture.context.user_id)
        .unwrap()
        .expires = Instant::now();
    assert!(fixture.observe(10, 0, 0).await.is_err());
    let rows = fixture.journal.batch().await.unwrap();
    assert_eq!(rows[0].bytes_in, 10);
    fixture.ledger.lock().unwrap().offline = false;
    fixture.observe(10, 0, 0).await.unwrap();
    fixture.manager.maintain(true).await.unwrap();
    assert_eq!(fixture.ledger.lock().unwrap().bytes, 80);
}

#[tokio::test]
async fn legacy_and_reserved_observations_never_merge_into_one_report() {
    let fixture = Fixture::new(100, 3).await;
    fixture
        .journal
        .record(
            fixture.context.tunnel_id.clone(),
            fixture.context.user_id.clone(),
            7,
            9,
        )
        .await
        .unwrap();
    fixture.observe(11, 13, 1).await.unwrap();
    let rows = fixture.journal.batch().await.unwrap();
    assert_eq!(rows.len(), 2);
    let old = rows.iter().find(|row| !row.quota_accounted).unwrap();
    let new = rows.iter().find(|row| row.quota_accounted).unwrap();
    assert_eq!((old.bytes_in, old.bytes_out, old.request_count), (7, 9, 1));
    assert_eq!(
        (new.bytes_in, new.bytes_out, new.request_count),
        (11, 13, 1)
    );
    assert_ne!(old.report_id, new.report_id);
}

#[tokio::test]
async fn version_one_migration_preserves_pending_report_ids_and_unaccounted_counters() {
    let fixture = Fixture::new(100, 3).await;
    let path = fixture.directory.join("legacy.sqlite");
    let legacy = rusqlite::Connection::open(&path).unwrap();
    legacy.execute_batch("CREATE TABLE counters(tunnel_id TEXT, user_id TEXT, bytes_in INTEGER, bytes_out INTEGER, request_count INTEGER, timestamp INTEGER, PRIMARY KEY(tunnel_id,timestamp));
        CREATE TABLE outbox(sequence INTEGER PRIMARY KEY AUTOINCREMENT, report_id TEXT UNIQUE, tunnel_id TEXT, user_id TEXT, bytes_in INTEGER, bytes_out INTEGER, request_count INTEGER, timestamp INTEGER);
        PRAGMA user_version=1;").unwrap();
    let id = uuid::Uuid::new_v4().to_string();
    let minute = chrono::Utc::now().timestamp() / 60 * 60;
    legacy
        .execute(
            "INSERT INTO counters VALUES(?,?,3,5,1,?)",
            rusqlite::params![fixture.context.tunnel_id, fixture.context.user_id, minute],
        )
        .unwrap();
    legacy.execute("INSERT INTO outbox(report_id,tunnel_id,user_id,bytes_in,bytes_out,request_count,timestamp) VALUES(?,?,?,7,9,1,?)",
        rusqlite::params![id, fixture.context.tunnel_id, fixture.context.user_id, minute]).unwrap();
    drop(legacy);
    let journal = Arc::new(UsageJournal::open(&path, &fixture.server.uri()).unwrap());
    let pending = journal.batch().await.unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].report_id, id);
    assert!(!pending[0].quota_accounted);
    assert_eq!((pending[0].bytes_in, pending[0].bytes_out), (7, 9));
    journal.acknowledge(&pending).await.unwrap();
    let manager = QuotaManager::new(journal.clone(), fixture.server.uri(), "test-server".into())
        .await
        .unwrap();
    manager.observe(&fixture.context, 11, 13, 1).await.unwrap();
    let rows = journal.batch().await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter()
            .find(|row| !row.quota_accounted)
            .unwrap()
            .bytes_in,
        3
    );
    assert_eq!(
        rows.iter()
            .find(|row| row.quota_accounted)
            .unwrap()
            .bytes_in,
        11
    );
    assert!(rows.iter().all(|row| row.report_id != id));
}

#[tokio::test]
async fn http_body_gating_preserves_trailers_and_bounded_frames() {
    use axum::{
        body::{Body, Bytes},
        http::HeaderMap,
    };
    use http_body_util::{BodyExt, StreamBody};
    use pike_core::byte_stream::Direction;
    let fixture = Fixture::new(1_000_000, 3).await;
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().unwrap());
    let input = futures_util::stream::iter(vec![
        Ok::<_, std::io::Error>(hyper::body::Frame::data(Bytes::from(vec![173; 128 * 1024]))),
        Ok(hyper::body::Frame::trailers(trailers.clone())),
    ]);
    let meter = crate::traffic_meter::TrafficMeter::new(
        Arc::new(crate::registry::ClientRegistry::new()),
        pike_core::types::TunnelId(uuid::Uuid::new_v4()),
        fixture.context.user_id.clone(),
        fixture.context.tunnel_id.clone(),
        Some(fixture.journal.clone()),
    )
    .with_quota(
        Some(fixture.manager.clone()),
        fixture.context.lease_id.clone(),
    );
    meter.opened().await.unwrap();
    let mut body = meter.wrap_body(Body::new(StreamBody::new(input)), Direction::SocketToTunnel);
    let mut count = 0;
    let mut saw_trailers = false;
    while let Some(frame) = body.frame().await {
        let frame = frame.unwrap();
        if let Some(bytes) = frame.data_ref() {
            assert!(bytes.len() <= 32768);
            count += bytes.len();
        }
        if let Some(actual) = frame.trailers_ref() {
            assert_eq!(actual, &trailers);
            saw_trailers = true;
        }
    }
    assert_eq!(count, 128 * 1024);
    assert!(saw_trailers);
    let rows = fixture.journal.batch().await.unwrap();
    assert_eq!(rows[0].bytes_in, count as u64);
    assert_eq!(rows[0].request_count, 1);
}
