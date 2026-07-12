//! Integration test for the end-to-end inbound request timeout (fix: no inbound request
//! timeout / slow-loris). A tunnel is registered whose backend never answers; the relay must
//! give up after the configured `request_timeout` and return 504 instead of hanging forever.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pike_core::types::TunnelId;
use pike_server::{
    config::TrafficInspectionConfig, dashboard_ws::DashboardBroadcaster, http::run_http_server,
    ingest::RequestBuffer, proxy::TunnelRequest, registry::ClientRegistry,
    request_log::RequestLogStore, router::TunnelEntry, router::VhostRouter,
    tunnel_metrics::TunnelMetricsStore,
};
use tokio::sync::{mpsc, watch};

#[tokio::test]
async fn hung_upstream_times_out_with_504() {
    let router = Arc::new(VhostRouter::new());
    let registry = Arc::new(ClientRegistry::new());
    let broadcaster = Arc::new(DashboardBroadcaster::new());
    let ingest_buffer = Arc::new(RequestBuffer::new(
        "http://unused".to_string(),
        "token".to_string(),
    ));
    let request_log_store = Arc::new(RequestLogStore::new());
    let tunnel_metrics_store = Arc::new(TunnelMetricsStore::new());

    // Register an ACTIVE tunnel whose receiver we keep alive but never answer, simulating a
    // hung upstream. The send inside proxy_request succeeds, then it awaits a response that
    // never arrives.
    let (stream_tx, _stream_rx) = mpsc::channel::<TunnelRequest>(8);
    router.register(
        "hang.pike.life",
        TunnelEntry {
            tunnel_id: TunnelId::new(),
            connection_id: uuid::Uuid::new_v4(),
            stream_tx,
            active: true,
        },
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener);

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let _shutdown_tx = Box::leak(Box::new(shutdown_tx));

    tokio::spawn(run_http_server(
        addr,
        router,
        registry,
        broadcaster,
        ingest_buffer,
        request_log_store,
        tunnel_metrics_store,
        None,
        None,
        true,
        TrafficInspectionConfig::default(),
        "pike.life".to_string(),
        // 1s timeout, well below proxy.rs's 30s internal timeout, so THIS wrapper fires first.
        Duration::from_secs(1),
        100 * 1024 * 1024,
        false,
        shutdown_rx,
    ));

    tokio::time::sleep(Duration::from_millis(150)).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    let start = std::time::Instant::now();
    let resp = client
        .get(format!("http://{addr}/"))
        .header("Host", "hang.pike.life")
        .send()
        .await
        .expect("request should complete (with 504), not hang");

    assert_eq!(
        resp.status(),
        504,
        "hung upstream should yield a gateway timeout"
    );
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "response should return promptly after the 1s request timeout, took {:?}",
        start.elapsed()
    );
}
