//! Integration test for the configurable max-body-size cap (fix: uncapped body buffering ->
//! memory exhaustion). A request body larger than `max_body_size` must be rejected with 413,
//! not buffered into memory.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use pike_server::{
    config::TrafficInspectionConfig, dashboard_ws::DashboardBroadcaster, http::run_http_server,
    ingest::RequestBuffer, registry::ClientRegistry, request_log::RequestLogStore,
    router::VhostRouter, tunnel_metrics::TunnelMetricsStore,
};
use tokio::sync::watch;

async fn start_server_with_body_cap(max_body_size: usize) -> SocketAddr {
    let router = Arc::new(VhostRouter::new());
    let registry = Arc::new(ClientRegistry::new());
    let broadcaster = Arc::new(DashboardBroadcaster::new());
    let ingest_buffer = Arc::new(RequestBuffer::new(
        "http://unused".to_string(),
        "token".to_string(),
    ));
    let request_log_store = Arc::new(RequestLogStore::new());
    let tunnel_metrics_store = Arc::new(TunnelMetricsStore::new());

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
        Duration::from_secs(30),
        max_body_size,
        false,
        shutdown_rx,
    ));

    tokio::time::sleep(Duration::from_millis(150)).await;
    addr
}

#[tokio::test]
async fn oversized_request_body_is_rejected_with_413() {
    // Cap bodies at 1 KiB.
    let addr = start_server_with_body_cap(1024).await;

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    // 64 KiB body, well over the 1 KiB cap.
    let big_body = vec![b'x'; 64 * 1024];
    let resp = client
        .post(format!("http://{addr}/"))
        .header("Host", "some-tunnel.pike.life")
        .body(big_body)
        .send()
        .await
        .expect("request should complete with 413, not OOM/hang");

    assert_eq!(
        resp.status(),
        413,
        "body over max_body_size must be rejected with Payload Too Large"
    );
}

#[tokio::test]
async fn small_request_body_is_not_rejected_by_cap() {
    let addr = start_server_with_body_cap(1024).await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    // 100-byte body, under the cap. No tunnel is registered, so the proxy returns a 307
    // redirect — the point is that it is NOT rejected with 413.
    let resp = client
        .post(format!("http://{addr}/"))
        .header("Host", "some-tunnel.pike.life")
        .body(vec![b'x'; 100])
        .send()
        .await
        .expect("request should complete");

    assert_ne!(resp.status(), 413, "under-cap body must not be rejected");
}
