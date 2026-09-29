//! Exercise cloud UUIDs at the relay HTTP boundary using actual forwarded traffic.
use axum::{body::Body, http::Response};
use pike_core::types::TunnelId;
use pike_server::{
    config::TrafficInspectionConfig,
    connection::{ClientConnection, ValidatedUser},
    dashboard_ws::DashboardBroadcaster,
    http::run_http_server,
    ingest::RequestBuffer,
    proxy::TunnelRequest,
    registry::ClientRegistry,
    request_log::RequestLogStore,
    router::{TunnelEntry, VhostRouter},
    tunnel_metrics::TunnelMetricsStore,
};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, watch};

#[tokio::test]
// Keep the ordered lifecycle and its boundary assertions together in this scenario.
#[allow(clippy::too_many_lines)]
async fn cloud_id_addresses_real_metrics_logs_status_and_owner_checks() {
    let key = "fixture-local-key";
    let owner = format!("local-{:x}", Sha256::digest(key.as_bytes()));
    let runtime = TunnelId::new();
    let public = uuid::Uuid::new_v4().to_string();
    let connection = uuid::Uuid::new_v4();
    let registry = Arc::new(ClientRegistry::new());
    let mut client = ClientConnection::new(connection, Some("127.0.0.1:1234".parse().unwrap()));
    client.info.transport = "WebSocket";
    client.set_validated_user(ValidatedUser {
        tunnel_limit: None,
        user_id: owner.clone(),
        email: "fixture@example.test".into(),
        plan: "pro".into(),
        plan_expires_at: None,
        status: pike_server::connection::UserStatus::Active,
        limits: pike_server::connection::UserLimits::default(),
    });
    registry.register_client(client).unwrap();
    registry
        .register_tunnel(connection, "fixture.pike.life".into(), runtime)
        .unwrap();
    registry
        .remember_tunnel_identity(runtime, public.clone())
        .unwrap();
    let metrics = Arc::new(TunnelMetricsStore::new());
    metrics.remember_tunnel(&runtime.to_string(), &owner).await;
    let router = Arc::new(VhostRouter::new());
    let (requests, mut incoming) = mpsc::channel(4);
    router.register(
        "fixture.pike.life",
        TunnelEntry {
            tunnel_id: runtime,
            connection_id: connection,
            stream_tx: requests,
            active: true,
            visitor: pike_server::visitor_policy::VisitorGate::unrestricted(),
            domain: None,
            origin_health: None,
        },
    );
    let forwarder = tokio::spawn(async move {
        while let Some(TunnelRequest::Http(request)) = incoming.recv().await {
            let _ = request.response_tx.send(Ok(Response::builder()
                .status(201)
                .header("content-length", "2")
                .body(Body::from("ok"))
                .unwrap()));
        }
    });
    let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = reservation.local_addr().unwrap();
    drop(reservation);
    let (shutdown, shutdown_rx) = watch::channel(false);
    let server = tokio::spawn(run_http_server(
        addr,
        router,
        registry.clone(),
        Arc::new(DashboardBroadcaster::new()),
        Arc::new(RequestBuffer::new(String::new(), String::new())),
        Arc::new(RequestLogStore::new()),
        metrics,
        None,
        Some(vec![key.into(), "other-key".into()]),
        false,
        TrafficInspectionConfig::default(),
        pike_server::http::DEFAULT_MAX_BODY_SIZE,
        "pike.life".into(),
        pike_server::visitor_policy::TrustedProxies::default(),
        false,
        None,
        pike_server::certificates::Certificates::disabled(),
        shutdown_rx,
        None,
        None,
    ));
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    for _ in 0..50 {
        if http
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let response = http
        .get(format!("http://{addr}/sample"))
        .header("host", "fixture.pike.life")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    assert_eq!(response.text().await.unwrap(), "ok");
    let base = format!("http://{addr}/api/v1/tunnels/{public}");
    let mut measured = serde_json::Value::Null;
    for _ in 0..50 {
        let response = http
            .get(format!("{base}/metrics"))
            .bearer_auth(key)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        measured = response.json().await.unwrap();
        if measured["total_requests"] == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(measured["total_requests"], 1);
    assert_eq!(measured["status_breakdown"]["2xx"], 1);
    let logs: serde_json::Value = http
        .get(format!("{base}/requests"))
        .bearer_auth(key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(logs["requests"][0]["tunnel_id"], public);
    assert_eq!(logs["requests"][0]["status_code"], 201);
    let runtime_logs: serde_json::Value = http
        .get(format!("http://{addr}/api/v1/tunnels/{runtime}/requests"))
        .bearer_auth(key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(runtime_logs["requests"][0]["tunnel_id"], public);

    let status: serde_json::Value = http
        .get(format!("{base}/status"))
        .bearer_auth(key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["status"], "active");
    assert_eq!(status["transport"], "WebSocket");
    assert_eq!(
        http.get(format!("{base}/metrics"))
            .bearer_auth("other-key")
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    registry.unregister_tunnel_if_owner("fixture.pike.life", &connection);
    let status: serde_json::Value = http
        .get(format!("{base}/status"))
        .bearer_auth(key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        status["status"], "inactive",
        "recent traffic must not fabricate a live tunnel"
    );
    assert!(status["transport"].is_null());
    let _ = shutdown.send(true);
    server.abort();
    let _ = server.await;
    forwarder.abort();
    let _ = forwarder.await;
}
