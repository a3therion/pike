mod capture;
mod forward;
mod platform;
mod replay;
mod serve;
mod tls;
use crate::{
    config::TrafficInspectionConfig,
    dashboard_ws::{DashboardBroadcaster, DashboardWsState, WsTicketStore, WS_TICKET_TTL},
    ingest::RequestBuffer,
    rate_limit::{ip_rate_limit::IpRateLimitLayer, IpRateLimiter},
    registry::ClientRegistry,
    request_log::RequestLogStore,
    router::VhostRouter,
    tunnel_metrics::TunnelMetricsStore,
};
use anyhow::Context;
use axum::{
    http::{
        header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE},
        Method,
    },
    routing::any,
    Router,
};
use dashmap::DashMap;
use forward::handle_request;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    limit::RequestBodyLimitLayer,
    trace::TraceLayer,
};
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_MAX_BODY_SIZE: usize = 200_000_000;

#[derive(Debug)]
struct SseTokenEntry {
    tunnel_id: String,
    user_id: String,
    authorization: HeaderValue,
    created_at: Instant,
}

#[derive(Clone)]
struct HttpState {
    certificates: Arc<crate::certificates::Certificates>,
    router: Arc<VhostRouter>,
    registry: Arc<ClientRegistry>,
    broadcaster: Arc<DashboardBroadcaster>,
    control_plane_url: Option<String>,
    local_api_keys: Option<Vec<String>>,
    http_client: reqwest::Client,
    dev_mode: bool,
    traffic_inspection: TrafficInspectionConfig,
    max_body_size: usize,
    platform_router: axum::Router,
    ingest_buffer: Arc<RequestBuffer>,
    request_log_store: Arc<RequestLogStore>,
    tunnel_metrics_store: Arc<TunnelMetricsStore>,
    sse_tokens: Arc<DashMap<String, SseTokenEntry>>,
    /// Short-lived single-use tickets for the dashboard WebSocket (shared with the WS
    /// handler so the raw JWT never travels in the WebSocket URL).
    ws_tickets: WsTicketStore,
    domain: String,
    tunnel_accept_tx: Option<tokio::sync::mpsc::Sender<crate::websocket::AcceptedWebSocket>>,
    pending_tunnel_logins: Arc<tokio::sync::Semaphore>,
    replay_slots: Arc<tokio::sync::Semaphore>,
    trusted_proxies: crate::visitor_policy::TrustedProxies,
    /// Present only in the cross-relay topology; forwards router misses.
    frontend: Option<Arc<crate::ingress::Frontend>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn run_http_server(
    bind_addr: SocketAddr,
    router: Arc<VhostRouter>,
    registry: Arc<ClientRegistry>,
    broadcaster: Arc<DashboardBroadcaster>,
    ingest_buffer: Arc<RequestBuffer>,
    request_log_store: Arc<RequestLogStore>,
    tunnel_metrics_store: Arc<TunnelMetricsStore>,
    control_plane_url: Option<String>,
    local_api_keys: Option<Vec<String>>,
    dev_mode: bool,
    traffic_inspection: TrafficInspectionConfig,
    max_body_size: usize,
    domain: String,
    trusted_proxies: crate::visitor_policy::TrustedProxies,
    trust_cloudflare: bool,
    public_https: Option<crate::config::PublicTlsConfig>,
    certificates: Arc<crate::certificates::Certificates>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
    tunnel_accept_tx: Option<tokio::sync::mpsc::Sender<crate::websocket::AcceptedWebSocket>>,
    ingress: Option<crate::ingress::HttpIngress>,
) -> anyhow::Result<()> {
    let (frontend, hop_http, hop_https) = match ingress {
        Some(ingress) => (ingress.frontend, Some(ingress.http), Some(ingress.https)),
        None => (None, None, None),
    };
    let http_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    // Shared between the ws-ticket mint endpoint (HttpState) and the /ws/dashboard
    // consumer (DashboardWsState).
    let ws_tickets: WsTicketStore = Arc::new(DashMap::new());
    let ws_state = DashboardWsState {
        broadcaster: broadcaster.clone(),
        control_plane_url: control_plane_url.clone(),
        local_api_keys: local_api_keys.clone(),
        http_client: http_client.clone(),
        dev_mode,
        ws_tickets: ws_tickets.clone(),
    };

    let allowed_origins: Vec<HeaderValue> = if dev_mode {
        vec![
            format!("https://app.{domain}")
                .parse()
                .with_context(|| format!("invalid CORS origin for domain: {domain}"))?,
            "http://localhost:5173"
                .parse()
                .context("invalid localhost CORS origin")?,
        ]
    } else {
        vec![format!("https://app.{domain}")
            .parse()
            .with_context(|| format!("invalid CORS origin for domain: {domain}"))?]
    };
    let cors_layer = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE]);

    let state_base = HttpState {
        certificates: certificates.clone(),
        trusted_proxies,
        router: router.clone(),
        registry: registry.clone(),
        broadcaster: broadcaster.clone(),
        control_plane_url,
        local_api_keys,
        http_client,
        dev_mode,
        traffic_inspection,
        max_body_size,
        platform_router: Router::new(),
        ingest_buffer,
        request_log_store,
        tunnel_metrics_store,
        sse_tokens: Arc::new(DashMap::new()),
        ws_tickets: ws_tickets.clone(),
        domain,
        tunnel_accept_tx,
        replay_slots: Arc::new(tokio::sync::Semaphore::new(8)),
        pending_tunnel_logins: Arc::new(tokio::sync::Semaphore::new(
            crate::websocket::MAX_PENDING_LOGINS,
        )),
        frontend: frontend.clone(),
    };

    let platform_router = platform::router(state_base.clone(), ws_state, cors_layer);

    let state = HttpState {
        platform_router,
        ..state_base
    };

    let sse_tokens_for_eviction = state.sse_tokens.clone();
    let ws_tickets_for_eviction = state.ws_tickets.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            sse_tokens_for_eviction
                .retain(|_, entry| entry.created_at.elapsed() <= Duration::from_secs(60));
            ws_tickets_for_eviction.retain(|_, entry| entry.created_at.elapsed() <= WS_TICKET_TTL);
        }
    });

    let ip_limiter = IpRateLimiter::new(100);
    let app = Router::new()
        .fallback(any(handle_request))
        .with_state(state)
        // Cap the inbound request body at the configured max. tower-http returns 413
        // automatically once the limit is exceeded, before the handler streams anything.
        .layer(RequestBodyLimitLayer::new(max_body_size))
        .layer(IpRateLimitLayer::new(ip_limiter, trust_cloudflare))
        .layer(TraceLayer::new_for_http().make_span_with(|request: &axum::http::Request<axum::body::Body>| {
            tracing::debug_span!("http.request", method = %request.method(), path = request.uri().path())
        }));

    let https = if let Some(config) = public_https {
        Some(
            tls::HttpsListener::bind(
                config,
                router,
                registry,
                certificates,
                frontend,
                hop_https,
                shutdown_rx.clone(),
            )
            .await?,
        )
    } else {
        // Without a native HTTPS listener the owner acceptor must see a closed
        // channel and reject HTTPS hops before the accept byte.
        drop(hop_https);
        None
    };
    let https_app = app
        .clone()
        .layer(axum::middleware::from_fn(tls::verified_peer));
    // Owner role: the same application on injected hop connections, behind the
    // middleware that rebinds each request to its hop-verified visitor.
    let hop_app = app
        .clone()
        .layer(axum::middleware::from_fn(crate::ingress::ingress_peer));
    // Every server below owns its connections and ends within a fixed bound of
    // the shutdown signal; see `serve::serve_bounded`.
    let mut hop_shutdown = shutdown_rx.clone();
    let hop_server = async move {
        if let Some(accepted) = hop_http {
            serve::serve_bounded(
                crate::ingress::HopHttpListener::new(accepted),
                hop_app,
                |io: &crate::ingress::HopHttpIo, _: &SocketAddr| io.peer(),
                hop_shutdown,
                serve::SHUTDOWN_DRAIN,
            )
            .await;
        } else {
            let _ = hop_shutdown.wait_for(|stop| *stop).await;
        }
    };
    let mut https_shutdown = shutdown_rx.clone();
    let secure_server = async move {
        if let Some(listener) = https {
            serve::serve_bounded(
                listener,
                https_app,
                |io: &tls::HttpsStream, _: &SocketAddr| io.peer(),
                https_shutdown,
                serve::SHUTDOWN_DRAIN,
            )
            .await;
        } else {
            let _ = https_shutdown.wait_for(|stop| *stop).await;
        }
    };
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind HTTP server on {bind_addr}"))?;
    tracing::info!(bind_addr = %bind_addr, "HTTP listener ready");

    let plain_server = serve::serve_bounded(
        listener,
        app,
        |_: &tokio::net::TcpStream, addr: &SocketAddr| *addr,
        shutdown_rx,
        serve::SHUTDOWN_DRAIN,
    );
    tokio::join!(plain_server, secure_server, hop_server);
    tracing::info!("HTTP servers stopped");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::platform::is_platform_host;

    #[test]
    fn test_custom_domain_in_host_detection() {
        // Test with default domain
        assert!(is_platform_host("pike.life", "pike.life"));
        assert!(is_platform_host("pike.life:8080", "pike.life"));
        assert!(!is_platform_host("example.com", "pike.life"));

        // Test with custom domain
        assert!(is_platform_host("example.com", "example.com"));
        assert!(is_platform_host("example.com:8080", "example.com"));
        assert!(!is_platform_host("pike.life", "example.com"));

        // Test localhost always works
        assert!(is_platform_host("localhost", "pike.life"));
        assert!(is_platform_host("localhost", "example.com"));

        // Test .internal always works
        assert!(is_platform_host("service.internal", "pike.life"));
        assert!(is_platform_host("service.internal", "example.com"));

        // Test case insensitivity
        assert!(is_platform_host("PIKE.LIFE", "pike.life"));
        assert!(is_platform_host("Example.Com", "example.com"));

        // Test IP addresses
        assert!(is_platform_host("127.0.0.1", "pike.life"));
        assert!(is_platform_host("192.168.1.1", "example.com"));
    }
}
