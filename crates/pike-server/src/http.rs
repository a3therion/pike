use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use axum::body::{Body, Bytes};
use axum::extract::ws::WebSocketUpgrade;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::header::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, Method, Request, Response, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{any, get};
use axum::Router;
use dashmap::DashMap;
use http_body_util::BodyExt;
use tower::ServiceExt;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;

use crate::auth::AuthLayer;
use crate::config::TrafficInspectionConfig;
use crate::dashboard_ws::{
    dashboard_ws_handler, validate_local_api_key, validate_token, DashboardBroadcaster,
    DashboardEvent, DashboardWsState,
};
use crate::ingest::{IngestEntry, RequestBuffer};
use crate::proxy::{extract_host, is_websocket_upgrade, proxy_request, ProxyContext, ProxyError};
use crate::rate_limit::{
    exceeded_headers, ip_rate_limit::IpRateLimitLayer, IpRateLimiter, RateLimitError,
    RateLimitHeaders,
};
use crate::registry::ClientRegistry;
use crate::request_log::RequestLogStore;
use crate::router::VhostRouter;
use crate::tunnel_metrics::{MetricsRange, TunnelMetricsStore};
use crate::websocket::handle_websocket;
use crate::ws_proxy;
use pike_core::types::TunnelId;

pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

#[derive(serde::Serialize)]
struct CapturedHeader {
    name: String,
    value: String,
}

#[derive(Debug)]
struct SseTokenEntry {
    tunnel_id: String,
    created_at: Instant,
}

/// Returns true if the content-type is text-like and worth previewing.
fn is_previewable_content_type(ct: &str) -> bool {
    let ct = ct.to_ascii_lowercase();
    ct.starts_with("text/")
        || ct.contains("json")
        || ct.contains("xml")
        || ct.contains("x-www-form-urlencoded")
        || ct.contains("graphql")
        || ct.contains("yaml")
        || ct.contains("toml")
        || ct.contains("javascript")
        || ct.contains("css")
        || ct.contains("html")
}

/// Serialize headers into a JSON string.
fn headers_to_json(headers: &axum::http::HeaderMap) -> String {
    let values: Vec<CapturedHeader> = headers
        .iter()
        .map(|(k, v)| CapturedHeader {
            name: k.as_str().to_string(),
            value: header_value_for_capture(k, v),
        })
        .collect();
    serde_json::to_string(&values).unwrap_or_default()
}

fn header_value_for_capture(name: &HeaderName, value: &HeaderValue) -> String {
    if is_sensitive_header_name(name.as_str()) {
        return "<redacted>".to_string();
    }

    value.to_str().unwrap_or("<binary>").to_string()
}

fn is_sensitive_header_name(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "x-csrf-token"
            | "x-forwarded-access-token"
            | "cf-access-jwt-assertion"
            | "x-amz-security-token"
    ) || normalized == "apikey"
        || normalized.ends_with("-token")
        || normalized.ends_with("_token")
        || normalized.ends_with("-secret")
        || normalized.ends_with("_secret")
        || normalized.ends_with("-api-key")
        || normalized.ends_with("_api_key")
        || normalized.contains("session")
}

fn is_sensitive_field_name(name: &str) -> bool {
    let normalized = name
        .trim()
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-')
        .to_ascii_lowercase();

    matches!(
        normalized.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "password"
            | "passwd"
            | "pwd"
            | "token"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "api_key"
            | "apikey"
            | "secret"
            | "client_secret"
            | "session"
            | "session_id"
    ) || normalized.ends_with("-token")
        || normalized.ends_with("_token")
        || normalized.ends_with("-secret")
        || normalized.ends_with("_secret")
        || normalized.ends_with("-key")
        || normalized.ends_with("_key")
        || normalized.contains("session")
        || normalized.contains("cookie")
}

fn maybe_capture_headers(
    headers: &axum::http::HeaderMap,
    capture_config: &TrafficInspectionConfig,
) -> Option<String> {
    capture_config
        .capture_headers
        .then(|| headers_to_json(headers))
}

fn should_capture_body_preview(
    capture_config: &TrafficInspectionConfig,
    content_type: Option<&str>,
    content_length: u64,
) -> bool {
    capture_config.capture_bodies
        && capture_config.max_body_preview_bytes > 0
        && content_type.is_some_and(is_previewable_content_type)
        && !(content_length > capture_config.max_body_preview_bytes as u64 && content_length != 0)
}

fn preview_body(
    bytes: &Bytes,
    max_body_preview_bytes: usize,
    content_type: Option<&str>,
) -> Option<String> {
    let truncated = bytes.len() > max_body_preview_bytes;
    let preview_bytes = &bytes[..bytes.len().min(max_body_preview_bytes)];
    let mut preview = String::from_utf8_lossy(preview_bytes).to_string();
    preview = redact_body_preview(content_type, preview);
    if truncated {
        preview.push_str("\n\n--- truncated ---");
    }

    if preview.is_empty() {
        None
    } else {
        Some(preview)
    }
}

fn redact_body_preview(content_type: Option<&str>, preview: String) -> String {
    let Some(content_type) = content_type else {
        return redact_text_preview(&preview);
    };

    let normalized = content_type.to_ascii_lowercase();
    if normalized.contains("json") {
        return redact_json_preview(&preview).unwrap_or_else(|| redact_text_preview(&preview));
    }
    if normalized.contains("x-www-form-urlencoded") {
        return redact_form_urlencoded_preview(&preview);
    }

    redact_text_preview(&preview)
}

fn redact_json_preview(preview: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(preview).ok()?;
    redact_json_value(&mut value);
    serde_json::to_string(&value).ok()
}

fn redact_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested_value) in map.iter_mut() {
                if is_sensitive_field_name(key) {
                    *nested_value = serde_json::Value::String("<redacted>".to_string());
                } else {
                    redact_json_value(nested_value);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_value(item);
            }
        }
        _ => {}
    }
}

fn redact_form_urlencoded_preview(preview: &str) -> String {
    preview
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _)) if is_sensitive_field_name(key) => format!("{key}=<redacted>"),
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn redact_text_preview(preview: &str) -> String {
    preview
        .lines()
        .map(redact_text_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_text_line(line: &str) -> String {
    let redacted = if let Some((key, _)) = line.split_once(':') {
        if is_sensitive_field_name(key) {
            format!("{key}: <redacted>")
        } else {
            line.to_string()
        }
    } else if let Some((key, _)) = line.split_once('=') {
        if is_sensitive_field_name(key) {
            format!("{key}=<redacted>")
        } else {
            line.to_string()
        }
    } else {
        line.to_string()
    };

    redact_bearer_tokens(&redacted)
}

fn redact_bearer_tokens(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut result = String::new();
    let mut cursor = 0;

    while let Some(offset) = lower[cursor..].find("bearer ") {
        let start = cursor + offset;
        result.push_str(&text[cursor..start]);
        result.push_str("Bearer <redacted>");

        let mut end = start + "bearer ".len();
        for ch in text[end..].chars() {
            if ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | ';' | ')' | ']' | '}') {
                break;
            }
            end += ch.len_utf8();
        }

        cursor = end;
    }

    result.push_str(&text[cursor..]);
    result
}

/// Extract the content-type header value as a string.
fn content_type_str(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[derive(Clone)]
struct HttpState {
    router: Arc<VhostRouter>,
    registry: Arc<ClientRegistry>,
    broadcaster: Arc<DashboardBroadcaster>,
    control_plane_url: Option<String>,
    local_api_keys: Option<Vec<String>>,
    http_client: reqwest::Client,
    dev_mode: bool,
    traffic_inspection: TrafficInspectionConfig,
    platform_router: axum::Router,
    ingest_buffer: Arc<RequestBuffer>,
    request_log_store: Arc<RequestLogStore>,
    tunnel_metrics_store: Arc<TunnelMetricsStore>,
    sse_tokens: Arc<DashMap<String, SseTokenEntry>>,
    domain: String,
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
    domain: String,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let http_client = reqwest::Client::new();
    let ws_state = DashboardWsState {
        broadcaster: broadcaster.clone(),
        control_plane_url: control_plane_url.clone(),
        local_api_keys: local_api_keys.clone(),
        http_client: http_client.clone(),
        dev_mode,
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
        router: router.clone(),
        registry: registry.clone(),
        broadcaster: broadcaster.clone(),
        control_plane_url,
        local_api_keys,
        http_client,
        dev_mode,
        traffic_inspection,
        platform_router: Router::new(),
        ingest_buffer,
        request_log_store,
        tunnel_metrics_store,
        sse_tokens: Arc::new(DashMap::new()),
        domain,
    };

    let platform_router = Router::new()
        .route(
            "/ws/dashboard",
            get(dashboard_ws_handler).with_state(ws_state),
        )
        .route(
            "/api/v1/tunnels/{tunnel_id}/requests",
            get(handle_get_requests),
        )
        .route(
            "/api/v1/tunnels/{tunnel_id}/requests/stream",
            get(handle_requests_stream),
        )
        .route(
            "/api/v1/tunnels/{tunnel_id}/metrics",
            get(handle_get_metrics),
        )
        .route(
            "/api/v1/tunnels/{tunnel_id}/metrics/timeseries",
            get(handle_get_metrics_timeseries),
        )
        .route(
            "/api/v1/tunnels/{tunnel_id}/status",
            get(handle_get_tunnel_status),
        )
        .route(
            "/api/v1/sse-token",
            axum::routing::post(handle_create_sse_token),
        )
        .with_state(state_base.clone())
        .layer(cors_layer);

    let state = HttpState {
        platform_router,
        ..state_base
    };

    let sse_tokens_for_eviction = state.sse_tokens.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            sse_tokens_for_eviction
                .retain(|_, entry| entry.created_at.elapsed() <= Duration::from_secs(60));
        }
    });

    let ip_limiter = IpRateLimiter::new(100);
    let app = Router::new()
        .fallback(any(handle_request))
        .with_state(state)
        .layer(AuthLayer::new(registry.clone()))
        .layer(RequestBodyLimitLayer::new(DEFAULT_MAX_BODY_SIZE))
        .layer(IpRateLimitLayer::new(ip_limiter))
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind HTTP server on {bind_addr}"))?;
    tracing::info!(bind_addr = %bind_addr, "HTTP listener ready");

    let mut shutdown_rx = shutdown_rx;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        let _ = shutdown_rx.changed().await;
        tracing::info!("HTTP server graceful shutdown initiated");
    })
    .await
    .context("HTTP server terminated unexpectedly")?;

    Ok(())
}

async fn handle_request(
    State(state): State<HttpState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    mut req: Request<Body>,
) -> Response<Body> {
    let host = extract_host(req.headers()).unwrap_or_default();
    let request_path = req.uri().path().to_string();

    if is_platform_host(&host, &state.domain) {
        if request_path == "/health" {
            return platform_health_response();
        }

        if request_path.starts_with("/ws/") || request_path.starts_with("/api/v1/") {
            return dispatch_platform_request(state.clone(), req).await;
        }
    }

    tracing::info!("HTTP handle_request called");
    let scheme = req
        .headers()
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("http")
        .to_string();
    let request_content_length = request_content_length(&req);

    let tunnel_entry = crate::proxy::extract_host(req.headers())
        .map(|host| crate::router::normalize_host(&host))
        .and_then(|host| state.router.route(&host));

    let mut rate_limit_headers = None;
    if let Some(tunnel) = &tunnel_entry {
        if state
            .registry
            .abuse_detector
            .is_suspended(&tunnel.tunnel_id)
        {
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Body::from("tunnel suspended due to abuse"))
                .unwrap_or_else(|_| Response::new(Body::from("tunnel suspended")));
        }

        let user_id = state
            .registry
            .user_id_for_connection(&tunnel.connection_id)
            .unwrap_or_else(|| format!("conn:{}", tunnel.connection_id));
        if let Err(error) = state.registry.rate_limiter.check_limit(user_id) {
            let headers = exceeded_headers();
            return build_rate_limited_response(error, Some(&headers));
        }
        match state
            .registry
            .rate_limiter
            .check_tunnel_limit(tunnel.tunnel_id)
        {
            Ok(headers) => {
                rate_limit_headers = Some(headers);
            }
            Err(error) => {
                let headers = exceeded_headers();
                return build_rate_limited_response(error, Some(&headers));
            }
        }
    }

    // Extract host/subdomain before we pass the request through
    let subdomain = extract_host(req.headers())
        .map(|h| crate::router::normalize_host(&h))
        .unwrap_or_default();

    req.extensions_mut().insert(ProxyContext {
        client_addr: Some(client_addr),
        scheme,
    });

    // Intercept WebSocket upgrades and relay raw bytes through the tunnel.
    if is_websocket_upgrade(req.headers()) {
        if let Some(tunnel) = &tunnel_entry {
            let source_addr = client_addr;
            let stream_header = pike_core::proto::StreamHeader {
                tunnel_id: tunnel.tunnel_id,
                connection_id: crate::proxy::connection_id_from_uuid(),
                source_addr,
                streaming: true,
            };

            let raw_upgrade = ws_proxy::build_raw_upgrade_request(&req);
            let request_id = uuid::Uuid::new_v4().to_string();
            let stream_tx = tunnel.stream_tx.clone();

            return ws_proxy::handle_ws_upgrade(
                req,
                stream_tx,
                stream_header,
                raw_upgrade,
                request_id,
            )
            .await;
        }
    }

    // Capture method and path for live event broadcasting
    let req_method = req.method().to_string();
    let req_path = req
        .uri()
        .path_and_query()
        .map_or("/".to_string(), |pq| pq.to_string());

    // Capture request headers and body preview
    let req_content_type = content_type_str(req.headers());
    let req_headers_json = maybe_capture_headers(req.headers(), &state.traffic_inspection);

    let req_body_preview = {
        if should_capture_body_preview(
            &state.traffic_inspection,
            req_content_type.as_deref(),
            request_content_length,
        ) {
            let (parts, body) = req.into_parts();
            let bytes = body
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            let preview = preview_body(
                &bytes,
                state.traffic_inspection.max_body_preview_bytes,
                req_content_type.as_deref(),
            );
            req = Request::from_parts(parts, Body::from(bytes.clone()));
            preview
        } else {
            None
        }
    };

    let proxy_start = Instant::now();

    if let Some(signature) = state
        .registry
        .abuse_detector
        .check_malware_signature(req.uri().path().as_bytes())
    {
        state
            .registry
            .abuse_detector
            .log_abuse(crate::abuse::AbuseLogEntry {
                timestamp: chrono::Utc::now(),
                source_ip: Some(client_addr.ip()),
                user_id: None,
                tunnel_id: tunnel_entry.as_ref().map(|entry| entry.tunnel_id),
                request_count_per_minute: None,
                bandwidth_bytes: Some(request_content_length),
                reason: format!("matched malware signature {signature}"),
            });
        return Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(Body::from("request blocked by malware signature"))
            .unwrap_or_else(|_| Response::new(Body::from("blocked")));
    }

    let mut response = match proxy_request(state.router, req).await {
        Ok(response) => response,
        Err(err) => {
            crate::metrics::ERROR_RATE
                .with_label_values(&["proxy_error"])
                .inc();
            build_error_response(err, &state.domain)
        }
    };

    if let Some(headers) = &rate_limit_headers {
        apply_rate_limit_headers(response.headers_mut(), headers);
    }

    let response_time_ms = proxy_start.elapsed().as_millis() as u64;

    // Capture response headers and body preview
    let resp_content_type = content_type_str(response.headers());
    let resp_headers_json = maybe_capture_headers(response.headers(), &state.traffic_inspection);
    let resp_content_len = response_content_length(&response);

    let resp_body_preview = {
        if should_capture_body_preview(
            &state.traffic_inspection,
            resp_content_type.as_deref(),
            resp_content_len,
        ) {
            let (parts, body) = response.into_parts();
            let bytes = body
                .collect()
                .await
                .map(|c| c.to_bytes())
                .unwrap_or_default();
            let preview = preview_body(
                &bytes,
                state.traffic_inspection.max_body_preview_bytes,
                resp_content_type.as_deref(),
            );
            response = Response::from_parts(parts, Body::from(bytes.clone()));
            preview
        } else {
            None
        }
    };

    if let Some(tunnel) = tunnel_entry {
        let status_code = response.status().as_u16();
        state
            .registry
            .record_tunnel_request(tunnel.tunnel_id, status_code);
        let response_content_length = response_content_length(&response);
        let total_bytes = request_content_length.saturating_add(response_content_length);
        state
            .registry
            .track_bandwidth(tunnel.tunnel_id, total_bytes);

        crate::metrics::BYTES_TRANSFERRED
            .with_label_values(&["in"])
            .inc_by(request_content_length as f64);
        crate::metrics::BYTES_TRANSFERRED
            .with_label_values(&["out"])
            .inc_by(response_content_length as f64);
        crate::metrics::REQUEST_LATENCY
            .with_label_values(&["http"])
            .observe(response_time_ms as f64 / 1000.0);

        // Log request for per-tunnel request log API
        {
            let log_entry = crate::request_log::RequestLogEntry {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                method: req_method.clone(),
                path: req_path.clone(),
                status_code,
                duration_ms: response_time_ms,
                request_size: request_content_length,
                response_size: response_content_length,
                tunnel_id: tunnel.tunnel_id.to_string(),
            };
            let store = state.request_log_store.clone();
            tokio::spawn(async move {
                store.log(log_entry).await;
            });
        }

        {
            let store = state.tunnel_metrics_store.clone();
            let tunnel_id = tunnel.tunnel_id.to_string();
            tokio::spawn(async move {
                store
                    .record(
                        &tunnel_id,
                        status_code,
                        response_time_ms,
                        request_content_length,
                        response_content_length,
                    )
                    .await;
            });
        }

        // Broadcast live request to dashboard subscribers
        if let Some(user_id) = state.registry.user_id_for_connection(&tunnel.connection_id) {
            let timestamp = chrono::Utc::now().to_rfc3339();
            let event = DashboardEvent::LiveRequest {
                tunnel_id: tunnel.tunnel_id.to_string(),
                subdomain: subdomain.clone(),
                method: req_method.clone(),
                path: req_path.clone(),
                status_code,
                response_time_ms,
                bytes: total_bytes,
                client_ip: client_addr.ip().to_string(),
                timestamp: timestamp.clone(),
                request_headers: req_headers_json.clone(),
                request_body: req_body_preview.clone(),
                response_headers: resp_headers_json.clone(),
                response_body: resp_body_preview.clone(),
                request_content_type: req_content_type.clone(),
                response_content_type: resp_content_type.clone(),
            };
            if let Ok(json) = serde_json::to_string(&event) {
                state.broadcaster.broadcast(&user_id, &json);
            }

            // Push to ingest buffer for D1 persistence
            let entry = IngestEntry {
                user_id,
                tunnel_id: tunnel.tunnel_id.to_string(),
                subdomain: subdomain.clone(),
                method: req_method,
                path: req_path,
                status_code,
                response_time_ms,
                bytes_transferred: total_bytes,
                client_ip: client_addr.ip().to_string(),
                timestamp,
                request_headers: req_headers_json,
                request_body: req_body_preview,
                response_headers: resp_headers_json,
                response_body: resp_body_preview,
                request_content_type: req_content_type,
                response_content_type: resp_content_type,
            };
            let buffer = state.ingest_buffer.clone();
            tokio::spawn(async move {
                buffer.push(entry).await;
            });
        }
    }

    response
}

async fn dispatch_platform_request(state: HttpState, req: Request<Body>) -> Response<Body> {
    state
        .platform_router
        .clone()
        .oneshot(req)
        .await
        .unwrap_or_else(|_| {
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from("failed to dispatch platform route"))
                .unwrap_or_else(|_| Response::new(Body::from("internal server error")))
        })
}

fn platform_health_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"status":"healthy","service":"pike-server"}"#,
        ))
        .unwrap_or_else(|_| Response::new(Body::from("OK")))
}

fn is_platform_host(host: &str, domain: &str) -> bool {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return false;
    }

    let host_without_port = if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            &rest[..end]
        } else {
            trimmed
        }
    } else if let Some((name, port)) = trimmed.rsplit_once(':') {
        if !name.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            name
        } else {
            trimmed
        }
    } else {
        trimmed
    };

    if host_without_port.is_empty() {
        return false;
    }

    if IpAddr::from_str(host_without_port).is_ok() {
        return true;
    }

    let normalized = host_without_port.to_ascii_lowercase();
    let domain_lower = domain.to_ascii_lowercase();
    normalized == domain_lower || normalized == "localhost" || normalized.ends_with(".internal")
}

#[derive(serde::Deserialize)]
struct TimeseriesQuery {
    range: Option<String>,
}

async fn handle_get_metrics(
    Path(tunnel_id): Path<String>,
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Response<Body> {
    if uuid::Uuid::from_str(&tunnel_id).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "invalid tunnel_id"})),
        )
            .into_response();
    }
    if let Err(response) = ensure_tunnel_access(&state, &headers, &tunnel_id).await {
        return response;
    }
    let uptime_seconds = tunnel_uptime_seconds(&state, &tunnel_id).await;
    let resp = state
        .tunnel_metrics_store
        .metrics_response(&tunnel_id, uptime_seconds)
        .await;
    (StatusCode::OK, axum::Json(resp)).into_response()
}

async fn handle_get_metrics_timeseries(
    Path(tunnel_id): Path<String>,
    Query(query): Query<TimeseriesQuery>,
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Response<Body> {
    if uuid::Uuid::from_str(&tunnel_id).is_err() {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "invalid tunnel_id"})),
        )
            .into_response();
    }
    if let Err(response) = ensure_tunnel_access(&state, &headers, &tunnel_id).await {
        return response;
    }
    let range = query
        .range
        .as_deref()
        .and_then(MetricsRange::parse)
        .unwrap_or(MetricsRange::OneHour);

    let resp = state
        .tunnel_metrics_store
        .timeseries_response(&tunnel_id, range)
        .await;
    (StatusCode::OK, axum::Json(resp)).into_response()
}

async fn handle_get_tunnel_status(
    Path(tunnel_id): Path<String>,
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Response<Body> {
    let Ok(parsed) = uuid::Uuid::from_str(&tunnel_id) else {
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({"error": "invalid tunnel_id"})),
        )
            .into_response();
    };
    if let Err(response) = ensure_tunnel_access(&state, &headers, &tunnel_id).await {
        return response;
    }
    let tunnel_uuid = TunnelId(parsed);

    let registry_entry = lookup_tunnel_in_registry(&state.registry, tunnel_uuid);
    let has_registry_entry = registry_entry.is_some();
    let snapshot = state.tunnel_metrics_store.snapshot_times(&tunnel_id).await;

    let now = chrono::Utc::now();
    let now_unix_ms = now.timestamp_millis().max(0) as u64;

    let (mut status, mut connected_since, mut uptime_seconds) = if let Some(entry) = registry_entry
    {
        let uptime = now
            .signed_duration_since(entry.created_at)
            .num_seconds()
            .max(0) as u64;
        (
            if entry.active { "active" } else { "inactive" },
            Some(entry.created_at.to_rfc3339()),
            uptime,
        )
    } else {
        ("inactive", None, 0)
    };

    if connected_since.is_none() {
        if let Some(s) = snapshot.as_ref() {
            connected_since = Some(s.created_at_rfc3339.clone());
            let now_unix_sec = now.timestamp().max(0) as u64;
            uptime_seconds = now_unix_sec.saturating_sub(s.created_at_unix_sec);
        }
    }

    if connected_since.is_none() {
        connected_since = Some(now.to_rfc3339());
    }

    let last_activity = snapshot
        .as_ref()
        .and_then(|s| s.last_activity_rfc3339.clone())
        .or_else(|| connected_since.clone());

    if status == "inactive" && !has_registry_entry {
        if let Some(s) = snapshot.as_ref() {
            if s.last_activity_unix_ms != 0
                && now_unix_ms.saturating_sub(s.last_activity_unix_ms) <= 5 * 60 * 1000
            {
                status = "active";
            }
        }
    }

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": status,
            "uptime_seconds": uptime_seconds,
            "last_activity": last_activity,
            "connected_since": connected_since,
            "transport": "QUIC",
        })),
    )
        .into_response()
}

fn lookup_tunnel_in_registry(
    registry: &ClientRegistry,
    tunnel_id: TunnelId,
) -> Option<crate::registry::TunnelEntry> {
    registry
        .tunnels
        .iter()
        .find(|entry| entry.tunnel_id == tunnel_id)
        .map(|entry| entry.clone())
}

async fn tunnel_uptime_seconds(state: &HttpState, tunnel_id: &str) -> u64 {
    let parsed = uuid::Uuid::from_str(tunnel_id).ok().map(TunnelId);
    if let Some(tunnel_id) = parsed {
        if let Some(entry) = lookup_tunnel_in_registry(&state.registry, tunnel_id) {
            return chrono::Utc::now()
                .signed_duration_since(entry.created_at)
                .num_seconds()
                .max(0) as u64;
        }
    }

    if let Some(snapshot) = state.tunnel_metrics_store.snapshot_times(tunnel_id).await {
        let now = chrono::Utc::now();
        let now_unix_sec = now.timestamp().max(0) as u64;
        return now_unix_sec.saturating_sub(snapshot.created_at_unix_sec);
    }

    0
}

#[derive(serde::Deserialize)]
struct RequestsQuery {
    page: Option<usize>,
    per_page: Option<usize>,
}

async fn handle_get_requests(
    Path(tunnel_id): Path<String>,
    Query(query): Query<RequestsQuery>,
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Response<Body> {
    if let Err(response) = ensure_tunnel_access(&state, &headers, &tunnel_id).await {
        return response;
    }
    let per_page = query.per_page.unwrap_or(50).min(100);
    let page = query.page.unwrap_or(1).max(1);
    let offset = (page - 1) * per_page;

    let (requests, total) = state
        .request_log_store
        .get_entries(&tunnel_id, per_page, offset)
        .await;

    axum::Json(serde_json::json!({
        "requests": requests,
        "total": total,
        "page": page,
        "per_page": per_page,
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct SseTokenRequest {
    tunnel_id: String,
}

#[derive(serde::Serialize)]
struct SseTokenResponse {
    token: String,
}

async fn handle_create_sse_token(
    State(state): State<HttpState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    let user_id = match authenticate_platform_user(&state, &headers).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };

    let body: SseTokenRequest = match serde_json::from_slice(&body) {
        Ok(body) => body,
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("invalid json"))
                .unwrap_or_else(|_| Response::new(Body::from("bad request")));
        }
    };

    if !state.dev_mode && !user_owns_tunnel(&state, &user_id, &body.tunnel_id).await {
        return tunnel_not_found_response();
    }

    let exchange_token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );

    state.sse_tokens.insert(
        exchange_token.clone(),
        SseTokenEntry {
            tunnel_id: body.tunnel_id,
            created_at: Instant::now(),
        },
    );

    let resp_body = serde_json::to_vec(&SseTokenResponse {
        token: exchange_token,
    })
    .unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(resp_body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

async fn authenticate_platform_user(
    state: &HttpState,
    headers: &HeaderMap,
) -> Result<String, Response<Body>> {
    let Some(token) = extract_bearer_token(headers) else {
        return Err(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(Body::from("missing token"))
            .unwrap_or_else(|_| Response::new(Body::from("unauthorized"))));
    };

    if state.dev_mode {
        return Ok("dev-mode".to_string());
    }

    if let Some(local_api_keys) = state.local_api_keys.as_deref() {
        return validate_local_api_key(local_api_keys, token).ok_or_else(|| {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("invalid token"))
                .unwrap_or_else(|_| Response::new(Body::from("unauthorized")))
        });
    }

    let Some(url) = state.control_plane_url.as_deref() else {
        return Err(Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Body::from("auth source not configured"))
            .unwrap_or_else(|_| Response::new(Body::from("unavailable"))));
    };

    validate_token(url, token, &state.http_client)
        .await
        .ok_or_else(|| {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("invalid token"))
                .unwrap_or_else(|_| Response::new(Body::from("unauthorized")))
        })
}

async fn ensure_tunnel_access(
    state: &HttpState,
    headers: &HeaderMap,
    tunnel_id: &str,
) -> Result<String, Response<Body>> {
    let user_id = authenticate_platform_user(state, headers).await?;

    if state.dev_mode || user_owns_tunnel(state, &user_id, tunnel_id).await {
        Ok(user_id)
    } else {
        Err(tunnel_not_found_response())
    }
}

async fn user_owns_tunnel(state: &HttpState, user_id: &str, tunnel_id: &str) -> bool {
    if state
        .tunnel_metrics_store
        .owner_user_id(tunnel_id)
        .await
        .as_deref()
        == Some(user_id)
    {
        return true;
    }

    let Ok(parsed) = uuid::Uuid::from_str(tunnel_id) else {
        return false;
    };
    let tunnel_uuid = TunnelId(parsed);

    lookup_tunnel_in_registry(&state.registry, tunnel_uuid)
        .and_then(|entry| state.registry.user_id_for_connection(&entry.connection_id))
        .as_deref()
        == Some(user_id)
}

fn tunnel_not_found_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Body::from("tunnel not found"))
        .unwrap_or_else(|_| Response::new(Body::from("not found")))
}

#[derive(serde::Deserialize)]
struct StreamQuery {
    token: Option<String>,
}

async fn handle_requests_stream(
    Path(tunnel_id): Path<String>,
    Query(query): Query<StreamQuery>,
    State(state): State<HttpState>,
) -> Response<Body> {
    let token = match query.token {
        Some(t) if !t.is_empty() => t,
        _ => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("missing token"))
                .unwrap_or_else(|_| Response::new(Body::from("unauthorized")));
        }
    };

    if !state.dev_mode {
        let entry = state.sse_tokens.remove(&token);
        let Some((_, entry)) = entry else {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("invalid or expired token"))
                .unwrap_or_else(|_| Response::new(Body::from("unauthorized")));
        };

        if entry.created_at.elapsed() > Duration::from_secs(30) {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("token expired"))
                .unwrap_or_else(|_| Response::new(Body::from("unauthorized")));
        }

        if entry.tunnel_id != tunnel_id {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("token tunnel mismatch"))
                .unwrap_or_else(|_| Response::new(Body::from("unauthorized")));
        }
    }

    tracing::info!(tunnel_id = %tunnel_id, "SSE stream connected");

    let rx = state.request_log_store.subscribe(&tunnel_id).await;
    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(entry) => {
                    if let Ok(data) = serde_json::to_string(&entry) {
                        return Some((Ok::<_, Infallible>(Event::default().data(data)), rx));
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

#[allow(dead_code)]
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<HttpState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_websocket(socket, state.registry))
}

fn build_error_response(error: ProxyError, domain: &str) -> Response<Body> {
    if matches!(error, ProxyError::NotFound) {
        return Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header("location", format!("https://app.{}", domain))
            .body(Body::empty())
            .unwrap_or_else(|_| Response::new(Body::from("redirecting...")));
    }
    Response::builder()
        .status(error.status_code())
        .body(Body::from(error.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from("proxy error")))
}

fn build_rate_limited_response(
    error: RateLimitError,
    headers: Option<&RateLimitHeaders>,
) -> Response<Body> {
    let mut response = Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .body(Body::from(error.to_string()))
        .unwrap_or_else(|_| Response::new(Body::from("rate limit exceeded")));
    if let Some(headers) = headers {
        apply_rate_limit_headers(response.headers_mut(), headers);
        let retry_after = headers
            .reset_unix_seconds
            .saturating_sub(chrono::Utc::now().timestamp().max(0) as u64)
            .max(1);
        let _ = response.headers_mut().insert(
            HeaderName::from_static("retry-after"),
            HeaderValue::from_str(&retry_after.to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("1")),
        );
    }
    response
}

fn apply_rate_limit_headers(headers: &mut axum::http::HeaderMap, rate: &RateLimitHeaders) {
    let _ = headers.insert(
        HeaderName::from_static("x-ratelimit-limit"),
        HeaderValue::from_str(&rate.limit.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );
    let _ = headers.insert(
        HeaderName::from_static("x-ratelimit-remaining"),
        HeaderValue::from_str(&rate.remaining.to_string()).unwrap_or(HeaderValue::from_static("0")),
    );
    let _ = headers.insert(
        HeaderName::from_static("x-ratelimit-reset"),
        HeaderValue::from_str(&rate.reset_unix_seconds.to_string())
            .unwrap_or(HeaderValue::from_static("0")),
    );
}

fn request_content_length(request: &Request<Body>) -> u64 {
    request
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn response_content_length(response: &Response<Body>) -> u64 {
    response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::{COOKIE, SET_COOKIE};
    use serde_json::json;

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

    #[test]
    fn sensitive_headers_are_redacted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer secret-token"),
        );
        headers.insert(COOKIE, HeaderValue::from_static("session=abc"));
        headers.insert(SET_COOKIE, HeaderValue::from_static("api_key=xyz"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let json: serde_json::Value =
            serde_json::from_str(&headers_to_json(&headers)).expect("headers must serialize");

        let headers = json
            .as_array()
            .expect("headers should serialize as an array");
        let lookup = |name: &str| {
            headers
                .iter()
                .find(|entry| entry["name"] == name)
                .map(|entry| entry["value"].clone())
                .unwrap_or(serde_json::Value::Null)
        };

        assert_eq!(lookup("authorization"), "<redacted>");
        assert_eq!(lookup("cookie"), "<redacted>");
        assert_eq!(lookup("set-cookie"), "<redacted>");
        assert_eq!(lookup("content-type"), "application/json");
    }

    #[test]
    fn json_body_preview_redacts_sensitive_fields() {
        let preview = redact_body_preview(
            Some("application/json"),
            json!({
                "ok": "value",
                "access_token": "secret",
                "nested": {
                    "password": "hidden",
                    "session_id": "sid"
                }
            })
            .to_string(),
        );

        let value: serde_json::Value = serde_json::from_str(&preview).expect("valid json");
        assert_eq!(value["ok"], "value");
        assert_eq!(value["access_token"], "<redacted>");
        assert_eq!(value["nested"]["password"], "<redacted>");
        assert_eq!(value["nested"]["session_id"], "<redacted>");
    }

    #[test]
    fn form_body_preview_redacts_sensitive_fields() {
        let preview = redact_body_preview(
            Some("application/x-www-form-urlencoded"),
            "name=pike&token=secret&api_key=abc".to_string(),
        );

        assert_eq!(preview, "name=pike&token=<redacted>&api_key=<redacted>");
    }

    #[test]
    fn default_capture_policy_disables_body_previews() {
        let capture_config = TrafficInspectionConfig::default();

        assert!(!should_capture_body_preview(
            &capture_config,
            Some("application/json"),
            128,
        ));
    }
}
