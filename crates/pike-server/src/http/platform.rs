//! Authenticated dashboard APIs, request streams and transport upgrades.
use super::{HttpState, SseTokenEntry};
use crate::dashboard_ws::{
    dashboard_ws_handler, validate_local_api_key, DashboardWsState, WsTicketEntry,
};
use crate::registry::ClientRegistry;
use crate::tunnel_metrics::MetricsRange;
use axum::{
    body::{Body, Bytes},
    extract::{ws::WebSocketUpgrade, ConnectInfo, Path, Query, State},
    http::{
        header::{HeaderValue, AUTHORIZATION},
        HeaderMap, Request, Response, StatusCode,
    },
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse,
    },
    routing::get,
    Router,
};
use pike_core::types::TunnelId;
use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    time::{Duration, Instant},
};
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
pub(super) async fn dispatch_platform_request(
    state: HttpState,
    req: Request<Body>,
) -> Response<Body> {
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

pub(super) fn platform_health_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"status":"healthy","service":"pike-server"}"#,
        ))
        .unwrap_or_else(|_| Response::new(Body::from("OK")))
}

pub(super) fn is_platform_host(host: &str, domain: &str) -> bool {
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
    let tunnel_id = state.registry.runtime_tunnel_id(&tunnel_id);
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
    let active_tunnels = state.registry.active_tunnels() as u64;
    let resp = state
        .tunnel_metrics_store
        .metrics_response(&tunnel_id, uptime_seconds, active_tunnels)
        .await;
    (StatusCode::OK, axum::Json(resp)).into_response()
}

async fn handle_get_metrics_timeseries(
    Path(tunnel_id): Path<String>,
    Query(query): Query<TimeseriesQuery>,
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Response<Body> {
    let tunnel_id = state.registry.runtime_tunnel_id(&tunnel_id);
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
    let tunnel_id = state.registry.runtime_tunnel_id(&tunnel_id);
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
    let transport = registry_entry.as_ref().and_then(|entry| {
        state
            .registry
            .clients
            .get(&entry.connection_id)
            .map(|client| client.info.transport)
    });
    let snapshot = state.tunnel_metrics_store.snapshot_times(&tunnel_id).await;
    let streaming = state
        .tunnel_metrics_store
        .streaming_status(&tunnel_id)
        .await;

    let now = chrono::Utc::now();

    let (status, mut connected_since, mut uptime_seconds) = if let Some(entry) = registry_entry {
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

    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "status": status,
            "uptime_seconds": uptime_seconds,
            "last_activity": last_activity,
            "connected_since": connected_since,
            "transport": transport,
            "wss_connections": streaming.wss_connections,
            "reconnects": streaming.reconnects,
            "close_reason": streaming.close_reason,
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

    let tunnel_id = public_log_id(&state, &tunnel_id);
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
            user_id,
            authorization: headers
                .get(AUTHORIZATION)
                .cloned()
                .unwrap_or_else(|| HeaderValue::from_static("")),
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

#[derive(serde::Serialize)]
struct WsTicketResponse {
    ticket: String,
}

/// POST /api/v1/ws-ticket — mint a short-lived, single-use ticket for the dashboard
/// WebSocket so the raw JWT never appears in the WS URL (and therefore not in access
/// logs). Authenticated by the caller's Bearer token — a JWT, a self-hosted static api
/// key, or dev mode — exactly like the sse-token endpoint. The ticket carries the
/// credential so the live connection keeps revalidating it after the upgrade.
async fn handle_create_ws_ticket(
    State(state): State<HttpState>,
    headers: HeaderMap,
) -> Response<Body> {
    let user_id = match authenticate_platform_user(&state, &headers).await {
        Ok(user_id) => user_id,
        Err(response) => return response,
    };
    let credential = extract_bearer_token(&headers)
        .unwrap_or_default()
        .to_string();

    let ticket = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );

    state.ws_tickets.insert(
        ticket.clone(),
        WsTicketEntry {
            user_id,
            credential,
            created_at: Instant::now(),
        },
    );

    let resp_body = serde_json::to_vec(&WsTicketResponse { ticket }).unwrap_or_default();
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

// These guards return the ready-to-send rejection response as their `Err`, the
// idiomatic axum shape; boxing it would add allocation without changing behaviour.
#[allow(clippy::result_large_err)]
async fn authenticate_platform_user(
    state: &HttpState,
    headers: &HeaderMap,
) -> Result<String, Response<Body>> {
    authenticate_platform_user_for_scope(state, headers, "analytics:read").await
}

#[allow(clippy::result_large_err)]
pub(super) async fn authenticate_platform_user_for_scope(
    state: &HttpState,
    headers: &HeaderMap,
    scope: &str,
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

    crate::dashboard_ws::validate_token_scopes(url, token, &state.http_client, &[scope])
        .await
        .ok_or_else(|| {
            Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("invalid token"))
                .unwrap_or_else(|_| Response::new(Body::from("unauthorized")))
        })
}

#[allow(clippy::result_large_err)]
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

fn public_log_id(state: &HttpState, id: &str) -> String {
    uuid::Uuid::parse_str(&state.registry.runtime_tunnel_id(id)).map_or_else(
        |_| id.to_owned(),
        |runtime| state.registry.public_tunnel_id(TunnelId(runtime)),
    )
}

async fn user_owns_tunnel(state: &HttpState, user_id: &str, tunnel_id: &str) -> bool {
    let runtime_id = state.registry.runtime_tunnel_id(tunnel_id);
    let tunnel_id = runtime_id.as_str();
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

    let mut stream_auth = None;
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
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, entry.authorization);
        if authenticate_platform_user(&state, &headers)
            .await
            .as_deref()
            .ok()
            != Some(entry.user_id.as_str())
        {
            return StatusCode::UNAUTHORIZED.into_response();
        }
        stream_auth = Some((headers, entry.user_id));
    }

    tracing::info!(tunnel_id = %tunnel_id, "SSE stream connected");

    let log_id = public_log_id(&state, &tunnel_id);
    let mut rx = state.request_log_store.subscribe(&log_id).await;
    let stream = async_stream::stream! {
        let mut validation = tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(30), Duration::from_secs(30));
        loop {
            tokio::select! {
                _ = validation.tick(), if stream_auth.is_some() => {
                    if let Some((headers, user_id)) = &stream_auth {
                        if authenticate_platform_user(&state, headers).await.as_deref().ok() != Some(user_id.as_str()) { break; }
                    }
                }
                entry = rx.recv() => match entry {
                    Ok(entry) => {
                        if let Ok(data) = serde_json::to_string(&entry) { yield Ok::<_, Infallible>(Event::default().data(data)); }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {},
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(state): State<HttpState>,
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
) -> axum::response::Response {
    let Some(accept_tx) = state.tunnel_accept_tx else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(login_permit) = state.pending_tunnel_logins.try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let Ok(permit) = accept_tx.try_reserve_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    ws.max_message_size(pike_core::websocket::MAX_MESSAGE_SIZE)
        .max_frame_size(pike_core::websocket::MAX_MESSAGE_SIZE)
        .on_upgrade(move |socket| async move {
            permit.send(crate::websocket::AcceptedWebSocket {
                socket,
                peer_addr,
                login_permit,
            });
        })
        .into_response()
}

pub(super) fn router(
    state: HttpState,
    ws_state: DashboardWsState,
    cors_layer: CorsLayer,
) -> Router {
    Router::new()
        .route("/ws/tunnel", get(websocket_handler))
        .route(
            "/api/v1/tunnels/{tunnel_id}/replay",
            axum::routing::post(super::replay::handle),
        )
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
        .route(
            "/api/v1/ws-ticket",
            axum::routing::post(handle_create_ws_ticket),
        )
        .with_state(state)
        .layer(cors_layer)
}
