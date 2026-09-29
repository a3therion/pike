use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use std::str::FromStr;

use crate::metrics::metrics_handler;
use anyhow::Context;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{header::AUTHORIZATION, Request, Response, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use pike_core::types::TunnelId;
use serde::Serialize;
use serde_json::json;
use tower::ServiceBuilder;
use tower_http::auth::{AsyncAuthorizeRequest, AsyncRequireAuthorizationLayer};
use uuid::Uuid;

use crate::registry::ClientRegistry;

#[derive(Clone)]
struct ManagementState {
    registry: Arc<ClientRegistry>,
}

#[derive(Debug, Clone)]
struct InternalTokenAuth {
    expected_bearer: String,
}

impl InternalTokenAuth {
    fn new(internal_token: &str) -> Self {
        Self {
            expected_bearer: format!("Bearer {internal_token}"),
        }
    }
}

impl<B> AsyncAuthorizeRequest<B> for InternalTokenAuth
where
    B: Send + 'static,
{
    type RequestBody = B;
    type ResponseBody = Body;
    type Future = std::future::Ready<Result<Request<B>, Response<Self::ResponseBody>>>;

    fn authorize(&mut self, request: Request<B>) -> Self::Future {
        let is_authorized = request
            .headers()
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|header| header == self.expected_bearer);

        if is_authorized {
            return std::future::ready(Ok(request));
        }

        let response = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"error": "missing or invalid authorization token"}).to_string(),
            ))
            .unwrap_or_else(|_| Response::new(Body::from("unauthorized")));
        std::future::ready(Err(response))
    }
}

#[derive(Debug, Serialize)]
pub struct TunnelListResponse {
    tunnels: Vec<TunnelInfo>,
}

#[derive(Debug, Serialize)]
pub struct TunnelInfo {
    id: String,
    subdomain: String,
    tunnel_type: String,
    active_connections: usize,
    bytes_in: u64,
    bytes_out: u64,
    created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct StatsResponse {
    uptime_seconds: u64,
    total_connections: usize,
    active_tunnels: usize,
    total_bytes_in: u64,
    total_bytes_out: u64,
    requests_per_minute: f64,
}

#[derive(Debug, Serialize)]
pub struct ConnectionsResponse {
    connections: Vec<ConnectionInfo>,
}

#[derive(Debug, Serialize)]
pub struct ConnectionInfo {
    id: String,
    client_addr: String,
    tunnels: Vec<String>,
    connected_at: DateTime<Utc>,
    last_heartbeat: DateTime<Utc>,
}

pub fn management_router(registry: Arc<ClientRegistry>, internal_token: &str) -> Router {
    let state = ManagementState { registry };
    let authenticated = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/api/tunnels", get(get_tunnels))
        .route("/api/stats", get(get_stats))
        .route("/api/connections", get(get_connections))
        // Fix #6c: authenticated push endpoints that act on the LIVE registry so the
        // control-plane admin gets an immediate enforcement path. They degrade
        // gracefully: if unreachable, the D1 status + session revalidation still enforces.
        .route("/api/tunnels/{id}/suspend", post(suspend_tunnel_handler))
        .route(
            "/api/tunnels/{id}/unsuspend",
            post(unsuspend_tunnel_handler),
        )
        .route("/api/users/{id}/disconnect", post(disconnect_user_handler))
        .route("/api/users/{id}/ban", post(ban_user_handler))
        .route("/api/users/{id}/unban", post(unban_user_handler))
        .route("/api/ingress/routes", get(get_ingress_routes))
        .with_state(state)
        .layer(
            ServiceBuilder::new().layer(AsyncRequireAuthorizationLayer::new(
                InternalTokenAuth::new(internal_token),
            )),
        );

    Router::new().merge(authenticated)
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IngressQuery {
    nonce: String,
}

async fn get_ingress_routes(
    State(state): State<ManagementState>,
    Query(query): Query<IngressQuery>,
) -> Response<Body> {
    if query.nonce.len() != 32 || !query.nonce.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("cache-control", "no-store")
            .body(Body::from("invalid nonce"))
            .unwrap();
    }
    let result = state
        .registry
        .ingress
        .snapshot(&query.nonce)
        .and_then(|snapshot| Ok(serde_json::to_vec(&snapshot)?))
        .and_then(|body| {
            anyhow::ensure!(
                body.len() <= crate::ingress_directory::MAX_RESPONSE_BYTES,
                "ingress snapshot too large"
            );
            Ok(body)
        });
    match result {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("cache-control", "no-store")
            .body(Body::from(body))
            .unwrap(),
        Err(error) => {
            tracing::warn!(%error, "ingress snapshot unavailable");
            Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("cache-control", "no-store")
                .body(Body::from("ingress snapshot unavailable"))
                .unwrap()
        }
    }
}

pub async fn run_management_server(
    bind_addr: SocketAddr,
    registry: Arc<ClientRegistry>,
    internal_token: String,
) -> anyhow::Result<()> {
    let app = management_router(registry, &internal_token);

    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind management API on {bind_addr}"))?;
    tracing::info!(bind_addr = %bind_addr, "management API listener ready");

    axum::serve(listener, app)
        .await
        .context("management API server terminated unexpectedly")?;
    Ok(())
}

async fn get_tunnels(State(state): State<ManagementState>) -> Json<TunnelListResponse> {
    let mut tunnels = Vec::new();
    for tunnel in &state.registry.tunnels {
        let tunnel_type = if state.registry.tcp_listeners.contains_key(&tunnel.tunnel_id) {
            "tcp"
        } else {
            "http"
        };
        let active_connections = usize::from(
            tunnel.active
                && state
                    .registry
                    .clients
                    .get(&tunnel.connection_id)
                    .is_some_and(|client| {
                        client.state != crate::connection::ConnectionState::Closed
                    }),
        );

        tunnels.push(TunnelInfo {
            id: tunnel.tunnel_id.to_string(),
            subdomain: tunnel.key().clone(),
            tunnel_type: tunnel_type.to_string(),
            active_connections,
            bytes_in: tunnel.bytes_in,
            bytes_out: tunnel.bytes_out,
            created_at: tunnel.created_at,
        });
    }

    Json(TunnelListResponse { tunnels })
}

async fn get_stats(State(state): State<ManagementState>) -> Json<StatsResponse> {
    let active_tunnels = state
        .registry
        .tunnels
        .iter()
        .filter(|entry| entry.active)
        .count();
    Json(StatsResponse {
        uptime_seconds: state.registry.uptime_seconds(),
        total_connections: state.registry.total_connections.load(Ordering::Relaxed),
        active_tunnels,
        total_bytes_in: state.registry.total_bytes_in.load(Ordering::Relaxed),
        total_bytes_out: state.registry.total_bytes_out.load(Ordering::Relaxed),
        requests_per_minute: state.registry.requests_per_minute(),
    })
}

async fn get_connections(State(state): State<ManagementState>) -> Json<ConnectionsResponse> {
    let mut connections = Vec::new();
    for connection in &state.registry.clients {
        let client_addr = connection
            .info
            .remote_addr
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let tunnels = connection.tunnels.iter().map(ToString::to_string).collect();
        connections.push(ConnectionInfo {
            id: connection.info.connection_id.to_string(),
            client_addr,
            tunnels,
            connected_at: connection.connected_at,
            last_heartbeat: connection.last_heartbeat_at,
        });
    }

    Json(ConnectionsResponse { connections })
}

fn json_ok(message: &str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({ "status": "ok", "message": message }).to_string(),
        ))
        .unwrap_or_else(|_| Response::new(Body::from("ok")))
}

fn json_error(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(json!({ "error": message }).to_string()))
        .unwrap_or_else(|_| Response::new(Body::from("error")))
}

/// POST /api/tunnels/:id/suspend — suspend a tunnel on the live registry (persists to
/// the state store via the abuse detector). The Worker sends the canonical DB UUID,
/// while traffic enforcement keys on runtime tunnel IDs, so the ID is resolved to
/// every registered runtime member before suspending.
async fn suspend_tunnel_handler(
    State(state): State<ManagementState>,
    Path(tunnel_id): Path<String>,
) -> Response<Body> {
    let Ok(parsed) = Uuid::from_str(&tunnel_id) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid tunnel_id");
    };
    match state.registry.suspend_tunnel_identity(TunnelId(parsed)) {
        Ok(members) => {
            tracing::warn!(
                tunnel_id = %tunnel_id,
                runtime_members = ?members,
                "tunnel suspended via management API"
            );
            json_ok("tunnel suspended")
        }
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

/// POST /api/tunnels/:id/unsuspend — lift a tunnel suspension on the live registry
/// (clears the state-store record via the abuse detector) for the ID and every
/// registered runtime member, mirroring the suspend handler.
async fn unsuspend_tunnel_handler(
    State(state): State<ManagementState>,
    Path(tunnel_id): Path<String>,
) -> Response<Body> {
    let Ok(parsed) = Uuid::from_str(&tunnel_id) else {
        return json_error(StatusCode::BAD_REQUEST, "invalid tunnel_id");
    };
    match state.registry.unsuspend_tunnel_identity(TunnelId(parsed)) {
        Ok(members) => {
            tracing::warn!(
                tunnel_id = %tunnel_id,
                runtime_members = ?members,
                "tunnel unsuspended via management API"
            );
            json_ok("tunnel unsuspended")
        }
        Err(error) => json_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string()),
    }
}

/// POST /api/users/:id/disconnect — tear down a user's live QUIC connections and
/// revoke their session api keys (without a persistent ban).
async fn disconnect_user_handler(
    State(state): State<ManagementState>,
    Path(user_id): Path<String>,
) -> Response<Body> {
    if let Err(error) = state.registry.kill_user_tunnels(&user_id) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    tracing::warn!(user_id = %user_id, "user disconnected via management API");
    json_ok("user disconnected")
}

/// POST /api/users/:id/ban — persistently ban a user and immediately disconnect their
/// live connections + revoke their session api keys.
async fn ban_user_handler(
    State(state): State<ManagementState>,
    Path(user_id): Path<String>,
) -> Response<Body> {
    if let Err(error) = state.registry.abuse_detector.ban_user(user_id.clone()) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    if let Err(error) = state.registry.kill_user_tunnels(&user_id) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    tracing::warn!(user_id = %user_id, "user banned via management API");
    json_ok("user banned")
}

/// POST /api/users/:id/unban — lift a ban and restore the user's revoked api keys.
async fn unban_user_handler(
    State(state): State<ManagementState>,
    Path(user_id): Path<String>,
) -> Response<Body> {
    if let Err(error) = state.registry.abuse_detector.unban_user(user_id.clone()) {
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string());
    }
    state.registry.restore_user_api_keys(&user_id);
    tracing::info!(user_id = %user_id, "user unbanned via management API");
    json_ok("user unbanned")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::management_router;
    use crate::connection::ClientConnection;
    use crate::registry::ClientRegistry;

    const TOKEN: &str = "test-token";

    #[tokio::test]
    async fn rejects_request_without_bearer_token() {
        let app = management_router(Arc::new(ClientRegistry::new()), TOKEN);
        let request = Request::builder()
            .uri("/api/stats")
            .body(Body::empty())
            .expect("request");

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rejects_metrics_without_bearer_token() {
        let app = management_router(Arc::new(ClientRegistry::new()), TOKEN);
        let request = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .expect("request");

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn returns_stats_with_valid_token() {
        let registry = Arc::new(ClientRegistry::new());
        registry
            .register_client(ClientConnection::new(uuid::Uuid::new_v4(), None))
            .ok();
        registry.record_request();
        let app = management_router(registry, TOKEN);

        let request = Request::builder()
            .uri("/api/stats")
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .expect("request");

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 8 * 1024)
            .await
            .expect("body bytes");
        let payload: Value = serde_json::from_slice(&body).expect("json payload");
        assert_eq!(payload["total_connections"], 1);
        assert!(payload["uptime_seconds"].as_u64().is_some());
    }

    #[tokio::test]
    async fn returns_connections_with_valid_token() {
        let registry = Arc::new(ClientRegistry::new());
        let _ = registry.register_client(ClientConnection::new(
            uuid::Uuid::new_v4(),
            Some("127.0.0.1:50001".parse().expect("socket")),
        ));
        let app = management_router(registry, TOKEN);

        let request = Request::builder()
            .uri("/api/connections")
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .expect("request");

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), 8 * 1024)
            .await
            .expect("body bytes");
        let payload: Value = serde_json::from_slice(&body).expect("json payload");
        let connections = payload["connections"]
            .as_array()
            .expect("connections array");
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0]["client_addr"], "127.0.0.1:50001");
    }

    #[tokio::test]
    async fn suspend_endpoint_requires_token() {
        let app = management_router(Arc::new(ClientRegistry::new()), TOKEN);
        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/tunnels/{}/suspend", uuid::Uuid::new_v4()))
            .body(Body::empty())
            .expect("request");

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn suspend_endpoint_suspends_with_valid_token() {
        let registry = Arc::new(ClientRegistry::new());
        let tunnel_id = pike_core::types::TunnelId::new();
        let app = management_router(registry.clone(), TOKEN);

        let request = Request::builder()
            .method("POST")
            .uri(format!("/api/tunnels/{tunnel_id}/suspend"))
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .expect("request");

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(registry.abuse_detector.is_suspended(&tunnel_id));
    }

    /// The Worker addresses tunnels by canonical DB UUID, but forwarders check the
    /// runtime tunnel ID. Suspend/unsuspend must cover every runtime member of that
    /// canonical identity and leave unrelated tunnels alone.
    #[tokio::test]
    async fn suspend_and_unsuspend_cover_every_runtime_member_of_a_canonical_id() {
        use pike_core::types::TunnelId;

        let registry = Arc::new(ClientRegistry::new());
        let add_tunnel = |host: &str, canonical: &str| {
            let conn_id = uuid::Uuid::new_v4();
            let mut client = ClientConnection::new(conn_id, None);
            client.state = crate::connection::ConnectionState::Authenticated;
            registry.register_client(client).expect("register client");
            let runtime = TunnelId::new();
            registry
                .register_new_tunnel(conn_id, host.into(), runtime, canonical.into(), true)
                .expect("register tunnel");
            runtime
        };

        let canonical = uuid::Uuid::new_v4();
        let member_a = add_tunnel("member-a.test", &canonical.to_string());
        let member_b = add_tunnel("member-b.test", &canonical.to_string());
        let unrelated = add_tunnel("unrelated.test", &uuid::Uuid::new_v4().to_string());
        assert_ne!(member_a, member_b);
        // The latest-runtime mapping alone only knows one member.
        assert_eq!(
            registry.runtime_tunnel_id(&canonical.to_string()),
            member_b.to_string()
        );

        let app = management_router(registry.clone(), TOKEN);
        let post = |path: String| {
            Request::builder()
                .method("POST")
                .uri(path)
                .header("authorization", format!("Bearer {TOKEN}"))
                .body(Body::empty())
                .expect("request")
        };

        let response = app
            .clone()
            .oneshot(post(format!("/api/tunnels/{canonical}/suspend")))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        let detector = &registry.abuse_detector;
        assert!(detector.is_suspended(&member_a));
        assert!(detector.is_suspended(&member_b));
        assert!(detector.is_suspended(&TunnelId(canonical)));
        assert!(!detector.is_suspended(&unrelated));
        assert!(registry.lookup_tunnel("unrelated.test").is_some());

        let response = app
            .oneshot(post(format!("/api/tunnels/{canonical}/unsuspend")))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(!detector.is_suspended(&member_a));
        assert!(!detector.is_suspended(&member_b));
        assert!(!detector.is_suspended(&TunnelId(canonical)));
        assert!(!detector.is_suspended(&unrelated));
        // Suspension never removes routing for anyone.
        assert_eq!(registry.active_tunnels(), 3);
    }

    #[tokio::test]
    async fn ban_endpoint_bans_with_valid_token() {
        let registry = Arc::new(ClientRegistry::new());
        let app = management_router(registry.clone(), TOKEN);

        let request = Request::builder()
            .method("POST")
            .uri("/api/users/user-123/ban")
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .expect("request");

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
        assert!(registry.abuse_detector.is_banned(&"user-123".to_string()));
    }

    #[tokio::test]
    async fn returns_metrics_with_valid_token() {
        let app = management_router(Arc::new(ClientRegistry::new()), TOKEN);
        let request = Request::builder()
            .uri("/metrics")
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .expect("request");

        let response = app.oneshot(request).await.expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }
}
