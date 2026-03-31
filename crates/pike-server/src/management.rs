use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use crate::metrics::metrics_handler;
use anyhow::Context;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header::AUTHORIZATION, Request, Response, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use tower::ServiceBuilder;
use tower_http::auth::{AsyncAuthorizeRequest, AsyncRequireAuthorizationLayer};

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
        .with_state(state)
        .layer(
            ServiceBuilder::new().layer(AsyncRequireAuthorizationLayer::new(
                InternalTokenAuth::new(internal_token),
            )),
        );

    Router::new().merge(authenticated)
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
