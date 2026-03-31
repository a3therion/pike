use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::http::{Response, StatusCode};
use axum::response::IntoResponse;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;
use tracing::{info, warn};

/// Per-user broadcast fanout for real-time dashboard events.
#[derive(Debug)]
pub struct DashboardBroadcaster {
    channels: DashMap<String, broadcast::Sender<String>>,
}

impl DashboardBroadcaster {
    #[must_use]
    pub fn new() -> Self {
        Self {
            channels: DashMap::new(),
        }
    }

    /// Get or create a broadcast receiver for a user.
    pub fn subscribe(&self, user_id: &str) -> broadcast::Receiver<String> {
        let entry = self
            .channels
            .entry(user_id.to_string())
            .or_insert_with(|| broadcast::channel(256).0);
        entry.subscribe()
    }

    /// Broadcast a JSON event to all subscribers for a user.
    /// Silently drops if no subscribers exist.
    pub fn broadcast(&self, user_id: &str, event_json: &str) {
        if let Some(sender) = self.channels.get(user_id) {
            // send returns Err if there are no active receivers — that's fine
            let _ = sender.send(event_json.to_string());
        }
    }

    /// Remove a user's channel if no subscribers remain.
    pub fn remove_if_empty(&self, user_id: &str) {
        if let Some(entry) = self.channels.get(user_id) {
            if entry.receiver_count() == 0 {
                drop(entry);
                self.channels.remove(user_id);
            }
        }
    }
}

impl Default for DashboardBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

/// Events sent over the dashboard WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::large_enum_variant)]
pub enum DashboardEvent {
    #[serde(rename = "live_request")]
    LiveRequest {
        tunnel_id: String,
        subdomain: String,
        method: String,
        path: String,
        status_code: u16,
        response_time_ms: u64,
        bytes: u64,
        client_ip: String,
        timestamp: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        request_headers: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        request_body: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        response_headers: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        response_body: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        request_content_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        response_content_type: Option<String>,
    },
    #[serde(rename = "tunnel_status")]
    TunnelStatus {
        tunnel_id: String,
        subdomain: String,
        status: String,
    },
}

#[derive(Debug, Deserialize)]
pub struct DashboardWsQuery {
    pub token: Option<String>,
}

/// Validate a JWT token by calling the Workers API.
/// Returns the user_id on success.
pub(crate) async fn validate_token(
    control_plane_url: &str,
    token: &str,
    http_client: &reqwest::Client,
) -> Option<String> {
    let url = format!(
        "{}/api/v1/auth/validate",
        control_plane_url.trim_end_matches('/')
    );
    let response = http_client
        .post(&url)
        .header("Authorization", format!("Bearer {token}"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;

    if !response.status().is_success() {
        return None;
    }

    #[derive(Deserialize)]
    struct ValidateResponse {
        user_id: String,
    }

    let body: ValidateResponse = response.json().await.ok()?;
    Some(body.user_id)
}

pub(crate) fn validate_local_api_key(local_api_keys: &[String], token: &str) -> Option<String> {
    if !local_api_keys.iter().any(|key| key == token) {
        return None;
    }

    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    Some(format!("local-{:x}", hasher.finalize()))
}

/// State passed into the dashboard WebSocket handler.
#[derive(Clone)]
pub struct DashboardWsState {
    pub broadcaster: Arc<DashboardBroadcaster>,
    pub control_plane_url: Option<String>,
    pub local_api_keys: Option<Vec<String>>,
    pub http_client: reqwest::Client,
    pub dev_mode: bool,
}

/// Axum handler for `GET /ws/dashboard?token=...`
pub async fn dashboard_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<DashboardWsState>,
    Query(query): Query<DashboardWsQuery>,
) -> impl IntoResponse {
    let token = match query.token {
        Some(t) if !t.is_empty() => t,
        _ => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("missing token"))
                .unwrap_or_else(|_| Response::new(Body::from("unauthorized")))
                .into_response();
        }
    };

    let user_id = if let Some(local_keys) = state.local_api_keys.as_deref() {
        match validate_local_api_key(local_keys, &token) {
            Some(uid) => uid,
            None => {
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::from("invalid token"))
                    .unwrap_or_else(|_| Response::new(Body::from("unauthorized")))
                    .into_response();
            }
        }
    } else {
        let Some(ref url) = state.control_plane_url else {
            return Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("auth source not configured"))
                .unwrap_or_else(|_| Response::new(Body::from("unavailable")))
                .into_response();
        };
        match validate_token(url, &token, &state.http_client).await {
            Some(uid) => uid,
            None => {
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::from("invalid token"))
                    .unwrap_or_else(|_| Response::new(Body::from("unauthorized")))
                    .into_response();
            }
        }
    };

    info!(user_id = %user_id, "dashboard WebSocket upgrading");

    let broadcaster = state.broadcaster.clone();
    ws.on_upgrade(move |socket| handle_dashboard_ws(socket, broadcaster, user_id))
        .into_response()
}

async fn handle_dashboard_ws(
    mut socket: WebSocket,
    broadcaster: Arc<DashboardBroadcaster>,
    user_id: String,
) {
    info!(user_id = %user_id, "dashboard WebSocket connected");

    let mut rx = broadcaster.subscribe(&user_id);
    let mut ping_interval = tokio::time::interval(Duration::from_secs(30));
    ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            event = rx.recv() => {
                match event {
                    Ok(json) => {
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(user_id = %user_id, skipped = n, "dashboard ws lagged");
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {} // ignore other messages
                    Some(Err(_)) => break,
                }
            }
            _ = ping_interval.tick() => {
                if socket.send(Message::Ping(vec![].into())).await.is_err() {
                    break;
                }
            }
        }
    }

    info!(user_id = %user_id, "dashboard WebSocket disconnected");
    broadcaster.remove_if_empty(&user_id);
}
