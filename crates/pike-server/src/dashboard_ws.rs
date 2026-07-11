use std::sync::Arc;
use std::time::{Duration, Instant};

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
    /// Short-lived single-use ticket minted by `POST /api/v1/ws-ticket`. Preferred: it
    /// keeps the raw JWT out of the WebSocket URL (and therefore out of access logs).
    pub ticket: Option<String>,
    /// Legacy direct token (self-hosted static api key, or JWT). Kept as a resilient
    /// fallback for clients that can't obtain a ticket.
    pub token: Option<String>,
}

/// Time-to-live for a `ws-ticket`. Long enough to cover a fetch + WebSocket open,
/// short enough that a leaked ticket is near-useless. Tickets are also single-use.
pub(crate) const WS_TICKET_TTL: Duration = Duration::from_secs(30);

/// A minted WebSocket auth ticket: the authenticated user plus its creation time.
#[derive(Debug)]
pub(crate) struct WsTicketEntry {
    pub user_id: String,
    pub created_at: Instant,
}

/// Shared store of outstanding `ws-ticket`s. Cloned into both the HTTP state (which
/// mints tickets) and the dashboard WebSocket state (which consumes them).
pub(crate) type WsTicketStore = Arc<DashMap<String, WsTicketEntry>>;

fn ws_error(status: StatusCode, msg: &'static str) -> axum::response::Response {
    Response::builder()
        .status(status)
        .body(Body::from(msg))
        .unwrap_or_else(|_| Response::new(Body::from("error")))
        .into_response()
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
    pub(crate) ws_tickets: WsTicketStore,
}

/// Resolve the authenticated user for a dashboard WebSocket connection. Prefers a
/// single-use `ticket`; falls back to the legacy `token` (self-hosted static key or JWT)
/// so older/degraded clients keep working.
async fn authenticate_dashboard_ws(
    state: &DashboardWsState,
    query: &DashboardWsQuery,
) -> Result<String, axum::response::Response> {
    // Preferred path: a short-lived, single-use ticket. Consume it (remove) regardless of
    // expiry so a ticket can never be replayed.
    if let Some(ticket) = query.ticket.as_deref().filter(|t| !t.is_empty()) {
        return match state.ws_tickets.remove(ticket) {
            Some((_, entry)) if entry.created_at.elapsed() <= WS_TICKET_TTL => Ok(entry.user_id),
            _ => Err(ws_error(StatusCode::UNAUTHORIZED, "invalid or expired ticket")),
        };
    }

    // Legacy fallback: a token in the query string.
    let token = match query.token.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => return Err(ws_error(StatusCode::UNAUTHORIZED, "missing ticket")),
    };

    if let Some(local_keys) = state.local_api_keys.as_deref() {
        return validate_local_api_key(local_keys, token)
            .ok_or_else(|| ws_error(StatusCode::UNAUTHORIZED, "invalid token"));
    }

    let Some(ref url) = state.control_plane_url else {
        return Err(ws_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth source not configured",
        ));
    };
    validate_token(url, token, &state.http_client)
        .await
        .ok_or_else(|| ws_error(StatusCode::UNAUTHORIZED, "invalid token"))
}

/// Axum handler for `GET /ws/dashboard?ticket=...` (preferred) or `?token=...` (legacy).
pub async fn dashboard_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<DashboardWsState>,
    Query(query): Query<DashboardWsQuery>,
) -> impl IntoResponse {
    let user_id = match authenticate_dashboard_ws(&state, &query).await {
        Ok(uid) => uid,
        Err(response) => return response,
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
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(_)) => {} // ignore other messages
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

#[cfg(test)]
mod tests {
    use super::*;

    fn state(ws_tickets: WsTicketStore, local_api_keys: Option<Vec<String>>) -> DashboardWsState {
        DashboardWsState {
            broadcaster: Arc::new(DashboardBroadcaster::new()),
            control_plane_url: None,
            local_api_keys,
            http_client: reqwest::Client::new(),
            dev_mode: false,
            ws_tickets,
        }
    }

    fn query(ticket: Option<&str>, token: Option<&str>) -> DashboardWsQuery {
        DashboardWsQuery {
            ticket: ticket.map(str::to_string),
            token: token.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn valid_ticket_authenticates_and_is_single_use() {
        let tickets: WsTicketStore = Arc::new(DashMap::new());
        tickets.insert(
            "abc".to_string(),
            WsTicketEntry {
                user_id: "user-1".to_string(),
                created_at: Instant::now(),
            },
        );
        let st = state(tickets, None);

        let first = authenticate_dashboard_ws(&st, &query(Some("abc"), None)).await;
        assert_eq!(first.unwrap(), "user-1");

        // Second use must fail — the ticket was consumed.
        let second = authenticate_dashboard_ws(&st, &query(Some("abc"), None)).await;
        assert_eq!(second.unwrap_err().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_ticket_is_rejected_and_consumed() {
        let tickets: WsTicketStore = Arc::new(DashMap::new());
        let past = Instant::now()
            .checked_sub(WS_TICKET_TTL + Duration::from_secs(5))
            .expect("instant in the past");
        tickets.insert(
            "old".to_string(),
            WsTicketEntry {
                user_id: "user-1".to_string(),
                created_at: past,
            },
        );
        let st = state(tickets.clone(), None);

        let res = authenticate_dashboard_ws(&st, &query(Some("old"), None)).await;
        assert_eq!(res.unwrap_err().status(), StatusCode::UNAUTHORIZED);
        // Even an expired ticket is removed so it can't be retried.
        assert!(tickets.is_empty());
    }

    #[tokio::test]
    async fn legacy_local_api_key_token_still_works() {
        let st = state(
            Arc::new(DashMap::new()),
            Some(vec!["pk_self_hosted".to_string()]),
        );
        let ok = authenticate_dashboard_ws(&st, &query(None, Some("pk_self_hosted"))).await;
        assert!(ok.unwrap().starts_with("local-"));

        let bad = authenticate_dashboard_ws(&st, &query(None, Some("wrong"))).await;
        assert_eq!(bad.unwrap_err().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_ticket_and_token_is_rejected() {
        let st = state(Arc::new(DashMap::new()), None);
        let res = authenticate_dashboard_ws(&st, &query(None, None)).await;
        assert_eq!(res.unwrap_err().status(), StatusCode::UNAUTHORIZED);
    }
}
