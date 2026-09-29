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

/// A minted WebSocket auth ticket: the authenticated user, the bearer credential the
/// ticket was minted with (so the live connection keeps revalidating it, exactly like
/// a legacy `?token=` connection) and its creation time.
#[derive(Debug)]
pub(crate) struct WsTicketEntry {
    pub user_id: String,
    pub credential: String,
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

/// Validate a live dashboard credential through Workers. API keys must carry
/// analytics:read; identity validation alone does not authorize captured traffic.
pub(crate) async fn validate_token(
    control_plane_url: &str,
    token: &str,
    http_client: &reqwest::Client,
) -> Option<String> {
    validate_token_scopes(control_plane_url, token, http_client, &["analytics:read"]).await
}

pub(crate) async fn validate_token_scopes(
    control_plane_url: &str,
    token: &str,
    http_client: &reqwest::Client,
    required_scopes: &[&str],
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
        #[serde(default)]
        valid: bool,
        user_id: String,
        auth_type: String,
        #[serde(default)]
        scopes: Option<Vec<String>>,
    }

    let body: ValidateResponse = response.json().await.ok()?;
    let permitted = body.auth_type == "jwt"
        || (body.auth_type == "apikey"
            && body.scopes.as_ref().is_some_and(|scopes| {
                required_scopes
                    .iter()
                    .all(|required| scopes.iter().any(|scope| scope == required))
            }));
    (body.valid && !body.user_id.is_empty() && permitted).then_some(body.user_id)
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

/// Resolve the authenticated user for a dashboard WebSocket connection and the bearer
/// credential the live connection keeps revalidating. Prefers a single-use `ticket`;
/// falls back to the legacy `token` (self-hosted static key or JWT) so older/degraded
/// clients keep working.
async fn authenticate_dashboard_ws(
    state: &DashboardWsState,
    query: &DashboardWsQuery,
) -> Result<(String, String), axum::response::Response> {
    // Preferred path: a short-lived, single-use ticket. Consume it (remove) regardless of
    // expiry so a ticket can never be replayed.
    if let Some(ticket) = query.ticket.as_deref().filter(|t| !t.is_empty()) {
        return match state.ws_tickets.remove(ticket) {
            Some((_, entry)) if entry.created_at.elapsed() <= WS_TICKET_TTL => {
                Ok((entry.user_id, entry.credential))
            }
            _ => Err(ws_error(
                StatusCode::UNAUTHORIZED,
                "invalid or expired ticket",
            )),
        };
    }

    // Legacy fallback: a token in the query string.
    let token = match query.token.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => return Err(ws_error(StatusCode::UNAUTHORIZED, "missing ticket")),
    };

    let user_id = if let Some(local_keys) = state.local_api_keys.as_deref() {
        validate_local_api_key(local_keys, token)
    } else {
        let Some(ref url) = state.control_plane_url else {
            return Err(ws_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "auth source not configured",
            ));
        };
        validate_token(url, token, &state.http_client).await
    };
    user_id
        .map(|user_id| (user_id, token.to_string()))
        .ok_or_else(|| ws_error(StatusCode::UNAUTHORIZED, "invalid token"))
}

/// Axum handler for `GET /ws/dashboard?ticket=...` (preferred) or `?token=...` (legacy).
pub async fn dashboard_ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<DashboardWsState>,
    Query(query): Query<DashboardWsQuery>,
) -> impl IntoResponse {
    let (user_id, token) = match authenticate_dashboard_ws(&state, &query).await {
        Ok(authenticated) => authenticated,
        Err(response) => return response,
    };

    info!(user_id = %user_id, "dashboard WebSocket upgrading");

    let broadcaster = state.broadcaster.clone();
    ws.on_upgrade(move |socket| handle_dashboard_ws(socket, broadcaster, user_id, state, token))
        .into_response()
}

async fn handle_dashboard_ws(
    mut socket: WebSocket,
    broadcaster: Arc<DashboardBroadcaster>,
    user_id: String,
    auth: DashboardWsState,
    token: String,
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
                let current_user = if let Some(keys) = auth.local_api_keys.as_deref() {
                    validate_local_api_key(keys, &token)
                } else if let Some(url) = auth.control_plane_url.as_deref() {
                    validate_token(url, &token, &auth.http_client).await
                } else { None };
                if current_user.as_deref() != Some(user_id.as_str()) {
                    let _ = socket.send(Message::Close(Some(axum::extract::ws::CloseFrame { code: 4401, reason: "unauthorized".into() }))).await;
                    break;
                }
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
    use axum::{routing::get, Router};
    use futures_util::{SinkExt, StreamExt};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
                credential: "session-jwt".to_string(),
                created_at: Instant::now(),
            },
        );
        let st = state(tickets, None);

        let first = authenticate_dashboard_ws(&st, &query(Some("abc"), None)).await;
        // The ticket hands the live connection the credential it keeps revalidating.
        assert_eq!(
            first.unwrap(),
            ("user-1".to_string(), "session-jwt".to_string())
        );

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
                credential: "session-jwt".to_string(),
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
        assert!(ok.unwrap().0.starts_with("local-"));

        let bad = authenticate_dashboard_ws(&st, &query(None, Some("wrong"))).await;
        assert_eq!(bad.unwrap_err().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn missing_ticket_and_token_is_rejected() {
        let st = state(Arc::new(DashMap::new()), None);
        let res = authenticate_dashboard_ws(&st, &query(None, None)).await;
        assert_eq!(res.unwrap_err().status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoked_jwt_is_not_cached_by_dashboard_validation() {
        let server = MockServer::start().await;
        let revoked = Arc::new(AtomicBool::new(false));
        let state = revoked.clone();
        Mock::given(method("POST")).and(path("/api/v1/auth/validate"))
            .and(header("Authorization", "Bearer session-jwt"))
            .respond_with(move |_request: &wiremock::Request| {
                if state.load(Ordering::SeqCst) { ResponseTemplate::new(401) }
                else { ResponseTemplate::new(200).set_body_json(serde_json::json!({"valid":true,"user_id":"owner","auth_type":"jwt","scopes":null})) }
            }).expect(2).mount(&server).await;
        let client = reqwest::Client::new();
        assert_eq!(
            validate_token(&server.uri(), "session-jwt", &client)
                .await
                .as_deref(),
            Some("owner")
        );
        revoked.store(true, Ordering::SeqCst);
        assert!(validate_token(&server.uri(), "session-jwt", &client)
            .await
            .is_none());
    }

    #[tokio::test]
    async fn active_dashboard_websocket_closes_when_its_session_is_revoked() {
        let control_plane = MockServer::start().await;
        let revoked = Arc::new(AtomicBool::new(false));
        let revoked_checks = Arc::new(AtomicUsize::new(0));
        let auth_state = revoked.clone();
        let failed_checks = revoked_checks.clone();
        Mock::given(method("POST")).and(path("/api/v1/auth/validate"))
            .and(header("Authorization", "Bearer session-jwt"))
            .respond_with(move |_request: &wiremock::Request| {
                if auth_state.load(Ordering::SeqCst) {
                    failed_checks.fetch_add(1, Ordering::SeqCst);
                    ResponseTemplate::new(401)
                } else { ResponseTemplate::new(200).set_body_json(serde_json::json!({"valid":true,"user_id":"owner","auth_type":"jwt","scopes":null})) }
            }).mount(&control_plane).await;
        let broadcaster = Arc::new(DashboardBroadcaster::new());
        let state = DashboardWsState {
            broadcaster: broadcaster.clone(),
            control_plane_url: Some(control_plane.uri()),
            local_api_keys: None,
            http_client: reqwest::Client::new(),
            dev_mode: false,
            ws_tickets: Arc::new(DashMap::new()),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/ws/dashboard", get(dashboard_ws_handler))
            .with_state(state);
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let (mut socket, response) =
            tokio_tungstenite::connect_async(format!("ws://{addr}/ws/dashboard?token=session-jwt"))
                .await
                .unwrap();
        assert_eq!(response.status(), 101);
        // The initial ping proves the upgrade's immediate live validation passed.
        let initial = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(initial.is_ping());
        socket
            .send(tokio_tungstenite::tungstenite::Message::Pong(
                initial.into_data(),
            ))
            .await
            .unwrap();
        broadcaster.broadcast("owner", r#"{"type":"fixture"}"#);
        let event = tokio::time::timeout(Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(event.to_text().unwrap(), r#"{"type":"fixture"}"#);
        revoked.store(true, Ordering::SeqCst);
        let close = tokio::time::timeout(Duration::from_secs(40), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match close {
            tokio_tungstenite::tungstenite::Message::Close(Some(frame)) => {
                assert_eq!(u16::from(frame.code), 4401);
            }
            other => panic!("expected explicit unauthorized close after revocation, got {other:?}"),
        }
        assert!(revoked_checks.load(Ordering::SeqCst) > 0);
        server.abort();
        let _ = server.await;
    }
    #[tokio::test]
    async fn dashboard_access_requires_live_session_or_explicit_analytics_scope() {
        use serde_json::json;
        for (body, expected) in [
            (
                json!({"valid":true,"user_id":"owner","auth_type":"jwt","scopes":null}),
                true,
            ),
            (
                json!({"valid":true,"user_id":"owner","auth_type":"apikey","scopes":["analytics:read"]}),
                true,
            ),
            (
                json!({"valid":true,"user_id":"owner","auth_type":"apikey","scopes":["tunnels:read","tunnels:write"]}),
                false,
            ),
            (
                json!({"valid":true,"user_id":"owner","auth_type":"apikey","scopes":[]}),
                false,
            ),
            (
                json!({"valid":true,"user_id":"owner","auth_type":"apikey"}),
                false,
            ),
            (
                json!({"valid":false,"user_id":"owner","auth_type":"jwt"}),
                false,
            ),
            (json!({"user_id":"owner","auth_type":"jwt"}), false),
            (json!({"valid":true,"user_id":"owner"}), false),
            (json!({"valid":true,"user_id":"","auth_type":"jwt"}), false),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/api/v1/auth/validate"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body.clone()))
                .expect(1)
                .mount(&server)
                .await;
            let result = validate_token(&server.uri(), "credential", &reqwest::Client::new()).await;
            assert_eq!(
                result.is_some(),
                expected,
                "unexpected authorization for {body}"
            );
        }
    }
}
