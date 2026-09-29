use super::storage::RequestStore;
use crate::{replay::ReplayClient, tunnel::pool::OriginPool};
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{
        sse::{Event, KeepAlive, Sse},
        Html, IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use futures::stream::Stream;
use pike_core::replay::{ReplayRequest, MAX_JSON_BYTES};
use serde_json::json;
use std::{convert::Infallible, sync::Arc};

#[derive(Clone)]
struct InspectorState {
    store: Arc<RequestStore>,
    pool: OriginPool,
    replay: Result<ReplayClient, String>,
    token: String,
    authority: String,
    replay_slots: Arc<tokio::sync::Semaphore>,
}

pub struct InspectorServer {
    store: Arc<RequestStore>,
    pool: OriginPool,
    replay: Result<ReplayClient, String>,
}
impl InspectorServer {
    pub fn new(
        store: Arc<RequestStore>,
        pool: OriginPool,
        replay: anyhow::Result<ReplayClient>,
    ) -> Self {
        Self {
            store,
            pool,
            replay: replay.map_err(|error| error.to_string()),
        }
    }
    pub async fn run(
        self,
        listener: tokio::net::TcpListener,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let addr = listener.local_addr()?;
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let state = InspectorState {
            store: self.store,
            pool: self.pool,
            replay: self.replay,
            token: token.clone(),
            authority: addr.to_string(),
            replay_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        };
        let app = Router::new()
            .route("/", get(|| async { Html(include_str!("ui.html")) }))
            .route("/api/requests", get(handle_requests))
            .route(
                "/api/origins",
                get(|State(state): State<InspectorState>| async move { Json(state.pool.status()) }),
            )
            .route("/api/requests/stream", get(handle_stream))
            .route(
                "/api/requests/clear",
                post(|State(state): State<InspectorState>| async move {
                    state.store.clear();
                    StatusCode::OK
                }),
            )
            .route("/api/replay", post(handle_replay))
            .layer(DefaultBodyLimit::max(MAX_JSON_BYTES))
            .layer(middleware::from_fn_with_state(state.clone(), authenticate))
            .with_state(state);
        println!("Inspector access: http://{addr}/#{token}");
        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn authenticate(
    State(state): State<InspectorState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let host = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok());
    let origin = request
        .headers()
        .get("origin")
        .and_then(|value| value.to_str().ok());
    let mut response = if host != Some(state.authority.as_str())
        || origin.is_some_and(|value| value != format!("http://{}", state.authority))
    {
        StatusCode::FORBIDDEN.into_response()
    } else if request.uri().path() != "/"
        && request
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            != Some(format!("Bearer {}", state.token).as_str())
    {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error":"Open the inspector access link printed by pike"})),
        )
            .into_response()
    } else {
        next.run(request).await
    };
    let headers = response.headers_mut();
    headers.insert("cache-control", "no-store".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert("content-security-policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'".parse().unwrap());
    response
}

async fn handle_requests(State(state): State<InspectorState>) -> Json<serde_json::Value> {
    let requests = state.store.get_all();
    Json(json!({ "count":requests.len(), "requests":requests }))
}
async fn handle_stream(
    State(state): State<InspectorState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.store.subscribe();
    let stream = async_stream::stream! {
        loop { match rx.recv().await {
            Ok(req) => if let Ok(data) = serde_json::to_string(&req) { yield Ok(Event::default().data(data)); },
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {},
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
        } }
    };
    Sse::new(stream).keep_alive(KeepAlive::default())
}
async fn handle_replay(
    State(state): State<InspectorState>,
    Json(request): Json<ReplayRequest>,
) -> Response {
    let Ok(_permit) = state.replay_slots.clone().try_acquire_owned() else {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    };
    let client = match &state.replay {
        Ok(client) => client,
        Err(reason) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":reason})),
            )
                .into_response()
        }
    };
    match client.send(request).await {
        Ok(result) => Json(result).into_response(),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error":error.to_string()})),
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn inspector_ui_escapes_captured_values_before_using_inner_html() {
        let html = include_str!("ui.html");

        assert!(html.contains("function escapeHtml"));
        assert!(html.contains("escapeHtml(r.method)"));
        assert!(html.contains("escapeHtml(r.path)"));
        assert!(html.contains("escapeHtml(r.body)"));
        assert!(html.contains("escapeHtml(r.response_body)"));
        assert!(html.contains("escapeHtml(e[0]) + ': ' + escapeHtml(e[1])"));
        assert!(html.contains("onclick=\"showDetail(' + jsString(r.id) + ')\""));
        assert!(html.contains("methodClass(r.method)"));
        assert!(!html.contains("'<td class=\"path\">' + r.path + '</td>'"));
        assert!(!html.contains("'<pre>' + r.body + '</pre>"));
        assert!(!html.contains("'<pre>' + r.response_body + '</pre>"));
        assert!(!html.contains("showDetail(\\'' + r.id"));
    }
}
