//! Authenticated HTTP replay through the same admission, quota and forwarding
//! path as public traffic. No outbound URL or alternate Host is accepted.
use super::{
    forward::forward_tunnel_request, platform::authenticate_platform_user_for_scope, HttpState,
};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, HeaderValue, Request, Response, StatusCode},
    response::IntoResponse,
    Json,
};
use http_body_util::BodyExt;
use pike_core::{
    replay::{Header, ReplayRequest, ReplayResponse, MAX_BODY_BYTES, MAX_JSON_BYTES},
    types::TunnelId,
};
use std::{net::SocketAddr, time::Duration};

#[derive(Clone)]
pub(super) struct ExpectedTunnel(pub TunnelId, pub uuid::Uuid);

fn error(status: StatusCode, message: &str) -> Response<Body> {
    (status, Json(serde_json::json!({"error": message}))).into_response()
}

pub(super) async fn handle(
    State(state): State<HttpState>,
    Path(tunnel_id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> Response<Body> {
    let mut response = execute(state, tunnel_id, peer, req).await;
    response
        .headers_mut()
        .insert("cache-control", HeaderValue::from_static("no-store"));
    response
}

async fn execute(
    state: HttpState,
    tunnel_id: String,
    peer: SocketAddr,
    req: Request<Body>,
) -> Response<Body> {
    let user_id =
        match authenticate_platform_user_for_scope(&state, req.headers(), "tunnels:write").await {
            Ok(user) => user,
            Err(response) => return response,
        };
    let runtime_id = state.registry.runtime_tunnel_id(&tunnel_id);
    let Ok(id) = uuid::Uuid::parse_str(&runtime_id).map(TunnelId) else {
        return error(StatusCode::NOT_FOUND, "active HTTP tunnel not found");
    };
    let Some((host, entry)) = state
        .registry
        .tunnels
        .iter()
        .find(|entry| entry.tunnel_id == id && entry.active)
        .map(|entry| (entry.key().clone(), entry.value().clone()))
    else {
        return error(StatusCode::NOT_FOUND, "active HTTP tunnel not found");
    };
    let owner = state.registry.user_id_for_connection(&entry.connection_id);
    let allowed = if state.dev_mode {
        // Development replay still requires the credential of this connector;
        // the older read-only dashboard dev bypass is insufficient here.
        let token = req
            .headers()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "));
        state
            .registry
            .clients
            .get(&entry.connection_id)
            .is_some_and(|client| token.is_some() && client.info.api_key.as_deref() == token)
    } else {
        owner.as_deref() == Some(&user_id)
    };
    if !allowed
        || !state
            .router
            .route_for_connection(&host, &entry.connection_id)
            .is_some_and(|route| {
                route.tunnel_id == id && route.connection_id == entry.connection_id && route.active
            })
    {
        return error(StatusCode::NOT_FOUND, "active HTTP tunnel not found");
    }
    let Ok(_permit) = state.replay_slots.clone().try_acquire_owned() else {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "replay concurrency limit reached",
        );
    };
    if req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v.split(';').next().unwrap_or("").trim() != "application/json")
    {
        return error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "replay requires application/json",
        );
    }
    let visitor = match state.trusted_proxies.resolve(peer, req.headers()) {
        Ok(visitor) => visitor,
        Err(error) => return error.response(),
    };
    let body = match tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(req.into_body(), MAX_JSON_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "replay JSON exceeds 128 KiB or cannot be read",
            )
        }
        Err(_) => return error(StatusCode::REQUEST_TIMEOUT, "replay draft read timed out"),
    };
    let Ok(draft) = serde_json::from_slice::<ReplayRequest>(&body) else {
        return error(
            StatusCode::BAD_REQUEST,
            "invalid replay draft; method, path, headers and body_base64 are required",
        );
    };
    let draft = match draft.validate() {
        Ok(draft) => draft,
        Err(reason) => return error(StatusCode::BAD_REQUEST, reason),
    };
    let Ok(host) = HeaderValue::from_str(&host) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "invalid tunnel hostname");
    };
    let mut request = Request::new(Body::from(draft.body));
    request.extensions_mut().insert(visitor);
    *request.method_mut() = draft.method;
    *request.uri_mut() = draft.uri;
    *request.headers_mut() = draft.headers;
    request.headers_mut().insert("host", host);
    request
        .extensions_mut()
        .insert(ExpectedTunnel(id, entry.connection_id));
    let started = std::time::Instant::now();
    let exchange = async {
        let response = forward_tunnel_request(state, peer, request).await;
        let status = response.status().as_u16();
        let headers = headers(response.headers());
        let mut body = response.into_body();
        let mut captured = Vec::new();
        let mut trailers = Vec::new();
        let mut truncated = false;
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| error(StatusCode::BAD_GATEWAY,
                "replay response interrupted; the origin may have processed the request; no retry was sent"))?;
            match frame.into_data() {
                Ok(data) => {
                    let take = data
                        .len()
                        .min(MAX_BODY_BYTES.saturating_sub(captured.len()));
                    captured.extend_from_slice(&data[..take]);
                    if take < data.len() {
                        truncated = true;
                        break;
                    }
                }
                Err(frame) => {
                    if let Ok(values) = frame.into_trailers() {
                        trailers = self::headers(&values);
                    }
                }
            }
        }
        Ok::<_, Response<Body>>(ReplayResponse {
            status,
            headers,
            trailers,
            body_base64: ReplayResponse::encode_body(&captured),
            truncated,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    };
    match tokio::time::timeout(Duration::from_secs(30), exchange).await {
        Ok(Ok(result)) => Json(result).into_response(),
        Ok(Err(response)) => response,
        Err(_) => error(
            StatusCode::GATEWAY_TIMEOUT,
            "replay timed out; the origin may have processed the request; no retry was sent",
        ),
    }
}

fn headers(map: &HeaderMap) -> Vec<Header> {
    map.iter()
        .map(|(name, value)| Header {
            name: name.to_string(),
            value: value.to_str().unwrap_or("<binary>").to_owned(),
        })
        .collect()
}
