use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ws::Message as AxumWsMessage;
use axum::http::header::{CONNECTION, HOST, UPGRADE};
use axum::http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use pike_core::proto::StreamHeader;
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message as TungsteniteMessage;

use crate::router::{normalize_host, VhostRouter};

pub const DEFAULT_PROXY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct ProxyContext {
    pub client_addr: Option<SocketAddr>,
    pub scheme: String,
}

#[derive(Debug)]
pub struct HttpRequest {
    pub stream_header: StreamHeader,
    pub request_id: String,
    pub websocket: bool,
    pub request: Request<Body>,
    pub response_tx: oneshot::Sender<Result<Response<Body>, ProxyError>>,
}

/// A tunnel request that can be either a normal HTTP request or a WebSocket upgrade.
pub enum TunnelRequest {
    Http(Box<HttpRequest>),
    WebSocket(WebSocketRequest),
}

/// A WebSocket upgrade request to be relayed through the tunnel.
pub struct WebSocketRequest {
    pub stream_header: StreamHeader,
    pub request_id: String,
    pub raw_upgrade_request: Vec<u8>,
    /// Receives bytes from the WS relay to send through QUIC to the client.
    pub ws_to_quic_rx: mpsc::Receiver<Vec<u8>>,
    /// Sends bytes received from QUIC to the WS relay to forward to the browser.
    pub quic_to_ws_tx: mpsc::Sender<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyError {
    BadRequest(&'static str),
    NotFound,
    TunnelUnavailable,
    DispatchFailed,
    Timeout,
    Upstream(String),
}

impl ProxyError {
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::TunnelUnavailable => StatusCode::BAD_GATEWAY,
            Self::DispatchFailed => StatusCode::BAD_GATEWAY,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadRequest(msg) => write!(f, "bad request: {msg}"),
            Self::NotFound => write!(f, "subdomain not registered"),
            Self::TunnelUnavailable => write!(f, "tunnel unavailable"),
            Self::DispatchFailed => write!(f, "failed to dispatch request to tunnel"),
            Self::Timeout => write!(f, "upstream tunnel timeout"),
            Self::Upstream(msg) => write!(f, "upstream error: {msg}"),
        }
    }
}

impl Error for ProxyError {}

pub async fn proxy_request(
    router: std::sync::Arc<VhostRouter>,
    mut request: Request<Body>,
) -> Result<Response<Body>, ProxyError> {
    let host =
        extract_host(request.headers()).ok_or(ProxyError::BadRequest("missing Host header"))?;
    let host_key = normalize_host(&host);
    let tunnel = router.route(&host_key).ok_or(ProxyError::NotFound)?;

    if !tunnel.is_active() {
        return Err(ProxyError::TunnelUnavailable);
    }

    let context = request
        .extensions()
        .get::<ProxyContext>()
        .cloned()
        .unwrap_or(ProxyContext {
            client_addr: None,
            scheme: "http".to_string(),
        });
    let request_id = uuid::Uuid::new_v4().to_string();
    add_forwarded_headers(&mut request, &host_key, &request_id, &context);
    let websocket = is_websocket_upgrade(request.headers());

    let source_addr = context
        .client_addr
        .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let header = StreamHeader {
        tunnel_id: tunnel.tunnel_id,
        connection_id: connection_id_from_uuid(),
        source_addr,
        streaming: false,
    };

    let (response_tx, response_rx) = oneshot::channel();
    let envelope = HttpRequest {
        stream_header: header,
        request_id,
        websocket,
        request,
        response_tx,
    };

    tunnel
        .stream_tx
        .send(TunnelRequest::Http(Box::new(envelope)))
        .await
        .map_err(|_| ProxyError::DispatchFailed)?;

    let result = tokio::time::timeout(DEFAULT_PROXY_TIMEOUT, response_rx)
        .await
        .map_err(|_| ProxyError::Timeout)?
        .map_err(|_| ProxyError::DispatchFailed)?;

    result
}

#[must_use]
pub fn extract_host(headers: &HeaderMap) -> Option<String> {
    headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[must_use]
pub fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let has_upgrade = headers
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
        })
        .unwrap_or(false);

    let is_ws = headers
        .get(UPGRADE)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    has_upgrade && is_ws
}

#[must_use]
pub fn to_tungstenite_message(message: AxumWsMessage) -> Option<TungsteniteMessage> {
    match message {
        AxumWsMessage::Text(text) => Some(TungsteniteMessage::Text(text.to_string())),
        AxumWsMessage::Binary(bin) => Some(TungsteniteMessage::Binary(bin.to_vec())),
        AxumWsMessage::Ping(data) => Some(TungsteniteMessage::Ping(data.to_vec())),
        AxumWsMessage::Pong(data) => Some(TungsteniteMessage::Pong(data.to_vec())),
        AxumWsMessage::Close(frame) => Some(TungsteniteMessage::Close(frame.map(|frame| {
            tokio_tungstenite::tungstenite::protocol::CloseFrame {
                code: frame.code.into(),
                reason: frame.reason.to_string().into(),
            }
        }))),
    }
}

fn add_forwarded_headers(
    request: &mut Request<Body>,
    host: &str,
    request_id: &str,
    context: &ProxyContext,
) {
    let headers = request.headers_mut();
    if let Some(client_addr) = context.client_addr {
        let _ = headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&client_addr.ip().to_string())
                .unwrap_or_else(|_| HeaderValue::from_static("unknown")),
        );
    }

    let _ = headers.insert(
        "x-forwarded-proto",
        HeaderValue::from_str(&context.scheme).unwrap_or_else(|_| HeaderValue::from_static("http")),
    );
    let _ = headers.insert(
        "x-forwarded-host",
        HeaderValue::from_str(host).unwrap_or_else(|_| HeaderValue::from_static("unknown")),
    );
    let _ = headers.insert(
        "x-pike-request-id",
        HeaderValue::from_str(request_id).unwrap_or_else(|_| HeaderValue::from_static("invalid")),
    );
}

pub fn connection_id_from_uuid() -> u64 {
    let id = uuid::Uuid::new_v4();
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&id.as_bytes()[..8]);
    u64::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{HeaderValue, Request, Response, StatusCode};
    use pike_core::types::TunnelId;
    use tokio::sync::mpsc;

    use super::{
        extract_host, is_websocket_upgrade, proxy_request, ProxyContext, ProxyError, TunnelRequest,
    };
    use crate::router::{TunnelEntry, VhostRouter};

    #[test]
    fn extracts_host_header() {
        let req = Request::builder()
            .uri("/")
            .header("host", "demo.pike.life")
            .body(Body::empty())
            .expect("request");
        let host = extract_host(req.headers()).expect("host");
        assert_eq!(host, "demo.pike.life");
    }

    #[test]
    fn detects_websocket_upgrade() {
        let req = Request::builder()
            .uri("/")
            .header("connection", "keep-alive, Upgrade")
            .header("upgrade", "websocket")
            .body(Body::empty())
            .expect("request");
        assert!(is_websocket_upgrade(req.headers()));
    }

    #[tokio::test]
    async fn returns_not_found_for_unknown_host() {
        let router = Arc::new(VhostRouter::new());
        let req = Request::builder()
            .uri("/")
            .header("host", "missing.pike.life")
            .body(Body::empty())
            .expect("request");

        let err = proxy_request(router, req).await.expect_err("not found");
        assert_eq!(err, ProxyError::NotFound);
        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn returns_bad_gateway_for_inactive_tunnel() {
        let router = Arc::new(VhostRouter::new());
        let (tx, _rx) = mpsc::channel(1);
        router.register(
            "inactive",
            TunnelEntry {
                tunnel_id: TunnelId::new(),
                connection_id: uuid::Uuid::new_v4(),
                stream_tx: tx,
                active: false,
            },
        );

        let req = Request::builder()
            .uri("/")
            .header("host", "inactive.pike.life")
            .body(Body::empty())
            .expect("request");

        let err = proxy_request(router, req).await.expect_err("bad gateway");
        assert_eq!(err, ProxyError::TunnelUnavailable);
        assert_eq!(err.status_code(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn dispatches_request_to_registered_tunnel() {
        let router = Arc::new(VhostRouter::new());
        let (tx, mut rx) = mpsc::channel(1);
        router.register(
            "demo",
            TunnelEntry {
                tunnel_id: TunnelId::new(),
                connection_id: uuid::Uuid::new_v4(),
                stream_tx: tx,
                active: true,
            },
        );

        tokio::spawn(async move {
            let Some(tunnel_req) = rx.recv().await else {
                return;
            };
            let TunnelRequest::Http(envelope) = tunnel_req else {
                panic!("expected HTTP request");
            };
            let envelope = *envelope;
            let x_host = envelope
                .request
                .headers()
                .get("x-forwarded-host")
                .cloned()
                .unwrap_or(HeaderValue::from_static(""));
            let response = Response::builder()
                .status(StatusCode::OK)
                .header("x-forwarded-host", x_host)
                .body(Body::from("ok"))
                .expect("response");
            let _ = envelope.response_tx.send(Ok(response));
        });

        let mut req = Request::builder()
            .uri("/hello")
            .header("host", "demo.pike.life")
            .body(Body::empty())
            .expect("request");
        req.extensions_mut().insert(ProxyContext {
            client_addr: Some("127.0.0.1:50000".parse().expect("socket")),
            scheme: "http".to_string(),
        });

        let response = proxy_request(router, req).await.expect("proxy response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("x-forwarded-host")
                .and_then(|h| h.to_str().ok()),
            Some("demo.pike.life")
        );
    }
}
