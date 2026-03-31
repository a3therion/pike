use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use base64::Engine;
use pike_core::proto::StreamHeader;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::proxy::{TunnelRequest, WebSocketRequest};

/// WebSocket GUID used to compute the Sec-WebSocket-Accept header.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-5AB5B13F4088";

/// Build the raw HTTP upgrade request bytes from the original request parts.
pub fn build_raw_upgrade_request(req: &Request<Body>) -> Vec<u8> {
    let target = req.uri().path_and_query().map_or("/", |v| v.as_str());

    let mut raw = format!("{} {} HTTP/1.1\r\n", req.method().as_str(), target,).into_bytes();

    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            raw.extend_from_slice(name.as_str().as_bytes());
            raw.extend_from_slice(b": ");
            raw.extend_from_slice(v.as_bytes());
            raw.extend_from_slice(b"\r\n");
        }
    }
    raw.extend_from_slice(b"\r\n");
    raw
}

/// Compute the Sec-WebSocket-Accept value from the client's key.
fn compute_accept_key(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WS_GUID.as_bytes());
    let hash = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(hash)
}

/// Handle a WebSocket upgrade by accepting it and relaying raw bytes
/// (not decoded WS frames) through the tunnel's QUIC stream.
///
/// This makes the tunnel transparent — raw WS protocol frames flow through
/// unchanged. The browser and local server negotiate the WS protocol directly.
pub async fn handle_ws_upgrade(
    req: Request<Body>,
    tunnel_request_tx: mpsc::Sender<TunnelRequest>,
    stream_header: StreamHeader,
    raw_upgrade_request: Vec<u8>,
    request_id: String,
) -> Response<Body> {
    // Extract the Sec-WebSocket-Key to compute the accept value
    let ws_key = match req.headers().get("sec-websocket-key") {
        Some(key) => match key.to_str() {
            Ok(k) => k.to_string(),
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from("invalid Sec-WebSocket-Key"))
                    .unwrap_or_else(|_| Response::new(Body::from("error")));
            }
        },
        None => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("missing Sec-WebSocket-Key"))
                .unwrap_or_else(|_| Response::new(Body::from("error")));
        }
    };

    let accept_key = compute_accept_key(&ws_key);

    // Extract the hyper OnUpgrade to get raw connection after 101
    let on_upgrade = hyper::upgrade::on(req);

    // Create channels for bidirectional relay between raw connection and QUIC
    let (ws_to_quic_tx, ws_to_quic_rx) = mpsc::channel::<Vec<u8>>(256);
    let (quic_to_ws_tx, quic_to_ws_rx) = mpsc::channel::<Vec<u8>>(256);

    let ws_req = WebSocketRequest {
        stream_header,
        request_id,
        raw_upgrade_request,
        ws_to_quic_rx,
        quic_to_ws_tx,
    };

    // Send the WebSocket request to the tunnel forwarder
    if tunnel_request_tx
        .send(TunnelRequest::WebSocket(ws_req))
        .await
        .is_err()
    {
        return Response::builder()
            .status(502)
            .body(Body::from("tunnel unavailable"))
            .unwrap_or_else(|_| Response::new(Body::from("error")));
    }

    // Spawn the raw byte relay task
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                info!("WebSocket upgrade completed, starting raw byte relay");
                let io = hyper_util::rt::TokioIo::new(upgraded);
                let (mut read_half, mut write_half) = tokio::io::split(io);

                relay_raw(
                    &mut read_half,
                    &mut write_half,
                    quic_to_ws_rx,
                    ws_to_quic_tx,
                )
                .await;
            }
            Err(e) => {
                warn!(error = %e, "WebSocket upgrade failed");
            }
        }
    });

    // Return the 101 Switching Protocols response to trigger the upgrade
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Accept", accept_key)
        .body(Body::empty())
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

/// Bidirectional raw byte relay between the upgraded browser connection
/// and the tunnel's QUIC stream (via channels).
async fn relay_raw<R, W>(
    read_half: &mut R,
    write_half: &mut W,
    mut from_tunnel: mpsc::Receiver<Vec<u8>>,
    to_tunnel: mpsc::Sender<Vec<u8>>,
) where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let to_tunnel_for_read = to_tunnel.clone();

    // Browser -> Tunnel: read raw bytes from browser, send through QUIC
    let browser_to_tunnel = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => {
                    if to_tunnel_for_read.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "browser read error in WS relay");
                    break;
                }
            }
        }
    };

    // Tunnel -> Browser: receive bytes from QUIC, write to browser
    let tunnel_to_browser = async {
        while let Some(data) = from_tunnel.recv().await {
            if data.is_empty() {
                continue;
            }
            if write_half.write_all(&data).await.is_err() {
                break;
            }
        }
    };

    tokio::select! {
        _ = browser_to_tunnel => {}
        _ = tunnel_to_browser => {}
    }

    info!("WebSocket raw byte relay ended");
}
