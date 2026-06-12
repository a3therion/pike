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
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WebSocketFrameStats {
    pub frames: u64,
    pub payload_bytes: u64,
    pub incomplete: bool,
}

/// Count complete WebSocket frames in a raw byte batch without mutating it.
///
/// Browser-to-relay frames are normally masked, and relay-to-browser frames
/// are normally unmasked. The parser accepts either form because this is an
/// observability path and should not reject traffic that the transparent relay
/// can otherwise pass through unchanged.
#[must_use]
pub fn websocket_frame_stats(payload: &[u8]) -> WebSocketFrameStats {
    let mut offset = 0_usize;
    let mut stats = WebSocketFrameStats::default();

    while offset < payload.len() {
        if payload.len().saturating_sub(offset) < 2 {
            stats.incomplete = true;
            break;
        }

        let second = payload[offset + 1];
        let masked = second & 0x80 != 0;
        let mut length = usize::from(second & 0x7f);
        let mut cursor = offset + 2;

        if length == 126 {
            if payload.len().saturating_sub(cursor) < 2 {
                stats.incomplete = true;
                break;
            }
            length = usize::from(u16::from_be_bytes([payload[cursor], payload[cursor + 1]]));
            cursor += 2;
        } else if length == 127 {
            if payload.len().saturating_sub(cursor) < 8 {
                stats.incomplete = true;
                break;
            }
            let extended = u64::from_be_bytes([
                payload[cursor],
                payload[cursor + 1],
                payload[cursor + 2],
                payload[cursor + 3],
                payload[cursor + 4],
                payload[cursor + 5],
                payload[cursor + 6],
                payload[cursor + 7],
            ]);
            let Ok(converted) = usize::try_from(extended) else {
                stats.incomplete = true;
                break;
            };
            length = converted;
            cursor += 8;
        }

        if masked {
            if payload.len().saturating_sub(cursor) < 4 {
                stats.incomplete = true;
                break;
            }
            cursor += 4;
        }

        if payload.len().saturating_sub(cursor) < length {
            stats.incomplete = true;
            break;
        }

        stats.frames = stats.frames.saturating_add(1);
        stats.payload_bytes = stats.payload_bytes.saturating_add(length as u64);
        offset = cursor + length;
    }

    if stats.frames == 0 && !payload.is_empty() {
        stats.frames = 1;
        stats.payload_bytes = payload.len() as u64;
    }

    stats
}

/// Build the raw HTTP upgrade request bytes from the original request parts.
pub fn build_raw_upgrade_request(req: &Request<Body>) -> Vec<u8> {
    let target = req.uri().path_and_query().map_or("/", |v| v.as_str());

    let mut raw = format!("{} {} HTTP/1.1\r\n", req.method().as_str(), target).into_bytes();

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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{build_raw_upgrade_request, compute_accept_key, relay_raw, websocket_frame_stats};
    use axum::body::Body;
    use axum::http::Request;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::mpsc;

    #[test]
    fn computes_rfc_websocket_accept_key() {
        // RFC 6455 section 1.3 example vector.
        let key = "dGhlIHNhbXBsZSBub25jZQ==";

        assert_eq!(compute_accept_key(key), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn raw_upgrade_request_preserves_target_and_websocket_headers() {
        let request = Request::builder()
            .method("GET")
            .uri("/media?call_id=abc")
            .header("Host", "surya.pike.life")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Protocol", "audio.telephony.v1")
            .body(Body::empty())
            .expect("request should build");

        let raw = String::from_utf8(build_raw_upgrade_request(&request))
            .expect("raw request should be utf8");

        assert!(raw.starts_with("GET /media?call_id=abc HTTP/1.1\r\n"));
        assert!(raw.contains("host: surya.pike.life\r\n"));
        assert!(raw.contains("connection: Upgrade\r\n"));
        assert!(raw.contains("upgrade: websocket\r\n"));
        assert!(raw.contains("sec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
        assert!(raw.contains("sec-websocket-protocol: audio.telephony.v1\r\n"));
        assert!(raw.ends_with("\r\n\r\n"));
    }

    #[test]
    fn websocket_frame_stats_counts_masked_and_unmasked_frames() {
        let client_frames = [
            masked_client_frame(0x2, b"audio-1"),
            masked_client_frame(0x9, b"ping"),
        ]
        .concat();
        let server_frames = [server_frame(0x2, b"reply-1"), server_frame(0xa, b"pong")].concat();

        let client_stats = websocket_frame_stats(&client_frames);
        assert_eq!(client_stats.frames, 2);
        assert_eq!(client_stats.payload_bytes, 11);
        assert!(!client_stats.incomplete);

        let server_stats = websocket_frame_stats(&server_frames);
        assert_eq!(server_stats.frames, 2);
        assert_eq!(server_stats.payload_bytes, 11);
        assert!(!server_stats.incomplete);
    }

    #[test]
    fn websocket_frame_stats_marks_incomplete_batch() {
        let frame = masked_client_frame(0x2, b"audio-1");
        let partial = &frame[..frame.len() - 2];

        let stats = websocket_frame_stats(partial);

        assert_eq!(stats.frames, 1);
        assert!(stats.incomplete);
    }

    #[tokio::test]
    async fn raw_relay_preserves_websocket_frame_bytes_in_both_directions() {
        let client_frames = [
            masked_client_frame(0x2, b"\x00binary\xff"),
            masked_client_frame(0x9, b"ping"),
            masked_client_frame(0x8, &[0x03, 0xe8]),
        ]
        .concat();
        let server_frames = [
            server_frame(0x2, b"\x01reply\xfe"),
            server_frame(0xa, b"pong"),
            server_frame(0x8, &[0x03, 0xe8]),
        ]
        .concat();

        let (relay_side, mut browser_side) = tokio::io::duplex(4096);
        let (mut relay_read, mut relay_write) = tokio::io::split(relay_side);
        let (from_tunnel_tx, from_tunnel_rx) = mpsc::channel(4);
        let (to_tunnel_tx, mut to_tunnel_rx) = mpsc::channel(4);

        let relay = tokio::spawn(async move {
            relay_raw(
                &mut relay_read,
                &mut relay_write,
                from_tunnel_rx,
                to_tunnel_tx,
            )
            .await;
        });

        browser_side
            .write_all(&client_frames)
            .await
            .expect("browser frames should write");
        let relayed_client_frames =
            receive_relayed_bytes(&mut to_tunnel_rx, client_frames.len()).await;
        assert_eq!(relayed_client_frames, client_frames);

        from_tunnel_tx
            .send(server_frames.clone())
            .await
            .expect("server frames should send");
        let mut received_server_frames = vec![0; server_frames.len()];
        browser_side
            .read_exact(&mut received_server_frames)
            .await
            .expect("browser should receive server frames");
        assert_eq!(received_server_frames, server_frames);

        drop(from_tunnel_tx);
        browser_side
            .shutdown()
            .await
            .expect("browser side should shutdown");
        tokio::time::timeout(Duration::from_secs(1), relay)
            .await
            .expect("relay should stop after browser shutdown")
            .expect("relay task should not panic");
    }

    fn masked_client_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mask = [0x12, 0x34, 0x56, 0x78];
        let payload_len = u8::try_from(payload.len()).expect("test payload should fit in u8");
        assert!(payload_len < 126);

        let mut frame = Vec::with_capacity(6 + payload.len());
        frame.push(0x80 | opcode);
        frame.push(0x80 | payload_len);
        frame.extend_from_slice(&mask);
        frame.extend(
            payload
                .iter()
                .enumerate()
                .map(|(index, byte)| byte ^ mask[index % mask.len()]),
        );
        frame
    }

    fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let payload_len = u8::try_from(payload.len()).expect("test payload should fit in u8");
        assert!(payload_len < 126);

        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.push(0x80 | opcode);
        frame.push(payload_len);
        frame.extend_from_slice(payload);
        frame
    }

    async fn receive_relayed_bytes(rx: &mut mpsc::Receiver<Vec<u8>>, len: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(len);
        while bytes.len() < len {
            let chunk = tokio::time::timeout(Duration::from_secs(1), rx.recv())
                .await
                .expect("relay should produce bytes before timeout")
                .expect("relay channel should stay open");
            bytes.extend_from_slice(&chunk);
        }
        bytes
    }
}
