use crate::proxy::DEFAULT_PROXY_TIMEOUT;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode};
use base64::Engine;
use pike_core::http_response::{parse_head, Event, ResponseDecoder, ResponseHead, MAX_HEADERS};
use pike_core::proto::StreamHeader;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{timeout_at, Instant};
use tracing::{info, warn};

use crate::proxy::{TunnelRequest, WebSocketRequest};
use crate::traffic_meter::TrafficMeter;
use pike_core::byte_stream::Direction;

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

/// Expected Sec-WebSocket-Accept for a raw upgrade request, if it carries a key.
fn expected_accept_key(raw_upgrade_request: &[u8]) -> Option<String> {
    let end = raw_upgrade_request
        .windows(4)
        .position(|part| part == b"\r\n\r\n")?;
    std::str::from_utf8(&raw_upgrade_request[..end])
        .ok()?
        .split("\r\n")
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("sec-websocket-key")
                .then(|| compute_accept_key(value.trim()))
        })
}

fn upgrade_accepted(head: &ResponseHead, accept_key: &str) -> bool {
    head.status == 101
        && head.header("sec-websocket-accept") == Some(accept_key)
        && head
            .header("upgrade")
            .is_some_and(|value| value.eq_ignore_ascii_case("websocket"))
        && head.header("connection").is_some_and(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
}

enum UpgradeResponse {
    /// The response head has not fully arrived yet.
    Incomplete,
    /// Upgrade accepted; WebSocket frames start at `header_end`.
    Accepted { header_end: usize },
    /// Not a valid 101 for this request; nothing that follows is WebSocket.
    Rejected,
}

/// Classify buffered upstream bytes the same way `handle_ws_upgrade` does.
fn classify_upgrade_response(accept_key: Option<&str>, raw: &[u8]) -> UpgradeResponse {
    let Some(end) = raw.windows(4).position(|part| part == b"\r\n\r\n") else {
        return if raw.len() > MAX_HEADERS {
            UpgradeResponse::Rejected
        } else {
            UpgradeResponse::Incomplete
        };
    };
    match (parse_head(&raw[..end]), accept_key) {
        (Ok(head), Some(key)) if upgrade_accepted(&head, key) => UpgradeResponse::Accepted {
            header_end: end + 4,
        },
        _ => UpgradeResponse::Rejected,
    }
}

/// What telemetry should record for one upstream chunk of a relayed WebSocket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UpstreamObservation {
    /// This chunk completed an accepted upgrade; count the connection as open.
    pub accepted: bool,
    /// WebSocket frames and bytes after the upgrade head; zero for handshake bytes.
    pub frames: u64,
    pub bytes: u64,
}

impl UpstreamObservation {
    fn frames(bytes: &[u8]) -> Self {
        if bytes.is_empty() {
            return Self::default();
        }
        Self {
            accepted: false,
            frames: websocket_frame_stats(bytes).frames.max(1),
            bytes: bytes.len() as u64,
        }
    }
}

enum UpstreamState {
    Handshake(Vec<u8>),
    Open,
    Rejected,
}

/// Separates the upstream upgrade response from WebSocket frames so telemetry
/// never counts HTTP headers or rejected upgrades as frames.
pub struct UpstreamObserver {
    accept_key: Option<String>,
    state: UpstreamState,
}

impl UpstreamObserver {
    #[must_use]
    pub fn new(raw_upgrade_request: &[u8]) -> Self {
        Self {
            accept_key: expected_accept_key(raw_upgrade_request),
            state: UpstreamState::Handshake(Vec::new()),
        }
    }

    pub fn observe(&mut self, bytes: &[u8]) -> UpstreamObservation {
        match &mut self.state {
            UpstreamState::Rejected => UpstreamObservation::default(),
            UpstreamState::Open => UpstreamObservation::frames(bytes),
            UpstreamState::Handshake(head) => {
                head.extend_from_slice(bytes);
                match classify_upgrade_response(self.accept_key.as_deref(), head) {
                    UpgradeResponse::Incomplete => UpstreamObservation::default(),
                    UpgradeResponse::Rejected => {
                        self.state = UpstreamState::Rejected;
                        UpstreamObservation::default()
                    }
                    UpgradeResponse::Accepted { header_end } => {
                        let observation = UpstreamObservation {
                            accepted: true,
                            ..UpstreamObservation::frames(&head[header_end..])
                        };
                        self.state = UpstreamState::Open;
                        observation
                    }
                }
            }
        }
    }
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
    meter: TrafficMeter,
    visitor: crate::visitor_policy::VisitorAdmission,
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
    if let Err(error) = meter.opened().await {
        warn!(%error, "WebSocket usage observation failed");
        return crate::quota::error_response(&error);
    }

    // Extract the hyper OnUpgrade to get raw connection after 101
    let on_upgrade = hyper::upgrade::on(req);

    // Create channels for bidirectional relay between raw connection and QUIC
    let (ws_to_quic_tx, ws_to_quic_rx) = mpsc::channel::<Vec<u8>>(16);
    let (quic_to_ws_tx, mut quic_to_ws_rx) = mpsc::channel::<Vec<u8>>(16);

    let ws_req = WebSocketRequest {
        stream_header,
        request_id,
        raw_upgrade_request,
        ws_to_quic_rx,
        quic_to_ws_tx,
    };

    let deadline = Instant::now() + DEFAULT_PROXY_TIMEOUT;
    if !matches!(
        timeout_at(
            deadline,
            tunnel_request_tx.send(TunnelRequest::WebSocket(ws_req))
        )
        .await,
        Ok(Ok(()))
    ) {
        return Response::builder()
            .status(502)
            .body(Body::from("tunnel unavailable"))
            .unwrap_or_else(|_| Response::new(Body::from("error")));
    }

    let handshake = timeout_at(deadline, async {
        let mut raw = Vec::new();
        loop {
            let bytes = quic_to_ws_rx
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("upstream closed during upgrade"))?;
            raw.extend_from_slice(&bytes);
            if let Some(end) = raw.windows(4).position(|part| part == b"\r\n\r\n") {
                let head = parse_head(&raw[..end])?;
                return Ok::<_, anyhow::Error>((head, raw, end + 4));
            }
            if raw.len() > MAX_HEADERS {
                anyhow::bail!("upgrade headers too large");
            }
        }
    })
    .await;
    let Ok(Ok((head, raw, header_end))) = handshake else {
        return Response::builder()
            .status(502)
            .body(Body::from("upstream upgrade failed"))
            .unwrap();
    };
    if head.status != 101 {
        let mut decoder = ResponseDecoder::new(false);
        let mut body = Vec::new();
        let result = timeout_at(deadline, async {
            let mut next = Some(raw);
            loop {
                let eof = next.is_none();
                for event in decoder.feed(next.as_deref().unwrap_or(&[]), eof)? {
                    if let Event::Body(bytes) = event {
                        body.extend(bytes);
                    }
                }
                if body.len() > 1024 * 1024 {
                    anyhow::bail!("upgrade rejection body too large");
                }
                if decoder.is_done() {
                    return Ok::<_, anyhow::Error>(());
                }
                next = quic_to_ws_rx.recv().await;
            }
        })
        .await;
        if !matches!(result, Ok(Ok(()))) {
            body.clear();
        }
        if meter
            .bytes(Direction::TunnelToSocket, body.len())
            .await
            .is_err()
        {
            return Response::builder()
                .status(503)
                .body(Body::from("usage storage unavailable"))
                .unwrap();
        }
        let mut response = Response::builder().status(head.status);
        for (name, value) in head
            .end_to_end_headers()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("content-length"))
        {
            response = response.header(name, value);
        }
        return response
            .body(Body::from(body))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }
    if !upgrade_accepted(&head, &accept_key) {
        return Response::builder()
            .status(502)
            .body(Body::from("invalid upstream upgrade response"))
            .unwrap();
    }
    let early_frames = raw[header_end..].to_vec();
    // Spawn the raw byte relay task
    tokio::spawn(async move {
        let forwarding = async {
            match on_upgrade.await {
                Ok(upgraded) => {
                    info!("WebSocket upgrade completed, starting raw byte relay");
                    let io = hyper_util::rt::TokioIo::new(upgraded);
                    let (mut read_half, mut write_half) = tokio::io::split(io);

                    if meter
                        .bytes(Direction::TunnelToSocket, early_frames.len())
                        .await
                        .is_err()
                        || write_half.write_all(&early_frames).await.is_err()
                    {
                        return;
                    }
                    relay_raw(
                        &mut read_half,
                        &mut write_half,
                        quic_to_ws_rx,
                        ws_to_quic_tx,
                        meter,
                    )
                    .await;
                }
                Err(e) => {
                    warn!(error = %e, "WebSocket upgrade failed");
                }
            }
        };
        tokio::select! {
            biased;
            () = visitor.cancelled() => {},
            () = forwarding => {},
        }
    });

    let mut response = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (name, value) in head.headers {
        response = response.header(name, value);
    }
    response
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
    meter: TrafficMeter,
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
                    if let Err(error) = meter.bytes(Direction::SocketToTunnel, n).await {
                        warn!(%error, "WebSocket ingress accounting failed");
                        break;
                    }
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
            if let Err(error) = meter.bytes(Direction::TunnelToSocket, data.len()).await {
                warn!(%error, "WebSocket egress accounting failed");
                break;
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
    use super::{
        build_raw_upgrade_request, websocket_frame_stats, UpstreamObservation, UpstreamObserver,
    };
    use axum::body::Body;
    use axum::http::Request;

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

    const UPGRADE_REQUEST: &[u8] = b"GET /media HTTP/1.1\r\nhost: a.test\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    const ACCEPTED_HEAD: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";

    #[test]
    fn upstream_observer_opens_empty_upgrade_without_frames() {
        let mut observer = UpstreamObserver::new(UPGRADE_REQUEST);
        let (first, rest) = ACCEPTED_HEAD.split_at(20);

        assert_eq!(observer.observe(first), UpstreamObservation::default());
        assert_eq!(
            observer.observe(rest),
            UpstreamObservation {
                accepted: true,
                frames: 0,
                bytes: 0,
            }
        );
        let frame = server_frame(0x1, b"hello");
        let next = observer.observe(&frame);
        assert!(!next.accepted);
        assert_eq!((next.frames, next.bytes), (1, frame.len() as u64));
    }

    #[test]
    fn upstream_observer_keeps_frame_coalesced_with_head() {
        let frame = server_frame(0x2, b"early");
        let mut observer = UpstreamObserver::new(UPGRADE_REQUEST);

        let observed = observer.observe(&[ACCEPTED_HEAD, &frame[..]].concat());

        assert_eq!(
            observed,
            UpstreamObservation {
                accepted: true,
                frames: 1,
                bytes: frame.len() as u64,
            }
        );
    }

    #[test]
    fn upstream_observer_counts_fragmented_frame_chunks_after_upgrade() {
        let frame = server_frame(0x2, b"fragmented-payload");
        let (head_part, tail_part) = frame.split_at(4);
        let mut observer = UpstreamObserver::new(UPGRADE_REQUEST);

        let first = observer.observe(&[ACCEPTED_HEAD, head_part].concat());
        let second = observer.observe(tail_part);

        assert!(first.accepted);
        assert_eq!((first.frames, first.bytes), (1, 4));
        assert!(!second.accepted);
        assert_eq!(second.bytes, tail_part.len() as u64);
        assert!(second.frames >= 1);
    }

    #[test]
    fn upstream_observer_ignores_rejected_upgrades() {
        let rejection = b"HTTP/1.1 403 Forbidden\r\ncontent-length: 4\r\n\r\ndeny";
        let mut observer = UpstreamObserver::new(UPGRADE_REQUEST);
        assert_eq!(observer.observe(rejection), UpstreamObservation::default());
        assert_eq!(
            observer.observe(&server_frame(0x1, b"after")),
            UpstreamObservation::default()
        );

        let wrong_accept = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: bogus\r\n\r\n";
        let mut observer = UpstreamObserver::new(UPGRADE_REQUEST);
        assert_eq!(
            observer.observe(wrong_accept),
            UpstreamObservation::default()
        );

        let mut observer = UpstreamObserver::new(b"GET / HTTP/1.1\r\nupgrade: websocket\r\n\r\n");
        assert_eq!(
            observer.observe(ACCEPTED_HEAD),
            UpstreamObservation::default()
        );
    }

    #[test]
    fn websocket_accept_matches_rfc6455_example() {
        assert_eq!(
            super::compute_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }
}
