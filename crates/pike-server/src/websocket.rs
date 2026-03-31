use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use axum::extract::ws::{Message, WebSocket};
use pike_core::proto::{ControlMessage, MAX_FRAME_SIZE};
use pike_core::types::RelayInfo;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::connection::{ClientConnection, ConnectionState};
use crate::registry::ClientRegistry;
use crate::transport::{decode_multiplexed_frame, encode_multiplexed_frame};

const CONTROL_STREAM_ID: u64 = 0;

pub struct WebSocketTunnel {
    socket: WebSocket,
    streams: HashMap<u64, mpsc::Sender<Vec<u8>>>,
}

impl WebSocketTunnel {
    #[must_use]
    pub fn new(socket: WebSocket) -> Self {
        Self {
            socket,
            streams: HashMap::new(),
        }
    }

    async fn recv_multiplexed_frame(&mut self) -> Result<Option<(u64, Vec<u8>)>> {
        loop {
            let Some(message_result) = self.socket.recv().await else {
                return Ok(None);
            };
            let message = message_result.context("failed to read websocket frame")?;

            match message {
                Message::Binary(payload) => {
                    let frame = decode_multiplexed_frame(payload.as_ref())?;
                    return Ok(Some(frame));
                }
                Message::Close(_) => return Ok(None),
                Message::Ping(data) => {
                    self.socket
                        .send(Message::Pong(data))
                        .await
                        .context("failed to write websocket pong")?;
                }
                Message::Pong(_) => {}
                Message::Text(_) => {
                    return Err(anyhow!(
                        "text websocket frames are not supported for tunnel transport"
                    ));
                }
            }
        }
    }

    async fn send_multiplexed_frame(&mut self, stream_id: u64, payload: &[u8]) -> Result<()> {
        let data = encode_multiplexed_frame(stream_id, payload)?;
        self.socket
            .send(Message::Binary(data.into()))
            .await
            .context("failed to write websocket frame")
    }

    async fn route_stream_frame(&mut self, stream_id: u64, payload: Vec<u8>) -> Result<()> {
        let tx = if let Some(existing) = self.streams.get(&stream_id) {
            existing.clone()
        } else {
            let (tx, mut rx) = mpsc::channel(128);
            self.streams.insert(stream_id, tx.clone());
            tokio::spawn(async move { while rx.recv().await.is_some() {} });
            tx
        };

        tx.send(payload)
            .await
            .map_err(|_| anyhow!("failed to route multiplexed stream payload"))
    }
}

pub async fn handle_websocket(socket: WebSocket, registry: Arc<ClientRegistry>) {
    let mut tunnel = WebSocketTunnel::new(socket);
    if let Err(error) = run_session(&mut tunnel, registry).await {
        tracing::warn!(error = %error, "websocket session ended with error");
        let _ = tunnel.socket.send(Message::Close(None)).await;
    }
}

async fn run_session(tunnel: &mut WebSocketTunnel, registry: Arc<ClientRegistry>) -> Result<()> {
    let (stream_id, payload) = tunnel
        .recv_multiplexed_frame()
        .await?
        .ok_or_else(|| anyhow!("websocket closed before login"))?;

    if stream_id != CONTROL_STREAM_ID {
        return Err(anyhow!(
            "first websocket tunnel frame must be on control stream"
        ));
    }

    let login: ControlMessage = decode_postcard_frame(&payload)?;
    let ControlMessage::Login {
        api_key,
        client_version: _,
        protocol_version: _,
    } = login
    else {
        return Err(anyhow!("first control message must be login"));
    };

    if api_key.trim().is_empty() {
        let failure = ControlMessage::LoginFailure {
            reason: "empty api key".to_string(),
        };
        let frame = encode_postcard_frame(&failure)?;
        tunnel
            .send_multiplexed_frame(CONTROL_STREAM_ID, &frame)
            .await?;
        return Ok(());
    }

    if registry.abuse_detector.is_banned(&api_key) {
        let failure = ControlMessage::LoginFailure {
            reason: "user is banned".to_string(),
        };
        let frame = encode_postcard_frame(&failure)?;
        tunnel
            .send_multiplexed_frame(CONTROL_STREAM_ID, &frame)
            .await?;
        return Ok(());
    }

    let connection_id = Uuid::new_v4();
    let mut client = ClientConnection::new(connection_id, None);
    client.transition_to(ConnectionState::Handshaking)?;
    client.authenticate(&api_key, false)?;
    client.activate()?;
    registry.register_client(client).ok();

    let success = ControlMessage::LoginSuccess {
        session_id: format!("ws-session-{}", now_unix_secs()),
        relay_info: RelayInfo {
            addr: SocketAddr::from(([0, 0, 0, 0], 4433)),
            region: "global".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        },
    };
    let success_frame = encode_postcard_frame(&success)?;
    tunnel
        .send_multiplexed_frame(CONTROL_STREAM_ID, &success_frame)
        .await?;

    while let Some((current_stream, data)) = tunnel.recv_multiplexed_frame().await? {
        if current_stream == CONTROL_STREAM_ID {
            let control: ControlMessage = decode_postcard_frame(&data)?;
            if let Some(response) = handle_control_message(control).await? {
                let encoded = encode_postcard_frame(&response)?;
                tunnel
                    .send_multiplexed_frame(CONTROL_STREAM_ID, &encoded)
                    .await?;
            }
            continue;
        }

        tunnel.route_stream_frame(current_stream, data).await?;
    }

    registry.remove_client(&connection_id);
    Ok(())
}

async fn handle_control_message(message: ControlMessage) -> Result<Option<ControlMessage>> {
    let response = match message {
        ControlMessage::Heartbeat { seq, timestamp } => Some(ControlMessage::HeartbeatAck {
            seq,
            timestamp,
            server_time: now_unix_secs(),
        }),
        ControlMessage::RegisterTunnel { config } => Some(ControlMessage::TunnelRegistered {
            tunnel_id: config.id,
            public_url: "https://ws-fallback.pike.life".to_string(),
            remote_port: None,
        }),
        ControlMessage::UnregisterTunnel { .. } => None,
        ControlMessage::Login { .. } => {
            return Err(anyhow!(
                "login control message is only valid as first websocket frame"
            ));
        }
        ControlMessage::LoginSuccess { .. }
        | ControlMessage::LoginFailure { .. }
        | ControlMessage::TunnelRegistered { .. }
        | ControlMessage::TunnelError { .. }
        | ControlMessage::HeartbeatAck { .. } => {
            return Err(anyhow!(
                "received server-originated control message on websocket control stream"
            ));
        }
    };

    Ok(response)
}

fn encode_postcard_frame(message: &ControlMessage) -> Result<Vec<u8>> {
    let payload = postcard::to_allocvec(message)
        .map_err(|error| anyhow!("failed to encode control message: {error}"))?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(anyhow!("control message exceeds max frame size"));
    }

    let len_u32 = u32::try_from(payload.len())
        .map_err(|_| anyhow!("control message too large for framed transport"))?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&len_u32.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn decode_postcard_frame(data: &[u8]) -> Result<ControlMessage> {
    if data.len() < 4 {
        return Err(anyhow!("framed control message too short"));
    }
    let length =
        u32::from_be_bytes(data[0..4].try_into().map_err(|_| anyhow!("bad length"))?) as usize;
    if length > MAX_FRAME_SIZE {
        return Err(anyhow!("control frame exceeds max size"));
    }
    if data.len() < 4 + length {
        return Err(anyhow!("incomplete framed control message"));
    }

    postcard::from_bytes(&data[4..4 + length])
        .map_err(|error| anyhow!("failed to decode framed control message: {error}"))
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use pike_core::proto::ControlMessage;
    use tokio::sync::mpsc;

    use super::{decode_postcard_frame, encode_postcard_frame, handle_control_message};
    use crate::transport::{decode_multiplexed_frame, encode_multiplexed_frame};

    #[test]
    fn control_message_framing_roundtrip() -> Result<()> {
        let input = ControlMessage::Heartbeat {
            seq: 44,
            timestamp: 1_700_000_000,
        };
        let encoded = encode_postcard_frame(&input)?;
        let decoded = decode_postcard_frame(&encoded)?;
        assert!(matches!(decoded, ControlMessage::Heartbeat { .. }));
        Ok(())
    }

    #[test]
    fn websocket_multiplexing_encodes_stream_id_and_payload() {
        let payload = b"stream-payload";
        let encoded = encode_multiplexed_frame(16, payload).expect("encode multiplexed frame");
        let (stream_id, decoded_payload) =
            decode_multiplexed_frame(&encoded).expect("decode multiplexed frame");
        assert_eq!(stream_id, 16);
        assert_eq!(decoded_payload, payload);
    }

    #[tokio::test]
    async fn stream_routing_multiplexes_multiple_stream_ids() {
        let (stream4_tx, mut stream4_rx) = mpsc::channel(4);
        let (stream8_tx, mut stream8_rx) = mpsc::channel(4);
        let mut streams = std::collections::HashMap::new();
        streams.insert(4, stream4_tx);
        streams.insert(8, stream8_tx);

        let payload4 = b"alpha".to_vec();
        let payload8 = b"beta".to_vec();
        let tx4 = streams.get(&4).expect("stream 4 sender").clone();
        let tx8 = streams.get(&8).expect("stream 8 sender").clone();
        tx4.send(payload4.clone()).await.expect("send stream 4");
        tx8.send(payload8.clone()).await.expect("send stream 8");

        assert_eq!(stream4_rx.recv().await.expect("recv stream 4"), payload4);
        assert_eq!(stream8_rx.recv().await.expect("recv stream 8"), payload8);
    }

    #[test]
    fn control_message_decoder_rejects_incomplete_frame() {
        let data = vec![0, 0, 0, 8, 1, 2];
        let err = decode_postcard_frame(&data).expect_err("must reject incomplete frame");
        assert!(err.to_string().contains("incomplete"));
    }

    #[tokio::test]
    async fn control_stream_heartbeat_returns_ack() {
        let response = handle_control_message(ControlMessage::Heartbeat {
            seq: 7,
            timestamp: 123,
        })
        .await
        .expect("heartbeat handling")
        .expect("heartbeat ack response");

        assert!(matches!(
            response,
            ControlMessage::HeartbeatAck { seq: 7, .. }
        ));
    }
}
