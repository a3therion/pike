use std::sync::Arc;

use anyhow::{anyhow, Result};
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc, Mutex};

const FRAME_HEADER_LEN: usize = 12;

pub fn encode_multiplexed_frame(stream_id: u64, payload: &[u8]) -> Result<Vec<u8>> {
    let payload_len = u32::try_from(payload.len())
        .map_err(|_| anyhow!("payload too large for websocket multiplex frame"))?;
    let mut frame = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(&payload_len.to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn decode_multiplexed_frame(data: &[u8]) -> Result<(u64, Vec<u8>)> {
    if data.len() < FRAME_HEADER_LEN {
        return Err(anyhow!("frame too short"));
    }

    let stream_id = u64::from_be_bytes(
        data[0..8]
            .try_into()
            .map_err(|_| anyhow!("invalid stream id bytes"))?,
    );
    let length = u32::from_be_bytes(
        data[8..12]
            .try_into()
            .map_err(|_| anyhow!("invalid length bytes"))?,
    ) as usize;

    if data.len() < FRAME_HEADER_LEN + length {
        return Err(anyhow!("incomplete frame payload"));
    }

    Ok((
        stream_id,
        data[FRAME_HEADER_LEN..FRAME_HEADER_LEN + length].to_vec(),
    ))
}

pub trait Transport: Send + Sync {
    async fn send(&mut self, stream_id: u64, data: &[u8]) -> Result<()>;
    async fn recv(&mut self) -> Result<(u64, Vec<u8>)>;
    async fn close(&mut self) -> Result<()>;
}

pub struct QuicTransport {
    outbound_tx: mpsc::Sender<(u64, Vec<u8>)>,
    inbound_rx: Arc<Mutex<mpsc::Receiver<(u64, Vec<u8>)>>>,
}

pub struct QuicTransportHandle {
    pub outbound_rx: mpsc::Receiver<(u64, Vec<u8>)>,
    pub inbound_tx: mpsc::Sender<(u64, Vec<u8>)>,
}

impl QuicTransport {
    #[must_use]
    pub fn new(buffer: usize) -> (Self, QuicTransportHandle) {
        let (outbound_tx, outbound_rx) = mpsc::channel(buffer);
        let (inbound_tx, inbound_rx) = mpsc::channel(buffer);
        (
            Self {
                outbound_tx,
                inbound_rx: Arc::new(Mutex::new(inbound_rx)),
            },
            QuicTransportHandle {
                outbound_rx,
                inbound_tx,
            },
        )
    }
}

impl Transport for QuicTransport {
    async fn send(&mut self, stream_id: u64, data: &[u8]) -> Result<()> {
        self.outbound_tx
            .send((stream_id, data.to_vec()))
            .await
            .map_err(|_| anyhow!("failed to send QUIC frame"))
    }

    async fn recv(&mut self) -> Result<(u64, Vec<u8>)> {
        self.inbound_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow!("QUIC transport closed"))
    }

    async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

enum OutboundWsMessage {
    Data(Vec<u8>),
    Close,
}

pub struct WebSocketTransport {
    outbound_tx: mpsc::Sender<OutboundWsMessage>,
    inbound_rx: Arc<Mutex<mpsc::Receiver<(u64, Vec<u8>)>>>,
}

impl WebSocketTransport {
    #[must_use]
    pub fn from_socket(socket: WebSocket) -> Self {
        let (mut ws_tx, mut ws_rx) = socket.split();
        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let (outbound_tx, mut outbound_rx) = mpsc::channel(256);

        tokio::spawn(async move {
            while let Some(result) = ws_rx.next().await {
                match result {
                    Ok(Message::Binary(payload)) => {
                        if let Ok(frame) = decode_multiplexed_frame(payload.as_ref()) {
                            if inbound_tx.send(frame).await.is_err() {
                                break;
                            }
                        }
                    }
                    Ok(Message::Close(_)) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        });

        tokio::spawn(async move {
            while let Some(outbound) = outbound_rx.recv().await {
                match outbound {
                    OutboundWsMessage::Data(payload) => {
                        if ws_tx.send(Message::Binary(payload.into())).await.is_err() {
                            break;
                        }
                    }
                    OutboundWsMessage::Close => {
                        let _ = ws_tx.send(Message::Close(None)).await;
                        break;
                    }
                }
            }
        });

        Self {
            outbound_tx,
            inbound_rx: Arc::new(Mutex::new(inbound_rx)),
        }
    }
}

impl Transport for WebSocketTransport {
    async fn send(&mut self, stream_id: u64, data: &[u8]) -> Result<()> {
        let encoded = encode_multiplexed_frame(stream_id, data)?;
        self.outbound_tx
            .send(OutboundWsMessage::Data(encoded))
            .await
            .map_err(|_| anyhow!("failed to send websocket frame"))
    }

    async fn recv(&mut self) -> Result<(u64, Vec<u8>)> {
        self.inbound_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow!("websocket transport closed"))
    }

    async fn close(&mut self) -> Result<()> {
        self.outbound_tx
            .send(OutboundWsMessage::Close)
            .await
            .map_err(|_| anyhow!("failed to close websocket transport"))
    }
}

pub enum ClientTransport {
    Quic(QuicTransport),
    WebSocket(WebSocketTransport),
}

impl Transport for ClientTransport {
    async fn send(&mut self, stream_id: u64, data: &[u8]) -> Result<()> {
        match self {
            Self::Quic(inner) => inner.send(stream_id, data).await,
            Self::WebSocket(inner) => inner.send(stream_id, data).await,
        }
    }

    async fn recv(&mut self) -> Result<(u64, Vec<u8>)> {
        match self {
            Self::Quic(inner) => inner.recv().await,
            Self::WebSocket(inner) => inner.recv().await,
        }
    }

    async fn close(&mut self) -> Result<()> {
        match self {
            Self::Quic(inner) => inner.close().await,
            Self::WebSocket(inner) => inner.close().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_multiplexed_frame, encode_multiplexed_frame, ClientTransport, QuicTransport,
        Transport,
    };

    #[test]
    fn multiplex_frame_roundtrip() {
        let encoded = encode_multiplexed_frame(8, b"hello").expect("encode frame");
        let (stream_id, payload) = decode_multiplexed_frame(&encoded).expect("decode frame");
        assert_eq!(stream_id, 8);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn multiplex_frame_rejects_short_input() {
        let err = decode_multiplexed_frame(&[0, 1, 2]).expect_err("reject short frame");
        assert!(err.to_string().contains("short"));
    }

    #[test]
    fn multiplex_frame_rejects_truncated_payload() {
        let mut data = Vec::new();
        data.extend_from_slice(&4_u64.to_be_bytes());
        data.extend_from_slice(&32_u32.to_be_bytes());
        data.extend_from_slice(b"tiny");

        let err = decode_multiplexed_frame(&data).expect_err("reject truncated payload");
        assert!(err.to_string().contains("incomplete"));
    }

    #[tokio::test]
    async fn quic_transport_trait_roundtrip() {
        let (mut transport, mut handle) = QuicTransport::new(8);
        transport.send(4, b"outbound").await.expect("send outbound");
        let (stream_id, outbound) = handle.outbound_rx.recv().await.expect("outbound frame");
        assert_eq!(stream_id, 4);
        assert_eq!(outbound, b"outbound");

        handle
            .inbound_tx
            .send((12, b"inbound".to_vec()))
            .await
            .expect("seed inbound");
        let (inbound_stream_id, inbound) = transport.recv().await.expect("recv inbound");
        assert_eq!(inbound_stream_id, 12);
        assert_eq!(inbound, b"inbound");
    }

    #[tokio::test]
    async fn client_transport_delegates_to_quic_variant() {
        let (quic, mut handle) = QuicTransport::new(4);
        let mut transport = ClientTransport::Quic(quic);
        transport
            .send(20, b"delegated")
            .await
            .expect("send through enum transport");

        let (stream_id, payload) = handle
            .outbound_rx
            .recv()
            .await
            .expect("outbound delegated frame");
        assert_eq!(stream_id, 20);
        assert_eq!(payload, b"delegated");
    }
}
