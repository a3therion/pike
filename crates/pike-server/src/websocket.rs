//! WebSocket fallback carries the same session messages as the QUIC transport.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use anyhow::{anyhow, bail, Result};
use axum::extract::ws::{Message, WebSocket};
use futures_util::{SinkExt, StreamExt};
use pike_core::proto::{ControlMessage, StreamHeader};
use pike_core::quic::server::{InboundData, OutboundData, PikeMessage, PikeOutboundMessage};
use pike_core::websocket::{decode, encode, WsMessage, MAX_HEADER_SIZE};
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit};

const MAX_OPEN_STREAMS: usize = 256;
// Held from HTTP upgrade until successful login (or connection teardown).
// This bounds pre-authentication frame buffers independently of active sessions.
pub const MAX_PENDING_LOGINS: usize = 8;

pub struct AcceptedWebSocket {
    pub socket: WebSocket,
    pub peer_addr: SocketAddr,
    pub login_permit: OwnedSemaphorePermit,
}

fn decode_inbound(bytes: &[u8], authenticated: bool) -> Result<WsMessage> {
    if !authenticated && (bytes.len() > MAX_HEADER_SIZE + 1 || bytes.first() != Some(&0)) {
        bail!("only a bounded login control message is allowed before authentication");
    }
    let message = decode(bytes)?;
    if !authenticated && !matches!(&message, WsMessage::Control(ControlMessage::Login { .. })) {
        bail!("authentication required");
    }
    Ok(message)
}

struct StreamState {
    header: StreamHeader,
    sent_fin: bool,
    received_fin: bool,
}

#[derive(Default)]
struct Streams {
    next_id: u64,
    active: HashMap<u64, StreamState>,
    connections: HashMap<u64, u64>,
}

impl Streams {
    fn outbound(&mut self, data: OutboundData) -> Result<WsMessage> {
        let header = StreamHeader {
            tunnel_id: data.tunnel_id,
            connection_id: data.connection_id,
            source_addr: data.source_addr,
            streaming: data.streaming,
            mode: data.mode,
        };
        let existing = data
            .stream_id
            .or_else(|| self.connections.get(&data.connection_id).copied());
        let id = if let Some(id) = existing {
            id
        } else {
            if self.active.len() >= MAX_OPEN_STREAMS {
                bail!("WebSocket stream limit reached");
            }
            self.next_id = self
                .next_id
                .checked_add(4)
                .ok_or_else(|| anyhow!("stream IDs exhausted"))?;
            self.active.insert(
                self.next_id,
                StreamState {
                    header: header.clone(),
                    sent_fin: false,
                    received_fin: false,
                },
            );
            self.connections.insert(header.connection_id, self.next_id);
            self.next_id
        };
        let state = self
            .active
            .get_mut(&id)
            .ok_or_else(|| anyhow!("unknown outbound stream"))?;
        if state.header != header || state.sent_fin {
            bail!("invalid outbound stream state");
        }
        state.sent_fin = data.fin;
        self.remove_closed(id);
        Ok(WsMessage::Data {
            stream_id: id,
            header,
            payload: data.payload,
            fin: data.fin,
        })
    }

    fn inbound(&mut self, id: u64, header: &StreamHeader, fin: bool) -> Result<()> {
        let state = self
            .active
            .get_mut(&id)
            .ok_or_else(|| anyhow!("unsolicited data stream"))?;
        if &state.header != header || state.received_fin {
            bail!("invalid inbound stream state");
        }
        state.received_fin = fin;
        self.remove_closed(id);
        Ok(())
    }

    fn remove_closed(&mut self, id: u64) {
        if self
            .active
            .get(&id)
            .is_some_and(|s| s.sent_fin && s.received_fin)
        {
            if let Some(state) = self.active.remove(&id) {
                self.connections.remove(&state.header.connection_id);
            }
        }
    }
}

pub async fn run_transport(
    socket: WebSocket,
    login_permit: OwnedSemaphorePermit,
    inbound: mpsc::Sender<PikeMessage>,
    mut outbound: mpsc::Receiver<PikeOutboundMessage>,
) {
    let (mut writer, mut reader) = socket.split();
    let authenticated = Arc::new(AtomicBool::new(false));
    let streams = Arc::new(Mutex::new(Streams::default()));
    let mut login_permit = Some(login_permit);
    let read = async {
        while let Some(message) = reader.next().await {
            match message? {
                Message::Binary(bytes) => {
                    let message =
                        match decode_inbound(&bytes, authenticated.load(Ordering::Acquire))? {
                            WsMessage::Control(control) => {
                                if !authenticated.load(Ordering::Acquire)
                                    && !matches!(control, ControlMessage::Login { .. })
                                {
                                    bail!("authentication required");
                                }
                                PikeMessage::Control(control)
                            }
                            WsMessage::Data {
                                stream_id,
                                header,
                                payload,
                                fin,
                            } => {
                                if !authenticated.load(Ordering::Acquire) {
                                    bail!("authentication required");
                                }
                                streams.lock().await.inbound(stream_id, &header, fin)?;
                                PikeMessage::Data(InboundData {
                                    stream_id,
                                    tunnel_id: header.tunnel_id,
                                    connection_id: header.connection_id,
                                    source_addr: header.source_addr,
                                    payload,
                                    fin,
                                    streaming: header.streaming,
                                    mode: header.mode,
                                })
                            }
                        };
                    inbound
                        .send(message)
                        .await
                        .map_err(|_| anyhow!("session closed"))?;
                }
                Message::Close(_) => break,
                Message::Ping(_) | Message::Pong(_) => {}
                Message::Text(_) => bail!("binary tunnel envelopes required"),
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let write = async {
        while let Some(message) = outbound.recv().await {
            let denied = matches!(
                &message,
                PikeOutboundMessage::Control(ControlMessage::LoginFailure { .. })
            );
            let message = match message {
                PikeOutboundMessage::Control(control) => {
                    if matches!(control, ControlMessage::LoginSuccess { .. }) {
                        authenticated.store(true, Ordering::Release);
                        login_permit.take();
                    }
                    WsMessage::Control(control)
                }
                PikeOutboundMessage::Data(data) => streams.lock().await.outbound(data)?,
            };
            writer
                .send(Message::Binary(encode(&message)?.into()))
                .await?;
            if denied {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let result = tokio::select! { result = read => result, result = write => result };
    if let Err(error) = result {
        tracing::debug!(%error, "WebSocket tunnel transport closed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pike_core::types::TunnelId;

    #[test]
    fn half_close_keeps_other_direction_and_releases_completed_streams() {
        let mut streams = Streams::default();
        for connection_id in 0..1000 {
            let data = OutboundData {
                stream_id: None,
                tunnel_id: TunnelId::new(),
                connection_id,
                source_addr: "127.0.0.1:3456".parse().unwrap(),
                payload: vec![],
                fin: false,
                streaming: true,
                mode: pike_core::proto::StreamMode::Raw,
            };
            let WsMessage::Data {
                stream_id, header, ..
            } = streams.outbound(data.clone()).unwrap()
            else {
                panic!("expected data")
            };
            streams.inbound(stream_id, &header, true).unwrap();
            assert_eq!(streams.active.len(), 1);
            streams
                .outbound(OutboundData { fin: true, ..data })
                .unwrap();
            assert!(streams.active.is_empty());
            assert!(streams.connections.is_empty());
        }
    }

    #[test]
    fn http_response_fragments_keep_identity_until_fin() {
        let mut streams = Streams::default();
        let request = OutboundData {
            stream_id: None,
            tunnel_id: TunnelId::new(),
            connection_id: 42,
            source_addr: "127.0.0.1:3456".parse().unwrap(),
            payload: b"GET / HTTP/1.1\r\n\r\n".to_vec(),
            fin: true,
            streaming: false,
            mode: pike_core::proto::StreamMode::Raw,
        };
        let WsMessage::Data {
            stream_id, header, ..
        } = streams.outbound(request).unwrap()
        else {
            panic!("expected HTTP request");
        };
        streams.inbound(stream_id, &header, false).unwrap();
        streams.inbound(stream_id, &header, false).unwrap();
        assert_eq!(streams.active.len(), 1);
        let mut changed = header.clone();
        changed.connection_id += 1;
        assert!(streams.inbound(stream_id, &changed, false).is_err());
        streams.inbound(stream_id, &header, true).unwrap();
        assert!(streams.active.is_empty());
        assert!(streams.connections.is_empty());
        assert!(streams.inbound(stream_id, &header, false).is_err());
    }

    #[test]
    fn rejects_unsolicited_and_mismatched_data() {
        let mut streams = Streams::default();
        let header = StreamHeader {
            tunnel_id: TunnelId::new(),
            connection_id: 1,
            source_addr: "127.0.0.1:3456".parse().unwrap(),
            streaming: false,
            mode: pike_core::proto::StreamMode::Raw,
        };
        assert!(streams.inbound(4, &header, true).is_err());
    }

    #[test]
    fn pre_login_rejects_data_before_decoding_and_limits_control_size() {
        let error = decode_inbound(&[1], false).unwrap_err();
        assert!(error.to_string().contains("before authentication"));
        assert!(decode_inbound(&vec![0; MAX_HEADER_SIZE + 2], false).is_err());
        let heartbeat = encode(&WsMessage::Control(ControlMessage::Heartbeat {
            seq: 1,
            timestamp: 0,
        }))
        .unwrap();
        assert!(decode_inbound(&heartbeat, false).is_err());
        let login = encode(&WsMessage::Control(ControlMessage::Login {
            api_key: "test".into(),
            client_version: "test".into(),
            protocol_version: None,
        }))
        .unwrap();
        assert!(matches!(
            decode_inbound(&login, false).unwrap(),
            WsMessage::Control(ControlMessage::Login { .. })
        ));
    }
}
