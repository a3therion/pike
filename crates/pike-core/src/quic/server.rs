use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_quiche::quic::{HandshakeInfo, QuicheConnection};
use tokio_quiche::{quiche, ApplicationOverQuic, QuicResult};

use crate::proto::{ControlMessage, StreamHeader, MAX_FRAME_SIZE};
use crate::types::{PikeError, TunnelConfig, TunnelId};
use tracing::info;

const SCRATCH_BUFFER_SIZE: usize = 64 * 1024;
const CONTROL_WAIT_TIMEOUT: Duration = Duration::from_millis(100);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Idle,
    Authenticated(bool),
    Active,
    Closing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundData {
    pub stream_id: u64,
    pub tunnel_id: TunnelId,
    pub connection_id: u64,
    pub source_addr: SocketAddr,
    pub payload: Vec<u8>,
    pub fin: bool,
    pub streaming: bool,
}

#[derive(Debug, Clone)]
pub enum PikeMessage {
    Control(ControlMessage),
    Data(InboundData),
}

#[derive(Debug, Clone)]
pub struct OutboundData {
    pub stream_id: Option<u64>,
    pub tunnel_id: TunnelId,
    pub connection_id: u64,
    pub source_addr: SocketAddr,
    pub payload: Vec<u8>,
    pub fin: bool,
    pub streaming: bool,
}

#[derive(Debug, Clone)]
pub enum PikeOutboundMessage {
    Control(ControlMessage),
    Data(OutboundData),
}

#[derive(Debug, Clone)]
#[allow(clippy::struct_excessive_bools)]
pub struct StreamInfo {
    pub stream_id: u64,
    pub is_control: bool,
    pub tunnel_id: Option<TunnelId>,
    pub connection_id: Option<u64>,
    pub source_addr: Option<SocketAddr>,
    pub recv_buf: Vec<u8>,
    pub header_received: bool,
    pub closed: bool,
    pub streaming: bool,
}

impl StreamInfo {
    fn control(stream_id: u64) -> Self {
        Self {
            stream_id,
            is_control: true,
            tunnel_id: None,
            connection_id: None,
            source_addr: None,
            recv_buf: Vec::new(),
            header_received: true,
            closed: false,
            streaming: false,
        }
    }

    fn data(stream_id: u64) -> Self {
        Self {
            stream_id,
            is_control: false,
            tunnel_id: None,
            connection_id: None,
            source_addr: None,
            recv_buf: Vec::new(),
            header_received: false,
            closed: false,
            streaming: false,
        }
    }
}

pub struct PikeTunnelApp {
    pub state: ConnectionState,
    pub buf: Vec<u8>,
    pub data_rx: mpsc::Receiver<PikeOutboundMessage>,
    pub data_tx: mpsc::Sender<PikeMessage>,
    pub streams: HashMap<u64, StreamInfo>,
    pub control_stream_id: Option<u64>,
    pub write_queue: VecDeque<(u64, Vec<u8>, bool)>,
    registered_tunnels: HashMap<TunnelId, TunnelConfig>,
    next_server_stream_id: u64,
    session_id: Option<String>,
    /// Maps `connection_id` → `stream_id` for streaming (WebSocket) connections,
    /// allowing subsequent outbound data to reuse the same QUIC stream.
    streaming_connections: HashMap<u64, u64>,
    last_keepalive: std::time::Instant,
}

impl PikeTunnelApp {
    #[must_use]
    pub fn new(
        data_tx: mpsc::Sender<PikeMessage>,
        data_rx: mpsc::Receiver<PikeOutboundMessage>,
    ) -> Self {
        Self {
            state: ConnectionState::Idle,
            buf: vec![0; SCRATCH_BUFFER_SIZE],
            data_rx,
            data_tx,
            streams: HashMap::new(),
            control_stream_id: None,
            write_queue: VecDeque::new(),
            registered_tunnels: HashMap::new(),
            next_server_stream_id: 1,
            streaming_connections: HashMap::new(),
            session_id: None,
            last_keepalive: Instant::now(),
        }
    }

    fn is_authenticated(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Authenticated(true) | ConnectionState::Active
        )
    }

    fn is_client_initiated_bidi(stream_id: u64) -> bool {
        stream_id % 4 == 0
    }

    fn alloc_server_stream_id(&mut self) -> u64 {
        let stream_id = self.next_server_stream_id;
        self.next_server_stream_id = self.next_server_stream_id.saturating_add(4);
        stream_id
    }

    fn enqueue_control_message(
        &mut self,
        stream_id: u64,
        message: &ControlMessage,
    ) -> Result<(), PikeError> {
        let payload = encode_control_message_blocking(message)?;
        self.write_queue.push_back((stream_id, payload, false));
        Ok(())
    }

    fn enqueue_stream_header(
        &mut self,
        stream_id: u64,
        header: &StreamHeader,
    ) -> Result<(), PikeError> {
        let payload = encode_frame(header)?;
        self.write_queue.push_back((stream_id, payload, false));
        Ok(())
    }

    fn queue_outbound_data(&mut self, outbound: OutboundData) -> Result<(), PikeError> {
        let stream_id = if let Some(stream_id) = outbound.stream_id {
            // Explicit stream_id: reuse existing stream, skip re-sending header
            stream_id
        } else if outbound.streaming {
            // Streaming mode: reuse existing stream for this connection_id, or create one
            if let Some(&existing_sid) = self.streaming_connections.get(&outbound.connection_id) {
                existing_sid
            } else {
                let sid = self.alloc_server_stream_id();
                let header = StreamHeader {
                    tunnel_id: outbound.tunnel_id,
                    connection_id: outbound.connection_id,
                    source_addr: outbound.source_addr,
                    streaming: true,
                };
                let mut stream_info = StreamInfo::data(sid);
                stream_info.header_received = true;
                stream_info.tunnel_id = Some(outbound.tunnel_id);
                stream_info.connection_id = Some(outbound.connection_id);
                stream_info.source_addr = Some(outbound.source_addr);
                stream_info.streaming = true;
                self.streams.insert(sid, stream_info);
                self.enqueue_stream_header(sid, &header)?;
                self.streaming_connections
                    .insert(outbound.connection_id, sid);
                sid
            }
        } else {
            let sid = self.alloc_server_stream_id();
            let header = StreamHeader {
                tunnel_id: outbound.tunnel_id,
                connection_id: outbound.connection_id,
                source_addr: outbound.source_addr,
                streaming: false,
            };
            let mut stream_info = StreamInfo::data(sid);
            stream_info.header_received = true;
            stream_info.tunnel_id = Some(outbound.tunnel_id);
            stream_info.connection_id = Some(outbound.connection_id);
            stream_info.source_addr = Some(outbound.source_addr);
            self.streams.insert(sid, stream_info);
            self.enqueue_stream_header(sid, &header)?;
            sid
        };

        self.write_queue
            .push_back((stream_id, outbound.payload, outbound.fin));

        // Clean up streaming connection tracking on fin
        if outbound.fin && outbound.streaming {
            self.streaming_connections.remove(&outbound.connection_id);
        }

        Ok(())
    }

    fn process_control_chunk(
        &mut self,
        stream_id: u64,
        chunk: &[u8],
        fin: bool,
    ) -> Result<(), PikeError> {
        let stream = self
            .streams
            .entry(stream_id)
            .or_insert_with(|| StreamInfo::control(stream_id));
        stream.recv_buf.extend_from_slice(chunk);

        let frames = drain_frames(&mut stream.recv_buf)?;
        for frame in frames {
            let message: ControlMessage = postcard::from_bytes(&frame).map_err(|e| {
                PikeError::ProtocolError(format!("failed to decode control message: {e}"))
            })?;
            self.handle_control_message(stream_id, message)?;
        }

        if fin {
            if let Some(info) = self.streams.get_mut(&stream_id) {
                info.closed = true;
            }
            self.state = ConnectionState::Closing;
        }

        Ok(())
    }

    fn process_data_chunk(
        &mut self,
        stream_id: u64,
        chunk: &[u8],
        fin: bool,
    ) -> Result<(), PikeError> {
        let stream = self
            .streams
            .entry(stream_id)
            .or_insert_with(|| StreamInfo::data(stream_id));
        stream.recv_buf.extend_from_slice(chunk);

        if !stream.header_received {
            // Extract only the first frame (the stream header).
            // Everything after it is raw application payload, not length-prefixed.
            if stream.recv_buf.len() < 4 {
                return Ok(());
            }
            let header_len = u32::from_be_bytes([
                stream.recv_buf[0],
                stream.recv_buf[1],
                stream.recv_buf[2],
                stream.recv_buf[3],
            ]) as usize;
            if header_len > MAX_FRAME_SIZE {
                return Err(PikeError::ProtocolError(format!(
                    "header frame size {header_len} exceeds max frame size {MAX_FRAME_SIZE}"
                )));
            }
            if stream.recv_buf.len() < 4 + header_len {
                return Ok(()); // Not enough data yet
            }
            let header_bytes = stream.recv_buf[4..4 + header_len].to_vec();
            stream.recv_buf.drain(..4 + header_len);

            let header: StreamHeader = postcard::from_bytes(&header_bytes)
                .map_err(|e| PikeError::ProtocolError(format!("invalid stream header: {e}")))?;

            stream.tunnel_id = Some(header.tunnel_id);
            stream.connection_id = Some(header.connection_id);
            stream.source_addr = Some(header.source_addr);
            stream.streaming = header.streaming;
            stream.header_received = true;
        }

        // Streaming mode: dispatch every chunk immediately.
        // Normal mode: buffer until fin.
        let should_emit = stream.streaming || fin;
        if stream.header_received && should_emit && !stream.recv_buf.is_empty() {
            let inbound = InboundData {
                stream_id,
                tunnel_id: stream.tunnel_id.ok_or_else(|| {
                    PikeError::ProtocolError("missing tunnel id on stream".to_string())
                })?,
                connection_id: stream.connection_id.ok_or_else(|| {
                    PikeError::ProtocolError("missing connection id on stream".to_string())
                })?,
                source_addr: stream.source_addr.ok_or_else(|| {
                    PikeError::ProtocolError("missing source addr on stream".to_string())
                })?,
                payload: std::mem::take(&mut stream.recv_buf),
                fin,
                streaming: stream.streaming,
            };
            let _ = self.data_tx.try_send(PikeMessage::Data(inbound));
        }

        if fin {
            if let Some(info) = self.streams.get_mut(&stream_id) {
                info.closed = true;
            }
        }

        Ok(())
    }

    fn handle_control_message(
        &mut self,
        stream_id: u64,
        message: ControlMessage,
    ) -> Result<(), PikeError> {
        match message {
            ControlMessage::Login {
                api_key,
                client_version,
                protocol_version,
            } => {
                if api_key.trim().is_empty() {
                    self.state = ConnectionState::Authenticated(false);
                    let response = ControlMessage::LoginFailure {
                        reason: "empty api key".to_string(),
                    };
                    self.enqueue_control_message(stream_id, &response)?;
                    return Ok(());
                }

                if let Err(e) = self
                    .data_tx
                    .try_send(PikeMessage::Control(ControlMessage::Login {
                        api_key,
                        client_version,
                        protocol_version,
                    }))
                {
                    tracing::warn!("Failed to forward Login to main loop: {}", e);
                    let response = ControlMessage::LoginFailure {
                        reason: "server busy".to_string(),
                    };
                    self.enqueue_control_message(stream_id, &response)?;
                }
            }
            ControlMessage::RegisterTunnel { config } => {
                if !self.is_authenticated() {
                    let response = ControlMessage::TunnelError {
                        tunnel_id: config.id,
                        reason: "not authenticated".to_string(),
                    };
                    self.enqueue_control_message(stream_id, &response)?;
                    return Ok(());
                }

                self.state = ConnectionState::Active;
                if let Err(e) =
                    self.data_tx
                        .try_send(PikeMessage::Control(ControlMessage::RegisterTunnel {
                            config,
                        }))
                {
                    tracing::warn!("Failed to forward RegisterTunnel to main loop: {}", e);
                }
            }
            ControlMessage::UnregisterTunnel { tunnel_id } => {
                self.registered_tunnels.remove(&tunnel_id);
                if let Err(e) =
                    self.data_tx
                        .try_send(PikeMessage::Control(ControlMessage::UnregisterTunnel {
                            tunnel_id,
                        }))
                {
                    tracing::warn!("Failed to forward UnregisterTunnel to main loop: {}", e);
                }
            }
            ControlMessage::Heartbeat { seq, timestamp } => {
                if let Err(e) =
                    self.data_tx
                        .try_send(PikeMessage::Control(ControlMessage::Heartbeat {
                            seq,
                            timestamp,
                        }))
                {
                    tracing::warn!("Failed to forward Heartbeat to main loop: {}", e);
                }
            }
            ControlMessage::LoginSuccess { .. }
            | ControlMessage::LoginFailure { .. }
            | ControlMessage::TunnelRegistered { .. }
            | ControlMessage::TunnelError { .. }
            | ControlMessage::HeartbeatAck { .. } => {
                return Err(PikeError::ProtocolError(
                    "received server-originated control message from client".to_string(),
                ));
            }
        }

        Ok(())
    }
}

impl ApplicationOverQuic for PikeTunnelApp {
    fn on_conn_established(
        &mut self,
        qconn: &mut QuicheConnection,
        _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        self.state = ConnectionState::Authenticated(false);
        info!(timeout = ?qconn.timeout(), "server: QUIC connection established");
        Ok(())
    }

    fn should_act(&self) -> bool {
        !matches!(self.state, ConnectionState::Idle)
            || !self.write_queue.is_empty()
            || !self.streams.is_empty()
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    async fn wait_for_data(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        tokio::select! {
            outbound = self.data_rx.recv() => {
                if let Some(outbound) = outbound {
                    match outbound {
                        PikeOutboundMessage::Data(data) => {
                            self.queue_outbound_data(data)
                                .map_err(|_| quiche::Error::InvalidState)?;
                        }
                        PikeOutboundMessage::Control(message) => {
                            match &message {
                                ControlMessage::LoginSuccess { session_id, .. } => {
                                    self.session_id = Some(session_id.clone());
                                    self.state = ConnectionState::Authenticated(true);
                                }
                                ControlMessage::LoginFailure { .. } => {
                                    self.session_id = None;
                                    self.state = ConnectionState::Authenticated(false);
                                }
                                _ => {}
                            }
                            let stream_id = self.control_stream_id.ok_or(quiche::Error::InvalidState)?;
                            self.enqueue_control_message(stream_id, &message)
                                .map_err(|_| quiche::Error::InvalidState)?;
                        }
                    }
                } else {
                    self.state = ConnectionState::Closing;
                }
            }
            _ = tokio::time::sleep(CONTROL_WAIT_TIMEOUT) => {}
        }

        Ok(())
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        for stream_id in qconn.readable() {
            if self.control_stream_id.is_none() && Self::is_client_initiated_bidi(stream_id) {
                self.control_stream_id = Some(stream_id);
                self.streams
                    .insert(stream_id, StreamInfo::control(stream_id));
            }

            loop {
                match qconn.stream_recv(stream_id, &mut self.buf) {
                    Ok((n, fin)) => {
                        let chunk = self.buf[..n].to_vec();

                        if Some(stream_id) == self.control_stream_id {
                            self.process_control_chunk(stream_id, &chunk, fin)
                                .map_err(|_| quiche::Error::InvalidState)?;
                        } else {
                            self.process_data_chunk(stream_id, &chunk, fin)
                                .map_err(|_| quiche::Error::InvalidState)?;
                        }

                        if fin {
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(error) => return Err(error.into()),
                }
            }
        }

        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        while let Some((stream_id, payload, fin)) = self.write_queue.pop_front() {
            match qconn.stream_send(stream_id, &payload, fin) {
                Ok(written) if written < payload.len() => {
                    self.write_queue
                        .push_front((stream_id, payload[written..].to_vec(), fin));
                    break;
                }
                Ok(_) => {}
                Err(quiche::Error::Done) => {
                    self.write_queue.push_front((stream_id, payload, fin));
                    break;
                }
                Err(error) => return Err(error.into()),
            }
        }

        if self.last_keepalive.elapsed() >= KEEPALIVE_INTERVAL {
            let _ = qconn.send_ack_eliciting();
            self.last_keepalive = std::time::Instant::now();
        }

        if matches!(self.state, ConnectionState::Closing) && self.write_queue.is_empty() {
            let _ = qconn.close(true, 0, b"closing");
        }

        Ok(())
    }
}

fn frame_len_prefix(len: usize) -> Result<[u8; 4], PikeError> {
    let len_u32 = u32::try_from(len)
        .map_err(|_| PikeError::ProtocolError("frame length exceeds u32".to_string()))?;
    Ok(len_u32.to_be_bytes())
}

fn encode_frame<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, PikeError> {
    let payload = postcard::to_allocvec(value)
        .map_err(|e| PikeError::ProtocolError(format!("failed to encode frame: {e}")))?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(PikeError::ProtocolError(format!(
            "frame size {} exceeds max {}",
            payload.len(),
            MAX_FRAME_SIZE
        )));
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&frame_len_prefix(payload.len())?);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn encode_control_message_blocking(message: &ControlMessage) -> Result<Vec<u8>, PikeError> {
    encode_frame(message)
}

fn drain_frames(buffer: &mut Vec<u8>) -> Result<Vec<Vec<u8>>, PikeError> {
    let mut frames = Vec::new();
    let mut offset = 0;

    while offset + 4 <= buffer.len() {
        let len = u32::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]) as usize;

        if len > MAX_FRAME_SIZE {
            return Err(PikeError::ProtocolError(format!(
                "frame size {len} exceeds max frame size {MAX_FRAME_SIZE}"
            )));
        }

        let start = offset + 4;
        let end = start + len;
        if end > buffer.len() {
            break;
        }

        frames.push(buffer[start..end].to_vec());
        offset = end;
    }

    if offset > 0 {
        buffer.drain(0..offset);
    }

    Ok(frames)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{read_control_message, write_control_message};
    use crate::types::TunnelType;

    fn sample_tunnel_config(tunnel_id: TunnelId) -> TunnelConfig {
        TunnelConfig {
            id: tunnel_id,
            tunnel_type: TunnelType::Http {
                local_port: 8080,
                subdomain: Some("demo".to_string()),
            },
            local_addr: "127.0.0.1:8080".parse().expect("valid addr"),
        }
    }

    #[tokio::test]
    async fn control_message_parsing_with_proto_framing() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let msg = ControlMessage::Login {
            api_key: "valid-key".to_string(),
            client_version: "0.1.0".to_string(),
            protocol_version: Some(1),
        };

        write_control_message(&mut client, &msg)
            .await
            .expect("write control message");

        let decoded = read_control_message(&mut server)
            .await
            .expect("read control message");
        let decoded_enc = postcard::to_allocvec(&decoded).expect("encode decoded");
        let msg_enc = postcard::to_allocvec(&msg).expect("encode expected");
        assert_eq!(decoded_enc, msg_enc);
    }

    #[tokio::test]
    async fn login_is_forwarded_to_main_loop_until_authenticated_response() {
        let (data_tx, mut data_rx) = mpsc::channel(16);
        let (_out_tx, out_rx) = mpsc::channel(16);
        let mut app = PikeTunnelApp::new(data_tx, out_rx);
        app.state = ConnectionState::Authenticated(false);

        app.handle_control_message(
            4,
            ControlMessage::Login {
                api_key: "my-api-key".to_string(),
                client_version: "0.1.0".to_string(),
                protocol_version: Some(1),
            },
        )
        .expect("handle login");

        assert!(matches!(app.state, ConnectionState::Authenticated(false)));
        assert_eq!(app.write_queue.len(), 0);

        let forwarded = data_rx
            .recv()
            .await
            .expect("forwarded login control message");
        let PikeMessage::Control(ControlMessage::Login {
            api_key,
            client_version,
            protocol_version,
        }) = forwarded
        else {
            panic!("expected forwarded login control message");
        };
        assert_eq!(api_key, "my-api-key");
        assert_eq!(client_version, "0.1.0");
        assert_eq!(protocol_version, Some(1));
    }

    #[tokio::test]
    async fn register_without_auth_is_rejected() {
        let (data_tx, _data_rx) = mpsc::channel(16);
        let (_out_tx, out_rx) = mpsc::channel(16);
        let mut app = PikeTunnelApp::new(data_tx, out_rx);

        let tunnel_id = TunnelId::new();
        app.handle_control_message(
            4,
            ControlMessage::RegisterTunnel {
                config: sample_tunnel_config(tunnel_id),
            },
        )
        .expect("handle register");

        assert!(app.registered_tunnels.is_empty());
        assert_eq!(app.write_queue.len(), 1);
    }

    #[tokio::test]
    async fn data_stream_routing_after_header() {
        let (data_tx, mut data_rx) = mpsc::channel(16);
        let (_out_tx, out_rx) = mpsc::channel(16);
        let mut app = PikeTunnelApp::new(data_tx, out_rx);

        let tunnel_id = TunnelId::new();
        let stream_id = 8;
        let header = StreamHeader {
            tunnel_id,
            connection_id: 42,
            source_addr: "10.1.1.3:50200".parse().expect("valid socket"),
            streaming: false,
        };
        let mut header_bytes = encode_frame(&header).expect("encode header");
        header_bytes.extend_from_slice(b"hello");

        app.process_data_chunk(stream_id, &header_bytes, true)
            .expect("process data");

        let inbound = data_rx.recv().await.expect("inbound data");
        let PikeMessage::Data(inbound) = inbound else {
            panic!("expected data message");
        };
        assert_eq!(inbound.stream_id, stream_id);
        assert_eq!(inbound.tunnel_id, tunnel_id);
        assert_eq!(inbound.connection_id, 42);
        assert_eq!(inbound.payload, b"hello");
        assert!(inbound.fin);
        assert!(!inbound.streaming);
    }
}
