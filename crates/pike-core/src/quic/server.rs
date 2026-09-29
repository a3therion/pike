use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_quiche::quic::{HandshakeInfo, QuicheConnection};
use tokio_quiche::{quiche, ApplicationOverQuic, QuicResult};

use super::flow::{
    Delivery, MAX_CONNECTION_BUFFER, MAX_STREAM_BUFFER, MAX_TRACKED_STREAMS, MAX_WRITE_ENTRIES,
};
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
    pub mode: crate::proto::StreamMode,
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
    pub mode: crate::proto::StreamMode,
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
    pub mode: crate::proto::StreamMode,
    send_closed: bool,
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
            mode: crate::proto::StreamMode::Raw,
            send_closed: false,
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
            mode: crate::proto::StreamMode::Raw,
            send_closed: false,
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
    delivery: Delivery<PikeMessage>,
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
            delivery: Delivery::default(),
        }
    }

    fn is_authenticated(&self) -> bool {
        matches!(
            self.state,
            ConnectionState::Authenticated(true) | ConnectionState::Active
        )
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
        self.check_write_budget(payload.len(), 1)?;
        self.write_queue.push_back((stream_id, payload, false));
        Ok(())
    }

    fn enqueue_stream_header(
        &mut self,
        stream_id: u64,
        header: &StreamHeader,
    ) -> Result<(), PikeError> {
        let payload = encode_frame(header)?;
        self.check_write_budget(payload.len(), 1)?;
        self.write_queue.push_back((stream_id, payload, false));
        Ok(())
    }

    fn writes_have_capacity(&self) -> bool {
        self.write_queue.len() < MAX_WRITE_ENTRIES - 2
            && self
                .write_queue
                .iter()
                .map(|(_, bytes, _)| bytes.len())
                .sum::<usize>()
                <= MAX_CONNECTION_BUFFER - MAX_STREAM_BUFFER - MAX_FRAME_SIZE - 4
    }

    fn check_write_budget(&self, bytes: usize, entries: usize) -> Result<(), PikeError> {
        if bytes > MAX_STREAM_BUFFER + MAX_FRAME_SIZE + 4
            || self.write_queue.len() + entries > MAX_WRITE_ENTRIES
            || self
                .write_queue
                .iter()
                .map(|(_, bytes, _)| bytes.len())
                .sum::<usize>()
                + bytes
                > MAX_CONNECTION_BUFFER
        {
            return Err(PikeError::ProtocolError(
                "outbound buffering limit exceeded".into(),
            ));
        }
        Ok(())
    }

    fn queue_outbound_data(&mut self, outbound: OutboundData) -> Result<(), PikeError> {
        if outbound.payload.len() > MAX_STREAM_BUFFER {
            return Err(PikeError::ProtocolError(
                "outbound payload limit exceeded".into(),
            ));
        }
        self.check_write_budget(outbound.payload.len() + MAX_FRAME_SIZE + 4, 2)?;
        let existing = outbound.stream_id.or_else(|| {
            outbound
                .streaming
                .then(|| {
                    self.streaming_connections
                        .get(&outbound.connection_id)
                        .copied()
                })
                .flatten()
        });
        let stream_id = if let Some(sid) = existing {
            if self
                .streams
                .get(&sid)
                .is_none_or(|stream| stream.send_closed)
            {
                return Err(PikeError::ProtocolError(
                    "outbound data for unknown or closed stream".into(),
                ));
            }
            sid
        } else {
            if self.streams.len() >= MAX_TRACKED_STREAMS {
                return Err(PikeError::ProtocolError(
                    "too many active data streams".into(),
                ));
            }
            let sid = self.alloc_server_stream_id();
            let header = StreamHeader {
                tunnel_id: outbound.tunnel_id,
                connection_id: outbound.connection_id,
                source_addr: outbound.source_addr,
                streaming: outbound.streaming,
                mode: outbound.mode,
            };
            let mut stream = StreamInfo::data(sid);
            stream.header_received = true;
            stream.tunnel_id = Some(outbound.tunnel_id);
            stream.connection_id = Some(outbound.connection_id);
            stream.source_addr = Some(outbound.source_addr);
            stream.streaming = outbound.streaming;
            stream.mode = outbound.mode;
            self.enqueue_stream_header(sid, &header)?;
            self.streams.insert(sid, stream);
            if outbound.streaming {
                self.streaming_connections
                    .insert(outbound.connection_id, sid);
            }
            sid
        };
        self.write_queue
            .push_back((stream_id, outbound.payload, outbound.fin));
        Ok(())
    }

    fn finish_write(&mut self, stream_id: u64, fin: bool) {
        if fin {
            if let Some(stream) = self.streams.get_mut(&stream_id) {
                stream.send_closed = true;
            }
            self.cleanup_stream(stream_id);
        }
    }

    fn cleanup_stream(&mut self, stream_id: u64) {
        if self
            .streams
            .get(&stream_id)
            .is_some_and(|stream| !stream.is_control && stream.closed && stream.send_closed)
        {
            if let Some(stream) = self.streams.remove(&stream_id) {
                if let Some(connection_id) = stream.connection_id {
                    self.streaming_connections.remove(&connection_id);
                }
            }
        }
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
        if stream.recv_buf.len() + chunk.len() > MAX_FRAME_SIZE + SCRATCH_BUFFER_SIZE + 4 {
            return Err(PikeError::ProtocolError(
                "control stream buffering limit exceeded".into(),
            ));
        }
        stream.recv_buf.extend_from_slice(chunk);
        stream.closed |= fin;
        // Parse only while delivery has room. The unparsed tail stays bounded
        // in the control stream buffer and resumes with the data streams.
        while !self.delivery.is_pending() {
            let stream = self
                .streams
                .get_mut(&stream_id)
                .ok_or_else(|| PikeError::ProtocolError("missing control stream".into()))?;
            let Some(frame) = drain_frame(&mut stream.recv_buf)? else {
                break;
            };
            let message: ControlMessage = postcard::from_bytes(&frame).map_err(|error| {
                PikeError::ProtocolError(format!("invalid control message: {error}"))
            })?;
            self.handle_control_message(stream_id, message)?;
        }
        if self
            .streams
            .get(&stream_id)
            .is_some_and(|stream| stream.closed && stream.recv_buf.is_empty())
        {
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
        if !self.is_authenticated() {
            return Err(PikeError::ProtocolError(
                "data received before authentication".into(),
            ));
        }
        if self.delivery.is_pending() {
            return Err(PikeError::ProtocolError(
                "application delivery is backpressured".into(),
            ));
        }
        if !self.streams.contains_key(&stream_id) && self.streams.len() >= MAX_TRACKED_STREAMS {
            return Err(PikeError::ProtocolError(
                "too many active data streams".into(),
            ));
        }
        if self
            .streams
            .values()
            .map(|stream| stream.recv_buf.len())
            .sum::<usize>()
            + chunk.len()
            > MAX_CONNECTION_BUFFER
        {
            return Err(PikeError::ProtocolError(
                "connection receive buffering limit exceeded".into(),
            ));
        }
        let stream = self
            .streams
            .entry(stream_id)
            .or_insert_with(|| StreamInfo::data(stream_id));
        if stream.closed || stream.recv_buf.len() + chunk.len() > MAX_STREAM_BUFFER {
            return Err(PikeError::ProtocolError(
                "closed or oversized data stream".into(),
            ));
        }
        stream.recv_buf.extend_from_slice(chunk);
        let is_opening = !stream.header_received;
        if is_opening {
            if stream.recv_buf.len() < 4 {
                return if fin {
                    Err(PikeError::ProtocolError("truncated stream header".into()))
                } else {
                    Ok(())
                };
            }
            let header_len =
                u32::from_be_bytes(stream.recv_buf[..4].try_into().expect("four byte prefix"))
                    as usize;
            if header_len > MAX_FRAME_SIZE {
                return Err(PikeError::ProtocolError(
                    "header frame size exceeds limit".into(),
                ));
            }
            if stream.recv_buf.len() < 4 + header_len {
                return if fin {
                    Err(PikeError::ProtocolError("truncated stream header".into()))
                } else {
                    Ok(())
                };
            }
            let header: StreamHeader = postcard::from_bytes(&stream.recv_buf[4..4 + header_len])
                .map_err(|error| {
                    PikeError::ProtocolError(format!("invalid stream header: {error}"))
                })?;
            stream.recv_buf.drain(..4 + header_len);
            stream.tunnel_id = Some(header.tunnel_id);
            stream.connection_id = Some(header.connection_id);
            stream.source_addr = Some(header.source_addr);
            stream.streaming = header.streaming;
            stream.mode = header.mode;
            stream.header_received = true;
        }
        if !stream.recv_buf.is_empty() || (stream.streaming && is_opening) || fin {
            let inbound = InboundData {
                stream_id,
                tunnel_id: stream
                    .tunnel_id
                    .ok_or_else(|| PikeError::ProtocolError("missing tunnel id".into()))?,
                connection_id: stream
                    .connection_id
                    .ok_or_else(|| PikeError::ProtocolError("missing connection id".into()))?,
                source_addr: stream
                    .source_addr
                    .ok_or_else(|| PikeError::ProtocolError("missing source address".into()))?,
                payload: std::mem::take(&mut stream.recv_buf),
                fin,
                streaming: stream.streaming,
                mode: stream.mode,
            };
            self.delivery
                .send(&self.data_tx, PikeMessage::Data(inbound))
                .map_err(|error| PikeError::ProtocolError(error.into()))?;
        }
        stream.closed = fin;
        self.cleanup_stream(stream_id);
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

                self.delivery
                    .send(
                        &self.data_tx,
                        PikeMessage::Control(ControlMessage::Login {
                            api_key,
                            client_version,
                            protocol_version,
                        }),
                    )
                    .map_err(|error| PikeError::ProtocolError(error.into()))?;
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
                self.delivery
                    .send(
                        &self.data_tx,
                        PikeMessage::Control(ControlMessage::RegisterTunnel { config }),
                    )
                    .map_err(|error| PikeError::ProtocolError(error.into()))?;
            }
            ControlMessage::UnregisterTunnel { tunnel_id } => {
                if !self.is_authenticated() {
                    return Err(PikeError::ProtocolError("not authenticated".into()));
                }
                self.registered_tunnels.remove(&tunnel_id);
                self.delivery
                    .send(
                        &self.data_tx,
                        PikeMessage::Control(ControlMessage::UnregisterTunnel { tunnel_id }),
                    )
                    .map_err(|error| PikeError::ProtocolError(error.into()))?;
            }
            ControlMessage::Heartbeat { seq, timestamp } => {
                self.delivery
                    .send(
                        &self.data_tx,
                        PikeMessage::Control(ControlMessage::Heartbeat { seq, timestamp }),
                    )
                    .map_err(|error| PikeError::ProtocolError(error.into()))?;
            }
            response @ ControlMessage::OriginHealthResponse { .. } => {
                if !self.is_authenticated() {
                    return Err(PikeError::ProtocolError("not authenticated".into()));
                }
                self.delivery
                    .send(&self.data_tx, PikeMessage::Control(response))
                    .map_err(|error| PikeError::ProtocolError(error.into()))?;
            }
            ControlMessage::OriginHealthRequest { .. }
            | ControlMessage::LoginSuccess { .. }
            | ControlMessage::LoginFailure { .. }
            | ControlMessage::TunnelRegistered { .. }
            | ControlMessage::TunnelError { .. }
            | ControlMessage::TunnelUnregistered { .. }
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
            result = self.delivery.wait(&self.data_tx), if self.delivery.is_pending() => {
                result.map_err(|_| quiche::Error::InvalidState)?;
            }
            outbound = self.data_rx.recv(), if self.writes_have_capacity() => {
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
        self.delivery
            .flush(&self.data_tx)
            .map_err(|_| quiche::Error::InvalidState)?;
        if let Some(control_id) = self.control_stream_id {
            self.process_control_chunk(control_id, &[], false)
                .map_err(|_| quiche::Error::InvalidState)?;
        }
        for stream_id in qconn.readable().collect::<Vec<_>>() {
            if stream_id == 0 && self.control_stream_id.is_none() {
                self.control_stream_id = Some(0);
                self.streams.insert(0, StreamInfo::control(0));
            }
            if stream_id % 4 > 1 {
                return Err(quiche::Error::InvalidState.into());
            }
            loop {
                if self.delivery.is_pending() {
                    return Ok(());
                }
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
        // Resume previously-readable streams on consumer wakeups as well as
        // incoming packets; tokio-quiche does not call process_reads for both.
        self.process_reads(qconn)?;
        while let Some((stream_id, payload, fin)) = self.write_queue.pop_front() {
            match qconn.stream_send(stream_id, &payload, fin) {
                Ok(written) if written < payload.len() => {
                    self.write_queue
                        .push_front((stream_id, payload[written..].to_vec(), fin));
                    break;
                }
                Ok(_) => self.finish_write(stream_id, fin),
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

fn drain_frame(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>, PikeError> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_be_bytes(buffer[..4].try_into().expect("four byte prefix")) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(PikeError::ProtocolError(format!(
            "frame size {len} exceeds max frame size {MAX_FRAME_SIZE}"
        )));
    }
    if buffer.len() < 4 + len {
        return Ok(None);
    }
    let frame = buffer[4..4 + len].to_vec();
    buffer.drain(..4 + len);
    Ok(Some(frame))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{read_control_message, write_control_message};
    use crate::types::TunnelType;

    fn sample_tunnel_config(tunnel_id: TunnelId) -> TunnelConfig {
        TunnelConfig {
            cloud: None,
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
        app.state = ConnectionState::Active;
        let header = StreamHeader {
            tunnel_id,
            connection_id: 42,
            source_addr: "10.1.1.3:50200".parse().expect("valid socket"),
            streaming: false,
            mode: crate::proto::StreamMode::Raw,
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
    fn data_app(capacity: usize) -> (PikeTunnelApp, mpsc::Receiver<PikeMessage>) {
        let (data_tx, data_rx) = mpsc::channel(capacity);
        let (_, out_rx) = mpsc::channel(4);
        let mut app = PikeTunnelApp::new(data_tx, out_rx);
        app.state = ConnectionState::Active;
        (app, data_rx)
    }

    fn data_header(connection_id: u64, streaming: bool) -> StreamHeader {
        StreamHeader {
            tunnel_id: TunnelId::new(),
            connection_id,
            source_addr: "127.0.0.1:3000".parse().unwrap(),
            streaming,
            mode: crate::proto::StreamMode::Raw,
        }
    }

    fn expect_data(message: PikeMessage) -> InboundData {
        match message {
            PikeMessage::Data(data) => data,
            PikeMessage::Control(_) => panic!("expected data"),
        }
    }

    #[tokio::test]
    async fn full_channel_retains_exact_stream_bytes_and_empty_fin() {
        let (mut app, mut rx) = data_app(1);
        let header = data_header(1, true);
        let mut first = encode_frame(&header).unwrap();
        first.extend_from_slice(b"first payload");
        app.process_data_chunk(4, &first, false).unwrap();
        assert_eq!(app.data_tx.capacity(), 0);
        app.process_data_chunk(4, b"second payload", false).unwrap();
        assert!(app.delivery.is_pending());
        // A cancelled wait must retain ownership, too.
        assert!(
            tokio::time::timeout(Duration::from_millis(10), app.delivery.wait(&app.data_tx))
                .await
                .is_err()
        );
        let first = expect_data(rx.recv().await.unwrap());
        app.delivery.wait(&app.data_tx).await.unwrap();
        app.process_data_chunk(4, &[], true).unwrap();
        assert!(app.delivery.is_pending());
        let second = expect_data(rx.recv().await.unwrap());
        app.delivery.wait(&app.data_tx).await.unwrap();
        let end = expect_data(rx.recv().await.unwrap());
        assert_eq!(
            [first.payload, second.payload].concat(),
            b"first payloadsecond payload"
        );
        assert!(!first.fin && !second.fin);
        assert!(end.fin && end.payload.is_empty());
        assert!(rx.try_recv().is_err());
        assert!(
            app.streams.contains_key(&4),
            "read FIN alone must preserve response direction"
        );
        app.finish_write(4, true);
        assert!(app.streams.is_empty());
    }

    #[tokio::test]
    async fn normal_message_and_fin_survive_full_delivery_queue() {
        let (mut app, mut rx) = data_app(1);
        let header = data_header(1, false);
        let mut frame = encode_frame(&header).unwrap();
        frame.extend_from_slice(b"complete response");
        app.process_data_chunk(4, &frame, true).unwrap();
        app.process_data_chunk(8, &frame, true).unwrap();
        assert!(app.delivery.is_pending());
        assert_eq!(
            expect_data(rx.recv().await.unwrap()).payload,
            b"complete response"
        );
        app.delivery.wait(&app.data_tx).await.unwrap();
        let second = expect_data(rx.recv().await.unwrap());
        assert_eq!(second.payload, b"complete response");
        assert!(second.fin);
    }

    #[tokio::test]
    async fn control_frames_resume_in_order_after_saturation() {
        let (mut app, mut rx) = data_app(1);
        let mut bytes = Vec::new();
        for seq in 0..3 {
            bytes.extend(
                encode_frame(&ControlMessage::Heartbeat {
                    seq,
                    timestamp: seq,
                })
                .unwrap(),
            );
        }
        app.process_control_chunk(0, &bytes, false).unwrap();
        assert!(app.delivery.is_pending());
        assert!(!app.streams[&0].recv_buf.is_empty());
        for expected in 0..3 {
            let message = rx.recv().await.unwrap();
            assert!(
                matches!(message, PikeMessage::Control(ControlMessage::Heartbeat { seq, .. }) if seq == expected)
            );
            app.delivery.flush(&app.data_tx).unwrap();
            app.process_control_chunk(0, &[], false).unwrap();
        }
        assert!(!app.delivery.is_pending());
        assert!(app.streams[&0].recv_buf.is_empty());
    }

    #[tokio::test]
    async fn unauthenticated_data_is_rejected_without_allocating_streams() {
        let (mut app, mut rx) = data_app(1);
        app.state = ConnectionState::Authenticated(false);
        let frame = encode_frame(&data_header(1, false)).unwrap();
        assert!(app.process_data_chunk(4, &frame, false).is_err());
        assert!(app.streams.is_empty());
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn response_fragments_stream_before_fin_and_stop_at_delivery_backpressure() {
        let (mut app, mut rx) = data_app(1);
        let frame = encode_frame(&data_header(1, false)).unwrap();
        app.process_data_chunk(4, &frame, false).unwrap();
        app.process_data_chunk(4, b"first", false).unwrap();
        app.process_data_chunk(4, b"second", false).unwrap();
        assert!(app.delivery.is_pending());
        assert!(app.streams[&4].recv_buf.is_empty());
        assert!(app.process_data_chunk(4, b"third", false).is_err());
        assert_eq!(expect_data(rx.recv().await.unwrap()).payload, b"first");
        app.delivery.flush(&app.data_tx).unwrap();
        assert_eq!(expect_data(rx.recv().await.unwrap()).payload, b"second");
        assert!(app
            .process_data_chunk(4, &vec![0; MAX_STREAM_BUFFER + 1], false)
            .is_err());
        app.process_data_chunk(4, b"third", true).unwrap();
        assert!(expect_data(rx.recv().await.unwrap()).fin);
    }

    #[tokio::test]
    async fn completed_streams_release_metadata_after_both_fin_directions() {
        let (mut app, mut rx) = data_app(1);
        for connection_id in 0..2000 {
            let header = data_header(connection_id, true);
            app.queue_outbound_data(OutboundData {
                stream_id: None,
                tunnel_id: header.tunnel_id,
                connection_id,
                source_addr: header.source_addr,
                payload: b"request".to_vec(),
                fin: true,
                streaming: true,
                mode: crate::proto::StreamMode::Raw,
            })
            .unwrap();
            let sid = app.streaming_connections[&connection_id];
            app.write_queue.clear();
            app.finish_write(sid, true);
            assert!(
                app.streams.contains_key(&sid),
                "write FIN must preserve read direction"
            );
            app.process_data_chunk(sid, b"response", true).unwrap();
            let data = expect_data(rx.recv().await.unwrap());
            assert_eq!(data.payload, b"response");
            assert!(app.streams.is_empty());
            assert!(app.streaming_connections.is_empty());
        }
    }

    #[tokio::test]
    async fn outbound_queue_stops_accepting_before_memory_budget() {
        let (mut app, _rx) = data_app(1);
        let header = data_header(1, true);
        let mut messages = 0;
        while app.writes_have_capacity() {
            app.queue_outbound_data(OutboundData {
                stream_id: None,
                tunnel_id: header.tunnel_id,
                connection_id: header.connection_id,
                source_addr: header.source_addr,
                payload: vec![0; 1024 * 1024],
                fin: false,
                streaming: true,
                mode: crate::proto::StreamMode::Raw,
            })
            .unwrap();
            messages += 1;
        }
        assert!(messages > 1);
        assert!(
            app.write_queue
                .iter()
                .map(|(_, bytes, _)| bytes.len())
                .sum::<usize>()
                <= MAX_CONNECTION_BUFFER
        );
        assert!(app.write_queue.len() <= MAX_WRITE_ENTRIES);
        assert!(app
            .queue_outbound_data(OutboundData {
                stream_id: None,
                tunnel_id: header.tunnel_id,
                connection_id: 2,
                source_addr: header.source_addr,
                payload: vec![0; MAX_STREAM_BUFFER + 1],
                fin: true,
                streaming: false,
                mode: crate::proto::StreamMode::Raw,
            })
            .is_err());
    }
    #[tokio::test]
    async fn real_quic_reads_resume_without_fresh_packets_after_consumer_wakeup() {
        let (mut app, mut rx) = data_app(1);
        let mut pair = super::super::test_support::Pair::new();
        let header = data_header(42, true);
        let mut wire = encode_frame(&header).unwrap();
        let expected = (0..256 * 1024)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        wire.extend_from_slice(&expected);
        let mut offset = 0;
        let mut received = Vec::new();
        let mut fin_count = 0;
        let mut saw_backpressure = false;
        let mut saw_partial_write = false;
        for iteration in 0..10000 {
            if offset < wire.len() {
                match pair.client.stream_send(4, &wire[offset..], true) {
                    Ok(written) => {
                        saw_partial_write |= written < wire.len() - offset;
                        offset += written;
                    }
                    Err(quiche::Error::Done) => {}
                    Err(error) => panic!("send: {error}"),
                }
            }
            pair.exchange();
            app.process_reads(&mut pair.server).unwrap();
            // Stall the consumer initially, then resume entirely through the
            // process_writes callback that runs on an application wakeup.
            if iteration > 20 {
                while let Ok(message) = rx.try_recv() {
                    let data = expect_data(message);
                    received.extend(data.payload);
                    fin_count += usize::from(data.fin);
                }
            }
            saw_backpressure |= app.delivery.is_pending();
            app.process_writes(&mut pair.server).unwrap();
            if fin_count == 1 {
                break;
            }
        }
        assert!(saw_backpressure && saw_partial_write);
        assert_eq!(received, expected);
        assert_eq!(fin_count, 1);
    }
}
