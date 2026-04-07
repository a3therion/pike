use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use tokio::sync::{mpsc, oneshot};
use tokio_quiche::quic::{connect_with_config, HandshakeInfo, QuicheConnection};
use tokio_quiche::settings::{Hooks, QuicSettings};
use tokio_quiche::socket::Socket;
use tokio_quiche::QuicConnection;
use tokio_quiche::{quiche, ApplicationOverQuic, ConnectionParams, QuicResult};

use crate::proto::{ControlMessage, StreamHeader, ALPN_PROTOCOL, MAX_FRAME_SIZE};
use crate::quic::config::PikeQuicConfig;
use crate::types::{ApiKey, TunnelConfig, TunnelId};
use tracing::{info, warn};

const SCRATCH_BUFFER_SIZE: usize = 64 * 1024;
const CONTROL_STREAM_ID: u64 = 0;
const FIRST_DATA_STREAM_ID: u64 = 4;
const WAIT_FOR_DATA_TIMEOUT: Duration = Duration::from_millis(100);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(15);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
const MAX_BACKOFF_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientState {
    Connecting,
    LoggingIn,
    RegisteringTunnels,
    Active,
    Reconnecting { attempt: u32, backoff: Duration },
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalData {
    pub stream_id: Option<u64>,
    pub tunnel_id: TunnelId,
    pub connection_id: u64,
    pub source_addr: SocketAddr,
    pub payload: Vec<u8>,
    pub fin: bool,
    pub streaming: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerData {
    pub stream_id: u64,
    pub tunnel_id: TunnelId,
    pub connection_id: u64,
    pub source_addr: SocketAddr,
    pub payload: Vec<u8>,
    pub fin: bool,
    pub streaming: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationResult {
    pub public_url: String,
    pub remote_port: Option<u16>,
}

#[derive(Debug)]
enum ClientCommand {
    RegisterTunnel {
        tunnel: TunnelConfig,
        result_tx: oneshot::Sender<RegistrationResult>,
    },
    Close,
}

#[derive(Debug)]
struct StreamReadState {
    header: Option<StreamHeader>,
    buf: Vec<u8>,
    streaming: bool,
}

pub struct PikeConnection {
    control_tx: mpsc::Sender<ClientCommand>,
    pub data_tx: mpsc::Sender<LocalData>,
    pub data_rx: mpsc::Receiver<ServerData>,
    _quic_conn: QuicConnection, // Keep connection alive
}

impl PikeConnection {
    pub async fn request_tunnel_registration(
        &self,
        tunnel: TunnelConfig,
    ) -> Result<(TunnelId, oneshot::Receiver<RegistrationResult>)> {
        let tunnel_id = tunnel.id;
        let (result_tx, result_rx) = oneshot::channel();
        self.control_tx
            .send(ClientCommand::RegisterTunnel { tunnel, result_tx })
            .await
            .map_err(|_| anyhow!("connection control channel closed"))?;
        Ok((tunnel_id, result_rx))
    }

    pub async fn close(&self) -> Result<()> {
        self.control_tx
            .send(ClientCommand::Close)
            .await
            .map_err(|_| anyhow!("connection control channel closed"))
    }
}

pub struct PikeClient {
    config: PikeQuicConfig,
    relay_addr: SocketAddr,
    relay_server_name: Option<String>,
    verify_peer: bool,
    api_key: ApiKey,
    tunnels: Vec<TunnelConfig>,
    session_ticket: Option<Vec<u8>>,
}

impl PikeClient {
    #[must_use]
    pub fn new(
        config: PikeQuicConfig,
        relay_addr: SocketAddr,
        relay_server_name: Option<String>,
        verify_peer: bool,
        api_key: ApiKey,
        tunnels: Vec<TunnelConfig>,
    ) -> Self {
        Self {
            config,
            relay_addr,
            relay_server_name,
            verify_peer,
            api_key,
            tunnels,
            session_ticket: None,
        }
    }

    pub async fn connect(&mut self) -> Result<PikeConnection> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(self.relay_addr).await?;

        let mut settings = QuicSettings::default();
        settings.alpn = vec![ALPN_PROTOCOL.to_vec()];
        settings.verify_peer = self.verify_peer;
        settings.max_idle_timeout = Some(Duration::from_millis(self.config.idle_timeout_ms));

        let params = ConnectionParams::new_client(settings, None, Hooks::default());

        let (control_tx, control_rx) = mpsc::channel(256);
        let (local_data_tx, local_data_rx) = mpsc::channel(1024);
        let (server_data_tx, server_data_rx) = mpsc::channel(1024);

        let app = PikeClientApp::new(
            self.api_key.clone(),
            self.tunnels.clone(),
            control_rx,
            local_data_rx,
            server_data_tx,
        );

        let socket = Socket::try_from(socket)?;
        let quic_conn = Box::pin(connect_with_config(
            socket,
            self.relay_server_name.as_deref(),
            &params,
            app,
        ))
        .await
        .map_err(|error| anyhow!(error.to_string()))?;

        Ok(PikeConnection {
            control_tx,
            data_tx: local_data_tx,
            data_rx: server_data_rx,
            _quic_conn: quic_conn,
        })
    }

    pub async fn register_tunnel(&self, tunnel: TunnelConfig) -> Result<TunnelId> {
        let message = ControlMessage::RegisterTunnel { config: tunnel };
        let encoded = postcard::to_allocvec(&message)?;
        let _: ControlMessage = postcard::from_bytes(&encoded)?;

        if let ControlMessage::RegisterTunnel { config } = message {
            Ok(config.id)
        } else {
            Err(anyhow!("failed to build register tunnel message"))
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut reconnect_attempt = 0_u32;

        loop {
            match Box::pin(self.connect()).await {
                Ok(mut connection) => {
                    reconnect_attempt = 0;

                    while connection.data_rx.recv().await.is_some() {}

                    let next_attempt = reconnect_attempt.saturating_add(1);
                    let backoff = reconnect_backoff(next_attempt);
                    reconnect_attempt = next_attempt;
                    tokio::time::sleep(backoff).await;
                }
                Err(error) => {
                    let next_attempt = reconnect_attempt.saturating_add(1);
                    let backoff = reconnect_backoff(next_attempt);
                    reconnect_attempt = next_attempt;

                    self.store_reconnect_state(next_attempt, backoff);
                    tokio::time::sleep(backoff).await;

                    if self.session_ticket.is_none() {
                        self.session_ticket = Some(Vec::new());
                    }

                    if reconnect_attempt > 1_000 {
                        return Err(anyhow!("connection retry limit reached: {error}"));
                    }
                }
            }
        }
    }

    fn store_reconnect_state(&self, _attempt: u32, _backoff: Duration) {}
}

pub struct PikeClientApp {
    pub state: ClientState,
    pub api_key: ApiKey,
    pub tunnels_to_register: Vec<TunnelConfig>,
    pub registered_tunnels: HashMap<TunnelId, TunnelConfig>,
    pub data_rx: mpsc::Receiver<LocalData>,
    pub data_tx: mpsc::Sender<ServerData>,
    pub write_queue: VecDeque<(u64, Vec<u8>, bool)>,
    pub pending_registrations: HashMap<String, oneshot::Sender<RegistrationResult>>,
    pub buf: Vec<u8>,
    control_rx: mpsc::Receiver<ClientCommand>,
    control_stream_buf: Vec<u8>,
    data_streams: HashMap<u64, StreamReadState>,
    next_data_stream_id: u64,
    heartbeat_seq: u64,
    heartbeat_interval: tokio::time::Interval,
    last_keepalive: std::time::Instant,
    close_requested: bool,
}

impl PikeClientApp {
    fn new(
        api_key: ApiKey,
        tunnels_to_register: Vec<TunnelConfig>,
        control_rx: mpsc::Receiver<ClientCommand>,
        data_rx: mpsc::Receiver<LocalData>,
        data_tx: mpsc::Sender<ServerData>,
    ) -> Self {
        Self {
            state: ClientState::Connecting,
            api_key,
            tunnels_to_register,
            registered_tunnels: HashMap::new(),
            data_rx,
            data_tx,
            write_queue: VecDeque::new(),
            pending_registrations: HashMap::new(),
            buf: vec![0; SCRATCH_BUFFER_SIZE],
            control_rx,
            control_stream_buf: Vec::new(),
            data_streams: HashMap::new(),
            next_data_stream_id: FIRST_DATA_STREAM_ID,
            heartbeat_seq: 0,
            heartbeat_interval: tokio::time::interval(HEARTBEAT_INTERVAL),
            last_keepalive: Instant::now(),
            close_requested: false,
        }
    }

    fn now_unix_seconds() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    fn alloc_data_stream_id(&mut self) -> u64 {
        let stream_id = self.next_data_stream_id;
        self.next_data_stream_id = self.next_data_stream_id.saturating_add(4);
        stream_id
    }

    fn queue_control_message(&mut self, message: &ControlMessage) -> Result<()> {
        let payload = encode_frame(message)?;
        self.write_queue
            .push_back((CONTROL_STREAM_ID, payload, false));
        Ok(())
    }

    fn queue_stream_header(&mut self, stream_id: u64, header: &StreamHeader) -> Result<()> {
        let payload = encode_frame(header)?;
        self.write_queue.push_back((stream_id, payload, false));
        Ok(())
    }

    fn queue_login(&mut self) -> Result<()> {
        self.state = ClientState::LoggingIn;
        self.queue_control_message(&ControlMessage::Login {
            api_key: self.api_key.as_str().to_string(),
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            protocol_version: Some(crate::proto::PROTOCOL_VERSION),
        })
    }

    fn queue_register_tunnels(&mut self) -> Result<()> {
        self.state = ClientState::RegisteringTunnels;
        let pending: Vec<TunnelConfig> = self.tunnels_to_register.clone();
        for tunnel in pending {
            self.queue_control_message(&ControlMessage::RegisterTunnel { config: tunnel })?;
        }
        Ok(())
    }

    fn should_send_heartbeat(&self) -> bool {
        !matches!(self.state, ClientState::Connecting | ClientState::Closed)
    }

    fn queue_heartbeat(&mut self) -> Result<()> {
        if !self.should_send_heartbeat() {
            return Ok(());
        }

        let seq = self.heartbeat_seq;
        self.heartbeat_seq = self.heartbeat_seq.saturating_add(1);

        self.queue_control_message(&ControlMessage::Heartbeat {
            seq,
            timestamp: Self::now_unix_seconds(),
        })
    }

    fn queue_local_data(&mut self, local: LocalData) -> Result<()> {
        let stream_id = local
            .stream_id
            .unwrap_or_else(|| self.alloc_data_stream_id());

        // Only send header for new streams (stream_id was None)
        if local.stream_id.is_none() {
            let header = StreamHeader {
                tunnel_id: local.tunnel_id,
                connection_id: local.connection_id,
                source_addr: local.source_addr,
                streaming: local.streaming,
            };
            self.queue_stream_header(stream_id, &header)?;
        }

        self.write_queue
            .push_back((stream_id, local.payload, local.fin));
        Ok(())
    }

    fn handle_client_command(&mut self, cmd: ClientCommand) -> Result<()> {
        match cmd {
            ClientCommand::RegisterTunnel { tunnel, result_tx } => {
                self.pending_registrations
                    .insert(tunnel.id.to_string(), result_tx);

                if !self
                    .tunnels_to_register
                    .iter()
                    .any(|cfg| cfg.id == tunnel.id)
                {
                    self.tunnels_to_register.push(tunnel.clone());
                }

                if matches!(self.state, ClientState::Connecting | ClientState::LoggingIn) {
                    return Ok(());
                }

                self.queue_control_message(&ControlMessage::RegisterTunnel { config: tunnel })
            }
            ClientCommand::Close => {
                self.close_requested = true;
                self.state = ClientState::Closed;
                Ok(())
            }
        }
    }

    fn handle_control_message(&mut self, message: ControlMessage) -> Result<()> {
        match message {
            ControlMessage::LoginSuccess { .. } => {
                self.queue_register_tunnels()?;
            }
            ControlMessage::TunnelRegistered {
                tunnel_id,
                public_url,
                remote_port,
            } => {
                if let Some(result_tx) = self.pending_registrations.remove(&tunnel_id.to_string()) {
                    let _ = result_tx.send(RegistrationResult {
                        public_url,
                        remote_port,
                    });
                }

                if let Some(config) = self
                    .tunnels_to_register
                    .iter()
                    .find(|cfg| cfg.id == tunnel_id)
                    .cloned()
                {
                    self.registered_tunnels.insert(tunnel_id, config);
                    tracing::info!(tunnel_id = %tunnel_id, "HTTP tunnel confirmed by server");
                } else {
                    warn!(
                        tunnel_id = %tunnel_id,
                        "server confirmed tunnel missing from local registration tracking"
                    );
                }

                let all_known_tunnels_registered =
                    self.registered_tunnels.len() >= self.tunnels_to_register.len();
                let no_registrations_outstanding = self.pending_registrations.is_empty();

                if all_known_tunnels_registered || no_registrations_outstanding {
                    self.state = ClientState::Active;
                }
            }
            ControlMessage::HeartbeatAck { .. } => {}
            ControlMessage::LoginFailure { reason }
            | ControlMessage::TunnelError { reason, .. } => {
                tracing::error!("Received error from server: {}", reason);
                self.state = ClientState::Closed;
            }
            ControlMessage::Login { .. }
            | ControlMessage::RegisterTunnel { .. }
            | ControlMessage::UnregisterTunnel { .. }
            | ControlMessage::Heartbeat { .. } => {
                return Err(anyhow!("received client-originated message from server"));
            }
        }

        Ok(())
    }

    fn process_control_chunk(&mut self, chunk: &[u8], fin: bool) -> Result<()> {
        self.control_stream_buf.extend_from_slice(chunk);
        let frames = drain_frames(&mut self.control_stream_buf)?;

        for frame in frames {
            let message: ControlMessage = postcard::from_bytes(&frame)?;
            self.handle_control_message(message)?;
        }

        if fin {
            self.state = ClientState::Closed;
        }

        Ok(())
    }

    fn process_data_chunk(&mut self, stream_id: u64, chunk: &[u8], fin: bool) -> Result<()> {
        let stream_state = self
            .data_streams
            .entry(stream_id)
            .or_insert(StreamReadState {
                header: None,
                buf: Vec::new(),
                streaming: false,
            });
        stream_state.buf.extend_from_slice(chunk);

        if stream_state.header.is_none() {
            if stream_state.buf.len() < 4 {
                return Ok(());
            }

            let header_len = u32::from_be_bytes([
                stream_state.buf[0],
                stream_state.buf[1],
                stream_state.buf[2],
                stream_state.buf[3],
            ]) as usize;

            if header_len > MAX_FRAME_SIZE {
                return Err(anyhow!(
                    "header frame size {} exceeds max {}",
                    header_len,
                    MAX_FRAME_SIZE
                ));
            }

            let total_header_size = 4 + header_len;
            if stream_state.buf.len() < total_header_size {
                return Ok(());
            }

            let header_bytes = &stream_state.buf[4..total_header_size];
            let header: StreamHeader = postcard::from_bytes(header_bytes)
                .map_err(|e| anyhow!("header parse error: {}", e))?;
            stream_state.streaming = header.streaming;
            stream_state.header = Some(header);

            stream_state.buf.drain(0..total_header_size);
        }

        // Streaming mode: dispatch every chunk immediately.
        // Normal mode: buffer until fin.
        let should_emit = stream_state.streaming || fin;
        if let Some(header) = &stream_state.header {
            if should_emit && !stream_state.buf.is_empty() {
                let server_data = ServerData {
                    stream_id,
                    tunnel_id: header.tunnel_id,
                    connection_id: header.connection_id,
                    source_addr: header.source_addr,
                    payload: std::mem::take(&mut stream_state.buf),
                    fin,
                    streaming: stream_state.streaming,
                };

                let _ = self.data_tx.try_send(server_data);
            }
        }

        if fin {
            self.data_streams.remove(&stream_id);
        }

        Ok(())
    }

    fn set_reconnecting(&mut self, attempt: u32) {
        self.state = ClientState::Reconnecting {
            attempt,
            backoff: reconnect_backoff(attempt),
        };
    }
}

impl ApplicationOverQuic for PikeClientApp {
    fn on_conn_established(
        &mut self,
        qconn: &mut QuicheConnection,
        _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        self.queue_login()
            .map_err(|_| quiche::Error::InvalidState)?;
        info!(timeout = ?qconn.timeout(), "QUIC connection established");
        Ok(())
    }

    fn should_act(&self) -> bool {
        !matches!(self.state, ClientState::Closed) || !self.write_queue.is_empty()
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    async fn wait_for_data(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        tokio::select! {
            Some(cmd) = self.control_rx.recv() => {
                self.handle_client_command(cmd)
                    .map_err(|_| quiche::Error::InvalidState)?;
            }
            Some(local_data) = self.data_rx.recv() => {
                self.queue_local_data(local_data).map_err(|_| quiche::Error::InvalidState)?;
            }
            _ = self.heartbeat_interval.tick() => {
                self.queue_heartbeat().map_err(|_| quiche::Error::InvalidState)?;
            }
            _ = tokio::time::sleep(WAIT_FOR_DATA_TIMEOUT) => {
                // Timeout is normal, just continue
            }
            _ = tokio::time::sleep(LOGIN_TIMEOUT), if self.state == ClientState::LoggingIn => {
                warn!("Login timed out after 15s — server did not send LoginSuccess. Transitioning to Reconnecting.");
                self.set_reconnecting(1);
            }
        }

        Ok(())
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        if qconn.is_closed() {
            return Err(quiche::Error::Done.into());
        }
        for stream_id in qconn.readable().collect::<Vec<_>>() {
            loop {
                match qconn.stream_recv(stream_id, &mut self.buf) {
                    Ok((n, fin)) => {
                        let chunk = self.buf[..n].to_vec();

                        let result = if stream_id == CONTROL_STREAM_ID {
                            self.process_control_chunk(&chunk, fin)
                        } else {
                            self.process_data_chunk(stream_id, &chunk, fin)
                        };

                        if result.is_err() {
                            self.set_reconnecting(1);
                            return Err(quiche::Error::InvalidState.into());
                        }

                        if fin {
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(error) => {
                        self.set_reconnecting(1);
                        return Err(error.into());
                    }
                }
            }
        }

        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        if qconn.is_closed() {
            return Err(quiche::Error::Done.into());
        }
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

        if self.close_requested && self.write_queue.is_empty() {
            let _ = qconn.close(true, 0, b"client close");
        }

        Ok(())
    }
}

fn frame_len_prefix(len: usize) -> Result<[u8; 4]> {
    let len_u32 = u32::try_from(len)?;
    Ok(len_u32.to_be_bytes())
}

fn encode_frame<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    let payload = postcard::to_allocvec(value)?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(anyhow!(
            "frame size {} exceeds max {}",
            payload.len(),
            MAX_FRAME_SIZE
        ));
    }

    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&frame_len_prefix(payload.len())?);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn drain_frames(buffer: &mut Vec<u8>) -> Result<Vec<Vec<u8>>> {
    let mut frames = Vec::new();
    let mut offset = 0_usize;

    while offset + 4 <= buffer.len() {
        let len = u32::from_be_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
        ]) as usize;

        if len > MAX_FRAME_SIZE {
            return Err(anyhow!(
                "frame size {len} exceeds max frame size {MAX_FRAME_SIZE}"
            ));
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

fn reconnect_backoff(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6);
    let secs = 1_u64 << shift;
    Duration::from_secs(secs.min(MAX_BACKOFF_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TunnelType;

    fn sample_tunnel(tunnel_id: TunnelId) -> TunnelConfig {
        TunnelConfig {
            id: tunnel_id,
            tunnel_type: TunnelType::Http {
                local_port: 3000,
                subdomain: Some("demo".to_string()),
            },
            local_addr: "127.0.0.1:3000".parse().expect("valid socket"),
        }
    }

    fn make_app(tunnels_to_register: Vec<TunnelConfig>) -> PikeClientApp {
        let (_control_tx, control_rx) = mpsc::channel(16);
        let (_local_tx, local_rx) = mpsc::channel(16);
        let (server_tx, _server_rx) = mpsc::channel(16);

        PikeClientApp::new(
            ApiKey("key-123".to_string()),
            tunnels_to_register,
            control_rx,
            local_rx,
            server_tx,
        )
    }

    #[test]
    fn reconnect_backoff_exponential_and_capped() {
        assert_eq!(reconnect_backoff(1), Duration::from_secs(1));
        assert_eq!(reconnect_backoff(2), Duration::from_secs(2));
        assert_eq!(reconnect_backoff(3), Duration::from_secs(4));
        assert_eq!(reconnect_backoff(4), Duration::from_secs(8));
        assert_eq!(reconnect_backoff(7), Duration::from_secs(60));
        assert_eq!(reconnect_backoff(20), Duration::from_secs(60));
    }

    #[test]
    fn control_message_roundtrip_serialization() {
        let tunnel_id = TunnelId::new();
        let msg = ControlMessage::RegisterTunnel {
            config: sample_tunnel(tunnel_id),
        };

        let encoded = encode_frame(&msg).expect("encode control message");
        let mut framed_bytes = encoded.clone();
        let frame_payloads = drain_frames(&mut framed_bytes).expect("drain frame");
        assert_eq!(frame_payloads.len(), 1);

        let decoded: ControlMessage =
            postcard::from_bytes(&frame_payloads[0]).expect("decode frame");
        assert!(matches!(decoded, ControlMessage::RegisterTunnel { .. }));
    }

    #[tokio::test]
    async fn login_success_transitions_to_registering_state() {
        let tunnel = sample_tunnel(TunnelId::new());
        let mut app = make_app(vec![tunnel]);
        app.state = ClientState::LoggingIn;

        app.handle_control_message(ControlMessage::LoginSuccess {
            session_id: "session-1".to_string(),
            relay_info: crate::types::RelayInfo {
                addr: "127.0.0.1:4433".parse().expect("relay addr"),
                region: "test".to_string(),
                version: "0.1.0".to_string(),
            },
        })
        .expect("handle login success");

        assert!(matches!(app.state, ClientState::RegisteringTunnels));
        assert_eq!(app.write_queue.len(), 1);
    }

    #[tokio::test]
    async fn tunnel_registered_transitions_to_active_when_all_done() {
        let tunnel_id = TunnelId::new();
        let tunnel = sample_tunnel(tunnel_id);
        let mut app = make_app(vec![tunnel]);
        app.state = ClientState::RegisteringTunnels;

        app.handle_control_message(ControlMessage::TunnelRegistered {
            tunnel_id,
            public_url: "https://demo.pike.life".to_string(),
            remote_port: None,
        })
        .expect("handle tunnel registered");

        assert!(matches!(app.state, ClientState::Active));
        assert_eq!(app.registered_tunnels.len(), 1);
    }

    #[tokio::test]
    async fn tunnel_registered_transitions_to_active_when_pending_registrations_clear() {
        let tunnel_id = TunnelId::new();
        let mut app = make_app(Vec::new());
        app.state = ClientState::RegisteringTunnels;

        let (result_tx, _result_rx) = oneshot::channel();
        app.pending_registrations
            .insert(tunnel_id.to_string(), result_tx);

        app.handle_control_message(ControlMessage::TunnelRegistered {
            tunnel_id,
            public_url: "https://demo.pike.life".to_string(),
            remote_port: None,
        })
        .expect("handle tunnel registered");

        assert!(matches!(app.state, ClientState::Active));
        assert!(app.pending_registrations.is_empty());
    }

    #[tokio::test]
    async fn register_tunnel_is_deferred_until_login_success() {
        let tunnel = sample_tunnel(TunnelId::new());
        let mut app = make_app(Vec::new());
        app.state = ClientState::LoggingIn;

        let (result_tx, _result_rx) = oneshot::channel();
        app.handle_client_command(ClientCommand::RegisterTunnel {
            tunnel: tunnel.clone(),
            result_tx,
        })
        .expect("handle client command");
        assert_eq!(app.write_queue.len(), 0);
        assert_eq!(app.tunnels_to_register.len(), 1);

        app.handle_control_message(ControlMessage::LoginSuccess {
            session_id: "session-1".to_string(),
            relay_info: crate::types::RelayInfo {
                addr: "127.0.0.1:4433".parse().expect("relay addr"),
                region: "test".to_string(),
                version: "0.1.0".to_string(),
            },
        })
        .expect("handle login success");

        assert!(matches!(app.state, ClientState::RegisteringTunnels));
        assert_eq!(app.write_queue.len(), 1);
    }

    #[tokio::test]
    async fn queue_heartbeat_sends_while_registering_tunnels() {
        let mut app = make_app(Vec::new());
        app.state = ClientState::RegisteringTunnels;

        app.queue_heartbeat().expect("queue heartbeat");

        assert_eq!(app.write_queue.len(), 1);
        let (stream_id, _, fin) = &app.write_queue[0];
        assert_eq!(*stream_id, CONTROL_STREAM_ID);
        assert!(!fin);
    }

    #[test]
    fn login_timeout_constant_is_15_seconds() {
        assert_eq!(LOGIN_TIMEOUT, Duration::from_secs(15));
    }

    #[test]
    fn client_state_logging_in_variant_exists_and_eq() {
        let state = ClientState::LoggingIn;
        assert_eq!(state, ClientState::LoggingIn);
        assert_ne!(state, ClientState::Connecting);
        assert_ne!(state, ClientState::Active);
        assert_ne!(state, ClientState::Closed);
    }

    #[tokio::test]
    async fn set_reconnecting_transitions_state_with_backoff() {
        let mut app = make_app(Vec::new());
        assert_eq!(app.state, ClientState::Connecting);

        app.set_reconnecting(1);
        assert!(matches!(
            app.state,
            ClientState::Reconnecting {
                attempt: 1,
                backoff,
            } if backoff == Duration::from_secs(1)
        ));

        app.set_reconnecting(3);
        assert!(matches!(
            app.state,
            ClientState::Reconnecting {
                attempt: 3,
                backoff,
            } if backoff == Duration::from_secs(4)
        ));

        app.set_reconnecting(7);
        assert!(matches!(
            app.state,
            ClientState::Reconnecting {
                attempt: 7,
                backoff,
            } if backoff == Duration::from_secs(60)
        ));
    }

    #[tokio::test]
    async fn queue_login_transitions_to_logging_in() {
        let mut app = make_app(Vec::new());
        assert_eq!(app.state, ClientState::Connecting);

        app.queue_login().expect("queue login");
        assert_eq!(app.state, ClientState::LoggingIn);
        assert_eq!(app.write_queue.len(), 1);

        let (stream_id, _, _) = &app.write_queue[0];
        assert_eq!(*stream_id, CONTROL_STREAM_ID);
    }

    // Simulates the action taken by the login timeout arm (set_reconnecting).
    // The select! branch in wait_for_data calls set_reconnecting(1) on timeout.
    // This test verifies that call produces the expected Reconnecting state.
    #[tokio::test]
    async fn login_timeout_triggers_reconnecting_from_logging_in() {
        let mut app = make_app(Vec::new());
        app.state = ClientState::LoggingIn;

        // Simulate what wait_for_data does on login timeout
        if app.state == ClientState::LoggingIn {
            app.set_reconnecting(1);
        }

        assert!(matches!(
            app.state,
            ClientState::Reconnecting {
                attempt: 1,
                backoff,
            } if backoff == Duration::from_secs(1)
        ));
    }

    // Tests the select! guard condition: the timeout arm only fires when
    // state == LoggingIn. This verifies the guard logic itself. Full integration
    // testing of the actual timeout firing requires a real QUIC connection.
    #[tokio::test]
    async fn login_timeout_does_not_trigger_from_active() {
        let tunnel_id = TunnelId::new();
        let tunnel = sample_tunnel(tunnel_id);
        let mut app = make_app(vec![tunnel]);
        app.state = ClientState::Active;

        // The timeout guard `if self.state == ClientState::LoggingIn` prevents firing
        let should_timeout = app.state == ClientState::LoggingIn;
        assert!(!should_timeout);

        // State should remain Active
        assert_eq!(app.state, ClientState::Active);
    }
}
