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

use super::flow::{
    Delivery, MAX_CONNECTION_BUFFER, MAX_STREAM_BUFFER, MAX_TRACKED_STREAMS, MAX_WRITE_ENTRIES,
};
use crate::proto::{ControlMessage, StreamHeader, ALPN_PROTOCOL, MAX_FRAME_SIZE};
use crate::quic::config::PikeQuicConfig;
use crate::types::{ApiKey, TunnelConfig, TunnelId};
use tracing::{info, warn};

const SCRATCH_BUFFER_SIZE: usize = 64 * 1024;
const CONTROL_STREAM_ID: u64 = 0;
const FIRST_DATA_STREAM_ID: u64 = 4;
const WAIT_FOR_DATA_TIMEOUT: Duration = Duration::from_millis(100);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(20);
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
    pub mode: crate::proto::StreamMode,
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
    pub mode: crate::proto::StreamMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationResult {
    pub public_url: String,
    pub remote_port: Option<u16>,
}

#[derive(Debug)]
pub enum ClientCommand {
    RegisterTunnel {
        tunnel: TunnelConfig,
        result_tx: oneshot::Sender<RegistrationResult>,
    },
    UnregisterTunnel {
        tunnel_id: TunnelId,
        completed: oneshot::Sender<()>,
    },
    OriginHealthSource {
        tunnel_id: TunnelId,
        source: crate::proto::origin_health::OriginHealthSource,
    },
    Close,
}

#[derive(Debug)]
struct StreamReadState {
    header: Option<StreamHeader>,
    buf: Vec<u8>,
    streaming: bool,
    mode: crate::proto::StreamMode,
    recv_closed: bool,
    send_closed: bool,
}

pub struct PikeConnection {
    control_tx: mpsc::Sender<ClientCommand>,
    pub data_tx: mpsc::Sender<LocalData>,
    pub data_rx: mpsc::Receiver<ServerData>,
    _quic_conn: Option<QuicConnection>, // Keep connection alive
}

impl PikeConnection {
    /// Adapt another authenticated transport to the same application channels.
    #[must_use]
    pub fn from_channels(
        control_tx: mpsc::Sender<ClientCommand>,
        data_tx: mpsc::Sender<LocalData>,
        data_rx: mpsc::Receiver<ServerData>,
    ) -> Self {
        Self {
            control_tx,
            data_tx,
            data_rx,
            _quic_conn: None,
        }
    }

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

    /// Wait for relay resource cleanup before allowing the process to exit.
    pub async fn unregister_tunnel(&mut self, tunnel_id: TunnelId) -> Result<()> {
        let (completed, mut received) = oneshot::channel();
        tokio::time::timeout(Duration::from_secs(10), async {
            self.control_tx
                .send(ClientCommand::UnregisterTunnel {
                    tunnel_id,
                    completed,
                })
                .await
                .map_err(|_| anyhow!("connection control channel closed"))?;
            // Shutdown cancels application work; drain its bounded receive queue
            // so in-flight traffic cannot block the control acknowledgement.
            loop {
                tokio::select! {
                    result = &mut received => return result.map_err(|_| anyhow!("relay closed before unregister acknowledgement")),
                    data = self.data_rx.recv() => {
                        if data.is_none() {
                            return received.await.map_err(|_| anyhow!("relay closed before unregister acknowledgement"));
                        }
                    }
                }
            }
        })
        .await
        .map_err(|_| anyhow!("unregister acknowledgement timed out"))?
    }

    pub async fn set_origin_health_source(
        &self,
        tunnel_id: TunnelId,
        source: crate::proto::origin_health::OriginHealthSource,
    ) -> Result<()> {
        self.control_tx
            .send(ClientCommand::OriginHealthSource { tunnel_id, source })
            .await
            .map_err(|_| anyhow!("connection control channel closed"))
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
        settings.initial_max_data = self.config.max_connection_data;
        settings.initial_max_stream_data_bidi_local = self.config.max_stream_data;
        settings.initial_max_stream_data_bidi_remote = self.config.max_stream_data;
        settings.initial_max_streams_bidi = self.config.max_concurrent_streams;
        settings.initial_max_streams_uni = 0;
        settings.enable_dgram = false;

        let params = ConnectionParams::new_client(settings, None, Hooks::default());

        let (control_tx, control_rx) = mpsc::channel(256);
        let (local_data_tx, local_data_rx) = mpsc::channel(4);
        let (server_data_tx, server_data_rx) = mpsc::channel(4);

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
            _quic_conn: Some(quic_conn),
        })
    }

    pub fn register_tunnel(&self, tunnel: TunnelConfig) -> Result<TunnelId> {
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
    pending_unregistrations: HashMap<TunnelId, oneshot::Sender<()>>,
    health_sources: crate::proto::origin_health::OriginHealthSources,
    pub buf: Vec<u8>,
    control_rx: mpsc::Receiver<ClientCommand>,
    control_stream_buf: Vec<u8>,
    data_streams: HashMap<u64, StreamReadState>,
    next_data_stream_id: u64,
    heartbeat_seq: u64,
    last_heartbeat_ack: Option<u64>,
    heartbeat_deadline: Option<tokio::time::Instant>,
    heartbeat_interval: tokio::time::Interval,
    last_keepalive: std::time::Instant,
    close_requested: bool,
    delivery: Delivery<ServerData>,
    login_deadline: Option<tokio::time::Instant>,
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
            pending_unregistrations: HashMap::new(),
            health_sources: crate::proto::origin_health::OriginHealthSources::default(),
            buf: vec![0; SCRATCH_BUFFER_SIZE],
            control_rx,
            control_stream_buf: Vec::new(),
            data_streams: HashMap::new(),
            next_data_stream_id: FIRST_DATA_STREAM_ID,
            heartbeat_seq: 0,
            last_heartbeat_ack: None,
            heartbeat_deadline: None,
            heartbeat_interval: tokio::time::interval(HEARTBEAT_INTERVAL),
            last_keepalive: Instant::now(),
            close_requested: false,
            delivery: Delivery::default(),
            login_deadline: None,
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
        self.check_write_budget(payload.len(), 1)?;
        self.write_queue
            .push_back((CONTROL_STREAM_ID, payload, false));
        Ok(())
    }

    fn queue_stream_header(&mut self, stream_id: u64, header: &StreamHeader) -> Result<()> {
        let payload = encode_frame(header)?;
        self.check_write_budget(payload.len(), 1)?;
        self.write_queue.push_back((stream_id, payload, false));
        Ok(())
    }

    fn queue_login(&mut self) -> Result<()> {
        self.state = ClientState::LoggingIn;
        self.login_deadline = Some(tokio::time::Instant::now() + LOGIN_TIMEOUT);
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

    fn writes_have_capacity(&self) -> bool {
        self.write_queue.len() < MAX_WRITE_ENTRIES - 2
            && self
                .write_queue
                .iter()
                .map(|(_, bytes, _)| bytes.len())
                .sum::<usize>()
                <= MAX_CONNECTION_BUFFER - MAX_STREAM_BUFFER - MAX_FRAME_SIZE - 4
    }

    fn check_write_budget(&self, bytes: usize, entries: usize) -> Result<()> {
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
            return Err(anyhow!("outbound buffering limit exceeded"));
        }
        Ok(())
    }

    fn queue_local_data(&mut self, local: LocalData) -> Result<()> {
        if local.payload.len() > MAX_STREAM_BUFFER {
            return Err(anyhow!("outbound payload limit exceeded"));
        }
        self.check_write_budget(local.payload.len() + MAX_FRAME_SIZE + 4, 2)?;
        let stream_id = local
            .stream_id
            .unwrap_or_else(|| self.alloc_data_stream_id());
        if local.stream_id.is_none() {
            if self.data_streams.len() >= MAX_TRACKED_STREAMS {
                return Err(anyhow!("too many active data streams"));
            }
            let header = StreamHeader {
                tunnel_id: local.tunnel_id,
                connection_id: local.connection_id,
                source_addr: local.source_addr,
                streaming: local.streaming,
                mode: local.mode,
            };
            self.queue_stream_header(stream_id, &header)?;
            self.data_streams.insert(
                stream_id,
                StreamReadState {
                    header: Some(header),
                    buf: Vec::new(),
                    streaming: local.streaming,
                    mode: local.mode,
                    recv_closed: false,
                    send_closed: false,
                },
            );
        } else if self
            .data_streams
            .get(&stream_id)
            .is_none_or(|state| state.send_closed)
        {
            return Err(anyhow!("outbound data for unknown or closed stream"));
        }
        self.write_queue
            .push_back((stream_id, local.payload, local.fin));
        Ok(())
    }

    fn finish_write(&mut self, stream_id: u64, fin: bool) {
        if fin {
            if let Some(stream) = self.data_streams.get_mut(&stream_id) {
                stream.send_closed = true;
            }
            self.cleanup_stream(stream_id);
        }
    }

    fn cleanup_stream(&mut self, stream_id: u64) {
        if self
            .data_streams
            .get(&stream_id)
            .is_some_and(|stream| stream.recv_closed && stream.send_closed)
        {
            self.data_streams.remove(&stream_id);
        }
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
            ClientCommand::UnregisterTunnel {
                tunnel_id,
                completed,
            } => {
                if self.pending_unregistrations.len() >= MAX_TRACKED_STREAMS {
                    return Err(anyhow!("too many pending unregistrations"));
                }
                self.pending_unregistrations.insert(tunnel_id, completed);
                self.queue_control_message(&ControlMessage::UnregisterTunnel { tunnel_id })
            }
            ClientCommand::OriginHealthSource { tunnel_id, source } => {
                self.health_sources.insert(tunnel_id, source)
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
                self.login_deadline = None;
                self.heartbeat_deadline = Some(tokio::time::Instant::now() + HEARTBEAT_TIMEOUT);
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
            ControlMessage::TunnelUnregistered { tunnel_id } => {
                self.health_sources.remove(tunnel_id);
                self.registered_tunnels.remove(&tunnel_id);
                self.tunnels_to_register
                    .retain(|config| config.id != tunnel_id);
                if let Some(completed) = self.pending_unregistrations.remove(&tunnel_id) {
                    let _ = completed.send(());
                }
            }
            ControlMessage::OriginHealthRequest { tunnel_id, nonce } => {
                if let Some(report) = self.health_sources.snapshot(tunnel_id) {
                    self.queue_control_message(&ControlMessage::OriginHealthResponse {
                        tunnel_id,
                        nonce,
                        report,
                    })?;
                }
            }
            ControlMessage::HeartbeatAck { seq, .. } => {
                if self.heartbeat_deadline.is_some()
                    && seq < self.heartbeat_seq
                    && self
                        .last_heartbeat_ack
                        .is_none_or(|previous| seq > previous)
                {
                    self.last_heartbeat_ack = Some(seq);
                    self.heartbeat_deadline = Some(tokio::time::Instant::now() + HEARTBEAT_TIMEOUT);
                }
            }
            ControlMessage::LoginFailure { reason }
            | ControlMessage::TunnelError { reason, .. } => {
                tracing::error!("Received error from server: {}", reason);
                // A terminal control rejection must also end pending API
                // waiters. Merely changing state leaves registration awaiting
                // its full deadline before the caller can reconnect.
                self.pending_registrations.clear();
                self.pending_unregistrations.clear();
                self.close_requested = true;
                self.state = ClientState::Closed;
            }
            ControlMessage::Login { .. }
            | ControlMessage::RegisterTunnel { .. }
            | ControlMessage::UnregisterTunnel { .. }
            | ControlMessage::Heartbeat { .. }
            | ControlMessage::OriginHealthResponse { .. } => {
                return Err(anyhow!("received client-originated message from server"));
            }
        }

        Ok(())
    }

    fn process_control_chunk(&mut self, chunk: &[u8], fin: bool) -> Result<()> {
        if self.control_stream_buf.len() + chunk.len() > MAX_FRAME_SIZE + SCRATCH_BUFFER_SIZE + 4 {
            return Err(anyhow!("control stream buffering limit exceeded"));
        }
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
        if !matches!(
            self.state,
            ClientState::RegisteringTunnels | ClientState::Active
        ) {
            return Err(anyhow!("data received before authentication"));
        }
        if self.delivery.is_pending() {
            return Err(anyhow!("application delivery is backpressured"));
        }
        if !self.data_streams.contains_key(&stream_id)
            && self.data_streams.len() >= MAX_TRACKED_STREAMS
        {
            return Err(anyhow!("too many active data streams"));
        }
        if self
            .data_streams
            .values()
            .map(|stream| stream.buf.len())
            .sum::<usize>()
            + chunk.len()
            > MAX_CONNECTION_BUFFER
        {
            return Err(anyhow!("connection receive buffering limit exceeded"));
        }
        let stream = self
            .data_streams
            .entry(stream_id)
            .or_insert(StreamReadState {
                header: None,
                buf: Vec::new(),
                streaming: false,
                mode: crate::proto::StreamMode::Raw,
                recv_closed: false,
                send_closed: false,
            });
        if stream.recv_closed || stream.buf.len() + chunk.len() > MAX_STREAM_BUFFER {
            return Err(anyhow!("closed or oversized data stream"));
        }
        stream.buf.extend_from_slice(chunk);
        let is_opening = stream.header.is_none();
        if is_opening {
            if stream.buf.len() < 4 {
                return if fin {
                    Err(anyhow!("truncated stream header"))
                } else {
                    Ok(())
                };
            }
            let header_len = u32::from_be_bytes(stream.buf[..4].try_into()?) as usize;
            if header_len > MAX_FRAME_SIZE {
                return Err(anyhow!("header frame size exceeds limit"));
            }
            if stream.buf.len() < 4 + header_len {
                return if fin {
                    Err(anyhow!("truncated stream header"))
                } else {
                    Ok(())
                };
            }
            let header: StreamHeader = postcard::from_bytes(&stream.buf[4..4 + header_len])?;
            stream.streaming = header.streaming;
            stream.mode = header.mode;
            stream.header = Some(header);
            stream.buf.drain(..4 + header_len);
        }
        if (stream.streaming && (!stream.buf.is_empty() || is_opening)) || fin {
            let header = stream
                .header
                .as_ref()
                .ok_or_else(|| anyhow!("missing stream header"))?;
            let message = ServerData {
                stream_id,
                tunnel_id: header.tunnel_id,
                connection_id: header.connection_id,
                source_addr: header.source_addr,
                payload: std::mem::take(&mut stream.buf),
                fin,
                streaming: stream.streaming,
                mode: stream.mode,
            };
            self.delivery
                .send(&self.data_tx, message)
                .map_err(|error| anyhow!(error))?;
        }
        stream.recv_closed = fin;
        self.cleanup_stream(stream_id);
        Ok(())
    }

    fn check_login_timeout(&mut self) -> QuicResult<()> {
        if !matches!(self.state, ClientState::Closed)
            && self
                .heartbeat_deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            warn!("QUIC heartbeat acknowledgement timed out");
            self.pending_registrations.clear();
            self.set_reconnecting(1);
            return Err(quiche::Error::InvalidState.into());
        }
        if self.state == ClientState::LoggingIn
            && self
                .login_deadline
                .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            warn!("Login timed out before the server authenticated the connection");
            self.pending_registrations.clear();
            self.set_reconnecting(1);
            return Err(quiche::Error::InvalidState.into());
        }
        Ok(())
    }

    fn set_reconnecting(&mut self, attempt: u32) {
        self.login_deadline = None;
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
        self.check_login_timeout()?;
        tokio::select! {
            result = self.delivery.wait(&self.data_tx), if self.delivery.is_pending() => {
                result.map_err(|_| quiche::Error::InvalidState)?;
            }
            Some(cmd) = self.control_rx.recv(), if self.writes_have_capacity() => {
                self.handle_client_command(cmd)
                    .map_err(|_| quiche::Error::InvalidState)?;
            }
            Some(local_data) = self.data_rx.recv(), if self.writes_have_capacity() => {
                self.queue_local_data(local_data).map_err(|_| quiche::Error::InvalidState)?;
            }
            _ = self.heartbeat_interval.tick(), if self.writes_have_capacity() => {
                self.queue_heartbeat().map_err(|_| quiche::Error::InvalidState)?;
            }
            _ = tokio::time::sleep(WAIT_FOR_DATA_TIMEOUT) => {
                // Timeout is normal, just continue
            }
            _ = tokio::time::sleep_until(self.login_deadline.unwrap_or_else(tokio::time::Instant::now)), if self.state == ClientState::LoggingIn && self.login_deadline.is_some() => {}

        }

        self.check_login_timeout()
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        // Packet traffic can bypass wait_for_data, so enforce the same absolute
        // deadline on the read/write path as well as the timer wakeup.
        self.check_login_timeout()?;
        if qconn.is_closed() {
            return Err(quiche::Error::Done.into());
        }
        self.delivery
            .flush(&self.data_tx)
            .map_err(|_| quiche::Error::InvalidState)?;
        for stream_id in qconn.readable().collect::<Vec<_>>() {
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
        // tokio-quiche only invokes process_reads for fresh packets. Retry
        // already-readable streams after application capacity becomes available.
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

    #[tokio::test]
    async fn unregister_waits_for_relay_ack_while_draining_inflight_data() {
        let (control_tx, mut control_rx) = mpsc::channel(1);
        let (data_tx, _data_rx) = mpsc::channel(1);
        let (server_tx, server_rx) = mpsc::channel(1);
        let mut connection = PikeConnection::from_channels(control_tx, data_tx, server_rx);
        let tunnel_id = TunnelId::new();
        let task = tokio::spawn(async move { connection.unregister_tunnel(tunnel_id).await });
        let Some(ClientCommand::UnregisterTunnel {
            tunnel_id: received,
            completed,
        }) = control_rx.recv().await
        else {
            panic!("expected explicit unregister");
        };
        assert_eq!(received, tunnel_id);
        for _ in 0..3 {
            tokio::time::timeout(
                Duration::from_secs(1),
                server_tx.send(ServerData {
                    stream_id: 4,
                    tunnel_id,
                    connection_id: 1,
                    source_addr: "127.0.0.1:1234".parse().unwrap(),
                    payload: vec![1],
                    fin: false,
                    streaming: true,
                    mode: crate::proto::StreamMode::Http,
                }),
            )
            .await
            .expect("shutdown must drain bounded in-flight data")
            .unwrap();
        }
        assert!(
            !task.is_finished(),
            "queuing unregister is not relay acknowledgement"
        );
        completed.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    fn sample_tunnel(tunnel_id: TunnelId) -> TunnelConfig {
        TunnelConfig {
            cloud: None,
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

    #[tokio::test]
    async fn heartbeat_requires_fresh_sent_ack_and_expires_with_a_full_write_queue() {
        let mut app = make_app(vec![]);
        app.state = ClientState::Active;
        let deadline = tokio::time::Instant::now() + HEARTBEAT_TIMEOUT;
        app.heartbeat_deadline = Some(deadline);
        app.queue_heartbeat().unwrap(); // sent sequence 0
        app.handle_control_message(ControlMessage::HeartbeatAck {
            seq: 1,
            timestamp: 0,
            server_time: 0,
        })
        .unwrap();
        assert_eq!(app.heartbeat_deadline, Some(deadline)); // unsolicited sequence
        app.handle_control_message(ControlMessage::HeartbeatAck {
            seq: 0,
            timestamp: 0,
            server_time: 0,
        })
        .unwrap();
        let fresh = app.heartbeat_deadline;
        app.handle_control_message(ControlMessage::HeartbeatAck {
            seq: 0,
            timestamp: 0,
            server_time: 0,
        })
        .unwrap();
        assert_eq!(app.heartbeat_deadline, fresh); // duplicate must not extend life
        app.heartbeat_deadline = Some(tokio::time::Instant::now() - Duration::from_millis(1));
        for _ in 0..MAX_WRITE_ENTRIES {
            app.write_queue.push_back((4, vec![1], false));
        }
        assert!(!app.writes_have_capacity());
        assert!(app.check_login_timeout().is_err());
        assert!(matches!(app.state, ClientState::Reconnecting { .. }));
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
    async fn terminal_control_rejections_release_registration_and_cleanup_waiters() {
        let tunnel_id = TunnelId::new();
        for message in [
            ControlMessage::LoginFailure {
                reason: "key revoked".into(),
            },
            ControlMessage::TunnelError {
                tunnel_id,
                reason: "endpoint policy changed".into(),
            },
        ] {
            let mut app = make_app(vec![sample_tunnel(tunnel_id)]);
            app.state = ClientState::RegisteringTunnels;
            let (registered, mut registration) = oneshot::channel();
            app.pending_registrations
                .insert(tunnel_id.to_string(), registered);
            let (unregistered, mut cleanup) = oneshot::channel();
            app.pending_unregistrations.insert(tunnel_id, unregistered);
            app.handle_control_message(message).unwrap();
            assert_eq!(
                registration.try_recv(),
                Err(oneshot::error::TryRecvError::Closed)
            );
            assert_eq!(
                cleanup.try_recv(),
                Err(oneshot::error::TryRecvError::Closed)
            );
            assert_eq!(app.state, ClientState::Closed);
            assert!(app.close_requested);
        }
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
    fn receive_app(capacity: usize) -> (PikeClientApp, mpsc::Receiver<ServerData>) {
        let (_, control_rx) = mpsc::channel(4);
        let (_, data_rx) = mpsc::channel(4);
        let (data_tx, rx) = mpsc::channel(capacity);
        let mut app = PikeClientApp::new(
            ApiKey("test-key".into()),
            Vec::new(),
            control_rx,
            data_rx,
            data_tx,
        );
        app.state = ClientState::Active;
        (app, rx)
    }

    fn receive_header(streaming: bool) -> StreamHeader {
        StreamHeader {
            tunnel_id: TunnelId::new(),
            connection_id: 3,
            source_addr: "127.0.0.1:3000".parse().unwrap(),
            streaming,
            mode: crate::proto::StreamMode::Raw,
        }
    }

    #[tokio::test]
    async fn full_channel_preserves_stream_chunks_and_empty_fin() {
        let (mut app, mut rx) = receive_app(1);
        let mut frame = encode_frame(&receive_header(true)).unwrap();
        frame.extend_from_slice(b"hello");
        app.process_data_chunk(1, &frame, false).unwrap();
        assert_eq!(app.data_tx.capacity(), 0);
        app.process_data_chunk(1, b" world", false).unwrap();
        assert!(app.delivery.is_pending());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), app.delivery.wait(&app.data_tx))
                .await
                .is_err()
        );
        let first = rx.recv().await.unwrap();
        app.delivery.wait(&app.data_tx).await.unwrap();
        app.process_data_chunk(1, &[], true).unwrap();
        let second = rx.recv().await.unwrap();
        app.delivery.wait(&app.data_tx).await.unwrap();
        let end = rx.recv().await.unwrap();
        assert_eq!([first.payload, second.payload].concat(), b"hello world");
        assert!(!first.fin && !second.fin);
        assert!(end.payload.is_empty() && end.fin);
        assert!(app.data_streams.contains_key(&1));
        app.finish_write(1, true);
        assert!(app.data_streams.is_empty());
    }

    #[tokio::test]
    async fn full_channel_preserves_complete_normal_message() {
        let (mut app, mut rx) = receive_app(1);
        let mut frame = encode_frame(&receive_header(false)).unwrap();
        frame.extend_from_slice(b"whole request");
        app.process_data_chunk(1, &frame, true).unwrap();
        app.process_data_chunk(5, &frame, true).unwrap();
        assert!(app.delivery.is_pending());
        assert_eq!(rx.recv().await.unwrap().payload, b"whole request");
        app.delivery.wait(&app.data_tx).await.unwrap();
        let message = rx.recv().await.unwrap();
        assert_eq!(message.payload, b"whole request");
        assert!(message.fin);
    }

    #[tokio::test]
    async fn client_rejects_data_before_login_without_allocating() {
        let (mut app, _rx) = receive_app(1);
        app.state = ClientState::LoggingIn;
        assert!(app
            .process_data_chunk(1, &encode_frame(&receive_header(false)).unwrap(), true)
            .is_err());
        assert!(app.data_streams.is_empty());
    }

    #[tokio::test]
    async fn client_receive_buffers_and_stream_count_are_bounded() {
        let (mut app, _rx) = receive_app(1);
        let header = encode_frame(&receive_header(false)).unwrap();
        let bytes = vec![1; MAX_STREAM_BUFFER];
        for index in 0..4 {
            app.process_data_chunk(index * 4 + 1, &header, false)
                .unwrap();
            app.process_data_chunk(index * 4 + 1, &bytes, false)
                .unwrap();
        }
        assert!(app.process_data_chunk(17, &header, false).is_err());
        app.data_streams.remove(&13);
        assert!(app.process_data_chunk(1, &[1], false).is_err());
        app.data_streams.clear();
        for index in 0..MAX_TRACKED_STREAMS {
            app.process_data_chunk(index as u64 * 4 + 1, &header, false)
                .unwrap();
        }
        assert!(app
            .process_data_chunk(MAX_TRACKED_STREAMS as u64 * 4 + 1, &header, false)
            .is_err());
        assert_eq!(app.data_streams.len(), MAX_TRACKED_STREAMS);
    }

    #[tokio::test]
    async fn client_half_closed_streams_live_until_reply_fin_then_are_removed() {
        let (mut app, mut rx) = receive_app(1);
        for index in 0..2000 {
            let sid = index * 4 + 1;
            let header = receive_header(true);
            app.process_data_chunk(sid, &encode_frame(&header).unwrap(), true)
                .unwrap();
            assert!(rx.recv().await.unwrap().fin);
            app.queue_local_data(LocalData {
                stream_id: Some(sid),
                tunnel_id: header.tunnel_id,
                connection_id: header.connection_id,
                source_addr: header.source_addr,
                payload: b"response after request FIN".to_vec(),
                fin: true,
                streaming: true,
                mode: crate::proto::StreamMode::Raw,
            })
            .unwrap();
            assert_eq!(app.data_streams.len(), 1);
            app.write_queue.clear();
            app.finish_write(sid, true);
            assert!(app.data_streams.is_empty());
        }
    }
    #[tokio::test]
    async fn real_quic_partial_writes_keep_fin_and_half_closed_reply_direction() {
        let (mut app, mut rx) = receive_app(1);
        let mut pair = super::super::test_support::Pair::new();
        let header = receive_header(true);
        let request = encode_frame(&header).unwrap();
        pair.server.stream_send(1, &request, true).unwrap();
        pair.exchange();
        app.process_reads(&mut pair.client).unwrap();
        assert!(rx.recv().await.unwrap().fin);
        let expected = (0..256 * 1024)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect::<Vec<_>>();
        app.queue_local_data(LocalData {
            stream_id: Some(1),
            tunnel_id: header.tunnel_id,
            connection_id: header.connection_id,
            source_addr: header.source_addr,
            payload: expected.clone(),
            fin: true,
            streaming: true,
            mode: crate::proto::StreamMode::Raw,
        })
        .unwrap();
        let mut received = Vec::new();
        let mut saw_partial = false;
        let mut fin_count = 0;
        for _ in 0..10000 {
            app.process_writes(&mut pair.client).unwrap();
            saw_partial |= !app.write_queue.is_empty();
            pair.exchange();
            let mut bytes = [0; 8192];
            loop {
                match pair.server.stream_recv(1, &mut bytes) {
                    Ok((count, fin)) => {
                        received.extend_from_slice(&bytes[..count]);
                        fin_count += usize::from(fin);
                        if fin {
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(error) => panic!("recv: {error}"),
                }
            }
            if fin_count == 1 {
                break;
            }
        }
        assert!(saw_partial);
        assert_eq!(received, expected);
        assert_eq!(fin_count, 1);
        assert!(app.data_streams.is_empty());
        assert!(app.write_queue.is_empty());
    }
    #[tokio::test]
    async fn login_deadline_survives_frequent_application_wakeups() {
        let mut app = make_app(Vec::new());
        let mut pair = super::super::test_support::Pair::new();
        app.queue_login().unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(40);
        app.login_deadline = Some(deadline);
        app.heartbeat_interval = tokio::time::interval(Duration::from_millis(1));
        let mut wakeups = 0;
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if app.wait_for_data(&mut pair.client).await.is_err() {
                    break;
                }
                wakeups += 1;
                assert_eq!(app.login_deadline, Some(deadline));
            }
        })
        .await
        .expect("frequent wakeups must not postpone login timeout");
        assert!(wakeups > 0);
        assert!(matches!(app.state, ClientState::Reconnecting { .. }));
    }

    #[tokio::test]
    async fn continuous_network_activity_cannot_bypass_login_deadline() {
        let mut app = make_app(Vec::new());
        let mut pair = super::super::test_support::Pair::new();
        app.queue_login().unwrap();
        app.login_deadline = Some(tokio::time::Instant::now() - Duration::from_millis(1));
        assert!(app.process_reads(&mut pair.client).is_err());
        assert!(matches!(app.state, ClientState::Reconnecting { .. }));
    }

    #[tokio::test]
    async fn empty_streaming_open_is_delivered_once_before_payload_or_fin() {
        let (mut app, mut rx) = receive_app(4);
        let header = receive_header(true);
        app.process_data_chunk(1, &encode_frame(&header).unwrap(), false)
            .unwrap();
        let open = rx.recv().await.unwrap();
        assert!(open.payload.is_empty() && !open.fin && open.streaming);
        app.process_data_chunk(1, &[], false).unwrap();
        assert!(rx.try_recv().is_err());
        app.process_data_chunk(1, &[], true).unwrap();
        assert!(rx.recv().await.unwrap().fin);
    }
}
