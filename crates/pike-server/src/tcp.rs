use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use pike_core::proto::StreamHeader;
use pike_core::quic::stream_manager::StreamManager;
use pike_core::types::TunnelId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::time::sleep;

const PORT_MIN: u16 = 10_000;
const PORT_MAX: u16 = 65_000;
const COPY_BUFFER_SIZE: usize = 16 * 1024;
const BACKPRESSURE_WAIT: Duration = Duration::from_millis(10);
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, thiserror::Error)]
pub enum TcpError {
    #[error("no available TCP port in pool")]
    PortExhausted,
    #[error("failed to bind TCP listener on {0}: {1}")]
    Bind(SocketAddr, std::io::Error),
    #[error("listener not found for tunnel {0}")]
    ListenerNotFound(TunnelId),
    #[error("tunnel over bandwidth quota, suspended, or rate-limited")]
    QuotaExceeded,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("QUIC error: {0}")]
    Quic(#[from] quiche::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),
}

#[derive(Debug)]
pub struct TcpTunnelManager {
    listeners: DashMap<TunnelId, TcpListenerHandle>,
    dispatchers: DashMap<TunnelId, mpsc::Sender<TcpStream>>,
    port_pool: Arc<Mutex<PortPool>>,
    stream_manager: Arc<StreamManager>,
}

#[derive(Debug, Clone)]
pub struct TcpListenerHandle {
    pub tunnel_id: TunnelId,
    pub local_addr: SocketAddr,
    shutdown_tx: mpsc::Sender<()>,
}

impl TcpTunnelManager {
    #[must_use]
    pub fn new(stream_manager: Arc<StreamManager>) -> Self {
        Self {
            listeners: DashMap::new(),
            dispatchers: DashMap::new(),
            port_pool: Arc::new(Mutex::new(PortPool::new())),
            stream_manager,
        }
    }

    pub async fn create_listener(
        &self,
        tunnel_id: TunnelId,
        preferred_port: Option<u16>,
    ) -> Result<TcpListenerHandle, TcpError> {
        self.create_listener_inner(tunnel_id, preferred_port, None)
            .await
    }

    pub async fn create_listener_with_dispatcher(
        &self,
        tunnel_id: TunnelId,
        preferred_port: Option<u16>,
        dispatcher: mpsc::Sender<TcpStream>,
    ) -> Result<TcpListenerHandle, TcpError> {
        self.dispatchers.insert(tunnel_id, dispatcher);
        self.create_listener_inner(tunnel_id, preferred_port, Some(tunnel_id))
            .await
    }

    pub async fn close_listener(&self, tunnel_id: TunnelId) {
        if let Some((_, handle)) = self.listeners.remove(&tunnel_id) {
            let _ = handle.shutdown_tx.send(()).await;
            let mut pool = self.port_pool.lock().await;
            pool.release(handle.local_addr.port());
        }

        self.dispatchers.remove(&tunnel_id);
    }

    #[must_use]
    pub fn active_listeners(&self) -> Vec<(TunnelId, SocketAddr)> {
        self.listeners
            .iter()
            .map(|entry| (*entry.key(), entry.local_addr))
            .collect()
    }

    #[must_use]
    pub fn stream_manager(&self) -> Arc<StreamManager> {
        Arc::clone(&self.stream_manager)
    }

    async fn create_listener_inner(
        &self,
        tunnel_id: TunnelId,
        preferred_port: Option<u16>,
        dispatcher_tunnel: Option<TunnelId>,
    ) -> Result<TcpListenerHandle, TcpError> {
        if self.listeners.contains_key(&tunnel_id) {
            self.close_listener(tunnel_id).await;
        }

        let listener = self.bind_listener(preferred_port).await?;
        let local_addr = listener.local_addr()?;
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        let dispatchers = self.dispatchers.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    maybe_shutdown = shutdown_rx.recv() => {
                        if maybe_shutdown.is_some() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _peer)) => {
                                if let Some(dispatch_tunnel_id) = dispatcher_tunnel {
                                    if let Some(dispatcher) = dispatchers.get(&dispatch_tunnel_id) {
                                        if dispatcher.send(stream).await.is_err() {
                                            tracing::warn!(tunnel_id = %dispatch_tunnel_id, "TCP dispatcher dropped");
                                        }
                                    }
                                }
                            }
                            Err(error) => {
                                tracing::warn!(tunnel_id = %tunnel_id, error = %error, "TCP accept failed");
                                break;
                            }
                        }
                    }
                }
            }
        });

        let handle = TcpListenerHandle {
            tunnel_id,
            local_addr,
            shutdown_tx,
        };
        self.listeners.insert(tunnel_id, handle.clone());
        Ok(handle)
    }

    async fn bind_listener(&self, preferred_port: Option<u16>) -> Result<TcpListener, TcpError> {
        let mut pool = self.port_pool.lock().await;

        if let Some(port) = preferred_port {
            if let Some(allocated) = pool.allocate(Some(port)) {
                let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), allocated);
                match TcpListener::bind(addr).await {
                    Ok(listener) => return Ok(listener),
                    Err(error) => {
                        pool.release(allocated);
                        return Err(TcpError::Bind(addr, error));
                    }
                }
            }
        }

        for _ in 0..64 {
            let Some(port) = pool.allocate(None) else {
                break;
            };

            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
            match TcpListener::bind(addr).await {
                Ok(listener) => return Ok(listener),
                Err(_) => pool.release(port),
            }
        }

        Err(TcpError::PortExhausted)
    }
}

#[derive(Debug)]
pub struct PortPool {
    available: Vec<u16>,
    in_use: HashSet<u16>,
}

impl Default for PortPool {
    fn default() -> Self {
        Self::new()
    }
}

impl PortPool {
    #[must_use]
    pub fn new() -> Self {
        Self {
            available: (PORT_MIN..=PORT_MAX).collect(),
            in_use: HashSet::new(),
        }
    }

    pub fn allocate(&mut self, preferred: Option<u16>) -> Option<u16> {
        if let Some(port) = preferred {
            if !(PORT_MIN..=PORT_MAX).contains(&port) || self.in_use.contains(&port) {
                return None;
            }
            if let Some(idx) = self
                .available
                .iter()
                .position(|candidate| *candidate == port)
            {
                self.available.swap_remove(idx);
                self.in_use.insert(port);
                return Some(port);
            }
            return None;
        }

        if self.available.is_empty() {
            return None;
        }

        let idx = pseudo_random_index(self.available.len());
        let port = self.available.swap_remove(idx);
        self.in_use.insert(port);
        Some(port)
    }

    pub fn release(&mut self, port: u16) {
        if self.in_use.remove(&port) {
            self.available.push(port);
        }
    }

    #[cfg(test)]
    fn from_ports(ports: Vec<u16>) -> Self {
        Self {
            available: ports,
            in_use: HashSet::new(),
        }
    }
}

pub trait QuicConnectionIo {
    fn stream_capacity(&mut self, stream_id: u64) -> Result<usize, quiche::Error>;
    fn stream_send(
        &mut self,
        stream_id: u64,
        buf: &[u8],
        fin: bool,
    ) -> Result<usize, quiche::Error>;
    fn stream_recv(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), quiche::Error>;
    fn stream_shutdown(
        &mut self,
        stream_id: u64,
        direction: quiche::Shutdown,
        error_code: u64,
    ) -> Result<(), quiche::Error>;
}

impl QuicConnectionIo for quiche::Connection {
    fn stream_capacity(&mut self, stream_id: u64) -> Result<usize, quiche::Error> {
        quiche::Connection::stream_capacity(self, stream_id)
    }

    fn stream_send(
        &mut self,
        stream_id: u64,
        buf: &[u8],
        fin: bool,
    ) -> Result<usize, quiche::Error> {
        quiche::Connection::stream_send(self, stream_id, buf, fin)
    }

    fn stream_recv(
        &mut self,
        stream_id: u64,
        buf: &mut [u8],
    ) -> Result<(usize, bool), quiche::Error> {
        quiche::Connection::stream_recv(self, stream_id, buf)
    }

    fn stream_shutdown(
        &mut self,
        stream_id: u64,
        direction: quiche::Shutdown,
        error_code: u64,
    ) -> Result<(), quiche::Error> {
        quiche::Connection::stream_shutdown(self, stream_id, direction, error_code)
    }
}

/// Bandwidth accounting + quota gate for TCP tunnels (fix #1).
///
/// TCP tunnels previously moved bytes with no accounting or quota enforcement — only
/// the HTTP path metered traffic. The proxy loop now feeds every byte moved in both
/// directions into a meter, and consults `allow()` so an over-quota / suspended /
/// rate-limited tunnel is torn down.
pub trait TcpBandwidthMeter: Send + Sync {
    /// Returns `true` if the tunnel may (continue to) run. Called once before the
    /// proxy loop starts and again each loop iteration so a user going over quota
    /// mid-stream is cut off. Implementations should keep this cheap.
    fn allow(&self) -> bool;
    /// Record bytes moved from the client toward the upstream (inbound).
    fn record_in(&self, bytes: u64);
    /// Record bytes moved from the upstream toward the client (outbound).
    fn record_out(&self, bytes: u64);
}

/// A meter that performs no accounting and always allows traffic. Used in tests and
/// as a safe default where metering is not wired.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopBandwidthMeter;

impl TcpBandwidthMeter for NoopBandwidthMeter {
    fn allow(&self) -> bool {
        true
    }
    fn record_in(&self, _bytes: u64) {}
    fn record_out(&self, _bytes: u64) {}
}

/// Meter backed by the live `ClientRegistry`: it counts bytes into the same monthly
/// bandwidth accounting the HTTP path uses (`rate_limit.rs`) and refuses the tunnel
/// when the user is over their quota, suspended, or rate-limited (fix #1).
pub struct RegistryTcpMeter {
    registry: Arc<crate::registry::ClientRegistry>,
    tunnel_id: TunnelId,
    user_id: String,
}

impl RegistryTcpMeter {
    #[must_use]
    pub fn new(
        registry: Arc<crate::registry::ClientRegistry>,
        tunnel_id: TunnelId,
        user_id: String,
    ) -> Self {
        Self {
            registry,
            tunnel_id,
            user_id,
        }
    }
}

impl TcpBandwidthMeter for RegistryTcpMeter {
    fn allow(&self) -> bool {
        if self.registry.abuse_detector.is_suspended(&self.tunnel_id) {
            return false;
        }
        // check_limit enforces both the per-user request governor and the monthly
        // bandwidth quota (BandwidthLimitExceeded).
        if self
            .registry
            .rate_limiter
            .check_limit(self.user_id.clone())
            .is_err()
        {
            return false;
        }
        self.registry
            .rate_limiter
            .check_tunnel_limit(self.tunnel_id)
            .is_ok()
    }

    fn record_in(&self, bytes: u64) {
        self.registry.track_bandwidth(self.tunnel_id, bytes);
    }

    fn record_out(&self, bytes: u64) {
        self.registry.track_bandwidth_out(self.tunnel_id, bytes);
    }
}

pub async fn handle_tcp_connection<Q: QuicConnectionIo>(
    tcp_stream: TcpStream,
    tunnel_id: TunnelId,
    quic_conn: &mut Q,
    stream_manager: &StreamManager,
    meter: &dyn TcpBandwidthMeter,
) -> Result<u64, TcpError> {
    // Refuse up front if the user is over quota / suspended / rate-limited (fix #1).
    if !meter.allow() {
        return Err(TcpError::QuotaExceeded);
    }

    let stream_id = stream_manager.next_stream_id();
    stream_manager.register_stream(stream_id, tunnel_id);

    let source_addr = tcp_stream
        .peer_addr()
        .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let header = StreamHeader {
        tunnel_id,
        connection_id: NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed),
        source_addr,
        streaming: false,
    };
    let header_frame = framed_postcard(&header)?;
    send_with_backpressure(quic_conn, stream_id, &header_frame, false).await?;

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();
    copy_with_backpressure(&mut tcp_read, &mut tcp_write, quic_conn, stream_id, meter).await?;
    stream_manager.close_stream(stream_id);

    Ok(stream_id)
}

pub async fn copy_with_backpressure<Q: QuicConnectionIo>(
    tcp_read: &mut tokio::net::tcp::OwnedReadHalf,
    tcp_write: &mut tokio::net::tcp::OwnedWriteHalf,
    quic_conn: &mut Q,
    stream_id: u64,
    meter: &dyn TcpBandwidthMeter,
) -> Result<(), TcpError> {
    let mut tcp_buf = vec![0_u8; COPY_BUFFER_SIZE];
    let mut quic_buf = vec![0_u8; COPY_BUFFER_SIZE];
    let mut tcp_read_closed = false;
    let mut quic_read_closed = false;

    loop {
        // Enforce quota/suspension mid-stream (fix #1): if the user has gone over
        // their monthly cap or been suspended, tear the tunnel down.
        if !meter.allow() {
            let _ = quic_conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0);
            let _ = tcp_write.shutdown().await;
            return Err(TcpError::QuotaExceeded);
        }

        let mut progressed = false;

        loop {
            match quic_conn.stream_recv(stream_id, &mut quic_buf) {
                Ok((n, fin)) => {
                    progressed = true;
                    if n > 0 {
                        // upstream -> client (outbound)
                        meter.record_out(n as u64);
                        tcp_write.write_all(&quic_buf[..n]).await?;
                    }
                    if fin {
                        quic_read_closed = true;
                        tcp_write.shutdown().await?;
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(error) => return Err(TcpError::Quic(error)),
            }
        }

        if !tcp_read_closed {
            let capacity = quic_conn.stream_capacity(stream_id).unwrap_or(0);
            if capacity == 0 {
                sleep(BACKPRESSURE_WAIT).await;
            } else {
                let max_read = capacity.min(tcp_buf.len());
                match tokio::time::timeout(
                    BACKPRESSURE_WAIT,
                    tcp_read.read(&mut tcp_buf[..max_read]),
                )
                .await
                {
                    Ok(Ok(0)) => {
                        tcp_read_closed = true;
                        quic_conn.stream_shutdown(stream_id, quiche::Shutdown::Write, 0)?;
                        progressed = true;
                    }
                    Ok(Ok(n)) => {
                        progressed = true;
                        // client -> upstream (inbound)
                        meter.record_in(n as u64);
                        send_with_backpressure(quic_conn, stream_id, &tcp_buf[..n], false).await?;
                    }
                    Ok(Err(error)) => return Err(TcpError::Io(error)),
                    Err(_) => {}
                }
            }
        }

        if tcp_read_closed && quic_read_closed {
            break;
        }

        if !progressed {
            sleep(BACKPRESSURE_WAIT).await;
        }
    }

    Ok(())
}

async fn send_with_backpressure<Q: QuicConnectionIo>(
    quic_conn: &mut Q,
    stream_id: u64,
    bytes: &[u8],
    fin: bool,
) -> Result<(), TcpError> {
    let mut offset = 0;

    while offset < bytes.len() {
        match quic_conn.stream_send(stream_id, &bytes[offset..], false) {
            Ok(written) => {
                offset += written;
            }
            Err(quiche::Error::Done) => sleep(BACKPRESSURE_WAIT).await,
            Err(error) => return Err(TcpError::Quic(error)),
        }
    }

    if fin {
        quic_conn.stream_send(stream_id, &[], true)?;
    }

    Ok(())
}

fn framed_postcard<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, TcpError> {
    let payload = postcard::to_allocvec(value)?;
    let len = u32::try_from(payload.len())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "frame too large"))?;

    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(&payload);
    Ok(framed)
}

fn pseudo_random_index(len: usize) -> usize {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as usize;
    if len == 0 {
        0
    } else {
        seed % len
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;

    #[test]
    fn port_pool_allocates_preferred_and_releases() {
        let mut pool = PortPool::new();
        let preferred = 12_345;

        let allocated = pool.allocate(Some(preferred));
        assert_eq!(allocated, Some(preferred));
        assert_eq!(pool.allocate(Some(preferred)), None);

        pool.release(preferred);
        assert_eq!(pool.allocate(Some(preferred)), Some(preferred));
    }

    #[test]
    fn port_pool_exhaustion() {
        let mut pool = PortPool::from_ports(vec![20_001, 20_002]);
        assert!(pool.allocate(None).is_some());
        assert!(pool.allocate(None).is_some());
        assert_eq!(pool.allocate(None), None);
    }

    #[test]
    fn stream_header_frame_roundtrip() {
        let header = StreamHeader {
            tunnel_id: TunnelId::new(),
            connection_id: 42,
            source_addr: "127.0.0.1:12345".parse().expect("valid addr"),
            streaming: false,
        };

        let frame = framed_postcard(&header).expect("encode framed header");
        let len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        let decoded: StreamHeader =
            postcard::from_bytes(&frame[4..4 + len]).expect("decode header");
        assert_eq!(decoded, header);
    }

    #[derive(Default)]
    struct MockQuicConn {
        capacity: usize,
        recv_chunks: VecDeque<(Vec<u8>, bool)>,
        sent_payloads: Vec<Vec<u8>>,
        shutdowns: Vec<(u64, quiche::Shutdown)>,
    }

    impl QuicConnectionIo for MockQuicConn {
        fn stream_capacity(&mut self, _stream_id: u64) -> Result<usize, quiche::Error> {
            Ok(self.capacity)
        }

        fn stream_send(
            &mut self,
            _stream_id: u64,
            buf: &[u8],
            _fin: bool,
        ) -> Result<usize, quiche::Error> {
            if self.capacity == 0 {
                return Err(quiche::Error::Done);
            }

            self.sent_payloads.push(buf.to_vec());
            Ok(buf.len())
        }

        fn stream_recv(
            &mut self,
            _stream_id: u64,
            buf: &mut [u8],
        ) -> Result<(usize, bool), quiche::Error> {
            if let Some((chunk, fin)) = self.recv_chunks.pop_front() {
                let n = chunk.len().min(buf.len());
                buf[..n].copy_from_slice(&chunk[..n]);
                return Ok((n, fin));
            }
            Err(quiche::Error::Done)
        }

        fn stream_shutdown(
            &mut self,
            stream_id: u64,
            direction: quiche::Shutdown,
            _error_code: u64,
        ) -> Result<(), quiche::Error> {
            self.shutdowns.push((stream_id, direction));
            Ok(())
        }
    }

    #[tokio::test]
    async fn copy_with_backpressure_moves_data_both_directions() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");

        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect(addr).await.expect("connect");
            client.write_all(b"ping").await.expect("write ping");
            client.shutdown().await.expect("shutdown client write");

            let mut inbound = Vec::new();
            client
                .read_to_end(&mut inbound)
                .await
                .expect("read server response");
            inbound
        });

        let (server_stream, _) = listener.accept().await.expect("accept");
        let (mut read_half, mut write_half) = server_stream.into_split();

        let mut mock = MockQuicConn {
            capacity: COPY_BUFFER_SIZE,
            recv_chunks: VecDeque::from(vec![(b"pong".to_vec(), true)]),
            sent_payloads: Vec::new(),
            shutdowns: Vec::new(),
        };

        copy_with_backpressure(
            &mut read_half,
            &mut write_half,
            &mut mock,
            4,
            &NoopBandwidthMeter,
        )
        .await
        .expect("copy with backpressure");

        let client_received = client_task.await.expect("client task");
        assert_eq!(client_received, b"pong");
        assert!(mock
            .sent_payloads
            .iter()
            .any(|payload| payload.as_slice() == b"ping"));
        assert!(
            mock.shutdowns
                .iter()
                .any(|(stream_id, direction)| *stream_id == 4
                    && *direction == quiche::Shutdown::Write)
        );
    }
}
