//! Frontend role: fresh route discovery over the hop, fail-closed target
//! resolution, and forwarding of public HTTP, TLS, TCP and UDP traffic to the
//! owning relay. Nothing here admits or meters a visitor; the owner does that
//! with the original visitor address carried in the hop header.
use super::{
    valid_authority, valid_challenge_token, ChallengeRequest, Duplex, HopHeader, HopRequest,
    ACCEPTED, CONNECT_TIMEOUT, HOP_TIMEOUT, MAX_CHALLENGE_PROOF_BYTES, REJECTED,
};
use crate::{
    config::IngressConfig,
    ingress_directory::{
        Advertisement, Directory, Protocol, Snapshot, Target, MAX_AGE_MS, MAX_RESPONSE_BYTES,
        MAX_ROUTES, VERSION,
    },
    proxy::{is_websocket_upgrade, DEFAULT_PROXY_TIMEOUT},
    visitor_policy::VisitorPeer,
};
use anyhow::{anyhow, bail, ensure, Context, Result};
use axum::{
    body::Body,
    http::{Request, Response, StatusCode},
};
use futures_util::StreamExt;
use http_body_util::{BodyStream, StreamBody};
use hyper::rt::Executor;
use hyper_util::rt::TokioIo;
use pike_core::datagram::{self, Packets, MAX_PACKET_BYTES, MAX_PEERS, QUEUE_PACKETS};
use rustls::pki_types::ServerName;
use std::{
    collections::{HashMap, HashSet},
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, PoisonError,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{mpsc, watch, Semaphore},
    task::{JoinHandle, JoinSet},
    time::{timeout, Instant},
};

pub type HopStream = tokio_rustls::client::TlsStream<TcpStream>;

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const POLL_TIMEOUT: Duration = Duration::from_millis(1500);
/// Backstop for a leaked hold; a `PortHold` normally releases on drop.
const HOLD: Duration = Duration::from_secs(15);
/// Concurrent forwarded TCP streams and UDP associations, all ports combined.
const MAX_FORWARDED: usize = 2048;
/// Safety net above the longest profile idle timeout; the owner's own idle
/// expiry normally ends an association first by closing the hop.
const UDP_IDLE: Duration = Duration::from_secs(330);

struct Peer {
    name: String,
    server_name: ServerName<'static>,
    addr: SocketAddr,
}

struct PeerRoutes {
    /// Measured from the poll start on this relay's monotonic clock.
    expires: Instant,
    routes: Vec<Advertisement>,
}

struct Forwarder {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

/// Registration-scoped withdrawal of one forwarded port. Dropping it, on any
/// outcome of the local registration, lets the next poll reopen the forwarder
/// if a peer still advertises the target and this relay does not serve it.
pub struct PortHold {
    frontend: Arc<Frontend>,
    target: Target,
}

impl Drop for PortHold {
    fn drop(&mut self) {
        self.frontend
            .holds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.target);
    }
}

impl Forwarder {
    /// The listener socket is released only after the task has returned.
    async fn close(self) {
        self.stop.send_replace(true);
        let _ = self.task.await;
    }
}

/// Live peers ordered for one new stream: healthiest first, rotating among
/// equals. Never used after bytes reached a relay.
pub struct Resolved {
    pub authority: String,
    candidates: Vec<usize>,
}

enum Attempt {
    /// Connect or TLS failed before any hop header was written.
    Unreachable(anyhow::Error),
    /// The owner refused before dispatch; no origin side effects occurred.
    Rejected,
    /// Failure after the header was attempted; never retried.
    Ambiguous(anyhow::Error),
}

/// Outcome of one challenge lookup on one owner. A lookup carries no visitor
/// bytes and creates no origin side effect, so an explicit refusal may move on
/// to the next agreeing owner; anything malformed or ambiguous ends the lookup.
enum ChallengeAnswer {
    Proof(String),
    Refused,
    Failed(anyhow::Error),
}

pub struct Frontend {
    peers: Vec<Peer>,
    client: Arc<rustls::ClientConfig>,
    local: Arc<Directory>,
    bind_ip: Ipv4Addr,
    table: Mutex<Vec<Option<PeerRoutes>>>,
    holds: Mutex<HashMap<Target, Instant>>,
    forwarders: Mutex<HashMap<Target, Forwarder>>,
    rotation: AtomicUsize,
    streams: Arc<Semaphore>,
    shutdown: watch::Receiver<bool>,
}

impl Frontend {
    /// Build the frontend and start its one-second snapshot poll.
    pub fn spawn(
        config: &IngressConfig,
        bind_ip: Ipv4Addr,
        client: Arc<rustls::ClientConfig>,
        local: Arc<Directory>,
        shutdown: watch::Receiver<bool>,
    ) -> Result<Arc<Self>> {
        let frontend = Self::new(config, bind_ip, client, local, shutdown)?;
        tokio::spawn(frontend.clone().run());
        Ok(frontend)
    }

    fn new(
        config: &IngressConfig,
        bind_ip: Ipv4Addr,
        client: Arc<rustls::ClientConfig>,
        local: Arc<Directory>,
        shutdown: watch::Receiver<bool>,
    ) -> Result<Arc<Self>> {
        let peers = config
            .peers
            .iter()
            .map(|peer| {
                Ok(Peer {
                    name: peer.name.clone(),
                    server_name: ServerName::try_from(peer.name.clone())?,
                    addr: peer.addr,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(!peers.is_empty(), "ingress frontend requires peers");
        Ok(Arc::new(Self {
            table: Mutex::new(peers.iter().map(|_| None).collect()),
            peers,
            client,
            local,
            bind_ip,
            holds: Mutex::default(),
            forwarders: Mutex::default(),
            rotation: AtomicUsize::new(0),
            streams: Arc::new(Semaphore::new(MAX_FORWARDED)),
            shutdown,
        }))
    }

    pub fn shutdown_signal(&self) -> watch::Receiver<bool> {
        self.shutdown.clone()
    }

    /// Current agreement on one target across fresh snapshots. Any disagreement
    /// about the authority fails closed; an expired or failed poll contributes
    /// nothing.
    pub fn resolve(&self, target: &Target) -> Option<Resolved> {
        let now = Instant::now();
        let table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
        let mut authority: Option<&str> = None;
        let mut candidates: Vec<(u8, usize)> = Vec::new();
        for (index, peer) in table.iter().enumerate() {
            let Some(routes) = peer.as_ref().filter(|routes| routes.expires > now) else {
                continue;
            };
            let Some(route) = routes.routes.iter().find(|route| route.target == *target) else {
                continue;
            };
            match authority {
                Some(current) if current != route.authority => return None,
                Some(_) => {}
                None => authority = Some(&route.authority),
            }
            candidates.push((health_rank(&route.origin_health), index));
        }
        let authority = authority?.to_owned();
        candidates.sort_unstable();
        let best = candidates
            .iter()
            .take_while(|(rank, _)| *rank == candidates[0].0)
            .count();
        let start = self.rotation.fetch_add(1, Ordering::Relaxed) % best;
        candidates[..best].rotate_left(start);
        Some(Resolved {
            authority,
            candidates: candidates.into_iter().map(|(_, index)| index).collect(),
        })
    }

    /// Stop forwarding one port so local registration can bind it. Call only
    /// after the cloud reservation proved this profile owns the port. Forwarded
    /// TCP streams already accepted stay pinned; UDP associations end with the
    /// socket they reply through. The returned hold must live until the local
    /// registration is advertised or has failed.
    pub async fn hold_port(self: &Arc<Self>, target: &Target) -> PortHold {
        self.holds
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(target.clone(), Instant::now() + HOLD);
        let forwarder = self
            .forwarders
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(target);
        if let Some(forwarder) = forwarder {
            forwarder.close().await;
        }
        PortHold {
            frontend: self.clone(),
            target: target.clone(),
        }
    }

    /// ACME HTTP-01 for a hostname owned elsewhere as a TLS-terminate profile,
    /// which advertises no HTTP target. Strictly one token lookup per hop; the
    /// owner verifies the target and authority and answers only from the
    /// certificate entry bound to that endpoint's gate. Owners with separate
    /// ACME stores hold different challenges for one hostname, so an owner's
    /// explicit refusal moves on to the next owner that advertised the same
    /// authority; a malformed or ambiguous answer ends the lookup, and peers
    /// that disagree about the authority are never asked at all.
    pub async fn forward_challenge(&self, host: &str, token: &str) -> Option<String> {
        if !valid_challenge_token(token) {
            return None;
        }
        let target = Target::hostname(Protocol::Tls, host);
        let resolved = self.resolve(&target)?;
        let request = HopRequest::Challenge(ChallengeRequest {
            target,
            authority: resolved.authority.clone(),
            token: token.to_owned(),
        })
        .encode()
        .ok()?;
        self.challenge_candidates(host, token, resolved.candidates, &request, |index| {
            self.handshake(&self.peers[index])
        })
        .await
    }

    /// One lookup per candidate in order. `connect` opens the hop to a peer by
    /// index; only a connection that never carried the request is skipped
    /// silently, an explicit refusal continues, everything else fails closed.
    async fn challenge_candidates<S, F, Fut>(
        &self,
        host: &str,
        token: &str,
        candidates: Vec<usize>,
        request: &[u8],
        mut connect: F,
    ) -> Option<String>
    where
        S: AsyncRead + AsyncWrite + Unpin,
        F: FnMut(usize) -> Fut,
        Fut: Future<Output = Result<S>>,
    {
        for index in candidates {
            let peer = &self.peers[index];
            let mut hop = match connect(index).await {
                Ok(hop) => hop,
                Err(error) => {
                    tracing::debug!(peer = %peer.name, %host, %error, "ingress challenge peer unreachable");
                    continue;
                }
            };
            match exchange_challenge(&mut hop, request, token).await {
                ChallengeAnswer::Proof(proof) => return Some(proof),
                ChallengeAnswer::Refused => {
                    tracing::debug!(peer = %peer.name, %host, "ingress challenge refused; trying the next agreeing owner");
                }
                ChallengeAnswer::Failed(error) => {
                    tracing::debug!(peer = %peer.name, %host, %error, "ingress challenge failed");
                    return None;
                }
            }
        }
        None
    }

    /// One accepted hop for one visitor stream. Only connect/TLS failures and an
    /// explicit pre-dispatch rejection lead to another attempt, and rejection
    /// permits exactly one re-resolve from a fresh snapshot.
    pub async fn open(
        &self,
        target: &Target,
        visitor: SocketAddr,
        secure: bool,
    ) -> Result<HopStream> {
        let mut reresolved = false;
        loop {
            let resolved = self
                .resolve(target)
                .context("no live relay advertises this target")?;
            let header = HopHeader {
                target: target.clone(),
                authority: resolved.authority,
                visitor,
                secure,
            };
            let mut rejected = false;
            for index in resolved.candidates {
                let peer = &self.peers[index];
                match self.connect(peer, &header).await {
                    Ok(stream) => return Ok(stream),
                    Err(Attempt::Unreachable(error)) => {
                        tracing::debug!(peer = %peer.name, %error, "ingress peer unreachable");
                    }
                    Err(Attempt::Rejected) => {
                        tracing::debug!(peer = %peer.name, ?target, "ingress hop rejected before dispatch");
                        rejected = true;
                        break;
                    }
                    Err(Attempt::Ambiguous(error)) => {
                        return Err(error.context("ingress hop failed after the header was sent"));
                    }
                }
            }
            if rejected && !reresolved {
                reresolved = true;
                continue;
            }
            bail!("no relay accepted the ingress hop");
        }
    }

    async fn handshake(&self, peer: &Peer) -> Result<HopStream> {
        let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(peer.addr))
            .await
            .context("hop connect timed out")??;
        let _ = tcp.set_nodelay(true);
        let connector = tokio_rustls::TlsConnector::from(self.client.clone());
        timeout(
            CONNECT_TIMEOUT,
            connector.connect(peer.server_name.clone(), tcp),
        )
        .await
        .context("hop TLS timed out")?
        .context("hop TLS handshake failed")
    }

    async fn connect(&self, peer: &Peer, header: &HopHeader) -> Result<HopStream, Attempt> {
        let request = HopRequest::Stream(header.clone())
            .encode()
            .map_err(Attempt::Ambiguous)?;
        let mut tls = self.handshake(peer).await.map_err(Attempt::Unreachable)?;
        match timeout(HOP_TIMEOUT, async {
            tls.write_all(&request).await?;
            tls.flush().await
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(Attempt::Ambiguous(error.into())),
            Err(_) => return Err(Attempt::Ambiguous(anyhow!("hop header write timed out"))),
        }
        let mut decision = [0_u8; 1];
        match timeout(HOP_TIMEOUT, tls.read_exact(&mut decision)).await {
            Ok(Ok(_)) if decision[0] == ACCEPTED => Ok(tls),
            Ok(Ok(_)) if decision[0] == REJECTED => Err(Attempt::Rejected),
            Ok(Ok(_)) => Err(Attempt::Ambiguous(anyhow!("invalid hop decision byte"))),
            Ok(Err(error)) => Err(Attempt::Ambiguous(error.into())),
            Err(_) => Err(Attempt::Ambiguous(anyhow!("hop decision timed out"))),
        }
    }

    async fn fetch(&self, index: usize) -> Result<PeerRoutes> {
        let started = Instant::now();
        let peer = &self.peers[index];
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let mut tls = self.handshake(peer).await?;
        tls.write_all(&HopRequest::Directory(nonce.clone()).encode()?)
            .await?;
        tls.flush().await?;
        let mut length = [0_u8; 4];
        tls.read_exact(&mut length).await?;
        let length = u32::from_be_bytes(length) as usize;
        ensure!(
            length > 0 && length <= MAX_RESPONSE_BYTES,
            "ingress snapshot exceeds 2 MiB"
        );
        let mut body = vec![0_u8; length];
        tls.read_exact(&mut body).await?;
        let snapshot: Snapshot = serde_json::from_slice(&body)?;
        ensure!(
            snapshot.version == VERSION,
            "unsupported ingress snapshot version"
        );
        ensure!(snapshot.nonce == nonce, "ingress snapshot nonce mismatch");
        ensure!(
            snapshot.routes.len() <= MAX_ROUTES,
            "ingress snapshot exceeds route bound"
        );
        for route in &snapshot.routes {
            route.target.validate()?;
            ensure!(
                valid_authority(&route.authority),
                "invalid advertised authority"
            );
        }
        Ok(PeerRoutes {
            expires: started + Duration::from_millis(snapshot.max_age_ms.min(MAX_AGE_MS)),
            routes: snapshot.routes,
        })
    }

    async fn run(self: Arc<Self>) {
        let mut shutdown = self.shutdown.clone();
        let mut interval = tokio::time::interval(POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = interval.tick() => {}
            }
            let this = &self;
            let results =
                futures_util::future::join_all((0..self.peers.len()).map(|index| async move {
                    timeout(POLL_TIMEOUT, this.fetch(index))
                        .await
                        .map_err(|_| anyhow!("ingress snapshot poll timed out"))
                        .and_then(|result| result)
                }))
                .await;
            {
                let mut table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
                for (index, result) in results.into_iter().enumerate() {
                    match result {
                        Ok(routes) => table[index] = Some(routes),
                        Err(error) => {
                            if table[index].take().is_some() {
                                tracing::warn!(peer = %self.peers[index].name, %error, "ingress snapshot unavailable; peer routes withdrawn");
                            }
                        }
                    }
                }
            }
            self.reconcile_ports().await;
        }
        let forwarders: Vec<_> = self
            .forwarders
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain()
            .map(|(_, forwarder)| forwarder)
            .collect();
        for forwarder in forwarders {
            forwarder.close().await;
        }
    }

    /// Open public listeners only for conflict-free port targets that this
    /// relay does not serve itself and that no local registration is claiming.
    /// Withdrawn or conflicting targets close within one poll.
    async fn reconcile_ports(self: &Arc<Self>) {
        let now = Instant::now();
        let local: HashSet<Target> = self
            .local
            .snapshot(&uuid::Uuid::new_v4().simple().to_string())
            .map(|snapshot| {
                snapshot
                    .routes
                    .into_iter()
                    .map(|route| route.target)
                    .collect()
            })
            .unwrap_or_default();
        let held: HashSet<Target> = {
            let mut holds = self.holds.lock().unwrap_or_else(PoisonError::into_inner);
            holds.retain(|_, until| *until > now);
            holds.keys().cloned().collect()
        };
        let candidates: HashSet<Target> = {
            let table = self.table.lock().unwrap_or_else(PoisonError::into_inner);
            table
                .iter()
                .flatten()
                .filter(|routes| routes.expires > now)
                .flat_map(|routes| routes.routes.iter().map(|route| route.target.clone()))
                .filter(|target| matches!(target.protocol, Protocol::Tcp | Protocol::Udp))
                .collect()
        };
        let desired: HashSet<Target> = candidates
            .into_iter()
            .filter(|target| {
                !local.contains(target) && !held.contains(target) && self.resolve(target).is_some()
            })
            .collect();
        let stale: Vec<Forwarder> = {
            let mut forwarders = self
                .forwarders
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            forwarders.retain(|_, forwarder| !forwarder.task.is_finished());
            let keys: Vec<_> = forwarders
                .keys()
                .filter(|target| !desired.contains(target))
                .cloned()
                .collect();
            keys.into_iter()
                .filter_map(|key| forwarders.remove(&key))
                .collect()
        };
        for forwarder in stale {
            forwarder.close().await;
        }
        for target in desired {
            if self
                .forwarders
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .contains_key(&target)
            {
                continue;
            }
            match self.bind(&target).await {
                Ok(forwarder) => {
                    tracing::info!(?target, "ingress frontend forwarder opened");
                    self.forwarders
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(target, forwarder);
                }
                Err(error) => {
                    tracing::debug!(?target, %error, "ingress frontend port unavailable; retrying next poll");
                }
            }
        }
    }

    async fn bind(self: &Arc<Self>, target: &Target) -> Result<Forwarder> {
        let port = target.port.context("port target required")?;
        let (stop, stopped) = watch::channel(false);
        let task = match target.protocol {
            Protocol::Tcp => {
                let listener = crate::tcp::TcpTunnelManager::bind_public_listener(
                    SocketAddr::new(self.bind_ip.into(), port),
                )?;
                tokio::spawn(self.clone().run_tcp(target.clone(), listener, stopped))
            }
            Protocol::Udp => {
                let socket = UdpSocket::bind((self.bind_ip, port)).await?;
                datagram::configure_socket(&socket)?;
                tokio::spawn(self.clone().run_udp(target.clone(), socket, stopped))
            }
            Protocol::Http | Protocol::Https | Protocol::Tls => bail!("not a port target"),
        };
        Ok(Forwarder { task, stop })
    }

    async fn run_tcp(
        self: Arc<Self>,
        target: Target,
        listener: TcpListener,
        mut stopped: watch::Receiver<bool>,
    ) {
        loop {
            let accepted = tokio::select! {
                _ = stopped.changed() => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((socket, visitor)) = accepted else {
                break;
            };
            let Ok(permit) = self.streams.clone().try_acquire_owned() else {
                continue;
            };
            let this = self.clone();
            let target = target.clone();
            tokio::spawn(async move {
                let _permit = permit;
                this.pipe_tcp(&target, socket, visitor).await;
            });
        }
    }

    async fn pipe_tcp(&self, target: &Target, mut socket: TcpStream, visitor: SocketAddr) {
        let _ = socket.set_nodelay(true);
        let mut shutdown = self.shutdown.clone();
        let mut hop = match self.open(target, visitor, false).await {
            Ok(hop) => hop,
            Err(error) => {
                tracing::debug!(?target, %visitor, %error, "ingress TCP forward refused");
                return;
            }
        };
        tokio::select! {
            _ = shutdown.changed() => {}
            _ = tokio::io::copy_bidirectional(&mut socket, &mut hop) => {}
        }
    }

    async fn run_udp(
        self: Arc<Self>,
        target: Target,
        socket: UdpSocket,
        mut stopped: watch::Receiver<bool>,
    ) {
        let socket = Arc::new(socket);
        let mut peers: HashMap<SocketAddr, (u64, mpsc::Sender<Vec<u8>>)> = HashMap::new();
        let mut tasks: JoinSet<(SocketAddr, u64)> = JoinSet::new();
        let mut buffer = vec![0_u8; 65_535];
        let mut next = 0_u64;
        loop {
            tokio::select! {
                biased;
                _ = stopped.changed() => break,
                finished = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Ok((peer, id))) = finished {
                        if peers.get(&peer).is_some_and(|(current, _)| *current == id) { peers.remove(&peer); }
                    }
                }
                datagram = socket.recv_from(&mut buffer) => {
                    let Ok((size, peer)) = datagram else { break; };
                    if size > MAX_PACKET_BYTES { continue; }
                    if let Some((_, sender)) = peers.get(&peer) {
                        // Drop complete packets under pressure, never fragments.
                        let _ = sender.try_send(buffer[..size].to_vec());
                        continue;
                    }
                    if peers.len() >= MAX_PEERS { continue; }
                    let Ok(permit) = self.streams.clone().try_acquire_owned() else { continue; };
                    let (sender, receiver) = mpsc::channel(QUEUE_PACKETS);
                    let _ = sender.try_send(buffer[..size].to_vec());
                    next += 1;
                    let id = next;
                    peers.insert(peer, (id, sender));
                    let this = self.clone();
                    let target = target.clone();
                    let socket = socket.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        this.udp_association(&target, socket, peer, receiver).await;
                        (peer, id)
                    });
                }
            }
        }
        tasks.shutdown().await;
    }

    /// One visitor address pins to one hop association: its packets travel
    /// length-framed to the owner and every reply returns to that address.
    async fn udp_association(
        &self,
        target: &Target,
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
        mut packets: mpsc::Receiver<Vec<u8>>,
    ) {
        let hop = match self.open(target, peer, false).await {
            Ok(hop) => hop,
            Err(error) => {
                tracing::debug!(?target, %peer, %error, "ingress UDP association refused");
                return;
            }
        };
        let (mut reader, mut writer) = tokio::io::split(hop);
        let (activity, mut latest) = watch::channel(Instant::now());
        let uplink = async {
            while let Some(packet) = packets.recv().await {
                writer.write_all(&datagram::frame(&packet)?).await?;
                writer.flush().await?;
                activity.send_replace(Instant::now());
            }
            Ok::<_, anyhow::Error>(())
        };
        let downlink = async {
            let mut decoder = Packets::default();
            let mut buffer = vec![0_u8; 65_536];
            loop {
                let count = reader.read(&mut buffer).await?;
                if count == 0 {
                    break;
                }
                for packet in decoder.feed(&buffer[..count])? {
                    socket.send_to(&packet, peer).await?;
                    activity.send_replace(Instant::now());
                }
            }
            decoder.finish()
        };
        let expiry = async {
            loop {
                let deadline = *latest.borrow_and_update() + UDP_IDLE;
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => break,
                    result = latest.changed() => { if result.is_err() { break; } }
                }
            }
        };
        let mut shutdown = self.shutdown.clone();
        tokio::select! {
            biased;
            _ = shutdown.changed() => {}
            _ = expiry => {}
            _ = uplink => {}
            _ = downlink => {}
        }
    }

    /// Forward one plain-HTTP request for a hostname this relay does not route.
    /// HTTP/2 prior knowledge carries ordinary requests including gRPC trailers;
    /// HTTP/1.1 carries WebSocket upgrades. Nothing is retried once request
    /// headers have been written to the hop.
    pub async fn forward_http(
        &self,
        host: &str,
        visitor: VisitorPeer,
        mut request: Request<Body>,
    ) -> Response<Body> {
        let target = Target::hostname(Protocol::Http, host);
        let websocket = is_websocket_upgrade(request.headers());
        let downstream = websocket.then(|| hyper::upgrade::on(&mut request));
        let hop = match self.open(&target, visitor.addr, visitor.secure).await {
            Ok(hop) => hop,
            Err(error) => {
                tracing::debug!(%host, %error, "ingress HTTP forward refused");
                return simple(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "no relay accepted this request",
                );
            }
        };
        let io = TokioIo::new(hop);
        let result = match downstream {
            Some(downstream) => {
                forward_upgrade(io, request, downstream, self.shutdown.clone()).await
            }
            None => forward_h2(io, host, request, self.shutdown.clone()).await,
        };
        match result {
            Ok(response) => response,
            Err(error) => {
                tracing::debug!(%host, %error, "ingress HTTP forward failed after dispatch");
                simple(
                    StatusCode::BAD_GATEWAY,
                    "owning relay did not complete the request",
                )
            }
        }
    }

    /// Forward a TLS connection after the ClientHello peek. The visitor's own
    /// handshake, certificate and proof of possession reach the owning relay.
    pub async fn forward_tls(
        &self,
        target: &Target,
        io: Box<dyn Duplex>,
        prefix: Vec<u8>,
        visitor: SocketAddr,
    ) -> Result<TlsForward> {
        let hop = self.open(target, visitor, true).await?;
        Ok(TlsForward { io, prefix, hop })
    }
}

/// One challenge request on an open hop: decision byte, then on acceptance a
/// u16 length and the key authorization, which must be for exactly `token`.
async fn exchange_challenge<S>(hop: &mut S, request: &[u8], token: &str) -> ChallengeAnswer
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let answer = timeout(HOP_TIMEOUT, async {
        hop.write_all(request).await?;
        hop.flush().await?;
        let mut decision = [0_u8; 1];
        hop.read_exact(&mut decision).await?;
        match decision[0] {
            ACCEPTED => {}
            REJECTED => return Ok(None),
            _ => bail!("invalid hop decision byte"),
        }
        let mut length = [0_u8; 2];
        hop.read_exact(&mut length).await?;
        let length = usize::from(u16::from_be_bytes(length));
        ensure!(
            length > 0 && length <= MAX_CHALLENGE_PROOF_BYTES,
            "challenge proof length out of bounds"
        );
        let mut proof = vec![0_u8; length];
        hop.read_exact(&mut proof).await?;
        let proof = String::from_utf8(proof).context("challenge proof is not UTF-8")?;
        // A key authorization is `<token>.<thumbprint>`; anything else is not
        // an answer to this lookup.
        ensure!(
            proof.len() > token.len() + 1
                && proof.starts_with(token)
                && proof.as_bytes()[token.len()] == b'.'
                && proof.bytes().all(|c| c.is_ascii_graphic()),
            "challenge proof does not answer this token"
        );
        Ok::<_, anyhow::Error>(Some(proof))
    })
    .await;
    match answer {
        Ok(Ok(Some(proof))) => ChallengeAnswer::Proof(proof),
        Ok(Ok(None)) => ChallengeAnswer::Refused,
        Ok(Err(error)) => ChallengeAnswer::Failed(error),
        Err(_) => ChallengeAnswer::Failed(anyhow!("challenge hop timed out")),
    }
}

/// Runs every hyper task behind one forwarded hop under the frontend shutdown
/// signal. hyper's HTTP/2 client spawns the socket-owning connection driver
/// through the executor it is given, separately from the dispatcher it returns,
/// so only the executor reaches both; the HTTP/1.1 upgrade driver and the
/// upgraded byte copy go through it as well. When shutdown fires each task is
/// dropped where it stands, which closes the hop socket whether or not any
/// visitor is still polling a response body: a stalled downstream connection
/// cannot keep the hop, or graceful HTTP shutdown, open. Anything a task was
/// awaiting on the hop then fails, never completes, so no request is replayed.
/// A closed signal counts as shutdown, as everywhere in this module.
#[derive(Clone)]
struct HopExecutor {
    shutdown: watch::Receiver<bool>,
}

impl<Fut> Executor<Fut> for HopExecutor
where
    Fut: Future + Send + 'static,
    Fut::Output: Send + 'static,
{
    fn execute(&self, future: Fut) {
        let mut shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                biased;
                _ = shutdown.wait_for(|stop| *stop) => {}
                _ = future => {}
            }
        });
    }
}

/// HTTP/1.1 over the hop for one WebSocket upgrade. The hop's connection
/// driver, the acquisition of both upgraded halves and the byte copy all run
/// under `HopExecutor`, so shutdown ends the hop even while the owner or the
/// visitor has yet to complete its side of the upgrade. A response other than
/// 101 carries its body through `guarded_body` exactly like a forwarded HTTP/2
/// response.
async fn forward_upgrade<I>(
    io: TokioIo<I>,
    mut request: Request<Body>,
    downstream: hyper::upgrade::OnUpgrade,
    shutdown: watch::Receiver<bool>,
) -> Result<Response<Body>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let executor = HopExecutor {
        shutdown: shutdown.clone(),
    };
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
    executor.execute(async move {
        let _ = connection.with_upgrades().await;
    });
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |value| value.as_str())
        .to_owned();
    *request.uri_mut() = path.parse()?;
    sender.ready().await?;
    let mut response = timeout(DEFAULT_PROXY_TIMEOUT, sender.send_request(request))
        .await
        .context("owning relay upgrade response timed out")??;
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return Ok(response.map(|body| guarded_body(body, shutdown)));
    }
    let upstream = hyper::upgrade::on(&mut response);
    executor.execute(async move {
        let (Ok(upstream), Ok(downstream)) = tokio::join!(upstream, downstream) else {
            return;
        };
        let mut upstream = TokioIo::new(upstream);
        let mut downstream = TokioIo::new(downstream);
        let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await;
    });
    Ok(response.map(|_| Body::empty()))
}

/// The owner compares `:authority` with `Host` before routing, so the request
/// keeps the visitor's full authority (including any port); the normalized
/// `host` served only route lookup and is the fallback when the request carried
/// no authority at all.
async fn forward_h2<I>(
    io: TokioIo<I>,
    host: &str,
    mut request: Request<Body>,
    shutdown: watch::Receiver<bool>,
) -> Result<Response<Body>>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let executor = HopExecutor {
        shutdown: shutdown.clone(),
    };
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(executor.clone(), io).await?;
    // hyper drives the hop socket on a task of its own, spawned through the
    // executor above. This dispatcher only carries the one request and finishes
    // as soon as `sender` is dropped below; from then on the response body
    // returned by `guarded_body` is the only handle that keeps the hop open
    // while the frontend runs, and shutdown drops both tasks regardless.
    executor.execute(async move {
        let _ = connection.await;
    });
    let path = request
        .uri()
        .path_and_query()
        .map_or("/", |value| value.as_str())
        .to_owned();
    let authority = request
        .headers()
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(|value| value.as_str().to_owned())
        })
        .unwrap_or_else(|| host.to_owned());
    *request.uri_mut() = axum::http::Uri::builder()
        .scheme("http")
        .authority(authority)
        .path_and_query(path)
        .build()?;
    sender.ready().await?;
    let response = timeout(DEFAULT_PROXY_TIMEOUT, sender.send_request(request))
        .await
        .context("owning relay response timed out")??;
    Ok(response.map(|body| guarded_body(body, shutdown)))
}

/// The forwarded response body owns the hop once the request is dispatched:
/// dropping it resets the HTTP/2 stream, and hyper closes a connection that has
/// no stream and no request handle left, which releases the hop socket and its
/// driver task. A visitor that goes away therefore frees the hop by itself.
/// Frontend shutdown ends the hop through `HopExecutor` without waiting for
/// anyone to poll this body; here the body is additionally dropped and the
/// visitor's response ends with an error rather than a clean end of stream, so
/// a truncated response is never mistaken for a complete one. Trailers pass
/// through unchanged.
fn guarded_body(body: hyper::body::Incoming, shutdown: watch::Receiver<bool>) -> Body {
    let frames = futures_util::stream::unfold(
        (Some(Box::pin(BodyStream::new(body))), shutdown),
        |(mut body, mut shutdown)| async move {
            let next = {
                let stream = body.as_mut()?;
                tokio::select! {
                    biased;
                    _ = shutdown.wait_for(|stop| *stop) => None,
                    frame = stream.next() => Some(frame),
                }
            };
            let frame = match next {
                Some(Some(frame)) => frame.map_err(std::io::Error::other),
                Some(None) => return None,
                None => {
                    body = None;
                    Err(std::io::Error::other("ingress frontend is shutting down"))
                }
            };
            Some((frame, (body, shutdown)))
        },
    );
    Body::new(StreamBody::new(frames))
}

pub struct TlsForward {
    io: Box<dyn Duplex>,
    prefix: Vec<u8>,
    hop: HopStream,
}

impl TlsForward {
    pub async fn pipe(mut self, mut shutdown: watch::Receiver<bool>) {
        if self.hop.write_all(&self.prefix).await.is_err() || self.hop.flush().await.is_err() {
            return;
        }
        tokio::select! {
            _ = shutdown.changed() => {}
            _ = tokio::io::copy_bidirectional(&mut self.io, &mut self.hop) => {}
        }
    }
}

fn health_rank(health: &str) -> u8 {
    match health {
        "healthy" => 0,
        "unknown" => 1,
        _ => 2,
    }
}

fn simple(status: StatusCode, message: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("cache-control", "no-store")
        .body(Body::from(message))
        .unwrap_or_else(|_| Response::new(Body::from(message)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::IngressPeer;
    use hyper_util::rt::TokioExecutor;

    fn frontend(names: &[&str]) -> Arc<Frontend> {
        let config = IngressConfig {
            ca_path: "unused".into(),
            cert_path: "unused".into(),
            key_path: "unused".into(),
            hop_bind_addr: None,
            peers: names
                .iter()
                .enumerate()
                .map(|(index, name)| IngressPeer {
                    name: (*name).to_owned(),
                    addr: format!("127.0.0.1:{}", 1 + index).parse().unwrap(),
                })
                .collect(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let (_shutdown, receiver) = watch::channel(false);
        // No poll loop: the tests place snapshots in the table directly.
        Frontend::new(
            &config,
            Ipv4Addr::LOCALHOST,
            Arc::new(client),
            Arc::default(),
            receiver,
        )
        .unwrap()
    }

    fn advertisement(target: &Target, authority: &str, health: &str) -> Advertisement {
        Advertisement {
            target: target.clone(),
            authority: authority.into(),
            members: 1,
            origin_health: health.into(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn resolution_prefers_health_rotates_equals_and_fails_closed_on_conflict_or_age() {
        let frontend = frontend(&["a.internal", "b.internal", "c.internal"]);
        let target = Target::hostname(Protocol::Http, "demo.pike.test");
        let same = "1".repeat(64);
        let now = Instant::now();
        {
            let mut table = frontend.table.lock().unwrap();
            table[0] = Some(PeerRoutes {
                expires: now + Duration::from_secs(2),
                routes: vec![advertisement(&target, &same, "unknown")],
            });
            table[1] = Some(PeerRoutes {
                expires: now + Duration::from_secs(2),
                routes: vec![advertisement(&target, &same, "healthy")],
            });
            table[2] = Some(PeerRoutes {
                expires: now + Duration::from_secs(1),
                routes: vec![advertisement(&target, &same, "healthy")],
            });
        }
        let first = frontend.resolve(&target).unwrap();
        let second = frontend.resolve(&target).unwrap();
        assert_eq!(first.candidates.len(), 3);
        assert_ne!(first.candidates[0], second.candidates[0]);
        assert!(first.candidates[0] != 0 && second.candidates[0] != 0);
        assert_eq!(first.candidates[2], 0);
        tokio::time::advance(Duration::from_millis(1001)).await;
        assert_eq!(frontend.resolve(&target).unwrap().candidates.len(), 2);
        {
            let mut table = frontend.table.lock().unwrap();
            table[0] = Some(PeerRoutes {
                expires: now + Duration::from_secs(2),
                routes: vec![advertisement(&target, &"2".repeat(64), "healthy")],
            });
        }
        assert!(frontend.resolve(&target).is_none());
        tokio::time::advance(Duration::from_millis(1000)).await;
        assert!(frontend.resolve(&target).is_none());
        assert!(frontend
            .open(&target, "127.0.0.1:5".parse().unwrap(), false)
            .await
            .is_err());
        // A TLS-only hostname is never a challenge candidate through an HTTP
        // target, and an invalid token never opens a hop at all.
        assert!(frontend
            .forward_challenge("demo.pike.test", "bad/token")
            .await
            .is_none());
        assert!(frontend
            .forward_challenge("demo.pike.test", "token")
            .await
            .is_none());
    }

    #[tokio::test]
    async fn forwarded_requests_keep_the_visitor_authority_including_port() {
        use http_body_util::Full;
        use hyper::{server::conn::http2, service::service_fn};
        for (uri, host_header, expected) in [
            (
                "/echo?x=1",
                Some("demo.pike.test:8080"),
                "demo.pike.test:8080",
            ),
            ("/echo", Some("demo.pike.test"), "demo.pike.test"),
            ("http://demo.pike.test:8080/h2", None, "demo.pike.test:8080"),
            ("/plain", None, "demo.pike.test"),
        ] {
            let (client, server) = tokio::io::duplex(65_536);
            let seen: Arc<Mutex<Option<(Option<String>, Result<String, String>)>>> = Arc::default();
            let record = seen.clone();
            tokio::spawn(async move {
                let service = service_fn(move |mut request: Request<hyper::body::Incoming>| {
                    let record = record.clone();
                    async move {
                        let authority = request
                            .uri()
                            .authority()
                            .map(|value| value.as_str().to_owned());
                        let canonical = crate::proxy::canonicalize_authority(&mut request)
                            .map_err(|error| error.to_string());
                        *record.lock().unwrap() = Some((authority, canonical));
                        Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                            axum::body::Bytes::new(),
                        )))
                    }
                });
                let _ = http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(server), service)
                    .await;
            });
            let mut request = Request::builder().uri(uri);
            if let Some(host) = host_header {
                request = request.header("host", host);
            }
            // A live signal: a closed one counts as shutdown and would end the hop.
            let (_keep, shutdown) = watch::channel(false);
            let response = forward_h2(
                TokioIo::new(client),
                "demo.pike.test",
                request.body(Body::empty()).unwrap(),
                shutdown,
            )
            .await
            .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{uri}");
            let (authority, canonical) = seen.lock().unwrap().clone().unwrap();
            assert_eq!(authority.as_deref(), Some(expected), "{uri}");
            // The owner's own check accepts the request and routes by hostname.
            assert_eq!(canonical.as_deref(), Ok(expected), "{uri}");
            assert_eq!(crate::router::normalize_host(expected), "demo.pike.test");
        }
    }

    #[tokio::test]
    async fn unreachable_peers_are_skipped_and_rejection_rules_never_retry_after_header() {
        let frontend = frontend(&["a.internal"]);
        let target = Target::port(Protocol::Tcp, 30000);
        let visitor: SocketAddr = "203.0.113.1:4000".parse().unwrap();
        // Nothing is listening on 127.0.0.1:1, so this is a connect failure before
        // any header; open() reports no acceptance rather than an ambiguous error.
        {
            let mut table = frontend.table.lock().unwrap();
            table[0] = Some(PeerRoutes {
                expires: Instant::now() + Duration::from_secs(2),
                routes: vec![advertisement(&target, &"a".repeat(64), "unknown")],
            });
        }
        let error = frontend.open(&target, visitor, false).await.unwrap_err();
        assert!(error.to_string().contains("no relay accepted"), "{error}");
        assert!(frontend.forwarders.lock().unwrap().is_empty());
        // A hold is scoped to the local registration: it releases on drop so a
        // failed registration cannot keep a peer's port withdrawn.
        let hold = frontend.hold_port(&target).await;
        assert!(frontend.holds.lock().unwrap().contains_key(&target));
        drop(hold);
        assert!(!frontend.holds.lock().unwrap().contains_key(&target));
    }

    /// An endless response body: one `chunk` of bytes every `pause`.
    fn endless_body(chunk: usize, pause: Duration) -> Body {
        use hyper::body::Frame;
        Body::new(StreamBody::new(futures_util::stream::unfold(
            0_u64,
            move |n| async move {
                tokio::time::sleep(pause).await;
                let mut bytes = format!("chunk-{n}\n").into_bytes();
                bytes.resize(chunk.max(bytes.len()), b'.');
                Some((
                    Ok::<_, axum::Error>(Frame::data(axum::body::Bytes::from(bytes))),
                    n + 1,
                ))
            },
        )))
    }

    /// A real hyper HTTP/2 server over a duplex that answers every request with
    /// an endless streaming body. The returned task finishes only once the
    /// connection itself has closed.
    fn endless_owner_with(
        chunk: usize,
        pause: Duration,
    ) -> (tokio::io::DuplexStream, JoinHandle<()>) {
        use hyper::{server::conn::http2, service::service_fn};
        let (client, server) = tokio::io::duplex(65_536);
        let task = tokio::spawn(async move {
            let service = service_fn(move |_request: Request<hyper::body::Incoming>| async move {
                Ok::<_, std::convert::Infallible>(Response::new(endless_body(chunk, pause)))
            });
            let _ = http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(server), service)
                .await;
        });
        (client, task)
    }

    fn endless_owner() -> (tokio::io::DuplexStream, JoinHandle<()>) {
        endless_owner_with(0, Duration::from_millis(5))
    }

    /// A real hyper HTTP/1.1 owner over a duplex for one upgrade-shaped request.
    /// With `switching` it answers 101 and then holds the upgraded connection
    /// until the frontend closes it; otherwise it answers 200 with an endless
    /// body. Either way the returned task finishes only once the hop has closed.
    fn upgrade_owner(switching: bool) -> (tokio::io::DuplexStream, JoinHandle<()>) {
        use hyper::{server::conn::http1, service::service_fn};
        let (client, server) = tokio::io::duplex(65_536);
        let task = tokio::spawn(async move {
            let (upgrades, mut upgrade_rx) = mpsc::channel::<hyper::upgrade::OnUpgrade>(1);
            let service = service_fn(move |mut request: Request<hyper::body::Incoming>| {
                let upgrades = upgrades.clone();
                async move {
                    let response = if switching {
                        let _ = upgrades.send(hyper::upgrade::on(&mut request)).await;
                        Response::builder()
                            .status(StatusCode::SWITCHING_PROTOCOLS)
                            .header("upgrade", "websocket")
                            .header("connection", "upgrade")
                            .body(Body::empty())
                            .unwrap()
                    } else {
                        Response::new(endless_body(0, Duration::from_millis(5)))
                    };
                    Ok::<_, std::convert::Infallible>(response)
                }
            });
            let connection = tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(server), service)
                    .with_upgrades()
                    .await;
            });
            if let Some(on_upgrade) = upgrade_rx.recv().await {
                if let Ok(io) = on_upgrade.await {
                    let mut io = TokioIo::new(io);
                    let mut sink = vec![0_u8; 4096];
                    while matches!(io.read(&mut sink).await, Ok(count) if count > 0) {}
                }
            }
            let _ = connection.await;
        });
        (client, task)
    }

    fn upgrade_request() -> Request<Body> {
        Request::builder()
            .uri("/socket")
            .header("host", "demo.pike.test")
            .header("connection", "upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("sec-websocket-version", "13")
            .body(Body::empty())
            .unwrap()
    }

    /// A visitor-side `OnUpgrade` that stays pending: the visitor's own HTTP/1.1
    /// connection has received the upgrade request but no 101 is ever written on
    /// it. The returned half must stay alive for the upgrade to remain pending.
    async fn pending_downstream() -> (hyper::upgrade::OnUpgrade, tokio::io::DuplexStream) {
        use hyper::{server::conn::http1, service::service_fn};
        let (mut visitor, server) = tokio::io::duplex(4096);
        let (upgrades, mut upgrade_rx) = mpsc::channel::<hyper::upgrade::OnUpgrade>(1);
        tokio::spawn(async move {
            let service = service_fn(move |mut request: Request<hyper::body::Incoming>| {
                let upgrades = upgrades.clone();
                async move {
                    let _ = upgrades.send(hyper::upgrade::on(&mut request)).await;
                    std::future::pending::<Result<Response<Body>, std::convert::Infallible>>().await
                }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(server), service)
                .with_upgrades()
                .await;
        });
        visitor
            .write_all(b"GET /socket HTTP/1.1\r\nhost: demo.pike.test\r\nconnection: upgrade\r\nupgrade: websocket\r\n\r\n")
            .await
            .unwrap();
        (upgrade_rx.recv().await.unwrap(), visitor)
    }

    /// Polls `body` to its end: `Err` for a cut response, `Ok` for a clean end.
    async fn settle(body: &mut Body) -> Result<(), String> {
        use http_body_util::BodyExt;
        timeout(Duration::from_secs(5), async {
            loop {
                match body.frame().await {
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Err(error.to_string()),
                    None => return Ok(()),
                }
            }
        })
        .await
        .expect("body settles after shutdown")
    }

    #[tokio::test]
    async fn frontend_shutdown_closes_the_hop_without_any_poll_of_the_forwarded_body() {
        let (client, owner) = endless_owner();
        let (stop, shutdown) = watch::channel(false);
        let response = forward_h2(
            TokioIo::new(client),
            "demo.pike.test",
            streaming_request(),
            shutdown,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        // Nobody polls the body. The owner keeps the stream open regardless.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!owner.is_finished());
        stop.send_replace(true);
        timeout(Duration::from_secs(5), owner)
            .await
            .expect("hop closed on shutdown while the body was never polled")
            .unwrap();
        // Whenever the visitor does read, the response is cut, never complete.
        assert!(settle(&mut body)
            .await
            .is_err_and(|error| error.contains("shutting down")));
    }

    #[tokio::test]
    async fn frontend_shutdown_closes_the_hop_while_the_visitor_connection_grants_no_send_capacity()
    {
        use http_body_util::BodyExt;
        use hyper::{server::conn::http2, service::service_fn};
        let (stop, shutdown) = watch::channel(false);
        let (visitor_io, frontend_io) = tokio::io::duplex(65_536);
        // Frames the frontend's visitor-facing server actually pulled from the
        // forwarded body.
        let polled = Arc::new(AtomicUsize::new(0));
        let (owners, mut owner) = mpsc::channel::<JoinHandle<()>>(1);
        let frontend_server = {
            let polled = polled.clone();
            tokio::spawn(async move {
                let service = service_fn(move |_request: Request<hyper::body::Incoming>| {
                    let polled = polled.clone();
                    let shutdown = shutdown.clone();
                    let owners = owners.clone();
                    async move {
                        let (client, owner) = endless_owner_with(16_384, Duration::from_millis(1));
                        let _ = owners.send(owner).await;
                        let response = forward_h2(
                            TokioIo::new(client),
                            "demo.pike.test",
                            streaming_request(),
                            shutdown,
                        )
                        .await
                        .unwrap();
                        Ok::<_, std::convert::Infallible>(response.map(|body| {
                            Body::new(body.map_frame(move |frame| {
                                polled.fetch_add(1, Ordering::Relaxed);
                                frame
                            }))
                        }))
                    }
                });
                let _ = http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(frontend_io), service)
                    .await;
            })
        };
        // The visitor: a small receive window and a body it never reads, so the
        // frontend's server side runs out of send capacity and stops polling the
        // forwarded body on its own.
        let (mut sender, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .initial_stream_window_size(16_384)
                .initial_connection_window_size(16_384)
                .handshake(TokioIo::new(visitor_io))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        sender.ready().await.unwrap();
        let response = sender
            .send_request(
                Request::builder()
                    .uri("http://demo.pike.test/stream")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let owner = owner.recv().await.unwrap();
        let stalled = timeout(Duration::from_secs(5), async {
            loop {
                let before = polled.load(Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(300)).await;
                if before > 0 && polled.load(Ordering::Relaxed) == before {
                    return before;
                }
            }
        })
        .await
        .expect("the forwarded body stops being polled once the visitor grants no capacity");
        assert!(
            !owner.is_finished(),
            "the hop stays open while the visitor stalls"
        );
        stop.send_replace(true);
        timeout(Duration::from_secs(5), owner)
            .await
            .expect("hop closed on shutdown without the visitor polling anything")
            .unwrap();
        assert_eq!(polled.load(Ordering::Relaxed), stalled);
        // The visitor finally reads: buffered data, then an error, never a clean end.
        let mut body = response.into_body();
        let outcome = timeout(Duration::from_secs(5), async {
            loop {
                match body.frame().await {
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Err(error.to_string()),
                    None => return Ok(()),
                }
            }
        })
        .await
        .expect("visitor response settles");
        assert!(outcome.is_err(), "{outcome:?}");
        frontend_server.abort();
    }

    #[tokio::test]
    async fn a_non_101_upgrade_response_is_guarded_like_any_forwarded_body() {
        let (client, owner) = upgrade_owner(false);
        let (stop, shutdown) = watch::channel(false);
        let mut request = upgrade_request();
        let downstream = hyper::upgrade::on(&mut request);
        let response = forward_upgrade(TokioIo::new(client), request, downstream, shutdown)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!owner.is_finished(), "the owner streams while nobody polls");
        stop.send_replace(true);
        timeout(Duration::from_secs(5), owner)
            .await
            .expect("hop closed on shutdown without any poll of the non-101 body")
            .unwrap();
        assert!(settle(&mut body)
            .await
            .is_err_and(|error| error.contains("shutting down")));
    }

    #[tokio::test]
    async fn frontend_shutdown_ends_an_upgrade_whose_visitor_side_never_completes() {
        let (client, owner) = upgrade_owner(true);
        let (stop, shutdown) = watch::channel(false);
        let (downstream, _visitor_half) = pending_downstream().await;
        let response = forward_upgrade(
            TokioIo::new(client),
            upgrade_request(),
            downstream,
            shutdown,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
        // The owner's side is upgraded and held; the visitor's side never is, so
        // the copy cannot start and nothing downstream will ever release the hop.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !owner.is_finished(),
            "the hop stays open while the visitor never upgrades"
        );
        stop.send_replace(true);
        timeout(Duration::from_secs(5), owner)
            .await
            .expect("hop closed on shutdown during upgrade acquisition")
            .unwrap();
    }

    #[tokio::test]
    async fn a_completed_upgrade_copies_both_ways_and_ends_on_shutdown() {
        use hyper::{server::conn::http1, service::service_fn};
        let (client, owner) = upgrade_owner(true);
        let (stop, shutdown) = watch::channel(false);
        // A visitor that does complete its upgrade: its connection is served by
        // hyper with the forwarded 101, then both halves are copied.
        let (mut visitor, server) = tokio::io::duplex(65_536);
        let (responses, mut response) = mpsc::channel::<Response<Body>>(1);
        let hop = std::sync::Mutex::new(Some(TokioIo::new(client)));
        let visitor_server = tokio::spawn(async move {
            let service = service_fn(move |mut request: Request<hyper::body::Incoming>| {
                let downstream = hyper::upgrade::on(&mut request);
                let hop = hop.lock().unwrap().take().unwrap();
                let shutdown = shutdown.clone();
                let responses = responses.clone();
                async move {
                    let response =
                        forward_upgrade(hop, request.map(Body::new), downstream, shutdown)
                            .await
                            .unwrap();
                    let _ = responses
                        .send(Response::new(Body::from(
                            response.status().as_u16().to_string(),
                        )))
                        .await;
                    Ok::<_, std::convert::Infallible>(response)
                }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(server), service)
                .with_upgrades()
                .await;
        });
        visitor
            .write_all(b"GET /socket HTTP/1.1\r\nhost: demo.pike.test\r\nconnection: upgrade\r\nupgrade: websocket\r\nsec-websocket-key: dGhlIHNhbXBsZSBub25jZQ==\r\nsec-websocket-version: 13\r\n\r\n")
            .await
            .unwrap();
        let forwarded = response.recv().await.unwrap();
        assert_eq!(forwarded.status(), StatusCode::OK);
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0_u8; 1];
            visitor.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        assert!(
            head.starts_with(b"HTTP/1.1 101"),
            "{}",
            String::from_utf8_lossy(&head)
        );
        // Bytes written by the visitor reach the owner's upgraded connection; the
        // owner task is reading them and stays alive.
        visitor.write_all(b"visitor-frame").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!owner.is_finished());
        stop.send_replace(true);
        timeout(Duration::from_secs(5), owner)
            .await
            .expect("upgraded copy ended on shutdown and the hop closed")
            .unwrap();
        visitor_server.abort();
    }

    fn streaming_request() -> Request<Body> {
        Request::builder()
            .uri("/stream")
            .header("host", "demo.pike.test")
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn dropping_a_forwarded_streaming_response_closes_the_hop() {
        use http_body_util::BodyExt;
        let (client, owner) = endless_owner();
        let (_keep, shutdown) = watch::channel(false);
        let response = forward_h2(
            TokioIo::new(client),
            "demo.pike.test",
            streaming_request(),
            shutdown,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        for _ in 0..3 {
            assert!(body.frame().await.unwrap().unwrap().is_data());
        }
        assert!(
            !owner.is_finished(),
            "the owner keeps streaming while the visitor reads"
        );
        // The visitor goes away: nothing else references the hop, so it closes.
        drop(body);
        timeout(Duration::from_secs(5), owner)
            .await
            .expect("hop closed after the visitor cancelled")
            .unwrap();
    }

    #[tokio::test]
    async fn frontend_shutdown_ends_a_forwarded_streaming_response_with_an_error_and_closes_the_hop(
    ) {
        use http_body_util::BodyExt;
        let (client, owner) = endless_owner();
        let (stop, shutdown) = watch::channel(false);
        let response = forward_h2(
            TokioIo::new(client),
            "demo.pike.test",
            streaming_request(),
            shutdown,
        )
        .await
        .unwrap();
        let mut body = response.into_body();
        assert!(body.frame().await.unwrap().unwrap().is_data());
        assert!(!owner.is_finished());
        stop.send_replace(true);
        // The response is cut with an error, never a clean end of stream, and
        // the hop closes even though the visitor still holds the body.
        let ended = timeout(Duration::from_secs(5), async {
            loop {
                match body.frame().await {
                    Some(Ok(_)) => {}
                    Some(Err(error)) => return Some(error.to_string()),
                    None => return None,
                }
            }
        })
        .await
        .expect("body settles after shutdown");
        assert!(
            ended
                .as_deref()
                .is_some_and(|error| error.contains("shutting down")),
            "{ended:?}"
        );
        assert!(body.frame().await.is_none());
        timeout(Duration::from_secs(5), owner)
            .await
            .expect("hop closed on shutdown")
            .unwrap();
        drop(body);
    }

    /// A scripted owner on a duplex: reads the hop request, records it and
    /// replies with the given bytes before closing.
    fn scripted_owner(
        reply: Vec<u8>,
        seen: Arc<Mutex<Vec<HopRequest>>>,
    ) -> tokio::io::DuplexStream {
        let (client, mut server) = tokio::io::duplex(4096);
        tokio::spawn(async move {
            if let Ok(request) = HopRequest::read(&mut server).await {
                seen.lock().unwrap().push(request);
            }
            let _ = server.write_all(&reply).await;
            let _ = server.shutdown().await;
        });
        client
    }

    #[tokio::test]
    async fn challenge_lookup_moves_past_a_refusing_owner_but_never_past_conflict_or_malformed_answers(
    ) {
        let frontend = frontend(&["a.internal", "b.internal", "c.internal"]);
        let host = "term.pike.test";
        let token = "Yz1-_token";
        let target = Target::hostname(Protocol::Tls, host);
        let same = "3".repeat(64);
        // a is healthy and therefore always asked first; b and c follow in order.
        let advertise = |authorities: [&str; 3]| {
            let mut table = frontend.table.lock().unwrap();
            for (index, (authority, health)) in authorities
                .iter()
                .zip(["healthy", "unknown", "unknown"])
                .enumerate()
            {
                table[index] = Some(PeerRoutes {
                    expires: Instant::now() + Duration::from_secs(60),
                    routes: vec![advertisement(&target, authority, health)],
                });
            }
        };
        let accepted = |proof: &str| {
            let mut reply = vec![ACCEPTED];
            reply.extend_from_slice(&u16::try_from(proof.len()).unwrap().to_be_bytes());
            reply.extend_from_slice(proof.as_bytes());
            reply
        };
        // `None` is an owner that cannot be reached at all.
        let lookup = |replies: Vec<Option<Vec<u8>>>| {
            let frontend = &frontend;
            let target = &target;
            async move {
                let Some(resolved) = frontend.resolve(target) else {
                    return (None, Vec::new(), Vec::new());
                };
                let request = HopRequest::Challenge(ChallengeRequest {
                    target: target.clone(),
                    authority: resolved.authority.clone(),
                    token: token.into(),
                })
                .encode()
                .unwrap();
                let seen: Arc<Mutex<Vec<HopRequest>>> = Arc::default();
                let mut asked = Vec::new();
                let mut owners = replies;
                let proof = frontend
                    .challenge_candidates(host, token, resolved.candidates, &request, |index| {
                        asked.push(index);
                        let reply = owners[index].take();
                        let seen = seen.clone();
                        async move {
                            reply
                                .map(|reply| scripted_owner(reply, seen))
                                .context("unreachable")
                        }
                    })
                    .await;
                let seen = seen.lock().unwrap().clone();
                (proof, seen, asked)
            }
        };
        let expected = HopRequest::Challenge(ChallengeRequest {
            target: target.clone(),
            authority: same.clone(),
            token: token.into(),
        });
        let proof_b = format!("{token}.thumbprint-of-owner-b");
        let proof_c = format!("{token}.thumbprint-of-owner-c");
        advertise([&same, &same, &same]);
        // Owner a has no challenge for this token; owner b holds it. The exact
        // request reaches both and b's exact key authorization is served.
        let (proof, seen, asked) = lookup(vec![
            Some(vec![REJECTED]),
            Some(accepted(&proof_b)),
            Some(accepted(&proof_c)),
        ])
        .await;
        assert_eq!(proof.as_deref(), Some(proof_b.as_str()));
        assert_eq!(asked, vec![0, 1]);
        assert_eq!(seen, vec![expected.clone(), expected.clone()]);
        // An unreachable owner is skipped like a stream candidate.
        let (proof, _, asked) =
            lookup(vec![Some(vec![REJECTED]), None, Some(accepted(&proof_c))]).await;
        assert_eq!(proof.as_deref(), Some(proof_c.as_str()));
        assert_eq!(asked, vec![0, 1, 2]);
        // Every agreeing owner refusing is a clean miss.
        let (proof, _, asked) = lookup(vec![
            Some(vec![REJECTED]),
            Some(vec![REJECTED]),
            Some(vec![REJECTED]),
        ])
        .await;
        assert!(proof.is_none());
        assert_eq!(asked, vec![0, 1, 2]);
        // Malformed or ambiguous answers fail closed without asking anyone else,
        // even though owner b would answer.
        let mut truncated = accepted(&proof_b);
        truncated.truncate(8);
        let mut oversize = vec![ACCEPTED];
        oversize.extend_from_slice(&u16::MAX.to_be_bytes());
        for malformed in [
            vec![7],
            vec![],
            oversize,
            truncated,
            accepted("other-token.thumbprint"),
            accepted(""),
            accepted(&format!("{token}.bad proof")),
        ] {
            let (proof, _, asked) = lookup(vec![
                Some(malformed.clone()),
                Some(accepted(&proof_b)),
                Some(accepted(&proof_c)),
            ])
            .await;
            assert!(proof.is_none(), "{malformed:?}");
            assert_eq!(asked, vec![0], "{malformed:?}");
        }
        // Peers that disagree about the authority are never asked at all.
        advertise([&same, &same, &"4".repeat(64)]);
        let (proof, seen, asked) = lookup(vec![
            Some(accepted(&proof_b)),
            Some(accepted(&proof_b)),
            Some(accepted(&proof_c)),
        ])
        .await;
        assert!(proof.is_none());
        assert!(seen.is_empty() && asked.is_empty());
    }
}
