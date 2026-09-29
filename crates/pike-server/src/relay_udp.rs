use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{Arc, OnceLock},
    time::Duration,
};

use anyhow::{ensure, Result};
use pike_core::{
    datagram::{self, Input, Reply, Source, MAX_PACKET_BYTES, MAX_PEERS, QUEUE_PACKETS},
    http_wire::Writer,
    proto::StreamMode,
    quic::server::{InboundData, OutboundData, PikeOutboundMessage},
    types::TunnelId,
};
use pike_server::traffic_meter::TrafficMeter;
use tokio::{
    io::AsyncReadExt,
    net::UdpSocket,
    sync::{mpsc, watch, Mutex, Semaphore},
    task::JoinSet,
};

/// One visitor association arriving over an authenticated ingress hop. Packets
/// travel length-framed in both directions; replies return through this stream
/// only, so the frontend pins them to the original visitor address.
pub struct Injected {
    pub io: Box<dyn super::relay_tcp::Duplex>,
    pub peer: SocketAddr,
    pub permit: tokio::sync::OwnedSemaphorePermit,
}
const INJECT_QUEUE: usize = 8;

#[derive(Clone)]
pub struct Route {
    tunnel_id: TunnelId,
    peer: SocketAddr,
    stream_id: Arc<OnceLock<u64>>,
    sender: datagram::Sender,
    cancel: watch::Sender<bool>,
}
pub type Routes = Arc<Mutex<HashMap<u64, Route>>>;

pub async fn route(routes: &Routes, data: InboundData) -> Result<()> {
    let route = routes.lock().await.get(&data.connection_id).cloned();
    let Some(route) = route else {
        return Ok(());
    }; // Late data for an expired peer.
    ensure!(
        data.tunnel_id == route.tunnel_id
            && data.source_addr == route.peer
            && data.streaming
            && data.mode == StreamMode::Datagram
            && *route.stream_id.get_or_init(|| data.stream_id) == data.stream_id,
        "UDP stream identity changed"
    );
    let input = Input::new(data.payload, data.fin);
    if let Err(input) = route.sender.try_send(input) {
        tokio::task::yield_now().await;
        if route.sender.try_send(input).is_err() {
            let _ = route.cancel.send(true);
        }
    }
    Ok(())
}

pub async fn forget(routes: &Routes, id: TunnelId) {
    routes.lock().await.retain(|_, route| {
        if route.tunnel_id == id {
            route.cancel.send_replace(true);
            false
        } else {
            true
        }
    });
}

pub async fn bind(bind_ip: std::net::Ipv4Addr, preferred: Option<u16>) -> Result<UdpSocket> {
    if let Some(port) = preferred {
        ensure!(
            (10_000..=65_000).contains(&port),
            "UDP port must be between 10000 and 65000"
        );
        let socket = UdpSocket::bind((bind_ip, port)).await?;
        datagram::configure_socket(&socket)?;
        return Ok(socket);
    }
    // The OS owns port exclusivity, including other relay processes. TCP and
    // UDP may share a number because they are separate protocols.
    let start = (uuid::Uuid::new_v4().as_u128() % 55_001) as u16;
    for offset in 0..55_001_u32 {
        let port = 10_000 + ((u32::from(start) + offset) % 55_001) as u16;
        match UdpSocket::bind((bind_ip, port)).await {
            Ok(socket) => {
                datagram::configure_socket(&socket)?;
                return Ok(socket);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => return Err(error.into()),
        }
    }
    anyhow::bail!("no UDP ports available")
}

/// Transport resources belong to the connector, while the UDP socket and peer
/// table belong to the saved profile. Selecting a member never moves a packet
/// from an existing association to another connector.
pub struct Connector {
    pub id: pike_server::connection::ConnectionId,
    pub outbound: mpsc::Sender<PikeOutboundMessage>,
    pub routes: Routes,
    pub budget: Arc<Semaphore>,
    pub meter: TrafficMeter,
}

struct Member {
    connector: Connector,
    revoked: watch::Sender<bool>,
}

#[derive(Default)]
struct Members {
    entries: std::sync::Mutex<Vec<Arc<Member>>>,
    next: std::sync::atomic::AtomicUsize,
}

impl Members {
    fn add(&self, connector: Connector) -> Result<()> {
        let mut entries = self.entries.lock().unwrap();
        ensure!(
            entries.len() < pike_server::registry::MAX_CONNECTORS_PER_TUNNEL,
            "connector limit reached"
        );
        ensure!(
            entries
                .iter()
                .all(|entry| entry.connector.id != connector.id),
            "connector already registered"
        );
        let (revoked, _) = watch::channel(false);
        entries.push(Arc::new(Member { connector, revoked }));
        Ok(())
    }

    fn remove(&self, id: pike_server::connection::ConnectionId) {
        self.entries.lock().unwrap().retain(|member| {
            if member.connector.id == id {
                member.revoked.send_replace(true);
                false
            } else {
                true
            }
        });
    }

    fn select(&self) -> Option<(Arc<Member>, tokio::sync::OwnedSemaphorePermit)> {
        let entries = self.entries.lock().unwrap();
        if entries.is_empty() {
            return None;
        }
        let start = self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % entries.len();
        for offset in 0..entries.len() {
            let member = &entries[(start + offset) % entries.len()];
            if member.connector.outbound.is_closed() {
                continue;
            }
            if let Ok(permit) = member.connector.budget.clone().try_acquire_owned() {
                return Some((member.clone(), permit));
            }
        }
        None
    }
}

pub struct Endpoint {
    pub port: u16,
    members: Arc<Members>,
    injected: mpsc::Sender<Injected>,
    shutdown: watch::Sender<bool>,
    task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Endpoint {
    pub async fn bind(
        tunnel_id: TunnelId,
        bind_ip: std::net::Ipv4Addr,
        preferred: Option<u16>,
        idle: Duration,
        visitor: Arc<pike_server::visitor_policy::VisitorGate>,
    ) -> Result<Self> {
        let socket = bind(bind_ip, preferred).await?;
        let port = socket.local_addr()?.port();
        let members = Arc::new(Members::default());
        let (shutdown, stopped) = watch::channel(false);
        let (injected, injected_rx) = mpsc::channel(INJECT_QUEUE);
        let task = tokio::spawn(
            Listener {
                tunnel_id,
                socket,
                members: members.clone(),
                idle,
                visitor,
                stopped,
                injected: injected_rx,
            }
            .run(),
        );
        Ok(Self {
            port,
            members,
            injected,
            shutdown,
            task: std::sync::Mutex::new(Some(task)),
        })
    }

    /// Bounded admission for hop associations; the acceptor reserves a slot
    /// before it writes the accept byte.
    pub fn injector(&self) -> mpsc::Sender<Injected> {
        self.injected.clone()
    }

    pub fn add(&self, connector: Connector) -> Result<()> {
        self.members.add(connector)
    }
    pub fn remove(&self, id: pike_server::connection::ConnectionId) {
        self.members.remove(id);
    }

    /// Wait for socket ownership to end before admitting a replacement on the
    /// same port. UDP has no `TIME_WAIT`, but abort alone is not a join barrier.
    pub async fn close(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            self.shutdown.send_replace(true);
            let _ = task.await;
        }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        if let Some(task) = self.task.get_mut().unwrap().take() {
            task.abort();
        }
    }
}

struct Listener {
    tunnel_id: TunnelId,
    socket: UdpSocket,
    members: Arc<Members>,
    idle: Duration,
    visitor: Arc<pike_server::visitor_policy::VisitorGate>,
    stopped: watch::Receiver<bool>,
    injected: mpsc::Receiver<Injected>,
}

impl Listener {
    async fn run(mut self) {
        let socket = Arc::new(self.socket);
        let mut peers: HashMap<SocketAddr, (u64, mpsc::Sender<Vec<u8>>)> = HashMap::new();
        // Hop associations share the peer cap but never the socket demultiplexer.
        let mut hops: HashSet<u64> = HashSet::new();
        let mut tasks = JoinSet::new();
        let mut buffer = vec![0; 65_535];
        loop {
            tokio::select! {
                biased;
                () = async { let _ = self.stopped.wait_for(|closed| *closed).await; } => break,
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Ok((peer, id, routes, hop))) = result {
                        if hop { hops.remove(&id); }
                        else if peers.get(&peer).is_some_and(|(current, _)| *current == id) { peers.remove(&peer); }
                        let routes: Routes = routes;
                        routes.lock().await.remove(&id);
                    }
                }
                injected = self.injected.recv() => {
                    // The endpoint owning the sender is gone; its close() already fired.
                    let Some(injected) = injected else { break; };
                    // The hop header carries the original visitor address; the
                    // same active gate and IP rules apply as for a direct packet.
                    if !self.visitor.allows_ip(injected.peer.ip()) { continue; }
                    if peers.len() + hops.len() >= MAX_PEERS { continue; }
                    let Some((member, permit)) = self.members.select() else { continue; };
                    if member.connector.meter.admit().is_err() { continue; }
                    let id = pike_server::proxy::connection_id_from_uuid();
                    let peer = injected.peer;
                    let (sender, input) = datagram::channel();
                    let (cancel, cancelled) = watch::channel(false);
                    {
                        let mut routes = member.connector.routes.lock().await;
                        if *member.revoked.borrow() { continue; }
                        routes.insert(id, Route {
                            tunnel_id: self.tunnel_id, peer, stream_id: Arc::default(), sender, cancel: cancel.clone(),
                        });
                    }
                    hops.insert(id);
                    let template = PikeOutboundMessage::Data(OutboundData {
                        stream_id: None, tunnel_id: self.tunnel_id, connection_id: id, source_addr: peer,
                        payload: vec![], fin: false, streaming: true, mode: StreamMode::Datagram,
                    });
                    let writer = Writer::new(member.connector.outbound.clone(), template);
                    let idle = self.idle;
                    let visitor = self.visitor.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let _hop_permit = injected.permit;
                        let mut revoked = member.revoked.subscribe();
                        let (mut reader, reply) = tokio::io::split(injected.io);
                        let (packets, packet_rx) = mpsc::channel(QUEUE_PACKETS);
                        let pump = async move {
                            let packets = packets;
                            let mut decoder = datagram::Packets::default();
                            let mut buffer = vec![0; 65_536];
                            loop {
                                let count = reader.read(&mut buffer).await?;
                                if count == 0 { break; }
                                for packet in decoder.feed(&buffer[..count])? {
                                    // Drop complete packets under pressure, never fragments.
                                    let _ = packets.try_send(packet);
                                }
                            }
                            decoder.finish()
                        };
                        let forwarding = datagram::forward(writer, input, Source::Public(packet_rx), Reply::Stream(Box::pin(reply)), idle, cancelled,
                            |direction, size| member.connector.meter.packet(direction, size));
                        tokio::pin!(forwarding);
                        tokio::pin!(pump);
                        let result = tokio::select! {
                            biased;
                            () = visitor.cancelled() => { cancel.send_replace(true); forwarding.await },
                            () = async { let _ = revoked.wait_for(|closed| *closed).await; } => { cancel.send_replace(true); forwarding.await },
                            result = &mut forwarding => result,
                            // Hop EOF or bad framing drops the packet source; forwarding then ends itself.
                            _ = &mut pump => forwarding.await,
                        };
                        if let Err(error) = result { tracing::debug!(%error, %peer, "ingress UDP association ended"); }
                        (peer, id, member.connector.routes.clone(), true)
                    });
                }
                received = socket.recv_from(&mut buffer) => {
                    let Ok((size, peer)) = received else { break; };
                    if !self.visitor.allows_ip(peer.ip()) || size > MAX_PACKET_BYTES { continue; }
                    if let Some((_, sender)) = peers.get(&peer) {
                        // Drop complete UDP packets under pressure, never fragments.
                        let _ = sender.try_send(buffer[..size].to_vec());
                        continue;
                    }
                    if peers.len() + hops.len() >= MAX_PEERS { continue; }
                    let Some((member, permit)) = self.members.select() else { continue; };
                    if member.connector.meter.admit().is_err() { continue; }
                    let id = pike_server::proxy::connection_id_from_uuid();
                    let (sender, input) = datagram::channel();
                    let (cancel, cancelled) = watch::channel(false);
                    {
                        let mut routes = member.connector.routes.lock().await;
                        // Removal can race the route-map await. Do not insert a
                        // stale route after that session's final forget pass.
                        if *member.revoked.borrow() { continue; }
                        routes.insert(id, Route {
                            tunnel_id: self.tunnel_id, peer, stream_id: Arc::default(), sender, cancel: cancel.clone(),
                        });
                    }
                    let (packets, packet_rx) = mpsc::channel(QUEUE_PACKETS);
                    let _ = packets.try_send(buffer[..size].to_vec());
                    peers.insert(peer, (id, packets));
                    let template = PikeOutboundMessage::Data(OutboundData {
                        stream_id: None, tunnel_id: self.tunnel_id, connection_id: id, source_addr: peer,
                        payload: vec![], fin: false, streaming: true, mode: StreamMode::Datagram,
                    });
                    let writer = Writer::new(member.connector.outbound.clone(), template);
                    let destination = Reply::Peer(socket.clone(), peer);
                    let idle = self.idle;
                    let visitor = self.visitor.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        let mut revoked = member.revoked.subscribe();
                        let forwarding = datagram::forward(writer, input, Source::Public(packet_rx), destination, idle, cancelled,
                            |direction, size| member.connector.meter.packet(direction, size));
                        tokio::pin!(forwarding);
                        let result = tokio::select! {
                            biased;
                            () = visitor.cancelled() => { cancel.send_replace(true); forwarding.await },
                            () = async { let _ = revoked.wait_for(|closed| *closed).await; } => { cancel.send_replace(true); forwarding.await },
                            result = &mut forwarding => result,
                        };
                        if let Err(error) = result { tracing::debug!(%error, %peer, "UDP peer ended"); }
                        (peer, id, member.connector.routes.clone(), false)
                    });
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connector(budget: usize) -> (Connector, mpsc::Receiver<PikeOutboundMessage>) {
        let (outbound, incoming) = mpsc::channel(4);
        let tunnel = TunnelId::new();
        (
            Connector {
                id: uuid::Uuid::new_v4(),
                outbound,
                routes: Arc::default(),
                budget: Arc::new(Semaphore::new(budget)),
                meter: TrafficMeter::new(
                    Arc::new(pike_server::registry::ClientRegistry::new()),
                    tunnel,
                    "owner".into(),
                    tunnel.to_string(),
                    None,
                ),
            },
            incoming,
        )
    }

    #[tokio::test]
    async fn member_selection_balances_peers_and_skips_exhausted_or_closed_connectors() {
        let members = Members::default();
        let (first, first_rx) = connector(1);
        let first_id = first.id;
        let (second, second_rx) = connector(1);
        let second_id = second.id;
        members.add(first).unwrap();
        members.add(second).unwrap();
        let (a, a_permit) = members.select().unwrap();
        let (b, b_permit) = members.select().unwrap();
        assert_eq!(a.connector.id, first_id);
        assert_eq!(b.connector.id, second_id);
        assert!(members.select().is_none());
        drop(b_permit);
        assert_eq!(members.select().unwrap().0.connector.id, second_id);
        members.remove(first_id);
        assert!(*a.revoked.borrow());
        assert!(!*b.revoked.borrow());
        members.remove(first_id);
        drop(a_permit);
        drop(first_rx);
        drop(second_rx);
        assert!(members.select().is_none());
    }

    #[test]
    fn member_admission_is_bounded_and_duplicate_cleanup_cannot_revoke_a_replacement() {
        let members = Members::default();
        let mut receivers = vec![];
        let mut ids = vec![];
        for _ in 0..pike_server::registry::MAX_CONNECTORS_PER_TUNNEL {
            let (connector, receiver) = connector(1);
            ids.push(connector.id);
            receivers.push(receiver);
            members.add(connector).unwrap();
        }
        assert!(members.add(connector(1).0).is_err());
        members.remove(ids[0]);
        let (replacement, receiver) = connector(1);
        let replacement_id = replacement.id;
        receivers.push(receiver);
        members.add(replacement).unwrap();
        members.remove(ids[0]);
        let entries = members.entries.lock().unwrap();
        assert_eq!(entries.len(), 8);
        assert!(!*entries
            .iter()
            .find(|entry| entry.connector.id == replacement_id)
            .unwrap()
            .revoked
            .borrow());
    }

    #[tokio::test]
    async fn injected_associations_pass_the_same_ip_rules_as_direct_packets() {
        use pike_server::visitor_policy::{Policy, VisitorGate};
        let visitor = VisitorGate::pending();
        visitor
            .activate(
                Policy {
                    deny_cidrs: vec!["203.0.113.0/24".into()],
                    ..Policy::default()
                },
                "udp",
            )
            .unwrap();
        let tunnel = TunnelId::new();
        let endpoint = Endpoint::bind(
            tunnel,
            std::net::Ipv4Addr::LOCALHOST,
            None,
            Duration::from_secs(5),
            visitor,
        )
        .await
        .unwrap();
        let (member, mut outbound) = connector(4);
        let routes = member.routes.clone();
        endpoint.add(member).unwrap();
        let budget = Arc::new(Semaphore::new(2));
        let inject = |peer: SocketAddr| {
            let (hop, remote) = tokio::io::duplex(65_536);
            let injected = Injected {
                io: Box::new(hop),
                peer,
                permit: budget.clone().try_acquire_owned().unwrap(),
            };
            (injected, remote)
        };
        let (denied, _denied_remote) = inject("203.0.113.9:4000".parse().unwrap());
        endpoint.injector().send(denied).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            outbound.try_recv().is_err(),
            "denied visitor must not open an association"
        );
        assert!(routes.lock().await.is_empty());
        let allowed_peer: SocketAddr = "198.51.100.7:4001".parse().unwrap();
        let (allowed, mut remote) = inject(allowed_peer);
        endpoint.injector().send(allowed).await.unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut remote, &datagram::frame(b"hello").unwrap())
            .await
            .unwrap();
        let opened = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(PikeOutboundMessage::Data(data)) = outbound.recv().await {
                    if data.mode == StreamMode::Datagram && !data.fin {
                        return data;
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(opened.source_addr, allowed_peer);
        assert_eq!(opened.tunnel_id, tunnel);
        assert_eq!(routes.lock().await.len(), 1);
        endpoint.close().await;
    }

    #[tokio::test]
    async fn validates_peer_identity_and_cancels_only_saturated_route() {
        let routes: Routes = Arc::default();
        let (sender, mut input) = datagram::channel();
        let (cancel, cancelled) = watch::channel(false);
        let data = InboundData {
            stream_id: 17,
            tunnel_id: TunnelId::new(),
            connection_id: 42,
            source_addr: "127.0.0.1:1234".parse().unwrap(),
            payload: vec![1],
            fin: false,
            streaming: true,
            mode: StreamMode::Datagram,
        };
        routes.lock().await.insert(
            42,
            Route {
                tunnel_id: data.tunnel_id,
                peer: data.source_addr,
                stream_id: Arc::default(),
                sender,
                cancel,
            },
        );
        route(&routes, data.clone()).await.unwrap();
        assert_eq!(input.recv().await.unwrap().payload, vec![1]);
        for wrong in [
            InboundData {
                source_addr: "127.0.0.1:5678".parse().unwrap(),
                ..data.clone()
            },
            InboundData {
                tunnel_id: TunnelId::new(),
                ..data.clone()
            },
            InboundData {
                stream_id: 18,
                ..data.clone()
            },
            InboundData {
                mode: StreamMode::Raw,
                ..data.clone()
            },
        ] {
            assert!(route(&routes, wrong).await.is_err());
        }
        assert!(input.try_recv().is_err());
        for _ in 0..65 {
            route(&routes, data.clone()).await.unwrap();
        }
        assert!(*cancelled.borrow());
        forget(&routes, data.tunnel_id).await;
        assert!(routes.lock().await.is_empty());
        route(&routes, data).await.unwrap(); // Late data cannot recreate a route.
    }
}
