use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::anyhow;
use pike_core::{
    quic::server::{InboundData, OutboundData, PikeOutboundMessage},
    types::TunnelId,
};
use tokio::{
    net::TcpStream,
    sync::{mpsc, watch, Mutex},
    task::JoinSet,
    time::timeout,
};

/// Both plain TCP and accepted TLS streams use the same bounded byte bridge,
/// including streams injected by an authenticated ingress hop.
pub use pike_server::ingress::Duplex;
pub struct RelayStream {
    pub io: Box<dyn Duplex>,
    pub source_addr: std::net::SocketAddr,
    pub prefix: Vec<u8>,
    pub permit: Option<tokio::sync::OwnedSemaphorePermit>,
    pub admission: Option<pike_server::visitor_policy::VisitorAdmission>,
}
pub trait IntoRelayStream: Send + 'static {
    fn into_relay_stream(self) -> std::io::Result<RelayStream>;
}
impl IntoRelayStream for TcpStream {
    fn into_relay_stream(self) -> std::io::Result<RelayStream> {
        Ok(RelayStream {
            source_addr: self.peer_addr()?,
            io: Box::new(self),
            prefix: vec![],
            permit: None,
            admission: None,
        })
    }
}
impl IntoRelayStream for RelayStream {
    fn into_relay_stream(self) -> std::io::Result<RelayStream> {
        Ok(self)
    }
}

use pike_server::traffic_meter::TrafficMeter;

const ENQUEUE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct TcpRelay {
    tunnel_id: TunnelId,
    input: Arc<Mutex<pike_core::byte_stream::Ingress<PikeOutboundMessage>>>,
    cancel: watch::Sender<bool>,
}
pub type TcpRelays = Arc<Mutex<HashMap<u64, TcpRelay>>>;

pub async fn route_data(
    relays: &TcpRelays,
    data: InboundData,
) -> std::result::Result<(), InboundData> {
    let route = relays.lock().await.get(&data.connection_id).cloned();
    let Some(route) = route.filter(|route| route.tunnel_id == data.tunnel_id) else {
        return Err(data);
    };
    if data.mode != pike_core::proto::StreamMode::ByteStream
        || route
            .input
            .lock()
            .await
            .feed(&data.payload, data.fin)
            .is_err()
    {
        let _ = route.cancel.send(true);
    }
    Ok(())
}

/// Remove per-session routes after their owning listener task is cancelled.
pub async fn forget_tunnel(relays: &TcpRelays, tunnel_id: TunnelId) {
    relays
        .lock()
        .await
        .retain(|_, relay| relay.tunnel_id != tunnel_id);
}

pub async fn run_listener<S: IntoRelayStream>(
    tunnel_id: TunnelId,
    mut accepted: mpsc::Receiver<S>,
    outbound: mpsc::Sender<PikeOutboundMessage>,
    relays: TcpRelays,
    meter: TrafficMeter,
    visitor: Arc<pike_server::visitor_policy::VisitorGate>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = connections.join_next(), if !connections.is_empty() => {},
            stream = accepted.recv() => {
                let Some(stream) = stream else { break; };
                if connections.len() >= 128 { continue; }
                let Ok(stream) = stream.into_relay_stream() else { continue; };
                if !visitor.allows_ip(stream.source_addr.ip()) { continue; }
                let Ok(admission) = stream.admission.clone().map_or_else(|| visitor.tls_admission(None), Ok) else { continue; };
                if let Err(error) = meter.admit() { tracing::debug!(%error, %tunnel_id, "TCP/TLS admission rejected"); continue; }
                let meter = meter.clone();
                let outbound = outbound.clone();
                let relays = relays.clone();
                connections.spawn(async move {
                    let connection_id = pike_server::proxy::connection_id_from_uuid();
                    let (cancel, cancelled) = watch::channel(false);
                    let template = OutboundData {
                        stream_id: None, tunnel_id, connection_id, source_addr: stream.source_addr,
                        payload: vec![], fin: false, streaming: true, mode: pike_core::proto::StreamMode::ByteStream,
                    };
                    let writer = pike_core::http_wire::Writer::new(outbound.clone(), PikeOutboundMessage::Data(template.clone()));
                    let (input, forwarding) = pike_core::byte_stream::channel(writer);
                    relays.lock().await.insert(connection_id, TcpRelay { tunnel_id, input: Arc::new(Mutex::new(input)), cancel });
                    // Empty opening connects server-first origins before any bytes are sent.
                    let forwarding = async {
                        meter.opened().await?;
                        outbound.send(PikeOutboundMessage::Data(template)).await.map_err(|_| anyhow!("transport closed"))?;
                        let RelayStream { io, prefix, permit: _permit, .. } = stream;
                        forwarding.forward(io, &prefix, cancelled, |direction, length| meter.bytes(direction, length)).await
                    };
                    let result = tokio::select! {
                        biased;
                        () = admission.cancelled() => Err(anyhow!("visitor authorization ended")),
                        result = forwarding => result,
                    };
                    if let Err(error) = result { tracing::debug!(%error, %tunnel_id, connection_id, "TCP/TLS relay connection ended"); }
                    relays.lock().await.remove(&connection_id);
                });
            }
        }
    }
    {
        let routes = relays.lock().await;
        for route in routes.values().filter(|route| route.tunnel_id == tunnel_id) {
            let _ = route.cancel.send(true);
        }
    }
    let _ = timeout(ENQUEUE_TIMEOUT + Duration::from_secs(1), async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    forget_tunnel(&relays, tunnel_id).await;
}
