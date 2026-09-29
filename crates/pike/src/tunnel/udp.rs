use anyhow::{bail, ensure, Result};
use pike_core::{
    datagram::{self, Input, Source},
    http_wire::Writer,
    proto::StreamMode,
    quic::client::{LocalData, PikeConnection, ServerData},
    types::{TunnelConfig, TunnelType},
};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::{net::UdpSocket, sync::watch, task::JoinSet, time::timeout};

struct Route {
    stream: u64,
    peer: std::net::SocketAddr,
    sender: datagram::Sender,
    cancel: watch::Sender<bool>,
}

pub struct UdpTunnel {
    config: TunnelConfig,
    connection: PikeConnection,
}

impl UdpTunnel {
    pub fn new(config: TunnelConfig, connection: PikeConnection) -> Self {
        Self { config, connection }
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.connection.unregister_tunnel(self.config.id).await?;
        self.connection.close().await
    }

    pub async fn register(&mut self) -> Result<u16> {
        let (_, receiver) = self
            .connection
            .request_tunnel_registration(self.config.clone())
            .await?;
        let registration = timeout(Duration::from_secs(10), receiver).await??;
        let port = registration
            .remote_port
            .ok_or_else(|| anyhow::anyhow!("relay did not allocate a UDP port"))?;
        ensure!((10_000..=65_000).contains(&port), "invalid relay UDP port");
        if let TunnelType::Udp {
            remote_port: Some(requested),
            ..
        } = self.config.tunnel_type
        {
            ensure!(
                requested == port,
                "relay allocated a different UDP port than requested"
            );
        }
        Ok(port)
    }

    pub async fn run(&mut self) -> Result<()> {
        let TunnelType::Udp {
            idle_timeout_secs, ..
        } = self.config.tunnel_type
        else {
            bail!("not a UDP tunnel")
        };
        let mut routes: HashMap<u64, Route> = HashMap::new();
        let mut closed = HashSet::new();
        let mut received_fin = HashSet::new();
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Ok(id)) = result {
                        routes.remove(&id);
                        if !received_fin.remove(&id) { closed.insert(id); }
                    }
                }
                msg = self.connection.data_rx.recv() => {
                    let Some(msg) = msg else { break; };
                    ensure!(msg.tunnel_id == self.config.id && msg.mode == StreamMode::Datagram && msg.streaming,
                        "invalid UDP stream identity");
                    let id = msg.connection_id;
                    if closed.contains(&id) {
                        if msg.fin { closed.remove(&id); }
                        continue;
                    }
                    if msg.fin { received_fin.insert(id); }
                    if let Some(route) = routes.get(&id) {
                        ensure!(msg.stream_id == route.stream && msg.source_addr == route.peer, "UDP peer identity changed");
                        let input = Input::new(msg.payload, msg.fin);
                        if let Err(input) = route.sender.try_send(input) {
                            tokio::task::yield_now().await;
                            if route.sender.try_send(input).is_err() { let _ = route.cancel.send(true); }
                        }
                        continue;
                    }
                    ensure!(routes.len() + closed.len() < 256, "too many unfinished UDP peers");
                    ensure!(tasks.len() < 64, "too many active UDP peers");
                    let (sender, input) = datagram::channel();
                    let (cancel, cancelled) = watch::channel(false);
                    routes.insert(id, Route { stream: msg.stream_id, peer: msg.source_addr, sender: sender.clone(), cancel });
                    sender.try_send(Input::new(msg.payload.clone(), msg.fin)).map_err(|_| anyhow::anyhow!("UDP opening exceeds queue budget"))?;
                    let writer = Writer::new(self.connection.data_tx.clone(), response(&msg));
                    let address = self.config.local_addr;
                    tasks.spawn(async move {
                        let result = async {
                            let bind = if address.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
                            let socket = Arc::new(UdpSocket::bind(bind).await?);
                            datagram::configure_socket(&socket)?;
                            socket.connect(address).await?;
                            datagram::forward(writer.clone(), input, Source::Connected(socket.clone()), datagram::Reply::Connected(socket),
                                Duration::from_secs(u64::from(idle_timeout_secs)), cancelled, |_, _| std::future::ready(Ok(()))).await
                        }.await;
                        if let Err(error) = result {
                            tracing::debug!(%error, "local UDP peer ended");
                            let _ = timeout(Duration::from_secs(2), writer.send(pike_core::http_wire::HttpFrame::End, true)).await;
                        }
                        id
                    });
                }
            }
        }
        // JoinSet cancellation drops every origin socket when the transport ends.
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

fn response(msg: &ServerData) -> LocalData {
    LocalData {
        stream_id: Some(msg.stream_id),
        tunnel_id: msg.tunnel_id,
        connection_id: msg.connection_id,
        source_addr: msg.source_addr,
        payload: vec![],
        fin: false,
        streaming: true,
        mode: StreamMode::Datagram,
    }
}
