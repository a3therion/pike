use anyhow::{anyhow, bail, Result};
use pike_core::quic::client::{LocalData, PikeConnection, ServerData};
use pike_core::types::{TunnelConfig, TunnelId};
use pike_core::{byte_stream, http_wire::Writer, proto::StreamMode};
use std::collections::{HashMap, HashSet};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};
use tracing::info;

const ENQUEUE_TIMEOUT: Duration = Duration::from_secs(2);

struct LocalRelay {
    input: byte_stream::Ingress<LocalData>,
    stream_id: u64,
    cancel: watch::Sender<bool>,
}

pub struct TcpTunnel {
    config: TunnelConfig,
    local_port: u16,
    local_host: String,
    remote_port: Option<u16>,
    connection: PikeConnection,
    tunnel_id: Option<TunnelId>,
    public_url: Option<String>,
}

impl TcpTunnel {
    pub fn new(
        config: TunnelConfig,
        port: u16,
        host: String,
        remote_port: Option<u16>,
        connection: PikeConnection,
    ) -> Self {
        Self {
            config,
            local_port: port,
            local_host: host,
            remote_port,
            connection,
            tunnel_id: None,
            public_url: None,
        }
    }

    pub fn public_url(&self) -> Option<&str> {
        self.public_url.as_deref()
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.connection.unregister_tunnel(self.config.id).await?;
        self.connection.close().await
    }

    pub async fn register(&mut self) -> Result<u16> {
        let (tunnel_id, registration_rx) = self
            .connection
            .request_tunnel_registration(self.config.clone())
            .await?;
        self.tunnel_id = Some(tunnel_id);
        let registration = match timeout(Duration::from_secs(10), registration_rx).await {
            Ok(Ok(registration)) => registration,
            Ok(Err(_)) => bail!("registration confirmation channel closed"),
            Err(_) => bail!("registration timed out after 10s"),
        };
        let assigned_port = registration
            .remote_port
            .filter(|port| *port > 0)
            .ok_or_else(|| anyhow!("relay did not allocate a TCP port"))?;
        if self
            .remote_port
            .is_some_and(|requested| requested != assigned_port)
        {
            bail!("relay allocated a different TCP port than requested");
        }
        self.public_url = Some(registration.public_url);
        info!(%tunnel_id, remote_port = assigned_port, "TCP tunnel registration confirmed");
        Ok(assigned_port)
    }

    pub async fn run(&mut self) -> Result<()> {
        let tunnel_id = self.tunnel_id.unwrap_or(self.config.id);
        let mut relays: HashMap<u64, LocalRelay> = HashMap::new();
        let mut received_fin = HashSet::new();
        let mut closed = HashSet::new();
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                completed = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Ok(id)) = completed {
                        relays.remove(&id);
                        if !received_fin.remove(&id) { closed.insert(id); }
                    }
                }
                msg = self.connection.data_rx.recv() => {
                    let Some(msg) = msg else { break; };
                    if msg.tunnel_id != tunnel_id || !msg.streaming || msg.mode != StreamMode::ByteStream { bail!("invalid TCP stream identity"); }
                    let id = msg.connection_id;
                    // Late bytes after a failed local socket must never open a
                    // second local connection with the same stream identity.
                    if closed.contains(&id) {
                        if msg.fin { closed.remove(&id); }
                        continue;
                    }
                    if msg.fin { received_fin.insert(id); }
                    if let Some(route) = relays.get_mut(&id) {
                        if msg.stream_id != route.stream_id || route.input.feed(&msg.payload, msg.fin).is_err() {
                            let _ = route.cancel.send(true);
                        }
                        continue;
                    }
                    if relays.len() + closed.len() >= 256 {
                        bail!("too many unfinished TCP streams");
                    }
                    let data_tx = self.connection.data_tx.clone();
                    if tasks.len() >= 128 {
                        let writer = Writer::new(data_tx, response(&msg, vec![], false));
                        let _ = timeout(ENQUEUE_TIMEOUT, writer.send(pike_core::http_wire::HttpFrame::Reset("TCP stream limit reached".into()), true)).await;
                        if !received_fin.remove(&id) { closed.insert(id); }
                        continue;
                    }
                    let address = format!("{}:{}", if self.local_host.contains(':') { format!("[{}]", self.local_host) } else { self.local_host.clone() }, self.local_port);
                    let (cancel, cancelled) = watch::channel(false);
                    let (mut input, stream) = byte_stream::channel(Writer::new(data_tx, response(&msg, vec![], false)));
                    if input.feed(&msg.payload, msg.fin).is_err() {
                        let _ = cancel.send(true);
                    }
                    relays.insert(id, LocalRelay { input, stream_id: msg.stream_id, cancel });
                    tasks.spawn(async move {
                        let result = if let Ok(Ok(socket)) = timeout(Duration::from_secs(5), TcpStream::connect(&address)).await {
                            stream.forward(socket, &[], cancelled, |_, _| std::future::ready(Ok(()))).await
                        } else {
                            stream.reset("origin connection failed").await;
                            Err(anyhow!("origin connection failed"))
                        };
                        if let Err(error) = result { tracing::debug!(%error, connection_id = id, "local TCP connection ended"); }
                        id
                    });
                }
            }
        }
        for route in relays.values() {
            let _ = route.cancel.send(true);
        }
        let _ = timeout(ENQUEUE_TIMEOUT + Duration::from_secs(1), async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        Ok(())
    }
}

fn response(msg: &ServerData, payload: Vec<u8>, fin: bool) -> LocalData {
    LocalData {
        stream_id: Some(msg.stream_id),
        tunnel_id: msg.tunnel_id,
        connection_id: msg.connection_id,
        source_addr: msg.source_addr,
        payload,
        fin,
        streaming: true,
        mode: pike_core::proto::StreamMode::ByteStream,
    }
}
