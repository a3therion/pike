//! Shared, bounded SNI listener. Private keys are selected from operator-owned
//! configuration; tunnel owners can select a mode but cannot supply relay keys.
//! A hostname owned by another relay leaves after the ClientHello peek with its
//! handshake intact; a hostname arriving over the ingress hop is admitted here
//! with the same checks as a direct connection, bound to the expected gate.
use super::relay_tcp::{Duplex, RelayStream};
use anyhow::{anyhow, ensure, Context, Result};
use pike_core::types::{TlsMode, TunnelId};
use pike_server::{
    certificates::Certificates,
    config::PublicTlsConfig,
    ingress::{frontend::TlsForward, Frontend},
    ingress_directory::{Protocol, Target},
    visitor_policy::VisitorGate,
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{mpsc, watch, OwnedSemaphorePermit, RwLock, Semaphore},
    task::{JoinHandle, JoinSet},
    time::timeout,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONNECTIONS: usize = 256;

#[derive(Clone)]
struct Route {
    tunnel_id: TunnelId,
    mode: TlsMode,
    owner: String,
    sender: mpsc::Sender<RelayStream>,
    visitor: Arc<VisitorGate>,
    domain: Option<Arc<pike_server::domain_grants::DomainGrant>>,
}
type Routes = Arc<RwLock<HashMap<String, Route>>>;

pub struct TlsEndpoints {
    pub address: SocketAddr,
    routes: Routes,
    certificates: Arc<Certificates>,
    frontend: Option<Arc<Frontend>>,
    task: JoinHandle<()>,
}
impl Drop for TlsEndpoints {
    fn drop(&mut self) {
        self.task.abort();
    }
}

enum Outcome {
    Served,
    Forward(TlsForward, OwnedSemaphorePermit),
}

/// One accepted stream: SNI, route, mode-specific handshake and a final
/// route-identity recheck before the stream reaches a connector. `expected`
/// binds an ingress-injected stream to the hostname and gate the hop acceptor
/// verified; such streams are never forwarded again.
async fn admit(
    routes: Routes,
    certificates: Arc<Certificates>,
    frontend: Option<Arc<Frontend>>,
    socket: Box<dyn Duplex>,
    source_addr: SocketAddr,
    permit: OwnedSemaphorePermit,
    expected: Option<(String, Arc<VisitorGate>)>,
) {
    let result = timeout(HANDSHAKE_TIMEOUT, async {
        let (socket, accepted, prefix) = pike_server::tls_material::read_hello(socket).await?;
        let name = accepted
            .client_hello()
            .server_name()
            .context("SNI is required")?
            .to_ascii_lowercase();
        if let Some((host, _)) = &expected {
            ensure!(name == *host, "TLS SNI differs from the ingress hop target");
        }
        let route = routes.read().await.get(&name).cloned();
        let Some(route) = route else {
            if let Some(frontend) = frontend.as_ref().filter(|_| expected.is_none()) {
                let target = Target::hostname(Protocol::Tls, &name);
                if frontend.resolve(&target).is_some() {
                    let forward = frontend
                        .forward_tls(&target, socket, prefix, source_addr)
                        .await?;
                    return Ok(Outcome::Forward(forward, permit));
                }
            }
            anyhow::bail!("unknown TLS hostname");
        };
        if let Some((_, gate)) = &expected {
            ensure!(
                Arc::ptr_eq(&route.visitor, gate),
                "TLS route authority differs from the ingress hop"
            );
        }
        ensure!(
            route.domain.as_ref().is_none_or(|grant| grant.is_active()),
            "TLS hostname ownership expired"
        );
        ensure!(
            route.visitor.allows_ip(source_addr.ip()),
            "TLS visitor IP denied"
        );
        let (io, prefix, identity): (Box<dyn Duplex>, Vec<u8>, _) = match route.mode {
            TlsMode::Passthrough => (socket, prefix, None),
            TlsMode::Terminate => {
                let config = certificates
                    .server_config(
                        &name,
                        &route.owner,
                        &route.visitor,
                        route.visitor.tls_verifier()?,
                        false,
                    )
                    .await?;
                let stream = tokio_rustls::server::StartHandshake::from_parts(accepted, socket)
                    .into_stream(config)
                    .await?;
                let identity = route
                    .visitor
                    .tls_identity(source_addr.ip(), stream.get_ref().1.peer_certificates())?;
                (Box::new(stream), vec![], identity)
            }
        };
        // Never enqueue onto a replacement/disabled route after a slow handshake.
        let current = routes.read().await;
        ensure!(
            current
                .get(&name)
                .is_some_and(|current| current.tunnel_id == route.tunnel_id
                    && current.sender.same_channel(&route.sender)),
            "TLS endpoint changed during handshake"
        );
        let admission = route
            .visitor
            .tls_admission(identity.as_ref())
            .and_then(|admission| admission.with_domain(route.domain.clone()))
            .map_err(|_| anyhow!("TLS visitor admission denied"))?;
        route
            .sender
            .try_send(RelayStream {
                io,
                source_addr,
                prefix,
                permit: Some(permit),
                admission: Some(admission),
            })
            .map_err(|_| anyhow!("TLS endpoint is busy or closed"))?;
        Ok::<_, anyhow::Error>(Outcome::Served)
    })
    .await;
    match result {
        Ok(Ok(Outcome::Served)) => {}
        Ok(Ok(Outcome::Forward(forward, permit))) => {
            let _permit = permit;
            let shutdown = frontend.as_ref().map_or_else(
                || watch::channel(false).1,
                |frontend| frontend.shutdown_signal(),
            );
            forward.pipe(shutdown).await;
        }
        Ok(Err(error)) => tracing::debug!(%error, %source_addr, "public TLS connection rejected"),
        Err(_) => tracing::debug!(%source_addr, "public TLS handshake timed out"),
    }
}

impl TlsEndpoints {
    pub async fn bind(
        config: &PublicTlsConfig,
        certificates: Arc<Certificates>,
        frontend: Option<Arc<Frontend>>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<Arc<Self>> {
        let listener = TcpListener::bind(config.bind_addr)
            .await
            .context("bind public TLS listener")?;
        let address = listener.local_addr()?;
        let routes = Routes::default();
        let routing = routes.clone();
        let managed = certificates.clone();
        let forwarding = frontend.clone();
        let task = tokio::spawn(async move {
            let budget = Arc::new(Semaphore::new(MAX_CONNECTIONS));
            let mut handshakes = JoinSet::new();
            loop {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    _ = handshakes.join_next(), if !handshakes.is_empty() => {},
                    accepted = listener.accept() => {
                        let Ok((socket, source_addr)) = accepted else { break; };
                        let Ok(permit) = budget.clone().try_acquire_owned() else { continue; };
                        handshakes.spawn(admit(routing.clone(), managed.clone(), forwarding.clone(), Box::new(socket), source_addr, permit, None));
                    }
                }
            }
            handshakes.shutdown().await;
            routing.write().await.clear();
        });
        tracing::info!(%address, "public TLS SNI listener ready");
        Ok(Arc::new(Self {
            address,
            routes,
            certificates,
            frontend,
            task,
        }))
    }

    /// Pre-dispatch binding for the owner acceptor: the SNI hostname must be a
    /// live route whose gate is the one the directory verified.
    pub async fn bound_route(&self, hostname: &str, gate: &Arc<VisitorGate>) -> Result<()> {
        let routes = self.routes.read().await;
        let route = routes.get(hostname).context("TLS hostname is not routed")?;
        ensure!(
            Arc::ptr_eq(&route.visitor, gate)
                && route.domain.as_ref().is_none_or(|grant| grant.is_active()),
            "TLS route authority differs from the ingress hop"
        );
        Ok(())
    }

    /// Admit an ingress-injected stream through the same handshake path.
    pub async fn inject(
        &self,
        io: Box<dyn Duplex>,
        source_addr: SocketAddr,
        permit: OwnedSemaphorePermit,
        hostname: String,
        gate: Arc<VisitorGate>,
    ) {
        admit(
            self.routes.clone(),
            self.certificates.clone(),
            None,
            io,
            source_addr,
            permit,
            Some((hostname, gate)),
        )
        .await;
    }

    pub async fn register(
        &self,
        hostname: &str,
        owner: &str,
        tunnel_id: TunnelId,
        mode: TlsMode,
        visitor: Arc<VisitorGate>,
    ) -> Result<mpsc::Receiver<RelayStream>> {
        self.certificates
            .check_owner(hostname, owner, mode == TlsMode::Terminate)?;
        let mut routes = self.routes.write().await;
        ensure!(
            !routes.contains_key(hostname),
            "TLS hostname already registered"
        );
        let (sender, receiver) = mpsc::channel(4);
        routes.insert(
            hostname.into(),
            Route {
                tunnel_id,
                mode,
                owner: owner.into(),
                sender,
                visitor,
                domain: None,
            },
        );
        Ok(receiver)
    }

    pub async fn register_aliases(
        &self,
        primary: &str,
        owner: &str,
        tunnel_id: TunnelId,
        domains: &pike_server::domain_grants::DomainGrants,
    ) -> Result<()> {
        let route = self
            .routes
            .read()
            .await
            .get(primary)
            .cloned()
            .context("primary TLS route missing")?;
        ensure!(route.tunnel_id == tunnel_id, "primary TLS route changed");
        let mut aliases = Vec::new();
        for (hostname, grant) in domains.hosts() {
            self.certificates
                .check_owner(hostname, owner, route.mode == TlsMode::Terminate)?;
            aliases.push((
                hostname.to_owned(),
                Route {
                    domain: Some(grant.clone()),
                    ..route.clone()
                },
            ));
        }
        let mut routes = self.routes.write().await;
        ensure!(
            routes
                .get(primary)
                .is_some_and(|current| current.tunnel_id == tunnel_id
                    && current.sender.same_channel(&route.sender)),
            "primary TLS route changed"
        );
        ensure!(
            aliases
                .iter()
                .all(|(hostname, _)| !routes.contains_key(hostname)),
            "custom TLS hostname already routed"
        );
        routes.extend(aliases);
        Ok(())
    }

    pub async fn unregister(&self, tunnel_id: TunnelId) {
        self.routes
            .write()
            .await
            .retain(|_, route| route.tunnel_id != tunnel_id);
    }

    #[allow(dead_code)]
    pub fn forwards(&self) -> bool {
        self.frontend.is_some()
    }
}
