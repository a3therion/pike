//! Native HTTPS keeps proof of certificate possession attached to its TLS
//! connection. Header-based reverse-proxy identities cannot create this proof.
//! An ingress frontend forwards the visitor's raw handshake to the owning relay,
//! which terminates it here with the same certificate, mTLS and route checks.
use crate::{
    certificates::Certificates,
    config::PublicTlsConfig,
    ingress::{frontend::TlsForward, Duplex, Frontend, InjectedTls},
    ingress_directory::{Protocol, Target},
    registry::ClientRegistry,
    router::{normalize_host, VhostRouter},
    visitor_policy::{mtls::TlsPeer, VisitorGate, VisitorPeer},
};
use anyhow::{ensure, Context, Result};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, Response},
    middleware::Next,
};
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::server::TlsStream;

pub(super) struct HttpsListener {
    address: SocketAddr,
    accepted: mpsc::Receiver<(HttpsStream, SocketAddr)>,
    task: JoinHandle<()>,
}
impl Drop for HttpsListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}
pub(super) struct HttpsStream {
    io: TlsStream<Box<dyn Duplex>>,
    peer: TlsPeer,
    _permit: OwnedSemaphorePermit,
}
impl HttpsStream {
    /// The verified TLS peer; it becomes the connection's `ConnectInfo`.
    pub(super) fn peer(&self) -> TlsPeer {
        self.peer.clone()
    }
}
impl AsyncRead for HttpsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buffer)
    }
}
impl AsyncWrite for HttpsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}
impl axum::serve::Listener for HttpsListener {
    type Io = HttpsStream;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.accepted.recv().await {
            Some(stream) => stream,
            None => std::future::pending().await,
        }
    }
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.address)
    }
}

#[derive(Clone)]
struct Shared {
    router: Arc<VhostRouter>,
    registry: Arc<ClientRegistry>,
    certificates: Arc<Certificates>,
    sender: mpsc::Sender<(HttpsStream, SocketAddr)>,
    frontend: Option<Arc<Frontend>>,
}

enum Outcome {
    Served,
    Forward(Box<TlsForward>, OwnedSemaphorePermit),
}

async fn injected(receiver: &mut Option<mpsc::Receiver<InjectedTls>>) -> Option<InjectedTls> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

impl HttpsListener {
    pub async fn bind(
        config: PublicTlsConfig,
        router: Arc<VhostRouter>,
        registry: Arc<ClientRegistry>,
        certificates: Arc<Certificates>,
        frontend: Option<Arc<Frontend>>,
        injected_streams: Option<mpsc::Receiver<InjectedTls>>,
        mut shutdown: watch::Receiver<bool>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(config.bind_addr)
            .await
            .context("bind native HTTPS listener")?;
        let address = listener.local_addr()?;
        let (sender, accepted) = mpsc::channel(16);
        let shared = Shared {
            router,
            registry,
            certificates,
            sender,
            frontend,
        };
        let task = tokio::spawn(async move {
            let budget = Arc::new(Semaphore::new(256));
            let mut handshakes = JoinSet::new();
            let mut injected_streams = injected_streams;
            loop {
                tokio::select! {
                    _ = shutdown.changed() => break,
                    _ = handshakes.join_next(), if !handshakes.is_empty() => {},
                    stream = injected(&mut injected_streams) => {
                        let Some(stream) = stream else { injected_streams = None; continue; };
                        // Injected streams were bound to a gate by the hop acceptor
                        // and are never forwarded again.
                        let shared = Shared { frontend: None, ..shared.clone() };
                        handshakes.spawn(admit(shared, stream.io, stream.addr, stream.permit, Some((stream.hostname, stream.gate))));
                    }
                    incoming = listener.accept() => {
                        let Ok((socket, addr)) = incoming else { break; };
                        let Ok(permit) = budget.clone().try_acquire_owned() else { continue; };
                        handshakes.spawn(admit(shared.clone(), Box::new(socket), addr, permit, None));
                    }
                }
            }
            handshakes.shutdown().await;
        });
        tracing::info!(%address, "native HTTPS listener ready");
        Ok(Self {
            address,
            accepted,
            task,
        })
    }
}

/// One accepted connection: SNI, route, certificate, optional visitor mTLS and
/// a final route-gate recheck before the stream reaches the HTTP server. A
/// hostname routed on another relay leaves after the ClientHello peek with its
/// handshake bytes intact.
async fn admit(
    shared: Shared,
    io: Box<dyn Duplex>,
    addr: SocketAddr,
    permit: OwnedSemaphorePermit,
    expected: Option<(String, Arc<VisitorGate>)>,
) {
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let (io, hello, prefix) = crate::tls_material::read_hello(io).await?;
        let hostname = hello
            .client_hello()
            .server_name()
            .context("HTTPS requires SNI")?
            .to_ascii_lowercase();
        if let Some((expected_host, _)) = &expected {
            ensure!(
                hostname == *expected_host,
                "HTTPS SNI differs from the ingress hop target"
            );
        }
        let Some(route) = shared.router.route(&hostname) else {
            if let Some(frontend) = shared.frontend.as_ref().filter(|_| expected.is_none()) {
                let target = Target::hostname(Protocol::Https, &hostname);
                if frontend.resolve(&target).is_some() {
                    let forward = frontend.forward_tls(&target, io, prefix, addr).await?;
                    return Ok(Outcome::Forward(Box::new(forward), permit));
                }
            }
            anyhow::bail!("unknown HTTPS endpoint");
        };
        if let Some((_, gate)) = &expected {
            ensure!(
                Arc::ptr_eq(&route.visitor, gate),
                "HTTPS route authority differs from the ingress hop"
            );
        }
        ensure!(
            route.visitor.allows_ip(addr.ip()),
            "HTTPS visitor IP denied"
        );
        let owner = shared
            .registry
            .user_id_for_connection(&route.connection_id)
            .context("HTTPS route owner missing")?;
        let config = shared
            .certificates
            .server_config(
                &hostname,
                &owner,
                &route.visitor,
                route.visitor.tls_verifier()?,
                true,
            )
            .await?;
        let io = tokio_rustls::server::StartHandshake::from_parts(hello, io)
            .into_stream(config)
            .await?;
        let identity = route
            .visitor
            .tls_identity(addr.ip(), io.get_ref().1.peer_certificates())?;
        ensure!(
            shared
                .router
                .route(&hostname)
                .is_some_and(|current| Arc::ptr_eq(&current.visitor, &route.visitor)),
            "HTTPS endpoint changed during handshake"
        );
        let peer = TlsPeer {
            addr,
            hostname,
            gate: route.visitor,
            certificate: identity,
        };
        shared
            .sender
            .try_send((
                HttpsStream {
                    io,
                    peer,
                    _permit: permit,
                },
                addr,
            ))
            .map_err(|_| anyhow::anyhow!("HTTPS listener busy or closed"))?;
        Ok::<_, anyhow::Error>(Outcome::Served)
    })
    .await;
    match result {
        Ok(Ok(Outcome::Served)) => {}
        Ok(Ok(Outcome::Forward(forward, permit))) => {
            let _permit = permit;
            let shutdown = shared.frontend.as_ref().map_or_else(
                || watch::channel(false).1,
                |frontend| frontend.shutdown_signal(),
            );
            (*forward).pipe(shutdown).await;
        }
        _ => tracing::debug!(%addr, "native HTTPS handshake rejected"),
    }
}

pub(super) async fn verified_peer(
    ConnectInfo(peer): ConnectInfo<TlsPeer>,
    mut request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let authority = crate::proxy::canonicalize_authority(&mut request);
    if !authority.is_ok_and(|host| normalize_host(&host) == peer.hostname) {
        return Response::builder()
            .status(421)
            .body(Body::from("HTTP authority must match TLS SNI"))
            .unwrap();
    }
    request.extensions_mut().insert(ConnectInfo(peer.addr));
    request.extensions_mut().insert(VisitorPeer {
        addr: peer.addr,
        secure: true,
        allow_plaintext: false,
    });
    request.extensions_mut().insert(peer);
    next.run(request).await
}
