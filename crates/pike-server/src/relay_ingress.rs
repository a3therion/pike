//! Owner role of public ingress: accept authenticated hops from frontends,
//! recheck the exact target and expected authority against current live
//! registrations, bind dispatch to that endpoint's gate, and only then write
//! the accept byte and inject the stream into the existing handler. Everything
//! after the accept byte is the same code path a directly accepted visitor uses.
use super::{
    public_tls::TlsEndpoints, relay_endpoints::Endpoints, relay_streams::StreamDispatcher,
    relay_tcp::RelayStream, relay_udp,
};
use anyhow::{anyhow, ensure, Context, Result};
use pike_server::{
    certificates::Certificates,
    ingress::{
        self, ChallengeRequest, HopHeader, HopHttpStream, HopPeer, HopRequest, InjectedTls,
        HOP_TIMEOUT, MAX_CHALLENGE_PROOF_BYTES, MAX_LIVE_HOPS,
    },
    ingress_directory::{Protocol, MAX_RESPONSE_BYTES},
    registry::ClientRegistry,
    router::VhostRouter,
    visitor_policy::VisitorGate,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::{server::TlsStream, TlsAcceptor};

#[derive(Clone)]
pub struct OwnerHandles {
    pub registry: Arc<ClientRegistry>,
    pub vhost_router: Arc<VhostRouter>,
    pub endpoints: Arc<Endpoints>,
    pub tls_endpoints: Option<Arc<TlsEndpoints>>,
    pub certificates: Arc<Certificates>,
    pub http: mpsc::Sender<HopHttpStream>,
    pub https: mpsc::Sender<InjectedTls>,
}

/// Dispatch bound before the accept byte. Reservations hold queue capacity so a
/// full or missing handler is a pre-dispatch rejection, never an accepted stream
/// that goes nowhere.
enum Bound {
    Tcp(Arc<StreamDispatcher>),
    Udp(mpsc::OwnedPermit<relay_udp::Injected>),
    Tls(Arc<TlsEndpoints>, String, Arc<VisitorGate>),
    Https(mpsc::OwnedPermit<InjectedTls>, String, Arc<VisitorGate>),
    Http(mpsc::OwnedPermit<HopHttpStream>, String, Arc<VisitorGate>),
}

pub async fn run_owner(
    bind: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    handles: OwnerHandles,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("bind ingress hop listener on {bind}"))?;
    tracing::info!(address = %listener.local_addr()?, "ingress hop listener ready");
    let acceptor = TlsAcceptor::from(tls);
    let budget = Arc::new(Semaphore::new(MAX_LIVE_HOPS));
    let mut hops = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            _ = hops.join_next(), if !hops.is_empty() => {},
            accepted = listener.accept() => {
                let Ok((socket, peer)) = accepted else { break; };
                let Ok(permit) = budget.clone().try_acquire_owned() else { continue; };
                let handles = handles.clone();
                let acceptor = acceptor.clone();
                hops.spawn(async move {
                    let _ = socket.set_nodelay(true);
                    let opened = timeout(HOP_TIMEOUT, async {
                        let mut tls = acceptor.accept(socket).await.context("hop TLS handshake")?;
                        // The verifier already required a chain to the dedicated CA;
                        // a missing certificate must never pass silently.
                        ensure!(
                            tls.get_ref().1.peer_certificates().is_some_and(|chain| !chain.is_empty()),
                            "hop client certificate missing"
                        );
                        let request = HopRequest::read(&mut tls).await?;
                        Ok::<_, anyhow::Error>((tls, request))
                    })
                    .await;
                    let (tls, request) = match opened {
                        Ok(Ok(opened)) => opened,
                        Ok(Err(error)) => { tracing::debug!(%peer, %error, "ingress hop refused"); return; }
                        Err(_) => { tracing::debug!(%peer, "ingress hop timed out"); return; }
                    };
                    match request {
                        HopRequest::Directory(nonce) => serve_directory(tls, &handles.registry, &nonce).await,
                        HopRequest::Stream(header) => admit(tls, header, handles, permit, peer).await,
                        HopRequest::Challenge(challenge) => serve_challenge(tls, challenge, &handles, peer).await,
                    }
                });
            }
        }
    }
    hops.shutdown().await;
    Ok(())
}

async fn serve_directory(mut tls: TlsStream<TcpStream>, registry: &ClientRegistry, nonce: &str) {
    let body = registry
        .ingress
        .snapshot(nonce)
        .and_then(|snapshot| Ok(serde_json::to_vec(&snapshot)?))
        .and_then(|body| {
            ensure!(
                body.len() <= MAX_RESPONSE_BYTES,
                "ingress snapshot too large"
            );
            Ok(body)
        });
    let body = match body {
        Ok(body) => body,
        Err(error) => {
            tracing::warn!(%error, "ingress snapshot unavailable");
            return;
        }
    };
    let Ok(length) = u32::try_from(body.len()) else {
        return;
    };
    let _ = timeout(HOP_TIMEOUT, async {
        tls.write_all(&length.to_be_bytes()).await?;
        tls.write_all(&body).await?;
        tls.flush().await?;
        tls.shutdown().await
    })
    .await;
}

/// ACME HTTP-01 for a hostname this relay holds the certificate lease for,
/// including TLS-terminate profiles that have no HTTP route. The target and
/// authority pass the same `Directory::verify` as a stream, and the proof comes
/// only from the certificate entry bound to that verified gate.
async fn serve_challenge(
    mut tls: TlsStream<TcpStream>,
    challenge: ChallengeRequest,
    handles: &OwnerHandles,
    peer: SocketAddr,
) {
    let proof = async {
        let hostname = challenge
            .target
            .hostname
            .as_deref()
            .context("challenge hostname missing")?;
        let (_, gate) = handles
            .registry
            .ingress
            .verify(&challenge.target, &challenge.authority)?;
        ensure!(gate.is_active(), "route authority is closing");
        let proof = handles
            .certificates
            .bound_challenge(hostname, &challenge.token, &gate)
            .await
            .context("no challenge for this hostname on the verified endpoint")?;
        ensure!(
            proof.len() <= MAX_CHALLENGE_PROOF_BYTES,
            "challenge proof exceeds bound"
        );
        Ok::<_, anyhow::Error>(proof)
    }
    .await;
    let proof = match proof {
        Ok(proof) => proof,
        Err(error) => {
            tracing::debug!(%peer, target = ?challenge.target, %error, "ingress challenge refused");
            let _ = timeout(HOP_TIMEOUT, ingress::decide(&mut tls, false)).await;
            return;
        }
    };
    let Ok(length) = u16::try_from(proof.len()) else {
        return;
    };
    let _ = timeout(HOP_TIMEOUT, async {
        ingress::decide(&mut tls, true).await?;
        tls.write_all(&length.to_be_bytes()).await?;
        tls.write_all(proof.as_bytes()).await?;
        tls.flush().await?;
        tls.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    })
    .await;
}

async fn admit(
    mut tls: TlsStream<TcpStream>,
    header: HopHeader,
    handles: OwnerHandles,
    permit: OwnedSemaphorePermit,
    peer: SocketAddr,
) {
    let bound = match bind(&header, &handles).await {
        Ok(bound) => bound,
        Err(error) => {
            tracing::debug!(%peer, target = ?header.target, %error, "ingress hop rejected before dispatch");
            let _ = timeout(HOP_TIMEOUT, ingress::decide(&mut tls, false)).await;
            return;
        }
    };
    if !matches!(
        timeout(HOP_TIMEOUT, ingress::decide(&mut tls, true)).await,
        Ok(Ok(()))
    ) {
        return;
    }
    let visitor = header.visitor;
    match bound {
        Bound::Tcp(dispatcher) => {
            dispatcher
                .dispatch(RelayStream {
                    io: Box::new(tls),
                    source_addr: visitor,
                    prefix: vec![],
                    permit: Some(permit),
                    admission: None,
                })
                .await;
        }
        Bound::Udp(reservation) => {
            reservation.send(relay_udp::Injected {
                io: Box::new(tls),
                peer: visitor,
                permit,
            });
        }
        Bound::Tls(endpoints, hostname, gate) => {
            endpoints
                .inject(Box::new(tls), visitor, permit, hostname, gate)
                .await;
        }
        Bound::Https(reservation, hostname, gate) => {
            reservation.send(InjectedTls {
                io: Box::new(tls),
                addr: visitor,
                hostname,
                gate,
                permit,
            });
        }
        Bound::Http(reservation, hostname, gate) => {
            reservation.send(HopHttpStream {
                io: Box::new(tls),
                peer: HopPeer {
                    addr: visitor,
                    secure: header.secure,
                    hostname,
                    gate,
                },
                permit,
            });
        }
    }
}

/// Authority, then route binding to the same live endpoint and gate. Shared
/// members of one profile reuse one gate, so pointer equality binds to the
/// endpoint rather than to any one connector.
async fn bind(header: &HopHeader, handles: &OwnerHandles) -> Result<Bound> {
    let (primary, gate) = handles
        .registry
        .ingress
        .verify(&header.target, &header.authority)?;
    match header.target.protocol {
        Protocol::Tcp => {
            let endpoint = handles
                .endpoints
                .get(&primary)
                .await
                .context("TCP endpoint is not live")?;
            let stream = endpoint.stream.as_ref().context("TCP listener missing")?;
            ensure!(
                endpoint.kind == "tcp"
                    && Arc::ptr_eq(&endpoint.visitor, &gate)
                    && Some(stream.port) == header.target.port,
                "TCP endpoint differs from the verified route"
            );
            Ok(Bound::Tcp(stream.dispatcher.clone()))
        }
        Protocol::Udp => {
            let endpoint = handles
                .endpoints
                .get(&primary)
                .await
                .context("UDP endpoint is not live")?;
            let datagram = endpoint.datagram.as_ref().context("UDP listener missing")?;
            ensure!(
                endpoint.kind == "udp"
                    && Arc::ptr_eq(&endpoint.visitor, &gate)
                    && Some(datagram.port) == header.target.port,
                "UDP endpoint differs from the verified route"
            );
            let reservation = datagram
                .injector()
                .try_reserve_owned()
                .map_err(|_| anyhow!("UDP endpoint hop queue is full"))?;
            Ok(Bound::Udp(reservation))
        }
        Protocol::Tls => {
            let hostname = header
                .target
                .hostname
                .clone()
                .context("TLS hostname missing")?;
            let endpoints = handles
                .tls_endpoints
                .as_ref()
                .context("public TLS listener is not configured")?;
            endpoints.bound_route(&hostname, &gate).await?;
            Ok(Bound::Tls(endpoints.clone(), hostname, gate))
        }
        Protocol::Https | Protocol::Http => {
            let hostname = header.target.hostname.clone().context("hostname missing")?;
            let route = handles
                .vhost_router
                .route(&hostname)
                .context("HTTP route is not live")?;
            ensure!(
                route.is_active() && Arc::ptr_eq(&route.visitor, &gate),
                "HTTP route authority differs from the verified route"
            );
            if header.target.protocol == Protocol::Https {
                let reservation = handles
                    .https
                    .clone()
                    .try_reserve_owned()
                    .map_err(|_| anyhow!("native HTTPS listener is busy or not configured"))?;
                Ok(Bound::Https(reservation, hostname, gate))
            } else {
                let reservation = handles
                    .http
                    .clone()
                    .try_reserve_owned()
                    .map_err(|_| anyhow!("hop HTTP server is busy or not running"))?;
                Ok(Bound::Http(reservation, hostname, gate))
            }
        }
    }
}
