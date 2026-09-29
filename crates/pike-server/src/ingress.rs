//! Authenticated relay-to-relay hop for public ingress.
//!
//! A frontend relay accepts public traffic for a target it does not own and
//! opens one mutually authenticated TLS connection per stream to the owning
//! relay. The owner rechecks the exact target and expected authority against its
//! current live registrations, binds dispatch to that endpoint's gate and only
//! then writes one accept byte. Before that byte the frontend has forwarded
//! nothing, so an explicit rejection permits one re-resolve; anything after it
//! is never retried. Accepted IO enters the same handlers, admission, metering
//! and cancellation as a locally accepted visitor. The frontend never meters.
//!
//! Directory snapshots also travel over this hop, so the bearer-token management
//! listener stays private.
pub mod frontend;

use crate::{
    config::IngressConfig,
    ingress_directory::{Protocol, Target},
    router::normalize_host,
    visitor_policy::{VisitorGate, VisitorPeer},
};
use anyhow::{bail, ensure, Context, Result};
use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderValue, Request, Response},
    middleware::Next,
};
pub use frontend::Frontend;
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    sync::{mpsc, OwnedSemaphorePermit},
};

/// Both plain TCP and accepted TLS streams use the same bounded byte bridge.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// Wire prefix; the version is part of the magic so an unknown version cannot be
/// parsed as a header of the wrong shape.
pub const MAGIC: &[u8; 8] = b"PIKEHOP1";
pub const KIND_STREAM: u8 = 1;
pub const KIND_DIRECTORY: u8 = 2;
pub const KIND_CHALLENGE: u8 = 3;
pub const ACCEPTED: u8 = 1;
pub const REJECTED: u8 = 0;
pub const MAX_HEADER_BYTES: usize = 1024;
/// ACME HTTP-01 tokens are base64url and short; key authorizations are bounded.
pub const MAX_CHALLENGE_TOKEN_BYTES: usize = 256;
pub const MAX_CHALLENGE_PROOF_BYTES: usize = 1024;
/// Handshake, header exchange and directory fetch each complete within this.
pub const HOP_TIMEOUT: Duration = Duration::from_secs(5);
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Concurrent accepted hop streams per owning relay, all protocols combined.
pub const MAX_LIVE_HOPS: usize = 1024;
const MAX_TRUST_BYTES: usize = 64 * 1024;

/// Exact stream request. Every field is bounded and validated on both ends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HopHeader {
    pub target: Target,
    /// Authority digest the frontend saw in a fresh snapshot. The owner requires
    /// its current registration to carry the same digest.
    pub authority: String,
    /// Original visitor address. It reaches IP rules and metering unchanged.
    pub visitor: SocketAddr,
    /// The visitor reached the frontend over TLS (plain HTTP only).
    pub secure: bool,
}

/// ACME HTTP-01 lookup for one hostname the owner holds a certificate lease
/// for. It carries no visitor bytes: the owner verifies the exact target and
/// authority like a stream, then answers only the key authorization for
/// `token` from the certificate entry bound to that same gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeRequest {
    pub target: Target,
    pub authority: String,
    pub token: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HopRequest {
    Stream(HopHeader),
    /// `Directory::snapshot` with this nonce; the response is a length-prefixed
    /// JSON snapshot of at most `MAX_RESPONSE_BYTES`.
    Directory(String),
    /// One decision byte, then on acceptance a u16 length and the proof.
    Challenge(ChallengeRequest),
}

pub fn valid_challenge_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CHALLENGE_TOKEN_BYTES
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

impl ChallengeRequest {
    pub fn validate(&self) -> Result<()> {
        self.target.validate()?;
        ensure!(
            matches!(
                self.target.protocol,
                Protocol::Http | Protocol::Https | Protocol::Tls
            ),
            "challenge target must be a hostname"
        );
        ensure!(
            valid_authority(&self.authority),
            "invalid ingress authority"
        );
        ensure!(
            valid_challenge_token(&self.token),
            "invalid ACME challenge token"
        );
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let hostname = self.target.hostname.as_deref().unwrap_or_default();
        let mut out = Vec::with_capacity(96 + hostname.len() + self.token.len());
        out.push(protocol_code(self.target.protocol));
        out.push(u8::try_from(hostname.len())?);
        out.extend_from_slice(hostname.as_bytes());
        out.extend_from_slice(self.authority.as_bytes());
        out.extend_from_slice(&u16::try_from(self.token.len())?.to_be_bytes());
        out.extend_from_slice(self.token.as_bytes());
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor(bytes);
        let protocol = protocol_from(cursor.u8()?)?;
        let name_len = usize::from(cursor.u8()?);
        let hostname = std::str::from_utf8(cursor.take(name_len)?)
            .context("ingress hostname is not UTF-8")?
            .to_owned();
        let authority = std::str::from_utf8(cursor.take(64)?)
            .context("ingress authority is not UTF-8")?
            .to_owned();
        let token_len = usize::from(cursor.u16()?);
        let token = std::str::from_utf8(cursor.take(token_len)?)
            .context("challenge token is not UTF-8")?
            .to_owned();
        ensure!(cursor.0.is_empty(), "trailing ingress header bytes");
        let request = Self {
            target: Target {
                protocol,
                hostname: (!hostname.is_empty()).then_some(hostname),
                port: None,
            },
            authority,
            token,
        };
        request.validate()?;
        Ok(request)
    }
}

fn protocol_code(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::Http => 1,
        Protocol::Https => 2,
        Protocol::Tls => 3,
        Protocol::Tcp => 4,
        Protocol::Udp => 5,
    }
}

fn protocol_from(code: u8) -> Result<Protocol> {
    Ok(match code {
        1 => Protocol::Http,
        2 => Protocol::Https,
        3 => Protocol::Tls,
        4 => Protocol::Tcp,
        5 => Protocol::Udp,
        _ => bail!("unknown ingress protocol"),
    })
}

pub fn valid_authority(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub fn valid_nonce(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|c| c.is_ascii_hexdigit())
}

impl HopHeader {
    pub fn validate(&self) -> Result<()> {
        self.target.validate()?;
        ensure!(
            valid_authority(&self.authority),
            "invalid ingress authority"
        );
        ensure!(
            !self.visitor.ip().is_unspecified(),
            "ingress visitor address missing"
        );
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::with_capacity(96);
        out.push(protocol_code(self.target.protocol));
        let hostname = self.target.hostname.as_deref().unwrap_or_default();
        out.push(u8::try_from(hostname.len())?);
        out.extend_from_slice(hostname.as_bytes());
        out.extend_from_slice(&self.target.port.unwrap_or_default().to_be_bytes());
        out.extend_from_slice(self.authority.as_bytes());
        match self.visitor.ip() {
            IpAddr::V4(ip) => {
                out.push(4);
                out.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                out.push(6);
                out.extend_from_slice(&ip.octets());
            }
        }
        out.extend_from_slice(&self.visitor.port().to_be_bytes());
        out.push(u8::from(self.secure));
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor(bytes);
        let protocol = protocol_from(cursor.u8()?)?;
        let name_len = usize::from(cursor.u8()?);
        let hostname = std::str::from_utf8(cursor.take(name_len)?)
            .context("ingress hostname is not UTF-8")?
            .to_owned();
        let port = cursor.u16()?;
        let authority = std::str::from_utf8(cursor.take(64)?)
            .context("ingress authority is not UTF-8")?
            .to_owned();
        let ip = match cursor.u8()? {
            4 => IpAddr::from(<[u8; 4]>::try_from(cursor.take(4)?)?),
            6 => IpAddr::from(<[u8; 16]>::try_from(cursor.take(16)?)?),
            _ => bail!("unknown ingress address family"),
        };
        let visitor = SocketAddr::new(ip, cursor.u16()?);
        let secure = match cursor.u8()? {
            0 => false,
            1 => true,
            _ => bail!("invalid ingress secure flag"),
        };
        ensure!(cursor.0.is_empty(), "trailing ingress header bytes");
        let target = Target {
            protocol,
            hostname: (!hostname.is_empty()).then_some(hostname),
            port: (port != 0).then_some(port),
        };
        let header = Self {
            target,
            authority,
            visitor,
            secure,
        };
        header.validate()?;
        Ok(header)
    }
}

struct Cursor<'a>(&'a [u8]);
impl Cursor<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8]> {
        ensure!(self.0.len() >= count, "truncated ingress header");
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into()?))
    }
}

impl HopRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let (kind, body) = match self {
            Self::Stream(header) => (KIND_STREAM, header.encode()?),
            Self::Directory(nonce) => {
                ensure!(
                    valid_nonce(nonce),
                    "nonce must be 32 hexadecimal characters"
                );
                (KIND_DIRECTORY, nonce.as_bytes().to_vec())
            }
            Self::Challenge(challenge) => (KIND_CHALLENGE, challenge.encode()?),
        };
        ensure!(body.len() <= MAX_HEADER_BYTES, "ingress header too large");
        let mut out = Vec::with_capacity(MAGIC.len() + 3 + body.len());
        out.extend_from_slice(MAGIC);
        out.push(kind);
        out.extend_from_slice(&u16::try_from(body.len())?.to_be_bytes());
        out.extend_from_slice(&body);
        Ok(out)
    }

    pub async fn read<S: AsyncRead + Unpin>(io: &mut S) -> Result<Self> {
        let mut head = [0_u8; 11];
        io.read_exact(&mut head).await?;
        ensure!(&head[..8] == MAGIC, "not an ingress hop request");
        let length = usize::from(u16::from_be_bytes([head[9], head[10]]));
        ensure!(length <= MAX_HEADER_BYTES, "ingress header too large");
        let mut body = vec![0_u8; length];
        io.read_exact(&mut body).await?;
        match head[8] {
            KIND_STREAM => Ok(Self::Stream(HopHeader::decode(&body)?)),
            KIND_DIRECTORY => {
                let nonce = String::from_utf8(body).context("nonce is not UTF-8")?;
                ensure!(
                    valid_nonce(&nonce),
                    "nonce must be 32 hexadecimal characters"
                );
                Ok(Self::Directory(nonce))
            }
            KIND_CHALLENGE => Ok(Self::Challenge(ChallengeRequest::decode(&body)?)),
            _ => bail!("unknown ingress request kind"),
        }
    }
}

/// Operator-owned hop trust. Client and server certificates both chain to the
/// dedicated CA; frontends verify the configured peer name, owners require a
/// client certificate. Network position alone never authenticates a hop.
pub struct HopTls {
    pub client: Arc<rustls::ClientConfig>,
    pub server: Arc<rustls::ServerConfig>,
}

impl HopTls {
    pub async fn load(config: &IngressConfig) -> Result<Self> {
        let (ca, chain, key) = tokio::try_join!(
            tokio::fs::read(&config.ca_path),
            tokio::fs::read(&config.cert_path),
            tokio::fs::read(&config.key_path),
        )
        .context("read [ingress] hop trust material")?;
        ensure!(
            ca.len() <= MAX_TRUST_BYTES && chain.len() <= MAX_TRUST_BYTES && key.len() <= 16 * 1024,
            "[ingress] trust material exceeds limit"
        );
        let mut roots = rustls::RootCertStore::empty();
        let mut count = 0;
        for certificate in CertificateDer::pem_slice_iter(&ca) {
            roots.add(certificate?)?;
            count += 1;
        }
        ensure!(
            (1..=8).contains(&count),
            "[ingress] ca_path must contain 1 to 8 CA certificates"
        );
        let roots = Arc::new(roots);
        let chain = CertificateDer::pem_slice_iter(&chain).collect::<Result<Vec<_>, _>>()?;
        ensure!(
            !chain.is_empty() && chain.len() <= 8,
            "[ingress] cert_path chain is empty or too long"
        );
        let key = PrivateKeyDer::from_pem_slice(&key)
            .context("[ingress] key_path is not a private key")?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots.clone())
            .with_client_auth_cert(chain.clone(), key.clone_key())?;
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(roots, provider.clone())
                .build()
                .context("[ingress] hop client verifier")?;
        let mut server = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)?;
        server.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        server.send_tls13_tickets = 0;
        server.max_early_data_size = 0;
        Ok(Self {
            client: Arc::new(client),
            server: Arc::new(server),
        })
    }
}

/// Hop-verified visitor identity for one injected plain-HTTP connection. Only
/// the owner's hop acceptor constructs it, after `Directory::verify` and route
/// binding, so no public client can supply these values.
#[derive(Clone)]
pub struct HopPeer {
    pub addr: SocketAddr,
    pub secure: bool,
    pub hostname: String,
    pub gate: Arc<VisitorGate>,
}

/// Routed requests must land on the endpoint whose gate the hop was bound to.
#[derive(Clone)]
pub struct ExpectedGate(pub Arc<VisitorGate>);

pub fn misdirected(reason: &'static str) -> Response<Body> {
    Response::builder()
        .status(421)
        .header("cache-control", "no-store")
        .body(Body::from(reason))
        .unwrap_or_else(|_| Response::new(Body::from("misdirected request")))
}

/// Outermost layer of the hop-served application. Rebinds the request to the
/// verified visitor and hostname; hop-served requests never forward again.
pub async fn ingress_peer(
    ConnectInfo(peer): ConnectInfo<HopPeer>,
    mut request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let authority = crate::proxy::canonicalize_authority(&mut request);
    if !authority.is_ok_and(|host| normalize_host(&host) == peer.hostname) {
        return misdirected("HTTP authority must match the ingress hop target");
    }
    let forged: Vec<_> = request
        .headers()
        .keys()
        .filter(|name| name.as_str().starts_with("x-pike-visitor-"))
        .cloned()
        .collect();
    for name in forged {
        request.headers_mut().remove(name);
    }
    // Per-IP limits key on this header first; only the hop value is trusted.
    request.headers_mut().insert(
        "x-forwarded-for",
        HeaderValue::from_str(&peer.addr.ip().to_string()).expect("IP header"),
    );
    request.extensions_mut().insert(ConnectInfo(peer.addr));
    request.extensions_mut().insert(VisitorPeer {
        addr: peer.addr,
        secure: peer.secure,
        allow_plaintext: false,
    });
    request
        .extensions_mut()
        .insert(ExpectedGate(peer.gate.clone()));
    next.run(request).await
}

/// One accepted plain-HTTP hop connection (h2 prior knowledge or h1 upgrade).
pub struct HopHttpStream {
    pub io: Box<dyn Duplex>,
    pub peer: HopPeer,
    pub permit: OwnedSemaphorePermit,
}

/// One accepted HTTPS hop connection carrying the visitor's own ClientHello.
/// The native HTTPS listener terminates it with the same certificate, mTLS and
/// route-gate checks as a direct connection.
pub struct InjectedTls {
    pub io: Box<dyn Duplex>,
    pub addr: SocketAddr,
    pub hostname: String,
    pub gate: Arc<VisitorGate>,
    pub permit: OwnedSemaphorePermit,
}

pub struct HopHttpIo {
    io: Box<dyn Duplex>,
    peer: HopPeer,
    _permit: OwnedSemaphorePermit,
}
impl HopHttpIo {
    /// The hop-verified visitor this connection was bound to; it becomes the
    /// connection's `ConnectInfo`.
    #[must_use]
    pub fn peer(&self) -> HopPeer {
        self.peer.clone()
    }
}
impl AsyncRead for HopHttpIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buffer)
    }
}
impl AsyncWrite for HopHttpIo {
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

/// Serves the existing application on injected hop connections.
pub struct HopHttpListener {
    accepted: mpsc::Receiver<HopHttpStream>,
}
impl HopHttpListener {
    #[must_use]
    pub fn new(accepted: mpsc::Receiver<HopHttpStream>) -> Self {
        Self { accepted }
    }
}
impl axum::serve::Listener for HopHttpListener {
    type Io = HopHttpIo;
    type Addr = SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.accepted.recv().await {
            Some(stream) => {
                let addr = stream.peer.addr;
                (
                    HopHttpIo {
                        io: stream.io,
                        peer: stream.peer,
                        _permit: stream.permit,
                    },
                    addr,
                )
            }
            None => std::future::pending().await,
        }
    }
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(SocketAddr::from(([0, 0, 0, 0], 0)))
    }
}

/// Everything the HTTP server needs for either ingress role.
pub struct HttpIngress {
    pub frontend: Option<Arc<Frontend>>,
    pub http: mpsc::Receiver<HopHttpStream>,
    pub https: mpsc::Receiver<InjectedTls>,
}

/// Write the single decision byte. Rejection closes the connection; the
/// frontend has forwarded no visitor bytes yet, so it may re-resolve once.
pub async fn decide<S: AsyncWrite + Unpin>(io: &mut S, accepted: bool) -> Result<()> {
    io.write_all(&[if accepted { ACCEPTED } else { REJECTED }])
        .await?;
    io.flush().await?;
    if !accepted {
        let _ = io.shutdown().await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> HopHeader {
        HopHeader {
            target: Target::hostname(Protocol::Https, "demo.pike.test"),
            authority: "ab".repeat(32),
            visitor: "[2001:db8::7]:4433".parse().unwrap(),
            secure: true,
        }
    }

    #[tokio::test]
    async fn requests_round_trip_exactly_and_reject_every_malformed_shape() {
        for request in [
            HopRequest::Stream(header()),
            HopRequest::Stream(HopHeader {
                target: Target::port(Protocol::Udp, 30000),
                visitor: "203.0.113.9:53".parse().unwrap(),
                secure: false,
                ..header()
            }),
            HopRequest::Directory("0123456789abcdef0123456789abcdef".into()),
            HopRequest::Challenge(ChallengeRequest {
                target: Target::hostname(Protocol::Tls, "demo.pike.test"),
                authority: "ab".repeat(32),
                token: "Yz1-_token".into(),
            }),
        ] {
            let encoded = request.encode().unwrap();
            let mut cursor = std::io::Cursor::new(encoded.clone());
            assert_eq!(HopRequest::read(&mut cursor).await.unwrap(), request);
            // Truncation at every boundary is an error, never a shorter valid request.
            for cut in 0..encoded.len() {
                let mut cursor = std::io::Cursor::new(encoded[..cut].to_vec());
                assert!(HopRequest::read(&mut cursor).await.is_err(), "{cut}");
            }
        }
        for bad in [
            HopHeader {
                authority: "AB".repeat(32),
                ..header()
            },
            HopHeader {
                target: Target::hostname(Protocol::Http, "Demo.pike.test"),
                ..header()
            },
            HopHeader {
                target: Target {
                    protocol: Protocol::Tcp,
                    hostname: Some("demo.pike.test".into()),
                    port: Some(30000),
                },
                ..header()
            },
            HopHeader {
                target: Target::port(Protocol::Tcp, 80),
                ..header()
            },
            HopHeader {
                visitor: "0.0.0.0:1".parse().unwrap(),
                ..header()
            },
        ] {
            assert!(HopRequest::Stream(bad).encode().is_err());
        }
        assert!(HopRequest::Directory("short".into()).encode().is_err());
        let long = "a".repeat(257);
        for (target, token) in [
            (
                Target::hostname(Protocol::Tls, "demo.pike.test"),
                "bad/token",
            ),
            (Target::hostname(Protocol::Tls, "demo.pike.test"), ""),
            (
                Target::hostname(Protocol::Tls, "demo.pike.test"),
                long.as_str(),
            ),
            (Target::port(Protocol::Tcp, 30000), "token"),
        ] {
            assert!(HopRequest::Challenge(ChallengeRequest {
                target,
                authority: "ab".repeat(32),
                token: token.into(),
            })
            .encode()
            .is_err());
        }
        let mut wrong_magic = HopRequest::Stream(header()).encode().unwrap();
        wrong_magic[7] = b'2';
        assert!(HopRequest::read(&mut std::io::Cursor::new(wrong_magic))
            .await
            .is_err());
        let mut oversize = MAGIC.to_vec();
        oversize.push(KIND_STREAM);
        oversize.extend_from_slice(&u16::MAX.to_be_bytes());
        assert!(HopRequest::read(&mut std::io::Cursor::new(oversize))
            .await
            .is_err());
        let mut trailing = HopRequest::Stream(header()).encode().unwrap();
        trailing.push(0);
        let length = u16::from_be_bytes([trailing[9], trailing[10]]) + 1;
        trailing[9..11].copy_from_slice(&length.to_be_bytes());
        assert!(HopRequest::read(&mut std::io::Cursor::new(trailing))
            .await
            .is_err());
    }
}
