//! Visitor admission is independent of connector and dashboard credentials.
use anyhow::{ensure, Context, Result};
use axum::{
    body::Body,
    http::{HeaderMap, Response},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, OnceLock,
    },
};

pub mod identity_http;
pub mod jwks;
pub mod jwt;
pub mod mtls;
pub mod oidc;
pub const POLICY_PROTOCOL: u8 = 4;
#[derive(Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub allow_cidrs: Option<Vec<String>>,
    #[serde(default)]
    pub deny_cidrs: Vec<String>,
    #[serde(default)]
    pub basic: Vec<BasicUser>,
    pub jwt: Option<jwt::JwtPolicy>,
    pub oidc: Option<oidc::OidcPolicy>,
    pub mtls: Option<mtls::MtlsPolicy>,
}
impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("allow_cidrs", &self.allow_cidrs)
            .field("deny_cidrs", &self.deny_cidrs)
            .field("basic_user_count", &self.basic.len())
            .field("jwt_enabled", &self.jwt.is_some())
            .field("oidc_enabled", &self.oidc.is_some())
            .field("mtls_enabled", &self.mtls.is_some())
            .finish()
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BasicUser {
    pub username: String,
    pub password_hash: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRecord {
    pub revision: u64,
    pub policy: Policy,
}
struct Password {
    username: String,
    salt: Vec<u8>,
    hash: Vec<u8>,
}
struct Compiled {
    allow: Option<Vec<IpNet>>,
    deny: Vec<IpNet>,
    basic: Vec<Password>,
    jwt: Option<jwt::JwtVerifier>,
    oidc: Option<oidc::Oidc>,
    mtls: Option<mtls::Mtls>,
}
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip @ IpAddr::V4(_) => ip,
    }
}
fn nets(values: &[String]) -> Result<Vec<IpNet>> {
    ensure!(values.len() <= 64, "too many visitor CIDRs");
    values
        .iter()
        .map(|s| {
            let net: IpNet = s.parse().context("invalid visitor CIDR")?;
            if let IpNet::V6(v6) = net {
                if let Some(v4) = v6.addr().to_ipv4_mapped() {
                    ensure!(
                        v6.prefix_len() >= 96,
                        "mapped IPv4 prefix must be at least 96"
                    );
                    return Ok(IpNet::new(v4.into(), v6.prefix_len() - 96)?);
                }
            }
            Ok(net)
        })
        .collect()
}
impl Compiled {
    fn new(
        policy: Policy,
        kind: &str,
        keys: &Arc<jwks::KeyStore>,
        sessions: Arc<oidc::Sessions>,
        scope: &str,
        revision: Option<u64>,
    ) -> Result<Self> {
        let fingerprint = oidc::store::digest(&serde_json::to_string(&policy)?);
        ensure!(
            policy.oidc.is_none()
                || (kind == "http" && policy.basic.is_empty() && policy.jwt.is_none()),
            "OIDC requires HTTP and cannot be combined with other authentication"
        );
        ensure!(
            policy.mtls.is_none() || matches!(kind, "http" | "tls-terminate"),
            "mTLS requires native HTTPS or terminated TLS"
        );
        let mtls = policy.mtls.map(mtls::Mtls::new).transpose()?;
        let oidc_scope = format!("{scope}:{revision:?}:{fingerprint}");
        let oidc = policy
            .oidc
            .map(|policy| oidc::Oidc::new(policy, oidc_scope, keys.clone(), sessions))
            .transpose()?;
        ensure!(
            policy.basic.is_empty() || kind == "http",
            "Basic authentication requires an HTTP endpoint"
        );
        ensure!(
            policy.jwt.is_none() || (kind == "http" && policy.basic.is_empty()),
            "JWT requires HTTP and cannot be combined with Basic authentication"
        );
        let jwt = policy
            .jwt
            .map(|jwt| jwt::JwtVerifier::new(jwt, keys))
            .transpose()?;
        ensure!(policy.basic.len() <= 8, "too many Basic users");
        let mut basic = Vec::<Password>::new();
        for user in policy.basic {
            ensure!(
                !user.username.is_empty()
                    && user.username.len() <= 64
                    && user
                        .username
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
                "invalid Basic username"
            );
            ensure!(
                !basic.iter().any(|prior| prior.username == user.username),
                "duplicate Basic username"
            );
            let parts: Vec<_> = user.password_hash.split('$').collect();
            ensure!(
                parts.len() == 4 && parts[0] == "pbkdf2_sha256" && parts[1] == "100000",
                "unsupported visitor password hash"
            );
            let salt = STANDARD.decode(parts[2]).context("invalid visitor salt")?;
            let hash = STANDARD.decode(parts[3]).context("invalid visitor hash")?;
            ensure!(
                salt.len() == 32 && hash.len() == 32,
                "invalid visitor password hash length"
            );
            basic.push(Password {
                username: user.username,
                salt,
                hash,
            });
        }
        Ok(Self {
            allow: policy
                .allow_cidrs
                .as_ref()
                .map(|list| nets(list))
                .transpose()?,
            deny: nets(&policy.deny_cidrs)?,
            basic,
            jwt,
            oidc,
            mtls,
        })
    }
    fn allows(&self, ip: IpAddr) -> bool {
        let ip = canonical_ip(ip);
        !self.deny.iter().any(|net| net.contains(&ip))
            && self
                .allow
                .as_ref()
                .is_none_or(|nets| nets.iter().any(|net| net.contains(&ip)))
    }
}
/// Closed until the authoritative lease and its policy have both been accepted.
/// A captured gate remains closed after its route is removed or replaced.
pub struct VisitorGate {
    active: AtomicBool,
    fingerprint: OnceLock<String>,
    policy: OnceLock<Arc<Compiled>>,
    closed: tokio::sync::watch::Sender<bool>,
    keys: Arc<jwks::KeyStore>,
    sessions: Arc<oidc::Sessions>,
    scope: String,
}
impl std::fmt::Debug for VisitorGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VisitorGate")
            .field("active", &self.active.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}
impl VisitorGate {
    pub fn pending() -> Arc<Self> {
        Self::with_keys(jwks::KeyStore::new(&[]).expect("default JWKS client"))
    }
    pub fn with_keys(keys: Arc<jwks::KeyStore>) -> Arc<Self> {
        Self::with_identity(keys, oidc::Sessions::new(), String::new())
    }
    pub fn with_identity(
        keys: Arc<jwks::KeyStore>,
        sessions: Arc<oidc::Sessions>,
        scope: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicBool::new(false),
            fingerprint: OnceLock::new(),
            policy: OnceLock::new(),
            closed: tokio::sync::watch::channel(false).0,
            keys,
            sessions,
            scope,
        })
    }
    pub fn unrestricted() -> Arc<Self> {
        let gate = Self::pending();
        gate.activate(Policy::default(), "http")
            .expect("empty policy");
        gate
    }
    pub fn activate(&self, policy: Policy, kind: &str) -> Result<()> {
        self.activate_with_revision(policy, kind, None)
    }
    pub fn activate_with_revision(
        &self,
        policy: Policy,
        kind: &str,
        revision: Option<u64>,
    ) -> Result<()> {
        ensure!(!*self.closed.borrow(), "visitor gate was revoked");
        let fingerprint = format!(
            "{:x}",
            sha2::Sha256::digest(serde_json::to_vec(&(kind, revision, &policy))?)
        );
        let policy = Compiled::new(
            policy,
            kind,
            &self.keys,
            self.sessions.clone(),
            &self.scope,
            revision,
        )?;
        ensure!(
            self.policy.set(Arc::new(policy)).is_ok(),
            "visitor gate already initialized"
        );
        let _ = self.fingerprint.set(fingerprint);
        self.active.store(true, Ordering::Release);
        Ok(())
    }
    /// Opaque configuration identity for authenticated ingress advertisements.
    /// This exposes neither policy credentials nor a visitor admission grant.
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.get().map(String::as_str)
    }
    pub fn close(&self) {
        self.active.store(false, Ordering::Release);
        self.closed.send_replace(true);
    }
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }
    pub async fn cancelled(&self) {
        let mut closed = self.closed.subscribe();
        let _ = closed.wait_for(|closed| *closed).await;
    }
    pub fn wrap_body(self: &Arc<Self>, body: Body) -> Body {
        VisitorAdmission {
            gate: self.clone(),
            expires: None,
            session: None,
            domain: None,
        }
        .wrap_body(body)
    }
    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        self.active.load(Ordering::Acquire)
            && self.policy.get().is_some_and(|policy| policy.allows(ip))
    }
    pub fn tls_verifier(
        &self,
    ) -> Result<Option<Arc<dyn rustls::server::danger::ClientCertVerifier>>> {
        ensure!(
            self.active.load(Ordering::Acquire),
            "visitor policy unavailable"
        );
        Ok(self
            .policy
            .get()
            .context("visitor policy unavailable")?
            .mtls
            .as_ref()
            .map(mtls::Mtls::verifier))
    }
    /// The chain must come from a successfully completed rustls handshake.
    pub fn tls_identity(
        &self,
        peer: IpAddr,
        chain: Option<&[rustls::pki_types::CertificateDer<'_>]>,
    ) -> Result<Option<mtls::CertificateIdentity>> {
        ensure!(self.allows_ip(peer), "visitor policy denied TLS peer");
        self.policy
            .get()
            .context("visitor policy unavailable")?
            .mtls
            .as_ref()
            .map(|mtls| mtls.identity(chain.context("client certificate required")?))
            .transpose()
    }
    pub fn tls_admission(
        self: &Arc<Self>,
        identity: Option<&mtls::CertificateIdentity>,
    ) -> Result<VisitorAdmission, Rejection> {
        let policy = self.policy.get().ok_or(Rejection::Unavailable)?;
        if !self.active.load(Ordering::Acquire) {
            return Err(Rejection::Unavailable);
        }
        if policy.mtls.is_some() && identity.is_none() {
            return Err(Rejection::Certificate);
        }
        if identity.is_some_and(|identity| identity.expires <= tokio::time::Instant::now()) {
            return Err(Rejection::Certificate);
        }
        Ok(VisitorAdmission {
            gate: self.clone(),
            expires: identity.map(|identity| identity.expires),
            session: None,
            domain: None,
        })
    }
    pub async fn handle_http(
        self: &Arc<Self>,
        visitor: VisitorPeer,
        req: &mut axum::http::Request<Body>,
    ) -> Result<VisitorDecision, Rejection> {
        if !self.active.load(Ordering::Acquire) {
            return Err(Rejection::Unavailable);
        }
        let policy = self.policy.get().ok_or(Rejection::Unavailable)?;
        if !policy.allows(visitor.addr.ip()) {
            return Err(Rejection::Forbidden);
        }
        let tls = req.extensions().get::<mtls::TlsPeer>();
        if tls.is_some_and(|peer| !Arc::ptr_eq(&peer.gate, self)) {
            return Err(Rejection::Certificate);
        }
        let certificate = tls.and_then(|peer| peer.certificate.as_ref());
        let certificate_admission = self.tls_admission(certificate)?;
        let decision = if let Some(oidc) = &policy.oidc {
            tokio::select! {
                biased;
                () = self.cancelled() => Err(Rejection::Unavailable),
                result = oidc.handle(self, visitor, req) => result,
            }?
        } else {
            VisitorDecision::Admit(
                self.authorize_credentials(visitor, req.headers_mut())
                    .await?,
            )
        };
        Ok(match decision {
            VisitorDecision::Admit(mut admission) => {
                if let Some(deadline) = certificate_admission.expires {
                    admission.expires = Some(
                        admission
                            .expires
                            .map_or(deadline, |expires| expires.min(deadline)),
                    );
                }
                VisitorDecision::Admit(admission)
            }
            response @ VisitorDecision::Response(_) => response,
        })
    }
    pub async fn authorize_http(
        self: &Arc<Self>,
        visitor: VisitorPeer,
        headers: &mut HeaderMap,
    ) -> Result<VisitorAdmission, Rejection> {
        if self
            .policy
            .get()
            .is_some_and(|policy| policy.mtls.is_some())
        {
            return Err(Rejection::Certificate);
        }
        self.authorize_credentials(visitor, headers).await
    }
    async fn authorize_credentials(
        self: &Arc<Self>,
        visitor: VisitorPeer,
        headers: &mut HeaderMap,
    ) -> Result<VisitorAdmission, Rejection> {
        if !self.active.load(Ordering::Acquire) {
            return Err(Rejection::Unavailable);
        }
        let policy = self.policy.get().cloned().ok_or(Rejection::Unavailable)?;
        if !policy.allows(visitor.addr.ip()) {
            return Err(Rejection::Forbidden);
        }
        let admission = VisitorAdmission {
            gate: self.clone(),
            expires: None,
            session: None,
            domain: None,
        };
        if policy.oidc.is_some() {
            return Err(Rejection::Unavailable);
        }
        if policy.basic.is_empty() && policy.jwt.is_none() {
            return Ok(admission);
        }
        if !visitor.secure && !visitor.allow_plaintext {
            return Err(Rejection::Insecure);
        }
        if let Some(jwt) = &policy.jwt {
            let auth = one_header(headers, "authorization").ok_or(Rejection::Bearer)?;
            let (scheme, token) = auth.split_once(' ').ok_or(Rejection::Bearer)?;
            if !scheme.eq_ignore_ascii_case("Bearer") {
                return Err(Rejection::Bearer);
            }
            let expires = tokio::select! {
                biased;
                () = self.cancelled() => return Err(Rejection::Unavailable),
                expiry = jwt.authorize(token) => expiry?,
            };
            if !self.active.load(Ordering::Acquire) {
                return Err(Rejection::Unavailable);
            }
            headers.remove("authorization");
            return Ok(VisitorAdmission {
                expires: Some(expires),
                ..admission
            });
        }
        let auth = one_header(headers, "authorization").ok_or(Rejection::Unauthorized)?;
        let (scheme, encoded) = auth.split_once(' ').ok_or(Rejection::Unauthorized)?;
        if !scheme.eq_ignore_ascii_case("Basic") || encoded.len() > 1500 {
            return Err(Rejection::Unauthorized);
        }
        let decoded = STANDARD
            .decode(encoded)
            .map_err(|_| Rejection::Unauthorized)?;
        let decoded = String::from_utf8(decoded).map_err(|_| Rejection::Unauthorized)?;
        let (username, password) = decoded.split_once(':').ok_or(Rejection::Unauthorized)?;
        if username.len() > 64 || password.len() > 1024 {
            return Err(Rejection::Unauthorized);
        }
        let username = username.to_owned();
        let password = password.to_owned();
        static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
        let permit = SLOTS
            .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(8)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| Rejection::Unavailable)?;
        let valid = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let matched = policy.basic.iter().find(|user| user.username == username);
            // Unknown users incur the same PBKDF2 work as a wrong password.
            let candidate = matched.unwrap_or(&policy.basic[0]);
            let verified = ring::pbkdf2::verify(
                ring::pbkdf2::PBKDF2_HMAC_SHA256,
                NonZeroU32::new(100_000).unwrap(),
                &candidate.salt,
                password.as_bytes(),
                &candidate.hash,
            )
            .is_ok();
            verified && matched.is_some()
        })
        .await
        .map_err(|_| Rejection::Unavailable)?;
        if !valid {
            return Err(Rejection::Unauthorized);
        }
        if !self.active.load(Ordering::Acquire) {
            return Err(Rejection::Unavailable);
        }
        headers.remove("authorization");
        Ok(admission)
    }
}
pub enum VisitorDecision {
    Admit(VisitorAdmission),
    Response(Response<Body>),
}
/// One request's authorization lifetime, shared by HTTP bodies and WebSockets.
#[derive(Clone, Debug)]
pub struct VisitorAdmission {
    gate: Arc<VisitorGate>,
    expires: Option<tokio::time::Instant>,
    session: Option<Arc<oidc::store::Session>>,
    domain: Option<Arc<crate::domain_grants::DomainGrant>>,
}
impl VisitorAdmission {
    pub fn with_domain(
        mut self,
        domain: Option<Arc<crate::domain_grants::DomainGrant>>,
    ) -> Result<Self, Rejection> {
        if domain.as_ref().is_some_and(|grant| !grant.is_active()) {
            return Err(Rejection::Unavailable);
        }
        self.domain = domain;
        Ok(self)
    }
    pub async fn cancelled(&self) {
        let expiry = async {
            match self.expires {
                Some(at) => tokio::time::sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        let session = async {
            match &self.session {
                Some(session) => session.cancelled().await,
                None => std::future::pending().await,
            }
        };
        let domain = async {
            match &self.domain {
                Some(grant) => grant.cancelled().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! { () = self.gate.cancelled() => {}, () = expiry => {}, () = session => {}, () = domain => {} }
    }
    /// Preserve data and trailer frames; stop stalled bodies at revocation or expiry.
    pub fn wrap_body(&self, body: Body) -> Body {
        use futures_util::StreamExt;
        let stream = futures_util::stream::unfold(
            Some((http_body_util::BodyStream::new(body), self.clone())),
            |state| async move {
                let (mut body, admission) = state?;
                let frame = tokio::select! {
                    biased;
                    () = admission.cancelled() => return Some((Err(std::io::Error::other("visitor authorization ended")), None)),
                    frame = body.next() => frame,
                };
                frame.map(|frame| {
                    (
                        frame.map_err(std::io::Error::other),
                        Some((body, admission)),
                    )
                })
            },
        );
        Body::new(http_body_util::StreamBody::new(stream))
    }
}
#[derive(Debug)]
pub enum Rejection {
    Unauthorized,
    Bearer,
    Forbidden,
    Unavailable,
    Insecure,
    InvalidProxy,
    InvalidSignIn,
    CrossOrigin,
    Certificate,
}
impl Rejection {
    pub fn response(self) -> Response<Body> {
        let bearer = matches!(self, Self::Bearer);
        let (code, message) = match self {
            Self::Bearer => (401, "Valid visitor token required"),
            Self::Unauthorized => (401, "Visitor authentication required"),
            Self::Forbidden => (403, "Visitor IP denied"),
            Self::Unavailable => (503, "Visitor policy unavailable"),
            Self::Insecure => (403, "Visitor authentication requires HTTPS"),
            Self::InvalidSignIn => (401, "Visitor sign-in could not be verified"),
            Self::Certificate => (403, "Verified visitor client certificate required"),
            Self::CrossOrigin => (403, "Visitor session requires a same-origin request"),
            Self::InvalidProxy => (400, "Invalid trusted proxy identity"),
        };
        let mut response = Response::builder()
            .status(code)
            .header("cache-control", "no-store")
            .header("referrer-policy", "no-referrer")
            .header("x-content-type-options", "nosniff");
        if matches!(self, Self::Unauthorized | Self::Bearer) {
            response = response.header(
                "www-authenticate",
                if bearer {
                    "Bearer realm=\"Pike protected tunnel\", error=\"invalid_token\""
                } else {
                    "Basic realm=\"Pike protected tunnel\", charset=\"UTF-8\""
                },
            );
        }
        response.body(Body::from(message)).unwrap()
    }
}
#[derive(Clone, Copy, Debug)]
pub struct VisitorPeer {
    pub addr: SocketAddr,
    pub secure: bool,
    pub allow_plaintext: bool,
}
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    networks: Vec<IpNet>,
    allow_insecure_loopback: bool,
}
impl TrustedProxies {
    pub fn new(cidrs: &[String], allow_insecure_loopback: bool) -> Result<Self> {
        Ok(Self {
            networks: nets(cidrs)?,
            allow_insecure_loopback,
        })
    }
    /// The last trusted proxy must overwrite these single-value headers. Never
    /// infer identity or TLS from arbitrary caller-supplied forwarding headers.
    pub fn resolve(&self, peer: SocketAddr, headers: &HeaderMap) -> Result<VisitorPeer, Rejection> {
        if !self
            .networks
            .iter()
            .any(|net| net.contains(&canonical_ip(peer.ip())))
        {
            return Ok(VisitorPeer {
                addr: peer,
                secure: false,
                allow_plaintext: self.allow_insecure_loopback
                    && canonical_ip(peer.ip()).is_loopback(),
            });
        }
        let ip = one_header(headers, "x-real-ip")
            .and_then(|s| s.parse::<IpAddr>().ok())
            .ok_or(Rejection::InvalidProxy)?;
        let proto = one_header(headers, "x-forwarded-proto")
            .filter(|s| matches!(*s, "http" | "https"))
            .ok_or(Rejection::InvalidProxy)?;
        Ok(VisitorPeer {
            addr: SocketAddr::new(canonical_ip(ip), peer.port()),
            secure: proto == "https",
            allow_plaintext: false,
        })
    }
}
fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
#[path = "visitor_policy/tests.rs"]
mod tests;
