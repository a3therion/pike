//! Authenticated control-plane client. Same rules as the saved-profile loader:
//! HTTPS only except loopback development, no redirects, bounded time and
//! bounded bodies. Responses never contain private keys.
use crate::config::Config;
use anyhow::{ensure, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const MAX_BODY: usize = 256 * 1024;

#[derive(Debug)]
pub enum ApiError {
    /// The control plane answered with an error status.
    Rejected { status: u16, message: String },
    /// No answer, a malformed answer or a local failure.
    Transport(anyhow::Error),
}

impl ApiError {
    /// Authoritative refusals: the credential, member or network is gone.
    pub fn is_definitive(&self) -> bool {
        matches!(self, Self::Rejected { status, .. } if matches!(status, 401 | 403 | 404 | 410))
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected { status, message } => write!(
                f,
                "control plane rejected the request ({status}): {message}"
            ),
            Self::Transport(error) => write!(f, "control plane unreachable: {error:#}"),
        }
    }
}

impl std::error::Error for ApiError {}

#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    base: reqwest::Url,
    key: String,
}

impl Api {
    pub fn new(config: &Config) -> Result<Self> {
        let key = config
            .auth
            .api_key
            .clone()
            .context("login with an API key that has the networks scopes first")?;
        let base = reqwest::Url::parse(&config.relay.api_url).context("invalid api_url")?;
        ensure!(
            base.username().is_empty() && base.password().is_none(),
            "api_url must not contain credentials"
        );
        ensure!(
            base.scheme() == "https"
                || (base.scheme() == "http"
                    && matches!(base.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))),
            "API credentials require HTTPS, except loopback development"
        );
        Ok(Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(15))
                .build()?,
            base,
            key,
        })
    }

    fn url(&self, path: &str) -> reqwest::Url {
        let mut url = self.base.clone();
        url.set_path(&format!("/api/v1{path}"));
        url.set_query(None);
        url.set_fragment(None);
        url
    }

    async fn send<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&(impl Serialize + ?Sized)>,
    ) -> Result<T, ApiError> {
        let mut request = self
            .http
            .request(method, self.url(path))
            .bearer_auth(&self.key);
        if let Some(body) = body {
            request = request.json(body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.into()))?;
        let status = response.status();
        let mut bytes = Vec::new();
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|e| ApiError::Transport(e.into()))?;
            let Some(chunk) = chunk else { break };
            if bytes.len() + chunk.len() > MAX_BODY {
                return Err(ApiError::Transport(anyhow::anyhow!(
                    "response exceeds 256 KiB"
                )));
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            #[derive(Deserialize)]
            struct Failure {
                error: String,
            }
            let message = serde_json::from_slice::<Failure>(&bytes)
                .map(|f| f.error)
                .unwrap_or_else(|_| status.canonical_reason().unwrap_or("error").to_owned());
            return Err(ApiError::Rejected {
                status: status.as_u16(),
                message: message.chars().take(300).collect(),
            });
        }
        if bytes.is_empty() {
            bytes.extend_from_slice(b"null");
        }
        serde_json::from_slice(&bytes).map_err(|e| {
            ApiError::Transport(anyhow::anyhow!("invalid control plane response: {e}"))
        })
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        self.send(reqwest::Method::GET, path, None::<&()>).await
    }

    pub async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, ApiError> {
        self.send(reqwest::Method::POST, path, Some(body)).await
    }

    pub async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        self.send(reqwest::Method::DELETE, path, None::<&()>).await
    }
}

// ─── Response shapes (public identity only) ─────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct Network {
    pub id: String,
    pub name: String,
    pub client_cidr: String,
    pub revision: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Member {
    pub id: String,
    pub name: String,
    pub role: String,
    pub public_key: String,
    pub address: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub listen_port: Option<u16>,
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Route {
    pub id: String,
    pub cidr: String,
    #[serde(default)]
    pub via_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Grant {
    pub id: String,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub cidr: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayView {
    pub name: String,
    pub reported: bool,
    pub fresh: bool,
    pub current: bool,
    #[serde(default)]
    pub applied_revision: Option<u64>,
    #[serde(default)]
    pub routes: Vec<String>,
    #[serde(default)]
    pub peers: Vec<PeerReport>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Status {
    pub network: Network,
    pub members: Vec<Member>,
    pub routes: Vec<Route>,
    pub grants: Vec<Grant>,
    #[serde(default)]
    pub hub: Option<GatewayView>,
    #[serde(default)]
    pub sites: Vec<GatewayView>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HubPeer {
    pub public_key: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemberConfig {
    pub network: Network,
    pub member: ConfigMember,
    #[serde(default)]
    pub hub: Option<HubPeer>,
    pub allowed_ips: Vec<String>,
    pub mtu: u16,
    pub persistent_keepalive: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConfigMember {
    pub id: String,
    pub name: String,
    pub address: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DesiredNetwork {
    pub id: String,
    pub client_cidr: String,
    pub revision: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DesiredSelf {
    pub id: String,
    pub role: String,
    pub public_key: String,
    pub address: String,
    #[serde(default)]
    pub listen_port: Option<u16>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DesiredPeer {
    pub name: String,
    pub role: String,
    pub public_key: String,
    pub address: String,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DesiredGrant {
    pub client_address: String,
    pub cidr: String,
}

/// Desired state for a hub (`peers`, `grants`) or a site (`hub`, `routes`).
#[derive(Debug, Clone, Deserialize)]
pub struct Desired {
    pub protocol: u16,
    pub network: DesiredNetwork,
    #[serde(rename = "self")]
    pub this: DesiredSelf,
    pub lease_seconds: u64,
    #[serde(default)]
    pub peers: Vec<DesiredPeer>,
    #[serde(default)]
    pub grants: Vec<DesiredGrant>,
    #[serde(default)]
    pub hub: Option<HubPeer>,
    #[serde(default)]
    pub routes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerReport {
    pub public_key: String,
    pub last_handshake: u64,
    pub rx: u64,
    pub tx: u64,
}

#[derive(Debug, Serialize)]
pub struct StatusReport {
    pub applied_revision: u64,
    pub lease_seconds: u64,
    pub peers: Vec<PeerReport>,
}
