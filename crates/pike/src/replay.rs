//! CLI and inspector share one authenticated relay client. Never follow an
//! origin redirect or retry a replay automatically: it may have side effects.
use crate::config::Config;
use anyhow::{bail, ensure, Context, Result};
use pike_core::replay::{ReplayRequest, ReplayResponse, MAX_JSON_BYTES};
use std::{path::Path, time::Duration};
use tokio::io::AsyncReadExt;

#[derive(Clone)]
pub struct ReplayClient {
    http: reqwest::Client,
    endpoint: reqwest::Url,
    token: String,
}

impl ReplayClient {
    pub fn new(config: &Config, tunnel_id: &str, relay_url: Option<&str>) -> Result<Self> {
        let id = uuid::Uuid::parse_str(tunnel_id).context("replay requires a tunnel UUID")?;
        let mut url = if let Some(url) = relay_url {
            reqwest::Url::parse(url)?
        } else if let Some(url) = &config.relay.ws_url {
            let mut url = reqwest::Url::parse(url)?;
            let scheme = match url.scheme() {
                "wss" => "https",
                "ws" => "http",
                _ => bail!("invalid relay WebSocket URL"),
            };
            url.set_scheme(scheme)
                .map_err(|()| anyhow::anyhow!("invalid relay URL"))?;
            url
        } else {
            reqwest::Url::parse(&format!("https://{}", config.relay.addr))?
        };
        ensure!(
            url.username().is_empty() && url.password().is_none(),
            "relay URL must not contain credentials"
        );
        ensure!(
            url.scheme() == "https"
                || (url.scheme() == "http"
                    && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))),
            "replay credentials require HTTPS, except loopback development"
        );
        url.set_path(&format!("/api/v1/tunnels/{id}/replay"));
        url.set_query(None);
        url.set_fragment(None);
        Ok(Self {
            endpoint: url,
            token: config
                .auth
                .api_key
                .clone()
                .context("login before replaying a request")?,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(40))
                .build()?,
        })
    }

    pub async fn send(&self, request: ReplayRequest) -> Result<ReplayResponse> {
        request.clone().validate().map_err(anyhow::Error::msg)?;
        let mut response = self
            .http
            .post(self.endpoint.clone())
            .bearer_auth(&self.token)
            .json(&request)
            .send()
            .await
            .context("replay failed; no automatic retry was sent")?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            ensure!(
                bytes.len() + chunk.len() <= 1024 * 1024,
                "replay response exceeds 1 MiB"
            );
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            // The relay's response is bounded and is never interpolated into HTML.
            bail!(
                "replay rejected ({status}): {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        serde_json::from_slice(&bytes)
            .context("invalid replay response; no automatic retry was sent")
    }
}

pub async fn run(
    config: &Config,
    tunnel: &str,
    file: &Path,
    relay_url: Option<&str>,
) -> Result<()> {
    let id = if uuid::Uuid::parse_str(tunnel).is_ok() {
        tunnel.to_owned()
    } else {
        crate::managed::fetch(config, tunnel).await?.id
    };
    let mut bytes = Vec::new();
    tokio::fs::File::open(file)
        .await?
        .take((MAX_JSON_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        bytes.len() <= MAX_JSON_BYTES,
        "replay draft exceeds 128 KiB"
    );
    let request: ReplayRequest =
        serde_json::from_slice(&bytes).context("invalid replay JSON draft")?;
    let result = ReplayClient::new(config, &id, relay_url)?
        .send(request)
        .await?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}
