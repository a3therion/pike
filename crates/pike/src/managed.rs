//! Saved control-plane configuration is read once per explicit `pike start`.
//! Changed profiles require a restart; relay leases reject stale configuration.
use crate::{
    config::Config,
    tunnel::{
        origin::{OriginOptions, OriginProtocol},
        pool::PoolOptions,
    },
};
use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
pub struct Definition {
    pub id: String,
    pub subdomain: String,
    pub tunnel_type: String,
    pub status: String,
    pub config: Value,
}

pub async fn fetch(config: &Config, name: &str) -> Result<Definition> {
    let name = pike_core::types::SubdomainSpec::new(name.to_lowercase())?;
    let key = config
        .auth
        .api_key
        .as_deref()
        .context("login before starting a saved tunnel")?;
    let mut url = reqwest::Url::parse(&config.relay.api_url)?;
    ensure!(
        url.scheme() == "https"
            || (url.scheme() == "http"
                && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"))),
        "API credentials require HTTPS, except loopback development"
    );
    url.set_path(&format!("/api/v1/tunnels/by-name/{}", name.0));
    url.set_query(None);
    url.set_fragment(None);
    #[derive(Deserialize)]
    struct Response {
        tunnel: Definition,
    }
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()?
        .get(url)
        .bearer_auth(key)
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "cannot load saved tunnel: {}",
        response.status()
    );
    let definition = response.json::<Response>().await?.tunnel;
    ensure!(
        definition.status == "active",
        "tunnel is disabled; enable it in the dashboard first"
    );
    ensure!(
        definition.config.is_object()
            && definition
                .config
                .as_object()
                .is_some_and(|map| !map.is_empty()),
        "configure this tunnel in the dashboard before starting it"
    );
    ensure!(
        definition
            .config
            .get("local_host")
            .and_then(Value::as_str)
            .is_some(),
        "legacy profile: edit and save its configuration in the dashboard before using pike start"
    );
    Ok(definition)
}

#[derive(Deserialize)]
pub struct Settings {
    pub local_host: String,
    pub local_port: Option<u16>,
    #[serde(default)]
    pub origins: Vec<String>,
    pub unix_socket: Option<std::path::PathBuf>,
    pub origin_protocol: Option<String>,
    pub origin_ca: Option<std::path::PathBuf>,
    pub origin_server_name: Option<String>,
    pub health_path: Option<String>,
    pub health_interval: Option<u64>,
    pub health_timeout_ms: Option<u64>,
    pub tls_mode: Option<pike_core::types::TlsMode>,
    pub remote_port: Option<u16>,
    pub idle_timeout_secs: Option<u16>,
}

impl Settings {
    pub fn http_options(&self) -> Result<(OriginOptions, PoolOptions)> {
        let protocol = match self.origin_protocol.as_deref().unwrap_or("auto") {
            "auto" => OriginProtocol::Auto,
            "http1" => OriginProtocol::Http1,
            "http2" => OriginProtocol::Http2,
            _ => bail!("invalid saved origin protocol"),
        };
        Ok((
            OriginOptions {
                upstream: self.origins.clone(),
                unix_socket: self.unix_socket.clone(),
                upstream_protocol: protocol,
                origin_ca: self.origin_ca.clone(),
                origin_server_name: self.origin_server_name.clone(),
            },
            PoolOptions {
                health_path: self.health_path.clone(),
                health_interval: self.health_interval.unwrap_or(5),
                health_timeout_ms: self.health_timeout_ms.unwrap_or(2000),
            },
        ))
    }
}

pub async fn run(mut config: Config, name: &str, max_reconnects: Option<u32>) -> Result<()> {
    let definition = fetch(&config, name).await?;
    let settings: Settings = serde_json::from_value(definition.config.clone())?;
    let cloud = Some(pike_core::types::CloudTunnelConfig {
        name: Some(definition.subdomain.clone()),
        settings_json: Some(serde_json::to_string(&definition.config)?),
    });
    let id = pike_core::types::TunnelId(uuid::Uuid::parse_str(&definition.id)?);
    match definition.tunnel_type.as_str() {
        "http" => {
            let (origin, pool) = settings.http_options()?;
            let pool = crate::tunnel::pool::OriginPool::from_options(
                settings.local_port,
                &settings.local_host,
                origin,
                pool,
            )?;
            let mut tunnel = config
                .as_http_tunnel_config(pool.registration_address(), Some(definition.subdomain));
            tunnel.id = id;
            tunnel.cloud = cloud;
            crate::run_http_command(config, tunnel, pool, None, max_reconnects).await
        }
        "tcp" | "udp" | "tls" => {
            let port = settings
                .local_port
                .context("saved local port is required")?;
            let address =
                tokio::net::lookup_host((settings.local_host.trim_matches(['[', ']']), port))
                    .await?
                    .next()
                    .context("origin has no address")?;
            config.tunnel.bind_addr = address.ip().to_string();
            let mut tunnel = config.as_tcp_tunnel_config(port, settings.remote_port)?;
            tunnel.id = id;
            tunnel.cloud = cloud;
            if definition.tunnel_type == "tls" {
                tunnel.tunnel_type = pike_core::types::TunnelType::Tls {
                    local_port: port,
                    subdomain: definition.subdomain,
                    mode: settings.tls_mode.unwrap_or_default(),
                };
            } else if definition.tunnel_type == "udp" {
                tunnel.tunnel_type = pike_core::types::TunnelType::Udp {
                    local_port: port,
                    remote_port: settings.remote_port,
                    idle_timeout_secs: settings.idle_timeout_secs.unwrap_or(60),
                };
            }
            crate::run_port_command(config, tunnel, port, settings.remote_port, max_reconnects)
                .await
        }
        _ => bail!("unsupported saved tunnel type"),
    }
}
