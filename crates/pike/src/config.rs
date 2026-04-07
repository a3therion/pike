use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::mpsc;

use anyhow::{anyhow, Context, Result};
use notify::{RecursiveMode, Watcher};
use pike_core::types::{TunnelConfig, TunnelId, TunnelType};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub auth: AuthConfig,
    pub relay: RelayConfig,
    pub tunnel: TunnelSection,
    pub inspector: InspectorConfig,
    pub advanced: AdvancedConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    pub addr: String,
    pub ws_fallback: bool,
    pub quic_timeout_ms: u64,
    #[serde(default = "default_api_url")]
    pub api_url: String,
    pub tls_server_name: Option<String>,
    #[serde(default)]
    pub insecure_skip_tls_verify: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelSection {
    pub subdomain_prefix: String,
    pub bind_addr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InspectorConfig {
    pub port: u16,
    pub enabled: bool,
    pub max_requests: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedConfig {
    pub log_level: String,
    pub zero_rtt: bool,
    pub heartbeat_interval: u64,
}

fn default_api_url() -> String {
    "https://api.pike.life".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            auth: AuthConfig { api_key: None },
            relay: RelayConfig {
                addr: "relay.pike.life:443".to_string(),
                ws_fallback: true,
                quic_timeout_ms: 60000,
                api_url: default_api_url(),
                tls_server_name: None,
                insecure_skip_tls_verify: false,
            },
            tunnel: TunnelSection {
                subdomain_prefix: String::new(),
                bind_addr: "127.0.0.1".to_string(),
            },
            inspector: InspectorConfig {
                port: 4040,
                enabled: true,
                max_requests: 500,
            },
            advanced: AdvancedConfig {
                log_level: "info".to_string(),
                zero_rtt: true,
                heartbeat_interval: 15,
            },
        }
    }
}

impl Config {
    pub fn as_http_tunnel_config(
        &self,
        local_host: &str,
        local_port: u16,
        subdomain: Option<String>,
    ) -> Result<TunnelConfig> {
        let local_addr = SocketAddr::from_str(&format!("{local_host}:{local_port}"))
            .with_context(|| format!("invalid bind addr '{local_host}':{local_port}"))?;

        Ok(TunnelConfig {
            id: TunnelId::new(),
            tunnel_type: TunnelType::Http {
                local_port,
                subdomain,
            },
            local_addr,
        })
    }

    pub fn as_tcp_tunnel_config(
        &self,
        local_port: u16,
        remote_port: Option<u16>,
    ) -> Result<TunnelConfig> {
        let local_addr = SocketAddr::from_str(&format!("{}:{local_port}", self.tunnel.bind_addr))
            .with_context(|| {
            format!("invalid bind addr '{}':{local_port}", self.tunnel.bind_addr)
        })?;

        Ok(TunnelConfig {
            id: TunnelId::new(),
            tunnel_type: TunnelType::Tcp {
                local_port,
                remote_port,
            },
            local_addr,
        })
    }
}

pub fn resolve_config_path(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if raw == "~/.pike/config.toml" {
        return default_config_path();
    }
    if let Some(stripped) = raw.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    }

    path.to_path_buf()
}

pub fn default_config_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".pike").join("config.toml")
    } else {
        PathBuf::from(".pike/config.toml")
    }
}

pub async fn load_or_create_config(path: &Path) -> Result<Config> {
    if !path.exists() {
        create_default_config(path).await?;
    }
    load_config(path).await
}

pub async fn create_default_config(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create config directory {}", parent.display()))?;
    }

    let default = Config::default();
    save_config(path, &default).await
}

pub async fn load_config(path: &Path) -> Result<Config> {
    let content = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("failed to read config file {}", path.display()))?;

    let mut cfg: Config = toml::from_str(&content)
        .with_context(|| format!("failed to parse TOML config {}", path.display()))?;

    if cfg.auth.api_key.as_ref().is_some_and(String::is_empty) {
        cfg.auth.api_key = None;
    }

    Ok(cfg)
}

pub async fn save_config(path: &Path, config: &Config) -> Result<()> {
    let content = toml::to_string_pretty(config).context("failed to serialize config")?;
    tokio::fs::write(path, content)
        .await
        .with_context(|| format!("failed to write config file {}", path.display()))
}

pub async fn watch_config<F>(path: PathBuf, on_change: F) -> Result<()>
where
    F: Fn(Config) + Send + Sync + 'static,
{
    tokio::task::spawn_blocking(move || watch_config_blocking(path, on_change))
        .await
        .map_err(|err| anyhow!("watch task failed: {err}"))?
}

fn watch_config_blocking<F>(path: PathBuf, on_change: F) -> Result<()>
where
    F: Fn(Config) + Send + Sync + 'static,
{
    let (tx, rx) = mpsc::channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .context("failed to create config watcher")?;

    watcher
        .watch(&path, RecursiveMode::NonRecursive)
        .with_context(|| format!("failed to watch config path {}", path.display()))?;

    while let Ok(event) = rx.recv() {
        if event.is_ok() {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(mut cfg) = toml::from_str::<Config>(&content) {
                    if cfg.auth.api_key.as_ref().is_some_and(String::is_empty) {
                        cfg.auth.api_key = None;
                    }
                    on_change(cfg);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config_path() -> PathBuf {
        std::env::temp_dir()
            .join(format!("pike-{}", uuid::Uuid::new_v4()))
            .join("config.toml")
    }

    #[tokio::test]
    async fn creates_default_config_if_missing() {
        let path = temp_config_path();
        let cfg = load_or_create_config(&path)
            .await
            .expect("load_or_create_config should succeed");

        assert!(path.exists());
        assert_eq!(cfg.relay.addr, "relay.pike.life:443");
        assert_eq!(cfg.inspector.port, 4040);

        let _ = std::fs::remove_file(&path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }

    #[tokio::test]
    async fn parses_toml_config() {
        let path = temp_config_path();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .expect("create_dir_all should succeed");
        }

        let content = r#"
[auth]
api_key = "pk_test_123"

[relay]
addr = "relay.pike.life:4433"
ws_fallback = true
quic_timeout_ms = 60000

[tunnel]
subdomain_prefix = "my-app"
bind_addr = "127.0.0.1"

[inspector]
port = 4040
enabled = true
max_requests = 500

[advanced]
log_level = "debug"
zero_rtt = true
heartbeat_interval = 15
"#;

        tokio::fs::write(&path, content)
            .await
            .expect("write should succeed");

        let cfg = load_config(&path)
            .await
            .expect("load_config should succeed");
        assert_eq!(cfg.auth.api_key.as_deref(), Some("pk_test_123"));
        assert_eq!(cfg.tunnel.subdomain_prefix, "my-app");
        assert_eq!(cfg.advanced.log_level, "debug");

        let _ = std::fs::remove_file(&path);
        if let Some(parent) = path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }

    #[test]
    fn expands_tilde_config_path() {
        let expanded = resolve_config_path(Path::new("~/.pike/config.toml"));
        assert!(expanded.to_string_lossy().contains(".pike/config.toml"));
    }

    #[test]
    fn http_tunnel_config_ignores_sticky_shared_subdomain_defaults() {
        let mut cfg = Config::default();
        cfg.tunnel.subdomain_prefix = "sticky".to_string();
        cfg.tunnel.bind_addr = "0.0.0.0".to_string();

        let tunnel = cfg
            .as_http_tunnel_config("127.0.0.1", 3000, None)
            .expect("http tunnel config");

        assert_eq!(tunnel.local_addr, "127.0.0.1:3000".parse().unwrap());
        assert!(matches!(
            tunnel.tunnel_type,
            TunnelType::Http {
                local_port: 3000,
                subdomain: None
            }
        ));
    }
}
