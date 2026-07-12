use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use clap::Parser;
use pike_core::quic::config::{CongestionControlAlgorithm, PikeQuicConfig};
use serde::Deserialize;

use crate::admin::AdminCommand;

const DEFAULT_BIND_ADDR: &str = "[::]:4433";
const DEFAULT_HTTP_BIND_ADDR: &str = "127.0.0.1:8080";
const DEFAULT_MANAGEMENT_BIND_ADDR: &str = "127.0.0.1:9090";
const DEFAULT_HEARTBEAT_TIMEOUT_SECS: u64 = 45;
const DEFAULT_SHUTDOWN_TIMEOUT_SECS: u64 = 30;
const DEFAULT_INTERNAL_TOKEN: &str = "pike-internal-token";
/// Placeholder API key shipped in `deploy/server-vps.toml`; must be replaced before
/// a production start (see fix #11).
const PLACEHOLDER_LOCAL_API_KEY: &str = "pk_self_hosted_replace_me";
const DEFAULT_TUNNEL_CREATIONS_PER_USER_PER_HOUR: u32 = 5;
const DEFAULT_TUNNEL_CREATIONS_PER_IP_PER_HOUR: u32 = 20;
const DEFAULT_AUTO_SUSPEND_REQUESTS_PER_MINUTE: u64 = 1_000;
const DEFAULT_PHISHING_ERROR_RATE_PERCENT: u64 = 90;
const DEFAULT_ABUSE_LOG_RETENTION_DAYS: i64 = 90;
// Privacy: capture is OFF by default so the relay honors the "we do not collect the
// content of tunneled traffic" promise. Operators must explicitly opt in via config,
// and even then query-string values and sensitive headers are redacted (fix #17).
const DEFAULT_CAPTURE_HEADERS: bool = false;
const DEFAULT_CAPTURE_BODIES: bool = false;
const DEFAULT_MAX_BODY_PREVIEW_BYTES: usize = 64 * 1024;
const DEFAULT_DEPLOYMENT_TOPOLOGY: &str = "single-node";
/// End-to-end timeout for a single inbound proxied HTTP request (slow-loris / hung-upstream
/// protection). Applied to the whole request-body read + upstream round-trip + response-body
/// read; WebSocket upgrades are exempt (long-lived by design).
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 30;
/// Maximum buffered request/response body size, both directions. Bodies larger than this are
/// rejected with 413 instead of being buffered into memory (OOM protection). Kept modest because
/// the proxy buffers whole bodies in memory per in-flight request; raise via `max_body_size` in
/// server.toml if a deployment needs larger uploads and has the headroom.
const DEFAULT_MAX_BODY_SIZE: usize = 32 * 1024 * 1024;
/// When false (default), the enforced per-IP identity is the real connection peer IP and any
/// client-supplied `X-Forwarded-For` is ignored (non-spoofable). Set true ONLY when the relay
/// sits behind Cloudflare, in which case the validated `CF-Connecting-IP` header is trusted.
const DEFAULT_TRUST_CLOUDFLARE: bool = false;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub bind_addr: SocketAddr,
    pub http_bind_addr: SocketAddr,
    pub management_bind_addr: SocketAddr,
    pub internal_token: String,
    pub quic_config: PikeQuicConfig,
    pub dev_mode: bool,
    pub control_plane_url: Option<String>,
    pub local_api_keys: Option<Vec<String>>,
    pub workers_api_url: Option<String>,
    pub server_token: Option<String>,
    pub redis_url: Option<String>,
    pub require_redis: bool,
    pub heartbeat_timeout_secs: u64,
    pub shutdown_timeout_secs: u64,
    pub abuse: AbuseConfig,
    pub traffic_inspection: TrafficInspectionConfig,
    pub deployment_topology: DeploymentTopology,
    pub domain: String,
    pub max_connections: usize,
    pub max_tunnels_per_connection: usize,
    /// End-to-end inbound request timeout in seconds (fix: no inbound request timeout).
    pub request_timeout_secs: u64,
    /// Maximum buffered body size in bytes, both directions (fix: uncapped body buffering).
    pub max_body_size: usize,
    /// Trust Cloudflare's `CF-Connecting-IP` for per-IP limiting (fix: XFF-spoofable IP).
    pub trust_cloudflare: bool,
    /// Sentry DSN for error monitoring; `None`/empty disables Sentry entirely (fix #6).
    pub sentry_dsn: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AbuseConfig {
    pub tunnel_creations_per_user_per_hour: u32,
    pub tunnel_creations_per_ip_per_hour: u32,
    pub auto_suspend_requests_per_minute: u64,
    pub phishing_error_rate_percent: u64,
    pub abuse_log_retention_days: i64,
    pub webhook_url: Option<String>,
    /// Mirrors the top-level `require_redis`. When true, a failed ban-status lookup
    /// against the state store is logged loudly (fix #9) rather than silently ignored.
    pub require_redis: bool,
}

#[derive(Debug, Clone)]
pub struct TrafficInspectionConfig {
    pub capture_headers: bool,
    pub capture_bodies: bool,
    pub max_body_preview_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentTopology {
    SingleNode,
}

impl DeploymentTopology {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SingleNode => DEFAULT_DEPLOYMENT_TOPOLOGY,
        }
    }
}

impl Default for AbuseConfig {
    fn default() -> Self {
        Self {
            tunnel_creations_per_user_per_hour: DEFAULT_TUNNEL_CREATIONS_PER_USER_PER_HOUR,
            tunnel_creations_per_ip_per_hour: DEFAULT_TUNNEL_CREATIONS_PER_IP_PER_HOUR,
            auto_suspend_requests_per_minute: DEFAULT_AUTO_SUSPEND_REQUESTS_PER_MINUTE,
            phishing_error_rate_percent: DEFAULT_PHISHING_ERROR_RATE_PERCENT,
            abuse_log_retention_days: DEFAULT_ABUSE_LOG_RETENTION_DAYS,
            webhook_url: None,
            require_redis: false,
        }
    }
}

impl Default for TrafficInspectionConfig {
    fn default() -> Self {
        Self {
            capture_headers: DEFAULT_CAPTURE_HEADERS,
            capture_bodies: DEFAULT_CAPTURE_BODIES,
            max_body_preview_bytes: DEFAULT_MAX_BODY_PREVIEW_BYTES,
        }
    }
}

#[derive(Debug, Parser, Clone)]
#[command(author, version, about = "Pike relay server")]
pub struct CliArgs {
    #[arg(long, default_value = "config/server.toml")]
    pub config: PathBuf,
    #[arg(long)]
    pub dev_mode: bool,
    #[command(subcommand)]
    pub command: Option<AdminCommand>,
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    bind_addr: Option<SocketAddr>,
    http_bind_addr: Option<SocketAddr>,
    management_bind_addr: Option<SocketAddr>,
    metrics_bind_addr: Option<SocketAddr>,
    internal_token: Option<String>,
    control_plane_url: Option<String>,
    local_api_keys: Option<Vec<String>>,
    workers_api_url: Option<String>,
    server_token: Option<String>,
    redis_url: Option<String>,
    require_redis: Option<bool>,
    heartbeat_timeout_secs: Option<u64>,
    shutdown_timeout_secs: Option<u64>,
    domain: Option<String>,
    deployment_topology: Option<String>,
    max_connections: Option<usize>,
    max_tunnels_per_connection: Option<usize>,
    request_timeout_secs: Option<u64>,
    max_body_size: Option<usize>,
    trust_cloudflare: Option<bool>,
    sentry_dsn: Option<String>,
    quic: Option<QuicConfigFile>,
    abuse: Option<AbuseConfigFile>,
    traffic_inspection: Option<TrafficInspectionConfigFile>,
}

#[derive(Debug, Deserialize)]
struct AbuseConfigFile {
    tunnel_creations_per_user_per_hour: Option<u32>,
    tunnel_creations_per_ip_per_hour: Option<u32>,
    auto_suspend_requests_per_minute: Option<u64>,
    phishing_error_rate_percent: Option<u64>,
    abuse_log_retention_days: Option<i64>,
    webhook_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TrafficInspectionConfigFile {
    capture_headers: Option<bool>,
    capture_bodies: Option<bool>,
    max_body_preview_bytes: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct QuicConfigFile {
    idle_timeout_ms: Option<u64>,
    max_concurrent_streams: Option<u64>,
    max_stream_data: Option<u64>,
    max_connection_data: Option<u64>,
    congestion_control: Option<String>,
    enable_early_data: Option<bool>,
    enable_dgram: Option<bool>,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
}

impl ServerConfig {
    pub fn from_file(path: impl AsRef<Path>, dev_mode: bool) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file at {}", path.display()))?;
        let parsed: FileConfig = toml::from_str(&raw)
            .with_context(|| format!("failed to parse TOML config from {}", path.display()))?;

        let default_bind: SocketAddr = DEFAULT_BIND_ADDR
            .parse()
            .expect("default bind addr must be valid");
        let default_http_bind: SocketAddr = DEFAULT_HTTP_BIND_ADDR
            .parse()
            .expect("default HTTP bind addr must be valid");
        let default_management_bind: SocketAddr = DEFAULT_MANAGEMENT_BIND_ADDR
            .parse()
            .expect("default management bind addr must be valid");

        let mut quic = PikeQuicConfig::default();
        if let Some(quic_cfg) = parsed.quic {
            if let Some(value) = quic_cfg.idle_timeout_ms {
                quic.idle_timeout_ms = value;
            }
            if let Some(value) = quic_cfg.max_concurrent_streams {
                quic.max_concurrent_streams = value;
            }
            if let Some(value) = quic_cfg.max_stream_data {
                quic.max_stream_data = value;
            }
            if let Some(value) = quic_cfg.max_connection_data {
                quic.max_connection_data = value;
            }
            if let Some(value) = quic_cfg.enable_early_data {
                quic.enable_early_data = value;
            }
            if let Some(value) = quic_cfg.enable_dgram {
                quic.enable_dgram = value;
            }
            if let Some(value) = quic_cfg.cert_path {
                quic.cert_path = Some(value);
            }
            if let Some(value) = quic_cfg.key_path {
                quic.key_path = Some(value);
            }
            if let Some(value) = quic_cfg.congestion_control {
                quic.congestion_control = parse_cc_algorithm(&value)?;
            }
        }
        ensure_tls_assets(&quic, dev_mode)?;

        let control_plane_url = parsed.control_plane_url;
        let local_api_keys = parsed.local_api_keys;
        let deployment_topology = parse_deployment_topology(parsed.deployment_topology.as_deref())?;
        // Fail-safe default (fix #16): in production mode require_redis defaults to `true`
        // so a misconfigured instance refuses to silently fall back to in-memory state
        // (which resets bandwidth/ban counters on restart). Operators who genuinely want
        // in-memory state in production must set `require_redis = false` explicitly.
        // Dev mode keeps the permissive default of `false`.
        let require_redis = parsed.require_redis.unwrap_or(!dev_mode);

        if !dev_mode && control_plane_url.is_none() && local_api_keys.is_none() {
            anyhow::bail!("production mode requires either control_plane_url or local_api_keys");
        }

        let internal_token = parsed
            .internal_token
            .filter(|token| !token.trim().is_empty())
            .or_else(|| {
                if dev_mode {
                    Some(DEFAULT_INTERNAL_TOKEN.to_string())
                } else {
                    None
                }
            })
            .context("internal_token is required when not running in --dev-mode")?;

        if !dev_mode
            && (internal_token == DEFAULT_INTERNAL_TOKEN || is_placeholder_secret(&internal_token))
        {
            anyhow::bail!(
                "internal_token cannot be the default/placeholder value in production mode. \
                 Please set a custom internal_token in your config file."
            );
        }

        // Fix #11: refuse to start in production with placeholder/empty secrets that ship
        // in deploy/server-vps.toml. These would otherwise silently authenticate anyone.
        if !dev_mode {
            if let Some(server_token) = parsed.server_token.as_deref() {
                if server_token.trim().is_empty() || is_placeholder_secret(server_token) {
                    anyhow::bail!(
                        "server_token is empty or still set to a placeholder value in production \
                         mode. Remove it (if you are not using a remote control plane) or set a \
                         real secret."
                    );
                }
            }

            if let Some(local_keys) = local_api_keys.as_deref() {
                if local_keys.iter().any(|key| {
                    key.trim().is_empty()
                        || key.trim() == PLACEHOLDER_LOCAL_API_KEY
                        || is_placeholder_secret(key)
                }) {
                    anyhow::bail!(
                        "local_api_keys still contains the shipped placeholder \
                         ('{PLACEHOLDER_LOCAL_API_KEY}') or an empty/placeholder key in production \
                         mode. Replace it with a real API key before starting."
                    );
                }
            }
        }

        // Enforced after secret validation so misconfigured secrets surface first.
        if require_redis && parsed.redis_url.is_none() {
            anyhow::bail!("require_redis = true requires redis_url to be configured (require_redis defaults to true in production; set it to false explicitly to opt into in-memory state)");
        }

        Ok(Self {
            bind_addr: parsed.bind_addr.unwrap_or(default_bind),
            http_bind_addr: parsed.http_bind_addr.unwrap_or(default_http_bind),
            management_bind_addr: parsed
                .management_bind_addr
                .or(parsed.metrics_bind_addr)
                .unwrap_or(default_management_bind),
            internal_token,
            quic_config: quic,
            dev_mode,
            control_plane_url: control_plane_url.clone(),
            local_api_keys,
            workers_api_url: parsed.workers_api_url.or(control_plane_url),
            server_token: parsed.server_token,
            redis_url: parsed.redis_url,
            require_redis,
            heartbeat_timeout_secs: parsed
                .heartbeat_timeout_secs
                .unwrap_or(DEFAULT_HEARTBEAT_TIMEOUT_SECS),
            shutdown_timeout_secs: parsed
                .shutdown_timeout_secs
                .unwrap_or(DEFAULT_SHUTDOWN_TIMEOUT_SECS),
            abuse: parse_abuse_config(parsed.abuse, require_redis),
            traffic_inspection: parse_traffic_inspection_config(parsed.traffic_inspection),
            deployment_topology,
            domain: parsed.domain.unwrap_or_else(|| "pike.life".to_string()),
            max_connections: parsed.max_connections.unwrap_or(1000),
            max_tunnels_per_connection: parsed.max_tunnels_per_connection.unwrap_or(10),
            request_timeout_secs: parsed
                .request_timeout_secs
                .unwrap_or(DEFAULT_REQUEST_TIMEOUT_SECS),
            max_body_size: parsed.max_body_size.unwrap_or(DEFAULT_MAX_BODY_SIZE),
            trust_cloudflare: parsed.trust_cloudflare.unwrap_or(DEFAULT_TRUST_CLOUDFLARE),
            // Prefer the config file value, else fall back to the SENTRY_DSN env var. An empty
            // string is normalized to None so Sentry stays a no-op when unset (fix #6).
            sentry_dsn: parsed
                .sentry_dsn
                .or_else(|| std::env::var("SENTRY_DSN").ok())
                .map(|dsn| dsn.trim().to_string())
                .filter(|dsn| !dsn.is_empty()),
        })
    }
}

fn ensure_tls_assets(quic: &PikeQuicConfig, dev_mode: bool) -> Result<()> {
    if !dev_mode {
        return Ok(());
    }

    let (Some(cert_path), Some(key_path)) = (quic.cert_path.as_ref(), quic.key_path.as_ref())
    else {
        return Ok(());
    };

    if cert_path.exists() && key_path.exists() {
        return Ok(());
    }

    generate_dev_tls_assets(cert_path, key_path)
}

fn generate_dev_tls_assets(cert_path: &Path, key_path: &Path) -> Result<()> {
    if let Some(parent) = cert_path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create certificate directory {}",
                parent.display()
            )
        })?;
    }
    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create key directory {}", parent.display()))?;
    }

    let output = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            &key_path.to_string_lossy(),
            "-out",
            &cert_path.to_string_lossy(),
            "-days",
            "365",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
        ])
        .output()
        .context("failed to invoke openssl for dev TLS generation")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("failed to generate dev TLS certificate: {stderr}");
    }

    Ok(())
}

fn parse_abuse_config(parsed: Option<AbuseConfigFile>, require_redis: bool) -> AbuseConfig {
    let defaults = AbuseConfig::default();
    let Some(parsed) = parsed else {
        return AbuseConfig {
            require_redis,
            ..defaults
        };
    };

    AbuseConfig {
        tunnel_creations_per_user_per_hour: parsed
            .tunnel_creations_per_user_per_hour
            .unwrap_or(defaults.tunnel_creations_per_user_per_hour),
        tunnel_creations_per_ip_per_hour: parsed
            .tunnel_creations_per_ip_per_hour
            .unwrap_or(defaults.tunnel_creations_per_ip_per_hour),
        auto_suspend_requests_per_minute: parsed
            .auto_suspend_requests_per_minute
            .unwrap_or(defaults.auto_suspend_requests_per_minute),
        phishing_error_rate_percent: parsed
            .phishing_error_rate_percent
            .unwrap_or(defaults.phishing_error_rate_percent),
        abuse_log_retention_days: parsed
            .abuse_log_retention_days
            .unwrap_or(defaults.abuse_log_retention_days),
        webhook_url: parsed.webhook_url,
        require_redis,
    }
}

fn parse_traffic_inspection_config(
    parsed: Option<TrafficInspectionConfigFile>,
) -> TrafficInspectionConfig {
    let defaults = TrafficInspectionConfig::default();
    let Some(parsed) = parsed else {
        return defaults;
    };

    TrafficInspectionConfig {
        capture_headers: parsed.capture_headers.unwrap_or(defaults.capture_headers),
        capture_bodies: parsed.capture_bodies.unwrap_or(defaults.capture_bodies),
        max_body_preview_bytes: parsed
            .max_body_preview_bytes
            .unwrap_or(defaults.max_body_preview_bytes),
    }
}

fn parse_deployment_topology(parsed: Option<&str>) -> Result<DeploymentTopology> {
    let normalized = parsed.unwrap_or(DEFAULT_DEPLOYMENT_TOPOLOGY).trim();
    match normalized {
        "single-node" | "single_node" | "single" => Ok(DeploymentTopology::SingleNode),
        _ => anyhow::bail!(
            "unsupported deployment_topology: {normalized}; only \"single-node\" is supported until distributed tunnel routing is implemented"
        ),
    }
}

/// Returns true if `value` looks like a shipped placeholder secret that an operator
/// forgot to replace (e.g. the `CHANGE_ME_*` / `*replace_me*` tokens in the deploy
/// templates). Used to fail-closed on startup in production (fix #11).
fn is_placeholder_secret(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.contains("change_me")
        || normalized.contains("changeme")
        || normalized.contains("replace_me")
        || normalized.contains("replaceme")
}

fn parse_cc_algorithm(value: &str) -> Result<CongestionControlAlgorithm> {
    let normalized = value.trim().to_ascii_lowercase();
    let parsed = match normalized.as_str() {
        "reno" => CongestionControlAlgorithm::Reno,
        "cubic" => CongestionControlAlgorithm::Cubic,
        "bbr" => CongestionControlAlgorithm::Bbr,
        "bbr2" | "bbr2gcongestion" => CongestionControlAlgorithm::Bbr2Gcongestion,
        _ => anyhow::bail!("unsupported congestion_control: {value}"),
    };
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::ServerConfig;

    fn write_temp_config(contents: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("pike-server-config-{}.toml", uuid::Uuid::new_v4()));
        fs::write(&path, contents).expect("write temp config");
        path
    }

    #[test]
    fn parses_toml_config_with_quic_fields() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
http_bind_addr = "127.0.0.1:8080"
management_bind_addr = "127.0.0.1:9090"
internal_token = "dashboard-secret"
control_plane_url = "https://cp.pike.life"
require_redis = false
heartbeat_timeout_secs = 50
shutdown_timeout_secs = 33

[quic]
idle_timeout_ms = 20000
max_concurrent_streams = 128
congestion_control = "cubic"
enable_early_data = false
"#,
        );

        let config = ServerConfig::from_file(&path, false).expect("config parsed");
        assert_eq!(config.bind_addr.to_string(), "127.0.0.1:7443");
        assert_eq!(config.http_bind_addr.to_string(), "127.0.0.1:8080");
        assert_eq!(config.management_bind_addr.to_string(), "127.0.0.1:9090");
        assert_eq!(config.internal_token, "dashboard-secret");
        assert_eq!(
            config.control_plane_url.as_deref(),
            Some("https://cp.pike.life")
        );
        assert_eq!(config.heartbeat_timeout_secs, 50);
        assert_eq!(config.shutdown_timeout_secs, 33);
        assert_eq!(config.quic_config.idle_timeout_ms, 20_000);
        assert_eq!(config.quic_config.max_concurrent_streams, 128);
        assert!(!config.quic_config.enable_early_data);
        assert!(!config.traffic_inspection.capture_headers);
        assert!(!config.traffic_inspection.capture_bodies);
        assert_eq!(config.traffic_inspection.max_body_preview_bytes, 64 * 1024);
        assert_eq!(
            config.deployment_topology.as_str(),
            super::DEFAULT_DEPLOYMENT_TOPOLOGY
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn dev_mode_allows_missing_control_plane_url() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
"#,
        );

        let config = ServerConfig::from_file(&path, true).expect("dev config parsed");
        assert!(config.dev_mode);
        assert!(config.control_plane_url.is_none());
        assert_eq!(config.management_bind_addr.to_string(), "127.0.0.1:9090");
        assert_eq!(config.internal_token, "pike-internal-token");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn production_mode_requires_auth_source() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
internal_token = "custom-token"
"#,
        );

        let result = ServerConfig::from_file(&path, false);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("production mode requires either control_plane_url or local_api_keys")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn production_mode_accepts_local_api_keys_without_control_plane_url() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
internal_token = "custom-token"
local_api_keys = ["pk_test_abc123"]
require_redis = false
"#,
        );

        let config = ServerConfig::from_file(&path, false).expect("config parsed");
        assert_eq!(
            config.local_api_keys,
            Some(vec!["pk_test_abc123".to_string()])
        );
        assert!(config.control_plane_url.is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn production_mode_requires_internal_token() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
control_plane_url = "https://cp.pike.life"
"#,
        );

        let result = ServerConfig::from_file(&path, false);
        assert!(result.is_err());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_rejects_default_token_in_production() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
control_plane_url = "https://cp.pike.life"
internal_token = "pike-internal-token"
"#,
        );

        let result = ServerConfig::from_file(&path, false);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cannot be the default"),
            "expected error about default token, got: {err_msg}"
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_accepts_custom_token_in_production() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
control_plane_url = "https://cp.pike.life"
internal_token = "my-custom-secret-token"
require_redis = false
"#,
        );

        let config = ServerConfig::from_file(&path, false).expect("config should parse");
        assert_eq!(config.internal_token, "my-custom-secret-token");
        assert!(!config.dev_mode);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_dev_mode_accepts_default_token() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
internal_token = "pike-internal-token"
"#,
        );

        let config = ServerConfig::from_file(&path, true).expect("dev config should parse");
        assert_eq!(config.internal_token, "pike-internal-token");
        assert!(config.dev_mode);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn parses_custom_traffic_inspection_config() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
control_plane_url = "https://cp.pike.life"
internal_token = "dashboard-secret"
require_redis = false

[traffic_inspection]
capture_headers = false
capture_bodies = true
max_body_preview_bytes = 2048
"#,
        );

        let config = ServerConfig::from_file(&path, false).expect("config should parse");
        assert!(!config.traffic_inspection.capture_headers);
        assert!(config.traffic_inspection.capture_bodies);
        assert_eq!(config.traffic_inspection.max_body_preview_bytes, 2048);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn parses_supported_deployment_topology() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
control_plane_url = "https://cp.pike.life"
internal_token = "dashboard-secret"
require_redis = false
deployment_topology = "single-node"
"#,
        );

        let config = ServerConfig::from_file(&path, false).expect("config should parse");
        assert_eq!(
            config.deployment_topology,
            super::DeploymentTopology::SingleNode
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_unsupported_deployment_topology() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
control_plane_url = "https://cp.pike.life"
internal_token = "dashboard-secret"
deployment_topology = "multi-node"
"#,
        );

        let result = ServerConfig::from_file(&path, false);
        assert!(result.is_err());
        let err = result.expect_err("config should fail").to_string();
        assert!(err.contains("unsupported deployment_topology"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn require_redis_true_requires_redis_url() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
control_plane_url = "https://cp.pike.life"
internal_token = "dashboard-secret"
require_redis = true
"#,
        );

        let result = ServerConfig::from_file(&path, false);
        assert!(result.is_err());
        let err = result.expect_err("config should fail").to_string();
        assert!(err.contains("require_redis = true requires redis_url"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_placeholder_local_api_key_in_production() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
internal_token = "dashboard-secret"
local_api_keys = ["pk_self_hosted_replace_me"]
require_redis = false
"#,
        );

        let result = ServerConfig::from_file(&path, false);
        assert!(result.is_err());
        let err = result.expect_err("config should fail").to_string();
        assert!(err.contains("local_api_keys"), "unexpected error: {err}");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_placeholder_server_token_in_production() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
control_plane_url = "https://cp.pike.life"
internal_token = "dashboard-secret"
server_token = "CHANGE_ME_IF_USING_REMOTE_CONTROL_PLANE"
require_redis = false
"#,
        );

        let result = ServerConfig::from_file(&path, false);
        assert!(result.is_err());
        let err = result.expect_err("config should fail").to_string();
        assert!(err.contains("server_token"), "unexpected error: {err}");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn require_redis_defaults_true_in_production() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
control_plane_url = "https://cp.pike.life"
internal_token = "dashboard-secret"
"#,
        );

        // No require_redis and no redis_url: production must refuse to start (fail-safe).
        let result = ServerConfig::from_file(&path, false);
        assert!(result.is_err());
        let err = result.expect_err("config should fail").to_string();
        assert!(err.contains("require_redis"), "unexpected error: {err}");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn dev_mode_require_redis_defaults_false() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
"#,
        );

        let config = ServerConfig::from_file(&path, true).expect("dev config should parse");
        assert!(!config.require_redis);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn parses_required_redis_configuration() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
control_plane_url = "https://cp.pike.life"
internal_token = "dashboard-secret"
require_redis = true
redis_url = "redis://127.0.0.1:6379/0"
"#,
        );

        let config = ServerConfig::from_file(&path, false).expect("config should parse");
        assert!(config.require_redis);
        assert_eq!(
            config.redis_url.as_deref(),
            Some("redis://127.0.0.1:6379/0")
        );

        let _ = fs::remove_file(path);
    }
}
