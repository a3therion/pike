//! Shared type definitions used across pike-core, pike-server, and pike.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ────────────────────────────────────────────
// Reserved Subdomains
// ────────────────────────────────────────────

/// List of reserved subdomains that cannot be used for tunnels.
const RESERVED_SUBDOMAINS: &[&str] = &[
    "admin",
    "api",
    "www",
    "mail",
    "dashboard",
    "app",
    "status",
    "health",
    "metrics",
    "ftp",
    "ssh",
    "smtp",
    "imap",
    "pop3",
    "ns1",
    "ns2",
    "localhost",
    "pike",
    "internal",
];

// ────────────────────────────────────────────
// Tunnel Identification
// ────────────────────────────────────────────

/// Unique identifier for a tunnel instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TunnelId(pub Uuid);

impl TunnelId {
    /// Create a new random tunnel ID.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for TunnelId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TunnelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A subdomain specification, e.g. "my-app" → my-app.pike.life
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubdomainSpec(pub String);

impl SubdomainSpec {
    /// Create a new subdomain spec, validating the format.
    ///
    /// # Errors
    ///
    /// Returns `PikeError::ConfigError` if:
    /// - The subdomain is empty
    /// - The subdomain exceeds 63 characters
    /// - The subdomain contains invalid characters (only alphanumeric and hyphens allowed)
    /// - The subdomain starts or ends with a hyphen
    /// - The subdomain is reserved
    pub fn new(subdomain: impl Into<String>) -> Result<Self, PikeError> {
        let s = subdomain.into();
        if s.is_empty() {
            return Err(PikeError::ConfigError("subdomain cannot be empty".into()));
        }
        if s.len() > 63 {
            return Err(PikeError::ConfigError(
                "subdomain too long (max 63 chars)".into(),
            ));
        }
        if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err(PikeError::ConfigError(
                "subdomain can only contain alphanumeric characters and hyphens".into(),
            ));
        }
        if s.starts_with('-') || s.ends_with('-') {
            return Err(PikeError::ConfigError(
                "subdomain cannot start or end with a hyphen".into(),
            ));
        }
        let s_lower = s.to_lowercase();
        if RESERVED_SUBDOMAINS.contains(&s_lower.as_str()) {
            return Err(PikeError::ConfigError(format!(
                "subdomain '{}' is reserved",
                s_lower
            )));
        }
        Ok(Self(s))
    }

    /// Get the full domain name.
    #[must_use]
    pub fn full_domain(&self, base_domain: &str) -> String {
        format!("{}.{base_domain}", self.0)
    }
}

impl fmt::Display for SubdomainSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ────────────────────────────────────────────
// Tunnel Configuration
// ────────────────────────────────────────────

/// The type of tunnel being created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TunnelType {
    /// HTTP/HTTPS tunnel with optional subdomain.
    Http {
        local_port: u16,
        subdomain: Option<String>,
    },
    /// Raw TCP tunnel with optional remote port.
    Tcp {
        local_port: u16,
        remote_port: Option<u16>,
    },
}

/// Configuration for a single tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelConfig {
    pub id: TunnelId,
    pub tunnel_type: TunnelType,
    pub local_addr: SocketAddr,
}

// ────────────────────────────────────────────
// Authentication
// ────────────────────────────────────────────

/// An API key for authenticating with the relay server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKey(pub String);

impl ApiKey {
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Mask the key for security in logs
        if self.0.len() > 8 {
            write!(f, "{}...{}", &self.0[..4], &self.0[self.0.len() - 4..])
        } else {
            write!(f, "****")
        }
    }
}

/// A session auth token received after login.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthToken(pub String);

// ────────────────────────────────────────────
// Server Information
// ────────────────────────────────────────────

/// Information about a relay server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    pub addr: SocketAddr,
    pub region: String,
    pub version: String,
}

// ────────────────────────────────────────────
// Statistics
// ────────────────────────────────────────────

/// Runtime statistics for a tunnel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunnelStats {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connections: u64,
    pub uptime_secs: u64,
}

impl TunnelStats {
    /// Get uptime as a Duration.
    #[must_use]
    pub fn uptime(&self) -> Duration {
        Duration::from_secs(self.uptime_secs)
    }

    /// Get total bytes transferred.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.bytes_in + self.bytes_out
    }
}

// ────────────────────────────────────────────
// Errors
// ────────────────────────────────────────────

/// Pike-specific error type.
#[derive(Debug, thiserror::Error)]
pub enum PikeError {
    #[error("QUIC error: {0}")]
    QuicError(String),

    #[error("authentication error: {0}")]
    AuthError(String),

    #[error("tunnel error: {0}")]
    TunnelError(String),

    #[error("configuration error: {0}")]
    ConfigError(String),

    #[error("protocol error: {0}")]
    ProtocolError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}

// ────────────────────────────────────────────
// Constants
// ────────────────────────────────────────────

/// Protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

/// ALPN protocol identifier for QUIC negotiation.
pub const ALPN_PROTOCOL: &[u8] = b"pike/1";

/// Default base domain for subdomains.
pub const DEFAULT_BASE_DOMAIN: &str = "pike.life";

/// Default heartbeat interval.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

/// Default heartbeat timeout (3 missed heartbeats).
pub const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(45);

// ────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_id_roundtrip() {
        let id = TunnelId::new();
        let bytes = postcard::to_allocvec(&id).unwrap();
        let deserialized: TunnelId = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(id, deserialized);
    }

    #[test]
    fn tunnel_config_roundtrip() {
        let config = TunnelConfig {
            id: TunnelId::new(),
            tunnel_type: TunnelType::Http {
                local_port: 3000,
                subdomain: Some("my-app".into()),
            },
            local_addr: "127.0.0.1:3000".parse().unwrap(),
        };
        let bytes = postcard::to_allocvec(&config).unwrap();
        let deserialized: TunnelConfig = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(config.id, deserialized.id);
    }

    #[test]
    fn tunnel_type_tcp_roundtrip() {
        let tt = TunnelType::Tcp {
            local_port: 5432,
            remote_port: Some(15432),
        };
        let bytes = postcard::to_allocvec(&tt).unwrap();
        let deserialized: TunnelType = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(tt, deserialized);
    }

    #[test]
    fn api_key_display_masks() {
        let key = ApiKey("pk_live_1234567890abcdef".into());
        let display = format!("{key}");
        assert!(display.contains("..."));
        assert!(!display.contains("1234567890"));
    }

    #[test]
    fn subdomain_validation() {
        assert!(SubdomainSpec::new("my-app").is_ok());
        assert!(SubdomainSpec::new("hello123").is_ok());
        assert!(SubdomainSpec::new("").is_err());
        assert!(SubdomainSpec::new("-bad").is_err());
        assert!(SubdomainSpec::new("bad-").is_err());
        assert!(SubdomainSpec::new("has space").is_err());
        assert!(SubdomainSpec::new("has_underscore").is_err());
    }

    #[test]
    fn subdomain_full_domain() {
        let sub = SubdomainSpec::new("my-app").unwrap();
        assert_eq!(sub.full_domain("pike.life"), "my-app.pike.life");
    }

    #[test]
    fn test_rejects_reserved_subdomain() {
        assert!(SubdomainSpec::new("admin").is_err());
        assert!(SubdomainSpec::new("api").is_err());
        assert!(SubdomainSpec::new("www").is_err());
        assert!(SubdomainSpec::new("dashboard").is_err());
        assert!(SubdomainSpec::new("pike").is_err());
        assert!(SubdomainSpec::new("internal").is_err());
        let err = SubdomainSpec::new("admin").unwrap_err();
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn test_accepts_valid_subdomain() {
        assert!(SubdomainSpec::new("my-app").is_ok());
        assert!(SubdomainSpec::new("hello123").is_ok());
        assert!(SubdomainSpec::new("test-service").is_ok());
        assert!(SubdomainSpec::new("prod").is_ok());
        let spec = SubdomainSpec::new("my-service").unwrap();
        assert_eq!(spec.0, "my-service");
    }

    #[test]
    fn test_subdomain_format_validation() {
        assert!(SubdomainSpec::new("").is_err());
        assert!(SubdomainSpec::new("-bad").is_err());
        assert!(SubdomainSpec::new("bad-").is_err());
        assert!(SubdomainSpec::new("has space").is_err());
        assert!(SubdomainSpec::new("has_underscore").is_err());
        assert!(SubdomainSpec::new("a".repeat(64).as_str()).is_err());
    }

    #[test]
    fn tunnel_stats_total() {
        let stats = TunnelStats {
            bytes_in: 100,
            bytes_out: 200,
            connections: 5,
            uptime_secs: 60,
        };
        assert_eq!(stats.total_bytes(), 300);
        assert_eq!(stats.uptime(), Duration::from_secs(60));
    }

    #[test]
    fn relay_info_roundtrip() {
        let info = RelayInfo {
            addr: "1.2.3.4:4433".parse().unwrap(),
            region: "ap-south-1".into(),
            version: "0.1.0".into(),
        };
        let bytes = postcard::to_allocvec(&info).unwrap();
        let deserialized: RelayInfo = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(info.region, deserialized.region);
    }

    #[test]
    fn pike_error_display() {
        let err = PikeError::AuthError("invalid key".into());
        assert_eq!(err.to_string(), "authentication error: invalid key");
    }
}
