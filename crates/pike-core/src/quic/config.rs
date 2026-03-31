use std::path::PathBuf;
use std::time::Duration;

use crate::proto::ALPN_PROTOCOL;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CongestionControlAlgorithm {
    Reno,
    Cubic,
    Bbr,
    Bbr2Gcongestion,
}

impl CongestionControlAlgorithm {
    fn to_quiche(self) -> quiche::CongestionControlAlgorithm {
        match self {
            Self::Reno => quiche::CongestionControlAlgorithm::Reno,
            Self::Cubic => quiche::CongestionControlAlgorithm::CUBIC,
            // BBR maps to Bbr2Gcongestion in quiche 0.24
            Self::Bbr | Self::Bbr2Gcongestion => {
                quiche::CongestionControlAlgorithm::Bbr2Gcongestion
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct PikeQuicConfig {
    pub idle_timeout_ms: u64,
    pub max_concurrent_streams: u64,
    pub max_stream_data: u64,
    pub max_connection_data: u64,
    pub congestion_control: CongestionControlAlgorithm,
    pub enable_early_data: bool,
    pub enable_dgram: bool,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
    pub require_tls: bool,
}

impl Default for PikeQuicConfig {
    fn default() -> Self {
        Self {
            idle_timeout_ms: 60_000,
            max_concurrent_streams: 100,
            max_stream_data: 1_000_000,
            max_connection_data: 10_000_000,
            congestion_control: CongestionControlAlgorithm::Bbr2Gcongestion,
            enable_early_data: true,
            enable_dgram: true,
            cert_path: None,
            key_path: None,
            require_tls: true,
        }
    }
}

impl PikeQuicConfig {
    pub fn with_idle_timeout_ms(mut self, idle_timeout_ms: u64) -> Self {
        self.idle_timeout_ms = idle_timeout_ms;
        self
    }

    pub fn with_max_concurrent_streams(mut self, max_concurrent_streams: u64) -> Self {
        self.max_concurrent_streams = max_concurrent_streams;
        self
    }

    pub fn with_max_stream_data(mut self, max_stream_data: u64) -> Self {
        self.max_stream_data = max_stream_data;
        self
    }

    pub fn with_max_connection_data(mut self, max_connection_data: u64) -> Self {
        self.max_connection_data = max_connection_data;
        self
    }

    pub fn with_congestion_control(
        mut self,
        congestion_control: CongestionControlAlgorithm,
    ) -> Self {
        self.congestion_control = congestion_control;
        self
    }

    pub fn with_early_data(mut self, enable_early_data: bool) -> Self {
        self.enable_early_data = enable_early_data;
        self
    }

    pub fn with_dgram(mut self, enable_dgram: bool) -> Self {
        self.enable_dgram = enable_dgram;
        self
    }

    pub fn with_cert_path(mut self, cert_path: impl Into<PathBuf>) -> Self {
        self.cert_path = Some(cert_path.into());
        self
    }

    pub fn with_key_path(mut self, key_path: impl Into<PathBuf>) -> Self {
        self.key_path = Some(key_path.into());
        self
    }

    pub fn with_require_tls(mut self, require_tls: bool) -> Self {
        self.require_tls = require_tls;
        self
    }

    pub fn to_quiche_config(&self) -> Result<quiche::Config, QuicConfigError> {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
        config.set_application_protos(&[ALPN_PROTOCOL])?;

        let idle_timeout = Duration::from_millis(self.idle_timeout_ms);
        config.set_max_idle_timeout(idle_timeout.as_millis() as u64);
        config.set_initial_max_streams_bidi(self.max_concurrent_streams);
        config.set_initial_max_stream_data_bidi_local(self.max_stream_data);
        config.set_initial_max_stream_data_bidi_remote(self.max_stream_data);
        config.set_initial_max_data(self.max_connection_data);
        config.set_cc_algorithm(self.congestion_control.to_quiche());

        if self.enable_early_data {
            config.enable_early_data();
        }

        if self.enable_dgram {
            config.enable_dgram(true, 64, 64);
        }

        match (&self.cert_path, &self.key_path) {
            (Some(cert_path), Some(key_path)) => {
                let cert_str = cert_path.to_str().ok_or(QuicConfigError::InvalidCertPath)?;
                let key_str = key_path.to_str().ok_or(QuicConfigError::InvalidCertPath)?;
                config.load_cert_chain_from_pem_file(cert_str)?;
                config.load_priv_key_from_pem_file(key_str)?;
            }
            (None, None) => {
                if self.require_tls {
                    return Err(QuicConfigError::TlsRequired);
                }
            }
            _ => return Err(QuicConfigError::IncompleteTlsConfiguration),
        }

        Ok(config)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QuicConfigError {
    #[error("quiche configuration error: {0}")]
    Quiche(#[from] quiche::Error),
    #[error("both cert_path and key_path must be set together")]
    IncompleteTlsConfiguration,
    #[error("TLS certificates are required but not provided")]
    TlsRequired,
    #[error("certificate or key path contains invalid UTF-8")]
    InvalidCertPath,
}

#[cfg(test)]
mod tests {
    use super::{CongestionControlAlgorithm, PikeQuicConfig, QuicConfigError};
    use crate::proto::ALPN_PROTOCOL;

    #[test]
    fn default_config_builds_successfully() {
        let config = PikeQuicConfig::default().with_require_tls(false);
        assert!(config.to_quiche_config().is_ok());
    }

    #[test]
    fn custom_config_builds_successfully() {
        let config = PikeQuicConfig::default()
            .with_idle_timeout_ms(30_000)
            .with_max_concurrent_streams(32)
            .with_max_stream_data(512_000)
            .with_max_connection_data(5_000_000)
            .with_congestion_control(CongestionControlAlgorithm::Cubic)
            .with_early_data(false)
            .with_dgram(false)
            .with_require_tls(false);

        assert!(config.to_quiche_config().is_ok());
    }

    #[test]
    fn alpn_is_set_correctly() {
        let config = PikeQuicConfig::default().with_require_tls(false);
        assert!(config.to_quiche_config().is_ok());
        assert_eq!(ALPN_PROTOCOL, b"pike/1");
    }

    #[test]
    fn bbr2_congestion_control_is_configured() {
        let config = PikeQuicConfig::default()
            .with_congestion_control(CongestionControlAlgorithm::Bbr2Gcongestion)
            .with_require_tls(false);

        assert!(config.to_quiche_config().is_ok());
        assert!(matches!(
            config.congestion_control,
            CongestionControlAlgorithm::Bbr2Gcongestion
        ));
    }

    #[test]
    fn partial_tls_configuration_returns_error() {
        let config = PikeQuicConfig::default().with_cert_path("cert.pem");

        let error = config
            .to_quiche_config()
            .err()
            .expect("expected missing key error");
        assert!(matches!(error, QuicConfigError::IncompleteTlsConfiguration));
    }

    #[test]
    fn test_tls_required_rejects_no_certs() {
        let config = PikeQuicConfig::default().with_require_tls(true);

        let error = config
            .to_quiche_config()
            .err()
            .expect("expected TLS required error");
        assert!(matches!(error, QuicConfigError::TlsRequired));
    }

    #[test]
    fn test_tls_optional_allows_no_certs() {
        let config = PikeQuicConfig::default().with_require_tls(false);

        assert!(config.to_quiche_config().is_ok());
    }
}
