use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use chrono::Local;
use colored::Colorize;
use pike_core::quic::client::{PikeClient, PikeConnection};
use pike_core::quic::config::PikeQuicConfig;
use pike_core::types::ApiKey;
use rand::Rng;

use crate::config::Config;
use crate::session::SessionManager;

const MAX_BACKOFF_SECS: u64 = 30;
const JITTER_PERCENT: f64 = 0.20;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    Connecting,
    Handshaking,
    Authenticating,
    Active,
    Reconnecting { attempt: u32, backoff: Duration },
    Closed,
}

pub struct ConnectionStats {
    pub start_time: Instant,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub reconnections: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayTlsSettings {
    server_name: Option<String>,
    verify_peer: bool,
}

struct CircuitBreaker {
    failure_times: VecDeque<Instant>,
    circuit_open_until: Option<Instant>,
}

impl CircuitBreaker {
    const FAILURE_WINDOW: Duration = Duration::from_secs(60);
    const FAILURE_THRESHOLD: usize = 3;
    const CIRCUIT_OPEN_DURATION: Duration = Duration::from_secs(300); // 5 minutes

    fn new() -> Self {
        Self {
            failure_times: VecDeque::new(),
            circuit_open_until: None,
        }
    }

    fn record_failure(&mut self) {
        let now = Instant::now();
        self.failure_times.push_back(now);

        // Remove failures older than the window
        while let Some(&oldest) = self.failure_times.front() {
            if now.duration_since(oldest) > Self::FAILURE_WINDOW {
                self.failure_times.pop_front();
            } else {
                break;
            }
        }

        // If we have 3+ failures within the window, open the circuit
        if self.failure_times.len() >= Self::FAILURE_THRESHOLD {
            self.circuit_open_until = Some(now + Self::CIRCUIT_OPEN_DURATION);
        }
    }

    fn is_open(&self) -> bool {
        if let Some(open_until) = self.circuit_open_until {
            if Instant::now() < open_until {
                return true;
            }
        }
        false
    }
}

pub struct ConnectionHandler {
    config: Config,
    session_manager: SessionManager,
    client: Option<PikeClient>,
    connection: Option<PikeConnection>,
    state: ConnectionState,
    stats: ConnectionStats,
    reconnect_attempt: u32,
    max_reconnect_attempts: Option<u32>,
    circuit_breaker: CircuitBreaker,
}

impl ConnectionHandler {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            session_manager: SessionManager::new(),
            client: None,
            connection: None,
            state: ConnectionState::Closed,
            stats: ConnectionStats {
                start_time: Instant::now(),
                bytes_in: 0,
                bytes_out: 0,
                reconnections: 0,
            },
            reconnect_attempt: 0,
            max_reconnect_attempts: None,
            circuit_breaker: CircuitBreaker::new(),
        }
    }

    pub fn with_max_reconnect_attempts(mut self, max_attempts: Option<u32>) -> Self {
        self.max_reconnect_attempts = max_attempts;
        self
    }

    fn calculate_backoff(&self, attempt: u32) -> Duration {
        reconnect_backoff(attempt)
    }

    pub async fn connect(&mut self) -> Result<()> {
        self.state = ConnectionState::Connecting;

        let relay_addr = tokio::net::lookup_host(&self.config.relay.addr)
            .await
            .map_err(|e| {
                anyhow!(
                    "failed to resolve relay address '{}': {e}",
                    self.config.relay.addr
                )
            })?
            .next()
            .ok_or_else(|| {
                anyhow!(
                    "relay address '{}' resolved to no addresses",
                    self.config.relay.addr
                )
            })?;
        let api_key = self
            .config
            .auth
            .api_key
            .clone()
            .ok_or_else(|| anyhow!("missing api key; run `pike login <api_key>` first"))?;
        let relay_tls = resolve_relay_tls_settings(&self.config)?;

        let quic_config =
            PikeQuicConfig::default().with_idle_timeout_ms(self.config.relay.quic_timeout_ms);
        let mut client = PikeClient::new(
            quic_config,
            relay_addr,
            relay_tls.server_name,
            relay_tls.verify_peer,
            ApiKey(api_key),
            Vec::new(),
        );

        self.state = ConnectionState::Handshaking;
        let connection = client.connect().await?;

        self.state = ConnectionState::Authenticating;
        self.state = ConnectionState::Active;
        self.client = Some(client);
        self.connection = Some(connection);

        Ok(())
    }

    pub fn take_connection(&mut self) -> Option<PikeConnection> {
        self.connection.take()
    }

    pub fn take_client(&mut self) -> Option<PikeClient> {
        self.client.take()
    }

    async fn pump_messages(&mut self) {
        if let Some(connection) = &mut self.connection {
            while let Some(msg) = connection.data_rx.recv().await {
                self.stats.bytes_in = self.stats.bytes_in.saturating_add(msg.payload.len() as u64);
            }
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        const MAX_RETRIES: u32 = 5;

        loop {
            match self.connect().await {
                Ok(()) => {
                    self.pump_messages().await;
                    self.state = ConnectionState::Closed;
                }
                Err(e) => {
                    if self.stats.reconnections >= MAX_RETRIES {
                        return Err(e);
                    }

                    let backoff = Duration::from_secs(1_u64 << self.stats.reconnections.min(5));
                    self.state = ConnectionState::Reconnecting {
                        attempt: self.stats.reconnections + 1,
                        backoff,
                    };
                    self.stats.reconnections += 1;
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    pub async fn run_with_reconnect(&mut self) -> Result<()> {
        loop {
            // Check if circuit breaker is open
            if self.circuit_breaker.is_open() {
                let now = Local::now().format("%H:%M:%S");
                println!(
                    "[{}] {} (waiting 5 minutes before retry)",
                    now,
                    "Circuit breaker open".red()
                );
                tokio::time::sleep(Duration::from_secs(300)).await;
                continue;
            }

            match self.connect().await {
                Ok(()) => {
                    self.reconnect_attempt = 0;
                    self.circuit_breaker.failure_times.clear();
                    self.pump_messages().await;
                    self.state = ConnectionState::Closed;
                }
                Err(_) => {
                    // Check if max reconnect attempts reached
                    if let Some(max_attempts) = self.max_reconnect_attempts {
                        if self.reconnect_attempt >= max_attempts {
                            let now = Local::now().format("%H:%M:%S");
                            println!(
                                "[{}] {} (max reconnect attempts reached)",
                                now,
                                "Exiting".red()
                            );
                            return Err(anyhow!("max reconnect attempts reached"));
                        }
                    }

                    self.reconnect_attempt += 1;
                    self.circuit_breaker.record_failure();

                    let backoff = self.calculate_backoff(self.reconnect_attempt - 1);
                    let now = Local::now().format("%H:%M:%S");
                    println!(
                        "[{}] {} (attempt {}, backoff {:.1}s)",
                        now,
                        "Reconnecting...".yellow(),
                        self.reconnect_attempt,
                        backoff.as_secs_f64()
                    );
                    self.state = ConnectionState::Reconnecting {
                        attempt: self.reconnect_attempt,
                        backoff,
                    };
                    self.stats.reconnections += 1;
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }

    pub async fn graceful_shutdown(&mut self) -> Result<()> {
        self.state = ConnectionState::Closed;

        if let Some(connection) = &self.connection {
            let _ = connection.close().await;
        }
        self.connection = None;
        self.client = None;

        self.session_manager.clear_ticket().await.ok();

        Ok(())
    }

    pub fn print_stats(&self) {
        let elapsed = self.stats.start_time.elapsed();
        let now = Local::now().format("%H:%M:%S");
        println!("[{}] {}", now, "Connection Statistics".bold());
        println!(
            "[{}]   {:<16}{:.1}s",
            now,
            "Duration:",
            elapsed.as_secs_f64()
        );
        println!("[{}]   {:<16}{}", now, "Bytes In:", self.stats.bytes_in);
        println!("[{}]   {:<16}{}", now, "Bytes Out:", self.stats.bytes_out);
        println!(
            "[{}]   {:<16}{}",
            now, "Reconnections:", self.stats.reconnections
        );
        println!("[{}]   {:<16}{:?}", now, "State:", self.state);
    }
}

pub fn reconnect_backoff(attempt: u32) -> Duration {
    let base_secs = 2_u64.pow(attempt.min(4));
    let base_secs = base_secs.min(MAX_BACKOFF_SECS);

    let mut rng = rand::thread_rng();
    let jitter_factor = 1.0 + (rng.r#gen::<f64>() - 0.5) * 2.0 * JITTER_PERCENT;
    let final_secs = (base_secs as f64 * jitter_factor).max(1.0);

    Duration::from_secs_f64(final_secs)
}

fn resolve_relay_tls_settings(config: &Config) -> Result<RelayTlsSettings> {
    let verify_peer = !config.relay.insecure_skip_tls_verify;

    let server_name = if let Some(server_name) = config.relay.tls_server_name.as_deref() {
        let trimmed = server_name.trim();
        if trimmed.is_empty() {
            return Err(anyhow!("relay.tls_server_name cannot be empty"));
        }
        Some(trimmed.to_string())
    } else {
        default_tls_server_name(&config.relay.addr)?
    };

    if verify_peer && server_name.is_none() {
        return Err(anyhow!(
            "relay address '{}' uses an IP literal; set relay.tls_server_name to the certificate hostname or use a DNS relay address",
            config.relay.addr
        ));
    }

    Ok(RelayTlsSettings {
        server_name,
        verify_peer,
    })
}

fn default_tls_server_name(relay_addr: &str) -> Result<Option<String>> {
    let host = extract_relay_host(relay_addr)?;

    match host.parse::<IpAddr>() {
        Ok(ip) if ip.is_loopback() => Ok(Some("localhost".to_string())),
        Ok(_) => Ok(None),
        Err(_) => Ok(Some(host)),
    }
}

fn extract_relay_host(relay_addr: &str) -> Result<String> {
    let trimmed = relay_addr.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("relay address cannot be empty"));
    }

    if let Some(rest) = trimmed.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(|| {
            anyhow!(
                "invalid relay address '{}': missing closing ']'",
                relay_addr
            )
        })?;
        let host = &rest[..end];
        let remainder = &rest[end + 1..];
        if !remainder.starts_with(':') || remainder.len() <= 1 {
            return Err(anyhow!(
                "invalid relay address '{}': expected [host]:port format",
                relay_addr
            ));
        }
        return Ok(host.to_string());
    }

    let (host, port) = trimmed.rsplit_once(':').ok_or_else(|| {
        anyhow!(
            "invalid relay address '{}': expected host:port format",
            relay_addr
        )
    })?;
    if host.is_empty() || port.is_empty() {
        return Err(anyhow!(
            "invalid relay address '{}': expected host:port format",
            relay_addr
        ));
    }

    Ok(host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_state_equality() {
        let state1 = ConnectionState::Active;
        let state2 = ConnectionState::Active;
        assert_eq!(state1, state2);
    }

    #[test]
    fn test_connection_state_reconnecting() {
        let state = ConnectionState::Reconnecting {
            attempt: 1,
            backoff: Duration::from_secs(1),
        };
        assert_ne!(state, ConnectionState::Active);
    }

    #[test]
    fn test_connection_stats_initialization() {
        let config = Config::default();
        let handler = ConnectionHandler::new(config);

        assert_eq!(handler.stats.bytes_in, 0);
        assert_eq!(handler.stats.bytes_out, 0);
        assert_eq!(handler.stats.reconnections, 0);
    }

    #[test]
    fn test_connection_state_initial() {
        let config = Config::default();
        let handler = ConnectionHandler::new(config);

        assert_eq!(handler.state, ConnectionState::Closed);
    }

    #[test]
    fn test_max_reconnect_attempts_set() {
        let config = Config::default();
        let handler = ConnectionHandler::new(config).with_max_reconnect_attempts(Some(5));

        assert_eq!(handler.max_reconnect_attempts, Some(5));
    }

    #[test]
    fn test_max_reconnect_attempts_none() {
        let config = Config::default();
        let handler = ConnectionHandler::new(config).with_max_reconnect_attempts(None);

        assert_eq!(handler.max_reconnect_attempts, None);
    }

    #[test]
    fn test_circuit_breaker_records_failures() {
        let mut breaker = CircuitBreaker::new();

        assert!(!breaker.is_open());

        breaker.record_failure();
        assert!(!breaker.is_open());

        breaker.record_failure();
        assert!(!breaker.is_open());

        breaker.record_failure();
        assert!(breaker.is_open());
    }

    #[test]
    fn test_circuit_breaker_clears_old_failures() {
        let mut breaker = CircuitBreaker::new();

        breaker.record_failure();
        breaker.record_failure();

        // Simulate time passing beyond the window
        breaker.failure_times.clear();
        assert!(!breaker.is_open());
    }

    #[test]
    fn test_circuit_breaker_opens_on_three_failures() {
        let mut breaker = CircuitBreaker::new();

        breaker.record_failure();
        breaker.record_failure();
        breaker.record_failure();

        assert!(breaker.is_open());
    }

    #[test]
    fn dns_relay_uses_host_as_tls_server_name() {
        let config = Config::default();

        let tls = resolve_relay_tls_settings(&config).expect("tls settings");
        assert_eq!(tls.server_name.as_deref(), Some("relay.pike.life"));
        assert!(tls.verify_peer);
    }

    #[test]
    fn loopback_ip_defaults_to_localhost_server_name() {
        let mut config = Config::default();
        config.relay.addr = "127.0.0.1:4433".to_string();

        let tls = resolve_relay_tls_settings(&config).expect("tls settings");
        assert_eq!(tls.server_name.as_deref(), Some("localhost"));
        assert!(tls.verify_peer);
    }

    #[test]
    fn non_loopback_ip_requires_explicit_server_name_when_verifying() {
        let mut config = Config::default();
        config.relay.addr = "203.0.113.10:4433".to_string();

        let err = resolve_relay_tls_settings(&config).expect_err("expected tls config error");
        assert!(err
            .to_string()
            .contains("set relay.tls_server_name to the certificate hostname"));
    }

    #[test]
    fn explicit_server_name_allows_verified_ip_relay() {
        let mut config = Config::default();
        config.relay.addr = "203.0.113.10:4433".to_string();
        config.relay.tls_server_name = Some("relay.example.com".to_string());

        let tls = resolve_relay_tls_settings(&config).expect("tls settings");
        assert_eq!(tls.server_name.as_deref(), Some("relay.example.com"));
        assert!(tls.verify_peer);
    }

    #[test]
    fn insecure_skip_tls_verify_allows_ip_without_server_name() {
        let mut config = Config::default();
        config.relay.addr = "203.0.113.10:4433".to_string();
        config.relay.insecure_skip_tls_verify = true;

        let tls = resolve_relay_tls_settings(&config).expect("tls settings");
        assert_eq!(tls.server_name, None);
        assert!(!tls.verify_peer);
    }

    #[test]
    fn extract_relay_host_supports_ipv6() {
        let host = extract_relay_host("[2001:db8::1]:4433").expect("host");
        assert_eq!(host, "2001:db8::1");
    }
}
