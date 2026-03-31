use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::{DateTime, Utc};
use pike_core::types::TunnelId;
use pike_core::types::{TunnelConfig, TunnelType};
use uuid::Uuid;

pub type ConnectionId = Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    New,
    Handshaking,
    Authenticated,
    Active,
    Draining,
    Closed,
}

#[derive(Debug, Clone)]
pub struct ValidatedUser {
    pub user_id: String,
    pub email: String,
    pub plan: String,
    pub plan_expires_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ClientInfo {
    pub connection_id: ConnectionId,
    pub remote_addr: Option<SocketAddr>,
    pub api_key: Option<String>,
    pub assigned_subdomain: Option<String>,
    pub validated_user: Option<ValidatedUser>,
}

#[derive(Debug, Clone)]
pub struct ClientConnection {
    pub state: ConnectionState,
    pub info: ClientInfo,
    pub connected_at: DateTime<Utc>,
    pub last_heartbeat: Instant,
    pub last_heartbeat_at: DateTime<Utc>,
    pub tunnels: Vec<TunnelId>,
    pub tcp_remote_ports: HashMap<TunnelId, u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TunnelRegistration {
    pub tunnel_id: TunnelId,
    pub remote_port: Option<u16>,
}

impl ClientConnection {
    #[must_use]
    pub fn new(connection_id: ConnectionId, remote_addr: Option<SocketAddr>) -> Self {
        Self {
            state: ConnectionState::New,
            info: ClientInfo {
                connection_id,
                remote_addr,
                api_key: None,
                assigned_subdomain: None,
                validated_user: None,
            },
            connected_at: Utc::now(),
            last_heartbeat: Instant::now(),
            last_heartbeat_at: Utc::now(),
            tunnels: Vec::new(),
            tcp_remote_ports: HashMap::new(),
        }
    }

    pub fn transition_to(&mut self, next: ConnectionState) -> Result<()> {
        let valid = matches!(
            (self.state, next),
            (ConnectionState::New, ConnectionState::Handshaking)
                | (ConnectionState::Handshaking, ConnectionState::Authenticated)
                | (ConnectionState::Authenticated, ConnectionState::Active)
                | (ConnectionState::Active, ConnectionState::Draining)
                | (ConnectionState::New, ConnectionState::Closed)
                | (ConnectionState::Handshaking, ConnectionState::Closed)
                | (ConnectionState::Authenticated, ConnectionState::Closed)
                | (ConnectionState::Active, ConnectionState::Closed)
                | (ConnectionState::Draining, ConnectionState::Closed)
        );

        if !valid {
            anyhow::bail!(
                "invalid connection transition: {:?} -> {:?}",
                self.state,
                next
            );
        }

        self.state = next;
        Ok(())
    }

    pub fn authenticate(&mut self, api_key: &str, dev_mode: bool) -> Result<()> {
        validate_api_key(api_key, dev_mode)?;
        self.info.api_key = Some(api_key.to_string());
        self.transition_to(ConnectionState::Authenticated)
    }

    pub fn activate(&mut self) -> Result<()> {
        self.transition_to(ConnectionState::Active)
    }

    pub fn mark_heartbeat(&mut self) {
        self.last_heartbeat = Instant::now();
        self.last_heartbeat_at = Utc::now();
    }

    #[must_use]
    pub fn is_half_open(&self, timeout: Duration) -> bool {
        self.last_heartbeat.elapsed() > timeout
    }

    pub fn begin_drain(&mut self) -> Result<()> {
        match self.state {
            ConnectionState::Closed | ConnectionState::Draining => Ok(()),
            ConnectionState::Active => self.transition_to(ConnectionState::Draining),
            _ => self.transition_to(ConnectionState::Closed),
        }
    }

    pub fn register_tunnel_config(
        &mut self,
        config: &TunnelConfig,
        allocated_tcp_port: Option<u16>,
    ) -> Result<TunnelRegistration> {
        let remote_port = match config.tunnel_type {
            TunnelType::Tcp { remote_port, .. } => {
                let selected = allocated_tcp_port.or(remote_port).ok_or_else(|| {
                    anyhow::anyhow!("tcp tunnel registration requires allocated remote port")
                })?;
                self.tcp_remote_ports.insert(config.id, selected);
                Some(selected)
            }
            TunnelType::Http { .. } => None,
        };

        if !self.tunnels.contains(&config.id) {
            self.tunnels.push(config.id);
        }

        if matches!(self.state, ConnectionState::Authenticated) {
            self.state = ConnectionState::Active;
        }

        Ok(TunnelRegistration {
            tunnel_id: config.id,
            remote_port,
        })
    }

    pub fn unregister_tunnel(&mut self, tunnel_id: TunnelId) {
        self.tunnels.retain(|id| *id != tunnel_id);
        self.tcp_remote_ports.remove(&tunnel_id);
    }

    pub fn set_validated_user(&mut self, user: ValidatedUser) {
        self.info.validated_user = Some(user);
    }
}

pub fn validate_api_key(api_key: &str, _dev_mode: bool) -> Result<()> {
    let normalized = api_key.trim();
    if normalized.is_empty() {
        anyhow::bail!("empty API key is not allowed");
    }

    if normalized.contains(char::is_whitespace) {
        anyhow::bail!("API key cannot contain whitespace");
    }

    if normalized.len() < 8 {
        anyhow::bail!("API key too short (minimum 8 characters)");
    }

    if !normalized.starts_with("pk_") {
        anyhow::bail!("API key must start with pk_");
    }

    if !normalized[3..]
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_')
    {
        anyhow::bail!("API key contains invalid characters (only alphanumeric and underscore allowed after pk_)");
    }

    let suffix = &normalized[3..];
    let unique_chars: std::collections::HashSet<char> = suffix.chars().collect();
    if unique_chars.len() == 1 {
        anyhow::bail!("API key must not be all the same character");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{validate_api_key, ClientConnection, ConnectionState};
    use pike_core::types::{TunnelConfig, TunnelId, TunnelType};

    #[test]
    fn state_machine_accepts_happy_path_transitions() {
        let mut conn = ClientConnection::new(uuid::Uuid::new_v4(), None);
        conn.transition_to(ConnectionState::Handshaking)
            .expect("new -> handshaking");
        conn.authenticate("pk_test_key_1234", true)
            .expect("authenticate");
        conn.activate().expect("activate");
        conn.begin_drain().expect("drain");
        conn.transition_to(ConnectionState::Closed)
            .expect("close from draining");

        assert_eq!(conn.state, ConnectionState::Closed);
    }

    #[test]
    fn state_machine_rejects_invalid_transition() {
        let mut conn = ClientConnection::new(uuid::Uuid::new_v4(), None);
        let result = conn.transition_to(ConnectionState::Active);
        assert!(result.is_err());
    }

    #[test]
    fn heartbeat_timeout_marks_half_open() {
        let mut conn = ClientConnection::new(uuid::Uuid::new_v4(), None);
        let now = std::time::Instant::now();
        conn.last_heartbeat = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
        assert!(conn.is_half_open(Duration::from_secs(45)));
    }

    #[test]
    fn auth_rejects_empty_key_in_dev_mode_too() {
        assert!(validate_api_key("", true).is_err());
        assert!(validate_api_key("pk_test_key_1234", true).is_ok());
    }

    #[test]
    fn production_authentication_rejects_empty_key() {
        assert!(validate_api_key("", false).is_err());
        assert!(validate_api_key("pk_test_key_1234", false).is_ok());
    }

    #[test]
    fn production_authentication_rejects_whitespace_in_key() {
        assert!(validate_api_key("pk_abc def", false).is_err());
        assert!(validate_api_key("pk_abc_def_1234", false).is_ok());
    }

    #[test]
    fn tcp_tunnel_registration_requires_allocated_port() {
        let mut conn = ClientConnection::new(uuid::Uuid::new_v4(), None);
        conn.transition_to(ConnectionState::Handshaking)
            .expect("transition");
        conn.authenticate("pk_test_key_1234", true).expect("auth");

        let config = TunnelConfig {
            id: TunnelId::new(),
            tunnel_type: TunnelType::Tcp {
                local_port: 5432,
                remote_port: None,
            },
            local_addr: "127.0.0.1:5432".parse().expect("socket"),
        };

        let result = conn.register_tunnel_config(&config, None);
        assert!(result.is_err());
    }

    #[test]
    fn tcp_tunnel_registration_uses_allocated_port() {
        let mut conn = ClientConnection::new(uuid::Uuid::new_v4(), None);
        conn.transition_to(ConnectionState::Handshaking)
            .expect("transition");
        conn.authenticate("pk_test_key_1234", true).expect("auth");

        let config = TunnelConfig {
            id: TunnelId::new(),
            tunnel_type: TunnelType::Tcp {
                local_port: 5432,
                remote_port: None,
            },
            local_addr: "127.0.0.1:5432".parse().expect("socket"),
        };

        let registration = conn
            .register_tunnel_config(&config, Some(15_432))
            .expect("register tunnel");
        assert_eq!(registration.remote_port, Some(15_432));
        assert_eq!(conn.tcp_remote_ports.get(&config.id), Some(&15_432));
        assert!(matches!(conn.state, ConnectionState::Active));
    }
}
