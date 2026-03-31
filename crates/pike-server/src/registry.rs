use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use pike_core::types::TunnelId;

use crate::abuse::{AbuseDetector, AbuseError};
use crate::config::AbuseConfig;
use crate::connection::{ClientConnection, ConnectionId, ConnectionState};
use crate::rate_limit::RateLimiter;
use crate::state_store::StateStore;

#[derive(Debug, Clone)]
pub struct TunnelEntry {
    pub tunnel_id: TunnelId,
    pub connection_id: ConnectionId,
    pub active: bool,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct TcpListenerEntry {
    pub tunnel_id: TunnelId,
    pub connection_id: ConnectionId,
    pub local_addr: SocketAddr,
    pub active: bool,
}

#[derive(Debug)]
pub struct ClientRegistry {
    pub clients: DashMap<ConnectionId, ClientConnection>,
    pub tunnels: DashMap<String, TunnelEntry>,
    pub tcp_listeners: DashMap<TunnelId, TcpListenerEntry>,
    pub revoked_api_keys: DashMap<String, ()>,
    pub rate_limiter: Arc<RateLimiter>,
    pub abuse_detector: Arc<AbuseDetector>,
    pub total_connections: AtomicUsize,
    pub total_bytes_in: AtomicU64,
    pub total_bytes_out: AtomicU64,
    started_at: std::time::Instant,
    request_count: AtomicU64,
    max_connections: usize,
    max_tunnels_per_connection: usize,
}

impl Default for ClientRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::new_with_abuse_config(AbuseConfig::default())
    }

    #[must_use]
    pub fn new_with_abuse_config(abuse_config: AbuseConfig) -> Self {
        Self::with_limits(abuse_config, 1000, 10)
    }

    #[must_use]
    pub fn with_limits(
        abuse_config: AbuseConfig,
        max_connections: usize,
        max_tunnels_per_connection: usize,
    ) -> Self {
        Self::with_limits_and_store(
            abuse_config,
            max_connections,
            max_tunnels_per_connection,
            None,
        )
    }

    #[must_use]
    pub fn with_limits_and_store(
        abuse_config: AbuseConfig,
        max_connections: usize,
        max_tunnels_per_connection: usize,
        state_store: Option<Arc<dyn StateStore>>,
    ) -> Self {
        let rate_limiter = Arc::new(match state_store.clone() {
            Some(store) => RateLimiter::with_store(store),
            None => RateLimiter::new(),
        });

        let abuse_detector = Arc::new(match state_store {
            Some(store) => AbuseDetector::with_store(abuse_config, store),
            None => AbuseDetector::new(abuse_config),
        });

        Self {
            clients: DashMap::new(),
            tunnels: DashMap::new(),
            tcp_listeners: DashMap::new(),
            revoked_api_keys: DashMap::new(),
            rate_limiter,
            abuse_detector,
            total_connections: AtomicUsize::new(0),
            total_bytes_in: AtomicU64::new(0),
            total_bytes_out: AtomicU64::new(0),
            started_at: std::time::Instant::now(),
            request_count: AtomicU64::new(0),
            max_connections,
            max_tunnels_per_connection,
        }
    }

    pub fn active_connections(&self) -> usize {
        self.clients.len()
    }

    pub fn active_tunnels(&self) -> usize {
        self.tunnels.len()
    }

    pub fn register_client(&self, client: ClientConnection) -> anyhow::Result<()> {
        if self.clients.len() >= self.max_connections {
            anyhow::bail!(
                "connection limit reached ({}/{})",
                self.clients.len(),
                self.max_connections
            );
        }
        self.clients.insert(client.info.connection_id, client);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        crate::metrics::ACTIVE_CONNECTIONS.inc();
        Ok(())
    }

    pub fn remove_client(&self, connection_id: &ConnectionId) {
        if let Some((_, client)) = self.clients.remove(connection_id) {
            for tunnel_id in client.tunnels {
                self.rate_limiter.unregister_tunnel(tunnel_id);
            }
        }
        self.tunnels
            .retain(|_, tunnel| &tunnel.connection_id != connection_id);
        self.tcp_listeners
            .retain(|_, listener| &listener.connection_id != connection_id);
        crate::metrics::ACTIVE_CONNECTIONS.dec();
    }

    pub fn register_tunnel(
        &self,
        connection_id: ConnectionId,
        subdomain: String,
        tunnel_id: TunnelId,
    ) -> anyhow::Result<()> {
        if let Some(mut client) = self.clients.get_mut(&connection_id) {
            if client.tunnels.len() >= self.max_tunnels_per_connection {
                anyhow::bail!(
                    "tunnel limit per connection reached ({}/{})",
                    client.tunnels.len(),
                    self.max_tunnels_per_connection
                );
            }

            let user_id = client
                .info
                .validated_user
                .as_ref()
                .map(|user| user.user_id.clone())
                .or_else(|| client.info.api_key.clone())
                .unwrap_or_else(|| format!("conn:{connection_id}"));

            let source_ip = client
                .info
                .remote_addr
                .map(|addr| addr.ip())
                .unwrap_or(IpAddr::from([0, 0, 0, 0]));
            self.abuse_detector
                .check_tunnel_creation_rate(&user_id, source_ip)
                .map_err(abuse_error_to_anyhow)?;

            let plan_name = client
                .info
                .validated_user
                .as_ref()
                .map(|user| user.plan.as_str());
            self.rate_limiter
                .register_tunnel(user_id, tunnel_id, plan_name)
                .map_err(|error| anyhow::anyhow!(error.to_string()))?;

            client.tunnels.push(tunnel_id);
            if matches!(client.state, ConnectionState::Authenticated) {
                client.state = ConnectionState::Active;
            }
            self.tunnels.insert(
                subdomain,
                TunnelEntry {
                    tunnel_id,
                    connection_id,
                    active: true,
                    bytes_in: 0,
                    bytes_out: 0,
                    created_at: Utc::now(),
                },
            );
            crate::metrics::ACTIVE_TUNNELS.inc();
            return Ok(());
        }

        anyhow::bail!("client connection not found: {connection_id}");
    }

    pub fn unregister_tunnel(&self, subdomain: &str) {
        if let Some((_, tunnel)) = self.tunnels.remove(subdomain) {
            self.rate_limiter.unregister_tunnel(tunnel.tunnel_id);
            crate::metrics::ACTIVE_TUNNELS.dec();
        }
    }

    pub fn register_tcp_listener(
        &self,
        connection_id: ConnectionId,
        tunnel_id: TunnelId,
        local_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        if !self.clients.contains_key(&connection_id) {
            anyhow::bail!("client connection not found: {connection_id}");
        }

        self.tcp_listeners.insert(
            tunnel_id,
            TcpListenerEntry {
                tunnel_id,
                connection_id,
                local_addr,
                active: true,
            },
        );

        Ok(())
    }

    pub fn unregister_tcp_listener(&self, tunnel_id: TunnelId) {
        self.tcp_listeners.remove(&tunnel_id);
    }

    #[must_use]
    pub fn lookup_tcp_listener(&self, tunnel_id: TunnelId) -> Option<TcpListenerEntry> {
        self.tcp_listeners
            .get(&tunnel_id)
            .map(|entry| entry.clone())
    }

    #[must_use]
    pub fn active_tcp_listeners(&self) -> Vec<(TunnelId, SocketAddr)> {
        self.tcp_listeners
            .iter()
            .filter(|entry| entry.active)
            .map(|entry| (entry.tunnel_id, entry.local_addr))
            .collect()
    }

    #[must_use]
    pub fn lookup_tunnel(&self, subdomain: &str) -> Option<TunnelEntry> {
        self.tunnels.get(subdomain).map(|entry| entry.clone())
    }

    pub fn heartbeat(&self, connection_id: &ConnectionId) {
        if let Some(mut client) = self.clients.get_mut(connection_id) {
            client.mark_heartbeat();
        }
    }

    pub fn mark_dead_connections(&self, timeout: Duration) -> Vec<ConnectionId> {
        let mut dead = Vec::new();
        for mut item in self.clients.iter_mut() {
            if item.is_half_open(timeout) {
                item.state = ConnectionState::Closed;
                dead.push(*item.key());
            }
        }

        for dead_conn_id in &dead {
            self.tunnels.retain(|_, tunnel| {
                if &tunnel.connection_id == dead_conn_id {
                    tunnel.active = false;
                }
                true
            });
            self.tcp_listeners.retain(|_, listener| {
                if &listener.connection_id == dead_conn_id {
                    listener.active = false;
                }
                true
            });
        }

        dead
    }

    pub fn begin_shutdown_drain(&self) {
        for mut client in self.clients.iter_mut() {
            let _ = client.begin_drain();
        }

        self.tunnels.retain(|_, tunnel| {
            tunnel.active = false;
            true
        });

        self.tcp_listeners.retain(|_, listener| {
            listener.active = false;
            true
        });
    }

    #[must_use]
    pub fn user_id_for_connection(&self, connection_id: &ConnectionId) -> Option<String> {
        self.clients.get(connection_id).and_then(|client| {
            client
                .info
                .validated_user
                .as_ref()
                .map(|user| user.user_id.clone())
                .or_else(|| client.info.api_key.clone())
        })
    }

    pub fn track_bandwidth(&self, tunnel_id: TunnelId, bytes: u64) {
        self.total_bytes_in.fetch_add(bytes, Ordering::Relaxed);
        self.rate_limiter.track_bandwidth(tunnel_id, bytes);

        if let Some(mut tunnel) = self
            .tunnels
            .iter_mut()
            .find(|entry| entry.tunnel_id == tunnel_id)
        {
            tunnel.bytes_in = tunnel.bytes_in.saturating_add(bytes);
        }
    }

    #[must_use]
    pub fn uptime_seconds(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    pub fn record_request(&self) {
        self.request_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_tunnel_request(&self, tunnel_id: TunnelId, status: u16) {
        self.record_request();
        self.abuse_detector.record_request(tunnel_id, status);
    }

    #[must_use]
    pub fn requests_per_minute(&self) -> f64 {
        let elapsed_minutes = (self.started_at.elapsed().as_secs_f64() / 60.0).max(1.0 / 60.0);
        self.request_count.load(Ordering::Relaxed) as f64 / elapsed_minutes
    }

    pub async fn kill_user_tunnels(&self, user_id: &str) -> anyhow::Result<()> {
        let connection_ids: Vec<_> = self
            .clients
            .iter()
            .filter(|entry| {
                entry
                    .info
                    .validated_user
                    .as_ref()
                    .map(|user| user.user_id.as_str())
                    .or(entry.info.api_key.as_deref())
                    == Some(user_id)
            })
            .map(|entry| *entry.key())
            .collect();

        for connection_id in connection_ids {
            self.remove_client(&connection_id);
        }

        Ok(())
    }

    #[must_use]
    pub fn is_api_key_allowed(&self, api_key: &str) -> bool {
        !self.revoked_api_keys.contains_key(api_key)
    }
}

fn abuse_error_to_anyhow(error: AbuseError) -> anyhow::Error {
    anyhow::anyhow!(error.to_string())
}

#[cfg(test)]
mod tests {
    use crate::config::AbuseConfig;
    use crate::connection::{ClientConnection, ConnectionState, ValidatedUser};

    use super::ClientRegistry;

    #[test]
    fn register_lookup_unregister_tunnel() {
        let registry = ClientRegistry::new();
        let conn_id = uuid::Uuid::new_v4();
        let mut client = ClientConnection::new(conn_id, None);
        client.state = ConnectionState::Authenticated;
        let _ = registry.register_client(client);

        let tunnel_id = pike_core::types::TunnelId::new();
        registry
            .register_tunnel(conn_id, "demo.pike.life".to_string(), tunnel_id)
            .expect("register tunnel");

        let entry = registry
            .lookup_tunnel("demo.pike.life")
            .expect("entry exists");
        assert_eq!(entry.connection_id, conn_id);
        assert!(entry.active);

        registry.unregister_tunnel("demo.pike.life");
        assert!(registry.lookup_tunnel("demo.pike.life").is_none());
    }

    #[test]
    fn remove_client_cleans_tunnels() {
        let registry = ClientRegistry::new();
        let conn_id = uuid::Uuid::new_v4();
        let mut client = ClientConnection::new(conn_id, None);
        client.state = ConnectionState::Authenticated;
        let _ = registry.register_client(client);

        registry
            .register_tunnel(
                conn_id,
                "cleanup.pike.life".to_string(),
                pike_core::types::TunnelId::new(),
            )
            .expect("register tunnel");
        registry.remove_client(&conn_id);

        assert!(registry.clients.get(&conn_id).is_none());
        assert!(registry.lookup_tunnel("cleanup.pike.life").is_none());
    }

    #[test]
    fn register_lookup_unregister_tcp_listener() {
        let registry = ClientRegistry::new();
        let conn_id = uuid::Uuid::new_v4();
        let mut client = ClientConnection::new(conn_id, None);
        client.state = ConnectionState::Authenticated;
        let _ = registry.register_client(client);

        let tunnel_id = pike_core::types::TunnelId::new();
        let local_addr: std::net::SocketAddr = "127.0.0.1:15432".parse().expect("socket");
        registry
            .register_tcp_listener(conn_id, tunnel_id, local_addr)
            .expect("register tcp listener");

        let listener = registry
            .lookup_tcp_listener(tunnel_id)
            .expect("tcp listener exists");
        assert_eq!(listener.connection_id, conn_id);
        assert_eq!(listener.local_addr, local_addr);
        assert!(listener.active);

        registry.unregister_tcp_listener(tunnel_id);
        assert!(registry.lookup_tcp_listener(tunnel_id).is_none());
    }

    #[test]
    fn connection_limit_enforced() {
        let registry = ClientRegistry::with_limits(AbuseConfig::default(), 2, 10);
        for i in 0..2u64 {
            let mut client = ClientConnection::new(uuid::Uuid::from_u128(i as u128), None);
            client.state = ConnectionState::Authenticated;
            registry.register_client(client).expect("within limit");
        }
        let mut overflow = ClientConnection::new(uuid::Uuid::from_u128(99), None);
        overflow.state = ConnectionState::Authenticated;
        assert!(
            registry.register_client(overflow).is_err(),
            "3rd client should be rejected at limit=2"
        );
    }

    #[test]
    fn tunnel_per_connection_limit_enforced() {
        let registry = ClientRegistry::with_limits(AbuseConfig::default(), 100, 2);
        let conn_id = uuid::Uuid::new_v4();
        let mut client = ClientConnection::new(conn_id, None);
        client.state = ConnectionState::Authenticated;
        client.info.api_key = Some("pk_test_key_1234".to_string());
        client.set_validated_user(ValidatedUser {
            user_id: "pro-user".to_string(),
            email: "pro@example.com".to_string(),
            plan: "pro".to_string(),
            plan_expires_at: None,
        });
        registry.register_client(client).expect("register client");

        for i in 0..2u32 {
            registry
                .register_tunnel(
                    conn_id,
                    format!("tunnel{i}.example.com"),
                    pike_core::types::TunnelId::new(),
                )
                .expect("within tunnel limit");
        }
        let overflow = registry.register_tunnel(
            conn_id,
            "overflow.example.com".to_string(),
            pike_core::types::TunnelId::new(),
        );
        assert!(
            overflow.is_err(),
            "3rd tunnel should be rejected at limit=2"
        );
    }
}
