use std::collections::BTreeSet;
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

pub const MAX_CONNECTORS_PER_TUNNEL: usize = 8;

#[derive(Debug, Clone)]
pub struct TunnelEntry {
    pub tunnel_id: TunnelId,
    pub connections: BTreeSet<ConnectionId>,
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

/// Billing attribution survives removal of live routing/client state.
#[derive(Debug, Clone)]
pub struct UsageTunnel {
    pub runtime_id: TunnelId,
    pub user_id: String,
    pub canonical_id: String,
    pub finished_at: Option<tokio::time::Instant>,
}

#[derive(Debug)]
pub struct ClientRegistry {
    pub ingress: Arc<crate::ingress_directory::Directory>,
    pub clients: DashMap<ConnectionId, ClientConnection>,
    pub tunnels: DashMap<String, TunnelEntry>,
    pub tcp_listeners: DashMap<TunnelId, TcpListenerEntry>,
    /// Revoked API keys mapped to the owning user_id (or "" if unknown) so a ban can be
    /// lifted per-user (fix #6d/#7/#8). Checked at session login and revalidation.
    pub revoked_api_keys: DashMap<String, String>,
    usage_tunnels: DashMap<TunnelId, UsageTunnel>,
    public_tunnel_ids: DashMap<TunnelId, String>,
    runtime_tunnel_ids: DashMap<String, TunnelId>,
    lease_reconnects: DashMap<(String, String, TunnelId, ConnectionId), tokio::time::Instant>,
    tunnel_lifecycle: std::sync::Mutex<()>,
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
            ingress: Arc::default(),
            clients: DashMap::new(),
            tunnels: DashMap::new(),
            tcp_listeners: DashMap::new(),
            revoked_api_keys: DashMap::new(),
            usage_tunnels: DashMap::new(),
            public_tunnel_ids: DashMap::new(),
            runtime_tunnel_ids: DashMap::new(),
            lease_reconnects: DashMap::new(),
            tunnel_lifecycle: std::sync::Mutex::new(()),
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

    // Registration changes several maps and quota counters as one ownership
    // transition. Never hold a DashMap entry while acquiring this lock.
    fn lock_tunnels(&self) -> std::sync::MutexGuard<'_, ()> {
        self.tunnel_lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn runtime_is_routed(&self, runtime_id: TunnelId) -> bool {
        self.tunnels
            .iter()
            .any(|entry| entry.tunnel_id == runtime_id)
    }

    fn quota_identity(&self, connection_id: &ConnectionId) -> Option<(String, Option<String>)> {
        self.clients.get(connection_id).map(|client| {
            let owner = client
                .info
                .validated_user
                .as_ref()
                .map(|user| user.user_id.clone())
                .or_else(|| client.info.api_key.clone())
                .unwrap_or_else(|| format!("conn:{connection_id}"));
            let plan = client
                .info
                .validated_user
                .as_ref()
                .map(|user| user.plan.clone());
            (owner, plan)
        })
    }

    /// Retain public identifiers alongside metrics, independently of billing
    /// retirement. A public tunnel resolves to its latest registered runtime.
    pub fn remember_tunnel_identity(
        &self,
        runtime_id: TunnelId,
        public_id: String,
    ) -> anyhow::Result<()> {
        let _guard = self.lock_tunnels();
        self.validate_tunnel_identity_locked(runtime_id, &public_id)?;
        self.public_tunnel_ids.insert(runtime_id, public_id.clone());
        self.runtime_tunnel_ids.insert(public_id, runtime_id);
        Ok(())
    }

    fn validate_tunnel_identity_locked(
        &self,
        runtime_id: TunnelId,
        public_id: &str,
    ) -> anyhow::Result<()> {
        if self
            .public_tunnel_ids
            .get(&runtime_id)
            .is_some_and(|existing| existing.value() != public_id)
        {
            anyhow::bail!("runtime tunnel already has a different public identity");
        }
        if self
            .usage_tunnels
            .get(&runtime_id)
            .is_some_and(|existing| existing.canonical_id != public_id)
        {
            anyhow::bail!("public tunnel identity differs from usage attribution");
        }
        Ok(())
    }

    #[must_use]
    pub fn public_tunnel_id(&self, runtime_id: TunnelId) -> String {
        self.public_tunnel_ids
            .get(&runtime_id)
            .map_or_else(|| runtime_id.to_string(), |id| id.clone())
    }

    #[must_use]
    pub fn runtime_tunnel_id(&self, public_id: &str) -> String {
        self.runtime_tunnel_ids
            .get(public_id)
            .map_or_else(|| public_id.to_string(), |id| id.to_string())
    }

    /// Every runtime tunnel known under `id`, which may be either a canonical
    /// control-plane identity or a raw runtime ID. The input is always included so
    /// standalone runtime/direct handling is unchanged. Consults every identity map
    /// rather than only the latest-runtime mapping: several connector generations
    /// can share one canonical identity, and traffic enforcement keys on the runtime ID.
    #[must_use]
    pub fn runtime_tunnel_members(&self, id: TunnelId) -> Vec<TunnelId> {
        let public_id = id.to_string();
        let mut members = vec![id];
        let mut push = |candidate: TunnelId| {
            if !members.contains(&candidate) {
                members.push(candidate);
            }
        };
        if let Some(latest) = self.runtime_tunnel_ids.get(&public_id) {
            push(*latest.value());
        }
        for entry in &self.public_tunnel_ids {
            if entry.value() == &public_id {
                push(*entry.key());
            }
        }
        for entry in &self.usage_tunnels {
            if entry.canonical_id == public_id {
                push(entry.runtime_id);
            }
        }
        members
    }

    /// Suspend `id` and every runtime member registered under it, so the per-request
    /// runtime-ID check in the forwarders blocks live traffic for a canonical identity.
    /// Returns the IDs that were suspended.
    pub fn suspend_tunnel_identity(&self, id: TunnelId) -> Result<Vec<TunnelId>, AbuseError> {
        let members = self.runtime_tunnel_members(id);
        for member in &members {
            self.abuse_detector.suspend_tunnel(*member)?;
        }
        Ok(members)
    }

    /// Mirror of [`Self::suspend_tunnel_identity`]. Returns the IDs that were cleared.
    pub fn unsuspend_tunnel_identity(&self, id: TunnelId) -> Result<Vec<TunnelId>, AbuseError> {
        let members = self.runtime_tunnel_members(id);
        for member in &members {
            self.abuse_detector.unsuspend_tunnel(*member)?;
        }
        Ok(members)
    }

    /// Set the canonical control-plane ID, not the client-generated runtime UUID.
    pub fn remember_usage_tunnel(
        &self,
        runtime_id: TunnelId,
        user_id: String,
        canonical_id: String,
    ) -> anyhow::Result<()> {
        let _guard = self.lock_tunnels();
        if self
            .public_tunnel_ids
            .get(&runtime_id)
            .is_some_and(|public_id| public_id.value() != &canonical_id)
        {
            anyhow::bail!("usage attribution differs from public tunnel identity");
        }
        let owner = self
            .tunnels
            .iter()
            .find(|entry| entry.tunnel_id == runtime_id)
            .map(|entry| entry.connection_id);
        if owner
            .and_then(|owner| self.quota_identity(&owner))
            .is_some_and(|(owner, _)| owner != user_id)
        {
            anyhow::bail!("usage attribution does not match the live tunnel owner");
        }
        match self.usage_tunnels.entry(runtime_id) {
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                if entry.get().user_id != user_id || entry.get().canonical_id != canonical_id {
                    anyhow::bail!("runtime tunnel already has different usage attribution");
                }
                entry.get_mut().finished_at = None;
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(UsageTunnel {
                    runtime_id,
                    user_id,
                    canonical_id,
                    finished_at: None,
                });
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn usage_tunnels(&self) -> Vec<UsageTunnel> {
        self.usage_tunnels
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Mark routing retired after forwarding is cancelled. The reporter retains
    /// attribution through a quiet grace period for final bounded HTTP metrics.
    pub fn finalize_usage_tunnel(&self, runtime_id: TunnelId) {
        let _guard = self.lock_tunnels();
        self.finalize_usage_tunnel_locked(runtime_id);
    }

    fn finalize_usage_tunnel_locked(&self, runtime_id: TunnelId) {
        // An old session may finalize after its replacement has registered.
        if self.runtime_is_routed(runtime_id) {
            return;
        }
        if let Some(mut entry) = self.usage_tunnels.get_mut(&runtime_id) {
            entry
                .finished_at
                .get_or_insert_with(tokio::time::Instant::now);
        }
    }

    /// Remove only the finalized generation acknowledged by the reporter.
    pub fn forget_finished_usage_tunnel(
        &self,
        runtime_id: TunnelId,
        expected_finished_at: tokio::time::Instant,
    ) {
        let _guard = self.lock_tunnels();
        if self.runtime_is_routed(runtime_id) {
            return;
        }
        self.usage_tunnels.remove_if(&runtime_id, |_, entry| {
            entry.finished_at == Some(expected_finished_at)
        });
    }

    pub fn active_connections(&self) -> usize {
        self.clients.len()
    }

    pub fn active_tunnels(&self) -> usize {
        self.tunnels.len()
    }

    pub fn register_client(&self, client: ClientConnection) -> anyhow::Result<()> {
        let _guard = self.lock_tunnels();
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
        let _guard = self.lock_tunnels();
        let hosts: Vec<_> = self
            .tunnels
            .iter()
            .filter(|entry| entry.connections.contains(connection_id))
            .map(|entry| entry.key().clone())
            .collect();
        for host in hosts {
            self.unregister_tunnel_if_owner_locked(&host, connection_id);
        }
        // Force-removal paths (kill_user_tunnels) may remove the entry before the
        // session's own cleanup runs remove_client again; only a real removal
        // touches the gauge so it never goes negative.
        if let Some((_, client)) = self.clients.remove(connection_id) {
            for tunnel_id in client.tunnels {
                if !self.runtime_is_routed(tunnel_id) {
                    self.rate_limiter.unregister_tunnel(tunnel_id);
                    self.finalize_usage_tunnel_locked(tunnel_id);
                }
            }
            crate::metrics::ACTIVE_CONNECTIONS.dec();
        }
        self.tcp_listeners
            .retain(|_, listener| &listener.connection_id != connection_id);
    }

    /// A relay-triggered lease reset may reconnect each existing tunnel once.
    /// Authentication, ownership and simultaneous-tunnel limits still apply.
    pub fn allow_lease_reconnect(&self, connection_id: &ConnectionId) {
        let _guard = self.lock_tunnels();
        let Some((owner, _)) = self.quota_identity(connection_id) else {
            return;
        };
        let now = tokio::time::Instant::now();
        self.lease_reconnects.retain(|_, deadline| *deadline > now);
        for route in self
            .tunnels
            .iter()
            .filter(|route| route.connections.contains(connection_id))
        {
            if self.lease_reconnects.len() >= 16384 {
                break;
            }
            self.lease_reconnects.insert(
                (
                    owner.clone(),
                    route.key().clone(),
                    route.tunnel_id,
                    *connection_id,
                ),
                now + Duration::from_secs(90),
            );
        }
    }

    pub fn register_tunnel(
        &self,
        connection_id: ConnectionId,
        subdomain: String,
        tunnel_id: TunnelId,
    ) -> anyhow::Result<()> {
        let _guard = self.lock_tunnels();
        self.register_tunnel_locked(connection_id, subdomain, tunnel_id)
    }

    /// Claim a vacant session route and its retained identities together. Session
    /// activation must not evict a live owner before its listener can be created.
    pub fn register_new_tunnel(
        &self,
        connection_id: ConnectionId,
        subdomain: String,
        tunnel_id: TunnelId,
        public_id: String,
        reports_usage: bool,
    ) -> anyhow::Result<()> {
        let _guard = self.lock_tunnels();
        self.register_new_tunnel_locked(
            connection_id,
            subdomain,
            tunnel_id,
            public_id,
            reports_usage,
        )
    }

    fn register_new_tunnel_locked(
        &self,
        connection_id: ConnectionId,
        subdomain: String,
        tunnel_id: TunnelId,
        public_id: String,
        reports_usage: bool,
    ) -> anyhow::Result<()> {
        if self.tunnels.contains_key(&subdomain) {
            anyhow::bail!("hostname is still registered; retry after its session disconnects");
        }
        self.validate_tunnel_identity_locked(tunnel_id, &public_id)?;
        let (user_id, _) = self
            .quota_identity(&connection_id)
            .ok_or_else(|| anyhow::anyhow!("client connection not found: {connection_id}"))?;
        // register_tunnel_locked also checks retained usage ownership before any
        // route/quota mutation. After it succeeds, every remaining step is infallible.
        self.register_tunnel_locked(connection_id, subdomain, tunnel_id)?;
        self.public_tunnel_ids.insert(tunnel_id, public_id.clone());
        self.runtime_tunnel_ids.insert(public_id.clone(), tunnel_id);
        if reports_usage {
            self.usage_tunnels.insert(
                tunnel_id,
                UsageTunnel {
                    runtime_id: tunnel_id,
                    user_id,
                    canonical_id: public_id,
                    finished_at: None,
                },
            );
        }
        Ok(())
    }

    /// Join one existing endpoint without creating another account tunnel or
    /// resetting its request/bandwidth windows. The session validates matching
    /// desired settings and policy before exposing the new forwarding channel.
    pub fn register_connector(
        &self,
        connection_id: ConnectionId,
        subdomain: String,
        tunnel_id: TunnelId,
        public_id: String,
        reports_usage: bool,
    ) -> anyhow::Result<()> {
        let _guard = self.lock_tunnels();
        let Some(existing) = self.tunnels.get(&subdomain).map(|entry| entry.clone()) else {
            return self.register_new_tunnel_locked(
                connection_id,
                subdomain,
                tunnel_id,
                public_id,
                reports_usage,
            );
        };
        self.validate_tunnel_identity_locked(tunnel_id, &public_id)?;
        let (owner, _) = self
            .quota_identity(&connection_id)
            .ok_or_else(|| anyhow::anyhow!("connector client missing"))?;
        anyhow::ensure!(
            existing.tunnel_id == tunnel_id
                && self.public_tunnel_id(tunnel_id) == public_id
                && self
                    .quota_identity(&existing.connection_id)
                    .is_some_and(|(current, _)| current == owner),
            "connector does not own the same saved endpoint"
        );
        anyhow::ensure!(
            !existing.connections.contains(&connection_id),
            "connector already registered"
        );
        anyhow::ensure!(
            existing.connections.len() < MAX_CONNECTORS_PER_TUNNEL,
            "connector limit reached"
        );
        anyhow::ensure!(
            self.clients.get(&connection_id).is_none_or(|client| client
                .info
                .validated_user
                .as_ref()
                .is_none_or(|user| user.tunnel_limit != Some(0))),
            "account tunnel limit exceeded"
        );
        self.check_connector_creation(connection_id, &owner, &subdomain, tunnel_id, false)?;
        self.tunnels
            .get_mut(&subdomain)
            .expect("lifecycle locked")
            .connections
            .insert(connection_id);
        let mut client = self
            .clients
            .get_mut(&connection_id)
            .expect("lifecycle locked");
        if !client.tunnels.contains(&tunnel_id) {
            client.tunnels.push(tunnel_id);
        }
        if matches!(client.state, ConnectionState::Authenticated) {
            client.state = ConnectionState::Active;
        }
        Ok(())
    }

    fn register_tunnel_locked(
        &self,
        connection_id: ConnectionId,
        subdomain: String,
        tunnel_id: TunnelId,
    ) -> anyhow::Result<()> {
        let tunnel_cap = self.clients.get(&connection_id).and_then(|client| {
            client
                .info
                .validated_user
                .as_ref()
                .and_then(|user| user.tunnel_limit)
        });
        let (user_id, plan) = self
            .quota_identity(&connection_id)
            .ok_or_else(|| anyhow::anyhow!("client connection not found: {connection_id}"))?;
        // Seed the control-plane limit overrides (bandwidth, daily requests) before
        // the quota registration below so plan defaults never mask the hosted limits.
        if let Some(user) = self
            .clients
            .get(&connection_id)
            .and_then(|client| client.info.validated_user.clone())
        {
            self.rate_limiter.set_user_limits(&user_id, &user.limits);
        }
        let previous = self
            .tunnels
            .get(&subdomain)
            .map(|entry| entry.value().clone());
        if previous
            .as_ref()
            .is_some_and(|old| old.connection_id == connection_id && old.tunnel_id == tunnel_id)
        {
            return Ok(());
        }
        if self
            .tunnels
            .iter()
            .any(|entry| entry.tunnel_id == tunnel_id && entry.key() != &subdomain)
        {
            anyhow::bail!("runtime tunnel ID is already registered under another hostname");
        }
        if self
            .usage_tunnels
            .get(&tunnel_id)
            .is_some_and(|entry| entry.user_id != user_id)
        {
            anyhow::bail!("runtime tunnel already has different usage attribution");
        }
        anyhow::ensure!(
            previous
                .as_ref()
                .is_none_or(|old| old.connections.len() == 1),
            "cannot replace a shared endpoint"
        );
        self.check_connector_creation(
            connection_id,
            &user_id,
            &subdomain,
            tunnel_id,
            previous
                .as_ref()
                .is_some_and(|old| old.connection_id == connection_id),
        )?;
        let old_identity = previous
            .as_ref()
            .and_then(|old| self.quota_identity(&old.connection_id));
        let retains_quota = previous
            .as_ref()
            .is_some_and(|old| old.tunnel_id == tunnel_id)
            && old_identity
                .as_ref()
                .is_some_and(|(owner, old_plan)| owner == &user_id && old_plan == &plan);
        if !retains_quota {
            if let Some(old) = &previous {
                self.rate_limiter.unregister_tunnel(old.tunnel_id);
            }
            if let Err(error) = self.rate_limiter.register_tunnel_with_cap(
                user_id,
                tunnel_id,
                plan.as_deref(),
                tunnel_cap,
            ) {
                // A rejected replacement leaves the previous route and quota intact.
                if let (Some(old), Some((owner, old_plan))) = (&previous, old_identity) {
                    self.rate_limiter
                        .register_tunnel_with_cap(
                            owner,
                            old.tunnel_id,
                            old_plan.as_deref(),
                            Some(u64::MAX),
                        )
                        .map_err(|restore| {
                            anyhow::anyhow!(
                                "failed to restore tunnel quota after {error}: {restore}"
                            )
                        })?;
                }
                return Err(anyhow::anyhow!(error.to_string()));
            }
        }
        if let Some(old) = &previous {
            if let Some(mut client) = self.clients.get_mut(&old.connection_id) {
                client.unregister_tunnel(old.tunnel_id);
            }
            self.tcp_listeners.remove_if(&old.tunnel_id, |_, listener| {
                listener.connection_id == old.connection_id
            });
        }
        if let Some(mut client) = self.clients.get_mut(&connection_id) {
            if !client.tunnels.contains(&tunnel_id) {
                client.tunnels.push(tunnel_id);
            }
            if matches!(client.state, ConnectionState::Authenticated) {
                client.state = ConnectionState::Active;
            }
        }
        self.tunnels.insert(
            subdomain,
            TunnelEntry {
                tunnel_id,
                connections: BTreeSet::from([connection_id]),
                connection_id,
                active: true,
                bytes_in: 0,
                bytes_out: 0,
                created_at: Utc::now(),
            },
        );
        if let Some(mut attribution) = self.usage_tunnels.get_mut(&tunnel_id) {
            attribution.finished_at = None;
        }
        if let Some(old) = previous {
            self.finalize_usage_tunnel_locked(old.tunnel_id);
        } else {
            crate::metrics::ACTIVE_TUNNELS.inc();
        }
        Ok(())
    }

    fn check_connector_creation(
        &self,
        connection_id: ConnectionId,
        user_id: &String,
        subdomain: &str,
        tunnel_id: TunnelId,
        replacing_owned: bool,
    ) -> anyhow::Result<()> {
        let (owned_count, source_ip) = {
            let client = self
                .clients
                .get(&connection_id)
                .ok_or_else(|| anyhow::anyhow!("client connection not found"))?;
            (
                client.tunnels.len(),
                client
                    .info
                    .remote_addr
                    .map(|addr| addr.ip())
                    .unwrap_or(IpAddr::from([0, 0, 0, 0])),
            )
        };
        if owned_count.saturating_sub(usize::from(replacing_owned))
            >= self.max_tunnels_per_connection
        {
            anyhow::bail!(
                "tunnel limit per connection reached ({owned_count}/{})",
                self.max_tunnels_per_connection
            );
        }
        if self.abuse_detector.is_banned(user_id) {
            return Err(abuse_error_to_anyhow(AbuseError::UserBanned));
        }
        let now = tokio::time::Instant::now();
        self.lease_reconnects.retain(|_, deadline| *deadline > now);
        let reconnect = self.lease_reconnects.iter().find_map(|entry| {
            let (owner, host, runtime, _) = entry.key();
            (owner == user_id && host == subdomain && *runtime == tunnel_id)
                .then(|| entry.key().clone())
        });
        let reconnect = reconnect.is_some_and(|key| self.lease_reconnects.remove(&key).is_some());
        if !reconnect {
            self.abuse_detector
                .check_tunnel_creation_rate(user_id, source_ip)
                .map_err(abuse_error_to_anyhow)?;
        }
        Ok(())
    }

    pub fn unregister_tunnel(&self, subdomain: &str) {
        let _guard = self.lock_tunnels();
        let members = self
            .tunnels
            .get(subdomain)
            .map(|entry| entry.connections.clone())
            .unwrap_or_default();
        for owner in members {
            self.unregister_tunnel_if_owner_locked(subdomain, &owner);
        }
    }

    /// Remove only this connection's routing. A late disconnect cannot remove a
    /// replacement connection that registered the same hostname.
    pub fn unregister_tunnel_if_owner(
        &self,
        subdomain: &str,
        connection_id: &ConnectionId,
    ) -> bool {
        let _guard = self.lock_tunnels();
        self.unregister_tunnel_if_owner_locked(subdomain, connection_id)
    }

    fn unregister_tunnel_if_owner_locked(
        &self,
        subdomain: &str,
        connection_id: &ConnectionId,
    ) -> bool {
        let Some(mut entry) = self.tunnels.get_mut(subdomain) else {
            return false;
        };
        if !entry.connections.remove(connection_id) {
            return false;
        }
        if let Some(mut client) = self.clients.get_mut(connection_id) {
            client.unregister_tunnel(entry.tunnel_id);
        }
        if !entry.connections.is_empty() {
            self.refresh_live_owner(&mut entry);
            return false;
        }
        let tunnel = entry.clone();
        drop(entry);
        self.tunnels.remove(subdomain);
        self.rate_limiter.unregister_tunnel(tunnel.tunnel_id);
        self.tcp_listeners.remove_if(&tunnel.tunnel_id, |_, entry| {
            &entry.connection_id == connection_id
        });
        if let Some(mut client) = self.clients.get_mut(connection_id) {
            client.unregister_tunnel(tunnel.tunnel_id);
        }
        self.finalize_usage_tunnel_locked(tunnel.tunnel_id);
        crate::metrics::ACTIVE_TUNNELS.dec();
        true
    }

    pub fn register_tcp_listener(
        &self,
        connection_id: ConnectionId,
        tunnel_id: TunnelId,
        local_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let _guard = self.lock_tunnels();
        if !self.clients.contains_key(&connection_id) {
            anyhow::bail!("client connection not found: {connection_id}");
        }
        if !self
            .tunnels
            .iter()
            .any(|entry| entry.tunnel_id == tunnel_id && entry.connection_id == connection_id)
        {
            anyhow::bail!("TCP listener registration no longer owns the runtime tunnel");
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
        let _guard = self.lock_tunnels();
        self.tcp_listeners.remove(&tunnel_id);
    }

    pub fn unregister_tcp_listener_if_owner(
        &self,
        tunnel_id: TunnelId,
        connection_id: &ConnectionId,
    ) -> bool {
        let _guard = self.lock_tunnels();
        self.tcp_listeners
            .remove_if(&tunnel_id, |_, listener| {
                &listener.connection_id == connection_id
            })
            .is_some()
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

    fn refresh_live_owner(&self, entry: &mut TunnelEntry) {
        let live = entry.connections.iter().find(|id| {
            self.clients.get(id).is_some_and(|client| {
                !matches!(
                    client.state,
                    ConnectionState::Closed | ConnectionState::Draining
                )
            })
        });
        entry.active = live.is_some();
        if let Some(id) = live.or_else(|| entry.connections.first()) {
            entry.connection_id = *id;
        }
        if let Some(mut listener) = self.tcp_listeners.get_mut(&entry.tunnel_id) {
            listener.connection_id = entry.connection_id;
            listener.active = entry.active;
        }
    }

    pub fn mark_dead_connections(&self, timeout: Duration) -> Vec<ConnectionId> {
        let _guard = self.lock_tunnels();
        let mut dead = Vec::new();
        for mut item in self.clients.iter_mut() {
            if item.is_half_open(timeout) {
                item.state = ConnectionState::Closed;
                dead.push(*item.key());
            }
        }

        for dead_conn_id in &dead {
            self.tunnels.retain(|_, tunnel| {
                if tunnel.connections.contains(dead_conn_id) {
                    self.refresh_live_owner(tunnel);
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
        let _guard = self.lock_tunnels();
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

    /// Record inbound bytes (client -> upstream) for a tunnel and feed them into the
    /// monthly bandwidth quota accounting.
    pub fn track_bandwidth(&self, tunnel_id: TunnelId, bytes: u64) {
        self.track_transfer(tunnel_id, bytes, 0);
    }

    /// Record outbound bytes (upstream -> client) for a tunnel. Both directions count
    /// toward the monthly bandwidth quota (fixes #1/#3/#4).
    pub fn track_bandwidth_out(&self, tunnel_id: TunnelId, bytes: u64) {
        self.track_transfer(tunnel_id, 0, bytes);
    }

    pub fn track_transfer(&self, tunnel_id: TunnelId, incoming: u64, outgoing: u64) {
        if incoming == 0 && outgoing == 0 {
            return;
        }
        self.total_bytes_in.fetch_add(incoming, Ordering::Relaxed);
        self.total_bytes_out.fetch_add(outgoing, Ordering::Relaxed);
        self.rate_limiter
            .track_bandwidth(tunnel_id, incoming.saturating_add(outgoing));

        if let Some(mut tunnel) = self
            .tunnels
            .iter_mut()
            .find(|entry| entry.tunnel_id == tunnel_id)
        {
            tunnel.bytes_in = tunnel.bytes_in.saturating_add(incoming);
            tunnel.bytes_out = tunnel.bytes_out.saturating_add(outgoing);
        }
    }

    /// Returns true if the user identified by `user_id` is currently within their
    /// monthly bandwidth quota. Used by the TCP proxy path to refuse over-quota
    /// tunnels (fix #1).
    #[must_use]
    pub fn is_within_bandwidth_quota(&self, user_id: &str) -> bool {
        self.rate_limiter.check_bandwidth_quota(user_id).is_ok()
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

    pub fn kill_user_tunnels(&self, user_id: &str) -> anyhow::Result<()> {
        let matches: Vec<(ConnectionId, Option<String>)> = self
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
            .map(|entry| (*entry.key(), entry.info.api_key.clone()))
            .collect();

        for (connection_id, api_key) in matches {
            // Fix #6d/#7: revoke the live session's api key so an immediate reconnect
            // with the same key is rejected on the QUIC/WS login path.
            if let Some(api_key) = api_key {
                self.revoke_api_key(&api_key, user_id);
            }
            self.remove_client(&connection_id);
        }

        Ok(())
    }

    /// Insert an api key into the revoked set so subsequent logins with it are denied
    /// (fix #6d). Idempotent. `user_id` lets a later unban restore all of a user's keys.
    pub fn revoke_api_key(&self, api_key: &str, user_id: &str) {
        self.revoked_api_keys
            .insert(api_key.to_string(), user_id.to_string());
    }

    /// Remove a single api key from the revoked set.
    pub fn restore_api_key(&self, api_key: &str) {
        self.revoked_api_keys.remove(api_key);
    }

    /// Remove every revoked api key that belongs to `user_id` (e.g. on unban).
    pub fn restore_user_api_keys(&self, user_id: &str) {
        self.revoked_api_keys
            .retain(|_, owner| owner.as_str() != user_id);
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
    use crate::connection::{
        ClientConnection, ConnectionState, UserLimits, UserStatus, ValidatedUser,
    };

    use super::ClientRegistry;

    #[tokio::test]
    async fn connector_members_share_one_quota_and_retain_usage_until_the_last_leaves() {
        let registry = ClientRegistry::new_with_abuse_config(AbuseConfig {
            tunnel_creations_per_user_per_hour: 100,
            tunnel_creations_per_ip_per_hour: 100,
            ..AbuseConfig::default()
        });
        let add = |owner: &str| {
            let id = uuid::Uuid::new_v4();
            let mut client = ClientConnection::new(id, None);
            client.state = ConnectionState::Authenticated;
            client.set_validated_user(ValidatedUser {
                tunnel_limit: Some(1),
                user_id: owner.into(),
                email: "test@example.test".into(),
                plan: "free".into(),
                plan_expires_at: None,
                status: UserStatus::Active,
                limits: UserLimits::default(),
            });
            registry.register_client(client).unwrap();
            id
        };
        let tunnel = pike_core::types::TunnelId::new();
        let members: Vec<_> = (0..9).map(|_| add("owner")).collect();
        for member in &members[..8] {
            registry
                .register_connector(
                    *member,
                    "shared.test".into(),
                    tunnel,
                    "canonical".into(),
                    true,
                )
                .unwrap();
        }
        assert_eq!(registry.active_tunnels(), 1);
        registry
            .clients
            .get_mut(&members[0])
            .unwrap()
            .last_heartbeat = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(60))
            .unwrap();
        assert_eq!(
            registry.mark_dead_connections(std::time::Duration::from_secs(45)),
            vec![members[0]]
        );
        let live = registry.lookup_tunnel("shared.test").unwrap();
        assert!(live.active);
        assert_ne!(live.connection_id, members[0]);
        assert_eq!(
            registry
                .lookup_tunnel("shared.test")
                .unwrap()
                .connections
                .len(),
            8
        );
        assert!(registry
            .register_connector(
                members[8],
                "shared.test".into(),
                tunnel,
                "canonical".into(),
                true
            )
            .is_err());
        assert!(registry
            .register_connector(
                add("other"),
                "shared.test".into(),
                tunnel,
                "canonical".into(),
                true
            )
            .is_err());
        assert!(registry
            .register_connector(
                members[8],
                "shared.test".into(),
                tunnel,
                "different".into(),
                true
            )
            .is_err());
        assert!(registry
            .register_new_tunnel(
                members[8],
                "extra.test".into(),
                pike_core::types::TunnelId::new(),
                "extra".into(),
                true
            )
            .is_err());
        for member in &members[..7] {
            assert!(!registry.unregister_tunnel_if_owner("shared.test", member));
            registry.remove_client(member);
            assert!(registry.usage_tunnels()[0].finished_at.is_none());
            assert_eq!(registry.active_tunnels(), 1);
        }
        assert_eq!(
            registry.lookup_tunnel("shared.test").unwrap().connection_id,
            members[7]
        );
        assert!(!registry.unregister_tunnel_if_owner("shared.test", &members[0]));
        assert!(registry.unregister_tunnel_if_owner("shared.test", &members[7]));
        assert!(registry.usage_tunnels()[0].finished_at.is_some());
        assert_eq!(registry.active_tunnels(), 0);
        registry
            .register_connector(
                members[8],
                "shared.test".into(),
                tunnel,
                "canonical".into(),
                true,
            )
            .unwrap();
        assert!(registry.usage_tunnels()[0].finished_at.is_none());
    }

    #[tokio::test]
    async fn shared_endpoint_reconnect_allowances_are_per_member_and_single_use() {
        let registry = ClientRegistry::new_with_abuse_config(AbuseConfig {
            tunnel_creations_per_user_per_hour: 2,
            tunnel_creations_per_ip_per_hour: 100,
            ..AbuseConfig::default()
        });
        let add = || {
            let id = uuid::Uuid::new_v4();
            let mut client = ClientConnection::new(id, None);
            client.state = ConnectionState::Authenticated;
            client.set_validated_user(ValidatedUser {
                tunnel_limit: Some(1),
                user_id: "owner".into(),
                email: "test@example.test".into(),
                plan: "free".into(),
                plan_expires_at: None,
                status: UserStatus::Active,
                limits: UserLimits::default(),
            });
            registry.register_client(client).unwrap();
            id
        };
        let tunnel = pike_core::types::TunnelId::new();
        let first = add();
        let second = add();
        for id in [first, second] {
            registry
                .register_connector(id, "shared.test".into(), tunnel, "canonical".into(), true)
                .unwrap();
        }
        registry.allow_lease_reconnect(&first);
        registry.allow_lease_reconnect(&first);
        registry.allow_lease_reconnect(&second);
        registry.remove_client(&first);
        registry.remove_client(&second);
        for _ in 0..2 {
            registry
                .register_connector(
                    add(),
                    "shared.test".into(),
                    tunnel,
                    "canonical".into(),
                    true,
                )
                .unwrap();
        }
        assert!(registry
            .register_connector(
                add(),
                "shared.test".into(),
                tunnel,
                "canonical".into(),
                true
            )
            .is_err());
    }

    #[tokio::test]
    async fn lease_reconnect_credit_is_scoped_single_use_expiring_and_preserves_bans() {
        let registry = ClientRegistry::new_with_abuse_config(AbuseConfig {
            tunnel_creations_per_user_per_hour: 1,
            tunnel_creations_per_ip_per_hour: 100,
            ..AbuseConfig::default()
        });
        let add = |owner: &str| {
            let id = uuid::Uuid::new_v4();
            let mut client = ClientConnection::new(id, None);
            client.state = ConnectionState::Authenticated;
            client.set_validated_user(ValidatedUser {
                tunnel_limit: None,
                user_id: owner.into(),
                email: "fixture@example.test".into(),
                plan: "free".into(),
                plan_expires_at: None,
                status: UserStatus::Active,
                limits: UserLimits::default(),
            });
            registry.register_client(client).unwrap();
            id
        };
        let runtime = pike_core::types::TunnelId::new();
        let first = add("owner");
        registry
            .register_new_tunnel(first, "one.test".into(), runtime, "canonical".into(), true)
            .unwrap();
        registry.allow_lease_reconnect(&first);
        registry.remove_client(&first);
        let next = add("owner");
        assert!(registry
            .register_new_tunnel(
                next,
                "different.test".into(),
                pike_core::types::TunnelId::new(),
                "different".into(),
                true
            )
            .is_err());
        assert!(registry
            .register_new_tunnel(
                next,
                "one.test".into(),
                pike_core::types::TunnelId::new(),
                "changed".into(),
                true
            )
            .is_err());
        let other = add("other-owner");
        assert!(registry
            .register_new_tunnel(other, "one.test".into(), runtime, "canonical".into(), true)
            .is_err());
        registry.abuse_detector.ban_user("owner".into()).unwrap();
        assert!(registry
            .register_new_tunnel(next, "one.test".into(), runtime, "canonical".into(), true)
            .is_err());
        registry.abuse_detector.unban_user("owner".into()).unwrap();
        registry
            .register_new_tunnel(next, "one.test".into(), runtime, "canonical".into(), true)
            .unwrap();
        registry.remove_client(&next);
        let last = add("owner");
        assert!(
            registry
                .register_new_tunnel(last, "one.test".into(), runtime, "canonical".into(), true)
                .is_err(),
            "credit must be single use"
        );
        registry.lease_reconnects.insert(
            ("owner".into(), "one.test".into(), runtime, next),
            tokio::time::Instant::now() - std::time::Duration::from_secs(1),
        );
        assert!(
            registry
                .register_new_tunnel(last, "one.test".into(), runtime, "canonical".into(), true)
                .is_err(),
            "expired credit cannot bypass the creation limit"
        );
    }

    #[test]
    fn session_registration_rejects_live_routes_and_identity_conflicts_without_mutation() {
        let registry = ClientRegistry::new();
        let add_client = |user: &str| {
            let id = uuid::Uuid::new_v4();
            let mut client = ClientConnection::new(id, None);
            client.state = ConnectionState::Authenticated;
            client.set_validated_user(ValidatedUser {
                tunnel_limit: None,
                user_id: user.into(),
                email: "fixture@example.test".into(),
                plan: "free".into(),
                plan_expires_at: None,
                status: UserStatus::Active,
                limits: UserLimits::default(),
            });
            registry.register_client(client).unwrap();
            id
        };
        let old = add_client("owner");
        let new = add_client("owner");
        let other = add_client("other-owner");
        let runtime = pike_core::types::TunnelId::new();
        let rejected_runtime = pike_core::types::TunnelId::new();
        registry
            .register_new_tunnel(old, "live.test".into(), runtime, "canonical".into(), true)
            .unwrap();
        registry
            .register_tcp_listener(old, runtime, "127.0.0.1:12345".parse().unwrap())
            .unwrap();
        assert!(registry
            .register_new_tunnel(
                new,
                "live.test".into(),
                rejected_runtime,
                "replacement".into(),
                true,
            )
            .is_err());
        assert_eq!(
            registry.lookup_tunnel("live.test").unwrap().connection_id,
            old
        );
        assert_eq!(
            registry.lookup_tcp_listener(runtime).unwrap().connection_id,
            old
        );
        assert_eq!(registry.clients.get(&old).unwrap().tunnels, vec![runtime]);
        assert!(registry.clients.get(&new).unwrap().tunnels.is_empty());
        assert_eq!(registry.active_tunnels(), 1);
        assert_eq!(registry.usage_tunnels().len(), 1);
        assert_eq!(
            registry.public_tunnel_id(rejected_runtime),
            rejected_runtime.to_string()
        );

        registry.unregister_tunnel_if_owner("live.test", &old);
        let finished_at = registry.usage_tunnels()[0].finished_at;
        assert!(finished_at.is_some());
        for (connection, public_id) in [(new, "wrong-canonical"), (other, "canonical")] {
            assert!(registry
                .register_new_tunnel(
                    connection,
                    "live.test".into(),
                    runtime,
                    public_id.into(),
                    true
                )
                .is_err());
            assert_eq!(registry.active_tunnels(), 0);
            assert_eq!(registry.public_tunnel_id(runtime), "canonical");
            assert_eq!(registry.runtime_tunnel_id("canonical"), runtime.to_string());
            assert_eq!(registry.usage_tunnels()[0].finished_at, finished_at);
            assert!(registry
                .clients
                .get(&connection)
                .unwrap()
                .tunnels
                .is_empty());
        }
        // Valid retry still owns the free plan's sole quota slot. Failed identity
        // attempts neither consumed quota nor reactivated finalized attribution.
        registry
            .register_new_tunnel(new, "live.test".into(), runtime, "canonical".into(), true)
            .unwrap();
        assert!(registry.usage_tunnels()[0].finished_at.is_none());
        assert!(registry
            .register_new_tunnel(
                new,
                "extra.test".into(),
                rejected_runtime,
                "quota-rejected".into(),
                true,
            )
            .is_err());
        assert_eq!(
            registry.public_tunnel_id(rejected_runtime),
            rejected_runtime.to_string()
        );
        assert_eq!(
            registry.runtime_tunnel_id("quota-rejected"),
            "quota-rejected"
        );
        registry.remove_client(&old);
        assert_eq!(
            registry.lookup_tunnel("live.test").unwrap().connection_id,
            new
        );
        registry.remove_client(&new);
        registry.remove_client(&other);
    }

    #[tokio::test]
    async fn runtime_members_resolve_canonical_ids_across_every_identity_map() {
        use pike_core::types::TunnelId;

        let registry = ClientRegistry::new();
        let canonical = uuid::Uuid::new_v4();
        let public_id = canonical.to_string();
        let older = TunnelId::new();
        let latest = TunnelId::new();
        let usage_only = TunnelId::new();
        let unrelated = TunnelId::new();
        registry
            .remember_tunnel_identity(older, public_id.clone())
            .unwrap();
        registry
            .remember_tunnel_identity(latest, public_id.clone())
            .unwrap();
        registry
            .remember_usage_tunnel(usage_only, "owner".into(), public_id.clone())
            .unwrap();
        registry
            .remember_tunnel_identity(unrelated, uuid::Uuid::new_v4().to_string())
            .unwrap();
        assert_eq!(registry.runtime_tunnel_id(&public_id), latest.to_string());

        let members = registry.runtime_tunnel_members(TunnelId(canonical));
        assert_eq!(members.len(), 4, "{members:?}");
        for expected in [TunnelId(canonical), older, latest, usage_only] {
            assert!(
                members.contains(&expected),
                "{expected} missing from {members:?}"
            );
        }
        assert!(!members.contains(&unrelated));

        // A raw runtime ID with no canonical identity resolves to itself only.
        let standalone = TunnelId::new();
        assert_eq!(
            registry.runtime_tunnel_members(standalone),
            vec![standalone]
        );

        let suspended = registry
            .suspend_tunnel_identity(TunnelId(canonical))
            .unwrap();
        assert_eq!(suspended.len(), 4);
        for member in [older, latest, usage_only] {
            assert!(registry.abuse_detector.is_suspended(&member));
        }
        assert!(!registry.abuse_detector.is_suspended(&unrelated));
        registry
            .unsuspend_tunnel_identity(TunnelId(canonical))
            .unwrap();
        for member in [TunnelId(canonical), older, latest, usage_only] {
            assert!(!registry.abuse_detector.is_suspended(&member));
        }
    }

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
            .register_tunnel(conn_id, "tcp-listener.test".to_string(), tunnel_id)
            .expect("register tunnel owner");
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
            let mut client = ClientConnection::new(uuid::Uuid::from_u128(u128::from(i)), None);
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
            tunnel_limit: None,
            user_id: "pro-user".to_string(),
            email: "pro@example.com".to_string(),
            plan: "pro".to_string(),
            plan_expires_at: None,
            status: UserStatus::Active,
            limits: UserLimits::default(),
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
