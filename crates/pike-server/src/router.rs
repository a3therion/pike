use std::sync::Arc;

use dashmap::DashMap;
use pike_core::types::TunnelId;
use tokio::sync::mpsc;

use crate::connection::ConnectionId;
use crate::proxy::TunnelRequest;

#[derive(Debug, Clone)]
pub struct TunnelEntry {
    pub tunnel_id: TunnelId,
    pub connection_id: ConnectionId,
    pub stream_tx: mpsc::Sender<TunnelRequest>,
    pub active: bool,
    pub visitor: Arc<crate::visitor_policy::VisitorGate>,
    pub domain: Option<Arc<crate::domain_grants::DomainGrant>>,
    pub origin_health: Option<Arc<crate::origin_health::ConnectorHealth>>,
}

impl TunnelEntry {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active && self.domain.as_ref().is_none_or(|grant| grant.is_active())
    }
}

#[derive(Debug)]
struct RouteGroup {
    members: Vec<TunnelEntry>,
    next: std::sync::atomic::AtomicUsize,
}

impl RouteGroup {
    fn select(&self, connection: Option<&ConnectionId>) -> Option<TunnelEntry> {
        let start = if connection.is_some() {
            0
        } else {
            self.next.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.members.len()
        };
        (0..self.members.len())
            .map(|offset| &self.members[(start + offset) % self.members.len()])
            .filter(|entry| {
                entry.is_active()
                    && !entry.stream_tx.is_closed()
                    && connection.is_none_or(|id| entry.connection_id == *id)
            })
            // min_by_key retains the first equal-ranked member, preserving the
            // rotating order. Replay names a connection and never changes it.
            .min_by_key(|entry| {
                entry
                    .origin_health
                    .as_ref()
                    .map_or(crate::origin_health::OriginReadiness::Unknown, |health| {
                        health.readiness()
                    })
            })
            // Preserve the known-but-disabled endpoint response. Disabled
            // routes never win selection while an active member is available.
            .or_else(|| {
                self.members.iter().find(|entry| {
                    !entry.active
                        && entry.domain.as_ref().is_none_or(|grant| grant.is_active())
                        && connection.is_none_or(|id| entry.connection_id == *id)
                })
            })
            .cloned()
    }
}

#[derive(Debug, Default)]
pub struct VhostRouter {
    tunnels: Arc<DashMap<String, RouteGroup>>,
}

impl VhostRouter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Explicit replacement is retained for low-level route setup. Production
    /// connector admission uses register_member and cannot replace a live group.
    pub fn register(&self, host: &str, entry: TunnelEntry) {
        self.tunnels.insert(
            normalize_host(host),
            RouteGroup {
                members: vec![entry],
                next: std::sync::atomic::AtomicUsize::new(0),
            },
        );
    }

    pub fn register_member(&self, host: &str, entry: TunnelEntry) -> anyhow::Result<()> {
        match self.tunnels.entry(normalize_host(host)) {
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                slot.insert(RouteGroup {
                    members: vec![entry],
                    next: std::sync::atomic::AtomicUsize::new(0),
                });
            }
            dashmap::mapref::entry::Entry::Occupied(mut slot) => {
                let group = slot.get_mut();
                let owner = &group.members[0];
                anyhow::ensure!(
                    owner.tunnel_id == entry.tunnel_id
                        && Arc::ptr_eq(&owner.visitor, &entry.visitor)
                        && match (&owner.domain, &entry.domain) {
                            (None, None) => true,
                            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
                            _ => false,
                        },
                    "connector route authority differs"
                );
                anyhow::ensure!(
                    !group
                        .members
                        .iter()
                        .any(|member| member.connection_id == entry.connection_id),
                    "connector route already registered"
                );
                anyhow::ensure!(
                    group.members.len() < crate::registry::MAX_CONNECTORS_PER_TUNNEL,
                    "connector route limit reached"
                );
                group.members.push(entry);
            }
        }
        Ok(())
    }

    pub fn unregister(&self, host: &str) {
        self.tunnels.remove(&normalize_host(host));
    }

    /// Each alias uses the same profile authority and this connector's channel.
    pub fn register_aliases(
        &self,
        primary: &str,
        connection_id: &ConnectionId,
        domains: &crate::domain_grants::DomainGrants,
    ) -> anyhow::Result<()> {
        let entry = self
            .route_for_connection(primary, connection_id)
            .ok_or_else(|| anyhow::anyhow!("primary connector route missing"))?;
        for (hostname, grant) in domains.hosts() {
            self.register_member(
                hostname,
                TunnelEntry {
                    domain: Some(grant.clone()),
                    ..entry.clone()
                },
            )?;
        }
        Ok(())
    }

    pub fn unregister_tunnel_if_owner(&self, tunnel_id: TunnelId, connection_id: &ConnectionId) {
        self.tunnels.retain(|_, group| {
            group.members.retain(|entry| {
                entry.tunnel_id != tunnel_id || entry.connection_id != *connection_id
            });
            !group.members.is_empty()
        });
    }

    pub fn unregister_if_owner(&self, host: &str, connection_id: &ConnectionId) {
        self.tunnels
            .remove_if_mut(&normalize_host(host), |_, group| {
                group
                    .members
                    .retain(|entry| entry.connection_id != *connection_id);
                group.members.is_empty()
            });
    }

    pub fn unregister_by_connection_id(&self, connection_id: &ConnectionId) -> Vec<String> {
        let mut affected = Vec::new();
        self.tunnels.retain(|host, group| {
            let count = group.members.len();
            group
                .members
                .retain(|entry| entry.connection_id != *connection_id);
            if group.members.len() != count {
                affected.push(host.clone());
            }
            !group.members.is_empty()
        });
        affected
    }

    /// New exchanges select one live member; their captured entry keeps the
    /// stream pinned. A disconnected channel is skipped before any bytes move.
    #[must_use]
    pub fn route(&self, host: &str) -> Option<TunnelEntry> {
        self.tunnels
            .get(&normalize_host(host))
            .and_then(|group| group.select(None))
    }

    /// Replay must retain the connector selected during authorization.
    #[must_use]
    pub fn route_for_connection(
        &self,
        host: &str,
        connection_id: &ConnectionId,
    ) -> Option<TunnelEntry> {
        self.tunnels
            .get(&normalize_host(host))
            .and_then(|group| group.select(Some(connection_id)))
    }
}

#[must_use]
pub fn normalize_host(host: &str) -> String {
    host.split(':')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{normalize_host, TunnelEntry, VhostRouter};
    use pike_core::types::TunnelId;
    use tokio::sync::mpsc;

    #[test]
    fn shared_routes_balance_live_members_and_pin_replay_without_weakening_authority() {
        let router = VhostRouter::new();
        let tunnel = TunnelId::new();
        let gate = crate::visitor_policy::VisitorGate::unrestricted();
        let (a, _a_rx) = mpsc::channel(4);
        let (b, b_rx) = mpsc::channel(4);
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        let entry = super::TunnelEntry {
            tunnel_id: tunnel,
            connection_id: first,
            stream_tx: a,
            active: true,
            visitor: gate.clone(),
            domain: None,
            origin_health: None,
        };
        router
            .register_member("shared.test", entry.clone())
            .unwrap();
        router
            .register_member(
                "shared.test",
                super::TunnelEntry {
                    connection_id: second,
                    stream_tx: b,
                    ..entry.clone()
                },
            )
            .unwrap();
        let selected: Vec<_> = (0..8)
            .map(|_| router.route("shared.test").unwrap().connection_id)
            .collect();
        assert_eq!(selected.iter().filter(|id| **id == first).count(), 4);
        assert_eq!(selected.iter().filter(|id| **id == second).count(), 4);
        assert_eq!(
            router
                .route_for_connection("shared.test", &second)
                .unwrap()
                .connection_id,
            second
        );
        assert!(router
            .register_member(
                "shared.test",
                super::TunnelEntry {
                    connection_id: uuid::Uuid::new_v4(),
                    visitor: crate::visitor_policy::VisitorGate::unrestricted(),
                    ..entry.clone()
                }
            )
            .is_err());
        drop(b_rx);
        for _ in 0..8 {
            assert_eq!(router.route("shared.test").unwrap().connection_id, first);
        }
        assert!(router
            .route_for_connection("shared.test", &second)
            .is_none());
        router.unregister_if_owner("shared.test", &second);
        assert_eq!(router.route("shared.test").unwrap().connection_id, first);
        router.unregister_by_connection_id(&second);
        assert!(gate.is_active());
        router.unregister_tunnel_if_owner(tunnel, &first);
        assert!(router.route("shared.test").is_none());
    }

    #[test]
    fn normalize_host_removes_port_and_lowercases() {
        assert_eq!(normalize_host("Demo.Pike.Dev:8080"), "demo.pike.dev");
    }

    #[test]
    fn register_route_unregister_roundtrip() {
        let router = VhostRouter::new();
        let (tx, _rx) = mpsc::channel(8);
        let tunnel_id = TunnelId::new();
        let conn_id = uuid::Uuid::new_v4();

        router.register(
            "demo.pike.life",
            TunnelEntry {
                tunnel_id,
                connection_id: conn_id,
                stream_tx: tx,
                active: true,
                visitor: crate::visitor_policy::VisitorGate::unrestricted(),
                domain: None,
                origin_health: None,
            },
        );

        let by_full_host = router.route("demo.pike.life").expect("route full host");
        assert_eq!(by_full_host.tunnel_id, tunnel_id);
        assert!(by_full_host.is_active());

        assert!(router.route("demo").is_none());
        assert!(router.route("demo.attacker.com").is_none());
        router.unregister("demo.pike.life");
        assert!(router.route("demo.pike.life").is_none());
    }

    #[test]
    fn reconnection_race_unregister_if_owner_skips_different_connection() {
        let router = VhostRouter::new();
        let (tx_a, _rx_a) = mpsc::channel(8);
        let (tx_b, _rx_b) = mpsc::channel(8);
        let tunnel_id_a = TunnelId::new();
        let tunnel_id_b = TunnelId::new();
        let conn_id_a = uuid::Uuid::new_v4();
        let conn_id_b = uuid::Uuid::new_v4();

        router.register(
            "demo",
            TunnelEntry {
                tunnel_id: tunnel_id_a,
                connection_id: conn_id_a,
                stream_tx: tx_a,
                active: true,
                visitor: crate::visitor_policy::VisitorGate::unrestricted(),
                domain: None,
                origin_health: None,
            },
        );

        router.register(
            "demo",
            TunnelEntry {
                tunnel_id: tunnel_id_b,
                connection_id: conn_id_b,
                stream_tx: tx_b,
                active: true,
                visitor: crate::visitor_policy::VisitorGate::unrestricted(),
                domain: None,
                origin_health: None,
            },
        );

        router.unregister_if_owner("demo", &conn_id_a);

        let entry = router
            .route("demo")
            .expect("connection B tunnel should still exist");
        assert_eq!(
            entry.connection_id, conn_id_b,
            "entry should still belong to connection B"
        );

        router.unregister_if_owner("demo", &conn_id_b);
        assert!(
            router.route("demo").is_none(),
            "after B cleanup, entry should be gone"
        );
    }

    #[test]
    fn unregister_by_connection_id_removes_all_for_connection() {
        let router = VhostRouter::new();
        let conn_id_a = uuid::Uuid::new_v4();
        let conn_id_b = uuid::Uuid::new_v4();

        for name in &["a1", "a2", "a3"] {
            let (tx, _rx) = mpsc::channel(8);
            router.register(
                name,
                TunnelEntry {
                    tunnel_id: TunnelId::new(),
                    connection_id: conn_id_a,
                    stream_tx: tx,
                    active: true,
                    visitor: crate::visitor_policy::VisitorGate::unrestricted(),
                    domain: None,
                    origin_health: None,
                },
            );
        }

        let (tx_b, _rx_b) = mpsc::channel(8);
        router.register(
            "b1",
            TunnelEntry {
                tunnel_id: TunnelId::new(),
                connection_id: conn_id_b,
                stream_tx: tx_b,
                active: true,
                visitor: crate::visitor_policy::VisitorGate::unrestricted(),
                domain: None,
                origin_health: None,
            },
        );

        router.unregister_by_connection_id(&conn_id_a);

        assert!(router.route("a1").is_none());
        assert!(router.route("a2").is_none());
        assert!(router.route("a3").is_none());

        let entry = router
            .route("b1")
            .expect("connection B tunnel should exist");
        assert_eq!(entry.connection_id, conn_id_b);
    }

    #[tokio::test]
    async fn concurrent_register_and_route() {
        use std::sync::Arc;

        let router = Arc::new(VhostRouter::new());
        let mut handles = vec![];

        for i in 0..10 {
            let r = router.clone();
            handles.push(tokio::spawn(async move {
                let subdomain = format!("sub{i}");
                let (tx, _rx) = mpsc::channel(8);
                r.register(
                    &subdomain,
                    TunnelEntry {
                        tunnel_id: TunnelId::new(),
                        connection_id: uuid::Uuid::new_v4(),
                        stream_tx: tx,
                        active: true,
                        visitor: crate::visitor_policy::VisitorGate::unrestricted(),
                        domain: None,
                        origin_health: None,
                    },
                );

                assert!(
                    r.route(&subdomain).is_some(),
                    "route should find {subdomain}"
                );
            }));
        }

        for handle in handles {
            handle.await.expect("task should not panic");
        }
    }
}
