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
}

impl TunnelEntry {
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }
}

#[derive(Debug, Default)]
pub struct VhostRouter {
    tunnels: Arc<DashMap<String, TunnelEntry>>,
}

impl VhostRouter {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, subdomain: &str, entry: TunnelEntry) {
        let normalized = normalize_host(subdomain);
        tracing::info!(subdomain = %subdomain, normalized = %normalized, "VhostRouter registering tunnel");
        self.tunnels.insert(normalized, entry);
        tracing::info!(
            tunnel_count = self.tunnels.len(),
            "VhostRouter tunnel count after register"
        );
    }

    pub fn unregister(&self, subdomain: &str) {
        tracing::warn!(subdomain = %subdomain, "VhostRouter unregistering tunnel");
        self.tunnels.remove(&normalize_host(subdomain));
        tracing::warn!(
            tunnel_count = self.tunnels.len(),
            "VhostRouter tunnel count after unregister"
        );
    }

    pub fn unregister_if_owner(&self, subdomain: &str, connection_id: &ConnectionId) {
        let normalized = normalize_host(subdomain);
        let removed = self.tunnels.remove_if(&normalized, |_, entry| {
            entry.connection_id == *connection_id
        });
        if removed.is_some() {
            tracing::warn!(subdomain = %subdomain, %connection_id, "VhostRouter unregistered tunnel (owner match)");
        } else {
            tracing::info!(subdomain = %subdomain, %connection_id, "VhostRouter skipped unregister (different owner)");
        }
    }

    pub fn unregister_by_connection_id(&self, connection_id: &ConnectionId) -> Vec<String> {
        let mut removed = Vec::new();
        self.tunnels.retain(|key, entry| {
            if entry.connection_id == *connection_id {
                removed.push(key.clone());
                false
            } else {
                true
            }
        });
        if !removed.is_empty() {
            tracing::info!(%connection_id, removed_count = removed.len(), "VhostRouter cleaned up entries for dead connection");
        }
        removed
    }

    #[must_use]
    pub fn route(&self, host: &str) -> Option<TunnelEntry> {
        let normalized = normalize_host(host);
        tracing::debug!(host = %host, normalized = %normalized, "VhostRouter route lookup");
        tracing::debug!(
            tunnel_count = self.tunnels.len(),
            "VhostRouter current tunnel count"
        );

        if let Some(entry) = self.tunnels.get(&normalized) {
            tracing::debug!("VhostRouter found exact match");
            return Some(entry.clone());
        }

        let subdomain = extract_subdomain_key(&normalized);
        tracing::debug!(subdomain = %subdomain, "VhostRouter trying subdomain key");
        if let Some(entry) = self.tunnels.get(&subdomain) {
            tracing::debug!("VhostRouter found subdomain match");
            return Some(entry.clone());
        }

        tracing::debug!("VhostRouter no match found");
        None
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

#[must_use]
pub fn extract_subdomain_key(host: &str) -> String {
    if !host.contains('.') {
        return host.to_string();
    }

    host.split('.').next().unwrap_or_default().to_string()
}

#[cfg(test)]
mod tests {
    use super::{extract_subdomain_key, normalize_host, TunnelEntry, VhostRouter};
    use pike_core::types::TunnelId;
    use tokio::sync::mpsc;

    #[test]
    fn normalize_host_removes_port_and_lowercases() {
        assert_eq!(normalize_host("Demo.Pike.Dev:8080"), "demo.pike.dev");
    }

    #[test]
    fn extract_subdomain_from_domain() {
        assert_eq!(extract_subdomain_key("demo.pike.life"), "demo");
        assert_eq!(extract_subdomain_key("demo"), "demo");
    }

    #[test]
    fn register_route_unregister_roundtrip() {
        let router = VhostRouter::new();
        let (tx, _rx) = mpsc::channel(8);
        let tunnel_id = TunnelId::new();
        let conn_id = uuid::Uuid::new_v4();

        router.register(
            "demo",
            TunnelEntry {
                tunnel_id,
                connection_id: conn_id,
                stream_tx: tx,
                active: true,
            },
        );

        let by_full_host = router.route("demo.pike.life").expect("route full host");
        assert_eq!(by_full_host.tunnel_id, tunnel_id);
        assert!(by_full_host.is_active());

        let by_subdomain = router.route("demo").expect("route short host");
        assert_eq!(by_subdomain.connection_id, conn_id);

        router.unregister("demo");
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
            },
        );

        router.register(
            "demo",
            TunnelEntry {
                tunnel_id: tunnel_id_b,
                connection_id: conn_id_b,
                stream_tx: tx_b,
                active: true,
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
