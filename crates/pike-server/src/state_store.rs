//! Storage contract shared by the relay, with distinct memory/Redis/fallback implementations.
mod fallback;
mod memory;
mod metrics;
mod redis;
use crate::{
    abuse::AbuseLogEntry,
    request_log::RequestLogEntry,
    tunnel_metrics::{PersistedTunnelMetrics, PersistedTunnelMetricsDelta},
};
use anyhow::Result;
use async_trait::async_trait;
pub use fallback::FallbackStateStore;
pub use memory::InMemoryStateStore;
pub use redis::RedisStateStore;
#[async_trait]
pub trait StateStore: Send + Sync {
    async fn get_counter(&self, key: &str) -> Result<Option<u64>>;
    async fn increment_counter(&self, key: &str, window_secs: u64) -> Result<u64>;
    async fn increment_counter_by(&self, key: &str, amount: u64, window_secs: u64) -> Result<u64>;
    async fn get_bandwidth(&self, key: &str) -> Result<u64>;
    async fn add_bandwidth(&self, key: &str, bytes: u64) -> Result<u64>;
    async fn increment_gauge(&self, key: &str) -> Result<u64>;
    async fn decrement_gauge(&self, key: &str) -> Result<u64>;
    async fn get_gauge(&self, key: &str) -> Result<u64>;
    async fn is_banned(&self, user_id: &str) -> Result<bool>;
    async fn ban_user(&self, user_id: &str, reason: &str, duration_secs: u64) -> Result<()>;
    async fn unban_user(&self, user_id: &str) -> Result<()>;
    async fn is_tunnel_suspended(&self, tunnel_id: &str) -> Result<bool>;
    async fn suspend_tunnel(&self, tunnel_id: &str, reason: &str, duration_secs: u64)
        -> Result<()>;
    async fn unsuspend_tunnel(&self, tunnel_id: &str) -> Result<()>;
    async fn log_abuse(&self, entry: &AbuseLogEntry) -> Result<()>;
    async fn get_abuse_logs(&self, limit: usize) -> Result<Vec<AbuseLogEntry>>;
    async fn append_request_log(&self, entry: &RequestLogEntry, max_entries: usize) -> Result<()>;
    async fn get_request_logs(
        &self,
        tunnel_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<RequestLogEntry>, usize)>;
    async fn remember_tunnel_owner(
        &self,
        tunnel_id: &str,
        owner_user_id: &str,
        created_at_unix_sec: u64,
        created_at_rfc3339: &str,
        last_activity_unix_ms: u64,
    ) -> Result<()>;
    async fn record_tunnel_metrics(
        &self,
        tunnel_id: &str,
        delta: &PersistedTunnelMetricsDelta,
    ) -> Result<()>;
    async fn get_tunnel_metrics(&self, tunnel_id: &str) -> Result<Option<PersistedTunnelMetrics>>;
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use chrono::Utc;
    use pike_core::types::TunnelId;

    use super::{FallbackStateStore, InMemoryStateStore, RedisStateStore, StateStore};
    use crate::abuse::AbuseLogEntry;
    use crate::request_log::RequestLogEntry;
    use crate::tunnel_metrics::PersistedTunnelMetricsDelta;

    #[tokio::test]
    async fn test_in_memory_store_basic_ops() {
        let store = InMemoryStateStore::new();

        let counter = store
            .increment_counter("requests:user-a", 60)
            .await
            .expect("increment counter");
        assert_eq!(counter, 1);
        assert_eq!(
            store
                .get_counter("requests:user-a")
                .await
                .expect("get counter"),
            Some(1)
        );

        let bandwidth = store
            .add_bandwidth("bw:user-a", 1024)
            .await
            .expect("add bandwidth");
        assert_eq!(bandwidth, 1024);
        assert_eq!(
            store
                .get_bandwidth("bw:user-a")
                .await
                .expect("get bandwidth"),
            1024
        );

        store
            .ban_user("user-a", "test", 60)
            .await
            .expect("ban user");
        assert!(store.is_banned("user-a").await.expect("is banned"));
        store.unban_user("user-a").await.expect("unban user");
        assert!(!store
            .is_banned("user-a")
            .await
            .expect("is banned after unban"));

        assert!(!store.is_tunnel_suspended("tunnel-1").await.expect("query"));
        store
            .suspend_tunnel("tunnel-1", "abuse", 0)
            .await
            .expect("suspend tunnel");
        assert!(store.is_tunnel_suspended("tunnel-1").await.expect("query"));
        store
            .unsuspend_tunnel("tunnel-1")
            .await
            .expect("unsuspend tunnel");
        assert!(!store.is_tunnel_suspended("tunnel-1").await.expect("query"));

        let entry = AbuseLogEntry {
            timestamp: Utc::now(),
            source_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            user_id: Some("user-a".to_string()),
            tunnel_id: Some(TunnelId::new()),
            request_count_per_minute: Some(42),
            bandwidth_bytes: Some(1024),
            reason: "suspicious payload".to_string(),
        };
        store.log_abuse(&entry).await.expect("log abuse");
        let logs = store.get_abuse_logs(10).await.expect("get abuse logs");
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].reason, entry.reason);

        let request_log = RequestLogEntry {
            id: "req-1".to_string(),
            timestamp: "2026-03-21T10:00:00Z".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            status_code: 200,
            duration_ms: 11,
            request_size: 12,
            response_size: 13,
            tunnel_id: "tunnel-1".to_string(),
        };
        store
            .append_request_log(&request_log, 1_000)
            .await
            .expect("append request log");
        let (request_logs, total) = store
            .get_request_logs("tunnel-1", 10, 0)
            .await
            .expect("get request logs");
        assert_eq!(total, 1);
        assert_eq!(request_logs[0].id, "req-1");

        store
            .remember_tunnel_owner("tunnel-1", "user-a", 123, "2026-03-21T10:00:00Z", 123_000)
            .await
            .expect("remember tunnel owner");
        store
            .record_tunnel_metrics(
                "tunnel-1",
                &PersistedTunnelMetricsDelta {
                    created_at_unix_sec: 123,
                    created_at_rfc3339: "2026-03-21T10:00:00Z".to_string(),
                    last_activity_unix_ms: 124_000,
                    total_requests_delta: 1,
                    bytes_in_delta: 64,
                    bytes_out_delta: 128,
                    status_2xx_delta: 1,
                    status_4xx_delta: 0,
                    status_5xx_delta: 0,
                    total_latency_ms_delta: 25,
                    minute_start_unix_sec: 120,
                    minute_count_delta: 1,
                    minute_total_latency_ms_delta: 25,
                    pruned_minute_starts: vec![],
                },
            )
            .await
            .expect("record tunnel metrics");
        let metrics = store
            .get_tunnel_metrics("tunnel-1")
            .await
            .expect("get tunnel metrics")
            .expect("metrics should exist");
        assert_eq!(metrics.owner_user_id.as_deref(), Some("user-a"));
        assert_eq!(metrics.total_requests, 1);
        assert_eq!(metrics.bytes_out, 128);
    }

    #[tokio::test]
    async fn test_fallback_store_degrades_gracefully() {
        let redis = RedisStateStore::new("redis://127.0.0.1:1/").expect("create redis store");
        let store = FallbackStateStore::new(
            Arc::new(redis) as Arc<dyn StateStore>,
            Arc::new(InMemoryStateStore::new()),
        );

        assert_eq!(
            store
                .increment_counter("requests:user-b", 60)
                .await
                .expect("increment via fallback"),
            1
        );
        assert_eq!(
            store
                .add_bandwidth("bw:user-b", 512)
                .await
                .expect("bandwidth via fallback"),
            512
        );

        store
            .ban_user("user-b", "fallback test", 60)
            .await
            .expect("ban via fallback");
        assert!(store
            .is_banned("user-b")
            .await
            .expect("is banned via fallback"));
        store
            .unban_user("user-b")
            .await
            .expect("unban via fallback");
        assert!(!store
            .is_banned("user-b")
            .await
            .expect("is unbanned via fallback"));

        store
            .suspend_tunnel("tunnel-b", "fallback test", 60)
            .await
            .expect("suspend via fallback");
        assert!(store
            .is_tunnel_suspended("tunnel-b")
            .await
            .expect("suspended via fallback"));
        store
            .unsuspend_tunnel("tunnel-b")
            .await
            .expect("unsuspend via fallback");
        assert!(!store
            .is_tunnel_suspended("tunnel-b")
            .await
            .expect("lifted via fallback"));
    }
}
