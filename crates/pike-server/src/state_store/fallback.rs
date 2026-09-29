//! Explicit primary/fallback behavior for optional cache storage.
use super::{InMemoryStateStore, StateStore};
use crate::{
    abuse::AbuseLogEntry,
    request_log::RequestLogEntry,
    tunnel_metrics::{PersistedTunnelMetrics, PersistedTunnelMetricsDelta},
};
use anyhow::Result;
use async_trait::async_trait;
use std::sync::Arc;
use tracing::warn;
pub struct FallbackStateStore {
    primary: Arc<dyn StateStore>,
    fallback: Arc<InMemoryStateStore>,
}

impl FallbackStateStore {
    #[must_use]
    pub fn new(primary: Arc<dyn StateStore>, fallback: Arc<InMemoryStateStore>) -> Self {
        Self { primary, fallback }
    }
}

#[async_trait]
impl StateStore for FallbackStateStore {
    async fn get_counter(&self, key: &str) -> Result<Option<u64>> {
        match self.primary.get_counter(key).await {
            Ok(value) => Ok(value),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.get_counter(key).await
            }
        }
    }

    async fn increment_counter(&self, key: &str, window_secs: u64) -> Result<u64> {
        match self.primary.increment_counter(key, window_secs).await {
            Ok(value) => Ok(value),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.increment_counter(key, window_secs).await
            }
        }
    }

    async fn increment_counter_by(&self, key: &str, amount: u64, window_secs: u64) -> Result<u64> {
        match self
            .primary
            .increment_counter_by(key, amount, window_secs)
            .await
        {
            Ok(value) => Ok(value),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback
                    .increment_counter_by(key, amount, window_secs)
                    .await
            }
        }
    }

    async fn get_bandwidth(&self, key: &str) -> Result<u64> {
        match self.primary.get_bandwidth(key).await {
            Ok(value) => Ok(value),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.get_bandwidth(key).await
            }
        }
    }

    async fn add_bandwidth(&self, key: &str, bytes: u64) -> Result<u64> {
        match self.primary.add_bandwidth(key, bytes).await {
            Ok(value) => Ok(value),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.add_bandwidth(key, bytes).await
            }
        }
    }

    async fn increment_gauge(&self, key: &str) -> Result<u64> {
        match self.primary.increment_gauge(key).await {
            Ok(value) => Ok(value),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.increment_gauge(key).await
            }
        }
    }

    async fn decrement_gauge(&self, key: &str) -> Result<u64> {
        match self.primary.decrement_gauge(key).await {
            Ok(value) => Ok(value),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.decrement_gauge(key).await
            }
        }
    }

    async fn get_gauge(&self, key: &str) -> Result<u64> {
        match self.primary.get_gauge(key).await {
            Ok(value) => Ok(value),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.get_gauge(key).await
            }
        }
    }

    async fn is_banned(&self, user_id: &str) -> Result<bool> {
        match self.primary.is_banned(user_id).await {
            Ok(value) => Ok(value),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.is_banned(user_id).await
            }
        }
    }

    async fn ban_user(&self, user_id: &str, reason: &str, duration_secs: u64) -> Result<()> {
        match self.primary.ban_user(user_id, reason, duration_secs).await {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.ban_user(user_id, reason, duration_secs).await
            }
        }
    }

    async fn unban_user(&self, user_id: &str) -> Result<()> {
        match self.primary.unban_user(user_id).await {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.unban_user(user_id).await
            }
        }
    }

    async fn is_tunnel_suspended(&self, tunnel_id: &str) -> Result<bool> {
        match self.primary.is_tunnel_suspended(tunnel_id).await {
            Ok(value) => Ok(value),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.is_tunnel_suspended(tunnel_id).await
            }
        }
    }

    async fn suspend_tunnel(
        &self,
        tunnel_id: &str,
        reason: &str,
        duration_secs: u64,
    ) -> Result<()> {
        match self
            .primary
            .suspend_tunnel(tunnel_id, reason, duration_secs)
            .await
        {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback
                    .suspend_tunnel(tunnel_id, reason, duration_secs)
                    .await
            }
        }
    }

    async fn unsuspend_tunnel(&self, tunnel_id: &str) -> Result<()> {
        match self.primary.unsuspend_tunnel(tunnel_id).await {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.unsuspend_tunnel(tunnel_id).await
            }
        }
    }

    async fn log_abuse(&self, entry: &AbuseLogEntry) -> Result<()> {
        match self.primary.log_abuse(entry).await {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.log_abuse(entry).await
            }
        }
    }

    async fn get_abuse_logs(&self, limit: usize) -> Result<Vec<AbuseLogEntry>> {
        match self.primary.get_abuse_logs(limit).await {
            Ok(value) => Ok(value),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.get_abuse_logs(limit).await
            }
        }
    }

    async fn append_request_log(&self, entry: &RequestLogEntry, max_entries: usize) -> Result<()> {
        match self.primary.append_request_log(entry, max_entries).await {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.append_request_log(entry, max_entries).await
            }
        }
    }

    async fn get_request_logs(
        &self,
        tunnel_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<RequestLogEntry>, usize)> {
        match self
            .primary
            .get_request_logs(tunnel_id, limit, offset)
            .await
        {
            Ok(value) => Ok(value),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback
                    .get_request_logs(tunnel_id, limit, offset)
                    .await
            }
        }
    }

    async fn remember_tunnel_owner(
        &self,
        tunnel_id: &str,
        owner_user_id: &str,
        created_at_unix_sec: u64,
        created_at_rfc3339: &str,
        last_activity_unix_ms: u64,
    ) -> Result<()> {
        match self
            .primary
            .remember_tunnel_owner(
                tunnel_id,
                owner_user_id,
                created_at_unix_sec,
                created_at_rfc3339,
                last_activity_unix_ms,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback
                    .remember_tunnel_owner(
                        tunnel_id,
                        owner_user_id,
                        created_at_unix_sec,
                        created_at_rfc3339,
                        last_activity_unix_ms,
                    )
                    .await
            }
        }
    }

    async fn record_tunnel_metrics(
        &self,
        tunnel_id: &str,
        delta: &PersistedTunnelMetricsDelta,
    ) -> Result<()> {
        match self.primary.record_tunnel_metrics(tunnel_id, delta).await {
            Ok(()) => Ok(()),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.record_tunnel_metrics(tunnel_id, delta).await
            }
        }
    }

    async fn get_tunnel_metrics(&self, tunnel_id: &str) -> Result<Option<PersistedTunnelMetrics>> {
        match self.primary.get_tunnel_metrics(tunnel_id).await {
            Ok(value) => Ok(value),
            Err(err) => {
                warn!("Redis unavailable, using in-memory fallback: {err}");
                self.fallback.get_tunnel_metrics(tunnel_id).await
            }
        }
    }
}
