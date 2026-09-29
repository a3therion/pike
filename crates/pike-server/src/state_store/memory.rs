//! In-process counters, request history and metric snapshots.
use super::metrics::{apply_metrics_delta, persisted_metrics_seed};
use super::StateStore;
use crate::{
    abuse::AbuseLogEntry,
    request_log::RequestLogEntry,
    tunnel_metrics::{PersistedTunnelMetrics, PersistedTunnelMetricsDelta},
};
use anyhow::Result;
use async_trait::async_trait;
use dashmap::DashMap;
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Instant,
};
const MAX_ABUSE_LOGS: usize = 10_000;
#[derive(Debug, Clone)]
struct BanEntry {
    #[allow(dead_code)]
    reason: String,
    expires_at: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct InMemoryStateStore {
    counters: DashMap<String, u64>,
    bans: DashMap<String, BanEntry>,
    suspensions: DashMap<String, BanEntry>,
    abuse_logs: Arc<Mutex<VecDeque<AbuseLogEntry>>>,
    request_logs: Arc<Mutex<HashMap<String, VecDeque<RequestLogEntry>>>>,
    tunnel_metrics: Arc<Mutex<HashMap<String, PersistedTunnelMetrics>>>,
}

impl InMemoryStateStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            counters: DashMap::new(),
            bans: DashMap::new(),
            suspensions: DashMap::new(),
            abuse_logs: Arc::new(Mutex::new(VecDeque::new())),
            request_logs: Arc::new(Mutex::new(HashMap::new())),
            tunnel_metrics: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn counter_key(key: &str) -> String {
        format!("counter:{key}")
    }

    fn bandwidth_key(key: &str) -> String {
        format!("bandwidth:{key}")
    }

    fn gauge_key(key: &str) -> String {
        format!("gauge:{key}")
    }
}

#[async_trait]
impl StateStore for InMemoryStateStore {
    async fn get_counter(&self, key: &str) -> Result<Option<u64>> {
        Ok(self
            .counters
            .get(&Self::counter_key(key))
            .map(|entry| *entry))
    }

    async fn increment_counter(&self, key: &str, window_secs: u64) -> Result<u64> {
        self.increment_counter_by(key, 1, window_secs).await
    }

    async fn increment_counter_by(&self, key: &str, amount: u64, _window_secs: u64) -> Result<u64> {
        let key = Self::counter_key(key);
        let mut entry = self.counters.entry(key).or_insert(0);
        *entry = entry.saturating_add(amount);
        Ok(*entry)
    }

    async fn get_bandwidth(&self, key: &str) -> Result<u64> {
        Ok(self
            .counters
            .get(&Self::bandwidth_key(key))
            .map_or(0, |entry| *entry))
    }

    async fn add_bandwidth(&self, key: &str, bytes: u64) -> Result<u64> {
        let key = Self::bandwidth_key(key);
        let mut entry = self.counters.entry(key).or_insert(0);
        *entry = entry.saturating_add(bytes);
        Ok(*entry)
    }

    async fn increment_gauge(&self, key: &str) -> Result<u64> {
        let key = Self::gauge_key(key);
        let mut entry = self.counters.entry(key).or_insert(0);
        *entry = entry.saturating_add(1);
        Ok(*entry)
    }

    async fn decrement_gauge(&self, key: &str) -> Result<u64> {
        let key = Self::gauge_key(key);
        let mut entry = self.counters.entry(key).or_insert(0);
        *entry = entry.saturating_sub(1);
        Ok(*entry)
    }

    async fn get_gauge(&self, key: &str) -> Result<u64> {
        Ok(self
            .counters
            .get(&Self::gauge_key(key))
            .map_or(0, |entry| *entry))
    }

    async fn is_banned(&self, user_id: &str) -> Result<bool> {
        let Some(entry) = self.bans.get(user_id) else {
            return Ok(false);
        };

        if entry
            .expires_at
            .is_some_and(|expires_at| expires_at <= Instant::now())
        {
            drop(entry);
            self.bans.remove(user_id);
            return Ok(false);
        }

        Ok(true)
    }

    async fn ban_user(&self, user_id: &str, reason: &str, duration_secs: u64) -> Result<()> {
        let expires_at = if duration_secs == 0 {
            None
        } else {
            Some(Instant::now() + std::time::Duration::from_secs(duration_secs))
        };

        self.bans.insert(
            user_id.to_string(),
            BanEntry {
                reason: reason.to_string(),
                expires_at,
            },
        );
        Ok(())
    }

    async fn unban_user(&self, user_id: &str) -> Result<()> {
        self.bans.remove(user_id);
        Ok(())
    }

    async fn is_tunnel_suspended(&self, tunnel_id: &str) -> Result<bool> {
        let Some(entry) = self.suspensions.get(tunnel_id) else {
            return Ok(false);
        };

        if entry
            .expires_at
            .is_some_and(|expires_at| expires_at <= Instant::now())
        {
            drop(entry);
            self.suspensions.remove(tunnel_id);
            return Ok(false);
        }

        Ok(true)
    }

    async fn suspend_tunnel(
        &self,
        tunnel_id: &str,
        reason: &str,
        duration_secs: u64,
    ) -> Result<()> {
        let expires_at = if duration_secs == 0 {
            None
        } else {
            Some(Instant::now() + std::time::Duration::from_secs(duration_secs))
        };

        self.suspensions.insert(
            tunnel_id.to_string(),
            BanEntry {
                reason: reason.to_string(),
                expires_at,
            },
        );
        Ok(())
    }

    async fn unsuspend_tunnel(&self, tunnel_id: &str) -> Result<()> {
        self.suspensions.remove(tunnel_id);
        Ok(())
    }

    async fn log_abuse(&self, entry: &AbuseLogEntry) -> Result<()> {
        let mut logs = self
            .abuse_logs
            .lock()
            .map_err(|_| anyhow::anyhow!("abuse log mutex poisoned"))?;

        logs.push_front(entry.clone());
        while logs.len() > MAX_ABUSE_LOGS {
            logs.pop_back();
        }

        Ok(())
    }

    async fn get_abuse_logs(&self, limit: usize) -> Result<Vec<AbuseLogEntry>> {
        let logs = self
            .abuse_logs
            .lock()
            .map_err(|_| anyhow::anyhow!("abuse log mutex poisoned"))?;
        Ok(logs.iter().take(limit).cloned().collect())
    }

    async fn append_request_log(&self, entry: &RequestLogEntry, max_entries: usize) -> Result<()> {
        let mut request_logs = self
            .request_logs
            .lock()
            .map_err(|_| anyhow::anyhow!("request log mutex poisoned"))?;
        let entries = request_logs
            .entry(entry.tunnel_id.clone())
            .or_insert_with(VecDeque::new);
        entries.push_front(entry.clone());
        while entries.len() > max_entries {
            entries.pop_back();
        }
        Ok(())
    }

    async fn get_request_logs(
        &self,
        tunnel_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<RequestLogEntry>, usize)> {
        let request_logs = self
            .request_logs
            .lock()
            .map_err(|_| anyhow::anyhow!("request log mutex poisoned"))?;
        let Some(entries) = request_logs.get(tunnel_id) else {
            return Ok((vec![], 0));
        };

        let total = entries.len();
        let items = entries.iter().skip(offset).take(limit).cloned().collect();
        Ok((items, total))
    }

    async fn remember_tunnel_owner(
        &self,
        tunnel_id: &str,
        owner_user_id: &str,
        created_at_unix_sec: u64,
        created_at_rfc3339: &str,
        last_activity_unix_ms: u64,
    ) -> Result<()> {
        let mut tunnel_metrics = self
            .tunnel_metrics
            .lock()
            .map_err(|_| anyhow::anyhow!("tunnel metrics mutex poisoned"))?;
        let metrics = tunnel_metrics
            .entry(tunnel_id.to_string())
            .or_insert_with(|| {
                persisted_metrics_seed(
                    created_at_unix_sec,
                    created_at_rfc3339,
                    last_activity_unix_ms,
                )
            });
        if metrics.owner_user_id.is_none() {
            metrics.owner_user_id = Some(owner_user_id.to_string());
        }
        metrics.last_activity_unix_ms = metrics.last_activity_unix_ms.max(last_activity_unix_ms);
        Ok(())
    }

    async fn record_tunnel_metrics(
        &self,
        tunnel_id: &str,
        delta: &PersistedTunnelMetricsDelta,
    ) -> Result<()> {
        let mut tunnel_metrics = self
            .tunnel_metrics
            .lock()
            .map_err(|_| anyhow::anyhow!("tunnel metrics mutex poisoned"))?;
        let metrics = tunnel_metrics
            .entry(tunnel_id.to_string())
            .or_insert_with(|| {
                persisted_metrics_seed(
                    delta.created_at_unix_sec,
                    &delta.created_at_rfc3339,
                    delta.last_activity_unix_ms,
                )
            });
        apply_metrics_delta(metrics, delta);
        Ok(())
    }

    async fn get_tunnel_metrics(&self, tunnel_id: &str) -> Result<Option<PersistedTunnelMetrics>> {
        let tunnel_metrics = self
            .tunnel_metrics
            .lock()
            .map_err(|_| anyhow::anyhow!("tunnel metrics mutex poisoned"))?;
        Ok(tunnel_metrics.get(tunnel_id).cloned())
    }
}
