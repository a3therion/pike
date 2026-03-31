use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use deadpool_redis::redis::{self, AsyncCommands};
use deadpool_redis::{Config as RedisConfig, Pool, Runtime};
use tracing::warn;

use crate::abuse::AbuseLogEntry;
use crate::request_log::RequestLogEntry;
use crate::tunnel_metrics::{
    PersistedMinuteBucket, PersistedTunnelMetrics, PersistedTunnelMetricsDelta, MAX_MINUTE_BUCKETS,
};

const MAX_ABUSE_LOGS: usize = 10_000;
const ABUSE_LOGS_KEY: &str = "abuse:logs";
const MAX_ABUSE_LOGS_I64: i64 = 9_999;
const FIELD_CREATED_AT_UNIX_SEC: &str = "created_at_unix_sec";
const FIELD_CREATED_AT_RFC3339: &str = "created_at_rfc3339";
const FIELD_LAST_ACTIVITY_UNIX_MS: &str = "last_activity_unix_ms";
const FIELD_OWNER_USER_ID: &str = "owner_user_id";
const FIELD_TOTAL_REQUESTS: &str = "total_requests";
const FIELD_BYTES_IN: &str = "bytes_in";
const FIELD_BYTES_OUT: &str = "bytes_out";
const FIELD_STATUS_2XX: &str = "status_2xx";
const FIELD_STATUS_4XX: &str = "status_4xx";
const FIELD_STATUS_5XX: &str = "status_5xx";
const FIELD_TOTAL_LATENCY_MS: &str = "total_latency_ms";

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

#[derive(Debug, Clone)]
pub struct RedisStateStore {
    pool: Pool,
}

impl RedisStateStore {
    pub fn new(redis_url: &str) -> Result<Self> {
        let cfg = RedisConfig::from_url(redis_url.to_string());
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1))
            .context("failed to create Redis pool")?;
        Ok(Self { pool })
    }

    pub async fn ping(&self) -> Result<()> {
        let mut conn = self.get_conn().await?;
        let response: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .context("failed to ping Redis")?;
        if response == "PONG" {
            Ok(())
        } else {
            anyhow::bail!("unexpected Redis ping response: {response}");
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

    fn ban_key(user_id: &str) -> String {
        format!("user:ban:{user_id}")
    }

    fn request_log_key(tunnel_id: &str) -> String {
        format!("request_logs:{tunnel_id}")
    }

    fn tunnel_metrics_summary_key(tunnel_id: &str) -> String {
        format!("tunnel_metrics:{tunnel_id}:summary")
    }

    fn tunnel_metrics_counts_key(tunnel_id: &str) -> String {
        format!("tunnel_metrics:{tunnel_id}:counts")
    }

    fn tunnel_metrics_latency_key(tunnel_id: &str) -> String {
        format!("tunnel_metrics:{tunnel_id}:latency")
    }

    async fn get_conn(&self) -> Result<deadpool_redis::Connection> {
        self.pool
            .get()
            .await
            .context("failed to get Redis connection")
    }
}

#[async_trait]
impl StateStore for RedisStateStore {
    async fn get_counter(&self, key: &str) -> Result<Option<u64>> {
        let mut conn = self.get_conn().await?;
        let value = conn
            .get::<_, Option<u64>>(Self::counter_key(key))
            .await
            .context("failed to get counter from Redis")?;
        Ok(value)
    }

    async fn increment_counter(&self, key: &str, window_secs: u64) -> Result<u64> {
        self.increment_counter_by(key, 1, window_secs).await
    }

    async fn increment_counter_by(&self, key: &str, amount: u64, window_secs: u64) -> Result<u64> {
        let mut conn = self.get_conn().await?;
        let key = Self::counter_key(key);
        let (value, _): (u64, bool) = redis::pipe()
            .atomic()
            .cmd("INCRBY")
            .arg(&key)
            .arg(amount)
            .cmd("EXPIRE")
            .arg(&key)
            .arg(window_secs)
            .query_async(&mut conn)
            .await
            .context("failed to increment counter in Redis")?;
        Ok(value)
    }

    async fn get_bandwidth(&self, key: &str) -> Result<u64> {
        let mut conn = self.get_conn().await?;
        let value = conn
            .get::<_, Option<u64>>(Self::bandwidth_key(key))
            .await
            .context("failed to get bandwidth from Redis")?
            .unwrap_or(0);
        Ok(value)
    }

    async fn add_bandwidth(&self, key: &str, bytes: u64) -> Result<u64> {
        let mut conn = self.get_conn().await?;
        let key = Self::bandwidth_key(key);
        let value = conn
            .incr::<_, _, u64>(key, bytes)
            .await
            .context("failed to increment bandwidth in Redis")?;
        Ok(value)
    }

    async fn increment_gauge(&self, key: &str) -> Result<u64> {
        let mut conn = self.get_conn().await?;
        let key = Self::gauge_key(key);
        let value = conn
            .incr::<_, _, u64>(key, 1_u64)
            .await
            .context("failed to increment gauge in Redis")?;
        Ok(value)
    }

    async fn decrement_gauge(&self, key: &str) -> Result<u64> {
        let mut conn = self.get_conn().await?;
        let script = redis::Script::new(
            "local current = tonumber(redis.call('GET', KEYS[1]) or '0')\n\
             if current <= 0 then\n\
               redis.call('SET', KEYS[1], 0)\n\
               return 0\n\
             end\n\
             current = current - 1\n\
             redis.call('SET', KEYS[1], current)\n\
             return current",
        );
        let value = script
            .key(Self::gauge_key(key))
            .invoke_async::<u64>(&mut conn)
            .await
            .context("failed to decrement gauge in Redis")?;
        Ok(value)
    }

    async fn get_gauge(&self, key: &str) -> Result<u64> {
        let mut conn = self.get_conn().await?;
        let value = conn
            .get::<_, Option<u64>>(Self::gauge_key(key))
            .await
            .context("failed to get gauge from Redis")?
            .unwrap_or(0);
        Ok(value)
    }

    async fn is_banned(&self, user_id: &str) -> Result<bool> {
        let mut conn = self.get_conn().await?;
        let exists = conn
            .exists::<_, bool>(Self::ban_key(user_id))
            .await
            .context("failed to check ban in Redis")?;
        Ok(exists)
    }

    async fn ban_user(&self, user_id: &str, reason: &str, duration_secs: u64) -> Result<()> {
        let mut conn = self.get_conn().await?;
        let key = Self::ban_key(user_id);
        redis::cmd("SET")
            .arg(key)
            .arg(reason)
            .arg("EX")
            .arg(duration_secs)
            .query_async::<()>(&mut conn)
            .await
            .context("failed to write ban to Redis")?;
        Ok(())
    }

    async fn unban_user(&self, user_id: &str) -> Result<()> {
        let mut conn = self.get_conn().await?;
        conn.del::<_, ()>(Self::ban_key(user_id))
            .await
            .context("failed to remove ban from Redis")?;
        Ok(())
    }

    async fn log_abuse(&self, entry: &AbuseLogEntry) -> Result<()> {
        let mut conn = self.get_conn().await?;
        let serialized = serde_json::to_string(entry).context("failed to serialize abuse entry")?;
        redis::pipe()
            .atomic()
            .cmd("LPUSH")
            .arg(ABUSE_LOGS_KEY)
            .arg(serialized)
            .cmd("LTRIM")
            .arg(ABUSE_LOGS_KEY)
            .arg(0)
            .arg(MAX_ABUSE_LOGS_I64)
            .query_async::<()>(&mut conn)
            .await
            .context("failed to write abuse log to Redis")?;
        Ok(())
    }

    async fn get_abuse_logs(&self, limit: usize) -> Result<Vec<AbuseLogEntry>> {
        let mut conn = self.get_conn().await?;
        let end = if limit == 0 {
            -1
        } else {
            isize::try_from(limit.saturating_sub(1)).unwrap_or(isize::MAX)
        };
        let raw = conn
            .lrange::<_, Vec<String>>(ABUSE_LOGS_KEY, 0, end)
            .await
            .context("failed to fetch abuse logs from Redis")?;
        raw.into_iter()
            .enumerate()
            .map(|(idx, value)| {
                serde_json::from_str(&value)
                    .with_context(|| format!("failed to deserialize abuse log at index {idx}"))
            })
            .collect()
    }

    async fn append_request_log(&self, entry: &RequestLogEntry, max_entries: usize) -> Result<()> {
        let mut conn = self.get_conn().await?;
        let serialized =
            serde_json::to_string(entry).context("failed to serialize request log entry")?;
        let key = Self::request_log_key(&entry.tunnel_id);
        let trim_end = isize::try_from(max_entries.saturating_sub(1)).unwrap_or(isize::MAX);
        redis::pipe()
            .atomic()
            .cmd("LPUSH")
            .arg(&key)
            .arg(serialized)
            .cmd("LTRIM")
            .arg(&key)
            .arg(0)
            .arg(trim_end)
            .query_async::<()>(&mut conn)
            .await
            .context("failed to persist request log entry to Redis")?;
        Ok(())
    }

    async fn get_request_logs(
        &self,
        tunnel_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<RequestLogEntry>, usize)> {
        let mut conn = self.get_conn().await?;
        let key = Self::request_log_key(tunnel_id);

        if limit == 0 {
            let total = conn
                .llen::<_, usize>(&key)
                .await
                .context("failed to count request logs in Redis")?;
            return Ok((vec![], total));
        }

        let start = isize::try_from(offset).unwrap_or(isize::MAX);
        let end =
            isize::try_from(offset.saturating_add(limit).saturating_sub(1)).unwrap_or(isize::MAX);
        let (total, raw): (usize, Vec<String>) = redis::pipe()
            .cmd("LLEN")
            .arg(&key)
            .cmd("LRANGE")
            .arg(&key)
            .arg(start)
            .arg(end)
            .query_async(&mut conn)
            .await
            .context("failed to fetch request logs from Redis")?;

        let entries = raw
            .into_iter()
            .enumerate()
            .map(|(idx, value)| {
                serde_json::from_str(&value).with_context(|| {
                    format!("failed to deserialize request log entry at index {idx}")
                })
            })
            .collect::<Result<Vec<RequestLogEntry>>>()?;

        Ok((entries, total))
    }

    async fn remember_tunnel_owner(
        &self,
        tunnel_id: &str,
        owner_user_id: &str,
        created_at_unix_sec: u64,
        created_at_rfc3339: &str,
        last_activity_unix_ms: u64,
    ) -> Result<()> {
        let mut conn = self.get_conn().await?;
        let summary_key = Self::tunnel_metrics_summary_key(tunnel_id);
        redis::pipe()
            .atomic()
            .cmd("HSETNX")
            .arg(&summary_key)
            .arg(FIELD_CREATED_AT_UNIX_SEC)
            .arg(created_at_unix_sec)
            .cmd("HSETNX")
            .arg(&summary_key)
            .arg(FIELD_CREATED_AT_RFC3339)
            .arg(created_at_rfc3339)
            .cmd("HSETNX")
            .arg(&summary_key)
            .arg(FIELD_LAST_ACTIVITY_UNIX_MS)
            .arg(last_activity_unix_ms)
            .cmd("HSETNX")
            .arg(&summary_key)
            .arg(FIELD_OWNER_USER_ID)
            .arg(owner_user_id)
            .query_async::<()>(&mut conn)
            .await
            .context("failed to persist tunnel owner to Redis")?;
        Ok(())
    }

    async fn record_tunnel_metrics(
        &self,
        tunnel_id: &str,
        delta: &PersistedTunnelMetricsDelta,
    ) -> Result<()> {
        let mut conn = self.get_conn().await?;
        let summary_key = Self::tunnel_metrics_summary_key(tunnel_id);
        let counts_key = Self::tunnel_metrics_counts_key(tunnel_id);
        let latency_key = Self::tunnel_metrics_latency_key(tunnel_id);
        let minute_field = delta.minute_start_unix_sec.to_string();

        let mut pipe = redis::pipe();
        pipe.atomic()
            .cmd("HSETNX")
            .arg(&summary_key)
            .arg(FIELD_CREATED_AT_UNIX_SEC)
            .arg(delta.created_at_unix_sec)
            .cmd("HSETNX")
            .arg(&summary_key)
            .arg(FIELD_CREATED_AT_RFC3339)
            .arg(&delta.created_at_rfc3339)
            .cmd("HSET")
            .arg(&summary_key)
            .arg(FIELD_LAST_ACTIVITY_UNIX_MS)
            .arg(delta.last_activity_unix_ms)
            .cmd("HINCRBY")
            .arg(&summary_key)
            .arg(FIELD_TOTAL_REQUESTS)
            .arg(u64_to_i64_saturating(delta.total_requests_delta))
            .cmd("HINCRBY")
            .arg(&summary_key)
            .arg(FIELD_BYTES_IN)
            .arg(u64_to_i64_saturating(delta.bytes_in_delta))
            .cmd("HINCRBY")
            .arg(&summary_key)
            .arg(FIELD_BYTES_OUT)
            .arg(u64_to_i64_saturating(delta.bytes_out_delta))
            .cmd("HINCRBY")
            .arg(&summary_key)
            .arg(FIELD_STATUS_2XX)
            .arg(u64_to_i64_saturating(delta.status_2xx_delta))
            .cmd("HINCRBY")
            .arg(&summary_key)
            .arg(FIELD_STATUS_4XX)
            .arg(u64_to_i64_saturating(delta.status_4xx_delta))
            .cmd("HINCRBY")
            .arg(&summary_key)
            .arg(FIELD_STATUS_5XX)
            .arg(u64_to_i64_saturating(delta.status_5xx_delta))
            .cmd("HINCRBY")
            .arg(&summary_key)
            .arg(FIELD_TOTAL_LATENCY_MS)
            .arg(u64_to_i64_saturating(delta.total_latency_ms_delta))
            .cmd("HINCRBY")
            .arg(&counts_key)
            .arg(&minute_field)
            .arg(u64_to_i64_saturating(delta.minute_count_delta))
            .cmd("HINCRBY")
            .arg(&latency_key)
            .arg(&minute_field)
            .arg(u64_to_i64_saturating(delta.minute_total_latency_ms_delta));

        if !delta.pruned_minute_starts.is_empty() {
            let pruned_fields: Vec<String> = delta
                .pruned_minute_starts
                .iter()
                .map(ToString::to_string)
                .collect();
            pipe.cmd("HDEL").arg(&counts_key).arg(&pruned_fields);
            pipe.cmd("HDEL").arg(&latency_key).arg(&pruned_fields);
        }

        pipe.query_async::<()>(&mut conn)
            .await
            .context("failed to persist tunnel metrics delta to Redis")?;
        Ok(())
    }

    async fn get_tunnel_metrics(&self, tunnel_id: &str) -> Result<Option<PersistedTunnelMetrics>> {
        let mut conn = self.get_conn().await?;
        let summary_key = Self::tunnel_metrics_summary_key(tunnel_id);
        let counts_key = Self::tunnel_metrics_counts_key(tunnel_id);
        let latency_key = Self::tunnel_metrics_latency_key(tunnel_id);
        let (summary, counts, latencies): (
            HashMap<String, String>,
            HashMap<String, String>,
            HashMap<String, String>,
        ) = redis::pipe()
            .cmd("HGETALL")
            .arg(&summary_key)
            .cmd("HGETALL")
            .arg(&counts_key)
            .cmd("HGETALL")
            .arg(&latency_key)
            .query_async(&mut conn)
            .await
            .context("failed to load tunnel metrics from Redis")?;

        if summary.is_empty() && counts.is_empty() && latencies.is_empty() {
            return Ok(None);
        }

        let created_at_unix_sec = parse_map_u64(&summary, FIELD_CREATED_AT_UNIX_SEC).unwrap_or(0);
        let created_at_rfc3339 = summary
            .get(FIELD_CREATED_AT_RFC3339)
            .cloned()
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

        let mut minute_buckets = counts
            .into_iter()
            .filter_map(|(minute_start, count)| {
                let minute_start_unix_sec = minute_start.parse::<u64>().ok()?;
                let count = count.parse::<u64>().ok()?;
                let total_latency_ms = latencies
                    .get(&minute_start)
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0);
                Some(PersistedMinuteBucket {
                    minute_start_unix_sec,
                    count,
                    total_latency_ms,
                })
            })
            .collect::<Vec<_>>();
        minute_buckets.sort_by_key(|bucket| bucket.minute_start_unix_sec);
        if minute_buckets.len() > MAX_MINUTE_BUCKETS {
            let keep_from = minute_buckets.len() - MAX_MINUTE_BUCKETS;
            minute_buckets = minute_buckets.split_off(keep_from);
        }

        Ok(Some(PersistedTunnelMetrics {
            created_at_unix_sec,
            created_at_rfc3339,
            last_activity_unix_ms: parse_map_u64(&summary, FIELD_LAST_ACTIVITY_UNIX_MS)
                .unwrap_or(0),
            owner_user_id: summary
                .get(FIELD_OWNER_USER_ID)
                .cloned()
                .filter(|owner| !owner.is_empty()),
            total_requests: parse_map_u64(&summary, FIELD_TOTAL_REQUESTS).unwrap_or(0),
            bytes_in: parse_map_u64(&summary, FIELD_BYTES_IN).unwrap_or(0),
            bytes_out: parse_map_u64(&summary, FIELD_BYTES_OUT).unwrap_or(0),
            status_2xx: parse_map_u64(&summary, FIELD_STATUS_2XX).unwrap_or(0),
            status_4xx: parse_map_u64(&summary, FIELD_STATUS_4XX).unwrap_or(0),
            status_5xx: parse_map_u64(&summary, FIELD_STATUS_5XX).unwrap_or(0),
            total_latency_ms: parse_map_u64(&summary, FIELD_TOTAL_LATENCY_MS).unwrap_or(0),
            minute_buckets,
        }))
    }
}

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

fn persisted_metrics_seed(
    created_at_unix_sec: u64,
    created_at_rfc3339: &str,
    last_activity_unix_ms: u64,
) -> PersistedTunnelMetrics {
    PersistedTunnelMetrics {
        created_at_unix_sec,
        created_at_rfc3339: created_at_rfc3339.to_string(),
        last_activity_unix_ms,
        owner_user_id: None,
        total_requests: 0,
        bytes_in: 0,
        bytes_out: 0,
        status_2xx: 0,
        status_4xx: 0,
        status_5xx: 0,
        total_latency_ms: 0,
        minute_buckets: vec![],
    }
}

fn apply_metrics_delta(metrics: &mut PersistedTunnelMetrics, delta: &PersistedTunnelMetricsDelta) {
    metrics.last_activity_unix_ms = metrics
        .last_activity_unix_ms
        .max(delta.last_activity_unix_ms);
    metrics.total_requests = metrics
        .total_requests
        .saturating_add(delta.total_requests_delta);
    metrics.bytes_in = metrics.bytes_in.saturating_add(delta.bytes_in_delta);
    metrics.bytes_out = metrics.bytes_out.saturating_add(delta.bytes_out_delta);
    metrics.status_2xx = metrics.status_2xx.saturating_add(delta.status_2xx_delta);
    metrics.status_4xx = metrics.status_4xx.saturating_add(delta.status_4xx_delta);
    metrics.status_5xx = metrics.status_5xx.saturating_add(delta.status_5xx_delta);
    metrics.total_latency_ms = metrics
        .total_latency_ms
        .saturating_add(delta.total_latency_ms_delta);

    if let Some(last) = metrics.minute_buckets.last_mut() {
        if last.minute_start_unix_sec == delta.minute_start_unix_sec {
            last.count = last.count.saturating_add(delta.minute_count_delta);
            last.total_latency_ms = last
                .total_latency_ms
                .saturating_add(delta.minute_total_latency_ms_delta);
        } else {
            metrics.minute_buckets.push(PersistedMinuteBucket {
                minute_start_unix_sec: delta.minute_start_unix_sec,
                count: delta.minute_count_delta,
                total_latency_ms: delta.minute_total_latency_ms_delta,
            });
        }
    } else {
        metrics.minute_buckets.push(PersistedMinuteBucket {
            minute_start_unix_sec: delta.minute_start_unix_sec,
            count: delta.minute_count_delta,
            total_latency_ms: delta.minute_total_latency_ms_delta,
        });
    }

    if !delta.pruned_minute_starts.is_empty() {
        let pruned: HashSet<u64> = delta.pruned_minute_starts.iter().copied().collect();
        metrics
            .minute_buckets
            .retain(|bucket| !pruned.contains(&bucket.minute_start_unix_sec));
    }

    metrics
        .minute_buckets
        .sort_by_key(|bucket| bucket.minute_start_unix_sec);
    if metrics.minute_buckets.len() > MAX_MINUTE_BUCKETS {
        let keep_from = metrics.minute_buckets.len() - MAX_MINUTE_BUCKETS;
        metrics.minute_buckets.drain(0..keep_from);
    }
}

fn parse_map_u64(map: &HashMap<String, String>, key: &str) -> Option<u64> {
    map.get(key).and_then(|value| value.parse::<u64>().ok())
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
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
    }
}
