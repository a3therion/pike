//! Redis persistence; key layout and Lua atomic operations live here.
use super::StateStore;
use crate::tunnel_metrics::{PersistedMinuteBucket, MAX_MINUTE_BUCKETS};
use crate::{
    abuse::AbuseLogEntry,
    request_log::RequestLogEntry,
    tunnel_metrics::{PersistedTunnelMetrics, PersistedTunnelMetricsDelta},
};
use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;
use deadpool_redis::{
    redis::{self, AsyncCommands},
    Config as RedisConfig, Pool, Runtime,
};
use std::collections::HashMap;
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

    fn suspend_key(tunnel_id: &str) -> String {
        format!("tunnel:suspended:{tunnel_id}")
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

    async fn is_tunnel_suspended(&self, tunnel_id: &str) -> Result<bool> {
        let mut conn = self.get_conn().await?;
        let exists = conn
            .exists::<_, bool>(Self::suspend_key(tunnel_id))
            .await
            .context("failed to check tunnel suspension in Redis")?;
        Ok(exists)
    }

    async fn suspend_tunnel(
        &self,
        tunnel_id: &str,
        reason: &str,
        duration_secs: u64,
    ) -> Result<()> {
        let mut conn = self.get_conn().await?;
        let mut command = redis::cmd("SET");
        command.arg(Self::suspend_key(tunnel_id)).arg(reason);
        if duration_secs > 0 {
            command.arg("EX").arg(duration_secs);
        }
        command
            .query_async::<()>(&mut conn)
            .await
            .context("failed to write tunnel suspension to Redis")?;
        Ok(())
    }

    async fn unsuspend_tunnel(&self, tunnel_id: &str) -> Result<()> {
        let mut conn = self.get_conn().await?;
        conn.del::<_, ()>(Self::suspend_key(tunnel_id))
            .await
            .context("failed to remove tunnel suspension from Redis")?;
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

fn parse_map_u64(map: &HashMap<String, String>, key: &str) -> Option<u64> {
    map.get(key).and_then(|value| value.parse::<u64>().ok())
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}
