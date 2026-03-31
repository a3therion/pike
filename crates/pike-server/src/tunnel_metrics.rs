use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::warn;

use crate::state_store::StateStore;

pub(crate) const MAX_MINUTE_BUCKETS: usize = 7 * 24 * 60 + 10;

fn unix_sec_to_i64(sec: u64) -> i64 {
    i64::try_from(sec).unwrap_or(i64::MAX)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricsRange {
    OneHour,
    TwentyFourHours,
    SevenDays,
}

impl MetricsRange {
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "1h" => Some(Self::OneHour),
            "24h" => Some(Self::TwentyFourHours),
            "7d" => Some(Self::SevenDays),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OneHour => "1h",
            Self::TwentyFourHours => "24h",
            Self::SevenDays => "7d",
        }
    }

    #[must_use]
    pub fn range_seconds(self) -> u64 {
        match self {
            Self::OneHour => 60 * 60,
            Self::TwentyFourHours => 24 * 60 * 60,
            Self::SevenDays => 7 * 24 * 60 * 60,
        }
    }

    #[must_use]
    pub fn bucket_size_seconds(self) -> u64 {
        match self {
            Self::OneHour => 60,
            Self::TwentyFourHours => 60 * 60,
            Self::SevenDays => 60 * 60,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TunnelMetricsResponse {
    pub total_requests: u64,
    pub requests_per_minute: f64,
    pub status_breakdown: StatusBreakdown,
    pub avg_latency_ms: f64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatusBreakdown {
    #[serde(rename = "2xx")]
    pub two_xx: u64,
    #[serde(rename = "4xx")]
    pub four_xx: u64,
    #[serde(rename = "5xx")]
    pub five_xx: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TunnelMetricsTimeseriesResponse {
    pub range: String,
    pub bucket_size_seconds: u64,
    pub data: Vec<TimeseriesPoint>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TimeseriesPoint {
    pub timestamp: String,
    pub count: u64,
    pub avg_latency_ms: f64,
}

#[derive(Debug, Clone)]
pub struct TunnelMetricsSnapshot {
    pub created_at_unix_sec: u64,
    pub created_at_rfc3339: String,
    pub last_activity_unix_ms: u64,
    pub last_activity_rfc3339: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedMinuteBucket {
    pub minute_start_unix_sec: u64,
    pub count: u64,
    pub total_latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PersistedTunnelMetrics {
    pub created_at_unix_sec: u64,
    pub created_at_rfc3339: String,
    pub last_activity_unix_ms: u64,
    pub owner_user_id: Option<String>,
    pub total_requests: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub status_2xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub total_latency_ms: u64,
    pub minute_buckets: Vec<PersistedMinuteBucket>,
}

#[derive(Debug, Clone)]
pub struct PersistedTunnelMetricsDelta {
    pub created_at_unix_sec: u64,
    pub created_at_rfc3339: String,
    pub last_activity_unix_ms: u64,
    pub total_requests_delta: u64,
    pub bytes_in_delta: u64,
    pub bytes_out_delta: u64,
    pub status_2xx_delta: u64,
    pub status_4xx_delta: u64,
    pub status_5xx_delta: u64,
    pub total_latency_ms_delta: u64,
    pub minute_start_unix_sec: u64,
    pub minute_count_delta: u64,
    pub minute_total_latency_ms_delta: u64,
    pub pruned_minute_starts: Vec<u64>,
}

pub struct TunnelMetricsStore {
    tunnels: RwLock<HashMap<String, Arc<TunnelMetrics>>>,
    state_store: Option<Arc<dyn StateStore>>,
}

impl Default for TunnelMetricsStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TunnelMetricsStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tunnels: RwLock::new(HashMap::new()),
            state_store: None,
        }
    }

    #[must_use]
    pub fn with_state_store(state_store: Option<Arc<dyn StateStore>>) -> Self {
        Self {
            tunnels: RwLock::new(HashMap::new()),
            state_store,
        }
    }

    pub async fn record(
        &self,
        tunnel_id: &str,
        status_code: u16,
        latency_ms: u64,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        let now = Utc::now();
        let now_unix_ms = now.timestamp_millis().max(0) as u64;
        let now_unix_sec = now.timestamp().max(0) as u64;

        let metrics = self
            .get_or_create(tunnel_id, now_unix_ms, now_unix_sec)
            .await;
        let delta = metrics
            .record(
                status_code,
                latency_ms,
                bytes_in,
                bytes_out,
                now_unix_ms,
                now_unix_sec,
            )
            .await;

        if let Some(state_store) = self.state_store.as_ref() {
            if let Err(err) = state_store.record_tunnel_metrics(tunnel_id, &delta).await {
                warn!(tunnel_id, error = %err, "failed to persist tunnel metrics delta");
            }
        }
    }

    pub async fn remember_tunnel(&self, tunnel_id: &str, owner_user_id: &str) {
        let now = Utc::now();
        let now_unix_ms = now.timestamp_millis().max(0) as u64;
        let now_unix_sec = now.timestamp().max(0) as u64;

        let metrics = self
            .get_or_create(tunnel_id, now_unix_ms, now_unix_sec)
            .await;
        let changed = metrics.remember_owner(owner_user_id).await;

        if changed {
            if let Some(state_store) = self.state_store.as_ref() {
                if let Err(err) = state_store
                    .remember_tunnel_owner(
                        tunnel_id,
                        owner_user_id,
                        metrics.created_at_unix_sec(),
                        metrics.created_at_rfc3339(),
                        metrics.last_activity_unix_ms(),
                    )
                    .await
                {
                    warn!(tunnel_id, error = %err, "failed to persist tunnel owner");
                }
            }
        }
    }

    pub async fn owner_user_id(&self, tunnel_id: &str) -> Option<String> {
        let metrics = self.get_or_load(tunnel_id).await?;
        metrics.owner_user_id().await
    }

    pub async fn metrics_response(
        &self,
        tunnel_id: &str,
        uptime_seconds: u64,
    ) -> TunnelMetricsResponse {
        let Some(metrics) = self.get_or_load(tunnel_id).await else {
            return TunnelMetricsResponse {
                total_requests: 0,
                requests_per_minute: 0.0,
                status_breakdown: StatusBreakdown {
                    two_xx: 0,
                    four_xx: 0,
                    five_xx: 0,
                },
                avg_latency_ms: 0.0,
                bytes_in: 0,
                bytes_out: 0,
                uptime_seconds,
            };
        };

        let total_requests = metrics.total_requests.load(Ordering::Relaxed);
        let total_latency_ms = metrics.total_latency_ms.load(Ordering::Relaxed);
        let avg_latency_ms = if total_requests == 0 {
            0.0
        } else {
            total_latency_ms as f64 / total_requests as f64
        };

        let requests_per_minute = metrics.requests_per_minute().await;

        TunnelMetricsResponse {
            total_requests,
            requests_per_minute,
            status_breakdown: StatusBreakdown {
                two_xx: metrics.status_2xx.load(Ordering::Relaxed),
                four_xx: metrics.status_4xx.load(Ordering::Relaxed),
                five_xx: metrics.status_5xx.load(Ordering::Relaxed),
            },
            avg_latency_ms,
            bytes_in: metrics.bytes_in.load(Ordering::Relaxed),
            bytes_out: metrics.bytes_out.load(Ordering::Relaxed),
            uptime_seconds,
        }
    }

    pub async fn timeseries_response(
        &self,
        tunnel_id: &str,
        range: MetricsRange,
    ) -> TunnelMetricsTimeseriesResponse {
        let Some(metrics) = self.get_or_load(tunnel_id).await else {
            return TunnelMetricsTimeseriesResponse {
                range: range.as_str().to_string(),
                bucket_size_seconds: range.bucket_size_seconds(),
                data: vec![],
            };
        };

        metrics.timeseries(range).await
    }

    pub async fn snapshot_times(&self, tunnel_id: &str) -> Option<TunnelMetricsSnapshot> {
        let metrics = self.get_or_load(tunnel_id).await?;

        let created_at_rfc3339 = metrics.created_at_rfc3339().to_string();
        let created_at_unix_sec = metrics.created_at_unix_sec();
        let last_activity_unix_ms = metrics.last_activity_unix_ms();
        let last_activity_rfc3339 = if last_activity_unix_ms == 0 {
            None
        } else {
            let secs = unix_sec_to_i64(last_activity_unix_ms / 1000);
            Some(Utc.timestamp_opt(secs, 0).single()?.to_rfc3339())
        };

        Some(TunnelMetricsSnapshot {
            created_at_unix_sec,
            created_at_rfc3339,
            last_activity_unix_ms,
            last_activity_rfc3339,
        })
    }

    async fn get_or_load(&self, tunnel_id: &str) -> Option<Arc<TunnelMetrics>> {
        {
            let tunnels = self.tunnels.read().await;
            if let Some(existing) = tunnels.get(tunnel_id) {
                return Some(existing.clone());
            }
        }

        let loaded = self.load_from_state_store(tunnel_id).await?;
        let mut tunnels = self.tunnels.write().await;
        let metrics = tunnels
            .entry(tunnel_id.to_string())
            .or_insert_with(|| loaded.clone())
            .clone();
        Some(metrics)
    }

    async fn get_or_create(
        &self,
        tunnel_id: &str,
        now_unix_ms: u64,
        now_unix_sec: u64,
    ) -> Arc<TunnelMetrics> {
        if let Some(existing) = self.get_or_load(tunnel_id).await {
            return existing;
        }

        let mut tunnels = self.tunnels.write().await;
        tunnels
            .entry(tunnel_id.to_string())
            .or_insert_with(|| Arc::new(TunnelMetrics::new(now_unix_ms, now_unix_sec)))
            .clone()
    }

    async fn load_from_state_store(&self, tunnel_id: &str) -> Option<Arc<TunnelMetrics>> {
        let state_store = self.state_store.as_ref()?;
        match state_store.get_tunnel_metrics(tunnel_id).await {
            Ok(Some(snapshot)) => Some(Arc::new(TunnelMetrics::from_persisted(snapshot))),
            Ok(None) => None,
            Err(err) => {
                warn!(tunnel_id, error = %err, "failed to load persisted tunnel metrics");
                None
            }
        }
    }
}

#[derive(Debug)]
struct TunnelMetrics {
    created_at_unix_sec: u64,
    created_at_rfc3339: String,
    last_activity_unix_ms: AtomicU64,
    owner_user_id: RwLock<Option<String>>,

    total_requests: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    status_2xx: AtomicU64,
    status_4xx: AtomicU64,
    status_5xx: AtomicU64,
    total_latency_ms: AtomicU64,

    timeseries: Mutex<MinuteTimeseries>,
}

impl TunnelMetrics {
    fn new(now_unix_ms: u64, now_unix_sec: u64) -> Self {
        let created_at_rfc3339 = Utc
            .timestamp_opt(unix_sec_to_i64(now_unix_sec), 0)
            .single()
            .unwrap_or_else(Utc::now)
            .to_rfc3339();

        Self {
            created_at_unix_sec: now_unix_sec,
            created_at_rfc3339,
            last_activity_unix_ms: AtomicU64::new(now_unix_ms),
            owner_user_id: RwLock::new(None),
            total_requests: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            status_2xx: AtomicU64::new(0),
            status_4xx: AtomicU64::new(0),
            status_5xx: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            timeseries: Mutex::new(MinuteTimeseries::new()),
        }
    }

    fn from_persisted(snapshot: PersistedTunnelMetrics) -> Self {
        Self {
            created_at_unix_sec: snapshot.created_at_unix_sec,
            created_at_rfc3339: snapshot.created_at_rfc3339,
            last_activity_unix_ms: AtomicU64::new(snapshot.last_activity_unix_ms),
            owner_user_id: RwLock::new(snapshot.owner_user_id),
            total_requests: AtomicU64::new(snapshot.total_requests),
            bytes_in: AtomicU64::new(snapshot.bytes_in),
            bytes_out: AtomicU64::new(snapshot.bytes_out),
            status_2xx: AtomicU64::new(snapshot.status_2xx),
            status_4xx: AtomicU64::new(snapshot.status_4xx),
            status_5xx: AtomicU64::new(snapshot.status_5xx),
            total_latency_ms: AtomicU64::new(snapshot.total_latency_ms),
            timeseries: Mutex::new(MinuteTimeseries::from_persisted(snapshot.minute_buckets)),
        }
    }

    fn created_at_unix_sec(&self) -> u64 {
        self.created_at_unix_sec
    }

    fn created_at_rfc3339(&self) -> &str {
        &self.created_at_rfc3339
    }

    fn last_activity_unix_ms(&self) -> u64 {
        self.last_activity_unix_ms.load(Ordering::Relaxed)
    }

    async fn remember_owner(&self, owner_user_id: &str) -> bool {
        let mut slot = self.owner_user_id.write().await;
        if slot.is_none() {
            *slot = Some(owner_user_id.to_string());
            true
        } else {
            false
        }
    }

    async fn owner_user_id(&self) -> Option<String> {
        self.owner_user_id.read().await.clone()
    }

    async fn record(
        &self,
        status_code: u16,
        latency_ms: u64,
        bytes_in: u64,
        bytes_out: u64,
        now_unix_ms: u64,
        now_unix_sec: u64,
    ) -> PersistedTunnelMetricsDelta {
        self.last_activity_unix_ms
            .store(now_unix_ms, Ordering::Relaxed);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);

        let (status_2xx_delta, status_4xx_delta, status_5xx_delta) = match status_code / 100 {
            2 => {
                self.status_2xx.fetch_add(1, Ordering::Relaxed);
                (1, 0, 0)
            }
            4 => {
                self.status_4xx.fetch_add(1, Ordering::Relaxed);
                (0, 1, 0)
            }
            5 => {
                self.status_5xx.fetch_add(1, Ordering::Relaxed);
                (0, 0, 1)
            }
            _ => (0, 0, 0),
        };

        let mut ts = self.timeseries.lock().await;
        let timeseries_delta = ts.record(now_unix_sec, latency_ms);

        PersistedTunnelMetricsDelta {
            created_at_unix_sec: self.created_at_unix_sec,
            created_at_rfc3339: self.created_at_rfc3339.clone(),
            last_activity_unix_ms: now_unix_ms,
            total_requests_delta: 1,
            bytes_in_delta: bytes_in,
            bytes_out_delta: bytes_out,
            status_2xx_delta,
            status_4xx_delta,
            status_5xx_delta,
            total_latency_ms_delta: latency_ms,
            minute_start_unix_sec: timeseries_delta.minute_start_unix_sec,
            minute_count_delta: timeseries_delta.count_delta,
            minute_total_latency_ms_delta: timeseries_delta.total_latency_ms_delta,
            pruned_minute_starts: timeseries_delta.pruned_minute_starts,
        }
    }

    async fn requests_per_minute(&self) -> f64 {
        let now_unix_sec = Utc::now().timestamp().max(0) as u64;
        let cutoff = now_unix_sec.saturating_sub(5 * 60);

        let ts = self.timeseries.lock().await;

        let mut total_count: u64 = 0;
        let mut first_bucket: Option<u64> = None;

        for b in ts
            .buckets
            .iter()
            .filter(|b| b.minute_start_unix_sec >= cutoff)
        {
            total_count = total_count.saturating_add(b.count);
            if first_bucket.is_none() {
                first_bucket = Some(b.minute_start_unix_sec);
            }
        }

        let minutes = if let Some(first) = first_bucket {
            let span_seconds = now_unix_sec.saturating_sub(first);
            let span_minutes = (span_seconds / 60).saturating_add(1);
            span_minutes.clamp(1, 5) as f64
        } else {
            1.0
        };

        total_count as f64 / minutes
    }

    async fn timeseries(&self, range: MetricsRange) -> TunnelMetricsTimeseriesResponse {
        let now_unix_sec = Utc::now().timestamp().max(0) as u64;
        let cutoff = now_unix_sec.saturating_sub(range.range_seconds());
        let bucket_size_seconds = range.bucket_size_seconds();

        let ts = self.timeseries.lock().await;
        let raw: Vec<MinuteBucket> = ts
            .buckets
            .iter()
            .filter(|b| b.minute_start_unix_sec >= cutoff)
            .cloned()
            .collect();

        let data = if bucket_size_seconds == 60 {
            raw.into_iter()
                .map(|b| TimeseriesPoint {
                    timestamp: Utc
                        .timestamp_opt(unix_sec_to_i64(b.minute_start_unix_sec), 0)
                        .single()
                        .unwrap_or_else(Utc::now)
                        .to_rfc3339(),
                    count: b.count,
                    avg_latency_ms: if b.count == 0 {
                        0.0
                    } else {
                        b.total_latency_ms as f64 / b.count as f64
                    },
                })
                .collect()
        } else {
            let mut agg: BTreeMap<u64, (u64, u64)> = BTreeMap::new();
            for b in raw {
                let bucket_start =
                    (b.minute_start_unix_sec / bucket_size_seconds) * bucket_size_seconds;
                let entry = agg.entry(bucket_start).or_insert((0, 0));
                entry.0 = entry.0.saturating_add(b.count);
                entry.1 = entry.1.saturating_add(b.total_latency_ms);
            }

            agg.into_iter()
                .map(
                    |(bucket_start, (count, total_latency_ms))| TimeseriesPoint {
                        timestamp: Utc
                            .timestamp_opt(unix_sec_to_i64(bucket_start), 0)
                            .single()
                            .unwrap_or_else(Utc::now)
                            .to_rfc3339(),
                        count,
                        avg_latency_ms: if count == 0 {
                            0.0
                        } else {
                            total_latency_ms as f64 / count as f64
                        },
                    },
                )
                .collect()
        };

        TunnelMetricsTimeseriesResponse {
            range: range.as_str().to_string(),
            bucket_size_seconds,
            data,
        }
    }
}

#[derive(Debug, Clone)]
struct MinuteBucket {
    minute_start_unix_sec: u64,
    count: u64,
    total_latency_ms: u64,
}

#[derive(Debug, Clone)]
struct MinuteTimeseriesDelta {
    minute_start_unix_sec: u64,
    count_delta: u64,
    total_latency_ms_delta: u64,
    pruned_minute_starts: Vec<u64>,
}

#[derive(Debug)]
struct MinuteTimeseries {
    buckets: VecDeque<MinuteBucket>,
}

impl MinuteTimeseries {
    fn new() -> Self {
        Self {
            buckets: VecDeque::new(),
        }
    }

    fn from_persisted(mut buckets: Vec<PersistedMinuteBucket>) -> Self {
        buckets.sort_by_key(|bucket| bucket.minute_start_unix_sec);
        if buckets.len() > MAX_MINUTE_BUCKETS {
            let keep_from = buckets.len() - MAX_MINUTE_BUCKETS;
            buckets = buckets.split_off(keep_from);
        }

        Self {
            buckets: buckets
                .into_iter()
                .map(|bucket| MinuteBucket {
                    minute_start_unix_sec: bucket.minute_start_unix_sec,
                    count: bucket.count,
                    total_latency_ms: bucket.total_latency_ms,
                })
                .collect(),
        }
    }

    fn record(&mut self, now_unix_sec: u64, latency_ms: u64) -> MinuteTimeseriesDelta {
        let minute_start = (now_unix_sec / 60) * 60;

        match self.buckets.back_mut() {
            Some(last) if last.minute_start_unix_sec == minute_start => {
                last.count = last.count.saturating_add(1);
                last.total_latency_ms = last.total_latency_ms.saturating_add(latency_ms);
            }
            _ => {
                if let Some(last) = self.buckets.back() {
                    let mut next = last.minute_start_unix_sec.saturating_add(60);
                    while next < minute_start {
                        self.buckets.push_back(MinuteBucket {
                            minute_start_unix_sec: next,
                            count: 0,
                            total_latency_ms: 0,
                        });
                        next = next.saturating_add(60);
                    }
                }

                self.buckets.push_back(MinuteBucket {
                    minute_start_unix_sec: minute_start,
                    count: 1,
                    total_latency_ms: latency_ms,
                });
            }
        }

        let mut pruned_minute_starts = Vec::new();
        while self.buckets.len() > MAX_MINUTE_BUCKETS {
            if let Some(pruned_bucket) = self.buckets.pop_front() {
                pruned_minute_starts.push(pruned_bucket.minute_start_unix_sec);
            }
        }

        MinuteTimeseriesDelta {
            minute_start_unix_sec: minute_start,
            count_delta: 1,
            total_latency_ms_delta: latency_ms,
            pruned_minute_starts,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::state_store::{InMemoryStateStore, StateStore};

    use super::{MetricsRange, TunnelMetricsStore};

    #[tokio::test]
    async fn metrics_survive_store_restart() {
        let shared_store = Arc::new(InMemoryStateStore::new()) as Arc<dyn StateStore>;
        let store = TunnelMetricsStore::with_state_store(Some(shared_store.clone()));

        store.remember_tunnel("tunnel-1", "user-1").await;
        store.record("tunnel-1", 200, 50, 10, 20).await;
        store.record("tunnel-1", 500, 150, 5, 8).await;

        let first_snapshot = store
            .snapshot_times("tunnel-1")
            .await
            .expect("snapshot should exist");

        let restarted = TunnelMetricsStore::with_state_store(Some(shared_store));
        let response = restarted.metrics_response("tunnel-1", 42).await;

        assert_eq!(
            restarted.owner_user_id("tunnel-1").await.as_deref(),
            Some("user-1")
        );
        assert_eq!(response.total_requests, 2);
        assert_eq!(response.status_breakdown.two_xx, 1);
        assert_eq!(response.status_breakdown.five_xx, 1);
        assert_eq!(response.bytes_in, 15);
        assert_eq!(response.bytes_out, 28);
        assert_eq!(response.avg_latency_ms, 100.0);
        assert_eq!(response.uptime_seconds, 42);

        let restored_snapshot = restarted
            .snapshot_times("tunnel-1")
            .await
            .expect("snapshot should load from state store");
        assert_eq!(
            restored_snapshot.created_at_unix_sec,
            first_snapshot.created_at_unix_sec
        );
        assert_eq!(
            restored_snapshot.created_at_rfc3339,
            first_snapshot.created_at_rfc3339
        );
        assert!(restored_snapshot.last_activity_unix_ms >= first_snapshot.last_activity_unix_ms);

        let timeseries = restarted
            .timeseries_response("tunnel-1", MetricsRange::OneHour)
            .await;
        let total_count: u64 = timeseries.data.iter().map(|point| point.count).sum();
        assert_eq!(total_count, 2);
    }
}
