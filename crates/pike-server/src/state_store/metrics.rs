//! Deterministic metric snapshot accumulation for the memory store.
use crate::tunnel_metrics::{
    PersistedMinuteBucket, PersistedTunnelMetrics, PersistedTunnelMetricsDelta, MAX_MINUTE_BUCKETS,
};
use std::collections::HashSet;
pub(super) fn persisted_metrics_seed(
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

pub(super) fn apply_metrics_delta(
    metrics: &mut PersistedTunnelMetrics,
    delta: &PersistedTunnelMetricsDelta,
) {
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
