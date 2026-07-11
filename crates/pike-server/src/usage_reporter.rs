use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::registry::ClientRegistry;
use crate::tunnel_metrics::TunnelMetricsStore;

const FLUSH_INTERVAL_SECS: u64 = 300;

#[derive(Debug, Clone, Copy, Default)]
struct ShadowCounter {
    bytes_in: u64,
    bytes_out: u64,
    request_count: u64,
}

#[derive(Debug, Clone, Serialize)]
struct UsageReport {
    tunnel_id: String,
    user_id: String,
    bytes_in: u64,
    bytes_out: u64,
    request_count: u64,
    timestamp: u64,
}

#[derive(Debug, Clone)]
struct PendingReport {
    report: UsageReport,
    current: ShadowCounter,
}

pub struct UsageReporter {
    shadow_counters: Mutex<HashMap<String, ShadowCounter>>,
    workers_api_url: String,
    server_token: String,
    tunnel_metrics_store: Arc<TunnelMetricsStore>,
    registry: Arc<ClientRegistry>,
    http_client: reqwest::Client,
}

impl UsageReporter {
    #[must_use]
    pub fn new(
        workers_api_url: String,
        server_token: String,
        tunnel_metrics_store: Arc<TunnelMetricsStore>,
        registry: Arc<ClientRegistry>,
    ) -> Self {
        Self {
            shadow_counters: Mutex::new(HashMap::new()),
            workers_api_url,
            server_token,
            tunnel_metrics_store,
            registry,
            http_client: reqwest::Client::new(),
        }
    }

    pub fn spawn_flush_loop(self: &Arc<Self>, mut shutdown_rx: tokio::sync::watch::Receiver<bool>) {
        let this = self.clone();
        tokio::spawn(async move {
            info!("usage reporter started");
            let mut interval = tokio::time::interval(Duration::from_secs(FLUSH_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        this.flush().await;
                    }
                    changed = shutdown_rx.changed() => {
                        if changed.is_ok() && *shutdown_rx.borrow() {
                            this.flush().await;
                            break;
                        }
                    }
                }
            }
            info!("usage reporter stopped");
        });
    }

    #[cfg(test)]
    pub async fn flush_for_test(&self) {
        self.flush().await;
    }

    async fn flush(&self) {
        let tunnel_users = self.collect_tunnel_users();
        if tunnel_users.is_empty() {
            return;
        }

        let previous = { self.shadow_counters.lock().await.clone() };
        let timestamp = chrono::Utc::now().timestamp().max(0) as u64;
        let mut pending_reports = Vec::new();

        for (tunnel_id, user_id) in tunnel_users {
            let Some(user_id) = user_id else {
                warn!(tunnel_id = %tunnel_id, "missing validated user_id for tunnel; skipping usage report");
                continue;
            };

            let metrics = self
                .tunnel_metrics_store
                .metrics_response(&tunnel_id, 0, self.registry.active_tunnels() as u64)
                .await;
            let current = ShadowCounter {
                bytes_in: metrics.bytes_in,
                bytes_out: metrics.bytes_out,
                request_count: metrics.total_requests,
            };
            let last_reported = previous.get(&tunnel_id).copied().unwrap_or_default();

            let delta_bytes_in = current.bytes_in.saturating_sub(last_reported.bytes_in);
            let delta_bytes_out = current.bytes_out.saturating_sub(last_reported.bytes_out);
            let delta_request_count = current
                .request_count
                .saturating_sub(last_reported.request_count);
            if delta_bytes_in == 0 && delta_bytes_out == 0 && delta_request_count == 0 {
                continue;
            }

            pending_reports.push(PendingReport {
                report: UsageReport {
                    tunnel_id,
                    user_id,
                    bytes_in: delta_bytes_in,
                    bytes_out: delta_bytes_out,
                    request_count: delta_request_count,
                    timestamp,
                },
                current,
            });
        }

        if pending_reports.is_empty() {
            return;
        }

        let payload: Vec<UsageReport> = pending_reports
            .iter()
            .map(|pending| pending.report.clone())
            .collect();

        // Idempotency key keyed on each tunnel's cumulative ("to") counter, which
        // uniquely positions this window on the counter timeline. A retried batch (send
        // failed → `shadow_counters` not advanced → same deltas AND same cumulative on
        // the next flush) hashes identically and is deduped by Workers; two distinct
        // windows that happen to carry identical deltas have different cumulative
        // counters, so they hash differently and are NOT wrongly dropped.
        let id_entries: Vec<ReportIdEntry> = pending_reports
            .iter()
            .map(|pending| ReportIdEntry {
                tunnel_id: pending.report.tunnel_id.clone(),
                user_id: pending.report.user_id.clone(),
                cumulative: pending.current,
            })
            .collect();
        let report_id = batch_report_id(&id_entries);

        if let Err(error) = self.send_batch(&payload, &report_id).await {
            error!(error = %error, count = payload.len(), "failed to report usage batch to Workers API");
            return;
        }

        let mut shadow_counters = self.shadow_counters.lock().await;
        for pending in pending_reports {
            shadow_counters.insert(pending.report.tunnel_id, pending.current);
        }
    }

    /// Collect tunnel IDs and their associated user IDs.
    ///
    /// **TOCTOU Gap:** This method iterates `self.registry.tunnels` (DashMap) and then
    /// separately reads `self.registry.clients` for each tunnel's connection ID. These are
    /// two independent map reads with no unified snapshot. If a client disconnects between
    /// the tunnel iteration and the client lookup, the tunnel's `user_id` will be `None`
    /// and the tunnel will be skipped in the usage report. This results in under-counted
    /// usage for that interval, but is acceptable for non-billing metrics.
    fn collect_tunnel_users(&self) -> Vec<(String, Option<String>)> {
        let mut seen = HashSet::new();
        let mut tunnel_users = Vec::new();

        for tunnel in &self.registry.tunnels {
            let tunnel_entry = tunnel.value();
            let tunnel_id = tunnel_entry.tunnel_id.to_string();
            if !seen.insert(tunnel_id.clone()) {
                continue;
            }

            let user_id = self
                .registry
                .clients
                .get(&tunnel_entry.connection_id)
                .and_then(|client| {
                    client
                        .info
                        .validated_user
                        .as_ref()
                        .map(|validated| validated.user_id.clone())
                });

            tunnel_users.push((tunnel_id, user_id));
        }

        tunnel_users
    }

    async fn send_batch(&self, reports: &[UsageReport], report_id: &str) -> anyhow::Result<()> {
        #[derive(Serialize)]
        struct UsagePayload<'a> {
            // Fix #19: a unique id per batch so the Workers `/internal/report` endpoint
            // can dedupe a retried batch (e.g. after a dropped ack) instead of
            // double-counting. `shadow_counters` still only advance on a 2xx, so a
            // duplicate carrying the same id is harmless.
            report_id: &'a str,
            reports: &'a [UsageReport],
        }

        let url = format!(
            "{}/api/v1/usage/internal/report",
            self.workers_api_url.trim_end_matches('/')
        );

        let response = self
            .http_client
            .post(url)
            .bearer_auth(&self.server_token)
            .json(&UsagePayload { report_id, reports })
            .timeout(Duration::from_secs(10))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("usage report API returned {status}: {body}");
        }

        Ok(())
    }
}

/// One tunnel's contribution to a batch's idempotency key: its identity plus the
/// cumulative ("to") counter the batch is advancing it to.
struct ReportIdEntry {
    tunnel_id: String,
    user_id: String,
    cumulative: ShadowCounter,
}

/// Derive a stable idempotency key for a batch (fix #19).
///
/// The key is keyed on each tunnel's *cumulative* counter (the "to" position), not on the
/// per-window delta. This gives two properties the Workers-side 1h dedup relies on:
///
/// * **Stable across retries.** `flush` only advances `shadow_counters` on a 2xx, so a
///   batch whose ack was lost is recomputed on the next flush from the same baseline; if
///   no traffic occurred in between it has the same deltas *and* the same cumulative
///   counter, hashing identically so Workers dedupes it. (A random uuid per send would
///   defeat dedup.)
/// * **Unique across windows.** Two genuinely different windows that happen to carry the
///   same byte/request delta still sit at different cumulative positions on the counter
///   timeline, so they hash differently and the second is NOT wrongly dropped as a
///   duplicate. (A delta-only or timestamp-less key collided here — the original bug.)
fn batch_report_id(entries: &[ReportIdEntry]) -> String {
    let mut lines: Vec<String> = entries
        .iter()
        .map(|e| {
            format!(
                "{}:{}:{}:{}:{}",
                e.tunnel_id,
                e.user_id,
                e.cumulative.bytes_in,
                e.cumulative.bytes_out,
                e.cumulative.request_count
            )
        })
        .collect();
    lines.sort();

    let mut hasher = Sha256::new();
    for line in lines {
        hasher.update(line.as_bytes());
        hasher.update(b"\n");
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::{batch_report_id, ReportIdEntry, ShadowCounter};

    fn entry(tunnel: &str, bytes_in: u64, bytes_out: u64, requests: u64) -> ReportIdEntry {
        ReportIdEntry {
            tunnel_id: tunnel.to_string(),
            user_id: "u1".to_string(),
            cumulative: ShadowCounter {
                bytes_in,
                bytes_out,
                request_count: requests,
            },
        }
    }

    #[test]
    fn report_id_is_stable_for_a_retried_batch() {
        // A retry recomputes from an un-advanced baseline with no intervening traffic:
        // same cumulative counter → same id → Workers dedupes it (no double-count).
        let batch = [entry("t1", 1000, 2000, 5)];
        assert_eq!(batch_report_id(&batch), batch_report_id(&batch));
    }

    #[test]
    fn report_id_differs_for_same_delta_in_different_windows() {
        // Two windows with an identical delta (1000 in) but at different cumulative
        // positions must NOT collide — otherwise the second window is wrongly dropped as
        // a duplicate (the original bug). Window 1 advances the counter to 1000, window 2
        // to 2000.
        let window1 = [entry("t1", 1000, 0, 0)];
        let window2 = [entry("t1", 2000, 0, 0)];
        assert_ne!(batch_report_id(&window1), batch_report_id(&window2));
    }

    #[test]
    fn report_id_is_order_independent() {
        let a = [entry("t1", 10, 20, 1), entry("t2", 30, 40, 2)];
        let b = [entry("t2", 30, 40, 2), entry("t1", 10, 20, 1)];
        assert_eq!(batch_report_id(&a), batch_report_id(&b));
    }
}
