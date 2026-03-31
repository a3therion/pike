use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use dashmap::{DashMap, DashSet};
use governor::clock::{Clock, DefaultClock};
use governor::state::direct::NotKeyed;
use governor::state::InMemoryState;
use governor::{Quota, RateLimiter as Governor};
use pike_core::types::TunnelId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::runtime::{Handle, RuntimeFlavor};

use crate::config::AbuseConfig;
use crate::state_store::StateStore;

pub type UserId = String;

type DirectLimiter = Governor<NotKeyed, InMemoryState, DefaultClock>;

#[derive(Debug, thiserror::Error)]
pub enum AbuseError {
    #[error("user is banned")]
    UserBanned,
    #[error("tunnel is suspended")]
    TunnelSuspended,
    #[error("tunnel creation rate exceeded for user; retry after {retry_after_secs}s")]
    UserTunnelCreationRateExceeded { retry_after_secs: u64 },
    #[error("tunnel creation rate exceeded for ip; retry after {retry_after_secs}s")]
    IpTunnelCreationRateExceeded { retry_after_secs: u64 },
}

#[derive(Debug)]
pub struct RequestCounter {
    pub requests_per_minute: AtomicU64,
    pub error_count: AtomicU64,
    pub last_reset: Mutex<Instant>,
}

impl Default for RequestCounter {
    fn default() -> Self {
        Self {
            requests_per_minute: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            last_reset: Mutex::new(Instant::now()),
        }
    }
}

impl RequestCounter {
    fn reset_window_if_needed(&self) {
        if let Ok(mut last) = self.last_reset.lock() {
            if last.elapsed() >= Duration::from_secs(60) {
                self.requests_per_minute.store(0, Ordering::Relaxed);
                self.error_count.store(0, Ordering::Relaxed);
                *last = Instant::now();
            }
        }
    }

    fn error_rate_percent(&self) -> u64 {
        let requests = self.requests_per_minute.load(Ordering::Relaxed);
        if requests == 0 {
            return 0;
        }
        let errors = self.error_count.load(Ordering::Relaxed);
        (errors.saturating_mul(100)) / requests
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AbuseEvent {
    HighRequestRate {
        tunnel_id: String,
        requests_per_minute: u64,
    },
    HighErrorRate {
        tunnel_id: String,
        error_rate_percent: u64,
    },
    MalwareSignature {
        signature: String,
    },
    UserBanned {
        user_id: String,
    },
    TunnelSuspended {
        tunnel_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbuseLogEntry {
    pub timestamp: DateTime<Utc>,
    pub source_ip: Option<IpAddr>,
    pub user_id: Option<UserId>,
    pub tunnel_id: Option<TunnelId>,
    pub request_count_per_minute: Option<u64>,
    pub bandwidth_bytes: Option<u64>,
    pub reason: String,
}

#[derive(Clone)]
pub struct AbuseDetector {
    tunnel_creation_limits: DashMap<UserId, Arc<DirectLimiter>>,
    ip_limits: DashMap<IpAddr, Arc<DirectLimiter>>,
    request_counters: DashMap<TunnelId, Arc<RequestCounter>>,
    malware_signatures: Arc<HashSet<String>>,
    banned_users: DashSet<UserId>,
    suspended_tunnels: DashSet<TunnelId>,
    abuse_logs: Arc<Mutex<VecDeque<AbuseLogEntry>>>,
    state_store: Option<Arc<dyn StateStore>>,
    webhook_url: Option<String>,
    webhook_client: reqwest::Client,
    tunnel_creations_per_user_per_hour: u32,
    tunnel_creations_per_ip_per_hour: u32,
    auto_suspend_requests_per_minute: u64,
    phishing_error_rate_percent: u64,
    abuse_log_retention_days: i64,
}

impl fmt::Debug for AbuseDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AbuseDetector")
            .field("tunnel_creation_limits", &self.tunnel_creation_limits)
            .field("ip_limits", &self.ip_limits)
            .field("request_counters", &self.request_counters)
            .field("malware_signatures", &self.malware_signatures)
            .field("banned_users", &self.banned_users)
            .field("suspended_tunnels", &self.suspended_tunnels)
            .field("abuse_logs", &self.abuse_logs)
            .field(
                "state_store",
                &self.state_store.as_ref().map(|_| "configured"),
            )
            .field("webhook_url", &self.webhook_url)
            .field(
                "tunnel_creations_per_user_per_hour",
                &self.tunnel_creations_per_user_per_hour,
            )
            .field(
                "tunnel_creations_per_ip_per_hour",
                &self.tunnel_creations_per_ip_per_hour,
            )
            .field(
                "auto_suspend_requests_per_minute",
                &self.auto_suspend_requests_per_minute,
            )
            .field(
                "phishing_error_rate_percent",
                &self.phishing_error_rate_percent,
            )
            .field("abuse_log_retention_days", &self.abuse_log_retention_days)
            .finish_non_exhaustive()
    }
}

impl Default for AbuseDetector {
    fn default() -> Self {
        Self::new(AbuseConfig::default())
    }
}

impl AbuseDetector {
    #[must_use]
    pub fn new(config: AbuseConfig) -> Self {
        Self::from_parts(config, None)
    }

    #[must_use]
    pub fn with_store(config: AbuseConfig, store: Arc<dyn StateStore>) -> Self {
        Self::from_parts(config, Some(store))
    }

    fn from_parts(config: AbuseConfig, state_store: Option<Arc<dyn StateStore>>) -> Self {
        let signatures = default_malware_signatures();
        Self {
            tunnel_creation_limits: DashMap::new(),
            ip_limits: DashMap::new(),
            request_counters: DashMap::new(),
            malware_signatures: Arc::new(signatures),
            banned_users: DashSet::new(),
            suspended_tunnels: DashSet::new(),
            abuse_logs: Arc::new(Mutex::new(VecDeque::new())),
            state_store,
            webhook_url: config.webhook_url,
            webhook_client: reqwest::Client::new(),
            tunnel_creations_per_user_per_hour: config.tunnel_creations_per_user_per_hour,
            tunnel_creations_per_ip_per_hour: config.tunnel_creations_per_ip_per_hour,
            auto_suspend_requests_per_minute: config.auto_suspend_requests_per_minute,
            phishing_error_rate_percent: config.phishing_error_rate_percent,
            abuse_log_retention_days: config.abuse_log_retention_days,
        }
    }

    pub fn check_tunnel_creation_rate(
        &self,
        user_id: &UserId,
        ip: IpAddr,
    ) -> Result<(), AbuseError> {
        if self.is_banned(user_id) {
            return Err(AbuseError::UserBanned);
        }

        let user_limiter = self
            .tunnel_creation_limits
            .entry(user_id.clone())
            .or_insert_with(|| Arc::new(new_hour_limiter(self.tunnel_creations_per_user_per_hour)))
            .clone();
        if let Err(negative) = user_limiter.check() {
            let retry_after_secs = negative
                .wait_time_from(DefaultClock::default().now())
                .as_secs()
                .max(1);
            return Err(AbuseError::UserTunnelCreationRateExceeded { retry_after_secs });
        }

        let ip_limiter = self
            .ip_limits
            .entry(ip)
            .or_insert_with(|| Arc::new(new_hour_limiter(self.tunnel_creations_per_ip_per_hour)))
            .clone();
        if let Err(negative) = ip_limiter.check() {
            let retry_after_secs = negative
                .wait_time_from(DefaultClock::default().now())
                .as_secs()
                .max(1);
            return Err(AbuseError::IpTunnelCreationRateExceeded { retry_after_secs });
        }

        Ok(())
    }

    pub fn record_request(&self, tunnel_id: TunnelId, status: u16) {
        let counter = self
            .request_counters
            .entry(tunnel_id)
            .or_insert_with(|| Arc::new(RequestCounter::default()))
            .clone();

        counter.reset_window_if_needed();
        let requests = counter.requests_per_minute.fetch_add(1, Ordering::Relaxed) + 1;

        if status >= 400 {
            counter.error_count.fetch_add(1, Ordering::Relaxed);
        }

        if requests > self.auto_suspend_requests_per_minute
            && self.suspended_tunnels.insert(tunnel_id)
        {
            self.log_abuse(AbuseLogEntry {
                timestamp: Utc::now(),
                source_ip: None,
                user_id: None,
                tunnel_id: Some(tunnel_id),
                request_count_per_minute: Some(requests),
                bandwidth_bytes: None,
                reason: "auto-suspended due to high request rate".to_string(),
            });

            let detector = self.clone();
            tokio::spawn(async move {
                let _ = detector
                    .send_webhook(AbuseEvent::HighRequestRate {
                        tunnel_id: tunnel_id.to_string(),
                        requests_per_minute: requests,
                    })
                    .await;
            });
        }

        let error_rate = counter.error_rate_percent();
        if error_rate > self.phishing_error_rate_percent {
            self.log_abuse(AbuseLogEntry {
                timestamp: Utc::now(),
                source_ip: None,
                user_id: None,
                tunnel_id: Some(tunnel_id),
                request_count_per_minute: Some(requests),
                bandwidth_bytes: None,
                reason: "high 4xx/5xx error rate flagged as suspicious".to_string(),
            });

            let detector = self.clone();
            tokio::spawn(async move {
                let _ = detector
                    .send_webhook(AbuseEvent::HighErrorRate {
                        tunnel_id: tunnel_id.to_string(),
                        error_rate_percent: error_rate,
                    })
                    .await;
            });
        }
    }

    #[must_use]
    pub fn check_malware_signature(&self, content: &[u8]) -> Option<String> {
        let md5_hash = format!("{:x}", md5::compute(content));
        if self.malware_signatures.contains(&md5_hash) {
            return Some(md5_hash);
        }

        let mut hasher = Sha256::new();
        hasher.update(content);
        let sha256_hash = format!("{:x}", hasher.finalize());
        if self.malware_signatures.contains(&sha256_hash) {
            return Some(sha256_hash);
        }

        None
    }

    #[must_use]
    pub fn should_auto_suspend(&self, tunnel_id: TunnelId) -> bool {
        self.request_counters
            .get(&tunnel_id)
            .map(|counter| {
                counter.requests_per_minute.load(Ordering::Relaxed)
                    > self.auto_suspend_requests_per_minute
            })
            .unwrap_or(false)
    }

    pub fn ban_user(&self, user_id: UserId) -> Result<(), AbuseError> {
        const DEFAULT_BAN_DURATION_SECS: u64 = 365 * 24 * 60 * 60;
        let reason = "user banned by admin command";

        self.banned_users.insert(user_id.clone());
        let _ = self.call_store_result(async {
            let Some(store) = &self.state_store else {
                return Ok(());
            };
            store
                .ban_user(&user_id, reason, DEFAULT_BAN_DURATION_SECS)
                .await
        });

        self.log_abuse(AbuseLogEntry {
            timestamp: Utc::now(),
            source_ip: None,
            user_id: Some(user_id.clone()),
            tunnel_id: None,
            request_count_per_minute: None,
            bandwidth_bytes: None,
            reason: reason.to_string(),
        });

        let detector = self.clone();
        tokio::spawn(async move {
            let _ = detector
                .send_webhook(AbuseEvent::UserBanned { user_id })
                .await;
        });
        Ok(())
    }

    pub fn unban_user(&self, user_id: UserId) -> Result<(), AbuseError> {
        self.banned_users.remove(&user_id);
        let _ = self.call_store_result(async {
            let Some(store) = &self.state_store else {
                return Ok(());
            };
            store.unban_user(&user_id).await
        });

        self.log_abuse(AbuseLogEntry {
            timestamp: Utc::now(),
            source_ip: None,
            user_id: Some(user_id),
            tunnel_id: None,
            request_count_per_minute: None,
            bandwidth_bytes: None,
            reason: "user unbanned by admin command".to_string(),
        });
        Ok(())
    }

    pub fn suspend_tunnel(&self, tunnel_id: TunnelId) -> Result<(), AbuseError> {
        self.suspended_tunnels.insert(tunnel_id);
        self.log_abuse(AbuseLogEntry {
            timestamp: Utc::now(),
            source_ip: None,
            user_id: None,
            tunnel_id: Some(tunnel_id),
            request_count_per_minute: None,
            bandwidth_bytes: None,
            reason: "tunnel suspended by abuse detector".to_string(),
        });

        let detector = self.clone();
        tokio::spawn(async move {
            let _ = detector
                .send_webhook(AbuseEvent::TunnelSuspended {
                    tunnel_id: tunnel_id.to_string(),
                })
                .await;
        });
        Ok(())
    }

    #[must_use]
    pub fn list_bans(&self) -> Vec<UserId> {
        self.banned_users
            .iter()
            .map(|entry| entry.clone())
            .collect()
    }

    #[must_use]
    pub fn is_banned(&self, user_id: &UserId) -> bool {
        if self.banned_users.contains(user_id) {
            return true;
        }

        let is_banned_in_store = self
            .call_store_result(async {
                let Some(store) = &self.state_store else {
                    return Ok(false);
                };
                store.is_banned(user_id).await
            })
            .unwrap_or(false);

        if is_banned_in_store {
            self.banned_users.insert(user_id.clone());
            return true;
        }

        false
    }

    #[must_use]
    pub fn is_suspended(&self, tunnel_id: &TunnelId) -> bool {
        self.suspended_tunnels.contains(tunnel_id)
    }

    pub fn log_abuse(&self, entry: AbuseLogEntry) {
        const MAX_ABUSE_LOGS: usize = 10_000;

        let _ = self.call_store_result(async {
            let Some(store) = &self.state_store else {
                return Ok(());
            };
            store.log_abuse(&entry).await
        });

        if let Ok(mut logs) = self.abuse_logs.lock() {
            logs.push_back(entry);
            if logs.len() > MAX_ABUSE_LOGS {
                logs.pop_front();
            }
            let retention_cutoff =
                Utc::now() - chrono::Duration::days(self.abuse_log_retention_days);
            logs.retain(|item| item.timestamp >= retention_cutoff);
        }
    }

    #[must_use]
    pub fn get_abuse_logs(&self, since: DateTime<Utc>) -> Vec<AbuseLogEntry> {
        if let Ok(logs) = self.abuse_logs.lock() {
            return logs
                .iter()
                .filter(|entry| entry.timestamp >= since)
                .cloned()
                .collect();
        }
        Vec::new()
    }

    pub async fn send_webhook(&self, event: AbuseEvent) -> anyhow::Result<()> {
        let Some(url) = &self.webhook_url else {
            return Ok(());
        };

        self.webhook_client
            .post(url)
            .json(&event)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    fn call_store_result<F, T>(&self, future: F) -> anyhow::Result<T>
    where
        F: Future<Output = anyhow::Result<T>> + Send,
        T: Send,
    {
        if let Ok(handle) = Handle::try_current() {
            if matches!(handle.runtime_flavor(), RuntimeFlavor::MultiThread) {
                tokio::task::block_in_place(|| handle.block_on(future))
            } else {
                std::thread::scope(|scope| {
                    let join = scope.spawn(|| {
                        let runtime = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        runtime.block_on(future)
                    });

                    join.join()
                        .map_err(|_| anyhow::anyhow!("state store thread panicked"))?
                })
            }
        } else {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(future)
        }
    }
}

fn new_hour_limiter(per_hour: u32) -> DirectLimiter {
    Governor::direct(Quota::per_hour(
        NonZeroU32::new(per_hour).expect("per-hour quota must be non-zero"),
    ))
}

fn default_malware_signatures() -> HashSet<String> {
    HashSet::new()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use chrono::Duration;
    use pike_core::types::TunnelId;

    use super::{AbuseConfig, AbuseDetector, AbuseLogEntry};
    use crate::state_store::{InMemoryStateStore, StateStore};

    impl AbuseDetector {
        fn with_test_signatures(signatures: &[&str]) -> Self {
            let mut detector = Self::new(AbuseConfig::default());
            detector.malware_signatures = Arc::new(
                signatures
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            );
            detector
        }
    }

    #[test]
    fn enforces_tunnel_creation_rate_limits() {
        let detector = AbuseDetector::new(AbuseConfig {
            tunnel_creations_per_user_per_hour: 2,
            tunnel_creations_per_ip_per_hour: 10,
            ..AbuseConfig::default()
        });
        let user = "user-a".to_string();
        let ip = Ipv4Addr::LOCALHOST.into();

        assert!(detector.check_tunnel_creation_rate(&user, ip).is_ok());
        assert!(detector.check_tunnel_creation_rate(&user, ip).is_ok());
        assert!(detector.check_tunnel_creation_rate(&user, ip).is_err());
    }

    #[tokio::test]
    async fn ban_unban_lifecycle_works() {
        let detector = AbuseDetector::default();
        let user = "user-ban-test".to_string();

        detector.ban_user(user.clone()).expect("ban user");
        assert!(detector.is_banned(&user));

        detector.unban_user(user.clone()).expect("unban user");
        assert!(!detector.is_banned(&user));
    }

    #[tokio::test]
    async fn test_banned_user_persists() {
        let store = Arc::new(InMemoryStateStore::new()) as Arc<dyn StateStore>;
        let detector = AbuseDetector::with_store(AbuseConfig::default(), store.clone());
        let user = "persisted-banned-user".to_string();

        detector.ban_user(user.clone()).expect("ban user");

        let detector_after_restart = AbuseDetector::with_store(AbuseConfig::default(), store);
        assert!(detector_after_restart.is_banned(&user));
    }

    #[tokio::test]
    async fn test_abuse_logs_persist() {
        let store = Arc::new(InMemoryStateStore::new()) as Arc<dyn StateStore>;
        let detector = AbuseDetector::with_store(AbuseConfig::default(), store.clone());

        let entry = AbuseLogEntry {
            timestamp: chrono::Utc::now(),
            source_ip: None,
            user_id: Some("persisted-user".to_string()),
            tunnel_id: None,
            request_count_per_minute: Some(8),
            bandwidth_bytes: Some(1024),
            reason: "persisted abuse event".to_string(),
        };
        detector.log_abuse(entry.clone());

        let _detector_after_restart =
            AbuseDetector::with_store(AbuseConfig::default(), store.clone());
        let persisted_logs = store.get_abuse_logs(10).await.expect("get abuse logs");

        assert!(persisted_logs.iter().any(|log| {
            log.reason == entry.reason
                && log.user_id == entry.user_id
                && log.request_count_per_minute == entry.request_count_per_minute
        }));
    }

    #[tokio::test]
    async fn auto_suspend_triggers_on_request_pattern() {
        let detector = AbuseDetector::new(AbuseConfig {
            auto_suspend_requests_per_minute: 3,
            ..AbuseConfig::default()
        });
        let tunnel_id = TunnelId::new();

        for _ in 0..4 {
            detector.record_request(tunnel_id, 200);
        }
        assert!(detector.should_auto_suspend(tunnel_id));
        assert!(detector.is_suspended(&tunnel_id));
    }

    #[test]
    fn malware_signature_detection_checks_md5_and_sha256() {
        let md5_detector =
            AbuseDetector::with_test_signatures(&["d41d8cd98f00b204e9800998ecf8427e"]);
        assert_eq!(
            md5_detector.check_malware_signature(&[]),
            Some("d41d8cd98f00b204e9800998ecf8427e".to_string())
        );

        let sha256_detector = AbuseDetector::with_test_signatures(&[
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ]);
        assert_eq!(
            sha256_detector.check_malware_signature(&[]),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string())
        );
    }

    #[test]
    fn malware_signature_detection_is_disabled_by_default() {
        let detector = AbuseDetector::default();
        assert_eq!(detector.check_malware_signature(&[]), None);
    }

    #[test]
    fn abuse_logs_apply_retention_window() {
        let detector = AbuseDetector::new(AbuseConfig {
            abuse_log_retention_days: 90,
            ..AbuseConfig::default()
        });

        let old = AbuseLogEntry {
            timestamp: chrono::Utc::now() - Duration::days(91),
            source_ip: None,
            user_id: None,
            tunnel_id: None,
            request_count_per_minute: None,
            bandwidth_bytes: None,
            reason: "stale".to_string(),
        };
        detector.log_abuse(old);

        let fresh = AbuseLogEntry {
            timestamp: chrono::Utc::now(),
            source_ip: None,
            user_id: None,
            tunnel_id: None,
            request_count_per_minute: None,
            bandwidth_bytes: Some(42),
            reason: "fresh".to_string(),
        };
        detector.log_abuse(fresh);

        let logs = detector.get_abuse_logs(chrono::Utc::now() - Duration::days(1));
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].reason, "fresh");
    }

    #[test]
    fn test_abuse_logs_bounded() {
        let detector = AbuseDetector::default();

        for i in 0..10_001 {
            detector.log_abuse(AbuseLogEntry {
                timestamp: chrono::Utc::now(),
                source_ip: None,
                user_id: None,
                tunnel_id: None,
                request_count_per_minute: Some(i as u64),
                bandwidth_bytes: None,
                reason: format!("entry_{}", i),
            });
        }

        let logs = detector.get_abuse_logs(chrono::Utc::now() - Duration::days(1));
        assert_eq!(
            logs.len(),
            10_000,
            "abuse logs should be capped at 10,000 entries"
        );
    }

    #[test]
    fn test_abuse_log_eviction_order() {
        let detector = AbuseDetector::default();

        detector.log_abuse(AbuseLogEntry {
            timestamp: chrono::Utc::now(),
            source_ip: None,
            user_id: None,
            tunnel_id: None,
            request_count_per_minute: Some(1),
            bandwidth_bytes: None,
            reason: "entry_1".to_string(),
        });

        detector.log_abuse(AbuseLogEntry {
            timestamp: chrono::Utc::now(),
            source_ip: None,
            user_id: None,
            tunnel_id: None,
            request_count_per_minute: Some(2),
            bandwidth_bytes: None,
            reason: "entry_2".to_string(),
        });

        detector.log_abuse(AbuseLogEntry {
            timestamp: chrono::Utc::now(),
            source_ip: None,
            user_id: None,
            tunnel_id: None,
            request_count_per_minute: Some(3),
            bandwidth_bytes: None,
            reason: "entry_3".to_string(),
        });

        {
            let logs = detector.abuse_logs.lock().unwrap();
            assert_eq!(logs.len(), 3);
            assert_eq!(logs[0].request_count_per_minute, Some(1));
            assert_eq!(logs[1].request_count_per_minute, Some(2));
            assert_eq!(logs[2].request_count_per_minute, Some(3));
        }

        detector.log_abuse(AbuseLogEntry {
            timestamp: chrono::Utc::now(),
            source_ip: None,
            user_id: None,
            tunnel_id: None,
            request_count_per_minute: Some(4),
            bandwidth_bytes: None,
            reason: "entry_4".to_string(),
        });

        {
            let logs = detector.abuse_logs.lock().unwrap();
            assert_eq!(logs.len(), 4);
            assert_eq!(
                logs[0].request_count_per_minute,
                Some(1),
                "first entry should still be present"
            );
        }

        const MAX_ABUSE_LOGS: usize = 10_000;
        for i in 5..=MAX_ABUSE_LOGS as u64 {
            detector.log_abuse(AbuseLogEntry {
                timestamp: chrono::Utc::now(),
                source_ip: None,
                user_id: None,
                tunnel_id: None,
                request_count_per_minute: Some(i),
                bandwidth_bytes: None,
                reason: format!("entry_{}", i),
            });
        }

        {
            let logs = detector.abuse_logs.lock().unwrap();
            assert_eq!(logs.len(), MAX_ABUSE_LOGS);
            assert_eq!(
                logs[0].request_count_per_minute,
                Some(1),
                "entry_1 should still be present at capacity"
            );
        }

        detector.log_abuse(AbuseLogEntry {
            timestamp: chrono::Utc::now(),
            source_ip: None,
            user_id: None,
            tunnel_id: None,
            request_count_per_minute: Some(10_001),
            bandwidth_bytes: None,
            reason: "entry_10001".to_string(),
        });

        {
            let logs = detector.abuse_logs.lock().unwrap();
            assert_eq!(logs.len(), MAX_ABUSE_LOGS);
            assert_eq!(
                logs[0].request_count_per_minute,
                Some(2),
                "entry_1 should be evicted (FIFO), entry_2 should be first"
            );
            assert_eq!(
                logs[MAX_ABUSE_LOGS - 1].request_count_per_minute,
                Some(10_001),
                "newest entry should be last"
            );
        }
    }
}
