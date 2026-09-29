//! DNS-proven hostname assignments from one authoritative endpoint lease.
//! Requests retain the same grant across renewals and stop when it is withdrawn.
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{sync::watch, time::Instant};
pub const DOMAIN_PROTOCOL: u8 = 1;
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DomainSet {
    pub revision: u64,
    pub domains: Vec<VerifiedDomain>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedDomain {
    pub hostname: String,
    pub verified_until: u64,
}
#[derive(Debug)]
pub struct DomainGrant {
    deadline: watch::Sender<Option<Instant>>,
    closed: AtomicBool,
}
impl DomainGrant {
    fn new(deadline: Instant) -> Arc<Self> {
        Self::with_deadline(Some(deadline))
    }
    fn with_deadline(deadline: Option<Instant>) -> Arc<Self> {
        Arc::new(Self {
            deadline: watch::channel(deadline).0,
            closed: AtomicBool::new(false),
        })
    }
    pub fn is_active(&self) -> bool {
        !self.closed.load(Ordering::Acquire)
            && self
                .deadline
                .borrow()
                .is_none_or(|deadline| deadline > Instant::now())
    }
    fn update(&self, deadline: Instant) -> Result<()> {
        if !self.is_active() {
            self.close();
            anyhow::bail!("custom-domain grant already expired or closed");
        }
        self.deadline.send_replace(Some(deadline));
        Ok(())
    }
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.deadline.send_replace(None);
    }
    pub async fn cancelled(&self) {
        let mut state = self.deadline.subscribe();
        loop {
            let deadline = *state.borrow_and_update();
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            let expires = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                biased;
                changed = state.changed() => { if changed.is_err() { return; } },
                () = expires => { if !self.is_active() { return; } },
            }
        }
    }
}
#[derive(Debug)]
pub struct DomainGrants {
    revision: u64,
    platform: String,
    grants: HashMap<String, Arc<DomainGrant>>,
}
impl DomainGrants {
    /// A self-hosted operator authorizes exact names in local configuration.
    /// No control-plane clock or renewable DNS lease applies to these grants.
    pub fn from_operator(hostnames: &[String], platform: &str) -> Result<Arc<Self>> {
        ensure!(hostnames.len() <= 16, "too many custom-domain grants");
        let mut grants = HashMap::new();
        for hostname in hostnames {
            validate_hostname(hostname, platform)?;
            ensure!(
                grants
                    .insert(hostname.clone(), DomainGrant::with_deadline(None))
                    .is_none(),
                "duplicate custom-domain grant"
            );
        }
        Ok(Arc::new(Self {
            revision: 0,
            platform: platform.to_owned(),
            grants,
        }))
    }
    pub fn bind(set: DomainSet, platform: &str) -> Result<Arc<Self>> {
        let domains = validate(&set, platform)?;
        Ok(Arc::new(Self {
            revision: set.revision,
            platform: platform.to_owned(),
            grants: domains
                .into_iter()
                .map(|(host, deadline)| (host, DomainGrant::new(deadline)))
                .collect(),
        }))
    }
    pub fn revision(&self) -> u64 {
        self.revision
    }
    pub fn hosts(&self) -> impl Iterator<Item = (&str, &Arc<DomainGrant>)> {
        self.grants
            .iter()
            .map(|(host, grant)| (host.as_str(), grant))
    }
    pub fn reconcile(&self, set: &DomainSet) -> Result<()> {
        let update = (|| {
            ensure!(
                set.revision == self.revision,
                "custom-domain assignment changed"
            );
            let values = validate(set, &self.platform)?;
            ensure!(
                values.len() == self.grants.len()
                    && values.keys().all(|host| self.grants.contains_key(host)),
                "new hostname without a domain revision"
            );
            for (host, grant) in &self.grants {
                grant.update(*values.get(host).expect("validated domain membership"))?;
            }
            Ok(())
        })();
        if update.is_err() {
            self.close();
        }
        update
    }
    pub fn close(&self) {
        for grant in self.grants.values() {
            grant.close();
        }
    }
}
fn validate(set: &DomainSet, platform: &str) -> Result<HashMap<String, Instant>> {
    ensure!(set.domains.len() <= 16, "too many custom-domain grants");
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?;
    let mut output = HashMap::new();
    for domain in &set.domains {
        let host = &domain.hostname;
        validate_hostname(host, platform)?;
        let remaining = Duration::from_millis(domain.verified_until)
            .checked_sub(now)
            .context("expired custom-domain grant")?;
        ensure!(
            !remaining.is_zero() && remaining <= Duration::from_secs(24 * 3600 + 60),
            "invalid custom-domain grant lifetime"
        );
        ensure!(
            output
                .insert(host.clone(), Instant::now() + remaining)
                .is_none(),
            "duplicate custom-domain grant"
        );
    }
    Ok(output)
}
fn validate_hostname(host: &str, platform: &str) -> Result<()> {
    let platform = platform.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<_> = host.split('.').collect();
    ensure!(
        host.len() <= 253
            && labels.len() >= 2
            && labels.iter().all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            })
            && labels
                .last()
                .is_some_and(|label| label.bytes().any(|b| b.is_ascii_lowercase())),
        "invalid custom hostname"
    );
    ensure!(
        host != platform && !host.ends_with(&format!(".{platform}")),
        "custom hostname overlaps platform zone"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn set(host: &str) -> DomainSet {
        DomainSet {
            revision: 4,
            domains: vec![VerifiedDomain {
                hostname: host.into(),
                verified_until: u64::try_from(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_millis(),
                )
                .unwrap()
                    + 60_000,
            }],
        }
    }
    #[test]
    fn untrusted_domain_snapshots_are_bounded_and_never_cover_the_platform() {
        assert!(DomainGrants::bind(set("preview.example.com"), "pike.life").is_ok());
        for host in [
            "pike.life",
            "a.pike.life",
            "a..com",
            "A.example.com",
            "127.0.0.1",
            "*.example.com",
            "https://example.com",
            "a.example.com:443",
            "a.example.com.",
        ] {
            assert!(
                DomainGrants::bind(set(host), "pike.life").is_err(),
                "{host}"
            );
        }
        let mut duplicate = set("preview.example.com");
        duplicate.domains.push(duplicate.domains[0].clone());
        assert!(DomainGrants::bind(duplicate, "pike.life").is_err());
        for expiry in [0, u64::MAX] {
            let mut invalid = set("preview.example.com");
            invalid.domains[0].verified_until = expiry;
            assert!(DomainGrants::bind(invalid, "pike.life").is_err());
        }
    }
    #[tokio::test(start_paused = true)]
    async fn renewal_extends_active_work_but_expiry_and_withdrawal_cancel_it() {
        let grant = DomainGrant::new(Instant::now() + Duration::from_secs(2));
        let held = grant.clone();
        let task = tokio::spawn(async move {
            held.cancelled().await;
        });
        tokio::task::yield_now().await;
        grant
            .update(Instant::now() + Duration::from_secs(10))
            .unwrap();
        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;
        assert!(!task.is_finished());
        grant.close();
        task.await.unwrap();
        assert!(!grant.is_active());
        assert!(grant
            .update(Instant::now() + Duration::from_secs(2))
            .is_err());
        let grant = DomainGrant::new(Instant::now() + Duration::from_secs(2));
        tokio::time::advance(Duration::from_secs(3)).await;
        grant.cancelled().await;
        assert!(!grant.is_active());
    }
    #[tokio::test]
    async fn changed_revision_or_membership_stickily_closes_captured_grants() {
        for changed in [
            DomainSet {
                revision: 5,
                ..set("preview.example.com")
            },
            set("different.example.com"),
        ] {
            let initial = set("preview.example.com");
            let grants = DomainGrants::bind(initial.clone(), "pike.life").unwrap();
            let held = grants.hosts().next().unwrap().1.clone();
            assert!(grants.reconcile(&changed).is_err());
            assert!(!held.is_active());
            assert!(grants.reconcile(&initial).is_err());
            assert!(!held.is_active());
            tokio::time::timeout(Duration::from_millis(100), held.cancelled())
                .await
                .unwrap();
        }
    }
}
