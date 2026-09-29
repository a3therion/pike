//! Shared ACME state and renewable, fenced per-host issuance leases.
//! Redis is authoritative for jobs; validated local certificates remain usable offline.
use super::SavedCertificate;
use anyhow::{ensure, Context, Result};
use deadpool_redis::{redis::Script, Config as RedisConfig, Pool, Runtime};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

const TIMEOUT: Duration = Duration::from_secs(2);
const MAX_RECORD: usize = 131_072;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharedConfig {
    pub redis_url: String,
    pub namespace: String,
}
impl std::fmt::Debug for SharedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedAcmeConfig")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}
pub(super) struct Shared {
    pool: Pool,
    prefix: String,
    proof_slots: tokio::sync::Semaphore,
}
#[derive(Default)]
pub(super) struct Snapshot {
    pub owner: String,
    pub version: String,
    pub certificate: Option<SavedCertificate>,
    pub retry_at: u64,
}
pub(super) struct Lease {
    store: Arc<Shared>,
    host: String,
    owner: String,
    fence: String,
    stop: watch::Sender<bool>,
    lost: watch::Sender<bool>,
}
impl Shared {
    pub fn new(config: &SharedConfig, directory: &str) -> Result<Arc<Self>> {
        ensure!(
            !config.namespace.is_empty()
                && config.namespace.len() <= 64
                && config
                    .namespace
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "ACME shared namespace requires 1-64 ASCII letters, digits, underscores or hyphens"
        );
        let url = reqwest::Url::parse(&config.redis_url)
            .map_err(|_| anyhow::anyhow!("invalid ACME Redis URL"))?;
        ensure!(
            matches!(url.scheme(), "redis" | "rediss") && url.fragment().is_none(),
            "ACME shared state requires Redis without insecure TLS options"
        );
        let mut cfg = RedisConfig::from_url(config.redis_url.clone());
        cfg.pool = Some(deadpool_redis::PoolConfig::new(8));
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|_| anyhow::anyhow!("invalid ACME Redis configuration"))?;
        Ok(Arc::new(Self {
            pool,
            proof_slots: tokio::sync::Semaphore::new(4),
            prefix: format!(
                "pike:acme:v1:{{{}}}:{:x}",
                config.namespace,
                Sha256::digest(directory.as_bytes())
            ),
        }))
    }
    fn keys(&self, host: &str) -> [String; 5] {
        let host = format!("{:x}", Sha256::digest(host.as_bytes()));
        [
            format!("{}:account", self.prefix),
            format!("{}:index", self.prefix),
            format!("{}:{host}:state", self.prefix),
            format!("{}:{host}:lease", self.prefix),
            format!("{}:{host}:challenge", self.prefix),
        ]
    }
    async fn call(
        &self,
        host: &str,
        op: &str,
        owner: &str,
        fence: &str,
        args: &[String],
    ) -> Result<Vec<String>> {
        tokio::time::timeout(TIMEOUT, async {
            let mut conn = self
                .pool
                .get()
                .await
                .map_err(|_| anyhow::anyhow!("ACME shared store unavailable"))?;
            let script = Script::new(include_str!("shared/state.lua"));
            let mut invocation = script.prepare_invoke();
            for key in self.keys(host) {
                invocation.key(key);
            }
            invocation.arg(op).arg(owner).arg(fence);
            for arg in args {
                invocation.arg(arg);
            }
            let rows: Vec<String> = invocation
                .invoke_async(&mut conn)
                .await
                .map_err(|_| anyhow::anyhow!("ACME shared store operation failed"))?;
            ensure!(
                rows.len() <= 4 && rows.iter().all(|v| v.len() <= MAX_RECORD),
                "ACME shared state exceeds limit"
            );
            Ok(rows)
        })
        .await
        .context("ACME shared store deadline exceeded")?
    }
    pub async fn account<T: DeserializeOwned>(&self) -> Result<Option<T>> {
        let rows = self.call("", "account_get", "", "", &[]).await?;
        rows.first()
            .map(|s| serde_json::from_str(s).context("invalid shared ACME account"))
            .transpose()
    }
    pub async fn initialize_account<T: Serialize + DeserializeOwned>(
        &self,
        candidate: &T,
    ) -> Result<T> {
        let rows = self
            .call("", "account_init", "", "", &[encode(candidate)?])
            .await?;
        serde_json::from_str(rows.first().context("missing shared ACME account")?)
            .context("invalid shared ACME account")
    }
    pub async fn finish_account<T: Serialize>(&self, pending: &T, ready: &T) -> Result<()> {
        let rows = self
            .call(
                "",
                "account_finish",
                "",
                "",
                &[encode(pending)?, encode(ready)?],
            )
            .await?;
        accepted(&rows)
    }
    pub async fn read(&self, host: &str) -> Result<Snapshot> {
        let rows = self.call(host, "read", "", "", &[]).await?;
        if rows.is_empty() {
            return Ok(Snapshot::default());
        }
        ensure!(rows.len() == 4, "invalid shared ACME certificate record");
        Ok(Snapshot {
            owner: rows[0].clone(),
            version: rows[1].clone(),
            certificate: if rows[2].is_empty() {
                None
            } else {
                Some(serde_json::from_str(&rows[2]).context("invalid shared ACME certificate")?)
            },
            retry_at: rows[3].parse().context("invalid shared ACME retry time")?,
        })
    }
    pub async fn claim(
        self: &Arc<Self>,
        host: &str,
        owner: &str,
        version: &str,
    ) -> Result<Option<Lease>> {
        let fence = uuid::Uuid::new_v4().to_string();
        let rows = self
            .call(host, "claim", owner, &fence, &[version.into()])
            .await?;
        if rows.is_empty() {
            return Ok(None);
        }
        accepted(&rows)?;
        let lease = Lease {
            store: self.clone(),
            host: host.into(),
            owner: owner.into(),
            fence,
            stop: watch::channel(false).0,
            lost: watch::channel(false).0,
        };
        lease.watch();
        Ok(Some(lease))
    }
    pub async fn proof(&self, host: &str, owner: &str, token: &str) -> Result<Option<String>> {
        if !valid_token(token) {
            return Ok(None);
        }
        let _slot = self
            .proof_slots
            .try_acquire()
            .context("ACME challenge lookup capacity exhausted")?;
        let rows = self.call(host, "proof", owner, token, &[]).await?;
        ensure!(
            rows.first().is_none_or(|value| value.len() <= 512),
            "ACME shared proof exceeds limit"
        );
        Ok(rows.into_iter().next())
    }
}
impl Lease {
    fn watch(&self) {
        let (store, host, owner, fence, lost) = (
            self.store.clone(),
            self.host.clone(),
            self.owner.clone(),
            self.fence.clone(),
            self.lost.clone(),
        );
        let mut stop = self.stop.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! { biased; _ = stop.changed() => return, _ = tokio::time::sleep(Duration::from_secs(5)) => {} }
                let result = tokio::select! { biased; _ = stop.changed() => return, result = store.call(&host, "renew", &owner, &fence, &[]) => result };
                if result.and_then(|rows| accepted(&rows)).is_err() {
                    lost.send_replace(true);
                    return;
                }
            }
        });
    }
    pub async fn cancelled(&self) {
        let _ = self.lost.subscribe().wait_for(|value| *value).await;
    }
    pub async fn publish(&self, token: &str, value: &str) -> Result<()> {
        ensure!(
            valid_token(token) && !value.is_empty() && value.len() <= 512,
            "invalid shared ACME proof"
        );
        accepted(
            &self
                .store
                .call(
                    &self.host,
                    "publish",
                    &self.owner,
                    &self.fence,
                    &[token.into(), value.into()],
                )
                .await?,
        )
    }
    pub async fn commit(&self, saved: &SavedCertificate, expires: u64) -> Result<()> {
        ensure!(
            saved.hostname == self.host && saved.owner == self.owner,
            "shared certificate identity mismatch"
        );
        accepted(
            &self
                .store
                .call(
                    &self.host,
                    "commit",
                    &self.owner,
                    &self.fence,
                    &[encode(saved)?, expires.to_string()],
                )
                .await?,
        )
    }
    pub async fn failure(&self, retry_secs: u64) -> Result<u64> {
        let rows = self
            .store
            .call(
                &self.host,
                "failure",
                &self.owner,
                &self.fence,
                &[retry_secs.to_string()],
            )
            .await?;
        rows.first()
            .context("shared ACME lease ended")?
            .parse()
            .context("invalid shared ACME retry time")
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.stop.send_replace(true);
        let (store, host, owner, fence) = (
            self.store.clone(),
            self.host.clone(),
            self.owner.clone(),
            self.fence.clone(),
        );
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = store.call(&host, "release", &owner, &fence, &[]).await;
            });
        }
        // If shutdown or Redis prevents release, the 15-second lease expires.
    }
}
fn encode(value: &impl Serialize) -> Result<String> {
    let value = serde_json::to_string(value)?;
    ensure!(
        value.len() <= MAX_RECORD,
        "ACME shared record exceeds limit"
    );
    Ok(value)
}
fn accepted(rows: &[String]) -> Result<()> {
    ensure!(
        rows.first().map(String::as_str) == Some("ok"),
        "shared ACME lease ended or capacity exceeded"
    );
    Ok(())
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 256
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_rejects_insecure_options_and_separates_ca_state() {
        for namespace in ["", "bad:key", "{slot}", &"a".repeat(65)] {
            assert!(Shared::new(
                &SharedConfig {
                    redis_url: "redis://127.0.0.1/0".into(),
                    namespace: namespace.into()
                },
                "https://ca.example/dir"
            )
            .is_err());
        }
        for url in ["http://127.0.0.1", "rediss://host/#insecure", "invalid"] {
            assert!(Shared::new(
                &SharedConfig {
                    redis_url: url.into(),
                    namespace: "test".into()
                },
                "https://ca.example/dir"
            )
            .is_err());
        }
        let config = SharedConfig {
            redis_url: "rediss://user:private-secret@redis.example/0".into(),
            namespace: "test".into(),
        };
        let one = Shared::new(&config, "https://one.example/dir").unwrap();
        let two = Shared::new(&config, "https://two.example/dir").unwrap();
        assert_ne!(one.keys("app.example"), two.keys("app.example"));
        assert!(!format!("{config:?}").contains("private-secret"));
    }

    #[tokio::test]
    #[ignore = "requires disposable Redis; run by the shared ACME E2E fixture"]
    async fn shared_acme_redis_contract() {
        let config = SharedConfig {
            redis_url: std::env::var("PIKE_ACME_REDIS_URL").expect("fixture Redis URL"),
            namespace: format!("contract-{}", uuid::Uuid::new_v4()),
        };
        let a = Shared::new(&config, "https://fixture-ca.example/dir").unwrap();
        let b = Shared::new(&config, "https://fixture-ca.example/dir").unwrap();
        let other_ca = Shared::new(&config, "https://other-ca.example/dir").unwrap();
        let pending_a = serde_json::json!({"state":"pending", "key":"a"});
        let pending_b = serde_json::json!({"state":"pending", "key":"b"});
        let (one, two) = tokio::join!(
            a.initialize_account(&pending_a),
            b.initialize_account(&pending_b)
        );
        let pending = one.unwrap();
        assert_eq!(pending, two.unwrap());
        assert!(other_ca
            .account::<serde_json::Value>()
            .await
            .unwrap()
            .is_none());
        let ready = serde_json::json!({"state":"ready", "key":pending["key"]});
        assert!(a
            .finish_account(&serde_json::json!({"wrong":true}), &ready)
            .await
            .is_err());
        a.finish_account(&pending, &ready).await.unwrap();
        b.finish_account(&pending, &ready).await.unwrap();
        assert!(a
            .finish_account(&pending, &serde_json::json!({"replacement":true}))
            .await
            .is_err());
        assert_eq!(
            b.account::<serde_json::Value>().await.unwrap().unwrap(),
            ready
        );
        let host = "app.example.com";
        let (one, two) = tokio::join!(a.claim(host, "owner", ""), b.claim(host, "owner", ""));
        let (one, two) = (one.unwrap(), two.unwrap());
        assert_ne!(one.is_some(), two.is_some());
        let first = one.or(two).unwrap();
        first.publish("first-token", "first-proof").await.unwrap();
        assert!(first
            .publish("first-token", "different-proof")
            .await
            .is_err());
        assert_eq!(
            b.proof(host, "owner", "first-token")
                .await
                .unwrap()
                .as_deref(),
            Some("first-proof")
        );
        assert!(b
            .proof("other.example", "owner", "first-token")
            .await
            .unwrap()
            .is_none());
        assert!(b
            .proof(host, "other-owner", "first-token")
            .await
            .unwrap()
            .is_none());
        assert!(b
            .proof(host, "owner", "other-token")
            .await
            .unwrap()
            .is_none());
        assert!(b.proof(host, "owner", "bad/path").await.unwrap().is_none());
        let slots: Vec<_> = (0..4)
            .map(|_| b.proof_slots.try_acquire().unwrap())
            .collect();
        assert!(b.proof(host, "owner", "first-token").await.is_err());
        assert!(b.account::<serde_json::Value>().await.unwrap().is_some());
        drop(slots);
        // Force lease expiration without waiting for renewal. Both stale writes
        // and delayed cleanup must preserve a newly claimed owner's proof.
        let mut conn = a.pool.get().await.unwrap();
        let keys = a.keys(host);
        let _: usize = deadpool_redis::redis::cmd("DEL")
            .arg(&keys[3])
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(b
            .proof(host, "owner", "first-token")
            .await
            .unwrap()
            .is_none());
        let snapshot = b.read(host).await.unwrap();
        let replacement = b
            .claim(host, "new-owner", &snapshot.version)
            .await
            .unwrap()
            .unwrap();
        // The old proof has an independently bounded TTL, but may not block its
        // successor's publication once the owning lease is gone.
        replacement
            .publish("replacement-token", "replacement-proof")
            .await
            .unwrap();
        let old_saved = SavedCertificate {
            hostname: host.into(),
            owner: "owner".into(),
            chain_pem: "old-chain".into(),
            key_pem: "old-key".into(),
        };
        assert!(first
            .commit(&old_saved, super::super::material::now() + 60)
            .await
            .is_err());
        assert!(first.publish("late-token", "late-proof").await.is_err());
        assert!(first.failure(5).await.is_err());
        tokio::time::timeout(Duration::from_secs(7), first.cancelled())
            .await
            .unwrap();
        drop(first);
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert_eq!(
            a.proof(host, "new-owner", "replacement-token")
                .await
                .unwrap()
                .as_deref(),
            Some("replacement-proof")
        );
        assert!(a
            .proof(host, "owner", "replacement-token")
            .await
            .unwrap()
            .is_none());
        let saved = SavedCertificate {
            hostname: host.into(),
            owner: "new-owner".into(),
            chain_pem: "fixture-chain".into(),
            key_pem: "fixture-key".into(),
        };
        replacement
            .commit(&saved, super::super::material::now() + 60)
            .await
            .unwrap();
        let current = a.read(host).await.unwrap();
        assert_eq!(current.certificate.unwrap().chain_pem, "fixture-chain");
        drop(replacement);
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(a
            .claim(host, "new-owner", &snapshot.version)
            .await
            .unwrap()
            .is_none());
        let next = a
            .claim(host, "new-owner", &current.version)
            .await
            .unwrap()
            .unwrap();
        let retry_at = next.failure(5).await.unwrap();
        assert!(retry_at > super::super::material::now() * 1000);
        drop(next);
        tokio::time::sleep(Duration::from_millis(25)).await;
        let restarted = Shared::new(&config, "https://fixture-ca.example/dir").unwrap();
        let snapshot = restarted.read(host).await.unwrap();
        assert_eq!(snapshot.retry_at, retry_at);
        assert!(restarted
            .claim(host, "new-owner", &snapshot.version)
            .await
            .unwrap()
            .is_none());
        assert!(
            snapshot.certificate.is_some(),
            "failed renewal keeps prior certificate"
        );
        // Populate the index to its documented ceiling without spawning 16k
        // live renewal tasks. A new host must not allocate the 16,385th slot.
        let mut pipe = deadpool_redis::redis::pipe();
        for n in 0..16384 {
            pipe.cmd("ZADD")
                .arg(&keys[1])
                .arg((super::super::material::now() + 60) * 1000)
                .arg(format!("fixture-{n}"))
                .ignore();
        }
        let _: () = pipe.query_async(&mut conn).await.unwrap();
        assert!(a.claim("capacity.example", "owner", "").await.is_err());
        let _: usize = deadpool_redis::redis::cmd("DEL")
            .arg(&keys)
            .query_async(&mut conn)
            .await
            .unwrap();
    }
}
