//! Shared OIDC state. Never falls back to local authentication on Redis failure.
use super::{digest, random, Config, Pending, Session};
use crate::visitor_policy::Rejection;
use deadpool_redis::{redis::Script, Config as RedisConfig, Pool, Runtime};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Weak,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;

const TIMEOUT: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_secs(1);
const MAX_SESSIONS: usize = 8192;

pub(super) struct Store {
    pool: Pool,
    keys: [String; 5],
    // Weak entries only: a finished response does not keep a watcher alive.
    active: Mutex<HashMap<String, Weak<Session>>>,
    watching: AtomicBool,
}
impl Store {
    pub(super) fn new(config: &Config) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(!config.namespace.is_empty() && config.namespace.len() <= 64
            && config.namespace.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "visitor session namespace must contain 1-64 ASCII letters, digits, underscores or hyphens");
        let url = reqwest::Url::parse(&config.redis_url)
            .map_err(|_| anyhow::anyhow!("invalid visitor session Redis URL"))?;
        anyhow::ensure!(
            matches!(url.scheme(), "redis" | "rediss") && url.fragment().is_none(),
            "visitor sessions require a redis:// or rediss:// URL without insecure TLS options"
        );
        let mut cfg = RedisConfig::from_url(config.redis_url.clone());
        cfg.pool = Some(deadpool_redis::PoolConfig::new(8));
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|_| anyhow::anyhow!("invalid visitor session Redis configuration"))?;
        let prefix = format!("pike:oidc:v1:{{{}}}", config.namespace);
        Ok(Arc::new(Self {
            pool,
            keys: [
                "pending",
                "pending_expiry",
                "pending_scopes",
                "sessions",
                "session_expiry",
            ]
            .map(|s| format!("{prefix}:{s}")),
            active: Mutex::new(HashMap::new()),
            watching: AtomicBool::new(false),
        }))
    }
    async fn call(&self, op: &str, args: &[String]) -> Result<Vec<String>, Rejection> {
        tokio::time::timeout(TIMEOUT, async {
            let mut connection = self.pool.get().await.map_err(|_| Rejection::Unavailable)?;
            let script = Script::new(include_str!("state.lua"));
            let mut invocation = script.prepare_invoke();
            for key in &self.keys {
                invocation.key(key);
            }
            invocation.arg(op);
            for arg in args {
                invocation.arg(arg);
            }
            invocation
                .invoke_async(&mut connection)
                .await
                .map_err(|_| Rejection::Unavailable)
        })
        .await
        .map_err(|_| Rejection::Unavailable)?
    }
    pub(super) async fn begin(&self, pending: Pending) -> Result<String, Rejection> {
        let token = random()?;
        let expiry = deadline(pending.expires, Duration::from_secs(300))?;
        let value = serde_json::to_string(&pending).map_err(|_| Rejection::Unavailable)?;
        if value.len() > 8192 {
            return Err(Rejection::Unavailable);
        }
        let result = self
            .call("begin", &[digest(&token), pending.scope, value, expiry])
            .await?;
        if result.first().map(String::as_str) != Some("ok") {
            return Err(Rejection::Unavailable);
        }
        Ok(token)
    }
    pub(super) async fn consume(
        &self,
        token: &str,
        browser: &str,
        scope: &str,
    ) -> Result<Pending, Rejection> {
        let result = self
            .call("consume", &[digest(token), scope.into(), digest(browser)])
            .await?;
        let value = result.first().ok_or(Rejection::InvalidSignIn)?;
        serde_json::from_str(value).map_err(|_| Rejection::Unavailable)
    }
    pub(super) async fn create(
        self: &Arc<Self>,
        scope: &str,
        expires: Instant,
    ) -> Result<(String, Arc<Session>), Rejection> {
        let token = random()?;
        let key = digest(&token);
        let expiry = deadline(expires, Duration::from_secs(86400))?;
        let start = Instant::now();
        let result = self
            .call(
                "create",
                &[key.clone(), scope.into(), String::new(), expiry],
            )
            .await?;
        let remaining = lifetime(&result)?.ok_or(Rejection::Unavailable)?;
        let session = self.track(key, scope, expires.min(start + remaining))?;
        Ok((token, session))
    }
    pub(super) async fn get(
        self: &Arc<Self>,
        token: &str,
        scope: &str,
    ) -> Result<Option<Arc<Session>>, Rejection> {
        let key = digest(token);
        let start = Instant::now();
        let result = self.call("get", &[key.clone(), scope.into()]).await?;
        match lifetime(&result)? {
            Some(remaining) if start + remaining > Instant::now() => {
                self.track(key, scope, start + remaining).map(Some)
            }
            _ => {
                self.close_local(&key, scope);
                Ok(None)
            }
        }
    }
    pub(super) async fn revoke(&self, token: &str, scope: &str) -> Result<(), Rejection> {
        let key = digest(token);
        self.close_local(&key, scope);
        let result = self.call("revoke", &[key, scope.into()]).await?;
        if result.first().map(String::as_str) != Some("ok") {
            return Err(Rejection::Unavailable);
        }
        Ok(())
    }
    fn close_local(&self, key: &str, scope: &str) {
        if let Ok(active) = self.active.lock() {
            if let Some(session) = active
                .get(key)
                .and_then(Weak::upgrade)
                .filter(|s| s.scope == scope)
            {
                session.close();
            }
        }
    }
    fn track(
        self: &Arc<Self>,
        key: String,
        scope: &str,
        expires: Instant,
    ) -> Result<Arc<Session>, Rejection> {
        let mut active = self.active.lock().map_err(|_| Rejection::Unavailable)?;
        active.retain(|_, entry| entry.strong_count() > 0);
        if let Some(session) = active.get(&key).and_then(Weak::upgrade) {
            if session.scope != scope
                || *session.closed.borrow()
                || session.expires <= Instant::now()
            {
                return Err(Rejection::Unavailable);
            }
            return Ok(session);
        }
        if active.len() >= MAX_SESSIONS {
            return Err(Rejection::Unavailable);
        }
        let session = Arc::new(Session {
            scope: scope.into(),
            expires,
            closed: tokio::sync::watch::channel(false).0,
        });
        active.insert(key, Arc::downgrade(&session));
        if !self.watching.swap(true, Ordering::AcqRel) {
            tokio::spawn(Self::watch(Arc::downgrade(self)));
        }
        Ok(session)
    }
    async fn watch(weak: Weak<Self>) {
        loop {
            tokio::time::sleep(POLL).await;
            let Some(store) = weak.upgrade() else {
                return;
            };
            let sessions: Vec<_> = match store.active.lock() {
                Ok(mut active) => {
                    active.retain(|_, entry| entry.strong_count() > 0);
                    active
                        .iter()
                        .filter_map(|(key, entry)| entry.upgrade().map(|s| (key.clone(), s)))
                        .collect()
                }
                Err(_) => return,
            };
            if sessions.is_empty() {
                continue;
            }
            let args: Vec<_> = sessions
                .iter()
                .flat_map(|(key, s)| [key.clone(), s.scope.clone()])
                .collect();
            let result = store.call("check", &args).await;
            for (index, (_, session)) in sessions.iter().enumerate() {
                let valid = result
                    .as_ref()
                    .ok()
                    .filter(|rows| rows.len() == sessions.len())
                    .and_then(|rows| rows[index].parse::<u64>().ok())
                    .is_some_and(|ms| ms > 0 && ms <= 86_400_000);
                if !valid || session.expires <= Instant::now() {
                    session.close();
                }
            }
        }
    }
}
fn deadline(expires: Instant, max: Duration) -> Result<String, Rejection> {
    let remaining = expires.saturating_duration_since(Instant::now()).min(max);
    let expiry = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Rejection::Unavailable)?
        + remaining;
    Ok(expiry.as_millis().to_string())
}
fn lifetime(result: &[String]) -> Result<Option<Duration>, Rejection> {
    // Empty create result means capacity/expiry rejection; get always returns one.
    let Some(value) = result.first() else {
        return Ok(None);
    };
    let millis: u64 = value.parse().map_err(|_| Rejection::Unavailable)?;
    if millis > 86_400_000 {
        return Err(Rejection::Unavailable);
    }
    Ok((millis > 0).then_some(Duration::from_millis(millis)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::visitor_policy::oidc::tests::pending;

    #[tokio::test]
    #[ignore = "requires a disposable Redis server; exercised by the shared OIDC E2E fixture"]
    async fn shared_redis_contract() {
        let url = std::env::var("PIKE_OIDC_REDIS_URL").expect("disposable fixture Redis URL");
        let config = Config {
            redis_url: url,
            namespace: format!("contract-{}", uuid::Uuid::new_v4()),
        };
        let a = Store::new(&config).unwrap();
        let b = Store::new(&config).unwrap();
        let state = a.begin(pending("profile:1", "browser")).await.unwrap();
        assert!(b.consume(&state, "wrong", "profile:1").await.is_err());
        assert!(b.consume(&state, "browser", "profile:2").await.is_err());
        let (one, two) = tokio::join!(
            a.consume(&state, "browser", "profile:1"),
            b.consume(&state, "browser", "profile:1")
        );
        assert_ne!(
            one.is_ok(),
            two.is_ok(),
            "exactly one relay consumes the state"
        );
        assert!(b.consume(&state, "browser", "profile:1").await.is_err());
        let expiry = Instant::now() + Duration::from_secs(300);
        let (token, first) = a.create("profile:1", expiry).await.unwrap();
        let second = b.get(&token, "profile:1").await.unwrap().unwrap();
        let isolated = Store::new(&Config {
            redis_url: config.redis_url.clone(),
            namespace: format!("{}-isolated", config.namespace),
        })
        .unwrap();
        assert!(isolated.get(&token, "profile:1").await.unwrap().is_none());
        assert!(b.get(&token, "profile:2").await.unwrap().is_none());
        b.revoke(&token, "profile:2").await.unwrap();
        assert!(a.get(&token, "profile:1").await.unwrap().is_some());
        let restarted = Store::new(&config).unwrap();
        assert!(restarted.get(&token, "profile:1").await.unwrap().is_some());
        b.revoke(&token, "profile:1").await.unwrap();
        tokio::time::timeout(Duration::from_secs(4), async {
            tokio::join!(first.cancelled(), second.cancelled());
        })
        .await
        .unwrap();
        assert!(restarted.get(&token, "profile:1").await.unwrap().is_none());
        for n in 0..1024 {
            a.begin(pending(&format!("scope:{}", n / 64), "browser"))
                .await
                .unwrap();
            if n == 63 {
                // Assert the policy cap before the global cap can mask it.
                assert!(b.begin(pending("scope:0", "browser")).await.is_err());
            }
        }
        assert!(b.begin(pending("scope:0", "browser")).await.is_err());
        assert!(b.begin(pending("another", "browser")).await.is_err());
        for _ in 0..8192 {
            a.create("profile:1", expiry).await.unwrap();
        }
        assert!(b.create("profile:1", expiry).await.is_err());
        // The raw token never enters Redis: only its SHA-256 lookup key is stored.
        let mut conn = a.pool.get().await.unwrap();
        let keys: Vec<String> = deadpool_redis::redis::cmd("HKEYS")
            .arg(&a.keys[3])
            .query_async(&mut conn)
            .await
            .unwrap();
        assert!(keys.iter().all(|k| k.len() == 43 && k != &token));
        let _: usize = deadpool_redis::redis::cmd("DEL")
            .arg(&a.keys)
            .query_async(&mut conn)
            .await
            .unwrap();
        let short = Instant::now() + Duration::from_millis(150);
        let (token, session) = a.create("profile:1", short).await.unwrap();
        tokio::time::sleep(Duration::from_millis(170)).await;
        assert!(b.get(&token, "profile:1").await.unwrap().is_none());
        tokio::time::timeout(Duration::from_secs(4), session.cancelled())
            .await
            .unwrap();
        // Pruning returns capacity after TTL, including per-policy accounting.
        let mut flow = pending("short", "browser");
        flow.expires = Instant::now() + Duration::from_millis(50);
        let token = a.begin(flow).await.unwrap();
        tokio::time::sleep(Duration::from_millis(75)).await;
        assert!(b.consume(&token, "browser", "short").await.is_err());
        assert!(b.begin(pending("short", "browser")).await.is_ok());
        let _: usize = deadpool_redis::redis::cmd("DEL")
            .arg(&a.keys)
            .query_async(&mut conn)
            .await
            .unwrap();
    }
}
