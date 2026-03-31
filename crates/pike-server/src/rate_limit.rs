use std::future::Future;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use dashmap::DashMap;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter as Governor};
use pike_core::types::TunnelId;
use tokio::runtime::{Handle, RuntimeFlavor};

use crate::state_store::StateStore;

pub type UserId = String;
type DirectRateLimiter = DefaultDirectRateLimiter;

pub const FREE_TIER_BANDWIDTH_BYTES_PER_MONTH: u64 = 10 * 1024 * 1024 * 1024;
pub const PRO_TIER_BANDWIDTH_BYTES_PER_MONTH: u64 = 100 * 1024 * 1024 * 1024;
pub const FREE_TIER_MAX_TUNNELS: u32 = 1;
pub const PRO_TIER_MAX_TUNNELS: u32 = 20;
pub const FREE_TIER_MAX_REQUESTS_PER_TUNNEL_PER_MINUTE: u32 = 100;
const FREE_TIER_USER_REQUESTS_PER_MINUTE: u32 = 500;
const PRO_TIER_USER_REQUESTS_PER_MINUTE: u32 = 2_000;
const ENTERPRISE_USER_REQUESTS_PER_MINUTE: u32 = 10_000;
const SELF_HOSTED_USER_REQUESTS_PER_MINUTE: u32 = 10_000;
const PRO_TIER_MAX_REQUESTS_PER_TUNNEL_PER_MINUTE: u32 = 1_000;
const ENTERPRISE_MAX_REQUESTS_PER_TUNNEL_PER_MINUTE: u32 = 10_000;
const SELF_HOSTED_MAX_REQUESTS_PER_TUNNEL_PER_MINUTE: u32 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubscriptionPlan {
    Free,
    Pro,
    Enterprise,
    SelfHosted,
}

impl SubscriptionPlan {
    fn from_name(name: Option<&str>) -> Self {
        let Some(name) = name else {
            return Self::Free;
        };

        match name.trim().to_ascii_lowercase().as_str() {
            "pro" => Self::Pro,
            "enterprise" => Self::Enterprise,
            "self-hosted" | "self_hosted" | "selfhosted" => Self::SelfHosted,
            _ => Self::Free,
        }
    }

    const fn limits(self) -> PlanLimits {
        match self {
            Self::Free => PlanLimits {
                bandwidth_bytes_per_month: Some(FREE_TIER_BANDWIDTH_BYTES_PER_MONTH),
                max_tunnels: Some(FREE_TIER_MAX_TUNNELS),
                user_requests_per_minute: FREE_TIER_USER_REQUESTS_PER_MINUTE,
                tunnel_requests_per_minute: FREE_TIER_MAX_REQUESTS_PER_TUNNEL_PER_MINUTE,
            },
            Self::Pro => PlanLimits {
                bandwidth_bytes_per_month: Some(PRO_TIER_BANDWIDTH_BYTES_PER_MONTH),
                max_tunnels: Some(PRO_TIER_MAX_TUNNELS),
                user_requests_per_minute: PRO_TIER_USER_REQUESTS_PER_MINUTE,
                tunnel_requests_per_minute: PRO_TIER_MAX_REQUESTS_PER_TUNNEL_PER_MINUTE,
            },
            Self::Enterprise => PlanLimits {
                bandwidth_bytes_per_month: None,
                max_tunnels: None,
                user_requests_per_minute: ENTERPRISE_USER_REQUESTS_PER_MINUTE,
                tunnel_requests_per_minute: ENTERPRISE_MAX_REQUESTS_PER_TUNNEL_PER_MINUTE,
            },
            Self::SelfHosted => PlanLimits {
                bandwidth_bytes_per_month: None,
                max_tunnels: None,
                user_requests_per_minute: SELF_HOSTED_USER_REQUESTS_PER_MINUTE,
                tunnel_requests_per_minute: SELF_HOSTED_MAX_REQUESTS_PER_TUNNEL_PER_MINUTE,
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PlanLimits {
    bandwidth_bytes_per_month: Option<u64>,
    max_tunnels: Option<u32>,
    user_requests_per_minute: u32,
    tunnel_requests_per_minute: u32,
}

struct PlannedRateLimiter {
    plan: SubscriptionPlan,
    limiter: DirectRateLimiter,
}

impl PlannedRateLimiter {
    fn new(plan: SubscriptionPlan) -> Self {
        Self {
            plan,
            limiter: RateLimiter::new_direct_limiter(plan.limits().user_requests_per_minute),
        }
    }
}

impl std::fmt::Debug for PlannedRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlannedRateLimiter")
            .field("plan", &self.plan)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone)]
pub struct RateLimitHeaders {
    pub limit: u32,
    pub remaining: u32,
    pub reset_unix_seconds: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("user request rate exceeded")]
    UserRequestRateExceeded,
    #[error("tunnel request rate exceeded")]
    TunnelRequestRateExceeded,
    #[error("free tier bandwidth limit exceeded")]
    BandwidthLimitExceeded,
    #[error("free tier tunnel limit exceeded")]
    TunnelLimitExceeded,
}

#[derive(Debug, Clone)]
struct UserUsage {
    month_epoch: u64,
    bandwidth_bytes: u64,
    active_tunnels: u32,
}

#[derive(Debug, Clone)]
struct TunnelWindow {
    window_started_at: Instant,
    window_started_unix_secs: u64,
    requests_in_window: u32,
}

pub struct RateLimiter {
    limits: DashMap<UserId, PlannedRateLimiter>,
    tunnel_limits: DashMap<TunnelId, DirectRateLimiter>,
    user_usage: DashMap<UserId, UserUsage>,
    tunnel_windows: DashMap<TunnelId, TunnelWindow>,
    tunnel_owners: DashMap<TunnelId, UserId>,
    user_plans: DashMap<UserId, SubscriptionPlan>,
    tunnel_plans: DashMap<TunnelId, SubscriptionPlan>,
    state_store: Option<Arc<dyn StateStore>>,
}

impl std::fmt::Debug for RateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimiter")
            .field("limits", &self.limits)
            .field("tunnel_limits", &self.tunnel_limits)
            .field("user_usage", &self.user_usage)
            .field("tunnel_windows", &self.tunnel_windows)
            .field("tunnel_owners", &self.tunnel_owners)
            .field("user_plans", &self.user_plans)
            .field("tunnel_plans", &self.tunnel_plans)
            .field("state_store_configured", &self.state_store.is_some())
            .finish()
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    #[must_use]
    pub fn new() -> Self {
        Self::from_store(None)
    }

    #[must_use]
    pub fn with_store(store: Arc<dyn StateStore>) -> Self {
        Self::from_store(Some(store))
    }

    fn from_store(state_store: Option<Arc<dyn StateStore>>) -> Self {
        Self {
            limits: DashMap::new(),
            tunnel_limits: DashMap::new(),
            user_usage: DashMap::new(),
            tunnel_windows: DashMap::new(),
            tunnel_owners: DashMap::new(),
            user_plans: DashMap::new(),
            tunnel_plans: DashMap::new(),
            state_store,
        }
    }

    pub fn check_limit(&self, user_id: UserId) -> Result<(), RateLimitError> {
        self.ensure_user_quota(&user_id)?;

        let plan = self
            .user_plans
            .get(&user_id)
            .map(|entry| *entry)
            .unwrap_or(SubscriptionPlan::Free);
        let mut limiter = self
            .limits
            .entry(user_id)
            .or_insert_with(|| PlannedRateLimiter::new(plan));
        if limiter.plan != plan {
            *limiter = PlannedRateLimiter::new(plan);
        }
        if limiter.limiter.check().is_err() {
            return Err(RateLimitError::UserRequestRateExceeded);
        }

        Ok(())
    }

    pub fn check_tunnel_limit(
        &self,
        tunnel_id: TunnelId,
    ) -> Result<RateLimitHeaders, RateLimitError> {
        let plan = self
            .tunnel_plans
            .get(&tunnel_id)
            .map(|entry| *entry)
            .unwrap_or(SubscriptionPlan::Free);
        let per_minute = plan.limits().tunnel_requests_per_minute;
        let limiter = self
            .tunnel_limits
            .entry(tunnel_id)
            .or_insert_with(|| Self::new_direct_limiter(per_minute));
        if limiter.check().is_err() {
            return Err(RateLimitError::TunnelRequestRateExceeded);
        }

        let now_unix = now_unix_secs();
        let mut window = self
            .tunnel_windows
            .entry(tunnel_id)
            .or_insert_with(|| TunnelWindow {
                window_started_at: Instant::now(),
                window_started_unix_secs: now_unix,
                requests_in_window: 0,
            });

        if window.window_started_at.elapsed() >= Duration::from_secs(60) {
            window.window_started_at = Instant::now();
            window.window_started_unix_secs = now_unix;
            window.requests_in_window = 0;
        }

        window.requests_in_window = window.requests_in_window.saturating_add(1);
        let consumed = window.requests_in_window.min(per_minute);
        let remaining = per_minute - consumed;

        Ok(RateLimitHeaders {
            limit: per_minute,
            remaining,
            reset_unix_seconds: window.window_started_unix_secs + 60,
        })
    }

    pub fn register_tunnel(
        &self,
        user_id: UserId,
        tunnel_id: TunnelId,
        plan_name: Option<&str>,
    ) -> Result<(), RateLimitError> {
        let month = month_epoch();
        let plan = SubscriptionPlan::from_name(plan_name);
        let plan_limits = plan.limits();
        self.user_plans.insert(user_id.clone(), plan);
        let mut usage = self
            .user_usage
            .entry(user_id.clone())
            .or_insert_with(|| UserUsage {
                month_epoch: month,
                bandwidth_bytes: 0,
                active_tunnels: 0,
            });

        if usage.month_epoch != month {
            usage.month_epoch = month;
            usage.bandwidth_bytes = 0;
            usage.active_tunnels = 0;
        }

        if let Some(max_tunnels) = plan_limits.max_tunnels {
            if usage.active_tunnels >= max_tunnels {
                return Err(RateLimitError::TunnelLimitExceeded);
            }
        }

        usage.active_tunnels = usage.active_tunnels.saturating_add(1);
        self.tunnel_owners.insert(tunnel_id, user_id);
        self.tunnel_plans.insert(tunnel_id, plan);
        self.tunnel_limits.insert(
            tunnel_id,
            Self::new_direct_limiter(plan_limits.tunnel_requests_per_minute),
        );

        Ok(())
    }

    pub fn unregister_tunnel(&self, tunnel_id: TunnelId) {
        if let Some((_, user_id)) = self.tunnel_owners.remove(&tunnel_id) {
            if let Some(mut usage) = self.user_usage.get_mut(&user_id) {
                usage.active_tunnels = usage.active_tunnels.saturating_sub(1);
            }
        }

        self.tunnel_plans.remove(&tunnel_id);
        self.tunnel_limits.remove(&tunnel_id);
        self.tunnel_windows.remove(&tunnel_id);
    }

    pub fn track_bandwidth(&self, tunnel_id: TunnelId, bytes: u64) {
        let Some(owner) = self
            .tunnel_owners
            .get(&tunnel_id)
            .map(|entry| entry.clone())
        else {
            return;
        };

        let month = month_epoch();
        let mut usage = self
            .user_usage
            .entry(owner.clone())
            .or_insert_with(|| UserUsage {
                month_epoch: month,
                bandwidth_bytes: 0,
                active_tunnels: 0,
            });

        if usage.month_epoch != month {
            usage.month_epoch = month;
            usage.bandwidth_bytes = 0;
        }

        usage.bandwidth_bytes = usage.bandwidth_bytes.saturating_add(bytes);

        if self.state_store.is_some() {
            let bandwidth_key = Self::bandwidth_key(&owner, month);
            let _ = self.call_store_result(async {
                let Some(store) = &self.state_store else {
                    return Ok(0);
                };
                store.add_bandwidth(&bandwidth_key, bytes).await
            });
        }
    }

    fn ensure_user_quota(&self, user_id: &UserId) -> Result<(), RateLimitError> {
        let month = month_epoch();
        let plan = self
            .user_plans
            .get(user_id)
            .map(|entry| *entry)
            .unwrap_or(SubscriptionPlan::Free);
        let plan_limits = plan.limits();
        let mut fallback_bandwidth = 0;
        if let Some(mut usage) = self.user_usage.get_mut(user_id) {
            if usage.month_epoch != month {
                usage.month_epoch = month;
                usage.bandwidth_bytes = 0;
                usage.active_tunnels = 0;
            }

            fallback_bandwidth = usage.bandwidth_bytes;

            if let Some(store_bandwidth) = self.read_store_bandwidth(user_id, month) {
                usage.bandwidth_bytes = store_bandwidth;
            }
        }

        let bandwidth_bytes = self
            .read_store_bandwidth(user_id, month)
            .unwrap_or(fallback_bandwidth);
        if let Some(max_bandwidth) = plan_limits.bandwidth_bytes_per_month {
            if bandwidth_bytes > max_bandwidth {
                return Err(RateLimitError::BandwidthLimitExceeded);
            }
        }

        Ok(())
    }

    fn bandwidth_key(user_id: &str, month_epoch: u64) -> String {
        format!("bw:{user_id}:{month_epoch}")
    }

    fn read_store_bandwidth(&self, user_id: &UserId, month_epoch: u64) -> Option<u64> {
        self.state_store.as_ref()?;

        let key = Self::bandwidth_key(user_id, month_epoch);
        self.call_store_result(async move {
            let Some(store) = &self.state_store else {
                return Ok(0);
            };
            store.get_bandwidth(&key).await
        })
        .ok()
    }

    fn call_store_result<F, T>(&self, future: F) -> anyhow::Result<T>
    where
        F: Future<Output = anyhow::Result<T>>,
    {
        if let Ok(handle) = Handle::try_current() {
            if matches!(handle.runtime_flavor(), RuntimeFlavor::MultiThread) {
                tokio::task::block_in_place(|| handle.block_on(future))
            } else {
                Err(anyhow::anyhow!(
                    "cannot bridge StateStore calls on current-thread runtime"
                ))
            }
        } else {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            runtime.block_on(future)
        }
    }

    fn new_direct_limiter(per_minute: u32) -> DefaultDirectRateLimiter {
        Governor::direct(Quota::per_minute(
            NonZeroU32::new(per_minute).expect("per-minute quota must be non-zero"),
        ))
    }
}

#[must_use]
pub fn exceeded_headers() -> RateLimitHeaders {
    RateLimitHeaders {
        limit: FREE_TIER_MAX_REQUESTS_PER_TUNNEL_PER_MINUTE,
        remaining: 0,
        reset_unix_seconds: now_unix_secs() + 60,
    }
}

#[must_use]
pub fn shared_limiter() -> Arc<RateLimiter> {
    Arc::new(RateLimiter::new())
}

// ── Per-IP rate limiter ──────────────────────────────────────────────────────

const IP_LIMITER_MAX_ENTRIES: usize = 10_000;

/// Token-bucket rate limiter keyed by client IP address.
///
/// Applied at the outermost HTTP layer so every request is accounted for
/// regardless of whether it hits the platform API or a tunnel proxy.
#[derive(Debug, Clone)]
pub struct IpRateLimiter {
    limiters: Arc<DashMap<IpAddr, Arc<DefaultDirectRateLimiter>>>,
    per_minute: u32,
}

impl IpRateLimiter {
    #[must_use]
    pub fn new(per_minute: u32) -> Self {
        Self {
            limiters: Arc::new(DashMap::new()),
            per_minute,
        }
    }

    /// Returns `true` if the request from `ip` is within the rate limit.
    pub fn check(&self, ip: IpAddr) -> bool {
        // Evict when at capacity to prevent unbounded growth.
        if self.limiters.len() >= IP_LIMITER_MAX_ENTRIES {
            // Remove up to 1000 arbitrary entries.
            let keys: Vec<_> = self
                .limiters
                .iter()
                .take(1000)
                .map(|r: dashmap::mapref::multiple::RefMulti<IpAddr, _>| *r.key())
                .collect();
            for k in keys {
                self.limiters.remove(&k);
            }
        }

        let limiter = self
            .limiters
            .entry(ip)
            .or_insert_with(|| Arc::new(Self::make_limiter(self.per_minute)))
            .clone();

        limiter.check().is_ok()
    }

    fn make_limiter(per_minute: u32) -> DefaultDirectRateLimiter {
        Governor::direct(Quota::per_minute(
            NonZeroU32::new(per_minute).expect("per-minute quota must be non-zero"),
        ))
    }
}

// Tower middleware that enforces `IpRateLimiter` on every request.
pub mod ip_rate_limit {
    use std::future::Future;
    use std::net::{IpAddr, SocketAddr};
    use std::pin::Pin;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use axum::body::Body;
    use axum::extract::ConnectInfo;
    use axum::http::{HeaderValue, Request, Response, StatusCode};
    use tower::{Layer, Service};

    use super::IpRateLimiter;

    #[derive(Debug, Clone)]
    pub struct IpRateLimitLayer {
        limiter: Arc<IpRateLimiter>,
    }

    impl IpRateLimitLayer {
        pub fn new(limiter: IpRateLimiter) -> Self {
            Self {
                limiter: Arc::new(limiter),
            }
        }
    }

    impl<S> Layer<S> for IpRateLimitLayer {
        type Service = IpRateLimitMiddleware<S>;

        fn layer(&self, inner: S) -> Self::Service {
            IpRateLimitMiddleware {
                inner,
                limiter: self.limiter.clone(),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct IpRateLimitMiddleware<S> {
        inner: S,
        limiter: Arc<IpRateLimiter>,
    }

    impl<S> Service<Request<Body>> for IpRateLimitMiddleware<S>
    where
        S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
        S::Future: Send + 'static,
    {
        type Response = Response<Body>;
        type Error = S::Error;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

        fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(cx)
        }

        fn call(&mut self, req: Request<Body>) -> Self::Future {
            let ip = extract_ip(&req);
            if !self.limiter.check(ip) {
                crate::metrics::RATE_LIMIT_REJECTIONS.inc();
                let mut resp = Response::new(Body::from("rate limit exceeded"));
                *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                resp.headers_mut()
                    .insert("Retry-After", HeaderValue::from_static("60"));
                return Box::pin(async move { Ok(resp) });
            }
            let fut = self.inner.call(req);
            Box::pin(fut)
        }
    }

    fn extract_ip(req: &Request<Body>) -> IpAddr {
        // Prefer X-Forwarded-For from a reverse proxy and take the first entry.
        if let Some(xff) = req.headers().get("x-forwarded-for") {
            if let Ok(v) = xff.to_str() {
                if let Some(first) = v.split(',').next() {
                    if let Ok(ip) = first.trim().parse::<IpAddr>() {
                        return ip;
                    }
                }
            }
        }

        // Fall back to the socket address injected by Axum's ConnectInfo extension.
        req.extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
            .unwrap_or(IpAddr::from([127, 0, 0, 1]))
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn month_epoch() -> u64 {
    now_unix_secs() / (30 * 24 * 60 * 60)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{
        RateLimitError, RateLimiter, FREE_TIER_BANDWIDTH_BYTES_PER_MONTH,
        FREE_TIER_MAX_REQUESTS_PER_TUNNEL_PER_MINUTE, PRO_TIER_BANDWIDTH_BYTES_PER_MONTH,
    };
    use pike_core::types::TunnelId;

    use crate::state_store::{FallbackStateStore, InMemoryStateStore, RedisStateStore, StateStore};

    #[test]
    fn allows_tunnel_requests_within_window_limit() {
        let limiter = RateLimiter::new();
        let tunnel_id = TunnelId::new();
        limiter
            .register_tunnel("user-a".to_string(), tunnel_id, None)
            .expect("register tunnel");

        for _ in 0..FREE_TIER_MAX_REQUESTS_PER_TUNNEL_PER_MINUTE {
            limiter
                .check_tunnel_limit(tunnel_id)
                .expect("request should pass");
        }

        let exceeded = limiter.check_tunnel_limit(tunnel_id);
        assert!(matches!(
            exceeded,
            Err(RateLimitError::TunnelRequestRateExceeded)
        ));
    }

    #[test]
    fn enforces_max_tunnels_per_user() {
        let limiter = RateLimiter::new();
        for _ in 0..super::FREE_TIER_MAX_TUNNELS {
            limiter
                .register_tunnel("user-b".to_string(), TunnelId::new(), None)
                .expect("within free tier tunnel cap");
        }

        let overflow = limiter.register_tunnel("user-b".to_string(), TunnelId::new(), None);
        assert!(matches!(overflow, Err(RateLimitError::TunnelLimitExceeded)));
    }

    #[test]
    fn enforces_monthly_bandwidth_quota() {
        let limiter = RateLimiter::new();
        let tunnel_id = TunnelId::new();
        let user_id = "user-c".to_string();
        limiter
            .register_tunnel(user_id.clone(), tunnel_id, None)
            .expect("register tunnel");

        limiter.track_bandwidth(tunnel_id, FREE_TIER_BANDWIDTH_BYTES_PER_MONTH + 1);
        let result = limiter.check_limit(user_id);
        assert!(matches!(
            result,
            Err(RateLimitError::BandwidthLimitExceeded)
        ));
    }

    #[test]
    fn ip_rate_limiter_allows_requests_under_limit() {
        use std::net::IpAddr;
        let limiter = super::IpRateLimiter::new(100);
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..10 {
            assert!(limiter.check(ip), "request under limit should pass");
        }
    }

    #[test]
    fn ip_rate_limiter_blocks_over_limit() {
        use std::net::IpAddr;
        let limiter = super::IpRateLimiter::new(1);
        let ip: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(limiter.check(ip), "first request should pass");
        assert!(
            !limiter.check(ip),
            "second request should be blocked at limit=1/min"
        );
    }

    #[test]
    fn test_rate_limit_persists_across_store_reinit() {
        let store = Arc::new(InMemoryStateStore::new()) as Arc<dyn StateStore>;
        let tunnel_id = TunnelId::new();
        let user_id = "persist-user".to_string();

        let limiter = RateLimiter::with_store(store.clone());
        limiter
            .register_tunnel(user_id.clone(), tunnel_id, None)
            .expect("register tunnel");
        limiter.track_bandwidth(tunnel_id, 50);

        let reinit = RateLimiter::with_store(store.clone());
        reinit
            .register_tunnel(user_id.clone(), TunnelId::new(), None)
            .expect("register tunnel from reinitialized limiter");

        let used = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime")
            .block_on(store.get_bandwidth(&RateLimiter::bandwidth_key(
                "persist-user",
                super::month_epoch(),
            )))
            .expect("read persisted bandwidth");
        assert_eq!(used, 50);
    }

    #[test]
    fn test_rate_limit_works_without_redis() {
        let redis = RedisStateStore::new("redis://localhost:9999/").expect("create redis store");
        let fallback = Arc::new(InMemoryStateStore::new());
        let store = Arc::new(FallbackStateStore::new(
            Arc::new(redis) as Arc<dyn StateStore>,
            fallback,
        )) as Arc<dyn StateStore>;

        let limiter = RateLimiter::with_store(store);
        let tunnel_id = TunnelId::new();
        limiter
            .register_tunnel("fallback-user".to_string(), tunnel_id, None)
            .expect("register tunnel with fallback store");
        limiter.track_bandwidth(tunnel_id, FREE_TIER_BANDWIDTH_BYTES_PER_MONTH + 1);

        let limited = limiter.check_limit("fallback-user".to_string());
        assert!(matches!(
            limited,
            Err(RateLimitError::BandwidthLimitExceeded)
        ));
    }

    #[test]
    fn pro_plan_allows_control_plane_tunnel_count_and_bandwidth() {
        let limiter = RateLimiter::new();
        let user_id = "pro-user".to_string();

        for _ in 0..super::PRO_TIER_MAX_TUNNELS {
            limiter
                .register_tunnel(user_id.clone(), TunnelId::new(), Some("pro"))
                .expect("within pro tunnel cap");
        }

        let overflow = limiter.register_tunnel(user_id.clone(), TunnelId::new(), Some("pro"));
        assert!(matches!(overflow, Err(RateLimitError::TunnelLimitExceeded)));

        let tunnel_id = TunnelId::new();
        let limiter = RateLimiter::new();
        limiter
            .register_tunnel(user_id.clone(), tunnel_id, Some("pro"))
            .expect("register pro tunnel");
        limiter.track_bandwidth(tunnel_id, PRO_TIER_BANDWIDTH_BYTES_PER_MONTH);
        assert!(limiter.check_limit(user_id.clone()).is_ok());
        limiter.track_bandwidth(tunnel_id, 1);
        assert!(matches!(
            limiter.check_limit(user_id),
            Err(RateLimitError::BandwidthLimitExceeded)
        ));
    }

    #[test]
    fn self_hosted_plan_skips_hosted_quota_caps() {
        let limiter = RateLimiter::new();
        let user_id = "self-hosted-user".to_string();
        let tunnel_id = TunnelId::new();
        limiter
            .register_tunnel(user_id.clone(), tunnel_id, Some("self-hosted"))
            .expect("self-hosted tunnel should register");
        limiter.track_bandwidth(tunnel_id, FREE_TIER_BANDWIDTH_BYTES_PER_MONTH + 1);
        assert!(limiter.check_limit(user_id).is_ok());
    }
}
