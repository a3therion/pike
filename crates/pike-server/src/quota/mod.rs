//! Finite, shared cloud quota credits. The journal is the source of truth;
//! in-memory clocks only shorten validity, never recreate a remaining balance.
mod store;
#[cfg(test)]
mod tests;

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Weak,
};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dashmap::DashMap;
use futures_util::{stream, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::{watch, Mutex};

use crate::usage_journal::{Observation, UsageJournal};
use store::State;

pub const QUOTA_PROTOCOL: u8 = 1;
const CREDIT_BYTES: u64 = 4 * 1024 * 1024;
const CREDIT_REQUESTS: u64 = 16;
const IDLE_RETURN: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct QuotaContext {
    pub user_id: String,
    pub tunnel_id: String,
    pub lease_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Reservation {
    id: String,
    user_id: String,
    relay_id: String,
    tunnel_id: String,
    lease_id: String,
    minimum_bytes: u64,
    minimum_requests: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Grant {
    #[serde(flatten)]
    request: Reservation,
    expires_at: i64,
    month_start: String,
    day_start: String,
    bytes: u64,
    requests: u64,
    closed_at: Option<i64>,
    unused_bytes: Option<u64>,
    unused_requests: Option<u64>,
}

#[derive(Deserialize)]
struct Reply {
    quota_protocol: u8,
    server_time_ms: i64,
    grant: Grant,
}

#[derive(Clone)]
struct CreditClock {
    id: String,
    expires: Instant,
    received: Instant,
    server_time_ms: i64,
    last_used: Instant,
}

impl CreditClock {
    fn valid(&self) -> bool {
        Instant::now() < self.expires
    }
    fn timestamp(&self) -> u64 {
        // Use the authoritative period clock, independent of local wall-clock
        // adjustments. Expiry subtracts the entire request RTT conservatively.
        (self
            .server_time_ms
            .saturating_add(self.received.elapsed().as_millis() as i64)
            .max(0)
            / 1000) as u64
    }
}

#[derive(Debug, thiserror::Error)]
#[error("account traffic quota exhausted")]
pub struct QuotaExceeded {
    pub retry_after: u64,
}

pub struct QuotaManager {
    journal: Arc<UsageJournal>,
    relay_id: String,
    client: reqwest::Client,
    url: String,
    token: String,
    locks: DashMap<String, Weak<Mutex<()>>>,
    clocks: DashMap<String, CreditClock>,
    closing: AtomicBool,
}

impl QuotaManager {
    pub async fn new(journal: Arc<UsageJournal>, url: String, token: String) -> Result<Self> {
        anyhow::ensure!(
            !url.is_empty() && !token.is_empty(),
            "cloud quota destination and token required"
        );
        let relay_id = journal.relay_identity().await?;
        Ok(Self {
            journal,
            relay_id,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            url: url.trim_end_matches('/').into(),
            token,
            locks: DashMap::new(),
            clocks: DashMap::new(),
            closing: AtomicBool::new(false),
        })
    }

    fn account_lock(&self, user: &str) -> Arc<Mutex<()>> {
        if self.locks.len() > 1024 {
            self.locks.retain(|_, lock| lock.strong_count() > 0);
        }
        let mut entry = self.locks.entry(user.into()).or_default();
        if let Some(lock) = entry.upgrade() {
            return lock;
        }
        let lock = Arc::new(Mutex::new(()));
        *entry = Arc::downgrade(&lock);
        lock
    }

    pub async fn observe(
        &self,
        context: &QuotaContext,
        incoming: u64,
        outgoing: u64,
        requests: u64,
    ) -> Result<()> {
        let length = incoming
            .checked_add(outgoing)
            .context("quota observation overflow")?;
        anyhow::ensure!(
            length <= CREDIT_BYTES && requests <= 1,
            "quota observation must be a bounded chunk or admission"
        );
        for id in [&context.user_id, &context.tunnel_id, &context.lease_id] {
            uuid::Uuid::parse_str(id)?;
        }
        let lock = self.account_lock(&context.user_id);
        let _guard = lock.lock().await;
        // Finite state transitions: create, reserve, possibly seal/refund an old
        // grant, then consume. An outage fails this observation, never bypasses it.
        for _ in 0..8 {
            anyhow::ensure!(
                !self.closing.load(Ordering::Acquire),
                "quota manager is shutting down"
            );
            match self.journal.quota_state(context.user_id.clone()).await? {
                None => {
                    self.journal
                        .quota_pending(Reservation {
                            id: uuid::Uuid::new_v4().to_string(),
                            user_id: context.user_id.clone(),
                            relay_id: self.relay_id.clone(),
                            tunnel_id: context.tunnel_id.clone(),
                            lease_id: context.lease_id.clone(),
                            minimum_bytes: length.max(1),
                            minimum_requests: requests,
                        })
                        .await?;
                }
                Some(State::Pending(request)) => self.resolve_pending(request).await?,
                Some(State::Sealed {
                    grant,
                    bytes,
                    requests,
                }) => self.return_credit(grant, bytes, requests).await?,
                Some(State::Active {
                    grant,
                    bytes,
                    requests: remaining,
                }) => {
                    let clock = self.clocks.get(&context.user_id).map(|clock| clock.clone());
                    if let Some(clock) = clock.filter(|clock| {
                        clock.id == grant.request.id
                            && clock.valid()
                            && bytes >= length.max(u64::from(requests > 0))
                            && remaining >= requests
                    }) {
                        let observation = Observation {
                            tunnel_id: context.tunnel_id.clone(),
                            user_id: context.user_id.clone(),
                            bytes_in: incoming,
                            bytes_out: outgoing,
                            request_count: requests,
                            timestamp: 0,
                            quota_accounted: true,
                        };
                        if self
                            .journal
                            .quota_consume(grant.request.id, clock, observation)
                            .await?
                        {
                            if let Some(mut clock) = self.clocks.get_mut(&context.user_id) {
                                clock.last_used = Instant::now();
                            }
                            return Ok(());
                        }
                    }
                    self.journal.quota_seal(context.user_id.clone()).await?;
                    self.clocks.remove(&context.user_id);
                }
            }
        }
        anyhow::bail!("quota state changed repeatedly; retry observation")
    }

    async fn post(
        &self,
        path: &str,
        body: serde_json::Value,
    ) -> Result<(reqwest::StatusCode, serde_json::Value)> {
        let mut response = self
            .client
            .post(format!("{}/api/v1/quotas/internal/{path}", self.url))
            .bearer_auth(&self.token)
            .json(&body)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(
                bytes.len() + chunk.len() <= 8192,
                "oversized quota response"
            );
            bytes.extend_from_slice(&chunk);
        }
        Ok((status, serde_json::from_slice(&bytes)?))
    }

    async fn resolve_pending(&self, request: Reservation) -> Result<()> {
        let sent = Instant::now();
        let mut payload = serde_json::to_value(&request)?;
        payload["quota_protocol"] = QUOTA_PROTOCOL.into();
        let (status, value) = self.post("reserve", payload).await?;
        if !status.is_success() {
            // Only a known, terminal ledger rejection can discard the durable
            // request ID. Ambiguous storage/network failures retain it for retry.
            if value["quota_protocol"].as_u64() == Some(u64::from(QUOTA_PROTOCOL))
                && matches!(status.as_u16(), 400 | 404 | 409 | 429)
            {
                self.journal
                    .quota_forget(request.user_id.clone(), request.id)
                    .await?;
                if status.as_u16() == 429 {
                    let retry = value["retry_at"]
                        .as_i64()
                        .unwrap_or(0)
                        .saturating_sub(value["server_time_ms"].as_i64().unwrap_or(0));
                    return Err(QuotaExceeded {
                        retry_after: ((retry.max(1000) as u64).div_ceil(1000)).min(32 * 86400),
                    }
                    .into());
                }
            }
            anyhow::bail!("quota reservation unavailable: {status}");
        }
        let reply: Reply = serde_json::from_value(value)?;
        anyhow::ensure!(
            reply.quota_protocol == QUOTA_PROTOCOL && reply.grant.request == request,
            "quota acknowledgement identity mismatch"
        );
        let grant = reply.grant;
        anyhow::ensure!(
            grant.bytes <= CREDIT_BYTES
                && grant.requests <= CREDIT_REQUESTS
                && grant.bytes >= request.minimum_bytes
                && grant.requests >= request.minimum_requests,
            "invalid quota grant counters"
        );
        if grant.closed_at.is_some() {
            self.journal
                .quota_forget(request.user_id, request.id)
                .await?;
            return Ok(());
        }
        anyhow::ensure!(
            grant.unused_bytes.is_none() && grant.unused_requests.is_none(),
            "unsealed grant has refund counters"
        );
        let lifetime = grant
            .expires_at
            .saturating_sub(reply.server_time_ms)
            .clamp(0, 60_000) as u64;
        let day = chrono::DateTime::parse_from_rfc3339(&grant.day_start)?.timestamp_millis();
        let month = chrono::DateTime::parse_from_rfc3339(&grant.month_start)?.timestamp_millis();
        anyhow::ensure!(
            reply.server_time_ms >= month
                && reply.server_time_ms >= day
                && grant.expires_at <= day + 86_400_000,
            "invalid quota grant period"
        );
        if self.journal.quota_accept(grant.clone()).await? {
            let received = Instant::now();
            self.clocks.insert(
                request.user_id,
                CreditClock {
                    id: grant.request.id,
                    expires: sent + Duration::from_millis(lifetime),
                    received,
                    server_time_ms: reply.server_time_ms,
                    last_used: received,
                },
            );
        }
        Ok(())
    }

    async fn return_credit(&self, grant: Grant, bytes: u64, requests: u64) -> Result<()> {
        let (status, value) = self.post("release", serde_json::json!({
            "quota_protocol": QUOTA_PROTOCOL, "id":grant.request.id, "user_id":grant.request.user_id,
            "relay_id":grant.request.relay_id, "unused_bytes":bytes, "unused_requests":requests,
        })).await?;
        if status.as_u16() == 404
            && value["quota_protocol"].as_u64() == Some(u64::from(QUOTA_PROTOCOL))
        {
            // Account erasure removes the authoritative grant. No credit can be
            // spent or refunded there; discard only our already sealed state.
            self.journal
                .quota_forget(grant.request.user_id.clone(), grant.request.id)
                .await?;
            self.clocks.remove(&grant.request.user_id);
            return Ok(());
        }
        anyhow::ensure!(status.is_success(), "quota return unavailable: {status}");
        let reply: Reply = serde_json::from_value(value)?;
        anyhow::ensure!(
            reply.quota_protocol == QUOTA_PROTOCOL
                && reply.grant.request == grant.request
                && reply.grant.closed_at.is_some()
                && reply.grant.unused_bytes == Some(bytes)
                && reply.grant.unused_requests == Some(requests),
            "quota return acknowledgement mismatch"
        );
        self.journal
            .quota_forget(grant.request.user_id.clone(), grant.request.id)
            .await?;
        self.clocks.remove(&grant.request.user_id);
        Ok(())
    }

    async fn settle(&self, user: String, force: bool) -> Result<()> {
        let lock = self.account_lock(&user);
        let _guard = tokio::time::timeout(Duration::from_secs(1), lock.lock()).await?;
        if !force
            && self
                .clocks
                .get(&user)
                .is_some_and(|clock| clock.valid() && clock.last_used.elapsed() < IDLE_RETURN)
        {
            return Ok(());
        }
        if let Some(State::Pending(request)) = self.journal.quota_state(user.clone()).await? {
            self.resolve_pending(request).await?;
        }
        self.journal.quota_seal(user.clone()).await?;
        self.clocks.remove(&user);
        if let Some(State::Sealed {
            grant,
            bytes,
            requests,
        }) = self.journal.quota_state(user).await?
        {
            self.return_credit(grant, bytes, requests).await?;
        }
        Ok(())
    }

    pub async fn maintain(&self, force: bool) -> Result<()> {
        let users = self.journal.quota_users().await?;
        stream::iter(users)
            .for_each_concurrent(8, |user| async move {
                if let Err(error) = self.settle(user, force).await {
                    tracing::warn!(%error, "quota recovery remains durably pending");
                }
            })
            .await;
        Ok(())
    }

    pub fn spawn_maintenance(
        self: &Arc<Self>,
        mut shutdown: watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let this = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = interval.tick() => { let _ = this.maintain(false).await; },
                    changed = shutdown.changed() => if changed.is_err() || *shutdown.borrow() {
                        this.closing.store(true, Ordering::Release);
                        let _ = this.maintain(true).await; break;
                    }
                }
            }
        })
    }
}

pub fn error_response(error: &anyhow::Error) -> axum::http::Response<axum::body::Body> {
    use axum::{body::Body, http::Response};
    if let Some(exceeded) = error.downcast_ref::<QuotaExceeded>() {
        Response::builder()
            .status(429)
            .header("retry-after", exceeded.retry_after.to_string())
            .body(Body::from("account traffic quota exhausted"))
            .expect("valid quota response")
    } else {
        tracing::warn!(%error, "traffic accounting unavailable");
        Response::builder()
            .status(503)
            .body(Body::from("traffic accounting unavailable"))
            .expect("valid accounting response")
    }
}
