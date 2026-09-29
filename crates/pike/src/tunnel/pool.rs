//! A bounded origin set. Selection retries only before application bytes are sent.
use super::origin::{Origin, OriginIo, OriginOptions, OriginProtocol};
use anyhow::{ensure, Context, Result};
use axum::{
    body::Body,
    http::{Request, Uri},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    task::JoinSet,
    time::{interval, timeout, MissedTickBehavior},
};

const MAX_ORIGINS: usize = 16;
const CONNECT_BUDGET: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, clap::Args)]
pub struct PoolOptions {
    /// Optional HTTP HEAD health path; 2xx is healthy. Default probes connectivity/TLS.
    #[arg(long)]
    pub health_path: Option<String>,
    /// Active health-check interval, in seconds.
    #[arg(long, default_value_t=5, value_parser=clap::value_parser!(u64).range(1..=300))]
    pub health_interval: u64,
    /// Maximum time per health check, in milliseconds.
    #[arg(long, default_value_t=2000, value_parser=clap::value_parser!(u64).range(100..=5000))]
    pub health_timeout_ms: u64,
}
impl Default for PoolOptions {
    fn default() -> Self {
        Self {
            health_path: None,
            health_interval: 5,
            health_timeout_ms: 2000,
        }
    }
}

struct Health {
    healthy: bool,
    checked: bool,
    generation: u64,
    checked_at: Option<tokio::time::Instant>,
}
struct Member {
    origin: Origin,
    health: Mutex<Health>,
}
struct Inner {
    members: Vec<Member>,
    next: AtomicUsize,
    options: PoolOptions,
}
#[derive(Clone)]
pub struct OriginPool(Arc<Inner>);

#[derive(Debug)]
pub struct PoolUnavailable;
impl std::fmt::Display for PoolUnavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no healthy origin is available")
    }
}
impl std::error::Error for PoolUnavailable {}

#[derive(serde::Serialize)]
pub struct OriginStatus {
    pub origin: String,
    pub healthy: bool,
    pub checked: bool,
    pub stale: bool,
}

impl OriginPool {
    pub fn from_options(
        port: Option<u16>,
        host: &str,
        options: OriginOptions,
        health: PoolOptions,
    ) -> Result<Self> {
        ensure!(
            options.upstream.len() <= MAX_ORIGINS,
            "at most {MAX_ORIGINS} origins are allowed"
        );
        let origins = if options.upstream.len() > 1 {
            ensure!(
                port.is_none() && options.unix_socket.is_none(),
                "origin pools cannot be combined with a port or Unix socket"
            );
            options
                .upstream
                .iter()
                .map(|url| {
                    Origin::from_options(
                        None,
                        host,
                        OriginOptions {
                            upstream: vec![url.clone()],
                            ..options.clone()
                        },
                    )
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            vec![Origin::from_options(port, host, options)?]
        };
        Self::new(origins, health)
    }

    fn new(origins: Vec<Origin>, options: PoolOptions) -> Result<Self> {
        ensure!(
            !origins.is_empty() && origins.len() <= MAX_ORIGINS,
            "origin pool must contain 1..={MAX_ORIGINS} members"
        );
        if let Some(path) = &options.health_path {
            let uri: Uri = path.parse().context("invalid origin health path")?;
            ensure!(
                path.starts_with('/')
                    && !path.starts_with("//")
                    && uri.scheme().is_none()
                    && uri.authority().is_none(),
                "health path must be origin-relative"
            );
        }
        ensure!(
            (1..=300).contains(&options.health_interval),
            "health interval must be 1..=300 seconds"
        );
        ensure!(
            (100..=5000).contains(&options.health_timeout_ms),
            "health timeout must be 100..=5000 milliseconds"
        );
        let mut identities = std::collections::HashSet::new();
        for origin in &origins {
            ensure!(
                identities.insert(origin.display()),
                "duplicate origin {}",
                origin.display()
            );
        }
        Ok(Self(Arc::new(Inner {
            members: origins
                .into_iter()
                .map(|origin| Member {
                    origin,
                    health: Mutex::new(Health {
                        healthy: true,
                        checked: false,
                        generation: 0,
                        checked_at: None,
                    }),
                })
                .collect(),
            next: AtomicUsize::new(0),
            options,
        })))
    }

    pub fn display(&self) -> String {
        self.0
            .members
            .iter()
            .map(|entry| entry.origin.display())
            .collect::<Vec<_>>()
            .join(", ")
    }
    pub fn registration_address(&self) -> SocketAddr {
        self.0.members[0].origin.registration_address()
    }
    fn checks_enabled(&self) -> bool {
        self.0.members.len() > 1 || self.0.options.health_path.is_some()
    }
    pub fn health_report(&self) -> pike_core::proto::origin_health::OriginHealthReport {
        use pike_core::proto::origin_health::{OriginHealthReport, OriginObservation};
        OriginHealthReport {
            origins: self
                .0
                .members
                .iter()
                .map(|member| {
                    let health = member
                        .health
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    OriginObservation {
                        healthy: health.checked_at.map(|_| health.healthy),
                        checked_ago_ms: health
                            .checked_at
                            .map(|at| u32::try_from(at.elapsed().as_millis()).unwrap_or(u32::MAX)),
                    }
                })
                .collect(),
        }
    }

    pub fn status(&self) -> Vec<OriginStatus> {
        self.0
            .members
            .iter()
            .map(|member| {
                let health = member
                    .health
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                OriginStatus {
                    origin: member.origin.display(),
                    healthy: health.healthy,
                    checked: health.checked,
                    stale: health.checked_at.is_some_and(|at| {
                        at.elapsed()
                            > Duration::from_secs(self.0.options.health_interval * 2)
                                + Duration::from_millis(self.0.options.health_timeout_ms)
                    }),
                }
            })
            .collect()
    }

    /// The caller owns this future. Dropping the tunnel cancels every probe.
    pub async fn monitor(&self) {
        if !self.checks_enabled() {
            futures::future::pending::<()>().await;
        }
        let mut ticks = interval(Duration::from_secs(self.0.options.health_interval));
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            self.refresh().await;
        }
    }
    pub async fn refresh(&self) {
        if !self.checks_enabled() {
            return;
        }
        futures::future::join_all(self.0.members.iter().map(|member| async {
            let generation = member
                .health
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .generation;
            let healthy = matches!(
                timeout(
                    Duration::from_millis(self.0.options.health_timeout_ms),
                    probe(&member.origin, self.0.options.health_path.as_deref())
                )
                .await,
                Ok(Ok(()))
            );
            let mut state = member
                .health
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // A newer failed request must not be overridden by an older probe.
            if state.generation == generation {
                if !state.checked || state.healthy != healthy {
                    tracing::info!(origin=%member.origin.display(),healthy,"origin health changed");
                }
                state.healthy = healthy;
                state.checked = true;
                state.checked_at = Some(tokio::time::Instant::now());
            }
        }))
        .await;
    }

    /// Return a connected origin; never replay a request after application bytes.
    pub async fn connect(&self, websocket: bool) -> Result<(Origin, OriginIo, OriginProtocol)> {
        if !self.checks_enabled() {
            let origin = self.0.members[0].origin.clone();
            let (io, protocol) = origin.connect(websocket).await?;
            return Ok((origin, io, protocol));
        }
        let start = self.0.next.fetch_add(1, Ordering::Relaxed) % self.0.members.len();
        timeout(CONNECT_BUDGET, async {
            for step in 0..self.0.members.len() {
                let member = &self.0.members[(start + step) % self.0.members.len()];
                if !member
                    .health
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .healthy
                {
                    continue;
                }
                // Per-member deadlines leave room to try another healthy origin.
                match timeout(
                    Duration::from_millis(self.0.options.health_timeout_ms),
                    member.origin.connect(websocket),
                )
                .await
                {
                    Ok(Ok((io, protocol))) => return Ok((member.origin.clone(), io, protocol)),
                    _ => {
                        let mut state = member
                            .health
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        state.healthy = false;
                        state.checked = true;
                        state.checked_at = Some(tokio::time::Instant::now());
                        state.generation = state.generation.wrapping_add(1);
                    }
                }
            }
            Err(PoolUnavailable)
        })
        .await
        .unwrap_or(Err(PoolUnavailable))
        .map_err(Into::into)
    }
}
impl From<Origin> for OriginPool {
    fn from(origin: Origin) -> Self {
        Self::new(vec![origin], PoolOptions::default()).expect("one validated origin")
    }
}

async fn probe(origin: &Origin, path: Option<&str>) -> Result<()> {
    let (io, protocol) = origin.connect(false).await?;
    let Some(path) = path else {
        return Ok(());
    };
    let (mut parts, ()) = Request::builder()
        .method("HEAD")
        .uri(path)
        .body(())?
        .into_parts();
    origin.prepare_request(&mut parts, protocol)?;
    let request = Request::from_parts(parts, Body::empty());
    let mut connections = JoinSet::new();
    let response = if protocol == OriginProtocol::Http2 {
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io)).await?;
        connections.spawn(connection);
        sender.send_request(request).await?
    } else {
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
        connections.spawn(connection);
        sender.send_request(request).await?
    };
    ensure!(
        response.status().is_success(),
        "origin health status {}",
        response.status()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_duplicate_origins_and_absolute_probe_urls() {
        let origin =
            Origin::from_options(Some(8080), "127.0.0.1", OriginOptions::default()).unwrap();
        assert!(
            OriginPool::new(vec![origin.clone(), origin.clone()], PoolOptions::default()).is_err()
        );
        for path in [
            "https://other.example/health",
            "//other.example/health",
            "health",
        ] {
            assert!(OriginPool::new(
                vec![origin.clone()],
                PoolOptions {
                    health_path: Some(path.into()),
                    ..Default::default()
                }
            )
            .is_err());
        }
    }
    #[tokio::test]
    async fn connection_failure_fails_over_and_probe_recovers_member() {
        let a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();
        let a_origin =
            Origin::from_options(Some(a_addr.port()), "127.0.0.1", OriginOptions::default())
                .unwrap();
        let b_origin =
            Origin::from_options(Some(b_addr.port()), "127.0.0.1", OriginOptions::default())
                .unwrap();
        let pool = OriginPool::new(vec![a_origin, b_origin], PoolOptions::default()).unwrap();
        drop(a);
        let (chosen, io, _) = pool.connect(false).await.unwrap();
        assert_eq!(chosen.registration_address(), b_addr);
        assert!(!pool.status()[0].healthy);
        drop(io);
        drop(b);
        assert!(pool
            .connect(false)
            .await
            .err()
            .unwrap()
            .is::<PoolUnavailable>());
        let _recovered = tokio::net::TcpListener::bind(a_addr).await.unwrap();
        pool.refresh().await;
        assert!(pool.status()[0].healthy);
        assert!(!pool.status()[1].healthy);
        let (chosen, _, _) = pool.connect(false).await.unwrap();
        assert_eq!(chosen.registration_address(), a_addr);
    }

    #[tokio::test]
    async fn cancelled_probe_closes_socket_and_old_success_cannot_clear_new_failure() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let origin =
            Origin::from_options(Some(address.port()), "127.0.0.1", OriginOptions::default())
                .unwrap();
        let pool = OriginPool::new(
            vec![origin],
            PoolOptions {
                health_path: Some("/health".into()),
                health_timeout_ms: 500,
                ..Default::default()
            },
        )
        .unwrap();
        let task_pool = pool.clone();
        let probe = tokio::spawn(async move {
            task_pool.refresh().await;
        });
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 4096];
        assert!(socket.read(&mut buffer).await.unwrap() > 0);
        probe.await.unwrap();
        assert!(!pool.status()[0].healthy);
        assert_eq!(
            timeout(Duration::from_secs(2), socket.read(&mut buffer))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        drop(socket);
        // Let a probe succeed only after a newer request has observed refusal.
        let task_pool = pool.clone();
        let probe = tokio::spawn(async move {
            task_pool.refresh().await;
        });
        let (mut socket, _) = listener.accept().await.unwrap();
        assert!(socket.read(&mut buffer).await.unwrap() > 0);
        // Restore the last known healthy state to simulate concurrent traffic
        // during a recovery probe; the actual connection will then be refused.
        pool.0.members[0].health.lock().unwrap().healthy = true;
        drop(listener);
        assert!(pool.connect(false).await.is_err());
        socket
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        probe.await.unwrap();
        assert!(
            !pool.status()[0].healthy,
            "old probe must not override a new failure"
        );
    }
}
