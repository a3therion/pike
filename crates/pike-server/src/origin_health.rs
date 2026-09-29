//! Lease-scoped, pull-based observations for cloud visibility and HTTP selection.
//! Observations never renew ownership or move an already admitted stream.
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Result;
use pike_core::{
    proto::{origin_health::OriginHealthReport, ControlMessage},
    quic::server::PikeOutboundMessage,
    types::TunnelId,
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
    time::Instant,
};

use crate::{control_plane::ControlPlaneClient, visitor_policy::VisitorGate};

struct Poll {
    nonce: u64,
    started: Instant,
    reply: oneshot::Sender<OriginHealthReport>,
}

#[derive(Default)]
struct Pending(Mutex<Option<Poll>>);
impl Pending {
    fn accept(&self, nonce: u64, mut report: OriginHealthReport, count: usize) -> Result<()> {
        report.validate(count)?;
        let mut pending = self.0.lock().unwrap();
        if pending
            .as_ref()
            .is_some_and(|p| p.nonce == nonce && p.started.elapsed() < Duration::from_secs(3))
        {
            let poll = pending.take().unwrap();
            // Include the entire request/response round trip, conservatively
            // covering both transport queues without trusting client clocks.
            report.age_by(poll.started.elapsed());
            let _ = poll.reply.send(report);
        }
        Ok(())
    }
}

pub struct ReportingLease {
    pub tunnel_id: TunnelId,
    pub public_id: String,
    pub lease_id: String,
    pub api_key: String,
    pub server_token: String,
    pub origin_count: usize,
    pub max_probe_age: Duration,
}

/// Lower values are preferred. Unknown includes unprobed and expired reports;
/// it is never promoted to healthy merely because the channel is still open.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum OriginReadiness {
    Healthy,
    Unknown,
    Unhealthy,
}

#[derive(Debug)]
pub struct ConnectorHealth {
    max_probe_age: Duration,
    latest: Mutex<Option<(Instant, OriginHealthReport)>>,
}

impl ConnectorHealth {
    fn new(max_probe_age: Duration) -> Self {
        Self {
            max_probe_age,
            latest: Mutex::new(None),
        }
    }

    fn record(&self, report: Option<OriginHealthReport>) {
        *self.latest.lock().unwrap() = report.map(|value| (Instant::now(), value));
    }

    pub fn readiness(&self) -> OriginReadiness {
        let latest = self.latest.lock().unwrap();
        let Some((received, report)) = latest.as_ref() else {
            return OriginReadiness::Unknown;
        };
        let elapsed = received.elapsed();
        if elapsed >= Duration::from_secs(15) {
            return OriginReadiness::Unknown;
        }
        report
            .origins
            .iter()
            .map(|origin| match (origin.healthy, origin.checked_ago_ms) {
                (Some(healthy), Some(age))
                    if Duration::from_millis(u64::from(age)).saturating_add(elapsed)
                        < self.max_probe_age =>
                {
                    if healthy {
                        OriginReadiness::Healthy
                    } else {
                        OriginReadiness::Unhealthy
                    }
                }
                _ => OriginReadiness::Unknown,
            })
            .min()
            .unwrap_or(OriginReadiness::Unknown)
    }
}

pub struct HealthReporter {
    pending: Arc<Pending>,
    count: usize,
    routing: Arc<ConnectorHealth>,
    task: JoinHandle<()>,
}
impl HealthReporter {
    pub fn spawn(
        lease: ReportingLease,
        control: Arc<ControlPlaneClient>,
        outbound: mpsc::Sender<PikeOutboundMessage>,
        gate: Arc<VisitorGate>,
    ) -> Self {
        let pending = Arc::new(Pending::default());
        let polls = pending.clone();
        let count = lease.origin_count;
        let routing = Arc::new(ConnectorHealth::new(lease.max_probe_age));
        let observations = routing.clone();
        let task = tokio::spawn(async move {
            let mut ticks = tokio::time::interval(Duration::from_secs(5));
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let mut nonce = 0_u64;
            loop {
                ticks.tick().await;
                if !gate.is_active() {
                    break;
                }
                let Some(next) = nonce.checked_add(1) else {
                    break;
                };
                nonce = next;
                let (tx, rx) = oneshot::channel();
                *polls.0.lock().unwrap() = Some(Poll {
                    nonce,
                    started: Instant::now(),
                    reply: tx,
                });
                let report = tokio::time::timeout(Duration::from_secs(3), async {
                    outbound
                        .send(PikeOutboundMessage::Control(
                            ControlMessage::OriginHealthRequest {
                                tunnel_id: lease.tunnel_id,
                                nonce,
                            },
                        ))
                        .await
                        .ok()?;
                    rx.await.ok()
                })
                .await
                .ok()
                .flatten();
                *polls.0.lock().unwrap() = None;
                if !gate.is_active() {
                    break;
                }
                // Local selection does not wait for a successful cloud POST.
                // Only this poll's validated, transit-aged reply can update it.
                observations.record(report.clone());
                // A missing response explicitly clears observations. Publication
                // failure leaves the last report to expire; it never renews it.
                let _ = control
                    .publish_origin_health(
                        &lease.api_key,
                        &lease.server_token,
                        &lease.public_id,
                        &lease.lease_id,
                        report.as_ref(),
                    )
                    .await;
            }
        });
        Self {
            pending,
            count,
            routing,
            task,
        }
    }

    pub fn accept(&self, nonce: u64, report: OriginHealthReport) -> Result<()> {
        self.pending.accept(nonce, report, self.count)
    }

    pub fn routing(&self) -> Arc<ConnectorHealth> {
        self.routing.clone()
    }
}
impl Drop for HealthReporter {
    fn drop(&mut self) {
        self.task.abort();
        self.routing.record(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pike_core::proto::origin_health::OriginObservation;
    fn report() -> OriginHealthReport {
        OriginHealthReport {
            origins: vec![OriginObservation {
                healthy: Some(true),
                checked_ago_ms: Some(2),
            }],
        }
    }

    #[tokio::test(start_paused = true)]
    async fn routing_health_expires_without_promoting_unknown_or_old_probes() {
        let health = ConnectorHealth::new(Duration::from_secs(20));
        assert_eq!(health.readiness(), OriginReadiness::Unknown);
        let mut observed = report();
        observed.origins[0].healthy = Some(false);
        health.record(Some(observed.clone()));
        assert_eq!(health.readiness(), OriginReadiness::Unhealthy);
        observed.origins.push(OriginObservation {
            healthy: None,
            checked_ago_ms: None,
        });
        health.record(Some(observed.clone()));
        assert_eq!(health.readiness(), OriginReadiness::Unknown);
        observed.origins[1] = OriginObservation {
            healthy: Some(true),
            checked_ago_ms: Some(19_000),
        };
        health.record(Some(observed));
        assert_eq!(health.readiness(), OriginReadiness::Healthy);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(health.readiness(), OriginReadiness::Unknown);
        health.record(Some(report()));
        tokio::time::advance(Duration::from_secs(15)).await;
        assert_eq!(health.readiness(), OriginReadiness::Unknown);
        health.record(Some(report()));
        health.record(None);
        assert_eq!(health.readiness(), OriginReadiness::Unknown);
    }

    #[tokio::test(start_paused = true)]
    async fn router_prefers_fresh_healthy_members_but_never_retargets_replay() {
        use crate::router::{TunnelEntry, VhostRouter};
        let router = VhostRouter::new();
        let health = Arc::new(ConnectorHealth::new(Duration::from_secs(20)));
        let (first, _first_rx) = mpsc::channel(4);
        let (second, second_rx) = mpsc::channel(4);
        let entry = TunnelEntry {
            tunnel_id: TunnelId::new(),
            connection_id: uuid::Uuid::new_v4(),
            stream_tx: first,
            active: true,
            visitor: VisitorGate::unrestricted(),
            domain: None,
            origin_health: None,
        };
        let second_id = uuid::Uuid::new_v4();
        router
            .register_member("health.test", entry.clone())
            .unwrap();
        router
            .register_member(
                "health.test",
                TunnelEntry {
                    connection_id: second_id,
                    stream_tx: second,
                    origin_health: Some(health.clone()),
                    ..entry.clone()
                },
            )
            .unwrap();
        health.record(Some(report()));
        for _ in 0..8 {
            assert_eq!(
                router.route("health.test").unwrap().connection_id,
                second_id
            );
        }
        assert_eq!(
            router
                .route_for_connection("health.test", &entry.connection_id)
                .unwrap()
                .connection_id,
            entry.connection_id
        );
        let mut down = report();
        down.origins[0].healthy = Some(false);
        health.record(Some(down));
        for _ in 0..8 {
            assert_eq!(
                router.route("health.test").unwrap().connection_id,
                entry.connection_id
            );
        }
        // Replay keeps its selected member even when its origins are unhealthy.
        // The CLI returns the normal all-down response without replaying elsewhere.
        assert_eq!(
            router
                .route_for_connection("health.test", &second_id)
                .unwrap()
                .connection_id,
            second_id
        );
        tokio::time::advance(Duration::from_secs(15)).await;
        let selected: Vec<_> = (0..8)
            .map(|_| router.route("health.test").unwrap().connection_id)
            .collect();
        assert_eq!(selected.iter().filter(|id| **id == second_id).count(), 4);
        health.record(Some(report()));
        drop(second_rx);
        assert_eq!(
            router.route("health.test").unwrap().connection_id,
            entry.connection_id
        );
    }

    #[tokio::test(start_paused = true)]
    async fn poll_is_single_use_scoped_and_includes_transit_age() {
        let pending = Pending::default();
        let (tx, mut rx) = oneshot::channel();
        *pending.0.lock().unwrap() = Some(Poll {
            nonce: 9,
            started: Instant::now(),
            reply: tx,
        });
        pending.accept(8, report(), 1).unwrap();
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(pending.accept(9, report(), 2).is_err());
        tokio::time::advance(Duration::from_millis(80)).await;
        pending.accept(9, report(), 1).unwrap();
        assert_eq!(rx.await.unwrap().origins[0].checked_ago_ms, Some(82));
        pending.accept(9, report(), 1).unwrap();
        assert!(pending.0.lock().unwrap().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn expired_poll_cannot_publish_and_unknown_is_not_healthy() {
        let pending = Pending::default();
        let (tx, mut rx) = oneshot::channel();
        *pending.0.lock().unwrap() = Some(Poll {
            nonce: 1,
            started: Instant::now(),
            reply: tx,
        });
        tokio::time::advance(Duration::from_secs(3)).await;
        pending.accept(1, report(), 1).unwrap();
        assert!(matches!(
            rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        let mut invalid = report();
        invalid.origins[0].checked_ago_ms = None;
        assert!(invalid.validate(1).is_err());
        invalid.origins[0].healthy = None;
        invalid.validate(1).unwrap();
        assert!(invalid.validate(17).is_err());
    }
}
