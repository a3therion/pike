//! Canonical, directional observations for non-HTTP traffic. Commit each bounded
//! observation before forwarding it; a disconnect cannot discard in-flight totals.
use std::sync::Arc;

use anyhow::Result;
use pike_core::{byte_stream::Direction, types::TunnelId};

use crate::{registry::ClientRegistry, usage_journal::UsageJournal};

#[derive(Clone)]
pub struct TrafficMeter {
    registry: Arc<ClientRegistry>,
    tunnel_id: TunnelId,
    owner: String,
    canonical_id: String,
    journal: Option<Arc<UsageJournal>>,
    quota: Option<(Arc<crate::quota::QuotaManager>, String)>,
}

impl TrafficMeter {
    pub fn new(
        registry: Arc<ClientRegistry>,
        tunnel_id: TunnelId,
        owner: String,
        canonical_id: String,
        journal: Option<Arc<UsageJournal>>,
    ) -> Self {
        Self {
            registry,
            tunnel_id,
            owner,
            canonical_id,
            journal,
            quota: None,
        }
    }

    pub fn admit(&self) -> Result<()> {
        if self.quota.is_some() {
            self.registry
                .rate_limiter
                .check_request_rate(self.owner.clone())?;
        } else {
            self.registry.rate_limiter.check_limit(self.owner.clone())?;
        }
        self.registry
            .rate_limiter
            .check_tunnel_limit(self.tunnel_id)?;
        Ok(())
    }

    pub fn with_quota(
        mut self,
        quota: Option<Arc<crate::quota::QuotaManager>>,
        lease_id: String,
    ) -> Self {
        self.quota = quota.map(|quota| (quota, lease_id));
        self
    }

    pub async fn opened(&self) -> Result<()> {
        self.observe(0, 0, 1).await
    }

    pub async fn bytes(&self, direction: Direction, length: usize) -> Result<()> {
        self.transfer(direction, length, false).await
    }

    pub async fn packet(&self, direction: Direction, length: usize) -> Result<()> {
        self.transfer(direction, length, direction == Direction::SocketToTunnel)
            .await
    }

    async fn transfer(&self, direction: Direction, length: usize, request: bool) -> Result<()> {
        if self.quota.is_none() {
            self.registry.rate_limiter.check_bandwidth(&self.owner)?;
        }
        let (incoming, outgoing) = match direction {
            Direction::SocketToTunnel => (length as u64, 0),
            Direction::TunnelToSocket => (0, length as u64),
        };
        self.observe(incoming, outgoing, u64::from(request)).await?;
        self.registry
            .track_transfer(self.tunnel_id, incoming, outgoing);
        Ok(())
    }

    async fn observe(&self, incoming: u64, outgoing: u64, requests: u64) -> Result<()> {
        if incoming == 0 && outgoing == 0 && requests == 0 {
            return Ok(());
        }
        if let Some((quota, lease)) = &self.quota {
            quota
                .observe(
                    &crate::quota::QuotaContext {
                        user_id: self.owner.clone(),
                        tunnel_id: self.canonical_id.clone(),
                        lease_id: lease.clone(),
                    },
                    incoming,
                    outgoing,
                    requests,
                )
                .await?;
        } else if let Some(journal) = &self.journal {
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                journal.record_delta(
                    self.canonical_id.clone(),
                    self.owner.clone(),
                    incoming,
                    outgoing,
                    requests,
                ),
            )
            .await??;
        }
        Ok(())
    }

    /// Preserve HTTP data/trailers while admitting bounded byte observations
    /// before the proxy can forward them. Backpressure stays with the reader.
    pub fn wrap_body(&self, mut body: axum::body::Body, direction: Direction) -> axum::body::Body {
        use http_body_util::{BodyExt, StreamBody};
        let meter = self.clone();
        let stream: std::pin::Pin<
            Box<
                dyn futures_util::Stream<
                        Item = Result<hyper::body::Frame<axum::body::Bytes>, axum::Error>,
                    > + Send,
            >,
        > = Box::pin(async_stream::try_stream! {
            while let Some(frame) = body.frame().await {
                let frame = frame?;
                match frame.into_data() {
                    Ok(mut bytes) => while !bytes.is_empty() {
                        let chunk = bytes.split_to(bytes.len().min(32 * 1024));
                        meter.bytes(direction, chunk.len()).await.map_err(|error| axum::Error::new(std::io::Error::other(error.to_string())))?;
                        yield hyper::body::Frame::data(chunk);
                    },
                    Err(frame) => { yield frame; }
                }
            }
        });
        axum::body::Body::new(StreamBody::new(stream))
    }
}
