//! Deliver the durable usage outbox; never derive billing from dashboard counters.
use crate::usage_journal::{UsageJournal, UsageReport};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Mutex};
use tracing::{error, info};

pub struct UsageReporter {
    flush_lock: Mutex<()>,
    journal: Arc<UsageJournal>,
    workers_api_url: String,
    server_token: String,
    http_client: reqwest::Client,
}
impl UsageReporter {
    #[must_use]
    pub fn new(workers_api_url: String, server_token: String, journal: Arc<UsageJournal>) -> Self {
        Self {
            flush_lock: Mutex::new(()),
            journal,
            workers_api_url,
            server_token,
            http_client: reqwest::Client::new(),
        }
    }
    pub fn spawn_flush_loop(self: &Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = interval.tick() => this.flush().await,
                    changed = shutdown.changed() => if changed.is_err() || *shutdown.borrow() { this.flush().await; break; }
                }
            }
            info!("usage reporter stopped; unacknowledged reports remain on disk");
        });
    }
    pub async fn flush(&self) {
        let _guard = self.flush_lock.lock().await;
        if let Err(error) = self.flush_inner().await {
            error!(%error, "usage remains durably queued for retry");
        }
    }
    async fn flush_inner(&self) -> Result<()> {
        // Bound a tick so shutdown and other work cannot starve under ongoing traffic.
        for _ in 0..40 {
            let reports = self.journal.batch().await?;
            if reports.is_empty() {
                break;
            }
            self.send_batch(&reports).await?;
            self.journal.acknowledge(&reports).await?;
        }
        Ok(())
    }
    async fn send_batch(&self, reports: &[UsageReport]) -> Result<()> {
        #[derive(Serialize)]
        struct Payload<'a> {
            reports: &'a [UsageReport],
        }
        #[derive(Deserialize)]
        struct Acknowledgement {
            processed: usize,
        }
        let url = format!(
            "{}/api/v1/usage/internal/report",
            self.workers_api_url.trim_end_matches('/')
        );
        let mut response = self
            .http_client
            .post(url)
            .bearer_auth(&self.server_token)
            .json(&Payload { reports })
            .timeout(Duration::from_secs(10))
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "usage API returned {}",
            response.status()
        );
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(
                body.len() + chunk.len() <= 1024,
                "oversized usage acknowledgement"
            );
            body.extend_from_slice(&chunk);
        }
        let ack: Acknowledgement = serde_json::from_slice(&body)?;
        anyhow::ensure!(
            ack.processed == reports.len(),
            "usage API acknowledged {} of {} reports",
            ack.processed,
            reports.len()
        );
        Ok(())
    }
}
