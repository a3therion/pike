use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::sync::Mutex;
use tracing::{info, warn};

const FLUSH_INTERVAL_SECS: u64 = 30;
const MAX_BATCH_SIZE: usize = 1000;

/// A single request log entry for D1 ingestion.
#[derive(Debug, Clone, Serialize)]
pub struct IngestEntry {
    pub user_id: String,
    pub tunnel_id: String,
    pub subdomain: String,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub response_time_ms: u64,
    pub bytes_transferred: u64,
    pub client_ip: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_headers: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_headers: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_content_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_content_type: Option<String>,
}

/// Batches request logs and periodically flushes them to the Workers API.
pub struct RequestBuffer {
    buffer: Mutex<Vec<IngestEntry>>,
    workers_api_url: String,
    server_token: String,
    http_client: reqwest::Client,
}

impl RequestBuffer {
    #[must_use]
    pub fn new(workers_api_url: String, server_token: String) -> Self {
        Self {
            buffer: Mutex::new(Vec::new()),
            workers_api_url,
            server_token,
            http_client: reqwest::Client::new(),
        }
    }

    /// Add an entry to the buffer.
    pub async fn push(&self, entry: IngestEntry) {
        self.buffer.lock().await.push(entry);
    }

    /// Spawn a background loop that flushes the buffer every 30 seconds.
    pub fn spawn_flush_loop(self: &Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(FLUSH_INTERVAL_SECS));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                this.flush().await;
            }
        });
    }

    #[cfg(test)]
    pub async fn flush_for_test(&self) {
        self.flush().await;
    }

    async fn flush(&self) {
        let entries: Vec<IngestEntry> = {
            let mut buf = self.buffer.lock().await;
            if buf.is_empty() {
                return;
            }
            buf.drain(..).collect()
        };

        let total = entries.len();
        info!(count = total, "flushing request buffer to D1");

        // Split into chunks of MAX_BATCH_SIZE
        for (index, chunk) in entries.chunks(MAX_BATCH_SIZE).enumerate() {
            if let Err(error) = self.send_batch(chunk).await {
                warn!(error = %error, count = chunk.len(), "failed to ingest batch to Workers API");
                let failed_start = index * MAX_BATCH_SIZE;
                self.requeue_failed_entries(entries[failed_start..].to_vec())
                    .await;
                return;
            }
        }
    }

    async fn requeue_failed_entries(&self, failed_entries: Vec<IngestEntry>) {
        let mut buffer = self.buffer.lock().await;
        let mut retained = failed_entries;
        retained.append(&mut *buffer);
        *buffer = retained;
    }

    async fn send_batch(&self, entries: &[IngestEntry]) -> anyhow::Result<()> {
        #[derive(Serialize)]
        struct BatchPayload<'a> {
            logs: &'a [IngestEntry],
        }

        let url = format!(
            "{}/api/v1/analytics/ingest",
            self.workers_api_url.trim_end_matches('/')
        );
        let response = self
            .http_client
            .post(&url)
            .header("X-Server-Token", &self.server_token)
            .json(&BatchPayload { logs: entries })
            .timeout(Duration::from_secs(10))
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("ingest API returned {status}: {body}");
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::{IngestEntry, RequestBuffer};

    fn sample_entry(id_suffix: &str) -> IngestEntry {
        IngestEntry {
            user_id: "u1".to_string(),
            tunnel_id: format!("tunnel-{id_suffix}"),
            subdomain: "demo.pike.life".to_string(),
            method: "GET".to_string(),
            path: format!("/{id_suffix}"),
            status_code: 200,
            response_time_ms: 12,
            bytes_transferred: 128,
            client_ip: "127.0.0.1".to_string(),
            timestamp: "2026-03-21T00:00:00Z".to_string(),
            request_headers: None,
            request_body: None,
            response_headers: None,
            response_body: None,
            request_content_type: None,
            response_content_type: None,
        }
    }

    #[derive(Debug)]
    struct FailOnce {
        failed: std::sync::atomic::AtomicBool,
    }

    impl FailOnce {
        fn new() -> Self {
            Self {
                failed: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl Respond for FailOnce {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            if self.failed.swap(true, std::sync::atomic::Ordering::SeqCst) {
                ResponseTemplate::new(200)
            } else {
                ResponseTemplate::new(500)
            }
        }
    }

    #[tokio::test]
    async fn failed_ingest_batch_is_requeued_for_next_flush() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/analytics/ingest"))
            .and(header("X-Server-Token", "test-token"))
            .respond_with(FailOnce::new())
            .mount(&server)
            .await;

        let buffer = Arc::new(RequestBuffer::new(server.uri(), "test-token".to_string()));
        buffer.push(sample_entry("a")).await;
        buffer.push(sample_entry("b")).await;

        buffer.flush_for_test().await;
        buffer.flush_for_test().await;

        let requests = server
            .received_requests()
            .await
            .expect("received requests should be available");
        assert_eq!(requests.len(), 2);

        let body: serde_json::Value =
            serde_json::from_slice(&requests[1].body).expect("ingest payload should be json");
        let logs = body["logs"].as_array().expect("logs array");
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0]["path"], "/a");
        assert_eq!(logs[1]["path"], "/b");
    }
}
