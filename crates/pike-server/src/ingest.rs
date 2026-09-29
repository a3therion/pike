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

const MAX_ENTRIES: usize = 4096;
const MAX_BUFFER_BYTES: usize = 8 * 1024 * 1024;
const MAX_ENTRY_BYTES: usize = 64 * 1024;

#[derive(Default)]
struct Queue {
    entries: std::collections::VecDeque<Vec<u8>>,
    bytes: usize,
}

/// At most 8 MiB queued plus a 1 MiB batch copy and its serialized payload. Drop new entries when
/// full, preserving older retries. Disabled entirely when no sink is configured.
pub struct RequestBuffer {
    buffer: Mutex<Queue>,
    flush_lock: Mutex<()>,
    workers_api_url: String,
    server_token: String,
    http_client: reqwest::Client,
}

impl RequestBuffer {
    #[must_use]
    pub fn new(workers_api_url: String, server_token: String) -> Self {
        Self {
            buffer: Mutex::new(Queue::default()),
            flush_lock: Mutex::new(()),
            workers_api_url,
            server_token,
            http_client: reqwest::Client::new(),
        }
    }

    pub async fn push(&self, entry: IngestEntry) {
        if self.workers_api_url.is_empty() || self.server_token.is_empty() {
            return;
        }
        #[derive(Serialize)]
        struct Event {
            id: String,
            #[serde(flatten)]
            entry: IngestEntry,
        }
        let Ok(bytes) = serde_json::to_vec(&Event {
            id: uuid::Uuid::new_v4().to_string(),
            entry,
        }) else {
            return;
        };
        let mut queue = self.buffer.lock().await;
        if bytes.len() > MAX_ENTRY_BYTES
            || queue.entries.len() >= MAX_ENTRIES
            || queue.bytes + bytes.len() > MAX_BUFFER_BYTES
        {
            crate::metrics::INGEST_DROPPED.inc();
            return;
        }
        queue.bytes += bytes.len();
        queue.entries.push_back(bytes);
        crate::metrics::INGEST_QUEUED_BYTES.set(i64::try_from(queue.bytes).unwrap_or(i64::MAX));
    }

    pub fn spawn_flush_loop(self: &Arc<Self>) {
        if self.workers_api_url.is_empty() || self.server_token.is_empty() {
            return;
        }
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
        // Keep entries in the queue while awaiting acknowledgement. This reserves
        // their bytes across concurrent producers and preserves stable retry IDs.
        let Ok(_guard) = self.flush_lock.try_lock() else {
            return;
        };
        {
            let mut batch_bytes = 0;
            let entries: Vec<_> = self
                .buffer
                .lock()
                .await
                .entries
                .iter()
                .take(MAX_BATCH_SIZE)
                .take_while(|entry| {
                    batch_bytes += entry.len();
                    batch_bytes <= 1024 * 1024
                })
                .cloned()
                .collect();
            if entries.is_empty() {
                return;
            }
            let mut payload = Vec::from(b"{\"logs\":[".as_slice());
            for (i, entry) in entries.iter().enumerate() {
                if i > 0 {
                    payload.push(b',');
                }
                payload.extend_from_slice(entry);
            }
            payload.extend_from_slice(b"]}");
            let url = format!(
                "{}/api/v1/analytics/ingest",
                self.workers_api_url.trim_end_matches('/')
            );
            let result = self
                .http_client
                .post(url)
                .header("X-Server-Token", &self.server_token)
                .header("Content-Type", "application/json")
                .body(payload)
                .timeout(Duration::from_secs(10))
                .send()
                .await;
            match result {
                Ok(response) if response.status().is_success() => {
                    let expected = entries.len();
                    let ack = response.json::<serde_json::Value>().await;
                    if !matches!(ack, Ok(ref value) if value["ingested"].as_u64() == Some(expected as u64) && value["skipped"].as_u64().unwrap_or(0) == 0)
                    {
                        crate::metrics::INGEST_RETRIES.inc();
                        warn!("ingest acknowledgement incomplete; retaining batch");
                        return;
                    }
                }
                other => {
                    crate::metrics::INGEST_RETRIES.inc();
                    warn!(status = ?other.map(|response| response.status()), "ingest failed; retaining bounded batch");
                    return;
                }
            }
            let mut queue = self.buffer.lock().await;
            for _ in 0..entries.len() {
                if let Some(entry) = queue.entries.pop_front() {
                    queue.bytes -= entry.len();
                }
            }
            crate::metrics::INGEST_QUEUED_BYTES.set(i64::try_from(queue.bytes).unwrap_or(i64::MAX));
            info!(count = entries.len(), "request logs acknowledged");
            // Next tick drains the next batch.
        }
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
                    .set_body_json(serde_json::json!({"ingested":2,"skipped":0}))
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
        assert_eq!(
            requests[0].body, requests[1].body,
            "retries keep stable event IDs"
        );
        assert_eq!(buffer.buffer.lock().await.bytes, 0);

        let body: serde_json::Value =
            serde_json::from_slice(&requests[1].body).expect("ingest payload should be json");
        let logs = body["logs"].as_array().expect("logs array");
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0]["path"], "/a");
        assert_eq!(logs[1]["path"], "/b");
    }
    #[tokio::test]
    async fn missing_sink_and_backpressure_have_bounded_memory() {
        let disabled = RequestBuffer::new(String::new(), String::new());
        disabled.push(sample_entry("disabled")).await;
        assert!(disabled.buffer.lock().await.entries.is_empty());
        let buffer = RequestBuffer::new("http://unreachable.invalid".into(), "test".into());
        for _ in 0..super::MAX_ENTRIES + 10 {
            buffer.push(sample_entry("bounded")).await;
        }
        let queue = buffer.buffer.lock().await;
        assert_eq!(queue.entries.len(), super::MAX_ENTRIES);
        assert!(queue.bytes <= super::MAX_BUFFER_BYTES);
    }
}
