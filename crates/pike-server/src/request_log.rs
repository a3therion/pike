use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, RwLock};
use tracing::warn;

use crate::state_store::StateStore;

const MAX_ENTRIES_PER_TUNNEL: usize = 1000;
const BROADCAST_CAPACITY: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestLogEntry {
    pub id: String,
    pub timestamp: String,
    pub method: String,
    pub path: String,
    pub status_code: u16,
    pub duration_ms: u64,
    pub request_size: u64,
    pub response_size: u64,
    pub tunnel_id: String,
}

struct TunnelLog {
    entries: VecDeque<RequestLogEntry>,
    broadcast_tx: broadcast::Sender<RequestLogEntry>,
}

impl TunnelLog {
    fn new() -> Self {
        let (tx, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self {
            entries: VecDeque::new(),
            broadcast_tx: tx,
        }
    }

    fn push(&mut self, entry: RequestLogEntry) {
        if self.entries.len() >= MAX_ENTRIES_PER_TUNNEL {
            self.entries.pop_front();
        }
        let _ = self.broadcast_tx.send(entry.clone());
        self.entries.push_back(entry);
    }

    fn recent(&self, limit: usize, offset: usize) -> Vec<RequestLogEntry> {
        self.entries
            .iter()
            .rev()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    fn subscribe(&self) -> broadcast::Receiver<RequestLogEntry> {
        self.broadcast_tx.subscribe()
    }
}

pub struct RequestLogStore {
    logs: RwLock<HashMap<String, TunnelLog>>,
    state_store: Option<Arc<dyn StateStore>>,
}

impl Default for RequestLogStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestLogStore {
    pub fn new() -> Self {
        Self {
            logs: RwLock::new(HashMap::new()),
            state_store: None,
        }
    }

    pub fn with_state_store(state_store: Option<Arc<dyn StateStore>>) -> Self {
        Self {
            logs: RwLock::new(HashMap::new()),
            state_store,
        }
    }

    pub async fn log(&self, entry: RequestLogEntry) {
        if let Some(state_store) = self.state_store.as_ref() {
            if let Err(err) = state_store
                .append_request_log(&entry, MAX_ENTRIES_PER_TUNNEL)
                .await
            {
                warn!(tunnel_id = %entry.tunnel_id, error = %err, "failed to persist request log entry");
            }
        }

        let mut logs = self.logs.write().await;
        logs.entry(entry.tunnel_id.clone())
            .or_insert_with(TunnelLog::new)
            .push(entry);
    }

    pub async fn get_entries(
        &self,
        tunnel_id: &str,
        limit: usize,
        offset: usize,
    ) -> (Vec<RequestLogEntry>, usize) {
        let (local_recent, local_total) = self
            .local_entries(tunnel_id, MAX_ENTRIES_PER_TUNNEL, 0)
            .await;

        let Some(state_store) = self.state_store.as_ref() else {
            let page = local_recent.into_iter().skip(offset).take(limit).collect();
            return (page, local_total);
        };

        match state_store
            .get_request_logs(tunnel_id, MAX_ENTRIES_PER_TUNNEL, 0)
            .await
        {
            Ok((persisted_recent, _)) => {
                let merged = merge_entries(persisted_recent, local_recent);
                let total = merged.len();
                let page = merged.into_iter().skip(offset).take(limit).collect();
                (page, total)
            }
            Err(err) => {
                warn!(tunnel_id, error = %err, "failed to load persisted request logs");
                let page = local_recent.into_iter().skip(offset).take(limit).collect();
                (page, local_total)
            }
        }
    }

    pub async fn subscribe(&self, tunnel_id: &str) -> broadcast::Receiver<RequestLogEntry> {
        let mut logs = self.logs.write().await;
        let tlog = logs
            .entry(tunnel_id.to_string())
            .or_insert_with(TunnelLog::new);
        tlog.subscribe()
    }

    async fn local_entries(
        &self,
        tunnel_id: &str,
        limit: usize,
        offset: usize,
    ) -> (Vec<RequestLogEntry>, usize) {
        let logs = self.logs.read().await;
        if let Some(tlog) = logs.get(tunnel_id) {
            let total = tlog.entries.len();
            (tlog.recent(limit, offset), total)
        } else {
            (vec![], 0)
        }
    }
}

fn merge_entries(
    persisted_recent: Vec<RequestLogEntry>,
    local_recent: Vec<RequestLogEntry>,
) -> Vec<RequestLogEntry> {
    let mut combined = persisted_recent;
    combined.extend(local_recent);
    combined.sort_by(|left, right| {
        right
            .timestamp
            .cmp(&left.timestamp)
            .then_with(|| right.id.cmp(&left.id))
    });

    let mut seen_ids = HashSet::new();
    combined.retain(|entry| seen_ids.insert(entry.id.clone()));
    combined.truncate(MAX_ENTRIES_PER_TUNNEL);
    combined
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::state_store::{InMemoryStateStore, StateStore};

    use super::{RequestLogEntry, RequestLogStore};

    fn request_entry(id: &str, timestamp: &str) -> RequestLogEntry {
        RequestLogEntry {
            id: id.to_string(),
            timestamp: timestamp.to_string(),
            method: "GET".to_string(),
            path: "/health".to_string(),
            status_code: 200,
            duration_ms: 12,
            request_size: 32,
            response_size: 64,
            tunnel_id: "tunnel-1".to_string(),
        }
    }

    #[tokio::test]
    async fn request_logs_survive_store_restart() {
        let shared_store = Arc::new(InMemoryStateStore::new()) as Arc<dyn StateStore>;
        let store = RequestLogStore::with_state_store(Some(shared_store.clone()));

        store
            .log(request_entry("req-1", "2026-03-21T10:00:00Z"))
            .await;
        store
            .log(request_entry("req-2", "2026-03-21T10:00:01Z"))
            .await;

        let restarted = RequestLogStore::with_state_store(Some(shared_store));
        let (entries, total) = restarted.get_entries("tunnel-1", 50, 0).await;

        assert_eq!(total, 2);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, "req-2");
        assert_eq!(entries[1].id, "req-1");
    }
}
