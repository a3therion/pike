use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedRequest {
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub method: String,
    pub path: String,
    pub headers: Vec<CapturedHeader>,
    pub body: Option<String>,
    pub response_status: u16,
    pub response_headers: Vec<CapturedHeader>,
    pub response_body: Option<String>,
    pub duration_ms: u64,
}

pub struct RequestStore {
    buffer: Arc<RwLock<VecDeque<CapturedRequest>>>,
    max_size: usize,
    tx: broadcast::Sender<CapturedRequest>,
}

impl RequestStore {
    pub fn new(max_size: usize) -> Self {
        let (tx, _) = broadcast::channel(256);
        Self {
            buffer: Arc::new(RwLock::new(VecDeque::with_capacity(max_size))),
            max_size,
            tx,
        }
    }

    pub fn add(&self, request: CapturedRequest) {
        let mut buffer = self.buffer.write().unwrap();
        if buffer.len() >= self.max_size {
            buffer.pop_front();
        }
        buffer.push_back(request.clone());
        let _ = self.tx.send(request);
    }

    pub fn get_all(&self) -> Vec<CapturedRequest> {
        let buffer = self.buffer.read().unwrap();
        buffer.iter().cloned().collect()
    }

    pub fn get(&self, id: &str) -> Option<CapturedRequest> {
        let buffer = self.buffer.read().unwrap();
        buffer.iter().find(|r| r.id == id).cloned()
    }

    pub fn len(&self) -> usize {
        self.buffer.read().unwrap().len()
    }

    pub fn clear(&self) {
        self.buffer.write().unwrap().clear();
    }

    pub fn subscribe(&self) -> broadcast::Receiver<CapturedRequest> {
        self.tx.subscribe()
    }
}

impl Default for RequestStore {
    fn default() -> Self {
        Self::new(500)
    }
}
