use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime};

use dashmap::DashMap;

use crate::types::TunnelId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Active,
    Closing,
    Closed,
}

#[derive(Debug)]
pub struct StreamInfo {
    pub stream_id: u64,
    pub tunnel_id: TunnelId,
    pub connection_id: u64,
    pub created_at: Instant,
    pub created_at_system: SystemTime,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub state: StreamState,
}

impl StreamInfo {
    #[must_use]
    pub fn new(stream_id: u64, tunnel_id: TunnelId, connection_id: u64) -> Self {
        Self {
            stream_id,
            tunnel_id,
            connection_id,
            created_at: Instant::now(),
            created_at_system: SystemTime::now(),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            state: StreamState::Active,
        }
    }

    #[must_use]
    pub fn bytes(&self) -> (u64, u64) {
        (
            self.bytes_in.load(Ordering::Relaxed),
            self.bytes_out.load(Ordering::Relaxed),
        )
    }
}

impl Clone for StreamInfo {
    fn clone(&self) -> Self {
        Self {
            stream_id: self.stream_id,
            tunnel_id: self.tunnel_id,
            connection_id: self.connection_id,
            created_at: self.created_at,
            created_at_system: self.created_at_system,
            bytes_in: AtomicU64::new(self.bytes_in.load(Ordering::Relaxed)),
            bytes_out: AtomicU64::new(self.bytes_out.load(Ordering::Relaxed)),
            state: self.state,
        }
    }
}

#[derive(Debug)]
pub struct StreamManager {
    active_streams: DashMap<u64, StreamInfo>,
    next_stream_id: AtomicU64,
}

impl Default for StreamManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            active_streams: DashMap::new(),
            next_stream_id: AtomicU64::new(4),
        }
    }

    #[must_use]
    pub fn next_stream_id(&self) -> u64 {
        self.next_stream_id.fetch_add(4, Ordering::Relaxed)
    }

    pub fn register_stream(&self, stream_id: u64, tunnel_id: TunnelId) -> StreamInfo {
        let info = StreamInfo::new(stream_id, tunnel_id, 0);
        self.active_streams.insert(stream_id, info.clone());
        info
    }

    #[must_use]
    pub fn get_tunnel(&self, stream_id: u64) -> Option<TunnelId> {
        self.active_streams
            .get(&stream_id)
            .map(|entry| entry.tunnel_id)
    }

    #[must_use]
    pub fn get_stream_info(&self, stream_id: u64) -> Option<StreamInfo> {
        self.active_streams
            .get(&stream_id)
            .map(|entry| entry.clone())
    }

    pub fn close_stream(&self, stream_id: u64) {
        if let Some(mut stream) = self.active_streams.get_mut(&stream_id) {
            stream.state = StreamState::Closed;
        }
    }

    pub fn update_bytes(&self, stream_id: u64, bytes_in: u64, bytes_out: u64) {
        if let Some(stream) = self.active_streams.get(&stream_id) {
            stream.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
            stream.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active_streams
            .iter()
            .filter(|entry| entry.state != StreamState::Closed)
            .count()
    }

    #[must_use]
    pub fn streams_for_tunnel(&self, tunnel_id: TunnelId) -> Vec<u64> {
        self.active_streams
            .iter()
            .filter(|entry| entry.tunnel_id == tunnel_id && entry.state != StreamState::Closed)
            .map(|entry| *entry.key())
            .collect()
    }

    #[must_use]
    pub fn tunnel_stream_count(&self, tunnel_id: TunnelId) -> usize {
        self.streams_for_tunnel(tunnel_id).len()
    }

    #[must_use]
    pub fn total_bytes(&self) -> (u64, u64) {
        self.active_streams
            .iter()
            .fold((0, 0), |(in_total, out_total), entry| {
                (
                    in_total + entry.bytes_in.load(Ordering::Relaxed),
                    out_total + entry.bytes_out.load(Ordering::Relaxed),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[test]
    fn register_and_lookup_stream() {
        let manager = StreamManager::new();
        let tunnel_id = TunnelId::new();
        let stream_id = manager.next_stream_id();

        let stream = manager.register_stream(stream_id, tunnel_id);

        assert_eq!(stream.stream_id, stream_id);
        assert_eq!(manager.get_tunnel(stream_id), Some(tunnel_id));
        assert_eq!(manager.active_count(), 1);

        let stream_info = manager
            .get_stream_info(stream_id)
            .expect("stream info should be present");
        assert_eq!(stream_info.tunnel_id, tunnel_id);
        assert_eq!(stream_info.state, StreamState::Active);
    }

    #[test]
    fn stream_id_generation_sequence() {
        let manager = StreamManager::new();
        assert_eq!(manager.next_stream_id(), 4);
        assert_eq!(manager.next_stream_id(), 8);
        assert_eq!(manager.next_stream_id(), 12);
    }

    #[test]
    fn bytes_tracking_accuracy() {
        let manager = StreamManager::new();
        let tunnel_id = TunnelId::new();
        let stream_id = manager.next_stream_id();
        manager.register_stream(stream_id, tunnel_id);

        manager.update_bytes(stream_id, 100, 40);
        manager.update_bytes(stream_id, 25, 10);

        let stream_info = manager
            .get_stream_info(stream_id)
            .expect("stream info should exist");
        assert_eq!(stream_info.bytes(), (125, 50));
        assert_eq!(manager.total_bytes(), (125, 50));
    }

    #[test]
    fn concurrent_register_and_close_operations() {
        let manager = Arc::new(StreamManager::new());
        let tunnel_id = TunnelId::new();

        let mut register_threads = Vec::new();
        for _ in 0..16 {
            let manager = Arc::clone(&manager);
            register_threads.push(thread::spawn(move || {
                for _ in 0..100 {
                    let stream_id = manager.next_stream_id();
                    manager.register_stream(stream_id, tunnel_id);
                }
            }));
        }

        for handle in register_threads {
            handle.join().expect("register thread should join");
        }

        let all_streams = manager.streams_for_tunnel(tunnel_id);
        assert_eq!(all_streams.len(), 1600);

        let streams_to_close: Vec<u64> = all_streams.iter().copied().take(600).collect();
        let mut close_threads = Vec::new();
        for chunk in streams_to_close.chunks(100) {
            let manager = Arc::clone(&manager);
            let stream_ids = chunk.to_vec();
            close_threads.push(thread::spawn(move || {
                for stream_id in stream_ids {
                    manager.close_stream(stream_id);
                }
            }));
        }

        for handle in close_threads {
            handle.join().expect("close thread should join");
        }

        assert_eq!(manager.active_count(), 1000);
        assert_eq!(manager.tunnel_stream_count(tunnel_id), 1000);
    }
}
