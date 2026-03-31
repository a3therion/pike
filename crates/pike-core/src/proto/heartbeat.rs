use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
pub const DEFAULT_HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug)]
pub struct HeartbeatManager {
    interval: Duration,
    timeout: Duration,
    last_sent: Instant,
    last_received: Instant,
    seq: u64,
    in_flight: HashMap<u64, Instant>,
    last_rtt: Option<Duration>,
}

impl Default for HeartbeatManager {
    fn default() -> Self {
        Self::new(DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT)
    }
}

impl HeartbeatManager {
    #[must_use]
    pub fn new(interval: Duration, timeout: Duration) -> Self {
        let now = Instant::now();
        Self {
            interval,
            timeout,
            last_sent: now,
            last_received: now,
            seq: 0,
            in_flight: HashMap::new(),
            last_rtt: None,
        }
    }

    #[must_use]
    pub fn interval(&self) -> Duration {
        self.interval
    }

    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.seq + 1
    }

    #[must_use]
    pub fn should_send(&self) -> bool {
        self.last_sent.elapsed() >= self.interval
    }

    pub fn record_sent(&mut self) -> u64 {
        self.seq = self.seq.wrapping_add(1);
        let now = Instant::now();
        self.last_sent = now;
        self.in_flight.insert(self.seq, now);
        self.seq
    }

    pub fn record_received(&mut self, seq: u64) {
        self.last_received = Instant::now();
        if let Some(sent_at) = self.in_flight.remove(&seq) {
            self.last_rtt = Some(sent_at.elapsed());
        }
    }

    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        self.last_received.elapsed() >= self.timeout
    }

    #[must_use]
    pub fn rtt(&self) -> Option<Duration> {
        self.last_rtt
    }
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::Duration;

    use super::{HeartbeatManager, DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT};

    #[test]
    fn default_values_match_spec() {
        let hb = HeartbeatManager::default();
        assert_eq!(hb.interval(), DEFAULT_HEARTBEAT_INTERVAL);
        assert_eq!(hb.timeout(), DEFAULT_HEARTBEAT_TIMEOUT);
    }

    #[test]
    fn timeout_detection_after_three_missed_heartbeats() {
        let timeout = Duration::from_millis(30);
        let hb = HeartbeatManager::new(Duration::from_millis(10), timeout);

        thread::sleep(Duration::from_millis(35));
        assert!(hb.is_timed_out());
    }

    #[test]
    fn should_send_after_interval_elapsed() {
        let hb = HeartbeatManager::new(Duration::from_millis(20), Duration::from_millis(60));
        assert!(!hb.should_send());
        thread::sleep(Duration::from_millis(25));
        assert!(hb.should_send());
    }

    #[test]
    fn receiving_heartbeat_resets_timeout_timer() {
        let mut hb = HeartbeatManager::new(Duration::from_millis(10), Duration::from_millis(30));
        thread::sleep(Duration::from_millis(20));
        hb.record_received(1234);
        assert!(!hb.is_timed_out());
    }

    #[test]
    fn rtt_is_estimated_from_send_and_ack() {
        let mut hb = HeartbeatManager::new(Duration::from_millis(5), Duration::from_secs(1));
        let seq = hb.record_sent();
        thread::sleep(Duration::from_millis(10));
        hb.record_received(seq);

        let rtt = hb.rtt().expect("rtt should be recorded after ack");
        assert!(rtt >= Duration::from_millis(8));
    }
}
