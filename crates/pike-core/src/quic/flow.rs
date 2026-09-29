//! Application limits complement QUIC flow control: stop draining streams when
//! the consumer is slow, and reject oversized buffered (non-streaming) messages.
use tokio::sync::mpsc;

pub(super) const MAX_STREAM_BUFFER: usize = 16 * 1024 * 1024;
pub(super) const MAX_CONNECTION_BUFFER: usize = 64 * 1024 * 1024;
pub(super) const MAX_TRACKED_STREAMS: usize = 256;
pub(super) const MAX_WRITE_ENTRIES: usize = 256;
const MAX_DELIVERED_MESSAGES: usize = 4;

/// At most four messages may be in the application channel, plus one retained
/// here. Reserving the excess channel slots enforces this even for callers
/// supplying a larger channel, without changing the public channel API.
pub(super) struct Delivery<T> {
    pending: Option<T>,
}

impl<T> Default for Delivery<T> {
    fn default() -> Self {
        Self { pending: None }
    }
}

impl<T> Delivery<T> {
    pub(super) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    fn reservations(tx: &mpsc::Sender<T>) -> usize {
        tx.max_capacity().saturating_sub(MAX_DELIVERED_MESSAGES) + 1
    }

    pub(super) fn send(&mut self, tx: &mpsc::Sender<T>, message: T) -> Result<(), &'static str> {
        if self.pending.is_some() {
            return Err("delivery must drain before reading another message");
        }
        self.pending = Some(message);
        self.flush(tx)
    }

    pub(super) fn flush(&mut self, tx: &mpsc::Sender<T>) -> Result<(), &'static str> {
        if !self.is_pending() {
            return Ok(());
        }
        match tx.try_reserve_many(Self::reservations(tx)) {
            Ok(mut permits) => {
                if let (Some(permit), Some(message)) = (permits.next(), self.pending.take()) {
                    permit.send(message);
                }
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(())) => Err("application receiver closed"),
        }
    }

    /// Cancellation safe: ownership stays here until a channel permit is ready.
    pub(super) async fn wait(&mut self, tx: &mpsc::Sender<T>) -> Result<(), &'static str> {
        let mut permits = tx
            .reserve_many(Self::reservations(tx))
            .await
            .map_err(|_| "application receiver closed")?;
        if let (Some(permit), Some(message)) = (permits.next(), self.pending.take()) {
            permit.send(message);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn large_channels_are_still_limited_to_four_messages() {
        let (tx, mut rx) = mpsc::channel(1024);
        let mut delivery = Delivery::default();
        for value in 0..5 {
            delivery.send(&tx, vec![value; 100]).unwrap();
        }
        assert_eq!(rx.len(), MAX_DELIVERED_MESSAGES);
        assert!(delivery.is_pending());
        assert_eq!(rx.recv().await.unwrap(), vec![0; 100]);
        delivery.wait(&tx).await.unwrap();
        for value in 1..5 {
            assert_eq!(rx.recv().await.unwrap(), vec![value; 100]);
        }
        assert!(!delivery.is_pending());
    }

    #[tokio::test]
    async fn closed_consumer_is_an_error_not_silent_loss() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let mut delivery = Delivery::default();
        assert!(delivery.send(&tx, vec![42]).is_err());
        assert!(delivery.is_pending());
    }
}
