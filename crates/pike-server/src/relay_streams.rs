//! A profile keeps one public listener; each accepted stream chooses one member.
//! No bytes have reached an origin at this point. Admitted streams never migrate.
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

use anyhow::{ensure, Result};
use futures_util::{stream::FuturesUnordered, StreamExt};
use pike_server::{connection::ConnectionId, registry::MAX_CONNECTORS_PER_TUNNEL};
use tokio::{
    sync::{mpsc, Notify},
    task::JoinHandle,
    time::{timeout, Duration},
};

use super::relay_tcp::{IntoRelayStream, RelayStream};

#[derive(Default)]
pub struct StreamDispatcher {
    members: Mutex<Vec<(ConnectionId, mpsc::Sender<RelayStream>)>>,
    next: AtomicUsize,
    changed: Notify,
}

impl StreamDispatcher {
    pub fn add(&self, id: ConnectionId, sender: mpsc::Sender<RelayStream>) -> Result<()> {
        let mut members = self.members.lock().unwrap();
        ensure!(
            members.len() < MAX_CONNECTORS_PER_TUNNEL,
            "connector limit reached"
        );
        ensure!(
            members.iter().all(|(current, _)| *current != id),
            "connector already registered"
        );
        members.push((id, sender));
        self.changed.notify_one();
        Ok(())
    }

    pub fn remove(&self, id: ConnectionId) {
        self.members
            .lock()
            .unwrap()
            .retain(|(current, _)| *current != id);
        self.changed.notify_one();
    }

    fn try_dispatch(&self, stream: RelayStream) -> Option<RelayStream> {
        let members = self.members.lock().unwrap();
        if members.is_empty() {
            return None;
        }
        let start = self.next.fetch_add(1, Ordering::Relaxed) % members.len();
        for offset in 0..members.len() {
            let (_, sender) = &members[(start + offset) % members.len()];
            // A busy or closed member must not block another open member. The
            // reservation and send happen before releasing the membership lock.
            if let Ok(permit) = sender.try_reserve() {
                permit.send(stream);
                return None;
            }
        }
        Some(stream)
    }

    /// Select one live member for a stream that has moved no bytes yet. The
    /// ingress owner acceptor uses this directly after binding to the endpoint.
    pub async fn dispatch(&self, stream: RelayStream) {
        let Some(stream) = self.try_dispatch(stream) else {
            return;
        };
        // Preserve the listener's backpressure during short bursts. Only this
        // dispatcher holds one extra stream; it never spawns waiting tasks.
        let _ = timeout(Duration::from_secs(2), async {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let candidates = self.members.lock().unwrap().clone();
                let mut ready = candidates.into_iter().map(|(id, sender)| async move {
                    let permit = sender.clone().reserve_owned().await;
                    (id, sender, permit)
                }).collect::<FuturesUnordered<_>>();
                loop {
                    tokio::select! {
                        () = &mut changed => break,
                        candidate = ready.next() => {
                            let Some((id, sender, Ok(permit))) = candidate else {
                                if ready.is_empty() { return; }
                                continue;
                            };
                            let members = self.members.lock().unwrap();
                            if members.iter().any(|(current, active)| *current == id && active.same_channel(&sender)) {
                                permit.send(stream);
                                return;
                            }
                        }
                    }
                }
            }
        }).await;
    }

    pub fn spawn<S: IntoRelayStream>(
        self: &Arc<Self>,
        mut accepted: mpsc::Receiver<S>,
    ) -> JoinHandle<()> {
        let dispatcher = self.clone();
        tokio::spawn(async move {
            while let Some(stream) = accepted.recv().await {
                if let Ok(stream) = stream.into_relay_stream() {
                    dispatcher.dispatch(stream).await;
                }
            }
        })
    }
}

/// Held by endpoint authority, never by a per-connector forwarding task.
pub struct StreamEndpoint {
    pub port: u16,
    pub dispatcher: Arc<StreamDispatcher>,
    pub task: JoinHandle<()>,
}

impl Drop for StreamEndpoint {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn accepted() -> (RelayStream, tokio::io::DuplexStream) {
        let (io, peer) = tokio::io::duplex(16);
        (
            RelayStream {
                io: Box::new(io),
                source_addr: "127.0.0.1:1234".parse().unwrap(),
                prefix: vec![],
                permit: None,
                admission: None,
            },
            peer,
        )
    }

    #[tokio::test]
    async fn balances_before_bytes_skips_busy_members_and_preserves_pinned_streams() {
        let dispatcher = StreamDispatcher::default();
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        let (a, mut a_rx) = mpsc::channel(1);
        let (b, mut b_rx) = mpsc::channel(1);
        dispatcher.add(first, a).unwrap();
        dispatcher.add(second, b).unwrap();
        let (one, mut first_peer) = accepted();
        dispatcher.dispatch(one).await;
        let mut pinned = a_rx.recv().await.unwrap();
        let (two, _second_peer) = accepted();
        dispatcher.dispatch(two).await;
        assert!(b_rx.try_recv().is_ok());
        let (three, _third_peer) = accepted();
        dispatcher.dispatch(three).await; // Fill A's queue.
        let (four, _fourth_peer) = accepted();
        dispatcher.dispatch(four).await; // Fill B's queue.
        let mut second_pinned = b_rx.recv().await.unwrap();
        let (five, mut fifth_peer) = accepted();
        dispatcher.dispatch(five).await; // A is full, so B receives it.
        let mut fallback = b_rx.recv().await.unwrap();
        dispatcher.remove(first);
        dispatcher.remove(first); // Delayed duplicate cleanup is harmless.
        first_peer.write_all(b"A").await.unwrap();
        assert_eq!(pinned.io.read_u8().await.unwrap(), b'A');
        fifth_peer.write_all(b"B").await.unwrap();
        assert_eq!(fallback.io.read_u8().await.unwrap(), b'B');
        second_pinned.io.write_all(b"still pinned").await.unwrap();
        drop(b_rx);
        let (closed, mut peer) = accepted();
        dispatcher.dispatch(closed).await;
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn burst_waits_for_capacity_and_never_delivers_to_a_removed_member() {
        let dispatcher = Arc::new(StreamDispatcher::default());
        let first = uuid::Uuid::new_v4();
        let (sender, mut receiver) = mpsc::channel(1);
        dispatcher.add(first, sender).unwrap();
        dispatcher.dispatch(accepted().0).await;
        let (queued, mut peer) = accepted();
        let pending = tokio::spawn({
            let dispatcher = dispatcher.clone();
            async move { dispatcher.dispatch(queued).await }
        });
        tokio::task::yield_now().await;
        assert!(!pending.is_finished());
        dispatcher.remove(first);
        let (replacement, mut replacement_rx) = mpsc::channel(1);
        dispatcher.add(uuid::Uuid::new_v4(), replacement).unwrap();
        pending.await.unwrap();
        let mut stream = replacement_rx.recv().await.unwrap();
        peer.write_all(b"new").await.unwrap();
        let mut bytes = [0; 3];
        stream.io.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"new");
        assert!(receiver.try_recv().is_ok());
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn saturated_member_wait_is_bounded_and_releases_the_pending_stream() {
        let dispatcher = Arc::new(StreamDispatcher::default());
        let (sender, _receiver) = mpsc::channel(1);
        dispatcher.add(uuid::Uuid::new_v4(), sender).unwrap();
        dispatcher.dispatch(accepted().0).await;
        let (queued, mut peer) = accepted();
        let started = tokio::time::Instant::now();
        dispatcher.dispatch(queued).await;
        assert_eq!(started.elapsed(), Duration::from_secs(2));
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    }
}
