//! Flow-controlled bidirectional bytes. Ingress decodes credits separately from
//! socket writes, so a slow consumer cannot block another stream or its reverse
//! direction. Logical End half-closes the socket; transport FIN waits for both.
use anyhow::{bail, Result};
use http_body_util::BodyExt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
    time::{timeout, Duration},
};

use crate::http_wire::{
    body_channel, BodySender, Decoder, Envelope, HttpFrame as Frame, IncomingBody, Writer,
    DATA_CHUNK_BYTES,
};

const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// Direction relative to the socket at this end of a tunnel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    SocketToTunnel,
    TunnelToSocket,
}

pub struct Ingress<T> {
    decoder: Decoder,
    body: BodySender,
    writer: Writer<T>,
}

pub struct Stream<T> {
    writer: Writer<T>,
    incoming: IncomingBody,
}

pub fn channel<T: Envelope + Sync + 'static>(writer: Writer<T>) -> (Ingress<T>, Stream<T>) {
    let (body, incoming) = body_channel(writer.clone());
    (
        Ingress {
            decoder: Decoder::default(),
            body,
            writer: writer.clone(),
        },
        Stream { writer, incoming },
    )
}

impl<T: Envelope> Ingress<T> {
    /// Synchronous and bounded by the receive window, regardless of transport
    /// fragmentation. No waiting for the destination socket in the dispatcher.
    pub fn feed(&mut self, bytes: &[u8], fin: bool) -> Result<()> {
        for frame in self.decoder.feed(bytes, fin)? {
            match frame {
                Frame::Credit(count) => self.writer.grant(count)?,
                Frame::Data(_) | Frame::End => self.body.try_send(Ok(frame))?,
                Frame::Reset(reason) => bail!("byte-stream peer reset: {reason}"),
                _ => bail!("unexpected frame on byte stream"),
            }
        }
        Ok(())
    }
}

impl<T: Envelope + Sync> Stream<T> {
    /// Consume decoded bytes and write framed bytes directly when a protocol
    /// handshake must finish before its socket can be forwarded. Ingress still
    /// handles credits independently; polling the body returns receive credit.
    pub fn into_parts(self) -> (Writer<T>, IncomingBody) {
        (self.writer, self.incoming)
    }

    pub async fn reset(self, reason: &str) {
        let _ = timeout(
            Duration::from_secs(2),
            self.writer.send(Frame::Reset(reason.into()), true),
        )
        .await;
    }

    pub async fn forward<
        S: AsyncRead + AsyncWrite + Unpin,
        F: std::future::Future<Output = Result<()>> + Send,
    >(
        mut self,
        socket: S,
        prefix: &[u8],
        mut cancelled: watch::Receiver<bool>,
        account: impl Fn(Direction, usize) -> F + Send + Sync,
    ) -> Result<()> {
        let (mut read, mut write) = tokio::io::split(socket);
        let send = async {
            for bytes in prefix.chunks(DATA_CHUNK_BYTES) {
                timeout(
                    WRITE_TIMEOUT,
                    account(Direction::SocketToTunnel, bytes.len()),
                )
                .await??;
                timeout(
                    WRITE_TIMEOUT,
                    self.writer.send(Frame::Data(bytes.to_vec()), false),
                )
                .await??;
            }
            let mut buffer = vec![0; DATA_CHUNK_BYTES];
            loop {
                let count = read.read(&mut buffer).await?;
                if count == 0 {
                    timeout(WRITE_TIMEOUT, self.writer.send(Frame::End, false)).await??;
                    return Ok::<_, anyhow::Error>(());
                }
                timeout(WRITE_TIMEOUT, account(Direction::SocketToTunnel, count)).await??;
                timeout(
                    WRITE_TIMEOUT,
                    self.writer
                        .send(Frame::Data(buffer[..count].to_vec()), false),
                )
                .await??;
            }
        };
        let receive = async {
            while let Some(frame) = self.incoming.frame().await {
                let frame = frame?;
                let bytes = frame
                    .data_ref()
                    .ok_or_else(|| anyhow::anyhow!("non-data byte-stream body"))?;
                timeout(
                    WRITE_TIMEOUT,
                    account(Direction::TunnelToSocket, bytes.len()),
                )
                .await??;
                timeout(WRITE_TIMEOUT, write.write_all(bytes)).await??;
            }
            timeout(WRITE_TIMEOUT, write.shutdown()).await??;
            Ok::<_, anyhow::Error>(())
        };
        let result = tokio::select! {
            biased;
            _ = cancelled.changed() => Err(anyhow::anyhow!("byte stream cancelled")),
            result = async { tokio::try_join!(send, receive)?; Ok(()) } => result,
        };
        match result {
            Ok(()) => timeout(Duration::from_secs(2), self.writer.finish()).await?,
            Err(error) => {
                self.reset("socket closed or forwarding failed").await;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_wire::{encode, INITIAL_WINDOW};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::sync::mpsc;

    #[derive(Clone)]
    struct Packet {
        bytes: Vec<u8>,
        fin: bool,
    }
    impl Envelope for Packet {
        fn with_frame(&self, bytes: Vec<u8>, fin: bool) -> Self {
            Self { bytes, fin }
        }
    }
    fn endpoint() -> (Ingress<Packet>, Stream<Packet>, mpsc::Receiver<Packet>) {
        let (tx, rx) = mpsc::channel(4);
        let (input, stream) = channel(Writer::new(
            tx,
            Packet {
                bytes: vec![],
                fin: false,
            },
        ));
        (input, stream, rx)
    }
    async fn deliver(
        mut wire: mpsc::Receiver<Packet>,
        mut input: Ingress<Packet>,
        count: Arc<AtomicUsize>,
    ) {
        while let Some(packet) = wire.recv().await {
            count.fetch_add(packet.bytes.len(), Ordering::Relaxed);
            // Worst-case fragmentation must not consume queue entries before
            // decoding a complete frame.
            for byte in packet.bytes {
                input.feed(&[byte], false).unwrap();
            }
            input.feed(&[], packet.fin).unwrap();
            if packet.fin {
                break;
            }
        }
    }

    // Virtual time advances only after runnable forwarding tasks quiesce, so
    // a busy host cannot mistake an unfinished initial burst for excess credit.
    #[tokio::test(start_paused = true)]
    async fn stalled_consumer_backpressures_then_resumes_without_losing_bytes_or_half_closes() {
        timeout(Duration::from_secs(10), async {
            let (left_input, left_stream, left_wire) = endpoint();
            let (right_input, right_stream, right_wire) = endpoint();
            let sent = Arc::new(AtomicUsize::new(0));
            let left_delivery = tokio::spawn(deliver(left_wire, right_input, sent.clone()));
            let right_delivery = tokio::spawn(deliver(right_wire, left_input, Arc::default()));
            let (mut public, left) = tokio::io::duplex(1024);
            let (mut origin, right) = tokio::io::duplex(1024);
            let (_left_cancel, left_cancelled) = watch::channel(false);
            let (_right_cancel, right_cancelled) = watch::channel(false);
            let left_forward =
                tokio::spawn(
                    left_stream
                        .forward(left, &[], left_cancelled, |_, _| std::future::ready(Ok(()))),
                );
            let right_forward =
                tokio::spawn(right_stream.forward(right, &[], right_cancelled, |_, _| {
                    std::future::ready(Ok(()))
                }));
            let payload: Vec<u8> = (0..=255).cycle().take(512 * 1024).collect();
            let client_payload = payload.clone();
            let client = tokio::spawn(async move {
                assert_eq!(public.read_u8().await.unwrap(), b'B');
                public.write_all(&client_payload).await.unwrap();
                public.shutdown().await.unwrap();
                let mut reply = vec![];
                public.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, b"reply after EOF");
            });
            origin.write_all(b"B").await.unwrap();
            tokio::time::sleep(Duration::from_millis(150)).await;
            let first = sent.load(Ordering::Relaxed);
            assert!(
                first > 0 && first < INITIAL_WINDOW * 2 + 4096,
                "unbounded send: {first}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(
                sent.load(Ordering::Relaxed),
                first,
                "sender did not stop at credit window"
            );
            assert!(
                !client.is_finished(),
                "blocked socket was cancelled instead of backpressured"
            );
            let mut received = vec![];
            origin.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, payload);
            origin.write_all(b"reply after EOF").await.unwrap();
            origin.shutdown().await.unwrap();
            client.await.unwrap();
            left_forward.await.unwrap().unwrap();
            right_forward.await.unwrap().unwrap();
            // A peer may finish and drop its ingress before the final empty FIN.
            left_delivery.abort();
            right_delivery.abort();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn burst_of_tiny_frames_waits_for_consumer_and_over_credit_is_rejected() {
        let (mut input, _stream, _wire) = endpoint();
        let frame = encode(&Frame::Data(vec![7])).unwrap();
        for _ in 0..64 {
            input.feed(&frame, false).unwrap();
        }
        assert!(input.feed(&frame, false).is_err());
        let (mut independent, _other, _wire) = endpoint();
        independent.feed(&frame, false).unwrap();
        independent
            .feed(&encode(&Frame::End).unwrap(), true)
            .unwrap();
    }

    #[tokio::test]
    async fn malformed_frames_and_forged_credits_fail_closed() {
        for bytes in [
            encode(&Frame::Credit(1)).unwrap(),
            encode(&Frame::Request {
                method: "GET".into(),
                target: "/".into(),
                headers: vec![],
            })
            .unwrap(),
            vec![255; 4],
        ] {
            let (mut input, _stream, _wire) = endpoint();
            assert!(input.feed(&bytes, false).is_err());
        }
        let (mut input, _stream, _wire) = endpoint();
        assert!(input.feed(&[], true).is_err());
    }

    #[tokio::test]
    async fn rejected_accounting_does_not_forward_bytes_in_either_direction() {
        for direction in [Direction::SocketToTunnel, Direction::TunnelToSocket] {
            let (mut input, stream, mut wire) = endpoint();
            let (mut peer, socket) = tokio::io::duplex(1024);
            let (_cancel, cancelled) = watch::channel(false);
            if direction == Direction::SocketToTunnel {
                peer.write_all(b"must not forward").await.unwrap();
            } else {
                input
                    .feed(
                        &encode(&Frame::Data(b"must not forward".to_vec())).unwrap(),
                        false,
                    )
                    .unwrap();
            }
            let result = stream
                .forward(socket, &[], cancelled, move |observed, _| {
                    assert_eq!(observed, direction);
                    std::future::ready(Err(anyhow::anyhow!("usage journal unavailable")))
                })
                .await;
            assert!(result.is_err());
            let mut frames = Vec::new();
            let mut decoder = Decoder::default();
            while let Ok(packet) = wire.try_recv() {
                frames.extend(decoder.feed(&packet.bytes, packet.fin).unwrap());
            }
            assert!(frames
                .iter()
                .all(|frame| matches!(frame, Frame::Credit(_) | Frame::Reset(_))));
            assert!(frames.iter().any(|frame| matches!(frame, Frame::Reset(_))));
            let mut received = vec![];
            peer.read_to_end(&mut received).await.unwrap();
            assert!(received.is_empty());
        }
    }

    #[tokio::test]
    async fn cancellation_closes_socket_and_emits_one_terminal_reset() {
        let (_input, stream, mut wire) = endpoint();
        let (mut peer, socket) = tokio::io::duplex(1024);
        let (cancel, cancelled) = watch::channel(false);
        let task =
            tokio::spawn(stream.forward(socket, &[], cancelled, |_, _| std::future::ready(Ok(()))));
        cancel.send(true).unwrap();
        assert!(task.await.unwrap().is_err());
        let end = wire.recv().await.unwrap();
        assert!(end.fin);
        assert!(matches!(
            Decoder::default()
                .feed(&end.bytes, true)
                .unwrap()
                .as_slice(),
            [Frame::Reset(_)]
        ));
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        assert!(wire.try_recv().is_err());
    }
}
