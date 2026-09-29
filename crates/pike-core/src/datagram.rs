//! UDP packets over either reliable tunnel transport. The outer Data/Credit/
//! End records reuse the bounded stream codec; each UDP packet has its own
//! four-byte length, independent of transport reads and Data frame boundaries.
use std::{net::SocketAddr, pin::Pin, sync::Arc, time::Duration};

use anyhow::{bail, ensure, Result};
use tokio::{
    io::{AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    sync::{mpsc, watch},
    time::{timeout, Instant},
};

use crate::byte_stream::Direction;
use crate::http_wire::{Decoder, Envelope, HttpFrame as Frame, Writer, DATA_CHUNK_BYTES};

pub const MAX_PACKET_BYTES: usize = 65_507;
pub const MAX_PEERS: usize = 32;
pub const QUEUE_PACKETS: usize = 4;
/// Explicit, bounded OS queues also permit full-size datagrams on hosts whose
/// default UDP send buffer is smaller than one maximum packet (including macOS).
pub fn configure_socket(socket: &UdpSocket) -> std::io::Result<()> {
    let socket = socket2::SockRef::from(socket);
    socket.set_send_buffer_size(4 * 65_536)?;
    socket.set_recv_buffer_size(4 * 65_536)
}

const IO_TIMEOUT: Duration = Duration::from_secs(2);

pub struct Input {
    pub payload: Vec<u8>,
    pub fin: bool,
    reservation: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl Input {
    pub fn new(payload: Vec<u8>, fin: bool) -> Self {
        Self {
            payload,
            fin,
            reservation: None,
        }
    }
}

#[derive(Clone)]
pub struct Sender {
    channel: mpsc::Sender<Input>,
    capacity: Arc<tokio::sync::Semaphore>,
}

/// Transport read boundaries can be much smaller than a packet. Bound both
/// bytes and metadata, while allowing a burst of fragments to reach the codec.
pub fn channel() -> (Sender, mpsc::Receiver<Input>) {
    let (sender, receiver) = mpsc::channel(64);
    (
        Sender {
            channel: sender,
            capacity: Arc::new(tokio::sync::Semaphore::new(128 * 1024)),
        },
        receiver,
    )
}

impl Sender {
    pub fn try_send(&self, mut input: Input) -> std::result::Result<(), Input> {
        if input.reservation.is_none() {
            let Ok(cost) = u32::try_from(input.payload.len().max(128)) else {
                return Err(input);
            };
            let Ok(permit) = self.capacity.clone().try_acquire_many_owned(cost) else {
                return Err(input);
            };
            input.reservation = Some(permit);
        }
        self.channel
            .try_send(input)
            .map_err(tokio::sync::mpsc::error::TrySendError::into_inner)
    }
}

/// The relay demultiplexes a public socket; the connector has one connected
/// socket per client. Connected sockets reject replies from other origins.
pub enum Source {
    Public(mpsc::Receiver<Vec<u8>>),
    Connected(Arc<UdpSocket>),
}

impl Source {
    async fn recv(&mut self, buffer: &mut [u8]) -> Result<Vec<u8>> {
        match self {
            Self::Public(input) => input
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("UDP listener closed")),
            Self::Connected(socket) => {
                let size = socket.recv(buffer).await?;
                Ok(buffer[..size].to_vec())
            }
        }
    }
}

/// Where replies for one association go: the connector's connected socket, the
/// relay's public socket, or a length-framed stream to an ingress frontend.
pub enum Reply {
    Connected(Arc<UdpSocket>),
    Peer(Arc<UdpSocket>, SocketAddr),
    Stream(Pin<Box<dyn AsyncWrite + Send>>),
}

impl Reply {
    async fn send(&mut self, packet: &[u8]) -> Result<()> {
        let delivered = match self {
            Self::Connected(socket) => socket.send(packet).await?,
            Self::Peer(socket, peer) => socket.send_to(packet, *peer).await?,
            Self::Stream(writer) => {
                writer.write_all(&frame(packet)?).await?;
                writer.flush().await?;
                packet.len()
            }
        };
        ensure!(delivered == packet.len(), "partial UDP send");
        Ok(())
    }
}

/// One packet with its four-byte length prefix, as carried on any stream.
pub fn frame(packet: &[u8]) -> Result<Vec<u8>> {
    ensure!(packet.len() <= MAX_PACKET_BYTES, "UDP packet too large");
    let mut encoded = Vec::with_capacity(packet.len() + 4);
    encoded.extend(u32::try_from(packet.len())?.to_be_bytes());
    encoded.extend_from_slice(packet);
    Ok(encoded)
}

/// Reassembles length-prefixed packets from arbitrary stream boundaries.
#[derive(Default)]
pub struct Packets {
    buffer: Vec<u8>,
}

impl Packets {
    pub fn feed(&mut self, mut bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
        let mut packets = Vec::new();
        while !bytes.is_empty() {
            let wanted = if self.buffer.len() < 4 {
                4
            } else {
                4 + u32::from_be_bytes(self.buffer[..4].try_into()?) as usize
            };
            let take = (wanted - self.buffer.len()).min(bytes.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buffer.len() < 4 {
                continue;
            }
            let size = u32::from_be_bytes(self.buffer[..4].try_into()?) as usize;
            ensure!(size <= MAX_PACKET_BYTES, "UDP packet too large");
            if self.buffer.len() == size + 4 {
                packets.push(self.buffer[4..].to_vec());
                self.buffer.clear();
            }
        }
        Ok(packets)
    }

    pub fn finish(&self) -> Result<()> {
        ensure!(self.buffer.is_empty(), "truncated UDP packet");
        Ok(())
    }
}

async fn send_packets<T: Envelope, F: std::future::Future<Output = Result<()>> + Send>(
    source: &mut Source,
    writer: &Writer<T>,
    activity: &watch::Sender<Instant>,
    account: &(impl Fn(Direction, usize) -> F + Send + Sync),
) -> Result<()> {
    let mut buffer = vec![
        0;
        if matches!(source, Source::Connected(_)) {
            65_535
        } else {
            0
        }
    ]; // Detect oversize instead of truncating.
    loop {
        let packet = source.recv(&mut buffer).await?;
        if packet.len() > MAX_PACKET_BYTES {
            continue;
        }
        timeout(IO_TIMEOUT, account(Direction::SocketToTunnel, packet.len())).await??;
        activity.send_replace(Instant::now());
        let encoded = frame(&packet)?;
        // One deadline for the complete packet, including credit waits.
        timeout(IO_TIMEOUT, async {
            for chunk in encoded.chunks(DATA_CHUNK_BYTES) {
                writer.send(Frame::Data(chunk.to_vec()), false).await?;
            }
            Ok::<_, anyhow::Error>(())
        })
        .await??;
    }
}

/// Owns both directions and closes the peer on timeout, malformed data or
/// cancellation. Only packet activity extends idle life, never window credits.
pub async fn forward<T: Envelope, F: std::future::Future<Output = Result<()>> + Send>(
    writer: Writer<T>,
    mut inbound: mpsc::Receiver<Input>,
    mut source: Source,
    mut destination: Reply,
    idle: Duration,
    mut cancelled: watch::Receiver<bool>,
    account: impl Fn(Direction, usize) -> F + Send + Sync,
) -> Result<()> {
    let (activity, mut latest) = watch::channel(Instant::now());
    let send = send_packets(&mut source, &writer, &activity, &account);
    let receive = async {
        let mut frames = Decoder::default();
        let mut packets = Packets::default();
        while let Some(input) = inbound.recv().await {
            for frame in frames.feed(&input.payload, input.fin)? {
                match frame {
                    Frame::Data(bytes) => {
                        for packet in packets.feed(&bytes)? {
                            timeout(IO_TIMEOUT, account(Direction::TunnelToSocket, packet.len()))
                                .await??;
                            timeout(IO_TIMEOUT, destination.send(&packet)).await??;
                            activity.send_replace(Instant::now());
                        }
                        timeout(IO_TIMEOUT, writer.consumed(bytes.len())).await??;
                    }
                    Frame::Credit(count) => writer.grant(count)?,
                    Frame::End => {
                        packets.finish()?;
                        return Ok(());
                    }
                    Frame::Reset(reason) => bail!("UDP peer reset: {reason}"),
                    _ => bail!("non-datagram frame on UDP stream"),
                }
            }
        }
        bail!("UDP transport closed before End")
    };
    let expiry = async {
        loop {
            let deadline = *latest.borrow_and_update() + idle;
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => break,
                result = latest.changed() => { if result.is_err() { break; } },
            }
        }
    };
    let result = tokio::select! {
        biased;
        _ = cancelled.changed() => Ok(()),
        _ = expiry => Ok(()),
        result = receive => result,
        result = send => result,
    };
    let _ = timeout(IO_TIMEOUT, writer.send(Frame::End, true)).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundaries_survive_every_split_and_empty_packets() {
        let packets = [vec![], vec![0, 255, 3], vec![7; MAX_PACKET_BYTES], vec![]];
        let encoded: Vec<u8> = packets
            .iter()
            .flat_map(|packet| {
                let mut data = (packet.len() as u32).to_be_bytes().to_vec();
                data.extend(packet);
                data
            })
            .collect();
        for chunk_size in [1, 2, 3, 4, 17, DATA_CHUNK_BYTES, encoded.len()] {
            let mut decoder = Packets::default();
            let mut actual = Vec::new();
            for chunk in encoded.chunks(chunk_size) {
                actual.extend(decoder.feed(chunk).unwrap());
            }
            decoder.finish().unwrap();
            assert_eq!(actual, packets);
        }
    }

    #[test]
    fn reject_oversize_length_before_allocation_and_truncation() {
        let mut decoder = Packets::default();
        assert!(decoder.feed(&u32::MAX.to_be_bytes()).is_err());
        assert_eq!(decoder.buffer.len(), 4);
        let mut decoder = Packets::default();
        decoder.feed(&[0, 0, 0, 2, 5]).unwrap();
        assert!(decoder.finish().is_err());
    }

    #[tokio::test]
    async fn receive_queue_bounds_bytes_and_metadata_and_releases_capacity() {
        let (sender, mut input) = channel();
        assert!(sender
            .try_send(Input::new(vec![0; 128 * 1024], false))
            .is_ok());
        assert!(sender.try_send(Input::new(vec![1], false)).is_err());
        drop(input.recv().await.unwrap());
        for _ in 0..64 {
            assert!(sender.try_send(Input::new(vec![], false)).is_ok());
        }
        assert!(sender.try_send(Input::new(vec![], false)).is_err());
        drop(input);
        assert_eq!(sender.capacity.available_permits(), 128 * 1024);
        assert!(sender.try_send(Input::new(vec![1], false)).is_err());
    }
}
