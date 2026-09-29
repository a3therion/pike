//! Bounded HTTP messages independent of QUIC and WebSocket delivery boundaries.
//!
//! Bodies and trailers remain frames, never a whole-request allocation. The
//! enclosing stream mode selects this codec; content sniffing is not required.
use anyhow::{bail, ensure, Result};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};

pub const DEFAULT_MAX_REQUEST_BYTES: u64 = 200_000_000;
/// Large active uploads may need minutes before the origin sends response headers.
pub const RESPONSE_HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);
pub const DATA_CHUNK_BYTES: usize = 32 * 1024;
pub const MAX_FRAME_BYTES: usize = 96 * 1024;
const MAX_DELIVERY_BYTES: usize = 256 * 1024;
#[derive(Clone, Copy)]
pub struct RequestLimit(pub u64);

pub const INITIAL_WINDOW: usize = 64 * 1024;
// Charge small chunks for their metadata too: at most 64 unconsumed frames.
const MIN_FRAME_CREDIT: usize = 1024;

pub type Headers = Vec<(String, Vec<u8>)>;

/// Adapters keep the stream identity fixed while replacing only frame bytes.
pub trait Envelope: Clone + Send {
    fn with_frame(&self, payload: Vec<u8>, fin: bool) -> Self;
}

/// Per-stream credit is independent of connection-wide transport queues. A slow
/// body consumer stops this writer without blocking other request dispatchers.
#[derive(Clone)]
pub struct Writer<T> {
    sender: tokio::sync::mpsc::Sender<T>,
    template: T,
    credits: std::sync::Arc<tokio::sync::Semaphore>,
    outstanding: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    sealed: std::sync::Arc<tokio::sync::Mutex<bool>>,
}

impl<T: Envelope> Writer<T> {
    pub fn new(sender: tokio::sync::mpsc::Sender<T>, template: T) -> Self {
        Self {
            sender,
            template,
            sealed: std::sync::Arc::new(tokio::sync::Mutex::new(false)),
            outstanding: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            credits: std::sync::Arc::new(tokio::sync::Semaphore::new(INITIAL_WINDOW)),
        }
    }

    pub fn grant(&self, count: u32) -> Result<()> {
        let count = count as usize;
        ensure!(
            count > 0
                && self
                    .outstanding
                    .fetch_update(
                        std::sync::atomic::Ordering::AcqRel,
                        std::sync::atomic::Ordering::Acquire,
                        |debt| debt.checked_sub(count)
                    )
                    .is_ok(),
            "invalid HTTP window credit"
        );
        self.credits.add_permits(count);
        Ok(())
    }

    pub async fn send(&self, frame: HttpFrame, fin: bool) -> Result<()> {
        if let HttpFrame::Data(bytes) = &frame {
            ensure!(
                !bytes.is_empty() && bytes.len() <= DATA_CHUNK_BYTES,
                "invalid HTTP data frame size"
            );
            let cost = bytes.len().max(MIN_FRAME_CREDIT);
            self.credits
                .acquire_many(u32::try_from(cost)?)
                .await?
                .forget();
            self.outstanding
                .fetch_add(cost, std::sync::atomic::Ordering::Release);
        }
        let encoded = encode(&frame)?;
        // Credit callbacks can race an early response or cancellation. Serialize
        // the final marker with all sends so none can follow it on the transport.
        let mut sealed = self.sealed.lock().await;
        ensure!(!*sealed, "HTTP stream already closed");
        self.sender
            .send(self.template.with_frame(encoded, fin))
            .await
            .map_err(|_| anyhow::anyhow!("HTTP transport closed"))?;
        *sealed = fin;
        if fin {
            self.credits.close();
        }
        Ok(())
    }

    /// Close transport output after a logical End while allowing credits during
    /// a byte stream's half-close. Serializes with every cloned writer.
    pub async fn finish(&self) -> Result<()> {
        let mut sealed = self.sealed.lock().await;
        ensure!(!*sealed, "stream already closed");
        self.sender
            .send(self.template.with_frame(vec![], true))
            .await
            .map_err(|_| anyhow::anyhow!("transport closed"))?;
        *sealed = true;
        self.credits.close();
        Ok(())
    }

    pub async fn consumed(&self, count: usize) -> Result<()> {
        if count > 0 {
            self.send(
                HttpFrame::Credit(u32::try_from(count.max(MIN_FRAME_CREDIT))?),
                false,
            )
            .await?;
        }
        Ok(())
    }
}

impl Envelope for crate::quic::client::LocalData {
    fn with_frame(&self, payload: Vec<u8>, fin: bool) -> Self {
        Self {
            payload,
            fin,
            ..self.clone()
        }
    }
}

impl Envelope for crate::quic::server::PikeOutboundMessage {
    fn with_frame(&self, payload: Vec<u8>, fin: bool) -> Self {
        match self {
            Self::Data(data) => Self::Data(crate::quic::server::OutboundData {
                payload,
                fin,
                ..data.clone()
            }),
            Self::Control(_) => unreachable!("HTTP writer requires a data template"),
        }
    }
}

/// Remove hop-specific headers, including fields nominated by Connection.
pub fn headers_to_wire(headers: &http::HeaderMap) -> Headers {
    let nominated: Vec<_> = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| {
            value
                .split(',')
                .map(|name| name.trim().to_ascii_lowercase())
        })
        .collect();
    headers
        .iter()
        .filter(|(name, _)| {
            !crate::http_response::is_hop_by_hop(name.as_str())
                && !nominated.iter().any(|item| item == name.as_str())
        })
        .map(|(name, value)| (name.to_string(), value.as_bytes().to_vec()))
        .collect()
}

pub fn headers_from_wire(headers: Headers) -> Result<http::HeaderMap> {
    let mut result = http::HeaderMap::new();
    for (name, value) in headers {
        result.append(
            http::HeaderName::from_bytes(name.as_bytes())?,
            http::HeaderValue::from_bytes(&value)?,
        );
    }
    let clean = headers_to_wire(&result);
    result.clear();
    for (name, value) in clean {
        result.append(
            http::HeaderName::from_bytes(name.as_bytes())?,
            http::HeaderValue::from_bytes(&value)?,
        );
    }
    Ok(result)
}

#[derive(Clone)]
pub struct BodySender {
    sender: tokio::sync::mpsc::Sender<std::result::Result<HttpFrame, String>>,
    queued: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    phase: std::sync::Arc<std::sync::atomic::AtomicU8>,
}
impl BodySender {
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
    pub async fn closed(&self) {
        self.sender.closed().await;
    }
    pub fn try_send(&self, frame: std::result::Result<HttpFrame, String>) -> Result<()> {
        use std::sync::atomic::Ordering;
        match &frame {
            Ok(HttpFrame::Data(bytes)) => ensure!(
                !bytes.is_empty()
                    && bytes.len() <= DATA_CHUNK_BYTES
                    && self.phase.load(Ordering::Acquire) == 0,
                "invalid HTTP body data sequence"
            ),
            Ok(HttpFrame::Trailers(_)) => {
                self.phase
                    .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                    .map_err(|_| anyhow::anyhow!("duplicate or late HTTP trailers"))?;
            }
            Ok(HttpFrame::End) => ensure!(
                self.phase.swap(2, Ordering::AcqRel) < 2,
                "duplicate HTTP end"
            ),
            Err(_) => {}
            _ => bail!("unexpected HTTP body frame"),
        }
        let cost = match &frame {
            Ok(HttpFrame::Data(bytes)) => bytes.len().max(MIN_FRAME_CREDIT),
            _ => 0,
        };
        self.queued
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |queued| {
                queued
                    .checked_add(cost)
                    .filter(|next| *next <= INITIAL_WINDOW)
            })
            .map_err(|_| anyhow::anyhow!("peer exceeded HTTP receive window"))?;
        if self.sender.try_send(frame).is_err() {
            self.queued.fetch_sub(cost, Ordering::Release);
            bail!("HTTP body consumer closed or stalled");
        }
        Ok(())
    }
}
pub type IncomingBody = http_body_util::combinators::UnsyncBoxBody<bytes::Bytes, std::io::Error>;

/// Credits are returned when the HTTP stack polls the body, not when transport
/// packets arrive. An explicit End distinguishes completion from disconnection.
pub fn body_channel<T: Envelope + Sync + 'static>(writer: Writer<T>) -> (BodySender, IncomingBody) {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<std::result::Result<HttpFrame, String>>(128);
    let queued = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let consumed = queued.clone();
    let stream = async_stream::try_stream! {
        let mut trailers_seen = false;
        loop {
            let frame = rx.recv().await.ok_or_else(|| std::io::Error::other("HTTP stream disconnected"))?
                .map_err(std::io::Error::other)?;
            match frame {
                HttpFrame::Data(data) if !trailers_seen => {
                    consumed.fetch_sub(data.len().max(MIN_FRAME_CREDIT), std::sync::atomic::Ordering::Release);
                    writer.consumed(data.len()).await.map_err(std::io::Error::other)?;
                    yield http_body::Frame::data(bytes::Bytes::from(data));
                }
                HttpFrame::Trailers(headers) if !trailers_seen => {
                    trailers_seen = true;
                    yield http_body::Frame::trailers(headers_from_wire(headers).map_err(std::io::Error::other)?);
                }
                HttpFrame::End => break,
                _ => Err(std::io::Error::other("invalid HTTP body sequence"))?,
            }
        }
    };
    (
        BodySender {
            sender: tx,
            queued,
            phase: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(0)),
        },
        http_body_util::StreamBody::new(stream).boxed_unsync(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpFrame {
    Request {
        method: String,
        target: String,
        headers: Headers,
    },
    Response {
        status: u16,
        headers: Headers,
    },
    Data(Vec<u8>),
    Trailers(Headers),
    End,
    Credit(u32),
    Reset(String),
}

/// Encode one bounded record. Large bodies must be sent in `DATA_CHUNK_BYTES`
/// chunks, so increasing the total upload limit never increases queue entries.
pub fn encode(frame: &HttpFrame) -> Result<Vec<u8>> {
    if let HttpFrame::Data(data) = frame {
        ensure!(
            !data.is_empty() && data.len() <= DATA_CHUNK_BYTES,
            "invalid HTTP data frame size"
        );
    }
    let payload = postcard::to_allocvec(frame)?;
    ensure!(payload.len() <= MAX_FRAME_BYTES, "HTTP frame too large");
    let mut encoded = Vec::with_capacity(payload.len() + 4);
    encoded.extend(u32::try_from(payload.len())?.to_be_bytes());
    encoded.extend(payload);
    Ok(encoded)
}

#[derive(Default)]
pub struct Decoder {
    buffer: Vec<u8>,
    ended: bool,
}

impl Decoder {
    /// Decode fragmented or coalesced transport chunks, keeping at most one
    /// bounded record between calls. FIN without an End/Reset is truncation.
    pub fn feed(&mut self, mut bytes: &[u8], fin: bool) -> Result<Vec<HttpFrame>> {
        ensure!(bytes.len() <= MAX_DELIVERY_BYTES, "HTTP delivery too large");
        let mut frames = Vec::new();
        while !bytes.is_empty() {
            let wanted = if self.buffer.len() < 4 {
                4
            } else {
                let length = u32::from_be_bytes(self.buffer[..4].try_into()?) as usize;
                ensure!(
                    length > 0 && length <= MAX_FRAME_BYTES,
                    "invalid HTTP frame size"
                );
                length + 4
            };
            let take = (wanted - self.buffer.len()).min(bytes.len());
            self.buffer.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.buffer.len() < 4 {
                continue;
            }
            let length = u32::from_be_bytes(self.buffer[..4].try_into()?) as usize;
            ensure!(
                length > 0 && length <= MAX_FRAME_BYTES,
                "invalid HTTP frame size"
            );
            if self.buffer.len() == length + 4 {
                let frame: HttpFrame = postcard::from_bytes(&self.buffer[4..])?;
                if let HttpFrame::Data(data) = &frame {
                    ensure!(
                        !data.is_empty() && data.len() <= DATA_CHUNK_BYTES,
                        "invalid HTTP data frame size"
                    );
                }
                ensure!(
                    !self.ended || matches!(frame, HttpFrame::Credit(_) | HttpFrame::Reset(_)),
                    "HTTP data after end"
                );
                self.ended |= matches!(frame, HttpFrame::End | HttpFrame::Reset(_));
                frames.push(frame);
                self.buffer.clear();
            }
        }
        if fin && (!self.ended || !self.buffer.is_empty()) {
            bail!("truncated HTTP stream");
        }
        Ok(frames)
    }

    #[must_use]
    pub const fn is_ended(&self) -> bool {
        self.ended
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_binary_and_trailers_at_every_fragment_boundary() {
        let frames = vec![
            HttpFrame::Response {
                status: 200,
                headers: vec![("content-type".into(), b"application/grpc".to_vec())],
            },
            HttpFrame::Data(vec![0, 255, 128, 4]),
            HttpFrame::Trailers(vec![("grpc-status".into(), b"0".to_vec())]),
            HttpFrame::End,
        ];
        let wire: Vec<_> = frames.iter().flat_map(|f| encode(f).unwrap()).collect();
        for boundary in 0..=wire.len() {
            let mut decoder = Decoder::default();
            let mut result = decoder.feed(&wire[..boundary], false).unwrap();
            result.extend(decoder.feed(&wire[boundary..], true).unwrap());
            assert_eq!(result, frames);
        }
        let mut decoder = Decoder::default();
        let mut result = vec![];
        for byte in &wire {
            result.extend(decoder.feed(&[*byte], false).unwrap());
        }
        decoder.feed(&[], true).unwrap();
        assert_eq!(result, frames);
    }

    #[test]
    fn rejects_oversize_truncation_and_bytes_after_end() {
        assert!(Decoder::default()
            .feed(&u32::MAX.to_be_bytes(), false)
            .is_err());
        assert!(Decoder::default().feed(&[0, 0], true).is_err());
        assert!(encode(&HttpFrame::Data(vec![0; DATA_CHUNK_BYTES + 1])).is_err());
        let mut decoder = Decoder::default();
        decoder
            .feed(&encode(&HttpFrame::End).unwrap(), true)
            .unwrap();
        assert!(decoder
            .feed(&encode(&HttpFrame::Data(vec![0])).unwrap(), false)
            .is_err());
    }
    #[derive(Clone)]
    struct Packet(Vec<u8>);
    impl Envelope for Packet {
        fn with_frame(&self, payload: Vec<u8>, _fin: bool) -> Self {
            Self(payload)
        }
    }
    #[tokio::test]
    async fn window_bounds_tiny_frames_and_other_streams_can_progress() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(128);
        let writer = Writer::new(tx.clone(), Packet(vec![]));
        assert!(writer.grant(1).is_err());
        for _ in 0..64 {
            writer.send(HttpFrame::Data(vec![1]), false).await.unwrap();
        }
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(5),
            writer.send(HttpFrame::Data(vec![1]), false)
        )
        .await
        .is_err());
        let other = Writer::new(tx, Packet(vec![]));
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            other.send(HttpFrame::Data(vec![2]), false),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(writer.grant(65537).is_err());
        writer.grant(1024).unwrap();
        writer.send(HttpFrame::Data(vec![3]), false).await.unwrap();
        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 66);
    }
    #[tokio::test]
    async fn body_credit_waits_for_consumer_and_preserves_trailers() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let (sender, mut body) = body_channel(Writer::new(tx, Packet(vec![])));
        sender.try_send(Ok(HttpFrame::Data(vec![0, 255]))).unwrap();
        sender
            .try_send(Ok(HttpFrame::Trailers(vec![(
                "grpc-status".into(),
                b"0".to_vec(),
            )])))
            .unwrap();
        sender.try_send(Ok(HttpFrame::End)).unwrap();
        assert!(rx.try_recv().is_err());
        assert_eq!(
            body.frame()
                .await
                .unwrap()
                .unwrap()
                .into_data()
                .unwrap()
                .as_ref(),
            &[0, 255]
        );
        let credit = Decoder::default()
            .feed(&rx.recv().await.unwrap().0, false)
            .unwrap();
        assert_eq!(credit, vec![HttpFrame::Credit(1024)]);
        assert_eq!(
            body.frame()
                .await
                .unwrap()
                .unwrap()
                .into_trailers()
                .unwrap()["grpc-status"],
            "0"
        );
        assert!(body.frame().await.is_none());
    }
    #[test]
    fn connection_nominated_headers_are_removed_and_binary_values_survive() {
        let mut headers = http::HeaderMap::new();
        headers.insert("connection", "x-private, keep-alive".parse().unwrap());
        headers.insert("x-private", "remove".parse().unwrap());
        headers.insert("x-binary", http::HeaderValue::from_bytes(&[255]).unwrap());
        headers.append("set-cookie", "a=1".parse().unwrap());
        headers.append("set-cookie", "b=2".parse().unwrap());
        let result = headers_from_wire(headers_to_wire(&headers)).unwrap();
        assert!(!result.contains_key("connection"));
        assert!(!result.contains_key("x-private"));
        assert_eq!(result["x-binary"].as_bytes(), &[255]);
        assert_eq!(result.get_all("set-cookie").iter().count(), 2);
    }
    #[tokio::test]
    async fn uncooperative_peer_cannot_exceed_receive_window() {
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let (sender, _body) = body_channel(Writer::new(tx, Packet(vec![])));
        sender
            .try_send(Ok(HttpFrame::Data(vec![0; DATA_CHUNK_BYTES])))
            .unwrap();
        sender
            .try_send(Ok(HttpFrame::Data(vec![0; DATA_CHUNK_BYTES])))
            .unwrap();
        assert!(sender.try_send(Ok(HttpFrame::Data(vec![0]))).is_err());
    }
    #[tokio::test]
    async fn cancellation_seals_all_writer_clones_before_late_credit() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let writer = Writer::new(tx, Packet(vec![]));
        writer
            .send(HttpFrame::Data(vec![0; DATA_CHUNK_BYTES]), false)
            .await
            .unwrap();
        writer
            .send(HttpFrame::Data(vec![0; DATA_CHUNK_BYTES]), false)
            .await
            .unwrap();
        let blocked_writer = writer.clone();
        let blocked =
            tokio::spawn(async move { blocked_writer.send(HttpFrame::Data(vec![1]), false).await });
        let late_body_callback = writer.clone();
        writer
            .send(HttpFrame::Reset("cancelled".into()), true)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), blocked)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(late_body_callback.consumed(12).await.is_err());
        assert!(writer.send(HttpFrame::End, true).await.is_err());
        for _ in 0..3 {
            assert!(rx.try_recv().is_ok());
        }
        assert!(rx.try_recv().is_err());
    }
}
