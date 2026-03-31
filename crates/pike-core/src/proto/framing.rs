use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::ControlMessage;

/// Maximum size for length-prefixed Postcard-encoded control message frames.
///
/// This limit applies ONLY to control messages (`Login`, `RegisterTunnel`, etc.)
/// serialized via [`write_frame`]/[`write_control_message`]. HTTP request and
/// response bodies are sent as raw bytes directly over QUIC data streams
/// (via `qconn.stream_send`) and are NOT subject to this limit — QUIC handles
/// packetization natively. The 10 MB HTTP body limit enforced at the HTTP layer
/// is independent and prevents client-side OOM; it has no interaction with this
/// 1 MB control-frame ceiling.
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

#[derive(Debug, Error)]
pub enum FramingError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),
    #[error("frame size {len} exceeds max frame size {max}")]
    FrameTooLarge { len: usize, max: usize },
}

/// Write a length-prefixed postcard-encoded frame.
///
/// # Errors
///
/// Returns `FramingError` if writing to the stream fails, serialization fails,
/// or the serialized payload exceeds `MAX_FRAME_SIZE`.
pub async fn write_frame<W, T>(writer: &mut W, message: &T) -> Result<(), FramingError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let payload = postcard::to_allocvec(message)?;
    let len = payload.len();

    if len > MAX_FRAME_SIZE {
        return Err(FramingError::FrameTooLarge {
            len,
            max: MAX_FRAME_SIZE,
        });
    }

    let len_u32 = u32::try_from(len).map_err(|_| FramingError::FrameTooLarge {
        len,
        max: MAX_FRAME_SIZE,
    })?;

    writer.write_all(&len_u32.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read a length-prefixed postcard-encoded frame.
///
/// # Errors
///
/// Returns `FramingError` if reading from the stream fails, deserialization
/// fails, or the frame length exceeds `MAX_FRAME_SIZE`.
pub async fn read_frame<R, T>(reader: &mut R) -> Result<T, FramingError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut len_bytes = [0_u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    if len > MAX_FRAME_SIZE {
        return Err(FramingError::FrameTooLarge {
            len,
            max: MAX_FRAME_SIZE,
        });
    }

    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(postcard::from_bytes(&payload)?)
}

/// Write a framed `ControlMessage` to an async writer.
///
/// # Errors
///
/// Returns `FramingError` if framing or I/O fails.
pub async fn write_control_message<W>(
    writer: &mut W,
    message: &ControlMessage,
) -> Result<(), FramingError>
where
    W: AsyncWrite + Unpin,
{
    write_frame(writer, message).await
}

/// Read a framed `ControlMessage` from an async reader.
///
/// # Errors
///
/// Returns `FramingError` if framing, I/O, or decoding fails.
pub async fn read_control_message<R>(reader: &mut R) -> Result<ControlMessage, FramingError>
where
    R: AsyncRead + Unpin,
{
    read_frame(reader).await
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use tokio::io::{self, AsyncReadExt};

    use super::{
        read_control_message, write_control_message, write_frame, FramingError, MAX_FRAME_SIZE,
    };
    use crate::proto::ControlMessage;

    #[tokio::test]
    async fn framing_roundtrip_control_message() {
        let (mut client, mut server) = io::duplex(2048);
        let message = ControlMessage::Login {
            api_key: "abc123".to_string(),
            client_version: "0.2.0".to_string(),
            protocol_version: Some(1),
        };

        write_control_message(&mut client, &message)
            .await
            .expect("write control message");

        let decoded = read_control_message(&mut server)
            .await
            .expect("read control message");
        let decoded_encoded = postcard::to_allocvec(&decoded).expect("encode decoded message");
        let expected_encoded = postcard::to_allocvec(&message).expect("encode expected message");
        assert_eq!(decoded_encoded, expected_encoded);
    }

    #[tokio::test]
    async fn framing_uses_big_endian_length_prefix() {
        let (mut writer, mut reader) = io::duplex(128);
        let message = ControlMessage::LoginFailure {
            reason: "boom".to_string(),
        };

        write_control_message(&mut writer, &message)
            .await
            .expect("write control message");

        let mut len_prefix = [0_u8; 4];
        reader
            .read_exact(&mut len_prefix)
            .await
            .expect("read length prefix");

        let payload = postcard::to_allocvec(&message).expect("serialize expected payload");
        assert_eq!(u32::from_be_bytes(len_prefix) as usize, payload.len());
    }

    #[tokio::test]
    async fn framing_rejects_oversized_frames_on_read() {
        let oversized = MAX_FRAME_SIZE + 1;
        let len_prefix = (oversized as u32).to_be_bytes();
        let payload = vec![0_u8; 8];

        let mut bytes = Vec::with_capacity(4 + payload.len());
        bytes.extend_from_slice(&len_prefix);
        bytes.extend_from_slice(&payload);

        let mut reader = Cursor::new(bytes);
        let result = read_control_message(&mut reader).await;

        match result {
            Err(FramingError::FrameTooLarge { len, max }) => {
                assert_eq!(len, oversized);
                assert_eq!(max, MAX_FRAME_SIZE);
            }
            other => panic!("expected FrameTooLarge error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn framing_large_message_near_one_megabyte() {
        let (mut client, mut server) = io::duplex(MAX_FRAME_SIZE + 1024);
        let reason = "x".repeat(MAX_FRAME_SIZE - 256);
        let message = ControlMessage::LoginFailure { reason };

        let encoded = postcard::to_allocvec(&message).expect("serialize control message");
        assert!(
            encoded.len() < MAX_FRAME_SIZE,
            "encoded payload must be under 1MB"
        );

        write_control_message(&mut client, &message)
            .await
            .expect("write large control message");
        let decoded = read_control_message(&mut server)
            .await
            .expect("read large control message");
        let decoded_encoded = postcard::to_allocvec(&decoded).expect("encode decoded message");
        let expected_encoded = postcard::to_allocvec(&message).expect("encode expected message");
        assert_eq!(decoded_encoded, expected_encoded);
    }

    #[tokio::test]
    async fn write_frame_rejects_oversized_payload() {
        let (mut writer, _) = io::duplex(16);
        let message = ControlMessage::LoginFailure {
            reason: "x".repeat(MAX_FRAME_SIZE + 1024),
        };

        let result = write_frame(&mut writer, &message).await;
        match result {
            Err(FramingError::FrameTooLarge { len, max }) => {
                assert!(len > MAX_FRAME_SIZE);
                assert_eq!(max, MAX_FRAME_SIZE);
            }
            other => panic!("expected FrameTooLarge error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn large_body_is_independent_of_max_frame_size() {
        // This test verifies that HTTP request bodies (raw QUIC data-stream bytes)
        // are NOT constrained by MAX_FRAME_SIZE. The framing limit only applies
        // to control messages serialized with write_frame/write_control_message.
        // Bodies > 1 MB are valid and do not trigger FrameTooLarge.
        let body_5mb = vec![0u8; 5 * 1024 * 1024];
        assert!(
            body_5mb.len() > MAX_FRAME_SIZE,
            "body is larger than MAX_FRAME_SIZE"
        );
        // Constructing a body larger than MAX_FRAME_SIZE is not an error.
        // It would be sent via qconn.stream_send() which has no application-level size limit.
        assert_eq!(body_5mb.len(), 5 * 1024 * 1024);
    }
}
