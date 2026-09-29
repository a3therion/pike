//! Bounded binary envelopes used by the WebSocket fallback transport.
//! Data bytes remain raw; only the small stream header uses postcard framing.
use anyhow::{anyhow, bail, Result};

use crate::proto::{ControlMessage, StreamHeader};

pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;
pub const MAX_HEADER_SIZE: usize = 4096;
pub const MAX_MESSAGE_SIZE: usize = MAX_PAYLOAD_SIZE + MAX_HEADER_SIZE + 14;

#[derive(Debug)]
pub enum WsMessage {
    Control(ControlMessage),
    Data {
        stream_id: u64,
        header: StreamHeader,
        payload: Vec<u8>,
        fin: bool,
    },
}

pub fn encode(message: &WsMessage) -> Result<Vec<u8>> {
    match message {
        WsMessage::Control(control) => {
            let data = postcard::to_allocvec(control)?;
            if data.len() > MAX_HEADER_SIZE {
                bail!("WebSocket control message too large");
            }
            let mut result = vec![0];
            result.extend(data);
            Ok(result)
        }
        WsMessage::Data {
            stream_id,
            header,
            payload,
            fin,
        } => {
            if payload.len() > MAX_PAYLOAD_SIZE {
                bail!("WebSocket payload too large");
            }
            let header = postcard::to_allocvec(header)?;
            if header.len() > MAX_HEADER_SIZE {
                bail!("WebSocket stream header too large");
            }
            let mut result = Vec::with_capacity(14 + header.len() + payload.len());
            result.push(1);
            result.extend(stream_id.to_be_bytes());
            result.push(u8::from(*fin));
            result.extend(u32::try_from(header.len())?.to_be_bytes());
            result.extend(header);
            result.extend(payload);
            Ok(result)
        }
    }
}

pub fn decode(bytes: &[u8]) -> Result<WsMessage> {
    if bytes.len() > MAX_MESSAGE_SIZE {
        bail!("WebSocket message too large");
    }
    match bytes.first() {
        Some(0) => {
            if bytes.len() > MAX_HEADER_SIZE + 1 {
                bail!("WebSocket control message too large");
            }
            Ok(WsMessage::Control(postcard::from_bytes(&bytes[1..])?))
        }
        Some(1) if bytes.len() >= 14 => {
            let stream_id = u64::from_be_bytes(bytes[1..9].try_into()?);
            let fin = match bytes[9] {
                0 => false,
                1 => true,
                _ => bail!("invalid FIN flag"),
            };
            let length = u32::from_be_bytes(bytes[10..14].try_into()?) as usize;
            if length > MAX_HEADER_SIZE || length > bytes.len() - 14 {
                bail!("invalid stream header length");
            }
            let payload = &bytes[14 + length..];
            if payload.len() > MAX_PAYLOAD_SIZE {
                bail!("WebSocket payload too large");
            }
            Ok(WsMessage::Data {
                stream_id,
                header: postcard::from_bytes(&bytes[14..14 + length])?,
                payload: payload.to_vec(),
                fin,
            })
        }
        _ => Err(anyhow!("invalid WebSocket tunnel envelope")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TunnelId;

    #[test]
    fn preserves_bytes_and_empty_half_close() {
        let header = StreamHeader {
            tunnel_id: TunnelId::new(),
            connection_id: 19,
            source_addr: "127.0.0.1:1234".parse().unwrap(),
            streaming: true,
            mode: crate::proto::StreamMode::Raw,
        };
        for payload in [vec![0, 255, 9], vec![]] {
            let message = WsMessage::Data {
                stream_id: 2,
                header: header.clone(),
                payload: payload.clone(),
                fin: true,
            };
            let WsMessage::Data {
                header: decoded_header,
                payload: decoded,
                fin,
                ..
            } = decode(&encode(&message).unwrap()).unwrap()
            else {
                panic!("data expected")
            };
            assert_eq!(decoded_header, header);
            assert_eq!(decoded, payload);
            assert!(fin);
        }
    }

    #[test]
    fn rejects_truncated_and_oversized_envelopes() {
        assert!(decode(&[1, 0]).is_err());
        let mut frame = vec![1; 14];
        frame[9] = 0;
        frame[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode(&frame).is_err());
        assert!(decode(&vec![0; MAX_HEADER_SIZE + 2]).is_err());
    }
}
