use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::types::{RelayInfo, TunnelConfig, TunnelId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ControlMessage {
    // Client -> Server
    Login {
        api_key: String,
        client_version: String,
        #[serde(default)]
        protocol_version: Option<u32>,
    },
    RegisterTunnel {
        config: TunnelConfig,
    },
    UnregisterTunnel {
        tunnel_id: TunnelId,
    },
    Heartbeat {
        seq: u64,
        timestamp: u64,
    },
    // Server -> Client
    LoginSuccess {
        session_id: String,
        relay_info: RelayInfo,
    },
    LoginFailure {
        reason: String,
    },
    TunnelRegistered {
        tunnel_id: TunnelId,
        public_url: String,
        remote_port: Option<u16>,
    },
    TunnelError {
        tunnel_id: TunnelId,
        reason: String,
    },
    HeartbeatAck {
        seq: u64,
        timestamp: u64,
        server_time: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamHeader {
    pub tunnel_id: TunnelId,
    pub connection_id: u64,
    pub source_addr: SocketAddr,
    #[serde(default)]
    pub streaming: bool,
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{ControlMessage, StreamHeader};
    use crate::types::{RelayInfo, TunnelConfig, TunnelId, TunnelType};

    fn sample_config() -> TunnelConfig {
        TunnelConfig {
            id: TunnelId::new(),
            tunnel_type: TunnelType::Http {
                local_port: 8080,
                subdomain: Some("demo".to_string()),
            },
            local_addr: "127.0.0.1:8080".parse().expect("valid socket addr"),
        }
    }

    fn sample_relay() -> RelayInfo {
        RelayInfo {
            addr: "10.0.0.1:4433".parse().expect("valid socket addr"),
            region: "us-east-1".to_string(),
            version: "1.0.0".to_string(),
        }
    }

    fn assert_roundtrip(msg: &ControlMessage) {
        let encoded = postcard::to_allocvec(msg).expect("serialize control message");
        let decoded: ControlMessage =
            postcard::from_bytes(&encoded).expect("deserialize control message");
        let re_encoded = postcard::to_allocvec(&decoded).expect("re-serialize control message");
        assert_eq!(re_encoded, encoded);
    }

    #[test]
    fn control_message_roundtrip_all_variants() {
        let tunnel_id = TunnelId::new();

        let cases = vec![
            ControlMessage::Login {
                api_key: "api-key-123".to_string(),
                client_version: "0.1.0".to_string(),
                protocol_version: Some(1),
            },
            ControlMessage::RegisterTunnel {
                config: sample_config(),
            },
            ControlMessage::UnregisterTunnel { tunnel_id },
            ControlMessage::Heartbeat {
                seq: 42,
                timestamp: 1_717_171_717,
            },
            ControlMessage::LoginSuccess {
                session_id: "session-abc".to_string(),
                relay_info: sample_relay(),
            },
            ControlMessage::LoginFailure {
                reason: "invalid key".to_string(),
            },
            ControlMessage::TunnelRegistered {
                tunnel_id,
                public_url: "https://demo.pike.life".to_string(),
                remote_port: Some(40_000),
            },
            ControlMessage::TunnelError {
                tunnel_id,
                reason: "port already allocated".to_string(),
            },
            ControlMessage::HeartbeatAck {
                seq: 42,
                timestamp: 1_717_171_717,
                server_time: 1_717_171_718,
            },
        ];

        for msg in &cases {
            assert_roundtrip(msg);
        }
    }

    #[test]
    fn stream_header_roundtrip() {
        let header = StreamHeader {
            tunnel_id: TunnelId::new(),
            connection_id: 7,
            source_addr: SocketAddr::from(([192, 168, 1, 10], 51432)),
            streaming: false,
        };

        let encoded = postcard::to_allocvec(&header).expect("serialize stream header");
        let decoded: StreamHeader =
            postcard::from_bytes(&encoded).expect("deserialize stream header");
        assert_eq!(decoded, header);
    }

    #[test]
    fn stream_header_roundtrip_streaming() {
        let header = StreamHeader {
            tunnel_id: TunnelId::new(),
            connection_id: 42,
            source_addr: SocketAddr::from(([10, 0, 0, 1], 8080)),
            streaming: true,
        };

        let encoded = postcard::to_allocvec(&header).expect("serialize stream header");
        let decoded: StreamHeader =
            postcard::from_bytes(&encoded).expect("deserialize stream header");
        assert_eq!(decoded, header);
        assert!(decoded.streaming);
    }

    #[test]
    fn test_old_login_deserializes_without_version() {
        // Simulate old client sending Login without protocol_version field.
        // We serialize a Login with protocol_version: None, which should match
        // what an old client would send (no field at all).
        let old_login = ControlMessage::Login {
            api_key: "test_key".to_string(),
            client_version: "1.0.0".to_string(),
            protocol_version: None,
        };

        let encoded = postcard::to_allocvec(&old_login).expect("serialize old login");

        // Deserialize with the new struct definition (which has #[serde(default)])
        let decoded: ControlMessage =
            postcard::from_bytes(&encoded).expect("deserialize old login with new struct");

        match decoded {
            ControlMessage::Login {
                api_key,
                client_version,
                protocol_version,
            } => {
                assert_eq!(api_key, "test_key");
                assert_eq!(client_version, "1.0.0");
                assert_eq!(protocol_version, None);
            }
            _ => panic!("expected Login variant"),
        }
    }

    #[test]
    fn test_new_login_includes_version() {
        let new_login = ControlMessage::Login {
            api_key: "test_key".to_string(),
            client_version: "1.0.0".to_string(),
            protocol_version: Some(1),
        };

        let encoded = postcard::to_allocvec(&new_login).expect("serialize new login");
        let decoded: ControlMessage =
            postcard::from_bytes(&encoded).expect("deserialize new login");

        match decoded {
            ControlMessage::Login {
                api_key,
                client_version,
                protocol_version,
            } => {
                assert_eq!(api_key, "test_key");
                assert_eq!(client_version, "1.0.0");
                assert_eq!(protocol_version, Some(1));
            }
            _ => panic!("expected Login variant"),
        }
    }
}
