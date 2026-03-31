mod framing;
mod heartbeat;
mod messages;

pub use framing::{
    read_control_message, read_frame, write_control_message, write_frame, FramingError,
    MAX_FRAME_SIZE,
};
pub use heartbeat::{HeartbeatManager, DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT};
pub use messages::{ControlMessage, StreamHeader};

pub const PROTOCOL_VERSION: u32 = 1;
pub const MIN_SUPPORTED_VERSION: u32 = 1;
pub const ALPN_PROTOCOL: &[u8] = b"pike/1";
