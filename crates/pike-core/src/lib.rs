#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::return_self_not_must_use,
    clippy::uninlined_format_args,
    clippy::ignored_unit_patterns,
    clippy::unused_self,
    clippy::unused_async,
    clippy::cast_possible_truncation
)]

pub mod http_response;
pub mod proto;
pub mod quic;
pub mod types;
pub mod websocket;

pub mod datagram;
pub mod http_wire;

pub mod byte_stream;
pub mod replay;
