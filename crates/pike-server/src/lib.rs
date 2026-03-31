#![allow(
    async_fn_in_trait,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::module_name_repetitions,
    clippy::uninlined_format_args,
    clippy::ignored_unit_patterns,
    clippy::items_after_statements,
    clippy::unnested_or_patterns,
    clippy::unused_self,
    clippy::unused_async,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::return_self_not_must_use,
    clippy::struct_field_names,
    clippy::needless_pass_by_value,
    clippy::map_unwrap_or,
    clippy::type_complexity,
    clippy::too_many_lines,
    clippy::redundant_closure_for_method_calls,
    clippy::cast_sign_loss,
    clippy::incompatible_msrv
)]

pub mod abuse;
pub mod admin;
pub mod auth;
pub mod config;
pub mod connection;
pub mod control_plane;
pub mod dashboard_ws;
pub mod http;
pub mod ingest;
pub mod management;
pub mod metrics;
pub mod proxy;
pub mod rate_limit;
pub mod registry;
pub mod request_log;
pub mod router;
pub mod state_store;
pub mod tcp;
pub mod transport;
pub mod tunnel_metrics;
pub mod usage_reporter;
pub mod websocket;
pub mod ws_proxy;
