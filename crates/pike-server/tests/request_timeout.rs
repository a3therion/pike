// Intentionally empty: the upstream `request_timeout_secs` whole-request timeout was
// superseded by the streaming proxy's fixed response-head deadline
// (`pike_core::http_wire::RESPONSE_HEAD_TIMEOUT`) plus the 30 s idle body timeout in
// `relay_http.rs`, which is covered by that module's tests. Delete this file with
// `git rm` when convenient.
