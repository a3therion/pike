//! Bounded traffic inspection and credential redaction, independent of routing.
use crate::config::TrafficInspectionConfig;
use axum::{
    body::Bytes,
    http::header::{HeaderName, HeaderValue, CONTENT_TYPE},
};
#[derive(serde::Serialize)]
struct CapturedHeader {
    name: String,
    value: String,
}

/// Returns true if the content-type is text-like and worth previewing.
pub(super) fn is_previewable_content_type(ct: &str) -> bool {
    let ct = ct.to_ascii_lowercase();
    ct.starts_with("text/")
        || ct.contains("json")
        || ct.contains("xml")
        || ct.contains("x-www-form-urlencoded")
        || ct.contains("graphql")
        || ct.contains("yaml")
        || ct.contains("toml")
        || ct.contains("javascript")
        || ct.contains("css")
        || ct.contains("html")
}

/// Serialize headers into a JSON string.
fn headers_to_json(headers: &axum::http::HeaderMap) -> String {
    let values: Vec<CapturedHeader> = headers
        .iter()
        .map(|(k, v)| CapturedHeader {
            name: k.as_str().to_string(),
            value: header_value_for_capture(k, v),
        })
        .collect();
    serde_json::to_string(&values).unwrap_or_default()
}

fn header_value_for_capture(name: &HeaderName, value: &HeaderValue) -> String {
    if is_sensitive_header_name(name.as_str()) {
        return "<redacted>".to_string();
    }

    value.to_str().unwrap_or("<binary>").to_string()
}

fn is_sensitive_header_name(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "x-csrf-token"
            | "x-forwarded-access-token"
            | "cf-access-jwt-assertion"
            | "x-amz-security-token"
    ) || normalized == "apikey"
        || normalized.ends_with("-token")
        || normalized.ends_with("_token")
        || normalized.ends_with("-secret")
        || normalized.ends_with("_secret")
        || normalized.ends_with("-api-key")
        || normalized.ends_with("_api_key")
        || normalized.contains("session")
}

fn is_sensitive_field_name(name: &str) -> bool {
    let normalized = name
        .trim()
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-')
        .to_ascii_lowercase();

    matches!(
        normalized.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "password"
            | "passwd"
            | "pwd"
            | "token"
            | "access_token"
            | "refresh_token"
            | "id_token"
            | "api_key"
            | "apikey"
            | "secret"
            | "client_secret"
            | "session"
            | "session_id"
    ) || normalized.ends_with("-token")
        || normalized.ends_with("_token")
        || normalized.ends_with("-secret")
        || normalized.ends_with("_secret")
        || normalized.ends_with("-key")
        || normalized.ends_with("_key")
        || normalized.contains("session")
        || normalized.contains("cookie")
}

/// Rebuild a `path?query` string, redacting the VALUES of sensitive query params
/// (fix #17). Non-sensitive params are preserved verbatim so the log stays useful.
pub(super) fn redact_path_query(path: &str, query: Option<&str>) -> String {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return path.to_string();
    };

    let redacted = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _)) if is_sensitive_field_name(key) => format!("{key}=<redacted>"),
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&");

    format!("{path}?{redacted}")
}

pub(super) fn maybe_capture_headers(
    headers: &axum::http::HeaderMap,
    capture_config: &TrafficInspectionConfig,
) -> Option<String> {
    capture_config
        .capture_headers
        .then(|| headers_to_json(headers))
}

pub(super) fn should_capture_body_preview(
    capture_config: &TrafficInspectionConfig,
    content_type: Option<&str>,
    content_length: u64,
) -> bool {
    capture_config.capture_bodies
        && capture_config.max_body_preview_bytes > 0
        && content_type.is_some_and(is_previewable_content_type)
        && !(content_length > capture_config.max_body_preview_bytes as u64 && content_length != 0)
}

pub(super) fn preview_body(
    bytes: &Bytes,
    max_body_preview_bytes: usize,
    content_type: Option<&str>,
) -> Option<String> {
    let truncated = bytes.len() > max_body_preview_bytes;
    let preview_bytes = &bytes[..bytes.len().min(max_body_preview_bytes)];
    let mut preview = String::from_utf8_lossy(preview_bytes).to_string();
    preview = redact_body_preview(content_type, preview);
    if truncated {
        preview.push_str("\n\n--- truncated ---");
    }

    if preview.is_empty() {
        None
    } else {
        Some(preview)
    }
}

fn redact_body_preview(content_type: Option<&str>, preview: String) -> String {
    let Some(content_type) = content_type else {
        return redact_text_preview(&preview);
    };

    let normalized = content_type.to_ascii_lowercase();
    if normalized.contains("json") {
        return redact_json_preview(&preview).unwrap_or_else(|| redact_text_preview(&preview));
    }
    if normalized.contains("x-www-form-urlencoded") {
        return redact_form_urlencoded_preview(&preview);
    }

    redact_text_preview(&preview)
}

fn redact_json_preview(preview: &str) -> Option<String> {
    let mut value: serde_json::Value = serde_json::from_str(preview).ok()?;
    redact_json_value(&mut value);
    serde_json::to_string(&value).ok()
}

fn redact_json_value(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, nested_value) in map.iter_mut() {
                if is_sensitive_field_name(key) {
                    *nested_value = serde_json::Value::String("<redacted>".to_string());
                } else {
                    redact_json_value(nested_value);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact_json_value(item);
            }
        }
        _ => {}
    }
}

fn redact_form_urlencoded_preview(preview: &str) -> String {
    preview
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _)) if is_sensitive_field_name(key) => format!("{key}=<redacted>"),
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

fn redact_text_preview(preview: &str) -> String {
    preview
        .lines()
        .map(redact_text_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_text_line(line: &str) -> String {
    let redacted = if let Some((key, _)) = line.split_once(':') {
        if is_sensitive_field_name(key) {
            format!("{key}: <redacted>")
        } else {
            line.to_string()
        }
    } else if let Some((key, _)) = line.split_once('=') {
        if is_sensitive_field_name(key) {
            format!("{key}=<redacted>")
        } else {
            line.to_string()
        }
    } else {
        line.to_string()
    };

    redact_bearer_tokens(&redacted)
}

fn redact_bearer_tokens(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut result = String::new();
    let mut cursor = 0;

    while let Some(offset) = lower[cursor..].find("bearer ") {
        let start = cursor + offset;
        result.push_str(&text[cursor..start]);
        result.push_str("Bearer <redacted>");

        let mut end = start + "bearer ".len();
        for ch in text[end..].chars() {
            if ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | ';' | ')' | ']' | '}') {
                break;
            }
            end += ch.len_utf8();
        }

        cursor = end;
    }

    result.push_str(&text[cursor..]);
    result
}

/// Extract the content-type header value as a string.
pub(super) fn content_type_str(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
    use axum::http::HeaderMap;
    use serde_json::json;
    #[test]
    fn sensitive_headers_are_redacted() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer secret-token"),
        );
        headers.insert(COOKIE, HeaderValue::from_static("session=abc"));
        headers.insert(SET_COOKIE, HeaderValue::from_static("api_key=xyz"));
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        let json: serde_json::Value =
            serde_json::from_str(&headers_to_json(&headers)).expect("headers must serialize");

        let headers = json
            .as_array()
            .expect("headers should serialize as an array");
        let lookup = |name: &str| {
            headers
                .iter()
                .find(|entry| entry["name"] == name)
                .map(|entry| entry["value"].clone())
                .unwrap_or(serde_json::Value::Null)
        };

        assert_eq!(lookup("authorization"), "<redacted>");
        assert_eq!(lookup("cookie"), "<redacted>");
        assert_eq!(lookup("set-cookie"), "<redacted>");
        assert_eq!(lookup("content-type"), "application/json");
    }

    #[test]
    fn json_body_preview_redacts_sensitive_fields() {
        let preview = redact_body_preview(
            Some("application/json"),
            json!({
                "ok": "value",
                "access_token": "secret",
                "nested": {
                    "password": "hidden",
                    "session_id": "sid"
                }
            })
            .to_string(),
        );

        let value: serde_json::Value = serde_json::from_str(&preview).expect("valid json");
        assert_eq!(value["ok"], "value");
        assert_eq!(value["access_token"], "<redacted>");
        assert_eq!(value["nested"]["password"], "<redacted>");
        assert_eq!(value["nested"]["session_id"], "<redacted>");
    }

    #[test]
    fn form_body_preview_redacts_sensitive_fields() {
        let preview = redact_body_preview(
            Some("application/x-www-form-urlencoded"),
            "name=pike&token=secret&api_key=abc".to_string(),
        );

        assert_eq!(preview, "name=pike&token=<redacted>&api_key=<redacted>");
    }

    #[test]
    fn query_string_secrets_are_redacted_but_the_path_is_kept() {
        assert_eq!(super::redact_path_query("/login", None), "/login");
        assert_eq!(super::redact_path_query("/login", Some("")), "/login");
        assert_eq!(
            super::redact_path_query("/cb", Some("next=%2Fdemo&access_token=abc&session=1&k")),
            "/cb?next=%2Fdemo&access_token=<redacted>&session=<redacted>&k"
        );
    }

    #[test]
    fn default_capture_policy_disables_body_previews() {
        let capture_config = TrafficInspectionConfig::default();

        assert!(!should_capture_body_preview(
            &capture_config,
            Some("application/json"),
            128,
        ));
    }
}
