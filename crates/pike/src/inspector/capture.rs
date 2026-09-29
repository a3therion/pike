//! Small, redacted inspection records for streaming exchanges.
use super::storage::{CapturedHeader, CapturedRequest};
use axum::http::HeaderMap;

const PREVIEW_BYTES: usize = 8192;

pub struct Capture {
    pub record: CapturedRequest,
    request_body: Vec<u8>,
    response_body: Vec<u8>,
    request_content_type: String,
    response_content_type: String,
    started: std::time::Instant,
}
impl Capture {
    pub fn new() -> Self {
        Self {
            record: CapturedRequest {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                method: String::new(),
                path: String::new(),
                headers: vec![],
                body: None,
                response_status: 502,
                response_headers: vec![],
                response_body: None,
                duration_ms: 0,
            },
            request_body: vec![],
            response_body: vec![],
            request_content_type: String::new(),
            response_content_type: String::new(),
            started: std::time::Instant::now(),
        }
    }
    pub fn request(&mut self, method: &str, target: &str, headers: &HeaderMap) {
        self.record.method = method.into();
        self.record.path = target.into();
        self.record.headers = capture_headers(headers);
        self.request_content_type = content_type(headers);
    }
    pub fn response(&mut self, status: u16, headers: &HeaderMap) {
        self.record.response_status = status;
        self.record.response_headers = capture_headers(headers);
        self.response_content_type = content_type(headers);
    }
    pub fn data(&mut self, response: bool, data: &[u8]) {
        let preview = if response {
            &mut self.response_body
        } else {
            &mut self.request_body
        };
        let count = data
            .len()
            .min((PREVIEW_BYTES + 1).saturating_sub(preview.len()));
        preview.extend_from_slice(&data[..count]);
    }
    pub fn finish(mut self) -> CapturedRequest {
        self.record.body = body_preview(&self.request_body, &self.request_content_type);
        self.record.response_body = body_preview(&self.response_body, &self.response_content_type);
        self.record.duration_ms =
            u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.record
    }
}
fn content_type(headers: &HeaderMap) -> String {
    headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase()
}
fn sensitive(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "cookie",
        "session",
        "api-key",
        "api_key",
        "apikey",
    ]
    .iter()
    .any(|value| name.contains(value))
}
fn capture_headers(headers: &HeaderMap) -> Vec<CapturedHeader> {
    headers
        .iter()
        .map(|(name, value)| CapturedHeader {
            name: name.to_string(),
            value: if sensitive(name.as_str()) {
                "<redacted>".into()
            } else {
                value.to_str().unwrap_or("<binary>").to_owned()
            },
        })
        .collect()
}
fn redact(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if sensitive(key) {
                    *value = serde_json::Value::String("<redacted>".into());
                } else {
                    redact(value);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                redact(item);
            }
        }
        _ => {}
    }
}
fn body_preview(data: &[u8], content_type: &str) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    if data.len() > PREVIEW_BYTES {
        return Some("<body exceeds capture limit>".into());
    }
    if content_type.contains("json") {
        let mut value: serde_json::Value = serde_json::from_slice(data).ok()?;
        redact(&mut value);
        return serde_json::to_string(&value).ok();
    }
    if content_type.contains("x-www-form-urlencoded") {
        let text = std::str::from_utf8(data).ok()?;
        let url = reqwest::Url::parse(&format!("http://localhost/?{text}")).ok()?;
        let pairs: Vec<_> = url
            .query_pairs()
            .map(|(key, value)| {
                let value = if sensitive(&key) {
                    "<redacted>".to_owned()
                } else {
                    value.into_owned()
                };
                (key.into_owned(), value)
            })
            .collect();
        return serde_json::to_string(&pairs).ok();
    }
    // Unstructured/binary content cannot be reliably credential-redacted.
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn redacts_nested_credentials_and_never_retains_complete_large_bodies() {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer secret".parse().unwrap());
        headers.insert("content-type", "application/json".parse().unwrap());
        let mut capture = Capture::new();
        capture.request("POST", "/upload", &headers);
        capture.data(false, br#"{"profile":{"password":"secret","name":"a"}}"#);
        capture.response(200, &headers);
        for _ in 0..100 {
            capture.data(true, &[b'x'; 8192]);
        }
        assert_eq!(capture.response_body.len(), PREVIEW_BYTES + 1);
        let result = capture.finish();
        assert!(!serde_json::to_string(&result).unwrap().contains("secret"));
        assert!(result.body.unwrap().contains("redacted"));
        assert_eq!(
            result.response_body.as_deref(),
            Some("<body exceeds capture limit>")
        );
    }
}
