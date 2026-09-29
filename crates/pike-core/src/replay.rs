//! An explicit, bounded HTTP replay draft. Routing and authentication are never
//! copied from the captured request: the caller supplies an owned live tunnel.
use base64::{engine::general_purpose::STANDARD, Engine};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use serde::{Deserialize, Serialize};

pub const MAX_BODY_BYTES: usize = 64 * 1024;
pub const MAX_JSON_BYTES: usize = 128 * 1024;
pub const MAX_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<Header>,
    /// Standard padded base64, including the empty string for an empty body.
    /// Mandatory: an absent capture must never silently become an empty body.
    pub body_base64: String,
}

pub struct ValidatedRequest {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// Response bytes are available only to the authenticated replay caller, never
/// copied into a persistent capture. Normal inspection still applies redaction.
#[derive(Debug, Deserialize, Serialize)]
pub struct ReplayResponse {
    pub status: u16,
    pub headers: Vec<Header>,
    pub trailers: Vec<Header>,
    pub body_base64: String,
    pub truncated: bool,
    pub duration_ms: u64,
}

pub fn reserved_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "upgrade"
            | "trailer"
            | "te"
            | "expect"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "forwarded"
            | "via"
    ) || name.starts_with("x-forwarded-")
        || name.starts_with("x-pike-")
        || name.starts_with("sec-websocket-")
}

fn placeholder(bytes: &[u8]) -> bool {
    [
        b"<redacted>".as_slice(),
        b"<binary>",
        b"<body exceeds capture limit>",
        b"<non-text body>",
        b"--- truncated ---",
    ]
    .iter()
    .any(|marker| bytes.windows(marker.len()).any(|part| part == *marker))
}

impl ReplayRequest {
    pub fn validate(self) -> Result<ValidatedRequest, &'static str> {
        let method =
            Method::from_bytes(self.method.as_bytes()).map_err(|_| "invalid HTTP method")?;
        if !matches!(
            method,
            Method::GET
                | Method::POST
                | Method::PUT
                | Method::PATCH
                | Method::DELETE
                | Method::HEAD
                | Method::OPTIONS
        ) {
            return Err("replay supports GET, POST, PUT, PATCH, DELETE, HEAD and OPTIONS");
        }
        if self.path.len() > 8192
            || !self.path.starts_with('/')
            || self.path.starts_with("//")
            || self.path.contains(['#', '\\'])
            || placeholder(self.path.as_bytes())
        {
            return Err("replay path must be an origin-relative path and query");
        }
        let uri: Uri = self.path.parse().map_err(|_| "invalid request path")?;
        if uri.scheme().is_some() || uri.authority().is_some() {
            return Err("replay cannot select a different host");
        }
        if self.headers.len() > 100 {
            return Err("replay permits at most 100 headers");
        }
        let mut headers = HeaderMap::new();
        let mut bytes = 0;
        for header in self.headers {
            bytes += header.name.len() + header.value.len();
            if bytes > MAX_HEADER_BYTES {
                return Err("replay headers exceed 16 KiB");
            }
            let name = HeaderName::from_bytes(header.name.as_bytes())
                .map_err(|_| "invalid header name")?;
            if reserved_header(name.as_str()) {
                return Err(
                    "remove routing, framing, forwarding and upgrade headers before replay",
                );
            }
            if placeholder(header.value.as_bytes()) {
                return Err("replace or remove redacted headers before replay");
            }
            let value = HeaderValue::from_str(&header.value).map_err(|_| "invalid header value")?;
            headers.append(name, value);
        }
        if self.body_base64.len() > MAX_BODY_BYTES.div_ceil(3) * 4 {
            return Err("replay request body exceeds 64 KiB");
        }
        let body = STANDARD
            .decode(self.body_base64)
            .map_err(|_| "body_base64 must be standard base64")?;
        if body.len() > MAX_BODY_BYTES {
            return Err("replay request body exceeds 64 KiB");
        }
        if placeholder(&body) {
            return Err("replace incomplete or redacted body previews before replay");
        }
        Ok(ValidatedRequest {
            method,
            uri,
            headers,
            body,
        })
    }
}

impl ReplayResponse {
    pub fn encode_body(body: &[u8]) -> String {
        STANDARD.encode(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn draft() -> ReplayRequest {
        ReplayRequest {
            method: "POST".into(),
            path: "/items?name=x%2Fy".into(),
            headers: vec![],
            body_base64: STANDARD.encode([0, 255, 10, 13]),
        }
    }

    #[test]
    fn preserves_binary_query_and_duplicate_headers() {
        let mut request = draft();
        request.headers = vec![
            Header {
                name: "x-item".into(),
                value: "a".into(),
            },
            Header {
                name: "x-item".into(),
                value: "b".into(),
            },
        ];
        let validated = request.validate().unwrap();
        assert_eq!(validated.body, [0, 255, 10, 13]);
        assert_eq!(validated.uri.to_string(), "/items?name=x%2Fy");
        assert_eq!(validated.headers.get_all("x-item").iter().count(), 2);
    }

    #[test]
    fn rejects_host_escape_framing_upgrade_and_unusable_captures() {
        for path in [
            "http://other.test/path",
            "//other.test/path",
            "/\\other",
            "/path#fragment",
        ] {
            let mut request = draft();
            request.path = path.into();
            assert!(request.validate().is_err());
        }
        for name in [
            "Host",
            "Content-Length",
            "Connection",
            "X-Forwarded-Host",
            "X-Pike-Request-Id",
            "Upgrade",
        ] {
            let mut request = draft();
            request.headers.push(Header {
                name: name.into(),
                value: "x".into(),
            });
            assert!(request.validate().is_err());
        }
        for value in ["<redacted>", "\r\ninjected: yes"] {
            let mut request = draft();
            request.headers.push(Header {
                name: "authorization".into(),
                value: value.into(),
            });
            assert!(request.validate().is_err());
        }
        let mut request = draft();
        request.body_base64 = STANDARD.encode(br#"{"password":"<redacted>"}"#);
        assert!(request.validate().is_err());
        let mut request = draft();
        request.method = "CONNECT".into();
        assert!(request.validate().is_err());
    }

    #[test]
    fn checks_exact_request_body_bound() {
        let mut request = draft();
        request.body_base64 = STANDARD.encode(vec![255; MAX_BODY_BYTES]);
        assert_eq!(request.validate().unwrap().body.len(), MAX_BODY_BYTES);
        let mut request = draft();
        request.body_base64 = STANDARD.encode(vec![255; MAX_BODY_BYTES + 1]);
        assert!(request.validate().is_err());
    }
}
