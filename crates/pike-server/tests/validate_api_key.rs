use std::time::Duration;

use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use pike_server::connection::validate_api_key;

fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap()
}

fn build_control_plane(mock_uri: &str) -> pike_server::control_plane::ControlPlaneClient {
    pike_server::control_plane::ControlPlaneClient::new(
        build_http_client(),
        mock_uri.to_string(),
        "http://unused-workers.test".to_string(),
        false,
        None,
    )
}

#[tokio::test]
async fn validate_api_key_success() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/validate"))
        .and(header("Authorization", "Bearer pk_test_valid"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "valid": true,
            "user_id": "u1",
            "email": "test@example.com",
            "plan": "pro",
            "plan_expires_at": null
        })))
        .mount(&mock_server)
        .await;

    let client = build_control_plane(&mock_server.uri());
    let user = client
        .validate_api_key("pk_test_valid")
        .await
        .expect("validation should succeed");

    assert_eq!(user.user_id, "u1");
    assert_eq!(user.email, "test@example.com");
    assert_eq!(user.plan, "pro");
    assert!(user.plan_expires_at.is_none());
}

#[tokio::test]
async fn validate_api_key_invalid_401() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/validate"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock_server)
        .await;

    let client = build_control_plane(&mock_server.uri());
    let err = client.validate_api_key("pk_bad_key").await.unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("invalid API key"),
        "expected 'invalid API key', got: {msg}"
    );
}

#[tokio::test]
async fn validate_api_key_redirect_307() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/validate"))
        .respond_with(
            ResponseTemplate::new(307)
                .append_header("Location", "https://app.example.test/api/v1/auth/validate"),
        )
        .mount(&mock_server)
        .await;

    let client = build_control_plane(&mock_server.uri());
    let err = client.validate_api_key("pk_test_key").await.unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("307") || msg.contains("redirect"),
        "expected '307' or 'redirect', got: {msg}"
    );
}

#[tokio::test]
async fn validate_api_key_timeout() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/validate"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(15)))
        .mount(&mock_server)
        .await;

    let client = build_control_plane(&mock_server.uri());
    let start = std::time::Instant::now();
    let err = client.validate_api_key("pk_test_key").await.unwrap_err();
    let elapsed = start.elapsed();

    let msg = err.to_string();
    assert!(
        msg.contains("timed out"),
        "expected 'timed out', got: {msg}"
    );
    assert!(
        elapsed < Duration::from_secs(20),
        "should complete within 20s, took: {elapsed:?}"
    );
}

#[tokio::test]
async fn validate_api_key_server_error_500() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/validate"))
        .respond_with(ResponseTemplate::new(500))
        .expect(2)
        .mount(&mock_server)
        .await;

    let client = build_control_plane(&mock_server.uri());
    let err = client.validate_api_key("pk_test_key").await.unwrap_err();

    let msg = err.to_string();
    assert!(
        msg.contains("500") || msg.contains("server error"),
        "expected '500' or 'server error', got: {msg}"
    );
}

#[test]
fn validate_api_key_too_short() {
    let err = validate_api_key("pk_abc", false).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("too short"),
        "expected 'too short', got: {msg}"
    );
}

#[test]
fn validate_api_key_missing_prefix() {
    let err = validate_api_key("test_key_1234", false).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("must start with pk_"),
        "expected 'must start with pk_', got: {msg}"
    );
}

#[test]
fn validate_api_key_invalid_characters() {
    let err = validate_api_key("pk_test-key@123", false).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("invalid characters"),
        "expected 'invalid characters', got: {msg}"
    );
}

#[test]
fn validate_api_key_all_same_character() {
    let err = validate_api_key("pk_aaaaaaaa", false).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("all the same character"),
        "expected 'all the same character', got: {msg}"
    );
}

#[test]
fn validate_api_key_valid_format() {
    let result = validate_api_key("pk_test_key_1234", false);
    assert!(result.is_ok(), "valid key should pass: {result:?}");
}

#[test]
fn validate_api_key_valid_with_numbers() {
    let result = validate_api_key("pk_abc123def456", false);
    assert!(
        result.is_ok(),
        "valid key with numbers should pass: {result:?}"
    );
}

#[test]
fn validate_api_key_valid_with_underscores() {
    let result = validate_api_key("pk_test_key_with_underscores", false);
    assert!(
        result.is_ok(),
        "valid key with underscores should pass: {result:?}"
    );
}

#[test]
fn validate_api_key_minimum_length() {
    let result = validate_api_key("pk_12345", false);
    assert!(
        result.is_ok(),
        "key with exactly 8 chars should pass: {result:?}"
    );
}

#[test]
fn validate_api_key_empty() {
    let err = validate_api_key("", false).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("empty"), "expected 'empty', got: {msg}");
}

#[test]
fn validate_api_key_whitespace_only() {
    let err = validate_api_key("   ", false).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("empty"), "expected 'empty', got: {msg}");
}

#[test]
fn validate_api_key_contains_whitespace() {
    let err = validate_api_key("pk_test key", false).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("whitespace"),
        "expected 'whitespace', got: {msg}"
    );
}
