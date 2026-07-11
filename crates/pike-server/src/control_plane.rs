use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::connection::{UserLimits, UserStatus, ValidatedUser};
use anyhow::{anyhow, Result};
use dashmap::DashMap;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use tracing::error;

/// Outcome of validating an API key against the control plane.
///
/// Distinguishes a DEFINITIVE negative (`Invalid` — the key is genuinely bad, the user
/// is gone, or the control plane explicitly said `valid: false`) from a TRANSIENT failure
/// (`Unavailable` — network error, timeout, or 5xx after retry). Callers that take
/// destructive action on a negative (e.g. the revalidation loop disconnecting live
/// sessions) MUST act only on `Invalid`, never on `Unavailable`, so a momentary
/// control-plane blip can't disconnect every connected user.
#[derive(Debug)]
pub enum ApiKeyValidation {
    Valid(Box<ValidatedUser>),
    Invalid,
    Unavailable(String),
}

pub struct ControlPlaneClient {
    http_client: reqwest::Client,
    control_plane_url: String,
    workers_api_url: String,
    dev_mode: bool,
    local_api_keys: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct TunnelRegistrationResponse {
    pub id: String,
    pub subdomain: String,
}

#[derive(Deserialize)]
struct ValidateApiKeyResponse {
    valid: bool,
    user_id: String,
    email: String,
    plan: String,
    plan_expires_at: Option<String>,
    // Fix #5/#18 contract: the control plane includes the user's current status and
    // per-plan limits so the relay can revalidate live sessions. Both are optional so
    // older control planes remain compatible.
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limits: Option<ControlPlaneLimits>,
}

#[derive(Deserialize, Default)]
struct ControlPlaneLimits {
    // The Workers control plane serialises plan limits as `{ tunnels, bandwidth_gb,
    // requests_per_day }`; accept those names via aliases while still tolerating the
    // relay's richer internal names (bytes / per-minute) if a future control plane sends
    // them. All optional so an older/newer control plane stays compatible.
    #[serde(default)]
    bandwidth_bytes_per_month: Option<u64>,
    #[serde(default)]
    bandwidth_gb: Option<u64>,
    #[serde(default, alias = "tunnels")]
    max_tunnels: Option<u32>,
    #[serde(default)]
    requests_per_minute: Option<u32>,
    #[serde(default)]
    requests_per_day: Option<u32>,
}

impl From<ControlPlaneLimits> for UserLimits {
    fn from(value: ControlPlaneLimits) -> Self {
        // Prefer an explicit byte figure; otherwise derive it from the GiB field the
        // Workers control plane sends.
        let bandwidth_bytes_per_month = value
            .bandwidth_bytes_per_month
            .or_else(|| value.bandwidth_gb.map(|gb| gb * 1024 * 1024 * 1024));
        Self {
            bandwidth_bytes_per_month,
            max_tunnels: value.max_tunnels,
            requests_per_minute: value.requests_per_minute,
            requests_per_day: value.requests_per_day,
        }
    }
}

#[derive(Serialize)]
struct RegisterTunnelRequest<'a> {
    subdomain: &'a str,
    tunnel_type: &'a str,
}

#[derive(Deserialize)]
struct CreateTunnelResponse {
    tunnel: TunnelRegistrationResponse,
}

#[derive(Deserialize)]
struct ListTunnelsResponse {
    tunnels: Vec<TunnelRegistrationResponse>,
}

#[derive(Deserialize)]
struct ApiErrorResponse {
    error: Option<String>,
    message: Option<String>,
}

impl ControlPlaneClient {
    pub fn new(
        http_client: reqwest::Client,
        control_plane_url: String,
        workers_api_url: String,
        dev_mode: bool,
        local_api_keys: Option<Vec<String>>,
    ) -> Self {
        Self {
            http_client,
            control_plane_url,
            workers_api_url,
            dev_mode,
            local_api_keys,
        }
    }

    /// Validate an API key, classifying the result as valid / definitively-invalid /
    /// transiently-unavailable. Prefer this over [`Self::validate_api_key`] whenever a
    /// negative result triggers destructive action (see [`ApiKeyValidation`]).
    pub async fn validate_api_key_status(&self, api_key: &str) -> ApiKeyValidation {
        if let Some(local_keys) = &self.local_api_keys {
            if !local_keys.iter().any(|key| key == api_key) {
                return ApiKeyValidation::Invalid;
            }

            let key_hash = AuthCache::hash_key(api_key);
            return ApiKeyValidation::Valid(Box::new(ValidatedUser {
                user_id: format!("local-{key_hash}"),
                email: "local@self-hosted".into(),
                plan: "self-hosted".into(),
                plan_expires_at: None,
                status: UserStatus::Active,
                limits: UserLimits::default(),
            }));
        }

        if self.control_plane_url.trim().is_empty() {
            // Not configured is a config/transient condition, not a definitive "this key
            // is bad" — never disconnect live users because of it.
            return ApiKeyValidation::Unavailable("auth source not configured".into());
        }

        let url = format!(
            "{}/api/v1/auth/validate",
            self.control_plane_url.trim_end_matches('/')
        );

        for attempt in 0..2 {
            let response = self
                .http_client
                .post(&url)
                .header("Authorization", format!("Bearer {api_key}"))
                .timeout(Duration::from_secs(5))
                .send()
                .await;

            let response = match response {
                Ok(response) => response,
                Err(error) if error.is_timeout() => {
                    if attempt == 0 {
                        sleep(Duration::from_secs(2)).await;
                        continue;
                    }
                    return ApiKeyValidation::Unavailable(
                        "auth validation request timed out".into(),
                    );
                }
                Err(error) => {
                    return ApiKeyValidation::Unavailable(format!(
                        "auth validation request failed: {error}"
                    ));
                }
            };

            let status = response.status();
            if status == StatusCode::UNAUTHORIZED {
                // Definitive: the control plane rejected the key.
                return ApiKeyValidation::Invalid;
            }

            if status.is_server_error() {
                if attempt == 0 {
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }
                error!(url = %url, status = %status, "API key validation failed: server error");
                return ApiKeyValidation::Unavailable(format!("auth validation failed: {status}"));
            }

            if !status.is_success() {
                // Any other non-success (3xx/4xx besides 401) is ambiguous — treat as
                // transient so we never disconnect a live user on an unexpected response.
                error!(url = %url, status = %status, "API key validation returned unexpected status");
                return ApiKeyValidation::Unavailable(format!(
                    "auth validation returned {status}"
                ));
            }

            let body: ValidateApiKeyResponse = match response.json().await {
                Ok(body) => body,
                Err(error) => {
                    return ApiKeyValidation::Unavailable(format!(
                        "failed to parse auth validation response: {error}"
                    ));
                }
            };

            if !body.valid {
                // Definitive: the control plane says this key/user is not valid
                // (includes the suspended case, which sets valid: false).
                return ApiKeyValidation::Invalid;
            }

            return ApiKeyValidation::Valid(Box::new(ValidatedUser {
                user_id: body.user_id,
                email: body.email,
                plan: body.plan,
                plan_expires_at: body.plan_expires_at,
                status: UserStatus::from_name(body.status.as_deref()),
                limits: body.limits.map(UserLimits::from).unwrap_or_default(),
            }));
        }

        ApiKeyValidation::Unavailable("auth validation failed after retry".into())
    }

    /// Validate an API key, collapsing the outcome to a `Result`. Suitable for the login
    /// path, where a transient failure and a bad key are both simply "reject this login"
    /// (fail-closed at login is safe — it's disconnecting *established* sessions on a
    /// transient blip that is not; use [`Self::validate_api_key_status`] there).
    pub async fn validate_api_key(&self, api_key: &str) -> Result<ValidatedUser> {
        match self.validate_api_key_status(api_key).await {
            ApiKeyValidation::Valid(user) => Ok(*user),
            ApiKeyValidation::Invalid => Err(anyhow!("invalid API key")),
            ApiKeyValidation::Unavailable(message) => Err(anyhow!(message)),
        }
    }

    pub async fn register_tunnel(
        &self,
        api_key: &str,
        subdomain: &str,
        tunnel_type: &str,
    ) -> Result<TunnelRegistrationResponse> {
        if self.dev_mode || self.should_skip_remote_tunnel_registration() {
            return Ok(TunnelRegistrationResponse {
                id: uuid::Uuid::new_v4().to_string(),
                subdomain: subdomain.to_string(),
            });
        }

        let url = format!(
            "{}/api/v1/tunnels",
            self.workers_api_url.trim_end_matches('/')
        );

        for attempt in 0..2 {
            let response = self
                .http_client
                .post(&url)
                .header("Authorization", format!("Bearer {api_key}"))
                .json(&RegisterTunnelRequest {
                    subdomain,
                    tunnel_type,
                })
                .timeout(Duration::from_secs(5))
                .send()
                .await;

            let response = match response {
                Ok(response) => response,
                Err(error) if error.is_timeout() => {
                    if attempt == 0 {
                        sleep(Duration::from_secs(2)).await;
                        continue;
                    }

                    return Err(anyhow!("tunnel registration request timed out"));
                }
                Err(error) => return Err(anyhow!("tunnel registration request failed: {error}")),
            };

            let status = response.status();
            if status == StatusCode::CREATED {
                let body: CreateTunnelResponse = response.json().await.map_err(|error| {
                    anyhow!("failed to parse tunnel registration response: {error}")
                })?;
                return Ok(body.tunnel);
            }

            if status == StatusCode::CONFLICT {
                if let Some(existing) = self.find_tunnel_by_subdomain(api_key, subdomain).await? {
                    return Ok(existing);
                }
                return Err(anyhow!("subdomain already in use by another user"));
            }

            if status == StatusCode::PAYMENT_REQUIRED {
                return Err(anyhow!("tunnel limit reached for your plan"));
            }

            if status == StatusCode::BAD_REQUEST {
                let body = response
                    .json::<ApiErrorResponse>()
                    .await
                    .unwrap_or(ApiErrorResponse {
                        error: None,
                        message: None,
                    });
                let message = body
                    .error
                    .or(body.message)
                    .unwrap_or_else(|| "invalid tunnel registration request".to_string());
                return Err(anyhow!(message));
            }

            if status.is_server_error() {
                if attempt == 0 {
                    sleep(Duration::from_secs(2)).await;
                    continue;
                }

                return Err(anyhow!("tunnel registration failed: {status}"));
            }

            return Err(anyhow!("tunnel registration failed: {status}"));
        }

        anyhow::bail!("tunnel registration retry loop exhausted without result")
    }

    fn should_skip_remote_tunnel_registration(&self) -> bool {
        self.local_api_keys.is_some() && self.workers_api_url.trim().is_empty()
    }

    async fn find_tunnel_by_subdomain(
        &self,
        api_key: &str,
        subdomain: &str,
    ) -> Result<Option<TunnelRegistrationResponse>> {
        if self.dev_mode {
            return Ok(None);
        }

        let url = format!(
            "{}/api/v1/tunnels",
            self.workers_api_url.trim_end_matches('/')
        );
        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {api_key}"))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|error| anyhow!("tunnel list request failed: {error}"))?;

        let status = response.status();
        if status != StatusCode::OK {
            return Ok(None);
        }

        let body: ListTunnelsResponse = response
            .json()
            .await
            .map_err(|error| anyhow!("failed to parse tunnel list response: {error}"))?;

        Ok(body.tunnels.into_iter().find(|t| t.subdomain == subdomain))
    }
}

struct CachedAuth {
    user: ValidatedUser,
    cached_at: Instant,
}

pub struct AuthCache {
    cache: DashMap<String, CachedAuth>,
    ttl: Duration,
}

impl AuthCache {
    pub fn new(ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            cache: DashMap::new(),
            ttl,
        })
    }

    fn hash_key(api_key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(api_key.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    pub fn get(&self, api_key: &str) -> Option<ValidatedUser> {
        let key_hash = Self::hash_key(api_key);
        let entry = self.cache.get(&key_hash)?;
        if entry.cached_at.elapsed() > self.ttl {
            drop(entry);
            self.cache.remove(&key_hash);
            return None;
        }
        Some(entry.user.clone())
    }

    pub fn insert(&self, api_key: &str, user: ValidatedUser) {
        let key_hash = Self::hash_key(api_key);
        self.cache.insert(
            key_hash,
            CachedAuth {
                user,
                cached_at: Instant::now(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use serde_json::json;
    use sha2::{Digest, Sha256};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{ApiKeyValidation, AuthCache, ControlPlaneClient};
    use crate::config::ServerConfig;
    use crate::connection::UserStatus;

    const TEST_KEY: &str = "pk_test_abc123";

    fn success_auth_body() -> serde_json::Value {
        json!({
            "valid": true,
            "user_id": "u1",
            "email": "test@example.com",
            "plan": "free",
            "plan_expires_at": null,
            "auth_type": "api_key"
        })
    }

    fn make_client(mock_uri: &str, dev_mode: bool) -> ControlPlaneClient {
        ControlPlaneClient::new(
            reqwest::Client::new(),
            mock_uri.to_string(),
            mock_uri.to_string(),
            dev_mode,
            None,
        )
    }

    fn write_temp_config(contents: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pike-server-control-plane-config-{}.toml",
            uuid::Uuid::new_v4()
        ));
        fs::write(&path, contents).expect("write temp config");
        path
    }

    #[tokio::test]
    async fn test_validate_api_key_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .and(header("Authorization", "Bearer pk_test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(success_auth_body()))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        let user = client.validate_api_key("pk_test").await.unwrap();
        assert_eq!(user.user_id, "u1");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.plan, "free");
        assert!(user.plan_expires_at.is_none());
    }

    #[tokio::test]
    async fn test_validate_api_key_invalid() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        let err = client.validate_api_key("bad_key").await.unwrap_err();
        assert!(err.to_string().contains("invalid API key"));
    }

    #[tokio::test]
    async fn test_validate_api_key_workers_down() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        let err = client.validate_api_key("pk_test").await.unwrap_err();
        assert!(err.to_string().contains("auth validation failed"));
    }

    // --- validate_api_key_status classification (revalidation-loop safety) ---
    //
    // These pin the property that a TRANSIENT failure is never reported as a definitive
    // negative: the revalidation loop disconnects (and used to permanently revoke) only
    // on `Invalid`, so misclassifying a 5xx/network blip as `Invalid` would brick every
    // connected user's key on a momentary control-plane outage.

    #[tokio::test]
    async fn test_status_transient_server_error_is_unavailable() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        // A transient 5xx must NOT be Invalid — the loop must leave connections intact.
        assert!(matches!(
            client.validate_api_key_status("pk_test").await,
            ApiKeyValidation::Unavailable(_)
        ));
    }

    #[tokio::test]
    async fn test_status_unexpected_4xx_is_unavailable() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        // Non-401 4xx (e.g. rate-limited) is ambiguous → treat as transient, not Invalid.
        assert!(matches!(
            client.validate_api_key_status("pk_test").await,
            ApiKeyValidation::Unavailable(_)
        ));
    }

    #[tokio::test]
    async fn test_status_unauthorized_is_invalid() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        assert!(matches!(
            client.validate_api_key_status("bad_key").await,
            ApiKeyValidation::Invalid
        ));
    }

    #[tokio::test]
    async fn test_status_valid_false_is_invalid() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "valid": false,
                "user_id": "u1",
                "email": "test@example.com",
                "plan": "free"
            })))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        assert!(matches!(
            client.validate_api_key_status("pk_test").await,
            ApiKeyValidation::Invalid
        ));
    }

    #[tokio::test]
    async fn test_status_suspended_user_is_valid_but_suspended() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "valid": true,
                "user_id": "u1",
                "email": "test@example.com",
                "plan": "free",
                "status": "suspended"
            })))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        // A suspended user validates as Valid(status=Suspended); the loop keys off the
        // status to disconnect, so this must NOT collapse to Unavailable/Invalid.
        match client.validate_api_key_status("pk_test").await {
            ApiKeyValidation::Valid(user) => {
                assert_eq!(user.status, UserStatus::Suspended);
                assert!(!user.status.is_active());
            }
            other => panic!("expected Valid(suspended), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_validate_api_key_dev_mode_uses_control_plane_when_configured() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .and(header("Authorization", "Bearer pk_test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(success_auth_body()))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), true);
        let user = client.validate_api_key("pk_test").await.unwrap();
        assert_eq!(user.user_id, "u1");
        assert_eq!(user.email, "test@example.com");
        assert_eq!(user.plan, "free");
    }

    #[tokio::test]
    async fn test_local_auth_accepts_configured_key() {
        let client = ControlPlaneClient::new(
            reqwest::Client::new(),
            String::new(),
            String::new(),
            false,
            Some(vec![TEST_KEY.to_string()]),
        );

        let user = client
            .validate_api_key(TEST_KEY)
            .await
            .expect("local key valid");
        let mut hasher = Sha256::new();
        hasher.update(TEST_KEY.as_bytes());
        let expected_hash = format!("{:x}", hasher.finalize());
        assert_eq!(user.user_id, format!("local-{expected_hash}"));
        assert_eq!(user.plan, "self-hosted");
    }

    #[tokio::test]
    async fn test_local_auth_rejects_unknown_key() {
        let client = ControlPlaneClient::new(
            reqwest::Client::new(),
            String::new(),
            String::new(),
            false,
            Some(vec![TEST_KEY.to_string()]),
        );

        let err = client
            .validate_api_key("pk_test_unknown")
            .await
            .expect_err("unknown key should fail");
        assert!(err.to_string().contains("invalid API key"));
    }

    #[test]
    fn test_production_requires_auth_source() {
        let path = write_temp_config(
            r#"
bind_addr = "127.0.0.1:7443"
internal_token = "custom-internal-token"
"#,
        );

        let result = ServerConfig::from_file(&path, false);
        assert!(result.is_err());
        let err = result.expect_err("config should fail").to_string();
        assert!(
            err.contains("production mode requires either control_plane_url or local_api_keys"),
            "unexpected error: {err}"
        );

        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_auth_cache_hit() {
        let mock_server = MockServer::start().await;
        let _guard = Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(success_auth_body()))
            .expect(1)
            .mount_as_scoped(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        let cache = AuthCache::new(Duration::from_secs(60));

        assert!(cache.get("pk_test").is_none());
        let user = client.validate_api_key("pk_test").await.unwrap();
        cache.insert("pk_test", user);

        let cached = cache.get("pk_test");
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().user_id, "u1");
    }

    #[tokio::test]
    async fn test_auth_cache_expiry() {
        let mock_server = MockServer::start().await;
        let _guard = Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(success_auth_body()))
            .expect(2)
            .mount_as_scoped(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        let cache = AuthCache::new(Duration::from_millis(1));

        let user = client.validate_api_key("pk_test").await.unwrap();
        cache.insert("pk_test", user);

        tokio::time::sleep(Duration::from_millis(5)).await;

        assert!(cache.get("pk_test").is_none());
        let user = client.validate_api_key("pk_test").await.unwrap();
        cache.insert("pk_test", user);
    }

    #[tokio::test]
    async fn test_register_tunnel_success() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels"))
            .and(header("Authorization", "Bearer pk_test"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "tunnel": {
                    "id": "tun_123",
                    "subdomain": "myapp"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        let resp = client
            .register_tunnel("pk_test", "myapp", "http")
            .await
            .unwrap();
        assert_eq!(resp.id, "tun_123");
        assert_eq!(resp.subdomain, "myapp");
    }

    #[tokio::test]
    async fn test_register_tunnel_subdomain_conflict() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels"))
            .respond_with(ResponseTemplate::new(409))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        let err = client
            .register_tunnel("pk_test", "taken", "http")
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("subdomain already in use"));
    }

    #[tokio::test]
    async fn test_register_tunnel_plan_limit() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels"))
            .respond_with(ResponseTemplate::new(402))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        let err = client
            .register_tunnel("pk_test", "another", "http")
            .await
            .err()
            .unwrap();
        assert!(err.to_string().contains("tunnel limit reached"));
    }

    #[tokio::test]
    async fn test_register_tunnel_retries_on_5xx() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels"))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels"))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "tunnel": {
                    "id": "tun_retry",
                    "subdomain": "myapp"
                }
            })))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        let resp = client
            .register_tunnel("pk_test", "myapp", "http")
            .await
            .expect("register_tunnel should retry once after 5xx and succeed");
        assert_eq!(resp.id, "tun_retry");
        assert_eq!(resp.subdomain, "myapp");
    }

    #[tokio::test]
    async fn test_register_tunnel_no_retry_on_plan_limit() {
        let mock_server = MockServer::start().await;

        let _mock = Mock::given(method("POST"))
            .and(path("/api/v1/tunnels"))
            .respond_with(ResponseTemplate::new(402))
            .expect(1)
            .mount_as_scoped(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        let result = client.register_tunnel("pk_test", "another", "http").await;
        assert!(
            result.is_err(),
            "plan-limit response should not be retried and must fail"
        );
        let err = result
            .err()
            .expect("error should be present for plan-limit response");
        assert!(err.to_string().contains("tunnel limit reached"));
    }

    #[tokio::test]
    async fn test_register_tunnel_dev_mode() {
        let client = make_client("http://localhost:1", true);
        let resp = client
            .register_tunnel("anything", "myapp", "http")
            .await
            .unwrap();
        assert_eq!(resp.subdomain, "myapp");
        assert!(!resp.id.is_empty());
    }

    #[tokio::test]
    async fn test_register_tunnel_local_self_hosted_without_workers() {
        let client = ControlPlaneClient::new(
            reqwest::Client::new(),
            String::new(),
            String::new(),
            false,
            Some(vec![TEST_KEY.to_string()]),
        );

        let resp = client
            .register_tunnel(TEST_KEY, "myapp", "http")
            .await
            .expect("local self-hosted registration should not require workers");
        assert_eq!(resp.subdomain, "myapp");
        assert!(!resp.id.is_empty());
    }
}
