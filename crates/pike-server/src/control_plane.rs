use std::time::Duration;

use crate::connection::{UserLimits, UserStatus, ValidatedUser};
use anyhow::{anyhow, Result};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use tracing::error;

/// Outcome of validating an API key against the control plane.
///
/// Distinguishes a DEFINITIVE negative (`Invalid` — the key is genuinely bad, lacks the
/// tunnel scope, the user is gone, or the control plane explicitly said `valid: false`)
/// from a TRANSIENT failure (`Unavailable` — network error, timeout, 5xx after retry, or
/// a relay/Workers version mismatch). Callers that take destructive action on a negative
/// (the session revalidation tick disconnecting a live connection) MUST act only on
/// `Invalid`, never on `Unavailable`, so a momentary control-plane blip can't disconnect
/// every connected user.
#[derive(Debug)]
pub enum ApiKeyValidation {
    Valid(Box<ValidatedUser>),
    Invalid(String),
    Unavailable(String),
}

/// Version of the Worker public-port reservation contract.
pub const PORT_PROTOCOL: u8 = 1;

pub struct ControlPlaneClient {
    http_client: reqwest::Client,
    control_plane_url: String,
    workers_api_url: String,
    dev_mode: bool,
    local_api_keys: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct TunnelRegistrationResponse {
    pub id: String,
    pub subdomain: String,
}

#[derive(Deserialize)]
struct ValidateApiKeyResponse {
    #[serde(default)]
    quota_protocol: Option<u8>,
    valid: bool,
    #[serde(default)]
    scopes: Option<Vec<String>>,
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
    config: &'a serde_json::Value,
}

#[derive(Deserialize)]
struct CreateTunnelResponse {
    tunnel: TunnelRegistrationResponse,
}

#[derive(Clone, Serialize)]
pub struct EndpointLease {
    pub quota_protocol: u8,
    pub policy_protocol: u8,
    pub domain_protocol: u8,
    #[serde(skip)]
    pub tunnel_id: String,
    pub lease_id: String,
    pub endpoint_url: String,
    pub remote_port: Option<u16>,
    pub transport: String,
    pub config: serde_json::Value,
}

#[derive(Serialize)]
pub struct EndpointRenewal<'a> {
    pub lease_id: &'a str,
    pub quota_protocol: u8,
    pub policy_protocol: u8,
    pub policy_revision: u64,
    pub domain_protocol: u8,
    pub domain_revision: u64,
    pub certificates: Vec<crate::certificates::CertificateStatus>,
}

#[derive(Deserialize)]
pub struct EndpointAdmission {
    pub visitor: crate::visitor_policy::PolicyRecord,
    pub domains: crate::domain_grants::DomainSet,
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

    pub async fn validate_api_key(&self, api_key: &str) -> Result<ValidatedUser> {
        self.validate_relay_api_key(api_key, None).await
    }

    /// Relay session validation (login, registration, live revocation checks).
    /// The configured server token identifies relay traffic to the Worker so
    /// steady revalidation is not throttled as interactive validation; the API
    /// key itself is still validated live in full.
    ///
    /// Collapses the outcome to a `Result`: at login a transient failure and a bad
    /// key are both simply "reject" (fail-closed). Use
    /// [`Self::validate_relay_api_key_status`] where a negative would tear down an
    /// established session.
    pub async fn validate_relay_api_key(
        &self,
        api_key: &str,
        server_token: Option<&str>,
    ) -> Result<ValidatedUser> {
        match self
            .validate_relay_api_key_status(api_key, server_token)
            .await
        {
            ApiKeyValidation::Valid(user) => Ok(*user),
            ApiKeyValidation::Invalid(reason) | ApiKeyValidation::Unavailable(reason) => {
                Err(anyhow!(reason))
            }
        }
    }

    /// Classified validation without a server token (see [`ApiKeyValidation`]).
    pub async fn validate_api_key_status(&self, api_key: &str) -> ApiKeyValidation {
        self.validate_relay_api_key_status(api_key, None).await
    }

    /// Validate an API key, classifying the result as valid / definitively-invalid /
    /// transiently-unavailable. Prefer this over [`Self::validate_relay_api_key`]
    /// whenever a negative result triggers destructive action.
    pub async fn validate_relay_api_key_status(
        &self,
        api_key: &str,
        server_token: Option<&str>,
    ) -> ApiKeyValidation {
        if let Some(local_keys) = &self.local_api_keys {
            if !local_keys.iter().any(|key| key == api_key) {
                return ApiKeyValidation::Invalid("invalid API key".into());
            }

            let key_hash = hash_api_key(api_key);
            return ApiKeyValidation::Valid(Box::new(ValidatedUser {
                tunnel_limit: None,
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
            let mut request = self
                .http_client
                .post(&url)
                .header("Authorization", format!("Bearer {api_key}"));
            // The server token is only ever sent to the Workers API it is issued for.
            let same_worker = self.control_plane_url.trim_end_matches('/')
                == self.workers_api_url.trim_end_matches('/');
            if let Some(token) = server_token.filter(|token| same_worker && !token.is_empty()) {
                request = request.header("X-Server-Token", token);
            }
            let response = request.timeout(Duration::from_secs(5)).send().await;

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
                return ApiKeyValidation::Invalid("invalid API key".into());
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
                return ApiKeyValidation::Unavailable(format!("auth validation returned {status}"));
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
                return ApiKeyValidation::Invalid("invalid API key".into());
            }
            if !self.dev_mode && body.quota_protocol != Some(crate::quota::QUOTA_PROTOCOL) {
                // A relay/Workers version mismatch, not a verdict on the key: login must
                // fail, but an established session is not torn down for it.
                return ApiKeyValidation::Unavailable(
                    "control plane quota protocol 1 required; upgrade Workers before this relay"
                        .into(),
                );
            }
            if !body
                .scopes
                .as_ref()
                .is_some_and(|scopes| scopes.iter().any(|scope| scope == "tunnels:write"))
            {
                return ApiKeyValidation::Invalid("API key requires tunnels:write scope".into());
            }
            let limits = body.limits.map(UserLimits::from).unwrap_or_default();
            return ApiKeyValidation::Valid(Box::new(ValidatedUser {
                tunnel_limit: limits.max_tunnels.map(u64::from),
                user_id: body.user_id,
                email: body.email,
                plan: body.plan,
                plan_expires_at: body.plan_expires_at,
                status: UserStatus::from_name(body.status.as_deref()),
                limits,
            }));
        }

        ApiKeyValidation::Unavailable("auth validation failed after retry".into())
    }

    pub async fn register_tunnel(
        &self,
        api_key: &str,
        subdomain: &str,
        tunnel_type: &str,
        config: &serde_json::Value,
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
                    config,
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
                if let Some(existing) = self
                    .find_tunnel_by_subdomain(api_key, subdomain, tunnel_type)
                    .await?
                {
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

    /// Atomic public-port reservation for a TCP or UDP profile, taken before
    /// the relay binds anything. The Worker returns the profile's one reserved
    /// number: the configured `remote_port`, or a stable number it chose for a
    /// profile without one. Every relay and connector of the profile receives
    /// the same number; a number reserved by another profile is refused.
    pub async fn reserve_public_port(
        &self,
        api_key: &str,
        server_token: &str,
        tunnel_id: &str,
        requested_port: Option<u16>,
    ) -> Result<u16> {
        let response = self
            .http_client
            .post(format!(
                "{}/api/v1/tunnels/{tunnel_id}/reserve-port",
                self.workers_api_url.trim_end_matches('/')
            ))
            .bearer_auth(api_key)
            .header("X-Server-Token", server_token)
            .json(&serde_json::json!({"port_protocol": PORT_PROTOCOL, "requested_port": requested_port}))
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let reason = response
                .json::<ApiErrorResponse>()
                .await
                .ok()
                .and_then(|body| body.error)
                .unwrap_or_default();
            anyhow::bail!("public port reservation failed: {status} {reason}");
        }
        let body: serde_json::Value = response.json().await?;
        anyhow::ensure!(
            body["port_protocol"].as_u64() == Some(u64::from(PORT_PROTOCOL)),
            "public port protocol 1 acknowledgement required; upgrade Workers"
        );
        let port = body["port"]
            .as_u64()
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| (10_000..=65_000).contains(port))
            .ok_or_else(|| anyhow!("public port reservation returned an invalid port"))?;
        anyhow::ensure!(
            requested_port.is_none_or(|requested| requested == port),
            "public port reservation {port} differs from the requested port"
        );
        Ok(port)
    }

    pub async fn publish_endpoint(
        &self,
        api_key: &str,
        server_token: &str,
        lease: &EndpointLease,
    ) -> Result<EndpointAdmission> {
        let acknowledgement = self
            .lease_request(
                api_key,
                server_token,
                &format!("{}/connect", lease.tunnel_id),
                &serde_json::to_value(lease)?,
            )
            .await?;
        Ok(serde_json::from_value(acknowledgement)?)
    }

    pub async fn publish_origin_health(
        &self,
        api_key: &str,
        server_token: &str,
        tunnel_id: &str,
        lease_id: &str,
        report: Option<&pike_core::proto::origin_health::OriginHealthReport>,
    ) -> Result<()> {
        let response = self.http_client.post(format!("{}/api/v1/tunnels/{tunnel_id}/health", self.workers_api_url.trim_end_matches('/')))
            .bearer_auth(api_key).header("X-Server-Token", server_token)
            .json(&serde_json::json!({ "health_protocol": 1, "lease_id": lease_id, "report": report, "sent_at": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis() as u64 }))
            .timeout(Duration::from_secs(5)).send().await?;
        anyhow::ensure!(
            response.status().is_success(),
            "origin health publication rejected"
        );
        Ok(())
    }

    pub async fn renew_endpoint(
        &self,
        api_key: &str,
        server_token: &str,
        tunnel_id: &str,
        renewal: &EndpointRenewal<'_>,
    ) -> Result<crate::domain_grants::DomainSet> {
        let acknowledgement = self
            .lease_request(
                api_key,
                server_token,
                &format!("{tunnel_id}/heartbeat"),
                &serde_json::to_value(renewal)?,
            )
            .await?;
        anyhow::ensure!(
            acknowledgement["policy_revision"].as_u64() == Some(renewal.policy_revision),
            "visitor policy revision changed"
        );
        Ok(serde_json::from_value(acknowledgement["domains"].clone())?)
    }

    async fn lease_request(
        &self,
        api_key: &str,
        server_token: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let response = self
            .http_client
            .post(format!(
                "{}/api/v1/tunnels/{path}",
                self.workers_api_url.trim_end_matches('/')
            ))
            .bearer_auth(api_key)
            .header("X-Server-Token", server_token)
            .json(body)
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            let reason = response
                .json::<ApiErrorResponse>()
                .await
                .ok()
                .and_then(|body| body.error)
                .unwrap_or_default();
            anyhow::bail!("cloud endpoint lease failed: {status} {reason}");
        }
        let acknowledgement: serde_json::Value = response.json().await?;
        anyhow::ensure!(
            acknowledgement["quota_protocol"].as_u64()
                == Some(u64::from(crate::quota::QUOTA_PROTOCOL)),
            "endpoint lease requires quota protocol 1 acknowledgement"
        );
        anyhow::ensure!(
            acknowledgement["policy_protocol"].as_u64()
                == Some(u64::from(crate::visitor_policy::POLICY_PROTOCOL)),
            "visitor policy protocol 4 acknowledgement required; upgrade Workers"
        );
        anyhow::ensure!(
            acknowledgement["domain_protocol"].as_u64()
                == Some(u64::from(crate::domain_grants::DOMAIN_PROTOCOL)),
            "domain protocol 1 acknowledgement required; upgrade Workers"
        );
        Ok(acknowledgement)
    }

    pub async fn release_endpoint(
        &self,
        server_token: &str,
        tunnel_id: &str,
        lease_id: &str,
    ) -> Result<()> {
        self.http_client
            .post(format!(
                "{}/api/v1/tunnels/internal/release",
                self.workers_api_url.trim_end_matches('/')
            ))
            .header("X-Server-Token", server_token)
            .json(&serde_json::json!({"tunnel_id": tunnel_id, "lease_id": lease_id}))
            .timeout(Duration::from_secs(5))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    fn should_skip_remote_tunnel_registration(&self) -> bool {
        self.local_api_keys.is_some() && self.workers_api_url.trim().is_empty()
    }

    async fn find_tunnel_by_subdomain(
        &self,
        api_key: &str,
        subdomain: &str,
        tunnel_type: &str,
    ) -> Result<Option<TunnelRegistrationResponse>> {
        let response = self
            .http_client
            .post(format!(
                "{}/api/v1/tunnels/resolve",
                self.workers_api_url.trim_end_matches('/')
            ))
            .bearer_auth(api_key)
            .json(&serde_json::json!({"subdomain": subdomain, "tunnel_type": tunnel_type}))
            .timeout(Duration::from_secs(5))
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            anyhow::bail!("owned tunnel resolution failed: {}", response.status());
        }
        Ok(Some(response.json::<CreateTunnelResponse>().await?.tunnel))
    }
}

fn hash_api_key(api_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(api_key.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::json;
    use sha2::{Digest, Sha256};
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{ApiKeyValidation, ControlPlaneClient};
    use crate::config::ServerConfig;
    use crate::connection::UserStatus;

    const TEST_KEY: &str = "pk_test_abc123";

    fn success_auth_body() -> serde_json::Value {
        json!({
            "valid": true,
            "quota_protocol": 1,
                "scopes": ["tunnels:read", "tunnels:write"],
            "user_id": "u1",
            "email": "test@example.com",
            "plan": "free",
            "plan_expires_at": null,
            "auth_type": "apikey"
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
            ApiKeyValidation::Invalid(_)
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
            ApiKeyValidation::Invalid(_)
        ));
    }

    #[tokio::test]
    async fn test_status_missing_scope_is_invalid_and_stale_quota_contract_is_unavailable() {
        for (body, definitive) in [
            (
                json!({
                    "valid": true, "quota_protocol": 1, "scopes": ["tunnels:read"],
                    "user_id": "u1", "email": "test@example.com", "plan": "free"
                }),
                true,
            ),
            (
                json!({
                    "valid": true, "quota_protocol": 0, "scopes": ["tunnels:write"],
                    "user_id": "u1", "email": "test@example.com", "plan": "free"
                }),
                false,
            ),
        ] {
            let mock_server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/api/v1/auth/validate"))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&mock_server)
                .await;
            let client = make_client(&mock_server.uri(), false);
            let outcome = client.validate_api_key_status("pk_test").await;
            assert_eq!(
                matches!(outcome, ApiKeyValidation::Invalid(_)),
                definitive,
                "unexpected classification: {outcome:?}"
            );
            assert!(client.validate_api_key("pk_test").await.is_err());
        }
    }

    #[tokio::test]
    async fn test_status_suspended_user_is_valid_but_suspended() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "valid": true,
                "quota_protocol": 1,
                "scopes": ["tunnels:write"],
                "user_id": "u1",
                "email": "test@example.com",
                "plan": "free",
                "status": "suspended",
                "limits": { "tunnels": 3, "bandwidth_gb": 1, "requests_per_day": 10 }
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
                // The hosted tunnel cap and the plan limits come from one `limits` object.
                assert_eq!(user.tunnel_limit, Some(3));
                assert_eq!(user.limits.max_tunnels, Some(3));
                assert_eq!(user.limits.bandwidth_bytes_per_month, Some(1 << 30));
                assert_eq!(user.limits.requests_per_day, Some(10));
            }
            other => panic!("expected Valid(suspended), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn relay_validation_identifies_the_relay_and_ordinary_validation_does_not() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .and(header("Authorization", "Bearer pk_revoked"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&mock_server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .and(header("Authorization", "Bearer pk_test"))
            .respond_with(ResponseTemplate::new(200).set_body_json(success_auth_body()))
            .mount(&mock_server)
            .await;

        let client = make_client(&mock_server.uri(), false);
        let user = client
            .validate_relay_api_key("pk_test", Some("relay-secret"))
            .await
            .unwrap();
        assert_eq!(user.user_id, "u1");
        client.validate_api_key("pk_test").await.unwrap();
        // The server token never substitutes for a valid API key.
        let err = client
            .validate_relay_api_key("pk_revoked", Some("relay-secret"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid API key"));

        let requests = mock_server.received_requests().await.unwrap();
        let tokens: Vec<_> = requests
            .iter()
            .map(|request| {
                request
                    .headers
                    .get("X-Server-Token")
                    .map(|value| value.to_str().unwrap().to_string())
            })
            .collect();
        assert_eq!(
            tokens,
            vec![
                Some("relay-secret".to_string()),
                None,
                Some("relay-secret".to_string())
            ]
        );
    }

    #[tokio::test]
    async fn relay_validation_keeps_the_token_off_a_separate_auth_host() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/auth/validate"))
            .respond_with(ResponseTemplate::new(200).set_body_json(success_auth_body()))
            .mount(&mock_server)
            .await;

        let client = ControlPlaneClient::new(
            reqwest::Client::new(),
            mock_server.uri(),
            "http://workers.invalid".to_string(),
            false,
            None,
        );
        client
            .validate_relay_api_key("pk_test", Some("relay-secret"))
            .await
            .unwrap();
        let requests = mock_server.received_requests().await.unwrap();
        assert!(requests[0].headers.get("X-Server-Token").is_none());
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
            .register_tunnel("pk_test", "myapp", "http", &serde_json::json!({}))
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
            .register_tunnel("pk_test", "taken", "http", &serde_json::json!({}))
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
            .register_tunnel("pk_test", "another", "http", &serde_json::json!({}))
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
            .register_tunnel("pk_test", "myapp", "http", &serde_json::json!({}))
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
        let result = client
            .register_tunnel("pk_test", "another", "http", &serde_json::json!({}))
            .await;
        assert!(
            result.is_err(),
            "plan-limit response should not be retried and must fail"
        );
        let err = result.expect_err("error should be present for plan-limit response");
        assert!(err.to_string().contains("tunnel limit reached"));
    }

    #[tokio::test]
    async fn test_register_tunnel_dev_mode() {
        let client = make_client("http://localhost:1", true);
        let resp = client
            .register_tunnel("anything", "myapp", "http", &serde_json::json!({}))
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
            .register_tunnel(TEST_KEY, "myapp", "http", &serde_json::json!({}))
            .await
            .expect("local self-hosted registration should not require workers");
        assert_eq!(resp.subdomain, "myapp");
        assert!(!resp.id.is_empty());
    }
    #[tokio::test]
    async fn port_reservation_requires_protocol_agreement_and_a_pool_port() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels/profile-1/reserve-port"))
            .and(header("X-Server-Token", "relay-secret"))
            .and(wiremock::matchers::body_json(
                json!({"port_protocol": 1, "requested_port": null}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"port_protocol": 1, "port": 30555})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels/profile-2/reserve-port"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"port_protocol": 1, "port": 30555})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels/profile-3/reserve-port"))
            .respond_with(
                ResponseTemplate::new(409)
                    .set_body_json(json!({"error": "Public port is reserved by another tunnel"})),
            )
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels/profile-4/reserve-port"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"port": 30555})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels/profile-5/reserve-port"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"port_protocol": 1, "port": 80})),
            )
            .mount(&server)
            .await;
        let client = make_client(&server.uri(), false);
        assert_eq!(
            client
                .reserve_public_port("pk_test", "relay-secret", "profile-1", None)
                .await
                .unwrap(),
            30555
        );
        // The Worker's number is authoritative; a disagreeing explicit request fails.
        let error = client
            .reserve_public_port("pk_test", "relay-secret", "profile-2", Some(30556))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("differs"), "{error}");
        assert_eq!(
            client
                .reserve_public_port("pk_test", "relay-secret", "profile-2", Some(30555))
                .await
                .unwrap(),
            30555
        );
        let error = client
            .reserve_public_port("pk_test", "relay-secret", "profile-3", None)
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("reserved by another tunnel"),
            "{error}"
        );
        assert!(client
            .reserve_public_port("pk_test", "relay-secret", "profile-4", None)
            .await
            .is_err());
        assert!(client
            .reserve_public_port("pk_test", "relay-secret", "profile-5", None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn owned_conflict_resolves_with_write_scope_without_reactivating() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels"))
            .respond_with(ResponseTemplate::new(409))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels/resolve"))
            .and(header("Authorization", "Bearer pk_owner"))
            .and(wiremock::matchers::body_json(
                json!({"subdomain":"myapp","tunnel_type":"http"}),
            ))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({"tunnel":{"id":"canonical-id","subdomain":"myapp"}})),
            )
            .expect(1)
            .mount(&server)
            .await;
        let result = make_client(&server.uri(), false)
            .register_tunnel("pk_owner", "myapp", "http", &json!({}))
            .await
            .unwrap();
        assert_eq!(result.id, "canonical-id");
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn disabled_or_changed_owned_tunnel_is_not_reactivated() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels"))
            .respond_with(ResponseTemplate::new(409))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/api/v1/tunnels/resolve"))
            .respond_with(ResponseTemplate::new(409))
            .expect(1)
            .mount(&server)
            .await;
        let error = make_client(&server.uri(), false)
            .register_tunnel("pk_owner", "myapp", "http", &json!({}))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("resolution failed: 409"));
    }
}
