//! Discovery and authorization-code exchange. Endpoints originate only from
//! certificate-verified discovery for the exact configured issuer.
use super::{OidcPolicy, TokenAuth};
use crate::visitor_policy::{
    identity_http::Document,
    jwks::KeyStore,
    jwt::{JwtPolicy, JwtVerifier},
    Rejection,
};
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Option<Vec<String>>,
    code_challenge_methods_supported: Option<Vec<String>>,
}
pub struct Provider {
    pub binding: String,
    pub authorization_url: reqwest::Url,
    token_url: String,
    verifier: JwtVerifier,
    keys: Arc<KeyStore>,
}
fn json<T: serde::de::DeserializeOwned>(document: &Document) -> Result<T> {
    let content_type = document
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    ensure!(
        content_type
            .split(';')
            .next()
            .is_some_and(|s| s.trim().eq_ignore_ascii_case("application/json")),
        "OIDC requires JSON responses"
    );
    Ok(serde_json::from_slice(&document.body)?)
}
impl Provider {
    #[cfg(test)]
    pub(super) fn fixture() -> Arc<Self> {
        let keys = KeyStore::new(&[]).unwrap();
        Arc::new(Self {
            binding: "fixture-provider".into(),
            authorization_url: "https://identity.example.com/authorize".parse().unwrap(),
            token_url: "https://identity.example.com/token".into(),
            verifier: JwtVerifier::new(
                JwtPolicy {
                    issuer: "https://identity.example.com".into(),
                    audience: "pike".into(),
                    jwks_url: "https://identity.example.com/keys".into(),
                    algorithm: crate::visitor_policy::jwt::SigningAlgorithm::RS256,
                    token_type: None,
                    required_scopes: vec![],
                    revoked_jti: vec![],
                    max_lifetime_secs: 3600,
                },
                &keys,
            )
            .unwrap(),
            keys,
        })
    }
    pub async fn discover(policy: &OidcPolicy, keys: Arc<KeyStore>) -> Result<Arc<Self>> {
        let source = format!(
            "{}/.well-known/openid-configuration",
            policy.issuer.trim_end_matches('/')
        );
        let document = keys.http().get(&source).await?;
        let discovery: Discovery = json(&document)?;
        ensure!(
            discovery.issuer == policy.issuer,
            "OIDC discovery issuer mismatch"
        );
        ensure!(
            discovery
                .response_types_supported
                .iter()
                .any(|v| v == "code"),
            "OIDC code flow required"
        );
        let algorithm = match policy.algorithm {
            crate::visitor_policy::jwt::SigningAlgorithm::RS256 => "RS256",
            crate::visitor_policy::jwt::SigningAlgorithm::ES256 => "ES256",
        };
        ensure!(
            discovery
                .id_token_signing_alg_values_supported
                .iter()
                .any(|v| v == algorithm),
            "OIDC signing algorithm not supported"
        );
        ensure!(
            discovery
                .code_challenge_methods_supported
                .is_none_or(|v| v.iter().any(|v| v == "S256")),
            "OIDC PKCE S256 required"
        );
        let methods = discovery
            .token_endpoint_auth_methods_supported
            .unwrap_or_else(|| vec!["client_secret_basic".into()]);
        ensure!(
            methods
                .iter()
                .any(|v| v == policy.token_endpoint_auth_method.name()),
            "OIDC client authentication method not supported"
        );
        // Authorization is a browser redirect; token and key endpoints also pass
        // the relay's actual-IP egress rules before any credential can be sent.
        let authorization_url = keys.http().validate(&discovery.authorization_endpoint)?;
        ensure!(
            authorization_url.query_pairs().all(|(name, _)| ![
                "response_type",
                "client_id",
                "redirect_uri",
                "scope",
                "state",
                "nonce",
                "code_challenge",
                "code_challenge_method",
                "response_mode",
                "request",
                "request_uri"
            ]
            .contains(&name.as_ref())),
            "OIDC authorization endpoint has conflicting parameters"
        );
        keys.http().validate(&discovery.token_endpoint)?;
        let binding = super::store::digest(&serde_json::to_string(&[
            &discovery.authorization_endpoint,
            &discovery.token_endpoint,
            &discovery.jwks_uri,
        ])?);
        let verifier = JwtVerifier::new(
            JwtPolicy {
                issuer: policy.issuer.clone(),
                audience: policy.client_id.clone(),
                jwks_url: discovery.jwks_uri,
                algorithm: policy.algorithm,
                token_type: None,
                required_scopes: vec![],
                revoked_jti: vec![],
                max_lifetime_secs: 86400,
            },
            &keys,
        )?;
        Ok(Arc::new(Self {
            binding,
            authorization_url,
            token_url: discovery.token_endpoint,
            verifier,
            keys,
        }))
    }
    pub async fn exchange(
        &self,
        policy: &OidcPolicy,
        code: &str,
        verifier: &str,
        nonce: &str,
    ) -> Result<tokio::time::Instant, Rejection> {
        let mut fields = vec![
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), code.into()),
            ("redirect_uri".into(), policy.redirect_uri.clone()),
            ("code_verifier".into(), verifier.into()),
        ];
        let secret = policy.client_secret.as_deref().unwrap_or("");
        let mut encoded = None;
        match policy.token_endpoint_auth_method {
            TokenAuth::None => fields.push(("client_id".into(), policy.client_id.clone())),
            TokenAuth::SecretPost => {
                fields.push(("client_id".into(), policy.client_id.clone()));
                fields.push(("client_secret".into(), secret.into()));
            }
            TokenAuth::SecretBasic => {
                // RFC 6749 encodes each credential as form data before Basic.
                fn encode(value: &str) -> String {
                    reqwest::Url::parse_with_params("https://unused.invalid", &[("", value)])
                        .unwrap()
                        .query()
                        .unwrap()
                        .trim_start_matches('=')
                        .to_owned()
                }
                encoded = Some((encode(&policy.client_id), encode(secret)));
            }
        }
        let basic = encoded
            .as_ref()
            .map(|(id, secret)| (id.as_str(), secret.as_str()));
        let document = self
            .keys
            .http()
            .post_form(&self.token_url, &fields, basic)
            .await
            .map_err(|_| Rejection::Unavailable)?;
        let tokens: Tokens = json(&document).map_err(|_| Rejection::InvalidSignIn)?;
        if !tokens.token_type.eq_ignore_ascii_case("Bearer")
            || tokens.access_token.len() > 16384
            || tokens.access_token.is_empty()
            || !tokens.access_token.bytes().all(|b| (33..=126).contains(&b))
        {
            return Err(Rejection::InvalidSignIn);
        }
        let expires = self
            .verifier
            .authorize(&tokens.id_token)
            .await
            .map_err(|e| {
                if matches!(e, Rejection::Unavailable) {
                    e
                } else {
                    Rejection::InvalidSignIn
                }
            })?;
        let body = tokens
            .id_token
            .split('.')
            .nth(1)
            .ok_or(Rejection::InvalidSignIn)?;
        let claims: Identity = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(body)
                .map_err(|_| Rejection::InvalidSignIn)?,
        )
        .map_err(|_| Rejection::InvalidSignIn)?;
        let sole_audience = match &claims.aud {
            Audience::One(value) => value == &policy.client_id,
            Audience::Many(values) => {
                !values.is_empty() && values.iter().all(|value| value == &policy.client_id)
            }
        };
        if claims.nonce != nonce
            || !sole_audience
            || claims.azp.as_ref().is_some_and(|v| v != &policy.client_id)
            || policy
                .allowed_subjects
                .as_ref()
                .is_some_and(|values| !values.contains(&claims.sub))
            || policy.allowed_emails.as_ref().is_some_and(|values| {
                claims.email_verified != Some(true)
                    || claims
                        .email
                        .as_ref()
                        .is_none_or(|email| !values.contains(email))
            })
            || claims
                .at_hash
                .as_ref()
                .is_some_and(|expected| expected != &half_hash(&tokens.access_token))
            || claims
                .c_hash
                .as_ref()
                .is_some_and(|expected| expected != &half_hash(code))
        {
            return Err(Rejection::InvalidSignIn);
        }
        Ok(expires)
    }
}
fn half_hash(value: &str) -> String {
    URL_SAFE_NO_PAD
        .encode(&ring::digest::digest(&ring::digest::SHA256, value.as_bytes()).as_ref()[..16])
}
#[derive(Deserialize)]
struct Tokens {
    id_token: String,
    access_token: String,
    token_type: String,
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
#[derive(Deserialize)]
struct Identity {
    sub: String,
    aud: Audience,
    nonce: String,
    azp: Option<String>,
    email: Option<String>,
    email_verified: Option<bool>,
    at_hash: Option<String>,
    c_hash: Option<String>,
}
