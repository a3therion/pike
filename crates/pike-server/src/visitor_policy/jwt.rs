//! Pinned asymmetric JWT authentication. Claims are checked only as rejection
//! hints before key retrieval; admission always requires a verified signature.
use super::{
    jwks::{KeyError, KeyStore, Source},
    Rejection,
};
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{decode, decode_header, errors::ErrorKind, Algorithm, Validation};
use serde::{Deserialize, Serialize};
use std::{
    sync::{Arc, OnceLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JwtPolicy {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
    pub algorithm: SigningAlgorithm,
    pub token_type: Option<String>,
    #[serde(default)]
    pub required_scopes: Vec<String>,
    #[serde(default)]
    pub revoked_jti: Vec<String>,
    #[serde(default = "default_lifetime")]
    pub max_lifetime_secs: u64,
}
const fn default_lifetime() -> u64 {
    3600
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum SigningAlgorithm {
    RS256,
    ES256,
}
impl SigningAlgorithm {
    fn algorithm(self) -> Algorithm {
        match self {
            Self::RS256 => Algorithm::RS256,
            Self::ES256 => Algorithm::ES256,
        }
    }
}
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}
#[derive(Deserialize)]
struct Claims {
    iss: String,
    aud: Audience,
    sub: String,
    exp: u64,
    iat: u64,
    nbf: Option<u64>,
    scope: Option<String>,
    scp: Option<Vec<String>>,
    jti: Option<String>,
}
pub struct JwtVerifier {
    policy: JwtPolicy,
    source: Arc<Source>,
    validation: Validation,
}
fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.bytes().any(|c| c <= 32 || c == 127)
}
impl JwtVerifier {
    pub fn new(policy: JwtPolicy, keys: &KeyStore) -> Result<Self> {
        ensure!(
            bounded(&policy.issuer, 2048) && bounded(&policy.audience, 512),
            "invalid JWT issuer or audience"
        );
        ensure!(
            policy.token_type.as_ref().is_none_or(|v| bounded(v, 64)),
            "invalid JWT token type"
        );
        ensure!(
            (60..=86400).contains(&policy.max_lifetime_secs),
            "invalid JWT maximum lifetime"
        );
        ensure!(
            policy.required_scopes.len() <= 32
                && policy.required_scopes.iter().all(|s| bounded(s, 128)),
            "invalid JWT required scopes"
        );
        ensure!(
            policy.revoked_jti.len() <= 64 && policy.revoked_jti.iter().all(|s| bounded(s, 256)),
            "invalid JWT revoked token IDs"
        );
        let mut validation = Validation::new(policy.algorithm.algorithm());
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.set_issuer(&[&policy.issuer]);
        validation.set_audience(&[&policy.audience]);
        validation.leeway = 0;
        validation.validate_nbf = true;
        Ok(Self {
            source: keys.source(&policy.jwks_url)?,
            policy,
            validation,
        })
    }
    fn claims_valid(&self, claims: &Claims, now: u64) -> bool {
        let audience = match &claims.aud {
            Audience::One(value) => bounded(value, 512) && value == &self.policy.audience,
            Audience::Many(values) => {
                !values.is_empty()
                    && values.len() <= 32
                    && values.iter().all(|v| bounded(v, 512))
                    && values.contains(&self.policy.audience)
            }
        };
        let scopes = claims
            .scope
            .as_ref()
            .is_none_or(|s| s.len() <= 4096 && !s.bytes().any(|c| c < 32 || c == 127))
            && claims
                .scp
                .as_ref()
                .is_none_or(|s| s.len() <= 64 && s.iter().all(|v| bounded(v, 128)))
            && self.policy.required_scopes.iter().all(|required| {
                claims
                    .scope
                    .as_ref()
                    .is_some_and(|s| s.split(' ').any(|v| v == required))
                    || claims.scp.as_ref().is_some_and(|s| s.contains(required))
            });
        claims.iss == self.policy.issuer
            && audience
            && bounded(&claims.sub, 512)
            && claims.iat <= now
            && claims.exp > now
            && claims.exp > claims.iat
            && claims.exp - claims.iat <= self.policy.max_lifetime_secs
            && claims.nbf.is_none_or(|nbf| nbf <= now)
            && claims
                .jti
                .as_ref()
                .is_none_or(|jti| bounded(jti, 256) && !self.policy.revoked_jti.contains(jti))
            && scopes
    }
    pub async fn authorize(&self, token: &str) -> Result<tokio::time::Instant, Rejection> {
        let invalid = || Rejection::Bearer;
        if token.len() > 16384 {
            return Err(invalid());
        }
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() != 3
            || parts.iter().any(|p| p.is_empty())
            || parts[0].len() > 4096
            || parts[2].len() > 1400
        {
            return Err(invalid());
        }
        let header = decode_header(token).map_err(|_| invalid())?;
        let algorithm = self.policy.algorithm.algorithm();
        if header.alg != algorithm
            || header.jku.is_some()
            || header.jwk.is_some()
            || header.x5u.is_some()
            || header.crit.is_some()
            || header.enc.is_some()
            || header.zip.is_some()
            || header
                .extras
                .get::<serde_json::Value>("b64")
                .map_err(|_| invalid())?
                .is_some()
            || self
                .policy
                .token_type
                .as_ref()
                .is_some_and(|expected| header.typ.as_ref() != Some(expected))
        {
            return Err(invalid());
        }
        let kid = header
            .kid
            .filter(|kid| bounded(kid, 128))
            .ok_or_else(invalid)?;
        let claims: Claims =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).map_err(|_| invalid())?)
                .map_err(|_| invalid())?;
        if !self.claims_valid(&claims, epoch()?) {
            return Err(invalid());
        }
        static SLOTS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
        let permit = SLOTS
            .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(32)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| Rejection::Unavailable)?;
        let key = self
            .source
            .key(&kid, algorithm, false)
            .await
            .map_err(key_error)?;
        let token_owned = token.to_owned();
        let validation = self.validation.clone();
        let (verified, permit) = tokio::task::spawn_blocking(move || {
            (
                decode::<Claims>(&token_owned, &key.decoding, &validation),
                permit,
            )
        })
        .await
        .map_err(|_| Rejection::Unavailable)?;
        let verified = if verified
            .as_ref()
            .is_err_and(|e| matches!(e.kind(), ErrorKind::InvalidSignature))
        {
            let key = self
                .source
                .key(&kid, algorithm, true)
                .await
                .map_err(key_error)?;
            let token = token.to_owned();
            let validation = self.validation.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                decode::<Claims>(&token, &key.decoding, &validation)
            })
            .await
            .map_err(|_| Rejection::Unavailable)?
        } else {
            drop(permit);
            verified
        };
        let claims = verified.map_err(|_| invalid())?.claims;
        let now = SystemTime::now();
        let seconds = now
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Rejection::Unavailable)?;
        if !self.claims_valid(&claims, seconds.as_secs()) {
            return Err(invalid());
        }
        let remaining = Duration::from_secs(claims.exp)
            .checked_sub(seconds)
            .ok_or_else(invalid)?;
        Ok(tokio::time::Instant::now() + remaining)
    }
}
fn epoch() -> Result<u64, Rejection> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Rejection::Unavailable)?
        .as_secs())
}
fn key_error(error: KeyError) -> Rejection {
    match error {
        KeyError::Invalid => Rejection::Bearer,
        KeyError::Unavailable => Rejection::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn verifier() -> JwtVerifier {
        JwtVerifier::new(
            JwtPolicy {
                issuer: "https://issuer.test/".into(),
                audience: "pike".into(),
                jwks_url: "https://keys.example.com/jwks".into(),
                algorithm: SigningAlgorithm::RS256,
                token_type: Some("at+jwt".into()),
                required_scopes: vec!["read".into()],
                revoked_jti: vec!["revoked".into()],
                max_lifetime_secs: 3600,
            },
            &KeyStore::new(&[]).unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn claims_require_exact_identity_times_scope_and_nonrevoked_id() {
        let verifier = verifier();
        let valid = serde_json::json!({"iss":"https://issuer.test/", "aud":["another", "pike"], "sub":"visitor", "iat":1000, "exp":1100, "nbf":999, "scope":"read write", "jti":"allowed"});
        assert!(verifier.claims_valid(&serde_json::from_value(valid.clone()).unwrap(), 1050));
        for (field, value) in [
            ("iss", serde_json::json!("https://issuer.test")),
            ("aud", serde_json::json!("other")),
            ("sub", serde_json::json!("")),
            ("iat", serde_json::json!(1051)),
            ("exp", serde_json::json!(1050)),
            ("exp", serde_json::json!(9999)),
            ("nbf", serde_json::json!(1051)),
            ("scope", serde_json::json!("bread")),
            ("jti", serde_json::json!("revoked")),
        ] {
            let mut claims = valid.clone();
            claims[field] = value;
            assert!(
                !verifier.claims_valid(&serde_json::from_value(claims).unwrap(), 1050),
                "{field}"
            );
        }
        for field in ["iss", "aud", "sub", "iat", "exp"] {
            let mut claims = valid.clone();
            claims.as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<Claims>(claims).is_err());
        }
        assert!(serde_json::from_str::<Claims>(
            r#"{"iss":"x","iss":"y","aud":"pike","sub":"v","iat":1,"exp":2}"#
        )
        .is_err());
    }
    #[tokio::test]
    async fn malicious_headers_and_claims_fail_before_network() {
        let verifier = verifier();
        let now = epoch().unwrap();
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&serde_json::json!({"iss":"https://issuer.test/","aud":"pike","sub":"v","iat":now,"exp":now+100,"scope":"read"})).unwrap());
        for extra in [
            serde_json::json!({"jku":"https://attacker.test"}),
            serde_json::json!({"jwk":{}}),
            serde_json::json!({"x5u":"https://attacker.test"}),
            serde_json::json!({"crit":["custom"]}),
            serde_json::json!({"b64":false}),
            serde_json::json!({"alg":"HS256"}),
            serde_json::json!({"typ":"JWT"}),
            serde_json::json!({"kid":null}),
        ] {
            let mut header = serde_json::json!({"alg":"RS256","typ":"at+jwt","kid":"key"});
            header
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            let token = format!(
                "{}.{}.c2ln",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
                claims
            );
            assert!(matches!(
                verifier.authorize(&token).await,
                Err(Rejection::Bearer)
            ));
        }
    }
}
