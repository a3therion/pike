//! HTTPS signing-key retrieval. Only operator configuration may allow private
//! networks or additional trust roots; token headers never select a key source.
#[cfg(test)]
use super::identity_http::public_ip;
pub use super::identity_http::{validate_url, SourceConfig};
use anyhow::{bail, ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::{jwk::Jwk, Algorithm, DecodingKey};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak},
    time::{Duration, Instant},
};
use tokio::sync::Mutex as AsyncMutex;
const REFRESH_INTERVAL: Duration = Duration::from_secs(5);
pub struct KeyStore {
    http: Arc<super::identity_http::IdentityHttp>,
    sources: Mutex<HashMap<String, Weak<Source>>>,
}
impl std::fmt::Debug for KeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyStore").finish_non_exhaustive()
    }
}
impl KeyStore {
    pub fn new(config: &[SourceConfig]) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            http: super::identity_http::IdentityHttp::new(config)?,
            sources: Mutex::new(HashMap::new()),
        }))
    }
    pub fn http(&self) -> Arc<super::identity_http::IdentityHttp> {
        self.http.clone()
    }
    pub fn source(&self, value: &str) -> Result<Arc<Source>> {
        let url = self.http.validate(value)?;
        let mut sources = self
            .sources
            .lock()
            .map_err(|_| anyhow::anyhow!("JWKS cache unavailable"))?;
        sources.retain(|_, source| source.strong_count() > 0);
        if let Some(source) = sources.get(url.as_str()).and_then(Weak::upgrade) {
            return Ok(source);
        }
        ensure!(sources.len() < 256, "too many active JWKS sources");
        let source = Arc::new(Source {
            url: url.to_string(),
            http: self.http.clone(),
            state: AsyncMutex::new(State::default()),
        });
        sources.insert(url.to_string(), Arc::downgrade(&source));
        Ok(source)
    }
}
#[derive(Clone)]
pub struct Key {
    pub algorithm: Algorithm,
    pub decoding: DecodingKey,
}
struct Snapshot {
    keys: HashMap<String, Key>,
    expires: Instant,
}
#[derive(Default)]
struct State {
    snapshot: Option<Snapshot>,
    last_attempt: Option<Instant>,
    failed: bool,
}
pub struct Source {
    url: String,
    http: Arc<super::identity_http::IdentityHttp>,
    state: AsyncMutex<State>,
}
#[derive(Debug)]
pub enum KeyError {
    Invalid,
    Unavailable,
}
impl Source {
    pub async fn key(
        &self,
        kid: &str,
        algorithm: Algorithm,
        refresh: bool,
    ) -> Result<Key, KeyError> {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        let recent = state
            .last_attempt
            .is_some_and(|t| now.duration_since(t) < REFRESH_INTERVAL);
        if let Some(snapshot) = &state.snapshot {
            if snapshot.expires > now {
                let found = snapshot
                    .keys
                    .get(kid)
                    .filter(|key| key.algorithm == algorithm);
                if !refresh {
                    if let Some(key) = found {
                        return Ok(key.clone());
                    }
                }
                if recent {
                    return Err(KeyError::Invalid);
                }
            }
        }
        if state.failed && recent {
            return Err(KeyError::Unavailable);
        }
        state.last_attempt = Some(now);
        let fetched = self.fetch().await;
        let Ok(snapshot) = fetched else {
            // A failed early refresh must not evict still-valid cached keys.
            // The normal expiry check above prevents using them past their TTL.
            state.failed = true;
            return Err(KeyError::Unavailable);
        };
        let key = snapshot
            .keys
            .get(kid)
            .filter(|key| key.algorithm == algorithm)
            .cloned();
        state.snapshot = Some(snapshot);
        state.failed = false;
        key.ok_or(KeyError::Invalid)
    }
    async fn fetch(&self) -> Result<Snapshot> {
        let document = self.http.get(&self.url).await?;
        let mut ttl = 60;
        for value in document.headers.get_all("cache-control") {
            for directive in value.to_str().unwrap_or("").split(',').map(str::trim) {
                if directive.eq_ignore_ascii_case("no-store")
                    || directive.eq_ignore_ascii_case("no-cache")
                {
                    ttl = 0;
                }
                if let Some((key, value)) = directive.split_once('=') {
                    if key.eq_ignore_ascii_case("max-age") {
                        if let Ok(age) = value.trim_matches('"').parse::<u64>() {
                            ttl = ttl.min(age);
                        }
                    }
                }
            }
        }
        Ok(Snapshot {
            keys: parse_keys(&document.body)?,
            expires: Instant::now() + Duration::from_secs(ttl),
        })
    }
}
fn parse_keys(bytes: &[u8]) -> Result<HashMap<String, Key>> {
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    let list = value
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .context("missing JWKS keys")?;
    ensure!(list.len() <= 64, "too many JWKS keys");
    let mut keys = HashMap::new();
    for value in list {
        let text = |name| value.get(name).and_then(serde_json::Value::as_str);
        if text("use").is_some_and(|s| s != "sig") {
            continue;
        }
        if let Some(ops) = value.get("key_ops") {
            let ops = ops.as_array().context("invalid JWK operations")?;
            if !ops.iter().any(|s| s.as_str() == Some("verify")) {
                continue;
            }
        }
        let algorithm = match text("kty") {
            Some("RSA") if text("alg").is_none_or(|s| s == "RS256") => {
                let n = URL_SAFE_NO_PAD.decode(text("n").context("missing RSA modulus")?)?;
                let e = URL_SAFE_NO_PAD.decode(text("e").context("missing RSA exponent")?)?;
                ensure!(
                    (256..=1024).contains(&n.len()) && n[0] >= 128 && (1..=4).contains(&e.len()),
                    "invalid RSA size"
                );
                let exponent = e.iter().fold(0u64, |n, byte| n * 256 + u64::from(*byte));
                ensure!(exponent >= 3 && exponent % 2 == 1, "invalid RSA exponent");
                Algorithm::RS256
            }
            Some("EC")
                if text("alg").is_none_or(|s| s == "ES256") && text("crv") == Some("P-256") =>
            {
                for coordinate in ["x", "y"] {
                    ensure!(
                        URL_SAFE_NO_PAD
                            .decode(text(coordinate).context("missing EC coordinate")?)?
                            .len()
                            == 32,
                        "invalid EC coordinate"
                    );
                }
                Algorithm::ES256
            }
            _ => continue,
        };
        let kid = text("kid").context("missing signing key ID")?;
        ensure!(
            !kid.is_empty() && kid.len() <= 128 && !kid.chars().any(char::is_control),
            "invalid signing key ID"
        );
        let jwk: Jwk = serde_json::from_value(value.clone())?;
        let key = Key {
            algorithm,
            decoding: DecodingKey::from_jwk(&jwk)?,
        };
        ensure!(
            keys.insert(kid.to_owned(), key).is_none(),
            "ambiguous signing key ID"
        );
    }
    if keys.is_empty() {
        bail!("no supported verification keys");
    }
    Ok(keys)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_nonpublic_addresses_and_untrusted_sources() {
        for value in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "64:ff9b::a00:1",
            "2001:db8::1",
            "2002:7f00:1::",
        ] {
            assert!(!public_ip(value.parse().unwrap()), "{value}");
        }
        for value in ["1.1.1.1", "8.8.8.8", "2606:4700::1111"] {
            assert!(public_ip(value.parse().unwrap()));
        }
        let store = KeyStore::new(&[]).unwrap();
        for url in [
            "http://example.com/keys",
            "https://user:secret@example.com/keys",
            "https://example.com/keys#frag",
            "https://127.0.0.1/keys",
            "https://[::1]/keys",
            "https://localhost/keys",
        ] {
            assert!(store.source(url).is_err());
        }
        assert!(store.source("https://example.com/keys").is_ok());
    }
    #[test]
    fn rejects_ambiguous_and_weak_jwks() {
        let key = serde_json::json!({"kty":"RSA", "kid":"key", "n": URL_SAFE_NO_PAD.encode(vec![255;256]), "e":"AQAB", "alg":"RS256", "use":"sig"});
        assert_eq!(
            parse_keys(&serde_json::to_vec(&serde_json::json!({"keys":[key.clone()]})).unwrap())
                .unwrap()
                .len(),
            1
        );
        assert!(parse_keys(
            &serde_json::to_vec(&serde_json::json!({"keys":[key.clone(), key.clone()]})).unwrap()
        )
        .is_err());
        let mut weak = key;
        weak["n"] = URL_SAFE_NO_PAD.encode(vec![255; 128]).into();
        assert!(
            parse_keys(&serde_json::to_vec(&serde_json::json!({"keys":[weak]})).unwrap()).is_err()
        );
        assert!(parse_keys(br#"{"keys":[{"kty":"oct","kid":"key","k":"c2VjcmV0"}]}"#).is_err());
    }
    #[tokio::test]
    async fn failed_early_refresh_keeps_unexpired_keys_but_never_extends_their_lifetime() {
        let keys = parse_keys(&serde_json::to_vec(&serde_json::json!({ "keys": [{ "kty": "RSA", "kid": "known", "n": URL_SAFE_NO_PAD.encode(vec![255; 256]), "e": "AQAB" }] })).unwrap()).unwrap();
        let source = Source {
            // HTTPS-only client rejects this before DNS or network access.
            url: "http://example.com/keys".into(),
            http: super::super::identity_http::IdentityHttp::new(&[]).unwrap(),
            state: AsyncMutex::new(State {
                snapshot: Some(Snapshot {
                    keys,
                    expires: Instant::now() + Duration::from_secs(60),
                }),
                ..State::default()
            }),
        };
        assert!(matches!(
            source.key("unknown", Algorithm::RS256, false).await,
            Err(KeyError::Unavailable)
        ));
        assert!(source.key("known", Algorithm::RS256, false).await.is_ok());
        source.state.lock().await.snapshot.as_mut().unwrap().expires = Instant::now();
        assert!(matches!(
            source.key("known", Algorithm::RS256, false).await,
            Err(KeyError::Unavailable)
        ));
    }
}
