//! OIDC authorization-code sign-in for one protected tunnel policy.
mod provider;
pub(super) mod store;
#[cfg(test)]
mod tests;
use super::{
    identity_http::validate_url, jwks::KeyStore, jwt::SigningAlgorithm, Rejection,
    VisitorAdmission, VisitorGate, VisitorPeer,
};
use anyhow::{ensure, Result};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Method, Request, Response},
};
use provider::Provider;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc, time::Duration};
pub use store::{Config as SessionStoreConfig, Sessions};
use tokio::time::Instant;

const SESSION: &str = "__Host-Pike-Visitor";
const BROWSER: &str = "__Host-Pike-OIDC";
const LOGIN: &str = "/.pike/auth/login";
const CALLBACK: &str = "/.pike/auth/callback";
const LOGOUT: &str = "/.pike/auth/logout";
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OidcPolicy {
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub algorithm: SigningAlgorithm,
    pub token_endpoint_auth_method: TokenAuth,
    pub client_secret: Option<String>,
    pub session_ttl_secs: u64,
    pub allowed_subjects: Option<Vec<String>>,
    pub allowed_emails: Option<Vec<String>>,
}
#[derive(Clone, Copy, Deserialize, Serialize)]
pub enum TokenAuth {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "client_secret_basic")]
    SecretBasic,
    #[serde(rename = "client_secret_post")]
    SecretPost,
}
impl TokenAuth {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::SecretBasic => "client_secret_basic",
            Self::SecretPost => "client_secret_post",
        }
    }
}
struct CachedProvider {
    provider: Arc<Provider>,
    expires: Instant,
}
struct DiscoveryState {
    cached: Option<CachedProvider>,
    retry_at: Instant,
}
pub struct Oidc {
    policy: OidcPolicy,
    origin: String,
    scope: String,
    keys: Arc<KeyStore>,
    sessions: Arc<Sessions>,
    discovery: tokio::sync::Mutex<DiscoveryState>,
}
fn bounded(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.bytes().any(|b| b <= 32 || b == 127)
}
impl Oidc {
    pub fn new(
        policy: OidcPolicy,
        scope: String,
        keys: Arc<KeyStore>,
        sessions: Arc<Sessions>,
    ) -> Result<Self> {
        let issuer = validate_url(&policy.issuer)?;
        let redirect = validate_url(&policy.redirect_uri)?;
        ensure!(
            issuer.query().is_none() && redirect.query().is_none() && redirect.path() == CALLBACK,
            "invalid OIDC issuer or callback"
        );
        ensure!(
            bounded(&policy.client_id, 512) && (60..=86400).contains(&policy.session_ttl_secs),
            "invalid OIDC client or lifetime"
        );
        match policy.token_endpoint_auth_method {
            TokenAuth::None => ensure!(
                policy.client_secret.is_none(),
                "public OIDC client cannot have a secret"
            ),
            TokenAuth::SecretBasic | TokenAuth::SecretPost => ensure!(
                policy.client_secret.as_ref().is_some_and(|s| !s.is_empty()
                    && s.len() <= 4096
                    && !s.chars().any(char::is_control)),
                "OIDC client secret required"
            ),
        }
        for (values, size) in [
            (&policy.allowed_subjects, 512),
            (&policy.allowed_emails, 254),
        ] {
            ensure!(
                values
                    .as_ref()
                    .is_none_or(|v| v.len() <= 64 && v.iter().all(|value| bounded(value, size))),
                "invalid OIDC allowlist"
            );
        }
        ensure!(
            policy
                .allowed_emails
                .as_ref()
                .is_none_or(|v| v.iter().all(|email| email.matches('@').count() == 1)),
            "invalid OIDC email"
        );
        Ok(Self {
            origin: redirect.origin().ascii_serialization(),
            policy,
            scope,
            keys,
            sessions,
            discovery: tokio::sync::Mutex::new(DiscoveryState {
                cached: None,
                retry_at: Instant::now(),
            }),
        })
    }
    async fn provider(&self) -> Result<Arc<Provider>, Rejection> {
        let mut state = self.discovery.lock().await;
        if let Some(cached) = &state.cached {
            if cached.expires > Instant::now() {
                return Ok(cached.provider.clone());
            }
        }
        if Instant::now() < state.retry_at {
            return Err(Rejection::Unavailable);
        }
        state.retry_at = Instant::now() + Duration::from_secs(5);
        let provider = Provider::discover(&self.policy, self.keys.clone())
            .await
            .map_err(|_| Rejection::Unavailable)?;
        state.cached = Some(CachedProvider {
            provider: provider.clone(),
            expires: Instant::now() + Duration::from_secs(300),
        });
        Ok(provider)
    }
    pub async fn handle(
        &self,
        gate: &Arc<VisitorGate>,
        peer: VisitorPeer,
        req: &mut Request<Body>,
    ) -> Result<super::VisitorDecision, Rejection> {
        // Secure cookies never use the fixture-only plaintext authorization opt-in.
        if !peer.secure {
            return Err(Rejection::Insecure);
        }
        let host = super::one_header(req.headers(), "host").ok_or(Rejection::InvalidSignIn)?;
        let current = reqwest::Url::parse(&format!("https://{host}"))
            .map_err(|_| Rejection::InvalidSignIn)?;
        if current.origin().ascii_serialization() != self.origin {
            return Err(Rejection::InvalidSignIn);
        }
        let cookies = Cookies::parse(req.headers())?;
        let path = req.uri().path();
        if path == CALLBACK {
            if req.method() != Method::GET {
                return Ok(super::VisitorDecision::Response(page(
                    405,
                    "Sign-in callback requires GET",
                )));
            }
            return self
                .callback(req.uri().query(), &cookies)
                .await
                .map(super::VisitorDecision::Response);
        }
        if path == LOGIN {
            if req.method() != Method::GET {
                return Ok(super::VisitorDecision::Response(page(
                    405,
                    "Sign-in requires GET",
                )));
            }
            let params = parameters(req.uri().query())?;
            let target = params.get("return_to").map_or("/", String::as_str);
            return self
                .login(target, &cookies)
                .await
                .map(super::VisitorDecision::Response);
        }
        if path == LOGOUT {
            return self
                .logout(
                    req.method(),
                    super::one_header(req.headers(), "origin"),
                    &cookies,
                )
                .await
                .map(super::VisitorDecision::Response);
        }
        if path.starts_with("/.pike/auth/") {
            return Ok(super::VisitorDecision::Response(page(
                404,
                "Unknown sign-in endpoint",
            )));
        }
        let session = match cookies.session.as_ref() {
            Some(token) => self.sessions.get(token, &self.scope).await?,
            None => None,
        };
        if let Some(session) = session {
            if !self.same_origin_request(req) {
                return Err(Rejection::CrossOrigin);
            }
            cookies.strip(req.headers_mut())?;
            return Ok(super::VisitorDecision::Admit(VisitorAdmission {
                gate: gate.clone(),
                expires: Some(session.expires),
                session: Some(session),
                domain: None,
            }));
        }
        let html = req.method() == Method::GET
            && super::one_header(req.headers(), "accept").is_some_and(|v| {
                v.split(',')
                    .any(|part| part.trim().starts_with("text/html"))
            });
        let response = if html {
            self.login(
                req.uri()
                    .path_and_query()
                    .map_or("/", axum::http::uri::PathAndQuery::as_str),
                &cookies,
            )
            .await?
        } else {
            page(401, "Sign in to access this tunnel")
        };
        Ok(super::VisitorDecision::Response(response))
    }
    fn same_origin_request(&self, req: &Request<Body>) -> bool {
        let origin = super::one_header(req.headers(), "origin");
        if req.headers().contains_key("origin") && origin.is_none() {
            return false;
        }
        let upgraded = super::one_header(req.headers(), "upgrade")
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));
        if origin.is_some_and(|value| value != self.origin) {
            return false;
        }
        if (upgraded || !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS))
            && origin != Some(self.origin.as_str())
        {
            return false;
        }
        let foreign = super::one_header(req.headers(), "sec-fetch-site")
            .is_some_and(|v| matches!(v, "cross-site" | "same-site"));
        !foreign
            || (super::one_header(req.headers(), "sec-fetch-mode") == Some("navigate")
                && matches!(*req.method(), Method::GET | Method::HEAD))
    }
    async fn login(&self, target: &str, cookies: &Cookies) -> Result<Response<Body>, Rejection> {
        let _slot = self.sessions.authentication_slot()?;
        let return_to = return_target(&self.origin, target)?;
        let provider = self.provider().await?;
        let browser = cookies.browser.clone().unwrap_or(store::random()?);
        let verifier = store::random()?;
        let nonce = store::random()?;
        let state = self
            .sessions
            .begin(store::Pending {
                scope: self.scope.clone(),
                browser_hash: store::digest(&browser),
                verifier: verifier.clone(),
                nonce: nonce.clone(),
                return_to,
                provider_binding: provider.binding.clone(),
                expires: Instant::now() + Duration::from_secs(300),
            })
            .await?;
        let mut url = provider.authorization_url.clone();
        url.query_pairs_mut().extend_pairs([
            ("response_type", "code"),
            ("client_id", &self.policy.client_id),
            ("redirect_uri", &self.policy.redirect_uri),
            ("scope", "openid email"),
            ("response_mode", "query"),
            ("state", &state),
            ("nonce", &nonce),
            ("code_challenge", &store::digest(&verifier)),
            ("code_challenge_method", "S256"),
        ]);
        let mut response = redirect(url.as_str())?;
        set_cookie(&mut response, BROWSER, &browser, 300)?;
        Ok(response)
    }
    async fn callback(
        &self,
        query: Option<&str>,
        cookies: &Cookies,
    ) -> Result<Response<Body>, Rejection> {
        let _slot = self.sessions.authentication_slot()?;
        let params = parameters(query)?;
        let state = params
            .get("state")
            .filter(|s| token(s))
            .ok_or(Rejection::InvalidSignIn)?;
        let browser = cookies.browser.as_deref().ok_or(Rejection::InvalidSignIn)?;
        let flow = self.sessions.consume(state, browser, &self.scope).await?;
        if params.contains_key("error")
            || params.get("iss").is_some_and(|v| v != &self.policy.issuer)
        {
            return Err(Rejection::InvalidSignIn);
        }
        let code = params
            .get("code")
            .filter(|s| bounded(s, 4096))
            .ok_or(Rejection::InvalidSignIn)?;
        let provider = self.provider().await?;
        if provider.binding != flow.provider_binding {
            return Err(Rejection::InvalidSignIn);
        }
        let token_expires = provider
            .exchange(&self.policy, code, &flow.verifier, &flow.nonce)
            .await?;
        let expires =
            token_expires.min(Instant::now() + Duration::from_secs(self.policy.session_ttl_secs));
        let seconds = expires.saturating_duration_since(Instant::now()).as_secs();
        if seconds == 0 {
            return Err(Rejection::InvalidSignIn);
        }
        let (session, _) = self.sessions.create(&self.scope, expires).await?;
        if let Some(previous) = &cookies.session {
            self.sessions.revoke(previous, &self.scope).await?;
        }
        let mut response = redirect(&flow.return_to)?;
        set_cookie(&mut response, SESSION, &session, seconds)?;
        Ok(response)
    }
    async fn logout(
        &self,
        method: &Method,
        origin: Option<&str>,
        cookies: &Cookies,
    ) -> Result<Response<Body>, Rejection> {
        if method == Method::GET {
            return Ok(page(200, "Sign out of this tunnel"));
        }
        if method != Method::POST {
            return Ok(page(405, "Sign-out requires POST"));
        }
        if origin != Some(self.origin.as_str()) {
            return Err(Rejection::CrossOrigin);
        }
        if let Some(token) = &cookies.session {
            self.sessions.revoke(token, &self.scope).await?;
        }
        let mut response = page(200, "You are signed out of this tunnel");
        set_cookie(&mut response, SESSION, "", 0)?;
        set_cookie(&mut response, BROWSER, "", 0)?;
        Ok(response)
    }
}
fn token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}
struct Cookies {
    session: Option<String>,
    browser: Option<String>,
    remaining: Vec<String>,
}
impl Cookies {
    fn parse(headers: &HeaderMap) -> Result<Self, Rejection> {
        let mut result = Self {
            session: None,
            browser: None,
            remaining: vec![],
        };
        let mut size = 0;
        for header in headers.get_all("cookie") {
            let value = header.to_str().map_err(|_| Rejection::InvalidSignIn)?;
            size += value.len();
            if size > 16384 {
                return Err(Rejection::InvalidSignIn);
            }
            for crumb in value.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                let (name, value) = crumb.split_once('=').ok_or(Rejection::InvalidSignIn)?;
                let slot = match name.trim() {
                    SESSION => &mut result.session,
                    BROWSER => &mut result.browser,
                    _ => {
                        result.remaining.push(crumb.to_owned());
                        continue;
                    }
                };
                if slot.is_some() || !token(value) {
                    return Err(Rejection::InvalidSignIn);
                }
                *slot = Some(value.to_owned());
            }
        }
        Ok(result)
    }
    fn strip(&self, headers: &mut HeaderMap) -> Result<(), Rejection> {
        headers.remove("cookie");
        if !self.remaining.is_empty() {
            headers.insert(
                "cookie",
                HeaderValue::from_str(&self.remaining.join("; "))
                    .map_err(|_| Rejection::InvalidSignIn)?,
            );
        }
        Ok(())
    }
}
fn parameters(query: Option<&str>) -> Result<HashMap<String, String>, Rejection> {
    let query = query.unwrap_or("");
    if query.len() > 8192 {
        return Err(Rejection::InvalidSignIn);
    }
    let url = reqwest::Url::parse(&format!("https://unused.invalid/?{query}"))
        .map_err(|_| Rejection::InvalidSignIn)?;
    let mut params = HashMap::new();
    for (key, value) in url.query_pairs() {
        if params.len() >= 16
            || value.len() > 4096
            || params
                .insert(key.into_owned(), value.into_owned())
                .is_some()
        {
            return Err(Rejection::InvalidSignIn);
        }
    }
    Ok(params)
}
fn return_target(origin: &str, value: &str) -> Result<String, Rejection> {
    if value.len() > 2048
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.bytes().any(|b| b <= 32 || b == 127)
        || value.starts_with("/.pike/auth/")
    {
        return Err(Rejection::InvalidSignIn);
    }
    let url =
        reqwest::Url::parse(&format!("{origin}{value}")).map_err(|_| Rejection::InvalidSignIn)?;
    if url.origin().ascii_serialization() != origin || url.path().starts_with("/.pike/auth/") {
        return Err(Rejection::InvalidSignIn);
    }
    Ok(url.to_string())
}
fn page(status: u16, message: &str) -> Response<Body> {
    // Messages are fixed server strings; provider errors and user inputs are never interpolated.
    Response::builder().status(status).header("cache-control", "no-store").header("referrer-policy", "no-referrer")
        .header("content-type", "text/html; charset=utf-8").header("x-content-type-options", "nosniff")
        .header("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        .body(Body::from(format!("<!doctype html><meta charset=utf-8><meta name=viewport content=\"width=device-width,initial-scale=1\"><title>Pike visitor access</title><style>body{{font:18px system-ui;max-width:36rem;margin:12vh auto;padding:2rem;background:#f6f5ef;color:#1c322b}}a{{color:#285f42}}button{{font:inherit;padding:.6rem 1rem}}</style><h1>{message}</h1><p><a href=\"{LOGIN}\">Sign in</a></p><form method=post action=\"{LOGOUT}\"><button>Sign out</button></form>"))).unwrap()
}
fn redirect(location: &str) -> Result<Response<Body>, Rejection> {
    let mut response = page(303, "Continue signing in");
    response.headers_mut().insert(
        "location",
        HeaderValue::from_str(location).map_err(|_| Rejection::InvalidSignIn)?,
    );
    Ok(response)
}
fn set_cookie(
    response: &mut Response<Body>,
    name: &str,
    value: &str,
    seconds: u64,
) -> Result<(), Rejection> {
    response.headers_mut().append(
        "set-cookie",
        HeaderValue::from_str(&format!(
            "{name}={value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={seconds}"
        ))
        .map_err(|_| Rejection::Unavailable)?,
    );
    Ok(())
}
