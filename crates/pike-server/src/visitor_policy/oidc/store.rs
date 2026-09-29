//! Opaque browser capabilities, with bounded local or fail-closed shared storage.
mod memory;
mod redis;
use crate::visitor_policy::Rejection;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::time::Instant;

pub fn random() -> Result<String, Rejection> {
    let mut bytes = [0; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| Rejection::Unavailable)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
pub fn digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(ring::digest::digest(&ring::digest::SHA256, value.as_bytes()).as_ref())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub redis_url: String,
    pub namespace: String,
}
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VisitorSessionStoreConfig")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub scope: String,
    pub browser_hash: String,
    pub verifier: String,
    pub nonce: String,
    pub return_to: String,
    pub provider_binding: String,
    #[serde(skip, default = "Instant::now")]
    pub expires: Instant,
}
#[derive(Debug)]
pub struct Session {
    pub scope: String,
    pub expires: Instant,
    closed: tokio::sync::watch::Sender<bool>,
}
impl Session {
    pub async fn cancelled(&self) {
        let _ = self.closed.subscribe().wait_for(|v| *v).await;
    }
    fn close(&self) {
        self.closed.send_replace(true);
    }
}
enum Backend {
    Local(memory::Store),
    Shared(Arc<redis::Store>),
}
pub struct Sessions {
    backend: Backend,
    authentication_slots: Arc<tokio::sync::Semaphore>,
}
impl std::fmt::Debug for Sessions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VisitorSessions")
            .field("shared", &matches!(self.backend, Backend::Shared(_)))
            .finish_non_exhaustive()
    }
}
impl Sessions {
    pub fn new() -> Arc<Self> {
        Self::with_backend(Backend::Local(memory::Store::new()))
    }
    pub fn configured(config: Option<&Config>) -> anyhow::Result<Arc<Self>> {
        Ok(match config {
            None => Self::new(),
            Some(config) => Self::with_backend(Backend::Shared(redis::Store::new(config)?)),
        })
    }
    fn with_backend(backend: Backend) -> Arc<Self> {
        Arc::new(Self {
            backend,
            authentication_slots: Arc::new(tokio::sync::Semaphore::new(32)),
        })
    }
    pub fn authentication_slot(&self) -> Result<tokio::sync::OwnedSemaphorePermit, Rejection> {
        self.authentication_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| Rejection::Unavailable)
    }
    pub async fn begin(&self, pending: Pending) -> Result<String, Rejection> {
        match &self.backend {
            Backend::Local(store) => store.begin(pending),
            Backend::Shared(store) => store.begin(pending).await,
        }
    }
    pub async fn consume(
        &self,
        token: &str,
        browser: &str,
        scope: &str,
    ) -> Result<Pending, Rejection> {
        match &self.backend {
            Backend::Local(store) => store.consume(token, browser, scope),
            Backend::Shared(store) => store.consume(token, browser, scope).await,
        }
    }
    pub async fn create(
        &self,
        scope: &str,
        expires: Instant,
    ) -> Result<(String, Arc<Session>), Rejection> {
        match &self.backend {
            Backend::Local(store) => store.create(scope, expires),
            Backend::Shared(store) => store.create(scope, expires).await,
        }
    }
    pub async fn get(&self, token: &str, scope: &str) -> Result<Option<Arc<Session>>, Rejection> {
        if token.len() != 43 {
            return Ok(None);
        }
        match &self.backend {
            Backend::Local(store) => Ok(store.get(token, scope)),
            Backend::Shared(store) => store.get(token, scope).await,
        }
    }
    pub async fn revoke(&self, token: &str, scope: &str) -> Result<(), Rejection> {
        match &self.backend {
            Backend::Local(store) => store.revoke(token, scope),
            Backend::Shared(store) => store.revoke(token, scope).await,
        }
    }
}
