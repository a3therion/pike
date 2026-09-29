//! Exact-host certificate authority shared by native HTTPS and raw TLS.
//! Only a live, owner-bound route can publish a challenge or use managed keys.
mod coordination;
mod issuer;
mod material;
mod shared;
mod storage;
pub use shared::SharedConfig;
#[cfg(test)]
mod tests;
use crate::{config::PublicCertificate, domain_grants::DomainGrant, visitor_policy::VisitorGate};
use anyhow::{ensure, Context, Result};
use dashmap::DashMap;
use material::{now, Material};
use rustls::{
    pki_types::{pem::PemObject, CertificateDer},
    server::danger::ClientCertVerifier,
    RootCertStore,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Weak},
    time::Duration,
};
use tokio::sync::{watch, RwLock};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    pub directory_url: String,
    pub contact_email: String,
    pub terms_of_service_agreed: bool,
    pub storage_dir: PathBuf,
    pub shared: Option<SharedConfig>,
    pub directory_ca_path: Option<PathBuf>,
    pub certificate_ca_path: Option<PathBuf>,
    #[serde(default = "renew_default")]
    pub renew_before_secs: u64,
    #[serde(default = "retry_default")]
    pub retry_secs: u64,
}
fn renew_default() -> u64 {
    30 * 86400
}
fn retry_default() -> u64 {
    60
}
impl AcmeConfig {
    pub fn validate(&self) -> Result<reqwest::Url> {
        let url = reqwest::Url::parse(&self.directory_url)?;
        ensure!(
            url.scheme() == "https"
                && url.username().is_empty()
                && url.password().is_none()
                && url.fragment().is_none()
                && url.query().is_none(),
            "ACME directory requires HTTPS without credentials, query or fragment"
        );
        ensure!(
            self.terms_of_service_agreed,
            "ACME requires explicit terms_of_service_agreed"
        );
        ensure!(
            self.contact_email.len() <= 254
                && self.contact_email.contains('@')
                && !self
                    .contact_email
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
                && !self.contact_email.contains(['?', '#', '/']),
            "invalid ACME contact email"
        );
        ensure!(
            (5..=3600).contains(&self.retry_secs)
                && (5..=90 * 86400).contains(&self.renew_before_secs),
            "ACME retry/renewal settings are outside supported bounds"
        );
        Ok(url)
    }
}
struct Authority {
    hostname: String,
    owner: String,
    gate: Arc<VisitorGate>,
    domain: Option<Arc<DomainGrant>>,
    closed: watch::Sender<bool>,
}
impl Authority {
    fn active(&self) -> bool {
        !*self.closed.borrow()
            && self.gate.is_active()
            && self.domain.as_ref().is_none_or(|grant| grant.is_active())
    }
    async fn cancelled(&self) {
        let mut closed = self.closed.subscribe();
        let domain = async {
            match &self.domain {
                Some(grant) => grant.cancelled().await,
                None => std::future::pending().await,
            }
        };
        tokio::select! { _ = closed.wait_for(|closed| *closed) => {}, () = self.gate.cancelled() => {}, () = domain => {} }
    }
}
struct Challenge {
    authority: Arc<Authority>,
    token: String,
    value: String,
}
#[derive(Default, Clone)]
struct Challenges(Arc<DashMap<(String, String), Arc<Challenge>>>);
struct ChallengeGuard {
    registry: Challenges,
    value: Arc<Challenge>,
}
impl Challenges {
    fn publish(&self, challenge: Challenge) -> Result<ChallengeGuard> {
        ensure!(challenge.authority.active(), "hostname authorization ended");
        let value = Arc::new(challenge);
        let key = (value.authority.hostname.clone(), value.token.clone());
        match self.0.entry(key) {
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                slot.insert(value.clone());
            }
            dashmap::mapref::entry::Entry::Occupied(_) => {
                anyhow::bail!("ACME challenge already published")
            }
        }
        Ok(ChallengeGuard {
            registry: self.clone(),
            value,
        })
    }
}
impl Drop for ChallengeGuard {
    fn drop(&mut self) {
        self.registry.0.remove_if(
            &(
                self.value.authority.hostname.clone(),
                self.value.token.clone(),
            ),
            |_, current| Arc::ptr_eq(current, &self.value),
        );
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedCertificate {
    hostname: String,
    owner: String,
    chain_pem: String,
    key_pem: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct CertificateStatus {
    pub hostname: String,
    pub state: &'static str,
    pub expires_at: Option<u64>,
    pub last_error: Option<&'static str>,
}
struct ManagedState {
    material: Option<Arc<Material>>,
    busy: bool,
    retry_at: u64,
    failures: u32,
    error: Option<&'static str>,
    loaded: bool,
}
struct Entry {
    authority: Arc<Authority>,
    state: RwLock<ManagedState>,
}
struct Automatic {
    config: AcmeConfig,
    storage: Arc<storage::Storage>,
    issuer: issuer::Issuer,
    roots: Arc<RootCertStore>,
    shared: Option<Arc<shared::Shared>>,
}
pub struct Certificates {
    manual: HashMap<String, PublicCertificate>,
    entries: DashMap<String, Arc<Entry>>,
    automatic: Option<Automatic>,
    challenges: Challenges,
}
pub struct CertificateLease {
    store: Weak<Certificates>,
    entry: Arc<Entry>,
}
impl Drop for CertificateLease {
    fn drop(&mut self) {
        self.entry.authority.closed.send_replace(true);
        if let Some(store) = self.store.upgrade() {
            store
                .entries
                .remove_if(&self.entry.authority.hostname, |_, current| {
                    Arc::ptr_eq(current, &self.entry)
                });
        }
    }
}
impl Certificates {
    pub fn disabled() -> Arc<Self> {
        Arc::new(Self {
            manual: HashMap::new(),
            entries: DashMap::new(),
            automatic: None,
            challenges: Challenges::default(),
        })
    }
    pub async fn new(
        manual: impl IntoIterator<Item = PublicCertificate>,
        config: Option<AcmeConfig>,
        shutdown: watch::Receiver<bool>,
    ) -> Result<Arc<Self>> {
        let mut certificates: HashMap<String, PublicCertificate> = HashMap::new();
        for certificate in manual {
            ensure!(
                crate::router::normalize_host(&certificate.hostname) == certificate.hostname
                    && !certificate.hostname.contains('*')
                    && !certificate.owner_user_id.trim().is_empty(),
                "certificates require an exact lowercase hostname and owner"
            );
            ensure!(certificates.len() < 512, "too many manual certificates");
            Self::manual_material(&certificate).await?;
            if let Some(previous) = certificates.get(&certificate.hostname) {
                ensure!(
                    previous.owner_user_id == certificate.owner_user_id
                        && previous.cert_path == certificate.cert_path
                        && previous.key_path == certificate.key_path,
                    "conflicting HTTPS and TLS certificates for one hostname"
                );
            } else {
                certificates.insert(certificate.hostname.clone(), certificate);
            }
        }
        let automatic = if let Some(config) = config {
            config.validate()?;
            let storage = Arc::new(storage::Storage::open(&config.storage_dir)?);
            let mut roots = RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            if let Some(path) = &config.certificate_ca_path {
                let bytes = tokio::fs::read(path).await?;
                ensure!(bytes.len() <= 65536, "ACME certificate trust exceeds limit");
                let mut count = 0;
                for certificate in CertificateDer::pem_slice_iter(&bytes) {
                    count += 1;
                    roots.add(certificate?)?;
                }
                ensure!(
                    count > 0 && count <= 16,
                    "ACME certificate CA bundle must contain 1 to 16 certificates"
                );
            }
            let shared = config
                .shared
                .as_ref()
                .map(|value| shared::Shared::new(value, &config.directory_url))
                .transpose()?;
            let issuer =
                issuer::Issuer::new(config.clone(), storage.clone(), shared.clone()).await?;
            Some(Automatic {
                config,
                storage,
                issuer,
                roots: Arc::new(roots),
                shared,
            })
        } else {
            None
        };
        let store = Arc::new(Self {
            manual: certificates,
            entries: DashMap::new(),
            automatic,
            challenges: Challenges::default(),
        });
        if store.automatic.is_some() {
            tokio::spawn(Self::run(Arc::downgrade(&store), shutdown));
        }
        Ok(store)
    }
    /// Called before route publication; manual ownership cannot be overridden by ACME.
    pub fn check_owner(
        &self,
        hostname: &str,
        owner: &str,
        require_certificate: bool,
    ) -> Result<()> {
        if let Some(certificate) = self.manual.get(hostname) {
            ensure!(
                certificate.owner_user_id == owner,
                "TLS certificate belongs to another account"
            );
        }
        if require_certificate {
            ensure!(
                self.manual.contains_key(hostname) || self.automatic.is_some(),
                "relay has no certificate configured for this TLS hostname"
            );
        }
        Ok(())
    }
    pub fn authorize(
        self: &Arc<Self>,
        hostname: &str,
        owner: &str,
        gate: Arc<VisitorGate>,
        domain: Option<Arc<DomainGrant>>,
    ) -> Result<CertificateLease> {
        ensure!(
            self.entries.len() < 16384,
            "certificate assignment limit reached"
        );
        let entry = Arc::new(Entry {
            authority: Arc::new(Authority {
                hostname: hostname.to_owned(),
                owner: owner.to_owned(),
                gate,
                domain,
                closed: watch::channel(false).0,
            }),
            state: RwLock::new(ManagedState {
                material: None,
                busy: false,
                retry_at: 0,
                failures: 0,
                error: None,
                loaded: false,
            }),
        });
        match self.entries.entry(hostname.to_owned()) {
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                slot.insert(entry.clone());
            }
            dashmap::mapref::entry::Entry::Occupied(_) => {
                anyhow::bail!("certificate hostname already assigned")
            }
        }
        Ok(CertificateLease {
            store: Arc::downgrade(self),
            entry,
        })
    }
    /// `challenge` restricted to the certificate entry bound to `gate`. The
    /// ingress owner answers a forwarded HTTP-01 lookup only for the endpoint
    /// whose route authority it verified for the same hop.
    pub async fn bound_challenge(
        &self,
        hostname: &str,
        token: &str,
        gate: &Arc<VisitorGate>,
    ) -> Option<String> {
        let entry = self.entries.get(hostname).map(|entry| entry.clone())?;
        if !entry.authority.active() || !Arc::ptr_eq(&entry.authority.gate, gate) {
            return None;
        }
        let proof = self.challenge(hostname, token).await?;
        // The shared lookup awaited; a replaced or closed lease cannot answer.
        entry.authority.active().then_some(proof)
    }
    pub async fn challenge(&self, hostname: &str, token: &str) -> Option<String> {
        if let Some(shared) = self
            .automatic
            .as_ref()
            .and_then(|automatic| automatic.shared.as_ref())
        {
            let authority = self.entries.get(hostname)?.authority.clone();
            if !authority.active() {
                return None;
            }
            let proof = shared
                .proof(hostname, &authority.owner, token)
                .await
                .ok()
                .flatten();
            return authority.active().then_some(proof).flatten();
        }
        self.challenges
            .0
            .get(&(hostname.to_owned(), token.to_owned()))
            .filter(|challenge| challenge.authority.active())
            .map(|challenge| challenge.value.clone())
    }
    async fn manual_material(certificate: &PublicCertificate) -> Result<Material> {
        let (chain, key) = tokio::try_join!(
            tokio::fs::read(&certificate.cert_path),
            tokio::fs::read(&certificate.key_path)
        )?;
        Material::parse(&certificate.hostname, &chain, &key, None)
    }
    pub async fn server_config(
        &self,
        hostname: &str,
        owner: &str,
        gate: &Arc<VisitorGate>,
        verifier: Option<Arc<dyn ClientCertVerifier>>,
        http: bool,
    ) -> Result<Arc<rustls::ServerConfig>> {
        self.check_owner(hostname, owner, true)?;
        let entry = self
            .entries
            .get(hostname)
            .map(|entry| entry.clone())
            .context("certificate hostname is not authorized")?;
        ensure!(
            entry.authority.owner == owner
                && Arc::ptr_eq(&entry.authority.gate, gate)
                && entry.authority.active(),
            "certificate authorization changed"
        );
        if let Some(certificate) = self.manual.get(hostname) {
            return Self::manual_material(certificate)
                .await?
                .server_config(verifier, http);
        }
        let material = entry
            .state
            .read()
            .await
            .material
            .clone()
            .context("managed certificate is not ready")?;
        material.server_config(verifier, http)
    }
    pub async fn status(&self, hostname: &str) -> Option<CertificateStatus> {
        let entry = self.entries.get(hostname).map(|entry| entry.clone())?;
        if !entry.authority.active() {
            return None;
        }
        if let Some(certificate) = self.manual.get(hostname) {
            if certificate.owner_user_id != entry.authority.owner {
                return Some(CertificateStatus {
                    hostname: hostname.into(),
                    state: "error",
                    expires_at: None,
                    last_error: Some("Operator certificate belongs to another account"),
                });
            }
            return Some(match Self::manual_material(certificate).await {
                Ok(material) => CertificateStatus {
                    hostname: hostname.into(),
                    state: "manual",
                    expires_at: Some(material.expires * 1000),
                    last_error: None,
                },
                Err(_) => CertificateStatus {
                    hostname: hostname.into(),
                    state: "error",
                    expires_at: None,
                    last_error: Some("Operator certificate is unavailable or invalid"),
                },
            });
        }
        let state = entry.state.read().await;
        let ready = state
            .material
            .as_ref()
            .is_some_and(|material| now() < material.expires);
        Some(CertificateStatus {
            hostname: hostname.into(),
            state: if ready {
                "ready"
            } else if state.error.is_some() {
                "error"
            } else if self.automatic.is_some() {
                "pending"
            } else {
                "unconfigured"
            },
            expires_at: state
                .material
                .as_ref()
                .map(|material| material.expires * 1000),
            last_error: state.error,
        })
    }
    async fn run(store: Weak<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut jobs = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = jobs.join_next(), if !jobs.is_empty() => {},
                _ = interval.tick() => {
                    let Some(store) = store.upgrade() else { break; };
                    let entries: Vec<_> = store.entries.iter().map(|entry| entry.value().clone()).collect();
                    for entry in entries {
                        if jobs.len() >= 4 { break; }
                        if !entry.authority.active() || store.manual.contains_key(&entry.authority.hostname) { continue; }
                        let mut state = entry.state.write().await;
                        if state.busy || state.retry_at > now() { continue; }
                        if store.automatic.as_ref().expect("automatic store").shared.is_none() && state.material.as_ref().is_some_and(|material| now() < material.renew_at(store.automatic.as_ref().expect("automatic store").config.renew_before_secs)) { continue; }
                        state.busy = true; drop(state);
                        let store = store.clone(); jobs.spawn(async move { store.refresh(entry).await; });
                    }
                }
            }
        }
        jobs.shutdown().await;
    }
    async fn refresh(&self, entry: Arc<Entry>) {
        if let Some(shared) = self
            .automatic
            .as_ref()
            .and_then(|automatic| automatic.shared.as_ref())
        {
            self.refresh_shared(entry, shared).await;
        } else {
            self.refresh_local(entry).await;
        }
    }
    async fn refresh_local(&self, entry: Arc<Entry>) {
        let automatic = self.automatic.as_ref().expect("automatic store");
        let host = &entry.authority.hostname;
        let filename = storage::Storage::certificate_name(host);
        {
            let mut state = entry.state.write().await;
            if !state.loaded {
                state.loaded = true;
                if let Ok(Some(saved)) = automatic.storage.read::<SavedCertificate>(&filename) {
                    if saved.hostname == *host && saved.owner == entry.authority.owner {
                        if let Ok(material) = Material::parse(
                            host,
                            saved.chain_pem.as_bytes(),
                            saved.key_pem.as_bytes(),
                            Some(&automatic.roots),
                        ) {
                            state.material = Some(Arc::new(material));
                        }
                    }
                }
                if state.material.as_ref().is_some_and(|material| {
                    now() < material.renew_at(automatic.config.renew_before_secs)
                }) {
                    state.busy = false;
                    return;
                }
            }
        }
        let result = tokio::select! {
            biased;
            () = entry.authority.cancelled() => Err(anyhow::anyhow!("hostname authorization ended")),
            result = tokio::time::timeout(Duration::from_secs(150), automatic.issuer.issue(entry.authority.clone(), &self.challenges, None)) => result.context("ACME issuance timed out").and_then(|result| result),
        };
        let result = result.and_then(|(chain_pem, key_pem)| {
            ensure!(entry.authority.active(), "hostname authorization ended");
            let material = Material::parse(
                host,
                chain_pem.as_bytes(),
                key_pem.as_bytes(),
                Some(&automatic.roots),
            )?;
            // Hold the assignment through atomic persistence. A replacement owner
            // cannot install its state and then be overwritten by this old job.
            let current = self
                .entries
                .get(host)
                .context("certificate assignment removed")?;
            ensure!(
                Arc::ptr_eq(current.value(), &entry) && entry.authority.active(),
                "certificate assignment changed"
            );
            automatic.storage.write(
                &filename,
                &SavedCertificate {
                    hostname: host.clone(),
                    owner: entry.authority.owner.clone(),
                    chain_pem,
                    key_pem,
                },
            )?;
            Ok(material)
        });
        let mut state = entry.state.write().await;
        state.busy = false;
        match result {
            Ok(material) => {
                state.material = Some(Arc::new(material));
                state.failures = 0;
                state.retry_at = 0;
                state.error = None;
                tracing::info!(hostname=%host, "managed certificate installed");
            }
            Err(error) => {
                state.failures = state.failures.saturating_add(1);
                state.retry_at = now().saturating_add(
                    automatic
                        .config
                        .retry_secs
                        .saturating_mul(1_u64 << state.failures.min(6))
                        .min(3600),
                );
                state.error = Some("Certificate issuance or renewal failed; retry scheduled");
                let detail: String = error
                    .to_string()
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(256)
                    .collect();
                tracing::warn!(hostname=%host, error=%detail, "managed certificate request failed");
            }
        }
    }
}
