//! Connect shared issuance authority to independently validated local TLS material.
use super::{
    material::{now, Material},
    shared::{Lease, Shared},
    storage::Storage,
    Certificates, Entry, SavedCertificate,
};
use anyhow::{ensure, Context, Result};
use std::{sync::Arc, time::Duration};

impl Certificates {
    pub(super) async fn refresh_shared(&self, entry: Arc<Entry>, shared: &Arc<Shared>) {
        let result = self.shared_work(&entry, shared).await;
        let automatic = self.automatic.as_ref().expect("automatic store");
        let mut state = entry.state.write().await;
        state.busy = false;
        // Other relays' renewal and shared backoff are polled independently of
        // this relay's current valid certificate. Polling never grants authority.
        state.retry_at = now().saturating_add(5);
        match result {
            Ok(()) => {
                state.error = None;
                state.failures = 0;
            }
            Err(error) => {
                state.failures = state.failures.saturating_add(1);
                state.retry_at = now().saturating_add(automatic.config.retry_secs.min(30));
                state.error = Some("Shared certificate coordination unavailable; retry scheduled");
                let detail: String = error
                    .to_string()
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(256)
                    .collect();
                tracing::warn!(hostname=%entry.authority.hostname, error=%detail, "managed certificate request failed");
            }
        }
    }
    async fn shared_work(&self, entry: &Arc<Entry>, shared: &Arc<Shared>) -> Result<()> {
        let automatic = self.automatic.as_ref().expect("automatic store");
        let authority = &entry.authority;
        let filename = Storage::certificate_name(&authority.hostname);
        {
            let mut state = entry.state.write().await;
            if !state.loaded {
                state.loaded = true;
                if let Ok(Some(saved)) = automatic.storage.read::<SavedCertificate>(&filename) {
                    if let Ok(material) = self.shared_material(entry, &saved) {
                        state.material = Some(Arc::new(material));
                    }
                }
            }
        }
        let snapshot = shared.read(&authority.hostname).await?;
        ensure!(authority.active(), "hostname authorization ended");
        if snapshot.owner == authority.owner {
            if let Some(saved) = snapshot.certificate.as_ref() {
                if let Ok(material) = self.shared_material(entry, saved) {
                    let current = entry.state.read().await.material.clone();
                    if current
                        .as_ref()
                        .is_none_or(|old| !material.same_certificate(old))
                    {
                        self.save_local(entry, &filename, saved)?;
                        entry.state.write().await.material = Some(Arc::new(material));
                    }
                }
            }
            if snapshot.retry_at > now().saturating_mul(1000) {
                // Report a shared renewal warning even when the old certificate
                // can still serve. Never let another relay bypass CA backoff.
                anyhow::bail!("shared ACME retry backoff is active");
            }
        }
        if entry
            .state
            .read()
            .await
            .material
            .as_ref()
            .is_some_and(|material| now() < material.renew_at(automatic.config.renew_before_secs))
        {
            return Ok(());
        }
        let Some(lease) = shared
            .claim(&authority.hostname, &authority.owner, &snapshot.version)
            .await?
        else {
            return Ok(());
        };
        tracing::info!(hostname=%authority.hostname, "managed certificate issuance lease acquired");
        let result = tokio::select! {
            biased;
            () = authority.cancelled() => Err(anyhow::anyhow!("hostname authorization ended")),
            () = lease.cancelled() => Err(anyhow::anyhow!("shared ACME issuance lease ended")),
            result = tokio::time::timeout(Duration::from_secs(150), self.issue_shared(entry, &lease, &filename)) => result.context("ACME issuance timed out").and_then(|result| result),
        };
        let material = match result {
            Ok(material) => material,
            Err(error) => {
                if authority.active() {
                    let _ = lease.failure(automatic.config.retry_secs).await;
                }
                return Err(error);
            }
        };
        ensure!(authority.active(), "hostname authorization ended");
        entry.state.write().await.material = Some(Arc::new(material));
        tracing::info!(hostname=%authority.hostname, "managed certificate installed from shared issuance");
        Ok(())
    }
    async fn issue_shared(
        &self,
        entry: &Arc<Entry>,
        lease: &Lease,
        filename: &str,
    ) -> Result<Material> {
        let authority = &entry.authority;
        let (chain_pem, key_pem) = self
            .automatic
            .as_ref()
            .expect("automatic store")
            .issuer
            .issue(authority.clone(), &self.challenges, Some(lease))
            .await?;
        let saved = SavedCertificate {
            hostname: authority.hostname.clone(),
            owner: authority.owner.clone(),
            chain_pem,
            key_pem,
        };
        let material = self.shared_material(entry, &saved)?;
        lease.commit(&saved, material.expires).await?;
        self.save_local(entry, filename, &saved)?;
        Ok(material)
    }
    fn shared_material(&self, entry: &Entry, saved: &SavedCertificate) -> Result<Material> {
        ensure!(
            saved.hostname == entry.authority.hostname
                && saved.owner == entry.authority.owner
                && entry.authority.active(),
            "shared certificate identity or authority changed"
        );
        Material::parse(
            &saved.hostname,
            saved.chain_pem.as_bytes(),
            saved.key_pem.as_bytes(),
            Some(&self.automatic.as_ref().expect("automatic store").roots),
        )
    }
    fn save_local(
        &self,
        entry: &Arc<Entry>,
        filename: &str,
        saved: &SavedCertificate,
    ) -> Result<()> {
        let current = self
            .entries
            .get(&entry.authority.hostname)
            .context("certificate assignment removed")?;
        ensure!(
            Arc::ptr_eq(current.value(), entry) && entry.authority.active(),
            "certificate assignment changed"
        );
        self.automatic
            .as_ref()
            .expect("automatic store")
            .storage
            .write(filename, saved)
    }
}
