//! Endpoint authority outlives any one connector. Only sessions retain
//! strong ownership; router/certificate references cannot keep it alive forever.
use anyhow::{ensure, Result};
use pike_core::types::TunnelId;
use pike_server::{
    certificates::CertificateLease, domain_grants::DomainGrants, visitor_policy::VisitorGate,
};
use std::{
    collections::HashMap,
    sync::{Arc, Weak},
};
use tokio::sync::Mutex;

#[derive(Default)]
pub struct Endpoints(Mutex<HashMap<String, Weak<Endpoint>>>);

impl Endpoints {
    // The caller holds SessionContext's hostname lifecycle guard for admission
    // and teardown; this mutex only protects lookups on different hostnames.
    pub async fn get(&self, host: &str) -> Option<Arc<Endpoint>> {
        let mut entries = self.0.lock().await;
        entries.retain(|_, entry| entry.strong_count() > 0);
        entries.get(host).and_then(Weak::upgrade)
    }
    pub async fn insert(&self, host: String, endpoint: &Arc<Endpoint>) {
        self.0.lock().await.insert(host, Arc::downgrade(endpoint));
    }
}

pub struct Endpoint {
    pub owner: String,
    pub public_id: String,
    pub tunnel_id: TunnelId,
    pub kind: &'static str,
    pub settings: serde_json::Value,
    pub policy_revision: Option<u64>,
    pub visitor: Arc<VisitorGate>,
    pub domains: Option<Arc<DomainGrants>>,
    pub certificates: Vec<CertificateLease>,
    pub stream: Option<super::relay_streams::StreamEndpoint>,
    pub datagram: Option<super::relay_udp::Endpoint>,
}

impl Endpoint {
    pub fn validate(
        &self,
        owner: &str,
        public_id: &str,
        tunnel_id: TunnelId,
        kind: &str,
        settings: &serde_json::Value,
    ) -> Result<()> {
        ensure!(
            self.owner == owner
                && self.public_id == public_id
                && self.tunnel_id == tunnel_id
                && self.kind == kind
                && self.settings == *settings,
            "connector must match the saved endpoint owner, identity and configuration"
        );
        ensure!(self.visitor.is_active(), "endpoint authority is closing");
        Ok(())
    }

    pub fn validate_admission(&self, revision: u64, domains: &DomainGrants) -> Result<()> {
        ensure!(
            self.policy_revision == Some(revision),
            "endpoint policy changed; retry after old connectors disconnect"
        );
        let current = self
            .domains
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("endpoint domain authority missing"))?;
        ensure!(
            current.revision() == domains.revision()
                && current.hosts().count() == domains.hosts().count()
                && current.hosts().all(|(host, grant)| grant.is_active()
                    && domains.hosts().any(|(next, _)| next == host)),
            "endpoint domains changed; retry after old connectors disconnect"
        );
        Ok(())
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.visitor.close();
        if let Some(domains) = &self.domains {
            domains.close();
        }
        self.certificates.clear();
    }
}
