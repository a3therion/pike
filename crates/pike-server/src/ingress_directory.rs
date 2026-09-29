//! Authenticated route advertisements follow actual connector lifetimes.
//! A snapshot is discovery data; forwarding must recheck current authority.
use crate::{
    domain_grants::{DomainGrant, DomainGrants},
    origin_health::{ConnectorHealth, OriginReadiness},
    visitor_policy::VisitorGate,
};
use anyhow::{ensure, Context, Result};
use pike_core::quic::server::PikeOutboundMessage;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex, Weak},
};
use tokio::sync::mpsc;
use uuid::Uuid;

pub const VERSION: u8 = 1;
pub const MAX_AGE_MS: u64 = 2_000;
pub const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_MEMBERS: usize = 16_384;
pub const MAX_ROUTES: usize = 4_096;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Http,
    Https,
    Tls,
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub protocol: Protocol,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Advertisement {
    pub target: Target,
    pub authority: String,
    pub members: u8,
    pub origin_health: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u8,
    pub nonce: String,
    pub max_age_ms: u64,
    pub routes: Vec<Advertisement>,
}

#[derive(Default)]
pub struct Directory(Mutex<HashMap<Uuid, Weak<Entry>>>);

impl std::fmt::Debug for Directory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Directory")
            .field("members", &self.0.lock().unwrap().len())
            .finish()
    }
}

pub struct Claim<'a> {
    pub owner: &'a str,
    pub profile: &'a str,
    pub hostname: &'a str,
    pub kind: &'a str,
    pub port: Option<u16>,
    pub settings: &'a serde_json::Value,
    pub https: bool,
    /// A TCP/UDP port is advertised only when its number is a coordinated public
    /// identity reserved by the cloud profile. A standalone relay has no global
    /// port authority, so its ports are relay-local and never forwarded by peers.
    pub public_port: bool,
}

impl Target {
    #[must_use]
    pub fn hostname(protocol: Protocol, hostname: &str) -> Self {
        Self {
            protocol,
            hostname: Some(hostname.to_owned()),
            port: None,
        }
    }
    #[must_use]
    pub fn port(protocol: Protocol, port: u16) -> Self {
        Self {
            protocol,
            hostname: None,
            port: Some(port),
        }
    }
    /// Exact shape: hostname protocols carry a lowercase name and no port; port
    /// protocols carry a pool port and no name.
    pub fn validate(&self) -> Result<()> {
        match self.protocol {
            Protocol::Http | Protocol::Https | Protocol::Tls => {
                let hostname = self.hostname.as_deref().context("hostname required")?;
                ensure!(
                    self.port.is_none()
                        && !hostname.is_empty()
                        && hostname.len() <= 253
                        && crate::router::normalize_host(hostname) == hostname,
                    "invalid ingress hostname target"
                );
            }
            Protocol::Tcp | Protocol::Udp => {
                ensure!(
                    self.hostname.is_none()
                        && self
                            .port
                            .is_some_and(|port| (10_000..=65_000).contains(&port)),
                    "invalid ingress port target"
                );
            }
        }
        Ok(())
    }
}

struct Route {
    target: Target,
    authority: String,
    domain: Option<Arc<DomainGrant>>,
}

struct Entry {
    hostname: String,
    routes: Vec<Route>,
    visitor: Arc<VisitorGate>,
    channel: mpsc::Sender<PikeOutboundMessage>,
    health: Option<Arc<ConnectorHealth>>,
}

fn identity(
    claim: &Claim<'_>,
    visitor: &VisitorGate,
    domains: Option<&DomainGrants>,
) -> Result<Vec<u8>> {
    let fingerprint = visitor
        .fingerprint()
        .context("visitor policy not initialized")?;
    Ok(serde_json::to_vec(&(
        claim.owner,
        claim.profile,
        claim.settings,
        fingerprint,
        domains.map(DomainGrants::revision),
    ))?)
}

fn digest(identity: &[u8], target: &Target) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(identity);
    digest.update(serde_json::to_vec(target)?);
    Ok(format!("{:x}", digest.finalize()))
}

/// Only the admitted session owns this registration. Snapshots hold no lease.
pub struct Registration {
    id: Uuid,
    directory: Weak<Directory>,
    _entry: Arc<Entry>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(directory) = self.directory.upgrade() {
            directory.0.lock().unwrap().remove(&self.id);
        }
    }
}

impl Directory {
    /// The digest a registration of `claim` would advertise for `target`.
    pub fn authority(
        claim: &Claim<'_>,
        visitor: &VisitorGate,
        domains: Option<&DomainGrants>,
        target: &Target,
    ) -> Result<String> {
        digest(&identity(claim, visitor, domains)?, target)
    }

    pub fn register(
        self: &Arc<Self>,
        claim: Claim<'_>,
        visitor: Arc<VisitorGate>,
        domains: Option<&DomainGrants>,
        channel: mpsc::Sender<PikeOutboundMessage>,
        health: Option<Arc<ConnectorHealth>>,
    ) -> Result<Registration> {
        ensure!(
            visitor.is_active() && !channel.is_closed(),
            "route is not active"
        );
        ensure!(
            !claim.owner.is_empty() && !claim.profile.is_empty(),
            "route identity missing"
        );
        ensure!(
            claim.hostname.len() <= 253 && !claim.hostname.is_empty(),
            "invalid route hostname"
        );
        let identity = identity(&claim, &visitor, domains)?;
        let protocols: &[Protocol] = match claim.kind {
            "http" if claim.https => &[Protocol::Http, Protocol::Https],
            "http" => &[Protocol::Http],
            "tls" => &[Protocol::Tls],
            "tcp" => &[Protocol::Tcp],
            "udp" => &[Protocol::Udp],
            _ => anyhow::bail!("unsupported ingress protocol"),
        };
        let uses_hostname = matches!(claim.kind, "http" | "tls");
        ensure!(
            uses_hostname
                || claim
                    .port
                    .is_some_and(|port| (10_000..=65_000).contains(&port)),
            "route port missing or invalid"
        );
        let mut names = vec![(claim.hostname, None)];
        if let Some(domains) = domains {
            ensure!(
                uses_hostname || domains.hosts().next().is_none(),
                "port route cannot have aliases"
            );
            names.extend(
                domains
                    .hosts()
                    .map(|(name, grant)| (name, Some(grant.clone()))),
            );
        }
        let mut routes = Vec::new();
        if uses_hostname || claim.public_port {
            for protocol in protocols {
                for (hostname, domain) in &names {
                    let target = Target {
                        protocol: *protocol,
                        hostname: uses_hostname.then(|| (*hostname).to_owned()),
                        port: (!uses_hostname).then_some(claim.port).flatten(),
                    };
                    routes.push(Route {
                        authority: digest(&identity, &target)?,
                        target,
                        domain: domain.clone(),
                    });
                }
            }
        }
        let entry = Arc::new(Entry {
            hostname: claim.hostname.to_owned(),
            routes,
            visitor,
            channel,
            health,
        });
        let id = Uuid::new_v4();
        let mut entries = self.0.lock().unwrap();
        entries.retain(|_, entry| entry.strong_count() != 0);
        ensure!(
            entries.len() < MAX_MEMBERS,
            "ingress directory capacity reached"
        );
        entries.insert(id, Arc::downgrade(&entry));
        Ok(Registration {
            id,
            directory: Arc::downgrade(self),
            _entry: entry,
        })
    }

    /// Current live authority for one exact target. Every active registration
    /// advertising the target must carry `expected` and share one visitor gate;
    /// absence, a conflicting digest or a second gate all fail closed. Returns
    /// the primary hostname of the owning endpoint and its gate so the caller
    /// can bind dispatch to that same live endpoint.
    pub fn verify(&self, target: &Target, expected: &str) -> Result<(String, Arc<VisitorGate>)> {
        target.validate()?;
        let mut found: Option<(String, Arc<VisitorGate>)> = None;
        let entries = self.0.lock().unwrap();
        for entry in entries.values().filter_map(Weak::upgrade) {
            if !entry.visitor.is_active() || entry.channel.is_closed() {
                continue;
            }
            for route in &entry.routes {
                if route.target != *target
                    || route
                        .domain
                        .as_ref()
                        .is_some_and(|grant| !grant.is_active())
                {
                    continue;
                }
                ensure!(
                    route.authority == expected,
                    "ingress route authority differs from the current registration"
                );
                match &found {
                    Some((_, gate)) => ensure!(
                        Arc::ptr_eq(gate, &entry.visitor),
                        "conflicting ingress route authority"
                    ),
                    None => found = Some((entry.hostname.clone(), entry.visitor.clone())),
                }
            }
        }
        found.context("ingress target is not registered on this relay")
    }

    pub fn snapshot(&self, nonce: &str) -> Result<Snapshot> {
        ensure!(
            nonce.len() == 32 && nonce.bytes().all(|c| c.is_ascii_hexdigit()),
            "nonce must be 32 hexadecimal characters"
        );
        let mut routes: BTreeMap<Target, (Advertisement, OriginReadiness)> = BTreeMap::new();
        let entries = self.0.lock().unwrap();
        for entry in entries.values().filter_map(Weak::upgrade) {
            if !entry.visitor.is_active() || entry.channel.is_closed() {
                continue;
            }
            let health = entry
                .health
                .as_ref()
                .map_or(OriginReadiness::Unknown, |h| h.readiness());
            for route in &entry.routes {
                if route
                    .domain
                    .as_ref()
                    .is_some_and(|grant| !grant.is_active())
                {
                    continue;
                }
                if let Some((current, readiness)) = routes.get_mut(&route.target) {
                    ensure!(
                        current.authority == route.authority,
                        "conflicting ingress route authority"
                    );
                    ensure!(
                        usize::from(current.members) < crate::registry::MAX_CONNECTORS_PER_TUNNEL,
                        "ingress route member limit reached"
                    );
                    current.members += 1;
                    *readiness = (*readiness).min(health);
                } else {
                    ensure!(
                        routes.len() < MAX_ROUTES,
                        "ingress snapshot capacity reached"
                    );
                    routes.insert(
                        route.target.clone(),
                        (
                            Advertisement {
                                target: route.target.clone(),
                                authority: route.authority.clone(),
                                members: 1,
                                origin_health: String::new(),
                            },
                            health,
                        ),
                    );
                }
            }
        }
        Ok(Snapshot {
            version: VERSION,
            nonce: nonce.to_owned(),
            max_age_ms: MAX_AGE_MS,
            routes: routes
                .into_values()
                .map(|(mut route, health)| {
                    route.origin_health = match health {
                        OriginReadiness::Healthy => "healthy",
                        OriginReadiness::Unknown => "unknown",
                        OriginReadiness::Unhealthy => "unhealthy",
                    }
                    .into();
                    route
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests;
