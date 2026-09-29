//! Bounded observations; origin identity is its position in the saved configuration.
use std::{collections::HashMap, sync::Arc};

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::types::TunnelId;

pub const MAX_HEALTH_ORIGINS: usize = 16;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OriginObservation {
    pub healthy: Option<bool>,
    pub checked_ago_ms: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OriginHealthReport {
    pub origins: Vec<OriginObservation>,
}

impl OriginHealthReport {
    pub fn validate(&self, count: usize) -> Result<()> {
        ensure!(
            count > 0 && count <= MAX_HEALTH_ORIGINS && self.origins.len() == count,
            "invalid origin health count"
        );
        ensure!(
            self.origins
                .iter()
                .all(|o| o.healthy.is_some() == o.checked_ago_ms.is_some()),
            "health result requires an observation age"
        );
        Ok(())
    }

    pub fn age_by(&mut self, elapsed: std::time::Duration) {
        let elapsed = u32::try_from(elapsed.as_millis()).unwrap_or(u32::MAX);
        for origin in &mut self.origins {
            origin.checked_ago_ms = origin.checked_ago_ms.map(|age| age.saturating_add(elapsed));
        }
    }
}

/// A synchronous, short snapshot read. Both transports sample only when polled.
#[derive(Clone)]
pub struct OriginHealthSource(Arc<dyn Fn() -> OriginHealthReport + Send + Sync>);
impl std::fmt::Debug for OriginHealthSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OriginHealthSource")
    }
}
impl OriginHealthSource {
    pub fn new(read: impl Fn() -> OriginHealthReport + Send + Sync + 'static) -> Self {
        Self(Arc::new(read))
    }
}

#[derive(Default)]
pub struct OriginHealthSources(HashMap<TunnelId, OriginHealthSource>);
impl OriginHealthSources {
    pub fn insert(&mut self, id: TunnelId, source: OriginHealthSource) -> Result<()> {
        ensure!(
            self.0.len() < 64 || self.0.contains_key(&id),
            "too many health sources"
        );
        self.0.insert(id, source);
        Ok(())
    }
    pub fn remove(&mut self, id: TunnelId) {
        self.0.remove(&id);
    }
    pub fn snapshot(&self, id: TunnelId) -> Option<OriginHealthReport> {
        self.0.get(&id).map(|source| (source.0)())
    }
}
