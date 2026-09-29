//! Bounded process-local store used unless shared storage is configured.
use super::{digest, random, Pending, Session};
use crate::visitor_policy::Rejection;
use std::collections::HashMap;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::time::Instant;
struct State {
    pending: HashMap<String, Pending>,
    sessions: HashMap<String, Arc<Session>>,
    prune_at: Instant,
}
pub(super) struct Store {
    state: Mutex<State>,
}
impl Store {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(State {
                pending: HashMap::new(),
                sessions: HashMap::new(),
                prune_at: Instant::now(),
            }),
        }
    }
    fn prune(state: &mut State) {
        let now = Instant::now();
        if now < state.prune_at && state.pending.len() < 1024 && state.sessions.len() < 8192 {
            return;
        }
        state.pending.retain(|_, flow| flow.expires > now);
        state.sessions.retain(|_, session| {
            if session.expires > now {
                true
            } else {
                session.close();
                false
            }
        });
        state.prune_at = now + Duration::from_secs(30);
    }
    pub fn begin(&self, pending: Pending) -> Result<String, Rejection> {
        let token = random()?;
        let mut state = self.state.lock().map_err(|_| Rejection::Unavailable)?;
        Self::prune(&mut state);
        if state.pending.len() >= 1024
            || state
                .pending
                .values()
                .filter(|p| p.scope == pending.scope)
                .count()
                >= 64
        {
            return Err(Rejection::Unavailable);
        }
        state.pending.insert(digest(&token), pending);
        Ok(token)
    }
    pub fn consume(&self, token: &str, browser: &str, scope: &str) -> Result<Pending, Rejection> {
        let mut state = self.state.lock().map_err(|_| Rejection::Unavailable)?;
        let key = digest(token);
        let matching = state.pending.get(&key).is_some_and(|flow| {
            flow.scope == scope
                && flow.expires > Instant::now()
                && flow.browser_hash == digest(browser)
        });
        if !matching {
            return Err(Rejection::InvalidSignIn);
        }
        state.pending.remove(&key).ok_or(Rejection::InvalidSignIn)
    }
    pub fn create(
        &self,
        scope: &str,
        expires: Instant,
    ) -> Result<(String, Arc<Session>), Rejection> {
        let token = random()?;
        let mut state = self.state.lock().map_err(|_| Rejection::Unavailable)?;
        Self::prune(&mut state);
        if state.sessions.len() >= 8192 {
            return Err(Rejection::Unavailable);
        }
        let session = Arc::new(Session {
            scope: scope.into(),
            expires,
            closed: tokio::sync::watch::channel(false).0,
        });
        state.sessions.insert(digest(&token), session.clone());
        Ok((token, session))
    }
    pub fn get(&self, token: &str, scope: &str) -> Option<Arc<Session>> {
        if token.len() != 43 {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        Self::prune(&mut state);
        state
            .sessions
            .get(&digest(token))
            .filter(|session| {
                session.scope == scope
                    && session.expires > Instant::now()
                    && !*session.closed.borrow()
            })
            .cloned()
    }
    pub fn revoke(&self, token: &str, scope: &str) -> Result<(), Rejection> {
        let mut state = self.state.lock().map_err(|_| Rejection::Unavailable)?;
        let key = digest(token);
        if state
            .sessions
            .get(&key)
            .is_some_and(|session| session.scope == scope)
        {
            if let Some(session) = state.sessions.remove(&key) {
                session.close();
            }
        }
        Ok(())
    }
}
