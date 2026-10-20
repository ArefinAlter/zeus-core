//! Consent: the grants that decide whether session material may be released (01 section 5).
//!
//! A grant is a recorded consent and **never contains cookies**. Only a human on a trust surface creates,
//! renews or revokes grants; this trait is the daemon's persistence-neutral view of them, and an
//! in-memory implementation is provided for tests and embedders. The extension keeps its own consent
//! records for the release gate (02 section 10.2); those live in TypeScript, not here.
use std::sync::Mutex;

use zeus_types::{
    Actor, ApprovalId, GrantId, GrantScope, GrantState, IdGenerator, JobId, Origin, RunId,
    SessionGrant, Timestamp,
};

use crate::error::{SessionError, SessionResult};

/// The data a human decision supplies when it creates a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewGrant {
    /// The one origin the grant covers.
    pub origin: Origin,
    /// The scope the human chose.
    pub scope: zeus_types::GrantScope,
    /// For `once`: the job.
    pub job_id: Option<JobId>,
    /// For `workflow`: the run.
    pub run_id: Option<RunId>,
    /// The approval that produced the decision.
    pub approval_id: ApprovalId,
    /// The human who decided. Must be a human on a trust surface (01 section 5.3 rule 1).
    pub decided_by: Actor,
}

/// The result of resolving the effective grant for a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    /// A `never` grant blocks the origin.
    Denied(SessionGrant),
    /// The effective grant.
    Allowed(SessionGrant),
    /// No effective grant: ask a human.
    None,
}

/// The daemon's grant store. Synchronous; callers on async tasks use `spawn_blocking` when the
/// implementation is journal-backed.
pub trait ConsentStore: Send + Sync {
    /// Creates a grant from a human decision: validates the scope bindings (`once` needs `job_id`,
    /// `workflow` needs `run_id`), refuses a non-human decider, and computes `expires_at` from the scope
    /// (`once`: at most 24 h; `site`: 24 h; `workflow`: 7 d; `never`: none).
    fn create(&self, new: NewGrant, now: Timestamp) -> SessionResult<SessionGrant>;

    /// One grant by id.
    fn get(&self, id: GrantId) -> SessionResult<Option<SessionGrant>>;

    /// Grants, newest first; with `include_inactive` also expired, revoked and consumed ones.
    fn list(&self, include_inactive: bool) -> SessionResult<Vec<SessionGrant>>;

    /// The effective grant by the precedence of 01 section 5.2: `never` (deny), `once` bound to the
    /// job, `workflow` bound to the run, `site`; only active, unexpired grants for the exact origin.
    fn resolve(
        &self,
        origin: &Origin,
        job: Option<JobId>,
        run: Option<RunId>,
        now: Timestamp,
    ) -> SessionResult<Resolution>;

    /// Records one lease issued under the grant (`uses` + 1, `last_used_at`). The audit record
    /// `session.lease_requested` is made durable by the caller **before** the lease is requested.
    fn record_use(&self, id: GrantId, now: Timestamp) -> SessionResult<SessionGrant>;

    /// Revokes immediately; idempotent. A revoked grant stays revoked.
    fn revoke(&self, id: GrantId, by: &Actor, now: Timestamp) -> SessionResult<SessionGrant>;

    /// Renews a `workflow` grant for another 7 days (a human decision), incrementing `renewal_count`.
    /// Other scopes are not renewable.
    fn renew(&self, id: GrantId, by: &Actor, now: Timestamp) -> SessionResult<SessionGrant>;

    /// Marks the `once` grants of a finished job `consumed`.
    fn consume_for_job(&self, job: JobId, now: Timestamp) -> SessionResult<Vec<SessionGrant>>;

    /// Moves every active grant past its `expires_at` to `expired` and returns them (the sweeper runs
    /// every 60 s; every use also checks lazily).
    fn sweep_expired(&self, now: Timestamp) -> SessionResult<Vec<SessionGrant>>;
}

/// A [`ConsentStore`] that keeps grants in memory.
#[derive(Debug, Default)]
pub struct InMemoryConsentStore {
    grants: Mutex<Vec<SessionGrant>>,
}

impl InMemoryConsentStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ConsentStore for InMemoryConsentStore {
    fn create(&self, new: NewGrant, now: Timestamp) -> SessionResult<SessionGrant> {
        if !new.decided_by.is_human_on_trust_surface()
            || !new
                .decided_by
                .surface
                .is_some_and(zeus_types::Surface::is_approving_surface)
        {
            return Err(SessionError::Protocol(
                "grant requires a human trust surface",
            ));
        }
        if (new.scope == GrantScope::Once && new.job_id.is_none())
            || (new.scope == GrantScope::Workflow && new.run_id.is_none())
        {
            return Err(SessionError::Protocol("grant scope lacks binding"));
        }
        let grant = SessionGrant {
            id: IdGenerator::new().grant_id(),
            origin: new.origin,
            scope: new.scope,
            state: GrantState::Active,
            created_at: now,
            expires_at: new.scope.lifetime_ms().map(|ms| now.saturating_add_ms(ms)),
            job_id: new.job_id,
            run_id: new.run_id,
            approval_id: new.approval_id,
            decided_by: new.decided_by,
            uses: 0,
            last_used_at: None,
            revoked_at: None,
            renewable: new.scope.renewable(),
            renewal_count: 0,
            renewed_at: None,
            revoked_by: None,
            revocation_reason: None,
        };
        self.grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(grant.clone());
        Ok(grant)
    }

    fn get(&self, id: GrantId) -> SessionResult<Option<SessionGrant>> {
        Ok(self
            .grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .find(|g| g.id == id)
            .cloned())
    }

    fn list(&self, include_inactive: bool) -> SessionResult<Vec<SessionGrant>> {
        let mut grants: Vec<_> = self
            .grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|g| include_inactive || g.is_effective_at(Timestamp::now()))
            .cloned()
            .collect();
        grants.sort_by_key(|g| std::cmp::Reverse(g.created_at));
        Ok(grants)
    }

    fn resolve(
        &self,
        origin: &Origin,
        job: Option<JobId>,
        run: Option<RunId>,
        now: Timestamp,
    ) -> SessionResult<Resolution> {
        let grants = self
            .grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(
            match zeus_types::grant::resolve_grant(grants.iter(), origin, job, run, now) {
                zeus_types::grant::GrantResolution::Denied(g) => Resolution::Denied(g.clone()),
                zeus_types::grant::GrantResolution::Allowed(g) => Resolution::Allowed(g.clone()),
                zeus_types::grant::GrantResolution::None => Resolution::None,
            },
        )
    }

    fn record_use(&self, id: GrantId, now: Timestamp) -> SessionResult<SessionGrant> {
        let mut grants = self
            .grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let g = grants
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or(SessionError::Protocol("unknown grant"))?;
        if !g.is_effective_at(now) || g.scope == GrantScope::Never {
            return Err(SessionError::Protocol("grant is not effective"));
        }
        g.uses += 1;
        g.last_used_at = Some(now);
        Ok(g.clone())
    }

    fn revoke(&self, id: GrantId, by: &Actor, now: Timestamp) -> SessionResult<SessionGrant> {
        if !by.is_human_on_trust_surface()
            || !by
                .surface
                .is_some_and(zeus_types::Surface::is_approving_surface)
        {
            return Err(SessionError::Protocol(
                "revocation requires a human trust surface",
            ));
        }
        let mut grants = self
            .grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let g = grants
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or(SessionError::Protocol("unknown grant"))?;
        if g.state != GrantState::Revoked {
            g.state = GrantState::Revoked;
            g.revoked_at = Some(now);
            g.revoked_by = Some(by.clone());
            g.revocation_reason = Some(zeus_types::grant::RevocationReason::UserRequest);
        }
        Ok(g.clone())
    }

    fn renew(&self, id: GrantId, by: &Actor, now: Timestamp) -> SessionResult<SessionGrant> {
        if !by.is_human_on_trust_surface()
            || !by
                .surface
                .is_some_and(zeus_types::Surface::is_approving_surface)
        {
            return Err(SessionError::Protocol(
                "renewal requires a human trust surface",
            ));
        }
        let mut grants = self
            .grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let g = grants
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or(SessionError::Protocol("unknown grant"))?;
        if g.scope != GrantScope::Workflow
            || g.state == GrantState::Revoked
            || g.state == GrantState::Consumed
        {
            return Err(SessionError::Protocol("grant cannot be renewed"));
        }
        g.state = GrantState::Active;
        g.expires_at = Some(now.saturating_add_ms(604_800_000));
        g.renewal_count += 1;
        g.renewed_at = Some(now);
        Ok(g.clone())
    }

    fn consume_for_job(&self, job: JobId, now: Timestamp) -> SessionResult<Vec<SessionGrant>> {
        let mut grants = self
            .grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut changed = Vec::new();
        for g in grants.iter_mut().filter(|g| {
            g.job_id == Some(job) && g.scope == GrantScope::Once && g.is_effective_at(now)
        }) {
            g.state = GrantState::Consumed;
            changed.push(g.clone());
        }
        Ok(changed)
    }

    fn sweep_expired(&self, now: Timestamp) -> SessionResult<Vec<SessionGrant>> {
        let mut grants = self
            .grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut changed = Vec::new();
        for g in grants
            .iter_mut()
            .filter(|g| g.state == GrantState::Active && g.expires_at.is_some_and(|t| t <= now))
        {
            g.state = GrantState::Expired;
            changed.push(g.clone());
        }
        Ok(changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_store_trait_is_object_safe() {
        let store: Box<dyn ConsentStore> = Box::new(InMemoryConsentStore::new());
        assert!(store.list(true).unwrap().is_empty());
    }
}
