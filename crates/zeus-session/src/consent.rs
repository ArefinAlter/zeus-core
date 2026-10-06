//! Consent: the grants that decide whether session material may be released (01 section 5).
//!
//! A grant is a recorded consent and **never contains cookies**. Only a human on a trust surface creates,
//! renews or revokes grants; this trait is the daemon's persistence-neutral view of them, and an
//! in-memory implementation is provided for tests and embedders. The extension keeps its own consent
//! records for the release gate (02 section 10.2); those live in TypeScript, not here.
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: InMemoryConsentStore is filled in by the zeus-session implementation task"
)]

use std::sync::Mutex;

use zeus_types::{Actor, ApprovalId, GrantId, JobId, Origin, RunId, SessionGrant, Timestamp};

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
        Err(SessionError::NotImplemented("InMemoryConsentStore::create"))
    }

    fn get(&self, id: GrantId) -> SessionResult<Option<SessionGrant>> {
        Err(SessionError::NotImplemented("InMemoryConsentStore::get"))
    }

    fn list(&self, include_inactive: bool) -> SessionResult<Vec<SessionGrant>> {
        Err(SessionError::NotImplemented("InMemoryConsentStore::list"))
    }

    fn resolve(
        &self,
        origin: &Origin,
        job: Option<JobId>,
        run: Option<RunId>,
        now: Timestamp,
    ) -> SessionResult<Resolution> {
        Err(SessionError::NotImplemented(
            "InMemoryConsentStore::resolve",
        ))
    }

    fn record_use(&self, id: GrantId, now: Timestamp) -> SessionResult<SessionGrant> {
        Err(SessionError::NotImplemented(
            "InMemoryConsentStore::record_use",
        ))
    }

    fn revoke(&self, id: GrantId, by: &Actor, now: Timestamp) -> SessionResult<SessionGrant> {
        Err(SessionError::NotImplemented("InMemoryConsentStore::revoke"))
    }

    fn renew(&self, id: GrantId, by: &Actor, now: Timestamp) -> SessionResult<SessionGrant> {
        Err(SessionError::NotImplemented("InMemoryConsentStore::renew"))
    }

    fn consume_for_job(&self, job: JobId, now: Timestamp) -> SessionResult<Vec<SessionGrant>> {
        Err(SessionError::NotImplemented(
            "InMemoryConsentStore::consume_for_job",
        ))
    }

    fn sweep_expired(&self, now: Timestamp) -> SessionResult<Vec<SessionGrant>> {
        Err(SessionError::NotImplemented(
            "InMemoryConsentStore::sweep_expired",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_store_trait_is_object_safe() {
        let store: Box<dyn ConsentStore> = Box::new(InMemoryConsentStore::new());
        assert!(matches!(
            store.list(true),
            Err(SessionError::NotImplemented(_))
        ));
    }
}
