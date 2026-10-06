//! Ports the engine calls out through, owned by the embedding daemon.
//!
//! Approvals are **human-only** and their lifecycle (daemon-computed facts, request hash, expiry,
//! single-use decisions, channels) belongs to the daemon (spec 07). The engine only knows when a
//! decision is *needed* (transitions S02, S07, S11, S23, S41) and when one has been *taken*
//! ([`Engine::apply_approval`](crate::Engine::apply_approval)); it never decides, creates grants from
//! agent input, or reads cookies on behalf of an agent.

use async_trait::async_trait;
use zeus_types::{
    Approval, ApprovalId, ApprovalKind, ApprovalSummary, ErrorEnvelope, GrantScope, JobId, Origin,
    RunId,
};

/// What the engine asks the daemon to put in front of a human.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRequest {
    /// What is being asked.
    pub kind: ApprovalKind,
    /// The job concerned.
    pub job_id: Option<JobId>,
    /// The run concerned.
    pub run_id: Option<RunId>,
    /// The origin concerned.
    pub origin: Option<Origin>,
    /// Scopes the human may choose (defaults per kind: [`ApprovalKind::default_allowed_scopes`]).
    pub allowed_scopes: Vec<GrantScope>,
    /// Why, for example `handoff.interrupted`, `session.first_use`, `retry.exhausted`, `grant.revoked`.
    pub reason_codes: Vec<String>,
    /// Display data computed by the engine from the job (redacted URL, size, source kind). The title is
    /// untrusted text.
    pub summary: ApprovalSummary,
}

/// The daemon's approvals manager, as the engine sees it.
#[async_trait]
pub trait ApprovalPort: Send + Sync {
    /// Creates the approval (assigns its id and expiry, computes the request hash, notifies the trust
    /// surfaces) and returns it. Fails with `policy.too_many_pending` when 50 are already pending.
    async fn request(&self, request: ApprovalRequest) -> Result<Approval, ErrorEnvelope>;

    /// Withdraws a pending approval because its job was canceled (decision `cancel`, actor `system`).
    async fn withdraw(&self, approval_id: ApprovalId) -> Result<(), ErrorEnvelope>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_port_is_object_safe() {
        fn takes(_: Option<&dyn ApprovalPort>) {}
        takes(None);
    }
}
