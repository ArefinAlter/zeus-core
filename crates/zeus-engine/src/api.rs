//! Request and result types of the [`Engine`](crate::Engine) facade.

use zeus_types::{
    ActorKind, Approval, ApprovalId, ErrorEnvelope, HttpUrl, Job, JobId, JobSpec, JobState,
    JobSummary, Origin, ProbeResult, SessionGrant,
};

/// Who is calling: used for idempotency scoping, rate limits, audit records and the `Source` of the job.
/// The authenticated identity comes from the daemon, never from the request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The client id (at most 128 characters), for example `claude-code:3d9e` or `ext:chrome`.
    pub client_id: String,
    /// What kind of actor it is.
    pub kind: ActorKind,
}

/// `enqueue`: a job spec from an authenticated caller. The engine fills defaults, resolves the
/// effective grant, decides between transitions S01 and S02, reserves the destination and returns.
/// It never blocks on the download.
#[derive(Debug, Clone)]
pub struct EnqueueRequest {
    /// The job spec. `spec.source` must be consistent with `caller`.
    pub spec: JobSpec,
    /// The caller.
    pub caller: Caller,
}

/// The result of `enqueue`.
#[derive(Debug, Clone)]
pub struct EnqueueOutcome {
    /// The job (`queued` or `awaiting_approval`).
    pub job: Job,
    /// True when `idempotency_key` matched an earlier identical request and its stored job is returned.
    pub deduplicated: bool,
    /// The approval raised by S02, if any.
    pub approval: Option<Approval>,
}

/// A standalone probe: learn about a URL without creating a job (the `zeus_probe` tool).
#[derive(Debug, Clone)]
pub struct ProbeUrlRequest {
    /// The URL to probe.
    pub url: HttpUrl,
    /// The origin whose session the probe would need; with no effective grant the probe runs without
    /// session and reports `requires_session` instead of asking for one.
    pub session_origin: Option<Origin>,
    /// The caller.
    pub caller: Caller,
}

/// What a client may do to a job (01 section 7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlAction {
    /// Pause (S05, S15, S24, S61). Refused in `finalizing` and `verifying` with `api.not_interruptible`.
    Pause,
    /// Resume a paused job (S50).
    Resume,
    /// Cancel (S06, S16, S26, S32, S43, S51, S62, S73): deletes the partial data, zeroizes any lease,
    /// withdraws a pending approval. Refused in `finalizing`.
    Cancel,
    /// Retry a failed job now (S90) or a `retry_scheduled` job without waiting (S60).
    Retry,
    /// Change the priority (the only mutable spec field); not a state transition.
    SetPriority(zeus_types::Priority),
}

/// Filters of `list`.
#[derive(Debug, Clone, Default)]
pub struct ListFilter {
    /// Only these states.
    pub states: Option<Vec<JobState>>,
    /// Only jobs created by this run.
    pub run_id: Option<zeus_types::RunId>,
    /// Continuation cursor (the id of the last job of the previous page).
    pub cursor: Option<JobId>,
    /// Page size, default 50, at most 100.
    pub limit: Option<usize>,
}

/// One page of results.
#[derive(Debug, Clone)]
pub struct Page<T> {
    /// The items.
    pub items: Vec<T>,
    /// The cursor of the next page, or `None` at the end.
    pub next_cursor: Option<JobId>,
}

impl<T> Page<T> {
    /// An empty last page.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
        }
    }
}

/// A human decision already applied by the daemon's approvals manager, handed to the engine so it can
/// apply the resulting transition (S30, S31, S32) in order with the job's other transitions.
#[derive(Debug, Clone)]
pub struct ApprovalResolution {
    /// The decided approval (immutable).
    pub approval: Approval,
    /// The grant the decision created, if any (`approve`, or `deny` with scope `never`).
    pub grant: Option<SessionGrant>,
}

/// A change to the grants a job may depend on, from a revocation or an expiry sweep (01 section 5.2
/// rules 4 and 5): the engine re-evaluates dependent jobs (S07, S23, S41).
#[derive(Debug, Clone)]
pub struct GrantChange {
    /// The origin whose grant changed.
    pub origin: Origin,
    /// Why.
    pub kind: GrantChangeKind,
}

/// How a grant ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantChangeKind {
    /// A human revoked it.
    Revoked,
    /// It expired.
    Expired,
}

/// A summary of what the engine knows right now.
#[derive(Debug, Clone, Default)]
pub struct EngineStatus {
    /// Jobs per state.
    pub jobs_by_state: Vec<(JobState, u64)>,
    /// Approvals the engine is waiting on.
    pub pending_approvals: Vec<ApprovalId>,
    /// Whether an extension connection is available for session handoff.
    pub extension_connected: bool,
    /// The newest durable event sequence.
    pub head_seq: u64,
}

/// The envelope for a rejected `enqueue` is carried by [`crate::EngineError::Rejected`].
pub type Rejection = ErrorEnvelope;

/// Projects a job into a list item.
#[must_use]
pub fn summary_of(job: &Job) -> JobSummary {
    job.summary()
}

/// The standalone probe result.
pub type ProbeReport = ProbeResult;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_page() {
        let p: Page<JobSummary> = Page::empty();
        assert!(p.items.is_empty() && p.next_cursor.is_none());
    }
}

/// Durable results of an emergency-stop policy transaction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KillSwitchOutcome {
    /// Whether network admission is stopped.
    pub engaged: bool,
    /// Active allow grants revoked by this transaction.
    pub grants_revoked: u64,
    /// Interruptible jobs paused by this transaction.
    pub jobs_paused: u64,
}
