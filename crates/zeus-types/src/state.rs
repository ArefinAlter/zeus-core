//! The job state machine (01 sections 6 and 7).
//!
//! [`TRANSITIONS`] is a transcription of `schema/job-state-machine.v1.json`, the normative
//! machine-readable table; the integration test `state_machine_conformance` loads a copy of that
//! file and checks that every row is present here and that every pair of states not in the table is
//! rejected. Guards are prose in the specification (they depend on journal contents, grants and
//! budgets), so this module checks *structure* (source state, actor, event set, cause) and the engine
//! evaluates guards.

use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ErrorEnvelope, TypesError, codes};
use crate::event::EventKind;

/// The twelve job states (01 section 6).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    /// Accepted, waiting for a scheduler slot.
    Queued,
    /// Probe and resume validation in flight; no payload bytes are committed in this state.
    Probing,
    /// Blocked on a human decision (an Approval is pending).
    AwaitingApproval,
    /// Blocked on session material, a fresh URL or the in-browser proxy; no human needed.
    AwaitingSession,
    /// Payload bytes are being fetched and committed.
    Downloading,
    /// Held by an explicit pause; resumes only on request.
    Paused,
    /// Waiting for `next_attempt_at` after a retryable error.
    RetryScheduled,
    /// All bytes committed; hashing and content checks.
    Verifying,
    /// Non-interruptible: OS marks, fsync, atomic rename, completion commit.
    Finalizing,
    /// File is at its final path and verified. May carry `quarantined = true`.
    Completed,
    /// Stopped with an error. Only a manual retry leaves this state.
    Failed,
    /// Stopped by request; partial data deleted.
    Canceled,
}

impl JobState {
    /// All states in the order of the specification.
    pub const ALL: [Self; 12] = [
        Self::Queued,
        Self::Probing,
        Self::AwaitingApproval,
        Self::AwaitingSession,
        Self::Downloading,
        Self::Paused,
        Self::RetryScheduled,
        Self::Verifying,
        Self::Finalizing,
        Self::Completed,
        Self::Failed,
        Self::Canceled,
    ];

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Probing => "probing",
            Self::AwaitingApproval => "awaiting_approval",
            Self::AwaitingSession => "awaiting_session",
            Self::Downloading => "downloading",
            Self::Paused => "paused",
            Self::RetryScheduled => "retry_scheduled",
            Self::Verifying => "verifying",
            Self::Finalizing => "finalizing",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
        }
    }

    /// Terminal per the table: only `completed` and `canceled`. `failed` is not terminal because a
    /// manual retry (S90) leaves it.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Canceled)
    }

    /// States in which the engine owns running work, and which daemon-startup recovery moves back
    /// to `queued` or `failed` (S95 and S96).
    #[must_use]
    pub const fn is_in_flight(self) -> bool {
        matches!(
            self,
            Self::Probing | Self::Downloading | Self::Verifying | Self::Finalizing
        )
    }

    /// States that wait for something outside the engine (a person, the extension, a timer or a
    /// pause) and keep their state across a daemon restart.
    #[must_use]
    pub const fn is_waiting(self) -> bool {
        matches!(
            self,
            Self::AwaitingApproval | Self::AwaitingSession | Self::Paused | Self::RetryScheduled
        )
    }

    /// True while the job holds a destination reservation and, possibly, a data file: every state
    /// except `completed`, `canceled` and `failed` past its retention (03 section 3.2).
    #[must_use]
    pub const fn holds_reservation(self) -> bool {
        !matches!(self, Self::Completed | Self::Canceled)
    }

    /// True when `pause` is meaningful (not in `verifying`, `finalizing` or a final state).
    #[must_use]
    pub const fn can_pause(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Probing | Self::Downloading | Self::RetryScheduled
        )
    }

    /// True when `cancel` is accepted (01 section 6 rule 6: refused in `finalizing`).
    #[must_use]
    pub const fn can_cancel(self) -> bool {
        !matches!(
            self,
            Self::Finalizing | Self::Completed | Self::Canceled | Self::Failed
        )
    }
}

impl fmt::Display for JobState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for JobState {
    type Err = TypesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|st| st.as_str() == s)
            .ok_or(TypesError::Invalid("unknown job state"))
    }
}

/// Who may trigger a transition (01 section 6, "Actors").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransitionActor {
    /// Any authenticated client allowed to control jobs: CLI, TUI, MCP, A2A, extension popup.
    Client,
    /// A human-only trust surface. Never an agent.
    Human,
    /// Daemon internals: scheduler, probe, transfer and verification tasks.
    Engine,
    /// Policy evaluation inside the daemon (grants, never-list, roots).
    Policy,
    /// Timers and daemon startup recovery.
    System,
}

/// Closed set of causes carried by `job.state_changed` (01 section 7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StateCause {
    /// Reserved for the creation event payload.
    Created,
    /// Pause, resume, cancel or retry by a client.
    UserRequest,
    /// A scheduler slot was granted.
    Scheduler,
    /// The probe succeeded.
    ProbeOk,
    /// Session material, a fresh URL or the proxy is needed.
    SessionNeeded,
    /// A human decision is needed.
    ApprovalNeeded,
    /// The approval was approved.
    ApprovalApproved,
    /// The approval was denied.
    ApprovalDenied,
    /// The approval expired.
    ApprovalExpired,
    /// Session material arrived.
    SessionDelivered,
    /// The `awaiting_session` deadline passed.
    SessionDeadline,
    /// The extension cannot refresh.
    RefreshImpossible,
    /// `next_attempt_at` was reached.
    RetryTimer,
    /// A client asked to retry now.
    RetryNow,
    /// All ranges are committed.
    AllCommitted,
    /// Verification passed.
    VerificationOk,
    /// An integrity mismatch restarts the download.
    IntegrityRestart,
    /// An integrity mismatch with no restart budget left.
    IntegrityFailed,
    /// The file reached its final path.
    Finalized,
    /// A disk error during finalization.
    FinalizeError,
    /// A classified error.
    Error,
    /// The refresh budget is exhausted.
    Escalation,
    /// A grant the job depends on was revoked.
    GrantRevoked,
    /// A grant the job depends on expired.
    GrantExpired,
    /// A policy rule applies.
    Policy,
    /// Startup recovery re-queued the job.
    Recovered,
    /// Startup recovery gave up (crash loop).
    CrashLoop,
}

/// A transition identifier `S<nn>`, validated against the table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct TransitionId(String);

impl TransitionId {
    /// Validates the form `S<two digits>` and that the table contains it.
    pub fn new(id: &str) -> Result<Self, TypesError> {
        if transition_def(id).is_some() {
            Ok(Self(id.to_owned()))
        } else {
            Err(TypesError::Invalid("unknown transition id"))
        }
    }

    /// The identifier text, for example `S30`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The table row.
    #[must_use]
    pub fn def(&self) -> &'static TransitionDef {
        // Constructed only from table ids, so the lookup cannot fail; the fallback keeps this total.
        transition_def(&self.0).unwrap_or(&TRANSITIONS[0])
    }
}

impl fmt::Display for TransitionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TransitionId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        // Unknown ids from a newer peer must not break an old reader (00 section 4 rule 7): accept
        // any well-formed `S<nn>` and let `def()` fall back. Behaviour never hinges on the id.
        let well_formed =
            s.len() == 3 && s.starts_with('S') && s[1..].bytes().all(|b| b.is_ascii_digit());
        if well_formed {
            Ok(Self(s))
        } else {
            Err(serde::de::Error::custom("invalid transition id"))
        }
    }
}

/// One row of the transition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransitionDef {
    /// `S01` and so on.
    pub id: &'static str,
    /// Source states; `None` is "no job yet" (creation).
    pub from: &'static [Option<JobState>],
    /// Target state.
    pub to: JobState,
    /// Human-readable trigger.
    pub trigger: &'static str,
    /// Who may trigger it.
    pub actors: &'static [TransitionActor],
    /// The guard, as prose. Evaluated by the engine, not by this crate.
    pub guard: &'static str,
    /// Events emitted, in this order.
    pub events: &'static [EventKind],
    /// Causes allowed in the `job.state_changed` event (01 section 7.1); empty for creation.
    pub causes: &'static [StateCause],
}

impl TransitionDef {
    /// True when `actor` may trigger this transition.
    #[must_use]
    pub fn permits(&self, actor: TransitionActor) -> bool {
        self.actors.contains(&actor)
    }

    /// True when the row starts from `state` (`None` for creation).
    #[must_use]
    pub fn starts_from(&self, state: Option<JobState>) -> bool {
        self.from.contains(&state)
    }
}

use EventKind as E;
use JobState::{
    AwaitingApproval as AwApproval, AwaitingSession as AwSession, Canceled, Completed, Downloading,
    Failed, Finalizing, Paused, Probing, Queued, RetryScheduled as Retry, Verifying,
};
use StateCause as C;
use TransitionActor::{Client, Engine, Human, Policy, System};

macro_rules! row {
    ($id:literal, [$($from:expr),+], $to:expr, $trigger:literal, [$($actor:expr),+], $guard:literal, [$($ev:expr),+], [$($cause:expr),*]) => {
        TransitionDef {
            id: $id,
            from: &[$($from),+],
            to: $to,
            trigger: $trigger,
            actors: &[$($actor),+],
            guard: $guard,
            events: &[$($ev),+],
            causes: &[$($cause),*],
        }
    };
}

/// The normative transition table. Every row is a test case and every pair of states not in it
/// is illegal (01 section 6 rule 1).
pub const TRANSITIONS: &[TransitionDef] = &[
    row!(
        "S01",
        [None],
        Queued,
        "create",
        [Client],
        "No approval needed (no session required, or an effective grant exists).",
        [E::JobCreated],
        []
    ),
    row!(
        "S02",
        [None],
        AwApproval,
        "create",
        [Client],
        "Approval needed at creation: browser_handoff without an effective grant, or enqueue naming session_origin without one.",
        [E::JobCreated, E::ApprovalRequested],
        []
    ),
    row!(
        "S03",
        [Some(Queued)],
        Probing,
        "scheduler slot granted",
        [Engine],
        "Global and per-host budget available; journal does not already cover every byte.",
        [E::JobStateChanged],
        [C::Scheduler]
    ),
    row!(
        "S04",
        [Some(Queued)],
        Verifying,
        "scheduler slot granted",
        [Engine],
        "Journal shows every byte committed (resumption after a crash or a finalize retry).",
        [E::JobStateChanged],
        [C::Scheduler]
    ),
    row!(
        "S05",
        [Some(Queued)],
        Paused,
        "pause",
        [Client],
        "",
        [E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S06",
        [Some(Queued)],
        Canceled,
        "cancel",
        [Client],
        "",
        [E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S07",
        [Some(Queued)],
        AwApproval,
        "policy re-evaluation",
        [Policy],
        "A grant the job depends on was revoked or expired while queued.",
        [E::JobStateChanged, E::ApprovalRequested],
        [C::ApprovalNeeded, C::GrantRevoked, C::GrantExpired]
    ),
    row!(
        "S08",
        [Some(Queued)],
        Failed,
        "policy re-evaluation",
        [Policy],
        "Origin is on the never-list or the destination violates the write roots (class policy_denied).",
        [E::JobStateChanged, E::JobFailed],
        [C::Policy]
    ),
    row!(
        "S10",
        [Some(Probing)],
        Downloading,
        "probe and resume validation succeeded",
        [Engine],
        "Origin reachable; no session needed, or a valid lease is held.",
        [E::JobProbed, E::JobStateChanged],
        [C::ProbeOk]
    ),
    row!(
        "S11",
        [Some(Probing)],
        AwApproval,
        "probe shows session required",
        [Engine],
        "requires_session and no effective grant covers the origin.",
        [E::JobProbed, E::JobStateChanged, E::ApprovalRequested],
        [C::ApprovalNeeded]
    ),
    row!(
        "S12",
        [Some(Probing)],
        AwSession,
        "probe needs session material or proxy",
        [Engine],
        "Effective grant exists but no valid lease, or class blocked with refresh/proxy budget left.",
        [E::JobProbed, E::JobStateChanged, E::SessionRefreshNeeded],
        [C::SessionNeeded]
    ),
    row!(
        "S13",
        [Some(Probing)],
        Retry,
        "retryable error",
        [Engine],
        "Class transient_network, throttled or disk(transient) and retry budget left; or class integrity with a restart budget left (ranges are invalidated first).",
        [E::JobStateChanged, E::JobRetryScheduled, E::JobThrottled],
        [C::Error]
    ),
    row!(
        "S14",
        [Some(Probing)],
        Failed,
        "terminal error",
        [Engine],
        "Non-retryable class or retry budget exhausted.",
        [E::JobStateChanged, E::JobFailed],
        [C::Error]
    ),
    row!(
        "S15",
        [Some(Probing)],
        Paused,
        "pause",
        [Client],
        "",
        [E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S16",
        [Some(Probing)],
        Canceled,
        "cancel",
        [Client],
        "",
        [E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S20",
        [Some(Downloading)],
        Verifying,
        "all ranges committed",
        [Engine],
        "Committed range set equals [0, total) (or EOF reached for unknown length).",
        [E::JobStateChanged],
        [C::AllCommitted]
    ),
    row!(
        "S21",
        [Some(Downloading)],
        Retry,
        "retryable error",
        [Engine],
        "Class transient_network, throttled or disk(transient) and retry budget left; or class integrity with a restart budget left (ranges are invalidated first).",
        [E::JobStateChanged, E::JobRetryScheduled, E::JobThrottled],
        [C::Error]
    ),
    row!(
        "S22",
        [Some(Downloading)],
        AwSession,
        "auth, URL or block failure",
        [Engine],
        "Class auth_expired, url_expired or blocked with refresh/proxy budget left and an effective grant; or the extension connection carrying a browser_proxy transfer was lost.",
        [E::JobStateChanged, E::SessionRefreshNeeded],
        [C::Error]
    ),
    row!(
        "S23",
        [Some(Downloading)],
        AwApproval,
        "escalation to human",
        [Engine, Policy],
        "Refresh budget exhausted, or the grant was revoked or expired mid-transfer.",
        [E::JobStateChanged, E::ApprovalRequested],
        [C::Escalation, C::GrantRevoked, C::GrantExpired]
    ),
    row!(
        "S24",
        [Some(Downloading)],
        Paused,
        "pause",
        [Client],
        "",
        [E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S25",
        [Some(Downloading)],
        Failed,
        "terminal error",
        [Engine],
        "Class permanent, integrity (budget spent), policy_denied, non-transient disk, blocked after a failed proxy attempt, or retry budget exhausted.",
        [E::JobStateChanged, E::JobFailed],
        [C::Error]
    ),
    row!(
        "S26",
        [Some(Downloading)],
        Canceled,
        "cancel",
        [Client],
        "",
        [E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S30",
        [Some(AwApproval)],
        Queued,
        "approval approved",
        [Human],
        "Approval decision is approve and the approval has not expired. grant.created is emitted only when the decision creates a grant.",
        [E::ApprovalDecided, E::GrantCreated, E::JobStateChanged],
        [C::ApprovalApproved]
    ),
    row!(
        "S31",
        [Some(AwApproval)],
        Failed,
        "approval denied or expired",
        [Human, System],
        "Decision deny, or approval deadline passed (class policy_denied). grant.created is emitted only when a deny decision also records a never grant.",
        [
            E::ApprovalDecided,
            E::GrantCreated,
            E::JobStateChanged,
            E::JobFailed
        ],
        [C::ApprovalDenied, C::ApprovalExpired]
    ),
    row!(
        "S32",
        [Some(AwApproval)],
        Canceled,
        "cancel",
        [Client],
        "The pending approval is withdrawn (decision canceled, actor system).",
        [E::ApprovalDecided, E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S40",
        [Some(AwSession)],
        Queued,
        "material delivered",
        [Engine],
        "Session lease, refreshed URL or proxy channel is now available.",
        [E::JobStateChanged],
        [C::SessionDelivered]
    ),
    row!(
        "S41",
        [Some(AwSession)],
        AwApproval,
        "consent missing",
        [Engine, Policy],
        "Extension answered consent_required, or the grant was revoked or expired while waiting.",
        [E::JobStateChanged, E::ApprovalRequested],
        [C::ApprovalNeeded, C::GrantRevoked, C::GrantExpired]
    ),
    row!(
        "S42",
        [Some(AwSession)],
        Failed,
        "wait deadline or refresh impossible",
        [Engine, System],
        "session_wait deadline passed, or the extension answered cannot_refresh / proxy failure with class blocked.",
        [E::JobStateChanged, E::JobFailed],
        [C::SessionDeadline, C::RefreshImpossible]
    ),
    row!(
        "S43",
        [Some(AwSession)],
        Canceled,
        "cancel",
        [Client],
        "",
        [E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S50",
        [Some(Paused)],
        Queued,
        "resume",
        [Client],
        "",
        [E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S51",
        [Some(Paused)],
        Canceled,
        "cancel",
        [Client],
        "",
        [E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S60",
        [Some(Retry)],
        Queued,
        "next_attempt_at reached, or retry now",
        [System, Client],
        "",
        [E::JobStateChanged],
        [C::RetryTimer, C::RetryNow]
    ),
    row!(
        "S61",
        [Some(Retry)],
        Paused,
        "pause",
        [Client],
        "",
        [E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S62",
        [Some(Retry)],
        Canceled,
        "cancel",
        [Client],
        "",
        [E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S70",
        [Some(Verifying)],
        Finalizing,
        "verification passed",
        [Engine],
        "Size, expected hash (if any) and content checks pass.",
        [E::JobVerified, E::JobQuarantined, E::JobStateChanged],
        [C::VerificationOk]
    ),
    row!(
        "S71",
        [Some(Verifying)],
        Retry,
        "integrity mismatch with restart budget, or transient disk error",
        [Engine],
        "Mismatch and integrity restarts < 1, or class disk(transient). On a mismatch all ranges are invalidated first.",
        [E::JobStateChanged, E::JobRetryScheduled],
        [C::IntegrityRestart, C::Error]
    ),
    row!(
        "S72",
        [Some(Verifying)],
        Failed,
        "integrity failure",
        [Engine],
        "Mismatch and no restart budget, or non-transient disk error.",
        [E::JobStateChanged, E::JobFailed],
        [C::IntegrityFailed, C::Error]
    ),
    row!(
        "S73",
        [Some(Verifying)],
        Canceled,
        "cancel",
        [Client],
        "",
        [E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S80",
        [Some(Finalizing)],
        Completed,
        "rename and completion commit done",
        [Engine],
        "",
        [E::JobCompleted, E::JobStateChanged],
        [C::Finalized]
    ),
    row!(
        "S81",
        [Some(Finalizing)],
        Retry,
        "transient disk error",
        [Engine],
        "Sharing violation, destination directory missing, transient I/O error; retry budget left.",
        [E::JobStateChanged, E::JobRetryScheduled],
        [C::FinalizeError]
    ),
    row!(
        "S82",
        [Some(Finalizing)],
        Failed,
        "terminal disk error",
        [Engine],
        "Permission denied, no space after retries, or destination outside write roots.",
        [E::JobStateChanged, E::JobFailed],
        [C::FinalizeError]
    ),
    row!(
        "S90",
        [Some(Failed)],
        Queued,
        "manual retry",
        [Client],
        "Journal data is kept; counters reset. A policy_denied job re-enters approval via S07 on the next evaluation.",
        [E::JobStateChanged],
        [C::UserRequest]
    ),
    row!(
        "S95",
        [
            Some(Probing),
            Some(Downloading),
            Some(Verifying),
            Some(Finalizing)
        ],
        Queued,
        "daemon startup recovery",
        [System],
        "recovery_count since last committed progress < 3.",
        [E::JobStateChanged],
        [C::Recovered]
    ),
    row!(
        "S96",
        [
            Some(Probing),
            Some(Downloading),
            Some(Verifying),
            Some(Finalizing)
        ],
        Failed,
        "daemon startup recovery",
        [System],
        "recovery_count since last committed progress >= 3 (crash loop). Error engine.crash_loop, class internal.",
        [E::JobStateChanged, E::JobFailed],
        [C::CrashLoop]
    ),
];

/// The row with identifier `id`, if any.
#[must_use]
pub fn transition_def(id: &str) -> Option<&'static TransitionDef> {
    TRANSITIONS.iter().find(|t| t.id == id)
}

/// All rows that lead from `from` (`None` for creation) to `to`. More than one row can match: the
/// caller disambiguates by trigger and guard (for example S03 and S04 both leave `queued`).
pub fn find_transitions(
    from: Option<JobState>,
    to: JobState,
) -> impl Iterator<Item = &'static TransitionDef> {
    TRANSITIONS
        .iter()
        .filter(move |t| t.to == to && t.starts_from(from))
}

/// All rows that leave `from` (`None` for creation).
pub fn transitions_from(from: Option<JobState>) -> impl Iterator<Item = &'static TransitionDef> {
    TRANSITIONS.iter().filter(move |t| t.starts_from(from))
}

/// True when at least one row leads from `from` to `to`.
#[must_use]
pub fn is_legal(from: Option<JobState>, to: JobState) -> bool {
    find_transitions(from, to).next().is_some()
}

/// Why a requested transition was refused. Maps to `conflict` / `api.invalid_transition`
/// (01 section 6 rule 1).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransitionError {
    /// The id is not in the table.
    #[error("unknown transition {0}")]
    Unknown(String),
    /// The row does not start from the job's current state.
    #[error("transition {id} cannot start from {from}")]
    WrongSource {
        /// The transition id.
        id: &'static str,
        /// Current state, or `none` for creation.
        from: String,
    },
    /// The actor may not trigger this row.
    #[error("{actor:?} may not trigger transition {id}")]
    ActorNotPermitted {
        /// The transition id.
        id: &'static str,
        /// The refused actor.
        actor: TransitionActor,
    },
    /// No row leads from `from` to `to`.
    #[error("no transition from {from} to {to}")]
    NoSuchEdge {
        /// Current state, or `none` for creation.
        from: String,
        /// Requested state.
        to: JobState,
    },
}

impl TransitionError {
    /// The envelope servers return: class `conflict`, code `api.invalid_transition`.
    #[must_use]
    pub fn to_envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope::from_code(codes::API_INVALID_TRANSITION, self.to_string())
    }
}

fn state_name(state: Option<JobState>) -> String {
    state.map_or_else(|| "none".to_owned(), |s| s.as_str().to_owned())
}

/// Validates that `actor` may apply transition `id` to a job currently in `from` and returns the
/// row and the resulting state. Guards are *not* evaluated.
pub fn apply(
    from: Option<JobState>,
    id: &str,
    actor: TransitionActor,
) -> Result<(JobState, &'static TransitionDef), TransitionError> {
    let def = transition_def(id).ok_or_else(|| TransitionError::Unknown(id.to_owned()))?;
    if !def.starts_from(from) {
        return Err(TransitionError::WrongSource {
            id: def.id,
            from: state_name(from),
        });
    }
    if !def.permits(actor) {
        return Err(TransitionError::ActorNotPermitted { id: def.id, actor });
    }
    Ok((def.to, def))
}

/// Like [`apply`] for callers that know the edge but not the id. Returns the first row that starts
/// at `from`, ends at `to` and permits `actor`.
pub fn apply_edge(
    from: Option<JobState>,
    to: JobState,
    actor: TransitionActor,
) -> Result<&'static TransitionDef, TransitionError> {
    let mut saw_edge = false;
    for def in find_transitions(from, to) {
        saw_edge = true;
        if def.permits(actor) {
            return Ok(def);
        }
    }
    if saw_edge {
        // Report the first row's id for diagnostics.
        let id = find_transitions(from, to).next().map_or("S??", |d| d.id);
        Err(TransitionError::ActorNotPermitted { id, actor })
    } else {
        Err(TransitionError::NoSuchEdge {
            from: state_name(from),
            to,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_ids_are_unique_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for t in TRANSITIONS {
            assert!(seen.insert(t.id), "duplicate {}", t.id);
            assert_eq!(t.id.len(), 3);
            assert!(t.id.starts_with('S'));
            assert!(!t.from.is_empty() && !t.actors.is_empty() && !t.events.is_empty());
        }
        assert_eq!(TRANSITIONS.len(), 44);
    }

    #[test]
    fn happy_path_is_legal() {
        let path = [
            (None, "S01", Client, Queued),
            (Some(Queued), "S03", Engine, Probing),
            (Some(Probing), "S10", Engine, Downloading),
            (Some(Downloading), "S20", Engine, Verifying),
            (Some(Verifying), "S70", Engine, Finalizing),
            (Some(Finalizing), "S80", Engine, Completed),
        ];
        for (from, id, actor, to) in path {
            assert_eq!(apply(from, id, actor).unwrap().0, to);
        }
    }

    #[test]
    fn only_humans_decide_approvals() {
        assert!(apply(Some(AwApproval), "S30", Human).is_ok());
        for actor in [Client, Engine, Policy, System] {
            assert!(matches!(
                apply(Some(AwApproval), "S30", actor),
                Err(TransitionError::ActorNotPermitted { .. })
            ));
        }
    }

    #[test]
    fn terminal_states_have_no_exits_and_failed_only_retries() {
        assert_eq!(transitions_from(Some(Completed)).count(), 0);
        assert_eq!(transitions_from(Some(Canceled)).count(), 0);
        let from_failed: Vec<_> = transitions_from(Some(Failed)).map(|t| t.id).collect();
        assert_eq!(from_failed, ["S90"]);
    }

    #[test]
    fn finalizing_cannot_be_paused_or_canceled() {
        assert!(!is_legal(Some(Finalizing), Paused));
        assert!(!is_legal(Some(Finalizing), Canceled));
        assert!(!JobState::Finalizing.can_cancel());
        assert!(!JobState::Verifying.can_pause());
        assert!(JobState::Verifying.can_cancel());
    }

    #[test]
    fn wrong_source_and_unknown_ids_are_rejected() {
        assert!(matches!(
            apply(Some(Queued), "S10", Engine),
            Err(TransitionError::WrongSource { .. })
        ));
        assert!(matches!(
            apply(Some(Queued), "S99", Engine),
            Err(TransitionError::Unknown(_))
        ));
        assert!(matches!(
            apply_edge(Some(Queued), Completed, Engine),
            Err(TransitionError::NoSuchEdge { .. })
        ));
        let err = apply(Some(Queued), "S10", Engine).unwrap_err();
        let env = err.to_envelope();
        assert_eq!(env.code.as_str(), "api.invalid_transition");
        assert_eq!(env.class, crate::error::ErrorClass::Conflict);
    }

    #[test]
    fn recovery_rows_cover_all_in_flight_states() {
        for state in JobState::ALL.into_iter().filter(|s| s.is_in_flight()) {
            assert!(apply(Some(state), "S95", System).is_ok());
            assert!(apply(Some(state), "S96", System).is_ok());
        }
        assert!(apply(Some(Queued), "S95", System).is_err());
    }

    #[test]
    fn state_names_round_trip() {
        for state in JobState::ALL {
            assert_eq!(state.as_str().parse::<JobState>().unwrap(), state);
            assert_eq!(
                serde_json::to_string(&state).unwrap(),
                format!("\"{}\"", state.as_str())
            );
        }
    }
}
