//! The event catalogue (01 section 9).
//!
//! An [`Event`] is `{seq | after_seq, ts, type, job_id?, run_id?, data}`. **Durable** events carry
//! `seq` and are stored in the journal inside the transaction that records the state change they
//! describe; **ephemeral** events (only `job.progress`) carry `after_seq` and are live only.
//! Consumers MUST ignore unknown event types and unknown fields: an unknown `type` deserialises
//! to [`EventPayload::Unknown`] instead of failing.

use schemars::JsonSchema;
use serde::de::{self, Deserializer};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::error::{ErrorEnvelope, TypesError};
use crate::grant::{Actor, Approval, ApprovalKind, DecisionOutcome, GrantScope, SessionGrant};
use crate::ids::EventSeq;
use crate::ids::{ApprovalId, GrantId, JobId, RunId, SessionLeaseId};
use crate::job::{Priority, ProbeResult, Progress, QuarantineReason, Source};
use crate::limits::MAX_EVENT_DATA_BYTES;
use crate::origin::{Origin, RedactedUrl};
use crate::state::{JobState, StateCause, TransitionId};
use crate::timestamp::Timestamp;
use crate::units::Hex256;

/// What `job.state_changed` and friends say about why session material is needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RefreshNeed {
    /// New cookies and headers.
    Session,
    /// A fresh signed URL.
    Url,
    /// The in-browser fetch proxy.
    Proxy,
}

/// Why session material is needed (`session.refresh_needed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RefreshReason {
    /// First use of a grant.
    FirstUse,
    /// The server rejected the session.
    AuthExpired,
    /// The signed URL expired.
    UrlExpired,
    /// The server blocked the engine.
    Blocked,
    /// The lease time to live ended.
    LeaseExpired,
    /// The extension connection was lost.
    ExtensionDisconnected,
}

/// Why a lease was requested (`session.leased`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LeasePurpose {
    /// Bytes will be downloaded with it.
    Download,
    /// A probe.
    Probe,
    /// A URL or session refresh.
    Refresh,
}

/// Advice for agents on what to do after a failure. Never an automatic action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SuggestedAction {
    /// Retry the job.
    Retry,
    /// Ask a human to approve.
    Approve,
    /// Request a session.
    RequestSession,
    /// Open the URL in the browser.
    OpenInBrowser,
    /// Free disk space.
    FreeDiskSpace,
    /// Fix the destination.
    FixDestination,
    /// Check the URL.
    CheckUrl,
    /// Nothing to do.
    None,
}

/// `job.failed.suggested_next`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SuggestedNext {
    /// The advised action.
    pub action: SuggestedAction,
    /// A Zeus MCP tool name such as `zeus_control`, or `null`.
    #[serde(default)]
    pub tool: Option<String>,
}

/// Why the daemon stops (`daemon.stopping`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// `daemon.shutdown` was called.
    UserRequest,
    /// SIGTERM, console close.
    Signal,
    /// An upgrade restarts the daemon.
    Upgrade,
    /// An unrecoverable error.
    FatalError,
}

/// Startup recovery summary (`daemon.started.recovery`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RecoverySummary {
    /// Jobs moved back to `queued`.
    pub jobs_recovered: u32,
    /// Jobs failed as a crash loop.
    pub jobs_failed: u32,
    /// `.zpart` files no job owns.
    pub orphans_found: u32,
    /// Whether the audit chain tail verified.
    pub audit_chain_ok: bool,
}

/// `job.created`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobCreatedData {
    /// Who asked.
    pub source: Source,
    /// `queued` or `awaiting_approval`.
    pub state: JobState,
    /// The URL after `redact_url(log)`.
    pub url_redacted: RedactedUrl,
    /// File name hint (untrusted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename_hint: Option<String>,
    /// Origin of the URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    /// Origin whose session the job needs.
    #[serde(default)]
    pub session_origin: Option<Origin>,
    /// Effective priority.
    pub priority: Priority,
}

/// `job.state_changed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobStateChangedData {
    /// Previous state.
    pub from: JobState,
    /// New state.
    pub to: JobState,
    /// The transition id from the table.
    pub transition: TransitionId,
    /// Why.
    pub cause: StateCause,
    /// Who.
    pub actor: Actor,
}

/// `job.probed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobProbedData {
    /// The probe result.
    pub probe: ProbeResult,
}

/// `job.progress` (ephemeral).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobProgressData {
    /// Committed-byte progress.
    pub progress: Progress,
}

/// `job.throttled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobThrottledData {
    /// Host that throttled.
    pub host: String,
    /// HTTP status, when the signal was a status.
    #[serde(default)]
    pub status: Option<u16>,
    /// `Retry-After` in milliseconds.
    #[serde(default)]
    pub retry_after_ms: Option<u64>,
    /// Connections to the host before.
    pub concurrency_before: u32,
    /// Connections to the host after.
    pub concurrency_after: u32,
}

/// `job.retry_scheduled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobRetryScheduledData {
    /// Which retry this is (1 for the first).
    pub attempt: u32,
    /// The error that caused it.
    pub error: ErrorEnvelope,
    /// Backoff delay.
    pub delay_ms: u64,
    /// When the retry fires.
    pub next_attempt_at: Timestamp,
    /// The restart invalidated every committed range.
    #[serde(default)]
    pub restart_from_zero: bool,
}

/// `session.refresh_needed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionRefreshNeededData {
    /// The origin concerned.
    pub origin: Origin,
    /// What is needed.
    pub need: RefreshNeed,
    /// Why.
    pub reason: RefreshReason,
    /// Which attempt (1 for the first).
    pub attempt: u32,
    /// When the wait gives up.
    pub deadline_at: Timestamp,
}

/// `session.leased`. Carries counts and handles only: never a cookie name or value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionLeasedData {
    /// The lease handle.
    pub lease_id: SessionLeaseId,
    /// The grant it was issued under.
    pub grant_id: GrantId,
    /// The origin.
    pub origin: Origin,
    /// Why it was requested.
    pub purpose: LeasePurpose,
    /// How many cookies it contains.
    pub cookie_count: u32,
    /// Time to live.
    pub ttl_ms: u64,
}

/// `grant.created`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GrantCreatedData {
    /// The new grant.
    pub grant: SessionGrant,
}

/// `grant.revoked`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GrantRevokedData {
    /// The grant.
    pub grant_id: GrantId,
    /// Its origin.
    pub origin: Origin,
    /// Who revoked it.
    pub by: Actor,
}

/// `grant.expired`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct GrantExpiredData {
    /// The grant.
    pub grant_id: GrantId,
    /// Its origin.
    pub origin: Origin,
}

/// `approval.requested`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalRequestedData {
    /// The approval, with daemon-computed facts.
    pub approval: Approval,
}

/// `approval.decided`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalDecidedData {
    /// The approval.
    pub approval_id: ApprovalId,
    /// Its kind.
    pub kind: ApprovalKind,
    /// The outcome.
    pub outcome: DecisionOutcome,
    /// The scope chosen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<GrantScope>,
    /// Who decided.
    pub actor: Actor,
    /// The grant created, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<GrantId>,
}

/// `job.verified`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobVerifiedData {
    /// Size of the verified file.
    pub size_bytes: u64,
    /// SHA-256.
    pub sha256: Hex256,
    /// BLAKE3.
    pub blake3: Hex256,
    /// From magic bytes.
    #[serde(default)]
    pub detected_mime: Option<String>,
    /// From `Content-Type`.
    #[serde(default)]
    pub declared_mime: Option<String>,
    /// Whether the two agree, when both are known.
    #[serde(default)]
    pub mime_match: Option<bool>,
    /// Whether `expected_sha256` matched; `null` when none was given.
    pub expected_sha256_match: Option<bool>,
    /// Whether `expected_size` matched; `null` when none was given.
    pub expected_size_match: Option<bool>,
}

/// `job.quarantined`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobQuarantinedData {
    /// Which rules fired (at least one).
    pub reasons: Vec<QuarantineReason>,
}

/// `job.completed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobCompletedData {
    /// Absolute final path.
    pub path: String,
    /// Size.
    pub size_bytes: u64,
    /// SHA-256.
    pub sha256: Hex256,
    /// BLAKE3.
    pub blake3: Hex256,
    /// Quarantine flag.
    pub quarantined: bool,
    /// Wall time from creation to completion.
    pub duration_ms: u64,
}

/// `job.failed`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobFailedData {
    /// The error.
    pub error: ErrorEnvelope,
    /// Advice for agents.
    pub suggested_next: SuggestedNext,
}

/// `daemon.started`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DaemonStartedData {
    /// Daemon version (semver).
    pub version: String,
    /// 32 lowercase hex characters, new on every start.
    pub instance_id: String,
    /// What recovery did.
    pub recovery: RecoverySummary,
}

/// `daemon.stopping`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DaemonStoppingData {
    /// Why.
    pub reason: StopReason,
}

macro_rules! event_catalogue {
    ($( $variant:ident($data:ty) = $name:literal, durable: $durable:literal, job_id: $job:literal; )*) => {
        /// The closed set of event names (01 section 9.1).
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum EventKind {
            $( #[doc = concat!("`", $name, "`.")] $variant, )*
        }

        impl EventKind {
            /// Every event name, in catalogue order.
            pub const ALL: &'static [Self] = &[ $( Self::$variant, )* ];

            /// The wire name, for example `job.state_changed`.
            #[must_use]
            pub const fn name(self) -> &'static str {
                match self { $( Self::$variant => $name, )* }
            }

            /// Looks a wire name up.
            #[must_use]
            pub fn from_name(name: &str) -> Option<Self> {
                match name { $( $name => Some(Self::$variant), )* _ => None }
            }

            /// True for events stored in the journal with a `seq`; false for `job.progress`.
            #[must_use]
            pub const fn is_durable(self) -> bool {
                match self { $( Self::$variant => $durable, )* }
            }

            /// True when the event must carry a `job_id`.
            #[must_use]
            pub const fn requires_job_id(self) -> bool {
                match self { $( Self::$variant => $job, )* }
            }
        }

        impl std::fmt::Display for EventKind {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.name())
            }
        }

        /// The typed `data` of an event.
        #[derive(Debug, Clone, PartialEq, Eq)]
        #[non_exhaustive]
        pub enum EventPayload {
            $( #[doc = concat!("`", $name, "`.")] $variant($data), )*
            /// An event type this build does not know. Preserved so it can be forwarded or logged.
            Unknown {
                /// The `type` string as received.
                kind: String,
                /// The `data` object as received.
                data: Map<String, Value>,
            },
        }

        impl EventPayload {
            /// The event kind, or `None` for [`EventPayload::Unknown`].
            #[must_use]
            pub fn kind(&self) -> Option<EventKind> {
                match self { $( Self::$variant(_) => Some(EventKind::$variant), )* Self::Unknown { .. } => None }
            }

            /// The wire `type` string.
            #[must_use]
            pub fn type_name(&self) -> &str {
                match self { $( Self::$variant(_) => $name, )* Self::Unknown { kind, .. } => kind }
            }

            fn to_parts(&self) -> Result<(String, Value), serde_json::Error> {
                Ok(match self {
                    $( Self::$variant(d) => ($name.to_owned(), serde_json::to_value(d)?), )*
                    Self::Unknown { kind, data } => (kind.clone(), Value::Object(data.clone())),
                })
            }

            fn from_parts(kind: &str, data: Value) -> Result<Self, serde_json::Error> {
                Ok(match kind {
                    $( $name => Self::$variant(serde_json::from_value(data)?), )*
                    other => match data {
                        Value::Object(map) => Self::Unknown { kind: other.to_owned(), data: map },
                        _ => return Err(<serde_json::Error as de::Error>::custom("event data must be an object")),
                    },
                })
            }
        }

        $(
            impl From<$data> for EventPayload {
                fn from(data: $data) -> Self { Self::$variant(data) }
            }
        )*
    };
}

event_catalogue! {
    JobCreated(JobCreatedData) = "job.created", durable: true, job_id: true;
    JobStateChanged(JobStateChangedData) = "job.state_changed", durable: true, job_id: true;
    JobProbed(JobProbedData) = "job.probed", durable: true, job_id: true;
    JobProgress(JobProgressData) = "job.progress", durable: false, job_id: true;
    JobThrottled(JobThrottledData) = "job.throttled", durable: true, job_id: true;
    JobRetryScheduled(JobRetryScheduledData) = "job.retry_scheduled", durable: true, job_id: true;
    SessionRefreshNeeded(SessionRefreshNeededData) = "session.refresh_needed", durable: true, job_id: true;
    SessionLeased(SessionLeasedData) = "session.leased", durable: true, job_id: true;
    GrantCreated(GrantCreatedData) = "grant.created", durable: true, job_id: false;
    GrantRevoked(GrantRevokedData) = "grant.revoked", durable: true, job_id: false;
    GrantExpired(GrantExpiredData) = "grant.expired", durable: true, job_id: false;
    ApprovalRequested(ApprovalRequestedData) = "approval.requested", durable: true, job_id: false;
    ApprovalDecided(ApprovalDecidedData) = "approval.decided", durable: true, job_id: false;
    JobVerified(JobVerifiedData) = "job.verified", durable: true, job_id: true;
    JobQuarantined(JobQuarantinedData) = "job.quarantined", durable: true, job_id: true;
    JobCompleted(JobCompletedData) = "job.completed", durable: true, job_id: true;
    JobFailed(JobFailedData) = "job.failed", durable: true, job_id: true;
    DaemonStarted(DaemonStartedData) = "daemon.started", durable: true, job_id: false;
    DaemonStopping(DaemonStoppingData) = "daemon.stopping", durable: true, job_id: false;
}

/// An event: the envelope plus a typed payload.
///
/// Exactly one of `seq` (durable) and `after_seq` (ephemeral) is set; the constructors enforce it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// Position in the durable log; `None` for ephemeral events.
    pub seq: Option<EventSeq>,
    /// For ephemeral events: the last durable sequence allocated when the event was emitted.
    pub after_seq: Option<u64>,
    /// Wall-clock time (informational: `seq` is the order of record).
    pub ts: Timestamp,
    /// The job concerned.
    pub job_id: Option<JobId>,
    /// The run concerned.
    pub run_id: Option<RunId>,
    /// The typed payload.
    pub payload: EventPayload,
}

impl Event {
    /// A durable event with the sequence number the journal allocated.
    #[must_use]
    pub fn durable(seq: EventSeq, ts: Timestamp, payload: impl Into<EventPayload>) -> Self {
        Self {
            seq: Some(seq),
            after_seq: None,
            ts,
            job_id: None,
            run_id: None,
            payload: payload.into(),
        }
    }

    /// An ephemeral event, stamped with the last durable sequence at emission.
    #[must_use]
    pub fn ephemeral(after_seq: u64, ts: Timestamp, payload: impl Into<EventPayload>) -> Self {
        Self {
            seq: None,
            after_seq: Some(after_seq),
            ts,
            job_id: None,
            run_id: None,
            payload: payload.into(),
        }
    }

    /// Sets the job.
    #[must_use]
    pub fn with_job(mut self, job_id: JobId) -> Self {
        self.job_id = Some(job_id);
        self
    }

    /// Sets the run.
    #[must_use]
    pub fn with_run(mut self, run_id: RunId) -> Self {
        self.run_id = Some(run_id);
        self
    }

    /// True for events stored in the journal.
    #[must_use]
    pub fn is_durable(&self) -> bool {
        self.seq.is_some()
    }

    /// Checks the rules of the catalogue: durability matches the kind, `job_id` is present where
    /// required, and `data` is at most 64 KiB serialised.
    pub fn validate(&self) -> Result<(), TypesError> {
        match (self.seq, self.after_seq) {
            (Some(_), None) | (None, Some(_)) => {}
            _ => {
                return Err(TypesError::Invalid(
                    "exactly one of seq and after_seq must be set",
                ));
            }
        }
        if let Some(kind) = self.payload.kind() {
            if kind.is_durable() != self.seq.is_some() {
                return Err(TypesError::Invalid(
                    "durability does not match the event kind",
                ));
            }
            if kind.requires_job_id() && self.job_id.is_none() {
                return Err(TypesError::Invalid("event requires a job_id"));
            }
        }
        let (_, data) = self
            .payload
            .to_parts()
            .map_err(|_| TypesError::Invalid("event data is not serialisable"))?;
        if serde_json::to_vec(&data).map_or(true, |v| v.len() > MAX_EVENT_DATA_BYTES) {
            return Err(TypesError::Invalid("event data larger than 64 KiB"));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct RawEvent {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seq: Option<EventSeq>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    after_seq: Option<u64>,
    ts: Timestamp,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    job_id: Option<JobId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    run_id: Option<RunId>,
    data: Value,
}

impl Serialize for Event {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (kind, data) = self.payload.to_parts().map_err(serde::ser::Error::custom)?;
        RawEvent {
            seq: self.seq,
            after_seq: self.after_seq,
            ts: self.ts,
            kind,
            job_id: self.job_id,
            run_id: self.run_id,
            data,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Event {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawEvent::deserialize(deserializer)?;
        let payload = EventPayload::from_parts(&raw.kind, raw.data).map_err(de::Error::custom)?;
        let event = Self {
            seq: raw.seq,
            after_seq: raw.after_seq,
            ts: raw.ts,
            job_id: raw.job_id,
            run_id: raw.run_id,
            payload,
        };
        // An unknown kind cannot be checked against the catalogue; everything else must conform.
        event.validate().map_err(de::Error::custom)?;
        Ok(event)
    }
}

impl JsonSchema for Event {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Event".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        // The typed payloads are generated as separate definitions so consumers can reference them.
        let _ = generator.subschema_for::<JobCreatedData>();
        let _ = generator.subschema_for::<JobStateChangedData>();
        let _ = generator.subschema_for::<JobProbedData>();
        let _ = generator.subschema_for::<JobProgressData>();
        let _ = generator.subschema_for::<JobThrottledData>();
        let _ = generator.subschema_for::<JobRetryScheduledData>();
        let _ = generator.subschema_for::<SessionRefreshNeededData>();
        let _ = generator.subschema_for::<SessionLeasedData>();
        let _ = generator.subschema_for::<GrantCreatedData>();
        let _ = generator.subschema_for::<GrantRevokedData>();
        let _ = generator.subschema_for::<GrantExpiredData>();
        let _ = generator.subschema_for::<ApprovalRequestedData>();
        let _ = generator.subschema_for::<ApprovalDecidedData>();
        let _ = generator.subschema_for::<JobVerifiedData>();
        let _ = generator.subschema_for::<JobQuarantinedData>();
        let _ = generator.subschema_for::<JobCompletedData>();
        let _ = generator.subschema_for::<JobFailedData>();
        let _ = generator.subschema_for::<DaemonStartedData>();
        let _ = generator.subschema_for::<DaemonStoppingData>();
        schemars::json_schema!({
            "type": "object",
            "required": ["ts", "type", "data"],
            "properties": {
                "seq": generator.subschema_for::<EventSeq>(),
                "after_seq": { "type": "integer", "minimum": 0 },
                "ts": generator.subschema_for::<Timestamp>(),
                "type": { "type": "string" },
                "job_id": generator.subschema_for::<JobId>(),
                "run_id": generator.subschema_for::<RunId>(),
                "data": { "type": "object" }
            },
            "oneOf": [{ "required": ["seq"] }, { "required": ["after_seq"] }]
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalogue_matches_the_state_machine_file_order() {
        let names: Vec<_> = EventKind::ALL.iter().map(|k| k.name()).collect();
        assert_eq!(
            names,
            [
                "job.created",
                "job.state_changed",
                "job.probed",
                "job.progress",
                "job.throttled",
                "job.retry_scheduled",
                "session.refresh_needed",
                "session.leased",
                "grant.created",
                "grant.revoked",
                "grant.expired",
                "approval.requested",
                "approval.decided",
                "job.verified",
                "job.quarantined",
                "job.completed",
                "job.failed",
                "daemon.started",
                "daemon.stopping",
            ]
        );
        for kind in EventKind::ALL {
            assert_eq!(EventKind::from_name(kind.name()), Some(*kind));
        }
        assert!(!EventKind::JobProgress.is_durable());
        assert_eq!(EventKind::ALL.iter().filter(|k| !k.is_durable()).count(), 1);
    }

    #[test]
    fn unknown_types_survive_a_round_trip() {
        let text =
            r#"{"seq":5,"ts":"2026-10-05T09:15:30.250Z","type":"future.thing","data":{"x":1}}"#;
        let ev: Event = serde_json::from_str(text).unwrap();
        assert!(
            matches!(&ev.payload, EventPayload::Unknown { kind, .. } if kind == "future.thing")
        );
        assert_eq!(
            serde_json::to_value(&ev).unwrap(),
            serde_json::from_str::<Value>(text).unwrap()
        );
    }

    #[test]
    fn durability_and_job_id_rules() {
        let ts = Timestamp::UNIX_EPOCH;
        let stopping = DaemonStoppingData {
            reason: StopReason::Signal,
        };
        assert!(
            Event::durable(EventSeq::FIRST, ts, stopping.clone())
                .validate()
                .is_ok()
        );
        assert!(
            Event::ephemeral(0, ts, stopping).validate().is_err(),
            "daemon.stopping is durable"
        );
        let progress = JobProgressData {
            progress: Progress::new(ts),
        };
        assert!(
            Event::ephemeral(0, ts, progress.clone())
                .validate()
                .is_err(),
            "job.progress needs a job_id"
        );
        let job = crate::ids::IdGenerator::new().job_id();
        assert!(
            Event::ephemeral(7, ts, progress.clone())
                .with_job(job)
                .validate()
                .is_ok()
        );
        assert!(
            Event::durable(EventSeq::FIRST, ts, progress)
                .with_job(job)
                .validate()
                .is_err()
        );
    }

    #[test]
    fn rejects_both_or_neither_stamp() {
        let text = r#"{"ts":"2026-10-05T09:15:30.250Z","type":"daemon.stopping","data":{"reason":"signal"}}"#;
        assert!(serde_json::from_str::<Event>(text).is_err());
        let both = r#"{"seq":1,"after_seq":1,"ts":"2026-10-05T09:15:30.250Z","type":"daemon.stopping","data":{"reason":"signal"}}"#;
        assert!(serde_json::from_str::<Event>(both).is_err());
    }

    #[test]
    fn known_type_with_bad_data_is_an_error() {
        let text = r#"{"seq":1,"ts":"2026-10-05T09:15:30.250Z","type":"daemon.stopping","data":{"reason":"because"}}"#;
        assert!(serde_json::from_str::<Event>(text).is_err());
    }
}
