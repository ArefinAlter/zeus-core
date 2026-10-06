//! Zeus wire and domain types.
//!
//! This crate is the Rust form of the normative contracts in `docs/spec` of the `zeus` repository
//! (documents 00 to 04 and their JSON Schemas). Everything that crosses a process boundary or is
//! stored lives here: identifiers, instants, origins and URLs (with redaction), the job entity and
//! its state machine, error classes and codes, grants and approvals, and the event catalogue.
//!
//! Design rules, from 00 conventions:
//!
//! * `snake_case` keys and enum values; receivers ignore unknown keys (no `deny_unknown_fields`).
//! * Byte counts and offsets are `u64` bounded by 2^53 - 1 so every JSON implementation reads them.
//! * Raw URLs and session material are wrapped ([`HttpUrl`], [`SecretString`]) so `Debug` and
//!   `Display` can never print a secret; [`redact_url`] is the only sanctioned way to show a URL.
//! * The job state machine is table-driven ([`state::TRANSITIONS`]) and validated by
//!   [`state::apply`]; a copy of the normative JSON table is checked in the conformance tests.
//!
//! The crate has no I/O and no async code.

#![forbid(unsafe_code)]

pub mod error;
pub mod event;
pub mod grant;
pub mod ids;
pub mod job;
pub mod limits;
pub mod origin;
pub mod policy;
pub mod redact;
pub mod schema;
pub mod secret;
pub mod segment;
#[cfg(feature = "spec-testing")]
pub mod spec_testing;
pub mod state;
pub mod storage;
pub mod timestamp;
pub mod units;

pub use error::{CodeInfo, ErrorClass, ErrorCode, ErrorEnvelope, ToEnvelope, TypesError, codes};
pub use event::{Event, EventKind, EventPayload};
pub use grant::{
    Actor, ActorKind, Approval, ApprovalKind, ApprovalState, ApprovalSummary, Decision,
    DecisionOutcome, GrantResolution, GrantScope, GrantState, SessionGrant, Surface, resolve_grant,
};
pub use ids::{
    ApprovalId, ChainId, ConnectionId, EventSeq, GrantId, IdGenerator, JobId, RunId,
    SessionLeaseId, StoreId,
};
pub use job::{
    BrowserInfo, BrowserName, Job, JobResult, JobSpec, JobSummary, Overwrite, Priority,
    ProbeMethod, ProbeResult, Progress, QuarantineReason, RangeSupport, ResolvedFilename,
    RetryState, Source, SourceKind, SourceVia, Transport, TransportHint, Validators,
};
pub use origin::{HttpUrl, Origin, RedactedUrl};
pub use redact::{RedactMode, Redacted, redact_url};
pub use secret::SecretString;
pub use segment::{Segment, SegmentState};
pub use state::{JobState, StateCause, TransitionActor, TransitionDef, TransitionError};
pub use storage::{AuditHead, FileId, OsMetadataKind, OsMetadataMode};
pub use timestamp::Timestamp;
pub use units::{ByteRange, Hex256};
