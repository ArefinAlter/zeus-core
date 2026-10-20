//! Logical (JSON) form of the journal records (03 section 4, `journal.v1.schema.json`).
//!
//! Rows of the fixed-layout tables (`ranges`, `unit_crc`) are stored in a compact binary form by the
//! backend but must round-trip to these shapes.

use serde::{Deserialize, Serialize};
use zeus_types::{
    AuditHead, ByteRange, FileId, Hex256, Job, JobId, RangeSupport, StoreId, Timestamp, Validators,
};

/// The journal format version this build reads and writes (`meta.schema_version`).
pub const SCHEMA_VERSION: u32 = 1;

/// The value of the `meta` table, key `"store"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// Format version; a store with a larger value is refused (`journal.version_unsupported`).
    pub schema_version: u32,
    /// Identifies this store (a bare ULID).
    pub store_id: StoreId,
    /// Creation instant.
    pub created_at: Timestamp,
    /// For example `zeus-journal 0.1.0`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Durable emergency stop latch. New work is refused while engaged.
    #[serde(default, skip_serializing_if = "KillSwitchState::is_initial")]
    pub kill_switch: KillSwitchState,
    /// The newest durable event sequence (0 before the first event).
    pub last_event_seq: u64,
    /// Highest durable event already written to the audit log (outbox cursor).
    pub audit_cursor: u64,
    /// Highest durable event already reflected in provenance manifests (outbox cursor; never above
    /// `audit_cursor`).
    pub manifest_cursor: u64,
    /// Highest event registered in the shared artifact store.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub artifact_cursor: u64,
    /// The newest audit record, updated after each audit fsync.
    pub audit_head: Option<AuditHead>,
}

/// Persisted emergency-stop state (journal schema v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchState {
    /// A human must release the latch before work can run.
    pub engaged: bool,
    /// When this state last changed.
    pub changed_at: Timestamp,
}
impl Default for KillSwitchState {
    fn default() -> Self {
        Self {
            engaged: false,
            changed_at: Timestamp::UNIX_EPOCH,
        }
    }
}
impl KillSwitchState {
    fn is_initial(&self) -> bool {
        !self.engaged && self.changed_at == Timestamp::UNIX_EPOCH
    }
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}
impl Meta {
    /// Whether new work must be refused.
    #[must_use]
    pub fn kill_switch_engaged(&self) -> bool {
        self.kill_switch.engaged
    }
}

/// How much of the committed data is re-read on resume (`internal.resume_recheck`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeRecheck {
    /// Trust the journal.
    None,
    /// Re-read the last 16 commit units and compare CRC32C (default).
    #[default]
    Tail,
    /// Re-read every unit.
    Full,
}

/// Result of the verification pass (step F0), committed with S70.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyResult {
    /// Size of the data file.
    pub size_bytes: u64,
    /// SHA-256 computed from the bytes on disk.
    pub sha256: Hex256,
    /// BLAKE3 computed from the bytes on disk.
    pub blake3: Hex256,
    /// From magic bytes.
    #[serde(default)]
    pub detected_mime: Option<String>,
    /// When verification finished.
    pub verified_at: Timestamp,
    /// Modification time of the data file when hashed; with size and file id it lets recovery skip a
    /// re-hash (the fingerprint rule of 03 section 8.1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_ms: Option<u64>,
}

/// Which side of the rename a crash fell on is decided by this record (03 section 8.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinalizePhase {
    /// F3 committed: the rename may or may not have happened.
    Intent,
    /// The rename is known to have happened.
    Renamed,
}

/// The `finalize` member of [`JobInternal`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalizeState {
    /// Phase.
    pub phase: FinalizePhase,
    /// The data file.
    pub tmp_path: String,
    /// The destination.
    pub dest_path: String,
    /// Identity of the verified data file; the destination must have it after a rename.
    pub file_id: FileId,
    /// When the intent was committed.
    pub intent_at: Timestamp,
}

/// Engine-private state of a job; never exposed through any API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobInternal {
    /// First failure since committed progress, for the durable stall budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_no_progress_since: Option<Timestamp>,
    /// Consecutive response/code counters, cleared on meaningful committed progress.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub retry_counts: std::collections::BTreeMap<String, u32>,
    /// Sequence of the last durable creation or state-change event; zero for legacy records.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub last_state_seq: u64,
    /// Provenance marks actually applied to the completed file, not merely requested.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub os_metadata: Vec<zeus_types::OsMetadataKind>,
    /// Incremented on every entry to `probing`; a commit carrying another epoch is refused (I5).
    pub epoch: u32,
    /// The reserved final path.
    pub dest_path: String,
    /// `dest_path` plus `.zpart`.
    pub zpart_path: String,
    /// Identity of the data file once created (03 section 6 step 5); `None` before.
    pub zpart_file_id: Option<FileId>,
    /// Total size when known.
    pub total_bytes: Option<u64>,
    /// True once the committed ranges cover `[0, total_bytes)` (or EOF was reached for an unknown length).
    pub data_complete: bool,
    /// The size seen at EOF for an unknown length.
    #[serde(default)]
    pub eof_size: Option<u64>,
    /// Validators of the representation the committed ranges were fetched from.
    pub bound_validators: Validators,
    /// What the server was observed to support.
    pub range_support: RangeSupport,
    /// Resume re-check mode.
    #[serde(default)]
    pub resume_recheck: ResumeRecheck,
    /// Set by S70.
    #[serde(default)]
    pub verify_result: Option<VerifyResult>,
    /// Set from F3 until S80.
    #[serde(default)]
    pub finalize: Option<FinalizeState>,
    /// True when `spec.url` carries a query that is persisted verbatim (needed to resume).
    #[serde(default)]
    pub url_secret_stored: bool,
}

/// The value of the `jobs` table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobRecord {
    /// Record format version (1).
    pub schema: u32,
    /// The public entity (01 section 3.1).
    pub job: Job,
    /// Private engine state.
    pub internal: JobInternal,
}

impl JobRecord {
    /// A record at the current schema version.
    #[must_use]
    pub fn new(job: Job, internal: JobInternal) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            job,
            internal,
        }
    }

    /// Public summary with its durable state-event cursor.
    #[must_use]
    pub fn summary(&self) -> zeus_types::JobSummary {
        let mut summary = self.job.summary();
        summary.state_seq = zeus_types::EventSeq::new(self.internal.last_state_seq).ok();
        summary
    }

    /// The id of the job.
    #[must_use]
    pub fn id(&self) -> JobId {
        self.job.id
    }
}

/// A row of the `ranges` table: `[start, end)` committed under `epoch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeRow {
    /// The job.
    pub job_id: JobId,
    /// First byte.
    pub start: u64,
    /// One past the last byte.
    pub end: u64,
    /// The epoch of the attempt that produced it.
    pub epoch: u32,
}

impl RangeRow {
    /// The interval.
    pub fn range(&self) -> Result<ByteRange, zeus_types::TypesError> {
        ByteRange::new(self.start, self.end)
    }
}

/// A row of the `unit_crc` table: the checksum of one commit unit, never coalesced, used by the tail
/// check of resume validation (03 section 7.2 check L4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnitCrcRow {
    /// The job.
    pub job_id: JobId,
    /// File offset of the unit.
    pub offset: u64,
    /// Length of the unit in bytes (at least 1).
    pub length: u32,
    /// CRC32C of the unit's bytes.
    pub crc32c: u32,
}

/// Why a range set shrank (`invalidations` table, invariant I3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvalidationReason {
    /// The validators or total changed upstream.
    ValidatorChanged,
    /// The server turned out not to support ranges.
    RangeUnsupported,
    /// A hash or size mismatch restarts the download.
    IntegrityRestart,
    /// The data file was replaced.
    FileReplaced,
    /// The data file was truncated.
    FileTruncated,
    /// The tail check failed.
    TailCheckFailed,
    /// The overlap check failed.
    OverlapCheckFailed,
    /// A person asked for a restart.
    UserRequest,
}

/// A row of the `invalidations` table: an append-only record of every shrink of a range set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationRow {
    /// The job.
    pub job_id: JobId,
    /// When.
    pub at: Timestamp,
    /// The epoch in force.
    pub epoch: u32,
    /// Why.
    pub reason: InvalidationReason,
    /// Bytes dropped from the committed set.
    pub dropped_bytes: u64,
}

/// A row of the `reservations` table: guarantees two jobs never target one final path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservationRow {
    /// The normalised path, case-folded on case-insensitive file systems.
    pub path_key: String,
    /// The owner.
    pub job_id: JobId,
    /// When it was taken.
    pub created_at: Timestamp,
}

/// A row of the `idempotency` table (00 section 5.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdempotencyRow {
    /// The authenticated client.
    pub client_id: String,
    /// The client's key (1 to 128 characters).
    pub key: String,
    /// BLAKE3 of the JCS form of the request parameters without the key.
    pub request_hash: Hex256,
    /// The job the first request created.
    pub job_id: JobId,
    /// Method bound to a generic API mutation, absent for legacy enqueue records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Exact durable response of a generic API mutation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// When the row was created.
    pub created_at: Timestamp,
    /// Retention end (at least 24 hours after creation).
    pub expires_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        assert_eq!(ResumeRecheck::default(), ResumeRecheck::Tail);
        assert_eq!(SCHEMA_VERSION, 1);
    }
}
