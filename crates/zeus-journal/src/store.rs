//! The backend-neutral journal store (03 section 3.3).
//!
//! `zeus-engine` and recovery depend only on these traits, so the redb backend can be replaced by any
//! store that provides atomic, durable, multi-row transactions (SQLite in WAL mode with
//! `synchronous=FULL`, or the in-memory simulation used by crash tests) without touching the engine.
//!
//! A transaction is the unit of atomicity: a job transition, the counters it changes and its events
//! commit together or not at all (invariant I9). Only `Durability::Immediate`-equivalent commits exist
//! at this level: a store MUST NOT offer a non-durable commit for range rows or state changes (03
//! section 5.4).

use zeus_control::RangeSet;
use zeus_types::{
    Approval, ApprovalId, ApprovalState, AuditHead, ByteRange, Event, EventPayload, EventSeq,
    GrantId, JobId, JobState, RunId, SessionGrant, Timestamp,
};

use crate::error::JournalResult;
use crate::records::{
    IdempotencyRow, InvalidationRow, JobRecord, Meta, RangeRow, ReservationRow, UnitCrcRow,
};

/// Selects jobs for [`ReadTxn::jobs`]. Job ids are ULIDs, so ascending id order is creation order and
/// `after` is a stable cursor.
#[derive(Debug, Clone, Default)]
pub struct JobFilter {
    /// Only these states; `None` for all.
    pub states: Option<Vec<JobState>>,
    /// Only jobs whose id is greater than this.
    pub after: Option<JobId>,
    /// At most this many rows (the API maximum is 100); `None` for no limit (recovery scans).
    pub limit: Option<usize>,
}

/// A read-only snapshot. Many may exist at once and they never block the writer.
pub trait ReadTxn {
    /// The `meta` row.
    fn meta(&self) -> JournalResult<Meta>;

    /// One job.
    fn job(&self, id: JobId) -> JournalResult<Option<JobRecord>>;

    /// Jobs matching `filter`, ascending by id.
    fn jobs(&self, filter: &JobFilter) -> JournalResult<Vec<JobRecord>>;

    /// The committed range set of a job.
    fn ranges(&self, job: JobId) -> JournalResult<RangeSet>;

    /// The committed range rows with their epochs.
    fn range_rows(&self, job: JobId) -> JournalResult<Vec<RangeRow>>;

    /// The last `limit` unit checksums of a job, ascending by offset (the tail check).
    fn tail_unit_crcs(&self, job: JobId, limit: usize) -> JournalResult<Vec<UnitCrcRow>>;

    /// Every unit checksum of a job, ascending by offset (the `full` re-check).
    fn all_unit_crcs(&self, job: JobId) -> JournalResult<Vec<UnitCrcRow>>;

    /// Durable events with `seq` greater than `after`, ascending, at most `limit`.
    fn events_since(&self, after: Option<EventSeq>, limit: usize) -> JournalResult<Vec<Event>>;

    /// The invalidation history of a job.
    fn invalidations(&self, job: JobId) -> JournalResult<Vec<InvalidationRow>>;

    /// One reservation by normalised path key.
    fn reservation(&self, path_key: &str) -> JournalResult<Option<ReservationRow>>;

    /// Every reservation (orphan cleanup in recovery step 7).
    fn reservations(&self) -> JournalResult<Vec<ReservationRow>>;

    /// One grant.
    fn grant(&self, id: GrantId) -> JournalResult<Option<SessionGrant>>;

    /// All grants.
    fn grants(&self) -> JournalResult<Vec<SessionGrant>>;

    /// One approval.
    fn approval(&self, id: ApprovalId) -> JournalResult<Option<Approval>>;

    /// Approvals in any of `states` (`None` for all), ascending by id.
    fn approvals(&self, states: Option<&[ApprovalState]>) -> JournalResult<Vec<Approval>>;

    /// The idempotency row of `(client_id, key)`.
    fn idempotency(&self, client_id: &str, key: &str) -> JournalResult<Option<IdempotencyRow>>;
}

/// The single write transaction. One at a time per store; everything it records becomes visible and
/// durable at [`WriteTxn::commit`], or not at all.
pub trait WriteTxn: ReadTxn {
    /// Inserts or replaces a job record.
    fn put_job(&mut self, record: &JobRecord) -> JournalResult<()>;

    /// Deletes a job record (tombstone expiry, 03 section 13).
    fn delete_job(&mut self, id: JobId) -> JournalResult<()>;

    /// Unions `[range)` into the job's committed set (coalescing, idempotent) under `epoch` and returns
    /// the number of newly covered bytes. The caller has already checked the epoch fence (I5).
    fn insert_range(&mut self, job: JobId, range: ByteRange, epoch: u32) -> JournalResult<u64>;

    /// Removes `range` (or everything, for `None`) from the committed set and returns the bytes
    /// dropped. Used only by invalidation, which also writes an [`InvalidationRow`] (I3).
    fn remove_ranges(&mut self, job: JobId, range: Option<ByteRange>) -> JournalResult<u64>;

    /// Inserts a unit checksum.
    fn put_unit_crc(&mut self, row: &UnitCrcRow) -> JournalResult<()>;

    /// Removes every unit checksum of a job.
    fn remove_unit_crcs(&mut self, job: JobId) -> JournalResult<()>;

    /// Appends an invalidation record.
    fn put_invalidation(&mut self, row: &InvalidationRow) -> JournalResult<()>;

    /// Takes a path reservation; fails with an invariant error when another job holds it.
    fn put_reservation(&mut self, row: &ReservationRow) -> JournalResult<()>;

    /// Releases a reservation.
    fn remove_reservation(&mut self, path_key: &str) -> JournalResult<()>;

    /// Appends a durable event: allocates the next `seq` (strictly increasing by one, never reused,
    /// invariant I9), stores it and updates `meta.last_event_seq`, all inside this transaction.
    /// Ephemeral payloads (`job.progress`) are rejected.
    fn append_event(
        &mut self,
        ts: Timestamp,
        job_id: Option<JobId>,
        run_id: Option<RunId>,
        payload: EventPayload,
    ) -> JournalResult<Event>;

    /// Deletes events with `seq` at or below `through` (retention), never above
    /// `min(audit_cursor, manifest_cursor)`.
    fn prune_events(&mut self, through: EventSeq) -> JournalResult<u64>;

    /// Inserts or replaces a grant.
    fn put_grant(&mut self, grant: &SessionGrant) -> JournalResult<()>;

    /// Inserts or replaces an approval.
    fn put_approval(&mut self, approval: &Approval) -> JournalResult<()>;

    /// Inserts an idempotency row.
    fn put_idempotency(&mut self, row: &IdempotencyRow) -> JournalResult<()>;

    /// Deletes idempotency rows past their `expires_at`; returns how many.
    fn expire_idempotency(&mut self, now: Timestamp) -> JournalResult<u64>;

    /// Updates the audit head in `meta`.
    fn set_audit_head(&mut self, head: Option<AuditHead>) -> JournalResult<()>;

    /// Advances the outbox cursors in `meta`; they never move backwards.
    fn set_cursors(&mut self, audit_cursor: u64, manifest_cursor: u64) -> JournalResult<()>;

    /// Commits durably. After `Ok`, everything is on stable storage. On `Err` the outcome may be
    /// ambiguous ([`crate::JournalError::CommitAmbiguous`]): the caller re-reads and reconciles.
    fn commit(self: Box<Self>) -> JournalResult<()>;

    /// Discards everything.
    fn rollback(self: Box<Self>) -> JournalResult<()>;
}

/// A store of journal records.
pub trait JournalStore: Send + Sync + 'static {
    /// Starts the single write transaction, waiting if another is open.
    fn begin_write(&self) -> JournalResult<Box<dyn WriteTxn + '_>>;

    /// Starts a read snapshot.
    fn begin_read(&self) -> JournalResult<Box<dyn ReadTxn + '_>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_filter_defaults_select_everything() {
        let f = JobFilter::default();
        assert!(f.states.is_none() && f.after.is_none() && f.limit.is_none());
    }

    /// The traits must stay object safe: the engine holds `Arc<dyn JournalStore>`.
    #[test]
    fn traits_are_object_safe() {
        fn takes_store(_: &dyn JournalStore) {}
        fn takes_read(_: &dyn ReadTxn) {}
        fn takes_write(_: &mut dyn WriteTxn) {}
        let _ = (takes_store, takes_read, takes_write);
    }
}
