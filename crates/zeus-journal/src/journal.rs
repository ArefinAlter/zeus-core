//! The journal facade the engine uses.
//!
//! [`Journal`] wraps an `Arc<dyn JournalStore>` with the operations of the commit protocol: atomic
//! transactions, job creation, committed-range queries, and the multi-row operations that must be one
//! transaction (a commit round, a state transition with its events, an invalidation, finalization).
#![expect(
    unused_variables,
    reason = "skeleton: the multi-row protocol operations are filled in by the zeus-journal implementation task"
)]

use std::path::Path;
use std::sync::Arc;

use zeus_control::{RangeSet, SharedClock};
use zeus_types::{
    Actor, ByteRange, Event, EventPayload, JobId, JobState, StateCause, Timestamp, TransitionActor,
};

use crate::commit::{CommitPolicy, CommitUnit, RoundOutcome};
use crate::error::{JournalError, JournalResult};
use crate::fault::{FaultInjector, NoFaults};
use crate::records::{InvalidationReason, JobRecord, Meta, ReservationRow};
use crate::redb_store::RedbStore;
use crate::store::{JobFilter, JournalStore, ReadTxn, WriteTxn};

/// Options for opening a journal file.
#[derive(Debug, Clone, Default)]
pub struct JournalOptions {
    /// Committer tuning.
    pub commit: CommitPolicy,
    /// redb `set_quick_repair(true)`: near-instant recovery after an unclean shutdown at the cost of
    /// slower commits (03 section 3.3, open issue O2). Default false.
    pub quick_repair: bool,
    /// redb `set_two_phase_commit(true)`: an extra `fsync` per commit for hardware with unreliable
    /// ordering. Default false.
    pub two_phase_commit: bool,
}

/// One job transition to apply atomically (01 section 6 rule 2).
#[derive(Debug, Clone)]
pub struct TransitionRequest {
    /// The job.
    pub job_id: JobId,
    /// The transition id from the table, for example `S10`.
    pub transition: &'static str,
    /// Who may trigger it according to the table.
    pub trigger: TransitionActor,
    /// The cause recorded in `job.state_changed`.
    pub cause: StateCause,
    /// The actor recorded in `job.state_changed`.
    pub actor: Actor,
    /// Wall-clock time of the transition.
    pub now: Timestamp,
    /// Events emitted **before** `job.state_changed`, in table order (for example `job.probed`).
    pub events_before: Vec<EventPayload>,
    /// Events emitted **after** `job.state_changed`, in table order (for example `job.retry_scheduled`).
    pub events_after: Vec<EventPayload>,
}

/// What a transition did.
#[derive(Debug, Clone)]
pub struct TransitionOutcome {
    /// The stored record after the transition.
    pub record: JobRecord,
    /// The events appended, in order, with their sequence numbers.
    pub events: Vec<Event>,
}

/// The journal.
#[derive(Clone)]
pub struct Journal {
    store: Arc<dyn JournalStore>,
    clock: SharedClock,
    faults: Arc<dyn FaultInjector>,
}

impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal").finish_non_exhaustive()
    }
}

impl Journal {
    /// A journal over any store (the redb store, or an in-memory one in tests).
    #[must_use]
    pub fn new(store: Arc<dyn JournalStore>, clock: SharedClock) -> Self {
        Self {
            store,
            clock,
            faults: Arc::new(NoFaults),
        }
    }

    /// Replaces the fault injector (tests only).
    #[must_use]
    pub fn with_faults(mut self, faults: Arc<dyn FaultInjector>) -> Self {
        self.faults = faults;
        self
    }

    /// Opens or creates the redb journal at `path` (`<state>/zeus.redb`), migrating forward if its
    /// schema is older and refusing a newer one.
    pub fn open(path: &Path, options: &JournalOptions, clock: SharedClock) -> JournalResult<Self> {
        let store = RedbStore::open(path, options)?;
        Ok(Self::new(Arc::new(store), clock))
    }

    /// The underlying store.
    #[must_use]
    pub fn store(&self) -> &Arc<dyn JournalStore> {
        &self.store
    }

    /// The injected clock.
    #[must_use]
    pub fn clock(&self) -> &SharedClock {
        &self.clock
    }

    /// The fault injector.
    #[must_use]
    pub fn faults(&self) -> &Arc<dyn FaultInjector> {
        &self.faults
    }

    /// Runs `f` in a read snapshot.
    pub fn read<R>(&self, f: impl FnOnce(&dyn ReadTxn) -> JournalResult<R>) -> JournalResult<R> {
        let txn = self.store.begin_read()?;
        f(txn.as_ref())
    }

    /// Runs `f` in the write transaction: commits durably when it returns `Ok`, rolls back when it
    /// returns `Err`. Blocking: call it from a blocking thread.
    pub fn transact<R>(
        &self,
        f: impl FnOnce(&mut dyn WriteTxn) -> JournalResult<R>,
    ) -> JournalResult<R> {
        let mut txn = self.store.begin_write()?;
        match f(txn.as_mut()) {
            Ok(value) => {
                txn.commit()?;
                Ok(value)
            }
            Err(e) => {
                // A failed rollback must not mask the original error.
                let _ = txn.rollback();
                Err(e)
            }
        }
    }

    /// The `meta` row.
    pub fn meta(&self) -> JournalResult<Meta> {
        self.read(|txn| txn.meta())
    }

    /// One job.
    pub fn job(&self, id: JobId) -> JournalResult<Option<JobRecord>> {
        self.read(|txn| txn.job(id))
    }

    /// The committed range set of a job: the only evidence of what is on disk (invariant I2).
    pub fn committed(&self, job: JobId) -> JournalResult<RangeSet> {
        self.read(|txn| txn.ranges(job))
    }

    /// Jobs that are not in a terminal state (`completed`, `canceled`), ascending by id: what recovery
    /// and the scheduler need after a restart.
    pub fn list_incomplete(&self) -> JournalResult<Vec<JobRecord>> {
        self.read(|txn| {
            let all = txn.jobs(&JobFilter::default())?;
            Ok(all
                .into_iter()
                .filter(|r| !r.job.state.is_terminal())
                .collect())
        })
    }

    /// Stores a new job (state `queued` or `awaiting_approval`), takes its path reservation if given,
    /// and appends its creation events, all in one transaction. Returns the appended events.
    pub fn create_job(
        &self,
        record: &JobRecord,
        reservation: Option<&ReservationRow>,
        events: Vec<(Option<JobId>, EventPayload)>,
    ) -> JournalResult<Vec<Event>> {
        if !matches!(
            record.job.state,
            JobState::Queued | JobState::AwaitingApproval
        ) {
            return Err(JournalError::Invariant(
                "a new job starts in queued or awaiting_approval",
            ));
        }
        let now = self.clock.now();
        self.transact(|txn| {
            txn.put_job(record)?;
            if let Some(r) = reservation {
                txn.put_reservation(r)?;
            }
            events
                .into_iter()
                .map(|(job, payload)| txn.append_event(now, job, None, payload))
                .collect()
        })
    }

    /// One committer round (03 section 5.2, steps C3 and C4): in one `Durability::Immediate`
    /// transaction, for every unit whose epoch matches and whose job is `downloading`, insert the range
    /// and its checksum, update `bytes_done`, `updated_at` and `last_progress_at`; when a job's set now
    /// covers the resource, perform S20 in the same transaction; append every event of the round.
    /// Units failing the epoch fence are returned in `discarded` and never committed (I5).
    ///
    /// The caller has already run `sync_data` on every touched data file (step C2); this method never
    /// does, and a `commit` error is ambiguous ([`JournalError::CommitAmbiguous`]).
    pub fn commit_round(
        &self,
        units: &[CommitUnit],
        now: Timestamp,
    ) -> JournalResult<RoundOutcome> {
        Err(JournalError::NotImplemented("Journal::commit_round"))
    }

    /// Applies one transition of the state-machine table atomically: validates it with
    /// `zeus_types::state::apply`, updates the record and its counters through `update`, appends the
    /// events in table order and commits. An illegal transition is a `conflict`
    /// (`api.invalid_transition`) and changes nothing.
    pub fn apply_transition(
        &self,
        request: TransitionRequest,
        update: &mut dyn FnMut(&mut JobRecord) -> JournalResult<()>,
    ) -> JournalResult<TransitionOutcome> {
        Err(JournalError::NotImplemented("Journal::apply_transition"))
    }

    /// Restart from zero (03 section 7.6), one transaction: remove every range and unit checksum of the
    /// job, write one `invalidations` row with the dropped byte count and `reason`, update bound
    /// validators and totals through `update`, and clear `verify_result`. The data file is truncated by
    /// the caller **after** this commits, so a crash never leaves committed ranges pointing at overwritten
    /// bytes. Returns the number of bytes dropped.
    pub fn invalidate_all(
        &self,
        job: JobId,
        reason: InvalidationReason,
        now: Timestamp,
        update: &mut dyn FnMut(&mut JobRecord) -> JournalResult<()>,
    ) -> JournalResult<u64> {
        Err(JournalError::NotImplemented("Journal::invalidate_all"))
    }

    /// Removes the part `range` of a job's committed set (recovery checks L3 and L4) with an
    /// `invalidations` row (I3). Returns the bytes dropped.
    pub fn invalidate_range(
        &self,
        job: JobId,
        range: ByteRange,
        reason: InvalidationReason,
        now: Timestamp,
    ) -> JournalResult<u64> {
        Err(JournalError::NotImplemented("Journal::invalidate_range"))
    }

    /// The point of no return (step F6, transition S80): in one transaction set `completed`, store the
    /// result, clear `finalize`, delete the job's range and checksum rows and release its reservation,
    /// and append `job.completed` and `job.state_changed`.
    pub fn finish_job(
        &self,
        request: TransitionRequest,
        update: &mut dyn FnMut(&mut JobRecord) -> JournalResult<()>,
    ) -> JournalResult<TransitionOutcome> {
        Err(JournalError::NotImplemented("Journal::finish_job"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_options() {
        let o = JournalOptions::default();
        assert!(!o.quick_repair && !o.two_phase_commit);
        assert!(o.commit.validate().is_ok());
    }
}
