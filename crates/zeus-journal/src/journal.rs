//! The journal facade the engine uses.
//!
//! [`Journal`] wraps an `Arc<dyn JournalStore>` with the operations of the commit protocol: atomic
//! transactions, job creation, committed-range queries, and the multi-row operations that must be one
//! transaction (a commit round, a state transition with its events, an invalidation, finalization).

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
            if txn.job(record.id())?.is_some() {
                return Err(JournalError::Invariant("job already exists"));
            }
            txn.put_job(record)?;
            if let Some(r) = reservation {
                txn.put_reservation(r)?;
            }
            let mut record = record.clone();
            let mut appended = Vec::new();
            for (job, payload) in events {
                let event = txn.append_event(now, job, record.job.spec.source.run_id, payload)?;
                if job == Some(record.id())
                    && matches!(
                        event.payload.kind(),
                        Some(
                            zeus_types::EventKind::JobCreated
                                | zeus_types::EventKind::JobStateChanged
                        )
                    )
                {
                    record.internal.last_state_seq = event
                        .seq
                        .ok_or(JournalError::Invariant("journal event lacks sequence"))?
                        .get();
                }
                appended.push(event);
            }
            txn.put_job(&record)?;
            Ok(appended)
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
        self.commit_round_guarded(units, now, &mut |_, _| Ok(true))
    }

    /// Commit a synced round only when `guard` still permits each job inside the same
    /// serialized write transaction. The durable kill switch is always checked first.
    /// A refused unit is discarded without changing ranges or checksums.
    pub fn commit_round_guarded(
        &self,
        units: &[CommitUnit],
        now: Timestamp,
        guard: &mut dyn FnMut(&dyn ReadTxn, &JobRecord) -> JournalResult<bool>,
    ) -> JournalResult<RoundOutcome> {
        crate::fault::check(
            self.faults.as_ref(),
            crate::fault::CrashPoint::AfterSyncBeforeCommit,
        )?;
        let outcome = self.transact(|txn| {
            let mut outcome = RoundOutcome::default();
            for unit in units {
                let Some(mut record) = txn.job(unit.job_id)? else {
                    outcome.discarded.push(*unit);
                    continue;
                };
                if txn.meta()?.kill_switch_engaged()
                    || record.internal.epoch != unit.epoch
                    || record.job.state != JobState::Downloading
                    || !guard(txn, &record)?
                {
                    outcome.discarded.push(*unit);
                    continue;
                }
                if unit.range.is_empty()
                    || record
                        .internal
                        .total_bytes
                        .is_some_and(|total| unit.range.end > total)
                {
                    return Err(JournalError::Invariant("commit unit outside resource"));
                }
                let added = txn.insert_range(unit.job_id, unit.range, unit.epoch)?;
                if let Some(crc32c) = unit.crc32c {
                    txn.put_unit_crc(&crate::records::UnitCrcRow {
                        job_id: unit.job_id,
                        offset: unit.range.start,
                        length: unit
                            .range
                            .len()
                            .try_into()
                            .map_err(|_| JournalError::Invariant("commit unit too large"))?,
                        crc32c,
                    })?;
                }
                let ranges = txn.ranges(unit.job_id)?;
                record.job.progress.bytes_done = ranges.covered_bytes();
                record.job.updated_at = now;
                record.job.progress.updated_at = now;
                if added > 0 {
                    record.job.retry.last_progress_at = Some(now);
                    record.job.retry.recovery_count = 0;
                    if added >= zeus_types::policy::budgets::PROGRESS_RESET_BYTES {
                        record.job.retry.consecutive_failures = 0;
                        record.internal.retry_counts.clear();
                        record.internal.retry_no_progress_since = None;
                    }
                }
                if record
                    .internal
                    .total_bytes
                    .or(record.internal.eof_size)
                    .is_some_and(|n| ranges.is_complete(n))
                {
                    record.internal.data_complete = true;
                    record.job.state = JobState::Verifying;
                    record.job.state_since = now;
                    record.job.progress.rate_ewma = 0;
                    record.job.progress.segments_active = 0;
                    let state_event = txn.append_event(
                        now,
                        Some(unit.job_id),
                        record.job.spec.source.run_id,
                        zeus_types::event::JobStateChangedData {
                            from: JobState::Downloading,
                            to: JobState::Verifying,
                            transition: zeus_types::state::TransitionId::new("S20")?,
                            cause: StateCause::AllCommitted,
                            actor: Actor::engine(),
                        }
                        .into(),
                    )?;
                    record.internal.last_state_seq = state_event
                        .seq
                        .ok_or(JournalError::Invariant("journal event lacks sequence"))?
                        .get();
                    crate::fault::check(
                        self.faults.as_ref(),
                        crate::fault::CrashPoint::DuringCompletionTransaction,
                    )?;
                    outcome.completed.push(unit.job_id);
                }
                txn.put_job(&record)?;
                outcome.acknowledged.push(*unit);
            }
            crate::fault::check(self.faults.as_ref(), crate::fault::CrashPoint::DuringCommit)?;
            Ok(outcome)
        })?;
        crate::fault::check(
            self.faults.as_ref(),
            crate::fault::CrashPoint::AfterCommitBeforeAck,
        )?;
        Ok(outcome)
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
        self.transact(|txn| transition(txn, request, update, false))
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
        let dropped = self.transact(|txn| {
            let mut record = txn
                .job(job)?
                .ok_or(JournalError::NotFound { what: "job" })?;
            let dropped = txn.remove_ranges(job, None)?;
            txn.remove_unit_crcs(job)?;
            txn.put_invalidation(&crate::records::InvalidationRow {
                job_id: job,
                at: now,
                epoch: record.internal.epoch,
                reason,
                dropped_bytes: dropped,
            })?;
            record.internal.verify_result = None;
            record.internal.data_complete = false;
            record.internal.eof_size = None;
            record.job.progress.bytes_done = 0;
            record.job.updated_at = now;
            record.job.progress.updated_at = now;
            update(&mut record)?;
            txn.put_job(&record)?;
            Ok(dropped)
        })?;
        crate::fault::check(
            self.faults.as_ref(),
            crate::fault::CrashPoint::RestartJournalClearedFileNot,
        )?;
        Ok(dropped)
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
        self.transact(|txn| {
            let mut record = txn
                .job(job)?
                .ok_or(JournalError::NotFound { what: "job" })?;
            let dropped = txn.remove_ranges(job, Some(range))?;
            txn.put_invalidation(&crate::records::InvalidationRow {
                job_id: job,
                at: now,
                epoch: record.internal.epoch,
                reason,
                dropped_bytes: dropped,
            })?;
            record.internal.verify_result = None;
            record.internal.data_complete = false;
            record.job.progress.bytes_done = txn.ranges(job)?.covered_bytes();
            record.job.updated_at = now;
            record.job.progress.updated_at = now;
            txn.put_job(&record)?;
            Ok(dropped)
        })
    }

    /// The point of no return (step F6, transition S80): in one transaction set `completed`, store the
    /// result, clear `finalize`, delete the job's range and checksum rows and release its reservation,
    /// and append `job.completed` and `job.state_changed`.
    pub fn finish_job(
        &self,
        request: TransitionRequest,
        update: &mut dyn FnMut(&mut JobRecord) -> JournalResult<()>,
    ) -> JournalResult<TransitionOutcome> {
        if request.transition != "S80" {
            return Err(JournalError::Invariant("finish requires S80"));
        }
        crate::fault::check(
            self.faults.as_ref(),
            crate::fault::CrashPoint::BeforeCompletionCommit,
        )?;
        let outcome = self.transact(|txn| transition(txn, request, update, true))?;
        crate::fault::check(
            self.faults.as_ref(),
            crate::fault::CrashPoint::AfterCompletionBeforeOutbox,
        )?;
        Ok(outcome)
    }
}

/// Applies a validated state transition inside a caller-owned transaction.
/// Used when policy changes must atomically update several jobs and grants.
pub fn apply_transition_in(
    txn: &mut dyn WriteTxn,
    request: TransitionRequest,
    update: &mut dyn FnMut(&mut JobRecord) -> JournalResult<()>,
) -> JournalResult<TransitionOutcome> {
    transition(txn, request, update, false)
}

fn transition(
    txn: &mut dyn WriteTxn,
    request: TransitionRequest,
    update: &mut dyn FnMut(&mut JobRecord) -> JournalResult<()>,
    finish: bool,
) -> JournalResult<TransitionOutcome> {
    let mut record = txn
        .job(request.job_id)?
        .ok_or(JournalError::NotFound { what: "job" })?;
    let from = record.job.state;
    let (to, def) = zeus_types::state::apply(Some(from), request.transition, request.trigger)
        .map_err(|_| JournalError::Invariant("illegal state transition"))?;
    if !def.causes.contains(&request.cause)
        && !(request.cause == zeus_types::StateCause::WorkflowRunner
            && request.trigger == zeus_types::TransitionActor::Client
            && request.actor.kind == zeus_types::ActorKind::System)
    {
        return Err(JournalError::Invariant("invalid transition cause"));
    }
    update(&mut record)?;
    record.job.state = to;
    record.job.state_since = request.now;
    record.job.updated_at = request.now;
    if to == JobState::Probing {
        record.internal.epoch = record
            .internal
            .epoch
            .checked_add(1)
            .ok_or(JournalError::Invariant("epoch exhausted"))?;
    }
    if to != JobState::RetryScheduled {
        record.job.retry.next_attempt_at = None;
    }
    if !matches!(to, JobState::Downloading | JobState::Verifying) {
        record.job.progress.rate_ewma = 0;
        record.job.progress.eta_s = None;
        record.job.progress.segments_active = 0;
    }
    if finish {
        if record.job.result.is_none() {
            return Err(JournalError::Invariant(
                "completion requires verified result",
            ));
        }
        record.internal.finalize = None;
        txn.remove_ranges(record.id(), None)?;
        txn.remove_unit_crcs(record.id())?;
        for r in txn.reservations()? {
            if r.job_id == record.id() {
                txn.remove_reservation(&r.path_key)?;
            }
        }
    }
    record.job.check_invariants()?;
    let mut payloads = request.events_before;
    payloads.push(
        zeus_types::event::JobStateChangedData {
            from,
            to,
            transition: zeus_types::state::TransitionId::new(request.transition)?,
            cause: request.cause,
            actor: request.actor,
        }
        .into(),
    );
    payloads.extend(request.events_after);
    // Optional rows (for example throttling) may be absent; supplied events must preserve table order.
    let mut position = 0;
    for payload in &payloads {
        let kind = payload
            .kind()
            .ok_or(JournalError::Invariant("unknown transition event"))?;
        let offset = def.events[position..]
            .iter()
            .position(|k| *k == kind)
            .ok_or(JournalError::Invariant(
                "transition event order differs from specification",
            ))?;
        position += offset + 1;
    }
    let mut events = Vec::new();
    for payload in payloads {
        let event = txn.append_event(
            request.now,
            Some(record.id()),
            record.job.spec.source.run_id,
            payload,
        )?;
        if event.payload.kind() == Some(zeus_types::EventKind::JobStateChanged) {
            record.internal.last_state_seq = event
                .seq
                .ok_or(JournalError::Invariant("journal event lacks sequence"))?
                .get();
        }
        events.push(event);
    }
    if to.is_terminal() {
        for mut grant in txn.grants()? {
            if grant.scope == zeus_types::GrantScope::Once
                && grant.state == zeus_types::GrantState::Active
                && grant.job_id == Some(record.id())
            {
                grant.state = zeus_types::GrantState::Consumed;
                txn.put_grant(&grant)?;
            }
        }
    }
    txn.put_job(&record)?;
    Ok(TransitionOutcome { record, events })
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
