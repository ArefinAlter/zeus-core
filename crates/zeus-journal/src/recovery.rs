//! Recovery on startup (03 section 10) and the local resume checks (03 section 7.2).
//!
//! `zeusd` runs [`recover`] before accepting any connection. Every step is idempotent: a crash during
//! recovery followed by another recovery gives the same result (invariant I11). Ordinary resume
//! hashes later in `verifying`; a pending finalization rechecks its opened bytes within one shared
//! startup budget before publishing or accepting a previously renamed file.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use zeus_control::RangeSet;
use zeus_fs::Filesystem;
use zeus_types::event::RecoverySummary;

use crate::error::{JournalError, JournalResult};
use crate::journal::Journal;
use crate::records::{InvalidationReason, JobRecord};

/// Inputs of startup recovery.
#[derive(Clone)]
pub struct RecoveryContext {
    /// The file system, injectable so recovery runs under the crash simulator.
    pub fs: Arc<dyn Filesystem>,
    /// Directories to scan for orphan `.zpart` files besides the directories of non-terminal jobs
    /// (the configured write roots).
    pub scan_roots: Vec<PathBuf>,
    /// Orphans older than this are deleted (default 7 days, minimum 1 hour); younger ones are reported.
    pub orphan_gc_age: Duration,
    /// Whether the audit chain tail verified (recovery step 6 reports it; the caller verifies).
    pub audit_chain_ok: bool,
}

impl std::fmt::Debug for RecoveryContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryContext")
            .field("scan_roots", &self.scan_roots)
            .finish_non_exhaustive()
    }
}

/// Runs steps 2 to 8 of 03 section 10 (step 1, opening the store, is `Journal::open`): migrate, apply
/// S95 or S96 to every in-flight job (`recovery_count` reaching 3 without committed progress is a crash
/// loop, `engine.crash_loop`), re-arm timers from stored instants, resolve interrupted finalizations
/// with the decision procedure of 03 section 8.2, normalise range sets (I4), collect orphan `.zpart`
/// files, expire grants and approvals, prune retention. Step 6 (outbox replay into the audit log and the
/// manifest) is driven by the daemon from the cursors in `meta`. Returns the summary for `daemon.started`.
pub fn recover(journal: &Journal, context: &RecoveryContext) -> JournalResult<RecoverySummary> {
    recover_limited(
        journal,
        context,
        &mut FinalizationBudget {
            remaining: u64::MAX,
            deadline: std::time::Instant::now() + Duration::from_secs(120),
        },
    )
}

// One deadline for the entire startup, never a new deadline per job. The byte allowance also lets
// deterministic regressions exercise exhaustion without sleeping or relying on machine speed.
struct FinalizationBudget {
    remaining: u64,
    deadline: std::time::Instant,
}

fn recover_limited(
    journal: &Journal,
    context: &RecoveryContext,
    budget: &mut FinalizationBudget,
) -> JournalResult<RecoverySummary> {
    use crate::journal::TransitionRequest;
    use zeus_types::event::*;
    use zeus_types::*;
    let now = journal.clock().now();
    let mut summary = RecoverySummary {
        jobs_recovered: 0,
        jobs_failed: 0,
        orphans_found: 0,
        audit_chain_ok: context.audit_chain_ok,
    };
    for record in journal.list_incomplete()? {
        crate::fault::check(
            journal.faults().as_ref(),
            crate::fault::CrashPoint::DuringRecovery,
        )?;
        // Failed receipts stay held for explicit review; startup never retries their effects.
        if record.job.state == JobState::Finalizing
            && record.internal.finalize.is_some()
            && recover_finalization(journal, context, &record, budget)?
        {
            if journal
                .job(record.id())?
                .is_some_and(|r| r.job.state == JobState::Failed)
            {
                summary.jobs_failed += 1;
            } else {
                summary.jobs_recovered += 1;
            }
            continue;
        }
        if !record.job.state.is_in_flight() {
            continue;
        }
        let count = record.job.retry.recovery_count.saturating_add(1);
        let failed = count >= 3;
        let error = ErrorEnvelope::from_code(
            codes::ENGINE_CRASH_LOOP,
            "repeated daemon interruption without committed progress",
        );
        let after = if failed {
            vec![
                JobFailedData {
                    error: error.clone(),
                    suggested_next: SuggestedNext {
                        action: SuggestedAction::Retry,
                        tool: Some("zeus_control".into()),
                    },
                }
                .into(),
            ]
        } else {
            vec![]
        };
        journal.apply_transition(
            TransitionRequest {
                job_id: record.id(),
                transition: if failed { "S96" } else { "S95" },
                trigger: TransitionActor::System,
                cause: if failed {
                    StateCause::CrashLoop
                } else {
                    StateCause::Recovered
                },
                actor: Actor::system(),
                now,
                events_before: vec![],
                events_after: after,
            },
            &mut |r| {
                r.job.retry.recovery_count = count;
                if failed {
                    r.job.error = Some(error.clone());
                }
                Ok(())
            },
        )?;
        if failed {
            summary.jobs_failed += 1;
        } else {
            summary.jobs_recovered += 1;
        }
    }
    let records = journal.read(|t| t.jobs(&crate::store::JobFilter::default()))?;
    for record in &records {
        if let Some(total) = record.internal.total_bytes {
            for range in journal
                .committed(record.id())?
                .iter()
                .filter(|r| r.end > total)
            {
                journal.invalidate_range(
                    record.id(),
                    ByteRange::new(range.start.max(total), range.end)?,
                    InvalidationReason::FileTruncated,
                    now,
                )?;
            }
        }
    }
    let mut roots = context.scan_roots.clone();
    let mut owned = std::collections::HashSet::new();
    for record in &records {
        if !record.job.state.is_terminal() {
            let path = PathBuf::from(&record.internal.zpart_path);
            owned.insert(path.clone());
            if let Some(parent) = path.parent() {
                roots.push(parent.to_path_buf());
            }
        }
    }
    roots.sort();
    roots.dedup();
    let retention = context.orphan_gc_age.max(Duration::from_secs(3600));
    let oldest = now
        .unix_millis()
        .saturating_sub(retention.as_millis().min(i64::MAX as u128) as i64);
    let mut seen = std::collections::HashSet::new();
    for root in roots {
        if context.fs.metadata(&root).map_err(fs_error)?.is_none() {
            continue;
        }
        for entry in context.fs.read_dir(&root).map_err(fs_error)? {
            if !entry.meta.is_regular_file
                || !zeus_fs::finalize::is_zpart(&entry.path)
                || owned.contains(&entry.path)
                || !seen.insert(entry.path.clone())
            {
                continue;
            }
            summary.orphans_found += 1;
            if (entry.meta.len == 0 || entry.meta.mtime_ms < oldest)
                && let Some(identity) = &entry.meta.file_id
            {
                context
                    .fs
                    .remove_expected(&entry.path, identity)
                    .map_err(fs_error)?;
            }
        }
    }
    journal.transact(|t| {
        for reservation in t.reservations()? {
            if t.job(reservation.job_id)?
                .is_none_or(|r| r.job.state.is_terminal())
            {
                t.remove_reservation(&reservation.path_key)?;
            }
        }
        for mut grant in t.grants()? {
            if grant.state == GrantState::Active && grant.expires_at.is_some_and(|e| e <= now) {
                grant.state = GrantState::Expired;
                t.put_grant(&grant)?;
                t.append_event(
                    now,
                    grant.job_id,
                    grant.run_id,
                    GrantExpiredData {
                        grant_id: grant.id,
                        origin: grant.origin,
                    }
                    .into(),
                )?;
            }
        }
        for mut approval in t.approvals(Some(&[ApprovalState::Pending]))? {
            if approval.expires_at <= now {
                approval.state = ApprovalState::Expired;
                approval.decided_at = Some(now);
                t.put_approval(&approval)?;
                t.append_event(
                    now,
                    approval.job_id,
                    approval.run_id,
                    ApprovalDecidedData {
                        approval_id: approval.id,
                        kind: approval.kind,
                        outcome: DecisionOutcome::Expire,
                        scope: None,
                        actor: Actor::system(),
                        grant_id: None,
                    }
                    .into(),
                )?;
            }
        }
        t.expire_idempotency(now)?;
        Ok(())
    })?;
    Ok(summary)
}

/// What the local checks of 03 section 7.2 concluded for one job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeAssessment {
    /// The committed ranges that survive the checks.
    pub trusted: RangeSet,
    /// The first failing check and the invalidation it requires, if any ranges were dropped.
    pub invalidated: Option<InvalidationReason>,
    /// Bytes dropped from the committed set.
    pub dropped_bytes: u64,
}

/// Local checks L1 to L4 before any request: the data file exists and is a regular file (L1), its
/// identity equals `zpart_file_id` (L2), its length covers the committed ranges (L3), and the CRC32C of
/// the last 16 units (`resume_recheck = tail`, continuing one unit earlier until 4 consecutive units pass)
/// or of every unit (`full`) matches the journal (L4). Returns what is still trusted; the caller commits
/// the invalidation and then probes.
pub fn assess_resume(
    fs: &dyn Filesystem,
    record: &JobRecord,
    journal: &Journal,
) -> JournalResult<ResumeAssessment> {
    let mut trusted = journal.committed(record.id())?;
    let before = trusted.covered_bytes();
    let mut invalidated = None;
    let metadata = fs
        .metadata(std::path::Path::new(&record.internal.zpart_path))
        .map_err(fs_error)?;
    let Some(meta) = metadata else {
        trusted.clear();
        return Ok(ResumeAssessment {
            trusted,
            invalidated: (before > 0).then_some(InvalidationReason::FileTruncated),
            dropped_bytes: before,
        });
    };
    if !meta.is_regular_file || meta.file_id != record.internal.zpart_file_id {
        trusted.clear();
        return Ok(ResumeAssessment {
            trusted,
            invalidated: (before > 0).then_some(InvalidationReason::FileReplaced),
            dropped_bytes: before,
        });
    }
    if trusted.truncate_to(meta.len) > 0 {
        invalidated = Some(InvalidationReason::FileTruncated);
    }
    if record.internal.resume_recheck != crate::records::ResumeRecheck::None && !trusted.is_empty()
    {
        let file = fs
            .open_existing(std::path::Path::new(&record.internal.zpart_path))
            .map_err(fs_error)?;
        if Some(file.file_id().map_err(fs_error)?) != record.internal.zpart_file_id {
            trusted.clear();
            return Ok(ResumeAssessment {
                trusted,
                invalidated: Some(InvalidationReason::FileReplaced),
                dropped_bytes: before,
            });
        }
        let rows = journal.read(|t| t.all_unit_crcs(record.id()))?;
        let full = record.internal.resume_recheck == crate::records::ResumeRecheck::Full;
        let mut failure = false;
        let mut consecutive = 0;
        for (n, row) in rows.iter().rev().enumerate() {
            if !full && n >= 16 && (!failure || consecutive >= 4) {
                break;
            }
            let range = zeus_types::ByteRange::from_offset_len(row.offset, row.length.into())?;
            if range.is_empty() || trusted.covered_in(range) == 0 {
                continue;
            }
            let mut offset = 0;
            let mut crc = 0;
            let mut buffer = vec![0; (row.length as usize).min(64 << 10)];
            let mut ok = true;
            while offset < row.length as u64 {
                let len = ((row.length as u64 - offset) as usize).min(buffer.len());
                if file
                    .read_exact_at(row.offset + offset, &mut buffer[..len])
                    .is_err()
                {
                    ok = false;
                    break;
                }
                crc = crc32c::crc32c_append(crc, &buffer[..len]);
                offset += len as u64;
            }
            if !ok || crc != row.crc32c {
                trusted.remove(range);
                invalidated.get_or_insert(InvalidationReason::TailCheckFailed);
                failure = true;
                consecutive = 0;
            } else {
                consecutive += 1;
            }
        }
    }
    let dropped_bytes = before - trusted.covered_bytes();
    Ok(ResumeAssessment {
        trusted,
        invalidated,
        dropped_bytes,
    })
}

/// Default orphan garbage-collection age: 7 days.
pub const DEFAULT_ORPHAN_GC_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

fn fs_error(e: zeus_fs::FsError) -> JournalError {
    JournalError::Storage(e.to_string())
}

fn recover_finalization(
    journal: &Journal,
    context: &RecoveryContext,
    record: &JobRecord,
    budget: &mut FinalizationBudget,
) -> JournalResult<bool> {
    use zeus_fs::finalize::*;
    use zeus_types::*;
    let Some(intent) = &record.internal.finalize else {
        return Ok(false);
    };
    let Some(verify) = &record.internal.verify_result else {
        return Err(JournalError::Invariant(
            "finalize intent lacks verification",
        ));
    };
    // Once the shared allowance is exhausted, do not open more candidate paths at all.
    if std::time::Instant::now() >= budget.deadline || verify.size_bytes > budget.remaining {
        fail_finalization(journal, record, finalization_budget_error())?;
        return Ok(true);
    }
    let tmp = std::path::Path::new(&intent.tmp_path);
    let dest = std::path::Path::new(&intent.dest_path);
    let observed = (|| -> zeus_fs::FsResult<FinalizeObservation> {
        Ok(FinalizeObservation {
            tmp: context.fs.metadata(tmp)?.and_then(|m| m.file_id),
            dest: context.fs.metadata(dest)?.and_then(|m| m.file_id),
        })
    })();
    let observed = match observed {
        Ok(observed) => observed,
        Err(_) => {
            fail_finalization(
                journal,
                record,
                ErrorEnvelope::from_code(
                    codes::FS_IO_ERROR,
                    "Interrupted finalization cannot inspect its retained paths; files and receipt are preserved for review.",
                ),
            )?;
            return Ok(true);
        }
    };
    let action = decide_recovery(&observed, &intent.file_id);
    if action == RecoveryAction::Lost {
        fail_finalization(
            journal,
            record,
            ErrorEnvelope::from_code(
                codes::FS_FINALIZE_LOST,
                "Verified file identity cannot be recovered; files and receipt are preserved for review.",
            ),
        )?;
        return Ok(true);
    }
    let candidate = if action == RecoveryAction::ContinueAfterRename {
        dest
    } else {
        tmp
    };
    let opened = if action == RecoveryAction::ContinueAfterRename {
        context.fs.open_read(candidate)
    } else {
        context.fs.open_existing(candidate)
    };
    let file = match opened {
        Ok(file) => file,
        Err(_) => {
            fail_finalization(
                journal,
                record,
                ErrorEnvelope::from_code(
                    codes::FS_IO_ERROR,
                    "Interrupted finalization cannot open its retained file; files and receipt are preserved for review.",
                ),
            )?;
            return Ok(true);
        }
    };
    if let Err(error) = recheck_finalized(file.as_ref(), &intent.file_id, verify, budget) {
        fail_finalization(journal, record, error)?;
        return Ok(true);
    }
    let mut target = dest.to_path_buf();
    match action {
        RecoveryAction::RepeatRename => {
            context
                .fs
                .publish_opened(tmp, dest, file.as_ref())
                .map_err(fs_error)?;
        }
        RecoveryAction::ContinueAfterRename => {}
        RecoveryAction::PickNewName => {
            if record.job.spec.overwrite() != Overwrite::Rename {
                return Err(JournalError::Invariant(
                    "foreign destination blocks finalization recovery",
                ));
            }
            let parent = dest
                .parent()
                .ok_or(JournalError::Invariant("destination has no parent"))?;
            let name = zeus_fs::unique_name(
                &dest
                    .file_name()
                    .ok_or(JournalError::Invariant("destination has no name"))?
                    .to_string_lossy(),
                &|n| {
                    context
                        .fs
                        .metadata(&parent.join(n))
                        .map_or(true, |m| m.is_some())
                },
                zeus_fs::CollisionStrategy::Counter,
                context.fs.is_case_insensitive(parent).map_err(fs_error)?,
            )
            .map_err(fs_error)?;
            target = parent.join(name);
            journal.transact(|t| {
                let mut r = t
                    .job(record.id())?
                    .ok_or(JournalError::NotFound { what: "job" })?;
                r.internal.dest_path = target.to_string_lossy().into_owned();
                if let Some(f) = r.internal.finalize.as_mut() {
                    f.dest_path = r.internal.dest_path.clone();
                }
                t.put_job(&r)
            })?;
            context
                .fs
                .publish_opened(tmp, &target, file.as_ref())
                .map_err(fs_error)?;
        }
        RecoveryAction::Lost => unreachable!("handled before opening the candidate"),
    }
    context
        .fs
        .sync_dir(
            target
                .parent()
                .ok_or(JournalError::Invariant("destination has no parent"))?,
        )
        .map_err(fs_error)?;
    let now = journal.clock().now();
    let target = target.to_string_lossy().into_owned();
    // Normally the persisted state is finalizing; an interrupted older recovery may have queued it.
    if record.job.state != JobState::Finalizing {
        return Err(JournalError::Invariant(
            "finalize intent outside finalizing state",
        ));
    }
    let quarantined = !record.job.quarantine_reasons.is_empty();
    journal.finish_job(
        crate::TransitionRequest {
            job_id: record.id(),
            transition: "S80",
            trigger: TransitionActor::Engine,
            cause: StateCause::Finalized,
            actor: Actor::engine(),
            now,
            events_before: vec![
                zeus_types::event::JobCompletedData {
                    path: target.clone(),
                    size_bytes: verify.size_bytes,
                    sha256: verify.sha256,
                    blake3: verify.blake3,
                    quarantined,
                    duration_ms: now
                        .unix_millis()
                        .saturating_sub(record.job.created_at.unix_millis())
                        .max(0) as u64,
                }
                .into(),
            ],
            events_after: vec![],
        },
        &mut |r| {
            r.job.quarantined = quarantined;
            r.job.result = Some(JobResult {
                path: target.clone(),
                size_bytes: verify.size_bytes,
                sha256: verify.sha256,
                blake3: verify.blake3,
                detected_mime: verify.detected_mime.clone(),
                completed_at: now,
            });
            Ok(())
        },
    )?;
    Ok(true)
}

fn fail_finalization(
    journal: &Journal,
    record: &JobRecord,
    error: zeus_types::ErrorEnvelope,
) -> JournalResult<()> {
    use zeus_types::*;
    journal.apply_transition(
        crate::TransitionRequest {
            job_id: record.id(),
            transition: "S82",
            trigger: TransitionActor::Engine,
            cause: StateCause::FinalizeError,
            actor: Actor::system(),
            now: journal.clock().now(),
            events_before: vec![],
            events_after: vec![
                event::JobFailedData {
                    error: error.clone(),
                    suggested_next: event::SuggestedNext {
                        action: event::SuggestedAction::FixDestination,
                        tool: None,
                    },
                }
                .into(),
            ],
        },
        &mut |r| {
            r.job.error = Some(error.clone());
            // Keep finalize + verify_result and the owned partial identity. No data is removed and
            // subsequent startup leaves this failed receipt held until a person explicitly acts.
            Ok(())
        },
    )?;
    Ok(())
}

fn finalization_budget_error() -> zeus_types::ErrorEnvelope {
    zeus_types::ErrorEnvelope::from_code(
        zeus_types::codes::FS_BUSY,
        "Interrupted finalization exhausted the shared startup verification budget; files and receipt are preserved for review.",
    )
}

fn recheck_finalized(
    file: &dyn zeus_fs::DataFile,
    expected_id: &zeus_types::FileId,
    expected: &crate::records::VerifyResult,
    budget: &mut FinalizationBudget,
) -> Result<(), zeus_types::ErrorEnvelope> {
    use zeus_types::{ErrorEnvelope, codes};
    let unavailable = || {
        ErrorEnvelope::from_code(
            codes::FS_IO_ERROR,
            "Interrupted finalization could not read its retained file; files and receipt are preserved for review.",
        )
    };
    let changed = || {
        ErrorEnvelope::from_code(
            codes::INTEGRITY_HASH_MISMATCH,
            "Interrupted finalization no longer matches its verified bytes; files and receipt are preserved for review.",
        )
    };

    if std::time::Instant::now() >= budget.deadline || expected.size_bytes > budget.remaining {
        return Err(finalization_budget_error());
    }
    let before = file.metadata().map_err(|_| unavailable())?;
    if before.file_id.as_ref() != Some(expected_id)
        || !before.is_regular_file
        || before.len != expected.size_bytes
    {
        return Err(changed());
    }
    let modified = || {
        file.native_file()
            .map(|f| f.metadata().and_then(|m| m.modified()))
            .transpose()
            .map_err(|_| unavailable())
    };
    let before_modified = modified()?;
    let mut hash = zeus_verify::hash::DualHasher::new();
    let mut bytes = vec![0; 1 << 20];
    let mut offset = 0;
    while offset < before.len {
        if std::time::Instant::now() >= budget.deadline {
            return Err(finalization_budget_error());
        }
        let requested = (before.len - offset).min(bytes.len() as u64) as usize;
        let n = file
            .read_at(offset, &mut bytes[..requested])
            .map_err(|_| unavailable())?;
        if n == 0 || n > requested {
            return Err(changed());
        }
        budget.remaining = budget
            .remaining
            .checked_sub(n as u64)
            .ok_or_else(finalization_budget_error)?;
        hash.update(&bytes[..n]);
        offset += n as u64;
    }
    if std::time::Instant::now() >= budget.deadline {
        return Err(finalization_budget_error());
    }
    let digest = hash.finalize();
    if before != file.metadata().map_err(|_| unavailable())?
        || before_modified != modified()?
        || digest.size_bytes != expected.size_bytes
        || digest.sha256 != expected.sha256
        || digest.blake3 != expected.blake3
    {
        return Err(changed());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc_age_default_is_a_week() {
        assert_eq!(DEFAULT_ORPHAN_GC_AGE.as_secs(), 604_800);
    }
}

#[cfg(test)]
#[path = "recovery_retained_tests.rs"]
mod retained_tests;
