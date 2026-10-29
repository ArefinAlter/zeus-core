//! Actual native files and durable restart receipts, including edits which preserve the fingerprint.
use super::*;
use crate::{
    FinalizePhase, FinalizeState, JobInternal, JournalOptions, ResumeRecheck, VerifyResult,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use zeus_fs::{RetainedFs, WriteRoots};
use zeus_types::*;

fn fixture() -> (tempfile::TempDir, Journal, RecoveryContext) {
    let dir = tempfile::tempdir().unwrap();
    let journal = Journal::open(
        &dir.path().join("journal.redb"),
        &JournalOptions::default(),
        Arc::new(zeus_control::ManualClock::new(Timestamp::UNIX_EPOCH)),
    )
    .unwrap();
    let fs = RetainedFs::open(&WriteRoots::open(&[dir.path().to_path_buf()]).unwrap()).unwrap();
    let context = RecoveryContext {
        fs: Arc::new(fs),
        scan_roots: vec![dir.path().to_path_buf()],
        orphan_gc_age: Duration::from_secs(3600),
        audit_chain_ok: true,
    };
    (dir, journal, context)
}
fn pending(
    dir: &Path,
    journal: &Journal,
    context: &RecoveryContext,
    name: &str,
) -> (JobRecord, PathBuf, PathBuf) {
    let part = dir.join(format!("{name}.zpart"));
    let dest = dir.join(name);
    let file = context.fs.create_new(&part).unwrap();
    file.write_all_at(0, b"original").unwrap();
    file.sync_all().unwrap();
    let id = file.file_id().unwrap();
    let meta = file.metadata().unwrap();
    let digests = zeus_verify::hash::hash_bytes(b"original");
    let mut spec = JobSpec::new(
        HttpUrl::parse("https://example.org/file").unwrap(),
        Source::new(SourceKind::Cli),
    );
    spec.overwrite = Some(Overwrite::Rename);
    let record = JobRecord::new(
        Job::new(
            IdGenerator::new().job_id(),
            spec,
            JobState::Finalizing,
            Timestamp::UNIX_EPOCH,
        ),
        JobInternal {
            retry_no_progress_since: None,
            retry_counts: Default::default(),
            last_state_seq: 0,
            os_metadata: vec![],
            epoch: 0,
            dest_path: dest.to_string_lossy().into_owned(),
            zpart_path: part.to_string_lossy().into_owned(),
            zpart_file_id: Some(id.clone()),
            total_bytes: Some(8),
            data_complete: true,
            eof_size: Some(8),
            bound_validators: Validators::default(),
            range_support: RangeSupport::Verified,
            resume_recheck: ResumeRecheck::Full,
            verify_result: Some(VerifyResult {
                size_bytes: 8,
                sha256: digests.sha256,
                blake3: digests.blake3,
                detected_mime: None,
                verified_at: Timestamp::UNIX_EPOCH,
                mtime_ms: u64::try_from(meta.mtime_ms).ok(),
            }),
            finalize: Some(FinalizeState {
                phase: FinalizePhase::Intent,
                tmp_path: part.to_string_lossy().into_owned(),
                dest_path: dest.to_string_lossy().into_owned(),
                file_id: id,
                intent_at: Timestamp::UNIX_EPOCH,
            }),
            url_secret_stored: false,
        },
    );
    journal.transact(|t| t.put_job(&record)).unwrap();
    (record, part, dest)
}
fn unchanged_receipt(record: &JobRecord, after: &JobRecord) {
    assert_eq!(after.job.state, JobState::Failed);
    assert!(after.job.result.is_none());
    assert_eq!(after.internal.finalize, record.internal.finalize);
    assert_eq!(after.internal.verify_result, record.internal.verify_result);
}

#[test]
fn interrupted_finalize_rechecks_before_rename_after_rename_and_collision() {
    for phase in 0..3 {
        let (dir, journal, context) = fixture();
        let (record, part, dest) = pending(dir.path(), &journal, &context, "file");
        if phase == 1 {
            context.fs.rename_noreplace(&part, &dest).unwrap();
        }
        if phase == 2 {
            std::fs::write(&dest, b"foreign").unwrap();
        }
        let summary = recover(&journal, &context).unwrap();
        assert_eq!(summary.jobs_recovered, 1);
        let after = journal.job(record.id()).unwrap().unwrap();
        assert_eq!(after.job.state, JobState::Completed);
        let result = after.job.result.unwrap();
        assert_eq!(std::fs::read(&result.path).unwrap(), b"original");
        assert_eq!(
            result.sha256,
            zeus_verify::hash::hash_bytes(b"original").sha256
        );
        if phase == 2 {
            assert_ne!(Path::new(&result.path), dest);
            assert_eq!(std::fs::read(&dest).unwrap(), b"foreign");
        }
        assert_eq!(recover(&journal, &context).unwrap().jobs_recovered, 0);
    }
}

#[test]
fn stopped_same_object_edit_with_preserved_size_and_mtime_never_completes() {
    for renamed in [false, true] {
        let (dir, journal, context) = fixture();
        let (record, part, dest) = pending(dir.path(), &journal, &context, "file");
        if renamed {
            context.fs.rename_noreplace(&part, &dest).unwrap();
        }
        let candidate = if renamed { &dest } else { &part };
        let before = context.fs.metadata(candidate).unwrap().unwrap();
        let modified = std::fs::metadata(candidate).unwrap().modified().unwrap();
        std::fs::write(candidate, b"modified").unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(candidate)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        assert_eq!(context.fs.metadata(candidate).unwrap().unwrap(), before);
        assert_eq!(recover(&journal, &context).unwrap().jobs_failed, 1);
        let after = journal.job(record.id()).unwrap().unwrap();
        unchanged_receipt(&record, &after);
        assert_eq!(
            after.job.error.unwrap().code.as_str(),
            codes::INTEGRITY_HASH_MISMATCH
        );
        assert_eq!(std::fs::read(candidate).unwrap(), b"modified");
        if !renamed {
            assert!(!dest.exists());
        }
        assert_eq!(recover(&journal, &context).unwrap().jobs_failed, 0);
        assert_eq!(std::fs::read(candidate).unwrap(), b"modified");
    }
}

#[test]
fn replaced_object_with_matching_bytes_does_not_acquire_finalize_authority() {
    let (dir, journal, context) = fixture();
    let (record, part, dest) = pending(dir.path(), &journal, &context, "file");
    let preserved = dir.path().join("preserved");
    std::fs::rename(&part, &preserved).unwrap();
    std::fs::write(&part, b"original").unwrap();
    assert_ne!(
        context.fs.metadata(&part).unwrap().unwrap().file_id,
        record.internal.zpart_file_id
    );
    assert_eq!(recover(&journal, &context).unwrap().jobs_failed, 1);
    unchanged_receipt(&record, &journal.job(record.id()).unwrap().unwrap());
    assert_eq!(std::fs::read(&part).unwrap(), b"original");
    assert_eq!(std::fs::read(preserved).unwrap(), b"original");
    assert!(!dest.exists());
}

#[test]
fn pending_jobs_share_one_budget_and_unprocessed_receipts_remain_held_on_restart() {
    let (dir, journal, context) = fixture();
    let a = pending(dir.path(), &journal, &context, "first");
    let b = pending(dir.path(), &journal, &context, "second");
    let mut budget = FinalizationBudget {
        remaining: 8,
        deadline: Instant::now() + Duration::from_secs(120),
    };
    let summary = recover_limited(&journal, &context, &mut budget).unwrap();
    assert_eq!(
        (
            summary.jobs_recovered,
            summary.jobs_failed,
            budget.remaining
        ),
        (1, 1, 0)
    );
    for (record, part, dest) in [a, b] {
        let after = journal.job(record.id()).unwrap().unwrap();
        if after.job.state == JobState::Failed {
            unchanged_receipt(&record, &after);
            assert_eq!(after.job.error.unwrap().code.as_str(), codes::FS_BUSY);
            assert_eq!(std::fs::read(&part).unwrap(), b"original");
            assert!(!dest.exists());
            recover(&journal, &context).unwrap();
            assert_eq!(
                journal.job(record.id()).unwrap().unwrap().job.state,
                JobState::Failed
            );
            assert!(!dest.exists());
        }
    }
    let (record, part, dest) = pending(dir.path(), &journal, &context, "deadline");
    let mut elapsed = FinalizationBudget {
        remaining: u64::MAX,
        deadline: Instant::now(),
    };
    assert_eq!(
        recover_limited(&journal, &context, &mut elapsed)
            .unwrap()
            .jobs_failed,
        1
    );
    unchanged_receipt(&record, &journal.job(record.id()).unwrap().unwrap());
    assert_eq!(elapsed.remaining, u64::MAX);
    assert_eq!(std::fs::read(part).unwrap(), b"original");
    assert!(!dest.exists());
}
