//! Hermetic storage and crash-recovery regressions.
use std::sync::Arc;
use zeus_control::ManualClock;
use zeus_fs::{Filesystem, RealFs};
use zeus_journal::*;
use zeus_types::*;

fn record(path: &std::path::Path) -> JobRecord {
    let id = IdGenerator::new().job_id();
    let now = Timestamp::UNIX_EPOCH;
    let spec = JobSpec::new(
        HttpUrl::parse("https://example.org/file").unwrap(),
        Source::new(SourceKind::Cli),
    );
    JobRecord::new(
        Job::new(id, spec, JobState::Queued, now),
        JobInternal {
            retry_no_progress_since: None,
            retry_counts: Default::default(),
            last_state_seq: 0,
            os_metadata: Vec::new(),
            epoch: 0,
            dest_path: path.join("file").to_string_lossy().into_owned(),
            zpart_path: path.join("file.zpart").to_string_lossy().into_owned(),
            zpart_file_id: None,
            total_bytes: Some(8),
            data_complete: false,
            eof_size: None,
            bound_validators: Validators::default(),
            range_support: RangeSupport::Verified,
            resume_recheck: ResumeRecheck::Full,
            verify_result: None,
            finalize: None,
            url_secret_stored: false,
        },
    )
}
fn transition(j: &Journal, id: JobId, name: &'static str, cause: StateCause) {
    j.apply_transition(
        TransitionRequest {
            job_id: id,
            transition: name,
            trigger: TransitionActor::Engine,
            cause,
            actor: Actor::engine(),
            now: Timestamp::UNIX_EPOCH,
            events_before: vec![],
            events_after: vec![],
        },
        &mut |_| Ok(()),
    )
    .unwrap();
}
fn open(path: &std::path::Path) -> Journal {
    Journal::open(
        path,
        &JournalOptions::default(),
        Arc::new(ManualClock::new(Timestamp::UNIX_EPOCH)),
    )
    .unwrap()
}

#[test]
fn durable_ranges_epoch_fence_and_tamper_recheck() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("journal.redb");
    let journal = open(&db);
    let mut r = record(dir.path());
    let file = RealFs
        .create_new(std::path::Path::new(&r.internal.zpart_path))
        .unwrap();
    r.internal.zpart_file_id = Some(file.file_id().unwrap());
    journal.create_job(&r, None, vec![]).unwrap();
    transition(&journal, r.id(), "S03", StateCause::Scheduler);
    transition(&journal, r.id(), "S10", StateCause::ProbeOk);
    file.write_all_at(0, b"abcdefgh").unwrap();
    file.sync_data().unwrap();
    let first = CommitUnit {
        job_id: r.id(),
        range: ByteRange::new(0, 4).unwrap(),
        epoch: 1,
        crc32c: Some(crc32c::crc32c(b"abcd")),
    };
    let stale = CommitUnit { epoch: 0, ..first };
    assert_eq!(
        journal
            .commit_round(&[stale], Timestamp::UNIX_EPOCH)
            .unwrap()
            .discarded,
        vec![stale]
    );
    assert!(journal.committed(r.id()).unwrap().is_empty());
    journal
        .commit_round(&[first], Timestamp::UNIX_EPOCH)
        .unwrap();
    assert_eq!(
        journal
            .job(r.id())
            .unwrap()
            .unwrap()
            .job
            .progress
            .bytes_done,
        4
    );
    file.write_all_at(2, b"XX").unwrap();
    file.sync_data().unwrap();
    let stored = journal.job(r.id()).unwrap().unwrap();
    let assessment = recovery::assess_resume(&RealFs, &stored, &journal).unwrap();
    assert_eq!(
        assessment.invalidated,
        Some(InvalidationReason::TailCheckFailed)
    );
    assert_eq!(assessment.dropped_bytes, 4);
    drop(journal);
    let journal = open(&db);
    assert_eq!(journal.committed(r.id()).unwrap().covered_bytes(), 4);
    assert_eq!(
        journal
            .invalidate_all(
                r.id(),
                InvalidationReason::TailCheckFailed,
                Timestamp::UNIX_EPOCH,
                &mut |_| Ok(())
            )
            .unwrap(),
        4
    );
    assert!(journal.committed(r.id()).unwrap().is_empty());
    assert_eq!(journal.read(|t| t.invalidations(r.id())).unwrap().len(), 1);
}

#[derive(Debug)]
struct CrashAt(CrashPoint);
impl FaultInjector for CrashAt {
    fn hit(&self, point: CrashPoint) -> Result<(), fault::InjectedCrash> {
        if point == self.0 {
            Err(fault::InjectedCrash(point))
        } else {
            Ok(())
        }
    }
}
#[test]
fn crash_before_commit_rolls_back_and_after_commit_recovers_durable_progress() {
    for point in [CrashPoint::DuringCommit, CrashPoint::AfterCommitBeforeAck] {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("journal.redb");
        let journal = open(&db).with_faults(Arc::new(CrashAt(point)));
        let r = record(dir.path());
        journal.create_job(&r, None, vec![]).unwrap();
        transition(&journal, r.id(), "S03", StateCause::Scheduler);
        transition(&journal, r.id(), "S10", StateCause::ProbeOk);
        let unit = CommitUnit {
            job_id: r.id(),
            range: ByteRange::new(0, 8).unwrap(),
            epoch: 1,
            crc32c: None,
        };
        assert!(
            journal
                .commit_round(&[unit], Timestamp::UNIX_EPOCH)
                .is_err()
        );
        drop(journal);
        let journal = open(&db);
        let saved = journal.job(r.id()).unwrap().unwrap();
        if point == CrashPoint::DuringCommit {
            assert_eq!(saved.job.state, JobState::Downloading);
            assert_eq!(saved.job.progress.bytes_done, 0);
        } else {
            assert_eq!(saved.job.state, JobState::Verifying);
            assert_eq!(saved.job.progress.bytes_done, 8);
        }
        let context = recovery::RecoveryContext {
            fs: Arc::new(RealFs),
            scan_roots: vec![dir.path().to_path_buf()],
            orphan_gc_age: recovery::DEFAULT_ORPHAN_GC_AGE,
            audit_chain_ok: true,
        };
        assert_eq!(
            recovery::recover(&journal, &context)
                .unwrap()
                .jobs_recovered,
            1
        );
        assert_eq!(
            recovery::recover(&journal, &context)
                .unwrap()
                .jobs_recovered,
            0
        );
        assert_eq!(
            journal
                .job(r.id())
                .unwrap()
                .unwrap()
                .job
                .retry
                .recovery_count,
            1
        );
    }
}
#[test]
fn writer_rollback_event_sequence_and_kill_switch_are_durable() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("journal.redb");
    let journal = open(&db);
    assert!(
        Journal::open(
            &db,
            &JournalOptions::default(),
            Arc::new(ManualClock::new(Timestamp::UNIX_EPOCH))
        )
        .is_err()
    );
    let r = record(dir.path());
    let failed: JournalResult<()> = journal.transact(|t| {
        t.put_job(&r)?;
        t.set_kill_switch(true)?;
        Err(JournalError::Invariant("simulated failure"))
    });
    assert!(failed.is_err());
    assert!(journal.job(r.id()).unwrap().is_none());
    assert!(!journal.meta().unwrap().kill_switch_engaged());
    journal.transact(|t| t.set_kill_switch(true)).unwrap();
    drop(journal);
    assert!(open(&db).meta().unwrap().kill_switch_engaged());
}

#[test]
fn guarded_commit_observes_latch_and_preserves_durable_state_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let journal = open(&dir.path().join("journal"));
    let mut r = record(dir.path());
    r.job.spec.source.run_id = Some(IdGenerator::new().run_id());
    journal.create_job(&r, None, vec![]).unwrap();
    transition(&journal, r.id(), "S03", StateCause::Scheduler);
    transition(&journal, r.id(), "S10", StateCause::ProbeOk);
    let before = journal.job(r.id()).unwrap().unwrap();
    assert!(before.summary().state_seq.is_some());
    let unit = CommitUnit {
        job_id: r.id(),
        range: ByteRange::new(0, 8).unwrap(),
        epoch: 1,
        crc32c: None,
    };
    let refused = journal
        .commit_round_guarded(&[unit], Timestamp::UNIX_EPOCH, &mut |_, _| Ok(false))
        .unwrap();
    assert_eq!(refused.discarded, vec![unit]);
    assert!(journal.committed(r.id()).unwrap().is_empty());
    journal.transact(|tx| tx.set_kill_switch(true)).unwrap();
    let refused = journal
        .commit_round(&[unit], Timestamp::UNIX_EPOCH)
        .unwrap();
    assert_eq!(refused.discarded, vec![unit]);
    journal.transact(|tx| tx.set_kill_switch(false)).unwrap();
    journal
        .commit_round(&[unit], Timestamp::UNIX_EPOCH)
        .unwrap();
    let after = journal.job(r.id()).unwrap().unwrap();
    assert_eq!(after.job.state, JobState::Verifying);
    assert!(after.internal.last_state_seq > before.internal.last_state_seq);
    let events = journal.read(|tx| tx.events_since(None, 100)).unwrap();
    assert!(
        events
            .iter()
            .filter(|e| e.job_id == Some(r.id()))
            .all(|e| e.run_id == r.job.spec.source.run_id)
    );
}

#[test]
fn approval_evidence_commits_atomically_is_private_and_cannot_be_rewritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("evidence.redb");
    let journal = open(&path);
    let ids = IdGenerator::new();
    let id = ids.approval_id();
    let grant_id = ids.grant_id();
    let mut approval: Approval = serde_json::from_value(serde_json::json!({
        "id":id,"kind":"session_grant","state":"pending","revision":1,"request_hash":"11".repeat(32),
        "allowed_scopes":["site"],"reason_codes":["session.first_use"],"summary":{"title":"example.test"},
        "created_at":"2026-10-05T00:00:00.000Z","expires_at":"2026-10-06T00:00:00.000Z"
    })).unwrap();
    let grant: SessionGrant = serde_json::from_value(serde_json::json!({
        "id":grant_id,"origin":"https://example.test","scope":"site","state":"active",
        "created_at":"2026-10-05T00:00:00.000Z","expires_at":"2026-10-06T00:00:00.000Z",
        "approval_id":id,"decided_by":{"kind":"human","surface":"cli_interactive"},"uses":0,"renewable":true
    })).unwrap();
    let evidence = serde_json::json!({
        "approval_id":id,"revision":1,"request_hash":"11".repeat(32),"outcome":"approve","scope":"site",
        "actor":{"kind":"human","surface":"cli_interactive"},"decided_at":"2026-10-05T00:00:01.000Z",
        "grant_ids":[grant_id],"evidence":{"surface":"cli_interactive","role":"cli","client_id":"private-client-id",
        "credential_kind":"human","effective_kind":"human","exe_verified":true,"peer_pid":1234,"tty":"verified","confirmation":"gesture"}
    });
    let mut txn = journal.store().begin_write().unwrap();
    txn.put_approval(&approval).unwrap();
    assert!(txn.put_approval_decision(id, &evidence).is_err());
    txn.commit().unwrap();
    approval.state = ApprovalState::Approved;
    let mut txn = journal.store().begin_write().unwrap();
    txn.put_approval(&approval).unwrap();
    txn.put_grant(&grant).unwrap();
    txn.put_approval_decision(id, &evidence).unwrap();
    txn.rollback().unwrap();
    let reader = journal.store().begin_read().unwrap();
    assert_eq!(
        reader.approval(id).unwrap().unwrap().state,
        ApprovalState::Pending
    );
    assert!(reader.approval_decision(id).unwrap().is_none());
    assert!(reader.grant(grant_id).unwrap().is_none());
    drop(reader);
    let mut txn = journal.store().begin_write().unwrap();
    txn.put_approval(&approval).unwrap();
    txn.put_grant(&grant).unwrap();
    txn.put_approval_decision(id, &evidence).unwrap();
    txn.commit().unwrap();
    drop(journal);
    let journal = open(&path);
    let reader = journal.store().begin_read().unwrap();
    assert_eq!(
        reader.approval_decision(id).unwrap(),
        Some(evidence.clone())
    );
    assert_eq!(reader.grant(grant_id).unwrap(), Some(grant));
    assert!(
        !serde_json::to_string(&reader.approval(id).unwrap())
            .unwrap()
            .contains("private-client-id")
    );
    assert!(reader.events_since(None, 100).unwrap().is_empty());
    drop(reader);
    let mut txn = journal.store().begin_write().unwrap();
    txn.put_approval_decision(id, &evidence).unwrap();
    let mut changed = evidence.clone();
    changed["evidence"]["peer_pid"] = serde_json::json!(999);
    assert!(txn.put_approval_decision(id, &changed).is_err());
    changed = evidence.clone();
    changed["revision"] = serde_json::json!(2);
    assert!(txn.put_approval_decision(id, &changed).is_err());
    changed = evidence;
    changed["evidence"]["padding"] = serde_json::json!("x".repeat(65536));
    assert!(txn.put_approval_decision(id, &changed).is_err());
    txn.rollback().unwrap();
}

#[test]
fn receipt_retention_tracks_job_lifetime_and_binds_method() {
    let dir = tempfile::tempdir().unwrap();
    let journal = open(&dir.path().join("receipts.redb"));
    let job = record(dir.path());
    journal.create_job(&job, None, vec![]).unwrap();
    let receipt: IdempotencyRow = serde_json::from_value(serde_json::json!({
        "client_id":"client","key":"download","request_hash":"22".repeat(32),"job_id":job.id(),
        "method":"jobs.enqueue","result":{"job_id":job.id()},
        "created_at":"2026-10-05T00:00:00.000Z","expires_at":"2026-10-06T00:00:00.000Z"
    }))
    .unwrap();
    let mut txn = journal.store().begin_write().unwrap();
    txn.put_idempotency(&receipt).unwrap();
    txn.commit().unwrap();
    let now = Timestamp::parse("2026-10-07T00:00:00.000Z").unwrap();
    let mut txn = journal.store().begin_write().unwrap();
    assert_eq!(txn.expire_idempotency(now).unwrap(), 0);
    assert_eq!(
        txn.idempotency("client", "download").unwrap(),
        Some(receipt.clone())
    );
    let mut changed = receipt;
    changed.method = Some("jobs.cancel".into());
    assert!(txn.put_idempotency(&changed).is_err());
    txn.delete_job(job.id()).unwrap();
    assert_eq!(txn.expire_idempotency(now).unwrap(), 1);
    assert!(txn.idempotency("client", "download").unwrap().is_none());
    txn.commit().unwrap();
}
