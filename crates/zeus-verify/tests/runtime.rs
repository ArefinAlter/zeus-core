//! Hermetic storage and crash-recovery regressions.
use zeus_types::{Actor, IdGenerator, Timestamp};
use zeus_verify::{audit::*, hash::*};
#[test]
fn disk_verification_hashes_bytes_and_cancels() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("file");
    let bytes = vec![23u8; 100_000];
    std::fs::write(&path, &bytes).unwrap();
    let (digests, head) = verify_file(&path, &VerifyFileOptions::default(), &mut |_| true).unwrap();
    assert_eq!(digests, hash_bytes(&bytes));
    assert_eq!(head.len(), 8192);
    assert!(verify_file(&path, &VerifyFileOptions::default(), &mut |_| false).is_err());
}
#[test]
fn file_audit_round_trip_rotation_torn_tail_and_tampering() {
    let dir = tempfile::tempdir().unwrap();
    let ids = IdGenerator::new();
    let store = ids.store_id();
    let chain = ids.chain_id();
    let options = AuditOptions {
        rotate_bytes: 1024,
        ..AuditOptions::default()
    };
    let log = AuditLog::open(dir.path(), Some(chain), store, "test", options.clone()).unwrap();
    assert!(AuditLog::open(dir.path(), Some(chain), store, "test", options.clone()).is_err());
    for _ in 0..8 {
        log.append(AuditEntry::new(
            Timestamp::now(),
            Actor::system(),
            actions::DAEMON_STARTED,
            AuditOutcome::Ok,
        ))
        .unwrap();
    }
    let head = log.head().unwrap();
    drop(log);
    let report = verify_dir(
        dir.path(),
        &VerifyOptions {
            journal_head: head.clone(),
            ..VerifyOptions::default()
        },
    )
    .unwrap();
    assert_eq!(report.head, head);
    let mut files: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "jsonl"))
        .collect();
    files.sort();
    assert!(files.len() > 1);
    use std::io::Write;
    std::fs::OpenOptions::new()
        .append(true)
        .open(files.last().unwrap())
        .unwrap()
        .write_all(b"{torn")
        .unwrap();
    assert!(verify_dir(dir.path(), &VerifyOptions::default()).is_err());
    let log = AuditLog::open(dir.path(), Some(chain), store, "test", options).unwrap();
    drop(log);
    assert!(verify_dir(dir.path(), &VerifyOptions::default()).is_ok());
    let first = &files[0];
    let text = std::fs::read_to_string(first)
        .unwrap()
        .replace("daemon.started", "daemon.stopped");
    std::fs::write(first, text).unwrap();
    assert!(verify_dir(dir.path(), &VerifyOptions::default()).is_err());
}
#[test]
fn disguised_html_is_quarantined() {
    use zeus_verify::{content::*, quarantine::*};
    let (verdict, detected) = check_content(
        &InferDetector,
        b"<!DOCTYPE html><html>sign in</html>",
        &ContentClaim {
            file_name: "archive.zip",
            declared_mime: Some("application/zip"),
        },
    )
    .unwrap();
    let reasons = evaluate(
        &QuarantineInput {
            file_name: "archive.zip",
            verdict,
            detected: detected.as_ref(),
            origin: None,
            session_derived: false,
            av_flagged: false,
        },
        &QuarantinePolicy::default(),
    )
    .unwrap();
    assert!(reasons.contains(&zeus_types::QuarantineReason::HtmlDisguised));
}
