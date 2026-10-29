//! Bundle validation precedes mutation; exact collection protects current references and unrelated files.
use std::{path::Path, sync::Arc};
use zeus_artifact::*;
use zeus_control::ManualClock;
use zeus_fs::RealFs;
use zeus_types::{IdGenerator, Timestamp};
use zeus_verify::{audit::MemoryAuditLog, canonical::to_jcs_bytes, provenance::UrlQueryPrivacy};
fn open(path: &Path, quota: u64) -> ArtifactStore {
    let ids = IdGenerator::new();
    let audit = Arc::new(MemoryAuditLog::new(
        ids.chain_id(),
        ids.store_id(),
        "test",
        Timestamp::UNIX_EPOCH,
        None,
    ));
    ArtifactStore::open(
        path,
        StoreConfig {
            quota_bytes: Some(quota),
            min_free_bytes: 0,
            gc_grace: std::time::Duration::ZERO,
            ..StoreConfig::default()
        },
        Arc::new(RealFs),
        Arc::new(ManualClock::new(Timestamp::UNIX_EPOCH)),
        Some(audit),
    )
    .unwrap()
}
fn record(store: &ArtifactStore, path: &Path, bytes: &[u8]) -> Artifact {
    std::fs::write(path, bytes).unwrap();
    store
        .ingest(
            path,
            ArtifactDraft::local("zeus", "test", Some("report.txt".into())),
            None,
        )
        .unwrap()
}
fn privacy() -> Privacy {
    Privacy {
        url_query: UrlQueryPrivacy::Dropped,
        session_origin_included: false,
    }
}
fn bytes(bundle: &ArtifactBundle) -> Vec<u8> {
    let mut b = vec![];
    bundle.write(&mut b).unwrap();
    b
}
fn rewrite(bundle: &ArtifactBundle, f: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let b = bytes(bundle);
    let n = u32::from_le_bytes(b[8..12].try_into().unwrap()) as usize;
    let mut m: serde_json::Value = serde_json::from_slice(&b[12..12 + n]).unwrap();
    f(&mut m);
    let j = to_jcs_bytes(&m).unwrap();
    let mut out = b[..8].to_vec();
    out.extend_from_slice(&(j.len() as u32).to_le_bytes());
    out.extend(j);
    out.extend_from_slice(&b[12 + n..]);
    out
}
#[test]
fn bundles_verify_bytes_keep_retention_and_evidence_and_replay_without_rewriting() {
    let d = tempfile::tempdir().unwrap();
    let source = open(&d.path().join("source"), 10000);
    let r = record(&source, &d.path().join("input"), b"verified report");
    let deadline = Timestamp::UNIX_EPOCH.saturating_add_ms(60_000);
    source
        .set_retention(r.id, Retention::Keep, Some(deadline))
        .unwrap();
    let bundle = source.export_bundle(&[r.id], true, &privacy()).unwrap();
    let imported = ArtifactBundle::read(bytes(&bundle).as_slice()).unwrap();
    assert_eq!(bundle.summary(), imported.summary());
    let dst = open(&d.path().join("destination"), 10000);
    let rows = dst.import_bundle(&imported).unwrap();
    assert_eq!(rows[0].digests(), r.digests());
    assert_eq!(rows[0].retention, Retention::Keep);
    assert_eq!(rows[0].retain_until, Some(deadline));
    assert_eq!(rows[0].imports.len(), 1);
    assert_eq!(
        std::fs::read(dst.object_path(r.blake3)).unwrap(),
        b"verified report"
    );
    assert_eq!(dst.import_bundle(&imported).unwrap()[0].id, rows[0].id);
    assert_eq!(dst.list(&ArtifactFilter::default()).unwrap().len(), 1);
    assert!(source.import_bundle(&imported).is_err());
    // Immutable source evidence disagrees, even though both content hashes still match.
    let changed = ArtifactBundle::parse(rewrite(&bundle, |v| {
        v["records"][0]["name"] = "different.txt".into()
    }))
    .unwrap();
    assert!(matches!(
        dst.import_bundle(&changed),
        Err(ArtifactError::ImportConflict)
    ));
    assert_eq!(
        dst.get(rows[0].id).unwrap().name.as_deref(),
        Some("report.txt")
    );
}
#[test]
fn malformed_members_corruption_compression_and_bounds_fail_before_store_effects() {
    let d = tempfile::tempdir().unwrap();
    let source = open(&d.path().join("source"), 10000);
    let r = record(&source, &d.path().join("input"), b"abc");
    let b = source.export_bundle(&[r.id], true, &privacy()).unwrap();
    for name in [
        "../escape",
        "/absolute",
        "objects/../x",
        "objects\\x",
        "C:stream",
        "objects/abc",
    ] {
        assert!(
            ArtifactBundle::parse(rewrite(&b, |v| v["objects"][0]["name"] = name.into())).is_err()
        );
    }
    assert!(
        ArtifactBundle::parse(rewrite(&b, |v| v["objects"][0]["type"] = "symlink".into())).is_err()
    );
    assert!(
        ArtifactBundle::parse(rewrite(&b, |v| {
            let o = v["objects"][0].clone();
            v["objects"].as_array_mut().unwrap().push(o);
        }))
        .is_err()
    );
    assert!(
        ArtifactBundle::parse(rewrite(&b, |v| v["objects"][0]["size_bytes"] = (u64::MAX).into()))
            .is_err()
    );
    assert!(ArtifactBundle::parse(rewrite(&b, |v| v["version"] = 2.into())).is_err());
    let mut corrupt = bytes(&b);
    *corrupt.last_mut().unwrap() ^= 1;
    assert!(matches!(
        ArtifactBundle::parse(corrupt),
        Err(ArtifactError::DigestMismatch)
    ));
    let mut trailing = bytes(&b);
    trailing.push(0);
    assert!(ArtifactBundle::parse(trailing).is_err());
    assert!(ArtifactBundle::read(std::io::repeat(0)).is_err());
    assert!(ArtifactBundle::read(&b"\x1f\x8bgzip"[..]).is_err());
    let dst = open(&d.path().join("destination"), 2);
    assert!(matches!(
        dst.import_bundle(&b),
        Err(ArtifactError::QuotaExceeded)
    ));
    assert!(dst.list(&ArtifactFilter::default()).unwrap().is_empty());
}
#[test]
fn quarantine_can_cross_only_as_metadata_and_deleted_records_never_resurrect() {
    let d = tempfile::tempdir().unwrap();
    let source = open(&d.path().join("source"), 10000);
    let path = d.path().join("input");
    std::fs::write(&path, b"quarantine").unwrap();
    let mut draft = ArtifactDraft::local("zeus", "test", None);
    draft.record.quarantined = true;
    draft
        .record
        .quarantine_reasons
        .push(zeus_types::QuarantineReason::ExecutableType);
    let r = source.ingest(&path, draft, None).unwrap();
    assert!(matches!(
        source.export_bundle(&[r.id], true, &privacy()),
        Err(ArtifactError::QuarantineBlocked)
    ));
    let b = source.export_bundle(&[r.id], false, &privacy()).unwrap();
    assert!(b.summary().objects.is_empty());
    let dst = open(&d.path().join("dst"), 10000);
    let r = dst.import_bundle(&b).unwrap().remove(0);
    assert!(r.quarantined);
    assert_eq!(r.object.state, ObjectState::Absent);
    assert_eq!(r.verification.state, VerificationState::Unverified);
    dst.delete(r.id).unwrap();
    assert!(dst.export_bundle(&[r.id], false, &privacy()).is_err());
}
#[test]
fn collection_is_exact_retention_aware_and_restart_replay_safe() {
    let d = tempfile::tempdir().unwrap();
    let path = d.path().join("store");
    let store = open(&path, 10000);
    let input = d.path().join("input");
    let a = record(&store, &input, b"one");
    let b = record(&store, &input, b"two");
    store
        .set_retention(a.id, Retention::Evictable, None)
        .unwrap();
    store
        .set_retention(b.id, Retention::Evictable, None)
        .unwrap();
    let plan = store.collection_preview(true, 128).unwrap();
    assert_eq!(plan.objects.len(), 2);
    store.set_retention(b.id, Retention::Keep, None).unwrap();
    assert!(store.collection_apply(&plan, false).is_err());
    assert!(store.object_path(a.blake3).exists());
    let plan = store.collection_preview(true, 128).unwrap();
    assert_eq!(plan.objects.len(), 1);
    assert_eq!(store.collection_apply(&plan, false).unwrap(), 3);
    assert!(!store.object_path(a.blake3).exists());
    assert!(store.object_path(b.blake3).exists());
    assert_eq!(std::fs::read(&input).unwrap(), b"two");
    drop(store);
    let store = open(&path, 10000);
    assert_eq!(store.collection_apply(&plan, true).unwrap(), 0);
    assert!(store.collection_apply(&plan, false).is_err());
    assert_eq!(store.get(a.id).unwrap().state, ArtifactState::Active);
}
#[test]
fn collection_refuses_replaced_objects_and_does_not_select_new_eligible_content() {
    let d = tempfile::tempdir().unwrap();
    let store = open(&d.path().join("store"), 10000);
    let a = record(&store, &d.path().join("input"), b"first");
    store
        .set_retention(a.id, Retention::Evictable, None)
        .unwrap();
    let plan = store.collection_preview(true, 1).unwrap();
    let b = record(&store, &d.path().join("input"), b"second");
    store
        .set_retention(b.id, Retention::Evictable, None)
        .unwrap();
    let original = store.object_path(a.blake3);
    let moved = d.path().join("held-original");
    std::fs::rename(&original, &moved).unwrap();
    std::fs::write(&original, b"first").unwrap();
    assert!(store.collection_apply(&plan, false).is_err());
    assert_eq!(std::fs::read(&original).unwrap(), b"first");
    assert!(store.object_path(b.blake3).exists());
}

#[test]
fn repair_from_validated_bytes_never_changes_identity_and_rechecks_present_content() {
    let d = tempfile::tempdir().unwrap();
    let store = open(&d.path().join("store"), 10000);
    let digests = zeus_verify::hash::hash_bytes(b"recoverable");
    let record = store
        .ingest_record_only(
            digests,
            ArtifactDraft::local("zeus", "test", None),
            None,
            None,
        )
        .unwrap();
    assert!(store.repair_from_bytes(record.id, b"different").is_err());
    assert_eq!(
        store.get(record.id).unwrap().object.state,
        ObjectState::Absent
    );
    store.repair_from_bytes(record.id, b"recoverable").unwrap();
    assert_eq!(store.get(record.id).unwrap().digests(), digests);
    assert_eq!(
        store.get(record.id).unwrap().object.state,
        ObjectState::Present
    );
    store.repair_from_bytes(record.id, b"recoverable").unwrap();
    let source = store.object_path(record.blake3);
    let moved = d.path().join("old-object");
    std::fs::rename(&source, moved).unwrap();
    std::fs::write(&source, b"tampered").unwrap();
    assert!(store.repair_from_bytes(record.id, b"recoverable").is_err());
    assert_eq!(std::fs::read(source).unwrap(), b"tampered");
}

#[test]
fn integrity_checks_exact_retained_targets_and_quarantines_truncated_bytes_without_losing_user_files()
 {
    let d = tempfile::tempdir().unwrap();
    let store = open(&d.path().join("store"), 10000);
    let a = record(&store, &d.path().join("source"), b"original complete bytes");
    let object = store.object_path(a.blake3);
    let held = d.path().join("original-object");
    std::fs::rename(&object, held).unwrap();
    std::fs::write(&object, b"bad").unwrap();
    let plan = store.integrity_preview(&[a.id]).unwrap();
    assert_eq!(plan.objects[0].observed_size, 3);
    let result = store.integrity_apply(&plan).unwrap();
    assert_eq!(result.damaged, vec![a.blake3]);
    assert_eq!(store.get(a.id).unwrap().object.state, ObjectState::Damaged);
    assert!(!object.exists());
    assert_eq!(
        std::fs::read(d.path().join("source")).unwrap(),
        b"original complete bytes"
    );
    assert_eq!(
        std::fs::read_dir(store.root().join("damaged"))
            .unwrap()
            .count(),
        1
    );
    assert!(store.integrity_apply(&plan).is_err());
    store
        .repair_from_bytes(a.id, b"original complete bytes")
        .unwrap();
    let plan = store.integrity_preview(&[a.id]).unwrap();
    assert_eq!(
        store.integrity_apply(&plan).unwrap().verified,
        vec![a.blake3]
    );
}
