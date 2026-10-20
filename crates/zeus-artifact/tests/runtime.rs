//! Content identity, lifecycle, isolation, and crash recovery regressions.
use std::sync::Arc;
use zeus_artifact::*;
use zeus_control::ManualClock;
use zeus_fs::RealFs;
use zeus_types::{OsMetadataMode, Timestamp};
fn open(root: &std::path::Path, writes: Vec<std::path::PathBuf>, quota: u64) -> ArtifactStore {
    ArtifactStore::open(
        root,
        StoreConfig {
            quota_bytes: Some(quota),
            min_free_bytes: 0,
            write_roots: writes,
            gc_grace: std::time::Duration::ZERO,
            ..StoreConfig::default()
        },
        Arc::new(RealFs),
        Arc::new(ManualClock::new(Timestamp::UNIX_EPOCH)),
        None,
    )
    .unwrap()
}
fn draft() -> ArtifactDraft {
    ArtifactDraft::local("zeus", "0.1.0", Some("file.bin".into()))
}
#[test]
fn ingest_deduplicates_content_but_preserves_provenance_and_first_key() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    std::fs::write(&source, b"content").unwrap();
    let root = dir.path().join("store");
    let store = open(&root, vec![], 1000);
    let first = store
        .ingest(&source, draft(), Some("zeus.test:first"))
        .unwrap();
    let second = store
        .ingest(&source, draft(), Some("zeus.test:second"))
        .unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(first.digests(), second.digests());
    assert_eq!(first.object.state, ObjectState::Present);
    std::fs::write(&source, b"changed").unwrap();
    assert_eq!(
        store
            .ingest(&source, draft(), Some("zeus.test:first"))
            .unwrap()
            .id,
        first.id
    );
    assert_eq!(
        std::fs::read(store.object_path(first.blake3)).unwrap(),
        b"content"
    );
    assert!(
        ArtifactStore::open(
            &root,
            StoreConfig::default(),
            Arc::new(RealFs),
            Arc::new(ManualClock::new(Timestamp::UNIX_EPOCH)),
            None
        )
        .is_err()
    );
    drop(store);
    assert_eq!(
        open(&root, vec![], 1000).get(first.id).unwrap().sha256,
        first.sha256
    );
}
#[test]
fn copies_are_independent_and_quarantine_and_roots_are_enforced() {
    let dir = tempfile::tempdir().unwrap();
    let writes = dir.path().join("downloads");
    std::fs::create_dir(&writes).unwrap();
    let source = dir.path().join("source");
    std::fs::write(&source, b"safe bytes").unwrap();
    let store = open(&dir.path().join("store"), vec![writes.clone()], 1000);
    let mut d = draft();
    d.record.quarantined = true;
    d.record
        .quarantine_reasons
        .push(zeus_types::QuarantineReason::ExecutableType);
    let a = store.ingest(&source, d, None).unwrap();
    let out = writes.join("copy.bin");
    assert!(matches!(
        store.materialize(
            a.id,
            &out,
            &[MaterializeMode::Copy],
            OsMetadataMode::Off,
            false
        ),
        Err(ArtifactError::QuarantineBlocked)
    ));
    store
        .materialize(
            a.id,
            &out,
            &[MaterializeMode::Copy],
            OsMetadataMode::Off,
            true,
        )
        .unwrap();
    std::fs::write(&out, b"edited").unwrap();
    assert_eq!(
        std::fs::read(store.object_path(a.blake3)).unwrap(),
        b"safe bytes"
    );
    assert!(
        store
            .materialize(
                a.id,
                &dir.path().join("escape"),
                &[MaterializeMode::Copy],
                OsMetadataMode::Off,
                true
            )
            .is_err()
    );
    assert!(
        store
            .materialize(
                a.id,
                &out,
                &[MaterializeMode::Copy],
                OsMetadataMode::Off,
                true
            )
            .is_err()
    );
}
#[test]
fn import_checks_both_digests_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    std::fs::write(&source, b"artifact").unwrap();
    let a = open(&dir.path().join("a"), vec![], 1000);
    let b = open(&dir.path().join("b"), vec![], 1000);
    let artifact = a.ingest(&source, draft(), None).unwrap();
    let exported =
        serde_json::to_value(a.export(artifact.id, &Privacy::default()).unwrap()).unwrap();
    let imported = b
        .import(&exported, Some(&source), "zeus", "api", Retention::Keep)
        .unwrap();
    assert_eq!(imported.digests(), artifact.digests());
    assert_ne!(imported.id, artifact.id);
    assert_eq!(imported.imports.len(), 1);
    assert_eq!(
        b.import(&exported, None, "zeus", "api", Retention::Keep)
            .unwrap()
            .id,
        imported.id
    );
    let c = open(&dir.path().join("c"), vec![], 1000);
    std::fs::write(&source, b"tampered").unwrap();
    assert!(matches!(
        c.import(&exported, Some(&source), "zeus", "api", Retention::Keep),
        Err(ArtifactError::DigestMismatch)
    ));
    let record_only = c
        .import(&exported, None, "zeus", "api", Retention::Keep)
        .unwrap();
    assert_eq!(record_only.object.state, ObjectState::Absent);
    assert_eq!(
        record_only.verification.state,
        VerificationState::Unverified
    );
}
#[test]
fn scrub_damage_repair_gc_preserves_user_files_and_kept_objects() {
    use zeus_fs::Filesystem;
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    std::fs::write(&source, b"original").unwrap();
    let store = open(&dir.path().join("store"), vec![], 1000);
    let a = store.ingest(&source, draft(), None).unwrap();
    let object = store.object_path(a.blake3);
    RealFs.set_readonly(&object, false).unwrap();
    std::fs::write(&object, b"tampered").unwrap();
    store.scrub_step(10).unwrap();
    assert_eq!(store.get(a.id).unwrap().object.state, ObjectState::Damaged);
    store.repair_from_file(a.id, &source).unwrap();
    assert_eq!(store.get(a.id).unwrap().object.state, ObjectState::Present);
    store.set_retention(a.id, Retention::Keep, None).unwrap();
    assert_eq!(store.collect_step(true, 10).unwrap(), 0);
    store.delete(a.id).unwrap();
    assert_eq!(store.collect_step(false, 10).unwrap(), 8);
    assert_eq!(std::fs::read(source).unwrap(), b"original");
    assert_eq!(store.get(a.id).unwrap().state, ArtifactState::Deleted);
}
#[test]
fn quota_and_untrusted_lineage_fail_without_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    std::fs::write(&source, b"too large").unwrap();
    let store = open(&dir.path().join("store"), vec![], 3);
    assert!(matches!(
        store.ingest(&source, draft(), None),
        Err(ArtifactError::QuotaExceeded)
    ));
    assert!(store.list(&ArtifactFilter::default()).unwrap().is_empty());
    let mut d = draft();
    d.record.origin = ArtifactOrigin::Derived;
    d.record.produced_at = Some(Timestamp::UNIX_EPOCH);
    d.record.parents.push(ParentRef {
        artifact_id: Some(zeus_types::IdGenerator::new().artifact_id()),
        blake3: zeus_types::Hex256::from_bytes([0; 32]),
        sha256: zeus_types::Hex256::from_bytes([0; 32]),
        size_bytes: 0,
        role: "input".into(),
    });
    assert!(matches!(
        store.ingest_record_only(zeus_verify::hash_bytes(b""), d, None, None),
        Err(ArtifactError::LineageInvalid)
    ));
}

#[test]
fn newest_first_listing_bounds_kept_records_only() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let store = open(&dir.path().join("store"), vec![], 1000);
    for content in [&b"one"[..], b"two", b"three", b"four"] {
        std::fs::write(&source, content).unwrap();
        store.ingest(&source, draft(), None).unwrap();
    }
    let mut ids: Vec<_> = store
        .list(&ArtifactFilter::default())
        .unwrap()
        .into_iter()
        .map(|a| a.id)
        .collect();
    ids.reverse();
    let bounded = ArtifactFilter {
        limit: 2,
        ..ArtifactFilter::default()
    };
    let newest: Vec<_> = store
        .list_newest_where(&bounded, |_| true)
        .unwrap()
        .into_iter()
        .map(|a| a.id)
        .collect();
    assert_eq!(newest, ids[..2]);
    // A record the caller drops does not use up the bound.
    let kept: Vec<_> = store
        .list_newest_where(&bounded, |a| a.id != ids[0])
        .unwrap()
        .into_iter()
        .map(|a| a.id)
        .collect();
    assert_eq!(kept, ids[1..3]);
}

#[derive(Debug)]
struct CrashFs {
    stage: usize,
    fail: std::sync::atomic::AtomicBool,
    reads: std::sync::atomic::AtomicUsize,
}
impl zeus_fs::Filesystem for CrashFs {
    fn create_new(&self, p: &std::path::Path) -> zeus_fs::FsResult<Box<dyn zeus_fs::DataFile>> {
        zeus_fs::Filesystem::create_new(&RealFs, p)
    }
    fn open_existing(&self, p: &std::path::Path) -> zeus_fs::FsResult<Box<dyn zeus_fs::DataFile>> {
        zeus_fs::Filesystem::open_existing(&RealFs, p)
    }
    fn open_read(&self, p: &std::path::Path) -> zeus_fs::FsResult<Box<dyn zeus_fs::DataFile>> {
        self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        zeus_fs::Filesystem::open_read(&RealFs, p)
    }
    fn set_readonly(&self, p: &std::path::Path, r: bool) -> zeus_fs::FsResult<()> {
        zeus_fs::Filesystem::set_readonly(&RealFs, p, r)
    }
    fn metadata(&self, p: &std::path::Path) -> zeus_fs::FsResult<Option<zeus_fs::FileMeta>> {
        zeus_fs::Filesystem::metadata(&RealFs, p)
    }
    fn rename_noreplace(&self, a: &std::path::Path, b: &std::path::Path) -> zeus_fs::FsResult<()> {
        if self.stage == 1
            && b.components().any(|c| c.as_os_str() == "objects")
            && self.fail.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(
                std::io::Error::other("simulated interruption after durable intent").into(),
            );
        }
        zeus_fs::Filesystem::rename_noreplace(&RealFs, a, b)
    }
    fn replace_with_backup(
        &self,
        a: &std::path::Path,
        b: &std::path::Path,
        c: &std::path::Path,
    ) -> zeus_fs::FsResult<()> {
        zeus_fs::Filesystem::replace_with_backup(&RealFs, a, b, c)
    }
    fn sync_dir(&self, p: &std::path::Path) -> zeus_fs::FsResult<()> {
        if self.stage == 2
            && p.components().any(|c| c.as_os_str() == "objects")
            && std::fs::read_dir(p)?.any(|e| e.is_ok_and(|e| e.path().is_file()))
            && self.fail.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            return Err(std::io::Error::other("simulated interruption after object rename").into());
        }
        zeus_fs::Filesystem::sync_dir(&RealFs, p)
    }
    fn remove_file(&self, p: &std::path::Path) -> zeus_fs::FsResult<()> {
        zeus_fs::Filesystem::remove_file(&RealFs, p)
    }
    fn create_dir_all(&self, p: &std::path::Path) -> zeus_fs::FsResult<()> {
        zeus_fs::Filesystem::create_dir_all(&RealFs, p)
    }
    fn read_dir(&self, p: &std::path::Path) -> zeus_fs::FsResult<Vec<zeus_fs::DirEntryInfo>> {
        zeus_fs::Filesystem::read_dir(&RealFs, p)
    }
    fn free_space(&self, p: &std::path::Path) -> zeus_fs::FsResult<u64> {
        zeus_fs::Filesystem::free_space(&RealFs, p)
    }
    fn canonicalize(&self, p: &std::path::Path) -> zeus_fs::FsResult<std::path::PathBuf> {
        zeus_fs::Filesystem::canonicalize(&RealFs, p)
    }
    fn is_case_insensitive(&self, p: &std::path::Path) -> zeus_fs::FsResult<bool> {
        zeus_fs::Filesystem::is_case_insensitive(&RealFs, p)
    }
}
#[test]
fn ingest_recovers_both_sides_of_rename_without_reading_content() {
    use std::sync::atomic::Ordering;
    for stage in [1, 2] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("store");
        let source = dir.path().join("source");
        std::fs::write(&source, b"crash safe").unwrap();
        let fs = Arc::new(CrashFs {
            stage,
            fail: std::sync::atomic::AtomicBool::new(true),
            reads: std::sync::atomic::AtomicUsize::new(0),
        });
        let config = StoreConfig {
            min_free_bytes: 0,
            ..StoreConfig::default()
        };
        let clock = Arc::new(ManualClock::new(Timestamp::UNIX_EPOCH));
        let store =
            ArtifactStore::open(&root, config.clone(), fs.clone(), clock.clone(), None).unwrap();
        assert!(
            store
                .ingest(&source, draft(), Some("zeus.test:crash"))
                .is_err()
        );
        drop(store);
        let reads = fs.reads.load(Ordering::SeqCst);
        let store =
            ArtifactStore::open(&root, config.clone(), fs.clone(), clock.clone(), None).unwrap();
        assert_eq!(
            fs.reads.load(Ordering::SeqCst),
            reads,
            "recovery must not hash bytes"
        );
        let records = store.list(&ArtifactFilter::default()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(
            std::fs::read(store.object_path(records[0].blake3)).unwrap(),
            b"crash safe"
        );
        let id = records[0].id;
        drop(store);
        let store = ArtifactStore::open(&root, config, fs, clock, None).unwrap();
        assert_eq!(store.list(&ArtifactFilter::default()).unwrap()[0].id, id);
    }
}
