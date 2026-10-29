//! Retained engine filesystem acceptance on the native platform.
use std::path::Path;
use zeus_fs::{Filesystem, FsError, RetainedFs, WriteRoots};
fn setup() -> (tempfile::TempDir, RetainedFs) {
    let tmp = tempfile::tempdir().unwrap();
    let fs = RetainedFs::open(&WriteRoots::open(&[tmp.path().to_path_buf()]).unwrap()).unwrap();
    (tmp, fs)
}
#[test]
fn retained_files_publish_exact_opened_object_and_preserve_collisions() {
    let (tmp, fs) = setup();
    let part = tmp.path().join("a.zpart");
    let final_path = tmp.path().join("a");
    let file = fs.create_new(&part).unwrap();
    file.write_all_at(0, b"trusted").unwrap();
    std::fs::write(&final_path, b"foreign").unwrap();
    assert!(matches!(
        fs.publish_opened(&part, &final_path, file.as_ref()),
        Err(FsError::AlreadyExists)
    ));
    assert_eq!(std::fs::read(&final_path).unwrap(), b"foreign");
    std::fs::remove_file(&final_path).unwrap();
    fs.publish_opened(&part, &final_path, file.as_ref())
        .unwrap();
    let identity = file.file_id().unwrap();
    assert_eq!(
        fs.metadata(&final_path).unwrap().unwrap().file_id,
        Some(identity.clone())
    );
    drop(file);
    assert_eq!(
        fs.metadata(&final_path).unwrap().unwrap().file_id,
        Some(identity)
    );
    assert_eq!(std::fs::read(&final_path).unwrap(), b"trusted");
}
#[test]
fn retained_removal_requires_the_expected_identity() {
    let (tmp, fs) = setup();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    let original = fs.create_new(&a).unwrap().file_id().unwrap();
    std::fs::rename(&a, &b).unwrap();
    std::fs::write(&a, b"foreign").unwrap();
    assert!(fs.remove_expected(&a, &original).is_err());
    assert_eq!(std::fs::read(&a).unwrap(), b"foreign");
    fs.remove_expected(&b, &original).unwrap();
    assert!(!b.exists());
    assert!(fs.create_new(&tmp.path().join("../escape")).is_err());
    assert!(fs.create_new(&tmp.path().join("a:stream")).is_err());
}
#[test]
fn retained_file_keeps_its_parent_and_never_redirects_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    let moved = tmp.path().join("moved");
    std::fs::create_dir(&root).unwrap();
    let fs = RetainedFs::open(&WriteRoots::open(std::slice::from_ref(&root)).unwrap()).unwrap();
    fs.create_dir_all(&root.join("a/b")).unwrap();
    let file = fs.create_new(&root.join("a/b/data")).unwrap();
    #[cfg(windows)]
    assert!(std::fs::rename(&root, &moved).is_err());
    #[cfg(unix)]
    {
        std::fs::rename(&root, &moved).unwrap();
        std::fs::create_dir_all(root.join("a/b")).unwrap();
    }
    file.write_all_at(0, b"held").unwrap();
    #[cfg(unix)]
    {
        assert!(!root.join("a/b/data").exists());
        assert_eq!(std::fs::read(moved.join("a/b/data")).unwrap(), b"held");
    }
    #[cfg(windows)]
    assert_eq!(std::fs::read(root.join("a/b/data")).unwrap(), b"held");
}
#[test]
fn retained_provenance_and_free_space_use_held_objects() {
    let (tmp, fs) = setup();
    let path = tmp.path().join("data.zpart");
    let file = fs.create_new(&path).unwrap();
    let marks = zeus_fs::provenance::ProvenanceMarks {
        origin_url: None,
        referrer_url: None,
        retrieved_at_unix_s: 0,
    };
    let applied = fs
        .mark_opened(
            &path,
            file.as_ref(),
            &marks,
            zeus_types::OsMetadataMode::MarkOnly,
        )
        .unwrap();
    #[cfg(windows)]
    {
        assert_eq!(applied, vec![zeus_types::OsMetadataKind::ZoneIdentifier]);
        assert_eq!(
            std::fs::read(format!("{}:Zone.Identifier", path.display())).unwrap(),
            b"[ZoneTransfer]\r\nZoneId=3\r\n"
        );
    }
    #[cfg(not(windows))]
    let _ = applied;
    assert!(fs.free_space(tmp.path()).unwrap() > 0);
    assert!(fs.canonicalize(Path::new("relative")).is_err());
}
#[cfg(unix)]
#[test]
fn retained_paths_reject_intermediate_and_final_links() {
    let (tmp, fs) = setup();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("data"), b"keep").unwrap();
    std::os::unix::fs::symlink(outside.path(), tmp.path().join("junction")).unwrap();
    std::os::unix::fs::symlink(outside.path().join("data"), tmp.path().join("link")).unwrap();
    assert!(fs.open_read(&tmp.path().join("junction/data")).is_err());
    assert!(fs.open_existing(&tmp.path().join("link")).is_err());
    assert!(fs.remove_file(&tmp.path().join("link")).is_err());
    assert_eq!(std::fs::read(outside.path().join("data")).unwrap(), b"keep");
}

#[test]
fn application_trash_rechecks_payload_identity_after_restart() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("original");
    std::fs::write(&original, b"owned").unwrap();
    let root = temp.path().join("trash");
    let trash = zeus_fs::trash::Trash::new(root.clone());
    let entry = trash
        .trash(&original, zeus_types::Timestamp::now())
        .unwrap();
    drop(trash);
    let replaced = entry.trash_path.with_file_name("kept-original");
    std::fs::rename(&entry.trash_path, &replaced).unwrap();
    std::fs::write(&entry.trash_path, b"foreign").unwrap();
    let trash = zeus_fs::trash::Trash::new(root);
    assert_eq!(trash.entries().unwrap(), vec![entry.clone()]);
    assert!(trash.restore(&entry).is_err());
    assert!(
        trash
            .purge_older_than(
                std::time::Duration::ZERO,
                zeus_types::Timestamp::now()
                    .checked_add(std::time::Duration::from_secs(1))
                    .unwrap()
            )
            .is_err()
    );
    assert_eq!(std::fs::read(&entry.trash_path).unwrap(), b"foreign");
    assert_eq!(std::fs::read(&replaced).unwrap(), b"owned");
    assert!(!original.exists());
}
#[test]
fn application_trash_refuses_a_replaced_original_parent() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("parent");
    std::fs::create_dir(&parent).unwrap();
    let original = parent.join("original");
    std::fs::write(&original, b"owned").unwrap();
    let trash = zeus_fs::trash::Trash::new(temp.path().join("trash"));
    let entry = trash
        .trash(&original, zeus_types::Timestamp::now())
        .unwrap();
    std::fs::rename(&parent, temp.path().join("old-parent")).unwrap();
    std::fs::create_dir(&parent).unwrap();
    assert!(trash.restore(&entry).is_err());
    assert!(!original.exists());
    assert_eq!(std::fs::read(entry.trash_path).unwrap(), b"owned");
}
#[test]
fn application_trash_purge_requires_an_explicit_call_and_expected_object() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("original");
    std::fs::write(&original, b"owned").unwrap();
    let root = temp.path().join("trash");
    let now = zeus_types::Timestamp::parse("2026-10-01T00:00:00.000Z").unwrap();
    let trash = zeus_fs::trash::Trash::new(root.clone());
    let entry = trash.trash(&original, now).unwrap();
    drop(trash);
    let trash = zeus_fs::trash::Trash::new(root);
    assert!(entry.trash_path.exists());
    let later = zeus_types::Timestamp::parse("2026-10-29T00:00:00.000Z").unwrap();
    assert_eq!(
        trash
            .purge_older_than(std::time::Duration::from_secs(86400), later)
            .unwrap(),
        1
    );
    assert!(!entry.trash_path.exists());
    assert!(trash.entries().unwrap().is_empty());
}

#[test]
fn retained_roots_refuse_substitution_after_policy_admission() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let admitted = WriteRoots::open(std::slice::from_ref(&root)).unwrap();
    std::fs::rename(&root, temp.path().join("old-root")).unwrap();
    std::fs::create_dir(&root).unwrap();
    assert!(matches!(
        RetainedFs::open(&admitted),
        Err(FsError::OutsideRoots)
    ));
}

#[cfg(unix)]
#[test]
#[ignore = "requires ZEUS_TEST_SECOND_VOLUME on a different mounted filesystem"]
fn application_trash_cross_volume_copy_restore_and_collision() {
    use std::os::unix::fs::MetadataExt;
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir_in(
        std::env::var_os("ZEUS_TEST_SECOND_VOLUME").expect("explicit second-volume fixture"),
    )
    .unwrap();
    assert_ne!(
        std::fs::metadata(first.path()).unwrap().dev(),
        std::fs::metadata(second.path()).unwrap().dev(),
        "fixture must cross actual filesystems"
    );
    let original = first.path().join("file");
    std::fs::write(&original, b"cross-volume payload").unwrap();
    let original_id = zeus_fs::DirectoryCap::open_root(first.path())
        .unwrap()
        .entry_metadata(std::ffi::OsStr::new("file"))
        .unwrap()
        .file_id;
    let trash_dir = second.path().join("trash");
    let trash = zeus_fs::trash::Trash::new(trash_dir.clone());
    let entry = trash
        .trash(&original, zeus_types::Timestamp::now())
        .unwrap();
    assert!(!original.exists());
    assert_eq!(
        std::fs::read(&entry.trash_path).unwrap(),
        b"cross-volume payload"
    );
    assert!(entry.trash_path.with_extension("copy.json").is_file());
    let copied_id = zeus_fs::DirectoryCap::open_root(entry.trash_path.parent().unwrap())
        .unwrap()
        .entry_metadata(entry.trash_path.file_name().unwrap())
        .unwrap()
        .file_id;
    assert_ne!(original_id, copied_id);
    drop(trash);
    let restarted = zeus_fs::trash::Trash::new(trash_dir);
    assert_eq!(
        restarted.receipt_state(&entry).unwrap(),
        zeus_fs::trash::TrashReceiptState::IdentityBound
    );
    std::fs::write(&original, b"foreign occupant").unwrap();
    assert!(matches!(
        restarted.restore(&entry),
        Err(FsError::AlreadyExists)
    ));
    assert_eq!(std::fs::read(&original).unwrap(), b"foreign occupant");
    assert_eq!(
        std::fs::read(&entry.trash_path).unwrap(),
        b"cross-volume payload"
    );
    std::fs::remove_file(&original).unwrap();
    restarted.restore(&entry).unwrap();
    assert_eq!(std::fs::read(&original).unwrap(), b"cross-volume payload");
    assert!(!entry.trash_path.exists());
    assert!(!entry.trash_path.with_extension("json").exists());
    assert!(!entry.trash_path.with_extension("copy.json").exists());
    assert!(restarted.entries().unwrap().is_empty());
}
