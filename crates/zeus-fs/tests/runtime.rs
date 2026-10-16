//! Hermetic storage and crash-recovery regressions.
use zeus_fs::finalize::{FinalizePlan, rename_into_place};
use zeus_fs::{Filesystem, RealFs, SafeRoot, SanitizeOptions, sanitize_filename};
use zeus_types::Overwrite;

#[test]
fn positional_writes_durable_finalize_and_no_clobber() {
    let dir = tempfile::tempdir().unwrap();
    let fs = RealFs;
    let tmp = dir.path().join("data.zpart");
    let dest = dir.path().join("data.bin");
    let file = fs.create_new(&tmp).unwrap();
    file.set_len(6).unwrap();
    file.write_all_at(3, b"def").unwrap();
    file.write_all_at(0, b"abc").unwrap();
    file.sync_data().unwrap();
    let id = file.file_id().unwrap();
    let mut bytes = [0; 6];
    file.read_exact_at(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"abcdef");
    drop(file);
    std::fs::write(&dest, b"foreign").unwrap();
    let plan = FinalizePlan {
        tmp_path: tmp.clone(),
        dest_path: dest.clone(),
        overwrite: Overwrite::Fail,
        backup_path: None,
    };
    assert!(matches!(
        rename_into_place(&fs, &plan),
        Err(zeus_fs::FsError::AlreadyExists)
    ));
    assert_eq!(std::fs::read(&dest).unwrap(), b"foreign");
    let result = rename_into_place(
        &fs,
        &FinalizePlan {
            overwrite: Overwrite::Rename,
            ..plan
        },
    )
    .unwrap();
    assert_ne!(result.final_path, dest);
    assert_eq!(std::fs::read(&result.final_path).unwrap(), b"abcdef");
    assert_eq!(
        fs.open_existing(&result.final_path)
            .unwrap()
            .file_id()
            .unwrap(),
        id
    );
}

#[test]
fn root_and_filename_containment() {
    let dir = tempfile::tempdir().unwrap();
    let root = SafeRoot::open(dir.path()).unwrap();
    for path in [
        "../escape",
        "a/../escape",
        "a:b",
        "a\\b",
        "/tmp/outside",
        "a//b",
    ] {
        assert!(
            root.join_checked(std::path::Path::new(path)).is_err(),
            "{path}"
        );
    }
    assert!(
        root.check_existing(
            &root
                .join_checked(std::path::Path::new("new/file.bin"))
                .unwrap()
        )
        .is_ok()
    );
    for raw in [
        "CON.txt",
        "invoice.pdf.exe",
        "../../a.zip",
        "a:b.txt",
        "nul",
        "a\u{202e}txt",
    ] {
        let safe = sanitize_filename(raw, &SanitizeOptions::default())
            .unwrap()
            .name;
        assert!(!safe.contains(['/', '\\', ':']));
        assert!(safe.len() <= 255);
        assert_ne!(safe, "nul");
    }
}

#[cfg(unix)]
#[test]
fn symlink_to_outside_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
    let root = SafeRoot::open(dir.path()).unwrap();
    assert!(
        root.check_existing(&dir.path().join("escape/file"))
            .is_err()
    );
    std::fs::write(outside.path().join("target"), b"secret").unwrap();
    std::os::unix::fs::symlink(outside.path().join("target"), dir.path().join("link")).unwrap();
    assert!(RealFs.open_existing(&dir.path().join("link")).is_err());
}

#[test]
fn trash_restore_keeps_foreign_destination() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keep.bin");
    std::fs::write(&path, b"original").unwrap();
    let trash = zeus_fs::trash::Trash::new(dir.path().join("trash"));
    let entry = trash.trash(&path, zeus_types::Timestamp::now()).unwrap();
    assert!(!path.exists());
    assert_eq!(trash.entries().unwrap(), vec![entry.clone()]);
    std::fs::write(&path, b"foreign").unwrap();
    assert!(trash.restore(&entry).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"foreign");
    std::fs::remove_file(&path).unwrap();
    trash.restore(&entry).unwrap();
    assert_eq!(std::fs::read(path).unwrap(), b"original");
}

#[test]
fn immutable_file_supports_identity_reads_rename_and_explicit_unseal() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("sealed.zpart");
    let dest = dir.path().join("sealed");
    let fs = RealFs;
    let file = fs.create_new(&source).expect("create");
    file.write_all_at(0, b"immutable").expect("write");
    file.sync_all().expect("sync");
    let identity = file.file_id().expect("identity before seal");
    drop(file);
    fs.set_readonly(&source, true).expect("set readonly");
    assert_eq!(
        fs.open_read(&source)
            .expect("readonly open")
            .file_id()
            .expect("readonly identity"),
        identity
    );
    assert_eq!(
        fs.metadata(&source)
            .expect("readonly metadata")
            .unwrap()
            .file_id,
        Some(identity.clone())
    );
    fs.rename_noreplace(&source, &dest)
        .expect("readonly rename");
    assert_eq!(
        fs.metadata(&dest)
            .expect("renamed metadata")
            .unwrap()
            .file_id,
        Some(identity)
    );
    fs.set_readonly(&dest, false).expect("unseal");
    fs.remove_file(&dest).expect("delete");
}
