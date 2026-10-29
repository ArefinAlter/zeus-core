//! Deletes go to the application trash, never straight to unlink (01 section 12.3 rule 4).
//!
//! The only exception is the partial data of a *canceled* job. The application trash lives under the
//! state directory (`<state>/trash/<yyyymmdd>/`, 03 section 3.1) with an undo journal of move records
//! so a destructive file operation can be reverted; the platform recycle bin (the `trash` crate) is
//! offered for files outside Zeus's own tree.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use zeus_types::{Hex256, Timestamp};

use crate::error::{FsError, FsResult};

/// One move into the trash: enough to restore the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrashEntry {
    /// Identifier of the entry (a random hex string), also the file name inside the trash day folder.
    pub id: String,
    /// Where the file was.
    pub original_path: PathBuf,
    /// Where it is now.
    pub trash_path: PathBuf,
    /// When it was trashed.
    pub trashed_at: Timestamp,
    /// SHA-256 of the content, when known, so a restore can verify it.
    pub sha256: Option<Hex256>,
}

/// Whether a recorded trash entry carries identity-bound authority for automated recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrashReceiptState {
    /// Both original parent and payload identities were recorded before the effect.
    IdentityBound,
    /// An older receipt remains visible, but cannot authorize restore or purge.
    LegacyManualRecovery,
}

/// The application trash with its undo journal. A retained root protects data paths after the
/// first explicit ambient root acquisition; records are bounded and opened relative to that root.
#[derive(Debug, Clone)]
pub struct Trash {
    dir: PathBuf,
    root: std::sync::Arc<std::sync::OnceLock<crate::DirectoryCap>>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    #[serde(flatten)]
    entry: TrashEntry,
    #[serde(default)]
    payload_id: Option<zeus_types::FileId>,
    #[serde(default)]
    parent_id: Option<zeus_types::FileId>,
}
fn missing(error: &FsError) -> bool {
    matches!(error, FsError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound)
}
fn os(name: &str) -> &std::ffi::OsStr {
    std::ffi::OsStr::new(name)
}
fn identity(meta: &crate::FileMeta) -> FsResult<&zeus_types::FileId> {
    meta.file_id.as_ref().ok_or(FsError::OutsideRoots)
}
impl Trash {
    /// A trash rooted at `dir` (normally `<state>/trash`), created on first use with mode 0700.
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            root: std::sync::Arc::new(std::sync::OnceLock::new()),
        }
    }
    /// The configured trash root.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
    fn root(&self, create: bool) -> FsResult<crate::DirectoryCap> {
        if let Some(root) = self.root.get() {
            return Ok(root.clone());
        }
        if !self.dir.is_absolute() {
            return Err(FsError::OutsideRoots);
        }
        let cap = if create {
            let mut ancestor = self.dir.as_path();
            let mut suffix = PathBuf::new();
            loop {
                match crate::DirectoryCap::open_root(ancestor) {
                    Ok(parent) => break parent.create_dir_all(&suffix)?,
                    Err(e) if missing(&e) => {
                        suffix = Path::new(ancestor.file_name().ok_or(FsError::OutsideRoots)?)
                            .join(suffix);
                        ancestor = ancestor.parent().ok_or(FsError::OutsideRoots)?;
                    }
                    Err(e) => return Err(e),
                }
            }
        } else {
            crate::DirectoryCap::open_root(&self.dir)?
        };
        let _ = self.root.set(cap);
        Ok(self.root.get().ok_or(FsError::OutsideRoots)?.clone())
    }
    /// Move an explicitly supplied ambient file into application trash. Callers with retained
    /// managed roots should use `trash_pinned`; this compatibility entry point captures its parent.
    pub fn trash(&self, path: &Path, now: Timestamp) -> FsResult<TrashEntry> {
        let parent_path = std::fs::canonicalize(path.parent().ok_or(FsError::OutsideRoots)?)?;
        let parent = crate::DirectoryCap::open_root(&parent_path)?;
        let name = path.file_name().ok_or(FsError::OutsideRoots)?;
        self.trash_pinned(&parent, name, &parent_path.join(name), now)
    }
    /// Trash through a caller-retained source parent. The durable intent precedes publication.
    /// Cross-volume copies are exclusive, bounded by the opened source length, checked for change,
    /// flushed and published without replacement before the expected original object is removed.
    pub fn trash_pinned(
        &self,
        source: &crate::DirectoryCap,
        name: &std::ffi::OsStr,
        original: &Path,
        now: Timestamp,
    ) -> FsResult<TrashEntry> {
        if !original.is_absolute() || original.file_name() != Some(name) {
            return Err(FsError::OutsideRoots);
        }
        let opened = source.prepare_rename(name)?;
        let meta = opened.metadata()?;
        if !meta.is_regular_file {
            return Err(FsError::SymlinkRefused);
        }
        let root = self.root(true)?;
        let day_name = day_folder(now);
        let day = root.create_dir_all(Path::new(&day_name))?;
        let id = zeus_types::IdGenerator::new().next_ulid().to_string();
        let entry = TrashEntry {
            id: id.clone(),
            original_path: original.to_path_buf(),
            trash_path: self.dir.join(&day_name).join(&id),
            trashed_at: now,
            sha256: None,
        };
        let record = Record {
            entry: entry.clone(),
            payload_id: Some(identity(&meta)?.clone()),
            parent_id: Some(source.file_id()?),
        };
        write_record(&day, &format!("{id}.json"), &record)?;
        match opened.rename_noreplace(&day, os(&id)) {
            Ok(()) => (),
            Err(FsError::Io { source: error, .. })
                if error.kind() == std::io::ErrorKind::CrossesDevices =>
            {
                copy_move(source, name, &day, os(&id), identity(&meta)?, |new_id| {
                    let mut copied = record.clone();
                    copied.payload_id = Some(new_id);
                    write_record(&day, &format!("{id}.copy.json"), &copied)
                })?;
            }
            Err(e) => return Err(e),
        }
        source.sync()?;
        day.sync()?;
        Ok(entry)
    }
    /// Restore an explicitly supplied journal entry, capturing its recorded ambient destination
    /// parent. Callers with managed roots use `restore_pinned` and retain their existing scope policy.
    pub fn restore(&self, entry: &TrashEntry) -> FsResult<PathBuf> {
        let parent = crate::DirectoryCap::open_root(
            entry.original_path.parent().ok_or(FsError::OutsideRoots)?,
        )?;
        self.restore_pinned(entry, &parent)
    }
    /// Restore only an exact journal entry and payload identity into its recorded parent object.
    pub fn restore_pinned(
        &self,
        entry: &TrashEntry,
        destination: &crate::DirectoryCap,
    ) -> FsResult<PathBuf> {
        let (day, record) = self.record(entry)?;
        let parent_id = record.parent_id.as_ref().ok_or(FsError::Unsupported(
            "legacy trash receipt has no parent identity; preserve for manual recovery",
        ))?;
        if parent_id != &destination.file_id()? {
            return Err(FsError::OutsideRoots);
        }
        let expected = record.payload_id.as_ref().ok_or(FsError::Unsupported(
            "legacy trash receipt has no file identity; preserve for manual recovery",
        ))?;
        let source = day.prepare_rename(os(&entry.id))?;
        if source.metadata()?.file_id.as_ref() != Some(expected) {
            return Err(FsError::OutsideRoots);
        }
        let name = entry
            .original_path
            .file_name()
            .ok_or(FsError::OutsideRoots)?;
        match source.rename_noreplace(destination, name) {
            Ok(()) => (),
            Err(FsError::Io { source: error, .. })
                if error.kind() == std::io::ErrorKind::CrossesDevices =>
            {
                copy_move(&day, os(&entry.id), destination, name, expected, |_| Ok(()))?;
            }
            Err(e) => return Err(e),
        }
        remove_record(&day, &entry.id)?;
        destination.sync()?;
        day.sync()?;
        Ok(entry.original_path.clone())
    }
    fn record(&self, entry: &TrashEntry) -> FsResult<(crate::DirectoryCap, Record)> {
        validate_entry(&self.dir, entry)?;
        let day = self
            .root(false)?
            .open_dir(Path::new(&day_folder(entry.trashed_at)))?;
        let mut record = read_record(&day, &format!("{}.json", entry.id))?;
        if record.entry != *entry {
            return Err(FsError::InvalidName(
                "trash entry does not match its undo record",
            ));
        }
        let copy = format!("{}.copy.json", entry.id);
        if day.entry_exists(os(&copy))? {
            let copied = read_record(&day, &copy)?;
            if copied.entry != *entry || copied.parent_id != record.parent_id {
                return Err(FsError::InvalidName(
                    "copy receipt does not match its trash intent",
                ));
            }
            record = copied;
        }
        Ok((day, record))
    }
    /// Inspect recovery eligibility without reading payload contents or adopting legacy authority.
    pub fn receipt_state(&self, entry: &TrashEntry) -> FsResult<TrashReceiptState> {
        let (_, record) = self.record(entry)?;
        Ok(
            if record.payload_id.is_some() && record.parent_id.is_some() {
                TrashReceiptState::IdentityBound
            } else {
                TrashReceiptState::LegacyManualRecovery
            },
        )
    }

    /// List bounded undo records newest first. Legacy records remain visible without being granted
    /// destructive authority; a restore/purge requires the identity recorded by the new writer.
    pub fn entries(&self) -> FsResult<Vec<TrashEntry>> {
        let root = match self.root(false) {
            Ok(root) => root,
            Err(e) if missing(&e) => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut entries = Vec::new();
        let mut count = 0usize;
        for day_name in root.entry_names(20_000)? {
            let text = day_name.to_string_lossy();
            if text.len() != 8 || !text.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let day = root.open_dir(Path::new(&day_name))?;
            for name in day.entry_names(20_000 - count)? {
                count += 1;
                let text = name.to_string_lossy();
                if !text.ends_with(".json") || text.ends_with(".copy.json") {
                    continue;
                }
                let record = read_record(&day, &text)?;
                validate_entry(&self.dir, &record.entry)?;
                if os(&day_folder(record.entry.trashed_at)) != day_name
                    || text != format!("{}.json", record.entry.id)
                {
                    return Err(FsError::InvalidName("trash record location mismatch"));
                }
                if day.entry_exists(os(&record.entry.id))? {
                    entries.push(record.entry);
                }
            }
        }
        entries.sort_by_key(|e| std::cmp::Reverse(e.trashed_at));
        Ok(entries)
    }
    /// Explicitly purge expired entries. Every opened payload identity must match its durable
    /// receipt. This method never schedules itself and never follows a substituted link.
    pub fn purge_older_than(&self, retention: Duration, now: Timestamp) -> FsResult<usize> {
        let cutoff = now.checked_sub(retention).unwrap_or(Timestamp::UNIX_EPOCH);
        let mut removed = 0;
        for entry in self.entries()? {
            if entry.trashed_at >= cutoff {
                continue;
            }
            let (day, record) = self.record(&entry)?;
            if record.parent_id.is_none() {
                return Err(FsError::Unsupported(
                    "legacy trash receipt has no parent identity; preserve for manual recovery",
                ));
            }
            let expected = record.payload_id.as_ref().ok_or(FsError::Unsupported(
                "legacy trash receipt has no file identity; preserve for manual recovery",
            ))?;
            day.prepare_rename(os(&entry.id))?.remove(expected)?;
            remove_record(&day, &entry.id)?;
            day.sync()?;
            removed += 1;
        }
        Ok(removed)
    }
}
fn validate_entry(root: &Path, entry: &TrashEntry) -> FsResult<()> {
    if entry.id.len() != 26
        || !entry.id.bytes().all(|b| b.is_ascii_alphanumeric())
        || !entry.original_path.is_absolute()
        || entry
            .original_path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        || entry.trash_path != root.join(day_folder(entry.trashed_at)).join(&entry.id)
    {
        return Err(FsError::InvalidName("invalid trash record paths"));
    }
    Ok(())
}
fn read_record(day: &crate::DirectoryCap, name: &str) -> FsResult<Record> {
    use std::io::Read;
    let mut bytes = Vec::new();
    day.open_read(os(name))?
        .take(65_537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        return Err(FsError::InvalidName("trash record exceeds its bound"));
    }
    serde_json::from_slice(&bytes).map_err(|_| FsError::InvalidName("corrupt trash record"))
}
fn write_record(day: &crate::DirectoryCap, name: &str, record: &Record) -> FsResult<()> {
    use std::io::Write;
    let mut file = day.create_new(os(name))?;
    file.write_all(
        &serde_json::to_vec(record).map_err(|_| FsError::InvalidName("invalid trash record"))?,
    )?;
    file.sync_all()?;
    day.sync()
}
fn remove_record(day: &crate::DirectoryCap, id: &str) -> FsResult<()> {
    for name in [format!("{id}.copy.json"), format!("{id}.json")] {
        if !day.entry_exists(os(&name))? {
            continue;
        }
        let source = day.prepare_rename(os(&name))?;
        let meta = source.metadata()?;
        source.remove(identity(&meta)?)?;
    }
    Ok(())
}
fn copy_move(
    source: &crate::DirectoryCap,
    name: &std::ffi::OsStr,
    destination: &crate::DirectoryCap,
    target: &std::ffi::OsStr,
    expected: &zeus_types::FileId,
    before_publish: impl FnOnce(zeus_types::FileId) -> FsResult<()>,
) -> FsResult<()> {
    use std::io::{Read, Write};
    let removal = source.prepare_rename(name)?;
    let before = removal.metadata()?;
    if identity(&before)? != expected {
        return Err(FsError::OutsideRoots);
    }
    let input = source.open_read(name)?;
    if crate::opened_file_metadata(&input)? != before {
        return Err(FsError::OutsideRoots);
    }
    let modified = input.metadata()?.modified()?;
    let unchanged = || -> FsResult<()> {
        if crate::opened_file_metadata(&input)? != before
            || input.metadata()?.modified()? != modified
        {
            return Err(FsError::OutsideRoots);
        }
        Ok(())
    };
    let staging = format!(
        ".zeus-restore-{}.zpart",
        zeus_types::IdGenerator::new().next_ulid()
    );
    let mut output = destination.create_new(os(&staging))?;
    let result = (|| {
        let mut buffer = vec![0; 1 << 20];
        let mut input_ref = &input;
        let mut copied = 0u64;
        loop {
            let n = input_ref.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            copied = copied
                .checked_add(n as u64)
                .ok_or(FsError::InvalidName("copy size overflow"))?;
            if copied > before.len {
                return Err(FsError::OutsideRoots);
            }
            output.write_all(&buffer[..n])?;
        }
        if copied != before.len {
            return Err(FsError::OutsideRoots);
        }
        unchanged()?;
        output.sync_all()?;
        before_publish(
            crate::opened_file_metadata(&output)?
                .file_id
                .ok_or(FsError::OutsideRoots)?,
        )?;
        unchanged()?;
        destination.publish_opened(os(&staging), &output, destination, target)?;
        destination.sync()?;
        unchanged()?;
        removal.remove(expected)?;
        source.sync()
    })();
    if result.is_err() && destination.entry_exists(os(&staging))? {
        let _ = destination.discard_created(os(&staging), output);
    }
    result
}

/// Sends a file to the platform recycle bin (Windows Recycle Bin, macOS Trash, freedesktop trash),
/// for files outside Zeus's own tree.
pub fn move_to_platform_trash(path: &Path) -> FsResult<()> {
    trash::delete(path).map_err(|e| FsError::from(std::io::Error::other(e.to_string())))
}

/// The day folder name for an instant: `yyyymmdd` in UTC (03 section 3.1).
#[must_use]
pub fn day_folder(now: Timestamp) -> String {
    let text = now.to_rfc3339();
    text.chars().take(10).filter(char::is_ascii_digit).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copied_move_publishes_before_removing_original_and_checks_identity() {
        let temp = tempfile::tempdir().unwrap();
        let root = crate::DirectoryCap::open_root(temp.path()).unwrap();
        let src = root.create_dir_all(Path::new("source")).unwrap();
        let dst = root.create_dir_all(Path::new("dest")).unwrap();
        std::fs::write(temp.path().join("source/file"), b"copied bytes").unwrap();
        let original = src.entry_metadata(os("file")).unwrap().file_id.unwrap();
        let mut copied_id = None;
        copy_move(&src, os("file"), &dst, os("file"), &original, |id| {
            copied_id = Some(id);
            Ok(())
        })
        .unwrap();
        assert!(!temp.path().join("source/file").exists());
        assert_eq!(
            std::fs::read(temp.path().join("dest/file")).unwrap(),
            b"copied bytes"
        );
        assert_ne!(copied_id.as_ref(), Some(&original));
        assert_eq!(dst.entry_metadata(os("file")).unwrap().file_id, copied_id);
    }
    #[test]
    fn copied_move_preserves_original_and_cleans_partial_when_receipt_fails() {
        let temp = tempfile::tempdir().unwrap();
        let root = crate::DirectoryCap::open_root(temp.path()).unwrap();
        let src = root.create_dir_all(Path::new("source")).unwrap();
        let dst = root.create_dir_all(Path::new("dest")).unwrap();
        std::fs::write(temp.path().join("source/file"), b"original").unwrap();
        let original = src.entry_metadata(os("file")).unwrap().file_id.unwrap();
        assert!(
            copy_move(&src, os("file"), &dst, os("file"), &original, |_| Err(
                FsError::InvalidName("receipt unavailable")
            ))
            .is_err()
        );
        assert_eq!(
            std::fs::read(temp.path().join("source/file")).unwrap(),
            b"original"
        );
        assert!(dst.entry_names(10).unwrap().is_empty());
        std::fs::write(temp.path().join("dest/file"), b"foreign").unwrap();
        assert!(copy_move(&src, os("file"), &dst, os("file"), &original, |_| Ok(())).is_err());
        assert_eq!(
            std::fs::read(temp.path().join("dest/file")).unwrap(),
            b"foreign"
        );
        assert_eq!(dst.entry_names(10).unwrap().len(), 1);
    }

    #[test]
    fn copied_move_refuses_post_copy_mutation_before_removing_original() {
        let temp = tempfile::tempdir().unwrap();
        let root = crate::DirectoryCap::open_root(temp.path()).unwrap();
        let src = root.create_dir_all(Path::new("source")).unwrap();
        let dst = root.create_dir_all(Path::new("dest")).unwrap();
        let path = temp.path().join("source/file");
        std::fs::write(&path, b"original").unwrap();
        let base = std::time::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer
            .set_times(std::fs::FileTimes::new().set_modified(base))
            .unwrap();
        let original = src.entry_metadata(os("file")).unwrap().file_id.unwrap();
        let result = copy_move(&src, os("file"), &dst, os("file"), &original, |_| {
            use std::io::Write;
            (&writer).write_all(b"modified")?;
            writer.set_times(
                std::fs::FileTimes::new().set_modified(base + Duration::from_nanos(100)),
            )?;
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"modified");
        assert!(dst.entry_names(10).unwrap().is_empty());
    }

    #[test]
    fn legacy_json_stays_visible_without_restore_overwrite_or_purge_authority() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original");
        std::fs::write(&original, b"legacy payload").unwrap();
        let trash = Trash::new(temp.path().join("trash"));
        let now = Timestamp::parse("2026-10-05T23:59:59.999Z").unwrap();
        let entry = trash.trash(&original, now).unwrap();
        let receipt = entry.trash_path.with_extension("json");
        // This is the exact old flattened JSON shape, with no identity fields.
        let legacy_bytes = serde_json::to_vec(&entry).unwrap();
        std::fs::write(&receipt, &legacy_bytes).unwrap();
        drop(trash);
        let restarted = Trash::new(temp.path().join("trash"));
        assert_eq!(restarted.entries().unwrap(), vec![entry.clone()]);
        assert_eq!(
            restarted.receipt_state(&entry).unwrap(),
            TrashReceiptState::LegacyManualRecovery
        );
        assert!(matches!(
            restarted.restore(&entry),
            Err(FsError::Unsupported(_))
        ));
        assert!(!original.exists());
        std::fs::write(&original, b"foreign occupant").unwrap();
        assert!(matches!(
            restarted.restore(&entry),
            Err(FsError::Unsupported(_))
        ));
        assert!(matches!(
            restarted.purge_older_than(Duration::ZERO, Timestamp::now()),
            Err(FsError::Unsupported(_))
        ));
        assert_eq!(std::fs::read(&original).unwrap(), b"foreign occupant");
        assert_eq!(std::fs::read(&entry.trash_path).unwrap(), b"legacy payload");
        assert_eq!(std::fs::read(&receipt).unwrap(), legacy_bytes);
        assert_eq!(restarted.entries().unwrap(), vec![entry]);
    }

    #[test]
    fn day_folder_is_utc_yyyymmdd() {
        let t = Timestamp::parse("2026-10-05T23:59:59.999Z").unwrap();
        assert_eq!(day_folder(t), "20261005");
    }
}
