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

/// The application trash with its undo journal.
#[derive(Debug, Clone)]
pub struct Trash {
    dir: PathBuf,
}

impl Trash {
    /// A trash rooted at `dir` (normally `<state>/trash`), created on first use with mode 0700.
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// The trash root.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Moves `path` into today's folder, appends a move record to the undo journal and returns it.
    /// Falls back to copy-and-delete when the trash is on another volume.
    pub fn trash(&self, path: &Path, now: Timestamp) -> FsResult<TrashEntry> {
        use crate::Filesystem;
        use std::io::Write;
        let fs = crate::RealFs;
        let original = std::fs::canonicalize(path)?;
        if !fs.metadata(path)?.is_some_and(|m| m.is_regular_file) {
            return Err(FsError::SymlinkRefused);
        }
        let day = self.dir.join(day_folder(now));
        fs.create_dir_all(&day)?;
        let id = zeus_types::IdGenerator::new().next_ulid().to_string();
        let target = day.join(&id);
        let entry = TrashEntry {
            id,
            original_path: original,
            trash_path: target,
            trashed_at: now,
            sha256: None,
        };
        // Durable intent precedes the move. A crash before the move leaves a harmless pending record.
        let record = day.join(format!("{}.json", entry.id));
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&record)?;
        output.write_all(
            &serde_json::to_vec(&entry)
                .map_err(|_| FsError::InvalidName("invalid trash record"))?,
        )?;
        output.sync_all()?;
        fs.sync_dir(&day)?;
        move_with_copy(&fs, path, &entry.trash_path)?;
        Ok(entry)
    }

    /// Moves the file back to its original path (or, if that is taken, refuses with
    /// [`FsError::AlreadyExists`]) and removes the journal record.
    pub fn restore(&self, entry: &TrashEntry) -> FsResult<PathBuf> {
        use crate::Filesystem;
        let fs = crate::RealFs;
        if !self.entries()?.iter().any(|saved| saved == entry) {
            return Err(FsError::InvalidName(
                "trash entry does not match its undo record",
            ));
        }
        let root = crate::SafeRoot::open(&self.dir)?;
        root.check_existing(&entry.trash_path)?;
        if !fs
            .metadata(&entry.trash_path)?
            .is_some_and(|m| m.is_regular_file)
        {
            return Err(FsError::SymlinkRefused);
        }
        move_with_copy(&fs, &entry.trash_path, &entry.original_path)?;
        let record = entry
            .trash_path
            .with_file_name(format!("{}.json", entry.id));
        fs.remove_file(&record)?;
        if let Some(parent) = record.parent() {
            fs.sync_dir(parent)?;
        }
        Ok(entry.original_path.clone())
    }

    /// Lists the undo journal, newest first.
    pub fn entries(&self) -> FsResult<Vec<TrashEntry>> {
        if !self.dir.try_exists()? {
            return Ok(Vec::new());
        }
        let mut entries = Vec::new();
        for day in std::fs::read_dir(&self.dir)? {
            let day = day?;
            if !day.file_type()?.is_dir() {
                continue;
            }
            for item in std::fs::read_dir(day.path())? {
                let item = item?;
                if item.file_type()?.is_file()
                    && item.path().extension().is_some_and(|s| s == "json")
                {
                    let entry: TrashEntry = serde_json::from_slice(&std::fs::read(item.path())?)
                        .map_err(|_| FsError::InvalidName("corrupt trash record"))?;
                    if entry.trash_path.try_exists()? {
                        entries.push(entry);
                    }
                }
            }
        }
        entries.sort_by_key(|e| std::cmp::Reverse(e.trashed_at));
        Ok(entries)
    }

    /// Deletes entries older than `retention` (30 days by default) and returns how many were removed.
    pub fn purge_older_than(&self, retention: Duration, now: Timestamp) -> FsResult<usize> {
        use crate::Filesystem;
        let cutoff = now.checked_sub(retention).unwrap_or(Timestamp::UNIX_EPOCH);
        let mut removed = 0;
        for entry in self.entries()? {
            if entry.trashed_at < cutoff {
                crate::SafeRoot::open(&self.dir)?.check_existing(&entry.trash_path)?;
                crate::RealFs.remove_file(&entry.trash_path)?;
                crate::RealFs.remove_file(
                    &entry
                        .trash_path
                        .with_file_name(format!("{}.json", entry.id)),
                )?;
                removed += 1;
            }
        }
        Ok(removed)
    }
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

fn move_with_copy(fs: &crate::RealFs, from: &Path, to: &Path) -> FsResult<()> {
    use crate::Filesystem;
    match fs.rename_noreplace(from, to) {
        Ok(()) => {}
        Err(FsError::Io { source, .. }) if source.kind() == std::io::ErrorKind::CrossesDevices => {
            // Create-new prevents overwriting any foreign file on the other volume.
            let temp = to.with_file_name(format!(
                ".zeus-restore-{}.zpart",
                zeus_types::IdGenerator::new().next_ulid()
            ));
            let input = fs.open_read(from)?;
            let output = fs.create_new(&temp)?;
            let mut offset = 0;
            let mut buffer = vec![0; 1 << 20];
            loop {
                let n = input.read_at(offset, &mut buffer)?;
                if n == 0 {
                    break;
                }
                output.write_all_at(offset, &buffer[..n])?;
                offset += n as u64;
            }
            output.sync_all()?;
            drop(output);
            drop(input);
            fs.rename_noreplace(&temp, to)?;
            if let Some(parent) = to.parent() {
                fs.sync_dir(parent)?;
            }
            fs.remove_file(from)?;
        }
        Err(e) => return Err(e),
    }
    if let Some(parent) = to.parent() {
        fs.sync_dir(parent)?;
    }
    if let Some(parent) = from.parent() {
        fs.sync_dir(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn day_folder_is_utc_yyyymmdd() {
        let t = Timestamp::parse("2026-10-05T23:59:59.999Z").unwrap();
        assert_eq!(day_folder(t), "20261005");
    }
}
