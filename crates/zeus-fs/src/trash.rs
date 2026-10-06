//! Deletes go to the application trash, never straight to unlink (01 section 12.3 rule 4).
//!
//! The only exception is the partial data of a *canceled* job. The application trash lives under the
//! state directory (`<state>/trash/<yyyymmdd>/`, 03 section 3.1) with an undo journal of move records
//! so a destructive file operation can be reverted; the platform recycle bin (the `trash` crate) is
//! offered for files outside Zeus's own tree.
#![expect(
    unused_variables,
    reason = "skeleton: bodies are filled in by the zeus-fs implementation task"
)]

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
        Err(FsError::NotImplemented("Trash::trash"))
    }

    /// Moves the file back to its original path (or, if that is taken, refuses with
    /// [`FsError::AlreadyExists`]) and removes the journal record.
    pub fn restore(&self, entry: &TrashEntry) -> FsResult<PathBuf> {
        Err(FsError::NotImplemented("Trash::restore"))
    }

    /// Lists the undo journal, newest first.
    pub fn entries(&self) -> FsResult<Vec<TrashEntry>> {
        Err(FsError::NotImplemented("Trash::entries"))
    }

    /// Deletes entries older than `retention` (30 days by default) and returns how many were removed.
    pub fn purge_older_than(&self, retention: Duration, now: Timestamp) -> FsResult<usize> {
        Err(FsError::NotImplemented("Trash::purge_older_than"))
    }
}

/// Sends a file to the platform recycle bin (Windows Recycle Bin, macOS Trash, freedesktop trash),
/// for files outside Zeus's own tree.
pub fn move_to_platform_trash(path: &Path) -> FsResult<()> {
    Err(FsError::NotImplemented("move_to_platform_trash"))
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
    fn day_folder_is_utc_yyyymmdd() {
        let t = Timestamp::parse("2026-10-05T23:59:59.999Z").unwrap();
        assert_eq!(day_folder(t), "20261005");
    }
}
