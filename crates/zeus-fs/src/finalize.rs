//! The rename half of finalization (03 section 8.1, steps F4 and F5) and its crash decision procedure
//! (03 section 8.2).
//!
//! Journal bookkeeping (`finalize.phase = intent`, the S80 commit) belongs to the engine; this module
//! performs the file-system operations and answers "which side of the rename did a crash fall on?".
#![expect(
    unused_variables,
    reason = "skeleton: bodies are filled in by the zeus-fs implementation task"
)]

use std::path::{Path, PathBuf};

use zeus_types::{FileId, Overwrite};

use crate::error::{FsError, FsResult};
use crate::fs::Filesystem;

/// What to rename and how to treat an existing destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizePlan {
    /// The verified data file (`<name>.zpart`).
    pub tmp_path: PathBuf,
    /// The final path, reserved for this job.
    pub dest_path: PathBuf,
    /// The job's overwrite policy.
    pub overwrite: Overwrite,
    /// Where `overwrite = replace` moves the old file (the application trash).
    pub backup_path: Option<PathBuf>,
}

/// What the rename did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizeOutcome {
    /// The path the file ended up at (the destination, or a renamed variant under `rename`).
    pub final_path: PathBuf,
    /// A pre-existing file was moved aside.
    pub replaced_existing: bool,
}

/// Performs F4 and F5: atomic no-replace rename, then a directory sync. The destination directory's
/// identity is re-checked before the rename (03 section 14); a swapped directory fails with
/// [`FsError::OutsideRoots`].
pub fn rename_into_place(fs: &dyn Filesystem, plan: &FinalizePlan) -> FsResult<FinalizeOutcome> {
    Err(FsError::NotImplemented("rename_into_place"))
}

/// Where a crash during `finalizing` left the files, as observed by recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizeObservation {
    /// The data file exists, and its identity if so.
    pub tmp: Option<FileId>,
    /// The final path exists, and its identity if so.
    pub dest: Option<FileId>,
}

/// The decision of 03 section 8.2, "decision procedure when `finalize.phase` is `intent`".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    /// The rename did not happen: repeat F4.
    RepeatRename,
    /// The rename happened: continue at F5 (directory sync), then F6.
    ContinueAfterRename,
    /// The destination appeared after the intent and the data file is still ours: pick a new unique
    /// name and rename again.
    PickNewName,
    /// Someone else put a file at the destination, or neither file exists: `fs.finalize_lost`.
    Lost,
}

/// Applies the five-case decision procedure of 03 section 8.2. `expected` is `finalize.file_id`.
#[must_use]
pub fn decide_recovery(observed: &FinalizeObservation, expected: &FileId) -> RecoveryAction {
    match (&observed.tmp, &observed.dest) {
        (Some(_), None) => RecoveryAction::RepeatRename,
        (None, Some(dest)) if dest == expected => RecoveryAction::ContinueAfterRename,
        (None, Some(_)) | (None, None) => RecoveryAction::Lost,
        (Some(tmp), Some(_)) if tmp == expected => RecoveryAction::PickNewName,
        (Some(_), Some(_)) => RecoveryAction::Lost,
    }
}

/// True when `path` ends in the data-file suffix.
#[must_use]
pub fn is_zpart(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "zpart")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u64) -> FileId {
        FileId::unix(1, n)
    }

    #[test]
    fn the_five_crash_cases_of_the_specification() {
        let me = id(7);
        // 1. tmp exists, dest does not: repeat F4.
        assert_eq!(
            decide_recovery(
                &FinalizeObservation {
                    tmp: Some(me.clone()),
                    dest: None
                },
                &me
            ),
            RecoveryAction::RepeatRename
        );
        // 2. dest exists with our identity, tmp gone: continue at F5.
        assert_eq!(
            decide_recovery(
                &FinalizeObservation {
                    tmp: None,
                    dest: Some(me.clone())
                },
                &me
            ),
            RecoveryAction::ContinueAfterRename
        );
        // 3. dest exists with another identity, tmp gone: lost.
        assert_eq!(
            decide_recovery(
                &FinalizeObservation {
                    tmp: None,
                    dest: Some(id(8))
                },
                &me
            ),
            RecoveryAction::Lost
        );
        // 4. both exist and tmp is ours: pick a new name.
        assert_eq!(
            decide_recovery(
                &FinalizeObservation {
                    tmp: Some(me.clone()),
                    dest: Some(id(8))
                },
                &me
            ),
            RecoveryAction::PickNewName
        );
        // 5. neither exists: lost.
        assert_eq!(
            decide_recovery(
                &FinalizeObservation {
                    tmp: None,
                    dest: None
                },
                &me
            ),
            RecoveryAction::Lost
        );
        // Both exist but tmp is not ours: nothing of ours is safe to rename.
        assert_eq!(
            decide_recovery(
                &FinalizeObservation {
                    tmp: Some(id(9)),
                    dest: Some(id(8))
                },
                &me
            ),
            RecoveryAction::Lost
        );
    }

    #[test]
    fn zpart_detection() {
        assert!(is_zpart(Path::new("/d/a.zip.zpart")));
        assert!(!is_zpart(Path::new("/d/a.zip")));
    }
}
