//! The file-system seam of the commit protocol (03 section 12.3).
//!
//! The engine and the journal's recovery code talk to the disk only through [`Filesystem`] and
//! [`DataFile`]. That makes the protocol testable under a crash-simulating implementation (`SimFs`:
//! a volatile and a durable layer, a seeded choice for unsynced regions at a simulated crash) without
//! touching a real disk, and keeps every platform-specific call in one place.
//!
//! The traits are synchronous: callers run them on blocking threads (the writer task per job and the
//! committer are dedicated). Everything takes `&self` so a [`DataFile`] can be shared between the
//! writer (positional writes) and the committer (`sync_data`).
#![expect(
    unused_variables,
    reason = "skeleton: bodies are filled in by the zeus-fs implementation task"
)]

use std::fmt;
use std::path::{Path, PathBuf};

use zeus_types::FileId;

use crate::error::{FsError, FsResult};

/// Metadata of a path, read without following a final symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMeta {
    /// A regular file (not a symlink, junction, reparse point or directory).
    pub is_regular_file: bool,
    /// A directory.
    pub is_dir: bool,
    /// A symlink, junction or other reparse point.
    pub is_symlink: bool,
    /// Length in bytes.
    pub len: u64,
    /// Modification time, milliseconds since the Unix epoch.
    pub mtime_ms: i64,
    /// Stable identity, when it can be read.
    pub file_id: Option<FileId>,
}

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryInfo {
    /// The entry's file name.
    pub name: String,
    /// Its full path.
    pub path: PathBuf,
    /// Its metadata (without following symlinks).
    pub meta: FileMeta,
}

/// How a request to preallocate was satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreallocOutcome {
    /// Blocks were reserved (`fallocate`, `F_PREALLOCATE`, or NTFS allocation).
    Reserved,
    /// The length was set but no blocks were reserved (sparse file).
    SparseLength,
    /// The file system refused; the file keeps its previous length.
    Unsupported,
}

/// An open data file (`<name>.zpart`). Byte `i` of the resource lives at file offset `i`.
pub trait DataFile: Send + Sync + fmt::Debug {
    /// Writes all of `buf` at `offset`, looping over short writes. Never moves a shared cursor.
    fn write_all_at(&self, offset: u64, buf: &[u8]) -> FsResult<()>;

    /// Reads up to `buf.len()` bytes at `offset`; returns the count (0 at end of file).
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize>;

    /// Reads exactly `buf.len()` bytes at `offset` or fails.
    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> FsResult<()> {
        let mut filled = 0;
        while filled < buf.len() {
            let n = self.read_at(offset + filled as u64, &mut buf[filled..])?;
            if n == 0 {
                return Err(FsError::Io {
                    fault: crate::error::FsFault::Io,
                    source: std::io::Error::from(std::io::ErrorKind::UnexpectedEof),
                });
            }
            filled += n;
        }
        Ok(())
    }

    /// Flushes written data (not necessarily metadata) to stable storage: `fdatasync`,
    /// `FlushFileBuffers`, or `fcntl(F_FULLFSYNC)` on macOS. Step C2 of the commit protocol.
    fn sync_data(&self) -> FsResult<()>;

    /// Flushes data and metadata (length, attributes): step F2 of finalization.
    fn sync_all(&self) -> FsResult<()>;

    /// Sets the file length (truncating or extending).
    fn set_len(&self, len: u64) -> FsResult<()>;

    /// The current length. **Never evidence of progress** (invariant I2): a preallocated file has its
    /// final length from the first second.
    fn len(&self) -> FsResult<u64>;

    /// True when the file has length zero.
    fn is_empty(&self) -> FsResult<bool> {
        Ok(self.len()? == 0)
    }

    /// Reserves `len` bytes if the free space allows (03 section 3.2 item 5); marks the file sparse on
    /// NTFS before extending so a write at a far offset does not zero-fill the gap.
    fn preallocate(&self, len: u64) -> FsResult<PreallocOutcome>;

    /// The identity of the open file object (device and inode, or volume serial and file index).
    fn file_id(&self) -> FsResult<FileId>;
}

/// The operations the commit protocol needs from a file system.
pub trait Filesystem: Send + Sync + fmt::Debug {
    /// Creates a new data file: `O_CREAT | O_EXCL | O_NOFOLLOW` and mode 0600 on Unix, `CREATE_NEW`
    /// with `FILE_FLAG_OPEN_REPARSE_POINT` on Windows, so a pre-planted symlink or file cannot be
    /// followed or reused (03 section 6 step 2).
    fn create_new(&self, path: &Path) -> FsResult<Box<dyn DataFile>>;

    /// Opens an existing data file for reading and writing without following a final symlink.
    fn open_existing(&self, path: &Path) -> FsResult<Box<dyn DataFile>>;

    /// Metadata without following a final symlink; `Ok(None)` when the path does not exist.
    fn metadata(&self, path: &Path) -> FsResult<Option<FileMeta>>;

    /// Atomically renames `from` to `to` **without replacing** an existing `to` (step F4):
    /// `renameat2(RENAME_NOREPLACE)`, `renamex_np(RENAME_EXCL)`, or `MoveFileExW` with
    /// `MOVEFILE_WRITE_THROUGH` and no `MOVEFILE_REPLACE_EXISTING`. Fails with [`FsError::AlreadyExists`]
    /// when `to` exists.
    fn rename_noreplace(&self, from: &Path, to: &Path) -> FsResult<()>;

    /// Replaces `to` with `from`, moving the old `to` to `backup` first (overwrite policy `replace`):
    /// `link` then `rename` on Unix, `ReplaceFile` with a backup name on Windows.
    fn replace_with_backup(&self, from: &Path, to: &Path, backup: &Path) -> FsResult<()>;

    /// Flushes a directory entry to stable storage (Unix `fsync` on the directory; a no-op on Windows,
    /// where `MOVEFILE_WRITE_THROUGH` already covers it). Step F5.
    fn sync_dir(&self, dir: &Path) -> FsResult<()>;

    /// Deletes a file. A missing file is not an error.
    fn remove_file(&self, path: &Path) -> FsResult<()>;

    /// Creates a directory and its parents (mode 0700 for directories Zeus creates on Unix).
    fn create_dir_all(&self, path: &Path) -> FsResult<()>;

    /// Lists a directory (used by the orphan scan of recovery step 7).
    fn read_dir(&self, path: &Path) -> FsResult<Vec<DirEntryInfo>>;

    /// Free space on the volume holding `path`, in bytes.
    fn free_space(&self, path: &Path) -> FsResult<u64>;

    /// Resolves symlinks and `.`/`..` in an existing path.
    fn canonicalize(&self, path: &Path) -> FsResult<PathBuf>;

    /// True when the volume holding `path` compares names case-insensitively (NTFS and APFS by
    /// default), which decides how reservation keys are folded.
    fn is_case_insensitive(&self, path: &Path) -> FsResult<bool>;
}

/// The real operating-system file system.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealFs;

impl RealFs {
    /// A handle to the real file system.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Filesystem for RealFs {
    fn create_new(&self, path: &Path) -> FsResult<Box<dyn DataFile>> {
        Err(FsError::NotImplemented("RealFs::create_new"))
    }

    fn open_existing(&self, path: &Path) -> FsResult<Box<dyn DataFile>> {
        Err(FsError::NotImplemented("RealFs::open_existing"))
    }

    fn metadata(&self, path: &Path) -> FsResult<Option<FileMeta>> {
        Err(FsError::NotImplemented("RealFs::metadata"))
    }

    fn rename_noreplace(&self, from: &Path, to: &Path) -> FsResult<()> {
        Err(FsError::NotImplemented("RealFs::rename_noreplace"))
    }

    fn replace_with_backup(&self, from: &Path, to: &Path, backup: &Path) -> FsResult<()> {
        Err(FsError::NotImplemented("RealFs::replace_with_backup"))
    }

    fn sync_dir(&self, dir: &Path) -> FsResult<()> {
        Err(FsError::NotImplemented("RealFs::sync_dir"))
    }

    fn remove_file(&self, path: &Path) -> FsResult<()> {
        Err(FsError::NotImplemented("RealFs::remove_file"))
    }

    fn create_dir_all(&self, path: &Path) -> FsResult<()> {
        Err(FsError::NotImplemented("RealFs::create_dir_all"))
    }

    fn read_dir(&self, path: &Path) -> FsResult<Vec<DirEntryInfo>> {
        Err(FsError::NotImplemented("RealFs::read_dir"))
    }

    fn free_space(&self, path: &Path) -> FsResult<u64> {
        Err(FsError::NotImplemented("RealFs::free_space"))
    }

    fn canonicalize(&self, path: &Path) -> FsResult<PathBuf> {
        Err(FsError::NotImplemented("RealFs::canonicalize"))
    }

    fn is_case_insensitive(&self, path: &Path) -> FsResult<bool> {
        Err(FsError::NotImplemented("RealFs::is_case_insensitive"))
    }
}

/// Suffix of data files in progress (00 section 3).
pub const ZPART_SUFFIX: &str = ".zpart";

/// The data file path for a final path: `<final>.zpart` in the same directory, so the final rename is
/// atomic on one file system (03 section 3.2).
#[must_use]
pub fn zpart_path(final_path: &Path) -> PathBuf {
    let mut name = final_path.as_os_str().to_owned();
    name.push(ZPART_SUFFIX);
    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_file_sits_next_to_the_final_file() {
        let p = zpart_path(Path::new("/downloads/dataset-v3.tar.zst"));
        assert_eq!(p, PathBuf::from("/downloads/dataset-v3.tar.zst.zpart"));
        assert_eq!(
            p.parent(),
            Path::new("/downloads/dataset-v3.tar.zst").parent()
        );
    }

    #[test]
    fn skeleton_filesystem_reports_not_implemented() {
        let fs = RealFs::new();
        assert!(matches!(
            fs.metadata(Path::new(".")),
            Err(FsError::NotImplemented(_))
        ));
    }
}
