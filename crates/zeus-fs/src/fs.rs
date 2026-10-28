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

    /// Opens a regular file read-only without following a final symlink.
    fn open_read(&self, path: &Path) -> FsResult<Box<dyn DataFile>> {
        self.open_existing(path)
    }

    /// Sets the read-only flag. Objects are sealed before becoming visible.
    fn set_readonly(&self, _path: &Path, _readonly: bool) -> FsResult<()> {
        Err(FsError::Unsupported("read-only attributes"))
    }

    /// Creates a hard link without replacing its target.
    fn hard_link(&self, _from: &Path, _to: &Path) -> FsResult<()> {
        Err(FsError::Unsupported("hard links"))
    }

    /// Creates an independent copy-on-write clone, or returns Unsupported for the next policy mode.
    fn reflink(&self, _from: &Path, _to: &Path) -> FsResult<()> {
        Err(FsError::Unsupported("copy-on-write cloning"))
    }

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

#[derive(Debug)]
struct RealDataFile(std::fs::File);

impl DataFile for RealDataFile {
    fn write_all_at(&self, mut offset: u64, mut buf: &[u8]) -> FsResult<()> {
        while !buf.is_empty() {
            #[cfg(unix)]
            let written = std::os::unix::fs::FileExt::write_at(&self.0, buf, offset);
            #[cfg(windows)]
            let written = std::os::windows::fs::FileExt::seek_write(&self.0, buf, offset);
            let n = match written {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                other => other?,
            };
            if n == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into());
            }
            offset = offset
                .checked_add(n as u64)
                .ok_or(FsError::InvalidName("file offset overflow"))?;
            buf = &buf[n..];
        }
        Ok(())
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        loop {
            #[cfg(unix)]
            let result = std::os::unix::fs::FileExt::read_at(&self.0, buf, offset);
            #[cfg(windows)]
            let result = std::os::windows::fs::FileExt::seek_read(&self.0, buf, offset);
            match result {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                result => return result.map_err(Into::into),
            }
        }
    }
    fn sync_data(&self) -> FsResult<()> {
        self.sync_all()
    }
    fn sync_all(&self) -> FsResult<()> {
        self.0.sync_all()?;
        #[cfg(target_os = "macos")]
        {
            rustix::fs::fcntl_fullfsync(&self.0).map_err(std::io::Error::from)?;
        }
        Ok(())
    }
    fn set_len(&self, len: u64) -> FsResult<()> {
        self.0.set_len(len)?;
        Ok(())
    }
    fn len(&self) -> FsResult<u64> {
        Ok(self.0.metadata()?.len())
    }
    fn preallocate(&self, len: u64) -> FsResult<PreallocOutcome> {
        match fs4::FileExt::allocate(&self.0, len) {
            Ok(()) => {
                self.0.set_len(len)?;
                Ok(PreallocOutcome::Reserved)
            }
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {
                self.0.set_len(len)?;
                Ok(PreallocOutcome::SparseLength)
            }
            Err(e) => Err(e.into()),
        }
    }
    fn file_id(&self) -> FsResult<FileId> {
        file_identity(&self.0)
    }
}

pub(crate) fn file_identity(file: &std::fs::File) -> FsResult<FileId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = file.metadata()?;
        Ok(FileId::unix(m.dev(), m.ino()))
    }
    #[cfg(windows)]
    {
        crate::sys::file_identity(file)
    }
}

fn open_file(path: &Path, create: bool, writable: bool) -> FsResult<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true).write(writable).create_new(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            FsError::AlreadyExists
        } else {
            e.into()
        }
    })?;
    let m = file.metadata()?;
    if !m.is_file() || is_reparse(&m) {
        return Err(FsError::SymlinkRefused);
    }
    Ok(file)
}

pub(crate) fn is_reparse(m: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        m.file_attributes() & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        m.file_type().is_symlink()
    }
}

impl Filesystem for RealFs {
    fn create_new(&self, path: &Path) -> FsResult<Box<dyn DataFile>> {
        Ok(Box::new(RealDataFile(open_file(path, true, true)?)))
    }
    fn open_existing(&self, path: &Path) -> FsResult<Box<dyn DataFile>> {
        Ok(Box::new(RealDataFile(open_file(path, false, true)?)))
    }
    fn open_read(&self, path: &Path) -> FsResult<Box<dyn DataFile>> {
        Ok(Box::new(RealDataFile(open_file(path, false, false)?)))
    }
    fn set_readonly(&self, path: &Path, readonly: bool) -> FsResult<()> {
        #[cfg(unix)]
        let file = open_file(path, false, false)?;
        #[cfg(windows)]
        let file = {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_WRITE_ATTRIBUTES,
            };
            let file = std::fs::OpenOptions::new()
                .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)?;
            let metadata = file.metadata()?;
            if !metadata.is_file() || is_reparse(&metadata) {
                return Err(FsError::SymlinkRefused);
            }
            file
        };
        let mut permissions = file.metadata()?.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(if readonly { 0o400 } else { 0o600 });
        }
        #[cfg(windows)]
        {
            permissions.set_readonly(readonly);
        }
        file.set_permissions(permissions)?;
        Ok(())
    }
    fn hard_link(&self, from: &Path, to: &Path) -> FsResult<()> {
        if !self.metadata(from)?.is_some_and(|m| m.is_regular_file) {
            return Err(FsError::SymlinkRefused);
        }
        std::fs::hard_link(from, to).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                FsError::AlreadyExists
            } else {
                e.into()
            }
        })
    }
    fn reflink(&self, from: &Path, to: &Path) -> FsResult<()> {
        #[cfg(target_os = "linux")]
        {
            let source = open_file(from, false, false)?;
            let target = open_file(to, true, true)?;
            match rustix::fs::ioctl_ficlone(&target, &source) {
                Ok(()) => Ok(()),
                Err(e) => {
                    drop(target);
                    let _ = std::fs::remove_file(to);
                    if [
                        rustix::io::Errno::OPNOTSUPP,
                        rustix::io::Errno::INVAL,
                        rustix::io::Errno::XDEV,
                        rustix::io::Errno::NOTTY,
                    ]
                    .contains(&e)
                    {
                        Err(FsError::Unsupported("copy-on-write cloning"))
                    } else {
                        Err(std::io::Error::from(e).into())
                    }
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (from, to);
            Err(FsError::Unsupported(
                "copy-on-write cloning on this platform",
            ))
        }
    }
    fn metadata(&self, path: &Path) -> FsResult<Option<FileMeta>> {
        let m = match std::fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let link = is_reparse(&m);
        #[cfg(unix)]
        let id = {
            use std::os::unix::fs::MetadataExt;
            Some(FileId::unix(m.dev(), m.ino()))
        };
        #[cfg(windows)]
        let id = if !link && (m.is_file() || m.is_dir()) {
            if m.is_dir() {
                use std::os::windows::fs::OpenOptionsExt;
                let directory = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(
                        windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS
                            | windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
                    )
                    .open(path)?;
                Some(file_identity(&directory)?)
            } else {
                Some(file_identity(&open_file(path, false, false)?)?)
            }
        } else {
            None
        };
        Ok(Some(FileMeta {
            is_regular_file: m.is_file() && !link,
            is_dir: m.is_dir() && !link,
            is_symlink: link,
            len: m.len(),
            mtime_ms: m
                .modified()?
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis().min(i64::MAX as u128) as i64),
            file_id: id,
        }))
    }
    fn rename_noreplace(&self, from: &Path, to: &Path) -> FsResult<()> {
        #[cfg(unix)]
        {
            rustix::fs::renameat_with(
                rustix::fs::CWD,
                from,
                rustix::fs::CWD,
                to,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|e| {
                if e == rustix::io::Errno::EXIST {
                    FsError::AlreadyExists
                } else {
                    std::io::Error::from(e).into()
                }
            })?;
        }
        #[cfg(windows)]
        {
            crate::sys::move_noreplace(from, to)?;
        }
        Ok(())
    }
    fn replace_with_backup(&self, from: &Path, to: &Path, backup: &Path) -> FsResult<()> {
        if self.metadata(backup)?.is_some() {
            return Err(FsError::AlreadyExists);
        }
        if self.metadata(to)?.is_some_and(|m| !m.is_regular_file) {
            return Err(FsError::SymlinkRefused);
        }
        #[cfg(unix)]
        {
            std::fs::hard_link(to, backup)?;
            if let Some(parent) = backup.parent() {
                self.sync_dir(parent)?;
            }
            std::fs::rename(from, to)?;
        }
        #[cfg(windows)]
        {
            crate::sys::replace(from, to, backup)?;
        }
        Ok(())
    }
    fn sync_dir(&self, _dir: &Path) -> FsResult<()> {
        #[cfg(unix)]
        {
            std::fs::File::open(_dir)?.sync_all()?;
        }
        Ok(())
    }
    fn remove_file(&self, path: &Path) -> FsResult<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
    fn create_dir_all(&self, path: &Path) -> FsResult<()> {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)?;
        Ok(())
    }
    fn read_dir(&self, path: &Path) -> FsResult<Vec<DirEntryInfo>> {
        std::fs::read_dir(path)?
            .map(|entry| {
                let entry = entry?;
                let path = entry.path();
                let meta = self.metadata(&path)?.ok_or_else(|| {
                    FsError::from(std::io::Error::from(std::io::ErrorKind::NotFound))
                })?;
                Ok(DirEntryInfo {
                    name: entry.file_name().to_string_lossy().into_owned(),
                    path,
                    meta,
                })
            })
            .collect()
    }
    fn free_space(&self, path: &Path) -> FsResult<u64> {
        Ok(fs4::available_space(path)?)
    }
    fn canonicalize(&self, path: &Path) -> FsResult<PathBuf> {
        Ok(std::fs::canonicalize(path)?)
    }
    fn is_case_insensitive(&self, _path: &Path) -> FsResult<bool> {
        Ok(cfg!(any(windows, target_os = "macos")))
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
    fn real_filesystem_reads_metadata() {
        let fs = RealFs::new();
        assert!(matches!(fs.metadata(Path::new(".")), Ok(Some(_))));
    }
}
