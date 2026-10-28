//! Directory capabilities for explicitly opted-in local file operations.
//!
//! Opening a root is an ambient-authority decision. Descendants are opened one plain component at
//! a time without following links; each child keeps its ancestors alive. Windows directory handles
//! deny delete sharing. Unix capabilities continue to name the opened directory object after an
//! external rename. These primitives are containment, not isolation from a same-user process.

use crate::{
    FileMeta, FsError, FsResult,
    fs::{file_identity, is_reparse},
};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt};
use cap_std::fs::{Dir, OpenOptions};
use std::{
    ffi::OsStr,
    path::{Component, Path},
    sync::Arc,
};

#[derive(Debug)]
struct HeldDir {
    dir: Dir,
    // Keep every opened ancestor alive: Windows path-backed directory operations depend on this.
    _parent: Option<Arc<HeldDir>>,
}

/// Authority over an opened directory. The embedding application supplies read/write policy.
/// After the ambient root open, operations refuse absolute paths and traversal; file methods take
/// a single leaf name.
#[derive(Debug, Clone)]
pub struct DirectoryCap(Arc<HeldDir>);

/// An opened regular file or directory prepared for a no-replace rename.
/// Windows pins the source object with DELETE access and denies other rename/delete operations.
#[derive(Debug)]
pub struct RenameSource {
    _parent: DirectoryCap,
    #[cfg(not(windows))]
    name: std::ffi::OsString,
    file: std::fs::File,
}

fn io_error(e: std::io::Error) -> FsError {
    if e.kind() == std::io::ErrorKind::AlreadyExists {
        FsError::AlreadyExists
    } else {
        e.into()
    }
}

// Names are checked, never silently rewritten. Preserve Unicode normalization and non-UTF8 Unix
// names; reject platform aliases using the ASCII subset of OsStr's self-synchronizing encoding.
fn leaf(name: &OsStr) -> FsResult<()> {
    let b = name.as_encoded_bytes();
    if b.is_empty()
        || b.len() > 255
        || b == b"."
        || b == b".."
        || b.last().is_some_and(|x| *x == b'.' || *x == b' ')
        || b.iter()
            .any(|x| *x < 32 || *x == 127 || b"/\\:<>\"|?*".contains(x))
    {
        return Err(FsError::InvalidName("a plain file name is required"));
    }
    let stem = b
        .split(|x| *x == b'.')
        .next()
        .unwrap_or(b"")
        .trim_ascii_end();
    if [
        b"CON".as_slice(),
        b"PRN",
        b"AUX",
        b"NUL",
        b"CONIN$",
        b"CONOUT$",
    ]
    .iter()
    .any(|s| stem.eq_ignore_ascii_case(s))
        || (stem.len() == 4
            && (stem[..3].eq_ignore_ascii_case(b"COM") || stem[..3].eq_ignore_ascii_case(b"LPT"))
            && matches!(stem[3], b'1'..=b'9'))
        || name.to_str().is_some_and(|s| {
            let stem = s.split('.').next().unwrap_or("").to_uppercase();
            ["COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³"].contains(&stem.as_str())
        })
    {
        return Err(FsError::InvalidName("reserved device name"));
    }
    if Path::new(name).components().count() != 1 {
        return Err(FsError::OutsideRoots);
    }
    Ok(())
}

/// Read regular-file or directory metadata and identity from the opened object.
pub fn opened_file_metadata(file: &std::fs::File) -> FsResult<FileMeta> {
    let m = file.metadata()?;
    if is_reparse(&m) || (!m.is_file() && !m.is_dir()) {
        return Err(FsError::SymlinkRefused);
    }
    Ok(FileMeta {
        is_regular_file: m.is_file(),
        is_dir: m.is_dir(),
        is_symlink: false,
        len: m.len(),
        mtime_ms: m
            .modified()?
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis().min(i64::MAX as u128) as i64),
        file_id: Some(file_identity(file)?),
    })
}

impl DirectoryCap {
    /// Open an explicitly authorized ambient root, refusing a final link/reparse point.
    /// Ancestors of this initial path belong to the ambient-authority boundary. Callers retaining a
    /// configured root identity must compare it with [`Self::file_id`] before using this capability.
    pub fn open_root(path: &Path) -> FsResult<Self> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(
                (rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NONBLOCK)
                    .bits() as i32,
            );
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::*;
            options
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        }
        let file = options.open(path)?;
        if !opened_file_metadata(&file)?.is_dir {
            return Err(FsError::InvalidName("root is not a directory"));
        }
        Ok(Self(Arc::new(HeldDir {
            dir: Dir::from_std_file(file),
            _parent: None,
        })))
    }

    /// Identity of the retained directory object, without reopening its path.
    pub fn file_id(&self) -> FsResult<zeus_types::FileId> {
        file_identity(&self.0.dir.try_clone()?.into_std_file())
    }

    /// Resolve an existing directory using only normal, non-link components. Empty means this root.
    pub fn open_dir(&self, relative: &Path) -> FsResult<Self> {
        let mut current = self.clone();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(FsError::OutsideRoots);
            };
            leaf(name)?;
            let dir = current.0.dir.open_dir_nofollow(name)?;
            // The library refuses symlinks; also reject every Windows reparse tag, including junctions.
            if !opened_file_metadata(&dir.try_clone()?.into_std_file())?.is_dir {
                return Err(FsError::SymlinkRefused);
            }
            current = Self(Arc::new(HeldDir {
                dir,
                _parent: Some(current.0),
            }));
        }
        Ok(current)
    }

    /// Create exactly one directory without accepting an existing target.
    pub fn create_dir(&self, name: &OsStr) -> FsResult<()> {
        leaf(name)?;
        let builder = cap_std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use cap_std::fs::DirBuilderExt;
            let mut builder = builder;
            builder.mode(0o700);
            self.0.dir.create_dir_with(name, &builder).map_err(io_error)
        }
        #[cfg(not(unix))]
        self.0.dir.create_dir_with(name, &builder).map_err(io_error)
    }

    /// Create missing normal directory components; refuse links even when they point inside root.
    pub fn create_dir_all(&self, relative: &Path) -> FsResult<Self> {
        let mut current = self.clone();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(FsError::OutsideRoots);
            };
            leaf(name)?;
            match current.create_dir(name) {
                Ok(()) | Err(FsError::AlreadyExists) => (),
                Err(e) => return Err(e),
            }
            current = current.open_dir(Path::new(name))?;
        }
        Ok(current)
    }

    fn open(
        &self,
        name: &OsStr,
        create: bool,
        rename: bool,
        directories: bool,
    ) -> FsResult<std::fs::File> {
        leaf(name)?;
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(create)
            .create_new(create)
            .follow(FollowSymlinks::No)
            .maybe_dir(directories);
        #[cfg(unix)]
        {
            let _ = rename; // Source-object pinning for rename is a Windows access-mode choice.
            use cap_std::fs::OpenOptionsExt;
            // Never block on a FIFO substituted for a regular file.
            options
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
        }
        #[cfg(windows)]
        {
            use cap_std::fs::OpenOptionsExt;
            use windows_sys::Win32::Storage::FileSystem::*;
            if create {
                options
                    .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
            }
            // A rename acts on this object, including directories, rather than reopening its name.
            if rename {
                options
                    .access_mode(DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
            }
        }
        let file = self
            .0
            .dir
            .open_with(name, &options)
            .map_err(io_error)?
            .into_std();
        let m = opened_file_metadata(&file)?;
        if !directories && !m.is_regular_file {
            return Err(FsError::InvalidName("a regular file is required"));
        }
        Ok(file)
    }

    /// Inspect a regular file or directory through a read-only no-follow handle.
    pub fn entry_metadata(&self, name: &OsStr) -> FsResult<FileMeta> {
        opened_file_metadata(&self.open(name, false, false, true)?)
    }

    /// List up to `limit` child names without following their entries. Exceeding the bound fails.
    pub fn entry_names(&self, limit: usize) -> FsResult<Vec<std::ffi::OsString>> {
        let mut names = Vec::new();
        for entry in self.0.dir.entries()? {
            if names.len() >= limit {
                return Err(FsError::InvalidName("directory entry limit exceeded"));
            }
            names.push(entry?.file_name());
        }
        Ok(names)
    }

    /// Open an existing regular file read-only without following its final component.
    pub fn open_read(&self, name: &OsStr) -> FsResult<std::fs::File> {
        self.open(name, false, false, false)
    }

    /// Exclusively create a regular file (0600 on Unix). Never follows or replaces a target.
    pub fn create_new(&self, name: &OsStr) -> FsResult<std::fs::File> {
        self.open(name, true, false, false)
    }

    /// Discard a file created by [`Self::create_new`]. Windows deletes the held object on close;
    /// Unix checks identity before unlinking relative to the parent (not an atomic compare-unlink).
    /// An unrelated replacement is refused, never intentionally cleaned up as this copy's output.
    pub fn discard_created(&self, name: &OsStr, file: std::fs::File) -> FsResult<()> {
        leaf(name)?;
        #[cfg(windows)]
        {
            crate::sys::delete_open_file(&file)
        }
        #[cfg(unix)]
        {
            if file_identity(&file)? != file_identity(&self.open_read(name)?)? {
                return Err(FsError::OutsideRoots);
            }
            self.remove_file(name)
        }
    }

    /// Open and retain the item which a subsequent no-replace rename must move.
    pub fn prepare_rename(&self, name: &OsStr) -> FsResult<RenameSource> {
        Ok(RenameSource {
            file: self.open(name, false, true, true)?,
            _parent: self.clone(),
            #[cfg(not(windows))]
            name: name.to_owned(),
        })
    }

    /// Remove a regular file name relative to this held directory. No recursive deletion.
    /// Like unlinkat, this addresses a directory entry; it is not an identity-conditional delete.
    pub fn remove_file(&self, name: &OsStr) -> FsResult<()> {
        leaf(name)?;
        self.0.dir.remove_file(name).map_err(io_error)
    }
}

impl RenameSource {
    /// Metadata and identity read from the retained source object.
    pub fn metadata(&self) -> FsResult<FileMeta> {
        opened_file_metadata(&self.file)
    }

    /// Atomically publish without replacing a destination. Cross-volume moves fail.
    /// Unix checks source identity immediately before directory-relative rename, but has no atomic
    /// rename-if-file-id primitive against a concurrent same-user source-entry replacement.
    pub fn rename_noreplace(self, destination: &DirectoryCap, name: &OsStr) -> FsResult<()> {
        leaf(name)?;
        #[cfg(windows)]
        {
            crate::sys::rename_handle_noreplace(&self.file, &destination.0.dir, name)
        }
        #[cfg(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "redox"
        ))]
        {
            let current = self._parent.open(&self.name, false, true, true)?;
            if file_identity(&current)? != file_identity(&self.file)? {
                return Err(FsError::OutsideRoots);
            }
            rustix::fs::renameat_with(
                &self._parent.0.dir,
                &self.name,
                &destination.0.dir,
                name,
                rustix::fs::RenameFlags::NOREPLACE,
            )
            .map_err(|e| io_error(e.into()))
        }
        #[cfg(not(any(
            windows,
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "redox"
        )))]
        {
            let _ = (destination, name);
            Err(FsError::Unsupported(
                "atomic directory-relative no-replace rename",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    fn os(s: &str) -> &OsStr {
        OsStr::new(s)
    }

    #[test]
    fn creates_and_moves_files_and_directories_without_replacing() {
        let temp = tempfile::tempdir().unwrap();
        let root = DirectoryCap::open_root(temp.path()).unwrap();
        let a = root.create_dir_all(Path::new("a/b")).unwrap();
        let b = root.create_dir_all(Path::new("dest")).unwrap();
        a.create_new(os("one"))
            .unwrap()
            .write_all(b"contents")
            .unwrap();
        b.create_new(os("one")).unwrap().write_all(b"keep").unwrap();
        let identity = a
            .prepare_rename(os("one"))
            .unwrap()
            .metadata()
            .unwrap()
            .file_id;
        assert!(matches!(
            a.prepare_rename(os("one"))
                .unwrap()
                .rename_noreplace(&b, os("one")),
            Err(FsError::AlreadyExists)
        ));
        assert_eq!(
            std::fs::read(temp.path().join("dest/one")).unwrap(),
            b"keep"
        );
        a.prepare_rename(os("one"))
            .unwrap()
            .rename_noreplace(&b, os("two"))
            .unwrap();
        assert_eq!(
            b.prepare_rename(os("two"))
                .unwrap()
                .metadata()
                .unwrap()
                .file_id,
            identity
        );
        assert!(!temp.path().join("a/b/one").exists());
        drop(a);
        root.prepare_rename(os("a"))
            .unwrap()
            .rename_noreplace(&b, os("folder"))
            .unwrap();
        assert!(temp.path().join("dest/folder/b").is_dir());
    }

    #[test]
    fn rejects_path_and_device_aliases_and_exclusive_create_collisions() {
        let temp = tempfile::tempdir().unwrap();
        let root = DirectoryCap::open_root(temp.path()).unwrap();
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "x:stream",
            "CON",
            "NUL.txt",
            "COM1",
            "LPT².txt",
            "CONIN$",
            "x.",
            "x ",
            "x\0",
        ] {
            assert!(root.create_new(os(bad)).is_err(), "{bad:?}");
            assert!(root.create_dir(os(bad)).is_err(), "{bad:?}");
        }
        assert!(root.open_dir(Path::new("../")).is_err());
        assert!(root.open_dir(temp.path()).is_err());
        root.create_new(os("é normal.txt")).unwrap();
        assert!(matches!(
            root.create_new(os("é normal.txt")),
            Err(FsError::AlreadyExists)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn retained_parent_cannot_be_redirected_by_replacement_or_links() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = DirectoryCap::open_root(temp.path()).unwrap();
        let held = root.create_dir_all(Path::new("parent")).unwrap();
        let other = tempfile::tempdir().unwrap();
        std::fs::write(other.path().join("victim"), b"keep").unwrap();
        std::fs::rename(temp.path().join("parent"), temp.path().join("old-parent")).unwrap();
        symlink(other.path(), temp.path().join("parent")).unwrap();
        held.create_new(os("victim"))
            .unwrap()
            .write_all(b"owned")
            .unwrap();
        assert_eq!(std::fs::read(other.path().join("victim")).unwrap(), b"keep");
        assert_eq!(
            std::fs::read(temp.path().join("old-parent/victim")).unwrap(),
            b"owned"
        );
        assert!(root.open_dir(Path::new("parent")).is_err());
        assert!(root.create_dir_all(Path::new("parent/nested")).is_err());
        symlink(other.path().join("victim"), temp.path().join("link")).unwrap();
        assert!(root.open_read(os("link")).is_err());
        assert!(root.prepare_rename(os("link")).is_err());
        assert!(DirectoryCap::open_root(&temp.path().join("parent")).is_err());
        rustix::fs::mknodat(
            &root.0.dir,
            "pipe",
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            0,
        )
        .unwrap();
        assert!(root.open_read(os("pipe")).is_err());
    }

    #[test]
    fn discards_only_the_opened_incomplete_file() {
        let temp = tempfile::tempdir().unwrap();
        let cap = DirectoryCap::open_root(temp.path()).unwrap();
        let mut incomplete = cap.create_new(os("partial")).unwrap();
        incomplete.write_all(b"partial output").unwrap();
        cap.discard_created(os("partial"), incomplete).unwrap();
        assert!(!temp.path().join("partial").exists());
        #[cfg(unix)]
        {
            let original = cap.create_new(os("changed")).unwrap();
            std::fs::rename(temp.path().join("changed"), temp.path().join("moved")).unwrap();
            std::fs::write(temp.path().join("changed"), b"foreign").unwrap();
            assert!(cap.discard_created(os("changed"), original).is_err());
            assert_eq!(
                std::fs::read(temp.path().join("changed")).unwrap(),
                b"foreign"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn retained_directories_and_source_refuse_concurrent_rename() {
        let temp = tempfile::tempdir().unwrap();
        let root = DirectoryCap::open_root(temp.path()).unwrap();
        let parent = root.create_dir_all(Path::new("parent")).unwrap();
        assert!(std::fs::rename(temp.path().join("parent"), temp.path().join("replaced")).is_err());
        parent
            .create_new(os("source"))
            .unwrap()
            .write_all(b"owned")
            .unwrap();
        let source = parent.prepare_rename(os("source")).unwrap();
        assert!(
            std::fs::rename(
                temp.path().join("parent/source"),
                temp.path().join("parent/replaced")
            )
            .is_err()
        );
        source.rename_noreplace(&parent, os("renamed")).unwrap();
        assert_eq!(
            std::fs::read(temp.path().join("parent/renamed")).unwrap(),
            b"owned"
        );
    }

    #[cfg(windows)]
    #[test]
    fn refuses_intermediate_final_and_root_junctions() {
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let root = DirectoryCap::open_root(temp.path()).unwrap();
        let link = temp.path().join("junction");
        // Junction creation does not require symlink privilege/developer mode on Windows.
        let status = std::process::Command::new("cmd.exe")
            .current_dir(temp.path())
            .args(["/d", "/c", "mklink", "/j"])
            .arg(&link)
            .arg(outside.path())
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        assert!(root.open_dir(Path::new("junction")).is_err());
        assert!(root.create_dir_all(Path::new("junction/new")).is_err());
        assert!(root.prepare_rename(os("junction")).is_err());
        assert!(root.open_read(os("junction")).is_err());
        assert!(DirectoryCap::open_root(&link).is_err());
        std::fs::remove_dir(link).unwrap();
    }
}
