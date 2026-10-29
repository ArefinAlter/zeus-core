//! Filesystem implementation rooted in retained directory capabilities. Opening configured roots
//! is the sole ambient authority boundary; every data path after it uses relative, no-follow opens.
//! This is the engine default. `RealFs` and injected simulation implementations remain compatible.
use crate::{
    DataFile, DirEntryInfo, DirectoryCap, FileMeta, Filesystem, FsError, FsResult, PreallocOutcome,
};
use std::{
    ffi::{OsStr, OsString},
    path::{Component, Path, PathBuf},
};
use zeus_types::FileId;

/// Real filesystem restricted to explicitly configured roots retained for its lifetime.
#[derive(Debug)]
pub struct RetainedFs {
    roots: Vec<(PathBuf, DirectoryCap)>,
}

fn missing(e: &FsError) -> bool {
    matches!(e, FsError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound)
}
fn normalized(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::{OsStrExt, OsStringExt};
        let units: Vec<u16> = path.as_os_str().encode_wide().collect();
        let unc: Vec<u16> = r"\\?\UNC\".encode_utf16().collect();
        let local: Vec<u16> = r"\\?\".encode_utf16().collect();
        if units.starts_with(&unc) {
            let mut plain = vec![b'\\' as u16, b'\\' as u16];
            plain.extend_from_slice(&units[unc.len()..]);
            return PathBuf::from(OsString::from_wide(&plain));
        }
        if units.starts_with(&local) && units.get(local.len() + 1) == Some(&(b':' as u16)) {
            return PathBuf::from(OsString::from_wide(&units[local.len()..]));
        }
    }
    path.to_path_buf()
}
impl RetainedFs {
    /// Capture configured roots after their existing policy validation. Each root identity is
    /// checked against the opened object, preventing substitution between validation and capture.
    pub fn open(roots: &crate::WriteRoots) -> FsResult<Self> {
        let mut held = Vec::new();
        for root in roots.roots() {
            let cap = DirectoryCap::open_root(root.path())?;
            if root.identity() != Some(&cap.file_id()?) {
                return Err(FsError::OutsideRoots);
            }
            held.push((normalized(root.path()), cap));
        }
        held.sort_by_key(|(p, _)| std::cmp::Reverse(p.components().count()));
        Ok(Self { roots: held })
    }
    fn relative<'a>(&'a self, path: &Path) -> FsResult<(&'a DirectoryCap, PathBuf)> {
        let path = normalized(path);
        if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(FsError::OutsideRoots);
        }
        for (root, cap) in &self.roots {
            if let Ok(rel) = path.strip_prefix(root) {
                return Ok((cap, rel.to_path_buf()));
            }
            #[cfg(windows)]
            {
                let mut parts = path.components();
                if root.components().all(|r| {
                    parts.next().is_some_and(|p| {
                        r.as_os_str()
                            .as_encoded_bytes()
                            .eq_ignore_ascii_case(p.as_os_str().as_encoded_bytes())
                    })
                }) {
                    return Ok((cap, parts.as_path().to_path_buf()));
                }
            }
        }
        Err(FsError::OutsideRoots)
    }
    fn directory(&self, path: &Path) -> FsResult<DirectoryCap> {
        let (root, relative) = self.relative(path)?;
        root.open_dir(&relative)
    }
    fn parent(&self, path: &Path) -> FsResult<(DirectoryCap, OsString)> {
        let (root, relative) = self.relative(path)?;
        let name = relative.file_name().ok_or(FsError::OutsideRoots)?;
        crate::directory::validate_filename(name)?;
        Ok((
            root.open_dir(relative.parent().ok_or(FsError::OutsideRoots)?)?,
            name.to_owned(),
        ))
    }
    fn file(&self, path: &Path, create: bool, write: bool) -> FsResult<Box<dyn DataFile>> {
        let (parent, name) = self.parent(path)?;
        let file = if create {
            parent.create_new(&name)?
        } else if write {
            parent.open_existing(&name)?
        } else {
            parent.open_read(&name)?
        };
        Ok(Box::new(RetainedFile {
            file: crate::fs::RealDataFile(file),
            parent,
            name,
        }))
    }
}
#[derive(Debug)]
struct RetainedFile {
    file: crate::fs::RealDataFile,
    parent: DirectoryCap,
    name: OsString,
}
impl DataFile for RetainedFile {
    fn write_all_at(&self, at: u64, buf: &[u8]) -> FsResult<()> {
        self.file.write_all_at(at, buf)
    }
    fn read_at(&self, at: u64, buf: &mut [u8]) -> FsResult<usize> {
        self.file.read_at(at, buf)
    }
    fn sync_data(&self) -> FsResult<()> {
        self.file.sync_data()
    }
    fn sync_all(&self) -> FsResult<()> {
        self.file.sync_all()
    }
    fn set_len(&self, n: u64) -> FsResult<()> {
        self.file.set_len(n)
    }
    fn len(&self) -> FsResult<u64> {
        self.file.len()
    }
    fn preallocate(&self, n: u64) -> FsResult<PreallocOutcome> {
        self.file.preallocate(n)
    }
    fn file_id(&self) -> FsResult<FileId> {
        self.file.file_id()
    }
    fn metadata(&self) -> FsResult<FileMeta> {
        self.file.metadata()
    }
    fn native_file(&self) -> Option<&std::fs::File> {
        self.file.native_file()
    }
    fn retained_location(&self) -> Option<(&DirectoryCap, &OsStr)> {
        Some((&self.parent, &self.name))
    }
}
impl Filesystem for RetainedFs {
    fn create_new(&self, path: &Path) -> FsResult<Box<dyn DataFile>> {
        self.file(path, true, true)
    }
    fn open_existing(&self, path: &Path) -> FsResult<Box<dyn DataFile>> {
        self.file(path, false, true)
    }
    fn open_read(&self, path: &Path) -> FsResult<Box<dyn DataFile>> {
        self.file(path, false, false)
    }
    fn metadata(&self, path: &Path) -> FsResult<Option<FileMeta>> {
        let (root, relative) = self.relative(path)?;
        if relative.as_os_str().is_empty() {
            return root.metadata().map(Some);
        }
        let result = self.parent(path).and_then(|(p, n)| p.entry_metadata(&n));
        match result {
            Ok(m) => Ok(Some(m)),
            Err(e) if missing(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }
    fn rename_noreplace(&self, from: &Path, to: &Path) -> FsResult<()> {
        let (source, name) = self.parent(from)?;
        let (dest, target) = self.parent(to)?;
        source
            .prepare_rename(&name)?
            .rename_noreplace(&dest, &target)
    }
    fn publish_opened(&self, _from: &Path, to: &Path, file: &dyn DataFile) -> FsResult<()> {
        let (source, name) = file
            .retained_location()
            .ok_or(FsError::Unsupported("retained publication for custom file"))?;
        let native = file
            .native_file()
            .ok_or(FsError::Unsupported("native retained file"))?;
        let (dest, target) = self.parent(to)?;
        source.publish_opened(name, native, &dest, &target)
    }
    fn mark_opened(
        &self,
        _path: &Path,
        file: &dyn DataFile,
        marks: &crate::provenance::ProvenanceMarks,
        mode: zeus_types::OsMetadataMode,
    ) -> FsResult<Vec<zeus_types::OsMetadataKind>> {
        let (parent, name) = file
            .retained_location()
            .ok_or(FsError::Unsupported("retained marks for custom file"))?;
        parent.mark_opened(
            name,
            file.native_file()
                .ok_or(FsError::Unsupported("native retained file"))?,
            marks,
            mode,
        )
    }
    fn replace_with_backup(&self, _from: &Path, _to: &Path, _backup: &Path) -> FsResult<()> {
        // The engine only publishes without replacement. Do not weaken the legacy atomic backup
        // contract by implementing it as a fallible sequence of two directory-relative renames.
        Err(FsError::Unsupported(
            "atomic retained replacement with backup",
        ))
    }
    fn sync_dir(&self, path: &Path) -> FsResult<()> {
        self.directory(path)?.sync()
    }
    fn remove_file(&self, path: &Path) -> FsResult<()> {
        let result = self.parent(path).and_then(|(p, n)| {
            let item = p.prepare_rename(&n)?;
            let m = item.metadata()?;
            if !m.is_regular_file {
                return Err(FsError::SymlinkRefused);
            }
            item.remove(&m.file_id.ok_or(FsError::OutsideRoots)?)
        });
        match result {
            Err(e) if missing(&e) => Ok(()),
            other => other,
        }
    }
    fn remove_expected(&self, path: &Path, expected: &FileId) -> FsResult<()> {
        let result = self.parent(path).and_then(|(p, n)| {
            let item = p.prepare_rename(&n)?;
            if !item.metadata()?.is_regular_file {
                return Err(FsError::SymlinkRefused);
            }
            item.remove(expected)
        });
        match result {
            Err(e) if missing(&e) => Ok(()),
            other => other,
        }
    }
    fn create_dir_all(&self, path: &Path) -> FsResult<()> {
        let (root, relative) = self.relative(path)?;
        root.create_dir_all(&relative).map(|_| ())
    }
    fn read_dir(&self, path: &Path) -> FsResult<Vec<DirEntryInfo>> {
        let dir = self.directory(path)?;
        let mut entries = Vec::new();
        for name in dir.iter_names()? {
            let name = name?;
            // Orphan discovery skips links and unsupported special entries; it never follows them.
            match dir.entry_metadata(&name) {
                Ok(meta) => entries.push(DirEntryInfo {
                    name: name.to_string_lossy().into_owned(),
                    path: path.join(name),
                    meta,
                }),
                Err(FsError::SymlinkRefused | FsError::InvalidName(_)) => (),
                Err(e) if missing(&e) => (),
                Err(e) => return Err(e),
            }
        }
        Ok(entries)
    }
    fn free_space(&self, path: &Path) -> FsResult<u64> {
        self.directory(path)?.free_space()
    }
    fn canonicalize(&self, path: &Path) -> FsResult<PathBuf> {
        self.metadata(path)?
            .ok_or_else(|| FsError::from(std::io::Error::from(std::io::ErrorKind::NotFound)))?;
        Ok(normalized(path))
    }
    fn is_case_insensitive(&self, path: &Path) -> FsResult<bool> {
        self.directory(path)?;
        Ok(cfg!(any(windows, target_os = "macos")))
    }
}
