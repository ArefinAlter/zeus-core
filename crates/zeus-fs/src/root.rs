//! Write roots and path containment (01 section 12.3 rule 1, 03 section 14).
//!
//! Every destination is canonicalised and must lie inside a configured write root **after resolving
//! symlinks** (the bug class Playwright MCP fixed in 2025). A [`SafeRoot`] hands out only paths it has
//! checked, and re-checking at the moment of use (`check_existing`) closes the time-of-check gap
//! together with the no-follow open flags of [`crate::Filesystem`].

use std::path::{Path, PathBuf};

use crate::error::{FsError, FsResult};

/// One canonicalised write root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeRoot {
    root: PathBuf,
    identity: Option<zeus_types::FileId>,
}

impl SafeRoot {
    /// Canonicalises `path` (which must exist and be a directory) into a root.
    pub fn open(path: &Path) -> FsResult<Self> {
        let root = std::fs::canonicalize(path)?;
        if !root.is_dir() {
            return Err(FsError::InvalidName("write root must be a directory"));
        }
        let identity = crate::Filesystem::metadata(&crate::RealFs, &root)?.and_then(|m| m.file_id);
        Ok(Self { root, identity })
    }

    /// The canonical root path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.root
    }

    /// Joins a *relative* path to the root without touching the file system and rejects anything that
    /// could escape: absolute paths, drive or UNC prefixes, `..` components, device paths
    /// (`\\.\`, `\\?\`), alternate-data-stream syntax (`name:stream`) and empty components.
    /// Symlinks are checked later by [`SafeRoot::check_existing`].
    pub fn join_checked(&self, relative: &Path) -> FsResult<PathBuf> {
        let text = relative.to_string_lossy();
        if text.is_empty()
            || text.contains(['\\', ':'])
            || text
                .split('/')
                .any(|c| c.is_empty() || c == "." || c == "..")
            || relative
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err(FsError::OutsideRoots);
        }
        Ok(self.root.join(relative))
    }

    /// Resolves symlinks, junctions and reparse points in the existing part of `path` and verifies the
    /// result still lies inside the root. Returns the resolved path.
    pub fn check_existing(&self, path: &Path) -> FsResult<PathBuf> {
        if crate::Filesystem::metadata(&crate::RealFs, &self.root)?.and_then(|m| m.file_id)
            != self.identity
        {
            return Err(FsError::OutsideRoots);
        }
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.join_checked(path)?
        };
        if path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(FsError::OutsideRoots);
        }
        if path.components().any(
            |c| matches!(c, std::path::Component::Normal(n) if n.to_string_lossy().contains(':')),
        ) {
            return Err(FsError::OutsideRoots);
        }
        let mut ancestor = path.as_path();
        let mut suffix = Vec::new();
        while !ancestor.try_exists()? {
            suffix.push(
                ancestor
                    .file_name()
                    .ok_or(FsError::OutsideRoots)?
                    .to_os_string(),
            );
            ancestor = ancestor.parent().ok_or(FsError::OutsideRoots)?;
        }
        let mut resolved = std::fs::canonicalize(ancestor)?;
        if !resolved.starts_with(&self.root) {
            return Err(FsError::OutsideRoots);
        }
        for name in suffix.iter().rev() {
            resolved.push(name);
        }
        Ok(resolved)
    }

    /// True when `path` (after resolving what exists) is inside this root.
    pub fn contains(&self, path: &Path) -> FsResult<bool> {
        match self.check_existing(path) {
            Ok(_) => Ok(true),
            Err(FsError::OutsideRoots) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// The set of configured write roots; a destination must lie inside one of them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WriteRoots {
    roots: Vec<SafeRoot>,
}

impl WriteRoots {
    /// Opens every root; fails on the first that cannot be canonicalised.
    pub fn open(paths: &[PathBuf]) -> FsResult<Self> {
        paths
            .iter()
            .map(|p| SafeRoot::open(p))
            .collect::<FsResult<Vec<_>>>()
            .map(|roots| Self { roots })
    }

    /// The roots.
    #[must_use]
    pub fn roots(&self) -> &[SafeRoot] {
        &self.roots
    }

    /// True when no root is configured (then every write is refused).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// The root that contains `dir`, after symlink resolution, or [`FsError::OutsideRoots`].
    pub fn root_for(&self, dir: &Path) -> FsResult<&SafeRoot> {
        for root in &self.roots {
            if root.contains(dir)? {
                return Ok(root);
            }
        }
        Err(FsError::OutsideRoots)
    }

    /// Resolves the directory a job writes into: it must exist (or be creatable inside a root) and lie
    /// inside a root. Returns the canonical directory.
    pub fn resolve_dest_dir(&self, dir: &Path) -> FsResult<PathBuf> {
        self.root_for(dir)?.check_existing(dir)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_set_of_roots_is_empty() {
        let roots = WriteRoots::open(&[]).unwrap();
        assert!(roots.is_empty());
        assert!(roots.roots().is_empty());
    }
}
