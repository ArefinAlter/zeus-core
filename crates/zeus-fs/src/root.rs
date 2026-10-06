//! Write roots and path containment (01 section 12.3 rule 1, 03 section 14).
//!
//! Every destination is canonicalised and must lie inside a configured write root **after resolving
//! symlinks** (the bug class Playwright MCP fixed in 2025). A [`SafeRoot`] hands out only paths it has
//! checked, and re-checking at the moment of use (`check_existing`) closes the time-of-check gap
//! together with the no-follow open flags of [`crate::Filesystem`].
#![expect(
    unused_variables,
    reason = "skeleton: bodies are filled in by the zeus-fs implementation task"
)]

use std::path::{Path, PathBuf};

use crate::error::{FsError, FsResult};

/// One canonicalised write root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SafeRoot {
    root: PathBuf,
}

impl SafeRoot {
    /// Canonicalises `path` (which must exist and be a directory) into a root.
    pub fn open(path: &Path) -> FsResult<Self> {
        Err(FsError::NotImplemented("SafeRoot::open"))
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
        Err(FsError::NotImplemented("SafeRoot::join_checked"))
    }

    /// Resolves symlinks, junctions and reparse points in the existing part of `path` and verifies the
    /// result still lies inside the root. Returns the resolved path.
    pub fn check_existing(&self, path: &Path) -> FsResult<PathBuf> {
        Err(FsError::NotImplemented("SafeRoot::check_existing"))
    }

    /// True when `path` (after resolving what exists) is inside this root.
    pub fn contains(&self, path: &Path) -> FsResult<bool> {
        Err(FsError::NotImplemented("SafeRoot::contains"))
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
        Err(FsError::NotImplemented("WriteRoots::root_for"))
    }

    /// Resolves the directory a job writes into: it must exist (or be creatable inside a root) and lie
    /// inside a root. Returns the canonical directory.
    pub fn resolve_dest_dir(&self, dir: &Path) -> FsResult<PathBuf> {
        Err(FsError::NotImplemented("WriteRoots::resolve_dest_dir"))
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
