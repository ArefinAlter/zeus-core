//! Observed file allocation and hard-link identity. This is accounting metadata, never authority.
//! Reflinks, filesystem compression/deduplication and shared extents can make totals differ from
//! volume free-space changes; aliases outside the selected roots are not inspected.
use crate::{FsResult, fs::file_identity};
use serde::{Deserialize, Serialize};

/// Storage facts obtained from one retained file handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileStorage {
    /// Volume/inode or volume/file-index identity, used to count observed aliases once.
    pub file_id: zeus_types::FileId,
    /// Allocated bytes reported by this filesystem; absence means unsupported or unreadable.
    pub allocated_bytes: Option<u64>,
    /// Total hard-link count reported for the file, including names outside selected roots.
    pub hard_links: Option<u64>,
}
/// Native metadata and optional storage facts from a single no-follow open.
#[derive(Debug)]
pub struct EntryObservation {
    /// Standard OS metadata, including hidden/system flags used by the index.
    pub metadata: std::fs::Metadata,
    /// Regular-file identity and filesystem allocation observations, if available.
    pub storage: Option<FileStorage>,
}

pub(crate) fn observe(file: &std::fs::File, metadata: &std::fs::Metadata) -> FsResult<FileStorage> {
    let file_id = file_identity(file)?;
    #[cfg(unix)]
    let (allocated_bytes, hard_links) = {
        use std::os::unix::fs::MetadataExt;
        (metadata.blocks().checked_mul(512), Some(metadata.nlink()))
    };
    #[cfg(windows)]
    let (allocated_bytes, hard_links) = {
        let _ = metadata;
        crate::sys::storage_observation(file)
    };
    #[cfg(not(any(unix, windows)))]
    let (allocated_bytes, hard_links) = {
        let _ = metadata;
        (None, None)
    };
    Ok(FileStorage {
        file_id,
        allocated_bytes,
        hard_links,
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    #[test]
    fn alias_identity_and_link_count_come_from_the_opened_object() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a"), b"allocated fixture").unwrap();
        std::fs::hard_link(tmp.path().join("a"), tmp.path().join("alias")).unwrap();
        let root = crate::DirectoryCap::open_root(tmp.path()).unwrap();
        let first = root.entry_observation(OsStr::new("a")).unwrap();
        let alias = root.entry_observation(OsStr::new("alias")).unwrap();
        let a = first.storage.unwrap();
        let b = alias.storage.unwrap();
        assert_eq!(a.file_id, b.file_id);
        assert!(a.hard_links.unwrap() >= 2);
        assert_eq!(a.allocated_bytes, b.allocated_bytes);
        assert_eq!(first.metadata.len(), 17);
    }
    #[cfg(unix)]
    #[test]
    fn sparse_file_observation_does_not_substitute_logical_length() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::File::create(tmp.path().join("sparse"))
            .unwrap()
            .set_len(32 * 1024 * 1024)
            .unwrap();
        let root = crate::DirectoryCap::open_root(tmp.path()).unwrap();
        let observed = root.entry_observation(OsStr::new("sparse")).unwrap();
        use std::os::unix::fs::MetadataExt;
        assert_eq!(
            observed.storage.unwrap().allocated_bytes,
            observed.metadata.blocks().checked_mul(512)
        );
    }
}
