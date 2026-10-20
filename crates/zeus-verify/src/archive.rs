//! Archive-bomb guard (01 section 11.3, `archive_limits`; 12 "archive-bomb limits").
//!
//! Zeus never expands an archive on its own. When an inspection or a conversion does, it feeds every
//! entry to an [`ArchiveGuard`] first; the guard enforces the limits as a policy so the extractor
//! stays a dumb loop. The extractor itself is out of scope for this crate.
/// Safety limits for archive inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchiveLimits {
    /// Maximum ratio of uncompressed to compressed size (default 100).
    pub max_ratio: u64,
    /// Maximum nesting depth of archives inside archives (default 3).
    pub max_depth: u32,
    /// Maximum number of entries (default 10,000).
    pub max_entries: u64,
    /// Maximum total uncompressed size in bytes (default 100 GiB).
    pub max_total_bytes: u64,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_ratio: 100,
            max_depth: 3,
            max_entries: 10_000,
            max_total_bytes: 100 << 30,
        }
    }
}

/// One entry as reported by an extractor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryInfo<'a> {
    /// The entry's path inside the archive, exactly as stored.
    pub path: &'a str,
    /// Compressed size in bytes.
    pub compressed_bytes: u64,
    /// Uncompressed size in bytes.
    pub uncompressed_bytes: u64,
    /// Nesting depth of the archive that contains this entry (0 for the outermost).
    pub depth: u32,
    /// The entry is a symlink or hard link.
    pub is_link: bool,
}

/// Which limit an entry violated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ArchiveViolation {
    /// The compression ratio exceeds `max_ratio`.
    #[error("compression ratio above the limit")]
    Ratio,
    /// Nested deeper than `max_depth`.
    #[error("archive nesting too deep")]
    Depth,
    /// More than `max_entries` entries.
    #[error("too many entries")]
    Entries,
    /// More than `max_total_bytes` uncompressed.
    #[error("uncompressed size above the limit")]
    TotalBytes,
    /// The entry path escapes the archive root (`..`, absolute, drive letter, or a link out of it).
    #[error("entry path escapes the archive root")]
    PathEscape,
}

/// Accumulates per-archive totals and judges each entry.
#[derive(Debug, Clone)]
pub struct ArchiveGuard {
    limits: ArchiveLimits,
    entries: u64,
    total_bytes: u64,
}

impl ArchiveGuard {
    /// A guard with the given limits and no entries seen.
    #[must_use]
    pub fn new(limits: ArchiveLimits) -> Self {
        Self {
            limits,
            entries: 0,
            total_bytes: 0,
        }
    }

    /// Records `entry` and returns the violated limit, if any. After a violation the caller stops.
    pub fn observe(&mut self, entry: &EntryInfo<'_>) -> Result<(), ArchiveViolation> {
        if entry.is_link || entry_path_escapes(entry.path) {
            return Err(ArchiveViolation::PathEscape);
        }
        if entry.depth > self.limits.max_depth {
            return Err(ArchiveViolation::Depth);
        }
        self.entries = self.entries.saturating_add(1);
        if self.entries > self.limits.max_entries {
            return Err(ArchiveViolation::Entries);
        }
        self.total_bytes = self.total_bytes.saturating_add(entry.uncompressed_bytes);
        if self.total_bytes > self.limits.max_total_bytes {
            return Err(ArchiveViolation::TotalBytes);
        }
        if u128::from(entry.uncompressed_bytes)
            > u128::from(entry.compressed_bytes.max(1)) * u128::from(self.limits.max_ratio)
        {
            return Err(ArchiveViolation::Ratio);
        }
        Ok(())
    }
}

/// True when an archive entry path could write outside the extraction root: absolute, starts with a
/// drive letter or UNC prefix, contains a `..` component, or contains a NUL.
#[must_use]
pub fn entry_path_escapes(path: &str) -> bool {
    let normalised = path.replace('\\', "/");
    normalised.starts_with('/')
        || normalised.contains('\0')
        || normalised.split('/').any(|c| c == "..")
        || normalised.contains(':')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, compressed: u64, uncompressed: u64, depth: u32) -> EntryInfo<'_> {
        EntryInfo {
            path,
            compressed_bytes: compressed,
            uncompressed_bytes: uncompressed,
            depth,
            is_link: false,
        }
    }

    #[test]
    fn guard_enforces_every_limit() {
        let limits = ArchiveLimits {
            max_entries: 3,
            max_total_bytes: 1000,
            ..ArchiveLimits::default()
        };
        let fresh = || ArchiveGuard::new(limits);
        assert_eq!(fresh().observe(&entry("a", 10, 100, 0)), Ok(()));
        assert_eq!(
            fresh().observe(&entry("../b", 10, 10, 0)),
            Err(ArchiveViolation::PathEscape)
        );
        assert_eq!(
            fresh().observe(&entry("c", 10, 10, 4)),
            Err(ArchiveViolation::Depth)
        );
        assert_eq!(
            fresh().observe(&entry("d", 1, 101, 0)),
            Err(ArchiveViolation::Ratio)
        );
        assert_eq!(
            fresh().observe(&entry("d", 1, 100, 0)),
            Ok(()),
            "exactly at the ratio limit is allowed"
        );
        let mut g = fresh();
        assert_eq!(g.observe(&entry("e", 900, 900, 0)), Ok(()));
        assert_eq!(
            g.observe(&entry("f", 900, 900, 0)),
            Err(ArchiveViolation::TotalBytes)
        );
        let mut g = ArchiveGuard::new(limits);
        for i in 0..3 {
            assert_eq!(g.observe(&entry(&format!("f{i}"), 1, 1, 0)), Ok(()));
        }
        assert_eq!(
            g.observe(&entry("one-too-many", 1, 1, 0)),
            Err(ArchiveViolation::Entries)
        );
    }

    #[test]
    fn zip_slip_paths_are_flagged() {
        for bad in [
            "../evil",
            "a/../../evil",
            "/etc/passwd",
            "C:\\Windows\\x",
            "dir\\..\\..\\x",
            "a\0b",
        ] {
            assert!(entry_path_escapes(bad), "{bad:?}");
        }
        for ok in ["a/b/c.txt", "dir/file..name", ".hidden", "a/b/"] {
            assert!(!entry_path_escapes(ok), "{ok:?}");
        }
    }

    #[test]
    fn defaults_match_the_specification() {
        let l = ArchiveLimits::default();
        assert_eq!((l.max_ratio, l.max_depth, l.max_entries), (100, 3, 10_000));
    }
}
