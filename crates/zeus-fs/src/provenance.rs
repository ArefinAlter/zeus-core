//! OS provenance metadata (04 section 6): Mark-of-the-Web and origin attributes written to the data
//! file **before** the final rename (03 section 8.1 step F1), so the final file is never visible
//! without them.
//!
//! These attributes are a convenience for other software. Zeus never *reads* them as provenance: any
//! program can edit them. The manifest and the audit log are the record.

use std::path::Path;

use zeus_types::{OsMetadataKind, OsMetadataMode, RedactedUrl};

use crate::error::{FsError, FsResult};

/// What to record about where a file came from. URLs are already redacted (`strict` mode: query
/// dropped, secret-looking path segments masked); the raw job URL is never accepted here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceMarks {
    /// The redacted download URL (`HostUrl`, `kMDItemWhereFroms[0]`, `user.xdg.origin.url`).
    pub origin_url: Option<RedactedUrl>,
    /// The redacted referrer (`ReferrerUrl`, `kMDItemWhereFroms[1]`, `user.xdg.referrer.url`).
    pub referrer_url: Option<RedactedUrl>,
    /// Time the file was retrieved, seconds since the Unix epoch (macOS quarantine timestamp).
    pub retrieved_at_unix_s: i64,
}

/// Writes OS provenance attributes.
pub trait ProvenanceMarker: Send + Sync {
    /// Applies the marks permitted by `mode` to the data file at `path` and returns which attributes
    /// were actually written. Idempotent. A file system without the facility (FAT, exFAT, tmpfs
    /// without user xattrs, many network shares) yields `Ok(vec![])`, never an error.
    ///
    /// When the job came from a private window, used a session, or the destination is a network
    /// share, removable medium or cloud-synchronised folder, the *caller* lowers `mode` to
    /// `MarkOnly` or `Off` first (04 section 6.5); this trait does not decide privacy.
    fn apply(
        &self,
        path: &Path,
        marks: &ProvenanceMarks,
        mode: OsMetadataMode,
    ) -> FsResult<Vec<OsMetadataKind>>;
}

/// The marker for the current platform: `Zone.Identifier` on Windows, `com.apple.quarantine` and
/// `kMDItemWhereFroms` on macOS, `user.xdg.*` on Linux.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeMarker;

impl ProvenanceMarker for NativeMarker {
    fn apply(
        &self,
        path: &Path,
        marks: &ProvenanceMarks,
        mode: OsMetadataMode,
    ) -> FsResult<Vec<OsMetadataKind>> {
        if mode == OsMetadataMode::Off {
            return Ok(Vec::new());
        }
        if !crate::Filesystem::metadata(&crate::RealFs, path)?.is_some_and(|m| m.is_regular_file) {
            return Err(FsError::SymlinkRefused);
        }
        #[cfg(windows)]
        {
            use std::io::Write;
            let mut stream = path.as_os_str().to_os_string();
            stream.push(":Zone.Identifier");
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(std::path::PathBuf::from(stream))?;
            file.write_all(
                zone_identifier_text(marks, mode)
                    .unwrap_or_default()
                    .as_bytes(),
            )?;
            file.sync_all()?;
            Ok(vec![OsMetadataKind::ZoneIdentifier])
        }
        #[cfg(target_os = "macos")]
        {
            let quarantine = format!("0083;{:08x};Zeus;", marks.retrieved_at_unix_s);
            xattr::set(path, "com.apple.quarantine", quarantine.as_bytes())?;
            // Quarantine is always written; URL-bearing Finder plist support is separate.
            Ok(vec![OsMetadataKind::QuarantineXattr])
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let mut written = Vec::new();
            if mode == OsMetadataMode::Full {
                if let Some(url) = &marks.origin_url {
                    xattr::set(path, "user.xdg.origin.url", url.to_string().as_bytes())?;
                    written.push(OsMetadataKind::XdgOriginUrl);
                }
                if let Some(url) = &marks.referrer_url {
                    xattr::set(path, "user.xdg.referrer.url", url.to_string().as_bytes())?;
                    written.push(OsMetadataKind::XdgReferrerUrl);
                }
            }
            Ok(written)
        }
    }
}

/// A marker that records nothing; for tests and for `mode = off` roots.
#[derive(Debug, Clone, Copy, Default)]
pub struct NullMarker;

impl ProvenanceMarker for NullMarker {
    fn apply(
        &self,
        _path: &Path,
        _marks: &ProvenanceMarks,
        _mode: OsMetadataMode,
    ) -> FsResult<Vec<OsMetadataKind>> {
        Ok(Vec::new())
    }
}

/// The content of the `Zone.Identifier` stream (CRLF line endings, no byte-order mark) for `mode`.
/// `mark_only` writes `ZoneId=3` only; `full` adds `ReferrerUrl` and `HostUrl` (04 section 6.2).
#[must_use]
pub fn zone_identifier_text(marks: &ProvenanceMarks, mode: OsMetadataMode) -> Option<String> {
    match mode {
        OsMetadataMode::Off => None,
        OsMetadataMode::MarkOnly => Some("[ZoneTransfer]\r\nZoneId=3\r\n".to_owned()),
        OsMetadataMode::Full => {
            let mut text = String::from("[ZoneTransfer]\r\nZoneId=3\r\n");
            if let Some(r) = &marks.referrer_url {
                text.push_str(&format!("ReferrerUrl={r}\r\n"));
            }
            if let Some(h) = &marks.origin_url {
                text.push_str(&format!("HostUrl={h}\r\n"));
            }
            Some(text)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn marks() -> ProvenanceMarks {
        ProvenanceMarks {
            origin_url: Some(
                RedactedUrl::new("https://cdn.example.org/blobs/dataset-v3.tar.zst").unwrap(),
            ),
            referrer_url: Some(RedactedUrl::new("https://portal.example.org/datasets/v3").unwrap()),
            retrieved_at_unix_s: 1_790_000_000,
        }
    }

    #[test]
    fn zone_identifier_matches_the_specification() {
        assert_eq!(zone_identifier_text(&marks(), OsMetadataMode::Off), None);
        assert_eq!(
            zone_identifier_text(&marks(), OsMetadataMode::MarkOnly).unwrap(),
            "[ZoneTransfer]\r\nZoneId=3\r\n"
        );
        assert_eq!(
            zone_identifier_text(&marks(), OsMetadataMode::Full).unwrap(),
            "[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://portal.example.org/datasets/v3\r\nHostUrl=https://cdn.example.org/blobs/dataset-v3.tar.zst\r\n"
        );
    }

    #[test]
    fn null_marker_writes_nothing() {
        let written = NullMarker
            .apply(Path::new("x"), &marks(), OsMetadataMode::Full)
            .unwrap();
        assert!(written.is_empty());
    }
}

/// Apply native Unix attributes to the already opened object, without reopening an ambient path.
#[cfg(unix)]
pub(crate) fn mark_opened(
    file: &std::fs::File,
    marks: &ProvenanceMarks,
    mode: OsMetadataMode,
) -> FsResult<Vec<OsMetadataKind>> {
    use xattr::FileExt;
    if mode == OsMetadataMode::Off {
        return Ok(Vec::new());
    }
    #[cfg(target_os = "macos")]
    {
        let quarantine = format!("0083;{:08x};Zeus;", marks.retrieved_at_unix_s);
        file.set_xattr("com.apple.quarantine", quarantine.as_bytes())?;
        Ok(vec![OsMetadataKind::QuarantineXattr])
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut written = Vec::new();
        if mode == OsMetadataMode::Full {
            if let Some(url) = &marks.origin_url {
                file.set_xattr("user.xdg.origin.url", url.to_string().as_bytes())?;
                written.push(OsMetadataKind::XdgOriginUrl);
            }
            if let Some(url) = &marks.referrer_url {
                file.set_xattr("user.xdg.referrer.url", url.to_string().as_bytes())?;
                written.push(OsMetadataKind::XdgReferrerUrl);
            }
        }
        Ok(written)
    }
}
