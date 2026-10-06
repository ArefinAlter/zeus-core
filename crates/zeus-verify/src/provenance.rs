//! The provenance manifest v0 (04 section 3): one JSON Lines ledger per write root, a header then one
//! record per file, answering "where did this file come from and what is it?".
//!
//! Records are append-only; a replaced file produces a new record and consumers use the most recent
//! per `path`. URLs are always redacted (`record` or `strict` mode): there is no way to store a raw URL
//! in a manifest. Absolute paths never appear, so manifests do not leak user names.
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: ProvenanceWriter and export are filled in by the zeus-verify implementation task"
)]

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeus_types::{
    AuditHead, Hex256, JobId, Origin, OsMetadataKind, OsMetadataMode, RedactedUrl, RunId,
    SourceKind, Timestamp,
};

use crate::error::{VerifyError, VerifyResult};

/// Which digests every file record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlgorithm {
    /// SHA-256.
    Sha256,
    /// BLAKE3.
    Blake3,
}

/// How URL queries are stored in the manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UrlQueryPrivacy {
    /// `redact_url` in `record` mode: secret-looking parameters dropped, the rest kept.
    Sanitized,
    /// `redact_url` in `strict` mode: the query is dropped entirely.
    Dropped,
}

/// The privacy block of the header: what was removed or never written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Privacy {
    /// URL query handling.
    pub url_query: UrlQueryPrivacy,
    /// If false, every `session_origin` is `null`.
    pub session_origin_included: bool,
    /// What OS metadata was written to the files.
    pub os_metadata: OsMetadataMode,
}

/// `{name: "zeus", version}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generator {
    /// Always `zeus`.
    pub name: String,
    /// The generating version.
    pub version: String,
}

/// The first line of a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestHeader {
    /// Always `header`.
    pub record_type: HeaderTag,
    /// Always 0.
    pub manifest_version: u8,
    /// When the ledger (or export) was created.
    pub created_at: Timestamp,
    /// The generator.
    pub generator: Generator,
    /// Present on exports of one workflow run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    /// Human label of the root (not a path).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_label: Option<String>,
    /// Privacy block.
    pub privacy: Privacy,
    /// Digests present in every file record.
    pub hash_algorithms: Vec<HashAlgorithm>,
}

/// Tag type of the header record: serialises as `"header"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderTag {
    /// The header record.
    Header,
}

/// Tag type of a file record: serialises as `"file"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileTag {
    /// A file record.
    File,
}

/// Where the file came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSource {
    /// Who asked.
    pub kind: SourceKind,
    /// `spec.url` after `redact_url`.
    pub url: RedactedUrl,
    /// The final URL after redirects, likewise redacted.
    pub final_url: RedactedUrl,
    /// True when redaction removed or masked anything in `url`, `final_url` or `referrer`.
    pub url_redacted: bool,
    /// The referrer, redacted, when the job had one and privacy allows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer: Option<RedactedUrl>,
}

/// The validators the bytes were fetched under.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestHttp {
    /// Status of the first data response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// Entity tag.
    #[serde(default)]
    pub etag: Option<String>,
    /// `Last-Modified`.
    #[serde(default)]
    pub last_modified: Option<String>,
    /// `Date`.
    #[serde(default)]
    pub date: Option<String>,
    /// `Repr-Digest`.
    #[serde(default)]
    pub repr_digest: Option<String>,
}

/// Versions of the tools involved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestTools {
    /// The daemon version.
    pub zeus: String,
    /// The engine library version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    /// The extension version, for handoffs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
}

/// One conversion step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConverterStep {
    /// Tool name.
    pub tool: String,
    /// Tool version.
    pub version: String,
    /// SHA-256 of the step's input.
    pub input_sha256: Hex256,
    /// SHA-256 of the step's output.
    pub output_sha256: Hex256,
    /// Digest of the arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub args_digest: Option<Hex256>,
}

/// Where a license claim comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseSource {
    /// Nothing is known. A consumer must not read this as "permissive".
    Unknown,
    /// A header such as `Link: rel="license"`, workflow-extracted metadata, or a caller-provided label.
    Declared,
    /// Content analysis (not in the MVP).
    Detected,
    /// A human supplied it.
    User,
}

/// License information. Zeus never guesses a license.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LicenseInfo {
    /// An SPDX expression, a `LicenseRef-*` id, or the literal `unknown`.
    pub spdx: String,
    /// Where the claim comes from.
    pub source: LicenseSource,
    /// A URL that evidences it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_url: Option<RedactedUrl>,
}

impl LicenseInfo {
    /// The default: nothing known.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            spdx: "unknown".to_owned(),
            source: LicenseSource::Unknown,
            evidence_url: None,
        }
    }
}

/// One file record of the manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestFile {
    /// Always `file`.
    pub record_type: FileTag,
    /// Path relative to the root, `/` separators, no drive letter, no `..`.
    pub path: String,
    /// Size from the verify result.
    pub size_bytes: u64,
    /// SHA-256 of the bytes on disk.
    pub sha256: Hex256,
    /// BLAKE3 of the bytes on disk.
    pub blake3: Hex256,
    /// Detected from magic bytes.
    #[serde(default)]
    pub media_type: Option<String>,
    /// `Content-Type` without parameters.
    #[serde(default)]
    pub declared_media_type: Option<String>,
    /// Source.
    pub source: ManifestSource,
    /// When the last byte was committed (entry into `verifying`).
    pub retrieved_at: Timestamp,
    /// The origin whose session was used, else `null`.
    pub session_origin: Option<Origin>,
    /// Validators.
    #[serde(default)]
    pub http: Option<ManifestHttp>,
    /// Tool versions.
    pub tools: ManifestTools,
    /// Conversion steps; empty for untransformed downloads.
    #[serde(default)]
    pub converter_chain: Vec<ConverterStep>,
    /// License.
    pub license: LicenseInfo,
    /// The workflow run, if any.
    #[serde(default)]
    pub run_id: Option<RunId>,
    /// The job.
    pub job_id: JobId,
    /// Final quarantine flag.
    pub quarantined: bool,
    /// Which OS attributes were written.
    #[serde(default)]
    pub os_metadata: Vec<OsMetadataKind>,
    /// For converted files: the input digests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub derived_from: Vec<Hex256>,
    /// Pointer to the audit record that recorded this file.
    pub audit: AuditHead,
}

/// A line of a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ManifestLine {
    /// The header.
    Header(ManifestHeader),
    /// A file.
    File(Box<ManifestFile>),
}

/// Validates the `RelPath` form of the manifest schema: not empty, no leading `/`, no `..` segment,
/// no backslash or colon, no control characters, at most 4096 bytes.
pub fn validate_rel_path(path: &str) -> VerifyResult<()> {
    let bad = path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.split('/').any(|seg| seg == "..")
        || path
            .chars()
            .any(|c| c == '\\' || c == ':' || c.is_control());
    if bad {
        Err(VerifyError::Invalid("not a valid manifest-relative path"))
    } else {
        Ok(())
    }
}

/// Appends records to `<write_root>/.zeus/manifest.jsonl` (04 section 3.4): one complete line per
/// `write`, never rewriting a line, idempotent by `(job_id, path)`, fsync batched (1 s, 64 records,
/// shutdown), a lost tail regenerated from the outbox at recovery.
#[derive(Debug)]
pub struct ProvenanceWriter {
    root: PathBuf,
}

impl ProvenanceWriter {
    /// Opens the ledger of `root`, writing the header if the file is new.
    pub fn open(root: &Path, header: ManifestHeader) -> VerifyResult<Self> {
        Err(VerifyError::NotImplemented("ProvenanceWriter::open"))
    }

    /// Appends a file record unless a line with the same `job_id` and `path` already exists.
    /// Returns whether a line was written.
    pub fn append(&self, record: &ManifestFile) -> VerifyResult<bool> {
        Err(VerifyError::NotImplemented("ProvenanceWriter::append"))
    }

    /// Flushes pending lines to stable storage.
    pub fn flush(&self) -> VerifyResult<()> {
        Err(VerifyError::NotImplemented("ProvenanceWriter::flush"))
    }
}

/// Output formats of `zeus manifest export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// A filtered copy with a fresh header whose `privacy` block states what was removed.
    Jsonl,
    /// Comma-separated values.
    Csv,
    /// W3C PROV-JSON (04 section 7.1).
    ProvJson,
    /// A Croissant (JSON-LD) rendering (04 section 7.2).
    Croissant,
}

/// Filters of an export.
#[derive(Debug, Clone, Default)]
pub struct ExportFilter {
    /// Only this run.
    pub run_id: Option<RunId>,
    /// Only files under this relative directory.
    pub under: Option<String>,
    /// Only files retrieved at or after this instant.
    pub since: Option<Timestamp>,
    /// Drop `session_origin` from every record.
    pub strip_session_origin: bool,
    /// Drop URL queries entirely (`strict` mode).
    pub strip_url_query: bool,
}

/// Reads `manifest` and writes the filtered, re-rendered ledger to `out` in `format`.
pub fn export_manifest(
    manifest: &Path,
    out: &Path,
    format: ExportFormat,
    filter: &ExportFilter,
) -> VerifyResult<u64> {
    Err(VerifyError::NotImplemented("export_manifest"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rel_paths() {
        for ok in [
            "a.txt",
            "reports/q3.csv",
            "dataset-v3.tar.zst",
            "dir/sub dir/file name.pdf",
        ] {
            assert!(validate_rel_path(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "/abs",
            "../up",
            "a/../b",
            "C:\\x",
            "a\\b",
            "a:b",
            "tab\tname",
            "x/..",
        ] {
            assert!(validate_rel_path(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn license_defaults_to_unknown() {
        let l = LicenseInfo::unknown();
        assert_eq!(
            (l.spdx.as_str(), l.source),
            ("unknown", LicenseSource::Unknown)
        );
    }
}
