//! Content sniffing and the MIME check (01 section 11.3).
//!
//! A file's *claimed* type (`Content-Type`, extension) is compared with its *detected* type (magic
//! bytes) through a pluggable [`ContentDetector`]; `infer` is the default and a learned detector can
//! be dropped in later. The verdict feeds the quarantine decision and `job.verified.mime_match`.
#![expect(
    unused_variables,
    reason = "skeleton: check_content is filled in by the zeus-verify implementation task"
)]

use crate::error::{VerifyError, VerifyResult};

/// A type recognised from the leading bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedType {
    /// Media type, for example `application/zip`.
    pub mime: String,
    /// Canonical extension without the dot, for example `zip`.
    pub extension: String,
}

/// Recognises a file type from its first bytes.
pub trait ContentDetector: Send + Sync {
    /// The detected type, or `None` when unknown. `head` is at most the first 8 KiB.
    fn detect(&self, head: &[u8]) -> Option<DetectedType>;
}

/// The default detector, backed by the `infer` crate's magic-byte tables.
#[derive(Debug, Clone, Copy, Default)]
pub struct InferDetector;

impl ContentDetector for InferDetector {
    fn detect(&self, head: &[u8]) -> Option<DetectedType> {
        infer::get(head).map(|t| DetectedType {
            mime: t.mime_type().to_owned(),
            extension: t.extension().to_owned(),
        })
    }
}

/// The outcome of comparing claimed and detected types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentVerdict {
    /// Detected and claimed types agree (or the claim is a generic type such as
    /// `application/octet-stream` and nothing contradicts it).
    Ok,
    /// Detected type contradicts the claim in a harmless way (for example `.txt` that is really CSV).
    Mismatch,
    /// Nothing could be detected; no evidence either way.
    Unknown,
    /// The detected type is dangerous (executable, script, installer) or crosses a safety boundary
    /// relative to the claim (a document or image name on executable content).
    DangerousType,
}

/// Inputs of [`check_content`].
#[derive(Debug, Clone, Copy)]
pub struct ContentClaim<'a> {
    /// The file name as it will be stored (after sanitising).
    pub file_name: &'a str,
    /// `Content-Type` of the response without parameters, if any.
    pub declared_mime: Option<&'a str>,
}

/// Compares the claim with what `detector` sees in `head` (the first bytes of the file).
pub fn check_content(
    detector: &dyn ContentDetector,
    head: &[u8],
    claim: &ContentClaim<'_>,
) -> VerifyResult<(ContentVerdict, Option<DetectedType>)> {
    Err(VerifyError::NotImplemented("check_content"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_recognises_common_magic_bytes() {
        let d = InferDetector;
        let png = d
            .detect(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0])
            .unwrap();
        assert_eq!(
            (png.mime.as_str(), png.extension.as_str()),
            ("image/png", "png")
        );
        let pdf = d.detect(b"%PDF-1.7\n").unwrap();
        assert_eq!(pdf.mime, "application/pdf");
        let zip = d.detect(&[b'P', b'K', 3, 4, 0, 0, 0, 0]).unwrap();
        assert_eq!(zip.mime, "application/zip");
        assert!(d.detect(b"plain text, no magic").is_none());
        assert!(d.detect(b"").is_none());
    }
}
