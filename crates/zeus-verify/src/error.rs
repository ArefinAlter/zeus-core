//! Errors of the verification crate.

use std::io;

use serde::{Deserialize, Serialize};
use zeus_types::{ErrorEnvelope, ToEnvelope, codes};

/// What kind of break a hash-chain verification found (04 section 4.5, "Output").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditFailureKind {
    /// A line is empty, not JSON, not an object, or fails the record schema (a torn write or damage).
    TornOrMalformed,
    /// `seq` skips or repeats a value.
    SeqGap,
    /// `prev_hash` does not equal the previous record's hash.
    PrevMismatch,
    /// The recomputed hash differs from `hash`.
    HashMismatch,
    /// The first record is not `audit.chain_started` with a valid genesis `prev_hash`.
    BadGenesis,
    /// A non-final file does not end with `audit.rotated`, or the next file does not continue the chain.
    Rotation,
    /// Records were removed from the end: the journal head is ahead of the log.
    TailTruncated,
    /// A trusted anchor does not match the log.
    AnchorMismatch,
    /// A file named by the rotation sequence is missing.
    MissingFile,
}

/// Where and how a chain verification failed. Carried in `details` of `audit.chain_broken`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("audit chain broken ({kind:?}) at seq {seq:?}")]
pub struct AuditFailure {
    /// The kind of break.
    pub kind: AuditFailureKind,
    /// Sequence number of the offending record, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// File name (not path) of the offending record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// 1-based line number within the file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
}

impl AuditFailure {
    /// A failure of `kind` at record `seq`.
    #[must_use]
    pub fn at(kind: AuditFailureKind, seq: u64) -> Self {
        Self {
            kind,
            seq: Some(seq),
            file: None,
            line: None,
        }
    }

    /// A failure of `kind` with no position.
    #[must_use]
    pub fn of(kind: AuditFailureKind) -> Self {
        Self {
            kind,
            seq: None,
            file: None,
            line: None,
        }
    }
}

/// Errors of this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// A file operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    /// JSON could not be parsed or produced.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    /// A document violates a rule of 00 section 7 (floats, out-of-range integers, duplicate keys).
    #[error("not canonicalisable: {0}")]
    NotCanonical(&'static str),
    /// The audit chain is broken.
    #[error(transparent)]
    Audit(#[from] AuditFailure),
    /// The audit log cannot be written; write-ahead actions must fail closed (04 section 4.6 item 8).
    #[error("audit log unavailable: {0}")]
    AuditUnavailable(String),
    /// A value violated a documented rule.
    #[error("{0}")]
    Invalid(&'static str),
    /// The operation exists in the API but has no implementation yet.
    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),
}

/// Result alias.
pub type VerifyResult<T> = Result<T, VerifyError>;

impl ToEnvelope for VerifyError {
    fn to_envelope(&self) -> ErrorEnvelope {
        match self {
            Self::Audit(failure) => {
                let mut env =
                    ErrorEnvelope::from_code(codes::AUDIT_CHAIN_BROKEN, failure.to_string());
                if let Ok(serde_json::Value::Object(details)) = serde_json::to_value(failure) {
                    env = env.with_details(details);
                }
                env
            }
            Self::AuditUnavailable(_) => {
                ErrorEnvelope::from_code(codes::AUDIT_UNAVAILABLE, self.to_string())
            }
            Self::Io(_) => ErrorEnvelope::from_code(
                codes::FS_IO_ERROR,
                "I/O error while verifying or writing records",
            ),
            Self::Json(_) | Self::NotCanonical(_) | Self::Invalid(_) | Self::NotImplemented(_) => {
                ErrorEnvelope::from_code(codes::INTERNAL_BUG, self.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_break_maps_to_the_registered_code_with_details() {
        let err = VerifyError::from(AuditFailure::at(AuditFailureKind::HashMismatch, 7));
        let env = err.to_envelope();
        assert_eq!(env.code.as_str(), "audit.chain_broken");
        let details = env.details.unwrap();
        assert_eq!(details["kind"], "hash_mismatch");
        assert_eq!(details["seq"], 7);
    }
}
