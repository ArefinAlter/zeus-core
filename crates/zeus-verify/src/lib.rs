//! Integrity and provenance for Zeus (04, and 03 section 8).
//!
//! * [`hash`]: incremental SHA-256 + BLAKE3 hashing and file verification.
//! * [`canonical`]: RFC 8785 canonical JSON and the request hash.
//! * [`content`]: magic-byte sniffing and the claimed-versus-detected type check.
//! * [`quarantine`]: the quarantine rules of 01 section 11.3.
//! * [`archive`]: archive-bomb limits for inspection.
//! * [`audit`]: the hash-chained audit log (typed records, pure chain verification against the
//!   published test vectors, an in-memory writer, the file-backed log API).
//! * [`provenance`]: the manifest v0 types and writer.
//!
//! Secrets never enter this crate: records carry redacted URLs, handles and counts only.

#![forbid(unsafe_code)]

pub mod archive;
pub mod audit;
pub mod canonical;
pub mod content;
pub mod error;
pub mod hash;
pub mod provenance;
pub mod quarantine;

pub use audit::{
    AuditEntry, AuditLog, AuditOutcome, AuditRecord, AuditSink, AuditSubject, MemoryAuditLog,
};
pub use error::{AuditFailure, AuditFailureKind, VerifyError, VerifyResult};
pub use hash::{Digests, DualHasher, hash_bytes};
