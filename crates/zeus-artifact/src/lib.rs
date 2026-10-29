//! Shared content-addressed artifact store (specification 13).
#![forbid(unsafe_code)]
pub mod model;
pub use model::*;
mod bundle;
pub use bundle::*;
mod store;
pub use store::*;
/// Errors are intentionally free of source paths and record contents.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    /// Missing record.
    #[error("artifact.not_found")]
    NotFound,
    /// No stored bytes.
    #[error("artifact.object_absent")]
    ObjectAbsent,
    /// Stored bytes cannot be trusted.
    #[error("artifact.object_damaged")]
    ObjectDamaged,
    /// Identity disagreement.
    #[error("artifact.digest_mismatch")]
    DigestMismatch,
    /// Capacity limit.
    #[error("artifact.quota_exceeded")]
    QuotaExceeded,
    /// Another owner holds the store.
    #[error("artifact.store_locked")]
    StoreLocked,
    /// Newer format.
    #[error("artifact.version_unsupported")]
    VersionUnsupported,
    /// Invalid index or internal path.
    #[error("artifact.store_corrupt")]
    StoreCorrupt,
    /// Unsafe relationship with write roots.
    #[error("artifact.store_location_unsuitable")]
    LocationUnsuitable,
    /// Invalid portable record.
    #[error("artifact.record_invalid: {0}")]
    RecordInvalid(&'static str),
    /// Missing or inconsistent parent.
    #[error("artifact.lineage_invalid")]
    LineageInvalid,
    /// The same source record changed identity.
    #[error("artifact.import_conflict")]
    ImportConflict,
    /// No materialization mode worked.
    #[error("artifact.materialize_unsupported")]
    MaterializeUnsupported,
    /// Product permission required.
    #[error("policy.quarantine_blocked")]
    QuarantineBlocked,
    /// Filesystem error.
    #[error(transparent)]
    Fs(#[from] zeus_fs::FsError),
    /// Filesystem I/O.
    #[error("artifact filesystem I/O failed")]
    Io(#[from] std::io::Error),
    /// Invalid serialized data.
    #[error("artifact JSON encoding failed")]
    Json(#[from] serde_json::Error),
    /// Digest or audit verification.
    #[error(transparent)]
    Verify(#[from] zeus_verify::VerifyError),
    /// Index failure.
    #[error("artifact index write failed")]
    Index,
}
/// Artifact operations result.
pub type Result<T> = std::result::Result<T, ArtifactError>;

impl zeus_types::ToEnvelope for ArtifactError {
    fn to_envelope(&self) -> zeus_types::ErrorEnvelope {
        use zeus_types::codes;
        let code = match self {
            Self::NotFound => codes::ARTIFACT_NOT_FOUND,
            Self::ObjectAbsent => codes::ARTIFACT_OBJECT_ABSENT,
            Self::ObjectDamaged => codes::ARTIFACT_OBJECT_DAMAGED,
            Self::DigestMismatch => codes::ARTIFACT_DIGEST_MISMATCH,
            Self::QuotaExceeded => codes::ARTIFACT_QUOTA_EXCEEDED,
            Self::StoreLocked => codes::ARTIFACT_STORE_LOCKED,
            Self::VersionUnsupported => codes::ARTIFACT_VERSION_UNSUPPORTED,
            Self::StoreCorrupt | Self::Index | Self::Json(_) => codes::ARTIFACT_STORE_CORRUPT,
            Self::LocationUnsuitable => codes::ARTIFACT_STORE_LOCATION_UNSUITABLE,
            Self::RecordInvalid(_) => codes::ARTIFACT_RECORD_INVALID,
            Self::LineageInvalid => codes::ARTIFACT_LINEAGE_INVALID,
            Self::ImportConflict => codes::ARTIFACT_IMPORT_CONFLICT,
            Self::MaterializeUnsupported => codes::ARTIFACT_MATERIALIZE_UNSUPPORTED,
            Self::QuarantineBlocked => codes::POLICY_QUARANTINE_BLOCKED,
            Self::Io(_) => codes::FS_IO_ERROR,
            Self::Fs(error) => return error.to_envelope(),
            Self::Verify(error) => return error.to_envelope(),
        };
        zeus_types::ErrorEnvelope::from_code(code, "artifact operation could not be completed")
    }
}
