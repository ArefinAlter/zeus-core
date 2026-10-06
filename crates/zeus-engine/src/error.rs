//! Errors of the engine facade.

use zeus_types::{ErrorEnvelope, ToEnvelope, codes};

/// What an engine call can fail with. Every variant maps to an [`ErrorEnvelope`] the daemon, the MCP
/// server and the CLI return unchanged.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EngineError {
    /// The request was malformed or violated a rule (`invalid_request`, `policy_denied`, ...). The
    /// envelope is the answer.
    #[error("{0}")]
    Rejected(ErrorEnvelope),
    /// The job, approval or grant does not exist (`api.not_found`).
    #[error("{what} not found")]
    NotFound {
        /// What was looked up.
        what: &'static str,
    },
    /// The requested transition is not legal from the job's current state (`api.invalid_transition`),
    /// or the job is in a non-interruptible state (`api.not_interruptible`).
    #[error("{0}")]
    Conflict(ErrorEnvelope),
    /// The same idempotency key was used with different parameters (`api.idempotency_conflict`).
    #[error("idempotency key reused with different parameters")]
    IdempotencyConflict,
    /// The engine is shutting down (`engine.shutdown`).
    #[error("the engine is shutting down")]
    ShuttingDown,
    /// The journal failed.
    #[error(transparent)]
    Journal(#[from] zeus_journal::JournalError),
    /// The file system failed.
    #[error(transparent)]
    Fs(#[from] zeus_fs::FsError),
    /// The audit log failed; a write-ahead action must not proceed (`audit.unavailable`).
    #[error(transparent)]
    Verify(#[from] zeus_verify::VerifyError),
    /// The HTTP layer failed.
    #[error(transparent)]
    Http(#[from] zeus_http::HttpError),
    /// The session layer failed.
    #[error(transparent)]
    Session(#[from] zeus_session::SessionError),
    /// The operation exists in the API but has no implementation yet.
    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),
}

/// Result alias.
pub type EngineResult<T> = Result<T, EngineError>;

impl ToEnvelope for EngineError {
    fn to_envelope(&self) -> ErrorEnvelope {
        match self {
            Self::Rejected(e) | Self::Conflict(e) => e.clone(),
            Self::NotFound { .. } => {
                ErrorEnvelope::from_code(codes::API_NOT_FOUND, self.to_string())
            }
            Self::IdempotencyConflict => {
                ErrorEnvelope::from_code(codes::API_IDEMPOTENCY_CONFLICT, self.to_string())
            }
            Self::ShuttingDown => {
                ErrorEnvelope::from_code(codes::ENGINE_SHUTDOWN, self.to_string())
            }
            Self::Journal(e) => e.to_envelope(),
            Self::Fs(e) => e.to_envelope(),
            Self::Verify(e) => e.to_envelope(),
            Self::Http(e) => e.to_envelope(),
            Self::Session(e) => e.to_envelope(),
            Self::NotImplemented(_) => {
                ErrorEnvelope::from_code(codes::INTERNAL_BUG, self.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variants_map_to_registered_codes() {
        assert_eq!(
            EngineError::NotFound { what: "job" }
                .to_envelope()
                .code
                .as_str(),
            "api.not_found"
        );
        assert_eq!(
            EngineError::IdempotencyConflict.to_envelope().code.as_str(),
            "api.idempotency_conflict"
        );
        assert_eq!(
            EngineError::ShuttingDown.to_envelope().code.as_str(),
            "engine.shutdown"
        );
        let env = EngineError::from(zeus_journal::JournalError::AlreadyOpen).to_envelope();
        assert_eq!(env.code.as_str(), "journal.already_open");
    }
}
