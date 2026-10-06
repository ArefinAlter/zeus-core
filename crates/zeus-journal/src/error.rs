//! Journal errors (03 section 15).

use zeus_types::{ErrorEnvelope, ToEnvelope, TypesError, codes};

use crate::fault::CrashPoint;

/// Errors of the journal.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum JournalError {
    /// The store cannot be opened or repaired (`journal.corrupt`, 03 section 10 step 1).
    #[error("journal is corrupt: {0}")]
    Corrupt(String),
    /// `meta.schema_version` is newer than this build understands (`journal.version_unsupported`).
    #[error("journal schema version {found} is newer than the supported {supported}")]
    VersionUnsupported {
        /// Version found in the store.
        found: u32,
        /// Highest version this build reads.
        supported: u32,
    },
    /// Another process holds the store (`journal.already_open`, invariant I6).
    #[error("journal is already open in another process")]
    AlreadyOpen,
    /// A commit returned an error whose outcome is unknown (`journal.commit_ambiguous`): the changes
    /// are atomic but may already be durable. The committer re-reads the journal and reconciles.
    #[error("commit outcome is ambiguous: {0}")]
    CommitAmbiguous(String),
    /// The store reported `TransactionPoisoned` (`journal.poisoned`): the daemon must restart.
    #[error("journal transaction is poisoned")]
    Poisoned,
    /// A row that must exist does not.
    #[error("{what} not found")]
    NotFound {
        /// What was looked up.
        what: &'static str,
    },
    /// A write violated a journal invariant (a duplicate reservation, an illegal range, a transition
    /// not in the table).
    #[error("journal invariant violated: {0}")]
    Invariant(&'static str),
    /// A backend error that fits no other variant. Never contains row contents.
    #[error("storage error: {0}")]
    Storage(String),
    /// A stored value did not decode.
    #[error("cannot decode stored value: {0}")]
    Decode(String),
    /// A fault injector asked the protocol to stop here (tests only).
    #[error("injected crash at {0:?}")]
    InjectedCrash(CrashPoint),
    /// A wire type rejected a value.
    #[error(transparent)]
    Types(#[from] TypesError),
    /// The operation exists in the API but has no implementation yet.
    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),
}

/// Result alias.
pub type JournalResult<T> = Result<T, JournalError>;

impl ToEnvelope for JournalError {
    fn to_envelope(&self) -> ErrorEnvelope {
        let code = match self {
            Self::Corrupt(_) | Self::Decode(_) => codes::JOURNAL_CORRUPT,
            Self::VersionUnsupported { .. } => codes::JOURNAL_VERSION_UNSUPPORTED,
            Self::AlreadyOpen => codes::JOURNAL_ALREADY_OPEN,
            Self::CommitAmbiguous(_) => codes::JOURNAL_COMMIT_AMBIGUOUS,
            Self::Poisoned => codes::JOURNAL_POISONED,
            Self::NotFound { .. } => codes::API_NOT_FOUND,
            Self::Invariant(_)
            | Self::Types(_)
            | Self::InjectedCrash(_)
            | Self::NotImplemented(_) => codes::INTERNAL_BUG,
            Self::Storage(_) => codes::FS_IO_ERROR,
        };
        // Row contents (which may hold URLs with secrets) never appear in the envelope.
        ErrorEnvelope::from_code(code, format!("journal: {}", self.kind_name()))
    }
}

impl JournalError {
    fn kind_name(&self) -> &'static str {
        match self {
            Self::Corrupt(_) => "corrupt",
            Self::VersionUnsupported { .. } => "version unsupported",
            Self::AlreadyOpen => "already open",
            Self::CommitAmbiguous(_) => "commit outcome ambiguous",
            Self::Poisoned => "transaction poisoned",
            Self::NotFound { .. } => "not found",
            Self::Invariant(_) => "invariant violated",
            Self::Storage(_) => "storage error",
            Self::Decode(_) => "decode error",
            Self::InjectedCrash(_) => "injected crash",
            Self::Types(_) => "invalid value",
            Self::NotImplemented(_) => "not implemented",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_follow_03_section_15() {
        let code = |e: JournalError| e.to_envelope().code.to_string();
        assert_eq!(code(JournalError::Corrupt("x".into())), "journal.corrupt");
        assert_eq!(
            code(JournalError::VersionUnsupported {
                found: 2,
                supported: 1
            }),
            "journal.version_unsupported"
        );
        assert_eq!(code(JournalError::AlreadyOpen), "journal.already_open");
        assert_eq!(
            code(JournalError::CommitAmbiguous("x".into())),
            "journal.commit_ambiguous"
        );
        assert_eq!(code(JournalError::Poisoned), "journal.poisoned");
    }

    #[test]
    fn envelopes_hide_details() {
        let env = JournalError::Storage("row contained https://x/?token=ZEUS-CANARY".into())
            .to_envelope();
        assert!(!env.message.contains("ZEUS-CANARY"));
    }
}
