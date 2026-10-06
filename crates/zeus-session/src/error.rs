//! Errors of the session crate: codec, protocol, and the provider traits.

use std::io;

use zeus_types::{ErrorEnvelope, ToEnvelope, codes};

/// A violation of the framing rules of 02 section 3.3 and 13.2.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FrameError {
    /// The length prefix is 0: the stream cannot be skipped safely, the connection must close
    /// (`nm.malformed_frame`).
    #[error("zero-length frame")]
    ZeroLength,
    /// The announced or actual payload exceeds the limit of its direction (`nm.frame_too_large`). The
    /// check happens on the prefix, before any allocation.
    #[error("frame of {announced} bytes exceeds the limit of {limit}")]
    TooLarge {
        /// The announced payload length.
        announced: u64,
        /// The limit for the direction.
        limit: usize,
    },
    /// The stream ended inside a prefix or payload: treat as a disconnect.
    #[error("stream ended inside a frame")]
    Truncated,
    /// The payload is not valid UTF-8 JSON (`nm.invalid_json`); framing is intact so reading may continue.
    #[error("payload is not valid UTF-8 JSON")]
    InvalidJson,
    /// The JSON nests deeper than 32 levels (`nm.schema_violation`); framing is intact so reading may
    /// continue.
    #[error("JSON nesting deeper than 32 levels")]
    TooDeep,
    /// An operating-system error on the stream.
    #[error("stream error: {0}")]
    Io(#[from] io::Error),
}

impl FrameError {
    /// True when the stream is still correctly framed after this error, so the reader may continue
    /// (only invalid JSON; every other error closes the connection).
    #[must_use]
    pub const fn is_recoverable(&self) -> bool {
        matches!(self, Self::InvalidJson | Self::TooDeep)
    }

    /// The registered code for the error.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ZeroLength | Self::Truncated => codes::NM_MALFORMED_FRAME,
            Self::TooLarge { .. } => codes::NM_FRAME_TOO_LARGE,
            Self::InvalidJson => codes::NM_INVALID_JSON,
            Self::TooDeep => codes::NM_SCHEMA_VIOLATION,
            Self::Io(_) => codes::NM_MALFORMED_FRAME,
        }
    }
}

/// Why a JSON object could not become a typed message (02 section 6.4).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DecodeError {
    /// The `type` is not in the catalogue (`nm.unknown_type` for a request, ignorable for a notification).
    #[error("unknown message type")]
    UnknownType {
        /// The `type` string as received (not a secret).
        type_name: String,
        /// The request id, when readable, so the error can carry `re`.
        id: Option<String>,
    },
    /// Valid JSON that violates the schema (`nm.schema_violation`).
    #[error("schema violation: {message}")]
    Schema {
        /// What was wrong, without values.
        message: String,
        /// The request id, when readable.
        id: Option<String>,
    },
}

impl DecodeError {
    /// The request id to answer with `re`, when it could be read.
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Self::UnknownType { id, .. } | Self::Schema { id, .. } => id.as_deref(),
        }
    }

    /// The envelope to send back.
    #[must_use]
    pub fn to_envelope(&self) -> ErrorEnvelope {
        match self {
            Self::UnknownType { type_name, .. } => ErrorEnvelope::from_code(
                codes::NM_UNKNOWN_TYPE,
                format!("unknown message type `{}`", truncate(type_name, 64)),
            ),
            Self::Schema { message, .. } => {
                ErrorEnvelope::from_code(codes::NM_SCHEMA_VIOLATION, message.clone())
            }
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Errors of the provider traits and the correlator.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionError {
    /// The extension answered with an error: `consent_required`, `denied`, `unavailable`,
    /// `cannot_refresh`, or a `fetch.error`. The envelope is the extension's, already redacted.
    #[error("extension answered: {0}")]
    Remote(ErrorEnvelope),
    /// No extension connection can serve the request (`session.extension_unavailable`).
    #[error("no extension is connected")]
    ExtensionUnavailable,
    /// No answer within the deadline (`nm.timeout`).
    #[error("no answer within the deadline")]
    Timeout,
    /// The connection closed while the request was outstanding.
    #[error("connection lost")]
    ConnectionLost,
    /// A request id is still outstanding (`nm.duplicate_id`).
    #[error("duplicate request id")]
    DuplicateId,
    /// The peer broke the protocol (offset gap, chunk after end, credit overrun).
    #[error("protocol violation: {0}")]
    Protocol(&'static str),
    /// A frame-level error.
    #[error(transparent)]
    Frame(#[from] FrameError),
    /// The operation exists in the API but has no implementation yet.
    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),
}

/// Result alias.
pub type SessionResult<T> = Result<T, SessionError>;

impl ToEnvelope for SessionError {
    fn to_envelope(&self) -> ErrorEnvelope {
        match self {
            Self::Remote(env) => env.clone(),
            Self::ExtensionUnavailable => {
                ErrorEnvelope::from_code(codes::SESSION_EXTENSION_UNAVAILABLE, self.to_string())
            }
            Self::Timeout => ErrorEnvelope::from_code(codes::NM_TIMEOUT, self.to_string()),
            Self::ConnectionLost => {
                ErrorEnvelope::from_code(codes::NM_SHUTTING_DOWN, self.to_string())
            }
            Self::DuplicateId => ErrorEnvelope::from_code(codes::NM_DUPLICATE_ID, self.to_string()),
            Self::Protocol(_) => {
                ErrorEnvelope::from_code(codes::NM_STREAM_PROTOCOL_VIOLATION, self.to_string())
            }
            Self::Frame(f) => ErrorEnvelope::from_code(f.code(), f.to_string()),
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
    fn only_invalid_json_is_recoverable() {
        assert!(FrameError::InvalidJson.is_recoverable());
        assert!(!FrameError::ZeroLength.is_recoverable());
        assert!(!FrameError::Truncated.is_recoverable());
        assert!(
            !FrameError::TooLarge {
                announced: 9,
                limit: 1
            }
            .is_recoverable()
        );
    }

    #[test]
    fn decode_errors_map_to_registered_codes_and_keep_the_request_id() {
        let e = DecodeError::UnknownType {
            type_name: "future.thing".into(),
            id: Some("e9".into()),
        };
        assert_eq!(e.request_id(), Some("e9"));
        assert_eq!(e.to_envelope().code.as_str(), "nm.unknown_type");
        let e = DecodeError::Schema {
            message: "missing field".into(),
            id: None,
        };
        assert_eq!(e.to_envelope().code.as_str(), "nm.schema_violation");
    }

    #[test]
    fn session_errors_map_to_registered_codes() {
        assert_eq!(
            SessionError::Timeout.to_envelope().code.as_str(),
            "nm.timeout"
        );
        assert_eq!(
            SessionError::ExtensionUnavailable
                .to_envelope()
                .code
                .as_str(),
            "session.extension_unavailable"
        );
        assert_eq!(
            SessionError::Protocol("x").to_envelope().code.as_str(),
            "nm.stream_protocol_violation"
        );
    }
}
