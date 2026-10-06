//! Errors of the HTTP layer.

use zeus_types::{ErrorEnvelope, ToEnvelope, codes};

/// What the HTTP layer reports to the engine.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HttpError {
    /// A failure classified by the rules of 01 section 8.3. The envelope never contains a URL with a
    /// query, a header value or a cookie.
    #[error("{0}")]
    Classified(ErrorEnvelope),
    /// The operation was canceled through its `CancellationToken`; not a failure of the resource.
    #[error("canceled")]
    Canceled,
    /// The caller passed something the layer refuses (a non-http(s) URL, a forbidden header).
    #[error("invalid request: {0}")]
    Invalid(&'static str),
    /// The operation exists in the API but has no implementation yet.
    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),
}

impl HttpError {
    /// The classified envelope, when this is a classified failure.
    #[must_use]
    pub fn envelope(&self) -> Option<&ErrorEnvelope> {
        match self {
            Self::Classified(e) => Some(e),
            _ => None,
        }
    }
}

impl ToEnvelope for HttpError {
    fn to_envelope(&self) -> ErrorEnvelope {
        match self {
            Self::Classified(e) => e.clone(),
            Self::Canceled => ErrorEnvelope::from_code(codes::FETCH_ABORTED, "canceled"),
            Self::Invalid(m) => ErrorEnvelope::from_code(
                codes::HTTP_PROTOCOL_ERROR,
                format!("invalid request: {m}"),
            ),
            Self::NotImplemented(_) => {
                ErrorEnvelope::from_code(codes::INTERNAL_BUG, self.to_string())
            }
        }
    }
}

impl From<ErrorEnvelope> for HttpError {
    fn from(e: ErrorEnvelope) -> Self {
        Self::Classified(e)
    }
}

/// Result alias.
pub type HttpResult<T> = Result<T, HttpError>;
