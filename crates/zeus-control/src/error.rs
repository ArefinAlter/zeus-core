//! Errors of the control algorithms.

use zeus_types::{ErrorEnvelope, ToEnvelope, codes};

/// Failure of a control algorithm.
///
/// The algorithms are pure, so the only runtime failures are invalid parameters. Skeleton items that
/// another agent has not implemented yet return [`ControlError::NotImplemented`]; the integration
/// phase greps for it (`git grep NotImplemented`) and treats any hit in an MVP path as a defect.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ControlError {
    /// A parameter was out of range, not finite, or inconsistent with another.
    #[error("invalid parameter `{name}`: {reason}")]
    InvalidParameter {
        /// Parameter name.
        name: &'static str,
        /// Why it was rejected.
        reason: &'static str,
    },
    /// The operation exists in the API but has no implementation yet.
    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),
}

impl ControlError {
    /// Shorthand for an [`InvalidParameter`](Self::InvalidParameter) error.
    #[must_use]
    pub const fn invalid(name: &'static str, reason: &'static str) -> Self {
        Self::InvalidParameter { name, reason }
    }
}

impl ToEnvelope for ControlError {
    fn to_envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope::from_code(codes::INTERNAL_BUG, self.to_string())
    }
}

/// Convenience alias.
pub type Result<T, E = ControlError> = std::result::Result<T, E>;

/// Rejects NaN and infinities.
pub(crate) fn finite(name: &'static str, value: f64) -> Result<f64> {
    if value.is_finite() {
        Ok(value)
    } else {
        Err(ControlError::invalid(name, "must be finite"))
    }
}
