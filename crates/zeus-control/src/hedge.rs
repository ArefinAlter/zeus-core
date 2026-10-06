//! Tail-latency hedging with a streaming quantile (research.md section 8.7).
//!
//! A request that has taken longer than the observed p-th percentile of its peers is duplicated on
//! another connection ("hedged"); the first answer wins and the other is cancelled. Both copies are
//! fetched under the same bound validators (03 section 3.4), so overlapping commits are safe.
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: bodies are filled in by the zeus-control implementation task"
)]

use std::time::Duration;

use crate::error::{ControlError, Result};

/// The P-squared algorithm (Jain and Chlamtac, 1985): a constant-memory streaming estimate of one quantile.
#[derive(Debug, Clone)]
pub struct P2Quantile {
    p: f64,
    count: u64,
}

impl P2Quantile {
    /// Estimates the `p`-quantile, `0 < p < 1`.
    pub fn new(p: f64) -> Result<Self> {
        if !(p > 0.0 && p < 1.0) {
            return Err(ControlError::invalid("p", "must be in (0, 1)"));
        }
        Ok(Self { p, count: 0 })
    }

    /// Number of observations folded in.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// Folds in one observation.
    pub fn observe(&mut self, value: f64) -> Result<()> {
        Err(ControlError::NotImplemented("P2Quantile::observe"))
    }

    /// The current estimate, or `None` before enough observations (five) exist.
    #[must_use]
    pub fn estimate(&self) -> Option<f64> {
        None
    }
}

/// Decides when to hedge: when a request's elapsed time exceeds `factor` times the p-th quantile of
/// completed requests, once at least `min_samples` have completed.
#[derive(Debug, Clone)]
pub struct HedgeTrigger {
    quantile: P2Quantile,
    factor: f64,
    min_samples: u64,
}

impl HedgeTrigger {
    /// A trigger on the `p`-quantile (for example 0.95) with a safety `factor` of at least 1.
    pub fn new(p: f64, factor: f64, min_samples: u64) -> Result<Self> {
        if !(factor >= 1.0 && factor.is_finite()) {
            return Err(ControlError::invalid(
                "factor",
                "must be finite and at least 1",
            ));
        }
        Ok(Self {
            quantile: P2Quantile::new(p)?,
            factor,
            min_samples,
        })
    }

    /// Records the duration of a completed request.
    pub fn record_completion(&mut self, took: Duration) -> Result<()> {
        self.quantile.observe(took.as_secs_f64())
    }

    /// True when a request that has been running for `elapsed` should be hedged.
    pub fn should_hedge(&self, elapsed: Duration) -> Result<bool> {
        Err(ControlError::NotImplemented("HedgeTrigger::should_hedge"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_validation() {
        assert!(P2Quantile::new(0.0).is_err());
        assert!(P2Quantile::new(1.0).is_err());
        assert!(P2Quantile::new(0.95).is_ok());
        assert!(HedgeTrigger::new(0.95, 0.5, 20).is_err());
        assert!(HedgeTrigger::new(0.95, 1.5, 20).is_ok());
    }
}
