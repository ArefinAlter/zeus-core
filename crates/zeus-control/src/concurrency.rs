//! Adaptive concurrency: additive increase, multiplicative decrease (research.md section 8.4).
//!
//! Every interval `T` the controller sees the aggregate throughput. While throughput keeps rising it
//! adds connections (+1); on a throttle signal (429, 503, connection reset, HTTP/2
//! `ENHANCE_YOUR_CALM`) or a throughput drop it halves them. The result is bounded by the job's
//! `max_connections` and the per-host budget, and is never below one.
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: bodies are filled in by the zeus-control implementation task"
)]

use std::time::Duration;

use crate::error::{ControlError, Result};

/// Controller parameters.
#[derive(Debug, Clone, PartialEq)]
pub struct AimdConfig {
    /// Starting number of connections.
    pub initial: u32,
    /// Lower bound, at least 1.
    pub min: u32,
    /// Upper bound (the job's `max_connections`, 1 to 32).
    pub max: u32,
    /// Connections added per interval while throughput improves.
    pub additive_increase: u32,
    /// Factor applied on a decrease signal, in `(0, 1)`; 0.5 halves.
    pub multiplicative_decrease: f64,
    /// Control interval `T`.
    pub interval: Duration,
    /// Relative throughput gain below which adding connections stops (the marginal-gain threshold).
    pub min_marginal_gain: f64,
    /// Relative throughput drop between intervals that counts as a decrease signal.
    pub throughput_drop_ratio: f64,
}

impl Default for AimdConfig {
    fn default() -> Self {
        Self {
            initial: 2,
            min: 1,
            max: 8,
            additive_increase: 1,
            multiplicative_decrease: 0.5,
            interval: Duration::from_secs(2),
            min_marginal_gain: 0.05,
            throughput_drop_ratio: 0.3,
        }
    }
}

/// What the engine observed during one interval.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Signal {
    /// A normal interval with the aggregate throughput (bytes per second) and, if known, the mean RTT.
    Interval {
        /// Aggregate throughput of the job over the interval.
        throughput_bps: u64,
        /// Mean round-trip time, for the gradient variant.
        rtt: Option<Duration>,
    },
    /// The server throttled: 429, 503, `ENHANCE_YOUR_CALM`, or a burst of resets.
    Throttled,
}

/// The controller's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// Connections to use from now on.
    pub target: u32,
    /// Why the target changed (or `Hold`).
    pub reason: Reason,
}

/// Why the target changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Increased because throughput improved.
    Increase,
    /// Halved because of a throttle signal.
    Throttled,
    /// Halved because throughput dropped.
    ThroughputDrop,
    /// Unchanged.
    Hold,
}

/// AIMD concurrency controller.
#[derive(Debug, Clone)]
pub struct AimdController {
    config: AimdConfig,
    current: u32,
}

impl AimdController {
    /// Validates the configuration (`1 <= min <= initial <= max`, decrease factor in `(0, 1)`).
    pub fn new(config: AimdConfig) -> Result<Self> {
        if config.min == 0
            || config.min > config.max
            || config.initial < config.min
            || config.initial > config.max
        {
            return Err(ControlError::invalid(
                "config",
                "need 1 <= min <= initial <= max",
            ));
        }
        if !(config.multiplicative_decrease > 0.0 && config.multiplicative_decrease < 1.0) {
            return Err(ControlError::invalid(
                "multiplicative_decrease",
                "must be in (0, 1)",
            ));
        }
        let current = config.initial;
        Ok(Self { config, current })
    }

    /// The current target.
    #[must_use]
    pub const fn current(&self) -> u32 {
        self.current
    }

    /// Feeds one interval's observation and returns the new target.
    pub fn observe(&mut self, signal: Signal) -> Result<Decision> {
        Err(ControlError::NotImplemented("AimdController::observe"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_validation() {
        assert!(AimdController::new(AimdConfig::default()).is_ok());
        assert!(
            AimdController::new(AimdConfig {
                min: 0,
                ..AimdConfig::default()
            })
            .is_err()
        );
        assert!(
            AimdController::new(AimdConfig {
                initial: 9,
                ..AimdConfig::default()
            })
            .is_err()
        );
        assert!(
            AimdController::new(AimdConfig {
                multiplicative_decrease: 1.0,
                ..AimdConfig::default()
            })
            .is_err()
        );
        assert_eq!(
            AimdController::new(AimdConfig::default())
                .unwrap()
                .current(),
            2
        );
    }
}
