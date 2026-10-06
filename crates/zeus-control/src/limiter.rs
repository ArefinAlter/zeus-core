//! Rate limiters driven by an explicit monotonic time argument, so they are deterministic and need no
//! clock of their own: pass `Clock::monotonic()` (00 section 10 rate limits, per-host politeness).
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: bodies are filled in by the zeus-control implementation task"
)]

use std::time::Duration;

use crate::error::{ControlError, Result};

/// The verdict of a limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admit {
    /// Proceed now.
    Allowed,
    /// Do not proceed; try again after this long (`details.retry_after_ms` of a `rate_limited` error).
    RetryAfter(Duration),
}

/// A token bucket: `rate_per_s` tokens per second up to `burst`. The default burst of the
/// specification is twice the sustained rate.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    rate_per_s: f64,
    burst: f64,
    tokens: f64,
    last: Duration,
}

impl TokenBucket {
    /// A full bucket at monotonic time `now`.
    pub fn new(rate_per_s: f64, burst: f64, now: Duration) -> Result<Self> {
        if !(rate_per_s.is_finite() && rate_per_s > 0.0 && burst.is_finite() && burst >= 1.0) {
            return Err(ControlError::invalid(
                "rate/burst",
                "rate must be positive and burst at least 1",
            ));
        }
        Ok(Self {
            rate_per_s,
            burst,
            tokens: burst,
            last: now,
        })
    }

    /// Takes `cost` tokens if available at `now`, otherwise reports how long to wait.
    pub fn try_acquire(&mut self, now: Duration, cost: f64) -> Result<Admit> {
        Err(ControlError::NotImplemented("TokenBucket::try_acquire"))
    }
}

/// The generic cell rate algorithm: one theoretical arrival time, constant memory, exact spacing.
#[derive(Debug, Clone)]
pub struct Gcra {
    emission_interval: Duration,
    tolerance: Duration,
    theoretical_arrival: Duration,
}

impl Gcra {
    /// A limiter admitting one cell per `emission_interval` with up to `burst` cells of slack.
    pub fn new(emission_interval: Duration, burst: u32) -> Result<Self> {
        if emission_interval.is_zero() || burst == 0 {
            return Err(ControlError::invalid(
                "emission_interval/burst",
                "must be positive",
            ));
        }
        Ok(Self {
            emission_interval,
            tolerance: emission_interval * burst.saturating_sub(1),
            theoretical_arrival: Duration::ZERO,
        })
    }

    /// Admits or delays one cell arriving at `now`.
    pub fn check(&mut self, now: Duration) -> Result<Admit> {
        Err(ControlError::NotImplemented("Gcra::check"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_validate() {
        assert!(TokenBucket::new(0.0, 2.0, Duration::ZERO).is_err());
        assert!(TokenBucket::new(1.0, 0.5, Duration::ZERO).is_err());
        assert!(TokenBucket::new(10.0, 20.0, Duration::ZERO).is_ok());
        assert!(Gcra::new(Duration::ZERO, 1).is_err());
        assert!(Gcra::new(Duration::from_millis(100), 3).is_ok());
    }
}
