//! Tail-latency hedging with a streaming quantile (research.md section 8.7).
//!
//! A request that has taken longer than the observed p-th percentile of its peers is duplicated on
//! another connection ("hedged"); the first answer wins and the other is cancelled. Both copies are
//! fetched under the same bound validators (03 section 3.4), so overlapping commits are safe.
use std::time::Duration;

use crate::error::{ControlError, Result};

/// The P-squared algorithm (Jain and Chlamtac, 1985): a constant-memory streaming estimate of one quantile.
#[derive(Debug, Clone)]
pub struct P2Quantile {
    p: f64,
    count: u64,
    /// Marker heights `q`, the estimate is `heights[2]`.
    heights: [f64; 5],
    /// Actual marker positions `n` (1-based ranks).
    positions: [f64; 5],
    /// Desired marker positions `n'`.
    desired: [f64; 5],
    /// Increments of the desired positions per observation.
    increments: [f64; 5],
}

impl P2Quantile {
    /// Estimates the `p`-quantile, `0 < p < 1`.
    pub fn new(p: f64) -> Result<Self> {
        if !(p > 0.0 && p < 1.0) {
            return Err(ControlError::invalid("p", "must be in (0, 1)"));
        }
        Ok(Self {
            p,
            count: 0,
            heights: [0.0; 5],
            positions: [1.0, 2.0, 3.0, 4.0, 5.0],
            desired: [1.0, 1.0 + 2.0 * p, 1.0 + 4.0 * p, 3.0 + 2.0 * p, 5.0],
            increments: [0.0, p / 2.0, p, (1.0 + p) / 2.0, 1.0],
        })
    }

    /// Number of observations folded in.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }

    /// The quantile this estimator tracks.
    #[must_use]
    pub const fn p(&self) -> f64 {
        self.p
    }

    /// Folds in one observation: the first five seed the markers, every later one moves them by at most
    /// one position with the piecewise-parabolic (or, failing that, linear) height formula.
    pub fn observe(&mut self, value: f64) -> Result<()> {
        crate::error::finite("value", value)?;
        if self.count < 5 {
            self.heights[self.count as usize] = value;
            self.count += 1;
            if self.count == 5 {
                self.heights.sort_by(f64::total_cmp);
            }
            return Ok(());
        }
        self.count += 1;
        let q = &mut self.heights;
        let cell = if value < q[0] {
            q[0] = value;
            0
        } else if value >= q[4] {
            q[4] = value;
            3
        } else {
            (0..4).find(|&i| value < q[i + 1]).unwrap_or(3)
        };
        for i in cell + 1..5 {
            self.positions[i] += 1.0;
        }
        for i in 0..5 {
            self.desired[i] += self.increments[i];
        }
        for i in 1..4 {
            let n = &self.positions;
            let d = self.desired[i] - n[i];
            if (d >= 1.0 && n[i + 1] - n[i] > 1.0) || (d <= -1.0 && n[i - 1] - n[i] < -1.0) {
                let s = d.signum();
                let q = &self.heights;
                let parabolic = q[i]
                    + s / (n[i + 1] - n[i - 1])
                        * ((n[i] - n[i - 1] + s) * (q[i + 1] - q[i]) / (n[i + 1] - n[i])
                            + (n[i + 1] - n[i] - s) * (q[i] - q[i - 1]) / (n[i] - n[i - 1]));
                let next = if q[i - 1] < parabolic && parabolic < q[i + 1] {
                    parabolic
                } else {
                    let j = if s > 0.0 { i + 1 } else { i - 1 };
                    q[i] + s * (q[j] - q[i]) / (n[j] - n[i])
                };
                self.heights[i] = next;
                self.positions[i] += s;
            }
        }
        Ok(())
    }

    /// The current estimate, or `None` before enough observations (five) exist.
    #[must_use]
    pub fn estimate(&self) -> Option<f64> {
        (self.count >= 5).then_some(self.heights[2])
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

    /// True when a request that has been running for `elapsed` should be hedged: at least `min_samples`
    /// completions are known and `elapsed > factor * quantile`.
    pub fn should_hedge(&self, elapsed: Duration) -> Result<bool> {
        if self.quantile.count() < self.min_samples.max(5) {
            return Ok(false);
        }
        Ok(self
            .quantile
            .estimate()
            .is_some_and(|q| elapsed.as_secs_f64() > self.factor * q))
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

    #[test]
    fn p_squared_tracks_quantiles_of_a_known_distribution() {
        let mut rng = crate::random::SplitMix64::new(42);
        let mut p95 = P2Quantile::new(0.95).unwrap();
        let mut median = P2Quantile::new(0.5).unwrap();
        assert_eq!(p95.estimate(), None);
        for _ in 0..20_000 {
            let x = crate::random::RandomSource::unit_f64(&mut rng);
            p95.observe(x).unwrap();
            median.observe(x).unwrap();
        }
        assert!(
            (p95.estimate().unwrap() - 0.95).abs() < 0.01,
            "{:?}",
            p95.estimate()
        );
        assert!(
            (median.estimate().unwrap() - 0.5).abs() < 0.01,
            "{:?}",
            median.estimate()
        );
        assert_eq!(p95.count(), 20_000);
        assert!(p95.observe(f64::NAN).is_err());
    }

    #[test]
    fn hedging_waits_for_samples_and_then_fires_only_on_the_tail() {
        let mut trigger = HedgeTrigger::new(0.95, 1.5, 20).unwrap();
        for ms in 1..=19 {
            trigger
                .record_completion(Duration::from_millis(100 + ms))
                .unwrap();
        }
        assert!(
            !trigger.should_hedge(Duration::from_secs(60)).unwrap(),
            "too few samples"
        );
        for ms in 0..200 {
            trigger
                .record_completion(Duration::from_millis(100 + ms % 20))
                .unwrap();
        }
        assert!(!trigger.should_hedge(Duration::from_millis(150)).unwrap());
        assert!(trigger.should_hedge(Duration::from_millis(200)).unwrap());
    }
}
