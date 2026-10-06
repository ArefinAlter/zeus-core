//! Smoothing and estimation: EWMA (implemented), windowed throughput, a 1-D Kalman filter and ETA
//! with a confidence band (research.md section 8.8).
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: bodies are filled in by the zeus-control implementation task"
)]

use std::time::Duration;

use crate::error::{ControlError, Result, finite};

/// Exponentially weighted moving average, `v <- alpha * x + (1 - alpha) * v`, seeded by the first sample.
///
/// The progress rate of a job (01 section 3.7) is an EWMA with `alpha = 0.2` over 1 s samples.
#[derive(Debug, Clone, PartialEq)]
pub struct Ewma {
    alpha: f64,
    value: Option<f64>,
}

impl Ewma {
    /// `alpha` must be finite and in `(0, 1]`.
    pub fn new(alpha: f64) -> Result<Self> {
        if finite("alpha", alpha)? <= 0.0 || alpha > 1.0 {
            return Err(ControlError::invalid("alpha", "must be in (0, 1]"));
        }
        Ok(Self { alpha, value: None })
    }

    /// Folds in a sample and returns the new average.
    pub fn update(&mut self, sample: f64) -> Result<f64> {
        finite("sample", sample)?;
        let next = self
            .value
            .map_or(sample, |v| self.alpha * sample + (1.0 - self.alpha) * v);
        self.value = Some(next);
        Ok(next)
    }

    /// The current average, if any sample has been seen.
    #[must_use]
    pub const fn value(&self) -> Option<f64> {
        self.value
    }

    /// Forgets the history.
    pub fn reset(&mut self) {
        self.value = None;
    }
}

/// Bytes-per-second estimator over fixed sampling intervals (1 s in the specification).
///
/// Bytes recorded within an interval are summed; when the interval closes the sum becomes one
/// sample of an [`Ewma`]. A silent interval is a zero sample, so the rate decays when a transfer stalls.
#[derive(Debug, Clone)]
pub struct RateEstimator {
    interval: Duration,
    ewma: Ewma,
}

impl RateEstimator {
    /// An estimator with the given smoothing factor and sampling interval.
    pub fn new(alpha: f64, interval: Duration) -> Result<Self> {
        if interval.is_zero() {
            return Err(ControlError::invalid("interval", "must be positive"));
        }
        Ok(Self {
            interval,
            ewma: Ewma::new(alpha)?,
        })
    }

    /// Records `bytes` transferred at monotonic time `now` (any reading of one clock, non-decreasing).
    pub fn record(&mut self, now: Duration, bytes: u64) -> Result<()> {
        Err(ControlError::NotImplemented("RateEstimator::record"))
    }

    /// The smoothed rate in bytes per second as of `now` (closing any elapsed intervals first).
    pub fn rate_bps(&mut self, now: Duration) -> Result<u64> {
        Err(ControlError::NotImplemented("RateEstimator::rate_bps"))
    }
}

/// Posterior of a [`Kalman1D`] filter.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KalmanState {
    /// The filtered estimate.
    pub estimate: f64,
    /// The variance of the estimate.
    pub variance: f64,
}

/// A scalar Kalman filter for a slowly drifting quantity (throughput) observed with noise.
#[derive(Debug, Clone)]
pub struct Kalman1D {
    process_variance: f64,
    measurement_variance: f64,
    state: KalmanState,
}

impl Kalman1D {
    /// Both variances must be positive and finite.
    pub fn new(
        process_variance: f64,
        measurement_variance: f64,
        initial: KalmanState,
    ) -> Result<Self> {
        if finite("process_variance", process_variance)? <= 0.0
            || finite("measurement_variance", measurement_variance)? <= 0.0
        {
            return Err(ControlError::invalid("variance", "must be positive"));
        }
        Ok(Self {
            process_variance,
            measurement_variance,
            state: initial,
        })
    }

    /// The current posterior.
    #[must_use]
    pub const fn state(&self) -> KalmanState {
        self.state
    }

    /// Predict-then-update with one measurement.
    pub fn update(&mut self, measurement: f64) -> Result<KalmanState> {
        Err(ControlError::NotImplemented("Kalman1D::update"))
    }
}

/// A remaining-time estimate with a band: `eta_s` is the point estimate, `lower_s` and `upper_s`
/// bracket it at the requested confidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EtaEstimate {
    /// Point estimate in seconds (integer division, as `Progress.eta_s`).
    pub eta_s: u64,
    /// Optimistic bound in seconds.
    pub lower_s: u64,
    /// Pessimistic bound in seconds.
    pub upper_s: u64,
}

/// ETA for `remaining_bytes` at a rate with mean `mean_bps` and standard deviation `std_dev_bps`;
/// `z` is the band width in standard deviations (1.64 for roughly 90 %). `None` when the mean rate is zero.
pub fn eta_with_band(
    remaining_bytes: u64,
    mean_bps: f64,
    std_dev_bps: f64,
    z: f64,
) -> Result<Option<EtaEstimate>> {
    Err(ControlError::NotImplemented("eta_with_band"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ewma_follows_the_recurrence() {
        let mut e = Ewma::new(0.2).unwrap();
        assert_eq!(e.value(), None);
        assert_eq!(e.update(100.0).unwrap(), 100.0);
        assert!((e.update(200.0).unwrap() - 120.0).abs() < 1e-12);
        assert!((e.update(0.0).unwrap() - 96.0).abs() < 1e-12);
        e.reset();
        assert_eq!(e.value(), None);
    }

    #[test]
    fn ewma_rejects_bad_input() {
        for alpha in [0.0, -0.1, 1.1, f64::NAN, f64::INFINITY] {
            assert!(Ewma::new(alpha).is_err(), "{alpha}");
        }
        let mut e = Ewma::new(1.0).unwrap();
        assert!(e.update(f64::NAN).is_err());
        assert_eq!(e.update(5.0).unwrap(), 5.0);
        assert_eq!(
            e.update(7.0).unwrap(),
            7.0,
            "alpha = 1 keeps only the latest sample"
        );
    }
}
