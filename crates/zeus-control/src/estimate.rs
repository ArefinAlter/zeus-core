//! Smoothing and estimation: EWMA (implemented), windowed throughput, a 1-D Kalman filter and ETA
//! with a confidence band (research.md section 8.8).
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
    /// Start of the open interval, set by the first reading.
    open_since: Option<Duration>,
    /// Bytes recorded in the open interval.
    open_bytes: u64,
}

/// Silent intervals folded one by one before the decay is applied in closed form.
const MAX_STEPPED_INTERVALS: u64 = 1024;

impl RateEstimator {
    /// An estimator with the given smoothing factor and sampling interval.
    pub fn new(alpha: f64, interval: Duration) -> Result<Self> {
        if interval.is_zero() {
            return Err(ControlError::invalid("interval", "must be positive"));
        }
        Ok(Self {
            interval,
            ewma: Ewma::new(alpha)?,
            open_since: None,
            open_bytes: 0,
        })
    }

    /// Close every interval that ended by `now`: the open one becomes a sample, and each later silent one a
    /// zero sample. A very long silence decays the average in closed form instead of one sample at a time.
    fn close(&mut self, now: Duration) -> Result<()> {
        let Some(since) = self.open_since else {
            self.open_since = Some(now);
            return Ok(());
        };
        if now < since {
            return Err(ControlError::invalid("now", "must not go backwards"));
        }
        let elapsed = (now - since).as_nanos() / self.interval.as_nanos();
        if elapsed == 0 {
            return Ok(());
        }
        let seconds = self.interval.as_secs_f64();
        self.ewma.update(self.open_bytes as f64 / seconds)?;
        self.open_bytes = 0;
        let silent = u64::try_from(elapsed - 1).unwrap_or(u64::MAX);
        for _ in 0..silent.min(MAX_STEPPED_INTERVALS) {
            self.ewma.update(0.0)?;
        }
        if silent > MAX_STEPPED_INTERVALS
            && let Some(value) = self.ewma.value
        {
            let remaining = (silent - MAX_STEPPED_INTERVALS) as f64;
            self.ewma.value = Some(value * (1.0 - self.ewma.alpha).powf(remaining));
        }
        let advanced = self
            .interval
            .saturating_mul(u32::try_from(elapsed).unwrap_or(u32::MAX));
        self.open_since = Some(since.saturating_add(advanced).min(now));
        Ok(())
    }

    /// Records `bytes` transferred at monotonic time `now` (any reading of one clock, non-decreasing).
    pub fn record(&mut self, now: Duration, bytes: u64) -> Result<()> {
        self.close(now)?;
        self.open_bytes = self.open_bytes.saturating_add(bytes);
        Ok(())
    }

    /// The smoothed rate in bytes per second as of `now` (closing any elapsed intervals first); zero before
    /// the first interval closes.
    pub fn rate_bps(&mut self, now: Duration) -> Result<u64> {
        self.close(now)?;
        Ok(self.ewma.value().map_or(0, |v| v.max(0.0).round() as u64))
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

    /// Predict-then-update with one measurement (research.md 8.8): `P += Q`, `K = P / (P + R)`,
    /// `x += K (z - x)`, `P = (1 - K) P`.
    pub fn update(&mut self, measurement: f64) -> Result<KalmanState> {
        finite("measurement", measurement)?;
        let predicted = self.state.variance + self.process_variance;
        let gain = predicted / (predicted + self.measurement_variance);
        self.state = KalmanState {
            estimate: self.state.estimate + gain * (measurement - self.state.estimate),
            variance: (1.0 - gain) * predicted,
        };
        Ok(self.state)
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
    if finite("mean_bps", mean_bps)? < 0.0
        || finite("std_dev_bps", std_dev_bps)? < 0.0
        || finite("z", z)? < 0.0
    {
        return Err(ControlError::invalid(
            "eta",
            "mean, deviation and z must not be negative",
        ));
    }
    if mean_bps == 0.0 {
        return Ok(None);
    }
    let remaining = remaining_bytes as f64;
    let seconds = |rate: f64| remaining / rate;
    let fast = mean_bps + z * std_dev_bps;
    let slow = mean_bps - z * std_dev_bps;
    Ok(Some(EtaEstimate {
        eta_s: seconds(mean_bps).floor() as u64,
        lower_s: seconds(fast).floor() as u64,
        // A band reaching zero throughput has no finite pessimistic bound.
        upper_s: if slow > 0.0 {
            seconds(slow).ceil().min(u64::MAX as f64) as u64
        } else {
            u64::MAX
        },
    }))
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
    fn the_rate_estimator_samples_whole_intervals_and_decays_through_silence() {
        let second = Duration::from_secs(1);
        let mut r = RateEstimator::new(0.2, second).unwrap();
        assert_eq!(r.rate_bps(Duration::ZERO).unwrap(), 0);
        r.record(Duration::from_millis(100), 600).unwrap();
        r.record(Duration::from_millis(900), 400).unwrap();
        assert_eq!(
            r.rate_bps(Duration::from_millis(999)).unwrap(),
            0,
            "the interval is still open"
        );
        assert_eq!(r.rate_bps(second).unwrap(), 1000);
        r.record(Duration::from_millis(1500), 2000).unwrap();
        // 0.2 * 2000 + 0.8 * 1000 = 1200, then one silent second: 0.8 * 1200 = 960.
        assert_eq!(r.rate_bps(Duration::from_secs(2)).unwrap(), 1200);
        assert_eq!(r.rate_bps(Duration::from_secs(3)).unwrap(), 960);
        // A day of silence decays to zero without stepping 86,400 samples.
        assert_eq!(r.rate_bps(Duration::from_secs(86_400)).unwrap(), 0);
        assert!(
            r.record(Duration::from_secs(10), 1).is_err(),
            "time cannot go backwards"
        );
    }

    #[test]
    fn kalman_follows_the_research_recurrence() {
        let mut k = Kalman1D::new(
            1.0,
            4.0,
            KalmanState {
                estimate: 10.0,
                variance: 1.0,
            },
        )
        .unwrap();
        // P = 1 + 1 = 2, K = 2 / 6, x = 10 + (16 - 10) / 3 = 12, P = (2/3) * 2.
        let s = k.update(16.0).unwrap();
        assert!((s.estimate - 12.0).abs() < 1e-12);
        assert!((s.variance - 4.0 / 3.0).abs() < 1e-12);
        assert!(k.update(f64::INFINITY).is_err());
    }

    #[test]
    fn eta_matches_the_research_example_with_an_honest_band() {
        // research.md 8.8: 600 MB at 12 MB/s is 50 s.
        let mb = 1_000_000.0;
        let eta = eta_with_band(600_000_000, 12.0 * mb, 2.0 * mb, 1.0)
            .unwrap()
            .unwrap();
        assert_eq!(eta.eta_s, 50);
        assert_eq!(eta.lower_s, 42, "600 / 14 = 42.9");
        assert_eq!(eta.upper_s, 60, "600 / 10 = 60");
        let wide = eta_with_band(600_000_000, 12.0 * mb, 12.0 * mb, 1.64)
            .unwrap()
            .unwrap();
        assert_eq!(
            wide.upper_s,
            u64::MAX,
            "a band reaching zero rate has no upper bound"
        );
        assert_eq!(eta_with_band(10, 0.0, 1.0, 1.0).unwrap(), None);
        assert!(eta_with_band(10, -1.0, 1.0, 1.0).is_err());
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
