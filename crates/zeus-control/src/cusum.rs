//! CUSUM change-point detection for throttle detection (a sustained downward shift of throughput).
use crate::error::{ControlError, Result, finite};

/// Verdict of one [`Cusum`] update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shift {
    /// No change detected.
    None,
    /// The mean dropped: the server probably started throttling.
    Down,
    /// The mean rose.
    Up,
}

/// Two-sided tabular CUSUM around a reference mean.
///
/// `slack` (often half the shift to detect) is subtracted so noise does not accumulate; a shift is
/// reported when a cumulative sum exceeds `threshold`, after which the sums reset.
#[derive(Debug, Clone)]
pub struct Cusum {
    target: f64,
    slack: f64,
    threshold: f64,
    high: f64,
    low: f64,
}

impl Cusum {
    /// All parameters must be finite; `slack >= 0`, `threshold > 0`.
    pub fn new(target: f64, slack: f64, threshold: f64) -> Result<Self> {
        finite("target", target)?;
        if finite("slack", slack)? < 0.0 || finite("threshold", threshold)? <= 0.0 {
            return Err(ControlError::invalid(
                "slack/threshold",
                "slack >= 0 and threshold > 0",
            ));
        }
        Ok(Self {
            target,
            slack,
            threshold,
            high: 0.0,
            low: 0.0,
        })
    }

    /// Folds in one observation: `high = max(0, high + x - target - slack)` and
    /// `low = max(0, low + target - slack - x)`. A sum above `threshold` reports its shift and resets both.
    pub fn update(&mut self, value: f64) -> Result<Shift> {
        finite("value", value)?;
        self.high = (self.high + value - self.target - self.slack).max(0.0);
        self.low = (self.low + self.target - self.slack - value).max(0.0);
        let shift = if self.low > self.threshold {
            Shift::Down
        } else if self.high > self.threshold {
            Shift::Up
        } else {
            return Ok(Shift::None);
        };
        self.high = 0.0;
        self.low = 0.0;
        Ok(shift)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameter_validation() {
        assert!(Cusum::new(100.0, 5.0, 20.0).is_ok());
        assert!(Cusum::new(f64::NAN, 5.0, 20.0).is_err());
        assert!(Cusum::new(100.0, -1.0, 20.0).is_err());
        assert!(Cusum::new(100.0, 1.0, 0.0).is_err());
    }

    #[test]
    fn noise_within_the_slack_never_alarms_but_a_sustained_drop_does() {
        let mut c = Cusum::new(100.0, 5.0, 20.0).unwrap();
        for x in [103.0, 97.0, 104.0, 96.0, 100.0, 105.0, 95.0] {
            assert_eq!(c.update(x).unwrap(), Shift::None);
        }
        // Throttled to 80: each sample adds 15 to the low sum, so the second one crosses 20.
        assert_eq!(c.update(80.0).unwrap(), Shift::None);
        assert_eq!(c.update(80.0).unwrap(), Shift::Down);
        assert_eq!(
            c.update(100.0).unwrap(),
            Shift::None,
            "sums reset after a report"
        );
        assert_eq!(c.update(130.0).unwrap(), Shift::Up);
        assert!(c.update(f64::NAN).is_err());
    }
}
