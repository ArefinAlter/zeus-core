//! Retry backoff with jitter (01 section 8.5, research.md section 8.9).
//!
//! The default, and the one the specification fixes, is *full jitter with a floor*:
//!
//! ```text
//! delay_ms = max(floor_ms, uniform(0, min(cap_ms, base_ms * 2^(n-1))))
//! ```
//!
//! for retry number `n` (1 for the first retry), so a retry never happens at once and a thundering
//! herd spreads out. For `throttled` with a `Retry-After`, [`with_retry_after`] raises the delay to
//! the server's request. Equal and decorrelated jitter are provided for mirrors and workflow fetches.

use zeus_types::ErrorClass;
use zeus_types::policy::{BackoffSpec, backoff_for_class};

use crate::random::RandomSource;

/// The jitter strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Jitter {
    /// `uniform(0, envelope)`: the specified default.
    #[default]
    Full,
    /// `envelope / 2 + uniform(0, envelope / 2)`: keeps at least half the envelope.
    Equal,
    /// `min(cap, uniform(base, 3 * previous_delay))`: grows from the previous delay, not the attempt number.
    Decorrelated,
}

/// A backoff policy: parameters plus a jitter strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    spec: BackoffSpec,
    jitter: Jitter,
}

impl Backoff {
    /// A policy from explicit parameters.
    #[must_use]
    pub const fn new(spec: BackoffSpec, jitter: Jitter) -> Self {
        Self { spec, jitter }
    }

    /// The specified policy of a job error class, or `None` when the class does not back off
    /// (`auth_expired`, `url_expired`, `blocked`, `permanent`, `policy_denied`, and `disk`, which is
    /// per code: use `zeus_types::policy::disk_retry`).
    #[must_use]
    pub fn for_class(class: ErrorClass) -> Option<Self> {
        backoff_for_class(class).map(|spec| Self::new(spec, Jitter::Full))
    }

    /// The parameters.
    #[must_use]
    pub const fn spec(&self) -> BackoffSpec {
        self.spec
    }

    /// `min(cap, base * 2^(n-1))` in milliseconds for retry number `n` (1-based; 0 is treated as 1).
    /// Saturates instead of overflowing.
    #[must_use]
    pub fn envelope_ms(&self, retry: u32) -> u64 {
        let shift = retry.saturating_sub(1).min(63);
        let grown = self.spec.base_ms.saturating_mul(1u64 << shift);
        grown.min(self.spec.cap_ms)
    }

    /// The delay before retry number `retry` (1-based), in milliseconds. `previous_ms` is the
    /// previous delay and is used only by [`Jitter::Decorrelated`].
    pub fn delay_ms(
        &self,
        retry: u32,
        previous_ms: Option<u64>,
        rng: &mut dyn RandomSource,
    ) -> u64 {
        let envelope = self.envelope_ms(retry);
        let raw = match self.jitter {
            Jitter::Full => rng.between_inclusive(0, envelope),
            Jitter::Equal => {
                let half = envelope / 2;
                half + rng.between_inclusive(0, envelope - half)
            }
            Jitter::Decorrelated => {
                let prev = previous_ms
                    .unwrap_or(self.spec.base_ms)
                    .max(self.spec.base_ms);
                rng.between_inclusive(self.spec.base_ms, prev.saturating_mul(3))
                    .min(self.spec.cap_ms)
            }
        };
        raw.max(self.spec.floor_ms)
    }
}

/// Raises `delay_ms` to the server's `Retry-After` (`delay_ms = max(delay_ms, retry_after_ms)`).
#[must_use]
pub fn with_retry_after(delay_ms: u64, retry_after_ms: Option<u64>) -> u64 {
    retry_after_ms.map_or(delay_ms, |ra| delay_ms.max(ra))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use zeus_types::policy::{THROTTLED_BACKOFF, TRANSIENT_NETWORK_BACKOFF};

    use super::*;
    use crate::random::SplitMix64;

    #[test]
    fn envelope_doubles_until_the_cap() {
        let b = Backoff::new(TRANSIENT_NETWORK_BACKOFF, Jitter::Full);
        let seq: Vec<u64> = (1..=12).map(|n| b.envelope_ms(n)).collect();
        assert_eq!(&seq[..4], &[1_000, 2_000, 4_000, 8_000]);
        assert_eq!(seq[9], 512_000);
        assert_eq!(seq[10], 900_000, "1,024,000 is capped at 15 minutes");
        assert_eq!(
            b.envelope_ms(1_000),
            900_000,
            "no overflow for absurd attempt numbers"
        );
        assert_eq!(b.envelope_ms(0), 1_000);
    }

    #[test]
    fn full_jitter_respects_floor_and_envelope() {
        let b = Backoff::for_class(ErrorClass::TransientNetwork).unwrap();
        let mut rng = SplitMix64::new(1);
        for n in 1..=20 {
            for _ in 0..200 {
                let d = b.delay_ms(n, None, &mut rng);
                assert!(d >= 250, "floor");
                assert!(d <= b.envelope_ms(n).max(250));
            }
        }
    }

    #[test]
    fn equal_jitter_keeps_half() {
        let b = Backoff::new(TRANSIENT_NETWORK_BACKOFF, Jitter::Equal);
        let mut rng = SplitMix64::new(2);
        for _ in 0..200 {
            let d = b.delay_ms(4, None, &mut rng); // envelope 8000
            assert!((4_000..=8_000).contains(&d));
        }
    }

    #[test]
    fn decorrelated_jitter_never_exceeds_the_cap() {
        let b = Backoff::new(THROTTLED_BACKOFF, Jitter::Decorrelated);
        let mut rng = SplitMix64::new(3);
        let mut prev = None;
        for _ in 0..200 {
            let d = b.delay_ms(1, prev, &mut rng);
            assert!((1_000..=900_000).contains(&d));
            prev = Some(d);
        }
    }

    #[test]
    fn retry_after_only_raises() {
        assert_eq!(with_retry_after(2_000, Some(30_000)), 30_000);
        assert_eq!(with_retry_after(60_000, Some(30_000)), 60_000);
        assert_eq!(with_retry_after(2_000, None), 2_000);
    }

    #[test]
    fn classes_without_backoff() {
        for class in [
            ErrorClass::AuthExpired,
            ErrorClass::UrlExpired,
            ErrorClass::Blocked,
            ErrorClass::Permanent,
            ErrorClass::PolicyDenied,
            ErrorClass::Disk,
        ] {
            assert!(Backoff::for_class(class).is_none(), "{class}");
        }
    }

    proptest! {
        #[test]
        fn delay_is_deterministic_for_a_seed(seed in any::<u64>(), retry in 1u32..40) {
            let b = Backoff::for_class(ErrorClass::Throttled).unwrap();
            let a = b.delay_ms(retry, None, &mut SplitMix64::new(seed));
            let c = b.delay_ms(retry, None, &mut SplitMix64::new(seed));
            prop_assert_eq!(a, c);
            prop_assert!((1_000..=900_000).contains(&a));
        }
    }
}
