//! Injectable randomness. Backoff jitter, Thompson sampling and hedging draw from a
//! [`RandomSource`] so tests can fix the sequence ([`SplitMix64`]) while production uses the
//! operating system's generator ([`SystemRandom`]).

/// A source of uniformly distributed random numbers.
pub trait RandomSource: Send {
    /// A uniformly distributed `u64`.
    fn next_u64(&mut self) -> u64;

    /// A uniformly distributed `f64` in `[0, 1)` with 53 bits of resolution.
    fn unit_f64(&mut self) -> f64 {
        // 2^-53 times a 53-bit integer.
        (self.next_u64() >> 11) as f64 * (1.0 / 9_007_199_254_740_992.0)
    }

    /// A uniformly distributed integer in `[0, bound)`, without modulo bias. `bound == 0` returns 0.
    fn below(&mut self, bound: u64) -> u64 {
        if bound <= 1 {
            return 0;
        }
        // Rejection sampling over the largest multiple of `bound` that fits in a u64.
        let zone = u64::MAX - (u64::MAX % bound);
        loop {
            let x = self.next_u64();
            if x < zone {
                return x % bound;
            }
        }
    }

    /// A uniformly distributed integer in `[low, high]` (inclusive). Returns `low` if `high <= low`.
    fn between_inclusive(&mut self, low: u64, high: u64) -> u64 {
        if high <= low {
            return low;
        }
        match (high - low).checked_add(1) {
            Some(span) => low + self.below(span),
            None => self.next_u64(),
        }
    }
}

/// The operating system's generator (`rand`'s thread-local CSPRNG). Use in production.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRandom;

impl RandomSource for SystemRandom {
    fn next_u64(&mut self) -> u64 {
        rand::random::<u64>()
    }
}

/// SplitMix64: a tiny, fast, deterministic generator for tests and simulations. Not for secrets.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// A generator with the given seed. The same seed yields the same sequence on every platform.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

impl RandomSource for SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix_matches_the_reference_sequence() {
        // First outputs of SplitMix64 seeded with 0 (Vigna's reference implementation).
        let mut rng = SplitMix64::new(0);
        assert_eq!(rng.next_u64(), 0xE220_A839_7B1D_CDAF);
        assert_eq!(rng.next_u64(), 0x6E78_9E6A_A1B9_65F4);
        assert_eq!(rng.next_u64(), 0x06C4_5D18_8009_454F);
    }

    #[test]
    fn bounded_draws_stay_in_range() {
        let mut rng = SplitMix64::new(7);
        for bound in [1u64, 2, 3, 10, 1000, u64::MAX] {
            for _ in 0..200 {
                assert!(rng.below(bound) < bound.max(1));
            }
        }
        for _ in 0..200 {
            let x = rng.between_inclusive(5, 9);
            assert!((5..=9).contains(&x));
            let u = rng.unit_f64();
            assert!((0.0..1.0).contains(&u));
        }
        assert_eq!(rng.between_inclusive(9, 5), 9);
    }

    #[test]
    fn system_random_produces_values() {
        let mut rng = SystemRandom;
        let a = rng.next_u64();
        let b = rng.next_u64();
        assert_ne!((a, b), (0, 0));
    }
}
