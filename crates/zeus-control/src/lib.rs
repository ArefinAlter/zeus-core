//! Pure, deterministic control algorithms for Zeus.
//!
//! Nothing here performs I/O or spawns tasks, and nothing reads the clock or a random number
//! generator directly: time comes from an injected [`Clock`] (or an explicit monotonic argument) and
//! randomness from a [`RandomSource`]. That makes every algorithm exactly reproducible in tests.
//!
//! Modules: clocks, randomness, ranges, backoff, EWMA, AIMD, segment planning, limiters, fairness,
//! throughput and ETA estimation (windowed rate, Kalman), mirror selection (UCB1, Thompson,
//! sliding-window UCB), P-squared hedging, reliability math and CUSUM throttle detection. The engine uses
//! the core of these for basic transfers; the advanced selectors are available for scheduling work that
//! does not call them yet.

#![forbid(unsafe_code)]

pub mod backoff;
pub mod clock;
pub mod concurrency;
pub mod cusum;
pub mod error;
pub mod estimate;
pub mod fairness;
pub mod hedge;
pub mod limiter;
pub mod math;
pub mod mirror;
pub mod random;
pub mod range_set;
pub mod segments;

pub use backoff::{Backoff, Jitter, with_retry_after};
pub use clock::{Clock, ManualClock, SharedClock, SystemClock};
pub use error::{ControlError, Result};
pub use estimate::Ewma;
pub use random::{RandomSource, SplitMix64, SystemRandom};
pub use range_set::RangeSet;
