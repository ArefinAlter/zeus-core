//! Pure, deterministic control algorithms for Zeus.
//!
//! Nothing here performs I/O or spawns tasks, and nothing reads the clock or a random number
//! generator directly: time comes from an injected [`Clock`] (or an explicit monotonic argument) and
//! randomness from a [`RandomSource`]. That makes every algorithm exactly reproducible in tests.
//!
//! Implemented modules include clocks, randomness, ranges, backoff, EWMA, AIMD, segment planning,
//! limiters and fairness. Advanced estimators, mirror selection, hedging, reliability math and CUSUM
//! still expose typed `NotImplemented` results; the engine does not depend on them for basic transfers.

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
