//! Pure, deterministic control algorithms for Zeus.
//!
//! Nothing here performs I/O or spawns tasks, and nothing reads the clock or a random number
//! generator directly: time comes from an injected [`Clock`] (or an explicit monotonic argument) and
//! randomness from a [`RandomSource`]. That makes every algorithm exactly reproducible in tests.
//!
//! Implemented in the skeleton: [`Clock`], [`RandomSource`], [`RangeSet`] (the committed-range
//! interval set of 03 section 3.4), [`Backoff`] (01 section 8.5) and [`Ewma`]. The remaining modules
//! define the final API and return [`ControlError::NotImplemented`] until the `zeus-control`
//! implementation task fills them in.

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
