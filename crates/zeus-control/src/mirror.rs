//! Mirror and source selection as a multi-armed bandit (research.md section 8.5).
//!
//! An *arm* is a mirror (or a connection to one host). The reward is normalised throughput in
//! `[0, 1]`. Three selectors share one trait: UCB1, Thompson sampling with Beta posteriors, and a
//! sliding-window UCB for non-stationary mirrors.
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: bodies are filled in by the zeus-control implementation task"
)]

use std::collections::VecDeque;

use crate::error::{ControlError, Result};
use crate::random::RandomSource;

/// A bandit policy over a fixed number of arms.
pub trait MirrorSelector: Send {
    /// Number of arms.
    fn arms(&self) -> usize;

    /// Chooses the arm to use next. Untried arms are tried first. Errors when there are no arms.
    fn select(&mut self, rng: &mut dyn RandomSource) -> Result<usize>;

    /// Records the reward of one pull of `arm` (clamped to `[0, 1]`; NaN is rejected).
    fn record(&mut self, arm: usize, reward: f64) -> Result<()>;
}

/// UCB1: `mean + sqrt(2 ln N / n)`.
#[derive(Debug, Clone)]
pub struct Ucb1 {
    pulls: Vec<u64>,
    sums: Vec<f64>,
}

impl Ucb1 {
    /// A selector over `arms` arms.
    pub fn new(arms: usize) -> Result<Self> {
        if arms == 0 {
            return Err(ControlError::invalid("arms", "need at least one arm"));
        }
        Ok(Self {
            pulls: vec![0; arms],
            sums: vec![0.0; arms],
        })
    }
}

impl MirrorSelector for Ucb1 {
    fn arms(&self) -> usize {
        self.pulls.len()
    }

    fn select(&mut self, rng: &mut dyn RandomSource) -> Result<usize> {
        Err(ControlError::NotImplemented("Ucb1::select"))
    }

    fn record(&mut self, arm: usize, reward: f64) -> Result<()> {
        Err(ControlError::NotImplemented("Ucb1::record"))
    }
}

/// Thompson sampling with a Beta(1, 1) prior per arm.
#[derive(Debug, Clone)]
pub struct ThompsonBeta {
    successes: Vec<f64>,
    failures: Vec<f64>,
}

impl ThompsonBeta {
    /// A selector over `arms` arms.
    pub fn new(arms: usize) -> Result<Self> {
        if arms == 0 {
            return Err(ControlError::invalid("arms", "need at least one arm"));
        }
        Ok(Self {
            successes: vec![1.0; arms],
            failures: vec![1.0; arms],
        })
    }
}

impl MirrorSelector for ThompsonBeta {
    fn arms(&self) -> usize {
        self.successes.len()
    }

    fn select(&mut self, rng: &mut dyn RandomSource) -> Result<usize> {
        Err(ControlError::NotImplemented("ThompsonBeta::select"))
    }

    fn record(&mut self, arm: usize, reward: f64) -> Result<()> {
        Err(ControlError::NotImplemented("ThompsonBeta::record"))
    }
}

/// Sliding-window UCB: UCB1 over the last `window` pulls, so a mirror that degrades is abandoned.
#[derive(Debug, Clone)]
pub struct SlidingWindowUcb {
    window: usize,
    history: VecDeque<(usize, f64)>,
    arms: usize,
}

impl SlidingWindowUcb {
    /// A selector over `arms` arms remembering the last `window` pulls overall.
    pub fn new(arms: usize, window: usize) -> Result<Self> {
        if arms == 0 || window == 0 {
            return Err(ControlError::invalid("arms/window", "must be positive"));
        }
        Ok(Self {
            window,
            history: VecDeque::new(),
            arms,
        })
    }
}

impl MirrorSelector for SlidingWindowUcb {
    fn arms(&self) -> usize {
        self.arms
    }

    fn select(&mut self, rng: &mut dyn RandomSource) -> Result<usize> {
        Err(ControlError::NotImplemented("SlidingWindowUcb::select"))
    }

    fn record(&mut self, arm: usize, reward: f64) -> Result<()> {
        Err(ControlError::NotImplemented("SlidingWindowUcb::record"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructors_validate() {
        assert!(Ucb1::new(0).is_err());
        assert!(ThompsonBeta::new(0).is_err());
        assert!(SlidingWindowUcb::new(2, 0).is_err());
        assert_eq!(Ucb1::new(3).unwrap().arms(), 3);
    }
}
