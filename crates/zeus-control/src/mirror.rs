//! Mirror and source selection as a multi-armed bandit (research.md section 8.5).
//!
//! An *arm* is a mirror (or a connection to one host). The reward is normalised throughput in
//! `[0, 1]`. Three selectors share one trait: UCB1, Thompson sampling with Beta posteriors, and a
//! sliding-window UCB for non-stationary mirrors.
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

fn checked_reward(arm: usize, arms: usize, reward: f64) -> Result<f64> {
    if arm >= arms {
        return Err(ControlError::invalid("arm", "out of range"));
    }
    if reward.is_nan() {
        return Err(ControlError::invalid("reward", "must not be NaN"));
    }
    Ok(reward.clamp(0.0, 1.0))
}

/// UCB1 over per-arm pull counts and reward sums: the first untried arm, else the arm maximising
/// `mean + sqrt(2 ln N / n)`; ties go to the lowest index.
fn ucb_pick(pulls: &[u64], sums: &[f64]) -> usize {
    if let Some(untried) = pulls.iter().position(|&n| n == 0) {
        return untried;
    }
    let total = pulls.iter().sum::<u64>().max(1) as f64;
    let mut best = 0;
    let mut best_score = f64::NEG_INFINITY;
    for (arm, (&n, &sum)) in pulls.iter().zip(sums).enumerate() {
        let n = n as f64;
        let score = sum / n + (2.0 * total.ln() / n).sqrt();
        if score > best_score {
            best = arm;
            best_score = score;
        }
    }
    best
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

    fn select(&mut self, _rng: &mut dyn RandomSource) -> Result<usize> {
        Ok(ucb_pick(&self.pulls, &self.sums))
    }

    fn record(&mut self, arm: usize, reward: f64) -> Result<()> {
        let reward = checked_reward(arm, self.pulls.len(), reward)?;
        self.pulls[arm] += 1;
        self.sums[arm] += reward;
        Ok(())
    }
}

/// A standard normal variate (Box-Muller).
fn standard_normal(rng: &mut dyn RandomSource) -> f64 {
    let u1 = 1.0 - rng.unit_f64(); // (0, 1], so the logarithm is finite
    let u2 = rng.unit_f64();
    (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
}

/// A Gamma(shape, 1) variate (Marsaglia and Tsang, 2000); shapes below one use the `U^(1/shape)` boost.
fn gamma(shape: f64, rng: &mut dyn RandomSource) -> f64 {
    if shape < 1.0 {
        let u = 1.0 - rng.unit_f64();
        return gamma(shape + 1.0, rng) * u.powf(1.0 / shape);
    }
    let d = shape - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();
    loop {
        let x = standard_normal(rng);
        let v = 1.0 + c * x;
        if v <= 0.0 {
            continue;
        }
        let v = v * v * v;
        let u = 1.0 - rng.unit_f64();
        if u.ln() < 0.5 * x * x + d - d * v + d * v.ln() {
            return d * v;
        }
    }
}

/// A Beta(a, b) variate as `X / (X + Y)` of two gamma variates.
fn beta(a: f64, b: f64, rng: &mut dyn RandomSource) -> f64 {
    let x = gamma(a, rng);
    let y = gamma(b, rng);
    x / (x + y)
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

    /// The first untried arm (still at the prior), else the arm with the largest posterior draw. A
    /// fractional reward `r` counts as `r` successes and `1 - r` failures.
    fn select(&mut self, rng: &mut dyn RandomSource) -> Result<usize> {
        if let Some(untried) = self
            .successes
            .iter()
            .zip(&self.failures)
            .position(|(s, f)| s + f <= 2.0)
        {
            return Ok(untried);
        }
        let mut best = 0;
        let mut best_draw = f64::NEG_INFINITY;
        for arm in 0..self.successes.len() {
            let draw = beta(self.successes[arm], self.failures[arm], rng);
            if draw > best_draw {
                best = arm;
                best_draw = draw;
            }
        }
        Ok(best)
    }

    fn record(&mut self, arm: usize, reward: f64) -> Result<()> {
        let reward = checked_reward(arm, self.successes.len(), reward)?;
        self.successes[arm] += reward;
        self.failures[arm] += 1.0 - reward;
        Ok(())
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

    /// UCB1 over the window: an arm absent from the window counts as untried and is pulled again.
    fn select(&mut self, _rng: &mut dyn RandomSource) -> Result<usize> {
        let mut pulls = vec![0u64; self.arms];
        let mut sums = vec![0.0; self.arms];
        for &(arm, reward) in &self.history {
            pulls[arm] += 1;
            sums[arm] += reward;
        }
        Ok(ucb_pick(&pulls, &sums))
    }

    fn record(&mut self, arm: usize, reward: f64) -> Result<()> {
        let reward = checked_reward(arm, self.arms, reward)?;
        self.history.push_back((arm, reward));
        while self.history.len() > self.window {
            self.history.pop_front();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::SplitMix64;

    #[test]
    fn constructors_validate() {
        assert!(Ucb1::new(0).is_err());
        assert!(ThompsonBeta::new(0).is_err());
        assert!(SlidingWindowUcb::new(2, 0).is_err());
        assert_eq!(Ucb1::new(3).unwrap().arms(), 3);
    }

    /// Pull `steps` times; arm `i` pays `means[i](step)` exactly. Returns pulls per arm.
    fn run(
        selector: &mut dyn MirrorSelector,
        steps: usize,
        means: &dyn Fn(usize, usize) -> f64,
    ) -> Vec<usize> {
        let mut rng = SplitMix64::new(7);
        let mut pulls = vec![0; selector.arms()];
        for step in 0..steps {
            let arm = selector.select(&mut rng).unwrap();
            pulls[arm] += 1;
            selector.record(arm, means(arm, step)).unwrap();
        }
        pulls
    }

    #[test]
    fn untried_arms_go_first_and_rewards_are_validated() {
        let mut rng = SplitMix64::new(1);
        for selector in [
            &mut Ucb1::new(3).unwrap() as &mut dyn MirrorSelector,
            &mut ThompsonBeta::new(3).unwrap(),
            &mut SlidingWindowUcb::new(3, 10).unwrap(),
        ] {
            for expected in 0..3 {
                assert_eq!(selector.select(&mut rng).unwrap(), expected);
                selector.record(expected, 0.5).unwrap();
            }
            assert!(selector.record(3, 0.5).is_err());
            assert!(selector.record(0, f64::NAN).is_err());
            selector.record(0, 7.0).unwrap();
        }
    }

    #[test]
    fn ucb1_and_thompson_settle_on_the_better_mirror() {
        let means = |arm: usize, _: usize| if arm == 0 { 0.9 } else { 0.3 };
        let ucb = run(&mut Ucb1::new(2).unwrap(), 1000, &means);
        assert!(ucb[0] > 900, "{ucb:?}");
        let thompson = run(&mut ThompsonBeta::new(2).unwrap(), 1000, &means);
        assert!(thompson[0] > 900, "{thompson:?}");
    }

    #[test]
    fn the_sliding_window_abandons_a_mirror_that_degrades() {
        let mut selector = SlidingWindowUcb::new(2, 50).unwrap();
        // Mirror 0 is fast for 300 pulls, then collapses below mirror 1.
        let means = |arm: usize, step: usize| match (arm, step < 300) {
            (0, true) => 0.9,
            (0, false) => 0.05,
            _ => 0.5,
        };
        run(&mut selector, 300, &means);
        let mut rng = SplitMix64::new(3);
        let mut late = [0; 2];
        for step in 300..600 {
            let arm = selector.select(&mut rng).unwrap();
            late[arm] += 1;
            selector.record(arm, means(arm, step)).unwrap();
        }
        assert!(late[1] > 200, "{late:?}");
    }

    #[test]
    fn beta_draws_have_the_right_mean() {
        let mut rng = SplitMix64::new(11);
        for (a, b) in [(2.0, 5.0), (0.5, 0.5), (30.0, 10.0)] {
            let n = 20_000;
            let mean = (0..n).map(|_| beta(a, b, &mut rng)).sum::<f64>() / n as f64;
            assert!((mean - a / (a + b)).abs() < 0.01, "Beta({a}, {b}): {mean}");
        }
    }
}
