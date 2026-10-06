//! Closed-form models used for planning and for explaining behaviour (research.md section 8).
//!
//! Every formula is documented with its assumptions in the implementation; the tests re-derive the
//! worked examples of research.md 8.10 and flag any discrepancy.
#![expect(
    unused_variables,
    reason = "skeleton: bodies are filled in by the zeus-control implementation task"
)]

use crate::error::{ControlError, Result};

/// Expected completion time of a download that is **restarted from zero** after each failure.
///
/// `size_bytes` at `rate_bps` takes `T = size / rate`; failures arrive as a Poisson process with mean
/// time between failures `mtbf_s`. The expected total time is `mtbf * (exp(T / mtbf) - 1)` seconds
/// (plus `restart_overhead_s` per failure).
pub fn expected_time_without_resume(
    size_bytes: u64,
    rate_bps: f64,
    mtbf_s: f64,
    restart_overhead_s: f64,
) -> Result<f64> {
    Err(ControlError::NotImplemented("expected_time_without_resume"))
}

/// Expected completion time of a download that **resumes** at the last committed byte after each
/// failure: `T + failures * (restart_overhead + lost_work)`, with `failures = T / mtbf` and
/// `lost_work` bounded by the commit interval.
pub fn expected_time_with_resume(
    size_bytes: u64,
    rate_bps: f64,
    mtbf_s: f64,
    restart_overhead_s: f64,
    commit_interval_s: f64,
) -> Result<f64> {
    Err(ControlError::NotImplemented("expected_time_with_resume"))
}

/// Young/Daly optimal commit interval `sqrt(2 * commit_cost_s * mtbf_s)`: the checkpoint spacing that
/// minimises lost work plus commit overhead (used to sanity-check `group_commit_ms`, 03 section 5.3).
pub fn young_daly_interval_s(commit_cost_s: f64, mtbf_s: f64) -> Result<f64> {
    Err(ControlError::NotImplemented("young_daly_interval_s"))
}

/// Probability that `n` independent attempts each succeeding with probability `p` all fail: `(1 - p)^n`.
pub fn all_attempts_fail_probability(p_success: f64, attempts: u32) -> Result<f64> {
    Err(ControlError::NotImplemented(
        "all_attempts_fail_probability",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skeleton_returns_typed_errors_not_panics() {
        assert!(matches!(
            young_daly_interval_s(1.0, 100.0),
            Err(ControlError::NotImplemented(_))
        ));
    }
}
