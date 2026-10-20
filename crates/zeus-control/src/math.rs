//! Closed-form models used for planning and for explaining behaviour (research.md section 8).
//!
//! Every formula is documented with its assumptions in the implementation; the tests re-derive the
//! worked examples of research.md 8.10 and flag any discrepancy.
use crate::error::{ControlError, Result, finite};

fn positive(name: &'static str, value: f64) -> Result<f64> {
    if finite(name, value)? <= 0.0 {
        return Err(ControlError::invalid(name, "must be positive"));
    }
    Ok(value)
}

fn non_negative(name: &'static str, value: f64) -> Result<f64> {
    if finite(name, value)? < 0.0 {
        return Err(ControlError::invalid(name, "must not be negative"));
    }
    Ok(value)
}

/// Expected time to finish `work_s` seconds of uninterrupted work that restarts from its beginning after
/// each Poisson failure (rate `1 / mtbf_s`): `(e^(λT) - 1) / λ`, plus `restart_overhead_s` for each of the
/// `e^(λT) - 1` expected failures. Infinite when the exponent overflows.
fn restart_from_zero(work_s: f64, mtbf_s: f64, restart_overhead_s: f64) -> f64 {
    // One product, so an overflowed exponent stays infinite instead of becoming `inf * 0 = NaN`.
    (work_s / mtbf_s).exp_m1() * (mtbf_s + restart_overhead_s)
}

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
    let work = size_bytes as f64 / positive("rate_bps", rate_bps)?;
    Ok(restart_from_zero(
        work,
        positive("mtbf_s", mtbf_s)?,
        non_negative("restart_overhead_s", restart_overhead_s)?,
    ))
}

/// Expected completion time of a download that **resumes** at the last committed byte after each
/// failure. Only the uncommitted part of one commit interval `c` is lost, so the transfer is `T / c`
/// chunks that each restart from zero: `(T / c) * (e^(λc) - 1) / λ`, plus the restart overhead of each
/// expected failure (research.md 8.10). With `c >= T` this is the non-resumable case.
pub fn expected_time_with_resume(
    size_bytes: u64,
    rate_bps: f64,
    mtbf_s: f64,
    restart_overhead_s: f64,
    commit_interval_s: f64,
) -> Result<f64> {
    let work = size_bytes as f64 / positive("rate_bps", rate_bps)?;
    let mtbf = positive("mtbf_s", mtbf_s)?;
    let overhead = non_negative("restart_overhead_s", restart_overhead_s)?;
    let chunk = positive("commit_interval_s", commit_interval_s)?.min(work.max(f64::MIN_POSITIVE));
    if work == 0.0 {
        return Ok(0.0);
    }
    Ok(work / chunk * restart_from_zero(chunk, mtbf, overhead))
}

/// Young/Daly optimal commit interval `sqrt(2 * commit_cost_s * mtbf_s)`: the checkpoint spacing that
/// minimises lost work plus commit overhead (used to sanity-check `group_commit_ms`, 03 section 5.3).
pub fn young_daly_interval_s(commit_cost_s: f64, mtbf_s: f64) -> Result<f64> {
    Ok((2.0 * non_negative("commit_cost_s", commit_cost_s)? * positive("mtbf_s", mtbf_s)?).sqrt())
}

/// Probability that `n` independent attempts each succeeding with probability `p` all fail: `(1 - p)^n`.
pub fn all_attempts_fail_probability(p_success: f64, attempts: u32) -> Result<f64> {
    if !(0.0..=1.0).contains(&finite("p_success", p_success)?) {
        return Err(ControlError::invalid("p_success", "must be in [0, 1]"));
    }
    Ok((1.0 - p_success).powi(i32::try_from(attempts).unwrap_or(i32::MAX)))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: f64 = 3600.0;

    #[test]
    fn research_8_10_failure_example_is_reproduced() {
        // λ = 1/hour, T = 2 hours (7200 bytes at 1 B/s): restarting costs 6.39 h, resuming in 0.1 h
        // chunks 2.10 h.
        let restart = expected_time_without_resume(7200, 1.0, HOUR, 0.0).unwrap() / HOUR;
        assert!((restart - 6.389).abs() < 0.001, "{restart}");
        let resume = expected_time_with_resume(7200, 1.0, HOUR, 0.0, 0.1 * HOUR).unwrap() / HOUR;
        assert!((resume - 2.103).abs() < 0.001, "{resume}");
        // A commit interval longer than the transfer is the non-resumable case.
        let whole = expected_time_with_resume(7200, 1.0, HOUR, 0.0, 10.0 * HOUR).unwrap() / HOUR;
        assert!((whole - restart).abs() < 1e-9);
        // Restart overhead is paid once per expected failure (e^2 - 1 = 6.389 of them).
        let overhead = expected_time_without_resume(7200, 1.0, HOUR, 60.0).unwrap();
        assert!((overhead - restart * HOUR - 60.0 * 2f64.exp_m1()).abs() < 1e-6);
        assert_eq!(
            expected_time_with_resume(0, 1.0, HOUR, 5.0, 60.0).unwrap(),
            0.0
        );
        assert!(expected_time_without_resume(1, 0.0, HOUR, 0.0).is_err());
        assert!(
            expected_time_without_resume(1_000_000_000, 1.0, 1.0, 0.0)
                .unwrap()
                .is_infinite()
        );
    }

    #[test]
    fn young_daly_and_failure_probabilities() {
        assert!((young_daly_interval_s(1.0, 100.0).unwrap() - 200f64.sqrt()).abs() < 1e-12);
        assert!(young_daly_interval_s(1.0, 0.0).is_err());
        // research.md 8.9: per-try success 0.2 leaves 0.8^5 after five tries.
        assert!((all_attempts_fail_probability(0.2, 5).unwrap() - 0.327_68).abs() < 1e-12);
        assert_eq!(all_attempts_fail_probability(1.0, 3).unwrap(), 0.0);
        assert_eq!(all_attempts_fail_probability(0.5, 0).unwrap(), 1.0);
        assert!(all_attempts_fail_probability(1.5, 1).is_err());
    }
}
