//! Sharing capacity across jobs: weighted fair queueing and max-min fairness (research.md section 8.6).
//!
//! Job priorities map to weights 1, 2 and 4 (01 section 3.2). The scheduler uses [`Wfq`] to pick the
//! next job for a free slot and [`max_min_fair`] to divide a bandwidth budget.
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: bodies are filled in by the zeus-control implementation task"
)]

use zeus_types::Priority;

use crate::error::{ControlError, Result};

/// Weighted fair queueing weight of a priority class: 1, 2 or 4.
#[must_use]
pub const fn weight(priority: Priority) -> u32 {
    priority.weight()
}

/// Weighted fair queue over opaque job keys. Each enqueued job carries a weight and a cost (for
/// example expected bytes); the queue serves the smallest virtual finish time first, so over time each
/// weight class receives service proportional to its weight and no class starves.
#[derive(Debug, Clone, Default)]
pub struct Wfq {
    virtual_time: f64,
    queue: Vec<(u64, f64)>,
}

impl Wfq {
    /// An empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `key` with the given weight (at least 1) and cost (positive, finite).
    pub fn enqueue(&mut self, key: u64, weight: u32, cost: f64) -> Result<()> {
        Err(ControlError::NotImplemented("Wfq::enqueue"))
    }

    /// Removes and returns the next key, or `None` when empty.
    pub fn dequeue(&mut self) -> Result<Option<u64>> {
        Err(ControlError::NotImplemented("Wfq::dequeue"))
    }

    /// Number of queued jobs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// True when nothing is queued.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Max-min fair allocation of `capacity` across `demands`: no consumer gets more than it asked for,
/// and unused share is redistributed equally among the unsatisfied. The result has one entry per demand.
pub fn max_min_fair(capacity: f64, demands: &[f64]) -> Result<Vec<f64>> {
    Err(ControlError::NotImplemented("max_min_fair"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weights_follow_the_specification() {
        assert_eq!(
            (
                weight(Priority::Low),
                weight(Priority::Normal),
                weight(Priority::High)
            ),
            (1, 2, 4)
        );
        assert!(Wfq::new().is_empty());
    }
}
