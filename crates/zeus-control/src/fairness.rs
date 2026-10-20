//! Sharing capacity across jobs: weighted fair queueing and max-min fairness (research.md section 8.6).
//!
//! Job priorities map to weights 1, 2 and 4 (01 section 3.2). The scheduler uses [`Wfq`] to pick the
//! next job for a free slot and [`max_min_fair`] to divide a bandwidth budget.
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
        if weight == 0 || !cost.is_finite() || cost <= 0.0 {
            return Err(ControlError::invalid(
                "weight/cost",
                "must be positive and finite",
            ));
        }
        let prior = self
            .queue
            .iter()
            .filter(|(k, _)| *k == key)
            .map(|(_, finish)| *finish)
            .fold(self.virtual_time, f64::max);
        let finish = prior + cost / f64::from(weight);
        if !finish.is_finite() {
            return Err(ControlError::invalid("cost", "virtual clock overflow"));
        }
        self.queue.push((key, finish));
        Ok(())
    }

    /// Removes and returns the next key, or `None` when empty.
    pub fn dequeue(&mut self) -> Result<Option<u64>> {
        let Some(index) = self
            .queue
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.1.total_cmp(&b.1))
            .map(|(i, _)| i)
        else {
            return Ok(None);
        };
        let (key, finish) = self.queue.remove(index);
        self.virtual_time = finish;
        Ok(Some(key))
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
    if !capacity.is_finite() || capacity < 0.0 || demands.iter().any(|d| !d.is_finite() || *d < 0.0)
    {
        return Err(ControlError::invalid(
            "capacity/demands",
            "must be finite and nonnegative",
        ));
    }
    let mut order: Vec<_> = (0..demands.len()).collect();
    order.sort_by(|a, b| demands[*a].total_cmp(&demands[*b]));
    let mut allocations = vec![0.0; demands.len()];
    let mut remaining = capacity;
    for (rank, index) in order.into_iter().enumerate() {
        let share = remaining / (demands.len() - rank) as f64;
        let amount = demands[index].min(share);
        allocations[index] = amount;
        remaining = (remaining - amount).max(0.0);
    }
    Ok(allocations)
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

#[cfg(test)]
mod runtime_tests {
    use super::*;
    #[test]
    fn unused_share_goes_to_unsatisfied_consumers() {
        assert_eq!(
            max_min_fair(10.0, &[1.0, 100.0, 100.0]).unwrap(),
            vec![1.0, 4.5, 4.5]
        );
        assert_eq!(max_min_fair(100.0, &[1.0, 2.0]).unwrap(), vec![1.0, 2.0]);
        assert!(max_min_fair(1.0, &[-1.0]).is_err());
    }
    #[test]
    fn weighted_finish_times_are_stable_and_per_flow() {
        let mut queue = Wfq::new();
        queue.enqueue(1, 1, 4.0).unwrap();
        queue.enqueue(2, 4, 4.0).unwrap();
        queue.enqueue(2, 4, 4.0).unwrap();
        assert_eq!(queue.dequeue().unwrap(), Some(2));
        assert_eq!(queue.dequeue().unwrap(), Some(2));
        assert_eq!(queue.dequeue().unwrap(), Some(1));
        assert_eq!(queue.dequeue().unwrap(), None);
    }
}
