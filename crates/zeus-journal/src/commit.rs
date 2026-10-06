//! The commit protocol's group-commit policy and round types (03 section 5).
//!
//! One commit **unit** is a contiguous run of bytes written by a job's writer; the daemon-wide
//! **committer** collects written units, syncs every touched data file (step C2), then commits one
//! journal transaction for the whole round (C3, C4). A range reaches the journal only after the bytes
//! it names were flushed: write, then `sync_data`, then commit. Any other order violates I1.
use std::time::Duration;

use zeus_types::{ByteRange, JobId};

use crate::error::{JournalError, JournalResult};

/// Tuning of the committer (03 section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitPolicy {
    /// The writer closes a unit at this size (default 4 MiB; 256 KiB to 32 MiB).
    pub commit_unit_bytes: u64,
    /// A round starts at most this long after the first written unit enters an empty queue
    /// (default 200 ms; 20 to 2000).
    pub group_commit: Duration,
    /// A round starts early when written, uncommitted bytes of all jobs reach this (default 32 MiB; 4 to 256 MiB).
    pub group_commit_bytes: u64,
    /// A job with data written and no new data for this long is flushed (default 1 s; 100 ms to 10 s).
    pub flush_idle: Duration,
    /// Per job, written-but-uncommitted bytes at which the writer stops accepting buffers, throttling
    /// the network to disk speed (default 64 MiB; 8 to 512 MiB).
    pub max_unacked_bytes: u64,
    /// Store a CRC32C per unit for the tail check (default true).
    pub unit_crc: bool,
}

impl Default for CommitPolicy {
    fn default() -> Self {
        Self {
            commit_unit_bytes: 4 << 20,
            group_commit: Duration::from_millis(200),
            group_commit_bytes: 32 << 20,
            flush_idle: Duration::from_secs(1),
            max_unacked_bytes: 64 << 20,
            unit_crc: true,
        }
    }
}

impl CommitPolicy {
    /// Checks every parameter against the bounds of 03 section 5.3.
    pub fn validate(&self) -> JournalResult<()> {
        const MIB: u64 = 1 << 20;
        let ok = (256 * 1024..=32 * MIB).contains(&self.commit_unit_bytes)
            && (Duration::from_millis(20)..=Duration::from_millis(2000))
                .contains(&self.group_commit)
            && (4 * MIB..=256 * MIB).contains(&self.group_commit_bytes)
            && (Duration::from_millis(100)..=Duration::from_secs(10)).contains(&self.flush_idle)
            && (8 * MIB..=512 * MIB).contains(&self.max_unacked_bytes);
        if ok {
            Ok(())
        } else {
            Err(JournalError::Invariant(
                "commit policy parameter outside its documented bounds",
            ))
        }
    }
}

/// A written unit waiting to be committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitUnit {
    /// The job.
    pub job_id: JobId,
    /// The bytes `[start, end)` that were written.
    pub range: ByteRange,
    /// The epoch of the attempt that produced them.
    pub epoch: u32,
    /// CRC32C of the bytes, when `unit_crc` is on.
    pub crc32c: Option<u32>,
}

/// What one committer round did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoundOutcome {
    /// Units now durable: acknowledge them (step C5).
    pub acknowledged: Vec<CommitUnit>,
    /// Units refused by the epoch fence (stale epoch or the job is not `downloading`, I5). Their bytes
    /// are never trusted.
    pub discarded: Vec<CommitUnit>,
    /// Jobs whose committed set became complete: transition S20 was performed in the same transaction.
    pub completed: Vec<JobId>,
}

/// Decides when a committer round starts (the pure part of the group-commit policy). Time is an
/// explicit monotonic argument so the policy is deterministic under test.
#[derive(Debug, Clone)]
pub struct CommitBatcher {
    policy: CommitPolicy,
    pending: Vec<CommitUnit>,
    pending_bytes: u64,
    first_pending_at: Option<Duration>,
}

impl CommitBatcher {
    /// A batcher with an empty queue.
    pub fn new(policy: CommitPolicy) -> JournalResult<Self> {
        policy.validate()?;
        Ok(Self {
            policy,
            pending: Vec::new(),
            pending_bytes: 0,
            first_pending_at: None,
        })
    }

    /// Queues a written unit at monotonic time `now`.
    pub fn push(&mut self, unit: CommitUnit, now: Duration) {
        self.pending_bytes += unit.range.len();
        self.first_pending_at.get_or_insert(now);
        self.pending.push(unit);
    }

    /// True when a round should start at `now`: the time or byte threshold was reached.
    #[must_use]
    pub fn should_flush(&self, now: Duration) -> bool {
        if self.pending.is_empty() {
            return false;
        }
        if self.pending_bytes >= self.policy.group_commit_bytes {
            return true;
        }
        self.first_pending_at
            .is_some_and(|first| now.saturating_sub(first) >= self.policy.group_commit)
    }

    /// Snapshots and clears the queue: the units of one round. Units written after this call wait for
    /// the next round (the snapshot is never extended, 03 section 5.2).
    pub fn take_round(&mut self) -> Vec<CommitUnit> {
        self.pending_bytes = 0;
        self.first_pending_at = None;
        std::mem::take(&mut self.pending)
    }

    /// Bytes written but not yet part of a round.
    #[must_use]
    pub const fn pending_bytes(&self) -> u64 {
        self.pending_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_within_bounds() {
        assert!(CommitPolicy::default().validate().is_ok());
        let bad = CommitPolicy {
            group_commit: Duration::from_millis(5),
            ..CommitPolicy::default()
        };
        assert!(bad.validate().is_err());
        let bad = CommitPolicy {
            max_unacked_bytes: 1 << 40,
            ..CommitPolicy::default()
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn rounds_start_on_time_or_bytes() {
        let policy = CommitPolicy::default();
        let mut b = CommitBatcher::new(policy).unwrap();
        let job = zeus_types::IdGenerator::new().job_id();
        let unit = |bytes: u64| CommitUnit {
            job_id: job,
            range: ByteRange::new(0, bytes).unwrap(),
            epoch: 1,
            crc32c: None,
        };
        assert!(!b.should_flush(Duration::from_secs(10)), "nothing pending");
        b.push(unit(4 << 20), Duration::from_millis(100));
        assert!(
            !b.should_flush(Duration::from_millis(299)),
            "200 ms have not passed since the first unit"
        );
        assert!(b.should_flush(Duration::from_millis(300)));
        let _ = b.take_round();
        b.push(unit(32 << 20), Duration::from_secs(1));
        assert!(
            b.should_flush(Duration::from_secs(1)),
            "the byte threshold starts a round at once"
        );
    }

    #[test]
    fn take_round_snapshots_and_clears() {
        let mut b = CommitBatcher::new(CommitPolicy::default()).unwrap();
        let job = zeus_types::IdGenerator::new().job_id();
        let unit = CommitUnit {
            job_id: job,
            range: ByteRange::new(0, 100).unwrap(),
            epoch: 1,
            crc32c: None,
        };
        b.push(unit, Duration::ZERO);
        b.push(unit, Duration::from_millis(5));
        assert_eq!(b.pending_bytes(), 200);
        assert_eq!(b.take_round().len(), 2);
        assert_eq!(b.pending_bytes(), 0);
        assert!(b.take_round().is_empty());
    }
}
