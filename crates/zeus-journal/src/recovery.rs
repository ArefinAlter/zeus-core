//! Recovery on startup (03 section 10) and the local resume checks (03 section 7.2).
//!
//! `zeusd` runs [`recover`] before accepting any connection. Every step is idempotent: a crash during
//! recovery followed by another recovery gives the same result (invariant I11). Hashing is never
//! performed during recovery; it happens later, in `verifying`.
#![expect(
    unused_variables,
    reason = "skeleton: recovery is filled in by the zeus-journal implementation task"
)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use zeus_control::RangeSet;
use zeus_fs::Filesystem;
use zeus_types::event::RecoverySummary;

use crate::error::{JournalError, JournalResult};
use crate::journal::Journal;
use crate::records::{InvalidationReason, JobRecord};

/// Inputs of startup recovery.
#[derive(Clone)]
pub struct RecoveryContext {
    /// The file system, injectable so recovery runs under the crash simulator.
    pub fs: Arc<dyn Filesystem>,
    /// Directories to scan for orphan `.zpart` files besides the directories of non-terminal jobs
    /// (the configured write roots).
    pub scan_roots: Vec<PathBuf>,
    /// Orphans older than this are deleted (default 7 days, minimum 1 hour); younger ones are reported.
    pub orphan_gc_age: Duration,
    /// Whether the audit chain tail verified (recovery step 6 reports it; the caller verifies).
    pub audit_chain_ok: bool,
}

impl std::fmt::Debug for RecoveryContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryContext")
            .field("scan_roots", &self.scan_roots)
            .finish_non_exhaustive()
    }
}

/// Runs steps 2 to 8 of 03 section 10 (step 1, opening the store, is `Journal::open`): migrate, apply
/// S95 or S96 to every in-flight job (`recovery_count` reaching 3 without committed progress is a crash
/// loop, `engine.crash_loop`), re-arm timers from stored instants, resolve interrupted finalizations
/// with the decision procedure of 03 section 8.2, normalise range sets (I4), collect orphan `.zpart`
/// files, expire grants and approvals, prune retention. Step 6 (outbox replay into the audit log and the
/// manifest) is driven by the daemon from the cursors in `meta`. Returns the summary for `daemon.started`.
pub fn recover(journal: &Journal, context: &RecoveryContext) -> JournalResult<RecoverySummary> {
    Err(JournalError::NotImplemented("recover"))
}

/// What the local checks of 03 section 7.2 concluded for one job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeAssessment {
    /// The committed ranges that survive the checks.
    pub trusted: RangeSet,
    /// The first failing check and the invalidation it requires, if any ranges were dropped.
    pub invalidated: Option<InvalidationReason>,
    /// Bytes dropped from the committed set.
    pub dropped_bytes: u64,
}

/// Local checks L1 to L4 before any request: the data file exists and is a regular file (L1), its
/// identity equals `zpart_file_id` (L2), its length covers the committed ranges (L3), and the CRC32C of
/// the last 16 units (`resume_recheck = tail`, continuing one unit earlier until 4 consecutive units pass)
/// or of every unit (`full`) matches the journal (L4). Returns what is still trusted; the caller commits
/// the invalidation and then probes.
pub fn assess_resume(
    fs: &dyn Filesystem,
    record: &JobRecord,
    journal: &Journal,
) -> JournalResult<ResumeAssessment> {
    Err(JournalError::NotImplemented("assess_resume"))
}

/// Default orphan garbage-collection age: 7 days.
pub const DEFAULT_ORPHAN_GC_AGE: Duration = Duration::from_secs(7 * 24 * 3600);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc_age_default_is_a_week() {
        assert_eq!(DEFAULT_ORPHAN_GC_AGE.as_secs(), 604_800);
    }
}
