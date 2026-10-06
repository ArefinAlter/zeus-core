//! Crash-point injection for the commit protocol (03 sections 9 and 12.3).
//!
//! The engine and the journal call [`FaultInjector::hit`] at every protocol step. Production code uses
//! [`NoFaults`]; the deterministic simulation runs a job `N` times, crashing after call `k` for every
//! `k`, then recovers and asserts invariants I1 to I12.

use std::fmt;

use crate::error::{JournalError, JournalResult};

/// A protocol step at which a crash can be injected. Names follow 03: `W*` and `C*` are the steps of
/// one commit unit (section 5.2), `F*` the steps of finalization (section 8.1), `D*` crash points.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum CrashPoint {
    /// Bytes received, not yet written (D1).
    BeforeWrite,
    /// After `pwrite`, before `sync_data` (D2).
    AfterWriteBeforeSync,
    /// After `sync_data`, before the journal commit (D3).
    AfterSyncBeforeCommit,
    /// Inside the journal commit (D4).
    DuringCommit,
    /// After the commit, before the acknowledgement (D5).
    AfterCommitBeforeAck,
    /// Data file created, `zpart_file_id` not yet stored (D6).
    DataFileCreated,
    /// During the S20 transaction (D7).
    DuringCompletionTransaction,
    /// During restart from zero: journal cleared, file not yet truncated (D8).
    RestartJournalClearedFileNot,
    /// Verification finished, S70 not yet committed (F0).
    BeforeVerifyCommit,
    /// Marks applied, before `sync_all` (F1 to F2).
    AfterMarksBeforeSync,
    /// After `sync_all`, before the `intent` commit (F2 to F3).
    BeforeFinalizeIntent,
    /// `intent` committed, before the rename (F3 to F4).
    AfterIntentBeforeRename,
    /// Rename done, before the directory sync (F4 to F5).
    AfterRenameBeforeDirSync,
    /// Directory synced, before the S80 commit (F5 to F6).
    BeforeCompletionCommit,
    /// S80 committed, before the outbox side effects (F6 to F7).
    AfterCompletionBeforeOutbox,
    /// Inside startup recovery.
    DuringRecovery,
}

/// The error type carried by an injected crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InjectedCrash(pub CrashPoint);

impl fmt::Display for InjectedCrash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "injected crash at {:?}", self.0)
    }
}

/// Decides whether to crash at a protocol step.
pub trait FaultInjector: Send + Sync + fmt::Debug {
    /// Called at `point`. Returning an error aborts the operation as if the process had died there
    /// (the caller drops all in-memory state and the test then runs recovery).
    fn hit(&self, point: CrashPoint) -> Result<(), InjectedCrash>;
}

/// The production injector: never crashes.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoFaults;

impl FaultInjector for NoFaults {
    fn hit(&self, _point: CrashPoint) -> Result<(), InjectedCrash> {
        Ok(())
    }
}

/// Converts an injected crash into a [`JournalError`].
pub fn check(injector: &dyn FaultInjector, point: CrashPoint) -> JournalResult<()> {
    injector
        .hit(point)
        .map_err(|InjectedCrash(p)| JournalError::InjectedCrash(p))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    /// Crashes on the `n`-th call, whatever the point.
    #[derive(Debug)]
    struct CrashOnNth {
        n: u32,
        calls: AtomicU32,
    }

    impl FaultInjector for CrashOnNth {
        fn hit(&self, point: CrashPoint) -> Result<(), InjectedCrash> {
            if self.calls.fetch_add(1, Ordering::SeqCst) + 1 == self.n {
                Err(InjectedCrash(point))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn injector_trait_is_usable_through_check() {
        assert!(check(&NoFaults, CrashPoint::DuringCommit).is_ok());
        let inj = CrashOnNth {
            n: 2,
            calls: AtomicU32::new(0),
        };
        assert!(check(&inj, CrashPoint::BeforeWrite).is_ok());
        assert!(matches!(
            check(&inj, CrashPoint::DuringCommit),
            Err(JournalError::InjectedCrash(CrashPoint::DuringCommit))
        ));
        assert!(check(&inj, CrashPoint::DuringRecovery).is_ok());
    }
}
