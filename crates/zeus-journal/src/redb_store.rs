//! The redb backend (03 section 4).
//!
//! Tables: `meta`, `jobs`, `ranges` (key `(job_id, start)`, value `(end, epoch)`), `unit_crc`,
//! `invalidations`, `reservations`, `events` (key `seq`), `grants`, `approvals`, `idempotency`. Rows
//! holding JSON use `serde_json`; fixed-layout tables use redb's native integer and tuple encodings.
//!
//! redb 4.x facts the design relies on (verified against redb 4.3.0 on docs.rs, 2026-10-05):
//! `Durability` has exactly `Immediate` (the default) and `None`; `commit` returns `Result<(), CommitError>`
//! and on errors other than `TransactionPoisoned` the changes are atomic but may already be persisted;
//! opening an already-open database fails with `DatabaseAlreadyOpen`; there is one write transaction at a
//! time and any number of read transactions.
#![expect(
    unused_variables,
    reason = "skeleton: RedbStore is filled in by the zeus-journal implementation task"
)]

use std::path::{Path, PathBuf};

use redb::Durability;

use crate::error::{JournalError, JournalResult};
use crate::journal::JournalOptions;
use crate::store::{JournalStore, ReadTxn, WriteTxn};

/// The only durability level ever used for a transaction that carries range rows, job state, events,
/// grants or approvals (03 section 5.4). `Durability::None` is forbidden for them: a later `Immediate`
/// commit would persist those rows without any guarantee that the data they name was synced.
#[must_use]
pub const fn required_durability() -> Durability {
    Durability::Immediate
}

/// The redb-backed store at `<state>/zeus.redb`.
#[derive(Debug)]
pub struct RedbStore {
    path: PathBuf,
}

impl RedbStore {
    /// Opens or creates the database, applying `options` (`set_quick_repair`, `set_two_phase_commit`),
    /// checking `meta.schema_version` (a newer version is refused with `journal.version_unsupported`,
    /// an older one is migrated forward after copying the file to `zeus.redb.v<old>.bak`), and mapping
    /// `DatabaseAlreadyOpen` to `journal.already_open`. On unrepairable corruption the file is moved to
    /// `zeus.redb.corrupt-<ts>` and reported as `journal.corrupt` (03 section 10 step 1).
    pub fn open(path: &Path, options: &JournalOptions) -> JournalResult<Self> {
        Err(JournalError::NotImplemented("RedbStore::open"))
    }

    /// The database path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Compacts the file when it exceeds twice the live data (03 section 13); verify the compaction API
    /// of the pinned redb version.
    pub fn compact_if_needed(&self) -> JournalResult<bool> {
        Err(JournalError::NotImplemented("RedbStore::compact_if_needed"))
    }
}

impl JournalStore for RedbStore {
    fn begin_write(&self) -> JournalResult<Box<dyn WriteTxn + '_>> {
        Err(JournalError::NotImplemented("RedbStore::begin_write"))
    }

    fn begin_read(&self) -> JournalResult<Box<dyn ReadTxn + '_>> {
        Err(JournalError::NotImplemented("RedbStore::begin_read"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_commits_are_always_immediate() {
        assert!(matches!(required_durability(), Durability::Immediate));
    }
}
