//! The durable transfer journal and commit protocol (03).
//!
//! A download is worth more than the bytes already on disk only if the engine can prove which bytes are
//! right. This crate defines the records ([`records`]), the backend-neutral store traits ([`store`]),
//! the group-commit policy ([`commit`]), the redb backend ([`redb_store`]), crash-point injection
//! ([`fault`]), recovery ([`recovery`]) and the [`Journal`] facade the engine uses.
//!
//! The ordering rule that everything else serves: **a range is written to the journal only after the
//! bytes it names were flushed to stable storage** (write, `sync_data`, then commit). Only the journal
//! is evidence of progress; file length, preallocation and mtime never are (invariant I2).

#![forbid(unsafe_code)]

pub mod commit;
pub mod error;
pub mod fault;
pub mod journal;
pub mod records;
pub mod recovery;
pub mod redb_store;
pub mod store;

pub use commit::{CommitBatcher, CommitPolicy, CommitUnit, RoundOutcome};
pub use error::{JournalError, JournalResult};
pub use fault::{CrashPoint, FaultInjector, NoFaults};
pub use journal::{Journal, JournalOptions, TransitionOutcome, TransitionRequest};
pub use records::{
    FinalizePhase, FinalizeState, IdempotencyRow, InvalidationReason, InvalidationRow, JobInternal,
    JobRecord, Meta, RangeRow, ReservationRow, ResumeRecheck, SCHEMA_VERSION, UnitCrcRow,
    VerifyResult,
};
pub use store::{JobFilter, JournalStore, ReadTxn, WriteTxn};
