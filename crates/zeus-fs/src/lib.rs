//! File-system correctness primitives for Zeus.
//!
//! * [`names`]: sanitising untrusted file names and picking unique ones.
//! * [`root`]: write roots and checked path containment.
//! * [`directory`]: retained directory capabilities for opted-in local file operations.
//! * [`fs`]: the [`Filesystem`] / [`DataFile`] seam of the commit protocol (positional writes,
//!   `sync_data`, no-replace rename), with a [`RealFs`] implementation and room for a crash-simulating one.
//! * [`finalize`]: the rename half of finalization and its crash decision procedure.
//! * [`provenance`]: Mark-of-the-Web and origin attributes.
//! * [`trash`]: the application trash with an undo journal.
//! * [`cloud`]: cloud-folder detection.
//!
//! Platform FFI (Windows file ids and ADS, `renameat2`, `F_FULLFSYNC`) lives in a private `sys` module
//! (the only place `unsafe` is allowed). Everything else is safe
//! Rust: `unsafe_code` is denied crate-wide.

#![deny(unsafe_code)]

pub mod cloud;
pub mod directory;
pub mod error;
pub mod finalize;
pub mod fs;
pub mod names;
pub mod provenance;
pub mod root;
pub mod retained;
pub mod trash;

pub use directory::{DirectoryCap, RenameSource, opened_file_metadata};
pub use error::{FsError, FsFault, FsResult, classify_io};
pub use fs::{
    DataFile, DirEntryInfo, FileMeta, Filesystem, PreallocOutcome, RealFs, ZPART_SUFFIX, zpart_path,
};
pub use names::{
    CollisionStrategy, SanitizeOptions, SanitizeReason, SanitizedName, sanitize_filename,
    unique_name,
};
pub use root::{SafeRoot, WriteRoots};
pub use retained::RetainedFs;

#[cfg(windows)]
mod sys;
