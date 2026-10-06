//! File-system errors and their classification (01 section 8.3, stage A).

use std::io;

use zeus_types::{ErrorEnvelope, ToEnvelope, codes};

/// What went wrong at the operating-system level, in the vocabulary of the `fs.*` error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FsFault {
    /// `EACCES`, `EPERM`, `EROFS`, `ERROR_ACCESS_DENIED` (rule A1).
    PermissionDenied,
    /// `ENOSPC`, `ERROR_DISK_FULL`, `ERROR_HANDLE_DISK_FULL` (A2).
    NoSpace,
    /// `EDQUOT` (A3).
    QuotaExceeded,
    /// `EBUSY`, `ETXTBSY`, `ERROR_SHARING_VIOLATION`, `ERROR_LOCK_VIOLATION` (A4).
    Busy,
    /// `EIO`, `ERROR_CRC`, `ERROR_IO_DEVICE` (A5).
    Io,
    /// `ENAMETOOLONG`, `ERROR_FILENAME_EXCED_RANGE`: not an error but a request to shorten the name (A6).
    NameTooLong,
    /// `ENOENT` on the destination directory (A7).
    NotFound,
    /// `EMFILE`, `ENFILE`, `ERROR_TOO_MANY_OPEN_FILES` (A8).
    TooManyOpenFiles,
    /// Anything else.
    Other,
}

impl FsFault {
    /// The registered error code for the fault. `NameTooLong` maps to `fs.name_invalid` because that is
    /// what the job fails with if shortening the name does not help; callers shorten first.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::PermissionDenied => codes::FS_PERMISSION_DENIED,
            Self::NoSpace => codes::FS_NO_SPACE,
            Self::QuotaExceeded => codes::FS_QUOTA_EXCEEDED,
            Self::Busy => codes::FS_BUSY,
            Self::Io | Self::Other => codes::FS_IO_ERROR,
            Self::NameTooLong => codes::FS_NAME_INVALID,
            Self::NotFound => codes::FS_DEST_MISSING,
            Self::TooManyOpenFiles => codes::FS_TOO_MANY_OPEN_FILES,
        }
    }
}

/// Classifies an I/O error by the rules A1 to A8 of 01 section 8.3.
///
/// Uses [`io::ErrorKind`] first and the raw OS error for the cases the kind cannot express
/// (Windows `ERROR_*` numbers; Unix `errno` values, which coincide on Linux and macOS except
/// `EDQUOT` and `ENAMETOOLONG`).
#[must_use]
pub fn classify_io(err: &io::Error) -> FsFault {
    use io::ErrorKind as K;
    match err.kind() {
        K::PermissionDenied | K::ReadOnlyFilesystem => return FsFault::PermissionDenied,
        K::StorageFull => return FsFault::NoSpace,
        K::QuotaExceeded => return FsFault::QuotaExceeded,
        K::ResourceBusy | K::ExecutableFileBusy => return FsFault::Busy,
        K::InvalidFilename => return FsFault::NameTooLong,
        K::NotFound => return FsFault::NotFound,
        _ => {}
    }
    let Some(code) = err.raw_os_error() else {
        return FsFault::Other;
    };
    #[cfg(windows)]
    {
        match code {
            5 => FsFault::PermissionDenied, // ERROR_ACCESS_DENIED
            112 | 39 => FsFault::NoSpace,   // ERROR_DISK_FULL, ERROR_HANDLE_DISK_FULL
            32 | 33 => FsFault::Busy,       // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION
            23 | 1117 => FsFault::Io,       // ERROR_CRC, ERROR_IO_DEVICE
            206 => FsFault::NameTooLong,    // ERROR_FILENAME_EXCED_RANGE
            4 => FsFault::TooManyOpenFiles, // ERROR_TOO_MANY_OPEN_FILES
            _ => FsFault::Other,
        }
    }
    #[cfg(not(windows))]
    {
        #[cfg(target_os = "macos")]
        const EDQUOT: i32 = 69;
        #[cfg(not(target_os = "macos"))]
        const EDQUOT: i32 = 122;
        #[cfg(target_os = "macos")]
        const ENAMETOOLONG: i32 = 63;
        #[cfg(not(target_os = "macos"))]
        const ENAMETOOLONG: i32 = 36;
        match code {
            1 | 13 | 30 => FsFault::PermissionDenied, // EPERM, EACCES, EROFS
            28 => FsFault::NoSpace,                   // ENOSPC
            EDQUOT => FsFault::QuotaExceeded,
            16 | 26 => FsFault::Busy, // EBUSY, ETXTBSY
            5 => FsFault::Io,         // EIO
            ENAMETOOLONG => FsFault::NameTooLong,
            24 | 23 => FsFault::TooManyOpenFiles, // EMFILE, ENFILE
            _ => FsFault::Other,
        }
    }
}

/// Errors of this crate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FsError {
    /// A path resolved outside every write root (rule A9): traversal, absolute path, alternate data
    /// stream syntax, device path, or a symlink, junction or reparse point that leaves the root.
    #[error("path is outside the configured write roots")]
    OutsideRoots,
    /// A symlink or reparse point was found where a regular file or directory was required.
    #[error("refusing to follow a symlink or reparse point")]
    SymlinkRefused,
    /// A file name cannot be made usable even after sanitising and shortening.
    #[error("invalid file name: {0}")]
    InvalidName(&'static str),
    /// The destination already exists and the overwrite policy forbids replacing it.
    #[error("destination already exists")]
    AlreadyExists,
    /// The operation is not available on this platform or file system (for example no extended
    /// attributes on FAT); callers record it and continue.
    #[error("unsupported on this file system: {0}")]
    Unsupported(&'static str),
    /// An operating-system error, classified by [`classify_io`].
    #[error("{fault:?}: {source}")]
    Io {
        /// Classification.
        fault: FsFault,
        /// The underlying error. Its message may contain a path.
        #[source]
        source: io::Error,
    },
    /// The operation exists in the API but has no implementation yet.
    #[error("{0} is not implemented yet")]
    NotImplemented(&'static str),
}

/// Result alias.
pub type FsResult<T> = Result<T, FsError>;

impl From<io::Error> for FsError {
    fn from(source: io::Error) -> Self {
        Self::Io {
            fault: classify_io(&source),
            source,
        }
    }
}

impl ToEnvelope for FsError {
    fn to_envelope(&self) -> ErrorEnvelope {
        match self {
            Self::OutsideRoots | Self::SymlinkRefused => {
                ErrorEnvelope::from_code(codes::POLICY_PATH_OUTSIDE_ROOTS, self.to_string())
            }
            Self::InvalidName(_) => {
                ErrorEnvelope::from_code(codes::FS_NAME_INVALID, self.to_string())
            }
            Self::AlreadyExists => {
                ErrorEnvelope::from_code(codes::FS_PERMISSION_DENIED, self.to_string())
            }
            Self::Unsupported(_) => ErrorEnvelope::from_code(codes::FS_IO_ERROR, self.to_string()),
            // The OS message can contain a path; the code and class carry what callers need.
            Self::Io { fault, .. } => {
                ErrorEnvelope::from_code(fault.code(), format!("file system error: {fault:?}"))
            }
            Self::NotImplemented(_) => {
                ErrorEnvelope::from_code(codes::INTERNAL_BUG, self.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_by_kind() {
        let e = |k: io::ErrorKind| io::Error::new(k, "x");
        assert_eq!(
            classify_io(&e(io::ErrorKind::PermissionDenied)),
            FsFault::PermissionDenied
        );
        assert_eq!(
            classify_io(&e(io::ErrorKind::StorageFull)),
            FsFault::NoSpace
        );
        assert_eq!(
            classify_io(&e(io::ErrorKind::QuotaExceeded)),
            FsFault::QuotaExceeded
        );
        assert_eq!(classify_io(&e(io::ErrorKind::ResourceBusy)), FsFault::Busy);
        assert_eq!(
            classify_io(&e(io::ErrorKind::InvalidFilename)),
            FsFault::NameTooLong
        );
        assert_eq!(classify_io(&e(io::ErrorKind::NotFound)), FsFault::NotFound);
        assert_eq!(classify_io(&e(io::ErrorKind::Other)), FsFault::Other);
    }

    #[cfg(windows)]
    #[test]
    fn classifies_windows_error_numbers() {
        for (code, want) in [
            (5, FsFault::PermissionDenied),
            (112, FsFault::NoSpace),
            (39, FsFault::NoSpace),
            (32, FsFault::Busy),
            (33, FsFault::Busy),
            (23, FsFault::Io),
            (1117, FsFault::Io),
            (206, FsFault::NameTooLong),
            (4, FsFault::TooManyOpenFiles),
        ] {
            assert_eq!(
                classify_io(&io::Error::from_raw_os_error(code)),
                want,
                "{code}"
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn classifies_unix_errno() {
        for (code, want) in [
            (28, FsFault::NoSpace),
            (13, FsFault::PermissionDenied),
            (16, FsFault::Busy),
            (24, FsFault::TooManyOpenFiles),
            (5, FsFault::Io),
        ] {
            assert_eq!(
                classify_io(&io::Error::from_raw_os_error(code)),
                want,
                "{code}"
            );
        }
    }

    #[test]
    fn envelope_does_not_echo_the_os_message() {
        let err = FsError::from(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "C:\\Users\\ada\\secret-folder",
        ));
        let env = err.to_envelope();
        assert_eq!(env.code.as_str(), "fs.permission_denied");
        assert!(!env.message.contains("secret-folder"));
    }
}
