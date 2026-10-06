//! File name sanitising and collision handling (01 section 12.3, 03 section 3.2).
//!
//! Every name that reaches the file system passes through [`sanitize_filename`]. The rules are
//! deliberately the *union* of what Windows, macOS and Linux forbid, so a file downloaded on one
//! system can be copied to another and the manifest paths stay portable:
//!
//! * path separators and `..` removed; control characters, NUL, bidirectional overrides and
//!   zero-width characters removed;
//! * `< > : " | ? *` replaced by `_`; trailing dots and spaces removed;
//! * Windows device names (`CON PRN AUX NUL COM1`-`COM9` `LPT1`-`LPT9`, with or without an
//!   extension) prefixed with `_`;
//! * alternate-data-stream syntax (`name:stream`) neutralised;
//! * a name that is only dots becomes `download`;
//! * Unicode NFC; length limited to 255 UTF-8 bytes (and 255 UTF-16 units) preserving the extension.
#![expect(
    unused_variables,
    reason = "skeleton: bodies are filled in by the zeus-fs implementation task"
)]

use zeus_types::limits::MAX_FILE_NAME_BYTES;

use crate::error::{FsError, FsResult};

/// Why a name was changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SanitizeReason {
    /// A path separator or `..` was removed.
    PathSeparators,
    /// A control character, NUL, bidirectional override or zero-width character was removed.
    InvisibleCharacters,
    /// A character illegal on Windows was replaced.
    IllegalCharacters,
    /// Trailing dots or spaces were removed.
    TrailingDotsOrSpaces,
    /// A Windows device name was prefixed.
    ReservedDeviceName,
    /// Alternate data stream syntax was neutralised.
    StreamSyntax,
    /// The name consisted only of dots and became `download`.
    OnlyDots,
    /// The name was empty and a default was used.
    EmptyFallback,
    /// The name was normalised to Unicode NFC.
    Normalised,
    /// The name was shortened to the length limit.
    Truncated,
}

/// Options of [`sanitize_filename`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizeOptions {
    /// Longest result in UTF-8 bytes (default 255).
    pub max_bytes: usize,
    /// Name used when nothing usable remains.
    pub fallback: String,
}

impl Default for SanitizeOptions {
    fn default() -> Self {
        Self {
            max_bytes: MAX_FILE_NAME_BYTES,
            fallback: "download".to_owned(),
        }
    }
}

/// A sanitised name and what changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedName {
    /// The safe name: one path component, never empty.
    pub name: String,
    /// The reasons the input was altered; empty when it was already safe.
    pub reasons: Vec<SanitizeReason>,
}

impl SanitizedName {
    /// True when the input was altered.
    #[must_use]
    pub fn changed(&self) -> bool {
        !self.reasons.is_empty()
    }
}

/// Makes `raw` (untrusted text from a header, a URL or a hint) a safe single path component.
///
/// Fails with [`FsError::InvalidName`] only when nothing usable remains after every rule and the
/// fallback is itself unusable.
pub fn sanitize_filename(raw: &str, options: &SanitizeOptions) -> FsResult<SanitizedName> {
    Err(FsError::NotImplemented("sanitize_filename"))
}

/// How to pick a new name when the desired one is taken (03 section 3.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CollisionStrategy {
    /// `name (1).ext`, `name (2).ext`, ... before the extension. The default (`overwrite = rename`).
    #[default]
    Counter,
    /// `name~<4 hex of a hash of the original>.ext`, used when shortening a too-long name.
    HashSuffix,
}

/// Returns `desired` if `is_taken` says it is free, otherwise the first free variant under `strategy`.
/// When `case_insensitive` is true, two names that differ only in case count as the same name.
pub fn unique_name(
    desired: &str,
    is_taken: &dyn Fn(&str) -> bool,
    strategy: CollisionStrategy,
    case_insensitive: bool,
) -> FsResult<String> {
    Err(FsError::NotImplemented("unique_name"))
}

/// The key under which a path is reserved in the journal (`reservations` table, 03 section 3.2):
/// the normalised path, case-folded when the file system is case-insensitive.
#[must_use]
pub fn reservation_key(path: &str, case_insensitive: bool) -> String {
    if case_insensitive {
        path.to_lowercase()
    } else {
        path.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults() {
        let o = SanitizeOptions::default();
        assert_eq!(o.max_bytes, 255);
        assert_eq!(o.fallback, "download");
    }

    #[test]
    fn reservation_keys_fold_case_only_when_asked() {
        assert_eq!(
            reservation_key("C:\\Users\\Ada\\A.zip", true),
            "c:\\users\\ada\\a.zip"
        );
        assert_eq!(reservation_key("/home/Ada/A.zip", false), "/home/Ada/A.zip");
    }
}
