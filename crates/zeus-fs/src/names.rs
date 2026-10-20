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
    use unicode_normalization::UnicodeNormalization;
    let mut reasons = Vec::new();
    let normalized: String = raw.nfc().collect();
    if normalized != raw {
        reasons.push(SanitizeReason::Normalised);
    }
    let mut name = String::new();
    for c in normalized.chars() {
        if matches!(c, '/' | '\\') {
            reasons.push(SanitizeReason::PathSeparators);
        } else if c.is_control()
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')
        {
            reasons.push(SanitizeReason::InvisibleCharacters);
        } else if "<>:\"|?*".contains(c) {
            name.push('_');
            reasons.push(if c == ':' {
                SanitizeReason::StreamSyntax
            } else {
                SanitizeReason::IllegalCharacters
            });
        } else {
            name.push(c);
        }
    }
    if !name.is_empty() && name.chars().all(|c| c == '.') {
        name = "download".into();
        reasons.push(SanitizeReason::OnlyDots);
    }
    if name.contains("..") {
        name = name.replace("..", "_");
        reasons.push(SanitizeReason::PathSeparators);
    }
    let trimmed = name.trim_end_matches(['.', ' ']).to_string();
    if trimmed != name {
        reasons.push(SanitizeReason::TrailingDotsOrSpaces);
        name = trimmed;
    }
    if name.is_empty() {
        if options.fallback.is_empty() || options.fallback == raw {
            return Err(FsError::InvalidName("unusable fallback"));
        }
        let mut fallback = sanitize_filename(
            &options.fallback,
            &SanitizeOptions {
                fallback: String::new(),
                ..options.clone()
            },
        )?;
        fallback.reasons.push(SanitizeReason::EmptyFallback);
        return Ok(fallback);
    }
    let stem = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    if ["CON", "PRN", "AUX", "NUL"].contains(&stem.as_str())
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
    {
        name.insert(0, '_');
        reasons.push(SanitizeReason::ReservedDeviceName);
    }
    let max = options.max_bytes.min(255);
    if max == 0 {
        return Err(FsError::InvalidName("zero name length limit"));
    }
    if name.len() > max || name.encode_utf16().count() > 255 {
        let (stem, ext) = name
            .rsplit_once('.')
            .filter(|(_, ext)| ext.len() < max / 2)
            .map_or((name.as_str(), String::new()), |(s, e)| {
                (s, format!(".{e}"))
            });
        let mut shortened = stem.to_string();
        while shortened.len() + ext.len() > max
            || shortened.encode_utf16().count() + ext.encode_utf16().count() > 255
        {
            shortened.pop();
        }
        name = shortened + &ext;
        reasons.push(SanitizeReason::Truncated);
    }
    if name.is_empty() {
        return Err(FsError::InvalidName("name limit is too small"));
    }
    reasons.dedup();
    Ok(SanitizedName { name, reasons })
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
    let desired = sanitize_filename(desired, &SanitizeOptions::default())?.name;
    let taken = |n: &str| is_taken(n) || (case_insensitive && is_taken(&n.to_lowercase()));
    if !taken(&desired) {
        return Ok(desired);
    }
    let (stem, ext) = desired
        .rsplit_once('.')
        .map_or((desired.as_str(), String::new()), |(s, e)| {
            (s, format!(".{e}"))
        });
    for n in 1..=100_000u32 {
        let suffix = match strategy {
            CollisionStrategy::Counter => format!(" ({n})"),
            CollisionStrategy::HashSuffix => {
                use std::hash::{Hash, Hasher};
                let mut hash = std::collections::hash_map::DefaultHasher::new();
                desired.hash(&mut hash);
                if n == 1 {
                    format!("~{:04x}", hash.finish() & 0xffff)
                } else {
                    format!("~{:04x} ({n})", hash.finish() & 0xffff)
                }
            }
        };
        let mut shortened = stem.to_string();
        while shortened.len() + suffix.len() + ext.len() > 255 {
            shortened.pop();
        }
        let candidate = format!("{shortened}{suffix}{ext}");
        if !taken(&candidate) {
            return Ok(candidate);
        }
    }
    Err(FsError::AlreadyExists)
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
