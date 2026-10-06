//! Quarantine rules (01 section 11.3): Zeus's own flag, stronger than the operating system's
//! Mark-of-the-Web, decided during verification (transition S70) and stored with the job.
//!
//! A quarantined file is still placed at its final path; the flag is exposed in every API and event;
//! Zeus never opens, executes or converts it automatically, and any Zeus operation that opens,
//! converts, moves out of its directory or deletes it needs an approval.
#![expect(
    unused_variables,
    reason = "skeleton: evaluate is filled in by the zeus-verify implementation task"
)]

use zeus_types::{Origin, QuarantineReason};

use crate::content::{ContentVerdict, DetectedType};
use crate::error::{VerifyError, VerifyResult};

/// Optional rules and trust lists (configuration).
#[derive(Debug, Clone, Default)]
pub struct QuarantinePolicy {
    /// Quarantine files from origins not on `trusted_origins` (`quarantine_untrusted`, default off).
    pub quarantine_untrusted: bool,
    /// Quarantine files retrieved with a session lease (`quarantine_session_files`, default off).
    pub quarantine_session_files: bool,
    /// Origins the user trusts.
    pub trusted_origins: Vec<Origin>,
}

/// What is known about a verified file.
#[derive(Debug, Clone)]
pub struct QuarantineInput<'a> {
    /// The stored file name.
    pub file_name: &'a str,
    /// Result of the content check.
    pub verdict: ContentVerdict,
    /// What the magic bytes say.
    pub detected: Option<&'a DetectedType>,
    /// The origin the bytes came from.
    pub origin: Option<&'a Origin>,
    /// A session lease was used.
    pub session_derived: bool,
    /// The optional antivirus hook reported the file as not clean.
    pub av_flagged: bool,
}

/// Returns every rule that fires (empty when the file is not quarantined). Rules: `executable_type`,
/// `mime_mismatch`, `html_disguised`, `archive_limits` (set by the archive guard, not here),
/// `av_flagged`, `untrusted_origin`, `session_derived`.
pub fn evaluate(
    input: &QuarantineInput<'_>,
    policy: &QuarantinePolicy,
) -> VerifyResult<Vec<QuarantineReason>> {
    Err(VerifyError::NotImplemented("quarantine::evaluate"))
}

/// Extensions that identify executable, script, installer or shortcut files regardless of content
/// (01 section 11.3, `executable_type`).
pub const EXECUTABLE_EXTENSIONS: &[&str] = &[
    "exe", "dll", "scr", "msi", "pkg", "dmg", "appimage", "jar", "lnk", "ps1", "bat", "cmd", "sh",
    "js", "vbs", "wsf",
];

/// True when the last extension of `file_name` is on [`EXECUTABLE_EXTENSIONS`]. A double extension
/// such as `invoice.pdf.exe` is detected by looking at the last one only.
#[must_use]
pub fn has_executable_extension(file_name: &str) -> bool {
    file_name
        .rsplit_once('.')
        .is_some_and(|(_, ext)| EXECUTABLE_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_extensions_are_judged_by_the_last_one() {
        assert!(has_executable_extension("invoice.pdf.exe"));
        assert!(has_executable_extension("Setup.MSI"));
        assert!(!has_executable_extension("report.pdf"));
        assert!(!has_executable_extension("exe"));
        assert!(!has_executable_extension("notes.exe.txt"));
    }
}
