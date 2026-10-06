//! Small records shared by the file-system layer, the journal and the audit log.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::TypesError;
use crate::ids::ChainId;
use crate::units::Hex256;

/// Stable identity of an open file object, used to detect a replaced or swapped `.zpart`
/// (03 sections 3.1 and 7.2, checks L1 and L2). Numbers are decimal or hexadecimal *strings*
/// because inode numbers and 128-bit file indexes exceed the 2^53 JSON integer limit.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FileId {
    /// Unix: device and inode, decimal.
    Unix {
        /// `st_dev`.
        dev: String,
        /// `st_ino`.
        ino: String,
    },
    /// Windows: 64-bit volume serial (16 lowercase hex digits) and 128-bit file index (32 hex digits).
    Windows {
        /// Volume serial number.
        volume_serial: String,
        /// `FILE_ID_128`.
        file_index: String,
    },
}

impl FileId {
    /// A Unix file id.
    #[must_use]
    pub fn unix(dev: u64, ino: u64) -> Self {
        Self::Unix {
            dev: dev.to_string(),
            ino: ino.to_string(),
        }
    }

    /// A Windows file id from the volume serial and the 128-bit index.
    #[must_use]
    pub fn windows(volume_serial: u64, file_index: u128) -> Self {
        Self::Windows {
            volume_serial: format!("{volume_serial:016x}"),
            file_index: format!("{file_index:032x}"),
        }
    }

    /// Checks that the string members have the documented shape.
    pub fn validate(&self) -> Result<(), TypesError> {
        let dec = |s: &str| (1..=20).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
        let hex = |s: &str, n: usize| {
            s.len() == n
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        let ok = match self {
            Self::Unix { dev, ino } => dec(dev) && dec(ino),
            Self::Windows {
                volume_serial,
                file_index,
            } => hex(volume_serial, 16) && hex(file_index, 32),
        };
        if ok {
            Ok(())
        } else {
            Err(TypesError::Invalid("malformed file id"))
        }
    }
}

/// Which operating-system provenance attributes Zeus writes to downloaded files (04 section 6.1),
/// configured per write root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OsMetadataMode {
    /// Write nothing.
    Off,
    /// Only the mark that the file came from the internet: `Zone.Identifier` `ZoneId=3` on Windows,
    /// `com.apple.quarantine` on macOS, nothing on Linux. The default.
    #[default]
    MarkOnly,
    /// The mark plus redacted origin and referrer URLs (`ReferrerUrl`/`HostUrl`, `kMDItemWhereFroms`,
    /// `user.xdg.origin.url`/`user.xdg.referrer.url`).
    Full,
}

/// One attribute actually written to a file; recorded in the manifest and the `file.finalized`
/// audit record (04 sections 3.3 and 6).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum OsMetadataKind {
    /// NTFS alternate data stream `Zone.Identifier`.
    ZoneIdentifier,
    /// macOS `com.apple.quarantine` extended attribute.
    QuarantineXattr,
    /// macOS `com.apple.metadata:kMDItemWhereFroms`.
    WhereFroms,
    /// Linux `user.xdg.origin.url`.
    XdgOriginUrl,
    /// Linux `user.xdg.referrer.url`.
    XdgReferrerUrl,
}

/// The newest record of an audit chain: `(chain_id, seq, hash)` (04 section 2, "Head").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct AuditHead {
    /// Which chain.
    pub chain_id: ChainId,
    /// Sequence number of the newest record (1 or more).
    pub seq: u64,
    /// Its hash (BLAKE3 over `prev_hash || canonical record`).
    pub hash: Hex256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_example_round_trips() {
        let text = r#"{"kind":"unix","dev":"2049","ino":"5517423"}"#;
        let id: FileId = serde_json::from_str(text).unwrap();
        assert_eq!(id, FileId::unix(2049, 5_517_423));
        assert!(id.validate().is_ok());
        assert_eq!(serde_json::to_string(&id).unwrap(), text);
    }

    #[test]
    fn windows_ids_are_fixed_width_hex() {
        let id = FileId::windows(0x1234, 0xABCDEF);
        assert!(id.validate().is_ok());
        let FileId::Windows {
            volume_serial,
            file_index,
        } = &id
        else {
            unreachable!()
        };
        assert_eq!(volume_serial.len(), 16);
        assert_eq!(file_index.len(), 32);
        assert!(
            FileId::Windows {
                volume_serial: "1".into(),
                file_index: "2".into()
            }
            .validate()
            .is_err()
        );
    }
}
