//! Bounded, uncompressed artifact bundles. This is a data container, never an extractable filesystem.
//! Only canonical manifest JSON followed by digest-addressed bytes is accepted. No links, directories,
//! executable metadata, alternate member names or compression exist in this format.
use crate::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
};
use zeus_types::{ArtifactId, Hex256, StoreId};
use zeus_verify::{canonical::to_jcs_bytes, hash::hash_bytes};

const MAGIC: &[u8; 8] = b"ZEUSAB1\n";
/// The compressed and expanded limit are equal: compression is deliberately unsupported.
pub const BUNDLE_MAX_BYTES: usize = 32 * 1024 * 1024;
/// A single portable record keeps the specification's256KiB bound.
pub const BUNDLE_MAX_RECORDS: usize = 64;
const MAX_MANIFEST: usize = 4 * 1024 * 1024;
const MAX_OBJECT: u64 = 16 * 1024 * 1024;

/// A member is exactly `objects/<lowercase BLAKE3>`; it cannot describe a link or filesystem path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleObject {
    /// Strict logical member name.
    pub name: String,
    /// BLAKE3 identity.
    pub blake3: Hex256,
    /// Interoperability digest.
    pub sha256: Hex256,
    /// Exact member byte count.
    pub size_bytes: u64,
}
/// Versioned bundle manifest. Records use the privacy-reduced portable export form.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    /// Bundle format1.
    pub version: u32,
    /// The exporting product, distinct from the original producer.
    pub exporter: String,
    /// Exact source records, including any original unknown fields as import evidence.
    pub records: Vec<serde_json::Value>,
    /// Unique digest members, in their byte-stream order.
    pub objects: Vec<BundleObject>,
}
/// Safe public facts to bind to an exact preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleSummary {
    /// BLAKE3 of all container bytes, including framing.
    pub bundle_blake3: Hex256,
    /// SHA-256 of all container bytes.
    pub bundle_sha256: Hex256,
    /// Exact container length.
    pub size_bytes: u64,
    /// BLAKE3 of canonical manifest JSON.
    pub manifest_blake3: Hex256,
    /// Source store/record identities; never grants of local ownership.
    pub records: Vec<(StoreId, ArtifactId)>,
    /// Exact immutable members.
    pub objects: Vec<BundleObject>,
}
/// Fully validated bytes. Construction verifies every record, member and content digest before effects.
pub struct ArtifactBundle {
    pub(crate) manifest: BundleManifest,
    pub(crate) bytes: Vec<u8>,
    pub(crate) ranges: BTreeMap<Hex256, std::ops::Range<usize>>,
    summary: BundleSummary,
}
fn invalid() -> ArtifactError {
    ArtifactError::RecordInvalid("invalid or unsupported artifact bundle")
}
impl ArtifactBundle {
    /// Read with an enforced total bound, including for a growing file or untrusted stream.
    pub fn read(reader: impl Read) -> Result<Self> {
        let mut bytes = Vec::new();
        reader
            .take((BUNDLE_MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        Self::parse(bytes)
    }
    /// Decode exactly one uncompressed version1 bundle; trailing bytes and noncanonical JSON fail.
    pub fn parse(bytes: Vec<u8>) -> Result<Self> {
        if bytes.len() > BUNDLE_MAX_BYTES || bytes.len() < 12 || &bytes[..8] != MAGIC {
            return Err(invalid());
        }
        let len = u32::from_le_bytes(bytes[8..12].try_into().map_err(|_| invalid())?) as usize;
        if len > MAX_MANIFEST || 12 + len > bytes.len() {
            return Err(invalid());
        }
        let raw = &bytes[12..12 + len];
        let manifest: BundleManifest = serde_json::from_slice(raw)?;
        if manifest.version != 1
            || manifest.records.is_empty()
            || manifest.records.len() > BUNDLE_MAX_RECORDS
            || manifest.objects.len() > BUNDLE_MAX_RECORDS
            || to_jcs_bytes(&manifest)? != raw
            || manifest.exporter.is_empty()
            || manifest.exporter.len() > 64
            || !manifest
                .exporter
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        {
            return Err(invalid());
        }
        let mut identities = BTreeSet::new();
        let mut expected = BTreeMap::new();
        let mut records = Vec::new();
        for value in &manifest.records {
            let encoded = to_jcs_bytes(value)?;
            if encoded.len() > 256 * 1024 || encoded.windows(12).any(|w| w == b"ZEUS-CANARY-") {
                return Err(invalid());
            }
            let record: Artifact = serde_json::from_value(value.clone())?;
            record.validate()?;
            // Import never resurrects a tombstone. Metadata-only exports of active absent records work.
            if record.state != ArtifactState::Active
                || record.imports.len() >= 8
                || !identities.insert((record.store_id, record.id))
            {
                return Err(invalid());
            }
            let triple = (record.sha256, record.size_bytes);
            if expected
                .insert(record.blake3, triple)
                .is_some_and(|old| old != triple)
            {
                return Err(ArtifactError::DigestMismatch);
            }
            records.push((record.store_id, record.id));
        }
        let parsed: Vec<Artifact> = manifest
            .records
            .iter()
            .map(|v| serde_json::from_value(v.clone()))
            .collect::<std::result::Result<_, _>>()?;
        let quarantined: BTreeSet<_> = parsed
            .iter()
            .filter(|r| r.quarantined)
            .map(|r| r.blake3)
            .collect();
        if parsed.iter().any(|r| {
            !r.quarantined
                && (quarantined.contains(&r.blake3)
                    || r.parents.iter().any(|p| quarantined.contains(&p.blake3)))
        }) {
            return Err(ArtifactError::QuarantineBlocked);
        }
        let mut offset = 12 + len;
        let mut ranges = BTreeMap::new();
        for object in &manifest.objects {
            if object.name != format!("objects/{}", object.blake3)
                || object.size_bytes > MAX_OBJECT
                || expected.get(&object.blake3) != Some(&(object.sha256, object.size_bytes))
                || ranges.contains_key(&object.blake3)
            {
                return Err(invalid());
            }
            if manifest
                .records
                .iter()
                .any(|v| v["blake3"] == object.blake3.to_string() && v["quarantined"] == true)
            {
                return Err(ArtifactError::QuarantineBlocked);
            }
            let end = offset
                .checked_add(object.size_bytes as usize)
                .ok_or_else(invalid)?;
            let content = bytes.get(offset..end).ok_or_else(invalid)?;
            let hashes = hash_bytes(content);
            if hashes.blake3 != object.blake3 || hashes.sha256 != object.sha256 {
                return Err(ArtifactError::DigestMismatch);
            }
            ranges.insert(object.blake3, offset..end);
            offset = end;
        }
        if offset != bytes.len() {
            return Err(invalid());
        }
        let digests = hash_bytes(&bytes);
        let summary = BundleSummary {
            bundle_blake3: digests.blake3,
            bundle_sha256: digests.sha256,
            size_bytes: bytes.len() as u64,
            manifest_blake3: hash_bytes(raw).blake3,
            records,
            objects: manifest.objects.clone(),
        };
        Ok(Self {
            manifest,
            bytes,
            ranges,
            summary,
        })
    }
    /// Exact bounded preview facts, without private source paths.
    pub fn summary(&self) -> &BundleSummary {
        &self.summary
    }
    /// Write precisely the validated container to an already-authorized retained output handle.
    pub fn write(&self, mut output: impl std::io::Write) -> Result<()> {
        output.write_all(&self.bytes)?;
        Ok(())
    }
    pub(crate) fn encode(manifest: BundleManifest, objects: Vec<Vec<u8>>) -> Result<Self> {
        let json = to_jcs_bytes(&manifest)?;
        if json.len() > MAX_MANIFEST {
            return Err(invalid());
        }
        let total = objects
            .iter()
            .try_fold(12usize + json.len(), |n, b| n.checked_add(b.len()))
            .ok_or_else(invalid)?;
        if total > BUNDLE_MAX_BYTES {
            return Err(invalid());
        }
        let mut bytes = Vec::with_capacity(total);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&(json.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&json);
        for object in objects {
            bytes.extend_from_slice(&object);
        }
        Self::parse(bytes)
    }
}
