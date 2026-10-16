//! Version-one artifact records and embedding policies.
use crate::{ArtifactError, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeus_types::*;
use zeus_verify::provenance::{LicenseInfo, ManifestHttp, UrlQueryPrivacy};

macro_rules! vocabulary {
    ($name:ident {$($variant:ident => $wire:literal),+ $(,)?})=>{
        #[doc=concat!("Artifact ",stringify!($name)," vocabulary.")]
        #[derive(Debug,Clone,Copy,PartialEq,Eq,Serialize,Deserialize)]
        pub enum $name { $(#[doc=$wire] #[serde(rename=$wire)] $variant),+ }
    };
}
vocabulary!(ObjectState {Present=>"present",Absent=>"absent",Damaged=>"damaged"});
vocabulary!(ArtifactState {Active=>"active",Deleted=>"deleted"});
vocabulary!(VerificationState {Verified=>"verified",Unverified=>"unverified",Failed=>"failed"});
vocabulary!(VerificationBasis {SelfComputed=>"self",Origin=>"origin",Expected=>"expected"});
vocabulary!(Retention {Keep=>"keep",Evictable=>"evictable"});
vocabulary!(MaterializeMode {Reflink=>"reflink",Hardlink=>"hardlink",Copy=>"copy"});

/// An object's identity and current availability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CasObjectRef {
    /// Always blake3 in format one.
    pub algorithm: String,
    /// Content digest.
    pub digest: Hex256,
    /// Logical content length.
    pub size_bytes: u64,
    /// Composed from the object index row.
    pub state: ObjectState,
}
/// Provenance of bytes; never contains local paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactOrigin {
    /// Downloaded content.
    Remote {
        /// Redacted request URL.
        url: RedactedUrl,
        /// Redacted final URL.
        final_url: RedactedUrl,
        /// Whether either URL was reduced.
        url_redacted: bool,
        /// Redacted referrer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        referrer: Option<RedactedUrl>,
        /// Origin whose authorized browser session was used.
        session_origin: Option<Origin>,
        /// Response metadata.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        http: Option<Box<ManifestHttp>>,
    },
    /// Produced from parents.
    Derived,
    /// Registered local content.
    Local,
}
/// Product that first created the provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Producer {
    /// Product name.
    pub product: String,
    /// Product release.
    pub version: String,
    /// Engine release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    /// Extension release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension: Option<String>,
    /// Who requested the operation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<String>,
}
/// An external transformation program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tool {
    /// Name.
    pub name: String,
    /// Version.
    pub version: String,
}
/// Operation binding provenance to parameters without secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    /// Dotted product.operation name.
    pub name: String,
    /// Implementing release.
    pub version: String,
    /// BLAKE3 of canonical redacted parameters.
    pub params_blake3: Hex256,
    /// External program when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<Tool>,
}
/// One immutable lineage edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParentRef {
    /// Earlier record in this store, or content-only reference.
    pub artifact_id: Option<ArtifactId>,
    /// BLAKE3 content identity.
    pub blake3: Hex256,
    /// Independent content digest.
    pub sha256: Hex256,
    /// Length.
    pub size_bytes: u64,
    /// Input role.
    pub role: String,
}
/// Local verification of the described content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    /// Integrity state.
    pub state: VerificationState,
    /// Last local digest computation.
    pub checked_at: Option<Timestamp>,
    /// Trust rung for this record.
    pub basis: VerificationBasis,
}
/// Reductions applied to exported records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Privacy {
    /// Query reduction.
    pub url_query: UrlQueryPrivacy,
    /// Whether session-origin disclosure is permitted.
    pub session_origin_included: bool,
}
impl Default for Privacy {
    fn default() -> Self {
        Self {
            url_query: UrlQueryPrivacy::Dropped,
            session_origin_included: false,
        }
    }
}
/// Identity of a source record at an import boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportSource {
    /// Exporting product.
    pub product: String,
    /// Exporting store.
    pub store_id: StoreId,
    /// Source artifact.
    pub artifact_id: ArtifactId,
}
/// An authenticated import hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportRecord {
    /// Import time.
    pub imported_at: Timestamp,
    /// Source identity.
    pub from: ImportSource,
    /// api or export_file.
    pub via: String,
    /// copy, reflink, move, existing, or none.
    pub object_mode: String,
    /// Locally verified content.
    pub verified: bool,
    /// Hash of the exact received canonical record.
    pub record_blake3: Hex256,
}

/// A portable artifact record; locations and internal intents are never part of this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Artifact {
    /// Format version.
    pub artifact_version: u32,
    /// Store-local identifier.
    pub id: ArtifactId,
    /// Holding store.
    pub store_id: StoreId,
    /// Active record or tombstone.
    pub state: ArtifactState,
    /// Local commit time.
    pub created_at: Timestamp,
    /// Tombstone time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<Timestamp>,
    /// Interoperability digest.
    pub sha256: Hex256,
    /// CAS identity.
    pub blake3: Hex256,
    /// Logical size.
    pub size_bytes: u64,
    /// Object availability.
    pub object: CasObjectRef,
    /// Sanitized name hint.
    pub name: Option<String>,
    /// Detected type.
    pub media_type: Option<String>,
    /// Claimed type.
    pub declared_media_type: Option<String>,
    /// Origin of the bytes.
    pub origin: ArtifactOrigin,
    /// Download completion time.
    pub retrieved_at: Option<Timestamp>,
    /// Transformation completion time.
    pub produced_at: Option<Timestamp>,
    /// Original producer.
    pub producer: Producer,
    /// Producing operation.
    pub operation: Operation,
    /// Immutable lineage.
    pub parents: Vec<ParentRef>,
    /// Producing job.
    pub job_id: Option<JobId>,
    /// Producing run.
    pub run_id: Option<RunId>,
    /// License claim and evidence.
    pub license: LicenseInfo,
    /// Quarantine survives every import.
    pub quarantined: bool,
    /// Reasons for quarantine.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine_reasons: Vec<QuarantineReason>,
    /// Local integrity state and trust basis.
    pub verification: Verification,
    /// Retention policy.
    pub retention: Retention,
    /// Protection deadline.
    pub retain_until: Option<Timestamp>,
    /// Prior import hops.
    pub imports: Vec<ImportRecord>,
    /// Reductions already applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub privacy: Option<Privacy>,
    /// Untrusted labels.
    pub metadata: Map<String, Value>,
    /// Holding product's audit pointer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditHead>,
}

/// Caller-owned immutable metadata before the store assigns identity and digests.
#[derive(Debug, Clone)]
pub struct ArtifactDraft {
    /// Record template. The store replaces identity, digests, state and verification.
    pub record: Artifact,
}
impl ArtifactDraft {
    /// A local file registration with unknown license and evictable retention.
    pub fn local(product: &str, version: &str, name: Option<String>) -> Self {
        let ids = IdGenerator::new();
        let zero = Hex256::from_bytes([0; 32]);
        Self {
            record: Artifact {
                artifact_version: 1,
                id: ids.artifact_id(),
                store_id: ids.store_id(),
                state: ArtifactState::Active,
                created_at: Timestamp::UNIX_EPOCH,
                deleted_at: None,
                sha256: zero,
                blake3: zero,
                size_bytes: 0,
                object: CasObjectRef {
                    algorithm: "blake3".into(),
                    digest: zero,
                    size_bytes: 0,
                    state: ObjectState::Absent,
                },
                name,
                media_type: None,
                declared_media_type: None,
                origin: ArtifactOrigin::Local,
                retrieved_at: None,
                produced_at: None,
                producer: Producer {
                    product: product.into(),
                    version: version.into(),
                    engine: None,
                    extension: None,
                    source_kind: None,
                },
                operation: Operation {
                    name: format!("{product}.ingest"),
                    version: version.into(),
                    params_blake3: zeus_verify::hash::hash_bytes(b"{}").blake3,
                    tool: None,
                },
                parents: vec![],
                job_id: None,
                run_id: None,
                license: LicenseInfo::unknown(),
                quarantined: false,
                quarantine_reasons: vec![],
                verification: Verification {
                    state: VerificationState::Unverified,
                    checked_at: None,
                    basis: VerificationBasis::SelfComputed,
                },
                retention: Retention::Evictable,
                retain_until: None,
                imports: vec![],
                privacy: None,
                metadata: Map::new(),
                audit: None,
            },
        }
    }
}
impl Artifact {
    /// Validate bounded, portable provenance before any index mutation.
    pub fn validate(&self) -> Result<()> {
        if self.artifact_version != 1 {
            return Err(ArtifactError::VersionUnsupported);
        }
        if self.object.algorithm != "blake3"
            || self.object.digest != self.blake3
            || self.object.size_bytes != self.size_bytes
            || self.size_bytes > zeus_types::limits::MAX_SAFE_INTEGER
            || self.parents.len() > 1024
            || self.imports.len() > 8
            || self.metadata.len() > 32
            || (self.state == ArtifactState::Deleted) != self.deleted_at.is_some()
        {
            return Err(ArtifactError::RecordInvalid(
                "inconsistent identity, lifecycle, or limits",
            ));
        }
        if let Some(name) = &self.name
            && zeus_fs::sanitize_filename(name, &zeus_fs::SanitizeOptions::default())?.name != *name
        {
            return Err(ArtifactError::RecordInvalid("unsafe name"));
        }
        match self.origin {
            ArtifactOrigin::Remote { .. }
                if self.retrieved_at.is_some()
                    && self.produced_at.is_none()
                    && self.parents.is_empty() => {}
            ArtifactOrigin::Derived
                if self.retrieved_at.is_none() && self.produced_at.is_some() => {}
            ArtifactOrigin::Local
                if self.retrieved_at.is_none()
                    && self.produced_at.is_none()
                    && self.parents.is_empty() => {}
            _ => {
                return Err(ArtifactError::RecordInvalid(
                    "origin and timestamps disagree",
                ));
            }
        }
        if self.verification.state == VerificationState::Unverified
            && self.verification.checked_at.is_some()
        {
            return Err(ArtifactError::RecordInvalid(
                "unverified content has a verification time",
            ));
        }
        for (key, value) in &self.metadata {
            if key.is_empty()
                || key.chars().count() > 256
                || key.chars().any(char::is_control)
                || !match value {
                    Value::String(s) => s.chars().count() <= 1024,
                    Value::Bool(_) | Value::Number(_) => true,
                    _ => false,
                }
            {
                return Err(ArtifactError::RecordInvalid("invalid metadata"));
            }
        }
        fn word(value: &str) -> bool {
            value.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
                && value
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_')
        }
        if self.operation.name.len() > 96
            || self.operation.name.split('.').count() < 2
            || !self.operation.name.split('.').all(word)
            || self.producer.product.len() > 32
            || !word(&self.producer.product)
        {
            return Err(ArtifactError::RecordInvalid(
                "invalid producer or operation name",
            ));
        }
        for parent in &self.parents {
            if !word(&parent.role) || parent.size_bytes > zeus_types::limits::MAX_SAFE_INTEGER {
                return Err(ArtifactError::RecordInvalid("invalid parent reference"));
            }
        }
        if !self.quarantined && !self.quarantine_reasons.is_empty() {
            return Err(ArtifactError::RecordInvalid(
                "quarantine reasons without quarantine",
            ));
        }
        for value in self.metadata.values().filter_map(Value::as_str) {
            if value.starts_with(['/', '\\']) || value.as_bytes().get(1) == Some(&b':') {
                return Err(ArtifactError::RecordInvalid("absolute path in metadata"));
            }
        }
        if let ArtifactOrigin::Remote {
            url,
            final_url,
            referrer,
            ..
        } = &self.origin
        {
            for url in [Some(url), Some(final_url), referrer.as_ref()]
                .into_iter()
                .flatten()
            {
                if zeus_types::redact::redact_url(
                    &url.to_string(),
                    zeus_types::redact::RedactMode::Record,
                )
                .redacted
                {
                    return Err(ArtifactError::RecordInvalid(
                        "origin URL contains unredacted secrets",
                    ));
                }
            }
        }
        let value = serde_json::to_value(self)?;
        zeus_verify::canonical::check_hashable(&value)?;
        let bytes = serde_json::to_vec(&value)?;
        if bytes.len() > 256 << 10 || bytes.windows(12).any(|w| w == b"ZEUS-CANARY-") {
            return Err(ArtifactError::RecordInvalid("record size or secret canary"));
        }
        Ok(())
    }
    /// Content triple for cross-store identity comparisons.
    pub fn digests(&self) -> zeus_verify::hash::Digests {
        zeus_verify::hash::Digests {
            sha256: self.sha256,
            blake3: self.blake3,
            size_bytes: self.size_bytes,
        }
    }
}

/// Store limits chosen by the embedding product.
#[derive(Debug, Clone)]
pub struct StoreConfig {
    /// Product owning this instance.
    pub product: String,
    /// Product release.
    pub version: String,
    /// Logical byte ceiling; None is explicit unlimited storage.
    pub quota_bytes: Option<u64>,
    /// Reserve this free space after a copy.
    pub min_free_bytes: u64,
    /// Every destination root, disjoint from the store.
    pub write_roots: Vec<std::path::PathBuf>,
    /// Explicit human override for a cloud-synced store directory.
    pub allow_cloud_root: bool,
    /// Age before unreferenced objects are collected.
    pub gc_grace: std::time::Duration,
    /// Preserve transitive inputs of protected records.
    pub keep_lineage_inputs: bool,
}
impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            product: "zeus".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            quota_bytes: Some(10 << 30),
            min_free_bytes: 1 << 30,
            write_roots: vec![],
            allow_cloud_root: false,
            gc_grace: std::time::Duration::from_secs(86400),
            keep_lineage_inputs: false,
        }
    }
}
/// A bounded record query.
#[derive(Debug, Default, Clone)]
pub struct ArtifactFilter {
    /// Filter by BLAKE3.
    pub blake3: Option<Hex256>,
    /// Filter by producer job.
    pub job_id: Option<JobId>,
    /// Filter by run.
    pub run_id: Option<RunId>,
    /// Include tombstones.
    pub include_deleted: bool,
    /// Maximum records; capped at 10,000.
    pub limit: usize,
}
/// Result of a bounded graph traversal.
#[derive(Debug, Clone)]
pub struct Lineage {
    /// Records visited, including the root.
    pub artifacts: Vec<Artifact>,
    /// The traversal hit a caller or protocol bound.
    pub truncated: bool,
}

impl ArtifactDraft {
    /// Build immutable download provenance from a completed engine job. Paths stay outside the record.
    pub fn from_completed_job(job: &Job) -> Result<Self> {
        use zeus_types::redact::{RedactMode, redact_url};
        let result = job
            .result
            .as_ref()
            .filter(|_| job.state == JobState::Completed)
            .ok_or(ArtifactError::RecordInvalid("job is not completed"))?;
        let name = std::path::Path::new(&result.path)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned());
        let mut draft = Self::local("zeus", env!("CARGO_PKG_VERSION"), name);
        let private = job
            .spec
            .source
            .browser
            .as_ref()
            .is_some_and(|b| b.incognito);
        let raw = if private {
            format!("{}/", job.spec.url.origin())
        } else {
            job.spec.url.to_string()
        };
        let reduced = redact_url(&raw, RedactMode::Record);
        let url = RedactedUrl::new(&reduced.url)
            .map_err(|_| ArtifactError::RecordInvalid("invalid download URL"))?;
        let final_url = if private {
            url.clone()
        } else {
            job.probe
                .as_ref()
                .and_then(|p| p.final_url_redacted.clone())
                .unwrap_or_else(|| url.clone())
        };
        let referrer = if private {
            None
        } else {
            job.spec
                .referrer
                .as_ref()
                .map(|u| {
                    RedactedUrl::new(&redact_url(&u.to_string(), RedactMode::Record).url)
                        .map_err(|_| ArtifactError::RecordInvalid("invalid referrer"))
                })
                .transpose()?
        };
        let r = &mut draft.record;
        r.origin = ArtifactOrigin::Remote {
            url: url.clone(),
            final_url,
            url_redacted: private || reduced.redacted,
            referrer,
            session_origin: if private {
                None
            } else {
                job.spec.session_origin.clone()
            },
            http: job.probe.as_ref().map(|p| {
                Box::new(ManifestHttp {
                    status: Some(p.status),
                    etag: p.validators.etag.clone(),
                    last_modified: p.validators.last_modified.clone(),
                    date: None,
                    repr_digest: p.validators.repr_digest.clone(),
                })
            }),
        };
        r.retrieved_at = Some(job.retry.last_progress_at.unwrap_or(result.completed_at));
        r.job_id = Some(job.id);
        r.run_id = job.spec.source.run_id;
        r.producer.source_kind = serde_json::to_value(job.spec.source.kind)?
            .as_str()
            .map(str::to_owned);
        r.media_type = result.detected_mime.clone();
        r.declared_media_type = job
            .probe
            .as_ref()
            .and_then(|p| p.content_type.as_ref())
            .map(|s| s.split(';').next().unwrap_or(s).trim().to_owned());
        r.quarantined = job.quarantined;
        r.quarantine_reasons = job.quarantine_reasons.clone();
        r.metadata = job
            .spec
            .labels
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        let mut params = Map::new();
        params.insert("url".into(), serde_json::to_value(url)?);
        if let Some(hash) = job.spec.expected_sha256 {
            params.insert("expected_sha256".into(), serde_json::to_value(hash)?);
            r.verification.basis = VerificationBasis::Expected;
        }
        if let Some(size) = job.spec.expected_size {
            params.insert("expected_size".into(), Value::from(size));
        }
        r.operation = Operation {
            name: "zeus.download".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            params_blake3: zeus_verify::hash::hash_bytes(&zeus_verify::canonical::to_jcs_bytes(
                &params,
            )?)
            .blake3,
            tool: None,
        };
        Ok(draft)
    }
}
