//! Exact collection and validated bundle operations. Product policy owns human approval and receipts.
use super::*;
use std::io::Read;
use zeus_fs::directory::{DirectoryCap, opened_file_metadata};
use zeus_verify::{canonical::to_jcs_bytes, hash::hash_bytes};

/// One immutable content target, including the reviewed object and reference revisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionObject {
    /// BLAKE3 identity.
    pub blake3: Hex256,
    /// SHA-256 identity.
    pub sha256: Hex256,
    /// Logical bytes that may be removed.
    pub size_bytes: u64,
    /// Opened regular-file identity at preview.
    pub file_id: FileId,
    /// Hash of object metadata with availability normalized for interrupted-operation recovery.
    pub object_revision: Hex256,
    /// Hash of all referring artifact records; retention changes invalidate the plan.
    pub references_revision: Hex256,
}
/// Exact garbage-collection effect; never means “select whatever is eligible later”.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectionPlan {
    /// Format1.
    pub version: u32,
    /// Store identity.
    pub store_id: StoreId,
    /// Retained store root identity.
    pub root_id: FileId,
    /// Explicit permission to select evictable content, rather than only expired unreferenced objects.
    pub quota_pressure: bool,
    /// Exact bounded list of selected objects.
    pub objects: Vec<CollectionObject>,
}
fn stale() -> ArtifactError {
    ArtifactError::RecordInvalid("maintenance plan changed; preview again")
}
fn object_revision(row: &ObjectRow) -> Result<Hex256> {
    let mut value = serde_json::to_value(row)?;
    value["state"] = serde_json::json!("present");
    Ok(hash_bytes(&to_jcs_bytes(&value)?).blake3)
}
fn references_revision(state: &IndexState, digest: Hex256) -> Result<Hex256> {
    let records: Vec<_> = state
        .artifacts
        .values()
        .filter(|a| a.blake3 == digest)
        .collect();
    Ok(hash_bytes(&to_jcs_bytes(&records)?).blake3)
}
impl ArtifactStore {
    fn held_root(&self) -> Result<DirectoryCap> {
        let root = DirectoryCap::open_root(&self.root)?;
        if Some(root.file_id()?) != self.root_id {
            return Err(ArtifactError::StoreCorrupt);
        }
        Ok(root)
    }
    fn held_object(root: &DirectoryCap, digest: Hex256) -> Result<(DirectoryCap, String)> {
        let text = digest.to_string();
        let relative = PathBuf::from("objects")
            .join("blake3")
            .join(&text[..2])
            .join(&text[2..4]);
        Ok((root.open_dir(&relative)?, text))
    }
    fn read_bundle_object(&self, root: &DirectoryCap, record: &Artifact) -> Result<Vec<u8>> {
        if record.quarantined {
            return Err(ArtifactError::QuarantineBlocked);
        }
        if record.size_bytes > 16 * 1024 * 1024 {
            return Err(ArtifactError::QuotaExceeded);
        }
        if record.object.state != ObjectState::Present {
            return Err(ArtifactError::ObjectAbsent);
        }
        let (dir, name) = Self::held_object(root, record.blake3)?;
        let mut file = dir.open_read(name.as_ref())?;
        let before = opened_file_metadata(&file)?;
        if before.len != record.size_bytes {
            return Err(ArtifactError::DigestMismatch);
        }
        let mut content = Vec::new();
        (&mut file)
            .take(record.size_bytes + 1)
            .read_to_end(&mut content)?;
        let after = opened_file_metadata(&file)?;
        if before.file_id != after.file_id
            || before.len != after.len
            || before.mtime_ms != after.mtime_ms
            || hash_bytes(&content) != record.digests()
        {
            return Err(ArtifactError::DigestMismatch);
        }
        Ok(content)
    }
    /// Build a bounded portable archive from exact active IDs, optionally carrying verified bytes.
    /// Byte export of quarantined content fails; metadata-only records preserve quarantine and retention.
    pub fn export_bundle(
        &self,
        ids: &[ArtifactId],
        include_objects: bool,
        privacy: &Privacy,
    ) -> Result<ArtifactBundle> {
        let _guard = self.guard()?;
        if ids.is_empty()
            || ids.len() > BUNDLE_MAX_RECORDS
            || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
        {
            return Err(stale());
        }
        let root = self.held_root()?;
        let mut manifest = BundleManifest {
            version: 1,
            exporter: self.config.product.clone(),
            records: vec![],
            objects: vec![],
        };
        let quarantined: BTreeSet<_> = self
            .load()?
            .artifacts
            .values()
            .filter(|record| record.quarantined)
            .map(|record| record.blake3)
            .collect();
        let mut objects = vec![];
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for id in ids {
            let record = self.export(*id, privacy)?;
            if include_objects && (record.quarantined || quarantined.contains(&record.blake3)) {
                return Err(ArtifactError::QuarantineBlocked);
            }
            if include_objects && seen.insert(record.blake3) {
                total = total
                    .checked_add(record.size_bytes)
                    .ok_or(ArtifactError::QuotaExceeded)?;
                if total > BUNDLE_MAX_BYTES as u64 {
                    return Err(ArtifactError::QuotaExceeded);
                }
                objects.push(self.read_bundle_object(&root, &record)?);
                manifest.objects.push(BundleObject {
                    name: format!("objects/{}", record.blake3),
                    blake3: record.blake3,
                    sha256: record.sha256,
                    size_bytes: record.size_bytes,
                });
            }
            manifest.records.push(serde_json::to_value(record)?);
        }
        ArtifactBundle::encode(manifest, objects)
    }
    /// Validate every store conflict and capacity requirement before importing the first record.
    /// Per-record commits remain recoverable via immutable source identity; this is not a cross-record transaction.
    /// It never invokes automatic collection, repairs damaged objects, weakens existing retention or rewrites evidence.
    pub fn import_bundle(&self, bundle: &ArtifactBundle) -> Result<Vec<Artifact>> {
        let _guard = self.guard()?;
        self.held_root()?;
        let state = self.load()?;
        let mut additional = 0u64;
        for object in &bundle.manifest.objects {
            match state.objects.get(&object.blake3.to_string()) {
                Some(row) if row.sha256 != object.sha256 || row.size_bytes != object.size_bytes => {
                    return Err(ArtifactError::DigestMismatch);
                }
                Some(row) if row.state == ObjectState::Damaged => {
                    return Err(ArtifactError::ObjectDamaged);
                }
                Some(row) if row.state == ObjectState::Present => (),
                _ => {
                    additional = additional
                        .checked_add(object.size_bytes)
                        .ok_or(ArtifactError::QuotaExceeded)?
                }
            }
        }
        if self
            .config
            .quota_bytes
            .is_some_and(|q| state.present_bytes().saturating_add(additional) > q)
            || self.fs.free_space(&self.root)?.saturating_sub(additional)
                < self.config.min_free_bytes
        {
            return Err(ArtifactError::QuotaExceeded);
        }
        for received in &bundle.manifest.records {
            let record: Artifact = serde_json::from_value(received.clone())?;
            if record.store_id == state.store_id {
                return Err(ArtifactError::ImportConflict);
            }
            if let Some(id) = state
                .imports
                .get(&format!("{}/{}", record.store_id, record.id))
                && (state.get(*id)?.digests() != record.digests()
                    || state.import_sources.get(&id.to_string()) != Some(received))
            {
                return Err(ArtifactError::ImportConflict);
            }
            if let Some(object) = state.objects.get(&record.blake3.to_string())
                && (object.sha256 != record.sha256 || object.size_bytes != record.size_bytes)
            {
                return Err(ArtifactError::DigestMismatch);
            }
        }
        let mut imported = Vec::new();
        for received in &bundle.manifest.records {
            let record: Artifact = serde_json::from_value(received.clone())?;
            let content = bundle
                .ranges
                .get(&record.blake3)
                .map(|r| IngestSource::Bytes(&bundle.bytes[r.clone()]));
            imported.push(self.import_locked(
                received,
                content,
                ImportPolicy {
                    exporter: &bundle.manifest.exporter,
                    via: "export_file",
                    retention: record.retention,
                    until: record.retain_until,
                    exact_source: true,
                },
            )?);
        }
        Ok(imported)
    }
    /// Select at most128 present, unprotected objects without mutation, including exact retention revisions.
    pub fn collection_preview(&self, quota_pressure: bool, limit: usize) -> Result<CollectionPlan> {
        if !(1..=128).contains(&limit) {
            return Err(stale());
        }
        let _guard = self.guard()?;
        let root = self.held_root()?;
        let state = self.load()?;
        let protected = self.protected(&state);
        let threshold = self
            .clock
            .now()
            .checked_sub(self.config.gc_grace)
            .unwrap_or(Timestamp::UNIX_EPOCH);
        let mut candidates: Vec<_> = state
            .objects
            .iter()
            .filter(|(digest, row)| {
                row.state == ObjectState::Present
                    && !protected.contains(*digest)
                    && (quota_pressure || row.unreferenced_since.is_some_and(|t| t <= threshold))
            })
            .collect();
        candidates.sort_by_key(|(digest, row)| (row.last_access_at, row.created_at, *digest));
        let mut objects = Vec::new();
        for (text, row) in candidates.into_iter().take(limit) {
            let digest: Hex256 = text.parse().map_err(|_| ArtifactError::StoreCorrupt)?;
            let (dir, name) = Self::held_object(&root, digest)?;
            let meta = dir.entry_metadata(name.as_ref())?;
            if !meta.is_regular_file || meta.len != row.size_bytes {
                return Err(ArtifactError::ObjectDamaged);
            }
            objects.push(CollectionObject {
                blake3: digest,
                sha256: row.sha256,
                size_bytes: row.size_bytes,
                file_id: meta.file_id.ok_or(ArtifactError::StoreCorrupt)?,
                object_revision: object_revision(row)?,
                references_revision: references_revision(&state, digest)?,
            });
        }
        Ok(CollectionPlan {
            version: 1,
            store_id: state.store_id,
            root_id: root.file_id()?,
            quota_pressure,
            objects,
        })
    }
    /// Execute only exact reviewed targets. `resume` is allowed only after the owner durably records a start.
    /// Every still-present target is validated before any removal; newly protected or changed objects fail closed.
    pub fn collection_apply(&self, plan: &CollectionPlan, resume: bool) -> Result<u64> {
        let _guard = self.guard()?;
        let root = self.held_root()?;
        let mut state = self.load()?;
        if plan.version != 1
            || plan.store_id != state.store_id
            || plan.root_id != root.file_id()?
            || plan.objects.len() > 128
            || plan
                .objects
                .iter()
                .map(|o| o.blake3)
                .collect::<BTreeSet<_>>()
                .len()
                != plan.objects.len()
        {
            return Err(stale());
        }
        // Unlike embedding-controlled automatic GC, public administration requires a durable audit sink.
        if self.audit.is_none() {
            return Err(ArtifactError::RecordInvalid(
                "collection requires durable audit",
            ));
        }
        let protected = self.protected(&state);
        let threshold = self
            .clock
            .now()
            .checked_sub(self.config.gc_grace)
            .unwrap_or(Timestamp::UNIX_EPOCH);
        let mut held = Vec::new();
        let mut completed_intents = Vec::new();
        for expected in &plan.objects {
            let key = expected.blake3.to_string();
            let row = state.objects.get(&key).ok_or_else(stale)?;
            if row.sha256 != expected.sha256
                || row.size_bytes != expected.size_bytes
                || object_revision(row)? != expected.object_revision
                || references_revision(&state, expected.blake3)? != expected.references_revision
                || protected.contains(&key)
                || (!plan.quota_pressure && !row.unreferenced_since.is_some_and(|t| t <= threshold))
            {
                return Err(stale());
            }
            let (dir, name) = Self::held_object(&root, expected.blake3)?;
            let pending: Vec<_> = state
                .intents
                .iter()
                .filter_map(|(id, intent)| {
                    matches!(intent,Intent::Delete{digest} if *digest==expected.blake3)
                        .then_some(id.clone())
                })
                .collect();
            if resume && row.state == ObjectState::Absent {
                if !dir.entry_exists(name.as_ref())? {
                    completed_intents.extend(pending);
                    continue;
                }
                // A durable intent with the original retained identity may still need its unlink.
                // Without that intent, a new file at an already-completed path is never adopted or removed.
                if pending.is_empty() {
                    return Err(stale());
                }
            } else if row.state != ObjectState::Present {
                return Err(stale());
            }
            let source = dir.prepare_rename(name.as_ref())?;
            let meta = source.metadata()?;
            if !meta.is_regular_file
                || meta.file_id.as_ref() != Some(&expected.file_id)
                || meta.len != expected.size_bytes
            {
                return Err(stale());
            }
            held.push((expected, dir, source));
        }
        let digests: Vec<_> = plan.objects.iter().map(|o| o.blake3).collect();
        self.audit("artifact.gc_sweep",None,serde_json::json!({"objects":plan.objects.len(),"bytes":plan.objects.iter().map(|o|o.size_bytes).sum::<u64>(),"digests_blake3":hash_bytes(&to_jcs_bytes(&digests)?).blake3,"reason":if plan.quota_pressure {"quota"}else{"unreferenced"}}),true)?;
        if !completed_intents.is_empty() {
            for id in completed_intents {
                state.intents.remove(&id);
            }
            self.commit(&state)?;
        }
        let mut removed = 0;
        for (expected, dir, source) in held {
            let key = expected.blake3.to_string();
            let intent = IdGenerator::new().next_ulid().to_string();
            state.objects.get_mut(&key).ok_or_else(stale)?.state = ObjectState::Absent;
            state.intents.insert(
                intent.clone(),
                Intent::Delete {
                    digest: expected.blake3,
                },
            );
            self.commit(&state)?;
            #[cfg(windows)]
            self.fs
                .set_readonly(&self.object_path(expected.blake3), false)?;
            source.remove(&expected.file_id)?;
            dir.sync()?;
            state.intents.retain(
                |_, intent| !matches!(intent,Intent::Delete{digest}if *digest==expected.blake3),
            );
            self.commit(&state)?;
            removed += expected.size_bytes;
        }
        Ok(removed)
    }
}

impl ArtifactStore {
    /// Read committed import IDs for exact immutable source identities after an interrupted batch.
    /// Callers must retain their own authority binding; producer fields never confer ownership.
    pub fn bundle_import_progress(&self, summary: &BundleSummary) -> Result<Vec<ArtifactId>> {
        let state = self.load()?;
        Ok(summary
            .records
            .iter()
            .filter_map(|(store, id)| state.imports.get(&format!("{store}/{id}")).copied())
            .collect())
    }
    /// Count known absent targets without attempting further deletion. This does not verify who removed bytes.
    pub fn collection_progress(&self, plan: &CollectionPlan) -> Result<(u32, u32)> {
        let state = self.load()?;
        if state.store_id != plan.store_id {
            return Err(stale());
        }
        let absent = plan
            .objects
            .iter()
            .filter(|o| {
                state.objects.get(&o.blake3.to_string()).is_some_and(|r| {
                    r.state == ObjectState::Absent
                        && r.sha256 == o.sha256
                        && r.size_bytes == o.size_bytes
                }) && !state
                    .intents
                    .values()
                    .any(|intent| matches!(intent,Intent::Delete{digest} if *digest==o.blake3))
            })
            .count() as u32;
        Ok((absent, plan.objects.len() as u32 - absent))
    }
}

/// A reviewed integrity target also binds the observed length, so truncated content can be quarantined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityObject {
    /// Immutable index/reference and file identities.
    pub object: CollectionObject,
    /// Actual source length at review; may disagree with content identity.
    pub observed_size: u64,
}
/// Bounded integrity verification; bad bytes move only into this store's private damaged directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrityPlan {
    /// Format1.
    pub version: u32,
    /// Owning store.
    pub store_id: StoreId,
    /// Retained root identity.
    pub root_id: FileId,
    /// Exact unique targets, at most64 and32MiB observed bytes.
    pub objects: Vec<IntegrityObject>,
}
/// Integrity results; damaged content remains retained privately for later human-guided repair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityResult {
    /// Verified objects.
    pub verified: Vec<Hex256>,
    /// Objects marked damaged and moved without replacing another file.
    pub damaged: Vec<Hex256>,
}
impl ArtifactStore {
    /// Review integrity of exact present artifact content, including already quarantined records.
    pub fn integrity_preview(&self, ids: &[ArtifactId]) -> Result<IntegrityPlan> {
        if ids.is_empty()
            || ids.len() > 64
            || ids.iter().collect::<BTreeSet<_>>().len() != ids.len()
        {
            return Err(stale());
        }
        let _guard = self.guard()?;
        let root = self.held_root()?;
        let state = self.load()?;
        let mut seen = BTreeSet::new();
        let mut objects = vec![];
        let mut total = 0u64;
        for id in ids {
            let record = state.get(*id)?;
            if record.state != ArtifactState::Active || record.object.state != ObjectState::Present
            {
                return Err(ArtifactError::ObjectAbsent);
            }
            if !seen.insert(record.blake3) {
                continue;
            }
            let row = state
                .objects
                .get(&record.blake3.to_string())
                .ok_or(ArtifactError::StoreCorrupt)?;
            let (dir, name) = Self::held_object(&root, record.blake3)?;
            let meta = dir.entry_metadata(name.as_ref())?;
            if !meta.is_regular_file || meta.len > 16 * 1024 * 1024 {
                return Err(ArtifactError::QuotaExceeded);
            }
            total = total
                .checked_add(meta.len)
                .ok_or(ArtifactError::QuotaExceeded)?;
            if total > 32 * 1024 * 1024 {
                return Err(ArtifactError::QuotaExceeded);
            }
            objects.push(IntegrityObject {
                object: CollectionObject {
                    blake3: record.blake3,
                    sha256: record.sha256,
                    size_bytes: record.size_bytes,
                    file_id: meta.file_id.ok_or(ArtifactError::StoreCorrupt)?,
                    object_revision: object_revision(row)?,
                    references_revision: references_revision(&state, record.blake3)?,
                },
                observed_size: meta.len,
            });
        }
        Ok(IntegrityPlan {
            version: 1,
            store_id: state.store_id,
            root_id: root.file_id()?,
            objects,
        })
    }
    /// Verify all targets through retained handles before mutating index state. A caller must approve the
    /// exact possibility of moving mismatched bytes into quarantine. Interrupted checks need a fresh preview.
    pub fn integrity_apply(&self, plan: &IntegrityPlan) -> Result<IntegrityResult> {
        let _guard = self.guard()?;
        let root = self.held_root()?;
        let mut state = self.load()?;
        if self.audit.is_none()
            || plan.version != 1
            || plan.store_id != state.store_id
            || plan.root_id != root.file_id()?
            || plan.objects.is_empty()
            || plan.objects.len() > 64
            || plan
                .objects
                .iter()
                .map(|o| o.object.blake3)
                .collect::<BTreeSet<_>>()
                .len()
                != plan.objects.len()
        {
            return Err(stale());
        }
        let mut total = 0u64;
        let mut prepared = vec![];
        for target in &plan.objects {
            let expected = &target.object;
            let row = state
                .objects
                .get(&expected.blake3.to_string())
                .ok_or_else(stale)?;
            if row.state != ObjectState::Present
                || row.sha256 != expected.sha256
                || row.size_bytes != expected.size_bytes
                || object_revision(row)? != expected.object_revision
                || references_revision(&state, expected.blake3)? != expected.references_revision
            {
                return Err(stale());
            }
            if target.observed_size > 16 * 1024 * 1024 {
                return Err(ArtifactError::QuotaExceeded);
            }
            total = total
                .checked_add(target.observed_size)
                .ok_or(ArtifactError::QuotaExceeded)?;
            if total > 32 * 1024 * 1024 {
                return Err(ArtifactError::QuotaExceeded);
            }
            let (dir, name) = Self::held_object(&root, expected.blake3)?;
            let mut file = dir.open_read(name.as_ref())?;
            let before = opened_file_metadata(&file)?;
            if before.file_id.as_ref() != Some(&expected.file_id)
                || before.len != target.observed_size
            {
                return Err(stale());
            }
            let mut bytes = vec![];
            (&mut file)
                .take(target.observed_size + 1)
                .read_to_end(&mut bytes)?;
            let after = opened_file_metadata(&file)?;
            if before.len != after.len
                || before.mtime_ms != after.mtime_ms
                || before.file_id != after.file_id
                || bytes.len() as u64 != target.observed_size
            {
                return Err(stale());
            }
            let found = hash_bytes(&bytes);
            drop(file);
            let source = dir.prepare_rename(name.as_ref())?;
            if source.metadata()?.file_id.as_ref() != Some(&expected.file_id) {
                return Err(stale());
            }
            prepared.push((
                expected,
                dir,
                source,
                found
                    == Digests {
                        blake3: expected.blake3,
                        sha256: expected.sha256,
                        size_bytes: expected.size_bytes,
                    },
            ));
        }
        self.audit("artifact.scrub_intent",None,serde_json::json!({"objects":plan.objects.len(),"bytes":total,"digests_blake3":hash_bytes(&to_jcs_bytes(&plan.objects.iter().map(|o|o.object.blake3).collect::<Vec<_>>())?).blake3}),true)?;
        let mut result = IntegrityResult {
            verified: vec![],
            damaged: vec![],
        };
        for (expected, dir, source, valid) in prepared {
            let row = state
                .objects
                .get_mut(&expected.blake3.to_string())
                .ok_or_else(stale)?;
            row.checked_at = Some(self.clock.now());
            if valid {
                row.verification = VerificationState::Verified;
                self.commit(&state)?;
                result.verified.push(expected.blake3);
                continue;
            }
            let damaged = root.open_dir(Path::new("damaged"))?;
            let name = format!("{}-{}", expected.blake3, IdGenerator::new().next_ulid());
            let intent = IdGenerator::new().next_ulid().to_string();
            row.state = ObjectState::Damaged;
            row.verification = VerificationState::Failed;
            state.intents.insert(
                intent.clone(),
                Intent::Quarantine {
                    digest: expected.blake3,
                    dest: self.root.join("damaged").join(&name),
                },
            );
            self.commit(&state)?;
            #[cfg(windows)]
            self.fs
                .set_readonly(&self.object_path(expected.blake3), false)?;
            source.rename_noreplace(&damaged, name.as_ref())?;
            dir.sync()?;
            damaged.sync()?;
            state.intents.remove(&intent);
            self.commit(&state)?;
            self.audit(
                "artifact.object_damaged",
                None,
                serde_json::json!({"blake3":expected.blake3,"found":"mismatch"}),
                false,
            )?;
            result.damaged.push(expected.blake3);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod recovery_tests {
    use super::*;
    #[test]
    fn exact_collection_resumes_an_indexed_delete_intent_before_and_after_unlink() {
        let dir = tempfile::tempdir().unwrap();
        let ids = IdGenerator::new();
        let audit = Arc::new(zeus_verify::audit::MemoryAuditLog::new(
            ids.chain_id(),
            ids.store_id(),
            "test",
            Timestamp::UNIX_EPOCH,
            None,
        ));
        let store = ArtifactStore::open(
            &dir.path().join("store"),
            StoreConfig {
                min_free_bytes: 0,
                ..StoreConfig::default()
            },
            Arc::new(zeus_fs::RealFs),
            Arc::new(zeus_control::ManualClock::new(Timestamp::UNIX_EPOCH)),
            Some(audit),
        )
        .unwrap();
        for already_unlinked in [false, true] {
            let source = dir.path().join("source");
            std::fs::write(
                &source,
                if already_unlinked {
                    b"second".as_slice()
                } else {
                    b"first".as_slice()
                },
            )
            .unwrap();
            let record = store
                .ingest(&source, ArtifactDraft::local("zeus", "test", None), None)
                .unwrap();
            store
                .set_retention(record.id, Retention::Evictable, None)
                .unwrap();
            let plan = store.collection_preview(true, 128).unwrap();
            assert_eq!(plan.objects.len(), 1);
            let mut state = store.load().unwrap();
            state
                .objects
                .get_mut(&record.blake3.to_string())
                .unwrap()
                .state = ObjectState::Absent;
            state.intents.insert(
                "interrupted".into(),
                Intent::Delete {
                    digest: record.blake3,
                },
            );
            store.commit(&state).unwrap();
            if already_unlinked {
                store
                    .remove_object_file(&store.object_path(record.blake3))
                    .unwrap();
            }
            assert_eq!(store.collection_progress(&plan).unwrap(), (0, 1));
            store.collection_apply(&plan, true).unwrap();
            assert!(!store.object_path(record.blake3).exists());
            assert!(store.load().unwrap().intents.is_empty());
            assert_eq!(store.collection_progress(&plan).unwrap(), (1, 0));
        }
    }
}
