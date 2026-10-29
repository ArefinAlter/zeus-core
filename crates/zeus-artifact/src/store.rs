//! Durable content store. A serialized writer surrounds every multi-step operation.
use crate::*;
use redb::{ReadableDatabase, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use zeus_control::SharedClock;
use zeus_fs::{Filesystem, WriteRoots};
use zeus_types::*;
use zeus_verify::{
    audit::{AuditEntry, AuditOutcome, AuditSink},
    hash::{Digests, DualHasher},
};
#[path = "maintenance.rs"]
mod maintenance;
pub use maintenance::*;

enum IngestSource<'a> {
    Path(&'a Path),
    Bytes(&'a [u8]),
}
struct ImportPolicy<'a> {
    exporter: &'a str,
    via: &'a str,
    retention: Retention,
    until: Option<Timestamp>,
    exact_source: bool,
}

const SNAPSHOT: TableDefinition<&str, &[u8]> = TableDefinition::new("artifact_index");
/// Backend boundary: an atomic, durable index snapshot. Alternative backends must preserve atomicity.
pub trait ArtifactIndex: Send + Sync {
    /// Read the latest committed snapshot; None for an empty index.
    fn read_snapshot(&self) -> Result<Option<Vec<u8>>>;
    /// Atomically and durably replace the committed snapshot.
    fn commit_snapshot(&self, bytes: &[u8]) -> Result<()>;
}
struct RedbIndex(redb::Database);
impl ArtifactIndex for RedbIndex {
    fn read_snapshot(&self) -> Result<Option<Vec<u8>>> {
        let tx = self.0.begin_read().map_err(|_| ArtifactError::Index)?;
        let table = tx.open_table(SNAPSHOT).map_err(|_| ArtifactError::Index)?;
        Ok(table
            .get("store")
            .map_err(|_| ArtifactError::Index)?
            .map(|v| v.value().to_vec()))
    }
    fn commit_snapshot(&self, bytes: &[u8]) -> Result<()> {
        let mut tx = self.0.begin_write().map_err(|_| ArtifactError::Index)?;
        tx.set_durability(redb::Durability::Immediate)
            .map_err(|_| ArtifactError::Index)?;
        {
            tx.open_table(SNAPSHOT)
                .map_err(|_| ArtifactError::Index)?
                .insert("store", bytes)
                .map_err(|_| ArtifactError::Index)?;
        }
        tx.commit().map_err(|_| ArtifactError::Index)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ObjectRow {
    sha256: Hex256,
    size_bytes: u64,
    state: ObjectState,
    created_at: Timestamp,
    checked_at: Option<Timestamp>,
    verification: VerificationState,
    last_access_at: Timestamp,
    unreferenced_since: Option<Timestamp>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImportEvidence {
    source_store: StoreId,
    source_id: ArtifactId,
    record: Value,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Intent {
    Ingest {
        record: Box<Artifact>,
        key: Option<String>,
        tmp: PathBuf,
        file_id: FileId,
        evidence: Option<ImportEvidence>,
    },
    Delete {
        digest: Hex256,
    },
    Materialize {
        artifact_id: ArtifactId,
        tmp: PathBuf,
        dest: PathBuf,
        file_id: Option<FileId>,
        mode: MaterializeMode,
    },
    Quarantine {
        digest: Hex256,
        dest: PathBuf,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Location {
    digest: Hex256,
    path: PathBuf,
    file_id: FileId,
    recorded_at: Timestamp,
    mode: MaterializeMode,
}
#[derive(Debug, Serialize, Deserialize)]
struct IndexState {
    format_version: u32,
    store_id: StoreId,
    objects: BTreeMap<String, ObjectRow>,
    artifacts: BTreeMap<String, Artifact>,
    ingest_keys: BTreeMap<String, ArtifactId>,
    imports: BTreeMap<String, ArtifactId>,
    import_sources: BTreeMap<String, Value>,
    intents: BTreeMap<String, Intent>,
    locations: Vec<Location>,
}
impl IndexState {
    fn new(store_id: StoreId) -> Self {
        Self {
            format_version: 1,
            store_id,
            objects: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            ingest_keys: BTreeMap::new(),
            imports: BTreeMap::new(),
            import_sources: BTreeMap::new(),
            intents: BTreeMap::new(),
            locations: vec![],
        }
    }
    fn present_bytes(&self) -> u64 {
        self.objects
            .values()
            .filter(|o| o.state == ObjectState::Present)
            .map(|o| o.size_bytes)
            .sum()
    }
    fn get(&self, id: ArtifactId) -> Result<Artifact> {
        let mut artifact = self
            .artifacts
            .get(&id.to_string())
            .cloned()
            .ok_or(ArtifactError::NotFound)?;
        if let Some(object) = self.objects.get(&artifact.blake3.to_string()) {
            artifact.object.state = object.state;
            artifact.verification.state = object.verification;
            artifact.verification.checked_at = object.checked_at;
        }
        Ok(artifact)
    }
}
/// One owning process; methods are blocking and belong on a blocking task.
pub struct ArtifactStore {
    root: PathBuf,
    root_id: Option<FileId>,
    config: StoreConfig,
    fs: Arc<dyn Filesystem>,
    clock: SharedClock,
    audit: Option<Arc<dyn AuditSink>>,
    index: Arc<dyn ArtifactIndex>,
    writer: Mutex<()>,
    _lock: std::fs::File,
}
impl std::fmt::Debug for ArtifactStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArtifactStore")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}
impl ArtifactStore {
    /// Open a store, acquire exclusive ownership and finish durable operation intents before serving it.
    pub fn open(
        root: &Path,
        config: StoreConfig,
        fs: Arc<dyn Filesystem>,
        clock: SharedClock,
        audit: Option<Arc<dyn AuditSink>>,
    ) -> Result<Self> {
        ArtifactDraft::local(&config.product, &config.version, None)
            .record
            .validate()?;
        fs.create_dir_all(root)?;
        let root = fs.canonicalize(root)?;
        let root_id = fs.metadata(&root)?.and_then(|m| m.file_id);
        if !config.allow_cloud_root && zeus_fs::cloud::detect_cloud_synced(&root).is_some() {
            return Err(ArtifactError::LocationUnsuitable);
        }
        for path in &config.write_roots {
            let write = fs.canonicalize(path)?;
            if root.starts_with(&write) || write.starts_with(&root) {
                return Err(ArtifactError::LocationUnsuitable);
            }
        }
        for name in ["objects", "tmp", "damaged"] {
            let path = root.join(name);
            if fs
                .metadata(&path)?
                .is_some_and(|m| m.is_symlink || !m.is_dir)
            {
                return Err(ArtifactError::StoreCorrupt);
            }
            fs.create_dir_all(&path)?;
        }
        for name in ["store.lock", "index.redb", "store.json"] {
            if fs
                .metadata(&root.join(name))?
                .is_some_and(|m| !m.is_regular_file)
            {
                return Err(ArtifactError::StoreCorrupt);
            }
        }
        let mut lock_options = std::fs::OpenOptions::new();
        lock_options
            .read(true)
            .write(true)
            .create(true)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_options.mode(0o600);
        }
        let lock = lock_options.open(root.join("store.lock"))?;
        lock.try_lock().map_err(|_| ArtifactError::StoreLocked)?;
        let manifest_path = root.join("store.json");
        let manifest: Value = if fs.metadata(&manifest_path)?.is_some() {
            serde_json::from_slice(&std::fs::read(&manifest_path)?)?
        } else {
            let manifest = serde_json::json!({"format":"zeus-artifact-store","format_version":1,"store_id":IdGenerator::new().store_id(),"created_at":clock.now(),"created_by":{"product":config.product,"version":config.version,"library":concat!("zeus-artifact ",env!("CARGO_PKG_VERSION"))},"object_algorithm":"blake3","fanout":[2,2],"index":"redb"});
            let tmp = root.join(format!("store-{}.tmp", IdGenerator::new().next_ulid()));
            let file = fs.create_new(&tmp)?;
            file.write_all_at(0, &serde_json::to_vec(&manifest)?)?;
            file.sync_all()?;
            drop(file);
            fs.rename_noreplace(&tmp, &manifest_path)?;
            fs.sync_dir(&root)?;
            manifest
        };
        if manifest["format_version"] != 1 {
            return Err(ArtifactError::VersionUnsupported);
        }
        if manifest["format"] != "zeus-artifact-store"
            || manifest["object_algorithm"] != "blake3"
            || manifest["fanout"] != serde_json::json!([2, 2])
            || manifest["index"] != "redb"
        {
            return Err(ArtifactError::StoreCorrupt);
        }
        let id: StoreId = serde_json::from_value(manifest["store_id"].clone())?;
        let db = redb::Database::create(root.join("index.redb")).map_err(|e| match e {
            redb::DatabaseError::DatabaseAlreadyOpen => ArtifactError::StoreLocked,
            _ => ArtifactError::StoreCorrupt,
        })?;
        {
            let mut tx = db.begin_write().map_err(|_| ArtifactError::Index)?;
            tx.set_durability(redb::Durability::Immediate)
                .map_err(|_| ArtifactError::Index)?;
            {
                tx.open_table(SNAPSHOT).map_err(|_| ArtifactError::Index)?;
            }
            tx.commit().map_err(|_| ArtifactError::Index)?;
        }
        let index = Arc::new(RedbIndex(db));
        if index.read_snapshot()?.is_none() {
            index.commit_snapshot(&serde_json::to_vec(&IndexState::new(id))?)?;
        }
        let store = Self {
            root,
            root_id,
            config,
            fs,
            clock,
            audit,
            index,
            writer: Mutex::new(()),
            _lock: lock,
        };
        let state = store.load()?;
        if state.store_id != id || state.format_version != 1 {
            return Err(ArtifactError::StoreCorrupt);
        }
        store.recover()?;
        Ok(store)
    }
    /// Stable identity of this local store.
    pub fn store_id(&self) -> Result<StoreId> {
        Ok(self.load()?.store_id)
    }
    /// Store root, for trusted owner maintenance only.
    pub fn root(&self) -> &Path {
        &self.root
    }
    /// Canonical fan-out path computed only from validated digest bytes.
    pub fn object_path(&self, digest: Hex256) -> PathBuf {
        let text = digest.to_string();
        self.root
            .join("objects/blake3")
            .join(&text[..2])
            .join(&text[2..4])
            .join(text)
    }
    fn load(&self) -> Result<IndexState> {
        serde_json::from_slice(
            &self
                .index
                .read_snapshot()?
                .ok_or(ArtifactError::StoreCorrupt)?,
        )
        .map_err(Into::into)
    }
    fn commit(&self, state: &IndexState) -> Result<()> {
        self.index.commit_snapshot(&serde_json::to_vec(state)?)
    }
    fn guard(&self) -> Result<std::sync::MutexGuard<'_, ()>> {
        self.writer.lock().map_err(|_| ArtifactError::Index)
    }
    fn ensure_internal(&self, path: &Path) -> Result<()> {
        if self.fs.metadata(&self.root)?.and_then(|m| m.file_id) != self.root_id {
            return Err(ArtifactError::StoreCorrupt);
        }
        let relative = path
            .strip_prefix(&self.root)
            .map_err(|_| ArtifactError::StoreCorrupt)?;
        let mut current = self.root.clone();
        for component in relative.components() {
            if !matches!(component, std::path::Component::Normal(_)) {
                return Err(ArtifactError::StoreCorrupt);
            }
            current.push(component);
            if self.fs.metadata(&current)?.is_some_and(|m| m.is_symlink) {
                return Err(ArtifactError::StoreCorrupt);
            }
        }
        Ok(())
    }
    fn make_dirs(&self, path: &Path) -> Result<()> {
        self.ensure_internal(path)?;
        let mut missing = vec![];
        let mut current = path;
        while self.fs.metadata(current)?.is_none() {
            missing.push(current.to_path_buf());
            current = current.parent().ok_or(ArtifactError::StoreCorrupt)?;
        }
        self.fs.create_dir_all(path)?;
        for p in missing.iter().rev() {
            self.fs
                .sync_dir(p.parent().ok_or(ArtifactError::StoreCorrupt)?)?;
        }
        Ok(())
    }
    fn hash(&self, path: &Path) -> Result<Digests> {
        let file = self.fs.open_read(path)?;
        let size = file.len()?;
        let id = file.file_id()?;
        let mut offset = 0;
        let mut buffer = vec![0; 1 << 20];
        let mut hash = DualHasher::new();
        loop {
            let n = file.read_at(offset, &mut buffer)?;
            if n == 0 {
                break;
            }
            hash.update(&buffer[..n]);
            offset += n as u64;
        }
        if file.len()? != size || file.file_id()? != id || hash.size_bytes() != size {
            return Err(ArtifactError::DigestMismatch);
        }
        Ok(hash.finalize())
    }
    fn copy(&self, from: &Path, to: &Path) -> Result<()> {
        let input = self.fs.open_read(from)?;
        let output = self.fs.create_new(to)?;
        let mut offset = 0;
        let mut buffer = vec![0; 1 << 20];
        loop {
            let n = input.read_at(offset, &mut buffer)?;
            if n == 0 {
                break;
            }
            output.write_all_at(offset, &buffer[..n])?;
            offset += n as u64;
        }
        output.sync_all()?;
        Ok(())
    }
    fn remove_object_file(&self, path: &Path) -> Result<()> {
        self.ensure_internal(path)?;
        if self.fs.metadata(path)?.is_some() {
            self.fs.set_readonly(path, false)?;
            self.fs.remove_file(path)?;
            if let Some(parent) = path.parent() {
                self.fs.sync_dir(parent)?;
            }
        }
        Ok(())
    }
    fn audit(
        &self,
        action: &str,
        artifact: Option<&Artifact>,
        data: Value,
        write_ahead: bool,
    ) -> Result<()> {
        if let Some(audit) = &self.audit {
            let mut entry =
                AuditEntry::new(self.clock.now(), Actor::system(), action, AuditOutcome::Ok);
            entry.write_ahead = write_ahead;
            if let Some(a) = artifact {
                entry
                    .data
                    .insert("artifact_id".into(), Value::String(a.id.to_string()));
            }
            if let Value::Object(values) = data {
                entry.data.extend(values);
            }
            audit.append(entry)?;
        }
        Ok(())
    }
    fn prepare_record(
        &self,
        state: &IndexState,
        mut draft: ArtifactDraft,
        digests: Digests,
        verified: Option<Timestamp>,
    ) -> Result<Artifact> {
        let r = &mut draft.record;
        r.id = IdGenerator::new().artifact_id();
        r.store_id = state.store_id;
        r.created_at = self.clock.now();
        r.state = ArtifactState::Active;
        r.deleted_at = None;
        r.sha256 = digests.sha256;
        r.blake3 = digests.blake3;
        r.size_bytes = digests.size_bytes;
        r.object = CasObjectRef {
            algorithm: "blake3".into(),
            digest: r.blake3,
            size_bytes: r.size_bytes,
            state: ObjectState::Absent,
        };
        r.verification.state = if verified.is_some() {
            VerificationState::Verified
        } else {
            VerificationState::Unverified
        };
        r.verification.checked_at = verified;
        if let Some(name) = &r.name {
            r.name =
                Some(zeus_fs::sanitize_filename(name, &zeus_fs::SanitizeOptions::default())?.name);
        }
        for parent in &r.parents {
            if let Some(id) = parent.artifact_id {
                let p = state.get(id).map_err(|_| ArtifactError::LineageInvalid)?;
                if p.blake3 != parent.blake3
                    || p.sha256 != parent.sha256
                    || p.size_bytes != parent.size_bytes
                {
                    return Err(ArtifactError::LineageInvalid);
                }
            }
        }
        r.validate()?;
        Ok(draft.record)
    }
    fn register(
        &self,
        state: &mut IndexState,
        record: Artifact,
        key: Option<String>,
        present: bool,
        evidence: Option<ImportEvidence>,
    ) -> Result<Artifact> {
        let digest = record.blake3.to_string();
        let now = self.clock.now();
        if let Some(existing) = state.objects.get(&digest)
            && (existing.sha256 != record.sha256 || existing.size_bytes != record.size_bytes)
        {
            return Err(ArtifactError::DigestMismatch);
        }
        let row = state.objects.entry(digest).or_insert(ObjectRow {
            sha256: record.sha256,
            size_bytes: record.size_bytes,
            state: ObjectState::Absent,
            created_at: now,
            checked_at: record.verification.checked_at,
            verification: record.verification.state,
            last_access_at: now,
            unreferenced_since: None,
        });
        if present {
            row.state = ObjectState::Present;
            row.checked_at = Some(now);
            row.verification = VerificationState::Verified;
        } else if row.state != ObjectState::Damaged
            && record.verification.checked_at > row.checked_at
        {
            row.checked_at = record.verification.checked_at;
            row.verification = record.verification.state;
        }
        row.unreferenced_since = None;
        if let Some(key) = key {
            state.ingest_keys.insert(key, record.id);
        }
        if let Some(evidence) = evidence {
            state.imports.insert(
                format!("{}/{}", evidence.source_store, evidence.source_id),
                record.id,
            );
            state
                .import_sources
                .insert(record.id.to_string(), evidence.record);
        }
        let id = record.id;
        state.artifacts.insert(id.to_string(), record);
        self.commit(state)?;
        state.get(id)
    }
    /// Copy a readable file into immutable storage; the input remains independent and untouched.
    pub fn ingest(
        &self,
        source: &Path,
        draft: ArtifactDraft,
        key: Option<&str>,
    ) -> Result<Artifact> {
        self.ingest_expected(source, draft, key, None)
    }
    /// Ingest with an expected content triple; mismatches never create an artifact.
    pub fn ingest_expected(
        &self,
        source: &Path,
        draft: ArtifactDraft,
        key: Option<&str>,
        expected: Option<Digests>,
    ) -> Result<Artifact> {
        let _guard = self.guard()?;
        self.ingest_locked(source, draft, key, expected, None)
    }
    fn ingest_locked(
        &self,
        source: &Path,
        draft: ArtifactDraft,
        key: Option<&str>,
        expected: Option<Digests>,
        evidence: Option<ImportEvidence>,
    ) -> Result<Artifact> {
        self.ingest_input_locked(IngestSource::Path(source), draft, key, expected, evidence)
    }
    fn ingest_input_locked(
        &self,
        source: IngestSource<'_>,
        draft: ArtifactDraft,
        key: Option<&str>,
        expected: Option<Digests>,
        evidence: Option<ImportEvidence>,
    ) -> Result<Artifact> {
        validate_key(key)?;
        let mut state = self.load()?;
        if let Some(id) = key.and_then(|k| state.ingest_keys.get(k)) {
            return state.get(*id);
        }
        let source_len = match &source {
            IngestSource::Path(path) => {
                let meta = self.fs.metadata(path)?.ok_or(ArtifactError::ObjectAbsent)?;
                if !meta.is_regular_file {
                    return Err(ArtifactError::RecordInvalid(
                        "ingest requires a regular file",
                    ));
                }
                meta.len
            }
            IngestSource::Bytes(bytes) => bytes.len() as u64,
        };
        if self.config.quota_bytes.is_some_and(|q| source_len > q) {
            return Err(ArtifactError::QuotaExceeded);
        }
        if self.fs.free_space(&self.root)?.saturating_sub(source_len) < self.config.min_free_bytes {
            return Err(ArtifactError::QuotaExceeded);
        }
        let tmp = self
            .root
            .join("tmp")
            .join(format!("{}.zpart", IdGenerator::new().next_ulid()));
        self.ensure_internal(&tmp)?;
        let copied = match source {
            IngestSource::Path(path) => self.copy(path, &tmp),
            IngestSource::Bytes(bytes) => (|| -> Result<()> {
                let file = self.fs.create_new(&tmp)?;
                file.write_all_at(0, bytes)?;
                file.sync_all()?;
                Ok(())
            })(),
        };
        if let Err(error) = copied {
            let _ = self.fs.remove_file(&tmp);
            return Err(error);
        }
        let digests = match self.hash(&tmp) {
            Ok(d) => d,
            Err(e) => {
                let _ = self.fs.remove_file(&tmp);
                return Err(e);
            }
        };
        if expected.is_some_and(|d| d != digests) {
            self.fs.remove_file(&tmp)?;
            return Err(ArtifactError::DigestMismatch);
        }
        let existing = state.objects.get(&digests.blake3.to_string());
        if existing
            .is_some_and(|o| o.sha256 != digests.sha256 || o.size_bytes != digests.size_bytes)
        {
            self.fs.remove_file(&tmp)?;
            return Err(ArtifactError::DigestMismatch);
        }
        let record = match self.prepare_record(&state, draft, digests, Some(self.clock.now())) {
            Ok(r) => r,
            Err(e) => {
                self.fs.remove_file(&tmp)?;
                return Err(e);
            }
        };
        if existing.is_some_and(|o| o.state == ObjectState::Present) {
            self.fs.remove_file(&tmp)?;
            return self.register(&mut state, record, key.map(str::to_owned), false, evidence);
        }
        if self
            .config
            .quota_bytes
            .is_some_and(|q| state.present_bytes().saturating_add(digests.size_bytes) > q)
        {
            self.collect_locked(&mut state, true, 10_000)?;
            if self
                .config
                .quota_bytes
                .is_some_and(|q| state.present_bytes().saturating_add(digests.size_bytes) > q)
            {
                self.fs.remove_file(&tmp)?;
                return Err(ArtifactError::QuotaExceeded);
            }
        }
        let file = self.fs.open_existing(&tmp)?;
        file.sync_all()?;
        let file_id = file.file_id()?;
        drop(file);
        self.fs.set_readonly(&tmp, true)?;
        let intent_id = IdGenerator::new().next_ulid().to_string();
        state.intents.insert(
            intent_id.clone(),
            Intent::Ingest {
                record: Box::new(record.clone()),
                key: key.map(str::to_owned),
                tmp: tmp.clone(),
                file_id,
                evidence: evidence.clone(),
            },
        );
        self.commit(&state)?;
        let target = self.object_path(digests.blake3);
        self.make_dirs(target.parent().ok_or(ArtifactError::StoreCorrupt)?)?;
        if self.fs.metadata(&target)?.is_some() {
            if self.hash(&target)? == digests {
                let existing_id = self.fs.open_read(&target)?.file_id()?;
                if let Some(Intent::Ingest { file_id, .. }) = state.intents.get_mut(&intent_id) {
                    *file_id = existing_id;
                }
                self.commit(&state)?;
                self.remove_object_file(&tmp)?;
            } else {
                let damaged = self.root.join("damaged").join(format!(
                    "{}-{}",
                    digests.blake3,
                    IdGenerator::new().next_ulid()
                ));
                self.fs.set_readonly(&target, false)?;
                self.fs.rename_noreplace(&target, &damaged)?;
                self.fs.rename_noreplace(&tmp, &target)?;
            }
        } else {
            self.fs.rename_noreplace(&tmp, &target)?;
        }
        self.fs
            .sync_dir(target.parent().ok_or(ArtifactError::StoreCorrupt)?)?;
        state.intents.remove(&intent_id);
        self.register(&mut state, record, key.map(str::to_owned), true, evidence)
    }
    /// Register verified or externally claimed identity without storing a second copy of the bytes.
    pub fn ingest_record_only(
        &self,
        digests: Digests,
        draft: ArtifactDraft,
        key: Option<&str>,
        verified_at: Option<Timestamp>,
    ) -> Result<Artifact> {
        let _guard = self.guard()?;
        validate_key(key)?;
        let mut state = self.load()?;
        if let Some(id) = key.and_then(|k| state.ingest_keys.get(k)) {
            return state.get(*id);
        }
        let record = self.prepare_record(&state, draft, digests, verified_at)?;
        self.register(&mut state, record, key.map(str::to_owned), false, None)
    }
    /// Read a composed record; tombstones remain readable for lineage.
    pub fn get(&self, id: ArtifactId) -> Result<Artifact> {
        self.load()?.get(id)
    }
    /// List bounded records in stable identifier order.
    pub fn list(&self, filter: &ArtifactFilter) -> Result<Vec<Artifact>> {
        let state = self.load()?;
        state
            .artifacts
            .values()
            .filter(|a| filter.matches(a))
            .take(filter.bound())
            .map(|a| state.get(a.id))
            .collect()
    }
    /// List bounded records newest first, keeping only those `keep` accepts. The bound counts kept records,
    /// so a caller-side filter (visibility, digest) never hides newer records behind older ones.
    pub fn list_newest_where(
        &self,
        filter: &ArtifactFilter,
        mut keep: impl FnMut(&Artifact) -> bool,
    ) -> Result<Vec<Artifact>> {
        let state = self.load()?;
        let mut kept = Vec::new();
        for a in state.artifacts.values().rev().filter(|a| filter.matches(a)) {
            if kept.len() == filter.bound() {
                break;
            }
            let artifact = state.get(a.id)?;
            if keep(&artifact) {
                kept.push(artifact);
            }
        }
        Ok(kept)
    }
    /// Portable export with monotonic privacy reductions.
    pub fn export(&self, id: ArtifactId, privacy: &Privacy) -> Result<Artifact> {
        let mut record = self.get(id)?;
        reduce_privacy(&mut record, privacy)?;
        Ok(record)
    }
    /// Import a portable record, recomputing both digests whenever bytes are supplied.
    pub fn import(
        &self,
        received: &Value,
        source: Option<&Path>,
        exporter: &str,
        via: &str,
        retention: Retention,
    ) -> Result<Artifact> {
        let _guard = self.guard()?;
        self.import_locked(
            received,
            source.map(IngestSource::Path),
            ImportPolicy {
                exporter,
                via,
                retention,
                until: None,
                exact_source: false,
            },
        )
    }
    fn import_locked(
        &self,
        received: &Value,
        source: Option<IngestSource<'_>>,
        policy: ImportPolicy<'_>,
    ) -> Result<Artifact> {
        let ImportPolicy {
            exporter,
            via,
            retention,
            until,
            exact_source,
        } = policy;
        zeus_verify::canonical::check_hashable(received)?;
        let received_bytes = serde_json::to_vec(received)?;
        if received_bytes.len() > 256 << 10
            || received_bytes.windows(12).any(|w| w == b"ZEUS-CANARY-")
        {
            return Err(ArtifactError::RecordInvalid(
                "invalid import size or secret canary",
            ));
        }
        let original: Artifact = serde_json::from_value(received.clone())?;
        original.validate()?;
        if original.imports.len() >= 8 || !matches!(via, "api" | "export_file") {
            return Err(ArtifactError::RecordInvalid("invalid import hop"));
        }
        let mut state = self.load()?;
        let import_key = format!("{}/{}", original.store_id, original.id);
        if let Some(id) = state.imports.get(&import_key) {
            let saved = state.get(*id)?;
            if saved.digests() != original.digests()
                || (exact_source
                    && state.import_sources.get(&saved.id.to_string()) != Some(received))
            {
                return Err(ArtifactError::ImportConflict);
            }
            return Ok(saved);
        }
        let existing = state.objects.get(&original.blake3.to_string());
        if existing
            .is_some_and(|o| o.sha256 != original.sha256 || o.size_bytes != original.size_bytes)
        {
            return Err(ArtifactError::DigestMismatch);
        }
        let present = existing.is_some_and(|o| o.state == ObjectState::Present);
        let mut record = original.clone();
        // A foreign producer cannot clear this store's quarantine for equal bytes or known inputs.
        for known in state.artifacts.values().filter(|known| {
            known.quarantined
                && (known.blake3 == record.blake3
                    || original
                        .parents
                        .iter()
                        .any(|parent| parent.blake3 == known.blake3))
        }) {
            record.quarantined = true;
            for reason in &known.quarantine_reasons {
                if !record.quarantine_reasons.contains(reason) {
                    record.quarantine_reasons.push(*reason);
                }
            }
        }
        record.audit = None;
        record.retention = retention;
        record.retain_until = until;
        for parent in &mut record.parents {
            parent.artifact_id = parent.artifact_id.and_then(|id| {
                state
                    .imports
                    .get(&format!("{}/{}", original.store_id, id))
                    .copied()
            });
        }
        let record_hash =
            zeus_verify::hash::hash_bytes(&zeus_verify::canonical::to_jcs_bytes(received)?).blake3;
        record.imports.push(ImportRecord {
            imported_at: self.clock.now(),
            from: ImportSource {
                product: exporter.into(),
                store_id: original.store_id,
                artifact_id: original.id,
            },
            via: via.into(),
            object_mode: if present {
                "existing"
            } else if source.is_some() {
                "copy"
            } else {
                "none"
            }
            .into(),
            verified: present || source.is_some(),
            record_blake3: record_hash,
        });
        let evidence = Some(ImportEvidence {
            source_store: original.store_id,
            source_id: original.id,
            record: received.clone(),
        });
        let artifact = if !present && let Some(source) = source {
            self.ingest_input_locked(
                source,
                ArtifactDraft { record },
                None,
                Some(original.digests()),
                evidence,
            )?
        } else {
            let verified = existing.and_then(|o| o.checked_at);
            let record = self.prepare_record(
                &state,
                ArtifactDraft { record },
                original.digests(),
                verified,
            )?;
            self.register(&mut state, record, None, false, evidence)?
        };
        self.audit("artifact.imported",Some(&artifact),serde_json::json!({"from_product":exporter,"from_store_id":original.store_id,"from_artifact_id":original.id,"blake3":artifact.blake3,"sha256":artifact.sha256,"size_bytes":artifact.size_bytes,"record_blake3":record_hash}),false)?;
        Ok(artifact)
    }
    /// Materialize into a configured write root, using the first supported mode and no-replace rename.
    pub fn materialize(
        &self,
        id: ArtifactId,
        target: &Path,
        modes: &[MaterializeMode],
        os_mode: OsMetadataMode,
        allow_quarantined: bool,
    ) -> Result<MaterializeMode> {
        let _guard = self.guard()?;
        let mut state = self.load()?;
        let artifact = state.get(id)?;
        if artifact.state != ArtifactState::Active {
            return Err(ArtifactError::NotFound);
        }
        match artifact.object.state {
            ObjectState::Absent => return Err(ArtifactError::ObjectAbsent),
            ObjectState::Damaged => return Err(ArtifactError::ObjectDamaged),
            ObjectState::Present => {}
        }
        if artifact.quarantined && !allow_quarantined {
            return Err(ArtifactError::QuarantineBlocked);
        }
        let roots = WriteRoots::open(&self.config.write_roots)?;
        let root = roots.root_for(target)?;
        let target = root.check_existing(target)?;
        let parent = target.parent().ok_or(ArtifactError::LocationUnsuitable)?;
        self.fs.create_dir_all(parent)?;
        root.check_existing(&target)?;
        if self.fs.metadata(&target)?.is_some() {
            return Err(zeus_fs::FsError::AlreadyExists.into());
        }
        let tmp = zeus_fs::zpart_path(&target);
        if self.fs.metadata(&tmp)?.is_some() {
            return Err(zeus_fs::FsError::AlreadyExists.into());
        }
        let source = self.object_path(artifact.blake3);
        self.ensure_internal(&source)?;
        let intent_id = IdGenerator::new().next_ulid().to_string();
        let mut actual = None;
        state.intents.insert(
            intent_id.clone(),
            Intent::Materialize {
                artifact_id: id,
                tmp: tmp.clone(),
                dest: target.clone(),
                file_id: None,
                mode: MaterializeMode::Copy,
            },
        );
        self.commit(&state)?;
        for &mode in modes {
            let attempt = match mode {
                MaterializeMode::Copy => self.copy(&source, &tmp),
                MaterializeMode::Reflink => self.fs.reflink(&source, &tmp).map_err(Into::into),
                MaterializeMode::Hardlink if os_mode == OsMetadataMode::Off => {
                    self.fs.hard_link(&source, &tmp).map_err(Into::into)
                }
                MaterializeMode::Hardlink => continue,
            };
            match attempt {
                Ok(()) => {
                    actual = Some(mode);
                    break;
                }
                Err(ArtifactError::Fs(zeus_fs::FsError::Unsupported(_))) => continue,
                Err(e) => {
                    state.intents.remove(&intent_id);
                    self.commit(&state)?;
                    return Err(e);
                }
            }
        }
        let Some(mode) = actual else {
            state.intents.remove(&intent_id);
            self.commit(&state)?;
            return Err(ArtifactError::MaterializeUnsupported);
        };
        if self.hash(&tmp)? != artifact.digests() {
            self.fs.remove_file(&tmp)?;
            state.intents.remove(&intent_id);
            self.damage(&mut state, artifact.blake3)?;
            return Err(ArtifactError::ObjectDamaged);
        }
        if mode != MaterializeMode::Hardlink {
            self.fs.set_readonly(&tmp, false)?;
            if let ArtifactOrigin::Remote { url, referrer, .. } = &artifact.origin {
                use zeus_fs::provenance::ProvenanceMarker;
                let marks = zeus_fs::provenance::ProvenanceMarks {
                    origin_url: Some(strict(url)?),
                    referrer_url: referrer.as_ref().map(strict).transpose()?,
                    retrieved_at_unix_s: self.clock.now().unix_millis() / 1000,
                };
                match zeus_fs::provenance::NativeMarker.apply(&tmp, &marks, os_mode) {
                    Ok(_) => {}
                    Err(zeus_fs::FsError::Unsupported(_)) => {}
                    Err(e) => return Err(e.into()),
                }
            }
            self.fs.open_existing(&tmp)?.sync_all()?;
        }
        let file_id = self.fs.open_read(&tmp)?.file_id()?;
        state.intents.insert(
            intent_id.clone(),
            Intent::Materialize {
                artifact_id: id,
                tmp: tmp.clone(),
                dest: target.clone(),
                file_id: Some(file_id.clone()),
                mode,
            },
        );
        self.commit(&state)?;
        root.check_existing(&target)?;
        self.fs.rename_noreplace(&tmp, &target)?;
        self.fs.sync_dir(parent)?;
        state.locations.push(Location {
            digest: artifact.blake3,
            path: target,
            file_id,
            recorded_at: self.clock.now(),
            mode,
        });
        if let Some(object) = state.objects.get_mut(&artifact.blake3.to_string()) {
            object.last_access_at = self.clock.now();
        }
        state.intents.remove(&intent_id);
        self.commit(&state)?;
        self.audit("artifact.materialized",Some(&artifact),serde_json::json!({"mode":mode,"blake3":artifact.blake3,"size_bytes":artifact.size_bytes}),false)?;
        Ok(mode)
    }
    /// Tombstone provenance without deleting any user's file or materialization.
    pub fn delete(&self, id: ArtifactId) -> Result<()> {
        let _guard = self.guard()?;
        let mut state = self.load()?;
        let mut artifact = state.get(id)?;
        if artifact.state == ArtifactState::Deleted {
            return Ok(());
        }
        self.audit(
            "artifact.deleted",
            Some(&artifact),
            serde_json::json!({"blake3":artifact.blake3,"reason":"user_request"}),
            true,
        )?;
        artifact.state = ArtifactState::Deleted;
        artifact.deleted_at = Some(self.clock.now());
        state.artifacts.insert(id.to_string(), artifact.clone());
        if !state
            .artifacts
            .values()
            .any(|a| a.state == ArtifactState::Active && a.blake3 == artifact.blake3)
            && let Some(object) = state.objects.get_mut(&artifact.blake3.to_string())
        {
            object.unreferenced_since = Some(self.clock.now());
        }
        self.commit(&state)
    }
    /// Change retention; fixed content identity and provenance stay unchanged.
    pub fn set_retention(
        &self,
        id: ArtifactId,
        retention: Retention,
        until: Option<Timestamp>,
    ) -> Result<()> {
        let _guard = self.guard()?;
        let mut state = self.load()?;
        let artifact = state
            .artifacts
            .get_mut(&id.to_string())
            .ok_or(ArtifactError::NotFound)?;
        artifact.retention = retention;
        artifact.retain_until = until;
        let copy = artifact.clone();
        self.commit(&state)?;
        self.audit(
            "artifact.updated",
            Some(&copy),
            serde_json::json!({"fields":["retention","retain_until"]}),
            false,
        )
    }
    /// Change license after the embedding product verifies human authority.
    pub fn set_license(
        &self,
        id: ArtifactId,
        license: zeus_verify::provenance::LicenseInfo,
    ) -> Result<()> {
        let _guard = self.guard()?;
        let mut state = self.load()?;
        let artifact = state
            .artifacts
            .get_mut(&id.to_string())
            .ok_or(ArtifactError::NotFound)?;
        artifact.license = license;
        artifact.validate()?;
        let copy = artifact.clone();
        self.commit(&state)?;
        self.audit(
            "artifact.updated",
            Some(&copy),
            serde_json::json!({"fields":["license"]}),
            false,
        )
    }
    fn protected(&self, state: &IndexState) -> BTreeSet<String> {
        let now = self.clock.now();
        let mut protected: BTreeSet<_> = state
            .artifacts
            .values()
            .filter(|a| {
                a.state == ArtifactState::Active
                    && (a.retention == Retention::Keep || a.retain_until.is_some_and(|t| t > now))
            })
            .map(|a| a.blake3.to_string())
            .collect();
        for intent in state.intents.values() {
            match intent {
                Intent::Ingest { record, .. } => {
                    protected.insert(record.blake3.to_string());
                }
                Intent::Materialize { artifact_id, .. } => {
                    if let Ok(a) = state.get(*artifact_id) {
                        protected.insert(a.blake3.to_string());
                    }
                }
                _ => {}
            }
        }
        if self.config.keep_lineage_inputs {
            loop {
                let old = protected.len();
                for artifact in state.artifacts.values() {
                    if protected.contains(&artifact.blake3.to_string()) {
                        for parent in &artifact.parents {
                            protected.insert(parent.blake3.to_string());
                        }
                    }
                }
                if protected.len() == old {
                    break;
                }
            }
        }
        protected
    }
    /// Collect unreferenced objects; quota pressure additionally permits eviction of evictable content.
    pub fn collect_step(&self, quota_pressure: bool, limit: usize) -> Result<u64> {
        let _guard = self.guard()?;
        let mut state = self.load()?;
        self.collect_locked(&mut state, quota_pressure, limit)
    }
    fn collect_locked(&self, state: &mut IndexState, pressure: bool, limit: usize) -> Result<u64> {
        self.ensure_internal(&self.root.join("objects"))?;
        let protected = self.protected(state);
        let now = self.clock.now();
        let threshold = now
            .checked_sub(self.config.gc_grace)
            .unwrap_or(Timestamp::UNIX_EPOCH);
        let mut candidates: Vec<_> = state
            .objects
            .iter()
            .filter(|(digest, o)| {
                o.state == ObjectState::Present
                    && !protected.contains(*digest)
                    && (pressure || o.unreferenced_since.is_some_and(|t| t <= threshold))
            })
            .map(|(d, o)| (d.clone(), o.clone()))
            .collect();
        candidates.sort_by_key(|(_, o)| (o.last_access_at, o.created_at));
        candidates.truncate(limit.min(10_000));
        if candidates.is_empty() {
            return Ok(0);
        }
        let digests: Vec<_> = candidates.iter().map(|(d, _)| d).collect();
        let bytes: u64 = candidates.iter().map(|(_, o)| o.size_bytes).sum();
        self.audit("artifact.gc_sweep",None,serde_json::json!({"objects":candidates.len(),"bytes":bytes,"digests_blake3":zeus_verify::hash::hash_bytes(&zeus_verify::canonical::to_jcs_bytes(&digests)?).blake3,"reason":if pressure {"quota"} else {"unreferenced"}}),true)?;
        let mut removed = 0;
        for (key, object) in candidates {
            let digest: Hex256 = key.parse().map_err(|_| ArtifactError::StoreCorrupt)?;
            let intent_id = IdGenerator::new().next_ulid().to_string();
            state
                .objects
                .get_mut(&key)
                .ok_or(ArtifactError::StoreCorrupt)?
                .state = ObjectState::Absent;
            state
                .intents
                .insert(intent_id.clone(), Intent::Delete { digest });
            self.commit(state)?;
            self.remove_object_file(&self.object_path(digest))?;
            state.intents.remove(&intent_id);
            self.commit(state)?;
            removed += object.size_bytes;
        }
        Ok(removed)
    }
    fn damage(&self, state: &mut IndexState, digest: Hex256) -> Result<()> {
        let row = state
            .objects
            .get_mut(&digest.to_string())
            .ok_or(ArtifactError::ObjectAbsent)?;
        row.state = ObjectState::Damaged;
        row.verification = VerificationState::Failed;
        row.checked_at = Some(self.clock.now());
        let dest = self
            .root
            .join("damaged")
            .join(format!("{digest}-{}", IdGenerator::new().next_ulid()));
        let id = IdGenerator::new().next_ulid().to_string();
        state.intents.insert(
            id.clone(),
            Intent::Quarantine {
                digest,
                dest: dest.clone(),
            },
        );
        self.commit(state)?;
        let path = self.object_path(digest);
        if self.fs.metadata(&path)?.is_some() {
            self.ensure_internal(&path)?;
            self.fs.set_readonly(&path, false)?;
            self.fs.rename_noreplace(&path, &dest)?;
            self.fs
                .sync_dir(dest.parent().ok_or(ArtifactError::StoreCorrupt)?)?;
        }
        state.intents.remove(&id);
        self.commit(state)?;
        self.audit(
            "artifact.object_damaged",
            None,
            serde_json::json!({"blake3":digest,"found":"mismatch"}),
            false,
        )
    }
    /// Hash up to limit present objects, oldest checked first; damage invalidates every referring record.
    pub fn scrub_step(&self, limit: usize) -> Result<usize> {
        let _guard = self.guard()?;
        let mut state = self.load()?;
        let mut candidates: Vec<_> = state
            .objects
            .iter()
            .filter(|(_, o)| o.state == ObjectState::Present)
            .map(|(d, o)| (d.clone(), o.clone()))
            .collect();
        candidates.sort_by_key(|(_, o)| o.checked_at);
        candidates.truncate(limit.min(10_000));
        let count = candidates.len();
        for (key, object) in candidates {
            let digest: Hex256 = key.parse().map_err(|_| ArtifactError::StoreCorrupt)?;
            let expected = Digests {
                blake3: digest,
                sha256: object.sha256,
                size_bytes: object.size_bytes,
            };
            if self
                .hash(&self.object_path(digest))
                .is_ok_and(|d| d == expected)
            {
                let row = state
                    .objects
                    .get_mut(&key)
                    .ok_or(ArtifactError::StoreCorrupt)?;
                row.checked_at = Some(self.clock.now());
                row.verification = VerificationState::Verified;
                self.commit(&state)?;
            } else {
                self.damage(&mut state, digest)?;
            }
        }
        Ok(count)
    }
    /// Restore an absent or damaged object after recomputing the expected content triple.
    pub fn repair_from_file(&self, id: ArtifactId, source: &Path) -> Result<()> {
        let _guard = self.guard()?;
        self.repair_input_locked(id, IngestSource::Path(source))
    }
    /// Restore exact content from bytes already read through a retained, authorized source handle.
    /// Verify before staging; present content is checked rather than blindly accepted on recovery.
    pub fn repair_from_bytes(&self, id: ArtifactId, bytes: &[u8]) -> Result<()> {
        let _guard = self.guard()?;
        let record = self.load()?.get(id)?;
        if zeus_verify::hash::hash_bytes(bytes) != record.digests() {
            return Err(ArtifactError::DigestMismatch);
        }
        self.repair_input_locked(id, IngestSource::Bytes(bytes))
    }
    fn repair_input_locked(&self, id: ArtifactId, source: IngestSource<'_>) -> Result<()> {
        let mut state = self.load()?;
        let artifact = state.get(id)?;
        if artifact.state != ArtifactState::Active {
            return Err(ArtifactError::NotFound);
        }
        if artifact.object.state == ObjectState::Present {
            if self.hash(&self.object_path(artifact.blake3))? != artifact.digests() {
                return Err(ArtifactError::DigestMismatch);
            }
            return Ok(());
        }
        let tmp = self
            .root
            .join("tmp")
            .join(format!("{}.zpart", IdGenerator::new().next_ulid()));
        self.ensure_internal(&tmp)?;
        match source {
            IngestSource::Path(path) => self.copy(path, &tmp)?,
            IngestSource::Bytes(bytes) => {
                let file = self.fs.create_new(&tmp)?;
                file.write_all_at(0, bytes)?;
                file.sync_all()?;
            }
        }
        if self.hash(&tmp)? != artifact.digests() {
            self.fs.remove_file(&tmp)?;
            return Err(ArtifactError::DigestMismatch);
        }
        if self
            .config
            .quota_bytes
            .is_some_and(|q| state.present_bytes().saturating_add(artifact.size_bytes) > q)
        {
            self.fs.remove_file(&tmp)?;
            return Err(ArtifactError::QuotaExceeded);
        }
        let file = self.fs.open_existing(&tmp)?;
        file.sync_all()?;
        let file_id = file.file_id()?;
        drop(file);
        self.fs.set_readonly(&tmp, true)?;
        let intent = IdGenerator::new().next_ulid().to_string();
        state.intents.insert(
            intent.clone(),
            Intent::Ingest {
                record: Box::new(artifact.clone()),
                key: None,
                tmp: tmp.clone(),
                file_id,
                evidence: None,
            },
        );
        self.commit(&state)?;
        let target = self.object_path(artifact.blake3);
        self.make_dirs(target.parent().ok_or(ArtifactError::StoreCorrupt)?)?;
        self.fs.rename_noreplace(&tmp, &target)?;
        self.fs
            .sync_dir(target.parent().ok_or(ArtifactError::StoreCorrupt)?)?;
        state.intents.remove(&intent);
        self.register(&mut state, artifact.clone(), None, true, None)?;
        self.audit(
            "artifact.object_repaired",
            Some(&artifact),
            serde_json::json!({"blake3":artifact.blake3,"source":"location"}),
            false,
        )
    }
    /// Walk ancestors or descendants with cycle protection and protocol bounds.
    pub fn lineage(
        &self,
        id: ArtifactId,
        descendants: bool,
        max_depth: usize,
        max_nodes: usize,
    ) -> Result<Lineage> {
        let state = self.load()?;
        state.get(id)?;
        let depth_limit = max_depth.min(64);
        let node_limit = max_nodes.clamp(1, 10_000);
        let mut queue = std::collections::VecDeque::from([(id, 0)]);
        let mut seen = BTreeSet::new();
        let mut output = vec![];
        let mut truncated = false;
        while let Some((id, depth)) = queue.pop_front() {
            if !seen.insert(id) {
                continue;
            }
            if output.len() >= node_limit {
                truncated = true;
                break;
            }
            let record = state.get(id)?;
            let mut neighbors = vec![];
            if descendants {
                for candidate in state.artifacts.values() {
                    if candidate.parents.iter().any(|p| {
                        p.artifact_id == Some(id)
                            || (p.artifact_id.is_none()
                                && p.blake3 == record.blake3
                                && p.size_bytes == record.size_bytes)
                    }) {
                        neighbors.push(candidate.id);
                    }
                }
            } else {
                for parent in &record.parents {
                    if let Some(id) = parent.artifact_id {
                        neighbors.push(id);
                    } else {
                        neighbors.extend(
                            state
                                .artifacts
                                .values()
                                .filter(|a| {
                                    a.blake3 == parent.blake3 && a.size_bytes == parent.size_bytes
                                })
                                .map(|a| a.id),
                        );
                    }
                }
            }
            if depth >= depth_limit {
                truncated |= neighbors.iter().any(|n| !seen.contains(n));
            } else {
                queue.extend(neighbors.into_iter().map(|id| (id, depth + 1)));
            }
            output.push(record);
        }
        Ok(Lineage {
            artifacts: output,
            truncated,
        })
    }
    fn recover(&self) -> Result<()> {
        let _guard = self.guard()?;
        let mut state = self.load()?;
        for (id, intent) in state.intents.clone() {
            match intent {
                Intent::Ingest {
                    record,
                    key,
                    tmp,
                    file_id,
                    evidence,
                } => {
                    self.ensure_internal(&tmp)?;
                    let dest = self.object_path(record.blake3);
                    self.ensure_internal(&dest)?;
                    let is_ours = |path: &Path| {
                        self.fs.metadata(path).map(|m| {
                            m.is_some_and(|m| {
                                m.is_regular_file
                                    && m.len == record.size_bytes
                                    && m.file_id.as_ref() == Some(&file_id)
                            })
                        })
                    };
                    if is_ours(&dest)? {
                        self.fs
                            .sync_dir(dest.parent().ok_or(ArtifactError::StoreCorrupt)?)?;
                        state.intents.remove(&id);
                        self.register(&mut state, *record, key, true, evidence)?;
                    } else if is_ours(&tmp)? && self.fs.metadata(&dest)?.is_none() {
                        self.make_dirs(dest.parent().ok_or(ArtifactError::StoreCorrupt)?)?;
                        self.fs.rename_noreplace(&tmp, &dest)?;
                        self.fs
                            .sync_dir(dest.parent().ok_or(ArtifactError::StoreCorrupt)?)?;
                        state.intents.remove(&id);
                        self.register(&mut state, *record, key, true, evidence)?;
                    } else {
                        state.intents.remove(&id);
                        self.commit(&state)?;
                        if is_ours(&tmp)? {
                            self.remove_object_file(&tmp)?;
                        }
                    }
                }
                Intent::Delete { digest } => {
                    self.remove_object_file(&self.object_path(digest))?;
                    state.intents.remove(&id);
                    self.commit(&state)?;
                }
                Intent::Quarantine { digest, dest } => {
                    self.ensure_internal(&dest)?;
                    let source = self.object_path(digest);
                    if self.fs.metadata(&source)?.is_some() {
                        self.fs.set_readonly(&source, false)?;
                        self.fs.rename_noreplace(&source, &dest)?;
                    }
                    state.intents.remove(&id);
                    self.commit(&state)?;
                }
                Intent::Materialize {
                    artifact_id,
                    tmp,
                    dest,
                    file_id,
                    mode,
                } => {
                    if let Some(file_id) = file_id {
                        let roots = WriteRoots::open(&self.config.write_roots)?;
                        roots.root_for(&dest)?.check_existing(&dest)?;
                        let tmp_meta = self.fs.metadata(&tmp)?;
                        let dest_meta = self.fs.metadata(&dest)?;
                        if dest_meta.is_none()
                            && tmp_meta
                                .as_ref()
                                .is_some_and(|m| m.file_id.as_ref() == Some(&file_id))
                        {
                            self.fs.rename_noreplace(&tmp, &dest)?;
                        }
                        if self
                            .fs
                            .metadata(&dest)?
                            .is_some_and(|m| m.file_id.as_ref() == Some(&file_id))
                        {
                            self.fs.sync_dir(
                                dest.parent().ok_or(ArtifactError::LocationUnsuitable)?,
                            )?;
                            let a = state.get(artifact_id)?;
                            state.locations.push(Location {
                                digest: a.blake3,
                                path: dest,
                                file_id,
                                recorded_at: self.clock.now(),
                                mode,
                            });
                        }
                    }
                    state.intents.remove(&id);
                    self.commit(&state)?;
                }
            }
        }
        // Only store-owned temporary files can be discarded; external .zpart files with no identity are left for owner review.
        for entry in self.fs.read_dir(&self.root.join("tmp"))? {
            if entry.meta.is_symlink {
                return Err(ArtifactError::StoreCorrupt);
            }
            if entry.meta.is_regular_file {
                self.remove_object_file(&entry.path)?;
            }
        }
        Ok(())
    }
}
fn validate_key(key: Option<&str>) -> Result<()> {
    if key
        .is_some_and(|k| k.is_empty() || k.chars().count() > 128 || k.chars().any(char::is_control))
    {
        Err(ArtifactError::RecordInvalid("invalid ingest key"))
    } else {
        Ok(())
    }
}
fn strict(url: &RedactedUrl) -> Result<RedactedUrl> {
    RedactedUrl::new(
        &zeus_types::redact::redact_url(&url.to_string(), zeus_types::redact::RedactMode::Strict)
            .url,
    )
    .map_err(|_| ArtifactError::RecordInvalid("invalid redacted URL"))
}
fn reduce_privacy(record: &mut Artifact, requested: &Privacy) -> Result<()> {
    let prior = record.privacy.clone().unwrap_or(Privacy {
        url_query: zeus_verify::provenance::UrlQueryPrivacy::Sanitized,
        session_origin_included: true,
    });
    let drop_query = prior.url_query == zeus_verify::provenance::UrlQueryPrivacy::Dropped
        || requested.url_query == zeus_verify::provenance::UrlQueryPrivacy::Dropped;
    let session = prior.session_origin_included && requested.session_origin_included;
    if let ArtifactOrigin::Remote {
        url,
        final_url,
        url_redacted,
        referrer,
        session_origin,
        ..
    } = &mut record.origin
    {
        if drop_query {
            let old = url.to_string();
            *url = strict(url)?;
            *url_redacted |= old != url.to_string();
            let old = final_url.to_string();
            *final_url = strict(final_url)?;
            *url_redacted |= old != final_url.to_string();
            *referrer = referrer.as_ref().map(strict).transpose()?;
        }
        if !session {
            *session_origin = None;
        }
    }
    if drop_query {
        record.license.evidence_url = record
            .license
            .evidence_url
            .as_ref()
            .map(strict)
            .transpose()?;
    }
    record.privacy = Some(Privacy {
        url_query: if drop_query {
            zeus_verify::provenance::UrlQueryPrivacy::Dropped
        } else {
            zeus_verify::provenance::UrlQueryPrivacy::Sanitized
        },
        session_origin_included: session,
    });
    Ok(())
}
