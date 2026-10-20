//! Durable redb transactions. Each logical table stores versioned JSON rows with ordered keys.
use crate::{
    error::{JournalError, JournalResult},
    journal::JournalOptions,
    records::*,
    store::*,
};
use redb::{Durability, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Serialize, de::DeserializeOwned};
use std::path::{Path, PathBuf};
use zeus_control::RangeSet;
use zeus_types::*;

const TABLES: &[&str] = &[
    "meta",
    "jobs",
    "ranges",
    "unit_crc",
    "invalidations",
    "reservations",
    "events",
    "grants",
    "approvals",
    "approval_decisions",
    "idempotency",
];
fn table(name: &'static str) -> TableDefinition<'static, &'static str, &'static [u8]> {
    TableDefinition::new(name)
}
fn storage(e: impl std::fmt::Display) -> JournalError {
    JournalError::Storage(e.to_string())
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> JournalResult<T> {
    serde_json::from_slice(bytes).map_err(|e| JournalError::Decode(e.to_string()))
}
/// Every transaction is persisted before callers receive an acknowledgement.
pub const fn required_durability() -> Durability {
    Durability::Immediate
}

/// A database held exclusively by this process; transactions use redb's writer lock and MVCC snapshots.
#[derive(Debug)]
pub struct RedbStore {
    path: PathBuf,
    db: std::sync::RwLock<redb::Database>,
    options: JournalOptions,
}
impl RedbStore {
    /// Open the journal and initialize all tables atomically. Unknown schemas are refused.
    pub fn open(path: &Path, options: &JournalOptions) -> JournalResult<Self> {
        options.commit.validate()?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            zeus_fs::Filesystem::create_dir_all(&zeus_fs::RealFs, parent).map_err(storage)?;
        }
        let db = redb::Database::create(path).map_err(|e| match e {
            redb::DatabaseError::DatabaseAlreadyOpen => JournalError::AlreadyOpen,
            other => storage(other),
        })?;
        let store = Self {
            path: path.to_path_buf(),
            db: std::sync::RwLock::new(db),
            options: options.clone(),
        };
        let mut txn = store.write()?;
        if let Access::Write(ref w) = txn.access {
            for name in TABLES {
                w.open_table(table(name)).map_err(storage)?;
            }
        }
        match txn.get::<Meta>("meta", "store")? {
            Some(meta) if meta.schema_version > SCHEMA_VERSION => {
                return Err(JournalError::VersionUnsupported {
                    found: meta.schema_version,
                    supported: SCHEMA_VERSION,
                });
            }
            Some(meta) if meta.schema_version < SCHEMA_VERSION => {
                return Err(JournalError::Invariant(
                    "no migration exists for this journal schema",
                ));
            }
            Some(_) => {}
            None => txn.put(
                "meta",
                "store",
                &Meta {
                    schema_version: SCHEMA_VERSION,
                    store_id: IdGenerator::new().store_id(),
                    created_at: Timestamp::now(),
                    created_by: Some(format!("zeus-journal {}", env!("CARGO_PKG_VERSION"))),
                    kill_switch: KillSwitchState::default(),
                    last_event_seq: 0,
                    audit_cursor: 0,
                    manifest_cursor: 0,
                    artifact_cursor: 0,
                    audit_head: None,
                },
            )?,
        }
        Box::new(txn).commit()?;
        Ok(store)
    }
    /// Database path.
    pub fn path(&self) -> &Path {
        &self.path
    }
    /// Compact during maintenance. redb refuses compaction while any transaction is active.
    pub fn compact_if_needed(&self) -> JournalResult<bool> {
        self.db
            .write()
            .map_err(|_| JournalError::Poisoned)?
            .compact()
            .map_err(storage)
    }
    fn write(&self) -> JournalResult<Txn> {
        let mut txn = self
            .db
            .read()
            .map_err(|_| JournalError::Poisoned)?
            .begin_write()
            .map_err(storage)?;
        txn.set_durability(required_durability()).map_err(storage)?;
        txn.set_quick_repair(self.options.quick_repair);
        txn.set_two_phase_commit(self.options.two_phase_commit);
        Ok(Txn {
            access: Access::Write(Box::new(txn)),
        })
    }
}
impl JournalStore for RedbStore {
    fn begin_write(&self) -> JournalResult<Box<dyn WriteTxn + '_>> {
        Ok(Box::new(self.write()?))
    }
    fn begin_read(&self) -> JournalResult<Box<dyn ReadTxn + '_>> {
        Ok(Box::new(Txn {
            access: Access::Read(
                self.db
                    .read()
                    .map_err(|_| JournalError::Poisoned)?
                    .begin_read()
                    .map_err(storage)?,
            ),
        }))
    }
}
enum Access {
    Read(redb::ReadTransaction),
    Write(Box<redb::WriteTransaction>),
}
struct Txn {
    access: Access,
}
impl Txn {
    fn get<T: DeserializeOwned>(&self, name: &'static str, key: &str) -> JournalResult<Option<T>> {
        let bytes = match &self.access {
            Access::Read(t) => t
                .open_table(table(name))
                .map_err(storage)?
                .get(key)
                .map_err(storage)?
                .map(|v| v.value().to_vec()),
            Access::Write(t) => t
                .open_table(table(name))
                .map_err(storage)?
                .get(key)
                .map_err(storage)?
                .map(|v| v.value().to_vec()),
        };
        bytes.as_deref().map(decode).transpose()
    }
    fn rows<T: DeserializeOwned>(&self, name: &'static str) -> JournalResult<Vec<(String, T)>> {
        let bytes: Vec<(String, Vec<u8>)> = match &self.access {
            Access::Read(t) => t
                .open_table(table(name))
                .map_err(storage)?
                .iter()
                .map_err(storage)?
                .map(|v| {
                    v.map(|(k, v)| (k.value().to_owned(), v.value().to_vec()))
                        .map_err(storage)
                })
                .collect::<JournalResult<_>>()?,
            Access::Write(t) => t
                .open_table(table(name))
                .map_err(storage)?
                .iter()
                .map_err(storage)?
                .map(|v| {
                    v.map(|(k, v)| (k.value().to_owned(), v.value().to_vec()))
                        .map_err(storage)
                })
                .collect::<JournalResult<_>>()?,
        };
        bytes
            .into_iter()
            .map(|(k, v)| Ok((k, decode(&v)?)))
            .collect()
    }
    fn put<T: Serialize>(&mut self, name: &'static str, key: &str, value: &T) -> JournalResult<()> {
        let Access::Write(t) = &self.access else {
            return Err(JournalError::Invariant("write in read transaction"));
        };
        let bytes = serde_json::to_vec(value).map_err(storage)?;
        t.open_table(table(name))
            .map_err(storage)?
            .insert(key, bytes.as_slice())
            .map_err(storage)?;
        Ok(())
    }
    fn delete(&mut self, name: &'static str, key: &str) -> JournalResult<()> {
        let Access::Write(t) = &self.access else {
            return Err(JournalError::Invariant("write in read transaction"));
        };
        t.open_table(table(name))
            .map_err(storage)?
            .remove(key)
            .map_err(storage)?;
        Ok(())
    }
    fn replace_ranges(&mut self, job: JobId, ranges: &RangeSet, epoch: u32) -> JournalResult<()> {
        for (key, row) in self.rows::<RangeRow>("ranges")? {
            if row.job_id == job {
                self.delete("ranges", &key)?;
            }
        }
        for r in ranges.iter() {
            self.put(
                "ranges",
                &format!("{job}/{:020}", r.start),
                &RangeRow {
                    job_id: job,
                    start: r.start,
                    end: r.end,
                    epoch,
                },
            )?;
        }
        Ok(())
    }
}
impl ReadTxn for Txn {
    fn meta(&self) -> JournalResult<Meta> {
        self.get("meta", "store")?
            .ok_or(JournalError::NotFound { what: "meta" })
    }
    fn job(&self, id: JobId) -> JournalResult<Option<JobRecord>> {
        self.get("jobs", &id.to_string())
    }
    fn jobs(&self, filter: &JobFilter) -> JournalResult<Vec<JobRecord>> {
        Ok(self
            .rows::<JobRecord>("jobs")?
            .into_iter()
            .map(|(_, r)| r)
            .filter(|r| {
                filter
                    .states
                    .as_ref()
                    .is_none_or(|s| s.contains(&r.job.state))
                    && filter.after.is_none_or(|after| r.id() > after)
            })
            .take(filter.limit.unwrap_or(usize::MAX))
            .collect())
    }
    fn ranges(&self, job: JobId) -> JournalResult<RangeSet> {
        Ok(RangeSet::from_ranges(
            self.range_rows(job)?
                .into_iter()
                .map(|r| r.range())
                .collect::<Result<Vec<_>, _>>()?,
        ))
    }
    fn range_rows(&self, job: JobId) -> JournalResult<Vec<RangeRow>> {
        Ok(self
            .rows::<RangeRow>("ranges")?
            .into_iter()
            .map(|(_, r)| r)
            .filter(|r| r.job_id == job)
            .collect())
    }
    fn tail_unit_crcs(&self, job: JobId, limit: usize) -> JournalResult<Vec<UnitCrcRow>> {
        let mut rows = self.all_unit_crcs(job)?;
        let remove = rows.len().saturating_sub(limit);
        rows.drain(..remove);
        Ok(rows)
    }
    fn all_unit_crcs(&self, job: JobId) -> JournalResult<Vec<UnitCrcRow>> {
        Ok(self
            .rows::<UnitCrcRow>("unit_crc")?
            .into_iter()
            .map(|(_, r)| r)
            .filter(|r| r.job_id == job)
            .collect())
    }
    fn events_since(&self, after: Option<EventSeq>, limit: usize) -> JournalResult<Vec<Event>> {
        Ok(self
            .rows::<Event>("events")?
            .into_iter()
            .map(|(_, r)| r)
            .filter(|r| after.is_none_or(|a| r.seq.is_some_and(|s| s > a)))
            .take(limit)
            .collect())
    }
    fn invalidations(&self, job: JobId) -> JournalResult<Vec<InvalidationRow>> {
        Ok(self
            .rows::<InvalidationRow>("invalidations")?
            .into_iter()
            .map(|(_, r)| r)
            .filter(|r| r.job_id == job)
            .collect())
    }
    fn reservation(&self, key: &str) -> JournalResult<Option<ReservationRow>> {
        self.get("reservations", key)
    }
    fn reservations(&self) -> JournalResult<Vec<ReservationRow>> {
        Ok(self
            .rows("reservations")?
            .into_iter()
            .map(|(_, r)| r)
            .collect())
    }
    fn grant(&self, id: GrantId) -> JournalResult<Option<SessionGrant>> {
        self.get("grants", &id.to_string())
    }
    fn grants(&self) -> JournalResult<Vec<SessionGrant>> {
        Ok(self.rows("grants")?.into_iter().map(|(_, r)| r).collect())
    }
    fn approval(&self, id: ApprovalId) -> JournalResult<Option<Approval>> {
        self.get("approvals", &id.to_string())
    }
    fn approval_decision(&self, id: ApprovalId) -> JournalResult<Option<serde_json::Value>> {
        self.get("approval_decisions", &id.to_string())
    }
    fn approvals(&self, states: Option<&[ApprovalState]>) -> JournalResult<Vec<Approval>> {
        Ok(self
            .rows::<Approval>("approvals")?
            .into_iter()
            .map(|(_, r)| r)
            .filter(|r| states.is_none_or(|s| s.contains(&r.state)))
            .collect())
    }
    fn idempotency(&self, client: &str, key: &str) -> JournalResult<Option<IdempotencyRow>> {
        self.get(
            "idempotency",
            &serde_json::to_string(&(client, key)).map_err(storage)?,
        )
    }
}
impl WriteTxn for Txn {
    fn put_job(&mut self, record: &JobRecord) -> JournalResult<()> {
        self.put("jobs", &record.id().to_string(), record)
    }
    fn delete_job(&mut self, id: JobId) -> JournalResult<()> {
        self.delete("jobs", &id.to_string())
    }
    fn insert_range(&mut self, job: JobId, range: ByteRange, epoch: u32) -> JournalResult<u64> {
        let mut ranges = self.ranges(job)?;
        let added = ranges.insert(range);
        self.replace_ranges(job, &ranges, epoch)?;
        Ok(added)
    }
    fn remove_ranges(&mut self, job: JobId, range: Option<ByteRange>) -> JournalResult<u64> {
        let mut ranges = self.ranges(job)?;
        let removed = if let Some(r) = range {
            ranges.remove(r)
        } else {
            ranges.covered_bytes()
        };
        if range.is_none() {
            ranges.clear();
        }
        let epoch = self.job(job)?.map_or(0, |r| r.internal.epoch);
        self.replace_ranges(job, &ranges, epoch)?;
        Ok(removed)
    }
    fn put_unit_crc(&mut self, row: &UnitCrcRow) -> JournalResult<()> {
        self.put(
            "unit_crc",
            &format!("{}/{:020}", row.job_id, row.offset),
            row,
        )
    }
    fn remove_unit_crcs(&mut self, job: JobId) -> JournalResult<()> {
        for (key, row) in self.rows::<UnitCrcRow>("unit_crc")? {
            if row.job_id == job {
                self.delete("unit_crc", &key)?;
            }
        }
        Ok(())
    }
    fn put_invalidation(&mut self, row: &InvalidationRow) -> JournalResult<()> {
        let index = self.rows::<InvalidationRow>("invalidations")?.len();
        self.put("invalidations", &format!("{index:020}"), row)
    }
    fn put_reservation(&mut self, row: &ReservationRow) -> JournalResult<()> {
        if self
            .reservation(&row.path_key)?
            .is_some_and(|r| r.job_id != row.job_id)
        {
            return Err(JournalError::Invariant(
                "destination reserved by another job",
            ));
        }
        self.put("reservations", &row.path_key, row)
    }
    fn remove_reservation(&mut self, key: &str) -> JournalResult<()> {
        self.delete("reservations", key)
    }
    fn append_event(
        &mut self,
        ts: Timestamp,
        job: Option<JobId>,
        run: Option<RunId>,
        payload: EventPayload,
    ) -> JournalResult<Event> {
        if payload.kind().is_none_or(|k| !k.is_durable()) {
            return Err(JournalError::Invariant("non-durable event in journal"));
        }
        let mut meta = self.meta()?;
        meta.last_event_seq = meta
            .last_event_seq
            .checked_add(1)
            .ok_or(JournalError::Invariant("event sequence exhausted"))?;
        let mut event = Event::durable(EventSeq::new(meta.last_event_seq)?, ts, payload);
        event.job_id = job;
        event.run_id = run;
        event.validate()?;
        self.put("events", &format!("{:020}", meta.last_event_seq), &event)?;
        self.put("meta", "store", &meta)?;
        Ok(event)
    }
    fn prune_events(&mut self, through: EventSeq) -> JournalResult<u64> {
        let meta = self.meta()?;
        let cap = through
            .get()
            .min(meta.audit_cursor)
            .min(meta.manifest_cursor)
            .min(meta.artifact_cursor);
        let mut removed = 0;
        for (key, event) in self.rows::<Event>("events")? {
            if event.seq.is_some_and(|s| s.get() <= cap) {
                self.delete("events", &key)?;
                removed += 1;
            }
        }
        Ok(removed)
    }
    fn put_grant(&mut self, grant: &SessionGrant) -> JournalResult<()> {
        self.put("grants", &grant.id.to_string(), grant)
    }
    fn put_approval(&mut self, approval: &Approval) -> JournalResult<()> {
        self.put("approvals", &approval.id.to_string(), approval)
    }
    fn put_approval_decision(
        &mut self,
        id: ApprovalId,
        decision: &serde_json::Value,
    ) -> JournalResult<()> {
        if !decision.is_object() || serde_json::to_vec(decision).map_err(storage)?.len() > 64 * 1024
        {
            return Err(JournalError::Invariant(
                "approval decision must be an object at most 64 KiB",
            ));
        }
        let approval = self
            .approval(id)?
            .ok_or(JournalError::Invariant("decision approval is missing"))?;
        let outcome = match approval.state {
            ApprovalState::Approved => "approve",
            ApprovalState::Denied => "deny",
            ApprovalState::Expired => "expire",
            ApprovalState::Canceled => "cancel",
            ApprovalState::Pending => {
                return Err(JournalError::Invariant("decision approval is pending"));
            }
        };
        if decision["approval_id"].as_str() != Some(id.to_string().as_str())
            || decision["outcome"].as_str() != Some(outcome)
            || approval
                .revision
                .is_some_and(|revision| decision["revision"].as_u64() != Some(u64::from(revision)))
            || approval.request_hash.as_ref().is_some_and(|hash| {
                decision["request_hash"]
                    != serde_json::to_value(hash).unwrap_or(serde_json::Value::Null)
            })
        {
            return Err(JournalError::Invariant(
                "approval decision does not match approved facts",
            ));
        }
        if self
            .approval_decision(id)?
            .is_some_and(|existing| existing != *decision)
        {
            return Err(JournalError::Invariant("approval decision is immutable"));
        }
        self.put("approval_decisions", &id.to_string(), decision)
    }
    fn put_idempotency(&mut self, row: &IdempotencyRow) -> JournalResult<()> {
        let key = serde_json::to_string(&(&row.client_id, &row.key)).map_err(storage)?;
        if let Some(previous) = self.get::<IdempotencyRow>("idempotency", &key)?
            && previous != *row
        {
            return Err(JournalError::Invariant("idempotency key already bound"));
        }
        self.put("idempotency", &key, row)
    }
    fn expire_idempotency(&mut self, now: Timestamp) -> JournalResult<u64> {
        let mut n = 0;
        for (key, row) in self.rows::<IdempotencyRow>("idempotency")? {
            if row.expires_at <= now && self.job(row.job_id)?.is_none() {
                self.delete("idempotency", &key)?;
                n += 1;
            }
        }
        Ok(n)
    }
    fn set_kill_switch(&mut self, engaged: bool) -> JournalResult<()> {
        let mut meta = self.meta()?;
        meta.kill_switch = KillSwitchState {
            engaged,
            changed_at: Timestamp::now(),
        };
        self.put("meta", "store", &meta)
    }
    fn set_audit_head(&mut self, head: Option<AuditHead>) -> JournalResult<()> {
        let mut meta = self.meta()?;
        if let (Some(a), Some(b)) = (&meta.audit_head, &head)
            && (a.chain_id != b.chain_id || b.seq < a.seq)
        {
            return Err(JournalError::Invariant("audit head moved backwards"));
        }
        meta.audit_head = head;
        self.put("meta", "store", &meta)
    }
    fn set_cursors(&mut self, audit: u64, manifest: u64) -> JournalResult<()> {
        let mut meta = self.meta()?;
        if audit < meta.audit_cursor
            || manifest < meta.manifest_cursor
            || manifest > audit
            || audit > meta.last_event_seq
        {
            return Err(JournalError::Invariant("invalid outbox cursors"));
        }
        meta.audit_cursor = audit;
        meta.manifest_cursor = manifest;
        self.put("meta", "store", &meta)
    }
    fn set_artifact_cursor(&mut self, cursor: u64) -> JournalResult<()> {
        let mut meta = self.meta()?;
        if cursor < meta.artifact_cursor || cursor > meta.audit_cursor {
            return Err(JournalError::Invariant("invalid artifact cursor"));
        }
        meta.artifact_cursor = cursor;
        self.put("meta", "store", &meta)
    }
    fn commit(self: Box<Self>) -> JournalResult<()> {
        match self.access {
            Access::Write(t) => t
                .commit()
                .map_err(|e| JournalError::CommitAmbiguous(e.to_string())),
            Access::Read(_) => Err(JournalError::Invariant("commit read transaction")),
        }
    }
    fn rollback(self: Box<Self>) -> JournalResult<()> {
        match self.access {
            Access::Write(t) => t.abort().map_err(storage),
            Access::Read(_) => Ok(()),
        }
    }
}
