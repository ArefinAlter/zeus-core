//! The hash-chained, append-only audit log (04 section 4).
//!
//! Each record is canonical JSON (RFC 8785) and carries `prev_hash` and `hash`:
//!
//! ```text
//! hash = BLAKE3( prev_hash_bytes || JCS(record without "hash") )
//! genesis prev_hash = BLAKE3( "zeus.audit.genesis.v1" || chain_id )
//! ```
//!
//! This module provides the typed record, the pure chain functions (genesis, record hash, chain
//! verification over parsed records, verified against the published test vectors of 04 section 4.7),
//! an in-memory chain writer for tests, and the API of the file-backed log whose rotation, fsync
//! policy, torn-tail recovery and anchors are filled in by the implementation task.
//!
//! The chain proves consistency, not authorship: an attacker who can write the log can recompute every
//! hash (04 section 5). Keyed mode (a BLAKE3 key from the OS keyring) and external anchors narrow that.
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: AuditLog and verify_dir are filled in by the zeus-verify implementation task"
)]

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeus_types::{
    Actor, ApprovalId, AuditHead, ChainId, GrantId, Hex256, JobId, Origin, RedactedUrl, RunId,
    SessionLeaseId, StoreId, Timestamp,
};

use crate::canonical::{check_hashable, to_jcs_bytes};
use crate::error::{AuditFailure, AuditFailureKind, VerifyError, VerifyResult};

/// The prefix hashed into a chain's genesis `prev_hash`.
pub const GENESIS_PREFIX: &str = "zeus.audit.genesis.v1";

/// Action names (04 section 4.4) and which of them are write-ahead.
pub mod actions {
    macro_rules! actions {
        ($($name:ident = $text:literal, $write_ahead:literal;)*) => {
            $( #[doc = concat!("`", $text, "`.")] pub const $name: &str = $text; )*
            /// Every registered action with its write-ahead flag. `tool.call` is write-ahead only for
            /// mutating calls, which the caller decides; it is listed as `false` here.
            pub const REGISTRY: &[(&str, bool)] = &[ $( ($text, $write_ahead), )* ];
        };
    }
    actions! {
        CHAIN_STARTED = "audit.chain_started", false;
        ROTATED = "audit.rotated", false;
        CHECKPOINT = "audit.checkpoint", false;
        RECOVERED = "audit.recovered", false;
        DAEMON_STARTED = "daemon.started", false;
        DAEMON_STOPPING = "daemon.stopping", false;
        CLIENT_CONNECTED = "client.connected", false;
        CLIENT_REJECTED = "client.rejected", false;
        TOOL_CALL = "tool.call", false;
        APPROVAL_REQUESTED = "approval.requested", false;
        APPROVAL_DECIDED = "approval.decided", true;
        GRANT_CREATED = "grant.created", true;
        GRANT_REVOKED = "grant.revoked", true;
        GRANT_EXPIRED = "grant.expired", false;
        SESSION_LEASE_REQUESTED = "session.lease_requested", true;
        SESSION_LEASED = "session.leased", false;
        SESSION_DENIED = "session.denied", false;
        JOB_CREATED = "job.created", false;
        JOB_COMPLETED = "job.completed", false;
        FILE_FINALIZED = "file.finalized", false;
        JOB_FAILED = "job.failed", false;
        JOB_CANCELED = "job.canceled", false;
        FILE_CONVERTED = "file.converted", false;
        FILE_MOVED = "file.moved", true;
        FILE_DELETED = "file.deleted", true;
        FILE_RENAMED = "file.renamed", true;
        POLICY_DENIED = "policy.denied", false;
        CONFIG_CHANGED = "config.changed", true;
        AUDIT_VERIFY = "audit.verify", false;
        AUDIT_ERROR = "audit.error", false;
    }

    /// True when `action` is a write-ahead action: the record MUST be durably appended **before** the
    /// act it describes takes place.
    #[must_use]
    pub fn is_write_ahead(action: &str) -> bool {
        REGISTRY.iter().any(|(a, wa)| *a == action && *wa)
    }
}

/// The result recorded in a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// The act happened.
    Ok,
    /// The act was refused.
    Denied,
    /// The act failed.
    Error,
}

/// What a record concerned. Only redacted URLs: never a raw URL, a cookie or a token.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSubject {
    /// The job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<JobId>,
    /// The run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    /// The grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<GrantId>,
    /// The approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
    /// The session lease handle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<SessionLeaseId>,
    /// The origin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    /// The URL after `redact_url(record)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_redacted: Option<RedactedUrl>,
    /// A file path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// One line of the log (`audit-record.v1.schema.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Record format version; always 1.
    pub v: u8,
    /// 1, 2, 3, ... gapless within a chain.
    pub seq: u64,
    /// Wall-clock time; `seq` is the order of record.
    pub ts: Timestamp,
    /// Who did it.
    pub actor: Actor,
    /// Dotted action name from [`actions`].
    pub action: String,
    /// What it concerned.
    pub subject: AuditSubject,
    /// The result.
    pub outcome: AuditOutcome,
    /// Action-specific facts: integers only, at most 32 KiB, never secrets.
    pub data: Map<String, Value>,
    /// The previous record's `hash`, or the genesis hash.
    pub prev_hash: Hex256,
    /// This record's hash.
    pub hash: Hex256,
}

/// A record before it is chained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// Wall-clock time to stamp.
    pub ts: Timestamp,
    /// Who did it.
    pub actor: Actor,
    /// Dotted action name.
    pub action: String,
    /// What it concerned.
    pub subject: AuditSubject,
    /// The result.
    pub outcome: AuditOutcome,
    /// Action-specific facts (integers only, no secrets).
    pub data: Map<String, Value>,
    /// Write-ahead: the record is durable (written and fsynced) before `append` returns, and the caller
    /// acts only afterwards. Defaults from [`actions::is_write_ahead`] when built with [`AuditEntry::new`].
    pub write_ahead: bool,
}

impl AuditEntry {
    /// An entry with an empty subject and data; `write_ahead` follows the action registry.
    #[must_use]
    pub fn new(ts: Timestamp, actor: Actor, action: &str, outcome: AuditOutcome) -> Self {
        Self {
            ts,
            actor,
            action: action.to_owned(),
            subject: AuditSubject::default(),
            outcome,
            data: Map::new(),
            write_ahead: actions::is_write_ahead(action),
        }
    }
}

/// The destination the engine and the daemon write audit records to.
pub trait AuditSink: Send + Sync {
    /// Chains and appends `entry`. For a write-ahead entry the record is durable when this returns;
    /// if it cannot be made durable the call fails with `audit.unavailable` and the caller MUST NOT
    /// proceed with the act (04 section 4.6 item 8).
    fn append(&self, entry: AuditEntry) -> VerifyResult<AuditRecord>;

    /// The current head, or `None` before the first record.
    fn head(&self) -> VerifyResult<Option<AuditHead>>;
}

// ------------------------------------------------------------------ pure chain functions

fn hash_with(key: Option<&[u8; 32]>, data: &[u8]) -> Hex256 {
    let digest = match key {
        Some(k) => blake3::keyed_hash(k, data),
        None => blake3::hash(data),
    };
    Hex256::from_bytes(*digest.as_bytes())
}

/// The `prev_hash` of the first record of a chain: `BLAKE3(UTF-8("zeus.audit.genesis.v1" || chain_id))`,
/// keyed when the chain is keyed (04 section 4.3 items 4 and 6).
#[must_use]
pub fn genesis_hash(chain_id: &ChainId, key: Option<&[u8; 32]>) -> Hex256 {
    hash_with(key, format!("{GENESIS_PREFIX}{chain_id}").as_bytes())
}

/// The hash of a record given the previous hash and the record as parsed JSON. The `hash` member, if
/// present, is excluded (04 section 4.3 item 1).
pub fn record_hash(
    prev_hash: &Hex256,
    record: &Value,
    key: Option<&[u8; 32]>,
) -> VerifyResult<Hex256> {
    let mut body = record.clone();
    let Value::Object(map) = &mut body else {
        return Err(VerifyError::Invalid(
            "an audit record must be a JSON object",
        ));
    };
    map.remove("hash");
    check_hashable(&body)?;
    let mut data = Vec::with_capacity(32 + 256);
    data.extend_from_slice(prev_hash.as_bytes());
    data.extend_from_slice(&to_jcs_bytes(&body)?);
    Ok(hash_with(key, &data))
}

/// Where a verification starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStart {
    /// The first record must be `audit.chain_started` with `seq` 1 and a valid genesis `prev_hash`.
    Genesis,
    /// Verification starts mid-chain (older files were pruned): the first record must have
    /// `seq == anchor.seq + 1` and `prev_hash == anchor.hash`.
    After(AuditHead),
}

/// Verifies a sequence of parsed records and returns the head (the last record's `chain_id`, `seq`
/// and `hash`). Implements the per-record checks of 04 section 4.5: shape, sequence, link, hash.
/// File-level checks (rotation, anchors, journal head) belong to [`verify_dir`].
pub fn verify_records<'a>(
    records: impl IntoIterator<Item = &'a Value>,
    start: &ChainStart,
    key: Option<&[u8; 32]>,
) -> Result<Option<AuditHead>, AuditFailure> {
    let mut expect_seq: Option<u64> = None;
    let mut prev: Option<Hex256> = None;
    let mut chain_id: Option<ChainId> = None;
    let mut head: Option<AuditHead> = None;

    if let ChainStart::After(anchor) = start {
        expect_seq = Some(anchor.seq + 1);
        prev = Some(anchor.hash);
        chain_id = Some(anchor.chain_id);
    }

    for value in records {
        let record: AuditRecord = serde_json::from_value(value.clone())
            .map_err(|_| AuditFailure::of(AuditFailureKind::TornOrMalformed))?;
        if record.v != 1 {
            return Err(AuditFailure::at(
                AuditFailureKind::TornOrMalformed,
                record.seq,
            ));
        }
        let (seq_expected, prev_expected) = match (expect_seq, prev) {
            (Some(s), Some(p)) => (s, p),
            _ => {
                // First record of a genesis verification.
                let id = value["data"]["chain_id"]
                    .as_str()
                    .and_then(|s| s.parse::<ChainId>().ok());
                if record.action != actions::CHAIN_STARTED || record.seq != 1 {
                    return Err(AuditFailure::at(AuditFailureKind::BadGenesis, record.seq));
                }
                let Some(id) = id else {
                    return Err(AuditFailure::at(AuditFailureKind::BadGenesis, record.seq));
                };
                if record.prev_hash != genesis_hash(&id, key) {
                    return Err(AuditFailure::at(AuditFailureKind::BadGenesis, record.seq));
                }
                chain_id = Some(id);
                (1, record.prev_hash)
            }
        };
        if record.seq != seq_expected {
            return Err(AuditFailure::at(AuditFailureKind::SeqGap, record.seq));
        }
        if record.prev_hash != prev_expected {
            return Err(AuditFailure::at(AuditFailureKind::PrevMismatch, record.seq));
        }
        let computed = record_hash(&record.prev_hash, value, key)
            .map_err(|_| AuditFailure::at(AuditFailureKind::TornOrMalformed, record.seq))?;
        if computed != record.hash {
            return Err(AuditFailure::at(AuditFailureKind::HashMismatch, record.seq));
        }
        prev = Some(record.hash);
        expect_seq = Some(record.seq + 1);
        if let Some(id) = chain_id {
            head = Some(AuditHead {
                chain_id: id,
                seq: record.seq,
                hash: record.hash,
            });
        }
    }
    Ok(head)
}

// ------------------------------------------------------------------ in-memory writer

/// A chain kept in memory: the reference writer used by tests and by embedders that do not want files.
/// Hashing is real, so everything it produces verifies with [`verify_records`].
#[derive(Debug)]
pub struct MemoryAuditLog {
    chain_id: ChainId,
    key: Option<[u8; 32]>,
    records: Mutex<Vec<AuditRecord>>,
}

impl MemoryAuditLog {
    /// Starts a chain: writes the genesis record `audit.chain_started` (04 section 4.3 item 4).
    #[must_use]
    pub fn new(
        chain_id: ChainId,
        store_id: StoreId,
        zeus_version: &str,
        ts: Timestamp,
        key: Option<[u8; 32]>,
    ) -> Self {
        let log = Self {
            chain_id,
            key,
            records: Mutex::new(Vec::new()),
        };
        let mut entry = AuditEntry::new(
            ts,
            Actor::system(),
            actions::CHAIN_STARTED,
            AuditOutcome::Ok,
        );
        entry
            .data
            .insert("chain_id".into(), Value::String(chain_id.to_string()));
        entry.data.insert(
            "zeus_version".into(),
            Value::String(zeus_version.to_owned()),
        );
        entry
            .data
            .insert("store_id".into(), Value::String(store_id.to_string()));
        entry
            .data
            .insert("keyed".into(), Value::Bool(key.is_some()));
        // Cannot fail: the entry is built from valid values above.
        let _ = log.append(entry);
        log
    }

    /// All records so far, as JSON values (what a reader of the file would see).
    #[must_use]
    pub fn to_values(&self) -> Vec<Value> {
        let records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        records
            .iter()
            .filter_map(|r| serde_json::to_value(r).ok())
            .collect()
    }
}

impl AuditSink for MemoryAuditLog {
    fn append(&self, entry: AuditEntry) -> VerifyResult<AuditRecord> {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (seq, prev_hash) = match records.last() {
            Some(last) => (last.seq + 1, last.hash),
            None => (1, genesis_hash(&self.chain_id, self.key.as_ref())),
        };
        let mut record = AuditRecord {
            v: 1,
            seq,
            ts: entry.ts,
            actor: entry.actor,
            action: entry.action,
            subject: entry.subject,
            outcome: entry.outcome,
            data: entry.data,
            prev_hash,
            hash: prev_hash,
        };
        let value = serde_json::to_value(&record)?;
        record.hash = record_hash(&prev_hash, &value, self.key.as_ref())?;
        records.push(record.clone());
        Ok(record)
    }

    fn head(&self) -> VerifyResult<Option<AuditHead>> {
        let records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(records.last().map(|r| AuditHead {
            chain_id: self.chain_id,
            seq: r.seq,
            hash: r.hash,
        }))
    }
}

// ------------------------------------------------------------------ file-backed log (to implement)

/// Options of the file-backed log.
#[derive(Debug, Clone)]
pub struct AuditOptions {
    /// Keyed BLAKE3 chain key from the OS keyring (`zeus-audit-chain`); `None` for the plain chain.
    pub key: Option<[u8; 32]>,
    /// Rotate when the active file reaches this size (default 64 MiB) or the UTC date changes.
    pub rotate_bytes: u64,
    /// Batched fsync after this many records (default 64) ...
    pub fsync_every_records: u32,
    /// ... or this many bytes (default 64 KiB) ...
    pub fsync_every_bytes: u64,
    /// ... or this long (default 1 s), whichever comes first. Write-ahead records flush at once.
    pub fsync_every_ms: u64,
    /// Keep files at least this many days before pruning (default 365).
    pub retention_days: u32,
}

impl Default for AuditOptions {
    fn default() -> Self {
        Self {
            key: None,
            rotate_bytes: 64 << 20,
            fsync_every_records: 64,
            fsync_every_bytes: 64 << 10,
            fsync_every_ms: 1000,
            retention_days: 365,
        }
    }
}

/// The file-backed log: `<state>/audit/audit-<index>.jsonl`, one writer, one record per `write` call
/// with `O_APPEND`, torn-tail recovery, rotation with `audit.checkpoint` and `audit.rotated`, and
/// `audit/anchor.json` when old files are pruned (04 sections 4.1 and 4.6).
#[derive(Debug)]
pub struct AuditLog {
    dir: PathBuf,
    options: AuditOptions,
}

impl AuditLog {
    /// Opens (or creates, writing the genesis record) the log in `dir`, recovering a torn tail
    /// (`audit.recovered`) and taking the directory lock.
    pub fn open(
        dir: &Path,
        chain_id: Option<ChainId>,
        store_id: StoreId,
        zeus_version: &str,
        options: AuditOptions,
    ) -> VerifyResult<Self> {
        Err(VerifyError::NotImplemented("AuditLog::open"))
    }
}

impl AuditSink for AuditLog {
    fn append(&self, entry: AuditEntry) -> VerifyResult<AuditRecord> {
        Err(VerifyError::NotImplemented("AuditLog::append"))
    }

    fn head(&self) -> VerifyResult<Option<AuditHead>> {
        Err(VerifyError::NotImplemented("AuditLog::head"))
    }
}

/// Inputs of a full verification run (`zeus audit verify`).
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    /// A trusted `(seq, hash)` from `audit/anchor.json`, an external anchor or a manifest pointer.
    pub anchor: Option<AuditHead>,
    /// The journal's `meta.audit_head`; a head ahead of the log is `tail_truncated`.
    pub journal_head: Option<AuditHead>,
    /// The chain key for keyed chains.
    pub key: Option<[u8; 32]>,
}

/// What a successful verification found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// Records verified.
    pub records: u64,
    /// The head after the last record.
    pub head: Option<AuditHead>,
    /// Non-fatal observations, for example a backward `ts` jump of more than five minutes.
    pub warnings: Vec<String>,
}

/// Verifies every `audit-*.jsonl` file in `dir` in index order: per-record checks, rotation
/// continuity, the anchor and the journal head (04 section 4.5).
pub fn verify_dir(dir: &Path, options: &VerifyOptions) -> VerifyResult<VerifyReport> {
    Err(VerifyError::NotImplemented("verify_dir"))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde_json::json;

    use super::*;

    const CHAIN_ID: &str = "chain_01M3TC5H007DRT2QA1P1NY311K";

    #[test]
    fn genesis_matches_the_published_vector() {
        let id = ChainId::from_str(CHAIN_ID).unwrap();
        assert_eq!(
            genesis_hash(&id, None).to_hex(),
            "d2f842db12929eb9a0c5f557bd4506e3596619bcddb92a460403d8edbb4639a4"
        );
    }

    #[test]
    fn record_two_matches_the_published_vector() {
        let record: Value = json!({
            "action": "daemon.started", "actor": {"kind": "system"},
            "data": {"instance_id": "3f9a6c2d1b7e4a08c5d2e9f1a0b3c4d5", "version": "0.1.0"},
            "outcome": "ok",
            "prev_hash": "ccd1d1eec3132fd18803168d9492a1db7c3a8ff8bb6b37167efeb6aff0989434",
            "seq": 2, "subject": {}, "ts": "2026-10-01T00:00:00.412Z", "v": 1
        });
        let prev: Hex256 = "ccd1d1eec3132fd18803168d9492a1db7c3a8ff8bb6b37167efeb6aff0989434"
            .parse()
            .unwrap();
        assert_eq!(
            record_hash(&prev, &record, None).unwrap().to_hex(),
            "3df1096a1681e2d5473e36417a0cef262a1d6887ff94d8f7332d25e52d1f29a5"
        );
    }

    fn new_log() -> MemoryAuditLog {
        let ids = zeus_types::IdGenerator::new();
        MemoryAuditLog::new(
            ids.chain_id(),
            ids.store_id(),
            "0.1.0",
            Timestamp::UNIX_EPOCH,
            None,
        )
    }

    fn append(log: &MemoryAuditLog, n: u64) {
        let mut e = AuditEntry::new(
            Timestamp::UNIX_EPOCH,
            Actor::engine(),
            actions::JOB_CREATED,
            AuditOutcome::Ok,
        );
        e.data.insert("n".into(), json!(n));
        log.append(e).unwrap();
    }

    #[test]
    fn memory_log_produces_verifiable_chains() {
        let log = new_log();
        for n in 0..20 {
            append(&log, n);
        }
        let values = log.to_values();
        assert_eq!(values.len(), 21);
        let head = verify_records(&values, &ChainStart::Genesis, None)
            .unwrap()
            .unwrap();
        assert_eq!(head.seq, 21);
        assert_eq!(log.head().unwrap().unwrap(), head);
        // Mid-chain verification from an anchor.
        let anchor = verify_records(&values[..10], &ChainStart::Genesis, None)
            .unwrap()
            .unwrap();
        let tail = verify_records(&values[10..], &ChainStart::After(anchor), None)
            .unwrap()
            .unwrap();
        assert_eq!(tail, head);
    }

    #[test]
    fn every_tamper_is_detected_with_the_right_kind() {
        let log = new_log();
        for n in 0..6 {
            append(&log, n);
        }
        let values = log.to_values();
        let kind = |vs: &[Value]| {
            verify_records(vs, &ChainStart::Genesis, None)
                .unwrap_err()
                .kind
        };

        // Flip a field of an interior record.
        let mut edited = values.clone();
        edited[3]["data"]["n"] = json!(999);
        assert_eq!(kind(&edited), AuditFailureKind::HashMismatch);

        // Delete a middle record.
        let mut deleted = values.clone();
        deleted.remove(3);
        assert_eq!(kind(&deleted), AuditFailureKind::SeqGap);

        // Swap two records.
        let mut swapped = values.clone();
        swapped.swap(2, 3);
        assert_eq!(kind(&swapped), AuditFailureKind::SeqGap);

        // A record with a wrong prev_hash (but a self-consistent hash) breaks the link.
        let mut relinked = values.clone();
        let bogus = Hex256::from_bytes([7; 32]);
        relinked[4]["prev_hash"] = json!(bogus.to_hex());
        relinked[4]["hash"] = json!(record_hash(&bogus, &relinked[4], None).unwrap().to_hex());
        assert_eq!(kind(&relinked), AuditFailureKind::PrevMismatch);

        // A bad genesis.
        let mut bad_genesis = values.clone();
        bad_genesis[0]["prev_hash"] = json!(Hex256::from_bytes([1; 32]).to_hex());
        assert_eq!(kind(&bad_genesis), AuditFailureKind::BadGenesis);

        // Not a record at all.
        assert_eq!(
            kind(&[json!({"seq": 1})]),
            AuditFailureKind::TornOrMalformed
        );

        // Truncating the tail is invisible to verify_records (that is the journal head's job).
        assert!(verify_records(&values[..4], &ChainStart::Genesis, None).is_ok());
    }

    #[test]
    fn keyed_chains_need_the_key() {
        let ids = zeus_types::IdGenerator::new();
        let key = [42u8; 32];
        let log = MemoryAuditLog::new(
            ids.chain_id(),
            ids.store_id(),
            "0.1.0",
            Timestamp::UNIX_EPOCH,
            Some(key),
        );
        append(&log, 1);
        let values = log.to_values();
        assert!(verify_records(&values, &ChainStart::Genesis, Some(&key)).is_ok());
        assert!(verify_records(&values, &ChainStart::Genesis, None).is_err());
        assert!(verify_records(&values, &ChainStart::Genesis, Some(&[0u8; 32])).is_err());
    }

    #[test]
    fn write_ahead_registry() {
        assert!(actions::is_write_ahead(actions::SESSION_LEASE_REQUESTED));
        assert!(actions::is_write_ahead(actions::FILE_DELETED));
        assert!(!actions::is_write_ahead(actions::JOB_CREATED));
        assert!(!actions::is_write_ahead("nonexistent.action"));
        let mut seen = std::collections::HashSet::new();
        for (name, _) in actions::REGISTRY {
            assert!(seen.insert(*name), "duplicate {name}");
        }
    }
}
