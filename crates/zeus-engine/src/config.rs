//! Engine configuration (01 section 10, 03 section 5.3).

use std::path::PathBuf;
use std::time::Duration;

use zeus_http::ClientConfig;
use zeus_journal::CommitPolicy;
use zeus_types::policy::{budgets, scheduling};
use zeus_types::{ErrorEnvelope, OsMetadataMode, codes};

use crate::error::{EngineError, EngineResult};

/// Optional transfer policy, supplied through `EngineBuilder::transfer_tuning` so existing
/// embedders can keep constructing `EngineConfig` without a source-breaking new field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferTuning {
    /// Preferred HTTP range size, 8–32 MiB; durable commit units remain independent.
    pub segment_bytes: u64,
    /// Adapt the connection target from measured throughput. False uses the configured ceiling.
    pub adaptive_concurrency: bool,
    /// Reassign the unfinished tail of a slow request after its writer has drained.
    pub work_stealing: bool,
}

impl Default for TransferTuning {
    fn default() -> Self {
        Self {
            segment_bytes: 16 << 20,
            adaptive_concurrency: true,
            work_stealing: true,
        }
    }
}

impl TransferTuning {
    pub(crate) fn validate(&self) -> EngineResult<()> {
        if !(8 << 20..=32 << 20).contains(&self.segment_bytes) {
            return Err(EngineError::Rejected(ErrorEnvelope::from_code(
                codes::NM_SCHEMA_VIOLATION,
                "segment size must be between 8 and 32 MiB",
            )));
        }
        Ok(())
    }
}

/// Scheduling limits. Defaults and bounds from 01 section 10.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerLimits {
    /// Concurrent jobs, global (default 4; 1 to 64).
    pub concurrent_jobs: u32,
    /// Connections per job (default 8; 1 to 32, bounded further by `spec.max_connections`).
    pub connections_per_job: u32,
    /// Connections per host, global (default 8; 1 to 64). Halved on throttling, grows by 1 per 2 s
    /// without errors, never below 1.
    pub connections_per_host: u32,
}

impl Default for SchedulerLimits {
    fn default() -> Self {
        Self {
            concurrent_jobs: scheduling::CONCURRENT_JOBS,
            connections_per_job: scheduling::CONNECTIONS_PER_JOB,
            connections_per_host: scheduling::CONNECTIONS_PER_HOST,
        }
    }
}

/// Timers. Defaults from 01 section 10 and 8.5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timeouts {
    /// Probe deadline (default 45 s; 5 to 300 s).
    pub probe: Duration,
    /// Connect timeout (default 15 s).
    pub connect: Duration,
    /// Idle read timeout (default 30 s).
    pub read: Duration,
    /// How long `awaiting_session` waits for the extension (default 1 h; 1 min to 24 h).
    pub session_wait: Duration,
    /// How long to wait for a session lease inside `probing` (default 15 s).
    pub lease_wait: Duration,
    /// Job tombstone retention (default 30 days; 1 to 365).
    pub tombstone_retention: Duration,
    /// Approval expiry for kinds that default to 24 h (1 min to 30 days).
    pub approval_expiry: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            probe: Duration::from_millis(budgets::PROBE_DEADLINE_MS),
            connect: Duration::from_millis(scheduling::CONNECT_TIMEOUT_MS),
            read: Duration::from_millis(scheduling::READ_TIMEOUT_MS),
            session_wait: Duration::from_millis(budgets::SESSION_WAIT_MS),
            lease_wait: Duration::from_millis(budgets::LEASE_WAIT_MS),
            tombstone_retention: Duration::from_millis(scheduling::TOMBSTONE_RETENTION_MS),
            approval_expiry: Duration::from_secs(24 * 3600),
        }
    }
}

/// Everything the engine needs to know that is not an injected dependency.
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Write roots: every destination must resolve inside one of them (01 section 12.3).
    pub write_roots: Vec<PathBuf>,
    /// Destination directory for jobs that name none; must be inside a write root.
    pub default_dest_dir: PathBuf,
    /// The state directory: journal, audit log, trash (03 section 3.1). Owner-only.
    pub state_dir: PathBuf,
    /// Scheduling limits.
    pub limits: SchedulerLimits,
    /// Timers.
    pub timeouts: Timeouts,
    /// Committer tuning.
    pub commit: CommitPolicy,
    /// HTTP client settings.
    pub http: ClientConfig,
    /// OS provenance metadata mode per write root, falling back to `os_metadata` below.
    pub os_metadata: OsMetadataMode,
    /// Version strings recorded in manifests and audit records.
    pub zeus_version: String,
}

impl EngineConfig {
    /// A configuration with defaults for everything but the three directories.
    #[must_use]
    pub fn new(write_roots: Vec<PathBuf>, default_dest_dir: PathBuf, state_dir: PathBuf) -> Self {
        Self {
            write_roots,
            default_dest_dir,
            state_dir,
            limits: SchedulerLimits::default(),
            timeouts: Timeouts::default(),
            commit: CommitPolicy::default(),
            http: ClientConfig::default(),
            os_metadata: OsMetadataMode::MarkOnly,
            zeus_version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Checks every value against its documented bounds.
    pub fn validate(&self) -> EngineResult<()> {
        let within = |v: u32, lo: u32, hi: u32| (lo..=hi).contains(&v);
        let ok = !self.write_roots.is_empty()
            && within(self.limits.concurrent_jobs, 1, 64)
            && within(self.limits.connections_per_job, 1, 32)
            && within(self.limits.connections_per_host, 1, 64)
            && (Duration::from_secs(5)..=Duration::from_secs(300)).contains(&self.timeouts.probe)
            && (Duration::from_secs(60)..=Duration::from_secs(24 * 3600))
                .contains(&self.timeouts.session_wait);
        if !ok {
            return Err(EngineError::Rejected(ErrorEnvelope::from_code(
                codes::NM_SCHEMA_VIOLATION,
                "invalid engine configuration: a value is outside the bounds of 01 section 10, or no write root is configured",
            )));
        }
        self.commit.validate()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> EngineConfig {
        EngineConfig::new(
            vec![PathBuf::from("/downloads")],
            PathBuf::from("/downloads"),
            PathBuf::from("/state"),
        )
    }

    #[test]
    fn defaults_validate_and_match_the_specification() {
        let c = config();
        assert!(c.validate().is_ok());
        assert_eq!(
            (
                c.limits.concurrent_jobs,
                c.limits.connections_per_job,
                c.limits.connections_per_host
            ),
            (4, 8, 8)
        );
        assert_eq!(c.timeouts.probe, Duration::from_secs(45));
        assert_eq!(c.timeouts.session_wait, Duration::from_secs(3600));
    }

    #[test]
    fn bounds_are_enforced() {
        let mut c = config();
        c.limits.concurrent_jobs = 0;
        assert!(c.validate().is_err());
        let mut c = config();
        c.write_roots.clear();
        assert!(
            c.validate().is_err(),
            "without a write root every write would be refused"
        );
        let mut c = config();
        c.timeouts.session_wait = Duration::from_secs(1);
        assert!(c.validate().is_err());
    }
}
