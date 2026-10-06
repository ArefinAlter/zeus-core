//! The engine and its builder.
//!
//! [`EngineBuilder`] collects the injected dependencies; [`Engine`] is the cheap-to-clone handle that
//! embedders (the daemon, tests, other applications) use. Everything with a side effect on the outside
//! world is injected: the clock, randomness, the file system, the journal, the HTTP transport, the
//! session provider and in-browser fetch, the consent store, the audit sink and the approvals port. With
//! deterministic fakes for all of them the whole job pipeline runs under a simulated clock.
//!
//! Pipeline per job (01 section 6): `queued` -> `probing` (resume validation, session lease) ->
//! `downloading` (segment plan, AIMD, work stealing, per-host token bucket, weighted fair queue; bytes
//! flow through the writer and the committer of 03) -> `verifying` (hash from disk, content check,
//! quarantine) -> `finalizing` (OS marks, fsync, atomic rename, completion commit) -> `completed`, with
//! `awaiting_approval`, `awaiting_session`, `retry_scheduled` and `paused` as the waiting states and an
//! audit record at every material step.
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: the engine is filled in by the zeus-engine implementation task"
)]

use std::sync::Arc;

use zeus_control::{RandomSource, SharedClock, SystemClock, SystemRandom};
use zeus_fs::{Filesystem, RealFs};
use zeus_http::HttpTransport;
use zeus_journal::Journal;
use zeus_session::{ConsentStore, InMemoryConsentStore, ProxyFetch, SessionProvider};
use zeus_types::{EventSeq, IdGenerator, Job, JobId, ProbeResult};
use zeus_verify::AuditSink;
use zeus_verify::content::{ContentDetector, InferDetector};

use crate::api::{
    ApprovalResolution, ControlAction, EngineStatus, EnqueueOutcome, EnqueueRequest, GrantChange,
    ListFilter, Page, ProbeUrlRequest,
};
use crate::config::EngineConfig;
use crate::error::{EngineError, EngineResult};
use crate::events::EventSubscription;
use crate::ports::ApprovalPort;

/// Collects the engine's dependencies. Only the journal is mandatory; everything else has a default
/// or is optional (no session provider means jobs that need a session wait in `awaiting_session`).
pub struct EngineBuilder {
    pub(crate) config: EngineConfig,
    pub(crate) clock: SharedClock,
    pub(crate) rng: Box<dyn RandomSource>,
    pub(crate) ids: Arc<IdGenerator>,
    pub(crate) fs: Arc<dyn Filesystem>,
    pub(crate) journal: Option<Journal>,
    pub(crate) transport: Option<Arc<dyn HttpTransport>>,
    pub(crate) session: Option<Arc<dyn SessionProvider>>,
    pub(crate) proxy: Option<Arc<dyn ProxyFetch>>,
    pub(crate) consent: Arc<dyn ConsentStore>,
    pub(crate) audit: Option<Arc<dyn AuditSink>>,
    pub(crate) approvals: Option<Arc<dyn ApprovalPort>>,
    pub(crate) detector: Arc<dyn ContentDetector>,
}

impl EngineBuilder {
    /// A builder with production defaults: system clock and randomness, the real file system, the
    /// in-memory consent store and the `infer` content detector.
    #[must_use]
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            clock: Arc::new(SystemClock::new()),
            rng: Box::new(SystemRandom),
            ids: Arc::new(IdGenerator::new()),
            fs: Arc::new(RealFs::new()),
            journal: None,
            transport: None,
            session: None,
            proxy: None,
            consent: Arc::new(InMemoryConsentStore::new()),
            audit: None,
            approvals: None,
            detector: Arc::new(InferDetector),
        }
    }

    /// Injects the clock (tests use `ManualClock`).
    #[must_use]
    pub fn clock(mut self, clock: SharedClock) -> Self {
        self.clock = clock;
        self
    }

    /// Injects the random source used for backoff jitter and hedging (tests use `SplitMix64`).
    #[must_use]
    pub fn rng(mut self, rng: Box<dyn RandomSource>) -> Self {
        self.rng = rng;
        self
    }

    /// Injects the identifier generator.
    #[must_use]
    pub fn ids(mut self, ids: Arc<IdGenerator>) -> Self {
        self.ids = ids;
        self
    }

    /// Injects the file system (tests use a crash-simulating one).
    #[must_use]
    pub fn filesystem(mut self, fs: Arc<dyn Filesystem>) -> Self {
        self.fs = fs;
        self
    }

    /// The journal (required).
    #[must_use]
    pub fn journal(mut self, journal: Journal) -> Self {
        self.journal = Some(journal);
        self
    }

    /// Injects the HTTP transport. Default: the reqwest transport built from `config.http`.
    #[must_use]
    pub fn transport(mut self, transport: Arc<dyn HttpTransport>) -> Self {
        self.transport = Some(transport);
        self
    }

    /// Injects the session provider (the daemon's native-messaging session broker).
    #[must_use]
    pub fn session_provider(mut self, provider: Arc<dyn SessionProvider>) -> Self {
        self.session = Some(provider);
        self
    }

    /// Injects the in-browser fetch proxy.
    #[must_use]
    pub fn proxy_fetch(mut self, proxy: Arc<dyn ProxyFetch>) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Injects the consent store (the daemon's journal-backed one).
    #[must_use]
    pub fn consent_store(mut self, store: Arc<dyn ConsentStore>) -> Self {
        self.consent = store;
        self
    }

    /// Injects the audit sink. Without one, write-ahead actions that need a record fail closed.
    #[must_use]
    pub fn audit(mut self, audit: Arc<dyn AuditSink>) -> Self {
        self.audit = Some(audit);
        self
    }

    /// Injects the approvals port. Without one, an action that needs a human decision fails with
    /// `policy_denied` instead of waiting forever.
    #[must_use]
    pub fn approvals(mut self, port: Arc<dyn ApprovalPort>) -> Self {
        self.approvals = Some(port);
        self
    }

    /// Injects the content detector (default: `infer`).
    #[must_use]
    pub fn content_detector(mut self, detector: Arc<dyn ContentDetector>) -> Self {
        self.detector = detector;
        self
    }

    /// Validates the configuration, runs startup recovery (03 section 10) and starts the scheduler.
    pub async fn build(self) -> EngineResult<Engine> {
        self.config.validate()?;
        Err(EngineError::NotImplemented("EngineBuilder::build"))
    }
}

/// The engine handle. Cheap to clone; all clones share one scheduler and one journal.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    // Filled in by the implementation task: the scheduler handle, per-job owner tasks, the committer,
    // the event broadcast, rate limiters.
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}

impl Engine {
    /// Accepts a job. Idempotent by `spec.idempotency_key` scoped to the caller (00 section 5.4): the same
    /// key with the same parameters returns the stored job, with different parameters
    /// `api.idempotency_conflict`. Validates the spec (`JobSpec::validate`, scheme, write roots, never-list),
    /// resolves the effective grant, creates the job at S01 or S02, reserves the destination path and
    /// returns without waiting for the download.
    pub async fn enqueue(&self, request: EnqueueRequest) -> EngineResult<EnqueueOutcome> {
        Err(EngineError::NotImplemented("Engine::enqueue"))
    }

    /// Probes a URL without creating a job.
    pub async fn probe(&self, request: ProbeUrlRequest) -> EngineResult<ProbeResult> {
        Err(EngineError::NotImplemented("Engine::probe"))
    }

    /// One job.
    pub async fn get(&self, id: JobId) -> EngineResult<Job> {
        Err(EngineError::NotImplemented("Engine::get"))
    }

    /// A page of jobs, ascending by id (creation order).
    pub async fn list(&self, filter: ListFilter) -> EngineResult<Page<zeus_types::JobSummary>> {
        Err(EngineError::NotImplemented("Engine::list"))
    }

    /// Waits until the job leaves its current state or `timeout` (at most 60 s) elapses, then returns it
    /// (the building block of `zeus_wait`). Never blocks longer than the timeout.
    pub async fn wait(&self, id: JobId, timeout: std::time::Duration) -> EngineResult<Job> {
        Err(EngineError::NotImplemented("Engine::wait"))
    }

    /// Applies a client action. Requests that target the state the job is already in succeed silently with
    /// no event; an action illegal from the current state is `conflict` (`api.invalid_transition`); in
    /// `finalizing` pause and cancel are refused with `api.not_interruptible`.
    pub async fn control(&self, id: JobId, action: ControlAction) -> EngineResult<Job> {
        Err(EngineError::NotImplemented("Engine::control"))
    }

    /// Re-hashes a completed job's file from disk and reports whether it still matches (the `verify` tool).
    pub async fn verify(
        &self,
        id: JobId,
        expected_sha256: Option<zeus_types::Hex256>,
    ) -> EngineResult<zeus_verify::hash::Digests> {
        Err(EngineError::NotImplemented("Engine::verify"))
    }

    /// Subscribes to events: durable events above `since` are replayed from the journal, then live ones
    /// follow. `include_progress` adds the ephemeral `job.progress` events.
    pub fn subscribe(
        &self,
        since: Option<EventSeq>,
        include_progress: bool,
    ) -> EngineResult<EventSubscription> {
        Err(EngineError::NotImplemented("Engine::subscribe"))
    }

    /// Applies a human decision the approvals manager already recorded: S30 (approved), S31 (denied or
    /// expired) or S32. Only the daemon calls this, after checking that the decider is a human on a trust
    /// surface; the engine re-checks the approval's actor and refuses anything else.
    pub async fn apply_approval(&self, resolution: ApprovalResolution) -> EngineResult<()> {
        Err(EngineError::NotImplemented("Engine::apply_approval"))
    }

    /// Re-evaluates the jobs that depend on a grant that was revoked or expired: queued jobs go to
    /// `awaiting_approval` (S07), downloading jobs escalate (S23), waiting jobs return to approval (S41);
    /// outstanding leases are zeroized.
    pub async fn grants_changed(&self, change: GrantChange) -> EngineResult<()> {
        Err(EngineError::NotImplemented("Engine::grants_changed"))
    }

    /// The kill switch: pause every job and drop every lease (07 "kill switch semantics"). The daemon
    /// revokes the grants through its own path.
    pub async fn pause_all(&self) -> EngineResult<u64> {
        Err(EngineError::NotImplemented("Engine::pause_all"))
    }

    /// A summary of the current state.
    pub async fn status(&self) -> EngineResult<EngineStatus> {
        Err(EngineError::NotImplemented("Engine::status"))
    }

    /// Stops accepting work, flushes the committer (a barrier), drops every lease, records
    /// `daemon.stopping` and returns when the owner tasks have finished.
    pub async fn shutdown(&self) -> EngineResult<()> {
        Err(EngineError::NotImplemented("Engine::shutdown"))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn config() -> EngineConfig {
        EngineConfig::new(
            vec![PathBuf::from("/downloads")],
            PathBuf::from("/downloads"),
            PathBuf::from("/state"),
        )
    }

    #[tokio::test]
    async fn build_validates_the_configuration_first() {
        let mut bad = config();
        bad.write_roots.clear();
        let err = EngineBuilder::new(bad).build().await.unwrap_err();
        assert!(matches!(err, EngineError::Rejected(_)), "{err:?}");
    }

    #[tokio::test]
    async fn the_skeleton_reports_not_implemented_instead_of_pretending() {
        let err = EngineBuilder::new(config()).build().await.unwrap_err();
        assert!(matches!(
            err,
            EngineError::NotImplemented("EngineBuilder::build")
        ));
    }
}
