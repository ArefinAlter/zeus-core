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
use crate::api::*;
use crate::config::{EngineConfig, TransferTuning};
#[path = "adaptive.rs"]
mod adaptive;
use crate::error::{EngineError, EngineResult};
use crate::events::{EngineEvent, EventSubscription};
use crate::ports::ApprovalPort;
use futures::StreamExt;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Semaphore, broadcast, watch};
use tokio_util::sync::CancellationToken;
use zeus_control::{RandomSource, SharedClock, SystemClock, SystemRandom};
use zeus_fs::{DataFile, Filesystem, RealFs, WriteRoots};
use zeus_http::{
    HttpError, HttpProber, HttpSegmentFetcher, HttpTransport, ProbeRequest, Prober, SegmentEnd,
    SegmentFetcher, SegmentRequest,
};
use zeus_journal::{
    CommitUnit, InvalidationReason, JobInternal, JobRecord, Journal, ResumeRecheck,
    TransitionRequest,
};
use zeus_session::{ConsentStore, InMemoryConsentStore, ProxyFetch, SessionProvider};
use zeus_types::event::*;
use zeus_types::*;
use zeus_verify::AuditSink;
use zeus_verify::content::{ContentDetector, InferDetector};

/// Collects the engine's dependencies. Only the journal is mandatory; everything else has a default
/// or is optional (no session provider means jobs that need a session wait in `awaiting_session`).
pub struct EngineBuilder {
    pub(crate) config: EngineConfig,
    pub(crate) transfer_tuning: TransferTuning,
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
    pub(crate) job_transports: Option<Arc<dyn crate::ports::JobTransportFactory>>,
}

impl EngineBuilder {
    /// A builder with production defaults: system clock and randomness, the real file system, the
    /// in-memory consent store and the `infer` content detector.
    #[must_use]
    pub fn new(config: EngineConfig) -> Self {
        Self {
            config,
            transfer_tuning: TransferTuning::default(),
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
            job_transports: None,
        }
    }

    /// Sets adaptive range execution policy without changing the embedder's configuration shape.
    #[must_use]
    pub fn transfer_tuning(mut self, tuning: TransferTuning) -> Self {
        self.transfer_tuning = tuning;
        self
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

    /// Inject per-job transports enforcing approved workflow network scope on every request.
    #[must_use]
    pub fn job_transports(mut self, factory: Arc<dyn crate::ports::JobTransportFactory>) -> Self {
        self.job_transports = Some(factory);
        self
    }

    /// Validates the configuration, runs startup recovery (03 section 10) and starts the scheduler.
    pub async fn build(self) -> EngineResult<Engine> {
        self.config.validate()?;
        self.transfer_tuning.validate()?;
        let journal = self
            .journal
            .ok_or_else(|| rejected(codes::NM_SCHEMA_VIOLATION, "a journal is required"))?;
        let roots = WriteRoots::open(&self.config.write_roots)?;
        roots.resolve_dest_dir(&self.config.default_dest_dir)?;
        let transport = match self.transport {
            Some(t) => t,
            None => Arc::new(zeus_http::ReqwestTransport::new(&self.config.http)?),
        };
        zeus_journal::recovery::recover(
            &journal,
            &zeus_journal::recovery::RecoveryContext {
                fs: self.fs.clone(),
                scan_roots: self.config.write_roots.clone(),
                orphan_gc_age: zeus_journal::recovery::DEFAULT_ORPHAN_GC_AGE,
                audit_chain_ok: false,
            },
        )?;
        let (events, _) = broadcast::channel(1024);
        let engine = Engine {
            inner: Arc::new(EngineInner {
                slots: Arc::new(Semaphore::new(self.config.limits.concurrent_jobs as usize)),
                connections: Mutex::new(BTreeMap::new()),
                concurrency_targets: Mutex::new(BTreeMap::new()),
                transfer_tuning: self.transfer_tuning,
                config: self.config,
                clock: self.clock,
                rng: Mutex::new(self.rng),
                ids: self.ids,
                fs: self.fs,
                journal,
                transport,
                roots,
                events,
                running: Mutex::new(BTreeMap::new()),
                stopping: AtomicBool::new(false),
                shutdown_notice: Mutex::new(None),
                gate: tokio::sync::Mutex::new(()),
                session: self.session,
                proxy: self.proxy,
                consent: self.consent,
                detector: self.detector,
                approvals: self.approvals,
                audit: self.audit,
                job_transports: self.job_transports,
            }),
        };
        for record in engine.inner.journal.list_incomplete()? {
            if matches!(
                record.job.state,
                JobState::Queued | JobState::RetryScheduled
            ) && !engine.inner.journal.meta()?.kill_switch_engaged()
            {
                engine.start(record.id());
            }
        }
        Ok(engine)
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ControlReceipt {
    job: Job,
    summary: JobSummary,
}

/// The engine handle. Cheap to clone; all clones share one scheduler and one journal.
#[derive(Clone)]
pub struct Engine {
    inner: Arc<EngineInner>,
}

struct EngineInner {
    config: EngineConfig,
    clock: SharedClock,
    rng: Mutex<Box<dyn RandomSource>>,
    ids: Arc<IdGenerator>,
    fs: Arc<dyn Filesystem>,
    journal: Journal,
    transport: Arc<dyn HttpTransport>,
    roots: WriteRoots,
    slots: Arc<Semaphore>,
    // Bounded independent origin budgets; idle entries can be evicted without affecting active work.
    connections: Mutex<BTreeMap<String, Arc<adaptive::HostBudget>>>,
    concurrency_targets: Mutex<BTreeMap<String, u32>>,
    transfer_tuning: TransferTuning,
    running: Mutex<BTreeMap<JobId, Running>>,
    stopping: AtomicBool,
    shutdown_notice: Mutex<Option<ShutdownNotice>>,
    gate: tokio::sync::Mutex<()>,
    events: broadcast::Sender<Event>,
    session: Option<Arc<dyn SessionProvider>>,
    proxy: Option<Arc<dyn ProxyFetch>>,
    consent: Arc<dyn ConsentStore>,
    detector: Arc<dyn ContentDetector>,
    job_transports: Option<Arc<dyn crate::ports::JobTransportFactory>>,
    approvals: Option<Arc<dyn ApprovalPort>>,
    audit: Option<Arc<dyn AuditSink>>,
}
struct Running {
    cancel: CancellationToken,
    done: watch::Receiver<bool>,
}
struct ShutdownNotice {
    reason: StopReason,
    emitted: bool,
}

impl std::fmt::Debug for Engine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Engine").finish_non_exhaustive()
    }
}

fn rejected(code: &'static str, message: &'static str) -> EngineError {
    EngineError::Rejected(ErrorEnvelope::from_code(code, message))
}
fn internal() -> EngineError {
    rejected(codes::INTERNAL_BUG, "engine worker failed")
}
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> EngineResult<T> + Send + 'static,
) -> EngineResult<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| internal())?
}
impl Engine {
    /// Validates and durably accepts one download, scoped by the authenticated caller.
    pub async fn enqueue(&self, request: EnqueueRequest) -> EngineResult<EnqueueOutcome> {
        self.enqueue_inner(request, false).await
    }
    /// Reserve and commit a job in `paused` state without starting any worker.
    ///
    /// Trusted embedders can bind a separately durable source record to the
    /// returned job identity before explicitly resuming it. Creation and S05
    /// are one journal transaction; startup does not schedule paused jobs.
    /// Source factories must still reject absent or revoked identity bindings.
    /// Browser/session jobs use ordinary enqueue and are refused here.
    pub async fn enqueue_held(&self, request: EnqueueRequest) -> EngineResult<EnqueueOutcome> {
        if request.spec.session_origin.is_some()
            || request.spec.transport_hint() == TransportHint::BrowserProxy
            || request.spec.source.kind == SourceKind::BrowserHandoff
        {
            return Err(rejected(
                "api.invalid_params",
                "held admission does not support browser or session authority",
            ));
        }
        self.enqueue_inner(request, true).await
    }
    async fn enqueue_inner(
        &self,
        mut request: EnqueueRequest,
        held: bool,
    ) -> EngineResult<EnqueueOutcome> {
        let _gate = self.inner.gate.lock().await;
        if self.inner.stopping.load(Ordering::Acquire) {
            return Err(EngineError::ShuttingDown);
        }
        self.ensure_running()?;
        request.spec.validate().map_err(EngineError::Rejected)?;
        // Caller identity is supplied by the embedding, never trusted from the job body.
        request.spec.source.client_id = Some(request.caller.client_id.clone());
        request
            .spec
            .apply_defaults(&self.inner.config.default_dest_dir.to_string_lossy());
        let mut hash_spec = request.spec.clone();
        hash_spec.idempotency_key = None;
        let hash =
            zeus_verify::hash_bytes(&zeus_verify::canonical::to_jcs_bytes(&hash_spec)?).blake3;
        let method = if held {
            "jobs.enqueue_held"
        } else {
            "jobs.enqueue"
        };
        if let Some(key) = &request.spec.idempotency_key
            && let Some(row) = self
                .inner
                .journal
                .read(|t| t.idempotency(&request.caller.client_id, key))?
            && (row.expires_at > self.inner.clock.now()
                || self.inner.journal.job(row.job_id)?.is_some())
        {
            if row
                .method
                .as_deref()
                .map_or(held, |existing| existing != method)
                || row.request_hash != hash
            {
                return Err(EngineError::IdempotencyConflict);
            }
            return Ok(EnqueueOutcome {
                job: self.get(row.job_id).await?,
                deduplicated: true,
                approval: None,
            });
        }
        if request.spec.overwrite() == Overwrite::Replace {
            return Err(rejected(
                codes::POLICY_APPROVAL_DENIED,
                "replacement requires a human-approved destructive operation",
            ));
        }
        if request.spec.transport_hint() == TransportHint::BrowserProxy
            && (self.inner.proxy.is_none() || request.spec.source.kind == SourceKind::Workflow)
        {
            return Err(rejected(
                codes::POLICY_APPROVAL_DENIED,
                "browser fetch transport is not available for this job",
            ));
        }
        if request.spec.transport_hint() == TransportHint::BrowserProxy
            && request.spec.session_origin.is_none()
        {
            request.spec.session_origin = Some(request.spec.origin());
        }
        if request.spec.source.kind == SourceKind::BrowserHandoff
            && request.spec.session_origin.is_none()
        {
            request.spec.session_origin = Some(request.spec.origin());
        }
        if request
            .spec
            .session_origin
            .as_ref()
            .is_some_and(|o| !o.allows_session_release() || *o != request.spec.origin())
        {
            return Err(rejected(
                codes::POLICY_SCHEME_NOT_ALLOWED,
                "session origin must match the secure download origin",
            ));
        }
        if matches!(
            self.effective_grant(&request.spec.origin(), None, request.spec.source.run_id)?,
            zeus_session::consent::Resolution::Denied(_)
        ) {
            return Err(rejected(codes::POLICY_ORIGIN_NEVER, "origin is denied"));
        }
        let dir = self.inner.roots.resolve_dest_dir(Path::new(
            request.spec.dest_dir.as_deref().ok_or_else(internal)?,
        ))?;
        self.inner.fs.create_dir_all(&dir)?;
        let raw = request.spec.filename.clone().unwrap_or_else(|| {
            request
                .spec
                .url
                .url()
                .path_segments()
                .and_then(|mut p| p.next_back())
                .filter(|s| !s.is_empty())
                .unwrap_or("download")
                .to_owned()
        });
        let name = zeus_fs::sanitize_filename(&raw, &zeus_fs::SanitizeOptions::default())?.name;
        let id = self.inner.ids.job_id();
        let now = self.inner.clock.now();
        let mut dest = dir.join(&name);
        for n in 0..10_000 {
            let key = path_key(&dest);
            let occupied = self.inner.fs.metadata(&dest)?.is_some()
                || self
                    .inner
                    .fs
                    .metadata(&zeus_fs::zpart_path(&dest))?
                    .is_some()
                || self.inner.journal.read(|t| t.reservation(&key))?.is_some();
            if !occupied {
                break;
            }
            if request.spec.overwrite() == Overwrite::Fail || n == 9999 {
                return Err(zeus_fs::FsError::AlreadyExists.into());
            }
            let path = Path::new(&name);
            let stem = path.file_stem().unwrap_or_default().to_string_lossy();
            dest = dir.join(match path.extension() {
                Some(ext) => format!("{stem} ({}).{}", n + 1, ext.to_string_lossy()),
                None => format!("{stem} ({})", n + 1),
            });
        }
        let mut job = Job::new(id, request.spec, JobState::Queued, now);
        let mut approval = None;
        if let Some(origin) = job.spec.session_origin.as_ref() {
            match self.effective_grant(origin, Some(id), job.spec.source.run_id)? {
                zeus_session::consent::Resolution::Allowed(grant) => job.grant_id = Some(grant.id),
                zeus_session::consent::Resolution::Denied(_) => {
                    return Err(rejected(codes::POLICY_ORIGIN_NEVER, "origin is denied"));
                }
                zeus_session::consent::Resolution::None => {
                    let port = self.inner.approvals.as_ref().ok_or_else(|| {
                        rejected(
                            codes::POLICY_APPROVAL_DENIED,
                            "a human approval manager is required",
                        )
                    })?;
                    let kind = if job.spec.source.kind == SourceKind::BrowserHandoff {
                        ApprovalKind::Handoff
                    } else {
                        ApprovalKind::SessionGrant
                    };
                    let pending = port
                        .request(crate::ports::ApprovalRequest {
                            job: Some(job.clone()),
                            dest_path: Some(dest.to_string_lossy().into_owned()),
                            kind,
                            job_id: Some(id),
                            run_id: job.spec.source.run_id,
                            origin: Some(origin.clone()),
                            allowed_scopes: kind.default_allowed_scopes().to_vec(),
                            reason_codes: vec!["session.first_use".into()],
                            summary: ApprovalSummary {
                                title: name.clone(),
                                url_redacted: Some(job.spec.url.redact(RedactMode::Log)),
                                total_bytes: job.spec.expected_size,
                                source_kind: Some(job.spec.source.kind),
                                requested_by: Some(request.caller.client_id.clone()),
                            },
                        })
                        .await
                        .map_err(EngineError::Rejected)?;
                    if pending.request_hash.is_none() || pending.revision.is_none() {
                        return Err(rejected(
                            codes::POLICY_APPROVAL_DENIED,
                            "approval manager did not bind the request",
                        ));
                    }
                    job.state = JobState::AwaitingApproval;
                    job.approval_id = Some(pending.id);
                    approval = Some(pending);
                }
            }
        }
        let record = JobRecord::new(
            job.clone(),
            JobInternal {
                retry_no_progress_since: None,
                retry_counts: Default::default(),
                last_state_seq: 0,
                os_metadata: vec![],
                epoch: 0,
                dest_path: dest.to_string_lossy().into_owned(),
                zpart_path: zeus_fs::zpart_path(&dest).to_string_lossy().into_owned(),
                zpart_file_id: None,
                total_bytes: None,
                data_complete: false,
                eof_size: None,
                bound_validators: Validators::default(),
                range_support: RangeSupport::Unknown,
                resume_recheck: ResumeRecheck::Tail,
                verify_result: None,
                finalize: None,
                url_secret_stored: job.spec.url.url().query().is_some(),
            },
        );
        let event = self.inner.journal.transact(|t| {
            t.put_job(&record)?;
            t.put_reservation(&zeus_journal::ReservationRow {
                path_key: path_key(&dest),
                job_id: id,
                created_at: now,
            })?;
            if let Some(key) = &job.spec.idempotency_key {
                t.put_idempotency(&zeus_journal::IdempotencyRow {
                    method: Some(method.into()),
                    result: None,
                    client_id: request.caller.client_id.clone(),
                    key: key.clone(),
                    request_hash: hash,
                    job_id: id,
                    created_at: now,
                    expires_at: now.saturating_add_ms(86_400_000),
                })?;
            }
            if let Some(approval) = &approval {
                // A batch join is the next revision of a pending approval (07 section 4.7). A decision committed
                // after the approval manager read it wins; the enqueue fails rather than reopening it.
                if let Some(revision) = approval.revision.filter(|r| *r > 1) {
                    let current = t.approval(approval.id)?;
                    if !current.is_some_and(|c| {
                        c.state == ApprovalState::Pending
                            && c.revision.unwrap_or(1).saturating_add(1) == revision
                    }) {
                        return Err(zeus_journal::JournalError::Invariant("approval changed"));
                    }
                }
                t.put_approval(approval)?;
            }
            let created = t.append_event(
                now,
                Some(id),
                job.spec.source.run_id,
                JobCreatedData {
                    source: job.spec.source.clone(),
                    state: job.state,
                    url_redacted: job.spec.url.redact(RedactMode::Log),
                    filename_hint: Some(name.clone()),
                    origin: Some(job.spec.origin()),
                    session_origin: job.spec.session_origin.clone(),
                    priority: job.spec.priority(),
                }
                .into(),
            )?;
            let mut stored = record.clone();
            stored.internal.last_state_seq = created.seq.map_or(0, EventSeq::get);
            t.put_job(&stored)?;
            let mut events = vec![created];
            if let Some(approval) = &approval {
                let mut public = approval.clone();
                public.facts = None;
                public.agent_says = None;
                events.push(t.append_event(
                    now,
                    None,
                    job.spec.source.run_id,
                    ApprovalRequestedData { approval: public }.into(),
                )?);
            }
            if held {
                let paused = zeus_journal::apply_transition_in(
                    t,
                    TransitionRequest {
                        job_id: id,
                        transition: "S05",
                        trigger: TransitionActor::Client,
                        cause: StateCause::UserRequest,
                        actor: Actor {
                            kind: request.caller.kind,
                            client_id: Some(request.caller.client_id.clone()),
                            surface: None,
                        },
                        now,
                        events_before: vec![],
                        events_after: vec![],
                    },
                    &mut |_| Ok(()),
                )?;
                job = paused.record.job;
                events.extend(paused.events);
            }
            Ok(events)
        })?;
        self.publish(event);
        if job.state == JobState::Queued {
            self.start(id);
        }
        Ok(EnqueueOutcome {
            job,
            deduplicated: false,
            approval,
        })
    }
    /// Probes a public URL without persisting a job or releasing session material.
    pub async fn probe(&self, request: ProbeUrlRequest) -> EngineResult<ProbeResult> {
        self.ensure_running()?;
        let outcome = HttpProber::new(self.bounded_transport(self.inner.transport.clone()))
            .probe(
                ProbeRequest {
                    url: request.url,
                    hint_url: None,
                    referrer: None,
                    extra_headers: BTreeMap::new(),
                    session: None,
                    resume: None,
                    head_timeout: self.inner.config.timeouts.probe,
                    idle_timeout: self.inner.config.timeouts.read,
                },
                &CancellationToken::new(),
            )
            .await?;
        Ok(outcome.result)
    }
    /// Reads a durable job snapshot.
    pub async fn get(&self, id: JobId) -> EngineResult<Job> {
        Ok(self.record(id)?.job)
    }
    /// Compact snapshot carrying the durable state transition sequence.
    pub async fn summary(&self, id: JobId) -> EngineResult<JobSummary> {
        Ok(self.record(id)?.summary())
    }
    fn record(&self, id: JobId) -> EngineResult<JobRecord> {
        self.inner
            .journal
            .job(id)?
            .ok_or(EngineError::NotFound { what: "job" })
    }
    /// Lists jobs in stable creation order.
    pub async fn list(&self, filter: ListFilter) -> EngineResult<Page<JobSummary>> {
        let limit = filter.limit.unwrap_or(50).clamp(1, 100);
        let records = self.inner.journal.read(|t| {
            t.jobs(&zeus_journal::JobFilter {
                states: filter.states,
                after: filter.cursor,
                limit: None,
            })
        })?;
        let mut items: Vec<_> = records
            .into_iter()
            .filter(|r| filter.run_id.is_none() || r.job.spec.source.run_id == filter.run_id)
            .take(limit + 1)
            .map(|r| r.summary())
            .collect();
        let next_cursor = if items.len() > limit {
            items.pop();
            items.last().map(|j| j.id)
        } else {
            None
        };
        Ok(Page { items, next_cursor })
    }
    /// Waits for the next state change, for at most sixty seconds.
    pub async fn wait(&self, id: JobId, timeout: Duration) -> EngineResult<Job> {
        let mut events = self.inner.events.subscribe();
        let initial = self.get(id).await?;
        if initial.state.is_terminal() || initial.state == JobState::Failed {
            return Ok(initial);
        }
        let _ = tokio::time::timeout(timeout.min(Duration::from_secs(60)), async {
            loop {
                if events.recv().await.is_err() {
                    break;
                }
                if let Ok(job) = self.get(id).await
                    && job.state != initial.state
                {
                    break;
                }
            }
        })
        .await;
        self.get(id).await
    }
    /// Pauses, resumes, cancels, retries, or changes a job priority.
    pub async fn control(&self, id: JobId, action: ControlAction) -> EngineResult<Job> {
        self.control_inner(id, action, None, false, None)
            .await
            .map(|r| r.job)
    }
    /// Workflow control carries the system actor and workflow_runner cause in durable events.
    pub async fn control_workflow(&self, id: JobId, action: ControlAction) -> EngineResult<Job> {
        self.control_inner(id, action, None, true, None)
            .await
            .map(|r| r.job)
    }
    /// Bind a control response to the authenticated caller and method in the transition transaction.
    /// Retries return the original response even when the job has since changed state.
    pub async fn control_idempotent(
        &self,
        id: JobId,
        action: ControlAction,
        client_id: &str,
        key: &str,
        request_hash: Hex256,
        actor: Actor,
    ) -> EngineResult<JobSummary> {
        if key.is_empty() || key.len() > 128 || client_id.is_empty() || client_id.len() > 128 {
            return Err(rejected(
                "api.invalid_params",
                "invalid idempotency identity or key",
            ));
        }
        self.control_inner(
            id,
            action,
            Some((client_id, key, request_hash)),
            false,
            Some(actor),
        )
        .await
        .map(|r| r.summary)
    }
    async fn control_inner(
        &self,
        id: JobId,
        action: ControlAction,
        receipt: Option<(&str, &str, Hex256)>,
        workflow: bool,
        supplied_actor: Option<Actor>,
    ) -> EngineResult<ControlReceipt> {
        let _gate = self.inner.gate.lock().await;
        if let Some((client, key, hash)) = &receipt
            && let Some(row) = self.inner.journal.read(|t| t.idempotency(client, key))?
            && (row.expires_at > self.inner.clock.now()
                || self.inner.journal.job(row.job_id)?.is_some())
        {
            if row.method.as_deref() != Some("jobs.control")
                || row.job_id != id
                || row.request_hash != *hash
            {
                return Err(EngineError::IdempotencyConflict);
            }
            return row
                .result
                .and_then(|v| serde_json::from_value(v).ok())
                .ok_or_else(internal);
        }
        if matches!(action, ControlAction::Resume | ControlAction::Retry) {
            self.ensure_running()?;
        }
        let current_record = self.record(id)?;
        let current = current_record.job.clone();
        let now = self.inner.clock.now();
        let store_receipt = |txn: &mut dyn zeus_journal::WriteTxn,
                             record: &JobRecord|
         -> zeus_journal::JournalResult<()> {
            if let Some((client, key, hash)) = &receipt {
                txn.put_idempotency(&zeus_journal::IdempotencyRow {
                    client_id: (*client).into(),
                    key: (*key).into(),
                    request_hash: *hash,
                    job_id: id,
                    method: Some("jobs.control".into()),
                    result: Some(
                        serde_json::to_value(ControlReceipt {
                            job: record.job.clone(),
                            summary: record.summary(),
                        })
                        .map_err(|_| {
                            zeus_journal::JournalError::Invariant("control response serialization")
                        })?,
                    ),
                    created_at: now,
                    expires_at: now.saturating_add_ms(86_400_000),
                })?;
            }
            Ok(())
        };
        if let ControlAction::SetPriority(priority) = action {
            return Ok(self.inner.journal.transact(|t| {
                let mut r = t
                    .job(id)?
                    .ok_or(zeus_journal::JournalError::Invariant("missing job"))?;
                r.job.spec.priority = Some(priority);
                t.put_job(&r)?;
                store_receipt(t, &r)?;
                Ok(ControlReceipt {
                    summary: r.summary(),
                    job: r.job,
                })
            })?);
        }
        if matches!(
            (action, current.state),
            (ControlAction::Pause, JobState::Paused) | (ControlAction::Cancel, JobState::Canceled)
        ) {
            self.inner
                .journal
                .transact(|t| store_receipt(t, &current_record))?;
            return Ok(ControlReceipt {
                job: current,
                summary: current_record.summary(),
            });
        }
        let choose = |state| -> EngineResult<&'static str> {
            Ok(match (action, state) {
                (ControlAction::Pause, JobState::Queued) => "S05",
                (ControlAction::Pause, JobState::Probing) => "S15",
                (ControlAction::Pause, JobState::Downloading) => "S24",
                (ControlAction::Pause, JobState::RetryScheduled) => "S61",
                (ControlAction::Resume, JobState::Paused) => "S50",
                (ControlAction::Retry, JobState::Failed) => "S90",
                (ControlAction::Retry, JobState::RetryScheduled) => "S60",
                (ControlAction::Cancel, JobState::Queued) => "S06",
                (ControlAction::Cancel, JobState::Probing) => "S16",
                (ControlAction::Cancel, JobState::Downloading) => "S26",
                (ControlAction::Cancel, JobState::AwaitingApproval) => "S32",
                (ControlAction::Cancel, JobState::AwaitingSession) => "S43",
                (ControlAction::Cancel, JobState::Paused) => "S51",
                (ControlAction::Cancel, JobState::RetryScheduled) => "S62",
                (ControlAction::Cancel, JobState::Verifying) => "S73",
                (_, JobState::Finalizing) | (ControlAction::Pause, JobState::Verifying) => {
                    return Err(EngineError::Conflict(ErrorEnvelope::from_code(
                        codes::API_NOT_INTERRUPTIBLE,
                        "job is completing an atomic step",
                    )));
                }
                _ => {
                    return Err(EngineError::Conflict(ErrorEnvelope::from_code(
                        codes::API_INVALID_TRANSITION,
                        "action does not apply to current state",
                    )));
                }
            })
        };
        choose(current.state)?;
        self.stop_worker(id).await;
        let actual = self.record(id)?;
        let transition = choose(actual.job.state)?;
        if action == ControlAction::Retry
            && actual
                .job
                .error
                .as_ref()
                .is_some_and(|e| e.class == ErrorClass::Integrity)
        {
            self.inner.journal.invalidate_all(
                id,
                InvalidationReason::IntegrityRestart,
                now,
                &mut |r| {
                    r.internal.data_complete = false;
                    Ok(())
                },
            )?;
        }
        let replacement = if matches!(action, ControlAction::Resume | ControlAction::Retry) {
            if let Some(origin) = &actual.job.spec.session_origin {
                if !matches!(
                    self.effective_grant(origin, Some(id), actual.job.spec.source.run_id)?,
                    zeus_session::consent::Resolution::Allowed(_)
                ) {
                    Some(self.replacement_approval(&actual, "grant.revoked").await)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };
        let cause = if workflow {
            StateCause::WorkflowRunner
        } else if transition == "S60" {
            StateCause::RetryNow
        } else {
            StateCause::UserRequest
        };
        let actor = supplied_actor.unwrap_or_else(|| {
            if workflow {
                Actor::system()
            } else {
                Actor::engine()
            }
        });
        let (result, events) = self.inner.journal.transact(|t| {
            let mut before = vec![];
            if action == ControlAction::Cancel
                && actual.job.state == JobState::AwaitingApproval
                && let Some(approval_id) = actual.job.approval_id
                && let Some(approval) = t.approval(approval_id)?
                && approval.state == ApprovalState::Pending
            {
                before.extend(crate::approval_lifecycle::leave_pending(
                    t, approval, id, now,
                )?);
            }
            let outcome = zeus_journal::apply_transition_in(
                t,
                TransitionRequest {
                    job_id: id,
                    transition,
                    trigger: TransitionActor::Client,
                    cause,
                    actor: actor.clone(),
                    now,
                    events_before: before,
                    events_after: vec![],
                },
                &mut |r| {
                    if action == ControlAction::Retry {
                        r.job.error = None;
                        r.job.retry = RetryState::default();
                        r.internal.retry_no_progress_since = None;
                        r.internal.retry_counts.clear();
                    }
                    if action == ControlAction::Cancel {
                        r.job.approval_id = None;
                    }
                    Ok(())
                },
            )?;
            let mut record = outcome.record;
            let mut events = outcome.events;
            if let Some(approval) = &replacement {
                t.put_approval(approval)?;
                let mut public = approval.clone();
                public.facts = None;
                public.agent_says = None;
                let next = zeus_journal::apply_transition_in(
                    t,
                    TransitionRequest {
                        job_id: id,
                        transition: "S07",
                        trigger: TransitionActor::Policy,
                        cause: StateCause::ApprovalNeeded,
                        actor: Actor::system(),
                        now,
                        events_before: vec![],
                        events_after: vec![ApprovalRequestedData { approval: public }.into()],
                    },
                    &mut |r| {
                        r.job.approval_id = Some(approval.id);
                        r.job.grant_id = None;
                        Ok(())
                    },
                )?;
                record = next.record;
                events.extend(next.events);
            }
            store_receipt(t, &record)?;
            Ok((record, events))
        })?;
        self.publish(events);
        if action == ControlAction::Cancel {
            let partial = Path::new(&result.internal.zpart_path);
            if self.inner.fs.metadata(partial)?.is_some_and(|m| {
                m.is_regular_file
                    && m.file_id.is_some()
                    && m.file_id == result.internal.zpart_file_id
            }) {
                self.inner.fs.remove_file(partial)?;
            }
            self.inner.journal.transact(|t| {
                t.remove_ranges(id, None)?;
                t.remove_unit_crcs(id)?;
                t.remove_reservation(&path_key(Path::new(&result.internal.dest_path)))
            })?;
        }
        if matches!(action, ControlAction::Resume | ControlAction::Retry)
            && result.job.state == JobState::Queued
        {
            self.start(id);
        }
        Ok(ControlReceipt {
            summary: result.summary(),
            job: result.job,
        })
    }
    /// Re-hashes a completed file from disk and compares the expected digest.
    pub async fn verify(
        &self,
        id: JobId,
        expected_sha256: Option<Hex256>,
    ) -> EngineResult<zeus_verify::hash::Digests> {
        let job = self.get(id).await?;
        let result = job
            .result
            .ok_or_else(|| rejected(codes::API_INVALID_TRANSITION, "job has no completed file"))?;
        let expected = expected_sha256.unwrap_or(result.sha256);
        let digests = blocking(move || {
            Ok(zeus_verify::hash::verify_file(
                Path::new(&result.path),
                &Default::default(),
                &mut |_| true,
            )?
            .0)
        })
        .await?;
        if digests.sha256 != expected {
            return Err(rejected(
                codes::INTEGRITY_HASH_MISMATCH,
                "file checksum does not match",
            ));
        }
        Ok(digests)
    }
    /// Replays durable events, then follows live events with lag notification.
    pub fn subscribe(
        &self,
        since: Option<EventSeq>,
        include_progress: bool,
    ) -> EngineResult<EventSubscription> {
        let live = self.inner.events.subscribe();
        let head = EventSeq::new(self.inner.journal.meta()?.last_event_seq)
            .ok()
            .or(since);
        let journal = self.inner.journal.clone();
        let replay = futures::stream::unfold(
            (
                journal,
                since,
                std::collections::VecDeque::<Event>::new(),
                false,
            ),
            move |(journal, mut cursor, mut queue, mut ended)| async move {
                if ended {
                    return None;
                }
                if queue.is_empty() {
                    if cursor >= head {
                        return None;
                    }
                    match journal.read(|t| t.events_since(cursor, 256)) {
                        Ok(events) => queue.extend(events.into_iter().filter(|e| e.seq <= head)),
                        Err(_) => {
                            return Some((
                                EngineEvent::Lagged { missed: 1 },
                                (journal, cursor, queue, true),
                            ));
                        }
                    }
                }
                let event = queue.pop_front()?;
                cursor = event.seq;
                ended = cursor >= head;
                Some((EngineEvent::Event(event), (journal, cursor, queue, ended)))
            },
        );
        let live =
            futures::stream::unfold((live, head), move |(mut receiver, mut last)| async move {
                loop {
                    match receiver.recv().await {
                        Ok(event) => {
                            if event.seq.is_some() && event.seq <= last {
                                continue;
                            }
                            if event.seq.is_none() && !include_progress {
                                continue;
                            }
                            if event.seq.is_some() {
                                last = event.seq;
                            }
                            return Some((EngineEvent::Event(event), (receiver, last)));
                        }
                        Err(broadcast::error::RecvError::Lagged(missed)) => {
                            return Some((EngineEvent::Lagged { missed }, (receiver, last)));
                        }
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                }
            });
        Ok(EventSubscription::new(Box::pin(replay.chain(live))))
    }
    /// Accepts only decisions already authenticated and recorded by a human approval manager.
    pub async fn apply_approval(&self, resolution: ApprovalResolution) -> EngineResult<()> {
        let _gate = self.inner.gate.lock().await;
        let approval = self
            .inner
            .journal
            .read(|t| t.approval(resolution.approval.id))?
            .ok_or(EngineError::NotFound { what: "approval" })?;
        let id = resolution.job_id.or(approval.job_id).ok_or_else(|| {
            rejected(
                codes::API_INVALID_TRANSITION,
                "approval does not name a job",
            )
        })?;
        let job = self.get(id).await?;
        if job.state != JobState::AwaitingApproval || job.approval_id != Some(approval.id) {
            return Err(rejected(
                codes::API_INVALID_TRANSITION,
                "job is not waiting for this approval",
            ));
        }
        let decision = approval.decision.as_ref().ok_or_else(|| {
            rejected(
                codes::POLICY_APPROVAL_DENIED,
                "approval has no durable decision",
            )
        })?;
        let expired = approval.state == ApprovalState::Expired
            && decision.outcome == DecisionOutcome::Expire
            && decision.actor.kind == ActorKind::System;
        if !expired
            && (approval.request_hash.is_none()
                || approval.revision.is_none()
                || !decision.actor.is_human_on_trust_surface())
        {
            return Err(rejected(
                codes::POLICY_APPROVAL_DENIED,
                "approval lacks trusted decision evidence",
            ));
        }
        let approved = approval.state == ApprovalState::Approved
            && decision.outcome == DecisionOutcome::Approve;
        let grant = if approved {
            self.ensure_running()?;
            if !decision
                .actor
                .surface
                .is_some_and(Surface::is_approving_surface)
                || approval.decided_at.is_none_or(|t| t >= approval.expires_at)
            {
                return Err(rejected(
                    codes::POLICY_APPROVAL_DENIED,
                    "approval evidence is expired or unsupported",
                ));
            }
            let origin = job.spec.session_origin.as_ref().ok_or_else(internal)?;
            match self.effective_grant(origin, Some(id), job.spec.source.run_id)? {
                zeus_session::consent::Resolution::Allowed(g) => Some(g),
                _ => {
                    return Err(rejected(
                        codes::POLICY_APPROVAL_DENIED,
                        "approved job lacks an effective durable grant",
                    ));
                }
            }
        } else {
            None
        };
        if !approved
            && !matches!(
                approval.state,
                ApprovalState::Denied | ApprovalState::Expired
            )
        {
            return Err(rejected(
                codes::API_INVALID_TRANSITION,
                "approval is not a terminal decision",
            ));
        }
        let error =
            ErrorEnvelope::from_code(codes::POLICY_APPROVAL_DENIED, "human denied the download");
        let outcome = self.inner.journal.apply_transition(
            TransitionRequest {
                job_id: id,
                transition: if approved { "S30" } else { "S31" },
                trigger: if expired {
                    TransitionActor::System
                } else {
                    TransitionActor::Human
                },
                cause: if approved {
                    StateCause::ApprovalApproved
                } else if expired {
                    StateCause::ApprovalExpired
                } else {
                    StateCause::ApprovalDenied
                },
                actor: decision.actor.clone(),
                now: self.inner.clock.now(),
                events_before: vec![],
                events_after: if approved {
                    vec![]
                } else {
                    vec![
                        JobFailedData {
                            error: error.clone(),
                            suggested_next: SuggestedNext {
                                action: SuggestedAction::None,
                                tool: None,
                            },
                        }
                        .into(),
                    ]
                },
            },
            &mut |r| {
                r.job.approval_id = None;
                r.job.grant_id = grant.as_ref().map(|g| g.id);
                if !approved {
                    r.job.error = Some(error.clone());
                }
                Ok(())
            },
        )?;
        self.publish(outcome.events);
        if approved {
            self.start(id);
        }
        Ok(())
    }
    /// Re-evaluates jobs after durable revocation or expiry, stopping their writers first.
    pub async fn grants_changed(&self, change: GrantChange) -> EngineResult<()> {
        let _gate = self.inner.gate.lock().await;
        for record in self.inner.journal.list_incomplete()? {
            if record.job.spec.session_origin.as_ref() != Some(&change.origin)
                || matches!(
                    self.effective_grant(
                        &change.origin,
                        Some(record.id()),
                        record.job.spec.source.run_id
                    )?,
                    zeus_session::consent::Resolution::Allowed(_)
                )
            {
                continue;
            }
            if !matches!(
                record.job.state,
                JobState::Queued
                    | JobState::Probing
                    | JobState::Downloading
                    | JobState::AwaitingSession
            ) {
                continue;
            }
            self.stop_worker(record.id()).await;
            let record = self.record(record.id())?;
            let (transition, trigger, cause) = match record.job.state {
                JobState::Queued => (
                    "S07",
                    TransitionActor::Policy,
                    if change.kind == GrantChangeKind::Revoked {
                        StateCause::GrantRevoked
                    } else {
                        StateCause::GrantExpired
                    },
                ),
                JobState::Probing => ("S11", TransitionActor::Engine, StateCause::ApprovalNeeded),
                JobState::Downloading => (
                    "S23",
                    TransitionActor::Policy,
                    if change.kind == GrantChangeKind::Revoked {
                        StateCause::GrantRevoked
                    } else {
                        StateCause::GrantExpired
                    },
                ),
                JobState::AwaitingSession => (
                    "S41",
                    TransitionActor::Policy,
                    if change.kind == GrantChangeKind::Revoked {
                        StateCause::GrantRevoked
                    } else {
                        StateCause::GrantExpired
                    },
                ),
                _ => continue,
            };
            let reason = if change.kind == GrantChangeKind::Revoked {
                "grant.revoked"
            } else {
                "grant.expired"
            };
            let approval = self.replacement_approval(&record, reason).await;
            let now = self.inner.clock.now();
            let mut public = approval.clone();
            public.facts = None;
            public.agent_says = None;
            let outcome = self.inner.journal.transact(|t| {
                t.put_approval(&approval)?;
                zeus_journal::apply_transition_in(
                    t,
                    TransitionRequest {
                        job_id: record.id(),
                        transition,
                        trigger,
                        cause,
                        actor: Actor::system(),
                        now,
                        events_before: vec![],
                        events_after: vec![ApprovalRequestedData { approval: public }.into()],
                    },
                    &mut |r| {
                        r.job.approval_id = Some(approval.id);
                        r.job.grant_id = None;
                        r.job.retry.session_wait_deadline_at = None;
                        Ok(())
                    },
                )
            })?;
            self.publish(outcome.events);
        }
        Ok(())
    }
    /// Atomically changes the emergency-stop latch and its policy effects. The embedding daemon
    /// authenticates the actor and writes the audit intent before calling. Release restores nothing.
    pub async fn set_kill_switch(
        &self,
        engaged: bool,
        actor: Actor,
    ) -> EngineResult<KillSwitchOutcome> {
        if actor.kind != ActorKind::Human
            || !actor.surface.is_some_and(|s| {
                if engaged {
                    s.is_trust_surface()
                } else {
                    s.is_approving_surface()
                }
            })
        {
            return Err(rejected(
                codes::API_HUMAN_REQUIRED,
                "kill switch requires a human trust surface",
            ));
        }
        let _gate = self.inner.gate.lock().await;
        let mut approvals = BTreeMap::new();
        if engaged {
            for r in self.inner.journal.list_incomplete()? {
                if r.job.state == JobState::AwaitingSession {
                    approvals.insert(r.id(), self.replacement_approval(&r, "kill_switch").await);
                }
            }
        }
        let now = self.inner.clock.now();
        let (outcome, events, stopped) = self.inner.journal.transact(|t| {
            t.set_kill_switch(engaged)?;
            let mut outcome = KillSwitchOutcome {
                engaged,
                ..Default::default()
            };
            let mut events = Vec::new();
            let mut stopped = Vec::new();
            if engaged {
                for r in t.jobs(&Default::default())? {
                    let transition = match r.job.state {
                        JobState::Queued => "S05",
                        JobState::Probing => "S15",
                        JobState::Downloading => "S24",
                        JobState::RetryScheduled => "S61",
                        _ => continue,
                    };
                    let changed = zeus_journal::apply_transition_in(
                        t,
                        TransitionRequest {
                            job_id: r.id(),
                            transition,
                            trigger: TransitionActor::Client,
                            cause: StateCause::UserRequest,
                            actor: actor.clone(),
                            now,
                            events_before: vec![],
                            events_after: vec![],
                        },
                        &mut |_| Ok(()),
                    )?;
                    events.extend(changed.events);
                    stopped.push(r.id());
                    outcome.jobs_paused += 1;
                }
                for mut grant in t.grants()? {
                    if grant.state == GrantState::Active && grant.scope != GrantScope::Never {
                        grant.state = GrantState::Revoked;
                        grant.revoked_at = Some(now);
                        grant.revoked_by = Some(actor.clone());
                        grant.revocation_reason = Some(RevocationReason::KillSwitch);
                        t.put_grant(&grant)?;
                        events.push(
                            t.append_event(
                                now,
                                None,
                                None,
                                GrantRevokedData {
                                    grant_id: grant.id,
                                    origin: grant.origin,
                                    by: actor.clone(),
                                }
                                .into(),
                            )?,
                        );
                        outcome.grants_revoked += 1;
                    }
                }
                for r in t.jobs(&Default::default())? {
                    if r.job.state == JobState::AwaitingSession {
                        let approval = approvals
                            .remove(&r.id())
                            .unwrap_or_else(|| self.unbound_approval(&r, "kill_switch"));
                        let mut public = approval.clone();
                        public.facts = None;
                        public.agent_says = None;
                        t.put_approval(&approval)?;
                        let changed = zeus_journal::apply_transition_in(
                            t,
                            TransitionRequest {
                                job_id: r.id(),
                                transition: "S41",
                                trigger: TransitionActor::Policy,
                                cause: StateCause::GrantRevoked,
                                actor: actor.clone(),
                                now,
                                events_before: vec![],
                                events_after: vec![
                                    ApprovalRequestedData { approval: public }.into(),
                                ],
                            },
                            &mut |r| {
                                r.job.grant_id = None;
                                r.job.approval_id = Some(approval.id);
                                r.job.retry.session_wait_deadline_at = None;
                                Ok(())
                            },
                        )?;
                        events.extend(changed.events);
                        stopped.push(r.id());
                    }
                }
            }
            events.push(
                t.append_event(
                    now,
                    None,
                    None,
                    DaemonKillSwitchData {
                        engaged,
                        grants_revoked: outcome.grants_revoked,
                        jobs_paused: outcome.jobs_paused,
                        by: actor.clone(),
                    }
                    .into(),
                )?,
            );
            Ok((outcome, events, stopped))
        })?;
        self.publish(events);
        for id in stopped {
            self.stop_worker(id).await;
        }
        Ok(outcome)
    }
    async fn replacement_approval(&self, record: &JobRecord, reason: &str) -> Approval {
        let fallback = self.unbound_approval(record, reason);
        if let Some(port) = &self.inner.approvals {
            let request = crate::ports::ApprovalRequest {
                job: Some(record.job.clone()),
                dest_path: Some(record.internal.dest_path.clone()),
                kind: fallback.kind,
                job_id: fallback.job_id,
                run_id: fallback.run_id,
                origin: fallback.origin.clone(),
                allowed_scopes: fallback.allowed_scopes.clone(),
                reason_codes: fallback.reason_codes.clone(),
                summary: fallback.summary.clone(),
            };
            if let Ok(approval) = port.request(request).await
                && approval.state == ApprovalState::Pending
                && approval.job_id == Some(record.id())
                && approval.origin == fallback.origin
                && approval.request_hash.is_some()
                && approval.revision.is_some()
            {
                return approval;
            }
        }
        // Emergency restriction must still take effect when the approval manager is unavailable.
        // An unbound request is displayable and cancelable, but apply_approval will never approve it.
        fallback
    }
    fn unbound_approval(&self, r: &JobRecord, reason: &str) -> Approval {
        let now = self.inner.clock.now();
        let kind = ApprovalKind::SessionGrant;
        Approval {
            id: self.inner.ids.approval_id(),
            request_hash: None,
            requested_by: r.job.spec.source.client_id.clone(),
            revision: None,
            facts: None,
            agent_says: None,
            kind,
            state: ApprovalState::Pending,
            job_id: Some(r.id()),
            run_id: r.job.spec.source.run_id,
            origin: r.job.spec.session_origin.clone(),
            allowed_scopes: kind.default_allowed_scopes().to_vec(),
            reason_codes: vec![reason.into(), "approval.binding_unavailable".into()],
            summary: ApprovalSummary {
                title: r
                    .job
                    .spec
                    .filename
                    .clone()
                    .unwrap_or_else(|| "Download requires consent".into()),
                url_redacted: Some(r.job.spec.url.redact(RedactMode::Log)),
                total_bytes: r.job.progress.bytes_total,
                source_kind: Some(r.job.spec.source.kind),
                requested_by: r.job.spec.source.client_id.clone(),
            },
            created_at: now,
            expires_at: now.saturating_add_ms(kind.default_expiry_ms()),
            decided_at: None,
            decision: None,
        }
    }
    /// Pauses interruptible jobs and waits for their writers to stop.
    pub async fn pause_all(&self) -> EngineResult<u64> {
        let mut count = 0;
        for r in self.inner.journal.list_incomplete()? {
            if matches!(
                r.job.state,
                JobState::Queued
                    | JobState::Probing
                    | JobState::Downloading
                    | JobState::RetryScheduled
            ) && self.control(r.id(), ControlAction::Pause).await.is_ok()
            {
                count += 1;
            }
        }
        Ok(count)
    }
    /// Returns durable counts and session availability.
    pub async fn status(&self) -> EngineResult<EngineStatus> {
        let mut states = Vec::<(JobState, u64)>::new();
        for r in self.inner.journal.read(|t| t.jobs(&Default::default()))? {
            if let Some((_, n)) = states.iter_mut().find(|(s, _)| *s == r.job.state) {
                *n += 1;
            } else {
                states.push((r.job.state, 1));
            }
        }
        Ok(EngineStatus {
            jobs_by_state: states,
            pending_approvals: self
                .inner
                .journal
                .read(|t| t.approvals(Some(&[ApprovalState::Pending])))?
                .into_iter()
                .map(|a| a.id)
                .collect(),
            extension_connected: self
                .inner
                .session
                .as_ref()
                .is_some_and(|p| p.extension_connected(None)),
            head_seq: self.inner.journal.meta()?.last_event_seq,
        })
    }
    /// Stop admission immediately and publish one durable stopping event before draining.
    /// Repeated calls retain the initiating reason; failed persistence can be retried.
    pub fn begin_shutdown(&self, reason: StopReason) -> EngineResult<()> {
        self.inner.stopping.store(true, Ordering::Release);
        let mut notice = self
            .inner
            .shutdown_notice
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let notice = notice.get_or_insert(ShutdownNotice {
            reason,
            emitted: false,
        });
        if !notice.emitted {
            let event = self.inner.journal.transact(|tx| {
                tx.append_event(
                    self.inner.clock.now(),
                    None,
                    None,
                    DaemonStoppingData {
                        reason: notice.reason,
                    }
                    .into(),
                )
            })?;
            notice.emitted = true;
            self.publish(vec![event]);
        }
        Ok(())
    }
    /// Stops admission and waits for all writers; durable active jobs resume on next startup.
    pub async fn shutdown(&self) -> EngineResult<()> {
        let announced = self.begin_shutdown(StopReason::UserRequest);
        // Serialize with in-progress admissions and concurrent drain calls.
        let _gate = self.inner.gate.lock().await;
        let running = std::mem::take(
            &mut *self
                .inner
                .running
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        // Signal every worker before waiting for any potentially slow disk operation.
        for worker in running.values() {
            worker.cancel.cancel();
        }
        for (_, mut worker) in running {
            while !*worker.done.borrow_and_update() {
                if worker.done.changed().await.is_err() {
                    break;
                }
            }
        }
        announced
    }
    fn effective_grant(
        &self,
        origin: &Origin,
        job: Option<JobId>,
        run: Option<RunId>,
    ) -> EngineResult<zeus_session::consent::Resolution> {
        use zeus_session::consent::Resolution;
        let grants = self.inner.journal.read(|t| t.grants())?;
        match resolve_grant(grants.iter(), origin, job, run, self.inner.clock.now()) {
            GrantResolution::Allowed(g) => Ok(Resolution::Allowed(g.clone())),
            GrantResolution::Denied(g) => Ok(Resolution::Denied(g.clone())),
            GrantResolution::None => {
                Ok(self
                    .inner
                    .consent
                    .resolve(origin, job, run, self.inner.clock.now())?)
            }
        }
    }
    fn ensure_running(&self) -> EngineResult<()> {
        if self.inner.stopping.load(Ordering::Acquire) {
            return Err(EngineError::ShuttingDown);
        }
        if self.inner.journal.meta()?.kill_switch_engaged() {
            return Err(rejected(
                codes::POLICY_KILL_SWITCH_ENGAGED,
                "the kill switch is engaged",
            ));
        }
        Ok(())
    }
    fn publish(&self, events: Vec<Event>) {
        for event in events {
            let _ = self.inner.events.send(event);
        }
    }
    fn start(&self, id: JobId) {
        if self.inner.stopping.load(Ordering::Acquire) {
            return;
        }
        let cancel = CancellationToken::new();
        let (tx, rx) = watch::channel(false);
        self.inner
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(
                id,
                Running {
                    cancel: cancel.clone(),
                    done: rx,
                },
            );
        let engine = self.clone();
        tokio::spawn(async move {
            loop {
                if cancel.is_cancelled() {
                    break;
                }
                let Ok(record) = engine.record(id) else { break };
                if record.job.state == JobState::RetryScheduled {
                    let delay = record
                        .job
                        .retry
                        .next_attempt_at
                        .and_then(|at| at.duration_since(engine.inner.clock.now()))
                        .unwrap_or_default();
                    tokio::select! {biased;_=cancel.cancelled()=>break,_=tokio::time::sleep(delay)=>{}}
                    if engine.ensure_running().is_err() {
                        break;
                    }
                    if engine
                        .transition(
                            id,
                            "S60",
                            TransitionActor::System,
                            StateCause::RetryTimer,
                            vec![],
                            vec![],
                            |_| Ok(()),
                        )
                        .is_err()
                    {
                        break;
                    }
                } else if record.job.state != JobState::Queued {
                    break;
                }
                let slot = tokio::select! {biased;_=cancel.cancelled()=>None,s=engine.inner.slots.clone().acquire_owned()=>s.ok()};
                if slot.is_none() {
                    break;
                }
                let result = engine.run(id, &cancel).await;
                drop(slot);
                match result {
                    Ok(()) => break,
                    Err(error) => {
                        if cancel.is_cancelled() || engine.inner.stopping.load(Ordering::Acquire) {
                            break;
                        }
                        let mut error = error.to_envelope();
                        match engine.schedule_retry(id, &mut error) {
                            Ok(true) => continue,
                            _ => {
                                let _ = engine.fail(id, error);
                                break;
                            }
                        }
                    }
                }
            }
            engine
                .inner
                .running
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&id);
            drop(engine);
            let _ = tx.send(true);
        });
    }
    async fn stop_worker(&self, id: JobId) {
        let running = self
            .inner
            .running
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
        if let Some(mut running) = running {
            running.cancel.cancel();
            while !*running.done.borrow_and_update() {
                if running.done.changed().await.is_err() {
                    break;
                }
            }
        }
    }
    #[allow(clippy::too_many_arguments)]
    fn transition(
        &self,
        id: JobId,
        transition: &'static str,
        trigger: TransitionActor,
        cause: StateCause,
        before: Vec<EventPayload>,
        after: Vec<EventPayload>,
        mut update: impl FnMut(&mut JobRecord) -> zeus_journal::JournalResult<()>,
    ) -> EngineResult<JobRecord> {
        let result = self.inner.journal.apply_transition(
            TransitionRequest {
                job_id: id,
                transition,
                trigger,
                cause,
                actor: if trigger == TransitionActor::System {
                    Actor::system()
                } else {
                    Actor::engine()
                },
                now: self.inner.clock.now(),
                events_before: before,
                events_after: after,
            },
            &mut update,
        )?;
        self.publish(result.events);
        Ok(result.record)
    }
    fn schedule_retry(&self, id: JobId, error: &mut ErrorEnvelope) -> EngineResult<bool> {
        use zeus_types::policy::{self, budgets};
        let record = self.record(id)?;
        let transition = match record.job.state {
            JobState::Probing => "S13",
            JobState::Downloading => "S21",
            _ => return Ok(false),
        };
        if !error.retryable
            || !matches!(
                error.class,
                ErrorClass::TransientNetwork | ErrorClass::Throttled | ErrorClass::Disk
            )
        {
            return Ok(false);
        }
        self.ensure_running()?;
        let now = self.inner.clock.now();
        let mut counts = record.internal.retry_counts.clone();
        let code = error.code.as_str().to_owned();
        let consecutive = record.job.retry.consecutive_failures.saturating_add(1);
        let previous = record.job.error.as_ref();
        let same_code = if previous.is_some_and(|e| e.code == error.code) {
            counts
                .get("same_code")
                .copied()
                .unwrap_or(0)
                .saturating_add(1)
        } else {
            1
        };
        counts.insert("same_code".into(), same_code);
        let status = error
            .details
            .as_ref()
            .and_then(|d| d.get("status"))
            .and_then(|v| v.as_u64())
            .and_then(|v| u16::try_from(v).ok())
            .or_else(|| {
                code.strip_prefix("http.status_")
                    .and_then(|s| s.parse().ok())
            });
        let five_xx = if status.is_some_and(|s| (500..600).contains(&s)) {
            counts
                .get("http_5xx")
                .copied()
                .unwrap_or(0)
                .saturating_add(1)
        } else {
            0
        };
        counts.insert("http_5xx".into(), five_xx);
        let throttles = if error.class == ErrorClass::Throttled {
            counts
                .get("throttled")
                .copied()
                .unwrap_or(0)
                .saturating_add(1)
        } else {
            0
        };
        counts.insert("throttled".into(), throttles);
        if code == codes::NET_DNS_NXDOMAIN
            && same_code >= budgets::NXDOMAIN_BEFORE_PERMANENT
            && record.job.progress.bytes_done == 0
        {
            *error = ErrorEnvelope::from_code(
                codes::NET_HOST_NOT_FOUND,
                "host does not exist after repeated lookup failures",
            );
            return Ok(false);
        }
        if code == codes::NET_PREMATURE_EOF {
            let offset = record.job.progress.bytes_done;
            let repeats = if previous.is_some_and(|e| {
                e.code == error.code
                    && e.details
                        .as_ref()
                        .and_then(|d| d.get("committed_offset"))
                        .and_then(|v| v.as_u64())
                        == Some(offset)
            }) {
                counts
                    .get("eof_offset")
                    .copied()
                    .unwrap_or(0)
                    .saturating_add(1)
            } else {
                1
            };
            counts.insert("eof_offset".into(), repeats);
            let details = error.details.get_or_insert_with(Default::default);
            details.insert("committed_offset".into(), serde_json::json!(offset));
            if repeats >= budgets::PREMATURE_EOF_AT_SAME_OFFSET {
                *error = ErrorEnvelope::from_code(
                    codes::INTEGRITY_SIZE_MISMATCH,
                    "response repeatedly ended before its declared size",
                );
                error.retryable = false;
                return Ok(false);
            }
        } else {
            counts.remove("eof_offset");
        }
        let retry_after = error
            .details
            .as_ref()
            .and_then(|d| d.get("retry_after_ms"))
            .and_then(|v| v.as_u64());
        if retry_after.is_some_and(|v| v > budgets::MAX_RETRY_AFTER_MS) {
            *error = ErrorEnvelope::from_code(
                codes::HTTP_RETRY_AFTER_TOO_LONG,
                "server retry delay exceeds the approved retry horizon",
            );
            return Ok(false);
        }
        let since = record
            .internal
            .retry_no_progress_since
            .or(record.job.retry.last_progress_at)
            .unwrap_or(now);
        if five_xx >= budgets::CONSECUTIVE_5XX
            || throttles >= budgets::THROTTLES_WITHOUT_PROGRESS
            || now
                .duration_since(since)
                .is_some_and(|d| d.as_millis() >= u128::from(budgets::TRANSIENT_STALL_LIMIT_MS))
        {
            return Ok(false);
        }
        let backoff = if error.class == ErrorClass::Disk {
            let Some(policy) = policy::disk_retry(&code) else {
                return Ok(false);
            };
            if same_code >= policy.attempts {
                return Ok(false);
            }
            zeus_control::Backoff::new(
                policy::BackoffSpec {
                    base_ms: policy.base_ms,
                    cap_ms: policy.cap_ms,
                    floor_ms: policy.base_ms.min(250),
                },
                zeus_control::Jitter::Full,
            )
        } else {
            zeus_control::Backoff::for_class(error.class).ok_or_else(internal)?
        };
        let delay = zeus_control::with_retry_after(
            backoff.delay_ms(
                consecutive,
                None,
                self.inner
                    .rng
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .as_mut(),
            ),
            retry_after,
        );
        let next = now.saturating_add_ms(delay);
        let mut after = vec![
            JobRetryScheduledData {
                attempt: consecutive,
                error: error.clone(),
                delay_ms: delay,
                next_attempt_at: next,
                restart_from_zero: false,
            }
            .into(),
        ];
        if error.class == ErrorClass::Throttled {
            after.push(
                JobThrottledData {
                    host: record
                        .job
                        .spec
                        .url
                        .url()
                        .host_str()
                        .unwrap_or_default()
                        .into(),
                    status,
                    retry_after_ms: retry_after,
                    concurrency_before: self.inner.config.limits.connections_per_job,
                    concurrency_after: self.inner.config.limits.connections_per_job,
                }
                .into(),
            );
        }
        self.transition(
            id,
            transition,
            TransitionActor::Engine,
            StateCause::Error,
            vec![],
            after,
            |r| {
                r.job.error = Some(error.clone());
                r.job.retry.consecutive_failures = consecutive;
                r.job.retry.next_attempt_at = Some(next);
                r.internal.retry_no_progress_since = Some(since);
                r.internal.retry_counts = counts.clone();
                r.job.progress.last_error_class = Some(error.class);
                Ok(())
            },
        )?;
        Ok(true)
    }
    fn fail(&self, id: JobId, error: ErrorEnvelope) -> EngineResult<()> {
        // Shutdown is an interruption, never a terminal resource failure. In-flight
        // states remain durable for the recovery transition on the next build.
        if self.inner.stopping.load(Ordering::Acquire)
            || error.code.as_str() == codes::ENGINE_SHUTDOWN
        {
            return Ok(());
        }
        let state = self.record(id)?.job.state;
        let (transition, cause, trigger) = match state {
            JobState::Queued => ("S08", StateCause::Policy, TransitionActor::Policy),
            JobState::Probing => ("S14", StateCause::Error, TransitionActor::Engine),
            JobState::Downloading => ("S25", StateCause::Error, TransitionActor::Engine),
            JobState::Verifying => ("S72", StateCause::Error, TransitionActor::Engine),
            JobState::Finalizing => ("S82", StateCause::FinalizeError, TransitionActor::Engine),
            _ => return Ok(()),
        };
        let payload = JobFailedData {
            error: error.clone(),
            suggested_next: SuggestedNext {
                action: SuggestedAction::Retry,
                tool: Some("zeus_control".into()),
            },
        }
        .into();
        self.transition(id, transition, trigger, cause, vec![], vec![payload], |r| {
            r.job.retry.consecutive_failures = r.job.retry.consecutive_failures.saturating_add(1);
            r.job.error = Some(error.clone());
            r.job.progress.last_error_class = Some(error.class);
            Ok(())
        })?;
        Ok(())
    }
}
fn path_key(path: &Path) -> String {
    let s = path.to_string_lossy().into_owned();
    if cfg!(windows) { s.to_lowercase() } else { s }
}

impl Engine {
    async fn run(&self, id: JobId, cancel: &CancellationToken) -> EngineResult<()> {
        if cancel.is_cancelled() {
            return Err(HttpError::Canceled.into());
        }
        self.ensure_running()?;
        let mut record = self.record(id)?;
        self.inner
            .roots
            .root_for(Path::new(&record.internal.dest_path))?
            .check_existing(Path::new(&record.internal.dest_path))?;
        let assessment = zeus_journal::recovery::assess_resume(
            self.inner.fs.as_ref(),
            &record,
            &self.inner.journal,
        )?;
        if let Some(reason) = assessment.invalidated {
            self.inner
                .journal
                .invalidate_all(id, reason, self.inner.clock.now(), &mut |r| {
                    r.internal.data_complete = false;
                    Ok(())
                })?;
            record = self.record(id)?;
        }
        if record.internal.data_complete {
            self.transition(
                id,
                "S04",
                TransitionActor::Engine,
                StateCause::Scheduler,
                vec![],
                vec![],
                |_| Ok(()),
            )?;
            return self.finalize(id).await;
        }
        record = self.transition(
            id,
            "S03",
            TransitionActor::Engine,
            StateCause::Scheduler,
            vec![],
            vec![],
            |r| {
                r.job.retry.attempt += 1;
                Ok(())
            },
        )?;
        let spec = record.job.spec.clone();
        let mut transport = match self
            .inner
            .job_transports
            .as_ref()
            .map(|f| f.for_job_id(id, &spec))
            .transpose()
            .map_err(EngineError::Rejected)?
            .flatten()
        {
            Some(t) => t,
            None if spec.source.kind == SourceKind::Workflow => {
                return Err(rejected(
                    codes::POLICY_APPROVAL_DENIED,
                    "workflow requires an enforcing network transport",
                ));
            }
            None => self.inner.transport.clone(),
        };
        let mut browser_proxy = spec.transport_hint() == TransportHint::BrowserProxy;
        let mut session = if browser_proxy {
            match self.browser_transport(id)? {
                Some(proxy) => {
                    transport = proxy;
                    None
                }
                None => return Ok(()),
            }
        } else {
            self.session_binding(id, cancel).await?
        };
        if self.record(id)?.job.state == JobState::AwaitingSession {
            return Ok(());
        }
        transport = self.bounded_transport(transport);
        let request = ProbeRequest {
            url: spec.url.clone(),
            hint_url: spec.hint_url.clone(),
            referrer: spec.referrer.clone(),
            extra_headers: spec.extra_headers.clone(),
            session: session.clone(),
            resume: None,
            head_timeout: self.inner.config.timeouts.probe,
            idle_timeout: self.inner.config.timeouts.read,
        };
        let attempted = HttpProber::new(transport.clone())
            .probe(request.clone(), cancel)
            .await;
        let mut probe = match attempted {
            Err(error)
                if error
                    .envelope()
                    .is_some_and(|e| e.class == ErrorClass::Blocked)
                    && spec.transport_hint() == TransportHint::Auto
                    && spec.source.kind != SourceKind::Workflow
                    && spec.session_origin.is_some()
                    && self.inner.proxy.is_some() =>
            {
                let Some(proxy) = self.browser_transport(id)? else {
                    return Ok(());
                };
                transport = self.bounded_transport(proxy);
                session = None;
                browser_proxy = true;
                HttpProber::new(transport.clone())
                    .probe(
                        ProbeRequest {
                            session: None,
                            ..request
                        },
                        cancel,
                    )
                    .await?
            }
            result => result?,
        };
        if browser_proxy {
            probe.result.transport = Transport::BrowserProxy;
        }
        if spec.expected_size.is_some()
            && probe.result.total_bytes.is_some()
            && spec.expected_size != probe.result.total_bytes
        {
            return Err(rejected(
                codes::INTEGRITY_SIZE_MISMATCH,
                "resource size does not match expected size",
            ));
        }
        let committed = self.inner.journal.committed(id)?;
        if !committed.is_empty()
            && (probe.result.range_support != RangeSupport::Verified
                || !record.internal.bound_validators.is_strongly_identified()
                || record.internal.bound_validators.if_range_value()
                    != probe.result.validators.if_range_value()
                || record.internal.total_bytes != probe.result.total_bytes)
        {
            self.inner.journal.invalidate_all(
                id,
                InvalidationReason::ValidatorChanged,
                self.inner.clock.now(),
                &mut |r| {
                    r.internal.data_complete = false;
                    Ok(())
                },
            )?;
        }
        let record_for_file = self.record(id)?;
        let fs = self.inner.fs.clone();
        let file: Arc<dyn DataFile> = blocking(move || {
            let path = Path::new(&record_for_file.internal.zpart_path);
            let exists = fs.metadata(path)?.is_some();
            // Existing partial data is only reused if the journal recorded its identity.
            if exists && record_for_file.internal.zpart_file_id.is_none() {
                return Err(zeus_fs::FsError::AlreadyExists.into());
            }
            let opened = if exists {
                fs.open_existing(path)?
            } else {
                fs.create_new(path)?
            };
            if exists && record_for_file.internal.zpart_file_id.as_ref() != Some(&opened.file_id()?)
            {
                return Err(zeus_fs::FsError::AlreadyExists.into());
            }
            Ok(Arc::from(opened))
        })
        .await?;
        if self.inner.journal.committed(id)?.is_empty() {
            let f = file.clone();
            blocking(move || {
                f.set_len(0)?;
                Ok(())
            })
            .await?;
        }
        let file_id = file.file_id()?;
        let result = probe.result.clone();
        record = self.transition(
            id,
            "S10",
            TransitionActor::Engine,
            StateCause::ProbeOk,
            vec![
                JobProbedData {
                    probe: result.clone(),
                }
                .into(),
            ],
            vec![],
            |r| {
                r.job.transport = result.transport;
                r.job.probe = Some(result.clone());
                r.job.progress.bytes_total = result.total_bytes;
                r.internal.zpart_file_id = Some(file_id.clone());
                r.internal.total_bytes = result.total_bytes;
                r.internal.bound_validators = result.validators.clone();
                r.internal.range_support = result.range_support;
                Ok(())
            },
        )?;
        if probe.result.range_support == RangeSupport::Verified
            && probe.result.total_bytes.is_some()
        {
            let total = probe.result.total_bytes.unwrap_or(0);
            self.download_ranges(
                adaptive::RangeRun {
                    id,
                    epoch: record.internal.epoch,
                    file: file.clone(),
                    transport,
                    browser_proxy,
                    max_connections: spec.max_connections().into(),
                    request: SegmentRequest {
                        url: probe.resolved_url.clone(),
                        range: ByteRange {
                            start: 0,
                            end: total,
                        },
                        bound_validators: probe.result.validators.clone(),
                        total_bytes: Some(total),
                        session,
                        extra_headers: spec.extra_headers.clone(),
                        head_timeout: self.inner.config.timeouts.probe,
                        idle_timeout: self.inner.config.timeouts.read,
                        chunk_bytes: 64 * 1024,
                    },
                },
                cancel,
            )
            .await?;
        } else if let Some(mut body) = probe.body {
            let mut buffer =
                Vec::with_capacity(self.inner.config.commit.commit_unit_bytes as usize);
            let mut offset = 0u64;
            loop {
                if session.as_ref().is_some_and(|b| {
                    b.material.issued_at.saturating_add_ms(b.material.ttl_ms)
                        <= self.inner.clock.now()
                }) {
                    return Err(rejected(
                        codes::HTTP_FORBIDDEN_SESSION,
                        "session lease expired during transfer",
                    ));
                }
                let next = tokio::select! { biased; _ = cancel.cancelled() => return Err(HttpError::Canceled.into()), chunk = body.next() => chunk };
                let Some(chunk) = next else {
                    break;
                };
                let chunk = chunk.map_err(|e| {
                    EngineError::Rejected(
                        zeus_http::classify_transport(e.kind).envelope("download stream failed"),
                    )
                })?;
                if probe
                    .result
                    .total_bytes
                    .is_some_and(|t| offset + buffer.len() as u64 + chunk.len() as u64 > t)
                {
                    return Err(rejected(
                        codes::INTEGRITY_RANGE_OVERRUN,
                        "stream exceeds declared size",
                    ));
                }
                for mut part in chunk.chunks(64 * 1024) {
                    while !part.is_empty() {
                        let count = part.len().min(
                            self.inner.config.commit.commit_unit_bytes as usize - buffer.len(),
                        );
                        buffer.extend_from_slice(&part[..count]);
                        part = &part[count..];
                        if buffer.len() as u64 == self.inner.config.commit.commit_unit_bytes {
                            self.write_unit(
                                file.clone(),
                                id,
                                record.internal.epoch,
                                offset,
                                std::mem::take(&mut buffer),
                            )
                            .await?;
                            offset += self.inner.config.commit.commit_unit_bytes;
                        }
                    }
                }
            }
            if !buffer.is_empty() {
                let len = buffer.len() as u64;
                self.write_unit(file.clone(), id, record.internal.epoch, offset, buffer)
                    .await?;
                offset += len;
            }
            if probe.result.total_bytes.is_some_and(|t| t != offset) {
                return Err(rejected(
                    codes::NET_PREMATURE_EOF,
                    "stream ended before declared size",
                ));
            }
            if self.record(id)?.job.state == JobState::Downloading {
                self.inner.journal.transact(|t| {
                    let mut r = t
                        .job(id)?
                        .ok_or(zeus_journal::JournalError::Invariant("missing job"))?;
                    r.internal.total_bytes = Some(offset);
                    r.internal.eof_size = Some(offset);
                    r.internal.data_complete = true;
                    r.job.progress.bytes_total = Some(offset);
                    t.put_job(&r)
                })?;
                self.transition(
                    id,
                    "S20",
                    TransitionActor::Engine,
                    StateCause::AllCommitted,
                    vec![],
                    vec![],
                    |_| Ok(()),
                )?;
            }
        } else if probe.result.total_bytes == Some(0) {
            self.transition(
                id,
                "S20",
                TransitionActor::Engine,
                StateCause::AllCommitted,
                vec![],
                vec![],
                |r| {
                    r.internal.data_complete = true;
                    Ok(())
                },
            )?;
        } else {
            return Err(rejected(
                codes::HTTP_PROTOCOL_ERROR,
                "resource has no usable download stream",
            ));
        }
        if cancel.is_cancelled() {
            return Err(HttpError::Canceled.into());
        }
        self.finalize(id).await
    }
    async fn write_unit(
        &self,
        file: Arc<dyn DataFile>,
        id: JobId,
        epoch: u32,
        offset: u64,
        bytes: Vec<u8>,
    ) -> EngineResult<()> {
        let crc = crc32c::crc32c(&bytes);
        let end = offset + bytes.len() as u64;
        let writer = file.clone();
        blocking(move || {
            writer.write_all_at(offset, &bytes)?;
            Ok(())
        })
        .await?;
        self.commit(file, id, epoch, ByteRange { start: offset, end }, crc)
            .await
    }
    async fn commit(
        &self,
        file: Arc<dyn DataFile>,
        id: JobId,
        epoch: u32,
        range: ByteRange,
        crc: u32,
    ) -> EngineResult<()> {
        let engine = self.clone();
        blocking(move || {
            engine.ensure_running()?;
            let current = engine.record(id)?;
            if let Some(origin) = &current.job.spec.session_origin
                && !matches!(
                    engine.effective_grant(origin, Some(id), current.job.spec.source.run_id)?,
                    zeus_session::consent::Resolution::Allowed(_)
                )
            {
                return Err(rejected(
                    codes::POLICY_APPROVAL_DENIED,
                    "session grant is no longer effective",
                ));
            }
            file.sync_data()?;
            let progress_before = engine.record(id)?.job.progress;
            let before = engine.inner.journal.meta()?.last_event_seq;
            let now = engine.inner.clock.now();
            let mut policy_error = None;
            let outcome = engine.inner.journal.commit_round_guarded(
                &[CommitUnit {
                    job_id: id,
                    range,
                    epoch,
                    crc32c: Some(crc),
                }],
                now,
                &mut |txn, record| {
                    if let Some(factory) = &engine.inner.job_transports
                        && let Err(error) =
                            factory.validate_job_commit(id, &record.job.spec, txn, range)
                    {
                        policy_error = Some(error);
                        return Ok(false);
                    }
                    if let Some(origin) = &record.job.spec.session_origin {
                        let grants = txn.grants()?;
                        return Ok(matches!(
                            resolve_grant(
                                grants.iter(),
                                origin,
                                Some(id),
                                record.job.spec.source.run_id,
                                now
                            ),
                            GrantResolution::Allowed(_)
                        ));
                    }
                    Ok(true)
                },
            )?;
            if let Some(error) = policy_error {
                return Err(EngineError::Rejected(error));
            }
            if !outcome.discarded.is_empty() {
                return Err(HttpError::Canceled.into());
            }
            let events = engine
                .inner
                .journal
                .read(|t| t.events_since(EventSeq::new(before).ok(), 1024))?;
            engine.publish(events);
            let now = engine.inner.clock.now();
            let progress = engine.inner.journal.transact(|t| {
                let mut r = t
                    .job(id)?
                    .ok_or(zeus_journal::JournalError::Invariant("missing job"))?;
                let elapsed = now
                    .duration_since(progress_before.updated_at)
                    .unwrap_or_default()
                    .as_millis()
                    .max(1) as u64;
                let sample = r
                    .job
                    .progress
                    .bytes_done
                    .saturating_sub(progress_before.bytes_done)
                    .saturating_mul(1000)
                    / elapsed;
                r.job.progress.rate_ewma = if r.job.state == JobState::Downloading {
                    (progress_before.rate_ewma.saturating_mul(4) + sample) / 5
                } else {
                    0
                };
                r.job.progress.eta_s = Progress::compute_eta_s(
                    r.job.progress.bytes_done,
                    r.job.progress.bytes_total,
                    r.job.progress.rate_ewma,
                );
                r.job.progress.updated_at = now;
                let p = r.job.progress.clone();
                t.put_job(&r)?;
                Ok(p)
            })?;
            engine.publish(vec![
                Event::ephemeral(
                    engine.inner.journal.meta()?.last_event_seq,
                    now,
                    JobProgressData { progress },
                )
                .with_job(id),
            ]);
            Ok(())
        })
        .await
    }
    async fn finalize(&self, id: JobId) -> EngineResult<()> {
        let engine = self.clone();
        blocking(move || {
            let record = engine.record(id)?;
            let path = Path::new(&record.internal.zpart_path);
            let (digests, head) =
                zeus_verify::hash::verify_file(path, &Default::default(), &mut |_| true)?;
            if record
                .job
                .spec
                .expected_size
                .or(record.internal.total_bytes)
                .is_some_and(|n| n != digests.size_bytes)
            {
                return Err(rejected(
                    codes::INTEGRITY_SIZE_MISMATCH,
                    "completed file size does not match",
                ));
            }
            if record
                .job
                .spec
                .expected_sha256
                .is_some_and(|hash| hash != digests.sha256)
            {
                return Err(rejected(
                    codes::INTEGRITY_HASH_MISMATCH,
                    "completed file checksum does not match",
                ));
            }
            let name = Path::new(&record.internal.dest_path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy();
            let declared = record
                .job
                .probe
                .as_ref()
                .and_then(|p| p.content_type.as_deref());
            let (verdict, detected) = zeus_verify::content::check_content(
                engine.inner.detector.as_ref(),
                &head,
                &zeus_verify::content::ContentClaim {
                    file_name: &name,
                    declared_mime: declared,
                },
            )?;
            let origin = record.job.spec.origin();
            let reasons = zeus_verify::quarantine::evaluate(
                &zeus_verify::quarantine::QuarantineInput {
                    file_name: &name,
                    verdict,
                    detected: detected.as_ref(),
                    origin: Some(&origin),
                    session_derived: record.job.spec.session_origin.is_some(),
                    av_flagged: false,
                },
                &Default::default(),
            )?;
            let mime = detected.map(|d| d.mime);
            let now = engine.inner.clock.now();
            let verified = JobVerifiedData {
                size_bytes: digests.size_bytes,
                sha256: digests.sha256,
                blake3: digests.blake3,
                detected_mime: mime.clone(),
                declared_mime: declared.map(str::to_owned),
                mime_match: None,
                expected_sha256_match: record.job.spec.expected_sha256.map(|_| true),
                expected_size_match: record.job.spec.expected_size.map(|_| true),
            };
            let mut events = vec![verified.into()];
            if !reasons.is_empty() {
                events.push(
                    JobQuarantinedData {
                        reasons: reasons.clone(),
                    }
                    .into(),
                );
            }
            engine.transition(
                id,
                "S70",
                TransitionActor::Engine,
                StateCause::VerificationOk,
                events,
                vec![],
                |r| {
                    r.internal.verify_result = Some(zeus_journal::VerifyResult {
                        size_bytes: digests.size_bytes,
                        sha256: digests.sha256,
                        blake3: digests.blake3,
                        detected_mime: mime.clone(),
                        verified_at: now,
                        mtime_ms: None,
                    });
                    Ok(())
                },
            )?;
            let file = engine.inner.fs.open_existing(path)?;
            let identity = file.file_id()?;
            if record.internal.zpart_file_id.as_ref() != Some(&identity) {
                return Err(zeus_fs::FsError::AlreadyExists.into());
            }
            use zeus_fs::provenance::ProvenanceMarker;
            let os_metadata = zeus_fs::provenance::NativeMarker.apply(
                path,
                &zeus_fs::provenance::ProvenanceMarks {
                    origin_url: Some(record.job.spec.url.redact(RedactMode::Strict)),
                    referrer_url: record
                        .job
                        .spec
                        .referrer
                        .as_ref()
                        .map(|u| u.redact(RedactMode::Strict)),
                    retrieved_at_unix_s: now.unix_millis() / 1000,
                },
                engine.inner.config.os_metadata,
            )?;
            file.sync_all()?;
            engine.inner.journal.transact(|t| {
                let mut r = t
                    .job(id)?
                    .ok_or(zeus_journal::JournalError::Invariant("missing job"))?;
                r.internal.os_metadata = os_metadata.clone();
                if let Some(v) = &mut r.internal.verify_result {
                    v.mtime_ms = engine
                        .inner
                        .fs
                        .metadata(path)
                        .ok()
                        .flatten()
                        .and_then(|m| u64::try_from(m.mtime_ms).ok());
                }
                r.internal.finalize = Some(zeus_journal::FinalizeState {
                    phase: zeus_journal::FinalizePhase::Intent,
                    tmp_path: r.internal.zpart_path.clone(),
                    dest_path: r.internal.dest_path.clone(),
                    file_id: identity.clone(),
                    intent_at: now,
                });
                t.put_job(&r)
            })?;
            drop(file);
            engine
                .inner
                .roots
                .root_for(Path::new(&record.internal.dest_path))?
                .check_existing(Path::new(&record.internal.dest_path))?;
            engine
                .inner
                .fs
                .rename_noreplace(path, Path::new(&record.internal.dest_path))?;
            if let Some(dir) = Path::new(&record.internal.dest_path).parent() {
                engine.inner.fs.sync_dir(dir)?;
            }
            let completed = JobCompletedData {
                path: record.internal.dest_path.clone(),
                size_bytes: digests.size_bytes,
                sha256: digests.sha256,
                blake3: digests.blake3,
                quarantined: !reasons.is_empty(),
                duration_ms: now
                    .duration_since(record.job.created_at)
                    .unwrap_or_default()
                    .as_millis() as u64,
            };
            let result = engine.inner.journal.finish_job(
                TransitionRequest {
                    job_id: id,
                    transition: "S80",
                    trigger: TransitionActor::Engine,
                    cause: StateCause::Finalized,
                    actor: Actor::engine(),
                    now,
                    events_before: vec![completed.into()],
                    events_after: vec![],
                },
                &mut |r| {
                    r.job.error = None;
                    r.job.result = Some(JobResult {
                        path: r.internal.dest_path.clone(),
                        size_bytes: digests.size_bytes,
                        sha256: digests.sha256,
                        blake3: digests.blake3,
                        detected_mime: mime.clone(),
                        completed_at: now,
                    });
                    r.job.quarantined = !reasons.is_empty();
                    r.job.quarantine_reasons = reasons.clone();
                    r.job.progress.bytes_done = digests.size_bytes;
                    r.job.progress.rate_ewma = 0;
                    r.job.progress.segments_active = 0;
                    Ok(())
                },
            )?;
            engine.publish(result.events);
            Ok(())
        })
        .await
    }
}

impl Engine {
    /// Re-evaluates waiting jobs after browser connection changes and expires overdue session waits.
    /// The embedding calls this after attach and periodically while it runs.
    pub async fn refresh_sessions(&self) -> EngineResult<()> {
        let _gate = self.inner.gate.lock().await;
        for record in self.inner.journal.list_incomplete()? {
            if record.job.state != JobState::AwaitingSession {
                continue;
            }
            if record
                .job
                .retry
                .session_wait_deadline_at
                .is_some_and(|d| d <= self.inner.clock.now())
            {
                let error = ErrorEnvelope::from_code(
                    codes::SESSION_EXTENSION_UNAVAILABLE,
                    "browser session deadline elapsed",
                );
                self.transition(
                    record.id(),
                    "S42",
                    TransitionActor::System,
                    StateCause::SessionDeadline,
                    vec![],
                    vec![
                        JobFailedData {
                            error: error.clone(),
                            suggested_next: SuggestedNext {
                                action: SuggestedAction::Retry,
                                tool: Some("zeus_control".into()),
                            },
                        }
                        .into(),
                    ],
                    |r| {
                        r.job.error = Some(error.clone());
                        Ok(())
                    },
                )?;
            } else if !self.inner.journal.meta()?.kill_switch_engaged()
                && self.inner.session.as_ref().is_some_and(|p| {
                    p.extension_connected(
                        record
                            .job
                            .spec
                            .source
                            .browser
                            .as_ref()
                            .and_then(|b| b.profile_id.as_deref()),
                    )
                })
            {
                self.transition(
                    record.id(),
                    "S40",
                    TransitionActor::Engine,
                    StateCause::SessionDelivered,
                    vec![],
                    vec![],
                    |_| Ok(()),
                )?;
                self.start(record.id());
            }
        }
        Ok(())
    }
    fn browser_transport(&self, id: JobId) -> EngineResult<Option<Arc<dyn HttpTransport>>> {
        let record = self.record(id)?;
        let origin = record.job.spec.session_origin.clone().ok_or_else(|| {
            rejected(
                codes::POLICY_APPROVAL_DENIED,
                "browser transport requires consent",
            )
        })?;
        self.ensure_running()?;
        if !matches!(
            self.effective_grant(&origin, Some(id), record.job.spec.source.run_id)?,
            zeus_session::consent::Resolution::Allowed(_)
        ) {
            return Err(rejected(
                codes::POLICY_APPROVAL_DENIED,
                "browser transport grant is not effective",
            ));
        }
        let profile = record
            .job
            .spec
            .source
            .browser
            .as_ref()
            .and_then(|b| b.profile_id.clone());
        let Some(provider) = self
            .inner
            .proxy
            .as_ref()
            .filter(|p| p.available(profile.as_deref()))
        else {
            self.await_session(id, &origin)?;
            return Ok(None);
        };
        Ok(Some(Arc::new(crate::proxy::BrowserTransport {
            provider: provider.clone(),
            job_id: id,
            origin,
            profile_id: profile,
        })))
    }
    async fn session_binding(
        &self,
        id: JobId,
        cancel: &CancellationToken,
    ) -> EngineResult<Option<zeus_http::SessionBinding>> {
        let record = self.record(id)?;
        let Some(origin) = record.job.spec.session_origin.clone() else {
            return Ok(None);
        };
        self.ensure_running()?;
        let grant = match self.effective_grant(&origin, Some(id), record.job.spec.source.run_id)? {
            zeus_session::consent::Resolution::Allowed(g) => g,
            _ => {
                return Err(rejected(
                    codes::POLICY_APPROVAL_DENIED,
                    "session requires an effective grant",
                ));
            }
        };
        let browser = record.job.spec.source.browser.as_ref();
        let profile = browser.and_then(|b| b.profile_id.clone());
        let provider = self
            .inner
            .session
            .as_ref()
            .filter(|p| p.extension_connected(profile.as_deref()));
        let Some(provider) = provider else {
            self.await_session(id, &origin)?;
            return Ok(None);
        };
        let audit = self.inner.audit.as_ref().ok_or_else(|| {
            rejected(
                codes::AUDIT_UNAVAILABLE,
                "session lease requires a durable audit sink",
            )
        })?;
        let mut entry = zeus_verify::AuditEntry::new(
            self.inner.clock.now(),
            Actor::engine(),
            zeus_verify::audit::actions::SESSION_LEASE_REQUESTED,
            zeus_verify::AuditOutcome::Ok,
        );
        entry.subject = zeus_verify::AuditSubject {
            job_id: Some(id),
            grant_id: Some(grant.id),
            origin: Some(origin.clone()),
            ..Default::default()
        };
        audit.append(entry)?;
        let requested = zeus_session::provider::LeaseRequest {
            job_id: id,
            grant_id: grant.id,
            origin: origin.clone(),
            url: record.job.spec.url.clone(),
            purpose: LeasePurpose::Download,
            request_headers: vec![],
            ttl: Duration::from_secs(900),
            incognito: browser.is_some_and(|b| b.incognito),
            profile_id: profile,
        };
        let lease = tokio::select! {biased;_=cancel.cancelled()=>return Err(HttpError::Canceled.into()),r=tokio::time::timeout(self.inner.config.timeouts.lease_wait,provider.lease(requested))=>match r {Ok(Ok(lease))=>lease,Ok(Err(zeus_session::SessionError::ExtensionUnavailable))|Err(_)=>{self.await_session(id,&origin)?;return Ok(None)},Ok(Err(e))=>return Err(e.into())}};
        if lease.is_expired(self.inner.clock.as_ref())
            || lease.material.origin != origin
            || lease.ttl > Duration::from_secs(900)
            || lease.material.ttl_ms > 900_000
            || lease.material.cookies.len() > 150
        {
            return Err(rejected(
                codes::HTTP_FORBIDDEN_SESSION,
                "session provider returned an invalid lease",
            ));
        }
        self.ensure_running()?;
        if !matches!(self.effective_grant(&origin,Some(id),record.job.spec.source.run_id)?,zeus_session::consent::Resolution::Allowed(g) if g.id==grant.id)
        {
            return Err(rejected(
                codes::POLICY_APPROVAL_DENIED,
                "grant changed while requesting the lease",
            ));
        }
        let material_bytes = lease
            .material
            .cookies
            .iter()
            .map(|c| c.name.len() + c.value.expose().len() + c.domain.len() + c.path.len() + 128)
            .sum::<usize>()
            + lease.material.user_agent.len()
            + lease
                .material
                .headers
                .values()
                .map(String::len)
                .sum::<usize>();
        if material_bytes > 128 * 1024
            || lease
                .material
                .cookies
                .iter()
                .any(|c| c.name.len() > 256 || c.value.expose().len() > 8192)
            || lease.material.issued_at > self.inner.clock.now().saturating_add_ms(1000)
            || lease
                .material
                .issued_at
                .saturating_add_ms(lease.material.ttl_ms)
                <= self.inner.clock.now()
        {
            return Err(rejected(
                codes::HTTP_FORBIDDEN_SESSION,
                "session material is oversized or expired",
            ));
        }
        self.inner.journal.transact(|t| {
            if let Some(mut g) = t.grant(grant.id)? {
                g.uses = g.uses.saturating_add(1);
                g.last_used_at = Some(self.inner.clock.now());
                t.put_grant(&g)?;
            }
            Ok(())
        })?;
        Ok(Some(zeus_http::SessionBinding {
            origin,
            material: lease.material,
        }))
    }
    fn await_session(&self, id: JobId, origin: &Origin) -> EngineResult<()> {
        let deadline = self
            .inner
            .clock
            .now()
            .saturating_add_ms(self.inner.config.timeouts.session_wait.as_millis() as u64);
        self.transition(
            id,
            "S12",
            TransitionActor::Engine,
            StateCause::SessionNeeded,
            vec![],
            vec![
                SessionRefreshNeededData {
                    origin: origin.clone(),
                    need: RefreshNeed::Session,
                    reason: RefreshReason::ExtensionDisconnected,
                    attempt: 1,
                    deadline_at: deadline,
                }
                .into(),
            ],
            |r| {
                r.job.retry.session_wait_deadline_at = Some(deadline);
                Ok(())
            },
        )?;
        Ok(())
    }
}
