//! Session consent is exercised through real journal transactions and a hermetic HTTPS transport.
use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, StatusCode, Version};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use zeus_control::{SharedClock, SystemClock};
use zeus_engine::*;
use zeus_http::{HttpRequest, HttpResponse, HttpTransport, TransportError};
use zeus_journal::{Journal, JournalOptions};
use zeus_session::*;
use zeus_types::*;
use zeus_verify::MemoryAuditLog;

struct Approvals {
    clock: SharedClock,
    ids: IdGenerator,
}
#[async_trait]
impl ApprovalPort for Approvals {
    async fn request(&self, r: ApprovalRequest) -> Result<Approval, ErrorEnvelope> {
        let now = self.clock.now();
        Ok(Approval {
            id: self.ids.approval_id(),
            request_hash: Some(zeus_verify::hash_bytes(b"daemon-computed-facts").blake3),
            requested_by: r.summary.requested_by.clone(),
            revision: Some(1),
            facts: Some(serde_json::Map::from_iter([(
                "private_fact".into(),
                serde_json::json!("PRIVATE-FACT-MARKER"),
            )])),
            agent_says: Some("PRIVATE-ANNOTATION".into()),
            kind: r.kind,
            state: ApprovalState::Pending,
            job_id: r.job_id,
            run_id: r.run_id,
            origin: r.origin,
            allowed_scopes: r.allowed_scopes,
            reason_codes: r.reason_codes,
            summary: r.summary,
            created_at: now,
            expires_at: now.saturating_add_ms(60_000),
            decided_at: None,
            decision: None,
        })
    }
    async fn withdraw(&self, _: ApprovalId) -> Result<(), ErrorEnvelope> {
        Ok(())
    }
}
/// Joins every request after the first to the pending approval as its next revision, as the daemon batches
/// (07 section 4.7). With `race` set, a person approves the stored revision between the join and the engine's write.
struct JoiningApprovals {
    first: Approvals,
    journal: Journal,
    pending: Mutex<Option<Approval>>,
    race: std::sync::atomic::AtomicBool,
}
#[async_trait]
impl ApprovalPort for JoiningApprovals {
    async fn request(&self, r: ApprovalRequest) -> Result<Approval, ErrorEnvelope> {
        let pending = self.pending.lock().unwrap().clone();
        let Some(stored) = pending else {
            let a = self.first.request(r).await?;
            *self.pending.lock().unwrap() = Some(a.clone());
            return Ok(a);
        };
        if self.race.load(Ordering::SeqCst) {
            let mut decided = stored.clone();
            decided.state = ApprovalState::Approved;
            self.journal.transact(|t| t.put_approval(&decided)).unwrap();
        }
        let mut joined = stored;
        joined.revision = joined.revision.map(|v| v + 1);
        *self.pending.lock().unwrap() = Some(joined.clone());
        Ok(joined)
    }
    async fn withdraw(&self, _: ApprovalId) -> Result<(), ErrorEnvelope> {
        Ok(())
    }
}
async fn joining_rig(race: bool) -> Rig {
    rig_with(false, true, None, move |clock, journal| {
        Arc::new(JoiningApprovals {
            first: Approvals {
                clock,
                ids: IdGenerator::new(),
            },
            journal,
            pending: Mutex::new(None),
            race: race.into(),
        })
    })
    .await
}
struct Browser {
    clock: SharedClock,
    audit: Arc<MemoryAuditLog>,
    calls: AtomicUsize,
    connected: bool,
}
#[async_trait]
impl SessionProvider for Browser {
    async fn lease(&self, r: LeaseRequest) -> SessionResult<SessionLease> {
        assert!(
            self.audit
                .to_values()
                .iter()
                .any(|v| v["action"] == "session.lease_requested"),
            "lease must have write-ahead audit evidence"
        );
        self.calls.fetch_add(1, Ordering::SeqCst);
        let id = IdGenerator::new().session_lease_id();
        Ok(SessionLease {
            lease_id: id,
            acquired_at: self.clock.monotonic(),
            ttl: Duration::from_secs(60),
            material: Arc::new(SessionMaterial {
                session_id: id,
                origin: r.origin,
                issued_at: self.clock.now(),
                ttl_ms: 60_000,
                cookies: vec![Cookie {
                    name: "session_canary".into(),
                    value: SecretString::from("SECRET-COOKIE-MARKER"),
                    domain: "source.example".into(),
                    path: "/".into(),
                    secure: true,
                    http_only: true,
                    same_site: SameSite::Lax,
                    host_only: true,
                    expires_at: None,
                    partition_key: None,
                }],
                user_agent: "Zeus test".into(),
                headers: BTreeMap::new(),
                cookie_store_id: None,
            }),
        })
    }
    async fn refresh_url(&self, _: UrlRefreshRequest) -> SessionResult<RefreshedUrl> {
        Err(SessionError::ExtensionUnavailable)
    }
    fn extension_connected(&self, _: Option<&str>) -> bool {
        self.connected
    }
}
struct Transport {
    data: Vec<u8>,
    requests: Mutex<Vec<HttpRequest>>,
    redirect: bool,
}
#[async_trait]
impl HttpTransport for Transport {
    async fn send(&self, r: HttpRequest) -> Result<HttpResponse, TransportError> {
        self.requests.lock().unwrap().push(r.clone());
        let mut headers = HeaderMap::new();
        if self.redirect && r.url.host_str() == Some("source.example") {
            headers.insert(
                "location",
                HeaderValue::from_static("https://cdn.example/file.bin"),
            );
            return Ok(HttpResponse {
                status: StatusCode::FOUND,
                version: Version::HTTP_11,
                headers,
                url: r.url,
                body: Box::pin(futures::stream::empty()),
            });
        }
        let range = r.headers["range"]
            .to_str()
            .unwrap()
            .strip_prefix("bytes=")
            .unwrap();
        let (a, b) = range.split_once('-').unwrap();
        let start = a.parse::<usize>().unwrap();
        let end = b
            .parse::<usize>()
            .unwrap_or(self.data.len() - 1)
            .min(self.data.len() - 1);
        if start > 0 {
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
        headers.insert(
            "content-range",
            HeaderValue::from_str(&format!("bytes {start}-{end}/{}", self.data.len())).unwrap(),
        );
        headers.insert(
            "content-length",
            HeaderValue::from_str(&(end - start + 1).to_string()).unwrap(),
        );
        headers.insert("etag", HeaderValue::from_static("\"v1\""));
        headers.insert(
            "content-type",
            HeaderValue::from_static("application/octet-stream"),
        );
        let data = Bytes::copy_from_slice(&self.data[start..=end]);
        Ok(HttpResponse {
            status: StatusCode::PARTIAL_CONTENT,
            version: Version::HTTP_11,
            headers,
            url: r.url,
            body: Box::pin(futures::stream::once(async move { Ok(data) })),
        })
    }
}
struct Rig {
    _dir: TempDir,
    engine: Engine,
    journal: Journal,
    transport: Arc<Transport>,
    browser: Arc<Browser>,
}
async fn rig(redirect: bool, connected: bool) -> Rig {
    rig_with_proxy(redirect, connected, None).await
}
async fn rig_with_proxy(
    redirect: bool,
    connected: bool,
    proxy: Option<Arc<dyn ProxyFetch>>,
) -> Rig {
    rig_with(redirect, connected, proxy, |clock, _| {
        Arc::new(Approvals {
            clock,
            ids: IdGenerator::new(),
        })
    })
    .await
}
async fn rig_with(
    redirect: bool,
    connected: bool,
    proxy: Option<Arc<dyn ProxyFetch>>,
    approvals: impl FnOnce(SharedClock, Journal) -> Arc<dyn ApprovalPort>,
) -> Rig {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("downloads");
    std::fs::create_dir_all(&root).unwrap();
    let clock: SharedClock = Arc::new(SystemClock::new());
    let journal = Journal::open(
        &dir.path().join("journal.redb"),
        &JournalOptions::default(),
        clock.clone(),
    )
    .unwrap();
    let ids = IdGenerator::new();
    let audit = Arc::new(MemoryAuditLog::new(
        ids.chain_id(),
        ids.store_id(),
        "test",
        clock.now(),
        None,
    ));
    let browser = Arc::new(Browser {
        clock: clock.clone(),
        audit: audit.clone(),
        calls: AtomicUsize::new(0),
        connected,
    });
    let transport = Arc::new(Transport {
        data: vec![19; 1_000_000],
        requests: Mutex::new(vec![]),
        redirect,
    });
    let mut config = EngineConfig::new(vec![root.clone()], root, dir.path().to_owned());
    config.commit.commit_unit_bytes = 256 * 1024;
    config.limits.connections_per_job = 1;
    let mut builder = EngineBuilder::new(config)
        .clock(clock.clone())
        .journal(journal.clone())
        .transport(transport.clone())
        .session_provider(browser.clone())
        .audit(audit)
        .approvals(approvals(clock, journal.clone()));
    if let Some(proxy) = proxy {
        builder = builder.proxy_fetch(proxy);
    }
    let engine = builder.build().await.unwrap();
    Rig {
        _dir: dir,
        engine,
        journal,
        transport,
        browser,
    }
}
async fn enqueue(r: &Rig) -> EnqueueOutcome {
    try_enqueue(r).await.unwrap()
}
async fn try_enqueue(r: &Rig) -> Result<EnqueueOutcome, EngineError> {
    let mut spec = JobSpec::new(
        HttpUrl::parse("https://source.example/file.bin").unwrap(),
        Source::new(SourceKind::Cli),
    );
    spec.session_origin = Some(spec.origin());
    spec.expected_sha256 = Some(zeus_verify::hash_bytes(&r.transport.data).sha256);
    r.engine
        .enqueue(EnqueueRequest {
            spec,
            caller: Caller {
                client_id: "session-tests".into(),
                kind: ActorKind::Cli,
            },
        })
        .await
}
async fn approve(r: &Rig, mut a: Approval) -> GrantId {
    let now = Timestamp::now();
    let id = IdGenerator::new().grant_id();
    let actor = Actor::human(Surface::Tui);
    a.state = ApprovalState::Approved;
    a.decided_at = Some(now);
    a.decision = Some(Decision {
        outcome: DecisionOutcome::Approve,
        scope: Some(GrantScope::Once),
        actor: actor.clone(),
        grant_id: Some(id),
    });
    let grant = SessionGrant {
        id,
        origin: a.origin.clone().unwrap(),
        scope: GrantScope::Once,
        state: GrantState::Active,
        created_at: now,
        expires_at: Some(now.saturating_add_ms(60_000)),
        job_id: a.job_id,
        run_id: None,
        approval_id: a.id,
        decided_by: actor,
        uses: 0,
        last_used_at: None,
        revoked_at: None,
        renewable: false,
        renewal_count: 0,
        renewed_at: None,
        revoked_by: None,
        revocation_reason: None,
    };
    r.journal
        .transact(|t| {
            t.put_approval(&a)?;
            t.put_grant(&grant)
        })
        .unwrap();
    r.engine
        .apply_approval(ApprovalResolution {
            approval: a,
            grant: Some(grant),
            job_id: None,
        })
        .await
        .unwrap();
    id
}
async fn until(r: &Rig, id: JobId, predicate: impl Fn(&Job) -> bool) -> Job {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let j = r.engine.get(id).await.unwrap();
            if predicate(&j) {
                return j;
            }
            assert_ne!(j.state, JobState::Failed, "{:?}", j.error);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn session_requires_durable_approval_and_secrets_do_not_cross_redirects_or_events() {
    let r = rig(true, true).await;
    let accepted = enqueue(&r).await;
    assert_eq!(accepted.job.state, JobState::AwaitingApproval);
    assert!(r.transport.requests.lock().unwrap().is_empty());
    assert_eq!(r.browser.calls.load(Ordering::SeqCst), 0);
    let mut forged = accepted.approval.clone().unwrap();
    forged.state = ApprovalState::Approved;
    assert!(
        r.engine
            .apply_approval(ApprovalResolution {
                approval: forged,
                grant: None,
                job_id: None,
            })
            .await
            .is_err()
    );
    approve(&r, accepted.approval.unwrap()).await;
    let job = until(&r, accepted.job.id, |j| j.state == JobState::Completed).await;
    assert_eq!(
        std::fs::read(job.result.unwrap().path).unwrap(),
        r.transport.data
    );
    for request in r.transport.requests.lock().unwrap().iter() {
        if request.url.host_str() == Some("source.example") {
            assert_eq!(
                request.headers["cookie"],
                "session_canary=SECRET-COOKIE-MARKER"
            );
        } else {
            assert!(!request.headers.contains_key("cookie"));
            assert!(!request.headers.contains_key("user-agent"));
        }
    }
    let events = r.journal.read(|t| t.events_since(None, 1000)).unwrap();
    let encoded = serde_json::to_string(&events).unwrap();
    for secret in [
        "SECRET-COOKIE-MARKER",
        "session_canary",
        "PRIVATE-FACT-MARKER",
        "PRIVATE-ANNOTATION",
    ] {
        assert!(!encoded.contains(secret));
    }
    r.engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoked_grant_stops_writes_and_requires_a_new_approval() {
    let r = rig(false, true).await;
    let accepted = enqueue(&r).await;
    let grant = approve(&r, accepted.approval.unwrap()).await;
    until(&r, accepted.job.id, |j| j.progress.bytes_done > 0).await;
    r.journal
        .transact(|t| {
            let mut g = t.grant(grant)?.unwrap();
            g.state = GrantState::Revoked;
            t.put_grant(&g)
        })
        .unwrap();
    r.engine
        .grants_changed(GrantChange {
            origin: accepted.job.spec.origin(),
            kind: GrantChangeKind::Revoked,
        })
        .await
        .unwrap();
    let stopped = r.engine.get(accepted.job.id).await.unwrap();
    assert_eq!(stopped.state, JobState::AwaitingApproval);
    assert!(stopped.grant_id.is_none());
    assert!(stopped.approval_id.is_some());
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(
        r.engine.get(stopped.id).await.unwrap().progress.bytes_done,
        stopped.progress.bytes_done
    );
    r.engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_switch_atomically_revokes_and_pauses_and_release_restores_no_authority() {
    let r = rig(false, true).await;
    let accepted = enqueue(&r).await;
    let grant = approve(&r, accepted.approval.unwrap()).await;
    until(&r, accepted.job.id, |j| j.progress.bytes_done > 0).await;
    assert!(
        r.engine
            .set_kill_switch(true, Actor::agent(Surface::Mcp, "agent"))
            .await
            .is_err()
    );
    let outcome = r
        .engine
        .set_kill_switch(true, Actor::human(Surface::ExtensionNotification))
        .await
        .unwrap();
    assert_eq!((outcome.jobs_paused, outcome.grants_revoked), (1, 1));
    assert!(r.journal.meta().unwrap().kill_switch_engaged());
    let stopped = r.engine.get(accepted.job.id).await.unwrap();
    assert_eq!(stopped.state, JobState::Paused);
    assert!(
        r.engine
            .control(stopped.id, ControlAction::Resume)
            .await
            .is_err()
    );
    assert_eq!(
        r.journal
            .read(|t| t.grant(grant))
            .unwrap()
            .unwrap()
            .revocation_reason,
        Some(RevocationReason::KillSwitch)
    );
    let events = r.journal.read(|t| t.events_since(None, 1000)).unwrap();
    assert_eq!(
        events.last().unwrap().payload.kind(),
        Some(EventKind::DaemonKillSwitch)
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        r.engine.get(stopped.id).await.unwrap().progress.bytes_done,
        stopped.progress.bytes_done
    );
    assert!(
        r.engine
            .set_kill_switch(false, Actor::human(Surface::ExtensionNotification))
            .await
            .is_err()
    );
    r.engine
        .set_kill_switch(false, Actor::human(Surface::Tui))
        .await
        .unwrap();
    assert!(!r.journal.meta().unwrap().kill_switch_engaged());
    assert_eq!(
        r.engine.get(stopped.id).await.unwrap().state,
        JobState::Paused
    );
    r.engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kill_switch_moves_waiting_session_to_approval_and_preserves_pending_requests() {
    let r = rig(false, false).await;
    let first = enqueue(&r).await;
    approve(&r, first.approval.unwrap()).await;
    until(&r, first.job.id, |j| j.state == JobState::AwaitingSession).await;
    let pending = enqueue(&r).await;
    r.engine
        .set_kill_switch(true, Actor::human(Surface::Tui))
        .await
        .unwrap();
    assert_eq!(
        r.engine.get(first.job.id).await.unwrap().state,
        JobState::AwaitingApproval
    );
    assert_eq!(
        r.engine.get(pending.job.id).await.unwrap().approval_id,
        pending.job.approval_id
    );
    assert_eq!(
        r.journal
            .read(|t| t.approval(pending.approval.unwrap().id))
            .unwrap()
            .unwrap()
            .state,
        ApprovalState::Pending
    );
    r.engine.shutdown().await.unwrap();
}

struct Proxy {
    bad_offset: bool,
    calls: AtomicUsize,
}
#[async_trait]
impl ProxyFetch for Proxy {
    async fn fetch_range(&self, r: ProxyFetchRequest) -> SessionResult<ProxyResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(r.origin.as_str(), "https://source.example");
        let range = r.range.unwrap();
        assert!(range.end - range.start <= 8 * 1024 * 1024);
        if range.end - range.start > 1 {
            assert_eq!(r.if_range.as_deref(), Some("\"v1\""));
        }
        let headers = BTreeMap::from([
            (
                "content-range".into(),
                format!("bytes {}-{}/1000000", range.start, range.end - 1),
            ),
            (
                "content-length".into(),
                (range.end - range.start).to_string(),
            ),
            ("etag".into(), "\"v1\"".into()),
            ("content-type".into(), "application/octet-stream".into()),
        ]);
        let chunks = (range.start..range.end)
            .step_by(64 * 1024)
            .map(|offset| {
                Ok(ProxyChunk {
                    offset: offset + u64::from(self.bad_offset),
                    data: Bytes::from(vec![19; ((range.end - offset) as usize).min(64 * 1024)]),
                })
            })
            .collect::<Vec<_>>();
        Ok(ProxyResponse {
            head: ProxyHead {
                status: 206,
                final_url: r.url,
                redirected: false,
                headers,
            },
            body: Box::pin(futures::stream::iter(chunks)),
        })
    }
    fn available(&self, _: Option<&str>) -> bool {
        true
    }
}
async fn enqueue_proxy(r: &Rig) -> EnqueueOutcome {
    let mut spec = JobSpec::new(
        HttpUrl::parse("https://source.example/file.bin").unwrap(),
        Source::new(SourceKind::Cli),
    );
    spec.transport_hint = Some(TransportHint::BrowserProxy);
    spec.expected_sha256 = Some(zeus_verify::hash_bytes(&r.transport.data).sha256);
    r.engine
        .enqueue(EnqueueRequest {
            spec,
            caller: Caller {
                client_id: "proxy-test".into(),
                kind: ActorKind::Cli,
            },
        })
        .await
        .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_proxy_requires_approval_and_downloads_without_releasing_cookie_material() {
    let proxy = Arc::new(Proxy {
        bad_offset: false,
        calls: AtomicUsize::new(0),
    });
    let r = rig_with_proxy(false, false, Some(proxy.clone())).await;
    let accepted = enqueue_proxy(&r).await;
    assert_eq!(accepted.job.state, JobState::AwaitingApproval);
    assert_eq!(proxy.calls.load(Ordering::SeqCst), 0);
    approve(&r, accepted.approval.unwrap()).await;
    let job = until(&r, accepted.job.id, |j| j.state == JobState::Completed).await;
    assert_eq!(job.transport, zeus_types::Transport::BrowserProxy);
    assert_eq!(
        job.probe.unwrap().transport,
        zeus_types::Transport::BrowserProxy
    );
    assert_eq!(
        std::fs::read(job.result.unwrap().path).unwrap(),
        r.transport.data
    );
    assert_eq!(r.browser.calls.load(Ordering::SeqCst), 0);
    assert!(r.transport.requests.lock().unwrap().is_empty());
    r.engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn browser_proxy_wrong_offsets_never_commit() {
    let r = rig_with_proxy(
        false,
        false,
        Some(Arc::new(Proxy {
            bad_offset: true,
            calls: AtomicUsize::new(0),
        })),
    )
    .await;
    let accepted = enqueue_proxy(&r).await;
    approve(&r, accepted.approval.unwrap()).await;
    let job = until(&r, accepted.job.id, |j| j.state == JobState::Failed).await;
    assert_eq!(job.progress.bytes_done, 0);
    assert!(r.journal.committed(job.id).unwrap().is_empty());
    r.engine.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_receipt_preserves_original_state_sequence_and_never_reapplies_pause() {
    let r = rig(false, true).await;
    let accepted = enqueue(&r).await;
    approve(&r, accepted.approval.unwrap()).await;
    until(&r, accepted.job.id, |j| j.progress.bytes_done > 0).await;
    let hash = zeus_verify::hash_bytes(b"pause original exact params").blake3;
    let actor = Actor::human(Surface::Tui);
    let first = r
        .engine
        .control_idempotent(
            accepted.job.id,
            ControlAction::Pause,
            "control-tests",
            "pause-once",
            hash,
            actor.clone(),
        )
        .await
        .unwrap();
    assert_eq!(first.state, JobState::Paused);
    assert!(first.state_seq.is_some());
    r.engine
        .control(accepted.job.id, ControlAction::Resume)
        .await
        .unwrap();
    let repeated = r
        .engine
        .control_idempotent(
            accepted.job.id,
            ControlAction::Pause,
            "control-tests",
            "pause-once",
            hash,
            actor.clone(),
        )
        .await
        .unwrap();
    assert_eq!(repeated, first);
    assert_ne!(
        r.engine.get(accepted.job.id).await.unwrap().state,
        JobState::Paused
    );
    let changed = zeus_verify::hash_bytes(b"different params").blake3;
    assert!(matches!(
        r.engine
            .control_idempotent(
                accepted.job.id,
                ControlAction::Cancel,
                "control-tests",
                "pause-once",
                changed,
                actor
            )
            .await,
        Err(EngineError::IdempotencyConflict)
    ));
    let events = r.journal.read(|t| t.events_since(None, 1000)).unwrap();
    let event = events.iter().find(|e| e.seq == first.state_seq).unwrap();
    assert_eq!(
        serde_json::to_value(event).unwrap()["data"]["actor"]["kind"],
        "human"
    );
    r.engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn canceling_one_batched_job_keeps_the_approval_open_for_the_others() {
    let r = joining_rig(false).await;
    let first = enqueue(&r).await;
    let second = enqueue(&r).await;
    let approval_id = first.job.approval_id.unwrap();
    assert_eq!(second.job.approval_id, Some(approval_id));
    let approval = |r: &Rig| {
        r.journal
            .read(|t| t.approval(approval_id))
            .unwrap()
            .unwrap()
    };
    r.engine
        .control(first.job.id, ControlAction::Cancel)
        .await
        .unwrap();
    assert_eq!(approval(&r).state, ApprovalState::Pending);
    let waiting = r.engine.get(second.job.id).await.unwrap();
    assert_eq!(waiting.state, JobState::AwaitingApproval);
    assert_eq!(waiting.approval_id, Some(approval_id));
    // The last job leaving cancels the approval.
    r.engine
        .control(second.job.id, ControlAction::Cancel)
        .await
        .unwrap();
    assert_eq!(approval(&r).state, ApprovalState::Canceled);
    r.engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_batch_join_never_reopens_an_approval_decided_meanwhile() {
    let r = joining_rig(true).await;
    let first = enqueue(&r).await;
    let approval_id = first.job.approval_id.unwrap();
    assert!(try_enqueue(&r).await.is_err());
    let stored = r
        .journal
        .read(|t| t.approval(approval_id))
        .unwrap()
        .unwrap();
    assert_eq!(stored.state, ApprovalState::Approved);
    assert_eq!(stored.revision, Some(1));
    r.engine.shutdown().await.unwrap();
}
