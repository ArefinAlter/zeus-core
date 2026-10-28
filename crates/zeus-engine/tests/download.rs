//! Loopback acceptance tests for durable direct downloads.
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeus_engine::{Caller, ControlAction, Engine, EngineBuilder, EngineConfig, EnqueueRequest};
use zeus_journal::{Journal, JournalOptions};
use zeus_types::{ActorKind, HttpUrl, JobId, JobSpec, JobState, Source, SourceKind};

struct Server {
    url: HttpUrl,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server(
    data: Vec<u8>,
    etag: Arc<Mutex<String>>,
    delay: bool,
    corrupt_range: bool,
) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = HttpUrl::parse(&format!(
        "http://{}/file.bin",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let seen = requests.clone();
    let data = Arc::new(data);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let data = data.clone();
            let seen = seen.clone();
            let etag = etag.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.ends_with(b"\r\n\r\n") && request.len() < 16_384 {
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    request.extend_from_slice(&buf[..n]);
                }
                let request = String::from_utf8_lossy(&request).into_owned();
                seen.lock().unwrap().push(request.clone());
                let range = request.lines().find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("range: bytes=")
                        .map(str::to_owned)
                });
                let (start, end) = range
                    .as_deref()
                    .and_then(|r| r.split_once('-'))
                    .map(|(a, b)| {
                        (
                            a.trim().parse::<usize>().unwrap(),
                            b.trim()
                                .parse::<usize>()
                                .unwrap_or(data.len().saturating_sub(1)),
                        )
                    })
                    .unwrap_or((0, data.len().saturating_sub(1)));
                if delay && end > 0 && start > 0 {
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
                let tag = etag.lock().unwrap().clone();
                if data.is_empty() {
                    let _=socket.write_all(b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                    return;
                }
                if start >= data.len() {
                    return;
                }
                let end = end.min(data.len() - 1);
                let head = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {}-{}/{}\r\nContent-Length: {}\r\nETag: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                    if corrupt_range && end > 0 {
                        start + 1
                    } else {
                        start
                    },
                    end,
                    data.len(),
                    end - start + 1,
                    tag
                );
                if socket.write_all(head.as_bytes()).await.is_ok() {
                    if delay {
                        for chunk in data[start..=end].chunks(32 * 1024) {
                            if socket.write_all(chunk).await.is_err() {
                                break;
                            }
                            tokio::time::sleep(Duration::from_millis(5)).await;
                        }
                    } else {
                        let _ = socket.write_all(&data[start..=end]).await;
                    }
                }
            });
        }
    });
    Server {
        url,
        requests,
        task,
    }
}
async fn engine(dir: &TempDir) -> Engine {
    let root = dir.path().join("downloads");
    std::fs::create_dir_all(&root).unwrap();
    let journal = Journal::open(
        &dir.path().join("journal.redb"),
        &JournalOptions::default(),
        Arc::new(zeus_control::SystemClock::new()),
    )
    .unwrap();
    let mut config = EngineConfig::new(vec![root.clone()], root, dir.path().to_owned());
    config.commit.commit_unit_bytes = 256 * 1024;
    config.limits.connections_per_job = 1;
    config.http.proxy = zeus_http::ProxyConfig::None;
    EngineBuilder::new(config)
        .journal(journal)
        .build()
        .await
        .unwrap()
}
fn request(url: HttpUrl, data: &[u8]) -> EnqueueRequest {
    let mut spec = JobSpec::new(url, Source::new(SourceKind::Cli));
    spec.expected_sha256 = Some(zeus_verify::hash_bytes(data).sha256);
    spec.idempotency_key = Some("test-request".into());
    EnqueueRequest {
        spec,
        caller: Caller {
            client_id: "loopback-tests".into(),
            kind: ActorKind::Cli,
        },
    }
}
async fn complete(engine: &Engine, id: JobId) -> zeus_types::Job {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let job = engine.get(id).await.unwrap();
            if matches!(job.state, JobState::Completed | JobState::Failed) {
                return job;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_admission_is_durable_and_never_dispatches_before_explicit_resume() {
    let data = vec![17; 600_000];
    let server = server(
        data.clone(),
        Arc::new(Mutex::new("\"held-v1\"".into())),
        false,
        false,
    )
    .await;
    let dir = TempDir::new().unwrap();
    let first = engine(&dir).await;
    let req = request(server.url.clone(), &data);
    let held = first.enqueue_held(req.clone()).await.unwrap();
    assert_eq!(held.job.state, JobState::Paused);
    let attempts =
        futures::future::join_all((0..16).map(|_| first.enqueue_held(req.clone()))).await;
    for attempt in attempts {
        let duplicate = attempt.unwrap();
        assert!(duplicate.deduplicated);
        assert_eq!(duplicate.job.id, held.job.id);
        assert_eq!(duplicate.job.state, JobState::Paused);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(server.requests.lock().unwrap().is_empty());
    first.shutdown().await.unwrap();
    drop(first);
    // A source-record commit may have been interrupted here. The engine must
    // not promote held work during recovery before that binding is reconciled.
    let second = engine(&dir).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        second.get(held.job.id).await.unwrap().state,
        JobState::Paused
    );
    assert!(server.requests.lock().unwrap().is_empty());
    second
        .control(held.job.id, ControlAction::Resume)
        .await
        .unwrap();
    let completed = complete(&second, held.job.id).await;
    assert_eq!(
        completed.state,
        JobState::Completed,
        "{:?}",
        completed.error
    );
    assert_eq!(std::fs::read(completed.result.unwrap().path).unwrap(), data);
    second.shutdown().await.unwrap();
}

#[tokio::test]
async fn held_admission_does_not_alias_ordinary_enqueue_or_browser_authority() {
    let dir = TempDir::new().unwrap();
    let engine = engine(&dir).await;
    let req = request(
        HttpUrl::parse("https://sources.zeus.invalid/object").unwrap(),
        b"data",
    );
    engine.enqueue_held(req.clone()).await.unwrap();
    assert!(matches!(
        engine.enqueue(req.clone()).await,
        Err(zeus_engine::EngineError::IdempotencyConflict)
    ));
    let mut browser = req;
    browser.spec.idempotency_key = Some("browser-held-refusal".into());
    browser.spec.session_origin = Some(browser.spec.origin());
    assert!(engine.enqueue_held(browser).await.is_err());
    engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ranged_download_is_verified_and_idempotent() {
    let data = (0..800_000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let server = server(
        data.clone(),
        Arc::new(Mutex::new("\"v1\"".into())),
        false,
        false,
    )
    .await;
    let dir = TempDir::new().unwrap();
    let engine = engine(&dir).await;
    let req = request(server.url.clone(), &data);
    let accepted = engine.enqueue(req.clone()).await.unwrap();
    let duplicate = engine.enqueue(req.clone()).await.unwrap();
    assert!(duplicate.deduplicated);
    assert_eq!(accepted.job.id, duplicate.job.id);
    let mut conflict = req;
    conflict.spec.expected_size = Some(2);
    assert!(matches!(
        engine.enqueue(conflict).await,
        Err(zeus_engine::EngineError::IdempotencyConflict)
    ));
    let job = complete(&engine, accepted.job.id).await;
    assert_eq!(job.state, JobState::Completed, "{:?}", job.error);
    assert_eq!(
        std::fs::read(&job.result.as_ref().unwrap().path).unwrap(),
        data
    );
    engine.verify(job.id, None).await.unwrap();
    assert!(
        server
            .requests
            .lock()
            .unwrap()
            .iter()
            .skip(1)
            .all(|r| r.to_ascii_lowercase().contains("if-range: \"v1\""))
    );
    engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_resumes_only_committed_ranges_under_the_same_validator() {
    let data = (0..2_000_000).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    let server = server(
        data.clone(),
        Arc::new(Mutex::new("\"v1\"".into())),
        true,
        false,
    )
    .await;
    let dir = TempDir::new().unwrap();
    let first = engine(&dir).await;
    let id = first
        .enqueue(request(server.url.clone(), &data))
        .await
        .unwrap()
        .job
        .id;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if first.get(id).await.unwrap().progress.bytes_done >= 256 * 1024 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    first
        .begin_shutdown(zeus_types::event::StopReason::Signal)
        .unwrap();
    // Exercise the gap between admission stop and asynchronous worker drain.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_ne!(first.get(id).await.unwrap().state, JobState::Failed);
    first.shutdown().await.unwrap();
    let durable = first.get(id).await.unwrap().progress.bytes_done;
    assert!(durable < data.len() as u64);
    drop(first);
    server.requests.lock().unwrap().clear();
    let second = engine(&dir).await;
    let job = complete(&second, id).await;
    assert_eq!(job.state, JobState::Completed, "{:?}", job.error);
    assert_eq!(std::fs::read(job.result.unwrap().path).unwrap(), data);
    let requests = server.requests.lock().unwrap().clone();
    assert!(
        requests
            .iter()
            .skip(1)
            .all(|r| !r.to_ascii_lowercase().contains("range: bytes=0-")),
        "{requests:?}"
    );
    second.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_content_range_never_commits_bytes() {
    let data = vec![7; 500_000];
    let server = server(
        data.clone(),
        Arc::new(Mutex::new("\"v1\"".into())),
        false,
        true,
    )
    .await;
    let dir = TempDir::new().unwrap();
    let engine = engine(&dir).await;
    let id = engine
        .enqueue(request(server.url.clone(), &data))
        .await
        .unwrap()
        .job
        .id;
    let job = complete(&engine, id).await;
    assert_eq!(job.state, JobState::Failed);
    assert_eq!(job.progress.bytes_done, 0);
    assert!(job.result.is_none());
    engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pause_prevents_further_commits_until_resume() {
    let data = vec![9; 1_000_000];
    let server = server(
        data.clone(),
        Arc::new(Mutex::new("\"v1\"".into())),
        true,
        false,
    )
    .await;
    let dir = TempDir::new().unwrap();
    let engine = engine(&dir).await;
    let id = engine
        .enqueue(request(server.url.clone(), &data))
        .await
        .unwrap()
        .job
        .id;
    let paused = engine.control(id, ControlAction::Pause).await.unwrap();
    assert_eq!(paused.state, JobState::Paused);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        engine.get(id).await.unwrap().progress.bytes_done,
        paused.progress.bytes_done
    );
    engine.control(id, ControlAction::Resume).await.unwrap();
    assert_eq!(complete(&engine, id).await.state, JobState::Completed);
    engine.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn changed_validator_invalidates_previously_committed_bytes() {
    let data = vec![11; 1_000_000];
    let tag = Arc::new(Mutex::new("\"v1\"".into()));
    let server = server(data.clone(), tag.clone(), true, false).await;
    let dir = TempDir::new().unwrap();
    let first = engine(&dir).await;
    let id = first
        .enqueue(request(server.url.clone(), &data))
        .await
        .unwrap()
        .job
        .id;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if first.get(id).await.unwrap().progress.bytes_done > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    first.shutdown().await.unwrap();
    drop(first);
    *tag.lock().unwrap() = "\"v2\"".into();
    server.requests.lock().unwrap().clear();
    let second = engine(&dir).await;
    assert_eq!(complete(&second, id).await.state, JobState::Completed);
    assert!(
        server
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|r| r.to_ascii_lowercase().contains("range: bytes=0-"))
    );
    second.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn corrupt_committed_tail_is_downloaded_again() {
    use std::io::{Seek, Write};
    let data = vec![13; 1_000_000];
    let server = server(
        data.clone(),
        Arc::new(Mutex::new("\"v1\"".into())),
        true,
        false,
    )
    .await;
    let dir = TempDir::new().unwrap();
    let first = engine(&dir).await;
    let id = first
        .enqueue(request(server.url.clone(), &data))
        .await
        .unwrap()
        .job
        .id;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if first.get(id).await.unwrap().progress.bytes_done > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    first.shutdown().await.unwrap();
    drop(first);
    let mut partial = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.path().join("downloads/file.bin.zpart"))
        .unwrap();
    partial.seek(std::io::SeekFrom::Start(12)).unwrap();
    partial.write_all(&[99]).unwrap();
    partial.sync_all().unwrap();
    drop(partial);
    let second = engine(&dir).await;
    let completed = complete(&second, id).await;
    assert_eq!(
        completed.state,
        JobState::Completed,
        "{:?}",
        completed.error
    );
    assert_eq!(std::fs::read(completed.result.unwrap().path).unwrap(), data);
    second.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replaced_partial_file_is_never_overwritten_or_deleted() {
    let data = vec![17; 1_000_000];
    let server = server(
        data.clone(),
        Arc::new(Mutex::new("\"v1\"".into())),
        true,
        false,
    )
    .await;
    let dir = TempDir::new().unwrap();
    let first = engine(&dir).await;
    let id = first
        .enqueue(request(server.url.clone(), &data))
        .await
        .unwrap()
        .job
        .id;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if first.get(id).await.unwrap().progress.bytes_done > 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    first.shutdown().await.unwrap();
    drop(first);
    let partial = dir.path().join("downloads/file.bin.zpart");
    std::fs::rename(&partial, dir.path().join("saved-original.zpart")).unwrap();
    std::fs::write(&partial, b"unrelated user data").unwrap();
    let second = engine(&dir).await;
    assert_eq!(complete(&second, id).await.state, JobState::Failed);
    assert_eq!(std::fs::read(&partial).unwrap(), b"unrelated user data");
    second.shutdown().await.unwrap();
}

struct BoundedRun {
    transport: Arc<dyn zeus_http::HttpTransport>,
    limit: u64,
}
impl zeus_engine::JobTransportFactory for BoundedRun {
    fn for_job(
        &self,
        _: &JobSpec,
    ) -> Result<Option<Arc<dyn zeus_http::HttpTransport>>, zeus_types::ErrorEnvelope> {
        Ok(Some(self.transport.clone()))
    }
    fn validate_commit(
        &self,
        spec: &JobSpec,
        txn: &dyn zeus_journal::ReadTxn,
        range: zeus_types::ByteRange,
    ) -> Result<(), zeus_types::ErrorEnvelope> {
        let used = txn
            .jobs(&Default::default())
            .unwrap()
            .iter()
            .filter(|r| r.job.spec.source.run_id == spec.source.run_id)
            .map(|r| r.job.progress.bytes_done)
            .sum::<u64>();
        if used + range.end - range.start > self.limit {
            Err(zeus_types::ErrorEnvelope::from_code(
                "policy.approval_denied",
                "run budget reached",
            ))
        } else {
            Ok(())
        }
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_workflow_jobs_cannot_commit_past_the_shared_run_budget() {
    let data = vec![23; 1_000_000];
    let server = server(
        data.clone(),
        Arc::new(Mutex::new("\"v1\"".into())),
        false,
        false,
    )
    .await;
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("downloads");
    std::fs::create_dir_all(&root).unwrap();
    let clock = Arc::new(zeus_control::ManualClock::new(zeus_types::Timestamp::now()));
    let journal = Journal::open(
        &dir.path().join("journal.redb"),
        &JournalOptions::default(),
        clock.clone(),
    )
    .unwrap();
    let mut config = EngineConfig::new(vec![root.clone()], root, dir.path().to_owned());
    config.commit.commit_unit_bytes = 256 * 1024;
    config.http.proxy = zeus_http::ProxyConfig::None;
    let transport = Arc::new(zeus_http::ReqwestTransport::new(&config.http).unwrap());
    let engine = EngineBuilder::new(config)
        .clock(clock.clone())
        .journal(journal.clone())
        .job_transports(Arc::new(BoundedRun {
            transport,
            limit: 1_000_000,
        }))
        .build()
        .await
        .unwrap();
    let run = zeus_types::IdGenerator::new().run_id();
    let mut first = request(server.url.clone(), &data);
    first.spec.source.kind = SourceKind::Workflow;
    first.spec.source.run_id = Some(run);
    let mut second = first.clone();
    second.spec.idempotency_key = Some("second-workflow-file".into());
    let a = engine.enqueue(first.clone()).await.unwrap().job.id;
    let b = engine.enqueue(second).await.unwrap().job.id;
    let (a, b) = tokio::join!(complete(&engine, a), complete(&engine, b));
    assert!(a.progress.bytes_done + b.progress.bytes_done <= 1_000_000);
    assert!(a.state == JobState::Failed || b.state == JobState::Failed);
    clock.advance(Duration::from_secs(90_000));
    assert_eq!(
        journal
            .transact(|t| t.expire_idempotency(zeus_control::Clock::now(clock.as_ref())))
            .unwrap(),
        0
    );
    let replay = engine.enqueue(first).await.unwrap();
    assert!(replay.deduplicated);
    assert_eq!(replay.job.id, a.id);
    engine.shutdown().await.unwrap();
}
