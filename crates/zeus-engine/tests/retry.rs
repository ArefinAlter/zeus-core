//! Real loopback failures verify durable retry timers and bounded automatic recovery.
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeus_engine::*;
use zeus_journal::{Journal, JournalOptions};
use zeus_types::event::StopReason;
use zeus_types::*;
struct Zero;
impl zeus_control::RandomSource for Zero {
    fn next_u64(&mut self) -> u64 {
        0
    }
}
struct Server {
    url: HttpUrl,
    calls: Arc<AtomicUsize>,
    starts: Arc<Mutex<Vec<Instant>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server(status: u16, failures: usize, retry_after: Option<&str>) -> Server {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = HttpUrl::parse(&format!(
        "http://{}/file.bin",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let starts = Arc::new(Mutex::new(vec![]));
    let observed = calls.clone();
    let times = starts.clone();
    let retry_after = retry_after.map(str::to_owned);
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let number = observed.fetch_add(1, Ordering::SeqCst);
            times.lock().unwrap().push(Instant::now());
            let mut bytes = vec![];
            let mut buf = [0u8; 1024];
            while !bytes.ends_with(b"\r\n\r\n") && bytes.len() < 16384 {
                let n = socket.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..n]);
            }
            let request = String::from_utf8_lossy(&bytes);
            if number < failures {
                let retry = retry_after
                    .as_ref()
                    .map(|s| format!("Retry-After: {s}\r\n"))
                    .unwrap_or_default();
                let head = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\n{retry}Connection: close\r\n\r\n"
                );
                let _ = socket.write_all(head.as_bytes()).await;
            } else {
                let range = request
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("range: bytes=")
                            .map(str::to_owned)
                    })
                    .unwrap();
                let (a, b) = range.trim().split_once('-').unwrap();
                let start = a.parse::<usize>().unwrap();
                let end = b.parse::<usize>().unwrap();
                let data = b"payload!";
                let end = end.min(data.len() - 1);
                let head = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{end}/8\r\nContent-Length: {}\r\nETag: \"one\"\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                    end - start + 1
                );
                let _ = socket.write_all(head.as_bytes()).await;
                let _ = socket.write_all(&data[start..=end]).await;
            }
        }
    });
    Server {
        url,
        calls,
        starts,
        task,
    }
}
struct Rig {
    _dir: TempDir,
    config: EngineConfig,
    journal: Journal,
    engine: Engine,
}
async fn rig() -> Rig {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("downloads");
    std::fs::create_dir_all(&root).unwrap();
    let mut config = EngineConfig::new(vec![root.clone()], root, dir.path().into());
    config.http.proxy = zeus_http::ProxyConfig::None;
    let journal = Journal::open(
        &dir.path().join("journal.redb"),
        &JournalOptions::default(),
        Arc::new(zeus_control::SystemClock::new()),
    )
    .unwrap();
    let engine = build(&config, &journal).await;
    Rig {
        _dir: dir,
        config,
        journal,
        engine,
    }
}
async fn build(config: &EngineConfig, journal: &Journal) -> Engine {
    EngineBuilder::new(config.clone())
        .rng(Box::new(Zero))
        .journal(journal.clone())
        .build()
        .await
        .unwrap()
}
async fn enqueue(r: &Rig, url: HttpUrl) -> JobId {
    r.engine
        .enqueue(EnqueueRequest {
            spec: JobSpec::new(url, Source::new(SourceKind::Cli)),
            caller: Caller {
                client_id: "retry-test".into(),
                kind: ActorKind::Cli,
            },
        })
        .await
        .unwrap()
        .job
        .id
}
async fn state(engine: &Engine, id: JobId, expected: JobState) -> Job {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let job = engine.get(id).await.unwrap();
            if job.state == expected {
                return job;
            }
            assert!(
                !job.state.is_terminal() && job.state != JobState::Failed,
                "unexpected {:?}: {:?}",
                job.state,
                job.error
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retry_after_survives_restart_and_the_download_recovers() {
    let server = server(503, 1, Some("1")).await;
    let mut r = rig().await;
    let id = enqueue(&r, server.url.clone()).await;
    let scheduled = state(&r.engine, id, JobState::RetryScheduled).await;
    assert!(scheduled.retry.next_attempt_at.is_some());
    r.engine.shutdown().await.unwrap();
    r.engine = build(&r.config, &r.journal).await;
    let completed = state(&r.engine, id, JobState::Completed).await;
    assert_eq!(
        std::fs::read(completed.result.unwrap().path).unwrap(),
        b"payload!"
    );
    {
        let times = server.starts.lock().unwrap();
        assert!(times[1].duration_since(times[0]) >= Duration::from_millis(950));
    }
    let events = r.journal.read(|t| t.events_since(None, 1000)).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|e| matches!(
                e.payload,
                zeus_types::event::EventPayload::JobRetryScheduled(_)
            ))
            .count(),
        1
    );
    r.engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn permanent_http_error_never_retries() {
    let server = server(404, usize::MAX, None).await;
    let r = rig().await;
    let id = enqueue(&r, server.url.clone()).await;
    let failed = state(&r.engine, id, JobState::Failed).await;
    assert_eq!(failed.error.unwrap().class, ErrorClass::Permanent);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(server.calls.load(Ordering::SeqCst), 1);
    r.engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_five_xx_exhausts_the_durable_budget() {
    let server = server(500, usize::MAX, None).await;
    let r = rig().await;
    let id = enqueue(&r, server.url.clone()).await;
    let failed = state(&r.engine, id, JobState::Failed).await;
    assert_eq!(server.calls.load(Ordering::SeqCst), 10);
    assert_eq!(failed.retry.attempt, 10);
    assert_eq!(
        failed.error.as_ref().unwrap().code.as_str(),
        "http.status_500"
    );
    assert!(failed.error.unwrap().retryable);
    r.engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pause_cancel_and_kill_interrupt_scheduled_retry() {
    for action in [0, 1, 2] {
        let server = server(503, usize::MAX, Some("1")).await;
        let r = rig().await;
        let id = enqueue(&r, server.url.clone()).await;
        state(&r.engine, id, JobState::RetryScheduled).await;
        let expected = match action {
            0 => {
                r.engine.control(id, ControlAction::Pause).await.unwrap();
                JobState::Paused
            }
            1 => {
                r.engine.control(id, ControlAction::Cancel).await.unwrap();
                JobState::Canceled
            }
            _ => {
                r.engine
                    .set_kill_switch(true, Actor::human(Surface::Tui))
                    .await
                    .unwrap();
                JobState::Paused
            }
        };
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
        assert_eq!(r.engine.get(id).await.unwrap().state, expected);
        if action == 2 {
            r.engine
                .set_kill_switch(false, Actor::human(Surface::Tui))
                .await
                .unwrap();
            assert_eq!(r.engine.get(id).await.unwrap().state, JobState::Paused);
        }
        r.engine.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn shutdown_announcement_is_durable_immediate_and_idempotent() {
    let r = rig().await;
    r.engine.begin_shutdown(StopReason::Signal).unwrap();
    r.engine.begin_shutdown(StopReason::FatalError).unwrap();
    let events = r.journal.read(|tx| tx.events_since(None, 1000)).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event.payload,
                zeus_types::event::EventPayload::DaemonStopping(_)
            ))
            .count(),
        1
    );
    assert!(events.iter().any(|event|matches!(event.payload,
        zeus_types::event::EventPayload::DaemonStopping(ref data) if data.reason == StopReason::Signal)));
    let request = EnqueueRequest {
        spec: JobSpec::new(
            HttpUrl::parse("https://example.org/file").unwrap(),
            Source::new(SourceKind::Cli),
        ),
        caller: Caller {
            client_id: "shutdown-test".into(),
            kind: ActorKind::Cli,
        },
    };
    assert!(matches!(
        r.engine.enqueue(request).await,
        Err(EngineError::ShuttingDown)
    ));
    r.engine.shutdown().await.unwrap();
    r.engine.shutdown().await.unwrap();
    let events = r.journal.read(|tx| tx.events_since(None, 1000)).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(
                event.payload,
                zeus_types::event::EventPayload::DaemonStopping(_)
            ))
            .count(),
        1
    );
}
