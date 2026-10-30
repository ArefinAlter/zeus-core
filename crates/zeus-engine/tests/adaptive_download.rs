//! Actual HTTP requests, durable-prefix work stealing and per-origin budgets.
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeus_engine::{Caller, Engine, EngineBuilder, EngineConfig, EnqueueRequest, TransferTuning};
use zeus_journal::{Journal, JournalOptions};
use zeus_types::{ActorKind, HttpUrl, JobId, JobSpec, JobState, Source, SourceKind};
struct Server {
    url: HttpUrl,
    requests: Arc<Mutex<Vec<(u64, u64)>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn server(
    data: Arc<Vec<u8>>,
    slow_first: bool,
    active: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
) -> Server {
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = HttpUrl::parse(&format!(
        "http://{}/payload.bin",
        socket.local_addr().unwrap()
    ))
    .unwrap();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorded = requests.clone();
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut conn, _)) = socket.accept().await else {
                break;
            };
            let data = data.clone();
            let recorded = recorded.clone();
            let active = active.clone();
            let peak = peak.clone();
            tokio::spawn(async move {
                let mut head = vec![];
                while !head.ends_with(b"\r\n\r\n") && head.len() < 8192 {
                    let mut buf = [0; 1];
                    if conn.read(&mut buf).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(buf[0]);
                }
                let head = String::from_utf8(head).unwrap().to_ascii_lowercase();
                let range = head
                    .lines()
                    .find_map(|s| s.strip_prefix("range: bytes="))
                    .unwrap();
                let (a, b) = range.split_once('-').unwrap();
                let start = a.parse::<u64>().unwrap();
                let end = b.parse::<u64>().unwrap() + 1;
                recorded.lock().unwrap().push((start, end));
                let headers = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nETag: \"immutable-1\"\r\nConnection: close\r\n\r\n",
                    end - start,
                    start,
                    end - 1,
                    data.len()
                );
                if conn.write_all(headers.as_bytes()).await.is_err() {
                    return;
                }
                let n = active.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(n, Ordering::SeqCst);
                let mut counted = true;
                let body = &data[start as usize..end as usize];
                for (i, part) in body.chunks(64 * 1024).enumerate() {
                    if (i + 1) * 64 * 1024 >= body.len() {
                        active.fetch_sub(1, Ordering::SeqCst);
                        counted = false;
                    }
                    if conn.write_all(part).await.is_err() {
                        break;
                    }
                    if slow_first && start == 0 && end > 8 << 20 && i == 47 {
                        // Keep the original response stalled after 3 MiB until its client closes.
                        // A short sleep alone is not a reliable slow worker on a busy Windows disk:
                        // the nominally fast peer may finish only after both responses have drained.
                        // The engine must cancel this response and reassign its uncommitted tail.
                        let _ =
                            tokio::time::timeout(Duration::from_secs(20), conn.read(&mut [0; 1]))
                                .await;
                        break;
                    }
                    // The original large range is slow, but a stolen smaller range is fast.
                    if (slow_first && start == 0 && end > 8 << 20)
                        || (!slow_first && end - start > 1)
                    {
                        tokio::time::sleep(Duration::from_millis(3)).await;
                    }
                }
                if counted {
                    active.fetch_sub(1, Ordering::SeqCst);
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
async fn engine(
    dir: &TempDir,
    per_host: u32,
    connections: u32,
    segment: u64,
    stealing: bool,
    adaptive: bool,
) -> Engine {
    let root = dir.path().join("downloads");
    std::fs::create_dir(&root).unwrap();
    let journal = Journal::open(
        &dir.path().join("jobs.redb"),
        &JournalOptions::default(),
        Arc::new(zeus_control::SystemClock::new()),
    )
    .unwrap();
    let mut config = EngineConfig::new(vec![root.clone()], root, dir.path().into());
    config.commit.commit_unit_bytes = 1 << 20;
    config.limits.connections_per_host = per_host;
    config.limits.connections_per_job = connections;
    config.http.proxy = zeus_http::ProxyConfig::None;
    EngineBuilder::new(config)
        .journal(journal)
        .transfer_tuning(TransferTuning {
            segment_bytes: segment,
            adaptive_concurrency: adaptive,
            work_stealing: stealing,
        })
        .build()
        .await
        .unwrap()
}
async fn enqueue(engine: &Engine, url: HttpUrl, data: &[u8], name: &str, max: u8) -> JobId {
    let mut spec = JobSpec::new(url, Source::new(SourceKind::Cli));
    spec.filename = Some(name.into());
    spec.max_connections = Some(max);
    spec.expected_sha256 = Some(zeus_verify::hash_bytes(data).sha256);
    engine
        .enqueue(EnqueueRequest {
            spec,
            caller: Caller {
                client_id: "adaptive-fixture".into(),
                kind: ActorKind::Cli,
            },
        })
        .await
        .unwrap()
        .job
        .id
}
async fn wait(engine: &Engine, id: JobId) {
    let job = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let job = engine.get(id).await.unwrap();
            if matches!(job.state, JobState::Completed | JobState::Failed) {
                break job;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let job = match job {
        Ok(job) => job,
        Err(_) => {
            let current = engine.get(id).await.unwrap();
            panic!(
                "download timed out: state={:?}, progress={:?}, error={:?}",
                current.state, current.progress, current.error
            );
        }
    };
    assert_eq!(job.state, JobState::Completed, "{:?}", job.error);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_tail_is_reassigned_after_durable_prefix_and_file_is_exact() {
    let data = Arc::new(
        (0..24 * 1024 * 1024)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>(),
    );
    let server = server(
        data.clone(),
        true,
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
    )
    .await;
    let dir = TempDir::new().unwrap();
    let engine = engine(&dir, 4, 2, 16 << 20, true, false).await;
    let id = enqueue(&engine, server.url.clone(), &data, "stolen.bin", 2).await;
    wait(&engine, id).await;
    let requests = server.requests.lock().unwrap().clone();
    assert!(
        requests.iter().any(|(a, b)| b - a > 8 << 20),
        "large adaptive request absent: {requests:?}"
    );
    assert!(
        requests
            .iter()
            .skip(1)
            .any(|(a, b)| *a > 0 && *a < 12 << 20 && b - a <= 8 << 20),
        "unfinished first range was not reassigned: {requests:?}"
    );
    assert_eq!(
        std::fs::read(dir.path().join("downloads/stolen.bin")).unwrap(),
        *data
    );
    engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unrelated_origins_do_not_share_one_global_connection_slot() {
    let data = Arc::new(vec![37; 3 << 20]);
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let a = server(data.clone(), false, active.clone(), peak.clone()).await;
    let b = server(data.clone(), false, active, peak.clone()).await;
    let dir = TempDir::new().unwrap();
    let engine = engine(&dir, 1, 4, 8 << 20, true, false).await;
    let x = enqueue(&engine, a.url.clone(), &data, "a.bin", 4).await;
    let y = enqueue(&engine, b.url.clone(), &data, "b.bin", 4).await;
    tokio::join!(wait(&engine, x), wait(&engine, y));
    assert!(
        peak.load(Ordering::SeqCst) >= 2,
        "different origins were globally serialized"
    );
    engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_origin_jobs_obey_the_shared_connection_budget() {
    let data = Arc::new(vec![43; 3 << 20]);
    let peak = Arc::new(AtomicUsize::new(0));
    let server = server(
        data.clone(),
        false,
        Arc::new(AtomicUsize::new(0)),
        peak.clone(),
    )
    .await;
    let dir = TempDir::new().unwrap();
    let engine = engine(&dir, 1, 4, 8 << 20, true, false).await;
    let x = enqueue(&engine, server.url.clone(), &data, "a.bin", 4).await;
    let y = enqueue(&engine, server.url.clone(), &data, "b.bin", 4).await;
    tokio::join!(wait(&engine, x), wait(&engine, y));
    assert_eq!(peak.load(Ordering::SeqCst), 1);
    engine.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn measured_throughput_changes_actual_connection_count_and_request_sizes() {
    let data = Arc::new(vec![47; 96 << 20]);
    let peak = Arc::new(AtomicUsize::new(0));
    let source = server(
        data.clone(),
        false,
        Arc::new(AtomicUsize::new(0)),
        peak.clone(),
    )
    .await;
    let directory = TempDir::new().unwrap();
    let engine = engine(&directory, 8, 8, 16 << 20, true, true).await;
    let id = enqueue(&engine, source.url.clone(), &data, "adaptive.bin", 8).await;
    wait(&engine, id).await;
    let requests = source.requests.lock().unwrap().clone();
    assert!(
        peak.load(Ordering::SeqCst) >= 3,
        "controller did not change actual HTTP concurrency: {requests:?}"
    );
    assert!(
        requests.iter().skip(1).any(|(a, b)| b - a != 16 << 20),
        "request sizes did not adapt: {requests:?}"
    );
    engine.shutdown().await.unwrap();
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual controlled loopback performance sample"]
async fn benchmark_one_four_sixteen_connections() {
    let report = std::env::var_os("ZEUS_BENCH_REPORT")
        .expect("set ZEUS_BENCH_REPORT for a manual benchmark");
    let mut runs = Vec::new();
    let data = Arc::new(vec![53; 64 << 20]);
    for connections in [1, 4, 16] {
        let peak = Arc::new(AtomicUsize::new(0));
        let source = server(
            data.clone(),
            false,
            Arc::new(AtomicUsize::new(0)),
            peak.clone(),
        )
        .await;
        let directory = TempDir::new().unwrap();
        let engine = engine(&directory, 32, connections, 16 << 20, false, false).await;
        let started = std::time::Instant::now();
        let id = enqueue(
            &engine,
            source.url.clone(),
            &data,
            "benchmark.bin",
            connections as u8,
        )
        .await;
        wait(&engine, id).await;
        runs.push(serde_json::json!({"kind":"paced_loopback","connections":connections,"elapsed_ms":started.elapsed().as_millis(),"size_bytes":data.len(),"requests":source.requests.lock().unwrap().len(),"peak_streams":peak.load(Ordering::SeqCst),"sha256_verified":true}));
        engine.shutdown().await.unwrap();
    }
    std::fs::write(report, serde_json::to_vec_pretty(&runs).unwrap()).unwrap();
}
