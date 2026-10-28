//! Adaptive HTTP range execution. A canceled writer is drained before its remaining range is reused.
use super::*;
use futures::stream::FuturesUnordered;
use std::{collections::VecDeque, sync::atomic::AtomicU64};
use tokio::time::Instant;
use zeus_control::concurrency::{AimdConfig, AimdController, Signal};
use zeus_control::estimate::Ewma;
use zeus_control::segments::optimal_segment_bytes;

pub(super) struct RangeRun {
    pub id: JobId,
    pub epoch: u32,
    pub file: Arc<dyn DataFile>,
    pub request: SegmentRequest,
    pub transport: Arc<dyn HttpTransport>,
    pub max_connections: u32,
    pub browser_proxy: bool,
}
struct Active {
    range: ByteRange,
    durable: Arc<AtomicU64>,
    cancel: CancellationToken,
    splitting: bool,
    started: Instant,
}
impl Engine {
    pub(super) fn bounded_transport(
        &self,
        transport: Arc<dyn HttpTransport>,
    ) -> Arc<dyn HttpTransport> {
        Arc::new(HostBoundTransport {
            engine: self.clone(),
            transport,
        })
    }

    fn host_connections(&self, url: &HttpUrl) -> Option<Arc<HostBudget>> {
        let mut hosts = self
            .inner
            .connections
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key = url.origin().to_string();
        if let Some(gate) = hosts.get(&key) {
            gate.touch();
            return Some(gate.clone());
        }
        if hosts.len() >= 256 {
            let idle = hosts
                .iter()
                .filter(|(_, budget)| Arc::strong_count(budget) == 1)
                .min_by_key(|(_, budget)| {
                    budget
                        .state
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .last_used
                })
                .map(|(key, _)| key.clone());
            let idle = idle?;
            hosts.remove(&idle);
        }
        let gate = Arc::new(HostBudget::new(
            self.inner.config.limits.connections_per_host as usize,
        ));
        hosts.insert(key, gate.clone());
        Some(gate)
    }

    pub(super) async fn download_ranges(
        &self,
        run: RangeRun,
        cancel: &CancellationToken,
    ) -> EngineResult<()> {
        let total = run.request.range.end;
        let mut pending: VecDeque<_> = self
            .inner
            .journal
            .committed(run.id)?
            .uncovered(total)
            .into();
        let limit = run
            .max_connections
            .min(self.inner.config.limits.connections_per_job)
            .min(self.inner.config.limits.connections_per_host)
            .max(1);
        let tuning = &self.inner.transfer_tuning;
        let strong = run.request.bound_validators.is_strongly_identified();
        let unit = self.inner.config.commit.commit_unit_bytes;
        let ceiling = if run.browser_proxy { 8 << 20 } else { 32 << 20 };
        let mut preferred = tuning.segment_bytes.min(ceiling);
        // Weakly identified servers retain the one-commit-unit request contract.
        if !strong {
            preferred = unit.min(ceiling);
        }
        let mut controller = AimdController::new(AimdConfig {
            initial: if tuning.adaptive_concurrency {
                self.inner
                    .concurrency_targets
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&run.request.url.origin().to_string())
                    .copied()
                    .unwrap_or(2)
                    .min(limit)
                    .max(1)
            } else {
                limit
            },
            max: limit,
            ..AimdConfig::default()
        })
        .map_err(|_| internal())?;
        if total < preferred.saturating_mul(u64::from(controller.current())) {
            preferred = preferred.min(total.div_ceil(u64::from(controller.current())).max(unit));
        }
        let run = Arc::new(run);
        let host_budget = self.host_connections(&run.request.url).ok_or_else(|| {
            rejected(
                codes::NET_CONNECT_TIMEOUT,
                "origin scheduler capacity reached",
            )
        })?;
        let group = cancel.child_token();
        let network_bytes = Arc::new(AtomicU64::new(0));
        let mut active = BTreeMap::<u64, Active>::new();
        let mut work = FuturesUnordered::new();
        let mut ordinal = 0;
        let mut failure = None;
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut measured_at = Instant::now();
        let mut measured_bytes = 0;
        let mut published_active = 0;
        loop {
            if cancel.is_cancelled() && failure.is_none() {
                failure = Some(HttpError::Canceled.into());
                group.cancel();
                pending.clear();
            }
            while failure.is_none() && active.len() < controller.current() as usize {
                let Some(gap) = pending.pop_front() else {
                    break;
                };
                let range = ByteRange {
                    start: gap.start,
                    end: gap.start.saturating_add(preferred).min(gap.end),
                };
                if range.end < gap.end {
                    pending.push_front(ByteRange {
                        start: range.end,
                        end: gap.end,
                    });
                }
                let durable = Arc::new(AtomicU64::new(range.start));
                let token = group.child_token();
                work.push(execute_range(
                    self.clone(),
                    run.clone(),
                    ordinal,
                    range,
                    durable.clone(),
                    token.clone(),
                    network_bytes.clone(),
                ));
                active.insert(
                    ordinal,
                    Active {
                        range,
                        durable,
                        cancel: token,
                        splitting: false,
                        started: Instant::now(),
                    },
                );
                ordinal += 1;
            }
            if active.len() != published_active {
                if let Err(error) = self.set_active_ranges(run.id, active.len() as u32).await {
                    if failure.is_none() {
                        failure = Some(error);
                    }
                    group.cancel();
                    pending.clear();
                }
                published_active = active.len();
            }
            if active.is_empty() {
                break;
            }
            tokio::select! {
                outcome = work.next() => {
                    let Some((index, result)) = outcome else { return Err(internal()); };
                    let Some(worker) = active.remove(&index) else { return Err(internal()); };
                    let cursor = worker.durable.load(Ordering::Acquire);
                    match result {
                        Ok(()) => {},
                        Err(EngineError::Http(HttpError::Canceled)) if worker.splitting && failure.is_none() && !cancel.is_cancelled() => {
                            // The fetch future (including all blocking writes) returned. No old writer
                            // can now race either replacement request. Reuse only acknowledged bytes.
                            if cursor < worker.range.end {
                                let remaining = worker.range.end - cursor;
                                let half = (remaining / 2 / unit) * unit;
                                if half > 0 && half < remaining {
                                    pending.push_front(ByteRange { start: cursor + half, end: worker.range.end });
                                    pending.push_front(ByteRange { start: cursor, end: cursor + half });
                                } else { pending.push_front(ByteRange { start: cursor, end: worker.range.end }); }
                            }
                        },
                        Err(error) if failure.is_none() => {
                            if error.to_envelope().class == ErrorClass::Throttled
                                && let Ok(decision) = controller.observe(Signal::Throttled) {
                                self.remember_concurrency(&run.request.url, decision.target);
                            }
                            failure = Some(error);
                            pending.clear();
                            group.cancel();
                        },
                        Err(_) => {},
                    }
                },
                _ = tick.tick(), if failure.is_none() => {
                    host_budget.recover();
                    let elapsed = measured_at.elapsed();
                    if tuning.adaptive_concurrency && elapsed >= Duration::from_secs(2) {
                        let bytes = network_bytes.load(Ordering::Relaxed);
                        let bps = ((bytes - measured_bytes) as f64 / elapsed.as_secs_f64()) as u64;
                        // Establish a zero baseline so the first useful interval probes one more
                        // connection instead of permanently holding the initial target.
                        if measured_bytes == 0 {
                            controller.observe(Signal::Interval { throughput_bps: 1, rtt: host_budget.header_latency() }).map_err(|_| internal())?;
                        }
                        let decision = controller.observe(Signal::Interval { throughput_bps: bps, rtt: host_budget.header_latency() }).map_err(|_| internal())?;
                        self.remember_concurrency(&run.request.url, decision.target);
                        if strong {
                            // Header latency excludes local semaphore waiting and body transfer time;
                            // it is a TTFB estimate, not a packet-level RTT measurement.
                            let latency_ms=host_budget.header_latency().unwrap_or(Duration::from_millis(1)).as_millis().max(1).min(u128::from(u64::MAX)) as u64;
                            preferred = optimal_segment_bytes(total, controller.current(), latency_ms, bps)
                                .map_err(|_| internal())?.min(ceiling);
                        }
                        measured_at = Instant::now();
                        measured_bytes = bytes;
                    }
                    // A spare worker can reclaim a slow tail only after useful progress and an
                    // adequate observation window. No speculative duplicate writes are permitted.
                    if strong && tuning.work_stealing && pending.is_empty()
                        && active.len() < controller.current() as usize
                        && !active.values().any(|v| v.splitting)
                    {
                        let victim = active.values_mut().filter(|w| !w.splitting
                            && w.started.elapsed() >= Duration::from_millis(250)
                            && w.range.end.saturating_sub(w.durable.load(Ordering::Acquire)) > (4 << 20).max(unit * 2))
                            .max_by_key(|w| w.range.end.saturating_sub(w.durable.load(Ordering::Acquire)));
                        if let Some(worker) = victim {
                            worker.splitting = true;
                            worker.cancel.cancel();
                        }
                    }
                }
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(())
    }

    fn remember_concurrency(&self, url: &HttpUrl, target: u32) {
        let mut targets = self
            .inner
            .concurrency_targets
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key = url.origin().to_string();
        if targets.len() >= 256
            && !targets.contains_key(&key)
            && let Some(first) = targets.keys().next().cloned()
        {
            targets.remove(&first);
        }
        targets.insert(key, target);
    }

    async fn set_active_ranges(&self, id: JobId, count: u32) -> EngineResult<()> {
        let engine = self.clone();
        blocking(move || {
            engine.inner.journal.transact(|tx| {
                let Some(mut row) = tx.job(id)? else {
                    return Ok(());
                };
                if (row.job.state == JobState::Downloading || count == 0)
                    && row.job.progress.segments_active != count
                {
                    row.job.progress.segments_active = count;
                    tx.put_job(&row)?;
                }
                Ok(())
            })?;
            Ok(())
        })
        .await
    }
}

async fn execute_range(
    engine: Engine,
    run: Arc<RangeRun>,
    index: u64,
    range: ByteRange,
    durable: Arc<AtomicU64>,
    cancel: CancellationToken,
    network_bytes: Arc<AtomicU64>,
) -> (u64, EngineResult<()>) {
    let result = async {
        engine.ensure_running()?;
        let mut sink = CommitSink {
            engine: engine.clone(),
            run: run.clone(),
            range,
            cursor: range.start,
            block_start: range.start,
            crc: 0,
            durable,
            network_bytes,
        };
        let result = HttpSegmentFetcher::new(run.transport.clone())
            .fetch(
                SegmentRequest {
                    range,
                    ..run.request.clone()
                },
                &mut sink,
                &cancel,
            )
            .await?;
        if result.end != SegmentEnd::Complete {
            return Err(rejected(
                codes::NET_PREMATURE_EOF,
                "segment ended before all bytes arrived",
            ));
        }
        if cancel.is_cancelled() {
            return Err(HttpError::Canceled.into());
        }
        sink.finish().await
    }
    .await;
    (index, result)
}

struct CommitSink {
    engine: Engine,
    run: Arc<RangeRun>,
    range: ByteRange,
    cursor: u64,
    block_start: u64,
    crc: u32,
    durable: Arc<AtomicU64>,
    network_bytes: Arc<AtomicU64>,
}
impl CommitSink {
    async fn finish(&mut self) -> EngineResult<()> {
        if self.cursor > self.block_start {
            self.engine
                .commit(
                    self.run.file.clone(),
                    self.run.id,
                    self.run.epoch,
                    ByteRange {
                        start: self.block_start,
                        end: self.cursor,
                    },
                    self.crc,
                )
                .await?;
            self.durable.store(self.cursor, Ordering::Release);
            self.block_start = self.cursor;
            self.crc = 0;
        }
        Ok(())
    }
}
#[async_trait::async_trait]
impl zeus_http::Sink for CommitSink {
    async fn write_at(&mut self, offset: u64, mut data: bytes::Bytes) -> zeus_http::HttpResult<()> {
        if offset != self.cursor {
            return Err(HttpError::Invalid("non-sequential range writer"));
        }
        while !data.is_empty() {
            let unit = self.engine.inner.config.commit.commit_unit_bytes;
            let count = data
                .len()
                .min((unit - (self.cursor - self.block_start)) as usize);
            let part = data.split_to(count);
            let crc = crc32c::crc32c_append(self.crc, &part);
            let file = self.run.file.clone();
            let at = self.cursor;
            tokio::task::spawn_blocking(move || file.write_all_at(at, &part))
                .await
                .map_err(|_| HttpError::Invalid("writer task failed"))?
                .map_err(|e| HttpError::Classified(e.to_envelope()))?;
            self.crc = crc;
            self.cursor += count as u64;
            self.network_bytes
                .fetch_add(count as u64, Ordering::Relaxed);
            // The last block waits for a successful response EOF, so it cannot finalize the job
            // before body overrun/early-close checks. Earlier complete units have bound validators.
            if self.cursor - self.block_start == unit && self.cursor < self.range.end {
                self.finish()
                    .await
                    .map_err(|e| HttpError::Classified(e.to_envelope()))?;
            }
        }
        Ok(())
    }
}

/// A FIFO semaphore whose future capacity can shrink without aborting active requests.
/// Deferred reductions consume returning permits; growth repays that debt before adding capacity.
pub(super) struct HostBudget {
    semaphore: Arc<Semaphore>,
    ceiling: usize,
    state: Mutex<HostBudgetState>,
}
struct HostBudgetState {
    target: usize,
    debt: usize,
    last_recovery: Instant,
    last_used: Instant,
    header_latency: Ewma,
}
impl HostBudget {
    fn new(ceiling: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(ceiling)),
            ceiling,
            state: Mutex::new(HostBudgetState {
                target: ceiling,
                debt: 0,
                last_recovery: Instant::now(),
                last_used: Instant::now(),
                header_latency: Ewma::new(0.2).expect("constant valid smoothing factor"),
            }),
        }
    }
    fn touch(&self) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_used = Instant::now();
    }
    async fn acquire(self: &Arc<Self>) -> Result<HostPermit, tokio::sync::AcquireError> {
        let permit = self.semaphore.clone().acquire_owned().await?;
        self.touch();
        Ok(HostPermit {
            budget: self.clone(),
            permit: Some(permit),
        })
    }
    fn observe_header_latency(&self, elapsed: Duration) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // A configured finite head timeout bounds production samples. Zero from deterministic
        // test transports still has a small positive scheduling cost.
        let _ = state
            .header_latency
            .update(elapsed.as_secs_f64().max(0.000_001));
    }
    fn header_latency(&self) -> Option<Duration> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .header_latency
            .value()
            .map(Duration::from_secs_f64)
    }
    fn throttled(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let target = (state.target / 2).max(1);
        let reduction = state.target - target;
        state.debt += reduction - self.semaphore.forget_permits(reduction);
        state.target = target;
        state.last_recovery = Instant::now();
        state.last_used = Instant::now();
    }
    fn recover(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.target < self.ceiling && state.last_recovery.elapsed() >= Duration::from_secs(2) {
            state.target += 1;
            if state.debt > 0 {
                state.debt -= 1;
            } else {
                self.semaphore.add_permits(1);
            }
            state.last_recovery = Instant::now();
        }
    }
}
struct HostPermit {
    budget: Arc<HostBudget>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}
impl Drop for HostPermit {
    fn drop(&mut self) {
        let mut state = self.budget.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.debt > 0 {
            state.debt -= 1;
            if let Some(permit) = self.permit.take() {
                permit.forget();
            }
        }
        // Otherwise the owned permit returns after the state guard is released.
    }
}

/// Gate every actual HTTP request, including each redirect, and keep its permit through body EOF
/// or body drop. Gating only the original URL would undercount a shared redirect destination.
struct HostBoundTransport {
    engine: Engine,
    transport: Arc<dyn HttpTransport>,
}
#[async_trait::async_trait]
impl HttpTransport for HostBoundTransport {
    async fn send(
        &self,
        request: zeus_http::HttpRequest,
    ) -> Result<zeus_http::HttpResponse, zeus_http::TransportError> {
        use zeus_http::{TransportError, TransportFailure};
        let url = HttpUrl::parse(request.url.as_str()).map_err(|_| {
            TransportError::new(
                TransportFailure::ProtocolViolation,
                "invalid scheduled HTTP URL",
            )
        })?;
        let gate = self.engine.host_connections(&url).ok_or_else(|| {
            TransportError::new(TransportFailure::Other, "origin scheduler capacity reached")
        })?;
        let permit = tokio::time::timeout(request.head_timeout, gate.acquire())
            .await
            .map_err(|_| {
                TransportError::new(
                    TransportFailure::ConnectTimeout,
                    "origin connection budget wait timed out",
                )
            })?
            .map_err(|_| {
                TransportError::new(TransportFailure::Other, "origin connection budget closed")
            })?;
        self.engine.ensure_running().map_err(|_| {
            TransportError::new(
                TransportFailure::PolicyDenied,
                "engine network gate is closed",
            )
        })?;
        let started = Instant::now();
        let response = match self.transport.send(request).await {
            Ok(response) => response,
            Err(error) => {
                if matches!(
                    error.kind,
                    TransportFailure::H2EnhanceYourCalm | TransportFailure::ConnectionReset
                ) {
                    gate.throttled();
                }
                return Err(error);
            }
        };
        gate.observe_header_latency(started.elapsed());
        if matches!(response.status.as_u16(), 429 | 503) {
            gate.throttled();
        }

        let body =
            futures::stream::unfold((response.body, permit), |(mut body, permit)| async move {
                body.next().await.map(|chunk| (chunk, (body, permit)))
            });
        Ok(zeus_http::HttpResponse {
            body: Box::pin(body),
            ..response
        })
    }
}

#[cfg(test)]
mod host_tests {
    use super::*;
    struct DelayedHeaders;
    #[async_trait::async_trait]
    impl HttpTransport for DelayedHeaders {
        async fn send(
            &self,
            request: zeus_http::HttpRequest,
        ) -> Result<zeus_http::HttpResponse, zeus_http::TransportError> {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(zeus_http::HttpResponse {
                status: http::StatusCode::OK,
                version: http::Version::HTTP_11,
                headers: Default::default(),
                url: request.url,
                body: Box::pin(futures::stream::once(async {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Ok(bytes::Bytes::from_static(b"body"))
                })),
            })
        }
    }
    #[tokio::test(start_paused = true)]
    async fn header_latency_excludes_local_budget_wait_and_body_duration() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("downloads");
        std::fs::create_dir(&root).unwrap();
        let journal = Journal::open(
            &temp.path().join("journal.redb"),
            &Default::default(),
            Arc::new(SystemClock::new()),
        )
        .unwrap();
        let mut config = EngineConfig::new(vec![root.clone()], root, temp.path().into());
        config.limits.connections_per_host = 1;
        let engine = EngineBuilder::new(config)
            .journal(journal)
            .build()
            .await
            .unwrap();
        let url = HttpUrl::parse("https://latency.invalid/file").unwrap();
        let gate = engine.host_connections(&url).unwrap();
        let occupied = gate.acquire().await.unwrap();
        let transport = engine.bounded_transport(Arc::new(DelayedHeaders));
        let request = zeus_http::HttpRequest {
            method: http::Method::GET,
            url: url.url().clone(),
            headers: Default::default(),
            head_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(40),
        };
        let task = tokio::spawn(async move { transport.send(request).await.unwrap() });
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(5)).await;
        assert!(gate.header_latency().is_none());
        drop(occupied);
        let response = task.await.unwrap();
        assert_eq!(gate.header_latency(), Some(Duration::from_millis(20)));
        // The delayed body is still unpolled; body lifetime retains its capacity without entering
        // the header estimator. This prevents slow bodies from masquerading as slow handshakes.
        assert_eq!(gate.semaphore.available_permits(), 0);
        tokio::time::advance(Duration::from_secs(10)).await;
        assert_eq!(gate.header_latency(), Some(Duration::from_millis(20)));
        drop(response);
        assert_eq!(gate.semaphore.available_permits(), 1);
        engine.shutdown().await.unwrap();
    }
    #[tokio::test(start_paused = true)]
    async fn host_reduction_drains_existing_requests_before_admitting_replacements() {
        let budget = Arc::new(HostBudget::new(8));
        let mut active = Vec::new();
        for _ in 0..8 {
            active.push(budget.acquire().await.unwrap());
        }
        budget.throttled();
        assert_eq!(budget.state.lock().unwrap().target, 4);
        for _ in 0..4 {
            active.pop();
        }
        assert_eq!(budget.semaphore.available_permits(), 0);
        active.pop();
        assert_eq!(budget.semaphore.available_permits(), 1);
        tokio::time::advance(Duration::from_secs(2)).await;
        budget.recover();
        assert_eq!(budget.state.lock().unwrap().target, 5);
        assert_eq!(budget.semaphore.available_permits(), 2);
        drop(active);
        assert_eq!(budget.semaphore.available_permits(), 5);
    }
    #[tokio::test(start_paused = true)]
    async fn recovery_repays_pending_reduction_and_throttle_never_drops_below_one() {
        let budget = Arc::new(HostBudget::new(4));
        let mut active = Vec::new();
        for _ in 0..4 {
            active.push(budget.acquire().await.unwrap());
        }
        budget.throttled();
        tokio::time::advance(Duration::from_secs(2)).await;
        budget.recover();
        assert_eq!(budget.state.lock().unwrap().target, 3);
        assert_eq!(budget.state.lock().unwrap().debt, 1);
        drop(active);
        assert_eq!(budget.semaphore.available_permits(), 3);
        for _ in 0..8 {
            budget.throttled();
        }
        assert_eq!(budget.state.lock().unwrap().target, 1);
        assert_eq!(budget.semaphore.available_permits(), 1);
    }
}
