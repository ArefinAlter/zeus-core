//! Segmented fetching (03 section 7.4, 02 section 9 for the proxy equivalent).
//!
//! A [`SegmentFetcher`] performs one ranged `GET` and streams the body, in bounded chunks, into a
//! [`Sink`] at absolute offsets. This crate has **no journal dependency**: the engine wires the sink to
//! the writer task and the commit pipeline.
//!
//! For every `206` the fetcher checks **before handing bytes to the sink** that: `Content-Range` start
//! equals the requested start; the total equals the known total; `ETag` and a strong `Last-Modified`
//! equal the bound validators; the body does not exceed the requested length. A violation aborts the
//! request with `integrity.range_mismatch`, `integrity.resource_changed` or `integrity.range_overrun`;
//! the sink decides durability. The engine may acknowledge complete commit units from a strongly
//! validated response before EOF; its unfinished tail is never acknowledged and is re-requested.
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use tokio_util::sync::CancellationToken;
use zeus_types::{ByteRange, HttpUrl, Validators};

use crate::error::{HttpError, HttpResult};
use crate::probe::SessionBinding;
use crate::transport::HttpTransport;

/// Where the body goes. The engine's implementation hands buffers to the job's writer task and applies
/// backpressure by not returning until the buffer is accepted.
#[async_trait]
pub trait Sink: Send {
    /// Accepts `data`, which belongs at resource offset `offset`. An error aborts the segment.
    async fn write_at(&mut self, offset: u64, data: Bytes) -> HttpResult<()>;
}

/// One ranged request.
#[derive(Debug, Clone)]
pub struct SegmentRequest {
    /// The URL to fetch (the resolved URL, or the stable one when it expired).
    pub url: HttpUrl,
    /// The bytes wanted, half-open.
    pub range: ByteRange,
    /// The validators the job's data was fetched under; `If-Range` is derived from them.
    pub bound_validators: Validators,
    /// The known total, to check `Content-Range`.
    pub total_bytes: Option<u64>,
    /// Session material for the granted origin.
    pub session: Option<SessionBinding>,
    /// Allow-listed extra headers.
    pub extra_headers: BTreeMap<String, String>,
    /// Time allowed until the response head arrives.
    pub head_timeout: Duration,
    /// Time allowed between body chunks.
    pub idle_timeout: Duration,
    /// Largest chunk handed to the sink at once.
    pub chunk_bytes: usize,
}

/// How a segment request ended without an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentEnd {
    /// Every requested byte was delivered.
    Complete,
    /// The server closed the body early after delivering fewer bytes; the engine re-requests the rest
    /// (rule R5 escalates repeated early closes at one offset).
    ServerClosedEarly,
}

/// What a segment request delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentOutcome {
    /// Bytes handed to the sink.
    pub bytes_written: u64,
    /// The status of the response.
    pub status: u16,
    /// How it ended.
    pub end: SegmentEnd,
    /// The validators seen in the response, for the engine's comparison with the bound ones.
    pub validators_seen: Validators,
}

/// Fetches one segment.
#[async_trait]
pub trait SegmentFetcher: Send + Sync {
    /// Performs the request and streams the body into `sink`. Cancelable at every await; the sink never
    /// receives bytes after cancellation returns.
    async fn fetch(
        &self,
        request: SegmentRequest,
        sink: &mut dyn Sink,
        cancel: &CancellationToken,
    ) -> HttpResult<SegmentOutcome>;
}

/// The default fetcher over any [`HttpTransport`].
pub struct HttpSegmentFetcher {
    transport: Arc<dyn HttpTransport>,
}

impl HttpSegmentFetcher {
    /// A fetcher using `transport`.
    #[must_use]
    pub fn new(transport: Arc<dyn HttpTransport>) -> Self {
        Self { transport }
    }
}

#[async_trait]
impl SegmentFetcher for HttpSegmentFetcher {
    async fn fetch(
        &self,
        request: SegmentRequest,
        sink: &mut dyn Sink,
        cancel: &CancellationToken,
    ) -> HttpResult<SegmentOutcome> {
        use crate::response::{compare_validators, failure, send_following, validators, value};
        use futures::StreamExt;
        use zeus_types::codes;
        let range = range_header(request.range).ok_or(HttpError::Invalid("empty segment"))?;
        if request.chunk_bytes == 0 {
            return Err(HttpError::Invalid("zero chunk size"));
        }
        let (mut response, _, _) = send_following(
            &self.transport,
            request.url,
            &request.extra_headers,
            request.session.as_ref(),
            Some(&range),
            request.bound_validators.if_range_value(),
            request.head_timeout,
            request.idle_timeout,
            cancel,
        )
        .await?;
        if response.status.as_u16() != 206 {
            return Err(failure(
                codes::INTEGRITY_RANGE_IGNORED,
                "server ignored segment range",
            ));
        }
        let cr = value(&response.headers, "content-range")
            .ok_or(HttpError::Invalid("206 missing Content-Range"))?;
        match crate::parse::parse_content_range(&cr)? {
            crate::parse::ContentRange::Satisfied { range, total }
                if range == request.range
                    && (request.total_bytes.is_none() || total == request.total_bytes) => {}
            _ => {
                return Err(failure(
                    codes::INTEGRITY_RANGE_MISMATCH,
                    "segment Content-Range mismatch",
                ));
            }
        }
        let validators_seen = validators(&response.headers);
        compare_validators(&request.bound_validators, &validators_seen)?;
        let mut written = 0u64;
        loop {
            let next = tokio::select! { biased; _ = cancel.cancelled() => return Err(HttpError::Canceled), next = response.body.next() => next };
            let Some(chunk) = next else {
                break;
            };
            let chunk = chunk.map_err(|e| {
                crate::classify::classify_transport(e.kind).envelope("segment body failed")
            })?;
            if written.saturating_add(chunk.len() as u64) > request.range.len() {
                return Err(failure(
                    codes::INTEGRITY_RANGE_OVERRUN,
                    "segment body exceeds requested range",
                ));
            }
            for part in chunk.chunks(request.chunk_bytes) {
                if request.session.as_ref().is_some_and(|b| {
                    b.material.issued_at.saturating_add_ms(b.material.ttl_ms)
                        <= zeus_types::Timestamp::now()
                }) {
                    return Err(failure(
                        codes::HTTP_FORBIDDEN_SESSION,
                        "session lease expired during transfer",
                    ));
                }
                if cancel.is_cancelled() {
                    return Err(HttpError::Canceled);
                }
                // A writer may own a blocking disk operation: always join it before cancellation returns.
                sink.write_at(request.range.start + written, Bytes::copy_from_slice(part))
                    .await?;
                written += part.len() as u64;
            }
        }
        Ok(SegmentOutcome {
            bytes_written: written,
            status: 206,
            end: if written == request.range.len() {
                SegmentEnd::Complete
            } else {
                SegmentEnd::ServerClosedEarly
            },
            validators_seen,
        })
    }
}

/// The `Range` header value for a half-open range: the inclusive RFC 9110 form `bytes=first-last`.
/// `None` for an empty range, which HTTP cannot express.
#[must_use]
pub fn range_header(range: ByteRange) -> Option<String> {
    range
        .to_inclusive()
        .map(|(first, last)| format!("bytes={first}-{last}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_headers_are_inclusive_on_the_wire() {
        assert_eq!(
            range_header(ByteRange::new(0, 1).unwrap()).as_deref(),
            Some("bytes=0-0")
        );
        assert_eq!(
            range_header(ByteRange::new(402_653_184, 419_430_400).unwrap()).as_deref(),
            Some("bytes=402653184-419430399")
        );
        assert_eq!(range_header(ByteRange::new(5, 5).unwrap()), None);
    }

    #[test]
    fn the_traits_are_object_safe() {
        fn takes(_: Option<&dyn SegmentFetcher>, _: Option<&mut dyn Sink>) {}
        takes(None, None);
    }

    #[tokio::test]
    async fn cancellation_drains_an_inflight_writer_before_returning() {
        use crate::transport::{HttpRequest, HttpResponse, HttpTransport, TransportError};
        use std::sync::atomic::{AtomicBool, Ordering};

        struct OneResponse;
        #[async_trait]
        impl HttpTransport for OneResponse {
            async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
                let mut headers = http::HeaderMap::new();
                headers.insert("content-range", "bytes 0-3/4".parse().unwrap());
                headers.insert("content-length", "4".parse().unwrap());
                Ok(HttpResponse {
                    status: http::StatusCode::PARTIAL_CONTENT,
                    version: http::Version::HTTP_11,
                    headers,
                    url: request.url,
                    body: Box::pin(futures::stream::iter([Ok(Bytes::from_static(b"data"))])),
                })
            }
        }
        struct HeldWriter {
            entered: Option<tokio::sync::oneshot::Sender<()>>,
            release: Option<tokio::sync::oneshot::Receiver<()>>,
            completed: Arc<AtomicBool>,
        }
        #[async_trait]
        impl Sink for HeldWriter {
            async fn write_at(&mut self, _: u64, data: Bytes) -> HttpResult<()> {
                assert_eq!(&data[..], b"data");
                self.entered.take().unwrap().send(()).unwrap();
                self.release.take().unwrap().await.unwrap();
                self.completed.store(true, Ordering::SeqCst);
                Ok(())
            }
        }
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let completed = Arc::new(AtomicBool::new(false));
        let mut sink = HeldWriter {
            entered: Some(entered),
            release: Some(released),
            completed: completed.clone(),
        };
        let cancel = CancellationToken::new();
        let token = cancel.clone();
        let task = tokio::spawn(async move {
            HttpSegmentFetcher::new(Arc::new(OneResponse))
                .fetch(
                    SegmentRequest {
                        url: HttpUrl::parse("https://fixture.invalid/file").unwrap(),
                        range: ByteRange::new(0, 4).unwrap(),
                        bound_validators: Validators::default(),
                        total_bytes: Some(4),
                        session: None,
                        extra_headers: BTreeMap::new(),
                        head_timeout: Duration::from_secs(1),
                        idle_timeout: Duration::from_secs(1),
                        chunk_bytes: 4,
                    },
                    &mut sink,
                    &token,
                )
                .await
        });
        started.await.unwrap();
        cancel.cancel();
        // The current-thread executor polls the cancelled fetch while the writer remains held.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        assert!(
            !task.is_finished(),
            "cancellation returned while the old writer was still active"
        );
        assert!(!completed.load(Ordering::SeqCst));
        release.send(()).unwrap();
        assert!(matches!(task.await.unwrap(), Err(HttpError::Canceled)));
        assert!(completed.load(Ordering::SeqCst));
    }
}
