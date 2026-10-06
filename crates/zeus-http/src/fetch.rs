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
//! bytes already written for the failed response are never committed.
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: HttpSegmentFetcher is filled in by the zeus-http implementation task"
)]

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
        Err(HttpError::NotImplemented("HttpSegmentFetcher::fetch"))
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
}
