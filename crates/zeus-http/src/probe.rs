//! Probing: the first conditional request of a job (01 section 3.5, 03 section 7.3).
//!
//! A probe learns size, range support, validators, the file name and whether a session is needed. For a
//! resume it is a ranged `GET` starting at the first uncovered byte, so it doubles as the first data
//! request; the decision table R1 to R11 of 03 section 7.3 is applied to its response.
//!
//! Invariants the implementation keeps:
//!
//! * Redirects are followed **by this layer** (at most 10), never by the transport; session headers are
//!   attached only to requests whose origin equals the granted origin, so a cross-origin redirect
//!   continues without cookies (01 section 4 rule 4).
//! * `Accept-Encoding: identity` always; a `Content-Encoding` other than identity is
//!   `http.content_encoded`.
//! * `Accept-Ranges` is advisory; `range_support` is `verified` only after a `206` with a correct
//!   `Content-Range` was observed.
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: HttpProber is filled in by the zeus-http implementation task"
)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use zeus_session::SessionMaterial;
use zeus_types::{HttpUrl, Origin, ProbeResult, Validators};

use crate::error::{HttpError, HttpResult};
use crate::transport::{HttpTransport, ResponseBody};

/// Session material and the one origin it may be sent to.
#[derive(Clone)]
pub struct SessionBinding {
    /// The granted origin. Material is attached only to requests to exactly this origin.
    pub origin: Origin,
    /// The material, shared across the requests of one job.
    pub material: Arc<SessionMaterial>,
}

impl std::fmt::Debug for SessionBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionBinding")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

/// A resume probe: ask for the bytes from `start` under the bound validators.
#[derive(Debug, Clone)]
pub struct ResumeProbe {
    /// The first uncovered byte.
    pub start: u64,
    /// The validators the committed ranges were fetched under (`If-Range` is derived from them).
    pub bound_validators: Validators,
    /// The total the committed ranges assume.
    pub total_bytes: Option<u64>,
    /// Bytes already on disk just before `start`, for the overlap check when no strong validator exists
    /// (at most 1 MiB).
    pub overlap: Option<bytes::Bytes>,
}

/// What to probe.
#[derive(Debug, Clone)]
pub struct ProbeRequest {
    /// The stable URL (`spec.url`).
    pub url: HttpUrl,
    /// The last known resolved URL, tried first when present.
    pub hint_url: Option<HttpUrl>,
    /// Sent as `Referer` only to the same origin (or an allow-listed one).
    pub referrer: Option<HttpUrl>,
    /// Allow-listed extra headers from the job spec.
    pub extra_headers: BTreeMap<String, String>,
    /// Session material for the granted origin, if the job has a lease.
    pub session: Option<SessionBinding>,
    /// Present when resuming.
    pub resume: Option<ResumeProbe>,
    /// Time allowed per request until the head arrives.
    pub head_timeout: Duration,
    /// Time allowed between body chunks.
    pub idle_timeout: Duration,
}

/// What the probe found.
pub struct ProbeOutcome {
    /// The probe result for the job record and the `job.probed` event.
    pub result: ProbeResult,
    /// The URL that answered (after redirects). Secret-bearing: never log it.
    pub resolved_url: HttpUrl,
    /// For a resume or a plain `GET`, the response body positioned at `body_offset`, so the first bytes
    /// are not requested twice. `None` for `HEAD` and for `0-0` probes whose single byte is discarded.
    pub body: Option<ResponseBody>,
    /// The resource offset of the first byte of `body`.
    pub body_offset: u64,
}

impl std::fmt::Debug for ProbeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeOutcome")
            .field("result", &self.result)
            .field("body_offset", &self.body_offset)
            .finish_non_exhaustive()
    }
}

/// Probes a resource.
#[async_trait]
pub trait Prober: Send + Sync {
    /// Runs the probe. Cancelable at every await. Failures are classified (`HttpError::Classified`);
    /// the resume-validation outcomes R2 to R10 are `integrity.*` errors the engine turns into a restart.
    async fn probe(
        &self,
        request: ProbeRequest,
        cancel: &CancellationToken,
    ) -> HttpResult<ProbeOutcome>;
}

/// The default prober over any [`HttpTransport`].
pub struct HttpProber {
    transport: Arc<dyn HttpTransport>,
}

impl HttpProber {
    /// A prober using `transport`.
    #[must_use]
    pub fn new(transport: Arc<dyn HttpTransport>) -> Self {
        Self { transport }
    }
}

#[async_trait]
impl Prober for HttpProber {
    async fn probe(
        &self,
        request: ProbeRequest,
        cancel: &CancellationToken,
    ) -> HttpResult<ProbeOutcome> {
        Err(HttpError::NotImplemented("HttpProber::probe"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_prober_trait_is_object_safe() {
        fn takes(_: Option<&dyn Prober>) {}
        takes(None);
    }
}
