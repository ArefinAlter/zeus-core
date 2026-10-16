//! HTTP probing and segmented fetching for Zeus (01 section 8.3, 03 section 7).
//!
//! * [`transport`]: the [`HttpTransport`] abstraction (no redirects, no decompression, no implicit headers).
//! * [`parse`]: `Content-Range`, `Retry-After`, HTTP dates, `Content-Disposition`.
//! * [`classify`]: transport and response classification into the error classes that drive retry policy.
//! * [`probe`]: the [`Prober`]; [`fetch`]: the [`SegmentFetcher`] and its [`Sink`].
//! * [`client`] and, with the default `reqwest-transport` feature, `reqwest_transport`: the production
//!   transport.
//!
//! Session headers are attached only to requests whose origin equals the granted origin, including
//! across redirects, which this layer follows itself.

#![forbid(unsafe_code)]

pub mod classify;
pub mod client;
pub mod error;
pub mod fetch;
pub mod parse;
pub mod probe;
#[cfg(feature = "reqwest-transport")]
pub mod reqwest_transport;
pub mod transport;

pub use classify::{Classification, ResponseEvidence, classify_response, classify_transport};
pub use client::{ClientConfig, ProxyConfig, UserAgentPolicy};
pub use error::{HttpError, HttpResult};
pub use fetch::{
    HttpSegmentFetcher, SegmentEnd, SegmentFetcher, SegmentOutcome, SegmentRequest, Sink,
    range_header,
};
pub use parse::{ContentRange, parse_content_range, parse_retry_after};
pub use probe::{HttpProber, ProbeOutcome, ProbeRequest, Prober, ResumeProbe, SessionBinding};
#[cfg(feature = "reqwest-transport")]
pub use reqwest_transport::ReqwestTransport;
pub use transport::{
    HttpRequest, HttpResponse, HttpTransport, ResponseBody, TransportError, TransportFailure,
};

mod response;
