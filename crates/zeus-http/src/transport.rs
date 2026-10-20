//! The HTTP transport abstraction.
//!
//! The prober and the segment fetcher talk HTTP only through [`HttpTransport`], so the engine is
//! deterministic under a scripted fake transport and the production transport (reqwest + rustls) is one
//! implementation among others.
//!
//! The contract of a transport is deliberately *minimal*: it sends one request and returns the first
//! response, **without** following redirects, **without** decompressing bodies and **without**
//! adding any header the caller did not name (except what HTTP itself requires, such as `Host`). Redirect
//! handling, session headers, `Accept-Encoding: identity`, `Range` and `If-Range` are the layer above's
//! business, because every one of them is a security decision (session cookies only to the granted
//! origin; ranges compared with validators).

use std::fmt;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use http::{HeaderMap, Method, StatusCode, Version};
use url::Url;
use zeus_types::{RedactMode, redact_url};

/// One request. `Debug` prints the redacted URL and header **names** only: header values include
/// `Cookie` and `Authorization` (00 section 8.1).
#[derive(Clone)]
pub struct HttpRequest {
    /// The method (`GET` or `HEAD`).
    pub method: Method,
    /// The absolute http(s) URL.
    pub url: Url,
    /// The headers to send, complete.
    pub headers: HeaderMap,
    /// Time allowed until the response head arrives (connect included).
    pub head_timeout: Duration,
    /// Time allowed between body chunks before the stream fails with `net.read_timeout`.
    pub idle_timeout: Duration,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self.headers.keys().map(http::HeaderName::as_str).collect();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &redact_url(self.url.as_str(), RedactMode::Log).url)
            .field("header_names", &names)
            .finish_non_exhaustive()
    }
}

/// A response body: chunks as they arrive, a transport failure ends the stream with an `Err`.
pub type ResponseBody = Pin<Box<dyn Stream<Item = Result<Bytes, TransportError>> + Send>>;

/// The first response to a request.
pub struct HttpResponse {
    /// The status as received.
    pub status: StatusCode,
    /// The protocol version used.
    pub version: Version,
    /// The response headers.
    pub headers: HeaderMap,
    /// The URL that was requested (the transport does not redirect, so this equals the request URL).
    pub url: Url,
    /// The body, not yet read.
    pub body: ResponseBody,
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("version", &self.version)
            .field("url", &redact_url(self.url.as_str(), RedactMode::Log).url)
            .finish_non_exhaustive()
    }
}

/// What kind of transport failure occurred (01 section 8.3, stage C). No HTTP response was received,
/// or the body ended abnormally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportFailure {
    /// The resolver answered NXDOMAIN.
    DnsNxdomain,
    /// Another resolver failure (SERVFAIL, timeout).
    DnsFailure,
    /// The connection was refused.
    ConnectionRefused,
    /// The connection was reset, or a broken pipe.
    ConnectionReset,
    /// The connect timeout (15 s) elapsed.
    ConnectTimeout,
    /// No data arrived for the idle read timeout (30 s).
    ReadTimeout,
    /// The body ended before its declared length.
    PrematureEof,
    /// HTTP/2 `GOAWAY` or `RST_STREAM`.
    H2Reset,
    /// HTTP/2 `ENHANCE_YOUR_CALM`: the server asks to slow down.
    H2EnhanceYourCalm,
    /// A QUIC idle timeout.
    QuicTimeout,
    /// The network is unreachable.
    Unreachable,
    /// The proxy failed to connect.
    ProxyFailed,
    /// The proxy demanded authentication (407).
    ProxyAuthRequired,
    /// A certificate verification error (expired, unknown issuer, wrong host, revoked). No bypass exists.
    TlsCertificate,
    /// Another TLS handshake failure, or a reset during the handshake.
    TlsHandshake,
    /// A trusted transport rejected a malformed frame or impossible response.
    ProtocolViolation,
    /// A trusted scoped transport refused network authority or destination policy.
    PolicyDenied,
    /// Anything else; classified as `transient_network` with the generic code.
    Other,
}

/// A transport failure with a diagnostic that contains no URL query, header value or cookie.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{kind:?}: {detail}")]
pub struct TransportError {
    /// The kind.
    pub kind: TransportFailure,
    /// A short English diagnostic for logs.
    pub detail: String,
}

impl TransportError {
    /// A failure of `kind`.
    #[must_use]
    pub fn new(kind: TransportFailure, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }
}

/// Sends one HTTP request. See the module documentation for the exact contract.
#[async_trait]
pub trait HttpTransport: Send + Sync {
    /// Sends `request` and returns the first response, or a transport failure.
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_hides_header_values_and_url_queries() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::COOKIE,
            "session=ZEUS-CANARY-cookie".parse().unwrap(),
        );
        let req = HttpRequest {
            method: Method::GET,
            url: Url::parse("https://cdn.example.org/blob?X-Amz-Signature=ZEUS-CANARY-sig")
                .unwrap(),
            headers,
            head_timeout: Duration::from_secs(15),
            idle_timeout: Duration::from_secs(30),
        };
        let text = format!("{req:?} {req:#?}");
        assert!(!text.contains("ZEUS-CANARY"), "{text}");
        assert!(text.contains("cookie"), "header names are fine");
    }

    #[test]
    fn the_trait_is_object_safe() {
        fn takes(_: Option<&dyn HttpTransport>) {}
        takes(None);
    }
}
