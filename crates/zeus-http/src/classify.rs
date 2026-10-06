//! Mapping what the engine observed to `(class, code)` (01 section 8.3).
//!
//! Stage C (transport failures, rules C1 to C8) is implemented here. Stage D (an HTTP response, rules D0
//! to D12, with the block and expiry markers and the signing-parameter list) is the API contract of
//! [`classify_response`]; its body is filled in by the implementation task.
#![expect(
    unused_variables,
    reason = "skeleton: classify_response is filled in by the zeus-http implementation task"
)]

use http::HeaderMap;
use zeus_types::error::status_class;
use zeus_types::{ErrorClass, ErrorEnvelope, codes};

use crate::error::{HttpError, HttpResult};
use crate::transport::TransportFailure;

/// The outcome of classification: the class that drives retry policy and the registered code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// A registered code, for example `http.status_429` or `net.connect_timeout`.
    pub code: String,
    /// The class.
    pub class: ErrorClass,
    /// The `retryable` value emitted with the code.
    pub retryable: bool,
}

impl Classification {
    /// A classification of a registered code (class and `retryable` come from the registry).
    #[must_use]
    pub fn of(code: &'static str) -> Self {
        let info = zeus_types::error::lookup(code);
        debug_assert!(info.is_some(), "unregistered code {code}");
        let (class, retryable) =
            info.map_or((ErrorClass::Internal, false), |i| (i.class, i.retryable));
        Self {
            code: code.to_owned(),
            class,
            retryable,
        }
    }

    /// The HTTP status family `http.status_<nnn>` with the class of rules D7 to D12.
    #[must_use]
    pub fn for_status(status: u16) -> Self {
        let (class, retryable) = status_class(status);
        Self {
            code: format!("http.status_{status}"),
            class,
            retryable,
        }
    }

    /// The envelope for this classification with an English message and optional details.
    #[must_use]
    pub fn envelope(&self, message: impl Into<String>) -> ErrorEnvelope {
        let code = zeus_types::ErrorCode::new(self.code.clone())
            .unwrap_or_else(|_| zeus_types::ErrorCode::from_static(codes::INTERNAL_BUG));
        ErrorEnvelope::new(code, self.class, self.retryable, message)
    }
}

/// Stage C: no HTTP response was received (or the body ended abnormally).
///
/// * C1/C2: `net.dns_nxdomain`, `net.dns_failure` (`transient_network`; rule R3 may escalate repeated
///   NXDOMAIN to `net.host_not_found`).
/// * C3: refused, reset, timeouts, unreachable, premature EOF, `GOAWAY`/`RST_STREAM`, QUIC idle timeout:
///   `transient_network` with the matching `net.*` code.
/// * C4: HTTP/2 `ENHANCE_YOUR_CALM`: `throttled`, `net.h2_enhance_your_calm`.
/// * C5: certificate errors: `permanent`, `tls.cert_invalid`; no retry and no bypass.
/// * C6: other handshake failures: `transient_network`, `tls.handshake_failed` (rule R4 may escalate).
/// * C7: proxy 407: `permanent`, `net.proxy_auth_required`; other proxy failures `net.proxy_failed`.
#[must_use]
pub fn classify_transport(kind: TransportFailure) -> Classification {
    use TransportFailure as F;
    Classification::of(match kind {
        F::DnsNxdomain => codes::NET_DNS_NXDOMAIN,
        F::DnsFailure => codes::NET_DNS_FAILURE,
        F::ConnectionRefused => codes::NET_CONNECTION_REFUSED,
        F::ConnectionReset => codes::NET_CONNECTION_RESET,
        F::ConnectTimeout => codes::NET_CONNECT_TIMEOUT,
        F::ReadTimeout => codes::NET_READ_TIMEOUT,
        F::PrematureEof => codes::NET_PREMATURE_EOF,
        F::H2Reset => codes::NET_H2_RESET,
        F::H2EnhanceYourCalm => codes::NET_H2_ENHANCE_YOUR_CALM,
        F::QuicTimeout => codes::NET_QUIC_TIMEOUT,
        F::Unreachable | F::Other => codes::NET_UNREACHABLE,
        F::ProxyFailed => codes::NET_PROXY_FAILED,
        F::ProxyAuthRequired => codes::NET_PROXY_AUTH_REQUIRED,
        F::TlsCertificate => codes::TLS_CERT_INVALID,
        F::TlsHandshake => codes::TLS_HANDSHAKE_FAILED,
    })
}

/// Evidence for classifying an HTTP response.
#[derive(Debug)]
pub struct ResponseEvidence<'a> {
    /// The status.
    pub status: u16,
    /// The response headers.
    pub headers: &'a HeaderMap,
    /// At most the first 4 KiB of an error body, for marker matching only; never stored or logged.
    pub body_prefix: &'a [u8],
    /// The request URL carried signing parameters (`X-Amz-Signature`, `X-Goog-Signature`, `sig`+`se`,
    /// `hdnts`, `exp`, `token`, ...).
    pub url_has_signing_params: bool,
    /// The signed URL's own expiry is in the past, or none is parseable and it was obtained more than
    /// 5 minutes ago (rule D3); `None` when unknown.
    pub signed_url_expired: Option<bool>,
    /// A session lease was used for the request.
    pub session_used: bool,
    /// The probe set `requires_session`.
    pub requires_session: bool,
    /// A non-HTML file was expected (rule D6 applies to `200` HTML walls).
    pub expected_file: bool,
}

/// Stage D: classifies a response, or `Ok(None)` when it is not an error (rule D0: `200`, `206`, and
/// `3xx` with a valid `Location`; a `416` with the matching `Content-Range` total is resume logic, not
/// an error, rule D10). Before applying the rules the caller reads at most 4 KiB of any error body.
pub fn classify_response(evidence: &ResponseEvidence<'_>) -> HttpResult<Option<Classification>> {
    Err(HttpError::NotImplemented("classify_response"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_c_table() {
        use TransportFailure as F;
        let cases = [
            (
                F::DnsNxdomain,
                "net.dns_nxdomain",
                ErrorClass::TransientNetwork,
                true,
            ),
            (
                F::DnsFailure,
                "net.dns_failure",
                ErrorClass::TransientNetwork,
                true,
            ),
            (
                F::ConnectionRefused,
                "net.connection_refused",
                ErrorClass::TransientNetwork,
                true,
            ),
            (
                F::ConnectionReset,
                "net.connection_reset",
                ErrorClass::TransientNetwork,
                true,
            ),
            (
                F::ConnectTimeout,
                "net.connect_timeout",
                ErrorClass::TransientNetwork,
                true,
            ),
            (
                F::ReadTimeout,
                "net.read_timeout",
                ErrorClass::TransientNetwork,
                true,
            ),
            (
                F::PrematureEof,
                "net.premature_eof",
                ErrorClass::TransientNetwork,
                true,
            ),
            (
                F::H2Reset,
                "net.h2_reset",
                ErrorClass::TransientNetwork,
                true,
            ),
            (
                F::H2EnhanceYourCalm,
                "net.h2_enhance_your_calm",
                ErrorClass::Throttled,
                true,
            ),
            (
                F::QuicTimeout,
                "net.quic_timeout",
                ErrorClass::TransientNetwork,
                true,
            ),
            (
                F::Unreachable,
                "net.unreachable",
                ErrorClass::TransientNetwork,
                true,
            ),
            (
                F::ProxyFailed,
                "net.proxy_failed",
                ErrorClass::TransientNetwork,
                true,
            ),
            (
                F::ProxyAuthRequired,
                "net.proxy_auth_required",
                ErrorClass::Permanent,
                false,
            ),
            (
                F::TlsCertificate,
                "tls.cert_invalid",
                ErrorClass::Permanent,
                false,
            ),
            (
                F::TlsHandshake,
                "tls.handshake_failed",
                ErrorClass::TransientNetwork,
                true,
            ),
        ];
        for (kind, code, class, retryable) in cases {
            let c = classify_transport(kind);
            assert_eq!(
                (c.code.as_str(), c.class, c.retryable),
                (code, class, retryable),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn status_families() {
        assert_eq!(Classification::for_status(429).class, ErrorClass::Throttled);
        assert_eq!(Classification::for_status(503).class, ErrorClass::Throttled);
        assert_eq!(
            Classification::for_status(502).class,
            ErrorClass::TransientNetwork
        );
        assert_eq!(Classification::for_status(404).class, ErrorClass::Permanent);
        assert_eq!(Classification::for_status(404).code, "http.status_404");
        assert!(!Classification::for_status(404).retryable);
    }

    #[test]
    fn envelopes_use_the_registry_and_validate() {
        let env = classify_transport(TransportFailure::ConnectTimeout)
            .envelope("connect timed out after 15 s");
        assert!(env.validate().is_ok());
        assert_eq!(env.class, ErrorClass::TransientNetwork);
        let env = Classification::for_status(418).envelope("teapot");
        assert!(env.validate().is_ok());
    }
}
