//! The production transport: reqwest 0.13 with rustls (platform certificate verifier), HTTP/1.1 and h2.
//!
//! The client is built so that it honours the contract of [`crate::transport`]: no automatic
//! redirects, no automatic decompression (the `gzip`, `brotli`, `deflate` and `zstd` features are off,
//! so `Accept-Encoding` is never added), no cookie store, no referer, and no retry of its own.
use crate::transport::TransportFailure;
use async_trait::async_trait;
use futures::StreamExt;

use crate::client::{ClientConfig, ProxyConfig};
use crate::error::{HttpError, HttpResult};
use crate::transport::{HttpRequest, HttpResponse, HttpTransport, TransportError};

/// An [`HttpTransport`] over `reqwest::Client`.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Builds the client from `config`.
    pub fn new(config: &ClientConfig) -> HttpResult<Self> {
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .connect_timeout(config.connect_timeout)
            .read_timeout(config.read_timeout)
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .pool_idle_timeout(config.pool_idle_timeout)
            .user_agent(config.user_agent.value());
        builder = match &config.proxy {
            ProxyConfig::System => builder,
            ProxyConfig::None => builder.no_proxy(),
            ProxyConfig::Url(url) => builder.proxy(
                reqwest::Proxy::all(url).map_err(|_| HttpError::Invalid("invalid proxy URL"))?,
            ),
        };
        if !config.http2 {
            builder = builder.http1_only();
        }
        let client = builder
            .build()
            .map_err(|_| HttpError::Invalid("the HTTP client could not be built"))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let idle = request.idle_timeout;
        let response = tokio::time::timeout(
            request.head_timeout,
            self.client
                .request(request.method, request.url.clone())
                .headers(request.headers)
                .send(),
        )
        .await
        .map_err(|_| {
            TransportError::new(
                TransportFailure::ConnectTimeout,
                "response deadline elapsed",
            )
        })?
        .map_err(map_error)?;
        let status = response.status();
        let version = response.version();
        let headers = response.headers().clone();
        let stream = response.bytes_stream();
        let body = futures::stream::unfold(
            (Box::pin(stream), false),
            move |(mut stream, ended)| async move {
                if ended {
                    return None;
                }
                match tokio::time::timeout(idle, stream.next()).await {
                    Ok(Some(Ok(bytes))) => Some((Ok(bytes), (stream, false))),
                    Ok(Some(Err(error))) => Some((Err(map_error(error)), (stream, true))),
                    Ok(None) => None,
                    Err(_) => Some((
                        Err(TransportError::new(
                            TransportFailure::ReadTimeout,
                            "body idle deadline elapsed",
                        )),
                        (stream, true),
                    )),
                }
            },
        );
        Ok(HttpResponse {
            status,
            version,
            headers,
            url: request.url,
            body: Box::pin(body),
        })
    }
}

fn map_error(error: reqwest::Error) -> TransportError {
    // Error text from reqwest may include the complete URL. Never forward it.
    let kind = if let Some(failure) = tls_failure(&error) {
        failure
    } else if error.is_timeout() {
        TransportFailure::ReadTimeout
    } else if error.is_connect() {
        TransportFailure::ConnectionRefused
    } else if error.is_body() {
        TransportFailure::PrematureEof
    } else {
        TransportFailure::Other
    };
    TransportError::new(kind, "HTTP transport failed")
}

// Inspect typed causes, never Display text (which may contain a signed URL). io::Error's
// source can skip its wrapped error, so inspect its payload before following source().
fn tls_failure(mut error: &(dyn std::error::Error + 'static)) -> Option<TransportFailure> {
    for _ in 0..64 {
        if let Some(tls) = error.downcast_ref::<rustls::Error>() {
            return Some(match tls {
                rustls::Error::InvalidCertificate(_) | rustls::Error::NoCertificatesPresented => {
                    TransportFailure::TlsCertificate
                }
                _ => TransportFailure::TlsHandshake,
            });
        }
        if let Some(inner) = error
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::get_ref)
        {
            error = inner;
        } else if let Some(inner) = error.source() {
            error = inner;
        } else {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("connection wrapper")]
    struct Wrapped(#[source] std::io::Error);

    #[test]
    fn certificate_causes_survive_connection_and_io_wrappers() {
        for certificate in [
            rustls::CertificateError::Expired,
            rustls::CertificateError::NotValidYet,
            rustls::CertificateError::UnknownIssuer,
        ] {
            let error = Wrapped(std::io::Error::other(rustls::Error::InvalidCertificate(
                certificate,
            )));
            assert_eq!(tls_failure(&error), Some(TransportFailure::TlsCertificate));
        }
        assert_eq!(
            tls_failure(&rustls::Error::NoCertificatesPresented),
            Some(TransportFailure::TlsCertificate)
        );
    }

    #[test]
    fn handshake_errors_are_distinct_and_message_text_cannot_spoof_a_certificate_error() {
        let handshake = Wrapped(std::io::Error::other(rustls::Error::General(
            "handshake failed".into(),
        )));
        assert_eq!(
            tls_failure(&handshake),
            Some(TransportFailure::TlsHandshake)
        );
        let message = std::io::Error::other(
            "invalid certificate at https://fixture.invalid/?key=not-a-credential",
        );
        assert_eq!(tls_failure(&message), None);
    }

    #[test]
    fn the_client_builds_with_the_default_configuration() {
        ReqwestTransport::new(&ClientConfig::default())
            .expect("rustls platform verifier initialises");
        ReqwestTransport::new(&ClientConfig {
            proxy: ProxyConfig::None,
            ..ClientConfig::default()
        })
        .unwrap();
        assert!(
            ReqwestTransport::new(&ClientConfig {
                proxy: ProxyConfig::Url("not a url".into()),
                ..ClientConfig::default()
            })
            .is_err()
        );
    }
}
