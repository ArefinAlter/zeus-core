//! The production transport: reqwest 0.13 with rustls (platform certificate verifier), HTTP/1.1 and h2.
//!
//! The client is built so that it honours the contract of [`crate::transport`]: no automatic
//! redirects, no automatic decompression (the `gzip`, `brotli`, `deflate` and `zstd` features are off,
//! so `Accept-Encoding` is never added), no cookie store, no referer, and no retry of its own.
#![expect(
    unused_variables,
    dead_code,
    reason = "skeleton: ReqwestTransport::send is filled in by the zeus-http implementation task"
)]

use async_trait::async_trait;

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
        let client = builder
            .build()
            .map_err(|_| HttpError::Invalid("the HTTP client could not be built"))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        Err(TransportError::new(
            crate::transport::TransportFailure::Other,
            "ReqwestTransport::send is not implemented yet",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
