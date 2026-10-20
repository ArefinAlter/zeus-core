//! Browser responses pass through the same range and validator checks as direct HTTP.
use async_trait::async_trait;
use futures::StreamExt;
use std::{collections::BTreeMap, sync::Arc};
use zeus_http::{HttpRequest, HttpResponse, HttpTransport, TransportError, TransportFailure};
use zeus_session::{ProxyFetch, protocol::RequestHeaderName, provider::ProxyFetchRequest};
use zeus_types::{ByteRange, ErrorClass, HttpUrl, JobId, Origin, ToEnvelope};

pub(crate) struct BrowserTransport {
    pub provider: Arc<dyn ProxyFetch>,
    pub job_id: JobId,
    pub origin: Origin,
    pub profile_id: Option<String>,
}
fn failed() -> TransportError {
    TransportError::new(
        TransportFailure::ProtocolViolation,
        "browser response failed validation",
    )
}
fn provider_failed(error: zeus_session::SessionError) -> TransportError {
    let envelope = error.to_envelope();
    TransportError::new(
        if matches!(
            envelope.class,
            ErrorClass::PolicyDenied | ErrorClass::Permanent
        ) {
            TransportFailure::PolicyDenied
        } else {
            TransportFailure::ProxyFailed
        },
        "browser fetch failed or became unavailable",
    )
}
#[async_trait]
impl HttpTransport for BrowserTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        if request.method != http::Method::GET
            || request.url.origin().ascii_serialization() != self.origin.as_str()
        {
            return Err(failed());
        }
        let range = request
            .headers
            .get(http::header::RANGE)
            .map(|h| {
                let value = h
                    .to_str()
                    .map_err(|_| failed())?
                    .strip_prefix("bytes=")
                    .ok_or_else(failed)?;
                let (start, end) = value.split_once('-').ok_or_else(failed)?;
                let start = start.parse::<u64>().map_err(|_| failed())?;
                let end = end
                    .parse::<u64>()
                    .map_err(|_| failed())?
                    .checked_add(1)
                    .ok_or_else(failed)?;
                if end <= start || end - start > 8 * 1024 * 1024 {
                    return Err(failed());
                }
                Ok(ByteRange { start, end })
            })
            .transpose()?;
        let mut headers = BTreeMap::new();
        for (name, key) in [
            ("accept", RequestHeaderName::Accept),
            ("accept-language", RequestHeaderName::AcceptLanguage),
        ] {
            if let Some(value) = request.headers.get(name) {
                headers.insert(key, value.to_str().map_err(|_| failed())?.into());
            }
        }
        let response = self
            .provider
            .fetch_range(ProxyFetchRequest {
                job_id: self.job_id,
                url: HttpUrl::parse(request.url.as_str()).map_err(|_| failed())?,
                origin: self.origin.clone(),
                range,
                if_range: request
                    .headers
                    .get(http::header::IF_RANGE)
                    .map(|h| h.to_str().map(str::to_owned))
                    .transpose()
                    .map_err(|_| failed())?,
                request_headers: headers,
                chunk_bytes: 64 * 1024,
                deadline: request.head_timeout,
                profile_id: self.profile_id.clone(),
            })
            .await
            .map_err(provider_failed)?;
        if response.head.final_url.origin() != self.origin {
            return Err(failed());
        }
        let status = http::StatusCode::from_u16(response.head.status).map_err(|_| failed())?;
        let mut headers = http::HeaderMap::new();
        for (name, value) in response.head.headers {
            if matches!(name.as_str(), "set-cookie" | "set-cookie2") {
                return Err(failed());
            }
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| failed())?,
                http::HeaderValue::from_str(&value).map_err(|_| failed())?,
            );
        }
        let start = if status == http::StatusCode::PARTIAL_CONTENT {
            range.map(|r| r.start).unwrap_or(0)
        } else {
            0
        };
        let end = if status == http::StatusCode::PARTIAL_CONTENT {
            range.map(|r| r.end)
        } else {
            headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
        };
        let idle = request.idle_timeout;
        // Poll only on consumer demand; no task prefetches or releases browser byte credit early.
        let body = futures::stream::unfold(
            (response.body, start, false),
            move |(mut body, offset, done)| async move {
                if done {
                    return None;
                }
                match tokio::time::timeout(idle, body.next()).await {
                    Ok(Some(Ok(chunk)))
                        if chunk.offset == offset
                            && !chunk.data.is_empty()
                            && chunk.data.len() <= 64 * 1024
                            && offset
                                .checked_add(chunk.data.len() as u64)
                                .is_some_and(|n| end.is_none_or(|end| n <= end)) =>
                    {
                        let next = offset + chunk.data.len() as u64;
                        Some((Ok(chunk.data), (body, next, false)))
                    }
                    Ok(None) if end.is_none_or(|end| offset == end) => None,
                    Ok(Some(Err(error))) => {
                        Some((Err(provider_failed(error)), (body, offset, true)))
                    }
                    Err(_) => Some((
                        Err(TransportError::new(
                            TransportFailure::ReadTimeout,
                            "browser body deadline elapsed",
                        )),
                        (body, offset, true),
                    )),
                    _ => Some((Err(failed()), (body, offset, true))),
                }
            },
        );
        Ok(HttpResponse {
            status,
            version: http::Version::HTTP_11,
            headers,
            url: response.head.final_url.url().clone(),
            body: Box::pin(body),
        })
    }
}
