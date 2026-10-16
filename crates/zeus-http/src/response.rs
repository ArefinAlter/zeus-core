//! Shared request construction and representation validation.
use crate::{
    error::{HttpError, HttpResult},
    probe::SessionBinding,
    transport::{HttpRequest, HttpResponse, HttpTransport},
};
use futures::StreamExt;
use http::{HeaderMap, HeaderName, HeaderValue, Method, header};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use zeus_types::{ErrorEnvelope, HttpUrl, Timestamp, Validators, codes};

pub(crate) fn failure(code: &'static str, message: &'static str) -> HttpError {
    HttpError::Classified(ErrorEnvelope::from_code(code, message))
}
pub(crate) fn value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name)?.to_str().ok().map(str::to_owned)
}
pub(crate) fn validators(headers: &HeaderMap) -> Validators {
    let lm = value(headers, "last-modified");
    let strong = lm.as_ref().and_then(|lm| {
        value(headers, "date").map(|d| crate::parse::last_modified_is_strong(lm, &d))
    });
    Validators {
        etag: value(headers, "etag"),
        last_modified: lm,
        last_modified_strong: strong,
        repr_digest: value(headers, "repr-digest"),
    }
}
pub(crate) fn validate_encoding(headers: &HeaderMap) -> HttpResult<()> {
    if value(headers, "content-encoding").is_some_and(|e| !e.eq_ignore_ascii_case("identity")) {
        return Err(failure(
            codes::HTTP_CONTENT_ENCODED,
            "server returned an encoded representation",
        ));
    }
    Ok(())
}
pub(crate) fn compare_validators(bound: &Validators, seen: &Validators) -> HttpResult<()> {
    if (bound.has_strong_etag() && bound.etag != seen.etag)
        || (!bound.has_strong_etag()
            && bound.last_modified_strong == Some(true)
            && bound.last_modified != seen.last_modified)
    {
        return Err(failure(
            codes::INTEGRITY_RESOURCE_CHANGED,
            "representation validator changed or disappeared",
        ));
    }
    Ok(())
}
fn headers(
    url: &HttpUrl,
    extra: &BTreeMap<String, String>,
    session: Option<&SessionBinding>,
) -> HttpResult<HeaderMap> {
    let mut result = HeaderMap::new();
    result.insert(
        header::ACCEPT_ENCODING,
        HeaderValue::from_static("identity"),
    );
    for (name, val) in extra {
        if !zeus_types::job::ALLOWED_EXTRA_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
            return Err(HttpError::Invalid("forbidden extra header"));
        }
        result.insert(
            HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| HttpError::Invalid("invalid header name"))?,
            HeaderValue::from_str(val).map_err(|_| HttpError::Invalid("invalid header value"))?,
        );
    }
    if let Some(binding) = session.filter(|b| b.origin == url.origin()) {
        let m = &binding.material;
        if m.origin != binding.origin || Timestamp::now() >= m.issued_at.saturating_add_ms(m.ttl_ms)
        {
            return Err(failure(
                codes::HTTP_FORBIDDEN_SESSION,
                "session lease expired or origin mismatched",
            ));
        }
        if !binding.origin.allows_session_release() {
            return Err(HttpError::Invalid("session requires a secure origin"));
        }
        let injected = m
            .headers_for(url.url(), Timestamp::now())
            .ok_or(HttpError::Invalid("invalid session material"))?;
        if let Some(cookie) = injected.cookie {
            result.insert(
                header::COOKIE,
                HeaderValue::from_str(cookie.expose())
                    .map_err(|_| HttpError::Invalid("invalid cookies"))?,
            );
        }
        result.insert(
            header::USER_AGENT,
            HeaderValue::from_str(&injected.user_agent)
                .map_err(|_| HttpError::Invalid("invalid session user agent"))?,
        );
        // Session header enums are serialized to their wire names, preserving the fixed allow-list.
        for (name, val) in &injected.extra {
            let name = serde_json::to_value(name)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .ok_or(HttpError::Invalid("invalid session header"))?;
            result.insert(
                HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| HttpError::Invalid("invalid session header"))?,
                HeaderValue::from_str(val)
                    .map_err(|_| HttpError::Invalid("invalid session header value"))?,
            );
        }
    }
    Ok(result)
}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_following(
    transport: &Arc<dyn HttpTransport>,
    mut url: HttpUrl,
    extra: &BTreeMap<String, String>,
    session: Option<&SessionBinding>,
    range: Option<&str>,
    if_range: Option<&str>,
    head: Duration,
    idle: Duration,
    cancel: &CancellationToken,
) -> HttpResult<(HttpResponse, HttpUrl, u8)> {
    let mut visited = std::collections::HashSet::new();
    for redirects in 0..=10u8 {
        if !visited.insert(url.expose().to_owned()) {
            return Err(failure(codes::HTTP_REDIRECT_LOOP, "redirect loop"));
        }
        let mut headers = headers(&url, extra, session)?;
        if let Some(range) = range {
            headers.insert(
                header::RANGE,
                HeaderValue::from_str(range).map_err(|_| HttpError::Invalid("invalid range"))?,
            );
        }
        if let Some(v) = if_range {
            headers.insert(
                header::IF_RANGE,
                HeaderValue::from_str(v).map_err(|_| HttpError::Invalid("invalid validator"))?,
            );
        }
        let request = HttpRequest {
            method: Method::GET,
            url: url.url().clone(),
            headers,
            head_timeout: head,
            idle_timeout: idle,
        };
        let mut response = tokio::select! { biased; _ = cancel.cancelled() => return Err(HttpError::Canceled), r = transport.send(request) => r.map_err(|e| crate::classify::classify_transport(e.kind).envelope("HTTP transport failed"))? };
        if matches!(response.status.as_u16(), 301 | 302 | 303 | 307 | 308) {
            if redirects == 10 {
                return Err(failure(codes::HTTP_REDIRECT_LOOP, "too many redirects"));
            }
            let location = value(&response.headers, "location")
                .ok_or(HttpError::Invalid("redirect missing location"))?;
            let next = url
                .url()
                .join(&location)
                .map_err(|_| HttpError::Invalid("invalid redirect target"))?;
            if url.url().scheme() == "https" && next.scheme() != "https" {
                return Err(failure(
                    codes::HTTP_REDIRECT_SCHEME,
                    "insecure redirect refused",
                ));
            }
            url = HttpUrl::parse(next.as_str())
                .map_err(|_| failure(codes::HTTP_REDIRECT_SCHEME, "non-HTTP redirect refused"))?;
            continue;
        }
        if !response.status.is_success() && response.status.as_u16() != 416 {
            let mut prefix = Vec::new();
            while prefix.len() < 4096 {
                let chunk = tokio::select! { biased; _ = cancel.cancelled() => return Err(HttpError::Canceled), c = response.body.next() => c };
                match chunk {
                    Some(Ok(c)) => prefix.extend_from_slice(&c[..c.len().min(4096 - prefix.len())]),
                    _ => break,
                }
            }
            let evidence = crate::classify::ResponseEvidence {
                status: response.status.as_u16(),
                headers: &response.headers,
                body_prefix: &prefix,
                url_has_signing_params: url.url().query().is_some(),
                signed_url_expired: None,
                session_used: session.is_some(),
                requires_session: false,
                expected_file: false,
            };
            if let Some(c) = crate::classify::classify_response(&evidence)? {
                let mut error = c.envelope("server refused the request");
                let mut details = serde_json::Map::new();
                details.insert("status".into(), serde_json::json!(response.status.as_u16()));
                if let Some(delay) = value(&response.headers, "retry-after")
                    .and_then(|v| crate::parse::parse_retry_after(&v, Timestamp::now()))
                {
                    details.insert(
                        "retry_after_ms".into(),
                        serde_json::json!(delay.as_millis().min(u128::from(u64::MAX)) as u64),
                    );
                }
                error = error.with_details(details);
                return Err(error.into());
            }
        }
        // Browser proxies may follow redirects only within the already approved origin.
        if response.url != *url.url() {
            let resolved = HttpUrl::parse(response.url.as_str())
                .map_err(|_| HttpError::Invalid("invalid browser final URL"))?;
            if resolved.origin() != url.origin() {
                return Err(failure(
                    codes::HTTP_REDIRECT_SCHEME,
                    "browser redirect left the approved origin",
                ));
            }
            url = resolved;
        }
        validate_encoding(&response.headers)?;
        return Ok((response, url, redirects));
    }
    Err(failure(codes::HTTP_REDIRECT_LOOP, "too many redirects"))
}
