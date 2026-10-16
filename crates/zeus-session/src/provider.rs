//! The two capabilities the engine needs from the browser: session material and the in-browser fetch
//! proxy. Both are traits so the engine is testable without a browser, and so an embedding that has
//! no extension simply injects none (jobs that need a session then wait in `awaiting_session`).
//!
//! Neither trait ever exposes a cookie through a log, an event or an error: material lives in
//! [`SessionLease`], is `Debug`-redacted, and is dropped (zeroised) when the lease ends.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use zeus_control::Clock;
use zeus_types::event::LeasePurpose;
use zeus_types::{
    ByteRange, GrantId, HttpUrl, JobId, Origin, SecretString, SessionLeaseId, Validators,
};

use crate::error::SessionResult;
use crate::material::SessionMaterial;
use crate::protocol::{RefreshMethod, RefreshReason, RequestHeaderName, SessionHeaderName};

/// What the engine asks of [`SessionProvider::lease`].
#[derive(Debug, Clone)]
pub struct LeaseRequest {
    /// The job that needs the material.
    pub job_id: JobId,
    /// The effective grant. The provider's side already made the `session.lease_requested` audit record
    /// durable before calling (04 section 4.4).
    pub grant_id: GrantId,
    /// The origin of `url`.
    pub origin: Origin,
    /// The URL that will be requested (cookie matching uses it).
    pub url: HttpUrl,
    /// Why.
    pub purpose: LeasePurpose,
    /// Headers beyond `User-Agent`.
    pub request_headers: Vec<SessionHeaderName>,
    /// Requested lifetime (at most 15 minutes).
    pub ttl: Duration,
    /// The job came from a private window.
    pub incognito: bool,
    /// Route to the connection with this `profile_id` (handoff jobs), else the most recently active one.
    pub profile_id: Option<String>,
}

/// A granted lease: the material and when it ends.
#[derive(Clone)]
pub struct SessionLease {
    /// The handle (safe to log).
    pub lease_id: SessionLeaseId,
    /// The material, shared by the requests of one job. Dropping the last reference zeroises the values.
    pub material: Arc<SessionMaterial>,
    /// Monotonic reading of the issuing clock when the lease was received.
    pub acquired_at: Duration,
    /// Time to live from `acquired_at`.
    pub ttl: Duration,
}

impl std::fmt::Debug for SessionLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionLease")
            .field("lease_id", &self.lease_id)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl SessionLease {
    /// True when the monotonic time to live has elapsed on `clock`. A lease is never extended
    /// (02 section 13.1 rule 4); the engine requests a new one.
    #[must_use]
    pub fn is_expired(&self, clock: &dyn Clock) -> bool {
        clock.monotonic().saturating_sub(self.acquired_at) >= self.ttl
    }
}

/// The headers to attach to one outgoing request.
pub struct InjectedHeaders {
    /// The `Cookie` header value, or `None` when no cookie applies to the URL.
    pub cookie: Option<SecretString>,
    /// `User-Agent`.
    pub user_agent: String,
    /// The allow-listed extra headers (`accept-language`, `sec-ch-ua*`).
    pub extra: BTreeMap<SessionHeaderName, String>,
}

impl SessionMaterial {
    /// The headers to send to `url`, or `None` when `url`'s origin is not the material's origin: session
    /// material is attached **only** to requests whose origin equals the granted one (01 section 4 rule
    /// 4), so a redirect to another origin continues without cookies. Applies the cookie rules the
    /// browser would: domain and host-only matching, path prefix, `Secure`, expiry.
    pub fn headers_for(
        &self,
        url: &url::Url,
        now: zeus_types::Timestamp,
    ) -> Option<InjectedHeaders> {
        let origin = Origin::parse(&url.origin().ascii_serialization()).ok()?;
        if origin != self.origin
            || !origin.allows_session_release()
            || now >= self.issued_at.saturating_add_ms(self.ttl_ms)
        {
            return None;
        }
        let host = url.host_str()?.to_ascii_lowercase();
        let path = url.path();
        let mut applicable = Vec::new();
        for cookie in &self.cookies {
            let domain = cookie.domain.trim_start_matches('.').to_ascii_lowercase();
            let domain_matches =
                host == domain || (!cookie.host_only && host.ends_with(&format!(".{domain}")));
            let path_matches = cookie.path.starts_with('/')
                && (path == cookie.path
                    || (path.starts_with(&cookie.path)
                        && (cookie.path.ends_with('/')
                            || path.as_bytes().get(cookie.path.len()) == Some(&b'/'))));
            if !domain_matches
                || !path_matches
                || (cookie.secure && url.scheme() != "https")
                || cookie.expires_at.is_some_and(|t| t <= now)
                || cookie.partition_key.is_some()
            {
                continue;
            }
            if cookie.name.is_empty()
                || cookie
                    .name
                    .bytes()
                    .any(|b| b <= 32 || b >= 127 || b"()<>@,;:\\\"/[]?={}".contains(&b))
                || cookie
                    .value
                    .expose()
                    .bytes()
                    .any(|b| b < 32 || b == 127 || b == b';')
            {
                return None;
            }
            applicable.push(cookie);
        }
        applicable.sort_by_key(|c| std::cmp::Reverse(c.path.len()));
        let value = applicable
            .into_iter()
            .map(|c| format!("{}={}", c.name, c.value.expose()))
            .collect::<Vec<_>>()
            .join("; ");
        Some(InjectedHeaders {
            cookie: if value.is_empty() {
                None
            } else {
                Some(SecretString::new(value))
            },
            user_agent: self.user_agent.clone(),
            extra: self.headers.clone(),
        })
    }
}

/// A fresh URL derived by the extension.
#[derive(Debug, Clone)]
pub struct RefreshedUrl {
    /// The stable URL.
    pub url: HttpUrl,
    /// The new (signed) URL to try first.
    pub final_url: HttpUrl,
    /// How it was obtained.
    pub method: RefreshMethod,
    /// Validators seen, if any.
    pub validators: Option<Validators>,
    /// Size seen, if any.
    pub total_bytes: Option<u64>,
}

/// What the engine asks of [`SessionProvider::refresh_url`].
#[derive(Debug, Clone)]
pub struct UrlRefreshRequest {
    /// The job.
    pub job_id: JobId,
    /// The origin whose session applies.
    pub origin: Origin,
    /// The stable URL (`spec.url`).
    pub origin_url: HttpUrl,
    /// The URL that failed.
    pub stale_url: HttpUrl,
    /// Why.
    pub reason: RefreshReason,
    /// Methods to try, in order.
    pub methods: Vec<RefreshMethod>,
    /// Known size, to sanity-check the refresh.
    pub expected_total_bytes: Option<u64>,
    /// Known entity tag.
    pub expected_etag: Option<String>,
    /// How long the extension has (at most 60 s).
    pub deadline: Duration,
    /// Route to this browser profile.
    pub profile_id: Option<String>,
}

/// Supplies session material and fresh URLs. Implemented by the daemon's session broker over the native
/// messaging connection; faked in tests.
#[async_trait]
pub trait SessionProvider: Send + Sync {
    /// Asks the extension for session material. Waits at most the native-messaging timeout (15 s).
    /// `Err(Remote)` carries the extension's `consent_required`, `denied` or `unavailable` answer;
    /// `Err(ExtensionUnavailable)` means no connection exists and the job waits in `awaiting_session`.
    async fn lease(&self, request: LeaseRequest) -> SessionResult<SessionLease>;

    /// Asks the extension to derive a fresh URL after `url.expired`, `session.expired` or a block.
    async fn refresh_url(&self, request: UrlRefreshRequest) -> SessionResult<RefreshedUrl>;

    /// True when at least one extension connection (for `profile_id` when given) is up.
    fn extension_connected(&self, profile_id: Option<&str>) -> bool;
}

/// What the engine asks of [`ProxyFetch::fetch_range`].
#[derive(Debug, Clone)]
pub struct ProxyFetchRequest {
    /// The job.
    pub job_id: JobId,
    /// The URL to fetch.
    pub url: HttpUrl,
    /// The origin whose consent applies (equals the origin of `url`).
    pub origin: Origin,
    /// The range, or `None` for the whole resource. At most `max_range_bytes`; the engine slices.
    pub range: Option<ByteRange>,
    /// A strong validator for `If-Range`.
    pub if_range: Option<String>,
    /// Only `accept` and `accept-language`.
    pub request_headers: BTreeMap<RequestHeaderName, String>,
    /// Raw bytes per chunk.
    pub chunk_bytes: u32,
    /// Time allowed until response headers arrive.
    pub deadline: Duration,
    /// Route to this browser profile.
    pub profile_id: Option<String>,
}

/// The response head; the engine classifies the status exactly as for a direct response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHead {
    /// The HTTP status as received by the browser.
    pub status: u16,
    /// The final URL after redirects.
    pub final_url: HttpUrl,
    /// A redirect was followed.
    pub redirected: bool,
    /// The forwarded response headers, lowercase names.
    pub headers: BTreeMap<String, String>,
}

/// One chunk of body bytes at an absolute resource offset.
#[derive(Debug, Clone)]
pub struct ProxyChunk {
    /// Offset in the resource of the first byte.
    pub offset: u64,
    /// The bytes.
    pub data: Bytes,
}

/// The body of a proxied response. Polling it consumes and returns credits; dropping it sends
/// `fetch.cancel`, so a canceled job never leaves a stream running in the browser.
pub type ProxyBody = Pin<Box<dyn Stream<Item = SessionResult<ProxyChunk>> + Send>>;

/// A proxied response: the head, then the body.
pub struct ProxyResponse {
    /// The response head.
    pub head: ProxyHead,
    /// The body, ending with `Ok(None)` after `fetch.end` or an `Err` after `fetch.error`.
    pub body: ProxyBody,
}

impl std::fmt::Debug for ProxyResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyResponse")
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

/// Fetches byte ranges through the user's own browser (02 section 9): the recovery for class `blocked`.
/// The browser makes an ordinary credentialed request; nothing here disguises anything.
#[async_trait]
pub trait ProxyFetch: Send + Sync {
    /// Starts one stream and waits for its head.
    async fn fetch_range(&self, request: ProxyFetchRequest) -> SessionResult<ProxyResponse>;

    /// True when an extension that advertises `fetch_proxy` is connected (for `profile_id` when given).
    fn available(&self, profile_id: Option<&str>) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_traits_are_object_safe() {
        fn takes(_: Option<&dyn SessionProvider>, _: Option<&dyn ProxyFetch>) {}
        takes(None, None);
    }

    #[test]
    fn headers_are_origin_path_and_expiry_scoped() {
        use crate::material::{Cookie, SameSite};
        let now = zeus_types::Timestamp::now();
        let mut material = SessionMaterial {
            session_id: zeus_types::IdGenerator::new().session_lease_id(),
            origin: Origin::parse("https://a.example").unwrap(),
            issued_at: now,
            ttl_ms: 60_000,
            cookies: vec![Cookie {
                name: "sid".into(),
                value: SecretString::from("secret"),
                domain: "a.example".into(),
                path: "/private".into(),
                secure: true,
                http_only: true,
                same_site: SameSite::Lax,
                host_only: true,
                expires_at: None,
                partition_key: None,
            }],
            user_agent: "UA".into(),
            headers: BTreeMap::new(),
            cookie_store_id: None,
        };
        assert_eq!(
            material
                .headers_for(
                    &url::Url::parse("https://a.example/private/file").unwrap(),
                    now
                )
                .unwrap()
                .cookie
                .unwrap()
                .expose(),
            "sid=secret"
        );
        assert!(
            material
                .headers_for(
                    &url::Url::parse("https://a.example/private-other").unwrap(),
                    now
                )
                .unwrap()
                .cookie
                .is_none()
        );
        assert!(
            material
                .headers_for(
                    &url::Url::parse("https://other.example/private/file").unwrap(),
                    now
                )
                .is_none()
        );
        assert!(
            material
                .headers_for(
                    &url::Url::parse("http://a.example/private/file").unwrap(),
                    now
                )
                .is_none()
        );
        material.cookies[0].expires_at = Some(now);
        assert!(
            material
                .headers_for(
                    &url::Url::parse("https://a.example/private/file").unwrap(),
                    now
                )
                .unwrap()
                .cookie
                .is_none()
        );
        assert!(
            material
                .headers_for(
                    &url::Url::parse("https://a.example/private/file").unwrap(),
                    now.saturating_add_ms(60_000)
                )
                .is_none()
        );
    }

    #[test]
    fn a_lease_expires_on_the_monotonic_clock_only() {
        use zeus_control::ManualClock;
        let clock = ManualClock::new(zeus_types::Timestamp::UNIX_EPOCH);
        let ids = zeus_types::IdGenerator::new();
        let lease = SessionLease {
            lease_id: ids.session_lease_id(),
            material: Arc::new(SessionMaterial {
                session_id: ids.session_lease_id(),
                origin: Origin::parse("https://a.example").unwrap(),
                issued_at: zeus_types::Timestamp::UNIX_EPOCH,
                ttl_ms: 1000,
                cookies: vec![],
                user_agent: "UA".into(),
                headers: BTreeMap::new(),
                cookie_store_id: None,
            }),
            acquired_at: clock.monotonic(),
            ttl: Duration::from_secs(900),
        };
        assert!(!lease.is_expired(&clock));
        clock.set_wall(zeus_types::Timestamp::parse("2030-01-01T00:00:00.000Z").unwrap());
        assert!(
            !lease.is_expired(&clock),
            "a wall-clock step must not expire a lease"
        );
        clock.advance(Duration::from_secs(900));
        assert!(lease.is_expired(&clock));
    }
}
