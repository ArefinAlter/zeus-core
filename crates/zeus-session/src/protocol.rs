//! Native messaging protocol v1: the message catalogue (02 sections 5 to 11, 14).
//!
//! Every frame is one JSON object `{v, id, re?, type, body}` ([`Message`]). The typed bodies live here
//! and the two directions are the closed enums [`ExtensionBody`] (extension to daemon) and
//! [`DaemonBody`] (daemon to extension). Decoding is two-step: an unknown `type` is
//! [`DecodeError::UnknownType`] (an error for a request, ignorable for a notification) and a known
//! type with a malformed body is [`DecodeError::Schema`], so the daemon can answer with `re` set
//! (02 section 6.4). Receivers ignore unknown object keys; there is no `deny_unknown_fields`.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use zeus_types::event::LeasePurpose;
use zeus_types::{
    Approval, ApprovalId, ApprovalState, BrowserName, ConnectionId, ErrorEnvelope, Event, GrantId,
    GrantScope, HttpUrl, JobId, JobState, JobSummary, Origin, RunId, SessionGrant, SessionLeaseId,
    Timestamp, Validators,
};

use crate::error::DecodeError;
use crate::material::SessionMaterial;

/// The protocol version this crate speaks.
pub const PROTOCOL_VERSION: u16 = 1;

/// The native-messaging host name registered with the browsers (00 section 3).
pub const HOST_NAME: &str = "dev.zeus.native_host";

/// Capability names (02 section 5).
pub mod capability {
    /// `handoff.offer`, `.accept`, `.reject`, `.withdraw`. Declared by both sides.
    pub const HANDOFF: &str = "handoff";
    /// The extension can release session material.
    pub const SESSION: &str = "session";
    /// Bounded authenticated workflow documents fetched in the approved browser profile.
    pub const SESSION_PAGE: &str = "session.page";
    /// The extension can derive a fresh URL by refetching the origin URL.
    pub const URL_REFRESH_REFETCH: &str = "url_refresh.refetch";
    /// The extension can derive a fresh URL by starting and cancelling a browser download.
    pub const URL_REFRESH_DOWNLOAD_API: &str = "url_refresh.download_api";
    /// The in-browser fetch proxy (`fetch.*`). Declared by both sides.
    pub const FETCH_PROXY: &str = "fetch_proxy";
    /// The extension can serve requests flagged `incognito`.
    pub const INCOGNITO: &str = "incognito";
    /// The daemon supports `approval.list`, `approval.pending`, `approval.decide`.
    pub const APPROVALS: &str = "approvals";
    /// The daemon supports `events.subscribe` and `job.event`.
    pub const EVENTS: &str = "events";
    /// The daemon supports `job.list` and `job.control`.
    pub const JOB_CONTROL: &str = "job_control";
    /// The daemon supports `grant.list` and `grant.revoke`.
    pub const GRANTS: &str = "grants";
}

macro_rules! text_id {
    ($(#[$meta:meta])* $name:ident, $pattern:literal, $max:expr) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Validates the text: 1 to the maximum length, characters `A-Za-z0-9_-` only.
            pub fn new(text: impl Into<String>) -> Result<Self, &'static str> {
                let text = text.into();
                let ok = !text.is_empty()
                    && text.len() <= $max
                    && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
                if ok { Ok(Self(text)) } else { Err(concat!("invalid ", $pattern)) }
            }

            /// The text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $name {
            type Error = &'static str;

            fn try_from(text: String) -> Result<Self, Self::Error> {
                Self::new(text)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }
    };
}

text_id!(
    /// A message id: 1 to 64 characters `A-Za-z0-9_-`, unique among one sender's messages on a
    /// connection (00 section 5.3). Recommended form: the extension uses `e<counter>`, the daemon `d<counter>`.
    MessageId,
    "message id",
    64
);
text_id!(
    /// A fetch stream id: 1 to 32 characters `A-Za-z0-9_-`, chosen by the daemon, unique per connection
    /// while the stream is open.
    StreamId,
    "stream id",
    32
);
text_id!(
    /// An event subscription id: 1 to 32 characters `A-Za-z0-9_-`.
    SubscriptionId,
    "subscription id",
    32
);

/// `chrome.downloads.InterruptReason` (verified 2026-10-05) plus `UNKNOWN` for values an
/// implementation cannot map. Browser-defined spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types, reason = "browser-defined enum spelling")]
pub enum InterruptReason {
    /// The browser could not write the file.
    FILE_FAILED,
    /// Access denied on the target path.
    FILE_ACCESS_DENIED,
    /// No space left.
    FILE_NO_SPACE,
    /// The file name is too long.
    FILE_NAME_TOO_LONG,
    /// The file is too large for the file system.
    FILE_TOO_LARGE,
    /// The browser or an antivirus found a virus: a security decision, never rescued.
    FILE_VIRUS_INFECTED,
    /// A transient file error.
    FILE_TRANSIENT_ERROR,
    /// Blocked by policy: a security decision, never rescued.
    FILE_BLOCKED,
    /// The security check failed: a security decision, never rescued.
    FILE_SECURITY_CHECK_FAILED,
    /// Fewer bytes than expected on resume.
    FILE_TOO_SHORT,
    /// The file hash did not match.
    FILE_HASH_MISMATCH,
    /// Source and target are the same file.
    FILE_SAME_AS_SOURCE,
    /// Generic network failure.
    NETWORK_FAILED,
    /// Network timeout.
    NETWORK_TIMEOUT,
    /// The network disconnected.
    NETWORK_DISCONNECTED,
    /// The server went down.
    NETWORK_SERVER_DOWN,
    /// The request was invalid.
    NETWORK_INVALID_REQUEST,
    /// Generic server failure.
    SERVER_FAILED,
    /// The server does not support ranges.
    SERVER_NO_RANGE,
    /// The server does not have the file (also seen for expired signed URLs).
    SERVER_BAD_CONTENT,
    /// 401.
    SERVER_UNAUTHORIZED,
    /// Certificate problem: Zeus never bypasses certificate errors.
    SERVER_CERT_PROBLEM,
    /// 403.
    SERVER_FORBIDDEN,
    /// The server was unreachable.
    SERVER_UNREACHABLE,
    /// Content-Length mismatch.
    SERVER_CONTENT_LENGTH_MISMATCH,
    /// A cross-origin redirect.
    SERVER_CROSS_ORIGIN_REDIRECT,
    /// The user canceled: never rescued.
    USER_CANCELED,
    /// The browser shut down.
    USER_SHUTDOWN,
    /// The browser crashed.
    CRASH,
    /// A value the implementation could not map (not a browser value).
    UNKNOWN,
}

/// What the extension does with an interrupted download (01 section 8.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RescueOffer {
    /// Offer the user a rescue (automatic prompt).
    Prompt,
    /// Offer, but at low priority (the browser went away; the user may no longer care).
    PromptLowPriority,
    /// Never offer: a security decision, user intent, or an unrescuable request.
    Never,
}

impl InterruptReason {
    /// The rescue decision of 01 section 8.4. `FILE_VIRUS_INFECTED`, `FILE_BLOCKED` and
    /// `FILE_SECURITY_CHECK_FAILED` are **never** rescued (Zeus must not launder a security decision
    /// by downloading elsewhere); neither are `USER_CANCELED`, `SERVER_CERT_PROBLEM`,
    /// `NETWORK_INVALID_REQUEST`, `FILE_SAME_AS_SOURCE` and `UNKNOWN`.
    #[must_use]
    pub const fn rescue_offer(self) -> RescueOffer {
        use InterruptReason as R;
        match self {
            R::FILE_VIRUS_INFECTED
            | R::FILE_BLOCKED
            | R::FILE_SECURITY_CHECK_FAILED
            | R::USER_CANCELED
            | R::SERVER_CERT_PROBLEM
            | R::NETWORK_INVALID_REQUEST
            | R::FILE_SAME_AS_SOURCE
            | R::UNKNOWN => RescueOffer::Never,
            R::SERVER_BAD_CONTENT | R::USER_SHUTDOWN | R::CRASH => RescueOffer::PromptLowPriority,
            _ => RescueOffer::Prompt,
        }
    }

    /// The *hint* class of 01 section 8.4 (the daemon's own probe decides the real class). `None` for
    /// reasons that carry no hint (user intent, local oddities, `UNKNOWN`).
    #[must_use]
    pub const fn hint_class(self) -> Option<zeus_types::ErrorClass> {
        use InterruptReason as R;
        use zeus_types::ErrorClass as C;
        match self {
            R::NETWORK_FAILED
            | R::NETWORK_TIMEOUT
            | R::NETWORK_DISCONNECTED
            | R::NETWORK_SERVER_DOWN
            | R::SERVER_FAILED
            | R::SERVER_UNREACHABLE
            | R::SERVER_CONTENT_LENGTH_MISMATCH
            | R::SERVER_NO_RANGE
            | R::SERVER_CROSS_ORIGIN_REDIRECT
            | R::USER_SHUTDOWN
            | R::CRASH => Some(C::TransientNetwork),
            R::SERVER_UNAUTHORIZED => Some(C::AuthExpired),
            R::SERVER_BAD_CONTENT | R::NETWORK_INVALID_REQUEST | R::SERVER_CERT_PROBLEM => {
                Some(C::Permanent)
            }
            R::FILE_NO_SPACE
            | R::FILE_TRANSIENT_ERROR
            | R::FILE_FAILED
            | R::FILE_ACCESS_DENIED
            | R::FILE_NAME_TOO_LONG
            | R::FILE_TOO_LARGE => Some(C::Disk),
            R::FILE_TOO_SHORT | R::FILE_HASH_MISMATCH => Some(C::Integrity),
            R::FILE_VIRUS_INFECTED | R::FILE_BLOCKED | R::FILE_SECURITY_CHECK_FAILED => {
                Some(C::PolicyDenied)
            }
            // SERVER_FORBIDDEN is ambiguous (rules D1 to D5 decide), the rest carry no hint.
            R::SERVER_FORBIDDEN | R::USER_CANCELED | R::FILE_SAME_AS_SOURCE | R::UNKNOWN => None,
        }
    }
}

/// Request header names the daemon may ask the browser to send in a fetch (02 section 9.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequestHeaderName {
    /// `Accept`.
    Accept,
    /// `Accept-Language`.
    AcceptLanguage,
}

/// Response header names forwarded in `fetch.head` (lowercase). `Set-Cookie` is never visible to
/// scripts and is never forwarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResponseHeaderName {
    /// `accept-ranges`.
    AcceptRanges,
    /// `cache-control`.
    CacheControl,
    /// `cf-mitigated`.
    CfMitigated,
    /// `content-digest`.
    ContentDigest,
    /// `content-disposition`.
    ContentDisposition,
    /// `content-encoding`.
    ContentEncoding,
    /// `content-length`.
    ContentLength,
    /// `content-range`.
    ContentRange,
    /// `content-type`.
    ContentType,
    /// `date`.
    Date,
    /// `etag`.
    Etag,
    /// `last-modified`.
    LastModified,
    /// `repr-digest`.
    ReprDigest,
    /// `retry-after`.
    RetryAfter,
    /// `server`.
    Server,
    /// `www-authenticate`.
    WwwAuthenticate,
}

/// Header names released with session material (02 section 8.1). `User-Agent` is always included
/// separately; no other header is ever released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SessionHeaderName {
    /// `accept-language`.
    #[serde(rename = "accept-language")]
    AcceptLanguage,
    /// `sec-ch-ua`.
    #[serde(rename = "sec-ch-ua")]
    SecChUa,
    /// `sec-ch-ua-mobile`.
    #[serde(rename = "sec-ch-ua-mobile")]
    SecChUaMobile,
    /// `sec-ch-ua-platform`.
    #[serde(rename = "sec-ch-ua-platform")]
    SecChUaPlatform,
}

/// The hard maxima of a connection, announced in `hello.ack` (02 section 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    /// Largest frame the daemon sends (at most 1,000,000).
    pub max_frame_to_extension_bytes: u64,
    /// Largest frame the extension sends (at most 64 MiB; Zeus uses 4 MiB).
    pub max_frame_to_daemon_bytes: u64,
    /// Default raw bytes per `fetch.chunk`.
    pub default_chunk_bytes: u64,
    /// Largest raw bytes per `fetch.chunk` (at most 2 MiB).
    pub max_chunk_bytes: u64,
    /// Default initial credit grant.
    pub default_credit_window: u8,
    /// Largest credit window (at most 32).
    pub max_credit_window: u8,
    /// Concurrent fetch streams (at most 8).
    pub max_concurrent_streams: u8,
    /// Largest range per `fetch.range` (at least 1 MiB; Zeus uses 16 MiB).
    pub max_range_bytes: u64,
    /// Keepalive ping interval.
    pub ping_interval_ms: u64,
    /// How long to wait for a pong.
    pub pong_timeout_ms: u64,
    /// Cookies per session response (at most 150).
    pub max_cookie_count: u32,
    /// Session material time to live (at most 900,000).
    pub max_session_ttl_ms: u64,
}

impl Default for Limits {
    /// The defaults of 02 section 5 and 00 section 10.
    fn default() -> Self {
        Self {
            max_frame_to_extension_bytes: 1_000_000,
            max_frame_to_daemon_bytes: 4_194_304,
            default_chunk_bytes: 262_144,
            max_chunk_bytes: 2_097_152,
            default_credit_window: 8,
            max_credit_window: 32,
            max_concurrent_streams: 4,
            max_range_bytes: 16_777_216,
            ping_interval_ms: 20_000,
            pong_timeout_ms: 5_000,
            max_cookie_count: 150,
            max_session_ttl_ms: 900_000,
        }
    }
}

// ------------------------------------------------------------------------------- session control

/// The browser that connected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloBrowser {
    /// Browser family.
    pub name: BrowserName,
    /// Browser version string.
    pub version: String,
    /// Platform (`win`, `mac`, `linux`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
}

/// Where an extension left off, for event replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloResume {
    /// The highest event sequence the extension processed.
    pub last_event_seq: u64,
}

/// `hello` (extension to daemon): the first frame, always sent with `v = 1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloBody {
    /// Always `zeus-extension`.
    pub client: String,
    /// Self-declared extension id (informational; the attested id from `argv` is authoritative).
    pub extension_id: String,
    /// Extension version (semver).
    pub extension_version: String,
    /// The browser.
    pub browser: HelloBrowser,
    /// The protocol versions the extension speaks.
    pub protocol_versions: Vec<u16>,
    /// The capabilities it implements.
    pub capabilities: Vec<String>,
    /// 32 lowercase hex characters, created once per browser profile; routes browser-bound jobs to the
    /// right cookie jar.
    pub profile_id: String,
    /// 16 to 32 lowercase hex characters identifying this service-worker instance.
    pub sw_instance_id: String,
    /// Event replay position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume: Option<HelloResume>,
}

/// `hello.ack`'s `daemon` member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonIdentity {
    /// Daemon version (semver).
    pub version: String,
    /// 32 lowercase hex characters, new on every daemon start.
    pub instance_id: String,
}

/// `hello.ack`'s `host` member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostIdentity {
    /// Host version (semver).
    pub version: String,
}

/// `hello.ack` (daemon to extension): the negotiated session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloAckBody {
    /// The chosen protocol version: the highest both sides support.
    pub protocol_version: u16,
    /// The intersection of capabilities.
    pub capabilities: Vec<String>,
    /// The daemon.
    pub daemon: DaemonIdentity,
    /// The host.
    pub host: HostIdentity,
    /// Identifies the connection in logs.
    pub connection_id: ConnectionId,
    /// Hard maxima for this connection.
    pub limits: Limits,
    /// The daemon's clock.
    pub server_time: Timestamp,
    /// The newest durable event sequence.
    pub head_seq: u64,
}

/// `ping` payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PingBody {
    /// Optional echo value, at most 32 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// `pong` payload.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PongBody {
    /// The echoed nonce.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
}

/// Why a connection ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ByeReason {
    /// Orderly shutdown.
    Shutdown,
    /// The daemon went away (sent by the host).
    DaemonGone,
    /// The extension is unloading.
    ExtensionUnload,
    /// Too many malformed frames or rate-limit violations.
    ProtocolError,
    /// A newer connection with the same `profile_id` and `sw_instance_id` replaced this one.
    Superseded,
    /// Idle for too long.
    IdleTimeout,
}

/// `bye`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByeBody {
    /// Why.
    pub reason: ByeReason,
    /// Optional human-readable detail, at most 256 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// `error`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// The error envelope.
    pub error: ErrorEnvelope,
}

// ------------------------------------------------------------------------------- handoff

/// `handoff.reject` (daemon to extension): the offer was refused (`handoff.not_eligible`,
/// `handoff.rate_limited`, `policy.origin_never` or `invalid_request`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffRejectBody {
    /// Why.
    pub error: ErrorEnvelope,
}

/// Why a handoff was offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfferTrigger {
    /// The browser download was interrupted.
    Interrupted,
    /// The user forwarded a download from the extension's menu or popup.
    UserInitiated,
}

/// The browser's download item, as far as Zeus needs it. Absolute paths never leave the browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffDownload {
    /// The browser's download id.
    pub browser_download_id: u64,
    /// `DownloadItem.url`: the original URL before redirects (becomes `spec.url`).
    pub url: HttpUrl,
    /// `DownloadItem.finalUrl` after redirects, often signed (becomes `spec.hint_url`).
    pub final_url: HttpUrl,
    /// `DownloadItem.referrer`.
    pub referrer: Option<HttpUrl>,
    /// **Basename only** of `DownloadItem.filename`.
    pub filename: String,
    /// `DownloadItem.mime`.
    pub mime: Option<String>,
    /// Bytes the browser received. Informational: Zeus never trusts bytes the browser wrote.
    pub bytes_received: u64,
    /// Total, with `-1` converted to `null`.
    pub total_bytes: Option<u64>,
    /// `DownloadItem.startTime`.
    pub start_time: Timestamp,
    /// The download is from a private window.
    pub incognito: bool,
    /// `DownloadItem.canResume`.
    pub can_resume: bool,
    /// `DownloadItem.error`, or `null` when `trigger` is `user_initiated`.
    pub interrupt_reason: Option<InterruptReason>,
    /// `DownloadItem.byExtensionId`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_extension_id: Option<String>,
}

/// `handoff.offer`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffOfferBody {
    /// `<browser>:<download id>:<start time>`; the daemon deduplicates by it.
    pub offer_key: String,
    /// Why it was offered.
    pub trigger: OfferTrigger,
    /// The download.
    pub download: HandoffDownload,
    /// Validators, normally `null` (`chrome.downloads` exposes none); a hint the daemon re-probes.
    #[serde(default)]
    pub validators: Option<Validators>,
}

/// `handoff.accept`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffAcceptBody {
    /// The job.
    pub job_id: JobId,
    /// Its state.
    pub state: JobState,
    /// The approval that was raised, if any.
    #[serde(default)]
    pub approval_id: Option<ApprovalId>,
    /// True when the offer repeated an earlier one.
    pub deduplicated: bool,
}

/// Why the extension withdraws an offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawReason {
    /// The browser completed the download.
    CompletedInBrowser,
    /// The browser resumed it successfully.
    ResumedInBrowser,
    /// The user canceled the offer.
    CanceledByUser,
    /// The user erased the download.
    DownloadErased,
}

/// `handoff.withdraw` (notification).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffWithdrawBody {
    /// The job.
    pub job_id: JobId,
    /// The offer.
    pub offer_key: String,
    /// Why.
    pub reason: WithdrawReason,
}

// ------------------------------------------------------------------------------- session oracle

/// `session.request` (daemon to extension).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRequestBody {
    /// The job.
    pub job_id: JobId,
    /// The lease handle the daemon minted; echoed in the response.
    pub session_id: SessionLeaseId,
    /// The grant that covers the request.
    pub grant_id: GrantId,
    /// Must equal the origin of `url`.
    pub origin: Origin,
    /// The URL the daemon will request (used for `cookies.getAll({url})`).
    pub url: HttpUrl,
    /// Why.
    pub purpose: LeasePurpose,
    /// Headers beyond `User-Agent` that may be released.
    pub request_headers: Vec<SessionHeaderName>,
    /// Requested lifetime, at most 900,000.
    pub ttl_ms: u64,
    /// The job came from a private window: use the private cookie store.
    pub incognito: bool,
}

/// `session.response` (extension to daemon): material, or why not.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SessionResponseBody {
    /// Granted: the material for one origin.
    Granted {
        /// The cookies and headers.
        session: SessionMaterial,
    },
    /// The extension holds no consent record for this grant and origin (`session.consent_required`).
    ConsentRequired {
        /// The error.
        error: ErrorEnvelope,
    },
    /// The user denied, or the origin is on a local never-list.
    Denied {
        /// The error.
        error: ErrorEnvelope,
    },
    /// The private cookie store is unknown, or too many concurrent releases.
    Unavailable {
        /// The error.
        error: ErrorEnvelope,
    },
}

impl fmt::Debug for SessionResponseBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Granted { session } => {
                f.debug_struct("Granted").field("session", session).finish()
            }
            Self::ConsentRequired { error } => f
                .debug_struct("ConsentRequired")
                .field("error", error)
                .finish(),
            Self::Denied { error } => f.debug_struct("Denied").field("error", error).finish(),
            Self::Unavailable { error } => {
                f.debug_struct("Unavailable").field("error", error).finish()
            }
        }
    }
}

/// The document representation requested by a workflow; never arbitrary request headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PageRepresentation {
    /// HTML document, including XHTML.
    Html,
    /// JSON document or API page.
    Json,
    /// XML document, such as a sitemap.
    Xml,
    /// Plain text.
    Text,
}

impl PageRepresentation {
    /// The fixed Accept header associated with this representation.
    #[must_use]
    pub const fn accept(self) -> &'static str {
        match self {
            Self::Html => "text/html, application/xhtml+xml",
            Self::Json => "application/json",
            Self::Xml => "application/xml, text/xml",
            Self::Text => "text/plain",
        }
    }
}

/// Maximum decoded bytes returned in one authenticated workflow document.
pub const MAX_PAGE_BODY_BYTES: usize = 524_288;

/// The durable subject of a browser page read. Plan sampling and execution never share authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "purpose", rename_all = "snake_case")]
pub enum SessionPageSubject {
    /// Bounded sampling under an explicit site grant, owned by the authenticated requester.
    Plan {
        /// The application's durable `plan_` ULID; the core does not depend on its plan IR.
        plan_id: String,
    },
    /// Execution under the human approval and workflow grant for this exact run.
    Run {
        /// The run the grant covers.
        run_id: RunId,
    },
}

impl SessionPageSubject {
    /// Validate the subject identifier without interpreting application state or granting access.
    #[must_use]
    pub fn valid(&self) -> bool {
        match self {
            Self::Run { .. } => true,
            Self::Plan { plan_id } => plan_id.strip_prefix("plan_").is_some_and(|id| {
                id.len() == 26
                    && id.starts_with(|c: char| ('0'..='7').contains(&c))
                    && id
                        .bytes()
                        .all(|b| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&b))
            }),
        }
    }
}

/// `session.page.request`: read a document in the browser without exporting session material.
/// Both sides require the negotiated `session.page` capability and an exact live grant.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPageRequestBody {
    /// Exact owned plan or approved run; a job id is never substituted for either.
    pub subject: SessionPageSubject,
    /// Human-created site grant for sampling, or workflow grant for the exact run and origin.
    pub grant_id: GrantId,
    /// The profile that recorded the extension's human consent.
    pub profile_id: String,
    /// Must equal the URL origin and the grant origin.
    pub origin: Origin,
    /// Same-origin document URL. Redirects are refused by this capability.
    pub url: HttpUrl,
    /// Fixed representation; no caller-supplied authorization or other headers.
    pub representation: PageRepresentation,
    /// Decoded body ceiling, at most `MAX_PAGE_BODY_BYTES`.
    pub max_body_bytes: u32,
    /// Entire request deadline, from 1000 through 25000 milliseconds.
    pub deadline_ms: u32,
    /// Private browsing requires an explicitly supported private context; never falls back.
    #[serde(default)]
    pub incognito: bool,
}

impl fmt::Debug for SessionPageRequestBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionPageRequest([PRIVATE])")
    }
}

/// Cancel only the page request correlated to this daemon message on this connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPageCancelBody {
    /// Original `session.page.request` message ID; never a new authority or another connection.
    pub request_id: MessageId,
}

impl SessionPageRequestBody {
    /// Check public structural bounds before any browser or network operation.
    #[must_use]
    pub fn valid_bounds(&self) -> bool {
        self.url.origin() == self.origin
            && self.url.url().fragment().is_none()
            && self.subject.valid()
            && self.profile_id.len() == 32
            && self
                .profile_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && (1..=MAX_PAGE_BODY_BYTES as u32).contains(&self.max_body_bytes)
            && (1_000..=25_000).contains(&self.deadline_ms)
    }
}

/// A bounded authenticated document. Debug omits its body, headers and private URL.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionPageDocument {
    /// Echoed plan/run identity.
    pub subject: SessionPageSubject,
    /// Echoed grant identity.
    pub grant_id: GrantId,
    /// Profile that actually fetched the document.
    pub profile_id: String,
    /// Actual final URL, checked against the exact request before publication.
    pub final_url: HttpUrl,
    /// HTTP response status; redirects are not followed.
    pub http_status: u16,
    /// Bounded declared content type.
    pub content_type: String,
    /// Optional pagination Link header; all other response headers stay in the browser.
    pub link: Option<String>,
    /// Decoded body bytes; memory is cleared on drop and Debug never exposes their content.
    pub data: ChunkData,
    /// Browser observation time, used only to reject stale responses.
    pub issued_at: Timestamp,
}

impl SessionPageDocument {
    /// Bind a response to its exact request after the daemon rechecks current grant authority.
    #[must_use]
    pub fn matches_request(&self, request: &SessionPageRequestBody, now: Timestamp) -> bool {
        request.valid_bounds()
            && self.subject == request.subject
            && self.grant_id == request.grant_id
            && self.profile_id == request.profile_id
            && self.final_url == request.url
            && (100..=599).contains(&self.http_status)
            && !(300..=399).contains(&self.http_status)
            && self.content_type.len() <= 256
            && page_content_type(&self.content_type)
            && !self.content_type.chars().any(char::is_control)
            && self
                .link
                .as_ref()
                .is_none_or(|v| v.len() <= 4096 && !v.chars().any(char::is_control))
            && self.data.len() <= request.max_body_bytes as usize
            && self.issued_at <= now.saturating_add_ms(5_000)
            && now
                .unix_millis()
                .saturating_sub(self.issued_at.unix_millis())
                <= i64::from(request.deadline_ms)
    }
}

fn page_content_type(value: &str) -> bool {
    let mime = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    matches!(
        mime.as_str(),
        "text/html"
            | "application/xhtml+xml"
            | "text/plain"
            | "application/json"
            | "application/xml"
            | "text/xml"
    ) || mime.strip_prefix("application/").is_some_and(|subtype| {
        (subtype.ends_with("+json") || subtype.ends_with("+xml"))
            && subtype
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b))
    })
}

impl fmt::Debug for SessionPageDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionPageDocument([PRIVATE])")
    }
}

/// `session.page.response`: bounded document data or a stable refusal; never cookies or tokens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SessionPageResponseBody {
    /// Document fetched after browser and daemon consent checks.
    Fetched {
        /// Exact response binding and private payload.
        document: Box<SessionPageDocument>,
    },
    /// Request refused or unavailable; error text never contains page data or private URLs.
    Unavailable {
        /// Stable existing session/fetch error code.
        error: ErrorEnvelope,
    },
}

/// How the extension may derive a fresh URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshMethod {
    /// `fetch(origin_url)` with the user's cookies and read `response.url`.
    Refetch,
    /// `chrome.downloads.download` then cancel, reading `finalUrl`.
    DownloadApi,
}

/// Why the daemon asks for a fresh URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshReason {
    /// The signed URL expired.
    UrlExpired,
    /// The session expired.
    AuthExpired,
    /// The engine was blocked.
    Blocked,
}

/// What the daemon already knows about the resource, so the extension can sanity-check the refresh.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshExpected {
    /// Expected total size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    /// Expected entity tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// Expected file name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

/// `url.refresh.request` (daemon to extension).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlRefreshRequestBody {
    /// The job.
    pub job_id: JobId,
    /// The origin whose session applies.
    pub origin: Origin,
    /// The stable URL (`spec.url`) to refetch.
    pub origin_url: HttpUrl,
    /// The URL that failed.
    pub stale_url: HttpUrl,
    /// Why.
    pub reason: RefreshReason,
    /// Methods the extension may use, in preference order.
    pub methods: Vec<RefreshMethod>,
    /// Known facts about the resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<RefreshExpected>,
    /// How long the extension has, 1000 to 60000 ms.
    pub deadline_ms: u64,
}

/// `url.refresh.response` (extension to daemon).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[allow(
    clippy::large_enum_variant,
    reason = "short-lived protocol message; boxing the common variant would only add noise"
)]
pub enum UrlRefreshResponseBody {
    /// A new URL.
    Refreshed {
        /// The stable URL.
        url: HttpUrl,
        /// The fresh (signed) URL.
        final_url: HttpUrl,
        /// How it was obtained.
        method: RefreshMethod,
        /// Validators seen, if any.
        #[serde(default)]
        validators: Option<Validators>,
        /// Total size seen, if any.
        #[serde(default)]
        total_bytes: Option<u64>,
    },
    /// The browser obtained the same URL: expiry was not the cause.
    Unchanged {},
    /// The extension could not refresh.
    CannotRefresh {
        /// `url.refresh_failed`, `url.login_required`, `url.refresh_unsupported`,
        /// `session.consent_required` or `fetch.cross_origin_denied`.
        error: ErrorEnvelope,
    },
}

// ------------------------------------------------------------------------------- in-browser fetch

/// The byte range of a fetch (half-open, 00 section 6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchRange {
    /// First byte.
    pub offset: u64,
    /// Number of bytes, at most `limits.max_range_bytes`.
    pub length: u64,
}

/// `fetch.range` (daemon to extension).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchRangeBody {
    /// The stream.
    pub stream_id: StreamId,
    /// The job.
    pub job_id: JobId,
    /// The URL to fetch; its origin must equal `origin`.
    pub url: HttpUrl,
    /// The origin whose consent applies.
    pub origin: Origin,
    /// The range, or `null` for the whole resource.
    pub range: Option<FetchRange>,
    /// A strong validator for `If-Range`; absent for weak or missing validators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub if_range: Option<String>,
    /// Only `accept` and `accept-language`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub request_headers: BTreeMap<RequestHeaderName, String>,
    /// Raw bytes per chunk, 1024 to `max_chunk_bytes`.
    pub chunk_bytes: u32,
    /// Initial credit grant, 1 to `max_credit_window`.
    pub credits: u8,
    /// Time allowed until response headers arrive, 1000 to 60000 ms; the extension aborts at 25 s.
    pub deadline_ms: u64,
}

/// `fetch.head` (extension to daemon): the response head; the daemon classifies the status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchHeadBody {
    /// The stream.
    pub stream_id: StreamId,
    /// The HTTP status as received.
    pub status: u16,
    /// The final URL after redirects.
    pub final_url: HttpUrl,
    /// Whether a redirect was followed.
    pub redirected: bool,
    /// The forwarded response headers (lowercase names).
    pub headers: BTreeMap<ResponseHeaderName, String>,
}

/// Base64 payload of a chunk: standard alphabet with padding (RFC 4648 section 4). Holds the decoded
/// bytes; `Debug` shows the length only, and the memory is wiped on drop because downloaded bytes
/// from an authenticated session are sensitive.
#[derive(Clone, PartialEq, Eq)]
pub struct ChunkData(zeroize::Zeroizing<Vec<u8>>);

impl ChunkData {
    /// Wraps raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    /// The raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Number of raw bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for ChunkData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkData({} bytes)", self.0.len())
    }
}

impl Serialize for ChunkData {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use base64::Engine as _;
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(self.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for ChunkData {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use base64::Engine as _;
        let text = std::borrow::Cow::<str>::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(text.as_bytes())
            .map(Self::new)
            .map_err(|_| serde::de::Error::custom("chunk data is not canonical base64"))
    }
}

/// `fetch.chunk` (extension to daemon).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchChunkBody {
    /// The stream.
    pub stream_id: StreamId,
    /// 0, 1, 2, ... consecutive per stream.
    pub index: u64,
    /// Absolute offset in the resource of the first byte.
    pub offset: u64,
    /// Raw (decoded) length; must equal the decoded length of `data`.
    pub length: u32,
    /// The bytes.
    pub data: ChunkData,
}

impl FetchChunkBody {
    /// True when `length` equals the decoded length of `data` (a mismatch is
    /// `nm.stream_protocol_violation`).
    #[must_use]
    pub fn length_matches(&self) -> bool {
        usize::try_from(self.length).is_ok_and(|n| n == self.data.len())
    }
}

/// `fetch.credit` (daemon to extension).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchCreditBody {
    /// The stream.
    pub stream_id: StreamId,
    /// Credits added, 1 to `max_credit_window`. One credit permits one `fetch.chunk`.
    pub credits: u8,
}

/// How a stream ended normally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchEndReason {
    /// All bytes of the range were sent.
    Complete,
    /// The extension aborted after `fetch.cancel`.
    Canceled,
}

/// `fetch.end` (extension to daemon).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchEndBody {
    /// The stream.
    pub stream_id: StreamId,
    /// Why it ended.
    pub reason: FetchEndReason,
    /// Chunks sent.
    pub chunks: u64,
    /// Raw bytes sent.
    pub bytes: u64,
}

/// `fetch.error` (extension to daemon).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchErrorBody {
    /// The stream.
    pub stream_id: StreamId,
    /// `fetch.network_error`, `fetch.timeout`, `fetch.body_error`, `fetch.aborted`,
    /// `fetch.content_encoded`, `fetch.cross_origin_denied`, `fetch.extension_busy`,
    /// `session.consent_required` or `session.origin_mismatch`.
    pub error: ErrorEnvelope,
    /// Raw bytes sent before the error.
    pub bytes: u64,
}

/// Why the daemon cancels a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FetchCancelReason {
    /// The job was canceled.
    JobCanceled,
    /// The job was paused.
    JobPaused,
    /// The daemon replans (a non-2xx head, hedging, reordering).
    Superseded,
    /// The daemon is shutting down.
    Shutdown,
    /// The extension broke the stream protocol.
    ProtocolViolation,
}

/// `fetch.cancel` (daemon to extension, notification).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchCancelBody {
    /// The stream.
    pub stream_id: StreamId,
    /// Why.
    pub reason: FetchCancelReason,
}

// ------------------------------------------------------------------------------- trust surface

/// `approval.list` (extension to daemon).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalListBody {
    /// Only these states; default pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub states: Option<Vec<ApprovalState>>,
    /// Page size, at most 100.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Continuation cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// `approval.list.response`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalListResponseBody {
    /// At most 100 approvals.
    pub approvals: Vec<Approval>,
    /// Continuation cursor.
    pub next_cursor: Option<String>,
}

/// `approval.pending` (daemon to extension, notification).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalPendingBody {
    /// The approval, with daemon-computed facts.
    pub approval: Approval,
}

/// The human's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// Approve.
    Approve,
    /// Deny.
    Deny,
}

/// The extension surfaces that may carry a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionSurface {
    /// The popup.
    ExtensionPopup,
    /// The options page.
    ExtensionOptions,
    /// The side panel.
    ExtensionSidepanel,
    /// A notification button.
    ExtensionNotification,
}

/// The gesture attestation of a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecideUi {
    /// Where the click happened.
    pub surface: ExtensionSurface,
    /// Must be `true`; the daemon rejects anything else (`nm.user_gesture_required`).
    pub user_gesture: bool,
}

/// `approval.decide` (extension to daemon).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecideBody {
    /// The approval.
    pub approval_id: ApprovalId,
    /// BLAKE3 of the exact facts displayed to the human.
    pub request_hash: zeus_types::Hex256,
    /// Confirmation strength used by the trust surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation: Option<ConfirmationLevel>,
    /// Approve or deny.
    pub decision: Decision,
    /// The scope chosen (must be in `allowed_scopes` for approve; may be `never` or absent for deny).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<GrantScope>,
    /// The attestation.
    pub ui: DecideUi,
}

/// Human confirmation strength, ordered by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationLevel {
    /// Click or key press after the mandatory display delay.
    Gesture,
    /// Typed binding code.
    TypedCode,
    /// Operating-system user verification.
    OsAuth,
}
/// Native kill-switch action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchAction {
    /// Stop agent work and revoke grants.
    Engage,
    /// Re-enable admission after a human review.
    Release,
}
/// `kill_switch` from a trusted extension surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchBody {
    /// Requested action.
    pub action: KillSwitchAction,
    /// Human gesture evidence.
    pub ui: DecideUi,
    /// Optional human explanation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}
/// `kill_switch.response` after the durable sweep.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchResponseBody {
    /// Current latch state.
    pub engaged: bool,
    /// Whether the latch changed.
    pub changed: bool,
    /// Grants revoked.
    pub grants_revoked: u64,
    /// Jobs paused.
    pub jobs_paused: u64,
    /// Pending approvals.
    pub approvals_pending: u64,
    /// Whether this response is an idempotent replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replayed: Option<bool>,
}

/// `approval.decide.response`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDecideResponseBody {
    /// The updated approval.
    pub approval: Approval,
    /// The grant the decision created, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<SessionGrant>,
}

/// Which jobs a subscription covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscribeScope {
    /// Every job (the popup shows agent downloads too).
    All,
    /// Only jobs of this connection's browser profile.
    Own,
}

/// `events.subscribe` (extension to daemon).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsSubscribeBody {
    /// Replay durable events with a larger `seq`; absent for live only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_seq: Option<u64>,
    /// Filter by event name; absent for all permitted events (never `session.leased`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub types: Option<Vec<String>>,
    /// Deliver the ephemeral `job.progress` events.
    pub include_progress: bool,
    /// At least 1000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_interval_ms: Option<u32>,
    /// Which jobs.
    pub scope: SubscribeScope,
}

/// `events.subscribe.response`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsSubscribeResponseBody {
    /// The subscription.
    pub subscription_id: SubscriptionId,
    /// The newest durable sequence.
    pub head_seq: u64,
    /// Events that will be replayed before live ones.
    pub replay_count: u64,
    /// Older events were pruned: call `job.list`.
    pub replay_truncated: bool,
}

/// `events.unsubscribe` (notification).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsUnsubscribeBody {
    /// The subscription.
    pub subscription_id: SubscriptionId,
}

/// `job.event` (daemon to extension, notification).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobEventBody {
    /// The subscription.
    pub subscription_id: SubscriptionId,
    /// The event.
    pub event: Event,
}

/// `job.list`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobListBody {
    /// Only these states.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub states: Option<Vec<JobState>>,
    /// Page size, at most 100.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Continuation cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// `job.list.response`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobListResponseBody {
    /// At most 100 jobs.
    pub jobs: Vec<JobSummary>,
    /// Continuation cursor.
    pub next_cursor: Option<String>,
}

/// What a human may do to a job from the popup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobControlAction {
    /// Pause.
    Pause,
    /// Resume.
    Resume,
    /// Cancel.
    Cancel,
    /// Retry a failed job.
    Retry,
}

/// `job.control`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobControlBody {
    /// The job.
    pub job_id: JobId,
    /// The action.
    pub action: JobControlAction,
}

/// `job.control.response`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobControlResponseBody {
    /// The job after the action.
    pub job: JobSummary,
}

/// `grant.list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantListBody {
    /// Include expired, revoked and consumed grants.
    pub include_inactive: bool,
    /// At most 100.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// `grant.list.response`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantListResponseBody {
    /// At most 100 grants.
    pub grants: Vec<SessionGrant>,
}

/// `grant.revoke`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRevokeBody {
    /// The grant.
    pub grant_id: GrantId,
}

/// `grant.revoke.response`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRevokeResponseBody {
    /// The revoked grant.
    pub grant: SessionGrant,
}

// ------------------------------------------------------------------------------- the catalogue

/// Implemented by the two body enums so [`Message`] can encode and decode them.
pub trait MessageBody: Sized {
    /// The wire `type` string of this body.
    fn type_name(&self) -> &'static str;

    /// Serialises the body object.
    fn to_value(&self) -> Result<Value, serde_json::Error>;

    /// Builds the typed body for a `type` string, or `None` when the type is not in this direction's
    /// catalogue.
    fn from_value(type_name: &str, body: Value) -> Option<Result<Self, serde_json::Error>>;

    /// True for message types that expect a reply (kind Q in 02 section 6.2): an unknown type that
    /// looks like a request gets an error, an unknown notification is ignored.
    fn is_request(&self) -> bool;
}

macro_rules! body_enum {
    ($(#[$meta:meta])* $name:ident { $( $variant:ident($ty:ty) = $tag:literal, request: $req:literal; )* }) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        #[non_exhaustive]
        #[allow(clippy::large_enum_variant, reason = "short-lived protocol messages; boxing every body would only add noise")]
        pub enum $name {
            $( #[doc = concat!("`", $tag, "`.")] $variant($ty), )*
        }

        impl MessageBody for $name {
            fn type_name(&self) -> &'static str {
                match self { $( Self::$variant(_) => $tag, )* }
            }

            fn to_value(&self) -> Result<Value, serde_json::Error> {
                match self { $( Self::$variant(b) => serde_json::to_value(b), )* }
            }

            fn from_value(type_name: &str, body: Value) -> Option<Result<Self, serde_json::Error>> {
                match type_name {
                    $( $tag => Some(serde_json::from_value::<$ty>(body).map(Self::$variant)), )*
                    _ => None,
                }
            }

            fn is_request(&self) -> bool {
                match self { $( Self::$variant(_) => $req, )* }
            }
        }

        impl $name {
            /// Every `type` string of this direction.
            pub const TYPES: &'static [&'static str] = &[ $( $tag, )* ];
        }

        $( impl From<$ty> for $name { fn from(body: $ty) -> Self { Self::$variant(body) } } )*
    };
}

body_enum! {
    /// Messages sent by the extension to the daemon.
    ExtensionBody {
        Hello(HelloBody) = "hello", request: true;
        Ping(PingBody) = "ping", request: true;
        Pong(PongBody) = "pong", request: false;
        Bye(ByeBody) = "bye", request: false;
        Error(ErrorBody) = "error", request: false;
        HandoffOffer(HandoffOfferBody) = "handoff.offer", request: true;
        HandoffWithdraw(HandoffWithdrawBody) = "handoff.withdraw", request: false;
        SessionResponse(SessionResponseBody) = "session.response", request: false;
        SessionPageResponse(SessionPageResponseBody) = "session.page.response", request: false;
        UrlRefreshResponse(UrlRefreshResponseBody) = "url.refresh.response", request: false;
        FetchHead(FetchHeadBody) = "fetch.head", request: false;
        FetchChunk(FetchChunkBody) = "fetch.chunk", request: false;
        FetchEnd(FetchEndBody) = "fetch.end", request: false;
        FetchError(FetchErrorBody) = "fetch.error", request: false;
        ApprovalList(ApprovalListBody) = "approval.list", request: true;
        KillSwitch(KillSwitchBody) = "kill_switch", request: true;
        ApprovalDecide(ApprovalDecideBody) = "approval.decide", request: true;
        EventsSubscribe(EventsSubscribeBody) = "events.subscribe", request: true;
        EventsUnsubscribe(EventsUnsubscribeBody) = "events.unsubscribe", request: false;
        JobList(JobListBody) = "job.list", request: true;
        JobControl(JobControlBody) = "job.control", request: true;
        GrantList(GrantListBody) = "grant.list", request: true;
        GrantRevoke(GrantRevokeBody) = "grant.revoke", request: true;
    }
}

body_enum! {
    /// Messages sent by the daemon to the extension.
    DaemonBody {
        HelloAck(HelloAckBody) = "hello.ack", request: false;
        Ping(PingBody) = "ping", request: true;
        Pong(PongBody) = "pong", request: false;
        Bye(ByeBody) = "bye", request: false;
        Error(ErrorBody) = "error", request: false;
        HandoffAccept(HandoffAcceptBody) = "handoff.accept", request: false;
        HandoffReject(HandoffRejectBody) = "handoff.reject", request: false;
        SessionRequest(SessionRequestBody) = "session.request", request: true;
        SessionPageRequest(SessionPageRequestBody) = "session.page.request", request: true;
        SessionPageCancel(SessionPageCancelBody) = "session.page.cancel", request: false;
        UrlRefreshRequest(UrlRefreshRequestBody) = "url.refresh.request", request: true;
        FetchRange(FetchRangeBody) = "fetch.range", request: true;
        FetchCredit(FetchCreditBody) = "fetch.credit", request: false;
        FetchCancel(FetchCancelBody) = "fetch.cancel", request: false;
        ApprovalListResponse(ApprovalListResponseBody) = "approval.list.response", request: false;
        ApprovalPending(ApprovalPendingBody) = "approval.pending", request: false;
        KillSwitchResponse(KillSwitchResponseBody) = "kill_switch.response", request: false;
        ApprovalDecideResponse(ApprovalDecideResponseBody) = "approval.decide.response", request: false;
        EventsSubscribeResponse(EventsSubscribeResponseBody) = "events.subscribe.response", request: false;
        JobEvent(JobEventBody) = "job.event", request: false;
        JobListResponse(JobListResponseBody) = "job.list.response", request: false;
        JobControlResponse(JobControlResponseBody) = "job.control.response", request: false;
        GrantListResponse(GrantListResponseBody) = "grant.list.response", request: false;
        GrantRevokeResponse(GrantRevokeResponseBody) = "grant.revoke.response", request: false;
    }
}

/// One frame: the envelope around a typed body.
#[derive(Debug, Clone)]
pub struct Message<B> {
    /// Protocol version of this message; `1`.
    pub v: u16,
    /// The sender's message id.
    pub id: MessageId,
    /// On a response: the id of the request it answers.
    pub re: Option<MessageId>,
    /// The typed body.
    pub body: B,
}

/// A frame from the extension.
pub type ExtensionMessage = Message<ExtensionBody>;
/// A frame from the daemon.
pub type DaemonMessage = Message<DaemonBody>;

impl<B: MessageBody> Message<B> {
    /// A message at the current protocol version.
    #[must_use]
    pub fn new(id: MessageId, body: impl Into<B>) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            re: None,
            body: body.into(),
        }
    }

    /// A response to `request`.
    #[must_use]
    pub fn reply_to(request: &MessageId, id: MessageId, body: impl Into<B>) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            id,
            re: Some(request.clone()),
            body: body.into(),
        }
    }

    /// The envelope as a JSON object.
    pub fn to_json(&self) -> Result<Value, serde_json::Error> {
        let mut obj = Map::new();
        obj.insert("v".into(), Value::from(self.v));
        obj.insert("id".into(), Value::String(self.id.as_str().to_owned()));
        if let Some(re) = &self.re {
            obj.insert("re".into(), Value::String(re.as_str().to_owned()));
        }
        obj.insert(
            "type".into(),
            Value::String(self.body.type_name().to_owned()),
        );
        obj.insert("body".into(), self.body.to_value()?);
        Ok(Value::Object(obj))
    }

    /// The envelope as JSON bytes, ready for [`crate::codec::encode_frame`].
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&self.to_json()?)
    }

    /// Decodes a parsed JSON object (02 section 6.4): the envelope fields are validated first so an
    /// error can carry `re`; then the body is built for the `type`.
    pub fn from_json(value: Value) -> Result<Self, DecodeError> {
        let schema = |message: &str, id: Option<String>| DecodeError::Schema {
            message: message.to_owned(),
            id,
        };
        let Value::Object(mut obj) = value else {
            return Err(schema("a frame must be a JSON object", None));
        };
        let id_text = obj.get("id").and_then(Value::as_str).map(str::to_owned);
        let readable_id = id_text
            .clone()
            .filter(|s| MessageId::new(s.clone()).is_ok());
        let Some(type_name) = obj.get("type").and_then(Value::as_str).map(str::to_owned) else {
            return Err(schema("missing or non-string `type`", readable_id));
        };
        let Some(id) = id_text.and_then(|s| MessageId::new(s).ok()) else {
            return Err(schema("missing or invalid `id`", None));
        };
        let v = match obj
            .get("v")
            .and_then(Value::as_u64)
            .and_then(|n| u16::try_from(n).ok())
        {
            Some(v) if v >= 1 => v,
            _ => {
                return Err(schema(
                    "missing or invalid `v`",
                    Some(id.as_str().to_owned()),
                ));
            }
        };
        let re = match obj.remove("re") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => Some(
                MessageId::new(s)
                    .map_err(|_| schema("invalid `re`", Some(id.as_str().to_owned())))?,
            ),
            Some(_) => return Err(schema("invalid `re`", Some(id.as_str().to_owned()))),
        };
        let body_value = obj
            .remove("body")
            .unwrap_or_else(|| Value::Object(Map::new()));
        if !body_value.is_object() {
            return Err(schema(
                "`body` must be an object",
                Some(id.as_str().to_owned()),
            ));
        }
        match B::from_value(&type_name, body_value) {
            None => Err(DecodeError::UnknownType {
                type_name,
                id: Some(id.as_str().to_owned()),
            }),
            Some(Err(e)) => Err(DecodeError::Schema {
                message: format!("invalid body for `{type_name}`: {}", short(&e)),
                id: Some(id.as_str().to_owned()),
            }),
            Some(Ok(body)) => Ok(Self { v, id, re, body }),
        }
    }

    /// Decodes JSON bytes: not JSON is a schema error without an id.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let value: Value = serde_json::from_slice(bytes).map_err(|_| DecodeError::Schema {
            message: "payload is not JSON".into(),
            id: None,
        })?;
        Self::from_json(value)
    }
}

impl<B: MessageBody> Serialize for Message<B> {
    /// Serialises the envelope. For [`ExtensionMessage`] this includes session material in clear when the
    /// body is a granted `session.response`; only the extension (and test doubles of it) ever serialises
    /// that message.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_json()
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl<'de, B: MessageBody> Deserialize<'de> for Message<B> {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        Self::from_json(value).map_err(serde::de::Error::custom)
    }
}

/// An error message without the offending values (serde errors can quote input).
fn short(e: &serde_json::Error) -> String {
    use serde_json::error::Category;
    match e.classify() {
        Category::Data => "a field is missing or has the wrong type".to_owned(),
        Category::Syntax | Category::Eof => "malformed JSON".to_owned(),
        Category::Io => "I/O error".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_validate() {
        assert!(MessageId::new("e1").is_ok());
        assert!(MessageId::new("").is_err());
        assert!(MessageId::new("a".repeat(65)).is_err());
        assert!(MessageId::new("bad id").is_err());
        assert!(StreamId::new("s1").is_ok());
        assert!(StreamId::new("s".repeat(33)).is_err());
        assert!(serde_json::from_str::<MessageId>("\"has space\"").is_err());
    }

    #[test]
    fn rescue_offers_follow_the_interrupt_table() {
        use InterruptReason as R;
        for never in [
            R::FILE_VIRUS_INFECTED,
            R::FILE_BLOCKED,
            R::FILE_SECURITY_CHECK_FAILED,
            R::USER_CANCELED,
            R::SERVER_CERT_PROBLEM,
            R::NETWORK_INVALID_REQUEST,
        ] {
            assert_eq!(never.rescue_offer(), RescueOffer::Never, "{never:?}");
        }
        for low in [R::SERVER_BAD_CONTENT, R::USER_SHUTDOWN, R::CRASH] {
            assert_eq!(
                low.rescue_offer(),
                RescueOffer::PromptLowPriority,
                "{low:?}"
            );
        }
        for prompt in [
            R::NETWORK_DISCONNECTED,
            R::SERVER_NO_RANGE,
            R::SERVER_UNAUTHORIZED,
            R::SERVER_FORBIDDEN,
            R::FILE_NO_SPACE,
            R::FILE_HASH_MISMATCH,
        ] {
            assert_eq!(prompt.rescue_offer(), RescueOffer::Prompt, "{prompt:?}");
        }
        assert_eq!(R::SERVER_FORBIDDEN.hint_class(), None);
        assert_eq!(
            R::NETWORK_DISCONNECTED.hint_class(),
            Some(zeus_types::ErrorClass::TransientNetwork)
        );
    }

    #[test]
    fn unknown_types_and_bad_bodies_are_distinguished() {
        let unknown = serde_json::json!({"v": 1, "id": "e9", "type": "future.thing", "body": {}});
        let err = ExtensionMessage::from_json(unknown).unwrap_err();
        assert!(
            matches!(&err, DecodeError::UnknownType { type_name, id } if type_name == "future.thing" && id.as_deref() == Some("e9"))
        );
        let bad = serde_json::json!({"v": 1, "id": "e9", "type": "ping", "body": {"nonce": 7}});
        let err = ExtensionMessage::from_json(bad).unwrap_err();
        assert!(matches!(err, DecodeError::Schema { id: Some(_), .. }));
        let not_object = serde_json::json!([1, 2]);
        assert!(matches!(
            ExtensionMessage::from_json(not_object),
            Err(DecodeError::Schema { id: None, .. })
        ));
        let no_type = serde_json::json!({"v": 1, "id": "e1", "body": {}});
        assert!(matches!(
            ExtensionMessage::from_json(no_type),
            Err(DecodeError::Schema { id: Some(_), .. })
        ));
    }

    #[test]
    fn catalogue_sizes_match_the_schema_unions() {
        assert_eq!(ExtensionBody::TYPES.len(), 23);
        assert_eq!(DaemonBody::TYPES.len(), 24);
    }

    #[test]
    fn page_documents_bind_the_subject_profile_deadline_and_private_body() {
        let ids = zeus_types::IdGenerator::new();
        let now = Timestamp::now();
        let request = SessionPageRequestBody {
            subject: SessionPageSubject::Run {
                run_id: ids.run_id(),
            },
            grant_id: ids.grant_id(),
            profile_id: "a".repeat(32),
            origin: Origin::parse("https://portal.example").unwrap(),
            url: HttpUrl::parse("https://portal.example/page?private=ZEUS-CANARY-query").unwrap(),
            representation: PageRepresentation::Html,
            max_body_bytes: 128,
            deadline_ms: 5_000,
            incognito: false,
        };
        let document = SessionPageDocument {
            subject: request.subject.clone(),
            grant_id: request.grant_id,
            profile_id: request.profile_id.clone(),
            final_url: request.url.clone(),
            http_status: 200,
            content_type: "text/html".into(),
            link: None,
            data: ChunkData::new(b"ZEUS-CANARY-page".to_vec()),
            issued_at: now,
        };
        assert!(request.valid_bounds());
        assert!(document.matches_request(&request, now));
        assert!(!format!("{document:?}").contains("ZEUS-CANARY"));
        let mut other = document.clone();
        other.subject = SessionPageSubject::Run {
            run_id: ids.run_id(),
        };
        assert!(!other.matches_request(&request, now));
        other = document.clone();
        other.profile_id = "b".repeat(32);
        assert!(!other.matches_request(&request, now));
        other = document.clone();
        other.final_url = HttpUrl::parse("https://portal.example/other").unwrap();
        assert!(!other.matches_request(&request, now));
        other = document.clone();
        other.data = ChunkData::new(vec![0; 129]);
        assert!(!other.matches_request(&request, now));
        assert!(!document.matches_request(&request, now.saturating_add_ms(5_001)));
        for id in ["plan_invalid", "plan_Z1M45NHJ2AHWMXT8JVJ7BEEJ01"] {
            assert!(!SessionPageSubject::Plan { plan_id: id.into() }.valid());
        }
    }

    #[test]
    fn a_message_round_trips_and_a_response_carries_re() {
        let req = ExtensionMessage::new(
            MessageId::new("e1").unwrap(),
            PingBody {
                nonce: Some("n".into()),
            },
        );
        let bytes = req.to_json_bytes().unwrap();
        let back = ExtensionMessage::from_json_bytes(&bytes).unwrap();
        assert_eq!(
            (back.v, back.id.as_str(), back.re.is_none()),
            (1, "e1", true)
        );
        assert!(
            matches!(back.body, ExtensionBody::Ping(PingBody { nonce: Some(ref n) }) if n == "n")
        );
        let pong =
            DaemonMessage::reply_to(&req.id, MessageId::new("d1").unwrap(), PongBody::default());
        let json = pong.to_json().unwrap();
        assert_eq!(json["re"], "e1");
        assert_eq!(json["type"], "pong");
    }
}
