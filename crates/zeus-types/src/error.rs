//! The error envelope, error classes and the registry of stable error codes (00 section 9, 01 section 8).
//!
//! Codes are machine strings (`<namespace>.<reason>`), never translated and never reused for a
//! different meaning. Every code maps to exactly one [`ErrorClass`]; the registry in
//! [`REGISTRY`] is the single place that mapping lives for the Rust side.

use std::borrow::Cow;
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::limits::{MAX_ERROR_DETAILS_BYTES, MAX_ERROR_MESSAGE_CHARS};

/// Failure to construct or parse one of this crate's validated types.
///
/// Messages never include the offending value: it may be a URL carrying secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TypesError {
    /// An identifier did not match the pattern of its kind.
    #[error("invalid {kind} identifier")]
    InvalidId {
        /// Type name, for example `JobId`.
        kind: &'static str,
    },
    /// A timestamp was not RFC 3339 or was outside the representable range.
    #[error("invalid timestamp")]
    InvalidTimestamp,
    /// A URL was not an absolute http(s) URL within the size limit.
    #[error("invalid URL: {reason}")]
    InvalidUrl {
        /// Static reason, never the URL itself.
        reason: &'static str,
    },
    /// A URL used a scheme other than `http` or `https`: rejected with `policy.scheme_not_allowed`
    /// (01 section 3.2). See [`TypesError::policy_envelope`].
    #[error("URL scheme is not http or https")]
    SchemeNotAllowed,
    /// A string was not a well-formed origin in normalised form.
    #[error("invalid origin: {reason}")]
    InvalidOrigin {
        /// Static reason, never the input.
        reason: &'static str,
    },
    /// A hex digest was not 64 lowercase hexadecimal characters.
    #[error("invalid hex digest")]
    InvalidHex,
    /// An error code did not match `<namespace>.<reason>`.
    #[error("invalid error code")]
    InvalidErrorCode,
    /// A number was outside its allowed range.
    #[error("{what} out of range")]
    OutOfRange {
        /// What was out of range.
        what: &'static str,
    },
    /// A byte range had `start > end`.
    #[error("invalid byte range")]
    InvalidRange,
    /// A value violated a documented limit or rule.
    #[error("{0}")]
    Invalid(&'static str),
}

impl TypesError {
    /// The registered envelope for the errors the specification gives a dedicated code:
    /// [`TypesError::SchemeNotAllowed`] is `policy.scheme_not_allowed` (class `policy_denied`).
    /// Every other error is a plain validation failure that the API layer reports as an invalid
    /// request; this returns `None` for them.
    #[must_use]
    pub fn policy_envelope(&self) -> Option<ErrorEnvelope> {
        match self {
            Self::SchemeNotAllowed => Some(ErrorEnvelope::from_code(
                codes::POLICY_SCHEME_NOT_ALLOWED,
                "only http and https URLs are allowed",
            )),
            _ => None,
        }
    }
}

/// Coarse, stable failure class (00 section 9.2). The first nine drive job retry policy
/// (01 section 8); the rest classify protocol-level errors.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ErrorClass {
    /// Connection-level failure likely to pass.
    TransientNetwork,
    /// The server asked us to slow down.
    Throttled,
    /// The session or credential was rejected.
    AuthExpired,
    /// The signed or one-shot URL no longer works.
    UrlExpired,
    /// The server refuses this client but may accept the user's browser.
    Blocked,
    /// Retrying cannot help.
    Permanent,
    /// Local storage problem.
    Disk,
    /// Bytes or metadata contradict each other or an expectation.
    Integrity,
    /// A rule or a human said no.
    PolicyDenied,
    /// Malformed or semantically invalid input.
    InvalidRequest,
    /// The named entity does not exist.
    NotFound,
    /// The request conflicts with current state.
    Conflict,
    /// The caller is not an authorised peer.
    Unauthenticated,
    /// The peer lacks the capability or version.
    Unsupported,
    /// A dependency is not ready.
    Unavailable,
    /// No answer within the deadline.
    Timeout,
    /// Bug or invariant violation.
    Internal,
}

impl ErrorClass {
    /// All classes in declaration order.
    pub const ALL: [Self; 17] = [
        Self::TransientNetwork,
        Self::Throttled,
        Self::AuthExpired,
        Self::UrlExpired,
        Self::Blocked,
        Self::Permanent,
        Self::Disk,
        Self::Integrity,
        Self::PolicyDenied,
        Self::InvalidRequest,
        Self::NotFound,
        Self::Conflict,
        Self::Unauthenticated,
        Self::Unsupported,
        Self::Unavailable,
        Self::Timeout,
        Self::Internal,
    ];

    /// The wire spelling (`snake_case`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TransientNetwork => "transient_network",
            Self::Throttled => "throttled",
            Self::AuthExpired => "auth_expired",
            Self::UrlExpired => "url_expired",
            Self::Blocked => "blocked",
            Self::Permanent => "permanent",
            Self::Disk => "disk",
            Self::Integrity => "integrity",
            Self::PolicyDenied => "policy_denied",
            Self::InvalidRequest => "invalid_request",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Unauthenticated => "unauthenticated",
            Self::Unsupported => "unsupported",
            Self::Unavailable => "unavailable",
            Self::Timeout => "timeout",
            Self::Internal => "internal",
        }
    }

    /// True for the nine classes that describe how a *job* failed and drive its retry policy.
    #[must_use]
    pub const fn is_job_class(self) -> bool {
        matches!(
            self,
            Self::TransientNetwork
                | Self::Throttled
                | Self::AuthExpired
                | Self::UrlExpired
                | Self::Blocked
                | Self::Permanent
                | Self::Disk
                | Self::Integrity
                | Self::PolicyDenied
        )
    }

    /// The default value of `retryable` for the class (00 section 9.2). For [`Self::Disk`] and
    /// [`Self::Integrity`] the answer really depends on the code; this returns the optimistic
    /// reading and [`ErrorCode::retryable`] is authoritative where a code is registered.
    #[must_use]
    pub const fn default_retryable(self) -> bool {
        matches!(
            self,
            Self::TransientNetwork
                | Self::Throttled
                | Self::AuthExpired
                | Self::UrlExpired
                | Self::Blocked
                | Self::Disk
                | Self::Integrity
                | Self::Unavailable
                | Self::Timeout
        )
    }
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What the registry knows about one code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeInfo {
    /// The code, `<namespace>.<reason>`.
    pub code: &'static str,
    /// The only class this code may carry.
    pub class: ErrorClass,
    /// Value of `retryable` emitted with this code (01 section 8.2, "Retry" column; every
    /// "yes ... (after ...)" and "only via proxy" reading is `true`).
    pub retryable: bool,
}

macro_rules! error_codes {
    ($($(#[$m:meta])* $name:ident = $code:literal, $class:ident, $retry:literal;)*) => {
        /// Constants for every registered error code.
        pub mod codes {
            $( #[doc = concat!("`", $code, "`.")] $(#[$m])* pub const $name: &str = $code; )*
        }

        /// Every registered code with its class and `retryable` value. Sorted by declaration
        /// order, not alphabetically; use [`ErrorCode::info`] for lookups.
        pub const REGISTRY: &[CodeInfo] = &[
            $( CodeInfo { code: $code, class: ErrorClass::$class, retryable: $retry }, )*
        ];
    };
}

error_codes! {
    // 01 section 8.2: HTTP
    HTTP_STATUS_401 = "http.status_401", AuthExpired, true;
    HTTP_STATUS_403 = "http.status_403", Permanent, false;
    HTTP_STATUS_429 = "http.status_429", Throttled, true;
    HTTP_STATUS_503 = "http.status_503", Throttled, true;
    HTTP_FORBIDDEN_SESSION = "http.forbidden_session", AuthExpired, true;
    HTTP_BLOCKED_CHALLENGE = "http.blocked_challenge", Blocked, true;
    HTTP_UNEXPECTED_HTML = "http.unexpected_html", AuthExpired, true;
    HTTP_CONTENT_ENCODED = "http.content_encoded", Permanent, false;
    HTTP_REDIRECT_LOOP = "http.redirect_loop", Permanent, false;
    HTTP_REDIRECT_SCHEME = "http.redirect_scheme", Permanent, false;
    HTTP_PROTOCOL_ERROR = "http.protocol_error", Permanent, false;
    HTTP_RETRY_AFTER_TOO_LONG = "http.retry_after_too_long", Throttled, false;
    // net, tls
    NET_DNS_NXDOMAIN = "net.dns_nxdomain", TransientNetwork, true;
    NET_HOST_NOT_FOUND = "net.host_not_found", Permanent, false;
    NET_DNS_FAILURE = "net.dns_failure", TransientNetwork, true;
    NET_CONNECTION_REFUSED = "net.connection_refused", TransientNetwork, true;
    NET_CONNECTION_RESET = "net.connection_reset", TransientNetwork, true;
    NET_CONNECT_TIMEOUT = "net.connect_timeout", TransientNetwork, true;
    NET_READ_TIMEOUT = "net.read_timeout", TransientNetwork, true;
    NET_PREMATURE_EOF = "net.premature_eof", TransientNetwork, true;
    NET_H2_RESET = "net.h2_reset", TransientNetwork, true;
    NET_H2_ENHANCE_YOUR_CALM = "net.h2_enhance_your_calm", Throttled, true;
    NET_QUIC_TIMEOUT = "net.quic_timeout", TransientNetwork, true;
    NET_UNREACHABLE = "net.unreachable", TransientNetwork, true;
    NET_PROXY_FAILED = "net.proxy_failed", TransientNetwork, true;
    NET_PROXY_AUTH_REQUIRED = "net.proxy_auth_required", Permanent, false;
    TLS_CERT_INVALID = "tls.cert_invalid", Permanent, false;
    TLS_HANDSHAKE_FAILED = "tls.handshake_failed", TransientNetwork, true;
    TLS_HANDSHAKE_BLOCKED = "tls.handshake_blocked", Blocked, true;
    // url, session
    URL_EXPIRED = "url.expired", UrlExpired, true;
    URL_REFRESH_FAILED = "url.refresh_failed", UrlExpired, false;
    URL_LOGIN_REQUIRED = "url.login_required", AuthExpired, true;
    URL_REFRESH_UNSUPPORTED = "url.refresh_unsupported", Unsupported, false;
    SESSION_EXPIRED = "session.expired", AuthExpired, true;
    SESSION_LEASE_EXPIRED = "session.lease_expired", AuthExpired, true;
    SESSION_CONSENT_REQUIRED = "session.consent_required", AuthExpired, true;
    SESSION_EXTENSION_UNAVAILABLE = "session.extension_unavailable", Unavailable, true;
    SESSION_WAIT_EXPIRED = "session.wait_expired", AuthExpired, false;
    SESSION_CONSENT_DENIED = "session.consent_denied", PolicyDenied, false;
    SESSION_ORIGIN_MISMATCH = "session.origin_mismatch", InvalidRequest, false;
    SESSION_STORE_UNAVAILABLE = "session.store_unavailable", Unavailable, true;
    SESSION_EXTENSION_BUSY = "session.extension_busy", Unavailable, true;
    // fs
    FS_NO_SPACE = "fs.no_space", Disk, true;
    FS_QUOTA_EXCEEDED = "fs.quota_exceeded", Disk, true;
    FS_PERMISSION_DENIED = "fs.permission_denied", Disk, false;
    FS_BUSY = "fs.busy", Disk, true;
    FS_IO_ERROR = "fs.io_error", Disk, true;
    FS_NAME_INVALID = "fs.name_invalid", Disk, false;
    FS_DEST_MISSING = "fs.dest_missing", Disk, false;
    FS_TOO_MANY_OPEN_FILES = "fs.too_many_open_files", Disk, true;
    FS_FINALIZE_LOST = "fs.finalize_lost", Disk, false;
    // integrity
    INTEGRITY_HASH_MISMATCH = "integrity.hash_mismatch", Integrity, true;
    INTEGRITY_SIZE_MISMATCH = "integrity.size_mismatch", Integrity, true;
    INTEGRITY_RESOURCE_CHANGED = "integrity.resource_changed", Integrity, true;
    INTEGRITY_RESOURCE_UNSTABLE = "integrity.resource_unstable", Integrity, false;
    INTEGRITY_RANGE_IGNORED = "integrity.range_ignored", Integrity, true;
    INTEGRITY_RANGE_MISMATCH = "integrity.range_mismatch", Integrity, true;
    INTEGRITY_RANGE_OVERRUN = "integrity.range_overrun", Integrity, true;
    INTEGRITY_TAIL_CHECK_FAILED = "integrity.tail_check_failed", Integrity, true;
    // policy
    POLICY_KILL_SWITCH_ENGAGED = "policy.kill_switch_engaged", PolicyDenied, false;
    POLICY_ORIGIN_NEVER = "policy.origin_never", PolicyDenied, false;
    POLICY_APPROVAL_DENIED = "policy.approval_denied", PolicyDenied, false;
    POLICY_APPROVAL_EXPIRED = "policy.approval_expired", PolicyDenied, false;
    POLICY_PATH_OUTSIDE_ROOTS = "policy.path_outside_roots", PolicyDenied, false;
    POLICY_SCHEME_NOT_ALLOWED = "policy.scheme_not_allowed", PolicyDenied, false;
    POLICY_ROBOTS_DISALLOWED = "policy.robots_disallowed", PolicyDenied, false;
    POLICY_QUARANTINE_BLOCKED = "policy.quarantine_blocked", PolicyDenied, false;
    POLICY_TOO_MANY_PENDING = "policy.too_many_pending", Unavailable, true;
    // 13 section 17: content-addressed artifact store
    ARTIFACT_NOT_FOUND = "artifact.not_found", NotFound, false;
    ARTIFACT_OBJECT_ABSENT = "artifact.object_absent", NotFound, false;
    ARTIFACT_OBJECT_DAMAGED = "artifact.object_damaged", Integrity, false;
    ARTIFACT_DIGEST_MISMATCH = "artifact.digest_mismatch", Integrity, false;
    ARTIFACT_QUOTA_EXCEEDED = "artifact.quota_exceeded", Disk, false;
    ARTIFACT_STORE_LOCKED = "artifact.store_locked", Conflict, false;
    ARTIFACT_VERSION_UNSUPPORTED = "artifact.version_unsupported", Unsupported, false;
    ARTIFACT_STORE_CORRUPT = "artifact.store_corrupt", Internal, false;
    ARTIFACT_STORE_LOCATION_UNSUITABLE = "artifact.store_location_unsuitable", InvalidRequest, false;
    ARTIFACT_RECORD_INVALID = "artifact.record_invalid", InvalidRequest, false;
    ARTIFACT_LINEAGE_INVALID = "artifact.lineage_invalid", InvalidRequest, false;
    ARTIFACT_IMPORT_CONFLICT = "artifact.import_conflict", Conflict, false;
    ARTIFACT_MATERIALIZE_UNSUPPORTED = "artifact.materialize_unsupported", Unsupported, false;
    // engine, api
    ENGINE_CRASH_LOOP = "engine.crash_loop", Internal, false;
    ENGINE_SHUTDOWN = "engine.shutdown", Unavailable, true;
    API_INVALID_PARAMS = "api.invalid_params", InvalidRequest, false;
    WORKFLOW_BUDGET_EXHAUSTED = "workflow.budget_exhausted", PolicyDenied, false;
    API_IDEMPOTENCY_CONFLICT = "api.idempotency_conflict", Conflict, false;
    API_NOT_FOUND = "api.not_found", NotFound, false;
    API_HUMAN_REQUIRED = "api.human_required", PolicyDenied, false;
    API_INVALID_TRANSITION = "api.invalid_transition", Conflict, false;
    API_NOT_INTERRUPTIBLE = "api.not_interruptible", Conflict, true;
    // 02 section 14: native messaging
    NM_INVALID_JSON = "nm.invalid_json", InvalidRequest, false;
    NM_SCHEMA_VIOLATION = "nm.schema_violation", InvalidRequest, false;
    NM_MALFORMED_FRAME = "nm.malformed_frame", InvalidRequest, false;
    NM_FRAME_TOO_LARGE = "nm.frame_too_large", InvalidRequest, false;
    NM_UNKNOWN_TYPE = "nm.unknown_type", Unsupported, false;
    NM_NOT_NEGOTIATED = "nm.not_negotiated", Conflict, false;
    NM_VERSION_UNSUPPORTED = "nm.version_unsupported", Unsupported, false;
    NM_CAPABILITY_MISSING = "nm.capability_missing", Unsupported, false;
    NM_ORIGIN_NOT_ALLOWED = "nm.origin_not_allowed", Unauthenticated, false;
    NM_EXTENSION_MISMATCH = "nm.extension_mismatch", Unauthenticated, false;
    NM_USER_GESTURE_REQUIRED = "nm.user_gesture_required", Unauthenticated, false;
    NM_RATE_LIMITED = "nm.rate_limited", Unavailable, true;
    NM_TOO_MANY_CONNECTIONS = "nm.too_many_connections", Unavailable, true;
    NM_DAEMON_UNAVAILABLE = "nm.daemon_unavailable", Unavailable, true;
    NM_SHUTTING_DOWN = "nm.shutting_down", Unavailable, true;
    NM_TIMEOUT = "nm.timeout", Timeout, true;
    NM_DUPLICATE_ID = "nm.duplicate_id", InvalidRequest, false;
    NM_NOT_FOUND = "nm.not_found", NotFound, false;
    NM_CONFLICT = "nm.conflict", Conflict, false;
    NM_STREAM_UNKNOWN = "nm.stream_unknown", NotFound, false;
    NM_STREAM_PROTOCOL_VIOLATION = "nm.stream_protocol_violation", InvalidRequest, false;
    NM_CREDIT_EXCEEDED = "nm.credit_exceeded", InvalidRequest, false;
    NM_TOO_MANY_STREAMS = "nm.too_many_streams", Unavailable, true;
    NM_INTERNAL = "nm.internal", Internal, false;
    HANDOFF_NOT_ELIGIBLE = "handoff.not_eligible", PolicyDenied, false;
    HANDOFF_RATE_LIMITED = "handoff.rate_limited", Unavailable, true;
    FETCH_NETWORK_ERROR = "fetch.network_error", TransientNetwork, true;
    FETCH_TIMEOUT = "fetch.timeout", TransientNetwork, true;
    FETCH_BODY_ERROR = "fetch.body_error", TransientNetwork, true;
    FETCH_ABORTED = "fetch.aborted", TransientNetwork, true;
    FETCH_CONTENT_ENCODED = "fetch.content_encoded", Permanent, false;
    FETCH_CROSS_ORIGIN_DENIED = "fetch.cross_origin_denied", PolicyDenied, false;
    FETCH_EXTENSION_BUSY = "fetch.extension_busy", Unavailable, true;
    // 03 section 15: journal; 04: audit
    JOURNAL_CORRUPT = "journal.corrupt", Internal, false;
    JOURNAL_VERSION_UNSUPPORTED = "journal.version_unsupported", Unsupported, false;
    JOURNAL_ALREADY_OPEN = "journal.already_open", Conflict, false;
    JOURNAL_COMMIT_AMBIGUOUS = "journal.commit_ambiguous", Internal, true;
    JOURNAL_POISONED = "journal.poisoned", Internal, false;
    AUDIT_CHAIN_BROKEN = "audit.chain_broken", Internal, false;
    AUDIT_UNAVAILABLE = "audit.unavailable", Unavailable, true;
    /// A bug or violated invariant inside Zeus.
    INTERNAL_BUG = "internal.bug", Internal, false;
}

/// A validated error code: lowercase `snake_case` segments with at least one dot, at most 96
/// characters (`common.schema.json#/$defs/ErrorCode`).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ErrorCode(Cow<'static, str>);

impl ErrorCode {
    /// Validates a runtime string.
    pub fn new(code: impl Into<String>) -> Result<Self, TypesError> {
        let code = code.into();
        if is_valid_code(&code) {
            Ok(Self(Cow::Owned(code)))
        } else {
            Err(TypesError::InvalidErrorCode)
        }
    }

    /// Wraps a constant. Intended for the constants in [`codes`]; an invalid literal is a bug and
    /// is caught by the unit tests of this module.
    #[must_use]
    pub const fn from_static(code: &'static str) -> Self {
        Self(Cow::Borrowed(code))
    }

    /// The code text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Registry entry for this code. `http.status_<nnn>` is resolved by the status rules of
    /// 01 section 8.3 stage D (the 401 and 403 context rules need the caller's evidence, so a
    /// bare `http.status_403` is `permanent` and `http.status_401` is `auth_expired`).
    #[must_use]
    pub fn info(&self) -> Option<CodeInfo> {
        lookup(self.as_str())
    }

    /// The class this code must carry, if registered.
    #[must_use]
    pub fn class(&self) -> Option<ErrorClass> {
        self.info().map(|i| i.class)
    }

    /// The registered `retryable` value, if the code is registered.
    #[must_use]
    pub fn retryable(&self) -> Option<bool> {
        self.info().map(|i| i.retryable)
    }

    /// The namespace, the text before the first dot.
    #[must_use]
    pub fn namespace(&self) -> &str {
        self.as_str().split('.').next().unwrap_or("")
    }
}

impl fmt::Debug for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ErrorCode({})", self.as_str())
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for ErrorCode {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "ErrorCode".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "maxLength": 96,
            "pattern": "^[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*)+$",
            "description": "Stable machine string: <namespace>.<reason>, lowercase snake_case. Never translated."
        })
    }
}

fn is_valid_code(code: &str) -> bool {
    if code.len() > 96 || !code.contains('.') {
        return false;
    }
    code.split('.').all(|seg| {
        let mut chars = seg.chars();
        chars.next().is_some_and(|c| c.is_ascii_lowercase())
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    })
}

/// Looks a code up in [`REGISTRY`], resolving the `http.status_<nnn>` family.
#[must_use]
pub fn lookup(code: &str) -> Option<CodeInfo> {
    if let Some(info) = REGISTRY.iter().find(|i| i.code == code) {
        return Some(*info);
    }
    let status: u16 = code.strip_prefix("http.status_")?.parse().ok()?;
    let (class, retryable) = status_class(status);
    Some(CodeInfo {
        code: "http.status_<nnn>",
        class,
        retryable,
    })
}

/// Class and `retryable` for an HTTP status without more specific evidence (01 section 8.3,
/// rules D4 and D7 to D12). 401 is `auth_expired`; 403 is `permanent` (rule D5; the evidence for
/// D1 to D4 is the classifier's job, see `zeus-http`); 429 and 503 are `throttled`;
/// 408, 421, 425, 500, 502, 504, 520 to 526 and other 5xx except 501 and 505 are
/// `transient_network`; everything else is `permanent`.
#[must_use]
pub const fn status_class(status: u16) -> (ErrorClass, bool) {
    match status {
        401 => (ErrorClass::AuthExpired, true),
        429 | 503 => (ErrorClass::Throttled, true),
        408 | 421 | 425 | 500 | 502 | 504 | 520..=526 => (ErrorClass::TransientNetwork, true),
        501 | 505 => (ErrorClass::Permanent, false),
        506..=599 => (ErrorClass::TransientNetwork, true),
        _ => (ErrorClass::Permanent, false),
    }
}

/// The error envelope every process boundary uses (00 section 9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ErrorEnvelope {
    /// Stable machine identifier. Never translated.
    pub code: ErrorCode,
    /// Coarse class; drives retry and presentation.
    pub class: ErrorClass,
    /// English diagnostic, at most 1024 characters. Never parsed. No secrets.
    pub message: String,
    /// True iff repeating the same request, possibly after the delay or refresh the class
    /// implies, may succeed without human action.
    pub retryable: bool,
    /// Code-specific structured data, at most 8 KiB serialised. No secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Map<String, Value>>,
}

impl ErrorEnvelope {
    /// Builds an envelope for a registered code: class and `retryable` come from the registry.
    /// An unregistered code yields class `internal`, not retryable (and a debug assertion), so a
    /// typo cannot masquerade as a retryable condition.
    #[must_use]
    pub fn from_code(code: &'static str, message: impl Into<String>) -> Self {
        let info = lookup(code);
        debug_assert!(info.is_some(), "unregistered error code {code}");
        let (class, retryable) =
            info.map_or((ErrorClass::Internal, false), |i| (i.class, i.retryable));
        Self::new(ErrorCode::from_static(code), class, retryable, message)
    }

    /// Builds an envelope from explicit parts. The message is truncated to 1024 characters.
    #[must_use]
    pub fn new(
        code: ErrorCode,
        class: ErrorClass,
        retryable: bool,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            class,
            message: truncate_chars(message.into(), MAX_ERROR_MESSAGE_CHARS),
            retryable,
            details: None,
        }
    }

    /// Attaches `details`. Dropped (replaced by a marker) when it would exceed 8 KiB serialised.
    #[must_use]
    pub fn with_details(mut self, details: Map<String, Value>) -> Self {
        let size = serde_json::to_vec(&details).map_or(usize::MAX, |v| v.len());
        self.details = if size <= MAX_ERROR_DETAILS_BYTES {
            Some(details)
        } else {
            let mut marker = Map::new();
            marker.insert("details_dropped".into(), Value::Bool(true));
            Some(marker)
        };
        self
    }

    /// Attaches one `details` entry.
    #[must_use]
    pub fn with_detail(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.details
            .get_or_insert_with(Map::new)
            .insert(key.to_owned(), value.into());
        self
    }

    /// Overrides `retryable` (for example after a retry budget is exhausted).
    #[must_use]
    pub fn with_retryable(mut self, retryable: bool) -> Self {
        self.retryable = retryable;
        self
    }

    /// Checks the documented limits and the registry (class must match the code's registered class).
    pub fn validate(&self) -> Result<(), TypesError> {
        if self.message.chars().count() > MAX_ERROR_MESSAGE_CHARS {
            return Err(TypesError::Invalid(
                "error message longer than 1024 characters",
            ));
        }
        if let Some(d) = &self.details
            && serde_json::to_vec(d).map_or(true, |v| v.len() > MAX_ERROR_DETAILS_BYTES)
        {
            return Err(TypesError::Invalid("error details larger than 8 KiB"));
        }
        match self.code.class() {
            Some(class) if class != self.class => Err(TypesError::Invalid(
                "error class does not match the registered class of the code",
            )),
            _ => Ok(()),
        }
    }
}

impl fmt::Display for ErrorEnvelope {
    /// The one-line rendering used in MCP text content and CLI stderr: `"<code>: <message>"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ErrorEnvelope {}

/// Implemented by every error type that can cross a process boundary, so servers can map any
/// library error to the envelope without knowing its concrete type.
pub trait ToEnvelope {
    /// The envelope for this error. Must not contain secrets.
    fn to_envelope(&self) -> ErrorEnvelope;
}

impl ToEnvelope for ErrorEnvelope {
    fn to_envelope(&self) -> ErrorEnvelope {
        self.clone()
    }
}

fn truncate_chars(mut s: String, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s;
    }
    let keep: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    s.clear();
    s.push_str(&keep);
    s.push('\u{2026}');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_registered_code_is_valid_unique_and_consistent() {
        let mut seen = std::collections::HashSet::new();
        for info in REGISTRY {
            assert!(is_valid_code(info.code), "{}", info.code);
            assert!(seen.insert(info.code), "duplicate {}", info.code);
            assert!(codes_namespace_ok(info.code), "{}", info.code);
        }
    }

    fn codes_namespace_ok(code: &str) -> bool {
        const NAMESPACES: &[&str] = &[
            "http",
            "net",
            "tls",
            "fs",
            "integrity",
            "policy",
            "session",
            "url",
            "fetch",
            "handoff",
            "nm",
            "journal",
            "audit",
            "artifact",
            "workflow",
            "engine",
            "api",
            "internal",
        ];
        NAMESPACES.contains(&code.split('.').next().unwrap_or(""))
    }

    #[test]
    fn spec_example_envelope_round_trips() {
        let text = r#"{"code":"http.status_429","class":"throttled","message":"Server answered 429 Too Many Requests.","retryable":true,"details":{"status":429,"retry_after_ms":30000,"host":"files.example.com"}}"#;
        let env: ErrorEnvelope = serde_json::from_str(text).unwrap();
        assert_eq!(env.class, ErrorClass::Throttled);
        assert!(env.validate().is_ok());
        let again: ErrorEnvelope =
            serde_json::from_str(&serde_json::to_string(&env).unwrap()).unwrap();
        assert_eq!(env, again);
    }

    #[test]
    fn from_code_uses_the_registry() {
        let env = ErrorEnvelope::from_code(codes::FS_NO_SPACE, "disk full");
        assert_eq!(env.class, ErrorClass::Disk);
        assert!(env.retryable);
        let env = ErrorEnvelope::from_code(codes::TLS_CERT_INVALID, "bad cert");
        assert_eq!(env.class, ErrorClass::Permanent);
        assert!(!env.retryable);
    }

    #[test]
    fn http_status_family() {
        let code = ErrorCode::new("http.status_502").unwrap();
        assert_eq!(code.class(), Some(ErrorClass::TransientNetwork));
        assert_eq!(
            ErrorCode::new("http.status_404").unwrap().class(),
            Some(ErrorClass::Permanent)
        );
        assert_eq!(
            ErrorCode::new("http.status_501").unwrap().class(),
            Some(ErrorClass::Permanent)
        );
        assert_eq!(
            ErrorCode::new("http.status_522").unwrap().class(),
            Some(ErrorClass::TransientNetwork)
        );
        assert_eq!(status_class(429), (ErrorClass::Throttled, true));
        assert_eq!(status_class(299), (ErrorClass::Permanent, false));
    }

    #[test]
    fn rejects_bad_codes_and_mismatched_class() {
        for bad in [
            "nodots",
            "Upper.case",
            "a..b",
            "a.b-c",
            ".a",
            "a.",
            "1a.b",
            "",
        ] {
            assert!(ErrorCode::new(bad).is_err(), "{bad:?}");
        }
        let mut env = ErrorEnvelope::from_code(codes::NM_TIMEOUT, "late");
        env.class = ErrorClass::Disk;
        assert!(env.validate().is_err());
    }

    #[test]
    fn message_and_details_limits() {
        let env = ErrorEnvelope::from_code(codes::NM_TIMEOUT, "x".repeat(5000));
        assert_eq!(env.message.chars().count(), MAX_ERROR_MESSAGE_CHARS);
        let mut big = Map::new();
        big.insert("blob".into(), Value::String("y".repeat(10_000)));
        let env = ErrorEnvelope::from_code(codes::NM_TIMEOUT, "late").with_details(big);
        assert!(env.validate().is_ok());
        assert_eq!(
            env.details.unwrap().get("details_dropped"),
            Some(&Value::Bool(true))
        );
    }

    #[test]
    fn class_wire_spelling_matches_as_str() {
        for class in ErrorClass::ALL {
            assert_eq!(
                serde_json::to_string(&class).unwrap(),
                format!("\"{}\"", class.as_str())
            );
        }
    }
}
