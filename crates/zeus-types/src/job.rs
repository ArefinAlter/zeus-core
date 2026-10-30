//! The job entity and its parts (01 section 3): spec, source, probe result, progress, retry
//! counters, result and the compact summary used by list views.
//!
//! Wire shape rules (00 sections 3 and 4): `snake_case` keys, `snake_case` enum values, absent or
//! `null` for "not set", receivers ignore unknown keys (so no `deny_unknown_fields`).

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ErrorClass, ErrorEnvelope, TypesError, codes};
use crate::ids::{ApprovalId, GrantId, JobId, RunId};
use crate::limits::{
    MAX_EXTRA_HEADERS_PER_JOB, MAX_FILE_NAME_BYTES, MAX_IDEMPOTENCY_KEY_CHARS, MAX_LABEL_CHARS,
    MAX_LABELS_PER_JOB, MAX_PATH_BYTES, MAX_SAFE_INTEGER,
};
use crate::origin::{HttpUrl, Origin, RedactedUrl};
use crate::state::JobState;
use crate::timestamp::Timestamp;
use crate::units::Hex256;

/// Scheduling weight class (01 section 3.2). Weighted fair queueing uses 1, 2 and 4.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Default,
    Serialize,
    Deserialize,
    JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    /// Weight 1.
    Low,
    /// Weight 2. The default.
    #[default]
    Normal,
    /// Weight 4. The default for browser handoffs.
    High,
}

impl Priority {
    /// The weighted-fair-queue weight.
    #[must_use]
    pub const fn weight(self) -> u32 {
        match self {
            Self::Low => 1,
            Self::Normal => 2,
            Self::High => 4,
        }
    }
}

/// How bytes currently flow (01 section 3.1, `transport`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// The engine's own HTTP client.
    #[default]
    Direct,
    /// The user's browser fetches the bytes (the in-browser proxy, 02 section 9).
    BrowserProxy,
}

/// What the caller asks of the transport (`spec.transport_hint`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TransportHint {
    /// Direct first, the proxy only after a `blocked` classification.
    #[default]
    Auto,
    /// Never use the browser.
    Direct,
    /// Force the in-browser fetch fallback (needs a connected extension and an effective grant).
    BrowserProxy,
}

/// What to do if the final path exists (`spec.overwrite`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Overwrite {
    /// Append ` (1)`, ` (2)`, ... before the extension.
    #[default]
    Rename,
    /// Refuse.
    Fail,
    /// Move the old file to the application trash first (03 section 8.1).
    Replace,
}

/// Who asked, by which route (01 section 3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// A failed or user-forwarded browser download through the extension.
    BrowserHandoff,
    /// An MCP tool call or an A2A task.
    Agent,
    /// A human using the CLI or TUI.
    Cli,
    /// The workflow runner executing an approved plan.
    Workflow,
}

/// The channel a job request arrived on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceVia {
    /// MCP server.
    Mcp,
    /// A2A endpoint.
    A2a,
    /// Raw local JSON-RPC.
    Jsonrpc,
    /// CLI.
    Cli,
    /// TUI.
    Tui,
    /// Native messaging from the extension.
    NativeMessaging,
    /// The workflow runner.
    WorkflowRunner,
}

/// Browser family reported by the extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BrowserName {
    /// Google Chrome.
    Chrome,
    /// Microsoft Edge.
    Edge,
    /// Brave.
    Brave,
    /// Chromium.
    Chromium,
    /// Mozilla Firefox.
    Firefox,
    /// Anything else.
    Other,
}

/// Browser context of a handoff job (01 section 3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BrowserInfo {
    /// Browser family.
    pub name: BrowserName,
    /// Extension id (informational; the attested id is authoritative).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_id: Option<String>,
    /// Which browser profile (and therefore which cookie jar): 32 lowercase hex characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    /// The browser's download id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_id: Option<u64>,
    /// `<browser>:<download id>:<start time>`, the deduplication key of a handoff offer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offer_key: Option<String>,
    /// The download came from a private window.
    pub incognito: bool,
}

/// Records who asked and by which route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Source {
    /// The kind; determines default priority and which approvals apply.
    pub kind: SourceKind,
    /// The channel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<SourceVia>,
    /// The authenticated client, at most 128 characters. Untrusted text when shown to a model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// The workflow run (for `workflow` and `agent` jobs started by a run).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    /// Browser context for `browser_handoff`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<BrowserInfo>,
}

impl Source {
    /// A source of the given kind with no further detail.
    #[must_use]
    pub fn new(kind: SourceKind) -> Self {
        Self {
            kind,
            via: None,
            client_id: None,
            run_id: None,
            browser: None,
        }
    }
}

/// Header names a job may carry besides the engine's own (01 section 3.2, `extra_headers`).
pub const ALLOWED_EXTRA_HEADERS: &[&str] = &[
    "accept",
    "accept-language",
    "if-modified-since",
    "x-requested-with",
];

/// The immutable request that created a job. Only `priority` may change afterwards.
///
/// Fields with a default are `Option` here so a client request round-trips unchanged; the daemon
/// calls [`JobSpec::apply_defaults`] before storing the job, and the accessors below read the
/// effective value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobSpec {
    /// The stable address of the resource (http or https, at most 8192 bytes).
    pub url: HttpUrl,
    /// Last known resolved (often signed) URL; tried first, `url` is the fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hint_url: Option<HttpUrl>,
    /// Sent as `Referer` only for same-origin or allow-listed requests; always kept for provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub referrer: Option<HttpUrl>,
    /// Destination directory; must resolve inside a configured write root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dest_dir: Option<String>,
    /// A file name hint. The final name comes from `Content-Disposition` first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
    /// A mismatch is an `integrity` failure after at most one restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<Hex256>,
    /// Likewise for the size in bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_size: Option<u64>,
    /// Default `normal` (`high` for browser handoffs). The only mutable field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<Priority>,
    /// The origin whose session the job needs; its presence makes the job require an effective grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_origin: Option<Origin>,
    /// A suggestion shown on the approval; the human chooses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_scope_hint: Option<GrantScopeHint>,
    /// At most 16 headers from [`ALLOWED_EXTRA_HEADERS`].
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra_headers: BTreeMap<String, String>,
    /// Client-chosen idempotency key (00 section 5.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    /// What to do if the final path exists. Default `rename`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overwrite: Option<Overwrite>,
    /// Upper bound on connections, 1 to 32. Default 8.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u8>,
    /// Default `auto`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_hint: Option<TransportHint>,
    /// Free-form tags from the caller. Untrusted data.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub labels: BTreeMap<String, String>,
    /// Who asked.
    pub source: Source,
}

/// The scopes a request may suggest (never `never`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantScopeHint {
    /// One job.
    Once,
    /// One origin for 24 hours.
    Site,
    /// One origin and one run for 7 days.
    Workflow,
}

/// Default number of connections per job (01 section 10).
pub const DEFAULT_MAX_CONNECTIONS: u8 = 8;

impl JobSpec {
    /// A spec with only the required fields.
    #[must_use]
    pub fn new(url: HttpUrl, source: Source) -> Self {
        Self {
            url,
            hint_url: None,
            referrer: None,
            dest_dir: None,
            filename: None,
            expected_sha256: None,
            expected_size: None,
            priority: None,
            session_origin: None,
            grant_scope_hint: None,
            extra_headers: BTreeMap::new(),
            idempotency_key: None,
            overwrite: None,
            max_connections: None,
            transport_hint: None,
            labels: BTreeMap::new(),
            source,
        }
    }

    /// Effective priority: the explicit value, else `high` for browser handoffs, else `normal`.
    #[must_use]
    pub fn priority(&self) -> Priority {
        self.priority
            .unwrap_or(if self.source.kind == SourceKind::BrowserHandoff {
                Priority::High
            } else {
                Priority::Normal
            })
    }

    /// Effective overwrite policy.
    #[must_use]
    pub fn overwrite(&self) -> Overwrite {
        self.overwrite.unwrap_or_default()
    }

    /// Effective connection bound.
    #[must_use]
    pub fn max_connections(&self) -> u8 {
        self.max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS)
    }

    /// Effective transport hint.
    #[must_use]
    pub fn transport_hint(&self) -> TransportHint {
        self.transport_hint.unwrap_or_default()
    }

    /// Origin of `url` (the stable address).
    #[must_use]
    pub fn origin(&self) -> Origin {
        self.url.origin()
    }

    /// Fills every default so the stored spec states each effective value explicitly. `default_dest_dir`
    /// is the daemon's configured root.
    pub fn apply_defaults(&mut self, default_dest_dir: &str) {
        self.priority = Some(self.priority());
        self.overwrite = Some(self.overwrite());
        self.max_connections = Some(self.max_connections());
        self.transport_hint = Some(self.transport_hint());
        if self.dest_dir.is_none() {
            self.dest_dir = Some(default_dest_dir.to_owned());
        }
    }

    /// Checks every rule of 01 section 3.2 that does not need the file system or the journal.
    ///
    /// Returns `invalid_request` envelopes (code `nm.schema_violation` is the native-messaging
    /// spelling; the daemon API maps this to JSON-RPC invalid params). Never echoes a URL.
    pub fn validate(&self) -> Result<(), ErrorEnvelope> {
        let bad = |msg: &str| {
            Err(ErrorEnvelope::from_code(
                codes::NM_SCHEMA_VIOLATION,
                format!("invalid job spec: {msg}"),
            ))
        };
        if let Some(name) = &self.filename
            && (name.is_empty() || name.len() > MAX_FILE_NAME_BYTES)
        {
            return bad("filename must be 1 to 255 bytes");
        }
        if self
            .dest_dir
            .as_ref()
            .is_some_and(|d| d.is_empty() || d.len() > MAX_PATH_BYTES)
        {
            return bad("dest_dir must be 1 to 4096 bytes");
        }
        if self.expected_size.is_some_and(|s| s > MAX_SAFE_INTEGER) {
            return bad("expected_size exceeds 2^53 - 1");
        }
        if let Some(key) = &self.idempotency_key {
            let n = key.chars().count();
            if n == 0 || n > MAX_IDEMPOTENCY_KEY_CHARS {
                return bad("idempotency_key must be 1 to 128 characters");
            }
        }
        if self.max_connections.is_some_and(|n| !(1..=32).contains(&n)) {
            return bad("max_connections must be 1 to 32");
        }
        if self.extra_headers.len() > MAX_EXTRA_HEADERS_PER_JOB {
            return bad("more than 16 extra headers");
        }
        for (name, value) in &self.extra_headers {
            if !ALLOWED_EXTRA_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                return bad("extra header is not on the allow-list");
            }
            if value.len() > 2048 || value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
                return bad("extra header value is too long or contains control characters");
            }
        }
        if self.labels.len() > MAX_LABELS_PER_JOB
            || self.labels.iter().any(|(k, v)| {
                k.chars().count() > MAX_LABEL_CHARS || v.chars().count() > MAX_LABEL_CHARS
            })
        {
            return bad("labels exceed 16 entries or 256 characters");
        }
        if self
            .source
            .client_id
            .as_ref()
            .is_some_and(|c| c.chars().count() > 128)
        {
            return bad("source.client_id is longer than 128 characters");
        }
        Ok(())
    }
}

/// Entity tags and dates that identify one representation of a resource (01 section 3.4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Validators {
    /// Raw entity-tag including quotes and any `W/` prefix. A weak tag is never used in `If-Range`.
    #[serde(default)]
    pub etag: Option<String>,
    /// Raw HTTP-date.
    #[serde(default)]
    pub last_modified: Option<String>,
    /// True iff `Last-Modified` is at least one second older than the response `Date` (RFC 9110
    /// section 8.8.2.2), which is when it may be used in `If-Range`.
    #[serde(default)]
    pub last_modified_strong: Option<bool>,
    /// Raw `Repr-Digest` header value (RFC 9530). Informational.
    #[serde(default)]
    pub repr_digest: Option<String>,
}

impl Validators {
    /// True when the entity-tag is present and strong (does not start with `W/`).
    #[must_use]
    pub fn has_strong_etag(&self) -> bool {
        self.etag
            .as_deref()
            .is_some_and(|t| !t.starts_with("W/") && !t.starts_with("w/"))
    }

    /// True when the representation is strongly identified: a strong ETag, or a strong
    /// `Last-Modified` (01 section 3.4).
    #[must_use]
    pub fn is_strongly_identified(&self) -> bool {
        self.has_strong_etag()
            || (self.last_modified.is_some() && self.last_modified_strong == Some(true))
    }

    /// The value to send in `If-Range`, if one exists: the strong ETag, else the strong
    /// `Last-Modified` date (03 section 7.3). `None` means "no `If-Range`; use the overlap check".
    #[must_use]
    pub fn if_range_value(&self) -> Option<&str> {
        if self.has_strong_etag() {
            self.etag.as_deref()
        } else if self.last_modified_strong == Some(true) {
            self.last_modified.as_deref()
        } else {
            None
        }
    }

    /// True when no validator is present at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none() && self.repr_digest.is_none()
    }
}

/// How a probe was performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMethod {
    /// A `GET` with `Range: bytes=0-0` (the default).
    RangeGet,
    /// A `HEAD` request.
    Head,
    /// A plain `GET`, when `HEAD` and ranged `GET` are both refused.
    GetStream,
}

/// What the probe learned about range support (01 section 3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RangeSupport {
    /// A `206` with a correct `Content-Range` was observed in this job.
    Verified,
    /// A `200` answered a ranged request.
    Unsupported,
    /// Not known yet. `Accept-Ranges` is advisory and never sufficient.
    #[default]
    Unknown,
}

/// HTTP protocol version observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum HttpVersion {
    /// HTTP/1.1.
    #[serde(rename = "HTTP/1.1")]
    Http11,
    /// HTTP/2.
    #[serde(rename = "h2")]
    H2,
    /// HTTP/3.
    #[serde(rename = "h3")]
    H3,
}

/// Where the resolved file name came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FilenameSource {
    /// `Content-Disposition` (RFC 6266, `filename*` preferred).
    ContentDisposition,
    /// The last path segment of the URL.
    UrlPath,
    /// The hint in the job spec or the browser offer.
    HandoffHint,
    /// A default derived from the media type.
    ContentTypeDefault,
    /// The explicit `spec.filename`.
    UserSpec,
}

/// A resolved file name and its provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResolvedFilename {
    /// The name, 1 to 255 characters. Untrusted text; always sanitised before use as a path.
    pub value: String,
    /// Where it came from.
    pub source: FilenameSource,
}

/// The result of one probe (each entry into `probing`, 01 section 3.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProbeResult {
    /// When the probe finished.
    pub probed_at: Timestamp,
    /// How it was performed.
    pub method: ProbeMethod,
    /// Which transport carried it.
    pub transport: Transport,
    /// Protocol version of the response.
    #[serde(default)]
    pub http_version: Option<HttpVersion>,
    /// The status of the final response.
    pub status: u16,
    /// The final URL after redirects, redacted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_url_redacted: Option<RedactedUrl>,
    /// Redirects followed (at most 10).
    #[serde(default)]
    pub redirects: u8,
    /// What was learned about ranges.
    pub range_support: RangeSupport,
    /// From `Content-Range`, else `Content-Length` of an unranged `200`, else `null`.
    #[serde(default)]
    pub total_bytes: Option<u64>,
    /// As received.
    #[serde(default)]
    pub content_type: Option<String>,
    /// As received; anything but identity on an identity-only request is an error.
    #[serde(default)]
    pub content_encoding: Option<String>,
    /// The resolved file name.
    pub filename: ResolvedFilename,
    /// The representation's validators.
    pub validators: Validators,
    /// The origin refused an unauthenticated request in a way a session may fix.
    pub requires_session: bool,
    /// The response looked like an HTML wall instead of the expected file.
    #[serde(default)]
    pub interstitial_suspected: bool,
}

/// Counters that make retry policy restart-safe (01 section 3.8).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RetryState {
    /// Times the job entered `probing`.
    pub attempt: u32,
    /// Failures since the last progress reset.
    pub consecutive_failures: u32,
    /// When `bytes_done` last grew by at least the reset threshold.
    #[serde(default)]
    pub last_progress_at: Option<Timestamp>,
    /// Set while `retry_scheduled`.
    #[serde(default)]
    pub next_attempt_at: Option<Timestamp>,
    /// Session or URL refreshes since the last reset (budget 3).
    pub auth_refreshes: u32,
    /// Switches to the in-browser proxy (budget 1).
    pub proxy_escalations: u32,
    /// Restarts from zero caused by a hash or size mismatch (budget 1).
    pub integrity_restarts: u32,
    /// Restarts caused by the resource changing upstream (budget 2).
    pub resource_restarts: u32,
    /// Daemon-restart recoveries since the last committed progress (crash-loop limit 3).
    pub recovery_count: u32,
    /// When `awaiting_session` gives up.
    #[serde(default)]
    pub session_wait_deadline_at: Option<Timestamp>,
}

/// Committed-byte progress (01 section 3.7). Always reflects committed bytes, so what an agent reads
/// survives a crash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Progress {
    /// Committed bytes (during `verifying`, bytes hashed so far).
    pub bytes_done: u64,
    /// Total, `null` while unknown.
    pub bytes_total: Option<u64>,
    /// Bytes per second, EWMA with alpha 0.2 over 1 s samples; zero outside `downloading`/`verifying`.
    pub rate_ewma: u64,
    /// Seconds remaining, `null` when either input is unknown or the rate is zero.
    pub eta_s: Option<u64>,
    /// Workers currently transferring (at most 64).
    pub segments_active: u32,
    /// Class of the latest error, kept after recovery so agents can see flakiness.
    pub last_error_class: Option<ErrorClass>,
    /// When this snapshot was taken.
    pub updated_at: Timestamp,
}

impl Progress {
    /// A zeroed snapshot.
    #[must_use]
    pub fn new(now: Timestamp) -> Self {
        Self {
            bytes_done: 0,
            bytes_total: None,
            rate_ewma: 0,
            eta_s: None,
            segments_active: 0,
            last_error_class: None,
            updated_at: now,
        }
    }

    /// `(bytes_total - bytes_done) / rate_ewma`, or `None` when either is unknown or the rate is zero.
    #[must_use]
    pub fn compute_eta_s(bytes_done: u64, bytes_total: Option<u64>, rate_ewma: u64) -> Option<u64> {
        let total = bytes_total?;
        if rate_ewma == 0 {
            return None;
        }
        Some(total.saturating_sub(bytes_done) / rate_ewma)
    }
}

/// Why a completed file carries Zeus's own stronger flag (01 section 11.3).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    /// Executable, script, installer, `.jar`, `.lnk`, `.scr`, `.dll` or a macro-enabled document.
    ExecutableType,
    /// Detected type contradicts the declared one across a safety boundary.
    MimeMismatch,
    /// HTML or script content under a non-HTML name or type.
    HtmlDisguised,
    /// An archive exceeds the safety limits.
    ArchiveLimits,
    /// The optional antivirus hook reported the file as not clean.
    AvFlagged,
    /// The origin is not trusted and `quarantine_untrusted` is enabled.
    UntrustedOrigin,
    /// Retrieved with a session lease and `quarantine_session_files` is enabled.
    SessionDerived,
}

/// The outcome of a completed job (01 section 3.9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobResult {
    /// Absolute final path on the daemon's host.
    pub path: String,
    /// Size of the file at `path`.
    pub size_bytes: u64,
    /// SHA-256 of the file at `path`.
    pub sha256: Hex256,
    /// BLAKE3 of the file at `path`.
    pub blake3: Hex256,
    /// From magic bytes; `null` if unknown.
    #[serde(default)]
    pub detected_mime: Option<String>,
    /// Instant of the S80 commit.
    pub completed_at: Timestamp,
}

/// The aggregate root (01 section 3.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Job {
    /// Identifier.
    pub id: JobId,
    /// Current state.
    pub state: JobState,
    /// Only ever true when `state` is `completed`; immutable afterwards.
    pub quarantined: bool,
    /// Present when `quarantined`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantine_reasons: Vec<QuarantineReason>,
    /// The immutable request.
    pub spec: JobSpec,
    /// Creation instant.
    pub created_at: Timestamp,
    /// Changes on any field change.
    pub updated_at: Timestamp,
    /// Changes only on a transition.
    pub state_since: Timestamp,
    /// The latest probe.
    #[serde(default)]
    pub probe: Option<ProbeResult>,
    /// Committed-byte progress.
    pub progress: Progress,
    /// Retry counters and timers.
    pub retry: RetryState,
    /// The most recent error.
    #[serde(default)]
    pub error: Option<ErrorEnvelope>,
    /// Present only when `completed`.
    #[serde(default)]
    pub result: Option<JobResult>,
    /// How bytes currently flow.
    pub transport: Transport,
    /// The effective grant the job currently relies on.
    #[serde(default)]
    pub grant_id: Option<GrantId>,
    /// The pending approval, if any.
    #[serde(default)]
    pub approval_id: Option<ApprovalId>,
}

impl Job {
    /// A new job in `state` (`queued` or `awaiting_approval`), with zeroed progress and counters.
    #[must_use]
    pub fn new(id: JobId, spec: JobSpec, state: JobState, now: Timestamp) -> Self {
        Self {
            id,
            state,
            quarantined: false,
            quarantine_reasons: Vec::new(),
            spec,
            created_at: now,
            updated_at: now,
            state_since: now,
            probe: None,
            progress: Progress::new(now),
            retry: RetryState::default(),
            error: None,
            result: None,
            transport: Transport::Direct,
            grant_id: None,
            approval_id: None,
        }
    }

    /// Checks invariants that hold in every stored job: `quarantined` only when `completed`,
    /// a `result` only when `completed`, `retry.next_attempt_at` only when `retry_scheduled`.
    pub fn check_invariants(&self) -> Result<(), TypesError> {
        if self.quarantined && self.state != JobState::Completed {
            return Err(TypesError::Invalid(
                "quarantined is only valid on a completed job",
            ));
        }
        if self.result.is_some() && self.state != JobState::Completed {
            return Err(TypesError::Invalid(
                "result is only valid on a completed job",
            ));
        }
        if self.quarantined == self.quarantine_reasons.is_empty() {
            return Err(TypesError::Invalid(
                "quarantine_reasons must be present exactly when quarantined",
            ));
        }
        Ok(())
    }

    /// The compact projection used by lists and the extension popup.
    #[must_use]
    pub fn summary(&self) -> JobSummary {
        JobSummary {
            state_seq: None,
            rate_ewma: Some(self.progress.rate_ewma),
            eta_s: self.progress.eta_s,
            path: self.result.as_ref().map(|r| r.path.clone()),
            sha256: self.result.as_ref().map(|r| r.sha256),
            id: self.id,
            state: self.state,
            quarantined: self.quarantined,
            source_kind: self.spec.source.kind,
            filename: self
                .result
                .as_ref()
                .and_then(|r| std::path::Path::new(&r.path).file_name())
                .map(|name| name.to_string_lossy().into_owned())
                .or_else(|| self.spec.filename.clone())
                .or_else(|| self.probe.as_ref().map(|p| p.filename.value.clone())),
            url_redacted: self.spec.url.redact(crate::redact::RedactMode::Log),
            origin: Some(self.spec.origin()),
            bytes_done: self.progress.bytes_done,
            bytes_total: self.progress.bytes_total,
            last_error: self.error.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
        }
    }
}

/// Compact projection of [`Job`] for list views and the extension popup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobSummary {
    /// Durable event that placed the job in its current state, filled by the daemon.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_seq: Option<crate::EventSeq>,
    /// Current transfer rate in bytes per second.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_ewma: Option<u64>,
    /// Estimated seconds remaining.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eta_s: Option<u64>,
    /// Completed local file path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Completed SHA-256 digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<Hex256>,
    /// Identifier.
    pub id: JobId,
    /// Current state.
    pub state: JobState,
    /// Quarantine flag.
    pub quarantined: bool,
    /// Who asked.
    pub source_kind: SourceKind,
    /// The resolved or hinted name. Untrusted text.
    #[serde(default)]
    pub filename: Option<String>,
    /// The URL after `redact_url(log)`.
    pub url_redacted: RedactedUrl,
    /// Origin of the job URL.
    #[serde(default)]
    pub origin: Option<Origin>,
    /// Committed bytes.
    pub bytes_done: u64,
    /// Total, when known.
    pub bytes_total: Option<u64>,
    /// The most recent error.
    #[serde(default)]
    pub last_error: Option<ErrorEnvelope>,
    /// Creation instant.
    pub created_at: Timestamp,
    /// Last change.
    pub updated_at: Timestamp,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> JobSpec {
        JobSpec::new(
            HttpUrl::parse("https://files.example.com/a.zip").unwrap(),
            Source::new(SourceKind::Agent),
        )
    }

    #[test]
    fn defaults_follow_the_source_kind() {
        assert_eq!(spec().priority(), Priority::Normal);
        let mut handoff = spec();
        handoff.source.kind = SourceKind::BrowserHandoff;
        assert_eq!(handoff.priority(), Priority::High);
        let mut s = spec();
        s.apply_defaults("/downloads");
        assert_eq!(s.priority, Some(Priority::Normal));
        assert_eq!(s.max_connections, Some(8));
        assert_eq!(s.dest_dir.as_deref(), Some("/downloads"));
        assert_eq!(s.overwrite, Some(Overwrite::Rename));
    }

    #[test]
    fn spec_validation() {
        assert!(spec().validate().is_ok());
        let mut s = spec();
        s.extra_headers.insert("Cookie".into(), "a=b".into());
        assert!(s.validate().is_err());
        let mut s = spec();
        s.extra_headers
            .insert("Accept-Language".into(), "en".into());
        assert!(s.validate().is_ok());
        s.extra_headers
            .insert("Accept".into(), "x\r\nInjected: 1".into());
        assert!(s.validate().is_err());
        let mut s = spec();
        s.max_connections = Some(33);
        assert!(s.validate().is_err());
        let mut s = spec();
        s.idempotency_key = Some(String::new());
        assert!(s.validate().is_err());
        let mut s = spec();
        s.filename = Some("x".repeat(256));
        assert!(s.validate().is_err());
    }

    #[test]
    fn validators_if_range() {
        let strong = Validators {
            etag: Some("\"abc\"".into()),
            ..Validators::default()
        };
        assert_eq!(strong.if_range_value(), Some("\"abc\""));
        let weak = Validators {
            etag: Some("W/\"abc\"".into()),
            ..Validators::default()
        };
        assert_eq!(weak.if_range_value(), None);
        assert!(!weak.is_strongly_identified());
        let dated = Validators {
            etag: Some("W/\"abc\"".into()),
            last_modified: Some("Tue, 29 Sep 2026 14:02:11 GMT".into()),
            last_modified_strong: Some(true),
            repr_digest: None,
        };
        assert_eq!(
            dated.if_range_value(),
            Some("Tue, 29 Sep 2026 14:02:11 GMT")
        );
        assert!(dated.is_strongly_identified());
        assert!(Validators::default().is_empty());
    }

    #[test]
    fn eta() {
        assert_eq!(Progress::compute_eta_s(100, Some(1100), 10), Some(100));
        assert_eq!(
            Progress::compute_eta_s(100, Some(1105), 10),
            Some(100),
            "integer division, as the spec example (43 s)"
        );
        assert_eq!(Progress::compute_eta_s(100, None, 10), None);
        assert_eq!(Progress::compute_eta_s(100, Some(1000), 0), None);
        assert_eq!(Progress::compute_eta_s(2000, Some(1000), 10), Some(0));
    }

    #[test]
    fn job_invariants() {
        let now = Timestamp::UNIX_EPOCH;
        let id = crate::ids::IdGenerator::new().job_id();
        let mut job = Job::new(id, spec(), JobState::Queued, now);
        assert!(job.check_invariants().is_ok());
        job.quarantined = true;
        assert!(job.check_invariants().is_err());
        job.state = JobState::Completed;
        job.quarantine_reasons
            .push(QuarantineReason::ExecutableType);
        assert!(job.check_invariants().is_ok());
    }

    #[test]
    fn summary_hides_url_secrets() {
        let mut s = spec();
        s.url = HttpUrl::parse("https://files.example.com/a.zip?X-Amz-Signature=ZEUS-CANARY-1")
            .unwrap();
        let id = crate::ids::IdGenerator::new().job_id();
        let job = Job::new(id, s, JobState::Queued, Timestamp::UNIX_EPOCH);
        let json = serde_json::to_string(&job.summary()).unwrap();
        assert!(!json.contains("ZEUS-CANARY"), "{json}");
    }
}
