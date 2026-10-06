//! Normative numeric limits (00 section 10). A conforming receiver rejects anything above these
//! maxima; configuration may lower defaults but never raise a hard maximum.

/// Largest integer every JSON implementation represents exactly (2^53 - 1). Applies to byte
/// counts, offsets, durations in milliseconds and event sequence numbers.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// JSON nesting depth receivers accept.
pub const MAX_JSON_DEPTH: usize = 32;
/// Native-messaging frame, daemon to extension (browser limit is "1 MB"; the smaller reading is used).
pub const MAX_FRAME_TO_EXTENSION_BYTES: usize = 1_000_000;
/// Native-messaging frame, extension to daemon (4 MiB; browsers allow far more).
pub const MAX_FRAME_TO_DAEMON_BYTES: usize = 4 * 1024 * 1024;
/// Local API request body.
pub const MAX_API_REQUEST_BYTES: usize = 1024 * 1024;
/// Local API response body; larger results are paged.
pub const MAX_API_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// URL length in bytes after punycode and percent-encoding.
pub const MAX_URL_BYTES: usize = 8192;
/// Origin length in bytes.
pub const MAX_ORIGIN_BYTES: usize = 300;
/// File name length in UTF-8 bytes (one path component).
pub const MAX_FILE_NAME_BYTES: usize = 255;
/// Path length in bytes.
pub const MAX_PATH_BYTES: usize = 4096;
/// HTTP header value carried in a message.
pub const MAX_HEADER_VALUE_BYTES: usize = 8192;
/// Cookie name length in bytes.
pub const MAX_COOKIE_NAME_BYTES: usize = 256;
/// Cookie value length in bytes.
pub const MAX_COOKIE_VALUE_BYTES: usize = 8192;
/// Cookies in one session response.
pub const MAX_COOKIES_PER_SESSION: usize = 150;
/// Serialised size of the cookies in one session response.
pub const MAX_COOKIES_SERIALISED_BYTES: usize = 128 * 1024;
/// Error `message` length in characters.
pub const MAX_ERROR_MESSAGE_CHARS: usize = 1024;
/// Error `details` size when serialised.
pub const MAX_ERROR_DETAILS_BYTES: usize = 8 * 1024;
/// Event `data` size when serialised.
pub const MAX_EVENT_DATA_BYTES: usize = 64 * 1024;
/// `idempotency_key` length in characters.
pub const MAX_IDEMPOTENCY_KEY_CHARS: usize = 128;
/// Labels per job.
pub const MAX_LABELS_PER_JOB: usize = 16;
/// Label key and value length in characters.
pub const MAX_LABEL_CHARS: usize = 256;
/// Extra request headers per job.
pub const MAX_EXTRA_HEADERS_PER_JOB: usize = 16;
/// Default page size of list calls.
pub const DEFAULT_PAGE_SIZE: usize = 50;
/// Maximum page size of list calls.
pub const MAX_PAGE_SIZE: usize = 100;
/// Concurrent native-messaging streams per connection (default 4).
pub const MAX_CONCURRENT_STREAMS: usize = 8;
/// Session material time to live per release: 15 minutes.
pub const MAX_SESSION_TTL_MS: u64 = 900_000;
/// Redirects followed.
pub const MAX_REDIRECTS: u8 = 10;
/// Approvals pending at once (01 section 5.3 rule 4).
pub const MAX_PENDING_APPROVALS: usize = 50;
/// Native-messaging connections at once (02 section 5 rule 6).
pub const MAX_NM_CONNECTIONS: usize = 8;
/// MCP tool name length (00 section 3).
pub const MAX_MCP_TOOL_NAME_CHARS: usize = 64;

/// Grant lifetimes (01 section 5.1).
pub mod grants {
    /// A `site` grant lives 24 hours.
    pub const SITE_TTL_MS: u64 = 86_400_000;
    /// A `workflow` grant lives 7 days from creation or last renewal.
    pub const WORKFLOW_TTL_MS: u64 = 604_800_000;
    /// A `once` grant never outlives 24 hours even if its job does.
    pub const ONCE_MAX_MS: u64 = 86_400_000;
}
