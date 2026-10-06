//! Retry and scheduling parameters fixed by the specification (01 sections 8.5 and 10).
//!
//! These are *data*: the algorithms that use them (backoff with full jitter, retry budgets, the
//! scheduler) live in `zeus-control` and `zeus-engine`. Keeping the numbers here gives every crate
//! and every test one source of truth.

use crate::error::ErrorClass;

/// Parameters of `delay_ms = max(floor_ms, uniform(0, min(cap_ms, base_ms * 2^(n-1))))`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffSpec {
    /// Base of the exponential envelope in milliseconds.
    pub base_ms: u64,
    /// Cap of the envelope in milliseconds.
    pub cap_ms: u64,
    /// A retry never happens sooner than this.
    pub floor_ms: u64,
}

/// `transient_network`: base 1 s, cap 15 min, floor 250 ms.
pub const TRANSIENT_NETWORK_BACKOFF: BackoffSpec = BackoffSpec {
    base_ms: 1_000,
    cap_ms: 900_000,
    floor_ms: 250,
};
/// `throttled`: base 5 s, cap 15 min, floor 1 s; `Retry-After` raises the delay further.
pub const THROTTLED_BACKOFF: BackoffSpec = BackoffSpec {
    base_ms: 5_000,
    cap_ms: 900_000,
    floor_ms: 1_000,
};
/// `integrity`: a fixed 1 s before the single restart from zero.
pub const INTEGRITY_BACKOFF: BackoffSpec = BackoffSpec {
    base_ms: 1_000,
    cap_ms: 1_000,
    floor_ms: 1_000,
};

/// The backoff of a job error class, if the class backs off (`transient_network`, `throttled`,
/// `integrity`). `auth_expired`, `url_expired` and `blocked` retry only after a refresh; `permanent`
/// and `policy_denied` never retry; `disk` is per code ([`disk_retry`]).
#[must_use]
pub const fn backoff_for_class(class: ErrorClass) -> Option<BackoffSpec> {
    match class {
        ErrorClass::TransientNetwork => Some(TRANSIENT_NETWORK_BACKOFF),
        ErrorClass::Throttled => Some(THROTTLED_BACKOFF),
        ErrorClass::Integrity => Some(INTEGRITY_BACKOFF),
        _ => None,
    }
}

/// Retry parameters of one `fs.*` code (01 section 8.5, "disk parameters by code").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskRetry {
    /// The code these parameters belong to.
    pub code: &'static str,
    /// Backoff base.
    pub base_ms: u64,
    /// Backoff cap.
    pub cap_ms: u64,
    /// Attempts before the job fails.
    pub attempts: u32,
}

/// The retry table of the `disk` class. A code absent from the table (`fs.permission_denied`,
/// `fs.name_invalid`, `fs.dest_missing`, `fs.finalize_lost`) is not retried.
pub const DISK_RETRY: &[DiskRetry] = &[
    DiskRetry {
        code: "fs.busy",
        base_ms: 500,
        cap_ms: 30_000,
        attempts: 10,
    },
    DiskRetry {
        code: "fs.no_space",
        base_ms: 30_000,
        cap_ms: 900_000,
        attempts: 6,
    },
    DiskRetry {
        code: "fs.quota_exceeded",
        base_ms: 30_000,
        cap_ms: 900_000,
        attempts: 6,
    },
    DiskRetry {
        code: "fs.io_error",
        base_ms: 2_000,
        cap_ms: 30_000,
        attempts: 3,
    },
    DiskRetry {
        code: "fs.too_many_open_files",
        base_ms: 1_000,
        cap_ms: 30_000,
        attempts: 10,
    },
];

/// The retry parameters for a disk error code, if it is retried.
#[must_use]
pub fn disk_retry(code: &str) -> Option<DiskRetry> {
    DISK_RETRY.iter().copied().find(|d| d.code == code)
}

/// Budgets and thresholds (01 sections 3.8 and 8.5).
pub mod budgets {
    /// Session or URL refreshes before escalating to a `retry_escalation` approval.
    pub const AUTH_REFRESHES: u32 = 3;
    /// Switches to the in-browser proxy per job.
    pub const PROXY_ESCALATIONS: u32 = 1;
    /// Restarts from zero after a hash or size mismatch.
    pub const INTEGRITY_RESTARTS: u32 = 1;
    /// Restarts after the resource changed upstream.
    pub const RESOURCE_RESTARTS: u32 = 2;
    /// Daemon-restart recoveries without committed progress before `engine.crash_loop` (S96).
    pub const RECOVERIES_BEFORE_CRASH_LOOP: u32 = 3;
    /// Consecutive throttles without progress before failing.
    pub const THROTTLES_WITHOUT_PROGRESS: u32 = 20;
    /// Consecutive `5xx` responses without progress before giving up (rule R1).
    pub const CONSECUTIVE_5XX: u32 = 10;
    /// Consecutive `net.dns_nxdomain` before `net.host_not_found` (rule R3).
    pub const NXDOMAIN_BEFORE_PERMANENT: u32 = 3;
    /// Consecutive TLS handshake failures before `tls.handshake_blocked` (rule R4).
    pub const HANDSHAKE_FAILURES_BEFORE_BLOCKED: u32 = 3;
    /// Consecutive premature EOFs at one offset before `integrity.size_mismatch` (rule R5).
    pub const PREMATURE_EOF_AT_SAME_OFFSET: u32 = 5;
    /// New committed bytes that reset `consecutive_failures`.
    pub const PROGRESS_RESET_BYTES: u64 = 64 * 1024;
    /// New committed bytes after a refresh that reset `auth_refreshes`.
    pub const AUTH_REFRESH_RESET_BYTES: u64 = 1024 * 1024;
    /// A `transient_network` job that makes no progress for this long fails (24 h).
    pub const TRANSIENT_STALL_LIMIT_MS: u64 = 86_400_000;
    /// A `Retry-After` above this fails the job with `http.retry_after_too_long` (24 h).
    pub const MAX_RETRY_AFTER_MS: u64 = 86_400_000;
    /// Default `awaiting_session` wait (1 h).
    pub const SESSION_WAIT_MS: u64 = 3_600_000;
    /// Stall watchdog: `probing` for longer than this fails over (45 s).
    pub const PROBE_DEADLINE_MS: u64 = 45_000;
    /// Stall watchdog: `downloading` with no committed and no network byte for this long (60 s).
    pub const DOWNLOAD_STALL_MS: u64 = 60_000;
    /// Wait for a session lease inside `probing` (15 s, the native-messaging timeout).
    pub const LEASE_WAIT_MS: u64 = 15_000;
}

/// Scheduling defaults (01 section 10).
pub mod scheduling {
    /// Concurrent jobs, global.
    pub const CONCURRENT_JOBS: u32 = 4;
    /// Connections per job.
    pub const CONNECTIONS_PER_JOB: u32 = 8;
    /// Connections per host, global.
    pub const CONNECTIONS_PER_HOST: u32 = 8;
    /// Segment size, bytes (16 MiB).
    pub const SEGMENT_BYTES: u64 = 16 * 1024 * 1024;
    /// Smallest adaptive segment size (8 MiB).
    pub const SEGMENT_MIN_BYTES: u64 = 8 * 1024 * 1024;
    /// Largest adaptive segment size (32 MiB).
    pub const SEGMENT_MAX_BYTES: u64 = 32 * 1024 * 1024;
    /// A worker that idles steals when more than this many bytes remain in the largest segment (4 MiB).
    pub const STEAL_THRESHOLD_BYTES: u64 = 4 * 1024 * 1024;
    /// Connect timeout.
    pub const CONNECT_TIMEOUT_MS: u64 = 15_000;
    /// Idle read timeout.
    pub const READ_TIMEOUT_MS: u64 = 30_000;
    /// Job tombstone retention (30 days).
    pub const TOMBSTONE_RETENTION_MS: u64 = 30 * 86_400_000;
    /// EWMA smoothing factor of the progress rate.
    pub const RATE_EWMA_ALPHA: f64 = 0.2;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_table() {
        assert_eq!(
            backoff_for_class(ErrorClass::TransientNetwork)
                .unwrap()
                .floor_ms,
            250
        );
        assert_eq!(
            backoff_for_class(ErrorClass::Throttled).unwrap().base_ms,
            5_000
        );
        assert!(backoff_for_class(ErrorClass::Permanent).is_none());
        assert!(backoff_for_class(ErrorClass::AuthExpired).is_none());
    }

    #[test]
    fn disk_table_covers_only_retried_codes() {
        for code in [
            "fs.busy",
            "fs.no_space",
            "fs.quota_exceeded",
            "fs.io_error",
            "fs.too_many_open_files",
        ] {
            let spec = disk_retry(code).unwrap();
            assert!(spec.base_ms <= spec.cap_ms && spec.attempts > 0);
            // Every retried code is registered as retryable.
            assert_eq!(
                crate::error::lookup(code).map(|i| i.retryable),
                Some(true),
                "{code}"
            );
        }
        for code in [
            "fs.permission_denied",
            "fs.name_invalid",
            "fs.dest_missing",
            "fs.finalize_lost",
        ] {
            assert!(disk_retry(code).is_none());
            assert_eq!(
                crate::error::lookup(code).map(|i| i.retryable),
                Some(false),
                "{code}"
            );
        }
    }
}
