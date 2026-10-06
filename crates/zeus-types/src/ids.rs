//! Identifiers (00 section 5): prefixed ULIDs, the event sequence number and a monotonic generator.
//!
//! Identifiers are opaque. Only the daemon (or an embedding of `zeus-core`) mints them, through
//! [`IdGenerator`]; everything else parses them with `FromStr` or serde, which accept exactly the
//! pattern in `common.schema.json` (uppercase Crockford base32, first character `0` to `7`).

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};
use ulid::Ulid;

use crate::error::TypesError;
use crate::limits::MAX_SAFE_INTEGER;

const ULID_LEN: usize = 26;
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Validates the 26 character body of a ULID (uppercase Crockford base32, first character `0`-`7`).
fn parse_ulid_body(body: &str, kind: &'static str) -> Result<Ulid, TypesError> {
    let bytes = body.as_bytes();
    let first_ok = bytes.first().is_some_and(|b| (b'0'..=b'7').contains(b));
    if bytes.len() != ULID_LEN || !first_ok || !bytes.iter().all(|b| CROCKFORD.contains(b)) {
        return Err(TypesError::InvalidId { kind });
    }
    Ulid::from_string(body).map_err(|_| TypesError::InvalidId { kind })
}

macro_rules! prefixed_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Ulid);

        impl $name {
            /// The lowercase prefix, without the underscore.
            pub const PREFIX: &'static str = $prefix;

            /// Wraps an existing ULID. Prefer [`IdGenerator`] for new identifiers.
            #[must_use]
            pub const fn from_ulid(ulid: Ulid) -> Self {
                Self(ulid)
            }

            /// The underlying ULID.
            #[must_use]
            pub const fn ulid(&self) -> Ulid {
                self.0
            }

            /// Creation time in milliseconds since the Unix epoch. Display and sorting only,
            /// never a security decision (00 section 5.1 rule 2).
            #[must_use]
            pub const fn timestamp_ms(&self) -> u64 {
                self.0.timestamp_ms()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let mut buf = [0u8; ULID_LEN];
                write!(f, concat!($prefix, "_{}"), self.0.array_to_str(&mut buf))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self)
            }
        }

        impl FromStr for $name {
            type Err = TypesError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let body = s
                    .strip_prefix(concat!($prefix, "_"))
                    .ok_or(TypesError::InvalidId { kind: stringify!($name) })?;
                parse_ulid_body(body, stringify!($name)).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = <Cow<'de, str>>::deserialize(deserializer)?;
                s.parse().map_err(de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn inline_schema() -> bool {
                true
            }

            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }

            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({
                    "type": "string",
                    "pattern": concat!("^", $prefix, "_[0-7][0-9A-HJKMNP-TV-Z]{25}$"),
                    "description": concat!("Identifier with the prefix `", $prefix, "_` followed by a 26 character ULID.")
                })
            }
        }
    };
}

prefixed_id!(
    /// One download job (`job_<ULID>`).
    JobId,
    "job"
);
prefixed_id!(
    /// One workflow run (`run_<ULID>`), groups the jobs of an approved plan.
    RunId,
    "run"
);
prefixed_id!(
    /// A session grant, the recorded consent (`gr_<ULID>`). Never contains cookies.
    GrantId,
    "gr"
);
prefixed_id!(
    /// One pending or decided human approval (`ap_<ULID>`).
    ApprovalId,
    "ap"
);
prefixed_id!(
    /// Handle for one release of session material (`sess_<ULID>`). Safe to log; the material it
    /// names is never persisted.
    SessionLeaseId,
    "sess"
);
prefixed_id!(
    /// A native-messaging connection (`conn_<ULID>`), for logs.
    ConnectionId,
    "conn"
);
prefixed_id!(
    /// One audit hash chain (`chain_<ULID>`).
    ChainId,
    "chain"
);

/// Identifier of one journal store: a bare ULID without a prefix (`meta.store_id`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StoreId(Ulid);

impl StoreId {
    /// Wraps an existing ULID.
    #[must_use]
    pub const fn from_ulid(ulid: Ulid) -> Self {
        Self(ulid)
    }

    /// The underlying ULID.
    #[must_use]
    pub const fn ulid(&self) -> Ulid {
        self.0
    }
}

impl fmt::Display for StoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = [0u8; ULID_LEN];
        f.write_str(self.0.array_to_str(&mut buf))
    }
}

impl fmt::Debug for StoreId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StoreId({self})")
    }
}

impl FromStr for StoreId {
    type Err = TypesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_ulid_body(s, "StoreId").map(Self)
    }
}

impl Serialize for StoreId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for StoreId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <Cow<'de, str>>::deserialize(deserializer)?;
        s.parse().map_err(de::Error::custom)
    }
}

impl JsonSchema for StoreId {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "StoreId".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "string", "pattern": "^[0-7][0-9A-HJKMNP-TV-Z]{25}$" })
    }
}

/// Monotonic event sequence number (00 section 5.2): positive, strictly increasing, below 2^53.
///
/// JSON carries it as an integer; URIs, cursors and logs use `ev_<decimal>` ([`Display`](fmt::Display)).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventSeq(u64);

impl EventSeq {
    /// The first sequence number a fresh store allocates.
    pub const FIRST: Self = Self(1);
    /// The largest representable sequence number (2^53 - 1).
    pub const MAX: Self = Self(MAX_SAFE_INTEGER);

    /// Validates a raw value (1 through 2^53 - 1).
    pub const fn new(value: u64) -> Result<Self, TypesError> {
        if value == 0 || value > MAX_SAFE_INTEGER {
            Err(TypesError::OutOfRange {
                what: "event sequence",
            })
        } else {
            Ok(Self(value))
        }
    }

    /// The raw value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The next sequence number, or `None` at the 2^53 - 1 limit.
    #[must_use]
    pub const fn next(self) -> Option<Self> {
        if self.0 >= MAX_SAFE_INTEGER {
            None
        } else {
            Some(Self(self.0 + 1))
        }
    }
}

impl fmt::Display for EventSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ev_{}", self.0)
    }
}

impl fmt::Debug for EventSeq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventSeq({})", self.0)
    }
}

impl FromStr for EventSeq {
    type Err = TypesError;

    /// Accepts the textual form `ev_<decimal>` with no leading zeros.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let digits = s
            .strip_prefix("ev_")
            .ok_or(TypesError::InvalidId { kind: "EventSeq" })?;
        let canonical = !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
            && (digits == "0" || !digits.starts_with('0'));
        if !canonical {
            return Err(TypesError::InvalidId { kind: "EventSeq" });
        }
        let value: u64 = digits
            .parse()
            .map_err(|_| TypesError::InvalidId { kind: "EventSeq" })?;
        Self::new(value)
    }
}

impl Serialize for EventSeq {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for EventSeq {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

impl JsonSchema for EventSeq {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "EventSeq".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "integer", "minimum": 1, "maximum": MAX_SAFE_INTEGER })
    }
}

/// Mints identifiers. Monotonic: every ULID it returns is strictly greater than the previous one,
/// so identifiers sort by creation order even within one millisecond (00 section 5.1).
///
/// Thread safe. Share one generator per process (inside the engine) rather than creating many.
#[derive(Debug, Default)]
pub struct IdGenerator {
    last: Mutex<u128>,
}

impl IdGenerator {
    /// A generator with no history.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the next ULID using the system clock and the CSPRNG of the `ulid` crate.
    #[must_use]
    pub fn next_ulid(&self) -> Ulid {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        self.next_ulid_at(now_ms, Ulid::generate().random())
    }

    /// Deterministic variant for tests: the caller supplies the millisecond timestamp and the 80
    /// random bits (higher bits are discarded). The result is still strictly monotonic.
    #[must_use]
    pub fn next_ulid_at(&self, unix_ms: u64, random80: u128) -> Ulid {
        let candidate = Ulid::from_parts(unix_ms, random80).0;
        // A poisoned lock only means another thread panicked while holding a plain integer.
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next = if candidate > *last {
            candidate
        } else {
            last.checked_add(1).unwrap_or(candidate)
        };
        *last = next;
        Ulid(next)
    }

    /// A fresh [`JobId`].
    #[must_use]
    pub fn job_id(&self) -> JobId {
        JobId(self.next_ulid())
    }

    /// A fresh [`RunId`].
    #[must_use]
    pub fn run_id(&self) -> RunId {
        RunId(self.next_ulid())
    }

    /// A fresh [`GrantId`].
    #[must_use]
    pub fn grant_id(&self) -> GrantId {
        GrantId(self.next_ulid())
    }

    /// A fresh [`ApprovalId`].
    #[must_use]
    pub fn approval_id(&self) -> ApprovalId {
        ApprovalId(self.next_ulid())
    }

    /// A fresh [`SessionLeaseId`].
    #[must_use]
    pub fn session_lease_id(&self) -> SessionLeaseId {
        SessionLeaseId(self.next_ulid())
    }

    /// A fresh [`ConnectionId`].
    #[must_use]
    pub fn connection_id(&self) -> ConnectionId {
        ConnectionId(self.next_ulid())
    }

    /// A fresh [`ChainId`].
    #[must_use]
    pub fn chain_id(&self) -> ChainId {
        ChainId(self.next_ulid())
    }

    /// A fresh [`StoreId`].
    #[must_use]
    pub fn store_id(&self) -> StoreId {
        StoreId(self.next_ulid())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_example_round_trips() {
        let id: JobId = "job_01M45MN5M0PZ0D9W0APDCGRNZD".parse().unwrap();
        assert_eq!(id.to_string(), "job_01M45MN5M0PZ0D9W0APDCGRNZD");
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"job_01M45MN5M0PZ0D9W0APDCGRNZD\"");
        assert_eq!(serde_json::from_str::<JobId>(&json).unwrap(), id);
    }

    #[test]
    fn rejects_malformed_ids() {
        for bad in [
            "",
            "job_",
            "job_01M45MN5M0PZ0D9W0APDCGRNZ",   // too short
            "job_01M45MN5M0PZ0D9W0APDCGRNZDD", // too long
            "job_01m45mn5m0pz0d9w0apdcgrnzd",  // lowercase
            "job_81M45MN5M0PZ0D9W0APDCGRNZD",  // first character above 7
            "job_01M45MN5M0PZ0D9W0APDCGRNZU",  // U is not in the alphabet
            "run_01M45MN5M0PZ0D9W0APDCGRNZD",  // wrong prefix
            "01M45MN5M0PZ0D9W0APDCGRNZD",      // no prefix
        ] {
            assert!(bad.parse::<JobId>().is_err(), "{bad} must be rejected");
        }
    }

    #[test]
    fn prefixes_are_distinct_types() {
        assert!("gr_01M45NHPJP04TX6B1CJVQVQAK9".parse::<GrantId>().is_ok());
        assert!(
            "ap_01M45NHJ3XS0QXG9T42HHN2YR8"
                .parse::<ApprovalId>()
                .is_ok()
        );
        assert!(
            "sess_01M45NHQTC78XWWC8N35Y2BPEA"
                .parse::<SessionLeaseId>()
                .is_ok()
        );
        assert!(
            "conn_01M45NGARG09NTCP2S5QFQEN6J"
                .parse::<ConnectionId>()
                .is_ok()
        );
        assert!(
            "chain_01M3TC5H007DRT2QA1P1NY311K"
                .parse::<ChainId>()
                .is_ok()
        );
        assert!("01M2YVHK60EHVSRRHA6BW4QCWM".parse::<StoreId>().is_ok());
        assert!("gr_01M45NHPJP04TX6B1CJVQVQAK9".parse::<JobId>().is_err());
    }

    #[test]
    fn event_seq_text_form() {
        assert_eq!("ev_48213".parse::<EventSeq>().unwrap().get(), 48213);
        assert_eq!(EventSeq::new(7).unwrap().to_string(), "ev_7");
        for bad in [
            "ev_0",
            "ev_007",
            "ev_",
            "48213",
            "ev_-1",
            "ev_9007199254740992",
        ] {
            assert!(bad.parse::<EventSeq>().is_err(), "{bad}");
        }
        assert!(EventSeq::new(0).is_err());
        assert!(EventSeq::MAX.next().is_none());
        assert_eq!(EventSeq::FIRST.next().unwrap().get(), 2);
    }

    #[test]
    fn generator_is_strictly_monotonic_even_with_a_stuck_clock() {
        let generator = IdGenerator::new();
        let mut previous = generator.next_ulid_at(1_000, 5);
        for _ in 0..1_000 {
            let next = generator.next_ulid_at(1_000, 0);
            assert!(next > previous);
            previous = next;
        }
        // A clock that steps backwards still never yields a smaller identifier.
        assert!(generator.next_ulid_at(1, 0) > previous);
    }

    #[test]
    fn generated_ids_parse_back() {
        let generator = IdGenerator::new();
        let id = generator.job_id();
        assert_eq!(id.to_string().parse::<JobId>().unwrap(), id);
        let a = generator.job_id();
        let b = generator.job_id();
        assert!(b > a);
    }
}
