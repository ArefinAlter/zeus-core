//! Instants (00 section 6.1): RFC 3339, UTC only, exactly three fractional digits.
//!
//! [`Timestamp`] is a wall-clock instant stored as milliseconds since the Unix epoch. Wall-clock
//! instants are for display, for deadlines that must survive a restart and for ordering across
//! processes; elapsed time inside one process is measured with a monotonic clock (see the
//! `Clock` trait in `zeus-control`), never by subtracting timestamps.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::TypesError;

/// Smallest representable instant: `0000-01-01T00:00:00.000Z`.
pub const MIN_UNIX_MS: i64 = -62_167_219_200_000;
/// Largest representable instant: `9999-12-31T23:59:59.999Z`.
pub const MAX_UNIX_MS: i64 = 253_402_300_799_999;

/// A wall-clock instant with millisecond resolution.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Timestamp(i64);

impl Timestamp {
    /// The Unix epoch, `1970-01-01T00:00:00.000Z`.
    pub const UNIX_EPOCH: Self = Self(0);

    /// From milliseconds since the Unix epoch. Fails outside years 0000 to 9999.
    pub const fn from_unix_millis(ms: i64) -> Result<Self, TypesError> {
        if ms < MIN_UNIX_MS || ms > MAX_UNIX_MS {
            Err(TypesError::InvalidTimestamp)
        } else {
            Ok(Self(ms))
        }
    }

    /// Milliseconds since the Unix epoch.
    #[must_use]
    pub const fn unix_millis(self) -> i64 {
        self.0
    }

    /// The current wall-clock time (saturating at the representable range). Production code takes
    /// time from an injected `Clock`; this exists for that clock's system implementation.
    #[must_use]
    pub fn now() -> Self {
        let ms = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_millis()).unwrap_or(MAX_UNIX_MS),
            Err(e) => -i64::try_from(e.duration().as_millis()).unwrap_or(i64::MAX),
        };
        Self(ms.clamp(MIN_UNIX_MS, MAX_UNIX_MS))
    }

    /// Parses RFC 3339. Accepts zero to nine fractional digits and any offset, and normalises to
    /// UTC with the fraction truncated to milliseconds (00 section 6.1: parsers SHOULD accept this).
    pub fn parse(text: &str) -> Result<Self, TypesError> {
        if !text
            .as_bytes()
            .get(10)
            .is_some_and(|b| matches!(b, b'T' | b't'))
        {
            return Err(TypesError::InvalidTimestamp);
        }
        let parsed =
            OffsetDateTime::parse(text, &Rfc3339).map_err(|_| TypesError::InvalidTimestamp)?;
        let nanos = parsed.unix_timestamp_nanos();
        let ms =
            i64::try_from(nanos.div_euclid(1_000_000)).map_err(|_| TypesError::InvalidTimestamp)?;
        Self::from_unix_millis(ms)
    }

    /// The canonical wire form, for example `2026-10-05T09:15:30.250Z`.
    #[must_use]
    pub fn to_rfc3339(self) -> String {
        let dt = OffsetDateTime::from_unix_timestamp_nanos(i128::from(self.0) * 1_000_000)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH);
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
            dt.year(),
            u8::from(dt.month()),
            dt.day(),
            dt.hour(),
            dt.minute(),
            dt.second(),
            dt.millisecond()
        )
    }

    /// `self + duration`, or `None` when the result leaves the representable range.
    #[must_use]
    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        let ms = i64::try_from(duration.as_millis()).ok()?;
        Self::from_unix_millis(self.0.checked_add(ms)?).ok()
    }

    /// `self - duration`, or `None` when the result leaves the representable range.
    #[must_use]
    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        let ms = i64::try_from(duration.as_millis()).ok()?;
        Self::from_unix_millis(self.0.checked_sub(ms)?).ok()
    }

    /// `self + ms`, saturating at the largest instant.
    #[must_use]
    pub fn saturating_add_ms(self, ms: u64) -> Self {
        let ms = i64::try_from(ms).unwrap_or(i64::MAX);
        Self(self.0.saturating_add(ms).min(MAX_UNIX_MS))
    }

    /// Time elapsed from `earlier` to `self`, or `None` when `earlier` is later (a wall-clock step
    /// backwards must not become a negative duration).
    #[must_use]
    pub fn duration_since(self, earlier: Self) -> Option<Duration> {
        u64::try_from(self.0 - earlier.0)
            .ok()
            .map(Duration::from_millis)
    }

    /// Milliseconds remaining until `deadline`, clamped to zero when it has passed
    /// (00 section 6.2 rule 3: a negative remainder is zero).
    #[must_use]
    pub fn remaining_until(self, deadline: Self) -> u64 {
        u64::try_from(deadline.0 - self.0).unwrap_or(0)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

impl fmt::Debug for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Timestamp({})", self.to_rfc3339())
    }
}

impl FromStr for Timestamp {
    type Err = TypesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_rfc3339())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <Cow<'de, str>>::deserialize(deserializer)?;
        Self::parse(&s).map_err(de::Error::custom)
    }
}

impl JsonSchema for Timestamp {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "Timestamp".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "description": "RFC 3339 UTC instant with exactly three fractional digits and the Z designator.",
            "pattern": "^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)\\.[0-9]{3}Z$"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_form_has_three_digits() {
        let t = Timestamp::parse("2026-10-05T09:15:30.250Z").unwrap();
        assert_eq!(t.to_rfc3339(), "2026-10-05T09:15:30.250Z");
        assert_eq!(
            Timestamp::from_unix_millis(0).unwrap().to_string(),
            "1970-01-01T00:00:00.000Z"
        );
        assert_eq!(
            Timestamp::from_unix_millis(1).unwrap().to_string(),
            "1970-01-01T00:00:00.001Z"
        );
    }

    #[test]
    fn parser_normalises_offsets_and_fractions() {
        let a = Timestamp::parse("2026-10-05T11:15:30.2509+02:00").unwrap();
        assert_eq!(a.to_rfc3339(), "2026-10-05T09:15:30.250Z");
        let b = Timestamp::parse("2026-10-05T09:15:30Z").unwrap();
        assert_eq!(b.to_rfc3339(), "2026-10-05T09:15:30.000Z");
        assert!(Timestamp::parse("2026-10-05 09:15:30Z").is_err());
        assert!(Timestamp::parse("not a time").is_err());
    }

    #[test]
    fn range_limits() {
        assert_eq!(
            Timestamp::from_unix_millis(MAX_UNIX_MS)
                .unwrap()
                .to_string(),
            "9999-12-31T23:59:59.999Z"
        );
        assert_eq!(
            Timestamp::from_unix_millis(MIN_UNIX_MS)
                .unwrap()
                .to_string(),
            "0000-01-01T00:00:00.000Z"
        );
        assert!(Timestamp::from_unix_millis(MAX_UNIX_MS + 1).is_err());
        assert!(Timestamp::from_unix_millis(MIN_UNIX_MS - 1).is_err());
    }

    #[test]
    fn pre_epoch_instants_round_trip() {
        let t = Timestamp::from_unix_millis(-1).unwrap();
        assert_eq!(t.to_string(), "1969-12-31T23:59:59.999Z");
        assert_eq!(Timestamp::parse(&t.to_string()).unwrap(), t);
    }

    #[test]
    fn arithmetic_is_checked() {
        let t = Timestamp::parse("2026-10-05T09:15:30.250Z").unwrap();
        let later = t.checked_add(Duration::from_millis(750)).unwrap();
        assert_eq!(later.to_string(), "2026-10-05T09:15:31.000Z");
        assert_eq!(later.duration_since(t), Some(Duration::from_millis(750)));
        assert_eq!(t.duration_since(later), None);
        assert_eq!(t.remaining_until(later), 750);
        assert_eq!(later.remaining_until(t), 0);
        assert!(
            Timestamp::from_unix_millis(MAX_UNIX_MS)
                .unwrap()
                .checked_add(Duration::from_millis(1))
                .is_none()
        );
        assert_eq!(
            Timestamp::from_unix_millis(MAX_UNIX_MS)
                .unwrap()
                .saturating_add_ms(u64::MAX)
                .unix_millis(),
            MAX_UNIX_MS
        );
    }

    #[test]
    fn serde_round_trip_and_rejection() {
        let t = Timestamp::parse("2026-10-05T09:15:30.250Z").unwrap();
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"2026-10-05T09:15:30.250Z\"");
        assert_eq!(serde_json::from_str::<Timestamp>(&json).unwrap(), t);
        assert!(serde_json::from_str::<Timestamp>("123").is_err());
    }

    #[test]
    fn now_is_plausible() {
        assert!(Timestamp::now().unix_millis() > 1_700_000_000_000);
    }
}
