//! Byte counts, half-open byte ranges and fixed-size digests (00 section 6.3 and 6.4).

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};

use crate::error::TypesError;
use crate::limits::MAX_SAFE_INTEGER;

/// Checks that a byte count or offset is exactly representable in JSON (at most 2^53 - 1).
pub const fn check_wire_u64(value: u64) -> Result<u64, TypesError> {
    if value > MAX_SAFE_INTEGER {
        Err(TypesError::OutOfRange { what: "byte count" })
    } else {
        Ok(value)
    }
}

/// A half-open byte interval `[start, end)` (00 section 6.3 rule 4). The inclusive form of
/// RFC 9110 exists only at the HTTP boundary; convert there with [`ByteRange::from_inclusive`] and
/// [`ByteRange::to_inclusive`] and nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, JsonSchema)]
pub struct ByteRange {
    /// First byte, inclusive.
    pub start: u64,
    /// One past the last byte.
    pub end: u64,
}

impl ByteRange {
    /// Builds a range; `start <= end <= 2^53 - 1`.
    pub const fn new(start: u64, end: u64) -> Result<Self, TypesError> {
        if start > end {
            return Err(TypesError::InvalidRange);
        }
        if end > MAX_SAFE_INTEGER {
            return Err(TypesError::OutOfRange {
                what: "byte offset",
            });
        }
        Ok(Self { start, end })
    }

    /// `[offset, offset + length)`.
    pub fn from_offset_len(offset: u64, length: u64) -> Result<Self, TypesError> {
        let end = offset.checked_add(length).ok_or(TypesError::OutOfRange {
            what: "byte offset",
        })?;
        Self::new(offset, end)
    }

    /// From the inclusive pair of an HTTP `Range` or `Content-Range` header (`first-last`).
    pub fn from_inclusive(first: u64, last: u64) -> Result<Self, TypesError> {
        let end = last.checked_add(1).ok_or(TypesError::OutOfRange {
            what: "byte offset",
        })?;
        Self::new(first, end)
    }

    /// The inclusive `(first, last)` pair for an HTTP header, or `None` for an empty range
    /// (HTTP cannot express one).
    #[must_use]
    pub const fn to_inclusive(self) -> Option<(u64, u64)> {
        if self.start == self.end {
            None
        } else {
            Some((self.start, self.end - 1))
        }
    }

    /// Number of bytes.
    #[must_use]
    pub const fn len(self) -> u64 {
        self.end - self.start
    }

    /// True when the range covers no bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start == self.end
    }

    /// True when `offset` lies inside the range.
    #[must_use]
    pub const fn contains(self, offset: u64) -> bool {
        self.start <= offset && offset < self.end
    }

    /// True when the two ranges share at least one byte.
    #[must_use]
    pub const fn overlaps(self, other: Self) -> bool {
        !self.is_empty() && !other.is_empty() && self.start < other.end && other.start < self.end
    }

    /// True when the two ranges overlap or touch (their union is one interval).
    #[must_use]
    pub const fn touches(self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// The shared bytes, if any.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Option<Self> {
        let start = if self.start > other.start {
            self.start
        } else {
            other.start
        };
        let end = if self.end < other.end {
            self.end
        } else {
            other.end
        };
        if start < end {
            Some(Self { start, end })
        } else {
            None
        }
    }
}

impl<'de> Deserialize<'de> for ByteRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            start: u64,
            end: u64,
        }
        let Raw { start, end } = Raw::deserialize(deserializer)?;
        Self::new(start, end).map_err(de::Error::custom)
    }
}

/// A 32-byte digest (SHA-256 or BLAKE3) that serialises as 64 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hex256([u8; 32]);

impl Hex256 {
    /// Wraps raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lowercase hex text.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for b in self.0 {
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0x0f)]));
        }
        out
    }

    /// Parses 64 lowercase hex characters (uppercase is rejected, 00 section 6.4).
    pub fn from_hex(text: &str) -> Result<Self, TypesError> {
        let bytes = text.as_bytes();
        if bytes.len() != 64 {
            return Err(TypesError::InvalidHex);
        }
        let mut out = [0u8; 32];
        for (i, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
            out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
        }
        Ok(Self(out))
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn nibble(b: u8) -> Result<u8, TypesError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(TypesError::InvalidHex),
    }
}

impl fmt::Display for Hex256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Hex256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hex256({})", self.to_hex())
    }
}

impl FromStr for Hex256 {
    type Err = TypesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for Hex256 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hex256 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <Cow<'de, str>>::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(de::Error::custom)
    }
}

impl JsonSchema for Hex256 {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "Hex256".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "pattern": "^[0-9a-f]{64}$",
            "description": "Lowercase hex of a 32-byte digest (SHA-256 or BLAKE3)."
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn range_basics() {
        let r = ByteRange::new(10, 20).unwrap();
        assert_eq!(r.len(), 10);
        assert!(r.contains(10) && r.contains(19) && !r.contains(20));
        assert_eq!(r.to_inclusive(), Some((10, 19)));
        assert_eq!(ByteRange::from_inclusive(10, 19).unwrap(), r);
        assert_eq!(ByteRange::new(5, 5).unwrap().to_inclusive(), None);
        assert!(ByteRange::new(2, 1).is_err());
        assert!(ByteRange::new(0, MAX_SAFE_INTEGER + 1).is_err());
        assert!(ByteRange::from_offset_len(u64::MAX, 2).is_err());
    }

    #[test]
    fn an_empty_range_overlaps_nothing() {
        // Regression: [254, 254) lies inside [0, 255) but shares no byte with it.
        let empty = ByteRange::new(254, 254).unwrap();
        let big = ByteRange::new(0, 255).unwrap();
        assert!(!empty.overlaps(big) && !big.overlaps(empty));
        assert_eq!(empty.intersection(big), None);
    }

    #[test]
    fn range_relations() {
        let a = ByteRange::new(0, 10).unwrap();
        let b = ByteRange::new(10, 20).unwrap();
        let c = ByteRange::new(5, 15).unwrap();
        assert!(!a.overlaps(b) && a.touches(b));
        assert!(a.overlaps(c) && c.overlaps(b));
        assert_eq!(a.intersection(c), Some(ByteRange::new(5, 10).unwrap()));
        assert_eq!(a.intersection(b), None);
    }

    #[test]
    fn range_serde_validates() {
        let r: ByteRange = serde_json::from_str(r#"{"start":3,"end":9}"#).unwrap();
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"start":3,"end":9}"#);
        assert!(serde_json::from_str::<ByteRange>(r#"{"start":9,"end":3}"#).is_err());
    }

    #[test]
    fn hex_round_trip_and_rejection() {
        let text = "eba4a8587ad422baa9bb314f660b11dfd73563c9af06c6c6ed6ec4bf2da2bc47";
        let h: Hex256 = text.parse().unwrap();
        assert_eq!(h.to_string(), text);
        assert!(Hex256::from_hex(&text.to_uppercase()).is_err());
        assert!(Hex256::from_hex(&text[..63]).is_err());
        assert!(Hex256::from_hex(&format!("{text}0")).is_err());
        assert!(Hex256::from_hex(&"g".repeat(64)).is_err());
    }

    proptest! {
        #[test]
        fn hex_round_trips(bytes in proptest::array::uniform32(any::<u8>())) {
            let h = Hex256::from_bytes(bytes);
            prop_assert_eq!(Hex256::from_hex(&h.to_hex()).unwrap(), h);
            let json = serde_json::to_string(&h).unwrap();
            prop_assert_eq!(serde_json::from_str::<Hex256>(&json).unwrap(), h);
        }

        #[test]
        fn intersection_is_commutative(a in 0u64..1000, b in 0u64..1000, c in 0u64..1000, d in 0u64..1000) {
            let r1 = ByteRange::new(a.min(b), a.max(b)).unwrap();
            let r2 = ByteRange::new(c.min(d), c.max(d)).unwrap();
            prop_assert_eq!(r1.intersection(r2), r2.intersection(r1));
            prop_assert_eq!(r1.overlaps(r2), r1.intersection(r2).is_some());
        }
    }
}
