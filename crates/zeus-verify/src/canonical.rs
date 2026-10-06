//! Canonical JSON for hashing (00 section 7): RFC 8785 (JCS).
//!
//! Hashed documents MUST NOT contain floating-point numbers, `NaN`, infinities, integers outside
//! +/- (2^53 - 1) or duplicate object keys. [`check_hashable`] enforces the first three on a parsed
//! value; duplicate keys must be rejected by the parser that feeds a hash (`serde_json::Value`
//! silently keeps the last one, so use [`parse_hashable`]).

use serde::Serialize;
use serde_json::Value;
use zeus_types::Hex256;
use zeus_types::limits::MAX_SAFE_INTEGER;

use crate::error::{VerifyError, VerifyResult};

/// The JCS serialisation of `value` as UTF-8 bytes. Does not check the hashing rules; use
/// [`check_hashable`] first for documents that are hashed.
pub fn to_jcs_bytes<T: Serialize>(value: &T) -> VerifyResult<Vec<u8>> {
    Ok(serde_json_canonicalizer::to_vec(value)?)
}

/// Rejects floats, non-finite numbers and integers outside +/- (2^53 - 1), anywhere in `value`.
pub fn check_hashable(value: &Value) -> VerifyResult<()> {
    match value {
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                if u > MAX_SAFE_INTEGER {
                    return Err(VerifyError::NotCanonical("integer above 2^53 - 1"));
                }
            } else if let Some(i) = n.as_i64() {
                if i.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(VerifyError::NotCanonical("integer below -(2^53 - 1)"));
                }
            } else {
                return Err(VerifyError::NotCanonical("floating-point number"));
            }
            Ok(())
        }
        Value::Array(items) => items.iter().try_for_each(check_hashable),
        Value::Object(map) => map.values().try_for_each(check_hashable),
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
    }
}

/// Parses JSON text for hashing: rejects duplicate object keys and then applies [`check_hashable`].
pub fn parse_hashable(text: &str) -> VerifyResult<Value> {
    // serde_json::Value keeps the last of duplicate keys, so scan for duplicates separately.
    reject_duplicate_keys(text)?;
    let value: Value = serde_json::from_str(text)?;
    check_hashable(&value)?;
    Ok(value)
}

/// Fails when any object in `text` has the same key twice.
pub fn reject_duplicate_keys(text: &str) -> VerifyResult<()> {
    use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
    use std::collections::HashSet;
    use std::fmt;

    struct Strict;

    impl<'de> DeserializeSeed<'de> for Strict {
        type Value = ();

        fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
            deserializer.deserialize_any(StrictVisitor)
        }
    }

    struct StrictVisitor;

    impl<'de> Visitor<'de> for StrictVisitor {
        type Value = ();

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("any JSON value")
        }

        fn visit_bool<E>(self, _: bool) -> Result<(), E> {
            Ok(())
        }
        fn visit_i64<E>(self, _: i64) -> Result<(), E> {
            Ok(())
        }
        fn visit_u64<E>(self, _: u64) -> Result<(), E> {
            Ok(())
        }
        fn visit_f64<E>(self, _: f64) -> Result<(), E> {
            Ok(())
        }
        fn visit_str<E>(self, _: &str) -> Result<(), E> {
            Ok(())
        }
        fn visit_unit<E>(self) -> Result<(), E> {
            Ok(())
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
            while seq.next_element_seed(Strict)?.is_some() {}
            Ok(())
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
            let mut seen = HashSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !seen.insert(key) {
                    return Err(serde::de::Error::custom("duplicate object key"));
                }
                map.next_value_seed(Strict)?;
            }
            Ok(())
        }
    }

    let mut de = serde_json::Deserializer::from_str(text);
    Strict
        .deserialize(&mut de)
        .map_err(|_| VerifyError::NotCanonical("duplicate object key or invalid JSON"))?;
    de.end()
        .map_err(|_| VerifyError::NotCanonical("trailing characters after the JSON document"))
}

/// The request hash of 00 section 5.4 and 07: BLAKE3 of the JCS form of `value`.
pub fn request_hash(value: &Value) -> VerifyResult<Hex256> {
    check_hashable(value)?;
    Ok(Hex256::from_bytes(
        *blake3::hash(&to_jcs_bytes(value)?).as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn rfc8785_key_order_and_number_forms() {
        let v: Value = serde_json::from_str(
            r#"{"b": false, "c": 12e1, "a": "Hello!", "€": 1, "z": [3, 2, 1]}"#,
        )
        .unwrap();
        // 12e1 parses as a float 120.0; JCS prints it as 120.
        assert_eq!(
            String::from_utf8(to_jcs_bytes(&v).unwrap()).unwrap(),
            "{\"a\":\"Hello!\",\"b\":false,\"c\":120,\"z\":[3,2,1],\"\u{20ac}\":1}"
        );
    }

    #[test]
    fn hashing_rules_are_enforced() {
        assert!(check_hashable(&json!({"a": [1, -2, null, true, "x"]})).is_ok());
        assert!(check_hashable(&json!({"a": 1.5})).is_err());
        assert!(check_hashable(&json!({"a": 9_007_199_254_740_992u64})).is_err());
        assert!(check_hashable(&json!({"a": -9_007_199_254_740_992i64})).is_err());
        assert!(check_hashable(&json!({"a": 9_007_199_254_740_991u64})).is_ok());
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        assert!(parse_hashable(r#"{"a":1,"a":2}"#).is_err());
        assert!(parse_hashable(r#"{"a":{"b":1,"b":2}}"#).is_err());
        assert!(parse_hashable(r#"{"a":[{"b":1},{"b":2}]}"#).is_ok());
        assert!(parse_hashable(r#"{"a":1} trailing"#).is_err());
        assert!(parse_hashable(r#"{"a":1.5}"#).is_err());
    }

    #[test]
    fn request_hash_ignores_key_order_and_whitespace() {
        let a = request_hash(&json!({"x": 1, "y": [1, 2]})).unwrap();
        let b =
            request_hash(&serde_json::from_str::<Value>("{ \"y\": [1,2],\n \"x\": 1 }").unwrap())
                .unwrap();
        assert_eq!(a, b);
        assert_ne!(a, request_hash(&json!({"x": 2, "y": [1, 2]})).unwrap());
    }
}
