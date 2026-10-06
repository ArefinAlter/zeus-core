//! Secret-holding string type (00 section 8.3).
//!
//! [`SecretString`] wipes its memory on drop, prints as `[REDACTED]` in `Debug` and `Display`,
//! and deliberately does **not** implement [`serde::Serialize`]: a struct that contains one cannot
//! be serialised by accident. The few places that must put secret text on the wire (the native
//! messaging session response written by a test extension, for example) opt in explicitly with
//! `#[serde(serialize_with = "zeus_types::secret::serialize_exposed")]`, which is easy to grep for.

use std::borrow::Cow;
use std::fmt;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serializer};
use zeroize::Zeroizing;

/// A string that must never reach a log, an error message or a file.
#[derive(Clone, Default)]
pub struct SecretString(Zeroizing<String>);

impl SecretString {
    /// Takes ownership of the text.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    /// The secret text. Call sites are the audit surface: keep them few and short-lived.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    /// Length in bytes (not secret).
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True for the empty string.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = <Cow<'de, str>>::deserialize(deserializer).map_err(de::Error::custom)?;
        Ok(Self::new(value.into_owned()))
    }
}

impl JsonSchema for SecretString {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "SecretString".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({ "type": "string", "x-zeus-secret": true })
    }
}

/// `serialize_with` helper that writes the secret text. Use only where the wire format requires
/// it and the destination is the one party entitled to the secret (spec 02 `session.response`).
pub fn serialize_exposed<S: Serializer>(
    value: &SecretString,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value.expose())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_prints_the_value() {
        let s = SecretString::from("ZEUS-CANARY-cookie-value");
        assert_eq!(format!("{s:?}"), "[REDACTED]");
        assert_eq!(format!("{s}"), "[REDACTED]");
        assert_eq!(format!("{:#?}", Some(&s)), "Some(\n    [REDACTED],\n)");
        assert_eq!(s.expose(), "ZEUS-CANARY-cookie-value");
    }

    #[test]
    fn deserialises_from_json() {
        let s: SecretString = serde_json::from_str("\"abc\"").unwrap();
        assert_eq!(s.expose(), "abc");
        assert!(serde_json::from_str::<SecretString>("1").is_err());
    }
}
