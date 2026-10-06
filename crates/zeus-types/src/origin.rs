//! Origins and URLs (01 section 4, 00 section 8).
//!
//! * [`Origin`]: `scheme://host[:port]` in WHATWG normal form. Sessions are scoped to one exact origin.
//! * [`HttpUrl`]: an absolute http(s) URL **as received**. It may carry secrets in its query, so its
//!   `Debug` and `Display` print the redacted log form; the raw text needs an explicit
//!   [`HttpUrl::expose`].
//! * [`RedactedUrl`]: a URL after `redact_url`, safe to log, store in events and show to people.

use std::borrow::Cow;
use std::fmt;
use std::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::de::{self, Deserializer};
use serde::{Deserialize, Serialize, Serializer};
use url::Url;

use crate::error::TypesError;
use crate::limits::{MAX_ORIGIN_BYTES, MAX_URL_BYTES};
use crate::redact::{RedactMode, redact_url};

/// Longest [`RedactedUrl`] in characters; longer reductions are truncated with an ellipsis.
pub const MAX_REDACTED_URL_CHARS: usize = 2048;

/// A web origin in normal form: lowercase scheme, lowercase ASCII (punycode) host, default port
/// omitted, IPv6 hosts in brackets. No path, query, fragment or userinfo. Opaque origins do not
/// exist in Zeus.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Origin(String);

impl Origin {
    /// Parses text that must already be in normal form (this is what the wire carries).
    pub fn parse(text: &str) -> Result<Self, TypesError> {
        if text.len() > MAX_ORIGIN_BYTES {
            return Err(TypesError::InvalidOrigin { reason: "too long" });
        }
        let url = Url::parse(text).map_err(|_| TypesError::InvalidOrigin {
            reason: "not a URL",
        })?;
        if !(url.path() == "/" || url.path().is_empty())
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(TypesError::InvalidOrigin {
                reason: "has a path, query, fragment or userinfo",
            });
        }
        let origin = Self::from_url(&url)?;
        if origin.0 != text {
            return Err(TypesError::InvalidOrigin {
                reason: "not in normal form",
            });
        }
        Ok(origin)
    }

    /// The origin of any http(s) URL, computed by the WHATWG algorithm. Clients never send an
    /// origin they computed as proof of anything (01 section 4 rule 1): the daemon calls this.
    pub fn from_url(url: &Url) -> Result<Self, TypesError> {
        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(TypesError::InvalidOrigin {
                reason: "not an http(s) URL with a host",
            });
        }
        let text = url.origin().ascii_serialization();
        if text.len() > MAX_ORIGIN_BYTES {
            return Err(TypesError::InvalidOrigin { reason: "too long" });
        }
        Ok(Self(text))
    }

    /// The normal-form text, for example `https://portal.example.org`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// `http` or `https`.
    #[must_use]
    pub fn scheme(&self) -> &str {
        if self.0.starts_with("https://") {
            "https"
        } else {
            "http"
        }
    }

    /// The host as it appears in the origin (IPv6 addresses keep their brackets).
    #[must_use]
    pub fn host(&self) -> &str {
        let authority = self.0.split_once("://").map_or("", |(_, rest)| rest);
        if authority.starts_with('[') {
            authority
                .find(']')
                .map_or(authority, |end| &authority[..=end])
        } else {
            authority.split(':').next().unwrap_or(authority)
        }
    }

    /// True when session material may be released for this origin: `https`, or `http` only for
    /// `localhost`, `127.0.0.1` and `[::1]` (01 section 4 rule 3).
    #[must_use]
    pub fn allows_session_release(&self) -> bool {
        self.scheme() == "https" || matches!(self.host(), "localhost" | "127.0.0.1" | "[::1]")
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Origin({})", self.0)
    }
}

impl FromStr for Origin {
    type Err = TypesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for Origin {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Origin {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <Cow<'de, str>>::deserialize(deserializer)?;
        Self::parse(&s).map_err(de::Error::custom)
    }
}

impl JsonSchema for Origin {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "Origin".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "maxLength": 300,
            "pattern": "^https?://(\\[[0-9a-f:.]+\\]|[a-z0-9]([a-z0-9.-]*[a-z0-9])?)(:[0-9]{1,5})?$",
            "description": "Web origin: scheme, ASCII (punycode) lowercase host, non-default port only."
        })
    }
}

/// An absolute http(s) URL as received. Never log it directly: `Debug` and `Display` print the
/// `log` redaction, and [`HttpUrl::expose`] is the grep-able way to reach the raw text.
#[derive(Clone)]
pub struct HttpUrl {
    raw: String,
    parsed: Url,
    origin: Origin,
}

impl HttpUrl {
    /// Validates and wraps a URL: http or https, a host, at most 8192 bytes, no control characters
    /// or spaces. A URL whose scheme is not lowercase is stored in the parser's normal form so the
    /// wire pattern `^https?://` holds.
    pub fn parse(text: &str) -> Result<Self, TypesError> {
        if text.len() > MAX_URL_BYTES {
            return Err(TypesError::InvalidUrl {
                reason: "longer than 8192 bytes",
            });
        }
        if text.bytes().any(|b| b <= 0x20 || b == 0x7f) {
            return Err(TypesError::InvalidUrl {
                reason: "contains control characters or spaces",
            });
        }
        let parsed = Url::parse(text).map_err(|_| TypesError::InvalidUrl {
            reason: "not an absolute URL",
        })?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(TypesError::SchemeNotAllowed);
        }
        if parsed.host_str().is_none() {
            return Err(TypesError::InvalidUrl { reason: "no host" });
        }
        let raw = if text.starts_with("http://") || text.starts_with("https://") {
            text.to_owned()
        } else {
            parsed.as_str().to_owned()
        };
        if raw.len() > MAX_URL_BYTES || raw.len() < 8 {
            return Err(TypesError::InvalidUrl {
                reason: "outside the allowed length",
            });
        }
        // Computed once so `origin()` cannot fail later; a pathological host over 300 bytes is
        // rejected here.
        let origin = Origin::from_url(&parsed).map_err(|_| TypesError::InvalidUrl {
            reason: "host too long",
        })?;
        Ok(Self {
            raw,
            parsed,
            origin,
        })
    }

    /// The raw URL text. May contain secrets in its query string; every call site is an audit point.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.raw
    }

    /// The parsed form.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.parsed
    }

    /// The origin, computed by the WHATWG algorithm.
    #[must_use]
    pub fn origin(&self) -> Origin {
        self.origin.clone()
    }

    /// The URL reduced by `redact_url` in `mode`.
    #[must_use]
    pub fn redact(&self, mode: RedactMode) -> RedactedUrl {
        RedactedUrl::from_raw(&self.raw, mode)
    }
}

impl PartialEq for HttpUrl {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

impl Eq for HttpUrl {}

impl std::hash::Hash for HttpUrl {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.raw.hash(state);
    }
}

impl fmt::Display for HttpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&redact_url(&self.raw, RedactMode::Log).url)
    }
}

impl fmt::Debug for HttpUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HttpUrl({})", redact_url(&self.raw, RedactMode::Log).url)
    }
}

impl FromStr for HttpUrl {
    type Err = TypesError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl Serialize for HttpUrl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for HttpUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <Cow<'de, str>>::deserialize(deserializer)?;
        // Do not echo the offending value: it may be a URL with a secret.
        Self::parse(&s).map_err(|e| de::Error::custom(e.to_string()))
    }
}

impl JsonSchema for HttpUrl {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "Url".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 8,
            "maxLength": 8192,
            "pattern": "^https?://",
            "description": "Absolute http(s) URL as received. May contain secrets in its query string: never log it."
        })
    }
}

/// A URL after `redact_url`: no userinfo, no fragment, query dropped or sanitised.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RedactedUrl(String);

impl RedactedUrl {
    /// Redacts raw URL text. Total: unparseable input yields the `invalid-url://redacted`
    /// placeholder, wrapped here as an `https://invalid.invalid/` stand-in so the type invariant holds.
    #[must_use]
    pub fn from_raw(raw: &str, mode: RedactMode) -> Self {
        let r = redact_url(raw, mode);
        let mut text = if r.url.starts_with("http://") || r.url.starts_with("https://") {
            r.url
        } else {
            "https://invalid.invalid/".to_owned()
        };
        // The schema forbids '@' and whitespace; neither survives redaction of userinfo, but
        // an '@' inside a path or kept query value would break the invariant.
        if text.contains('@') {
            text = text.replace('@', "%40");
        }
        if text.chars().count() > MAX_REDACTED_URL_CHARS {
            let keep: String = text.chars().take(MAX_REDACTED_URL_CHARS - 1).collect();
            text = format!("{keep}\u{2026}");
        }
        Self(text)
    }

    /// Validates text that claims to be already redacted (used when reading it back from the wire).
    pub fn new(text: &str) -> Result<Self, TypesError> {
        let ok = (text.starts_with("http://") || text.starts_with("https://"))
            && text.len() >= 8
            && text.chars().count() <= MAX_REDACTED_URL_CHARS
            && !text
                .chars()
                .any(|c| c == '@' || c == '#' || c.is_whitespace());
        if ok {
            Ok(Self(text.to_owned()))
        } else {
            Err(TypesError::InvalidUrl {
                reason: "not a redacted URL",
            })
        }
    }

    /// The redacted text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RedactedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for RedactedUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RedactedUrl({})", self.0)
    }
}

impl Serialize for RedactedUrl {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RedactedUrl {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = <Cow<'de, str>>::deserialize(deserializer)?;
        Self::new(&s).map_err(de::Error::custom)
    }
}

impl JsonSchema for RedactedUrl {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> Cow<'static, str> {
        "RedactedUrl".into()
    }

    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 8,
            "maxLength": 2048,
            "pattern": "^https?://[^@\\s#]*$",
            "description": "URL after redact_url: no userinfo, no fragment, query dropped or sanitised."
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_normal_form() {
        assert!(Origin::parse("https://portal.example.org").is_ok());
        assert!(Origin::parse("http://localhost:8080").is_ok());
        assert!(Origin::parse("http://[::1]:3000").is_ok());
        for bad in [
            "https://portal.example.org/",
            "https://Portal.Example.org",
            "https://portal.example.org:443",
            "https://portal.example.org/path",
            "https://u:p@portal.example.org",
            "ftp://example.org",
            "example.org",
            "https://portal.example.org?x=1",
        ] {
            assert!(Origin::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn origin_from_url_normalises() {
        let url = Url::parse("HTTPS://Portal.Example.ORG:443/a/b?q=1#f").unwrap();
        assert_eq!(
            Origin::from_url(&url).unwrap().as_str(),
            "https://portal.example.org"
        );
        let url = Url::parse("https://bücher.example/x").unwrap();
        assert_eq!(
            Origin::from_url(&url).unwrap().as_str(),
            "https://xn--bcher-kva.example"
        );
        let url = Url::parse("http://example.org:8080/x").unwrap();
        assert_eq!(Origin::from_url(&url).unwrap().host(), "example.org");
    }

    #[test]
    fn session_release_rule() {
        let ok = |s: &str| Origin::parse(s).unwrap().allows_session_release();
        assert!(ok("https://example.org"));
        assert!(ok("http://localhost:3000"));
        assert!(ok("http://127.0.0.1:8080"));
        assert!(ok("http://[::1]:8080"));
        assert!(!ok("http://example.org"));
        assert!(!ok("http://127.0.0.2"));
    }

    #[test]
    fn http_url_never_prints_its_query() {
        let url = HttpUrl::parse("https://cdn.example.org/blob?X-Amz-Signature=ZEUS-CANARY-secret")
            .unwrap();
        for text in [
            format!("{url}"),
            format!("{url:?}"),
            format!("{:#?}", Some(&url)),
        ] {
            assert!(!text.contains("ZEUS-CANARY"), "{text}");
        }
        assert!(url.expose().contains("ZEUS-CANARY"));
        let json = serde_json::to_string(&url).unwrap();
        assert!(
            json.contains("ZEUS-CANARY"),
            "the wire form carries the raw URL"
        );
    }

    #[test]
    fn http_url_validation() {
        assert!(HttpUrl::parse("https://example.org/a b").is_err());
        assert!(HttpUrl::parse("https://example.org/\u{7}").is_err());
        assert!(HttpUrl::parse("file:///etc/passwd").is_err());
        assert!(HttpUrl::parse("javascript:alert(1)").is_err());
        assert!(HttpUrl::parse("/relative").is_err());
        assert!(HttpUrl::parse(&format!("https://example.org/{}", "a".repeat(9000))).is_err());
        let upper = HttpUrl::parse("HTTPS://EXAMPLE.org/x").unwrap();
        assert!(upper.expose().starts_with("https://"));
        assert_eq!(upper.origin().as_str(), "https://example.org");
    }

    #[test]
    fn redacted_url_invariants() {
        let url = HttpUrl::parse("https://user:pw@example.com/a/b.zip?x=1#frag").unwrap();
        let r = url.redact(RedactMode::Log);
        assert_eq!(r.as_str(), "https://example.com/a/b.zip?\u{2026}");
        assert!(RedactedUrl::new(r.as_str()).is_ok());
        let at = RedactedUrl::from_raw(
            "https://example.com/user@home/file?email=a@b.c",
            RedactMode::Record,
        );
        assert!(!at.as_str().contains('@'));
        assert!(RedactedUrl::new("https://user@example.com/").is_err());
        assert_eq!(
            RedactedUrl::from_raw("garbage", RedactMode::Log).as_str(),
            "https://invalid.invalid/"
        );
    }
}
