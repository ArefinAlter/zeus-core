//! `redact_url` (00 section 8.2): the only sanctioned way for a URL to reach a log line, an event,
//! an error message, an audit record or a manifest.
//!
//! Normative vectors live in `schema/redaction-vectors.v1.json` (a copy is under this crate's
//! `tests/fixtures`); the reference implementation is `docs/spec/tools/redact-url.mjs`. The function
//! is total, idempotent and deterministic. Over-redaction is a documented, acceptable failure;
//! under-redaction is a bug.

use percent_encoding_lite::percent_decode;
use url::Url;

/// How aggressively a URL is reduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedactMode {
    /// Logs, errors, events, MCP output and UI strings: the query becomes `?…` when present and
    /// secret-looking path segments become `…`.
    Log,
    /// Audit records and provenance manifests: query parameters are dropped individually when their
    /// name matches the deny pattern or their value looks secret; the path is kept.
    Record,
    /// Manifests with `privacy.url_query = dropped` and shared exports: the query is dropped
    /// entirely and secret-looking path segments are masked.
    Strict,
}

/// The result of [`redact_url`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redacted {
    /// The reduced URL, or [`UNPARSEABLE`] when the input was not a parseable absolute URL.
    pub url: String,
    /// True when anything was removed or masked.
    pub redacted: bool,
}

/// Returned instead of the input when it cannot be parsed, so a malformed URL carrying a secret
/// never leaks through the error path.
pub const UNPARSEABLE: &str = "invalid-url://redacted";

const DENY_WORDS: &[&str] = &[
    "token",
    "key",
    "secret",
    "sig",
    "signature",
    "auth",
    "authorization",
    "password",
    "passwd",
    "pwd",
    "credential",
    "credentials",
    "session",
    "sessionid",
    "sid",
    "jwt",
    "bearer",
    "otp",
    "code",
    "state",
    "nonce",
    "policy",
    "hmac",
    "hdnts",
    "sas",
];
const DENY_EXACT: &[&str] = &[
    "awsaccesskeyid",
    "googleaccessid",
    "access_token",
    "id_token",
    "refresh_token",
    "api_key",
    "apikey",
];

/// Reduces an absolute http(s) URL according to `mode`.
///
/// Common to all modes: userinfo and fragment are removed; scheme and host are lowercased and the
/// default port is dropped (both by the WHATWG URL parser).
#[must_use]
pub fn redact_url(input: &str, mode: RedactMode) -> Redacted {
    let Ok(url) = Url::parse(input) else {
        return Redacted {
            url: UNPARSEABLE.to_owned(),
            redacted: true,
        };
    };
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Redacted {
            url: UNPARSEABLE.to_owned(),
            redacted: true,
        };
    }

    let mut redacted = !url.username().is_empty() || url.password().is_some();
    if url.fragment().is_some_and(|f| !f.is_empty()) {
        redacted = true;
    }
    let origin = url.origin().ascii_serialization();

    let mut path = url.path().to_owned();
    if matches!(mode, RedactMode::Log | RedactMode::Strict) {
        path = path
            .split('/')
            .map(|segment| {
                if !segment.is_empty() && looks_secret(segment) {
                    redacted = true;
                    "\u{2026}"
                } else {
                    segment
                }
            })
            .collect::<Vec<_>>()
            .join("/");
    }

    let mut query = String::new();
    if let Some(q) = url.query().filter(|q| !q.is_empty()) {
        match mode {
            RedactMode::Record => {
                let mut kept = Vec::new();
                for pair in q.split('&').filter(|p| !p.is_empty()) {
                    let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                    let name = decode_lossy(name);
                    if deny_name(&name) || (!value.is_empty() && looks_secret(value)) {
                        redacted = true;
                    } else {
                        kept.push(pair);
                    }
                }
                if !kept.is_empty() {
                    query = format!("?{}", kept.join("&"));
                }
            }
            RedactMode::Log => {
                redacted = true;
                query.push_str("?\u{2026}");
            }
            RedactMode::Strict => redacted = true,
        }
    }

    Redacted {
        url: format!("{origin}{path}{query}"),
        redacted,
    }
}

/// True when a path segment or query value looks like a credential (00 section 8.2): after
/// percent-decoding it is not a UUID and it has the JWT shape, or is at least 32 hex digits, or is
/// at least 24 characters of `A-Za-z0-9_-+/=~` with three character classes, not a slug of three or
/// more alphabetic words, and Shannon entropy of at least 4.0 bits per character.
#[must_use]
pub fn looks_secret(value: &str) -> bool {
    let v = decode_lossy(value);
    if is_uuid(&v) {
        return false;
    }
    if is_jwt(&v) {
        return true;
    }
    if v.len() >= 32 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
        return true;
    }
    if v.chars().count() < 24
        || !v
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-+/=~".contains(&b))
    {
        return false;
    }
    let words = v
        .split(['-', '_'])
        .filter(|p| p.len() >= 3 && p.bytes().all(|b| b.is_ascii_alphabetic()))
        .count();
    if words >= 3 {
        return false;
    }
    let classes = [
        v.bytes().any(|b| b.is_ascii_lowercase()),
        v.bytes().any(|b| b.is_ascii_uppercase()),
        v.bytes().any(|b| b.is_ascii_digit()),
    ]
    .iter()
    .filter(|c| **c)
    .count();
    classes >= 3 && shannon_entropy(&v) >= 4.0
}

fn decode_lossy(s: &str) -> String {
    percent_decode(s).unwrap_or_else(|| s.to_owned())
}

fn is_uuid(v: &str) -> bool {
    let b = v.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

fn is_jwt(v: &str) -> bool {
    let Some(rest) = v.strip_prefix("eyJ") else {
        return false;
    };
    let mut parts = rest.split('.');
    let (Some(a), Some(b), Some(c), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    let b64 = |s: &str| {
        s.bytes()
            .all(|x| x.is_ascii_alphanumeric() || x == b'_' || x == b'-')
    };
    !a.is_empty() && !b.is_empty() && b64(a) && b64(b) && b64(c)
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = std::collections::BTreeMap::new();
    let mut total = 0f64;
    for ch in s.chars() {
        *counts.entry(ch).or_insert(0u32) += 1;
        total += 1.0;
    }
    counts
        .values()
        .map(|&c| {
            let p = f64::from(c) / total;
            -p * p.log2()
        })
        .sum()
}

fn deny_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if DENY_EXACT.contains(&n.as_str()) {
        return true;
    }
    if ["x-amz-", "x-goog-", "x-ms-"]
        .iter()
        .any(|p| n.starts_with(p))
    {
        return true;
    }
    n.split(['_', '.', '-'])
        .any(|part| DENY_WORDS.contains(&part))
}

/// Minimal percent-decoding that returns `None` when the decoded bytes are not valid UTF-8
/// (mirroring `decodeURIComponent` throwing, after which the raw text is used).
mod percent_encoding_lite {
    pub(super) fn percent_decode(s: &str) -> Option<String> {
        if !s.contains('%') {
            return Some(s.to_owned());
        }
        let bytes = s.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                let hi = bytes.get(i + 1).and_then(|b| (*b as char).to_digit(16))?;
                let lo = bytes.get(i + 2).and_then(|b| (*b as char).to_digit(16))?;
                out.push(u8::try_from(hi * 16 + lo).ok()?);
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_examples() {
        let r = redact_url(
            "https://user:pw@example.com/a/b.zip?x=1#frag",
            RedactMode::Log,
        );
        assert_eq!(
            r,
            Redacted {
                url: "https://example.com/a/b.zip?\u{2026}".into(),
                redacted: true
            }
        );
        let r = redact_url(
            "https://example.com/download?id=12345&format=pdf&token=abc",
            RedactMode::Record,
        );
        assert_eq!(r.url, "https://example.com/download?id=12345&format=pdf");
        assert!(r.redacted);
    }

    #[test]
    fn plain_urls_are_untouched() {
        for mode in [RedactMode::Log, RedactMode::Record, RedactMode::Strict] {
            let r = redact_url("https://example.com/files/report-2026.pdf", mode);
            assert_eq!(
                r,
                Redacted {
                    url: "https://example.com/files/report-2026.pdf".into(),
                    redacted: false
                }
            );
        }
    }

    #[test]
    fn unparseable_input_never_echoes() {
        let r = redact_url("not a url with token=ZEUS-CANARY-1", RedactMode::Log);
        assert_eq!(r.url, UNPARSEABLE);
        assert!(r.redacted);
        assert_eq!(
            redact_url("ftp://example.com/x", RedactMode::Log).url,
            UNPARSEABLE
        );
    }

    #[test]
    fn deny_pattern() {
        for name in [
            "token",
            "X-Amz-Signature",
            "access_token",
            "api-key",
            "my.sid",
            "x-goog-credential",
            "AWSAccessKeyId",
        ] {
            assert!(deny_name(name), "{name}");
        }
        for name in ["id", "format", "tokens", "monkey", "keyboard", "page"] {
            assert!(!deny_name(name), "{name}");
        }
    }

    #[test]
    fn secret_heuristics() {
        assert!(looks_secret("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"));
        assert!(looks_secret(&"a1".repeat(16)));
        assert!(!looks_secret("123e4567-e89b-12d3-a456-426614174000"));
        assert!(!looks_secret("quarterly-financial-report-final"));
        assert!(!looks_secret("short"));
    }
}
