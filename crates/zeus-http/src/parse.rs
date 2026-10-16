//! Parsers for the response headers that decide resume correctness.
//!
//! Byte ranges are half-open everywhere in Zeus; the inclusive form of RFC 9110 exists only in these
//! parsers and in the request builders, and converts at the boundary (00 section 6.3 rule 4).
use std::time::Duration;

use zeus_types::{ByteRange, Timestamp};

use crate::error::{HttpError, HttpResult};

/// A parsed `Content-Range` (RFC 9110 section 14.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentRange {
    /// `bytes first-last/total` or `bytes first-last/*`: the body carries `range`.
    Satisfied {
        /// The bytes of the body, half-open.
        range: ByteRange,
        /// The complete length, or `None` for `*`.
        total: Option<u64>,
    },
    /// `bytes */total`, the answer to an unsatisfiable range (status 416).
    Unsatisfied {
        /// The complete length.
        total: u64,
    },
}

/// Parses a `Content-Range` value. Only the `bytes` unit is accepted. Rejects `last < first`, a `last`
/// at or beyond a known `total`, numbers above 2^53 - 1, and any trailing text.
pub fn parse_content_range(value: &str) -> HttpResult<ContentRange> {
    let bad = || HttpError::Invalid("malformed Content-Range");
    let rest = value.trim().strip_prefix("bytes").ok_or_else(bad)?;
    let rest = rest.strip_prefix(' ').ok_or_else(bad)?.trim_start();
    let (spec, total) = rest.split_once('/').ok_or_else(bad)?;
    let number = |s: &str| -> HttpResult<u64> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad());
        }
        let n: u64 = s.parse().map_err(|_| bad())?;
        if n > zeus_types::limits::MAX_SAFE_INTEGER {
            Err(bad())
        } else {
            Ok(n)
        }
    };
    let total = if total == "*" {
        None
    } else {
        Some(number(total)?)
    };
    if spec == "*" {
        return total
            .map(|t| ContentRange::Unsatisfied { total: t })
            .ok_or_else(bad);
    }
    let (first, last) = spec.split_once('-').ok_or_else(bad)?;
    let (first, last) = (number(first)?, number(last)?);
    if last < first || total.is_some_and(|t| last >= t) {
        return Err(bad());
    }
    let range = ByteRange::from_inclusive(first, last).map_err(|_| bad())?;
    Ok(ContentRange::Satisfied { range, total })
}

/// Parses `Retry-After` (RFC 9110 section 10.2.3): either delta-seconds or an HTTP-date. A date in the
/// past is a zero delay. `None` when the value is neither.
#[must_use]
pub fn parse_retry_after(value: &str, now: Timestamp) -> Option<Duration> {
    let v = value.trim();
    if !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()) {
        return v.parse::<u64>().ok().map(Duration::from_secs);
    }
    let when = httpdate::parse_http_date(v).ok()?;
    let when_ms =
        i64::try_from(when.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis()).ok()?;
    Some(Duration::from_millis(
        u64::try_from(when_ms - now.unix_millis()).unwrap_or(0),
    ))
}

/// Parses an HTTP-date (`Last-Modified`, `Date`) into a [`Timestamp`].
#[must_use]
pub fn parse_http_date(value: &str) -> Option<Timestamp> {
    let t = httpdate::parse_http_date(value.trim()).ok()?;
    let ms = i64::try_from(t.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis()).ok()?;
    Timestamp::from_unix_millis(ms).ok()
}

/// True when `Last-Modified` is at least one second older than the response `Date`: the condition under
/// which RFC 9110 section 8.8.2.2 allows it as a strong validator in `If-Range`.
#[must_use]
pub fn last_modified_is_strong(last_modified: &str, date: &str) -> bool {
    match (parse_http_date(last_modified), parse_http_date(date)) {
        (Some(lm), Some(d)) => d.unix_millis() - lm.unix_millis() >= 1000,
        _ => false,
    }
}

/// Where a file name came from in a `Content-Disposition` header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedDisposition {
    /// The decoded name (untrusted; always sanitised before use).
    pub filename: String,
    /// True when it came from the extended `filename*` parameter (RFC 8187), which takes precedence.
    pub extended: bool,
}

/// Parses `Content-Disposition` per RFC 6266 and RFC 8187: `filename*` (with its charset and
/// percent-decoding) wins over `filename`; quoted-string escapes are honoured; only the `attachment`
/// and `inline` dispositions matter. `None` when no usable name exists.
pub fn parse_content_disposition(value: &str) -> HttpResult<Option<ParsedDisposition>> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut escaped = false;
    for ch in value.chars() {
        if escaped {
            field.push(ch);
            escaped = false;
            continue;
        }
        if quoted && ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == '"' {
            quoted = !quoted;
            continue;
        }
        if ch == ';' && !quoted {
            fields.push(std::mem::take(&mut field));
        } else {
            field.push(ch);
        }
    }
    if quoted || escaped {
        return Ok(None);
    }
    fields.push(field);
    if !fields.first().is_some_and(|f| {
        matches!(
            f.trim().to_ascii_lowercase().as_str(),
            "attachment" | "inline"
        )
    }) {
        return Ok(None);
    }
    let mut plain = None;
    let mut extended = None;
    for field in fields.iter().skip(1) {
        let Some((name, raw)) = field.split_once('=') else {
            continue;
        };
        let raw = raw.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "filename" if plain.is_none() => plain = Some(raw.to_owned()),
            "filename*" if extended.is_none() => {
                let parts: Vec<_> = raw.splitn(3, '\'').collect();
                if parts.len() == 3
                    && parts[0].eq_ignore_ascii_case("utf-8")
                    && let Ok(decoded) =
                        percent_encoding::percent_decode_str(parts[2]).decode_utf8()
                {
                    extended = Some(decoded.into_owned());
                }
            }
            _ => {}
        }
    }
    let (filename, extended) = match extended {
        Some(s) => (s, true),
        None => match plain {
            Some(s) => (s, false),
            None => return Ok(None),
        },
    };
    if filename.is_empty() || filename.chars().any(char::is_control) {
        return Ok(None);
    }
    Ok(Some(ParsedDisposition { filename, extended }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(first: u64, end: u64) -> ByteRange {
        ByteRange::new(first, end).unwrap()
    }

    #[test]
    fn content_range_forms() {
        assert_eq!(
            parse_content_range("bytes 402653184-419430399/1288490188").unwrap(),
            ContentRange::Satisfied {
                range: r(402_653_184, 419_430_400),
                total: Some(1_288_490_188)
            }
        );
        assert_eq!(
            parse_content_range("bytes 0-0/1").unwrap(),
            ContentRange::Satisfied {
                range: r(0, 1),
                total: Some(1)
            }
        );
        assert_eq!(
            parse_content_range("bytes 5-9/*").unwrap(),
            ContentRange::Satisfied {
                range: r(5, 10),
                total: None
            }
        );
        assert_eq!(
            parse_content_range("bytes */1000").unwrap(),
            ContentRange::Unsatisfied { total: 1000 }
        );
        assert_eq!(
            parse_content_range("  bytes 1-2/3 ").unwrap(),
            ContentRange::Satisfied {
                range: r(1, 3),
                total: Some(3)
            }
        );
    }

    #[test]
    fn content_range_rejections() {
        for bad in [
            "",
            "bytes",
            "bytes 5-4/10",
            "bytes 0-10/10",
            "bytes 0-9/",
            "bytes -5/10",
            "bytes 0-9",
            "items 0-9/10",
            "bytes */*",
            "bytes 0-9/10 extra",
            "bytes 0-a/10",
            "bytes 0x1-5/10",
            "bytes 0-9007199254740992/*",
            "bytes  0 - 9/10",
            "bytes+0-9/10",
        ] {
            assert!(
                parse_content_range(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn retry_after_forms() {
        let now = Timestamp::parse("2026-10-05T09:00:00.000Z").unwrap();
        assert_eq!(parse_retry_after("30", now), Some(Duration::from_secs(30)));
        assert_eq!(
            parse_retry_after(" 120 ", now),
            Some(Duration::from_secs(120))
        );
        assert_eq!(
            parse_retry_after("Mon, 05 Oct 2026 09:01:30 GMT", now),
            Some(Duration::from_secs(90))
        );
        assert_eq!(
            parse_retry_after("Mon, 05 Oct 2026 08:00:00 GMT", now),
            Some(Duration::ZERO),
            "a date in the past is no delay"
        );
        for bad in ["", "soon", "-5", "1.5", "30s"] {
            assert_eq!(parse_retry_after(bad, now), None, "{bad:?}");
        }
    }

    #[test]
    fn last_modified_strength() {
        let date = "Mon, 05 Oct 2026 09:15:36 GMT";
        assert!(last_modified_is_strong(
            "Tue, 29 Sep 2026 14:02:11 GMT",
            date
        ));
        assert!(
            !last_modified_is_strong("Mon, 05 Oct 2026 09:15:36 GMT", date),
            "same second is weak"
        );
        assert!(
            last_modified_is_strong("Mon, 05 Oct 2026 09:15:35 GMT", date),
            "exactly one second older is strong"
        );
        assert!(!last_modified_is_strong("garbage", date));
    }
}
