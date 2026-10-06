//! Session material: the cookies and minimal headers released for **one origin** under a grant
//! (02 section 8.1), held in memory for one lease and never persisted.
//!
//! * Cookie values are [`SecretString`]: zeroised on drop, `[REDACTED]` in `Debug`, not `Serialize`
//!   except through the explicit `serialize_with` below.
//! * Cookie *names* are also secret (00 section 8.1): `Debug` for [`Cookie`] and [`SessionMaterial`]
//!   prints counts only.
//! * `Serialize` for these types exists for the one place that must put material on the wire: a test
//!   extension answering `session.response`. The daemon only deserialises it.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeus_types::secret::serialize_exposed;
use zeus_types::{Origin, SecretString, SessionLeaseId, Timestamp};

use crate::protocol::SessionHeaderName;

/// `SameSite` attribute of a cookie, in the spelling of `chrome.cookies.SameSiteStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SameSite {
    /// `SameSite=None`.
    NoRestriction,
    /// `SameSite=Lax`.
    Lax,
    /// `SameSite=Strict`.
    Strict,
    /// Not set.
    Unspecified,
}

/// The CHIPS partition of a cookie.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartitionKey {
    /// The top-level site the cookie is partitioned under.
    pub top_level_site: String,
    /// Whether the partition has a cross-site ancestor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub has_cross_site_ancestor: Option<bool>,
}

/// One cookie as `chrome.cookies.getAll` reports it. Secret: never log, never persist.
#[derive(Clone, Serialize, Deserialize)]
pub struct Cookie {
    /// Name (at most 256 bytes). Treated as secret.
    pub name: String,
    /// Value (at most 8192 bytes).
    #[serde(serialize_with = "serialize_exposed")]
    pub value: SecretString,
    /// The `Domain` attribute, with a leading dot for domain cookies.
    pub domain: String,
    /// The `Path` attribute.
    pub path: String,
    /// `Secure`.
    pub secure: bool,
    /// `HttpOnly`.
    pub http_only: bool,
    /// `SameSite`.
    pub same_site: SameSite,
    /// True when no `Domain` attribute was set (the cookie matches the exact host only).
    pub host_only: bool,
    /// Expiry, or `null` for a session cookie.
    pub expires_at: Option<Timestamp>,
    /// CHIPS partition key, when partitioned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub partition_key: Option<PartitionKey>,
}

impl fmt::Debug for Cookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cookie([REDACTED])")
    }
}

/// The material released by one `session.response` with `status: granted`.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionMaterial {
    /// The lease handle minted by the daemon (safe to log).
    pub session_id: SessionLeaseId,
    /// The one origin the material is for.
    pub origin: Origin,
    /// When the extension issued it.
    pub issued_at: Timestamp,
    /// Time to live in milliseconds, 1000 to 900000. The daemon drops the material at
    /// `issued_at + ttl_ms` (monotonic) or when the job leaves the engine.
    pub ttl_ms: u64,
    /// At most 150 cookies and 128 KiB serialised.
    pub cookies: Vec<Cookie>,
    /// `navigator.userAgent` of the browser.
    pub user_agent: String,
    /// The allow-listed headers the extension could produce.
    pub headers: BTreeMap<SessionHeaderName, String>,
    /// Which cookie store was used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_store_id: Option<String>,
}

impl fmt::Debug for SessionMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionMaterial")
            .field("session_id", &self.session_id)
            .field("origin", &self.origin)
            .field("ttl_ms", &self.ttl_ms)
            .field("cookie_count", &self.cookies.len())
            .finish_non_exhaustive()
    }
}

impl SessionMaterial {
    /// Number of cookies (safe to log and to put in `session.leased`).
    #[must_use]
    pub fn cookie_count(&self) -> usize {
        self.cookies.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cookie() -> Cookie {
        Cookie {
            name: "portal_session".into(),
            value: SecretString::from("ZEUS-CANARY-cookie-value"),
            domain: "portal.example.org".into(),
            path: "/".into(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            host_only: true,
            expires_at: None,
            partition_key: None,
        }
    }

    #[test]
    fn debug_never_prints_names_or_values() {
        let c = cookie();
        for text in [format!("{c:?}"), format!("{:#?}", vec![&c])] {
            assert!(
                !text.contains("ZEUS-CANARY") && !text.contains("portal_session"),
                "{text}"
            );
        }
        let m = SessionMaterial {
            session_id: zeus_types::IdGenerator::new().session_lease_id(),
            origin: Origin::parse("https://portal.example.org").unwrap(),
            issued_at: Timestamp::UNIX_EPOCH,
            ttl_ms: 900_000,
            cookies: vec![c],
            user_agent: "UA".into(),
            headers: BTreeMap::new(),
            cookie_store_id: None,
        };
        let text = format!("{m:?}");
        assert!(text.contains("cookie_count: 1"));
        assert!(
            !text.contains("ZEUS-CANARY") && !text.contains("portal_session"),
            "{text}"
        );
    }

    #[test]
    fn the_wire_form_carries_the_value() {
        let json = serde_json::to_string(&cookie()).unwrap();
        assert!(json.contains("ZEUS-CANARY-cookie-value"));
        let back: Cookie = serde_json::from_str(&json).unwrap();
        assert_eq!(back.value.expose(), "ZEUS-CANARY-cookie-value");
    }
}
