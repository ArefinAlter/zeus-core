//! Version and capability negotiation (00 section 4.1, 02 section 5).
//!
//! The first frame the extension sends is `hello`, always with `v = 1`. The daemon picks the highest
//! protocol version present in both lists, answers with the intersection of capabilities and its own
//! limits, or fails with `nm.version_unsupported` (`details.supported` lists its versions) and closes.

use serde_json::json;
use zeus_types::{ConnectionId, ErrorEnvelope, Timestamp, codes};

use crate::protocol::{
    DaemonIdentity, HelloAckBody, HelloBody, HostIdentity, Limits, PROTOCOL_VERSION,
};

/// What the daemon (and host) offer.
#[derive(Debug, Clone)]
pub struct DaemonOffer {
    /// Protocol versions the daemon speaks, any order.
    pub versions: Vec<u16>,
    /// Capabilities the daemon implements.
    pub capabilities: Vec<String>,
    /// The daemon identity.
    pub daemon: DaemonIdentity,
    /// The host identity.
    pub host: HostIdentity,
    /// Hard maxima for the connection.
    pub limits: Limits,
}

impl DaemonOffer {
    /// An offer speaking protocol version 1 with the given capabilities.
    #[must_use]
    pub fn v1(capabilities: &[&str], daemon: DaemonIdentity, host: HostIdentity) -> Self {
        Self {
            versions: vec![PROTOCOL_VERSION],
            capabilities: capabilities.iter().map(|c| (*c).to_owned()).collect(),
            daemon,
            host,
            limits: Limits::default(),
        }
    }
}

/// The outcome of a successful negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    /// The chosen version, fixed for the connection.
    pub protocol_version: u16,
    /// The intersection of capabilities, in the daemon's order. Neither side may use behaviour gated by
    /// a capability outside it.
    pub capabilities: Vec<String>,
}

impl Negotiated {
    /// True when `capability` was negotiated.
    #[must_use]
    pub fn has(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|c| c == capability)
    }
}

/// Chooses the version and capabilities. `Err` is the envelope for `nm.version_unsupported`.
pub fn negotiate(hello: &HelloBody, offer: &DaemonOffer) -> Result<Negotiated, ErrorEnvelope> {
    let version = hello
        .protocol_versions
        .iter()
        .copied()
        .filter(|v| offer.versions.contains(v))
        .max();
    let Some(protocol_version) = version else {
        let mut supported = offer.versions.clone();
        supported.sort_unstable();
        return Err(ErrorEnvelope::from_code(
            codes::NM_VERSION_UNSUPPORTED,
            "no common protocol version",
        )
        .with_detail("supported", json!(supported)));
    };
    let capabilities = offer
        .capabilities
        .iter()
        .filter(|c| hello.capabilities.contains(c))
        .cloned()
        .collect();
    Ok(Negotiated {
        protocol_version,
        capabilities,
    })
}

/// Builds the `hello.ack` body for a negotiated connection.
#[must_use]
pub fn hello_ack(
    negotiated: &Negotiated,
    offer: &DaemonOffer,
    connection_id: ConnectionId,
    server_time: Timestamp,
    head_seq: u64,
) -> HelloAckBody {
    HelloAckBody {
        protocol_version: negotiated.protocol_version,
        capabilities: negotiated.capabilities.clone(),
        daemon: offer.daemon.clone(),
        host: offer.host.clone(),
        connection_id,
        limits: offer.limits,
        server_time,
        head_seq,
    }
}

#[cfg(test)]
mod tests {
    use zeus_types::BrowserName;

    use super::*;
    use crate::protocol::{HelloBrowser, capability as cap};

    fn hello(versions: &[u16], caps: &[&str]) -> HelloBody {
        HelloBody {
            client: "zeus-extension".into(),
            extension_id: "abcdefghijklmnopabcdefghijklmnop".into(),
            extension_version: "0.1.0".into(),
            browser: HelloBrowser {
                name: BrowserName::Chrome,
                version: "141".into(),
                platform: None,
            },
            protocol_versions: versions.to_vec(),
            capabilities: caps.iter().map(|c| (*c).to_owned()).collect(),
            profile_id: "5e0b1f6d9a2c47e8b3d1f0a7c6e92b41".into(),
            sw_instance_id: "9c1f4a7e52b84d06".into(),
            resume: None,
        }
    }

    fn offer(versions: &[u16], caps: &[&str]) -> DaemonOffer {
        let mut o = DaemonOffer::v1(
            caps,
            DaemonIdentity {
                version: "0.1.0".into(),
                instance_id: "0".repeat(32),
            },
            HostIdentity {
                version: "0.1.0".into(),
            },
        );
        o.versions = versions.to_vec();
        o
    }

    #[test]
    fn highest_common_version_and_capability_intersection() {
        let n = negotiate(
            &hello(&[1, 2], &[cap::HANDOFF, cap::SESSION, cap::INCOGNITO]),
            &offer(&[2, 1, 3], &[cap::HANDOFF, cap::APPROVALS, cap::SESSION]),
        )
        .unwrap();
        assert_eq!(n.protocol_version, 2);
        assert_eq!(
            n.capabilities,
            [cap::HANDOFF, cap::SESSION],
            "daemon order, intersection only"
        );
        assert!(n.has(cap::SESSION) && !n.has(cap::APPROVALS) && !n.has(cap::INCOGNITO));
    }

    #[test]
    fn no_common_version_lists_what_the_daemon_supports() {
        let err = negotiate(&hello(&[7], &[]), &offer(&[2, 1], &[])).unwrap_err();
        assert_eq!(err.code.as_str(), "nm.version_unsupported");
        assert_eq!(err.details.unwrap()["supported"], serde_json::json!([1, 2]));
        assert!(negotiate(&hello(&[], &[]), &offer(&[1], &[])).is_err());
    }

    #[test]
    fn ack_carries_the_negotiated_values() {
        let o = offer(&[1], &[cap::HANDOFF]);
        let n = negotiate(&hello(&[1], &[cap::HANDOFF]), &o).unwrap();
        let ids = zeus_types::IdGenerator::new();
        let ack = hello_ack(&n, &o, ids.connection_id(), Timestamp::UNIX_EPOCH, 48209);
        assert_eq!((ack.protocol_version, ack.head_seq), (1, 48209));
        assert_eq!(ack.limits, Limits::default());
    }
}
