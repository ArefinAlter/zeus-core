//! Session handoff for Zeus: the extension to daemon protocol, consent, and the traits the engine uses
//! to obtain session material and in-browser fetches (02, 01 section 5).
//!
//! * [`protocol`]: every message of native messaging v1 as typed Rust (`Message<ExtensionBody>` and
//!   `Message<DaemonBody>`), matching `native-messaging.v1.schema.json`.
//! * [`codec`]: the length-prefixed framing with per-direction limits, blocking, async and incremental.
//! * [`mod@negotiate`]: version and capability negotiation.
//! * [`flow`]: credit-based flow control and stream validation for the fetch proxy.
//! * [`material`]: cookies and headers released for one origin, with redacting `Debug` and zeroising values.
//! * [`consent`]: the grant store trait.
//! * [`provider`]: [`SessionProvider`] and [`ProxyFetch`], the engine's view of the browser.
//! * [`correlator`]: request/response correlation with timeouts.
//!
//! Secrets never leave this crate through `Debug`, errors or logs: cookie names and values are secret
//! (00 section 8.1) and printed as `[REDACTED]` or as counts.

#![forbid(unsafe_code)]

pub mod codec;
pub mod consent;
pub mod correlator;
pub mod error;
pub mod flow;
pub mod material;
pub mod negotiate;
pub mod protocol;
pub mod provider;

pub use codec::{
    Direction, FrameDecoder, FrameLimits, encode_frame, read_frame, read_frame_async, write_frame,
    write_frame_async,
};
pub use consent::{ConsentStore, InMemoryConsentStore, NewGrant, Resolution};
pub use correlator::{PendingResponse, RequestCorrelator};
pub use error::{DecodeError, FrameError, SessionError, SessionResult};
pub use material::{Cookie, SameSite, SessionMaterial};
pub use negotiate::{DaemonOffer, Negotiated, negotiate};
pub use protocol::{
    DaemonBody, DaemonMessage, ExtensionBody, ExtensionMessage, Limits, Message, MessageBody,
    MessageId, StreamId,
};
pub use provider::{
    LeaseRequest, ProxyBody, ProxyChunk, ProxyFetch, ProxyFetchRequest, ProxyHead, ProxyResponse,
    RefreshedUrl, SessionLease, SessionProvider, UrlRefreshRequest,
};
