//! The embeddable Zeus download engine.
//!
//! [`Engine`] ties the other crates together: it owns the job lifecycle of 01 (probe, session handoff,
//! segmented download with the commit protocol of 03, verification, finalization), the retry policy per
//! error class, scheduling and fairness, event broadcast with replay, and audit records at every material
//! step. It does **not** own a daemon, an MCP server or any UI; those embed it.
//!
//! Dependencies are injected through [`EngineBuilder`]: clock, randomness, file system, journal, HTTP
//! transport, [`SessionProvider`](zeus_session::SessionProvider), [`ProxyFetch`](zeus_session::ProxyFetch),
//! [`ConsentStore`](zeus_session::ConsentStore), [`AuditSink`](zeus_verify::AuditSink) and the
//! [`ApprovalPort`]. Approvals are human-only and decided outside the engine.
//!
//! Direct transfers use bounded HTTP ranges, durable checksummed commits and verified finalization.
//! The embedding daemon owns approvals, browser connection routing and audit-outbox publication.

#![forbid(unsafe_code)]

pub mod api;
pub mod config;
pub mod engine;
pub mod error;
pub mod events;
pub mod ports;
mod proxy;

pub use api::{
    ApprovalResolution, Caller, ControlAction, EngineStatus, EnqueueOutcome, EnqueueRequest,
    GrantChange, GrantChangeKind, KillSwitchOutcome, ListFilter, Page, ProbeUrlRequest,
};
pub use config::{EngineConfig, SchedulerLimits, Timeouts};
pub use engine::{Engine, EngineBuilder};
pub use error::{EngineError, EngineResult};
pub use events::{EngineEvent, EventSubscription};
pub use ports::{ApprovalPort, ApprovalRequest, JobTransportFactory};
