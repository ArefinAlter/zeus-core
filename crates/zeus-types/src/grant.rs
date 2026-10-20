//! Actors, session grants and approvals (01 section 5).
//!
//! A [`SessionGrant`] is a recorded consent and **never** contains cookies. Only a human on a trust
//! surface creates, renews or revokes grants; agents cannot (01 section 12.2).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{ApprovalId, GrantId, JobId, RunId};
use crate::job::SourceKind;
use crate::limits::grants::{ONCE_MAX_MS, SITE_TTL_MS, WORKFLOW_TTL_MS};
use crate::origin::{Origin, RedactedUrl};
use crate::timestamp::Timestamp;

/// Who did something (01 section 5.3, `Actor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// A person on a trust surface.
    Human,
    /// An autonomous client: MCP, A2A.
    Agent,
    /// The CLI or TUI as a program (a human typing at it is `human` on surface `cli_interactive`).
    Cli,
    /// The browser extension acting on its own.
    Extension,
    /// Daemon internals.
    Engine,
    /// Policy evaluation.
    Policy,
    /// Timers and recovery.
    System,
}

/// The surface an action arrived through.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// The extension popup.
    ExtensionPopup,
    /// The extension options page.
    ExtensionOptions,
    /// The extension side panel.
    ExtensionSidepanel,
    /// A browser notification button.
    ExtensionNotification,
    /// The terminal UI.
    Tui,
    /// An interactive CLI prompt on the controlling terminal.
    CliInteractive,
    /// The native desktop trust surface.
    Gui,
    /// A trusted operating-system notification.
    OsNotification,
    /// The MCP server.
    Mcp,
    /// The A2A endpoint.
    A2a,
    /// Raw local JSON-RPC.
    Jsonrpc,
}

impl Surface {
    /// True for surfaces permitted to approve or create lasting authority.
    #[must_use]
    pub const fn is_approving_surface(self) -> bool {
        self.is_trust_surface() && !matches!(self, Self::ExtensionNotification)
    }

    /// True for the surfaces that are trust surfaces: only a human can drive them (00 section 2).
    /// MCP, A2A and raw JSON-RPC are never trust surfaces.
    #[must_use]
    pub const fn is_trust_surface(self) -> bool {
        matches!(
            self,
            Self::ExtensionPopup
                | Self::ExtensionOptions
                | Self::ExtensionSidepanel
                | Self::ExtensionNotification
                | Self::Tui
                | Self::CliInteractive
                | Self::Gui
        )
    }
}

/// An actor: kind, surface and client id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Actor {
    /// What kind of actor.
    pub kind: ActorKind,
    /// The surface it used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<Surface>,
    /// The authenticated client id, at most 128 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
}

impl Actor {
    /// A human on `surface`.
    #[must_use]
    pub fn human(surface: Surface) -> Self {
        Self {
            kind: ActorKind::Human,
            surface: Some(surface),
            client_id: None,
        }
    }

    /// The engine.
    #[must_use]
    pub fn engine() -> Self {
        Self {
            kind: ActorKind::Engine,
            surface: None,
            client_id: None,
        }
    }

    /// The system (timers, recovery).
    #[must_use]
    pub fn system() -> Self {
        Self {
            kind: ActorKind::System,
            surface: None,
            client_id: None,
        }
    }

    /// An agent client reaching Zeus over `surface`.
    #[must_use]
    pub fn agent(surface: Surface, client_id: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::Agent,
            surface: Some(surface),
            client_id: Some(client_id.into()),
        }
    }

    /// True only for a human on a trust surface: the one combination allowed to decide an approval
    /// (01 section 5.3 rule 1).
    #[must_use]
    pub fn is_human_on_trust_surface(&self) -> bool {
        self.kind == ActorKind::Human && self.surface.is_some_and(Surface::is_trust_surface)
    }
}

/// Grant scope (01 section 5.1).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum GrantScope {
    /// One job and all its retries; hard maximum 24 hours.
    Once,
    /// One exact origin for 24 hours.
    Site,
    /// One origin and one run for 7 days, renewable by a human.
    Workflow,
    /// Block-list entry: no expiry until a human removes it.
    Never,
}

impl GrantScope {
    /// Lifetime from creation in milliseconds: 24 h (`once`, as a hard cap), 24 h (`site`), 7 d
    /// (`workflow`), none (`never`).
    #[must_use]
    pub const fn lifetime_ms(self) -> Option<u64> {
        match self {
            Self::Once => Some(ONCE_MAX_MS),
            Self::Site => Some(SITE_TTL_MS),
            Self::Workflow => Some(WORKFLOW_TTL_MS),
            Self::Never => None,
        }
    }

    /// True when a human can renew a grant of this scope (only `workflow`).
    #[must_use]
    pub const fn renewable(self) -> bool {
        matches!(self, Self::Workflow)
    }
}

/// Lifecycle state of a grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrantState {
    /// In force.
    Active,
    /// Past `expires_at`.
    Expired,
    /// Revoked by a human.
    Revoked,
    /// A `once` grant whose job ended.
    Consumed,
}

/// Recorded cause for a grant revocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// Explicit human action.
    UserRequest,
    /// Daemon kill switch.
    KillSwitch,
    /// A never grant blocks the origin.
    OriginBlocked,
}

/// A recorded consent. Holds no cookies: cookies are fetched per use and wiped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SessionGrant {
    /// Identifier.
    pub id: GrantId,
    /// The one origin the grant covers.
    pub origin: Origin,
    /// Scope.
    pub scope: GrantScope,
    /// Lifecycle state.
    pub state: GrantState,
    /// Creation instant.
    pub created_at: Timestamp,
    /// `null` for `never`.
    pub expires_at: Option<Timestamp>,
    /// For `once`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<JobId>,
    /// For `workflow`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    /// The approval that created it.
    pub approval_id: ApprovalId,
    /// The human who decided.
    pub decided_by: Actor,
    /// Number of leases issued under it.
    pub uses: u64,
    /// The latest lease.
    #[serde(default)]
    pub last_used_at: Option<Timestamp>,
    /// When it was revoked.
    #[serde(default)]
    pub revoked_at: Option<Timestamp>,
    /// Whether a human can renew it.
    pub renewable: bool,
    /// Times it was renewed.
    #[serde(default)]
    pub renewal_count: u32,
    /// Latest human renewal time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewed_at: Option<Timestamp>,
    /// Actor who revoked this consent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<Actor>,
    /// Reason for the revocation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_reason: Option<RevocationReason>,
}

impl SessionGrant {
    /// True when the grant is `active` and not past its expiry at `now`.
    #[must_use]
    pub fn is_effective_at(&self, now: Timestamp) -> bool {
        self.state == GrantState::Active && self.expires_at.is_none_or(|e| now < e)
    }

    /// True when this grant applies to a request for `origin` made on behalf of `job` / `run`
    /// (01 section 5.2 rule 2): same exact origin, and for `once` the same job, for `workflow` the
    /// same run.
    #[must_use]
    pub fn applies_to(&self, origin: &Origin, job: Option<JobId>, run: Option<RunId>) -> bool {
        if &self.origin != origin {
            return false;
        }
        match self.scope {
            GrantScope::Once => self.job_id.is_some() && self.job_id == job,
            GrantScope::Workflow => self.run_id.is_some() && self.run_id == run,
            GrantScope::Site | GrantScope::Never => true,
        }
    }
}

/// The outcome of resolving grants for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantResolution<'a> {
    /// A `never` grant blocks the origin: handoffs are rejected and no session is ever released.
    Denied(&'a SessionGrant),
    /// The effective grant.
    Allowed(&'a SessionGrant),
    /// No effective grant: the caller asks for an approval.
    None,
}

/// Resolves the effective grant by the precedence of 01 section 5.2 rule 2: `never` (deny), then
/// `once` bound to the job, then `workflow` bound to the run, then `site`. Only active, unexpired
/// grants for the exact origin are considered.
pub fn resolve_grant<'a>(
    grants: impl IntoIterator<Item = &'a SessionGrant>,
    origin: &Origin,
    job: Option<JobId>,
    run: Option<RunId>,
    now: Timestamp,
) -> GrantResolution<'a> {
    let rank = |scope: GrantScope| match scope {
        GrantScope::Never => 0,
        GrantScope::Once => 1,
        GrantScope::Workflow => 2,
        GrantScope::Site => 3,
    };
    let best = grants
        .into_iter()
        .filter(|g| g.is_effective_at(now) && g.applies_to(origin, job, run))
        .min_by_key(|g| (rank(g.scope), g.created_at));
    match best {
        Some(g) if g.scope == GrantScope::Never => GrantResolution::Denied(g),
        Some(g) => GrantResolution::Allowed(g),
        None => GrantResolution::None,
    }
}

/// What an approval asks (01 section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// A browser handoff arrived and no effective grant covers its origin.
    Handoff,
    /// A job names a `session_origin` and none is effective.
    SessionGrant,
    /// The refresh budget is exhausted.
    RetryEscalation,
    /// A rule needs a human override (destination outside the write roots, sensitive category).
    PolicyException,
    /// A workflow plan is ready to run.
    WorkflowPlan,
    /// A file operation that deletes or overwrites.
    DestructiveOp,
    /// One exact source, cloud account revision, destination, mode and budget.
    CloudDelivery,
}

impl ApprovalKind {
    /// The scopes a human may choose for this kind (`allowed_scopes`).
    #[must_use]
    pub const fn default_allowed_scopes(self) -> &'static [GrantScope] {
        match self {
            Self::Handoff => &[GrantScope::Once, GrantScope::Site, GrantScope::Never],
            Self::SessionGrant => &[
                GrantScope::Once,
                GrantScope::Site,
                GrantScope::Workflow,
                GrantScope::Never,
            ],
            Self::WorkflowPlan => &[GrantScope::Workflow],
            Self::RetryEscalation
            | Self::PolicyException
            | Self::DestructiveOp
            | Self::CloudDelivery => &[],
        }
    }

    /// Default expiry from creation: 24 h, or 7 days for `retry_escalation` and `workflow_plan`.
    #[must_use]
    pub const fn default_expiry_ms(self) -> u64 {
        match self {
            Self::RetryEscalation | Self::WorkflowPlan => 604_800_000,
            Self::Handoff
            | Self::SessionGrant
            | Self::PolicyException
            | Self::DestructiveOp
            | Self::CloudDelivery => 86_400_000,
        }
    }
}

/// Lifecycle state of an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    /// Waiting for a human.
    Pending,
    /// Approved.
    Approved,
    /// Denied.
    Denied,
    /// The deadline passed.
    Expired,
    /// Withdrawn because the job was canceled.
    Canceled,
}

/// The decision a human (or the system, for `expire` and `cancel`) took.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    /// Approve.
    Approve,
    /// Deny.
    Deny,
    /// The deadline passed (written by `system`).
    Expire,
    /// Withdrawn (written by `system`).
    Cancel,
}

/// Display data of an approval. Everything here is computed by the daemon except `title` and
/// `requested_by`, which are untrusted text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ApprovalSummary {
    /// File name or plan title (untrusted, at most 255 characters).
    pub title: String,
    /// Redacted URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_redacted: Option<RedactedUrl>,
    /// Total size when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    /// Who asked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_kind: Option<SourceKind>,
    /// The requesting client's name (untrusted, at most 128 characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
}

/// The recorded decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Decision {
    /// What was decided.
    pub outcome: DecisionOutcome,
    /// The scope chosen (for `approve`; `deny` may carry `never`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<GrantScope>,
    /// Who decided.
    pub actor: Actor,
    /// The grant the decision created, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<GrantId>,
}

/// A request for a human decision (01 section 5.3). Immutable once decided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Approval {
    /// Identifier.
    pub id: ApprovalId,
    /// Daemon-computed BLAKE3 over canonical approval facts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_hash: Option<crate::Hex256>,
    /// Authenticated requesting credential, independent of display text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_by: Option<String>,
    /// Revision bound into the decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u32>,
    /// Daemon-computed facts, present only on full approval views.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facts: Option<serde_json::Map<String, serde_json::Value>>,
    /// Untrusted requester annotation, shown separately from trusted facts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_says: Option<String>,
    /// What is being asked.
    pub kind: ApprovalKind,
    /// Lifecycle state.
    pub state: ApprovalState,
    /// The job concerned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<JobId>,
    /// The run concerned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<RunId>,
    /// The origin concerned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    /// Scopes a human may choose.
    pub allowed_scopes: Vec<GrantScope>,
    /// Why it is needed, for example `handoff.interrupted`, `session.first_use`, `retry.exhausted`.
    pub reason_codes: Vec<String>,
    /// Display data.
    pub summary: ApprovalSummary,
    /// Creation instant.
    pub created_at: Timestamp,
    /// Expiry instant.
    pub expires_at: Timestamp,
    /// When it was decided.
    #[serde(default)]
    pub decided_at: Option<Timestamp>,
    /// The decision, once taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
}

impl Approval {
    /// True while the approval can still be decided at `now`.
    #[must_use]
    pub fn is_open_at(&self, now: Timestamp) -> bool {
        self.state == ApprovalState::Pending && now < self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::IdGenerator;

    fn origin(s: &str) -> Origin {
        Origin::parse(s).unwrap()
    }

    fn grant(scope: GrantScope, origin_text: &str, now: Timestamp) -> SessionGrant {
        let gen_ = IdGenerator::new();
        SessionGrant {
            id: gen_.grant_id(),
            origin: origin(origin_text),
            scope,
            state: GrantState::Active,
            created_at: now,
            expires_at: scope.lifetime_ms().map(|ms| now.saturating_add_ms(ms)),
            job_id: None,
            run_id: None,
            approval_id: gen_.approval_id(),
            decided_by: Actor::human(Surface::ExtensionPopup),
            uses: 0,
            last_used_at: None,
            revoked_at: None,
            renewable: scope.renewable(),
            renewal_count: 0,
            renewed_at: None,
            revoked_by: None,
            revocation_reason: None,
        }
    }

    #[test]
    fn precedence_is_never_once_workflow_site() {
        let now = Timestamp::parse("2026-10-05T09:00:00.000Z").unwrap();
        let gen_ = IdGenerator::new();
        let (job, run) = (gen_.job_id(), gen_.run_id());
        let site = grant(GrantScope::Site, "https://a.example", now);
        let mut once = grant(GrantScope::Once, "https://a.example", now);
        once.job_id = Some(job);
        let mut wf = grant(GrantScope::Workflow, "https://a.example", now);
        wf.run_id = Some(run);
        let never = grant(GrantScope::Never, "https://a.example", now);
        let o = origin("https://a.example");

        let all = [site.clone(), once.clone(), wf.clone()];
        assert_eq!(
            resolve_grant(&all, &o, Some(job), Some(run), now),
            GrantResolution::Allowed(&once)
        );
        assert_eq!(
            resolve_grant(&all, &o, None, Some(run), now),
            GrantResolution::Allowed(&wf)
        );
        assert_eq!(
            resolve_grant(&all, &o, None, None, now),
            GrantResolution::Allowed(&site)
        );
        let with_never = [site, once, wf, never.clone()];
        assert_eq!(
            resolve_grant(&with_never, &o, Some(job), Some(run), now),
            GrantResolution::Denied(&never)
        );
        assert_eq!(
            resolve_grant(&with_never, &origin("https://b.example"), None, None, now),
            GrantResolution::None
        );
    }

    #[test]
    fn expired_and_revoked_grants_do_not_count() {
        let now = Timestamp::parse("2026-10-05T09:00:00.000Z").unwrap();
        let mut g = grant(GrantScope::Site, "https://a.example", now);
        assert!(g.is_effective_at(now));
        let later = now.saturating_add_ms(SITE_TTL_MS);
        assert!(!g.is_effective_at(later), "expiry is exclusive");
        g.state = GrantState::Revoked;
        assert!(!g.is_effective_at(now));
    }

    #[test]
    fn origins_are_matched_exactly() {
        let now = Timestamp::parse("2026-10-05T09:00:00.000Z").unwrap();
        let g = grant(GrantScope::Site, "https://example.com", now);
        assert_eq!(
            resolve_grant([&g], &origin("https://cdn.example.com"), None, None, now),
            GrantResolution::None
        );
        assert_eq!(
            resolve_grant([&g], &origin("http://example.com"), None, None, now),
            GrantResolution::None
        );
    }

    #[test]
    fn only_humans_on_trust_surfaces_decide() {
        assert!(Actor::human(Surface::ExtensionPopup).is_human_on_trust_surface());
        assert!(Actor::human(Surface::CliInteractive).is_human_on_trust_surface());
        assert!(!Actor::human(Surface::Mcp).is_human_on_trust_surface());
        assert!(!Actor::agent(Surface::Mcp, "claude-code:1").is_human_on_trust_surface());
        assert!(!Actor::engine().is_human_on_trust_surface());
        let spoof = Actor {
            kind: ActorKind::Human,
            surface: None,
            client_id: None,
        };
        assert!(!spoof.is_human_on_trust_surface());
    }

    #[test]
    fn approval_kind_tables() {
        assert_eq!(
            ApprovalKind::Handoff.default_allowed_scopes(),
            &[GrantScope::Once, GrantScope::Site, GrantScope::Never]
        );
        assert!(
            ApprovalKind::RetryEscalation
                .default_allowed_scopes()
                .is_empty()
        );
        assert_eq!(ApprovalKind::WorkflowPlan.default_expiry_ms(), 604_800_000);
        assert_eq!(ApprovalKind::Handoff.default_expiry_ms(), 86_400_000);
        assert_eq!(GrantScope::Never.lifetime_ms(), None);
        assert!(GrantScope::Workflow.renewable() && !GrantScope::Site.renewable());
    }
}
