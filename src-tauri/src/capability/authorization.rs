use super::descriptor::{ApprovalFloor, CapabilityId, CapabilityRegistry, ScopeRequirement};

const MAX_ID_LENGTH: usize = 128;
const USER_EXPLICIT_ACTOR_KIND: &str = "user_explicit";
const USER_AUTHORIZATION_ROOT_PROVENANCE_KIND: &str = "user_authorization_root";
const USER_EXPLICIT_EVIDENCE_VERSION: i64 = 1;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifeCapabilityAuthorization {
    pub(crate) life_id: String,
    pub(crate) capability_id: CapabilityId,
    pub(crate) enabled: bool,
    pub(crate) revision: i64,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifeCapabilityAuthorizationCreateRequest {
    pub(crate) life_id: String,
    pub(crate) capability_id: CapabilityId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifeCapabilityAuthorizationUpdateRequest {
    life_id: String,
    capability_id: CapabilityId,
    enabled: bool,
    expected_revision: i64,
    user_explicit_evidence: UserExplicitCapabilityAuthorizationEvidence,
}

/// Opaque evidence that can only be minted by an explicit user authorization
/// boundary. Production code can consume its fixed provenance, but cannot
/// construct an enabling request by supplying free-form evidence strings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UserExplicitCapabilityAuthorizationEvidence {
    event_id: String,
    actor_kind: UserExplicitActorKind,
    provenance_kind: UserAuthorizationRootProvenanceKind,
    evidence_version: UserExplicitEvidenceVersion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UserExplicitActorKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UserAuthorizationRootProvenanceKind;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UserExplicitEvidenceVersion;

impl UserExplicitCapabilityAuthorizationEvidence {
    pub(crate) fn event_id(&self) -> &str {
        &self.event_id
    }

    pub(crate) fn actor_kind(&self) -> &'static str {
        let _ = self.actor_kind;
        USER_EXPLICIT_ACTOR_KIND
    }

    pub(crate) fn provenance_kind(&self) -> &'static str {
        let _ = self.provenance_kind;
        USER_AUTHORIZATION_ROOT_PROVENANCE_KIND
    }

    pub(crate) fn evidence_version(&self) -> i64 {
        let _ = self.evidence_version;
        USER_EXPLICIT_EVIDENCE_VERSION
    }

    #[cfg(any(test, feature = "d29-h3-host-fixture"))]
    pub(crate) fn for_test(event_id: impl Into<String>) -> Self {
        Self {
            event_id: event_id.into(),
            actor_kind: UserExplicitActorKind,
            provenance_kind: UserAuthorizationRootProvenanceKind,
            evidence_version: UserExplicitEvidenceVersion,
        }
    }
}

impl LifeCapabilityAuthorizationUpdateRequest {
    pub(crate) fn event_id(&self) -> &str {
        self.user_explicit_evidence.event_id()
    }

    pub(crate) fn life_id(&self) -> &str {
        &self.life_id
    }

    pub(crate) fn capability_id(&self) -> &CapabilityId {
        &self.capability_id
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn expected_revision(&self) -> i64 {
        self.expected_revision
    }

    pub(crate) fn user_explicit_evidence(&self) -> &UserExplicitCapabilityAuthorizationEvidence {
        &self.user_explicit_evidence
    }

    #[cfg(any(test, feature = "d29-h3-host-fixture"))]
    pub(crate) fn for_test(
        event_id: impl Into<String>,
        life_id: impl Into<String>,
        capability_id: CapabilityId,
        enabled: bool,
        expected_revision: i64,
    ) -> Self {
        Self {
            life_id: life_id.into(),
            capability_id,
            enabled,
            expected_revision,
            user_explicit_evidence: UserExplicitCapabilityAuthorizationEvidence::for_test(event_id),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifeCapabilityAuthorizationEvent {
    event_id: String,
    life_id: String,
    capability_id: CapabilityId,
    old_enabled: bool,
    new_enabled: bool,
    old_revision: i64,
    new_revision: i64,
    changed_at: String,
    actor_kind: String,
    provenance_kind: String,
    evidence_version: i64,
}

impl LifeCapabilityAuthorizationEvent {
    pub(crate) fn event_id(&self) -> &str {
        &self.event_id
    }

    pub(crate) fn life_id(&self) -> &str {
        &self.life_id
    }

    pub(crate) fn capability_id(&self) -> &CapabilityId {
        &self.capability_id
    }

    pub(crate) fn old_enabled(&self) -> bool {
        self.old_enabled
    }

    pub(crate) fn new_enabled(&self) -> bool {
        self.new_enabled
    }

    pub(crate) fn old_revision(&self) -> i64 {
        self.old_revision
    }

    pub(crate) fn new_revision(&self) -> i64 {
        self.new_revision
    }

    pub(crate) fn changed_at(&self) -> &str {
        &self.changed_at
    }

    pub(crate) fn actor_kind(&self) -> &str {
        &self.actor_kind
    }

    pub(crate) fn provenance_kind(&self) -> &str {
        &self.provenance_kind
    }

    pub(crate) fn evidence_version(&self) -> i64 {
        self.evidence_version
    }

    pub(crate) fn from_update(
        request: &LifeCapabilityAuthorizationUpdateRequest,
        old_enabled: bool,
        old_revision: i64,
        changed_at: String,
    ) -> Self {
        let evidence = request.user_explicit_evidence();
        Self {
            event_id: request.event_id().to_owned(),
            life_id: request.life_id().to_owned(),
            capability_id: request.capability_id().clone(),
            old_enabled,
            new_enabled: request.enabled(),
            old_revision,
            new_revision: old_revision + 1,
            changed_at,
            actor_kind: evidence.actor_kind().to_owned(),
            provenance_kind: evidence.provenance_kind().to_owned(),
            evidence_version: evidence.evidence_version(),
        }
    }

    pub(crate) fn from_persisted(
        event_id: String,
        life_id: String,
        capability_id: CapabilityId,
        old_enabled: bool,
        new_enabled: bool,
        old_revision: i64,
        new_revision: i64,
        changed_at: String,
        actor_kind: String,
        provenance_kind: String,
        evidence_version: i64,
    ) -> Self {
        Self {
            event_id,
            life_id,
            capability_id,
            old_enabled,
            new_enabled,
            old_revision,
            new_revision,
            changed_at,
            actor_kind,
            provenance_kind,
            evidence_version,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityAuthorizationCreateOutcome {
    Applied(LifeCapabilityAuthorization),
    Replayed(LifeCapabilityAuthorization),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityAuthorizationUpdateOutcome {
    Applied {
        event: LifeCapabilityAuthorizationEvent,
        authorization: LifeCapabilityAuthorization,
    },
    Replayed {
        event: LifeCapabilityAuthorizationEvent,
        current: LifeCapabilityAuthorization,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityAuthorizationErrorCode {
    InvalidArgument,
    LifeNotFound,
    AuthorizationNotFound,
    AuthorizationConflict,
    EventConflict,
    RevisionConflict,
    InvalidTransition,
    DatabaseUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityAuthorizationError {
    pub(crate) code: CapabilityAuthorizationErrorCode,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

impl CapabilityAuthorizationError {
    fn new(code: CapabilityAuthorizationErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable: matches!(
                code,
                CapabilityAuthorizationErrorCode::LifeNotFound
                    | CapabilityAuthorizationErrorCode::AuthorizationNotFound
                    | CapabilityAuthorizationErrorCode::RevisionConflict
                    | CapabilityAuthorizationErrorCode::DatabaseUnavailable
            ),
        }
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(CapabilityAuthorizationErrorCode::InvalidArgument, message)
    }

    pub(crate) fn life_not_found() -> Self {
        Self::new(
            CapabilityAuthorizationErrorCode::LifeNotFound,
            "The specified life was not found.",
        )
    }

    pub(crate) fn authorization_not_found() -> Self {
        Self::new(
            CapabilityAuthorizationErrorCode::AuthorizationNotFound,
            "No capability authorization exists for the specified life and capability.",
        )
    }

    pub(crate) fn authorization_conflict() -> Self {
        Self::new(
            CapabilityAuthorizationErrorCode::AuthorizationConflict,
            "A capability authorization with conflicting identity evidence already exists.",
        )
    }

    pub(crate) fn event_conflict() -> Self {
        Self::new(
            CapabilityAuthorizationErrorCode::EventConflict,
            "A capability authorization event with conflicting evidence already exists.",
        )
    }

    pub(crate) fn revision_conflict() -> Self {
        Self::new(
            CapabilityAuthorizationErrorCode::RevisionConflict,
            "The capability authorization changed after it was loaded. Refresh and try again.",
        )
    }

    pub(crate) fn invalid_transition() -> Self {
        Self::new(
            CapabilityAuthorizationErrorCode::InvalidTransition,
            "The capability authorization update must change the current boolean state.",
        )
    }

    pub(crate) fn database() -> Self {
        Self::new(
            CapabilityAuthorizationErrorCode::DatabaseUnavailable,
            "The capability authorization storage operation failed.",
        )
    }
}

/// The only crate-internal persistence boundary for the durable user root.
/// No caller supplies SQL, JSON, prompt text, model output, credentials, or
/// executable arguments through this trait.
pub(crate) trait CapabilityAuthorizationRepository: Send + Sync {
    fn create_capability_authorization(
        &self,
        request: LifeCapabilityAuthorizationCreateRequest,
    ) -> Result<CapabilityAuthorizationCreateOutcome, CapabilityAuthorizationError>;

    fn find_capability_authorization(
        &self,
        life_id: &str,
        capability_id: &CapabilityId,
    ) -> Result<Option<LifeCapabilityAuthorization>, CapabilityAuthorizationError>;

    fn update_capability_authorization(
        &self,
        request: LifeCapabilityAuthorizationUpdateRequest,
    ) -> Result<CapabilityAuthorizationUpdateOutcome, CapabilityAuthorizationError>;

    fn find_capability_authorization_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifeCapabilityAuthorizationEvent>, CapabilityAuthorizationError>;
}

pub(crate) fn validate_create_request(
    request: &LifeCapabilityAuthorizationCreateRequest,
) -> Result<(), CapabilityAuthorizationError> {
    validate_life_id(&request.life_id)
}

pub(crate) fn validate_update_request(
    request: &LifeCapabilityAuthorizationUpdateRequest,
) -> Result<(), CapabilityAuthorizationError> {
    validate_identity("authorization event identity", request.event_id())?;
    validate_life_id(request.life_id())?;
    validate_expected_revision(request.expected_revision())?;
    validate_explicit_evidence(request.user_explicit_evidence())
}

pub(crate) fn validate_authorization_state(
    authorization: &LifeCapabilityAuthorization,
) -> Result<(), CapabilityAuthorizationError> {
    validate_life_id(&authorization.life_id)?;
    validate_persisted_revision(authorization.revision)?;
    validate_timestamp("authorization created_at", &authorization.created_at)?;
    validate_timestamp("authorization updated_at", &authorization.updated_at)
}

pub(crate) fn validate_event_state(
    event: &LifeCapabilityAuthorizationEvent,
) -> Result<(), CapabilityAuthorizationError> {
    validate_identity("authorization event identity", event.event_id())?;
    validate_life_id(event.life_id())?;
    if event.old_enabled() == event.new_enabled() {
        return Err(CapabilityAuthorizationError::invalid_argument(
            "a capability authorization event must represent a boolean transition.",
        ));
    }
    validate_expected_revision(event.old_revision())?;
    if event.new_revision() != event.old_revision() + 1 {
        return Err(CapabilityAuthorizationError::invalid_argument(
            "a capability authorization event must advance the revision by exactly one.",
        ));
    }
    validate_timestamp("authorization event changed_at", event.changed_at())?;
    if event.actor_kind() != USER_EXPLICIT_ACTOR_KIND
        || event.provenance_kind() != USER_AUTHORIZATION_ROOT_PROVENANCE_KIND
        || event.evidence_version() != USER_EXPLICIT_EVIDENCE_VERSION
    {
        return Err(CapabilityAuthorizationError::invalid_argument(
            "authorization event evidence must be the fixed explicit-user authorization root.",
        ));
    }
    Ok(())
}

fn validate_explicit_evidence(
    evidence: &UserExplicitCapabilityAuthorizationEvidence,
) -> Result<(), CapabilityAuthorizationError> {
    if evidence.actor_kind() != USER_EXPLICIT_ACTOR_KIND
        || evidence.provenance_kind() != USER_AUTHORIZATION_ROOT_PROVENANCE_KIND
        || evidence.evidence_version() != USER_EXPLICIT_EVIDENCE_VERSION
    {
        return Err(CapabilityAuthorizationError::invalid_argument(
            "authorization update evidence must be the fixed explicit-user authorization root.",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RequestedCapabilityScope {
    None,
    Workspace,
    NetworkDestination,
    ExternalResource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityAuthorizationDecisionKind {
    Denied,
    RootDisabled,
    ExplicitConfirmationRequired,
    ScopeRequired,
    Forbidden,
    Eligible,
}

pub(crate) const CAPABILITY_SCOPE_NOT_AVAILABLE: &str = "CAPABILITY_SCOPE_NOT_AVAILABLE";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityAuthorizationDecisionCode {
    Denied,
    RootDisabled,
    ExplicitConfirmationRequired,
    ScopeNotAvailable,
    Forbidden,
    Eligible,
}

impl CapabilityAuthorizationDecisionCode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Denied => "CAPABILITY_AUTHORIZATION_DENIED",
            Self::RootDisabled => "CAPABILITY_ROOT_DISABLED",
            Self::ExplicitConfirmationRequired => "CAPABILITY_CONFIRMATION_REQUIRED",
            Self::ScopeNotAvailable => CAPABILITY_SCOPE_NOT_AVAILABLE,
            Self::Forbidden => "CAPABILITY_FORBIDDEN",
            Self::Eligible => "CAPABILITY_ELIGIBLE",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityAuthorizationDecision {
    life_id: String,
    capability_id: CapabilityId,
    outcome: CapabilityAuthorizationDecisionKind,
    decision_code: CapabilityAuthorizationDecisionCode,
    /// Evidence from the fresh SQLite read. This is never itself a grant.
    authorization_revision: Option<i64>,
    approval_floor: ApprovalFloor,
    scope_requirement: ScopeRequirement,
    provenance: EvaluatorIssued,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EvaluatorIssued;

impl CapabilityAuthorizationDecision {
    fn issued(
        life_id: String,
        capability_id: CapabilityId,
        outcome: CapabilityAuthorizationDecisionKind,
        decision_code: CapabilityAuthorizationDecisionCode,
        authorization_revision: Option<i64>,
        approval_floor: ApprovalFloor,
        scope_requirement: ScopeRequirement,
    ) -> Self {
        Self {
            life_id,
            capability_id,
            outcome,
            decision_code,
            authorization_revision,
            approval_floor,
            scope_requirement,
            provenance: EvaluatorIssued,
        }
    }

    pub(crate) fn life_id(&self) -> &str {
        &self.life_id
    }

    pub(crate) fn capability_id(&self) -> &CapabilityId {
        &self.capability_id
    }

    pub(crate) fn outcome(&self) -> CapabilityAuthorizationDecisionKind {
        self.outcome
    }

    pub(crate) fn decision_code(&self) -> CapabilityAuthorizationDecisionCode {
        self.decision_code
    }

    pub(crate) fn authorization_revision(&self) -> Option<i64> {
        self.authorization_revision
    }

    pub(crate) fn approval_floor(&self) -> ApprovalFloor {
        self.approval_floor
    }

    pub(crate) fn scope_requirement(&self) -> ScopeRequirement {
        self.scope_requirement
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityEvaluationErrorCode {
    InvalidArgument,
    UnknownCapability,
    AuthorizationUnavailable,
    NotEligible,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityEvaluationError {
    pub(crate) code: CapabilityEvaluationErrorCode,
    pub(crate) message: String,
}

impl CapabilityEvaluationError {
    fn new(code: CapabilityEvaluationErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// Evaluates against the current SQLite row on every invocation. The
/// capability descriptor is always resolved from the canonical registry by
/// ID; no caller-supplied descriptor participates. No frontend, model,
/// persona, emotion, relationship, experience, goal, plan, action-intent,
/// autonomy, or vision value participates.
pub(crate) fn evaluate_capability_authorization(
    repository: &dyn CapabilityAuthorizationRepository,
    registry: &CapabilityRegistry,
    life_id: &str,
    capability_id: &CapabilityId,
    requested_scope: RequestedCapabilityScope,
) -> Result<CapabilityAuthorizationDecision, CapabilityEvaluationError> {
    validate_life_id(life_id).map_err(|error| {
        CapabilityEvaluationError::new(
            CapabilityEvaluationErrorCode::InvalidArgument,
            error.message,
        )
    })?;
    let descriptor = registry.descriptor(capability_id).ok_or_else(|| {
        CapabilityEvaluationError::new(
            CapabilityEvaluationErrorCode::UnknownCapability,
            "The capability ID is not present in the trusted registry.",
        )
    })?;

    let authorization = repository
        .find_capability_authorization(life_id, capability_id)
        .map_err(|_| {
            CapabilityEvaluationError::new(
                CapabilityEvaluationErrorCode::AuthorizationUnavailable,
                "The current capability authorization could not be read.",
            )
        })?;

    let Some(authorization) = authorization else {
        return Ok(CapabilityAuthorizationDecision::issued(
            life_id.to_string(),
            capability_id.clone(),
            CapabilityAuthorizationDecisionKind::Denied,
            CapabilityAuthorizationDecisionCode::Denied,
            None,
            descriptor.approval_floor(),
            descriptor.scope_requirement(),
        ));
    };
    if validate_authorization_state(&authorization).is_err() {
        return Err(CapabilityEvaluationError::new(
            CapabilityEvaluationErrorCode::AuthorizationUnavailable,
            "The current capability authorization row is malformed.",
        ));
    }
    if authorization.life_id != life_id || authorization.capability_id != *capability_id {
        return Err(CapabilityEvaluationError::new(
            CapabilityEvaluationErrorCode::AuthorizationUnavailable,
            "The current capability authorization row has mismatched identity evidence.",
        ));
    }

    let (outcome, decision_code) = if descriptor.approval_floor() == ApprovalFloor::Forbidden {
        (
            CapabilityAuthorizationDecisionKind::Forbidden,
            CapabilityAuthorizationDecisionCode::Forbidden,
        )
    } else if !authorization.enabled {
        (
            CapabilityAuthorizationDecisionKind::RootDisabled,
            CapabilityAuthorizationDecisionCode::RootDisabled,
        )
    } else if descriptor.scope_requirement() != ScopeRequirement::None
        || requested_scope != RequestedCapabilityScope::None
    {
        (
            CapabilityAuthorizationDecisionKind::ScopeRequired,
            CapabilityAuthorizationDecisionCode::ScopeNotAvailable,
        )
    } else if descriptor.approval_floor() == ApprovalFloor::ExplicitPerAction {
        (
            CapabilityAuthorizationDecisionKind::ExplicitConfirmationRequired,
            CapabilityAuthorizationDecisionCode::ExplicitConfirmationRequired,
        )
    } else {
        (
            CapabilityAuthorizationDecisionKind::Eligible,
            CapabilityAuthorizationDecisionCode::Eligible,
        )
    };

    Ok(CapabilityAuthorizationDecision::issued(
        life_id.to_string(),
        capability_id.clone(),
        outcome,
        decision_code,
        Some(authorization.revision),
        descriptor.approval_floor(),
        descriptor.scope_requirement(),
    ))
}

/// A typed, crate-internal, non-executable candidate for a later stage. It is
/// intentionally not serializable, persistable, transferable, or runnable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityGrantCandidate {
    life_id: String,
    task_id: String,
    capability_id: CapabilityId,
    authorization_revision: i64,
    approval_floor: ApprovalFloor,
    provenance: CandidateIssued,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CandidateIssued;

impl CapabilityGrantCandidate {
    pub(crate) fn life_id(&self) -> &str {
        &self.life_id
    }

    pub(crate) fn task_id(&self) -> &str {
        &self.task_id
    }

    pub(crate) fn capability_id(&self) -> &CapabilityId {
        &self.capability_id
    }

    pub(crate) fn authorization_revision(&self) -> i64 {
        self.authorization_revision
    }

    pub(crate) fn approval_floor(&self) -> ApprovalFloor {
        self.approval_floor
    }
}

/// Issues only a bounded, non-executable candidate from a fresh SQLite read.
/// A caller cannot turn a previously returned Decision into a candidate.
pub(crate) fn issue_capability_grant_candidate(
    repository: &dyn CapabilityAuthorizationRepository,
    registry: &CapabilityRegistry,
    life_id: &str,
    task_id: &str,
    capability_id: &CapabilityId,
    requested_scope: RequestedCapabilityScope,
) -> Result<CapabilityGrantCandidate, CapabilityEvaluationError> {
    validate_life_id(life_id).map_err(|error| {
        CapabilityEvaluationError::new(
            CapabilityEvaluationErrorCode::InvalidArgument,
            error.message,
        )
    })?;
    validate_task_id(task_id)?;

    let decision = evaluate_capability_authorization(
        repository,
        registry,
        life_id,
        capability_id,
        requested_scope,
    )?;
    let _evaluator_issued = decision.provenance;
    if decision.life_id() != life_id
        || decision.capability_id() != capability_id
        || decision.outcome() != CapabilityAuthorizationDecisionKind::Eligible
        || decision.decision_code() != CapabilityAuthorizationDecisionCode::Eligible
        || decision.scope_requirement() != ScopeRequirement::None
        || decision.approval_floor() != ApprovalFloor::RootEnabled
    {
        return Err(CapabilityEvaluationError::new(
            CapabilityEvaluationErrorCode::NotEligible,
            "only a fresh eligible root-enabled, no-scope decision can form a candidate.",
        ));
    }
    let authorization_revision = decision.authorization_revision().ok_or_else(|| {
        CapabilityEvaluationError::new(
            CapabilityEvaluationErrorCode::AuthorizationUnavailable,
            "an eligible decision must carry current authorization evidence.",
        )
    })?;
    Ok(CapabilityGrantCandidate {
        life_id: life_id.to_string(),
        task_id: task_id.to_string(),
        capability_id: capability_id.clone(),
        authorization_revision,
        approval_floor: decision.approval_floor(),
        provenance: CandidateIssued,
    })
}

fn validate_life_id(value: &str) -> Result<(), CapabilityAuthorizationError> {
    validate_identity("life identity", value)
}

fn validate_task_id(value: &str) -> Result<(), CapabilityEvaluationError> {
    if value.is_empty()
        || value.chars().count() > MAX_ID_LENGTH
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(CapabilityEvaluationError::new(
            CapabilityEvaluationErrorCode::InvalidArgument,
            "task identity must be non-empty and bounded.",
        ));
    }
    Ok(())
}

fn validate_identity(name: &str, value: &str) -> Result<(), CapabilityAuthorizationError> {
    if value.is_empty()
        || value.chars().count() > MAX_ID_LENGTH
        || value
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(CapabilityAuthorizationError::invalid_argument(format!(
            "{name} must be non-empty and bounded."
        )));
    }
    Ok(())
}

fn validate_persisted_revision(revision: i64) -> Result<(), CapabilityAuthorizationError> {
    if revision < 1 {
        return Err(CapabilityAuthorizationError::invalid_argument(
            "revision must be at least one.",
        ));
    }
    Ok(())
}

fn validate_expected_revision(revision: i64) -> Result<(), CapabilityAuthorizationError> {
    if !(1..i64::MAX).contains(&revision) {
        return Err(CapabilityAuthorizationError::invalid_argument(
            "revision must leave room for exactly one next revision.",
        ));
    }
    Ok(())
}

fn validate_timestamp(name: &str, value: &str) -> Result<(), CapabilityAuthorizationError> {
    if value.trim().is_empty() {
        return Err(CapabilityAuthorizationError::invalid_argument(format!(
            "{name} must not be empty."
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::descriptor::{CapabilityDescriptor, RiskClass, ScopeRequirement};

    #[derive(Default)]
    struct StubRepository {
        authorization: Option<LifeCapabilityAuthorization>,
    }

    impl CapabilityAuthorizationRepository for StubRepository {
        fn create_capability_authorization(
            &self,
            _request: LifeCapabilityAuthorizationCreateRequest,
        ) -> Result<CapabilityAuthorizationCreateOutcome, CapabilityAuthorizationError> {
            unimplemented!()
        }

        fn find_capability_authorization(
            &self,
            _life_id: &str,
            _capability_id: &CapabilityId,
        ) -> Result<Option<LifeCapabilityAuthorization>, CapabilityAuthorizationError> {
            Ok(self.authorization.clone())
        }

        fn update_capability_authorization(
            &self,
            _request: LifeCapabilityAuthorizationUpdateRequest,
        ) -> Result<CapabilityAuthorizationUpdateOutcome, CapabilityAuthorizationError> {
            unimplemented!()
        }

        fn find_capability_authorization_event(
            &self,
            _life_id: &str,
            _event_id: &str,
        ) -> Result<Option<LifeCapabilityAuthorizationEvent>, CapabilityAuthorizationError>
        {
            Ok(None)
        }
    }

    fn descriptor(
        id: &str,
        approval_floor: ApprovalFloor,
        scope_requirement: ScopeRequirement,
    ) -> CapabilityDescriptor {
        CapabilityDescriptor::synthetic(
            CapabilityId::try_from(id).unwrap(),
            "Synthetic capability",
            RiskClass::Low,
            approval_floor,
            scope_requirement,
        )
        .unwrap()
    }

    fn authorization(
        capability_id: &str,
        enabled: bool,
        revision: i64,
    ) -> LifeCapabilityAuthorization {
        LifeCapabilityAuthorization {
            life_id: "life-a".into(),
            capability_id: CapabilityId::try_from(capability_id).unwrap(),
            enabled,
            revision,
            created_at: "2026-09-01T00:00:00.000Z".into(),
            updated_at: "2026-09-01T00:00:00.000Z".into(),
        }
    }

    #[test]
    fn decision_is_default_deny_and_reads_current_revision_evidence() {
        let known_descriptor = descriptor(
            "test.one",
            ApprovalFloor::RootEnabled,
            ScopeRequirement::None,
        );
        let registry = CapabilityRegistry::synthetic([known_descriptor.clone()]).unwrap();
        let capability_id = known_descriptor.capability_id().clone();

        let denied = evaluate_capability_authorization(
            &StubRepository::default(),
            &registry,
            "life-a",
            &capability_id,
            RequestedCapabilityScope::None,
        )
        .unwrap();
        assert_eq!(
            denied.outcome(),
            CapabilityAuthorizationDecisionKind::Denied
        );
        assert_eq!(denied.authorization_revision(), None);

        let enabled = StubRepository {
            authorization: Some(authorization("test.one", true, 7)),
        };
        let eligible = evaluate_capability_authorization(
            &enabled,
            &registry,
            "life-a",
            &capability_id,
            RequestedCapabilityScope::None,
        )
        .unwrap();
        assert_eq!(
            eligible.outcome(),
            CapabilityAuthorizationDecisionKind::Eligible
        );
        assert_eq!(
            eligible.decision_code(),
            CapabilityAuthorizationDecisionCode::Eligible
        );
        assert_eq!(eligible.authorization_revision(), Some(7));
    }

    #[test]
    fn approval_floor_and_scope_can_only_restrict_a_root() {
        let explicit = descriptor(
            "test.explicit",
            ApprovalFloor::ExplicitPerAction,
            ScopeRequirement::None,
        );
        let scoped = descriptor(
            "test.workspace",
            ApprovalFloor::RootEnabled,
            ScopeRequirement::WorkspaceRequired,
        );
        let network_scoped = descriptor(
            "test.network",
            ApprovalFloor::RootEnabled,
            ScopeRequirement::NetworkDestinationRequired,
        );
        let forbidden = descriptor(
            "test.forbidden",
            ApprovalFloor::Forbidden,
            ScopeRequirement::None,
        );
        let registry = CapabilityRegistry::synthetic([
            explicit.clone(),
            scoped.clone(),
            network_scoped.clone(),
            forbidden.clone(),
        ])
        .unwrap();
        let explicit_repository = StubRepository {
            authorization: Some(authorization("test.explicit", true, 2)),
        };
        let scoped_repository = StubRepository {
            authorization: Some(authorization("test.workspace", true, 2)),
        };
        let network_scoped_repository = StubRepository {
            authorization: Some(authorization("test.network", true, 2)),
        };
        let forbidden_repository = StubRepository {
            authorization: Some(authorization("test.forbidden", true, 2)),
        };

        assert_eq!(
            evaluate_capability_authorization(
                &explicit_repository,
                &registry,
                "life-a",
                explicit.capability_id(),
                RequestedCapabilityScope::None,
            )
            .unwrap()
            .outcome(),
            CapabilityAuthorizationDecisionKind::ExplicitConfirmationRequired
        );
        assert_eq!(
            evaluate_capability_authorization(
                &scoped_repository,
                &registry,
                "life-a",
                scoped.capability_id(),
                RequestedCapabilityScope::Workspace,
            )
            .unwrap()
            .outcome(),
            CapabilityAuthorizationDecisionKind::ScopeRequired
        );
        let network_decision = evaluate_capability_authorization(
            &network_scoped_repository,
            &registry,
            "life-a",
            network_scoped.capability_id(),
            RequestedCapabilityScope::NetworkDestination,
        )
        .unwrap();
        assert_eq!(
            network_decision.outcome(),
            CapabilityAuthorizationDecisionKind::ScopeRequired
        );
        assert_eq!(
            network_decision.decision_code(),
            CapabilityAuthorizationDecisionCode::ScopeNotAvailable
        );
        assert_eq!(
            network_decision.decision_code().as_str(),
            CAPABILITY_SCOPE_NOT_AVAILABLE
        );
        assert_eq!(
            evaluate_capability_authorization(
                &forbidden_repository,
                &registry,
                "life-a",
                forbidden.capability_id(),
                RequestedCapabilityScope::None,
            )
            .unwrap()
            .outcome(),
            CapabilityAuthorizationDecisionKind::Forbidden
        );
    }

    #[test]
    fn candidate_is_bounded_non_executable_and_scope_required_never_becomes_eligible() {
        let known_descriptor = descriptor(
            "test.one",
            ApprovalFloor::RootEnabled,
            ScopeRequirement::None,
        );
        let registry = CapabilityRegistry::synthetic([known_descriptor.clone()]).unwrap();
        let repository = StubRepository {
            authorization: Some(authorization("test.one", true, 3)),
        };
        let candidate = issue_capability_grant_candidate(
            &repository,
            &registry,
            "life-a",
            "task-1",
            known_descriptor.capability_id(),
            RequestedCapabilityScope::None,
        )
        .unwrap();
        assert_eq!(candidate.life_id(), "life-a");
        assert_eq!(candidate.task_id(), "task-1");
        assert_eq!(candidate.capability_id(), known_descriptor.capability_id());
        assert_eq!(candidate.authorization_revision(), 3);
        assert_eq!(candidate.approval_floor(), ApprovalFloor::RootEnabled);
        assert!(issue_capability_grant_candidate(
            &repository,
            &registry,
            "life-a",
            " ",
            known_descriptor.capability_id(),
            RequestedCapabilityScope::None,
        )
        .is_err());

        let scoped_descriptor = descriptor(
            "test.scoped",
            ApprovalFloor::RootEnabled,
            ScopeRequirement::WorkspaceRequired,
        );
        let scoped_registry = CapabilityRegistry::synthetic([scoped_descriptor.clone()]).unwrap();
        let scoped_repository = StubRepository {
            authorization: Some(authorization("test.scoped", true, 4)),
        };
        let scoped_decision = evaluate_capability_authorization(
            &scoped_repository,
            &scoped_registry,
            "life-a",
            scoped_descriptor.capability_id(),
            RequestedCapabilityScope::Workspace,
        )
        .unwrap();
        assert_eq!(
            scoped_decision.outcome(),
            CapabilityAuthorizationDecisionKind::ScopeRequired
        );
        assert!(issue_capability_grant_candidate(
            &scoped_repository,
            &scoped_registry,
            "life-a",
            "task-2",
            scoped_descriptor.capability_id(),
            RequestedCapabilityScope::Workspace,
        )
        .is_err());

        assert!(issue_capability_grant_candidate(
            &repository,
            &registry,
            "another-life",
            "task-1",
            known_descriptor.capability_id(),
            RequestedCapabilityScope::None,
        )
        .is_err());
    }

    #[test]
    fn canonical_lookup_by_id_rejects_unknown_and_ignores_caller_descriptor_shape() {
        let known_descriptor = descriptor(
            "test.one",
            ApprovalFloor::RootEnabled,
            ScopeRequirement::None,
        );
        let other = descriptor(
            "test.other",
            ApprovalFloor::RootEnabled,
            ScopeRequirement::None,
        );
        let registry = CapabilityRegistry::synthetic([known_descriptor.clone()]).unwrap();
        let error = evaluate_capability_authorization(
            &StubRepository {
                authorization: Some(authorization("test.other", true, 9)),
            },
            &registry,
            "life-a",
            other.capability_id(),
            RequestedCapabilityScope::None,
        )
        .unwrap_err();
        assert_eq!(error.code, CapabilityEvaluationErrorCode::UnknownCapability);

        let canonical = registry
            .descriptor(known_descriptor.capability_id())
            .unwrap();
        assert_eq!(canonical.approval_floor(), ApprovalFloor::RootEnabled);
        assert_eq!(canonical.scope_requirement(), ScopeRequirement::None);
    }

    #[test]
    fn explicit_evidence_is_fixed_and_malformed_persisted_evidence_fails_closed() {
        let request = LifeCapabilityAuthorizationUpdateRequest::for_test(
            "event-1",
            "life-a",
            CapabilityId::try_from("test.one").unwrap(),
            true,
            1,
        );
        validate_update_request(&request).unwrap();
        assert_eq!(request.event_id(), "event-1");
        assert_eq!(
            request.user_explicit_evidence().actor_kind(),
            USER_EXPLICIT_ACTOR_KIND
        );
        assert_eq!(
            request.user_explicit_evidence().provenance_kind(),
            USER_AUTHORIZATION_ROOT_PROVENANCE_KIND
        );
        assert_eq!(
            request.user_explicit_evidence().evidence_version(),
            USER_EXPLICIT_EVIDENCE_VERSION
        );

        let malformed = LifeCapabilityAuthorizationEvent::from_persisted(
            "event-1".into(),
            "life-a".into(),
            CapabilityId::try_from("test.one").unwrap(),
            false,
            true,
            1,
            2,
            "2026-09-01T00:00:00.000Z".into(),
            "model_output".into(),
            USER_AUTHORIZATION_ROOT_PROVENANCE_KIND.into(),
            USER_EXPLICIT_EVIDENCE_VERSION,
        );
        assert!(validate_event_state(&malformed).is_err());
    }
}
