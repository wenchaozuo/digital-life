use super::descriptor::{
    ApprovalFloor, CapabilityDescriptor, CapabilityId, CapabilityRegistry, ScopeRequirement,
};

const MAX_ID_LENGTH: usize = 128;

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
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) capability_id: CapabilityId,
    pub(crate) enabled: bool,
    pub(crate) expected_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifeCapabilityAuthorizationEvent {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) capability_id: CapabilityId,
    pub(crate) old_enabled: bool,
    pub(crate) new_enabled: bool,
    pub(crate) old_revision: i64,
    pub(crate) new_revision: i64,
    pub(crate) changed_at: String,
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
    validate_identity("authorization event identity", &request.event_id)?;
    validate_life_id(&request.life_id)?;
    validate_expected_revision(request.expected_revision)
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
    validate_identity("authorization event identity", &event.event_id)?;
    validate_life_id(&event.life_id)?;
    if event.old_enabled == event.new_enabled {
        return Err(CapabilityAuthorizationError::invalid_argument(
            "a capability authorization event must represent a boolean transition.",
        ));
    }
    validate_expected_revision(event.old_revision)?;
    if event.new_revision != event.old_revision + 1 {
        return Err(CapabilityAuthorizationError::invalid_argument(
            "a capability authorization event must advance the revision by exactly one.",
        ));
    }
    validate_timestamp("authorization event changed_at", &event.changed_at)
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
    pub(crate) life_id: String,
    pub(crate) capability_id: CapabilityId,
    pub(crate) outcome: CapabilityAuthorizationDecisionKind,
    pub(crate) decision_code: CapabilityAuthorizationDecisionCode,
    /// Evidence from the fresh SQLite read. This is never itself a grant.
    pub(crate) authorization_revision: Option<i64>,
    pub(crate) approval_floor: ApprovalFloor,
    pub(crate) scope_requirement: ScopeRequirement,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CapabilityEvaluationErrorCode {
    InvalidArgument,
    UnknownCapability,
    AuthorizationUnavailable,
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
/// descriptor must be the exact object reconstructed from the trusted static
/// registry; no frontend, model, persona, emotion, relationship, experience,
/// goal, plan, action-intent, autonomy, or vision value participates.
pub(crate) fn evaluate_capability_authorization(
    repository: &dyn CapabilityAuthorizationRepository,
    registry: &CapabilityRegistry,
    life_id: &str,
    descriptor: &CapabilityDescriptor,
    requested_scope: RequestedCapabilityScope,
) -> Result<CapabilityAuthorizationDecision, CapabilityEvaluationError> {
    validate_life_id(life_id).map_err(|error| {
        CapabilityEvaluationError::new(
            CapabilityEvaluationErrorCode::InvalidArgument,
            error.message,
        )
    })?;
    if !registry.contains_exact(descriptor) {
        return Err(CapabilityEvaluationError::new(
            CapabilityEvaluationErrorCode::UnknownCapability,
            "The capability descriptor is not present in the trusted registry.",
        ));
    }

    let authorization = repository
        .find_capability_authorization(life_id, &descriptor.capability_id)
        .map_err(|_| {
            CapabilityEvaluationError::new(
                CapabilityEvaluationErrorCode::AuthorizationUnavailable,
                "The current capability authorization could not be read.",
            )
        })?;

    let Some(authorization) = authorization else {
        return Ok(CapabilityAuthorizationDecision {
            life_id: life_id.to_string(),
            capability_id: descriptor.capability_id.clone(),
            outcome: CapabilityAuthorizationDecisionKind::Denied,
            decision_code: CapabilityAuthorizationDecisionCode::Denied,
            authorization_revision: None,
            approval_floor: descriptor.approval_floor,
            scope_requirement: descriptor.scope_requirement,
        });
    };
    if validate_authorization_state(&authorization).is_err() {
        return Err(CapabilityEvaluationError::new(
            CapabilityEvaluationErrorCode::AuthorizationUnavailable,
            "The current capability authorization row is malformed.",
        ));
    }
    if authorization.life_id != life_id || authorization.capability_id != descriptor.capability_id {
        return Err(CapabilityEvaluationError::new(
            CapabilityEvaluationErrorCode::AuthorizationUnavailable,
            "The current capability authorization row has mismatched identity evidence.",
        ));
    }

    let (outcome, decision_code) = if descriptor.approval_floor == ApprovalFloor::Forbidden {
        (
            CapabilityAuthorizationDecisionKind::Forbidden,
            CapabilityAuthorizationDecisionCode::Forbidden,
        )
    } else if !authorization.enabled {
        (
            CapabilityAuthorizationDecisionKind::RootDisabled,
            CapabilityAuthorizationDecisionCode::RootDisabled,
        )
    } else if descriptor.scope_requirement != ScopeRequirement::None
        || requested_scope != RequestedCapabilityScope::None
    {
        (
            CapabilityAuthorizationDecisionKind::ScopeRequired,
            CapabilityAuthorizationDecisionCode::ScopeNotAvailable,
        )
    } else if descriptor.approval_floor == ApprovalFloor::ExplicitPerAction {
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

    Ok(CapabilityAuthorizationDecision {
        life_id: life_id.to_string(),
        capability_id: descriptor.capability_id.clone(),
        outcome,
        decision_code,
        authorization_revision: Some(authorization.revision),
        approval_floor: descriptor.approval_floor,
        scope_requirement: descriptor.scope_requirement,
    })
}

/// A typed, crate-internal, non-executable candidate for a later stage. It is
/// intentionally not serializable, persistable, transferable, or runnable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CapabilityGrantCandidate {
    pub(crate) life_id: String,
    pub(crate) task_id: String,
    pub(crate) capability_id: CapabilityId,
    pub(crate) authorization_revision: i64,
    pub(crate) approval_floor: ApprovalFloor,
}

impl CapabilityGrantCandidate {
    pub(crate) fn from_eligible_decision(
        decision: &CapabilityAuthorizationDecision,
        life_id: &str,
        task_id: &str,
    ) -> Result<Self, CapabilityEvaluationError> {
        validate_life_id(life_id).map_err(|error| {
            CapabilityEvaluationError::new(
                CapabilityEvaluationErrorCode::InvalidArgument,
                error.message,
            )
        })?;
        validate_task_id(task_id)?;
        if decision.life_id != life_id {
            return Err(CapabilityEvaluationError::new(
                CapabilityEvaluationErrorCode::InvalidArgument,
                "a capability candidate cannot be rebound to another life.",
            ));
        }
        if decision.outcome != CapabilityAuthorizationDecisionKind::Eligible
            || decision.decision_code != CapabilityAuthorizationDecisionCode::Eligible
            || decision.scope_requirement != ScopeRequirement::None
            || decision.approval_floor != ApprovalFloor::RootEnabled
        {
            return Err(CapabilityEvaluationError::new(
                CapabilityEvaluationErrorCode::InvalidArgument,
                "only an eligible root-enabled, no-scope decision can form a candidate.",
            ));
        }
        let authorization_revision = decision.authorization_revision.ok_or_else(|| {
            CapabilityEvaluationError::new(
                CapabilityEvaluationErrorCode::AuthorizationUnavailable,
                "an eligible decision must carry current authorization evidence.",
            )
        })?;
        Ok(Self {
            life_id: life_id.to_string(),
            task_id: task_id.to_string(),
            capability_id: decision.capability_id.clone(),
            authorization_revision,
            approval_floor: decision.approval_floor,
        })
    }
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
    use crate::capability::descriptor::{RiskClass, ScopeRequirement};

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
        CapabilityDescriptor::new(
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
        let registry =
            CapabilityRegistry::from_trusted_descriptors([known_descriptor.clone()]).unwrap();

        let denied = evaluate_capability_authorization(
            &StubRepository::default(),
            &registry,
            "life-a",
            &known_descriptor,
            RequestedCapabilityScope::None,
        )
        .unwrap();
        assert_eq!(denied.outcome, CapabilityAuthorizationDecisionKind::Denied);
        assert_eq!(denied.authorization_revision, None);

        let enabled = StubRepository {
            authorization: Some(authorization("test.one", true, 7)),
        };
        let eligible = evaluate_capability_authorization(
            &enabled,
            &registry,
            "life-a",
            &known_descriptor,
            RequestedCapabilityScope::None,
        )
        .unwrap();
        assert_eq!(
            eligible.outcome,
            CapabilityAuthorizationDecisionKind::Eligible
        );
        assert_eq!(
            eligible.decision_code,
            CapabilityAuthorizationDecisionCode::Eligible
        );
        assert_eq!(eligible.authorization_revision, Some(7));
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
        let registry = CapabilityRegistry::from_trusted_descriptors([
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
                &explicit,
                RequestedCapabilityScope::None,
            )
            .unwrap()
            .outcome,
            CapabilityAuthorizationDecisionKind::ExplicitConfirmationRequired
        );
        assert_eq!(
            evaluate_capability_authorization(
                &scoped_repository,
                &registry,
                "life-a",
                &scoped,
                RequestedCapabilityScope::Workspace,
            )
            .unwrap()
            .outcome,
            CapabilityAuthorizationDecisionKind::ScopeRequired
        );
        let network_decision = evaluate_capability_authorization(
            &network_scoped_repository,
            &registry,
            "life-a",
            &network_scoped,
            RequestedCapabilityScope::NetworkDestination,
        )
        .unwrap();
        assert_eq!(
            network_decision.outcome,
            CapabilityAuthorizationDecisionKind::ScopeRequired
        );
        assert_eq!(
            network_decision.decision_code,
            CapabilityAuthorizationDecisionCode::ScopeNotAvailable
        );
        assert_eq!(
            network_decision.decision_code.as_str(),
            CAPABILITY_SCOPE_NOT_AVAILABLE
        );
        assert_eq!(
            evaluate_capability_authorization(
                &forbidden_repository,
                &registry,
                "life-a",
                &forbidden,
                RequestedCapabilityScope::None,
            )
            .unwrap()
            .outcome,
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
        let registry =
            CapabilityRegistry::from_trusted_descriptors([known_descriptor.clone()]).unwrap();
        let repository = StubRepository {
            authorization: Some(authorization("test.one", true, 3)),
        };
        let decision = evaluate_capability_authorization(
            &repository,
            &registry,
            "life-a",
            &known_descriptor,
            RequestedCapabilityScope::None,
        )
        .unwrap();
        let candidate =
            CapabilityGrantCandidate::from_eligible_decision(&decision, "life-a", "task-1")
                .unwrap();
        assert_eq!(candidate.authorization_revision, 3);
        assert!(
            CapabilityGrantCandidate::from_eligible_decision(&decision, "life-a", " ",).is_err()
        );

        let scoped_descriptor = descriptor(
            "test.scoped",
            ApprovalFloor::RootEnabled,
            ScopeRequirement::WorkspaceRequired,
        );
        let scoped_registry =
            CapabilityRegistry::from_trusted_descriptors([scoped_descriptor.clone()]).unwrap();
        let scoped_repository = StubRepository {
            authorization: Some(authorization("test.scoped", true, 4)),
        };
        let scoped_decision = evaluate_capability_authorization(
            &scoped_repository,
            &scoped_registry,
            "life-a",
            &scoped_descriptor,
            RequestedCapabilityScope::Workspace,
        )
        .unwrap();
        assert_eq!(
            scoped_decision.outcome,
            CapabilityAuthorizationDecisionKind::ScopeRequired
        );
        assert!(CapabilityGrantCandidate::from_eligible_decision(
            &scoped_decision,
            "life-a",
            "task-2"
        )
        .is_err());

        assert!(CapabilityGrantCandidate::from_eligible_decision(
            &decision,
            "another-life",
            "task-1",
        )
        .is_err());
    }

    #[test]
    fn unknown_descriptor_and_malformed_task_fail_closed() {
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
        let registry =
            CapabilityRegistry::from_trusted_descriptors([known_descriptor.clone()]).unwrap();
        let error = evaluate_capability_authorization(
            &StubRepository {
                authorization: Some(authorization("test.other", true, 9)),
            },
            &registry,
            "life-a",
            &other,
            RequestedCapabilityScope::None,
        )
        .unwrap_err();
        assert_eq!(error.code, CapabilityEvaluationErrorCode::UnknownCapability);
    }
}
