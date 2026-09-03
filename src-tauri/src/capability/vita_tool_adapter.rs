//! Host-owned adapter from the neutral Vita authority port to frozen D28.
//!
//! This module is test-only in H1.  The Digital Life host owns the canonical
//! registry, repository, and evaluator; Vita receives only the bounded verdict
//! produced here.  No Tauri command or production execution path is installed.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use vita_agent::{
    VitaAuthorityError, VitaAuthorityEvidenceSource, VitaAuthorityFuture, VitaAuthorityOutcome,
    VitaAuthorityReason, VitaAuthorityVerdict, VitaRequestedScope, VitaToolAuthorityPort,
    VitaToolAuthorityRequest,
};

use super::authorization::{
    evaluate_capability_authorization, CapabilityAuthorizationDecisionCode,
    CapabilityAuthorizationDecisionKind, CapabilityAuthorizationError,
    CapabilityAuthorizationRepository, CapabilityAuthorizationUpdateOutcome,
    LifeCapabilityAuthorization, LifeCapabilityAuthorizationCreateRequest,
    LifeCapabilityAuthorizationEvent, LifeCapabilityAuthorizationUpdateRequest,
    RequestedCapabilityScope,
};
use super::descriptor::{CapabilityId, CapabilityRegistry};
use crate::storage::StorageService;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct CanonicalVitaAuthoritySnapshot {
    pub(crate) canonical_evaluations: usize,
    pub(crate) authorization_row_reads: usize,
    pub(crate) production_registry_size: usize,
}

/// The only H1 production-catalog adapter.  Its registry is the canonical
/// production registry, which intentionally contains zero descriptors.
pub(crate) struct CanonicalVitaAuthorityAdapter {
    repository: Arc<CountingAuthorizationRepository>,
    registry: CapabilityRegistry,
    canonical_evaluations: AtomicUsize,
}

impl CanonicalVitaAuthorityAdapter {
    pub(crate) fn production(storage: Arc<StorageService>) -> Result<Arc<Self>, String> {
        let registry = CapabilityRegistry::production().map_err(|error| error.to_string())?;
        let row_reads = Arc::new(AtomicUsize::new(0));
        Ok(Arc::new(Self {
            repository: Arc::new(CountingAuthorizationRepository { storage, row_reads }),
            registry,
            canonical_evaluations: AtomicUsize::new(0),
        }))
    }

    pub(crate) fn snapshot(&self) -> CanonicalVitaAuthoritySnapshot {
        CanonicalVitaAuthoritySnapshot {
            canonical_evaluations: self.canonical_evaluations.load(Ordering::Acquire),
            authorization_row_reads: self.repository.row_reads.load(Ordering::Acquire),
            production_registry_size: self.registry.len(),
        }
    }
}

impl VitaToolAuthorityPort for CanonicalVitaAuthorityAdapter {
    fn evaluate(&self, request: VitaToolAuthorityRequest) -> VitaAuthorityFuture {
        self.canonical_evaluations.fetch_add(1, Ordering::AcqRel);
        let repository = Arc::clone(&self.repository);
        let registry = self.registry.clone();
        Box::pin(async move {
            let capability_id = CapabilityId::try_from(request.capability_id().to_owned())
                .map_err(|_| VitaAuthorityError::InvalidRequest)?;
            let Some(life_id) = request
                .context()
                .map(|context| context.life_id().to_owned())
            else {
                return Err(VitaAuthorityError::InvalidRequest);
            };
            let requested_scope = map_scope(request.requested_scope());
            match evaluate_capability_authorization(
                repository.as_ref(),
                &registry,
                &life_id,
                &capability_id,
                requested_scope,
            ) {
                Ok(decision) => map_canonical_decision(&request, &decision),
                Err(error) => map_canonical_error(&request, error),
            }
        })
    }
}

fn map_scope(scope: VitaRequestedScope) -> RequestedCapabilityScope {
    match scope {
        VitaRequestedScope::None => RequestedCapabilityScope::None,
        VitaRequestedScope::Workspace => RequestedCapabilityScope::Workspace,
        VitaRequestedScope::NetworkDestination => RequestedCapabilityScope::NetworkDestination,
        VitaRequestedScope::ExternalResource => RequestedCapabilityScope::ExternalResource,
    }
}

fn map_canonical_decision(
    request: &VitaToolAuthorityRequest,
    decision: &super::authorization::CapabilityAuthorizationDecision,
) -> Result<VitaAuthorityVerdict, VitaAuthorityError> {
    let (outcome, reason) = match (decision.outcome(), decision.decision_code()) {
        (
            CapabilityAuthorizationDecisionKind::Denied,
            CapabilityAuthorizationDecisionCode::Denied,
        ) => (VitaAuthorityOutcome::Denied, VitaAuthorityReason::Denied),
        (
            CapabilityAuthorizationDecisionKind::RootDisabled,
            CapabilityAuthorizationDecisionCode::RootDisabled,
        ) => (
            VitaAuthorityOutcome::Denied,
            VitaAuthorityReason::RootDisabled,
        ),
        (
            CapabilityAuthorizationDecisionKind::ExplicitConfirmationRequired,
            CapabilityAuthorizationDecisionCode::ExplicitConfirmationRequired,
        ) => (
            VitaAuthorityOutcome::Denied,
            VitaAuthorityReason::ExplicitConfirmationRequired,
        ),
        (
            CapabilityAuthorizationDecisionKind::ScopeRequired,
            CapabilityAuthorizationDecisionCode::ScopeNotAvailable,
        ) => (
            VitaAuthorityOutcome::Denied,
            VitaAuthorityReason::ScopeNotAvailable,
        ),
        (
            CapabilityAuthorizationDecisionKind::Forbidden,
            CapabilityAuthorizationDecisionCode::Forbidden,
        ) => (VitaAuthorityOutcome::Denied, VitaAuthorityReason::Forbidden),
        (
            CapabilityAuthorizationDecisionKind::Eligible,
            CapabilityAuthorizationDecisionCode::Eligible,
        ) => (
            VitaAuthorityOutcome::Eligible,
            VitaAuthorityReason::Eligible,
        ),
        _ => (
            VitaAuthorityOutcome::Denied,
            VitaAuthorityReason::InvalidVerdict,
        ),
    };
    VitaAuthorityVerdict::from_request(
        request,
        outcome,
        reason,
        decision.authorization_revision(),
        VitaAuthorityEvidenceSource::HostCanonicalAuthority,
    )
}

fn map_canonical_error(
    request: &VitaToolAuthorityRequest,
    error: super::authorization::CapabilityEvaluationError,
) -> Result<VitaAuthorityVerdict, VitaAuthorityError> {
    let reason = map_canonical_error_reason(error.code);
    VitaAuthorityVerdict::from_request(
        request,
        VitaAuthorityOutcome::Denied,
        reason,
        None,
        VitaAuthorityEvidenceSource::HostCanonicalAuthority,
    )
}

fn map_canonical_error_reason(
    code: super::authorization::CapabilityEvaluationErrorCode,
) -> VitaAuthorityReason {
    match code {
        super::authorization::CapabilityEvaluationErrorCode::InvalidArgument => {
            VitaAuthorityReason::InvalidRequest
        }
        super::authorization::CapabilityEvaluationErrorCode::UnknownCapability => {
            VitaAuthorityReason::UnknownCapabilityDescriptor
        }
        super::authorization::CapabilityEvaluationErrorCode::AuthorizationUnavailable => {
            VitaAuthorityReason::AuthorizationUnavailable
        }
        super::authorization::CapabilityEvaluationErrorCode::NotEligible => {
            VitaAuthorityReason::NotEligible
        }
    }
}

struct CountingAuthorizationRepository {
    storage: Arc<StorageService>,
    row_reads: Arc<AtomicUsize>,
}

impl CapabilityAuthorizationRepository for CountingAuthorizationRepository {
    fn create_capability_authorization(
        &self,
        request: LifeCapabilityAuthorizationCreateRequest,
    ) -> Result<
        super::authorization::CapabilityAuthorizationCreateOutcome,
        CapabilityAuthorizationError,
    > {
        <StorageService as CapabilityAuthorizationRepository>::create_capability_authorization(
            &self.storage,
            request,
        )
    }

    fn find_capability_authorization(
        &self,
        life_id: &str,
        capability_id: &CapabilityId,
    ) -> Result<Option<LifeCapabilityAuthorization>, CapabilityAuthorizationError> {
        self.row_reads.fetch_add(1, Ordering::AcqRel);
        <StorageService as CapabilityAuthorizationRepository>::find_capability_authorization(
            &self.storage,
            life_id,
            capability_id,
        )
    }

    fn update_capability_authorization(
        &self,
        request: LifeCapabilityAuthorizationUpdateRequest,
    ) -> Result<CapabilityAuthorizationUpdateOutcome, CapabilityAuthorizationError> {
        <StorageService as CapabilityAuthorizationRepository>::update_capability_authorization(
            &self.storage,
            request,
        )
    }

    fn find_capability_authorization_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifeCapabilityAuthorizationEvent>, CapabilityAuthorizationError> {
        <StorageService as CapabilityAuthorizationRepository>::find_capability_authorization_event(
            &self.storage,
            life_id,
            event_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::descriptor::{
        ApprovalFloor, CapabilityDescriptor, RiskClass, ScopeRequirement,
    };

    #[derive(Default)]
    struct StubRepository {
        authorization: Option<LifeCapabilityAuthorization>,
        unavailable: bool,
    }

    impl CapabilityAuthorizationRepository for StubRepository {
        fn create_capability_authorization(
            &self,
            _request: LifeCapabilityAuthorizationCreateRequest,
        ) -> Result<
            super::super::authorization::CapabilityAuthorizationCreateOutcome,
            CapabilityAuthorizationError,
        > {
            unimplemented!()
        }

        fn find_capability_authorization(
            &self,
            _life_id: &str,
            _capability_id: &CapabilityId,
        ) -> Result<Option<LifeCapabilityAuthorization>, CapabilityAuthorizationError> {
            if self.unavailable {
                Err(CapabilityAuthorizationError::database())
            } else {
                Ok(self.authorization.clone())
            }
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
    fn canonical_error_mapping_is_conservative_and_unknown_is_distinct() {
        use super::super::authorization::CapabilityEvaluationErrorCode;
        assert_eq!(
            map_canonical_error_reason(CapabilityEvaluationErrorCode::UnknownCapability),
            VitaAuthorityReason::UnknownCapabilityDescriptor
        );
        assert_eq!(
            map_canonical_error_reason(CapabilityEvaluationErrorCode::AuthorizationUnavailable),
            VitaAuthorityReason::AuthorizationUnavailable
        );
        assert_eq!(
            map_canonical_error_reason(CapabilityEvaluationErrorCode::InvalidArgument),
            VitaAuthorityReason::InvalidRequest
        );
        assert_eq!(
            map_canonical_error_reason(CapabilityEvaluationErrorCode::NotEligible),
            VitaAuthorityReason::NotEligible
        );
    }

    #[test]
    fn canonical_decision_mapping_covers_denied_root_scope_forbidden_and_eligible() {
        let cases = [
            (
                ApprovalFloor::RootEnabled,
                ScopeRequirement::None,
                StubRepository::default(),
                VitaAuthorityOutcome::Denied,
                VitaAuthorityReason::Denied,
            ),
            (
                ApprovalFloor::RootEnabled,
                ScopeRequirement::None,
                StubRepository {
                    authorization: Some(authorization("test.one", false, 1)),
                    unavailable: false,
                },
                VitaAuthorityOutcome::Denied,
                VitaAuthorityReason::RootDisabled,
            ),
            (
                ApprovalFloor::ExplicitPerAction,
                ScopeRequirement::None,
                StubRepository {
                    authorization: Some(authorization("test.one", true, 1)),
                    unavailable: false,
                },
                VitaAuthorityOutcome::Denied,
                VitaAuthorityReason::ExplicitConfirmationRequired,
            ),
            (
                ApprovalFloor::RootEnabled,
                ScopeRequirement::WorkspaceRequired,
                StubRepository {
                    authorization: Some(authorization("test.one", true, 1)),
                    unavailable: false,
                },
                VitaAuthorityOutcome::Denied,
                VitaAuthorityReason::ScopeNotAvailable,
            ),
            (
                ApprovalFloor::Forbidden,
                ScopeRequirement::None,
                StubRepository {
                    authorization: Some(authorization("test.one", true, 1)),
                    unavailable: false,
                },
                VitaAuthorityOutcome::Denied,
                VitaAuthorityReason::Forbidden,
            ),
            (
                ApprovalFloor::RootEnabled,
                ScopeRequirement::None,
                StubRepository {
                    authorization: Some(authorization("test.one", true, 1)),
                    unavailable: false,
                },
                VitaAuthorityOutcome::Eligible,
                VitaAuthorityReason::Eligible,
            ),
        ];

        for (approval_floor, scope_requirement, repository, expected_outcome, expected_reason) in
            cases
        {
            let descriptor = descriptor("test.one", approval_floor, scope_requirement);
            let registry = CapabilityRegistry::synthetic([descriptor.clone()]).unwrap();
            let decision = evaluate_capability_authorization(
                &repository,
                &registry,
                "life-a",
                descriptor.capability_id(),
                if scope_requirement == ScopeRequirement::None {
                    RequestedCapabilityScope::None
                } else {
                    RequestedCapabilityScope::Workspace
                },
            )
            .unwrap();
            let (outcome, reason) = match (decision.outcome(), decision.decision_code()) {
                (
                    CapabilityAuthorizationDecisionKind::Denied,
                    CapabilityAuthorizationDecisionCode::Denied,
                ) => (VitaAuthorityOutcome::Denied, VitaAuthorityReason::Denied),
                (
                    CapabilityAuthorizationDecisionKind::RootDisabled,
                    CapabilityAuthorizationDecisionCode::RootDisabled,
                ) => (
                    VitaAuthorityOutcome::Denied,
                    VitaAuthorityReason::RootDisabled,
                ),
                (
                    CapabilityAuthorizationDecisionKind::ExplicitConfirmationRequired,
                    CapabilityAuthorizationDecisionCode::ExplicitConfirmationRequired,
                ) => (
                    VitaAuthorityOutcome::Denied,
                    VitaAuthorityReason::ExplicitConfirmationRequired,
                ),
                (
                    CapabilityAuthorizationDecisionKind::ScopeRequired,
                    CapabilityAuthorizationDecisionCode::ScopeNotAvailable,
                ) => (
                    VitaAuthorityOutcome::Denied,
                    VitaAuthorityReason::ScopeNotAvailable,
                ),
                (
                    CapabilityAuthorizationDecisionKind::Forbidden,
                    CapabilityAuthorizationDecisionCode::Forbidden,
                ) => (VitaAuthorityOutcome::Denied, VitaAuthorityReason::Forbidden),
                (
                    CapabilityAuthorizationDecisionKind::Eligible,
                    CapabilityAuthorizationDecisionCode::Eligible,
                ) => (
                    VitaAuthorityOutcome::Eligible,
                    VitaAuthorityReason::Eligible,
                ),
                _ => (
                    VitaAuthorityOutcome::Denied,
                    VitaAuthorityReason::InvalidVerdict,
                ),
            };
            assert_eq!((outcome, reason), (expected_outcome, expected_reason));
        }
    }

    #[test]
    fn canonical_unknown_capability_short_circuits_before_repository_row_read() {
        let repository = StubRepository {
            authorization: Some(authorization("other.capability", true, 4)),
            unavailable: false,
        };
        let registry = CapabilityRegistry::production().unwrap();
        let capability_id = CapabilityId::try_from("vita.governed_action").unwrap();
        let error = evaluate_capability_authorization(
            &repository,
            &registry,
            "life-a",
            &capability_id,
            RequestedCapabilityScope::None,
        )
        .unwrap_err();
        assert_eq!(
            map_canonical_error_reason(error.code),
            VitaAuthorityReason::UnknownCapabilityDescriptor
        );
    }
}
