//! D25-D3 final local authority composition for a future Vision delivery.
//!
//! This module revalidates the current local authorities immediately before
//! asking the frozen D2 broker to claim one delivery identity.  It does not
//! resolve a destination, borrow pixels, encode an image, perform transport,
//! retire a grant, or expose an IPC surface.

use super::screen_policy::{
    authorize_screen_perception, ScreenPerceptionRepository, ScreenPerceptionSessionGate,
};
use super::screen_vision_outbound_candidate::{
    ScreenVisionOutboundCandidateBroker, ScreenVisionOutboundCandidateError,
    ScreenVisionOutboundCandidateErrorCode,
};
use super::screen_vision_outbound_destination::ScreenVisionOutboundDestinationBinding;
use super::screen_vision_outbound_grant::{
    ScreenVisionOutboundGrantBroker, ScreenVisionOutboundGrantClaimOutcome,
    ScreenVisionOutboundGrantError, ScreenVisionOutboundGrantErrorCode,
    ScreenVisionOutboundGrantMetadata,
};
use super::screen_vision_outbound_policy::{
    validate_screen_vision_outbound_policy_state, ScreenVisionOutboundPolicyRepository,
};

const MAX_ID_CHARACTERS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundDeliveryClaimErrorCode {
    InvalidArgument,
    CandidateUnavailable,
    LocalScreenAuthorityUnavailable,
    SessionFenceMismatch,
    OutboundPolicyUnavailable,
    OutboundPolicyMismatch,
    DestinationMismatch,
    GrantUnavailable,
    GrantExpired,
    GrantConsumed,
    GrantInUse,
    DeliveryConflict,
    SynchronizationUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionOutboundDeliveryClaimError {
    code: ScreenVisionOutboundDeliveryClaimErrorCode,
}

impl ScreenVisionOutboundDeliveryClaimError {
    const fn new(code: ScreenVisionOutboundDeliveryClaimErrorCode) -> Self {
        Self { code }
    }

    pub(crate) const fn code(self) -> ScreenVisionOutboundDeliveryClaimErrorCode {
        self.code
    }
}

/// Backend-resolved request evidence for one future delivery claim.  The
/// destination binding is already validated by D1; this module compares it
/// exactly and never resolves or normalizes it again.
pub(crate) struct ScreenVisionOutboundDeliveryClaimRequest {
    pub(crate) grant_id: String,
    pub(crate) delivery_id: String,
    pub(crate) candidate_id: String,
    pub(crate) destination_binding: ScreenVisionOutboundDestinationBinding,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionOutboundDeliveryClaimMetadata {
    pub(crate) grant_id: String,
    pub(crate) delivery_id: String,
    pub(crate) candidate_id: String,
    pub(crate) life_id: String,
    pub(crate) outbound_policy_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundDeliveryClaimOutcome {
    Claimed(ScreenVisionOutboundDeliveryClaimMetadata),
    Replayed(ScreenVisionOutboundDeliveryClaimMetadata),
}

/// Revalidates every local authority before delegating the sole READY→BOUND
/// transition to D2.  A BOUND retry intentionally follows the same path, so
/// it cannot bypass current D23, session-fence, D25, or C2 authority.
pub(crate) fn claim_screen_vision_outbound_delivery(
    request: ScreenVisionOutboundDeliveryClaimRequest,
    screen_repository: &dyn ScreenPerceptionRepository,
    session_gate: &ScreenPerceptionSessionGate,
    outbound_repository: &dyn ScreenVisionOutboundPolicyRepository,
    candidate_broker: &ScreenVisionOutboundCandidateBroker,
    grant_broker: &ScreenVisionOutboundGrantBroker,
) -> Result<ScreenVisionOutboundDeliveryClaimOutcome, ScreenVisionOutboundDeliveryClaimError> {
    let ScreenVisionOutboundDeliveryClaimRequest {
        grant_id,
        delivery_id,
        candidate_id,
        destination_binding,
    } = request;

    validate_id(&grant_id)?;
    validate_id(&delivery_id)?;
    validate_id(&candidate_id)?;

    let candidate = candidate_broker
        .get_exact(&candidate_id)
        .map_err(map_candidate_error)?;
    let life_id = candidate.life_id.as_str();
    let candidate_fence = candidate.screen_session_fence.as_str();
    let candidate_revision = candidate.outbound_policy_revision;

    authorize_screen_perception(screen_repository, session_gate, life_id).map_err(|_| {
        delivery_claim_error(
            ScreenVisionOutboundDeliveryClaimErrorCode::LocalScreenAuthorityUnavailable,
        )
    })?;
    let current_fence = session_gate.life_fence_for(life_id).ok_or_else(|| {
        delivery_claim_error(
            ScreenVisionOutboundDeliveryClaimErrorCode::LocalScreenAuthorityUnavailable,
        )
    })?;
    let canonical_fence = current_fence.to_string();
    if canonical_fence != candidate_fence {
        return Err(delivery_claim_error(
            ScreenVisionOutboundDeliveryClaimErrorCode::SessionFenceMismatch,
        ));
    }

    let current_revision =
        read_outbound_policy_revision(outbound_repository, life_id).map_err(|_| {
            delivery_claim_error(
                ScreenVisionOutboundDeliveryClaimErrorCode::OutboundPolicyUnavailable,
            )
        })?;
    if current_revision != candidate_revision {
        return Err(delivery_claim_error(
            ScreenVisionOutboundDeliveryClaimErrorCode::OutboundPolicyMismatch,
        ));
    }

    // This is the final C2 check immediately before the only D2 state
    // transition.  D2 remains the sole owner of READY/BOUND state and exact
    // delivery replay semantics.
    candidate_broker
        .validate_exact_candidate(&candidate_id, life_id, &canonical_fence, candidate_revision)
        .map_err(map_candidate_error)?;

    let outcome = grant_broker
        .claim_exact_for_delivery(&grant_id, &delivery_id, &candidate_id, destination_binding)
        .map_err(map_grant_error)?;

    let metadata = |grant_metadata: ScreenVisionOutboundGrantMetadata| {
        ScreenVisionOutboundDeliveryClaimMetadata {
            grant_id: grant_metadata.grant_id,
            delivery_id: delivery_id.clone(),
            candidate_id: grant_metadata.candidate_id,
            life_id: grant_metadata.life_id,
            outbound_policy_revision: grant_metadata.outbound_policy_revision,
        }
    };
    Ok(match outcome {
        ScreenVisionOutboundGrantClaimOutcome::Claimed(grant_metadata) => {
            ScreenVisionOutboundDeliveryClaimOutcome::Claimed(metadata(grant_metadata))
        }
        ScreenVisionOutboundGrantClaimOutcome::Replayed(grant_metadata) => {
            ScreenVisionOutboundDeliveryClaimOutcome::Replayed(metadata(grant_metadata))
        }
    })
}

fn delivery_claim_error(
    code: ScreenVisionOutboundDeliveryClaimErrorCode,
) -> ScreenVisionOutboundDeliveryClaimError {
    ScreenVisionOutboundDeliveryClaimError::new(code)
}

fn validate_id(value: &str) -> Result<(), ScreenVisionOutboundDeliveryClaimError> {
    if value.trim().is_empty() || value.chars().count() > MAX_ID_CHARACTERS {
        return Err(delivery_claim_error(
            ScreenVisionOutboundDeliveryClaimErrorCode::InvalidArgument,
        ));
    }
    Ok(())
}

fn map_candidate_error(
    error: ScreenVisionOutboundCandidateError,
) -> ScreenVisionOutboundDeliveryClaimError {
    let code = match error.code() {
        ScreenVisionOutboundCandidateErrorCode::SynchronizationUnavailable => {
            ScreenVisionOutboundDeliveryClaimErrorCode::SynchronizationUnavailable
        }
        _ => ScreenVisionOutboundDeliveryClaimErrorCode::CandidateUnavailable,
    };
    delivery_claim_error(code)
}

fn map_grant_error(
    error: ScreenVisionOutboundGrantError,
) -> ScreenVisionOutboundDeliveryClaimError {
    let code = match error.code() {
        ScreenVisionOutboundGrantErrorCode::InvalidArgument => {
            ScreenVisionOutboundDeliveryClaimErrorCode::InvalidArgument
        }
        ScreenVisionOutboundGrantErrorCode::GrantMismatch => {
            ScreenVisionOutboundDeliveryClaimErrorCode::GrantUnavailable
        }
        ScreenVisionOutboundGrantErrorCode::GrantExpired => {
            ScreenVisionOutboundDeliveryClaimErrorCode::GrantExpired
        }
        ScreenVisionOutboundGrantErrorCode::GrantConsumed => {
            ScreenVisionOutboundDeliveryClaimErrorCode::GrantConsumed
        }
        ScreenVisionOutboundGrantErrorCode::GrantInUse => {
            ScreenVisionOutboundDeliveryClaimErrorCode::GrantInUse
        }
        ScreenVisionOutboundGrantErrorCode::DeliveryConflict => {
            ScreenVisionOutboundDeliveryClaimErrorCode::DeliveryConflict
        }
        ScreenVisionOutboundGrantErrorCode::DestinationMismatch => {
            ScreenVisionOutboundDeliveryClaimErrorCode::DestinationMismatch
        }
        ScreenVisionOutboundGrantErrorCode::SynchronizationUnavailable => {
            ScreenVisionOutboundDeliveryClaimErrorCode::SynchronizationUnavailable
        }
        ScreenVisionOutboundGrantErrorCode::CandidateUnavailable
        | ScreenVisionOutboundGrantErrorCode::LocalScreenAuthorityUnavailable
        | ScreenVisionOutboundGrantErrorCode::SessionFenceMismatch
        | ScreenVisionOutboundGrantErrorCode::OutboundPolicyUnavailable
        | ScreenVisionOutboundGrantErrorCode::OutboundPolicyMismatch
        | ScreenVisionOutboundGrantErrorCode::ConfirmationEventConflict
        | ScreenVisionOutboundGrantErrorCode::CandidateConsumed
        | ScreenVisionOutboundGrantErrorCode::RandomUnavailable => {
            ScreenVisionOutboundDeliveryClaimErrorCode::GrantUnavailable
        }
    };
    delivery_claim_error(code)
}

fn read_outbound_policy_revision(
    repository: &dyn ScreenVisionOutboundPolicyRepository,
    life_id: &str,
) -> Result<i64, ()> {
    let policy = repository
        .find_screen_vision_outbound_policy(life_id)
        .map_err(|_| ())?
        .ok_or(())?;
    validate_screen_vision_outbound_policy_state(&policy).map_err(|_| ())?;
    if policy.life_id != life_id || !policy.is_screen_vision_outbound_enabled() {
        return Err(());
    }
    Ok(policy.revision)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perception::screen_capture::{ScreenFrame, ScreenPixelFormat};
    use crate::perception::screen_policy::{
        LifeScreenPerceptionPolicy, LifeScreenPerceptionPolicyCreateRequest,
        LifeScreenPerceptionPolicyEvent, LifeScreenPerceptionPolicyUpdateOutcome,
        LifeScreenPerceptionPolicyUpdateRequest, ScreenPerceptionCreateOutcome,
        ScreenPerceptionError, ScreenPerceptionSessionGate,
    };
    use crate::perception::screen_vision_outbound_candidate::ScreenVisionOutboundCandidateBroker;
    use crate::perception::screen_vision_outbound_destination::ScreenVisionOutboundDestinationProviderKind;
    use crate::perception::screen_vision_outbound_grant::{
        issue_user_confirmed_screen_vision_grant, ScreenVisionOutboundGrantError,
        ScreenVisionOutboundGrantErrorCode, ScreenVisionOutboundGrantMetadata,
        ScreenVisionOutboundGrantState,
    };
    use crate::perception::screen_vision_outbound_policy::{
        LifeScreenVisionOutboundPolicy, LifeScreenVisionOutboundPolicyCreateRequest,
        LifeScreenVisionOutboundPolicyEvent, LifeScreenVisionOutboundPolicyUpdateOutcome,
        LifeScreenVisionOutboundPolicyUpdateRequest, ScreenVisionOutboundPolicyCreateOutcome,
        ScreenVisionOutboundPolicyError, ScreenVisionOutboundPolicyRepository,
    };
    use crate::perception::screen_vision_outbound_projection::{
        project_screen_frame, ScreenVisionOutboundProjection,
        ScreenVisionOutboundProjectionRequest, ScreenVisionOutboundRect,
    };
    use std::sync::{Arc, Mutex};

    const LIFE_A: &str = "life-a";
    const LIFE_B: &str = "life-b";
    const REVISION_A: i64 = 7;
    const PROFILE_ID_A: &str = "profile-a";
    const BASE_URL_A: &str = "https://vision.example.invalid/v1";
    const MODEL_NAME_A: &str = "vision-model-a";
    const PROFILE_UPDATED_AT_A: &str = "2026-08-31T00:00:00Z";

    #[derive(Clone)]
    struct FakeScreenPerceptionRepository {
        policy: Arc<Mutex<Option<LifeScreenPerceptionPolicy>>>,
    }

    impl FakeScreenPerceptionRepository {
        fn enabled_for(life_id: &str) -> Self {
            Self {
                policy: Arc::new(Mutex::new(Some(LifeScreenPerceptionPolicy {
                    life_id: life_id.to_string(),
                    screen_perception_enabled: true,
                    revision: 1,
                    created_at: "2026-08-31T00:00:00Z".to_string(),
                    updated_at: "2026-08-31T00:00:00Z".to_string(),
                    policy_version:
                        crate::perception::screen_policy::SCREEN_PERCEPTION_POLICY_VERSION,
                }))),
            }
        }

        fn set_enabled(&self, enabled: bool) {
            let mut policy = self.policy.lock().expect("screen policy should lock");
            if let Some(policy) = policy.as_mut() {
                policy.screen_perception_enabled = enabled;
            }
        }
    }

    impl ScreenPerceptionRepository for FakeScreenPerceptionRepository {
        fn create_screen_perception_policy(
            &self,
            _request: LifeScreenPerceptionPolicyCreateRequest,
        ) -> Result<ScreenPerceptionCreateOutcome<LifeScreenPerceptionPolicy>, ScreenPerceptionError>
        {
            Err(ScreenPerceptionError::database())
        }

        fn find_screen_perception_policy(
            &self,
            life_id: &str,
        ) -> Result<Option<LifeScreenPerceptionPolicy>, ScreenPerceptionError> {
            Ok(self
                .policy
                .lock()
                .expect("screen policy should lock")
                .clone()
                .filter(|policy| policy.life_id == life_id))
        }

        fn update_screen_perception_policy(
            &self,
            _request: LifeScreenPerceptionPolicyUpdateRequest,
        ) -> Result<LifeScreenPerceptionPolicyUpdateOutcome, ScreenPerceptionError> {
            Err(ScreenPerceptionError::database())
        }

        fn find_screen_perception_policy_event(
            &self,
            _life_id: &str,
            _event_id: &str,
        ) -> Result<Option<LifeScreenPerceptionPolicyEvent>, ScreenPerceptionError> {
            Ok(None)
        }
    }

    #[derive(Clone)]
    struct FakeScreenVisionOutboundPolicyRepository {
        policy: Arc<Mutex<Option<LifeScreenVisionOutboundPolicy>>>,
    }

    impl FakeScreenVisionOutboundPolicyRepository {
        fn enabled_for(revision: i64) -> Self {
            Self {
                policy: Arc::new(Mutex::new(Some(LifeScreenVisionOutboundPolicy {
                    life_id: LIFE_A.to_string(),
                    screen_vision_outbound_enabled: true,
                    revision,
                    created_at: "2026-08-31T00:00:00Z".to_string(),
                    updated_at: "2026-08-31T00:00:00Z".to_string(),
                    policy_version: crate::perception::screen_vision_outbound_policy::SCREEN_VISION_OUTBOUND_POLICY_VERSION,
                }))),
            }
        }

        fn set_policy(&self, enabled: bool, revision: i64) {
            *self
                .policy
                .lock()
                .expect("outbound policy should lock") = Some(LifeScreenVisionOutboundPolicy {
                life_id: LIFE_A.to_string(),
                screen_vision_outbound_enabled: enabled,
                revision,
                created_at: "2026-08-31T00:00:00Z".to_string(),
                updated_at: "2026-08-31T00:00:00Z".to_string(),
                policy_version: crate::perception::screen_vision_outbound_policy::SCREEN_VISION_OUTBOUND_POLICY_VERSION,
            });
        }
    }

    impl ScreenVisionOutboundPolicyRepository for FakeScreenVisionOutboundPolicyRepository {
        fn create_screen_vision_outbound_policy(
            &self,
            _request: LifeScreenVisionOutboundPolicyCreateRequest,
        ) -> Result<
            ScreenVisionOutboundPolicyCreateOutcome<LifeScreenVisionOutboundPolicy>,
            ScreenVisionOutboundPolicyError,
        > {
            Err(ScreenVisionOutboundPolicyError::database())
        }

        fn find_screen_vision_outbound_policy(
            &self,
            life_id: &str,
        ) -> Result<Option<LifeScreenVisionOutboundPolicy>, ScreenVisionOutboundPolicyError>
        {
            Ok(self
                .policy
                .lock()
                .expect("outbound policy should lock")
                .clone()
                .filter(|policy| policy.life_id == life_id))
        }

        fn update_screen_vision_outbound_policy(
            &self,
            _request: LifeScreenVisionOutboundPolicyUpdateRequest,
        ) -> Result<LifeScreenVisionOutboundPolicyUpdateOutcome, ScreenVisionOutboundPolicyError>
        {
            Err(ScreenVisionOutboundPolicyError::database())
        }

        fn find_screen_vision_outbound_policy_event(
            &self,
            _life_id: &str,
            _event_id: &str,
        ) -> Result<Option<LifeScreenVisionOutboundPolicyEvent>, ScreenVisionOutboundPolicyError>
        {
            Ok(None)
        }
    }

    struct Fixture {
        screen_repository: FakeScreenPerceptionRepository,
        outbound_repository: FakeScreenVisionOutboundPolicyRepository,
        session_gate: ScreenPerceptionSessionGate,
        candidate_broker: ScreenVisionOutboundCandidateBroker,
        grant_broker: ScreenVisionOutboundGrantBroker,
        candidate_id: String,
    }

    impl Fixture {
        fn new() -> Self {
            let screen_repository = FakeScreenPerceptionRepository::enabled_for(LIFE_A);
            let outbound_repository =
                FakeScreenVisionOutboundPolicyRepository::enabled_for(REVISION_A);
            let session_gate = ScreenPerceptionSessionGate::new();
            session_gate.arm_for_life(LIFE_A);
            let candidate_broker = ScreenVisionOutboundCandidateBroker::new();
            let session_fence = session_gate
                .life_fence_for(LIFE_A)
                .expect("test session should be armed")
                .to_string();
            let candidate_id = candidate_broker
                .replace_candidate(LIFE_A, &session_fence, REVISION_A, projection())
                .expect("test candidate should install");
            Self {
                screen_repository,
                outbound_repository,
                session_gate,
                candidate_broker,
                grant_broker: ScreenVisionOutboundGrantBroker::new(),
                candidate_id,
            }
        }

        fn issue_grant(&self, confirmation_event_id: &str) -> ScreenVisionOutboundGrantMetadata {
            match issue_user_confirmed_screen_vision_grant(
                &self.grant_broker,
                confirmation_event_id,
                &self.candidate_id,
                destination(),
                &self.screen_repository,
                &self.session_gate,
                &self.outbound_repository,
                &self.candidate_broker,
            )
            .expect("test grant issue should succeed")
            {
                super::super::screen_vision_outbound_grant::ScreenVisionOutboundGrantIssueOutcome::Issued(
                    metadata,
                ) => metadata,
                super::super::screen_vision_outbound_grant::ScreenVisionOutboundGrantIssueOutcome::Replayed(
                    metadata,
                ) => metadata,
            }
        }

        fn claim(
            &self,
            grant_id: &str,
            delivery_id: &str,
            candidate_id: &str,
            destination_binding: ScreenVisionOutboundDestinationBinding,
        ) -> Result<ScreenVisionOutboundDeliveryClaimOutcome, ScreenVisionOutboundDeliveryClaimError>
        {
            claim_screen_vision_outbound_delivery(
                ScreenVisionOutboundDeliveryClaimRequest {
                    grant_id: grant_id.to_string(),
                    delivery_id: delivery_id.to_string(),
                    candidate_id: candidate_id.to_string(),
                    destination_binding,
                },
                &self.screen_repository,
                &self.session_gate,
                &self.outbound_repository,
                &self.candidate_broker,
                &self.grant_broker,
            )
        }

        fn claim_current(
            &self,
            grant_id: &str,
            delivery_id: &str,
            destination_binding: ScreenVisionOutboundDestinationBinding,
        ) -> Result<ScreenVisionOutboundDeliveryClaimOutcome, ScreenVisionOutboundDeliveryClaimError>
        {
            self.claim(
                grant_id,
                delivery_id,
                &self.candidate_id,
                destination_binding,
            )
        }

        fn replace_candidate(&self) -> String {
            let fence = self
                .session_gate
                .life_fence_for(LIFE_A)
                .expect("test session should be armed")
                .to_string();
            self.candidate_broker
                .replace_candidate(LIFE_A, &fence, REVISION_A, projection())
                .expect("replacement candidate should install")
        }
    }

    fn projection() -> ScreenVisionOutboundProjection {
        let frame = ScreenFrame {
            width: 1,
            height: 1,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: vec![3, 2, 1, 255],
        };
        let request = ScreenVisionOutboundProjectionRequest::new(
            ScreenVisionOutboundRect::new(0, 0, 1, 1),
            Vec::new(),
        );
        project_screen_frame(&frame, &request).expect("test projection should succeed")
    }

    fn destination() -> ScreenVisionOutboundDestinationBinding {
        destination_with(PROFILE_ID_A, BASE_URL_A, MODEL_NAME_A, PROFILE_UPDATED_AT_A)
    }

    fn destination_with(
        profile_id: &str,
        base_url: &str,
        model_name: &str,
        profile_updated_at: &str,
    ) -> ScreenVisionOutboundDestinationBinding {
        ScreenVisionOutboundDestinationBinding::new(
            profile_id.to_string(),
            ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible,
            base_url.to_string(),
            model_name.to_string(),
            profile_updated_at.to_string(),
        )
        .expect("test destination should be valid")
    }

    fn assert_error_code<T>(
        result: Result<T, ScreenVisionOutboundDeliveryClaimError>,
        expected: ScreenVisionOutboundDeliveryClaimErrorCode,
    ) {
        match result {
            Ok(_) => panic!("operation should fail"),
            Err(error) => assert_eq!(error.code(), expected),
        }
    }

    fn assert_grant_error_code<T>(
        result: Result<T, ScreenVisionOutboundGrantError>,
        expected: ScreenVisionOutboundGrantErrorCode,
    ) {
        match result {
            Ok(_) => panic!("grant operation should fail"),
            Err(error) => assert_eq!(error.code(), expected),
        }
    }

    fn assert_grant_state(
        fixture: &Fixture,
        grant_id: &str,
        expected: ScreenVisionOutboundGrantState,
    ) {
        let metadata = fixture
            .grant_broker
            .get_exact(grant_id)
            .expect("grant should remain available");
        assert_eq!(metadata.state, expected);
    }

    fn assert_candidate_still_current(fixture: &Fixture, candidate_id: &str) {
        let metadata = fixture
            .candidate_broker
            .get_exact(candidate_id)
            .expect("candidate should remain current");
        assert_eq!(metadata.candidate_id, candidate_id);
        assert_eq!(metadata.life_id, LIFE_A);
        assert_eq!(metadata.screen_session_fence, "1");
        assert_eq!(metadata.outbound_policy_revision, REVISION_A);
    }

    #[test]
    fn ordering_failures_happen_before_d2_claim() {
        let missing_fixture = Fixture::new();
        let missing_grant = missing_fixture.issue_grant("event-missing-candidate");
        assert_error_code(
            missing_fixture.claim(
                &missing_grant.grant_id,
                "delivery",
                "missing-candidate",
                destination(),
            ),
            ScreenVisionOutboundDeliveryClaimErrorCode::CandidateUnavailable,
        );
        assert_grant_state(
            &missing_fixture,
            &missing_grant.grant_id,
            ScreenVisionOutboundGrantState::Ready,
        );

        let expired_fixture = Fixture::new();
        let expired_grant = expired_fixture.issue_grant("event-expired-candidate");
        expired_fixture.candidate_broker.expire_current_for_test();
        assert_error_code(
            expired_fixture.claim_current(&expired_grant.grant_id, "delivery", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::CandidateUnavailable,
        );
        assert_grant_state(
            &expired_fixture,
            &expired_grant.grant_id,
            ScreenVisionOutboundGrantState::Ready,
        );

        let replaced_fixture = Fixture::new();
        let replaced_grant = replaced_fixture.issue_grant("event-replaced-candidate");
        replaced_fixture.replace_candidate();
        assert_error_code(
            replaced_fixture.claim_current(&replaced_grant.grant_id, "delivery", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::CandidateUnavailable,
        );
        assert_grant_state(
            &replaced_fixture,
            &replaced_grant.grant_id,
            ScreenVisionOutboundGrantState::Ready,
        );
    }

    #[test]
    fn d23_authority_and_fence_failures_happen_before_d2_claim() {
        let disabled_fixture = Fixture::new();
        let disabled_grant = disabled_fixture.issue_grant("event-d23-disabled");
        disabled_fixture.screen_repository.set_enabled(false);
        assert_error_code(
            disabled_fixture.claim_current(&disabled_grant.grant_id, "delivery", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::LocalScreenAuthorityUnavailable,
        );
        assert_grant_state(
            &disabled_fixture,
            &disabled_grant.grant_id,
            ScreenVisionOutboundGrantState::Ready,
        );

        let disarmed_fixture = Fixture::new();
        let disarmed_grant = disarmed_fixture.issue_grant("event-disarmed");
        disarmed_fixture.session_gate.disarm();
        assert_error_code(
            disarmed_fixture.claim_current(&disarmed_grant.grant_id, "delivery", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::LocalScreenAuthorityUnavailable,
        );
        assert_grant_state(
            &disarmed_fixture,
            &disarmed_grant.grant_id,
            ScreenVisionOutboundGrantState::Ready,
        );

        let rearmed_fixture = Fixture::new();
        let rearmed_grant = rearmed_fixture.issue_grant("event-rearmed");
        rearmed_fixture.session_gate.disarm();
        rearmed_fixture.session_gate.arm_for_life(LIFE_A);
        assert_error_code(
            rearmed_fixture.claim_current(&rearmed_grant.grant_id, "delivery", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::SessionFenceMismatch,
        );
        assert_grant_state(
            &rearmed_fixture,
            &rearmed_grant.grant_id,
            ScreenVisionOutboundGrantState::Ready,
        );

        let other_life_fixture = Fixture::new();
        let other_life_grant = other_life_fixture.issue_grant("event-other-life");
        other_life_fixture.session_gate.disarm();
        other_life_fixture.session_gate.arm_for_life(LIFE_B);
        assert_error_code(
            other_life_fixture.claim_current(&other_life_grant.grant_id, "delivery", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::LocalScreenAuthorityUnavailable,
        );
        assert_grant_state(
            &other_life_fixture,
            &other_life_grant.grant_id,
            ScreenVisionOutboundGrantState::Ready,
        );
    }

    #[test]
    fn d25_revision_and_aba_failures_happen_before_d2_claim() {
        let disabled_fixture = Fixture::new();
        let disabled_grant = disabled_fixture.issue_grant("event-outbound-disabled");
        disabled_fixture
            .outbound_repository
            .set_policy(false, REVISION_A);
        assert_error_code(
            disabled_fixture.claim_current(&disabled_grant.grant_id, "delivery", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::OutboundPolicyUnavailable,
        );
        assert_grant_state(
            &disabled_fixture,
            &disabled_grant.grant_id,
            ScreenVisionOutboundGrantState::Ready,
        );

        let revision_fixture = Fixture::new();
        let revision_grant = revision_fixture.issue_grant("event-revision");
        revision_fixture
            .outbound_repository
            .set_policy(true, REVISION_A + 1);
        assert_error_code(
            revision_fixture.claim_current(&revision_grant.grant_id, "delivery", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::OutboundPolicyMismatch,
        );
        assert_grant_state(
            &revision_fixture,
            &revision_grant.grant_id,
            ScreenVisionOutboundGrantState::Ready,
        );

        let aba_fixture = Fixture::new();
        let aba_grant = aba_fixture.issue_grant("event-aba");
        aba_fixture
            .outbound_repository
            .set_policy(false, REVISION_A + 1);
        aba_fixture
            .outbound_repository
            .set_policy(true, REVISION_A + 2);
        assert_error_code(
            aba_fixture.claim_current(&aba_grant.grant_id, "delivery", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::OutboundPolicyMismatch,
        );
        assert_grant_state(
            &aba_fixture,
            &aba_grant.grant_id,
            ScreenVisionOutboundGrantState::Ready,
        );
    }

    #[test]
    fn stable_authorities_delegate_one_exact_claim_and_preserve_candidate() {
        let fixture = Fixture::new();
        let grant = fixture.issue_grant("event-stable");
        let outcome = fixture
            .claim_current(&grant.grant_id, "delivery-stable", destination())
            .expect("stable authorities should claim");
        let metadata = match outcome {
            ScreenVisionOutboundDeliveryClaimOutcome::Claimed(metadata) => metadata,
            ScreenVisionOutboundDeliveryClaimOutcome::Replayed(_) => {
                panic!("first claim must not replay")
            }
        };
        assert_eq!(metadata.grant_id, grant.grant_id);
        assert_eq!(metadata.delivery_id, "delivery-stable");
        assert_eq!(metadata.candidate_id, fixture.candidate_id);
        assert_eq!(metadata.life_id, LIFE_A);
        assert_eq!(metadata.outbound_policy_revision, REVISION_A);
        assert_grant_state(
            &fixture,
            &grant.grant_id,
            ScreenVisionOutboundGrantState::Bound,
        );
        assert_candidate_still_current(&fixture, &fixture.candidate_id);
    }

    #[test]
    fn exact_bound_retry_revalidates_and_replays_only_with_current_authorities() {
        let fixture = Fixture::new();
        let grant = fixture.issue_grant("event-retry");
        fixture
            .claim_current(&grant.grant_id, "delivery-retry", destination())
            .expect("first claim should succeed");
        let outcome = fixture
            .claim_current(&grant.grant_id, "delivery-retry", destination())
            .expect("exact retry should replay");
        match outcome {
            ScreenVisionOutboundDeliveryClaimOutcome::Replayed(metadata) => {
                assert_eq!(metadata.grant_id, grant.grant_id)
            }
            ScreenVisionOutboundDeliveryClaimOutcome::Claimed(_) => {
                panic!("exact retry must be a replay")
            }
        }
        assert_grant_state(
            &fixture,
            &grant.grant_id,
            ScreenVisionOutboundGrantState::Bound,
        );
    }

    #[test]
    fn bound_retry_after_d25_revocation_preserves_bound_state() {
        let fixture = Fixture::new();
        let grant = fixture.issue_grant("event-bound-revocation");
        fixture
            .claim_current(&grant.grant_id, "delivery-bound-revocation", destination())
            .expect("first claim should succeed");
        fixture.outbound_repository.set_policy(false, REVISION_A);
        assert_error_code(
            fixture.claim_current(&grant.grant_id, "delivery-bound-revocation", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::OutboundPolicyUnavailable,
        );
        assert_grant_state(
            &fixture,
            &grant.grant_id,
            ScreenVisionOutboundGrantState::Bound,
        );
    }

    #[test]
    fn bound_retry_after_d25_revision_change_preserves_bound_state() {
        let fixture = Fixture::new();
        let grant = fixture.issue_grant("event-bound-revision");
        fixture
            .claim_current(&grant.grant_id, "delivery-bound-revision", destination())
            .expect("first claim should succeed");
        fixture.outbound_repository.set_policy(true, REVISION_A + 1);
        assert_error_code(
            fixture.claim_current(&grant.grant_id, "delivery-bound-revision", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::OutboundPolicyMismatch,
        );
        assert_grant_state(
            &fixture,
            &grant.grant_id,
            ScreenVisionOutboundGrantState::Bound,
        );
    }

    #[test]
    fn bound_retry_after_d23_rearm_preserves_bound_state() {
        let fixture = Fixture::new();
        let grant = fixture.issue_grant("event-bound-rearm");
        fixture
            .claim_current(&grant.grant_id, "delivery-bound-rearm", destination())
            .expect("first claim should succeed");
        fixture.session_gate.disarm();
        fixture.session_gate.arm_for_life(LIFE_A);
        assert_error_code(
            fixture.claim_current(&grant.grant_id, "delivery-bound-rearm", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::SessionFenceMismatch,
        );
        assert_grant_state(
            &fixture,
            &grant.grant_id,
            ScreenVisionOutboundGrantState::Bound,
        );
    }

    #[test]
    fn bound_retry_after_candidate_replacement_or_expiry_preserves_bound_state() {
        let replaced_fixture = Fixture::new();
        let replaced_grant = replaced_fixture.issue_grant("event-bound-replaced");
        replaced_fixture
            .claim_current(
                &replaced_grant.grant_id,
                "delivery-bound-replaced",
                destination(),
            )
            .expect("first claim should succeed");
        replaced_fixture.replace_candidate();
        assert_error_code(
            replaced_fixture.claim_current(
                &replaced_grant.grant_id,
                "delivery-bound-replaced",
                destination(),
            ),
            ScreenVisionOutboundDeliveryClaimErrorCode::CandidateUnavailable,
        );
        assert_grant_state(
            &replaced_fixture,
            &replaced_grant.grant_id,
            ScreenVisionOutboundGrantState::Bound,
        );

        let expired_fixture = Fixture::new();
        let expired_grant = expired_fixture.issue_grant("event-bound-expired");
        expired_fixture
            .claim_current(
                &expired_grant.grant_id,
                "delivery-bound-expired",
                destination(),
            )
            .expect("first claim should succeed");
        expired_fixture.candidate_broker.expire_current_for_test();
        assert_error_code(
            expired_fixture.claim_current(
                &expired_grant.grant_id,
                "delivery-bound-expired",
                destination(),
            ),
            ScreenVisionOutboundDeliveryClaimErrorCode::CandidateUnavailable,
        );
        assert_grant_state(
            &expired_fixture,
            &expired_grant.grant_id,
            ScreenVisionOutboundGrantState::Bound,
        );
    }

    #[test]
    fn destination_drift_and_different_delivery_preserve_bound_state() {
        let destination_fixture = Fixture::new();
        let destination_grant = destination_fixture.issue_grant("event-bound-destination");
        destination_fixture
            .claim_current(
                &destination_grant.grant_id,
                "delivery-bound-destination",
                destination(),
            )
            .expect("first claim should succeed");
        assert_error_code(
            destination_fixture.claim_current(
                &destination_grant.grant_id,
                "delivery-bound-destination",
                destination_with("profile-b", BASE_URL_A, MODEL_NAME_A, PROFILE_UPDATED_AT_A),
            ),
            ScreenVisionOutboundDeliveryClaimErrorCode::DestinationMismatch,
        );
        assert_grant_state(
            &destination_fixture,
            &destination_grant.grant_id,
            ScreenVisionOutboundGrantState::Bound,
        );

        let delivery_fixture = Fixture::new();
        let delivery_grant = delivery_fixture.issue_grant("event-bound-delivery");
        delivery_fixture
            .claim_current(&delivery_grant.grant_id, "delivery-bound-a", destination())
            .expect("first claim should succeed");
        assert_error_code(
            delivery_fixture.claim_current(
                &delivery_grant.grant_id,
                "delivery-bound-b",
                destination(),
            ),
            ScreenVisionOutboundDeliveryClaimErrorCode::DeliveryConflict,
        );
        assert_grant_state(
            &delivery_fixture,
            &delivery_grant.grant_id,
            ScreenVisionOutboundGrantState::Bound,
        );
    }

    #[test]
    fn d3_never_creates_or_retires_grants_and_d2_errors_are_bounded() {
        let fixture = Fixture::new();
        assert_error_code(
            fixture.claim_current("unissued-grant", "delivery", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::GrantUnavailable,
        );
        assert_grant_error_code(
            fixture.grant_broker.get_exact("unissued-grant"),
            ScreenVisionOutboundGrantErrorCode::GrantMismatch,
        );

        let claimed_fixture = Fixture::new();
        let grant = claimed_fixture.issue_grant("event-no-retire");
        claimed_fixture
            .claim_current(&grant.grant_id, "delivery-no-retire", destination())
            .expect("first claim should succeed");
        assert_grant_state(
            &claimed_fixture,
            &grant.grant_id,
            ScreenVisionOutboundGrantState::Bound,
        );
        assert_candidate_still_current(&claimed_fixture, &claimed_fixture.candidate_id);
    }

    #[test]
    fn invalid_ids_fail_before_any_authority_or_d2_operation() {
        let fixture = Fixture::new();
        let grant = fixture.issue_grant("event-invalid-ids");
        assert_error_code(
            fixture.claim_current("", "delivery", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::InvalidArgument,
        );
        assert_error_code(
            fixture.claim_current(&grant.grant_id, "", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::InvalidArgument,
        );
        assert_error_code(
            fixture.claim(&grant.grant_id, "delivery", "", destination()),
            ScreenVisionOutboundDeliveryClaimErrorCode::InvalidArgument,
        );
        assert_grant_state(
            &fixture,
            &grant.grant_id,
            ScreenVisionOutboundGrantState::Ready,
        );
    }

    #[test]
    fn production_d3_source_has_no_pixel_network_provider_or_ipc_surface() {
        let production = include_str!("screen_vision_outbound_delivery_claim.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source should precede tests");
        for forbidden in [
            "tauri::command",
            "reqwest::Client",
            ".send(",
            "base64",
            "multipart",
            "SecretStore",
            "ModelPurpose",
            "VisionProvider",
            "Serialize",
            "ScreenVisionOutboundProjection",
            "as_bytes",
            "with_bytes",
            "get_bytes",
            "borrow_pixels",
            "encode_image",
            "retire_bound_after_success",
            "StorageService",
            "HashMap",
            "ScreenCaptureOperationGate",
        ] {
            assert!(
                !production.contains(forbidden),
                "D3 production source must not contain {forbidden}"
            );
        }
    }
}
