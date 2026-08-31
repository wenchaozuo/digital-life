//! D25-A durable Life-scoped authority for a future screen-vision outbound use.
//!
//! This module contains only the durable policy contract and its explicit
//! user-event evidence.  It does not observe a screen, hold a capture target,
//! select a provider, or perform any external operation.  The D23 local
//! screen-perception consent remains a separate authority and is never read
//! by this module.

pub(crate) const SCREEN_VISION_OUTBOUND_POLICY_VERSION: i64 = 1;
pub(crate) const SCREEN_VISION_OUTBOUND_POLICY_EVENT_VERSION: i64 = 1;
pub(crate) const SCREEN_VISION_OUTBOUND_POLICY_ACTOR_KIND_USER_EXPLICIT: &str = "user_explicit";
const MAX_ID_LENGTH: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifeScreenVisionOutboundPolicy {
    pub(crate) life_id: String,
    pub(crate) screen_vision_outbound_enabled: bool,
    pub(crate) revision: i64,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) policy_version: i64,
}

impl LifeScreenVisionOutboundPolicy {
    pub(crate) fn is_screen_vision_outbound_enabled(&self) -> bool {
        self.screen_vision_outbound_enabled
    }
}

/// Creation intentionally carries no enabled value.  A newly created policy
/// is always disabled and starts at revision one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifeScreenVisionOutboundPolicyCreateRequest {
    pub(crate) life_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifeScreenVisionOutboundPolicyUpdateRequest {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) screen_vision_outbound_enabled: bool,
    pub(crate) expected_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifeScreenVisionOutboundPolicyEvent {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) old_screen_vision_outbound_enabled: bool,
    pub(crate) new_screen_vision_outbound_enabled: bool,
    pub(crate) expected_revision: i64,
    pub(crate) applied_revision: i64,
    pub(crate) actor_kind: String,
    pub(crate) occurred_at: String,
    pub(crate) event_version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundPolicyCreateOutcome<T> {
    Applied(T),
    Replayed(T),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LifeScreenVisionOutboundPolicyUpdateOutcome {
    Applied {
        event: LifeScreenVisionOutboundPolicyEvent,
        policy: LifeScreenVisionOutboundPolicy,
    },
    Replayed {
        event: LifeScreenVisionOutboundPolicyEvent,
        current: LifeScreenVisionOutboundPolicy,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundPolicyErrorCode {
    InvalidArgument,
    LifeNotFound,
    PolicyNotFound,
    PolicyDisabled,
    PolicyConflict,
    PolicyEventConflict,
    RevisionConflict,
    InvalidTransition,
    DatabaseUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionOutboundPolicyError {
    pub(crate) code: ScreenVisionOutboundPolicyErrorCode,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

impl ScreenVisionOutboundPolicyError {
    pub(crate) fn new(
        code: ScreenVisionOutboundPolicyErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable: matches!(
                code,
                ScreenVisionOutboundPolicyErrorCode::LifeNotFound
                    | ScreenVisionOutboundPolicyErrorCode::PolicyNotFound
                    | ScreenVisionOutboundPolicyErrorCode::PolicyDisabled
                    | ScreenVisionOutboundPolicyErrorCode::DatabaseUnavailable
            ),
        }
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(
            ScreenVisionOutboundPolicyErrorCode::InvalidArgument,
            message,
        )
    }

    pub(crate) fn life_not_found() -> Self {
        Self::new(
            ScreenVisionOutboundPolicyErrorCode::LifeNotFound,
            "The specified life was not found.",
        )
    }

    pub(crate) fn policy_not_found() -> Self {
        Self::new(
            ScreenVisionOutboundPolicyErrorCode::PolicyNotFound,
            "No screen vision outbound policy exists for the specified life.",
        )
    }

    pub(crate) fn policy_disabled() -> Self {
        Self::new(
            ScreenVisionOutboundPolicyErrorCode::PolicyDisabled,
            "Screen vision outbound is disabled for the specified life.",
        )
    }

    pub(crate) fn policy_conflict() -> Self {
        Self::new(
            ScreenVisionOutboundPolicyErrorCode::PolicyConflict,
            "A screen vision outbound policy with conflicting evidence already exists.",
        )
    }

    pub(crate) fn policy_event_conflict() -> Self {
        Self::new(
            ScreenVisionOutboundPolicyErrorCode::PolicyEventConflict,
            "A screen vision outbound policy event with conflicting evidence already exists.",
        )
    }

    pub(crate) fn revision_conflict() -> Self {
        Self::new(
            ScreenVisionOutboundPolicyErrorCode::RevisionConflict,
            "The screen vision outbound policy changed after it was loaded. Refresh and try again.",
        )
    }

    pub(crate) fn invalid_transition() -> Self {
        Self::new(
            ScreenVisionOutboundPolicyErrorCode::InvalidTransition,
            "The screen vision outbound policy update does not change its current state.",
        )
    }

    pub(crate) fn database() -> Self {
        Self::new(
            ScreenVisionOutboundPolicyErrorCode::DatabaseUnavailable,
            "The screen vision outbound authority storage operation failed.",
        )
    }
}

/// Crate-internal persistence boundary for the D25-A authority.  This trait
/// intentionally exposes no observation, image, transport, or provider
/// operation.
pub(crate) trait ScreenVisionOutboundPolicyRepository: Send + Sync {
    fn create_screen_vision_outbound_policy(
        &self,
        request: LifeScreenVisionOutboundPolicyCreateRequest,
    ) -> Result<
        ScreenVisionOutboundPolicyCreateOutcome<LifeScreenVisionOutboundPolicy>,
        ScreenVisionOutboundPolicyError,
    >;

    fn find_screen_vision_outbound_policy(
        &self,
        life_id: &str,
    ) -> Result<Option<LifeScreenVisionOutboundPolicy>, ScreenVisionOutboundPolicyError>;

    fn update_screen_vision_outbound_policy(
        &self,
        request: LifeScreenVisionOutboundPolicyUpdateRequest,
    ) -> Result<LifeScreenVisionOutboundPolicyUpdateOutcome, ScreenVisionOutboundPolicyError>;

    fn find_screen_vision_outbound_policy_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifeScreenVisionOutboundPolicyEvent>, ScreenVisionOutboundPolicyError>;
}

pub(crate) fn validate_screen_vision_outbound_policy_create_request(
    request: &LifeScreenVisionOutboundPolicyCreateRequest,
) -> Result<(), ScreenVisionOutboundPolicyError> {
    validate_life_id(&request.life_id)
}

pub(crate) fn validate_screen_vision_outbound_policy_update_request(
    request: &LifeScreenVisionOutboundPolicyUpdateRequest,
) -> Result<(), ScreenVisionOutboundPolicyError> {
    validate_id("policy event identity", &request.event_id)?;
    validate_life_id(&request.life_id)?;
    validate_expected_revision(request.expected_revision)
}

pub(crate) fn validate_screen_vision_outbound_policy_state(
    policy: &LifeScreenVisionOutboundPolicy,
) -> Result<(), ScreenVisionOutboundPolicyError> {
    validate_life_id(&policy.life_id)?;
    validate_persisted_revision(policy.revision)?;
    if policy.policy_version != SCREEN_VISION_OUTBOUND_POLICY_VERSION {
        return Err(ScreenVisionOutboundPolicyError::invalid_argument(
            "screen vision outbound policy version must be 1.",
        ));
    }
    validate_required_timestamp("policy created_at", &policy.created_at)?;
    validate_required_timestamp("policy updated_at", &policy.updated_at)
}

pub(crate) fn validate_screen_vision_outbound_policy_event_state(
    event: &LifeScreenVisionOutboundPolicyEvent,
) -> Result<(), ScreenVisionOutboundPolicyError> {
    validate_id("policy event identity", &event.event_id)?;
    validate_life_id(&event.life_id)?;
    if event.old_screen_vision_outbound_enabled == event.new_screen_vision_outbound_enabled {
        return Err(ScreenVisionOutboundPolicyError::invalid_argument(
            "screen vision outbound policy event must represent a boolean state transition.",
        ));
    }
    validate_expected_revision(event.expected_revision)?;
    if Some(event.applied_revision) != event.expected_revision.checked_add(1) {
        return Err(ScreenVisionOutboundPolicyError::invalid_argument(
            "screen vision outbound policy event applied revision must equal expected revision plus one.",
        ));
    }
    if event.actor_kind != SCREEN_VISION_OUTBOUND_POLICY_ACTOR_KIND_USER_EXPLICIT {
        return Err(ScreenVisionOutboundPolicyError::invalid_argument(
            "screen vision outbound policy event actor kind must be user_explicit.",
        ));
    }
    if event.event_version != SCREEN_VISION_OUTBOUND_POLICY_EVENT_VERSION {
        return Err(ScreenVisionOutboundPolicyError::invalid_argument(
            "screen vision outbound policy event version must be 1.",
        ));
    }
    validate_required_timestamp("policy event occurred_at", &event.occurred_at)
}

/// Authorizes only the durable Life-scoped outbound policy.  A future caller
/// must add its own local/session, privacy, one-shot, and destination checks;
/// this helper is deliberately not a complete delivery authorization.
pub(crate) fn authorize_screen_vision_outbound(
    repository: &dyn ScreenVisionOutboundPolicyRepository,
    life_id: &str,
) -> Result<(), ScreenVisionOutboundPolicyError> {
    validate_life_id(life_id)?;
    let policy = repository
        .find_screen_vision_outbound_policy(life_id)?
        .ok_or_else(ScreenVisionOutboundPolicyError::policy_not_found)?;
    if !policy.is_screen_vision_outbound_enabled() {
        return Err(ScreenVisionOutboundPolicyError::policy_disabled());
    }
    Ok(())
}

fn validate_life_id(value: &str) -> Result<(), ScreenVisionOutboundPolicyError> {
    if value.trim().is_empty() {
        return Err(ScreenVisionOutboundPolicyError::invalid_argument(
            "life identity must not be empty.",
        ));
    }
    Ok(())
}

fn validate_id(name: &str, value: &str) -> Result<(), ScreenVisionOutboundPolicyError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_ID_LENGTH {
        return Err(ScreenVisionOutboundPolicyError::invalid_argument(format!(
            "{name} must be between 1 and {MAX_ID_LENGTH} characters after trimming."
        )));
    }
    Ok(())
}

fn validate_persisted_revision(revision: i64) -> Result<(), ScreenVisionOutboundPolicyError> {
    if revision < 1 {
        return Err(ScreenVisionOutboundPolicyError::invalid_argument(
            "revision must be at least 1.",
        ));
    }
    Ok(())
}

fn validate_expected_revision(revision: i64) -> Result<(), ScreenVisionOutboundPolicyError> {
    if !(1..i64::MAX).contains(&revision) {
        return Err(ScreenVisionOutboundPolicyError::invalid_argument(
            "expected revision must be between 1 and the maximum representable next revision.",
        ));
    }
    Ok(())
}

fn validate_required_timestamp(
    name: &str,
    value: &str,
) -> Result<(), ScreenVisionOutboundPolicyError> {
    if value.trim().is_empty() {
        return Err(ScreenVisionOutboundPolicyError::invalid_argument(format!(
            "{name} must not be empty."
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct StubRepository {
        policy: Option<LifeScreenVisionOutboundPolicy>,
    }

    impl ScreenVisionOutboundPolicyRepository for StubRepository {
        fn create_screen_vision_outbound_policy(
            &self,
            _request: LifeScreenVisionOutboundPolicyCreateRequest,
        ) -> Result<
            ScreenVisionOutboundPolicyCreateOutcome<LifeScreenVisionOutboundPolicy>,
            ScreenVisionOutboundPolicyError,
        > {
            unimplemented!()
        }

        fn find_screen_vision_outbound_policy(
            &self,
            _life_id: &str,
        ) -> Result<Option<LifeScreenVisionOutboundPolicy>, ScreenVisionOutboundPolicyError>
        {
            Ok(self.policy.clone())
        }

        fn update_screen_vision_outbound_policy(
            &self,
            _request: LifeScreenVisionOutboundPolicyUpdateRequest,
        ) -> Result<LifeScreenVisionOutboundPolicyUpdateOutcome, ScreenVisionOutboundPolicyError>
        {
            unimplemented!()
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

    fn policy(enabled: bool) -> LifeScreenVisionOutboundPolicy {
        LifeScreenVisionOutboundPolicy {
            life_id: "life-a".into(),
            screen_vision_outbound_enabled: enabled,
            revision: 1,
            created_at: "2026-08-31T00:00:00.000Z".into(),
            updated_at: "2026-08-31T00:00:00.000Z".into(),
            policy_version: SCREEN_VISION_OUTBOUND_POLICY_VERSION,
        }
    }

    #[test]
    fn create_request_has_no_enablement_field_and_policy_contract_is_versioned() {
        let request = LifeScreenVisionOutboundPolicyCreateRequest {
            life_id: "life-a".into(),
        };
        validate_screen_vision_outbound_policy_create_request(&request).unwrap();
        assert_eq!(SCREEN_VISION_OUTBOUND_POLICY_VERSION, 1);
        assert_eq!(SCREEN_VISION_OUTBOUND_POLICY_EVENT_VERSION, 1);
        assert_eq!(
            SCREEN_VISION_OUTBOUND_POLICY_ACTOR_KIND_USER_EXPLICIT,
            "user_explicit"
        );
    }

    #[test]
    fn missing_and_disabled_policy_fail_closed_but_enabled_policy_authorizes() {
        let missing = StubRepository::default();
        let missing_error = authorize_screen_vision_outbound(&missing, "life-a").unwrap_err();
        assert_eq!(
            missing_error.code,
            ScreenVisionOutboundPolicyErrorCode::PolicyNotFound
        );

        let disabled = StubRepository {
            policy: Some(policy(false)),
        };
        let disabled_error = authorize_screen_vision_outbound(&disabled, "life-a").unwrap_err();
        assert_eq!(
            disabled_error.code,
            ScreenVisionOutboundPolicyErrorCode::PolicyDisabled
        );

        let enabled = StubRepository {
            policy: Some(policy(true)),
        };
        authorize_screen_vision_outbound(&enabled, "life-a").unwrap();
    }

    #[test]
    fn event_validation_requires_explicit_user_and_exact_revision_step() {
        let mut event = LifeScreenVisionOutboundPolicyEvent {
            event_id: "event-a".into(),
            life_id: "life-a".into(),
            old_screen_vision_outbound_enabled: false,
            new_screen_vision_outbound_enabled: true,
            expected_revision: 1,
            applied_revision: 2,
            actor_kind: "agent".into(),
            occurred_at: "2026-08-31T00:00:00.000Z".into(),
            event_version: 1,
        };
        let error = validate_screen_vision_outbound_policy_event_state(&event).unwrap_err();
        assert_eq!(
            error.code,
            ScreenVisionOutboundPolicyErrorCode::InvalidArgument
        );

        event.actor_kind = SCREEN_VISION_OUTBOUND_POLICY_ACTOR_KIND_USER_EXPLICIT.into();
        event.applied_revision = 3;
        let error = validate_screen_vision_outbound_policy_event_state(&event).unwrap_err();
        assert_eq!(
            error.code,
            ScreenVisionOutboundPolicyErrorCode::InvalidArgument
        );
    }

    #[test]
    fn event_validation_accepts_real_transitions_and_rejects_no_ops() {
        for (event_id, old, new) in [
            ("event-enable", false, true),
            ("event-disable", true, false),
        ] {
            let event = LifeScreenVisionOutboundPolicyEvent {
                event_id: event_id.into(),
                life_id: "life-a".into(),
                old_screen_vision_outbound_enabled: old,
                new_screen_vision_outbound_enabled: new,
                expected_revision: 1,
                applied_revision: 2,
                actor_kind: SCREEN_VISION_OUTBOUND_POLICY_ACTOR_KIND_USER_EXPLICIT.into(),
                occurred_at: "2026-08-31T00:00:00.000Z".into(),
                event_version: SCREEN_VISION_OUTBOUND_POLICY_EVENT_VERSION,
            };
            validate_screen_vision_outbound_policy_event_state(&event).unwrap();
        }

        for (event_id, old, new) in [
            ("event-no-op-disabled", false, false),
            ("event-no-op-enabled", true, true),
        ] {
            let event = LifeScreenVisionOutboundPolicyEvent {
                event_id: event_id.into(),
                life_id: "life-a".into(),
                old_screen_vision_outbound_enabled: old,
                new_screen_vision_outbound_enabled: new,
                expected_revision: 1,
                applied_revision: 2,
                actor_kind: SCREEN_VISION_OUTBOUND_POLICY_ACTOR_KIND_USER_EXPLICIT.into(),
                occurred_at: "2026-08-31T00:00:00.000Z".into(),
                event_version: SCREEN_VISION_OUTBOUND_POLICY_EVENT_VERSION,
            };
            let error = validate_screen_vision_outbound_policy_event_state(&event).unwrap_err();
            assert_eq!(
                error.code,
                ScreenVisionOutboundPolicyErrorCode::InvalidArgument
            );
        }
    }

    #[test]
    fn invalid_life_and_event_arguments_are_bounded() {
        let error = validate_screen_vision_outbound_policy_create_request(
            &LifeScreenVisionOutboundPolicyCreateRequest {
                life_id: " ".into(),
            },
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            ScreenVisionOutboundPolicyErrorCode::InvalidArgument
        );

        let error = validate_screen_vision_outbound_policy_update_request(
            &LifeScreenVisionOutboundPolicyUpdateRequest {
                event_id: "event-a".into(),
                life_id: "life-a".into(),
                screen_vision_outbound_enabled: true,
                expected_revision: i64::MAX,
            },
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            ScreenVisionOutboundPolicyErrorCode::InvalidArgument
        );
    }
}
