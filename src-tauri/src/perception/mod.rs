//! D16 perception-consent authority and privacy-minimized focus observation.
//!
//! This module models only explicit user consent for the future, narrowly
//! defined foreground-focus context capability.  It does not persist any
//! operating-system observation, application content, or generic capability
//! grant.

pub(crate) mod foreground_focus;

pub(crate) const PERCEPTION_POLICY_VERSION: i64 = 1;
pub(crate) const PERCEPTION_POLICY_EVENT_VERSION: i64 = 1;
pub(crate) const PERCEPTION_POLICY_ACTOR_KIND_USER_EXPLICIT: &str = "user_explicit";
const MAX_ID_LENGTH: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifePerceptionPolicy {
    pub(crate) life_id: String,
    pub(crate) focus_context_enabled: bool,
    pub(crate) revision: i64,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) policy_version: i64,
}

impl LifePerceptionPolicy {
    /// Returns whether the persisted consent currently authorizes the future
    /// foreground-focus context capability.  Consent alone does not start an
    /// observer; that lifecycle belongs to a later D16 stage.
    pub(crate) fn is_focus_context_enabled(&self) -> bool {
        self.focus_context_enabled
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifePerceptionPolicyCreateRequest {
    pub(crate) life_id: String,
    pub(crate) focus_context_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifePerceptionPolicyUpdateRequest {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) focus_context_enabled: bool,
    pub(crate) expected_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifePerceptionPolicyEvent {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) old_focus_context_enabled: bool,
    pub(crate) new_focus_context_enabled: bool,
    pub(crate) expected_revision: i64,
    pub(crate) applied_revision: i64,
    pub(crate) actor_kind: String,
    pub(crate) occurred_at: String,
    pub(crate) event_version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PerceptionCreateOutcome<T> {
    Applied(T),
    Replayed(T),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LifePerceptionPolicyUpdateOutcome {
    Applied {
        event: LifePerceptionPolicyEvent,
        policy: LifePerceptionPolicy,
    },
    Replayed {
        event: LifePerceptionPolicyEvent,
        current: LifePerceptionPolicy,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PerceptionErrorCode {
    InvalidArgument,
    LifeNotFound,
    PerceptionPolicyConflict,
    PerceptionPolicyEventConflict,
    PolicyNotFound,
    RevisionConflict,
    InvalidTransition,
    DatabaseUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PerceptionError {
    pub(crate) code: PerceptionErrorCode,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

impl PerceptionError {
    pub(crate) fn new(code: PerceptionErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable: matches!(
                code,
                PerceptionErrorCode::LifeNotFound
                    | PerceptionErrorCode::PolicyNotFound
                    | PerceptionErrorCode::DatabaseUnavailable
            ),
        }
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(PerceptionErrorCode::InvalidArgument, message)
    }

    pub(crate) fn life_not_found() -> Self {
        Self::new(
            PerceptionErrorCode::LifeNotFound,
            "The specified life was not found.",
        )
    }

    pub(crate) fn policy_conflict() -> Self {
        Self::new(
            PerceptionErrorCode::PerceptionPolicyConflict,
            "A perception policy with conflicting evidence already exists.",
        )
    }

    pub(crate) fn policy_event_conflict() -> Self {
        Self::new(
            PerceptionErrorCode::PerceptionPolicyEventConflict,
            "A perception policy event with conflicting evidence already exists.",
        )
    }

    pub(crate) fn policy_not_found() -> Self {
        Self::new(
            PerceptionErrorCode::PolicyNotFound,
            "No perception policy exists for the specified life.",
        )
    }

    pub(crate) fn revision_conflict() -> Self {
        Self::new(
            PerceptionErrorCode::RevisionConflict,
            "The perception policy changed after it was loaded. Refresh and try again.",
        )
    }

    pub(crate) fn invalid_transition() -> Self {
        Self::new(
            PerceptionErrorCode::InvalidTransition,
            "The perception policy update does not change its current consent state.",
        )
    }

    pub(crate) fn database() -> Self {
        Self::new(
            PerceptionErrorCode::DatabaseUnavailable,
            "The perception authority storage operation failed.",
        )
    }
}

/// Crate-internal persistence boundary for the D16-B1 consent authority.
/// There is intentionally no observation, scheduling, delivery, or OS access
/// operation in this trait.
pub(crate) trait PerceptionRepository: Send + Sync {
    fn create_policy(
        &self,
        request: LifePerceptionPolicyCreateRequest,
    ) -> Result<PerceptionCreateOutcome<LifePerceptionPolicy>, PerceptionError>;

    fn find_policy(&self, life_id: &str) -> Result<Option<LifePerceptionPolicy>, PerceptionError>;

    fn update_policy(
        &self,
        request: LifePerceptionPolicyUpdateRequest,
    ) -> Result<LifePerceptionPolicyUpdateOutcome, PerceptionError>;

    fn find_policy_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifePerceptionPolicyEvent>, PerceptionError>;
}

pub(crate) fn validate_policy_create_request(
    request: &LifePerceptionPolicyCreateRequest,
) -> Result<(), PerceptionError> {
    validate_life_id(&request.life_id)
}

pub(crate) fn validate_policy_update_request(
    request: &LifePerceptionPolicyUpdateRequest,
) -> Result<(), PerceptionError> {
    validate_id("policy event identity", &request.event_id)?;
    validate_life_id(&request.life_id)?;
    validate_expected_revision(request.expected_revision)
}

pub(crate) fn validate_policy_state(policy: &LifePerceptionPolicy) -> Result<(), PerceptionError> {
    validate_life_id(&policy.life_id)?;
    validate_persisted_revision(policy.revision)?;
    if policy.policy_version != PERCEPTION_POLICY_VERSION {
        return Err(PerceptionError::invalid_argument(
            "perception policy version must be 1.",
        ));
    }
    validate_required_timestamp("policy created_at", &policy.created_at)?;
    validate_required_timestamp("policy updated_at", &policy.updated_at)
}

pub(crate) fn validate_policy_event_state(
    event: &LifePerceptionPolicyEvent,
) -> Result<(), PerceptionError> {
    validate_id("policy event identity", &event.event_id)?;
    validate_life_id(&event.life_id)?;
    validate_expected_revision(event.expected_revision)?;
    if Some(event.applied_revision) != event.expected_revision.checked_add(1) {
        return Err(PerceptionError::invalid_argument(
            "policy event applied revision must equal expected revision plus one.",
        ));
    }
    if event.actor_kind != PERCEPTION_POLICY_ACTOR_KIND_USER_EXPLICIT {
        return Err(PerceptionError::invalid_argument(
            "policy event actor kind must be user_explicit.",
        ));
    }
    if event.event_version != PERCEPTION_POLICY_EVENT_VERSION {
        return Err(PerceptionError::invalid_argument(
            "policy event version must be 1.",
        ));
    }
    validate_required_timestamp("policy event occurred_at", &event.occurred_at)
}

fn validate_life_id(value: &str) -> Result<(), PerceptionError> {
    if value.trim().is_empty() {
        return Err(PerceptionError::invalid_argument(
            "life identity must not be empty.",
        ));
    }
    Ok(())
}

fn validate_id(name: &str, value: &str) -> Result<(), PerceptionError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_ID_LENGTH {
        return Err(PerceptionError::invalid_argument(format!(
            "{name} must be between 1 and {MAX_ID_LENGTH} characters after trimming."
        )));
    }
    Ok(())
}

fn validate_persisted_revision(revision: i64) -> Result<(), PerceptionError> {
    if revision < 1 {
        return Err(PerceptionError::invalid_argument(
            "revision must be at least 1.",
        ));
    }
    Ok(())
}

fn validate_expected_revision(revision: i64) -> Result<(), PerceptionError> {
    if !(1..i64::MAX).contains(&revision) {
        return Err(PerceptionError::invalid_argument(
            "expected revision must be at least 1 and less than i64::MAX.",
        ));
    }
    Ok(())
}

fn validate_required_timestamp(name: &str, value: &str) -> Result<(), PerceptionError> {
    if value.trim().is_empty() {
        return Err(PerceptionError::invalid_argument(format!(
            "{name} must not be empty."
        )));
    }
    Ok(())
}

const _: fn(&LifePerceptionPolicyCreateRequest) -> Result<(), PerceptionError> =
    validate_policy_create_request;
const _: fn(&LifePerceptionPolicyUpdateRequest) -> Result<(), PerceptionError> =
    validate_policy_update_request;
