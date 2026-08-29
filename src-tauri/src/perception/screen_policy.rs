//! D23-B1 screen-perception consent authority (authority only).
//!
//! This module models an explicit, Life-scoped user consent policy for a
//! future, narrowly defined screen-perception capability.  It is an authority
//! foundation: it never captures a screen, never reads a window or process,
//! never performs text recognition from imagery, and never persists a capture
//! target.  The D23-C1 stage owns target selection and any real capture
//! implementation.
//!
//! The process-local [`ScreenPerceptionSessionGate`] is the second half of the
//! two-gate invariant:
//!
//! ```text
//! screen capture allowed
//! IFF
//! persistent policy enabled for life
//! AND
//! session gate armed for same life
//! ```
//!
//! The gate starts `Disarmed` on every process/service construction, is never
//! stored in SQLite (nor in browser, DOM, or process-variable state), and
//! therefore can never survive a restart.  Authorization always re-reads the
//! durable policy from the repository rather than trusting cached frontend
//! state, so a persistent revocation fails the next authorization even when
//! the in-memory gate is still armed.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

pub(crate) const SCREEN_PERCEPTION_POLICY_VERSION: i64 = 1;
pub(crate) const SCREEN_PERCEPTION_POLICY_EVENT_VERSION: i64 = 1;
pub(crate) const SCREEN_PERCEPTION_POLICY_ACTOR_KIND_USER_EXPLICIT: &str = "user_explicit";
const MAX_ID_LENGTH: usize = 128;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifeScreenPerceptionPolicy {
    pub(crate) life_id: String,
    pub(crate) screen_perception_enabled: bool,
    pub(crate) revision: i64,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
    pub(crate) policy_version: i64,
}

impl LifeScreenPerceptionPolicy {
    /// Returns whether the persisted consent currently authorizes the future
    /// screen-perception capability.  Consent alone does not start a capture;
    /// the D23-C1 stage owns the capture lifecycle.
    pub(crate) fn is_screen_perception_enabled(&self) -> bool {
        self.screen_perception_enabled
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifeScreenPerceptionPolicyCreateRequest {
    pub(crate) life_id: String,
    pub(crate) screen_perception_enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifeScreenPerceptionPolicyUpdateRequest {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) screen_perception_enabled: bool,
    pub(crate) expected_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LifeScreenPerceptionPolicyEvent {
    pub(crate) event_id: String,
    pub(crate) life_id: String,
    pub(crate) old_screen_perception_enabled: bool,
    pub(crate) new_screen_perception_enabled: bool,
    pub(crate) expected_revision: i64,
    pub(crate) applied_revision: i64,
    pub(crate) actor_kind: String,
    pub(crate) occurred_at: String,
    pub(crate) event_version: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ScreenPerceptionCreateOutcome<T> {
    Applied(T),
    Replayed(T),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum LifeScreenPerceptionPolicyUpdateOutcome {
    Applied {
        event: LifeScreenPerceptionPolicyEvent,
        policy: LifeScreenPerceptionPolicy,
    },
    Replayed {
        event: LifeScreenPerceptionPolicyEvent,
        current: LifeScreenPerceptionPolicy,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenPerceptionErrorCode {
    InvalidArgument,
    LifeNotFound,
    PolicyNotFound,
    PolicyDisabled,
    ScreenPerceptionPolicyConflict,
    ScreenPerceptionPolicyEventConflict,
    RevisionConflict,
    InvalidTransition,
    SessionNotArmed,
    SessionLifeMismatch,
    DatabaseUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenPerceptionError {
    pub(crate) code: ScreenPerceptionErrorCode,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

impl ScreenPerceptionError {
    pub(crate) fn new(code: ScreenPerceptionErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable: matches!(
                code,
                ScreenPerceptionErrorCode::LifeNotFound
                    | ScreenPerceptionErrorCode::PolicyNotFound
                    | ScreenPerceptionErrorCode::PolicyDisabled
                    | ScreenPerceptionErrorCode::SessionNotArmed
                    | ScreenPerceptionErrorCode::SessionLifeMismatch
                    | ScreenPerceptionErrorCode::DatabaseUnavailable
            ),
        }
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ScreenPerceptionErrorCode::InvalidArgument, message)
    }

    pub(crate) fn life_not_found() -> Self {
        Self::new(
            ScreenPerceptionErrorCode::LifeNotFound,
            "The specified life was not found.",
        )
    }

    pub(crate) fn policy_conflict() -> Self {
        Self::new(
            ScreenPerceptionErrorCode::ScreenPerceptionPolicyConflict,
            "A screen perception policy with conflicting evidence already exists.",
        )
    }

    pub(crate) fn policy_event_conflict() -> Self {
        Self::new(
            ScreenPerceptionErrorCode::ScreenPerceptionPolicyEventConflict,
            "A screen perception policy event with conflicting evidence already exists.",
        )
    }

    pub(crate) fn policy_not_found() -> Self {
        Self::new(
            ScreenPerceptionErrorCode::PolicyNotFound,
            "No screen perception policy exists for the specified life.",
        )
    }

    pub(crate) fn policy_disabled() -> Self {
        Self::new(
            ScreenPerceptionErrorCode::PolicyDisabled,
            "Screen perception is disabled for the specified life.",
        )
    }

    pub(crate) fn revision_conflict() -> Self {
        Self::new(
            ScreenPerceptionErrorCode::RevisionConflict,
            "The screen perception policy changed after it was loaded. Refresh and try again.",
        )
    }

    pub(crate) fn invalid_transition() -> Self {
        Self::new(
            ScreenPerceptionErrorCode::InvalidTransition,
            "The screen perception policy update does not change its current consent state.",
        )
    }

    pub(crate) fn session_not_armed() -> Self {
        Self::new(
            ScreenPerceptionErrorCode::SessionNotArmed,
            "The screen perception session gate is not armed.",
        )
    }

    pub(crate) fn session_life_mismatch() -> Self {
        Self::new(
            ScreenPerceptionErrorCode::SessionLifeMismatch,
            "The screen perception session gate is armed for a different life.",
        )
    }

    pub(crate) fn database() -> Self {
        Self::new(
            ScreenPerceptionErrorCode::DatabaseUnavailable,
            "The screen perception authority storage operation failed.",
        )
    }
}

/// The process-local session half of the two-gate invariant.
///
/// A fresh instance starts `Disarmed`.  It is never persisted to SQLite, never
/// exported, and never survives a restart: a restored backup therefore cannot
/// activate screen perception.  The gate only models `disarmed` / `armed for
/// life_id`; D23-C1 owns capture target selection.
pub(crate) struct ScreenPerceptionSessionGate {
    state: Mutex<GateState>,
    /// Monotonic process-local generation used only to make a re-arm after a
    /// disarm observably distinct; it is never an authority source.
    generation: AtomicU64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GateState {
    Disarmed,
    ArmedForLife(u64, String),
}

impl ScreenPerceptionSessionGate {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(GateState::Disarmed),
            generation: AtomicU64::new(0),
        }
    }

    pub(crate) fn is_disarmed(&self) -> bool {
        matches!(*self.state.lock().unwrap(), GateState::Disarmed)
    }

    /// Arms the gate for exactly one life.  The bound life identity is a
    /// process-local string (never a capture target).
    pub(crate) fn arm_for_life(&self, life_id: &str) {
        if life_id.trim().is_empty() {
            panic!("screen perception session gate cannot be armed for an empty life");
        }
        let generation = self.generation.fetch_add(1, Ordering::Relaxed) + 1;
        *self.state.lock().unwrap() = GateState::ArmedForLife(generation, life_id.to_string());
    }

    /// Disarms the gate.  Safety must never depend on this: durable
    /// revocation alone makes authorization fail on the next check.
    pub(crate) fn disarm(&self) {
        self.generation.fetch_add(1, Ordering::Relaxed);
        *self.state.lock().unwrap() = GateState::Disarmed;
    }

    /// The life the gate is currently armed for, if any.
    pub(crate) fn armed_life_id(&self) -> Option<String> {
        match &*self.state.lock().unwrap() {
            GateState::Disarmed => None,
            GateState::ArmedForLife(_, life_id) => Some(life_id.clone()),
        }
    }

    /// The opaque session-generation fence for the exact armed life, if any.
    /// A rearm or disarm changes the fence, so a capture target bound to an
    /// older fence is automatically rejected for the new session.  This is a
    /// process-local token, never persisted.
    pub(crate) fn life_fence_for(&self, life_id: &str) -> Option<u64> {
        match &*self.state.lock().unwrap() {
            GateState::Disarmed => None,
            GateState::ArmedForLife(generation, armed_life) if armed_life == life_id => {
                Some(*generation)
            }
            GateState::ArmedForLife(_, _) => None,
        }
    }
}

/// Crate-internal persistence boundary for the D23-B1 screen-perception
/// authority.  There is intentionally no observation, scheduling, delivery,
/// or OS capture operation in this trait.
pub(crate) trait ScreenPerceptionRepository: Send + Sync {
    fn create_screen_perception_policy(
        &self,
        request: LifeScreenPerceptionPolicyCreateRequest,
    ) -> Result<ScreenPerceptionCreateOutcome<LifeScreenPerceptionPolicy>, ScreenPerceptionError>;

    fn find_screen_perception_policy(
        &self,
        life_id: &str,
    ) -> Result<Option<LifeScreenPerceptionPolicy>, ScreenPerceptionError>;

    fn update_screen_perception_policy(
        &self,
        request: LifeScreenPerceptionPolicyUpdateRequest,
    ) -> Result<LifeScreenPerceptionPolicyUpdateOutcome, ScreenPerceptionError>;

    fn find_screen_perception_policy_event(
        &self,
        life_id: &str,
        event_id: &str,
    ) -> Result<Option<LifeScreenPerceptionPolicyEvent>, ScreenPerceptionError>;
}

pub(crate) fn validate_screen_perception_policy_create_request(
    request: &LifeScreenPerceptionPolicyCreateRequest,
) -> Result<(), ScreenPerceptionError> {
    validate_life_id(&request.life_id)
}

pub(crate) fn validate_screen_perception_policy_update_request(
    request: &LifeScreenPerceptionPolicyUpdateRequest,
) -> Result<(), ScreenPerceptionError> {
    validate_id("policy event identity", &request.event_id)?;
    validate_life_id(&request.life_id)?;
    validate_expected_revision(request.expected_revision)
}

pub(crate) fn validate_screen_perception_policy_state(
    policy: &LifeScreenPerceptionPolicy,
) -> Result<(), ScreenPerceptionError> {
    validate_life_id(&policy.life_id)?;
    validate_persisted_revision(policy.revision)?;
    if policy.policy_version != SCREEN_PERCEPTION_POLICY_VERSION {
        return Err(ScreenPerceptionError::invalid_argument(
            "screen perception policy version must be 1.",
        ));
    }
    validate_required_timestamp("policy created_at", &policy.created_at)?;
    validate_required_timestamp("policy updated_at", &policy.updated_at)
}

pub(crate) fn validate_screen_perception_policy_event_state(
    event: &LifeScreenPerceptionPolicyEvent,
) -> Result<(), ScreenPerceptionError> {
    validate_id("policy event identity", &event.event_id)?;
    validate_life_id(&event.life_id)?;
    validate_expected_revision(event.expected_revision)?;
    if Some(event.applied_revision) != event.expected_revision.checked_add(1) {
        return Err(ScreenPerceptionError::invalid_argument(
            "screen perception policy event applied revision must equal expected revision plus one.",
        ));
    }
    if event.actor_kind != SCREEN_PERCEPTION_POLICY_ACTOR_KIND_USER_EXPLICIT {
        return Err(ScreenPerceptionError::invalid_argument(
            "screen perception policy event actor kind must be user_explicit.",
        ));
    }
    if event.event_version != SCREEN_PERCEPTION_POLICY_EVENT_VERSION {
        return Err(ScreenPerceptionError::invalid_argument(
            "screen perception policy event version must be 1.",
        ));
    }
    validate_required_timestamp("policy event occurred_at", &event.occurred_at)
}

/// The frozen two-gate authorization check for a future D23-C1 capture stage.
///
/// It re-reads the durable policy on every call (never trusting cached
/// frontend state) and demands the process-local session gate be armed for the
/// exact same life.  B1 performs no OS capture; this is the authority surface
/// a later stage consumes.
pub(crate) fn authorize_screen_perception(
    repository: &dyn ScreenPerceptionRepository,
    gate: &ScreenPerceptionSessionGate,
    life_id: &str,
) -> Result<(), ScreenPerceptionError> {
    validate_life_id(life_id)?;
    let policy = repository
        .find_screen_perception_policy(life_id)?
        .ok_or_else(ScreenPerceptionError::policy_not_found)?;
    if !policy.is_screen_perception_enabled() {
        return Err(ScreenPerceptionError::policy_disabled());
    }
    match gate.armed_life_id() {
        None => Err(ScreenPerceptionError::session_not_armed()),
        Some(armed) if armed != life_id => Err(ScreenPerceptionError::session_life_mismatch()),
        Some(_) => Ok(()),
    }
}

fn validate_life_id(value: &str) -> Result<(), ScreenPerceptionError> {
    if value.trim().is_empty() {
        return Err(ScreenPerceptionError::invalid_argument(
            "life identity must not be empty.",
        ));
    }
    Ok(())
}

fn validate_id(name: &str, value: &str) -> Result<(), ScreenPerceptionError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_ID_LENGTH {
        return Err(ScreenPerceptionError::invalid_argument(format!(
            "{name} must be between 1 and {MAX_ID_LENGTH} characters after trimming."
        )));
    }
    Ok(())
}

fn validate_persisted_revision(revision: i64) -> Result<(), ScreenPerceptionError> {
    if revision < 1 {
        return Err(ScreenPerceptionError::invalid_argument(
            "revision must be at least 1.",
        ));
    }
    Ok(())
}

fn validate_expected_revision(revision: i64) -> Result<(), ScreenPerceptionError> {
    if !(1..i64::MAX).contains(&revision) {
        return Err(ScreenPerceptionError::invalid_argument(
            "expected revision must be at least 1 and less than i64::MAX.",
        ));
    }
    Ok(())
}

fn validate_required_timestamp(name: &str, value: &str) -> Result<(), ScreenPerceptionError> {
    if value.trim().is_empty() {
        return Err(ScreenPerceptionError::invalid_argument(format!(
            "{name} must not be empty."
        )));
    }
    Ok(())
}

const _: fn(&LifeScreenPerceptionPolicyCreateRequest) -> Result<(), ScreenPerceptionError> =
    validate_screen_perception_policy_create_request;
const _: fn(&LifeScreenPerceptionPolicyUpdateRequest) -> Result<(), ScreenPerceptionError> =
    validate_screen_perception_policy_update_request;
const _: fn(&LifeScreenPerceptionPolicy) -> Result<(), ScreenPerceptionError> =
    validate_screen_perception_policy_state;
const _: fn(&LifeScreenPerceptionPolicyEvent) -> Result<(), ScreenPerceptionError> =
    validate_screen_perception_policy_event_state;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_gate_is_disarmed() {
        let gate = ScreenPerceptionSessionGate::new();
        assert!(gate.is_disarmed());
        assert_eq!(gate.armed_life_id(), None);
    }

    #[test]
    fn arm_then_disarm_returns_to_disarmed() {
        let gate = ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        assert!(!gate.is_disarmed());
        assert_eq!(gate.armed_life_id().as_deref(), Some("life-a"));
        gate.disarm();
        assert!(gate.is_disarmed());
        assert_eq!(gate.armed_life_id(), None);
    }

    #[test]
    fn rearm_after_disarm_binds_the_new_life_only() {
        let gate = ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        gate.disarm();
        gate.arm_for_life("life-b");
        assert_eq!(gate.armed_life_id().as_deref(), Some("life-b"));
    }

    /// In-memory repository used only to prove the two-gate authorization
    /// invariant; it stores policy state alone and never persists a session.
    #[derive(Default)]
    struct InMemoryScreenPerceptionRepository {
        policy: std::sync::Mutex<Option<LifeScreenPerceptionPolicy>>,
    }

    impl InMemoryScreenPerceptionRepository {
        fn with_policy(policy: LifeScreenPerceptionPolicy) -> Self {
            Self {
                policy: std::sync::Mutex::new(Some(policy)),
            }
        }
    }

    impl ScreenPerceptionRepository for InMemoryScreenPerceptionRepository {
        fn create_screen_perception_policy(
            &self,
            request: LifeScreenPerceptionPolicyCreateRequest,
        ) -> Result<ScreenPerceptionCreateOutcome<LifeScreenPerceptionPolicy>, ScreenPerceptionError>
        {
            let mut slot = self.policy.lock().unwrap();
            if let Some(existing) = &*slot {
                if existing.life_id == request.life_id
                    && existing.screen_perception_enabled == request.screen_perception_enabled
                {
                    return Ok(ScreenPerceptionCreateOutcome::Replayed(existing.clone()));
                }
                return Err(ScreenPerceptionError::policy_conflict());
            }
            let now = "2026-08-29T00:00:00.000Z".to_string();
            let policy = LifeScreenPerceptionPolicy {
                life_id: request.life_id,
                screen_perception_enabled: request.screen_perception_enabled,
                revision: 1,
                created_at: now.clone(),
                updated_at: now,
                policy_version: SCREEN_PERCEPTION_POLICY_VERSION,
            };
            *slot = Some(policy.clone());
            Ok(ScreenPerceptionCreateOutcome::Applied(policy))
        }

        fn find_screen_perception_policy(
            &self,
            life_id: &str,
        ) -> Result<Option<LifeScreenPerceptionPolicy>, ScreenPerceptionError> {
            Ok(self
                .policy
                .lock()
                .unwrap()
                .clone()
                .filter(|policy| policy.life_id == life_id))
        }

        fn update_screen_perception_policy(
            &self,
            request: LifeScreenPerceptionPolicyUpdateRequest,
        ) -> Result<LifeScreenPerceptionPolicyUpdateOutcome, ScreenPerceptionError> {
            let mut slot = self.policy.lock().unwrap();
            let current = slot
                .clone()
                .filter(|policy| policy.life_id == request.life_id)
                .ok_or_else(ScreenPerceptionError::policy_not_found)?;
            if current.revision != request.expected_revision {
                return Err(ScreenPerceptionError::revision_conflict());
            }
            if current.screen_perception_enabled == request.screen_perception_enabled {
                return Err(ScreenPerceptionError::invalid_transition());
            }
            let updated = LifeScreenPerceptionPolicy {
                life_id: current.life_id.clone(),
                screen_perception_enabled: request.screen_perception_enabled,
                revision: request.expected_revision + 1,
                created_at: current.created_at.clone(),
                updated_at: "2026-08-29T00:00:01.000Z".to_string(),
                policy_version: current.policy_version,
            };
            *slot = Some(updated.clone());
            let event = LifeScreenPerceptionPolicyEvent {
                event_id: request.event_id,
                life_id: request.life_id,
                old_screen_perception_enabled: current.screen_perception_enabled,
                new_screen_perception_enabled: request.screen_perception_enabled,
                expected_revision: request.expected_revision,
                applied_revision: request.expected_revision + 1,
                actor_kind: SCREEN_PERCEPTION_POLICY_ACTOR_KIND_USER_EXPLICIT.to_string(),
                occurred_at: "2026-08-29T00:00:01.000Z".to_string(),
                event_version: SCREEN_PERCEPTION_POLICY_EVENT_VERSION,
            };
            Ok(LifeScreenPerceptionPolicyUpdateOutcome::Applied {
                event,
                policy: updated,
            })
        }

        fn find_screen_perception_policy_event(
            &self,
            _life_id: &str,
            _event_id: &str,
        ) -> Result<Option<LifeScreenPerceptionPolicyEvent>, ScreenPerceptionError> {
            Ok(None)
        }
    }

    fn make_policy(life_id: &str, enabled: bool, revision: i64) -> LifeScreenPerceptionPolicy {
        LifeScreenPerceptionPolicy {
            life_id: life_id.to_string(),
            screen_perception_enabled: enabled,
            revision,
            created_at: "2026-08-29T00:00:00.000Z".to_string(),
            updated_at: "2026-08-29T00:00:00.000Z".to_string(),
            policy_version: SCREEN_PERCEPTION_POLICY_VERSION,
        }
    }

    #[test]
    fn enabled_policy_without_gate_is_denied() {
        let repository =
            InMemoryScreenPerceptionRepository::with_policy(make_policy("life-a", true, 1));
        let gate = ScreenPerceptionSessionGate::new();
        let error = authorize_screen_perception(&repository, &gate, "life-a").unwrap_err();
        assert_eq!(error.code, ScreenPerceptionErrorCode::SessionNotArmed);
    }

    #[test]
    fn enabled_policy_with_same_life_gate_is_allowed() {
        let repository =
            InMemoryScreenPerceptionRepository::with_policy(make_policy("life-a", true, 1));
        let gate = ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        authorize_screen_perception(&repository, &gate, "life-a").unwrap();
    }

    #[test]
    fn enabled_policy_with_different_life_gate_is_denied() {
        let repository =
            InMemoryScreenPerceptionRepository::with_policy(make_policy("life-a", true, 1));
        let gate = ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-b");
        let error = authorize_screen_perception(&repository, &gate, "life-a").unwrap_err();
        assert_eq!(error.code, ScreenPerceptionErrorCode::SessionLifeMismatch);
    }

    #[test]
    fn disabled_policy_denies_even_when_gate_is_armed() {
        let repository =
            InMemoryScreenPerceptionRepository::with_policy(make_policy("life-a", false, 1));
        let gate = ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let error = authorize_screen_perception(&repository, &gate, "life-a").unwrap_err();
        assert_eq!(error.code, ScreenPerceptionErrorCode::PolicyDisabled);
    }

    #[test]
    fn missing_policy_denies_even_when_gate_is_armed() {
        let repository = InMemoryScreenPerceptionRepository::default();
        let gate = ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let error = authorize_screen_perception(&repository, &gate, "life-a").unwrap_err();
        assert_eq!(error.code, ScreenPerceptionErrorCode::PolicyNotFound);
    }

    #[test]
    fn revoked_policy_denies_while_gate_still_armed() {
        let repository =
            InMemoryScreenPerceptionRepository::with_policy(make_policy("life-a", true, 1));
        let gate = ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        authorize_screen_perception(&repository, &gate, "life-a").unwrap();

        // Explicit revocation through the repository.
        repository
            .update_screen_perception_policy(LifeScreenPerceptionPolicyUpdateRequest {
                event_id: "revoke-event".into(),
                life_id: "life-a".into(),
                screen_perception_enabled: false,
                expected_revision: 1,
            })
            .unwrap();
        // The in-memory gate is still armed for the same life.
        assert_eq!(gate.armed_life_id().as_deref(), Some("life-a"));

        let error = authorize_screen_perception(&repository, &gate, "life-a").unwrap_err();
        assert_eq!(error.code, ScreenPerceptionErrorCode::PolicyDisabled);
    }

    #[test]
    fn empty_life_authorization_is_rejected_before_storage() {
        let repository = InMemoryScreenPerceptionRepository::default();
        let gate = ScreenPerceptionSessionGate::new();
        let error = authorize_screen_perception(&repository, &gate, "  ").unwrap_err();
        assert_eq!(error.code, ScreenPerceptionErrorCode::InvalidArgument);
    }

    #[test]
    fn production_source_has_no_capture_observation_or_target_persistence() {
        let source = include_str!("screen_policy.rs");
        let production_source = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(production, _)| production);
        let forbidden = [
            format!("{}{}", "screen", "shot"),
            format!("{}{}", "Bit", "Blt"),
            format!("Print{}", "Window"),
            format!("{}{}", "O", "CR"),
            format!("GraphicsCapture{}", "Item"),
            format!("{}{}", "h", "wnd"),
            format!("capture_{}", "token"),
            format!("local{}", "Storage"),
            format!("session{}", "Storage"),
            "Pinia".to_string(),
        ];
        for token in forbidden {
            assert!(
                !production_source.contains(token.as_str()),
                "forbidden capture/session token appeared in the production source"
            );
        }
    }
}
