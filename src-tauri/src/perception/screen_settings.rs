//! Settings-only command boundary for the D23 screen-perception authority.
//!
//! This module exposes durable consent metadata and the one process-local
//! session gate to Settings.  It deliberately contains no observation,
//! capture, target, OS-handle, or content operation.  The raw gate arm
//! primitive remains an internal method on [`ScreenPerceptionSessionGate`];
//! commands can reach it only after the durable policy has been re-read and
//! found enabled.

use serde::{Deserialize, Serialize};
use tauri::State;

use super::screen_policy::{
    LifeScreenPerceptionPolicy, LifeScreenPerceptionPolicyCreateRequest,
    LifeScreenPerceptionPolicyUpdateOutcome, LifeScreenPerceptionPolicyUpdateRequest,
    ScreenPerceptionCreateOutcome, ScreenPerceptionError, ScreenPerceptionErrorCode,
    ScreenPerceptionRepository, ScreenPerceptionSessionGate,
};
use crate::storage::StorageService;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenPerceptionLifeRequest {
    pub life_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateScreenPerceptionPolicyRequest {
    pub life_id: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateScreenPerceptionPolicyRequest {
    pub event_id: String,
    pub life_id: String,
    pub enabled: bool,
    pub expected_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenPerceptionPolicyDto {
    pub life_id: String,
    pub enabled: bool,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum ScreenPerceptionSessionStatusDto {
    #[serde(rename = "disarmed")]
    Disarmed,
    #[serde(rename = "armed")]
    Armed {
        #[serde(rename = "lifeId")]
        life_id: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenPerceptionCommandError {
    pub code: String,
    pub message: String,
    pub recoverable: bool,
}

fn validate_life_id(life_id: &str) -> Result<(), ScreenPerceptionError> {
    if life_id.trim().is_empty() {
        return Err(ScreenPerceptionError::invalid_argument(
            "life identity must not be empty.",
        ));
    }
    Ok(())
}

fn policy_dto(policy: LifeScreenPerceptionPolicy) -> ScreenPerceptionPolicyDto {
    ScreenPerceptionPolicyDto {
        life_id: policy.life_id,
        enabled: policy.screen_perception_enabled,
        revision: policy.revision,
        created_at: policy.created_at,
        updated_at: policy.updated_at,
    }
}

fn session_status(gate: &ScreenPerceptionSessionGate) -> ScreenPerceptionSessionStatusDto {
    match gate.armed_life_id() {
        Some(life_id) => ScreenPerceptionSessionStatusDto::Armed { life_id },
        None => ScreenPerceptionSessionStatusDto::Disarmed,
    }
}

fn disarm_if_bound_to(gate: &ScreenPerceptionSessionGate, life_id: &str) {
    if gate.armed_life_id().as_deref() == Some(life_id) {
        gate.disarm();
    }
}

fn map_error(error: ScreenPerceptionError) -> ScreenPerceptionCommandError {
    let (code, message) = match error.code {
        ScreenPerceptionErrorCode::InvalidArgument => (
            "SCREEN_PERCEPTION_INVALID_ARGUMENT",
            "The screen perception request is invalid.",
        ),
        ScreenPerceptionErrorCode::LifeNotFound => (
            "SCREEN_PERCEPTION_LIFE_NOT_FOUND",
            "The selected Life could not be found.",
        ),
        ScreenPerceptionErrorCode::PolicyNotFound => (
            "SCREEN_PERCEPTION_POLICY_NOT_FOUND",
            "No screen perception consent has been configured for this Life.",
        ),
        ScreenPerceptionErrorCode::PolicyDisabled => (
            "SCREEN_PERCEPTION_POLICY_DISABLED",
            "Screen perception consent is disabled for this Life.",
        ),
        ScreenPerceptionErrorCode::ScreenPerceptionPolicyConflict => (
            "SCREEN_PERCEPTION_POLICY_CONFLICT",
            "The screen perception consent changed before it was created.",
        ),
        ScreenPerceptionErrorCode::ScreenPerceptionPolicyEventConflict => (
            "SCREEN_PERCEPTION_POLICY_EVENT_CONFLICT",
            "This screen perception consent action conflicts with an existing action.",
        ),
        ScreenPerceptionErrorCode::RevisionConflict => (
            "SCREEN_PERCEPTION_REVISION_CONFLICT",
            "Screen perception consent changed elsewhere. Refresh and try again.",
        ),
        ScreenPerceptionErrorCode::InvalidTransition => (
            "SCREEN_PERCEPTION_INVALID_TRANSITION",
            "The screen perception consent is already in that state.",
        ),
        ScreenPerceptionErrorCode::SessionNotArmed => (
            "SCREEN_PERCEPTION_SESSION_NOT_ARMED",
            "Screen perception is not enabled for this application session.",
        ),
        ScreenPerceptionErrorCode::SessionLifeMismatch => (
            "SCREEN_PERCEPTION_SESSION_LIFE_MISMATCH",
            "Screen perception is enabled for a different Life in this session.",
        ),
        ScreenPerceptionErrorCode::DatabaseUnavailable => (
            "SCREEN_PERCEPTION_DATABASE_UNAVAILABLE",
            "Screen perception settings are temporarily unavailable. Try again.",
        ),
    };

    ScreenPerceptionCommandError {
        code: code.to_string(),
        message: message.to_string(),
        recoverable: error.recoverable,
    }
}

pub(crate) fn get_screen_perception_policy_service(
    repository: &dyn ScreenPerceptionRepository,
    life_id: &str,
) -> Result<Option<ScreenPerceptionPolicyDto>, ScreenPerceptionCommandError> {
    validate_life_id(life_id).map_err(map_error)?;
    repository
        .find_screen_perception_policy(life_id)
        .map_err(map_error)
        .map(|policy| policy.map(policy_dto))
}

pub(crate) fn create_screen_perception_policy_service(
    repository: &dyn ScreenPerceptionRepository,
    request: CreateScreenPerceptionPolicyRequest,
) -> Result<ScreenPerceptionPolicyDto, ScreenPerceptionCommandError> {
    let outcome = repository
        .create_screen_perception_policy(LifeScreenPerceptionPolicyCreateRequest {
            life_id: request.life_id,
            screen_perception_enabled: request.enabled,
        })
        .map_err(map_error)?;
    let policy = match outcome {
        ScreenPerceptionCreateOutcome::Applied(policy)
        | ScreenPerceptionCreateOutcome::Replayed(policy) => policy,
    };
    Ok(policy_dto(policy))
}

pub(crate) fn update_screen_perception_policy_service(
    repository: &dyn ScreenPerceptionRepository,
    gate: &ScreenPerceptionSessionGate,
    request: UpdateScreenPerceptionPolicyRequest,
) -> Result<ScreenPerceptionPolicyDto, ScreenPerceptionCommandError> {
    let life_id = request.life_id.clone();
    let outcome = repository
        .update_screen_perception_policy(LifeScreenPerceptionPolicyUpdateRequest {
            event_id: request.event_id,
            life_id: request.life_id,
            screen_perception_enabled: request.enabled,
            expected_revision: request.expected_revision,
        })
        .map_err(map_error)?;
    let policy = match outcome {
        LifeScreenPerceptionPolicyUpdateOutcome::Applied { policy, .. } => policy,
        LifeScreenPerceptionPolicyUpdateOutcome::Replayed { current, .. } => current,
    };
    if !policy.screen_perception_enabled {
        disarm_if_bound_to(gate, &life_id);
    }
    Ok(policy_dto(policy))
}

pub(crate) fn arm_screen_perception_session_service(
    repository: &dyn ScreenPerceptionRepository,
    gate: &ScreenPerceptionSessionGate,
    life_id: &str,
) -> Result<ScreenPerceptionSessionStatusDto, ScreenPerceptionCommandError> {
    validate_life_id(life_id).map_err(map_error)?;
    let policy = repository
        .find_screen_perception_policy(life_id)
        .map_err(map_error)?
        .ok_or_else(|| map_error(ScreenPerceptionError::policy_not_found()))?;
    if !policy.screen_perception_enabled {
        return Err(map_error(ScreenPerceptionError::policy_disabled()));
    }

    // This is the only production path to the raw arm primitive.  All
    // durable-policy checks above must complete before it is reached.
    gate.arm_for_life(life_id);
    Ok(session_status(gate))
}

pub(crate) fn get_screen_perception_session_status_service(
    gate: &ScreenPerceptionSessionGate,
) -> ScreenPerceptionSessionStatusDto {
    session_status(gate)
}

pub(crate) fn disarm_screen_perception_session_service(
    gate: &ScreenPerceptionSessionGate,
) -> ScreenPerceptionSessionStatusDto {
    gate.disarm();
    session_status(gate)
}

#[tauri::command]
pub fn get_screen_perception_policy(
    storage: State<'_, StorageService>,
    request: ScreenPerceptionLifeRequest,
) -> Result<Option<ScreenPerceptionPolicyDto>, ScreenPerceptionCommandError> {
    get_screen_perception_policy_service(storage.inner(), &request.life_id)
}

#[tauri::command]
pub fn create_screen_perception_policy(
    storage: State<'_, StorageService>,
    request: CreateScreenPerceptionPolicyRequest,
) -> Result<ScreenPerceptionPolicyDto, ScreenPerceptionCommandError> {
    create_screen_perception_policy_service(storage.inner(), request)
}

#[tauri::command]
pub fn update_screen_perception_policy(
    storage: State<'_, StorageService>,
    gate: State<'_, ScreenPerceptionSessionGate>,
    request: UpdateScreenPerceptionPolicyRequest,
) -> Result<ScreenPerceptionPolicyDto, ScreenPerceptionCommandError> {
    update_screen_perception_policy_service(storage.inner(), gate.inner(), request)
}

#[tauri::command]
pub fn get_screen_perception_session_status(
    gate: State<'_, ScreenPerceptionSessionGate>,
) -> ScreenPerceptionSessionStatusDto {
    get_screen_perception_session_status_service(gate.inner())
}

#[tauri::command]
pub fn arm_screen_perception_session(
    storage: State<'_, StorageService>,
    gate: State<'_, ScreenPerceptionSessionGate>,
    request: ScreenPerceptionLifeRequest,
) -> Result<ScreenPerceptionSessionStatusDto, ScreenPerceptionCommandError> {
    arm_screen_perception_session_service(storage.inner(), gate.inner(), &request.life_id)
}

#[tauri::command]
pub fn disarm_screen_perception_session(
    gate: State<'_, ScreenPerceptionSessionGate>,
) -> ScreenPerceptionSessionStatusDto {
    disarm_screen_perception_session_service(gate.inner())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::super::screen_policy::{
        LifeScreenPerceptionPolicyEvent, SCREEN_PERCEPTION_POLICY_ACTOR_KIND_USER_EXPLICIT,
        SCREEN_PERCEPTION_POLICY_EVENT_VERSION,
    };
    use super::*;

    #[derive(Default)]
    struct FakeRepository {
        policies: Mutex<HashMap<String, LifeScreenPerceptionPolicy>>,
    }

    impl FakeRepository {
        fn with_policies(policies: impl IntoIterator<Item = LifeScreenPerceptionPolicy>) -> Self {
            Self {
                policies: Mutex::new(
                    policies
                        .into_iter()
                        .map(|policy| (policy.life_id.clone(), policy))
                        .collect(),
                ),
            }
        }
    }

    impl ScreenPerceptionRepository for FakeRepository {
        fn create_screen_perception_policy(
            &self,
            request: LifeScreenPerceptionPolicyCreateRequest,
        ) -> Result<ScreenPerceptionCreateOutcome<LifeScreenPerceptionPolicy>, ScreenPerceptionError>
        {
            let mut policies = self.policies.lock().unwrap();
            if let Some(existing) = policies.get(&request.life_id) {
                if existing.screen_perception_enabled == request.screen_perception_enabled {
                    return Ok(ScreenPerceptionCreateOutcome::Replayed(existing.clone()));
                }
                return Err(ScreenPerceptionError::policy_conflict());
            }
            let policy = make_policy(&request.life_id, request.screen_perception_enabled, 1);
            policies.insert(request.life_id, policy.clone());
            Ok(ScreenPerceptionCreateOutcome::Applied(policy))
        }

        fn find_screen_perception_policy(
            &self,
            life_id: &str,
        ) -> Result<Option<LifeScreenPerceptionPolicy>, ScreenPerceptionError> {
            Ok(self.policies.lock().unwrap().get(life_id).cloned())
        }

        fn update_screen_perception_policy(
            &self,
            request: LifeScreenPerceptionPolicyUpdateRequest,
        ) -> Result<LifeScreenPerceptionPolicyUpdateOutcome, ScreenPerceptionError> {
            let mut policies = self.policies.lock().unwrap();
            let current = policies
                .get(&request.life_id)
                .cloned()
                .ok_or_else(ScreenPerceptionError::policy_not_found)?;
            if current.revision != request.expected_revision {
                return Err(ScreenPerceptionError::revision_conflict());
            }
            if current.screen_perception_enabled == request.screen_perception_enabled {
                return Err(ScreenPerceptionError::invalid_transition());
            }
            let applied_revision = request.expected_revision + 1;
            let policy = make_policy(
                &request.life_id,
                request.screen_perception_enabled,
                applied_revision,
            );
            let event = LifeScreenPerceptionPolicyEvent {
                event_id: request.event_id,
                life_id: request.life_id.clone(),
                old_screen_perception_enabled: current.screen_perception_enabled,
                new_screen_perception_enabled: request.screen_perception_enabled,
                expected_revision: request.expected_revision,
                applied_revision,
                actor_kind: SCREEN_PERCEPTION_POLICY_ACTOR_KIND_USER_EXPLICIT.to_string(),
                occurred_at: policy.updated_at.clone(),
                event_version: SCREEN_PERCEPTION_POLICY_EVENT_VERSION,
            };
            policies.insert(request.life_id, policy.clone());
            Ok(LifeScreenPerceptionPolicyUpdateOutcome::Applied { event, policy })
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
            policy_version: super::super::screen_policy::SCREEN_PERCEPTION_POLICY_VERSION,
        }
    }

    #[test]
    fn arm_requires_a_present_enabled_policy_and_rejects_empty_life_without_panic() {
        let repository = FakeRepository::with_policies([make_policy("disabled", false, 1)]);
        let gate = ScreenPerceptionSessionGate::new();

        let missing =
            arm_screen_perception_session_service(&repository, &gate, "missing").unwrap_err();
        assert_eq!(missing.code, "SCREEN_PERCEPTION_POLICY_NOT_FOUND");

        let disabled =
            arm_screen_perception_session_service(&repository, &gate, "disabled").unwrap_err();
        assert_eq!(disabled.code, "SCREEN_PERCEPTION_POLICY_DISABLED");

        let empty = arm_screen_perception_session_service(&repository, &gate, "  ").unwrap_err();
        assert_eq!(empty.code, "SCREEN_PERCEPTION_INVALID_ARGUMENT");
        assert_eq!(
            get_screen_perception_session_status_service(&gate),
            ScreenPerceptionSessionStatusDto::Disarmed
        );
    }

    #[test]
    fn explicit_arm_rebinds_between_enabled_lives_and_explicit_disarm_is_immediate() {
        let repository = FakeRepository::with_policies([
            make_policy("life-a", true, 1),
            make_policy("life-b", true, 1),
        ]);
        let gate = ScreenPerceptionSessionGate::new();

        assert_eq!(
            arm_screen_perception_session_service(&repository, &gate, "life-a").unwrap(),
            ScreenPerceptionSessionStatusDto::Armed {
                life_id: "life-a".to_string()
            }
        );
        assert_eq!(
            arm_screen_perception_session_service(&repository, &gate, "life-b").unwrap(),
            ScreenPerceptionSessionStatusDto::Armed {
                life_id: "life-b".to_string()
            }
        );
        assert_eq!(
            disarm_screen_perception_session_service(&gate),
            ScreenPerceptionSessionStatusDto::Disarmed
        );
    }

    #[test]
    fn session_status_dto_contains_only_bounded_status_and_life_identity() {
        let gate = ScreenPerceptionSessionGate::new();
        assert_eq!(
            serde_json::to_value(get_screen_perception_session_status_service(&gate)).unwrap(),
            serde_json::json!({ "status": "disarmed" })
        );

        gate.arm_for_life("life-a");
        assert_eq!(
            serde_json::to_value(get_screen_perception_session_status_service(&gate)).unwrap(),
            serde_json::json!({ "status": "armed", "lifeId": "life-a" })
        );
    }

    #[test]
    fn durable_revoke_disarms_matching_gate_and_authorization_stays_denied() {
        let repository = FakeRepository::with_policies([make_policy("life-a", true, 1)]);
        let gate = ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");

        let updated = update_screen_perception_policy_service(
            &repository,
            &gate,
            UpdateScreenPerceptionPolicyRequest {
                event_id: "revoke-1".to_string(),
                life_id: "life-a".to_string(),
                enabled: false,
                expected_revision: 1,
            },
        )
        .unwrap();
        assert!(!updated.enabled);
        assert_eq!(
            get_screen_perception_session_status_service(&gate),
            ScreenPerceptionSessionStatusDto::Disarmed
        );

        let error =
            super::super::screen_policy::authorize_screen_perception(&repository, &gate, "life-a")
                .unwrap_err();
        assert_eq!(
            error.code,
            super::super::screen_policy::ScreenPerceptionErrorCode::PolicyDisabled
        );
    }

    #[test]
    fn policy_dto_exposes_only_settings_metadata() {
        let repository = FakeRepository::with_policies([make_policy("life-a", true, 4)]);
        let policy = get_screen_perception_policy_service(&repository, "life-a")
            .unwrap()
            .unwrap();
        assert_eq!(policy.life_id, "life-a");
        assert!(policy.enabled);
        assert_eq!(policy.revision, 4);
        assert_eq!(policy.created_at, "2026-08-29T00:00:00.000Z");
        assert_eq!(policy.updated_at, "2026-08-29T00:00:00.000Z");
    }
}
