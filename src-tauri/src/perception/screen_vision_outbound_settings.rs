//! Settings-only command boundary for the D25-A screen-vision outbound policy.
//!
//! This module exposes only durable consent metadata.  The repository remains
//! the sole owner of creation, explicit transitions, CAS, immutable event
//! evidence, and replay semantics; this boundary only adapts those operations
//! to bounded Settings DTOs and Tauri commands.

use serde::{Deserialize, Serialize};
use tauri::State;

use super::screen_vision_outbound_policy::{
    validate_screen_vision_outbound_policy_create_request,
    validate_screen_vision_outbound_policy_update_request, LifeScreenVisionOutboundPolicy,
    LifeScreenVisionOutboundPolicyCreateRequest, LifeScreenVisionOutboundPolicyUpdateOutcome,
    LifeScreenVisionOutboundPolicyUpdateRequest, ScreenVisionOutboundPolicyCreateOutcome,
    ScreenVisionOutboundPolicyError, ScreenVisionOutboundPolicyErrorCode,
    ScreenVisionOutboundPolicyRepository,
};
use crate::storage::StorageService;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScreenVisionOutboundPolicyLifeRequest {
    pub life_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateScreenVisionOutboundPolicyRequest {
    pub life_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateScreenVisionOutboundPolicyRequest {
    pub event_id: String,
    pub life_id: String,
    pub enabled: bool,
    pub expected_revision: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenVisionOutboundPolicyDto {
    pub life_id: String,
    pub enabled: bool,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenVisionOutboundCommandError {
    pub code: String,
    pub message: String,
    pub recoverable: bool,
}

fn validate_life_id(life_id: &str) -> Result<(), ScreenVisionOutboundPolicyError> {
    if life_id.trim().is_empty() {
        return Err(ScreenVisionOutboundPolicyError::invalid_argument(
            "life identity must not be empty.",
        ));
    }
    Ok(())
}

fn policy_dto(policy: LifeScreenVisionOutboundPolicy) -> ScreenVisionOutboundPolicyDto {
    ScreenVisionOutboundPolicyDto {
        life_id: policy.life_id,
        enabled: policy.screen_vision_outbound_enabled,
        revision: policy.revision,
        created_at: policy.created_at,
        updated_at: policy.updated_at,
    }
}

fn map_error(error: ScreenVisionOutboundPolicyError) -> ScreenVisionOutboundCommandError {
    let (code, message) = match error.code {
        ScreenVisionOutboundPolicyErrorCode::InvalidArgument => (
            "SCREEN_VISION_OUTBOUND_INVALID_ARGUMENT",
            "The screen vision outbound request is invalid.",
        ),
        ScreenVisionOutboundPolicyErrorCode::LifeNotFound => (
            "SCREEN_VISION_OUTBOUND_LIFE_NOT_FOUND",
            "The selected Life could not be found.",
        ),
        ScreenVisionOutboundPolicyErrorCode::PolicyNotFound => (
            "SCREEN_VISION_OUTBOUND_POLICY_NOT_FOUND",
            "No screen vision outbound consent has been configured for this Life.",
        ),
        ScreenVisionOutboundPolicyErrorCode::PolicyDisabled => (
            "SCREEN_VISION_OUTBOUND_POLICY_DISABLED",
            "Screen vision outbound consent is disabled for this Life.",
        ),
        ScreenVisionOutboundPolicyErrorCode::PolicyConflict => (
            "SCREEN_VISION_OUTBOUND_POLICY_CONFLICT",
            "The screen vision outbound consent already has conflicting evidence.",
        ),
        ScreenVisionOutboundPolicyErrorCode::PolicyEventConflict => (
            "SCREEN_VISION_OUTBOUND_POLICY_EVENT_CONFLICT",
            "This screen vision outbound consent action conflicts with an existing action.",
        ),
        ScreenVisionOutboundPolicyErrorCode::RevisionConflict => (
            "SCREEN_VISION_OUTBOUND_REVISION_CONFLICT",
            "Screen vision outbound consent changed elsewhere. Refresh and try again.",
        ),
        ScreenVisionOutboundPolicyErrorCode::InvalidTransition => (
            "SCREEN_VISION_OUTBOUND_INVALID_TRANSITION",
            "Screen vision outbound consent is already in that state.",
        ),
        ScreenVisionOutboundPolicyErrorCode::DatabaseUnavailable => (
            "SCREEN_VISION_OUTBOUND_DATABASE_UNAVAILABLE",
            "Screen vision outbound settings are temporarily unavailable. Try again.",
        ),
    };

    ScreenVisionOutboundCommandError {
        code: code.to_string(),
        message: message.to_string(),
        recoverable: error.recoverable,
    }
}

pub(crate) fn get_screen_vision_outbound_policy_service(
    repository: &dyn ScreenVisionOutboundPolicyRepository,
    life_id: &str,
) -> Result<Option<ScreenVisionOutboundPolicyDto>, ScreenVisionOutboundCommandError> {
    validate_life_id(life_id).map_err(map_error)?;
    repository
        .find_screen_vision_outbound_policy(life_id)
        .map_err(map_error)
        .map(|policy| policy.map(policy_dto))
}

pub(crate) fn create_screen_vision_outbound_policy_service(
    repository: &dyn ScreenVisionOutboundPolicyRepository,
    request: CreateScreenVisionOutboundPolicyRequest,
) -> Result<ScreenVisionOutboundPolicyDto, ScreenVisionOutboundCommandError> {
    let domain_request = LifeScreenVisionOutboundPolicyCreateRequest {
        life_id: request.life_id,
    };
    validate_screen_vision_outbound_policy_create_request(&domain_request).map_err(map_error)?;
    let outcome = repository
        .create_screen_vision_outbound_policy(domain_request)
        .map_err(map_error)?;
    let policy = match outcome {
        ScreenVisionOutboundPolicyCreateOutcome::Applied(policy)
        | ScreenVisionOutboundPolicyCreateOutcome::Replayed(policy) => policy,
    };
    Ok(policy_dto(policy))
}

pub(crate) fn update_screen_vision_outbound_policy_service(
    repository: &dyn ScreenVisionOutboundPolicyRepository,
    request: UpdateScreenVisionOutboundPolicyRequest,
) -> Result<ScreenVisionOutboundPolicyDto, ScreenVisionOutboundCommandError> {
    let domain_request = LifeScreenVisionOutboundPolicyUpdateRequest {
        event_id: request.event_id,
        life_id: request.life_id,
        screen_vision_outbound_enabled: request.enabled,
        expected_revision: request.expected_revision,
    };
    validate_screen_vision_outbound_policy_update_request(&domain_request).map_err(map_error)?;
    let outcome = repository
        .update_screen_vision_outbound_policy(domain_request)
        .map_err(map_error)?;
    let policy = match outcome {
        LifeScreenVisionOutboundPolicyUpdateOutcome::Applied { policy, .. } => policy,
        LifeScreenVisionOutboundPolicyUpdateOutcome::Replayed { current, .. } => current,
    };
    Ok(policy_dto(policy))
}

#[tauri::command]
pub fn get_screen_vision_outbound_policy(
    storage: State<'_, StorageService>,
    request: ScreenVisionOutboundPolicyLifeRequest,
) -> Result<Option<ScreenVisionOutboundPolicyDto>, ScreenVisionOutboundCommandError> {
    get_screen_vision_outbound_policy_service(storage.inner(), &request.life_id)
}

#[tauri::command]
pub fn create_screen_vision_outbound_policy(
    storage: State<'_, StorageService>,
    request: CreateScreenVisionOutboundPolicyRequest,
) -> Result<ScreenVisionOutboundPolicyDto, ScreenVisionOutboundCommandError> {
    create_screen_vision_outbound_policy_service(storage.inner(), request)
}

#[tauri::command]
pub fn update_screen_vision_outbound_policy(
    storage: State<'_, StorageService>,
    request: UpdateScreenVisionOutboundPolicyRequest,
) -> Result<ScreenVisionOutboundPolicyDto, ScreenVisionOutboundCommandError> {
    update_screen_vision_outbound_policy_service(storage.inner(), request)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tempfile::TempDir;

    use super::super::screen_vision_outbound_policy::{
        LifeScreenVisionOutboundPolicyEvent, ScreenVisionOutboundPolicyError,
        ScreenVisionOutboundPolicyErrorCode, ScreenVisionOutboundPolicyRepository,
    };
    use super::*;
    use crate::storage::{LifeIdentityRecord, PersonaTemplateRecord};

    struct Fixture {
        _root: TempDir,
        storage: StorageService,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let storage =
                StorageService::initialize_with_roots(root.path().to_path_buf(), None).unwrap();
            storage
                .save_persona(PersonaTemplateRecord {
                    id: "vision-settings-persona".into(),
                    name: "Vision Settings Persona".into(),
                    version: 1,
                    persona_json: "{}".into(),
                })
                .unwrap();
            storage
                .save_life(LifeIdentityRecord {
                    id: "vision-settings-life".into(),
                    name: "Vision Settings Life".into(),
                    created_at: "2026-08-31T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "vision-settings-body".into(),
                    persona_id: "vision-settings-persona".into(),
                    persona_version: 1,
                })
                .unwrap();
            Self {
                _root: root,
                storage,
            }
        }

        fn create(&self) -> ScreenVisionOutboundPolicyDto {
            create_screen_vision_outbound_policy_service(
                &self.storage,
                CreateScreenVisionOutboundPolicyRequest {
                    life_id: "vision-settings-life".into(),
                },
            )
            .unwrap()
        }

        fn update(
            &self,
            event_id: &str,
            enabled: bool,
            expected_revision: i64,
        ) -> Result<ScreenVisionOutboundPolicyDto, ScreenVisionOutboundCommandError> {
            update_screen_vision_outbound_policy_service(
                &self.storage,
                UpdateScreenVisionOutboundPolicyRequest {
                    event_id: event_id.into(),
                    life_id: "vision-settings-life".into(),
                    enabled,
                    expected_revision,
                },
            )
        }
    }

    #[test]
    fn get_missing_policy_returns_none_without_creating_policy() {
        let fixture = Fixture::new();

        assert!(get_screen_vision_outbound_policy_service(
            &fixture.storage,
            "vision-settings-life"
        )
        .unwrap()
        .is_none());
        assert!(fixture
            .storage
            .find_screen_vision_outbound_policy("vision-settings-life")
            .unwrap()
            .is_none());
    }

    #[test]
    fn create_is_disabled_revision_one_and_replay_returns_the_same_dto() {
        let fixture = Fixture::new();
        let first = fixture.create();
        assert!(!first.enabled);
        assert_eq!(first.revision, 1);
        assert_eq!(first.life_id, "vision-settings-life");
        assert_eq!(first.created_at, first.updated_at);

        let replay = fixture.create();
        assert_eq!(replay, first);
        let encoded = serde_json::to_value(&first).unwrap();
        assert_eq!(encoded["lifeId"], "vision-settings-life");
        assert_eq!(encoded["enabled"], false);
        assert_eq!(encoded["revision"], 1);
        assert_eq!(encoded["createdAt"], first.created_at);
        assert_eq!(encoded["updatedAt"], first.updated_at);
    }

    #[test]
    fn create_has_no_enabled_input_and_update_has_no_actor_kind_input() {
        let create = CreateScreenVisionOutboundPolicyRequest {
            life_id: "vision-settings-life".into(),
        };
        assert_eq!(create.life_id, "vision-settings-life");
        assert!(
            serde_json::from_value::<CreateScreenVisionOutboundPolicyRequest>(json!({
                "lifeId": "vision-settings-life",
                "enabled": true
            }))
            .is_err()
        );

        assert!(
            serde_json::from_value::<UpdateScreenVisionOutboundPolicyRequest>(json!({
                "eventId": "event-a",
                "lifeId": "vision-settings-life",
                "enabled": true,
                "expectedRevision": 1,
                "actorKind": "agent"
            }))
            .is_err()
        );
    }

    #[test]
    fn explicit_update_and_exact_replay_return_the_repository_policy() {
        let fixture = Fixture::new();
        fixture.create();

        let enabled = fixture.update("vision-settings-enable", true, 1).unwrap();
        assert!(enabled.enabled);
        assert_eq!(enabled.revision, 2);

        let replay = fixture.update("vision-settings-enable", true, 1).unwrap();
        assert_eq!(replay, enabled);

        let disabled = fixture.update("vision-settings-disable", false, 2).unwrap();
        assert!(!disabled.enabled);
        assert_eq!(disabled.revision, 3);
    }

    #[test]
    fn conflicting_event_revision_and_no_op_are_mapped_to_bounded_errors() {
        let fixture = Fixture::new();
        fixture.create();
        fixture.update("vision-settings-enable", true, 1).unwrap();

        let event_conflict = fixture
            .update("vision-settings-enable", false, 1)
            .unwrap_err();
        assert_eq!(
            event_conflict.code,
            "SCREEN_VISION_OUTBOUND_POLICY_EVENT_CONFLICT"
        );
        assert!(!event_conflict.recoverable);

        let revision_conflict = fixture
            .update("vision-settings-stale", false, 1)
            .unwrap_err();
        assert_eq!(
            revision_conflict.code,
            "SCREEN_VISION_OUTBOUND_REVISION_CONFLICT"
        );

        let no_op = fixture
            .update("vision-settings-no-op", true, 2)
            .unwrap_err();
        assert_eq!(no_op.code, "SCREEN_VISION_OUTBOUND_INVALID_TRANSITION");
    }

    #[test]
    fn missing_life_and_database_failures_are_safe() {
        let fixture = Fixture::new();
        let missing_life = create_screen_vision_outbound_policy_service(
            &fixture.storage,
            CreateScreenVisionOutboundPolicyRequest {
                life_id: "missing-life".into(),
            },
        )
        .unwrap_err();
        assert_eq!(missing_life.code, "SCREEN_VISION_OUTBOUND_LIFE_NOT_FOUND");
        assert!(missing_life.recoverable);

        let error =
            get_screen_vision_outbound_policy_service(&FailingRepository, "life-a").unwrap_err();
        assert_eq!(error.code, "SCREEN_VISION_OUTBOUND_DATABASE_UNAVAILABLE");
        assert!(error.recoverable);
        for forbidden in ["SELECT", "sqlite", "C:\\", "provider", "event_id"] {
            assert!(
                !error.message.contains(forbidden),
                "bounded error leaked {forbidden}"
            );
        }
    }

    #[test]
    fn settings_service_source_has_only_the_d25_repository_dependency() {
        let source = include_str!("screen_vision_outbound_settings.rs");
        for forbidden in [
            ["screen", "_policy"].concat(),
            ["screen", "_observation"].concat(),
            ["screen", "_context"].concat(),
            ["Screen", "PerceptionSessionGate"].concat(),
            ["Life", "ScreenPerceptionPolicy"].concat(),
            ["Screen", "PerceptionRepository"].concat(),
        ] {
            assert!(
                !source.contains(&forbidden),
                "Settings boundary must not depend on {forbidden}"
            );
        }
        assert!(source.contains("screen_vision_outbound_policy"));
        assert!(source.contains("ScreenVisionOutboundPolicyRepository"));
    }

    #[test]
    fn all_d25_commands_are_registered_and_acl_is_settings_only() {
        let registered = include_str!("../lib.rs");
        let settings = include_str!("../../permissions/settings-commands.toml");
        let chat = include_str!("../../permissions/chat-commands.toml");
        let main = include_str!("../../permissions/main-commands.toml");
        let default_capability = include_str!("../../capabilities/default.json");
        let settings_capability = include_str!("../../capabilities/settings.json");
        let chat_capability = include_str!("../../capabilities/chat.json");

        assert!(registered.contains(".invoke_handler(tauri::generate_handler!["));
        assert!(settings_capability.contains("\"windows\": [\"settings\"]"));
        assert!(settings_capability.contains("\"settings-commands\""));

        for command in [
            "get_screen_vision_outbound_policy",
            "create_screen_vision_outbound_policy",
            "update_screen_vision_outbound_policy",
        ] {
            assert!(
                registered.contains(&format!(
                    "perception::screen_vision_outbound_settings::{command}"
                )),
                "{command} must use the normal invoke handler"
            );
            assert!(settings
                .lines()
                .any(|line| line.trim() == format!("\"{command}\",")));
            assert!(!chat
                .lines()
                .any(|line| line.trim() == format!("\"{command}\",")));
            assert!(!main
                .lines()
                .any(|line| line.trim() == format!("\"{command}\",")));
            assert!(!default_capability.contains(command));
            assert!(!chat_capability.contains(command));
        }

        for command in [
            "get_screen_perception_policy",
            "create_screen_perception_policy",
            "update_screen_perception_policy",
            "get_screen_perception_session_status",
            "arm_screen_perception_session",
            "disarm_screen_perception_session",
            "pick_screen_capture_target",
            "get_screen_capture_target_status",
            "clear_screen_capture_target",
            "capture_screen_smoke",
        ] {
            assert!(settings
                .lines()
                .any(|line| line.trim() == format!("\"{command}\",")));
        }
    }

    #[derive(Default)]
    struct FailingRepository;

    fn database_error() -> ScreenVisionOutboundPolicyError {
        ScreenVisionOutboundPolicyError::new(
            ScreenVisionOutboundPolicyErrorCode::DatabaseUnavailable,
            r#"SELECT secret FROM C:\private\database.sqlite for provider event_id"#,
        )
    }

    impl ScreenVisionOutboundPolicyRepository for FailingRepository {
        fn create_screen_vision_outbound_policy(
            &self,
            _request: LifeScreenVisionOutboundPolicyCreateRequest,
        ) -> Result<
            ScreenVisionOutboundPolicyCreateOutcome<LifeScreenVisionOutboundPolicy>,
            ScreenVisionOutboundPolicyError,
        > {
            Err(database_error())
        }

        fn find_screen_vision_outbound_policy(
            &self,
            _life_id: &str,
        ) -> Result<Option<LifeScreenVisionOutboundPolicy>, ScreenVisionOutboundPolicyError>
        {
            Err(database_error())
        }

        fn update_screen_vision_outbound_policy(
            &self,
            _request: LifeScreenVisionOutboundPolicyUpdateRequest,
        ) -> Result<LifeScreenVisionOutboundPolicyUpdateOutcome, ScreenVisionOutboundPolicyError>
        {
            Err(database_error())
        }

        fn find_screen_vision_outbound_policy_event(
            &self,
            _life_id: &str,
            _event_id: &str,
        ) -> Result<Option<LifeScreenVisionOutboundPolicyEvent>, ScreenVisionOutboundPolicyError>
        {
            Err(database_error())
        }
    }
}
