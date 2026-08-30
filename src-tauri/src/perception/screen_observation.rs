//! Main-WebView command boundary for explicit, ephemeral screen observation.
//!
//! D23-D2 owns only the presentation command and its bounded DTOs.  The
//! capture, target, session, and OCR authorities remain in the frozen D23-C1
//! and D23-D1 modules.  In particular, the canonical operation permit is
//! acquired before a blocking task is submitted, and the blocking closure
//! reacquires the application-managed authorities before invoking D1.

use serde::Serialize;
use tauri::Manager;

use super::{
    screen_capture::{
        operation::{ScreenCaptureOperationGate, ScreenCaptureOperationPermit},
        target::ScreenCaptureTargetBroker,
    },
    screen_ocr::{
        capture_screen_observation_with_permit, ScreenObservation, ScreenObservationError,
        ScreenObservationStatus,
    },
    screen_policy::{
        LifeScreenPerceptionPolicy, ScreenPerceptionRepository, ScreenPerceptionSessionGate,
    },
};
use crate::storage::StorageService;

const MAX_LIFE_ID_CHARS: usize = 128;

const OBSERVATION_INVALID_ARGUMENT_CODE: &str = "OBSERVATION_INVALID_ARGUMENT";
const OBSERVATION_INVALID_ARGUMENT_MESSAGE: &str = "The screen observation request is invalid.";
const OBSERVATION_BUSY_CODE: &str = "OBSERVATION_BUSY";
const OBSERVATION_BUSY_MESSAGE: &str =
    "Another screen-perception operation is already in progress.";
const OBSERVATION_DISPATCH_FAILED_CODE: &str = "OBSERVATION_DISPATCH_FAILED";
const OBSERVATION_DISPATCH_FAILED_MESSAGE: &str = "The screen observation could not be dispatched.";
const STATUS_UNAVAILABLE_CODE: &str = "SCREEN_PERCEPTION_STATUS_UNAVAILABLE";
const STATUS_UNAVAILABLE_MESSAGE: &str =
    "Screen perception readiness is temporarily unavailable. Try again.";

/// Presentation-only readiness metadata.  No target identity, native handle,
/// display identity, frame, or OCR content crosses this boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainScreenPerceptionStatusDto {
    pub(crate) consent_enabled: bool,
    pub(crate) session_armed: bool,
    pub(crate) target_selected: bool,
    pub(crate) ready: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(crate) enum MainScreenObservationStatusDto {
    #[serde(rename = "recognized")]
    Recognized,
    #[serde(rename = "noText")]
    NoText,
}

/// Bounded D1-derived observation data for the Main WebView.  This is a
/// dedicated IPC DTO rather than a serialization of any raw-frame or native
/// OCR type.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainScreenObservationDto {
    pub(crate) captured_at: String,
    pub(crate) status: MainScreenObservationStatusDto,
    pub(crate) text: String,
    pub(crate) truncated: bool,
}

/// Bounded command error.  Native details and diagnostic payloads are never
/// exposed through the Main command boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainScreenPerceptionErrorDto {
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

fn bounded_error(code: &str, message: &str, recoverable: bool) -> MainScreenPerceptionErrorDto {
    MainScreenPerceptionErrorDto {
        code: code.to_string(),
        message: message.to_string(),
        recoverable,
    }
}

fn invalid_life_id_error() -> MainScreenPerceptionErrorDto {
    bounded_error(
        OBSERVATION_INVALID_ARGUMENT_CODE,
        OBSERVATION_INVALID_ARGUMENT_MESSAGE,
        false,
    )
}

fn busy_error() -> MainScreenPerceptionErrorDto {
    bounded_error(OBSERVATION_BUSY_CODE, OBSERVATION_BUSY_MESSAGE, true)
}

fn dispatch_failed_error() -> MainScreenPerceptionErrorDto {
    bounded_error(
        OBSERVATION_DISPATCH_FAILED_CODE,
        OBSERVATION_DISPATCH_FAILED_MESSAGE,
        true,
    )
}

fn status_unavailable_error() -> MainScreenPerceptionErrorDto {
    bounded_error(STATUS_UNAVAILABLE_CODE, STATUS_UNAVAILABLE_MESSAGE, true)
}

fn validate_life_id(life_id: &str) -> Result<(), MainScreenPerceptionErrorDto> {
    let trimmed = life_id.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_LIFE_ID_CHARS {
        return Err(invalid_life_id_error());
    }
    Ok(())
}

fn observation_dto(observation: ScreenObservation) -> MainScreenObservationDto {
    let status = match observation.status {
        ScreenObservationStatus::Recognized => MainScreenObservationStatusDto::Recognized,
        ScreenObservationStatus::NoText => MainScreenObservationStatusDto::NoText,
    };
    MainScreenObservationDto {
        captured_at: observation.captured_at,
        status,
        text: observation.text,
        truncated: observation.truncated,
    }
}

fn observation_error_dto(error: ScreenObservationError) -> MainScreenPerceptionErrorDto {
    bounded_error(error.code.as_str(), error.message, error.recoverable)
}

fn try_enter_observation_operation(
    operation_gate: &ScreenCaptureOperationGate,
) -> Result<ScreenCaptureOperationPermit, MainScreenPerceptionErrorDto> {
    operation_gate.try_enter().map_err(|_| busy_error())
}

/// Reads the three presentation booleans from the canonical authorities.  The
/// target lookup is fence-aware, so a target from an older armed session is
/// not presented as ready for the requested Life.
pub(crate) fn get_main_screen_perception_status_service(
    repository: &dyn ScreenPerceptionRepository,
    session_gate: &ScreenPerceptionSessionGate,
    target_broker: &ScreenCaptureTargetBroker,
    life_id: &str,
) -> Result<MainScreenPerceptionStatusDto, MainScreenPerceptionErrorDto> {
    validate_life_id(life_id)?;
    let policy = repository
        .find_screen_perception_policy(life_id)
        .map_err(|_| status_unavailable_error())?;
    let consent_enabled = policy
        .as_ref()
        .is_some_and(LifeScreenPerceptionPolicy::is_screen_perception_enabled);
    let session_armed = session_gate.armed_life_id().as_deref() == Some(life_id);
    let target_selected = target_broker
        .current_target_for_life(session_gate, life_id)
        .is_some();

    Ok(MainScreenPerceptionStatusDto {
        consent_enabled,
        session_armed,
        target_selected,
        ready: consent_enabled && session_armed && target_selected,
    })
}

async fn dispatch_observation_blocking(
    app: tauri::AppHandle,
    operation_permit: ScreenCaptureOperationPermit,
    life_id: String,
) -> Result<MainScreenObservationDto, MainScreenPerceptionErrorDto> {
    tauri::async_runtime::spawn_blocking(move || {
        let storage = app.state::<StorageService>();
        let session_gate = app.state::<ScreenPerceptionSessionGate>();
        let target_broker = app.state::<ScreenCaptureTargetBroker>();

        capture_screen_observation_with_permit(
            operation_permit,
            storage.inner(),
            session_gate.inner(),
            target_broker.inner(),
            &life_id,
        )
        .map(observation_dto)
        .map_err(observation_error_dto)
    })
    .await
    .map_err(|_| dispatch_failed_error())?
}

/// Explicit Main-WebView observation command.
///
/// The canonical single-flight permit is acquired synchronously before any
/// blocking task is submitted.  Only the owned permit crosses the async
/// boundary; canonical managed state is reacquired inside the blocking task.
#[tauri::command]
pub async fn observe_screen_now(
    app: tauri::AppHandle,
    life_id: String,
) -> Result<MainScreenObservationDto, MainScreenPerceptionErrorDto> {
    validate_life_id(&life_id)?;
    let operation_permit = {
        let operation_gate = app.state::<ScreenCaptureOperationGate>();
        try_enter_observation_operation(operation_gate.inner())?
    };

    dispatch_observation_blocking(app, operation_permit, life_id).await
}

/// Returns presentation-only readiness metadata for the requested Life.
/// Actual observation authorization is still re-read by the D1 command path.
#[tauri::command]
pub fn get_main_screen_perception_status(
    app: tauri::AppHandle,
    life_id: String,
) -> Result<MainScreenPerceptionStatusDto, MainScreenPerceptionErrorDto> {
    let storage = app.state::<StorageService>();
    let session_gate = app.state::<ScreenPerceptionSessionGate>();
    let target_broker = app.state::<ScreenCaptureTargetBroker>();
    get_main_screen_perception_status_service(
        storage.inner(),
        session_gate.inner(),
        target_broker.inner(),
        &life_id,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;
    use crate::perception::screen_policy::{
        LifeScreenPerceptionPolicyCreateRequest, LifeScreenPerceptionPolicyEvent,
        LifeScreenPerceptionPolicyUpdateOutcome, LifeScreenPerceptionPolicyUpdateRequest,
        ScreenPerceptionError, SCREEN_PERCEPTION_POLICY_VERSION,
    };

    struct FakeRepository {
        policies: Mutex<HashMap<String, LifeScreenPerceptionPolicy>>,
    }

    impl FakeRepository {
        fn with_policy(policy: LifeScreenPerceptionPolicy) -> Self {
            Self {
                policies: Mutex::new(HashMap::from([(policy.life_id.clone(), policy)])),
            }
        }
    }

    impl ScreenPerceptionRepository for FakeRepository {
        fn create_screen_perception_policy(
            &self,
            _request: LifeScreenPerceptionPolicyCreateRequest,
        ) -> Result<
            super::super::screen_policy::ScreenPerceptionCreateOutcome<LifeScreenPerceptionPolicy>,
            ScreenPerceptionError,
        > {
            Err(ScreenPerceptionError::database())
        }

        fn find_screen_perception_policy(
            &self,
            life_id: &str,
        ) -> Result<Option<LifeScreenPerceptionPolicy>, ScreenPerceptionError> {
            Ok(self.policies.lock().unwrap().get(life_id).cloned())
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

    fn make_policy(enabled: bool) -> LifeScreenPerceptionPolicy {
        LifeScreenPerceptionPolicy {
            life_id: "life-a".to_string(),
            screen_perception_enabled: enabled,
            revision: 1,
            created_at: "2026-08-30T00:00:00.000Z".to_string(),
            updated_at: "2026-08-30T00:00:00.000Z".to_string(),
            policy_version: SCREEN_PERCEPTION_POLICY_VERSION,
        }
    }

    fn status_for(
        policy_enabled: bool,
        armed_life: Option<&str>,
        install_current_target: bool,
    ) -> MainScreenPerceptionStatusDto {
        let repository = FakeRepository::with_policy(make_policy(policy_enabled));
        let session_gate = ScreenPerceptionSessionGate::new();
        let target_broker = ScreenCaptureTargetBroker::new();
        if let Some(armed_life) = armed_life {
            session_gate.arm_for_life(armed_life);
        }
        if install_current_target {
            let life_fence = session_gate
                .life_fence_for("life-a")
                .expect("the test target requires Life A to be armed");
            target_broker.install_target_for_test(life_fence);
        }

        get_main_screen_perception_status_service(
            &repository,
            &session_gate,
            &target_broker,
            "life-a",
        )
        .expect("bounded readiness lookup should succeed")
    }

    #[test]
    fn busy_is_rejected_before_a_worker_callback_can_be_submitted() {
        let operation_gate = ScreenCaptureOperationGate::new();
        let _held_permit = operation_gate
            .try_enter()
            .expect("the first operation must own the canonical slot");
        let mut callback_submitted = false;

        let result = match try_enter_observation_operation(&operation_gate) {
            Ok(permit) => {
                callback_submitted = true;
                drop(permit);
                None
            }
            Err(error) => Some(error),
        };

        assert_eq!(
            result.expect("the held slot must reject immediately").code,
            OBSERVATION_BUSY_CODE
        );
        assert!(!callback_submitted);
    }

    #[test]
    fn observation_dto_serializes_only_the_bounded_main_fields() {
        let dto = MainScreenObservationDto {
            captured_at: "2026-08-30T00:00:00.000Z".to_string(),
            status: MainScreenObservationStatusDto::Recognized,
            text: "D23 MAIN OBSERVE 24680".to_string(),
            truncated: false,
        };
        assert_eq!(
            serde_json::to_value(dto).unwrap(),
            serde_json::json!({
                "capturedAt": "2026-08-30T00:00:00.000Z",
                "status": "recognized",
                "text": "D23 MAIN OBSERVE 24680",
                "truncated": false,
            })
        );
    }

    #[test]
    fn error_dto_serializes_only_the_bounded_error_fields() {
        let dto = busy_error();
        assert_eq!(
            serde_json::to_value(dto).unwrap(),
            serde_json::json!({
                "code": "OBSERVATION_BUSY",
                "message": OBSERVATION_BUSY_MESSAGE,
                "recoverable": true,
            })
        );
    }

    #[test]
    fn readiness_requires_policy_session_and_current_life_target() {
        let enabled = status_for(true, Some("life-a"), true);
        let disarmed = status_for(true, None, false);
        let wrong_life = status_for(true, Some("life-b"), false);
        let no_target = status_for(true, Some("life-a"), false);
        let disabled = status_for(false, Some("life-a"), true);

        assert!(
            enabled.ready,
            "the setup helper starts with an enabled policy"
        );
        assert!(!disarmed.ready);
        assert!(!wrong_life.ready);
        assert!(!no_target.ready);
        assert!(!disabled.consent_enabled);
        assert!(disabled.session_armed);
        assert!(disabled.target_selected);
        assert!(!disabled.ready);
    }

    #[test]
    fn main_acl_contains_d2_commands_and_secondary_acls_do_not() {
        let main = include_str!("../../permissions/main-commands.toml");
        let settings = include_str!("../../permissions/settings-commands.toml");
        let chat = include_str!("../../permissions/chat-commands.toml");

        for command in ["observe_screen_now", "get_main_screen_perception_status"] {
            assert!(main.contains(&format!("\"{command}\"")));
            assert!(!settings.contains(&format!("\"{command}\"")));
            assert!(!chat.contains(&format!("\"{command}\"")));
        }
    }
}
