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
    screen_context::{
        ScreenContextCandidateInput, ScreenContextError, ScreenContextErrorCode,
        ScreenContextHandoffBroker, ScreenContextSessionFence,
    },
    screen_ocr::{
        capture_screen_observation_while_permit_held, ScreenObservation, ScreenObservationError,
        ScreenObservationStatus,
    },
    screen_policy::{
        authorize_screen_perception, LifeScreenPerceptionPolicy, ScreenPerceptionErrorCode,
        ScreenPerceptionRepository, ScreenPerceptionSessionGate,
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
const SCREEN_CONTEXT_LIFE_UNAVAILABLE_CODE: &str = "SCREEN_CONTEXT_LIFE_UNAVAILABLE";
const SCREEN_CONTEXT_LIFE_UNAVAILABLE_MESSAGE: &str =
    "The current Life could not be verified. Try again.";
const SCREEN_CONTEXT_LIFE_CHANGED_CODE: &str = "SCREEN_CONTEXT_LIFE_CHANGED";
const SCREEN_CONTEXT_LIFE_CHANGED_MESSAGE: &str =
    "The current Life changed during the screen operation. Try again.";
const SCREEN_CONTEXT_SESSION_UNAVAILABLE_CODE: &str = "SCREEN_CONTEXT_SESSION_UNAVAILABLE";
const SCREEN_CONTEXT_SESSION_UNAVAILABLE_MESSAGE: &str =
    "The screen-perception session is not available for this Life.";
const SCREEN_CONTEXT_SESSION_CHANGED_CODE: &str = "SCREEN_CONTEXT_SESSION_CHANGED";
const SCREEN_CONTEXT_SESSION_CHANGED_MESSAGE: &str =
    "The screen-perception session changed during the operation. Try again.";
const SCREEN_CONTEXT_CONSENT_UNAVAILABLE_CODE: &str = "SCREEN_CONTEXT_CONSENT_UNAVAILABLE";
const SCREEN_CONTEXT_CONSENT_UNAVAILABLE_MESSAGE: &str =
    "Screen-perception consent could not be verified. Try again.";
const SCREEN_CONTEXT_CONSENT_DISABLED_CODE: &str = "SCREEN_CONTEXT_CONSENT_DISABLED";
const SCREEN_CONTEXT_CONSENT_DISABLED_MESSAGE: &str =
    "Screen-perception consent is disabled for this Life.";
const SCREEN_CONTEXT_UNAVAILABLE_CODE: &str = "SCREEN_CONTEXT_UNAVAILABLE";
const SCREEN_CONTEXT_UNAVAILABLE_MESSAGE: &str =
    "The requested screen context is unavailable or stale.";
const SCREEN_CONTEXT_EXPIRED_CODE: &str = "SCREEN_CONTEXT_EXPIRED";
const SCREEN_CONTEXT_EXPIRED_MESSAGE: &str = "The screen context candidate has expired.";
const SCREEN_CONTEXT_NO_USABLE_CODE: &str = "SCREEN_CONTEXT_NO_USABLE";
const SCREEN_CONTEXT_NO_USABLE_MESSAGE: &str =
    "The current screen observation contains no usable screen text.";
const SCREEN_CONTEXT_BROKER_UNAVAILABLE_CODE: &str = "SCREEN_CONTEXT_BROKER_UNAVAILABLE";
const SCREEN_CONTEXT_BROKER_UNAVAILABLE_MESSAGE: &str =
    "The screen context handoff authority is temporarily unavailable.";

/// Narrow authority seam for the authoritative current Life lookup.  The
/// production implementation reads StorageService's current-life join; tests
/// use per-instance scripted readers without changing the production path.
trait CurrentLifeAuthority: Send + Sync {
    fn current_life_id(&self) -> Result<Option<String>, ()>;
}

impl CurrentLifeAuthority for StorageService {
    fn current_life_id(&self) -> Result<Option<String>, ()> {
        self.get_current_life()
            .map(|life| life.map(|record| record.id))
            .map_err(|_| ())
    }
}

struct ObservationAuthorities<'a> {
    current_life: &'a dyn CurrentLifeAuthority,
    repository: &'a dyn ScreenPerceptionRepository,
    session_gate: &'a ScreenPerceptionSessionGate,
    target_broker: &'a ScreenCaptureTargetBroker,
    handoff_broker: &'a ScreenContextHandoffBroker,
}

struct PrepareAuthorities<'a> {
    current_life: &'a dyn CurrentLifeAuthority,
    repository: &'a dyn ScreenPerceptionRepository,
    session_gate: &'a ScreenPerceptionSessionGate,
    handoff_broker: &'a ScreenContextHandoffBroker,
}

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
    pub(crate) candidate_id: String,
}

/// Main-only result for the explicit Candidate → GrantPending handoff.  The
/// grant remains opaque and no observation content crosses this command.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainScreenContextGrantDto {
    pub(crate) grant_id: String,
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

fn life_authority_unavailable_error() -> MainScreenPerceptionErrorDto {
    bounded_error(
        SCREEN_CONTEXT_LIFE_UNAVAILABLE_CODE,
        SCREEN_CONTEXT_LIFE_UNAVAILABLE_MESSAGE,
        true,
    )
}

fn life_changed_error() -> MainScreenPerceptionErrorDto {
    bounded_error(
        SCREEN_CONTEXT_LIFE_CHANGED_CODE,
        SCREEN_CONTEXT_LIFE_CHANGED_MESSAGE,
        true,
    )
}

fn session_unavailable_error() -> MainScreenPerceptionErrorDto {
    bounded_error(
        SCREEN_CONTEXT_SESSION_UNAVAILABLE_CODE,
        SCREEN_CONTEXT_SESSION_UNAVAILABLE_MESSAGE,
        true,
    )
}

fn session_changed_error() -> MainScreenPerceptionErrorDto {
    bounded_error(
        SCREEN_CONTEXT_SESSION_CHANGED_CODE,
        SCREEN_CONTEXT_SESSION_CHANGED_MESSAGE,
        true,
    )
}

fn consent_unavailable_error() -> MainScreenPerceptionErrorDto {
    bounded_error(
        SCREEN_CONTEXT_CONSENT_UNAVAILABLE_CODE,
        SCREEN_CONTEXT_CONSENT_UNAVAILABLE_MESSAGE,
        true,
    )
}

fn consent_disabled_error() -> MainScreenPerceptionErrorDto {
    bounded_error(
        SCREEN_CONTEXT_CONSENT_DISABLED_CODE,
        SCREEN_CONTEXT_CONSENT_DISABLED_MESSAGE,
        false,
    )
}

fn context_unavailable_error() -> MainScreenPerceptionErrorDto {
    bounded_error(
        SCREEN_CONTEXT_UNAVAILABLE_CODE,
        SCREEN_CONTEXT_UNAVAILABLE_MESSAGE,
        true,
    )
}

fn context_expired_error() -> MainScreenPerceptionErrorDto {
    bounded_error(
        SCREEN_CONTEXT_EXPIRED_CODE,
        SCREEN_CONTEXT_EXPIRED_MESSAGE,
        true,
    )
}

fn no_usable_context_error() -> MainScreenPerceptionErrorDto {
    bounded_error(
        SCREEN_CONTEXT_NO_USABLE_CODE,
        SCREEN_CONTEXT_NO_USABLE_MESSAGE,
        true,
    )
}

fn broker_unavailable_error() -> MainScreenPerceptionErrorDto {
    bounded_error(
        SCREEN_CONTEXT_BROKER_UNAVAILABLE_CODE,
        SCREEN_CONTEXT_BROKER_UNAVAILABLE_MESSAGE,
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

fn validate_candidate_id(candidate_id: &str) -> Result<(), MainScreenPerceptionErrorDto> {
    let trimmed = candidate_id.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_LIFE_ID_CHARS {
        return Err(invalid_life_id_error());
    }
    Ok(())
}

fn observation_dto(
    observation: ScreenObservation,
    candidate_id: String,
) -> MainScreenObservationDto {
    let status = match observation.status {
        ScreenObservationStatus::Recognized => MainScreenObservationStatusDto::Recognized,
        ScreenObservationStatus::NoText => MainScreenObservationStatusDto::NoText,
    };
    MainScreenObservationDto {
        captured_at: observation.captured_at,
        status,
        text: observation.text,
        truncated: observation.truncated,
        candidate_id,
    }
}

fn observation_error_dto(error: ScreenObservationError) -> MainScreenPerceptionErrorDto {
    bounded_error(error.code.as_str(), error.message, error.recoverable)
}

fn screen_authorization_error_dto(
    error: super::screen_policy::ScreenPerceptionError,
) -> MainScreenPerceptionErrorDto {
    match error.code {
        ScreenPerceptionErrorCode::InvalidArgument => invalid_life_id_error(),
        ScreenPerceptionErrorCode::PolicyDisabled => consent_disabled_error(),
        ScreenPerceptionErrorCode::PolicyNotFound
        | ScreenPerceptionErrorCode::DatabaseUnavailable => consent_unavailable_error(),
        ScreenPerceptionErrorCode::SessionNotArmed
        | ScreenPerceptionErrorCode::SessionLifeMismatch => session_unavailable_error(),
        ScreenPerceptionErrorCode::LifeNotFound => life_changed_error(),
        ScreenPerceptionErrorCode::ScreenPerceptionPolicyConflict
        | ScreenPerceptionErrorCode::ScreenPerceptionPolicyEventConflict
        | ScreenPerceptionErrorCode::RevisionConflict
        | ScreenPerceptionErrorCode::InvalidTransition => consent_unavailable_error(),
    }
}

fn screen_context_error_dto(error: ScreenContextError) -> MainScreenPerceptionErrorDto {
    match error.code {
        ScreenContextErrorCode::InvalidArgument => invalid_life_id_error(),
        ScreenContextErrorCode::Expired => context_expired_error(),
        ScreenContextErrorCode::NoUsableScreenContext => no_usable_context_error(),
        ScreenContextErrorCode::SynchronizationUnavailable => broker_unavailable_error(),
        ScreenContextErrorCode::NoCurrentContext
        | ScreenContextErrorCode::LifeMismatch
        | ScreenContextErrorCode::SessionFenceMismatch
        | ScreenContextErrorCode::GrantAlreadyBound => context_unavailable_error(),
    }
}

fn require_current_life(
    authority: &dyn CurrentLifeAuthority,
    requested_life_id: &str,
) -> Result<(), MainScreenPerceptionErrorDto> {
    match authority.current_life_id() {
        Err(()) => Err(life_authority_unavailable_error()),
        Ok(Some(current_life_id)) if current_life_id == requested_life_id => Ok(()),
        Ok(_) => Err(life_changed_error()),
    }
}

/// Uses the canonical D23 authorization check for every durable-consent
/// reread.  The caller separately samples the D23 session fence so consent
/// and stale-session evidence cannot be conflated.
fn require_current_screen_authorization(
    repository: &dyn ScreenPerceptionRepository,
    session_gate: &ScreenPerceptionSessionGate,
    life_id: &str,
) -> Result<(), MainScreenPerceptionErrorDto> {
    authorize_screen_perception(repository, session_gate, life_id)
        .map_err(screen_authorization_error_dto)
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
        let handoff_broker = app.state::<ScreenContextHandoffBroker>();
        let authorities = ObservationAuthorities {
            current_life: storage.inner(),
            repository: storage.inner(),
            session_gate: session_gate.inner(),
            target_broker: target_broker.inner(),
            handoff_broker: handoff_broker.inner(),
        };

        observe_screen_now_service(&authorities, &operation_permit, &life_id)
    })
    .await
    .map_err(|_| dispatch_failed_error())?
}

/// Runs the frozen Observe Now sequence while the caller retains the one
/// canonical operation permit through Candidate installation.
fn observe_screen_now_service(
    authorities: &ObservationAuthorities<'_>,
    operation_permit: &ScreenCaptureOperationPermit,
    life_id: &str,
) -> Result<MainScreenObservationDto, MainScreenPerceptionErrorDto> {
    observe_screen_now_service_with_capture(
        authorities,
        operation_permit,
        life_id,
        |permit, repository, session_gate, target_broker, life_id| {
            capture_screen_observation_while_permit_held(
                permit,
                repository,
                session_gate,
                target_broker,
                life_id,
            )
        },
    )
}

/// Shared authority choreography with a private capture callback seam.  The
/// production caller above supplies only the native D23 borrowed-permit path;
/// tests use deterministic per-instance capture outcomes to exercise races.
fn observe_screen_now_service_with_capture<Capture>(
    authorities: &ObservationAuthorities<'_>,
    operation_permit: &ScreenCaptureOperationPermit,
    life_id: &str,
    capture: Capture,
) -> Result<MainScreenObservationDto, MainScreenPerceptionErrorDto>
where
    Capture: FnOnce(
        &ScreenCaptureOperationPermit,
        &dyn ScreenPerceptionRepository,
        &ScreenPerceptionSessionGate,
        &ScreenCaptureTargetBroker,
        &str,
    ) -> Result<ScreenObservation, ScreenObservationError>,
{
    validate_life_id(life_id)?;
    require_current_life(authorities.current_life, life_id)?;
    let fence_before = authorities
        .session_gate
        .life_fence_for(life_id)
        .ok_or_else(session_unavailable_error)?;

    let observation = capture(
        operation_permit,
        authorities.repository,
        authorities.session_gate,
        authorities.target_broker,
        life_id,
    )
    .map_err(observation_error_dto)?;

    require_current_life(authorities.current_life, life_id)?;
    require_current_screen_authorization(
        authorities.repository,
        authorities.session_gate,
        life_id,
    )?;
    let fence_after = authorities
        .session_gate
        .life_fence_for(life_id)
        .ok_or_else(session_changed_error)?;
    if fence_after != fence_before {
        return Err(session_changed_error());
    }

    let preview_observation = observation.clone();
    let candidate_id = authorities
        .handoff_broker
        .install_candidate(ScreenContextCandidateInput {
            life_id: life_id.to_string(),
            session_fence: ScreenContextSessionFence(fence_after),
            observation,
        })
        .map_err(screen_context_error_dto)?;

    // The candidate install happens before this function returns, while the
    // borrowed permit is still owned by the caller.
    Ok(observation_dto(preview_observation, candidate_id))
}

async fn dispatch_prepare_blocking(
    app: tauri::AppHandle,
    operation_permit: ScreenCaptureOperationPermit,
    life_id: String,
    candidate_id: String,
) -> Result<MainScreenContextGrantDto, MainScreenPerceptionErrorDto> {
    tauri::async_runtime::spawn_blocking(move || {
        let storage = app.state::<StorageService>();
        let session_gate = app.state::<ScreenPerceptionSessionGate>();
        let handoff_broker = app.state::<ScreenContextHandoffBroker>();
        let authorities = PrepareAuthorities {
            current_life: storage.inner(),
            repository: storage.inner(),
            session_gate: session_gate.inner(),
            handoff_broker: handoff_broker.inner(),
        };

        prepare_main_screen_context_for_chat_service(
            &authorities,
            &operation_permit,
            &life_id,
            &candidate_id,
        )
    })
    .await
    .map_err(|_| dispatch_failed_error())?
}

/// Explicit Main-only Candidate → GrantPending handoff.  The target broker is
/// intentionally absent: the screen was already captured, so target
/// selection is not a prerequisite for this authority transition.
fn prepare_main_screen_context_for_chat_service(
    authorities: &PrepareAuthorities<'_>,
    _operation_permit: &ScreenCaptureOperationPermit,
    life_id: &str,
    candidate_id: &str,
) -> Result<MainScreenContextGrantDto, MainScreenPerceptionErrorDto> {
    prepare_main_screen_context_for_chat_service_with_post_issue(
        authorities,
        _operation_permit,
        life_id,
        candidate_id,
        |_| {},
    )
}

/// Shared prepare choreography with a private, per-call post-issue seam for
/// deterministic race tests.  Production supplies a no-op; it never exposes
/// an alternate broker or authority path.  The test callback receives only
/// the newly issued opaque identity so rollback can be proven behaviorally.
fn prepare_main_screen_context_for_chat_service_with_post_issue<AfterIssue>(
    authorities: &PrepareAuthorities<'_>,
    _operation_permit: &ScreenCaptureOperationPermit,
    life_id: &str,
    candidate_id: &str,
    after_issue: AfterIssue,
) -> Result<MainScreenContextGrantDto, MainScreenPerceptionErrorDto>
where
    AfterIssue: FnOnce(&str),
{
    validate_life_id(life_id)?;
    validate_candidate_id(candidate_id)?;
    require_current_life(authorities.current_life, life_id)?;
    require_current_screen_authorization(
        authorities.repository,
        authorities.session_gate,
        life_id,
    )?;
    let fence_before = authorities
        .session_gate
        .life_fence_for(life_id)
        .ok_or_else(session_unavailable_error)?;

    let grant_id = authorities
        .handoff_broker
        .issue_grant(
            candidate_id,
            life_id,
            ScreenContextSessionFence(fence_before),
        )
        .map_err(screen_context_error_dto)?;

    after_issue(&grant_id);

    let post_issue_check = (|| {
        require_current_life(authorities.current_life, life_id)?;
        require_current_screen_authorization(
            authorities.repository,
            authorities.session_gate,
            life_id,
        )?;
        let fence_after = authorities
            .session_gate
            .life_fence_for(life_id)
            .ok_or_else(session_changed_error)?;
        if fence_after != fence_before {
            return Err(session_changed_error());
        }
        Ok(())
    })();

    match post_issue_check {
        Ok(()) => Ok(MainScreenContextGrantDto { grant_id }),
        Err(error) => {
            // Candidate → GrantPending has already occurred.  Cancel is the
            // broker's authority-shrinking rollback and must run before any
            // transition error is returned to Main.
            match authorities.handoff_broker.cancel() {
                Ok(()) => Err(error),
                Err(cancel_error) => Err(screen_context_error_dto(cancel_error)),
            }
        }
    }
}

/// Explicit Main-WebView Candidate → GrantPending command.
#[tauri::command]
pub async fn prepare_main_screen_context_for_chat(
    app: tauri::AppHandle,
    life_id: String,
    candidate_id: String,
) -> Result<MainScreenContextGrantDto, MainScreenPerceptionErrorDto> {
    validate_life_id(&life_id)?;
    validate_candidate_id(&candidate_id)?;
    let operation_permit = {
        let operation_gate = app.state::<ScreenCaptureOperationGate>();
        try_enter_observation_operation(operation_gate.inner())?
    };

    dispatch_prepare_blocking(app, operation_permit, life_id, candidate_id).await
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
    use std::{collections::HashMap, sync::Mutex};

    use super::*;
    use crate::perception::screen_context::{
        ScreenContextErrorCode, ScreenContextIds, ScreenContextPayload, ScreenContextTextStatus,
    };
    use crate::perception::screen_policy::{
        LifeScreenPerceptionPolicyCreateRequest, LifeScreenPerceptionPolicyEvent,
        LifeScreenPerceptionPolicyUpdateOutcome, LifeScreenPerceptionPolicyUpdateRequest,
        ScreenPerceptionError, SCREEN_PERCEPTION_POLICY_VERSION,
    };

    const LIFE_A: &str = "life-a";
    const LIFE_B: &str = "life-b";
    const CONVERSATION_ID: &str = "conversation-1";
    const REQUEST_ID: &str = "request-1";

    struct FakeRepository {
        policies: Mutex<HashMap<String, LifeScreenPerceptionPolicy>>,
    }

    impl FakeRepository {
        fn with_policy(policy: LifeScreenPerceptionPolicy) -> Self {
            Self {
                policies: Mutex::new(HashMap::from([(policy.life_id.clone(), policy)])),
            }
        }

        fn set_enabled(&self, life_id: &str, enabled: bool) {
            if let Some(policy) = self.policies.lock().unwrap().get_mut(life_id) {
                policy.screen_perception_enabled = enabled;
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

    struct FakeCurrentLife {
        current: Mutex<Result<Option<String>, ()>>,
    }

    impl FakeCurrentLife {
        fn for_life(life_id: &str) -> Self {
            Self {
                current: Mutex::new(Ok(Some(life_id.to_string()))),
            }
        }

        fn set(&self, life_id: Option<&str>) {
            *self.current.lock().unwrap() = Ok(life_id.map(str::to_string));
        }

        fn unavailable(&self) {
            *self.current.lock().unwrap() = Err(());
        }
    }

    impl CurrentLifeAuthority for FakeCurrentLife {
        fn current_life_id(&self) -> Result<Option<String>, ()> {
            self.current.lock().unwrap().clone()
        }
    }

    fn make_policy(enabled: bool) -> LifeScreenPerceptionPolicy {
        LifeScreenPerceptionPolicy {
            life_id: LIFE_A.to_string(),
            screen_perception_enabled: enabled,
            revision: 1,
            created_at: "2026-08-30T00:00:00.000Z".to_string(),
            updated_at: "2026-08-30T00:00:00.000Z".to_string(),
            policy_version: SCREEN_PERCEPTION_POLICY_VERSION,
        }
    }

    fn recognized(text: &str) -> ScreenObservation {
        ScreenObservation {
            captured_at: "2026-08-30T00:00:00.000Z".to_string(),
            status: ScreenObservationStatus::Recognized,
            text: text.to_string(),
            truncated: false,
        }
    }

    fn no_text() -> ScreenObservation {
        ScreenObservation {
            captured_at: "2026-08-30T00:00:01.000Z".to_string(),
            status: ScreenObservationStatus::NoText,
            text: String::new(),
            truncated: false,
        }
    }

    fn test_fixture() -> (
        FakeCurrentLife,
        FakeRepository,
        ScreenPerceptionSessionGate,
        ScreenCaptureTargetBroker,
        ScreenContextHandoffBroker,
        ScreenCaptureOperationGate,
    ) {
        let current_life = FakeCurrentLife::for_life(LIFE_A);
        let repository = FakeRepository::with_policy(make_policy(true));
        let session_gate = ScreenPerceptionSessionGate::new();
        session_gate.arm_for_life(LIFE_A);
        (
            current_life,
            repository,
            session_gate,
            ScreenCaptureTargetBroker::new(),
            ScreenContextHandoffBroker::new(),
            ScreenCaptureOperationGate::new(),
        )
    }

    fn observe_with_capture<Capture>(
        current_life: &dyn CurrentLifeAuthority,
        repository: &dyn ScreenPerceptionRepository,
        session_gate: &ScreenPerceptionSessionGate,
        target_broker: &ScreenCaptureTargetBroker,
        handoff_broker: &ScreenContextHandoffBroker,
        operation_gate: &ScreenCaptureOperationGate,
        capture: Capture,
    ) -> Result<MainScreenObservationDto, MainScreenPerceptionErrorDto>
    where
        Capture: FnOnce(
            &ScreenCaptureOperationPermit,
            &dyn ScreenPerceptionRepository,
            &ScreenPerceptionSessionGate,
            &ScreenCaptureTargetBroker,
            &str,
        ) -> Result<ScreenObservation, ScreenObservationError>,
    {
        let operation_permit = operation_gate
            .try_enter()
            .expect("the test observation must own the canonical permit");
        let authorities = ObservationAuthorities {
            current_life,
            repository,
            session_gate,
            target_broker,
            handoff_broker,
        };
        let result = observe_screen_now_service_with_capture(
            &authorities,
            &operation_permit,
            LIFE_A,
            capture,
        );
        drop(operation_permit);
        result
    }

    fn prepare_with_hook<AfterIssue>(
        current_life: &dyn CurrentLifeAuthority,
        repository: &dyn ScreenPerceptionRepository,
        session_gate: &ScreenPerceptionSessionGate,
        handoff_broker: &ScreenContextHandoffBroker,
        operation_gate: &ScreenCaptureOperationGate,
        candidate_id: &str,
        after_issue: AfterIssue,
    ) -> Result<MainScreenContextGrantDto, MainScreenPerceptionErrorDto>
    where
        AfterIssue: FnOnce(&str),
    {
        let operation_permit = operation_gate
            .try_enter()
            .expect("the test prepare must own the canonical permit");
        let authorities = PrepareAuthorities {
            current_life,
            repository,
            session_gate,
            handoff_broker,
        };
        let result = prepare_main_screen_context_for_chat_service_with_post_issue(
            &authorities,
            &operation_permit,
            LIFE_A,
            candidate_id,
            after_issue,
        );
        drop(operation_permit);
        result
    }

    fn claim_payload(
        handoff_broker: &ScreenContextHandoffBroker,
        grant_id: &str,
        fence: u64,
    ) -> Result<ScreenContextPayload, ScreenContextError> {
        handoff_broker.claim_grant(ScreenContextIds {
            grant_id: grant_id.to_string(),
            life_id: LIFE_A.to_string(),
            session_fence: ScreenContextSessionFence(fence),
            conversation_id: CONVERSATION_ID.to_string(),
            request_id: REQUEST_ID.to_string(),
        })
    }

    fn install_sentinel_candidate(
        handoff_broker: &ScreenContextHandoffBroker,
        fence: u64,
    ) -> String {
        handoff_broker
            .install_candidate(ScreenContextCandidateInput {
                life_id: LIFE_A.to_string(),
                session_fence: ScreenContextSessionFence(fence),
                observation: recognized("sentinel"),
            })
            .expect("the sentinel candidate must install")
    }

    fn assert_candidate_survives(
        handoff_broker: &ScreenContextHandoffBroker,
        candidate_id: &str,
        fence: u64,
    ) {
        let grant_id = handoff_broker
            .issue_grant(candidate_id, LIFE_A, ScreenContextSessionFence(fence))
            .expect("the sentinel candidate must remain current");
        assert_eq!(
            claim_payload(handoff_broker, &grant_id, fence)
                .unwrap()
                .text,
            "sentinel"
        );
    }

    fn assert_grant_canceled(
        handoff_broker: &ScreenContextHandoffBroker,
        grant_id: &str,
        fence: u64,
    ) {
        let error = claim_payload(handoff_broker, grant_id, fence)
            .expect_err("the post-issue failure must cancel GrantPending");
        assert_eq!(error.code, ScreenContextErrorCode::NoCurrentContext);
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
    fn observe_keeps_permit_until_after_candidate_installation() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let operation_permit = operation_gate
            .try_enter()
            .expect("observation must acquire the canonical permit");
        let authorities = ObservationAuthorities {
            current_life: &current_life,
            repository: &repository,
            session_gate: &session_gate,
            target_broker: &target_broker,
            handoff_broker: &handoff_broker,
        };
        let result = observe_screen_now_service_with_capture(
            &authorities,
            &operation_permit,
            LIFE_A,
            |_, _, _, _, _| Ok(recognized("candidate text")),
        )
        .expect("the recognized observation must install a candidate");

        assert!(!result.candidate_id.is_empty());
        assert!(
            operation_gate.try_enter().is_err(),
            "candidate installation must occur while the caller-owned permit is held"
        );
        let fence = session_gate
            .life_fence_for(LIFE_A)
            .expect("the fixture session must remain armed");
        let grant_id = handoff_broker
            .issue_grant(
                &result.candidate_id,
                LIFE_A,
                ScreenContextSessionFence(fence),
            )
            .expect("the candidate must carry the unchanged D23 fence");
        assert_eq!(
            claim_payload(&handoff_broker, &grant_id, fence)
                .unwrap()
                .text,
            "candidate text"
        );

        drop(operation_permit);
        assert!(operation_gate.try_enter().is_ok());
    }

    #[test]
    fn unchanged_fence_installs_candidate_with_exact_fence_and_life() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let fence_before = session_gate.life_fence_for(LIFE_A).unwrap();
        let result = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("same fence")),
        )
        .unwrap();
        let grant_id = handoff_broker
            .issue_grant(
                &result.candidate_id,
                LIFE_A,
                ScreenContextSessionFence(fence_before),
            )
            .unwrap();
        let payload = claim_payload(&handoff_broker, &grant_id, fence_before).unwrap();
        assert_eq!(payload.text, "same fence");
        assert_eq!(payload.status, ScreenContextTextStatus::Recognized);
    }

    #[test]
    fn disarm_and_rearm_during_observation_rejects_candidate_installation() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let fence_before = session_gate.life_fence_for(LIFE_A).unwrap();
        let sentinel_id = install_sentinel_candidate(&handoff_broker, fence_before);
        let error = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, session_gate, _, _| {
                session_gate.disarm();
                session_gate.arm_for_life(LIFE_A);
                Ok(recognized("stale session"))
            },
        )
        .unwrap_err();
        assert_eq!(error.code, SCREEN_CONTEXT_SESSION_CHANGED_CODE);
        assert_ne!(session_gate.life_fence_for(LIFE_A), Some(fence_before));
        assert_candidate_survives(&handoff_broker, &sentinel_id, fence_before);
    }

    #[test]
    fn durable_consent_revoke_during_observation_rejects_candidate_installation() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let fence = session_gate.life_fence_for(LIFE_A).unwrap();
        let sentinel_id = install_sentinel_candidate(&handoff_broker, fence);
        let error = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| {
                repository.set_enabled(LIFE_A, false);
                Ok(recognized("revoked"))
            },
        )
        .unwrap_err();
        assert_eq!(error.code, SCREEN_CONTEXT_CONSENT_DISABLED_CODE);
        assert_candidate_survives(&handoff_broker, &sentinel_id, fence);
    }

    #[test]
    fn authoritative_life_change_during_observation_rejects_candidate_installation() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let fence = session_gate.life_fence_for(LIFE_A).unwrap();
        let sentinel_id = install_sentinel_candidate(&handoff_broker, fence);
        let error = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| {
                current_life.set(Some(LIFE_B));
                Ok(recognized("life changed"))
            },
        )
        .unwrap_err();
        assert_eq!(error.code, SCREEN_CONTEXT_LIFE_CHANGED_CODE);
        assert_candidate_survives(&handoff_broker, &sentinel_id, fence);
    }

    #[test]
    fn post_capture_failed_life_authority_returns_no_preview_or_candidate() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let fence = session_gate.life_fence_for(LIFE_A).unwrap();
        let sentinel_id = install_sentinel_candidate(&handoff_broker, fence);
        let error = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| {
                current_life.unavailable();
                Ok(recognized("authority failed"))
            },
        )
        .unwrap_err();
        assert_eq!(error.code, SCREEN_CONTEXT_LIFE_UNAVAILABLE_CODE);
        assert_candidate_survives(&handoff_broker, &sentinel_id, fence);
    }

    #[test]
    fn recognized_observation_installs_candidate_and_returns_opaque_id() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let result = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("recognized candidate")),
        )
        .unwrap();
        assert_eq!(result.status, MainScreenObservationStatusDto::Recognized);
        assert_eq!(result.text, "recognized candidate");
        assert!(!result.candidate_id.is_empty());
    }

    #[test]
    fn no_text_observation_installs_and_replaces_previous_handoff() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let first = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("old text")),
        )
        .unwrap();
        let fence = session_gate.life_fence_for(LIFE_A).unwrap();
        let old_grant = handoff_broker
            .issue_grant(
                &first.candidate_id,
                LIFE_A,
                ScreenContextSessionFence(fence),
            )
            .unwrap();
        let _old_bound = claim_payload(&handoff_broker, &old_grant, fence).unwrap();

        let second = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(no_text()),
        )
        .unwrap();
        assert_eq!(second.status, MainScreenObservationStatusDto::NoText);
        assert_ne!(second.candidate_id, first.candidate_id);
        assert_eq!(
            claim_payload(&handoff_broker, &old_grant, fence)
                .unwrap_err()
                .code,
            ScreenContextErrorCode::NoCurrentContext
        );
        assert_eq!(
            handoff_broker
                .issue_grant(
                    &second.candidate_id,
                    LIFE_A,
                    ScreenContextSessionFence(fence)
                )
                .unwrap_err()
                .code,
            ScreenContextErrorCode::NoUsableScreenContext
        );
    }

    #[test]
    fn second_success_replaces_pending_and_bound_handoff_authority() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let fence = session_gate.life_fence_for(LIFE_A).unwrap();
        let first = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("first")),
        )
        .unwrap();
        let first_grant = handoff_broker
            .issue_grant(
                &first.candidate_id,
                LIFE_A,
                ScreenContextSessionFence(fence),
            )
            .unwrap();

        let second = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("second")),
        )
        .unwrap();
        assert_eq!(
            claim_payload(&handoff_broker, &first_grant, fence)
                .unwrap_err()
                .code,
            ScreenContextErrorCode::NoCurrentContext
        );
        let second_grant = handoff_broker
            .issue_grant(
                &second.candidate_id,
                LIFE_A,
                ScreenContextSessionFence(fence),
            )
            .unwrap();
        let _second_bound = claim_payload(&handoff_broker, &second_grant, fence).unwrap();

        let third = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("third")),
        )
        .unwrap();
        assert_ne!(third.candidate_id, second.candidate_id);
        assert_eq!(
            claim_payload(&handoff_broker, &second_grant, fence)
                .unwrap_err()
                .code,
            ScreenContextErrorCode::NoCurrentContext
        );
    }

    #[test]
    fn prepare_requires_the_current_candidate_id() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let candidate = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("prepare me")),
        )
        .unwrap();
        let error = prepare_with_hook(
            &current_life,
            &repository,
            &session_gate,
            &handoff_broker,
            &operation_gate,
            "wrong-candidate",
            |_| {},
        )
        .unwrap_err();
        assert_eq!(error.code, SCREEN_CONTEXT_UNAVAILABLE_CODE);

        let prepared = prepare_with_hook(
            &current_life,
            &repository,
            &session_gate,
            &handoff_broker,
            &operation_gate,
            &candidate.candidate_id,
            |_| {},
        )
        .unwrap();
        assert!(!prepared.grant_id.is_empty());
    }

    #[test]
    fn prepare_requires_authoritative_current_life() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let candidate = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("life authority")),
        )
        .unwrap();
        current_life.set(Some(LIFE_B));
        let error = prepare_with_hook(
            &current_life,
            &repository,
            &session_gate,
            &handoff_broker,
            &operation_gate,
            &candidate.candidate_id,
            |_| {},
        )
        .unwrap_err();
        assert_eq!(error.code, SCREEN_CONTEXT_LIFE_CHANGED_CODE);
    }

    #[test]
    fn prepare_requires_current_durable_consent() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let candidate = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("consent authority")),
        )
        .unwrap();
        repository.set_enabled(LIFE_A, false);
        let error = prepare_with_hook(
            &current_life,
            &repository,
            &session_gate,
            &handoff_broker,
            &operation_gate,
            &candidate.candidate_id,
            |_| {},
        )
        .unwrap_err();
        assert_eq!(error.code, SCREEN_CONTEXT_CONSENT_DISABLED_CODE);
    }

    #[test]
    fn prepare_requires_the_current_session_fence() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let candidate = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("session authority")),
        )
        .unwrap();
        session_gate.disarm();
        session_gate.arm_for_life(LIFE_A);
        let error = prepare_with_hook(
            &current_life,
            &repository,
            &session_gate,
            &handoff_broker,
            &operation_gate,
            &candidate.candidate_id,
            |_| {},
        )
        .unwrap_err();
        assert_eq!(error.code, SCREEN_CONTEXT_UNAVAILABLE_CODE);
    }

    #[test]
    fn prepare_does_not_require_a_selected_capture_target() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        assert_eq!(
            target_broker.current_status(),
            super::super::screen_capture::target::ScreenCaptureTargetStatus::None
        );
        let candidate = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("target no longer needed")),
        )
        .unwrap();
        let prepared = prepare_with_hook(
            &current_life,
            &repository,
            &session_gate,
            &handoff_broker,
            &operation_gate,
            &candidate.candidate_id,
            |_| {},
        )
        .unwrap();
        assert!(!prepared.grant_id.is_empty());
    }

    #[test]
    fn prepare_while_capture_owns_operation_gate_is_busy() {
        let operation_gate = ScreenCaptureOperationGate::new();
        let _capture_permit = operation_gate
            .try_enter()
            .expect("the capture operation must own the canonical gate");
        let error = try_enter_observation_operation(&operation_gate).unwrap_err();
        assert_eq!(error.code, OBSERVATION_BUSY_CODE);
    }

    #[test]
    fn post_issue_life_change_cancels_grant_pending_before_error() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let candidate = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("post issue life")),
        )
        .unwrap();
        let fence_before = session_gate.life_fence_for(LIFE_A).unwrap();
        let issued_grant_id = Mutex::new(None);
        let error = prepare_with_hook(
            &current_life,
            &repository,
            &session_gate,
            &handoff_broker,
            &operation_gate,
            &candidate.candidate_id,
            |grant_id| {
                *issued_grant_id.lock().unwrap() = Some(grant_id.to_string());
                current_life.set(Some(LIFE_B));
            },
        )
        .unwrap_err();
        assert_eq!(error.code, SCREEN_CONTEXT_LIFE_CHANGED_CODE);
        let issued_grant_id = issued_grant_id.lock().unwrap().clone().unwrap();
        assert_grant_canceled(&handoff_broker, &issued_grant_id, fence_before);
    }

    #[test]
    fn post_issue_session_change_cancels_grant_pending_before_error() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let candidate = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("post issue session")),
        )
        .unwrap();
        let fence_before = session_gate.life_fence_for(LIFE_A).unwrap();
        let issued_grant_id = Mutex::new(None);
        let error = prepare_with_hook(
            &current_life,
            &repository,
            &session_gate,
            &handoff_broker,
            &operation_gate,
            &candidate.candidate_id,
            |grant_id| {
                *issued_grant_id.lock().unwrap() = Some(grant_id.to_string());
                session_gate.disarm();
                session_gate.arm_for_life(LIFE_A);
            },
        )
        .unwrap_err();
        assert_eq!(error.code, SCREEN_CONTEXT_SESSION_CHANGED_CODE);
        let issued_grant_id = issued_grant_id.lock().unwrap().clone().unwrap();
        assert_grant_canceled(&handoff_broker, &issued_grant_id, fence_before);
    }

    #[test]
    fn post_issue_consent_revoke_cancels_grant_pending_before_error() {
        let (current_life, repository, session_gate, target_broker, handoff_broker, operation_gate) =
            test_fixture();
        let candidate = observe_with_capture(
            &current_life,
            &repository,
            &session_gate,
            &target_broker,
            &handoff_broker,
            &operation_gate,
            |_, _, _, _, _| Ok(recognized("post issue consent")),
        )
        .unwrap();
        let fence_before = session_gate.life_fence_for(LIFE_A).unwrap();
        let issued_grant_id = Mutex::new(None);
        let error = prepare_with_hook(
            &current_life,
            &repository,
            &session_gate,
            &handoff_broker,
            &operation_gate,
            &candidate.candidate_id,
            |grant_id| {
                *issued_grant_id.lock().unwrap() = Some(grant_id.to_string());
                repository.set_enabled(LIFE_A, false);
            },
        )
        .unwrap_err();
        assert_eq!(error.code, SCREEN_CONTEXT_CONSENT_DISABLED_CODE);
        let issued_grant_id = issued_grant_id.lock().unwrap().clone().unwrap();
        assert_grant_canceled(&handoff_broker, &issued_grant_id, fence_before);
    }

    #[test]
    fn observation_dto_serializes_only_the_bounded_main_fields() {
        let dto = MainScreenObservationDto {
            captured_at: "2026-08-30T00:00:00.000Z".to_string(),
            status: MainScreenObservationStatusDto::Recognized,
            text: "D23 MAIN OBSERVE 24680".to_string(),
            truncated: false,
            candidate_id: "candidate-opaque".to_string(),
        };
        assert_eq!(
            serde_json::to_value(dto).unwrap(),
            serde_json::json!({
                "capturedAt": "2026-08-30T00:00:00.000Z",
                "status": "recognized",
                "text": "D23 MAIN OBSERVE 24680",
                "truncated": false,
                "candidateId": "candidate-opaque",
            })
        );
    }

    #[test]
    fn main_observation_dto_has_no_raw_frame_target_or_fence_fields() {
        let value = serde_json::to_value(MainScreenObservationDto {
            captured_at: "2026-08-30T00:00:00.000Z".to_string(),
            status: MainScreenObservationStatusDto::NoText,
            text: String::new(),
            truncated: false,
            candidate_id: "opaque-candidate".to_string(),
        })
        .unwrap();
        let mut keys = value
            .as_object()
            .expect("the Main observation DTO must serialize as an object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        keys.sort();
        let mut expected = vec![
            "capturedAt".to_string(),
            "status".to_string(),
            "text".to_string(),
            "truncated".to_string(),
            "candidateId".to_string(),
        ];
        expected.sort();
        assert_eq!(keys, expected);
        let encoded = value.to_string();
        for forbidden in ["frame", "target", "fence", "pid", "hwnd", "native"] {
            assert!(
                !encoded.contains(forbidden),
                "forbidden native observation field leaked into Main DTO: {forbidden}"
            );
        }
    }

    #[test]
    fn prepare_result_serializes_only_the_opaque_grant_id() {
        assert_eq!(
            serde_json::to_value(MainScreenContextGrantDto {
                grant_id: "opaque-grant".to_string(),
            })
            .unwrap(),
            serde_json::json!({"grantId": "opaque-grant"})
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

        for command in [
            "observe_screen_now",
            "prepare_main_screen_context_for_chat",
            "get_main_screen_perception_status",
        ] {
            assert!(main.contains(&format!("\"{command}\"")));
            assert!(!settings.contains(&format!("\"{command}\"")));
            assert!(!chat.contains(&format!("\"{command}\"")));
        }
    }
}
