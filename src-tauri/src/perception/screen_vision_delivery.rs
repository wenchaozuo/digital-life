//! D26-B Main-owned, explicit, one-shot screen Vision delivery.
//!
//! This module is the only composition point that can turn a local D25
//! candidate into an actual Vision provider request.  Preparation and review
//! state are process-local and single-slot; no image, PNG, base64, request, or
//! provider response is persisted or returned to a WebView.

use std::{
    io::{self, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{Duration, Instant},
};

use base64::Engine;
use serde::{Deserialize, Serialize};
use tauri::Manager;
use zeroize::Zeroizing;

use crate::{
    model::{
        profile::{credential_purpose, ModelProfile, ModelPurpose},
        provider::{
            build_screen_vision_request, parse_screen_vision_analysis,
            validate_screen_vision_profile, OpenAiCompatibleProvider,
            OpenAiCompatibleProviderConfig, ProviderError, ProviderErrorKind,
            SensitiveProviderExecutionError,
        },
        transport::http1::SendDisposition,
    },
    secrets::{SecretIdentifier, SecretStore, WindowsCredentialSecretStore},
    storage::StorageService,
};

use super::{
    screen_capture::{
        operation::{ScreenCaptureOperationGate, ScreenCaptureOperationPermit},
        target::ScreenCaptureTargetBroker,
    },
    screen_policy::{authorize_screen_perception, ScreenPerceptionSessionGate},
    screen_vision_outbound_candidate::{
        ScreenVisionOutboundCandidateBroker, ScreenVisionOutboundCandidateDeliveryLease,
        ScreenVisionOutboundCandidateError, ScreenVisionOutboundCandidateErrorCode,
    },
    screen_vision_outbound_delivery_claim::{
        claim_screen_vision_outbound_delivery, ScreenVisionOutboundDeliveryClaimError,
        ScreenVisionOutboundDeliveryClaimErrorCode, ScreenVisionOutboundDeliveryClaimRequest,
    },
    screen_vision_outbound_destination::ScreenVisionOutboundDestinationBinding,
    screen_vision_outbound_grant::{
        ScreenVisionOutboundGrantBroker, ScreenVisionOutboundGrantError,
        ScreenVisionOutboundGrantErrorCode, ScreenVisionOutboundGrantIssueOutcome,
    },
    screen_vision_outbound_policy::{
        authorize_screen_vision_outbound, validate_screen_vision_outbound_policy_state,
        ScreenVisionOutboundPolicyRepository,
    },
    screen_vision_outbound_preparation::{
        prepare_screen_vision_candidate_with_operation_permit,
        ScreenVisionOutboundPreparationError, ScreenVisionOutboundPreparationErrorCode,
        ScreenVisionOutboundPreparationRequest,
    },
    screen_vision_outbound_projection::{
        ScreenVisionOutboundProjection, ScreenVisionOutboundProjectionRequest,
        ScreenVisionOutboundRect,
    },
    screen_vision_outbound_resolver::{
        resolve_active_screen_vision_destination, ResolvedScreenVisionDestination,
        ScreenVisionDestinationResolverError, ScreenVisionDestinationResolverErrorCode,
    },
    CurrentLifeAuthority,
};

pub(crate) const MAX_SCREEN_VISION_PNG_BYTES: usize = 8 * 1024 * 1024;
const SCREEN_VISION_REVIEW_TTL: Duration = Duration::from_secs(2 * 60);
const REVIEW_ID_RANDOM_BYTES: usize = 16;
const REVIEW_ID_HEX_LENGTH: usize = REVIEW_ID_RANDOM_BYTES * 2;
const MAX_ID_CHARACTERS: usize = 128;
const FULL_SELECTED_TARGET_SCOPE: &str = "FULL_SELECTED_TARGET";
const FIXED_SCREEN_VISION_USER_TEXT: &str =
    "Describe the observable, task-relevant contents of this user-approved screen image.";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainScreenVisionErrorCode {
    InvalidArgument,
    LifeUnavailable,
    LocalScreenUnavailable,
    OutboundPolicyUnavailable,
    ProviderUnavailable,
    CredentialUnavailable,
    TargetUnavailable,
    CaptureUnavailable,
    ReviewInUse,
    ReviewUnavailable,
    ReviewExpired,
    ReviewStale,
    ReviewConflict,
    DeliveryInProgress,
    CandidateUnavailable,
    DeliveryUnavailable,
    DeliveryLeaseUnavailable,
    PngEncodingFailed,
    PngTooLarge,
    RequestTooLarge,
    NotSent,
    OutcomeUnknown,
    ProviderResponded,
    ResponseInvalidAfterSend,
    AbandonUnavailable,
    SynchronizationUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MainScreenVisionError {
    code: MainScreenVisionErrorCode,
    recoverable: bool,
}

impl MainScreenVisionError {
    const fn new(code: MainScreenVisionErrorCode, recoverable: bool) -> Self {
        Self { code, recoverable }
    }

    fn dto(self) -> MainScreenVisionErrorDto {
        MainScreenVisionErrorDto {
            code: self.code.as_str().to_string(),
            message: self.code.message().to_string(),
            recoverable: self.recoverable,
        }
    }
}

impl MainScreenVisionErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "VISION_INVALID_ARGUMENT",
            Self::LifeUnavailable => "VISION_LIFE_UNAVAILABLE",
            Self::LocalScreenUnavailable => "VISION_LOCAL_SCREEN_UNAVAILABLE",
            Self::OutboundPolicyUnavailable => "VISION_OUTBOUND_POLICY_UNAVAILABLE",
            Self::ProviderUnavailable => "VISION_PROVIDER_UNAVAILABLE",
            Self::CredentialUnavailable => "VISION_CREDENTIAL_UNAVAILABLE",
            Self::TargetUnavailable => "VISION_TARGET_UNAVAILABLE",
            Self::CaptureUnavailable => "VISION_CAPTURE_UNAVAILABLE",
            Self::ReviewInUse => "VISION_REVIEW_IN_USE",
            Self::ReviewUnavailable => "VISION_REVIEW_UNAVAILABLE",
            Self::ReviewExpired => "VISION_REVIEW_EXPIRED",
            Self::ReviewStale => "VISION_REVIEW_STALE",
            Self::ReviewConflict => "VISION_REVIEW_CONFLICT",
            Self::DeliveryInProgress => "VISION_DELIVERY_IN_PROGRESS",
            Self::CandidateUnavailable => "VISION_CANDIDATE_UNAVAILABLE",
            Self::DeliveryUnavailable => "VISION_DELIVERY_UNAVAILABLE",
            Self::DeliveryLeaseUnavailable => "VISION_DELIVERY_LEASE_UNAVAILABLE",
            Self::PngEncodingFailed => "VISION_PNG_ENCODING_FAILED",
            Self::PngTooLarge => "VISION_PNG_TOO_LARGE",
            Self::RequestTooLarge => "VISION_REQUEST_TOO_LARGE",
            Self::NotSent => "VISION_NOT_SENT",
            Self::OutcomeUnknown => "VISION_SEND_OUTCOME_UNKNOWN",
            Self::ProviderResponded => "VISION_PROVIDER_RESPONDED",
            Self::ResponseInvalidAfterSend => "VISION_RESPONSE_INVALID_AFTER_SEND",
            Self::AbandonUnavailable => "VISION_ABANDON_UNAVAILABLE",
            Self::SynchronizationUnavailable => "VISION_SYNCHRONIZATION_UNAVAILABLE",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::InvalidArgument => "The Vision request is invalid.",
            Self::LifeUnavailable => "The current Life could not be verified. Try again.",
            Self::LocalScreenUnavailable => {
                "Screen perception is not authorized for this session."
            }
            Self::OutboundPolicyUnavailable => {
                "Screen image sharing is not currently authorized for this Life."
            }
            Self::ProviderUnavailable => {
                "A valid active Vision provider is not available. Check Settings."
            }
            Self::CredentialUnavailable => {
                "A Vision credential is not configured for the active profile."
            }
            Self::TargetUnavailable => "The selected screen target is unavailable.",
            Self::CaptureUnavailable => "The selected screen target could not be captured.",
            Self::ReviewInUse => "Another Vision review or delivery is already using this target.",
            Self::ReviewUnavailable => "The Vision review is no longer available. Prepare again.",
            Self::ReviewExpired => "The Vision review expired. Prepare the screen again.",
            Self::ReviewStale => {
                "The Vision destination changed. Prepare and review the screen again."
            }
            Self::ReviewConflict => "This Vision review does not match the current attempt.",
            Self::DeliveryInProgress => "A Vision delivery is already in progress.",
            Self::CandidateUnavailable => "The prepared screen candidate is no longer available.",
            Self::DeliveryUnavailable => "The Vision delivery authorization is unavailable.",
            Self::DeliveryLeaseUnavailable => {
                "The prepared screen could not be reserved for this delivery."
            }
            Self::PngEncodingFailed => "The screen image could not be encoded for Vision.",
            Self::PngTooLarge => "The encoded screen image exceeds the allowed size.",
            Self::RequestTooLarge => "The Vision request exceeds the allowed size.",
            Self::NotSent => "The image was not sent. You may retry this same attempt.",
            Self::OutcomeUnknown => {
                "The image may have been sent. Retrying can send the same image again to the same Vision provider."
            }
            Self::ProviderResponded => {
                "The Vision provider responded. Prepare a new image before trying again."
            }
            Self::ResponseInvalidAfterSend => {
                "The image was sent, but the Vision response was invalid. Prepare a new analysis."
            }
            Self::AbandonUnavailable => "This Vision attempt can no longer be abandoned.",
            Self::SynchronizationUnavailable => "Vision delivery is temporarily unavailable.",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainScreenVisionErrorDto {
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainScreenVisionReviewDto {
    pub(crate) review_id: String,
    pub(crate) scope: String,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) provider_kind: String,
    pub(crate) provider_host: String,
    pub(crate) profile_display_name: String,
    pub(crate) model_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainScreenVisionReviewDisplayDto {
    pub(crate) scope: String,
    pub(crate) width: u32,
    pub(crate) height: u32,
    pub(crate) provider_kind: String,
    pub(crate) provider_host: String,
    pub(crate) profile_display_name: String,
    pub(crate) model_name: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum MainScreenVisionStatusKind {
    Idle,
    ReviewReady,
    DeliveryInProgress,
    AwaitingRetryDecision,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainScreenVisionStatusDto {
    pub(crate) status: MainScreenVisionStatusKind,
    pub(crate) review: Option<MainScreenVisionReviewDisplayDto>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainScreenVisionAnalysisDto {
    pub(crate) summary: String,
    pub(crate) observations: Vec<String>,
    pub(crate) provider_display_name: String,
    pub(crate) model_name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExecuteMainScreenVisionReviewRequest {
    pub(crate) review_id: String,
    pub(crate) confirmation_event_id: String,
    pub(crate) delivery_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct AbandonMainScreenVisionDeliveryRequest {
    pub(crate) review_id: String,
}

#[derive(Clone)]
struct ReviewEvidence {
    review_id: String,
    candidate_id: String,
    life_id: String,
    profile: ModelProfile,
    binding: ScreenVisionOutboundDestinationBinding,
    provider_host: String,
    width: u32,
    height: u32,
    created_at: Instant,
}

#[derive(Clone)]
struct CommittedReview {
    evidence: ReviewEvidence,
    confirmation_event_id: String,
    delivery_id: String,
    grant_id: String,
}

enum ReviewState {
    Empty,
    Ready(ReviewEvidence),
    Committed(CommittedReview),
}

#[derive(Clone)]
enum ScreenVisionReviewExecution {
    Ready(ReviewEvidence),
    Committed(CommittedReview),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionReviewErrorCode {
    InvalidArgument,
    NoReview,
    ReviewExpired,
    ReviewInUse,
    ReviewConflict,
    SynchronizationUnavailable,
    RandomUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionReviewError {
    code: ScreenVisionReviewErrorCode,
}

impl ScreenVisionReviewError {
    const fn new(code: ScreenVisionReviewErrorCode) -> Self {
        Self { code }
    }

    pub(crate) const fn code(self) -> ScreenVisionReviewErrorCode {
        self.code
    }
}

trait ReviewClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemReviewClock;

impl ReviewClock for SystemReviewClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

trait ReviewIdSource: Send + Sync {
    fn generate(&self) -> Result<String, ScreenVisionReviewError>;
}

struct CsPrngReviewIdSource;

impl ReviewIdSource for CsPrngReviewIdSource {
    fn generate(&self) -> Result<String, ScreenVisionReviewError> {
        let mut random = [0_u8; REVIEW_ID_RANDOM_BYTES];
        getrandom::fill(&mut random).map_err(|_| {
            ScreenVisionReviewError::new(ScreenVisionReviewErrorCode::RandomUnavailable)
        })?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut id = String::with_capacity(REVIEW_ID_HEX_LENGTH);
        for byte in random {
            id.push(char::from(HEX[usize::from(byte >> 4)]));
            id.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(id)
    }
}

pub(crate) struct ScreenVisionReviewBroker {
    state: Mutex<ReviewState>,
    clock: Arc<dyn ReviewClock>,
    id_source: Arc<dyn ReviewIdSource>,
}

impl ScreenVisionReviewBroker {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(ReviewState::Empty),
            clock: Arc::new(SystemReviewClock),
            id_source: Arc::new(CsPrngReviewIdSource),
        }
    }

    pub(crate) fn ensure_can_prepare(&self) -> Result<(), ScreenVisionReviewError> {
        let state = self.lock_state()?;
        if matches!(&*state, ReviewState::Committed(_)) {
            return Err(ScreenVisionReviewError::new(
                ScreenVisionReviewErrorCode::ReviewInUse,
            ));
        }
        Ok(())
    }

    pub(crate) fn install_ready(
        &self,
        candidate_id: String,
        life_id: String,
        resolved: ResolvedScreenVisionDestination,
        provider_host: String,
        width: u32,
        height: u32,
    ) -> Result<MainScreenVisionReviewDto, ScreenVisionReviewError> {
        validate_id(&candidate_id).map_err(|_| {
            ScreenVisionReviewError::new(ScreenVisionReviewErrorCode::InvalidArgument)
        })?;
        validate_id(&life_id).map_err(|_| {
            ScreenVisionReviewError::new(ScreenVisionReviewErrorCode::InvalidArgument)
        })?;
        if width == 0 || height == 0 {
            return Err(ScreenVisionReviewError::new(
                ScreenVisionReviewErrorCode::InvalidArgument,
            ));
        }
        let review_id = self.id_source.generate()?;
        let mut state = self.lock_state()?;
        if matches!(&*state, ReviewState::Committed(_)) {
            return Err(ScreenVisionReviewError::new(
                ScreenVisionReviewErrorCode::ReviewInUse,
            ));
        }
        let evidence = ReviewEvidence {
            review_id: review_id.clone(),
            candidate_id,
            life_id,
            profile: resolved.profile,
            binding: resolved.binding,
            provider_host,
            width,
            height,
            created_at: self.clock.now(),
        };
        let dto = review_dto(&evidence);
        *state = ReviewState::Ready(evidence);
        Ok(dto)
    }

    fn get_for_execution(
        &self,
        review_id: &str,
        confirmation_event_id: &str,
        delivery_id: &str,
    ) -> Result<ScreenVisionReviewExecution, ScreenVisionReviewError> {
        validate_id(review_id)?;
        validate_id(confirmation_event_id)?;
        validate_id(delivery_id)?;
        let mut state = self.lock_state()?;
        let now = self.clock.now();
        if let ReviewState::Ready(evidence) = &*state {
            if now.saturating_duration_since(evidence.created_at) >= SCREEN_VISION_REVIEW_TTL {
                *state = ReviewState::Empty;
                return Err(ScreenVisionReviewError::new(
                    ScreenVisionReviewErrorCode::ReviewExpired,
                ));
            }
        }
        match &*state {
            ReviewState::Ready(evidence) if evidence.review_id == review_id => {
                Ok(ScreenVisionReviewExecution::Ready(evidence.clone()))
            }
            ReviewState::Committed(committed) if committed.evidence.review_id == review_id => {
                if committed.confirmation_event_id != confirmation_event_id
                    || committed.delivery_id != delivery_id
                {
                    return Err(ScreenVisionReviewError::new(
                        ScreenVisionReviewErrorCode::ReviewConflict,
                    ));
                }
                Ok(ScreenVisionReviewExecution::Committed(committed.clone()))
            }
            ReviewState::Empty => Err(ScreenVisionReviewError::new(
                ScreenVisionReviewErrorCode::NoReview,
            )),
            _ => Err(ScreenVisionReviewError::new(
                ScreenVisionReviewErrorCode::ReviewConflict,
            )),
        }
    }

    fn get_committed_exact(
        &self,
        review_id: &str,
    ) -> Result<Option<CommittedReview>, ScreenVisionReviewError> {
        validate_id(review_id)?;
        let state = self.lock_state()?;
        match &*state {
            ReviewState::Committed(committed) if committed.evidence.review_id == review_id => {
                Ok(Some(committed.clone()))
            }
            ReviewState::Committed(_) | ReviewState::Ready(_) => Err(ScreenVisionReviewError::new(
                ScreenVisionReviewErrorCode::ReviewConflict,
            )),
            ReviewState::Empty => Err(ScreenVisionReviewError::new(
                ScreenVisionReviewErrorCode::NoReview,
            )),
        }
    }

    pub(crate) fn commit_exact(
        &self,
        review_id: &str,
        confirmation_event_id: &str,
        delivery_id: &str,
        grant_id: &str,
    ) -> Result<(), ScreenVisionReviewError> {
        validate_id(review_id)?;
        validate_id(confirmation_event_id)?;
        validate_id(delivery_id)?;
        validate_id(grant_id)?;
        let mut state = self.lock_state()?;
        let ReviewState::Ready(evidence) = &*state else {
            return match &*state {
                ReviewState::Committed(committed)
                    if committed.evidence.review_id == review_id
                        && committed.confirmation_event_id == confirmation_event_id
                        && committed.delivery_id == delivery_id
                        && committed.grant_id == grant_id =>
                {
                    Ok(())
                }
                ReviewState::Committed(_) => Err(ScreenVisionReviewError::new(
                    ScreenVisionReviewErrorCode::ReviewConflict,
                )),
                ReviewState::Empty => Err(ScreenVisionReviewError::new(
                    ScreenVisionReviewErrorCode::NoReview,
                )),
                ReviewState::Ready(_) => unreachable!(),
            };
        };
        if evidence.review_id != review_id {
            return Err(ScreenVisionReviewError::new(
                ScreenVisionReviewErrorCode::ReviewConflict,
            ));
        }
        let evidence = match std::mem::replace(&mut *state, ReviewState::Empty) {
            ReviewState::Ready(evidence) => evidence,
            _ => unreachable!("review state cannot change while its mutex is held"),
        };
        *state = ReviewState::Committed(CommittedReview {
            evidence,
            confirmation_event_id: confirmation_event_id.to_string(),
            delivery_id: delivery_id.to_string(),
            grant_id: grant_id.to_string(),
        });
        Ok(())
    }

    pub(crate) fn validate_committed_exact(
        &self,
        review_id: &str,
        confirmation_event_id: &str,
        delivery_id: &str,
        grant_id: &str,
    ) -> Result<(), ScreenVisionReviewError> {
        validate_id(review_id)?;
        validate_id(confirmation_event_id)?;
        validate_id(delivery_id)?;
        validate_id(grant_id)?;
        let state = self.lock_state()?;
        match &*state {
            ReviewState::Committed(committed)
                if committed.evidence.review_id == review_id
                    && committed.confirmation_event_id == confirmation_event_id
                    && committed.delivery_id == delivery_id
                    && committed.grant_id == grant_id =>
            {
                Ok(())
            }
            ReviewState::Committed(_) => Err(ScreenVisionReviewError::new(
                ScreenVisionReviewErrorCode::ReviewConflict,
            )),
            _ => Err(ScreenVisionReviewError::new(
                ScreenVisionReviewErrorCode::NoReview,
            )),
        }
    }

    pub(crate) fn clear_committed_exact(
        &self,
        review_id: &str,
        confirmation_event_id: &str,
        delivery_id: &str,
        grant_id: &str,
    ) -> Result<(), ScreenVisionReviewError> {
        self.validate_committed_exact(review_id, confirmation_event_id, delivery_id, grant_id)?;
        let mut state = self.lock_state()?;
        if matches!(
            &*state,
            ReviewState::Committed(committed)
                if committed.evidence.review_id == review_id
                    && committed.confirmation_event_id == confirmation_event_id
                    && committed.delivery_id == delivery_id
                    && committed.grant_id == grant_id
        ) {
            *state = ReviewState::Empty;
            Ok(())
        } else {
            Err(ScreenVisionReviewError::new(
                ScreenVisionReviewErrorCode::ReviewConflict,
            ))
        }
    }

    fn status_snapshot(&self) -> Result<ScreenVisionReviewStatusSnapshot, ScreenVisionReviewError> {
        let mut state = self.lock_state()?;
        let now = self.clock.now();
        if let ReviewState::Ready(evidence) = &*state {
            if now.saturating_duration_since(evidence.created_at) >= SCREEN_VISION_REVIEW_TTL {
                *state = ReviewState::Empty;
            }
        }
        Ok(match &*state {
            ReviewState::Empty => ScreenVisionReviewStatusSnapshot::Empty,
            ReviewState::Ready(evidence) => {
                ScreenVisionReviewStatusSnapshot::Ready(evidence.clone())
            }
            ReviewState::Committed(committed) => {
                ScreenVisionReviewStatusSnapshot::Committed(committed.clone())
            }
        })
    }

    fn lock_state(&self) -> Result<MutexGuard<'_, ReviewState>, ScreenVisionReviewError> {
        self.state.lock().map_err(|_| {
            ScreenVisionReviewError::new(ScreenVisionReviewErrorCode::SynchronizationUnavailable)
        })
    }
}

enum ScreenVisionReviewStatusSnapshot {
    Empty,
    Ready(ReviewEvidence),
    Committed(CommittedReview),
}

fn validate_id(value: &str) -> Result<(), ScreenVisionReviewError> {
    if value.trim().is_empty() || value.chars().count() > MAX_ID_CHARACTERS {
        return Err(ScreenVisionReviewError::new(
            ScreenVisionReviewErrorCode::InvalidArgument,
        ));
    }
    Ok(())
}

fn review_display(evidence: &ReviewEvidence) -> MainScreenVisionReviewDisplayDto {
    MainScreenVisionReviewDisplayDto {
        scope: FULL_SELECTED_TARGET_SCOPE.to_string(),
        width: evidence.width,
        height: evidence.height,
        provider_kind: evidence.binding.provider_kind().as_str().to_string(),
        provider_host: evidence.provider_host.clone(),
        profile_display_name: evidence.profile.display_name.clone(),
        model_name: evidence.profile.model_name.clone(),
    }
}

fn review_dto(evidence: &ReviewEvidence) -> MainScreenVisionReviewDto {
    MainScreenVisionReviewDto {
        review_id: evidence.review_id.clone(),
        scope: FULL_SELECTED_TARGET_SCOPE.to_string(),
        width: evidence.width,
        height: evidence.height,
        provider_kind: evidence.binding.provider_kind().as_str().to_string(),
        provider_host: evidence.provider_host.clone(),
        profile_display_name: evidence.profile.display_name.clone(),
        model_name: evidence.profile.model_name.clone(),
    }
}

/// Process-local single-flight gate for the actual Vision network operation.
pub(crate) struct ScreenVisionDeliveryOperationGate {
    in_flight: Arc<AtomicBool>,
}

impl ScreenVisionDeliveryOperationGate {
    pub(crate) fn new() -> Self {
        Self {
            in_flight: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn try_enter(&self) -> Result<ScreenVisionDeliveryOperationPermit, ()> {
        self.in_flight
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| ScreenVisionDeliveryOperationPermit {
                in_flight: Arc::clone(&self.in_flight),
            })
            .map_err(|_| ())
    }

    pub(crate) fn is_busy(&self) -> bool {
        self.in_flight.load(Ordering::Acquire)
    }
}

pub(crate) struct ScreenVisionDeliveryOperationPermit {
    in_flight: Arc<AtomicBool>,
}

impl Drop for ScreenVisionDeliveryOperationPermit {
    fn drop(&mut self) {
        self.in_flight.store(false, Ordering::Release);
    }
}

#[tauri::command]
pub async fn prepare_main_screen_vision_review(
    app: tauri::AppHandle,
) -> Result<MainScreenVisionReviewDto, MainScreenVisionErrorDto> {
    let operation_permit = {
        let operation_gate = app.state::<ScreenCaptureOperationGate>();
        operation_gate.try_enter().map_err(|_| {
            MainScreenVisionError::new(MainScreenVisionErrorCode::CaptureUnavailable, true).dto()
        })?
    };

    tauri::async_runtime::spawn_blocking(move || {
        let storage = app.state::<StorageService>();
        let secrets = app.state::<WindowsCredentialSecretStore>();
        let session_gate = app.state::<ScreenPerceptionSessionGate>();
        let target_broker = app.state::<ScreenCaptureTargetBroker>();
        let candidate_broker = app.state::<ScreenVisionOutboundCandidateBroker>();
        let review_broker = app.state::<ScreenVisionReviewBroker>();
        prepare_main_screen_vision_review_service(
            storage.inner(),
            secrets.inner(),
            session_gate.inner(),
            target_broker.inner(),
            operation_permit,
            candidate_broker.inner(),
            review_broker.inner(),
        )
    })
    .await
    .map_err(|_| {
        MainScreenVisionError::new(MainScreenVisionErrorCode::CaptureUnavailable, true).dto()
    })?
    .map_err(MainScreenVisionError::dto)
}

fn prepare_main_screen_vision_review_service(
    storage: &StorageService,
    secrets: &WindowsCredentialSecretStore,
    session_gate: &ScreenPerceptionSessionGate,
    target_broker: &ScreenCaptureTargetBroker,
    operation_permit: ScreenCaptureOperationPermit,
    candidate_broker: &ScreenVisionOutboundCandidateBroker,
    review_broker: &ScreenVisionReviewBroker,
) -> Result<MainScreenVisionReviewDto, MainScreenVisionError> {
    review_broker
        .ensure_can_prepare()
        .map_err(map_review_error)?;

    #[cfg(windows)]
    let _com = super::screen_capture::ComGuard::acquire(super::screen_capture::ComMode::Mta)
        .map_err(|_| {
            MainScreenVisionError::new(MainScreenVisionErrorCode::CaptureUnavailable, true)
        })?;

    let life_id = storage
        .current_life_id()
        .map_err(|_| MainScreenVisionError::new(MainScreenVisionErrorCode::LifeUnavailable, true))?
        .ok_or_else(|| {
            MainScreenVisionError::new(MainScreenVisionErrorCode::LifeUnavailable, true)
        })?;

    let resolved = resolve_active_screen_vision_destination(storage).map_err(map_resolver_error)?;
    validate_screen_vision_profile(&resolved.profile).map_err(|_| {
        MainScreenVisionError::new(MainScreenVisionErrorCode::ProviderUnavailable, true)
    })?;
    OpenAiCompatibleProviderConfig::from_vision_profile(&resolved.profile).map_err(|_| {
        MainScreenVisionError::new(MainScreenVisionErrorCode::ProviderUnavailable, true)
    })?;

    let credential = SecretIdentifier::new(
        credential_purpose(ModelPurpose::Vision),
        resolved.profile.id.clone(),
    )
    .map_err(|_| {
        MainScreenVisionError::new(MainScreenVisionErrorCode::CredentialUnavailable, true)
    })?;
    if !secrets.has_secret(&credential).map_err(|_| {
        MainScreenVisionError::new(MainScreenVisionErrorCode::CredentialUnavailable, true)
    })? {
        return Err(MainScreenVisionError::new(
            MainScreenVisionErrorCode::CredentialUnavailable,
            true,
        ));
    }

    authorize_screen_perception(storage, session_gate, &life_id).map_err(|_| {
        MainScreenVisionError::new(MainScreenVisionErrorCode::LocalScreenUnavailable, true)
    })?;
    authorize_screen_vision_outbound(storage, &life_id).map_err(|_| {
        MainScreenVisionError::new(MainScreenVisionErrorCode::OutboundPolicyUnavailable, true)
    })?;
    let dimensions = target_broker
        .current_dimensions_for_life(session_gate, &life_id)
        .ok_or_else(|| {
            MainScreenVisionError::new(MainScreenVisionErrorCode::TargetUnavailable, true)
        })?;

    let request = ScreenVisionOutboundPreparationRequest {
        life_id: life_id.clone(),
        projection_request: ScreenVisionOutboundProjectionRequest::new(
            ScreenVisionOutboundRect::new(0, 0, dimensions.width, dimensions.height),
            Vec::new(),
        ),
    };
    let prepared = prepare_screen_vision_candidate_with_operation_permit(
        storage,
        session_gate,
        target_broker,
        operation_permit,
        candidate_broker,
        &request,
    )
    .map_err(map_preparation_error)?;

    let post_resolved = match resolve_active_screen_vision_destination(storage) {
        Ok(resolved) => resolved,
        Err(error) => {
            revoke_candidate_best_effort(candidate_broker, &prepared.candidate_id);
            return Err(map_resolver_error(error));
        }
    };
    if post_resolved.binding != resolved.binding || post_resolved.profile != resolved.profile {
        revoke_candidate_best_effort(candidate_broker, &prepared.candidate_id);
        return Err(MainScreenVisionError::new(
            MainScreenVisionErrorCode::ReviewStale,
            true,
        ));
    }

    let provider_host = safe_provider_host(&post_resolved.binding).ok_or_else(|| {
        revoke_candidate_best_effort(candidate_broker, &prepared.candidate_id);
        MainScreenVisionError::new(MainScreenVisionErrorCode::ProviderUnavailable, true)
    })?;
    match review_broker.install_ready(
        prepared.candidate_id.clone(),
        life_id,
        post_resolved,
        provider_host,
        prepared.width,
        prepared.height,
    ) {
        Ok(review) => Ok(review),
        Err(error) => {
            revoke_candidate_best_effort(candidate_broker, &prepared.candidate_id);
            Err(map_review_error(error))
        }
    }
}

#[tauri::command]
pub fn get_main_screen_vision_status(
    app: tauri::AppHandle,
) -> Result<MainScreenVisionStatusDto, MainScreenVisionErrorDto> {
    let delivery_gate = app.state::<ScreenVisionDeliveryOperationGate>();
    let review_broker = app.state::<ScreenVisionReviewBroker>();
    let snapshot = review_broker
        .status_snapshot()
        .map_err(map_review_error)
        .map_err(MainScreenVisionError::dto)?;
    let (status, review) = match snapshot {
        ScreenVisionReviewStatusSnapshot::Empty => (MainScreenVisionStatusKind::Idle, None),
        ScreenVisionReviewStatusSnapshot::Ready(evidence) => (
            if delivery_gate.is_busy() {
                MainScreenVisionStatusKind::DeliveryInProgress
            } else {
                MainScreenVisionStatusKind::ReviewReady
            },
            Some(review_display(&evidence)),
        ),
        ScreenVisionReviewStatusSnapshot::Committed(committed) => (
            if delivery_gate.is_busy() {
                MainScreenVisionStatusKind::DeliveryInProgress
            } else {
                MainScreenVisionStatusKind::AwaitingRetryDecision
            },
            Some(review_display(&committed.evidence)),
        ),
    };
    Ok(MainScreenVisionStatusDto { status, review })
}

#[tauri::command]
pub async fn execute_main_screen_vision_review(
    app: tauri::AppHandle,
    request: ExecuteMainScreenVisionReviewRequest,
) -> Result<MainScreenVisionAnalysisDto, MainScreenVisionErrorDto> {
    let delivery_permit = {
        let delivery_gate = app.state::<ScreenVisionDeliveryOperationGate>();
        delivery_gate.try_enter().map_err(|_| {
            MainScreenVisionError::new(MainScreenVisionErrorCode::DeliveryInProgress, true).dto()
        })?
    };
    let storage = app.state::<StorageService>();
    let secrets = app.state::<WindowsCredentialSecretStore>();
    let session_gate = app.state::<ScreenPerceptionSessionGate>();
    let candidate_broker = app.state::<ScreenVisionOutboundCandidateBroker>();
    let grant_broker = app.state::<ScreenVisionOutboundGrantBroker>();
    let review_broker = app.state::<ScreenVisionReviewBroker>();
    execute_main_screen_vision_review_service(
        storage.inner(),
        secrets.inner(),
        session_gate.inner(),
        candidate_broker.inner(),
        grant_broker.inner(),
        review_broker.inner(),
        delivery_permit,
        request,
    )
    .await
    .map_err(MainScreenVisionError::dto)
}

async fn execute_main_screen_vision_review_service(
    storage: &StorageService,
    secrets: &WindowsCredentialSecretStore,
    session_gate: &ScreenPerceptionSessionGate,
    candidate_broker: &ScreenVisionOutboundCandidateBroker,
    grant_broker: &ScreenVisionOutboundGrantBroker,
    review_broker: &ScreenVisionReviewBroker,
    _delivery_permit: ScreenVisionDeliveryOperationPermit,
    request: ExecuteMainScreenVisionReviewRequest,
) -> Result<MainScreenVisionAnalysisDto, MainScreenVisionError> {
    validate_id(&request.review_id)
        .map_err(|_| MainScreenVisionError::new(MainScreenVisionErrorCode::InvalidArgument, false))
        .and_then(|_| {
            validate_id(&request.confirmation_event_id).map_err(|_| {
                MainScreenVisionError::new(MainScreenVisionErrorCode::InvalidArgument, false)
            })
        })
        .and_then(|_| {
            validate_id(&request.delivery_id).map_err(|_| {
                MainScreenVisionError::new(MainScreenVisionErrorCode::InvalidArgument, false)
            })
        })?;

    let execution = review_broker
        .get_for_execution(
            &request.review_id,
            &request.confirmation_event_id,
            &request.delivery_id,
        )
        .map_err(map_review_error)?;
    let (evidence, grant_id, needs_commit) = match execution {
        ScreenVisionReviewExecution::Ready(evidence) => (evidence, None, true),
        ScreenVisionReviewExecution::Committed(committed) => {
            (committed.evidence, Some(committed.grant_id), false)
        }
    };

    if storage
        .current_life_id()
        .map_err(|_| MainScreenVisionError::new(MainScreenVisionErrorCode::LifeUnavailable, true))?
        != Some(evidence.life_id.clone())
    {
        return Err(MainScreenVisionError::new(
            MainScreenVisionErrorCode::LifeUnavailable,
            true,
        ));
    }

    let resolved = resolve_active_screen_vision_destination(storage).map_err(map_resolver_error)?;
    if resolved.binding != evidence.binding || resolved.profile != evidence.profile {
        return Err(MainScreenVisionError::new(
            MainScreenVisionErrorCode::ReviewStale,
            true,
        ));
    }

    // Acquire the C2 lease before D2/D3 work so no concurrent preparation can
    // replace the exact candidate in the gap between claim and encoding.
    let candidate = candidate_broker
        .get_exact(&evidence.candidate_id)
        .map_err(map_candidate_error)?;
    let lease = candidate_broker
        .acquire_exact_delivery_lease(
            &evidence.candidate_id,
            &candidate.life_id,
            &candidate.screen_session_fence,
            candidate.outbound_policy_revision,
            &request.delivery_id,
        )
        .map_err(map_candidate_lease_error)?;

    let grant_id = match grant_id {
        Some(grant_id) => grant_id,
        None => {
            let issued = grant_broker
                .issue_user_confirmed_screen_vision_grant(
                    &request.confirmation_event_id,
                    &evidence.candidate_id,
                    evidence.binding.clone(),
                    storage,
                    session_gate,
                    storage,
                    candidate_broker,
                )
                .map_err(map_grant_error)?;
            match issued {
                ScreenVisionOutboundGrantIssueOutcome::Issued(metadata)
                | ScreenVisionOutboundGrantIssueOutcome::Replayed(metadata) => metadata.grant_id,
            }
        }
    };

    let claim = claim_screen_vision_outbound_delivery(
        ScreenVisionOutboundDeliveryClaimRequest {
            grant_id: grant_id.clone(),
            delivery_id: request.delivery_id.clone(),
            candidate_id: evidence.candidate_id.clone(),
            destination_binding: evidence.binding.clone(),
        },
        storage,
        session_gate,
        storage,
        candidate_broker,
        grant_broker,
    )
    .map_err(map_claim_error);
    if claim.is_err() && needs_commit {
        let _ = grant_broker.revoke_ready_exact(&grant_id);
    }
    claim?;

    if needs_commit {
        review_broker
            .commit_exact(
                &request.review_id,
                &request.confirmation_event_id,
                &request.delivery_id,
                &grant_id,
            )
            .map_err(map_review_error)?;
    }

    let png = candidate_broker
        .with_exact_leased_projection(&lease, encode_projection_to_png)
        .map_err(map_candidate_error)?
        .map_err(|error| error)?;
    let image_base64 =
        Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(png.as_slice()));
    drop(png);

    let provider_config = OpenAiCompatibleProviderConfig::from_vision_profile(&resolved.profile)
        .map_err(map_provider_error)?;
    let provider_request = build_screen_vision_request(
        &resolved.profile,
        FIXED_SCREEN_VISION_USER_TEXT,
        image_base64.as_str(),
    )
    .map_err(map_provider_error)?;
    drop(image_base64);

    let review_id = request.review_id.clone();
    let confirmation_event_id = request.confirmation_event_id.clone();
    let delivery_id = request.delivery_id.clone();
    let final_grant_id = grant_id.clone();
    let final_candidate_id = evidence.candidate_id.clone();
    let final_life_id = candidate.life_id.clone();
    let final_fence = candidate.screen_session_fence.clone();
    let final_revision = candidate.outbound_policy_revision;
    let final_binding = evidence.binding.clone();
    let final_profile = evidence.profile.clone();
    let pre_send_guard = || {
        final_pre_send_guard(
            storage,
            session_gate,
            candidate_broker,
            grant_broker,
            review_broker,
            &lease,
            &review_id,
            &confirmation_event_id,
            &delivery_id,
            &final_grant_id,
            &final_candidate_id,
            &final_life_id,
            &final_fence,
            final_revision,
            &final_binding,
            &final_profile,
        )
    };

    let provider = OpenAiCompatibleProvider::new(secrets);
    let response = provider
        .execute_sensitive_with_guard(&provider_config, provider_request, pre_send_guard)
        .await;

    match response {
        Ok(response) => {
            settle_terminal_success(
                grant_broker,
                candidate_broker,
                review_broker,
                lease,
                &request,
                &grant_id,
                &evidence.candidate_id,
            );
            let analysis = parse_screen_vision_analysis(response.body()).map_err(|_| {
                MainScreenVisionError::new(
                    MainScreenVisionErrorCode::ResponseInvalidAfterSend,
                    true,
                )
            })?;
            Ok(MainScreenVisionAnalysisDto {
                summary: analysis.summary().to_string(),
                observations: analysis.observations().to_vec(),
                provider_display_name: resolved.profile.display_name,
                model_name: resolved.profile.model_name,
            })
        }
        Err(SensitiveProviderExecutionError::PreSendGuard(_)) => {
            drop(lease);
            Err(MainScreenVisionError::new(
                MainScreenVisionErrorCode::NotSent,
                true,
            ))
        }
        Err(SensitiveProviderExecutionError::Provider(error)) => {
            if error.status().is_some() {
                settle_terminal_provider_response(
                    grant_broker,
                    candidate_broker,
                    review_broker,
                    lease,
                    &request,
                    &grant_id,
                    &evidence.candidate_id,
                );
                return Err(MainScreenVisionError::new(
                    MainScreenVisionErrorCode::ProviderResponded,
                    true,
                ));
            }
            drop(lease);
            if error.disposition() == SendDisposition::PossiblySent {
                Err(MainScreenVisionError::new(
                    MainScreenVisionErrorCode::OutcomeUnknown,
                    true,
                ))
            } else {
                Err(MainScreenVisionError::new(
                    MainScreenVisionErrorCode::NotSent,
                    true,
                ))
            }
        }
    }
}

fn final_pre_send_guard(
    storage: &StorageService,
    session_gate: &ScreenPerceptionSessionGate,
    candidate_broker: &ScreenVisionOutboundCandidateBroker,
    grant_broker: &ScreenVisionOutboundGrantBroker,
    review_broker: &ScreenVisionReviewBroker,
    lease: &ScreenVisionOutboundCandidateDeliveryLease<'_>,
    review_id: &str,
    confirmation_event_id: &str,
    delivery_id: &str,
    grant_id: &str,
    candidate_id: &str,
    life_id: &str,
    screen_session_fence: &str,
    outbound_policy_revision: i64,
    reviewed_binding: &ScreenVisionOutboundDestinationBinding,
    reviewed_profile: &ModelProfile,
) -> Result<(), MainScreenVisionError> {
    review_broker
        .validate_committed_exact(review_id, confirmation_event_id, delivery_id, grant_id)
        .map_err(map_review_error)?;

    let resolved = resolve_active_screen_vision_destination(storage).map_err(map_resolver_error)?;
    if resolved.binding != *reviewed_binding || resolved.profile != *reviewed_profile {
        return Err(MainScreenVisionError::new(
            MainScreenVisionErrorCode::ReviewStale,
            true,
        ));
    }

    if storage
        .current_life_id()
        .map_err(|_| MainScreenVisionError::new(MainScreenVisionErrorCode::LifeUnavailable, true))?
        != Some(life_id.to_string())
    {
        return Err(MainScreenVisionError::new(
            MainScreenVisionErrorCode::LifeUnavailable,
            true,
        ));
    }
    authorize_screen_perception(storage, session_gate, life_id).map_err(|_| {
        MainScreenVisionError::new(MainScreenVisionErrorCode::LocalScreenUnavailable, true)
    })?;
    let fence = session_gate.life_fence_for(life_id).ok_or_else(|| {
        MainScreenVisionError::new(MainScreenVisionErrorCode::LocalScreenUnavailable, true)
    })?;
    if fence.to_string() != screen_session_fence {
        return Err(MainScreenVisionError::new(
            MainScreenVisionErrorCode::NotSent,
            true,
        ));
    }
    let policy = storage
        .find_screen_vision_outbound_policy(life_id)
        .map_err(|_| {
            MainScreenVisionError::new(MainScreenVisionErrorCode::OutboundPolicyUnavailable, true)
        })?
        .ok_or_else(|| {
            MainScreenVisionError::new(MainScreenVisionErrorCode::OutboundPolicyUnavailable, true)
        })?;
    validate_screen_vision_outbound_policy_state(&policy).map_err(|_| {
        MainScreenVisionError::new(MainScreenVisionErrorCode::OutboundPolicyUnavailable, true)
    })?;
    if !policy.is_screen_vision_outbound_enabled() || policy.revision != outbound_policy_revision {
        return Err(MainScreenVisionError::new(
            MainScreenVisionErrorCode::NotSent,
            true,
        ));
    }

    candidate_broker
        .validate_exact_candidate(
            candidate_id,
            life_id,
            screen_session_fence,
            outbound_policy_revision,
        )
        .map_err(map_candidate_error)?;
    candidate_broker
        .validate_exact_delivery_lease(
            lease,
            candidate_id,
            life_id,
            screen_session_fence,
            outbound_policy_revision,
            delivery_id,
        )
        .map_err(map_candidate_lease_error)?;
    grant_broker
        .validate_bound_exact(
            grant_id,
            delivery_id,
            candidate_id,
            life_id,
            screen_session_fence,
            outbound_policy_revision,
            reviewed_binding,
        )
        .map_err(map_grant_error)?;

    claim_screen_vision_outbound_delivery(
        ScreenVisionOutboundDeliveryClaimRequest {
            grant_id: grant_id.to_string(),
            delivery_id: delivery_id.to_string(),
            candidate_id: candidate_id.to_string(),
            destination_binding: reviewed_binding.clone(),
        },
        storage,
        session_gate,
        storage,
        candidate_broker,
        grant_broker,
    )
    .map_err(map_claim_error)?;
    Ok(())
}

fn settle_terminal_success(
    grant_broker: &ScreenVisionOutboundGrantBroker,
    candidate_broker: &ScreenVisionOutboundCandidateBroker,
    review_broker: &ScreenVisionReviewBroker,
    lease: ScreenVisionOutboundCandidateDeliveryLease<'_>,
    request: &ExecuteMainScreenVisionReviewRequest,
    grant_id: &str,
    candidate_id: &str,
) {
    let _ = grant_broker.retire_bound_after_success(grant_id, &request.delivery_id);
    drop(lease);
    revoke_candidate_best_effort(candidate_broker, candidate_id);
    let _ = review_broker.clear_committed_exact(
        &request.review_id,
        &request.confirmation_event_id,
        &request.delivery_id,
        grant_id,
    );
}

fn settle_terminal_provider_response(
    grant_broker: &ScreenVisionOutboundGrantBroker,
    candidate_broker: &ScreenVisionOutboundCandidateBroker,
    review_broker: &ScreenVisionReviewBroker,
    lease: ScreenVisionOutboundCandidateDeliveryLease<'_>,
    request: &ExecuteMainScreenVisionReviewRequest,
    grant_id: &str,
    candidate_id: &str,
) {
    let _ = grant_broker.retire_bound_after_provider_response(grant_id, &request.delivery_id);
    drop(lease);
    revoke_candidate_best_effort(candidate_broker, candidate_id);
    let _ = review_broker.clear_committed_exact(
        &request.review_id,
        &request.confirmation_event_id,
        &request.delivery_id,
        grant_id,
    );
}

#[tauri::command]
pub fn abandon_main_screen_vision_delivery(
    app: tauri::AppHandle,
    request: AbandonMainScreenVisionDeliveryRequest,
) -> Result<(), MainScreenVisionErrorDto> {
    let delivery_permit = {
        let delivery_gate = app.state::<ScreenVisionDeliveryOperationGate>();
        delivery_gate.try_enter().map_err(|_| {
            MainScreenVisionError::new(MainScreenVisionErrorCode::DeliveryInProgress, true).dto()
        })?
    };
    let review_broker = app.state::<ScreenVisionReviewBroker>();
    let grant_broker = app.state::<ScreenVisionOutboundGrantBroker>();
    let candidate_broker = app.state::<ScreenVisionOutboundCandidateBroker>();
    let result = abandon_main_screen_vision_delivery_service(
        review_broker.inner(),
        grant_broker.inner(),
        candidate_broker.inner(),
        delivery_permit,
        request,
    );
    result.map_err(MainScreenVisionError::dto)
}

fn abandon_main_screen_vision_delivery_service(
    review_broker: &ScreenVisionReviewBroker,
    grant_broker: &ScreenVisionOutboundGrantBroker,
    candidate_broker: &ScreenVisionOutboundCandidateBroker,
    _delivery_permit: ScreenVisionDeliveryOperationPermit,
    request: AbandonMainScreenVisionDeliveryRequest,
) -> Result<(), MainScreenVisionError> {
    validate_id(&request.review_id).map_err(|_| {
        MainScreenVisionError::new(MainScreenVisionErrorCode::InvalidArgument, false)
    })?;
    let execution = review_broker
        .get_committed_exact(&request.review_id)
        .map_err(|error| match error.code() {
            ScreenVisionReviewErrorCode::ReviewConflict
            | ScreenVisionReviewErrorCode::NoReview
            | ScreenVisionReviewErrorCode::ReviewExpired => {
                MainScreenVisionError::new(MainScreenVisionErrorCode::AbandonUnavailable, false)
            }
            _ => map_review_error(error),
        })?;
    let Some(committed) = execution else {
        return Err(MainScreenVisionError::new(
            MainScreenVisionErrorCode::AbandonUnavailable,
            false,
        ));
    };
    grant_broker
        .abandon_bound_exact(&committed.grant_id, &committed.delivery_id)
        .map_err(|_| {
            MainScreenVisionError::new(MainScreenVisionErrorCode::AbandonUnavailable, false)
        })?;
    revoke_candidate_best_effort(candidate_broker, &committed.evidence.candidate_id);
    review_broker
        .clear_committed_exact(
            &committed.evidence.review_id,
            &committed.confirmation_event_id,
            &committed.delivery_id,
            &committed.grant_id,
        )
        .map_err(map_review_error)?;
    Ok(())
}

struct ZeroizingPngWriter {
    bytes: Zeroizing<Vec<u8>>,
}

impl ZeroizingPngWriter {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(Vec::new()),
        }
    }
}

impl Write for ZeroizingPngWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode_projection_to_png(
    projection: &ScreenVisionOutboundProjection,
) -> Result<Zeroizing<Vec<u8>>, MainScreenVisionError> {
    let mut writer = ZeroizingPngWriter::new();
    {
        let mut encoder = png::Encoder::new(&mut writer, projection.width(), projection.height());
        encoder.set_color(png::ColorType::Rgb);
        encoder.set_depth(png::BitDepth::Eight);
        let mut png_writer = encoder.write_header().map_err(|_| {
            MainScreenVisionError::new(MainScreenVisionErrorCode::PngEncodingFailed, true)
        })?;
        png_writer
            .write_image_data(projection.as_bytes())
            .map_err(|_| {
                MainScreenVisionError::new(MainScreenVisionErrorCode::PngEncodingFailed, true)
            })?;
    }
    if writer.bytes.len() > MAX_SCREEN_VISION_PNG_BYTES {
        return Err(MainScreenVisionError::new(
            MainScreenVisionErrorCode::PngTooLarge,
            true,
        ));
    }
    Ok(writer.bytes)
}

fn safe_provider_host(binding: &ScreenVisionOutboundDestinationBinding) -> Option<String> {
    let url = reqwest::Url::parse(binding.base_url()).ok()?;
    url.host_str().map(str::to_string)
}

fn revoke_candidate_best_effort(
    candidate_broker: &ScreenVisionOutboundCandidateBroker,
    candidate_id: &str,
) {
    let _ = candidate_broker.revoke_exact(candidate_id);
}

fn map_review_error(error: ScreenVisionReviewError) -> MainScreenVisionError {
    match error.code() {
        ScreenVisionReviewErrorCode::InvalidArgument => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::InvalidArgument, false)
        }
        ScreenVisionReviewErrorCode::NoReview => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::ReviewUnavailable, true)
        }
        ScreenVisionReviewErrorCode::ReviewExpired => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::ReviewExpired, true)
        }
        ScreenVisionReviewErrorCode::ReviewInUse => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::ReviewInUse, true)
        }
        ScreenVisionReviewErrorCode::ReviewConflict => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::ReviewConflict, true)
        }
        ScreenVisionReviewErrorCode::SynchronizationUnavailable
        | ScreenVisionReviewErrorCode::RandomUnavailable => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::SynchronizationUnavailable, true)
        }
    }
}

fn map_resolver_error(error: ScreenVisionDestinationResolverError) -> MainScreenVisionError {
    match error.code() {
        ScreenVisionDestinationResolverErrorCode::ProviderUnavailable
        | ScreenVisionDestinationResolverErrorCode::ProfileNotFound
        | ScreenVisionDestinationResolverErrorCode::PurposeMismatch
        | ScreenVisionDestinationResolverErrorCode::UnsupportedProvider
        | ScreenVisionDestinationResolverErrorCode::InvalidDestination
        | ScreenVisionDestinationResolverErrorCode::DatabaseUnavailable => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::ProviderUnavailable, true)
        }
    }
}

fn map_preparation_error(error: ScreenVisionOutboundPreparationError) -> MainScreenVisionError {
    match error.code() {
        ScreenVisionOutboundPreparationErrorCode::InvalidArgument => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::InvalidArgument, false)
        }
        ScreenVisionOutboundPreparationErrorCode::OperationBusy => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::CaptureUnavailable, true)
        }
        ScreenVisionOutboundPreparationErrorCode::LocalScreenAuthorityUnavailable
        | ScreenVisionOutboundPreparationErrorCode::SessionFenceChanged => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::LocalScreenUnavailable, true)
        }
        ScreenVisionOutboundPreparationErrorCode::OutboundPolicyUnavailable
        | ScreenVisionOutboundPreparationErrorCode::OutboundPolicyChanged => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::OutboundPolicyUnavailable, true)
        }
        ScreenVisionOutboundPreparationErrorCode::CaptureFailed => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::CaptureUnavailable, true)
        }
        ScreenVisionOutboundPreparationErrorCode::ProjectionFailed => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::CaptureUnavailable, true)
        }
        ScreenVisionOutboundPreparationErrorCode::CandidateInstallFailed
        | ScreenVisionOutboundPreparationErrorCode::SynchronizationUnavailable => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::CandidateUnavailable, true)
        }
    }
}

fn map_candidate_error(error: ScreenVisionOutboundCandidateError) -> MainScreenVisionError {
    match error.code() {
        ScreenVisionOutboundCandidateErrorCode::CandidateExpired => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::NotSent, true)
        }
        ScreenVisionOutboundCandidateErrorCode::CandidateInUse => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::DeliveryLeaseUnavailable, true)
        }
        ScreenVisionOutboundCandidateErrorCode::SynchronizationUnavailable => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::SynchronizationUnavailable, true)
        }
        _ => MainScreenVisionError::new(MainScreenVisionErrorCode::CandidateUnavailable, true),
    }
}

fn map_candidate_lease_error(error: ScreenVisionOutboundCandidateError) -> MainScreenVisionError {
    match error.code() {
        ScreenVisionOutboundCandidateErrorCode::CandidateExpired => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::NotSent, true)
        }
        ScreenVisionOutboundCandidateErrorCode::SynchronizationUnavailable => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::SynchronizationUnavailable, true)
        }
        _ => MainScreenVisionError::new(MainScreenVisionErrorCode::DeliveryLeaseUnavailable, true),
    }
}

fn map_grant_error(error: ScreenVisionOutboundGrantError) -> MainScreenVisionError {
    match error.code() {
        ScreenVisionOutboundGrantErrorCode::DestinationMismatch => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::ReviewStale, true)
        }
        ScreenVisionOutboundGrantErrorCode::GrantExpired => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::ReviewExpired, true)
        }
        ScreenVisionOutboundGrantErrorCode::GrantConsumed
        | ScreenVisionOutboundGrantErrorCode::CandidateConsumed => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::DeliveryUnavailable, true)
        }
        ScreenVisionOutboundGrantErrorCode::GrantInUse
        | ScreenVisionOutboundGrantErrorCode::DeliveryConflict
        | ScreenVisionOutboundGrantErrorCode::ConfirmationEventConflict => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::ReviewConflict, true)
        }
        ScreenVisionOutboundGrantErrorCode::LocalScreenAuthorityUnavailable
        | ScreenVisionOutboundGrantErrorCode::SessionFenceMismatch
        | ScreenVisionOutboundGrantErrorCode::OutboundPolicyUnavailable
        | ScreenVisionOutboundGrantErrorCode::OutboundPolicyMismatch => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::LocalScreenUnavailable, true)
        }
        ScreenVisionOutboundGrantErrorCode::SynchronizationUnavailable
        | ScreenVisionOutboundGrantErrorCode::RandomUnavailable => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::SynchronizationUnavailable, true)
        }
        _ => MainScreenVisionError::new(MainScreenVisionErrorCode::DeliveryUnavailable, true),
    }
}

fn map_claim_error(error: ScreenVisionOutboundDeliveryClaimError) -> MainScreenVisionError {
    match error.code() {
        ScreenVisionOutboundDeliveryClaimErrorCode::GrantExpired => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::ReviewExpired, true)
        }
        ScreenVisionOutboundDeliveryClaimErrorCode::DestinationMismatch => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::ReviewStale, true)
        }
        ScreenVisionOutboundDeliveryClaimErrorCode::DeliveryConflict
        | ScreenVisionOutboundDeliveryClaimErrorCode::GrantInUse => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::ReviewConflict, true)
        }
        ScreenVisionOutboundDeliveryClaimErrorCode::LocalScreenAuthorityUnavailable
        | ScreenVisionOutboundDeliveryClaimErrorCode::SessionFenceMismatch
        | ScreenVisionOutboundDeliveryClaimErrorCode::OutboundPolicyUnavailable
        | ScreenVisionOutboundDeliveryClaimErrorCode::OutboundPolicyMismatch => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::LocalScreenUnavailable, true)
        }
        ScreenVisionOutboundDeliveryClaimErrorCode::SynchronizationUnavailable => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::SynchronizationUnavailable, true)
        }
        _ => MainScreenVisionError::new(MainScreenVisionErrorCode::DeliveryUnavailable, true),
    }
}

fn map_provider_error(error: ProviderError) -> MainScreenVisionError {
    match error.kind() {
        ProviderErrorKind::Credential(_) => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::CredentialUnavailable, true)
        }
        ProviderErrorKind::RequestTooLarge => {
            MainScreenVisionError::new(MainScreenVisionErrorCode::RequestTooLarge, true)
        }
        _ => MainScreenVisionError::new(MainScreenVisionErrorCode::NotSent, true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perception::screen_capture::{ScreenFrame, ScreenPixelFormat};
    use crate::perception::screen_vision_outbound_destination::ScreenVisionOutboundDestinationProviderKind;
    use crate::perception::screen_vision_outbound_projection::project_screen_frame;

    #[derive(Clone)]
    struct ManualReviewClock {
        now: Arc<Mutex<Instant>>,
    }

    impl ManualReviewClock {
        fn new() -> Self {
            Self {
                now: Arc::new(Mutex::new(Instant::now())),
            }
        }

        fn advance(&self, duration: Duration) {
            let mut now = self
                .now
                .lock()
                .expect("review clock should not be poisoned");
            *now = now.checked_add(duration).expect("test clock should fit");
        }
    }

    impl ReviewClock for ManualReviewClock {
        fn now(&self) -> Instant {
            *self
                .now
                .lock()
                .expect("review clock should not be poisoned")
        }
    }

    struct SequenceReviewIdSource {
        ids: Mutex<Vec<String>>,
    }

    impl SequenceReviewIdSource {
        fn new(ids: Vec<&str>) -> Self {
            Self {
                ids: Mutex::new(ids.into_iter().rev().map(str::to_string).collect()),
            }
        }
    }

    impl ReviewIdSource for SequenceReviewIdSource {
        fn generate(&self) -> Result<String, ScreenVisionReviewError> {
            self.ids
                .lock()
                .expect("review id source should not be poisoned")
                .pop()
                .ok_or_else(|| {
                    ScreenVisionReviewError::new(ScreenVisionReviewErrorCode::RandomUnavailable)
                })
        }
    }

    fn profile(id: &str, updated_at: &str) -> ModelProfile {
        ModelProfile {
            id: id.to_string(),
            purpose: ModelPurpose::Vision,
            provider_kind: crate::model::profile::ModelProviderKind::OpenaiCompatible,
            display_name: "Vision profile".to_string(),
            base_url: "https://vision.example.invalid/v1".to_string(),
            model_name: "vision-model".to_string(),
            temperature: Some(0.0),
            max_tokens: Some(256),
            embedding_dimension: None,
            created_at: "2026-08-31T00:00:00Z".to_string(),
            updated_at: updated_at.to_string(),
        }
    }

    fn resolved(profile: ModelProfile) -> ResolvedScreenVisionDestination {
        let binding = ScreenVisionOutboundDestinationBinding::new(
            profile.id.clone(),
            ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible,
            profile.base_url.clone(),
            profile.model_name.clone(),
            profile.updated_at.clone(),
        )
        .expect("test destination should be valid");
        ResolvedScreenVisionDestination { profile, binding }
    }

    fn review_broker(clock: ManualReviewClock, ids: Vec<&str>) -> ScreenVisionReviewBroker {
        ScreenVisionReviewBroker {
            state: Mutex::new(ReviewState::Empty),
            clock: Arc::new(clock),
            id_source: Arc::new(SequenceReviewIdSource::new(ids)),
        }
    }

    fn install_review(
        broker: &ScreenVisionReviewBroker,
        profile_id: &str,
        review_id: &str,
    ) -> MainScreenVisionReviewDto {
        let profile = profile(profile_id, "2026-08-31T00:00:00Z");
        broker
            .install_ready(
                format!("candidate-{review_id}"),
                "life-a".to_string(),
                resolved(profile),
                "vision.example.invalid".to_string(),
                1920,
                1080,
            )
            .expect("review should install")
    }

    fn projection() -> ScreenVisionOutboundProjection {
        let frame = ScreenFrame {
            width: 2,
            height: 1,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: vec![3, 2, 1, 255, 6, 5, 4, 255],
        };
        let request = ScreenVisionOutboundProjectionRequest::new(
            ScreenVisionOutboundRect::new(0, 0, 2, 1),
            Vec::new(),
        );
        project_screen_frame(&frame, &request).expect("test projection should succeed")
    }

    #[test]
    fn review_id_source_is_csprng_sized_and_hex_encoded() {
        let id = CsPrngReviewIdSource
            .generate()
            .expect("OS CSPRNG should be available");
        assert_eq!(id.len(), REVIEW_ID_HEX_LENGTH);
        assert!(id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }

    #[test]
    fn ready_review_ttl_is_monotonic_and_committed_review_does_not_auto_expire() {
        let clock = ManualReviewClock::new();
        let broker = review_broker(clock.clone(), vec!["review-ready", "review-committed"]);
        let ready = install_review(&broker, "profile-a", "review-ready");
        assert!(matches!(
            broker.status_snapshot().unwrap(),
            ScreenVisionReviewStatusSnapshot::Ready(_)
        ));
        clock.advance(SCREEN_VISION_REVIEW_TTL);
        assert!(matches!(
            broker.status_snapshot().unwrap(),
            ScreenVisionReviewStatusSnapshot::Empty
        ));

        let committed = install_review(&broker, "profile-a", "review-committed");
        broker
            .commit_exact(
                &committed.review_id,
                "confirmation-a",
                "delivery-a",
                "grant-a",
            )
            .unwrap();
        clock.advance(SCREEN_VISION_REVIEW_TTL + Duration::from_secs(1));
        assert!(matches!(
            broker.status_snapshot().unwrap(),
            ScreenVisionReviewStatusSnapshot::Committed(_)
        ));
        assert_eq!(ready.scope, FULL_SELECTED_TARGET_SCOPE);
    }

    #[test]
    fn replacing_review_invalidates_old_confirmation_and_response_is_safe_metadata_only() {
        let clock = ManualReviewClock::new();
        let broker = review_broker(clock, vec!["review-old", "review-new"]);
        let old = install_review(&broker, "profile-a", "review-old");
        let new = install_review(&broker, "profile-b", "review-new");

        assert!(matches!(
            broker.get_for_execution(&old.review_id, "confirmation-a", "delivery-a"),
            Err(error) if error.code() == ScreenVisionReviewErrorCode::ReviewConflict
        ));
        let json = serde_json::to_string(&new).expect("review metadata should serialize");
        assert!(json.contains("vision.example.invalid"));
        assert!(json.contains("vision-model"));
        for forbidden in [
            "candidateId",
            "credential",
            "authorization",
            "sessionFence",
            "policyRevision",
            "pixels",
            "base64",
        ] {
            assert!(!json.contains(forbidden), "metadata leaked {forbidden}");
        }
    }

    #[test]
    fn full_rgb8_projection_encodes_deterministic_metadata_free_png() {
        let first = encode_projection_to_png(&projection()).expect("PNG should encode");
        let second = encode_projection_to_png(&projection()).expect("PNG should encode");
        assert_eq!(first.as_slice(), second.as_slice());
        assert_eq!(&first[..8], b"\x89PNG\r\n\x1a\n");

        let ihdr_length = u32::from_be_bytes(first[8..12].try_into().unwrap());
        assert_eq!(ihdr_length, 13);
        assert_eq!(&first[12..16], b"IHDR");
        assert_eq!(u32::from_be_bytes(first[16..20].try_into().unwrap()), 2);
        assert_eq!(u32::from_be_bytes(first[20..24].try_into().unwrap()), 1);
        assert_eq!(first[24], 8);
        assert_eq!(first[25], 2, "PNG must remain RGB with no alpha");

        let mut offset = 8_usize;
        while offset + 12 <= first.len() {
            let length = u32::from_be_bytes(first[offset..offset + 4].try_into().unwrap()) as usize;
            let chunk_type = &first[offset + 4..offset + 8];
            assert!(!matches!(
                chunk_type,
                b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"pHYs"
            ));
            offset += 12 + length;
        }
        assert_eq!(offset, first.len());

        fn require_zeroizing(_: Zeroizing<Vec<u8>>) {}
        require_zeroizing(first);
    }
}
