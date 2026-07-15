//! Minimal Tauri IPC surface for governed candidate confirmation (D-5A).
//!
//! These commands are the *only* way the chat window drives the confirmation
//! coordinator. They deliberately expose the smallest possible contract: prepare a
//! candidate, confirm with an Approval Token, or cancel. All authorization,
//! idempotency, and sensitive-grant issuance live in the coordinator; this layer
//! only validates the calling window, resolves the current life, and maps domain
//! results to stable IPC shapes.

use serde::{Deserialize, Serialize};
use tauri::{State, WebviewWindow};

use crate::memory::{
    candidate_service::{
        ApprovalToken, CancelOutcome, CandidateConfirmationCoordinator, ConfirmationError,
        ConfirmationOutcome, ConfirmationRequirement, ConfirmationSuccess, PreparedConfirmation,
    },
    MemoryKind,
};
use crate::storage::StorageService;

/// The only window permitted to drive candidate confirmation.
const CHAT_WINDOW_LABEL: &str = "chat";

// ── IPC error ─────────────────────────────────────────────────────────

/// Stable IPC error. `requiresReprepare` and `retryAfterMs` are the only optional
/// details surfaced; nothing about internal token state or candidate content leaks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmationCommandError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_reprepare: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
}

impl ConfirmationCommandError {
    fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
            requires_reprepare: None,
            retry_after_ms: None,
        }
    }

    /// The chat window is the only caller allowed to confirm memories.
    fn window_forbidden() -> Self {
        Self::new(
            "CANDIDATE_CONFIRMATION_UNAUTHORIZED_WINDOW",
            "Candidate confirmation is only available from the chat window.",
        )
    }

    /// No digital life is currently selected.
    fn no_current_life() -> Self {
        Self::new(
            "CANDIDATE_CONFIRMATION_NO_CURRENT_LIFE",
            "No current life is configured for candidate confirmation.",
        )
    }

    /// A required Approval Token was absent from the request.
    fn approval_required() -> Self {
        Self::new(
            "CANDIDATE_CONFIRMATION_APPROVAL_REQUIRED",
            "An approval token is required to confirm this candidate.",
        )
    }
}

impl From<ConfirmationError> for ConfirmationCommandError {
    fn from(error: ConfirmationError) -> Self {
        let requires_reprepare = error.requires_reprepare();
        let (code, message, retry_after_ms) = match error {
            ConfirmationError::NoCurrentLife => {
                return Self::no_current_life();
            }
            ConfirmationError::NotFound => (
                "CANDIDATE_CONFIRMATION_NOT_FOUND",
                "The candidate is not available for confirmation.",
                None,
            ),
            ConfirmationError::TokenInvalid => (
                "CANDIDATE_CONFIRMATION_TOKEN_INVALID",
                "The approval token is invalid.",
                None,
            ),
            ConfirmationError::TokenExpired => (
                "CANDIDATE_CONFIRMATION_TOKEN_EXPIRED",
                "The approval token has expired. Prepare the confirmation again.",
                None,
            ),
            ConfirmationError::TokenCancelled => (
                "CANDIDATE_CONFIRMATION_TOKEN_CANCELLED",
                "The approval token was cancelled. Prepare the confirmation again.",
                None,
            ),
            ConfirmationError::TokenConsumed => (
                "CANDIDATE_CONFIRMATION_TOKEN_CONSUMED",
                "The approval token was already used. Prepare the confirmation again.",
                None,
            ),
            ConfirmationError::TokenInFlight => (
                "CANDIDATE_CONFIRMATION_TOKEN_IN_FLIGHT",
                "A confirmation for this token is already in progress.",
                None,
            ),
            ConfirmationError::ContextChanged => (
                "CANDIDATE_CONFIRMATION_CONTEXT_CHANGED",
                "The candidate changed since it was prepared. Prepare the confirmation again.",
                None,
            ),
            ConfirmationError::SensitiveApprovalRequired => (
                "CANDIDATE_CONFIRMATION_APPROVAL_REQUIRED",
                "Confirming this candidate requires explicit approval.",
                None,
            ),
            ConfirmationError::TokenGeneration => (
                "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
                "Could not generate an approval token.",
                None,
            ),
            ConfirmationError::Busy => (
                "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE",
                "Confirmation storage is temporarily at capacity. Try again shortly.",
                Some(250),
            ),
            ConfirmationError::TemporarilyUnavailable { retry_after_ms } => (
                "CANDIDATE_CONFIRMATION_TEMPORARILY_UNAVAILABLE",
                "Candidate confirmation storage is temporarily unavailable.",
                Some(retry_after_ms),
            ),
            ConfirmationError::Internal => (
                "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
                "The candidate confirmation could not be completed.",
                None,
            ),
        };
        Self {
            code: code.to_string(),
            message: message.to_string(),
            requires_reprepare: requires_reprepare.then_some(true),
            retry_after_ms,
        }
    }
}

// ── Request / response DTOs ───────────────────────────────────────────

/// `prepare` input. `deny_unknown_fields` rejects any attempt to smuggle a
/// caller-supplied life id, revision, or request id — those are server-derived.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareConfirmationArgs {
    pub candidate_id: String,
}

/// `confirm` input. The Approval Token is optional at the wire level only so a
/// missing token maps to a precise `APPROVAL_REQUIRED` error instead of a generic
/// deserialization failure.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConfirmCandidateMemoryArgs {
    pub candidate_id: String,
    pub approval_token: Option<ApprovalToken>,
}

/// `cancel` input.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CancelConfirmationArgs {
    pub candidate_id: String,
    pub approval_token: Option<ApprovalToken>,
}

/// `prepare` output: the candidate preview plus the minted token. No `sourceId`,
/// evidence, or fingerprint is exposed — only a coarse `source` category.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareConfirmationResponse {
    pub candidate_id: String,
    pub expected_revision: i64,
    pub kind: MemoryKind,
    pub content: Option<String>,
    pub summary: Option<String>,
    pub is_sensitive: bool,
    pub source: String,
    pub confirmation_requirement: String,
    pub approval_token: ApprovalToken,
    pub expires_at: String,
}

/// `confirm` output: the outcome plus the identifiers the frontend needs.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmCandidateMemoryResponse {
    pub outcome: String,
    pub candidate_id: String,
    pub confirmed_memory_id: String,
}

/// `cancel` output: whether the confirmation was cancelled. `cancelled` is `true`
/// for a fresh cancellation and for idempotent re-cancellation; the frontend uses
/// this to tear down the confirmation UI.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CancelConfirmationResponse {
    pub candidate_id: String,
    pub cancelled: bool,
}

// ── Domain → response conversions ─────────────────────────────────────

impl PrepareConfirmationResponse {
    fn from_domain(prepared: PreparedConfirmation) -> Self {
        let confirmation_requirement = match prepared.requirement {
            ConfirmationRequirement::Standard => "standard",
            ConfirmationRequirement::ExplicitSensitiveApproval => "explicitSensitiveApproval",
        };
        Self {
            candidate_id: prepared.candidate_id,
            expected_revision: prepared.expected_revision,
            kind: prepared.kind,
            content: prepared.content,
            summary: prepared.summary,
            is_sensitive: prepared.is_sensitive,
            source: prepared.source.to_string(),
            confirmation_requirement: confirmation_requirement.to_string(),
            approval_token: prepared.approval_token,
            expires_at: prepared.expires_at,
        }
    }
}

impl From<ConfirmationSuccess> for ConfirmCandidateMemoryResponse {
    fn from(success: ConfirmationSuccess) -> Self {
        let outcome = match success.outcome {
            ConfirmationOutcome::Confirmed => "confirmed",
            ConfirmationOutcome::IdempotentReplay => "idempotentReplay",
        };
        Self {
            outcome: outcome.to_string(),
            candidate_id: success.candidate_id,
            confirmed_memory_id: success.confirmed_memory_id,
        }
    }
}

impl CancelConfirmationResponse {
    fn from_outcome(outcome: CancelOutcome, candidate_id: String) -> Self {
        let cancelled = matches!(
            outcome,
            CancelOutcome::Cancelled | CancelOutcome::AlreadyCancelled
        );
        Self {
            candidate_id,
            cancelled,
        }
    }
}

// ── Command guards ────────────────────────────────────────────────────

/// Reject any caller that is not the chat window. The label is assigned by the
/// Tauri capability configuration and cannot be spoofed by frontend code.
fn require_chat_window(window: &WebviewWindow) -> Result<(), ConfirmationCommandError> {
    if window.label() == CHAT_WINDOW_LABEL {
        Ok(())
    } else {
        Err(ConfirmationCommandError::window_forbidden())
    }
}

/// Resolve the current life id, mapping "no life" and storage errors to safe IPC
/// errors. The confirmation coordinator is always scoped to the active life.
fn current_life_id(storage: &StorageService) -> Result<String, ConfirmationCommandError> {
    match storage.get_current_life() {
        Ok(Some(life)) => Ok(life.id),
        Ok(None) => Err(ConfirmationCommandError::no_current_life()),
        Err(_) => Err(ConfirmationCommandError::new(
            "CANDIDATE_CONFIRMATION_TEMPORARILY_UNAVAILABLE",
            "The current life could not be resolved.",
        )),
    }
}

// ── Commands ──────────────────────────────────────────────────────────

/// Prepare a candidate for confirmation and return a preview plus Approval Token.
#[tauri::command]
pub fn prepare_candidate_confirmation(
    window: WebviewWindow,
    storage: State<'_, StorageService>,
    coordinator: State<'_, CandidateConfirmationCoordinator>,
    request: PrepareConfirmationArgs,
) -> Result<PrepareConfirmationResponse, ConfirmationCommandError> {
    require_chat_window(&window)?;
    let life_id = current_life_id(storage.inner())?;
    let prepared = coordinator
        .prepare(storage.inner(), &life_id, &request.candidate_id)
        .map_err(ConfirmationCommandError::from)?;
    Ok(PrepareConfirmationResponse::from_domain(prepared))
}

/// Confirm a candidate using its Approval Token, promoting it to a memory via D-4.
#[tauri::command]
pub fn confirm_candidate_memory(
    window: WebviewWindow,
    storage: State<'_, StorageService>,
    coordinator: State<'_, CandidateConfirmationCoordinator>,
    request: ConfirmCandidateMemoryArgs,
) -> Result<ConfirmCandidateMemoryResponse, ConfirmationCommandError> {
    require_chat_window(&window)?;
    let token = request
        .approval_token
        .ok_or_else(ConfirmationCommandError::approval_required)?;
    let life_id = current_life_id(storage.inner())?;
    let success = coordinator
        .confirm(storage.inner(), &life_id, &request.candidate_id, &token)
        .map_err(ConfirmationCommandError::from)?;
    Ok(ConfirmCandidateMemoryResponse::from(success))
}

/// Cancel a prepared confirmation, retiring the Approval Token. Never writes to the
/// database.
#[tauri::command]
pub fn cancel_candidate_confirmation_approval(
    window: WebviewWindow,
    storage: State<'_, StorageService>,
    coordinator: State<'_, CandidateConfirmationCoordinator>,
    request: CancelConfirmationArgs,
) -> Result<CancelConfirmationResponse, ConfirmationCommandError> {
    require_chat_window(&window)?;
    let token = request
        .approval_token
        .ok_or_else(ConfirmationCommandError::approval_required)?;
    let life_id = current_life_id(storage.inner())?;
    let outcome = coordinator
        .cancel(&life_id, &request.candidate_id, &token)
        .map_err(ConfirmationCommandError::from)?;
    Ok(CancelConfirmationResponse::from_outcome(
        outcome,
        request.candidate_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_args_reject_unknown_fields() {
        // A caller must not be able to smuggle a server-derived field.
        let sneaky = r#"{"candidateId":"c1","lifeId":"life-b"}"#;
        assert!(serde_json::from_str::<PrepareConfirmationArgs>(sneaky).is_err());
        let ok = r#"{"candidateId":"c1"}"#;
        assert!(serde_json::from_str::<PrepareConfirmationArgs>(ok).is_ok());
    }

    #[test]
    fn confirm_args_reject_unknown_fields_and_allow_missing_token() {
        let sneaky = r#"{"candidateId":"c1","expectedRevision":3}"#;
        assert!(serde_json::from_str::<ConfirmCandidateMemoryArgs>(sneaky).is_err());
        // A missing token deserializes to None so the command can return a precise
        // APPROVAL_REQUIRED rather than a deserialization failure.
        let no_token = r#"{"candidateId":"c1"}"#;
        let parsed: ConfirmCandidateMemoryArgs = serde_json::from_str(no_token).unwrap();
        assert!(parsed.approval_token.is_none());
    }

    #[test]
    fn confirm_args_accept_a_well_formed_token() {
        let token = "a".repeat(64);
        let json = format!(r#"{{"candidateId":"c1","approvalToken":"{token}"}}"#);
        let parsed: ConfirmCandidateMemoryArgs = serde_json::from_str(&json).unwrap();
        assert!(parsed.approval_token.is_some());
    }

    #[test]
    fn confirm_args_reject_a_malformed_token() {
        let json = r#"{"candidateId":"c1","approvalToken":"not-hex"}"#;
        assert!(serde_json::from_str::<ConfirmCandidateMemoryArgs>(json).is_err());
    }

    #[test]
    fn reprepare_errors_carry_the_flag() {
        for error in [
            ConfirmationError::TokenExpired,
            ConfirmationError::TokenConsumed,
            ConfirmationError::TokenCancelled,
            ConfirmationError::ContextChanged,
            ConfirmationError::TokenInvalid,
        ] {
            let mapped = ConfirmationCommandError::from(error);
            assert_eq!(mapped.requires_reprepare, Some(true), "{}", mapped.code);
        }
    }

    #[test]
    fn non_reprepare_errors_omit_the_flag() {
        let mapped = ConfirmationCommandError::from(ConfirmationError::TokenInFlight);
        assert_eq!(mapped.requires_reprepare, None);
        assert_eq!(mapped.code, "CANDIDATE_CONFIRMATION_TOKEN_IN_FLIGHT");
    }

    #[test]
    fn transient_errors_carry_retry_after() {
        let mapped = ConfirmationCommandError::from(ConfirmationError::TemporarilyUnavailable {
            retry_after_ms: 250,
        });
        assert_eq!(mapped.retry_after_ms, Some(250));
        let busy = ConfirmationCommandError::from(ConfirmationError::Busy);
        assert_eq!(busy.retry_after_ms, Some(250));
        assert_eq!(busy.code, "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE");
    }

    #[test]
    fn sensitive_approval_error_maps_to_stable_code() {
        let mapped = ConfirmationCommandError::from(ConfirmationError::SensitiveApprovalRequired);
        assert_eq!(mapped.code, "CANDIDATE_CONFIRMATION_APPROVAL_REQUIRED");
        assert_eq!(mapped.requires_reprepare, None);
    }

    #[test]
    fn token_generation_failure_is_reported_as_internal() {
        let mapped = ConfirmationCommandError::from(ConfirmationError::TokenGeneration);
        assert_eq!(mapped.code, "CANDIDATE_CONFIRMATION_INTERNAL_ERROR");
    }

    #[test]
    fn success_outcomes_serialize_to_expected_strings() {
        let confirmed = ConfirmCandidateMemoryResponse::from(ConfirmationSuccess {
            outcome: ConfirmationOutcome::Confirmed,
            candidate_id: "c1".into(),
            confirmed_memory_id: "m1".into(),
        });
        assert_eq!(confirmed.outcome, "confirmed");
        let replay = ConfirmCandidateMemoryResponse::from(ConfirmationSuccess {
            outcome: ConfirmationOutcome::IdempotentReplay,
            candidate_id: "c1".into(),
            confirmed_memory_id: "m1".into(),
        });
        assert_eq!(replay.outcome, "idempotentReplay");
    }

    #[test]
    fn cancel_outcomes_serialize_correctly() {
        let cancelled =
            CancelConfirmationResponse::from_outcome(CancelOutcome::Cancelled, "c1".into());
        assert!(cancelled.cancelled);
        assert_eq!(cancelled.candidate_id, "c1");

        let already =
            CancelConfirmationResponse::from_outcome(CancelOutcome::AlreadyCancelled, "c1".into());
        assert!(already.cancelled);

        let consumed =
            CancelConfirmationResponse::from_outcome(CancelOutcome::AlreadyConsumed, "c1".into());
        assert!(!consumed.cancelled);

        let expired =
            CancelConfirmationResponse::from_outcome(CancelOutcome::AlreadyExpired, "c1".into());
        assert!(!expired.cancelled);

        let invalidated = CancelConfirmationResponse::from_outcome(
            CancelOutcome::AlreadyInvalidated,
            "c1".into(),
        );
        assert!(!invalidated.cancelled);
    }

    #[test]
    fn cancel_response_serializes_with_camel_case() {
        let resp = CancelConfirmationResponse::from_outcome(CancelOutcome::Cancelled, "c1".into());
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["candidateId"], "c1");
        assert_eq!(json["cancelled"], true);
    }
}
