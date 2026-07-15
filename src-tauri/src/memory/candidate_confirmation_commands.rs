//! Minimal Tauri IPC surface for governed candidate confirmation (D-5A).
//!
//! These commands are the *only* way the chat window drives the confirmation
//! coordinator. They deliberately expose the smallest possible contract: prepare a
//! candidate, confirm with an Approval Token, or cancel. All authorization,
//! idempotency, and sensitive-grant issuance live in the coordinator; this layer
//! only validates the calling window, resolves the current life, and maps domain
//! results to stable IPC shapes.

use serde::Serialize;
use serde_json::Value;
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

    /// The IPC request is structurally invalid (unknown fields, wrong types, missing fields).
    fn invalid_request(detail: &str) -> Self {
        Self {
            code: "CANDIDATE_CONFIRMATION_INVALID_REQUEST".into(),
            message: format!("Invalid request: {detail}"),
            requires_reprepare: None,
            retry_after_ms: None,
        }
    }
}

impl From<ConfirmationError> for ConfirmationCommandError {
    fn from(error: ConfirmationError) -> Self {
        let requires_reprepare = error.requires_reprepare().then_some(true);
        match error {
            ConfirmationError::NoCurrentLife => Self::no_current_life(),
            ConfirmationError::NotFound => Self {
                code: "CANDIDATE_CONFIRMATION_NOT_FOUND".into(),
                message: "The candidate is not available for confirmation.".into(),
                requires_reprepare,
                retry_after_ms: None,
            },
            ConfirmationError::TokenInvalid => Self {
                code: "CANDIDATE_CONFIRMATION_TOKEN_INVALID".into(),
                message: "The approval token is invalid.".into(),
                requires_reprepare,
                retry_after_ms: None,
            },
            ConfirmationError::TokenExpired => Self {
                code: "CANDIDATE_CONFIRMATION_TOKEN_EXPIRED".into(),
                message: "The approval token has expired. Prepare the confirmation again.".into(),
                requires_reprepare,
                retry_after_ms: None,
            },
            ConfirmationError::TokenCancelled => Self {
                code: "CANDIDATE_CONFIRMATION_TOKEN_CANCELLED".into(),
                message: "The approval token was cancelled. Prepare the confirmation again.".into(),
                requires_reprepare,
                retry_after_ms: None,
            },
            ConfirmationError::TokenConsumed => Self {
                code: "CANDIDATE_CONFIRMATION_TOKEN_CONSUMED".into(),
                message: "The approval token was already used. Prepare the confirmation again."
                    .into(),
                requires_reprepare,
                retry_after_ms: None,
            },
            ConfirmationError::TokenInFlight => Self {
                code: "CANDIDATE_CONFIRMATION_TOKEN_IN_FLIGHT".into(),
                message: "A confirmation for this token is already in progress.".into(),
                requires_reprepare,
                retry_after_ms: None,
            },
            ConfirmationError::ContextChanged => Self {
                code: "CANDIDATE_CONFIRMATION_CONTEXT_CHANGED".into(),
                message:
                    "The candidate changed since it was prepared. Prepare the confirmation again."
                        .into(),
                requires_reprepare,
                retry_after_ms: None,
            },
            ConfirmationError::RevisionConflict => Self {
                code: "CANDIDATE_MEMORY_REVISION_CONFLICT".into(),
                message: "The candidate memory changed after it was loaded. Refresh and try again."
                    .into(),
                requires_reprepare,
                retry_after_ms: None,
            },
            ConfirmationError::RequestConflict => Self {
                code: "CANDIDATE_MEMORY_REQUEST_CONFLICT".into(),
                message:
                    "The confirmation request id was already used for a different candidate memory."
                        .into(),
                requires_reprepare,
                retry_after_ms: None,
            },
            ConfirmationError::ProhibitedContent => Self {
                code: "CANDIDATE_MEMORY_PROHIBITED_CONTENT".into(),
                message: "The candidate content contains prohibited material.".into(),
                requires_reprepare,
                retry_after_ms: None,
            },
            ConfirmationError::SensitiveApprovalRequired => Self {
                code: "CANDIDATE_CONFIRMATION_APPROVAL_REQUIRED".into(),
                message: "Confirming this candidate requires explicit approval.".into(),
                requires_reprepare,
                retry_after_ms: None,
            },
            ConfirmationError::TokenGeneration => Self {
                code: "CANDIDATE_CONFIRMATION_INTERNAL_ERROR".into(),
                message: "Could not generate an approval token.".into(),
                requires_reprepare,
                retry_after_ms: None,
            },
            ConfirmationError::RegistryCapacity => Self {
                code: "CANDIDATE_CONFIRMATION_TEMPORARILY_UNAVAILABLE".into(),
                message: "Confirmation storage is temporarily at capacity. Try again shortly."
                    .into(),
                requires_reprepare,
                retry_after_ms: Some(250),
            },
            ConfirmationError::StorageUnavailable { retry_after_ms } => Self {
                code: "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE".into(),
                message: "Candidate confirmation storage is temporarily unavailable.".into(),
                requires_reprepare,
                retry_after_ms: Some(retry_after_ms),
            },
            ConfirmationError::InvalidRequest(detail) => Self {
                code: "CANDIDATE_CONFIRMATION_INVALID_REQUEST".into(),
                message: detail,
                requires_reprepare,
                retry_after_ms: None,
            },
            ConfirmationError::Internal => Self {
                code: "CANDIDATE_CONFIRMATION_INTERNAL_ERROR".into(),
                message: "The candidate confirmation could not be completed.".into(),
                requires_reprepare,
                retry_after_ms: None,
            },
        }
    }
}

// ── Request parsing ──────────────────────────────────────────────────

/// Allowed top-level field names for `prepare_candidate_confirmation`.
const PREPARE_FIELDS: &[&str] = &["candidateId"];
/// Allowed top-level field names for `confirm_candidate_memory`.
const CONFIRM_FIELDS: &[&str] = &["candidateId", "approvalToken"];
/// Validate that a JSON object contains only the allowed field names. Returns
/// `INVALID_REQUEST` if any unknown field is present.
fn reject_unknown_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), ConfirmationCommandError> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(ConfirmationCommandError::invalid_request(&format!(
                "unknown field: {key}"
            )));
        }
    }
    Ok(())
}

/// Parse the `candidateId` field from a JSON object. Returns `INVALID_REQUEST`
/// if missing or not a string.
fn parse_candidate_id(
    object: &serde_json::Map<String, Value>,
) -> Result<String, ConfirmationCommandError> {
    match object.get("candidateId") {
        Some(Value::String(id)) if !id.is_empty() => Ok(id.clone()),
        Some(Value::String(_)) => Err(ConfirmationCommandError::invalid_request(
            "candidateId must not be empty",
        )),
        Some(_) => Err(ConfirmationCommandError::invalid_request(
            "candidateId must be a string",
        )),
        None => Err(ConfirmationCommandError::invalid_request(
            "missing required field: candidateId",
        )),
    }
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

// ── Request parsing helpers ───────────────────────────────────────────

/// Parsed prepare request: just the candidate id.
#[derive(Debug)]
struct ParsedPrepareRequest {
    candidate_id: String,
}

/// Parsed token-bearing request (confirm or cancel): candidate id plus the raw
/// token value for further validation.
#[derive(Debug)]
struct ParsedTokenRequest {
    candidate_id: String,
    token_raw: Value,
}

/// Parse a prepare request from a raw JSON value. Validates unknown fields and
/// extracts the candidate id.
fn parse_prepare_request(value: &Value) -> Result<ParsedPrepareRequest, ConfirmationCommandError> {
    let object = match value {
        Value::Object(map) => map,
        _ => {
            return Err(ConfirmationCommandError::invalid_request(
                "request must be a JSON object",
            ))
        }
    };
    reject_unknown_fields(object, PREPARE_FIELDS)?;
    let candidate_id = parse_candidate_id(object)?;
    Ok(ParsedPrepareRequest { candidate_id })
}

/// Parse a token-bearing request (confirm or cancel) from a raw JSON value.
/// Validates unknown fields, extracts the candidate id, and checks for token
/// presence. Does NOT deserialize the token — call `deserialize_token` for that.
fn parse_token_request(value: &Value) -> Result<ParsedTokenRequest, ConfirmationCommandError> {
    let object = match value {
        Value::Object(map) => map,
        _ => {
            return Err(ConfirmationCommandError::invalid_request(
                "request must be a JSON object",
            ))
        }
    };
    reject_unknown_fields(object, CONFIRM_FIELDS)?;
    let candidate_id = parse_candidate_id(object)?;
    let token_raw = match object.get("approvalToken") {
        Some(v) if !v.is_null() => v.clone(),
        _ => return Err(ConfirmationCommandError::approval_required()),
    };
    Ok(ParsedTokenRequest {
        candidate_id,
        token_raw,
    })
}

/// Deserialize an `ApprovalToken` from a raw JSON value. Returns `TOKEN_INVALID`
/// if the token is malformed.
fn deserialize_token(raw: &Value) -> Result<ApprovalToken, ConfirmationCommandError> {
    serde_json::from_value(raw.clone())
        .map_err(|_| ConfirmationCommandError::from(ConfirmationError::TokenInvalid))
}

// ── Commands ──────────────────────────────────────────────────────────

/// Prepare a candidate for confirmation and return a preview plus Approval Token.
///
/// Accepts a raw JSON value so that structural validation errors (unknown fields,
/// missing candidateId, wrong types) produce stable `INVALID_REQUEST` IPC codes
/// instead of uncontrolled Tauri/Serde string errors.
#[tauri::command]
pub fn prepare_candidate_confirmation(
    window: WebviewWindow,
    storage: State<'_, StorageService>,
    coordinator: State<'_, CandidateConfirmationCoordinator>,
    request: Value,
) -> Result<PrepareConfirmationResponse, ConfirmationCommandError> {
    require_chat_window(&window)?;
    let parsed = parse_prepare_request(&request)?;
    let life_id = current_life_id(storage.inner())?;
    let prepared = coordinator
        .prepare(storage.inner(), &life_id, &parsed.candidate_id)
        .map_err(ConfirmationCommandError::from)?;
    Ok(PrepareConfirmationResponse::from_domain(prepared))
}

/// Confirm a candidate using its Approval Token, promoting it to a memory via D-4.
#[tauri::command]
pub fn confirm_candidate_memory(
    window: WebviewWindow,
    storage: State<'_, StorageService>,
    coordinator: State<'_, CandidateConfirmationCoordinator>,
    request: Value,
) -> Result<ConfirmCandidateMemoryResponse, ConfirmationCommandError> {
    require_chat_window(&window)?;
    let parsed = parse_token_request(&request)?;
    let token = deserialize_token(&parsed.token_raw)?;
    let life_id = current_life_id(storage.inner())?;
    let success = coordinator
        .confirm(storage.inner(), &life_id, &parsed.candidate_id, &token)
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
    request: Value,
) -> Result<CancelConfirmationResponse, ConfirmationCommandError> {
    require_chat_window(&window)?;
    let parsed = parse_token_request(&request)?;
    let token = deserialize_token(&parsed.token_raw)?;
    let life_id = current_life_id(storage.inner())?;
    let outcome = coordinator
        .cancel(&life_id, &parsed.candidate_id, &token)
        .map_err(ConfirmationCommandError::from)?;
    Ok(CancelConfirmationResponse::from_outcome(
        outcome,
        parsed.candidate_id,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepare_unknown_field_returns_invalid_request() {
        let value: Value =
            serde_json::from_str(r#"{"candidateId":"c1","lifeId":"life-b"}"#).unwrap();
        let err = parse_prepare_request(&value).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_INVALID_REQUEST");
        assert!(err.message.contains("unknown field"));
    }

    #[test]
    fn prepare_missing_candidate_id_returns_invalid_request() {
        let value: Value = serde_json::from_str(r#"{}"#).unwrap();
        let err = parse_prepare_request(&value).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_INVALID_REQUEST");
        assert!(err.message.contains("candidateId"));
    }

    #[test]
    fn prepare_wrong_candidate_id_type_returns_invalid_request() {
        let value: Value = serde_json::from_str(r#"{"candidateId":42}"#).unwrap();
        let err = parse_prepare_request(&value).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_INVALID_REQUEST");
    }

    #[test]
    fn confirm_unknown_field_returns_invalid_request() {
        let value: Value =
            serde_json::from_str(r#"{"candidateId":"c1","expectedRevision":3}"#).unwrap();
        let err = parse_token_request(&value).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_INVALID_REQUEST");
    }

    #[test]
    fn confirm_missing_candidate_id_returns_invalid_request() {
        let token = "a".repeat(64);
        let value: Value =
            serde_json::from_str(&format!(r#"{{"approvalToken":"{token}"}}"#)).unwrap();
        let err = parse_token_request(&value).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_INVALID_REQUEST");
    }

    #[test]
    fn confirm_missing_token_returns_approval_required() {
        let value: Value = serde_json::from_str(r#"{"candidateId":"c1"}"#).unwrap();
        let err = parse_token_request(&value).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_APPROVAL_REQUIRED");
    }

    #[test]
    fn confirm_malformed_token_returns_token_invalid() {
        let value: Value =
            serde_json::from_str(r#"{"candidateId":"c1","approvalToken":"not-hex"}"#).unwrap();
        let parsed = parse_token_request(&value).unwrap();
        let err = deserialize_token(&parsed.token_raw).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_TOKEN_INVALID");
    }

    #[test]
    fn confirm_accepts_a_well_formed_token() {
        let token = "a".repeat(64);
        let value: Value = serde_json::from_str(&format!(
            r#"{{"candidateId":"c1","approvalToken":"{token}"}}"#
        ))
        .unwrap();
        let parsed = parse_token_request(&value).unwrap();
        assert!(deserialize_token(&parsed.token_raw).is_ok());
    }

    #[test]
    fn cancel_unknown_field_returns_invalid_request() {
        let value: Value = serde_json::from_str(r#"{"candidateId":"c1","foo":true}"#).unwrap();
        let err = parse_token_request(&value).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_INVALID_REQUEST");
    }

    #[test]
    fn cancel_missing_token_returns_approval_required() {
        let value: Value = serde_json::from_str(r#"{"candidateId":"c1"}"#).unwrap();
        let err = parse_token_request(&value).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_APPROVAL_REQUIRED");
    }

    #[test]
    fn cancel_malformed_token_returns_token_invalid() {
        let value: Value =
            serde_json::from_str(r#"{"candidateId":"c1","approvalToken":"bad"}"#).unwrap();
        let parsed = parse_token_request(&value).unwrap();
        let err = deserialize_token(&parsed.token_raw).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_TOKEN_INVALID");
    }

    // ── HIGH 4: confirm/cancel field rejection tests ──────────────────

    #[test]
    fn confirm_rejects_life_id() {
        let value: Value = serde_json::from_str(
            r#"{"candidateId":"c1","lifeId":"life-b","approvalToken":"aabb"}"#,
        )
        .unwrap();
        let err = parse_token_request(&value).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_INVALID_REQUEST");
        assert!(err.message.contains("lifeId"));
    }

    #[test]
    fn confirm_rejects_expected_revision() {
        let value: Value = serde_json::from_str(
            r#"{"candidateId":"c1","expectedRevision":1,"approvalToken":"aabb"}"#,
        )
        .unwrap();
        let err = parse_token_request(&value).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_INVALID_REQUEST");
    }

    #[test]
    fn confirm_rejects_request_id() {
        let value: Value =
            serde_json::from_str(r#"{"candidateId":"c1","requestId":"r1","approvalToken":"aabb"}"#)
                .unwrap();
        let err = parse_token_request(&value).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_INVALID_REQUEST");
    }

    #[test]
    fn confirm_rejects_is_sensitive() {
        let value: Value = serde_json::from_str(
            r#"{"candidateId":"c1","isSensitive":true,"approvalToken":"aabb"}"#,
        )
        .unwrap();
        let err = parse_token_request(&value).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_INVALID_REQUEST");
    }

    #[test]
    fn confirm_rejects_sensitive_confirmed() {
        let value: Value = serde_json::from_str(
            r#"{"candidateId":"c1","sensitiveConfirmed":true,"approvalToken":"aabb"}"#,
        )
        .unwrap();
        let err = parse_token_request(&value).unwrap_err();
        assert_eq!(err.code, "CANDIDATE_CONFIRMATION_INVALID_REQUEST");
    }

    // ── HIGH 2 + 3: Error mapping tests ──────────────────────────────

    #[test]
    fn reprepare_errors_carry_the_flag() {
        for error in [
            ConfirmationError::TokenExpired,
            ConfirmationError::TokenConsumed,
            ConfirmationError::TokenCancelled,
            ConfirmationError::ContextChanged,
            ConfirmationError::TokenInvalid,
            ConfirmationError::RevisionConflict,
            ConfirmationError::RequestConflict,
            ConfirmationError::ProhibitedContent,
        ] {
            let mapped = ConfirmationCommandError::from(error);
            assert_eq!(mapped.requires_reprepare, Some(true), "{}", mapped.code);
        }
    }

    #[test]
    fn non_reprepare_errors_omit_the_flag() {
        for error in [
            ConfirmationError::TokenInFlight,
            ConfirmationError::RegistryCapacity,
            ConfirmationError::StorageUnavailable {
                retry_after_ms: 250,
            },
            ConfirmationError::SensitiveApprovalRequired,
        ] {
            let mapped = ConfirmationCommandError::from(error);
            assert_eq!(mapped.requires_reprepare, None, "{}", mapped.code);
        }
    }

    #[test]
    fn registry_capacity_maps_to_temporarily_unavailable() {
        let mapped = ConfirmationCommandError::from(ConfirmationError::RegistryCapacity);
        assert_eq!(
            mapped.code,
            "CANDIDATE_CONFIRMATION_TEMPORARILY_UNAVAILABLE"
        );
        assert_eq!(mapped.retry_after_ms, Some(250));
        assert_eq!(mapped.requires_reprepare, None);
    }

    #[test]
    fn d4_storage_failure_maps_to_storage_unavailable() {
        let mapped = ConfirmationCommandError::from(ConfirmationError::StorageUnavailable {
            retry_after_ms: 500,
        });
        assert_eq!(mapped.code, "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE");
        assert_eq!(mapped.retry_after_ms, Some(500));
        assert_eq!(mapped.requires_reprepare, None);
    }

    #[test]
    fn storage_unavailable_is_retryable_with_same_token() {
        let mapped = ConfirmationCommandError::from(ConfirmationError::StorageUnavailable {
            retry_after_ms: 250,
        });
        assert_eq!(mapped.requires_reprepare, None);
        assert!(mapped.retry_after_ms.is_some());
    }

    #[test]
    fn registry_capacity_failure_does_not_consume_existing_token() {
        let mapped = ConfirmationCommandError::from(ConfirmationError::RegistryCapacity);
        assert_eq!(mapped.requires_reprepare, None);
    }

    #[test]
    fn revision_conflict_preserves_dedicated_ipc_code() {
        let mapped = ConfirmationCommandError::from(ConfirmationError::RevisionConflict);
        assert_eq!(mapped.code, "CANDIDATE_MEMORY_REVISION_CONFLICT");
        assert_eq!(mapped.requires_reprepare, Some(true));
    }

    #[test]
    fn request_conflict_preserves_dedicated_ipc_code() {
        let mapped = ConfirmationCommandError::from(ConfirmationError::RequestConflict);
        assert_eq!(mapped.code, "CANDIDATE_MEMORY_REQUEST_CONFLICT");
        assert_eq!(mapped.requires_reprepare, Some(true));
    }

    #[test]
    fn prohibited_content_preserves_dedicated_ipc_code() {
        let mapped = ConfirmationCommandError::from(ConfirmationError::ProhibitedContent);
        assert_eq!(mapped.code, "CANDIDATE_MEMORY_PROHIBITED_CONTENT");
        assert_eq!(mapped.requires_reprepare, Some(true));
    }

    #[test]
    fn candidate_state_change_maps_to_context_changed() {
        let mapped = ConfirmationCommandError::from(ConfirmationError::ContextChanged);
        assert_eq!(mapped.code, "CANDIDATE_CONFIRMATION_CONTEXT_CHANGED");
        assert_eq!(mapped.requires_reprepare, Some(true));
    }

    #[test]
    fn sensitivity_change_maps_to_context_changed() {
        // Sensitivity flip is detected as a context change at the coordinator level.
        let mapped = ConfirmationCommandError::from(ConfirmationError::ContextChanged);
        assert_eq!(mapped.code, "CANDIDATE_CONFIRMATION_CONTEXT_CHANGED");
    }

    #[test]
    fn transient_errors_carry_retry_after() {
        // D-4 storage failure → STORAGE_UNAVAILABLE with retryAfterMs.
        let mapped = ConfirmationCommandError::from(ConfirmationError::StorageUnavailable {
            retry_after_ms: 250,
        });
        assert_eq!(mapped.retry_after_ms, Some(250));
        assert_eq!(mapped.code, "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE");
        // Registry capacity → TEMPORARILY_UNAVAILABLE with retryAfterMs.
        let capacity = ConfirmationCommandError::from(ConfirmationError::RegistryCapacity);
        assert_eq!(capacity.retry_after_ms, Some(250));
        assert_eq!(
            capacity.code,
            "CANDIDATE_CONFIRMATION_TEMPORARILY_UNAVAILABLE"
        );
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
