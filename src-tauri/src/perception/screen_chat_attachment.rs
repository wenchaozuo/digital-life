//! D24-C1 Chat attachment ownership bridge (process-local presentation state).
//!
//! This module owns the ONE App-managed [`ScreenContextChatAttachmentBroker`]:
//! a single-slot marker that links a validated `GrantPending` from the D24-A
//! [`ScreenContextHandoffBroker`] to an opaque Chat-facing attachment ID.
//!
//! Frozen contract:
//!
//! - exactly one state: `EMPTY` or `OFFERED { attachment_id, grant_id,
//!   life_id, session_fence }` — no history, no queue, no per-Life map, no
//!   multiple active attachments;
//! - the broker stores no observation text and no observation payload; the
//!   underlying handoff broker remains the actual grant authority;
//! - the attachment ID is an opaque CSPRNG locator (never a sequential
//!   counter, a timestamp, or an embedded Life/grant identity); it is a
//!   locator, not bearer authority;
//! - offering the exact same `grant_id + life_id + session_fence` again
//!   returns the existing attachment ID (idempotent); any different valid
//!   offer replaces the stale marker;
//! - Chat-facing commands never accept authoritative screen data: the status
//!   command re-reads the authoritative current Life, durable consent, and
//!   current session fence, then re-validates the underlying Pending Grant;
//! - every exact removal cancels the matching Pending Grant only — never a
//!   newer handoff, never the global broker `cancel()`.
//!
//! The module adds exactly two Chat-only commands and emits a
//! presentation-only refresh hint (`screen-context-attachment-changed`,
//! payload `{ version: 1 }`) to the Chat window after a Main offer or after
//! attachment invalidation.  Chat never treats that event as authority;
//! D24-C2 uses it only to trigger a backend status reread.

use std::sync::Mutex;

use serde::Serialize;
use tauri::{Emitter, State, WebviewWindow};

use super::screen_context::{
    generate_opaque_identity, ScreenContextError, ScreenContextErrorCode,
    ScreenContextHandoffBroker, ScreenContextSessionFence,
};
use super::screen_policy::{
    authorize_screen_perception, ScreenPerceptionErrorCode, ScreenPerceptionRepository,
    ScreenPerceptionSessionGate,
};
use super::CurrentLifeAuthority;
use crate::storage::StorageService;

/// The only window permitted to read or dismiss Chat screen attachments.
pub(crate) const CHAT_WINDOW_LABEL: &str = "chat";

/// Targeted presentation-only refresh hint emitted to the Chat window after
/// a Main offer or after attachment invalidation.
pub(crate) const CHAT_ATTACHMENT_CHANGED_EVENT: &str = "screen-context-attachment-changed";

/// Identity bound for attachment, grant, and Life arguments on this command
/// surface (matches the D24-A identity bound).
const MAX_ID_CHARS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenContextChatAttachmentErrorCode {
    InvalidArgument,
    AttachmentNotFound,
    SynchronizationUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenContextChatAttachmentError {
    pub(crate) code: ScreenContextChatAttachmentErrorCode,
    pub(crate) message: String,
}

impl ScreenContextChatAttachmentError {
    fn new(code: ScreenContextChatAttachmentErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(
            ScreenContextChatAttachmentErrorCode::InvalidArgument,
            message,
        )
    }

    fn attachment_not_found() -> Self {
        Self::new(
            ScreenContextChatAttachmentErrorCode::AttachmentNotFound,
            "The screen context attachment no longer exists.",
        )
    }

    fn synchronization_unavailable() -> Self {
        Self::new(
            ScreenContextChatAttachmentErrorCode::SynchronizationUnavailable,
            "The screen context attachment authority is temporarily unavailable.",
        )
    }
}

/// Immutable metadata returned by exact removals.  It carries only the opaque
/// locator plus the exact grant / Life / session-fence tuple; never any
/// observation content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OfferedChatAttachment {
    pub(crate) attachment_id: String,
    pub(crate) grant_id: String,
    pub(crate) life_id: String,
    pub(crate) session_fence: ScreenContextSessionFence,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ChatAttachmentState {
    Empty,
    Offered {
        attachment_id: String,
        grant_id: String,
        life_id: String,
        session_fence: ScreenContextSessionFence,
    },
}

/// The single canonical process-local Chat screen-attachment marker.
///
/// Every transition runs through one [`Mutex`].  A freshly constructed broker
/// is always `EMPTY`; no state survives reconstruction and nothing is
/// persisted.  The broker performs no capture, no OCR, no conversation
/// binding, and no Provider integration.
pub(crate) struct ScreenContextChatAttachmentBroker {
    state: Mutex<ChatAttachmentState>,
}

impl ScreenContextChatAttachmentBroker {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(ChatAttachmentState::Empty),
        }
    }

    /// Offers one validated Pending Grant into the single attachment slot.
    ///
    /// - If the exact same `grant_id + life_id + session_fence` tuple is
    ///   already OFFERED, returns the existing same `attachment_id`
    ///   (idempotent, never duplicates the offer).
    /// - Any different offer replaces the stale previous marker.
    ///
    /// The underlying [`ScreenContextHandoffBroker`] remains the actual grant
    /// authority; this broker stores no payload and grants no authority.
    pub(crate) fn offer(
        &self,
        grant_id: &str,
        life_id: &str,
        session_fence: ScreenContextSessionFence,
    ) -> Result<String, ScreenContextChatAttachmentError> {
        validate_id("grant identity", grant_id)?;
        validate_id("life identity", life_id)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ScreenContextChatAttachmentError::synchronization_unavailable())?;
        if let ChatAttachmentState::Offered {
            attachment_id,
            grant_id: offered_grant_id,
            life_id: offered_life_id,
            session_fence: offered_fence,
        } = &*state
        {
            if offered_grant_id == grant_id
                && offered_life_id == life_id
                && *offered_fence == session_fence
            {
                return Ok(attachment_id.clone());
            }
        }
        let attachment_id = generate_opaque_identity()
            .map_err(|_| ScreenContextChatAttachmentError::synchronization_unavailable())?;
        *state = ChatAttachmentState::Offered {
            attachment_id: attachment_id.clone(),
            grant_id: grant_id.to_string(),
            life_id: life_id.to_string(),
            session_fence,
        };
        Ok(attachment_id)
    }

    /// Read-only view of the current marker, if any.  A poisoned lock fails
    /// closed to `None`; presentation code re-reads all real authority
    /// elsewhere anyway.
    pub(crate) fn current(&self) -> Option<OfferedChatAttachment> {
        match &*self.state.lock().ok()? {
            ChatAttachmentState::Empty => None,
            ChatAttachmentState::Offered {
                attachment_id,
                grant_id,
                life_id,
                session_fence,
            } => Some(OfferedChatAttachment {
                attachment_id: attachment_id.clone(),
                grant_id: grant_id.clone(),
                life_id: life_id.clone(),
                session_fence: *session_fence,
            }),
        }
    }

    /// Read-only lookup of the exact current attachment ID.  A different or
    /// newer offer is treated as not found, and a poisoned lock fails closed
    /// without changing the marker.
    pub(crate) fn get_exact(
        &self,
        attachment_id: &str,
    ) -> Result<OfferedChatAttachment, ScreenContextChatAttachmentError> {
        validate_id("attachment identity", attachment_id)?;
        let state = self
            .state
            .lock()
            .map_err(|_| ScreenContextChatAttachmentError::synchronization_unavailable())?;
        match &*state {
            ChatAttachmentState::Offered {
                attachment_id: current_attachment_id,
                grant_id,
                life_id,
                session_fence,
            } if current_attachment_id == attachment_id => Ok(OfferedChatAttachment {
                attachment_id: current_attachment_id.clone(),
                grant_id: grant_id.clone(),
                life_id: life_id.clone(),
                session_fence: *session_fence,
            }),
            _ => Err(ScreenContextChatAttachmentError::attachment_not_found()),
        }
    }

    /// Exact-removes the current attachment whose ID matches exactly and
    /// returns its stored metadata.  A different/newer offer is never
    /// removed; an absent or replaced attachment fails with
    /// [`ScreenContextChatAttachmentErrorCode::AttachmentNotFound`].
    pub(crate) fn remove_exact(
        &self,
        attachment_id: &str,
    ) -> Result<OfferedChatAttachment, ScreenContextChatAttachmentError> {
        validate_id("attachment identity", attachment_id)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| ScreenContextChatAttachmentError::synchronization_unavailable())?;
        match &*state {
            ChatAttachmentState::Offered {
                attachment_id: current_attachment_id,
                ..
            } if current_attachment_id == attachment_id => {
                let ChatAttachmentState::Offered {
                    attachment_id,
                    grant_id,
                    life_id,
                    session_fence,
                } = std::mem::replace(&mut *state, ChatAttachmentState::Empty)
                else {
                    unreachable!("OFFERED state was validated while holding the mutex");
                };
                Ok(OfferedChatAttachment {
                    attachment_id,
                    grant_id,
                    life_id,
                    session_fence,
                })
            }
            _ => Err(ScreenContextChatAttachmentError::attachment_not_found()),
        }
    }
}

fn validate_id(name: &str, value: &str) -> Result<(), ScreenContextChatAttachmentError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_ID_CHARS {
        return Err(ScreenContextChatAttachmentError::invalid_argument(format!(
            "{name} must be between 1 and {MAX_ID_CHARS} characters after trimming."
        )));
    }
    Ok(())
}

/// Exact-cancels a stored Pending Grant, treating only an exact absence of that
/// Pending Grant as an idempotent success.  A Life mismatch is safe here
/// because the opaque grant identity proves that the supplied old
/// grant/Life tuple cannot be the current exact Pending Grant.  Synchronization
/// failure remains an error so callers can preserve their attachment marker.
pub(crate) fn cancel_exact_pending_grant_or_confirm_absent(
    handoff_broker: &ScreenContextHandoffBroker,
    attachment: &OfferedChatAttachment,
) -> Result<(), ScreenContextError> {
    match handoff_broker.cancel_pending_grant(&attachment.grant_id, &attachment.life_id) {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.code,
                ScreenContextErrorCode::NoCurrentContext | ScreenContextErrorCode::LifeMismatch
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// Exact-cancels the matching Pending Grant before removing its attachment
/// marker.  The optional test-only hook runs after cancellation and before
/// final exact removal so replacement races are tested at the real boundary.
fn cancel_and_remove_exact_attachment_with_after_cancel<AfterCancel>(
    handoff_broker: &ScreenContextHandoffBroker,
    attachment_broker: &ScreenContextChatAttachmentBroker,
    attachment_id: &str,
    after_cancel: AfterCancel,
) -> Result<(), ScreenContextChatAttachmentError>
where
    AfterCancel: FnOnce(),
{
    let attachment = attachment_broker.get_exact(attachment_id)?;
    cancel_exact_pending_grant_or_confirm_absent(handoff_broker, &attachment)
        .map_err(chat_handoff_attachment_error)?;
    after_cancel();
    attachment_broker
        .remove_exact(&attachment.attachment_id)
        .map(|_| ())
}

/// Exact-cancels the matching Pending Grant before removing its attachment
/// marker.  A synchronization failure leaves the marker in place for retry.
pub(crate) fn cancel_and_remove_exact_attachment(
    handoff_broker: &ScreenContextHandoffBroker,
    attachment_broker: &ScreenContextChatAttachmentBroker,
    attachment_id: &str,
) -> Result<(), ScreenContextChatAttachmentError> {
    cancel_and_remove_exact_attachment_with_after_cancel(
        handoff_broker,
        attachment_broker,
        attachment_id,
        || {},
    )
}

#[cfg(test)]
pub(crate) fn cancel_and_remove_exact_attachment_with_test_hook<AfterCancel>(
    handoff_broker: &ScreenContextHandoffBroker,
    attachment_broker: &ScreenContextChatAttachmentBroker,
    attachment_id: &str,
    after_cancel: AfterCancel,
) -> Result<(), ScreenContextChatAttachmentError>
where
    AfterCancel: FnOnce(),
{
    cancel_and_remove_exact_attachment_with_after_cancel(
        handoff_broker,
        attachment_broker,
        attachment_id,
        after_cancel,
    )
}

/// Removes the current attachment marker (if any) only after exact-cancelling
/// its stored Pending Grant.  Returns whether a marker was actually removed.
///
/// This is the only shared invalidation path: it is used after a successful
/// Observe/Candidate installation (the old grant was replaced, so any marker
/// pointing at it is stale) and by the Chat status read when the marker no
/// longer belongs to the current Life/fence or its grant is stale/expired.
/// If exact cancellation cannot be confirmed because synchronization is
/// unavailable, the marker remains retryable and the global broker `cancel()`
/// is never used.
pub(crate) fn clear_current_attachment_and_cancel_grant(
    handoff_broker: &ScreenContextHandoffBroker,
    attachment_broker: &ScreenContextChatAttachmentBroker,
) -> bool {
    let Some(attachment_id) = attachment_broker.current().map(|a| a.attachment_id) else {
        return false;
    };
    cancel_and_remove_exact_attachment(handoff_broker, attachment_broker, &attachment_id).is_ok()
}

/// Bounded Chat-facing status: only `available` plus the opaque
/// `attachmentId` when available.  No grantId, candidateId, OCR, capturedAt,
/// session fence, target, PID, HWND, or window details ever leave the
/// backend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChatScreenContextAttachmentStatusDto {
    pub(crate) available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) attachment_id: Option<String>,
}

impl ChatScreenContextAttachmentStatusDto {
    fn unavailable() -> Self {
        Self {
            available: false,
            attachment_id: None,
        }
    }

    fn available(attachment_id: String) -> Self {
        Self {
            available: true,
            attachment_id: Some(attachment_id),
        }
    }
}

/// Bounded result of a successful Main offer: only the opaque attachment ID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MainScreenContextAttachmentOfferDto {
    pub(crate) attachment_id: String,
}

/// Bounded Chat-facing command error.  Native details are never exposed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChatScreenContextAttachmentErrorDto {
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

impl ChatScreenContextAttachmentErrorDto {
    fn new(code: &str, message: &str, recoverable: bool) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
            recoverable,
        }
    }

    fn unauthorized_window() -> Self {
        Self::new(
            "SCREEN_CONTEXT_ATTACHMENT_UNAUTHORIZED_WINDOW",
            "Screen context attachments are only available from the chat window.",
            false,
        )
    }

    fn invalid_argument() -> Self {
        Self::new(
            "SCREEN_CONTEXT_ATTACHMENT_INVALID_ARGUMENT",
            "The screen context attachment request is invalid.",
            false,
        )
    }

    fn not_found() -> Self {
        Self::new(
            "SCREEN_CONTEXT_ATTACHMENT_NOT_FOUND",
            "The screen context attachment no longer exists.",
            true,
        )
    }

    fn broker_unavailable() -> Self {
        Self::new(
            "SCREEN_CONTEXT_ATTACHMENT_BROKER_UNAVAILABLE",
            "The screen context attachment authority is temporarily unavailable.",
            true,
        )
    }

    fn life_unavailable() -> Self {
        Self::new(
            "SCREEN_CONTEXT_LIFE_UNAVAILABLE",
            "The current Life could not be verified. Try again.",
            true,
        )
    }

    fn consent_unavailable() -> Self {
        Self::new(
            "SCREEN_CONTEXT_CONSENT_UNAVAILABLE",
            "Screen-perception consent could not be verified. Try again.",
            true,
        )
    }
}

fn chat_attachment_error_dto(
    error: ScreenContextChatAttachmentError,
) -> ChatScreenContextAttachmentErrorDto {
    match error.code {
        ScreenContextChatAttachmentErrorCode::InvalidArgument => {
            ChatScreenContextAttachmentErrorDto::invalid_argument()
        }
        ScreenContextChatAttachmentErrorCode::AttachmentNotFound => {
            ChatScreenContextAttachmentErrorDto::not_found()
        }
        ScreenContextChatAttachmentErrorCode::SynchronizationUnavailable => {
            ChatScreenContextAttachmentErrorDto::broker_unavailable()
        }
    }
}

fn chat_handoff_attachment_error(error: ScreenContextError) -> ScreenContextChatAttachmentError {
    match error.code {
        ScreenContextErrorCode::InvalidArgument => {
            ScreenContextChatAttachmentError::invalid_argument(
                "The screen context handoff request is invalid.",
            )
        }
        _ => ScreenContextChatAttachmentError::synchronization_unavailable(),
    }
}

/// Rejects any caller that is not the Chat window.  The label is assigned by
/// the Tauri capability configuration and cannot be spoofed by frontend code.
fn require_chat_window(window: &WebviewWindow) -> Result<(), ChatScreenContextAttachmentErrorDto> {
    if window.label() == CHAT_WINDOW_LABEL {
        Ok(())
    } else {
        Err(ChatScreenContextAttachmentErrorDto::unauthorized_window())
    }
}

/// Fixed/versioned presentation-only refresh hint.  It carries no IDs, no
/// Life, and no content; Chat must never treat it as authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct ChatScreenContextAttachmentRefreshEvent {
    pub(crate) version: u8,
}

/// Emits the Chat refresh hint after a successful Main offer or after
/// attachment invalidation.  Delivery is presentation-only: a failure is
/// ignored and never affects the committed offer/cleanup authority.
pub(crate) fn emit_chat_attachment_changed(app: &tauri::AppHandle) {
    let _ = app.emit_to(
        CHAT_WINDOW_LABEL,
        CHAT_ATTACHMENT_CHANGED_EVENT,
        ChatScreenContextAttachmentRefreshEvent { version: 1 },
    );
}

/// Chat-only status read.  The frontend supplies no authoritative screen
/// data: the backend re-reads the authoritative current Life, the durable
/// screen consent, and the current session fence, then inspects the current
/// attachment.
///
/// When the attachment does not belong to the current Life/fence or its
/// underlying grant is stale/expired, the marker is cleared and — where safe
/// — its stored stale Pending Grant is exact-cancelled.  Returns only
/// `available` and, when available, the opaque `attachmentId`.
pub(crate) fn get_pending_screen_context_attachment_service(
    current_life: &dyn CurrentLifeAuthority,
    repository: &dyn ScreenPerceptionRepository,
    session_gate: &ScreenPerceptionSessionGate,
    handoff_broker: &ScreenContextHandoffBroker,
    attachment_broker: &ScreenContextChatAttachmentBroker,
) -> Result<ChatScreenContextAttachmentStatusDto, ChatScreenContextAttachmentErrorDto> {
    let current_life_id = match current_life.current_life_id() {
        Ok(Some(life_id)) => life_id,
        Ok(None) => {
            // No current Life: any stored marker is stale by definition.
            clear_current_attachment_and_cancel_grant(handoff_broker, attachment_broker);
            return Ok(ChatScreenContextAttachmentStatusDto::unavailable());
        }
        Err(()) => return Err(ChatScreenContextAttachmentErrorDto::life_unavailable()),
    };

    match authorize_screen_perception(repository, session_gate, &current_life_id) {
        Ok(()) => {}
        Err(error) => match error.code {
            ScreenPerceptionErrorCode::InvalidArgument
            | ScreenPerceptionErrorCode::DatabaseUnavailable => {
                // Transient authority failure: fail closed without destroying
                // state; the next read re-evaluates.
                return Err(ChatScreenContextAttachmentErrorDto::consent_unavailable());
            }
            _ => {
                // Disabled consent, missing policy, or a session not armed
                // for this Life: the attachment must not be exposed; clear it.
                clear_current_attachment_and_cancel_grant(handoff_broker, attachment_broker);
                return Ok(ChatScreenContextAttachmentStatusDto::unavailable());
            }
        },
    }

    let Some(fence) = session_gate.life_fence_for(&current_life_id) else {
        // Authorization passed but the fence disappeared (race): fail closed.
        clear_current_attachment_and_cancel_grant(handoff_broker, attachment_broker);
        return Ok(ChatScreenContextAttachmentStatusDto::unavailable());
    };
    let Some(attachment) = attachment_broker.current() else {
        return Ok(ChatScreenContextAttachmentStatusDto::unavailable());
    };
    if attachment.life_id != current_life_id
        || attachment.session_fence != ScreenContextSessionFence(fence)
    {
        clear_current_attachment_and_cancel_grant(handoff_broker, attachment_broker);
        return Ok(ChatScreenContextAttachmentStatusDto::unavailable());
    }

    match handoff_broker.validate_pending_grant(
        &attachment.grant_id,
        &current_life_id,
        ScreenContextSessionFence(fence),
    ) {
        Ok(()) => Ok(ChatScreenContextAttachmentStatusDto::available(
            attachment.attachment_id,
        )),
        Err(_) => {
            // Underlying grant is stale or expired (expiry also clears the
            // handoff state to EMPTY).
            clear_current_attachment_and_cancel_grant(handoff_broker, attachment_broker);
            Ok(ChatScreenContextAttachmentStatusDto::unavailable())
        }
    }
}

/// Chat-only dismiss.  Exact-cancels the matching underlying Pending Grant
/// before removing the attachment marker.  There is no UI-only dismissal and
/// no global cancel; a newer unrelated offer is never removed.
pub(crate) fn dismiss_pending_screen_context_attachment_service(
    handoff_broker: &ScreenContextHandoffBroker,
    attachment_broker: &ScreenContextChatAttachmentBroker,
    attachment_id: &str,
) -> Result<(), ChatScreenContextAttachmentErrorDto> {
    cancel_and_remove_exact_attachment(handoff_broker, attachment_broker, attachment_id)
        .map_err(chat_attachment_error_dto)
}

/// Chat-only: reads the current attachment status through full backend
/// authority re-verification.
#[tauri::command]
pub fn get_pending_screen_context_attachment(
    window: WebviewWindow,
    storage: State<'_, StorageService>,
    session_gate: State<'_, ScreenPerceptionSessionGate>,
    handoff_broker: State<'_, ScreenContextHandoffBroker>,
    attachment_broker: State<'_, ScreenContextChatAttachmentBroker>,
) -> Result<ChatScreenContextAttachmentStatusDto, ChatScreenContextAttachmentErrorDto> {
    require_chat_window(&window)?;
    get_pending_screen_context_attachment_service(
        storage.inner(),
        storage.inner(),
        session_gate.inner(),
        handoff_broker.inner(),
        attachment_broker.inner(),
    )
}

/// Chat-only: dismisses the exact attachment and cancels its Pending Grant.
#[tauri::command]
pub fn dismiss_pending_screen_context_attachment(
    window: WebviewWindow,
    handoff_broker: State<'_, ScreenContextHandoffBroker>,
    attachment_broker: State<'_, ScreenContextChatAttachmentBroker>,
    attachment_id: String,
) -> Result<(), ChatScreenContextAttachmentErrorDto> {
    require_chat_window(&window)?;
    dismiss_pending_screen_context_attachment_service(
        handoff_broker.inner(),
        attachment_broker.inner(),
        &attachment_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perception::screen_context::ScreenContextCandidateInput;
    use crate::perception::screen_ocr::{ScreenObservation, ScreenObservationStatus};

    const LIFE_A: &str = "life-a";
    const LIFE_B: &str = "life-b";
    const FENCE_1: ScreenContextSessionFence = ScreenContextSessionFence(1);

    fn recognized() -> ScreenObservation {
        ScreenObservation {
            captured_at: "2026-08-30T00:00:00.000Z".to_string(),
            status: ScreenObservationStatus::Recognized,
            text: "attachment bridge text".to_string(),
            truncated: false,
        }
    }

    fn install_and_issue(
        handoff_broker: &ScreenContextHandoffBroker,
        life_id: &str,
        fence: ScreenContextSessionFence,
    ) -> String {
        let candidate_id = handoff_broker
            .install_candidate(ScreenContextCandidateInput {
                life_id: life_id.to_string(),
                session_fence: fence,
                observation: recognized(),
            })
            .expect("candidate installation should succeed");
        handoff_broker
            .issue_grant(&candidate_id, life_id, fence)
            .expect("grant issuance should succeed")
    }

    fn offer(
        attachment_broker: &ScreenContextChatAttachmentBroker,
        grant_id: &str,
        life_id: &str,
        fence: ScreenContextSessionFence,
    ) -> String {
        attachment_broker
            .offer(grant_id, life_id, fence)
            .expect("offer should succeed")
    }

    fn assert_broker_empty(attachment_broker: &ScreenContextChatAttachmentBroker) {
        assert_eq!(
            attachment_broker.current(),
            None,
            "the attachment broker must be EMPTY"
        );
    }

    #[test]
    fn fresh_broker_is_empty() {
        let attachment_broker = ScreenContextChatAttachmentBroker::new();
        assert_broker_empty(&attachment_broker);
        let handoff_broker = ScreenContextHandoffBroker::new();
        let grant_id = install_and_issue(&handoff_broker, LIFE_A, FENCE_1);
        let attachment_id = offer(&attachment_broker, &grant_id, LIFE_A, FENCE_1);
        assert!(!attachment_id.is_empty());
        let current = attachment_broker.current().expect("one offer must exist");
        assert_eq!(current.attachment_id, attachment_id);
        assert_eq!(current.grant_id, grant_id);
        assert_eq!(current.life_id, LIFE_A);
        assert_eq!(current.session_fence, FENCE_1);
    }

    #[test]
    fn one_offer_only_and_identical_offer_is_idempotent() {
        let attachment_broker = ScreenContextChatAttachmentBroker::new();
        let handoff_broker = ScreenContextHandoffBroker::new();
        let grant_id = install_and_issue(&handoff_broker, LIFE_A, FENCE_1);
        let first = offer(&attachment_broker, &grant_id, LIFE_A, FENCE_1);
        let second = offer(&attachment_broker, &grant_id, LIFE_A, FENCE_1);
        assert_eq!(
            first, second,
            "the exact same tuple must return the same attachment ID"
        );
        let current = attachment_broker.current().expect("exactly one offer");
        assert_eq!(current.attachment_id, first);
    }

    #[test]
    fn different_offer_replaces_the_stale_marker() {
        let attachment_broker = ScreenContextChatAttachmentBroker::new();
        let handoff_broker = ScreenContextHandoffBroker::new();
        let old_grant = install_and_issue(&handoff_broker, LIFE_A, FENCE_1);
        let old_attachment = offer(&attachment_broker, &old_grant, LIFE_A, FENCE_1);
        let new_grant = install_and_issue(&handoff_broker, LIFE_A, FENCE_1);
        let new_attachment = offer(&attachment_broker, &new_grant, LIFE_A, FENCE_1);
        assert_ne!(old_attachment, new_attachment);
        let current = attachment_broker
            .current()
            .expect("the new offer is current");
        assert_eq!(current.attachment_id, new_attachment);
        assert_eq!(current.grant_id, new_grant);
        // The old marker is gone: exact removal of it must fail.
        let error = attachment_broker
            .remove_exact(&old_attachment)
            .expect_err("the replaced attachment must no longer exist");
        assert_eq!(
            error.code,
            ScreenContextChatAttachmentErrorCode::AttachmentNotFound
        );
    }

    #[test]
    fn remove_exact_removes_only_the_matching_attachment() {
        let attachment_broker = ScreenContextChatAttachmentBroker::new();
        let handoff_broker = ScreenContextHandoffBroker::new();
        let grant_id = install_and_issue(&handoff_broker, LIFE_A, FENCE_1);
        let attachment_id = offer(&attachment_broker, &grant_id, LIFE_A, FENCE_1);

        let removed = attachment_broker
            .remove_exact("not-the-attachment")
            .expect_err("a wrong attachment ID must not remove the offer");
        assert_eq!(
            removed.code,
            ScreenContextChatAttachmentErrorCode::AttachmentNotFound
        );
        let current = attachment_broker.current().expect("the offer must survive");
        assert_eq!(current.attachment_id, attachment_id);

        let removed = attachment_broker
            .remove_exact(&attachment_id)
            .expect("the exact attachment ID must remove the offer");
        assert_eq!(removed.grant_id, grant_id);
        assert_eq!(removed.life_id, LIFE_A);
        assert_broker_empty(&attachment_broker);
        // A second removal of the same ID is bounded and idempotent-safe.
        let error = attachment_broker
            .remove_exact(&attachment_id)
            .expect_err("an absent attachment must fail bounded");
        assert_eq!(
            error.code,
            ScreenContextChatAttachmentErrorCode::AttachmentNotFound
        );
    }

    #[test]
    fn get_exact_is_read_only_and_rejects_a_replaced_attachment() {
        let attachment_broker = ScreenContextChatAttachmentBroker::new();
        let handoff_broker = ScreenContextHandoffBroker::new();
        let old_grant = install_and_issue(&handoff_broker, LIFE_A, FENCE_1);
        let old_attachment = offer(&attachment_broker, &old_grant, LIFE_A, FENCE_1);

        let metadata = attachment_broker
            .get_exact(&old_attachment)
            .expect("the exact marker must be readable");
        assert_eq!(metadata.attachment_id, old_attachment);
        assert_eq!(metadata.grant_id, old_grant);
        assert!(attachment_broker.current().is_some());

        let new_grant = install_and_issue(&handoff_broker, LIFE_A, FENCE_1);
        let new_attachment = offer(&attachment_broker, &new_grant, LIFE_A, FENCE_1);
        let error = attachment_broker
            .get_exact(&old_attachment)
            .expect_err("a replaced marker must not be returned by exact read");
        assert_eq!(
            error.code,
            ScreenContextChatAttachmentErrorCode::AttachmentNotFound
        );
        assert_eq!(
            attachment_broker
                .current()
                .expect("the newer marker must remain")
                .attachment_id,
            new_attachment
        );
    }

    #[test]
    fn attachments_are_opaque_high_entropy_and_distinct() {
        let attachment_broker = ScreenContextChatAttachmentBroker::new();
        let handoff_broker = ScreenContextHandoffBroker::new();
        let mut ids = std::collections::HashSet::new();
        for _ in 0..64 {
            let grant_id = install_and_issue(&handoff_broker, LIFE_A, FENCE_1);
            let attachment_id = offer(&attachment_broker, &grant_id, LIFE_A, FENCE_1);
            ids.insert(attachment_id);
        }
        assert_eq!(ids.len(), 64, "attachment IDs must not repeat");
        for identity in &ids {
            assert_eq!(identity.len(), 32, "attachment IDs must be opaque hex");
            assert!(identity.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn empty_arguments_are_rejected() {
        let attachment_broker = ScreenContextChatAttachmentBroker::new();
        let error = attachment_broker
            .offer("  ", LIFE_A, FENCE_1)
            .expect_err("an empty grant identity must be rejected");
        assert_eq!(
            error.code,
            ScreenContextChatAttachmentErrorCode::InvalidArgument
        );
        let error = attachment_broker
            .offer("grant-1", " ", FENCE_1)
            .expect_err("an empty Life must be rejected");
        assert_eq!(
            error.code,
            ScreenContextChatAttachmentErrorCode::InvalidArgument
        );
        assert_broker_empty(&attachment_broker);
    }

    #[test]
    fn production_source_has_no_ocr_or_payload_fields() {
        let source = include_str!("screen_chat_attachment.rs");
        let (production_source, _) = source
            .split_once("#[cfg(test)]")
            .expect("the production/test module boundary must remain explicit");
        for token in [
            "ScreenContextPayload",
            "ScreenObservation",
            "Ocr",
            "captured_at",
            "truncated",
            "recognized",
        ] {
            assert!(
                !production_source.contains(token),
                "forbidden observation/OCR token appeared in the production source: {token}"
            );
        }
    }

    // ── Chat status service ──────────────────────────────────────────────

    /// Per-instance deterministic clock mirroring the D24-A test clock, so
    /// the TTL can be advanced without sleeping.  Owned by the broker under
    /// test; there is no process-global test clock.
    #[derive(Clone)]
    struct ManualClock {
        now: std::sync::Arc<std::sync::Mutex<std::time::Instant>>,
    }

    impl ManualClock {
        fn new() -> Self {
            Self {
                now: std::sync::Arc::new(std::sync::Mutex::new(std::time::Instant::now())),
            }
        }

        fn advance(&self, duration: std::time::Duration) {
            *self.now.lock().unwrap() += duration;
        }
    }

    impl super::super::screen_context::BrokerClock for ManualClock {
        fn now(&self) -> std::time::Instant {
            *self.now.lock().unwrap()
        }
    }

    #[derive(Default)]
    struct FakeRepository {
        policies: std::sync::Mutex<
            std::collections::HashMap<
                String,
                super::super::screen_policy::LifeScreenPerceptionPolicy,
            >,
        >,
    }

    impl FakeRepository {
        fn with_policy(enabled: bool) -> Self {
            let mut policies = std::collections::HashMap::new();
            policies.insert(
                LIFE_A.to_string(),
                super::super::screen_policy::LifeScreenPerceptionPolicy {
                    life_id: LIFE_A.to_string(),
                    screen_perception_enabled: enabled,
                    revision: 1,
                    created_at: "2026-08-30T00:00:00.000Z".to_string(),
                    updated_at: "2026-08-30T00:00:00.000Z".to_string(),
                    policy_version: 1,
                },
            );
            Self {
                policies: std::sync::Mutex::new(policies),
            }
        }
    }

    impl ScreenPerceptionRepository for FakeRepository {
        fn create_screen_perception_policy(
            &self,
            _request: super::super::screen_policy::LifeScreenPerceptionPolicyCreateRequest,
        ) -> Result<
            super::super::screen_policy::ScreenPerceptionCreateOutcome<
                super::super::screen_policy::LifeScreenPerceptionPolicy,
            >,
            super::super::screen_policy::ScreenPerceptionError,
        > {
            Err(super::super::screen_policy::ScreenPerceptionError::database())
        }

        fn find_screen_perception_policy(
            &self,
            life_id: &str,
        ) -> Result<
            Option<super::super::screen_policy::LifeScreenPerceptionPolicy>,
            super::super::screen_policy::ScreenPerceptionError,
        > {
            Ok(self.policies.lock().unwrap().get(life_id).cloned())
        }

        fn update_screen_perception_policy(
            &self,
            _request: super::super::screen_policy::LifeScreenPerceptionPolicyUpdateRequest,
        ) -> Result<
            super::super::screen_policy::LifeScreenPerceptionPolicyUpdateOutcome,
            super::super::screen_policy::ScreenPerceptionError,
        > {
            Err(super::super::screen_policy::ScreenPerceptionError::database())
        }

        fn find_screen_perception_policy_event(
            &self,
            _life_id: &str,
            _event_id: &str,
        ) -> Result<
            Option<super::super::screen_policy::LifeScreenPerceptionPolicyEvent>,
            super::super::screen_policy::ScreenPerceptionError,
        > {
            Ok(None)
        }
    }

    struct FakeCurrentLife {
        current: std::sync::Mutex<Result<Option<String>, ()>>,
    }

    impl FakeCurrentLife {
        fn for_life(life_id: &str) -> Self {
            Self {
                current: std::sync::Mutex::new(Ok(Some(life_id.to_string()))),
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

    struct StatusFixture {
        current_life: FakeCurrentLife,
        repository: FakeRepository,
        session_gate: ScreenPerceptionSessionGate,
        handoff_broker: ScreenContextHandoffBroker,
        attachment_broker: ScreenContextChatAttachmentBroker,
    }

    impl StatusFixture {
        fn armed() -> Self {
            let session_gate = ScreenPerceptionSessionGate::new();
            session_gate.arm_for_life(LIFE_A);
            Self {
                current_life: FakeCurrentLife::for_life(LIFE_A),
                repository: FakeRepository::with_policy(true),
                session_gate,
                handoff_broker: ScreenContextHandoffBroker::new(),
                attachment_broker: ScreenContextChatAttachmentBroker::new(),
            }
        }

        fn status(
            &self,
        ) -> Result<ChatScreenContextAttachmentStatusDto, ChatScreenContextAttachmentErrorDto>
        {
            get_pending_screen_context_attachment_service(
                &self.current_life,
                &self.repository,
                &self.session_gate,
                &self.handoff_broker,
                &self.attachment_broker,
            )
        }

        fn offer_current_grant(&self) -> String {
            let fence = self
                .session_gate
                .life_fence_for(LIFE_A)
                .expect("fixture gate is armed");
            let grant_id = install_and_issue(
                &self.handoff_broker,
                LIFE_A,
                ScreenContextSessionFence(fence),
            );
            offer(
                &self.attachment_broker,
                &grant_id,
                LIFE_A,
                ScreenContextSessionFence(fence),
            )
        }
    }

    #[test]
    fn status_is_unavailable_when_no_attachment_exists() {
        let fixture = StatusFixture::armed();
        assert_eq!(
            fixture.status().unwrap(),
            ChatScreenContextAttachmentStatusDto::unavailable()
        );
    }

    #[test]
    fn status_is_available_for_exact_life_fence_and_grant() {
        let fixture = StatusFixture::armed();
        let attachment_id = fixture.offer_current_grant();
        assert_eq!(
            fixture.status().unwrap(),
            ChatScreenContextAttachmentStatusDto::available(attachment_id)
        );
    }

    #[test]
    fn status_invalidates_stale_attachment_for_wrong_life() {
        let fixture = StatusFixture::armed();
        let _attachment_id = fixture.offer_current_grant();
        // A different Life becomes current and is itself authorized: the
        // marker belongs to another Life and must be cleared.
        fixture.current_life.set(Some(LIFE_B));
        fixture.session_gate.arm_for_life(LIFE_B);
        assert_eq!(
            fixture.status().unwrap(),
            ChatScreenContextAttachmentStatusDto::unavailable()
        );
        assert_broker_empty(&fixture.attachment_broker);
    }

    #[test]
    fn status_invalidates_stale_attachment_for_wrong_fence() {
        let fixture = StatusFixture::armed();
        let _attachment_id = fixture.offer_current_grant();
        // Disarm + re-arm for the same Life changes the session fence.
        fixture.session_gate.disarm();
        fixture.session_gate.arm_for_life(LIFE_A);
        assert_eq!(
            fixture.status().unwrap(),
            ChatScreenContextAttachmentStatusDto::unavailable()
        );
        assert_broker_empty(&fixture.attachment_broker);
    }

    #[test]
    fn status_clears_attachment_when_consent_is_disabled() {
        let mut fixture = StatusFixture::armed();
        let _attachment_id = fixture.offer_current_grant();
        fixture.repository = FakeRepository::with_policy(false);
        assert_eq!(
            fixture.status().unwrap(),
            ChatScreenContextAttachmentStatusDto::unavailable()
        );
        assert_broker_empty(&fixture.attachment_broker);
    }

    #[test]
    fn status_clears_attachment_when_session_is_disarmed() {
        let fixture = StatusFixture::armed();
        let _attachment_id = fixture.offer_current_grant();
        fixture.session_gate.disarm();
        assert_eq!(
            fixture.status().unwrap(),
            ChatScreenContextAttachmentStatusDto::unavailable()
        );
        assert_broker_empty(&fixture.attachment_broker);
    }

    #[test]
    fn status_clears_attachment_when_grant_expired() {
        // Deterministic clock so the TTL can be advanced without sleeping.
        let clock = ManualClock::new();
        let handoff_broker = ScreenContextHandoffBroker::with_clock(Box::new(clock.clone()));
        let session_gate = ScreenPerceptionSessionGate::new();
        session_gate.arm_for_life(LIFE_A);
        let fence = session_gate.life_fence_for(LIFE_A).unwrap();
        let grant_id = install_and_issue(&handoff_broker, LIFE_A, ScreenContextSessionFence(fence));
        let attachment_broker = ScreenContextChatAttachmentBroker::new();
        let attachment_id = offer(
            &attachment_broker,
            &grant_id,
            LIFE_A,
            ScreenContextSessionFence(fence),
        );

        clock.advance(super::super::screen_context::SCREEN_CONTEXT_HANDOFF_TTL);
        let fixture = StatusFixture {
            current_life: FakeCurrentLife::for_life(LIFE_A),
            repository: FakeRepository::with_policy(true),
            session_gate,
            handoff_broker,
            attachment_broker,
        };
        assert_eq!(
            fixture.status().unwrap(),
            ChatScreenContextAttachmentStatusDto::unavailable()
        );
        assert_broker_empty(&fixture.attachment_broker);
        let _ = attachment_id;
    }

    #[test]
    fn status_clears_attachment_when_grant_replaced_by_newer_candidate() {
        let fixture = StatusFixture::armed();
        let fence = fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("fixture gate is armed");
        let grant_id = install_and_issue(
            &fixture.handoff_broker,
            LIFE_A,
            ScreenContextSessionFence(fence),
        );
        offer(
            &fixture.attachment_broker,
            &grant_id,
            LIFE_A,
            ScreenContextSessionFence(fence),
        );
        // A newer Candidate installation replaces the grant: the marker is stale.
        let newer_candidate_id = fixture
            .handoff_broker
            .install_candidate(ScreenContextCandidateInput {
                life_id: LIFE_A.to_string(),
                session_fence: ScreenContextSessionFence(fence),
                observation: recognized(),
            })
            .expect("the newer candidate must install");
        assert_eq!(
            fixture.status().unwrap(),
            ChatScreenContextAttachmentStatusDto::unavailable()
        );
        assert_broker_empty(&fixture.attachment_broker);
        // The newer candidate itself survives the cleanup and can issue.
        let newer_grant = fixture
            .handoff_broker
            .issue_grant(
                &newer_candidate_id,
                LIFE_A,
                ScreenContextSessionFence(fence),
            )
            .expect("the newer candidate must remain usable");
        assert!(!newer_grant.is_empty());
    }

    #[test]
    fn status_fails_closed_when_life_authority_is_unavailable() {
        let fixture = StatusFixture::armed();
        let _attachment_id = fixture.offer_current_grant();
        fixture.current_life.unavailable();
        let error = fixture.status().unwrap_err();
        assert_eq!(error.code, "SCREEN_CONTEXT_LIFE_UNAVAILABLE");
        // Transient authority failure must not destroy the marker.
        assert!(fixture.attachment_broker.current().is_some());
    }

    #[test]
    fn status_fails_closed_when_consent_authority_is_unavailable() {
        // A transient repository failure must fail closed without destroying
        // the marker; the next read re-evaluates.
        struct FailingRepository;

        impl ScreenPerceptionRepository for FailingRepository {
            fn create_screen_perception_policy(
                &self,
                _r: super::super::screen_policy::LifeScreenPerceptionPolicyCreateRequest,
            ) -> Result<
                super::super::screen_policy::ScreenPerceptionCreateOutcome<
                    super::super::screen_policy::LifeScreenPerceptionPolicy,
                >,
                super::super::screen_policy::ScreenPerceptionError,
            > {
                Err(super::super::screen_policy::ScreenPerceptionError::database())
            }
            fn find_screen_perception_policy(
                &self,
                _life_id: &str,
            ) -> Result<
                Option<super::super::screen_policy::LifeScreenPerceptionPolicy>,
                super::super::screen_policy::ScreenPerceptionError,
            > {
                Err(super::super::screen_policy::ScreenPerceptionError::database())
            }
            fn update_screen_perception_policy(
                &self,
                _r: super::super::screen_policy::LifeScreenPerceptionPolicyUpdateRequest,
            ) -> Result<
                super::super::screen_policy::LifeScreenPerceptionPolicyUpdateOutcome,
                super::super::screen_policy::ScreenPerceptionError,
            > {
                Err(super::super::screen_policy::ScreenPerceptionError::database())
            }
            fn find_screen_perception_policy_event(
                &self,
                _life_id: &str,
                _event_id: &str,
            ) -> Result<
                Option<super::super::screen_policy::LifeScreenPerceptionPolicyEvent>,
                super::super::screen_policy::ScreenPerceptionError,
            > {
                Err(super::super::screen_policy::ScreenPerceptionError::database())
            }
        }

        let fixture = StatusFixture::armed();
        let _attachment_id = fixture.offer_current_grant();
        let error = get_pending_screen_context_attachment_service(
            &fixture.current_life,
            &FailingRepository,
            &fixture.session_gate,
            &fixture.handoff_broker,
            &fixture.attachment_broker,
        )
        .unwrap_err();
        assert_eq!(error.code, "SCREEN_CONTEXT_CONSENT_UNAVAILABLE");
        assert!(fixture.attachment_broker.current().is_some());
    }

    #[test]
    fn stale_cleanup_keeps_attachment_when_handoff_synchronization_fails() {
        let fixture = StatusFixture::armed();
        let attachment_id = fixture.offer_current_grant();
        fixture.handoff_broker.poison_for_test();

        assert!(!clear_current_attachment_and_cancel_grant(
            &fixture.handoff_broker,
            &fixture.attachment_broker,
        ));
        assert_eq!(
            fixture
                .attachment_broker
                .current()
                .expect("the marker must remain retryable")
                .attachment_id,
            attachment_id
        );
    }

    #[test]
    fn status_serializes_only_available_and_attachment_id() {
        let unavailable = ChatScreenContextAttachmentStatusDto::unavailable();
        assert_eq!(
            serde_json::to_value(unavailable).unwrap(),
            serde_json::json!({ "available": false })
        );
        let available =
            ChatScreenContextAttachmentStatusDto::available("opaque-attachment".to_string());
        let encoded = serde_json::to_string(&available).unwrap();
        assert_eq!(
            serde_json::to_value(&available).unwrap(),
            serde_json::json!({ "available": true, "attachmentId": "opaque-attachment" })
        );
        for forbidden in [
            "grant",
            "candidate",
            "ocr",
            "capturedAt",
            "fence",
            "target",
            "pid",
            "hwnd",
        ] {
            assert!(
                !encoded.to_lowercase().contains(forbidden),
                "forbidden field leaked into the Chat status payload: {forbidden}"
            );
        }
    }

    // ── Chat dismiss service ─────────────────────────────────────────────

    #[test]
    fn dismiss_removes_attachment_and_cancels_exact_pending_grant() {
        let fixture = StatusFixture::armed();
        let fence = fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("fixture gate is armed");
        let grant_id = install_and_issue(
            &fixture.handoff_broker,
            LIFE_A,
            ScreenContextSessionFence(fence),
        );
        let attachment_id = offer(
            &fixture.attachment_broker,
            &grant_id,
            LIFE_A,
            ScreenContextSessionFence(fence),
        );

        dismiss_pending_screen_context_attachment_service(
            &fixture.handoff_broker,
            &fixture.attachment_broker,
            &attachment_id,
        )
        .expect("dismiss must succeed");
        assert_broker_empty(&fixture.attachment_broker);
        // The exact Pending Grant is gone: it can no longer be validated or
        // claimed.
        let error = fixture
            .handoff_broker
            .validate_pending_grant(&grant_id, LIFE_A, ScreenContextSessionFence(fence))
            .expect_err("the dismissed grant must no longer be pending");
        assert_eq!(error.code, ScreenContextErrorCode::NoCurrentContext);
    }

    #[test]
    fn dismiss_returns_broker_error_and_keeps_attachment_on_cancel_failure() {
        let fixture = StatusFixture::armed();
        let attachment_id = fixture.offer_current_grant();
        fixture.handoff_broker.poison_for_test();

        let error = dismiss_pending_screen_context_attachment_service(
            &fixture.handoff_broker,
            &fixture.attachment_broker,
            &attachment_id,
        )
        .expect_err("dismiss must not report success when cancellation is unknown");
        assert_eq!(error.code, "SCREEN_CONTEXT_ATTACHMENT_BROKER_UNAVAILABLE");
        assert_eq!(
            fixture
                .attachment_broker
                .current()
                .expect("the failed dismiss must preserve the marker")
                .attachment_id,
            attachment_id
        );
    }

    #[test]
    fn dismiss_removes_marker_when_the_exact_grant_is_already_absent() {
        let fixture = StatusFixture::armed();
        let fence = fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("fixture gate is armed");
        let old_grant = install_and_issue(
            &fixture.handoff_broker,
            LIFE_A,
            ScreenContextSessionFence(fence),
        );
        let old_attachment = offer(
            &fixture.attachment_broker,
            &old_grant,
            LIFE_A,
            ScreenContextSessionFence(fence),
        );
        let newer_candidate = fixture
            .handoff_broker
            .install_candidate(ScreenContextCandidateInput {
                life_id: LIFE_A.to_string(),
                session_fence: ScreenContextSessionFence(fence),
                observation: recognized(),
            })
            .expect("the newer Candidate must replace the old grant");

        dismiss_pending_screen_context_attachment_service(
            &fixture.handoff_broker,
            &fixture.attachment_broker,
            &old_attachment,
        )
        .expect("an already-absent exact grant is idempotent for dismiss");
        assert_broker_empty(&fixture.attachment_broker);
        assert!(!fixture
            .handoff_broker
            .issue_grant(&newer_candidate, LIFE_A, ScreenContextSessionFence(fence),)
            .expect("the newer Candidate must survive cleanup")
            .is_empty());
    }

    #[test]
    fn exact_cleanup_does_not_remove_a_newer_marker_after_cancellation() {
        let fixture = StatusFixture::armed();
        let fence = fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("fixture gate is armed");
        let old_grant = install_and_issue(
            &fixture.handoff_broker,
            LIFE_A,
            ScreenContextSessionFence(fence),
        );
        let old_attachment = offer(
            &fixture.attachment_broker,
            &old_grant,
            LIFE_A,
            ScreenContextSessionFence(fence),
        );
        let mut newer_attachment = None;

        let error = cancel_and_remove_exact_attachment_with_test_hook(
            &fixture.handoff_broker,
            &fixture.attachment_broker,
            &old_attachment,
            || {
                let new_grant = install_and_issue(
                    &fixture.handoff_broker,
                    LIFE_A,
                    ScreenContextSessionFence(fence),
                );
                newer_attachment = Some(offer(
                    &fixture.attachment_broker,
                    &new_grant,
                    LIFE_A,
                    ScreenContextSessionFence(fence),
                ));
            },
        )
        .expect_err("old exact removal must lose to a newer marker");
        assert_eq!(
            error.code,
            ScreenContextChatAttachmentErrorCode::AttachmentNotFound
        );
        let newer_attachment = newer_attachment.expect("the hook must install a newer marker");
        assert_eq!(
            fixture
                .attachment_broker
                .current()
                .expect("the newer marker must survive")
                .attachment_id,
            newer_attachment
        );
        let newer_metadata = fixture
            .attachment_broker
            .get_exact(&newer_attachment)
            .expect("the newer marker must remain readable");
        fixture
            .handoff_broker
            .validate_pending_grant(
                &newer_metadata.grant_id,
                LIFE_A,
                ScreenContextSessionFence(fence),
            )
            .expect("the newer Pending Grant must remain untouched");
    }

    #[test]
    fn dismiss_cannot_remove_a_newer_unrelated_offer() {
        let fixture = StatusFixture::armed();
        let fence = fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("fixture gate is armed");
        let old_grant = install_and_issue(
            &fixture.handoff_broker,
            LIFE_A,
            ScreenContextSessionFence(fence),
        );
        let old_attachment = offer(
            &fixture.attachment_broker,
            &old_grant,
            LIFE_A,
            ScreenContextSessionFence(fence),
        );
        let new_grant = install_and_issue(
            &fixture.handoff_broker,
            LIFE_A,
            ScreenContextSessionFence(fence),
        );
        let new_attachment = offer(
            &fixture.attachment_broker,
            &new_grant,
            LIFE_A,
            ScreenContextSessionFence(fence),
        );

        let error = dismiss_pending_screen_context_attachment_service(
            &fixture.handoff_broker,
            &fixture.attachment_broker,
            &old_attachment,
        )
        .expect_err("dismissing a replaced attachment must fail bounded");
        assert_eq!(error.code, "SCREEN_CONTEXT_ATTACHMENT_NOT_FOUND");
        // The newer offer and its grant are untouched.
        let current = fixture
            .attachment_broker
            .current()
            .expect("newer offer survives");
        assert_eq!(current.attachment_id, new_attachment);
        fixture
            .handoff_broker
            .validate_pending_grant(&new_grant, LIFE_A, ScreenContextSessionFence(fence))
            .expect("the newer grant must remain pending");
        // And the replaced old grant must not have been cancelled through the
        // newer offer.
        let _ = old_grant;
    }

    #[test]
    fn dismiss_is_bounded_when_attachment_is_absent() {
        let fixture = StatusFixture::armed();
        let error = dismiss_pending_screen_context_attachment_service(
            &fixture.handoff_broker,
            &fixture.attachment_broker,
            "never-offered",
        )
        .expect_err("dismissing an absent attachment must fail bounded");
        assert_eq!(error.code, "SCREEN_CONTEXT_ATTACHMENT_NOT_FOUND");
    }

    #[test]
    fn dismiss_rejects_empty_attachment_id() {
        let fixture = StatusFixture::armed();
        let error = dismiss_pending_screen_context_attachment_service(
            &fixture.handoff_broker,
            &fixture.attachment_broker,
            "  ",
        )
        .expect_err("an empty attachment identity must be rejected");
        assert_eq!(error.code, "SCREEN_CONTEXT_ATTACHMENT_INVALID_ARGUMENT");
    }

    // ── Refresh hint ─────────────────────────────────────────────────────

    #[test]
    fn refresh_event_serializes_only_the_version() {
        assert_eq!(
            serde_json::to_value(ChatScreenContextAttachmentRefreshEvent { version: 1 }).unwrap(),
            serde_json::json!({ "version": 1 })
        );
        let encoded =
            serde_json::to_string(&ChatScreenContextAttachmentRefreshEvent { version: 1 }).unwrap();
        for forbidden in ["attachment", "grant", "life", "ocr", "id"] {
            assert!(
                !encoded.to_lowercase().contains(forbidden),
                "the refresh hint must contain no identifiers or content: {forbidden}"
            );
        }
    }

    #[test]
    fn refresh_event_constants_target_only_the_chat_window() {
        assert_eq!(CHAT_WINDOW_LABEL, "chat");
        assert_eq!(
            CHAT_ATTACHMENT_CHANGED_EVENT,
            "screen-context-attachment-changed"
        );
    }

    // ── ACL ──────────────────────────────────────────────────────────────

    #[test]
    fn c1_chat_and_main_acl_are_disjoint() {
        let main = include_str!("../../permissions/main-commands.toml");
        let chat = include_str!("../../permissions/chat-commands.toml");
        let settings = include_str!("../../permissions/settings-commands.toml");

        for command in [
            "offer_main_screen_context_to_chat",
            "revoke_main_pending_screen_context_grant",
            "revoke_main_screen_context_attachment",
        ] {
            assert!(
                main.contains(&format!("\"{command}\"")),
                "{command} must be Main-only"
            );
            assert!(
                !chat.contains(&format!("\"{command}\"")),
                "{command} must not be Chat"
            );
            assert!(
                !settings.contains(&format!("\"{command}\"")),
                "{command} must not be Settings"
            );
        }
        for command in [
            "get_pending_screen_context_attachment",
            "dismiss_pending_screen_context_attachment",
        ] {
            assert!(
                chat.contains(&format!("\"{command}\"")),
                "{command} must be Chat-only"
            );
            assert!(
                !main.contains(&format!("\"{command}\"")),
                "{command} must not be Main"
            );
            assert!(
                !settings.contains(&format!("\"{command}\"")),
                "{command} must not be Settings"
            );
        }
    }
}
