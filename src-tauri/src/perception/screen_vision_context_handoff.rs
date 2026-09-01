//! D27 process-local Cloud Vision semantic-context handoff authority.
//!
//! The broker owns one opaque Chat locator and a bounded semantic snapshot.
//! It never owns image bytes and never calls a provider.  A newer READY
//! semantic result may replace an unbound OFFERED handoff, while a BOUND
//! handoff is immutable until the exact governed conversation retires it.

use std::{
    sync::{Arc, Mutex},
    time::Instant,
};

use super::{
    perception_chat_offer_gate::{
        PerceptionChatOfferGate, PerceptionChatOfferGateErrorCode, PerceptionChatSourceKind,
    },
    screen_context::ScreenContextSessionFence,
    screen_vision_semantic_result::{
        validate_analysis, ScreenVisionSemanticAnalysis, ScreenVisionSemanticResult,
        ScreenVisionSemanticResultErrorCode, SCREEN_VISION_SEMANTIC_RESULT_TTL,
    },
};

const ATTACHMENT_ID_RANDOM_BYTES: usize = 16;
const ATTACHMENT_ID_HEX_CHARACTERS: usize = ATTACHMENT_ID_RANDOM_BYTES * 2;
const MAX_ID_CHARACTERS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionContextHandoffErrorCode {
    InvalidArgument,
    ResultUnavailable,
    ResultExpired,
    AttachmentNotFound,
    AttachmentInUse,
    LifeMismatch,
    SessionFenceMismatch,
    ConversationMismatch,
    SynchronizationUnavailable,
    RandomUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionContextHandoffError {
    pub(crate) code: ScreenVisionContextHandoffErrorCode,
}

impl ScreenVisionContextHandoffError {
    const fn new(code: ScreenVisionContextHandoffErrorCode) -> Self {
        Self { code }
    }
}

#[derive(Clone)]
struct VisionHandoffPayload {
    attachment_id: String,
    result_id: String,
    life_id: String,
    screen_session_fence: String,
    analysis: ScreenVisionSemanticAnalysis,
    source_created_at: Instant,
}

#[derive(Clone)]
struct BoundVisionHandoff {
    payload: VisionHandoffPayload,
    conversation_id: String,
    request_id: String,
}

enum VisionHandoffState {
    Empty,
    Offered(VisionHandoffPayload),
    Bound(BoundVisionHandoff),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionContextHandoffStatus {
    pub(crate) attachment_id: String,
    pub(crate) bound: bool,
}

/// The only Cloud Vision payload shape admitted to ConversationCognition.
/// IDs remain authority metadata and are never copied into PromptCompiler.
#[derive(Clone)]
pub(crate) struct ClaimedScreenVisionContext {
    pub(crate) attachment_id: String,
    pub(crate) result_id: String,
    pub(crate) life_id: String,
    pub(crate) screen_session_fence: String,
    pub(crate) summary: String,
    pub(crate) observations: Vec<String>,
}

impl std::fmt::Debug for ClaimedScreenVisionContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClaimedScreenVisionContext")
            .field("attachment_id", &self.attachment_id)
            .field("result_id", &self.result_id)
            .field("life_id", &self.life_id)
            .field("screen_session_fence", &self.screen_session_fence)
            .field("summary_len", &self.summary.chars().count())
            .field("observation_count", &self.observations.len())
            .finish()
    }
}

trait VisionHandoffClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct InstantVisionHandoffClock;

impl VisionHandoffClock for InstantVisionHandoffClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

trait VisionHandoffIdSource: Send + Sync {
    fn generate(&self) -> Result<String, ScreenVisionContextHandoffError>;
}

struct CsPrngVisionHandoffIdSource;

impl VisionHandoffIdSource for CsPrngVisionHandoffIdSource {
    fn generate(&self) -> Result<String, ScreenVisionContextHandoffError> {
        let mut bytes = [0_u8; ATTACHMENT_ID_RANDOM_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| {
            ScreenVisionContextHandoffError::new(
                ScreenVisionContextHandoffErrorCode::RandomUnavailable,
            )
        })?;
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut id = String::with_capacity(ATTACHMENT_ID_HEX_CHARACTERS);
        for byte in bytes {
            id.push(char::from(HEX[usize::from(byte >> 4)]));
            id.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(id)
    }
}

/// Single-slot Vision → Chat semantic handoff.  The shared gate prevents a
/// second OCR or Vision attachment from becoming active concurrently.
pub(crate) struct ScreenVisionContextHandoffBroker {
    state: Mutex<VisionHandoffState>,
    clock: Box<dyn VisionHandoffClock>,
    id_source: Box<dyn VisionHandoffIdSource>,
    offer_gate: Arc<PerceptionChatOfferGate>,
}

impl ScreenVisionContextHandoffBroker {
    pub(crate) fn new() -> Self {
        Self::new_with_offer_gate(Arc::new(PerceptionChatOfferGate::new()))
    }

    pub(crate) fn new_with_offer_gate(offer_gate: Arc<PerceptionChatOfferGate>) -> Self {
        Self {
            state: Mutex::new(VisionHandoffState::Empty),
            clock: Box::new(InstantVisionHandoffClock),
            id_source: Box::new(CsPrngVisionHandoffIdSource),
            offer_gate,
        }
    }

    #[cfg(test)]
    fn with_clock_and_id_source(
        clock: Box<dyn VisionHandoffClock>,
        id_source: Box<dyn VisionHandoffIdSource>,
        offer_gate: Arc<PerceptionChatOfferGate>,
    ) -> Self {
        Self {
            state: Mutex::new(VisionHandoffState::Empty),
            clock,
            id_source,
            offer_gate,
        }
    }

    pub(crate) fn offer_result(
        &self,
        result: ScreenVisionSemanticResult,
    ) -> Result<String, ScreenVisionContextHandoffError> {
        validate_id("Vision result identity", &result.result_id)?;
        validate_id("Life identity", &result.life_id)?;
        validate_id("screen session fence", &result.screen_session_fence)?;
        validate_analysis(&result.analysis).map_err(|error| map_result_error(error.code))?;
        if self
            .clock
            .now()
            .saturating_duration_since(result.created_at)
            >= SCREEN_VISION_SEMANTIC_RESULT_TTL
        {
            return Err(ScreenVisionContextHandoffError::new(
                ScreenVisionContextHandoffErrorCode::ResultExpired,
            ));
        }

        let mut state = self.lock_state()?;
        if matches!(&*state, VisionHandoffState::Bound(_)) {
            return Err(ScreenVisionContextHandoffError::new(
                ScreenVisionContextHandoffErrorCode::AttachmentInUse,
            ));
        }
        let previous_state = match &*state {
            VisionHandoffState::Offered(payload) => Some(payload.clone()),
            VisionHandoffState::Empty => None,
            VisionHandoffState::Bound(_) => unreachable!(),
        };
        if let Some(VisionHandoffPayload {
            attachment_id,
            result_id,
            life_id,
            screen_session_fence,
            analysis,
            source_created_at,
        }) = previous_state.as_ref()
        {
            if result_id == &result.result_id
                && life_id == &result.life_id
                && screen_session_fence == &result.screen_session_fence
                && analysis == &result.analysis
                && *source_created_at == result.created_at
            {
                return Ok(attachment_id.clone());
            }
        }
        let reservation = self
            .offer_gate
            .begin_offer(PerceptionChatSourceKind::CloudVision)
            .map_err(map_gate_error)?;
        let attachment_id = match self.id_source.generate() {
            Ok(id) => id,
            Err(error) => {
                let _ = self.offer_gate.abort_offer(&reservation);
                return Err(error);
            }
        };
        let payload = VisionHandoffPayload {
            attachment_id: attachment_id.clone(),
            result_id: result.result_id,
            life_id: result.life_id,
            screen_session_fence: result.screen_session_fence,
            analysis: result.analysis,
            source_created_at: result.created_at,
        };
        *state = VisionHandoffState::Offered(payload);
        if let Err(error) = self
            .offer_gate
            .commit_offer(&reservation, attachment_id.clone())
            .map_err(map_gate_error)
        {
            *state = previous_state.map_or(VisionHandoffState::Empty, VisionHandoffState::Offered);
            let _ = self.offer_gate.abort_offer(&reservation);
            return Err(error);
        }
        Ok(attachment_id)
    }

    /// Returns only the current opaque locator/status.  An OFFERED handoff is
    /// expired against its original semantic-result creation time.
    pub(crate) fn status(
        &self,
    ) -> Result<Option<ScreenVisionContextHandoffStatus>, ScreenVisionContextHandoffError> {
        let mut state = self.lock_state()?;
        if let VisionHandoffState::Offered(payload) = &*state {
            if self
                .clock
                .now()
                .saturating_duration_since(payload.source_created_at)
                >= SCREEN_VISION_SEMANTIC_RESULT_TTL
            {
                let attachment_id = payload.attachment_id.clone();
                let _ = self
                    .offer_gate
                    .clear_offered_exact(PerceptionChatSourceKind::CloudVision, &attachment_id)
                    .map_err(map_gate_error)?;
                *state = VisionHandoffState::Empty;
                return Ok(None);
            }
        }
        Ok(match &*state {
            VisionHandoffState::Empty => None,
            VisionHandoffState::Offered(payload) => Some(ScreenVisionContextHandoffStatus {
                attachment_id: payload.attachment_id.clone(),
                bound: false,
            }),
            VisionHandoffState::Bound(bound) => Some(ScreenVisionContextHandoffStatus {
                attachment_id: bound.payload.attachment_id.clone(),
                bound: true,
            }),
        })
    }

    /// Exact lookup used by the unified Chat resolver.  It returns bounded
    /// authority data only inside Rust and never through Chat status IPC.
    pub(crate) fn get_exact(
        &self,
        attachment_id: &str,
    ) -> Result<ScreenVisionContextHandoffStatus, ScreenVisionContextHandoffError> {
        validate_id("attachment identity", attachment_id)?;
        let mut state = self.lock_state()?;
        if let VisionHandoffState::Offered(payload) = &*state {
            if self
                .clock
                .now()
                .saturating_duration_since(payload.source_created_at)
                >= SCREEN_VISION_SEMANTIC_RESULT_TTL
            {
                let expired_id = payload.attachment_id.clone();
                let _ = self
                    .offer_gate
                    .clear_offered_exact(PerceptionChatSourceKind::CloudVision, &expired_id)
                    .map_err(map_gate_error)?;
                *state = VisionHandoffState::Empty;
                return Err(ScreenVisionContextHandoffError::new(
                    if expired_id == attachment_id {
                        ScreenVisionContextHandoffErrorCode::ResultExpired
                    } else {
                        ScreenVisionContextHandoffErrorCode::AttachmentNotFound
                    },
                ));
            }
        }
        match &*state {
            VisionHandoffState::Offered(payload) if payload.attachment_id == attachment_id => {
                Ok(ScreenVisionContextHandoffStatus {
                    attachment_id: payload.attachment_id.clone(),
                    bound: false,
                })
            }
            VisionHandoffState::Bound(bound) if bound.payload.attachment_id == attachment_id => {
                Ok(ScreenVisionContextHandoffStatus {
                    attachment_id: bound.payload.attachment_id.clone(),
                    bound: true,
                })
            }
            _ => Err(ScreenVisionContextHandoffError::new(
                ScreenVisionContextHandoffErrorCode::AttachmentNotFound,
            )),
        }
    }

    /// Revalidates only the source scope for Chat presentation.  Semantic
    /// text is not returned and the original source creation time remains the
    /// expiry anchor for OFFERED state.
    pub(crate) fn validate_for_presentation(
        &self,
        attachment_id: &str,
        life_id: &str,
        screen_session_fence: &str,
    ) -> Result<(), ScreenVisionContextHandoffError> {
        validate_id("attachment identity", attachment_id)?;
        validate_id("life identity", life_id)?;
        validate_id("screen session fence", screen_session_fence)?;
        let mut state = self.lock_state()?;
        if let VisionHandoffState::Offered(payload) = &*state {
            if self
                .clock
                .now()
                .saturating_duration_since(payload.source_created_at)
                >= SCREEN_VISION_SEMANTIC_RESULT_TTL
            {
                let expired_id = payload.attachment_id.clone();
                let _ = self
                    .offer_gate
                    .clear_offered_exact(PerceptionChatSourceKind::CloudVision, &expired_id)
                    .map_err(map_gate_error)?;
                *state = VisionHandoffState::Empty;
                return Err(ScreenVisionContextHandoffError::new(
                    ScreenVisionContextHandoffErrorCode::ResultExpired,
                ));
            }
        }
        match &*state {
            VisionHandoffState::Offered(payload) if payload.attachment_id == attachment_id => {
                validate_scope(payload, life_id, screen_session_fence)
            }
            VisionHandoffState::Bound(bound) if bound.payload.attachment_id == attachment_id => {
                validate_scope(&bound.payload, life_id, screen_session_fence)
            }
            _ => Err(ScreenVisionContextHandoffError::new(
                ScreenVisionContextHandoffErrorCode::AttachmentNotFound,
            )),
        }
    }

    /// Clears only an unbound Vision presentation marker.  A BOUND handoff is
    /// left intact for its exact conversation retry/retirement path.
    pub(crate) fn clear_offered_current(&self) -> Result<bool, ScreenVisionContextHandoffError> {
        let mut state = self.lock_state()?;
        let VisionHandoffState::Offered(payload) = &*state else {
            return Ok(false);
        };
        let attachment_id = payload.attachment_id.clone();
        self.offer_gate
            .clear_offered_exact(PerceptionChatSourceKind::CloudVision, &attachment_id)
            .map_err(map_gate_error)?;
        *state = VisionHandoffState::Empty;
        Ok(true)
    }

    /// Invalidates only the current Cloud Vision BOUND authority when backend
    /// evidence proves that its Life/session scope is stale.  `None` for
    /// either piece of scope is reserved for an explicit backend conclusion
    /// that no usable current scope exists (for example no current Life,
    /// consent revoked, or a disarmed session); callers must not use it for a
    /// transient authority read failure.
    ///
    /// The gate is cleared before the handoff state is changed.  If the exact
    /// gate marker cannot be cleared, this method returns an error and leaves
    /// the BOUND state intact so the two authorities cannot diverge.
    pub(crate) fn invalidate_bound_if_scope_stale(
        &self,
        current_life_id: Option<&str>,
        current_session_fence: Option<ScreenContextSessionFence>,
    ) -> Result<bool, ScreenVisionContextHandoffError> {
        if let Some(life_id) = current_life_id {
            validate_id("current life identity", life_id)?;
        }
        let mut state = self.lock_state()?;
        let (bound_life_id, bound_fence, attachment_id) = match &*state {
            VisionHandoffState::Bound(bound) => (
                bound.payload.life_id.clone(),
                bound.payload.screen_session_fence.clone(),
                bound.payload.attachment_id.clone(),
            ),
            VisionHandoffState::Empty | VisionHandoffState::Offered(_) => return Ok(false),
        };
        if current_life_id == Some(bound_life_id.as_str())
            && current_session_fence.is_some_and(|fence| fence.0.to_string() == bound_fence)
        {
            return Ok(false);
        }

        let cleared = self
            .offer_gate
            .clear_bound_exact(PerceptionChatSourceKind::CloudVision, &attachment_id)
            .map_err(map_gate_error)?;
        if !cleared {
            return Err(ScreenVisionContextHandoffError::new(
                ScreenVisionContextHandoffErrorCode::SynchronizationUnavailable,
            ));
        }
        *state = VisionHandoffState::Empty;
        Ok(true)
    }

    /// Claims an exact OFFERED locator or replays the exact BOUND request.
    /// Authority (current Life, D23 permission, and canonical fence) is
    /// supplied by the caller after it has been freshly re-read.
    pub(crate) fn claim_exact(
        &self,
        attachment_id: &str,
        life_id: &str,
        screen_session_fence: &str,
        conversation_id: &str,
        request_id: &str,
    ) -> Result<ClaimedScreenVisionContext, ScreenVisionContextHandoffError> {
        validate_id("attachment identity", attachment_id)?;
        validate_id("life identity", life_id)?;
        validate_id("screen session fence", screen_session_fence)?;
        validate_id("conversation identity", conversation_id)?;
        validate_id("request identity", request_id)?;
        let mut state = self.lock_state()?;
        match &*state {
            VisionHandoffState::Offered(payload) => {
                if self
                    .clock
                    .now()
                    .saturating_duration_since(payload.source_created_at)
                    >= SCREEN_VISION_SEMANTIC_RESULT_TTL
                {
                    let expired_id = payload.attachment_id.clone();
                    let _ = self
                        .offer_gate
                        .clear_offered_exact(PerceptionChatSourceKind::CloudVision, &expired_id)
                        .map_err(map_gate_error)?;
                    *state = VisionHandoffState::Empty;
                    return Err(ScreenVisionContextHandoffError::new(
                        ScreenVisionContextHandoffErrorCode::ResultExpired,
                    ));
                }
                if payload.attachment_id != attachment_id {
                    return Err(ScreenVisionContextHandoffError::new(
                        ScreenVisionContextHandoffErrorCode::AttachmentNotFound,
                    ));
                }
                validate_scope(payload, life_id, screen_session_fence)?;
                let claimed = claimed_from_payload(payload);
                self.offer_gate
                    .mark_bound(PerceptionChatSourceKind::CloudVision, attachment_id)
                    .map_err(map_gate_error)?;
                let payload = match std::mem::replace(&mut *state, VisionHandoffState::Empty) {
                    VisionHandoffState::Offered(payload) => payload,
                    _ => unreachable!("Vision offer cannot change while its mutex is held"),
                };
                *state = VisionHandoffState::Bound(BoundVisionHandoff {
                    payload,
                    conversation_id: conversation_id.to_string(),
                    request_id: request_id.to_string(),
                });
                Ok(claimed)
            }
            VisionHandoffState::Bound(bound) => {
                if bound.payload.attachment_id != attachment_id {
                    return Err(ScreenVisionContextHandoffError::new(
                        ScreenVisionContextHandoffErrorCode::AttachmentNotFound,
                    ));
                }
                validate_scope(&bound.payload, life_id, screen_session_fence)?;
                if bound.conversation_id != conversation_id || bound.request_id != request_id {
                    return Err(ScreenVisionContextHandoffError::new(
                        ScreenVisionContextHandoffErrorCode::ConversationMismatch,
                    ));
                }
                Ok(claimed_from_payload(&bound.payload))
            }
            VisionHandoffState::Empty => Err(ScreenVisionContextHandoffError::new(
                ScreenVisionContextHandoffErrorCode::AttachmentNotFound,
            )),
        }
    }

    pub(crate) fn dismiss_exact(
        &self,
        attachment_id: &str,
    ) -> Result<(), ScreenVisionContextHandoffError> {
        validate_id("attachment identity", attachment_id)?;
        let mut state = self.lock_state()?;
        match &*state {
            VisionHandoffState::Offered(payload) if payload.attachment_id == attachment_id => {
                self.offer_gate
                    .clear_offered_exact(PerceptionChatSourceKind::CloudVision, attachment_id)
                    .map_err(map_gate_error)?;
                *state = VisionHandoffState::Empty;
                Ok(())
            }
            VisionHandoffState::Bound(bound) if bound.payload.attachment_id == attachment_id => {
                Err(ScreenVisionContextHandoffError::new(
                    ScreenVisionContextHandoffErrorCode::AttachmentInUse,
                ))
            }
            _ => Err(ScreenVisionContextHandoffError::new(
                ScreenVisionContextHandoffErrorCode::AttachmentNotFound,
            )),
        }
    }

    pub(crate) fn retire_bound_exact(
        &self,
        attachment_id: &str,
        conversation_id: &str,
        request_id: &str,
    ) -> Result<(), ScreenVisionContextHandoffError> {
        validate_id("attachment identity", attachment_id)?;
        validate_id("conversation identity", conversation_id)?;
        validate_id("request identity", request_id)?;
        let mut state = self.lock_state()?;
        match &*state {
            VisionHandoffState::Bound(bound)
                if bound.payload.attachment_id == attachment_id
                    && bound.conversation_id == conversation_id
                    && bound.request_id == request_id =>
            {
                self.offer_gate
                    .clear_bound_exact(PerceptionChatSourceKind::CloudVision, attachment_id)
                    .map_err(map_gate_error)?;
                *state = VisionHandoffState::Empty;
                Ok(())
            }
            VisionHandoffState::Bound(bound) if bound.payload.attachment_id == attachment_id => {
                Err(ScreenVisionContextHandoffError::new(
                    ScreenVisionContextHandoffErrorCode::ConversationMismatch,
                ))
            }
            _ => Err(ScreenVisionContextHandoffError::new(
                ScreenVisionContextHandoffErrorCode::AttachmentNotFound,
            )),
        }
    }

    fn lock_state(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, VisionHandoffState>, ScreenVisionContextHandoffError>
    {
        self.state.lock().map_err(|_| {
            ScreenVisionContextHandoffError::new(
                ScreenVisionContextHandoffErrorCode::SynchronizationUnavailable,
            )
        })
    }
}

fn claimed_from_payload(payload: &VisionHandoffPayload) -> ClaimedScreenVisionContext {
    ClaimedScreenVisionContext {
        attachment_id: payload.attachment_id.clone(),
        result_id: payload.result_id.clone(),
        life_id: payload.life_id.clone(),
        screen_session_fence: payload.screen_session_fence.clone(),
        summary: payload.analysis.summary.clone(),
        observations: payload.analysis.observations.clone(),
    }
}

fn validate_scope(
    payload: &VisionHandoffPayload,
    life_id: &str,
    screen_session_fence: &str,
) -> Result<(), ScreenVisionContextHandoffError> {
    if payload.life_id != life_id {
        return Err(ScreenVisionContextHandoffError::new(
            ScreenVisionContextHandoffErrorCode::LifeMismatch,
        ));
    }
    if payload.screen_session_fence != screen_session_fence {
        return Err(ScreenVisionContextHandoffError::new(
            ScreenVisionContextHandoffErrorCode::SessionFenceMismatch,
        ));
    }
    Ok(())
}

fn validate_id(_name: &str, value: &str) -> Result<(), ScreenVisionContextHandoffError> {
    if value.trim().is_empty() || value.chars().count() > MAX_ID_CHARACTERS {
        return Err(ScreenVisionContextHandoffError::new(
            ScreenVisionContextHandoffErrorCode::InvalidArgument,
        ));
    }
    Ok(())
}

fn map_result_error(error: ScreenVisionSemanticResultErrorCode) -> ScreenVisionContextHandoffError {
    ScreenVisionContextHandoffError::new(match error {
        ScreenVisionSemanticResultErrorCode::ResultUnavailable => {
            ScreenVisionContextHandoffErrorCode::ResultUnavailable
        }
        ScreenVisionSemanticResultErrorCode::ResultExpired => {
            ScreenVisionContextHandoffErrorCode::ResultExpired
        }
        ScreenVisionSemanticResultErrorCode::RandomUnavailable => {
            ScreenVisionContextHandoffErrorCode::RandomUnavailable
        }
        ScreenVisionSemanticResultErrorCode::SynchronizationUnavailable => {
            ScreenVisionContextHandoffErrorCode::SynchronizationUnavailable
        }
        ScreenVisionSemanticResultErrorCode::InvalidArgument => {
            ScreenVisionContextHandoffErrorCode::InvalidArgument
        }
    })
}

fn map_gate_error(
    error: super::perception_chat_offer_gate::PerceptionChatOfferGateError,
) -> ScreenVisionContextHandoffError {
    ScreenVisionContextHandoffError::new(match error.code {
        PerceptionChatOfferGateErrorCode::AttachmentInUse => {
            ScreenVisionContextHandoffErrorCode::AttachmentInUse
        }
        PerceptionChatOfferGateErrorCode::CrossSourceInUse => {
            ScreenVisionContextHandoffErrorCode::AttachmentInUse
        }
        PerceptionChatOfferGateErrorCode::SynchronizationUnavailable => {
            ScreenVisionContextHandoffErrorCode::SynchronizationUnavailable
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perception::{
        perception_chat_offer_gate::PerceptionChatOfferGate,
        screen_chat_attachment::ScreenContextChatAttachmentBroker,
        screen_context::ScreenContextSessionFence,
        screen_vision_semantic_result::MAX_SEMANTIC_SUMMARY_CHARACTERS,
    };
    use std::time::Duration;

    #[derive(Clone)]
    struct ManualClock {
        now: Arc<Mutex<Instant>>,
    }

    impl ManualClock {
        fn new() -> Self {
            Self {
                now: Arc::new(Mutex::new(Instant::now())),
            }
        }

        fn advance(&self, duration: Duration) {
            let mut now = self.now.lock().expect("handoff clock should not poison");
            *now = now.checked_add(duration).expect("test clock should fit");
        }
    }

    impl VisionHandoffClock for ManualClock {
        fn now(&self) -> Instant {
            *self.now.lock().expect("handoff clock should not poison")
        }
    }

    struct SequenceIdSource {
        ids: Mutex<Vec<String>>,
    }

    impl SequenceIdSource {
        fn new(ids: &[&str]) -> Self {
            Self {
                ids: Mutex::new(ids.iter().rev().map(|id| (*id).to_string()).collect()),
            }
        }
    }

    impl VisionHandoffIdSource for SequenceIdSource {
        fn generate(&self) -> Result<String, ScreenVisionContextHandoffError> {
            self.ids
                .lock()
                .expect("handoff id source should not poison")
                .pop()
                .ok_or_else(|| {
                    ScreenVisionContextHandoffError::new(
                        ScreenVisionContextHandoffErrorCode::RandomUnavailable,
                    )
                })
        }
    }

    fn broker(
        clock: ManualClock,
        ids: &[&str],
        offer_gate: Arc<PerceptionChatOfferGate>,
    ) -> ScreenVisionContextHandoffBroker {
        ScreenVisionContextHandoffBroker::with_clock_and_id_source(
            Box::new(clock),
            Box::new(SequenceIdSource::new(ids)),
            offer_gate,
        )
    }

    fn result(result_id: &str, created_at: Instant) -> ScreenVisionSemanticResult {
        ScreenVisionSemanticResult {
            result_id: result_id.to_string(),
            life_id: "life-a".to_string(),
            screen_session_fence: "7".to_string(),
            analysis: ScreenVisionSemanticAnalysis {
                summary: "bounded summary".to_string(),
                observations: vec!["bounded observation".to_string()],
            },
            created_at,
        }
    }

    #[test]
    fn offered_vision_claims_once_and_exact_bound_retry_is_stable() {
        let clock = ManualClock::new();
        let broker = broker(
            clock.clone(),
            &["vision-attachment"],
            Arc::new(PerceptionChatOfferGate::new()),
        );
        let attachment_id = broker
            .offer_result(result("result-a", clock.now()))
            .expect("Vision result should be offered");

        let claimed = broker
            .claim_exact(&attachment_id, "life-a", "7", "conversation-a", "request-a")
            .expect("first exact claim should bind");
        assert_eq!(claimed.result_id, "result-a");
        assert_eq!(claimed.life_id, "life-a");
        assert_eq!(claimed.screen_session_fence, "7");
        assert_eq!(claimed.summary, "bounded summary");

        let retry = broker
            .claim_exact(&attachment_id, "life-a", "7", "conversation-a", "request-a")
            .expect("same request should replay the bound payload");
        assert_eq!(retry.summary, claimed.summary);
        assert_eq!(retry.observations, claimed.observations);

        let error = broker
            .claim_exact(&attachment_id, "life-a", "7", "conversation-b", "request-b")
            .expect_err("a different request must not steal a bound handoff");
        assert_eq!(
            error.code,
            ScreenVisionContextHandoffErrorCode::ConversationMismatch
        );
        assert!(broker.status().unwrap().is_some_and(|status| status.bound));
        assert_eq!(
            broker
                .dismiss_exact(&attachment_id)
                .expect_err("a bound handoff cannot be dismissed")
                .code,
            ScreenVisionContextHandoffErrorCode::AttachmentInUse
        );

        broker
            .retire_bound_exact(&attachment_id, "conversation-a", "request-a")
            .expect("exact successful retirement should empty the handoff");
        assert!(broker.status().unwrap().is_none());
    }

    #[test]
    fn stale_bound_scope_releases_the_gate_and_allows_new_sources() {
        let clock = ManualClock::new();
        let gate = Arc::new(PerceptionChatOfferGate::new());
        let broker = broker(
            clock.clone(),
            &["vision-bound", "vision-replacement"],
            gate.clone(),
        );
        let old_attachment = broker
            .offer_result(result("result-bound", clock.now()))
            .unwrap();
        broker
            .claim_exact(
                &old_attachment,
                "life-a",
                "7",
                "conversation-a",
                "request-a",
            )
            .unwrap();

        assert!(broker
            .invalidate_bound_if_scope_stale(Some("life-a"), Some(ScreenContextSessionFence(8)))
            .unwrap());
        assert!(broker.status().unwrap().is_none());
        assert!(gate.snapshot().is_none());
        assert_eq!(
            broker
                .claim_exact(
                    &old_attachment,
                    "life-a",
                    "8",
                    "conversation-a",
                    "request-a"
                )
                .unwrap_err()
                .code,
            ScreenVisionContextHandoffErrorCode::AttachmentNotFound
        );

        let replacement = broker
            .offer_result(result("result-replacement", clock.now()))
            .unwrap();
        assert_ne!(replacement, old_attachment);
        broker.dismiss_exact(&replacement).unwrap();

        let ocr = ScreenContextChatAttachmentBroker::new_with_offer_gate(gate);
        assert!(ocr
            .offer("grant-after-stale", "life-a", ScreenContextSessionFence(8))
            .is_ok());
    }

    #[test]
    fn same_scope_bound_reconciliation_preserves_exact_retry_and_gate() {
        let clock = ManualClock::new();
        let gate = Arc::new(PerceptionChatOfferGate::new());
        let broker = broker(clock.clone(), &["vision-same-scope"], gate.clone());
        let attachment_id = broker
            .offer_result(result("result-same-scope", clock.now()))
            .unwrap();
        broker
            .claim_exact(&attachment_id, "life-a", "7", "conversation-a", "request-a")
            .unwrap();

        assert!(!broker
            .invalidate_bound_if_scope_stale(Some("life-a"), Some(ScreenContextSessionFence(7)))
            .unwrap());
        broker
            .claim_exact(&attachment_id, "life-a", "7", "conversation-a", "request-a")
            .expect("same-scope exact retry must remain usable");
        assert_eq!(
            gate.snapshot(),
            Some((PerceptionChatSourceKind::CloudVision, attachment_id, true))
        );
    }

    #[test]
    fn gate_cleanup_failure_preserves_stale_bound_state_for_retry() {
        let clock = ManualClock::new();
        let gate = Arc::new(PerceptionChatOfferGate::new());
        let broker = broker(clock.clone(), &["vision-cleanup-failure"], gate.clone());
        let attachment_id = broker
            .offer_result(result("result-cleanup-failure", clock.now()))
            .unwrap();
        broker
            .claim_exact(&attachment_id, "life-a", "7", "conversation-a", "request-a")
            .unwrap();
        gate.fail_next_bound_clear_for_test();

        let error = broker
            .invalidate_bound_if_scope_stale(Some("life-a"), Some(ScreenContextSessionFence(8)))
            .expect_err("gate failure must not clear the Vision BOUND state");
        assert_eq!(
            error.code,
            ScreenVisionContextHandoffErrorCode::SynchronizationUnavailable
        );
        assert!(broker.status().unwrap().is_some_and(|status| status.bound));
        assert_eq!(
            gate.snapshot(),
            Some((
                PerceptionChatSourceKind::CloudVision,
                attachment_id.clone(),
                true
            ))
        );
        broker
            .claim_exact(&attachment_id, "life-a", "7", "conversation-a", "request-a")
            .expect("the preserved BOUND state must still support exact retry");
    }

    #[test]
    fn offered_replacement_is_atomic_and_invalidates_only_the_old_locator() {
        let clock = ManualClock::new();
        let gate = Arc::new(PerceptionChatOfferGate::new());
        let broker = broker(
            clock.clone(),
            &["attachment-old", "attachment-new"],
            gate.clone(),
        );
        let old = broker
            .offer_result(result("result-old", clock.now()))
            .unwrap();
        let new = broker
            .offer_result(result("result-new", clock.now()))
            .unwrap();

        assert_ne!(old, new);
        assert_eq!(
            broker.get_exact(&old).unwrap_err().code,
            ScreenVisionContextHandoffErrorCode::AttachmentNotFound
        );
        assert_eq!(broker.status().unwrap().unwrap().attachment_id, new);
        assert_eq!(
            gate.snapshot(),
            Some((
                PerceptionChatSourceKind::CloudVision,
                "attachment-new".to_string(),
                false
            ))
        );
    }

    #[test]
    fn offered_ttl_uses_original_result_creation_and_bound_survives_it() {
        let clock = ManualClock::new();
        let gate = Arc::new(PerceptionChatOfferGate::new());
        let offered_broker = broker(clock.clone(), &["attachment-offered"], gate.clone());
        let attachment_id = offered_broker
            .offer_result(result("result-offered", clock.now()))
            .unwrap();
        clock.advance(SCREEN_VISION_SEMANTIC_RESULT_TTL - Duration::from_secs(1));
        assert!(offered_broker.status().unwrap().is_some());
        clock.advance(Duration::from_secs(1));
        assert!(offered_broker.status().unwrap().is_none());
        assert!(gate.snapshot().is_none());

        let bound_broker = broker(clock.clone(), &["attachment-bound"], gate.clone());
        let bound_id = bound_broker
            .offer_result(result("result-bound", clock.now()))
            .unwrap();
        bound_broker
            .claim_exact(&bound_id, "life-a", "7", "conversation-a", "request-a")
            .unwrap();
        clock.advance(SCREEN_VISION_SEMANTIC_RESULT_TTL + Duration::from_secs(1));
        assert!(bound_broker
            .status()
            .unwrap()
            .is_some_and(|status| status.bound));
        bound_broker
            .claim_exact(&bound_id, "life-a", "7", "conversation-a", "request-a")
            .expect("BOUND state must not expire from the source TTL");
        assert_eq!(attachment_id, "attachment-offered");
    }

    #[test]
    fn life_and_fence_are_revalidated_before_the_offer_becomes_bound() {
        let clock = ManualClock::new();
        let broker = broker(
            clock.clone(),
            &["attachment-scope"],
            Arc::new(PerceptionChatOfferGate::new()),
        );
        let attachment_id = broker
            .offer_result(result("result-scope", clock.now()))
            .unwrap();

        let error = broker
            .claim_exact(&attachment_id, "life-b", "7", "conversation-a", "request-a")
            .expect_err("Life mismatch must fail closed");
        assert_eq!(
            error.code,
            ScreenVisionContextHandoffErrorCode::LifeMismatch
        );
        let error = broker
            .claim_exact(&attachment_id, "life-a", "8", "conversation-a", "request-a")
            .expect_err("session fence mismatch must fail closed");
        assert_eq!(
            error.code,
            ScreenVisionContextHandoffErrorCode::SessionFenceMismatch
        );
        assert!(!broker.status().unwrap().unwrap().bound);
    }

    #[test]
    fn malformed_internal_semantic_payload_is_rejected_without_an_offer() {
        let clock = ManualClock::new();
        let broker = broker(
            clock.clone(),
            &["attachment-invalid"],
            Arc::new(PerceptionChatOfferGate::new()),
        );
        let mut invalid = result("result-invalid", clock.now());
        invalid.analysis.summary = "s".repeat(MAX_SEMANTIC_SUMMARY_CHARACTERS + 1);
        let error = broker
            .offer_result(invalid)
            .expect_err("handoff must defend the semantic bounds again");
        assert_eq!(
            error.code,
            ScreenVisionContextHandoffErrorCode::InvalidArgument
        );
        assert!(broker.status().unwrap().is_none());
    }

    #[test]
    fn one_global_gate_blocks_cross_source_offers_without_orphans() {
        let gate = Arc::new(PerceptionChatOfferGate::new());
        let ocr = ScreenContextChatAttachmentBroker::new_with_offer_gate(gate.clone());
        let vision_clock = ManualClock::new();
        let vision = broker(vision_clock.clone(), &["vision-after-ocr"], gate.clone());
        let ocr_id = ocr
            .offer("grant-a", "life-a", ScreenContextSessionFence(7))
            .unwrap();
        let error = vision
            .offer_result(result("result-cross-source", vision_clock.now()))
            .expect_err("Vision must not replace a live OCR offer");
        assert_eq!(
            error.code,
            ScreenVisionContextHandoffErrorCode::AttachmentInUse
        );
        assert!(vision.status().unwrap().is_none());
        ocr.remove_exact(&ocr_id).unwrap();
        assert!(vision
            .offer_result(result("result-cross-source", vision_clock.now()))
            .is_ok());
    }

    #[test]
    fn bound_source_blocks_the_other_source_and_failed_offer_leaves_no_marker() {
        let gate = Arc::new(PerceptionChatOfferGate::new());
        let ocr = ScreenContextChatAttachmentBroker::new_with_offer_gate(gate.clone());
        let ocr_id = ocr
            .offer("grant-bound", "life-a", ScreenContextSessionFence(7))
            .unwrap();
        ocr.mark_bound(&ocr_id).unwrap();
        let clock = ManualClock::new();
        let vision = broker(clock.clone(), &["vision-blocked"], gate.clone());
        let error = vision
            .offer_result(result("result-blocked", clock.now()))
            .expect_err("BOUND OCR must block Vision");
        assert_eq!(
            error.code,
            ScreenVisionContextHandoffErrorCode::AttachmentInUse
        );
        assert!(vision.status().unwrap().is_none());
        assert_eq!(
            gate.snapshot(),
            Some((PerceptionChatSourceKind::LocalOcr, ocr_id, true))
        );
    }

    #[test]
    fn bound_vision_blocks_ocr_until_exact_retirement() {
        let gate = Arc::new(PerceptionChatOfferGate::new());
        let clock = ManualClock::new();
        let vision = broker(clock.clone(), &["vision-bound"], gate.clone());
        let vision_id = vision
            .offer_result(result("result-bound-source", clock.now()))
            .unwrap();
        vision
            .claim_exact(&vision_id, "life-a", "7", "conversation-a", "request-a")
            .unwrap();

        let ocr = ScreenContextChatAttachmentBroker::new_with_offer_gate(gate.clone());
        let error = ocr
            .offer("grant-blocked", "life-a", ScreenContextSessionFence(7))
            .expect_err("BOUND Vision must block OCR");
        assert_eq!(
            error.code,
            crate::perception::screen_chat_attachment::ScreenContextChatAttachmentErrorCode::PerceptionAttachmentInUse
        );
        assert!(ocr.current().is_none());
        vision
            .retire_bound_exact(&vision_id, "conversation-a", "request-a")
            .unwrap();
        assert!(ocr
            .offer(
                "grant-after-retirement",
                "life-a",
                ScreenContextSessionFence(7)
            )
            .is_ok());
    }
}
