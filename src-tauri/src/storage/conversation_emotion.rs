//! D11-C1: crate-internal atomic conversation + emotion turn commit.
//!
//! One governed conversation turn and its already-computed
//! [`EmotionTransition`] commit in ONE SQLite transaction. The real chat
//! orchestration (stimulus classification, clock calculation, switching the
//! production flow onto this primitive) belongs to D11-C2.
//!
//! Identity contract (deterministic helpers only — never parsed back):
//! - source kind: [`CONVERSATION_EMOTION_SOURCE_KIND`] = "conversation_turn"
//! - source ref : [`conversation_emotion_source_ref`] =
//!   "{conversation_id}:{turn_id}"
//! - event id   : [`conversation_emotion_event_id`] =
//!   "conversation-emotion:{life_id}:{conversation_id}:{turn_id}"
//!
//! Legacy turns committed by the non-emotion path before D11-C are NEVER
//! retroactively given an emotion event; this module is a primitive for NEW
//! governed commits only.

use rusqlite::TransactionBehavior;

use super::{
    conversation::{self},
    emotion::commit_transition_in_transaction,
    StorageService,
};
use crate::conversation::history::{AppendConversationTurnRequest, AppendConversationTurnResult};
use crate::emotion::{EmotionCommitOutcome, EmotionError, EmotionTransition};

/// Frozen source kind for conversation-generated emotion events. Crate-level
/// seam so the D11-C2 orchestrator can construct canonical identity without
/// duplicating string formatting.
pub(crate) const CONVERSATION_EMOTION_SOURCE_KIND: &str = "conversation_turn";

/// Deterministic binding of one emotion event to one conversation turn. The
/// identity is used for equality/idempotency only; it is never parsed back
/// into components.
pub(crate) fn conversation_emotion_source_ref(conversation_id: &str, turn_id: &str) -> String {
    format!("{conversation_id}:{turn_id}")
}

/// Deterministic canonical emotion event identity for one governed turn. The
/// D11-C2 orchestrator must construct event ids through this helper so a
/// retried turn always resolves to the same emotion event.
pub(crate) fn conversation_emotion_event_id(
    life_id: &str,
    conversation_id: &str,
    turn_id: &str,
) -> String {
    format!("conversation-emotion:{life_id}:{conversation_id}:{turn_id}")
}

/// Composite failure boundary for the atomic conversation+emotion commit.
/// The cause category is preserved so D11-C2 can map each case intentionally;
/// C1 never collapses emotion failures into generic conversation errors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConversationEmotionCommitError {
    Conversation(crate::conversation::history::ConversationHistoryError),
    Emotion(EmotionError),
    /// The supplied transition does not deterministically bind to the
    /// requested conversation turn (life, kind, ref, or canonical event id).
    BindingMismatch(String),
    /// The requested conversation turn already exists but carries NO emotion
    /// event under the canonical identity — a legacy (pre-D11-C) or
    /// incomplete turn. Never backfilled; the caller supplied a valid
    /// binding, persisted storage simply has no governed emotion evidence.
    EmotionEventMissing(String),
}

impl ConversationEmotionCommitError {
    fn storage_lock_unavailable() -> Self {
        Self::Conversation(conversation::storage_unavailable())
    }

    /// Stable machine-readable category for D11-C2's intentional mapping.
    #[allow(dead_code)] // consumed by tests now and by the C2 orchestrator later
    pub(crate) fn code(&self) -> String {
        match self {
            Self::Conversation(error) => format!("{:?}", error.code),
            Self::Emotion(error) => error.code.as_str().to_string(),
            Self::BindingMismatch(_) => "EMOTION_TURN_BINDING_MISMATCH".to_string(),
            Self::EmotionEventMissing(_) => "EMOTION_TURN_EVENT_MISSING".to_string(),
        }
    }
}

impl From<rusqlite::Error> for ConversationEmotionCommitError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Conversation(conversation::storage_unavailable())
    }
}

/// Result of one atomic composite commit: both domain outcomes together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConversationEmotionCommitOutcome {
    pub(crate) turn: AppendConversationTurnResult,
    pub(crate) emotion: EmotionCommitOutcome,
}

/// Validate that `transition` deterministically binds to the requested
/// conversation turn BEFORE any write happens. Fail closed; never rewrite the
/// caller-supplied transition.
fn validate_binding(
    request: &AppendConversationTurnRequest,
    transition: &EmotionTransition,
) -> Result<(), ConversationEmotionCommitError> {
    let expected_ref = conversation_emotion_source_ref(&request.conversation_id, &request.turn_id);
    if transition.life_id != request.life_id {
        return Err(ConversationEmotionCommitError::BindingMismatch(
            "transition life_id must equal the conversation life_id.".to_string(),
        ));
    }
    if transition.source.kind != CONVERSATION_EMOTION_SOURCE_KIND {
        return Err(ConversationEmotionCommitError::BindingMismatch(format!(
            "transition source kind must be {CONVERSATION_EMOTION_SOURCE_KIND}.",
        )));
    }
    if transition.source.reference != expected_ref {
        return Err(ConversationEmotionCommitError::BindingMismatch(
            "transition source reference must be the deterministic turn identity.".to_string(),
        ));
    }
    let expected_event_id =
        conversation_emotion_event_id(&request.life_id, &request.conversation_id, &request.turn_id);
    if transition.event_id != expected_event_id {
        return Err(ConversationEmotionCommitError::BindingMismatch(
            "transition event id must be the canonical turn event identity.".to_string(),
        ));
    }
    Ok(())
}

impl StorageService {
    /// The ONE atomic primitive for a governed emotion-aware conversation
    /// turn: conversation messages + revision + emotion_event + emotion_state
    /// in exactly ONE SQLite transaction. Any failure before the final commit
    /// leaves BOTH domains unchanged. Not exposed via Tauri in C1.
    #[allow(dead_code)] // C1 seam; the production orchestrator switches to it in D11-C2.
    pub(crate) fn append_complete_turn_with_emotion(
        &self,
        request: &AppendConversationTurnRequest,
        transition: EmotionTransition,
    ) -> Result<ConversationEmotionCommitOutcome, ConversationEmotionCommitError> {
        // Shared conversation input validation FIRST — the exact same rules
        // as legacy ConversationHistoryService::append_turn — so the
        // composite primitive can never bypass them (zero writes on failure).
        crate::conversation::history::validate_append_turn_request(request)
            .map_err(ConversationEmotionCommitError::Conversation)?;
        // Pure binding validation next: zero writes on mismatch.
        validate_binding(request, &transition)?;
        let mut state = self
            .state()
            .map_err(|_| ConversationEmotionCommitError::storage_lock_unavailable())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ConversationEmotionCommitError::from)?;

        // 1-2. Load + ownership-validate conversation; detect existing turn.
        let stored_conversation = conversation::load_conversation(
            &transaction,
            &request.life_id,
            &request.conversation_id,
        )
        .map_err(ConversationEmotionCommitError::Conversation)?;
        if let Some(mut existing) = conversation::load_turn(
            &transaction,
            &request.life_id,
            &request.conversation_id,
            &request.turn_id,
        )
        .map_err(ConversationEmotionCommitError::Conversation)?
        {
            // Replay path: same turn_id must carry identical user content.
            if existing.user_message.content != request.user_content {
                return Err(ConversationEmotionCommitError::Conversation(
                    crate::conversation::history::ConversationHistoryError::new(
                        crate::conversation::history::ConversationHistoryErrorCode::TurnIdConflict,
                    ),
                ));
            }
            // Legacy guard: a turn committed by the old non-emotion path has
            // NO emotion event under the canonical identity. It must NEVER be
            // retroactively given one, so fail closed BEFORE invoking the B1
            // helper (whose job would otherwise be to create the missing
            // event). This is a NON-MUTATING existence check only — replay
            // equality stays the exclusive property of the B1 semantic
            // implementation below.
            let emotion_event_exists: bool = transaction
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM emotion_event
                        WHERE event_id = ?1
                           OR (life_id = ?2 AND source_kind = ?3 AND source_ref = ?4)
                    )",
                    rusqlite::params![
                        transition.event_id,
                        transition.life_id,
                        transition.source.kind,
                        transition.source.reference,
                    ],
                    |row| row.get(0),
                )
                .map_err(ConversationEmotionCommitError::from)?;
            if !emotion_event_exists {
                return Err(ConversationEmotionCommitError::EmotionEventMissing(
                    "the conversation turn has no governed emotion event to replay.".to_string(),
                ));
            }
            // The persisted turn exists; its emotion evidence must match the
            // supplied transition EXACTLY (canonical replay), otherwise this
            // is a typed emotion conflict with no mutation anywhere. The B1
            // helper remains the single replay-equality authority.
            existing.replayed = true;
            existing.conversation_revision = stored_conversation.revision;
            let emotion = commit_transition_in_transaction(&transaction, transition)
                .map_err(ConversationEmotionCommitError::Emotion)?;
            transaction
                .commit()
                .map_err(ConversationEmotionCommitError::from)?;
            return Ok(ConversationEmotionCommitOutcome {
                turn: existing,
                emotion,
            });
        }

        // 3. Validate conversation expected_revision for a new turn.
        if request
            .expected_revision
            .is_some_and(|expected| expected != stored_conversation.revision)
        {
            return Err(ConversationEmotionCommitError::Conversation(
                crate::conversation::history::ConversationHistoryError::new(
                    crate::conversation::history::ConversationHistoryErrorCode::ConversationChangedDuringRequest,
                ),
            ));
        }

        // 5. Execute the B1 emotion transition inside THIS SAME transaction.
        //    Running it before message inserts means a stale EMOTION revision
        //    fails before any conversation row exists (case B), while any
        //    later conversation failure rolls the emotion work back (case D).
        let emotion = commit_transition_in_transaction(&transaction, transition)
            .map_err(ConversationEmotionCommitError::Emotion)?;

        // 6-8. Insert user message, assistant message, CAS conversation
        //      revision — reusing the exact legacy helpers/semantics.
        let next_sequence: i64 = transaction
            .query_row(
                "SELECT COALESCE(MAX(sequence_no), 0) + 1 FROM conversation_message
                 WHERE conversation_id = ?1 AND life_id = ?2",
                rusqlite::params![request.conversation_id, request.life_id],
                |row| row.get(0),
            )
            .map_err(ConversationEmotionCommitError::from)?;
        conversation::insert_message(
            &transaction,
            &crate::conversation::history::generate_id("message"),
            request,
            crate::conversation::history::ConversationRole::User,
            &request.user_content,
            next_sequence,
        )
        .map_err(ConversationEmotionCommitError::Conversation)?;
        conversation::insert_message(
            &transaction,
            &crate::conversation::history::generate_id("message"),
            request,
            crate::conversation::history::ConversationRole::Assistant,
            &request.assistant_content,
            next_sequence + 1,
        )
        .map_err(ConversationEmotionCommitError::Conversation)?;
        let updated = transaction
            .execute(
                "UPDATE conversation SET revision = revision + 1,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                 last_message_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND life_id = ?2 AND revision = ?3",
                rusqlite::params![
                    request.conversation_id,
                    request.life_id,
                    stored_conversation.revision
                ],
            )
            .map_err(ConversationEmotionCommitError::from)?;
        if updated != 1 {
            return Err(ConversationEmotionCommitError::Conversation(
                crate::conversation::history::ConversationHistoryError::new(
                    crate::conversation::history::ConversationHistoryErrorCode::ConversationChangedDuringRequest,
                ),
            ));
        }

        // 9. Reload the complete turn.
        let mut turn = conversation::load_turn(
            &transaction,
            &request.life_id,
            &request.conversation_id,
            &request.turn_id,
        )
        .map_err(ConversationEmotionCommitError::Conversation)?
        .ok_or(ConversationEmotionCommitError::Conversation(
            crate::conversation::history::ConversationHistoryError::new(
                crate::conversation::history::ConversationHistoryErrorCode::InternalError,
            ),
        ))?;
        turn.conversation_revision = stored_conversation.revision + 1;

        // 10. Commit once. There is NO intermediate commit between the
        //     emotion and conversation writes.
        transaction
            .commit()
            .map_err(ConversationEmotionCommitError::from)?;
        Ok(ConversationEmotionCommitOutcome { turn, emotion })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;
    use crate::conversation::history::{AppendConversationTurnRequest, ConversationHistoryService};
    use crate::emotion::{EmotionErrorCode, EmotionEventSource, INITIAL_POLICY_VERSION};
    use crate::storage::{unique_suffix, LifeIdentityRecord, PersonaTemplateRecord};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "digital-life-conv-emotion-{name}-{}",
                unique_suffix()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn seeded_service(root: &TestRoot) -> StorageService {
        let service = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        service
            .save_persona(PersonaTemplateRecord {
                id: "persona-a".into(),
                name: "Persona".into(),
                version: 1,
                persona_json: "{}".into(),
            })
            .unwrap();
        service
            .save_life(LifeIdentityRecord {
                id: "life-a".into(),
                name: "Life A".into(),
                created_at: "2026-08-24T00:00:00.000Z".into(),
                version: 1,
                body_id: "body-a".into(),
                persona_id: "persona-a".into(),
                persona_version: 1,
            })
            .unwrap();
        service
    }

    fn create_conversation(
        service: &StorageService,
    ) -> crate::conversation::history::ConversationRecord {
        ConversationHistoryService::new(service)
            .create(crate::conversation::history::CreateConversationRequest {
                life_id: "life-a".into(),
                title: "Composite".into(),
            })
            .unwrap()
    }

    const EVENT_TIME: &str = "2026-08-24T12:00:00.000Z";

    fn bound_transition(
        conversation_id: &str,
        turn_id: &str,
        expected_revision: i64,
        deltas: (i32, i32),
        result: (i32, i32),
    ) -> EmotionTransition {
        EmotionTransition::new(
            conversation_emotion_event_id("life-a", conversation_id, turn_id),
            "life-a",
            EmotionEventSource::new(
                CONVERSATION_EMOTION_SOURCE_KIND,
                conversation_emotion_source_ref(conversation_id, turn_id),
            ),
            deltas.0,
            deltas.1,
            expected_revision,
            result.0,
            result.1,
            INITIAL_POLICY_VERSION,
            EVENT_TIME,
        )
        .unwrap()
    }

    fn turn_request(
        conversation: &crate::conversation::history::ConversationRecord,
        turn_id: &str,
        user_content: &str,
        assistant_content: &str,
    ) -> AppendConversationTurnRequest {
        AppendConversationTurnRequest {
            life_id: "life-a".into(),
            conversation_id: conversation.id.clone(),
            turn_id: turn_id.into(),
            user_content: user_content.into(),
            assistant_content: assistant_content.into(),
            expected_revision: None,
        }
    }

    fn counts(service: &StorageService, conversation_id: &str) -> (i64, i64, i64, i64, i64) {
        let state = service.state().unwrap();
        let messages: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM conversation_message WHERE conversation_id = ?1",
                [conversation_id],
                |row| row.get(0),
            )
            .unwrap();
        let events: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM emotion_event WHERE life_id='life-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let emotion_states: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM emotion_state WHERE life_id='life-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let conversation_revision: i64 = state
            .connection
            .query_row(
                "SELECT revision FROM conversation WHERE id = ?1",
                [conversation_id],
                |row| row.get(0),
            )
            .unwrap();
        let emotion_revision: i64 = state
            .connection
            .query_row(
                "SELECT revision FROM emotion_state WHERE life_id='life-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        (
            messages,
            conversation_revision,
            events,
            emotion_states,
            emotion_revision,
        )
    }

    // ---------- 1. successful composite commit ----------

    #[test]
    fn successful_composite_commit_writes_both_domains_exactly_once() {
        let root = TestRoot::new("success");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);

        let outcome = service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "hello", "hi there"),
                bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20)),
            )
            .unwrap();

        assert!(!outcome.turn.replayed);
        assert_eq!(outcome.turn.conversation_revision, 1);
        let EmotionCommitOutcome::Committed { event, state } = outcome.emotion else {
            panic!("first composite commit must commit the emotion");
        };
        assert_eq!(event.applied_revision, 1);
        assert_eq!(state.revision, 1);
        assert_eq!((state.valence, state.activation), (40, -20));

        let (messages, conv_rev, events, emotion_states, emotion_rev) =
            counts(&service, &conversation.id);
        assert_eq!(messages, 2);
        assert_eq!(conv_rev, 1);
        assert_eq!(events, 1);
        assert_eq!(emotion_states, 1);
        assert_eq!(emotion_rev, 1);
    }

    // ---------- 2. exact retry ----------

    #[test]
    fn exact_retry_replays_without_any_double_apply() {
        let root = TestRoot::new("retry");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);
        let first = service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "hello", "persisted answer"),
                bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20)),
            )
            .unwrap();
        assert!(!first.turn.replayed);

        // Same turn, same user content, SAME canonical emotion evidence; the
        // regenerated assistant text may differ and must not matter.
        let retry = service
            .append_complete_turn_with_emotion(
                &turn_request(
                    &conversation,
                    "turn-1",
                    "hello",
                    "regenerated different answer",
                ),
                bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20)),
            )
            .unwrap();

        assert!(retry.turn.replayed);
        assert_eq!(retry.turn.assistant_message.content, "persisted answer");
        assert!(matches!(
            retry.emotion,
            EmotionCommitOutcome::Replayed { .. }
        ));
        let (messages, conv_rev, events, _, emotion_rev) = counts(&service, &conversation.id);
        assert_eq!(messages, 2);
        assert_eq!(conv_rev, 1);
        assert_eq!(events, 1);
        assert_eq!(emotion_rev, 1);
    }

    // ---------- 3. same turn_id + different user content ----------

    #[test]
    fn same_turn_with_different_user_content_conflicts_without_emotion_mutation() {
        let root = TestRoot::new("turn-conflict");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);
        service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "original question", "answer"),
                bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20)),
            )
            .unwrap();

        let error = service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "DIFFERENT question", "answer"),
                bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20)),
            )
            .unwrap_err();

        assert_eq!(
            error.code(),
            format!(
                "{:?}",
                crate::conversation::history::ConversationHistoryErrorCode::TurnIdConflict
            )
        );
        let (messages, conv_rev, events, _, emotion_rev) = counts(&service, &conversation.id);
        assert_eq!(messages, 2);
        assert_eq!(conv_rev, 1);
        assert_eq!(events, 1);
        assert_eq!(emotion_rev, 1);
    }

    // ---------- 4. conflicting emotion evidence on committed turn ----------

    #[test]
    fn conflicting_emotion_evidence_on_committed_turn_is_typed_event_conflict() {
        let root = TestRoot::new("evidence-conflict");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);
        service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "hello", "answer"),
                bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20)),
            )
            .unwrap();

        let conflicting = bound_transition(&conversation.id, "turn-1", 0, (10, -5), (10, -5));
        let error = service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "hello", "answer"),
                conflicting,
            )
            .unwrap_err();

        assert_eq!(error.code(), EmotionErrorCode::EventConflict.as_str());
        let (_, conv_rev, events, _, emotion_rev) = counts(&service, &conversation.id);
        assert_eq!(conv_rev, 1);
        assert_eq!(events, 1);
        assert_eq!(emotion_rev, 1);
        let messages: i64 = service
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT COUNT(*) FROM conversation_message WHERE conversation_id = ?1",
                [&conversation.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(messages, 2);
    }

    // ---------- 5-8. binding mismatches ----------

    #[test]
    fn binding_mismatches_fail_closed_with_zero_writes() {
        let root = TestRoot::new("binding");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);

        // 5. life_id mismatch
        let mut transition = bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20));
        transition.life_id = "life-b".into();
        let error = service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "u", "a"),
                transition,
            )
            .unwrap_err();
        assert_eq!(error.code(), "EMOTION_TURN_BINDING_MISMATCH");

        // 6. source kind mismatch
        let mut transition = bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20));
        transition.source.kind = "memory".into();
        let error = service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "u", "a"),
                transition,
            )
            .unwrap_err();
        assert_eq!(error.code(), "EMOTION_TURN_BINDING_MISMATCH");

        // 7. source_ref mismatch
        let mut transition = bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20));
        transition.source.reference = "not-the-turn".into();
        let error = service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "u", "a"),
                transition,
            )
            .unwrap_err();
        assert_eq!(error.code(), "EMOTION_TURN_BINDING_MISMATCH");

        // 8. event_id mismatch
        let mut transition = bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20));
        transition.event_id = "arbitrary-event-id".into();
        let error = service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "u", "a"),
                transition,
            )
            .unwrap_err();
        assert_eq!(error.code(), "EMOTION_TURN_BINDING_MISMATCH");

        // Zero writes anywhere across all four cases.
        let state = service.state().unwrap();
        let total_messages: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM conversation_message", [], |row| {
                row.get(0)
            })
            .unwrap();
        let total_events: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM emotion_event", [], |row| row.get(0))
            .unwrap();
        assert_eq!(total_messages, 0);
        assert_eq!(total_events, 0);
        drop(state);
        let (_, conv_rev, ..) = counts(&service, &conversation.id);
        assert_eq!(conv_rev, 0);
    }

    // ---------- 9. stale conversation revision ----------

    #[test]
    fn stale_conversation_revision_changes_neither_domain() {
        let root = TestRoot::new("stale-conversation");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);
        let mut request = turn_request(&conversation, "turn-1", "u", "a");
        request.expected_revision = Some(7);
        let error = service
            .append_complete_turn_with_emotion(
                &request,
                bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20)),
            )
            .unwrap_err();
        assert_eq!(
            error.code(),
            format!(
                "{:?}",
                crate::conversation::history::ConversationHistoryErrorCode::ConversationChangedDuringRequest
            )
        );
        // Neither domain changed.
        let (messages, conv_rev, events, _, emotion_rev) = counts(&service, &conversation.id);
        assert_eq!(messages, 0);
        assert_eq!(conv_rev, 0);
        assert_eq!(events, 0);
        assert_eq!(emotion_rev, 0);
    }

    // ---------- 10. stale emotion revision ----------

    #[test]
    fn stale_emotion_revision_changes_neither_domain() {
        let root = TestRoot::new("stale-emotion");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);
        // Emotion state is at revision 0; propose building on revision 5.
        let stale = bound_transition(&conversation.id, "turn-1", 5, (40, -20), (40, -20));
        let error = service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "u", "a"),
                stale,
            )
            .unwrap_err();
        assert_eq!(error.code(), EmotionErrorCode::RevisionConflict.as_str());
        let (messages, conv_rev, events, _, emotion_rev) = counts(&service, &conversation.id);
        assert_eq!(messages, 0);
        assert_eq!(conv_rev, 0);
        assert_eq!(events, 0);
        assert_eq!(emotion_rev, 0);
    }

    // ---------- 11. forced conversation failure after emotion mutation ----------

    #[test]
    fn forced_conversation_failure_rolls_back_emotion_work() {
        let root = TestRoot::new("rollback-after-emotion");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);
        // Force ONLY the user-message INSERT to fail after the emotion work
        // has already mutated emotion rows INSIDE the transaction.
        service
            .state()
            .unwrap()
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_user_message
                 BEFORE INSERT ON conversation_message WHEN NEW.role = 'user'
                 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
            )
            .unwrap();

        let error = service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "must roll back", "must roll back"),
                bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20)),
            )
            .unwrap_err();

        assert_eq!(
            error.code(),
            format!("{:?}", crate::conversation::history::ConversationHistoryErrorCode::ConversationStorageUnavailable)
        );
        // The emotion work rolled back WITH the conversation work.
        let (messages, conv_rev, events, _, emotion_rev) = counts(&service, &conversation.id);
        assert_eq!(messages, 0);
        assert_eq!(conv_rev, 0);
        assert_eq!(events, 0);
        assert_eq!(emotion_rev, 0);
    }

    // ---------- 12. B1 standalone still works ----------

    #[test]
    fn b1_standalone_commit_transition_still_works() {
        let root = TestRoot::new("b1-standalone");
        let service = seeded_service(&root);
        let standalone = EmotionTransition::new(
            "plain-event",
            "life-a",
            EmotionEventSource::new("other-kind", "other-ref"),
            5,
            5,
            0,
            5,
            5,
            INITIAL_POLICY_VERSION,
            EVENT_TIME,
        )
        .unwrap();
        let outcome = <StorageService as crate::emotion::EmotionRepository>::commit_transition(
            &service, standalone,
        )
        .unwrap();
        assert!(matches!(outcome, EmotionCommitOutcome::Committed { .. }));
        let state = <StorageService as crate::emotion::EmotionRepository>::load_current_state(
            &service, "life-a",
        )
        .unwrap()
        .unwrap();
        assert_eq!(state.revision, 1);
    }

    // ---------- 13. legacy append_turn does NOT mutate emotion ----------

    #[test]
    fn legacy_append_turn_still_works_and_never_mutates_emotion() {
        let root = TestRoot::new("legacy-append");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);
        let legacy = ConversationHistoryService::new(&service).append_turn(
            crate::conversation::history::AppendConversationTurnRequest {
                life_id: "life-a".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "legacy-1".into(),
                user_content: "user".into(),
                assistant_content: "assistant".into(),
                expected_revision: None,
            },
        );
        assert!(legacy.is_ok());
        let (messages, conv_rev, events, emotion_states, _) = counts(&service, &conversation.id);
        assert_eq!(messages, 2);
        assert_eq!(conv_rev, 1);
        assert_eq!(events, 0);
        assert_eq!(emotion_states, 1); // initializer trigger row only, untouched
    }

    // ---------- 14. competing composite writers ----------

    #[test]
    fn two_competing_new_composite_commits_cannot_both_win() {
        let root = TestRoot::new("competing-composite");
        let first = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        first
            .save_persona(PersonaTemplateRecord {
                id: "persona-a".into(),
                name: "Persona".into(),
                version: 1,
                persona_json: "{}".into(),
            })
            .unwrap();
        first
            .save_life(LifeIdentityRecord {
                id: "life-a".into(),
                name: "Life A".into(),
                created_at: "2026-08-24T00:00:00.000Z".into(),
                version: 1,
                body_id: "body-a".into(),
                persona_id: "persona-a".into(),
                persona_version: 1,
            })
            .unwrap();
        let second = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        let conversation = create_conversation(&first);

        let first = Arc::new(first);
        let second = Arc::new(second);
        let barrier = Arc::new(Barrier::new(3));
        let (b1, b2) = (barrier.clone(), barrier.clone());
        let (svc_a, svc_b) = (first.clone(), second.clone());
        let conv_a = conversation.clone();
        let conv_b = conversation.clone();
        let writer_a = thread::spawn(move || {
            b1.wait();
            svc_a.append_complete_turn_with_emotion(
                &turn_request(&conv_a, "race-turn-a", "user A", "assistant A"),
                bound_transition(&conv_a.id, "race-turn-a", 0, (40, -20), (40, -20)),
            )
        });
        let writer_b = thread::spawn(move || {
            b2.wait();
            svc_b.append_complete_turn_with_emotion(
                &turn_request(&conv_b, "race-turn-b", "user B", "assistant B"),
                bound_transition(&conv_b.id, "race-turn-b", 0, (40, -20), (40, -20)),
            )
        });
        barrier.wait();
        // Both threads race; join both outcomes without sleeps.
        let outcome_a = writer_a.join().unwrap();
        let outcome_b = writer_b.join().unwrap();

        let won_a = outcome_a.is_ok();
        let won_b = outcome_b.is_ok();
        assert_eq!(
            won_a as u8 + won_b as u8,
            1,
            "exactly one competing composite writer may win"
        );
        let loser_error = if won_a {
            outcome_b.unwrap_err()
        } else {
            outcome_a.unwrap_err()
        };
        // The loser must fail with a typed boundary error (either the emotion
        // revision conflict or the conversation CAS conflict), never silence.
        let loser_code = loser_error.code();
        assert!(
            loser_code == EmotionErrorCode::RevisionConflict.as_str()
                || loser_code == format!(
                    "{:?}",
                    crate::conversation::history::ConversationHistoryErrorCode::ConversationChangedDuringRequest
                ),
            "unexpected loser code: {loser_code}"
        );

        let (messages, conv_rev, events, _, emotion_rev) = counts(&first, &conversation.id);
        assert_eq!(messages, 2);
        assert_eq!(conv_rev, 1);
        assert_eq!(events, 1);
        assert_eq!(emotion_rev, 1);
    }

    // ---------- 12b. unknown-outcome reopen/retry evidence ----------

    #[test]
    fn retry_after_unknown_outcome_resolves_as_replay_via_reopen() {
        let root = TestRoot::new("unknown-outcome-reopen");
        let data_root = root.0.join("data");
        {
            let service = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
            service
                .save_persona(PersonaTemplateRecord {
                    id: "persona-a".into(),
                    name: "Persona".into(),
                    version: 1,
                    persona_json: "{}".into(),
                })
                .unwrap();
            service
                .save_life(LifeIdentityRecord {
                    id: "life-a".into(),
                    name: "Life A".into(),
                    created_at: "2026-08-24T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "body-a".into(),
                    persona_id: "persona-a".into(),
                    persona_version: 1,
                })
                .unwrap();
            let conversation = create_conversation(&service);
            service
                .append_complete_turn_with_emotion(
                    &turn_request(&conversation, "turn-1", "hello", "committed answer"),
                    bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20)),
                )
                .unwrap();
            // Service drops here simulating "caller never learned the outcome".
        }
        let reopened = StorageService::initialize_with_roots(data_root, None).unwrap();
        let conversations = ConversationHistoryService::new(&reopened)
            .list("life-a")
            .unwrap();
        let conversation = &conversations[0];
        let retry = reopened
            .append_complete_turn_with_emotion(
                &turn_request(conversation, "turn-1", "hello", "regenerated answer"),
                bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20)),
            )
            .unwrap();
        assert!(retry.turn.replayed);
        assert_eq!(retry.turn.assistant_message.content, "committed answer");
        assert!(matches!(
            retry.emotion,
            EmotionCommitOutcome::Replayed { .. }
        ));
        let (messages, conv_rev, events, _, emotion_rev) = counts(&reopened, &conversation.id);
        assert_eq!(messages, 2);
        assert_eq!(conv_rev, 1);
        assert_eq!(events, 1);
        assert_eq!(emotion_rev, 1);
    }

    // ---------- F1 Blocker A: legacy turn never receives retroactive emotion ----------

    #[test]
    fn legacy_turn_composite_retry_is_missing_event_without_any_mutation() {
        let root = TestRoot::new("legacy-guard");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);

        // Commit the turn through the LEGACY non-emotion path.
        ConversationHistoryService::new(&service)
            .append_turn(
                crate::conversation::history::AppendConversationTurnRequest {
                    life_id: "life-a".into(),
                    conversation_id: conversation.id.clone(),
                    turn_id: "legacy-turn".into(),
                    user_content: "asked before D11-C".into(),
                    assistant_content: "answered before D11-C".into(),
                    expected_revision: None,
                },
            )
            .unwrap();
        let (messages, conv_rev, events, _, emotion_rev) = counts(&service, &conversation.id);
        assert_eq!((messages, conv_rev, events, emotion_rev), (2, 1, 0, 0));

        // Retry THAT SAME turn through the composite primitive with a
        // perfectly canonical transition.
        let error = service
            .append_complete_turn_with_emotion(
                &turn_request(
                    &conversation,
                    "legacy-turn",
                    "asked before D11-C",
                    "ignored",
                ),
                bound_transition(&conversation.id, "legacy-turn", 0, (40, -20), (40, -20)),
            )
            .unwrap_err();

        assert_eq!(
            error.code(),
            "EMOTION_TURN_EVENT_MISSING",
            "a legacy turn must be typed as missing-event, not backfilled"
        );
        // Nothing mutated anywhere: no backfill, no state advance.
        let (messages, conv_rev, events, _, emotion_rev) = counts(&service, &conversation.id);
        assert_eq!(messages, 2);
        assert_eq!(conv_rev, 1);
        assert_eq!(events, 0);
        assert_eq!(emotion_rev, 0);
    }

    #[test]
    fn conflicting_legacy_retry_after_governed_commit_stays_event_conflict() {
        // Proves the missing-event guard does not disturb governed replay:
        // once a turn HAS its canonical event, exact evidence still replays
        // and conflicting evidence still yields B1 EventConflict.
        let root = TestRoot::new("governed-replay-intact");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);
        service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "hello", "answer"),
                bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20)),
            )
            .unwrap();

        let replay = service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "hello", "regenerated"),
                bound_transition(&conversation.id, "turn-1", 0, (40, -20), (40, -20)),
            )
            .unwrap();
        assert!(replay.turn.replayed);
        assert!(matches!(
            replay.emotion,
            EmotionCommitOutcome::Replayed { .. }
        ));

        let conflict = bound_transition(&conversation.id, "turn-1", 0, (10, -5), (10, -5));
        let error = service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1", "hello", "answer"),
                conflict,
            )
            .unwrap_err();
        assert_eq!(error.code(), EmotionErrorCode::EventConflict.as_str());
    }

    // ---------- F1 Blocker B: shared validation parity ----------

    #[test]
    fn composite_rejects_invalid_requests_before_any_mutation() {
        let root = TestRoot::new("validation-parity");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);

        let over_limit =
            "界".repeat(crate::conversation::history::MAX_CONVERSATION_MESSAGE_CHARACTERS + 1);
        let mut requests: Vec<(String, AppendConversationTurnRequest)> = vec![
            (
                "empty user content".into(),
                crate::conversation::history::AppendConversationTurnRequest {
                    life_id: "life-a".into(),
                    conversation_id: conversation.id.clone(),
                    turn_id: "bad-empty-user".into(),
                    user_content: "   ".into(),
                    assistant_content: "assistant".into(),
                    expected_revision: None,
                },
            ),
            (
                "empty assistant content".into(),
                crate::conversation::history::AppendConversationTurnRequest {
                    life_id: "life-a".into(),
                    conversation_id: conversation.id.clone(),
                    turn_id: "bad-empty-assistant".into(),
                    user_content: "user".into(),
                    assistant_content: "".into(),
                    expected_revision: None,
                },
            ),
            (
                "over-limit user content".into(),
                crate::conversation::history::AppendConversationTurnRequest {
                    life_id: "life-a".into(),
                    conversation_id: conversation.id.clone(),
                    turn_id: "bad-long-user".into(),
                    user_content: over_limit.clone(),
                    assistant_content: "assistant".into(),
                    expected_revision: None,
                },
            ),
            (
                "over-limit assistant content".into(),
                crate::conversation::history::AppendConversationTurnRequest {
                    life_id: "life-a".into(),
                    conversation_id: conversation.id.clone(),
                    turn_id: "bad-long-assistant".into(),
                    user_content: "user".into(),
                    assistant_content: over_limit,
                    expected_revision: None,
                },
            ),
            (
                "invalid turn id".into(),
                crate::conversation::history::AppendConversationTurnRequest {
                    life_id: "life-a".into(),
                    conversation_id: conversation.id.clone(),
                    turn_id: "  ".into(),
                    user_content: "user".into(),
                    assistant_content: "assistant".into(),
                    expected_revision: None,
                },
            ),
            (
                "negative expected revision".into(),
                crate::conversation::history::AppendConversationTurnRequest {
                    life_id: "life-a".into(),
                    conversation_id: conversation.id.clone(),
                    turn_id: "bad-negative-revision".into(),
                    user_content: "user".into(),
                    assistant_content: "assistant".into(),
                    expected_revision: Some(-1),
                },
            ),
        ];

        for (label, request) in requests.drain(..) {
            let error = service
                .append_complete_turn_with_emotion(
                    &request,
                    bound_transition(&conversation.id, &request.turn_id, 0, (40, -20), (40, -20)),
                )
                .unwrap_err();
            let code = error.code();
            assert!(
                code == format!(
                    "{:?}",
                    crate::conversation::history::ConversationHistoryErrorCode::InvalidMessageContent
                ) || code == format!(
                    "{:?}",
                    crate::conversation::history::ConversationHistoryErrorCode::InvalidRequest
                ),
                "{label}: unexpected rejection category {code}"
            );
            // Zero mutation in either domain after every rejected case.
            let (messages, conv_rev, events, _, emotion_rev) = counts(&service, &conversation.id);
            assert_eq!(
                (messages, conv_rev, events, emotion_rev),
                (0, 0, 0, 0),
                "{label}"
            );
        }

        // Parity proof: the legacy path rejects each IDENTICAL request with
        // the same category, i.e. one shared validator serves both paths.
        let make_empty_user = || crate::conversation::history::AppendConversationTurnRequest {
            life_id: "life-a".into(),
            conversation_id: conversation.id.clone(),
            turn_id: "p-user".into(),
            user_content: " ".into(),
            assistant_content: "assistant".into(),
            expected_revision: None,
        };
        let legacy_error = ConversationHistoryService::new(&service)
            .append_turn(make_empty_user())
            .unwrap_err();
        let composite_error = service
            .append_complete_turn_with_emotion(
                &make_empty_user(),
                bound_transition(
                    &conversation.id,
                    &make_empty_user().turn_id,
                    0,
                    (40, -20),
                    (40, -20),
                ),
            )
            .unwrap_err();
        assert_eq!(composite_error.code(), format!("{:?}", legacy_error.code));

        let make_negative_rev = || crate::conversation::history::AppendConversationTurnRequest {
            life_id: "life-a".into(),
            conversation_id: conversation.id.clone(),
            turn_id: "p-rev".into(),
            user_content: "user".into(),
            assistant_content: "assistant".into(),
            expected_revision: Some(-3),
        };
        let legacy_error = ConversationHistoryService::new(&service)
            .append_turn(make_negative_rev())
            .unwrap_err();
        let composite_error = service
            .append_complete_turn_with_emotion(
                &make_negative_rev(),
                bound_transition(
                    &conversation.id,
                    &make_negative_rev().turn_id,
                    0,
                    (40, -20),
                    (40, -20),
                ),
            )
            .unwrap_err();
        assert_eq!(composite_error.code(), format!("{:?}", legacy_error.code));

        // Still zero writes after every validation case on both paths.
        let (_, conv_rev, events, _, emotion_rev) = counts(&service, &conversation.id);
        assert_eq!((conv_rev, events, emotion_rev), (0, 0, 0));
    }

    // ---------- F1 Blocker C: C2 identity seam compile-level proof ----------

    #[test]
    fn canonical_identity_helpers_are_crate_reachable_and_deterministic() {
        // Compile-level seam proof: these items are pub(crate); a sibling
        // domain module (as crate::conversation::service will be in C2) can
        // reference them without duplicating string formatting. Determinism
        // is re-proven here so the frozen formats cannot drift silently.
        let kind = super::CONVERSATION_EMOTION_SOURCE_KIND;
        assert_eq!(kind, "conversation_turn");
        let source_ref = super::conversation_emotion_source_ref("conv-1", "turn-7");
        let event_id = super::conversation_emotion_event_id("life-a", "conv-1", "turn-7");
        assert_eq!(source_ref, "conv-1:turn-7");
        assert_eq!(event_id, "conversation-emotion:life-a:conv-1:turn-7");
        assert_eq!(
            source_ref,
            super::conversation_emotion_source_ref("conv-1", "turn-7")
        );
        assert_eq!(
            event_id,
            super::conversation_emotion_event_id("life-a", "conv-1", "turn-7")
        );
    }
}
