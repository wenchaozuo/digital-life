//! D12-C1: crate-internal atomic conversation + emotion + relationship turn
//! commit.
//!
//! One governed conversation turn, its already-computed
//! [`crate::emotion::EmotionTransition`], and its already-computed
//! [`RelationshipTransition`] commit in ONE SQLite transaction by reusing the
//! frozen D11 conversation+emotion transaction core
//! ([`append_complete_turn_with_emotion_in_transaction`]) plus the B1
//! relationship persistence helper. The production chat orchestration switch
//! belongs to D12-C2; C1 is the primitive only.
//!
//! Relationship identity contract (deterministic helpers only — never parsed
//! back):
//! - source kind : [`CONVERSATION_RELATIONSHIP_SOURCE_KIND`] = "conversation_turn"
//! - source ref  : [`conversation_relationship_source_ref`] =
//!   "{conversation_id}:{turn_id}"
//! - event id    : [`conversation_relationship_event_id`] =
//!   "conversation-relationship:{life_id}:{subject_id}:{conversation_id}:{turn_id}"
//! - change reason: [`CONVERSATION_RELATIONSHIP_CHANGE_REASON`] =
//!   "successful_interaction"
//!
//! The conversation seam is frozen to the primary-user counterpart
//! ([`PRIMARY_USER_SUBJECT_ID`]); arbitrary visitor/NPC subjects stay on the
//! generic B1 multi-subject layer. Legacy turns are NEVER retroactively given
//! missing domain events: a D11-era turn (canonical emotion event present,
//! canonical relationship event absent) fails closed with
//! `RelationshipEventMissing`, and a pre-D11 turn keeps the frozen D11
//! `EmotionEventMissing` behavior.

use rusqlite::{Transaction, TransactionBehavior};

use super::conversation_emotion;
use super::relationship::commit_transition_in_transaction;
use super::{
    conversation,
    conversation_emotion::{
        append_complete_turn_with_emotion_in_transaction, validate_binding,
        ConversationEmotionCommitError,
    },
    StorageService,
};
use crate::conversation::history::{AppendConversationTurnRequest, AppendConversationTurnResult};
use crate::emotion::{EmotionCommitOutcome, EmotionError, EmotionTransition};
use crate::relationship::{
    RelationshipCommitOutcome, RelationshipError, RelationshipTransition, PRIMARY_USER_SUBJECT_ID,
};

/// Frozen source kind for conversation-generated relationship events.
pub(crate) const CONVERSATION_RELATIONSHIP_SOURCE_KIND: &str = "conversation_turn";

/// Frozen structured change reason for a successful interaction occurrence.
pub(crate) const CONVERSATION_RELATIONSHIP_CHANGE_REASON: &str = "successful_interaction";

/// Deterministic binding of one relationship event to one conversation turn.
/// Identity for equality/idempotency only; never parsed back into components.
pub(crate) fn conversation_relationship_source_ref(conversation_id: &str, turn_id: &str) -> String {
    format!("{conversation_id}:{turn_id}")
}

/// Deterministic canonical relationship event identity for one governed turn.
/// The C2 orchestrator must construct event ids through this helper so a
/// retried turn always resolves to the same relationship event.
pub(crate) fn conversation_relationship_event_id(
    life_id: &str,
    subject_id: &str,
    conversation_id: &str,
    turn_id: &str,
) -> String {
    format!("conversation-relationship:{life_id}:{subject_id}:{conversation_id}:{turn_id}")
}

/// Composite failure boundary preserving every cause domain so D12-C2 can map
/// each case intentionally. Failures are never collapsed into one generic
/// category.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConversationEmotionRelationshipCommitError {
    Conversation(crate::conversation::history::ConversationHistoryError),
    Emotion(EmotionError),
    Relationship(RelationshipError),
    /// The supplied EmotionTransition does not deterministically bind to the
    /// requested turn (the frozen D11 binding rules).
    EmotionBindingMismatch(String),
    /// The supplied RelationshipTransition does not satisfy the D12-C1
    /// canonical conversation seam contract (life, subject, kind, ref, event
    /// id, or change reason).
    RelationshipBindingMismatch(String),
    /// The requested turn exists but carries NO canonical emotion event — a
    /// pre-D11 legacy turn. Frozen D11 behavior: never backfilled.
    EmotionEventMissing(String),
    /// The requested turn exists with its canonical emotion event but NO
    /// canonical relationship event — a D11-era turn. Never backfilled.
    RelationshipEventMissing(String),
}

impl ConversationEmotionRelationshipCommitError {
    fn storage_lock_unavailable() -> Self {
        Self::Conversation(conversation::storage_unavailable())
    }

    /// Stable machine-readable category for the future C2 mapping.
    #[allow(dead_code)] // consumed by tests now and by the C2 orchestrator later
    pub(crate) fn code(&self) -> String {
        match self {
            // The frozen D11 convention derives the conversation category
            // ONLY from ConversationHistoryErrorCode — never from message,
            // recoverable, or full Debug output.
            Self::Conversation(error) => format!("{:?}", error.code),
            Self::Emotion(error) => error.code.as_str().to_string(),
            Self::Relationship(error) => error.code.as_str().to_string(),
            Self::EmotionBindingMismatch(_) => "EMOTION_TURN_BINDING_MISMATCH".to_string(),
            Self::RelationshipBindingMismatch(_) => {
                "RELATIONSHIP_TURN_BINDING_MISMATCH".to_string()
            }
            Self::EmotionEventMissing(_) => "EMOTION_TURN_EVENT_MISSING".to_string(),
            Self::RelationshipEventMissing(_) => "RELATIONSHIP_TURN_EVENT_MISSING".to_string(),
        }
    }
}

impl From<rusqlite::Error> for ConversationEmotionRelationshipCommitError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Conversation(conversation::storage_unavailable())
    }
}

impl From<ConversationEmotionCommitError> for ConversationEmotionRelationshipCommitError {
    fn from(error: ConversationEmotionCommitError) -> Self {
        match error {
            ConversationEmotionCommitError::Conversation(inner) => Self::Conversation(inner),
            ConversationEmotionCommitError::Emotion(inner) => Self::Emotion(inner),
            ConversationEmotionCommitError::BindingMismatch(detail) => {
                Self::EmotionBindingMismatch(detail)
            }
            // The shared D11 core can only surface this for a turn that
            // appeared between the composite existence checks and the core
            // (a race with a concurrent legacy commit). It keeps the frozen
            // semantics: no emotion backfill, and no relationship work.
            ConversationEmotionCommitError::EmotionEventMissing(detail) => {
                Self::EmotionEventMissing(detail)
            }
        }
    }
}

/// Result of one atomic triple-composite commit: all three domain outcomes
/// together. No frontend serialization; no IPC exposure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConversationEmotionRelationshipCommitOutcome {
    pub(crate) turn: AppendConversationTurnResult,
    pub(crate) emotion: EmotionCommitOutcome,
    pub(crate) relationship: RelationshipCommitOutcome,
}

/// Validate that the caller-supplied relationship transition satisfies the
/// FULL D12-C1 conversation seam contract BEFORE any write happens. Fail
/// closed; never rewrite caller-provided evidence to make it match.
fn validate_relationship_binding(
    request: &AppendConversationTurnRequest,
    transition: &RelationshipTransition,
) -> Result<(), ConversationEmotionRelationshipCommitError> {
    let mismatch = |detail: String| {
        ConversationEmotionRelationshipCommitError::RelationshipBindingMismatch(detail)
    };
    if transition.life_id != request.life_id {
        return Err(mismatch(
            "transition life_id must equal the conversation life_id.".to_string(),
        ));
    }
    if transition.subject_id != PRIMARY_USER_SUBJECT_ID {
        return Err(mismatch(format!(
            "transition subject_id must be {PRIMARY_USER_SUBJECT_ID}."
        )));
    }
    if transition.source.kind != CONVERSATION_RELATIONSHIP_SOURCE_KIND {
        return Err(mismatch(format!(
            "transition source kind must be {CONVERSATION_RELATIONSHIP_SOURCE_KIND}."
        )));
    }
    let expected_ref =
        conversation_relationship_source_ref(&request.conversation_id, &request.turn_id);
    if transition.source.reference != expected_ref {
        return Err(mismatch(
            "transition source reference must be the deterministic turn identity.".to_string(),
        ));
    }
    let expected_event_id = conversation_relationship_event_id(
        &request.life_id,
        PRIMARY_USER_SUBJECT_ID,
        &request.conversation_id,
        &request.turn_id,
    );
    if transition.event_id != expected_event_id {
        return Err(mismatch(
            "transition event id must be the canonical turn event identity.".to_string(),
        ));
    }
    if transition.change_reason != CONVERSATION_RELATIONSHIP_CHANGE_REASON {
        return Err(mismatch(format!(
            "transition change_reason must be {CONVERSATION_RELATIONSHIP_CHANGE_REASON}."
        )));
    }
    Ok(())
}

/// Bounded NON-MUTATING existence check for the canonical relationship event
/// of this turn. Replay equality itself stays the exclusive property of the
/// B1 semantic helpers.
fn relationship_event_exists(
    transaction: &Transaction<'_>,
    transition: &RelationshipTransition,
) -> Result<bool, rusqlite::Error> {
    transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM relationship_event
            WHERE event_id = ?1
               OR (life_id = ?2 AND subject_id = ?3 AND source_kind = ?4 AND source_ref = ?5)
        )",
        rusqlite::params![
            transition.event_id,
            transition.life_id,
            transition.subject_id,
            transition.source.kind,
            transition.source.reference,
        ],
        |row| row.get(0),
    )
}

/// Bounded NON-MUTATING existence check mirroring the frozen D11 guard so C1
/// can distinguish a pre-D11 legacy turn BEFORE invoking the shared core
/// (which would otherwise surface it as its own EmotionEventMissing).
#[allow(dead_code)]
fn emotion_event_exists(
    transaction: &Transaction<'_>,
    request: &AppendConversationTurnRequest,
) -> Result<bool, rusqlite::Error> {
    transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM emotion_event
            WHERE event_id = ?1
               OR (life_id = ?2 AND source_kind = ?3 AND source_ref = ?4)
        )",
        rusqlite::params![
            conversation_emotion::conversation_emotion_event_id(
                &request.life_id,
                &request.conversation_id,
                &request.turn_id
            ),
            request.life_id,
            conversation_emotion::CONVERSATION_EMOTION_SOURCE_KIND,
            conversation_emotion::conversation_emotion_source_ref(
                &request.conversation_id,
                &request.turn_id
            ),
        ],
        |row| row.get(0),
    )
}

/// Validate the D12 conversation, emotion, and relationship inputs before the
/// StorageService lock or SQLite transaction is acquired. Both the frozen D12
/// wrapper and the D13 four-domain primitive use this exact helper so their
/// invalid-input timing and binding rules cannot diverge.
pub(super) fn validate_append_complete_turn_with_emotion_and_relationship(
    request: &AppendConversationTurnRequest,
    emotion_transition: &EmotionTransition,
    relationship_transition: &RelationshipTransition,
) -> Result<(), ConversationEmotionRelationshipCommitError> {
    crate::conversation::history::validate_append_turn_request(request)
        .map_err(ConversationEmotionRelationshipCommitError::Conversation)?;
    validate_binding(request, emotion_transition).map_err(|detail| {
        ConversationEmotionRelationshipCommitError::EmotionBindingMismatch(match detail {
            ConversationEmotionCommitError::BindingMismatch(text) => text,
            other => format!("unexpected binding failure: {other:?}"),
        })
    })?;
    validate_relationship_binding(request, relationship_transition)?;
    Ok(())
}

/// Caller-owned D12 triple transaction core. It performs the complete frozen
/// conversation + emotion + relationship semantic operation inside the
/// supplied transaction, but never begins, commits, or explicitly rolls back
/// one. An uncommitted transaction is rolled back by rusqlite when dropped.
pub(super) fn append_complete_turn_with_emotion_and_relationship_in_transaction(
    transaction: &Transaction<'_>,
    request: &AppendConversationTurnRequest,
    emotion_transition: EmotionTransition,
    relationship_transition: RelationshipTransition,
) -> Result<ConversationEmotionRelationshipCommitOutcome, ConversationEmotionRelationshipCommitError>
{
    // On an EXISTING turn, the frozen conflict semantics take precedence
    // FIRST: a same turn_id with different stored user content is ALWAYS
    // a Conversation TurnIdConflict, regardless of which governance era
    // produced the turn. Only identical content may proceed to the D12
    // legacy-event classification below. This duplicate NON-MUTATING
    // guard exists solely for classification precedence; the frozen D11
    // shared core re-performs its own check unchanged.
    let existing_turn = conversation::load_turn(
        transaction,
        &request.life_id,
        &request.conversation_id,
        &request.turn_id,
    )
    .map_err(ConversationEmotionRelationshipCommitError::Conversation)?;
    if let Some(existing) = &existing_turn {
        if existing.user_message.content != request.user_content {
            return Err(ConversationEmotionRelationshipCommitError::Conversation(
                crate::conversation::history::ConversationHistoryError::new(
                    crate::conversation::history::ConversationHistoryErrorCode::TurnIdConflict,
                ),
            ));
        }
    }
    // With content verified identical, distinguish pre-D11 / D11-only /
    // full-D12 with bounded non-mutating existence checks BEFORE invoking
    // any writer: emotion missing → EmotionEventMissing (frozen D11
    // behavior); else relationship missing → RelationshipEventMissing
    // (hard C1 invariant, no retroactive backfill).
    if existing_turn.is_some()
        && !emotion_event_exists(transaction, request)
            .map_err(ConversationEmotionRelationshipCommitError::from)?
    {
        return Err(
            ConversationEmotionRelationshipCommitError::EmotionEventMissing(
                "the conversation turn has no governed emotion event to replay.".to_string(),
            ),
        );
    }
    if existing_turn.is_some()
        && !relationship_event_exists(transaction, &relationship_transition)
            .map_err(ConversationEmotionRelationshipCommitError::from)?
    {
        return Err(
            ConversationEmotionRelationshipCommitError::RelationshipEventMissing(
                "the governed turn has no canonical relationship event; D11-era turns are never backfilled.".to_string(),
            ),
        );
    }

    // 1. Frozen D11 core: conversation + emotion inside THIS transaction,
    //    WITHOUT committing. Its replay semantics, legacy guard, message
    //    inserts, and CAS remain the single shared implementation.
    let outcome =
        append_complete_turn_with_emotion_in_transaction(transaction, request, emotion_transition)
            .map_err(ConversationEmotionRelationshipCommitError::from)?;

    // 2. B1 relationship persistence INSIDE THE SAME transaction. B1
    //    remains the single replay-equality/CAS authority; a revision or
    //    event conflict here aborts everything above via rollback-on-drop.
    let relationship = commit_transition_in_transaction(transaction, relationship_transition)
        .map_err(ConversationEmotionRelationshipCommitError::Relationship)?;

    Ok(ConversationEmotionRelationshipCommitOutcome {
        turn: outcome.turn,
        emotion: outcome.emotion,
        relationship,
    })
}

impl StorageService {
    /// The ONE atomic primitive for a fully governed D12 conversation turn:
    /// conversation messages + revision + emotion_event + emotion_state +
    /// relationship_event + relationship_state in exactly ONE SQLite
    /// transaction. Any failure before the final commit leaves ALL THREE
    /// domains unchanged. Not exposed via Tauri in C1; the production flow
    /// switches to it in D12-C2.
    #[allow(dead_code)] // C1 seam; the production orchestrator switches to it in D12-C2.
    pub(crate) fn append_complete_turn_with_emotion_and_relationship(
        &self,
        request: &AppendConversationTurnRequest,
        emotion_transition: EmotionTransition,
        relationship_transition: RelationshipTransition,
    ) -> Result<
        ConversationEmotionRelationshipCommitOutcome,
        ConversationEmotionRelationshipCommitError,
    > {
        validate_append_complete_turn_with_emotion_and_relationship(
            request,
            &emotion_transition,
            &relationship_transition,
        )?;

        let mut state = self
            .state()
            .map_err(|_| ConversationEmotionRelationshipCommitError::storage_lock_unavailable())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ConversationEmotionRelationshipCommitError::from)?;
        let outcome = append_complete_turn_with_emotion_and_relationship_in_transaction(
            &transaction,
            request,
            emotion_transition,
            relationship_transition,
        )?;
        // 3. Single COMMIT. There is no intermediate commit between domains.
        transaction
            .commit()
            .map_err(ConversationEmotionRelationshipCommitError::from)?;
        Ok(outcome)
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
    use crate::conversation::history::{
        AppendConversationTurnRequest, ConversationHistoryError, ConversationHistoryErrorCode,
        ConversationHistoryService, ConversationRecord,
    };
    use crate::emotion::{
        EmotionErrorCode, EmotionEventSource, EmotionTransition, INITIAL_POLICY_VERSION,
    };
    use crate::relationship::{
        RelationshipDimensions, RelationshipErrorCode, RelationshipEventSource,
    };
    use crate::storage::conversation_emotion::{
        conversation_emotion_event_id, conversation_emotion_source_ref,
        CONVERSATION_EMOTION_SOURCE_KIND,
    };
    use crate::storage::{unique_suffix, LifeIdentityRecord, PersonaTemplateRecord};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("digital-life-conv-rel-{name}-{}", unique_suffix()));
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
                created_at: "2026-08-25T00:00:00.000Z".into(),
                version: 1,
                body_id: "body-a".into(),
                persona_id: "persona-a".into(),
                persona_version: 1,
            })
            .unwrap();
        service
    }

    fn create_conversation(service: &StorageService) -> ConversationRecord {
        ConversationHistoryService::new(service)
            .create(crate::conversation::history::CreateConversationRequest {
                life_id: "life-a".into(),
                title: "Composite".into(),
            })
            .unwrap()
    }

    const EVENT_TIME: &str = "2026-08-25T12:00:00.000Z";

    fn emotion_transition(
        conversation_id: &str,
        turn_id: &str,
        expected_revision: i64,
    ) -> EmotionTransition {
        EmotionTransition::new(
            conversation_emotion_event_id("life-a", conversation_id, turn_id),
            "life-a",
            EmotionEventSource::new(
                CONVERSATION_EMOTION_SOURCE_KIND,
                conversation_emotion_source_ref(conversation_id, turn_id),
            ),
            40,
            -20,
            expected_revision,
            40,
            -20,
            INITIAL_POLICY_VERSION,
            EVENT_TIME,
        )
        .unwrap()
    }

    /// The canonical relationship transition for one turn, with optional
    /// field mutations for binding-mismatch cases.
    fn relationship_transition_for(
        conversation_id: &str,
        turn_id: &str,
        expected_revision: i64,
    ) -> RelationshipTransition {
        RelationshipTransition::new(
            conversation_relationship_event_id(
                "life-a",
                PRIMARY_USER_SUBJECT_ID,
                conversation_id,
                turn_id,
            ),
            "life-a",
            PRIMARY_USER_SUBJECT_ID,
            RelationshipEventSource::new(
                CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                conversation_relationship_source_ref(conversation_id, turn_id),
            ),
            CONVERSATION_RELATIONSHIP_CHANGE_REASON,
            RelationshipDimensions {
                familiarity: 1,
                ..RelationshipDimensions::neutral()
            },
            expected_revision,
            RelationshipDimensions {
                familiarity: 1,
                ..RelationshipDimensions::neutral()
            },
            INITIAL_POLICY_VERSION,
            EVENT_TIME,
        )
        .unwrap()
    }

    fn turn_request(
        conversation: &ConversationRecord,
        turn_id: &str,
    ) -> AppendConversationTurnRequest {
        AppendConversationTurnRequest {
            life_id: "life-a".into(),
            conversation_id: conversation.id.clone(),
            turn_id: turn_id.into(),
            user_content: "hello".into(),
            assistant_content: "hi there".into(),
            expected_revision: None,
        }
    }

    /// Full-domain count probe: (messages, conv_rev, emotion_events,
    /// emotion_rev, rel_events, rel_rev).
    fn all_counts(
        service: &StorageService,
        conversation_id: &str,
    ) -> (i64, i64, i64, i64, i64, i64) {
        let state = service.state().unwrap();
        let messages: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM conversation_message WHERE conversation_id = ?1",
                [conversation_id],
                |row| row.get(0),
            )
            .unwrap();
        let conv_rev: i64 = state
            .connection
            .query_row(
                "SELECT revision FROM conversation WHERE id = ?1",
                [conversation_id],
                |row| row.get(0),
            )
            .unwrap();
        let emotion_events: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM emotion_event", [], |row| row.get(0))
            .unwrap();
        let emotion_rev: i64 = state
            .connection
            .query_row(
                "SELECT revision FROM emotion_state WHERE life_id='life-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let rel_events: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM relationship_event", [], |row| {
                row.get(0)
            })
            .unwrap();
        let rel_rev: i64 = state
            .connection
            .query_row(
                "SELECT revision FROM relationship_state
                 WHERE life_id='life-a' AND subject_id='primary_user'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        (
            messages,
            conv_rev,
            emotion_events,
            emotion_rev,
            rel_events,
            rel_rev,
        )
    }

    fn commit_composite(
        service: &StorageService,
        conversation: &ConversationRecord,
        turn_id: &str,
        emotion_expected_revision: i64,
        relationship_expected_revision: i64,
    ) -> Result<
        ConversationEmotionRelationshipCommitOutcome,
        ConversationEmotionRelationshipCommitError,
    > {
        service.append_complete_turn_with_emotion_and_relationship(
            &turn_request(conversation, turn_id),
            emotion_transition(&conversation.id, turn_id, emotion_expected_revision),
            relationship_transition_for(&conversation.id, turn_id, relationship_expected_revision),
        )
    }

    // ---------- A/B. fresh new turn commits all three domains exactly once ----

    #[test]
    fn fresh_turn_commits_all_three_domains_exactly_once() {
        let root = TestRoot::new("fresh");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);

        let outcome = commit_composite(&service, &conversation, "turn-1", 0, 0).unwrap();

        assert!(!outcome.turn.replayed);
        assert_eq!(outcome.turn.conversation_revision, 1);
        assert!(matches!(
            outcome.emotion,
            EmotionCommitOutcome::Committed { .. }
        ));
        assert!(matches!(
            outcome.relationship,
            RelationshipCommitOutcome::Committed { .. }
        ));
        // B (policy isolation): only the SUPPLIED transition result is
        // persisted — C1 never computes policy. familiarity +1 exactly.
        let state = service.state().unwrap();
        let familiarity: i32 = state
            .connection
            .query_row(
                "SELECT familiarity FROM relationship_state
                 WHERE life_id='life-a' AND subject_id='primary_user'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(familiarity, 1);
        drop(state);
        let (messages, conv_rev, emotion_events, emotion_rev, rel_events, rel_rev) =
            all_counts(&service, &conversation.id);
        assert_eq!(
            (
                messages,
                conv_rev,
                emotion_events,
                emotion_rev,
                rel_events,
                rel_rev
            ),
            (2, 1, 1, 1, 1, 1)
        );
    }

    // ---------- C/L. exact full-D12 replay ----------

    #[test]
    fn exact_replay_returns_all_three_replayed_without_any_mutation() {
        let root = TestRoot::new("replay");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);
        commit_composite(&service, &conversation, "turn-1", 0, 0).unwrap();
        let before = all_counts(&service, &conversation.id);

        let replay = commit_composite(&service, &conversation, "turn-1", 0, 0).unwrap();

        assert!(replay.turn.replayed);
        assert_eq!(replay.turn.conversation_revision, 1);
        assert!(matches!(
            replay.emotion,
            EmotionCommitOutcome::Replayed { .. }
        ));
        assert!(matches!(
            replay.relationship,
            RelationshipCommitOutcome::Replayed { .. }
        ));
        let after = all_counts(&service, &conversation.id);
        assert_eq!(before, after);
        // No duplicate message/event rows.
        assert_eq!(after.0, 2);
        assert_eq!(after.2, 1);
        assert_eq!(after.4, 1);
    }

    // ---------- D. relationship revision conflict is fully atomic ----------

    #[test]
    fn relationship_revision_conflict_leaves_every_domain_unchanged() {
        let root = TestRoot::new("rel-rev-conflict");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);

        // Stale relationship revision (expected 5 vs actual 0) must abort the
        // ENTIRE composite attempt.
        let error = commit_composite(&service, &conversation, "turn-1", 0, 5).unwrap_err();
        assert_eq!(
            error.code(),
            RelationshipErrorCode::RevisionConflict.as_str()
        );
        let counts = all_counts(&service, &conversation.id);
        assert_eq!(
            counts,
            (0, 0, 0, 0, 0, 0),
            "no conversation/emotion/relationship mutation may survive"
        );
    }

    // ---------- E. emotion revision conflict is fully atomic ----------

    #[test]
    fn emotion_revision_conflict_leaves_every_domain_unchanged() {
        let root = TestRoot::new("emotion-rev-conflict");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);

        let error = commit_composite(&service, &conversation, "turn-1", 7, 0).unwrap_err();
        assert_eq!(error.code(), EmotionErrorCode::RevisionConflict.as_str());
        let counts = all_counts(&service, &conversation.id);
        assert_eq!(counts, (0, 0, 0, 0, 0, 0));
    }

    // ---------- F. relationship binding mismatch: table-driven zero writes ---

    #[test]
    fn relationship_binding_mismatches_fail_closed_with_zero_writes() {
        let root = TestRoot::new("rel-binding");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);
        let request = turn_request(&conversation, "turn-1");

        let base = || relationship_transition_for(&conversation.id, "turn-1", 0);

        let cases: Vec<(&str, RelationshipTransition)> = vec![
            ("life mismatch", {
                RelationshipTransition::new(
                    base().event_id,
                    "other-life",
                    base().subject_id.clone(),
                    base().source.clone(),
                    base().change_reason.clone(),
                    base().deltas,
                    base().expected_revision,
                    base().next,
                    base().policy_version,
                    base().event_time.clone(),
                )
                .unwrap()
            }),
            ("subject not primary_user", {
                RelationshipTransition::new(
                    conversation_relationship_event_id(
                        "life-a",
                        "npc_x",
                        &conversation.id,
                        "turn-1",
                    ),
                    "life-a",
                    "npc_x",
                    RelationshipEventSource::new(
                        CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                        conversation_relationship_source_ref(&conversation.id, "turn-1"),
                    ),
                    CONVERSATION_RELATIONSHIP_CHANGE_REASON,
                    base().deltas,
                    0,
                    base().next,
                    INITIAL_POLICY_VERSION,
                    EVENT_TIME,
                )
                .unwrap()
            }),
            ("source kind mismatch", {
                RelationshipTransition::new(
                    base().event_id,
                    "life-a",
                    PRIMARY_USER_SUBJECT_ID,
                    RelationshipEventSource::new(
                        "some_other_kind",
                        conversation_relationship_source_ref(&conversation.id, "turn-1"),
                    ),
                    CONVERSATION_RELATIONSHIP_CHANGE_REASON,
                    base().deltas,
                    0,
                    base().next,
                    INITIAL_POLICY_VERSION,
                    EVENT_TIME,
                )
                .unwrap()
            }),
            ("source ref mismatch", {
                RelationshipTransition::new(
                    base().event_id,
                    "life-a",
                    PRIMARY_USER_SUBJECT_ID,
                    RelationshipEventSource::new(
                        CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                        format!("{}:wrong-turn", conversation.id),
                    ),
                    CONVERSATION_RELATIONSHIP_CHANGE_REASON,
                    base().deltas,
                    0,
                    base().next,
                    INITIAL_POLICY_VERSION,
                    EVENT_TIME,
                )
                .unwrap()
            }),
            ("event id mismatch", {
                RelationshipTransition::new(
                    format!(
                        "conversation-relationship:life-a:primary_user:{}:other-turn",
                        conversation.id
                    ),
                    "life-a",
                    PRIMARY_USER_SUBJECT_ID,
                    RelationshipEventSource::new(
                        CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                        conversation_relationship_source_ref(&conversation.id, "turn-1"),
                    ),
                    CONVERSATION_RELATIONSHIP_CHANGE_REASON,
                    base().deltas,
                    0,
                    base().next,
                    INITIAL_POLICY_VERSION,
                    EVENT_TIME,
                )
                .unwrap()
            }),
            ("change reason mismatch", {
                RelationshipTransition::new(
                    base().event_id,
                    "life-a",
                    PRIMARY_USER_SUBJECT_ID,
                    RelationshipEventSource::new(
                        CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                        conversation_relationship_source_ref(&conversation.id, "turn-1"),
                    ),
                    "policy_other_reason",
                    base().deltas,
                    0,
                    base().next,
                    INITIAL_POLICY_VERSION,
                    EVENT_TIME,
                )
                .unwrap()
            }),
        ];

        for (label, transition) in cases {
            let error = service
                .append_complete_turn_with_emotion_and_relationship(
                    &request,
                    emotion_transition(&conversation.id, "turn-1", 0),
                    transition,
                )
                .unwrap_err();
            assert_eq!(
                error.code(),
                "RELATIONSHIP_TURN_BINDING_MISMATCH",
                "{label}"
            );
            let counts = all_counts(&service, &conversation.id);
            assert_eq!(counts, (0, 0, 0, 0, 0, 0), "{label}");
        }
    }

    // ---------- G. D11-only existing turn → RelationshipEventMissing ---------

    #[test]
    fn d11_only_turn_is_never_backfilled_with_a_relationship_event() {
        let root = TestRoot::new("d11-only-turn");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);

        // Commit via the frozen D11 primitive: conversation + emotion only.
        service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1"),
                emotion_transition(&conversation.id, "turn-1", 0),
            )
            .unwrap();
        let before = all_counts(&service, &conversation.id);
        assert_eq!(before.4, 0, "no relationship event yet");

        let error = commit_composite(&service, &conversation, "turn-1", 0, 0).unwrap_err();
        assert_eq!(error.code(), "RELATIONSHIP_TURN_EVENT_MISSING");

        // Hard invariant: no retroactive relationship backfill of any kind.
        let after = all_counts(&service, &conversation.id);
        assert_eq!(before, after);
        assert_eq!(after.4, 0, "relationship event count unchanged");
        assert_eq!(after.5, 0, "relationship revision unchanged");
    }

    // ---------- H. pre-D11 legacy turn → EmotionEventMissing -----------------

    #[test]
    fn pre_d11_legacy_turn_keeps_frozen_emotion_missing_behavior() {
        let root = TestRoot::new("pre-d11-turn");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);

        ConversationHistoryService::new(&service)
            .append_turn(turn_request(&conversation, "legacy-turn"))
            .unwrap();
        let before = all_counts(&service, &conversation.id);
        assert_eq!((before.2, before.4), (0, 0));

        let error = commit_composite(&service, &conversation, "legacy-turn", 0, 0).unwrap_err();
        assert_eq!(error.code(), "EMOTION_TURN_EVENT_MISSING");

        let after = all_counts(&service, &conversation.id);
        assert_eq!(before, after);
        assert_eq!(after.4, 0, "no retroactive relationship either");
    }

    // ---------- I. relationship event conflict preserved ----------

    #[test]
    fn relationship_event_collision_is_typed_conflict_with_no_mutation() {
        let root = TestRoot::new("rel-event-conflict");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);
        // Seed an INCOMPATIBLE canonical relationship event directly through
        // B1 with the same event identity but different evidence.
        let conflicting = RelationshipTransition::new(
            conversation_relationship_event_id(
                "life-a",
                PRIMARY_USER_SUBJECT_ID,
                &conversation.id,
                "turn-1",
            ),
            "life-a",
            PRIMARY_USER_SUBJECT_ID,
            RelationshipEventSource::new(
                CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                conversation_relationship_source_ref(&conversation.id, "turn-1"),
            ),
            CONVERSATION_RELATIONSHIP_CHANGE_REASON,
            RelationshipDimensions {
                familiarity: 9,
                ..RelationshipDimensions::neutral()
            },
            0,
            RelationshipDimensions {
                familiarity: 9,
                ..RelationshipDimensions::neutral()
            },
            INITIAL_POLICY_VERSION,
            EVENT_TIME,
        )
        .unwrap();
        <StorageService as crate::relationship::RelationshipRepository>::commit_transition(
            &service,
            conflicting,
        )
        .unwrap();
        let before = all_counts(&service, &conversation.id);

        // Now the composite attempt supplies DIFFERENT evidence under the
        // same canonical identity: B1 must type it EventConflict and C1 must
        // preserve that (never transform a conflict into a replay). Note the
        // turn does not exist, so the composite proceeds to write; the
        // relationship writer fails INSIDE the transaction and everything
        // rolls back.
        let error = commit_composite(&service, &conversation, "turn-1", 0, 0).unwrap_err();
        assert_eq!(error.code(), RelationshipErrorCode::EventConflict.as_str());

        let after = all_counts(&service, &conversation.id);
        assert_eq!(after.0, 0, "no conversation message survived");
        assert_eq!(after.1, 0, "conversation revision unchanged");
        assert_eq!(after.2, 0, "no emotion event survived");
        assert_eq!(after.3, 0, "emotion revision unchanged");
        assert_eq!(after.4, before.4, "relationship event count unchanged");
        assert_eq!(after.5, before.5, "relationship revision unchanged");
    }

    // ---------- J. conversation expected_revision conflict ----------

    #[test]
    fn conversation_expected_revision_conflict_leaves_every_domain_unchanged() {
        let root = TestRoot::new("conv-rev-conflict");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);

        let mut request = turn_request(&conversation, "turn-1");
        request.expected_revision = Some(42);
        let error = service
            .append_complete_turn_with_emotion_and_relationship(
                &request,
                emotion_transition(&conversation.id, "turn-1", 0),
                relationship_transition_for(&conversation.id, "turn-1", 0),
            )
            .unwrap_err();
        match error {
            ConversationEmotionRelationshipCommitError::Conversation(inner) => {
                assert_eq!(
                    inner.code,
                    ConversationHistoryErrorCode::ConversationChangedDuringRequest
                );
            }
            other => panic!("expected conversation error, got {other:?}"),
        }
        let counts = all_counts(&service, &conversation.id);
        assert_eq!(counts, (0, 0, 0, 0, 0, 0));
        let _ = ConversationHistoryError::new;
    }

    // ---------- K. complete transaction failure after authority work ---------

    #[test]
    fn forced_message_failure_rolls_back_all_three_domains() {
        let root = TestRoot::new("rollback-all");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);
        // Force ONLY the user-message INSERT to fail AFTER both domain
        // writers have already mutated rows INSIDE the transaction.
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

        let error = commit_composite(&service, &conversation, "turn-1", 0, 0).unwrap_err();

        match error {
            ConversationEmotionRelationshipCommitError::Conversation(_) => {}
            other => panic!("expected conversation error, got {other:?}"),
        }
        // NO partial authority: all three domains fully rolled back.
        let counts = all_counts(&service, &conversation.id);
        assert_eq!(counts, (0, 0, 0, 0, 0, 0));
    }

    // ---------- identity helpers determinism ----------

    #[test]
    fn canonical_identity_helpers_are_frozen_and_deterministic() {
        assert_eq!(CONVERSATION_RELATIONSHIP_SOURCE_KIND, "conversation_turn");
        assert_eq!(
            CONVERSATION_RELATIONSHIP_CHANGE_REASON,
            "successful_interaction"
        );
        let source_ref = conversation_relationship_source_ref("conv-1", "turn-7");
        let event_id =
            conversation_relationship_event_id("life-a", "primary_user", "conv-1", "turn-7");
        assert_eq!(source_ref, "conv-1:turn-7");
        assert_eq!(
            event_id,
            "conversation-relationship:life-a:primary_user:conv-1:turn-7"
        );
        assert_eq!(
            source_ref,
            conversation_relationship_source_ref("conv-1", "turn-7")
        );
        assert_eq!(
            event_id,
            conversation_relationship_event_id("life-a", "primary_user", "conv-1", "turn-7")
        );
    }

    // ---------- concurrency proof ----------

    #[test]
    fn two_competing_triple_writers_have_one_winner_and_no_mixed_state() {
        let root = TestRoot::new("triple-race");
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
                created_at: "2026-08-25T00:00:00.000Z".into(),
                version: 1,
                body_id: "body-a".into(),
                persona_id: "persona-a".into(),
                persona_version: 1,
            })
            .unwrap();
        let second = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        let conversation = create_conversation(&first);

        // The two writers race the SAME turn id but carry INCOMPATIBLE
        // relationship evidence under the same canonical identity, so exactly
        // one governed commit may win and the loser must receive a typed
        // conflict — never a silent replay of foreign evidence.
        let incompatible_relationship = RelationshipTransition::new(
            conversation_relationship_event_id(
                "life-a",
                PRIMARY_USER_SUBJECT_ID,
                &conversation.id,
                "race-turn",
            ),
            "life-a",
            PRIMARY_USER_SUBJECT_ID,
            RelationshipEventSource::new(
                CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                conversation_relationship_source_ref(&conversation.id, "race-turn"),
            ),
            CONVERSATION_RELATIONSHIP_CHANGE_REASON,
            RelationshipDimensions {
                familiarity: 5,
                ..RelationshipDimensions::neutral()
            },
            0,
            RelationshipDimensions {
                familiarity: 5,
                ..RelationshipDimensions::neutral()
            },
            INITIAL_POLICY_VERSION,
            EVENT_TIME,
        )
        .unwrap();

        let first = Arc::new(first);
        let second = Arc::new(second);
        let barrier = Arc::new(Barrier::new(3));
        let (b1, b2) = (barrier.clone(), barrier.clone());
        let (svc_a, svc_b) = (first.clone(), second.clone());
        let conv_a = conversation.clone();
        let conv_b = conversation.clone();
        let writer_a = thread::spawn(move || {
            b1.wait();
            commit_composite(&svc_a, &conv_a, "race-turn", 0, 0)
        });
        let writer_b = thread::spawn(move || {
            b2.wait();
            let request = turn_request(&conv_b, "race-turn");
            svc_b.append_complete_turn_with_emotion_and_relationship(
                &request,
                emotion_transition(&conv_b.id, "race-turn", 0),
                incompatible_relationship,
            )
        });
        barrier.wait();
        let outcome_a = writer_a.join().unwrap();
        let outcome_b = writer_b.join().unwrap();

        let won_a = outcome_a.is_ok();
        let won_b = outcome_b.is_ok();
        assert_eq!(
            won_a as u8 + won_b as u8,
            1,
            "exactly one competing triple-composite writer may win"
        );
        // The loser's incompatible relationship evidence must surface as a
        // typed B1 conflict (or, if it lost the turn race itself, a typed
        // conversation/missing-event error) — never silent success.
        let loser = if won_a {
            outcome_b.unwrap_err()
        } else {
            outcome_a.unwrap_err()
        };
        let loser_code = loser.code();
        assert!(
            loser_code == RelationshipErrorCode::RevisionConflict.as_str()
                || loser_code == RelationshipErrorCode::EventConflict.as_str()
                || loser_code == EmotionErrorCode::RevisionConflict.as_str()
                || loser_code == format!("{:?}", ConversationHistoryErrorCode::TurnIdConflict)
                || loser_code == "EMOTION_TURN_EVENT_MISSING"
                || loser_code == "RELATIONSHIP_TURN_EVENT_MISSING",
            "unexpected loser code: {loser_code}"
        );

        // No mixed state: every domain reflects exactly ONE attempt.
        let counts = all_counts(&first, &conversation.id);
        assert_eq!(
            counts,
            (2, 1, 1, 1, 1, 1),
            "exactly one turn's worth of rows across all three domains"
        );
    }

    // ---------- F1 regression: replay precedence over legacy classification --

    /// Builds a composite request with content that differs from the seeded
    /// turn ("hello") while keeping the same turn_id.
    fn conflicting_content_request(
        conversation: &ConversationRecord,
        turn_id: &str,
    ) -> AppendConversationTurnRequest {
        AppendConversationTurnRequest {
            life_id: "life-a".into(),
            conversation_id: conversation.id.clone(),
            turn_id: turn_id.into(),
            user_content: "DIFFERENT user content".into(),
            assistant_content: "ignored".into(),
            expected_revision: None,
        }
    }

    fn assert_turn_id_conflict(error: ConversationEmotionRelationshipCommitError, label: &str) {
        match error {
            ConversationEmotionRelationshipCommitError::Conversation(inner) => {
                assert_eq!(
                    inner.code,
                    ConversationHistoryErrorCode::TurnIdConflict,
                    "{label}"
                );
            }
            other => panic!("{label}: expected Conversation(TurnIdConflict), got {other:?}"),
        }
    }

    #[test]
    fn f1_pre_d11_turn_with_different_content_is_turn_conflict_not_missing_event() {
        let root = TestRoot::new("f1-pre-d11-conflict");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);

        // Pre-D11 era: the turn exists with NO emotion and NO relationship.
        ConversationHistoryService::new(&service)
            .append_turn(turn_request(&conversation, "legacy-turn"))
            .unwrap();
        let before = all_counts(&service, &conversation.id);

        let error = service
            .append_complete_turn_with_emotion_and_relationship(
                &conflicting_content_request(&conversation, "legacy-turn"),
                emotion_transition(&conversation.id, "legacy-turn", 0),
                relationship_transition_for(&conversation.id, "legacy-turn", 0),
            )
            .unwrap_err();

        // Content conflict takes precedence over EmotionEventMissing.
        assert_turn_id_conflict(error, "pre-D11 different content");
        let after = all_counts(&service, &conversation.id);
        assert_eq!(before, after, "zero mutation of any domain");
    }

    #[test]
    fn f1_d11_only_turn_with_different_content_is_turn_conflict_not_relationship_missing() {
        let root = TestRoot::new("f1-d11-only-conflict");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);

        // D11-only era: conversation + canonical emotion, no relationship.
        service
            .append_complete_turn_with_emotion(
                &turn_request(&conversation, "turn-1"),
                emotion_transition(&conversation.id, "turn-1", 0),
            )
            .unwrap();
        let before = all_counts(&service, &conversation.id);
        assert_eq!(before.4, 0);

        let error = service
            .append_complete_turn_with_emotion_and_relationship(
                &conflicting_content_request(&conversation, "turn-1"),
                emotion_transition(&conversation.id, "turn-1", 0),
                relationship_transition_for(&conversation.id, "turn-1", 0),
            )
            .unwrap_err();

        // Content conflict takes precedence over RelationshipEventMissing.
        assert_turn_id_conflict(error, "D11-only different content");
        let after = all_counts(&service, &conversation.id);
        assert_eq!(
            before, after,
            "no relationship/emotion/conversation mutation"
        );
    }

    #[test]
    fn f1_full_d12_turn_with_different_content_is_turn_conflict() {
        let root = TestRoot::new("f1-full-d12-conflict");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service);
        commit_composite(&service, &conversation, "turn-1", 0, 0).unwrap();
        let before = all_counts(&service, &conversation.id);

        let error = service
            .append_complete_turn_with_emotion_and_relationship(
                &conflicting_content_request(&conversation, "turn-1"),
                emotion_transition(&conversation.id, "turn-1", 0),
                relationship_transition_for(&conversation.id, "turn-1", 0),
            )
            .unwrap_err();

        assert_turn_id_conflict(error, "full-D12 different content");
        let after = all_counts(&service, &conversation.id);
        assert_eq!(after.0, before.0, "no duplicate messages");
        assert_eq!(after.1, before.1, "conversation revision unchanged");
        assert_eq!(after.2, before.2, "no extra emotion event");
        assert_eq!(after.3, before.3, "emotion revision unchanged");
        assert_eq!(after.4, before.4, "no extra relationship event");
        assert_eq!(after.5, before.5, "relationship revision unchanged");
    }

    // ---------- F1 regression: stable composite conversation code -------------

    #[test]
    fn f1_conversation_code_is_stable_category_from_error_code() {
        let cases = [
            (
                ConversationHistoryErrorCode::TurnIdConflict,
                "TurnIdConflict",
            ),
            (
                ConversationHistoryErrorCode::ConversationChangedDuringRequest,
                "ConversationChangedDuringRequest",
            ),
        ];
        for (code, expected) in cases {
            let error = ConversationEmotionRelationshipCommitError::Conversation(
                crate::conversation::history::ConversationHistoryError::new(code),
            );
            let category = error.code();
            assert_eq!(category, expected, "stable code for {category}");
            // The frozen D11 convention derives the category ONLY from
            // error.code — never from message/recoverable/full Debug output.
            assert!(
                !category.contains("ConversationHistoryError"),
                "must not leak struct Debug: {category}"
            );
            assert!(
                !category.contains("message"),
                "must not leak message text: {category}"
            );
            assert!(
                !category.contains("recoverable"),
                "must not leak recoverable flag: {category}"
            );
        }
    }
}
