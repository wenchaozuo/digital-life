//! D13-C1: one atomic conversation + emotion + relationship + experience turn.
//!
//! This module is a crate-internal storage primitive only. It composes the
//! frozen D12 caller-owned triple core, the frozen B2 conversation-to-episode
//! builder, and the frozen B1 caller-owned episode persistence helper inside
//! exactly one SQLite IMMEDIATE transaction. Production conversation cutover
//! belongs to D13-C2.

use rusqlite::TransactionBehavior;

use super::{
    conversation,
    conversation_relationship::{
        append_complete_turn_with_emotion_and_relationship_in_transaction,
        validate_append_complete_turn_with_emotion_and_relationship,
        ConversationEmotionRelationshipCommitError,
    },
    experience_episode::commit_episode_in_transaction,
    StorageService,
};
use crate::conversation::history::{
    AppendConversationTurnRequest, AppendConversationTurnResult, ConversationHistoryError,
};
use crate::emotion::{EmotionCommitOutcome, EmotionError};
use crate::experience::{
    build_conversation_turn_episode, ExperienceEpisodeCommitOutcome, ExperienceEpisodeError,
    ExperienceEpisodeErrorCode,
};
use crate::relationship::{RelationshipCommitOutcome, RelationshipError};

/// Result of one atomic four-domain commit. No frontend serialization or IPC
/// exposure is introduced by C1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ConversationEmotionRelationshipExperienceCommitOutcome {
    pub(crate) turn: AppendConversationTurnResult,
    pub(crate) emotion: EmotionCommitOutcome,
    pub(crate) relationship: RelationshipCommitOutcome,
    pub(crate) experience: ExperienceEpisodeCommitOutcome,
}

/// Typed failure boundary for the four-domain transaction. The D12 legacy and
/// binding categories remain explicit, while episode failures stay in the B1
/// experience domain except for the intentional D12-only missing-episode
/// classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConversationEmotionRelationshipExperienceCommitError {
    Conversation(ConversationHistoryError),
    Emotion(EmotionError),
    Relationship(RelationshipError),
    Experience(ExperienceEpisodeError),
    EmotionBindingMismatch(String),
    RelationshipBindingMismatch(String),
    EmotionEventMissing(String),
    RelationshipEventMissing(String),
    ExperienceEpisodeMissing(String),
}

impl ConversationEmotionRelationshipExperienceCommitError {
    fn storage_lock_unavailable() -> Self {
        Self::Conversation(conversation::storage_unavailable())
    }

    fn experience_episode_missing() -> Self {
        Self::ExperienceEpisodeMissing(
            "the governed turn has no experience episode to replay; retroactive backfill is forbidden."
                .to_string(),
        )
    }

    /// Stable machine-readable category for the future D13-C2 mapping. The
    /// category never depends on full Debug output, message text, or the
    /// recoverable flag.
    pub(crate) fn code(&self) -> String {
        match self {
            Self::Conversation(error) => format!("{:?}", error.code),
            Self::Emotion(error) => error.code.as_str().to_string(),
            Self::Relationship(error) => error.code.as_str().to_string(),
            Self::Experience(error) => match error.code {
                ExperienceEpisodeErrorCode::InvalidArgument => "EXPERIENCE_INVALID_ARGUMENT",
                ExperienceEpisodeErrorCode::LifeNotFound => "EXPERIENCE_LIFE_NOT_FOUND",
                ExperienceEpisodeErrorCode::SourceNotFound => "EXPERIENCE_SOURCE_NOT_FOUND",
                ExperienceEpisodeErrorCode::SourceBindingMismatch => {
                    "EXPERIENCE_SOURCE_BINDING_MISMATCH"
                }
                ExperienceEpisodeErrorCode::EpisodeConflict => "EXPERIENCE_EPISODE_CONFLICT",
                ExperienceEpisodeErrorCode::DatabaseUnavailable => {
                    "EXPERIENCE_DATABASE_UNAVAILABLE"
                }
            }
            .to_string(),
            Self::EmotionBindingMismatch(_) => "EMOTION_TURN_BINDING_MISMATCH".to_string(),
            Self::RelationshipBindingMismatch(_) => {
                "RELATIONSHIP_TURN_BINDING_MISMATCH".to_string()
            }
            Self::EmotionEventMissing(_) => "EMOTION_TURN_EVENT_MISSING".to_string(),
            Self::RelationshipEventMissing(_) => "RELATIONSHIP_TURN_EVENT_MISSING".to_string(),
            Self::ExperienceEpisodeMissing(_) => "EXPERIENCE_EPISODE_MISSING".to_string(),
        }
    }
}

impl From<rusqlite::Error> for ConversationEmotionRelationshipExperienceCommitError {
    fn from(_: rusqlite::Error) -> Self {
        Self::Conversation(conversation::storage_unavailable())
    }
}

impl From<ConversationEmotionRelationshipCommitError>
    for ConversationEmotionRelationshipExperienceCommitError
{
    fn from(error: ConversationEmotionRelationshipCommitError) -> Self {
        match error {
            ConversationEmotionRelationshipCommitError::Conversation(inner) => {
                Self::Conversation(inner)
            }
            ConversationEmotionRelationshipCommitError::Emotion(inner) => Self::Emotion(inner),
            ConversationEmotionRelationshipCommitError::Relationship(inner) => {
                Self::Relationship(inner)
            }
            ConversationEmotionRelationshipCommitError::EmotionBindingMismatch(detail) => {
                Self::EmotionBindingMismatch(detail)
            }
            ConversationEmotionRelationshipCommitError::RelationshipBindingMismatch(detail) => {
                Self::RelationshipBindingMismatch(detail)
            }
            ConversationEmotionRelationshipCommitError::EmotionEventMissing(detail) => {
                Self::EmotionEventMissing(detail)
            }
            ConversationEmotionRelationshipCommitError::RelationshipEventMissing(detail) => {
                Self::RelationshipEventMissing(detail)
            }
        }
    }
}

impl From<ExperienceEpisodeError> for ConversationEmotionRelationshipExperienceCommitError {
    fn from(error: ExperienceEpisodeError) -> Self {
        Self::Experience(error)
    }
}

/// The one four-domain storage primitive. Validation remains before the
/// StorageService lock and before BEGIN IMMEDIATE, as in D12. After that point
/// the D12 triple core, B2 builder, and B1 episode helper share one transaction
/// and one final COMMIT.
impl StorageService {
    #[allow(dead_code)] // C1 seam; production conversation cutover belongs to D13-C2.
    pub(crate) fn append_complete_turn_with_emotion_and_relationship_and_experience(
        &self,
        request: &AppendConversationTurnRequest,
        emotion_transition: crate::emotion::EmotionTransition,
        relationship_transition: crate::relationship::RelationshipTransition,
    ) -> Result<
        ConversationEmotionRelationshipExperienceCommitOutcome,
        ConversationEmotionRelationshipExperienceCommitError,
    > {
        validate_append_complete_turn_with_emotion_and_relationship(
            request,
            &emotion_transition,
            &relationship_transition,
        )?;

        let mut state = self.state().map_err(|_| {
            ConversationEmotionRelationshipExperienceCommitError::storage_lock_unavailable()
        })?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(ConversationEmotionRelationshipExperienceCommitError::from)?;

        let triple = append_complete_turn_with_emotion_and_relationship_in_transaction(
            &transaction,
            request,
            emotion_transition,
            relationship_transition,
        )?;
        let episode = build_conversation_turn_episode(&triple.turn)?;
        let experience = commit_episode_in_transaction(&transaction, episode)?;

        // A D12-only exact replay has all three prior domain events but no
        // durable episode. B1 temporarily inserts the episode above so its
        // frozen validation and SQL remain the sole episode writer; returning
        // this typed error drops the uncommitted transaction and prevents
        // retroactive backfill.
        if triple.turn.replayed
            && matches!(&experience, ExperienceEpisodeCommitOutcome::Applied { .. })
        {
            return Err(
                ConversationEmotionRelationshipExperienceCommitError::experience_episode_missing(),
            );
        }

        transaction
            .commit()
            .map_err(ConversationEmotionRelationshipExperienceCommitError::from)?;
        Ok(ConversationEmotionRelationshipExperienceCommitOutcome {
            turn: triple.turn,
            emotion: triple.emotion,
            relationship: triple.relationship,
            experience,
        })
    }
}

type CompositeCode = fn(&ConversationEmotionRelationshipExperienceCommitError) -> String;
const _: CompositeCode = ConversationEmotionRelationshipExperienceCommitError::code;

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use super::*;
    use crate::conversation::history::{
        AppendConversationTurnRequest, ConversationHistoryErrorCode, ConversationHistoryService,
        ConversationRecord, CreateConversationRequest,
    };
    use crate::emotion::{EmotionEventSource, EmotionTransition, INITIAL_POLICY_VERSION};
    use crate::relationship::{
        RelationshipDimensions, RelationshipEventSource,
        INITIAL_POLICY_VERSION as RELATIONSHIP_POLICY_VERSION, PRIMARY_USER_SUBJECT_ID,
    };
    use crate::storage::conversation_emotion::{
        conversation_emotion_event_id, conversation_emotion_source_ref,
        CONVERSATION_EMOTION_SOURCE_KIND,
    };
    use crate::storage::conversation_relationship::{
        conversation_relationship_event_id, conversation_relationship_source_ref,
        CONVERSATION_RELATIONSHIP_CHANGE_REASON, CONVERSATION_RELATIONSHIP_SOURCE_KIND,
    };
    use crate::storage::{unique_suffix, LifeIdentityRecord, PersonaTemplateRecord};

    const EVENT_TIME: &str = "2026-08-26T12:00:00.000Z";

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("digital-life-conv-exp-{name}-{}", unique_suffix()));
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

    fn create_conversation(service: &StorageService, title: &str) -> ConversationRecord {
        ConversationHistoryService::new(service)
            .create(CreateConversationRequest {
                life_id: "life-a".into(),
                title: title.into(),
            })
            .unwrap()
    }

    fn turn_request(
        conversation: &ConversationRecord,
        turn_id: &str,
    ) -> AppendConversationTurnRequest {
        AppendConversationTurnRequest {
            life_id: conversation.life_id.clone(),
            conversation_id: conversation.id.clone(),
            turn_id: turn_id.into(),
            user_content: "hello".into(),
            assistant_content: "hi there".into(),
            expected_revision: None,
        }
    }

    fn conflicting_content_request(
        conversation: &ConversationRecord,
        turn_id: &str,
    ) -> AppendConversationTurnRequest {
        AppendConversationTurnRequest {
            life_id: conversation.life_id.clone(),
            conversation_id: conversation.id.clone(),
            turn_id: turn_id.into(),
            user_content: "DIFFERENT user content".into(),
            assistant_content: "ignored".into(),
            expected_revision: None,
        }
    }

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

    fn relationship_transition(
        conversation_id: &str,
        turn_id: &str,
        expected_revision: i64,
    ) -> crate::relationship::RelationshipTransition {
        crate::relationship::RelationshipTransition::new(
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
            RELATIONSHIP_POLICY_VERSION,
            EVENT_TIME,
        )
        .unwrap()
    }

    fn commit_c1(
        service: &StorageService,
        conversation: &ConversationRecord,
        turn_id: &str,
        emotion_expected_revision: i64,
        relationship_expected_revision: i64,
    ) -> Result<
        ConversationEmotionRelationshipExperienceCommitOutcome,
        ConversationEmotionRelationshipExperienceCommitError,
    > {
        let request = turn_request(conversation, turn_id);
        service.append_complete_turn_with_emotion_and_relationship_and_experience(
            &request,
            emotion_transition(&conversation.id, turn_id, emotion_expected_revision),
            relationship_transition(&conversation.id, turn_id, relationship_expected_revision),
        )
    }

    fn commit_d12(
        service: &StorageService,
        conversation: &ConversationRecord,
        turn_id: &str,
    ) -> Result<
        crate::storage::conversation_relationship::ConversationEmotionRelationshipCommitOutcome,
        crate::storage::conversation_relationship::ConversationEmotionRelationshipCommitError,
    > {
        let request = turn_request(conversation, turn_id);
        service.append_complete_turn_with_emotion_and_relationship(
            &request,
            emotion_transition(&conversation.id, turn_id, 0),
            relationship_transition(&conversation.id, turn_id, 0),
        )
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Snapshot {
        message_count: i64,
        conversation_revision: i64,
        emotion_event_count: i64,
        emotion_revision: i64,
        emotion_valence: i32,
        emotion_activation: i32,
        relationship_event_count: i64,
        relationship_revision: i64,
        relationship_familiarity: i32,
        episode_count: i64,
    }

    fn snapshot(service: &StorageService, conversation_id: &str) -> Snapshot {
        let state = service.state().unwrap();
        Snapshot {
            message_count: state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM conversation_message WHERE conversation_id = ?1",
                    [conversation_id],
                    |row| row.get(0),
                )
                .unwrap(),
            conversation_revision: state
                .connection
                .query_row(
                    "SELECT revision FROM conversation WHERE id = ?1",
                    [conversation_id],
                    |row| row.get(0),
                )
                .unwrap(),
            emotion_event_count: state
                .connection
                .query_row("SELECT COUNT(*) FROM emotion_event", [], |row| row.get(0))
                .unwrap(),
            emotion_revision: state
                .connection
                .query_row(
                    "SELECT revision FROM emotion_state WHERE life_id = 'life-a'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            emotion_valence: state
                .connection
                .query_row(
                    "SELECT valence FROM emotion_state WHERE life_id = 'life-a'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            emotion_activation: state
                .connection
                .query_row(
                    "SELECT activation FROM emotion_state WHERE life_id = 'life-a'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            relationship_event_count: state
                .connection
                .query_row("SELECT COUNT(*) FROM relationship_event", [], |row| {
                    row.get(0)
                })
                .unwrap(),
            relationship_revision: state
                .connection
                .query_row(
                    "SELECT revision FROM relationship_state
                     WHERE life_id = 'life-a' AND subject_id = 'primary_user'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            relationship_familiarity: state
                .connection
                .query_row(
                    "SELECT familiarity FROM relationship_state
                     WHERE life_id = 'life-a' AND subject_id = 'primary_user'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            episode_count: state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM experience_episode WHERE life_id = 'life-a'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
        }
    }

    fn assert_turn_id_conflict(
        error: ConversationEmotionRelationshipExperienceCommitError,
        label: &str,
    ) {
        match error {
            ConversationEmotionRelationshipExperienceCommitError::Conversation(inner) => {
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
    fn new_four_domain_turn_commits_all_four_exactly_once_with_persisted_episode_evidence() {
        let root = TestRoot::new("new-four-domain");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service, "Four domains");

        let outcome = commit_c1(&service, &conversation, "turn-1", 0, 0).unwrap();

        assert!(!outcome.turn.replayed);
        assert!(matches!(
            outcome.emotion,
            EmotionCommitOutcome::Committed { .. }
        ));
        assert!(matches!(
            outcome.relationship,
            RelationshipCommitOutcome::Committed { .. }
        ));
        let episode = match &outcome.experience {
            ExperienceEpisodeCommitOutcome::Applied { episode } => episode,
            other => panic!("expected applied episode, got {other:?}"),
        };
        assert_eq!(episode.user_message_id, outcome.turn.user_message.id);
        assert_eq!(
            episode.assistant_message_id,
            outcome.turn.assistant_message.id
        );
        assert_eq!(episode.started_at, outcome.turn.user_message.created_at);
        assert_eq!(episode.ended_at, outcome.turn.assistant_message.created_at);
        assert_eq!(
            episode.created_at,
            outcome.turn.assistant_message.created_at
        );
        assert_eq!(
            episode.episode_id,
            "experience-conversation:life-a:".to_owned() + &conversation.id + ":turn-1"
        );
        assert_eq!(episode.source_ref, conversation.id.clone() + ":turn-1");
        assert_eq!(episode.counterpart_subject_id, "primary_user");
        assert_eq!(episode.outcome_kind, "completed");
        assert_eq!(episode.episode_version, 1);

        let state = service.state().unwrap();
        let columns: Vec<String> = state
            .connection
            .prepare("PRAGMA table_info(experience_episode)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!columns.iter().any(|column| column == "content"));
        drop(state);

        assert_eq!(
            snapshot(&service, &conversation.id),
            Snapshot {
                message_count: 2,
                conversation_revision: 1,
                emotion_event_count: 1,
                emotion_revision: 1,
                emotion_valence: 40,
                emotion_activation: -20,
                relationship_event_count: 1,
                relationship_revision: 1,
                relationship_familiarity: 1,
                episode_count: 1,
            }
        );
    }

    #[test]
    fn exact_full_d13_replay_replays_all_domains_without_duplicate_rows_or_revisions() {
        let root = TestRoot::new("full-replay");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service, "Replay");
        let first = commit_c1(&service, &conversation, "turn-1", 0, 0).unwrap();
        let before = snapshot(&service, &conversation.id);

        let replay = commit_c1(&service, &conversation, "turn-1", 0, 0).unwrap();

        assert!(replay.turn.replayed);
        assert!(matches!(
            replay.emotion,
            EmotionCommitOutcome::Replayed { .. }
        ));
        assert!(matches!(
            replay.relationship,
            RelationshipCommitOutcome::Replayed { .. }
        ));
        assert!(matches!(
            replay.experience,
            ExperienceEpisodeCommitOutcome::Replayed { .. }
        ));
        let first_episode = match &first.experience {
            ExperienceEpisodeCommitOutcome::Applied { episode } => episode,
            other => panic!("expected first episode to be applied, got {other:?}"),
        };
        let replay_episode = match &replay.experience {
            ExperienceEpisodeCommitOutcome::Replayed { episode } => episode,
            other => panic!("expected replay episode to be replayed, got {other:?}"),
        };
        assert_eq!(first_episode, replay_episode);
        assert_eq!(before, snapshot(&service, &conversation.id));
        assert_eq!(before.episode_count, 1);
    }

    #[test]
    fn d12_only_replay_returns_experience_missing_without_backfill_or_mutation() {
        let root = TestRoot::new("d12-only");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service, "D12 only");
        commit_d12(&service, &conversation, "turn-1").unwrap();
        let before = snapshot(&service, &conversation.id);
        assert_eq!(before.episode_count, 0);

        let error = commit_c1(&service, &conversation, "turn-1", 0, 0).unwrap_err();

        assert_eq!(error.code(), "EXPERIENCE_EPISODE_MISSING");
        assert!(matches!(
            error,
            ConversationEmotionRelationshipExperienceCommitError::ExperienceEpisodeMissing(_)
        ));
        assert_eq!(before, snapshot(&service, &conversation.id));
    }

    #[test]
    fn pre_d11_same_content_returns_emotion_missing_without_episode() {
        let root = TestRoot::new("pre-d11");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service, "Pre D11");
        let request = turn_request(&conversation, "legacy-turn");
        ConversationHistoryService::new(&service)
            .append_turn(request)
            .unwrap();
        let before = snapshot(&service, &conversation.id);

        let error = commit_c1(&service, &conversation, "legacy-turn", 0, 0).unwrap_err();

        assert_eq!(error.code(), "EMOTION_TURN_EVENT_MISSING");
        assert_eq!(before, snapshot(&service, &conversation.id));
        assert_eq!(before.episode_count, 0);
    }

    #[test]
    fn d11_only_same_content_returns_relationship_missing_without_episode() {
        let root = TestRoot::new("d11-only");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service, "D11 only");
        let request = turn_request(&conversation, "turn-1");
        service
            .append_complete_turn_with_emotion(
                &request,
                emotion_transition(&conversation.id, "turn-1", 0),
            )
            .unwrap();
        let before = snapshot(&service, &conversation.id);

        let error = commit_c1(&service, &conversation, "turn-1", 0, 0).unwrap_err();

        assert_eq!(error.code(), "RELATIONSHIP_TURN_EVENT_MISSING");
        assert_eq!(before, snapshot(&service, &conversation.id));
        assert_eq!(before.episode_count, 0);
    }

    #[test]
    fn different_content_wins_turn_id_conflict_in_every_governance_era() {
        let root = TestRoot::new("turn-conflict-precedence");
        let service = seeded_service(&root);
        let pre_d11 = create_conversation(&service, "Pre D11");
        let d11_only = create_conversation(&service, "D11 only");
        let d12_only = create_conversation(&service, "D12 only");
        let full_d13 = create_conversation(&service, "Full D13");

        ConversationHistoryService::new(&service)
            .append_turn(turn_request(&pre_d11, "pre-turn"))
            .unwrap();
        service
            .append_complete_turn_with_emotion(
                &turn_request(&d11_only, "d11-turn"),
                emotion_transition(&d11_only.id, "d11-turn", 0),
            )
            .unwrap();
        let d12_request = turn_request(&d12_only, "d12-turn");
        service
            .append_complete_turn_with_emotion_and_relationship(
                &d12_request,
                emotion_transition(&d12_only.id, "d12-turn", 1),
                relationship_transition(&d12_only.id, "d12-turn", 0),
            )
            .unwrap();
        commit_c1(&service, &full_d13, "d13-turn", 2, 1).unwrap();

        for (conversation, turn_id, label) in [
            (&pre_d11, "pre-turn", "pre-D11"),
            (&d11_only, "d11-turn", "D11-only"),
            (&d12_only, "d12-turn", "D12-only"),
            (&full_d13, "d13-turn", "full-D13"),
        ] {
            let before = snapshot(&service, &conversation.id);
            let request = conflicting_content_request(conversation, turn_id);
            let error = service
                .append_complete_turn_with_emotion_and_relationship_and_experience(
                    &request,
                    emotion_transition(&conversation.id, turn_id, 0),
                    relationship_transition(&conversation.id, turn_id, 0),
                )
                .unwrap_err();
            assert_turn_id_conflict(error, label);
            assert_eq!(before, snapshot(&service, &conversation.id), "{label}");
        }
    }

    #[test]
    fn emotion_revision_conflict_leaves_all_four_domains_unchanged() {
        let root = TestRoot::new("emotion-revision-conflict");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service, "Emotion conflict");
        let before = snapshot(&service, &conversation.id);

        let error = commit_c1(&service, &conversation, "turn-1", 7, 0).unwrap_err();

        assert_eq!(error.code(), "EMOTION_REVISION_CONFLICT");
        assert_eq!(before, snapshot(&service, &conversation.id));
    }

    #[test]
    fn relationship_revision_conflict_rolls_back_prior_triple_work() {
        let root = TestRoot::new("relationship-revision-conflict");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service, "Relationship conflict");
        let before = snapshot(&service, &conversation.id);

        let error = commit_c1(&service, &conversation, "turn-1", 0, 7).unwrap_err();

        assert_eq!(error.code(), "RELATIONSHIP_REVISION_CONFLICT");
        assert_eq!(before, snapshot(&service, &conversation.id));
    }

    #[test]
    fn episode_persistence_failure_rolls_back_conversation_emotion_and_relationship() {
        let root = TestRoot::new("episode-failure-rollback");
        let service = seeded_service(&root);
        let conversation = create_conversation(&service, "Episode failure");
        service
            .state()
            .unwrap()
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_experience_episode
                 BEFORE INSERT ON experience_episode
                 BEGIN SELECT RAISE(ABORT, 'forced episode fixture failure'); END;",
            )
            .unwrap();
        let before = snapshot(&service, &conversation.id);

        let error = commit_c1(&service, &conversation, "turn-1", 0, 0).unwrap_err();

        assert_eq!(error.code(), "EXPERIENCE_DATABASE_UNAVAILABLE");
        assert!(matches!(
            error,
            ConversationEmotionRelationshipExperienceCommitError::Experience(
                ExperienceEpisodeError {
                    code: ExperienceEpisodeErrorCode::DatabaseUnavailable,
                    ..
                }
            )
        ));
        assert_eq!(before, snapshot(&service, &conversation.id));
    }
}
