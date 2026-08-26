//! Pure binding from persisted conversation evidence to an ExperienceEpisode.
//!
//! This module deliberately does not know about SQLite, clocks, providers, or
//! storage mutation. It consumes only the two persisted source messages that
//! are already present in `AppendConversationTurnResult`.

use crate::conversation::history::{
    AppendConversationTurnResult, ConversationMessageRecord, ConversationRole,
};

use super::{
    ExperienceEpisode, ExperienceEpisodeError, COUNTERPART_SUBJECT_ID, EPISODE_KIND,
    EPISODE_VERSION, OUTCOME_KIND, SOURCE_KIND,
};

fn source_binding_error() -> ExperienceEpisodeError {
    ExperienceEpisodeError::source_binding_mismatch()
}

fn has_non_empty_identity(value: &str) -> bool {
    !value.trim().is_empty()
}

fn valid_source_pair(
    user_message: &ConversationMessageRecord,
    assistant_message: &ConversationMessageRecord,
) -> bool {
    user_message.role == ConversationRole::User
        && assistant_message.role == ConversationRole::Assistant
        && user_message.id != assistant_message.id
        && has_non_empty_identity(&user_message.id)
        && has_non_empty_identity(&assistant_message.id)
        && has_non_empty_identity(&user_message.life_id)
        && has_non_empty_identity(&user_message.conversation_id)
        && has_non_empty_identity(&user_message.turn_id)
        && has_non_empty_identity(&user_message.created_at)
        && has_non_empty_identity(&assistant_message.created_at)
        && user_message.life_id == assistant_message.life_id
        && user_message.conversation_id == assistant_message.conversation_id
        && user_message.turn_id == assistant_message.turn_id
        && user_message.created_at <= assistant_message.created_at
}

/// Builds the canonical D13-B1 episode for one already-persisted conversation
/// turn. Only structural fields from the two persisted messages are used;
/// replay metadata, message content, clocks, and storage are intentionally
/// outside this seam.
pub(crate) fn build_conversation_turn_episode(
    turn: &AppendConversationTurnResult,
) -> Result<ExperienceEpisode, ExperienceEpisodeError> {
    let user_message = &turn.user_message;
    let assistant_message = &turn.assistant_message;
    if !valid_source_pair(user_message, assistant_message) {
        return Err(source_binding_error());
    }

    let episode = ExperienceEpisode {
        episode_id: format!(
            "experience-conversation:{}:{}:{}",
            user_message.life_id, user_message.conversation_id, user_message.turn_id
        ),
        life_id: user_message.life_id.clone(),
        episode_kind: EPISODE_KIND.to_owned(),
        source_kind: SOURCE_KIND.to_owned(),
        source_ref: format!("{}:{}", user_message.conversation_id, user_message.turn_id),
        conversation_id: user_message.conversation_id.clone(),
        turn_id: user_message.turn_id.clone(),
        counterpart_subject_id: COUNTERPART_SUBJECT_ID.to_owned(),
        user_message_id: user_message.id.clone(),
        assistant_message_id: assistant_message.id.clone(),
        outcome_kind: OUTCOME_KIND.to_owned(),
        started_at: user_message.created_at.clone(),
        ended_at: assistant_message.created_at.clone(),
        episode_version: EPISODE_VERSION,
        created_at: assistant_message.created_at.clone(),
    };
    episode.validate()?;
    Ok(episode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::experience::ExperienceEpisodeErrorCode;

    fn message(
        id: &str,
        role: ConversationRole,
        content: &str,
        created_at: &str,
    ) -> ConversationMessageRecord {
        ConversationMessageRecord {
            id: id.to_owned(),
            conversation_id: "conversation-1".to_owned(),
            life_id: "life-1".to_owned(),
            turn_id: "turn-1".to_owned(),
            role,
            content: content.to_owned(),
            sequence_no: 11,
            created_at: created_at.to_owned(),
        }
    }

    fn turn() -> AppendConversationTurnResult {
        AppendConversationTurnResult {
            user_message: message(
                "user-message-1",
                ConversationRole::User,
                "user content",
                "2026-08-26T10:00:00.000Z",
            ),
            assistant_message: message(
                "assistant-message-1",
                ConversationRole::Assistant,
                "assistant content",
                "2026-08-26T10:00:01.000Z",
            ),
            conversation_revision: 7,
            replayed: false,
        }
    }

    fn binding_error(result: Result<ExperienceEpisode, ExperienceEpisodeError>) {
        let error = result.expect_err("malformed persisted source pair must fail closed");
        assert_eq!(
            error.code,
            ExperienceEpisodeErrorCode::SourceBindingMismatch
        );
    }

    #[test]
    fn valid_persisted_pair_builds_the_exact_canonical_episode() {
        let episode = build_conversation_turn_episode(&turn()).unwrap();

        assert_eq!(
            episode,
            ExperienceEpisode {
                episode_id: "experience-conversation:life-1:conversation-1:turn-1".to_owned(),
                life_id: "life-1".to_owned(),
                episode_kind: "conversation_turn".to_owned(),
                source_kind: "conversation_turn".to_owned(),
                source_ref: "conversation-1:turn-1".to_owned(),
                conversation_id: "conversation-1".to_owned(),
                turn_id: "turn-1".to_owned(),
                counterpart_subject_id: "primary_user".to_owned(),
                user_message_id: "user-message-1".to_owned(),
                assistant_message_id: "assistant-message-1".to_owned(),
                outcome_kind: "completed".to_owned(),
                started_at: "2026-08-26T10:00:00.000Z".to_owned(),
                ended_at: "2026-08-26T10:00:01.000Z".to_owned(),
                episode_version: 1,
                created_at: "2026-08-26T10:00:01.000Z".to_owned(),
            }
        );
    }

    #[test]
    fn repeated_construction_is_deterministic() {
        let first = build_conversation_turn_episode(&turn()).unwrap();
        let second = build_conversation_turn_episode(&turn()).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn replayed_flag_does_not_change_the_episode() {
        let original = turn();
        let mut replay = original.clone();
        replay.replayed = true;

        assert_eq!(
            build_conversation_turn_episode(&original).unwrap(),
            build_conversation_turn_episode(&replay).unwrap()
        );
    }

    #[test]
    fn conversation_revision_does_not_change_the_episode() {
        let original = turn();
        let mut different_revision = original.clone();
        different_revision.conversation_revision = 999;

        assert_eq!(
            build_conversation_turn_episode(&original).unwrap(),
            build_conversation_turn_episode(&different_revision).unwrap()
        );
    }

    #[test]
    fn message_content_does_not_change_the_episode() {
        let original = turn();
        let mut different_content = original.clone();
        different_content.user_message.content = "different user content".to_owned();
        different_content.assistant_message.content = "different assistant content".to_owned();

        assert_eq!(
            build_conversation_turn_episode(&original).unwrap(),
            build_conversation_turn_episode(&different_content).unwrap()
        );
    }

    #[test]
    fn wrong_user_role_fails_closed() {
        let mut malformed = turn();
        malformed.user_message.role = ConversationRole::Assistant;

        binding_error(build_conversation_turn_episode(&malformed));
    }

    #[test]
    fn wrong_assistant_role_fails_closed() {
        let mut malformed = turn();
        malformed.assistant_message.role = ConversationRole::User;

        binding_error(build_conversation_turn_episode(&malformed));
    }

    #[test]
    fn life_mismatch_fails_closed() {
        let mut malformed = turn();
        malformed.assistant_message.life_id = "life-2".to_owned();

        binding_error(build_conversation_turn_episode(&malformed));
    }

    #[test]
    fn conversation_mismatch_fails_closed() {
        let mut malformed = turn();
        malformed.assistant_message.conversation_id = "conversation-2".to_owned();

        binding_error(build_conversation_turn_episode(&malformed));
    }

    #[test]
    fn turn_mismatch_fails_closed() {
        let mut malformed = turn();
        malformed.assistant_message.turn_id = "turn-2".to_owned();

        binding_error(build_conversation_turn_episode(&malformed));
    }

    #[test]
    fn same_message_id_fails_closed() {
        let mut malformed = turn();
        malformed.assistant_message.id = malformed.user_message.id.clone();

        binding_error(build_conversation_turn_episode(&malformed));
    }

    #[test]
    fn empty_message_and_source_identifiers_fail_closed() {
        let mut empty_user_id = turn();
        empty_user_id.user_message.id.clear();
        binding_error(build_conversation_turn_episode(&empty_user_id));

        let mut empty_assistant_id = turn();
        empty_assistant_id.assistant_message.id.clear();
        binding_error(build_conversation_turn_episode(&empty_assistant_id));

        let mut empty_life_id = turn();
        empty_life_id.user_message.life_id.clear();
        binding_error(build_conversation_turn_episode(&empty_life_id));

        let mut empty_conversation_id = turn();
        empty_conversation_id.user_message.conversation_id.clear();
        binding_error(build_conversation_turn_episode(&empty_conversation_id));

        let mut empty_turn_id = turn();
        empty_turn_id.user_message.turn_id.clear();
        binding_error(build_conversation_turn_episode(&empty_turn_id));
    }

    #[test]
    fn empty_timestamps_fail_closed() {
        let mut empty_user_timestamp = turn();
        empty_user_timestamp.user_message.created_at.clear();
        binding_error(build_conversation_turn_episode(&empty_user_timestamp));

        let mut empty_assistant_timestamp = turn();
        empty_assistant_timestamp
            .assistant_message
            .created_at
            .clear();
        binding_error(build_conversation_turn_episode(&empty_assistant_timestamp));
    }

    #[test]
    fn started_after_ended_fails_closed() {
        let mut malformed = turn();
        malformed.user_message.created_at = "2026-08-26T10:00:02.000Z".to_owned();
        malformed.assistant_message.created_at = "2026-08-26T10:00:01.000Z".to_owned();

        binding_error(build_conversation_turn_episode(&malformed));
    }

    #[test]
    fn created_at_equals_the_assistant_persisted_timestamp() {
        let episode = build_conversation_turn_episode(&turn()).unwrap();

        assert_eq!(episode.created_at, episode.ended_at);
        assert_eq!(episode.created_at, "2026-08-26T10:00:01.000Z");
    }

    #[test]
    fn canonical_source_identity_and_fixed_fields_are_exact() {
        let episode = build_conversation_turn_episode(&turn()).unwrap();

        assert_eq!(episode.source_ref, "conversation-1:turn-1");
        assert_eq!(
            episode.episode_id,
            "experience-conversation:life-1:conversation-1:turn-1"
        );
        assert_eq!(episode.counterpart_subject_id, "primary_user");
        assert_eq!(episode.outcome_kind, "completed");
        assert_eq!(episode.episode_version, 1);
        episode.validate().unwrap();
    }
}
