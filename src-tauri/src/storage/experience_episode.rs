//! SQLite-authoritative persistence for D13-B1 experience episodes.
//!
//! This module is deliberately a storage boundary rather than a Tauri
//! command. It reads only persisted conversation identity/role/timestamp
//! columns, never message content, and keeps the transaction helper free of
//! commit/rollback decisions so a future composite transaction can compose it.

use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};

use crate::experience::{
    ExperienceEpisode, ExperienceEpisodeCommitOutcome, ExperienceEpisodeError,
    ExperienceEpisodeRepository, EPISODE_KIND, EPISODE_VERSION, OUTCOME_KIND, SOURCE_KIND,
};

use super::StorageService;

pub(super) const CREATE_EXPERIENCE_EPISODE_TABLE_SQL: &str =
    include_str!("migrations/021_experience_episode_authority.table.sql");
pub(super) const CREATE_EXPERIENCE_EPISODE_SOURCE_BINDING_TRIGGER_SQL: &str =
    include_str!("migrations/021_experience_episode_authority.source_binding_trigger.sql");
pub(super) const CREATE_EXPERIENCE_EPISODE_IMMUTABLE_TRIGGER_SQL: &str =
    include_str!("migrations/021_experience_episode_authority.immutable_trigger.sql");

const EXPERIENCE_EPISODE_COLUMNS: &str = "episode_id, life_id, episode_kind, source_kind, source_ref, conversation_id, turn_id, counterpart_subject_id, user_message_id, assistant_message_id, outcome_kind, started_at, ended_at, episode_version, created_at";

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceMessage {
    id: String,
    conversation_id: String,
    life_id: String,
    turn_id: String,
    role: String,
    created_at: String,
}

fn read_episode(row: &Row<'_>) -> rusqlite::Result<ExperienceEpisode> {
    Ok(ExperienceEpisode {
        episode_id: row.get(0)?,
        life_id: row.get(1)?,
        episode_kind: row.get(2)?,
        source_kind: row.get(3)?,
        source_ref: row.get(4)?,
        conversation_id: row.get(5)?,
        turn_id: row.get(6)?,
        counterpart_subject_id: row.get(7)?,
        user_message_id: row.get(8)?,
        assistant_message_id: row.get(9)?,
        outcome_kind: row.get(10)?,
        started_at: row.get(11)?,
        ended_at: row.get(12)?,
        episode_version: row.get(13)?,
        created_at: row.get(14)?,
    })
}

fn read_source_message(row: &Row<'_>) -> rusqlite::Result<SourceMessage> {
    Ok(SourceMessage {
        id: row.get(0)?,
        conversation_id: row.get(1)?,
        life_id: row.get(2)?,
        turn_id: row.get(3)?,
        role: row.get(4)?,
        created_at: row.get(5)?,
    })
}

fn invalid_query_argument(name: &str) -> ExperienceEpisodeError {
    ExperienceEpisodeError::invalid_argument(format!("{name} must not be empty."))
}

fn validate_lookup_arguments(
    life_id: Option<&str>,
    source_kind: Option<&str>,
    source_ref: Option<&str>,
) -> Result<(), ExperienceEpisodeError> {
    for (name, value) in [
        ("life identity", life_id),
        ("source kind", source_kind),
        ("source reference", source_ref),
    ] {
        if let Some(value) = value {
            if value.trim().is_empty() {
                return Err(invalid_query_argument(name));
            }
        }
    }
    Ok(())
}

fn load_episode_by_id(
    connection: &Connection,
    episode_id: &str,
) -> Result<Option<ExperienceEpisode>, ExperienceEpisodeError> {
    connection
        .query_row(
            &format!(
                "SELECT {EXPERIENCE_EPISODE_COLUMNS} FROM experience_episode
                 WHERE episode_id = ?1"
            ),
            [episode_id],
            read_episode,
        )
        .optional()
        .map_err(|_| ExperienceEpisodeError::database())
}

fn load_episode_by_source(
    connection: &Connection,
    life_id: &str,
    source_kind: &str,
    source_ref: &str,
) -> Result<Option<ExperienceEpisode>, ExperienceEpisodeError> {
    connection
        .query_row(
            &format!(
                "SELECT {EXPERIENCE_EPISODE_COLUMNS} FROM experience_episode
                 WHERE life_id = ?1 AND source_kind = ?2 AND source_ref = ?3"
            ),
            params![life_id, source_kind, source_ref],
            read_episode,
        )
        .optional()
        .map_err(|_| ExperienceEpisodeError::database())
}

fn load_source_message(
    transaction: &Transaction<'_>,
    message_id: &str,
) -> Result<Option<SourceMessage>, ExperienceEpisodeError> {
    transaction
        .query_row(
            "SELECT id, conversation_id, life_id, turn_id, role, created_at
             FROM conversation_message WHERE id = ?1",
            [message_id],
            read_source_message,
        )
        .optional()
        .map_err(|_| ExperienceEpisodeError::database())
}

fn source_message_matches(
    message: &SourceMessage,
    episode: &ExperienceEpisode,
    expected_role: &str,
    expected_timestamp: &str,
) -> bool {
    let expected_id = if expected_role == "user" {
        episode.user_message_id.as_str()
    } else {
        episode.assistant_message_id.as_str()
    };
    message.id == expected_id
        && message.conversation_id == episode.conversation_id
        && message.life_id == episode.life_id
        && message.turn_id == episode.turn_id
        && message.role == expected_role
        && message.created_at == expected_timestamp
}

fn validate_canonical_binding(episode: &ExperienceEpisode) -> Result<(), ExperienceEpisodeError> {
    let expected_source_ref = format!("{}:{}", episode.conversation_id, episode.turn_id);
    let expected_episode_id = format!(
        "experience-conversation:{}:{}:{}",
        episode.life_id, episode.conversation_id, episode.turn_id
    );
    if episode.source_ref != expected_source_ref || episode.episode_id != expected_episode_id {
        return Err(ExperienceEpisodeError::source_binding_mismatch());
    }
    Ok(())
}

fn validate_source_binding(
    transaction: &Transaction<'_>,
    episode: &ExperienceEpisode,
) -> Result<(), ExperienceEpisodeError> {
    let life_exists: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
            [&episode.life_id],
            |row| row.get(0),
        )
        .map_err(|_| ExperienceEpisodeError::database())?;
    if !life_exists {
        return Err(ExperienceEpisodeError::life_not_found());
    }

    let conversation_exists: bool = transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM conversation WHERE id = ?1 AND life_id = ?2
             )",
            params![&episode.conversation_id, &episode.life_id],
            |row| row.get(0),
        )
        .map_err(|_| ExperienceEpisodeError::database())?;
    if !conversation_exists {
        return Err(ExperienceEpisodeError::source_not_found());
    }

    let user_message = load_source_message(transaction, &episode.user_message_id)?
        .ok_or_else(ExperienceEpisodeError::source_not_found)?;
    let assistant_message = load_source_message(transaction, &episode.assistant_message_id)?
        .ok_or_else(ExperienceEpisodeError::source_not_found)?;
    if !source_message_matches(&user_message, episode, "user", &episode.started_at)
        || !source_message_matches(&assistant_message, episode, "assistant", &episode.ended_at)
    {
        return Err(ExperienceEpisodeError::source_binding_mismatch());
    }
    Ok(())
}

fn episode_evidence_matches(existing: &ExperienceEpisode, requested: &ExperienceEpisode) -> bool {
    existing == requested
}

fn map_insert_error(error: rusqlite::Error) -> ExperienceEpisodeError {
    if let rusqlite::Error::SqliteFailure(_, Some(message)) = &error {
        let lower = message.to_ascii_lowercase();
        if lower.contains("experience_episode_source_binding_mismatch") {
            return ExperienceEpisodeError::source_binding_mismatch();
        }
        if lower.contains("foreign key constraint failed") {
            return ExperienceEpisodeError::source_not_found();
        }
        if lower.contains("unique constraint failed") {
            return ExperienceEpisodeError::episode_conflict();
        }
    }
    ExperienceEpisodeError::database()
}

/// The one semantic implementation of an episode commit. It runs entirely in
/// a caller-owned transaction and never commits or rolls back that
/// transaction.
pub(super) fn commit_episode_in_transaction(
    transaction: &Transaction<'_>,
    episode: ExperienceEpisode,
) -> Result<ExperienceEpisodeCommitOutcome, ExperienceEpisodeError> {
    episode.validate_shape().map_err(|_| {
        ExperienceEpisodeError::invalid_argument("The experience episode is invalid.")
    })?;

    if let Some(_existing) = transaction
        .query_row(
            &format!(
                "SELECT {EXPERIENCE_EPISODE_COLUMNS} FROM experience_episode
                 WHERE episode_id = ?1"
            ),
            [&episode.episode_id],
            read_episode,
        )
        .optional()
        .map_err(|_| ExperienceEpisodeError::database())?
    {
        if episode_evidence_matches(&_existing, &episode) {
            validate_canonical_binding(&episode)?;
            validate_source_binding(transaction, &episode)?;
            return Ok(ExperienceEpisodeCommitOutcome::Replayed { episode: _existing });
        }
        return Err(ExperienceEpisodeError::episode_conflict());
    }

    if let Some(_existing) = transaction
        .query_row(
            &format!(
                "SELECT {EXPERIENCE_EPISODE_COLUMNS} FROM experience_episode
                 WHERE life_id = ?1 AND source_kind = ?2 AND source_ref = ?3"
            ),
            params![&episode.life_id, &episode.source_kind, &episode.source_ref],
            read_episode,
        )
        .optional()
        .map_err(|_| ExperienceEpisodeError::database())?
    {
        return Err(ExperienceEpisodeError::episode_conflict());
    }

    validate_canonical_binding(&episode)?;
    validate_source_binding(transaction, &episode)?;

    transaction
        .execute(
            &format!(
                "INSERT INTO experience_episode ({EXPERIENCE_EPISODE_COLUMNS})
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"
            ),
            params![
                &episode.episode_id,
                &episode.life_id,
                &episode.episode_kind,
                &episode.source_kind,
                &episode.source_ref,
                &episode.conversation_id,
                &episode.turn_id,
                &episode.counterpart_subject_id,
                &episode.user_message_id,
                &episode.assistant_message_id,
                &episode.outcome_kind,
                &episode.started_at,
                &episode.ended_at,
                episode.episode_version,
                &episode.created_at,
            ],
        )
        .map_err(map_insert_error)?;
    Ok(ExperienceEpisodeCommitOutcome::Applied { episode })
}

const _: for<'a> fn(
    &Transaction<'a>,
    ExperienceEpisode,
) -> Result<ExperienceEpisodeCommitOutcome, ExperienceEpisodeError> = commit_episode_in_transaction;

impl ExperienceEpisodeRepository for StorageService {
    fn find_episode(
        &self,
        episode_id: &str,
    ) -> Result<Option<ExperienceEpisode>, ExperienceEpisodeError> {
        if episode_id.trim().is_empty() {
            return Err(invalid_query_argument("episode identity"));
        }
        let state = self
            .state()
            .map_err(|_| ExperienceEpisodeError::database())?;
        load_episode_by_id(&state.connection, episode_id)
    }

    fn find_episode_by_source(
        &self,
        life_id: &str,
        source_kind: &str,
        source_ref: &str,
    ) -> Result<Option<ExperienceEpisode>, ExperienceEpisodeError> {
        validate_lookup_arguments(Some(life_id), Some(source_kind), Some(source_ref))?;
        let state = self
            .state()
            .map_err(|_| ExperienceEpisodeError::database())?;
        load_episode_by_source(&state.connection, life_id, source_kind, source_ref)
    }

    fn find_latest_episode_for_life(
        &self,
        life_id: &str,
    ) -> Result<Option<ExperienceEpisode>, ExperienceEpisodeError> {
        validate_lookup_arguments(Some(life_id), None, None)?;
        let state = self
            .state()
            .map_err(|_| ExperienceEpisodeError::database())?;
        state
            .connection
            .query_row(
                &format!(
                    "SELECT {EXPERIENCE_EPISODE_COLUMNS} FROM experience_episode
                     WHERE life_id = ?1
                     ORDER BY ended_at DESC, episode_id DESC LIMIT 1"
                ),
                [life_id],
                read_episode,
            )
            .optional()
            .map_err(|_| ExperienceEpisodeError::database())
    }

    fn commit_episode(
        &self,
        episode: ExperienceEpisode,
    ) -> Result<ExperienceEpisodeCommitOutcome, ExperienceEpisodeError> {
        let mut state = self
            .state()
            .map_err(|_| ExperienceEpisodeError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ExperienceEpisodeError::database())?;
        let outcome = commit_episode_in_transaction(&transaction, episode)?;
        transaction
            .commit()
            .map_err(|_| ExperienceEpisodeError::database())?;
        Ok(outcome)
    }
}

type EpisodeLookupResult = Result<Option<ExperienceEpisode>, ExperienceEpisodeError>;
type EpisodeLookup = for<'a> fn(&'a StorageService, &'a str) -> EpisodeLookupResult;
type EpisodeSourceLookup =
    for<'a> fn(&'a StorageService, &'a str, &'a str, &'a str) -> EpisodeLookupResult;
type LatestEpisodeLookup = for<'a> fn(&'a StorageService, &'a str) -> EpisodeLookupResult;
type EpisodeCommit = for<'a> fn(
    &'a StorageService,
    ExperienceEpisode,
) -> Result<ExperienceEpisodeCommitOutcome, ExperienceEpisodeError>;

const _: EpisodeLookup = <StorageService as ExperienceEpisodeRepository>::find_episode;
const _: EpisodeSourceLookup =
    <StorageService as ExperienceEpisodeRepository>::find_episode_by_source;
const _: LatestEpisodeLookup =
    <StorageService as ExperienceEpisodeRepository>::find_latest_episode_for_life;
const _: EpisodeCommit = <StorageService as ExperienceEpisodeRepository>::commit_episode;

pub(super) fn validate_schema_objects(connection: &Connection) -> Result<(), super::StorageError> {
    for (object_kind, object_name, expected_sql) in [
        (
            "table",
            "experience_episode",
            CREATE_EXPERIENCE_EPISODE_TABLE_SQL,
        ),
        (
            "trigger",
            "experience_episode_source_binding_guard",
            CREATE_EXPERIENCE_EPISODE_SOURCE_BINDING_TRIGGER_SQL,
        ),
        (
            "trigger",
            "experience_episode_immutable_guard",
            CREATE_EXPERIENCE_EPISODE_IMMUTABLE_TRIGGER_SQL,
        ),
    ] {
        let actual: Option<String> = connection
            .query_row(
                "SELECT sql FROM sqlite_schema WHERE type = ?1 AND name = ?2",
                params![object_kind, object_name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| super::StorageError::migration_transaction_failed())?;
        let Some(actual) = actual else {
            return Err(super::StorageError::migration_transaction_failed());
        };
        if normalize_schema_sql(&actual) != normalize_schema_sql(expected_sql) {
            return Err(super::StorageError::migration_transaction_failed());
        }
    }

    for (parent_table, from_column) in [
        ("life_identity", "life_id"),
        ("conversation", "conversation_id"),
        ("conversation_message", "user_message_id"),
        ("conversation_message", "assistant_message_id"),
    ] {
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM pragma_foreign_key_list('experience_episode')
                 WHERE \"table\" = ?1 AND \"from\" = ?2 AND on_delete = 'CASCADE'",
                params![parent_table, from_column],
                |row| row.get(0),
            )
            .map_err(|_| super::StorageError::migration_transaction_failed())?;
        if count != 1 {
            return Err(super::StorageError::migration_transaction_failed());
        }
    }
    let composite_conversation_fk: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM pragma_foreign_key_list('experience_episode')
             WHERE \"table\" = 'conversation' AND \"from\" = 'life_id'
               AND \"to\" = 'life_id' AND on_delete = 'CASCADE'",
            [],
            |row| row.get(0),
        )
        .map_err(|_| super::StorageError::migration_transaction_failed())?;
    if composite_conversation_fk != 1 {
        return Err(super::StorageError::migration_transaction_failed());
    }

    let invalid_rows: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM experience_episode AS e
             WHERE e.episode_kind <> ?1
                OR e.source_kind <> ?2
                OR e.outcome_kind <> ?3
                OR e.counterpart_subject_id <> 'primary_user'
                OR e.episode_version <> ?4
                OR e.user_message_id = e.assistant_message_id
                OR e.started_at > e.ended_at
                OR e.created_at <> e.ended_at
                OR e.source_ref <> e.conversation_id || ':' || e.turn_id
                OR e.episode_id <> 'experience-conversation:' || e.life_id || ':' || e.conversation_id || ':' || e.turn_id
                OR NOT EXISTS (
                    SELECT 1 FROM conversation_message AS u
                    WHERE u.id = e.user_message_id
                      AND u.conversation_id = e.conversation_id
                      AND u.life_id = e.life_id
                      AND u.turn_id = e.turn_id
                      AND u.role = 'user'
                      AND u.created_at = e.started_at
                )
                OR NOT EXISTS (
                    SELECT 1 FROM conversation_message AS a
                    WHERE a.id = e.assistant_message_id
                      AND a.conversation_id = e.conversation_id
                      AND a.life_id = e.life_id
                      AND a.turn_id = e.turn_id
                      AND a.role = 'assistant'
                      AND a.created_at = e.ended_at
                )",
            params![EPISODE_KIND, SOURCE_KIND, OUTCOME_KIND, EPISODE_VERSION],
            |row| row.get(0),
        )
        .map_err(|_| super::StorageError::migration_transaction_failed())?;
    if invalid_rows != 0 {
        return Err(super::StorageError::migration_transaction_failed());
    }
    Ok(())
}

fn normalize_schema_sql(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(';')
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .map(|byte| byte.to_ascii_lowercase())
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::{
        conversation::history::ConversationRepository,
        experience::ExperienceEpisodeErrorCode,
        storage::{LifeIdentityRecord, PersonaTemplateRecord},
    };
    use rusqlite::params;
    use tempfile::TempDir;

    use super::*;

    struct EpisodeFixture {
        _root: TempDir,
        storage: StorageService,
    }

    impl EpisodeFixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let default_root = root.path().join("default");
            fs::create_dir_all(&default_root).unwrap();
            let storage = StorageService::initialize_with_roots(default_root, None).unwrap();
            storage
                .save_persona(PersonaTemplateRecord {
                    id: "episode-persona".into(),
                    name: "Episode Persona".into(),
                    version: 1,
                    persona_json: "{}".into(),
                })
                .unwrap();
            storage
                .save_life(LifeIdentityRecord {
                    id: "episode-life".into(),
                    name: "Episode Life".into(),
                    created_at: "2026-08-26T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "episode-body".into(),
                    persona_id: "episode-persona".into(),
                    persona_version: 1,
                })
                .unwrap();
            let state = storage.state().unwrap();
            state
                .connection
                .execute_batch(
                    "INSERT INTO conversation
                         (id, life_id, title, revision, created_at, updated_at, last_message_at)
                     VALUES
                         ('episode-conversation', 'episode-life', 'Episode Conversation', 1,
                          '2026-08-26T00:00:00.000Z', '2026-08-26T00:00:00.002Z',
                          '2026-08-26T00:00:00.002Z');
                     INSERT INTO conversation_message
                         (id, conversation_id, life_id, turn_id, role, content, sequence_no, created_at)
                     VALUES
                         ('episode-user-message', 'episode-conversation', 'episode-life',
                          'episode-turn', 'user', 'raw user content that must never be copied', 1,
                          '2026-08-26T00:00:00.001Z'),
                         ('episode-assistant-message', 'episode-conversation', 'episode-life',
                          'episode-turn', 'assistant', 'raw assistant content that must never be copied', 2,
                          '2026-08-26T00:00:00.002Z');",
                )
                .unwrap();
            drop(state);
            Self {
                _root: root,
                storage,
            }
        }

        fn episode(&self) -> ExperienceEpisode {
            ExperienceEpisode {
                episode_id:
                    "experience-conversation:episode-life:episode-conversation:episode-turn".into(),
                life_id: "episode-life".into(),
                episode_kind: EPISODE_KIND.into(),
                source_kind: SOURCE_KIND.into(),
                source_ref: "episode-conversation:episode-turn".into(),
                conversation_id: "episode-conversation".into(),
                turn_id: "episode-turn".into(),
                counterpart_subject_id: "primary_user".into(),
                user_message_id: "episode-user-message".into(),
                assistant_message_id: "episode-assistant-message".into(),
                outcome_kind: OUTCOME_KIND.into(),
                started_at: "2026-08-26T00:00:00.001Z".into(),
                ended_at: "2026-08-26T00:00:00.002Z".into(),
                episode_version: EPISODE_VERSION,
                created_at: "2026-08-26T00:00:00.002Z".into(),
            }
        }

        fn count(&self) -> i64 {
            let state = self.storage.state().unwrap();
            state
                .connection
                .query_row("SELECT COUNT(*) FROM experience_episode", [], |row| {
                    row.get(0)
                })
                .unwrap()
        }
    }

    #[test]
    fn valid_exact_episode_insert_is_applied() {
        let fixture = EpisodeFixture::new();
        let expected = fixture.episode();
        let outcome = fixture.storage.commit_episode(expected.clone()).unwrap();
        assert_eq!(
            outcome,
            ExperienceEpisodeCommitOutcome::Applied { episode: expected }
        );
        assert_eq!(fixture.count(), 1);
    }

    #[test]
    fn exact_replay_is_replayed_without_a_duplicate() {
        let fixture = EpisodeFixture::new();
        let episode = fixture.episode();
        fixture.storage.commit_episode(episode.clone()).unwrap();
        let outcome = fixture.storage.commit_episode(episode.clone()).unwrap();
        assert_eq!(
            outcome,
            ExperienceEpisodeCommitOutcome::Replayed { episode }
        );
        assert_eq!(fixture.count(), 1);
    }

    #[test]
    fn same_episode_identity_with_different_evidence_is_a_conflict() {
        let fixture = EpisodeFixture::new();
        fixture.storage.commit_episode(fixture.episode()).unwrap();
        let mut conflicting = fixture.episode();
        conflicting.ended_at = "2026-08-26T00:00:00.003Z".into();
        conflicting.created_at = conflicting.ended_at.clone();
        let error = fixture.storage.commit_episode(conflicting).unwrap_err();
        assert_eq!(error.code, ExperienceEpisodeErrorCode::EpisodeConflict);
    }

    #[test]
    fn same_canonical_source_with_a_different_identity_is_a_conflict() {
        let fixture = EpisodeFixture::new();
        fixture.storage.commit_episode(fixture.episode()).unwrap();
        let mut conflicting = fixture.episode();
        conflicting.episode_id = "a-different-episode-id".into();
        let error = fixture.storage.commit_episode(conflicting).unwrap_err();
        assert_eq!(error.code, ExperienceEpisodeErrorCode::EpisodeConflict);
    }

    #[test]
    fn fixed_kind_source_outcome_and_version_are_rejected() {
        let fixture = EpisodeFixture::new();
        let mut invalid = fixture.episode();
        invalid.episode_kind = "memory".into();
        assert_eq!(
            fixture.storage.commit_episode(invalid).unwrap_err().code,
            ExperienceEpisodeErrorCode::InvalidArgument
        );
        let mut invalid = fixture.episode();
        invalid.source_kind = "memory".into();
        assert_eq!(
            fixture.storage.commit_episode(invalid).unwrap_err().code,
            ExperienceEpisodeErrorCode::InvalidArgument
        );
        let mut invalid = fixture.episode();
        invalid.outcome_kind = "failed".into();
        assert_eq!(
            fixture.storage.commit_episode(invalid).unwrap_err().code,
            ExperienceEpisodeErrorCode::InvalidArgument
        );
        let mut invalid = fixture.episode();
        invalid.episode_version = 2;
        assert_eq!(
            fixture.storage.commit_episode(invalid).unwrap_err().code,
            ExperienceEpisodeErrorCode::InvalidArgument
        );
    }

    #[test]
    fn wrong_life_conversation_or_turn_binding_is_rejected() {
        let fixture = EpisodeFixture::new();
        let mut invalid = fixture.episode();
        invalid.turn_id = "missing-turn".into();
        invalid.source_ref = "episode-conversation:missing-turn".into();
        invalid.episode_id =
            "experience-conversation:episode-life:episode-conversation:missing-turn".into();
        let error = fixture.storage.commit_episode(invalid).unwrap_err();
        assert_eq!(
            error.code,
            ExperienceEpisodeErrorCode::SourceBindingMismatch
        );
    }

    #[test]
    fn swapped_message_ids_and_message_timestamp_mismatch_are_rejected() {
        let fixture = EpisodeFixture::new();
        let mut swapped = fixture.episode();
        std::mem::swap(
            &mut swapped.user_message_id,
            &mut swapped.assistant_message_id,
        );
        assert_eq!(
            fixture.storage.commit_episode(swapped).unwrap_err().code,
            ExperienceEpisodeErrorCode::SourceBindingMismatch
        );

        let mut timestamp_mismatch = fixture.episode();
        timestamp_mismatch.started_at = "2026-08-26T00:00:00.000Z".into();
        assert_eq!(
            fixture
                .storage
                .commit_episode(timestamp_mismatch)
                .unwrap_err()
                .code,
            ExperienceEpisodeErrorCode::SourceBindingMismatch
        );
    }

    #[test]
    fn noncanonical_episode_id_and_source_reference_are_rejected() {
        let fixture = EpisodeFixture::new();
        let mut invalid = fixture.episode();
        invalid.episode_id = "wrong-episode-id".into();
        assert_eq!(
            fixture.storage.commit_episode(invalid).unwrap_err().code,
            ExperienceEpisodeErrorCode::SourceBindingMismatch
        );
        let mut invalid = fixture.episode();
        invalid.source_ref = "wrong-source-ref".into();
        assert_eq!(
            fixture.storage.commit_episode(invalid).unwrap_err().code,
            ExperienceEpisodeErrorCode::SourceBindingMismatch
        );
    }

    #[test]
    fn episode_update_is_rejected_by_the_immutable_guard() {
        let fixture = EpisodeFixture::new();
        fixture.storage.commit_episode(fixture.episode()).unwrap();
        let state = fixture.storage.state().unwrap();
        let error = state
            .connection
            .execute(
                "UPDATE experience_episode SET outcome_kind = 'completed'",
                [],
            )
            .unwrap_err();
        assert!(error.to_string().contains("EXPERIENCE_EPISODE_IMMUTABLE"));
    }

    #[test]
    fn deleting_conversation_cascades_to_episode() {
        let fixture = EpisodeFixture::new();
        fixture.storage.commit_episode(fixture.episode()).unwrap();
        ConversationRepository::delete_conversation(
            &fixture.storage,
            "episode-life",
            "episode-conversation",
        )
        .unwrap();
        assert_eq!(fixture.count(), 0);
    }

    #[test]
    fn deleting_either_message_cascades_to_episode() {
        for message_id in ["episode-user-message", "episode-assistant-message"] {
            let fixture = EpisodeFixture::new();
            fixture.storage.commit_episode(fixture.episode()).unwrap();
            fixture
                .storage
                .delete_conversation_message_governed(
                    "episode-life",
                    "episode-conversation",
                    message_id,
                )
                .unwrap();
            assert_eq!(fixture.count(), 0, "deleting {message_id} must cascade");
        }
    }

    #[test]
    fn deleting_life_cascades_to_episode() {
        let fixture = EpisodeFixture::new();
        fixture.storage.commit_episode(fixture.episode()).unwrap();
        let state = fixture.storage.state().unwrap();
        state
            .connection
            .execute(
                "UPDATE app_state SET current_life_id = NULL WHERE singleton = 1",
                [],
            )
            .unwrap();
        state
            .connection
            .execute("DELETE FROM life_identity WHERE id = 'episode-life'", [])
            .unwrap();
        drop(state);
        assert_eq!(fixture.count(), 0);
    }

    #[test]
    fn episode_record_and_schema_never_contain_raw_conversation_content() {
        let fixture = EpisodeFixture::new();
        let episode = fixture.episode();
        fixture.storage.commit_episode(episode.clone()).unwrap();
        let serialized = serde_json::to_string(&episode).unwrap();
        assert!(!serialized.contains("raw user content"));
        assert!(!serialized.contains("raw assistant content"));

        let state = fixture.storage.state().unwrap();
        let columns: Vec<String> = state
            .connection
            .prepare("SELECT name FROM pragma_table_info('experience_episode')")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|row| row.unwrap())
            .collect();
        assert!(!columns.iter().any(|column| column == "content"));
        let stored_debug = format!("{episode:?}");
        assert!(!stored_debug.contains("raw user content"));
        assert!(!stored_debug.contains("raw assistant content"));
    }

    #[test]
    fn source_binding_trigger_rejects_inconsistent_authorized_direct_insert() {
        let fixture = EpisodeFixture::new();
        let episode = fixture.episode();
        let state = fixture.storage.state().unwrap();
        let error = state
            .connection
            .execute(
                &format!(
                    "INSERT INTO experience_episode ({EXPERIENCE_EPISODE_COLUMNS})
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"
                ),
                params![
                    episode.episode_id,
                    episode.life_id,
                    episode.episode_kind,
                    episode.source_kind,
                    episode.source_ref,
                    episode.conversation_id,
                    episode.turn_id,
                    episode.counterpart_subject_id,
                    "episode-assistant-message",
                    episode.assistant_message_id,
                    episode.outcome_kind,
                    episode.started_at,
                    episode.ended_at,
                    episode.episode_version,
                    episode.created_at,
                ],
            )
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("EXPERIENCE_EPISODE_SOURCE_BINDING_MISMATCH"));
    }

    #[test]
    fn latest_episode_lookup_is_bounded_and_orders_by_ended_at() {
        let fixture = EpisodeFixture::new();
        let first = fixture.episode();
        fixture.storage.commit_episode(first).unwrap();

        let state = fixture.storage.state().unwrap();
        state
            .connection
            .execute(
                "INSERT INTO conversation
                     (id, life_id, title, revision, created_at, updated_at, last_message_at)
                 VALUES ('episode-conversation-later', 'episode-life', 'Later', 1,
                         '2026-08-26T00:00:00.003Z', '2026-08-26T00:00:00.004Z',
                         '2026-08-26T00:00:00.004Z')",
                [],
            )
            .unwrap();
        state
            .connection
            .execute(
                "INSERT INTO conversation_message
                     (id, conversation_id, life_id, turn_id, role, content, sequence_no, created_at)
                 VALUES ('episode-user-message-later', 'episode-conversation-later',
                         'episode-life', 'episode-turn-later', 'user', 'later user', 1,
                         '2026-08-26T00:00:00.003Z'),
                        ('episode-assistant-message-later', 'episode-conversation-later',
                         'episode-life', 'episode-turn-later', 'assistant', 'later assistant', 2,
                         '2026-08-26T00:00:00.004Z')",
                [],
            )
            .unwrap();
        drop(state);

        let later = ExperienceEpisode {
            episode_id:
                "experience-conversation:episode-life:episode-conversation-later:episode-turn-later"
                    .into(),
            life_id: "episode-life".into(),
            episode_kind: EPISODE_KIND.into(),
            source_kind: SOURCE_KIND.into(),
            source_ref: "episode-conversation-later:episode-turn-later".into(),
            conversation_id: "episode-conversation-later".into(),
            turn_id: "episode-turn-later".into(),
            counterpart_subject_id: "primary_user".into(),
            user_message_id: "episode-user-message-later".into(),
            assistant_message_id: "episode-assistant-message-later".into(),
            outcome_kind: OUTCOME_KIND.into(),
            started_at: "2026-08-26T00:00:00.003Z".into(),
            ended_at: "2026-08-26T00:00:00.004Z".into(),
            episode_version: EPISODE_VERSION,
            created_at: "2026-08-26T00:00:00.004Z".into(),
        };
        fixture.storage.commit_episode(later.clone()).unwrap();
        assert_eq!(
            fixture
                .storage
                .find_latest_episode_for_life("episode-life")
                .unwrap(),
            Some(later)
        );
    }
}
