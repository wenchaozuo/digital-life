use rusqlite::{params, Connection, OptionalExtension, Row, Transaction};

use crate::conversation::history::{
    generate_id, AppendConversationTurnRequest, AppendConversationTurnResult,
    ConversationHistoryError, ConversationHistoryErrorCode, ConversationMessagePage,
    ConversationMessageRecord, ConversationPageRequest, ConversationRecord, ConversationRepository,
    ConversationRole, CreateConversationRequest, RenameConversationRequest,
};

use super::StorageService;

const CONVERSATION_COLUMNS: &str =
    "id, life_id, title, revision, created_at, updated_at, last_message_at";
const MESSAGE_COLUMNS: &str =
    "id, conversation_id, life_id, turn_id, role, content, sequence_no, created_at";

impl ConversationRepository for StorageService {
    fn create_conversation(
        &self,
        id: &str,
        request: &CreateConversationRequest,
    ) -> Result<ConversationRecord, ConversationHistoryError> {
        let state = self.state().map_err(|_| storage_unavailable())?;
        let life_exists: bool = state
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
                params![request.life_id],
                |row| row.get(0),
            )
            .map_err(|_| storage_unavailable())?;
        if !life_exists {
            return Err(ConversationHistoryError::new(
                ConversationHistoryErrorCode::ConversationNotFound,
            ));
        }
        state
            .connection
            .execute(
                "INSERT INTO conversation (
                    id, life_id, title, revision, created_at, updated_at, last_message_at
                 ) VALUES (
                    ?1, ?2, ?3, 0,
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 )",
                params![id, request.life_id, request.title],
            )
            .map_err(|_| storage_unavailable())?;
        load_conversation(&state.connection, &request.life_id, id)
    }

    fn get_conversation(
        &self,
        life_id: &str,
        conversation_id: &str,
    ) -> Result<ConversationRecord, ConversationHistoryError> {
        let state = self.state().map_err(|_| storage_unavailable())?;
        load_conversation(&state.connection, life_id, conversation_id)
    }

    fn list_conversations(
        &self,
        life_id: &str,
    ) -> Result<Vec<ConversationRecord>, ConversationHistoryError> {
        let state = self.state().map_err(|_| storage_unavailable())?;
        ensure_life_exists(&state.connection, life_id)?;
        let mut statement = state
            .connection
            .prepare(&format!(
                "SELECT {CONVERSATION_COLUMNS} FROM conversation
                 WHERE life_id = ?1
                 ORDER BY last_message_at DESC, id ASC"
            ))
            .map_err(|_| storage_unavailable())?;
        let rows = statement
            .query_map(params![life_id], read_conversation)
            .map_err(|_| storage_unavailable())?;
        rows.map(|row| row.map_err(|_| storage_unavailable()))
            .collect()
    }

    fn rename_conversation(
        &self,
        request: &RenameConversationRequest,
    ) -> Result<ConversationRecord, ConversationHistoryError> {
        let state = self.state().map_err(|_| storage_unavailable())?;
        ensure_conversation_owner(
            &state.connection,
            &request.life_id,
            &request.conversation_id,
        )?;
        state
            .connection
            .execute(
                "UPDATE conversation SET title = ?3,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND life_id = ?2",
                params![request.conversation_id, request.life_id, request.title],
            )
            .map_err(|_| storage_unavailable())?;
        load_conversation(
            &state.connection,
            &request.life_id,
            &request.conversation_id,
        )
    }

    fn delete_conversation(
        &self,
        life_id: &str,
        conversation_id: &str,
    ) -> Result<(), ConversationHistoryError> {
        let state = self.state().map_err(|_| storage_unavailable())?;
        ensure_conversation_owner(&state.connection, life_id, conversation_id)?;
        let deleted = state
            .connection
            .execute(
                "DELETE FROM conversation WHERE id = ?1 AND life_id = ?2",
                params![conversation_id, life_id],
            )
            .map_err(|_| storage_unavailable())?;
        if deleted != 1 {
            return Err(ConversationHistoryError::new(
                ConversationHistoryErrorCode::ConversationNotFound,
            ));
        }
        Ok(())
    }

    fn load_recent_messages(
        &self,
        life_id: &str,
        conversation_id: &str,
        limit: usize,
    ) -> Result<Vec<ConversationMessageRecord>, ConversationHistoryError> {
        let state = self.state().map_err(|_| storage_unavailable())?;
        ensure_conversation_owner(&state.connection, life_id, conversation_id)?;
        let mut statement = state
            .connection
            .prepare(&format!(
                "SELECT {MESSAGE_COLUMNS} FROM (
                    SELECT {MESSAGE_COLUMNS} FROM conversation_message
                    WHERE conversation_id = ?1 AND life_id = ?2
                    ORDER BY sequence_no DESC LIMIT ?3
                 ) ORDER BY sequence_no ASC"
            ))
            .map_err(|_| storage_unavailable())?;
        let rows = statement
            .query_map(
                params![conversation_id, life_id, limit as i64],
                read_stored_message,
            )
            .map_err(|_| storage_unavailable())?;
        rows.map(|row| row.map_err(|_| storage_unavailable())?.try_into())
            .collect()
    }

    fn load_message_page(
        &self,
        request: &ConversationPageRequest,
    ) -> Result<ConversationMessagePage, ConversationHistoryError> {
        let state = self.state().map_err(|_| storage_unavailable())?;
        ensure_conversation_owner(
            &state.connection,
            &request.life_id,
            &request.conversation_id,
        )?;
        let after = request.after_sequence_no.unwrap_or(0);
        let mut statement = state
            .connection
            .prepare(&format!(
                "SELECT {MESSAGE_COLUMNS} FROM conversation_message
                 WHERE conversation_id = ?1 AND life_id = ?2 AND sequence_no > ?3
                 ORDER BY sequence_no ASC LIMIT ?4"
            ))
            .map_err(|_| storage_unavailable())?;
        let rows = statement
            .query_map(
                params![
                    request.conversation_id,
                    request.life_id,
                    after,
                    request.limit as i64
                ],
                read_stored_message,
            )
            .map_err(|_| storage_unavailable())?;
        let messages: Vec<ConversationMessageRecord> = rows
            .map(|row| row.map_err(|_| storage_unavailable())?.try_into())
            .collect::<Result<_, _>>()?;
        let next_after_sequence_no = messages
            .last()
            .map(|message| message.sequence_no)
            .filter(|_| messages.len() == request.limit);
        Ok(ConversationMessagePage {
            messages,
            next_after_sequence_no,
        })
    }

    fn append_complete_turn(
        &self,
        request: &AppendConversationTurnRequest,
    ) -> Result<AppendConversationTurnResult, ConversationHistoryError> {
        let mut state = self.state().map_err(|_| storage_unavailable())?;
        let transaction = state
            .connection
            .transaction()
            .map_err(|_| storage_unavailable())?;
        let conversation =
            load_conversation(&transaction, &request.life_id, &request.conversation_id)?;
        if let Some(mut existing) = load_turn(
            &transaction,
            &request.life_id,
            &request.conversation_id,
            &request.turn_id,
        )? {
            if existing.user_message.content != request.user_content {
                return Err(ConversationHistoryError::new(
                    ConversationHistoryErrorCode::TurnIdConflict,
                ));
            }
            existing.replayed = true;
            existing.conversation_revision = conversation.revision;
            return Ok(existing);
        }
        if request
            .expected_revision
            .is_some_and(|expected| expected != conversation.revision)
        {
            return Err(ConversationHistoryError::new(
                ConversationHistoryErrorCode::ConversationChangedDuringRequest,
            ));
        }
        let next_sequence: i64 = transaction
            .query_row(
                "SELECT COALESCE(MAX(sequence_no), 0) + 1 FROM conversation_message
                 WHERE conversation_id = ?1 AND life_id = ?2",
                params![request.conversation_id, request.life_id],
                |row| row.get(0),
            )
            .map_err(|_| storage_unavailable())?;
        insert_message(
            &transaction,
            &generate_id("message"),
            request,
            ConversationRole::User,
            &request.user_content,
            next_sequence,
        )?;
        insert_message(
            &transaction,
            &generate_id("message"),
            request,
            ConversationRole::Assistant,
            &request.assistant_content,
            next_sequence + 1,
        )?;
        let updated = transaction
            .execute(
                "UPDATE conversation SET revision = revision + 1,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                 last_message_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND life_id = ?2 AND revision = ?3",
                params![
                    request.conversation_id,
                    request.life_id,
                    conversation.revision
                ],
            )
            .map_err(|_| storage_unavailable())?;
        if updated != 1 {
            return Err(ConversationHistoryError::new(
                ConversationHistoryErrorCode::ConversationChangedDuringRequest,
            ));
        }
        let mut result = load_turn(
            &transaction,
            &request.life_id,
            &request.conversation_id,
            &request.turn_id,
        )?
        .ok_or_else(|| {
            ConversationHistoryError::new(ConversationHistoryErrorCode::InternalError)
        })?;
        result.conversation_revision = conversation.revision + 1;
        transaction.commit().map_err(|_| storage_unavailable())?;
        Ok(result)
    }

    fn find_committed_turn(
        &self,
        life_id: &str,
        conversation_id: &str,
        turn_id: &str,
    ) -> Result<Option<AppendConversationTurnResult>, ConversationHistoryError> {
        let state = self.state().map_err(|_| storage_unavailable())?;
        let conversation = load_conversation(&state.connection, life_id, conversation_id)?;
        let mut result = load_turn(&state.connection, life_id, conversation_id, turn_id)?;
        if let Some(value) = result.as_mut() {
            value.conversation_revision = conversation.revision;
        }
        Ok(result)
    }

    fn count_conversations(&self, life_id: &str) -> Result<usize, ConversationHistoryError> {
        let state = self.state().map_err(|_| storage_unavailable())?;
        ensure_life_exists(&state.connection, life_id)?;
        count_query(
            &state.connection,
            "SELECT COUNT(*) FROM conversation WHERE life_id = ?1",
            params![life_id],
        )
    }

    fn count_messages(
        &self,
        life_id: &str,
        conversation_id: &str,
    ) -> Result<usize, ConversationHistoryError> {
        let state = self.state().map_err(|_| storage_unavailable())?;
        ensure_conversation_owner(&state.connection, life_id, conversation_id)?;
        count_query(
            &state.connection,
            "SELECT COUNT(*) FROM conversation_message
             WHERE conversation_id = ?1 AND life_id = ?2",
            params![conversation_id, life_id],
        )
    }
}

fn insert_message(
    transaction: &Transaction<'_>,
    id: &str,
    request: &AppendConversationTurnRequest,
    role: ConversationRole,
    content: &str,
    sequence_no: i64,
) -> Result<(), ConversationHistoryError> {
    transaction
        .execute(
            "INSERT INTO conversation_message (
                id, conversation_id, life_id, turn_id, role, content, sequence_no, created_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7,
                strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             )",
            params![
                id,
                request.conversation_id,
                request.life_id,
                request.turn_id,
                role.as_str(),
                content,
                sequence_no
            ],
        )
        .map_err(|_| storage_unavailable())?;
    Ok(())
}

fn load_conversation(
    connection: &Connection,
    life_id: &str,
    conversation_id: &str,
) -> Result<ConversationRecord, ConversationHistoryError> {
    let record = connection
        .query_row(
            &format!("SELECT {CONVERSATION_COLUMNS} FROM conversation WHERE id = ?1"),
            params![conversation_id],
            read_conversation,
        )
        .optional()
        .map_err(|_| storage_unavailable())?
        .ok_or_else(|| {
            ConversationHistoryError::new(ConversationHistoryErrorCode::ConversationNotFound)
        })?;
    if record.life_id != life_id {
        return Err(ConversationHistoryError::new(
            ConversationHistoryErrorCode::ConversationLifeMismatch,
        ));
    }
    Ok(record)
}

fn ensure_conversation_owner(
    connection: &Connection,
    life_id: &str,
    conversation_id: &str,
) -> Result<(), ConversationHistoryError> {
    load_conversation(connection, life_id, conversation_id).map(|_| ())
}

fn ensure_life_exists(
    connection: &Connection,
    life_id: &str,
) -> Result<(), ConversationHistoryError> {
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
            params![life_id],
            |row| row.get(0),
        )
        .map_err(|_| storage_unavailable())?;
    if exists {
        Ok(())
    } else {
        Err(ConversationHistoryError::new(
            ConversationHistoryErrorCode::ConversationNotFound,
        ))
    }
}

fn load_turn(
    connection: &Connection,
    life_id: &str,
    conversation_id: &str,
    turn_id: &str,
) -> Result<Option<AppendConversationTurnResult>, ConversationHistoryError> {
    let mut statement = connection
        .prepare(&format!(
            "SELECT {MESSAGE_COLUMNS} FROM conversation_message
             WHERE conversation_id = ?1 AND life_id = ?2 AND turn_id = ?3
             ORDER BY sequence_no ASC"
        ))
        .map_err(|_| storage_unavailable())?;
    let rows = statement
        .query_map(
            params![conversation_id, life_id, turn_id],
            read_stored_message,
        )
        .map_err(|_| storage_unavailable())?;
    let messages: Vec<ConversationMessageRecord> = rows
        .map(|row| row.map_err(|_| storage_unavailable())?.try_into())
        .collect::<Result<_, _>>()?;
    if messages.is_empty() {
        return Ok(None);
    }
    if messages.len() != 2 {
        return Err(ConversationHistoryError::new(
            ConversationHistoryErrorCode::IncompleteTurn,
        ));
    }
    let user_message = messages
        .iter()
        .find(|message| message.role == ConversationRole::User)
        .cloned();
    let assistant_message = messages
        .iter()
        .find(|message| message.role == ConversationRole::Assistant)
        .cloned();
    match (user_message, assistant_message) {
        (Some(user_message), Some(assistant_message)) => Ok(Some(AppendConversationTurnResult {
            user_message,
            assistant_message,
            conversation_revision: 0,
            replayed: false,
        })),
        _ => Err(ConversationHistoryError::new(
            ConversationHistoryErrorCode::IncompleteTurn,
        )),
    }
}

fn read_conversation(row: &Row<'_>) -> rusqlite::Result<ConversationRecord> {
    Ok(ConversationRecord {
        id: row.get(0)?,
        life_id: row.get(1)?,
        title: row.get(2)?,
        revision: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        last_message_at: row.get(6)?,
    })
}

struct StoredConversationMessage {
    id: String,
    conversation_id: String,
    life_id: String,
    turn_id: String,
    role: String,
    content: String,
    sequence_no: i64,
    created_at: String,
}

impl TryFrom<StoredConversationMessage> for ConversationMessageRecord {
    type Error = ConversationHistoryError;

    fn try_from(value: StoredConversationMessage) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            conversation_id: value.conversation_id,
            life_id: value.life_id,
            turn_id: value.turn_id,
            role: ConversationRole::parse(&value.role)?,
            content: value.content,
            sequence_no: value.sequence_no,
            created_at: value.created_at,
        })
    }
}

fn read_stored_message(row: &Row<'_>) -> rusqlite::Result<StoredConversationMessage> {
    Ok(StoredConversationMessage {
        id: row.get(0)?,
        conversation_id: row.get(1)?,
        life_id: row.get(2)?,
        turn_id: row.get(3)?,
        role: row.get(4)?,
        content: row.get(5)?,
        sequence_no: row.get(6)?,
        created_at: row.get(7)?,
    })
}

fn count_query<P: rusqlite::Params>(
    connection: &Connection,
    sql: &str,
    params: P,
) -> Result<usize, ConversationHistoryError> {
    let count: i64 = connection
        .query_row(sql, params, |row| row.get(0))
        .map_err(|_| storage_unavailable())?;
    usize::try_from(count)
        .map_err(|_| ConversationHistoryError::new(ConversationHistoryErrorCode::InternalError))
}

fn storage_unavailable() -> ConversationHistoryError {
    ConversationHistoryError::new(ConversationHistoryErrorCode::ConversationStorageUnavailable)
}

#[cfg(test)]
mod tests {
    use crate::{
        conversation::history::{
            ConversationHistoryService, MAX_CONVERSATION_MESSAGE_CHARACTERS,
            MAX_CONVERSATION_TITLE_CHARACTERS,
        },
        memory::{CreateMemoryCandidateRequest, MemoryKind, MemoryService, MemorySourceType},
        storage::{LifeIdentityRecord, PersonaTemplateRecord, DATABASE_FILE_NAME, MIGRATIONS},
    };

    use super::*;

    fn seeded_storage() -> (tempfile::TempDir, StorageService) {
        let temp = tempfile::tempdir().unwrap();
        let storage =
            StorageService::initialize_with_roots(temp.path().join("data"), None).unwrap();
        for suffix in ["a", "b"] {
            storage
                .save_persona(PersonaTemplateRecord {
                    id: format!("persona-{suffix}"),
                    name: format!("Persona {suffix}"),
                    version: 1,
                    persona_json: format!(r#"{{"id":"persona-{suffix}"}}"#),
                })
                .unwrap();
            storage
                .save_life(LifeIdentityRecord {
                    id: format!("life-{suffix}"),
                    name: format!("Life {suffix}"),
                    created_at: "2026-07-13T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "test-body".into(),
                    persona_id: format!("persona-{suffix}"),
                    persona_version: 1,
                })
                .unwrap();
        }
        (temp, storage)
    }

    fn create(storage: &StorageService, life_id: &str, title: &str) -> ConversationRecord {
        ConversationHistoryService::new(storage)
            .create(CreateConversationRequest {
                life_id: life_id.into(),
                title: title.into(),
            })
            .unwrap()
    }

    fn append(
        storage: &StorageService,
        conversation: &ConversationRecord,
        turn: &str,
        user: &str,
        assistant: &str,
    ) -> AppendConversationTurnResult {
        ConversationHistoryService::new(storage)
            .append_turn(AppendConversationTurnRequest {
                life_id: conversation.life_id.clone(),
                conversation_id: conversation.id.clone(),
                turn_id: turn.into(),
                user_content: user.into(),
                assistant_content: assistant.into(),
                expected_revision: None,
            })
            .unwrap()
    }

    #[test]
    fn migration_005_upgrades_to_006_idempotently_without_governed_context_columns() {
        let temp = tempfile::tempdir().unwrap();
        let data_root = temp.path().join("data");
        std::fs::create_dir_all(&data_root).unwrap();
        let database = data_root.join(DATABASE_FILE_NAME);
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migration (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                 );",
            )
            .unwrap();
        for (version, name, sql) in MIGRATIONS.iter().take(5) {
            connection.execute_batch(sql).unwrap();
            connection
                .execute(
                    "INSERT INTO schema_migration (version, name, applied_at)
                     VALUES (?1, ?2, '2026-07-13T00:00:00.000Z')",
                    params![version, name],
                )
                .unwrap();
        }
        drop(connection);

        let storage = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        let state = storage.state().unwrap();
        let version: i64 = state
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 6);
        let mut columns = Vec::new();
        for table in ["conversation", "conversation_message"] {
            columns.extend(
                state
                    .connection
                    .prepare(&format!("PRAGMA table_info({table})"))
                    .unwrap()
                    .query_map([], |row| row.get::<_, String>(1))
                    .unwrap()
                    .map(Result::unwrap),
            );
        }
        for column in columns {
            let lower = column.to_ascii_lowercase();
            for forbidden in ["prompt", "memory", "api_key", "vector", "profile", "path"] {
                assert!(!lower.contains(forbidden));
            }
        }
        drop(state);
        drop(storage);

        let reopened = StorageService::initialize_with_roots(data_root, None).unwrap();
        let count: i64 = reopened
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migration WHERE version = 6",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn create_rename_list_title_limits_and_life_isolation_are_strict() {
        let (_temp, storage) = seeded_storage();
        let service = ConversationHistoryService::new(&storage);
        let first = service
            .create(CreateConversationRequest {
                life_id: "life-a".into(),
                title: "  First conversation  ".into(),
            })
            .unwrap();
        assert_eq!(first.title, "First conversation");
        let unicode = "界".repeat(MAX_CONVERSATION_TITLE_CHARACTERS);
        let second = create(&storage, "life-a", &unicode);
        assert!(service
            .create(CreateConversationRequest {
                life_id: "life-a".into(),
                title: "界".repeat(MAX_CONVERSATION_TITLE_CHARACTERS + 1),
            })
            .is_err());
        assert!(service
            .create(CreateConversationRequest {
                life_id: "life-a".into(),
                title: "  ".into(),
            })
            .is_err());
        let renamed = service
            .rename(RenameConversationRequest {
                life_id: "life-a".into(),
                conversation_id: first.id.clone(),
                title: " Renamed ".into(),
            })
            .unwrap();
        assert_eq!(renamed.title, "Renamed");

        {
            let state = storage.state().unwrap();
            state
                .connection
                .execute(
                    "UPDATE conversation SET last_message_at = '2026-07-13T02:00:00Z'
                     WHERE id IN (?1, ?2)",
                    params![first.id, second.id],
                )
                .unwrap();
        }
        let listed = service.list("life-a").unwrap();
        let mut expected = vec![first.id.clone(), second.id.clone()];
        expected.sort();
        assert_eq!(
            listed
                .iter()
                .map(|item| item.id.clone())
                .collect::<Vec<_>>(),
            expected
        );
        assert!(service.list("life-b").unwrap().is_empty());
        for error in [
            service.get("life-b", &first.id).unwrap_err(),
            service
                .rename(RenameConversationRequest {
                    life_id: "life-b".into(),
                    conversation_id: first.id.clone(),
                    title: "forbidden".into(),
                })
                .unwrap_err(),
            service.delete("life-b", &first.id).unwrap_err(),
        ] {
            assert_eq!(
                error.code,
                ConversationHistoryErrorCode::ConversationLifeMismatch
            );
        }
        assert_eq!(service.count_conversations("life-a").unwrap(), 2);
    }

    #[test]
    fn append_turn_is_atomic_contiguous_idempotent_and_content_safe() {
        let (_temp, storage) = seeded_storage();
        let conversation = create(&storage, "life-a", "Atomic turn");
        let first = append(
            &storage,
            &conversation,
            "request-1",
            " user exact ",
            " assistant exact ",
        );
        assert_eq!(first.user_message.sequence_no, 1);
        assert_eq!(first.assistant_message.sequence_no, 2);
        assert_eq!(first.user_message.content, " user exact ");
        assert_eq!(first.assistant_message.content, " assistant exact ");
        assert!(!first.replayed);

        let replay = append(
            &storage,
            &conversation,
            "request-1",
            " user exact ",
            "ignored new assistant",
        );
        assert!(replay.replayed);
        assert_eq!(replay.assistant_message.content, " assistant exact ");
        assert_eq!(
            ConversationHistoryService::new(&storage)
                .count_messages("life-a", &conversation.id)
                .unwrap(),
            2
        );
        let conflict = ConversationHistoryService::new(&storage)
            .append_turn(AppendConversationTurnRequest {
                life_id: "life-a".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "request-1".into(),
                user_content: "different".into(),
                assistant_content: "not stored".into(),
                expected_revision: None,
            })
            .unwrap_err();
        assert_eq!(conflict.code, ConversationHistoryErrorCode::TurnIdConflict);
        assert!(!conflict.message.contains("different"));

        let second = append(
            &storage,
            &conversation,
            "request-2",
            "next user",
            "next assistant",
        );
        assert_eq!(
            (
                second.user_message.sequence_no,
                second.assistant_message.sequence_no
            ),
            (3, 4)
        );
        let other = create(&storage, "life-a", "Other");
        assert_eq!(
            append(&storage, &other, "request-1", "allowed", "allowed")
                .user_message
                .sequence_no,
            1
        );
        let too_long = "界".repeat(MAX_CONVERSATION_MESSAGE_CHARACTERS + 1);
        let invalid = ConversationHistoryService::new(&storage)
            .append_turn(AppendConversationTurnRequest {
                life_id: "life-a".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "too-long".into(),
                user_content: too_long,
                assistant_content: "assistant".into(),
                expected_revision: None,
            })
            .unwrap_err();
        assert_eq!(
            invalid.code,
            ConversationHistoryErrorCode::InvalidMessageContent
        );
    }

    #[test]
    fn user_or_assistant_insert_failure_rolls_back_the_complete_turn_and_metadata() {
        let (_temp, storage) = seeded_storage();
        let conversation = create(&storage, "life-a", "Rollback");
        for role in ["user", "assistant"] {
            let trigger = format!(
                "CREATE TEMP TRIGGER fail_{role}_message
                 BEFORE INSERT ON conversation_message WHEN NEW.role = '{role}'
                 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;"
            );
            storage
                .state()
                .unwrap()
                .connection
                .execute_batch(&trigger)
                .unwrap();
            let before = ConversationHistoryService::new(&storage)
                .get("life-a", &conversation.id)
                .unwrap();
            let error = ConversationHistoryService::new(&storage)
                .append_turn(AppendConversationTurnRequest {
                    life_id: "life-a".into(),
                    conversation_id: conversation.id.clone(),
                    turn_id: format!("fail-{role}"),
                    user_content: "must roll back".into(),
                    assistant_content: "must roll back".into(),
                    expected_revision: Some(before.revision),
                })
                .unwrap_err();
            assert_eq!(
                error.code,
                ConversationHistoryErrorCode::ConversationStorageUnavailable
            );
            assert_eq!(
                ConversationHistoryService::new(&storage)
                    .count_messages("life-a", &conversation.id)
                    .unwrap(),
                0
            );
            let after = ConversationHistoryService::new(&storage)
                .get("life-a", &conversation.id)
                .unwrap();
            assert_eq!(
                (after.revision, after.updated_at, after.last_message_at),
                (before.revision, before.updated_at, before.last_message_at)
            );
            storage
                .state()
                .unwrap()
                .connection
                .execute_batch(&format!("DROP TRIGGER fail_{role}_message"))
                .unwrap();
        }
    }

    #[test]
    fn recent_window_and_cursor_pages_are_stable_and_ascending() {
        let (_temp, storage) = seeded_storage();
        let conversation = create(&storage, "life-a", "Paging");
        for index in 0..12 {
            append(
                &storage,
                &conversation,
                &format!("turn-{index}"),
                &format!("user-{index}"),
                &format!("assistant-{index}"),
            );
        }
        let service = ConversationHistoryService::new(&storage);
        let recent = service.recent_messages("life-a", &conversation.id).unwrap();
        assert_eq!(recent.len(), 20);
        assert_eq!(recent.first().unwrap().sequence_no, 5);
        assert_eq!(recent.last().unwrap().sequence_no, 24);
        assert!(recent
            .windows(2)
            .all(|pair| pair[0].sequence_no < pair[1].sequence_no));

        let first = service
            .page(ConversationPageRequest {
                life_id: "life-a".into(),
                conversation_id: conversation.id.clone(),
                after_sequence_no: None,
                limit: 7,
            })
            .unwrap();
        let second = service
            .page(ConversationPageRequest {
                life_id: "life-a".into(),
                conversation_id: conversation.id.clone(),
                after_sequence_no: first.next_after_sequence_no,
                limit: 7,
            })
            .unwrap();
        assert_eq!(first.messages.first().unwrap().sequence_no, 1);
        assert_eq!(first.messages.last().unwrap().sequence_no, 7);
        assert_eq!(second.messages.first().unwrap().sequence_no, 8);
        assert_eq!(second.messages.last().unwrap().sequence_no, 14);
    }

    #[test]
    fn invalid_roles_and_incomplete_legacy_turns_are_rejected() {
        let (_temp, storage) = seeded_storage();
        let conversation = create(&storage, "life-a", "Integrity");
        let state = storage.state().unwrap();
        let invalid_role = state.connection.execute(
            "INSERT INTO conversation_message
             (id, conversation_id, life_id, turn_id, role, content, sequence_no, created_at)
             VALUES ('invalid-role', ?1, 'life-a', 'invalid-role', 'system', 'body', 1, '2026-07-13T00:00:00Z')",
            params![conversation.id],
        );
        assert!(invalid_role.is_err());
        state.connection.execute(
            "INSERT INTO conversation_message
             (id, conversation_id, life_id, turn_id, role, content, sequence_no, created_at)
             VALUES ('legacy-user', ?1, 'life-a', 'legacy-turn', 'user', 'legacy body', 1, '2026-07-13T00:00:00Z')",
            params![conversation.id],
        ).unwrap();
        drop(state);
        let error = ConversationHistoryService::new(&storage)
            .find_turn("life-a", &conversation.id, "legacy-turn")
            .unwrap_err();
        assert_eq!(error.code, ConversationHistoryErrorCode::IncompleteTurn);
        assert!(!error.message.contains("legacy body"));
    }

    #[test]
    fn delete_cascades_messages_but_preserves_authoritative_memory() {
        let (_temp, storage) = seeded_storage();
        let memory = MemoryService::new(&storage)
            .create_candidate(CreateMemoryCandidateRequest {
                life_id: "life-a".into(),
                kind: MemoryKind::Fact,
                content: "memory must survive conversation deletion".into(),
                summary: None,
                source_type: MemorySourceType::Manual,
                source_ref: None,
                source_created_at: "2026-07-13T00:00:00Z".into(),
                importance: 0.5,
                confidence: 0.8,
                is_sensitive: false,
            })
            .unwrap();
        let conversation = create(&storage, "life-a", "Delete");
        append(&storage, &conversation, "delete-turn", "user", "assistant");
        ConversationHistoryService::new(&storage)
            .delete("life-a", &conversation.id)
            .unwrap();
        assert_eq!(
            storage
                .state()
                .unwrap()
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM conversation_message WHERE conversation_id = ?1",
                    params![conversation.id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            0
        );
        assert_eq!(
            MemoryService::new(&storage)
                .get("life-a", &memory.id)
                .unwrap()
                .content,
            "memory must survive conversation deletion"
        );
        let missing = ConversationHistoryService::new(&storage)
            .delete("life-a", &conversation.id)
            .unwrap_err();
        assert_eq!(
            missing.code,
            ConversationHistoryErrorCode::ConversationNotFound
        );
    }
}
