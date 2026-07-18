use rusqlite::{params, OptionalExtension, Row, Transaction, TransactionBehavior};

use crate::memory::{
    revisions::{
        DeleteMemoryPermanentlyRequest, MemoryRevisionChangeType, MemoryRevisionRecord,
        MemoryRevisionRepository, MemoryUpdateResult, SetMemorySensitivityRequest,
        UpdateConfirmedMemoryRequest,
    },
    vector_sync_outbox::MemoryVectorSyncAction,
    DeleteMemoryResult, MemoryError, MemoryKind, MemoryRecord, MemoryStatus,
};

use super::{
    memory::load_owned_memory, vector_sync_outbox::enqueue_in_transaction, StorageService,
};

impl MemoryRevisionRepository for StorageService {
    fn current_revision(&self, life_id: &str, memory_id: &str) -> Result<i64, MemoryError> {
        let state = self.state().map_err(|_| MemoryError::database())?;
        load_owned_memory(&state.connection, life_id, memory_id)?;
        load_revision_number(&state.connection, memory_id)
    }

    fn update_confirmed(
        &self,
        request: UpdateConfirmedMemoryRequest,
    ) -> Result<MemoryUpdateResult, MemoryError> {
        let mut state = self.state().map_err(|_| MemoryError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| MemoryError::database())?;
        let existing = load_owned_memory(&transaction, &request.life_id, &request.memory_id)?;
        require_confirmed(&existing)?;
        let current_revision = load_revision_number(&transaction, &request.memory_id)?;
        if current_revision != request.expected_revision {
            return Err(MemoryError::revision_conflict());
        }

        if existing.kind == request.kind
            && existing.content == request.content
            && existing.summary == request.summary
        {
            return Ok(MemoryUpdateResult {
                memory: existing,
                revision: current_revision,
                changed: false,
            });
        }

        ensure_revision_snapshot(
            &transaction,
            &existing,
            current_revision,
            MemoryRevisionChangeType::Confirmed,
        )?;
        let next_revision = current_revision + 1;
        let changed = transaction
            .execute(
                "UPDATE memory_record SET kind = ?4, content = ?5, summary = ?6,
                 revision = ?7, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND life_id = ?2 AND status = 'confirmed' AND revision = ?3",
                params![
                    request.memory_id,
                    request.life_id,
                    current_revision,
                    request.kind.as_str(),
                    request.content,
                    request.summary,
                    next_revision,
                ],
            )
            .map_err(|_| MemoryError::database())?;
        if changed != 1 {
            return Err(MemoryError::revision_conflict());
        }
        let updated = load_owned_memory(&transaction, &request.life_id, &request.memory_id)?;
        insert_revision_snapshot(
            &transaction,
            &updated,
            next_revision,
            MemoryRevisionChangeType::Edited,
        )?;
        let action = if updated.is_sensitive {
            MemoryVectorSyncAction::Delete
        } else {
            MemoryVectorSyncAction::Upsert
        };
        enqueue_in_transaction(&transaction, &request.life_id, &request.memory_id, action)
            .map_err(|_| MemoryError::database())?;
        transaction.commit().map_err(|_| MemoryError::database())?;
        Ok(MemoryUpdateResult {
            memory: updated,
            revision: next_revision,
            changed: true,
        })
    }

    fn set_sensitivity(
        &self,
        request: SetMemorySensitivityRequest,
    ) -> Result<MemoryUpdateResult, MemoryError> {
        let mut state = self.state().map_err(|_| MemoryError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| MemoryError::database())?;
        let existing = load_owned_memory(&transaction, &request.life_id, &request.memory_id)?;
        require_confirmed(&existing)?;
        let current_revision = load_revision_number(&transaction, &request.memory_id)?;
        if current_revision != request.expected_revision {
            return Err(MemoryError::revision_conflict());
        }
        if existing.is_sensitive == request.is_sensitive {
            return Ok(MemoryUpdateResult {
                memory: existing,
                revision: current_revision,
                changed: false,
            });
        }

        ensure_revision_snapshot(
            &transaction,
            &existing,
            current_revision,
            MemoryRevisionChangeType::Confirmed,
        )?;
        let next_revision = current_revision + 1;
        let changed = transaction
            .execute(
                "UPDATE memory_record SET is_sensitive = ?4, revision = ?5,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND life_id = ?2 AND status = 'confirmed' AND revision = ?3",
                params![
                    request.memory_id,
                    request.life_id,
                    current_revision,
                    request.is_sensitive,
                    next_revision,
                ],
            )
            .map_err(|_| MemoryError::database())?;
        if changed != 1 {
            return Err(MemoryError::revision_conflict());
        }
        let updated = load_owned_memory(&transaction, &request.life_id, &request.memory_id)?;
        insert_revision_snapshot(
            &transaction,
            &updated,
            next_revision,
            MemoryRevisionChangeType::SensitivityChanged,
        )?;
        let action = if updated.is_sensitive {
            MemoryVectorSyncAction::Delete
        } else {
            MemoryVectorSyncAction::Upsert
        };
        enqueue_in_transaction(&transaction, &request.life_id, &request.memory_id, action)
            .map_err(|_| MemoryError::database())?;
        transaction.commit().map_err(|_| MemoryError::database())?;
        Ok(MemoryUpdateResult {
            memory: updated,
            revision: next_revision,
            changed: true,
        })
    }

    fn list_revisions(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<Vec<MemoryRevisionRecord>, MemoryError> {
        let state = self.state().map_err(|_| MemoryError::database())?;
        load_owned_memory(&state.connection, life_id, memory_id)?;
        let mut statement = state
            .connection
            .prepare(
                "SELECT revision, kind, content, summary, is_sensitive, change_type, created_at
                 FROM memory_revision WHERE life_id = ?1 AND memory_id = ?2
                 ORDER BY revision ASC",
            )
            .map_err(|_| MemoryError::database())?;
        let rows = statement
            .query_map(params![life_id, memory_id], read_revision)
            .map_err(|_| MemoryError::database())?;
        rows.map(|row| row.map_err(|_| MemoryError::database())?.try_into())
            .collect()
    }

    fn delete_permanently(
        &self,
        request: DeleteMemoryPermanentlyRequest,
    ) -> Result<DeleteMemoryResult, MemoryError> {
        let mut state = self.state().map_err(|_| MemoryError::database())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| MemoryError::database())?;
        let existing = load_owned_memory(&transaction, &request.life_id, &request.memory_id)?;
        let current_revision = load_revision_number(&transaction, &request.memory_id)?;
        if current_revision != request.expected_revision {
            return Err(MemoryError::delete_conflict());
        }
        if existing.status == MemoryStatus::Confirmed {
            enqueue_in_transaction(
                &transaction,
                &request.life_id,
                &request.memory_id,
                MemoryVectorSyncAction::Delete,
            )
            .map_err(|_| MemoryError::database())?;
        }
        let deleted = transaction
            .execute(
                "DELETE FROM memory_record WHERE id = ?1 AND life_id = ?2 AND revision = ?3",
                params![request.memory_id, request.life_id, current_revision],
            )
            .map_err(|_| MemoryError::database())?;
        if deleted != 1 {
            return Err(MemoryError::delete_conflict());
        }
        transaction.commit().map_err(|_| MemoryError::database())?;
        Ok(DeleteMemoryResult {
            memory_id: request.memory_id,
            deleted: true,
        })
    }
}

pub(super) fn insert_confirmed_revision_in_transaction(
    transaction: &Transaction<'_>,
    memory: &MemoryRecord,
) -> Result<(), MemoryError> {
    insert_revision_snapshot(transaction, memory, 1, MemoryRevisionChangeType::Confirmed)
}

fn require_confirmed(memory: &MemoryRecord) -> Result<(), MemoryError> {
    if memory.status != MemoryStatus::Confirmed {
        return Err(MemoryError::not_confirmed());
    }
    Ok(())
}

fn load_revision_number(
    connection: &rusqlite::Connection,
    memory_id: &str,
) -> Result<i64, MemoryError> {
    connection
        .query_row(
            "SELECT revision FROM memory_record WHERE id = ?1",
            params![memory_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| MemoryError::database())?
        .ok_or_else(MemoryError::not_found)
}

fn ensure_revision_snapshot(
    transaction: &Transaction<'_>,
    memory: &MemoryRecord,
    revision: i64,
    change_type: MemoryRevisionChangeType,
) -> Result<(), MemoryError> {
    transaction
        .execute(
            "INSERT OR IGNORE INTO memory_revision (
                id, life_id, memory_id, revision, kind, content, summary,
                is_sensitive, change_type, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![
                revision_id(&memory.id, revision),
                memory.life_id,
                memory.id,
                revision,
                memory.kind.as_str(),
                memory.content,
                memory.summary,
                memory.is_sensitive,
                change_type.as_str(),
            ],
        )
        .map_err(|_| MemoryError::database())?;
    Ok(())
}

fn insert_revision_snapshot(
    transaction: &Transaction<'_>,
    memory: &MemoryRecord,
    revision: i64,
    change_type: MemoryRevisionChangeType,
) -> Result<(), MemoryError> {
    let inserted = transaction
        .execute(
            "INSERT INTO memory_revision (
                id, life_id, memory_id, revision, kind, content, summary,
                is_sensitive, change_type, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9,
                strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            params![
                revision_id(&memory.id, revision),
                memory.life_id,
                memory.id,
                revision,
                memory.kind.as_str(),
                memory.content,
                memory.summary,
                memory.is_sensitive,
                change_type.as_str(),
            ],
        )
        .map_err(|_| MemoryError::database())?;
    if inserted != 1 {
        return Err(MemoryError::database());
    }
    Ok(())
}

fn revision_id(memory_id: &str, revision: i64) -> String {
    format!("memory-revision-{memory_id}-{revision}")
}

struct StoredRevision {
    revision: i64,
    kind: String,
    content: String,
    summary: Option<String>,
    is_sensitive: bool,
    change_type: String,
    created_at: String,
}

impl TryFrom<StoredRevision> for MemoryRevisionRecord {
    type Error = MemoryError;

    fn try_from(value: StoredRevision) -> Result<Self, Self::Error> {
        Ok(Self {
            revision: value.revision,
            kind: MemoryKind::parse(&value.kind)?,
            content: value.content,
            summary: value.summary,
            is_sensitive: value.is_sensitive,
            change_type: MemoryRevisionChangeType::parse(&value.change_type)?,
            created_at: value.created_at,
        })
    }
}

fn read_revision(row: &Row<'_>) -> rusqlite::Result<StoredRevision> {
    Ok(StoredRevision {
        revision: row.get(0)?,
        kind: row.get(1)?,
        content: row.get(2)?,
        summary: row.get(3)?,
        is_sensitive: row.get(4)?,
        change_type: row.get(5)?,
        created_at: row.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf, sync::Arc, thread};

    use rusqlite::{params, Connection};

    use crate::memory::{
        revisions::{
            DeleteMemoryPermanentlyRequest, MemoryRevisionService, SetMemorySensitivityRequest,
            UpdateConfirmedMemoryRequest,
        },
        ConfirmMemoryRequest, CreateMemoryCandidateRequest, MemoryKind, MemoryService,
        MemorySourceType, UpdateMemoryRequest,
    };

    use super::super::{
        unique_suffix, LifeIdentityRecord, PersonaTemplateRecord, StorageService,
        DATABASE_FILE_NAME,
    };

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "digital-life-memory-revision-{name}-{}",
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

    fn seeded(root: &TestRoot) -> StorageService {
        let service = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        for suffix in ["a", "b"] {
            service
                .save_persona(PersonaTemplateRecord {
                    id: format!("persona-{suffix}"),
                    name: "Persona".into(),
                    version: 1,
                    persona_json: "{}".into(),
                })
                .unwrap();
            service
                .save_life(LifeIdentityRecord {
                    id: format!("life-{suffix}"),
                    name: format!("Life {suffix}"),
                    created_at: "2026-07-13T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "body".into(),
                    persona_id: format!("persona-{suffix}"),
                    persona_version: 1,
                })
                .unwrap();
        }
        service
    }

    fn candidate(
        service: &StorageService,
        life_id: &str,
        sensitive: bool,
    ) -> crate::memory::MemoryRecord {
        MemoryService::new(service)
            .create_candidate(CreateMemoryCandidateRequest {
                life_id: life_id.into(),
                kind: MemoryKind::Fact,
                content: "Original content".into(),
                summary: Some("Original summary".into()),
                source_type: MemorySourceType::Manual,
                source_ref: None,
                source_created_at: "2026-07-13T00:00:00.000Z".into(),
                importance: 0.5,
                confidence: 0.8,
                is_sensitive: sensitive,
            })
            .unwrap()
    }

    fn confirmed(
        service: &StorageService,
        life_id: &str,
        sensitive: bool,
    ) -> crate::memory::MemoryRecord {
        super::super::test_support::insert_confirmed_memory_fixture(
            service,
            life_id,
            "fact",
            "Original content",
            Some("Original summary"),
            0.5,
            0.8,
            sensitive,
            true,
        )
    }

    fn update(
        memory_id: &str,
        expected_revision: i64,
        content: &str,
    ) -> UpdateConfirmedMemoryRequest {
        UpdateConfirmedMemoryRequest {
            life_id: "life-a".into(),
            memory_id: memory_id.into(),
            expected_revision,
            kind: MemoryKind::Preference,
            content: content.into(),
            summary: Some("Revised summary".into()),
        }
    }

    fn outbox_action(service: &StorageService, memory_id: &str) -> Option<String> {
        service
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT desired_action FROM memory_vector_sync_outbox
                 WHERE life_id = 'life-a' AND memory_id = ?1",
                params![memory_id],
                |row| row.get(0),
            )
            .ok()
    }

    #[test]
    fn migration_006_upgrades_to_007_and_reopen_is_idempotent() {
        let root = TestRoot::new("migration");
        let data_root = root.0.join("data");
        fs::create_dir_all(&data_root).unwrap();
        let database = data_root.join(DATABASE_FILE_NAME);
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 CREATE TABLE schema_migration (
                    version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL
                 );",
            )
            .unwrap();
        for (version, name, sql) in [
            (1, "001_initial", include_str!("migrations/001_initial.sql")),
            (
                2,
                "002_memory_core",
                include_str!("migrations/002_memory_core.sql"),
            ),
            (
                3,
                "003_model_profiles",
                include_str!("migrations/003_model_profiles.sql"),
            ),
            (
                4,
                "004_memory_vector_sync_outbox",
                include_str!("migrations/004_memory_vector_sync_outbox.sql"),
            ),
            (
                5,
                "005_memory_vector_sync_settings",
                include_str!("migrations/005_memory_vector_sync_settings.sql"),
            ),
            (
                6,
                "006_conversation_history",
                include_str!("migrations/006_conversation_history.sql"),
            ),
        ] {
            connection.execute_batch(sql).unwrap();
            connection
                .execute(
                    "INSERT INTO schema_migration (version, name, applied_at)
                     VALUES (?1, ?2, '2026-07-13T00:00:00.000Z')",
                    params![version, name],
                )
                .unwrap();
        }
        connection.execute("INSERT INTO persona_template (id, name, version, persona_json) VALUES ('persona-a', 'Persona', 1, '{}')", []).unwrap();
        connection.execute("INSERT INTO life_identity (id, name, created_at, version, body_id, persona_id, persona_version) VALUES ('life-a', 'Life', '2026-07-13T00:00:00.000Z', 1, 'body', 'persona-a', 1)", []).unwrap();
        connection.execute("INSERT INTO memory_record (id, life_id, kind, status, content, summary, source_type, source_ref, source_created_at, importance, confidence, is_sensitive, created_at, updated_at, confirmed_at) VALUES ('memory-old', 'life-a', 'fact', 'confirmed', 'Old content', NULL, 'manual', NULL, '2026-07-13T00:00:00.000Z', 0.5, 0.8, 0, '2026-07-13T00:00:00.000Z', '2026-07-13T00:00:00.000Z', '2026-07-13T00:00:00.000Z')", []).unwrap();
        drop(connection);

        drop(StorageService::initialize_with_roots(data_root.clone(), None).unwrap());
        let service = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = service.state().unwrap();
        let version: i64 = state
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        let revision_count: i64 = state.connection.query_row("SELECT COUNT(*) FROM memory_revision WHERE memory_id = 'memory-old' AND change_type = 'confirmed'", [], |row| row.get(0)).unwrap();
        assert_eq!(version, 11);
        assert_eq!(revision_count, 1);
    }

    #[test]
    fn legacy_candidate_edit_is_unavailable_and_confirm_is_unavailable() {
        let root = TestRoot::new("initial");
        let service = seeded(&root);
        let candidate = candidate(&service, "life-a", false);
        let memory = MemoryService::new(&service);
        let update_error = memory
            .update_candidate(UpdateMemoryRequest {
                life_id: "life-a".into(),
                memory_id: candidate.id.clone(),
                kind: MemoryKind::Goal,
                content: "Candidate update".into(),
                summary: None,
                source_type: MemorySourceType::Manual,
                source_ref: None,
                source_created_at: "2026-07-13T00:00:01.000Z".into(),
                importance: 0.5,
                confidence: 0.8,
                is_sensitive: false,
            })
            .unwrap_err();
        assert_eq!(update_error.code, "CANDIDATE_LIFECYCLE_COMMAND_UNAVAILABLE");
        // A disabled legacy edit must not create a memory_revision entry.
        let revision_count: i64 = service
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_revision WHERE memory_id = ?1",
                rusqlite::params![candidate.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revision_count, 0);
        let error = memory
            .confirm(ConfirmMemoryRequest {
                life_id: "life-a".into(),
                memory_id: candidate.id.clone(),
                user_confirmed: true,
                sensitive_consent: false,
            })
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_CONFIRMATION_UNAVAILABLE");
        // Confirm does not create a revision when it returns an error.
        let revision_count: i64 = service
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_revision WHERE memory_id = ?1",
                rusqlite::params![candidate.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revision_count, 0);
    }

    #[test]
    fn confirmed_edits_are_versioned_noops_are_ignored_and_stale_writes_conflict() {
        let root = TestRoot::new("edit");
        let service = seeded(&root);
        let memory = confirmed(&service, "life-a", false);
        let revisions = MemoryRevisionService::new(&service);
        let changed = revisions
            .update_confirmed(update(&memory.id, 1, "Revised content"))
            .unwrap();
        assert!(changed.changed);
        assert_eq!(changed.revision, 2);
        assert_eq!(changed.memory.kind, MemoryKind::Preference);
        assert_eq!(changed.memory.summary.as_deref(), Some("Revised summary"));
        let unchanged = revisions
            .update_confirmed(update(&memory.id, 2, "Revised content"))
            .unwrap();
        assert!(!unchanged.changed);
        assert_eq!(unchanged.revision, 2);
        assert_eq!(
            revisions
                .list_revisions("life-a", &memory.id)
                .unwrap()
                .len(),
            2
        );
        let error = revisions
            .update_confirmed(update(&memory.id, 1, "Stale overwrite"))
            .unwrap_err();
        assert_eq!(error.code, "MEMORY_REVISION_CONFLICT");
        assert_eq!(
            outbox_action(&service, &memory.id).as_deref(),
            Some("upsert")
        );
    }

    #[test]
    fn concurrent_expected_revision_allows_exactly_one_writer() {
        let root = TestRoot::new("concurrent");
        let service = Arc::new(seeded(&root));
        let memory = confirmed(&service, "life-a", false);
        let mut handles = Vec::new();
        for content in ["Window one", "Window two"] {
            let service = Arc::clone(&service);
            let memory_id = memory.id.clone();
            handles.push(thread::spawn(move || {
                MemoryRevisionService::new(service.as_ref())
                    .update_confirmed(update(&memory_id, 1, content))
            }));
        }
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| result
                    .as_ref()
                    .is_err_and(|error| error.code == "MEMORY_REVISION_CONFLICT"))
                .count(),
            1
        );
    }

    #[test]
    fn sensitive_edits_and_sensitivity_changes_fold_to_safe_outbox_actions() {
        let root = TestRoot::new("sensitive");
        let service = seeded(&root);
        let non_sensitive = confirmed(&service, "life-a", false);
        let revisions = MemoryRevisionService::new(&service);
        let sensitive = revisions
            .set_sensitivity(SetMemorySensitivityRequest {
                life_id: "life-a".into(),
                memory_id: non_sensitive.id.clone(),
                expected_revision: 1,
                is_sensitive: true,
            })
            .unwrap();
        assert_eq!(
            outbox_action(&service, &non_sensitive.id).as_deref(),
            Some("delete")
        );
        revisions
            .update_confirmed(update(
                &non_sensitive.id,
                sensitive.revision,
                "Sensitive edit",
            ))
            .unwrap();
        assert_eq!(
            outbox_action(&service, &non_sensitive.id).as_deref(),
            Some("delete")
        );
        revisions
            .set_sensitivity(SetMemorySensitivityRequest {
                life_id: "life-a".into(),
                memory_id: non_sensitive.id.clone(),
                expected_revision: sensitive.revision + 1,
                is_sensitive: false,
            })
            .unwrap();
        assert_eq!(
            outbox_action(&service, &non_sensitive.id).as_deref(),
            Some("upsert")
        );
    }

    #[test]
    fn outbox_failure_rolls_back_memory_and_revision() {
        let root = TestRoot::new("rollback");
        let service = seeded(&root);
        let memory = confirmed(&service, "life-a", false);
        service
            .state()
            .unwrap()
            .connection
            .execute("DROP TABLE memory_vector_sync_outbox", [])
            .unwrap();
        let error = MemoryRevisionService::new(&service)
            .update_confirmed(update(&memory.id, 1, "Must roll back"))
            .unwrap_err();
        assert_eq!(error.code, "DATABASE_ERROR");
        let authoritative = MemoryService::new(&service)
            .get("life-a", &memory.id)
            .unwrap();
        assert_eq!(authoritative.content, "Original content");
        assert_eq!(
            MemoryRevisionService::new(&service)
                .current_revision("life-a", &memory.id)
                .unwrap(),
            1
        );
        assert_eq!(
            MemoryRevisionService::new(&service)
                .list_revisions("life-a", &memory.id)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn life_isolation_and_permanent_delete_clear_revisions_but_keep_delete_job() {
        let root = TestRoot::new("delete");
        let service = seeded(&root);
        let memory = confirmed(&service, "life-a", false);
        let revisions = MemoryRevisionService::new(&service);
        assert_eq!(
            revisions
                .update_confirmed(UpdateConfirmedMemoryRequest {
                    life_id: "life-b".into(),
                    ..update(&memory.id, 1, "Wrong life")
                })
                .unwrap_err()
                .code,
            "MEMORY_LIFE_MISMATCH"
        );
        revisions
            .update_confirmed(update(&memory.id, 1, "Version two"))
            .unwrap();
        let deleted = revisions
            .delete_permanently(DeleteMemoryPermanentlyRequest {
                life_id: "life-a".into(),
                memory_id: memory.id.clone(),
                expected_revision: 2,
            })
            .unwrap();
        assert!(deleted.deleted);
        let state = service.state().unwrap();
        let revision_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_revision WHERE memory_id = ?1",
                params![memory.id],
                |row| row.get(0),
            )
            .unwrap();
        let action: String = state.connection.query_row("SELECT desired_action FROM memory_vector_sync_outbox WHERE life_id = 'life-a' AND memory_id = ?1", params![memory.id], |row| row.get(0)).unwrap();
        assert_eq!(revision_count, 0);
        assert_eq!(action, "delete");
    }
}
