use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};

use crate::memory::vector_sync_outbox::{
    ClaimMemoryVectorSyncLeaseRequest, ClaimMemoryVectorSyncRequest,
    EnqueueMemoryVectorSyncRequest, MemoryVectorSyncAction, MemoryVectorSyncJob,
    MemoryVectorSyncOutboxError, MemoryVectorSyncOutboxErrorCode, MemoryVectorSyncOutboxRepository,
    MemoryVectorSyncState,
};

use super::StorageService;

const COLUMNS: &str = "id, life_id, memory_id, desired_action, state, attempt_count, next_attempt_at, lease_owner, lease_expires_at, last_error_code, created_at, updated_at";

pub(super) fn enqueue_in_transaction(
    transaction: &Transaction<'_>,
    life_id: &str,
    memory_id: &str,
    action: MemoryVectorSyncAction,
) -> Result<(), MemoryVectorSyncOutboxError> {
    validate_ids(life_id, memory_id)?;
    let owner: Option<String> = transaction
        .query_row(
            "SELECT life_id FROM memory_record WHERE id = ?1",
            params![memory_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| outbox_error())?;
    match owner.as_deref() {
        None => {
            return Err(MemoryVectorSyncOutboxError::new(
                MemoryVectorSyncOutboxErrorCode::SyncJobNotFound,
            ));
        }
        Some(owner) if owner != life_id => {
            return Err(MemoryVectorSyncOutboxError::new(
                MemoryVectorSyncOutboxErrorCode::SyncJobLifeMismatch,
            ));
        }
        Some(_) => {}
    }
    transaction
        .execute(
            "INSERT INTO memory_vector_sync_outbox (life_id, memory_id, desired_action)
         VALUES (?1, ?2, ?3)
         ON CONFLICT(life_id, memory_id) DO UPDATE SET
           desired_action = excluded.desired_action, state = 'pending', attempt_count = 0,
           next_attempt_at = NULL, lease_owner = NULL, lease_expires_at = NULL,
           last_error_code = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
            params![life_id, memory_id, action.as_str()],
        )
        .map_err(|_| outbox_error())?;
    Ok(())
}

impl MemoryVectorSyncOutboxRepository for StorageService {
    fn enqueue(
        &self,
        request: EnqueueMemoryVectorSyncRequest,
    ) -> Result<MemoryVectorSyncJob, MemoryVectorSyncOutboxError> {
        let mut state = self.state().map_err(|_| outbox_error())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| outbox_error())?;
        enqueue_in_transaction(
            &transaction,
            &request.life_id,
            &request.memory_id,
            request.desired_action,
        )?;
        let job = load_job(&transaction, &request.life_id, &request.memory_id)?;
        transaction.commit().map_err(|_| outbox_error())?;
        Ok(job)
    }

    fn claim_next(
        &self,
        request: ClaimMemoryVectorSyncRequest,
    ) -> Result<Option<MemoryVectorSyncJob>, MemoryVectorSyncOutboxError> {
        validate_worker(
            &request.life_id,
            &request.lease_owner,
            &request.lease_expires_at,
        )?;
        let mut state = self.state().map_err(|_| outbox_error())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| outbox_error())?;
        transaction.execute(
            "UPDATE memory_vector_sync_outbox SET state = 'pending', lease_owner = NULL, lease_expires_at = NULL,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE life_id = ?1 AND state = 'processing' AND lease_expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
            params![request.life_id],
        ).map_err(|_| outbox_error())?;
        let id: Option<i64> = transaction.query_row(
            "SELECT id FROM memory_vector_sync_outbox
             WHERE life_id = ?1 AND (state = 'pending' OR (state = 'retry_wait' AND next_attempt_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')))
             ORDER BY created_at ASC, id ASC LIMIT 1",
            params![request.life_id], |row| row.get(0),
        ).optional().map_err(|_| outbox_error())?;
        let Some(id) = id else {
            transaction.commit().map_err(|_| outbox_error())?;
            return Ok(None);
        };
        let changed = transaction.execute(
            "UPDATE memory_vector_sync_outbox SET state = 'processing', attempt_count = attempt_count + 1,
             lease_owner = ?2, lease_expires_at = ?3, next_attempt_at = NULL,
             updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE id = ?1 AND life_id = ?4 AND state IN ('pending', 'retry_wait')",
            params![id, request.lease_owner, request.lease_expires_at, request.life_id],
        ).map_err(|_| outbox_error())?;
        if changed != 1 {
            return Err(MemoryVectorSyncOutboxError::new(
                MemoryVectorSyncOutboxErrorCode::SyncJobLeaseConflict,
            ));
        }
        let job = load_job_by_id(&transaction, &request.life_id, id)?;
        transaction.commit().map_err(|_| outbox_error())?;
        Ok(Some(job))
    }

    fn claim_next_with_lease(
        &self,
        request: ClaimMemoryVectorSyncLeaseRequest,
    ) -> Result<Option<MemoryVectorSyncJob>, MemoryVectorSyncOutboxError> {
        if request.lease_seconds == 0 || request.lease_seconds > 3_600 {
            return Err(outbox_error());
        }
        validate_worker(&request.life_id, &request.lease_owner, "calculated")?;
        let mut state = self.state().map_err(|_| outbox_error())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| outbox_error())?;
        release_expired_in_transaction(&transaction, &request.life_id)?;
        let Some(id) = next_eligible_id(&transaction, &request.life_id)? else {
            transaction.commit().map_err(|_| outbox_error())?;
            return Ok(None);
        };
        let changed = transaction
            .execute(
                "UPDATE memory_vector_sync_outbox SET state = 'processing',
                 attempt_count = attempt_count + 1, lease_owner = ?2,
                 lease_expires_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', printf('+%d seconds', ?3)),
                 next_attempt_at = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND life_id = ?4 AND state IN ('pending', 'retry_wait')",
                params![
                    id,
                    request.lease_owner,
                    request.lease_seconds,
                    request.life_id
                ],
            )
            .map_err(|_| outbox_error())?;
        if changed != 1 {
            return Err(MemoryVectorSyncOutboxError::new(
                MemoryVectorSyncOutboxErrorCode::SyncJobLeaseConflict,
            ));
        }
        let job = load_job_by_id(&transaction, &request.life_id, id)?;
        transaction.commit().map_err(|_| outbox_error())?;
        Ok(Some(job))
    }

    fn mark_retry(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
        next_attempt_at: &str,
        error_code: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError> {
        self.set_claimed_state(
            life_id,
            memory_id,
            lease_owner,
            MemoryVectorSyncState::RetryWait,
            Some(next_attempt_at),
            error_code,
        )
    }

    fn mark_retry_after(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
        delay_seconds: u32,
        error_code: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError> {
        validate_ids(life_id, memory_id)?;
        if delay_seconds == 0 || delay_seconds > 3_600 {
            return Err(outbox_error());
        }
        let state = self.state().map_err(|_| outbox_error())?;
        let changed = state
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox SET state = 'retry_wait',
                 next_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', printf('+%d seconds', ?4)),
                 lease_owner = NULL, lease_expires_at = NULL, last_error_code = ?5,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE life_id = ?1 AND memory_id = ?2 AND state = 'processing' AND lease_owner = ?3",
                params![
                    life_id,
                    memory_id,
                    lease_owner,
                    delay_seconds,
                    safe_error_code(error_code)
                ],
            )
            .map_err(|_| outbox_error())?;
        claimed_change(changed)
    }
    fn mark_blocked(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
        error_code: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError> {
        self.set_claimed_state(
            life_id,
            memory_id,
            lease_owner,
            MemoryVectorSyncState::Blocked,
            None,
            error_code,
        )
    }
    fn mark_failed(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
        error_code: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError> {
        self.set_claimed_state(
            life_id,
            memory_id,
            lease_owner,
            MemoryVectorSyncState::Failed,
            None,
            error_code,
        )
    }

    fn complete(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError> {
        validate_ids(life_id, memory_id)?;
        let state = self.state().map_err(|_| outbox_error())?;
        let changed = state.connection.execute("DELETE FROM memory_vector_sync_outbox WHERE life_id = ?1 AND memory_id = ?2 AND state = 'processing' AND lease_owner = ?3", params![life_id, memory_id, lease_owner]).map_err(|_| outbox_error())?;
        claimed_change(changed)
    }

    fn release_expired_leases(&self, life_id: &str) -> Result<usize, MemoryVectorSyncOutboxError> {
        if life_id.trim().is_empty() {
            return Err(outbox_error());
        }
        let state = self.state().map_err(|_| outbox_error())?;
        state.connection.execute("UPDATE memory_vector_sync_outbox SET state = 'pending', lease_owner = NULL, lease_expires_at = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE life_id = ?1 AND state = 'processing' AND lease_expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", params![life_id]).map_err(|_| outbox_error())
    }

    fn list(&self, life_id: &str) -> Result<Vec<MemoryVectorSyncJob>, MemoryVectorSyncOutboxError> {
        if life_id.trim().is_empty() {
            return Err(outbox_error());
        }
        let state = self.state().map_err(|_| outbox_error())?;
        let mut statement = state.connection.prepare(&format!("SELECT {COLUMNS} FROM memory_vector_sync_outbox WHERE life_id = ?1 ORDER BY created_at, id")).map_err(|_| outbox_error())?;
        let rows = statement
            .query_map(params![life_id], read_job)
            .map_err(|_| outbox_error())?;
        rows.map(|row| row.map_err(|_| outbox_error())?.try_into())
            .collect()
    }

    fn count(
        &self,
        life_id: &str,
        sync_state: MemoryVectorSyncState,
    ) -> Result<usize, MemoryVectorSyncOutboxError> {
        let state = self.state().map_err(|_| outbox_error())?;
        let count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_sync_outbox WHERE life_id = ?1 AND state = ?2",
                params![life_id, sync_state.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| outbox_error())?;
        usize::try_from(count).map_err(|_| outbox_error())
    }

    fn retry_failures(&self, life_id: &str) -> Result<usize, MemoryVectorSyncOutboxError> {
        if life_id.trim().is_empty() {
            return Err(outbox_error());
        }
        let state = self.state().map_err(|_| outbox_error())?;
        state
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox SET state = 'pending', attempt_count = 0,
                 next_attempt_at = NULL, lease_owner = NULL, lease_expires_at = NULL,
                 last_error_code = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE life_id = ?1 AND state IN ('blocked', 'failed', 'retry_wait')",
                params![life_id],
            )
            .map_err(|_| outbox_error())
    }
}

impl StorageService {
    fn set_claimed_state(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
        sync_state: MemoryVectorSyncState,
        next_attempt_at: Option<&str>,
        error_code: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError> {
        validate_ids(life_id, memory_id)?;
        let state = self.state().map_err(|_| outbox_error())?;
        let changed = state.connection.execute("UPDATE memory_vector_sync_outbox SET state = ?4, next_attempt_at = ?5, lease_owner = NULL, lease_expires_at = NULL, last_error_code = ?6, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE life_id = ?1 AND memory_id = ?2 AND state = 'processing' AND lease_owner = ?3", params![life_id, memory_id, lease_owner, sync_state.as_str(), next_attempt_at, safe_error_code(error_code)]).map_err(|_| outbox_error())?;
        claimed_change(changed)
    }
}

struct StoredJob {
    id: i64,
    life_id: String,
    memory_id: String,
    action: String,
    state: String,
    attempt_count: i64,
    next_attempt_at: Option<String>,
    lease_owner: Option<String>,
    lease_expires_at: Option<String>,
    last_error_code: Option<String>,
    created_at: String,
    updated_at: String,
}
impl TryFrom<StoredJob> for MemoryVectorSyncJob {
    type Error = MemoryVectorSyncOutboxError;
    fn try_from(value: StoredJob) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            life_id: value.life_id,
            memory_id: value.memory_id,
            desired_action: MemoryVectorSyncAction::parse(&value.action)?,
            state: MemoryVectorSyncState::parse(&value.state)?,
            attempt_count: u32::try_from(value.attempt_count).map_err(|_| outbox_error())?,
            next_attempt_at: value.next_attempt_at,
            lease_owner: value.lease_owner,
            lease_expires_at: value.lease_expires_at,
            last_error_code: value.last_error_code,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}
fn read_job(row: &Row<'_>) -> rusqlite::Result<StoredJob> {
    Ok(StoredJob {
        id: row.get(0)?,
        life_id: row.get(1)?,
        memory_id: row.get(2)?,
        action: row.get(3)?,
        state: row.get(4)?,
        attempt_count: row.get(5)?,
        next_attempt_at: row.get(6)?,
        lease_owner: row.get(7)?,
        lease_expires_at: row.get(8)?,
        last_error_code: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}
fn load_job(
    connection: &Connection,
    life_id: &str,
    memory_id: &str,
) -> Result<MemoryVectorSyncJob, MemoryVectorSyncOutboxError> {
    connection.query_row(&format!("SELECT {COLUMNS} FROM memory_vector_sync_outbox WHERE life_id = ?1 AND memory_id = ?2"), params![life_id, memory_id], read_job).optional().map_err(|_| outbox_error())?.ok_or_else(|| MemoryVectorSyncOutboxError::new(MemoryVectorSyncOutboxErrorCode::SyncJobNotFound))?.try_into()
}
fn load_job_by_id(
    connection: &Connection,
    life_id: &str,
    id: i64,
) -> Result<MemoryVectorSyncJob, MemoryVectorSyncOutboxError> {
    connection
        .query_row(
            &format!(
                "SELECT {COLUMNS} FROM memory_vector_sync_outbox WHERE life_id = ?1 AND id = ?2"
            ),
            params![life_id, id],
            read_job,
        )
        .optional()
        .map_err(|_| outbox_error())?
        .ok_or_else(|| {
            MemoryVectorSyncOutboxError::new(MemoryVectorSyncOutboxErrorCode::SyncJobLifeMismatch)
        })?
        .try_into()
}
fn release_expired_in_transaction(
    transaction: &Transaction<'_>,
    life_id: &str,
) -> Result<(), MemoryVectorSyncOutboxError> {
    transaction
        .execute(
            "UPDATE memory_vector_sync_outbox SET state = 'pending', lease_owner = NULL,
             lease_expires_at = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
             WHERE life_id = ?1 AND state = 'processing'
               AND lease_expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
            params![life_id],
        )
        .map_err(|_| outbox_error())?;
    Ok(())
}
fn next_eligible_id(
    transaction: &Transaction<'_>,
    life_id: &str,
) -> Result<Option<i64>, MemoryVectorSyncOutboxError> {
    transaction
        .query_row(
            "SELECT id FROM memory_vector_sync_outbox
             WHERE life_id = ?1 AND (state = 'pending' OR
               (state = 'retry_wait' AND next_attempt_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')))
             ORDER BY created_at ASC, id ASC LIMIT 1",
            params![life_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| outbox_error())
}
fn validate_ids(life_id: &str, memory_id: &str) -> Result<(), MemoryVectorSyncOutboxError> {
    if life_id.trim().is_empty() || memory_id.trim().is_empty() {
        Err(outbox_error())
    } else {
        Ok(())
    }
}
fn validate_worker(
    life_id: &str,
    owner: &str,
    expires: &str,
) -> Result<(), MemoryVectorSyncOutboxError> {
    if life_id.trim().is_empty()
        || owner.trim().is_empty()
        || owner.chars().count() > 128
        || expires.trim().is_empty()
    {
        Err(outbox_error())
    } else {
        Ok(())
    }
}
fn safe_error_code(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || *character == '_'
        })
        .take(64)
        .collect()
}
fn claimed_change(changed: usize) -> Result<(), MemoryVectorSyncOutboxError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(MemoryVectorSyncOutboxError::new(
            MemoryVectorSyncOutboxErrorCode::SyncJobLeaseConflict,
        ))
    }
}
fn outbox_error() -> MemoryVectorSyncOutboxError {
    MemoryVectorSyncOutboxError::new(MemoryVectorSyncOutboxErrorCode::OutboxUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        memory::{
            revisions::{DeleteMemoryPermanentlyRequest, MemoryRevisionService},
            ConfirmMemoryRequest, CreateMemoryCandidateRequest, MemoryKind, MemoryService,
            MemorySourceType,
        },
        storage::{LifeIdentityRecord, PersonaTemplateRecord},
    };
    use std::{
        fs,
        path::PathBuf,
        sync::{Arc, Barrier},
        thread,
    };

    struct TestRoot(PathBuf);
    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("vector-outbox-{}", super::super::unique_suffix()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn storage() -> (TestRoot, StorageService) {
        let root = TestRoot::new();
        let storage = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        storage
            .save_persona(PersonaTemplateRecord {
                id: "persona".into(),
                name: "Persona".into(),
                version: 1,
                persona_json: "{\"id\":\"persona\"}".into(),
            })
            .unwrap();
        storage
            .save_life(LifeIdentityRecord {
                id: "life".into(),
                name: "Life".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                version: 1,
                body_id: "body".into(),
                persona_id: "persona".into(),
                persona_version: 1,
            })
            .unwrap();
        (root, storage)
    }
    fn candidate(storage: &StorageService, sensitive: bool) -> crate::memory::MemoryRecord {
        MemoryService::new(storage)
            .create_candidate(CreateMemoryCandidateRequest {
                life_id: "life".into(),
                kind: MemoryKind::Fact,
                content: "fixture memory".into(),
                summary: None,
                source_type: MemorySourceType::Manual,
                source_ref: None,
                source_created_at: "2026-01-01T00:00:00Z".into(),
                importance: 0.5,
                confidence: 0.5,
                is_sensitive: sensitive,
            })
            .unwrap()
    }

    fn confirmed(storage: &StorageService, sensitive: bool) -> crate::memory::MemoryRecord {
        super::super::test_support::insert_confirmed_memory_fixture(
            storage,
            "life",
            "fact",
            "fixture memory",
            None,
            0.5,
            0.5,
            sensitive,
            !sensitive,
        )
    }

    #[test]
    fn migration_schema_is_safe_and_candidate_does_not_enqueue() {
        let (_root, storage) = storage();
        candidate(&storage, false);
        assert!(storage.list("life").unwrap().is_empty());
        let state = storage.state().unwrap();
        let columns: Vec<String> = state
            .connection
            .prepare("PRAGMA table_info(memory_vector_sync_outbox)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for forbidden in ["content", "summary", "vector", "api_key"] {
            assert!(!columns.iter().any(|column| column == forbidden));
        }
        let version: i64 = state
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 8);
    }

    #[test]
    fn migration_003_upgrades_to_004_and_reopen_is_idempotent() {
        let root = TestRoot::new();
        let data_root = root.0.join("data");
        fs::create_dir_all(&data_root).unwrap();
        let database_path = data_root.join(super::super::DATABASE_FILE_NAME);
        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migration (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );",
            )
            .unwrap();
        for (version, name, sql) in super::super::MIGRATIONS.iter().take(3) {
            connection.execute_batch(sql).unwrap();
            connection
                .execute(
                    "INSERT INTO schema_migration (version, name, applied_at)
                     VALUES (?1, ?2, '2026-01-01T00:00:00Z')",
                    params![version, name],
                )
                .unwrap();
        }
        drop(connection);

        let storage = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        let version: i64 = storage
            .state()
            .unwrap()
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 8);
        drop(storage);

        let reopened = StorageService::initialize_with_roots(data_root, None).unwrap();
        let migration_count: i64 = reopened
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migration WHERE version = 4",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migration_count, 1);
    }

    #[test]
    fn confirmed_fixture_enqueues_and_delete_preserves_folded_job() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        let jobs = storage.list("life").unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].desired_action, MemoryVectorSyncAction::Upsert);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        assert_eq!(storage.list("life").unwrap().len(), 1);
        MemoryRevisionService::new(&storage)
            .delete_permanently(DeleteMemoryPermanentlyRequest {
                life_id: "life".into(),
                memory_id: record.id.clone(),
                expected_revision: 1,
            })
            .unwrap();
        let jobs = storage.list("life").unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].desired_action, MemoryVectorSyncAction::Delete);
        assert!(<StorageService as crate::memory::MemoryRepository>::get(
            &storage, "life", &record.id
        )
        .is_err());
    }

    #[test]
    fn sensitive_confirmation_is_unavailable_and_never_enqueues_upsert() {
        let (_root, storage) = storage();
        let record = candidate(&storage, true);
        let error = MemoryService::new(&storage)
            .confirm(ConfirmMemoryRequest {
                life_id: "life".into(),
                memory_id: record.id,
                user_confirmed: true,
                sensitive_consent: true,
            })
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_CONFIRMATION_UNAVAILABLE");
        assert!(storage.list("life").unwrap().is_empty());
    }

    #[test]
    fn confirm_is_unavailable_and_does_not_modify_candidate() {
        let (_root, storage) = storage();
        let record = candidate(&storage, false);
        let error = MemoryService::new(&storage)
            .confirm(ConfirmMemoryRequest {
                life_id: "life".into(),
                memory_id: record.id.clone(),
                user_confirmed: true,
                sensitive_consent: false,
            })
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_CONFIRMATION_UNAVAILABLE");
        let authoritative =
            <StorageService as crate::memory::MemoryRepository>::get(&storage, "life", &record.id)
                .unwrap();
        assert_eq!(authoritative.status, crate::memory::MemoryStatus::Candidate);
        assert!(storage.list("life").unwrap().is_empty());
    }

    #[test]
    fn leases_are_exclusive_resettable_and_expired_leases_recover() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        let first = storage
            .claim_next(ClaimMemoryVectorSyncRequest {
                life_id: "life".into(),
                lease_owner: "worker-a".into(),
                lease_expires_at: "2999-01-01T00:00:00.000Z".into(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(first.attempt_count, 1);
        assert!(storage
            .claim_next(ClaimMemoryVectorSyncRequest {
                life_id: "life".into(),
                lease_owner: "worker-b".into(),
                lease_expires_at: "2999-01-01T00:00:00.000Z".into()
            })
            .unwrap()
            .is_none());
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: record.id,
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
        let reset = storage.list("life").unwrap().remove(0);
        assert_eq!(reset.state, MemoryVectorSyncState::Pending);
        assert_eq!(reset.attempt_count, 0);
        let claimed = storage
            .claim_next(ClaimMemoryVectorSyncRequest {
                life_id: "life".into(),
                lease_owner: "worker-b".into(),
                lease_expires_at: "2000-01-01T00:00:00.000Z".into(),
            })
            .unwrap()
            .unwrap();
        assert_eq!(claimed.desired_action, MemoryVectorSyncAction::Delete);
        assert_eq!(storage.release_expired_leases("life").unwrap(), 1);
        assert_eq!(
            storage.list("life").unwrap()[0].state,
            MemoryVectorSyncState::Pending
        );
    }

    #[test]
    fn enqueue_rejects_a_memory_owned_by_another_life() {
        let (_root, storage) = storage();
        storage
            .save_life(LifeIdentityRecord {
                id: "other-life".into(),
                name: "Other Life".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                version: 1,
                body_id: "other-body".into(),
                persona_id: "persona".into(),
                persona_version: 1,
            })
            .unwrap();
        let other = super::super::test_support::insert_confirmed_memory_fixture(
            &storage,
            "other-life",
            "fact",
            "other fixture",
            None,
            0.5,
            0.5,
            false,
            false,
        );

        let error = storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: other.id,
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap_err();

        assert_eq!(
            error.code,
            MemoryVectorSyncOutboxErrorCode::SyncJobLifeMismatch
        );
        assert!(storage.list("life").unwrap().is_empty());
        assert!(storage.list("other-life").unwrap().is_empty());
    }

    #[test]
    fn concurrent_claims_obtain_the_job_at_most_once() {
        let (root, first_store) = storage();
        let _memory = confirmed(&first_store, false);
        let second_store =
            StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let claim = |store: StorageService, owner: &'static str, barrier: Arc<Barrier>| {
            thread::spawn(move || {
                barrier.wait();
                store.claim_next(ClaimMemoryVectorSyncRequest {
                    life_id: "life".into(),
                    lease_owner: owner.into(),
                    lease_expires_at: "2999-01-01T00:00:00.000Z".into(),
                })
            })
        };
        let first = claim(first_store, "worker-a", Arc::clone(&barrier));
        let second = claim(second_store, "worker-b", barrier);
        let obtained = [first.join().unwrap(), second.join().unwrap()]
            .into_iter()
            .filter(|result| matches!(result, Ok(Some(_))))
            .count();
        assert_eq!(obtained, 1);
    }
}
