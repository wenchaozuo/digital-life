use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::memory::vector_sync_outbox::MemoryVectorSyncAction;
use crate::memory::{
    vector_index::MemoryVectorIndexRepository, ConfirmMemoryRequest, CreateMemoryCandidateRequest,
    DeleteMemoryResult, MemoryError, MemoryKind, MemoryQuery, MemoryRecord, MemoryRepository,
    MemorySourceType, MemoryStatus, UpdateMemoryRequest,
};

use super::{
    memory_revision::insert_confirmed_revision_in_transaction,
    vector_sync_outbox::enqueue_in_transaction, StorageService,
};

pub(super) struct StoredMemoryRecord {
    id: String,
    life_id: String,
    kind: String,
    status: String,
    content: String,
    summary: Option<String>,
    source_type: String,
    source_ref: Option<String>,
    source_created_at: String,
    importance: f64,
    confidence: f64,
    is_sensitive: bool,
    created_at: String,
    updated_at: String,
    confirmed_at: Option<String>,
}

impl TryFrom<StoredMemoryRecord> for MemoryRecord {
    type Error = MemoryError;

    fn try_from(value: StoredMemoryRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            life_id: value.life_id,
            kind: MemoryKind::parse(&value.kind)?,
            status: MemoryStatus::parse(&value.status)?,
            content: value.content,
            summary: value.summary,
            source_type: MemorySourceType::parse(&value.source_type)?,
            source_ref: value.source_ref,
            source_created_at: value.source_created_at,
            importance: value.importance,
            confidence: value.confidence,
            is_sensitive: value.is_sensitive,
            created_at: value.created_at,
            updated_at: value.updated_at,
            confirmed_at: value.confirmed_at,
        })
    }
}

pub(super) const MEMORY_COLUMNS: &str =
    "id, life_id, kind, status, content, summary, source_type, \
    source_ref, source_created_at, importance, confidence, is_sensitive, created_at, \
    updated_at, confirmed_at";

impl MemoryRepository for StorageService {
    fn create_candidate(
        &self,
        id: &str,
        request: CreateMemoryCandidateRequest,
    ) -> Result<MemoryRecord, MemoryError> {
        let state = self.state().map_err(|_| MemoryError::database())?;
        let life_exists: bool = state
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
                params![request.life_id],
                |row| row.get(0),
            )
            .map_err(|_| MemoryError::database())?;
        if !life_exists {
            return Err(MemoryError::new(
                "LIFE_NOT_FOUND",
                "The specified life was not found.",
                true,
            ));
        }

        state
            .connection
            .execute(
                "INSERT INTO memory_record (
                    id, life_id, kind, status, content, summary, source_type, source_ref,
                    source_created_at, importance, confidence, is_sensitive, created_at,
                    updated_at, confirmed_at
                 ) VALUES (
                    ?1, ?2, ?3, 'candidate', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11,
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), NULL
                 )",
                params![
                    id,
                    request.life_id,
                    request.kind.as_str(),
                    request.content.trim(),
                    normalize_optional(request.summary),
                    request.source_type.as_str(),
                    normalize_optional(request.source_ref),
                    request.source_created_at,
                    request.importance,
                    request.confidence,
                    request.is_sensitive,
                ],
            )
            .map_err(|_| MemoryError::database())?;

        load_owned_memory(&state.connection, &request.life_id, id)
    }

    fn list(&self, query: MemoryQuery) -> Result<Vec<MemoryRecord>, MemoryError> {
        let state = self.state().map_err(|_| MemoryError::database())?;
        let status = query.status.map(MemoryStatus::as_str);
        let kind = query.kind.map(MemoryKind::as_str);
        let sql = format!(
            "SELECT {MEMORY_COLUMNS} FROM memory_record
             WHERE life_id = ?1
               AND (?2 IS NULL OR status = ?2)
               AND (?3 IS NULL OR kind = ?3)
             ORDER BY created_at ASC, id ASC"
        );
        let mut statement = state
            .connection
            .prepare(&sql)
            .map_err(|_| MemoryError::database())?;
        let rows = statement
            .query_map(params![query.life_id, status, kind], read_stored_memory)
            .map_err(|_| MemoryError::database())?;

        rows.map(|row| row.map_err(|_| MemoryError::database())?.try_into())
            .collect()
    }

    fn get(&self, life_id: &str, memory_id: &str) -> Result<MemoryRecord, MemoryError> {
        let state = self.state().map_err(|_| MemoryError::database())?;
        load_owned_memory(&state.connection, life_id, memory_id)
    }

    fn update_candidate(&self, request: UpdateMemoryRequest) -> Result<MemoryRecord, MemoryError> {
        let mut state = self.state().map_err(|_| MemoryError::database())?;
        let transaction = state
            .connection
            .transaction()
            .map_err(|_| MemoryError::database())?;
        let existing = load_owned_memory(&transaction, &request.life_id, &request.memory_id)?;
        if existing.status != MemoryStatus::Candidate {
            return Err(MemoryError::invalid_transition());
        }

        transaction
            .execute(
                "UPDATE memory_record SET
                    kind = ?3,
                    content = ?4,
                    summary = ?5,
                    source_type = ?6,
                    source_ref = ?7,
                    source_created_at = ?8,
                    importance = ?9,
                    confidence = ?10,
                    is_sensitive = ?11,
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND life_id = ?2 AND status = 'candidate'",
                params![
                    request.memory_id,
                    request.life_id,
                    request.kind.as_str(),
                    request.content.trim(),
                    normalize_optional(request.summary),
                    request.source_type.as_str(),
                    normalize_optional(request.source_ref),
                    request.source_created_at,
                    request.importance,
                    request.confidence,
                    request.is_sensitive,
                ],
            )
            .map_err(|_| MemoryError::database())?;
        let updated = load_owned_memory(&transaction, &request.life_id, &request.memory_id)?;
        transaction.commit().map_err(|_| MemoryError::database())?;
        Ok(updated)
    }

    fn confirm(&self, request: ConfirmMemoryRequest) -> Result<MemoryRecord, MemoryError> {
        let mut state = self.state().map_err(|_| MemoryError::database())?;
        let transaction = state
            .connection
            .transaction()
            .map_err(|_| MemoryError::database())?;
        let existing = load_owned_memory(&transaction, &request.life_id, &request.memory_id)?;
        if existing.status != MemoryStatus::Candidate {
            return Err(MemoryError::invalid_transition());
        }
        if existing.is_sensitive && !request.sensitive_consent {
            return Err(MemoryError::new(
                "SENSITIVE_CONSENT_REQUIRED",
                "Explicit consent is required to confirm sensitive memory.",
                true,
            ));
        }

        transaction
            .execute(
                "UPDATE memory_record SET
                    status = 'confirmed',
                    confirmed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'),
                    updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE id = ?1 AND life_id = ?2 AND status = 'candidate'",
                params![request.memory_id, request.life_id],
            )
            .map_err(|_| MemoryError::database())?;
        let confirmed = load_owned_memory(&transaction, &request.life_id, &request.memory_id)?;
        insert_confirmed_revision_in_transaction(&transaction, &confirmed)?;
        if !confirmed.is_sensitive {
            enqueue_in_transaction(
                &transaction,
                &request.life_id,
                &request.memory_id,
                MemoryVectorSyncAction::Upsert,
            )
            .map_err(|_| MemoryError::database())?;
        }
        transaction.commit().map_err(|_| MemoryError::database())?;
        Ok(confirmed)
    }

    fn delete(&self, life_id: &str, memory_id: &str) -> Result<DeleteMemoryResult, MemoryError> {
        let mut state = self.state().map_err(|_| MemoryError::database())?;
        let transaction = state
            .connection
            .transaction()
            .map_err(|_| MemoryError::database())?;
        let existing = load_owned_memory(&transaction, life_id, memory_id)?;
        if existing.status != MemoryStatus::Candidate {
            return Err(MemoryError::new(
                "MEMORY_NOT_CONFIRMED",
                "Confirmed memories require revision-aware permanent deletion.",
                true,
            ));
        }
        let deleted = transaction
            .execute(
                "DELETE FROM memory_record WHERE id = ?1 AND life_id = ?2",
                params![memory_id, life_id],
            )
            .map_err(|_| MemoryError::database())?;
        transaction.commit().map_err(|_| MemoryError::database())?;

        Ok(DeleteMemoryResult {
            memory_id: memory_id.to_string(),
            deleted: deleted == 1,
        })
    }
}

impl MemoryVectorIndexRepository for StorageService {
    fn get_authoritative(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<MemoryRecord, MemoryError> {
        <Self as MemoryRepository>::get(self, life_id, memory_id)
    }

    fn list_page(
        &self,
        life_id: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<MemoryRecord>, MemoryError> {
        let state = self.state().map_err(|_| MemoryError::database())?;
        let limit = i64::try_from(limit).map_err(|_| MemoryError::database())?;
        let offset = i64::try_from(offset).map_err(|_| MemoryError::database())?;
        let sql = format!(
            "SELECT {MEMORY_COLUMNS} FROM memory_record
             WHERE life_id = ?1
             ORDER BY created_at ASC, id ASC
             LIMIT ?2 OFFSET ?3"
        );
        let mut statement = state
            .connection
            .prepare(&sql)
            .map_err(|_| MemoryError::database())?;
        let rows = statement
            .query_map(params![life_id, limit, offset], read_stored_memory)
            .map_err(|_| MemoryError::database())?;
        rows.map(|row| row.map_err(|_| MemoryError::database())?.try_into())
            .collect()
    }
}

pub(super) fn load_owned_memory(
    connection: &Connection,
    life_id: &str,
    memory_id: &str,
) -> Result<MemoryRecord, MemoryError> {
    let sql = format!("SELECT {MEMORY_COLUMNS} FROM memory_record WHERE id = ?1");
    let stored = connection
        .query_row(&sql, params![memory_id], read_stored_memory)
        .optional()
        .map_err(|_| MemoryError::database())?
        .ok_or_else(MemoryError::not_found)?;
    if stored.life_id != life_id {
        return Err(MemoryError::life_mismatch());
    }
    stored.try_into()
}

pub(super) fn read_stored_memory(row: &Row<'_>) -> rusqlite::Result<StoredMemoryRecord> {
    Ok(StoredMemoryRecord {
        id: row.get(0)?,
        life_id: row.get(1)?,
        kind: row.get(2)?,
        status: row.get(3)?,
        content: row.get(4)?,
        summary: row.get(5)?,
        source_type: row.get(6)?,
        source_ref: row.get(7)?,
        source_created_at: row.get(8)?,
        importance: row.get(9)?,
        confidence: row.get(10)?,
        is_sensitive: row.get(11)?,
        created_at: row.get(12)?,
        updated_at: row.get(13)?,
        confirmed_at: row.get(14)?,
    })
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

#[cfg(test)]
impl StorageService {
    /// Simulates an authoritative confirmed-memory revision for integration
    /// tests without relaxing the production candidate-only update boundary.
    pub(crate) fn revise_confirmed_memory_for_vector_sync_test(
        &self,
        life_id: &str,
        memory_id: &str,
        kind: MemoryKind,
        content: &str,
        summary: Option<&str>,
    ) -> Result<MemoryRecord, MemoryError> {
        use crate::memory::revisions::{MemoryRevisionService, UpdateConfirmedMemoryRequest};

        let revisions = MemoryRevisionService::new(self);
        let expected_revision = revisions.current_revision(life_id, memory_id)?;
        revisions
            .update_confirmed(UpdateConfirmedMemoryRequest {
                life_id: life_id.to_string(),
                memory_id: memory_id.to_string(),
                expected_revision,
                kind,
                content: content.to_string(),
                summary: summary.map(str::to_string),
            })
            .map(|result| result.memory)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use rusqlite::Connection;

    use crate::memory::{
        ConfirmMemoryRequest, CreateMemoryCandidateRequest, MemoryKind, MemoryQuery, MemoryService,
        MemorySourceType, MemoryStatus, UpdateMemoryRequest,
    };

    use super::super::{
        unique_suffix, LifeIdentityRecord, PersonaTemplateRecord, StorageService,
        DATABASE_FILE_NAME,
    };

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("digital-life-memory-{name}-{}", unique_suffix()));
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
        for suffix in ["a", "b"] {
            service
                .save_persona(PersonaTemplateRecord {
                    id: format!("persona-{suffix}"),
                    name: "Custom Persona".into(),
                    version: 1,
                    persona_json: format!("{{\"id\":\"persona-{suffix}\"}}"),
                })
                .unwrap();
            service
                .save_life(LifeIdentityRecord {
                    id: format!("life-{suffix}"),
                    name: format!("Life {suffix}"),
                    created_at: "2026-07-11T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "default-png".into(),
                    persona_id: format!("persona-{suffix}"),
                    persona_version: 1,
                })
                .unwrap();
        }
        service
    }

    fn candidate_request(life_id: &str, sensitive: bool) -> CreateMemoryCandidateRequest {
        CreateMemoryCandidateRequest {
            life_id: life_id.into(),
            kind: MemoryKind::Experience,
            content: "A governed memory candidate.".into(),
            summary: Some("Candidate summary".into()),
            source_type: MemorySourceType::Manual,
            source_ref: Some("manual-entry".into()),
            source_created_at: "2026-07-11T01:00:00.000Z".into(),
            importance: 0.7,
            confidence: 0.8,
            is_sensitive: sensitive,
        }
    }

    fn update_request(life_id: &str, memory_id: &str) -> UpdateMemoryRequest {
        UpdateMemoryRequest {
            life_id: life_id.into(),
            memory_id: memory_id.into(),
            kind: MemoryKind::Preference,
            content: "Updated candidate content.".into(),
            summary: None,
            source_type: MemorySourceType::Manual,
            source_ref: None,
            source_created_at: "2026-07-11T02:00:00.000Z".into(),
            importance: 0.6,
            confidence: 0.9,
            is_sensitive: false,
        }
    }

    fn create_candidate(
        service: &StorageService,
        life_id: &str,
        sensitive: bool,
    ) -> crate::memory::MemoryRecord {
        MemoryService::new(service)
            .create_candidate(candidate_request(life_id, sensitive))
            .unwrap()
    }

    #[test]
    fn migrations_upgrade_version_001_and_create_no_default_memory() {
        let root = TestRoot::new("upgrade-v1");
        let data_root = root.0.join("data");
        fs::create_dir_all(&data_root).unwrap();
        let database_path = data_root.join(DATABASE_FILE_NAME);
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
        connection
            .execute_batch(include_str!("migrations/001_initial.sql"))
            .unwrap();
        connection
            .execute(
                "INSERT INTO schema_migration (version, name, applied_at)
                 VALUES (1, '001_initial', '2026-07-11T00:00:00.000Z')",
                [],
            )
            .unwrap();
        drop(connection);

        let service = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = service.state().unwrap();
        let version: i64 = state
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        let memory_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM memory_record", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 7);
        assert_eq!(memory_count, 0);
    }

    #[test]
    fn migration_is_idempotent() {
        let root = TestRoot::new("migration-idempotent");
        let data_root = root.0.join("data");
        drop(StorageService::initialize_with_roots(data_root.clone(), None).unwrap());
        let service = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = service.state().unwrap();
        let count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migration WHERE version = 2",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn creates_and_filters_candidate_memory() {
        let root = TestRoot::new("create");
        let service = seeded_service(&root);
        let record = create_candidate(&service, "life-a", false);
        assert_eq!(record.status, MemoryStatus::Candidate);
        assert_eq!(record.life_id, "life-a");

        let records = MemoryService::new(&service)
            .list(MemoryQuery {
                life_id: "life-a".into(),
                status: Some(MemoryStatus::Candidate),
                kind: Some(MemoryKind::Experience),
            })
            .unwrap();
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn empty_content_is_rejected() {
        let root = TestRoot::new("empty-content");
        let service = seeded_service(&root);
        let mut request = candidate_request("life-a", false);
        request.content = "   ".into();
        let error = MemoryService::new(&service)
            .create_candidate(request)
            .unwrap_err();
        assert_eq!(error.code, "INVALID_ARGUMENT");
    }

    #[test]
    fn importance_and_confidence_out_of_range_are_rejected() {
        let root = TestRoot::new("score-range");
        let service = seeded_service(&root);
        for (importance, confidence) in [(-0.1, 0.5), (1.1, 0.5), (0.5, -0.1), (0.5, 1.1)] {
            let mut request = candidate_request("life-a", false);
            request.importance = importance;
            request.confidence = confidence;
            let error = MemoryService::new(&service)
                .create_candidate(request)
                .unwrap_err();
            assert_eq!(error.code, "INVALID_ARGUMENT");
        }
    }

    #[test]
    fn source_reference_rejects_credentials_and_headers() {
        let root = TestRoot::new("source-ref-secrets");
        let service = seeded_service(&root);
        for source_ref in ["Authorization header", "x-api-key header", "api_key field"] {
            let mut request = candidate_request("life-a", false);
            request.source_ref = Some(source_ref.into());
            let error = MemoryService::new(&service)
                .create_candidate(request)
                .unwrap_err();
            assert_eq!(error.code, "INVALID_ARGUMENT");
        }
    }

    #[test]
    fn user_can_confirm_candidate_once() {
        let root = TestRoot::new("confirm-once");
        let service = seeded_service(&root);
        let candidate = create_candidate(&service, "life-a", false);
        let confirmed = MemoryService::new(&service)
            .confirm(ConfirmMemoryRequest {
                life_id: "life-a".into(),
                memory_id: candidate.id.clone(),
                user_confirmed: true,
                sensitive_consent: false,
            })
            .unwrap();
        assert_eq!(confirmed.status, MemoryStatus::Confirmed);
        assert!(confirmed.confirmed_at.is_some());

        let error = MemoryService::new(&service)
            .confirm(ConfirmMemoryRequest {
                life_id: "life-a".into(),
                memory_id: candidate.id,
                user_confirmed: true,
                sensitive_consent: false,
            })
            .unwrap_err();
        assert_eq!(error.code, "INVALID_STATE_TRANSITION");
    }

    #[test]
    fn explicit_user_confirmation_is_required() {
        let root = TestRoot::new("user-confirmation");
        let service = seeded_service(&root);
        let candidate = create_candidate(&service, "life-a", false);
        let error = MemoryService::new(&service)
            .confirm(ConfirmMemoryRequest {
                life_id: "life-a".into(),
                memory_id: candidate.id,
                user_confirmed: false,
                sensitive_consent: false,
            })
            .unwrap_err();
        assert_eq!(error.code, "USER_CONFIRMATION_REQUIRED");
    }

    #[test]
    fn confirmed_memory_cannot_be_updated_or_returned_to_candidate() {
        let root = TestRoot::new("confirmed-update");
        let service = seeded_service(&root);
        let candidate = create_candidate(&service, "life-a", false);
        MemoryService::new(&service)
            .confirm(ConfirmMemoryRequest {
                life_id: "life-a".into(),
                memory_id: candidate.id.clone(),
                user_confirmed: true,
                sensitive_consent: false,
            })
            .unwrap();
        let error = MemoryService::new(&service)
            .update_candidate(update_request("life-a", &candidate.id))
            .unwrap_err();
        assert_eq!(error.code, "INVALID_STATE_TRANSITION");
        assert_eq!(
            MemoryService::new(&service)
                .get("life-a", &candidate.id)
                .unwrap()
                .status,
            MemoryStatus::Confirmed
        );
    }

    #[test]
    fn sensitive_memory_requires_separate_explicit_consent() {
        let root = TestRoot::new("sensitive");
        let service = seeded_service(&root);
        let candidate = create_candidate(&service, "life-a", true);
        let error = MemoryService::new(&service)
            .confirm(ConfirmMemoryRequest {
                life_id: "life-a".into(),
                memory_id: candidate.id.clone(),
                user_confirmed: true,
                sensitive_consent: false,
            })
            .unwrap_err();
        assert_eq!(error.code, "SENSITIVE_CONSENT_REQUIRED");

        let confirmed = MemoryService::new(&service)
            .confirm(ConfirmMemoryRequest {
                life_id: "life-a".into(),
                memory_id: candidate.id,
                user_confirmed: true,
                sensitive_consent: true,
            })
            .unwrap();
        assert_eq!(confirmed.status, MemoryStatus::Confirmed);
    }

    #[test]
    fn life_isolation_applies_to_read_update_confirm_and_delete() {
        let root = TestRoot::new("life-isolation");
        let service = seeded_service(&root);
        let candidate = create_candidate(&service, "life-b", false);
        let memory = MemoryService::new(&service);

        assert_eq!(
            memory.get("life-a", &candidate.id).unwrap_err().code,
            "MEMORY_LIFE_MISMATCH"
        );
        assert_eq!(
            memory
                .update_candidate(update_request("life-a", &candidate.id))
                .unwrap_err()
                .code,
            "MEMORY_LIFE_MISMATCH"
        );
        assert_eq!(
            memory
                .confirm(ConfirmMemoryRequest {
                    life_id: "life-a".into(),
                    memory_id: candidate.id.clone(),
                    user_confirmed: true,
                    sensitive_consent: false,
                })
                .unwrap_err()
                .code,
            "MEMORY_LIFE_MISMATCH"
        );
        assert_eq!(
            memory.delete("life-a", &candidate.id).unwrap_err().code,
            "MEMORY_LIFE_MISMATCH"
        );
        assert!(memory
            .list(MemoryQuery {
                life_id: "life-a".into(),
                status: None,
                kind: None,
            })
            .unwrap()
            .is_empty());
    }

    #[test]
    fn permanent_delete_removes_content_and_returns_no_content() {
        let root = TestRoot::new("hard-delete");
        let service = seeded_service(&root);
        let candidate = create_candidate(&service, "life-a", false);
        let result = MemoryService::new(&service)
            .delete("life-a", &candidate.id)
            .unwrap();
        assert!(result.deleted);
        assert_eq!(result.memory_id, candidate.id);
        assert_eq!(
            MemoryService::new(&service)
                .get("life-a", &candidate.id)
                .unwrap_err()
                .code,
            "MEMORY_NOT_FOUND"
        );
        let state = service.state().unwrap();
        let count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_record WHERE id = ?1 OR content = ?2 OR summary = ?3",
                rusqlite::params![candidate.id, candidate.content, candidate.summary],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn deleting_missing_memory_returns_structured_error() {
        let root = TestRoot::new("missing-delete");
        let service = seeded_service(&root);
        let error = MemoryService::new(&service)
            .delete("life-a", "missing-memory")
            .unwrap_err();
        assert_eq!(error.code, "MEMORY_NOT_FOUND");
    }
}
