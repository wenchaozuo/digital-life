use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::memory::{
    candidate::{
        CandidateInferenceStatus, CandidateMemoryError, CandidateMemoryListFilter,
        CandidateMemoryRecord, CandidateMemoryRepository, CandidateMemorySourceType,
        CandidateMemoryStatus, NewCandidateMemory, MAX_CANDIDATE_PAGE_SIZE,
        PRIMARY_USER_SUBJECT_ID,
    },
    candidate_lifecycle_command_unavailable,
    vector_index::MemoryVectorIndexRepository,
    ConfirmMemoryRequest, CreateMemoryCandidateRequest, DeleteMemoryResult, MemoryError,
    MemoryKind, MemoryQuery, MemoryRecord, MemoryRepository, MemorySourceType, MemoryStatus,
};

use super::StorageService;

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

/// Temporary compatibility adapter.
/// Remove during D-5 command migration.
impl MemoryRepository for StorageService {
    fn create_candidate(
        &self,
        id: &str,
        request: CreateMemoryCandidateRequest,
    ) -> Result<MemoryRecord, MemoryError> {
        let now = current_timestamp(self)?;
        let (source_type, inference_status) = candidate_source(request.source_type);
        let life_id = request.life_id.clone();
        let record = <Self as CandidateMemoryRepository>::insert_candidate(
            self,
            NewCandidateMemory {
                id: id.to_string(),
                life_id,
                subject_id: PRIMARY_USER_SUBJECT_ID.to_string(),
                kind: request.kind,
                content: Some(request.content),
                summary: request.summary,
                source_type,
                source_id: request.source_ref,
                confidence: request.confidence,
                importance: request.importance,
                is_sensitive: request.is_sensitive,
                inference_status,
                status: CandidateMemoryStatus::Pending,
                dedup_fingerprint: None,
                proposed_at: request.source_created_at,
                expires_at: None,
                reviewed_at: None,
                last_user_edit_at: None,
                confirmed_memory_id: None,
                accepted_request_id: None,
                rejection_reason_code: None,
                superseded_by_candidate_id: None,
                conflicts_with_memory_id: None,
                created_at: now.clone(),
                updated_at: now,
            },
        )
        .map_err(map_candidate_error)?;
        candidate_as_legacy(record)
    }

    fn list(&self, query: MemoryQuery) -> Result<Vec<MemoryRecord>, MemoryError> {
        let mut records = Vec::new();
        if query.status != Some(MemoryStatus::Candidate) {
            let state = self.state().map_err(|_| MemoryError::database())?;
            let kind = query.kind.map(MemoryKind::as_str);
            let confirmed_status = MemoryStatus::Confirmed.as_str();
            let sql = format!(
                "SELECT {MEMORY_COLUMNS} FROM memory_record
                 WHERE life_id = ?1 AND status = ?2
                   AND (?3 IS NULL OR kind = ?3)
                 ORDER BY created_at ASC, id ASC"
            );
            let mut statement = state
                .connection
                .prepare(&sql)
                .map_err(|_| MemoryError::database())?;
            let rows = statement
                .query_map(
                    params![&query.life_id, confirmed_status, kind],
                    read_stored_memory,
                )
                .map_err(|_| MemoryError::database())?;
            records.extend(
                rows.map(|row| row.map_err(|_| MemoryError::database())?.try_into())
                    .collect::<Result<Vec<MemoryRecord>, MemoryError>>()?,
            );
        }
        if query.status != Some(MemoryStatus::Confirmed) {
            let mut cursor = None;
            loop {
                let (page, next) = <Self as CandidateMemoryRepository>::list_candidates(
                    self,
                    CandidateMemoryListFilter {
                        life_id: query.life_id.clone(),
                        status: Some(CandidateMemoryStatus::Pending),
                        kind: query.kind,
                        page_size: Some(MAX_CANDIDATE_PAGE_SIZE),
                        cursor,
                        ..Default::default()
                    },
                )
                .map_err(map_candidate_error)?;
                records.extend(
                    page.into_iter()
                        .map(candidate_as_legacy)
                        .collect::<Result<Vec<_>, _>>()?,
                );
                let Some(next_cursor) = next else { break };
                cursor = Some(next_cursor);
            }
        }
        records.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(records)
    }

    fn get(&self, life_id: &str, memory_id: &str) -> Result<MemoryRecord, MemoryError> {
        let confirmed = {
            let state = self.state().map_err(|_| MemoryError::database())?;
            load_owned_memory(&state.connection, life_id, memory_id)
        };
        match confirmed {
            Ok(record) => Ok(record),
            Err(error) if error.code != "MEMORY_NOT_FOUND" => Err(error),
            Err(_) => <Self as CandidateMemoryRepository>::get_candidate(self, life_id, memory_id)
                .map_err(map_candidate_error)
                .and_then(candidate_as_legacy),
        }
    }

    fn confirm(&self, request: ConfirmMemoryRequest) -> Result<MemoryRecord, MemoryError> {
        let _legacy_revision_writer =
            super::memory_revision::insert_confirmed_revision_in_transaction;
        <Self as CandidateMemoryRepository>::get_candidate(
            self,
            &request.life_id,
            &request.memory_id,
        )
        .map_err(map_candidate_error)?;
        Err(MemoryError::new(
            "CANDIDATE_CONFIRMATION_UNAVAILABLE",
            "Candidate confirmation is unavailable until the governed confirmation service is installed.",
            true,
        ))
    }

    fn delete(&self, life_id: &str, memory_id: &str) -> Result<DeleteMemoryResult, MemoryError> {
        match <Self as CandidateMemoryRepository>::get_candidate(self, life_id, memory_id) {
            Ok(_) => return Err(candidate_lifecycle_command_unavailable()),
            Err(error) if error.code != "CANDIDATE_MEMORY_NOT_FOUND" => {
                return Err(map_candidate_error(error));
            }
            Err(_) => {}
        }
        let state = self.state().map_err(|_| MemoryError::database())?;
        if load_owned_memory(&state.connection, life_id, memory_id).is_ok() {
            return Err(MemoryError::new(
                "MEMORY_NOT_CONFIRMED",
                "Confirmed memories require revision-aware permanent deletion.",
                true,
            ));
        }
        Err(MemoryError::not_found())
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
    let sql = format!(
        "SELECT {MEMORY_COLUMNS} FROM memory_record WHERE id = ?1 AND status = 'confirmed'"
    );
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

fn current_timestamp(storage: &StorageService) -> Result<String, MemoryError> {
    let state = storage.state().map_err(|_| MemoryError::database())?;
    state
        .connection
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| MemoryError::database())
}

fn candidate_source(
    source_type: MemorySourceType,
) -> (CandidateMemorySourceType, CandidateInferenceStatus) {
    let _legacy_source_name = source_type.as_str();
    match source_type {
        MemorySourceType::Manual => (
            CandidateMemorySourceType::Manual,
            CandidateInferenceStatus::Explicit,
        ),
        MemorySourceType::Conversation => (
            CandidateMemorySourceType::Conversation,
            CandidateInferenceStatus::Extracted,
        ),
        MemorySourceType::System => (
            CandidateMemorySourceType::Reflection,
            CandidateInferenceStatus::Extracted,
        ),
        MemorySourceType::Import => (
            CandidateMemorySourceType::Import,
            CandidateInferenceStatus::Extracted,
        ),
    }
}

fn legacy_source(source_type: CandidateMemorySourceType) -> MemorySourceType {
    match source_type {
        CandidateMemorySourceType::Manual | CandidateMemorySourceType::ExplicitUserRequest => {
            MemorySourceType::Manual
        }
        CandidateMemorySourceType::Conversation => MemorySourceType::Conversation,
        CandidateMemorySourceType::Import => MemorySourceType::Import,
        CandidateMemorySourceType::LifeEvent
        | CandidateMemorySourceType::Reflection
        | CandidateMemorySourceType::AgentProposal
        | CandidateMemorySourceType::PluginProposal => MemorySourceType::System,
    }
}

fn candidate_as_legacy(candidate: CandidateMemoryRecord) -> Result<MemoryRecord, MemoryError> {
    if candidate.status != CandidateMemoryStatus::Pending {
        return Err(MemoryError::not_found());
    }
    let content = candidate
        .content
        .filter(|content| !content.trim().is_empty())
        .ok_or_else(MemoryError::database)?;
    Ok(MemoryRecord {
        id: candidate.id,
        life_id: candidate.life_id,
        kind: candidate.kind,
        status: MemoryStatus::Candidate,
        content,
        summary: candidate.summary,
        source_type: legacy_source(candidate.source_type),
        source_ref: candidate.source_id,
        source_created_at: candidate.proposed_at,
        importance: candidate.importance,
        confidence: candidate.confidence,
        is_sensitive: candidate.is_sensitive,
        created_at: candidate.created_at,
        updated_at: candidate.updated_at,
        confirmed_at: None,
    })
}

fn map_candidate_error(error: CandidateMemoryError) -> MemoryError {
    match error.code.as_str() {
        "CANDIDATE_MEMORY_NOT_FOUND" => MemoryError::not_found(),
        "CANDIDATE_MEMORY_LIFE_MISMATCH" => MemoryError::life_mismatch(),
        "CANDIDATE_MEMORY_REVISION_CONFLICT" => MemoryError::new(
            "MEMORY_REVISION_CONFLICT",
            "The candidate memory changed after it was loaded. Refresh and try again.",
            true,
        ),
        _ => MemoryError::new(&error.code, error.message, error.recoverable),
    }
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
        assert_eq!(version, 9);
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
    fn legacy_candidate_create_uses_candidate_memory_as_sole_authority() {
        let root = TestRoot::new("legacy-candidate-authority");
        let service = seeded_service(&root);
        let record = create_candidate(&service, "life-a", false);
        let state = service.state().unwrap();
        let legacy_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_record WHERE id = ?1 AND status = 'candidate'",
                rusqlite::params![record.id],
                |row| row.get(0),
            )
            .unwrap();
        let authoritative_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory WHERE id = ?1 AND status = 'pending'",
                rusqlite::params![record.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_count, 0);
        assert_eq!(authoritative_count, 1);
    }

    #[test]
    fn legacy_candidate_update_is_disabled_without_side_effects() {
        let root = TestRoot::new("legacy-candidate-update-disabled");
        let service = seeded_service(&root);
        let candidate = create_candidate(&service, "life-a", false);
        {
            let state = service.state().unwrap();
            state
                .connection
                .execute(
                    "INSERT INTO candidate_memory_evidence (
                        id, candidate_id, life_id, source_type, source_id, conversation_id,
                        message_id, observed_at
                     ) VALUES ('evidence-a', ?1, 'life-a', 'manual', NULL, NULL, NULL, ?2)",
                    rusqlite::params![candidate.id, "2026-07-14T10:00:00.000Z"],
                )
                .unwrap();
        }
        let before = {
            let state = service.state().unwrap();
            let candidate_state: (String, Option<String>, String, i64) = state
                .connection
                .query_row(
                    "SELECT content, summary, kind, revision
                     FROM candidate_memory WHERE id = ?1 AND life_id = 'life-a'",
                    rusqlite::params![candidate.id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
            let evidence_count: i64 = state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM candidate_memory_evidence WHERE candidate_id = ?1",
                    rusqlite::params![candidate.id],
                    |row| row.get(0),
                )
                .unwrap();
            let audit_count: i64 = state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM candidate_memory_audit WHERE candidate_id = ?1",
                    rusqlite::params![candidate.id],
                    |row| row.get(0),
                )
                .unwrap();
            let outbox_count: i64 = state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM memory_vector_sync_outbox",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let revision_count: i64 = state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM memory_revision WHERE memory_id = ?1",
                    rusqlite::params![candidate.id],
                    |row| row.get(0),
                )
                .unwrap();
            (
                candidate_state,
                evidence_count,
                audit_count,
                outbox_count,
                revision_count,
            )
        };

        let error = MemoryService::new(&service)
            .update_candidate(update_request("life-a", &candidate.id))
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_LIFECYCLE_COMMAND_UNAVAILABLE");

        let state = service.state().unwrap();
        let after_candidate: (String, Option<String>, String, i64) = state
            .connection
            .query_row(
                "SELECT content, summary, kind, revision
                 FROM candidate_memory WHERE id = ?1 AND life_id = 'life-a'",
                rusqlite::params![candidate.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        let after_evidence: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory_evidence WHERE candidate_id = ?1",
                rusqlite::params![candidate.id],
                |row| row.get(0),
            )
            .unwrap();
        let after_audit: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory_audit WHERE candidate_id = ?1",
                rusqlite::params![candidate.id],
                |row| row.get(0),
            )
            .unwrap();
        let after_outbox: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_sync_outbox",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let after_revisions: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_revision WHERE memory_id = ?1",
                rusqlite::params![candidate.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(after_candidate, before.0);
        assert_eq!(after_evidence, before.1);
        assert_eq!(after_audit, before.2);
        assert_eq!(after_outbox, before.3);
        assert_eq!(after_revisions, before.4);
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
    fn legacy_confirmation_is_blocked_without_writing_confirmed_memory() {
        let root = TestRoot::new("confirm-blocked");
        let service = seeded_service(&root);
        let candidate = create_candidate(&service, "life-a", false);
        let error = MemoryService::new(&service)
            .confirm(ConfirmMemoryRequest {
                life_id: "life-a".into(),
                memory_id: candidate.id.clone(),
                user_confirmed: true,
                sensitive_consent: false,
            })
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_CONFIRMATION_UNAVAILABLE");
        let state = service.state().unwrap();
        let legacy_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_record WHERE id = ?1",
                rusqlite::params![candidate.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(legacy_count, 0);
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
    fn legacy_candidate_update_is_disabled_without_touching_confirmed_memory() {
        let root = TestRoot::new("confirmed-update");
        let service = seeded_service(&root);
        let state = service.state().unwrap();
        state
            .connection
            .execute(
                "INSERT INTO memory_record (
                    id, life_id, kind, status, content, summary, source_type, source_ref,
                    source_created_at, importance, confidence, is_sensitive, created_at,
                    updated_at, confirmed_at, revision
                 ) VALUES (
                    'confirmed', 'life-a', 'experience', 'confirmed', 'Confirmed', NULL,
                    'manual', NULL, ?1, 0.7, 0.8, 0, ?1, ?1, ?1, 1
                 )",
                rusqlite::params!["2026-07-11T01:00:00.000Z"],
            )
            .unwrap();
        drop(state);
        let error = MemoryService::new(&service)
            .update_candidate(update_request("life-a", "confirmed"))
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_LIFECYCLE_COMMAND_UNAVAILABLE");
        assert_eq!(
            MemoryService::new(&service)
                .get("life-a", "confirmed")
                .unwrap()
                .status,
            MemoryStatus::Confirmed
        );
    }

    #[test]
    fn legacy_confirmation_does_not_bypass_sensitive_candidate_governance() {
        let root = TestRoot::new("sensitive-confirm-blocked");
        let service = seeded_service(&root);
        let candidate = create_candidate(&service, "life-a", true);
        for sensitive_consent in [false, true] {
            let error = MemoryService::new(&service)
                .confirm(ConfirmMemoryRequest {
                    life_id: "life-a".into(),
                    memory_id: candidate.id.clone(),
                    user_confirmed: true,
                    sensitive_consent,
                })
                .unwrap_err();
            assert_eq!(error.code, "CANDIDATE_CONFIRMATION_UNAVAILABLE");
        }
        assert!(
            MemoryService::new(&service)
                .get("life-a", &candidate.id)
                .unwrap()
                .is_sensitive
        );
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
            "CANDIDATE_LIFECYCLE_COMMAND_UNAVAILABLE"
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
    fn legacy_candidate_delete_is_disabled_without_side_effects() {
        let root = TestRoot::new("legacy-candidate-delete-disabled");
        let service = seeded_service(&root);
        let candidate = create_candidate(&service, "life-a", false);
        {
            let state = service.state().unwrap();
            state
                .connection
                .execute(
                    "INSERT INTO candidate_memory_evidence (
                        id, candidate_id, life_id, source_type, source_id, conversation_id,
                        message_id, observed_at
                     ) VALUES ('evidence-a', ?1, 'life-a', 'manual', NULL, NULL, NULL, ?2)",
                    rusqlite::params![candidate.id, "2026-07-14T10:00:00.000Z"],
                )
                .unwrap();
        }
        let before = {
            let state = service.state().unwrap();
            let candidate_state: (String, Option<String>, String, i64) = state
                .connection
                .query_row(
                    "SELECT content, summary, kind, revision
                     FROM candidate_memory WHERE id = ?1 AND life_id = 'life-a'",
                    rusqlite::params![candidate.id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
            let evidence_count: i64 = state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM candidate_memory_evidence WHERE candidate_id = ?1",
                    rusqlite::params![candidate.id],
                    |row| row.get(0),
                )
                .unwrap();
            let audit_count: i64 = state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM candidate_memory_audit WHERE candidate_id = ?1",
                    rusqlite::params![candidate.id],
                    |row| row.get(0),
                )
                .unwrap();
            let outbox_count: i64 = state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM memory_vector_sync_outbox",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let revision_count: i64 = state
                .connection
                .query_row(
                    "SELECT COUNT(*) FROM memory_revision WHERE memory_id = ?1",
                    rusqlite::params![candidate.id],
                    |row| row.get(0),
                )
                .unwrap();
            (
                candidate_state,
                evidence_count,
                audit_count,
                outbox_count,
                revision_count,
            )
        };
        let error = MemoryService::new(&service)
            .delete("life-a", &candidate.id)
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_LIFECYCLE_COMMAND_UNAVAILABLE");
        let state = service.state().unwrap();
        let after_candidate: (String, Option<String>, String, i64) = state
            .connection
            .query_row(
                "SELECT content, summary, kind, revision
                 FROM candidate_memory WHERE id = ?1 AND life_id = 'life-a'",
                rusqlite::params![candidate.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        let after_evidence: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory_evidence WHERE candidate_id = ?1",
                rusqlite::params![candidate.id],
                |row| row.get(0),
            )
            .unwrap();
        let after_audit: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory_audit WHERE candidate_id = ?1",
                rusqlite::params![candidate.id],
                |row| row.get(0),
            )
            .unwrap();
        let after_outbox: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_sync_outbox",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let after_revisions: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_revision WHERE memory_id = ?1",
                rusqlite::params![candidate.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(after_candidate, before.0);
        assert_eq!(after_evidence, before.1);
        assert_eq!(after_audit, before.2);
        assert_eq!(after_outbox, before.3);
        assert_eq!(after_revisions, before.4);
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
