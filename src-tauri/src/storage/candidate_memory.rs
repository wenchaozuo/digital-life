use rusqlite::{params, Connection, Error as SqlError, ErrorCode, OptionalExtension, Row};

use crate::memory::{
    candidate::{
        CandidateInferenceStatus, CandidateMemoryAuditRecord, CandidateMemoryCursor,
        CandidateMemoryError, CandidateMemoryEvidenceRecord, CandidateMemoryListFilter,
        CandidateMemoryRecord, CandidateMemoryRepository, CandidateMemorySourceType,
        CandidateMemoryStatus, CandidateMemoryStorageUpdate, NewCandidateMemory,
        NewCandidateMemoryAudit, NewCandidateMemoryEvidence, DEFAULT_CANDIDATE_PAGE_SIZE,
        MAX_CANDIDATE_PAGE_SIZE,
    },
    MemoryKind,
};

use super::StorageService;

const CANDIDATE_COLUMNS: &str = "id, life_id, subject_id, kind, content, summary, source_type, \
    source_id, confidence, importance, is_sensitive, inference_status, status, revision, \
    dedup_fingerprint, proposed_at, expires_at, reviewed_at, last_user_edit_at, \
    confirmed_memory_id, accepted_request_id, rejection_reason_code, \
    superseded_by_candidate_id, conflicts_with_memory_id, created_at, updated_at";

const EVIDENCE_COLUMNS: &str = "id, candidate_id, life_id, source_type, source_id, \
    conversation_id, message_id, observed_at";

const AUDIT_COLUMNS: &str = "id, candidate_id, life_id, action, actor_type, request_id, \
    result_status, created_at";

struct StoredCandidateMemory {
    id: String,
    life_id: String,
    subject_id: String,
    kind: String,
    content: Option<String>,
    summary: Option<String>,
    source_type: String,
    source_id: Option<String>,
    confidence: f64,
    importance: f64,
    is_sensitive: bool,
    inference_status: String,
    status: String,
    revision: i64,
    dedup_fingerprint: Option<String>,
    proposed_at: String,
    expires_at: Option<String>,
    reviewed_at: Option<String>,
    last_user_edit_at: Option<String>,
    confirmed_memory_id: Option<String>,
    accepted_request_id: Option<String>,
    rejection_reason_code: Option<String>,
    superseded_by_candidate_id: Option<String>,
    conflicts_with_memory_id: Option<String>,
    created_at: String,
    updated_at: String,
}

impl TryFrom<StoredCandidateMemory> for CandidateMemoryRecord {
    type Error = CandidateMemoryError;

    fn try_from(value: StoredCandidateMemory) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            life_id: value.life_id,
            subject_id: value.subject_id,
            kind: MemoryKind::parse(&value.kind)
                .map_err(|_| CandidateMemoryError::invalid_stored_enum())?,
            content: value.content,
            summary: value.summary,
            source_type: CandidateMemorySourceType::parse(&value.source_type)?,
            source_id: value.source_id,
            confidence: value.confidence,
            importance: value.importance,
            is_sensitive: value.is_sensitive,
            inference_status: CandidateInferenceStatus::parse(&value.inference_status)?,
            status: CandidateMemoryStatus::parse(&value.status)?,
            revision: value.revision,
            dedup_fingerprint: value.dedup_fingerprint,
            proposed_at: value.proposed_at,
            expires_at: value.expires_at,
            reviewed_at: value.reviewed_at,
            last_user_edit_at: value.last_user_edit_at,
            confirmed_memory_id: value.confirmed_memory_id,
            accepted_request_id: value.accepted_request_id,
            rejection_reason_code: value.rejection_reason_code,
            superseded_by_candidate_id: value.superseded_by_candidate_id,
            conflicts_with_memory_id: value.conflicts_with_memory_id,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}

impl CandidateMemoryRepository for StorageService {
    fn insert_candidate(
        &self,
        candidate: NewCandidateMemory,
    ) -> Result<CandidateMemoryRecord, CandidateMemoryError> {
        validate_candidate_insert(&candidate)?;
        let candidate_id = candidate.id.clone();
        let life_id = candidate.life_id.clone();
        let state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        state
            .connection
            .execute(
                "INSERT INTO candidate_memory (
                    id, life_id, subject_id, kind, content, summary, source_type, source_id,
                    confidence, importance, is_sensitive, inference_status, status, revision,
                    dedup_fingerprint, proposed_at, expires_at, reviewed_at, last_user_edit_at,
                    confirmed_memory_id, accepted_request_id, rejection_reason_code,
                    superseded_by_candidate_id, conflicts_with_memory_id, created_at, updated_at
                 ) VALUES (
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 1,
                    ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25
                 )",
                params![
                    candidate.id,
                    candidate.life_id,
                    candidate.subject_id,
                    candidate.kind.as_str(),
                    normalize_optional(candidate.content),
                    normalize_optional(candidate.summary),
                    candidate.source_type.as_str(),
                    normalize_optional(candidate.source_id),
                    candidate.confidence,
                    candidate.importance,
                    candidate.is_sensitive,
                    candidate.inference_status.as_str(),
                    candidate.status.as_str(),
                    normalize_optional(candidate.dedup_fingerprint),
                    candidate.proposed_at,
                    normalize_optional(candidate.expires_at),
                    normalize_optional(candidate.reviewed_at),
                    normalize_optional(candidate.last_user_edit_at),
                    normalize_optional(candidate.confirmed_memory_id),
                    normalize_optional(candidate.accepted_request_id),
                    normalize_optional(candidate.rejection_reason_code),
                    normalize_optional(candidate.superseded_by_candidate_id),
                    normalize_optional(candidate.conflicts_with_memory_id),
                    candidate.created_at,
                    candidate.updated_at,
                ],
            )
            .map_err(map_sql_error)?;

        load_owned_candidate(&state.connection, &life_id, &candidate_id)
    }

    fn get_candidate(
        &self,
        life_id: &str,
        candidate_id: &str,
    ) -> Result<CandidateMemoryRecord, CandidateMemoryError> {
        validate_identifier(life_id)?;
        validate_identifier(candidate_id)?;
        let state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        load_owned_candidate(&state.connection, life_id, candidate_id)
    }

    fn list_candidates(
        &self,
        filter: CandidateMemoryListFilter,
    ) -> Result<(Vec<CandidateMemoryRecord>, Option<CandidateMemoryCursor>), CandidateMemoryError>
    {
        let life_id = filter_life_id(&filter)?;
        let page_size = validated_page_size(filter.page_size)?;
        let cursor = filter.cursor.as_ref();
        if let Some(cursor) = cursor {
            validate_identifier(&cursor.proposed_at)?;
            validate_identifier(&cursor.id)?;
        }
        let escaped_query = filter.query.as_deref().and_then(normalized_like_query);
        let state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        let sql = format!(
            "SELECT {CANDIDATE_COLUMNS} FROM candidate_memory
             WHERE life_id = ?1
               AND (?2 IS NULL OR status = ?2)
               AND (?3 IS NULL OR kind = ?3)
               AND (?4 IS NULL OR is_sensitive = ?4)
               AND (?5 IS NULL OR source_type = ?5)
               AND (?6 IS NULL OR inference_status = ?6)
               AND (?7 IS NULL OR (
                    content LIKE ?7 ESCAPE '\\'
                    OR COALESCE(summary, '') LIKE ?7 ESCAPE '\\'
               ))
               AND (?8 IS NULL OR proposed_at < ?8
                    OR (proposed_at = ?8 AND id > ?9))
             ORDER BY proposed_at DESC, id ASC
             LIMIT ?10"
        );
        let mut statement = state.connection.prepare(&sql).map_err(map_sql_error)?;
        let rows = statement
            .query_map(
                params![
                    life_id,
                    filter.status.map(CandidateMemoryStatus::as_str),
                    filter.kind.map(MemoryKind::as_str),
                    filter.is_sensitive.map(i64::from),
                    filter.source_type.map(CandidateMemorySourceType::as_str),
                    filter
                        .inference_status
                        .map(CandidateInferenceStatus::as_str),
                    escaped_query,
                    cursor.map(|value| value.proposed_at.as_str()),
                    cursor.map(|value| value.id.as_str()),
                    i64::try_from(page_size + 1)
                        .map_err(|_| CandidateMemoryError::invalid_query())?,
                ],
                read_candidate,
            )
            .map_err(map_sql_error)?;
        let mut records: Vec<CandidateMemoryRecord> = rows
            .map(|row| row.map_err(map_sql_error)?.try_into())
            .collect::<Result<_, CandidateMemoryError>>()?;

        let next_cursor = if records.len() > page_size {
            records.pop();
            records.last().map(|record| CandidateMemoryCursor {
                proposed_at: record.proposed_at.clone(),
                id: record.id.clone(),
            })
        } else {
            None
        };
        Ok((records, next_cursor))
    }

    fn update_candidate_guarded(
        &self,
        life_id: &str,
        candidate_id: &str,
        expected_revision: i64,
        update: CandidateMemoryStorageUpdate,
    ) -> Result<CandidateMemoryRecord, CandidateMemoryError> {
        validate_identifier(life_id)?;
        validate_identifier(candidate_id)?;
        if expected_revision <= 0 {
            return Err(CandidateMemoryError::constraint());
        }
        validate_candidate_update(&update)?;
        let mut state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        let transaction = state.connection.transaction().map_err(map_sql_error)?;
        let changed = transaction
            .execute(
                "UPDATE candidate_memory SET
                    kind = ?4,
                    content = ?5,
                    summary = ?6,
                    source_type = ?7,
                    source_id = ?8,
                    confidence = ?9,
                    importance = ?10,
                    is_sensitive = ?11,
                    inference_status = ?12,
                    status = ?13,
                    dedup_fingerprint = ?14,
                    proposed_at = ?15,
                    expires_at = ?16,
                    reviewed_at = ?17,
                    last_user_edit_at = ?18,
                    confirmed_memory_id = ?19,
                    accepted_request_id = ?20,
                    rejection_reason_code = ?21,
                    superseded_by_candidate_id = ?22,
                    conflicts_with_memory_id = ?23,
                    updated_at = ?24,
                    revision = revision + 1
                 WHERE id = ?1 AND life_id = ?2 AND revision = ?3",
                params![
                    candidate_id,
                    life_id,
                    expected_revision,
                    update.kind.as_str(),
                    normalize_optional(update.content),
                    normalize_optional(update.summary),
                    update.source_type.as_str(),
                    normalize_optional(update.source_id),
                    update.confidence,
                    update.importance,
                    update.is_sensitive,
                    update.inference_status.as_str(),
                    update.status.as_str(),
                    normalize_optional(update.dedup_fingerprint),
                    update.proposed_at,
                    normalize_optional(update.expires_at),
                    normalize_optional(update.reviewed_at),
                    normalize_optional(update.last_user_edit_at),
                    normalize_optional(update.confirmed_memory_id),
                    normalize_optional(update.accepted_request_id),
                    normalize_optional(update.rejection_reason_code),
                    normalize_optional(update.superseded_by_candidate_id),
                    normalize_optional(update.conflicts_with_memory_id),
                    update.updated_at,
                ],
            )
            .map_err(map_sql_error)?;
        if changed != 1 {
            return match load_owned_candidate(&transaction, life_id, candidate_id) {
                Ok(_) => Err(CandidateMemoryError::revision_conflict()),
                Err(error) => Err(error),
            };
        }
        let updated = load_owned_candidate(&transaction, life_id, candidate_id)?;
        transaction.commit().map_err(map_sql_error)?;
        Ok(updated)
    }

    fn delete_candidate_permanently(
        &self,
        life_id: &str,
        candidate_id: &str,
    ) -> Result<bool, CandidateMemoryError> {
        validate_identifier(life_id)?;
        validate_identifier(candidate_id)?;
        let mut state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        let transaction = state.connection.transaction().map_err(map_sql_error)?;
        load_owned_candidate(&transaction, life_id, candidate_id)?;
        let deleted = transaction
            .execute(
                "DELETE FROM candidate_memory WHERE id = ?1 AND life_id = ?2",
                params![candidate_id, life_id],
            )
            .map_err(map_sql_error)?;
        transaction.commit().map_err(map_sql_error)?;
        Ok(deleted == 1)
    }

    fn insert_evidence(
        &self,
        evidence: NewCandidateMemoryEvidence,
    ) -> Result<CandidateMemoryEvidenceRecord, CandidateMemoryError> {
        validate_evidence(&evidence)?;
        let evidence_id = evidence.id.clone();
        let life_id = evidence.life_id.clone();
        let state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        validate_evidence_references(&state.connection, &evidence)?;
        state
            .connection
            .execute(
                "INSERT INTO candidate_memory_evidence (
                    id, candidate_id, life_id, source_type, source_id, conversation_id,
                    message_id, observed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    evidence.id,
                    evidence.candidate_id,
                    evidence.life_id,
                    evidence.source_type.as_str(),
                    normalize_optional(evidence.source_id),
                    normalize_optional(evidence.conversation_id),
                    normalize_optional(evidence.message_id),
                    evidence.observed_at,
                ],
            )
            .map_err(map_sql_error)?;
        load_evidence(&state.connection, &life_id, &evidence_id)
    }

    fn list_evidence(
        &self,
        life_id: &str,
        candidate_id: &str,
    ) -> Result<Vec<CandidateMemoryEvidenceRecord>, CandidateMemoryError> {
        validate_identifier(life_id)?;
        validate_identifier(candidate_id)?;
        let state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        load_owned_candidate(&state.connection, life_id, candidate_id)?;
        let sql = format!(
            "SELECT {EVIDENCE_COLUMNS} FROM candidate_memory_evidence
             WHERE candidate_id = ?1 AND life_id = ?2
             ORDER BY observed_at ASC, id ASC"
        );
        let mut statement = state.connection.prepare(&sql).map_err(map_sql_error)?;
        let rows = statement
            .query_map(params![candidate_id, life_id], read_evidence)
            .map_err(map_sql_error)?;
        rows.map(|row| row.map_err(map_sql_error)).collect()
    }

    fn count_evidence(
        &self,
        life_id: &str,
        candidate_id: &str,
    ) -> Result<usize, CandidateMemoryError> {
        validate_identifier(life_id)?;
        validate_identifier(candidate_id)?;
        let state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        load_owned_candidate(&state.connection, life_id, candidate_id)?;
        let count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory_evidence
                 WHERE candidate_id = ?1 AND life_id = ?2",
                params![candidate_id, life_id],
                |row| row.get(0),
            )
            .map_err(map_sql_error)?;
        usize::try_from(count).map_err(|_| CandidateMemoryError::storage_unavailable())
    }

    fn delete_evidence(
        &self,
        life_id: &str,
        evidence_id: &str,
    ) -> Result<bool, CandidateMemoryError> {
        validate_identifier(life_id)?;
        validate_identifier(evidence_id)?;
        let state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        let stored_life: Option<String> = state
            .connection
            .query_row(
                "SELECT life_id FROM candidate_memory_evidence WHERE id = ?1",
                params![evidence_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sql_error)?;
        match stored_life.as_deref() {
            None => return Err(CandidateMemoryError::not_found()),
            Some(stored_life) if stored_life != life_id => {
                return Err(CandidateMemoryError::life_mismatch())
            }
            Some(_) => {}
        }
        let deleted = state
            .connection
            .execute(
                "DELETE FROM candidate_memory_evidence WHERE id = ?1 AND life_id = ?2",
                params![evidence_id, life_id],
            )
            .map_err(map_sql_error)?;
        Ok(deleted == 1)
    }

    fn append_audit(
        &self,
        audit: NewCandidateMemoryAudit,
    ) -> Result<CandidateMemoryAuditRecord, CandidateMemoryError> {
        validate_audit(&audit)?;
        let audit_id = audit.id.clone();
        let life_id = audit.life_id.clone();
        let state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        ensure_life_exists(&state.connection, &audit.life_id)?;
        state
            .connection
            .execute(
                "INSERT INTO candidate_memory_audit (
                    id, candidate_id, life_id, action, actor_type, request_id,
                    result_status, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    audit.id,
                    audit.candidate_id,
                    audit.life_id,
                    audit.action,
                    audit.actor_type,
                    normalize_optional(audit.request_id),
                    audit.result_status,
                    audit.created_at,
                ],
            )
            .map_err(map_sql_error)?;
        load_audit(&state.connection, &life_id, &audit_id)
    }

    fn purge_audit_before(
        &self,
        life_id: &str,
        before: &str,
    ) -> Result<usize, CandidateMemoryError> {
        validate_identifier(life_id)?;
        validate_identifier(before)?;
        let state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        let deleted = state
            .connection
            .execute(
                "DELETE FROM candidate_memory_audit
                 WHERE life_id = ?1 AND created_at < ?2",
                params![life_id, before],
            )
            .map_err(map_sql_error)?;
        Ok(deleted)
    }
}

fn load_owned_candidate(
    connection: &Connection,
    life_id: &str,
    candidate_id: &str,
) -> Result<CandidateMemoryRecord, CandidateMemoryError> {
    let sql = format!("SELECT {CANDIDATE_COLUMNS} FROM candidate_memory WHERE id = ?1");
    let stored = connection
        .query_row(&sql, params![candidate_id], read_candidate)
        .optional()
        .map_err(map_sql_error)?
        .ok_or_else(CandidateMemoryError::not_found)?;
    if stored.life_id != life_id {
        return Err(CandidateMemoryError::life_mismatch());
    }
    stored.try_into()
}

fn load_evidence(
    connection: &Connection,
    life_id: &str,
    evidence_id: &str,
) -> Result<CandidateMemoryEvidenceRecord, CandidateMemoryError> {
    let sql = format!("SELECT {EVIDENCE_COLUMNS} FROM candidate_memory_evidence WHERE id = ?1");
    let stored = connection
        .query_row(&sql, params![evidence_id], read_evidence)
        .optional()
        .map_err(map_sql_error)?
        .ok_or_else(CandidateMemoryError::not_found)?;
    if stored.life_id != life_id {
        return Err(CandidateMemoryError::life_mismatch());
    }
    Ok(stored)
}

fn load_audit(
    connection: &Connection,
    life_id: &str,
    audit_id: &str,
) -> Result<CandidateMemoryAuditRecord, CandidateMemoryError> {
    let sql = format!("SELECT {AUDIT_COLUMNS} FROM candidate_memory_audit WHERE id = ?1");
    let audit = connection
        .query_row(&sql, params![audit_id], read_audit)
        .optional()
        .map_err(map_sql_error)?
        .ok_or_else(CandidateMemoryError::not_found)?;
    if audit.life_id != life_id {
        return Err(CandidateMemoryError::life_mismatch());
    }
    Ok(audit)
}

fn read_candidate(row: &Row<'_>) -> rusqlite::Result<StoredCandidateMemory> {
    Ok(StoredCandidateMemory {
        id: row.get(0)?,
        life_id: row.get(1)?,
        subject_id: row.get(2)?,
        kind: row.get(3)?,
        content: row.get(4)?,
        summary: row.get(5)?,
        source_type: row.get(6)?,
        source_id: row.get(7)?,
        confidence: row.get(8)?,
        importance: row.get(9)?,
        is_sensitive: row.get(10)?,
        inference_status: row.get(11)?,
        status: row.get(12)?,
        revision: row.get(13)?,
        dedup_fingerprint: row.get(14)?,
        proposed_at: row.get(15)?,
        expires_at: row.get(16)?,
        reviewed_at: row.get(17)?,
        last_user_edit_at: row.get(18)?,
        confirmed_memory_id: row.get(19)?,
        accepted_request_id: row.get(20)?,
        rejection_reason_code: row.get(21)?,
        superseded_by_candidate_id: row.get(22)?,
        conflicts_with_memory_id: row.get(23)?,
        created_at: row.get(24)?,
        updated_at: row.get(25)?,
    })
}

fn read_evidence(row: &Row<'_>) -> rusqlite::Result<CandidateMemoryEvidenceRecord> {
    let source_type: String = row.get(3)?;
    CandidateMemorySourceType::parse(&source_type).map_err(|_| rusqlite::Error::InvalidQuery)?;
    Ok(CandidateMemoryEvidenceRecord {
        id: row.get(0)?,
        candidate_id: row.get(1)?,
        life_id: row.get(2)?,
        source_type: CandidateMemorySourceType::parse(&source_type)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        source_id: row.get(4)?,
        conversation_id: row.get(5)?,
        message_id: row.get(6)?,
        observed_at: row.get(7)?,
    })
}

fn read_audit(row: &Row<'_>) -> rusqlite::Result<CandidateMemoryAuditRecord> {
    Ok(CandidateMemoryAuditRecord {
        id: row.get(0)?,
        candidate_id: row.get(1)?,
        life_id: row.get(2)?,
        action: row.get(3)?,
        actor_type: row.get(4)?,
        request_id: row.get(5)?,
        result_status: row.get(6)?,
        created_at: row.get(7)?,
    })
}

fn validate_candidate_insert(candidate: &NewCandidateMemory) -> Result<(), CandidateMemoryError> {
    validate_identifier(&candidate.id)?;
    validate_identifier(&candidate.life_id)?;
    validate_identifier(&candidate.subject_id)?;
    validate_identifier(&candidate.proposed_at)?;
    validate_identifier(&candidate.created_at)?;
    validate_identifier(&candidate.updated_at)?;
    validate_scores(candidate.confidence, candidate.importance)
}

fn validate_candidate_update(
    update: &CandidateMemoryStorageUpdate,
) -> Result<(), CandidateMemoryError> {
    validate_identifier(&update.proposed_at)?;
    validate_identifier(&update.updated_at)?;
    validate_scores(update.confidence, update.importance)
}

fn validate_evidence(evidence: &NewCandidateMemoryEvidence) -> Result<(), CandidateMemoryError> {
    validate_identifier(&evidence.id)?;
    validate_identifier(&evidence.candidate_id)?;
    validate_identifier(&evidence.life_id)?;
    validate_identifier(&evidence.observed_at)
}

fn validate_audit(audit: &NewCandidateMemoryAudit) -> Result<(), CandidateMemoryError> {
    validate_identifier(&audit.id)?;
    validate_identifier(&audit.candidate_id)?;
    validate_identifier(&audit.life_id)?;
    validate_identifier(&audit.action)?;
    validate_identifier(&audit.actor_type)?;
    validate_identifier(&audit.result_status)?;
    validate_identifier(&audit.created_at)
}

fn validate_identifier(value: &str) -> Result<(), CandidateMemoryError> {
    if value.trim().is_empty() {
        return Err(CandidateMemoryError::constraint());
    }
    Ok(())
}

fn validate_scores(confidence: f64, importance: f64) -> Result<(), CandidateMemoryError> {
    if !confidence.is_finite()
        || !importance.is_finite()
        || !(0.0..=1.0).contains(&confidence)
        || !(0.0..=1.0).contains(&importance)
    {
        return Err(CandidateMemoryError::constraint());
    }
    Ok(())
}

fn validated_page_size(page_size: Option<usize>) -> Result<usize, CandidateMemoryError> {
    match page_size.unwrap_or(DEFAULT_CANDIDATE_PAGE_SIZE) {
        1..=MAX_CANDIDATE_PAGE_SIZE => Ok(page_size.unwrap_or(DEFAULT_CANDIDATE_PAGE_SIZE)),
        _ => Err(CandidateMemoryError::invalid_query()),
    }
}

fn filter_life_id(filter: &CandidateMemoryListFilter) -> Result<&str, CandidateMemoryError> {
    validate_identifier(&filter.life_id)?;
    Ok(&filter.life_id)
}

fn normalized_like_query(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let escaped = trimmed
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    Some(format!("%{escaped}%"))
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    })
}

fn ensure_life_exists(connection: &Connection, life_id: &str) -> Result<(), CandidateMemoryError> {
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM life_identity WHERE id = ?1)",
            params![life_id],
            |row| row.get(0),
        )
        .map_err(map_sql_error)?;
    if exists {
        Ok(())
    } else {
        Err(CandidateMemoryError::not_found())
    }
}

fn validate_evidence_references(
    connection: &Connection,
    evidence: &NewCandidateMemoryEvidence,
) -> Result<(), CandidateMemoryError> {
    load_owned_candidate(connection, &evidence.life_id, &evidence.candidate_id)?;
    if let Some(conversation_id) = evidence.conversation_id.as_deref() {
        let conversation_life: Option<String> = connection
            .query_row(
                "SELECT life_id FROM conversation WHERE id = ?1",
                params![conversation_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sql_error)?;
        if conversation_life.as_deref() != Some(evidence.life_id.as_str()) {
            return Err(CandidateMemoryError::constraint());
        }
    }
    if let Some(message_id) = evidence.message_id.as_deref() {
        let message: Option<(String, String)> = connection
            .query_row(
                "SELECT conversation_id, life_id FROM conversation_message WHERE id = ?1",
                params![message_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(map_sql_error)?;
        let Some((message_conversation_id, message_life_id)) = message else {
            return Err(CandidateMemoryError::constraint());
        };
        if message_life_id != evidence.life_id
            || evidence
                .conversation_id
                .as_deref()
                .is_some_and(|conversation_id| conversation_id != message_conversation_id)
        {
            return Err(CandidateMemoryError::constraint());
        }
    }
    Ok(())
}

fn map_sql_error(error: SqlError) -> CandidateMemoryError {
    match error {
        SqlError::SqliteFailure(code, message) if code.code == ErrorCode::ConstraintViolation => {
            if message.as_deref().is_some_and(|message| {
                message.contains("idx_candidate_memory_pending_dedup")
                    || (message.contains("candidate_memory.life_id")
                        && message.contains("candidate_memory.subject_id")
                        && message.contains("candidate_memory.kind")
                        && message.contains("candidate_memory.dedup_fingerprint"))
            }) {
                CandidateMemoryError::duplicate()
            } else {
                CandidateMemoryError::constraint()
            }
        }
        _ => CandidateMemoryError::storage_unavailable(),
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use rusqlite::{params, Connection};

    use crate::{
        memory::{
            candidate::{
                CandidateInferenceStatus, CandidateMemoryListFilter, CandidateMemoryRepository,
                CandidateMemorySourceType, CandidateMemoryStatus, CandidateMemoryStorageUpdate,
                NewCandidateMemory, NewCandidateMemoryAudit, NewCandidateMemoryEvidence,
                PRIMARY_USER_SUBJECT_ID,
            },
            MemoryKind,
        },
        storage::{
            unique_suffix, LifeIdentityRecord, PersonaTemplateRecord, StorageService,
            DATABASE_FILE_NAME,
        },
    };

    use super::CANDIDATE_COLUMNS;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "digital-life-candidate-storage-{name}-{}",
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
                    created_at: "2026-07-14T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "body".into(),
                    persona_id: format!("persona-{suffix}"),
                    persona_version: 1,
                })
                .unwrap();
        }
        service
    }

    fn pending(id: &str, life_id: &str, proposed_at: &str) -> NewCandidateMemory {
        NewCandidateMemory {
            id: id.into(),
            life_id: life_id.into(),
            subject_id: PRIMARY_USER_SUBJECT_ID.into(),
            kind: MemoryKind::Fact,
            content: Some(format!("Candidate {id}")),
            summary: Some(format!("Summary {id}")),
            source_type: CandidateMemorySourceType::Conversation,
            source_id: Some("conversation-source".into()),
            confidence: 0.8,
            importance: 0.6,
            is_sensitive: false,
            inference_status: CandidateInferenceStatus::Extracted,
            status: CandidateMemoryStatus::Pending,
            dedup_fingerprint: None,
            proposed_at: proposed_at.into(),
            expires_at: None,
            reviewed_at: None,
            last_user_edit_at: None,
            confirmed_memory_id: None,
            accepted_request_id: None,
            rejection_reason_code: None,
            superseded_by_candidate_id: None,
            conflicts_with_memory_id: None,
            created_at: proposed_at.into(),
            updated_at: proposed_at.into(),
        }
    }

    fn update_from(
        record: &crate::memory::candidate::CandidateMemoryRecord,
    ) -> CandidateMemoryStorageUpdate {
        CandidateMemoryStorageUpdate {
            kind: record.kind,
            content: record.content.clone(),
            summary: record.summary.clone(),
            source_type: record.source_type,
            source_id: record.source_id.clone(),
            confidence: record.confidence,
            importance: record.importance,
            is_sensitive: record.is_sensitive,
            inference_status: record.inference_status,
            status: record.status,
            dedup_fingerprint: record.dedup_fingerprint.clone(),
            proposed_at: record.proposed_at.clone(),
            expires_at: record.expires_at.clone(),
            reviewed_at: record.reviewed_at.clone(),
            last_user_edit_at: record.last_user_edit_at.clone(),
            confirmed_memory_id: record.confirmed_memory_id.clone(),
            accepted_request_id: record.accepted_request_id.clone(),
            rejection_reason_code: record.rejection_reason_code.clone(),
            superseded_by_candidate_id: record.superseded_by_candidate_id.clone(),
            conflicts_with_memory_id: record.conflicts_with_memory_id.clone(),
            updated_at: "2026-07-14T09:00:00.000Z".into(),
        }
    }

    fn insert_candidate(
        storage: &StorageService,
        id: &str,
        life_id: &str,
        proposed_at: &str,
    ) -> crate::memory::candidate::CandidateMemoryRecord {
        <StorageService as CandidateMemoryRepository>::insert_candidate(
            storage,
            pending(id, life_id, proposed_at),
        )
        .unwrap()
    }

    fn filter(life_id: &str) -> CandidateMemoryListFilter {
        CandidateMemoryListFilter {
            life_id: life_id.into(),
            ..Default::default()
        }
    }

    fn insert_conversation_with_message(storage: &StorageService, life_id: &str, suffix: &str) {
        let state = storage.state().unwrap();
        state
            .connection
            .execute(
                "INSERT INTO conversation (
                    id, life_id, title, revision, created_at, updated_at, last_message_at
                 ) VALUES (?1, ?2, 'Conversation', 0, ?3, ?3, ?3)",
                params![
                    format!("conversation-{suffix}"),
                    life_id,
                    "2026-07-14T00:00:00.000Z"
                ],
            )
            .unwrap();
        state
            .connection
            .execute(
                "INSERT INTO conversation_message (
                    id, conversation_id, life_id, turn_id, role, content, sequence_no, created_at
                 ) VALUES (?1, ?2, ?3, 'turn-1', 'user', 'Message', 1, ?4)",
                params![
                    format!("message-{suffix}"),
                    format!("conversation-{suffix}"),
                    life_id,
                    "2026-07-14T00:00:00.000Z"
                ],
            )
            .unwrap();
    }

    fn insert_confirmed_memory(storage: &StorageService, id: &str, life_id: &str) {
        let state = storage.state().unwrap();
        state
            .connection
            .execute(
                "INSERT INTO memory_record (
                    id, life_id, kind, status, content, summary, source_type, source_ref,
                    source_created_at, importance, confidence, is_sensitive, created_at,
                    updated_at, confirmed_at, revision
                 ) VALUES (
                    ?1, ?2, 'fact', 'confirmed', 'Confirmed', NULL, 'manual', NULL,
                    ?3, 0.5, 0.8, 0, ?3, ?3, ?3, 1
                 )",
                params![id, life_id, "2026-07-14T00:00:00.000Z"],
            )
            .unwrap();
    }

    fn create_v7_database(root: &TestRoot) -> PathBuf {
        let data_root = root.0.join("v7-data");
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
            (
                7,
                "007_memory_revisions",
                include_str!("migrations/007_memory_revisions.sql"),
            ),
        ] {
            connection.execute_batch(sql).unwrap();
            connection
                .execute(
                    "INSERT INTO schema_migration (version, name, applied_at)
                     VALUES (?1, ?2, '2026-07-14T00:00:00.000Z')",
                    params![version, name],
                )
                .unwrap();
        }
        connection
            .execute(
                "INSERT INTO persona_template (id, name, version, persona_json)
                 VALUES ('persona-a', 'Persona', 1, '{}')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO life_identity (
                    id, name, created_at, version, body_id, persona_id, persona_version
                 ) VALUES ('life-a', 'Life', '2026-07-14T00:00:00.000Z', 1, 'body', 'persona-a', 1)",
                [],
            )
            .unwrap();
        for (id, source_type, content) in [
            ("candidate-manual", "manual", "Manual candidate"),
            (
                "candidate-conversation",
                "conversation",
                "Conversation candidate",
            ),
        ] {
            connection
                .execute(
                    "INSERT INTO memory_record (
                        id, life_id, kind, status, content, summary, source_type, source_ref,
                        source_created_at, importance, confidence, is_sensitive, created_at,
                        updated_at, confirmed_at, revision
                     ) VALUES (?1, 'life-a', 'fact', 'candidate', ?2, 'Summary', ?3, 'source-ref',
                        '2026-07-13T09:00:00.000Z', 0.7, 0.8, 0,
                        '2026-07-13T10:00:00.000Z', '2026-07-13T11:00:00.000Z', NULL, 1)",
                    params![id, content, source_type],
                )
                .unwrap();
        }
        connection
            .execute(
                "INSERT INTO memory_record (
                    id, life_id, kind, status, content, summary, source_type, source_ref,
                    source_created_at, importance, confidence, is_sensitive, created_at,
                    updated_at, confirmed_at, revision
                 ) VALUES ('confirmed-old', 'life-a', 'fact', 'confirmed', 'Confirmed old', NULL,
                    'manual', NULL, '2026-07-13T00:00:00.000Z', 0.5, 0.8, 0,
                    '2026-07-13T00:00:00.000Z', '2026-07-13T00:00:00.000Z',
                    '2026-07-13T00:00:00.000Z', 1)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO memory_revision (
                    id, life_id, memory_id, revision, kind, content, summary, is_sensitive,
                    change_type, created_at
                 ) VALUES ('revision-old', 'life-a', 'confirmed-old', 1, 'fact', 'Confirmed old',
                    NULL, 0, 'confirmed', '2026-07-13T00:00:00.000Z')",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO memory_vector_sync_outbox (
                    life_id, memory_id, desired_action, state, created_at, updated_at
                 ) VALUES ('life-a', 'confirmed-old', 'upsert', 'pending',
                    '2026-07-13T00:00:00.000Z', '2026-07-13T00:00:00.000Z')",
                [],
            )
            .unwrap();
        drop(connection);
        data_root
    }

    #[test]
    fn empty_database_applies_all_migrations_through_008_with_foreign_keys_enabled() {
        let root = TestRoot::new("empty-migration");
        let service = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        let state = service.state().unwrap();
        let version: i64 = state
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        let foreign_keys: i64 = state
            .connection
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 8);
        assert_eq!(foreign_keys, 1);
        for table in [
            "candidate_memory",
            "candidate_memory_evidence",
            "candidate_memory_audit",
        ] {
            let exists: i64 = state
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(exists, 1);
        }
    }

    #[test]
    fn migration_007_to_008_moves_candidates_and_preserves_confirmed_revision_and_outbox() {
        let root = TestRoot::new("upgrade");
        let data_root = create_v7_database(&root);
        let service = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        let state = service.state().unwrap();
        let version: i64 = state
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 8);
        let old_candidate_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_record WHERE status = 'candidate'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let confirmed: String = state
            .connection
            .query_row(
                "SELECT content FROM memory_record WHERE id = 'confirmed-old'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let revision_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_revision WHERE id = 'revision-old'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let outbox_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_sync_outbox WHERE memory_id = 'confirmed-old'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_candidate_count, 0);
        assert_eq!(confirmed, "Confirmed old");
        assert_eq!(revision_count, 1);
        assert_eq!(outbox_count, 1);
        drop(state);
        let manual = <StorageService as CandidateMemoryRepository>::get_candidate(
            &service,
            "life-a",
            "candidate-manual",
        )
        .unwrap();
        assert_eq!(manual.subject_id, PRIMARY_USER_SUBJECT_ID);
        assert_eq!(manual.content.as_deref(), Some("Manual candidate"));
        assert_eq!(manual.summary.as_deref(), Some("Summary"));
        assert_eq!(manual.source_type, CandidateMemorySourceType::Manual);
        assert_eq!(manual.inference_status, CandidateInferenceStatus::Explicit);
        assert_eq!(manual.proposed_at, "2026-07-13T09:00:00.000Z");
        let conversation = <StorageService as CandidateMemoryRepository>::get_candidate(
            &service,
            "life-a",
            "candidate-conversation",
        )
        .unwrap();
        assert_eq!(
            conversation.source_type,
            CandidateMemorySourceType::Conversation
        );
        assert_eq!(
            conversation.inference_status,
            CandidateInferenceStatus::Extracted
        );
        drop(service);
        let reopened = StorageService::initialize_with_roots(data_root, None).unwrap();
        let migrated_count: i64 = reopened
            .state()
            .unwrap()
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_memory", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(migrated_count, 2);
    }

    #[test]
    fn migration_failure_rolls_back_candidate_move() {
        let root = TestRoot::new("migration-rollback");
        let data_root = create_v7_database(&root);
        let database = data_root.join(DATABASE_FILE_NAME);
        let mut connection = Connection::open(database).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .unwrap();
        connection
            .execute_batch("CREATE TABLE candidate_memory (id TEXT PRIMARY KEY);")
            .unwrap();
        let transaction = connection.transaction().unwrap();
        assert!(transaction
            .execute_batch(include_str!("migrations/008_candidate_memory_storage.sql"))
            .is_err());
        drop(transaction);
        let old_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM memory_record WHERE status = 'candidate'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let evidence_table_exists: i64 = connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'candidate_memory_evidence')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_count, 2);
        assert_eq!(evidence_table_exists, 0);
    }

    #[test]
    fn insert_get_filters_search_and_stable_cursor_are_life_scoped() {
        let root = TestRoot::new("list");
        let service = seeded_service(&root);
        let mut first = pending("a", "life-a", "2026-07-14T10:00:00.000Z");
        first.content = Some("literal % _ \\ query".into());
        first.source_type = CandidateMemorySourceType::Manual;
        first.inference_status = CandidateInferenceStatus::Explicit;
        first.is_sensitive = true;
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, first).unwrap();
        let mut second = pending("b", "life-a", "2026-07-14T10:00:00.000Z");
        second.kind = MemoryKind::Preference;
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, second).unwrap();
        let mut third = pending("c", "life-a", "2026-07-14T09:00:00.000Z");
        third.status = CandidateMemoryStatus::Rejected;
        third.content = None;
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, third).unwrap();
        insert_candidate(&service, "other", "life-b", "2026-07-14T11:00:00.000Z");

        let mut page = filter("life-a");
        page.page_size = Some(2);
        let (first_page, cursor) =
            <StorageService as CandidateMemoryRepository>::list_candidates(&service, page).unwrap();
        assert_eq!(
            first_page
                .iter()
                .map(|record| record.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        let mut next = filter("life-a");
        next.page_size = Some(2);
        next.cursor = cursor;
        let (second_page, next_cursor) =
            <StorageService as CandidateMemoryRepository>::list_candidates(&service, next).unwrap();
        assert_eq!(
            second_page
                .iter()
                .map(|record| record.id.as_str())
                .collect::<Vec<_>>(),
            ["c"]
        );
        assert!(next_cursor.is_none());

        let mut filtered = filter("life-a");
        filtered.is_sensitive = Some(true);
        filtered.source_type = Some(CandidateMemorySourceType::Manual);
        filtered.inference_status = Some(CandidateInferenceStatus::Explicit);
        filtered.query = Some("% _ \\".into());
        let (records, _) =
            <StorageService as CandidateMemoryRepository>::list_candidates(&service, filtered)
                .unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].id, "a");
        let mut pending_only = filter("life-a");
        pending_only.status = Some(CandidateMemoryStatus::Pending);
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::list_candidates(&service, pending_only)
                .unwrap()
                .0
                .iter()
                .map(|record| record.id.as_str())
                .collect::<Vec<_>>(),
            ["a", "b"]
        );
        let mut preference_only = filter("life-a");
        preference_only.kind = Some(MemoryKind::Preference);
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::list_candidates(
                &service,
                preference_only
            )
            .unwrap()
            .0
            .iter()
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>(),
            ["b"]
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(
                &service, "life-a", "other"
            )
            .unwrap_err()
            .code,
            "CANDIDATE_MEMORY_LIFE_MISMATCH"
        );
    }

    #[test]
    fn default_and_maximum_page_sizes_are_enforced_without_offsets() {
        let root = TestRoot::new("page-size");
        let service = seeded_service(&root);
        for index in 0..31 {
            insert_candidate(
                &service,
                &format!("candidate-{index:02}"),
                "life-a",
                &format!("2026-07-14T10:{index:02}:00.000Z"),
            );
        }
        let (default_page, default_cursor) =
            <StorageService as CandidateMemoryRepository>::list_candidates(
                &service,
                filter("life-a"),
            )
            .unwrap();
        assert_eq!(default_page.len(), 30);
        assert!(default_cursor.is_some());
        let mut maximum = filter("life-a");
        maximum.page_size = Some(100);
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::list_candidates(&service, maximum)
                .unwrap()
                .0
                .len(),
            31
        );
        let mut invalid = filter("life-a");
        invalid.page_size = Some(101);
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::list_candidates(&service, invalid)
                .unwrap_err()
                .code,
            "CANDIDATE_MEMORY_INVALID_QUERY"
        );
    }

    #[test]
    fn guarded_update_increments_revision_and_rejects_conflicts() {
        let root = TestRoot::new("revision");
        let service = seeded_service(&root);
        let created = insert_candidate(&service, "candidate", "life-a", "2026-07-14T10:00:00.000Z");
        let mut update = update_from(&created);
        update.content = Some("Updated content".into());
        let updated = <StorageService as CandidateMemoryRepository>::update_candidate_guarded(
            &service,
            "life-a",
            "candidate",
            1,
            update.clone(),
        )
        .unwrap();
        assert_eq!(updated.revision, 2);
        assert_eq!(updated.content.as_deref(), Some("Updated content"));
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::update_candidate_guarded(
                &service,
                "life-a",
                "candidate",
                1,
                update,
            )
            .unwrap_err()
            .code,
            "CANDIDATE_MEMORY_REVISION_CONFLICT"
        );
    }

    #[test]
    fn constraints_and_pending_deduplication_are_database_enforced() {
        let root = TestRoot::new("constraints");
        let service = seeded_service(&root);
        let mut first = pending("one", "life-a", "2026-07-14T10:00:00.000Z");
        first.dedup_fingerprint = Some("fingerprint".into());
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, first).unwrap();
        let mut duplicate = pending("two", "life-a", "2026-07-14T10:01:00.000Z");
        duplicate.dedup_fingerprint = Some("fingerprint".into());
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::insert_candidate(&service, duplicate)
                .unwrap_err()
                .code,
            "CANDIDATE_MEMORY_DUPLICATE"
        );
        let mut invalid_pending = pending("invalid", "life-a", "2026-07-14T10:02:00.000Z");
        invalid_pending.content = None;
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::insert_candidate(
                &service,
                invalid_pending
            )
            .unwrap_err()
            .code,
            "CANDIDATE_MEMORY_CONSTRAINT_VIOLATION"
        );
        let mut invalid_terminal = pending("terminal", "life-a", "2026-07-14T10:03:00.000Z");
        invalid_terminal.status = CandidateMemoryStatus::Rejected;
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::insert_candidate(
                &service,
                invalid_terminal
            )
            .unwrap_err()
            .code,
            "CANDIDATE_MEMORY_CONSTRAINT_VIOLATION"
        );
    }

    #[test]
    fn confirmed_memory_reference_rejects_cross_life_insert_and_update() {
        let root = TestRoot::new("confirmed-memory-life");
        let service = seeded_service(&root);
        insert_confirmed_memory(&service, "memory-a", "life-a");
        insert_confirmed_memory(&service, "memory-b", "life-b");

        let mut cross_life = pending("accepted", "life-a", "2026-07-14T10:00:00.000Z");
        cross_life.status = CandidateMemoryStatus::Accepted;
        cross_life.content = None;
        cross_life.confirmed_memory_id = Some("memory-b".into());
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::insert_candidate(&service, cross_life)
                .unwrap_err()
                .code,
            "CANDIDATE_MEMORY_CONSTRAINT_VIOLATION"
        );

        let mut valid = pending("valid-accepted", "life-a", "2026-07-14T10:01:00.000Z");
        valid.status = CandidateMemoryStatus::Accepted;
        valid.content = None;
        valid.confirmed_memory_id = Some("memory-a".into());
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, valid).unwrap();
        let state = service.state().unwrap();
        assert!(state
            .connection
            .execute(
                "UPDATE candidate_memory SET life_id = 'life-b' WHERE id = 'valid-accepted'",
                [],
            )
            .is_err());
    }

    #[test]
    fn conflicting_memory_reference_rejects_cross_life_insert_and_update() {
        let root = TestRoot::new("conflicting-memory-life");
        let service = seeded_service(&root);
        insert_confirmed_memory(&service, "memory-a", "life-a");
        insert_confirmed_memory(&service, "memory-b", "life-b");

        let mut cross_life = pending("cross-life", "life-a", "2026-07-14T10:00:00.000Z");
        cross_life.conflicts_with_memory_id = Some("memory-b".into());
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::insert_candidate(&service, cross_life)
                .unwrap_err()
                .code,
            "CANDIDATE_MEMORY_CONSTRAINT_VIOLATION"
        );

        let mut valid = pending("valid", "life-a", "2026-07-14T10:01:00.000Z");
        valid.conflicts_with_memory_id = Some("memory-a".into());
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, valid).unwrap();
        let state = service.state().unwrap();
        assert!(state
            .connection
            .execute(
                "UPDATE candidate_memory SET conflicts_with_memory_id = 'memory-b' WHERE id = 'valid'",
                [],
            )
            .is_err());
    }

    #[test]
    fn evidence_rejects_cross_life_insert_and_update_at_database_boundary() {
        let root = TestRoot::new("evidence-life-trigger");
        let service = seeded_service(&root);
        insert_candidate(
            &service,
            "candidate-a",
            "life-a",
            "2026-07-14T10:00:00.000Z",
        );
        let state = service.state().unwrap();
        assert!(state
            .connection
            .execute(
                "INSERT INTO candidate_memory_evidence (
                    id, candidate_id, life_id, source_type, observed_at
                 ) VALUES ('evidence-cross', 'candidate-a', 'life-b', 'manual', ?1)",
                params!["2026-07-14T10:00:00.000Z"],
            )
            .is_err());
        state
            .connection
            .execute(
                "INSERT INTO candidate_memory_evidence (
                    id, candidate_id, life_id, source_type, observed_at
                 ) VALUES ('evidence-valid', 'candidate-a', 'life-a', 'manual', ?1)",
                params!["2026-07-14T10:00:00.000Z"],
            )
            .unwrap();
        assert!(state
            .connection
            .execute(
                "UPDATE candidate_memory_evidence SET life_id = 'life-b'
                 WHERE id = 'evidence-valid'",
                [],
            )
            .is_err());
    }

    #[test]
    fn superseded_candidate_reference_rejects_cross_life_insert_and_update() {
        let root = TestRoot::new("superseded-life-trigger");
        let service = seeded_service(&root);
        insert_candidate(
            &service,
            "replacement-a",
            "life-a",
            "2026-07-14T10:00:00.000Z",
        );
        insert_candidate(
            &service,
            "replacement-b",
            "life-b",
            "2026-07-14T10:01:00.000Z",
        );

        let mut cross_life = pending("superseded-cross", "life-a", "2026-07-14T10:02:00.000Z");
        cross_life.status = CandidateMemoryStatus::Superseded;
        cross_life.content = None;
        cross_life.superseded_by_candidate_id = Some("replacement-b".into());
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::insert_candidate(&service, cross_life)
                .unwrap_err()
                .code,
            "CANDIDATE_MEMORY_CONSTRAINT_VIOLATION"
        );

        let mut valid = pending("superseded-valid", "life-a", "2026-07-14T10:03:00.000Z");
        valid.status = CandidateMemoryStatus::Superseded;
        valid.content = None;
        valid.superseded_by_candidate_id = Some("replacement-a".into());
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, valid).unwrap();
        let state = service.state().unwrap();
        assert!(state
            .connection
            .execute(
                "UPDATE candidate_memory SET superseded_by_candidate_id = 'replacement-b'
                 WHERE id = 'superseded-valid'",
                [],
            )
            .is_err());
    }

    #[test]
    fn confirmed_memory_deletion_cascades_accepted_candidate_only() {
        let root = TestRoot::new("confirmed-cascade");
        let service = seeded_service(&root);
        insert_confirmed_memory(&service, "confirmed", "life-a");
        let mut accepted = pending("accepted", "life-a", "2026-07-14T10:00:00.000Z");
        accepted.status = CandidateMemoryStatus::Accepted;
        accepted.content = None;
        accepted.confirmed_memory_id = Some("confirmed".into());
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, accepted)
            .unwrap();
        let state = service.state().unwrap();
        state
            .connection
            .execute("DELETE FROM memory_record WHERE id = 'confirmed'", [])
            .unwrap();
        let count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory WHERE id = 'accepted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn evidence_is_life_checked_and_cascades_from_candidate_conversation_and_message() {
        let root = TestRoot::new("evidence");
        let service = seeded_service(&root);
        insert_candidate(
            &service,
            "candidate-a",
            "life-a",
            "2026-07-14T10:00:00.000Z",
        );
        insert_conversation_with_message(&service, "life-a", "a");
        insert_conversation_with_message(&service, "life-b", "b");
        let evidence = NewCandidateMemoryEvidence {
            id: "evidence-a".into(),
            candidate_id: "candidate-a".into(),
            life_id: "life-a".into(),
            source_type: CandidateMemorySourceType::Conversation,
            source_id: Some("source".into()),
            conversation_id: Some("conversation-a".into()),
            message_id: Some("message-a".into()),
            observed_at: "2026-07-14T10:00:00.000Z".into(),
        };
        <StorageService as CandidateMemoryRepository>::insert_evidence(&service, evidence.clone())
            .unwrap();
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::list_evidence(
                &service,
                "life-a",
                "candidate-a",
            )
            .unwrap()
            .len(),
            1
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(
                &service,
                "life-a",
                "candidate-a"
            )
            .unwrap(),
            1
        );
        assert!(
            <StorageService as CandidateMemoryRepository>::delete_evidence(
                &service,
                "life-a",
                "evidence-a",
            )
            .unwrap()
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(
                &service,
                "life-a",
                "candidate-a"
            )
            .unwrap(),
            0
        );
        <StorageService as CandidateMemoryRepository>::insert_evidence(&service, evidence).unwrap();
        let invalid = NewCandidateMemoryEvidence {
            id: "evidence-invalid".into(),
            candidate_id: "candidate-a".into(),
            life_id: "life-a".into(),
            source_type: CandidateMemorySourceType::Conversation,
            source_id: None,
            conversation_id: Some("conversation-b".into()),
            message_id: None,
            observed_at: "2026-07-14T10:00:00.000Z".into(),
        };
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::insert_evidence(&service, invalid)
                .unwrap_err()
                .code,
            "CANDIDATE_MEMORY_CONSTRAINT_VIOLATION"
        );
        let state = service.state().unwrap();
        state
            .connection
            .execute(
                "DELETE FROM conversation_message WHERE id = 'message-a'",
                [],
            )
            .unwrap();
        let after_message_delete: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory_evidence",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(after_message_delete, 0);
        drop(state);
        let second = NewCandidateMemoryEvidence {
            id: "evidence-conversation".into(),
            candidate_id: "candidate-a".into(),
            life_id: "life-a".into(),
            source_type: CandidateMemorySourceType::Conversation,
            source_id: None,
            conversation_id: Some("conversation-a".into()),
            message_id: None,
            observed_at: "2026-07-14T10:01:00.000Z".into(),
        };
        <StorageService as CandidateMemoryRepository>::insert_evidence(&service, second).unwrap();
        let state = service.state().unwrap();
        state
            .connection
            .execute("DELETE FROM conversation WHERE id = 'conversation-a'", [])
            .unwrap();
        let after_conversation_delete: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory_evidence",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(after_conversation_delete, 0);
    }

    #[test]
    fn candidate_delete_cascades_evidence_but_preserves_audit_and_audit_can_purge() {
        let root = TestRoot::new("audit");
        let service = seeded_service(&root);
        insert_candidate(&service, "candidate", "life-a", "2026-07-14T10:00:00.000Z");
        let evidence = NewCandidateMemoryEvidence {
            id: "evidence".into(),
            candidate_id: "candidate".into(),
            life_id: "life-a".into(),
            source_type: CandidateMemorySourceType::Manual,
            source_id: None,
            conversation_id: None,
            message_id: None,
            observed_at: "2026-07-14T10:00:00.000Z".into(),
        };
        <StorageService as CandidateMemoryRepository>::insert_evidence(&service, evidence).unwrap();
        for (id, timestamp) in [
            ("audit-old", "2026-07-01T00:00:00.000Z"),
            ("audit-new", "2026-07-14T00:00:00.000Z"),
        ] {
            <StorageService as CandidateMemoryRepository>::append_audit(
                &service,
                NewCandidateMemoryAudit {
                    id: id.into(),
                    candidate_id: "candidate".into(),
                    life_id: "life-a".into(),
                    action: "deleted".into(),
                    actor_type: "user".into(),
                    request_id: None,
                    result_status: "success".into(),
                    created_at: timestamp.into(),
                },
            )
            .unwrap();
        }
        assert!(
            <StorageService as CandidateMemoryRepository>::delete_candidate_permanently(
                &service,
                "life-a",
                "candidate",
            )
            .unwrap()
        );
        let state = service.state().unwrap();
        let evidence_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory_evidence",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let audit_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_memory_audit", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(evidence_count, 0);
        assert_eq!(audit_count, 2);
        drop(state);
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::purge_audit_before(
                &service,
                "life-a",
                "2026-07-10T00:00:00.000Z",
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn life_deletion_cascades_candidate_evidence_and_audit() {
        let root = TestRoot::new("life-cascade");
        let service = seeded_service(&root);
        insert_candidate(&service, "candidate", "life-a", "2026-07-14T10:00:00.000Z");
        <StorageService as CandidateMemoryRepository>::insert_evidence(
            &service,
            NewCandidateMemoryEvidence {
                id: "evidence".into(),
                candidate_id: "candidate".into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Manual,
                source_id: None,
                conversation_id: None,
                message_id: None,
                observed_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        <StorageService as CandidateMemoryRepository>::append_audit(
            &service,
            NewCandidateMemoryAudit {
                id: "audit".into(),
                candidate_id: "candidate".into(),
                life_id: "life-a".into(),
                action: "created".into(),
                actor_type: "system".into(),
                request_id: None,
                result_status: "success".into(),
                created_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        let state = service.state().unwrap();
        state
            .connection
            .execute("DELETE FROM life_identity WHERE id = 'life-a'", [])
            .unwrap();
        for table in [
            "candidate_memory",
            "candidate_memory_evidence",
            "candidate_memory_audit",
        ] {
            let count: i64 = state
                .connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0);
        }
    }

    #[test]
    fn stored_candidate_columns_remain_complete_for_repository_reads() {
        let root = TestRoot::new("columns");
        let service = seeded_service(&root);
        insert_candidate(&service, "candidate", "life-a", "2026-07-14T10:00:00.000Z");
        let state = service.state().unwrap();
        let columns: i64 = state
            .connection
            .query_row(
                &format!("SELECT COUNT(*) FROM (SELECT {CANDIDATE_COLUMNS} FROM candidate_memory)"),
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(columns, 1);
    }
}
