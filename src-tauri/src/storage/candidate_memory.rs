use std::panic::{catch_unwind, AssertUnwindSafe};

use rusqlite::{
    params, Connection, Error as SqlError, ErrorCode, OptionalExtension, Row, Transaction,
    TransactionBehavior,
};

use crate::{
    candidate_memory_internal::fingerprint::{
        compute_dedup_fingerprint, compute_rejection_fingerprint,
    },
    memory::{
        candidate::{
            CandidateInferenceStatus, CandidateMemoryAuditRecord, CandidateMemoryCursor,
            CandidateMemoryError, CandidateMemoryEvidenceRecord, CandidateMemoryListFilter,
            CandidateMemoryRecord, CandidateMemoryRepository, CandidateMemorySourceType,
            CandidateMemoryStatus, CandidateMemoryStorageUpdate, NewCandidateMemory,
            NewCandidateMemoryAudit, NewCandidateMemoryEvidence, DEFAULT_CANDIDATE_PAGE_SIZE,
            MAX_CANDIDATE_PAGE_SIZE,
        },
        candidate_service::{
            contains_prohibited_content, AddEvidenceRequest,
            CandidateConfirmationRecoveryRepository, CandidateEditOutcome, CandidateEditResult,
            CandidateLifecycleRepository, CandidateLifecycleResult, ConfirmCandidateOutcome,
            ConfirmCandidateRequest, ConfirmCandidateResult, DeleteCandidateRequest,
            EditCandidateRequest, ExpiredCandidateScan, RejectCandidateRequest,
            SupersedeCandidateRequest,
        },
        vector_sync_outbox::MemoryVectorSyncAction,
        MemoryKind, MemoryRecord, MemoryStatus,
    },
};

use super::{
    memory::legacy_source, memory_revision::insert_confirmed_revision_in_transaction,
    vector_sync_outbox::enqueue_in_transaction, StorageService,
};

const CANDIDATE_COLUMNS: &str = "id, life_id, subject_id, kind, content, summary, source_type, \
    source_id, confidence, importance, is_sensitive, inference_status, status, revision, \
    dedup_fingerprint, proposed_at, expires_at, reviewed_at, last_user_edit_at, \
    confirmed_memory_id, accepted_request_id, rejection_reason_code, \
    superseded_by_candidate_id, conflicts_with_memory_id, created_at, updated_at";

const EVIDENCE_COLUMNS: &str = "id, candidate_id, life_id, source_type, source_id, \
    conversation_id, message_id, observed_at";

const AUDIT_COLUMNS: &str = "id, candidate_id, life_id, action, actor_type, request_id, \
    result_status, created_at";

/// Test-only D-4 failpoints. They are consumed by one StorageService instance
/// and compile out of production builds.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum D4PanicFailpoint {
    BeforeCommit,
    AfterCommit,
}

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
        let candidate_id = candidate.id.clone();
        let life_id = candidate.life_id.clone();
        let state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        insert_candidate_with_connection(&state.connection, &candidate)?;

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

/// The sole D-3 Candidate INSERT primitive used by both ordinary candidate
/// creation and the D-6 extraction transaction.
#[allow(dead_code)]
pub(super) fn insert_candidate_in_transaction(
    transaction: &Transaction<'_>,
    candidate: &NewCandidateMemory,
) -> Result<(), CandidateMemoryError> {
    insert_candidate_with_connection(transaction, candidate)
}

pub(super) fn insert_extraction_audit_in_transaction(
    transaction: &Transaction<'_>,
    audit_id: &str,
    life_id: &str,
    candidate_id: &str,
    now: &str,
) -> Result<(), CandidateMemoryError> {
    insert_audit(
        transaction,
        audit_id,
        life_id,
        candidate_id,
        "extracted",
        "system",
        now,
    )?;
    Ok(())
}

fn insert_candidate_with_connection(
    connection: &Connection,
    candidate: &NewCandidateMemory,
) -> Result<(), CandidateMemoryError> {
    validate_candidate_insert(candidate)?;
    connection
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
                normalize_optional(candidate.content.clone()),
                normalize_optional(candidate.summary.clone()),
                candidate.source_type.as_str(),
                normalize_optional(candidate.source_id.clone()),
                candidate.confidence,
                candidate.importance,
                candidate.is_sensitive,
                candidate.inference_status.as_str(),
                candidate.status.as_str(),
                normalize_optional(candidate.dedup_fingerprint.clone()),
                candidate.proposed_at,
                normalize_optional(candidate.expires_at.clone()),
                normalize_optional(candidate.reviewed_at.clone()),
                normalize_optional(candidate.last_user_edit_at.clone()),
                normalize_optional(candidate.confirmed_memory_id.clone()),
                normalize_optional(candidate.accepted_request_id.clone()),
                normalize_optional(candidate.rejection_reason_code.clone()),
                normalize_optional(candidate.superseded_by_candidate_id.clone()),
                normalize_optional(candidate.conflicts_with_memory_id.clone()),
                candidate.created_at,
                candidate.updated_at,
            ],
        )
        .map_err(map_sql_error)?;
    Ok(())
}

impl CandidateLifecycleRepository for StorageService {
    fn edit_candidate_atomic(
        &self,
        life_id: &str,
        request: EditCandidateRequest,
        now: &str,
        audit_id: &str,
    ) -> Result<CandidateEditResult, CandidateMemoryError> {
        validate_identifier(life_id)?;
        validate_identifier(&request.candidate_id)?;
        validate_identifier(now)?;
        validate_identifier(audit_id)?;
        let mut state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql_error)?;
        let candidate = load_owned_candidate(&transaction, life_id, &request.candidate_id)?;
        ensure_pending_revision(&candidate, request.expected_revision)?;
        if contains_prohibited_content(&request.content)
            || request
                .summary
                .as_deref()
                .is_some_and(contains_prohibited_content)
        {
            return Err(prohibited_content_error());
        }
        let content_changed = candidate.content.as_deref() != Some(request.content.as_str());
        let summary_changed = candidate.summary != request.summary;
        let kind_changed = candidate.kind != request.kind;
        if !content_changed && !summary_changed && !kind_changed {
            return Ok(CandidateEditResult {
                outcome: CandidateEditOutcome::NoChange,
                candidate,
            });
        }
        let fingerprint = compute_dedup_fingerprint(
            life_id,
            &candidate.subject_id,
            request.kind,
            &request.content,
        );
        let changed = transaction
            .execute(
                "UPDATE candidate_memory SET
                    kind = ?4, content = ?5, summary = ?6, dedup_fingerprint = ?7,
                    last_user_edit_at = ?8, updated_at = ?8, revision = revision + 1
                 WHERE id = ?1 AND life_id = ?2 AND revision = ?3 AND status = 'pending'",
                params![
                    request.candidate_id,
                    life_id,
                    request.expected_revision,
                    request.kind.as_str(),
                    request.content,
                    request.summary,
                    fingerprint,
                    now,
                ],
            )
            .map_err(map_sql_error)?;
        if changed != 1 {
            return Err(CandidateMemoryError::revision_conflict());
        }
        insert_audit(
            &transaction,
            audit_id,
            life_id,
            &request.candidate_id,
            "candidate_edited",
            "user",
            now,
        )?;
        let updated = load_owned_candidate(&transaction, life_id, &request.candidate_id)?;
        transaction.commit().map_err(map_sql_error)?;
        Ok(CandidateEditResult {
            outcome: CandidateEditOutcome::Changed,
            candidate: updated,
        })
    }

    fn reject_candidate_atomic(
        &self,
        life_id: &str,
        request: RejectCandidateRequest,
        now: &str,
        audit_id: &str,
    ) -> Result<CandidateLifecycleResult, CandidateMemoryError> {
        validate_atomic_identifiers(life_id, &request.candidate_id, now, audit_id)?;
        let mut state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql_error)?;
        let candidate = load_owned_candidate(&transaction, life_id, &request.candidate_id)?;
        ensure_pending_revision(&candidate, request.expected_revision)?;
        let suppression_fingerprint = compute_rejection_fingerprint(
            life_id,
            &candidate.subject_id,
            candidate.kind,
            candidate.content.as_deref().unwrap_or_default(),
        );
        let changed = transaction
            .execute(
                "UPDATE candidate_memory SET
                    status = 'rejected', content = NULL, summary = NULL, source_id = NULL,
                    dedup_fingerprint = ?4, reviewed_at = ?5, rejection_reason_code = ?6,
                    updated_at = ?5, revision = revision + 1
                 WHERE id = ?1 AND life_id = ?2 AND revision = ?3 AND status = 'pending'",
                params![
                    request.candidate_id,
                    life_id,
                    request.expected_revision,
                    suppression_fingerprint,
                    now,
                    request.reason.as_str(),
                ],
            )
            .map_err(map_sql_error)?;
        if changed != 1 {
            return Err(CandidateMemoryError::revision_conflict());
        }
        delete_candidate_evidence(&transaction, life_id, &request.candidate_id)?;
        let audit = insert_audit(
            &transaction,
            audit_id,
            life_id,
            &request.candidate_id,
            "candidate_rejected",
            "user",
            now,
        )?;
        let updated = load_owned_candidate(&transaction, life_id, &request.candidate_id)?;
        transaction.commit().map_err(map_sql_error)?;
        Ok(CandidateLifecycleResult {
            candidate: updated,
            audit,
        })
    }

    fn scan_expired_candidates(
        &self,
        life_id: &str,
        now: &str,
        limit: usize,
    ) -> Result<Vec<ExpiredCandidateScan>, CandidateMemoryError> {
        validate_identifier(life_id)?;
        validate_identifier(now)?;
        if limit == 0 || limit > 500 {
            return Err(CandidateMemoryError::invalid_query());
        }
        let state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        ensure_life_exists(&state.connection, life_id)?;
        let mut statement = state
            .connection
            .prepare(
                "SELECT id, revision FROM candidate_memory
                 WHERE life_id = ?1 AND status = 'pending'
                   AND expires_at IS NOT NULL AND expires_at <= ?2
                 ORDER BY expires_at ASC, id ASC LIMIT ?3",
            )
            .map_err(map_sql_error)?;
        let rows = statement
            .query_map(params![life_id, now, limit as i64], |row| {
                Ok(ExpiredCandidateScan {
                    candidate_id: row.get(0)?,
                    revision: row.get(1)?,
                })
            })
            .map_err(map_sql_error)?;
        rows.map(|row| row.map_err(map_sql_error)).collect()
    }

    fn expire_candidate_atomic(
        &self,
        life_id: &str,
        candidate_id: &str,
        scanned_expected_revision: i64,
        now: &str,
        audit_id: &str,
    ) -> Result<Option<CandidateLifecycleResult>, CandidateMemoryError> {
        validate_atomic_identifiers(life_id, candidate_id, now, audit_id)?;
        if scanned_expected_revision <= 0 {
            return Err(CandidateMemoryError::constraint());
        }
        let mut state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql_error)?;
        load_owned_candidate(&transaction, life_id, candidate_id)?;
        let changed = transaction
            .execute(
                "UPDATE candidate_memory SET
                    status = 'expired', content = NULL, summary = NULL, source_id = NULL,
                    dedup_fingerprint = NULL, reviewed_at = ?4, updated_at = ?4,
                    revision = revision + 1
                 WHERE id = ?1 AND life_id = ?2 AND revision = ?3
                   AND status = 'pending' AND expires_at IS NOT NULL AND expires_at <= ?4",
                params![candidate_id, life_id, scanned_expected_revision, now],
            )
            .map_err(map_sql_error)?;
        if changed == 0 {
            return Ok(None);
        }
        delete_candidate_evidence(&transaction, life_id, candidate_id)?;
        let audit = insert_audit(
            &transaction,
            audit_id,
            life_id,
            candidate_id,
            "candidate_expired",
            "system",
            now,
        )?;
        let updated = load_owned_candidate(&transaction, life_id, candidate_id)?;
        transaction.commit().map_err(map_sql_error)?;
        Ok(Some(CandidateLifecycleResult {
            candidate: updated,
            audit,
        }))
    }

    fn supersede_candidate_atomic(
        &self,
        life_id: &str,
        request: SupersedeCandidateRequest,
        now: &str,
        audit_id: &str,
    ) -> Result<CandidateLifecycleResult, CandidateMemoryError> {
        validate_atomic_identifiers(life_id, &request.candidate_id, now, audit_id)?;
        validate_identifier(&request.replacement_candidate_id)?;
        if request.candidate_id == request.replacement_candidate_id {
            return Err(CandidateMemoryError::constraint());
        }
        let mut state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql_error)?;
        let candidate = load_owned_candidate(&transaction, life_id, &request.candidate_id)?;
        ensure_pending_revision(&candidate, request.expected_revision)?;
        let replacement =
            load_owned_candidate(&transaction, life_id, &request.replacement_candidate_id)?;
        if replacement.status != CandidateMemoryStatus::Pending {
            return Err(CandidateMemoryError::invalid_status());
        }
        let changed = transaction
            .execute(
                "UPDATE candidate_memory SET
                    status = 'superseded', superseded_by_candidate_id = ?4,
                    content = NULL, summary = NULL, source_id = NULL,
                    dedup_fingerprint = NULL, reviewed_at = ?5, updated_at = ?5,
                    revision = revision + 1
                 WHERE id = ?1 AND life_id = ?2 AND revision = ?3 AND status = 'pending'",
                params![
                    request.candidate_id,
                    life_id,
                    request.expected_revision,
                    request.replacement_candidate_id,
                    now,
                ],
            )
            .map_err(map_sql_error)?;
        if changed != 1 {
            return Err(CandidateMemoryError::revision_conflict());
        }
        delete_candidate_evidence(&transaction, life_id, &request.candidate_id)?;
        let audit = insert_audit(
            &transaction,
            audit_id,
            life_id,
            &request.candidate_id,
            "candidate_superseded",
            "user",
            now,
        )?;
        let updated = load_owned_candidate(&transaction, life_id, &request.candidate_id)?;
        transaction.commit().map_err(map_sql_error)?;
        Ok(CandidateLifecycleResult {
            candidate: updated,
            audit,
        })
    }

    fn delete_candidate_atomic(
        &self,
        life_id: &str,
        request: DeleteCandidateRequest,
        now: &str,
        audit_id: &str,
    ) -> Result<CandidateMemoryAuditRecord, CandidateMemoryError> {
        validate_atomic_identifiers(life_id, &request.candidate_id, now, audit_id)?;
        let mut state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql_error)?;
        let candidate = load_owned_candidate(&transaction, life_id, &request.candidate_id)?;
        if candidate.revision != request.expected_revision {
            return Err(CandidateMemoryError::revision_conflict());
        }
        let audit = insert_audit(
            &transaction,
            audit_id,
            life_id,
            &request.candidate_id,
            "candidate_deleted",
            "user",
            now,
        )?;
        let deleted = transaction
            .execute(
                "DELETE FROM candidate_memory
                 WHERE id = ?1 AND life_id = ?2 AND revision = ?3",
                params![request.candidate_id, life_id, request.expected_revision],
            )
            .map_err(map_sql_error)?;
        if deleted != 1 {
            return Err(CandidateMemoryError::revision_conflict());
        }
        transaction.commit().map_err(map_sql_error)?;
        Ok(audit)
    }

    fn add_evidence_atomic(
        &self,
        life_id: &str,
        request: AddEvidenceRequest,
        now: &str,
        evidence_id: &str,
        audit_id: &str,
    ) -> Result<Option<CandidateMemoryRecord>, CandidateMemoryError> {
        validate_atomic_identifiers(life_id, &request.candidate_id, now, audit_id)?;
        validate_identifier(evidence_id)?;
        let mut state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql_error)?;
        let candidate = load_owned_candidate(&transaction, life_id, &request.candidate_id)?;
        if candidate.status != CandidateMemoryStatus::Pending {
            return Err(CandidateMemoryError::invalid_status());
        }
        let evidence = NewCandidateMemoryEvidence {
            id: evidence_id.to_string(),
            candidate_id: request.candidate_id.clone(),
            life_id: life_id.to_string(),
            source_type: request.source_type,
            source_id: normalize_optional(request.source_id),
            conversation_id: normalize_optional(request.conversation_id),
            message_id: normalize_optional(request.message_id),
            observed_at: now.to_string(),
        };
        validate_evidence(&evidence)?;
        validate_evidence_references(&transaction, &evidence)?;
        let duplicate: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM candidate_memory_evidence
                    WHERE candidate_id = ?1 AND source_type = ?2
                      AND source_id IS ?3 AND conversation_id IS ?4 AND message_id IS ?5
                 )",
                params![
                    evidence.candidate_id,
                    evidence.source_type.as_str(),
                    evidence.source_id,
                    evidence.conversation_id,
                    evidence.message_id,
                ],
                |row| row.get(0),
            )
            .map_err(map_sql_error)?;
        if duplicate {
            return Ok(None);
        }
        let inserted = transaction
            .execute(
                "INSERT INTO candidate_memory_evidence (
                    id, candidate_id, life_id, source_type, source_id, conversation_id,
                    message_id, observed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
                 ON CONFLICT DO NOTHING",
                params![
                    evidence.id,
                    evidence.candidate_id,
                    evidence.life_id,
                    evidence.source_type.as_str(),
                    evidence.source_id,
                    evidence.conversation_id,
                    evidence.message_id,
                    evidence.observed_at,
                ],
            )
            .map_err(map_sql_error)?;
        if inserted == 0 {
            return Ok(None);
        }
        let updated = transaction
            .execute(
                "UPDATE candidate_memory SET updated_at = ?4, revision = revision + 1
                 WHERE id = ?1 AND life_id = ?2 AND revision = ?3 AND status = 'pending'",
                params![request.candidate_id, life_id, candidate.revision, now],
            )
            .map_err(map_sql_error)?;
        if updated != 1 {
            return Err(CandidateMemoryError::revision_conflict());
        }
        insert_audit(
            &transaction,
            audit_id,
            life_id,
            &request.candidate_id,
            "candidate_evidence_added",
            "system",
            now,
        )?;
        let updated = load_owned_candidate(&transaction, life_id, &request.candidate_id)?;
        transaction.commit().map_err(map_sql_error)?;
        Ok(Some(updated))
    }

    fn confirm_candidate_atomic(
        &self,
        life_id: &str,
        request: ConfirmCandidateRequest,
        now: &str,
        memory_id: &str,
        audit_id: &str,
    ) -> Result<ConfirmCandidateResult, CandidateMemoryError> {
        validate_atomic_identifiers(life_id, &request.candidate_id, now, audit_id)?;
        validate_identifier(memory_id)?;
        validate_identifier(&request.request_id)?;
        if request.expected_revision <= 0 {
            return Err(CandidateMemoryError::constraint());
        }
        #[cfg(test)]
        self.record_candidate_confirmation_d4_call_for_test(&request.request_id, memory_id);
        #[cfg(test)]
        let failpoint = self.take_candidate_confirmation_panic_failpoint_for_test();
        let mut state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        // This is deliberately the narrowest panic boundary: `state` owns the
        // StorageService MutexGuard and stays outside the unwind. Therefore a
        // panic from the D-4 transaction rolls the transaction back while the
        // guard is still held, then the guard drops normally without poisoning
        // StorageService. AssertUnwindSafe covers only these local transaction
        // inputs; it never wraps the coordinator or a repository object.
        let result = catch_unwind(AssertUnwindSafe(|| {
            let transaction = state
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(map_sql_error)?;
            let candidate = load_owned_candidate(&transaction, life_id, &request.candidate_id)?;

            // Idempotent replay: an already-accepted candidate whose acceptance was
            // recorded under this same request id returns its prior confirmed memory.
            if candidate.status == CandidateMemoryStatus::Accepted {
                if candidate.accepted_request_id.as_deref() != Some(request.request_id.as_str()) {
                    // A distinct request id targeting an already-accepted candidate is a
                    // request-scoped conflict, not merely a wrong-status operation.
                    return Err(CandidateMemoryError::request_conflict());
                }
                let confirmed_memory_id = candidate
                    .confirmed_memory_id
                    .clone()
                    .ok_or_else(CandidateMemoryError::invalid_status)?;
                let memory = load_confirmed_memory(&transaction, life_id, &confirmed_memory_id)?;
                transaction.commit().map_err(map_sql_error)?;
                return Ok(ConfirmCandidateResult {
                    outcome: ConfirmCandidateOutcome::AlreadyConfirmed,
                    candidate,
                    memory,
                    audit: None,
                });
            }

            ensure_pending_revision(&candidate, request.expected_revision)?;
            if candidate.is_sensitive
                && request
                    .sensitive_grant
                    .as_ref()
                    .is_none_or(|grant| grant.candidate_id() != request.candidate_id)
            {
                return Err(CandidateMemoryError::sensitive_consent_required());
            }
            let content = candidate
                .content
                .clone()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(CandidateMemoryError::invalid_status)?;

            // Re-run the deterministic prohibited-content gate inside the transaction on
            // the freshly re-read candidate, so nothing credential-like is promoted into
            // authoritative memory even if it slipped past an earlier check.
            if contains_prohibited_content(&content)
                || candidate
                    .summary
                    .as_deref()
                    .is_some_and(contains_prohibited_content)
            {
                return Err(prohibited_content_error());
            }

            let memory = build_confirmed_memory(&candidate, memory_id, &content, now);
            insert_confirmed_memory(&transaction, &memory)?;
            insert_confirmed_revision_in_transaction(&transaction, &memory)
                .map_err(|_| CandidateMemoryError::storage_unavailable())?;
            let action = if memory.is_sensitive {
                MemoryVectorSyncAction::Delete
            } else {
                MemoryVectorSyncAction::Upsert
            };
            enqueue_in_transaction(&transaction, life_id, memory_id, action)
                .map_err(|_| CandidateMemoryError::storage_unavailable())?;

            let changed = transaction
                .execute(
                    "UPDATE candidate_memory SET
                    status = 'accepted', content = NULL, summary = NULL, source_id = NULL,
                    dedup_fingerprint = NULL, reviewed_at = ?4, updated_at = ?4,
                    confirmed_memory_id = ?5, accepted_request_id = ?6,
                    revision = revision + 1
                 WHERE id = ?1 AND life_id = ?2 AND revision = ?3 AND status = 'pending'",
                    params![
                        request.candidate_id,
                        life_id,
                        request.expected_revision,
                        now,
                        memory_id,
                        request.request_id,
                    ],
                )
                .map_err(confirm_update_error)?;
            if changed != 1 {
                return Err(CandidateMemoryError::revision_conflict());
            }
            delete_candidate_evidence(&transaction, life_id, &request.candidate_id)?;
            let audit = insert_audit_with_request_id(
                &transaction,
                audit_id,
                life_id,
                &request.candidate_id,
                "candidate_confirmed",
                "user",
                Some(&request.request_id),
                now,
            )?;
            let updated = load_owned_candidate(&transaction, life_id, &request.candidate_id)?;
            #[cfg(test)]
            if failpoint == Some(D4PanicFailpoint::BeforeCommit) {
                panic!("test-only D-4 panic before commit");
            }
            transaction.commit().map_err(map_sql_error)?;
            #[cfg(test)]
            if failpoint == Some(D4PanicFailpoint::AfterCommit) {
                panic!("test-only D-4 panic after commit");
            }
            Ok(ConfirmCandidateResult {
                outcome: ConfirmCandidateOutcome::Confirmed,
                candidate: updated,
                memory,
                audit: Some(audit),
            })
        }));
        match result {
            Ok(result) => result,
            Err(_) => Err(CandidateMemoryError::confirmation_panic_recovered()),
        }
    }
}

impl CandidateConfirmationRecoveryRepository for StorageService {
    fn confirmed_memory_for_request(
        &self,
        life_id: &str,
        candidate_id: &str,
        request_id: &str,
    ) -> Result<Option<String>, CandidateMemoryError> {
        validate_identifier(life_id)?;
        validate_identifier(candidate_id)?;
        validate_identifier(request_id)?;
        #[cfg(test)]
        self.candidate_confirmation_recovery_reads
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let state = self
            .state()
            .map_err(|_| CandidateMemoryError::storage_unavailable())?;
        state
            .connection
            .query_row(
                "SELECT memory.id
                 FROM candidate_memory AS candidate
                 INNER JOIN memory_record AS memory
                    ON memory.id = candidate.confirmed_memory_id
                   AND memory.life_id = candidate.life_id
                   AND memory.status = 'confirmed'
                 WHERE candidate.life_id = ?1
                   AND candidate.id = ?2
                   AND candidate.status = 'accepted'
                   AND candidate.accepted_request_id = ?3",
                params![life_id, candidate_id, request_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_sql_error)
    }
}

impl StorageService {
    #[cfg(test)]
    fn record_candidate_confirmation_d4_call_for_test(&self, request_id: &str, memory_id: &str) {
        self.candidate_confirmation_d4_calls
            .lock()
            .expect("test D-4 call trace mutex must be available")
            .push((request_id.to_string(), memory_id.to_string()));
    }

    #[cfg(test)]
    pub(crate) fn candidate_confirmation_d4_calls_for_test(&self) -> Vec<(String, String)> {
        self.candidate_confirmation_d4_calls
            .lock()
            .expect("test D-4 call trace mutex must be available")
            .clone()
    }

    #[cfg(test)]
    pub(crate) fn candidate_confirmation_recovery_reads_for_test(&self) -> u64 {
        self.candidate_confirmation_recovery_reads
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn request_candidate_confirmation_pre_commit_panic_for_test(&self) {
        *self
            .candidate_confirmation_panic_failpoint
            .lock()
            .expect("test failpoint mutex must be available") =
            Some(D4PanicFailpoint::BeforeCommit);
    }

    #[cfg(test)]
    pub(crate) fn request_candidate_confirmation_post_commit_panic_for_test(&self) {
        *self
            .candidate_confirmation_panic_failpoint
            .lock()
            .expect("test failpoint mutex must be available") = Some(D4PanicFailpoint::AfterCommit);
    }

    #[cfg(test)]
    fn take_candidate_confirmation_panic_failpoint_for_test(&self) -> Option<D4PanicFailpoint> {
        self.candidate_confirmation_panic_failpoint
            .lock()
            .expect("test failpoint mutex must be available")
            .take()
    }
}

fn build_confirmed_memory(
    candidate: &CandidateMemoryRecord,
    memory_id: &str,
    content: &str,
    now: &str,
) -> MemoryRecord {
    MemoryRecord {
        id: memory_id.to_string(),
        life_id: candidate.life_id.clone(),
        kind: candidate.kind,
        status: MemoryStatus::Confirmed,
        content: content.to_string(),
        summary: candidate.summary.clone(),
        source_type: legacy_source(candidate.source_type),
        source_ref: candidate.source_id.clone(),
        source_created_at: candidate.proposed_at.clone(),
        importance: candidate.importance,
        confidence: candidate.confidence,
        is_sensitive: candidate.is_sensitive,
        created_at: now.to_string(),
        updated_at: now.to_string(),
        confirmed_at: Some(now.to_string()),
    }
}

fn insert_confirmed_memory(
    transaction: &Transaction<'_>,
    memory: &MemoryRecord,
) -> Result<(), CandidateMemoryError> {
    let inserted = transaction
        .execute(
            "INSERT INTO memory_record (
                id, life_id, kind, status, content, summary, source_type, source_ref,
                source_created_at, importance, confidence, is_sensitive, created_at,
                updated_at, confirmed_at, revision
             ) VALUES (
                ?1, ?2, ?3, 'confirmed', ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12, ?12, 1
             )",
            params![
                memory.id,
                memory.life_id,
                memory.kind.as_str(),
                memory.content,
                memory.summary,
                memory.source_type.as_str(),
                memory.source_ref,
                memory.source_created_at,
                memory.importance,
                memory.confidence,
                memory.is_sensitive,
                memory.created_at,
            ],
        )
        .map_err(map_sql_error)?;
    if inserted != 1 {
        return Err(CandidateMemoryError::storage_unavailable());
    }
    Ok(())
}

fn load_confirmed_memory(
    connection: &Connection,
    life_id: &str,
    memory_id: &str,
) -> Result<MemoryRecord, CandidateMemoryError> {
    super::memory::load_owned_memory(connection, life_id, memory_id)
        .map_err(|_| CandidateMemoryError::storage_unavailable())
}

/// Maps the accepted-request-id uniqueness violation onto a stable domain error
/// so a request id reused across candidates does not surface as a generic
/// constraint failure.
fn confirm_update_error(error: SqlError) -> CandidateMemoryError {
    if let SqlError::SqliteFailure(code, message) = &error {
        if code.code == ErrorCode::ConstraintViolation
            && message
                .as_deref()
                .is_some_and(|message| message.contains("candidate_memory.accepted_request_id"))
        {
            return CandidateMemoryError::request_conflict();
        }
    }
    map_sql_error(error)
}

fn ensure_pending_revision(
    candidate: &CandidateMemoryRecord,
    expected_revision: i64,
) -> Result<(), CandidateMemoryError> {
    if candidate.status != CandidateMemoryStatus::Pending {
        return Err(CandidateMemoryError::invalid_status());
    }
    if candidate.revision != expected_revision {
        return Err(CandidateMemoryError::revision_conflict());
    }
    Ok(())
}

fn validate_atomic_identifiers(
    life_id: &str,
    candidate_id: &str,
    now: &str,
    audit_id: &str,
) -> Result<(), CandidateMemoryError> {
    validate_identifier(life_id)?;
    validate_identifier(candidate_id)?;
    validate_identifier(now)?;
    validate_identifier(audit_id)
}

fn prohibited_content_error() -> CandidateMemoryError {
    CandidateMemoryError::new(
        "CANDIDATE_MEMORY_PROHIBITED_CONTENT",
        "The candidate contains credential-like content that cannot be stored.",
        true,
    )
}

fn delete_candidate_evidence(
    transaction: &Transaction<'_>,
    life_id: &str,
    candidate_id: &str,
) -> Result<(), CandidateMemoryError> {
    transaction
        .execute(
            "DELETE FROM candidate_memory_evidence
             WHERE candidate_id = ?1 AND life_id = ?2",
            params![candidate_id, life_id],
        )
        .map_err(map_sql_error)?;
    Ok(())
}

fn insert_audit(
    transaction: &Transaction<'_>,
    audit_id: &str,
    life_id: &str,
    candidate_id: &str,
    action: &str,
    actor_type: &str,
    now: &str,
) -> Result<CandidateMemoryAuditRecord, CandidateMemoryError> {
    insert_audit_with_request_id(
        transaction,
        audit_id,
        life_id,
        candidate_id,
        action,
        actor_type,
        None,
        now,
    )
}

#[allow(clippy::too_many_arguments)]
fn insert_audit_with_request_id(
    transaction: &Transaction<'_>,
    audit_id: &str,
    life_id: &str,
    candidate_id: &str,
    action: &str,
    actor_type: &str,
    request_id: Option<&str>,
    now: &str,
) -> Result<CandidateMemoryAuditRecord, CandidateMemoryError> {
    transaction
        .execute(
            "INSERT INTO candidate_memory_audit (
                id, candidate_id, life_id, action, actor_type, request_id,
                result_status, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'success', ?7)",
            params![
                audit_id,
                candidate_id,
                life_id,
                action,
                actor_type,
                request_id,
                now
            ],
        )
        .map_err(map_sql_error)?;
    load_audit(transaction, life_id, audit_id)
}

#[derive(Clone)]
pub(super) struct SourceAffectedCandidate {
    candidate_id: String,
    revision: i64,
    source_type: CandidateMemorySourceType,
    status: CandidateMemoryStatus,
}

pub(super) fn collect_candidates_for_conversation(
    transaction: &Transaction<'_>,
    life_id: &str,
    conversation_id: &str,
) -> Result<Vec<SourceAffectedCandidate>, CandidateMemoryError> {
    collect_source_candidates(
        transaction,
        life_id,
        "e.conversation_id = ?2 OR e.message_id IN (
            SELECT id FROM conversation_message
            WHERE conversation_id = ?2 AND life_id = ?1
         )",
        conversation_id,
    )
}

/// Internal source-governance helper paired with the future message deletion API.
#[allow(dead_code)]
pub(super) fn collect_candidates_for_message(
    transaction: &Transaction<'_>,
    life_id: &str,
    message_id: &str,
) -> Result<Vec<SourceAffectedCandidate>, CandidateMemoryError> {
    collect_source_candidates(transaction, life_id, "e.message_id = ?2", message_id)
}

fn collect_source_candidates(
    transaction: &Transaction<'_>,
    life_id: &str,
    predicate: &str,
    source_id: &str,
) -> Result<Vec<SourceAffectedCandidate>, CandidateMemoryError> {
    let sql = format!(
        "SELECT DISTINCT c.id, c.revision, c.source_type, c.status
         FROM candidate_memory c
         JOIN candidate_memory_evidence e ON e.candidate_id = c.id AND e.life_id = c.life_id
         WHERE c.life_id = ?1 AND ({predicate})
         ORDER BY c.id ASC"
    );
    let mut statement = transaction.prepare(&sql).map_err(map_sql_error)?;
    let rows = statement
        .query_map(params![life_id, source_id], |row| {
            let source_type: String = row.get(2)?;
            let status: String = row.get(3)?;
            Ok((row.get(0)?, row.get(1)?, source_type, status))
        })
        .map_err(map_sql_error)?;
    rows.map(|row| {
        let (candidate_id, revision, source_type, status) = row.map_err(map_sql_error)?;
        Ok(SourceAffectedCandidate {
            candidate_id,
            revision,
            source_type: CandidateMemorySourceType::parse(&source_type)?,
            status: CandidateMemoryStatus::parse(&status)?,
        })
    })
    .collect()
}

pub(super) fn delete_orphaned_source_candidates(
    transaction: &Transaction<'_>,
    life_id: &str,
    affected: &[SourceAffectedCandidate],
) -> Result<usize, CandidateMemoryError> {
    let mut deleted = 0;
    for candidate in affected {
        if candidate.status != CandidateMemoryStatus::Pending
            || candidate.source_type != CandidateMemorySourceType::Conversation
        {
            continue;
        }
        let remaining: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory_evidence
                 WHERE candidate_id = ?1 AND life_id = ?2",
                params![candidate.candidate_id, life_id],
                |row| row.get(0),
            )
            .map_err(map_sql_error)?;
        if remaining != 0 {
            continue;
        }
        let audit_id = format!("audit-source-delete-{}", super::unique_suffix());
        insert_audit(
            transaction,
            &audit_id,
            life_id,
            &candidate.candidate_id,
            "candidate_orphaned_source_deleted",
            "system",
            &current_database_timestamp(transaction)?,
        )?;
        let changed = transaction
            .execute(
                "DELETE FROM candidate_memory
                 WHERE id = ?1 AND life_id = ?2 AND revision = ?3 AND status = 'pending'",
                params![candidate.candidate_id, life_id, candidate.revision],
            )
            .map_err(map_sql_error)?;
        if changed != 1 {
            return Err(CandidateMemoryError::revision_conflict());
        }
        deleted += 1;
    }
    Ok(deleted)
}

fn current_database_timestamp(
    transaction: &Transaction<'_>,
) -> Result<String, CandidateMemoryError> {
    transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(map_sql_error)
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
                    || message.contains("idx_candidate_memory_evidence_identity")
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
#[allow(deprecated)]
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::{Arc, Barrier},
        thread,
    };

    use rusqlite::{params, Connection};

    use crate::{
        conversation::history::ConversationRepository,
        memory::{
            candidate::{
                CandidateInferenceStatus, CandidateMemoryListFilter, CandidateMemoryRepository,
                CandidateMemorySourceType, CandidateMemoryStatus, CandidateMemoryStorageUpdate,
                NewCandidateMemory, NewCandidateMemoryAudit, NewCandidateMemoryEvidence,
                PRIMARY_USER_SUBJECT_ID,
            },
            candidate_service::{
                AddEvidenceRequest, CandidateMemoryService, ConfirmCandidateOutcome,
                ConfirmCandidateRequest, DeleteCandidateRequest, EditCandidateRequest,
                RejectCandidateRequest, RejectionReason, SensitiveConfirmationGrant,
                SupersedeCandidateRequest,
            },
            MemoryKind, MemoryStatus,
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
    fn empty_database_applies_all_migrations_through_009_with_foreign_keys_enabled() {
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
        assert_eq!(version, 12);
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
        assert_eq!(version, 12);
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
    fn migration_008_to_009_deduplicates_evidence_without_touching_authoritative_data() {
        let root = TestRoot::new("upgrade-009");
        let data_root = create_v7_database(&root);
        let database = data_root.join(DATABASE_FILE_NAME);
        let connection = Connection::open(&database).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .unwrap();
        connection
            .execute_batch(include_str!("migrations/008_candidate_memory_storage.sql"))
            .unwrap();
        connection
            .execute(
                "INSERT INTO schema_migration (version, name, applied_at)
                 VALUES (8, '008_candidate_memory_storage', '2026-07-14T00:00:00.000Z')",
                [],
            )
            .unwrap();
        for id in ["evidence-a", "evidence-b"] {
            connection
                .execute(
                    "INSERT INTO candidate_memory_evidence (
                        id, candidate_id, life_id, source_type, source_id,
                        conversation_id, message_id, observed_at
                     ) VALUES (?1, 'candidate-manual', 'life-a', 'manual', NULL, NULL, NULL,
                        '2026-07-14T00:00:00.000Z')",
                    params![id],
                )
                .unwrap();
        }
        drop(connection);

        let service = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = service.state().unwrap();
        let evidence: Vec<String> = state
            .connection
            .prepare("SELECT id FROM candidate_memory_evidence ORDER BY rowid")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        let candidate_revision: i64 = state
            .connection
            .query_row(
                "SELECT revision FROM candidate_memory WHERE id = 'candidate-manual'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let confirmed_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_record WHERE id = 'confirmed-old'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let revision_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM memory_revision", [], |row| row.get(0))
            .unwrap();
        let outbox_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_sync_outbox",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(evidence, ["evidence-a"]);
        assert_eq!(candidate_revision, 1);
        assert_eq!(confirmed_count, 1);
        assert_eq!(revision_count, 1);
        assert_eq!(outbox_count, 1);
    }

    #[test]
    fn migration_009_failure_rolls_back_deduplication_and_index_creation() {
        let root = TestRoot::new("upgrade-009-rollback");
        let data_root = create_v7_database(&root);
        let database = data_root.join(DATABASE_FILE_NAME);
        let mut connection = Connection::open(&database).unwrap();
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .unwrap();
        connection
            .execute_batch(include_str!("migrations/008_candidate_memory_storage.sql"))
            .unwrap();
        for id in ["evidence-a", "evidence-b"] {
            connection
                .execute(
                    "INSERT INTO candidate_memory_evidence (
                        id, candidate_id, life_id, source_type, source_id,
                        conversation_id, message_id, observed_at
                     ) VALUES (?1, 'candidate-manual', 'life-a', 'manual', NULL, NULL, NULL,
                        '2026-07-14T00:00:00.000Z')",
                    params![id],
                )
                .unwrap();
        }
        connection
            .execute_batch(
                "CREATE TRIGGER fail_migration_009_delete
                 BEFORE DELETE ON candidate_memory_evidence
                 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
            )
            .unwrap();
        let transaction = connection.transaction().unwrap();
        assert!(transaction
            .execute_batch(include_str!(
                "migrations/009_candidate_evidence_uniqueness.sql"
            ))
            .is_err());
        drop(transaction);
        let evidence_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory_evidence",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let index_exists: i64 = connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_master
                    WHERE type = 'index' AND name = 'idx_candidate_memory_evidence_identity'
                 )",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(evidence_count, 2);
        assert_eq!(index_exists, 0);
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
    fn duplicate_evidence_identity_maps_to_a_stable_duplicate_error() {
        let root = TestRoot::new("evidence-identity-duplicate");
        let service = seeded_service(&root);
        insert_candidate(
            &service,
            "candidate-a",
            "life-a",
            "2026-07-14T10:00:00.000Z",
        );
        let evidence = NewCandidateMemoryEvidence {
            id: "evidence-a".into(),
            candidate_id: "candidate-a".into(),
            life_id: "life-a".into(),
            source_type: CandidateMemorySourceType::Manual,
            source_id: Some("manual-source".into()),
            conversation_id: None,
            message_id: None,
            observed_at: "2026-07-14T10:00:00.000Z".into(),
        };
        <StorageService as CandidateMemoryRepository>::insert_evidence(&service, evidence.clone())
            .unwrap();
        let duplicate = NewCandidateMemoryEvidence {
            id: "evidence-b".into(),
            ..evidence
        };
        let error =
            <StorageService as CandidateMemoryRepository>::insert_evidence(&service, duplicate)
                .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_DUPLICATE");
        assert!(!error
            .message
            .contains("idx_candidate_memory_evidence_identity"));
        assert!(!error.message.contains("INSERT"));
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
        CandidateMemoryService::new(&service)
            .delete_permanently(
                "life-a",
                DeleteCandidateRequest {
                    candidate_id: "candidate".into(),
                    expected_revision: 1,
                },
            )
            .unwrap();
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
        assert_eq!(audit_count, 3);
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

    fn install_failure_trigger(service: &StorageService, sql: &str) {
        service
            .state()
            .unwrap()
            .connection
            .execute_batch(sql)
            .unwrap();
    }

    fn audit_count(service: &StorageService, action: &str) -> i64 {
        service
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory_audit WHERE action = ?1",
                params![action],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn add_fixture_evidence(service: &StorageService, candidate_id: &str, evidence_id: &str) {
        <StorageService as CandidateMemoryRepository>::insert_evidence(
            service,
            NewCandidateMemoryEvidence {
                id: evidence_id.into(),
                candidate_id: candidate_id.into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Manual,
                source_id: Some(evidence_id.into()),
                conversation_id: None,
                message_id: None,
                observed_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
    }

    #[test]
    fn edit_audit_failure_rolls_back_candidate_update() {
        let root = TestRoot::new("atomic-edit-audit");
        let service = seeded_service(&root);
        let before = insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        install_failure_trigger(
            &service,
            "CREATE TEMP TRIGGER fail_edit_audit BEFORE INSERT ON candidate_memory_audit
             WHEN NEW.action = 'candidate_edited'
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
        let error = CandidateMemoryService::new(&service)
            .edit(
                "life-a",
                EditCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    kind: MemoryKind::Goal,
                    content: "Changed content".into(),
                    summary: Some("Changed summary".into()),
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_CONSTRAINT_VIOLATION");
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .unwrap(),
            before
        );
        assert_eq!(audit_count(&service, "candidate_edited"), 0);
    }

    #[test]
    fn reject_evidence_delete_failure_rolls_back_everything() {
        let root = TestRoot::new("atomic-reject-evidence");
        let service = seeded_service(&root);
        let before = insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        add_fixture_evidence(&service, "c1", "ev1");
        install_failure_trigger(
            &service,
            "CREATE TEMP TRIGGER fail_reject_evidence BEFORE DELETE ON candidate_memory_evidence
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
        CandidateMemoryService::new(&service)
            .reject(
                "life-a",
                RejectCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    reason: RejectionReason::Other,
                },
            )
            .unwrap_err();
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .unwrap(),
            before
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(&service, "life-a", "c1")
                .unwrap(),
            1
        );
        assert_eq!(audit_count(&service, "candidate_rejected"), 0);
    }

    #[test]
    fn reject_audit_failure_rolls_back_candidate_and_evidence() {
        let root = TestRoot::new("atomic-reject-audit");
        let service = seeded_service(&root);
        let before = insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        add_fixture_evidence(&service, "c1", "ev1");
        install_failure_trigger(
            &service,
            "CREATE TEMP TRIGGER fail_reject_audit BEFORE INSERT ON candidate_memory_audit
             WHEN NEW.action = 'candidate_rejected'
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
        CandidateMemoryService::new(&service)
            .reject(
                "life-a",
                RejectCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    reason: RejectionReason::Other,
                },
            )
            .unwrap_err();
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .unwrap(),
            before
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(&service, "life-a", "c1")
                .unwrap(),
            1
        );
    }

    #[test]
    fn expire_audit_failure_rolls_back_candidate_and_evidence() {
        let root = TestRoot::new("atomic-expire-audit");
        let service = seeded_service(&root);
        let mut candidate = pending("c1", "life-a", "2026-07-14T10:00:00.000Z");
        candidate.expires_at = Some("2020-01-01T00:00:00.000Z".into());
        let before =
            <StorageService as CandidateMemoryRepository>::insert_candidate(&service, candidate)
                .unwrap();
        add_fixture_evidence(&service, "c1", "ev1");
        install_failure_trigger(
            &service,
            "CREATE TEMP TRIGGER fail_expire_audit BEFORE INSERT ON candidate_memory_audit
             WHEN NEW.action = 'candidate_expired'
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
        CandidateMemoryService::new(&service)
            .expire_one("life-a", "c1", 1, "2026-07-14T12:00:00.000Z")
            .unwrap_err();
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .unwrap(),
            before
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(&service, "life-a", "c1")
                .unwrap(),
            1
        );
    }

    #[test]
    fn supersede_evidence_delete_failure_rolls_back_both_candidates() {
        let root = TestRoot::new("atomic-supersede-evidence");
        let service = seeded_service(&root);
        let before = insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let replacement = insert_candidate(&service, "c2", "life-a", "2026-07-14T11:00:00.000Z");
        add_fixture_evidence(&service, "c1", "ev1");
        install_failure_trigger(
            &service,
            "CREATE TEMP TRIGGER fail_supersede_evidence BEFORE DELETE ON candidate_memory_evidence
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
        CandidateMemoryService::new(&service)
            .supersede(
                "life-a",
                SupersedeCandidateRequest {
                    candidate_id: "c1".into(),
                    replacement_candidate_id: "c2".into(),
                    expected_revision: 1,
                },
            )
            .unwrap_err();
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .unwrap(),
            before
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c2")
                .unwrap(),
            replacement
        );
    }

    #[test]
    fn supersede_audit_failure_rolls_back_candidate_and_evidence() {
        let root = TestRoot::new("atomic-supersede-audit");
        let service = seeded_service(&root);
        let before = insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        insert_candidate(&service, "c2", "life-a", "2026-07-14T11:00:00.000Z");
        add_fixture_evidence(&service, "c1", "ev1");
        install_failure_trigger(
            &service,
            "CREATE TEMP TRIGGER fail_supersede_audit BEFORE INSERT ON candidate_memory_audit
             WHEN NEW.action = 'candidate_superseded'
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
        CandidateMemoryService::new(&service)
            .supersede(
                "life-a",
                SupersedeCandidateRequest {
                    candidate_id: "c1".into(),
                    replacement_candidate_id: "c2".into(),
                    expected_revision: 1,
                },
            )
            .unwrap_err();
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .unwrap(),
            before
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(&service, "life-a", "c1")
                .unwrap(),
            1
        );
    }

    #[test]
    fn candidate_delete_failure_rolls_back_delete_audit() {
        let root = TestRoot::new("atomic-delete");
        let service = seeded_service(&root);
        let before = insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        add_fixture_evidence(&service, "c1", "ev1");
        install_failure_trigger(
            &service,
            "CREATE TEMP TRIGGER fail_candidate_delete BEFORE DELETE ON candidate_memory
             WHEN OLD.id = 'c1'
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
        CandidateMemoryService::new(&service)
            .delete_permanently(
                "life-a",
                DeleteCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                },
            )
            .unwrap_err();
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .unwrap(),
            before
        );
        assert_eq!(audit_count(&service, "candidate_deleted"), 0);
    }

    #[test]
    fn evidence_candidate_update_failure_rolls_back_insert() {
        let root = TestRoot::new("atomic-evidence-update");
        let service = seeded_service(&root);
        let before = insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        install_failure_trigger(
            &service,
            "CREATE TEMP TRIGGER fail_evidence_revision BEFORE UPDATE ON candidate_memory
             WHEN NEW.id = 'c1'
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
        CandidateMemoryService::new(&service)
            .add_evidence(
                "life-a",
                AddEvidenceRequest {
                    candidate_id: "c1".into(),
                    source_type: CandidateMemorySourceType::Manual,
                    source_id: Some("source-a".into()),
                    conversation_id: None,
                    message_id: None,
                },
            )
            .unwrap_err();
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .unwrap(),
            before
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(&service, "life-a", "c1")
                .unwrap(),
            0
        );
        assert_eq!(audit_count(&service, "candidate_evidence_added"), 0);
    }

    #[test]
    fn evidence_audit_failure_rolls_back_insert_and_revision() {
        let root = TestRoot::new("atomic-evidence-audit");
        let service = seeded_service(&root);
        let before = insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        install_failure_trigger(
            &service,
            "CREATE TEMP TRIGGER fail_evidence_audit BEFORE INSERT ON candidate_memory_audit
             WHEN NEW.action = 'candidate_evidence_added'
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
        CandidateMemoryService::new(&service)
            .add_evidence(
                "life-a",
                AddEvidenceRequest {
                    candidate_id: "c1".into(),
                    source_type: CandidateMemorySourceType::Manual,
                    source_id: Some("source-a".into()),
                    conversation_id: None,
                    message_id: None,
                },
            )
            .unwrap_err();
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .unwrap(),
            before
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(&service, "life-a", "c1")
                .unwrap(),
            0
        );
    }

    #[test]
    fn concurrent_edits_with_same_revision_commit_exactly_once() {
        let root = TestRoot::new("concurrent-edit");
        let data_root = root.0.join("data");
        let first = seeded_service(&root);
        insert_candidate(&first, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let second = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [(first, "First edit"), (second, "Second edit")]
            .into_iter()
            .map(|(service, content)| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    CandidateMemoryService::new(&service).edit(
                        "life-a",
                        EditCandidateRequest {
                            candidate_id: "c1".into(),
                            expected_revision: 1,
                            kind: MemoryKind::Fact,
                            content: content.into(),
                            summary: None,
                        },
                    )
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter_map(|result| result.as_ref().err())
                .filter(|error| error.code == "CANDIDATE_MEMORY_REVISION_CONFLICT")
                .count(),
            1
        );
        let verification = StorageService::initialize_with_roots(data_root, None).unwrap();
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(
                &verification,
                "life-a",
                "c1",
            )
            .unwrap()
            .revision,
            2
        );
        assert_eq!(audit_count(&verification, "candidate_edited"), 1);
    }

    #[test]
    fn concurrent_edit_and_expire_cannot_overwrite_each_other() {
        let root = TestRoot::new("concurrent-edit-expire");
        let data_root = root.0.join("data");
        let first = seeded_service(&root);
        let mut candidate = pending("c1", "life-a", "2026-07-14T10:00:00.000Z");
        candidate.expires_at = Some("2020-01-01T00:00:00.000Z".into());
        <StorageService as CandidateMemoryRepository>::insert_candidate(&first, candidate).unwrap();
        let second = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let edit_barrier = Arc::clone(&barrier);
        let edit = thread::spawn(move || {
            edit_barrier.wait();
            CandidateMemoryService::new(&first).edit(
                "life-a",
                EditCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    kind: MemoryKind::Fact,
                    content: "User edit wins safely".into(),
                    summary: None,
                },
            )
        });
        let expire = thread::spawn(move || {
            barrier.wait();
            CandidateMemoryService::new(&second).expire_one(
                "life-a",
                "c1",
                1,
                "2026-07-14T12:00:00.000Z",
            )
        });
        let edit_result = edit.join().unwrap();
        let expire_result = expire.join().unwrap();
        assert_ne!(edit_result.is_ok(), matches!(expire_result, Ok(Some(_))));
        let verification = StorageService::initialize_with_roots(data_root, None).unwrap();
        let stored = <StorageService as CandidateMemoryRepository>::get_candidate(
            &verification,
            "life-a",
            "c1",
        )
        .unwrap();
        assert_eq!(stored.revision, 2);
        if edit_result.is_ok() {
            assert_eq!(stored.content.as_deref(), Some("User edit wins safely"));
            assert_eq!(stored.status, CandidateMemoryStatus::Pending);
        } else {
            assert_eq!(stored.status, CandidateMemoryStatus::Expired);
        }
        assert_eq!(
            audit_count(&verification, "candidate_edited")
                + audit_count(&verification, "candidate_expired"),
            1
        );
    }

    #[test]
    fn concurrent_identical_evidence_is_a_single_noop_safe_write() {
        let root = TestRoot::new("concurrent-evidence-same");
        let data_root = root.0.join("data");
        let first = seeded_service(&root);
        insert_candidate(&first, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let second = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [first, second]
            .into_iter()
            .map(|service| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    CandidateMemoryService::new(&service).add_evidence(
                        "life-a",
                        AddEvidenceRequest {
                            candidate_id: "c1".into(),
                            source_type: CandidateMemorySourceType::Manual,
                            source_id: Some("same-source".into()),
                            conversation_id: None,
                            message_id: None,
                        },
                    )
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_some()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_none()).count(), 1);
        let verification = StorageService::initialize_with_roots(data_root, None).unwrap();
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(
                &verification,
                "life-a",
                "c1",
            )
            .unwrap(),
            1
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(
                &verification,
                "life-a",
                "c1",
            )
            .unwrap()
            .revision,
            2
        );
        assert_eq!(audit_count(&verification, "candidate_evidence_added"), 1);
    }

    #[test]
    fn concurrent_distinct_evidence_preserves_both_revision_updates() {
        let root = TestRoot::new("concurrent-evidence-distinct");
        let data_root = root.0.join("data");
        let first = seeded_service(&root);
        insert_candidate(&first, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let second = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [(first, "source-a"), (second, "source-b")]
            .into_iter()
            .map(|(service, source_id)| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    CandidateMemoryService::new(&service).add_evidence(
                        "life-a",
                        AddEvidenceRequest {
                            candidate_id: "c1".into(),
                            source_type: CandidateMemorySourceType::Manual,
                            source_id: Some(source_id.into()),
                            conversation_id: None,
                            message_id: None,
                        },
                    )
                })
            })
            .collect();
        for handle in handles {
            assert!(handle.join().unwrap().unwrap().is_some());
        }
        let verification = StorageService::initialize_with_roots(data_root, None).unwrap();
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(
                &verification,
                "life-a",
                "c1",
            )
            .unwrap(),
            2
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(
                &verification,
                "life-a",
                "c1",
            )
            .unwrap()
            .revision,
            3
        );
        assert_eq!(audit_count(&verification, "candidate_evidence_added"), 2);
    }

    #[test]
    fn conversation_delete_candidate_cleanup_failure_rolls_back_source_delete() {
        let root = TestRoot::new("conversation-delete-rollback");
        let service = seeded_service(&root);
        let mut candidate = pending("c1", "life-a", "2026-07-14T10:00:00.000Z");
        candidate.source_type = CandidateMemorySourceType::Conversation;
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, candidate)
            .unwrap();
        insert_conversation_with_message(&service, "life-a", "a");
        <StorageService as CandidateMemoryRepository>::insert_evidence(
            &service,
            NewCandidateMemoryEvidence {
                id: "ev1".into(),
                candidate_id: "c1".into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Conversation,
                source_id: None,
                conversation_id: Some("conversation-a".into()),
                message_id: Some("message-a".into()),
                observed_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        install_failure_trigger(
            &service,
            "CREATE TEMP TRIGGER fail_orphan_candidate_delete BEFORE DELETE ON candidate_memory
             WHEN OLD.id = 'c1'
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
        ConversationRepository::delete_conversation(&service, "life-a", "conversation-a")
            .unwrap_err();
        let state = service.state().unwrap();
        let conversation_exists: bool = state
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM conversation WHERE id = 'conversation-a')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let evidence_exists: bool = state
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM candidate_memory_evidence WHERE id = 'ev1')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(conversation_exists);
        assert!(evidence_exists);
        drop(state);
        assert!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .is_ok()
        );
        assert_eq!(
            audit_count(&service, "candidate_orphaned_source_deleted"),
            0
        );
    }

    #[test]
    fn source_delete_audit_contains_no_source_or_content_payload() {
        let root = TestRoot::new("conversation-delete-audit-privacy");
        let service = seeded_service(&root);
        let mut candidate = pending("c1", "life-a", "2026-07-14T10:00:00.000Z");
        candidate.source_type = CandidateMemorySourceType::Conversation;
        candidate.content = Some("private candidate content".into());
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, candidate)
            .unwrap();
        insert_conversation_with_message(&service, "life-a", "a");
        <StorageService as CandidateMemoryRepository>::insert_evidence(
            &service,
            NewCandidateMemoryEvidence {
                id: "ev1".into(),
                candidate_id: "c1".into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Conversation,
                source_id: Some("sensitive-source-id".into()),
                conversation_id: Some("conversation-a".into()),
                message_id: Some("message-a".into()),
                observed_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        ConversationRepository::delete_conversation(&service, "life-a", "conversation-a").unwrap();
        let state = service.state().unwrap();
        let audit_text: String = state
            .connection
            .query_row(
                "SELECT candidate_id || '|' || action || '|' || actor_type || '|' || result_status
                 FROM candidate_memory_audit
                 WHERE action = 'candidate_orphaned_source_deleted'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!audit_text.contains("conversation-a"));
        assert!(!audit_text.contains("message-a"));
        assert!(!audit_text.contains("sensitive-source-id"));
        assert!(!audit_text.contains("private candidate content"));
    }

    #[test]
    fn conversation_source_delete_never_removes_accepted_candidate_or_confirmed_memory() {
        let root = TestRoot::new("conversation-delete-accepted");
        let service = seeded_service(&root);
        insert_confirmed_memory(&service, "memory-confirmed", "life-a");
        let mut candidate = pending("c1", "life-a", "2026-07-14T10:00:00.000Z");
        candidate.source_type = CandidateMemorySourceType::Conversation;
        candidate.status = CandidateMemoryStatus::Accepted;
        candidate.content = None;
        candidate.summary = None;
        candidate.confirmed_memory_id = Some("memory-confirmed".into());
        candidate.accepted_request_id = Some("accepted-request".into());
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, candidate)
            .unwrap();
        insert_conversation_with_message(&service, "life-a", "a");
        <StorageService as CandidateMemoryRepository>::insert_evidence(
            &service,
            NewCandidateMemoryEvidence {
                id: "ev1".into(),
                candidate_id: "c1".into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Conversation,
                source_id: None,
                conversation_id: Some("conversation-a".into()),
                message_id: Some("message-a".into()),
                observed_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        ConversationRepository::delete_conversation(&service, "life-a", "conversation-a").unwrap();
        let accepted =
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .unwrap();
        assert_eq!(accepted.status, CandidateMemoryStatus::Accepted);
        let confirmed_exists: bool = service
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM memory_record WHERE id = 'memory-confirmed')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(confirmed_exists);
    }

    #[test]
    fn governed_message_delete_removes_only_orphan_candidate() {
        let root = TestRoot::new("message-delete-orphan");
        let service = seeded_service(&root);
        let mut candidate = pending("c1", "life-a", "2026-07-14T10:00:00.000Z");
        candidate.source_type = CandidateMemorySourceType::Conversation;
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, candidate)
            .unwrap();
        insert_conversation_with_message(&service, "life-a", "a");
        <StorageService as CandidateMemoryRepository>::insert_evidence(
            &service,
            NewCandidateMemoryEvidence {
                id: "ev1".into(),
                candidate_id: "c1".into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Conversation,
                source_id: None,
                conversation_id: Some("conversation-a".into()),
                message_id: Some("message-a".into()),
                observed_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        service
            .delete_conversation_message_governed("life-a", "conversation-a", "message-a")
            .unwrap();
        assert!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .is_err()
        );
        let state = service.state().unwrap();
        let conversation_exists: bool = state
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM conversation WHERE id = 'conversation-a')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(conversation_exists);
    }

    #[test]
    fn governed_message_delete_preserves_candidate_with_other_evidence() {
        let root = TestRoot::new("message-delete-remaining");
        let service = seeded_service(&root);
        let mut candidate = pending("c1", "life-a", "2026-07-14T10:00:00.000Z");
        candidate.source_type = CandidateMemorySourceType::Conversation;
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, candidate)
            .unwrap();
        insert_conversation_with_message(&service, "life-a", "a");
        {
            let state = service.state().unwrap();
            state
                .connection
                .execute(
                    "INSERT INTO conversation_message (
                        id, conversation_id, life_id, turn_id, role, content, sequence_no, created_at
                     ) VALUES ('message-b', 'conversation-a', 'life-a', 'turn-2', 'assistant',
                        'Message B', 2, '2026-07-14T00:01:00.000Z')",
                    [],
                )
                .unwrap();
        }
        for (evidence_id, message_id) in [("ev1", "message-a"), ("ev2", "message-b")] {
            <StorageService as CandidateMemoryRepository>::insert_evidence(
                &service,
                NewCandidateMemoryEvidence {
                    id: evidence_id.into(),
                    candidate_id: "c1".into(),
                    life_id: "life-a".into(),
                    source_type: CandidateMemorySourceType::Conversation,
                    source_id: None,
                    conversation_id: Some("conversation-a".into()),
                    message_id: Some(message_id.into()),
                    observed_at: "2026-07-14T10:00:00.000Z".into(),
                },
            )
            .unwrap();
        }
        service
            .delete_conversation_message_governed("life-a", "conversation-a", "message-a")
            .unwrap();
        assert!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .is_ok()
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(&service, "life-a", "c1")
                .unwrap(),
            1
        );
    }

    #[test]
    fn message_delete_and_candidate_cleanup_failures_both_roll_back() {
        for failure_point in ["message", "candidate"] {
            let root = TestRoot::new(&format!("message-delete-rollback-{failure_point}"));
            let service = seeded_service(&root);
            let mut candidate = pending("c1", "life-a", "2026-07-14T10:00:00.000Z");
            candidate.source_type = CandidateMemorySourceType::Conversation;
            <StorageService as CandidateMemoryRepository>::insert_candidate(&service, candidate)
                .unwrap();
            insert_conversation_with_message(&service, "life-a", "a");
            <StorageService as CandidateMemoryRepository>::insert_evidence(
                &service,
                NewCandidateMemoryEvidence {
                    id: "ev1".into(),
                    candidate_id: "c1".into(),
                    life_id: "life-a".into(),
                    source_type: CandidateMemorySourceType::Conversation,
                    source_id: None,
                    conversation_id: Some("conversation-a".into()),
                    message_id: Some("message-a".into()),
                    observed_at: "2026-07-14T10:00:00.000Z".into(),
                },
            )
            .unwrap();
            let trigger = if failure_point == "message" {
                "CREATE TEMP TRIGGER fail_message_delete BEFORE DELETE ON conversation_message
                 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;"
            } else {
                "CREATE TEMP TRIGGER fail_message_orphan_cleanup BEFORE DELETE ON candidate_memory
                 WHEN OLD.id = 'c1'
                 BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;"
            };
            install_failure_trigger(&service, trigger);
            service
                .delete_conversation_message_governed("life-a", "conversation-a", "message-a")
                .unwrap_err();
            let state = service.state().unwrap();
            let message_exists: bool = state
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM conversation_message WHERE id = 'message-a')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let evidence_exists: bool = state
                .connection
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM candidate_memory_evidence WHERE id = 'ev1')",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(message_exists);
            assert!(evidence_exists);
            drop(state);
            assert!(
                <StorageService as CandidateMemoryRepository>::get_candidate(
                    &service, "life-a", "c1"
                )
                .is_ok()
            );
        }
    }

    // ── Confirm (D-4) ─────────────────────────────────────────────────

    fn insert_sensitive_candidate(
        service: &StorageService,
        id: &str,
        life_id: &str,
    ) -> crate::memory::candidate::CandidateMemoryRecord {
        let mut candidate = pending(id, life_id, "2026-07-14T10:00:00.000Z");
        candidate.is_sensitive = true;
        candidate.source_type = CandidateMemorySourceType::Manual;
        candidate.source_id = None;
        <StorageService as CandidateMemoryRepository>::insert_candidate(service, candidate).unwrap()
    }

    fn count_rows(service: &StorageService, sql: &str) -> i64 {
        service
            .state()
            .unwrap()
            .connection
            .query_row(sql, [], |row| row.get(0))
            .unwrap()
    }

    fn confirm_request(
        candidate_id: &str,
        revision: i64,
        request_id: &str,
    ) -> ConfirmCandidateRequest {
        ConfirmCandidateRequest {
            candidate_id: candidate_id.into(),
            expected_revision: revision,
            request_id: request_id.into(),
            sensitive_grant: None,
        }
    }

    #[test]
    fn confirm_promotes_pending_candidate_to_confirmed_memory() {
        let root = TestRoot::new("confirm-ok");
        let service = seeded_service(&root);
        // Seed with every payload column populated so the NULL-out assertions bite.
        let mut candidate = pending("c1", "life-a", "2026-07-14T10:00:00.000Z");
        candidate.dedup_fingerprint = Some("fingerprint-c1".into());
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, candidate)
            .unwrap();
        add_fixture_evidence(&service, "c1", "ev1");
        let result = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c1", 1, "req-1"))
            .unwrap();
        assert_eq!(result.outcome, ConfirmCandidateOutcome::Confirmed);
        assert_eq!(result.candidate.status, CandidateMemoryStatus::Accepted);
        assert!(result.candidate.content.is_none());
        // The accepted candidate row nulls out every payload/provenance column.
        let (content, summary, source_id, fingerprint): (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ) = service
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT content, summary, source_id, dedup_fingerprint
                 FROM candidate_memory WHERE id = 'c1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(content, None);
        assert_eq!(summary, None);
        assert_eq!(source_id, None);
        assert_eq!(fingerprint, None);
        assert_eq!(result.candidate.revision, 2);
        assert_eq!(
            result.candidate.confirmed_memory_id.as_deref(),
            Some(result.memory.id.as_str())
        );
        assert_eq!(
            result.candidate.accepted_request_id.as_deref(),
            Some("req-1")
        );
        assert_eq!(result.memory.status, MemoryStatus::Confirmed);
        assert_eq!(result.memory.content, "Candidate c1");
        assert_eq!(
            result.memory.confirmed_at.as_deref(),
            result.candidate.reviewed_at.as_deref()
        );
        // Evidence cleared, audit + revision written.
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(&service, "life-a", "c1")
                .unwrap(),
            0
        );
        assert_eq!(audit_count(&service, "candidate_confirmed"), 1);
        assert_eq!(
            count_rows(
                &service,
                "SELECT COUNT(*) FROM memory_revision WHERE change_type = 'confirmed'"
            ),
            1
        );
    }

    #[test]
    fn confirm_non_sensitive_enqueues_upsert() {
        let root = TestRoot::new("confirm-upsert");
        let service = seeded_service(&root);
        insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let result = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c1", 1, "req-1"))
            .unwrap();
        let action: String = service
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT desired_action FROM memory_vector_sync_outbox WHERE memory_id = ?1",
                params![result.memory.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(action, "upsert");
    }

    #[test]
    fn confirm_sensitive_requires_consent_and_enqueues_delete() {
        let root = TestRoot::new("confirm-sensitive");
        let service = seeded_service(&root);
        insert_sensitive_candidate(&service, "c1", "life-a");
        // Missing grant is refused without side effects.
        let error = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c1", 1, "req-1"))
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_SENSITIVE_CONSENT_REQUIRED");
        assert_eq!(
            count_rows(&service, "SELECT COUNT(*) FROM memory_record"),
            0
        );
        // A grant acknowledging a *different* candidate cannot be reused as consent.
        let error = CandidateMemoryService::new(&service)
            .confirm(
                "life-a",
                ConfirmCandidateRequest {
                    sensitive_grant: Some(SensitiveConfirmationGrant::acknowledge_for_test(
                        "other",
                    )),
                    ..confirm_request("c1", 1, "req-1")
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_SENSITIVE_CONSENT_REQUIRED");
        assert_eq!(
            count_rows(&service, "SELECT COUNT(*) FROM memory_record"),
            0
        );
        // A grant acknowledging this candidate confirms; sensitive memory must not upsert.
        let result = CandidateMemoryService::new(&service)
            .confirm(
                "life-a",
                ConfirmCandidateRequest {
                    sensitive_grant: Some(SensitiveConfirmationGrant::acknowledge_for_test("c1")),
                    ..confirm_request("c1", 1, "req-1")
                },
            )
            .unwrap();
        assert!(result.memory.is_sensitive);
        let action: String = service
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT desired_action FROM memory_vector_sync_outbox WHERE memory_id = ?1",
                params![result.memory.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(action, "delete");
    }

    #[test]
    fn confirm_result_and_audit_do_not_leak_candidate_internals() {
        let root = TestRoot::new("confirm-no-leak");
        let service = seeded_service(&root);
        let mut candidate = pending("c1", "life-a", "2026-07-14T10:00:00.000Z");
        candidate.content = Some("SECRETCONTENT-marker".into());
        candidate.summary = Some("SECRETSUMMARY-marker".into());
        candidate.source_id = Some("SECRETSOURCE-marker".into());
        candidate.dedup_fingerprint = Some("SECRETFINGERPRINT-marker".into());
        <StorageService as CandidateMemoryRepository>::insert_candidate(&service, candidate)
            .unwrap();
        add_fixture_evidence(&service, "c1", "SECRETEVIDENCE-marker");
        let result = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c1", 1, "req-1"))
            .unwrap();
        // The audit record carries only ids/metadata — never candidate payload.
        let audit_json = serde_json::to_string(&result.audit.unwrap()).unwrap();
        for marker in [
            "SECRETCONTENT",
            "SECRETSUMMARY",
            "SECRETSOURCE",
            "SECRETFINGERPRINT",
            "SECRETEVIDENCE",
        ] {
            assert!(
                !audit_json.contains(marker),
                "audit leaked {marker}: {audit_json}"
            );
        }
        // The returned candidate is scrubbed of payload/provenance too.
        assert!(result.candidate.content.is_none());
        assert!(result.candidate.summary.is_none());
        assert!(result.candidate.source_id.is_none());
        assert!(result.candidate.dedup_fingerprint.is_none());
    }

    #[test]
    fn confirm_error_messages_reveal_no_sql_paths_or_raw_sqlite_text() {
        let root = TestRoot::new("confirm-error-privacy");
        let service = seeded_service(&root);
        insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        install_failure_trigger(
            &service,
            "CREATE TEMP TRIGGER fail_confirm_probe BEFORE INSERT ON memory_record
             WHEN NEW.status = 'confirmed'
             BEGIN SELECT RAISE(ABORT, 'raw sqlite detail /secret/path.db'); END;",
        );
        let error = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c1", 1, "req-1"))
            .unwrap_err();
        let text = format!("{} {}", error.code, error.message).to_lowercase();
        for needle in [
            "raw sqlite detail",
            "/secret/path.db",
            "insert into",
            "memory_record",
            "trigger",
            ".db",
        ] {
            assert!(!text.contains(needle), "error leaked {needle}: {text}");
        }
    }

    #[test]
    fn confirm_is_idempotent_for_same_request_id() {
        let root = TestRoot::new("confirm-idempotent");
        let service = seeded_service(&root);
        insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let first = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c1", 1, "req-1"))
            .unwrap();
        // Replay with the accepted revision and same request id returns the prior memory.
        let second = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c1", 2, "req-1"))
            .unwrap();
        assert_eq!(second.outcome, ConfirmCandidateOutcome::AlreadyConfirmed);
        assert!(second.audit.is_none());
        assert_eq!(second.memory.id, first.memory.id);
        assert_eq!(second.candidate.revision, 2);
        // No duplicate memory, outbox, or audit rows were created.
        assert_eq!(
            count_rows(&service, "SELECT COUNT(*) FROM memory_record"),
            1
        );
        assert_eq!(
            count_rows(&service, "SELECT COUNT(*) FROM memory_vector_sync_outbox"),
            1
        );
        assert_eq!(audit_count(&service, "candidate_confirmed"), 1);
    }

    #[test]
    fn confirm_accepted_with_different_request_id_is_request_conflict() {
        let root = TestRoot::new("confirm-accepted-other-req");
        let service = seeded_service(&root);
        insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let first = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c1", 1, "req-1"))
            .unwrap();
        let error = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c1", 2, "req-2"))
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_REQUEST_CONFLICT");
        // The accepted candidate and its confirmed memory are untouched by the reject.
        let stored =
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .unwrap();
        assert_eq!(stored.status, CandidateMemoryStatus::Accepted);
        assert_eq!(stored.accepted_request_id.as_deref(), Some("req-1"));
        assert_eq!(
            stored.confirmed_memory_id.as_deref(),
            Some(first.memory.id.as_str())
        );
        assert_eq!(
            count_rows(&service, "SELECT COUNT(*) FROM memory_record"),
            1
        );
    }

    #[test]
    fn confirm_reused_request_id_across_candidates_is_request_conflict() {
        let root = TestRoot::new("confirm-req-conflict");
        let service = seeded_service(&root);
        insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        insert_candidate(&service, "c2", "life-a", "2026-07-14T10:05:00.000Z");
        CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c1", 1, "shared-req"))
            .unwrap();
        let error = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c2", 1, "shared-req"))
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_REQUEST_CONFLICT");
        // c2 remains pending and no second memory leaked.
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c2")
                .unwrap()
                .status,
            CandidateMemoryStatus::Pending
        );
        assert_eq!(
            count_rows(&service, "SELECT COUNT(*) FROM memory_record"),
            1
        );
    }

    #[test]
    fn confirm_revision_conflict_is_rejected() {
        let root = TestRoot::new("confirm-revision");
        let service = seeded_service(&root);
        insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let error = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c1", 99, "req-1"))
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_REVISION_CONFLICT");
        assert_eq!(
            count_rows(&service, "SELECT COUNT(*) FROM memory_record"),
            0
        );
    }

    #[test]
    fn confirm_cross_life_is_rejected() {
        let root = TestRoot::new("confirm-life");
        let service = seeded_service(&root);
        insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let error = CandidateMemoryService::new(&service)
            .confirm("life-b", confirm_request("c1", 1, "req-1"))
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_LIFE_MISMATCH");
    }

    #[test]
    fn confirm_rejected_candidate_is_invalid_status() {
        let root = TestRoot::new("confirm-rejected");
        let service = seeded_service(&root);
        insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        CandidateMemoryService::new(&service)
            .reject(
                "life-a",
                RejectCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    reason: RejectionReason::Other,
                },
            )
            .unwrap();
        let error = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c1", 2, "req-1"))
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_INVALID_STATUS");
    }

    /// Asserts a failed confirm left no trace: the candidate is byte-for-byte
    /// unchanged (still pending, content + source retained, revision unchanged, no
    /// `confirmed_memory_id` / `accepted_request_id`), its evidence survives, and no
    /// memory, revision, outbox, or success audit row exists.
    fn assert_confirm_left_no_trace(
        service: &StorageService,
        candidate_id: &str,
        before: &crate::memory::candidate::CandidateMemoryRecord,
        expected_evidence: usize,
    ) {
        let stored = <StorageService as CandidateMemoryRepository>::get_candidate(
            service,
            "life-a",
            candidate_id,
        )
        .unwrap();
        assert_eq!(&stored, before);
        assert_eq!(stored.status, CandidateMemoryStatus::Pending);
        assert!(stored.content.is_some());
        assert!(stored.confirmed_memory_id.is_none());
        assert!(stored.accepted_request_id.is_none());
        assert_eq!(count_rows(service, "SELECT COUNT(*) FROM memory_record"), 0);
        assert_eq!(
            count_rows(service, "SELECT COUNT(*) FROM memory_revision"),
            0
        );
        assert_eq!(
            count_rows(service, "SELECT COUNT(*) FROM memory_vector_sync_outbox"),
            0
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(
                service,
                "life-a",
                candidate_id,
            )
            .unwrap(),
            expected_evidence
        );
        assert_eq!(audit_count(service, "candidate_confirmed"), 0);
    }

    fn confirm_failure_case(name: &str, trigger_sql: &str) {
        let root = TestRoot::new(name);
        let service = seeded_service(&root);
        let before = insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        add_fixture_evidence(&service, "c1", "ev1");
        install_failure_trigger(&service, trigger_sql);
        let error = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c1", 1, "req-1"))
            .unwrap_err();
        // Error surface is a stable code with a generic message (no SQL/paths).
        assert!(error.code.starts_with("CANDIDATE_MEMORY_"));
        assert!(!error.message.to_lowercase().contains("fixture failure"));
        assert_confirm_left_no_trace(&service, "c1", &before, 1);
    }

    #[test]
    fn confirm_memory_insert_failure_rolls_back_cleanly() {
        confirm_failure_case(
            "confirm-fail-memory",
            "CREATE TEMP TRIGGER fail_confirm_memory BEFORE INSERT ON memory_record
             WHEN NEW.status = 'confirmed'
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
    }

    #[test]
    fn confirm_revision_insert_failure_rolls_back_cleanly() {
        confirm_failure_case(
            "confirm-fail-revision",
            "CREATE TEMP TRIGGER fail_confirm_revision BEFORE INSERT ON memory_revision
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
    }

    #[test]
    fn confirm_outbox_insert_failure_rolls_back_cleanly() {
        confirm_failure_case(
            "confirm-fail-outbox",
            "CREATE TEMP TRIGGER fail_confirm_outbox BEFORE INSERT ON memory_vector_sync_outbox
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
    }

    #[test]
    fn confirm_candidate_update_failure_rolls_back_cleanly() {
        confirm_failure_case(
            "confirm-fail-candidate",
            "CREATE TEMP TRIGGER fail_confirm_candidate BEFORE UPDATE ON candidate_memory
             WHEN NEW.status = 'accepted'
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
    }

    #[test]
    fn confirm_evidence_delete_failure_rolls_back_cleanly() {
        confirm_failure_case(
            "confirm-fail-evidence",
            "CREATE TEMP TRIGGER fail_confirm_evidence BEFORE DELETE ON candidate_memory_evidence
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
    }

    #[test]
    fn confirm_audit_insert_failure_rolls_back_cleanly() {
        confirm_failure_case(
            "confirm-fail-audit",
            "CREATE TEMP TRIGGER fail_confirm_audit BEFORE INSERT ON candidate_memory_audit
             WHEN NEW.action = 'candidate_confirmed'
             BEGIN SELECT RAISE(ABORT, 'fixture failure'); END;",
        );
    }

    #[test]
    fn confirm_duplicate_request_id_constraint_rolls_back_before_commit() {
        // A real DB UNIQUE constraint (accepted_request_id), not a fixture trigger:
        // c1 is genuinely confirmed under "shared", then c2 attempts the same id.
        let root = TestRoot::new("confirm-fail-constraint");
        let service = seeded_service(&root);
        CandidateMemoryService::new(&service)
            .confirm("life-a", {
                insert_candidate(&service, "c1", "life-a", "2026-07-14T10:00:00.000Z");
                confirm_request("c1", 1, "shared")
            })
            .unwrap();
        let before = insert_candidate(&service, "c2", "life-a", "2026-07-14T10:05:00.000Z");
        add_fixture_evidence(&service, "c2", "ev2");
        let error = CandidateMemoryService::new(&service)
            .confirm("life-a", confirm_request("c2", 1, "shared"))
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_REQUEST_CONFLICT");
        // c2 is fully rolled back; only c1's single memory/audit remain.
        let stored =
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c2")
                .unwrap();
        assert_eq!(stored, before);
        assert_eq!(stored.status, CandidateMemoryStatus::Pending);
        assert!(stored.confirmed_memory_id.is_none());
        assert!(stored.accepted_request_id.is_none());
        assert_eq!(
            count_rows(&service, "SELECT COUNT(*) FROM memory_record"),
            1
        );
        assert_eq!(
            count_rows(&service, "SELECT COUNT(*) FROM memory_revision"),
            1
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(&service, "life-a", "c2")
                .unwrap(),
            1usize
        );
        assert_eq!(audit_count(&service, "candidate_confirmed"), 1);
    }

    #[test]
    fn concurrent_confirm_same_request_id_creates_single_memory() {
        let root = TestRoot::new("confirm-concurrent");
        let data_root = root.0.join("data");
        let first = seeded_service(&root);
        insert_candidate(&first, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let second = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = [first, second]
            .into_iter()
            .map(|service| {
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    CandidateMemoryService::new(&service)
                        .confirm("life-a", confirm_request("c1", 1, "req-1"))
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap())
            .collect();
        // Exactly one fresh confirmation; the other observes the idempotent replay.
        assert_eq!(
            results
                .iter()
                .filter(|r| r.outcome == ConfirmCandidateOutcome::Confirmed)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|r| r.outcome == ConfirmCandidateOutcome::AlreadyConfirmed)
                .count(),
            1
        );
        let verification = StorageService::initialize_with_roots(data_root, None).unwrap();
        assert_eq!(
            count_rows(&verification, "SELECT COUNT(*) FROM memory_record"),
            1
        );
        assert_eq!(audit_count(&verification, "candidate_confirmed"), 1);
    }

    /// Opens a second independent connection over the same data root and returns
    /// (first, second) services plus the data root for post-run verification.
    fn two_services(root: &TestRoot) -> (StorageService, StorageService, PathBuf) {
        let data_root = root.0.join("data");
        let first = seeded_service(root);
        let second = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        (first, second, data_root)
    }

    #[test]
    fn concurrent_confirm_vs_confirm_distinct_request_ids_confirm_once() {
        let root = TestRoot::new("confirm-vs-confirm-distinct");
        let (first, second, data_root) = two_services(&root);
        insert_candidate(&first, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let barrier = Arc::new(Barrier::new(2));
        let a = {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                CandidateMemoryService::new(&first)
                    .confirm("life-a", confirm_request("c1", 1, "req-a"))
            })
        };
        let b = thread::spawn(move || {
            barrier.wait();
            CandidateMemoryService::new(&second)
                .confirm("life-a", confirm_request("c1", 1, "req-b"))
        });
        let results = [a.join().unwrap(), b.join().unwrap()];
        // One fresh confirm; the loser sees the accepted candidate under a foreign
        // request id and is refused with REQUEST_CONFLICT. Never two memories.
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        let winner_req = results
            .iter()
            .find_map(|r| r.as_ref().ok())
            .unwrap()
            .candidate
            .accepted_request_id
            .clone()
            .unwrap();
        assert!(winner_req == "req-a" || winner_req == "req-b");
        assert_eq!(
            results
                .iter()
                .filter_map(|r| r.as_ref().err())
                .filter(|e| e.code == "CANDIDATE_MEMORY_REQUEST_CONFLICT")
                .count(),
            1
        );
        let verification = StorageService::initialize_with_roots(data_root, None).unwrap();
        assert_eq!(
            count_rows(&verification, "SELECT COUNT(*) FROM memory_record"),
            1
        );
        assert_eq!(audit_count(&verification, "candidate_confirmed"), 1);
        let stored = <StorageService as CandidateMemoryRepository>::get_candidate(
            &verification,
            "life-a",
            "c1",
        )
        .unwrap();
        assert_eq!(stored.status, CandidateMemoryStatus::Accepted);
        assert_eq!(
            stored.accepted_request_id.as_deref(),
            Some(winner_req.as_str())
        );
    }

    #[test]
    fn concurrent_confirm_vs_edit_are_mutually_exclusive() {
        let root = TestRoot::new("confirm-vs-edit");
        let (first, second, data_root) = two_services(&root);
        insert_candidate(&first, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let barrier = Arc::new(Barrier::new(2));
        let confirm = {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                CandidateMemoryService::new(&first)
                    .confirm("life-a", confirm_request("c1", 1, "req-1"))
            })
        };
        let edit = thread::spawn(move || {
            barrier.wait();
            CandidateMemoryService::new(&second).edit(
                "life-a",
                EditCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    kind: MemoryKind::Goal,
                    content: "Edited before confirm".into(),
                    summary: None,
                },
            )
        });
        let confirm_result = confirm.join().unwrap();
        let edit_result = edit.join().unwrap();
        // Exactly one of the two revision-1 writers wins.
        assert_ne!(confirm_result.is_ok(), edit_result.is_ok());
        let verification = StorageService::initialize_with_roots(data_root, None).unwrap();
        let stored = <StorageService as CandidateMemoryRepository>::get_candidate(
            &verification,
            "life-a",
            "c1",
        )
        .unwrap();
        assert_eq!(stored.revision, 2);
        if confirm_result.is_ok() {
            assert_eq!(stored.status, CandidateMemoryStatus::Accepted);
            assert_eq!(
                count_rows(&verification, "SELECT COUNT(*) FROM memory_record"),
                1
            );
        } else {
            assert_eq!(stored.status, CandidateMemoryStatus::Pending);
            assert_eq!(stored.content.as_deref(), Some("Edited before confirm"));
            assert_eq!(
                count_rows(&verification, "SELECT COUNT(*) FROM memory_record"),
                0
            );
        }
        assert_eq!(
            audit_count(&verification, "candidate_confirmed")
                + audit_count(&verification, "candidate_edited"),
            1
        );
    }

    #[test]
    fn concurrent_confirm_vs_reject_are_mutually_exclusive() {
        let root = TestRoot::new("confirm-vs-reject");
        let (first, second, data_root) = two_services(&root);
        insert_candidate(&first, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let barrier = Arc::new(Barrier::new(2));
        let confirm = {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                CandidateMemoryService::new(&first)
                    .confirm("life-a", confirm_request("c1", 1, "req-1"))
            })
        };
        let reject = thread::spawn(move || {
            barrier.wait();
            CandidateMemoryService::new(&second).reject(
                "life-a",
                RejectCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    reason: RejectionReason::Other,
                },
            )
        });
        let confirm_result = confirm.join().unwrap();
        let reject_result = reject.join().unwrap();
        assert_ne!(confirm_result.is_ok(), reject_result.is_ok());
        let verification = StorageService::initialize_with_roots(data_root, None).unwrap();
        let stored = <StorageService as CandidateMemoryRepository>::get_candidate(
            &verification,
            "life-a",
            "c1",
        )
        .unwrap();
        assert_eq!(stored.revision, 2);
        if confirm_result.is_ok() {
            assert_eq!(stored.status, CandidateMemoryStatus::Accepted);
            assert_eq!(
                count_rows(&verification, "SELECT COUNT(*) FROM memory_record"),
                1
            );
        } else {
            assert_eq!(stored.status, CandidateMemoryStatus::Rejected);
            assert_eq!(
                count_rows(&verification, "SELECT COUNT(*) FROM memory_record"),
                0
            );
        }
    }

    #[test]
    fn concurrent_confirm_vs_expire_are_mutually_exclusive() {
        let root = TestRoot::new("confirm-vs-expire");
        let (first, second, data_root) = two_services(&root);
        let mut candidate = pending("c1", "life-a", "2026-07-14T10:00:00.000Z");
        candidate.expires_at = Some("2020-01-01T00:00:00.000Z".into());
        <StorageService as CandidateMemoryRepository>::insert_candidate(&first, candidate).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let confirm = {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                CandidateMemoryService::new(&first)
                    .confirm("life-a", confirm_request("c1", 1, "req-1"))
            })
        };
        let expire = thread::spawn(move || {
            barrier.wait();
            CandidateMemoryService::new(&second).expire_one(
                "life-a",
                "c1",
                1,
                "2026-07-14T12:00:00.000Z",
            )
        });
        let confirm_result = confirm.join().unwrap();
        let expire_result = expire.join().unwrap();
        // Exactly one revision-1 writer wins the row.
        assert_ne!(confirm_result.is_ok(), matches!(expire_result, Ok(Some(_))));
        let verification = StorageService::initialize_with_roots(data_root, None).unwrap();
        let stored = <StorageService as CandidateMemoryRepository>::get_candidate(
            &verification,
            "life-a",
            "c1",
        )
        .unwrap();
        assert_eq!(stored.revision, 2);
        if confirm_result.is_ok() {
            assert_eq!(stored.status, CandidateMemoryStatus::Accepted);
            assert_eq!(
                count_rows(&verification, "SELECT COUNT(*) FROM memory_record"),
                1
            );
        } else {
            assert_eq!(stored.status, CandidateMemoryStatus::Expired);
            assert_eq!(
                count_rows(&verification, "SELECT COUNT(*) FROM memory_record"),
                0
            );
        }
    }

    #[test]
    fn concurrent_confirm_vs_permanent_delete_are_mutually_exclusive() {
        let root = TestRoot::new("confirm-vs-delete");
        let (first, second, data_root) = two_services(&root);
        insert_candidate(&first, "c1", "life-a", "2026-07-14T10:00:00.000Z");
        let barrier = Arc::new(Barrier::new(2));
        let confirm = {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                CandidateMemoryService::new(&first)
                    .confirm("life-a", confirm_request("c1", 1, "req-1"))
            })
        };
        let delete = thread::spawn(move || {
            barrier.wait();
            CandidateMemoryService::new(&second).delete_permanently(
                "life-a",
                DeleteCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                },
            )
        });
        let confirm_result = confirm.join().unwrap();
        let delete_result = delete.join().unwrap();
        assert_ne!(confirm_result.is_ok(), delete_result.is_ok());
        let verification = StorageService::initialize_with_roots(data_root, None).unwrap();
        let exists = count_rows(
            &verification,
            "SELECT COUNT(*) FROM candidate_memory WHERE id = 'c1'",
        );
        if confirm_result.is_ok() {
            // Confirm won: candidate accepted, memory present, delete lost to revision guard.
            assert_eq!(exists, 1);
            assert_eq!(
                count_rows(&verification, "SELECT COUNT(*) FROM memory_record"),
                1
            );
            let stored = <StorageService as CandidateMemoryRepository>::get_candidate(
                &verification,
                "life-a",
                "c1",
            )
            .unwrap();
            assert_eq!(stored.status, CandidateMemoryStatus::Accepted);
        } else {
            // Delete won: candidate row gone, no memory ever created.
            assert_eq!(exists, 0);
            assert_eq!(
                count_rows(&verification, "SELECT COUNT(*) FROM memory_record"),
                0
            );
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
