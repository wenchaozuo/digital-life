//! Storage-owned durable primitives for the pre-promotion D9D3-C phase.
//!
//! This module owns every SQLite mutation for a persisted rebuild job.  The
//! memory-layer orchestrator may hold the existing composition guard and do
//! external embedding/Lance work, but it cannot mutate job/item authority by
//! ad-hoc SQL.

use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::{params, OptionalExtension, Row, Transaction, TransactionBehavior};

use crate::memory::{
    candidate_service::contains_prohibited_content,
    existing_generation_binding::D9D2_GENERATION_DESCRIPTOR_VERSION,
    vector_index::{canonical_index_text, canonical_memory_index_hash},
};

use super::{late_delete_resolution, StorageError, StorageService};

pub(crate) const GENERATION_REBUILD_MAX_ATTEMPTS: i64 = 5;
const GENERATION_REBUILD_LEASE_SECONDS: i64 = 120;
static REBUILD_ATTEMPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static PROMOTION_FAULT: std::sync::Mutex<Option<PromotionFault>> = std::sync::Mutex::new(None);

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PromotionFault {
    AfterPointerTransientNull,
    AfterSourceRetired,
    AfterCandidateActivated,
    AfterFinalPointer,
    AfterResolutions,
    BeforeCommit,
    AfterCommitUnknown,
}

#[cfg(test)]
pub(crate) fn arm_promotion_fault_for_test(fault: PromotionFault) {
    *PROMOTION_FAULT.lock().unwrap() = Some(fault);
}

#[cfg(test)]
fn fail_promotion(fault: PromotionFault) -> bool {
    let mut armed = PROMOTION_FAULT.lock().unwrap();
    if *armed == Some(fault) {
        *armed = None;
        true
    } else {
        false
    }
}

#[cfg(test)]
fn promotion_fault_error() -> StorageError {
    StorageError::new(
        "GENERATION_REBUILD_PROMOTION_FAULT",
        "A test-only promotion transaction fault was injected.",
        false,
    )
}

fn promotion_commit_unknown() -> StorageError {
    StorageError::new(
        "GENERATION_REBUILD_PROMOTION_COMMIT_RESULT_UNKNOWN",
        "The atomic generation promotion commit result is unknown.",
        true,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GenerationRebuildJobRecord {
    pub(crate) job_id: String,
    pub(crate) request_id: String,
    pub(crate) generation_id: String,
    pub(crate) descriptor_hash: String,
    pub(crate) dimension: usize,
    pub(crate) generation_state: String,
    pub(crate) generation_authority_epoch: i64,
    pub(crate) descriptor_version: String,
    pub(crate) embedding_profile_id: String,
    pub(crate) create_operation_id: String,
    pub(crate) witness_state: String,
    pub(crate) source_active_generation_id: Option<String>,
    pub(crate) source_active_authority_epoch: Option<i64>,
    pub(crate) candidate_authority_epoch: i64,
    pub(crate) status: String,
    pub(crate) snapshot_sequence: Option<i64>,
    pub(crate) catchup_target_sequence: Option<i64>,
    pub(crate) caught_up_sequence: Option<i64>,
    pub(crate) promotion_operation_id: Option<String>,
    pub(crate) promotion_sequence: Option<i64>,
    pub(crate) snapshot_item_count: i64,
    pub(crate) applied_item_count: i64,
    pub(crate) cancel_requested: bool,
    pub(crate) lease_owner: Option<String>,
    pub(crate) lease_fence: i64,
    pub(crate) lease_expires_at: Option<String>,
    pub(crate) last_error_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GenerationRebuildItemRecord {
    pub(crate) job_id: String,
    pub(crate) life_id: String,
    pub(crate) memory_id: String,
    pub(crate) memory_revision: i64,
    pub(crate) content_hash: String,
    pub(crate) canonical_document: Option<String>,
    pub(crate) state: String,
    pub(crate) io_phase: String,
    pub(crate) attempt_count: i64,
    pub(crate) attempt_id: Option<String>,
    pub(crate) attempt_fence: i64,
    pub(crate) last_send_disposition: Option<String>,
    pub(crate) last_error_code: Option<String>,
}

/// Schema-18 durable identity for one selected coalesced D catch-up target.
/// It is intentionally distinct from `GenerationRebuildItemRecord`, whose
/// identity remains the Schema-17 snapshot/bulk authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GenerationRebuildCatchupItemRecord {
    pub(crate) job_id: String,
    pub(crate) source_outbox_id: i64,
    pub(crate) life_id: String,
    pub(crate) memory_id: String,
    pub(crate) mutation_sequence: i64,
    pub(crate) desired_action: String,
    pub(crate) target_revision: Option<i64>,
    pub(crate) target_content_hash: Option<String>,
    pub(crate) canonical_document: Option<String>,
    pub(crate) state: String,
    pub(crate) io_phase: String,
    pub(crate) attempt_count: i64,
    pub(crate) attempt_id: Option<String>,
    pub(crate) attempt_fence: i64,
    pub(crate) last_send_disposition: Option<String>,
    pub(crate) last_error_code: Option<String>,
}

/// Redacted exact-set member used by the final SQLite/Lance comparison.  It
/// contains identity and immutable metadata only; canonical documents never
/// leave the storage-owned validation path.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct GenerationRebuildEligibleItem {
    pub(crate) life_id: String,
    pub(crate) memory_id: String,
    pub(crate) memory_revision: i64,
    pub(crate) content_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GenerationStoreWitnessRecord {
    pub(crate) generation_id: String,
    pub(crate) create_operation_id: Option<String>,
    pub(crate) state: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GenerationRebuildLease {
    pub(crate) owner: String,
    pub(crate) fence: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GenerationRebuildSnapshotResult {
    pub(crate) snapshot_sequence: i64,
    pub(crate) snapshot_item_count: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GenerationRebuildFinalizeOutcome {
    Applied,
    AlreadyApplied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GenerationRebuildPromotionCommitClassification {
    Committed,
    NotCommitted,
    RecoveryRequired,
}

fn rebuild_error(code: &'static str, recoverable: bool) -> StorageError {
    StorageError::new(
        code,
        "The persisted vector generation rebuild operation failed.",
        recoverable,
    )
}

fn invalid() -> StorageError {
    rebuild_error("GENERATION_REBUILD_INVALID", false)
}

fn unavailable() -> StorageError {
    rebuild_error("GENERATION_REBUILD_UNAVAILABLE", true)
}

fn conflict() -> StorageError {
    rebuild_error("GENERATION_REBUILD_CONFLICT", true)
}

fn not_found() -> StorageError {
    rebuild_error("GENERATION_REBUILD_JOB_NOT_FOUND", true)
}

fn owner_valid(owner: &str) -> bool {
    !owner.trim().is_empty() && owner.len() <= 256 && !owner.chars().any(char::is_control)
}

fn request_valid(request_id: &str) -> bool {
    !request_id.trim().is_empty()
        && request_id.len() <= 512
        && !request_id.chars().any(char::is_control)
}

fn read_job(row: &Row<'_>) -> rusqlite::Result<GenerationRebuildJobRecord> {
    let dimension: i64 = row.get(4)?;
    Ok(GenerationRebuildJobRecord {
        job_id: row.get(0)?,
        request_id: row.get(1)?,
        generation_id: row.get(2)?,
        descriptor_hash: row.get(3)?,
        dimension: usize::try_from(dimension).unwrap_or_default(),
        generation_state: row.get(5)?,
        generation_authority_epoch: row.get(6)?,
        descriptor_version: row.get(7)?,
        embedding_profile_id: row.get(8)?,
        create_operation_id: row.get(9)?,
        witness_state: row.get(10)?,
        source_active_generation_id: row.get(11)?,
        source_active_authority_epoch: row.get(12)?,
        candidate_authority_epoch: row.get(13)?,
        status: row.get(14)?,
        snapshot_sequence: row.get(15)?,
        catchup_target_sequence: row.get(16)?,
        caught_up_sequence: row.get(17)?,
        promotion_operation_id: row.get(18)?,
        promotion_sequence: row.get(19)?,
        snapshot_item_count: row.get(20)?,
        applied_item_count: row.get(21)?,
        cancel_requested: row.get::<_, i64>(22)? != 0,
        lease_owner: row.get(23)?,
        lease_fence: row.get(24)?,
        lease_expires_at: row.get(25)?,
        last_error_code: row.get(26)?,
    })
}

const JOB_SELECT: &str = "SELECT j.job_id,j.request_id,j.generation_id,g.descriptor_hash,g.dimension,g.state,g.authority_epoch,b.descriptor_version,b.embedding_profile_id,w.create_operation_id,w.state,j.source_active_generation_id,j.source_active_authority_epoch,j.candidate_authority_epoch,j.status,j.snapshot_sequence,j.catchup_target_sequence,j.caught_up_sequence,j.promotion_operation_id,j.promotion_sequence,j.snapshot_item_count,j.applied_item_count,j.cancel_requested,j.lease_owner,j.lease_fence,j.lease_expires_at,j.last_error_code FROM memory_vector_generation_rebuild_job j JOIN memory_vector_generation g ON g.generation_id=j.generation_id JOIN memory_vector_generation_binding b ON b.generation_id=g.generation_id JOIN memory_vector_generation_store_witness w ON w.generation_id=g.generation_id";

impl StorageService {
    pub(crate) fn load_generation_rebuild_job_by_request(
        &self,
        request_id: &str,
    ) -> Result<Option<GenerationRebuildJobRecord>, StorageError> {
        if !request_valid(request_id) {
            return Err(invalid());
        }
        let state = self.state()?;
        state
            .connection
            .query_row(
                &format!("{JOB_SELECT} WHERE j.request_id=?1"),
                [request_id],
                read_job,
            )
            .optional()
            .map_err(|_| unavailable())
    }

    pub(crate) fn load_generation_rebuild_job(
        &self,
        job_id: &str,
    ) -> Result<GenerationRebuildJobRecord, StorageError> {
        if !request_valid(job_id) {
            return Err(invalid());
        }
        let state = self.state()?;
        state
            .connection
            .query_row(
                &format!("{JOB_SELECT} WHERE j.job_id=?1"),
                [job_id],
                read_job,
            )
            .optional()
            .map_err(|_| unavailable())?
            .ok_or_else(not_found)
    }

    pub(crate) fn load_nonterminal_generation_rebuild_job(
        &self,
    ) -> Result<Option<GenerationRebuildJobRecord>, StorageError> {
        let state = self.state()?;
        state
            .connection
            .query_row(
                &format!(
                    "{JOB_SELECT} WHERE j.status IN ('registered','snapshotting','bulk_building','catching_up','verifying','ready') LIMIT 1"
                ),
                [],
                read_job,
            )
            .optional()
            .map_err(|_| unavailable())
    }

    pub(crate) fn list_generation_rebuild_items(
        &self,
        job_id: &str,
    ) -> Result<Vec<GenerationRebuildItemRecord>, StorageError> {
        if !request_valid(job_id) {
            return Err(invalid());
        }
        let state = self.state()?;
        let mut statement = state
            .connection
            .prepare(
                "SELECT job_id,life_id,memory_id,memory_revision,content_hash,canonical_document,state,io_phase,attempt_count,attempt_id,attempt_fence,last_send_disposition,last_error_code
                 FROM memory_vector_generation_rebuild_item
                 WHERE job_id=?1 ORDER BY life_id ASC,memory_id ASC",
            )
            .map_err(|_| unavailable())?;
        let rows = statement
            .query_map([job_id], read_item)
            .map_err(|_| unavailable())?;
        rows.map(|row| row.map_err(|_| unavailable())).collect()
    }

    pub(crate) fn load_generation_store_witness(
        &self,
        generation_id: &str,
    ) -> Result<GenerationStoreWitnessRecord, StorageError> {
        if !request_valid(generation_id) {
            return Err(invalid());
        }
        let state = self.state()?;
        state
            .connection
            .query_row(
                "SELECT generation_id,create_operation_id,state FROM memory_vector_generation_store_witness WHERE generation_id=?1",
                [generation_id],
                |row| {
                    Ok(GenerationStoreWitnessRecord {
                        generation_id: row.get(0)?,
                        create_operation_id: row.get(1)?,
                        state: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|_| unavailable())?
            .ok_or_else(not_found)
    }

    pub(crate) fn mark_generation_store_witness_ready(
        &self,
        job_id: &str,
        lease: &GenerationRebuildLease,
        generation_id: &str,
        create_operation_id: &str,
    ) -> Result<(), StorageError> {
        if !request_valid(job_id)
            || !request_valid(generation_id)
            || !request_valid(create_operation_id)
        {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        assert_live_lease_in(&transaction, job_id, lease, &now)?;
        let changed = transaction
            .execute(
                "UPDATE memory_vector_generation_store_witness
                 SET state='ready',last_error_code=NULL,updated_at=?1
                 WHERE generation_id=(SELECT generation_id FROM memory_vector_generation_rebuild_job WHERE job_id=?4)
                   AND generation_id=?2 AND create_operation_id=?3
                   AND state IN ('create_started','uncertain','ready')",
                params![now, generation_id, create_operation_id, job_id],
            )
            .map_err(|_| unavailable())?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())
    }

    pub(crate) fn mark_generation_store_witness_uncertain(
        &self,
        job_id: &str,
        lease: &GenerationRebuildLease,
        generation_id: &str,
        create_operation_id: &str,
        error_code: &str,
    ) -> Result<(), StorageError> {
        if !request_valid(job_id)
            || !request_valid(generation_id)
            || !request_valid(create_operation_id)
            || error_code.trim().is_empty()
            || error_code.len() > 128
        {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        assert_live_lease_in(&transaction, job_id, lease, &now)?;
        let changed = transaction
            .execute(
                "UPDATE memory_vector_generation_store_witness
                 SET state='uncertain',last_error_code=?1,updated_at=?2
                 WHERE generation_id=(SELECT generation_id FROM memory_vector_generation_rebuild_job WHERE job_id=?5)
                   AND generation_id=?3 AND create_operation_id=?4
                   AND state IN ('absent','create_started','uncertain')",
                params![error_code, now, generation_id, create_operation_id, job_id],
            )
            .map_err(|_| unavailable())?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())
    }

    pub(crate) fn acquire_generation_rebuild_job_lease(
        &self,
        job_id: &str,
        owner: &str,
    ) -> Result<Option<GenerationRebuildLease>, StorageError> {
        if !request_valid(job_id) || !owner_valid(owner) {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        let changed = transaction
            .execute(
                "UPDATE memory_vector_generation_rebuild_job
                 SET lease_owner=?1,
                     lease_fence=CASE WHEN lease_owner=?1 AND lease_expires_at>?2
                                      THEN lease_fence ELSE lease_fence+1 END,
                     lease_expires_at=strftime('%Y-%m-%dT%H:%M:%fZ','now',?3),
                     updated_at=?2
                 WHERE job_id=?4
                   AND status IN ('registered','snapshotting','bulk_building','catching_up','verifying','ready')
                   AND (lease_owner IS NULL OR lease_expires_at<=?2 OR lease_owner=?1)",
                params![owner, now, format!("+{GENERATION_REBUILD_LEASE_SECONDS} seconds"), job_id],
            )
            .map_err(|_| unavailable())?;
        if changed == 0 {
            transaction.commit().map_err(|_| unavailable())?;
            return Ok(None);
        }
        let fence: i64 = transaction
            .query_row(
                "SELECT lease_fence FROM memory_vector_generation_rebuild_job WHERE job_id=?1 AND lease_owner=?2 AND lease_expires_at>?3",
                params![job_id, owner, now],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())?;
        transaction.commit().map_err(|_| unavailable())?;
        Ok(Some(GenerationRebuildLease {
            owner: owner.to_owned(),
            fence,
        }))
    }

    pub(crate) fn request_generation_rebuild_cancel(
        &self,
        job_id: &str,
    ) -> Result<(), StorageError> {
        if !request_valid(job_id) {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        let changed = transaction
            .execute(
                "UPDATE memory_vector_generation_rebuild_job
                 SET cancel_requested=1,updated_at=?1
                 WHERE job_id=?2 AND status IN ('registered','snapshotting','bulk_building','catching_up','verifying','ready')",
                params![now, job_id],
            )
            .map_err(|_| unavailable())?;
        if changed == 0 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())
    }

    pub(crate) fn snapshot_generation_rebuild(
        &self,
        job_id: &str,
        lease: &GenerationRebuildLease,
    ) -> Result<GenerationRebuildSnapshotResult, StorageError> {
        if !request_valid(job_id) || !owner_valid(&lease.owner) || lease.fence < 1 {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        let job = load_job_in(&transaction, job_id)?.ok_or_else(not_found)?;
        assert_live_lease_in(&transaction, job_id, lease, &now)?;
        if job.cancel_requested {
            return Err(conflict());
        }
        if job.generation_state != "building"
            || job.candidate_authority_epoch < 1
            || job.generation_authority_epoch != job.candidate_authority_epoch
            || job.witness_state != "ready"
        {
            return Err(conflict());
        }
        if let Some(snapshot_sequence) = job.snapshot_sequence {
            transaction.commit().map_err(|_| unavailable())?;
            return Ok(GenerationRebuildSnapshotResult {
                snapshot_sequence,
                snapshot_item_count: job.snapshot_item_count,
            });
        }
        if transaction
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM memory_vector_generation_rebuild_item WHERE job_id=?1)",
                [job_id],
                |row| row.get::<_, bool>(0),
            )
            .map_err(|_| unavailable())?
        {
            return Err(conflict());
        }
        let changed = transaction
            .execute(
                "UPDATE memory_vector_generation_rebuild_job SET status='snapshotting',updated_at=?1 WHERE job_id=?2 AND cancel_requested=0",
                params![now, job_id],
            )
            .map_err(|_| unavailable())?;
        if changed != 1 {
            return Err(conflict());
        }
        let snapshot_sequence: i64 = transaction
            .query_row(
                "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())?;
        let mut statement = transaction
            .prepare(
                "SELECT life_id,id,kind,revision,content,summary
                 FROM memory_record
                 WHERE status='confirmed' AND is_sensitive=0
                 ORDER BY life_id ASC,id ASC",
            )
            .map_err(|_| unavailable())?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })
            .map_err(|_| unavailable())?;
        let mut count = 0_i64;
        for row in rows {
            let (life_id, memory_id, kind, revision, content, summary) =
                row.map_err(|_| unavailable())?;
            let Some(selected) = canonical_index_text(summary.as_deref(), &content) else {
                continue;
            };
            let document = selected.trim();
            if document.is_empty()
                || contains_prohibited_content(&content)
                || summary.as_deref().is_some_and(contains_prohibited_content)
                || revision < 1
            {
                continue;
            }
            let content_hash =
                canonical_memory_index_hash(&kind, selected, &content, summary.as_deref());
            transaction
                .execute(
                    "INSERT INTO memory_vector_generation_rebuild_item
                     (job_id,life_id,memory_id,memory_revision,content_hash,canonical_document,state,io_phase,attempt_count,attempt_id,attempt_fence,last_send_disposition,last_error_code,updated_at)
                     VALUES (?1,?2,?3,?4,?5,?6,'pending','not_started',0,NULL,0,NULL,NULL,?7)",
                    params![job_id, life_id, memory_id, revision, content_hash, document, now],
                )
                .map_err(|_| unavailable())?;
            count += 1;
        }
        drop(statement);
        let changed = transaction
            .execute(
                "UPDATE memory_vector_generation_rebuild_job
                 SET status='bulk_building',snapshot_sequence=?1,snapshot_item_count=?2,applied_item_count=0,updated_at=?3
                 WHERE job_id=?4 AND lease_owner=?5 AND lease_fence=?6",
                params![snapshot_sequence, count, now, job_id, lease.owner, lease.fence],
            )
            .map_err(|_| unavailable())?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())?;
        Ok(GenerationRebuildSnapshotResult {
            snapshot_sequence,
            snapshot_item_count: count,
        })
    }

    pub(crate) fn reserve_next_generation_rebuild_item(
        &self,
        job_id: &str,
        lease: &GenerationRebuildLease,
    ) -> Result<Option<GenerationRebuildItemRecord>, StorageError> {
        if !request_valid(job_id) || !owner_valid(&lease.owner) || lease.fence < 1 {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        let job = load_job_in(&transaction, job_id)?.ok_or_else(not_found)?;
        assert_live_lease_in(&transaction, job_id, lease, &now)?;
        if job.cancel_requested {
            return Err(conflict());
        }
        if job.status != "bulk_building" {
            transaction.commit().map_err(|_| unavailable())?;
            return Ok(None);
        }
        let mut item = transaction
            .query_row(
                "SELECT job_id,life_id,memory_id,memory_revision,content_hash,canonical_document,state,io_phase,attempt_count,attempt_id,attempt_fence,last_send_disposition,last_error_code
                 FROM memory_vector_generation_rebuild_item
                 WHERE job_id=?1 AND state IN ('pending','processing')
                 ORDER BY life_id ASC,memory_id ASC LIMIT 1",
                [job_id],
                read_item,
            )
            .optional()
            .map_err(|_| unavailable())?;
        let Some(ref mut item) = item else {
            transaction.commit().map_err(|_| unavailable())?;
            return Ok(None);
        };
        if item.state == "processing" {
            if item.attempt_id.is_none()
                || item.attempt_fence < 1
                || item.canonical_document.is_none()
            {
                return Err(conflict());
            }
        } else {
            if item.attempt_count >= GENERATION_REBUILD_MAX_ATTEMPTS {
                return Err(rebuild_error("GENERATION_REBUILD_ATTEMPT_LIMIT", false));
            }
            let attempt_id = next_attempt_id();
            let attempt_fence = item.attempt_fence.saturating_add(1);
            let changed = transaction
                .execute(
                    "UPDATE memory_vector_generation_rebuild_item
                     SET state='processing',io_phase='reserved',attempt_count=attempt_count+1,attempt_id=?1,attempt_fence=?2,last_send_disposition=NULL,last_error_code=NULL,updated_at=?3
                     WHERE job_id=?4 AND life_id=?5 AND memory_id=?6 AND state='pending' AND io_phase='not_started' AND attempt_count=?7",
                    params![attempt_id, attempt_fence, now, job_id, item.life_id, item.memory_id, item.attempt_count],
                )
                .map_err(|_| unavailable())?;
            if changed != 1 {
                return Err(conflict());
            }
            item.state = "processing".to_owned();
            item.io_phase = "reserved".to_owned();
            item.attempt_count += 1;
            item.attempt_id = Some(attempt_id);
            item.attempt_fence = attempt_fence;
            item.last_send_disposition = None;
            item.last_error_code = None;
        }
        let result = item.clone();
        transaction.commit().map_err(|_| unavailable())?;
        Ok(Some(result))
    }

    pub(crate) fn mark_generation_rebuild_embedding_started(
        &self,
        item: &GenerationRebuildItemRecord,
        lease: &GenerationRebuildLease,
    ) -> Result<(), StorageError> {
        self.update_item_phase(item, lease, "embedding_started")
    }

    pub(crate) fn mark_generation_rebuild_vector_write_started(
        &self,
        item: &GenerationRebuildItemRecord,
        lease: &GenerationRebuildLease,
    ) -> Result<(), StorageError> {
        self.update_item_phase(item, lease, "vector_write_started")
    }

    fn update_item_phase(
        &self,
        item: &GenerationRebuildItemRecord,
        lease: &GenerationRebuildLease,
        phase: &str,
    ) -> Result<(), StorageError> {
        let phase_guard = match phase {
            "embedding_started" => "io_phase IN ('reserved','embedding_started')",
            "vector_write_started" => "io_phase IN ('embedding_started','vector_write_started')",
            _ => return Err(invalid()),
        };
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        assert_live_lease_in(&transaction, &item.job_id, lease, &now)?;
        let update_sql = format!(
            "UPDATE memory_vector_generation_rebuild_item SET io_phase=?1,updated_at=?2
             WHERE job_id=?3 AND life_id=?4 AND memory_id=?5 AND state='processing'
               AND {phase_guard} AND attempt_count=?6 AND attempt_id=?7 AND attempt_fence=?8"
        );
        let changed = transaction
            .execute(
                &update_sql,
                params![
                    phase,
                    now,
                    item.job_id,
                    item.life_id,
                    item.memory_id,
                    item.attempt_count,
                    item.attempt_id,
                    item.attempt_fence
                ],
            )
            .map_err(|_| unavailable())?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())
    }

    pub(crate) fn mark_generation_rebuild_embedding_definitely_not_sent(
        &self,
        item: &GenerationRebuildItemRecord,
        lease: &GenerationRebuildLease,
        error_code: &str,
    ) -> Result<(), StorageError> {
        self.update_embedding_failure(item, lease, error_code, true)
    }

    pub(crate) fn mark_generation_rebuild_embedding_response_failure(
        &self,
        item: &GenerationRebuildItemRecord,
        lease: &GenerationRebuildLease,
        error_code: &str,
    ) -> Result<(), StorageError> {
        self.update_embedding_failure(item, lease, error_code, false)
    }

    fn update_embedding_failure(
        &self,
        item: &GenerationRebuildItemRecord,
        lease: &GenerationRebuildLease,
        error_code: &str,
        definitely_not_sent: bool,
    ) -> Result<(), StorageError> {
        if error_code.trim().is_empty() || error_code.len() > 128 {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        assert_live_lease_in(&transaction, &item.job_id, lease, &now)?;
        let (next_state, next_phase, disposition, phase_guard) = if definitely_not_sent {
            (
                "processing",
                "reserved",
                Some("definitely_not_sent"),
                "io_phase IN ('reserved','embedding_started')",
            )
        } else {
            (
                "pending",
                "not_started",
                None,
                "io_phase='embedding_started'",
            )
        };
        let update_sql = format!(
            "UPDATE memory_vector_generation_rebuild_item
             SET state=?1,io_phase=?2,last_send_disposition=?3,last_error_code=?4,updated_at=?5
             WHERE job_id=?6 AND life_id=?7 AND memory_id=?8 AND state='processing'
               AND {phase_guard} AND attempt_count=?9 AND attempt_id=?10 AND attempt_fence=?11"
        );
        let changed = transaction
            .execute(
                &update_sql,
                params![
                    next_state,
                    next_phase,
                    disposition,
                    error_code,
                    now,
                    item.job_id,
                    item.life_id,
                    item.memory_id,
                    item.attempt_count,
                    item.attempt_id,
                    item.attempt_fence
                ],
            )
            .map_err(|_| unavailable())?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())
    }

    pub(crate) fn finalize_generation_rebuild_item(
        &self,
        job: &GenerationRebuildJobRecord,
        item: &GenerationRebuildItemRecord,
        lease: &GenerationRebuildLease,
    ) -> Result<GenerationRebuildFinalizeOutcome, StorageError> {
        if item.job_id != job.job_id || job.generation_state != "building" {
            return Err(conflict());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        assert_live_lease_in(&transaction, &item.job_id, lease, &now)?;
        let current: Option<(i64, String)> = transaction
            .query_row(
                "SELECT memory_revision,content_hash FROM memory_vector_generation_item WHERE generation_id=?1 AND life_id=?2 AND memory_id=?3",
                params![job.generation_id, item.life_id, item.memory_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(|_| unavailable())?;
        if let Some((revision, hash)) = current {
            if revision != item.memory_revision || hash != item.content_hash {
                return Err(conflict());
            }
        } else {
            transaction
                .execute(
                    "INSERT INTO memory_vector_generation_item (generation_id,life_id,memory_id,memory_revision,content_hash,updated_at) VALUES (?1,?2,?3,?4,?5,?6)",
                    params![job.generation_id, item.life_id, item.memory_id, item.memory_revision, item.content_hash, now],
                )
                .map_err(|_| unavailable())?;
        }
        let changed = transaction
            .execute(
                "UPDATE memory_vector_generation_rebuild_item
                 SET state='applied',io_phase='finalized',canonical_document=NULL,last_error_code=NULL,updated_at=?1
                 WHERE job_id=?2 AND life_id=?3 AND memory_id=?4
                   AND state='processing' AND io_phase='vector_write_started'
                   AND attempt_id=?5 AND attempt_fence=?6",
                params![now, item.job_id, item.life_id, item.memory_id, item.attempt_id, item.attempt_fence],
            )
            .map_err(|_| unavailable())?;
        if changed == 0 {
            let applied: bool = transaction
                .query_row(
                    "SELECT state='applied' FROM memory_vector_generation_rebuild_item WHERE job_id=?1 AND life_id=?2 AND memory_id=?3",
                    params![item.job_id, item.life_id, item.memory_id],
                    |row| row.get(0),
                )
                .map_err(|_| unavailable())?;
            if applied {
                transaction.commit().map_err(|_| unavailable())?;
                return Ok(GenerationRebuildFinalizeOutcome::AlreadyApplied);
            }
            return Err(conflict());
        }
        let job_changed = transaction
            .execute(
                "UPDATE memory_vector_generation_rebuild_job
                 SET applied_item_count=applied_item_count+1,updated_at=?1
                 WHERE job_id=?2 AND lease_owner=?3 AND lease_fence=?4 AND status='bulk_building'",
                params![now, item.job_id, lease.owner, lease.fence],
            )
            .map_err(|_| unavailable())?;
        if job_changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())?;
        Ok(GenerationRebuildFinalizeOutcome::Applied)
    }

    pub(crate) fn fail_generation_rebuild_after_unknown(
        &self,
        item: &GenerationRebuildItemRecord,
        lease: &GenerationRebuildLease,
        error_code: &str,
        candidate_epoch: i64,
    ) -> Result<(), StorageError> {
        self.terminalize_generation_rebuild(
            item.job_id.as_str(),
            lease,
            "failed",
            error_code,
            candidate_epoch,
            Some(item),
            None,
        )
    }

    pub(crate) fn fail_generation_rebuild_after_catchup_unknown(
        &self,
        item: &GenerationRebuildCatchupItemRecord,
        lease: &GenerationRebuildLease,
        error_code: &str,
        candidate_epoch: i64,
    ) -> Result<(), StorageError> {
        self.terminalize_generation_rebuild(
            item.job_id.as_str(),
            lease,
            "failed",
            error_code,
            candidate_epoch,
            None,
            Some(item),
        )
    }

    pub(crate) fn fail_generation_rebuild(
        &self,
        job_id: &str,
        lease: &GenerationRebuildLease,
        error_code: &str,
        candidate_epoch: i64,
    ) -> Result<(), StorageError> {
        self.terminalize_generation_rebuild(
            job_id,
            lease,
            "failed",
            error_code,
            candidate_epoch,
            None,
            None,
        )
    }

    pub(crate) fn cancel_generation_rebuild(
        &self,
        job_id: &str,
        lease: &GenerationRebuildLease,
        candidate_epoch: i64,
    ) -> Result<(), StorageError> {
        self.terminalize_generation_rebuild(
            job_id,
            lease,
            "cancelled",
            "GENERATION_REBUILD_CANCELLED",
            candidate_epoch,
            None,
            None,
        )
    }

    fn terminalize_generation_rebuild(
        &self,
        job_id: &str,
        lease: &GenerationRebuildLease,
        status: &str,
        error_code: &str,
        candidate_epoch: i64,
        uncertain_item: Option<&GenerationRebuildItemRecord>,
        uncertain_catchup_item: Option<&GenerationRebuildCatchupItemRecord>,
    ) -> Result<(), StorageError> {
        if !matches!(status, "failed" | "cancelled")
            || !request_valid(job_id)
            || !owner_valid(&lease.owner)
            || candidate_epoch < 1
            || error_code.trim().is_empty()
            || error_code.len() > 128
        {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        assert_live_lease_in(&transaction, job_id, lease, &now)?;
        if let Some(item) = uncertain_item {
            let changed = transaction
                .execute(
                    "UPDATE memory_vector_generation_rebuild_item
                     SET state='uncertain',last_send_disposition='possibly_sent',last_error_code=?1,updated_at=?2
                     WHERE job_id=?3 AND life_id=?4 AND memory_id=?5 AND state='processing' AND attempt_id=?6 AND attempt_fence=?7",
                    params![error_code, now, item.job_id, item.life_id, item.memory_id, item.attempt_id, item.attempt_fence],
                )
                .map_err(|_| unavailable())?;
            if changed != 1 {
                return Err(conflict());
            }
        }
        if let Some(item) = uncertain_catchup_item {
            let changed = transaction
                .execute(
                    "UPDATE memory_vector_generation_rebuild_catchup_item
                     SET state='uncertain',last_send_disposition='possibly_sent',last_error_code=?1,updated_at=?2
                     WHERE job_id=?3 AND source_outbox_id=?4 AND mutation_sequence=?5
                       AND state='processing' AND attempt_id=?6 AND attempt_fence=?7",
                    params![
                        error_code,
                        now,
                        item.job_id,
                        item.source_outbox_id,
                        item.mutation_sequence,
                        item.attempt_id,
                        item.attempt_fence
                    ],
                )
                .map_err(|_| unavailable())?;
            if changed != 1 {
                return Err(conflict());
            }
        }
        transaction
            .execute(
                "UPDATE memory_vector_generation_rebuild_catchup_item
                 SET state='uncertain',last_send_disposition='possibly_sent',last_error_code=?1,updated_at=?2
                 WHERE job_id=?3 AND state='processing'
                   AND io_phase IN ('embedding_started','vector_write_started')",
                params![error_code, now, job_id],
            )
            .map_err(|_| unavailable())?;
        let failed_job = load_job_in(&transaction, job_id)?.ok_or_else(not_found)?;
        requeue_failed_generation_outbox_in(&transaction, &failed_job, &now)?;
        let generation_changed = transaction
            .execute(
                "UPDATE memory_vector_generation
                 SET state='failed',authority_epoch=authority_epoch+1,updated_at=?1
                 WHERE generation_id=(SELECT generation_id FROM memory_vector_generation_rebuild_job WHERE job_id=?2)
                   AND state='building' AND authority_epoch=?3",
                params![now, job_id, candidate_epoch],
            )
            .map_err(|_| unavailable())?;
        if generation_changed != 1 {
            return Err(conflict());
        }
        let job_changed = transaction
            .execute(
                "UPDATE memory_vector_generation_rebuild_job
                 SET status=?1,last_error_code=?2,completed_at=?3,updated_at=?3,lease_owner=NULL,lease_expires_at=NULL
                 WHERE job_id=?4 AND lease_owner=?5 AND lease_fence=?6
                   AND status IN ('registered','snapshotting','bulk_building','catching_up','verifying','ready')",
                params![status, error_code, now, job_id, lease.owner, lease.fence],
            )
            .map_err(|_| unavailable())?;
        if job_changed != 1 {
            return Err(conflict());
        }
        transaction
            .execute(
                "UPDATE memory_vector_generation_rebuild_item SET canonical_document=NULL WHERE job_id=?1",
                [job_id],
            )
            .map_err(|_| unavailable())?;
        transaction
            .execute(
                "UPDATE memory_vector_generation_rebuild_catchup_item SET canonical_document=NULL WHERE job_id=?1",
                [job_id],
            )
            .map_err(|_| unavailable())?;
        transaction.commit().map_err(|_| unavailable())
    }

    pub(crate) fn finish_generation_rebuild_c_handoff(
        &self,
        job_id: &str,
        lease: &GenerationRebuildLease,
    ) -> Result<(), StorageError> {
        if !request_valid(job_id) || !owner_valid(&lease.owner) {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        assert_live_lease_in(&transaction, job_id, lease, &now)?;
        let job = load_job_in(&transaction, job_id)?.ok_or_else(not_found)?;
        if job.generation_state != "building"
            || job.candidate_authority_epoch < 1
            || job.generation_authority_epoch != job.candidate_authority_epoch
            || job.witness_state != "ready"
            || job.status != "bulk_building"
            || job.snapshot_sequence.is_none()
            || job.snapshot_item_count != job.applied_item_count
        {
            return Err(conflict());
        }
        let remaining: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_generation_rebuild_item WHERE job_id=?1 AND state<>'applied'",
                [job_id],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())?;
        if remaining != 0 {
            return Err(conflict());
        }
        let snapshot_sequence = job.snapshot_sequence.expect("checked above");
        let changed = transaction
            .execute(
                "UPDATE memory_vector_generation_rebuild_job
                 SET status='catching_up',catchup_target_sequence=?1,caught_up_sequence=?1,updated_at=?2
                 WHERE job_id=?3 AND lease_owner=?4 AND lease_fence=?5 AND status='bulk_building' AND cancel_requested=0",
                params![snapshot_sequence, now, job_id, lease.owner, lease.fence],
            )
            .map_err(|_| unavailable())?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())
    }

    pub(crate) fn list_generation_rebuild_catchup_items(
        &self,
        job_id: &str,
    ) -> Result<Vec<GenerationRebuildCatchupItemRecord>, StorageError> {
        if !request_valid(job_id) {
            return Err(invalid());
        }
        let state = self.state()?;
        let mut statement = state
            .connection
            .prepare(
                "SELECT job_id,source_outbox_id,life_id,memory_id,mutation_sequence,desired_action,
                    target_revision,target_content_hash,canonical_document,state,io_phase,
                    attempt_count,attempt_id,attempt_fence,last_send_disposition,last_error_code
             FROM memory_vector_generation_rebuild_catchup_item
             WHERE job_id=?1 ORDER BY mutation_sequence,source_outbox_id",
            )
            .map_err(|_| unavailable())?;
        let items = statement
            .query_map([job_id], read_catchup_item)
            .map_err(|_| unavailable())?
            .map(|row| row.map_err(|_| unavailable()))
            .collect();
        items
    }

    pub(crate) fn generation_rebuild_catchup_item_is_current(
        &self,
        item: &GenerationRebuildCatchupItemRecord,
    ) -> Result<bool, StorageError> {
        let state = self.state()?;
        state
            .connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1 FROM memory_vector_sync_outbox
                   WHERE id=?1 AND life_id=?2 AND memory_id=?3
                     AND mutation_sequence=?4 AND desired_action=?5
                     AND target_revision IS ?6
                     AND target_content_hash IS ?7
                     AND migration_disposition IS NULL
                )",
                params![
                    item.source_outbox_id,
                    item.life_id,
                    item.memory_id,
                    item.mutation_sequence,
                    item.desired_action,
                    item.target_revision,
                    item.target_content_hash,
                ],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())
    }

    pub(crate) fn list_generation_rebuild_generation_items(
        &self,
        generation_id: &str,
    ) -> Result<Vec<GenerationRebuildEligibleItem>, StorageError> {
        if !request_valid(generation_id) {
            return Err(invalid());
        }
        let state = self.state()?;
        generation_items_in_connection(&state.connection, generation_id)
    }

    /// Materializes the exact *current* coalesced outbox identities through a
    /// target clock. Existing historical rows are never rewritten into a new
    /// mutation; safe not-sent predecessors become `superseded` instead.
    pub(crate) fn materialize_generation_rebuild_catchup(
        &self,
        job_id: &str,
        lease: &GenerationRebuildLease,
        target_sequence: i64,
    ) -> Result<usize, StorageError> {
        if !request_valid(job_id) || !owner_valid(&lease.owner) || target_sequence < 0 {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        let job = load_job_in(&transaction, job_id)?.ok_or_else(not_found)?;
        assert_catchup_authority_in(&transaction, &job, lease, &now)?;
        let mut source = transaction.prepare(
            "SELECT id,life_id,memory_id,mutation_sequence,desired_action,target_revision,target_content_hash
             FROM memory_vector_sync_outbox
             WHERE migration_disposition IS NULL AND mutation_sequence>0 AND mutation_sequence<=?1
             ORDER BY mutation_sequence,id",
        ).map_err(|_| unavailable())?;
        let rows = source
            .query_map([target_sequence], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(|_| unavailable())?;
        let source_rows = rows
            .map(|row| row.map_err(|_| unavailable()))
            .collect::<Result<Vec<_>, _>>()?;
        drop(source);
        let mut count = 0;
        for (outbox_id, life_id, memory_id, mutation, action, revision, hash) in source_rows {
            let (revision, hash, document) = if action == "delete" {
                if revision.is_some() || hash.is_some() {
                    return Err(conflict());
                }
                (None, None, None)
            } else if action == "upsert" {
                let (kind, current_revision, content, summary, status, sensitive): (String, i64, String, Option<String>, String, i64) = transaction.query_row(
                    "SELECT kind,revision,content,summary,status,is_sensitive FROM memory_record WHERE life_id=?1 AND id=?2",
                    params![life_id, memory_id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
                ).map_err(|_| conflict())?;
                let Some(selected) = canonical_index_text(summary.as_deref(), &content) else {
                    return Err(conflict());
                };
                let canonical = selected.trim();
                let canonical_hash =
                    canonical_memory_index_hash(&kind, selected, &content, summary.as_deref());
                if status != "confirmed"
                    || sensitive != 0
                    || contains_prohibited_content(&content)
                    || summary.as_deref().is_some_and(contains_prohibited_content)
                    || canonical.is_empty()
                    || revision != Some(current_revision)
                    || hash.as_deref() != Some(canonical_hash.as_str())
                {
                    return Err(conflict());
                }
                (
                    Some(current_revision),
                    Some(canonical_hash),
                    Some(canonical.to_owned()),
                )
            } else {
                return Err(conflict());
            };

            let unsafe_old: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM memory_vector_generation_rebuild_catchup_item
                 WHERE job_id=?1 AND source_outbox_id=?2 AND mutation_sequence<>?3
                   AND state NOT IN ('applied','superseded')
                   AND (state='uncertain' OR io_phase IN ('embedding_started','vector_write_started') OR last_send_disposition='possibly_sent')",
                params![job_id,outbox_id,mutation], |row| row.get(0),
            ).map_err(|_| unavailable())?;
            if unsafe_old != 0 {
                transaction
                    .execute(
                        "UPDATE memory_vector_generation_rebuild_catchup_item
                         SET state='uncertain',last_send_disposition='possibly_sent',
                             last_error_code='GENERATION_REBUILD_CATCHUP_RESULT_UNKNOWN',updated_at=?1
                         WHERE job_id=?2 AND source_outbox_id=?3 AND mutation_sequence<>?4
                           AND state NOT IN ('applied','superseded')
                           AND (state='uncertain' OR io_phase IN ('embedding_started','vector_write_started') OR last_send_disposition='possibly_sent')",
                        params![now,job_id,outbox_id,mutation],
                    )
                    .map_err(|_| unavailable())?;
                transaction.commit().map_err(|_| unavailable())?;
                return Err(StorageError::new(
                    "GENERATION_REBUILD_CATCHUP_RESULT_UNKNOWN",
                    "A predecessor catch-up attempt has an unresolved external result.",
                    false,
                ));
            }
            transaction.execute(
                "UPDATE memory_vector_generation_rebuild_catchup_item
                 SET state='superseded',canonical_document=NULL,io_phase='finalized',updated_at=?1
                 WHERE job_id=?2 AND source_outbox_id=?3 AND mutation_sequence<>?4
                   AND state IN ('pending','processing','applied')
                   AND (io_phase IN ('not_started','reserved','finalized'))
                   AND (last_send_disposition IS NULL OR last_send_disposition='definitely_not_sent')",
                params![now,job_id,outbox_id,mutation],
            ).map_err(|_| unavailable())?;
            let inserted = transaction.execute(
                "INSERT OR IGNORE INTO memory_vector_generation_rebuild_catchup_item
                 (job_id,source_outbox_id,life_id,memory_id,mutation_sequence,desired_action,target_revision,target_content_hash,canonical_document,state,io_phase,updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,'pending','not_started',?10)",
                params![job_id,outbox_id,life_id,memory_id,mutation,action,revision,hash,document,now],
            ).map_err(|_| unavailable())?;
            count += inserted;
        }
        transaction.execute(
            "UPDATE memory_vector_generation_rebuild_job SET status='catching_up',catchup_target_sequence=?1,updated_at=?2
             WHERE job_id=?3 AND lease_owner=?4 AND lease_fence=?5",
            params![target_sequence,now,job_id,lease.owner,lease.fence],
        ).map_err(|_| unavailable())?;
        transaction.commit().map_err(|_| unavailable())?;
        Ok(count)
    }

    pub(crate) fn generation_rebuild_mutation_clock(&self) -> Result<i64, StorageError> {
        let state = self.state()?;
        state
            .connection
            .query_row(
                "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())
    }

    pub(crate) fn reserve_next_generation_rebuild_catchup_item(
        &self,
        job_id: &str,
        lease: &GenerationRebuildLease,
    ) -> Result<Option<GenerationRebuildCatchupItemRecord>, StorageError> {
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        let job = load_job_in(&transaction, job_id)?.ok_or_else(not_found)?;
        assert_catchup_authority_in(&transaction, &job, lease, &now)?;
        let item = transaction.query_row(
            "SELECT c.job_id,c.source_outbox_id,c.life_id,c.memory_id,c.mutation_sequence,c.desired_action,c.target_revision,c.target_content_hash,c.canonical_document,c.state,c.io_phase,c.attempt_count,c.attempt_id,c.attempt_fence,c.last_send_disposition,c.last_error_code
              FROM memory_vector_generation_rebuild_catchup_item c
              WHERE c.job_id=?1 AND c.attempt_count<5
                AND ((c.state='pending' AND c.io_phase='not_started')
                     OR (c.state='processing' AND c.io_phase='reserved'
                         AND (c.last_send_disposition IS NULL OR c.last_send_disposition='definitely_not_sent')))
                AND EXISTS (SELECT 1 FROM memory_vector_sync_outbox o WHERE o.id=c.source_outbox_id AND o.mutation_sequence=c.mutation_sequence AND o.desired_action=c.desired_action AND o.life_id=c.life_id AND o.memory_id=c.memory_id)
              ORDER BY c.mutation_sequence,c.source_outbox_id LIMIT 1",
            [job_id], read_catchup_item,
        ).optional().map_err(|_| unavailable())?;
        let Some(mut item) = item else {
            transaction.commit().map_err(|_| unavailable())?;
            return Ok(None);
        };
        if item.state == "pending" {
            let attempt_id = next_attempt_id();
            let changed = transaction.execute(
                "UPDATE memory_vector_generation_rebuild_catchup_item
                 SET state='processing',io_phase='reserved',attempt_count=attempt_count+1,attempt_id=?1,attempt_fence=attempt_fence+1,last_send_disposition=NULL,last_error_code=NULL,updated_at=?2
                 WHERE job_id=?3 AND source_outbox_id=?4 AND mutation_sequence=?5 AND state='pending' AND io_phase='not_started' AND attempt_count<5",
                params![attempt_id,now,item.job_id,item.source_outbox_id,item.mutation_sequence],
            ).map_err(|_| unavailable())?;
            if changed != 1 {
                return Err(conflict());
            }
            item.state = "processing".into();
            item.io_phase = "reserved".into();
            item.attempt_count += 1;
            item.attempt_fence += 1;
            item.attempt_id = Some(attempt_id);
            item.last_send_disposition = None;
            item.last_error_code = None;
        } else if item.state == "processing"
            && item.io_phase == "reserved"
            && (item.last_send_disposition.is_none()
                || item.last_send_disposition.as_deref() == Some("definitely_not_sent"))
        {
            let changed = transaction.execute(
                "UPDATE memory_vector_generation_rebuild_catchup_item
                 SET last_send_disposition=NULL,last_error_code=NULL,updated_at=?1
                 WHERE job_id=?2 AND source_outbox_id=?3 AND mutation_sequence=?4
                   AND state='processing' AND io_phase='reserved'
                   AND (last_send_disposition IS NULL OR last_send_disposition='definitely_not_sent')
                   AND attempt_id=?5 AND attempt_fence=?6",
                params![now,item.job_id,item.source_outbox_id,item.mutation_sequence,item.attempt_id,item.attempt_fence],
            ).map_err(|_| unavailable())?;
            if changed != 1 {
                return Err(conflict());
            }
            item.last_send_disposition = None;
            item.last_error_code = None;
        } else {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())?;
        Ok(Some(item))
    }

    pub(crate) fn finalize_generation_rebuild_catchup_item(
        &self,
        job: &GenerationRebuildJobRecord,
        item: &GenerationRebuildCatchupItemRecord,
        lease: &GenerationRebuildLease,
    ) -> Result<GenerationRebuildFinalizeOutcome, StorageError> {
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        assert_catchup_authority_in(&transaction, job, lease, &now)?;
        assert_catchup_target_authority_in(&transaction, item)?;
        let exact_generation_effect: bool = match item.desired_action.as_str() {
            "delete" => transaction
                .query_row(
                    "SELECT NOT EXISTS(
                        SELECT 1 FROM memory_vector_generation_item
                         WHERE generation_id=?1 AND life_id=?2 AND memory_id=?3
                    )",
                    params![job.generation_id, item.life_id, item.memory_id],
                    |row| row.get(0),
                )
                .map_err(|_| unavailable())?,
            "upsert" => transaction
                .query_row(
                    "SELECT EXISTS(
                        SELECT 1 FROM memory_vector_generation_item
                         WHERE generation_id=?1 AND life_id=?2 AND memory_id=?3
                           AND memory_revision=?4 AND content_hash=?5
                    )",
                    params![
                        job.generation_id,
                        item.life_id,
                        item.memory_id,
                        item.target_revision,
                        item.target_content_hash,
                    ],
                    |row| row.get(0),
                )
                .map_err(|_| unavailable())?,
            _ => false,
        };
        if !exact_generation_effect {
            return Err(catchup_final_proof_failed());
        }
        let changed = transaction.execute(
            "UPDATE memory_vector_generation_rebuild_catchup_item
             SET state='applied',io_phase='finalized',canonical_document=NULL,updated_at=?1
             WHERE job_id=?2 AND source_outbox_id=?3 AND mutation_sequence=?4 AND state='processing' AND attempt_id=?5 AND attempt_fence=?6",
            params![now,item.job_id,item.source_outbox_id,item.mutation_sequence,item.attempt_id,item.attempt_fence],
        ).map_err(|_| unavailable())?;
        if changed == 0 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())?;
        Ok(GenerationRebuildFinalizeOutcome::Applied)
    }

    pub(crate) fn mark_generation_rebuild_catchup_phase(
        &self,
        item: &GenerationRebuildCatchupItemRecord,
        lease: &GenerationRebuildLease,
        phase: &str,
    ) -> Result<(), StorageError> {
        if !matches!(phase, "embedding_started" | "vector_write_started") {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        let job = load_job_in(&transaction, &item.job_id)?.ok_or_else(not_found)?;
        assert_catchup_authority_in(&transaction, &job, lease, &now)?;
        let changed = transaction.execute(
            "UPDATE memory_vector_generation_rebuild_catchup_item SET io_phase=?1,updated_at=?2
             WHERE job_id=?3 AND source_outbox_id=?4 AND mutation_sequence=?5
               AND state='processing' AND attempt_id=?6 AND attempt_fence=?7
               AND ((?1='embedding_started' AND io_phase='reserved')
                    OR (?1='vector_write_started' AND io_phase IN ('reserved','embedding_started'))) ",
            params![phase,now,item.job_id,item.source_outbox_id,item.mutation_sequence,item.attempt_id,item.attempt_fence],
        ).map_err(|_| unavailable())?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())
    }

    pub(crate) fn mark_generation_rebuild_catchup_embedding_definitely_not_sent(
        &self,
        item: &GenerationRebuildCatchupItemRecord,
        lease: &GenerationRebuildLease,
        error_code: &str,
    ) -> Result<(), StorageError> {
        self.update_catchup_embedding_failure(item, lease, error_code, true)
    }

    pub(crate) fn mark_generation_rebuild_catchup_embedding_response_failure(
        &self,
        item: &GenerationRebuildCatchupItemRecord,
        lease: &GenerationRebuildLease,
        error_code: &str,
    ) -> Result<(), StorageError> {
        self.update_catchup_embedding_failure(item, lease, error_code, false)
    }

    pub(crate) fn mark_generation_rebuild_catchup_delete_definitely_not_sent(
        &self,
        item: &GenerationRebuildCatchupItemRecord,
        lease: &GenerationRebuildLease,
        error_code: &str,
    ) -> Result<(), StorageError> {
        if error_code.trim().is_empty() || error_code.len() > 128 {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        let job = load_job_in(&transaction, &item.job_id)?.ok_or_else(not_found)?;
        assert_catchup_authority_in(&transaction, &job, lease, &now)?;
        let changed = transaction
            .execute(
                "UPDATE memory_vector_generation_rebuild_catchup_item
                 SET io_phase='reserved',last_send_disposition='definitely_not_sent',
                     last_error_code=?1,updated_at=?2
                 WHERE job_id=?3 AND source_outbox_id=?4 AND mutation_sequence=?5
                   AND state='processing' AND io_phase='vector_write_started'
                   AND attempt_id=?6 AND attempt_fence=?7",
                params![
                    error_code,
                    now,
                    item.job_id,
                    item.source_outbox_id,
                    item.mutation_sequence,
                    item.attempt_id,
                    item.attempt_fence,
                ],
            )
            .map_err(|_| unavailable())?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())
    }

    fn update_catchup_embedding_failure(
        &self,
        item: &GenerationRebuildCatchupItemRecord,
        lease: &GenerationRebuildLease,
        error_code: &str,
        definitely_not_sent: bool,
    ) -> Result<(), StorageError> {
        if error_code.trim().is_empty() || error_code.len() > 128 {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        let job = load_job_in(&transaction, &item.job_id)?.ok_or_else(not_found)?;
        assert_catchup_authority_in(&transaction, &job, lease, &now)?;
        let (next_state, next_phase, disposition, phase_guard) = if definitely_not_sent {
            (
                "processing",
                "reserved",
                Some("definitely_not_sent"),
                "io_phase IN ('reserved','embedding_started')",
            )
        } else {
            (
                "pending",
                "not_started",
                None,
                "io_phase='embedding_started'",
            )
        };
        let update_sql = format!(
            "UPDATE memory_vector_generation_rebuild_catchup_item
             SET state=?1,io_phase=?2,last_send_disposition=?3,last_error_code=?4,updated_at=?5
             WHERE job_id=?6 AND source_outbox_id=?7 AND mutation_sequence=?8
               AND state='processing' AND {phase_guard}
               AND attempt_id=?9 AND attempt_fence=?10"
        );
        let changed = transaction
            .execute(
                &update_sql,
                params![
                    next_state,
                    next_phase,
                    disposition,
                    error_code,
                    now,
                    item.job_id,
                    item.source_outbox_id,
                    item.mutation_sequence,
                    item.attempt_id,
                    item.attempt_fence
                ],
            )
            .map_err(|_| unavailable())?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())
    }

    pub(crate) fn write_generation_rebuild_catchup_metadata(
        &self,
        job: &GenerationRebuildJobRecord,
        item: &GenerationRebuildCatchupItemRecord,
        lease: &GenerationRebuildLease,
    ) -> Result<(), StorageError> {
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        assert_catchup_authority_in(&transaction, job, lease, &now)?;
        assert_catchup_target_authority_in(&transaction, item)?;
        if item.desired_action == "upsert" {
            let revision = item.target_revision.ok_or_else(conflict)?;
            let hash = item.target_content_hash.as_deref().ok_or_else(conflict)?;
            let changed = transaction.execute(
                "INSERT INTO memory_vector_generation_item (generation_id,life_id,memory_id,memory_revision,content_hash,updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6)
                 ON CONFLICT(generation_id,life_id,memory_id) DO UPDATE SET memory_revision=excluded.memory_revision,content_hash=excluded.content_hash,updated_at=excluded.updated_at",
                params![job.generation_id,item.life_id,item.memory_id,revision,hash,now],
            ).map_err(|_| unavailable())?;
            if changed != 1 {
                return Err(conflict());
            }
        } else if item.desired_action == "delete" {
            transaction.execute(
                "DELETE FROM memory_vector_generation_item WHERE generation_id=?1 AND life_id=?2 AND memory_id=?3",
                params![job.generation_id,item.life_id,item.memory_id],
            ).map_err(|_| unavailable())?;
        } else {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())
    }

    pub(crate) fn advance_generation_rebuild_catchup(
        &self,
        job_id: &str,
        lease: &GenerationRebuildLease,
        target_sequence: i64,
    ) -> Result<bool, StorageError> {
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        let job = load_job_in(&transaction, job_id)?.ok_or_else(not_found)?;
        assert_catchup_authority_in(&transaction, &job, lease, &now)?;
        let clock: i64 = transaction
            .query_row(
                "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())?;
        if clock != target_sequence {
            transaction.commit().map_err(|_| unavailable())?;
            return Ok(false);
        }
        if !catchup_target_is_complete_in(&transaction, job_id, target_sequence)? {
            transaction.commit().map_err(|_| unavailable())?;
            return Ok(false);
        }
        verify_sqlite_final_set_in(&transaction, &job.generation_id)?;
        let changed = transaction.execute(
            "UPDATE memory_vector_generation_rebuild_job SET caught_up_sequence=?1,catchup_target_sequence=?1,status='verifying',updated_at=?2
             WHERE job_id=?3 AND lease_owner=?4 AND lease_fence=?5 AND status='catching_up'",
            params![target_sequence,now,job_id,lease.owner,lease.fence],
        ).map_err(|_| unavailable())?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())?;
        Ok(true)
    }

    pub(crate) fn mark_generation_rebuild_ready(
        &self,
        job_id: &str,
        lease: &GenerationRebuildLease,
        target_sequence: i64,
    ) -> Result<(), StorageError> {
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        let job = load_job_in(&transaction, job_id)?.ok_or_else(not_found)?;
        assert_catchup_authority_in(&transaction, &job, lease, &now)?;
        let clock: i64 = transaction
            .query_row(
                "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())?;
        let incomplete: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_generation_rebuild_item
             WHERE job_id=?1 AND (state<>'applied' OR io_phase<>'finalized')",
                [job_id],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())?;
        if clock != target_sequence {
            let changed = transaction
                .execute(
                    "UPDATE memory_vector_generation_rebuild_job
                     SET status='catching_up',catchup_target_sequence=?1,caught_up_sequence=NULL,updated_at=?2
                     WHERE job_id=?3 AND status='verifying' AND lease_owner=?4 AND lease_fence=?5",
                    params![clock, now, job_id, lease.owner, lease.fence],
                )
                .map_err(|_| unavailable())?;
            if changed != 1 {
                return Err(conflict());
            }
            transaction.commit().map_err(|_| unavailable())?;
            return Err(StorageError::new(
                "GENERATION_REBUILD_MUTATION_RACE",
                "A new authoritative mutation arrived during catch-up verification.",
                true,
            ));
        }
        if incomplete != 0
            || job.caught_up_sequence != Some(target_sequence)
            || !catchup_target_is_complete_in(&transaction, job_id, target_sequence)?
        {
            transaction.commit().map_err(|_| unavailable())?;
            return Err(conflict());
        }
        verify_sqlite_final_set_in(&transaction, &job.generation_id)?;
        let changed = transaction.execute(
            "UPDATE memory_vector_generation_rebuild_job SET status='ready',catchup_target_sequence=?1,caught_up_sequence=?1,updated_at=?2
             WHERE job_id=?3 AND status='verifying' AND lease_owner=?4 AND lease_fence=?5",
            params![target_sequence,now,job_id,lease.owner,lease.fence],
        ).map_err(|_| unavailable())?;
        if changed != 1 {
            return Err(conflict());
        }
        transaction.commit().map_err(|_| unavailable())
    }

    /// The cutover is intentionally one caller-owned storage transaction. A
    /// transient NULL pointer exists only before this transaction commits.
    pub(crate) fn promote_generation_rebuild(
        &self,
        job_id: &str,
        lease: &GenerationRebuildLease,
        late_delete_lease: &late_delete_resolution::LateDeleteRuntimeLease,
        target_sequence: i64,
        operation_id: &str,
    ) -> Result<(), StorageError> {
        if !request_valid(operation_id) {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| unavailable())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)?;
        late_delete_resolution::assert_runtime_lease_current_in(
            &transaction,
            late_delete_lease,
            &now,
        )?;
        let job = load_job_in(&transaction, job_id)?.ok_or_else(not_found)?;
        assert_catchup_authority_in(&transaction, &job, lease, &now)?;
        assert_source_authority_in(&transaction, &job)?;
        if job.status != "ready" || job.caught_up_sequence != Some(target_sequence) {
            return Err(conflict());
        }
        let clock: i64 = transaction
            .query_row(
                "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())?;
        if clock != target_sequence {
            let changed = transaction
                .execute(
                    "UPDATE memory_vector_generation_rebuild_job
                     SET status='catching_up',catchup_target_sequence=?1,caught_up_sequence=NULL,updated_at=?2
                     WHERE job_id=?3 AND status='ready' AND lease_owner=?4 AND lease_fence=?5",
                    params![clock, now, job_id, lease.owner, lease.fence],
                )
                .map_err(|_| unavailable())?;
            if changed != 1 {
                return Err(conflict());
            }
            transaction.commit().map_err(|_| unavailable())?;
            return Err(StorageError::new(
                "GENERATION_REBUILD_MUTATION_RACE",
                "A new authoritative mutation arrived during promotion proof.",
                true,
            ));
        }
        if !catchup_target_is_complete_in(&transaction, job_id, target_sequence)? {
            return Err(conflict());
        }
        verify_sqlite_final_set_in(&transaction, &job.generation_id)?;
        let pointer: Option<String> = transaction.query_row("SELECT active_generation_id FROM memory_vector_generation_authority WHERE singleton=1", [], |row| row.get(0)).map_err(|_| unavailable())?;
        if pointer != job.source_active_generation_id {
            return Err(conflict());
        }
        transaction.execute(
            "INSERT INTO memory_vector_generation_rebuild_resolution
             (job_id,source_kind,source_row_id,life_id,memory_id,mutation_sequence,source_generation_id,source_generation_authority_epoch,disposition,replacement_mutation_sequence,created_at)
             SELECT ?1,'outbox',o.id,o.life_id,o.memory_id,o.mutation_sequence,o.claimed_generation_id,o.claimed_generation_authority_epoch,
                    CASE WHEN o.claimed_generation_authority_epoch IS NULL THEN 'legacy_rebuild_resolved' ELSE 'resolved_by_rebuild' END,NULL,?2
              FROM memory_vector_sync_outbox o WHERE o.migration_disposition IS NULL AND o.mutation_sequence>0 AND o.mutation_sequence<=?3
               AND EXISTS (SELECT 1 FROM memory_vector_generation_rebuild_catchup_item c
                            WHERE c.job_id=?1 AND c.source_outbox_id=o.id
                              AND c.life_id=o.life_id AND c.memory_id=o.memory_id
                              AND c.mutation_sequence=o.mutation_sequence
                              AND c.desired_action=o.desired_action
                              AND c.target_revision IS o.target_revision
                              AND c.target_content_hash IS o.target_content_hash
                              AND c.state='applied' AND c.io_phase='finalized')",
            params![job_id,now,target_sequence],
        ).map_err(|_| unavailable())?;
        transaction.execute(
            "INSERT OR IGNORE INTO memory_vector_generation_rebuild_resolution
             (job_id,source_kind,source_row_id,life_id,memory_id,mutation_sequence,source_generation_id,source_generation_authority_epoch,disposition,replacement_mutation_sequence,created_at)
             SELECT ?1,'late_delete',r.resolution_id,r.life_id,r.memory_id,r.mutation_sequence,
                    r.claimed_generation_id,r.captured_generation_authority_epoch,'resolved_by_rebuild',NULL,?2
             FROM memory_vector_late_delete_resolution r
             JOIN memory_vector_sync_outbox o
               ON o.id=r.outbox_id AND o.life_id=r.life_id AND o.memory_id=r.memory_id
              AND o.mutation_sequence=r.mutation_sequence AND o.desired_action='delete'
             WHERE o.migration_disposition IS NULL AND o.mutation_sequence>0 AND o.mutation_sequence<=?3
               AND r.state NOT IN ('resolved_absent','resolved_deleted','resolved_rebuilt','superseded')
               AND NOT EXISTS (
                   SELECT 1 FROM memory_vector_late_delete_resolution newer
                   WHERE newer.life_id=r.life_id AND newer.memory_id=r.memory_id
                     AND newer.mutation_sequence>r.mutation_sequence
                     AND newer.state NOT IN ('resolved_absent','resolved_deleted','resolved_rebuilt','superseded')
               )
                AND NOT EXISTS (
                    SELECT 1 FROM memory_vector_generation_item gi
                   WHERE gi.generation_id=(SELECT generation_id FROM memory_vector_generation_rebuild_job WHERE job_id=?1)
                      AND gi.life_id=r.life_id AND gi.memory_id=r.memory_id
                )
                AND EXISTS (
                    SELECT 1 FROM memory_vector_generation_rebuild_catchup_item c
                    WHERE c.job_id=?1 AND c.source_outbox_id=o.id
                      AND c.life_id=r.life_id AND c.memory_id=r.memory_id
                      AND c.mutation_sequence=r.mutation_sequence
                      AND c.desired_action='delete'
                      AND c.target_revision IS NULL AND c.target_content_hash IS NULL
                      AND c.state='applied' AND c.io_phase='finalized'
                )",
            params![job_id,now,target_sequence],
        ).map_err(|_| unavailable())?;
        transaction.execute(
            "UPDATE memory_vector_late_delete_resolution
             SET state='resolved_rebuilt',last_resolution_disposition='resolved_rebuilt',
                 last_disposition_epoch=resolution_epoch,resolved_at=?1,updated_at=?1,
                 lease_owner=NULL,lease_fence_epoch=NULL,lease_expires_at=NULL,next_attempt_at=NULL
             WHERE state NOT IN ('resolved_absent','resolved_deleted','resolved_rebuilt','superseded')
               AND NOT EXISTS (
                   SELECT 1 FROM memory_vector_late_delete_resolution newer
                   WHERE newer.life_id=memory_vector_late_delete_resolution.life_id
                     AND newer.memory_id=memory_vector_late_delete_resolution.memory_id
                     AND newer.mutation_sequence>memory_vector_late_delete_resolution.mutation_sequence
                     AND newer.state NOT IN ('resolved_absent','resolved_deleted','resolved_rebuilt','superseded')
               )
               AND EXISTS (
                    SELECT 1 FROM memory_vector_generation_rebuild_resolution rr
                    WHERE rr.job_id=?3 AND rr.source_kind='late_delete'
                      AND rr.source_row_id=memory_vector_late_delete_resolution.resolution_id
                      AND rr.mutation_sequence=memory_vector_late_delete_resolution.mutation_sequence
                      AND rr.disposition='resolved_by_rebuild'
               )
               AND EXISTS (
                   SELECT 1 FROM memory_vector_sync_outbox o
                   WHERE o.id=memory_vector_late_delete_resolution.outbox_id
                     AND o.life_id=memory_vector_late_delete_resolution.life_id
                     AND o.memory_id=memory_vector_late_delete_resolution.memory_id
                     AND o.mutation_sequence=memory_vector_late_delete_resolution.mutation_sequence
                     AND o.desired_action='delete' AND o.migration_disposition IS NULL
                     AND o.mutation_sequence>0 AND o.mutation_sequence<=?2
               )
               AND NOT EXISTS (
                   SELECT 1 FROM memory_vector_generation_item gi
                   WHERE gi.generation_id=(SELECT generation_id FROM memory_vector_generation_rebuild_job WHERE job_id=?3)
                     AND gi.life_id=memory_vector_late_delete_resolution.life_id
                     AND gi.memory_id=memory_vector_late_delete_resolution.memory_id
               )",
            params![now,target_sequence,job_id],
        ).map_err(|_| unavailable())?;
        #[cfg(test)]
        if fail_promotion(PromotionFault::AfterResolutions) {
            return Err(promotion_fault_error());
        }
        transaction.execute(
            "DELETE FROM memory_vector_sync_outbox WHERE migration_disposition IS NULL AND mutation_sequence>0 AND mutation_sequence<=?1
               AND EXISTS (SELECT 1 FROM memory_vector_generation_rebuild_catchup_item c
                            WHERE c.job_id=?2 AND c.source_outbox_id=memory_vector_sync_outbox.id
                              AND c.life_id=memory_vector_sync_outbox.life_id
                              AND c.memory_id=memory_vector_sync_outbox.memory_id
                              AND c.mutation_sequence=memory_vector_sync_outbox.mutation_sequence
                              AND c.desired_action=memory_vector_sync_outbox.desired_action
                              AND c.target_revision IS memory_vector_sync_outbox.target_revision
                              AND c.target_content_hash IS memory_vector_sync_outbox.target_content_hash
                              AND c.state='applied' AND c.io_phase='finalized')",
            params![target_sequence,job_id],
        ).map_err(|_| unavailable())?;
        if let Some(source) = job.source_active_generation_id.as_deref() {
            let expected_epoch = job.source_active_authority_epoch.ok_or_else(conflict)?;
            let source_changed = transaction.execute(
                "UPDATE memory_vector_generation_authority SET active_generation_id=NULL,updated_at=?1 WHERE singleton=1 AND active_generation_id=?2",
                params![now,source],
            ).map_err(|_| unavailable())?;
            if source_changed != 1 {
                return Err(conflict());
            }
            #[cfg(test)]
            if fail_promotion(PromotionFault::AfterPointerTransientNull) {
                return Err(promotion_fault_error());
            }
            let retired = transaction.execute(
                "UPDATE memory_vector_generation SET state='retired',authority_epoch=authority_epoch+1,updated_at=?1 WHERE generation_id=?2 AND state='active' AND authority_epoch=?3",
                params![now,source,expected_epoch],
            ).map_err(|_| unavailable())?;
            if retired != 1 {
                return Err(conflict());
            }
            #[cfg(test)]
            if fail_promotion(PromotionFault::AfterSourceRetired) {
                return Err(promotion_fault_error());
            }
        }
        let active = transaction.execute(
            "UPDATE memory_vector_generation SET state='active',authority_epoch=authority_epoch+1,updated_at=?1 WHERE generation_id=?2 AND state='building' AND authority_epoch=?3",
            params![now,job.generation_id,job.candidate_authority_epoch],
        ).map_err(|_| unavailable())?;
        if active != 1 {
            return Err(conflict());
        }
        #[cfg(test)]
        if fail_promotion(PromotionFault::AfterCandidateActivated) {
            return Err(promotion_fault_error());
        }
        let pointed = transaction.execute(
            "UPDATE memory_vector_generation_authority SET active_generation_id=?1,updated_at=?2 WHERE singleton=1 AND active_generation_id IS NULL",
            params![job.generation_id,now],
        ).map_err(|_| unavailable())?;
        if pointed != 1 {
            return Err(conflict());
        }
        #[cfg(test)]
        if fail_promotion(PromotionFault::AfterFinalPointer) {
            return Err(promotion_fault_error());
        }
        let completed = transaction.execute(
            "UPDATE memory_vector_generation_rebuild_job SET status='completed',promotion_operation_id=?1,promotion_sequence=?2,completed_at=?3,updated_at=?3,lease_owner=NULL,lease_expires_at=NULL
             WHERE job_id=?4 AND status='ready' AND lease_owner=?5 AND lease_fence=?6",
            params![operation_id,target_sequence,now,job_id,lease.owner,lease.fence],
        ).map_err(|_| unavailable())?;
        if completed != 1 {
            return Err(conflict());
        }
        #[cfg(test)]
        if fail_promotion(PromotionFault::BeforeCommit) {
            return Err(promotion_fault_error());
        }
        transaction
            .commit()
            .map_err(|_| promotion_commit_unknown())?;
        #[cfg(test)]
        if fail_promotion(PromotionFault::AfterCommitUnknown) {
            return Err(promotion_commit_unknown());
        }
        Ok(())
    }

    /// Read-only postimage/preimage classifier for a promotion commit whose
    /// caller could not observe SQLite's commit result.  A mixed image is
    /// deliberately not guessed or retried.
    pub(crate) fn classify_generation_rebuild_promotion_commit(
        &self,
        job_id: &str,
        operation_id: &str,
        target_sequence: i64,
    ) -> Result<GenerationRebuildPromotionCommitClassification, StorageError> {
        if !request_valid(job_id) || !request_valid(operation_id) || target_sequence < 0 {
            return Err(invalid());
        }
        let state = self.state()?;
        let connection = &state.connection;
        let post: bool = connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1
                   FROM memory_vector_generation_rebuild_job j
                   JOIN memory_vector_generation g ON g.generation_id=j.generation_id
                   JOIN memory_vector_generation_binding b ON b.generation_id=g.generation_id
                   JOIN memory_vector_generation_store_witness w ON w.generation_id=g.generation_id
                   JOIN memory_vector_generation_authority a ON a.singleton=1
                   LEFT JOIN memory_vector_generation source
                     ON source.generation_id=j.source_active_generation_id
                   WHERE j.job_id=?1 AND j.status='completed'
                     AND j.promotion_operation_id=?2 AND j.promotion_sequence=?3
                     AND j.lease_owner IS NULL AND j.lease_expires_at IS NULL
                     AND g.state='active'
                     AND g.authority_epoch=j.candidate_authority_epoch+1
                     AND g.descriptor_hash<>'' AND g.dimension>0
                     AND b.descriptor_version=?4 AND b.embedding_profile_id<>''
                     AND w.create_operation_id IS NOT NULL AND w.state='ready'
                     AND a.active_generation_id=j.generation_id
                     AND (j.source_active_generation_id IS NULL
                          OR (source.state='retired'
                              AND source.authority_epoch=j.source_active_authority_epoch+1))
                     AND NOT EXISTS (
                         SELECT 1 FROM memory_vector_sync_outbox o
                         WHERE o.migration_disposition IS NULL
                           AND o.mutation_sequence>0
                           AND o.mutation_sequence<=j.promotion_sequence)
                     -- Every covered outbox item (disposition-NULL outbox row with
                     -- an applied+finalized catch-up attempt) must carry exactly
                     -- the outbox resolution the promotion writes.  The catch-up
                     -- items persist after the promotion deletes the outbox rows,
                     -- so they remain the authoritative evidence set.
                     AND NOT EXISTS (
                         SELECT 1 FROM memory_vector_generation_rebuild_catchup_item c
                         WHERE c.job_id=j.job_id
                           AND c.mutation_sequence>0
                           AND c.mutation_sequence<=j.promotion_sequence
                           AND c.state='applied' AND c.io_phase='finalized'
                           AND NOT EXISTS (
                               SELECT 1 FROM memory_vector_generation_rebuild_resolution r
                               WHERE r.job_id=j.job_id AND r.source_kind='outbox'
                                 AND r.source_row_id=c.source_outbox_id
                                 AND r.life_id=c.life_id
                                 AND r.memory_id=c.memory_id
                                 AND r.mutation_sequence=c.mutation_sequence
                           )
                     )
                     -- No outbox resolution may exist without its covered catch-up
                     -- item (no orphan or invention of promotion evidence).
                     AND NOT EXISTS (
                         SELECT 1 FROM memory_vector_generation_rebuild_resolution r
                         WHERE r.job_id=j.job_id AND r.source_kind='outbox'
                           AND NOT EXISTS (
                               SELECT 1 FROM memory_vector_generation_rebuild_catchup_item c
                               WHERE c.job_id=j.job_id
                                 AND c.source_outbox_id=r.source_row_id
                                 AND c.life_id=r.life_id
                                 AND c.memory_id=r.memory_id
                                 AND c.mutation_sequence=r.mutation_sequence
                                 AND c.state='applied' AND c.io_phase='finalized'
                           )
                     )
                     -- Every late-delete resolution the promotion wrote must have
                     -- its selected Late Delete row in the terminal resolved_rebuilt
                     -- state (no mutated-away or resurrected LD evidence).
                     AND NOT EXISTS (
                         SELECT 1 FROM memory_vector_generation_rebuild_resolution r
                         WHERE r.job_id=j.job_id AND r.source_kind='late_delete'
                           AND NOT EXISTS (
                               SELECT 1 FROM memory_vector_late_delete_resolution ld
                               WHERE ld.resolution_id=r.source_row_id
                                 AND ld.state='resolved_rebuilt'
                           )
                     )
                   )",
                params![
                    job_id,
                    operation_id,
                    target_sequence,
                    D9D2_GENERATION_DESCRIPTOR_VERSION
                ],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())?;

        // The preimage must prove the promotion-only side effects did not
        // partially persist: the job is still ready, carries no promotion
        // identity, the candidate generation is still building at its candidate
        // epoch, the pointer still names the source (or NULL for a bootstrap),
        // and no rebuild resolution row (outbox or late-delete) exists for this
        // job.  A late-delete row can only be terminal via this promotion when a
        // resolution row exists, so the absence of resolution rows also proves no
        // selected Late Delete row was changed to resolved_rebuilt by it.
        let pre: bool = connection
            .query_row(
                "SELECT EXISTS(
                   SELECT 1
                   FROM memory_vector_generation_rebuild_job j
                   JOIN memory_vector_generation g ON g.generation_id=j.generation_id
                   JOIN memory_vector_generation_binding b ON b.generation_id=g.generation_id
                   JOIN memory_vector_generation_store_witness w ON w.generation_id=g.generation_id
                   JOIN memory_vector_generation_authority a ON a.singleton=1
                   LEFT JOIN memory_vector_generation source
                     ON source.generation_id=j.source_active_generation_id
                   WHERE j.job_id=?1 AND j.status='ready'
                     AND j.promotion_operation_id IS NULL
                     AND j.promotion_sequence IS NULL
                     AND j.lease_owner IS NOT NULL AND j.lease_expires_at IS NOT NULL
                     AND g.state='building'
                     AND g.authority_epoch=j.candidate_authority_epoch
                     AND g.descriptor_hash<>'' AND g.dimension>0
                     AND b.descriptor_version=?2 AND b.embedding_profile_id<>''
                     AND w.create_operation_id IS NOT NULL AND w.state='ready'
                     AND (a.active_generation_id IS j.source_active_generation_id)
                     AND (j.source_active_generation_id IS NULL
                          OR (source.state='active'
                              AND source.authority_epoch=j.source_active_authority_epoch))
                     AND NOT EXISTS (
                         SELECT 1 FROM memory_vector_generation_rebuild_resolution r
                         WHERE r.job_id=j.job_id)
                  )",
                params![job_id, D9D2_GENERATION_DESCRIPTOR_VERSION],
                |row| row.get(0),
            )
            .map_err(|_| unavailable())?;
        Ok(match (pre, post) {
            (false, true) => GenerationRebuildPromotionCommitClassification::Committed,
            (true, false) => GenerationRebuildPromotionCommitClassification::NotCommitted,
            _ => GenerationRebuildPromotionCommitClassification::RecoveryRequired,
        })
    }
}

fn current_eligible_items_in_connection(
    connection: &rusqlite::Connection,
) -> Result<Vec<GenerationRebuildEligibleItem>, StorageError> {
    let mut statement = connection
        .prepare(
            "SELECT life_id,id,kind,revision,content,summary
             FROM memory_record
             WHERE status='confirmed' AND is_sensitive=0
             ORDER BY life_id,id",
        )
        .map_err(|_| unavailable())?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })
        .map_err(|_| unavailable())?;
    let mut items = Vec::new();
    for row in rows {
        let (life_id, memory_id, kind, revision, content, summary) =
            row.map_err(|_| unavailable())?;
        let Some(selected) = canonical_index_text(summary.as_deref(), &content) else {
            continue;
        };
        let document = selected.trim();
        if revision < 1
            || document.is_empty()
            || contains_prohibited_content(&content)
            || summary.as_deref().is_some_and(contains_prohibited_content)
        {
            continue;
        }
        items.push(GenerationRebuildEligibleItem {
            life_id,
            memory_id,
            memory_revision: revision,
            content_hash: canonical_memory_index_hash(
                &kind,
                selected,
                &content,
                summary.as_deref(),
            ),
        });
    }
    Ok(items)
}

fn generation_items_in_connection(
    connection: &rusqlite::Connection,
    generation_id: &str,
) -> Result<Vec<GenerationRebuildEligibleItem>, StorageError> {
    let mut statement = connection
        .prepare(
            "SELECT life_id,memory_id,memory_revision,content_hash
             FROM memory_vector_generation_item
             WHERE generation_id=?1 ORDER BY life_id,memory_id",
        )
        .map_err(|_| unavailable())?;
    let items = statement
        .query_map([generation_id], |row| {
            Ok(GenerationRebuildEligibleItem {
                life_id: row.get(0)?,
                memory_id: row.get(1)?,
                memory_revision: row.get(2)?,
                content_hash: row.get(3)?,
            })
        })
        .map_err(|_| unavailable())?
        .map(|row| row.map_err(|_| unavailable()))
        .collect();
    items
}

fn verify_sqlite_final_set_in(
    connection: &rusqlite::Connection,
    generation_id: &str,
) -> Result<(), StorageError> {
    let current = current_eligible_items_in_connection(connection)?;
    let generation = generation_items_in_connection(connection, generation_id)?;
    if current != generation {
        return Err(StorageError::new(
            "GENERATION_REBUILD_SQLITE_SET_MISMATCH",
            "The candidate SQLite generation set is not the exact current eligible set.",
            true,
        ));
    }
    Ok(())
}

fn catchup_target_is_complete_in(
    connection: &rusqlite::Connection,
    job_id: &str,
    target_sequence: i64,
) -> Result<bool, StorageError> {
    let missing_current: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM memory_vector_sync_outbox o
             WHERE o.migration_disposition IS NULL
               AND o.mutation_sequence>0 AND o.mutation_sequence<=?2
               AND NOT EXISTS (
                   SELECT 1
                   FROM memory_vector_generation_rebuild_catchup_item c
                   WHERE c.job_id=?1
                     AND c.source_outbox_id=o.id
                     AND c.life_id=o.life_id AND c.memory_id=o.memory_id
                     AND c.mutation_sequence=o.mutation_sequence
                     AND c.desired_action=o.desired_action
                     AND c.target_revision IS o.target_revision
                     AND c.target_content_hash IS o.target_content_hash
                     AND c.state='applied' AND c.io_phase='finalized'
               )",
            params![job_id, target_sequence],
            |row| row.get(0),
        )
        .map_err(|_| unavailable())?;
    if missing_current != 0 {
        return Ok(false);
    }

    let unresolved_orphan: i64 = connection
        .query_row(
            "SELECT COUNT(*)
             FROM memory_vector_generation_rebuild_catchup_item c
             WHERE c.job_id=?1
               AND c.mutation_sequence>0 AND c.mutation_sequence<=?2
               AND c.state NOT IN ('applied','superseded')
               AND NOT EXISTS (
                   SELECT 1
                   FROM memory_vector_sync_outbox o
                   WHERE o.id=c.source_outbox_id
                     AND o.life_id=c.life_id AND o.memory_id=c.memory_id
                     AND o.mutation_sequence=c.mutation_sequence
                     AND o.desired_action=c.desired_action
                     AND o.target_revision IS c.target_revision
                     AND o.target_content_hash IS c.target_content_hash
                     AND o.migration_disposition IS NULL
               )",
            params![job_id, target_sequence],
            |row| row.get(0),
        )
        .map_err(|_| unavailable())?;
    Ok(unresolved_orphan == 0)
}

fn requeue_failed_generation_outbox_in(
    transaction: &Transaction<'_>,
    job: &GenerationRebuildJobRecord,
    now: &str,
) -> Result<(), StorageError> {
    let active_generation: Option<String> = transaction
        .query_row(
            "SELECT active_generation_id
             FROM memory_vector_generation_authority
             WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| unavailable())?;
    let has_active_generation = active_generation.is_some();
    let mut statement = transaction
        .prepare(
            "SELECT id,life_id,memory_id,desired_action,mutation_sequence,
                    target_revision,target_content_hash
             FROM memory_vector_sync_outbox
             WHERE migration_disposition IS NULL
               AND claimed_generation_id=?1
               AND claimed_generation_authority_epoch=?2
             ORDER BY id",
        )
        .map_err(|_| unavailable())?;
    let rows = statement
        .query_map(
            params![job.generation_id, job.candidate_authority_epoch],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .map_err(|_| unavailable())?;
    let rows = rows
        .map(|row| row.map_err(|_| unavailable()))
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);

    for (
        outbox_id,
        life_id,
        memory_id,
        desired_action,
        old_mutation_sequence,
        target_revision,
        target_content_hash,
    ) in rows
    {
        if !matches!(desired_action.as_str(), "upsert" | "delete") {
            return Err(conflict());
        }
        let replacement_mutation_sequence = allocate_mutation_sequence_in(transaction)?;
        late_delete_resolution::supersede_for_new_mutation_in(
            transaction,
            &life_id,
            &memory_id,
            replacement_mutation_sequence,
            now,
        )?;
        transaction
            .execute(
                "INSERT INTO memory_vector_generation_rebuild_resolution
                 (job_id,source_kind,source_row_id,life_id,memory_id,mutation_sequence,
                  source_generation_id,source_generation_authority_epoch,disposition,
                  replacement_mutation_sequence,created_at)
                 VALUES (?1,'outbox',?2,?3,?4,?5,?6,?7,'failed_generation_requeued',?8,?9)
                 ON CONFLICT(job_id,source_kind,source_row_id,mutation_sequence)
                 DO UPDATE SET replacement_mutation_sequence=excluded.replacement_mutation_sequence",
                params![
                    job.job_id,
                    outbox_id,
                    life_id,
                    memory_id,
                    old_mutation_sequence,
                    job.generation_id,
                    job.candidate_authority_epoch,
                    replacement_mutation_sequence,
                    now,
                ],
            )
            .map_err(|_| unavailable())?;
        let (state, error_code) = if has_active_generation {
            ("pending", None)
        } else {
            ("blocked", Some("GENERATION_REBUILD_NO_ACTIVE_GENERATION"))
        };
        let changed = transaction
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET state=?1,attempt_count=0,fenced_claim_epoch=0,last_marked_claim_epoch=0,
                     next_attempt_at=NULL,lease_owner=NULL,lease_expires_at=NULL,
                     lease_fence_epoch=NULL,claimed_generation_id=NULL,
                     claimed_generation_authority_epoch=NULL,last_send_disposition=NULL,
                     last_error_code=?2,migration_disposition=NULL,
                     mutation_sequence=?3,target_revision=?4,target_content_hash=?5,
                     delete_witness_at=NULL,updated_at=?6
                 WHERE id=?7 AND mutation_sequence=?8
                   AND claimed_generation_id=?9
                   AND claimed_generation_authority_epoch=?10
                   AND migration_disposition IS NULL",
                params![
                    state,
                    error_code,
                    replacement_mutation_sequence,
                    target_revision,
                    target_content_hash,
                    now,
                    outbox_id,
                    old_mutation_sequence,
                    job.generation_id,
                    job.candidate_authority_epoch,
                ],
            )
            .map_err(|_| unavailable())?;
        if changed != 1 {
            return Err(conflict());
        }
    }
    Ok(())
}

fn allocate_mutation_sequence_in(transaction: &Transaction<'_>) -> Result<i64, StorageError> {
    let changed = transaction
        .execute(
            "UPDATE memory_vector_sync_mutation_clock
             SET last_sequence=last_sequence+1
             WHERE singleton=1 AND last_sequence<9223372036854775807",
            [],
        )
        .map_err(|_| unavailable())?;
    if changed != 1 {
        return Err(conflict());
    }
    transaction
        .query_row(
            "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| unavailable())
}

fn load_job_in(
    transaction: &Transaction<'_>,
    job_id: &str,
) -> Result<Option<GenerationRebuildJobRecord>, StorageError> {
    transaction
        .query_row(
            &format!("{JOB_SELECT} WHERE j.job_id=?1"),
            [job_id],
            read_job,
        )
        .optional()
        .map_err(|_| unavailable())
}

fn assert_live_lease_in(
    transaction: &Transaction<'_>,
    job_id: &str,
    lease: &GenerationRebuildLease,
    now: &str,
) -> Result<(), StorageError> {
    let live: bool = transaction
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM memory_vector_generation_rebuild_job WHERE job_id=?1 AND lease_owner=?2 AND lease_fence=?3 AND lease_expires_at>?4 AND status IN ('registered','snapshotting','bulk_building','catching_up','verifying','ready'))",
            params![job_id, lease.owner, lease.fence, now],
            |row| row.get(0),
        )
        .map_err(|_| unavailable())?;
    if !live {
        return Err(conflict());
    }
    Ok(())
}

fn read_item(row: &Row<'_>) -> rusqlite::Result<GenerationRebuildItemRecord> {
    Ok(GenerationRebuildItemRecord {
        job_id: row.get(0)?,
        life_id: row.get(1)?,
        memory_id: row.get(2)?,
        memory_revision: row.get(3)?,
        content_hash: row.get(4)?,
        canonical_document: row.get(5)?,
        state: row.get(6)?,
        io_phase: row.get(7)?,
        attempt_count: row.get(8)?,
        attempt_id: row.get(9)?,
        attempt_fence: row.get(10)?,
        last_send_disposition: row.get(11)?,
        last_error_code: row.get(12)?,
    })
}

fn assert_catchup_authority_in(
    transaction: &Transaction<'_>,
    job: &GenerationRebuildJobRecord,
    lease: &GenerationRebuildLease,
    now: &str,
) -> Result<(), StorageError> {
    assert_live_lease_in(transaction, &job.job_id, lease, now)?;
    let exact: bool = transaction
        .query_row(
            "SELECT EXISTS(
             SELECT 1 FROM memory_vector_generation_rebuild_job j
             JOIN memory_vector_generation g ON g.generation_id=j.generation_id
             JOIN memory_vector_generation_binding b ON b.generation_id=g.generation_id
             JOIN memory_vector_generation_store_witness w ON w.generation_id=g.generation_id
             WHERE j.job_id=?1 AND j.status IN ('catching_up','verifying','ready')
               AND g.state='building' AND g.authority_epoch=j.candidate_authority_epoch
                AND b.descriptor_version=?2 AND b.embedding_profile_id=?3
                AND w.create_operation_id=?4 AND w.state='ready'
            )",
            params![
                job.job_id,
                job.descriptor_version,
                job.embedding_profile_id,
                job.create_operation_id,
            ],
            |row| row.get(0),
        )
        .map_err(|_| unavailable())?;
    if !exact {
        return Err(conflict());
    }
    Ok(())
}

fn assert_source_authority_in(
    transaction: &Transaction<'_>,
    job: &GenerationRebuildJobRecord,
) -> Result<(), StorageError> {
    let (active_generation_id, active_state, active_epoch): (
        Option<String>,
        Option<String>,
        Option<i64>,
    ) = transaction
        .query_row(
            "SELECT a.active_generation_id,g.state,g.authority_epoch
             FROM memory_vector_generation_authority a
             LEFT JOIN memory_vector_generation g
               ON g.generation_id=a.active_generation_id
             WHERE a.singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| unavailable())?;
    match job.source_active_generation_id.as_deref() {
        Some(source_generation_id)
            if active_generation_id.as_deref() == Some(source_generation_id)
                && active_state.as_deref() == Some("active")
                && active_epoch == job.source_active_authority_epoch =>
        {
            Ok(())
        }
        None if active_generation_id.is_none() => Ok(()),
        _ => Err(conflict()),
    }
}

fn catchup_final_target_mismatch() -> StorageError {
    StorageError::new(
        "GENERATION_REBUILD_CATCHUP_FINAL_TARGET_MISMATCH",
        "The catch-up effect no longer matches the authoritative current target.",
        false,
    )
}

fn catchup_final_proof_failed() -> StorageError {
    StorageError::new(
        "GENERATION_REBUILD_CATCHUP_FINAL_PROOF_FAILED",
        "The catch-up effect did not satisfy the exact final SQLite proof.",
        false,
    )
}

fn assert_catchup_target_authority_in(
    transaction: &Transaction<'_>,
    item: &GenerationRebuildCatchupItemRecord,
) -> Result<(), StorageError> {
    let current: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM memory_vector_sync_outbox
                 WHERE id=?1 AND life_id=?2 AND memory_id=?3
                   AND mutation_sequence=?4 AND desired_action=?5
                   AND target_revision IS ?6
                   AND target_content_hash IS ?7
                   AND migration_disposition IS NULL
            )",
            params![
                item.source_outbox_id,
                item.life_id,
                item.memory_id,
                item.mutation_sequence,
                item.desired_action,
                item.target_revision,
                item.target_content_hash,
            ],
            |row| row.get(0),
        )
        .map_err(|_| unavailable())?;
    if !current {
        return Err(catchup_final_target_mismatch());
    }

    match item.desired_action.as_str() {
        "delete"
            if item.target_revision.is_none()
                && item.target_content_hash.is_none()
                && item.canonical_document.is_none() =>
        {
            Ok(())
        }
        "upsert" => {
            let record: Option<(String, i64, String, Option<String>, String, i64)> = transaction
                .query_row(
                    "SELECT kind,revision,content,summary,status,is_sensitive
                     FROM memory_record WHERE life_id=?1 AND id=?2",
                    params![item.life_id, item.memory_id],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                            row.get(5)?,
                        ))
                    },
                )
                .optional()
                .map_err(|_| unavailable())?;
            let Some((kind, revision, content, summary, status, sensitive)) = record else {
                return Err(catchup_final_target_mismatch());
            };
            let Some(selected) = canonical_index_text(summary.as_deref(), &content) else {
                return Err(catchup_final_target_mismatch());
            };
            let canonical = selected.trim();
            let hash = canonical_memory_index_hash(&kind, selected, &content, summary.as_deref());
            if status != "confirmed"
                || sensitive != 0
                || contains_prohibited_content(&content)
                || summary.as_deref().is_some_and(contains_prohibited_content)
                || canonical.is_empty()
                || item.target_revision != Some(revision)
                || item.target_content_hash.as_deref() != Some(hash.as_str())
                || item.canonical_document.as_deref() != Some(canonical)
            {
                return Err(catchup_final_target_mismatch());
            }
            Ok(())
        }
        _ => Err(catchup_final_target_mismatch()),
    }
}

fn read_catchup_item(row: &Row<'_>) -> rusqlite::Result<GenerationRebuildCatchupItemRecord> {
    Ok(GenerationRebuildCatchupItemRecord {
        job_id: row.get(0)?,
        source_outbox_id: row.get(1)?,
        life_id: row.get(2)?,
        memory_id: row.get(3)?,
        mutation_sequence: row.get(4)?,
        desired_action: row.get(5)?,
        target_revision: row.get(6)?,
        target_content_hash: row.get(7)?,
        canonical_document: row.get(8)?,
        state: row.get(9)?,
        io_phase: row.get(10)?,
        attempt_count: row.get(11)?,
        attempt_id: row.get(12)?,
        attempt_fence: row.get(13)?,
        last_send_disposition: row.get(14)?,
        last_error_code: row.get(15)?,
    })
}

fn next_attempt_id() -> String {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default();
    let sequence = REBUILD_ATTEMPT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("generation-rebuild-attempt-{millis:032x}-{sequence:016x}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::generation_lifecycle_authority::GenerationAuthorityRegistration;
    use std::{
        sync::{Arc, Barrier},
        thread,
    };
    use tempfile::TempDir;

    fn service(label: &str) -> (TempDir, StorageService) {
        let root = tempfile::Builder::new().prefix(label).tempdir().unwrap();
        let storage =
            StorageService::initialize_with_roots(root.path().join("data"), None).unwrap();
        (root, storage)
    }

    fn registration<'a>(
        generation_id: &'a str,
        operation_id: &'a str,
        job_id: &'a str,
        request_id: &'a str,
    ) -> GenerationAuthorityRegistration<'a> {
        GenerationAuthorityRegistration {
            generation_id,
            descriptor_hash: "descriptor-a",
            dimension: 3,
            embedding_profile_id: "profile-a",
            create_operation_id: operation_id,
            job_id,
            request_id,
        }
    }

    fn seed_life(storage: &StorageService) {
        let state = storage.state().unwrap();
        state
            .connection
            .execute(
                "INSERT INTO persona_template (id,name,version,persona_json) VALUES ('persona-a','Persona',1,'{}')",
                [],
            )
            .unwrap();
        state
            .connection
            .execute(
                "INSERT INTO life_identity (id,name,created_at,version,body_id,persona_id,persona_version) VALUES ('life-a','Life','2026-08-18T00:00:00.000Z',1,'body','persona-a',1)",
                [],
            )
            .unwrap();
    }

    fn insert_memory(
        storage: &StorageService,
        id: &str,
        status: &str,
        content: &str,
        summary: Option<&str>,
        sensitive: i64,
        revision: i64,
    ) {
        let state = storage.state().unwrap();
        state
            .connection
            .execute(
                "INSERT INTO memory_record
                 (id,life_id,kind,status,content,summary,source_type,source_ref,source_created_at,
                  importance,confidence,is_sensitive,created_at,updated_at,confirmed_at,revision)
                 VALUES (?1,'life-a','fact',?2,?3,?4,'manual',NULL,'2026-08-18T00:00:00.000Z',
                         0.5,0.8,?5,'2026-08-18T00:00:00.000Z','2026-08-18T00:00:00.000Z',
                         '2026-08-18T00:00:00.000Z',?6)",
                rusqlite::params![id, status, content, summary, sensitive, revision],
            )
            .unwrap();
    }

    fn registered_building(storage: &StorageService) -> GenerationRebuildLease {
        storage
            .register_generation_lifecycle_authority(registration(
                "generation-a",
                "operation-a",
                "job-a",
                "request-a",
            ))
            .unwrap();
        let lease = storage
            .acquire_generation_rebuild_job_lease("job-a", "owner-a")
            .unwrap()
            .unwrap();
        storage
            .mark_generation_store_witness_ready("job-a", &lease, "generation-a", "operation-a")
            .unwrap();
        lease
    }

    #[test]
    fn snapshot_captures_pointer_null_bootstrap_and_exact_eligible_hash() {
        let (_root, storage) = service("generation-snapshot");
        seed_life(&storage);
        insert_memory(
            &storage,
            "safe",
            "confirmed",
            "authoritative content",
            Some("  Preferred summary  "),
            0,
            7,
        );
        insert_memory(
            &storage,
            "candidate",
            "candidate",
            "candidate content",
            None,
            0,
            1,
        );
        insert_memory(
            &storage,
            "sensitive",
            "confirmed",
            "sensitive content",
            None,
            1,
            1,
        );
        insert_memory(
            &storage,
            "secret-summary",
            "confirmed",
            "safe content",
            Some("api_key=SECRET_VALUE_123456"),
            0,
            1,
        );
        insert_memory(
            &storage,
            "secret-content",
            "confirmed",
            "password=SECRET_VALUE_123456",
            None,
            0,
            1,
        );
        let lease = registered_building(&storage);

        let snapshot = storage
            .snapshot_generation_rebuild("job-a", &lease)
            .unwrap();
        assert_eq!(snapshot.snapshot_sequence, 0);
        assert_eq!(snapshot.snapshot_item_count, 1);
        let items = storage.list_generation_rebuild_items("job-a").unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].memory_id, "safe");
        assert_eq!(items[0].memory_revision, 7);
        assert_eq!(
            items[0].canonical_document.as_deref(),
            Some("Preferred summary")
        );
        assert_eq!(
            items[0].content_hash,
            canonical_memory_index_hash(
                "fact",
                "  Preferred summary  ",
                "authoritative content",
                Some("  Preferred summary  "),
            )
        );

        // A later authoritative insert is outside the already committed S
        // materialization and cannot appear in the persisted item set.
        insert_memory(
            &storage,
            "after-s",
            "confirmed",
            "later content",
            None,
            0,
            1,
        );
        assert_eq!(
            storage
                .list_generation_rebuild_items("job-a")
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn source_pair_is_captured_from_the_singleton_pointer_not_the_caller() {
        let (_root, storage) = service("generation-source");
        {
            let state = storage.state().unwrap();
            state
                .connection
                .execute(
                    "INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch) VALUES ('active-a','descriptor-active',3,'active',9)",
                    [],
                )
                .unwrap();
            state
                .connection
                .execute(
                    "UPDATE memory_vector_generation_authority SET active_generation_id='active-a' WHERE singleton=1",
                    [],
                )
                .unwrap();
        }
        storage
            .register_generation_lifecycle_authority(registration(
                "generation-b",
                "operation-b",
                "job-b",
                "request-b",
            ))
            .unwrap();
        let state = storage.state().unwrap();
        let source: (Option<String>, Option<i64>) = state
            .connection
            .query_row(
                "SELECT source_active_generation_id,source_active_authority_epoch FROM memory_vector_generation_rebuild_job WHERE job_id='job-b'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(source, (Some("active-a".into()), Some(9)));
    }

    #[test]
    fn null_source_pointer_is_rejected_once_an_active_generation_exists() {
        let (_root, storage) = service("generation-null-source");
        {
            let state = storage.state().unwrap();
            state
                .connection
                .execute(
                    "INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch) VALUES ('active-a','descriptor-active',3,'active',9)",
                    [],
                )
                .unwrap();
        }
        assert!(storage
            .register_generation_lifecycle_authority(registration(
                "generation-b",
                "operation-b",
                "job-b",
                "request-b",
            ))
            .is_err());
        let state = storage.state().unwrap();
        let count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_generation WHERE generation_id='generation-b'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn two_connections_have_one_durable_job_lease_winner() {
        let root = tempfile::Builder::new()
            .prefix("generation-lease")
            .tempdir()
            .unwrap();
        let path = root.path().join("data");
        let first = Arc::new(StorageService::initialize_with_roots(path.clone(), None).unwrap());
        let second = Arc::new(StorageService::initialize_with_roots(path, None).unwrap());
        first
            .register_generation_lifecycle_authority(registration(
                "generation-a",
                "operation-a",
                "job-a",
                "request-a",
            ))
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let (tx, rx) = std::sync::mpsc::channel();
        for (storage, owner) in [(first, "owner-a"), (second, "owner-b")] {
            let barrier = Arc::clone(&barrier);
            let tx = tx.clone();
            thread::spawn(move || {
                barrier.wait();
                tx.send(
                    storage
                        .acquire_generation_rebuild_job_lease("job-a", owner)
                        .unwrap(),
                )
                .unwrap();
            });
        }
        drop(tx);
        let leases: Vec<_> = rx.into_iter().collect();
        assert_eq!(leases.iter().filter(|lease| lease.is_some()).count(), 1);
    }

    #[test]
    fn definitely_not_sent_reuses_the_same_attempt_identity() {
        let (_root, storage) = service("generation-retry-safety");
        seed_life(&storage);
        insert_memory(
            &storage,
            "safe",
            "confirmed",
            "content",
            Some("summary"),
            0,
            1,
        );
        let lease = registered_building(&storage);
        storage
            .snapshot_generation_rebuild("job-a", &lease)
            .unwrap();
        let reserved = storage
            .reserve_next_generation_rebuild_item("job-a", &lease)
            .unwrap()
            .unwrap();
        let attempt_id = reserved.attempt_id.clone();
        let attempt_count = reserved.attempt_count;
        let attempt_fence = reserved.attempt_fence;
        storage
            .mark_generation_rebuild_embedding_started(&reserved, &lease)
            .unwrap();
        storage
            .mark_generation_rebuild_embedding_definitely_not_sent(
                &reserved,
                &lease,
                "EMBEDDING_REQUEST_NOT_SENT",
            )
            .unwrap();

        let resumed = storage
            .reserve_next_generation_rebuild_item("job-a", &lease)
            .unwrap()
            .unwrap();
        assert_eq!(resumed.state, "processing");
        assert_eq!(resumed.io_phase, "reserved");
        assert_eq!(resumed.attempt_id, attempt_id);
        assert_eq!(resumed.attempt_count, attempt_count);
        assert_eq!(resumed.attempt_fence, attempt_fence);
        assert_eq!(
            resumed.last_send_disposition.as_deref(),
            Some("definitely_not_sent")
        );
    }

    #[test]
    fn stale_job_lease_cannot_mutate_a_reserved_item() {
        let root = tempfile::Builder::new()
            .prefix("generation-stale-lease")
            .tempdir()
            .unwrap();
        let path = root.path().join("data");
        let first = StorageService::initialize_with_roots(path.clone(), None).unwrap();
        let second = StorageService::initialize_with_roots(path, None).unwrap();
        seed_life(&first);
        insert_memory(
            &first,
            "safe",
            "confirmed",
            "content",
            Some("summary"),
            0,
            1,
        );
        first
            .register_generation_lifecycle_authority(registration(
                "generation-a",
                "operation-a",
                "job-a",
                "request-a",
            ))
            .unwrap();
        let stale = first
            .acquire_generation_rebuild_job_lease("job-a", "owner-a")
            .unwrap()
            .unwrap();
        {
            let state = second.state().unwrap();
            state
                .connection
                .execute(
                    "UPDATE memory_vector_generation_rebuild_job SET lease_expires_at='1970-01-01T00:00:00.000Z' WHERE job_id='job-a'",
                    [],
                )
                .unwrap();
        }
        let current = second
            .acquire_generation_rebuild_job_lease("job-a", "owner-b")
            .unwrap()
            .unwrap();
        second
            .mark_generation_store_witness_ready("job-a", &current, "generation-a", "operation-a")
            .unwrap();
        second
            .snapshot_generation_rebuild("job-a", &current)
            .unwrap();
        let item = second
            .reserve_next_generation_rebuild_item("job-a", &current)
            .unwrap()
            .unwrap();
        assert!(second
            .mark_generation_rebuild_embedding_started(&item, &stale)
            .is_err());
    }

    #[test]
    fn failed_generation_requeues_explicit_g2_outbox_as_new_unbound_mutation() {
        let (_root, storage) = service("generation-failed-compensation");
        seed_life(&storage);
        insert_memory(
            &storage,
            "safe",
            "confirmed",
            "content",
            Some("summary"),
            0,
            1,
        );
        {
            let state = storage.state().unwrap();
            state
                .connection
                .execute(
                    "INSERT INTO memory_vector_generation
                     (generation_id,descriptor_hash,dimension,state,authority_epoch)
                     VALUES ('active-a','descriptor-active',3,'active',9)",
                    [],
                )
                .unwrap();
            state
                .connection
                .execute(
                    "UPDATE memory_vector_generation_authority
                     SET active_generation_id='active-a' WHERE singleton=1",
                    [],
                )
                .unwrap();
        }
        let lease = registered_building(&storage);
        {
            let state = storage.state().unwrap();
            state
                .connection
                .execute_batch(
                    "UPDATE memory_vector_sync_mutation_clock
                     SET last_sequence=1 WHERE singleton=1;
                     INSERT INTO memory_vector_sync_outbox
                       (life_id,memory_id,desired_action,state,attempt_count,
                        mutation_sequence,target_revision,target_content_hash,
                        claimed_generation_id,claimed_generation_authority_epoch,
                        last_send_disposition)
                     VALUES ('life-a','safe','upsert','processing',1,1,1,'old-hash',
                             'generation-a',1,'possibly_sent')",
                )
                .unwrap();
        }

        storage
            .fail_generation_rebuild("job-a", &lease, "D_TEST_FAILURE", 1)
            .unwrap();

        let state = storage.state().unwrap();
        let outbox: (
            String,
            i64,
            Option<String>,
            Option<i64>,
            Option<String>,
            i64,
        ) = state
            .connection
            .query_row(
                "SELECT state,mutation_sequence,claimed_generation_id,
                        claimed_generation_authority_epoch,last_send_disposition,attempt_count
                 FROM memory_vector_sync_outbox
                 WHERE life_id='life-a' AND memory_id='safe'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(outbox, ("pending".into(), 2, None, None, None, 0));
        let resolution: (String, i64, Option<i64>) = state
            .connection
            .query_row(
                "SELECT disposition,mutation_sequence,replacement_mutation_sequence
                 FROM memory_vector_generation_rebuild_resolution
                 WHERE job_id='job-a' AND source_kind='outbox' AND source_row_id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            resolution,
            ("failed_generation_requeued".into(), 1, Some(2))
        );
        let source: (Option<String>, String, i64) = state
            .connection
            .query_row(
                "SELECT a.active_generation_id,g.state,g.authority_epoch
                 FROM memory_vector_generation_authority a
                 JOIN memory_vector_generation g ON g.generation_id=a.active_generation_id
                 WHERE a.singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(source, (Some("active-a".into()), "active".into(), 9));
    }

    #[test]
    fn promotion_commit_classifier_distinguishes_pre_post_and_mixed_without_replay() {
        let (_root, storage) = service("generation-promotion-classifier");
        let lease = registered_building(&storage);
        storage
            .snapshot_generation_rebuild("job-a", &lease)
            .unwrap();
        storage
            .finish_generation_rebuild_c_handoff("job-a", &lease)
            .unwrap();
        storage
            .materialize_generation_rebuild_catchup("job-a", &lease, 0)
            .unwrap();
        assert!(storage
            .advance_generation_rebuild_catchup("job-a", &lease, 0)
            .unwrap());
        storage
            .mark_generation_rebuild_ready("job-a", &lease, 0)
            .unwrap();
        let late_delete_lease = storage
            .acquire_late_delete_runtime_lease("promotion-classifier")
            .unwrap()
            .unwrap();

        arm_promotion_fault_for_test(PromotionFault::BeforeCommit);
        let pre_error = storage
            .promote_generation_rebuild("job-a", &lease, &late_delete_lease, 0, "promotion-pre")
            .unwrap_err();
        assert_eq!(pre_error.code, "GENERATION_REBUILD_PROMOTION_FAULT");
        assert_eq!(
            storage
                .classify_generation_rebuild_promotion_commit("job-a", "promotion-pre", 0)
                .unwrap(),
            GenerationRebuildPromotionCommitClassification::NotCommitted
        );

        arm_promotion_fault_for_test(PromotionFault::AfterCommitUnknown);
        let post_error = storage
            .promote_generation_rebuild("job-a", &lease, &late_delete_lease, 0, "promotion-post")
            .unwrap_err();
        assert_eq!(
            post_error.code,
            "GENERATION_REBUILD_PROMOTION_COMMIT_RESULT_UNKNOWN"
        );
        assert_eq!(
            storage
                .classify_generation_rebuild_promotion_commit("job-a", "promotion-post", 0)
                .unwrap(),
            GenerationRebuildPromotionCommitClassification::Committed
        );

        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_generation_authority
                 SET active_generation_id=NULL WHERE singleton=1",
                [],
            )
            .unwrap();
        assert_eq!(
            storage
                .classify_generation_rebuild_promotion_commit("job-a", "promotion-post", 0)
                .unwrap(),
            GenerationRebuildPromotionCommitClassification::RecoveryRequired
        );
    }

    #[test]
    fn catchup_mutation_identity_uses_new_attempt_and_blocks_unsafe_supersession() {
        let (_root, storage) = service("generation-catchup-mutation-identity");
        let lease = registered_building(&storage);
        storage
            .snapshot_generation_rebuild("job-a", &lease)
            .unwrap();
        storage
            .finish_generation_rebuild_c_handoff("job-a", &lease)
            .unwrap();
        {
            let state = storage.state().unwrap();
            state
                .connection
                .execute_batch(
                    "UPDATE memory_vector_sync_mutation_clock
                     SET last_sequence=100 WHERE singleton=1;
                     INSERT INTO memory_vector_sync_outbox
                       (life_id,memory_id,desired_action,state,attempt_count,
                        mutation_sequence,target_revision,target_content_hash)
                     VALUES ('life-a','memory-a','delete','pending',0,100,NULL,NULL)",
                )
                .unwrap();
        }
        storage
            .materialize_generation_rebuild_catchup("job-a", &lease, 100)
            .unwrap();
        let old = storage
            .reserve_next_generation_rebuild_catchup_item("job-a", &lease)
            .unwrap()
            .unwrap();
        let old_attempt_id = old.attempt_id.clone();
        {
            let state = storage.state().unwrap();
            state
                .connection
                .execute_batch(
                    "UPDATE memory_vector_sync_outbox
                     SET mutation_sequence=103,updated_at='now' WHERE id=1;
                     UPDATE memory_vector_sync_mutation_clock
                     SET last_sequence=103 WHERE singleton=1",
                )
                .unwrap();
        }
        storage
            .materialize_generation_rebuild_catchup("job-a", &lease, 103)
            .unwrap();
        let items = storage
            .list_generation_rebuild_catchup_items("job-a")
            .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].mutation_sequence, 100);
        assert_eq!(items[0].state, "superseded");
        assert_eq!(items[0].canonical_document, None);
        assert_eq!(items[1].mutation_sequence, 103);
        let newer = storage
            .reserve_next_generation_rebuild_catchup_item("job-a", &lease)
            .unwrap()
            .unwrap();
        assert_eq!(newer.mutation_sequence, 103);
        assert_ne!(newer.attempt_id, old_attempt_id);
        assert_eq!(newer.attempt_count, 1);

        let (_unsafe_root, unsafe_storage) = service("generation-catchup-unsafe-supersession");
        let unsafe_lease = registered_building(&unsafe_storage);
        unsafe_storage
            .snapshot_generation_rebuild("job-a", &unsafe_lease)
            .unwrap();
        unsafe_storage
            .finish_generation_rebuild_c_handoff("job-a", &unsafe_lease)
            .unwrap();
        {
            let state = unsafe_storage.state().unwrap();
            state
                .connection
                .execute_batch(
                    "UPDATE memory_vector_sync_mutation_clock
                     SET last_sequence=100 WHERE singleton=1;
                     INSERT INTO memory_vector_sync_outbox
                       (life_id,memory_id,desired_action,state,attempt_count,
                        mutation_sequence,target_revision,target_content_hash)
                     VALUES ('life-a','memory-a','delete','pending',0,100,NULL,NULL)",
                )
                .unwrap();
        }
        unsafe_storage
            .materialize_generation_rebuild_catchup("job-a", &unsafe_lease, 100)
            .unwrap();
        let unsafe_item = unsafe_storage
            .reserve_next_generation_rebuild_catchup_item("job-a", &unsafe_lease)
            .unwrap()
            .unwrap();
        unsafe_storage
            .mark_generation_rebuild_catchup_phase(
                &unsafe_item,
                &unsafe_lease,
                "vector_write_started",
            )
            .unwrap();
        {
            let state = unsafe_storage.state().unwrap();
            state
                .connection
                .execute_batch(
                    "UPDATE memory_vector_sync_outbox
                     SET mutation_sequence=103,updated_at='now' WHERE id=1;
                     UPDATE memory_vector_sync_mutation_clock
                     SET last_sequence=103 WHERE singleton=1",
                )
                .unwrap();
        }
        let error = unsafe_storage
            .materialize_generation_rebuild_catchup("job-a", &unsafe_lease, 103)
            .unwrap_err();
        assert_eq!(error.code, "GENERATION_REBUILD_CATCHUP_RESULT_UNKNOWN");
        let unsafe_items = unsafe_storage
            .list_generation_rebuild_catchup_items("job-a")
            .unwrap();
        assert_eq!(unsafe_items.len(), 1);
        assert_eq!(unsafe_items[0].mutation_sequence, 100);
        assert_eq!(unsafe_items[0].state, "uncertain");
        assert_eq!(
            unsafe_items[0].last_send_disposition.as_deref(),
            Some("possibly_sent")
        );
    }

    #[test]
    fn finalize_is_exactly_once_and_unknown_attempt_is_terminal_no_replay() {
        let (_root, storage) = service("generation-finalize");
        seed_life(&storage);
        insert_memory(
            &storage,
            "safe",
            "confirmed",
            "content",
            Some("summary"),
            0,
            1,
        );
        let lease = registered_building(&storage);
        storage
            .snapshot_generation_rebuild("job-a", &lease)
            .unwrap();
        let item = storage
            .reserve_next_generation_rebuild_item("job-a", &lease)
            .unwrap()
            .unwrap();
        storage
            .mark_generation_rebuild_embedding_started(&item, &lease)
            .unwrap();
        storage
            .mark_generation_rebuild_vector_write_started(&item, &lease)
            .unwrap();
        let job = storage.load_generation_rebuild_job("job-a").unwrap();
        assert_eq!(
            storage
                .finalize_generation_rebuild_item(&job, &item, &lease)
                .unwrap(),
            GenerationRebuildFinalizeOutcome::Applied
        );
        let applied_again = storage
            .finalize_generation_rebuild_item(&job, &item, &lease)
            .unwrap();
        assert_eq!(
            applied_again,
            GenerationRebuildFinalizeOutcome::AlreadyApplied
        );
        let state = storage.state().unwrap();
        let row: (i64, Option<String>, String, String) = state
            .connection
            .query_row(
                "SELECT j.applied_item_count,ri.canonical_document,ri.state,ri.io_phase FROM memory_vector_generation_rebuild_job j JOIN memory_vector_generation_rebuild_item ri ON ri.job_id=j.job_id WHERE j.job_id='job-a'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(row.0, 1);
        assert_eq!(row.1, None);
        assert_eq!(row.2, "applied");
        assert_eq!(row.3, "finalized");

        drop(state);
        let (_root, unknown_storage) = service("generation-unknown-item");
        seed_life(&unknown_storage);
        insert_memory(
            &unknown_storage,
            "safe",
            "confirmed",
            "content",
            Some("summary"),
            0,
            1,
        );
        let unknown_lease = registered_building(&unknown_storage);
        unknown_storage
            .snapshot_generation_rebuild("job-a", &unknown_lease)
            .unwrap();
        let unknown_item = unknown_storage
            .reserve_next_generation_rebuild_item("job-a", &unknown_lease)
            .unwrap()
            .unwrap();
        unknown_storage
            .fail_generation_rebuild_after_unknown(
                &unknown_item,
                &unknown_lease,
                "GENERATION_REBUILD_PROVIDER_RESULT_UNKNOWN",
                1,
            )
            .unwrap();
        let unknown_job = unknown_storage
            .load_generation_rebuild_job("job-a")
            .unwrap();
        let unknown_items = unknown_storage
            .list_generation_rebuild_items("job-a")
            .unwrap();
        assert_eq!(unknown_job.status, "failed");
        assert_eq!(unknown_job.generation_state, "failed");
        assert_eq!(unknown_items[0].state, "uncertain");
        assert_eq!(unknown_items[0].canonical_document, None);
    }
}
