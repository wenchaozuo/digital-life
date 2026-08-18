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
    vector_index::{canonical_index_text, canonical_memory_index_hash},
};

use super::{late_delete_resolution, StorageError, StorageService};

pub(crate) const GENERATION_REBUILD_MAX_ATTEMPTS: i64 = 5;
const GENERATION_REBUILD_LEASE_SECONDS: i64 = 120;
static REBUILD_ATTEMPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
        snapshot_item_count: row.get(18)?,
        applied_item_count: row.get(19)?,
        cancel_requested: row.get::<_, i64>(20)? != 0,
        lease_owner: row.get(21)?,
        lease_fence: row.get(22)?,
        lease_expires_at: row.get(23)?,
        last_error_code: row.get(24)?,
    })
}

const JOB_SELECT: &str = "SELECT j.job_id,j.request_id,j.generation_id,g.descriptor_hash,g.dimension,g.state,g.authority_epoch,b.descriptor_version,b.embedding_profile_id,w.create_operation_id,w.state,j.source_active_generation_id,j.source_active_authority_epoch,j.candidate_authority_epoch,j.status,j.snapshot_sequence,j.catchup_target_sequence,j.caught_up_sequence,j.snapshot_item_count,j.applied_item_count,j.cancel_requested,j.lease_owner,j.lease_fence,j.lease_expires_at,j.last_error_code FROM memory_vector_generation_rebuild_job j JOIN memory_vector_generation g ON g.generation_id=j.generation_id JOIN memory_vector_generation_binding b ON b.generation_id=g.generation_id JOIN memory_vector_generation_store_witness w ON w.generation_id=g.generation_id";

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
