use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::memory::{
    candidate_service::contains_prohibited_content,
    vector_sync_outbox::{
        ClaimMemoryVectorSyncLeaseRequest, ClaimMemoryVectorSyncRequest,
        EnqueueMemoryVectorSyncRequest, MemoryVectorSyncAction, MemoryVectorSyncJob,
        MemoryVectorSyncOutboxError, MemoryVectorSyncOutboxErrorCode,
        MemoryVectorSyncOutboxRepository, MemoryVectorSyncState,
    },
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
    let memory: Option<(String, String, String, i64, String, Option<String>)> = transaction
        .query_row(
            "SELECT life_id, kind, status, revision, content, summary FROM memory_record WHERE id = ?1",
            params![memory_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .optional()
        .map_err(|_| outbox_error())?;
    match memory.as_ref().map(|row| row.0.as_str()) {
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
    let (target_revision, target_content_hash) = match action {
        MemoryVectorSyncAction::Upsert => {
            let (_, kind, status, revision, content, summary) =
                memory.as_ref().expect("checked memory");
            if status != "confirmed" {
                return Err(outbox_error());
            }
            let selected = summary
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(content);
            if selected.trim().is_empty() {
                return Err(outbox_error());
            }
            if contains_prohibited_content(content)
                || summary.as_deref().is_some_and(contains_prohibited_content)
            {
                return Err(outbox_error());
            }
            (
                Some(*revision),
                Some(canonical_content_hash(
                    kind,
                    content,
                    summary.as_deref(),
                    selected,
                )),
            )
        }
        MemoryVectorSyncAction::Delete => (None, None),
    };
    let changed = transaction
        .execute(
            "UPDATE memory_vector_sync_mutation_clock
         SET last_sequence = last_sequence + 1
         WHERE singleton = 1 AND last_sequence < 9223372036854775807",
            [],
        )
        .map_err(|_| outbox_error())?;
    if changed != 1 {
        return Err(outbox_error());
    }
    let sequence: i64 = transaction
        .query_row(
            "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| outbox_error())?;
    transaction
        .execute(
            "INSERT INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, mutation_sequence, target_revision, target_content_hash, migration_disposition)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL)
         ON CONFLICT(life_id, memory_id) DO UPDATE SET
           desired_action = excluded.desired_action, state = 'pending', attempt_count = 0,
           next_attempt_at = NULL, lease_owner = NULL, lease_expires_at = NULL,
           lease_fence_epoch = NULL, claimed_generation_id = NULL, last_send_disposition = NULL,
           migration_disposition = NULL, mutation_sequence = excluded.mutation_sequence,
           target_revision = excluded.target_revision, target_content_hash = excluded.target_content_hash,
           last_error_code = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')",
            params![life_id, memory_id, action.as_str(), sequence, target_revision, target_content_hash],
        )
        .map_err(|_| outbox_error())?;
    Ok(())
}

fn canonical_content_hash(
    kind: &str,
    content: &str,
    summary: Option<&str>,
    selected: &str,
) -> String {
    let mut hasher = Sha256::new();
    for field in [
        b"memory-index-v1".as_slice(),
        kind.as_bytes(),
        selected.as_bytes(),
        content.as_bytes(),
        summary.unwrap_or_default().as_bytes(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Private capability returned only after the global runtime lease and the
/// event lease have both been acquired.  It deliberately has no constructor
/// and its debug output never contains memory text or provider data.
#[allow(dead_code)]
pub(crate) struct FencedVectorSyncClaim {
    id: i64,
    life_id: String,
    memory_id: String,
    action: MemoryVectorSyncAction,
    mutation_sequence: i64,
    target_revision: Option<i64>,
    target_content_hash: Option<String>,
    generation_id: String,
    lease_owner: String,
    fence_epoch: i64,
}

impl std::fmt::Debug for FencedVectorSyncClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FencedVectorSyncClaim")
            .field("id", &self.id)
            .field("action", &self.action)
            .field("mutation_sequence", &self.mutation_sequence)
            .field("has_target", &self.target_revision.is_some())
            .field("generation_id_len", &self.generation_id.len())
            .field("fence_epoch", &self.fence_epoch)
            .finish()
    }
}

#[allow(dead_code)]
impl FencedVectorSyncClaim {
    pub(crate) fn id(&self) -> i64 {
        self.id
    }
    pub(crate) fn mutation_sequence(&self) -> i64 {
        self.mutation_sequence
    }
    pub(crate) fn lease_owner(&self) -> &str {
        &self.lease_owner
    }
    pub(crate) fn fence_epoch(&self) -> i64 {
        self.fence_epoch
    }
    pub(crate) fn action(&self) -> MemoryVectorSyncAction {
        self.action
    }
    pub(crate) fn life_id(&self) -> &str {
        &self.life_id
    }
    pub(crate) fn memory_id(&self) -> &str {
        &self.memory_id
    }
    pub(crate) fn generation_id(&self) -> &str {
        &self.generation_id
    }
    pub(crate) fn target_revision(&self) -> Option<i64> {
        self.target_revision
    }
    pub(crate) fn target_content_hash(&self) -> Option<&str> {
        self.target_content_hash.as_deref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum FencedFinalizeResult {
    Applied,
    LostLeaseOrSuperseded,
}

#[allow(dead_code)]
impl StorageService {
    /// D-9D1 creates only explicit, non-active generations.  Activation and
    /// rebuild orchestration remain D-9D3 responsibilities.
    pub(crate) fn register_building_vector_generation(
        &self,
        generation_id: &str,
        descriptor_hash: &str,
        dimension: usize,
    ) -> Result<(), crate::storage::StorageError> {
        if generation_id.is_empty() || descriptor_hash.is_empty() || dimension == 0 {
            return Err(single_event_error());
        }
        let state = self.state()?;
        state.connection.execute(
            "INSERT INTO memory_vector_generation (generation_id, descriptor_hash, dimension, state)
             VALUES (?1, ?2, ?3, 'building')
             ON CONFLICT(generation_id) DO NOTHING",
            params![generation_id, descriptor_hash, dimension as i64],
        ).map_err(|_| single_event_error())?;
        let existing: Option<(String, i64, String)> = state
            .connection
            .query_row(
                "SELECT descriptor_hash, dimension, state FROM memory_vector_generation WHERE generation_id=?1",
                params![generation_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| single_event_error())?;
        let Some((existing_descriptor, existing_dimension, existing_state)) = existing else {
            return Err(single_event_error());
        };
        if existing_descriptor != descriptor_hash {
            return Err(crate::storage::StorageError::new(
                "GENERATION_DESCRIPTOR_MISMATCH",
                "The vector generation descriptor does not match.",
                false,
            ));
        }
        if existing_dimension != dimension as i64 {
            return Err(crate::storage::StorageError::new(
                "GENERATION_DIMENSION_MISMATCH",
                "The vector generation dimension does not match.",
                false,
            ));
        }
        if existing_state != "building" {
            return Err(crate::storage::StorageError::new(
                "GENERATION_STATE_CONFLICT",
                "The vector generation cannot be registered in its current state.",
                false,
            ));
        }
        Ok(())
    }

    pub(crate) fn claim_one_fenced_vector_sync(
        &self,
        generation_id: &str,
        descriptor_hash: &str,
        dimension: usize,
        lease_owner: &str,
    ) -> Result<Option<FencedVectorSyncClaim>, crate::storage::StorageError> {
        if generation_id.is_empty()
            || descriptor_hash.is_empty()
            || dimension == 0
            || lease_owner.is_empty()
            || lease_owner.len() > 128
        {
            return Err(single_event_error());
        }
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        let generation_ok: Option<i64> = tx.query_row(
            "SELECT 1 FROM memory_vector_generation WHERE generation_id=?1 AND descriptor_hash=?2 AND dimension=?3 AND state='building'",
            params![generation_id, descriptor_hash, dimension as i64], |row| row.get(0),
        ).optional().map_err(|_| single_event_error())?;
        if generation_ok.is_none() {
            tx.commit().map_err(|_| single_event_error())?;
            return Ok(None);
        }
        let fence_epoch = acquire_runtime_lease(&tx, lease_owner)?;
        // A malformed post-012 upsert is fail-closed without materializing its
        // current memory body. Legacy quarantine is separately and permanently
        // excluded by the claim predicate below.
        tx.execute(
            "UPDATE memory_vector_sync_outbox SET state='blocked', lease_owner=NULL,
             lease_expires_at=NULL, lease_fence_epoch=NULL, claimed_generation_id=NULL,
             last_error_code='VECTOR_TARGET_BINDING_MISSING', updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE desired_action='upsert' AND migration_disposition IS NULL
               AND (target_revision IS NULL OR target_content_hash IS NULL)
               AND state IN ('pending','retry_wait','processing')",
            [],
        ).map_err(|_| single_event_error())?;
        tx.execute(
            "UPDATE memory_vector_sync_outbox SET state='pending', lease_owner=NULL,
             lease_expires_at=NULL, lease_fence_epoch=NULL, claimed_generation_id=NULL,
             last_send_disposition=NULL, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE state='processing' AND lease_expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            [],
        )
        .map_err(|_| single_event_error())?;
        let id: Option<i64> = tx.query_row(
            "SELECT id FROM memory_vector_sync_outbox WHERE migration_disposition IS NULL AND
              ((desired_action='upsert' AND target_revision IS NOT NULL AND target_content_hash IS NOT NULL)
               OR (desired_action='delete' AND target_revision IS NULL AND target_content_hash IS NULL)) AND
              (state='pending' OR (state='retry_wait' AND next_attempt_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now')))
             ORDER BY mutation_sequence ASC, id ASC LIMIT 1", [], |row| row.get(0),
        ).optional().map_err(|_| single_event_error())?;
        let Some(id) = id else {
            tx.commit().map_err(|_| single_event_error())?;
            return Ok(None);
        };
        let changed = tx.execute(
            "UPDATE memory_vector_sync_outbox SET state='processing',
             lease_owner=?2, lease_fence_epoch=?3, claimed_generation_id=?4,
             lease_expires_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','+120 seconds'), next_attempt_at=NULL,
             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE id=?1 AND migration_disposition IS NULL AND state IN ('pending','retry_wait')",
            params![id, lease_owner, fence_epoch, generation_id],
        ).map_err(|_| single_event_error())?;
        if changed != 1 {
            return Err(single_event_error());
        }
        let claim = tx.query_row(
            "SELECT id, life_id, memory_id, desired_action, mutation_sequence, target_revision, target_content_hash,
                    claimed_generation_id, lease_owner, lease_fence_epoch
             FROM memory_vector_sync_outbox WHERE id=?1", params![id], fenced_claim_from_row,
        ).map_err(|_| single_event_error())?;
        tx.commit().map_err(|_| single_event_error())?;
        Ok(Some(claim))
    }

    /// Reads authority only after a structurally valid upsert claim exists.
    /// A mismatch is returned as `None`, making stale data a safe no-write.
    pub(crate) fn read_fenced_vector_document(
        &self,
        claim: &FencedVectorSyncClaim,
    ) -> Result<Option<String>, crate::storage::StorageError> {
        if claim.action != MemoryVectorSyncAction::Upsert {
            return Ok(None);
        }
        let state = self.state()?;
        let row: Option<(String, String, i64, String, Option<String>, i64)> = state.connection.query_row(
            "SELECT kind, status, revision, content, summary, is_sensitive FROM memory_record WHERE id=?1 AND life_id=?2",
            params![claim.memory_id, claim.life_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        ).optional().map_err(|_| single_event_error())?;
        let Some((kind, status, revision, content, summary, sensitive)) = row else {
            return Ok(None);
        };
        if status != "confirmed" || sensitive != 0 || Some(revision) != claim.target_revision {
            return Ok(None);
        }
        if contains_prohibited_content(&content)
            || summary.as_deref().is_some_and(contains_prohibited_content)
        {
            return Ok(None);
        }
        let selected = summary
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(&content);
        if selected.trim().is_empty()
            || Some(canonical_content_hash(&kind, &content, summary.as_deref(), selected).as_str())
                != claim.target_content_hash()
        {
            return Ok(None);
        }
        Ok(Some(selected.to_owned()))
    }

    /// A second, short authority check immediately before external I/O.  It
    /// cannot make SQLite and LanceDB one transaction, but it prevents a known
    /// superseded claim from initiating a provider or vector operation.
    pub(crate) fn fenced_vector_claim_is_current(
        &self,
        claim: &FencedVectorSyncClaim,
    ) -> Result<bool, crate::storage::StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        let renewed = tx.execute(
            "UPDATE memory_vector_sync_runtime_lease
             SET expires_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','+120 seconds'), updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE lease_name='memory-vector-single-event-consumer' AND owner_id=?1 AND fence_epoch=?2
               AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            params![claim.lease_owner, claim.fence_epoch],
        ).map_err(|_| single_event_error())?;
        let current = renewed == 1 && fenced_claim_current_in(&tx, claim)?;
        tx.commit().map_err(|_| single_event_error())?;
        Ok(current)
    }

    pub(crate) fn mark_fenced_attempt_started(
        &self,
        claim: &FencedVectorSyncClaim,
    ) -> Result<bool, crate::storage::StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        let current = fenced_claim_current_in(&tx, claim)?;
        let changed = if current {
            tx.execute(
                "UPDATE memory_vector_sync_outbox SET attempt_count=attempt_count+1,
                 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE id=?1 AND mutation_sequence=?2 AND state='processing' AND lease_owner=?3
                   AND lease_fence_epoch=?4 AND claimed_generation_id=?5",
                params![
                    claim.id,
                    claim.mutation_sequence,
                    claim.lease_owner,
                    claim.fence_epoch,
                    claim.generation_id
                ],
            )
            .map_err(|_| single_event_error())?
        } else {
            0
        };
        tx.commit().map_err(|_| single_event_error())?;
        Ok(changed == 1)
    }

    pub(crate) fn finalize_fenced_vector_sync(
        &self,
        claim: &FencedVectorSyncClaim,
        content_hash: Option<&str>,
        error_code: Option<&str>,
        retry: bool,
        send_disposition: Option<&str>,
    ) -> Result<FencedFinalizeResult, crate::storage::StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        let predicate = "id=?1 AND mutation_sequence=?2 AND state='processing' AND lease_owner=?3 AND lease_fence_epoch=?4 AND claimed_generation_id=?5";
        if !fenced_claim_current_in(&tx, claim)? {
            tx.commit().map_err(|_| single_event_error())?;
            return Ok(FencedFinalizeResult::LostLeaseOrSuperseded);
        }
        if let Some(error_code) = error_code {
            let changed = tx.execute(
                &format!("UPDATE memory_vector_sync_outbox SET state={}, next_attempt_at={}, lease_owner=NULL, lease_expires_at=NULL, lease_fence_epoch=NULL, claimed_generation_id=NULL, last_error_code=?6, last_send_disposition=?7, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE {predicate}", if retry { "'retry_wait'" } else { "'blocked'" }, if retry { "strftime('%Y-%m-%dT%H:%M:%fZ','now','+30 seconds')" } else { "NULL" }),
                params![claim.id, claim.mutation_sequence, claim.lease_owner, claim.fence_epoch, claim.generation_id, safe_error_code(error_code), send_disposition],
            ).map_err(|_| single_event_error())?;
            tx.commit().map_err(|_| single_event_error())?;
            return Ok(if changed == 1 {
                FencedFinalizeResult::Applied
            } else {
                FencedFinalizeResult::LostLeaseOrSuperseded
            });
        }
        if claim.action == MemoryVectorSyncAction::Upsert {
            let hash = content_hash.ok_or_else(single_event_error)?;
            let changed = tx.execute(
                &format!("INSERT INTO memory_vector_generation_item (generation_id, life_id, memory_id, memory_revision, content_hash)
                 SELECT ?5, ?6, ?7, ?8, ?9 WHERE EXISTS (SELECT 1 FROM memory_vector_sync_outbox WHERE {predicate})
                 ON CONFLICT(generation_id, life_id, memory_id) DO UPDATE SET memory_revision=excluded.memory_revision, content_hash=excluded.content_hash, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')"),
                params![claim.id, claim.mutation_sequence, claim.lease_owner, claim.fence_epoch, claim.generation_id, claim.life_id, claim.memory_id, claim.target_revision, hash],
            ).map_err(|_| single_event_error())?;
            if changed != 1 {
                tx.commit().map_err(|_| single_event_error())?;
                return Ok(FencedFinalizeResult::LostLeaseOrSuperseded);
            }
        } else {
            tx.execute("DELETE FROM memory_vector_generation_item WHERE generation_id=?1 AND life_id=?2 AND memory_id=?3", params![claim.generation_id, claim.life_id, claim.memory_id]).map_err(|_| single_event_error())?;
        }
        let changed = tx
            .execute(
                &format!("DELETE FROM memory_vector_sync_outbox WHERE {predicate}"),
                params![
                    claim.id,
                    claim.mutation_sequence,
                    claim.lease_owner,
                    claim.fence_epoch,
                    claim.generation_id
                ],
            )
            .map_err(|_| single_event_error())?;
        tx.commit().map_err(|_| single_event_error())?;
        Ok(if changed == 1 {
            FencedFinalizeResult::Applied
        } else {
            FencedFinalizeResult::LostLeaseOrSuperseded
        })
    }

    #[cfg(test)]
    pub(crate) fn test_fenced_outbox_failure_snapshot(
        &self,
    ) -> Result<(i64, Option<String>, String), crate::storage::StorageError> {
        let state = self.state()?;
        state.connection.query_row(
            "SELECT attempt_count, last_send_disposition, last_error_code FROM memory_vector_sync_outbox",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| single_event_error())
    }

    #[cfg(test)]
    pub(crate) fn test_expire_fenced_runtime_lease(
        &self,
    ) -> Result<(), crate::storage::StorageError> {
        let state = self.state()?;
        state
            .connection
            .execute(
                "UPDATE memory_vector_sync_runtime_lease SET expires_at='2000-01-01T00:00:00.000Z'",
                [],
            )
            .map_err(|_| single_event_error())?;
        state
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox SET lease_expires_at='2000-01-01T00:00:00.000Z' WHERE state='processing'",
                [],
            )
            .map_err(|_| single_event_error())?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_fenced_completion_snapshot(
        &self,
    ) -> Result<(String, i64, i64), crate::storage::StorageError> {
        let state = self.state()?;
        let job = state
            .connection
            .query_row(
                "SELECT state, attempt_count FROM memory_vector_sync_outbox",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| single_event_error())?;
        let items = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_generation_item",
                [],
                |row| row.get(0),
            )
            .map_err(|_| single_event_error())?;
        Ok((job.0, job.1, items))
    }

    #[cfg(test)]
    pub(crate) fn test_get_outbox_snapshot_detailed(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<OutboxSnapshotDetailed, crate::storage::StorageError> {
        let state = self.state()?;
        let total_count: usize = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_sync_outbox",
                [],
                |row| row.get(0),
            )
            .map_err(|_| single_event_error())?;
        let row = state.connection.query_row(
            "SELECT id, desired_action, mutation_sequence, target_revision, target_content_hash,
                    state, attempt_count, lease_owner, lease_fence_epoch, claimed_generation_id,
                    (claimed_generation_id IS NULL), migration_disposition, last_error_code, last_send_disposition
             FROM memory_vector_sync_outbox WHERE life_id=?1 AND memory_id=?2",
            params![life_id, memory_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get::<_, i64>(10)? == 1,
                    r.get(11)?,
                    r.get(12)?,
                    r.get(13)?,
                ))
            },
        ).map_err(|_| single_event_error())?;
        Ok(OutboxSnapshotDetailed {
            total_count,
            id: row.0,
            desired_action: row.1,
            mutation_sequence: row.2,
            target_revision: row.3,
            target_content_hash: row.4,
            state: row.5,
            attempt_count: row.6,
            lease_owner: row.7,
            lease_fence_epoch: row.8,
            claimed_generation_id: row.9,
            claimed_generation_id_is_null: row.10,
            migration_disposition: row.11,
            last_error_code: row.12,
            last_send_disposition: row.13,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_insert_legacy_quarantine_fixture(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<i64, crate::storage::StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        tx.execute(
            "INSERT OR IGNORE INTO memory_vector_sync_mutation_clock (singleton, last_sequence) VALUES (1, 0)",
            [],
        )
        .map_err(|_| single_event_error())?;
        tx.execute(
            "UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton = 1",
            [],
        )
        .map_err(|_| single_event_error())?;
        let sequence: i64 = tx
            .query_row(
                "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| single_event_error())?;
        tx.execute(
            "INSERT INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, mutation_sequence, target_revision, target_content_hash, migration_disposition)
             VALUES (?1, ?2, 'upsert', 'blocked', 0, ?3, NULL, NULL, 'legacy_upsert_rebuild_required')
             ON CONFLICT(life_id, memory_id) DO UPDATE SET
               desired_action='upsert', state='blocked', attempt_count=0, mutation_sequence=?3,
               target_revision=NULL, target_content_hash=NULL, migration_disposition='legacy_upsert_rebuild_required',
               lease_owner=NULL, lease_expires_at=NULL, lease_fence_epoch=NULL, claimed_generation_id=NULL,
               updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            params![life_id, memory_id, sequence],
        ).map_err(|_| single_event_error())?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(|_| single_event_error())?;
        Ok(id)
    }

    #[cfg(test)]
    pub(crate) fn test_generation_item_count(
        &self,
    ) -> Result<usize, crate::storage::StorageError> {
        let state = self.state()?;
        state.connection.query_row(
            "SELECT COUNT(*) FROM memory_vector_generation_item",
            [],
            |r| r.get(0),
        ).map_err(|_| single_event_error())
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutboxSnapshotDetailed {
    pub total_count: usize,
    pub id: i64,
    pub desired_action: String,
    pub mutation_sequence: i64,
    pub target_revision: Option<i64>,
    pub target_content_hash: Option<String>,
    pub state: String,
    pub attempt_count: i64,
    pub lease_owner: Option<String>,
    pub lease_fence_epoch: Option<i64>,
    pub claimed_generation_id: Option<String>,
    pub claimed_generation_id_is_null: bool,
    pub migration_disposition: Option<String>,
    pub last_error_code: Option<String>,
    pub last_send_disposition: Option<String>,
}

#[allow(dead_code)]
fn acquire_runtime_lease(
    tx: &Transaction<'_>,
    owner: &str,
) -> Result<i64, crate::storage::StorageError> {
    tx.execute("INSERT OR IGNORE INTO memory_vector_sync_runtime_lease (lease_name, fence_epoch) VALUES ('memory-vector-single-event-consumer', 0)", []).map_err(|_| single_event_error())?;
    let renewed = tx.execute(
        "UPDATE memory_vector_sync_runtime_lease SET
         expires_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','+120 seconds'), updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE lease_name='memory-vector-single-event-consumer' AND owner_id=?1
           AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        params![owner],
    ).map_err(|_| single_event_error())?;
    if renewed == 1 {
        return tx.query_row(
            "SELECT fence_epoch FROM memory_vector_sync_runtime_lease WHERE lease_name='memory-vector-single-event-consumer' AND owner_id=?1",
            params![owner], |row| row.get(0),
        ).map_err(|_| single_event_error());
    }
    let acquired = tx.execute(
        "UPDATE memory_vector_sync_runtime_lease SET owner_id=?1, fence_epoch=fence_epoch+1,
         expires_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','+120 seconds'), updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE lease_name='memory-vector-single-event-consumer' AND fence_epoch < 9223372036854775807
           AND (owner_id IS NULL OR expires_at IS NULL OR expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        params![owner],
    ).map_err(|_| single_event_error())?;
    if acquired != 1 {
        return Err(single_event_error());
    }
    tx.query_row(
        "SELECT fence_epoch FROM memory_vector_sync_runtime_lease WHERE lease_name='memory-vector-single-event-consumer' AND owner_id=?1",
        params![owner], |row| row.get(0),
    ).map_err(|_| single_event_error())
}

fn fenced_claim_current_in(
    tx: &Transaction<'_>,
    claim: &FencedVectorSyncClaim,
) -> Result<bool, crate::storage::StorageError> {
    tx.query_row(
        "SELECT EXISTS(
           SELECT 1 FROM memory_vector_sync_outbox AS o
           JOIN memory_vector_sync_runtime_lease AS r
             ON r.lease_name='memory-vector-single-event-consumer'
          WHERE o.id=?1 AND o.mutation_sequence=?2 AND o.state='processing'
            AND o.lease_owner=?3 AND o.lease_fence_epoch=?4 AND o.claimed_generation_id=?5
            AND r.owner_id=?3 AND r.fence_epoch=?4
            AND r.expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')
        )",
        params![
            claim.id,
            claim.mutation_sequence,
            claim.lease_owner,
            claim.fence_epoch,
            claim.generation_id
        ],
        |row| Ok(row.get::<_, i64>(0)? == 1),
    )
    .map_err(|_| single_event_error())
}

#[allow(dead_code)]
fn fenced_claim_from_row(row: &Row<'_>) -> rusqlite::Result<FencedVectorSyncClaim> {
    let action: String = row.get(3)?;
    Ok(FencedVectorSyncClaim {
        id: row.get(0)?,
        life_id: row.get(1)?,
        memory_id: row.get(2)?,
        action: MemoryVectorSyncAction::parse(&action)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        mutation_sequence: row.get(4)?,
        target_revision: row.get(5)?,
        target_content_hash: row.get(6)?,
        generation_id: row.get(7)?,
        lease_owner: row.get(8)?,
        fence_epoch: row.get(9)?,
    })
}

#[allow(dead_code)]
fn single_event_error() -> crate::storage::StorageError {
    crate::storage::StorageError::new(
        "VECTOR_SYNC_UNAVAILABLE",
        "Vector synchronization is unavailable.",
        true,
    )
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
        // D-9D1 events are generation-fenced.  The legacy, life-scoped claim
        // token cannot carry that authority and must never consume this outbox.
        if legacy_claims_are_disabled() {
            return Ok(None);
        }
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
        // See claim_next: the legacy worker is deliberately failed closed.
        if legacy_claims_are_disabled() {
            return Ok(None);
        }
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

fn legacy_claims_are_disabled() -> bool {
    // Migration 012 events are only consumable through the fenced, single
    // event API. The old life-scoped claim tokens lack generation and runtime
    // fence authority, so this remains closed in every build, including tests.
    true
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
        assert_eq!(version, 12);
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
        assert_eq!(version, 12);
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
    fn migration_012_quarantines_legacy_upserts_and_releases_only_processing_deletes() {
        let root = TestRoot::new();
        let data_root = root.0.join("data");
        fs::create_dir_all(&data_root).unwrap();
        let database_path = data_root.join(super::super::DATABASE_FILE_NAME);
        let connection = Connection::open(&database_path).unwrap();
        connection.execute_batch("CREATE TABLE schema_migration (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL);").unwrap();
        for (version, name, sql) in super::super::MIGRATIONS.iter().take(11) {
            connection.execute_batch(sql).unwrap();
            connection.execute("INSERT INTO schema_migration (version, name, applied_at) VALUES (?1, ?2, '2026-01-01T00:00:00Z')", params![version, name]).unwrap();
        }
        connection.execute("INSERT INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, created_at, updated_at) VALUES ('life', 'legacy-upsert', 'upsert', 'processing', 2, 'OLD_CODE', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')", []).unwrap();
        connection.execute("INSERT INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, created_at, updated_at) VALUES ('life', 'legacy-delete', 'delete', 'processing', 3, 'DELETE_CODE', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')", []).unwrap();
        drop(connection);
        let storage = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = storage.state().unwrap();
        let upsert: (String, Option<String>, Option<i64>, Option<String>, i64, String) = state.connection.query_row(
            "SELECT state, migration_disposition, target_revision, target_content_hash, attempt_count, last_error_code FROM memory_vector_sync_outbox WHERE memory_id='legacy-upsert'", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        ).unwrap();
        assert_eq!(
            upsert,
            (
                "blocked".into(),
                Some("legacy_upsert_rebuild_required".into()),
                None,
                None,
                2,
                "OLD_CODE".into()
            )
        );
        let delete: (String, Option<String>, i64, String) = state.connection.query_row(
            "SELECT state, migration_disposition, attempt_count, last_error_code FROM memory_vector_sync_outbox WHERE memory_id='legacy-delete'", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).unwrap();
        assert_eq!(delete, ("pending".into(), None, 3, "DELETE_CODE".into()));
        let clock: i64 = state
            .connection
            .query_row(
                "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let max_sequence: i64 = state
            .connection
            .query_row(
                "SELECT MAX(mutation_sequence) FROM memory_vector_sync_outbox",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(clock >= max_sequence);
    }

    #[test]
    fn migration_012_failure_rolls_back_schema_and_outbox_mutations() {
        let root = TestRoot::new();
        let data_root = root.0.join("data");
        fs::create_dir_all(&data_root).unwrap();
        let database_path = data_root.join(super::super::DATABASE_FILE_NAME);
        let mut connection = Connection::open(&database_path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migration (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );",
            )
            .unwrap();
        for (version, name, sql) in super::super::MIGRATIONS.iter().take(11) {
            connection.execute_batch(sql).unwrap();
            connection
                .execute(
                    "INSERT INTO schema_migration (version, name, applied_at)
                     VALUES (?1, ?2, '2026-01-01T00:00:00Z')",
                    params![version, name],
                )
                .unwrap();
        }
        connection
            .execute(
                "INSERT INTO memory_vector_sync_outbox
                 (id, life_id, memory_id, desired_action, state, attempt_count, last_error_code,
                  next_attempt_at, created_at, updated_at)
                 VALUES (17, 'life', 'rollback-row', 'upsert', 'retry_wait', 4, 'OLD_CODE',
                         '2026-01-02T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-03T00:00:00Z')",
                [],
            )
            .unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute_batch(super::super::MIGRATIONS[11].2)
            .unwrap();
        assert!(transaction
            .execute_batch("SELECT intentionally_invalid_sql")
            .is_err());
        transaction.rollback().unwrap();

        let generation_table: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='memory_vector_generation'",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(generation_table, None);
        let row: (i64, String, i64, String, Option<String>, String, String) = connection
            .query_row(
                "SELECT id, state, attempt_count, last_error_code, next_attempt_at, created_at, updated_at
                 FROM memory_vector_sync_outbox WHERE memory_id='rollback-row'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            row,
            (
                17,
                "retry_wait".into(),
                4,
                "OLD_CODE".into(),
                Some("2026-01-02T00:00:00Z".into()),
                "2026-01-01T00:00:00Z".into(),
                "2026-01-03T00:00:00Z".into(),
            )
        );
        let columns: Vec<String> = connection
            .prepare("PRAGMA table_info(memory_vector_sync_outbox)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!columns.iter().any(|column| column == "mutation_sequence"));
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn migration_012_preserves_non_contiguous_rowids_and_maps_all_legacy_delete_states() {
        let root = TestRoot::new();
        let data_root = root.0.join("data");
        fs::create_dir_all(&data_root).unwrap();
        let database_path = data_root.join(super::super::DATABASE_FILE_NAME);
        let connection = Connection::open(&database_path).unwrap();
        connection.execute_batch("CREATE TABLE schema_migration (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL);").unwrap();
        for (version, name, sql) in super::super::MIGRATIONS.iter().take(11) {
            connection.execute_batch(sql).unwrap();
            connection.execute("INSERT INTO schema_migration (version, name, applied_at) VALUES (?1, ?2, '2026-01-01T00:00:00Z')", params![version, name]).unwrap();
        }
        let fixtures = [
            (2_i64, "upsert", "pending"),
            (7, "delete", "pending"),
            (19, "delete", "processing"),
            (41, "delete", "retry_wait"),
            (103, "delete", "blocked"),
            (211, "delete", "failed"),
        ];
        for (index, (id, action, state)) in fixtures.iter().enumerate() {
            connection
                .execute(
                    "INSERT INTO memory_vector_sync_outbox
                 (id, life_id, memory_id, desired_action, state, attempt_count, last_error_code,
                  next_attempt_at, lease_owner, lease_expires_at, created_at, updated_at)
                 VALUES (?1, 'life', ?2, ?3, ?4, ?5, ?6, ?7, 'legacy-owner',
                         '2099-01-01T00:00:00Z', ?8, ?9)",
                    params![
                        id,
                        format!("legacy-{id}"),
                        action,
                        state,
                        (index + 1) as i64,
                        format!("OLD_{id}"),
                        format!("2026-01-{:02}T00:00:00Z", index + 1),
                        format!("2025-12-{:02}T00:00:00Z", index + 1),
                        format!("2026-02-{:02}T00:00:00Z", index + 1),
                    ],
                )
                .unwrap();
        }
        let before: Vec<(i64, i64, String, String, String, i64, String, Option<String>, String, String)> = connection.prepare(
            "SELECT rowid, id, life_id, memory_id, desired_action, attempt_count, last_error_code, next_attempt_at, created_at, updated_at FROM memory_vector_sync_outbox ORDER BY id"
        ).unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?))).unwrap().map(Result::unwrap).collect();
        drop(connection);

        let storage = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = storage.state().unwrap();
        let after: Vec<(i64, i64, String, String, String, String, i64, String, Option<String>, String, Option<String>, Option<i64>, Option<String>, Option<String>, Option<String>, Option<i64>, Option<String>)> = state.connection.prepare(
            "SELECT rowid, id, life_id, memory_id, desired_action, state, attempt_count, last_error_code, next_attempt_at, created_at, migration_disposition, target_revision, target_content_hash, lease_owner, lease_expires_at, lease_fence_epoch, last_send_disposition FROM memory_vector_sync_outbox ORDER BY id"
        ).unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?, row.get(11)?, row.get(12)?, row.get(13)?, row.get(14)?, row.get(15)?, row.get(16)?))).unwrap().map(Result::unwrap).collect();
        assert_eq!(before.len(), after.len());
        for (index, row) in after.iter().enumerate() {
            let original = &before[index];
            assert_eq!(
                (row.0, row.1, &row.2, &row.3, &row.4, row.6, &row.7, &row.8, &row.9),
                (
                    original.0,
                    original.1,
                    &original.2,
                    &original.3,
                    &original.4,
                    original.5,
                    &original.6,
                    &original.7,
                    &original.8
                )
            );
            assert_eq!(row.13, None);
            assert_eq!(row.14, None);
            assert_eq!(row.15, None);
            assert_eq!(row.16, None);
            if row.4 == "upsert" {
                assert_eq!(row.5, "blocked");
                assert_eq!(row.10.as_deref(), Some("legacy_upsert_rebuild_required"));
            } else {
                let expected = if original.4 == "delete" && fixtures[index].2 == "processing" {
                    "pending"
                } else {
                    fixtures[index].2
                };
                assert_eq!(row.5, expected);
                assert_eq!(row.10, None);
                assert_eq!(row.11, None);
                assert_eq!(row.12, None);
            }
        }
    }

    #[test]
    fn post_012_mutation_replaces_legacy_quarantine_with_bound_target() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        let state = storage.state().unwrap();
        let row: (i64, Option<i64>, Option<String>, Option<String>) = state.connection.query_row(
            "SELECT mutation_sequence, target_revision, target_content_hash, migration_disposition FROM memory_vector_sync_outbox WHERE memory_id=?1", params![record.id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).unwrap();
        assert!(row.0 > 0);
        assert_eq!(row.1, Some(1));
        assert!(row.2.is_some());
        assert_eq!(row.3, None);
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
    fn legacy_claim_apis_fail_closed_for_post_012_outbox() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        assert!(storage
            .claim_next(ClaimMemoryVectorSyncRequest {
                life_id: "life".into(),
                lease_owner: "worker-a".into(),
                lease_expires_at: "2999-01-01T00:00:00.000Z".into(),
            })
            .unwrap()
            .is_none());
        assert!(storage
            .claim_next_with_lease(ClaimMemoryVectorSyncLeaseRequest {
                life_id: "life".into(),
                lease_owner: "worker-b".into(),
                lease_seconds: 120,
            })
            .unwrap()
            .is_none());
        let job = storage.list("life").unwrap().remove(0);
        assert_eq!(job.memory_id, record.id);
        assert_eq!(job.state, MemoryVectorSyncState::Pending);
        assert_eq!(job.attempt_count, 0);
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
        assert_eq!(obtained, 0);
    }

    #[test]
    fn same_owner_renewal_keeps_fence_and_expired_takeover_advances_it() {
        let (_root, storage) = storage();
        let mut state = storage.state().unwrap();
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let first = acquire_runtime_lease(&transaction, "worker-a").unwrap();
        transaction.commit().unwrap();

        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let renewed = acquire_runtime_lease(&transaction, "worker-a").unwrap();
        assert_eq!(renewed, first);
        transaction.commit().unwrap();

        state
            .connection
            .execute(
                "UPDATE memory_vector_sync_runtime_lease SET expires_at='2000-01-01T00:00:00.000Z'",
                [],
            )
            .unwrap();
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let takeover = acquire_runtime_lease(&transaction, "worker-b").unwrap();
        assert_eq!(takeover, first + 1);
    }

    #[test]
    fn fenced_attempt_and_finalize_require_the_current_runtime_lease() {
        let (_root, storage) = storage();
        confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        assert_eq!(storage.list("life").unwrap()[0].attempt_count, 0);
        assert!(storage.mark_fenced_attempt_started(&claim).unwrap());
        assert_eq!(storage.list("life").unwrap()[0].attempt_count, 1);

        let state = storage.state().unwrap();
        state
            .connection
            .execute(
                "UPDATE memory_vector_sync_runtime_lease SET expires_at='2000-01-01T00:00:00.000Z'",
                [],
            )
            .unwrap();
        drop(state);
        assert!(!storage.fenced_vector_claim_is_current(&claim).unwrap());
        assert!(!storage.mark_fenced_attempt_started(&claim).unwrap());
        assert_eq!(
            storage
                .finalize_fenced_vector_sync(
                    &claim,
                    None,
                    Some("VECTOR_TARGET_STALE"),
                    false,
                    None,
                )
                .unwrap(),
            FencedFinalizeResult::LostLeaseOrSuperseded
        );
        let job = storage.list("life").unwrap().remove(0);
        assert_eq!(job.state, MemoryVectorSyncState::Processing);
        assert_eq!(job.attempt_count, 1);
    }

    #[test]
    fn embedding_send_disposition_is_persisted_only_for_embedding_failures() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        assert!(storage.mark_fenced_attempt_started(&claim).unwrap());
        assert_eq!(
            storage
                .finalize_fenced_vector_sync(
                    &claim,
                    None,
                    Some("NETWORK_UNAVAILABLE"),
                    true,
                    Some("definitely_not_sent"),
                )
                .unwrap(),
            FencedFinalizeResult::Applied
        );
        let state = storage.state().unwrap();
        let saved: Option<String> = state
            .connection
            .query_row(
                "SELECT last_send_disposition FROM memory_vector_sync_outbox WHERE memory_id=?1",
                params![record.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(saved.as_deref(), Some("definitely_not_sent"));
        drop(state);

        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        let reset: Option<String> = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT last_send_disposition FROM memory_vector_sync_outbox WHERE memory_id=?1",
                params![record.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reset, None);
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        assert!(storage.mark_fenced_attempt_started(&claim).unwrap());
        assert_eq!(
            storage
                .finalize_fenced_vector_sync(
                    &claim,
                    None,
                    Some("NETWORK_UNAVAILABLE"),
                    true,
                    Some("possibly_sent"),
                )
                .unwrap(),
            FencedFinalizeResult::Applied
        );
        let saved: Option<String> = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT last_send_disposition FROM memory_vector_sync_outbox WHERE memory_id=?1",
                params![record.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(saved.as_deref(), Some("possibly_sent"));
    }

    #[test]
    fn generation_identity_is_immutable_after_registration() {
        let (_root, storage) = storage();
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let descriptor_error = storage
            .register_building_vector_generation("generation-a", "descriptor-b", 2)
            .unwrap_err();
        assert_eq!(descriptor_error.code, "GENERATION_DESCRIPTOR_MISMATCH");
        let dimension_error = storage
            .register_building_vector_generation("generation-a", "descriptor-a", 3)
            .unwrap_err();
        assert_eq!(dimension_error.code, "GENERATION_DIMENSION_MISMATCH");
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_generation SET state='active' WHERE generation_id='generation-a'",
                [],
            )
            .unwrap();
        let state_error = storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap_err();
        assert_eq!(state_error.code, "GENERATION_STATE_CONFLICT");
    }
}
