#![allow(dead_code)] // Resolver execution is deliberately not wired to the worker in LD-I2.

//! Durable, fenced resolution of Deletes whose external result is unknown.
//!
//! This module intentionally has no worker, provider, or vector-store dependency.
//! It is a storage-only capability: callers can obtain a token only after SQLite
//! has reserved a bounded resolution slot, and every subsequent transition is a
//! compare-and-swap against that token.

use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use super::{StorageError, StorageService};

const RUNTIME_LEASE_NAME: &str = "memory-vector-late-delete-resolver";
const RUNTIME_LEASE_SECONDS: i64 = 120;
pub(crate) const MAX_LATE_DELETE_RESOLUTIONS: i64 = 3;

/// A runtime-wide resolver lease.  The fence epoch is deliberately carried by
/// every row lease and token, so a new owner cannot finalize an old owner's work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LateDeleteRuntimeLease {
    owner: String,
    fence_epoch: i64,
}

impl LateDeleteRuntimeLease {
    pub(crate) fn owner(&self) -> &str {
        &self.owner
    }

    pub(crate) fn fence_epoch(&self) -> i64 {
        self.fence_epoch
    }
}

/// A claimed resolution identity.  This is not an external-I/O capability;
/// callers must reserve it to receive [`LateDeleteResolutionToken`].
pub(crate) struct LateDeleteResolutionClaim {
    resolution_id: i64,
    life_id: String,
    memory_id: String,
    mutation_sequence: i64,
    claimed_generation_id: String,
    embedding_descriptor_id: String,
    embedding_dimension: i64,
    captured_generation_state: String,
    witness_attempt_ordinal: i64,
    witness_claim_epoch: i64,
    witness_marked_claim_epoch: i64,
    lease_owner: String,
    runtime_fence_epoch: i64,
    resolution_epoch: i64,
    resolution_count: i64,
}

/// Non-serializable, non-cloneable capability for exactly one bounded Late
/// Delete resolution slot. It binds the complete historical witness identity.
pub(crate) struct LateDeleteResolutionToken {
    resolution_id: i64,
    outbox_id: i64,
    life_id: String,
    memory_id: String,
    mutation_sequence: i64,
    desired_action: LateDeleteAction,
    target_revision: Option<i64>,
    target_content_hash: Option<String>,
    claimed_generation_id: String,
    embedding_descriptor_id: String,
    embedding_dimension: i64,
    captured_generation_state: String,
    witness_attempt_ordinal: i64,
    witness_claim_epoch: i64,
    witness_marked_claim_epoch: i64,
    lease_owner: String,
    runtime_fence_epoch: i64,
    resolution_epoch: i64,
    resolution_ordinal: i64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LateDeleteAction {
    Delete,
}

impl LateDeleteResolutionToken {
    pub(crate) fn resolution_ordinal(&self) -> i64 {
        self.resolution_ordinal
    }

    pub(crate) fn resolution_id(&self) -> i64 {
        self.resolution_id
    }
}

/// Result of atomically claiming the next candidate under a runtime lease.
pub(crate) enum LateDeleteResolutionClaimResult {
    Claimed(Box<LateDeleteResolutionClaim>),
    NoEligibleResolution,
}

/// Result of reserving a token. An already-reserved claim never consumes a
/// second slot; callers must treat it as non-replayable without a token.
pub(crate) enum LateDeleteResolutionReservation {
    Reserved(Box<LateDeleteResolutionToken>),
    AlreadyReserved { resolution_ordinal: i64 },
    LostLeaseOrSuperseded,
    ResolutionLimitReached,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LateDeleteResolutionDisposition {
    QueryAbsent,
    QueryPresent,
    QueryUnknown,
    DeleteStarted,
    DeleteAbsent,
    DeleteDeleted,
    IdentityMismatch,
    DeleteUnknown,
    FinalizeUnknown,
    WaitingRebuild,
    ResolvedRebuilt,
    Superseded,
}

impl LateDeleteResolutionDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::QueryAbsent => "query_absent",
            Self::QueryPresent => "query_present",
            Self::QueryUnknown => "query_unknown",
            Self::DeleteStarted => "delete_started",
            Self::DeleteAbsent => "delete_absent",
            Self::DeleteDeleted => "delete_deleted",
            Self::IdentityMismatch => "identity_mismatch",
            Self::DeleteUnknown => "delete_unknown",
            Self::FinalizeUnknown => "finalize_unknown",
            Self::WaitingRebuild => "waiting_rebuild",
            Self::ResolvedRebuilt => "resolved_rebuilt",
            Self::Superseded => "superseded",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LateDeleteResolutionFinalizeResult {
    Applied,
    LostLeaseOrSuperseded,
}

#[derive(Clone)]
struct ResolutionRow {
    resolution_id: i64,
    outbox_id: i64,
    life_id: String,
    memory_id: String,
    mutation_sequence: i64,
    claimed_generation_id: String,
    embedding_descriptor_id: String,
    embedding_dimension: i64,
    captured_generation_state: String,
    witness_attempt_ordinal: i64,
    witness_claim_epoch: i64,
    witness_marked_claim_epoch: i64,
    state: String,
    resolution_count: i64,
    resolution_epoch: i64,
    last_reserved_resolution_epoch: i64,
    lease_owner: Option<String>,
    lease_fence_epoch: Option<i64>,
}

fn storage_error(error: impl std::fmt::Display) -> StorageError {
    StorageError::new(
        "LATE_DELETE_RESOLUTION_DATABASE_ERROR",
        error.to_string(),
        true,
    )
}

pub(super) fn authoritative_utc_millis_now_in(
    transaction: &Transaction<'_>,
) -> Result<String, StorageError> {
    transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(storage_error)
}

/// Supersede every older non-terminal resolution for the same memory before a
/// new outbox mutation is made visible. The caller owns the transaction, so a
/// failed postcondition rolls back both the supersede and the enqueue.
pub(super) fn supersede_for_new_mutation_in(
    tx: &Transaction<'_>,
    life_id: &str,
    memory_id: &str,
    new_mutation_sequence: i64,
    transaction_now: &str,
) -> Result<usize, StorageError> {
    let changed = tx
        .execute(
            "UPDATE memory_vector_late_delete_resolution
             SET state='superseded', last_resolution_disposition='superseded',
                 last_disposition_epoch=resolution_epoch, resolved_at=?4, updated_at=?4,
                 lease_owner=NULL, lease_fence_epoch=NULL, lease_expires_at=NULL,
                 next_attempt_at=NULL
             WHERE life_id=?1 AND memory_id=?2 AND mutation_sequence < ?3
               AND state NOT IN ('resolved_absent','resolved_deleted','resolved_rebuilt','superseded')",
            params![life_id, memory_id, new_mutation_sequence, transaction_now],
        )
        .map_err(storage_error)?;
    let remaining: i64 = tx
        .query_row(
            "SELECT COUNT(*) FROM memory_vector_late_delete_resolution
             WHERE life_id=?1 AND memory_id=?2
               AND state NOT IN ('resolved_absent','resolved_deleted','resolved_rebuilt','superseded')",
            params![life_id, memory_id],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if remaining != 0 {
        return Err(StorageError::new(
            "LATE_DELETE_RESOLUTION_INVARIANT_VIOLATION",
            "a new mutation cannot coexist with an unresolved late delete",
            true,
        ));
    }
    Ok(changed)
}

impl StorageService {
    pub(crate) fn acquire_late_delete_runtime_lease(
        &self,
        owner: &str,
    ) -> Result<Option<LateDeleteRuntimeLease>, StorageError> {
        if owner.trim().is_empty() {
            return Err(StorageError::new(
                "LATE_DELETE_RESOLUTION_INVALID_OWNER",
                "late delete resolver owner must not be empty",
                false,
            ));
        }
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let now = authoritative_utc_millis_now_in(&tx)?;
        let changed = tx
            .execute(
                "UPDATE memory_vector_late_delete_runtime_lease
                 SET lease_owner=?1, lease_fence_epoch=lease_fence_epoch+1,
                     lease_expires_at=strftime('%Y-%m-%dT%H:%M:%fZ','now',?2), updated_at=?3
                 WHERE lease_name=?4
                   AND (lease_owner IS NULL OR lease_expires_at <= ?3)",
                params![
                    owner,
                    format!("+{RUNTIME_LEASE_SECONDS} seconds"),
                    now,
                    RUNTIME_LEASE_NAME
                ],
            )
            .map_err(storage_error)?;
        if changed == 0 {
            tx.commit().map_err(storage_error)?;
            return Ok(None);
        }
        let fence_epoch = tx
            .query_row(
                "SELECT lease_fence_epoch FROM memory_vector_late_delete_runtime_lease WHERE lease_name=?1 AND lease_owner=?2",
                params![RUNTIME_LEASE_NAME, owner],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        tx.commit().map_err(storage_error)?;
        Ok(Some(LateDeleteRuntimeLease {
            owner: owner.to_string(),
            fence_epoch,
        }))
    }

    pub(crate) fn release_late_delete_runtime_lease(
        &self,
        lease: &LateDeleteRuntimeLease,
    ) -> Result<bool, StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let now = authoritative_utc_millis_now_in(&tx)?;
        let changed = tx
            .execute(
                "UPDATE memory_vector_late_delete_runtime_lease
             SET lease_owner=NULL, lease_expires_at=NULL, updated_at=?3
             WHERE lease_name=?1 AND lease_owner=?2 AND lease_fence_epoch=?4",
                params![RUNTIME_LEASE_NAME, lease.owner, now, lease.fence_epoch],
            )
            .map_err(storage_error)?;
        tx.commit().map_err(storage_error)?;
        Ok(changed == 1)
    }

    pub(crate) fn claim_one_late_delete_resolution(
        &self,
        lease: &LateDeleteRuntimeLease,
    ) -> Result<LateDeleteResolutionClaimResult, StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let now = authoritative_utc_millis_now_in(&tx)?;
        if !runtime_lease_is_current_in(&tx, lease, &now)? {
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteResolutionClaimResult::NoEligibleResolution);
        }
        let row = select_next_candidate_in(&tx, &now)?;
        let Some(row) = row else {
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteResolutionClaimResult::NoEligibleResolution);
        };
        if row.resolution_count > MAX_LATE_DELETE_RESOLUTIONS {
            return Err(StorageError::new(
                "LATE_DELETE_RESOLUTION_LIMIT_VIOLATION",
                "resolution count exceeds the fixed budget",
                false,
            ));
        }
        if row.resolution_count == MAX_LATE_DELETE_RESOLUTIONS {
            block_limit_in(&tx, row.resolution_id, &now)?;
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteResolutionClaimResult::NoEligibleResolution);
        }
        let changed = tx
            .execute(
                "UPDATE memory_vector_late_delete_resolution
             SET state='claimed', resolution_epoch=resolution_epoch+1, lease_owner=?2,
                 lease_fence_epoch=?3, lease_expires_at=strftime('%Y-%m-%dT%H:%M:%fZ','now',?4),
                 next_attempt_at=NULL, updated_at=?5
             WHERE resolution_id=?1 AND state=?6 AND resolution_epoch=?7
               AND (lease_owner IS NULL OR lease_expires_at <= ?5)",
                params![
                    row.resolution_id,
                    lease.owner,
                    lease.fence_epoch,
                    format!("+{RUNTIME_LEASE_SECONDS} seconds"),
                    now,
                    row.state,
                    row.resolution_epoch
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteResolutionClaimResult::NoEligibleResolution);
        }
        let claim = LateDeleteResolutionClaim {
            resolution_id: row.resolution_id,
            life_id: row.life_id,
            memory_id: row.memory_id,
            mutation_sequence: row.mutation_sequence,
            claimed_generation_id: row.claimed_generation_id,
            embedding_descriptor_id: row.embedding_descriptor_id,
            embedding_dimension: row.embedding_dimension,
            captured_generation_state: row.captured_generation_state,
            witness_attempt_ordinal: row.witness_attempt_ordinal,
            witness_claim_epoch: row.witness_claim_epoch,
            witness_marked_claim_epoch: row.witness_marked_claim_epoch,
            lease_owner: lease.owner.clone(),
            runtime_fence_epoch: lease.fence_epoch,
            resolution_epoch: row.resolution_epoch + 1,
            resolution_count: row.resolution_count,
        };
        tx.commit().map_err(storage_error)?;
        Ok(LateDeleteResolutionClaimResult::Claimed(Box::new(claim)))
    }

    pub(crate) fn reserve_late_delete_resolution(
        &self,
        claim: &LateDeleteResolutionClaim,
    ) -> Result<LateDeleteResolutionReservation, StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let now = authoritative_utc_millis_now_in(&tx)?;
        let row = load_resolution_in(&tx, claim.resolution_id)?;
        let Some(row) = row else {
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteResolutionReservation::LostLeaseOrSuperseded);
        };
        if !claim_matches_row(claim, &row) || !runtime_lease_matches_in(&tx, claim, &now)? {
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteResolutionReservation::LostLeaseOrSuperseded);
        }
        if row.resolution_count > MAX_LATE_DELETE_RESOLUTIONS {
            return Err(StorageError::new(
                "LATE_DELETE_RESOLUTION_LIMIT_VIOLATION",
                "resolution count exceeds the fixed budget",
                false,
            ));
        }
        if row.resolution_count == MAX_LATE_DELETE_RESOLUTIONS {
            block_limit_in(&tx, row.resolution_id, &now)?;
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteResolutionReservation::ResolutionLimitReached);
        }
        if row.last_reserved_resolution_epoch == row.resolution_epoch {
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteResolutionReservation::AlreadyReserved {
                resolution_ordinal: row.resolution_count,
            });
        }
        let changed = tx
            .execute(
                "UPDATE memory_vector_late_delete_resolution
             SET state='processing', resolution_count=resolution_count+1,
                 last_reserved_resolution_epoch=resolution_epoch, updated_at=?2
             WHERE resolution_id=?1 AND state='claimed' AND resolution_epoch=?3
               AND last_reserved_resolution_epoch < resolution_epoch AND lease_owner=?4
               AND lease_fence_epoch=?5 AND lease_expires_at > ?2",
                params![
                    row.resolution_id,
                    now,
                    row.resolution_epoch,
                    claim.lease_owner,
                    claim.runtime_fence_epoch
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteResolutionReservation::LostLeaseOrSuperseded);
        }
        let token = LateDeleteResolutionToken {
            resolution_id: row.resolution_id,
            outbox_id: row.outbox_id,
            life_id: row.life_id,
            memory_id: row.memory_id,
            mutation_sequence: row.mutation_sequence,
            desired_action: LateDeleteAction::Delete,
            target_revision: None,
            target_content_hash: None,
            claimed_generation_id: row.claimed_generation_id,
            embedding_descriptor_id: row.embedding_descriptor_id,
            embedding_dimension: row.embedding_dimension,
            captured_generation_state: row.captured_generation_state,
            witness_attempt_ordinal: row.witness_attempt_ordinal,
            witness_claim_epoch: row.witness_claim_epoch,
            witness_marked_claim_epoch: row.witness_marked_claim_epoch,
            lease_owner: claim.lease_owner.clone(),
            runtime_fence_epoch: claim.runtime_fence_epoch,
            resolution_epoch: row.resolution_epoch,
            resolution_ordinal: row.resolution_count + 1,
        };
        tx.commit().map_err(storage_error)?;
        Ok(LateDeleteResolutionReservation::Reserved(Box::new(token)))
    }

    /// Read-only currency guard immediately before any resolver external I/O.
    pub(crate) fn late_delete_resolution_token_is_current(
        &self,
        token: &LateDeleteResolutionToken,
    ) -> Result<bool, StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(storage_error)?;
        let now = authoritative_utc_millis_now_in(&tx)?;
        let current = token_is_current_in(&tx, token, &now)?;
        tx.commit().map_err(storage_error)?;
        Ok(current)
    }

    pub(crate) fn mark_late_delete_resolution_disposition(
        &self,
        token: &LateDeleteResolutionToken,
        disposition: LateDeleteResolutionDisposition,
    ) -> Result<LateDeleteResolutionFinalizeResult, StorageError> {
        self.transition_late_delete_resolution(token, "processing", disposition, None, None)
    }

    pub(crate) fn finalize_late_delete_resolution_absent(
        &self,
        token: &LateDeleteResolutionToken,
    ) -> Result<LateDeleteResolutionFinalizeResult, StorageError> {
        self.transition_late_delete_resolution(
            token,
            "resolved_absent",
            LateDeleteResolutionDisposition::QueryAbsent,
            None,
            Some(""),
        )
    }

    pub(crate) fn finalize_late_delete_resolution_deleted(
        &self,
        token: &LateDeleteResolutionToken,
    ) -> Result<LateDeleteResolutionFinalizeResult, StorageError> {
        self.transition_late_delete_resolution(
            token,
            "resolved_deleted",
            LateDeleteResolutionDisposition::DeleteDeleted,
            None,
            Some(""),
        )
    }

    pub(crate) fn finalize_late_delete_resolution_unknown(
        &self,
        token: &LateDeleteResolutionToken,
        disposition: LateDeleteResolutionDisposition,
        error_code: &str,
    ) -> Result<LateDeleteResolutionFinalizeResult, StorageError> {
        if !matches!(
            disposition,
            LateDeleteResolutionDisposition::QueryUnknown
                | LateDeleteResolutionDisposition::DeleteUnknown
                | LateDeleteResolutionDisposition::FinalizeUnknown
        ) {
            return Err(StorageError::new(
                "LATE_DELETE_RESOLUTION_INVALID_UNKNOWN_DISPOSITION",
                "unknown finalization requires a typed unknown disposition",
                false,
            ));
        }
        self.transition_late_delete_resolution(
            token,
            "unknown",
            disposition,
            Some(error_code),
            None,
        )
    }

    pub(crate) fn finalize_late_delete_resolution_retry_wait(
        &self,
        token: &LateDeleteResolutionToken,
        delay_seconds: i64,
        error_code: &str,
    ) -> Result<LateDeleteResolutionFinalizeResult, StorageError> {
        if delay_seconds <= 0 {
            return Err(StorageError::new(
                "LATE_DELETE_RESOLUTION_INVALID_RETRY_DELAY",
                "retry delay must be positive",
                false,
            ));
        }
        self.transition_late_delete_resolution(
            token,
            "retry_wait",
            LateDeleteResolutionDisposition::FinalizeUnknown,
            Some(error_code),
            Some(&format!("+{delay_seconds} seconds")),
        )
    }

    pub(crate) fn finalize_late_delete_resolution_waiting_rebuild(
        &self,
        token: &LateDeleteResolutionToken,
        error_code: &str,
    ) -> Result<LateDeleteResolutionFinalizeResult, StorageError> {
        self.transition_late_delete_resolution(
            token,
            "waiting_rebuild",
            LateDeleteResolutionDisposition::WaitingRebuild,
            Some(error_code),
            None,
        )
    }

    pub(crate) fn recover_expired_late_delete_resolutions(&self) -> Result<usize, StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let now = authoritative_utc_millis_now_in(&tx)?;
        let changed = tx.execute(
            "UPDATE memory_vector_late_delete_resolution
             SET state=CASE WHEN resolution_count >= ?1 THEN 'waiting_rebuild' WHEN state='claimed' THEN 'pending' ELSE 'unknown' END,
                 last_resolution_disposition=CASE WHEN resolution_count >= ?1 THEN 'waiting_rebuild' ELSE 'finalize_unknown' END,
                 last_disposition_epoch=resolution_epoch, last_error_code=CASE WHEN resolution_count >= ?1 THEN 'LATE_DELETE_RESOLUTION_LIMIT_REACHED' ELSE 'LATE_DELETE_RESOLUTION_LEASE_EXPIRED' END,
                 lease_owner=NULL, lease_fence_epoch=NULL, lease_expires_at=NULL,
                 next_attempt_at=NULL, updated_at=?2
             WHERE state IN ('claimed','processing') AND lease_expires_at <= ?2",
            params![MAX_LATE_DELETE_RESOLUTIONS, now],
        ).map_err(storage_error)?;
        tx.commit().map_err(storage_error)?;
        Ok(changed)
    }

    fn transition_late_delete_resolution(
        &self,
        token: &LateDeleteResolutionToken,
        target_state: &str,
        disposition: LateDeleteResolutionDisposition,
        error_code: Option<&str>,
        retry_modifier: Option<&str>,
    ) -> Result<LateDeleteResolutionFinalizeResult, StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let now = authoritative_utc_millis_now_in(&tx)?;
        if !token_is_current_in(&tx, token, &now)? {
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteResolutionFinalizeResult::LostLeaseOrSuperseded);
        }
        let terminal = matches!(
            target_state,
            "resolved_absent" | "resolved_deleted" | "resolved_rebuilt"
        );
        let next_attempt_at = if target_state == "retry_wait" {
            Some(retry_modifier.ok_or_else(|| {
                StorageError::new(
                    "LATE_DELETE_RESOLUTION_INVALID_RETRY",
                    "retry needs a delay",
                    false,
                )
            })?)
        } else {
            None
        };
        let changed = tx.execute(
            "UPDATE memory_vector_late_delete_resolution
             SET state=?2, last_resolution_disposition=?3, last_disposition_epoch=resolution_epoch,
                 last_error_code=?4, lease_owner=CASE WHEN ?5 THEN NULL ELSE lease_owner END,
                 lease_fence_epoch=CASE WHEN ?5 THEN NULL ELSE lease_fence_epoch END,
                 lease_expires_at=CASE WHEN ?5 THEN NULL ELSE lease_expires_at END,
                 next_attempt_at=CASE WHEN ?2='retry_wait' THEN strftime('%Y-%m-%dT%H:%M:%fZ','now',?6) ELSE NULL END,
                 resolved_at=CASE WHEN ?7 THEN ?8 ELSE NULL END, updated_at=?8
             WHERE resolution_id=?1 AND state='processing' AND resolution_epoch=?9
               AND resolution_count=?10 AND last_reserved_resolution_epoch=?9
               AND lease_owner=?11 AND lease_fence_epoch=?12 AND lease_expires_at > ?8",
            params![token.resolution_id, target_state, disposition.as_str(), error_code, target_state != "processing", next_attempt_at, terminal, now, token.resolution_epoch, token.resolution_ordinal, token.lease_owner, token.runtime_fence_epoch],
        ).map_err(storage_error)?;
        tx.commit().map_err(storage_error)?;
        Ok(if changed == 1 {
            LateDeleteResolutionFinalizeResult::Applied
        } else {
            LateDeleteResolutionFinalizeResult::LostLeaseOrSuperseded
        })
    }
}

fn runtime_lease_is_current_in(
    tx: &Transaction<'_>,
    lease: &LateDeleteRuntimeLease,
    now: &str,
) -> Result<bool, StorageError> {
    tx.query_row("SELECT EXISTS(SELECT 1 FROM memory_vector_late_delete_runtime_lease WHERE lease_name=?1 AND lease_owner=?2 AND lease_fence_epoch=?3 AND lease_expires_at > ?4)", params![RUNTIME_LEASE_NAME, lease.owner, lease.fence_epoch, now], |row| row.get(0)).map_err(storage_error)
}

fn runtime_lease_matches_in(
    tx: &Transaction<'_>,
    claim: &LateDeleteResolutionClaim,
    now: &str,
) -> Result<bool, StorageError> {
    tx.query_row("SELECT EXISTS(SELECT 1 FROM memory_vector_late_delete_runtime_lease WHERE lease_name=?1 AND lease_owner=?2 AND lease_fence_epoch=?3 AND lease_expires_at > ?4)", params![RUNTIME_LEASE_NAME, claim.lease_owner, claim.runtime_fence_epoch, now], |row| row.get(0)).map_err(storage_error)
}

fn load_resolution_in(
    tx: &Transaction<'_>,
    resolution_id: i64,
) -> Result<Option<ResolutionRow>, StorageError> {
    tx.query_row(
        &format!("{RESOLUTION_SELECT_SQL} WHERE resolution_id=?1"),
        [resolution_id],
        resolution_row,
    )
    .optional()
    .map_err(storage_error)
}

fn select_next_candidate_in(
    tx: &Transaction<'_>,
    now: &str,
) -> Result<Option<ResolutionRow>, StorageError> {
    tx.query_row(&format!("{RESOLUTION_SELECT_SQL} WHERE state IN ('pending','unknown','retry_wait') AND (state <> 'retry_wait' OR next_attempt_at <= ?1) AND (lease_owner IS NULL OR lease_expires_at <= ?1) ORDER BY mutation_sequence, resolution_id LIMIT 1"), [now], resolution_row).optional().map_err(storage_error)
}

const RESOLUTION_SELECT_SQL: &str = "SELECT resolution_id,outbox_id,life_id,memory_id,mutation_sequence,claimed_generation_id,embedding_descriptor_id,embedding_dimension,captured_generation_state,witness_attempt_ordinal,witness_claim_epoch,witness_marked_claim_epoch,state,resolution_count,resolution_epoch,last_reserved_resolution_epoch,lease_owner,lease_fence_epoch FROM memory_vector_late_delete_resolution";

fn resolution_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ResolutionRow> {
    Ok(ResolutionRow {
        resolution_id: row.get(0)?,
        outbox_id: row.get(1)?,
        life_id: row.get(2)?,
        memory_id: row.get(3)?,
        mutation_sequence: row.get(4)?,
        claimed_generation_id: row.get(5)?,
        embedding_descriptor_id: row.get(6)?,
        embedding_dimension: row.get(7)?,
        captured_generation_state: row.get(8)?,
        witness_attempt_ordinal: row.get(9)?,
        witness_claim_epoch: row.get(10)?,
        witness_marked_claim_epoch: row.get(11)?,
        state: row.get(12)?,
        resolution_count: row.get(13)?,
        resolution_epoch: row.get(14)?,
        last_reserved_resolution_epoch: row.get(15)?,
        lease_owner: row.get(16)?,
        lease_fence_epoch: row.get(17)?,
    })
}

fn claim_matches_row(claim: &LateDeleteResolutionClaim, row: &ResolutionRow) -> bool {
    row.state == "claimed"
        && row.resolution_id == claim.resolution_id
        && row.life_id == claim.life_id
        && row.memory_id == claim.memory_id
        && row.mutation_sequence == claim.mutation_sequence
        && row.claimed_generation_id == claim.claimed_generation_id
        && row.embedding_descriptor_id == claim.embedding_descriptor_id
        && row.embedding_dimension == claim.embedding_dimension
        && row.captured_generation_state == claim.captured_generation_state
        && row.witness_attempt_ordinal == claim.witness_attempt_ordinal
        && row.witness_claim_epoch == claim.witness_claim_epoch
        && row.witness_marked_claim_epoch == claim.witness_marked_claim_epoch
        && row.lease_owner.as_deref() == Some(claim.lease_owner.as_str())
        && row.lease_fence_epoch == Some(claim.runtime_fence_epoch)
        && row.resolution_epoch == claim.resolution_epoch
        && row.resolution_count == claim.resolution_count
}

fn token_is_current_in(
    tx: &Transaction<'_>,
    token: &LateDeleteResolutionToken,
    now: &str,
) -> Result<bool, StorageError> {
    if !matches!(token.desired_action, LateDeleteAction::Delete)
        || token.target_revision.is_some()
        || token.target_content_hash.is_some()
    {
        return Ok(false);
    }
    let row = load_resolution_in(tx, token.resolution_id)?;
    let Some(row) = row else {
        return Ok(false);
    };
    let runtime: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM memory_vector_late_delete_runtime_lease WHERE lease_name=?1 AND lease_owner=?2 AND lease_fence_epoch=?3 AND lease_expires_at > ?4)", params![RUNTIME_LEASE_NAME, token.lease_owner, token.runtime_fence_epoch, now], |r| r.get(0)).map_err(storage_error)?;
    Ok(runtime
        && row.state == "processing"
        && row.outbox_id == token.outbox_id
        && row.life_id == token.life_id
        && row.memory_id == token.memory_id
        && row.mutation_sequence == token.mutation_sequence
        && row.claimed_generation_id == token.claimed_generation_id
        && row.embedding_descriptor_id == token.embedding_descriptor_id
        && row.embedding_dimension == token.embedding_dimension
        && row.captured_generation_state == token.captured_generation_state
        && row.witness_attempt_ordinal == token.witness_attempt_ordinal
        && row.witness_claim_epoch == token.witness_claim_epoch
        && row.witness_marked_claim_epoch == token.witness_marked_claim_epoch
        && row.lease_owner.as_deref() == Some(token.lease_owner.as_str())
        && row.lease_fence_epoch == Some(token.runtime_fence_epoch)
        && row.resolution_epoch == token.resolution_epoch
        && row.resolution_count == token.resolution_ordinal
        && row.last_reserved_resolution_epoch == token.resolution_epoch)
}

fn block_limit_in(tx: &Transaction<'_>, resolution_id: i64, now: &str) -> Result<(), StorageError> {
    tx.execute("UPDATE memory_vector_late_delete_resolution SET state='waiting_rebuild', last_resolution_disposition='waiting_rebuild', last_disposition_epoch=resolution_epoch, last_error_code='LATE_DELETE_RESOLUTION_LIMIT_REACHED', lease_owner=NULL, lease_fence_epoch=NULL, lease_expires_at=NULL, next_attempt_at=NULL, updated_at=?2 WHERE resolution_id=?1", params![resolution_id, now]).map_err(storage_error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::vector_sync_outbox::{
        EnqueueMemoryVectorSyncRequest, MemoryVectorSyncAction, MemoryVectorSyncOutboxRepository,
    };
    use crate::storage::{LifeIdentityRecord, PersonaTemplateRecord};
    use std::{fs, path::PathBuf};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "late-delete-resolution-{}",
                super::super::unique_suffix()
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

    fn seed_resolution(storage: &StorageService, life_id: &str, memory_id: &str, sequence: i64) {
        let state = storage.state().unwrap();
        state.connection.execute(
            "INSERT INTO memory_vector_late_delete_resolution
             (outbox_id,life_id,memory_id,mutation_sequence,claimed_generation_id,
              embedding_descriptor_id,embedding_dimension,captured_generation_state,
              witness_attempt_ordinal,witness_claim_epoch,witness_marked_claim_epoch,
              witness_send_disposition,witness_error_code,state,created_at,updated_at)
             VALUES (17,?1,?2,?3,'generation-a','descriptor-a',2,'active',1,1,1,
                     'possibly_sent',NULL,'pending','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')",
            params![life_id, memory_id, sequence],
        ).unwrap();
    }

    #[test]
    fn late_delete_resolution_claim_resolution_reserve_resolution_token_resolution_finalize_resolution_recovery_runtime_lease_generation_binding_writer_fence_schema_15_migration_015(
    ) {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let lease = storage
            .acquire_late_delete_runtime_lease("resolver-a")
            .unwrap()
            .unwrap();
        let claim = match storage.claim_one_late_delete_resolution(&lease).unwrap() {
            LateDeleteResolutionClaimResult::Claimed(claim) => claim,
            LateDeleteResolutionClaimResult::NoEligibleResolution => panic!("candidate must claim"),
        };
        let token = match storage.reserve_late_delete_resolution(&claim).unwrap() {
            LateDeleteResolutionReservation::Reserved(token) => token,
            _ => panic!("claim must reserve exactly one resolution slot"),
        };
        assert!(storage
            .late_delete_resolution_token_is_current(&token)
            .unwrap());
        assert_eq!(
            storage
                .mark_late_delete_resolution_disposition(
                    &token,
                    LateDeleteResolutionDisposition::DeleteStarted
                )
                .unwrap(),
            LateDeleteResolutionFinalizeResult::Applied
        );
        assert_eq!(
            storage
                .finalize_late_delete_resolution_deleted(&token)
                .unwrap(),
            LateDeleteResolutionFinalizeResult::Applied
        );
        assert!(!storage
            .late_delete_resolution_token_is_current(&token)
            .unwrap());
        let state = storage.state().unwrap();
        let row: (String, i64, Option<String>, Option<i64>) = state.connection.query_row(
            "SELECT state,resolution_count,lease_owner,lease_fence_epoch FROM memory_vector_late_delete_resolution WHERE life_id='life' AND memory_id='memory'",
            [], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)),
        ).unwrap();
        assert_eq!(row, ("resolved_deleted".to_string(), 1, None, None));
    }

    #[test]
    fn late_delete_resolution_superseded_new_mutation_atomic_commit_unknown_mutation() {
        let (_root, storage) = storage();
        let memory = super::super::test_support::insert_confirmed_memory_fixture(
            &storage,
            "life",
            "fact",
            "late delete",
            None,
            0.5,
            0.5,
            false,
            true,
        );
        seed_resolution(&storage, "life", &memory.id, 1);
        storage.test_fail_next_enqueue_after_commit();
        let unknown_commit = <StorageService as MemoryVectorSyncOutboxRepository>::enqueue(
            &storage,
            EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: memory.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            },
        );
        assert!(
            unknown_commit.is_err(),
            "the simulated caller sees an unknown commit"
        );
        let state = storage.state().unwrap();
        let (resolution_state, disposition, resolution_updated_at, outbox_updated_at, outbox_sequence): (
            String,
            String,
            String,
            String,
            i64,
        ) = state
            .connection
            .query_row(
                "SELECT r.state,r.last_resolution_disposition,r.updated_at,o.updated_at,o.mutation_sequence
             FROM memory_vector_late_delete_resolution r JOIN memory_vector_sync_outbox o
               ON o.life_id=r.life_id AND o.memory_id=r.memory_id
             WHERE r.life_id='life' AND r.memory_id=?1 AND r.mutation_sequence=1",
                [&memory.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .unwrap();
        assert_eq!(resolution_state, "superseded");
        assert_eq!(disposition, "superseded");
        assert_eq!(resolution_updated_at, outbox_updated_at);
        assert_eq!(outbox_sequence, 2);
    }

    #[test]
    fn late_delete_resolution_two_resolver_runtime_takeover_concurrency() {
        for _ in 0..10 {
            let (_root, storage) = storage();
            seed_resolution(&storage, "life", "memory", 1);
            let old = storage
                .acquire_late_delete_runtime_lease("resolver-a")
                .unwrap()
                .unwrap();
            let old_claim = match storage.claim_one_late_delete_resolution(&old).unwrap() {
                LateDeleteResolutionClaimResult::Claimed(claim) => claim,
                LateDeleteResolutionClaimResult::NoEligibleResolution => {
                    panic!("old owner must claim")
                }
            };
            assert!(storage.release_late_delete_runtime_lease(&old).unwrap());
            let current = storage
                .acquire_late_delete_runtime_lease("resolver-b")
                .unwrap()
                .unwrap();
            assert!(current.fence_epoch() > old.fence_epoch());
            assert!(matches!(
                storage.reserve_late_delete_resolution(&old_claim).unwrap(),
                LateDeleteResolutionReservation::LostLeaseOrSuperseded
            ));
            storage
                .state()
                .unwrap()
                .connection
                .execute(
                    "UPDATE memory_vector_late_delete_resolution
                     SET lease_expires_at='2020-01-01T00:00:00.000Z'
                     WHERE life_id='life' AND memory_id='memory'",
                    [],
                )
                .unwrap();
            assert_eq!(
                storage.recover_expired_late_delete_resolutions().unwrap(),
                1
            );
            assert!(matches!(
                storage.claim_one_late_delete_resolution(&current).unwrap(),
                LateDeleteResolutionClaimResult::Claimed(_)
            ));
        }
    }
}
