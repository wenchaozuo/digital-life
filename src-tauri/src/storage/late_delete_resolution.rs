#![allow(dead_code)] // Resolver execution is deliberately not wired to the worker in LD-I2.

//! Durable, fenced resolution of Deletes whose external result is unknown.
//!
//! This module has no worker or concrete vector-store dependency. It owns narrow
//! trait-level Query and conditional-Delete capability bridges: callers can
//! obtain a token only after SQLite has reserved a bounded resolution slot, and
//! every subsequent transition is a compare-and-swap against that token.

use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};

use super::{StorageError, StorageService};
use crate::vector_store::{
    validate_hash, ConditionalGenerationDeleteOutcome, VectorGenerationContext, VectorGenerationId,
    VectorMetadataSample, VectorStore, VectorStoreError, VectorStoreErrorCode,
};

#[cfg(test)]
use std::cell::Cell;

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
    witness_send_disposition: Option<String>,
    witness_error_code: Option<String>,
    witness_age_anchor_at: String,
    captured_generation_authority_epoch: i64,
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
    witness_send_disposition: Option<String>,
    witness_error_code: Option<String>,
    witness_age_anchor_at: String,
    captured_generation_authority_epoch: i64,
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

/// Sealed, linear permission to perform exactly one future exact Query for a
/// newly and definitely reserved resolution ordinal. It owns the complete
/// token; no partial fencing snapshot can be reconstructed into this permit.
pub(crate) struct LateDeleteQueryPermit {
    token: Box<LateDeleteResolutionToken>,
}

/// Opaque, linear outcomes of the one storage-owned public VectorStore query.
/// Every variant owns the permit's token, so the ordinal cannot be queried again.
pub(crate) enum LateDeleteQueryHandoffOutcome {
    LostLeaseOrSuperseded,
    Absent(AbsentPostQueryCapability),
    Present(PresentPostQueryCapability),
    Failure(FailedPostQueryCapability),
    Corrupt(CorruptPostQueryCapability),
}

/// Sealed result of one exact Query returning no metadata.
pub(crate) struct AbsentPostQueryCapability {
    token: Box<LateDeleteResolutionToken>,
}

/// Sealed result of one exact Query which found the full expected identity.
/// S1 deliberately has no production constructor: S3 must consume a
/// [`LateDeleteQueryPermit`] after the real external Query.
pub(crate) struct PresentPostQueryCapability {
    token: Box<LateDeleteResolutionToken>,
    revision: i64,
    content_hash: String,
}

/// Sealed result of one exact Query whose external failure is not corruption.
pub(crate) struct FailedPostQueryCapability {
    token: Box<LateDeleteResolutionToken>,
    error: VectorStoreError,
}

/// Sealed result of one exact Query that produced structural corruption.
pub(crate) struct CorruptPostQueryCapability {
    token: Box<LateDeleteResolutionToken>,
    error_code: &'static str,
}

/// Sealed, linear permission for exactly one future conditional Delete. It is
/// produced only after the dedicated `delete_started` transaction definitely
/// commits, and intentionally has no row/token constructor.
pub(crate) struct LateDeleteDeletePermit {
    token: Box<LateDeleteResolutionToken>,
    revision: i64,
    content_hash: String,
}

pub(crate) enum LateDeleteDeleteHandoffOutcome {
    LostLeaseOrSuperseded,
    PreDeleteCorrupt(PreDeleteCorruptCapability),
    Deleted(DeletedPostDeleteCapability),
    Absent(AbsentPostDeleteCapability),
    IdentityMismatch(IdentityMismatchPostDeleteCapability),
    Failure(FailedPostDeleteCapability),
}

pub(crate) struct PreDeleteCorruptCapability {
    token: Box<LateDeleteResolutionToken>,
}

pub(crate) struct DeletedPostDeleteCapability {
    token: Box<LateDeleteResolutionToken>,
}

pub(crate) struct AbsentPostDeleteCapability {
    token: Box<LateDeleteResolutionToken>,
}

pub(crate) struct IdentityMismatchPostDeleteCapability {
    token: Box<LateDeleteResolutionToken>,
}

pub(crate) struct FailedPostDeleteCapability {
    token: Box<LateDeleteResolutionToken>,
    error_code: VectorStoreErrorCode,
}

/// The only outcomes of consuming a typed post-Delete capability.  A caller
/// cannot retry the capability after either kind of commit uncertainty: the
/// storage-owned reconciliation has already examined the durable row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LateDeletePostDeleteFinalizeResult {
    Applied,
    LostLeaseOrSuperseded,
    ReconciledExpectedDisposition,
    CommitUnknownStillDeleteStarted,
}

/// M2-specific reservation result. The frozen LD-I2 reservation API remains
/// unchanged and cannot be used to reconstruct a QueryPermit.
pub(crate) enum LateDeleteQueryReservation {
    Reserved(Box<LateDeleteQueryPermit>),
    AlreadyReserved { resolution_ordinal: i64 },
    LostLeaseOrSuperseded,
    ResolutionLimitReached,
}

/// Outcome of the only durable `delete_started` issuance path.
pub(crate) enum LateDeleteDeletePermitIssuance {
    Issued(Box<LateDeleteDeletePermit>),
    LostLeaseOrSuperseded,
    WaitingRebuild,
}

/// Runner-facing issuance result. Commit uncertainty is fully classified inside
/// storage and never carries a token or a capability to the caller.
pub(crate) enum LateDeleteDeletePermitRunnerIssuance {
    Issued(Box<LateDeleteDeletePermit>),
    LostLeaseOrSuperseded,
    WaitingRebuild,
    CommitUnknownRecoveryRequired(LateDeleteStartedCommitUnknownNoPermit),
}

/// Read-only classification of an exact consumed Present capability after the
/// DeleteStarted COMMIT result is unknown. The type name carries the binding
/// guarantee: a commit-unknown reconciliation never produces a DeletePermit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LateDeleteStartedCommitUnknownNoPermit {
    DeleteStartedDurable,
    PreIssuanceDurable,
    LostLeaseOrSuperseded,
}

enum LateDeleteDeletePermitIssuanceCore {
    Issued(Box<LateDeleteDeletePermit>),
    LostLeaseOrSuperseded,
    WaitingRebuild,
    CommitUnknown {
        token: Box<LateDeleteResolutionToken>,
    },
}

/// Read-only durable classification for a commit-result-unknown caller. It
/// intentionally contains no capability and can never recreate one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LateDeleteStartedDurableState {
    CurrentEpochDeleteStarted,
    NotCurrentEpochDeleteStarted,
}

impl LateDeleteQueryPermit {
    /// Runner-facing opaque Query surface. The generation context is derived
    /// only from the sealed permit and the existing H1 bridge remains the sole
    /// implementation that can invoke the public VectorStore Query.
    pub(crate) async fn execute_exact_query_once_opaque(
        self: Box<Self>,
        storage: &StorageService,
        vector_store: &dyn VectorStore,
    ) -> Result<LateDeleteQueryHandoffOutcome, StorageError> {
        let token = self.token;
        let context = VectorGenerationId::parse(&token.claimed_generation_id)
            .ok()
            .and_then(|generation_id| {
                usize::try_from(token.embedding_dimension)
                    .ok()
                    .and_then(|dimension| {
                        VectorGenerationContext::new(
                            generation_id,
                            token.embedding_descriptor_id.clone(),
                            dimension,
                        )
                        .ok()
                    })
            });
        let Some(context) = context else {
            return Ok(LateDeleteQueryHandoffOutcome::Corrupt(
                CorruptPostQueryCapability {
                    token,
                    error_code: "LATE_DELETE_QUERY_CONTEXT_CORRUPT",
                },
            ));
        };
        Box::new(LateDeleteQueryPermit { token })
            .execute_exact_query_once(storage, &context, vector_store)
            .await
    }

    /// Consumes this definite reservation's sole Query authority and performs
    /// the only public exact VectorStore query for its ordinal. The SQLite
    /// currency guard completes before the await, so no SQLite transaction or
    /// guard crosses external I/O.
    pub(crate) async fn execute_exact_query_once(
        self: Box<Self>,
        storage: &StorageService,
        context: &VectorGenerationContext,
        vector_store: &dyn VectorStore,
    ) -> Result<LateDeleteQueryHandoffOutcome, StorageError> {
        let token = self.token;
        if !context_matches_query_token(&token, context) {
            return Err(StorageError::new(
                "LATE_DELETE_QUERY_CONTEXT_MISMATCH",
                "the vector generation context does not match the late delete query authority",
                false,
            ));
        }
        if !storage.late_delete_resolution_token_is_current(&token)? {
            return Ok(LateDeleteQueryHandoffOutcome::LostLeaseOrSuperseded);
        }

        match vector_store
            .get_generation_metadata(context, &token.life_id, &token.memory_id)
            .await
        {
            Ok(None) => Ok(LateDeleteQueryHandoffOutcome::Absent(
                AbsentPostQueryCapability { token },
            )),
            Ok(Some(sample)) => {
                if let Some(error_code) = query_sample_corruption_code(&token, context, &sample) {
                    Ok(LateDeleteQueryHandoffOutcome::Corrupt(
                        CorruptPostQueryCapability { token, error_code },
                    ))
                } else {
                    Ok(LateDeleteQueryHandoffOutcome::Present(
                        PresentPostQueryCapability {
                            token,
                            revision: sample.memory_revision,
                            content_hash: sample.content_hash,
                        },
                    ))
                }
            }
            Err(error) if query_error_is_corruption(error.code) => Ok(
                LateDeleteQueryHandoffOutcome::Corrupt(CorruptPostQueryCapability {
                    token,
                    error_code: "LATE_DELETE_QUERY_CORRUPT",
                }),
            ),
            Err(error) => Ok(LateDeleteQueryHandoffOutcome::Failure(
                FailedPostQueryCapability { token, error },
            )),
        }
    }
}

impl LateDeleteDeletePermit {
    /// Consumes the only DeleteStarted capability for this ordinal. Its full
    /// expected identity stays sealed inside storage across the sole external
    /// conditional Delete call.
    pub(crate) async fn execute_conditional_delete_once(
        self: Box<Self>,
        storage: &StorageService,
        vector_store: &dyn VectorStore,
    ) -> Result<LateDeleteDeleteHandoffOutcome, StorageError> {
        let LateDeleteDeletePermit {
            token,
            revision,
            content_hash,
        } = *self;
        if !storage.late_delete_delete_permit_is_current(&token)? {
            return Ok(LateDeleteDeleteHandoffOutcome::LostLeaseOrSuperseded);
        }
        let generation_id = match VectorGenerationId::parse(&token.claimed_generation_id) {
            Ok(generation_id) => generation_id,
            Err(_) => {
                return Ok(LateDeleteDeleteHandoffOutcome::PreDeleteCorrupt(
                    PreDeleteCorruptCapability { token },
                ))
            }
        };
        let context = match VectorGenerationContext::new(
            generation_id,
            token.embedding_descriptor_id.clone(),
            token.embedding_dimension as usize,
        ) {
            Ok(context) if revision > 0 && validate_hash(&content_hash, "Content hash").is_ok() => {
                context
            }
            _ => {
                return Ok(LateDeleteDeleteHandoffOutcome::PreDeleteCorrupt(
                    PreDeleteCorruptCapability { token },
                ))
            }
        };

        match vector_store
            .delete_generation_memory_if_matches(
                &context,
                &token.life_id,
                &token.memory_id,
                revision,
                &content_hash,
            )
            .await
        {
            Ok(ConditionalGenerationDeleteOutcome::Deleted) => Ok(
                LateDeleteDeleteHandoffOutcome::Deleted(DeletedPostDeleteCapability { token }),
            ),
            Ok(ConditionalGenerationDeleteOutcome::Absent) => Ok(
                LateDeleteDeleteHandoffOutcome::Absent(AbsentPostDeleteCapability { token }),
            ),
            Ok(ConditionalGenerationDeleteOutcome::IdentityMismatch) => {
                Ok(LateDeleteDeleteHandoffOutcome::IdentityMismatch(
                    IdentityMismatchPostDeleteCapability { token },
                ))
            }
            Err(error) => Ok(LateDeleteDeleteHandoffOutcome::Failure(
                FailedPostDeleteCapability {
                    token,
                    error_code: error.code,
                },
            )),
        }
    }
}

fn context_matches_query_token(
    token: &LateDeleteResolutionToken,
    context: &VectorGenerationContext,
) -> bool {
    context.generation_id().as_str() == token.claimed_generation_id
        && context.descriptor_hash() == token.embedding_descriptor_id
        && context.dimension() == token.embedding_dimension as usize
}

fn query_sample_corruption_code(
    token: &LateDeleteResolutionToken,
    context: &VectorGenerationContext,
    sample: &VectorMetadataSample,
) -> Option<&'static str> {
    if sample.generation_id != token.claimed_generation_id
        || sample.generation_id != context.generation_id().as_str()
    {
        return Some("LATE_DELETE_QUERY_GENERATION_MISMATCH");
    }
    if sample.life_id != token.life_id {
        return Some("LATE_DELETE_QUERY_LIFE_MISMATCH");
    }
    if sample.memory_id != token.memory_id {
        return Some("LATE_DELETE_QUERY_MEMORY_MISMATCH");
    }
    if sample.descriptor_hash != token.embedding_descriptor_id
        || sample.descriptor_hash != context.descriptor_hash()
    {
        return Some("LATE_DELETE_QUERY_DESCRIPTOR_MISMATCH");
    }
    if sample.dimension != token.embedding_dimension as usize
        || sample.dimension != context.dimension()
    {
        return Some("LATE_DELETE_QUERY_DIMENSION_MISMATCH");
    }
    if sample.memory_revision <= 0 {
        return Some("LATE_DELETE_QUERY_INVALID_REVISION");
    }
    if validate_hash(&sample.content_hash, "Content hash").is_err() {
        return Some("LATE_DELETE_QUERY_INVALID_CONTENT_HASH");
    }
    None
}

fn query_error_is_corruption(code: VectorStoreErrorCode) -> bool {
    !matches!(
        code,
        VectorStoreErrorCode::StoreUnavailable | VectorStoreErrorCode::GenerationNotFound
    )
}

fn query_failure_error_code(error: &VectorStoreError) -> &'static str {
    match error.code {
        VectorStoreErrorCode::StoreUnavailable => "LATE_DELETE_QUERY_STORE_UNAVAILABLE",
        VectorStoreErrorCode::GenerationNotFound => "LATE_DELETE_QUERY_GENERATION_NOT_FOUND",
        _ => "LATE_DELETE_QUERY_UNKNOWN",
    }
}

#[cfg(test)]
pub(crate) fn acknowledge_query_present_for_test(
    permit: LateDeleteQueryPermit,
    revision: i64,
    content_hash: &str,
) -> PresentPostQueryCapability {
    PresentPostQueryCapability {
        token: permit.token,
        revision,
        content_hash: content_hash.into(),
    }
}

#[cfg(test)]
thread_local! {
    static DELETE_STARTED_BEFORE_COMMIT_FAULT: Cell<bool> = const { Cell::new(false) };
    static DELETE_STARTED_BEFORE_COMMIT_UNKNOWN_FAULT: Cell<bool> = const { Cell::new(false) };
    static DELETE_STARTED_RECONCILE_READ_FAILURE: Cell<bool> = const { Cell::new(false) };
    static DELETE_STARTED_AFTER_COMMIT_FAULT: Cell<bool> = const { Cell::new(false) };
    static QUERY_PERMIT_AFTER_COMMIT_FAULT: Cell<bool> = const { Cell::new(false) };
    static DELETE_STARTED_COMMIT_ATTEMPT_COUNT: Cell<usize> = const { Cell::new(0) };
    static POST_DELETE_FINALIZE_BEFORE_COMMIT_FAILURE: Cell<bool> = const { Cell::new(false) };
    static POST_DELETE_FINALIZE_BEFORE_COMMIT_UNKNOWN: Cell<bool> = const { Cell::new(false) };
    static POST_DELETE_FINALIZE_AFTER_COMMIT_UNKNOWN: Cell<bool> = const { Cell::new(false) };
    static POST_DELETE_FINALIZE_COMMIT_ATTEMPT_COUNT: Cell<usize> = const { Cell::new(0) };
    static AUTHORITATIVE_NOW_OVERRIDE_FOR_TEST: Cell<Option<String>> = const { Cell::new(None) };
}

/// Records every real DeleteStarted-issuance `transaction.commit()` attempt.
/// The pre-commit fault branch returns before this helper, so a pre-commit
/// failure is observably a zero-attempt failure while a real commit failure or
/// a post-commit result loss is observably a one-attempt failure.
#[cfg(test)]
fn record_delete_started_commit_attempt_for_test() {
    DELETE_STARTED_COMMIT_ATTEMPT_COUNT.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
pub(crate) fn reset_delete_started_commit_attempt_count_for_test() {
    DELETE_STARTED_COMMIT_ATTEMPT_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn delete_started_commit_attempt_count_for_test() -> usize {
    DELETE_STARTED_COMMIT_ATTEMPT_COUNT.with(|count| count.get())
}

#[cfg(test)]
fn record_post_delete_finalize_commit_attempt_for_test() {
    POST_DELETE_FINALIZE_COMMIT_ATTEMPT_COUNT.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
fn reset_post_delete_finalize_faults_for_test() {
    POST_DELETE_FINALIZE_BEFORE_COMMIT_FAILURE.with(|fault| fault.set(false));
    POST_DELETE_FINALIZE_BEFORE_COMMIT_UNKNOWN.with(|fault| fault.set(false));
    POST_DELETE_FINALIZE_AFTER_COMMIT_UNKNOWN.with(|fault| fault.set(false));
    POST_DELETE_FINALIZE_COMMIT_ATTEMPT_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
fn post_delete_finalize_commit_attempt_count_for_test() -> usize {
    POST_DELETE_FINALIZE_COMMIT_ATTEMPT_COUNT.with(Cell::get)
}

/// Freezes the authoritative-now that the production 24-hour comparator receives
/// as `?1`. The frozen value is always taken from the SQLite clock first and the
/// override is one-shot: the next `authoritative_utc_millis_now_in` call returns
/// it and then the seam resets, so no other call site can be affected.
#[cfg(test)]
pub(crate) fn arm_authoritative_now_override_for_test(frozen_now: &str) {
    AUTHORITATIVE_NOW_OVERRIDE_FOR_TEST.with(|slot| slot.set(Some(frozen_now.to_string())));
}

#[cfg(test)]
pub(crate) fn clear_authoritative_now_override_for_test() {
    AUTHORITATIVE_NOW_OVERRIDE_FOR_TEST.with(|slot| slot.set(None));
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
    witness_send_disposition: Option<String>,
    witness_error_code: Option<String>,
    witness_age_anchor_at: String,
    captured_generation_authority_epoch: i64,
    state: String,
    resolution_count: i64,
    resolution_epoch: i64,
    last_reserved_resolution_epoch: i64,
    last_disposition_epoch: i64,
    lease_owner: Option<String>,
    lease_fence_epoch: Option<i64>,
    lease_expires_at: Option<String>,
}

/// One durable post-Delete resolution row read by the read-only commit-result-
/// unknown reconciliation. A private shape alias only: the field order and
/// Option nesting are unchanged.
type PostDeleteCommitUnknownRow = (
    String,
    String,
    i64,
    i64,
    i64,
    i64,
    Option<String>,
    Option<i64>,
);

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
    // Test-only authoritative-time override: a test freezes a value already
    // taken from this same SQLite clock so the production comparator's `?1` is
    // bit-for-bit equal to `witness_age_anchor_at + 24h`. The override is
    // consumed by the first call (one-shot), and in release builds this branch
    // compiles out entirely, leaving the original SQLite authoritative-now path.
    #[cfg(test)]
    if let Some(frozen_now) = AUTHORITATIVE_NOW_OVERRIDE_FOR_TEST.with(|slot| slot.take()) {
        return Ok(frozen_now);
    }
    transaction
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(storage_error)
}

/// Creates the durable Resolution in the same SQLite transaction that first
/// persists canonical Delete-Unknown evidence.  A missing generation cannot
/// supply the immutable descriptor identity required by a Resolution, so that
/// case aborts the caller-owned transaction rather than committing executable
/// Unknown evidence without a durable Resolution.
pub(super) fn ensure_runtime_resolution_for_delete_unknown_in(
    tx: &Transaction<'_>,
    outbox_id: i64,
) -> Result<(), StorageError> {
    let changed = tx.execute(
        "INSERT INTO memory_vector_late_delete_resolution
         (outbox_id,life_id,memory_id,mutation_sequence,claimed_generation_id,
          embedding_descriptor_id,embedding_dimension,captured_generation_state,
          witness_attempt_ordinal,witness_claim_epoch,witness_marked_claim_epoch,
          witness_send_disposition,witness_error_code,witness_age_anchor_at,
          captured_generation_authority_epoch,state,last_resolution_disposition,
          last_disposition_epoch,created_at,updated_at)
          SELECT o.id,o.life_id,o.memory_id,o.mutation_sequence,o.claimed_generation_id,
                 g.descriptor_hash,g.dimension,g.state,
                o.attempt_count,o.fenced_claim_epoch,o.last_marked_claim_epoch,
                o.last_send_disposition,
                CASE WHEN o.last_error_code='PROVIDER_RESULT_UNKNOWN'
                     THEN o.last_error_code ELSE NULL END,
                o.delete_witness_at,
                 g.authority_epoch,
                 'pending',NULL,
                0,o.delete_witness_at,o.delete_witness_at
           FROM memory_vector_sync_outbox o
           JOIN memory_vector_generation g
             ON g.generation_id=o.claimed_generation_id
          WHERE o.id=?1 AND o.desired_action='delete'
            AND (o.last_send_disposition='possibly_sent' OR o.last_error_code='PROVIDER_RESULT_UNKNOWN')
            AND o.delete_witness_at IS NOT NULL AND o.mutation_sequence>0
            AND o.attempt_count BETWEEN 1 AND 5 AND o.fenced_claim_epoch>0
            AND o.last_marked_claim_epoch>0 AND o.last_marked_claim_epoch<=o.fenced_claim_epoch
            AND o.claimed_generation_id IS NOT NULL AND o.claimed_generation_id<>''
             AND o.target_revision IS NULL AND o.target_content_hash IS NULL AND o.migration_disposition IS NULL
             AND g.descriptor_hash<>'' AND g.dimension>0
             AND g.state IN ('building','active','retired','failed') AND g.authority_epoch>=1
          ON CONFLICT(life_id,memory_id,mutation_sequence) DO NOTHING",
        [outbox_id],
    ).map_err(storage_error)?;
    let resolution_exists: bool = tx
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM memory_vector_late_delete_resolution
                 WHERE outbox_id=?1
             )",
            [outbox_id],
            |row| row.get(0),
        )
        .map_err(storage_error)?;
    if changed == 0 && !resolution_exists {
        return Err(StorageError::new(
            "LATE_DELETE_RESOLUTION_INVARIANT_VIOLATION",
            "canonical Delete-Unknown cannot commit without a durable Resolution",
            true,
        ));
    }
    Ok(())
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
        if !resolution_authority_is_current_in(&tx, &row, &now)? {
            converge_waiting_rebuild_in(&tx, row.resolution_id, &now)?;
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteResolutionClaimResult::NoEligibleResolution);
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
            witness_send_disposition: row.witness_send_disposition,
            witness_error_code: row.witness_error_code,
            witness_age_anchor_at: row.witness_age_anchor_at,
            captured_generation_authority_epoch: row.captured_generation_authority_epoch,
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
        if !resolution_authority_is_current_in(&tx, &row, &now)? {
            converge_waiting_rebuild_in(&tx, row.resolution_id, &now)?;
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
            witness_send_disposition: row.witness_send_disposition,
            witness_error_code: row.witness_error_code,
            witness_age_anchor_at: row.witness_age_anchor_at,
            captured_generation_authority_epoch: row.captured_generation_authority_epoch,
            lease_owner: claim.lease_owner.clone(),
            runtime_fence_epoch: claim.runtime_fence_epoch,
            resolution_epoch: row.resolution_epoch,
            resolution_ordinal: row.resolution_count + 1,
        };
        tx.commit().map_err(storage_error)?;
        Ok(LateDeleteResolutionReservation::Reserved(Box::new(token)))
    }

    /// Reserves exactly one ordinal and returns its linear Query capability.
    /// The established LD-I2 reservation API above intentionally remains
    /// unchanged; this narrow wrapper is the only M2 entrypoint that may mint
    /// a Query permit after a definite SQLite commit.
    pub(crate) fn reserve_late_delete_resolution_for_query(
        &self,
        claim: &LateDeleteResolutionClaim,
    ) -> Result<LateDeleteQueryReservation, StorageError> {
        match self.reserve_late_delete_resolution(claim)? {
            LateDeleteResolutionReservation::Reserved(token) => {
                #[cfg(test)]
                if QUERY_PERMIT_AFTER_COMMIT_FAULT.with(|fault| fault.replace(false)) {
                    return Err(StorageError::new(
                        "LATE_DELETE_QUERY_RESERVATION_COMMIT_RESULT_UNKNOWN",
                        "test-only post-commit result loss; no Query permit is returned",
                        true,
                    ));
                }
                Ok(LateDeleteQueryReservation::Reserved(Box::new(
                    LateDeleteQueryPermit { token },
                )))
            }
            LateDeleteResolutionReservation::AlreadyReserved { resolution_ordinal } => {
                Ok(LateDeleteQueryReservation::AlreadyReserved { resolution_ordinal })
            }
            LateDeleteResolutionReservation::LostLeaseOrSuperseded => {
                Ok(LateDeleteQueryReservation::LostLeaseOrSuperseded)
            }
            LateDeleteResolutionReservation::ResolutionLimitReached => {
                Ok(LateDeleteQueryReservation::ResolutionLimitReached)
            }
        }
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

    /// Read-only guard immediately before the one external conditional Delete.
    /// Unlike the generic token guard this also proves that the durable source
    /// boundary is the current epoch's DeleteStarted transition.
    fn late_delete_delete_permit_is_current(
        &self,
        token: &LateDeleteResolutionToken,
    ) -> Result<bool, StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(storage_error)?;
        let now = authoritative_utc_millis_now_in(&tx)?;
        let current = token_is_current_in(&tx, token, &now)?
            && tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM memory_vector_late_delete_resolution
                     WHERE resolution_id=?1 AND state='processing'
                       AND resolution_epoch=?2 AND resolution_count=?3
                       AND last_reserved_resolution_epoch=?2
                       AND last_resolution_disposition='delete_started'
                       AND last_disposition_epoch=?2)",
                    params![
                        token.resolution_id,
                        token.resolution_epoch,
                        token.resolution_ordinal
                    ],
                    |row| row.get(0),
                )
                .map_err(storage_error)?;
        tx.commit().map_err(storage_error)?;
        Ok(current)
    }

    pub(crate) fn mark_late_delete_resolution_disposition(
        &self,
        token: &LateDeleteResolutionToken,
        disposition: LateDeleteResolutionDisposition,
    ) -> Result<LateDeleteResolutionFinalizeResult, StorageError> {
        if matches!(disposition, LateDeleteResolutionDisposition::DeleteStarted) {
            return Err(StorageError::new(
                "LATE_DELETE_DELETE_STARTED_REQUIRES_PERMIT",
                "delete_started may only be committed by issue_late_delete_permit",
                false,
            ));
        }
        self.transition_late_delete_resolution(token, "processing", disposition, None, None)
    }

    /// Durably records the DeleteStarted boundary and mints the one linear
    /// Delete capability only after that exact transaction commits. A caller
    /// which cannot determine the commit result receives no capability.
    pub(crate) fn issue_late_delete_permit(
        &self,
        present: PresentPostQueryCapability,
    ) -> Result<LateDeleteDeletePermitIssuance, StorageError> {
        match self.issue_late_delete_permit_core(present)? {
            LateDeleteDeletePermitIssuanceCore::Issued(permit) => {
                Ok(LateDeleteDeletePermitIssuance::Issued(permit))
            }
            LateDeleteDeletePermitIssuanceCore::LostLeaseOrSuperseded => {
                Ok(LateDeleteDeletePermitIssuance::LostLeaseOrSuperseded)
            }
            LateDeleteDeletePermitIssuanceCore::WaitingRebuild => {
                Ok(LateDeleteDeletePermitIssuance::WaitingRebuild)
            }
            LateDeleteDeletePermitIssuanceCore::CommitUnknown { .. } => Err(StorageError::new(
                "LATE_DELETE_DELETE_STARTED_COMMIT_RESULT_UNKNOWN",
                "DeleteStarted commit result is unknown; no Delete permit is returned",
                true,
            )),
        }
    }

    /// Consumes Present and makes a runner-safe issuance decision. The commit
    /// unknown branch is reconciled immediately with the sealed token and
    /// deliberately exposes neither that token nor a permit.
    pub(crate) fn issue_late_delete_permit_for_runner(
        &self,
        present: PresentPostQueryCapability,
    ) -> Result<LateDeleteDeletePermitRunnerIssuance, StorageError> {
        match self.issue_late_delete_permit_core(present)? {
            LateDeleteDeletePermitIssuanceCore::Issued(permit) => {
                Ok(LateDeleteDeletePermitRunnerIssuance::Issued(permit))
            }
            LateDeleteDeletePermitIssuanceCore::LostLeaseOrSuperseded => {
                Ok(LateDeleteDeletePermitRunnerIssuance::LostLeaseOrSuperseded)
            }
            LateDeleteDeletePermitIssuanceCore::WaitingRebuild => {
                Ok(LateDeleteDeletePermitRunnerIssuance::WaitingRebuild)
            }
            LateDeleteDeletePermitIssuanceCore::CommitUnknown { token } => Ok(
                LateDeleteDeletePermitRunnerIssuance::CommitUnknownRecoveryRequired(
                    self.reconcile_late_delete_started_exact_token(&token)?,
                ),
            ),
        }
    }

    fn issue_late_delete_permit_core(
        &self,
        present: PresentPostQueryCapability,
    ) -> Result<LateDeleteDeletePermitIssuanceCore, StorageError> {
        let PresentPostQueryCapability {
            token,
            revision,
            content_hash,
        } = present;
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let now = authoritative_utc_millis_now_in(&tx)?;
        if !token_is_current_in(&tx, &token, &now)? {
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteDeletePermitIssuanceCore::LostLeaseOrSuperseded);
        }
        let row = load_resolution_in(&tx, token.resolution_id)?;
        let Some(row) = row else {
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteDeletePermitIssuanceCore::LostLeaseOrSuperseded);
        };
        if !resolution_authority_is_current_in(&tx, &row, &now)? {
            converge_waiting_rebuild_in(&tx, row.resolution_id, &now)?;
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteDeletePermitIssuanceCore::WaitingRebuild);
        }
        if row.last_disposition_epoch >= row.resolution_epoch {
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteDeletePermitIssuanceCore::LostLeaseOrSuperseded);
        }
        let changed = tx
            .execute(
                "UPDATE memory_vector_late_delete_resolution
             SET last_resolution_disposition='delete_started',
                 last_disposition_epoch=resolution_epoch, updated_at=?2
             WHERE resolution_id=?1 AND outbox_id=?3 AND life_id=?4 AND memory_id=?5
               AND mutation_sequence=?6 AND state='processing'
               AND resolution_epoch=?7 AND resolution_count=?8
               AND last_reserved_resolution_epoch=?7
               AND last_disposition_epoch < resolution_epoch
               AND lease_owner=?9 AND lease_fence_epoch=?10 AND lease_expires_at > ?2
               AND claimed_generation_id=?11 AND embedding_descriptor_id=?12
               AND embedding_dimension=?13 AND captured_generation_state=?14
               AND witness_attempt_ordinal=?15 AND witness_claim_epoch=?16
               AND witness_marked_claim_epoch=?17
               AND witness_send_disposition IS ?18 AND witness_error_code IS ?19
               AND witness_age_anchor_at=?20 AND captured_generation_authority_epoch=?21",
                params![
                    token.resolution_id,
                    now,
                    token.outbox_id,
                    token.life_id,
                    token.memory_id,
                    token.mutation_sequence,
                    token.resolution_epoch,
                    token.resolution_ordinal,
                    token.lease_owner,
                    token.runtime_fence_epoch,
                    token.claimed_generation_id,
                    token.embedding_descriptor_id,
                    token.embedding_dimension,
                    token.captured_generation_state,
                    token.witness_attempt_ordinal,
                    token.witness_claim_epoch,
                    token.witness_marked_claim_epoch,
                    token.witness_send_disposition,
                    token.witness_error_code,
                    token.witness_age_anchor_at,
                    token.captured_generation_authority_epoch,
                ],
            )
            .map_err(storage_error)?;
        if changed != 1 {
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeleteDeletePermitIssuanceCore::LostLeaseOrSuperseded);
        }
        #[cfg(test)]
        if DELETE_STARTED_BEFORE_COMMIT_FAULT.with(|fault| fault.replace(false)) {
            return Err(StorageError::new(
                "LATE_DELETE_DELETE_STARTED_COMMIT_FAILED",
                "test-only pre-commit failure; no Delete permit is returned",
                true,
            ));
        }
        #[cfg(test)]
        if DELETE_STARTED_BEFORE_COMMIT_UNKNOWN_FAULT.with(|fault| fault.replace(false)) {
            drop(tx);
            return Ok(LateDeleteDeletePermitIssuanceCore::CommitUnknown { token });
        }
        // The real SQLite COMMIT attempt is recorded just before the call so a
        // test can prove a genuine commit was attempted (and not skipped by the
        // pre-commit fault branch above). In release builds this helper compiles
        // out and the call is byte-for-byte the previous `tx.commit()`.
        #[cfg(test)]
        record_delete_started_commit_attempt_for_test();
        let commit_result = tx.commit();
        commit_result.map_err(storage_error)?;
        #[cfg(test)]
        if DELETE_STARTED_AFTER_COMMIT_FAULT.with(|fault| fault.replace(false)) {
            return Ok(LateDeleteDeletePermitIssuanceCore::CommitUnknown { token });
        }
        Ok(LateDeleteDeletePermitIssuanceCore::Issued(Box::new(
            LateDeleteDeletePermit {
                token,
                revision,
                content_hash,
            },
        )))
    }

    /// Reconciles the exact consumed Present capability after a DeleteStarted
    /// commit result is unknown. This is intentionally SELECT-only and neither
    /// recreates a capability nor treats a bare resolution id as authority.
    fn reconcile_late_delete_started_exact_token(
        &self,
        token: &LateDeleteResolutionToken,
    ) -> Result<LateDeleteStartedCommitUnknownNoPermit, StorageError> {
        #[cfg(test)]
        if DELETE_STARTED_RECONCILE_READ_FAILURE.with(|fault| fault.replace(false)) {
            return Err(StorageError::new(
                "LATE_DELETE_DELETE_STARTED_RECONCILE_READ_FAILED",
                "test-only readonly reconciliation failure",
                true,
            ));
        }
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(storage_error)?;
        let row = load_resolution_in(&tx, token.resolution_id)?;
        let last_disposition = tx
            .query_row(
                "SELECT last_resolution_disposition
                 FROM memory_vector_late_delete_resolution WHERE resolution_id=?1",
                [token.resolution_id],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()
            .map_err(storage_error)?
            .flatten();
        let result = match (row, last_disposition.as_deref()) {
            (Some(row), Some("delete_started"))
                if token_matches_row_without_liveness(token, &row)
                    && row.state == "processing"
                    && row.last_reserved_resolution_epoch == token.resolution_epoch
                    && row.last_disposition_epoch == token.resolution_epoch
                    && row
                        .lease_owner
                        .as_deref()
                        .is_some_and(|owner| owner == token.lease_owner)
                    && row.lease_fence_epoch == Some(token.runtime_fence_epoch) =>
            {
                LateDeleteStartedCommitUnknownNoPermit::DeleteStartedDurable
            }
            (Some(row), _)
                if token_matches_row_without_liveness(token, &row)
                    && row.state == "processing"
                    && row.last_reserved_resolution_epoch == token.resolution_epoch
                    && row.last_disposition_epoch < token.resolution_epoch
                    && row
                        .lease_owner
                        .as_deref()
                        .is_some_and(|owner| owner == token.lease_owner)
                    && row.lease_fence_epoch == Some(token.runtime_fence_epoch) =>
            {
                LateDeleteStartedCommitUnknownNoPermit::PreIssuanceDurable
            }
            _ => LateDeleteStartedCommitUnknownNoPermit::LostLeaseOrSuperseded,
        };
        tx.commit().map_err(storage_error)?;
        Ok(result)
    }

    /// Reconciles only durable state after a caller has lost the result of the
    /// DeleteStarted commit. It intentionally cannot recreate a capability.
    pub(crate) fn reconcile_late_delete_started(
        &self,
        resolution_id: i64,
    ) -> Result<LateDeleteStartedDurableState, StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(storage_error)?;
        let current: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM memory_vector_late_delete_resolution
             WHERE resolution_id=?1 AND state='processing'
               AND last_resolution_disposition='delete_started'
               AND last_disposition_epoch=resolution_epoch
               AND last_reserved_resolution_epoch=resolution_epoch)",
                [resolution_id],
                |row| row.get(0),
            )
            .map_err(storage_error)?;
        tx.commit().map_err(storage_error)?;
        Ok(if current {
            LateDeleteStartedDurableState::CurrentEpochDeleteStarted
        } else {
            LateDeleteStartedDurableState::NotCurrentEpochDeleteStarted
        })
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

    /// Consumes the sealed Query=None outcome before using the frozen CAS
    /// finalizer. Callers never receive its token back.
    pub(crate) fn finalize_late_delete_query_absent(
        &self,
        absent: AbsentPostQueryCapability,
    ) -> Result<LateDeleteResolutionFinalizeResult, StorageError> {
        self.finalize_late_delete_resolution_absent(&absent.token)
    }

    /// Consumes one non-corrupt Query failure and converges it to the only
    /// allowed same-ordinal state: unknown/query_unknown.
    pub(crate) fn finalize_late_delete_query_failure(
        &self,
        failure: FailedPostQueryCapability,
    ) -> Result<LateDeleteResolutionFinalizeResult, StorageError> {
        self.finalize_late_delete_resolution_unknown(
            &failure.token,
            LateDeleteResolutionDisposition::QueryUnknown,
            query_failure_error_code(&failure.error),
        )
    }

    /// Consumes one structurally corrupt Query observation and prevents a
    /// DeleteStarted transition for that ordinal.
    pub(crate) fn finalize_late_delete_query_corrupt(
        &self,
        corrupt: CorruptPostQueryCapability,
    ) -> Result<LateDeleteResolutionFinalizeResult, StorageError> {
        self.finalize_late_delete_resolution_waiting_rebuild(&corrupt.token, corrupt.error_code)
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

    pub(crate) fn finalize_deleted_post_delete(
        &self,
        deleted: DeletedPostDeleteCapability,
    ) -> Result<LateDeletePostDeleteFinalizeResult, StorageError> {
        self.transition_post_delete(
            &deleted.token,
            "resolved_deleted",
            LateDeleteResolutionDisposition::DeleteDeleted,
            None,
        )
    }

    pub(crate) fn finalize_absent_post_delete(
        &self,
        absent: AbsentPostDeleteCapability,
    ) -> Result<LateDeletePostDeleteFinalizeResult, StorageError> {
        self.transition_post_delete(
            &absent.token,
            "resolved_deleted",
            LateDeleteResolutionDisposition::DeleteAbsent,
            None,
        )
    }

    pub(crate) fn finalize_identity_mismatch_post_delete(
        &self,
        mismatch: IdentityMismatchPostDeleteCapability,
    ) -> Result<LateDeletePostDeleteFinalizeResult, StorageError> {
        self.transition_post_delete(
            &mismatch.token,
            "waiting_rebuild",
            LateDeleteResolutionDisposition::IdentityMismatch,
            Some("LATE_DELETE_IDENTITY_MISMATCH"),
        )
    }

    pub(crate) fn finalize_failed_post_delete(
        &self,
        failure: FailedPostDeleteCapability,
    ) -> Result<LateDeletePostDeleteFinalizeResult, StorageError> {
        self.transition_post_delete(
            &failure.token,
            "unknown",
            LateDeleteResolutionDisposition::DeleteUnknown,
            Some(delete_failure_error_code(failure.error_code)),
        )
    }

    pub(crate) fn finalize_pre_delete_corrupt(
        &self,
        corrupt: PreDeleteCorruptCapability,
    ) -> Result<LateDeletePostDeleteFinalizeResult, StorageError> {
        self.transition_post_delete(
            &corrupt.token,
            "waiting_rebuild",
            LateDeleteResolutionDisposition::WaitingRebuild,
            Some("LATE_DELETE_PRE_DELETE_CORRUPT"),
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
        // DeleteStarted is a durable external-I/O boundary.  It must not fall
        // through the ordinary expired-processing rule, which would otherwise
        // produce a generic finalization outcome and blur the recovery proof.
        let delete_started_rows = {
            let mut statement = tx
                .prepare(&format!(
                    "{RESOLUTION_SELECT_SQL} WHERE state='processing'
                     AND last_resolution_disposition='delete_started'
                     AND last_disposition_epoch=resolution_epoch
                     AND last_reserved_resolution_epoch=resolution_epoch
                     AND lease_expires_at <= ?1"
                ))
                .map_err(storage_error)?;
            let rows = statement
                .query_map([&now], resolution_row)
                .map_err(storage_error)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(storage_error)?;
            rows
        };
        let mut changed = 0;
        for row in delete_started_rows {
            if row.resolution_count >= MAX_LATE_DELETE_RESOLUTIONS {
                block_limit_in(&tx, row.resolution_id, &now)?;
                changed += 1;
            } else if !resolution_authority_is_current_in(&tx, &row, &now)? {
                converge_waiting_rebuild_in(&tx, row.resolution_id, &now)?;
                changed += 1;
            } else {
                changed += tx
                    .execute(
                        "UPDATE memory_vector_late_delete_resolution
                     SET state='unknown', last_resolution_disposition='delete_unknown',
                         last_disposition_epoch=resolution_epoch,
                         last_error_code='LATE_DELETE_DELETE_STARTED_RECOVERY',
                         lease_owner=NULL, lease_fence_epoch=NULL, lease_expires_at=NULL,
                         next_attempt_at=NULL, updated_at=?2
                     WHERE resolution_id=?1 AND state='processing'
                       AND last_resolution_disposition='delete_started'
                       AND last_disposition_epoch=resolution_epoch
                       AND last_reserved_resolution_epoch=resolution_epoch
                       AND lease_expires_at <= ?2",
                        params![row.resolution_id, now],
                    )
                    .map_err(storage_error)?;
            }
        }
        changed += tx.execute(
            "UPDATE memory_vector_late_delete_resolution
             SET state=CASE WHEN resolution_count >= ?1 THEN 'waiting_rebuild' WHEN state='claimed' THEN 'pending' ELSE 'unknown' END,
                 last_resolution_disposition=CASE WHEN resolution_count >= ?1 THEN 'waiting_rebuild' ELSE 'finalize_unknown' END,
                 last_disposition_epoch=resolution_epoch, last_error_code=CASE WHEN resolution_count >= ?1 THEN 'LATE_DELETE_RESOLUTION_LIMIT_REACHED' ELSE 'LATE_DELETE_RESOLUTION_LEASE_EXPIRED' END,
                 lease_owner=NULL, lease_fence_epoch=NULL, lease_expires_at=NULL,
                 next_attempt_at=NULL, updated_at=?2
             WHERE state IN ('claimed','processing') AND lease_expires_at <= ?2
               AND NOT (state='processing'
                        AND last_resolution_disposition='delete_started'
                        AND last_disposition_epoch=resolution_epoch
                        AND last_reserved_resolution_epoch=resolution_epoch)",
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
                AND lease_owner=?11 AND lease_fence_epoch=?12 AND lease_expires_at > ?8
                AND witness_send_disposition IS ?13 AND witness_error_code IS ?14",
            params![token.resolution_id, target_state, disposition.as_str(), error_code, target_state != "processing", next_attempt_at, terminal, now, token.resolution_epoch, token.resolution_ordinal, token.lease_owner, token.runtime_fence_epoch, token.witness_send_disposition, token.witness_error_code],
        ).map_err(storage_error)?;
        tx.commit().map_err(storage_error)?;
        Ok(if changed == 1 {
            LateDeleteResolutionFinalizeResult::Applied
        } else {
            LateDeleteResolutionFinalizeResult::LostLeaseOrSuperseded
        })
    }

    fn transition_post_delete(
        &self,
        token: &LateDeleteResolutionToken,
        target_state: &str,
        disposition: LateDeleteResolutionDisposition,
        error_code: Option<&str>,
    ) -> Result<LateDeletePostDeleteFinalizeResult, StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage_error)?;
        let now = authoritative_utc_millis_now_in(&tx)?;
        if !token_is_current_in(&tx, token, &now)? {
            tx.commit().map_err(storage_error)?;
            return Ok(LateDeletePostDeleteFinalizeResult::LostLeaseOrSuperseded);
        }
        let terminal = matches!(target_state, "resolved_deleted");
        let changed = tx
            .execute(
                "UPDATE memory_vector_late_delete_resolution
             SET state=?2, last_resolution_disposition=?3, last_disposition_epoch=resolution_epoch,
                 last_error_code=?4, lease_owner=CASE WHEN ?5 THEN NULL ELSE lease_owner END,
                 lease_fence_epoch=CASE WHEN ?5 THEN NULL ELSE lease_fence_epoch END,
                 lease_expires_at=CASE WHEN ?5 THEN NULL ELSE lease_expires_at END,
                 next_attempt_at=NULL, resolved_at=CASE WHEN ?5 THEN ?6 ELSE NULL END, updated_at=?6
             WHERE resolution_id=?1 AND outbox_id=?7 AND life_id=?8 AND memory_id=?9
               AND mutation_sequence=?10 AND claimed_generation_id=?11
               AND embedding_descriptor_id=?12 AND embedding_dimension=?13
               AND captured_generation_authority_epoch=?14 AND state='processing'
               AND resolution_epoch=?15 AND resolution_count=?16
               AND last_reserved_resolution_epoch=?15
               AND last_resolution_disposition='delete_started' AND last_disposition_epoch=?15
               AND lease_owner=?17 AND lease_fence_epoch=?18 AND lease_expires_at > ?6
               AND witness_attempt_ordinal=?19 AND witness_claim_epoch=?20
               AND witness_marked_claim_epoch=?21 AND witness_send_disposition IS ?22
               AND witness_error_code IS ?23 AND witness_age_anchor_at=?24",
                params![
                    token.resolution_id,
                    target_state,
                    disposition.as_str(),
                    error_code,
                    terminal,
                    now,
                    token.outbox_id,
                    token.life_id,
                    token.memory_id,
                    token.mutation_sequence,
                    token.claimed_generation_id,
                    token.embedding_descriptor_id,
                    token.embedding_dimension,
                    token.captured_generation_authority_epoch,
                    token.resolution_epoch,
                    token.resolution_ordinal,
                    token.lease_owner,
                    token.runtime_fence_epoch,
                    token.witness_attempt_ordinal,
                    token.witness_claim_epoch,
                    token.witness_marked_claim_epoch,
                    token.witness_send_disposition,
                    token.witness_error_code,
                    token.witness_age_anchor_at
                ],
            )
            .map_err(storage_error)?;
        #[cfg(test)]
        if POST_DELETE_FINALIZE_BEFORE_COMMIT_FAILURE.with(|fault| fault.replace(false)) {
            return Err(StorageError::new(
                "LATE_DELETE_POST_DELETE_FINALIZE_COMMIT_FAILED",
                "test-only known pre-commit finalizer failure",
                true,
            ));
        }
        #[cfg(test)]
        if POST_DELETE_FINALIZE_BEFORE_COMMIT_UNKNOWN.with(|fault| fault.replace(false)) {
            drop(tx);
            drop(state);
            return self.reconcile_post_delete_commit_unknown(token, target_state, disposition);
        }
        // A post-commit result loss must never retry the SQLite write.  The
        // typed capability is already consumed, so this is followed only by
        // the readonly durable-world classification below.
        #[cfg(test)]
        record_post_delete_finalize_commit_attempt_for_test();
        tx.commit().map_err(storage_error)?;
        #[cfg(test)]
        if POST_DELETE_FINALIZE_AFTER_COMMIT_UNKNOWN.with(|fault| fault.replace(false)) {
            drop(state);
            return self.reconcile_post_delete_commit_unknown(token, target_state, disposition);
        }
        Ok(if changed == 1 {
            LateDeletePostDeleteFinalizeResult::Applied
        } else {
            LateDeletePostDeleteFinalizeResult::LostLeaseOrSuperseded
        })
    }

    /// Inspects the one durable row after a terminal COMMIT result is unknown.
    /// It deliberately performs no mutation, claim, reservation, or capability
    /// construction: once a post-Delete capability is consumed, recovery owns
    /// every unresolved case.
    fn reconcile_post_delete_commit_unknown(
        &self,
        token: &LateDeleteResolutionToken,
        target_state: &str,
        disposition: LateDeleteResolutionDisposition,
    ) -> Result<LateDeletePostDeleteFinalizeResult, StorageError> {
        let state = self.state()?;
        let row: Option<PostDeleteCommitUnknownRow> = state
            .connection
            .query_row(
                "SELECT state,last_resolution_disposition,last_disposition_epoch,
                        resolution_epoch,last_reserved_resolution_epoch,resolution_count,
                        lease_owner,lease_fence_epoch
                 FROM memory_vector_late_delete_resolution
                 WHERE resolution_id=?1 AND outbox_id=?2 AND life_id=?3 AND memory_id=?4
                   AND mutation_sequence=?5 AND claimed_generation_id=?6
                   AND embedding_descriptor_id=?7 AND embedding_dimension=?8
                   AND captured_generation_authority_epoch=?9
                   AND witness_attempt_ordinal=?10 AND witness_claim_epoch=?11
                   AND witness_marked_claim_epoch=?12 AND witness_send_disposition IS ?13
                   AND witness_error_code IS ?14 AND witness_age_anchor_at=?15",
                params![
                    token.resolution_id,
                    token.outbox_id,
                    token.life_id,
                    token.memory_id,
                    token.mutation_sequence,
                    token.claimed_generation_id,
                    token.embedding_descriptor_id,
                    token.embedding_dimension,
                    token.captured_generation_authority_epoch,
                    token.witness_attempt_ordinal,
                    token.witness_claim_epoch,
                    token.witness_marked_claim_epoch,
                    token.witness_send_disposition,
                    token.witness_error_code,
                    token.witness_age_anchor_at,
                ],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .optional()
            .map_err(storage_error)?;
        let Some((
            state,
            last_disposition,
            last_disposition_epoch,
            resolution_epoch,
            last_reserved_resolution_epoch,
            resolution_count,
            lease_owner,
            lease_fence_epoch,
        )) = row
        else {
            return Ok(LateDeletePostDeleteFinalizeResult::LostLeaseOrSuperseded);
        };
        if state == target_state
            && last_disposition == disposition.as_str()
            && last_disposition_epoch == token.resolution_epoch
            && resolution_epoch == token.resolution_epoch
            && resolution_count == token.resolution_ordinal
        {
            return Ok(LateDeletePostDeleteFinalizeResult::ReconciledExpectedDisposition);
        }
        if state == "processing"
            && last_disposition == "delete_started"
            && last_disposition_epoch == token.resolution_epoch
            && resolution_epoch == token.resolution_epoch
            && last_reserved_resolution_epoch == token.resolution_epoch
            && resolution_count == token.resolution_ordinal
            && lease_owner.as_deref() == Some(&token.lease_owner)
            && lease_fence_epoch == Some(token.runtime_fence_epoch)
        {
            return Ok(LateDeletePostDeleteFinalizeResult::CommitUnknownStillDeleteStarted);
        }
        Ok(LateDeletePostDeleteFinalizeResult::LostLeaseOrSuperseded)
    }
}

fn delete_failure_error_code(code: VectorStoreErrorCode) -> &'static str {
    match code {
        VectorStoreErrorCode::StoreUnavailable => "LATE_DELETE_STORE_UNAVAILABLE",
        _ => "LATE_DELETE_CONDITIONAL_DELETE_UNKNOWN",
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

const RESOLUTION_SELECT_SQL: &str = "SELECT resolution_id,outbox_id,life_id,memory_id,mutation_sequence,claimed_generation_id,embedding_descriptor_id,embedding_dimension,captured_generation_state,witness_attempt_ordinal,witness_claim_epoch,witness_marked_claim_epoch,witness_send_disposition,witness_error_code,witness_age_anchor_at,captured_generation_authority_epoch,state,resolution_count,resolution_epoch,last_reserved_resolution_epoch,last_disposition_epoch,lease_owner,lease_fence_epoch,lease_expires_at FROM memory_vector_late_delete_resolution";

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
        witness_send_disposition: row.get(12)?,
        witness_error_code: row.get(13)?,
        witness_age_anchor_at: row.get(14)?,
        captured_generation_authority_epoch: row.get(15)?,
        state: row.get(16)?,
        resolution_count: row.get(17)?,
        resolution_epoch: row.get(18)?,
        last_reserved_resolution_epoch: row.get(19)?,
        last_disposition_epoch: row.get(20)?,
        lease_owner: row.get(21)?,
        lease_fence_epoch: row.get(22)?,
        lease_expires_at: row.get(23)?,
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
        && row.witness_send_disposition == claim.witness_send_disposition
        && row.witness_error_code == claim.witness_error_code
        && row.witness_age_anchor_at == claim.witness_age_anchor_at
        && row.captured_generation_authority_epoch == claim.captured_generation_authority_epoch
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
        && row.witness_send_disposition == token.witness_send_disposition
        && row.witness_error_code == token.witness_error_code
        && row.witness_age_anchor_at == token.witness_age_anchor_at
        && row.captured_generation_authority_epoch == token.captured_generation_authority_epoch
        && row.lease_owner.as_deref() == Some(token.lease_owner.as_str())
        && row.lease_fence_epoch == Some(token.runtime_fence_epoch)
        && row
            .lease_expires_at
            .as_deref()
            .is_some_and(|expires| expires > now)
        && row.resolution_epoch == token.resolution_epoch
        && row.resolution_count == token.resolution_ordinal
        && row.last_reserved_resolution_epoch == token.resolution_epoch)
}

/// Exact token/row identity comparison for readonly commit-unknown
/// reconciliation. Liveness is intentionally evaluated by the caller's
/// classification rather than granting any authority from this predicate.
fn token_matches_row_without_liveness(
    token: &LateDeleteResolutionToken,
    row: &ResolutionRow,
) -> bool {
    matches!(token.desired_action, LateDeleteAction::Delete)
        && token.target_revision.is_none()
        && token.target_content_hash.is_none()
        && row.resolution_id == token.resolution_id
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
        && row.witness_send_disposition == token.witness_send_disposition
        && row.witness_error_code == token.witness_error_code
        && row.witness_age_anchor_at == token.witness_age_anchor_at
        && row.captured_generation_authority_epoch == token.captured_generation_authority_epoch
        && row.resolution_epoch == token.resolution_epoch
        && row.resolution_count == token.resolution_ordinal
}

fn resolution_authority_is_current_in(
    tx: &Transaction<'_>,
    row: &ResolutionRow,
    now: &str,
) -> Result<bool, StorageError> {
    if row.captured_generation_authority_epoch <= 0 {
        return Ok(false);
    }
    let before_fallback: bool = tx
        .query_row(
            "SELECT ?1 < strftime('%Y-%m-%dT%H:%M:%fZ', ?2, '+24 hours')",
            params![now, row.witness_age_anchor_at],
            |r| r.get(0),
        )
        .map_err(storage_error)?;
    if !before_fallback {
        return Ok(false);
    }
    tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM memory_vector_generation WHERE generation_id=?1 AND descriptor_hash=?2 AND dimension=?3 AND state=?4 AND authority_epoch=?5)",
        params![row.claimed_generation_id,row.embedding_descriptor_id,row.embedding_dimension,row.captured_generation_state,row.captured_generation_authority_epoch],
        |r| r.get(0),
    ).map_err(storage_error)
}

fn converge_waiting_rebuild_in(
    tx: &Transaction<'_>,
    resolution_id: i64,
    now: &str,
) -> Result<(), StorageError> {
    tx.execute(
        "UPDATE memory_vector_late_delete_resolution SET state='waiting_rebuild', last_resolution_disposition='waiting_rebuild', last_disposition_epoch=resolution_epoch, lease_owner=NULL, lease_fence_epoch=NULL, lease_expires_at=NULL, next_attempt_at=NULL, updated_at=?2 WHERE resolution_id=?1",
        params![resolution_id, now],
    ).map_err(storage_error)?;
    Ok(())
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
    use crate::vector_store::{
        VectorGenerationId, VectorRecord, VectorSearchHit, VectorSearchQuery, VectorSpace,
        VectorStoreFuture,
    };
    use std::{
        fs,
        future::Future,
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc, Barrier,
        },
        task::{Context, Poll, Waker},
        thread,
    };

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
        state.connection.execute("INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch) VALUES ('generation-a','descriptor-a',2,'active',1) ON CONFLICT(generation_id) DO NOTHING", []).unwrap();
        state
            .connection
            .execute(
                "INSERT INTO memory_vector_late_delete_resolution
             (outbox_id,life_id,memory_id,mutation_sequence,claimed_generation_id,
              embedding_descriptor_id,embedding_dimension,captured_generation_state,
              witness_attempt_ordinal,witness_claim_epoch,witness_marked_claim_epoch,
              witness_send_disposition,witness_error_code,witness_age_anchor_at,
              captured_generation_authority_epoch,state,created_at,updated_at)
             VALUES (17,?1,?2,?3,'generation-a','descriptor-a',2,'active',1,1,1,
                     'possibly_sent',NULL,'2099-01-01T00:00:00.000Z',1,
                     'pending','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')",
                params![life_id, memory_id, sequence],
            )
            .unwrap();
    }

    fn reserved_token(storage: &StorageService) -> Box<LateDeleteResolutionToken> {
        let lease = storage
            .acquire_late_delete_runtime_lease("resolver-a")
            .unwrap()
            .unwrap();
        let claim = match storage.claim_one_late_delete_resolution(&lease).unwrap() {
            LateDeleteResolutionClaimResult::Claimed(claim) => claim,
            LateDeleteResolutionClaimResult::NoEligibleResolution => panic!("candidate must claim"),
        };
        match storage.reserve_late_delete_resolution(&claim).unwrap() {
            LateDeleteResolutionReservation::Reserved(token) => token,
            _ => panic!("claim must reserve"),
        }
    }

    fn reserved_query_permit(storage: &StorageService) -> Box<LateDeleteQueryPermit> {
        let lease = storage
            .acquire_late_delete_runtime_lease("resolver-a")
            .unwrap()
            .unwrap();
        let claim = match storage.claim_one_late_delete_resolution(&lease).unwrap() {
            LateDeleteResolutionClaimResult::Claimed(claim) => claim,
            LateDeleteResolutionClaimResult::NoEligibleResolution => panic!("candidate must claim"),
        };
        match storage
            .reserve_late_delete_resolution_for_query(&claim)
            .unwrap()
        {
            LateDeleteQueryReservation::Reserved(permit) => permit,
            _ => panic!("claim must reserve one Query permit"),
        }
    }

    fn issued_delete_permit(storage: &StorageService) -> Box<LateDeleteDeletePermit> {
        let present =
            acknowledge_query_present_for_test(*reserved_query_permit(storage), 7, "hash-7");
        match storage.issue_late_delete_permit(present).unwrap() {
            LateDeleteDeletePermitIssuance::Issued(permit) => permit,
            _ => panic!("a definite DeleteStarted commit must issue one permit"),
        }
    }

    #[derive(Clone)]
    struct ScriptedQueryStore {
        result: Result<Option<VectorMetadataSample>, VectorStoreError>,
        query_count: Arc<AtomicUsize>,
        delete_result: Result<ConditionalGenerationDeleteOutcome, VectorStoreError>,
        delete_count: Arc<AtomicUsize>,
        delete_started: Option<mpsc::Sender<()>>,
    }

    impl ScriptedQueryStore {
        fn new(result: Result<Option<VectorMetadataSample>, VectorStoreError>) -> Self {
            Self {
                result,
                query_count: Arc::new(AtomicUsize::new(0)),
                delete_result: Err(VectorStoreError::new(
                    VectorStoreErrorCode::StoreUnavailable,
                    "scripted query store has no delete result",
                    false,
                )),
                delete_count: Arc::new(AtomicUsize::new(0)),
                delete_started: None,
            }
        }

        fn with_delete_result(
            mut self,
            result: Result<ConditionalGenerationDeleteOutcome, VectorStoreError>,
        ) -> Self {
            self.delete_result = result;
            self
        }

        fn with_pending_delete(mut self, started: mpsc::Sender<()>) -> Self {
            self.delete_started = Some(started);
            self
        }

        fn query_count(&self) -> usize {
            self.query_count.load(Ordering::SeqCst)
        }

        fn delete_count(&self) -> usize {
            self.delete_count.load(Ordering::SeqCst)
        }

        fn unsupported<T>() -> Result<T, VectorStoreError> {
            Err(VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "scripted query store only supports generation metadata",
                false,
            ))
        }
    }

    impl VectorStore for ScriptedQueryStore {
        fn upsert<'a>(
            &'a self,
            _record: VectorRecord,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }

        fn upsert_batch<'a>(
            &'a self,
            _records: Vec<VectorRecord>,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }

        fn search<'a>(
            &'a self,
            _query: VectorSearchQuery,
        ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }

        fn delete<'a>(
            &'a self,
            _life_id: &'a str,
            _memory_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }

        fn delete_from_space<'a>(
            &'a self,
            _life_id: &'a str,
            _memory_id: &'a str,
            _space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }

        fn delete_by_life<'a>(
            &'a self,
            _life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }

        fn clear_space<'a>(
            &'a self,
            _life_id: &'a str,
            _space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }

        fn count<'a>(
            &'a self,
            _life_id: &'a str,
            _space: Option<&'a VectorSpace>,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }

        fn health_check<'a>(
            &'a self,
            _life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }

        fn get_generation_metadata<'a>(
            &'a self,
            _context: &'a VectorGenerationContext,
            _life_id: &'a str,
            _memory_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<Option<VectorMetadataSample>, VectorStoreError>> {
            self.query_count.fetch_add(1, Ordering::SeqCst);
            let result = self.result.clone();
            Box::pin(async move { result })
        }

        fn delete_generation_memory_if_matches<'a>(
            &'a self,
            _context: &'a VectorGenerationContext,
            _life_id: &'a str,
            _memory_id: &'a str,
            _expected_revision: i64,
            _expected_content_hash: &'a str,
        ) -> VectorStoreFuture<'a, Result<ConditionalGenerationDeleteOutcome, VectorStoreError>>
        {
            self.delete_count.fetch_add(1, Ordering::SeqCst);
            if let Some(started) = self.delete_started.clone() {
                return Box::pin(async move {
                    started.send(()).unwrap();
                    std::future::pending::<
                        Result<ConditionalGenerationDeleteOutcome, VectorStoreError>,
                    >()
                    .await
                });
            }
            let result = self.delete_result.clone();
            Box::pin(async move { result })
        }
    }

    fn query_context() -> VectorGenerationContext {
        VectorGenerationContext::new(
            VectorGenerationId::parse("generation-a").unwrap(),
            "descriptor-a",
            2,
        )
        .unwrap()
    }

    fn valid_query_sample() -> VectorMetadataSample {
        VectorMetadataSample {
            generation_id: "generation-a".into(),
            life_id: "life".into(),
            memory_id: "memory".into(),
            memory_revision: 7,
            content_hash: "hash-7".into(),
            descriptor_hash: "descriptor-a".into(),
            dimension: 2,
        }
    }

    fn expire_resolution_lease(storage: &StorageService) {
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
    }

    /// Freezes the authoritative-now that the production comparator will receive.
    /// The frozen value is read once from the SQLite clock, the anchor is derived
    /// from that same frozen value via SQLite's own date arithmetic (`-24 hours`),
    /// and the one-shot override is armed so the comparator's `?1` equals
    /// `witness_age_anchor_at + 24h` exactly (never `>=`).
    ///
    /// Returns `(anchor, frozen_now)`: the anchor to write into the row, and the
    /// exact authoritative timestamp the production comparator will receive.
    fn freeze_exact_24h_boundary(storage: &StorageService) -> (String, String) {
        let frozen_now: String = storage
            .state()
            .unwrap()
            .connection
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
                row.get(0)
            })
            .unwrap();
        let anchor: String = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?1, '-24 hours')",
                [&frozen_now],
                |row| row.get(0),
            )
            .unwrap();
        arm_authoritative_now_override_for_test(&frozen_now);
        (anchor, frozen_now)
    }

    /// Same as [`freeze_exact_24h_boundary`] but with the anchor one second
    /// older, so the boundary `anchor + 24h` sits exactly one second *above* the
    /// frozen `now`: the strict `<` must then allow issuance.
    fn freeze_exact_24h_boundary_minus_1s(storage: &StorageService) -> (String, String) {
        let frozen_now: String = storage
            .state()
            .unwrap()
            .connection
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
                row.get(0)
            })
            .unwrap();
        let anchor: String = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?1, '-24 hours', '+1 second')",
                [&frozen_now],
                |row| row.get(0),
            )
            .unwrap();
        arm_authoritative_now_override_for_test(&frozen_now);
        (anchor, frozen_now)
    }

    /// Proves through SQLite itself that the frozen authoritative `now` is the
    /// exact `+24 hours` of the stored anchor, returning `1` (true).
    fn assert_sqlite_exact_24h_equality(
        storage: &StorageService,
        frozen_now: &str,
        resolution_id: i64,
    ) {
        let equal: bool = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT ?1 = strftime('%Y-%m-%dT%H:%M:%fZ', witness_age_anchor_at, '+24 hours')
                 FROM memory_vector_late_delete_resolution WHERE resolution_id=?2",
                params![frozen_now, resolution_id],
                |row| row.get(0),
            )
            .unwrap();
        assert!(equal, "frozen authoritative now must equal anchor + 24h");
    }

    /// Issues one real DeleteStarted permit (count=1, current-epoch delete_started)
    /// and returns the durable resolution id with the permit dropped.
    fn issue_delete_started_permit(storage: &StorageService) -> i64 {
        let present =
            acknowledge_query_present_for_test(*reserved_query_permit(storage), 7, "hash-7");
        let permit = match storage.issue_late_delete_permit(present).unwrap() {
            LateDeleteDeletePermitIssuance::Issued(permit) => permit,
            _ => panic!("a definite DeleteStarted commit must issue one permit"),
        };
        let resolution_id = permit.token.resolution_id();
        drop(permit);
        resolution_id
    }

    #[test]
    fn late_delete_query_permit_and_delete_permit_are_issued_only_after_definite_commits() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let query_permit = reserved_query_permit(&storage);
        let present = acknowledge_query_present_for_test(*query_permit, 7, "hash-7");
        let delete_permit = match storage.issue_late_delete_permit(present).unwrap() {
            LateDeleteDeletePermitIssuance::Issued(permit) => permit,
            _ => panic!("definite DeleteStarted commit must issue one permit"),
        };
        assert_eq!(delete_permit.token.resolution_ordinal(), 1);
        assert_eq!(delete_permit.revision, 7);
        assert_eq!(delete_permit.content_hash, "hash-7");
        assert_eq!(
            storage
                .reconcile_late_delete_started(delete_permit.token.resolution_id())
                .unwrap(),
            LateDeleteStartedDurableState::CurrentEpochDeleteStarted
        );
        let row: (String, String, i64, i64) = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT state,last_resolution_disposition,resolution_count,last_disposition_epoch
                 FROM memory_vector_late_delete_resolution WHERE resolution_id=?1",
                [delete_permit.token.resolution_id()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(row, ("processing".into(), "delete_started".into(), 1, 1));
    }

    #[test]
    fn late_delete_query_permit_commit_unknown_returns_zero_permit() {
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
        QUERY_PERMIT_AFTER_COMMIT_FAULT.with(|fault| fault.set(true));
        let error = match storage.reserve_late_delete_resolution_for_query(&claim) {
            Err(error) => error,
            Ok(_) => panic!("post-commit result loss must not return a Query permit"),
        };
        assert_eq!(
            error.code,
            "LATE_DELETE_QUERY_RESERVATION_COMMIT_RESULT_UNKNOWN"
        );
        let row: (String, i64, i64) = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT state,resolution_count,last_reserved_resolution_epoch
                 FROM memory_vector_late_delete_resolution WHERE life_id='life' AND memory_id='memory'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, ("processing".into(), 1, 1));
    }

    #[test]
    fn late_delete_delete_started_commit_unknown_reconciles_without_recreating_permit() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let query_permit = reserved_query_permit(&storage);
        let resolution_id = query_permit.token.resolution_id();
        let present = acknowledge_query_present_for_test(*query_permit, 7, "hash-7");
        DELETE_STARTED_AFTER_COMMIT_FAULT.with(|fault| fault.set(true));
        reset_delete_started_commit_attempt_count_for_test();
        let error = match storage.issue_late_delete_permit(present) {
            Err(error) => error,
            Ok(_) => panic!("post-commit result loss must not return a Delete permit"),
        };
        assert_eq!(
            error.code,
            "LATE_DELETE_DELETE_STARTED_COMMIT_RESULT_UNKNOWN"
        );
        assert_eq!(
            delete_started_commit_attempt_count_for_test(),
            1,
            "a genuine COMMIT was attempted before the outcome was hidden"
        );
        assert_eq!(
            storage
                .reconcile_late_delete_started(resolution_id)
                .unwrap(),
            LateDeleteStartedDurableState::CurrentEpochDeleteStarted
        );
    }

    #[test]
    fn late_delete_delete_permit_pre_commit_failure_returns_zero_permit() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let query_permit = reserved_query_permit(&storage);
        let resolution_id = query_permit.token.resolution_id();
        let present = acknowledge_query_present_for_test(*query_permit, 7, "hash-7");
        DELETE_STARTED_BEFORE_COMMIT_FAULT.with(|fault| fault.set(true));
        reset_delete_started_commit_attempt_count_for_test();
        let error = match storage.issue_late_delete_permit(present) {
            Err(error) => error,
            Ok(_) => panic!("pre-commit failure must not return a Delete permit"),
        };
        assert_eq!(error.code, "LATE_DELETE_DELETE_STARTED_COMMIT_FAILED");
        assert_eq!(
            delete_started_commit_attempt_count_for_test(),
            0,
            "a pre-commit failure never reaches the real COMMIT"
        );
        assert_eq!(
            storage
                .reconcile_late_delete_started(resolution_id)
                .unwrap(),
            LateDeleteStartedDurableState::NotCurrentEpochDeleteStarted
        );
    }

    #[test]
    fn late_delete_delete_started_24h_converges_waiting_rebuild() {
        // The Query capability may outlive the 24-hour anchor. Model that
        // passage only in this storage-local test by aging the same captured
        // witness held by both the row and the already-issued Query permit.
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let query_permit = reserved_query_permit(&storage);
        let mut token = query_permit.token;
        token.witness_age_anchor_at = "2000-01-01T00:00:00.000Z".into();
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_late_delete_resolution
                 SET witness_age_anchor_at='2000-01-01T00:00:00.000Z'
                 WHERE life_id='life' AND memory_id='memory'",
                [],
            )
            .unwrap();
        let present =
            acknowledge_query_present_for_test(LateDeleteQueryPermit { token }, 7, "hash-7");
        assert!(matches!(
            storage.issue_late_delete_permit(present).unwrap(),
            LateDeleteDeletePermitIssuance::WaitingRebuild
        ));
    }

    #[test]
    fn late_delete_delete_started_generation_authority_converges_waiting_rebuild() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let present =
            acknowledge_query_present_for_test(*reserved_query_permit(&storage), 7, "hash-7");
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_generation
                 SET state='retired',authority_epoch=2 WHERE generation_id='generation-a'",
                [],
            )
            .unwrap();
        assert!(matches!(
            storage.issue_late_delete_permit(present).unwrap(),
            LateDeleteDeletePermitIssuance::WaitingRebuild
        ));
    }

    #[test]
    fn late_delete_delete_started_recovery_preserves_count_and_only_uses_delete_unknown_when_authoritative(
    ) {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let present =
            acknowledge_query_present_for_test(*reserved_query_permit(&storage), 7, "hash-7");
        let permit = match storage.issue_late_delete_permit(present).unwrap() {
            LateDeleteDeletePermitIssuance::Issued(permit) => permit,
            _ => panic!("must issue before recovery"),
        };
        let resolution_id = permit.token.resolution_id();
        drop(permit);
        expire_resolution_lease(&storage);
        assert_eq!(
            storage.recover_expired_late_delete_resolutions().unwrap(),
            1
        );
        let row: (String, String, i64, Option<String>) = storage.state().unwrap().connection.query_row(
            "SELECT state,last_resolution_disposition,resolution_count,lease_owner FROM memory_vector_late_delete_resolution WHERE resolution_id=?1",
            [resolution_id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).unwrap();
        assert_eq!(row, ("unknown".into(), "delete_unknown".into(), 1, None));
    }

    #[test]
    fn late_delete_delete_started_recovery_limit_and_authority_failure_wait_for_rebuild() {
        for sql in [
            "UPDATE memory_vector_late_delete_resolution SET resolution_count=3 WHERE life_id='life' AND memory_id='memory'",
            "UPDATE memory_vector_generation SET state='retired',authority_epoch=2 WHERE generation_id='generation-a'",
        ] {
            let (_root, storage) = storage();
            seed_resolution(&storage, "life", "memory", 1);
            let present = acknowledge_query_present_for_test(*reserved_query_permit(&storage), 7, "hash-7");
            let permit = match storage.issue_late_delete_permit(present).unwrap() {
                LateDeleteDeletePermitIssuance::Issued(permit) => permit,
                _ => panic!("must issue before recovery"),
            };
            drop(permit);
            storage.state().unwrap().connection.execute(sql, []).unwrap();
            expire_resolution_lease(&storage);
            assert_eq!(storage.recover_expired_late_delete_resolutions().unwrap(), 1);
            let row: (String, String) = storage.state().unwrap().connection.query_row(
                "SELECT state,last_resolution_disposition FROM memory_vector_late_delete_resolution WHERE life_id='life' AND memory_id='memory'",
                [], |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            assert_eq!(row, ("waiting_rebuild".into(), "waiting_rebuild".into()));
        }
    }

    #[test]
    fn late_delete_delete_started_recovery_leaves_generic_expired_processing_semantics_unchanged() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let token = reserved_token(&storage);
        expire_resolution_lease(&storage);
        assert_eq!(
            storage.recover_expired_late_delete_resolutions().unwrap(),
            1
        );
        let row: (String, String) = storage.state().unwrap().connection.query_row(
            "SELECT state,last_resolution_disposition FROM memory_vector_late_delete_resolution WHERE resolution_id=?1",
            [token.resolution_id()], |row| Ok((row.get(0)?, row.get(1)?)),
        ).unwrap();
        assert_eq!(row, ("unknown".into(), "finalize_unknown".into()));
    }

    #[test]
    fn late_delete_resolution_witness_identity_mismatch_and_row_lease_expiry_reject_token_cas() {
        for (send, error, expiry) in [
            (None, Some("PROVIDER_RESULT_UNKNOWN"), false),
            (
                Some("possibly_sent"),
                Some("PROVIDER_RESULT_UNKNOWN"),
                false,
            ),
            (Some("possibly_sent"), None, true),
        ] {
            let (_root, storage) = storage();
            seed_resolution(&storage, "life", "memory", 1);
            let token = reserved_token(&storage);
            if expiry {
                storage.state().unwrap().connection.execute("UPDATE memory_vector_late_delete_resolution SET lease_expires_at='2020-01-01T00:00:00.000Z' WHERE memory_id='memory'", []).unwrap();
            } else {
                storage.state().unwrap().connection.execute("UPDATE memory_vector_late_delete_resolution SET witness_send_disposition=?1, witness_error_code=?2 WHERE memory_id='memory'", params![send, error]).unwrap();
            }
            assert!(!storage
                .late_delete_resolution_token_is_current(&token)
                .unwrap());
            assert_eq!(
                storage
                    .finalize_late_delete_resolution_absent(&token)
                    .unwrap(),
                LateDeleteResolutionFinalizeResult::LostLeaseOrSuperseded
            );
            assert_eq!(
                storage
                    .finalize_late_delete_resolution_deleted(&token)
                    .unwrap(),
                LateDeleteResolutionFinalizeResult::LostLeaseOrSuperseded
            );
            assert_eq!(
                storage
                    .finalize_late_delete_resolution_unknown(
                        &token,
                        LateDeleteResolutionDisposition::FinalizeUnknown,
                        "UNKNOWN"
                    )
                    .unwrap(),
                LateDeleteResolutionFinalizeResult::LostLeaseOrSuperseded
            );
        }
    }

    #[test]
    fn late_delete_resolution_resolver_new_mutation_real_two_storage_service_concurrency() {
        for _ in 0..10 {
            let (root, service_a) = storage();
            let memory = super::super::test_support::insert_confirmed_memory_fixture(
                &service_a,
                "life",
                "fact",
                "late delete",
                None,
                0.5,
                0.5,
                false,
                true,
            );
            seed_resolution(&service_a, "life", &memory.id, 1);
            let service_b =
                StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let (committed_tx, committed_rx) = mpsc::channel();
            let memory_id = memory.id.clone();
            let resolver_barrier = Arc::clone(&barrier);
            let resolver = thread::spawn(move || {
                let token = reserved_token(&service_a);
                resolver_barrier.wait();
                committed_rx.recv().unwrap();
                (
                    service_a
                        .late_delete_resolution_token_is_current(&token)
                        .unwrap(),
                    service_a
                        .finalize_late_delete_resolution_deleted(&token)
                        .unwrap(),
                )
            });
            let mutation_barrier = Arc::clone(&barrier);
            let mutation = thread::spawn(move || {
                mutation_barrier.wait();
                <StorageService as MemoryVectorSyncOutboxRepository>::enqueue(
                    &service_b,
                    EnqueueMemoryVectorSyncRequest {
                        life_id: "life".into(),
                        memory_id,
                        desired_action: MemoryVectorSyncAction::Delete,
                    },
                )
                .unwrap();
                committed_tx.send(()).unwrap();
            });
            mutation.join().unwrap();
            let (current, finalize) = resolver.join().unwrap();
            assert!(!current);
            assert_eq!(
                finalize,
                LateDeleteResolutionFinalizeResult::LostLeaseOrSuperseded
            );
        }
    }

    #[test]
    fn late_delete_resolution_two_resolver_real_two_storage_service_runtime_takeover() {
        for _ in 0..10 {
            let (root, service_a) = storage();
            seed_resolution(&service_a, "life", "memory", 1);
            let service_b =
                StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let (a_ready_tx, a_ready_rx) = mpsc::channel();
            let (b_done_tx, b_done_rx) = mpsc::channel();
            let owner_a = thread::spawn(move || {
                let lease = service_a
                    .acquire_late_delete_runtime_lease("owner-a")
                    .unwrap()
                    .unwrap();
                let claim = match service_a.claim_one_late_delete_resolution(&lease).unwrap() {
                    LateDeleteResolutionClaimResult::Claimed(claim) => claim,
                    LateDeleteResolutionClaimResult::NoEligibleResolution => panic!("A must claim"),
                };
                let token = match service_a.reserve_late_delete_resolution(&claim).unwrap() {
                    LateDeleteResolutionReservation::Reserved(token) => token,
                    _ => panic!("A must reserve"),
                };
                a_ready_tx.send(()).unwrap();
                b_done_rx.recv().unwrap();
                (service_a, lease, token)
            });
            let owner_b = thread::spawn(move || {
                a_ready_rx.recv().unwrap();
                assert!(service_b
                    .acquire_late_delete_runtime_lease("owner-b")
                    .unwrap()
                    .is_none());
                b_done_tx.send(()).unwrap();
                service_b
            });
            let (service_a, old_lease, old_token) = owner_a.join().unwrap();
            let service_b = owner_b.join().unwrap();
            service_a.state().unwrap().connection.execute(
                "UPDATE memory_vector_late_delete_runtime_lease SET lease_expires_at='2020-01-01T00:00:00.000Z' WHERE lease_name='memory-vector-late-delete-resolver'", [],
            ).unwrap();
            service_a.state().unwrap().connection.execute(
                "UPDATE memory_vector_late_delete_resolution SET lease_expires_at='2020-01-01T00:00:00.000Z' WHERE memory_id='memory'", [],
            ).unwrap();
            let lease_b = service_b
                .acquire_late_delete_runtime_lease("owner-b")
                .unwrap()
                .unwrap();
            assert!(lease_b.fence_epoch() > old_lease.fence_epoch());
            assert_eq!(
                service_b.recover_expired_late_delete_resolutions().unwrap(),
                1
            );
            let claim_b = match service_b
                .claim_one_late_delete_resolution(&lease_b)
                .unwrap()
            {
                LateDeleteResolutionClaimResult::Claimed(claim) => claim,
                LateDeleteResolutionClaimResult::NoEligibleResolution => {
                    panic!("B must claim after takeover")
                }
            };
            let token_b = match service_b.reserve_late_delete_resolution(&claim_b).unwrap() {
                LateDeleteResolutionReservation::Reserved(token) => token,
                _ => panic!("B must reserve after takeover"),
            };
            assert!(!service_a
                .late_delete_resolution_token_is_current(&old_token)
                .unwrap());
            assert_eq!(
                service_a
                    .finalize_late_delete_resolution_deleted(&old_token)
                    .unwrap(),
                LateDeleteResolutionFinalizeResult::LostLeaseOrSuperseded
            );
            assert!(service_b
                .late_delete_resolution_token_is_current(&token_b)
                .unwrap());
        }
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
        let error = storage
            .mark_late_delete_resolution_disposition(
                &token,
                LateDeleteResolutionDisposition::DeleteStarted,
            )
            .unwrap_err();
        assert_eq!(error.code, "LATE_DELETE_DELETE_STARTED_REQUIRES_PERMIT");
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
    fn captured_generation_authority_epoch_change_between_claim_and_reserve_returns_no_token_without_consuming_ordinal(
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

        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_generation
                 SET state='retired', authority_epoch=authority_epoch+1
                 WHERE generation_id='generation-a'",
                [],
            )
            .unwrap();
        assert!(matches!(
            storage.reserve_late_delete_resolution(&claim).unwrap(),
            LateDeleteResolutionReservation::LostLeaseOrSuperseded
        ));
        let row: (String, i64, Option<String>) = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT state,resolution_count,lease_owner
                 FROM memory_vector_late_delete_resolution
                 WHERE life_id='life' AND memory_id='memory'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, ("waiting_rebuild".to_string(), 0, None));
    }

    #[test]
    fn late_delete_24h_authority_guard_converges_before_the_third_resolution_budget_slot() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_late_delete_resolution
                 SET witness_age_anchor_at='2000-01-01T00:00:00.000Z',
                     resolution_count=2, resolution_epoch=2,
                     last_reserved_resolution_epoch=2
                 WHERE life_id='life' AND memory_id='memory'",
                [],
            )
            .unwrap();
        let lease = storage
            .acquire_late_delete_runtime_lease("resolver-a")
            .unwrap()
            .unwrap();
        assert!(matches!(
            storage.claim_one_late_delete_resolution(&lease).unwrap(),
            LateDeleteResolutionClaimResult::NoEligibleResolution
        ));
        let row: (String, i64, Option<String>) = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT state,resolution_count,lease_owner
                 FROM memory_vector_late_delete_resolution
                 WHERE life_id='life' AND memory_id='memory'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, ("waiting_rebuild".to_string(), 2, None));
    }

    #[test]
    fn late_delete_resolution_superseded_new_mutation_atomic_commit_unknown_mutation() {
        for _ in 0..10 {
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
            let lease = storage
                .acquire_late_delete_runtime_lease("resolver-a")
                .unwrap()
                .unwrap();
            let claim = match storage.claim_one_late_delete_resolution(&lease).unwrap() {
                LateDeleteResolutionClaimResult::Claimed(claim) => claim,
                LateDeleteResolutionClaimResult::NoEligibleResolution => {
                    panic!("candidate must claim")
                }
            };
            let token = match storage.reserve_late_delete_resolution(&claim).unwrap() {
                LateDeleteResolutionReservation::Reserved(token) => token,
                _ => panic!("claim must reserve exactly one resolution slot"),
            };
            assert!(storage
                .late_delete_resolution_token_is_current(&token)
                .unwrap());
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
            assert!(!storage
                .late_delete_resolution_token_is_current(&token)
                .unwrap());
            assert_eq!(
                storage
                    .finalize_late_delete_resolution_deleted(&token)
                    .unwrap(),
                LateDeleteResolutionFinalizeResult::LostLeaseOrSuperseded
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

    /// BLOCKER-1A: at the exact authoritative boundary `now == anchor + 24h` the
    /// strict `<` guard must not issue a Delete permit. The authoritative now the
    /// comparator receives is frozen to the very timestamp the anchor was derived
    /// from, and SQLite itself proves `frozen_now == anchor + 24h`.
    #[test]
    fn late_delete_delete_started_exact_24h_issuance_blocks_permit() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let query_permit = reserved_query_permit(&storage);
        let mut token = query_permit.token;
        let resolution_id = token.resolution_id();
        clear_authoritative_now_override_for_test();
        let (anchor, frozen_now) = freeze_exact_24h_boundary(&storage);
        token.witness_age_anchor_at = anchor.clone();
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_late_delete_resolution
                 SET witness_age_anchor_at=?1
                 WHERE life_id='life' AND memory_id='memory'",
                [&anchor],
            )
            .unwrap();
        assert_sqlite_exact_24h_equality(&storage, &frozen_now, resolution_id);
        let present =
            acknowledge_query_present_for_test(LateDeleteQueryPermit { token }, 7, "hash-7");
        assert!(matches!(
            storage.issue_late_delete_permit(present).unwrap(),
            LateDeleteDeletePermitIssuance::WaitingRebuild
        ));
        let row: (String, String, i64, i64, Option<String>, Option<String>) = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT state,last_resolution_disposition,resolution_count,resolution_epoch,lease_owner,lease_expires_at
                 FROM memory_vector_late_delete_resolution WHERE life_id='life' AND memory_id='memory'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            (
                "waiting_rebuild".into(),
                "waiting_rebuild".into(),
                1,
                1,
                None,
                None
            )
        );
    }

    /// Adjacency: when the boundary `anchor + 24h` sits exactly one second above
    /// the frozen `now`, the strict `<` must still allow issuance (so the failure
    /// is not caused by `<=`).
    #[test]
    fn late_delete_delete_started_exact_24h_adjacent_second_below_issuance_allowed() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let query_permit = reserved_query_permit(&storage);
        let mut token = query_permit.token;
        clear_authoritative_now_override_for_test();
        let (anchor, frozen_now) = freeze_exact_24h_boundary_minus_1s(&storage);
        token.witness_age_anchor_at = anchor.clone();
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_late_delete_resolution
                 SET witness_age_anchor_at=?1
                 WHERE life_id='life' AND memory_id='memory'",
                [&anchor],
            )
            .unwrap();
        let one_second_above_is_boundary: bool = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT strftime('%Y-%m-%dT%H:%M:%fZ', ?1, '+1 second')
                        = strftime('%Y-%m-%dT%H:%M:%fZ', witness_age_anchor_at, '+24 hours')
                 FROM memory_vector_late_delete_resolution WHERE life_id='life' AND memory_id='memory'",
                [&frozen_now],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            one_second_above_is_boundary,
            "frozen now + 1s must equal anchor + 24h"
        );
        let present =
            acknowledge_query_present_for_test(LateDeleteQueryPermit { token }, 7, "hash-7");
        assert!(matches!(
            storage.issue_late_delete_permit(present).unwrap(),
            LateDeleteDeletePermitIssuance::Issued(_)
        ));
    }

    /// BLOCKER-1B: a durable current-epoch delete_started whose witness anchor
    /// is exactly 24h in the past must recover to waiting_rebuild (the 24h guard
    /// executes), not to unknown/delete_unknown, and must not consume a new
    /// ordinal or leak a capability.
    #[test]
    fn late_delete_delete_started_exact_24h_recovery_waiting_rebuild() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let resolution_id = issue_delete_started_permit(&storage);
        clear_authoritative_now_override_for_test();
        let (anchor, frozen_now) = freeze_exact_24h_boundary(&storage);
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_late_delete_resolution
                 SET witness_age_anchor_at=?1 WHERE resolution_id=?2",
                params![anchor, resolution_id],
            )
            .unwrap();
        assert_sqlite_exact_24h_equality(&storage, &frozen_now, resolution_id);
        expire_resolution_lease(&storage);
        assert_eq!(
            storage.recover_expired_late_delete_resolutions().unwrap(),
            1
        );
        let row: (String, String, i64, i64, Option<String>, Option<i64>, Option<String>) = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT state,last_resolution_disposition,resolution_count,resolution_epoch,lease_owner,lease_fence_epoch,lease_expires_at
                 FROM memory_vector_late_delete_resolution WHERE resolution_id=?1",
                [resolution_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            (
                "waiting_rebuild".into(),
                "waiting_rebuild".into(),
                1,
                1,
                None,
                None,
                None
            )
        );
    }

    /// BLOCKER-3B: the same durable delete_started recovery well beyond 24h must
    /// also converge to waiting_rebuild through the delete_started branch's own
    /// 24h guard (not merely because some other predicate happened to block).
    #[test]
    fn late_delete_delete_started_24h_recovery_beyond_boundary_waiting_rebuild() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let resolution_id = issue_delete_started_permit(&storage);
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_late_delete_resolution
                 SET witness_age_anchor_at='2000-01-01T00:00:00.000Z'
                 WHERE resolution_id=?1",
                [resolution_id],
            )
            .unwrap();
        expire_resolution_lease(&storage);
        assert_eq!(
            storage.recover_expired_late_delete_resolutions().unwrap(),
            1
        );
        let row: (String, String, i64, i64, Option<String>, Option<i64>, Option<String>) = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT state,last_resolution_disposition,resolution_count,resolution_epoch,lease_owner,lease_fence_epoch,lease_expires_at
                 FROM memory_vector_late_delete_resolution WHERE resolution_id=?1",
                [resolution_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            (
                "waiting_rebuild".into(),
                "waiting_rebuild".into(),
                1,
                1,
                None,
                None,
                None
            )
        );
    }

    /// BLOCKER-2: a real SQLite COMMIT failure. All issuance SQL completes, the
    /// real `transaction.commit()` is invoked exactly once and returns a genuine
    /// `SQLITE_BUSY` (a reader's SHARED lock denies the EXCLUSIVE promotion),
    /// the caller receives a known database failure, and the whole transaction
    /// rolls back so no current-epoch delete_started is ever persisted.
    #[test]
    fn late_delete_delete_started_commit_failure_real_commit_attempt_rolls_back() {
        let (root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let query_permit = reserved_query_permit(&storage);
        let resolution_id = query_permit.token.resolution_id();
        let present = acknowledge_query_present_for_test(*query_permit, 7, "hash-7");
        let database_path = storage.state().unwrap().database_path.clone();

        // The storage database is WAL by default, and in WAL a reader never
        // blocks a writer's COMMIT. Switch the throwaway test DB to the
        // rollback-journal mode the rest of the codebase uses for genuine
        // commit-failure evidence, then let a second connection's plain read
        // transaction hold the SHARED lock that denies COMMIT its EXCLUSIVE
        // promotion. This is real SQLite lock arbitration, not a simulated error.
        storage
            .state()
            .unwrap()
            .connection
            .pragma_update(None, "journal_mode", "DELETE")
            .unwrap();
        storage
            .state()
            .unwrap()
            .connection
            .busy_timeout(std::time::Duration::from_millis(0))
            .unwrap();
        let mut reader = rusqlite::Connection::open(&database_path).unwrap();
        let reader_transaction = reader.transaction().unwrap();
        let _count: i64 = reader_transaction
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_late_delete_resolution",
                [],
                |row| row.get(0),
            )
            .unwrap();

        reset_delete_started_commit_attempt_count_for_test();
        let error = match storage.issue_late_delete_permit(present) {
            Err(error) => error,
            Ok(_) => panic!("a genuine SQLite COMMIT failure must not return a Delete permit"),
        };
        assert_eq!(error.code, "LATE_DELETE_RESOLUTION_DATABASE_ERROR");
        assert_eq!(
            delete_started_commit_attempt_count_for_test(),
            1,
            "the real COMMIT was attempted exactly once"
        );

        drop(reader_transaction);
        drop(reader);
        drop(storage);

        // Reopen from disk with a fresh connection: the issuance transaction
        // fully rolled back, so current-epoch delete_started was not persisted.
        let reopened = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        assert_eq!(
            reopened
                .reconcile_late_delete_started(resolution_id)
                .unwrap(),
            LateDeleteStartedDurableState::NotCurrentEpochDeleteStarted
        );
        let row: (String, Option<String>, i64, i64, i64) = reopened
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT state,last_resolution_disposition,resolution_count,last_disposition_epoch,resolution_epoch
                 FROM memory_vector_late_delete_resolution WHERE resolution_id=?1",
                [resolution_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .unwrap();
        assert_eq!(
            row,
            ("processing".into(), None, 1, 0, 1),
            "only the pre-issuance durable state survives a known commit failure"
        );
    }

    /// BLOCKER-3A: a durable current-epoch delete_started with resolution_count=2
    /// and a current generation authority recovers to unknown/delete_unknown,
    /// preserves the count and epoch, clears the row lease, and does not mint a
    /// new ordinal; only a future claim+reserve cycle may produce ordinal 3.
    #[test]
    fn late_delete_delete_started_recovery_count_two_converges_delete_unknown_without_new_ordinal()
    {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let resolution_id = issue_delete_started_permit(&storage);
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_late_delete_resolution
                 SET resolution_count=2 WHERE resolution_id=?1",
                [resolution_id],
            )
            .unwrap();
        expire_resolution_lease(&storage);
        assert_eq!(
            storage.recover_expired_late_delete_resolutions().unwrap(),
            1
        );
        let row: (String, String, i64, i64, i64) = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT state,last_resolution_disposition,resolution_count,resolution_epoch,last_disposition_epoch
                 FROM memory_vector_late_delete_resolution WHERE resolution_id=?1",
                [resolution_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .unwrap();
        assert_eq!(row, ("unknown".into(), "delete_unknown".into(), 2, 1, 1));
        let lease_row: (Option<String>, Option<i64>, Option<String>) = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT lease_owner,lease_fence_epoch,lease_expires_at
                 FROM memory_vector_late_delete_resolution WHERE resolution_id=?1",
                [resolution_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(lease_row, (None, None, None));
        // A future claim+reserve cycle is what produces ordinal 3, never Recovery.
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_late_delete_runtime_lease
                 SET lease_expires_at='2020-01-01T00:00:00.000Z'
                 WHERE lease_name=?1",
                [RUNTIME_LEASE_NAME],
            )
            .unwrap();
        let lease = storage
            .acquire_late_delete_runtime_lease("resolver-b")
            .unwrap()
            .unwrap();
        let claim = match storage.claim_one_late_delete_resolution(&lease).unwrap() {
            LateDeleteResolutionClaimResult::Claimed(claim) => claim,
            LateDeleteResolutionClaimResult::NoEligibleResolution => {
                panic!("an unknown candidate must be claimable")
            }
        };
        let token = match storage.reserve_late_delete_resolution(&claim).unwrap() {
            LateDeleteResolutionReservation::Reserved(token) => token,
            _ => panic!("claim must reserve the next ordinal"),
        };
        assert_eq!(token.resolution_ordinal(), 3);
        assert!(storage
            .late_delete_resolution_token_is_current(&token)
            .unwrap());
    }

    /// BLOCKER-3C: a terminal superseded row that retains residual
    /// delete_started historical evidence plus an expired lease must never be
    /// reopened by Recovery. Recovery is gated on state='processing', so the
    /// superseded terminal state stays byte-for-byte untouched.
    #[test]
    fn late_delete_delete_started_recovery_superseded_residual_delete_started_stays_terminal() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let resolution_id = issue_delete_started_permit(&storage);
        let resolved_at: String = storage
            .state()
            .unwrap()
            .connection
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
                row.get(0)
            })
            .unwrap();
        // Schema16-legal terminal fixture: superseded state with a residual
        // delete_started disposition/epoch history and an expired row lease.
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_late_delete_resolution
                 SET state='superseded', resolved_at=?2,
                     lease_expires_at='2020-01-01T00:00:00.000Z'
                 WHERE resolution_id=?1",
                params![resolution_id, resolved_at],
            )
            .unwrap();
        let row: (String, String, i64, i64, Option<String>, Option<i64>, Option<String>) = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT state,last_resolution_disposition,resolution_count,resolution_epoch,lease_owner,lease_fence_epoch,lease_expires_at
                 FROM memory_vector_late_delete_resolution WHERE resolution_id=?1",
                [resolution_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            )
            .unwrap();
        assert_eq!(row.0, "superseded");
        assert_eq!(row.1, "delete_started");
        assert_eq!(
            storage.recover_expired_late_delete_resolutions().unwrap(),
            0,
            "Recovery must not reopen a superseded terminal row"
        );
        let after: (String, String, i64, i64, Option<String>, Option<i64>, Option<String>) = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT state,last_resolution_disposition,resolution_count,resolution_epoch,lease_owner,lease_fence_epoch,lease_expires_at
                 FROM memory_vector_late_delete_resolution WHERE resolution_id=?1",
                [resolution_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
            )
            .unwrap();
        assert_eq!(row, after);
    }

    fn query_resolution_state(storage: &StorageService) -> (String, String) {
        storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT state,last_resolution_disposition FROM memory_vector_late_delete_resolution WHERE life_id='life' AND memory_id='memory'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    #[test]
    fn late_delete_query_handoff_present_consumes_permit_and_observation() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())));
        let outcome = tauri::async_runtime::block_on(
            reserved_query_permit(&storage).execute_exact_query_once(
                &storage,
                &query_context(),
                &store,
            ),
        )
        .unwrap();
        let present = match outcome {
            LateDeleteQueryHandoffOutcome::Present(present) => present,
            _ => panic!("a valid exact query must yield Present"),
        };
        assert_eq!(store.query_count(), 1);
        assert_eq!(present.revision, 7);
        assert_eq!(present.content_hash, "hash-7");
        assert!(matches!(
            storage.issue_late_delete_permit(present).unwrap(),
            LateDeleteDeletePermitIssuance::Issued(_)
        ));
    }

    #[test]
    fn late_delete_query_handoff_absent_finalizes_without_delete_capability() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let store = ScriptedQueryStore::new(Ok(None));
        let outcome = tauri::async_runtime::block_on(
            reserved_query_permit(&storage).execute_exact_query_once(
                &storage,
                &query_context(),
                &store,
            ),
        )
        .unwrap();
        let absent = match outcome {
            LateDeleteQueryHandoffOutcome::Absent(absent) => absent,
            _ => panic!("Query=None must yield Absent"),
        };
        assert_eq!(store.query_count(), 1);
        assert_eq!(
            storage.finalize_late_delete_query_absent(absent).unwrap(),
            LateDeleteResolutionFinalizeResult::Applied
        );
        assert_eq!(
            query_resolution_state(&storage),
            ("resolved_absent".into(), "query_absent".into())
        );
    }

    #[test]
    fn late_delete_query_handoff_failure_finalizes_unknown_without_retry() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let store = ScriptedQueryStore::new(Err(VectorStoreError::new(
            VectorStoreErrorCode::StoreUnavailable,
            "injected ordinary query failure",
            true,
        )));
        let outcome = tauri::async_runtime::block_on(
            reserved_query_permit(&storage).execute_exact_query_once(
                &storage,
                &query_context(),
                &store,
            ),
        )
        .unwrap();
        let failure = match outcome {
            LateDeleteQueryHandoffOutcome::Failure(failure) => failure,
            _ => panic!("ordinary query error must yield Failure"),
        };
        assert_eq!(store.query_count(), 1);
        assert_eq!(
            storage.finalize_late_delete_query_failure(failure).unwrap(),
            LateDeleteResolutionFinalizeResult::Applied
        );
        assert_eq!(
            query_resolution_state(&storage),
            ("unknown".into(), "query_unknown".into())
        );
    }

    #[test]
    fn late_delete_query_handoff_corrupt_finalizes_waiting_rebuild() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let store = ScriptedQueryStore::new(Err(VectorStoreError::new(
            VectorStoreErrorCode::GenerationCorrupt,
            "injected corrupt generation",
            false,
        )));
        let outcome = tauri::async_runtime::block_on(
            reserved_query_permit(&storage).execute_exact_query_once(
                &storage,
                &query_context(),
                &store,
            ),
        )
        .unwrap();
        let corrupt = match outcome {
            LateDeleteQueryHandoffOutcome::Corrupt(corrupt) => corrupt,
            _ => panic!("GenerationCorrupt must yield Corrupt"),
        };
        assert_eq!(store.query_count(), 1);
        assert_eq!(
            storage.finalize_late_delete_query_corrupt(corrupt).unwrap(),
            LateDeleteResolutionFinalizeResult::Applied
        );
        assert_eq!(
            query_resolution_state(&storage),
            ("waiting_rebuild".into(), "waiting_rebuild".into())
        );
    }

    #[test]
    fn late_delete_query_handoff_corrupt_rejects_invalid_exact_samples() {
        let mut samples = Vec::new();
        let mut generation = valid_query_sample();
        generation.generation_id = "other-generation".into();
        samples.push(generation);
        let mut life = valid_query_sample();
        life.life_id = "other-life".into();
        samples.push(life);
        let mut memory = valid_query_sample();
        memory.memory_id = "other-memory".into();
        samples.push(memory);
        let mut descriptor = valid_query_sample();
        descriptor.descriptor_hash = "other-descriptor".into();
        samples.push(descriptor);
        let mut dimension = valid_query_sample();
        dimension.dimension = 3;
        samples.push(dimension);
        let mut revision = valid_query_sample();
        revision.memory_revision = 0;
        samples.push(revision);
        let mut hash = valid_query_sample();
        hash.content_hash = "bad hash".into();
        samples.push(hash);

        for sample in samples {
            let (_root, storage) = storage();
            seed_resolution(&storage, "life", "memory", 1);
            let store = ScriptedQueryStore::new(Ok(Some(sample)));
            let outcome = tauri::async_runtime::block_on(
                reserved_query_permit(&storage).execute_exact_query_once(
                    &storage,
                    &query_context(),
                    &store,
                ),
            )
            .unwrap();
            assert!(matches!(outcome, LateDeleteQueryHandoffOutcome::Corrupt(_)));
            assert_eq!(store.query_count(), 1);
        }
    }

    #[test]
    fn late_delete_query_handoff_context_mismatch_consumes_without_query() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())));
        let mismatched_context = VectorGenerationContext::new(
            VectorGenerationId::parse("generation-a").unwrap(),
            "other-descriptor",
            2,
        )
        .unwrap();
        let error = match tauri::async_runtime::block_on(
            reserved_query_permit(&storage).execute_exact_query_once(
                &storage,
                &mismatched_context,
                &store,
            ),
        ) {
            Err(error) => error,
            Ok(_) => panic!("a context mismatch must not produce a handoff outcome"),
        };
        assert_eq!(error.code, "LATE_DELETE_QUERY_CONTEXT_MISMATCH");
        assert_eq!(store.query_count(), 0);
    }

    #[test]
    fn late_delete_query_handoff_lost_authority_consumes_without_query() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let permit = reserved_query_permit(&storage);
        expire_resolution_lease(&storage);
        let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())));
        let outcome = tauri::async_runtime::block_on(permit.execute_exact_query_once(
            &storage,
            &query_context(),
            &store,
        ))
        .unwrap();
        assert!(matches!(
            outcome,
            LateDeleteQueryHandoffOutcome::LostLeaseOrSuperseded
        ));
        assert_eq!(store.query_count(), 0);
    }

    #[test]
    fn late_delete_delete_handoff_maps_all_conditional_outcomes_once() {
        let cases = [
            (
                Ok(ConditionalGenerationDeleteOutcome::Deleted),
                "resolved_deleted",
                "delete_deleted",
            ),
            (
                Ok(ConditionalGenerationDeleteOutcome::Absent),
                "resolved_deleted",
                "delete_absent",
            ),
            (
                Ok(ConditionalGenerationDeleteOutcome::IdentityMismatch),
                "waiting_rebuild",
                "identity_mismatch",
            ),
            (
                Err(VectorStoreError::new(
                    VectorStoreErrorCode::StoreUnavailable,
                    "injected delete failure",
                    true,
                )),
                "unknown",
                "delete_unknown",
            ),
        ];
        for (delete_result, expected_state, expected_disposition) in cases {
            let (_root, storage) = storage();
            seed_resolution(&storage, "life", "memory", 1);
            let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())))
                .with_delete_result(delete_result);
            let outcome = tauri::async_runtime::block_on(
                issued_delete_permit(&storage).execute_conditional_delete_once(&storage, &store),
            )
            .unwrap();
            let result = match outcome {
                LateDeleteDeleteHandoffOutcome::Deleted(capability) => {
                    storage.finalize_deleted_post_delete(capability).unwrap()
                }
                LateDeleteDeleteHandoffOutcome::Absent(capability) => {
                    storage.finalize_absent_post_delete(capability).unwrap()
                }
                LateDeleteDeleteHandoffOutcome::IdentityMismatch(capability) => storage
                    .finalize_identity_mismatch_post_delete(capability)
                    .unwrap(),
                LateDeleteDeleteHandoffOutcome::Failure(capability) => {
                    storage.finalize_failed_post_delete(capability).unwrap()
                }
                _ => panic!("a scripted conditional result must produce its typed capability"),
            };
            assert_eq!(result, LateDeletePostDeleteFinalizeResult::Applied);
            assert_eq!(store.delete_count(), 1);
            assert_eq!(
                query_resolution_state(&storage),
                (expected_state.into(), expected_disposition.into())
            );
        }
    }

    #[test]
    fn late_delete_delete_handoff_pre_delete_corrupt_and_lost_authority_make_zero_calls() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let permit = issued_delete_permit(&storage);
        let LateDeleteDeletePermit {
            token,
            content_hash,
            ..
        } = *permit;
        let corrupt_permit = Box::new(LateDeleteDeletePermit {
            token,
            revision: 0,
            content_hash,
        });
        let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())))
            .with_delete_result(Ok(ConditionalGenerationDeleteOutcome::Deleted));
        let outcome = tauri::async_runtime::block_on(
            corrupt_permit.execute_conditional_delete_once(&storage, &store),
        )
        .unwrap();
        let corrupt = match outcome {
            LateDeleteDeleteHandoffOutcome::PreDeleteCorrupt(capability) => capability,
            _ => panic!("invalid permit context must be pre-delete corruption"),
        };
        assert_eq!(store.delete_count(), 0);
        assert_eq!(
            storage.finalize_pre_delete_corrupt(corrupt).unwrap(),
            LateDeletePostDeleteFinalizeResult::Applied
        );
        assert_eq!(
            query_resolution_state(&storage),
            ("waiting_rebuild".into(), "waiting_rebuild".into())
        );
    }

    #[test]
    fn late_delete_post_delete_commit_unknown_reconciles_expected_terminal_without_replay() {
        reset_post_delete_finalize_faults_for_test();
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())))
            .with_delete_result(Ok(ConditionalGenerationDeleteOutcome::Deleted));
        let deleted = match tauri::async_runtime::block_on(
            issued_delete_permit(&storage).execute_conditional_delete_once(&storage, &store),
        )
        .unwrap()
        {
            LateDeleteDeleteHandoffOutcome::Deleted(capability) => capability,
            _ => panic!("scripted delete must yield the sealed deleted capability"),
        };
        POST_DELETE_FINALIZE_AFTER_COMMIT_UNKNOWN.with(|fault| fault.set(true));
        assert_eq!(
            storage.finalize_deleted_post_delete(deleted).unwrap(),
            LateDeletePostDeleteFinalizeResult::ReconciledExpectedDisposition
        );
        assert_eq!(post_delete_finalize_commit_attempt_count_for_test(), 1);
        assert_eq!(store.delete_count(), 1);
        assert_eq!(
            query_resolution_state(&storage),
            ("resolved_deleted".into(), "delete_deleted".into())
        );
    }

    #[test]
    fn late_delete_post_delete_commit_unknown_still_delete_started_leaves_recovery_owner() {
        reset_post_delete_finalize_faults_for_test();
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())))
            .with_delete_result(Ok(ConditionalGenerationDeleteOutcome::Deleted));
        let deleted = match tauri::async_runtime::block_on(
            issued_delete_permit(&storage).execute_conditional_delete_once(&storage, &store),
        )
        .unwrap()
        {
            LateDeleteDeleteHandoffOutcome::Deleted(capability) => capability,
            _ => panic!("scripted delete must yield the sealed deleted capability"),
        };
        POST_DELETE_FINALIZE_BEFORE_COMMIT_UNKNOWN.with(|fault| fault.set(true));
        assert_eq!(
            storage.finalize_deleted_post_delete(deleted).unwrap(),
            LateDeletePostDeleteFinalizeResult::CommitUnknownStillDeleteStarted
        );
        assert_eq!(post_delete_finalize_commit_attempt_count_for_test(), 0);
        assert_eq!(store.delete_count(), 1);
        assert_eq!(
            query_resolution_state(&storage),
            ("processing".into(), "delete_started".into())
        );
        expire_resolution_lease(&storage);
        assert_eq!(
            storage.recover_expired_late_delete_resolutions().unwrap(),
            1
        );
    }

    #[test]
    fn late_delete_post_delete_reconcile_superseded_never_overwrites_new_mutation() {
        let (root, storage) = storage();
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
        let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())))
            .with_delete_result(Ok(ConditionalGenerationDeleteOutcome::Deleted));
        let deleted = match tauri::async_runtime::block_on(
            issued_delete_permit(&storage).execute_conditional_delete_once(&storage, &store),
        )
        .unwrap()
        {
            LateDeleteDeleteHandoffOutcome::Deleted(capability) => capability,
            _ => panic!("scripted delete must yield the sealed deleted capability"),
        };
        let DeletedPostDeleteCapability { token } = deleted;
        let service_b = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        <StorageService as MemoryVectorSyncOutboxRepository>::enqueue(
            &service_b,
            EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: memory.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            },
        )
        .unwrap();
        assert_eq!(
            storage
                .reconcile_post_delete_commit_unknown(
                    &token,
                    "resolved_deleted",
                    LateDeleteResolutionDisposition::DeleteDeleted,
                )
                .unwrap(),
            LateDeletePostDeleteFinalizeResult::LostLeaseOrSuperseded
        );
        assert_eq!(store.delete_count(), 1);
        let row: (String, String, i64) = service_b
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT r.state,r.last_resolution_disposition,o.mutation_sequence
             FROM memory_vector_late_delete_resolution r
             JOIN memory_vector_sync_outbox o ON o.life_id=r.life_id AND o.memory_id=r.memory_id
             WHERE r.life_id='life' AND r.memory_id=?1",
                [&memory.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, ("superseded".into(), "superseded".into(), 2));
    }

    #[test]
    fn late_delete_post_delete_known_failure_consumes_capability_without_retry() {
        reset_post_delete_finalize_faults_for_test();
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())))
            .with_delete_result(Ok(ConditionalGenerationDeleteOutcome::Deleted));
        let deleted = match tauri::async_runtime::block_on(
            issued_delete_permit(&storage).execute_conditional_delete_once(&storage, &store),
        )
        .unwrap()
        {
            LateDeleteDeleteHandoffOutcome::Deleted(capability) => capability,
            _ => panic!("scripted delete must yield the sealed deleted capability"),
        };
        POST_DELETE_FINALIZE_BEFORE_COMMIT_FAILURE.with(|fault| fault.set(true));
        let error = storage.finalize_deleted_post_delete(deleted).unwrap_err();
        assert_eq!(error.code, "LATE_DELETE_POST_DELETE_FINALIZE_COMMIT_FAILED");
        assert_eq!(post_delete_finalize_commit_attempt_count_for_test(), 0);
        assert_eq!(store.delete_count(), 1);
        assert_eq!(
            query_resolution_state(&storage),
            ("processing".into(), "delete_started".into())
        );
    }

    #[test]
    fn late_delete_post_delete_cancellation_consumes_delete_permit_during_external_delete() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let (started_tx, started_rx) = mpsc::channel();
        let store =
            ScriptedQueryStore::new(Ok(Some(valid_query_sample()))).with_pending_delete(started_tx);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(
            issued_delete_permit(&storage).execute_conditional_delete_once(&storage, &store),
        );
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        started_rx.recv().unwrap();
        assert_eq!(store.delete_count(), 1);
        drop(future);
        assert_eq!(
            query_resolution_state(&storage),
            ("processing".into(), "delete_started".into())
        );
        expire_resolution_lease(&storage);
        assert_eq!(
            storage.recover_expired_late_delete_resolutions().unwrap(),
            1
        );
    }

    #[test]
    fn late_delete_post_delete_crash_a_restart_has_no_delete_permit_reconstruction() {
        let (root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        drop(issued_delete_permit(&storage));
        let database_root = root.0.join("data");
        drop(storage);
        let reopened = StorageService::initialize_with_roots(database_root, None).unwrap();
        assert_eq!(
            query_resolution_state(&reopened),
            ("processing".into(), "delete_started".into())
        );
        expire_resolution_lease(&reopened);
        assert_eq!(
            reopened.recover_expired_late_delete_resolutions().unwrap(),
            1
        );
    }

    #[test]
    fn late_delete_post_delete_crash_b_restart_after_started_delete_has_no_replay() {
        let (root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let (started_tx, started_rx) = mpsc::channel();
        let store =
            ScriptedQueryStore::new(Ok(Some(valid_query_sample()))).with_pending_delete(started_tx);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(
            issued_delete_permit(&storage).execute_conditional_delete_once(&storage, &store),
        );
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        started_rx.recv().unwrap();
        assert_eq!(store.delete_count(), 1);
        drop(future);
        let database_root = root.0.join("data");
        drop(storage);
        let reopened = StorageService::initialize_with_roots(database_root, None).unwrap();
        assert_eq!(
            query_resolution_state(&reopened),
            ("processing".into(), "delete_started".into())
        );
        expire_resolution_lease(&reopened);
        assert_eq!(
            reopened.recover_expired_late_delete_resolutions().unwrap(),
            1
        );
    }

    #[test]
    fn late_delete_post_delete_crash_c_restart_drops_known_outcome_without_finalize() {
        let (root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())))
            .with_delete_result(Ok(ConditionalGenerationDeleteOutcome::Deleted));
        let capability = tauri::async_runtime::block_on(
            issued_delete_permit(&storage).execute_conditional_delete_once(&storage, &store),
        )
        .unwrap();
        assert!(matches!(
            capability,
            LateDeleteDeleteHandoffOutcome::Deleted(_)
        ));
        assert_eq!(store.delete_count(), 1);
        drop(capability);
        let database_root = root.0.join("data");
        drop(storage);
        let reopened = StorageService::initialize_with_roots(database_root, None).unwrap();
        assert_eq!(
            query_resolution_state(&reopened),
            ("processing".into(), "delete_started".into())
        );
        expire_resolution_lease(&reopened);
        assert_eq!(
            reopened.recover_expired_late_delete_resolutions().unwrap(),
            1
        );
    }

    #[test]
    fn late_delete_post_delete_new_mutation_race_old_finalizer_loses_without_overwrite() {
        for _ in 0..10 {
            let (root, service_a) = storage();
            let memory = super::super::test_support::insert_confirmed_memory_fixture(
                &service_a,
                "life",
                "fact",
                "late delete",
                None,
                0.5,
                0.5,
                false,
                true,
            );
            seed_resolution(&service_a, "life", &memory.id, 1);
            let service_b =
                StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let (capability_ready_tx, capability_ready_rx) = mpsc::channel();
            let (mutation_done_tx, mutation_done_rx) = mpsc::channel();
            let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())))
                .with_delete_result(Ok(ConditionalGenerationDeleteOutcome::Deleted));
            let old_barrier = Arc::clone(&barrier);
            let old_finalizer = thread::spawn(move || {
                let capability = match tauri::async_runtime::block_on(
                    issued_delete_permit(&service_a)
                        .execute_conditional_delete_once(&service_a, &store),
                )
                .unwrap()
                {
                    LateDeleteDeleteHandoffOutcome::Deleted(capability) => capability,
                    _ => panic!("scripted delete must yield a deleted capability"),
                };
                capability_ready_tx.send(()).unwrap();
                old_barrier.wait();
                mutation_done_rx.recv().unwrap();
                let result = service_a.finalize_deleted_post_delete(capability).unwrap();
                (result, store.delete_count())
            });
            let mutation_barrier = Arc::clone(&barrier);
            let memory_id = memory.id.clone();
            let mutation = thread::spawn(move || {
                capability_ready_rx.recv().unwrap();
                mutation_barrier.wait();
                <StorageService as MemoryVectorSyncOutboxRepository>::enqueue(
                    &service_b,
                    EnqueueMemoryVectorSyncRequest {
                        life_id: "life".into(),
                        memory_id,
                        desired_action: MemoryVectorSyncAction::Delete,
                    },
                )
                .unwrap();
                mutation_done_tx.send(()).unwrap();
                service_b
            });
            let service_b = mutation.join().unwrap();
            let (finalize, delete_count) = old_finalizer.join().unwrap();
            assert_eq!(
                finalize,
                LateDeletePostDeleteFinalizeResult::LostLeaseOrSuperseded
            );
            assert_eq!(delete_count, 1);
            let row: (String, String, i64) = service_b
                .state()
                .unwrap()
                .connection
                .query_row(
                    "SELECT r.state,r.last_resolution_disposition,o.mutation_sequence
                 FROM memory_vector_late_delete_resolution r
                 JOIN memory_vector_sync_outbox o ON o.life_id=r.life_id AND o.memory_id=r.memory_id
                 WHERE r.life_id='life' AND r.memory_id=?1",
                    [&memory.id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(row, ("superseded".into(), "superseded".into(), 2));
        }
    }

    #[test]
    fn late_delete_post_delete_finalizer_first_allows_later_new_mutation() {
        for _ in 0..10 {
            let (root, service_a) = storage();
            let memory = super::super::test_support::insert_confirmed_memory_fixture(
                &service_a,
                "life",
                "fact",
                "late delete",
                None,
                0.5,
                0.5,
                false,
                true,
            );
            seed_resolution(&service_a, "life", &memory.id, 1);
            let service_b =
                StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let (finalized_tx, finalized_rx) = mpsc::channel();
            let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())))
                .with_delete_result(Ok(ConditionalGenerationDeleteOutcome::Deleted));
            let finalizer_barrier = Arc::clone(&barrier);
            let finalizer = thread::spawn(move || {
                let capability = match tauri::async_runtime::block_on(
                    issued_delete_permit(&service_a)
                        .execute_conditional_delete_once(&service_a, &store),
                )
                .unwrap()
                {
                    LateDeleteDeleteHandoffOutcome::Deleted(capability) => capability,
                    _ => panic!("scripted delete must yield a deleted capability"),
                };
                finalizer_barrier.wait();
                let result = service_a.finalize_deleted_post_delete(capability).unwrap();
                finalized_tx.send(()).unwrap();
                (result, store.delete_count())
            });
            let mutation_barrier = Arc::clone(&barrier);
            let memory_id = memory.id.clone();
            let mutation = thread::spawn(move || {
                mutation_barrier.wait();
                finalized_rx.recv().unwrap();
                <StorageService as MemoryVectorSyncOutboxRepository>::enqueue(
                    &service_b,
                    EnqueueMemoryVectorSyncRequest {
                        life_id: "life".into(),
                        memory_id,
                        desired_action: MemoryVectorSyncAction::Delete,
                    },
                )
                .unwrap();
                service_b
            });
            let service_b = mutation.join().unwrap();
            let (finalize, delete_count) = finalizer.join().unwrap();
            assert_eq!(finalize, LateDeletePostDeleteFinalizeResult::Applied);
            assert_eq!(delete_count, 1);
            let row: (String, String, i64) = service_b
                .state()
                .unwrap()
                .connection
                .query_row(
                    "SELECT r.state,r.last_resolution_disposition,o.mutation_sequence
                 FROM memory_vector_late_delete_resolution r
                 JOIN memory_vector_sync_outbox o ON o.life_id=r.life_id AND o.memory_id=r.memory_id
                 WHERE r.life_id='life' AND r.memory_id=?1",
                    [&memory.id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(row, ("resolved_deleted".into(), "delete_deleted".into(), 2));
        }
    }

    #[test]
    fn late_delete_opaque_query_delegates_once_without_caller_context() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())));
        let outcome = tauri::async_runtime::block_on(
            reserved_query_permit(&storage).execute_exact_query_once_opaque(&storage, &store),
        )
        .unwrap();
        let present = match outcome {
            LateDeleteQueryHandoffOutcome::Present(present) => present,
            _ => panic!("opaque Query must preserve the H1 Present outcome"),
        };
        assert_eq!(store.query_count(), 1);
        assert!(matches!(
            storage
                .issue_late_delete_permit_for_runner(present)
                .unwrap(),
            LateDeleteDeletePermitRunnerIssuance::Issued(_)
        ));
    }

    #[test]
    fn late_delete_opaque_query_context_corrupt_consumes_without_query() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let permit = reserved_query_permit(&storage);
        let LateDeleteQueryPermit { mut token } = *permit;
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_late_delete_resolution
                 SET claimed_generation_id='not a generation id'
                 WHERE life_id='life' AND memory_id='memory'",
                [],
            )
            .unwrap();
        token.claimed_generation_id = "not a generation id".into();
        let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())));
        let corrupt = match tauri::async_runtime::block_on(
            Box::new(LateDeleteQueryPermit { token })
                .execute_exact_query_once_opaque(&storage, &store),
        )
        .unwrap()
        {
            LateDeleteQueryHandoffOutcome::Corrupt(corrupt) => corrupt,
            _ => panic!("internal context corruption must be opaque Corrupt"),
        };
        assert_eq!(store.query_count(), 0);
        assert_eq!(
            storage.finalize_late_delete_query_corrupt(corrupt).unwrap(),
            LateDeleteResolutionFinalizeResult::Applied
        );
        let code: Option<String> = storage.state().unwrap().connection.query_row(
            "SELECT last_error_code FROM memory_vector_late_delete_resolution WHERE life_id='life' AND memory_id='memory'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(code.as_deref(), Some("LATE_DELETE_QUERY_CONTEXT_CORRUPT"));
    }

    #[test]
    fn late_delete_opaque_query_lost_authority_makes_zero_queries() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let permit = reserved_query_permit(&storage);
        expire_resolution_lease(&storage);
        let store = ScriptedQueryStore::new(Ok(Some(valid_query_sample())));
        assert!(matches!(
            tauri::async_runtime::block_on(
                permit.execute_exact_query_once_opaque(&storage, &store)
            )
            .unwrap(),
            LateDeleteQueryHandoffOutcome::LostLeaseOrSuperseded
        ));
        assert_eq!(store.query_count(), 0);
    }

    #[test]
    fn late_delete_runner_issuance_commit_unknown_never_mints_a_permit() {
        for (before_commit, expected) in [
            (
                false,
                LateDeleteStartedCommitUnknownNoPermit::DeleteStartedDurable,
            ),
            (
                true,
                LateDeleteStartedCommitUnknownNoPermit::PreIssuanceDurable,
            ),
        ] {
            let (_root, storage) = storage();
            seed_resolution(&storage, "life", "memory", 1);
            let present =
                acknowledge_query_present_for_test(*reserved_query_permit(&storage), 7, "hash-7");
            if before_commit {
                DELETE_STARTED_BEFORE_COMMIT_UNKNOWN_FAULT.with(|fault| fault.set(true));
            } else {
                DELETE_STARTED_AFTER_COMMIT_FAULT.with(|fault| fault.set(true));
            }
            assert!(matches!(
                storage.issue_late_delete_permit_for_runner(present).unwrap(),
                LateDeleteDeletePermitRunnerIssuance::CommitUnknownRecoveryRequired(result)
                    if result == expected
            ));
            let row: (String, Option<String>) = storage.state().unwrap().connection.query_row(
                "SELECT state,last_resolution_disposition FROM memory_vector_late_delete_resolution WHERE life_id='life' AND memory_id='memory'",
                [], |row| Ok((row.get(0)?, row.get(1)?)),
            ).unwrap();
            assert_eq!(
                row,
                if before_commit {
                    ("processing".into(), None)
                } else {
                    ("processing".into(), Some("delete_started".into()))
                }
            );
        }
    }

    #[test]
    fn late_delete_runner_facade_dry_run_keeps_claim_opaque() {
        fn accepts_only_facade_claim(_claim: Box<crate::storage::LateDeleteResolutionClaim>) {}
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let lease = storage
            .acquire_late_delete_runtime_lease("facade-owner")
            .unwrap()
            .unwrap();
        let claim = match storage.claim_one_late_delete_resolution(&lease).unwrap() {
            LateDeleteResolutionClaimResult::Claimed(claim) => claim,
            _ => panic!("fixture must return an opaque claim"),
        };
        accepts_only_facade_claim(claim);
    }

    #[test]
    fn late_delete_runner_issuance_unknown_superseded_is_no_permit_no_replay() {
        let (root, storage) = storage();
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
        let present =
            acknowledge_query_present_for_test(*reserved_query_permit(&storage), 7, "hash-7");
        DELETE_STARTED_AFTER_COMMIT_FAULT.with(|fault| fault.set(true));
        let token = match storage.issue_late_delete_permit_core(present).unwrap() {
            LateDeleteDeletePermitIssuanceCore::CommitUnknown { token } => token,
            _ => panic!("test seam must produce commit uncertainty"),
        };
        let service_b = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        <StorageService as MemoryVectorSyncOutboxRepository>::enqueue(
            &service_b,
            EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: memory.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            },
        )
        .unwrap();
        assert_eq!(
            storage
                .reconcile_late_delete_started_exact_token(&token)
                .unwrap(),
            LateDeleteStartedCommitUnknownNoPermit::LostLeaseOrSuperseded
        );
        let row: (String, String, i64) = service_b
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT r.state,r.last_resolution_disposition,o.mutation_sequence
             FROM memory_vector_late_delete_resolution r
             JOIN memory_vector_sync_outbox o ON o.life_id=r.life_id AND o.memory_id=r.memory_id
             WHERE r.life_id='life' AND r.memory_id=?1",
                [&memory.id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(row, ("superseded".into(), "superseded".into(), 2));
    }

    #[test]
    fn late_delete_runner_issuance_unknown_read_failure_never_mints_a_permit() {
        let (_root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let present =
            acknowledge_query_present_for_test(*reserved_query_permit(&storage), 7, "hash-7");
        DELETE_STARTED_AFTER_COMMIT_FAULT.with(|fault| fault.set(true));
        DELETE_STARTED_RECONCILE_READ_FAILURE.with(|fault| fault.set(true));
        let error = match storage.issue_late_delete_permit_for_runner(present) {
            Err(error) => error,
            Ok(_) => panic!("read reconciliation failure must not issue a permit"),
        };
        assert_eq!(
            error.code,
            "LATE_DELETE_DELETE_STARTED_RECONCILE_READ_FAILED"
        );
        assert_eq!(
            query_resolution_state(&storage),
            ("processing".into(), "delete_started".into())
        );
    }

    #[test]
    fn late_delete_runner_issuance_unknown_cancel_before_reconcile_restarts_via_recovery() {
        let (root, storage) = storage();
        seed_resolution(&storage, "life", "memory", 1);
        let present =
            acknowledge_query_present_for_test(*reserved_query_permit(&storage), 7, "hash-7");
        DELETE_STARTED_AFTER_COMMIT_FAULT.with(|fault| fault.set(true));
        let token = match storage.issue_late_delete_permit_core(present).unwrap() {
            LateDeleteDeletePermitIssuanceCore::CommitUnknown { token } => token,
            _ => panic!("test seam must produce commit uncertainty"),
        };
        drop(token);
        let database_root = root.0.join("data");
        drop(storage);
        let reopened = StorageService::initialize_with_roots(database_root, None).unwrap();
        assert_eq!(
            query_resolution_state(&reopened),
            ("processing".into(), "delete_started".into())
        );
        expire_resolution_lease(&reopened);
        assert_eq!(
            reopened.recover_expired_late_delete_resolutions().unwrap(),
            1
        );
    }
}
