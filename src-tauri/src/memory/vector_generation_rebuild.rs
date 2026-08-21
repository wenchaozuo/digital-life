//! Private D9D3-C persisted snapshot and bulk-build phase.
//!
//! This is an internal phase, not a production runner or IPC command.  The
//! caller must lend the already-held fenced composition guard to this
//! function. C never acquires or releases that guard around a live job, so a
//! future full pipeline can keep the same guard across C and later phases.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    embedding::{EmbeddingErrorCode, EmbeddingPurpose, EmbeddingRequest, EmbeddingRetrySafety},
    memory::{
        existing_generation_binding::{
            compute_canonical_generation_descriptor, verify_provider_facts,
            D9D2_GENERATION_DESCRIPTOR_VERSION,
        },
        vector_sync_stage_runtime::FencedVectorSyncCompositionGuard,
    },
    model::{
        profile::ModelProfileRepository,
        runtime::{ModelRuntimeService, ResolvedEmbeddingProvider},
        transport::url_policy::validate_and_normalize_url,
    },
    secrets::SecretStore,
    storage::{
        GenerationAuthorityCommitClassification, GenerationAuthorityRegistration,
        GenerationRebuildCatchupItemRecord, GenerationRebuildFinalizeOutcome,
        GenerationRebuildItemRecord, GenerationRebuildJobRecord, GenerationRebuildLease,
        GenerationRebuildPromotionCommitClassification, LateDeleteRuntimeLease, StorageError,
        StorageService,
    },
    vector_store::{
        GenerationVectorRecord, LanceDbVectorStore, LanceDbVectorStoreRegistry,
        VectorGenerationContext, VectorGenerationId, VectorMetadataSample, VectorStore,
    },
};

static C_ID_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static C_STORE_CREATE_CALLS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static C_VECTOR_UPSERT_CALLS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static C_VECTOR_METADATA_READ_CALLS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
static C_AFTER_SNAPSHOT_HOOK: std::sync::Mutex<
    Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
> = std::sync::Mutex::new(None);

#[cfg(test)]
static D_BEFORE_PROMOTION_HOOK: std::sync::Mutex<
    Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
> = std::sync::Mutex::new(None);

#[cfg(test)]
pub(super) fn set_c_after_snapshot_hook_for_test(
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
) {
    *C_AFTER_SNAPSHOT_HOOK.lock().unwrap() = Some((entered, release));
}

#[cfg(test)]
pub(super) fn set_d_before_promotion_hook_for_test(
    entered: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
) {
    *D_BEFORE_PROMOTION_HOOK.lock().unwrap() = Some((entered, release));
}

#[cfg(test)]
fn wait_for_c_after_snapshot_hook() {
    if let Some((entered, release)) = C_AFTER_SNAPSHOT_HOOK.lock().unwrap().take() {
        let _ = entered.send(());
        let _ = release.recv_timeout(std::time::Duration::from_secs(30));
    }
}

#[cfg(test)]
fn wait_for_d_before_promotion_hook() {
    if let Some((entered, release)) = D_BEFORE_PROMOTION_HOOK.lock().unwrap().take() {
        let _ = entered.send(());
        let _ = release.recv_timeout(std::time::Duration::from_secs(30));
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GenerationRebuildCHandoff {
    pub(crate) job_id: String,
    pub(crate) generation_id: String,
    pub(crate) snapshot_sequence: i64,
    pub(crate) snapshot_item_count: i64,
    pub(crate) applied_item_count: i64,
    pub(crate) status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GenerationRebuildCError {
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) recoverable: bool,
}

impl GenerationRebuildCError {
    fn new(code: impl Into<String>, message: impl Into<String>, recoverable: bool) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            recoverable,
        }
    }

    pub(crate) fn storage(error: StorageError) -> Self {
        Self::new(error.code, error.message, error.recoverable)
    }

    fn conflict(message: &'static str) -> Self {
        Self::new("D9D3_C_CONFLICT", message, true)
    }

    fn target_changed() -> Self {
        Self::new(
            "GENERATION_REBUILD_CATCHUP_TARGET_CHANGED",
            "The catch-up target changed before external I/O; the newer mutation will be materialized.",
            true,
        )
    }

    fn invalid(message: &'static str) -> Self {
        Self::new("D9D3_C_INVALID", message, false)
    }

    pub(crate) fn failed(message: &'static str) -> Self {
        Self::new("D9D3_C_FAILED", message, false)
    }

    fn unknown() -> Self {
        Self::new(
            "GENERATION_REBUILD_PROVIDER_RESULT_UNKNOWN",
            "The rebuild stopped because an external result may have been applied.",
            true,
        )
    }

    /// A promotion commit-result-unknown world that the exact classifier judged
    /// RecoveryRequired.  This is a deliberately distinct, sealed internal
    /// classification: the outer lifecycle owner must NOT run the ordinary
    /// failed-generation compensation or derive safety from `job.status` alone;
    /// it must re-read the durable promotion state and reclassify exactly.
    pub(crate) fn promotion_recovery_required(message: &'static str) -> Self {
        Self::new(
            "GENERATION_REBUILD_PROMOTION_RECOVERY_REQUIRED",
            message,
            false,
        )
    }

    fn cancelled() -> Self {
        Self::new(
            "GENERATION_REBUILD_CANCELLED",
            "The persisted generation rebuild was cancelled.",
            true,
        )
    }
}

/// Exact completion authority for a persisted `completed` job.
///
/// `job.status = 'completed'` is NOT completion authority by itself.  The
/// promotion identity (a non-empty `promotion_operation_id` and a valid
/// `promotion_sequence`) must exist and the exact durable postimage classifier
/// must return `Committed`.  Anything else — missing or invalid promotion
/// identity, `NotCommitted` on an already-completed row, `RecoveryRequired`,
/// or a classifier read failure — is a fail-closed `RecoveryRequired`, never a
/// success.  `caught_up_sequence` is never substituted for a missing
/// `promotion_sequence` on a completed job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CompletedRebuildClassification {
    Committed,
    RecoveryRequired,
}

pub(crate) fn classify_completed_generation_rebuild(
    storage: &StorageService,
    job: &GenerationRebuildJobRecord,
) -> Result<CompletedRebuildClassification, StorageError> {
    if job.status != "completed" {
        return Ok(CompletedRebuildClassification::RecoveryRequired);
    }
    let Some(promotion_operation_id) = job.promotion_operation_id.as_deref() else {
        return Ok(CompletedRebuildClassification::RecoveryRequired);
    };
    let Some(promotion_sequence) = job.promotion_sequence else {
        return Ok(CompletedRebuildClassification::RecoveryRequired);
    };
    if promotion_operation_id.trim().is_empty() || promotion_sequence < 0 {
        return Ok(CompletedRebuildClassification::RecoveryRequired);
    }
    match storage.classify_generation_rebuild_promotion_commit(
        &job.job_id,
        promotion_operation_id,
        promotion_sequence,
    ) {
        Ok(GenerationRebuildPromotionCommitClassification::Committed) => {
            Ok(CompletedRebuildClassification::Committed)
        }
        // `NotCommitted` on a persisted completed row is itself inconsistent
        // (a completed job is never retried), so it collapses to fail-closed.
        Ok(
            GenerationRebuildPromotionCommitClassification::RecoveryRequired
            | GenerationRebuildPromotionCommitClassification::NotCommitted,
        )
        | Err(_) => Ok(CompletedRebuildClassification::RecoveryRequired),
    }
}

/// Runs the C phase while the caller-owned composition guard remains held.
///
/// The function is deliberately `pub(crate)` and has no Tauri command.  It is
/// the handoff point for the later full-pipeline orchestrator.
pub(crate) async fn run_generation_rebuild_c<'a, R, S>(
    storage: &'a StorageService,
    runtime: &'a ModelRuntimeService<'a, R, S>,
    registry: &'a LanceDbVectorStoreRegistry,
    request_id: &str,
    lease_owner: &str,
    _composition_guard: &FencedVectorSyncCompositionGuard<'_>,
) -> Result<GenerationRebuildCHandoff, GenerationRebuildCError>
where
    R: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    validate_control_input(request_id, lease_owner)?;

    let mut job = if let Some(job) = storage
        .load_generation_rebuild_job_by_request(request_id)
        .map_err(GenerationRebuildCError::storage)?
    {
        job
    } else {
        if storage
            .load_nonterminal_generation_rebuild_job()
            .map_err(GenerationRebuildCError::storage)?
            .is_some()
        {
            return Err(GenerationRebuildCError::conflict(
                "Another persisted generation rebuild is already nonterminal.",
            ));
        }
        register_new_job(storage, runtime, request_id).map_err(GenerationRebuildCError::storage)?
    };

    if matches!(job.status.as_str(), "catching_up" | "verifying" | "ready") {
        return handoff_from_job(&job);
    }
    if matches!(job.status.as_str(), "failed" | "cancelled" | "completed") {
        return Err(GenerationRebuildCError::failed(
            "The persisted generation rebuild is already terminal.",
        ));
    }
    let mut lease = storage
        .acquire_generation_rebuild_job_lease(&job.job_id, lease_owner)
        .map_err(GenerationRebuildCError::storage)?
        .ok_or_else(|| {
            GenerationRebuildCError::conflict("The persisted generation rebuild lease is held.")
        })?;

    if cancel_if_requested(storage, &job, &lease)? {
        return Err(GenerationRebuildCError::cancelled());
    }

    let context = generation_context(&job)?;
    let store = ensure_generation_store(storage, registry, &job, &lease, &context).await?;

    if cancel_if_requested(storage, &job, &lease)? {
        return Err(GenerationRebuildCError::cancelled());
    }

    if job.snapshot_sequence.is_none() {
        storage
            .snapshot_generation_rebuild(&job.job_id, &lease)
            .map_err(GenerationRebuildCError::storage)?;
        #[cfg(test)]
        wait_for_c_after_snapshot_hook();
    }

    loop {
        job = storage
            .load_generation_rebuild_job(&job.job_id)
            .map_err(GenerationRebuildCError::storage)?;
        if matches!(job.status.as_str(), "catching_up" | "verifying" | "ready") {
            return handoff_from_job(&job);
        }
        if job.status != "bulk_building" {
            return Err(GenerationRebuildCError::conflict(
                "The persisted generation rebuild is not in bulk-build state.",
            ));
        }
        if cancel_if_requested(storage, &job, &lease)? {
            return Err(GenerationRebuildCError::cancelled());
        }

        lease = storage
            .acquire_generation_rebuild_job_lease(&job.job_id, lease_owner)
            .map_err(GenerationRebuildCError::storage)?
            .ok_or_else(|| {
                GenerationRebuildCError::conflict("The persisted generation rebuild lease expired.")
            })?;
        let Some(item) = storage
            .reserve_next_generation_rebuild_item(&job.job_id, &lease)
            .map_err(GenerationRebuildCError::storage)?
        else {
            if cancel_if_requested(storage, &job, &lease)? {
                return Err(GenerationRebuildCError::cancelled());
            }
            storage
                .finish_generation_rebuild_c_handoff(&job.job_id, &lease)
                .map_err(GenerationRebuildCError::storage)?;
            let completed = storage
                .load_generation_rebuild_job(&job.job_id)
                .map_err(GenerationRebuildCError::storage)?;
            return handoff_from_job(&completed);
        };

        process_item(
            storage,
            runtime,
            &store,
            &context,
            &job,
            &item,
            &mut lease,
            lease_owner,
        )
        .await?;
    }
}

/// Shared D-layer resolution for an observed `completed` job: only an exact
/// Committed classification authorizes `Ok(job)`; a mixed/invalid/read-failed
/// world becomes the sealed `GENERATION_REBUILD_PROMOTION_RECOVERY_REQUIRED`
/// classification so the full lifecycle owner runs the fail-closed recovery
/// path instead of returning success from a `completed` row alone.
fn completed_d_outcome(
    storage: &StorageService,
    job: GenerationRebuildJobRecord,
) -> Result<GenerationRebuildJobRecord, GenerationRebuildCError> {
    match classify_completed_generation_rebuild(storage, &job) {
        Ok(CompletedRebuildClassification::Committed) => Ok(job),
        Ok(CompletedRebuildClassification::RecoveryRequired) => {
            Err(GenerationRebuildCError::promotion_recovery_required(
                "A persisted completed rebuild is not an exact committed promotion.",
            ))
        }
        Err(error) => Err(GenerationRebuildCError::storage(error)),
    }
}

/// Runs D under the guard already acquired by the full lifecycle owner.  The
/// catch-up table, not the C snapshot table, is the durable authority for any
/// post-snapshot attempt.
pub(crate) async fn run_generation_rebuild_d<'a, R, S>(
    storage: &'a StorageService,
    runtime: &'a ModelRuntimeService<'a, R, S>,
    registry: &'a LanceDbVectorStoreRegistry,
    handoff: &GenerationRebuildCHandoff,
    lease_owner: &str,
    deadline: std::time::Instant,
    _composition_guard: &FencedVectorSyncCompositionGuard<'_>,
) -> Result<GenerationRebuildJobRecord, GenerationRebuildCError>
where
    R: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    let mut job = storage
        .load_generation_rebuild_job(&handoff.job_id)
        .map_err(GenerationRebuildCError::storage)?;
    if job.status == "completed" {
        return completed_d_outcome(storage, job);
    }
    if !matches!(job.status.as_str(), "catching_up" | "verifying" | "ready") {
        return Err(GenerationRebuildCError::conflict(
            "The persisted rebuild is not catch-up or promotion eligible.",
        ));
    }
    let mut lease = storage
        .acquire_generation_rebuild_job_lease(&job.job_id, lease_owner)
        .map_err(GenerationRebuildCError::storage)?
        .ok_or_else(|| {
            GenerationRebuildCError::conflict("The persisted generation rebuild lease is held.")
        })?;
    let context = generation_context(&job)?;
    let store = ensure_generation_store(storage, registry, &job, &lease, &context).await?;
    let late_delete_owner = format!("generation-rebuild-late-delete-{}", job.job_id);
    let mut late_delete_lease: Option<LateDeleteRuntimeLease> = None;
    let promotion_operation_id = next_identity("generation-promotion");

    loop {
        job = storage
            .load_generation_rebuild_job(&handoff.job_id)
            .map_err(GenerationRebuildCError::storage)?;
        if job.status == "completed" {
            // The loop may observe `completed` right after a promotion COMMIT
            // succeeded while its result had not yet been observed; only an
            // exact Committed classification permits returning the job.
            return completed_d_outcome(storage, job);
        }
        if std::time::Instant::now() >= deadline {
            storage
                .fail_generation_rebuild(
                    &job.job_id,
                    &lease,
                    "GENERATION_REBUILD_DEADLINE_ELAPSED",
                    job.candidate_authority_epoch,
                )
                .map_err(GenerationRebuildCError::storage)?;
            return Err(GenerationRebuildCError::failed(
                "The generation rebuild deadline elapsed at a safe boundary.",
            ));
        }
        if is_cancel_requested(storage, &job.job_id)? {
            storage
                .cancel_generation_rebuild(&job.job_id, &lease, job.candidate_authority_epoch)
                .map_err(GenerationRebuildCError::storage)?;
            return Err(GenerationRebuildCError::cancelled());
        }
        lease = renew_generation_rebuild_lease(storage, &job.job_id, lease_owner)?;
        if job.status == "catching_up" {
            let target = storage
                .generation_rebuild_mutation_clock()
                .map_err(GenerationRebuildCError::storage)?;
            if let Err(error) =
                storage.materialize_generation_rebuild_catchup(&job.job_id, &lease, target)
            {
                if error.code == "GENERATION_REBUILD_CATCHUP_RESULT_UNKNOWN" {
                    let error_code = error.code.clone();
                    storage
                        .fail_generation_rebuild(
                            &job.job_id,
                            &lease,
                            &error_code,
                            job.candidate_authority_epoch,
                        )
                        .map_err(GenerationRebuildCError::storage)?;
                    return Err(GenerationRebuildCError::storage(error));
                }
                return Err(GenerationRebuildCError::storage(error));
            }
            let mut transient = false;
            while let Some(item) = storage
                .reserve_next_generation_rebuild_catchup_item(&job.job_id, &lease)
                .map_err(GenerationRebuildCError::storage)?
            {
                match process_catchup_item(
                    storage,
                    runtime,
                    &store,
                    &context,
                    &job,
                    &item,
                    &mut lease,
                    lease_owner,
                    deadline,
                )
                .await
                {
                    Ok(()) => {}
                    Err(error) if error.recoverable => {
                        let current = storage
                            .load_generation_rebuild_job(&job.job_id)
                            .map_err(GenerationRebuildCError::storage)?;
                        if current.status == "failed" || current.status == "cancelled" {
                            return Err(error);
                        }
                        transient = true;
                        break;
                    }
                    Err(error) => {
                        let current = storage
                            .load_generation_rebuild_job(&job.job_id)
                            .map_err(GenerationRebuildCError::storage)?;
                        if matches!(
                            current.status.as_str(),
                            "catching_up" | "verifying" | "ready"
                        ) {
                            storage
                                .fail_generation_rebuild(
                                    &job.job_id,
                                    &lease,
                                    &error.code,
                                    current.candidate_authority_epoch,
                                )
                                .map_err(GenerationRebuildCError::storage)?;
                        }
                        return Err(error);
                    }
                }
            }
            if transient {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                continue;
            }
            assert_catchup_payload_lifecycle(storage, &job.job_id)?;
            if !storage
                .advance_generation_rebuild_catchup(&job.job_id, &lease, target)
                .map_err(GenerationRebuildCError::storage)?
            {
                continue;
            }
        }

        job = storage
            .load_generation_rebuild_job(&job.job_id)
            .map_err(GenerationRebuildCError::storage)?;
        if job.status == "verifying" {
            let target = job.caught_up_sequence.ok_or_else(|| {
                GenerationRebuildCError::conflict("The catch-up proof has no target.")
            })?;
            match verify_generation_rebuild_lance_set(storage, &store, &context, &job).await {
                Ok(()) => {}
                Err(error) if error.recoverable => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    continue;
                }
                Err(error) => {
                    storage
                        .fail_generation_rebuild(
                            &job.job_id,
                            &lease,
                            &error.code,
                            job.candidate_authority_epoch,
                        )
                        .map_err(GenerationRebuildCError::storage)?;
                    return Err(error);
                }
            }
            match storage.mark_generation_rebuild_ready(&job.job_id, &lease, target) {
                Ok(()) => {}
                Err(error) if error.code == "GENERATION_REBUILD_MUTATION_RACE" => continue,
                Err(error) => return Err(GenerationRebuildCError::storage(error)),
            }
            continue;
        }
        if job.status != "ready" {
            continue;
        }

        let target = job.caught_up_sequence.ok_or_else(|| {
            GenerationRebuildCError::conflict("The promotion target is unavailable.")
        })?;
        match verify_generation_rebuild_lance_set(storage, &store, &context, &job).await {
            Ok(()) => {}
            Err(error) if error.recoverable => {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                continue;
            }
            Err(error) => {
                storage
                    .fail_generation_rebuild(
                        &job.job_id,
                        &lease,
                        &error.code,
                        job.candidate_authority_epoch,
                    )
                    .map_err(GenerationRebuildCError::storage)?;
                return Err(error);
            }
        }
        if late_delete_lease.is_none() {
            late_delete_lease = storage
                .acquire_late_delete_runtime_lease(&late_delete_owner)
                .map_err(GenerationRebuildCError::storage)?;
            if late_delete_lease.is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            continue;
        }
        let current_late_delete_lease = late_delete_lease
            .as_ref()
            .expect("late-delete lease was acquired above");
        #[cfg(test)]
        wait_for_d_before_promotion_hook();
        match storage.promote_generation_rebuild(
            &job.job_id,
            &lease,
            current_late_delete_lease,
            target,
            &promotion_operation_id,
        ) {
            Ok(()) => {}
            Err(error) if error.code == "GENERATION_REBUILD_MUTATION_RACE" => {
                let _ = storage.release_late_delete_runtime_lease(current_late_delete_lease);
                late_delete_lease = None;
                continue;
            }
            Err(error) if error.code == "GENERATION_REBUILD_PROMOTION_COMMIT_RESULT_UNKNOWN" => {
                // Test-only seam: after the real promotion COMMIT succeeded but
                // before the exact classification, corrupt one outbox-resolution
                // fact so a mixed world is observed while the job row still says
                // `completed`.
                #[cfg(test)]
                storage
                    .inject_promotion_recovery_corruption_if_armed(&job.job_id)
                    .unwrap();
                match storage
                    .classify_generation_rebuild_promotion_commit(
                        &job.job_id,
                        &promotion_operation_id,
                        target,
                    )
                    .map_err(GenerationRebuildCError::storage)?
                {
                    GenerationRebuildPromotionCommitClassification::Committed => {
                        let completed = storage
                            .load_generation_rebuild_job(&job.job_id)
                            .map_err(GenerationRebuildCError::storage)?;
                        let _ =
                            storage.release_late_delete_runtime_lease(current_late_delete_lease);
                        return Ok(completed);
                    }
                    GenerationRebuildPromotionCommitClassification::NotCommitted => continue,
                    GenerationRebuildPromotionCommitClassification::RecoveryRequired => {
                        // Surface a sealed, unambiguous classification to the
                        // outer lifecycle owner.  The promotion may have actually
                        // committed, so this failure MUST NOT be routed into the
                        // ordinary failed-generation compensation path.
                        return Err(GenerationRebuildCError::promotion_recovery_required(
                            "The generation promotion left a mixed durable world; exact reclassification is required before the composition guard may be released.",
                        ));
                    }
                }
            }
            Err(error) => return Err(GenerationRebuildCError::storage(error)),
        }
        let completed = storage
            .load_generation_rebuild_job(&job.job_id)
            .map_err(GenerationRebuildCError::storage)?;
        let _ = storage.release_late_delete_runtime_lease(current_late_delete_lease);
        return Ok(completed);
    }
}

async fn process_catchup_item<'a, R, S>(
    storage: &'a StorageService,
    runtime: &'a ModelRuntimeService<'a, R, S>,
    store: &std::sync::Arc<LanceDbVectorStore>,
    context: &VectorGenerationContext,
    job: &GenerationRebuildJobRecord,
    item: &GenerationRebuildCatchupItemRecord,
    lease: &mut GenerationRebuildLease,
    _lease_owner: &str,
    deadline: std::time::Instant,
) -> Result<(), GenerationRebuildCError>
where
    R: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    if item.desired_action == "delete" {
        if item.io_phase == "vector_write_started" {
            return recover_catchup_delete(storage, store, context, job, item, lease).await;
        }
        if item.io_phase != "reserved" {
            return Err(GenerationRebuildCError::conflict(
                "The catch-up Delete attempt phase is invalid.",
            ));
        }
        if !storage
            .generation_rebuild_catchup_item_is_current(item)
            .map_err(GenerationRebuildCError::storage)?
        {
            return Err(GenerationRebuildCError::target_changed());
        }
        storage
            .mark_generation_rebuild_catchup_phase(item, lease, "vector_write_started")
            .map_err(GenerationRebuildCError::storage)?;
        if !storage
            .generation_rebuild_catchup_item_is_current(item)
            .map_err(GenerationRebuildCError::storage)?
        {
            storage
                .mark_generation_rebuild_catchup_delete_definitely_not_sent(
                    item,
                    lease,
                    "GENERATION_REBUILD_CATCHUP_TARGET_CHANGED",
                )
                .map_err(GenerationRebuildCError::storage)?;
            return Err(GenerationRebuildCError::target_changed());
        }
        if std::time::Instant::now() >= deadline {
            storage
                .fail_generation_rebuild_after_catchup_unknown(
                    item,
                    lease,
                    "GENERATION_REBUILD_DEADLINE_AFTER_DELETE_RESERVATION",
                    job.candidate_authority_epoch,
                )
                .map_err(GenerationRebuildCError::storage)?;
            return Err(GenerationRebuildCError::unknown());
        }
        let delete_result = store
            .delete_generation_memory(context, &item.life_id, &item.memory_id)
            .await;
        return match delete_result {
            Ok(()) => recover_catchup_delete(storage, store, context, job, item, lease).await,
            Err(_) => recover_catchup_delete(storage, store, context, job, item, lease).await,
        };
    }

    if item.desired_action != "upsert" {
        return Err(GenerationRebuildCError::invalid(
            "The catch-up desired action is invalid.",
        ));
    }
    if item.io_phase == "embedding_started" {
        storage
            .fail_generation_rebuild_after_catchup_unknown(
                item,
                lease,
                "GENERATION_REBUILD_CATCHUP_EMBEDDING_RESULT_UNKNOWN",
                job.candidate_authority_epoch,
            )
            .map_err(GenerationRebuildCError::storage)?;
        return Err(GenerationRebuildCError::unknown());
    }
    if item.io_phase == "vector_write_started" {
        return recover_catchup_upsert(storage, store, context, job, item, lease).await;
    }
    if item.io_phase != "reserved" {
        return Err(GenerationRebuildCError::conflict(
            "The catch-up Upsert attempt phase is invalid.",
        ));
    }
    let document = item.canonical_document.as_deref().ok_or_else(|| {
        GenerationRebuildCError::conflict("The catch-up Upsert document is unavailable.")
    })?;
    if !storage
        .generation_rebuild_catchup_item_is_current(item)
        .map_err(GenerationRebuildCError::storage)?
    {
        return Err(GenerationRebuildCError::target_changed());
    }
    storage
        .mark_generation_rebuild_catchup_phase(item, lease, "embedding_started")
        .map_err(GenerationRebuildCError::storage)?;
    let resolved = match resolve_bound_provider(runtime, job) {
        Ok(resolved) => resolved,
        Err(error) => {
            storage
                .mark_generation_rebuild_catchup_embedding_definitely_not_sent(
                    item,
                    lease,
                    "GENERATION_REBUILD_PROVIDER_RESOLUTION_FAILED",
                )
                .map_err(GenerationRebuildCError::storage)?;
            if !error.recoverable {
                storage
                    .fail_generation_rebuild(
                        &job.job_id,
                        lease,
                        "GENERATION_REBUILD_PROVIDER_RESOLUTION_FAILED",
                        job.candidate_authority_epoch,
                    )
                    .map_err(GenerationRebuildCError::storage)?;
            }
            return Err(error);
        }
    };
    if !storage
        .generation_rebuild_catchup_item_is_current(item)
        .map_err(GenerationRebuildCError::storage)?
    {
        storage
            .mark_generation_rebuild_catchup_embedding_definitely_not_sent(
                item,
                lease,
                "GENERATION_REBUILD_CATCHUP_TARGET_CHANGED",
            )
            .map_err(GenerationRebuildCError::storage)?;
        return Err(GenerationRebuildCError::target_changed());
    }
    let embedding = resolved
        .provider()
        .embed(EmbeddingRequest {
            texts: vec![document.to_owned()],
            purpose: EmbeddingPurpose::Document,
        })
        .await;
    drop(resolved);
    let batch = match embedding {
        Ok(batch) => batch,
        Err(error) => return handle_catchup_embedding_error(storage, job, item, lease, error),
    };
    if batch.len() != 1 || batch.dimension() != job.dimension {
        storage
            .mark_generation_rebuild_catchup_embedding_response_failure(
                item,
                lease,
                "GENERATION_REBUILD_CATCHUP_EMBEDDING_DIMENSION_MISMATCH",
            )
            .map_err(GenerationRebuildCError::storage)?;
        storage
            .fail_generation_rebuild(
                &job.job_id,
                lease,
                "GENERATION_REBUILD_CATCHUP_EMBEDDING_DIMENSION_MISMATCH",
                job.candidate_authority_epoch,
            )
            .map_err(GenerationRebuildCError::storage)?;
        return Err(GenerationRebuildCError::failed(
            "The catch-up embedding dimension is invalid.",
        ));
    }
    if std::time::Instant::now() >= deadline || is_cancel_requested(storage, &job.job_id)? {
        storage
            .mark_generation_rebuild_catchup_embedding_response_failure(
                item,
                lease,
                "GENERATION_REBUILD_CATCHUP_CANCELLED_BEFORE_VECTOR_WRITE",
            )
            .map_err(GenerationRebuildCError::storage)?;
        let current = storage
            .load_generation_rebuild_job(&job.job_id)
            .map_err(GenerationRebuildCError::storage)?;
        storage
            .cancel_generation_rebuild(&job.job_id, lease, current.candidate_authority_epoch)
            .map_err(GenerationRebuildCError::storage)?;
        return Err(GenerationRebuildCError::cancelled());
    }
    let vector = batch
        .into_vectors()
        .into_iter()
        .next()
        .ok_or_else(|| {
            GenerationRebuildCError::failed("The catch-up embedding response is empty.")
        })?
        .into_values();
    let record = GenerationVectorRecord::try_new(
        context.generation_id().clone(),
        item.life_id.clone(),
        item.memory_id.clone(),
        item.target_revision.ok_or_else(|| {
            GenerationRebuildCError::conflict("The catch-up revision is unavailable.")
        })?,
        item.target_content_hash.clone().ok_or_else(|| {
            GenerationRebuildCError::conflict("The catch-up hash is unavailable.")
        })?,
        context.descriptor_hash().to_owned(),
        vector,
    )
    .map_err(|_| GenerationRebuildCError::failed("The catch-up vector is invalid."))?;
    storage
        .mark_generation_rebuild_catchup_phase(item, lease, "vector_write_started")
        .map_err(GenerationRebuildCError::storage)?;
    match store.upsert_generation(context, record).await {
        Ok(()) => recover_catchup_upsert(storage, store, context, job, item, lease).await,
        Err(_) => recover_catchup_upsert(storage, store, context, job, item, lease).await,
    }
}

async fn recover_catchup_delete(
    storage: &StorageService,
    store: &std::sync::Arc<LanceDbVectorStore>,
    context: &VectorGenerationContext,
    job: &GenerationRebuildJobRecord,
    item: &GenerationRebuildCatchupItemRecord,
    lease: &GenerationRebuildLease,
) -> Result<(), GenerationRebuildCError> {
    let metadata = match store
        .get_generation_metadata(context, &item.life_id, &item.memory_id)
        .await
    {
        Ok(metadata) => metadata,
        Err(_) => {
            storage
                .fail_generation_rebuild_after_catchup_unknown(
                    item,
                    lease,
                    "GENERATION_REBUILD_CATCHUP_DELETE_RESULT_UNKNOWN",
                    job.candidate_authority_epoch,
                )
                .map_err(GenerationRebuildCError::storage)?;
            return Err(GenerationRebuildCError::unknown());
        }
    };
    if metadata.is_some() {
        storage
            .fail_generation_rebuild_after_catchup_unknown(
                item,
                lease,
                "GENERATION_REBUILD_CATCHUP_DELETE_REMAINS_PRESENT",
                job.candidate_authority_epoch,
            )
            .map_err(GenerationRebuildCError::storage)?;
        return Err(GenerationRebuildCError::unknown());
    }
    storage
        .write_generation_rebuild_catchup_metadata(job, item, lease)
        .map_err(GenerationRebuildCError::storage)?;
    storage
        .finalize_generation_rebuild_catchup_item(job, item, lease)
        .map_err(GenerationRebuildCError::storage)?;
    Ok(())
}

async fn recover_catchup_upsert(
    storage: &StorageService,
    store: &std::sync::Arc<LanceDbVectorStore>,
    context: &VectorGenerationContext,
    job: &GenerationRebuildJobRecord,
    item: &GenerationRebuildCatchupItemRecord,
    lease: &GenerationRebuildLease,
) -> Result<(), GenerationRebuildCError> {
    let metadata = store
        .get_generation_metadata(context, &item.life_id, &item.memory_id)
        .await;
    match metadata {
        Ok(Some(sample)) if catchup_metadata_matches(&sample, job, item, context) => {
            storage
                .write_generation_rebuild_catchup_metadata(job, item, lease)
                .map_err(GenerationRebuildCError::storage)?;
            storage
                .finalize_generation_rebuild_catchup_item(job, item, lease)
                .map_err(GenerationRebuildCError::storage)?;
            Ok(())
        }
        Ok(Some(_)) | Ok(None) | Err(_) => {
            storage
                .fail_generation_rebuild_after_catchup_unknown(
                    item,
                    lease,
                    "GENERATION_REBUILD_CATCHUP_VECTOR_WRITE_RESULT_UNKNOWN",
                    job.candidate_authority_epoch,
                )
                .map_err(GenerationRebuildCError::storage)?;
            Err(GenerationRebuildCError::unknown())
        }
    }
}

fn handle_catchup_embedding_error(
    storage: &StorageService,
    job: &GenerationRebuildJobRecord,
    item: &GenerationRebuildCatchupItemRecord,
    lease: &GenerationRebuildLease,
    error: crate::embedding::EmbeddingError,
) -> Result<(), GenerationRebuildCError> {
    let code = embedding_error_code(error.code());
    match error.retry_safety() {
        EmbeddingRetrySafety::DefinitelyNotSent => {
            storage
                .mark_generation_rebuild_catchup_embedding_definitely_not_sent(item, lease, code)
                .map_err(GenerationRebuildCError::storage)?;
            Err(GenerationRebuildCError::new(
                "GENERATION_REBUILD_PROVIDER_UNAVAILABLE",
                "The catch-up embedding request was definitely not sent.",
                true,
            ))
        }
        EmbeddingRetrySafety::ResponseReceived if error.is_recoverable() => {
            storage
                .mark_generation_rebuild_catchup_embedding_response_failure(item, lease, code)
                .map_err(GenerationRebuildCError::storage)?;
            Err(GenerationRebuildCError::new(
                "GENERATION_REBUILD_PROVIDER_UNAVAILABLE",
                "The catch-up embedding provider returned a recoverable result.",
                true,
            ))
        }
        EmbeddingRetrySafety::ResponseReceived => {
            storage
                .mark_generation_rebuild_catchup_embedding_response_failure(item, lease, code)
                .map_err(GenerationRebuildCError::storage)?;
            storage
                .fail_generation_rebuild(&job.job_id, lease, code, job.candidate_authority_epoch)
                .map_err(GenerationRebuildCError::storage)?;
            Err(GenerationRebuildCError::failed(
                "The catch-up embedding provider returned a non-recoverable result.",
            ))
        }
        EmbeddingRetrySafety::PossiblySent => {
            storage
                .fail_generation_rebuild_after_catchup_unknown(
                    item,
                    lease,
                    code,
                    job.candidate_authority_epoch,
                )
                .map_err(GenerationRebuildCError::storage)?;
            Err(GenerationRebuildCError::unknown())
        }
    }
}

fn catchup_metadata_matches(
    sample: &VectorMetadataSample,
    job: &GenerationRebuildJobRecord,
    item: &GenerationRebuildCatchupItemRecord,
    context: &VectorGenerationContext,
) -> bool {
    sample.generation_id == context.generation_id().as_str()
        && sample.life_id == item.life_id
        && sample.memory_id == item.memory_id
        && sample.memory_revision == item.target_revision.unwrap_or_default()
        && sample.content_hash == item.target_content_hash.as_deref().unwrap_or_default()
        && sample.descriptor_hash == context.descriptor_hash()
        && sample.dimension == job.dimension
}

async fn verify_generation_rebuild_lance_set(
    storage: &StorageService,
    store: &std::sync::Arc<LanceDbVectorStore>,
    context: &VectorGenerationContext,
    job: &GenerationRebuildJobRecord,
) -> Result<(), GenerationRebuildCError> {
    let expected = storage
        .list_generation_rebuild_generation_items(&job.generation_id)
        .map_err(GenerationRebuildCError::storage)?;
    let actual = store.list_generation_metadata(context).await.map_err(|_| {
        GenerationRebuildCError::new(
            "GENERATION_REBUILD_LANCE_SET_UNAVAILABLE",
            "The candidate Lance set could not be read exactly.",
            true,
        )
    })?;
    let mut expected_map = std::collections::BTreeMap::new();
    for item in expected {
        expected_map.insert(
            (item.life_id, item.memory_id),
            (item.memory_revision, item.content_hash),
        );
    }
    let mut actual_map = std::collections::BTreeMap::new();
    for sample in actual {
        if sample.generation_id != job.generation_id
            || sample.descriptor_hash != job.descriptor_hash
            || sample.dimension != job.dimension
        {
            return Err(GenerationRebuildCError::failed(
                "The candidate Lance set contains incompatible metadata.",
            ));
        }
        if actual_map
            .insert(
                (sample.life_id, sample.memory_id),
                (sample.memory_revision, sample.content_hash),
            )
            .is_some()
        {
            return Err(GenerationRebuildCError::failed(
                "The candidate Lance set contains duplicate metadata identities.",
            ));
        }
    }
    if expected_map != actual_map {
        return Err(GenerationRebuildCError::failed(
            "The candidate Lance set is not the exact SQLite eligible set.",
        ));
    }
    Ok(())
}

fn assert_catchup_payload_lifecycle(
    storage: &StorageService,
    job_id: &str,
) -> Result<(), GenerationRebuildCError> {
    let items = storage
        .list_generation_rebuild_catchup_items(job_id)
        .map_err(GenerationRebuildCError::storage)?;
    for item in items {
        let terminal = matches!(item.state.as_str(), "applied" | "superseded" | "uncertain");
        if terminal && item.canonical_document.is_some() {
            return Err(GenerationRebuildCError::failed(
                "A terminal catch-up item retained sensitive canonical payload.",
            ));
        }
        if item.desired_action == "delete" && item.canonical_document.is_some() {
            return Err(GenerationRebuildCError::failed(
                "A catch-up Delete retained a canonical payload.",
            ));
        }
    }
    Ok(())
}

fn renew_generation_rebuild_lease(
    storage: &StorageService,
    job_id: &str,
    owner: &str,
) -> Result<GenerationRebuildLease, GenerationRebuildCError> {
    storage
        .acquire_generation_rebuild_job_lease(job_id, owner)
        .map_err(GenerationRebuildCError::storage)?
        .ok_or_else(|| {
            GenerationRebuildCError::conflict("The persisted generation rebuild lease expired.")
        })
}

fn validate_control_input(
    request_id: &str,
    lease_owner: &str,
) -> Result<(), GenerationRebuildCError> {
    let valid = |value: &str| {
        !value.trim().is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
    };
    if !valid(request_id) || !valid(lease_owner) {
        return Err(GenerationRebuildCError::invalid(
            "The rebuild request identity is invalid.",
        ));
    }
    Ok(())
}

fn register_new_job<R, S>(
    storage: &StorageService,
    runtime: &ModelRuntimeService<'_, R, S>,
    request_id: &str,
) -> Result<GenerationRebuildJobRecord, StorageError>
where
    R: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    let resolved = runtime.resolve_active_embedding_provider().map_err(|_| {
        StorageError::new(
            "D9D3_C_PROVIDER_UNAVAILABLE",
            "The active embedding provider is unavailable.",
            true,
        )
    })?;
    let dimension =
        verify_provider_facts(&resolved.profile, resolved.provider()).map_err(|_| {
            StorageError::new(
                "D9D3_C_PROVIDER_MISMATCH",
                "The active embedding provider facts are incompatible.",
                false,
            )
        })?;
    let target = validate_and_normalize_url(&resolved.profile.base_url).map_err(|_| {
        StorageError::new(
            "D9D3_C_PROVIDER_MISMATCH",
            "The active embedding transport target is invalid.",
            false,
        )
    })?;
    let descriptor = compute_canonical_generation_descriptor(
        &resolved.profile.provider_kind,
        &resolved.profile.profile_id,
        &target,
        &resolved.profile.model_name,
        dimension,
    )
    .map_err(|_| {
        StorageError::new(
            "D9D3_C_PROVIDER_MISMATCH",
            "The active embedding descriptor is invalid.",
            false,
        )
    })?;
    let profile_id = resolved.profile.profile_id.clone();
    drop(resolved);

    let generation_id = next_identity("generation");
    let create_operation_id = next_identity("generation-create");
    let job_id = next_identity("generation-rebuild-job");
    let registration = GenerationAuthorityRegistration {
        generation_id: &generation_id,
        descriptor_hash: &descriptor,
        dimension,
        embedding_profile_id: &profile_id,
        create_operation_id: &create_operation_id,
        job_id: &job_id,
        request_id,
    };

    let committed = match storage.register_generation_lifecycle_authority(registration.clone()) {
        Ok(()) => true,
        Err(error) if error.code == "GENERATION_AUTHORITY_COMMIT_RESULT_UNKNOWN" => {
            match storage.classify_generation_registration_commit(registration.clone())? {
                GenerationAuthorityCommitClassification::Committed => true,
                GenerationAuthorityCommitClassification::NotCommitted => {
                    storage.register_generation_lifecycle_authority(registration)?;
                    true
                }
                GenerationAuthorityCommitClassification::RecoveryRequired => {
                    return Err(StorageError::new(
                        "GENERATION_AUTHORITY_RECOVERY_REQUIRED",
                        "Generation registration requires explicit recovery.",
                        true,
                    ));
                }
            }
        }
        Err(error) => return Err(error),
    };
    if !committed {
        return Err(StorageError::new(
            "D9D3_C_REGISTRATION_FAILED",
            "Generation registration did not commit.",
            true,
        ));
    }
    storage
        .load_generation_rebuild_job_by_request(request_id)?
        .ok_or_else(|| {
            StorageError::new(
                "D9D3_C_REGISTRATION_FAILED",
                "The registered rebuild job could not be read.",
                false,
            )
        })
}

fn next_identity(prefix: &str) -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or_default();
    let sequence = C_ID_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{millis:032x}-{sequence:016x}")
}

fn generation_context(
    job: &GenerationRebuildJobRecord,
) -> Result<VectorGenerationContext, GenerationRebuildCError> {
    if job.generation_state != "building"
        || job.candidate_authority_epoch < 1
        || job.generation_authority_epoch != job.candidate_authority_epoch
        || job.descriptor_version != D9D2_GENERATION_DESCRIPTOR_VERSION
        || job.descriptor_hash.is_empty()
        || job.dimension == 0
        || job.create_operation_id.is_empty()
    {
        return Err(GenerationRebuildCError::conflict(
            "The persisted generation authority binding is not buildable.",
        ));
    }
    let generation_id = VectorGenerationId::parse(&job.generation_id).map_err(|_| {
        GenerationRebuildCError::invalid("The persisted generation identity is invalid.")
    })?;
    VectorGenerationContext::new(generation_id, job.descriptor_hash.clone(), job.dimension).map_err(
        |_| GenerationRebuildCError::invalid("The persisted generation context is invalid."),
    )
}

async fn ensure_generation_store(
    storage: &StorageService,
    registry: &LanceDbVectorStoreRegistry,
    job: &GenerationRebuildJobRecord,
    lease: &GenerationRebuildLease,
    context: &VectorGenerationContext,
) -> Result<std::sync::Arc<LanceDbVectorStore>, GenerationRebuildCError> {
    let witness = storage
        .load_generation_store_witness(&job.generation_id)
        .map_err(GenerationRebuildCError::storage)?;
    if witness.create_operation_id.as_deref() != Some(job.create_operation_id.as_str()) {
        return Err(GenerationRebuildCError::conflict(
            "The persisted store witness is bound to another create operation.",
        ));
    }
    let data_root = storage
        .active_data_root()
        .map_err(GenerationRebuildCError::storage)?;
    match witness.state.as_str() {
        "ready" => {
            let store = registry
                .existing_generation_store(&data_root, context.generation_id())
                .await
                .map_err(|_| {
                    GenerationRebuildCError::new(
                        "D9D3_C_STORE_UNAVAILABLE",
                        "The persisted generation store is unavailable.",
                        true,
                    )
                })?
                .ok_or_else(|| {
                    GenerationRebuildCError::new(
                        "D9D3_C_STORE_MISSING",
                        "The ready generation store is missing.",
                        false,
                    )
                })?;
            store.health_check_generation(context).await.map_err(|_| {
                GenerationRebuildCError::new(
                    "D9D3_C_STORE_CORRUPT",
                    "The ready generation store failed its exact health check.",
                    false,
                )
            })?;
            Ok(store)
        }
        "create_started" | "uncertain" | "absent" => {
            let existing = registry
                .existing_generation_store(&data_root, context.generation_id())
                .await
                .map_err(|_| {
                    GenerationRebuildCError::new(
                        "D9D3_C_STORE_UNAVAILABLE",
                        "The persisted generation store is unavailable.",
                        true,
                    )
                })?;
            let store = if let Some(store) = existing {
                store.health_check_generation(context).await.map_err(|_| {
                    GenerationRebuildCError::new(
                        "D9D3_C_STORE_CORRUPT",
                        "The existing generation store failed its exact health check.",
                        false,
                    )
                })?;
                store
            } else {
                let store = registry
                    .generation_store_for_write(&data_root, context.generation_id())
                    .await
                    .map_err(|_| {
                        let _ = mark_store_witness_uncertain(
                            storage,
                            job,
                            lease,
                            "GENERATION_STORE_CREATE_RESULT_UNKNOWN",
                        );
                        GenerationRebuildCError::new(
                            "D9D3_C_STORE_CREATE_FAILED",
                            "The persisted generation store could not be opened.",
                            true,
                        )
                    })?;
                #[cfg(test)]
                C_STORE_CREATE_CALLS.fetch_add(1, Ordering::SeqCst);
                if store.create_generation(context).await.is_err() {
                    mark_store_witness_uncertain(
                        storage,
                        job,
                        lease,
                        "GENERATION_STORE_CREATE_RESULT_UNKNOWN",
                    )?;
                    return Err(GenerationRebuildCError::new(
                        "D9D3_C_STORE_CREATE_FAILED",
                        "The persisted generation store schema could not be established.",
                        true,
                    ));
                }
                if store.health_check_generation(context).await.is_err() {
                    mark_store_witness_uncertain(
                        storage,
                        job,
                        lease,
                        "GENERATION_STORE_HEALTH_CHECK_FAILED",
                    )?;
                    return Err(GenerationRebuildCError::new(
                        "D9D3_C_STORE_CORRUPT",
                        "The generation store failed its exact health check.",
                        false,
                    ));
                }
                store
            };
            storage
                .mark_generation_store_witness_ready(
                    &job.job_id,
                    lease,
                    &job.generation_id,
                    &job.create_operation_id,
                )
                .map_err(GenerationRebuildCError::storage)?;
            Ok(store)
        }
        "unverified" | "deleted" => Err(GenerationRebuildCError::new(
            "D9D3_C_STORE_WITNESS_UNVERIFIED",
            "The generation store witness is not eligible for C recovery.",
            false,
        )),
        _ => Err(GenerationRebuildCError::invalid(
            "The generation store witness state is invalid.",
        )),
    }
}

fn mark_store_witness_uncertain(
    storage: &StorageService,
    job: &GenerationRebuildJobRecord,
    lease: &GenerationRebuildLease,
    error_code: &str,
) -> Result<(), GenerationRebuildCError> {
    storage
        .mark_generation_store_witness_uncertain(
            &job.job_id,
            lease,
            &job.generation_id,
            &job.create_operation_id,
            error_code,
        )
        .map_err(GenerationRebuildCError::storage)
}

fn cancel_if_requested(
    storage: &StorageService,
    job: &GenerationRebuildJobRecord,
    lease: &GenerationRebuildLease,
) -> Result<bool, GenerationRebuildCError> {
    let current = storage
        .load_generation_rebuild_job(&job.job_id)
        .map_err(GenerationRebuildCError::storage)?;
    if !current.cancel_requested {
        return Ok(false);
    }
    storage
        .cancel_generation_rebuild(&job.job_id, lease, current.candidate_authority_epoch)
        .map_err(GenerationRebuildCError::storage)?;
    Ok(true)
}

fn handoff_from_job(
    job: &GenerationRebuildJobRecord,
) -> Result<GenerationRebuildCHandoff, GenerationRebuildCError> {
    if !matches!(job.status.as_str(), "catching_up" | "verifying" | "ready") {
        return Err(GenerationRebuildCError::conflict(
            "The C phase did not reach its durable catching-up handoff.",
        ));
    }
    Ok(GenerationRebuildCHandoff {
        job_id: job.job_id.clone(),
        generation_id: job.generation_id.clone(),
        snapshot_sequence: job.snapshot_sequence.ok_or_else(|| {
            GenerationRebuildCError::conflict("The C handoff has no snapshot sequence.")
        })?,
        snapshot_item_count: job.snapshot_item_count,
        applied_item_count: job.applied_item_count,
        status: job.status.clone(),
    })
}

async fn process_item<'a, R, S>(
    storage: &'a StorageService,
    runtime: &'a ModelRuntimeService<'a, R, S>,
    store: &std::sync::Arc<LanceDbVectorStore>,
    context: &VectorGenerationContext,
    job: &GenerationRebuildJobRecord,
    item: &GenerationRebuildItemRecord,
    lease: &mut GenerationRebuildLease,
    lease_owner: &str,
) -> Result<(), GenerationRebuildCError>
where
    R: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    if item.state != "processing" {
        return Err(GenerationRebuildCError::conflict(
            "The reserved rebuild item is not processing.",
        ));
    }
    match item.io_phase.as_str() {
        "reserved" => {
            process_reserved_item(
                storage,
                runtime,
                store,
                context,
                job,
                item,
                lease,
                lease_owner,
            )
            .await
        }
        "embedding_started" => {
            storage
                .fail_generation_rebuild_after_unknown(
                    item,
                    lease,
                    "GENERATION_REBUILD_EMBEDDING_RESULT_UNKNOWN",
                    job.candidate_authority_epoch,
                )
                .map_err(GenerationRebuildCError::storage)?;
            Err(GenerationRebuildCError::unknown())
        }
        "vector_write_started" => {
            if is_cancel_requested(storage, &job.job_id)? {
                storage
                    .fail_generation_rebuild_after_unknown(
                        item,
                        lease,
                        "GENERATION_REBUILD_VECTOR_WRITE_RESULT_UNKNOWN",
                        job.candidate_authority_epoch,
                    )
                    .map_err(GenerationRebuildCError::storage)?;
                return Err(GenerationRebuildCError::unknown());
            }
            renew_lease(storage, &job.job_id, lease, lease_owner)?;
            recover_vector_write(storage, store, context, job, item, lease).await
        }
        _ => Err(GenerationRebuildCError::conflict(
            "The persisted rebuild item I/O phase is invalid.",
        )),
    }
}

async fn process_reserved_item<'a, R, S>(
    storage: &'a StorageService,
    runtime: &'a ModelRuntimeService<'a, R, S>,
    store: &std::sync::Arc<LanceDbVectorStore>,
    context: &VectorGenerationContext,
    job: &GenerationRebuildJobRecord,
    item: &GenerationRebuildItemRecord,
    lease: &mut GenerationRebuildLease,
    lease_owner: &str,
) -> Result<(), GenerationRebuildCError>
where
    R: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    let document = item.canonical_document.as_deref().ok_or_else(|| {
        GenerationRebuildCError::conflict("The persisted rebuild item has no canonical document.")
    })?;
    if document.trim().is_empty() {
        return Err(GenerationRebuildCError::invalid(
            "The persisted rebuild document is empty.",
        ));
    }
    storage
        .mark_generation_rebuild_embedding_started(item, lease)
        .map_err(GenerationRebuildCError::storage)?;
    if cancel_if_requested(storage, job, lease)? {
        return Err(GenerationRebuildCError::cancelled());
    }

    let resolved = match resolve_bound_provider(runtime, job) {
        Ok(resolved) => resolved,
        Err(error) => {
            storage
                .mark_generation_rebuild_embedding_definitely_not_sent(
                    item,
                    lease,
                    "GENERATION_REBUILD_PROVIDER_RESOLUTION_FAILED",
                )
                .map_err(GenerationRebuildCError::storage)?;
            if !error.recoverable {
                storage
                    .fail_generation_rebuild(
                        &job.job_id,
                        lease,
                        "GENERATION_REBUILD_PROVIDER_RESOLUTION_FAILED",
                        job.candidate_authority_epoch,
                    )
                    .map_err(GenerationRebuildCError::storage)?;
            }
            return Err(error);
        }
    };
    let embedding_result = resolved
        .provider()
        .embed(EmbeddingRequest {
            texts: vec![document.to_owned()],
            purpose: EmbeddingPurpose::Document,
        })
        .await;
    drop(resolved);

    let batch = match embedding_result {
        Ok(batch) => batch,
        Err(error) => return handle_embedding_error(storage, job, item, lease, error),
    };
    if batch.len() != 1 || batch.dimension() != job.dimension {
        storage
            .mark_generation_rebuild_embedding_response_failure(
                item,
                lease,
                "GENERATION_REBUILD_EMBEDDING_DIMENSION_MISMATCH",
            )
            .map_err(GenerationRebuildCError::storage)?;
        storage
            .fail_generation_rebuild(
                &job.job_id,
                lease,
                "GENERATION_REBUILD_EMBEDDING_DIMENSION_MISMATCH",
                job.candidate_authority_epoch,
            )
            .map_err(GenerationRebuildCError::storage)?;
        return Err(GenerationRebuildCError::failed(
            "The embedding response dimension did not match the immutable binding.",
        ));
    }
    let vector = batch
        .into_vectors()
        .into_iter()
        .next()
        .ok_or_else(|| GenerationRebuildCError::failed("The embedding response was empty."))?
        .into_values();

    if is_cancel_requested(storage, &job.job_id)? {
        storage
            .mark_generation_rebuild_embedding_response_failure(
                item,
                lease,
                "GENERATION_REBUILD_CANCELLED_BEFORE_VECTOR_WRITE",
            )
            .map_err(GenerationRebuildCError::storage)?;
        let current = storage
            .load_generation_rebuild_job(&job.job_id)
            .map_err(GenerationRebuildCError::storage)?;
        storage
            .cancel_generation_rebuild(&job.job_id, lease, current.candidate_authority_epoch)
            .map_err(GenerationRebuildCError::storage)?;
        return Err(GenerationRebuildCError::cancelled());
    }
    renew_lease(storage, &job.job_id, lease, lease_owner)?;
    let record = match GenerationVectorRecord::try_new(
        context.generation_id().clone(),
        item.life_id.clone(),
        item.memory_id.clone(),
        item.memory_revision,
        item.content_hash.clone(),
        context.descriptor_hash().to_owned(),
        vector,
    ) {
        Ok(record) => record,
        Err(_) => {
            storage
                .mark_generation_rebuild_embedding_response_failure(
                    item,
                    lease,
                    "GENERATION_REBUILD_VECTOR_VALIDATION_FAILED",
                )
                .map_err(GenerationRebuildCError::storage)?;
            storage
                .fail_generation_rebuild(
                    &job.job_id,
                    lease,
                    "GENERATION_REBUILD_VECTOR_VALIDATION_FAILED",
                    job.candidate_authority_epoch,
                )
                .map_err(GenerationRebuildCError::storage)?;
            return Err(GenerationRebuildCError::failed(
                "The embedding vector failed generation validation.",
            ));
        }
    };
    storage
        .mark_generation_rebuild_vector_write_started(item, lease)
        .map_err(GenerationRebuildCError::storage)?;
    if is_cancel_requested(storage, &job.job_id)? {
        storage
            .fail_generation_rebuild_after_unknown(
                item,
                lease,
                "GENERATION_REBUILD_CANCELLED_AFTER_VECTOR_WRITE_RESERVATION",
                job.candidate_authority_epoch,
            )
            .map_err(GenerationRebuildCError::storage)?;
        return Err(GenerationRebuildCError::unknown());
    }

    #[cfg(test)]
    C_VECTOR_UPSERT_CALLS.fetch_add(1, Ordering::SeqCst);
    match store.upsert_generation(context, record).await {
        Ok(()) => finalize_item(storage, job, item, lease),
        Err(_) => {
            if is_cancel_requested(storage, &job.job_id)? {
                storage
                    .fail_generation_rebuild_after_unknown(
                        item,
                        lease,
                        "GENERATION_REBUILD_VECTOR_WRITE_RESULT_UNKNOWN",
                        job.candidate_authority_epoch,
                    )
                    .map_err(GenerationRebuildCError::storage)?;
                Err(GenerationRebuildCError::unknown())
            } else {
                recover_vector_write(storage, store, context, job, item, lease).await
            }
        }
    }
}

fn handle_embedding_error(
    storage: &StorageService,
    job: &GenerationRebuildJobRecord,
    item: &GenerationRebuildItemRecord,
    lease: &GenerationRebuildLease,
    error: crate::embedding::EmbeddingError,
) -> Result<(), GenerationRebuildCError> {
    let code = embedding_error_code(error.code());
    match error.retry_safety() {
        EmbeddingRetrySafety::DefinitelyNotSent => storage
            .mark_generation_rebuild_embedding_definitely_not_sent(item, lease, code)
            .map_err(GenerationRebuildCError::storage),
        EmbeddingRetrySafety::ResponseReceived if error.is_recoverable() => storage
            .mark_generation_rebuild_embedding_response_failure(item, lease, code)
            .map_err(GenerationRebuildCError::storage),
        EmbeddingRetrySafety::ResponseReceived => {
            storage
                .mark_generation_rebuild_embedding_response_failure(item, lease, code)
                .map_err(GenerationRebuildCError::storage)?;
            storage
                .fail_generation_rebuild(&job.job_id, lease, code, job.candidate_authority_epoch)
                .map_err(GenerationRebuildCError::storage)?;
            Err(GenerationRebuildCError::failed(
                "The embedding provider returned a non-recoverable result.",
            ))
        }
        EmbeddingRetrySafety::PossiblySent => {
            storage
                .fail_generation_rebuild_after_unknown(
                    item,
                    lease,
                    code,
                    job.candidate_authority_epoch,
                )
                .map_err(GenerationRebuildCError::storage)?;
            Err(GenerationRebuildCError::unknown())
        }
    }
}

fn embedding_error_code(code: EmbeddingErrorCode) -> &'static str {
    match code {
        EmbeddingErrorCode::InvalidRequest => "EMBEDDING_INVALID_REQUEST",
        EmbeddingErrorCode::EmptyText => "EMBEDDING_EMPTY_TEXT",
        EmbeddingErrorCode::BatchLimitExceeded => "EMBEDDING_BATCH_LIMIT",
        EmbeddingErrorCode::TextLimitExceeded => "EMBEDDING_TEXT_LIMIT",
        EmbeddingErrorCode::NetworkError => "EMBEDDING_NETWORK_ERROR",
        EmbeddingErrorCode::AuthenticationFailed => "EMBEDDING_AUTHENTICATION_FAILED",
        EmbeddingErrorCode::RateLimited => "EMBEDDING_RATE_LIMITED",
        EmbeddingErrorCode::RequestTimeout => "EMBEDDING_REQUEST_TIMEOUT",
        EmbeddingErrorCode::InvalidProviderResponse => "EMBEDDING_INVALID_RESPONSE",
        EmbeddingErrorCode::DimensionMismatch => "EMBEDDING_DIMENSION_MISMATCH",
    }
}

fn resolve_bound_provider<'a, R, S>(
    runtime: &'a ModelRuntimeService<'a, R, S>,
    job: &GenerationRebuildJobRecord,
) -> Result<ResolvedEmbeddingProvider<'a>, GenerationRebuildCError>
where
    R: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    if job.descriptor_version != D9D2_GENERATION_DESCRIPTOR_VERSION {
        return Err(GenerationRebuildCError::invalid(
            "The persisted descriptor version is not D9D2_GENERATION_DESCRIPTOR_V1.",
        ));
    }
    let resolved = runtime
        .resolve_embedding_provider(&job.embedding_profile_id)
        .map_err(|_| {
            GenerationRebuildCError::new(
                "D9D3_C_PROVIDER_UNAVAILABLE",
                "The bound embedding provider is unavailable.",
                true,
            )
        })?;
    let dimension =
        verify_provider_facts(&resolved.profile, resolved.provider()).map_err(|_| {
            GenerationRebuildCError::new(
                "D9D3_C_PROVIDER_MISMATCH",
                "The bound embedding provider facts no longer match.",
                false,
            )
        })?;
    let target = validate_and_normalize_url(&resolved.profile.base_url).map_err(|_| {
        GenerationRebuildCError::new(
            "D9D3_C_PROVIDER_MISMATCH",
            "The bound embedding transport target no longer matches.",
            false,
        )
    })?;
    let descriptor = compute_canonical_generation_descriptor(
        &resolved.profile.provider_kind,
        &resolved.profile.profile_id,
        &target,
        &resolved.profile.model_name,
        dimension,
    )
    .map_err(|_| {
        GenerationRebuildCError::new(
            "D9D3_C_PROVIDER_MISMATCH",
            "The bound embedding descriptor could not be recomputed.",
            false,
        )
    })?;
    if dimension != job.dimension || descriptor != job.descriptor_hash {
        return Err(GenerationRebuildCError::new(
            "D9D3_C_PROVIDER_MISMATCH",
            "The bound embedding provider no longer matches the immutable generation.",
            false,
        ));
    }
    Ok(resolved)
}

async fn recover_vector_write(
    storage: &StorageService,
    store: &std::sync::Arc<LanceDbVectorStore>,
    context: &VectorGenerationContext,
    job: &GenerationRebuildJobRecord,
    item: &GenerationRebuildItemRecord,
    lease: &GenerationRebuildLease,
) -> Result<(), GenerationRebuildCError> {
    #[cfg(test)]
    C_VECTOR_METADATA_READ_CALLS.fetch_add(1, Ordering::SeqCst);
    let metadata = store
        .get_generation_metadata(context, &item.life_id, &item.memory_id)
        .await;
    match metadata {
        Ok(Some(sample)) if metadata_matches(&sample, job, item, context) => {
            finalize_item(storage, job, item, lease)
        }
        Ok(Some(_)) | Ok(None) | Err(_) => {
            storage
                .fail_generation_rebuild_after_unknown(
                    item,
                    lease,
                    "GENERATION_REBUILD_VECTOR_WRITE_RESULT_UNKNOWN",
                    job.candidate_authority_epoch,
                )
                .map_err(GenerationRebuildCError::storage)?;
            Err(GenerationRebuildCError::unknown())
        }
    }
}

fn metadata_matches(
    sample: &VectorMetadataSample,
    job: &GenerationRebuildJobRecord,
    item: &GenerationRebuildItemRecord,
    context: &VectorGenerationContext,
) -> bool {
    sample.generation_id == context.generation_id().as_str()
        && sample.life_id == item.life_id
        && sample.memory_id == item.memory_id
        && sample.memory_revision == item.memory_revision
        && sample.content_hash == item.content_hash
        && sample.descriptor_hash == context.descriptor_hash()
        && sample.dimension == job.dimension
}

fn finalize_item(
    storage: &StorageService,
    job: &GenerationRebuildJobRecord,
    item: &GenerationRebuildItemRecord,
    lease: &GenerationRebuildLease,
) -> Result<(), GenerationRebuildCError> {
    match storage
        .finalize_generation_rebuild_item(job, item, lease)
        .map_err(GenerationRebuildCError::storage)?
    {
        GenerationRebuildFinalizeOutcome::Applied
        | GenerationRebuildFinalizeOutcome::AlreadyApplied => Ok(()),
    }
}

fn renew_lease(
    storage: &StorageService,
    job_id: &str,
    lease: &mut GenerationRebuildLease,
    owner: &str,
) -> Result<(), GenerationRebuildCError> {
    *lease = storage
        .acquire_generation_rebuild_job_lease(job_id, owner)
        .map_err(GenerationRebuildCError::storage)?
        .ok_or_else(|| {
            GenerationRebuildCError::conflict("The persisted generation rebuild lease expired.")
        })?;
    Ok(())
}

fn is_cancel_requested(
    storage: &StorageService,
    job_id: &str,
) -> Result<bool, GenerationRebuildCError> {
    Ok(storage
        .load_generation_rebuild_job(job_id)
        .map_err(GenerationRebuildCError::storage)?
        .cancel_requested)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        collections::BTreeSet,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            mpsc::{self, Receiver, Sender},
            Arc, Mutex,
        },
        thread::{self, JoinHandle},
        time::Duration,
    };

    use tempfile::TempDir;
    use tokio::sync::Notify;

    use crate::{
        memory::vector_sync_stage_runtime::{
            arm_promotion_recovery_hide_job_for_test, fail_next_outer_compensation_for_test,
            resolve_generation_rebuild_status, run_fenced_vector_sync_drain,
            run_vector_generation_rebuild, run_vector_generation_rebuild_guarded,
            set_outer_compensation_failure_signal_for_test,
            set_promotion_recovery_entered_signal_for_test,
            set_promotion_recovery_missing_signal_for_test, FencedVectorSyncCompositionGate,
            VectorGenerationRebuildErrorCode,
        },
        model::{
            profile::{
                ActiveModelProfile, CreateModelProfileRequest, DeleteModelProfileResult,
                ModelProfile, ModelProfileError, ModelProfileRepository, ModelProfileService,
                ModelProviderKind, ModelPurpose, SetActiveModelProfileRequest,
            },
            runtime::{ModelRuntimeCoordinator, ModelRuntimeService},
        },
        secrets::{InMemorySecretStore, SecretIdentifier, SecretPurpose, SecretStore, SecretValue},
        storage::{
            arm_promotion_fault_for_test, open_authorized_test_connection,
            GenerationAuthorityRegistration, PromotionFault, StorageService,
        },
        vector_store::{
            LanceDbVectorStore, LanceDbVectorStoreRegistry, VectorGenerationContext,
            VectorGenerationId, VectorStore,
        },
    };

    use super::{set_c_after_snapshot_hook_for_test, set_d_before_promotion_hook_for_test};

    static COUNTER_LOCK: Mutex<()> = Mutex::new(());

    struct TestProfileRepository {
        profile: ModelProfile,
        active: ActiveModelProfile,
        fail_after_first_profile_read: AtomicBool,
        profile_reads: AtomicUsize,
    }

    impl TestProfileRepository {
        fn new(base_url: &str) -> Self {
            let profile = ModelProfile {
                id: "profile-a".into(),
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "F1 embedding".into(),
                base_url: base_url.into(),
                model_name: "embedding-model".into(),
                temperature: None,
                max_tokens: None,
                embedding_dimension: Some(3),
                created_at: String::new(),
                updated_at: String::new(),
            };
            Self {
                active: ActiveModelProfile {
                    purpose: ModelPurpose::Embedding,
                    profile_id: profile.id.clone(),
                },
                profile,
                fail_after_first_profile_read: AtomicBool::new(false),
                profile_reads: AtomicUsize::new(0),
            }
        }

        fn set_fail_after_first_profile_read(&self, value: bool) {
            self.fail_after_first_profile_read
                .store(value, Ordering::SeqCst);
        }
    }

    impl ModelProfileRepository for TestProfileRepository {
        fn create_profile(
            &self,
            profile: &ModelProfile,
        ) -> Result<ModelProfile, ModelProfileError> {
            Ok(profile.clone())
        }

        fn get_profile(&self, profile_id: &str) -> Result<Option<ModelProfile>, ModelProfileError> {
            let read = self.profile_reads.fetch_add(1, Ordering::SeqCst);
            if self.fail_after_first_profile_read.load(Ordering::SeqCst) && read >= 1 {
                return Err(ModelProfileError::not_found());
            }
            Ok((profile_id == self.profile.id).then(|| self.profile.clone()))
        }

        fn list_profiles(
            &self,
            purpose: Option<ModelPurpose>,
        ) -> Result<Vec<ModelProfile>, ModelProfileError> {
            if purpose.is_none() || purpose == Some(self.profile.purpose) {
                Ok(vec![self.profile.clone()])
            } else {
                Ok(Vec::new())
            }
        }

        fn update_profile(
            &self,
            profile: &ModelProfile,
        ) -> Result<ModelProfile, ModelProfileError> {
            Ok(profile.clone())
        }

        fn delete_profile(
            &self,
            _profile_id: &str,
        ) -> Result<DeleteModelProfileResult, ModelProfileError> {
            Err(ModelProfileError::not_found())
        }

        fn set_active_profile(
            &self,
            purpose: ModelPurpose,
            profile_id: &str,
        ) -> Result<ActiveModelProfile, ModelProfileError> {
            if purpose == self.active.purpose && profile_id == self.active.profile_id {
                Ok(self.active.clone())
            } else {
                Err(ModelProfileError::not_found())
            }
        }

        fn get_active_profile(
            &self,
            purpose: ModelPurpose,
        ) -> Result<Option<ActiveModelProfile>, ModelProfileError> {
            Ok((purpose == self.active.purpose).then(|| self.active.clone()))
        }
    }

    #[derive(Clone, Copy)]
    enum ServerBehavior {
        Success(usize),
        SuccessThenClose(usize, usize),
        CloseAfterRequest,
    }

    struct EmbeddingServer {
        base_url: String,
        requests: Arc<AtomicUsize>,
        stop: Option<Sender<()>>,
        handle: Option<JoinHandle<()>>,
    }

    impl EmbeddingServer {
        fn new(behavior: ServerBehavior) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let requests = Arc::new(AtomicUsize::new(0));
            let request_counter = Arc::clone(&requests);
            let (stop, stop_receiver) = mpsc::channel();
            let handle = thread::spawn(move || {
                serve_embedding_requests(listener, stop_receiver, request_counter, behavior);
            });
            Self {
                base_url: format!("http://{address}/v1"),
                requests,
                stop: Some(stop),
                handle: Some(handle),
            }
        }

        fn request_count(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }

    impl Drop for EmbeddingServer {
        fn drop(&mut self) {
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(handle) = self.handle.take() {
                handle.join().unwrap();
            }
        }
    }

    fn serve_embedding_requests(
        listener: TcpListener,
        stop_receiver: Receiver<()>,
        request_counter: Arc<AtomicUsize>,
        behavior: ServerBehavior,
    ) {
        loop {
            if stop_receiver.try_recv().is_ok() {
                return;
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let request_number = request_counter.fetch_add(1, Ordering::SeqCst) + 1;
                    stream.set_nonblocking(false).unwrap();
                    read_http_request(&mut stream);
                    let dimension = match behavior {
                        ServerBehavior::Success(dimension) => Some(dimension),
                        ServerBehavior::SuccessThenClose(dimension, successful_requests)
                            if request_number <= successful_requests =>
                        {
                            Some(dimension)
                        }
                        ServerBehavior::SuccessThenClose(_, _)
                        | ServerBehavior::CloseAfterRequest => None,
                    };
                    if let Some(dimension) = dimension {
                        let values = (0..dimension)
                            .map(|index| format!("0.{}", index + 1))
                            .collect::<Vec<_>>()
                            .join(",");
                        let body = format!(
                            r#"{{"object":"list","data":[{{"object":"embedding","index":0,"embedding":[{values}]}}],"model":"embedding-model","usage":{{"prompt_tokens":1,"total_tokens":1}}}}"#
                        );
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(header.as_bytes());
                        let _ = stream.write_all(body.as_bytes());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::yield_now();
                }
                Err(_) => return,
            }
        }
    }

    fn read_http_request(stream: &mut TcpStream) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 2048];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => return,
                Ok(read) => bytes.extend_from_slice(&buffer[..read]),
            }
            let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end]);
            let content_length = headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                (name.eq_ignore_ascii_case("content-length"))
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            });
            let Some(content_length) = content_length else {
                return;
            };
            if bytes.len() >= header_end + 4 + content_length {
                return;
            }
        }
    }

    fn full_fixture(
        behavior: ServerBehavior,
    ) -> (
        TempDir,
        StorageService,
        TestProfileRepository,
        InMemorySecretStore,
        ModelRuntimeCoordinator,
        LanceDbVectorStoreRegistry,
        EmbeddingServer,
    ) {
        let server = EmbeddingServer::new(behavior);
        let root = tempfile::Builder::new()
            .prefix("d9d3-c-f1")
            .tempdir()
            .unwrap();
        let storage =
            StorageService::initialize_with_roots(root.path().join("data"), None).unwrap();
        seed_life_and_memory(&storage);
        let profiles = TestProfileRepository::new(&server.base_url);
        let secrets = InMemorySecretStore::new();
        secrets
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, "profile-a").unwrap(),
                SecretValue::new("d9b-c-f1-test-key".into()).unwrap(),
            )
            .unwrap();
        (
            root,
            storage,
            profiles,
            secrets,
            ModelRuntimeCoordinator::default(),
            LanceDbVectorStoreRegistry::default(),
            server,
        )
    }

    fn seed_life_and_memory(storage: &StorageService) {
        let database = storage.test_database_main_path().unwrap();
        let connection = open_authorized_test_connection(&database).unwrap();
        connection
            .execute_batch(
                "INSERT INTO persona_template (id,name,version,persona_json) VALUES ('persona-a','Persona',1,'{}');
                 INSERT INTO life_identity (id,name,created_at,version,body_id,persona_id,persona_version) VALUES ('life-a','Life','2026-08-18T00:00:00.000Z',1,'body','persona-a',1);
                 INSERT INTO memory_record
                 (id,life_id,kind,status,content,summary,source_type,source_ref,source_created_at,
                  importance,confidence,is_sensitive,created_at,updated_at,confirmed_at,revision)
                 VALUES ('memory-a','life-a','fact','confirmed','authoritative content','summary','manual',NULL,'2026-08-18T00:00:00.000Z',
                         0.5,0.8,0,'2026-08-18T00:00:00.000Z','2026-08-18T00:00:00.000Z',
                         '2026-08-18T00:00:00.000Z',1);",
            )
            .unwrap();
    }

    fn register_store_fixture(
        label: &str,
        descriptor_hash: &'static str,
    ) -> (
        TempDir,
        StorageService,
        LanceDbVectorStoreRegistry,
        GenerationRebuildJobRecord,
        GenerationRebuildLease,
        VectorGenerationContext,
    ) {
        let root = tempfile::Builder::new().prefix(label).tempdir().unwrap();
        let storage =
            StorageService::initialize_with_roots(root.path().join("data"), None).unwrap();
        storage
            .register_generation_lifecycle_authority(GenerationAuthorityRegistration {
                generation_id: "generation-a",
                descriptor_hash,
                dimension: 3,
                embedding_profile_id: "profile-a",
                create_operation_id: "operation-a",
                job_id: "job-a",
                request_id: "request-a",
            })
            .unwrap();
        let lease = storage
            .acquire_generation_rebuild_job_lease("job-a", "owner-a")
            .unwrap()
            .unwrap();
        let job = storage.load_generation_rebuild_job("job-a").unwrap();
        let context = generation_context(&job).unwrap();
        (
            root,
            storage,
            LanceDbVectorStoreRegistry::default(),
            job,
            lease,
            context,
        )
    }

    async fn processing_fixture(
        label: &str,
    ) -> (
        TempDir,
        StorageService,
        LanceDbVectorStoreRegistry,
        GenerationRebuildJobRecord,
        GenerationRebuildLease,
        VectorGenerationContext,
        Arc<LanceDbVectorStore>,
        GenerationRebuildItemRecord,
    ) {
        let root = tempfile::Builder::new().prefix(label).tempdir().unwrap();
        let storage =
            StorageService::initialize_with_roots(root.path().join("data"), None).unwrap();
        seed_life_and_memory(&storage);
        storage
            .register_generation_lifecycle_authority(GenerationAuthorityRegistration {
                generation_id: "generation-a",
                descriptor_hash: "descriptor-a",
                dimension: 3,
                embedding_profile_id: "profile-a",
                create_operation_id: "operation-a",
                job_id: "job-a",
                request_id: "request-a",
            })
            .unwrap();
        let lease = storage
            .acquire_generation_rebuild_job_lease("job-a", "owner-a")
            .unwrap()
            .unwrap();
        let job = storage.load_generation_rebuild_job("job-a").unwrap();
        let context = generation_context(&job).unwrap();
        let registry = LanceDbVectorStoreRegistry::default();
        let data_root = storage.active_data_root().unwrap();
        let store = registry
            .generation_store_for_write(&data_root, context.generation_id())
            .await
            .unwrap();
        store.create_generation(&context).await.unwrap();
        store.health_check_generation(&context).await.unwrap();
        storage
            .mark_generation_store_witness_ready("job-a", &lease, "generation-a", "operation-a")
            .unwrap();
        storage
            .snapshot_generation_rebuild("job-a", &lease)
            .unwrap();
        let item = storage
            .reserve_next_generation_rebuild_item("job-a", &lease)
            .unwrap()
            .unwrap();
        (root, storage, registry, job, lease, context, store, item)
    }

    fn runtime_fixture<'a>(
        profiles: &'a TestProfileRepository,
        secrets: &'a InMemorySecretStore,
        coordinator: &'a ModelRuntimeCoordinator,
    ) -> ModelRuntimeService<'a, TestProfileRepository, InMemorySecretStore> {
        ModelRuntimeService::new(profiles, secrets, coordinator)
    }

    fn pointer_and_generation_state(
        storage: &StorageService,
        generation_id: &str,
    ) -> (Option<String>, String, i64) {
        let database = storage.test_database_main_path().unwrap();
        let connection = open_authorized_test_connection(&database).unwrap();
        let pointer = connection
            .query_row(
                "SELECT active_generation_id FROM memory_vector_generation_authority WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let generation = connection
            .query_row(
                "SELECT state,authority_epoch FROM memory_vector_generation WHERE generation_id=?1",
                [generation_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        (pointer, generation.0, generation.1)
    }

    fn generation_item_count(storage: &StorageService, generation_id: &str) -> i64 {
        let database = storage.test_database_main_path().unwrap();
        let connection = open_authorized_test_connection(&database).unwrap();
        connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_generation_item WHERE generation_id=?1",
                [generation_id],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn seed_active_source_generation(storage: &StorageService) {
        let database = storage.test_database_main_path().unwrap();
        let connection = open_authorized_test_connection(&database).unwrap();
        let descriptor = "a".repeat(64);
        connection
            .execute(
                "INSERT INTO memory_vector_generation
                    (generation_id,descriptor_hash,dimension,state,authority_epoch)
                 VALUES (?1,?2,3,'active',7)",
                rusqlite::params!["source-g1", descriptor],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE memory_vector_generation_authority
                 SET active_generation_id='source-g1' WHERE singleton=1",
                [],
            )
            .unwrap();
    }

    async fn create_retained_source_store(
        storage: &StorageService,
        registry: &LanceDbVectorStoreRegistry,
    ) {
        let data_root = storage.active_data_root().unwrap();
        let generation_id = VectorGenerationId::parse("source-g1").unwrap();
        let context = VectorGenerationContext::new(
            generation_id.clone(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            3,
        )
        .unwrap();
        let store = registry
            .generation_store_for_write(&data_root, &generation_id)
            .await
            .unwrap();
        store.create_generation(&context).await.unwrap();
        store.health_check_generation(&context).await.unwrap();
    }

    fn current_eligible_set(storage: &StorageService) -> BTreeSet<(String, String, i64, String)> {
        let database = storage.test_database_main_path().unwrap();
        let connection = open_authorized_test_connection(&database).unwrap();
        let mut statement = connection
            .prepare(
                "SELECT life_id,id,kind,revision,content,summary,status,is_sensitive
                 FROM memory_record ORDER BY life_id,id",
            )
            .unwrap();
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })
            .unwrap();
        let mut eligible = BTreeSet::new();
        for row in rows {
            let (life_id, memory_id, kind, revision, content, summary, status, sensitive) =
                row.unwrap();
            if status != "confirmed" || sensitive != 0 {
                continue;
            }
            let Some(selected) =
                crate::memory::vector_index::canonical_index_text(summary.as_deref(), &content)
            else {
                continue;
            };
            let canonical = selected.trim();
            if revision < 1
                || canonical.is_empty()
                || crate::memory::candidate_service::contains_prohibited_content(&content)
                || summary
                    .as_deref()
                    .is_some_and(crate::memory::candidate_service::contains_prohibited_content)
            {
                continue;
            }
            let content_hash = crate::memory::vector_index::canonical_memory_index_hash(
                &kind,
                selected,
                &content,
                summary.as_deref(),
            );
            eligible.insert((life_id, memory_id, revision, content_hash));
        }
        eligible
    }

    async fn assert_exact_sqlite_generation_and_lance_sets(
        storage: &StorageService,
        registry: &LanceDbVectorStoreRegistry,
        job: &GenerationRebuildJobRecord,
    ) {
        let expected = current_eligible_set(storage);
        let generation = storage
            .list_generation_rebuild_generation_items(&job.generation_id)
            .unwrap()
            .into_iter()
            .map(|item| {
                (
                    item.life_id,
                    item.memory_id,
                    item.memory_revision,
                    item.content_hash,
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(generation, expected, "SQLite generation set must be exact");

        let generation_id = VectorGenerationId::parse(&job.generation_id).unwrap();
        let context =
            VectorGenerationContext::new(generation_id, job.descriptor_hash.clone(), job.dimension)
                .unwrap();
        let data_root = storage.active_data_root().unwrap();
        let store = registry
            .existing_generation_store(&data_root, context.generation_id())
            .await
            .unwrap()
            .expect("the promoted Lance generation must remain present");
        let metadata = store.list_generation_metadata(&context).await.unwrap();
        assert!(metadata.iter().all(|sample| {
            sample.generation_id == job.generation_id
                && sample.descriptor_hash == job.descriptor_hash
                && sample.dimension == job.dimension
        }));
        let lance = metadata
            .into_iter()
            .map(|sample| {
                (
                    sample.life_id,
                    sample.memory_id,
                    sample.memory_revision,
                    sample.content_hash,
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(lance, expected, "Lance generation set must be exact");
    }

    fn assert_no_plaintext_test_credential(
        storage: &StorageService,
        status: &crate::memory::vector_sync_stage_runtime::VectorGenerationRebuildStatus,
    ) {
        let sentinel = "d9d3-f3-profile-key";
        let database = storage.test_database_main_path().unwrap();
        let connection = open_authorized_test_connection(&database).unwrap();
        let memory_hits: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM memory_record
                 WHERE content LIKE ?1 OR COALESCE(summary,'') LIKE ?1",
                [format!("%{sentinel}%")],
                |row| row.get(0),
            )
            .unwrap();
        let profile_hits: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM model_profile
                 WHERE display_name LIKE ?1 OR base_url LIKE ?1 OR model_name LIKE ?1",
                [format!("%{sentinel}%")],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(memory_hits, 0);
        assert_eq!(profile_hits, 0);
        let serialized = serde_json::to_string(status).unwrap();
        assert!(!serialized.contains(sentinel));
    }

    #[test]
    fn d9d3_e_isolated_filesystem_live_dry_run() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (root, storage, _profiles, secrets, coordinator, registry, server) =
                full_fixture(ServerBehavior::Success(3));
            let root_path = root.path().to_path_buf();
            register_storage_embedding_profile(&storage, &secrets, &server);
            let gate = FencedVectorSyncCompositionGate::default();

            let first = run_vector_generation_rebuild(
                &storage,
                &secrets,
                &coordinator,
                &registry,
                &gate,
                "d9d3-e-bootstrap",
                Duration::from_secs(30),
            )
            .await
            .unwrap();
            assert_eq!(first.status, "completed");
            assert_eq!(first.source_active_generation_id, None);
            assert_eq!(first.generation_state, "active");
            assert_eq!(first.generation_authority_epoch, 2);
            assert_eq!(first.candidate_authority_epoch, 1);

            let status = resolve_generation_rebuild_status(&storage, &first.job_id).unwrap();
            assert_eq!(status.status, "completed");
            assert_no_plaintext_test_credential(&storage, &status);
            assert_exact_sqlite_generation_and_lance_sets(&storage, &registry, &first).await;

            let database = storage.test_database_main_path().unwrap();
            let connection = open_authorized_test_connection(&database).unwrap();
            let pointer: Option<String> = connection
                .query_row(
                    "SELECT active_generation_id
                     FROM memory_vector_generation_authority WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(pointer, Some(first.generation_id.clone()));
            let generation_count: i64 = connection
                .query_row("SELECT COUNT(*) FROM memory_vector_generation", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(generation_count, 1);
            let attempt_count: i64 = connection
                .query_row(
                    "SELECT COALESCE((SELECT SUM(attempt_count)
                                      FROM memory_vector_generation_rebuild_item),0)
                            + COALESCE((SELECT SUM(attempt_count)
                                        FROM memory_vector_generation_rebuild_catchup_item),0)",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            drop(connection);
            let request_count = server.request_count();

            let second = run_vector_generation_rebuild(
                &storage,
                &secrets,
                &coordinator,
                &registry,
                &gate,
                "d9d3-e-bootstrap",
                Duration::from_secs(30),
            )
            .await
            .unwrap();
            assert_eq!(second.job_id, first.job_id);
            assert_eq!(second.generation_id, first.generation_id);
            assert_eq!(second.promotion_operation_id, first.promotion_operation_id);
            assert_eq!(server.request_count(), request_count);

            let connection = open_authorized_test_connection(&database).unwrap();
            let generation_count_after: i64 = connection
                .query_row("SELECT COUNT(*) FROM memory_vector_generation", [], |row| {
                    row.get(0)
                })
                .unwrap();
            let attempt_count_after: i64 = connection
                .query_row(
                    "SELECT COALESCE((SELECT SUM(attempt_count)
                                      FROM memory_vector_generation_rebuild_item),0)
                            + COALESCE((SELECT SUM(attempt_count)
                                        FROM memory_vector_generation_rebuild_catchup_item),0)",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(generation_count_after, generation_count);
            assert_eq!(attempt_count_after, attempt_count);
            drop(connection);

            let data_root = storage.active_data_root().unwrap();
            assert!(data_root
                .join("vectors/generations")
                .join(&first.generation_id)
                .join("lancedb")
                .is_dir());
            drop(registry);
            drop(storage);
            drop(secrets);
            drop(server);
            drop(root);
            assert!(
                !root_path.exists(),
                "isolated dry-run root must be removable"
            );
        });
    }

    #[test]
    fn d9d3_e_g1_to_g2_full_cutover_and_post_promotion_sync() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, _profiles, secrets, coordinator, registry, server) =
                full_fixture(ServerBehavior::Success(3));
            register_storage_embedding_profile(&storage, &secrets, &server);
            seed_active_source_generation(&storage);
            create_retained_source_store(&storage, &registry).await;
            let data_root = storage.active_data_root().unwrap();
            let gate = FencedVectorSyncCompositionGate::default();

            let job = run_vector_generation_rebuild(
                &storage,
                &secrets,
                &coordinator,
                &registry,
                &gate,
                "d9d3-e-g1-g2",
                Duration::from_secs(30),
            )
            .await
            .unwrap();
            assert_eq!(job.status, "completed");
            assert_eq!(
                job.source_active_generation_id.as_deref(),
                Some("source-g1")
            );
            assert_eq!(job.source_active_authority_epoch, Some(7));
            assert_exact_sqlite_generation_and_lance_sets(&storage, &registry, &job).await;

            let database = storage.test_database_main_path().unwrap();
            let connection = open_authorized_test_connection(&database).unwrap();
            let source_state: (String, i64) = connection
                .query_row(
                    "SELECT state,authority_epoch FROM memory_vector_generation
                     WHERE generation_id='source-g1'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            let pointer: Option<String> = connection
                .query_row(
                    "SELECT active_generation_id
                     FROM memory_vector_generation_authority WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(source_state, ("retired".into(), 8));
            assert_eq!(pointer, Some(job.generation_id.clone()));
            drop(connection);
            assert!(data_root
                .join("vectors/generations/source-g1/lancedb")
                .is_dir());

            let _updated = storage
                .revise_confirmed_memory_for_vector_sync_test(
                    "life-a",
                    "memory-a",
                    crate::memory::MemoryKind::Fact,
                    "post-promotion authoritative content",
                    Some("post-promotion authoritative summary"),
                )
                .unwrap();
            let ordinary = run_fenced_vector_sync_drain(
                &storage,
                &secrets,
                &coordinator,
                &registry,
                &gate,
                "d9d3-e-post-promotion-sync",
                16,
            )
            .await
            .unwrap();
            assert_eq!(ordinary.applied_upserts, 1);
            assert_eq!(ordinary.applied_deletes, 0);
            assert_exact_sqlite_generation_and_lance_sets(&storage, &registry, &job).await;

            let source_context = VectorGenerationContext::new(
                VectorGenerationId::parse("source-g1").unwrap(),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                3,
            )
            .unwrap();
            let source_store = registry
                .existing_generation_store(&data_root, source_context.generation_id())
                .await
                .unwrap()
                .unwrap();
            assert!(source_store
                .list_generation_metadata(&source_context)
                .await
                .unwrap()
                .is_empty());
        });
    }

    #[test]
    fn d9d3_e_post_snapshot_concurrent_mutation_catches_up() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, _profiles, secrets, coordinator, registry, server) =
                full_fixture(ServerBehavior::Success(3));
            register_storage_embedding_profile(&storage, &secrets, &server);
            let gate = FencedVectorSyncCompositionGate::default();
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            set_c_after_snapshot_hook_for_test(entered_tx, release_rx);

            let job = std::thread::scope(|scope| {
                let pipeline = scope.spawn(|| {
                    tauri::async_runtime::block_on(run_vector_generation_rebuild(
                        &storage,
                        &secrets,
                        &coordinator,
                        &registry,
                        &gate,
                        "d9d3-e-post-s",
                        Duration::from_secs(30),
                    ))
                });
                entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                let _updated = storage
                    .revise_confirmed_memory_for_vector_sync_test(
                        "life-a",
                        "memory-a",
                        crate::memory::MemoryKind::Fact,
                        "post-snapshot authoritative content",
                        Some("post-snapshot authoritative summary"),
                    )
                    .unwrap();
                release_tx.send(()).unwrap();
                pipeline.join().unwrap()
            })
            .unwrap();
            assert_eq!(job.status, "completed");
            assert_eq!(job.snapshot_sequence, Some(0));
            assert!(job.caught_up_sequence.unwrap() > job.snapshot_sequence.unwrap());
            assert_exact_sqlite_generation_and_lance_sets(&storage, &registry, &job).await;
            let generation_items = storage
                .list_generation_rebuild_generation_items(&job.generation_id)
                .unwrap();
            assert_eq!(generation_items.len(), 1);
            assert_eq!(generation_items[0].memory_revision, 2);
        });
    }

    #[test]
    fn d9d3_e_promotion_mutation_race_never_promotes_stale_t() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, _profiles, secrets, coordinator, registry, server) =
                full_fixture(ServerBehavior::Success(3));
            register_storage_embedding_profile(&storage, &secrets, &server);
            seed_active_source_generation(&storage);
            create_retained_source_store(&storage, &registry).await;
            let gate = FencedVectorSyncCompositionGate::default();
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            set_d_before_promotion_hook_for_test(entered_tx, release_rx);

            let job = std::thread::scope(|scope| {
                let pipeline = scope.spawn(|| {
                    tauri::async_runtime::block_on(run_vector_generation_rebuild(
                        &storage,
                        &secrets,
                        &coordinator,
                        &registry,
                        &gate,
                        "d9d3-e-promotion-race",
                        Duration::from_secs(30),
                    ))
                });
                entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                let before = storage
                    .load_generation_rebuild_job_by_request("d9d3-e-promotion-race")
                    .unwrap()
                    .unwrap();
                assert_eq!(before.status, "ready");
                let database = storage.test_database_main_path().unwrap();
                let connection = open_authorized_test_connection(&database).unwrap();
                let pointer: Option<String> = connection
                    .query_row(
                        "SELECT active_generation_id
                         FROM memory_vector_generation_authority WHERE singleton=1",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                let candidate_state: String = connection
                    .query_row(
                        "SELECT state FROM memory_vector_generation WHERE generation_id=?1",
                        [before.generation_id.as_str()],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(pointer.as_deref(), Some("source-g1"));
                assert_eq!(candidate_state, "building");
                drop(connection);
                let _updated = storage
                    .revise_confirmed_memory_for_vector_sync_test(
                        "life-a",
                        "memory-a",
                        crate::memory::MemoryKind::Fact,
                        "promotion-race authoritative content",
                        Some("promotion-race authoritative summary"),
                    )
                    .unwrap();
                release_tx.send(()).unwrap();
                pipeline.join().unwrap()
            })
            .unwrap();
            assert_eq!(job.status, "completed");
            assert!(job.promotion_sequence.unwrap() > job.snapshot_sequence.unwrap());
            assert_exact_sqlite_generation_and_lance_sets(&storage, &registry, &job).await;
            let database = storage.test_database_main_path().unwrap();
            let connection = open_authorized_test_connection(&database).unwrap();
            let pointer: Option<String> = connection
                .query_row(
                    "SELECT active_generation_id
                     FROM memory_vector_generation_authority WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(pointer, Some(job.generation_id.clone()));
        });
    }

    #[test]
    fn d9d3_e_late_delete_resolved_by_rebuild_without_generalizing_ld() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, _profiles, secrets, coordinator, registry, server) =
                full_fixture(ServerBehavior::Success(3));
            register_storage_embedding_profile(&storage, &secrets, &server);
            let database = storage.test_database_main_path().unwrap();
            seed_recovery_postimage(&storage, &database);
            let gate = FencedVectorSyncCompositionGate::default();

            let job = run_vector_generation_rebuild(
                &storage,
                &secrets,
                &coordinator,
                &registry,
                &gate,
                "d9d3-e-late-delete",
                Duration::from_secs(30),
            )
            .await
            .unwrap();
            assert_eq!(job.status, "completed");
            assert_exact_sqlite_generation_and_lance_sets(&storage, &registry, &job).await;

            let connection = open_authorized_test_connection(&database).unwrap();
            let late_delete: (String, String, Option<i64>) = connection
                .query_row(
                    "SELECT state,last_resolution_disposition,
                            captured_generation_authority_epoch
                     FROM memory_vector_late_delete_resolution
                     WHERE life_id='life-a' AND memory_id='memory-c'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(
                late_delete,
                (
                    "resolved_rebuilt".into(),
                    "resolved_rebuilt".into(),
                    Some(7)
                )
            );
            let rebuild_resolution: (String, Option<String>, Option<i64>, String, Option<i64>) =
                connection
                    .query_row(
                        "SELECT source_kind,source_generation_id,
                                source_generation_authority_epoch,disposition,
                                replacement_mutation_sequence
                         FROM memory_vector_generation_rebuild_resolution
                         WHERE job_id=?1 AND source_kind='late_delete'",
                        [job.job_id.as_str()],
                        |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                            ))
                        },
                    )
                    .unwrap();
            assert_eq!(
                rebuild_resolution,
                (
                    "late_delete".into(),
                    Some("source-g1".into()),
                    Some(7),
                    "resolved_by_rebuild".into(),
                    None,
                )
            );
            drop(connection);
            assert_eq!(
                server.request_count(),
                1,
                "the rebuild Delete must not replay embedding I/O"
            );
        });
    }

    #[test]
    fn d9d3_e_failed_g2_preserves_g1_and_requeues_without_rebind() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, _profiles, secrets, coordinator, registry, server) =
                full_fixture(ServerBehavior::SuccessThenClose(3, 1));
            register_storage_embedding_profile(&storage, &secrets, &server);
            seed_active_source_generation(&storage);
            create_retained_source_store(&storage, &registry).await;
            let database = storage.test_database_main_path().unwrap();
            let gate = FencedVectorSyncCompositionGate::default();
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            set_c_after_snapshot_hook_for_test(entered_tx, release_rx);

            let result = std::thread::scope(|scope| {
                let pipeline = scope.spawn(|| {
                    tauri::async_runtime::block_on(run_vector_generation_rebuild(
                        &storage,
                        &secrets,
                        &coordinator,
                        &registry,
                        &gate,
                        "d9d3-e-failed-g2",
                        Duration::from_secs(30),
                    ))
                });
                entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                let _updated = storage
                    .revise_confirmed_memory_for_vector_sync_test(
                        "life-a",
                        "memory-a",
                        crate::memory::MemoryKind::Fact,
                        "failed-g2 authoritative content",
                        Some("failed-g2 authoritative summary"),
                    )
                    .unwrap();
                release_tx.send(()).unwrap();
                pipeline.join().unwrap()
            });
            assert!(result.is_err());
            let job = storage
                .load_generation_rebuild_job_by_request("d9d3-e-failed-g2")
                .unwrap()
                .unwrap();
            assert_eq!(job.status, "failed");

            let connection = open_authorized_test_connection(&database).unwrap();
            let generations: (String, i64, String, Option<String>) = connection
                .query_row(
                    "SELECT source.state,source.authority_epoch,candidate.state,
                            authority.active_generation_id
                     FROM memory_vector_generation source
                     JOIN memory_vector_generation candidate
                       ON candidate.generation_id=?1
                     JOIN memory_vector_generation_authority authority
                       ON authority.singleton=1
                     WHERE source.generation_id='source-g1'",
                    [job.generation_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
            assert_eq!(generations.0, "active");
            assert_eq!(generations.1, 7);
            assert_eq!(generations.2, "failed");
            assert_eq!(generations.3.as_deref(), Some("source-g1"));

            let outbox: (i64, String, Option<String>, Option<i64>, Option<String>) = connection
                .query_row(
                    "SELECT mutation_sequence,state,claimed_generation_id,
                            claimed_generation_authority_epoch,last_send_disposition
                     FROM memory_vector_sync_outbox
                     WHERE life_id='life-a' AND memory_id='memory-a'",
                    [],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .unwrap();
            assert_eq!(outbox.0, 1);
            assert_eq!(outbox.1, "pending");
            assert_eq!(outbox.2, None);
            assert_eq!(outbox.3, None);
            assert_eq!(outbox.4, None);

            let resolution_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*)
                     FROM memory_vector_generation_rebuild_resolution
                     WHERE job_id=?1 AND source_kind='outbox'",
                    [job.job_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(resolution_count, 0);

            let catchup: (String, Option<String>, Option<String>) = connection
                .query_row(
                    "SELECT state,last_send_disposition,canonical_document
                     FROM memory_vector_generation_rebuild_catchup_item
                     WHERE job_id=?1",
                    [job.job_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(catchup.0, "uncertain");
            assert_eq!(catchup.1.as_deref(), Some("possibly_sent"));
            assert_eq!(catchup.2, None);
            drop(connection);
        });
    }

    #[test]
    fn d9d3_c_f1_direct_c_happy_path_retains_outer_guard_and_handoffs_exact_snapshot() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, profiles, secrets, coordinator, registry, server) =
                full_fixture(ServerBehavior::Success(3));
            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
            let gate = Arc::new(FencedVectorSyncCompositionGate::default());
            let guard = gate.acquire().await;
            let started = Arc::new(Notify::new());
            let started_wait = started.notified();
            let started_for_task = Arc::clone(&started);
            let (acquired_sender, mut acquired_receiver) = tokio::sync::mpsc::unbounded_channel();
            let competitor_gate = Arc::clone(&gate);
            tokio::spawn(async move {
                started_for_task.notify_one();
                let _competitor_guard = competitor_gate.acquire().await;
                acquired_sender.send(()).unwrap();
            });
            started_wait.await;

            let handoff = run_generation_rebuild_c(
                &storage,
                &runtime,
                &registry,
                "request-a",
                "owner-a",
                &guard,
            )
            .await
            .unwrap();

            assert_eq!(handoff.status, "catching_up");
            assert_eq!(handoff.snapshot_item_count, 1);
            assert_eq!(handoff.applied_item_count, 1);
            assert_eq!(server.request_count(), 1);
            assert_eq!(C_STORE_CREATE_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(C_VECTOR_UPSERT_CALLS.load(Ordering::SeqCst), 1);

            let job = storage
                .load_generation_rebuild_job(&handoff.job_id)
                .unwrap();
            assert_eq!(job.generation_id, handoff.generation_id);
            assert_eq!(job.status, "catching_up");
            assert_eq!(job.generation_state, "building");
            assert_eq!(job.candidate_authority_epoch, 1);
            assert_eq!(job.snapshot_item_count, job.applied_item_count);
            let items = storage.list_generation_rebuild_items(&job.job_id).unwrap();
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].state, "applied");
            assert_eq!(items[0].io_phase, "finalized");
            assert_eq!(items[0].canonical_document, None);
            assert_eq!(generation_item_count(&storage, &job.generation_id), 1);
            let database = storage.test_database_main_path().unwrap();
            let connection = open_authorized_test_connection(&database).unwrap();
            let generation_item: (String, String, String, i64, String) = connection
                .query_row(
                    "SELECT generation_id,life_id,memory_id,memory_revision,content_hash
                     FROM memory_vector_generation_item WHERE generation_id=?1",
                    [job.generation_id.as_str()],
                    |row| {
                        Ok((
                            row.get(0)?,
                            row.get(1)?,
                            row.get(2)?,
                            row.get(3)?,
                            row.get(4)?,
                        ))
                    },
                )
                .unwrap();
            assert_eq!(generation_item.0, job.generation_id);
            assert_eq!(generation_item.1, items[0].life_id);
            assert_eq!(generation_item.2, items[0].memory_id);
            assert_eq!(generation_item.3, items[0].memory_revision);
            assert_eq!(generation_item.4, items[0].content_hash);
            let (pointer, state, epoch) =
                pointer_and_generation_state(&storage, &job.generation_id);
            assert_eq!(pointer, None);
            assert_eq!(state, "building");
            assert_eq!(epoch, 1);

            tokio::task::yield_now().await;
            assert!(acquired_receiver.try_recv().is_err());
            drop(guard);
            acquired_receiver.recv().await.unwrap();
        });
    }

    #[test]
    fn d9d3_d_catchup_empty_target_promotes_exact_bootstrap_set() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, profiles, secrets, coordinator, registry, _server) =
                full_fixture(ServerBehavior::Success(3));
            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
            let gate = FencedVectorSyncCompositionGate::default();
            let guard = gate.acquire().await;
            let handoff = run_generation_rebuild_c(
                &storage,
                &runtime,
                &registry,
                "request-a",
                "owner-a",
                &guard,
            )
            .await
            .unwrap();
            arm_promotion_fault_for_test(PromotionFault::AfterCommitUnknown);
            let completed = run_generation_rebuild_d(
                &storage,
                &runtime,
                &registry,
                &handoff,
                "owner-a",
                std::time::Instant::now() + Duration::from_secs(5),
                &guard,
            )
            .await
            .unwrap();
            assert_eq!(completed.status, "completed");
            assert_eq!(completed.promotion_sequence, Some(0));
            assert_eq!(completed.promotion_operation_id.is_some(), true);
            let (pointer, state, epoch) =
                pointer_and_generation_state(&storage, &completed.generation_id);
            assert_eq!(pointer.as_deref(), Some(completed.generation_id.as_str()));
            assert_eq!(state, "active");
            assert_eq!(epoch, completed.candidate_authority_epoch + 1);
            assert_eq!(generation_item_count(&storage, &completed.generation_id), 1);
        });
    }

    #[test]
    fn d9d3_d_catchup_upsert_and_delete_prove_current_sqlite_and_lance_sets() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, profiles, secrets, coordinator, registry, server) =
                full_fixture(ServerBehavior::Success(3));
            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
            let gate = FencedVectorSyncCompositionGate::default();
            let guard = gate.acquire().await;
            let handoff = run_generation_rebuild_c(
                &storage,
                &runtime,
                &registry,
                "request-a",
                "owner-a",
                &guard,
            )
            .await
            .unwrap();

            let new_content = "catch-up content";
            let new_summary = Some("catch-up summary");
            let new_hash = crate::memory::vector_index::canonical_memory_index_hash(
                "fact",
                new_summary.unwrap(),
                new_content,
                new_summary,
            );
            let database = storage.test_database_main_path().unwrap();
            let connection = open_authorized_test_connection(&database).unwrap();
            connection
                .execute_batch(
                    "UPDATE memory_record SET status='candidate' WHERE id='memory-a';
                     INSERT INTO memory_record
                       (id,life_id,kind,status,content,summary,source_type,source_ref,source_created_at,
                        importance,confidence,is_sensitive,created_at,updated_at,confirmed_at,revision)
                     VALUES ('memory-b','life-a','fact','confirmed','catch-up content','catch-up summary',
                             'manual',NULL,'2026-08-18T00:00:00.000Z',0.5,0.8,0,
                             '2026-08-18T00:00:00.000Z','2026-08-18T00:00:00.000Z',
                             '2026-08-18T00:00:00.000Z',1);
                     UPDATE memory_vector_sync_mutation_clock SET last_sequence=2 WHERE singleton=1;",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO memory_vector_sync_outbox
                       (life_id,memory_id,desired_action,mutation_sequence,target_revision,target_content_hash,migration_disposition)
                     VALUES (?1,?2,'upsert',1,1,?3,NULL)",
                    rusqlite::params!["life-a", "memory-b", new_hash],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO memory_vector_sync_outbox
                       (life_id,memory_id,desired_action,mutation_sequence,target_revision,target_content_hash,migration_disposition)
                     VALUES ('life-a','memory-a','delete',2,NULL,NULL,NULL)",
                    [],
                )
                .unwrap();
            drop(connection);

            let completed = run_generation_rebuild_d(
                &storage,
                &runtime,
                &registry,
                &handoff,
                "owner-a",
                std::time::Instant::now() + Duration::from_secs(15),
                &guard,
            )
            .await
            .unwrap();
            assert_eq!(completed.status, "completed");
            assert_eq!(server.request_count(), 2);
            assert_eq!(generation_item_count(&storage, &completed.generation_id), 1);
            let pointer = pointer_and_generation_state(&storage, &completed.generation_id).0;
            assert_eq!(pointer.as_deref(), Some(completed.generation_id.as_str()));
        });
    }

    #[test]
    fn d9d3_d_promotion_stage_faults_rollback_to_exact_g1_preimage() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            for fault in [
                PromotionFault::AfterPointerTransientNull,
                PromotionFault::AfterSourceRetired,
                PromotionFault::AfterCandidateActivated,
                PromotionFault::AfterFinalPointer,
                PromotionFault::AfterResolutions,
                PromotionFault::BeforeCommit,
            ] {
                let (_root, storage, profiles, secrets, coordinator, registry, _server) =
                    full_fixture(ServerBehavior::Success(3));
                let database = storage.test_database_main_path().unwrap();
                let connection = open_authorized_test_connection(&database).unwrap();
                connection
                    .execute_batch(
                        "INSERT INTO memory_vector_generation
                           (generation_id,descriptor_hash,dimension,state,authority_epoch)
                         VALUES ('source-g1','source-descriptor',3,'active',7);
                         UPDATE memory_vector_generation_authority
                         SET active_generation_id='source-g1'
                         WHERE singleton=1;",
                    )
                    .unwrap();
                drop(connection);

                let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
                let gate = FencedVectorSyncCompositionGate::default();
                let guard = gate.acquire().await;
                let handoff = run_generation_rebuild_c(
                    &storage,
                    &runtime,
                    &registry,
                    "request-a",
                    "owner-a",
                    &guard,
                )
                .await
                .unwrap();
                arm_promotion_fault_for_test(fault);
                let error = run_generation_rebuild_d(
                    &storage,
                    &runtime,
                    &registry,
                    &handoff,
                    "owner-a",
                    std::time::Instant::now() + Duration::from_secs(5),
                    &guard,
                )
                .await
                .unwrap_err();
                assert_eq!(error.code, "GENERATION_REBUILD_PROMOTION_FAULT");

                let job = storage
                    .load_generation_rebuild_job(&handoff.job_id)
                    .unwrap();
                assert_eq!(job.status, "ready");
                assert_eq!(job.promotion_operation_id, None);
                assert_eq!(job.promotion_sequence, None);
                assert_eq!(
                    pointer_and_generation_state(&storage, "source-g1"),
                    (Some("source-g1".into()), "active".into(), 7)
                );
                assert_eq!(
                    pointer_and_generation_state(&storage, &handoff.generation_id),
                    (Some("source-g1".into()), "building".into(), 1)
                );
                let resolution_count: i64 = open_authorized_test_connection(&database)
                    .unwrap()
                    .query_row(
                        "SELECT COUNT(*) FROM memory_vector_generation_rebuild_resolution
                         WHERE job_id=?1",
                        [&handoff.job_id],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(resolution_count, 0);
            }
        });
    }

    #[test]
    fn d9d3_d_catchup_possibly_sent_fails_g2_without_replay() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, profiles, secrets, coordinator, registry, server) =
                full_fixture(ServerBehavior::SuccessThenClose(3, 1));
            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
            let gate = FencedVectorSyncCompositionGate::default();
            let guard = gate.acquire().await;
            let handoff = run_generation_rebuild_c(
                &storage,
                &runtime,
                &registry,
                "request-a",
                "owner-a",
                &guard,
            )
            .await
            .unwrap();

            let new_content = "catch-up failure content";
            let new_summary = Some("catch-up failure summary");
            let new_hash = crate::memory::vector_index::canonical_memory_index_hash(
                "fact",
                new_summary.unwrap(),
                new_content,
                new_summary,
            );
            let database = storage.test_database_main_path().unwrap();
            let connection = open_authorized_test_connection(&database).unwrap();
            connection
                .execute_batch(
                    "INSERT INTO memory_record
                       (id,life_id,kind,status,content,summary,source_type,source_ref,source_created_at,
                        importance,confidence,is_sensitive,created_at,updated_at,confirmed_at,revision)
                     VALUES ('memory-b','life-a','fact','confirmed','catch-up failure content',
                             'catch-up failure summary','manual',NULL,'2026-08-18T00:00:00.000Z',
                             0.5,0.8,0,'2026-08-18T00:00:00.000Z','2026-08-18T00:00:00.000Z',
                             '2026-08-18T00:00:00.000Z',1);
                     UPDATE memory_vector_sync_mutation_clock SET last_sequence=1 WHERE singleton=1;
                     ",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO memory_vector_sync_outbox
                       (life_id,memory_id,desired_action,mutation_sequence,target_revision,target_content_hash,migration_disposition)
                     VALUES ('life-a','memory-b','upsert',1,1,?1,NULL)",
                    rusqlite::params![new_hash],
                )
                .unwrap();
            drop(connection);

            let error = run_generation_rebuild_d(
                &storage,
                &runtime,
                &registry,
                &handoff,
                "owner-a",
                std::time::Instant::now() + Duration::from_secs(5),
                &guard,
            )
            .await
            .unwrap_err();
            assert_eq!(error.code, "GENERATION_REBUILD_PROVIDER_RESULT_UNKNOWN");
            assert!(error.recoverable);
            assert_eq!(server.request_count(), 2);

            let job = storage
                .load_generation_rebuild_job(&handoff.job_id)
                .unwrap();
            assert_eq!(job.status, "failed");
            assert_eq!(job.generation_state, "failed");
            assert_eq!(
                pointer_and_generation_state(&storage, &job.generation_id).0,
                None
            );
            let item = storage
                .list_generation_rebuild_catchup_items(&handoff.job_id)
                .unwrap()
                .into_iter()
                .find(|item| item.mutation_sequence == 1)
                .unwrap();
            assert_eq!(item.state, "uncertain");
            assert_eq!(item.io_phase, "embedding_started");
            assert_eq!(item.last_send_disposition.as_deref(), Some("possibly_sent"));
            assert_eq!(item.canonical_document, None);
            assert_eq!(item.attempt_count, 1);
        });
    }

    #[test]
    fn d9d3_c_f1_composition_guard_survives_error_return_until_outer_drop() {
        tauri::async_runtime::block_on(async {
            let (_root, storage, profiles, secrets, coordinator, registry, _server) =
                full_fixture(ServerBehavior::Success(3));
            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
            let gate = Arc::new(FencedVectorSyncCompositionGate::default());
            let guard = gate.acquire().await;
            let started = Arc::new(Notify::new());
            let started_wait = started.notified();
            let started_for_task = Arc::clone(&started);
            let (acquired_sender, mut acquired_receiver) = tokio::sync::mpsc::unbounded_channel();
            let competitor_gate = Arc::clone(&gate);
            tokio::spawn(async move {
                started_for_task.notify_one();
                let _competitor_guard = competitor_gate.acquire().await;
                acquired_sender.send(()).unwrap();
            });
            started_wait.await;

            let error =
                run_generation_rebuild_c(&storage, &runtime, &registry, "", "owner-a", &guard)
                    .await
                    .unwrap_err();
            assert_eq!(error.code, "D9D3_C_INVALID");
            tokio::task::yield_now().await;
            assert!(acquired_receiver.try_recv().is_err());
            drop(guard);
            acquired_receiver.recv().await.unwrap();
        });
    }

    #[test]
    fn d9d3_c_f1_store_unknown_exact_existing_skips_duplicate_create() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            let (_root, storage, registry, job, lease, context) =
                register_store_fixture("d9d3-c-f1-store-exact", "descriptor-a");
            let data_root = storage.active_data_root().unwrap();
            let store = registry
                .generation_store_for_write(&data_root, context.generation_id())
                .await
                .unwrap();
            store.create_generation(&context).await.unwrap();
            storage
                .mark_generation_store_witness_uncertain(
                    &job.job_id,
                    &lease,
                    &job.generation_id,
                    &job.create_operation_id,
                    "GENERATION_STORE_CREATE_RESULT_UNKNOWN",
                )
                .unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);

            let resumed = ensure_generation_store(&storage, &registry, &job, &lease, &context)
                .await
                .unwrap();
            assert!(Arc::ptr_eq(&store, &resumed));
            assert_eq!(C_STORE_CREATE_CALLS.load(Ordering::SeqCst), 0);
            assert_eq!(
                storage
                    .load_generation_store_witness(&job.generation_id)
                    .unwrap()
                    .state,
                "ready"
            );
        });
    }

    #[test]
    fn d9d3_c_f1_store_unknown_mismatch_fails_closed_without_create() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            let (_root, storage, registry, job, lease, context) =
                register_store_fixture("d9d3-c-f1-store-mismatch", "descriptor-a");
            let wrong_context = VectorGenerationContext::new(
                VectorGenerationId::parse("generation-a").unwrap(),
                "descriptor-b",
                3,
            )
            .unwrap();
            let data_root = storage.active_data_root().unwrap();
            let store = registry
                .generation_store_for_write(&data_root, context.generation_id())
                .await
                .unwrap();
            store.create_generation(&wrong_context).await.unwrap();
            storage
                .mark_generation_store_witness_uncertain(
                    &job.job_id,
                    &lease,
                    &job.generation_id,
                    &job.create_operation_id,
                    "GENERATION_STORE_CREATE_RESULT_UNKNOWN",
                )
                .unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);

            let error =
                match ensure_generation_store(&storage, &registry, &job, &lease, &context).await {
                    Ok(_) => panic!("a mismatched existing store must fail closed"),
                    Err(error) => error,
                };
            assert_eq!(error.code, "D9D3_C_STORE_CORRUPT");
            assert!(!error.recoverable);
            assert_eq!(C_STORE_CREATE_CALLS.load(Ordering::SeqCst), 0);
            assert_eq!(
                storage
                    .load_generation_store_witness(&job.generation_id)
                    .unwrap()
                    .state,
                "uncertain"
            );
        });
    }

    #[test]
    fn d9d3_c_f1_store_unknown_absent_uses_the_single_create_operation() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            let (_root, storage, registry, job, lease, context) =
                register_store_fixture("d9d3-c-f1-store-absent", "descriptor-a");
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);

            ensure_generation_store(&storage, &registry, &job, &lease, &context)
                .await
                .unwrap();
            assert_eq!(C_STORE_CREATE_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(
                storage
                    .load_generation_store_witness(&job.generation_id)
                    .unwrap()
                    .state,
                "ready"
            );
        });
    }

    #[test]
    fn d9d3_c_f1_recoverable_provider_resolution_preserves_attempt_and_resumes_same_job() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, profiles, secrets, coordinator, registry, server) =
                full_fixture(ServerBehavior::Success(3));
            profiles.set_fail_after_first_profile_read(true);
            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
            let gate = FencedVectorSyncCompositionGate::default();
            let first_guard = gate.acquire().await;
            let first_error = run_generation_rebuild_c(
                &storage,
                &runtime,
                &registry,
                "request-a",
                "owner-a",
                &first_guard,
            )
            .await
            .unwrap_err();
            drop(first_guard);

            assert_eq!(first_error.code, "D9D3_C_PROVIDER_UNAVAILABLE");
            assert!(first_error.recoverable);
            assert_eq!(server.request_count(), 0);
            let first_job = storage
                .load_generation_rebuild_job_by_request("request-a")
                .unwrap()
                .unwrap();
            let first_item = storage
                .list_generation_rebuild_items(&first_job.job_id)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            assert_eq!(first_job.status, "bulk_building");
            assert_eq!(first_job.generation_state, "building");
            assert_eq!(first_item.state, "processing");
            assert_eq!(first_item.io_phase, "reserved");
            assert_eq!(
                first_item.last_send_disposition.as_deref(),
                Some("definitely_not_sent")
            );
            let attempt_identity = (
                first_item.attempt_id.clone(),
                first_item.attempt_count,
                first_item.attempt_fence,
            );

            profiles.set_fail_after_first_profile_read(false);
            let second_guard = gate.acquire().await;
            let handoff = run_generation_rebuild_c(
                &storage,
                &runtime,
                &registry,
                "request-a",
                "owner-a",
                &second_guard,
            )
            .await
            .unwrap();
            drop(second_guard);

            let second_job = storage
                .load_generation_rebuild_job(&first_job.job_id)
                .unwrap();
            let second_item = storage
                .list_generation_rebuild_items(&first_job.job_id)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            assert_eq!(handoff.job_id, first_job.job_id);
            assert_eq!(handoff.generation_id, first_job.generation_id);
            assert_eq!(second_job.status, "catching_up");
            assert_eq!(second_job.generation_state, "building");
            assert_eq!(
                (
                    second_item.attempt_id.clone(),
                    second_item.attempt_count,
                    second_item.attempt_fence,
                ),
                attempt_identity
            );
            assert_eq!(second_item.state, "applied");
            assert_eq!(server.request_count(), 1);
            assert_eq!(C_STORE_CREATE_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(C_VECTOR_UPSERT_CALLS.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn d9d3_c_f1_provider_possibly_sent_has_no_second_provider_call() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            let (_root, storage, profiles, secrets, coordinator, registry, server) =
                full_fixture(ServerBehavior::CloseAfterRequest);
            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
            let gate = FencedVectorSyncCompositionGate::default();
            let guard = gate.acquire().await;
            let error = run_generation_rebuild_c(
                &storage,
                &runtime,
                &registry,
                "request-a",
                "owner-a",
                &guard,
            )
            .await
            .unwrap_err();
            drop(guard);

            assert_eq!(error.code, "GENERATION_REBUILD_PROVIDER_RESULT_UNKNOWN");
            assert!(error.recoverable);
            assert_eq!(server.request_count(), 1);
            let job = storage
                .load_generation_rebuild_job_by_request("request-a")
                .unwrap()
                .unwrap();
            let item = storage
                .list_generation_rebuild_items(&job.job_id)
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            assert_eq!(job.status, "failed");
            assert_eq!(job.generation_state, "failed");
            assert_eq!(item.state, "uncertain");
            assert_eq!(item.io_phase, "embedding_started");
            assert_eq!(item.last_send_disposition.as_deref(), Some("possibly_sent"));
            assert_eq!(item.canonical_document, None);
        });
    }

    #[test]
    fn d9d3_c_f1_vector_write_exact_recovery_finalizes_without_replay() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_METADATA_READ_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, _registry, _job, mut lease, context, store, reserved) =
                processing_fixture("d9d3-c-f1-vector-exact").await;
            storage
                .mark_generation_rebuild_embedding_started(&reserved, &lease)
                .unwrap();
            storage
                .mark_generation_rebuild_vector_write_started(&reserved, &lease)
                .unwrap();
            store
                .upsert_generation(
                    &context,
                    GenerationVectorRecord::try_new(
                        context.generation_id().clone(),
                        reserved.life_id.clone(),
                        reserved.memory_id.clone(),
                        reserved.memory_revision,
                        reserved.content_hash.clone(),
                        context.descriptor_hash().to_owned(),
                        vec![0.1, 0.2, 0.3],
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let item = storage
                .reserve_next_generation_rebuild_item("job-a", &lease)
                .unwrap()
                .unwrap();
            let job = storage.load_generation_rebuild_job("job-a").unwrap();
            let profiles = TestProfileRepository::new("http://127.0.0.1:9/v1");
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);

            process_item(
                &storage, &runtime, &store, &context, &job, &item, &mut lease, "owner-a",
            )
            .await
            .unwrap();

            let current_job = storage.load_generation_rebuild_job("job-a").unwrap();
            let current_item = storage
                .list_generation_rebuild_items("job-a")
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            assert_eq!(current_job.status, "bulk_building");
            assert_eq!(current_job.applied_item_count, 1);
            assert_eq!(current_item.state, "applied");
            assert_eq!(current_item.io_phase, "finalized");
            assert_eq!(current_item.canonical_document, None);
            assert_eq!(generation_item_count(&storage, "generation-a"), 1);
            assert_eq!(C_VECTOR_METADATA_READ_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(C_VECTOR_UPSERT_CALLS.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn d9d3_c_f1_vector_write_unclassifiable_fails_without_blind_replay() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_METADATA_READ_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, _registry, _job, mut lease, context, store, reserved) =
                processing_fixture("d9d3-c-f1-vector-unknown").await;
            storage
                .mark_generation_rebuild_embedding_started(&reserved, &lease)
                .unwrap();
            storage
                .mark_generation_rebuild_vector_write_started(&reserved, &lease)
                .unwrap();
            let item = storage
                .reserve_next_generation_rebuild_item("job-a", &lease)
                .unwrap()
                .unwrap();
            let job = storage.load_generation_rebuild_job("job-a").unwrap();
            let profiles = TestProfileRepository::new("http://127.0.0.1:9/v1");
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);

            let error = process_item(
                &storage, &runtime, &store, &context, &job, &item, &mut lease, "owner-a",
            )
            .await
            .unwrap_err();
            assert_eq!(error.code, "GENERATION_REBUILD_PROVIDER_RESULT_UNKNOWN");
            assert_eq!(C_VECTOR_METADATA_READ_CALLS.load(Ordering::SeqCst), 1);
            assert_eq!(C_VECTOR_UPSERT_CALLS.load(Ordering::SeqCst), 0);
            let current_job = storage.load_generation_rebuild_job("job-a").unwrap();
            let current_item = storage
                .list_generation_rebuild_items("job-a")
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            assert_eq!(current_job.status, "failed");
            assert_eq!(current_job.generation_state, "failed");
            assert_eq!(current_item.state, "uncertain");
            assert_eq!(current_item.canonical_document, None);
        });
    }

    #[test]
    fn d9d3_d_f1_promotion_classifier_rejects_missing_or_resurrected_resolution_evidence() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, profiles, secrets, coordinator, registry, _server) =
                full_fixture(ServerBehavior::Success(3));
            let database = storage.test_database_main_path().unwrap();
            let outbox_id: i64;
            {
                let connection = open_authorized_test_connection(&database).unwrap();
                connection
                    .execute_batch(
                        "INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch)
                         VALUES ('source-g1','source-descriptor',3,'active',7);
                         UPDATE memory_vector_generation_authority SET active_generation_id='source-g1' WHERE singleton=1;
                         UPDATE memory_vector_sync_mutation_clock SET last_sequence=2 WHERE singleton=1;
                         INSERT INTO memory_vector_sync_outbox (life_id,memory_id,desired_action,mutation_sequence,target_revision,target_content_hash,migration_disposition)
                         VALUES ('life-a','memory-c','delete',2,NULL,NULL,NULL);
                         INSERT INTO memory_vector_late_delete_resolution
                           (outbox_id,life_id,memory_id,mutation_sequence,claimed_generation_id,embedding_descriptor_id,embedding_dimension,captured_generation_state,
                            witness_attempt_ordinal,witness_claim_epoch,witness_marked_claim_epoch,witness_send_disposition,witness_age_anchor_at,captured_generation_authority_epoch,state,created_at,updated_at)
                         SELECT o.id,'life-a','memory-c',2,'source-g1','source-descriptor',3,'active',1,7,7,'possibly_sent','2026-01-01T00:00:00.000Z',7,'pending','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z'
                         FROM memory_vector_sync_outbox o WHERE o.memory_id='memory-c';",
                    )
                    .unwrap();
                outbox_id = connection
                    .query_row(
                        "SELECT id FROM memory_vector_sync_outbox WHERE memory_id='memory-c'",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                drop(connection);
            }

            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
            let gate = FencedVectorSyncCompositionGate::default();
            let guard = gate.acquire().await;
            let handoff = run_generation_rebuild_c(
                &storage,
                &runtime,
                &registry,
                "request-a",
                "owner-a",
                &guard,
            )
            .await
            .unwrap();
            arm_promotion_fault_for_test(PromotionFault::AfterCommitUnknown);
            // D reclassifies the unknown commit against durable state and
            // returns the completed job; the promotion really committed.
            let _completed = run_generation_rebuild_d(
                &storage,
                &runtime,
                &registry,
                &handoff,
                "owner-a",
                std::time::Instant::now() + Duration::from_secs(10),
                &guard,
            )
            .await
            .unwrap();
            let job = storage
                .load_generation_rebuild_job(&handoff.job_id)
                .unwrap();
            assert_eq!(job.status, "completed");
            let operation_id = job
                .promotion_operation_id
                .clone()
                .expect("promotion identity");
            let target = job.promotion_sequence.expect("promotion sequence");

            // The otherwise complete postimage classifies as Committed.
            assert_eq!(
                storage
                    .classify_generation_rebuild_promotion_commit(
                        &job.job_id,
                        &operation_id,
                        target,
                    )
                    .unwrap(),
                GenerationRebuildPromotionCommitClassification::Committed
            );

            // Corrupt exactly one promotion-resolution fact: delete the outbox
            // resolution evidence.  The classifier must fail closed without
            // retrying or guessing.
            let connection = open_authorized_test_connection(&database).unwrap();
            let removed = connection
                .execute(
                    "DELETE FROM memory_vector_generation_rebuild_resolution
                     WHERE job_id=?1 AND source_kind='outbox'",
                    [job.job_id.as_str()],
                )
                .unwrap();
            assert!(removed >= 1);
            drop(connection);
            assert_eq!(
                storage
                    .classify_generation_rebuild_promotion_commit(
                        &job.job_id,
                        &operation_id,
                        target,
                    )
                    .unwrap(),
                GenerationRebuildPromotionCommitClassification::RecoveryRequired
            );

            // Restore the outbox resolution (the promotion-only evidence set is
            // complete again) and prove the committed classification returns.
            // The restored row must carry the exact promotion-completion
            // timestamp, matching the classifier's operation-time invariant.
            let connection = open_authorized_test_connection(&database).unwrap();
            let completed_at: String = connection
                .query_row(
                    "SELECT completed_at FROM memory_vector_generation_rebuild_job WHERE job_id=?1",
                    [job.job_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO memory_vector_generation_rebuild_resolution
                     (job_id,source_kind,source_row_id,life_id,memory_id,mutation_sequence,source_generation_id,source_generation_authority_epoch,disposition,replacement_mutation_sequence,created_at)
                     VALUES (?1,'outbox',?2,'life-a','memory-c',2,NULL,NULL,'legacy_rebuild_resolved',NULL,?3)",
                    rusqlite::params![job.job_id.as_str(), outbox_id, completed_at],
                )
                .unwrap();
            drop(connection);
            assert_eq!(
                storage
                    .classify_generation_rebuild_promotion_commit(
                        &job.job_id,
                        &operation_id,
                        target,
                    )
                    .unwrap(),
                GenerationRebuildPromotionCommitClassification::Committed
            );

            // Corrupt a second promotion-resolution fact: resurrect the selected
            // Late Delete row out of its terminal resolved_rebuilt state.
            let connection = open_authorized_test_connection(&database).unwrap();
            let resurrected = connection
                .execute(
                    "UPDATE memory_vector_late_delete_resolution
                     SET state='pending',resolved_at=NULL
                     WHERE life_id='life-a' AND memory_id='memory-c'",
                    [],
                )
                .unwrap();
            assert_eq!(resurrected, 1);
            drop(connection);
            assert_eq!(
                storage
                    .classify_generation_rebuild_promotion_commit(
                        &job.job_id,
                        &operation_id,
                        target,
                    )
                    .unwrap(),
                GenerationRebuildPromotionCommitClassification::RecoveryRequired
            );
        });
    }

    #[test]
    fn d9d3_d_f1_failed_compensation_never_releases_guard_while_g2_nonterminal() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, _profiles, secrets, coordinator, registry, server) =
                full_fixture(ServerBehavior::Success(3));
            // The orchestrator resolves its embedding provider from the storage
            // repository, so register a real profile that points at the mock
            // embedding server and make it active.
            let profile = ModelProfileService::new(&storage)
                .create(CreateModelProfileRequest {
                    purpose: ModelPurpose::Embedding,
                    provider_kind: ModelProviderKind::OpenaiCompatible,
                    display_name: "D9D3-F1 compensated embedding profile".into(),
                    base_url: server.base_url.clone(),
                    model_name: "embedding-model".into(),
                    temperature: None,
                    max_tokens: None,
                    embedding_dimension: Some(3),
                })
                .unwrap();
            ModelProfileService::new(&storage)
                .set_active(SetActiveModelProfileRequest {
                    purpose: ModelPurpose::Embedding,
                    profile_id: profile.id.clone(),
                })
                .unwrap();
            secrets
                .set_secret(
                    &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, &profile.id)
                        .unwrap(),
                    SecretValue::new("d9d3-f1-compensation-key".into()).unwrap(),
                )
                .unwrap();
            let gate = Arc::new(FencedVectorSyncCompositionGate::default());
            let guard = gate.acquire().await;
            let database = storage.test_database_main_path().unwrap();

            arm_promotion_fault_for_test(PromotionFault::BeforeCommit);
            fail_next_outer_compensation_for_test();
            let (first_failure_tx, first_failure_rx) = std::sync::mpsc::channel();
            set_outer_compensation_failure_signal_for_test(first_failure_tx);
            let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
            let competitor_gate = Arc::clone(&gate);

            // The competitor lives outside the scope: it blocks on the
            // composition gate and must stay blocked until the original guard
            // is released explicitly after the pipeline reaches terminal state.
            let competitor = std::thread::spawn(move || {
                tauri::async_runtime::block_on(async move {
                    let _competitor_guard = competitor_gate.acquire().await;
                    acquired_tx.send(()).unwrap();
                })
            });

            let pipeline_result = std::thread::scope(|scope| {
                let pipeline = scope.spawn(|| {
                    tauri::async_runtime::block_on(run_vector_generation_rebuild_guarded(
                        &storage,
                        &secrets,
                        &coordinator,
                        &registry,
                        &guard,
                        "request-a",
                        Duration::from_secs(10),
                    ))
                });

                // Wait until the first compensation attempt has failed while the
                // guard is still held; the job must still be nonterminal and the
                // competitor must remain blocked.
                first_failure_rx
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap();
                std::thread::yield_now();
                assert!(
                    acquired_rx.try_recv().is_err(),
                    "a competitor must not acquire the gate while the candidate is nonterminal"
                );
                let job = storage
                    .load_generation_rebuild_job_by_request("request-a")
                    .unwrap()
                    .expect("the job must exist while awaiting durable terminal state");
                assert!(
                    matches!(
                        job.status.as_str(),
                        "registered"
                            | "snapshotting"
                            | "bulk_building"
                            | "catching_up"
                            | "verifying"
                            | "ready"
                    ),
                    "the job must still be nonterminal after the first compensation failure"
                );

                // Let the pipeline finish; it reports the original failure.  The
                // retried compensation has now made the world durably terminal.
                let result = pipeline.join().unwrap();
                assert!(
                    result.is_err(),
                    "the pipeline must report its original failure"
                );
                let job = storage
                    .load_generation_rebuild_job_by_request("request-a")
                    .unwrap()
                    .expect("job must exist after compensation");
                assert_eq!(job.status, "failed");
                result
            });

            // Only after durable terminal state is confirmed may the original
            // guard be released; the competitor then acquires the gate.
            drop(guard);
            acquired_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            competitor.join().unwrap();
            assert!(pipeline_result.is_err());
            let job = storage
                .load_generation_rebuild_job_by_request("request-a")
                .unwrap()
                .expect("the failed job must persist");
            let connection = open_authorized_test_connection(&database).unwrap();
            let generation_state: (String, i64) = connection
                .query_row(
                    "SELECT state, authority_epoch FROM memory_vector_generation WHERE generation_id=?1",
                    [job.generation_id.as_str()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(generation_state.0, "failed");
            drop(connection);
        });
    }

    #[test]
    fn d9d3_c_f1_cancel_before_next_external_io_makes_zero_provider_or_lance_calls() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_METADATA_READ_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, _registry, _job, mut lease, context, store, reserved) =
                processing_fixture("d9d3-c-f1-cancel").await;
            let server = EmbeddingServer::new(ServerBehavior::Success(3));
            let profiles = TestProfileRepository::new(&server.base_url);
            let secrets = InMemorySecretStore::new();
            secrets
                .set_secret(
                    &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, "profile-a")
                        .unwrap(),
                    SecretValue::new("d9b-c-f1-cancel-key".into()).unwrap(),
                )
                .unwrap();
            let coordinator = ModelRuntimeCoordinator::default();
            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
            storage.request_generation_rebuild_cancel("job-a").unwrap();
            let job = storage.load_generation_rebuild_job("job-a").unwrap();

            let error = process_item(
                &storage, &runtime, &store, &context, &job, &reserved, &mut lease, "owner-a",
            )
            .await
            .unwrap_err();
            assert_eq!(error.code, "GENERATION_REBUILD_CANCELLED");
            assert_eq!(server.request_count(), 0);
            assert_eq!(C_VECTOR_UPSERT_CALLS.load(Ordering::SeqCst), 0);
            assert_eq!(C_VECTOR_METADATA_READ_CALLS.load(Ordering::SeqCst), 0);
            let current_job = storage.load_generation_rebuild_job("job-a").unwrap();
            assert_eq!(current_job.status, "cancelled");
            assert_eq!(current_job.generation_state, "failed");
        });
    }

    #[test]
    fn d9d3_d_f2_recovery_required_holds_gate_until_exact_committed_restored() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, _profiles, secrets, coordinator, registry, server) =
                full_fixture(ServerBehavior::Success(3));
            let database = storage.test_database_main_path().unwrap();
            // The orchestrator resolves its embedding provider from the storage
            // repository, so register a real profile that points at the mock
            // embedding server and make it active.
            let profile = ModelProfileService::new(&storage)
                .create(CreateModelProfileRequest {
                    purpose: ModelPurpose::Embedding,
                    provider_kind: ModelProviderKind::OpenaiCompatible,
                    display_name: "D9D3-F2 recovery embedding profile".into(),
                    base_url: server.base_url.clone(),
                    model_name: "embedding-model".into(),
                    temperature: None,
                    max_tokens: None,
                    embedding_dimension: Some(3),
                })
                .unwrap();
            ModelProfileService::new(&storage)
                .set_active(SetActiveModelProfileRequest {
                    purpose: ModelPurpose::Embedding,
                    profile_id: profile.id.clone(),
                })
                .unwrap();
            secrets
                .set_secret(
                    &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, &profile.id)
                        .unwrap(),
                    SecretValue::new("d9d3-f2-recovery-key".into()).unwrap(),
                )
                .unwrap();
            // Seed one covered outbox Delete and one Late Delete row so the
            // promotion writes real resolution evidence (the injected corruption
            // needs a resolution row to corrupt).
            {
                let connection = open_authorized_test_connection(&database).unwrap();
                connection
                    .execute_batch(
                        "INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch)
                         VALUES ('source-g1','source-descriptor',3,'active',7);
                         UPDATE memory_vector_generation_authority SET active_generation_id='source-g1' WHERE singleton=1;
                         UPDATE memory_vector_sync_mutation_clock SET last_sequence=2 WHERE singleton=1;
                         INSERT INTO memory_vector_sync_outbox (life_id,memory_id,desired_action,mutation_sequence,target_revision,target_content_hash,migration_disposition)
                         VALUES ('life-a','memory-c','delete',2,NULL,NULL,NULL);
                         INSERT INTO memory_vector_late_delete_resolution
                           (outbox_id,life_id,memory_id,mutation_sequence,claimed_generation_id,embedding_descriptor_id,embedding_dimension,captured_generation_state,
                            witness_attempt_ordinal,witness_claim_epoch,witness_marked_claim_epoch,witness_send_disposition,witness_age_anchor_at,captured_generation_authority_epoch,state,created_at,updated_at)
                         SELECT o.id,'life-a','memory-c',2,'source-g1','source-descriptor',3,'active',1,7,7,'possibly_sent','2026-01-01T00:00:00.000Z',7,'pending','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z'
                         FROM memory_vector_sync_outbox o WHERE o.memory_id='memory-c';",
                    )
                    .unwrap();
                drop(connection);
            }

            let gate = Arc::new(FencedVectorSyncCompositionGate::default());
            let guard = gate.acquire().await;

            // The promotion really commits, but the D layer observes a controlled
            // mixed postimage (after COMMIT, before classification) and must
            // surface a sealed PromotionRecoveryRequired classification.
            arm_promotion_fault_for_test(PromotionFault::AfterCommitUnknown);
            crate::storage::arm_promotion_recovery_corruption_for_test();
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            set_promotion_recovery_entered_signal_for_test(entered_tx);
            let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
            let competitor_gate = Arc::clone(&gate);
            let competitor = std::thread::spawn(move || {
                tauri::async_runtime::block_on(async move {
                    let _competitor_guard = competitor_gate.acquire().await;
                    acquired_tx.send(()).unwrap();
                })
            });

            let pipeline_result = std::thread::scope(|scope| {
                let pipeline = scope.spawn(|| {
                    tauri::async_runtime::block_on(run_vector_generation_rebuild_guarded(
                        &storage,
                        &secrets,
                        &coordinator,
                        &registry,
                        &guard,
                        "request-a",
                        Duration::from_secs(10),
                    ))
                });

                // The outer owner entered the promotion-recovery fail-closed path.
                entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                std::thread::yield_now();
                assert!(
                    acquired_rx.try_recv().is_err(),
                    "a competitor must not acquire the gate while the promotion world is mixed"
                );
                let job = storage
                    .load_generation_rebuild_job_by_request("request-a")
                    .unwrap()
                    .expect("the committed job must exist");
                assert_eq!(
                    job.status, "completed",
                    "the job row still says completed even though the world is mixed"
                );
                let operation_id = job
                    .promotion_operation_id
                    .clone()
                    .expect("promotion identity");
                let target = job.promotion_sequence.expect("promotion sequence");
                assert!(
                    matches!(
                        storage
                            .classify_generation_rebuild_promotion_commit(
                                &job.job_id,
                                &operation_id,
                                target,
                            )
                            .unwrap(),
                        GenerationRebuildPromotionCommitClassification::RecoveryRequired
                    ),
                    "the mixed world must still classify as RecoveryRequired"
                );

                // No failed-generation compensation may have run against the
                // possibly-active G2: it is still active at the promoted epoch.
                let connection = open_authorized_test_connection(&database).unwrap();
                let generation_state: (String, i64) = connection
                    .query_row(
                        "SELECT state, authority_epoch FROM memory_vector_generation
                         WHERE generation_id=(SELECT generation_id FROM memory_vector_generation_rebuild_job WHERE job_id=?1)",
                        [job.job_id.as_str()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                assert_eq!(generation_state.0, "active");
                assert_eq!(generation_state.1, 2);

                // Restore the exact committed postimage (clear the injected
                // replacement sequence).  The outer owner may then reclassify
                // exact Committed and the pipeline scope may end.
                connection
                    .execute(
                        "UPDATE memory_vector_generation_rebuild_resolution
                         SET replacement_mutation_sequence=NULL
                         WHERE job_id=?1 AND source_kind='outbox'",
                        [job.job_id.as_str()],
                    )
                    .unwrap();
                drop(connection);

                let result = pipeline.join().unwrap();
                // After the exact Committed postimage is proven again, the
                // pipeline returns the authoritative completed job.
                assert!(
                    result.is_ok(),
                    "the pipeline must resolve to Ok once exact Committed"
                );
                let completed = result.as_ref().expect("authoritative completion");
                assert_eq!(completed.status, "completed");
                result
            });

            // Only after the exact committed image is proven may the guard be
            // released; the competitor then acquires.
            drop(guard);
            acquired_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            competitor.join().unwrap();
            assert!(
                pipeline_result.is_ok(),
                "the pipeline returns authoritative completion"
            );
        });
    }

    #[test]
    fn d9d3_d_f2_committed_classifier_rejects_resolution_tuple_corruptions() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, profiles, secrets, coordinator, registry, _server) =
                full_fixture(ServerBehavior::Success(3));
            let database = storage.test_database_main_path().unwrap();
            {
                let connection = open_authorized_test_connection(&database).unwrap();
                connection
                    .execute_batch(
                        "INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch)
                         VALUES ('source-g1','source-descriptor',3,'active',7);
                         UPDATE memory_vector_generation_authority SET active_generation_id='source-g1' WHERE singleton=1;
                         UPDATE memory_vector_sync_mutation_clock SET last_sequence=2 WHERE singleton=1;
                         INSERT INTO memory_vector_sync_outbox (life_id,memory_id,desired_action,mutation_sequence,target_revision,target_content_hash,migration_disposition)
                         VALUES ('life-a','memory-c','delete',2,NULL,NULL,NULL);
                         INSERT INTO memory_vector_late_delete_resolution
                           (outbox_id,life_id,memory_id,mutation_sequence,claimed_generation_id,embedding_descriptor_id,embedding_dimension,captured_generation_state,
                            witness_attempt_ordinal,witness_claim_epoch,witness_marked_claim_epoch,witness_send_disposition,witness_age_anchor_at,captured_generation_authority_epoch,state,created_at,updated_at)
                         SELECT o.id,'life-a','memory-c',2,'source-g1','source-descriptor',3,'active',1,7,7,'possibly_sent','2026-01-01T00:00:00.000Z',7,'pending','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z'
                         FROM memory_vector_sync_outbox o WHERE o.memory_id='memory-c';",
                    )
                    .unwrap();
                drop(connection);
            }
            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
            let gate = FencedVectorSyncCompositionGate::default();
            let guard = gate.acquire().await;
            let handoff = run_generation_rebuild_c(
                &storage,
                &runtime,
                &registry,
                "request-a",
                "owner-a",
                &guard,
            )
            .await
            .unwrap();
            arm_promotion_fault_for_test(PromotionFault::AfterCommitUnknown);
            let _completed = run_generation_rebuild_d(
                &storage,
                &runtime,
                &registry,
                &handoff,
                "owner-a",
                std::time::Instant::now() + Duration::from_secs(10),
                &guard,
            )
            .await
            .unwrap();
            let job = storage
                .load_generation_rebuild_job(&handoff.job_id)
                .unwrap();
            assert_eq!(job.status, "completed");
            let job_id = job.job_id.clone();
            let operation_id = job.promotion_operation_id.clone().unwrap();
            let target = job.promotion_sequence.unwrap();

            let connection = open_authorized_test_connection(&database).unwrap();
            let completed_at: String = connection
                .query_row(
                    "SELECT completed_at FROM memory_vector_generation_rebuild_job WHERE job_id=?1",
                    [job_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            let classify = || {
                storage
                    .classify_generation_rebuild_promotion_commit(&job_id, &operation_id, target)
                    .unwrap()
            };
            use GenerationRebuildPromotionCommitClassification as C;
            assert_eq!(classify(), C::Committed);

            // Attack 1: wrong outbox resolution disposition (failed_generation_requeued
            // must never masquerade as promotion completion evidence).
            connection
                .execute(
                    "UPDATE memory_vector_generation_rebuild_resolution
                     SET disposition='failed_generation_requeued'
                     WHERE job_id=?1 AND source_kind='outbox'",
                    [job_id.as_str()],
                )
                .unwrap();
            assert_eq!(classify(), C::RecoveryRequired);
            connection
                .execute(
                    "UPDATE memory_vector_generation_rebuild_resolution
                     SET disposition='legacy_rebuild_resolved'
                     WHERE job_id=?1 AND source_kind='outbox'",
                    [job_id.as_str()],
                )
                .unwrap();
            assert_eq!(classify(), C::Committed);

            // Attack 2: illegal non-NULL replacement_mutation_sequence on a
            // promotion-owned resolution.
            connection
                .execute(
                    "UPDATE memory_vector_generation_rebuild_resolution
                     SET replacement_mutation_sequence=999
                     WHERE job_id=?1 AND source_kind='outbox'",
                    [job_id.as_str()],
                )
                .unwrap();
            assert_eq!(classify(), C::RecoveryRequired);
            connection
                .execute(
                    "UPDATE memory_vector_generation_rebuild_resolution
                     SET replacement_mutation_sequence=NULL
                     WHERE job_id=?1 AND source_kind='outbox'",
                    [job_id.as_str()],
                )
                .unwrap();
            assert_eq!(classify(), C::Committed);

            // Attack 3: delete the selected Late Delete resolution while its LD
            // row stays resolved_rebuilt (the two-way proof must catch it).
            connection
                .execute(
                    "DELETE FROM memory_vector_generation_rebuild_resolution
                     WHERE job_id=?1 AND source_kind='late_delete'",
                    [job_id.as_str()],
                )
                .unwrap();
            assert_eq!(classify(), C::RecoveryRequired);
            // Restore the exact committed LD resolution reconstructed solely from
            // frozen Schema18 facts (proving the two-way evidence is rebuildable).
            connection
                .execute(
                    "INSERT INTO memory_vector_generation_rebuild_resolution
                     (job_id,source_kind,source_row_id,life_id,memory_id,mutation_sequence,source_generation_id,source_generation_authority_epoch,disposition,replacement_mutation_sequence,created_at)
                     SELECT ?1,'late_delete',ld.resolution_id,ld.life_id,ld.memory_id,ld.mutation_sequence,
                            ld.claimed_generation_id,ld.captured_generation_authority_epoch,
                            'resolved_by_rebuild',NULL,?2
                     FROM memory_vector_late_delete_resolution ld
                     WHERE ld.life_id='life-a' AND ld.memory_id='memory-c'",
                    rusqlite::params![job_id.as_str(), completed_at.as_str()],
                )
                .unwrap();
            assert_eq!(classify(), C::Committed);

            // Attack 4: corrupt a Late Delete resolution tuple (source generation
            // authority epoch and disposition) away from its source LD row.
            connection
                .execute(
                    "UPDATE memory_vector_generation_rebuild_resolution
                     SET source_generation_authority_epoch=1, disposition='legacy_rebuild_resolved'
                     WHERE job_id=?1 AND source_kind='late_delete'",
                    [job_id.as_str()],
                )
                .unwrap();
            assert_eq!(classify(), C::RecoveryRequired);
            connection
                .execute(
                    "UPDATE memory_vector_generation_rebuild_resolution
                     SET source_generation_authority_epoch=7, disposition='resolved_by_rebuild'
                     WHERE job_id=?1 AND source_kind='late_delete'",
                    [job_id.as_str()],
                )
                .unwrap();
            assert_eq!(classify(), C::Committed);
            drop(connection);
        });
    }

    /// Registers a real storage-backed embedding profile pointing at the mock
    /// server and makes it active, so the production orchestrator (which
    /// resolves providers from the storage repository) can run the C/D phases.
    fn register_storage_embedding_profile(
        storage: &StorageService,
        secrets: &InMemorySecretStore,
        server: &EmbeddingServer,
    ) {
        let profile = ModelProfileService::new(storage)
            .create(CreateModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "D9D3-F3 embedding profile".into(),
                base_url: server.base_url.clone(),
                model_name: "embedding-model".into(),
                temperature: None,
                max_tokens: None,
                embedding_dimension: Some(3),
            })
            .unwrap();
        ModelProfileService::new(storage)
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                profile_id: profile.id.clone(),
            })
            .unwrap();
        secrets
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, &profile.id).unwrap(),
                SecretValue::new("d9d3-f3-profile-key".into()).unwrap(),
            )
            .unwrap();
    }

    /// Seeds a covered outbox Delete and one Late Delete row so a promotion
    /// writes real outbox + Late Delete resolution evidence (used by the F2/F3
    /// mixed-world scenarios that need a corruptable resolution row).
    fn seed_recovery_postimage(_storage: &StorageService, database: &std::path::Path) {
        let connection = open_authorized_test_connection(database).unwrap();
        connection
            .execute_batch(
                "INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch)
                 VALUES ('source-g1','source-descriptor',3,'active',7);
                 UPDATE memory_vector_generation_authority SET active_generation_id='source-g1' WHERE singleton=1;
                 UPDATE memory_vector_sync_mutation_clock SET last_sequence=2 WHERE singleton=1;
                 INSERT INTO memory_vector_sync_outbox (life_id,memory_id,desired_action,mutation_sequence,target_revision,target_content_hash,migration_disposition)
                 VALUES ('life-a','memory-c','delete',2,NULL,NULL,NULL);
                 INSERT INTO memory_vector_late_delete_resolution
                   (outbox_id,life_id,memory_id,mutation_sequence,claimed_generation_id,embedding_descriptor_id,embedding_dimension,captured_generation_state,
                    witness_attempt_ordinal,witness_claim_epoch,witness_marked_claim_epoch,witness_send_disposition,witness_age_anchor_at,captured_generation_authority_epoch,state,created_at,updated_at)
                 SELECT o.id,'life-a','memory-c',2,'source-g1','source-descriptor',3,'active',1,7,7,'possibly_sent','2026-01-01T00:00:00.000Z',7,'pending','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z'
                 FROM memory_vector_sync_outbox o WHERE o.memory_id='memory-c';",
            )
            .unwrap();
        drop(connection);
    }

    /// Drives C then D (direct storage/memory phases) so a real promotion
    /// commits; with the corruption seam armed the D layer observes a
    /// deterministic mixed postimage and returns the sealed
    /// GENERATION_REBUILD_PROMOTION_RECOVERY_REQUIRED classification while the
    /// job row stays `completed`.
    async fn commit_mixed_promotion_through_d(
        storage: &StorageService,
        profiles: &TestProfileRepository,
        secrets: &InMemorySecretStore,
        coordinator: &ModelRuntimeCoordinator,
        registry: &LanceDbVectorStoreRegistry,
        guard: &FencedVectorSyncCompositionGuard<'_>,
    ) -> (std::string::String, std::string::String) {
        let runtime = runtime_fixture(profiles, secrets, coordinator);
        let handoff =
            run_generation_rebuild_c(storage, &runtime, registry, "request-a", "owner-a", guard)
                .await
                .unwrap();
        arm_promotion_fault_for_test(PromotionFault::AfterCommitUnknown);
        let error = run_generation_rebuild_d(
            storage,
            &runtime,
            registry,
            &handoff,
            "owner-a",
            std::time::Instant::now() + Duration::from_secs(10),
            guard,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "GENERATION_REBUILD_PROMOTION_RECOVERY_REQUIRED");
        let job = storage
            .load_generation_rebuild_job(&handoff.job_id)
            .unwrap();
        assert_eq!(job.status, "completed");
        (job.job_id, job.generation_id)
    }

    #[test]
    fn d9d3_d_f3_restart_does_not_trust_completed_mixed_world() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, profiles, secrets, coordinator, registry, _server) =
                full_fixture(ServerBehavior::Success(3));
            let database = storage.test_database_main_path().unwrap();

            // Phase 1 (original runtime/gate scope): seed, then a real promotion
            // really commits while the D layer observes the controlled mixed
            // postimage; the job row persists as `completed`.  The original gate
            // scope then ends (the process-local gate does not survive death).
            seed_recovery_postimage(&storage, &database);
            crate::storage::arm_promotion_recovery_corruption_for_test();
            let (job_id, generation_id) = {
                let gate = FencedVectorSyncCompositionGate::default();
                let guard = gate.acquire().await;
                commit_mixed_promotion_through_d(
                    &storage,
                    &profiles,
                    &secrets,
                    &coordinator,
                    &registry,
                    &guard,
                )
                .await
            };

            // Phase 2 (new process/gate): the same request resumes through the
            // production full-pipeline entry.  It must NOT trust the completed
            // row: exact classification stays RecoveryRequired, the NEW gate is
            // held (fail-closed), and no failed-generation compensation runs.
            let gate2 = Arc::new(FencedVectorSyncCompositionGate::default());
            let guard2 = gate2.acquire().await;
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            set_promotion_recovery_entered_signal_for_test(entered_tx);
            let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
            let competitor_gate = Arc::clone(&gate2);
            let competitor = std::thread::spawn(move || {
                tauri::async_runtime::block_on(async move {
                    let _competitor_guard = competitor_gate.acquire().await;
                    acquired_tx.send(()).unwrap();
                })
            });

            let pipeline_result = std::thread::scope(|scope| {
                let pipeline = scope.spawn(|| {
                    tauri::async_runtime::block_on(run_vector_generation_rebuild_guarded(
                        &storage,
                        &secrets,
                        &coordinator,
                        &registry,
                        &guard2,
                        "request-a",
                        Duration::from_secs(10),
                    ))
                });

                entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                std::thread::yield_now();
                assert!(
                    acquired_rx.try_recv().is_err(),
                    "a competitor on the NEW gate must stay blocked while the world is mixed"
                );
                let job = storage
                    .load_generation_rebuild_job_by_request("request-a")
                    .unwrap()
                    .expect("the completed job must exist");
                assert_eq!(job.status, "completed");
                assert_eq!(job.generation_id, generation_id);
                let operation_id = job.promotion_operation_id.clone().unwrap();
                let target = job.promotion_sequence.unwrap();
                assert!(matches!(
                    storage
                        .classify_generation_rebuild_promotion_commit(
                            &job.job_id,
                            &operation_id,
                            target,
                        )
                        .unwrap(),
                    GenerationRebuildPromotionCommitClassification::RecoveryRequired
                ));
                // No failed-generation compensation: the possibly-active G2 is
                // still active at the promoted epoch.
                let connection = open_authorized_test_connection(&database).unwrap();
                let generation_state: (String, i64) = connection
                    .query_row(
                        "SELECT state, authority_epoch FROM memory_vector_generation
                         WHERE generation_id=?1",
                        [generation_id.as_str()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                assert_eq!(generation_state.0, "active");

                // Test cleanup: restore the exact committed postimage.  Exact
                // reclassification now permits the resumed call to finish with
                // authoritative completion.
                connection
                    .execute(
                        "UPDATE memory_vector_generation_rebuild_resolution
                         SET replacement_mutation_sequence=NULL
                         WHERE job_id=?1 AND source_kind='outbox'",
                        [job_id.as_str()],
                    )
                    .unwrap();
                drop(connection);

                let result = pipeline.join().unwrap();
                let completed = result
                    .as_ref()
                    .expect("authoritative completion after exact Committed");
                assert_eq!(completed.status, "completed");
                assert_eq!(completed.job_id, job_id);
                result
            });

            drop(guard2);
            acquired_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            competitor.join().unwrap();
            assert!(pipeline_result.is_ok());
        });
    }

    #[test]
    fn d9d3_d_f3_exact_completed_resume_returns_success() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, profiles, secrets, coordinator, registry, _server) =
                full_fixture(ServerBehavior::Success(3));
            let database = storage.test_database_main_path().unwrap();

            // Persist an EXACT completed promotion (no corruption seam armed).
            seed_recovery_postimage(&storage, &database);
            let (job_id, generation_id, operation_id_first) = {
                let gate = FencedVectorSyncCompositionGate::default();
                let guard = gate.acquire().await;
                let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
                let handoff = run_generation_rebuild_c(
                    &storage,
                    &runtime,
                    &registry,
                    "request-a",
                    "owner-a",
                    &guard,
                )
                .await
                .unwrap();
                arm_promotion_fault_for_test(PromotionFault::AfterCommitUnknown);
                let completed = run_generation_rebuild_d(
                    &storage,
                    &runtime,
                    &registry,
                    &handoff,
                    "owner-a",
                    std::time::Instant::now() + Duration::from_secs(10),
                    &guard,
                )
                .await
                .unwrap();
                assert_eq!(completed.status, "completed");
                (
                    completed.job_id.clone(),
                    completed.generation_id.clone(),
                    completed.promotion_operation_id.clone(),
                )
            };

            // Simulate a new process/gate: resume the SAME request through the
            // production full-pipeline entry.  Exact classification returns the
            // existing completed job idempotently: no new generation, no new
            // promotion, no new Attempt.
            let gate2 = Arc::new(FencedVectorSyncCompositionGate::default());
            let guard2 = gate2.acquire().await;
            let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
            let competitor_gate = Arc::clone(&gate2);
            let competitor = std::thread::spawn(move || {
                tauri::async_runtime::block_on(async move {
                    let _competitor_guard = competitor_gate.acquire().await;
                    acquired_tx.send(()).unwrap();
                })
            });

            let pipeline_result = std::thread::scope(|scope| {
                let pipeline = scope.spawn(|| {
                    tauri::async_runtime::block_on(run_vector_generation_rebuild_guarded(
                        &storage,
                        &secrets,
                        &coordinator,
                        &registry,
                        &guard2,
                        "request-a",
                        Duration::from_secs(10),
                    ))
                });
                pipeline.join().unwrap()
            });

            let resumed = pipeline_result.expect("exact Committed resume returns success");
            assert_eq!(resumed.status, "completed");
            assert_eq!(resumed.job_id, job_id);
            assert_eq!(resumed.generation_id, generation_id);
            assert_eq!(
                resumed.promotion_operation_id, operation_id_first,
                "no promotion replay on exact resume"
            );

            // No new generation, no new Attempt, no new resolution for the job.
            let connection = open_authorized_test_connection(&database).unwrap();
            let generation_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM memory_vector_generation WHERE generation_id=?1",
                    [generation_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(generation_count, 1);
            let catchup_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM memory_vector_generation_rebuild_catchup_item WHERE job_id=?1",
                    [job_id.as_str()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(catchup_count, 1);
            drop(connection);

            drop(guard2);
            acquired_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            competitor.join().unwrap();
        });
    }

    #[test]
    fn d9d3_d_f3_d_internal_completed_bypass_is_closed() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, profiles, secrets, coordinator, registry, _server) =
                full_fixture(ServerBehavior::Success(3));
            let database = storage.test_database_main_path().unwrap();
            seed_recovery_postimage(&storage, &database);
            crate::storage::arm_promotion_recovery_corruption_for_test();
            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
            let gate = FencedVectorSyncCompositionGate::default();
            let guard = gate.acquire().await;
            let handoff = run_generation_rebuild_c(
                &storage,
                &runtime,
                &registry,
                "request-a",
                "owner-a",
                &guard,
            )
            .await
            .unwrap();
            arm_promotion_fault_for_test(PromotionFault::AfterCommitUnknown);
            let first = run_generation_rebuild_d(
                &storage,
                &runtime,
                &registry,
                &handoff,
                "owner-a",
                std::time::Instant::now() + Duration::from_secs(10),
                &guard,
            )
            .await
            .unwrap_err();
            assert_eq!(first.code, "GENERATION_REBUILD_PROMOTION_RECOVERY_REQUIRED");
            let job = storage
                .load_generation_rebuild_job(&handoff.job_id)
                .unwrap();
            assert_eq!(job.status, "completed");
            let operation_id = job.promotion_operation_id.clone().unwrap();

            // The D internal completed fast-path must NOT return the mixed job.
            let second = run_generation_rebuild_d(
                &storage,
                &runtime,
                &registry,
                &handoff,
                "owner-a",
                std::time::Instant::now() + Duration::from_secs(10),
                &guard,
            )
            .await
            .unwrap_err();
            assert_eq!(
                second.code,
                "GENERATION_REBUILD_PROMOTION_RECOVERY_REQUIRED"
            );

            // Restore the exact committed postimage; D then returns the existing
            // completed job without any promotion replay.
            let connection = open_authorized_test_connection(&database).unwrap();
            connection
                .execute(
                    "UPDATE memory_vector_generation_rebuild_resolution
                     SET replacement_mutation_sequence=NULL
                     WHERE job_id=?1 AND source_kind='outbox'",
                    [job.job_id.as_str()],
                )
                .unwrap();
            drop(connection);
            let resumed = run_generation_rebuild_d(
                &storage,
                &runtime,
                &registry,
                &handoff,
                "owner-a",
                std::time::Instant::now() + Duration::from_secs(10),
                &guard,
            )
            .await
            .unwrap();
            assert_eq!(resumed.status, "completed");
            assert_eq!(resumed.job_id, job.job_id);
            assert_eq!(
                resumed.promotion_operation_id.as_deref(),
                Some(operation_id.as_str())
            );
        });
    }

    #[test]
    fn d9d3_d_f3_status_ipc_never_reports_completed_for_mixed_world() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, profiles, secrets, coordinator, registry, _server) =
                full_fixture(ServerBehavior::Success(3));
            let database = storage.test_database_main_path().unwrap();
            seed_recovery_postimage(&storage, &database);
            let runtime = runtime_fixture(&profiles, &secrets, &coordinator);
            let gate = FencedVectorSyncCompositionGate::default();
            let guard = gate.acquire().await;
            let handoff = run_generation_rebuild_c(
                &storage,
                &runtime,
                &registry,
                "request-a",
                "owner-a",
                &guard,
            )
            .await
            .unwrap();
            arm_promotion_fault_for_test(PromotionFault::AfterCommitUnknown);
            let completed = run_generation_rebuild_d(
                &storage,
                &runtime,
                &registry,
                &handoff,
                "owner-a",
                std::time::Instant::now() + Duration::from_secs(10),
                &guard,
            )
            .await
            .unwrap();
            assert_eq!(completed.status, "completed");
            let job_id = completed.job_id.clone();

            // Exact completed world: the shared status helper reports completed.
            let status = resolve_generation_rebuild_status(&storage, &job_id).unwrap();
            assert_eq!(status.status, "completed");

            // Corrupt one resolution tuple -> a mixed completed world; the status
            // helper MUST NOT report completed, only the redacted error surface,
            // and never any authority details.
            let connection = open_authorized_test_connection(&database).unwrap();
            connection
                .execute(
                    "UPDATE memory_vector_generation_rebuild_resolution
                     SET replacement_mutation_sequence=999
                     WHERE job_id=?1 AND source_kind='outbox'",
                    [job_id.as_str()],
                )
                .unwrap();
            drop(connection);
            let error = resolve_generation_rebuild_status(&storage, &job_id).unwrap_err();
            assert_eq!(error.code, VectorGenerationRebuildErrorCode::Unavailable);
            assert_eq!(
                error.message,
                "The vector generation rebuild is unavailable."
            );

            // Restore the exact postimage: completed again.
            let connection = open_authorized_test_connection(&database).unwrap();
            connection
                .execute(
                    "UPDATE memory_vector_generation_rebuild_resolution
                     SET replacement_mutation_sequence=NULL
                     WHERE job_id=?1 AND source_kind='outbox'",
                    [job_id.as_str()],
                )
                .unwrap();
            drop(connection);
            let restored = resolve_generation_rebuild_status(&storage, &job_id).unwrap();
            assert_eq!(restored.status, "completed");
        });
    }

    #[test]
    fn d9d3_d_f3_missing_job_during_recovery_stays_fail_closed() {
        tauri::async_runtime::block_on(async {
            let _counter_lock = COUNTER_LOCK.lock().unwrap();
            C_STORE_CREATE_CALLS.store(0, Ordering::SeqCst);
            C_VECTOR_UPSERT_CALLS.store(0, Ordering::SeqCst);
            let (_root, storage, profiles, secrets, coordinator, registry, _server) =
                full_fixture(ServerBehavior::Success(3));
            let database = storage.test_database_main_path().unwrap();

            // Phase 1: real promotion commits while the D layer observes the
            // mixed postimage; the job persists as `completed`.
            seed_recovery_postimage(&storage, &database);
            crate::storage::arm_promotion_recovery_corruption_for_test();
            let job_id = {
                let gate = FencedVectorSyncCompositionGate::default();
                let guard = gate.acquire().await;
                commit_mixed_promotion_through_d(
                    &storage,
                    &profiles,
                    &secrets,
                    &coordinator,
                    &registry,
                    &guard,
                )
                .await
                .0
            };

            // Phase 2 (new gate/process): resume; the promotion-recovery loop
            // first observes the durable job as missing and must NOT treat that
            // absence as a terminal success release.
            let gate2 = Arc::new(FencedVectorSyncCompositionGate::default());
            let guard2 = gate2.acquire().await;
            arm_promotion_recovery_hide_job_for_test();
            let (missing_tx, missing_rx) = std::sync::mpsc::channel();
            set_promotion_recovery_missing_signal_for_test(missing_tx);
            let (acquired_tx, acquired_rx) = std::sync::mpsc::channel();
            let competitor_gate = Arc::clone(&gate2);
            let competitor = std::thread::spawn(move || {
                tauri::async_runtime::block_on(async move {
                    let _competitor_guard = competitor_gate.acquire().await;
                    acquired_tx.send(()).unwrap();
                })
            });

            let pipeline_result = std::thread::scope(|scope| {
                let pipeline = scope.spawn(|| {
                    tauri::async_runtime::block_on(run_vector_generation_rebuild_guarded(
                        &storage,
                        &secrets,
                        &coordinator,
                        &registry,
                        &guard2,
                        "request-a",
                        Duration::from_secs(10),
                    ))
                });

                // The recovery loop observed the missing/unavailable job and
                // failed closed: the NEW composition gate is still held.
                missing_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                std::thread::yield_now();
                assert!(
                    acquired_rx.try_recv().is_err(),
                    "a competitor must stay blocked while the recovery job is missing"
                );

                // Restore the exact committed postimage; the recovered world can
                // then resolve to authoritative completion and the gate releases.
                let connection = open_authorized_test_connection(&database).unwrap();
                connection
                    .execute(
                        "UPDATE memory_vector_generation_rebuild_resolution
                         SET replacement_mutation_sequence=NULL
                         WHERE job_id=?1 AND source_kind='outbox'",
                        [job_id.as_str()],
                    )
                    .unwrap();
                drop(connection);

                let result = pipeline.join().unwrap();
                let completed = result
                    .as_ref()
                    .expect("authoritative completion after restore");
                assert_eq!(completed.status, "completed");
                result
            });

            drop(guard2);
            acquired_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            competitor.join().unwrap();
            assert!(pipeline_result.is_ok());
        });
    }
}
