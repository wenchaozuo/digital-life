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
        GenerationRebuildFinalizeOutcome, GenerationRebuildItemRecord, GenerationRebuildJobRecord,
        GenerationRebuildLease, StorageError, StorageService,
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

    fn storage(error: StorageError) -> Self {
        Self::new(error.code, error.message, error.recoverable)
    }

    fn conflict(message: &'static str) -> Self {
        Self::new("D9D3_C_CONFLICT", message, true)
    }

    fn invalid(message: &'static str) -> Self {
        Self::new("D9D3_C_INVALID", message, false)
    }

    fn failed(message: &'static str) -> Self {
        Self::new("D9D3_C_FAILED", message, false)
    }

    fn unknown() -> Self {
        Self::new(
            "GENERATION_REBUILD_PROVIDER_RESULT_UNKNOWN",
            "The rebuild stopped because an external result may have been applied.",
            true,
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

    if job.status == "catching_up" {
        return handoff_from_job(&job);
    }
    if matches!(job.status.as_str(), "failed" | "cancelled" | "completed") {
        return Err(GenerationRebuildCError::failed(
            "The persisted generation rebuild is already terminal.",
        ));
    }
    if job.status == "ready" {
        return Err(GenerationRebuildCError::conflict(
            "The C phase cannot resume a promotion-ready job.",
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
    }

    loop {
        job = storage
            .load_generation_rebuild_job(&job.job_id)
            .map_err(GenerationRebuildCError::storage)?;
        if job.status == "catching_up" {
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
    if job.status != "catching_up" {
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
        memory::vector_sync_stage_runtime::FencedVectorSyncCompositionGate,
        model::{
            profile::{
                ActiveModelProfile, DeleteModelProfileResult, ModelProfile, ModelProfileError,
                ModelProfileRepository, ModelProviderKind, ModelPurpose,
            },
            runtime::{ModelRuntimeCoordinator, ModelRuntimeService},
        },
        secrets::{InMemorySecretStore, SecretIdentifier, SecretPurpose, SecretStore, SecretValue},
        storage::{
            open_authorized_test_connection, GenerationAuthorityRegistration, StorageService,
        },
        vector_store::{
            LanceDbVectorStore, LanceDbVectorStoreRegistry, VectorGenerationContext,
            VectorGenerationId, VectorStore,
        },
    };

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
                    request_counter.fetch_add(1, Ordering::SeqCst);
                    stream.set_nonblocking(false).unwrap();
                    read_http_request(&mut stream);
                    if let ServerBehavior::Success(dimension) = behavior {
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
}
