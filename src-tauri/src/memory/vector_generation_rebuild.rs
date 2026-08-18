//! Private D9D3-C persisted snapshot and bulk-build phase.
//!
//! This is an internal phase, not a production runner or IPC command.  The
//! caller must transfer the already-held fenced composition guard into this
//! function.  C never acquires or releases that guard around a live job, so a
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
    _composition_guard: FencedVectorSyncCompositionGuard<'_>,
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
            let store = match existing {
                Some(store) => store,
                None => registry
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
                    })?,
            };
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
            storage
                .fail_generation_rebuild(
                    &job.job_id,
                    lease,
                    "GENERATION_REBUILD_PROVIDER_RESOLUTION_FAILED",
                    job.candidate_authority_epoch,
                )
                .map_err(GenerationRebuildCError::storage)?;
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
