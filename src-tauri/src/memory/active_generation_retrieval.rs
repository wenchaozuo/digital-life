//! D10-B2 sealed, read-only semantic retrieval over the active vector generation.
//!
//! This capability starts from the SQLite active-generation authority, binds
//! the provider recorded for that generation, opens only the exact existing
//! generation store, and rechecks authority after the derived search. It does
//! not own keyword retrieval, memory hydration, ranking, or conversation
//! integration.

use std::sync::Arc;

use crate::{
    embedding::{
        validate_documents, EmbeddingBatch, EmbeddingError, EmbeddingErrorCode, EmbeddingPurpose,
        EmbeddingRequest,
    },
    memory::existing_generation_binding::{
        compute_canonical_generation_descriptor, verify_provider_facts,
        ExistingGenerationBindingError,
    },
    model::{
        profile::ModelProfileRepository,
        runtime::{ModelRuntimeService, ResolvedEmbeddingProvider},
        transport::url_policy::validate_and_normalize_url,
    },
    secrets::SecretStore,
    storage::StorageService,
    vector_store::{
        ExistingGenerationVectorStoreProvider, GenerationVectorSearchHit,
        GenerationVectorSearchQuery, LanceDbVectorStoreRegistry, VectorGenerationContext,
        VectorStore, VectorStoreErrorCode,
    },
};

/// Redacted failure classes consumed by the future D10-C retrieval cutover.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ActiveGenerationRetrievalErrorCode {
    InvalidQuery,
    NoActiveGeneration,
    GenerationProviderUnavailable,
    GenerationProviderMismatch,
    EmbeddingFailed,
    EmbeddingDimensionMismatch,
    GenerationStoreUnavailable,
    VectorSearchFailed,
    GenerationStale,
}

impl ActiveGenerationRetrievalErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidQuery => "D10B2_INVALID_QUERY",
            Self::NoActiveGeneration => "D10B2_NO_ACTIVE_GENERATION",
            Self::GenerationProviderUnavailable => "D10B2_GENERATION_PROVIDER_UNAVAILABLE",
            Self::GenerationProviderMismatch => "D10B2_GENERATION_PROVIDER_MISMATCH",
            Self::EmbeddingFailed => "D10B2_EMBEDDING_FAILED",
            Self::EmbeddingDimensionMismatch => "D10B2_EMBEDDING_DIMENSION_MISMATCH",
            Self::GenerationStoreUnavailable => "D10B2_GENERATION_STORE_UNAVAILABLE",
            Self::VectorSearchFailed => "D10B2_VECTOR_SEARCH_FAILED",
            Self::GenerationStale => "D10B2_GENERATION_STALE",
        }
    }

    const fn safe_message(self) -> &'static str {
        match self {
            Self::InvalidQuery => "The semantic query is invalid.",
            Self::NoActiveGeneration => "No active vector generation is available.",
            Self::GenerationProviderUnavailable => {
                "The generation-bound embedding provider is unavailable."
            }
            Self::GenerationProviderMismatch => {
                "The generation-bound embedding provider is incompatible."
            }
            Self::EmbeddingFailed => "The semantic query could not be embedded.",
            Self::EmbeddingDimensionMismatch => {
                "The query embedding dimension does not match the active generation."
            }
            Self::GenerationStoreUnavailable => {
                "The exact active-generation vector store is unavailable."
            }
            Self::VectorSearchFailed => "The active-generation vector search failed.",
            Self::GenerationStale => "The active vector generation changed during retrieval.",
        }
    }
}

/// Redacted, non-serializable error boundary for D10 semantic retrieval.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct ActiveGenerationRetrievalError {
    code: ActiveGenerationRetrievalErrorCode,
}

impl ActiveGenerationRetrievalError {
    const fn new(code: ActiveGenerationRetrievalErrorCode) -> Self {
        Self { code }
    }

    pub(crate) const fn code(self) -> ActiveGenerationRetrievalErrorCode {
        self.code
    }
}

impl std::fmt::Display for ActiveGenerationRetrievalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.code.safe_message())
    }
}

impl std::fmt::Debug for ActiveGenerationRetrievalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveGenerationRetrievalError")
            .field("code", &self.code.as_str())
            .field("message", &self.code.safe_message())
            .finish()
    }
}

impl std::error::Error for ActiveGenerationRetrievalError {}

/// Opaque, non-cloneable read capability for one active generation.
///
/// The capability exposes neither generation identity, provider, store, path,
/// nor context. The only operation is the semantic search method below.
pub(crate) struct ActiveGenerationRetrievalExecution<'storage, 'provider> {
    storage: &'storage StorageService,
    context: VectorGenerationContext,
    authority_epoch: i64,
    provider: ResolvedEmbeddingProvider<'provider>,
    store: Arc<dyn VectorStore>,
}

impl<'storage, 'provider> ActiveGenerationRetrievalExecution<'storage, 'provider> {
    /// Embeds one query with the generation-bound provider, searches the exact
    /// generation store, and returns only after a final active-authority check.
    pub(crate) async fn semantic_search(
        &self,
        life_id: &str,
        query_text: &str,
        limit: usize,
        min_score: Option<f32>,
    ) -> Result<Vec<GenerationVectorSearchHit>, ActiveGenerationRetrievalError> {
        let parameter_query = GenerationVectorSearchQuery::new(
            life_id.to_owned(),
            vec![1.0; self.context.dimension()],
            limit,
            min_score,
        );
        parameter_query
            .validate_against(&self.context)
            .map_err(|_| {
                ActiveGenerationRetrievalError::new(
                    ActiveGenerationRetrievalErrorCode::InvalidQuery,
                )
            })?;

        let texts = vec![query_text.to_owned()];
        validate_documents(&texts).map_err(|_| {
            ActiveGenerationRetrievalError::new(ActiveGenerationRetrievalErrorCode::InvalidQuery)
        })?;

        let batch = self
            .provider
            .provider()
            .embed(EmbeddingRequest {
                texts,
                purpose: EmbeddingPurpose::Query,
            })
            .await
            .map_err(map_embedding_error)?;
        let vector = extract_query_vector(batch, self.context.dimension())?;
        let query = GenerationVectorSearchQuery::new(life_id.to_owned(), vector, limit, min_score);
        let hits = self
            .store
            .search_generation(&self.context, query)
            .await
            .map_err(map_vector_store_error)?;

        self.final_authority_recheck()?;
        Ok(hits)
    }

    fn final_authority_recheck(&self) -> Result<(), ActiveGenerationRetrievalError> {
        let authority = self
            .storage
            .load_active_generation_authority()
            .map_err(|_| {
                ActiveGenerationRetrievalError::new(
                    ActiveGenerationRetrievalErrorCode::GenerationStale,
                )
            })?;
        if authority.bound_embedding_profile_id() != self.provider.profile.profile_id {
            return Err(ActiveGenerationRetrievalError::new(
                ActiveGenerationRetrievalErrorCode::GenerationStale,
            ));
        }
        let (context, authority_epoch) =
            authority
                .verify_current_and_seal(self.storage)
                .map_err(|_| {
                    ActiveGenerationRetrievalError::new(
                        ActiveGenerationRetrievalErrorCode::GenerationStale,
                    )
                })?;
        if context != self.context || authority_epoch != self.authority_epoch {
            return Err(ActiveGenerationRetrievalError::new(
                ActiveGenerationRetrievalErrorCode::GenerationStale,
            ));
        }
        Ok(())
    }
}

/// Resolves a read-only capability exclusively from canonical authority
/// services. No caller-supplied generation, profile, descriptor, dimension,
/// provider, store, or path is accepted.
pub(crate) async fn resolve_active_generation_retrieval_execution<'storage, 'runtime, R, S>(
    storage: &'storage StorageService,
    runtime: &'runtime ModelRuntimeService<'runtime, R, S>,
    registry: &LanceDbVectorStoreRegistry,
) -> Result<ActiveGenerationRetrievalExecution<'storage, 'runtime>, ActiveGenerationRetrievalError>
where
    R: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    let authority = storage
        .load_active_generation_authority()
        .map_err(map_binding_error)?;
    let resolved_provider = runtime
        .resolve_embedding_provider(authority.bound_embedding_profile_id())
        .map_err(|_| {
            ActiveGenerationRetrievalError::new(
                ActiveGenerationRetrievalErrorCode::GenerationProviderUnavailable,
            )
        })?;
    let profile = &resolved_provider.profile;
    let profile_dimension =
        verify_provider_facts(profile, resolved_provider.provider()).map_err(map_binding_error)?;
    let transport_target = validate_and_normalize_url(&profile.base_url).map_err(|_| {
        ActiveGenerationRetrievalError::new(
            ActiveGenerationRetrievalErrorCode::GenerationProviderMismatch,
        )
    })?;
    let descriptor = compute_canonical_generation_descriptor(
        &profile.provider_kind,
        &profile.profile_id,
        &transport_target,
        &profile.model_name,
        profile_dimension,
    )
    .map_err(map_binding_error)?;
    authority
        .verify_descriptor_and_dimension(&descriptor, profile_dimension)
        .map_err(map_binding_error)?;
    let (context, authority_epoch) = authority
        .verify_current_and_seal(storage)
        .map_err(map_binding_error)?;

    let data_root = storage.active_data_root().map_err(|_| {
        ActiveGenerationRetrievalError::new(
            ActiveGenerationRetrievalErrorCode::GenerationStoreUnavailable,
        )
    })?;
    let store_provider = registry
        .bind_existing_generation_provider(&data_root)
        .map_err(|_| {
            ActiveGenerationRetrievalError::new(
                ActiveGenerationRetrievalErrorCode::GenerationStoreUnavailable,
            )
        })?;
    let store = store_provider
        .existing_for_generation(context.generation_id())
        .await
        .map_err(|_| {
            ActiveGenerationRetrievalError::new(
                ActiveGenerationRetrievalErrorCode::GenerationStoreUnavailable,
            )
        })?;

    Ok(ActiveGenerationRetrievalExecution {
        storage,
        context,
        authority_epoch,
        provider: resolved_provider,
        store,
    })
}

fn map_binding_error(error: ExistingGenerationBindingError) -> ActiveGenerationRetrievalError {
    let code = match error.code().as_str() {
        "D9D2_NO_EXISTING_GENERATION" | "D9D2_AMBIGUOUS_EXISTING_GENERATION" => {
            ActiveGenerationRetrievalErrorCode::NoActiveGeneration
        }
        "D9D2_GENERATION_PROVIDER_UNAVAILABLE" => {
            ActiveGenerationRetrievalErrorCode::GenerationProviderUnavailable
        }
        "D9D2_GENERATION_PROVIDER_MISMATCH"
        | "D9D2_INVALID_GENERATION_METADATA"
        | "D9D2_GENERATION_BINDING_MISMATCH" => {
            ActiveGenerationRetrievalErrorCode::GenerationProviderMismatch
        }
        "D9D2_GENERATION_BINDING_STALE" => ActiveGenerationRetrievalErrorCode::GenerationStale,
        "D9D2_EXISTING_VECTOR_STORE_UNAVAILABLE" => {
            ActiveGenerationRetrievalErrorCode::GenerationStoreUnavailable
        }
        _ => ActiveGenerationRetrievalErrorCode::GenerationProviderMismatch,
    };
    ActiveGenerationRetrievalError::new(code)
}

fn map_embedding_error(error: EmbeddingError) -> ActiveGenerationRetrievalError {
    let code = match error.code() {
        EmbeddingErrorCode::InvalidRequest
        | EmbeddingErrorCode::EmptyText
        | EmbeddingErrorCode::BatchLimitExceeded
        | EmbeddingErrorCode::TextLimitExceeded => ActiveGenerationRetrievalErrorCode::InvalidQuery,
        EmbeddingErrorCode::DimensionMismatch => {
            ActiveGenerationRetrievalErrorCode::EmbeddingDimensionMismatch
        }
        EmbeddingErrorCode::NetworkError
        | EmbeddingErrorCode::AuthenticationFailed
        | EmbeddingErrorCode::RateLimited
        | EmbeddingErrorCode::RequestTimeout
        | EmbeddingErrorCode::InvalidProviderResponse => {
            ActiveGenerationRetrievalErrorCode::EmbeddingFailed
        }
    };
    ActiveGenerationRetrievalError::new(code)
}

fn extract_query_vector(
    batch: EmbeddingBatch,
    expected_dimension: usize,
) -> Result<Vec<f32>, ActiveGenerationRetrievalError> {
    if batch.len() != 1 {
        return Err(ActiveGenerationRetrievalError::new(
            ActiveGenerationRetrievalErrorCode::EmbeddingFailed,
        ));
    }
    let vector = batch.vectors().first().ok_or_else(|| {
        ActiveGenerationRetrievalError::new(ActiveGenerationRetrievalErrorCode::EmbeddingFailed)
    })?;
    if vector.input_index() != 0 || batch.dimension() != expected_dimension {
        return Err(ActiveGenerationRetrievalError::new(
            ActiveGenerationRetrievalErrorCode::EmbeddingDimensionMismatch,
        ));
    }
    if vector.dimension() != expected_dimension {
        return Err(ActiveGenerationRetrievalError::new(
            ActiveGenerationRetrievalErrorCode::EmbeddingDimensionMismatch,
        ));
    }
    if vector.values().iter().any(|value| !value.is_finite())
        || vector.values().iter().all(|value| *value == 0.0)
    {
        return Err(ActiveGenerationRetrievalError::new(
            ActiveGenerationRetrievalErrorCode::EmbeddingFailed,
        ));
    }
    Ok(vector.values().to_vec())
}

fn map_vector_store_error(
    error: crate::vector_store::VectorStoreError,
) -> ActiveGenerationRetrievalError {
    let code = match error.code {
        VectorStoreErrorCode::GenerationNotFound | VectorStoreErrorCode::StoreUnavailable => {
            ActiveGenerationRetrievalErrorCode::GenerationStoreUnavailable
        }
        _ => ActiveGenerationRetrievalErrorCode::VectorSearchFailed,
    };
    ActiveGenerationRetrievalError::new(code)
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    use rusqlite::params;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        embedding::{EmbeddingFuture, EmbeddingModelInfo, EmbeddingProvider, EmbeddingRequest},
        model::{
            profile::{
                CreateModelProfileRequest, ModelProfileService, ModelProviderKind, ModelPurpose,
                SetActiveModelProfileRequest,
            },
            runtime::{ModelRuntimeCoordinator, ResolvedEmbeddingProvider, ResolvedModelProfile},
        },
        secrets::InMemorySecretStore,
        storage::open_authorized_test_connection,
        vector_store::{
            generation_store_root, GenerationVectorRecord, InMemoryVectorStore, VectorGenerationId,
            VectorRecord, VectorSearchHit, VectorSearchQuery, VectorSpace, VectorStoreError,
            VectorStoreFuture,
        },
    };

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        tauri::async_runtime::block_on(future)
    }

    fn test_storage() -> (TempDir, StorageService) {
        let temp = tempfile::tempdir().unwrap();
        let storage =
            StorageService::initialize_with_roots(temp.path().join("data"), None).unwrap();
        (temp, storage)
    }

    fn profile(
        storage: &StorageService,
        base_url: &str,
        model_name: &str,
        dimension: u32,
    ) -> crate::model::profile::ModelProfile {
        ModelProfileService::new(storage)
            .create(CreateModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: format!("Embedding {model_name}"),
                base_url: base_url.to_owned(),
                model_name: model_name.to_owned(),
                temperature: None,
                max_tokens: None,
                embedding_dimension: Some(dimension),
            })
            .unwrap()
    }

    fn set_active_profile(storage: &StorageService, profile_id: &str) {
        ModelProfileService::new(storage)
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                profile_id: profile_id.to_owned(),
            })
            .unwrap();
    }

    fn descriptor(profile_id: &str, model_name: &str, dimension: usize) -> String {
        compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            profile_id,
            &validate_and_normalize_url("https://api.openai.com/v1").unwrap(),
            model_name,
            dimension,
        )
        .unwrap()
    }

    fn context(
        generation_id: &str,
        descriptor_hash: String,
        dimension: usize,
    ) -> VectorGenerationContext {
        VectorGenerationContext::new(
            VectorGenerationId::parse(generation_id).unwrap(),
            descriptor_hash,
            dimension,
        )
        .unwrap()
    }

    fn insert_generation_row(
        storage: &StorageService,
        generation_id: &str,
        descriptor_hash: &str,
        dimension: usize,
        state: &str,
        authority_epoch: i64,
    ) {
        let connection =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        connection
            .execute(
                "INSERT INTO memory_vector_generation
                 (generation_id,descriptor_hash,dimension,state,authority_epoch)
                 VALUES (?1,?2,?3,?4,?5)",
                params![
                    generation_id,
                    descriptor_hash,
                    dimension as i64,
                    state,
                    authority_epoch
                ],
            )
            .unwrap();
    }

    fn install_active_generation(
        storage: &StorageService,
        context: &VectorGenerationContext,
        profile_id: &str,
        authority_epoch: i64,
    ) {
        insert_generation_row(
            storage,
            context.generation_id().as_str(),
            context.descriptor_hash(),
            context.dimension(),
            "active",
            authority_epoch,
        );
        let connection =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        connection
            .execute(
                "INSERT INTO memory_vector_generation_binding
                 (generation_id,descriptor_version,embedding_profile_id,created_at)
                 VALUES (?1,?2,?3,'2026-01-01T00:00:00.000Z')",
                params![
                    context.generation_id().as_str(),
                    super::super::existing_generation_binding::D9D2_GENERATION_DESCRIPTOR_VERSION,
                    profile_id
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO memory_vector_generation_store_witness
                 (generation_id,create_operation_id,state,last_error_code,updated_at)
                 VALUES (?1,NULL,'ready',NULL,'2026-01-01T00:00:00.000Z')",
                [context.generation_id().as_str()],
            )
            .unwrap();
        connection
            .execute(
                "UPDATE memory_vector_generation_authority
                 SET active_generation_id=?1,updated_at='2026-01-01T00:00:00.000Z'
                 WHERE singleton=1",
                [context.generation_id().as_str()],
            )
            .unwrap();
    }

    fn install_ready_generation(
        storage: &StorageService,
        context: &VectorGenerationContext,
        profile_id: &str,
        authority_epoch: i64,
    ) {
        insert_generation_row(
            storage,
            context.generation_id().as_str(),
            context.descriptor_hash(),
            context.dimension(),
            "building",
            authority_epoch,
        );
        let connection =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        connection
            .execute(
                "INSERT INTO memory_vector_generation_binding
                 (generation_id,descriptor_version,embedding_profile_id,created_at)
                 VALUES (?1,?2,?3,'2026-01-01T00:00:00.000Z')",
                params![
                    context.generation_id().as_str(),
                    super::super::existing_generation_binding::D9D2_GENERATION_DESCRIPTOR_VERSION,
                    profile_id
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO memory_vector_generation_store_witness
                 (generation_id,create_operation_id,state,last_error_code,updated_at)
                 VALUES (?1,NULL,'ready',NULL,'2026-01-01T00:00:00.000Z')",
                [context.generation_id().as_str()],
            )
            .unwrap();
    }

    async fn seed_lance_generation(
        storage: &StorageService,
        registry: &LanceDbVectorStoreRegistry,
        context: &VectorGenerationContext,
    ) {
        let data_root = storage.active_data_root().unwrap();
        let store = registry
            .generation_store_for_write(&data_root, context.generation_id())
            .await
            .unwrap();
        store.create_generation(context).await.unwrap();
        store
            .upsert_generation(
                context,
                GenerationVectorRecord::try_new(
                    context.generation_id().clone(),
                    "life-a",
                    "memory-a",
                    1,
                    "content-a",
                    context.descriptor_hash(),
                    vec![1.0, 0.0],
                )
                .unwrap(),
            )
            .await
            .unwrap();
    }

    fn resolved_profile(
        profile_id: &str,
        model_name: &str,
        dimension: usize,
    ) -> ResolvedModelProfile {
        ResolvedModelProfile {
            profile_id: profile_id.to_owned(),
            purpose: crate::model::runtime::ModelRuntimePurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "Test embedding".to_owned(),
            base_url: "https://api.openai.com/v1".to_owned(),
            model_name: model_name.to_owned(),
            temperature: None,
            max_tokens: None,
            embedding_dimension: Some(dimension as u32),
        }
    }

    struct RecordingProvider {
        model_name: String,
        dimension: usize,
        outputs: Vec<Vec<f32>>,
        requests: Arc<Mutex<Vec<EmbeddingRequest>>>,
    }

    impl EmbeddingProvider for RecordingProvider {
        fn model_info(&self) -> EmbeddingModelInfo {
            EmbeddingModelInfo {
                model_name: self.model_name.clone(),
                dimension: Some(self.dimension),
            }
        }

        fn model_name(&self) -> &str {
            &self.model_name
        }

        fn vector_dimension(&self) -> Option<usize> {
            Some(self.dimension)
        }

        fn embed<'a>(
            &'a self,
            request: EmbeddingRequest,
        ) -> EmbeddingFuture<'a, Result<EmbeddingBatch, EmbeddingError>> {
            self.requests.lock().unwrap().push(request);
            let outputs = self.outputs.clone();
            Box::pin(async move { EmbeddingBatch::from_test_vectors(outputs) })
        }
    }

    fn direct_execution<'storage>(
        storage: &'storage StorageService,
        context: VectorGenerationContext,
        store: Arc<dyn VectorStore>,
        outputs: Vec<Vec<f32>>,
        provider_dimension: usize,
    ) -> (
        ActiveGenerationRetrievalExecution<'storage, 'static>,
        Arc<Mutex<Vec<EmbeddingRequest>>>,
    ) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let provider = RecordingProvider {
            model_name: "test-model".to_owned(),
            dimension: provider_dimension,
            outputs,
            requests: Arc::clone(&requests),
        };
        let resolved = ResolvedEmbeddingProvider::from_test_provider(
            resolved_profile("profile-p1", "test-model", context.dimension()),
            Box::new(provider),
        );
        (
            ActiveGenerationRetrievalExecution {
                storage,
                context,
                authority_epoch: 1,
                provider: resolved,
                store,
            },
            requests,
        )
    }

    fn unavailable<'a, T>() -> VectorStoreFuture<'a, Result<T, VectorStoreError>> {
        Box::pin(async {
            Err(VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "The test vector store is unavailable.",
                false,
            ))
        })
    }

    enum ProbeAction {
        Fail,
        Promote(PathBuf),
    }

    struct ProbeStore {
        calls: Arc<AtomicUsize>,
        action: ProbeAction,
    }

    impl VectorStore for ProbeStore {
        fn upsert<'a>(
            &'a self,
            _record: VectorRecord,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            unavailable()
        }

        fn upsert_batch<'a>(
            &'a self,
            _records: Vec<VectorRecord>,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            unavailable()
        }

        fn search<'a>(
            &'a self,
            _query: VectorSearchQuery,
        ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>> {
            unavailable()
        }

        fn search_generation<'a>(
            &'a self,
            _context: &'a VectorGenerationContext,
            _query: GenerationVectorSearchQuery,
        ) -> VectorStoreFuture<'a, Result<Vec<GenerationVectorSearchHit>, VectorStoreError>>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let action = match &self.action {
                ProbeAction::Fail => ProbeAction::Fail,
                ProbeAction::Promote(path) => ProbeAction::Promote(path.clone()),
            };
            Box::pin(async move {
                match action {
                    ProbeAction::Fail => Err(VectorStoreError::new(
                        VectorStoreErrorCode::StoreUnavailable,
                        "The test vector store is unavailable.",
                        false,
                    )),
                    ProbeAction::Promote(path) => {
                        let connection = open_authorized_test_connection(&path).unwrap();
                        connection
                            .execute_batch(
                                "UPDATE memory_vector_generation_authority
                                 SET active_generation_id=NULL,updated_at='2026-01-01T00:00:00.000Z'
                                 WHERE singleton=1;
                                 UPDATE memory_vector_generation
                                 SET state='retired',authority_epoch=authority_epoch+1
                                 WHERE generation_id='generation-1' AND state='active';
                                 UPDATE memory_vector_generation
                                 SET state='active',authority_epoch=authority_epoch+1
                                 WHERE generation_id='generation-2' AND state='building';
                                 UPDATE memory_vector_generation_authority
                                 SET active_generation_id='generation-2',updated_at='2026-01-01T00:00:00.000Z'
                                 WHERE singleton=1",
                            )
                            .unwrap();
                        Ok(Vec::new())
                    }
                }
            })
        }

        fn delete<'a>(
            &'a self,
            _life_id: &'a str,
            _memory_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            unavailable()
        }

        fn delete_from_space<'a>(
            &'a self,
            _life_id: &'a str,
            _memory_id: &'a str,
            _space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            unavailable()
        }

        fn delete_by_life<'a>(
            &'a self,
            _life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            unavailable()
        }

        fn clear_space<'a>(
            &'a self,
            _life_id: &'a str,
            _space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            unavailable()
        }

        fn count<'a>(
            &'a self,
            _life_id: &'a str,
            _space: Option<&'a VectorSpace>,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            unavailable()
        }

        fn health_check<'a>(
            &'a self,
            _life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            unavailable()
        }
    }

    fn sqlite_snapshot(
        storage: &StorageService,
    ) -> (
        String,
        Vec<(String, String, i64)>,
        Vec<(String, String)>,
        i64,
    ) {
        let connection =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        let active = connection
            .query_row(
                "SELECT COALESCE(active_generation_id,'')
                 FROM memory_vector_generation_authority WHERE singleton=1",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap();
        let mut statement = connection
            .prepare(
                "SELECT generation_id,state,authority_epoch
                 FROM memory_vector_generation ORDER BY generation_id",
            )
            .unwrap();
        let generations = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let mut witness_statement = connection
            .prepare(
                "SELECT generation_id,state
                 FROM memory_vector_generation_store_witness ORDER BY generation_id",
            )
            .unwrap();
        let witnesses = witness_statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let outbox_count = connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_sync_outbox",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap();
        (active, generations, witnesses, outbox_count)
    }

    #[test]
    fn capability_error_boundary_is_redacted() {
        let error = ActiveGenerationRetrievalError::new(
            ActiveGenerationRetrievalErrorCode::GenerationStoreUnavailable,
        );
        let rendered = format!("{error:?} {error}");
        for canary in [
            "QUERY_TEXT_CANARY",
            "CREDENTIAL_CANARY",
            "https://provider.invalid/canary",
            "C:\\secret\\vectors",
        ] {
            assert!(!rendered.contains(canary));
        }
    }

    #[test]
    fn resolver_uses_bound_generation_profile_not_process_active_profile() {
        block_on(async {
            let (_temp, storage) = test_storage();
            let p1 = profile(&storage, "https://api.openai.com/v1", "bound-model-p1", 2);
            let p2 = profile(&storage, "https://api.openai.com/v1", "current-model-p2", 2);
            set_active_profile(&storage, &p2.id);
            let context = context(
                "generation-bound-profile",
                descriptor(&p1.id, &p1.model_name, 2),
                2,
            );
            install_active_generation(&storage, &context, &p1.id, 1);
            let registry = LanceDbVectorStoreRegistry::default();
            seed_lance_generation(&storage, &registry, &context).await;
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

            let execution =
                resolve_active_generation_retrieval_execution(&storage, &runtime, &registry)
                    .await
                    .unwrap();
            assert_eq!(execution.provider.profile.profile_id, p1.id);
            assert_ne!(execution.provider.profile.profile_id, p2.id);
        });
    }

    #[test]
    fn resolver_selects_no_building_retired_or_failed_generation() {
        block_on(async {
            let (_temp, storage) = test_storage();
            insert_generation_row(&storage, "building-only", "descriptor-a", 2, "building", 1);
            insert_generation_row(&storage, "retired-only", "descriptor-b", 2, "retired", 1);
            insert_generation_row(&storage, "failed-only", "descriptor-c", 2, "failed", 1);
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let registry = LanceDbVectorStoreRegistry::default();

            let error =
                resolve_active_generation_retrieval_execution(&storage, &runtime, &registry)
                    .await
                    .err()
                    .unwrap();
            assert_eq!(
                error.code(),
                ActiveGenerationRetrievalErrorCode::NoActiveGeneration
            );
        });
    }

    #[test]
    fn resolver_rejects_descriptor_and_dimension_mismatch() {
        block_on(async {
            let (_temp, storage) = test_storage();
            let p1 = profile(&storage, "https://api.openai.com/v1", "descriptor-model", 2);
            set_active_profile(&storage, &p1.id);
            let wrong_descriptor =
                context("generation-wrong-descriptor", "wrong-descriptor".into(), 2);
            install_active_generation(&storage, &wrong_descriptor, &p1.id, 1);
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let registry = LanceDbVectorStoreRegistry::default();
            let error =
                resolve_active_generation_retrieval_execution(&storage, &runtime, &registry)
                    .await
                    .err()
                    .unwrap();
            assert_eq!(
                error.code(),
                ActiveGenerationRetrievalErrorCode::GenerationProviderMismatch
            );
        });
    }

    #[test]
    fn resolver_rejects_authority_dimension_mismatch() {
        block_on(async {
            let (_temp, storage) = test_storage();
            let p1 = profile(&storage, "https://api.openai.com/v1", "dimension-model", 2);
            set_active_profile(&storage, &p1.id);
            let wrong_dimension = context(
                "generation-wrong-dimension",
                descriptor(&p1.id, &p1.model_name, 2),
                3,
            );
            install_active_generation(&storage, &wrong_dimension, &p1.id, 1);
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let registry = LanceDbVectorStoreRegistry::default();

            let error =
                resolve_active_generation_retrieval_execution(&storage, &runtime, &registry)
                    .await
                    .err()
                    .unwrap();
            assert_eq!(
                error.code(),
                ActiveGenerationRetrievalErrorCode::GenerationProviderMismatch
            );
        });
    }

    #[test]
    fn resolver_requires_exact_generation_store_and_never_uses_legacy_store() {
        block_on(async {
            let (_temp, storage) = test_storage();
            let p1 = profile(&storage, "https://api.openai.com/v1", "store-model", 2);
            set_active_profile(&storage, &p1.id);
            let context = context(
                "generation-store-missing",
                descriptor(&p1.id, &p1.model_name, 2),
                2,
            );
            install_active_generation(&storage, &context, &p1.id, 1);
            let registry = LanceDbVectorStoreRegistry::default();
            let data_root = storage.active_data_root().unwrap();
            registry.store_for_write(&data_root).await.unwrap();
            assert!(data_root.join("vectors").join("lancedb").is_dir());
            assert!(!generation_store_root(&data_root, context.generation_id()).exists());
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

            let error =
                resolve_active_generation_retrieval_execution(&storage, &runtime, &registry)
                    .await
                    .err()
                    .unwrap();
            assert_eq!(
                error.code(),
                ActiveGenerationRetrievalErrorCode::GenerationStoreUnavailable
            );
            assert!(!generation_store_root(&data_root, context.generation_id()).exists());
        });
    }

    #[test]
    fn semantic_search_uses_query_once_and_returns_b1_identity_hits() {
        block_on(async {
            let (_temp, storage) = test_storage();
            let context = context(
                "generation-query-contract",
                "descriptor-query-contract".into(),
                2,
            );
            install_active_generation(&storage, &context, "profile-p1", 1);
            let store: Arc<dyn VectorStore> = Arc::new(InMemoryVectorStore::new());
            store.create_generation(&context).await.unwrap();
            store
                .upsert_generation(
                    &context,
                    GenerationVectorRecord::try_new(
                        context.generation_id().clone(),
                        "life-a",
                        "memory-a",
                        7,
                        "content-a",
                        context.descriptor_hash(),
                        vec![1.0, 0.0],
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let (execution, requests) =
                direct_execution(&storage, context, store, vec![vec![1.0, 0.0]], 2);

            let hits = execution
                .semantic_search("life-a", "QUERY_TEXT_CANARY", 10, Some(0.5))
                .await
                .unwrap();
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].memory_id(), "memory-a");
            assert_eq!(hits[0].memory_revision(), 7);
            assert_eq!(hits[0].content_hash(), "content-a");
            assert_eq!(hits[0].score(), 1.0);
            let requests = requests.lock().unwrap();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].purpose, EmbeddingPurpose::Query);
            assert_eq!(requests[0].texts, vec!["QUERY_TEXT_CANARY"]);
        });
    }

    #[test]
    fn invalid_query_fails_before_embedding_and_lance_search() {
        block_on(async {
            let (_temp, storage) = test_storage();
            let context = context(
                "generation-invalid-query",
                "descriptor-invalid-query".into(),
                2,
            );
            install_active_generation(&storage, &context, "profile-p1", 1);
            let calls = Arc::new(AtomicUsize::new(0));
            let store: Arc<dyn VectorStore> = Arc::new(ProbeStore {
                calls: Arc::clone(&calls),
                action: ProbeAction::Fail,
            });
            let (execution, requests) =
                direct_execution(&storage, context, store, vec![vec![1.0, 0.0]], 2);
            let error = execution
                .semantic_search("life-a", "   ", 10, None)
                .await
                .unwrap_err();
            assert_eq!(
                error.code(),
                ActiveGenerationRetrievalErrorCode::InvalidQuery
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert!(requests.lock().unwrap().is_empty());
        });
    }

    #[test]
    fn embedding_dimension_mismatch_fails_before_generation_search() {
        block_on(async {
            let (_temp, storage) = test_storage();
            let context = context(
                "generation-dimension-query",
                "descriptor-dimension-query".into(),
                2,
            );
            install_active_generation(&storage, &context, "profile-p1", 1);
            let calls = Arc::new(AtomicUsize::new(0));
            let store: Arc<dyn VectorStore> = Arc::new(ProbeStore {
                calls: Arc::clone(&calls),
                action: ProbeAction::Fail,
            });
            let (execution, _requests) =
                direct_execution(&storage, context, store, vec![vec![1.0, 0.0, 0.0]], 3);
            let error = execution
                .semantic_search("life-a", "valid query", 10, None)
                .await
                .unwrap_err();
            assert_eq!(
                error.code(),
                ActiveGenerationRetrievalErrorCode::EmbeddingDimensionMismatch
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn multiple_embedding_vectors_fail_closed_without_vector_search() {
        block_on(async {
            let (_temp, storage) = test_storage();
            let context = context(
                "generation-multiple-query",
                "descriptor-multiple-query".into(),
                2,
            );
            install_active_generation(&storage, &context, "profile-p1", 1);
            let calls = Arc::new(AtomicUsize::new(0));
            let store: Arc<dyn VectorStore> = Arc::new(ProbeStore {
                calls: Arc::clone(&calls),
                action: ProbeAction::Fail,
            });
            let (execution, requests) = direct_execution(
                &storage,
                context,
                store,
                vec![vec![1.0, 0.0], vec![0.0, 1.0]],
                2,
            );
            let error = execution
                .semantic_search("life-a", "valid query", 10, None)
                .await
                .unwrap_err();
            assert_eq!(
                error.code(),
                ActiveGenerationRetrievalErrorCode::EmbeddingFailed
            );
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(requests.lock().unwrap().len(), 1);
        });
    }

    #[test]
    fn promotion_during_query_returns_stale_without_hits() {
        block_on(async {
            let (_temp, storage) = test_storage();
            let context_one = context("generation-1", "descriptor-generation-1".into(), 2);
            install_active_generation(&storage, &context_one, "profile-p1", 1);
            let context_two = context("generation-2", "descriptor-generation-2".into(), 2);
            install_ready_generation(&storage, &context_two, "profile-p1", 2);
            let calls = Arc::new(AtomicUsize::new(0));
            let database_path = storage.test_database_main_path().unwrap();
            let store: Arc<dyn VectorStore> = Arc::new(ProbeStore {
                calls: Arc::clone(&calls),
                action: ProbeAction::Promote(database_path),
            });
            let (execution, _requests) =
                direct_execution(&storage, context_one, store, vec![vec![1.0, 0.0]], 2);

            let error = execution
                .semantic_search("life-a", "promotion query", 10, None)
                .await
                .unwrap_err();
            assert_eq!(
                error.code(),
                ActiveGenerationRetrievalErrorCode::GenerationStale
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        });
    }

    #[test]
    fn stable_authority_is_the_read_linearization_point_and_search_is_read_only() {
        block_on(async {
            let (_temp, storage) = test_storage();
            let context = context(
                "generation-stable",
                "descriptor-generation-stable".into(),
                2,
            );
            install_active_generation(&storage, &context, "profile-p1", 1);
            let store: Arc<dyn VectorStore> = Arc::new(InMemoryVectorStore::new());
            store.create_generation(&context).await.unwrap();
            store
                .upsert_generation(
                    &context,
                    GenerationVectorRecord::try_new(
                        context.generation_id().clone(),
                        "life-a",
                        "memory-a",
                        1,
                        "content-a",
                        context.descriptor_hash(),
                        vec![1.0, 0.0],
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let before_sqlite = sqlite_snapshot(&storage);
            let before_changes = storage.total_changes_for_test().unwrap();
            let before_rows = store.count_generation(&context, None).await.unwrap();
            let (execution, _requests) = direct_execution(
                &storage,
                context.clone(),
                Arc::clone(&store),
                vec![vec![1.0, 0.0]],
                2,
            );
            execution
                .semantic_search("life-a", "stable query", 10, None)
                .await
                .unwrap();
            assert_eq!(sqlite_snapshot(&storage), before_sqlite);
            assert_eq!(storage.total_changes_for_test().unwrap(), before_changes);
            assert_eq!(
                store.count_generation(&context, None).await.unwrap(),
                before_rows
            );
        });
    }

    #[test]
    fn search_and_store_errors_never_render_query_or_transport_canaries() {
        block_on(async {
            let (_temp, storage) = test_storage();
            let context = context(
                "generation-redaction",
                "descriptor-generation-redaction".into(),
                2,
            );
            install_active_generation(&storage, &context, "profile-p1", 1);
            let calls = Arc::new(AtomicUsize::new(0));
            let store: Arc<dyn VectorStore> = Arc::new(ProbeStore {
                calls,
                action: ProbeAction::Fail,
            });
            let (execution, _requests) =
                direct_execution(&storage, context, store, vec![vec![1.0, 0.0]], 2);
            let error = execution
                .semantic_search(
                    "life-a",
                    "QUERY_TEXT_CANARY https://provider.invalid/canary",
                    10,
                    None,
                )
                .await
                .unwrap_err();
            let rendered = format!("{error:?} {error}");
            for canary in [
                "QUERY_TEXT_CANARY",
                "CREDENTIAL_CANARY",
                "https://provider.invalid/canary",
                "C:\\secret\\vectors",
            ] {
                assert!(!rendered.contains(canary));
            }
        });
    }
}
