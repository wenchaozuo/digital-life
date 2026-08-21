//! D-9D2 Existing Generation Binding Read Bridge.
//!
//! Provides a sealed, read-only, non-IPC bridge from authoritative SQLite
//! generation metadata, active embedding provider configuration, and managed
//! LanceDB vector store registry to an owned, sealed [`ExistingGenerationFencedExecution`].
//!
//! This module adheres strictly to the following invariants:
//! - Authority source is strictly SQLite `memory_vector_generation` where `state = 'building'`.
//! - Exactly one `building` generation must exist; 0 rows fails with `D9D2_NO_EXISTING_GENERATION`,
//!   and 2+ rows fails with `D9D2_AMBIGUOUS_EXISTING_GENERATION`.
//! - Canonical generation descriptor is computed according to `D9D2_GENERATION_DESCRIPTOR_V1`.
//! - All metadata comparisons (profile, provider model info, dimension, descriptor hash) are exact.
//! - Exact currentness recheck verifies generation authority and authority epoch before sealing.
//! - The resulting types have private fields, no `Clone`, no `Debug`, no `Serialize`/`Deserialize`,
//!   no IPC exposure, no raw scalar getters, and no split getters.
//! - Execution is strictly owned and bounded per-drain; provider and store lifetimes are scoped
//!   to the drain execution and never leak or escape.
//! - Matching vector store is acquired strictly via canonical `active_data_root`, managed registry,
//!   and sealed private generation ID. Arbitrary store injection is impossible.
//! - Absolutely NO generation creation, registration, activation, switching, retirement, or mutation.

use std::fmt::Write as _;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use crate::{
    embedding::{EmbeddingProvider, MAX_VECTOR_DIMENSION, PROTOCOL_VERSION},
    memory::{
        vector_index::MEMORY_INDEX_FORMAT_VERSION,
        vector_sync_worker::{
            drain_fenced_vector_sync, FencedVectorSyncSingleEventConsumer,
            MemoryVectorSyncWorkerError, VectorSyncDrainReport,
        },
    },
    model::{
        profile::{ModelProfileRepository, ModelProviderKind},
        runtime::{
            ModelRuntimePurpose, ModelRuntimeService, ResolvedEmbeddingProvider,
            ResolvedModelProfile,
        },
        transport::url_policy::{
            validate_and_normalize_url, TransportTargetKind, ValidatedTransportTarget,
        },
    },
    secrets::SecretStore,
    storage::{ActiveGenerationAuthority, StorageService},
    vector_store::{
        ExistingGenerationVectorStoreProvider, LanceDbVectorStoreRegistry, VectorGenerationContext,
        VectorStore,
    },
};

#[cfg(test)]
use crate::{model::runtime::ModelRuntimeErrorCode, storage::ExistingBuildingGenerationAuthority};

/// Frozen persisted protocol identifier for a canonical D9 generation binding.
/// This is distinct from the hash domain separator used by descriptor hashing.
pub(crate) const D9D2_GENERATION_DESCRIPTOR_VERSION: &str = "D9D2_GENERATION_DESCRIPTOR_V1";

/// Fixed redacted error codes for D-9D2 generation binding read bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExistingGenerationBindingErrorCode {
    NoExistingGeneration,
    #[cfg(test)]
    AmbiguousExistingGeneration,
    InvalidGenerationMetadata,
    GenerationBindingMismatch,
    GenerationProviderUnavailable,
    GenerationProviderMismatch,
    GenerationBindingStale,
    ExistingVectorStoreUnavailable,
}

impl ExistingGenerationBindingErrorCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NoExistingGeneration => "D9D2_NO_EXISTING_GENERATION",
            #[cfg(test)]
            Self::AmbiguousExistingGeneration => "D9D2_AMBIGUOUS_EXISTING_GENERATION",
            Self::InvalidGenerationMetadata => "D9D2_INVALID_GENERATION_METADATA",
            Self::GenerationBindingMismatch => "D9D2_GENERATION_BINDING_MISMATCH",
            Self::GenerationProviderUnavailable => "D9D2_GENERATION_PROVIDER_UNAVAILABLE",
            Self::GenerationProviderMismatch => "D9D2_GENERATION_PROVIDER_MISMATCH",
            Self::GenerationBindingStale => "D9D2_GENERATION_BINDING_STALE",
            Self::ExistingVectorStoreUnavailable => "D9D2_EXISTING_VECTOR_STORE_UNAVAILABLE",
        }
    }

    pub(crate) const fn safe_message(self) -> &'static str {
        match self {
            Self::NoExistingGeneration => "No existing vector generation is available.",
            #[cfg(test)]
            Self::AmbiguousExistingGeneration => {
                "Multiple existing vector generations found in building state."
            }
            Self::InvalidGenerationMetadata => {
                "The existing vector generation metadata is invalid."
            }
            Self::GenerationBindingMismatch => {
                "The existing vector generation does not match the active descriptor."
            }
            Self::GenerationProviderUnavailable => "The active embedding provider is unavailable.",
            Self::GenerationProviderMismatch => {
                "The active embedding provider configuration is incompatible."
            }
            Self::GenerationBindingStale => "The existing vector generation authority is stale.",
            Self::ExistingVectorStoreUnavailable => "The existing vector store is unavailable.",
        }
    }
}

/// Redacted error type for existing generation binding operations.
/// Does not leak raw identifiers, credentials, hashes, paths, or URLs.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ExistingGenerationBindingError {
    code: ExistingGenerationBindingErrorCode,
}

impl ExistingGenerationBindingError {
    pub(crate) const fn new(code: ExistingGenerationBindingErrorCode) -> Self {
        Self { code }
    }

    pub(crate) const fn code(&self) -> ExistingGenerationBindingErrorCode {
        self.code
    }

    pub(crate) const fn no_existing_generation() -> Self {
        Self::new(ExistingGenerationBindingErrorCode::NoExistingGeneration)
    }

    #[cfg(test)]
    pub(crate) const fn ambiguous_existing_generation() -> Self {
        Self::new(ExistingGenerationBindingErrorCode::AmbiguousExistingGeneration)
    }

    pub(crate) const fn invalid_generation_metadata() -> Self {
        Self::new(ExistingGenerationBindingErrorCode::InvalidGenerationMetadata)
    }

    pub(crate) const fn generation_binding_mismatch() -> Self {
        Self::new(ExistingGenerationBindingErrorCode::GenerationBindingMismatch)
    }

    pub(crate) const fn generation_provider_unavailable() -> Self {
        Self::new(ExistingGenerationBindingErrorCode::GenerationProviderUnavailable)
    }

    pub(crate) const fn generation_provider_mismatch() -> Self {
        Self::new(ExistingGenerationBindingErrorCode::GenerationProviderMismatch)
    }

    pub(crate) const fn generation_binding_stale() -> Self {
        Self::new(ExistingGenerationBindingErrorCode::GenerationBindingStale)
    }

    pub(crate) const fn existing_vector_store_unavailable() -> Self {
        Self::new(ExistingGenerationBindingErrorCode::ExistingVectorStoreUnavailable)
    }
}

impl std::fmt::Display for ExistingGenerationBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.code.safe_message())
    }
}

impl std::fmt::Debug for ExistingGenerationBindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExistingGenerationBindingError")
            .field("code", &self.code.as_str())
            .field("message", &self.code.safe_message())
            .finish()
    }
}

impl std::error::Error for ExistingGenerationBindingError {}

/// Historical building-generation binding retained only for cumulative tests.
///
/// Production ordinary sync now resolves the Schema-17 active-generation
/// capability below, and D9D3 owns the building-generation lifecycle. Keeping
/// this bridge out of non-test builds prevents the retired D9D2 route from
/// becoming a second production authority.
///
/// Deliberately has NO `Clone`, NO `Copy`, NO `Debug`, NO `Serialize`, NO `Deserialize`,
/// NO IPC exposure, NO raw scalar getters, NO split getters, and NO generic callbacks.
#[cfg(test)]
pub(crate) struct ExistingVectorGenerationBinding<'a> {
    context: VectorGenerationContext,
    provider: ResolvedEmbeddingProvider<'a>,
}

#[cfg(test)]
impl<'a> ExistingVectorGenerationBinding<'a> {
    /// Consumes the intermediate binding by value to construct an owned, sealed
    /// [`ExistingGenerationFencedExecution`] using canonical storage root and managed registry.
    ///
    /// The exact matching store is acquired from the managed registry using the private
    /// sealed generation identifier. Neither provider, store, nor context can escape.
    pub(crate) async fn into_fenced_execution<'s>(
        self,
        storage: &'s StorageService,
        registry: &LanceDbVectorStoreRegistry,
    ) -> Result<ExistingGenerationFencedExecution<'s, 'a>, ExistingGenerationBindingError> {
        let data_root = storage
            .active_data_root()
            .map_err(|_| ExistingGenerationBindingError::existing_vector_store_unavailable())?;
        let store_provider = registry
            .bind_existing_generation_provider(&data_root)
            .map_err(|_| ExistingGenerationBindingError::existing_vector_store_unavailable())?;
        let store = store_provider
            .existing_for_generation(self.context.generation_id())
            .await
            .map_err(|_| ExistingGenerationBindingError::existing_vector_store_unavailable())?;
        Ok(ExistingGenerationFencedExecution {
            storage,
            context: self.context,
            provider: self.provider,
            store,
        })
    }
}

/// Opaque, sealed execution capability for the retired D9D2 building drain.
///
/// Strictly holds owned generation context, owned resolved embedding provider,
/// and exact matching existing-generation vector store.
///
/// Deliberately has NO `Clone`, NO `Copy`, NO `Debug`, NO `Serialize`, NO `Deserialize`,
/// NO IPC exposure, NO raw scalar getters, NO split getters, and NO generic callbacks.
#[cfg(test)]
pub(crate) struct ExistingGenerationFencedExecution<'storage, 'provider> {
    storage: &'storage StorageService,
    context: VectorGenerationContext,
    provider: ResolvedEmbeddingProvider<'provider>,
    store: Arc<dyn VectorStore>,
}

/// Sealed ordinary-execution capability for the Schema-17 active generation.
/// Unlike the retained D9D2 building bridge, this capability starts at the
/// singleton active pointer and carries its exact lifecycle epoch through the
/// worker's SQLite fences.
pub(crate) struct ActiveGenerationFencedExecution<'storage, 'provider> {
    storage: &'storage StorageService,
    context: VectorGenerationContext,
    authority_epoch: i64,
    provider: ResolvedEmbeddingProvider<'provider>,
    store: Arc<dyn VectorStore>,
}

impl<'storage, 'provider> ActiveGenerationFencedExecution<'storage, 'provider> {
    pub(crate) async fn drain_bounded(
        self,
        lease_owner: &str,
        limit: usize,
    ) -> Result<VectorSyncDrainReport, MemoryVectorSyncWorkerError> {
        let embedding = self.provider.provider();
        let consumer = FencedVectorSyncSingleEventConsumer::new_active_generation(
            self.storage,
            embedding,
            self.store.as_ref(),
            self.context,
            self.authority_epoch,
        );
        drain_fenced_vector_sync(&consumer, lease_owner, limit).await
    }
}

#[cfg(test)]
impl<'storage, 'provider> ExistingGenerationFencedExecution<'storage, 'provider> {
    /// Executes a bounded, fenced drain over the owned generation context.
    ///
    /// Consumes `self` by value, ensuring that the provider and store lifetimes
    /// are strictly bound to this single drain invocation.
    pub(crate) async fn drain_bounded(
        self,
        lease_owner: &str,
        limit: usize,
    ) -> Result<VectorSyncDrainReport, MemoryVectorSyncWorkerError> {
        let ExistingGenerationFencedExecution {
            storage,
            context,
            provider,
            store,
        } = self;
        let embedding = provider.provider();
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(storage, embedding, store.as_ref(), context);
        drain_fenced_vector_sync(&consumer, lease_owner, limit).await
    }
}

/// Pure raw calculation of the generation descriptor digest according to `D9D2_GENERATION_DESCRIPTOR_V1`.
///
/// Private parameter packaging for the raw descriptor calculation. This is not an
/// authority-bearing API: it only groups the frozen descriptor fields so the raw
/// function stays within the clippy argument limit without lint suppression.
struct CanonicalGenerationDescriptorInput<'a> {
    domain_separator: &'a str,
    memory_index_format_version: &'a str,
    protocol_version: &'a str,
    embedding_kind: &'a str,
    document_kind: &'a str,
    provider_kind_wire: &'a str,
    profile_id: &'a str,
    transport_target_kind: &'a str,
    host_ascii: &'a str,
    effective_port: u16,
    base_path_segments: &'a [&'a str],
    endpoint_kind: &'a str,
    trimmed_model_name: &'a str,
    dimension: usize,
}

fn compute_canonical_generation_descriptor_raw(
    input: &CanonicalGenerationDescriptorInput<'_>,
) -> String {
    let CanonicalGenerationDescriptorInput {
        domain_separator,
        memory_index_format_version,
        protocol_version,
        embedding_kind,
        document_kind,
        provider_kind_wire,
        profile_id,
        transport_target_kind,
        host_ascii,
        effective_port,
        base_path_segments,
        endpoint_kind,
        trimmed_model_name,
        dimension,
    } = *input;
    let mut hasher = Sha256::new();

    hash_length_prefixed(&mut hasher, domain_separator);
    hash_length_prefixed(&mut hasher, memory_index_format_version);
    hash_length_prefixed(&mut hasher, protocol_version);
    hash_length_prefixed(&mut hasher, embedding_kind);
    hash_length_prefixed(&mut hasher, document_kind);
    hash_length_prefixed(&mut hasher, provider_kind_wire);
    hash_length_prefixed(&mut hasher, profile_id);
    hash_length_prefixed(&mut hasher, transport_target_kind);
    hash_length_prefixed(&mut hasher, host_ascii);
    hasher.update(effective_port.to_be_bytes());
    hasher.update((base_path_segments.len() as u64).to_be_bytes());
    for segment in base_path_segments {
        hash_length_prefixed(&mut hasher, segment);
    }
    hash_length_prefixed(&mut hasher, endpoint_kind);
    hash_length_prefixed(&mut hasher, trimmed_model_name);
    hasher.update((dimension as u64).to_be_bytes());

    let digest = hasher.finalize();
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

/// Computes the canonical generation descriptor digest according to `D9D2_GENERATION_DESCRIPTOR_V1`.
pub(crate) fn compute_canonical_generation_descriptor(
    provider_kind: &ModelProviderKind,
    profile_id: &str,
    transport_target: &ValidatedTransportTarget,
    model_name: &str,
    dimension: usize,
) -> Result<String, ExistingGenerationBindingError> {
    let target_kind_str = match transport_target.kind() {
        TransportTargetKind::RemoteHttps => "remote_https",
        TransportTargetKind::LoopbackHttp => "loopback_http",
    };
    let segments: Vec<&str> = transport_target.base_path().segments().collect();

    Ok(compute_canonical_generation_descriptor_raw(
        &CanonicalGenerationDescriptorInput {
            domain_separator: "digital-life-vector-generation-descriptor-v1",
            memory_index_format_version: MEMORY_INDEX_FORMAT_VERSION,
            protocol_version: PROTOCOL_VERSION,
            embedding_kind: "embedding",
            document_kind: "document",
            provider_kind_wire: provider_kind.as_str(),
            profile_id,
            transport_target_kind: target_kind_str,
            host_ascii: transport_target.host_ascii(),
            effective_port: transport_target.port(),
            base_path_segments: &segments,
            endpoint_kind: "embeddings",
            trimmed_model_name: model_name.trim(),
            dimension,
        },
    ))
}

fn hash_length_prefixed(hasher: &mut Sha256, s: &str) {
    hasher.update((s.len() as u64).to_be_bytes());
    hasher.update(s.as_bytes());
}

/// Verifies exact compatibility of active profile and embedding provider facts.
///
/// Returns the verified dimension on exact match.
/// Fails closed with `D9D2_GENERATION_PROVIDER_MISMATCH` if provider dimension is `None`
/// or if any dimension/purpose/model fact differs.
pub(crate) fn verify_provider_facts(
    profile: &ResolvedModelProfile,
    provider: &dyn EmbeddingProvider,
) -> Result<usize, ExistingGenerationBindingError> {
    if profile.purpose != ModelRuntimePurpose::Embedding {
        return Err(ExistingGenerationBindingError::generation_provider_mismatch());
    }

    let profile_dimension = match profile.embedding_dimension {
        Some(dim) if dim > 0 && dim <= MAX_VECTOR_DIMENSION as u32 => dim as usize,
        _ => return Err(ExistingGenerationBindingError::generation_provider_mismatch()),
    };

    let provider_model_info = provider.model_info();
    match provider_model_info.dimension {
        Some(prov_dim) => {
            if prov_dim != profile_dimension {
                return Err(ExistingGenerationBindingError::generation_provider_mismatch());
            }
        }
        None => {
            // Provider dimension must be exact. Fail closed on None.
            return Err(ExistingGenerationBindingError::generation_provider_mismatch());
        }
    }

    if provider_model_info.model_name.trim() != profile.model_name.trim() {
        return Err(ExistingGenerationBindingError::generation_provider_mismatch());
    }

    Ok(profile_dimension)
}

/// Resolves the intermediate existing vector generation binding from SQLite generation authority and active model runtime.
#[cfg(test)]
pub(crate) fn resolve_existing_generation_binding<'a, R, S>(
    storage: &StorageService,
    runtime: &'a ModelRuntimeService<'a, R, S>,
) -> Result<ExistingVectorGenerationBinding<'a>, ExistingGenerationBindingError>
where
    R: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    // 1. Query unique SQLite building candidate
    let authority: ExistingBuildingGenerationAuthority =
        storage.load_existing_building_generation_candidate()?;

    // 2. Resolve active embedding provider candidate
    let resolved_provider = runtime
        .resolve_active_embedding_provider()
        .map_err(|err| match err.code {
            ModelRuntimeErrorCode::NoActiveProfile => {
                ExistingGenerationBindingError::generation_provider_unavailable()
            }
            _ => ExistingGenerationBindingError::generation_provider_unavailable(),
        })?;

    // 3. Inspect profile facts and enforce triple exact dimension check
    let profile = &resolved_provider.profile;
    let profile_dimension = verify_provider_facts(profile, resolved_provider.provider())?;

    // 4. Transport normalization
    let transport_target = validate_and_normalize_url(&profile.base_url)
        .map_err(|_| ExistingGenerationBindingError::generation_provider_mismatch())?;

    // 5. Compute canonical descriptor
    let canonical_descriptor = compute_canonical_generation_descriptor(
        &profile.provider_kind,
        &profile.profile_id,
        &transport_target,
        &profile.model_name,
        profile_dimension,
    )?;

    // 6. Verify candidate authority compatibility
    authority.verify_descriptor_and_dimension(&canonical_descriptor, profile_dimension)?;

    // 7. Perform exact authority recheck against SQLite before sealing
    let context = authority.verify_current_and_seal(storage)?;

    // 8. Construct sealed binding
    Ok(ExistingVectorGenerationBinding {
        context,
        provider: resolved_provider,
    })
}

/// Resolves the owned, sealed [`ExistingGenerationFencedExecution`] from authoritative services.
///
/// Caller supplies ONLY canonical authority services:
/// - `&StorageService`
/// - `&ModelRuntimeService`
/// - `&LanceDbVectorStoreRegistry`
///
/// The caller cannot supply arbitrary generation IDs, contexts, providers, stores, or filesystem paths.
#[cfg(test)]
pub(crate) async fn resolve_existing_generation_fenced_execution<'storage, 'runtime, R, S>(
    storage: &'storage StorageService,
    runtime: &'runtime ModelRuntimeService<'runtime, R, S>,
    registry: &LanceDbVectorStoreRegistry,
) -> Result<ExistingGenerationFencedExecution<'storage, 'runtime>, ExistingGenerationBindingError>
where
    R: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    let binding = resolve_existing_generation_binding(storage, runtime)?;
    binding.into_fenced_execution(storage, registry).await
}

/// Resolves the only capability used by ordinary production Vector Sync after
/// Schema 17.  The immutable binding supplies the profile id; the process-wide
/// active profile is deliberately not consulted.
pub(crate) async fn resolve_active_generation_fenced_execution<'storage, 'runtime, R, S>(
    storage: &'storage StorageService,
    runtime: &'runtime ModelRuntimeService<'runtime, R, S>,
    registry: &LanceDbVectorStoreRegistry,
) -> Result<ActiveGenerationFencedExecution<'storage, 'runtime>, ExistingGenerationBindingError>
where
    R: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    let authority: ActiveGenerationAuthority = storage.load_active_generation_authority()?;
    let resolved_provider = runtime
        .resolve_embedding_provider(authority.bound_embedding_profile_id())
        .map_err(|_| ExistingGenerationBindingError::generation_provider_unavailable())?;
    let profile = &resolved_provider.profile;
    let profile_dimension = verify_provider_facts(profile, resolved_provider.provider())?;
    let transport_target = validate_and_normalize_url(&profile.base_url)
        .map_err(|_| ExistingGenerationBindingError::generation_provider_mismatch())?;
    let descriptor = compute_canonical_generation_descriptor(
        &profile.provider_kind,
        &profile.profile_id,
        &transport_target,
        &profile.model_name,
        profile_dimension,
    )?;
    authority.verify_descriptor_and_dimension(&descriptor, profile_dimension)?;
    let (context, authority_epoch) = authority.verify_current_and_seal(storage)?;
    let data_root = storage
        .active_data_root()
        .map_err(|_| ExistingGenerationBindingError::existing_vector_store_unavailable())?;
    let store_provider = registry
        .bind_existing_generation_provider(&data_root)
        .map_err(|_| ExistingGenerationBindingError::existing_vector_store_unavailable())?;
    let store = store_provider
        .existing_for_generation(context.generation_id())
        .await
        .map_err(|_| ExistingGenerationBindingError::existing_vector_store_unavailable())?;
    Ok(ActiveGenerationFencedExecution {
        storage,
        context,
        authority_epoch,
        provider: resolved_provider,
        store,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::Duration;

    use rusqlite::params;
    use tempfile::TempDir;

    use super::*;
    use crate::{
        embedding::{
            EmbeddingBatch, EmbeddingError, EmbeddingErrorCode, EmbeddingFuture,
            EmbeddingModelInfo, EmbeddingRequest,
        },
        model::{
            profile::{
                CreateModelProfileRequest, ModelProfileService, ModelProviderKind, ModelPurpose,
                SetActiveModelProfileRequest,
            },
            runtime::{ModelRuntimeCoordinator, ModelRuntimeService},
            transport::url_policy::validate_and_normalize_url,
        },
        secrets::{
            InMemorySecretStore, SecretIdentifier, SecretPurpose, SecretStatus, SecretStoreError,
            SecretValue,
        },
        storage::{open_authorized_test_connection, ExistingGenerationBindingObservationResult},
        vector_store::{LanceDbVectorStore, VectorGenerationId},
    };

    fn test_storage() -> (TempDir, StorageService) {
        let temp_dir = tempfile::tempdir().unwrap();
        let service =
            StorageService::initialize_with_roots(temp_dir.path().join("data"), None).unwrap();
        (temp_dir, service)
    }

    fn store_credential<S>(secrets: &S, profile_id: &str)
    where
        S: SecretStore + ?Sized,
    {
        secrets
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, profile_id).unwrap(),
                SecretValue::new("fake-api-key".into()).unwrap(),
            )
            .unwrap();
    }

    fn create_test_profile<S>(
        storage: &StorageService,
        secrets: &S,
        base_url: &str,
        model_name: &str,
        dimension: u32,
    ) -> String
    where
        S: SecretStore + ?Sized,
    {
        let created = ModelProfileService::new(storage)
            .create(CreateModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "Test Embedding Profile".into(),
                base_url: base_url.into(),
                model_name: model_name.into(),
                temperature: None,
                max_tokens: None,
                embedding_dimension: Some(dimension),
            })
            .unwrap();
        ModelProfileService::new(storage)
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                profile_id: created.id.clone(),
            })
            .unwrap();
        store_credential(secrets, &created.id);
        created.id
    }

    fn insert_generation_fixture(
        storage: &StorageService,
        generation_id: &str,
        descriptor_hash: &str,
        dimension: usize,
        state: &str,
        authority_epoch: i64,
    ) {
        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        conn.execute(
            "INSERT INTO memory_vector_generation (generation_id, descriptor_hash, dimension, state, authority_epoch)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![generation_id, descriptor_hash, dimension as i64, state, authority_epoch],
        )
        .unwrap();
    }

    fn assert_second_building_fixture_rejected(
        storage: &StorageService,
        generation_id: &str,
        descriptor_hash: &str,
        dimension: usize,
    ) {
        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        let error = conn
            .execute(
                "INSERT INTO memory_vector_generation
                 (generation_id, descriptor_hash, dimension, state, authority_epoch)
                 VALUES (?1, ?2, ?3, 'building', 1)",
                params![generation_id, descriptor_hash, dimension as i64],
            )
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("UNIQUE constraint failed: memory_vector_generation.state"),
            "Schema 17 must reject a second building generation: {error}"
        );
    }

    async fn setup_pre_existing_lance_store(
        storage: &StorageService,
        registry: &LanceDbVectorStoreRegistry,
        generation_id: &str,
    ) -> Arc<LanceDbVectorStore> {
        let data_root = storage.active_data_root().unwrap();
        let gen_id = VectorGenerationId::parse(generation_id).unwrap();
        registry
            .generation_store_for_write(&data_root, &gen_id)
            .await
            .unwrap()
    }

    fn install_active_generation_fixture(
        storage: &StorageService,
        generation_id: &str,
        descriptor_hash: &str,
        dimension: usize,
        profile_id: &str,
        descriptor_version: &str,
        witness_state: &str,
    ) {
        insert_generation_fixture(
            storage,
            generation_id,
            descriptor_hash,
            dimension,
            "active",
            1,
        );
        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        conn.execute(
            "INSERT INTO memory_vector_generation_binding
             (generation_id,descriptor_version,embedding_profile_id,created_at)
             VALUES (?1,?2,?3,'2026-01-01T00:00:00.000Z')",
            params![generation_id, descriptor_version, profile_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO memory_vector_generation_store_witness
             (generation_id,create_operation_id,state,last_error_code,updated_at)
             VALUES (?1,NULL,?2,NULL,'2026-01-01T00:00:00.000Z')",
            params![generation_id, witness_state],
        )
        .unwrap();
        conn.execute(
            "UPDATE memory_vector_generation_authority
             SET active_generation_id=?1,updated_at='2026-01-01T00:00:00.000Z'
             WHERE singleton=1",
            [generation_id],
        )
        .unwrap();
    }

    fn canonical_test_descriptor(profile_id: &str, dimension: usize) -> String {
        compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            profile_id,
            &validate_and_normalize_url("https://api.openai.com/v1").unwrap(),
            "text-embedding-3-small",
            dimension,
        )
        .unwrap()
    }

    fn insert_outbox_fixture(
        storage: &StorageService,
        memory_id: &str,
        state: &str,
        attempt_count: i64,
        generation_id: Option<&str>,
        authority_epoch: Option<i64>,
    ) {
        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        conn.execute(
            "INSERT INTO memory_vector_sync_outbox
             (life_id,memory_id,desired_action,state,attempt_count,mutation_sequence,
              claimed_generation_id,claimed_generation_authority_epoch,created_at,updated_at)
             VALUES ('d9d3-b-life',?1,'delete',?2,?3,1,?4,?5,
                     '2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')",
            params![
                memory_id,
                state,
                attempt_count,
                generation_id,
                authority_epoch
            ],
        )
        .unwrap();
    }

    fn insert_upsert_outbox_fixture(
        storage: &StorageService,
        memory_id: &str,
        state: &str,
        attempt_count: i64,
        generation_id: Option<&str>,
        authority_epoch: Option<i64>,
    ) {
        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        conn.execute(
            "INSERT INTO memory_vector_sync_outbox
             (life_id,memory_id,desired_action,state,attempt_count,mutation_sequence,
              target_revision,target_content_hash,claimed_generation_id,
              claimed_generation_authority_epoch,next_attempt_at,created_at,updated_at)
             VALUES ('d9d3-b-life',?1,'upsert',?2,?3,1,1,'d9d3-b-content',?4,?5,
                     CASE WHEN ?2='retry_wait' THEN '1970-01-01T00:00:00.000Z' ELSE NULL END,
                     '2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z')",
            params![
                memory_id,
                state,
                attempt_count,
                generation_id,
                authority_epoch
            ],
        )
        .unwrap();
    }

    struct MockEmbeddingProviderWithoutDimension;

    impl EmbeddingProvider for MockEmbeddingProviderWithoutDimension {
        fn model_info(&self) -> EmbeddingModelInfo {
            EmbeddingModelInfo {
                model_name: "text-embedding-3-small".into(),
                dimension: None,
            }
        }
        fn model_name(&self) -> &str {
            "text-embedding-3-small"
        }
        fn vector_dimension(&self) -> Option<usize> {
            None
        }
        fn max_batch_size(&self) -> usize {
            1
        }
        fn embed<'a>(
            &'a self,
            _request: EmbeddingRequest,
        ) -> EmbeddingFuture<'a, Result<EmbeddingBatch, EmbeddingError>> {
            Box::pin(async {
                Err(EmbeddingError::definitely_not_sent(
                    EmbeddingErrorCode::InvalidRequest,
                ))
            })
        }
    }

    struct TrackingSecretStore {
        inner: InMemorySecretStore,
        reads: Arc<AtomicUsize>,
    }

    impl TrackingSecretStore {
        fn new() -> (Self, Arc<AtomicUsize>) {
            let reads = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    inner: InMemorySecretStore::new(),
                    reads: Arc::clone(&reads),
                },
                reads,
            )
        }
    }

    impl SecretStore for TrackingSecretStore {
        fn set_secret(
            &self,
            identifier: &SecretIdentifier,
            value: SecretValue,
        ) -> Result<SecretStatus, SecretStoreError> {
            self.inner.set_secret(identifier, value)
        }

        fn get_secret(
            &self,
            identifier: &SecretIdentifier,
        ) -> Result<SecretValue, SecretStoreError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.get_secret(identifier)
        }

        fn has_secret(&self, identifier: &SecretIdentifier) -> Result<bool, SecretStoreError> {
            self.inner.has_secret(identifier)
        }

        fn delete_secret(
            &self,
            identifier: &SecretIdentifier,
        ) -> Result<SecretStatus, SecretStoreError> {
            self.inner.delete_secret(identifier)
        }
    }

    #[test]
    fn d9d2_existing_generation_binding_golden_descriptor_vectors() {
        let target_a = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
        let desc_a = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            "profile-openai",
            &target_a,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();

        // 1. Exact hardcoded literal golden SHA-256 digest
        assert_eq!(
            desc_a,
            "b9b5e4d839faa4a74a0c2b302ecddeb8a474f416909c704327029f948c3d91b6"
        );
        assert_eq!(desc_a.len(), 64);
        assert!(desc_a.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));

        // 2. Golden vector stability: whitespace trimming produces identical digest
        let desc_a_again = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            "profile-openai",
            &target_a,
            "  text-embedding-3-small  ",
            1536,
        )
        .unwrap();
        assert_eq!(
            desc_a, desc_a_again,
            "Trimming model name must produce identical digest"
        );

        // 3. Profile ID change produces different digest
        let desc_b = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            "profile-other",
            &target_a,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();
        assert_ne!(
            desc_a, desc_b,
            "Profile ID change must produce different digest"
        );

        // 4. Path segmentation difference produces different digest
        let target_seg1 = validate_and_normalize_url("http://127.0.0.1:8000/v1/sub").unwrap();
        let target_seg2 = validate_and_normalize_url("http://127.0.0.1:8000/v1sub").unwrap();
        let desc_seg1 = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            "profile-openai",
            &target_seg1,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();
        let desc_seg2 = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            "profile-openai",
            &target_seg2,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();
        assert_ne!(
            desc_seg1, desc_seg2,
            "Path segmentation difference must produce different digest"
        );

        // 5. Dimension difference produces different digest
        let desc_dim = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            "profile-openai",
            &target_a,
            "text-embedding-3-small",
            768,
        )
        .unwrap();
        assert_ne!(
            desc_a, desc_dim,
            "Dimension difference must produce different digest"
        );
    }

    #[test]
    fn d9d2_existing_generation_binding_descriptor_field_matrix() {
        let base_digest =
            compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                domain_separator: "digital-life-vector-generation-descriptor-v1",
                memory_index_format_version: "memory-index-v1",
                protocol_version: "openai-compatible-embedding-v1",
                embedding_kind: "embedding",
                document_kind: "document",
                provider_kind_wire: "openai_compatible",
                profile_id: "profile-openai",
                transport_target_kind: "remote_https",
                host_ascii: "api.openai.com",
                effective_port: 443,
                base_path_segments: &["v1"],
                endpoint_kind: "embeddings",
                trimmed_model_name: "text-embedding-3-small",
                dimension: 1536,
            });

        assert_eq!(
            base_digest,
            "b9b5e4d839faa4a74a0c2b302ecddeb8a474f416909c704327029f948c3d91b6"
        );

        // Matrix covering every individual field and constant
        let variations = vec![
            (
                "domain_separator",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "other-domain-separator",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "embedding",
                    document_kind: "document",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-openai",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.openai.com",
                    effective_port: 443,
                    base_path_segments: &["v1"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 1536,
                }),
            ),
            (
                "memory_index_format_version",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v2",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "embedding",
                    document_kind: "document",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-openai",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.openai.com",
                    effective_port: 443,
                    base_path_segments: &["v1"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 1536,
                }),
            ),
            (
                "protocol_version",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v2",
                    embedding_kind: "embedding",
                    document_kind: "document",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-openai",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.openai.com",
                    effective_port: 443,
                    base_path_segments: &["v1"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 1536,
                }),
            ),
            (
                "embedding_kind",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "chat",
                    document_kind: "document",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-openai",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.openai.com",
                    effective_port: 443,
                    base_path_segments: &["v1"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 1536,
                }),
            ),
            (
                "document_kind",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "embedding",
                    document_kind: "query",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-openai",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.openai.com",
                    effective_port: 443,
                    base_path_segments: &["v1"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 1536,
                }),
            ),
            (
                "provider_kind_wire",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "embedding",
                    document_kind: "document",
                    provider_kind_wire: "custom_provider",
                    profile_id: "profile-openai",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.openai.com",
                    effective_port: 443,
                    base_path_segments: &["v1"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 1536,
                }),
            ),
            (
                "profile_id",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "embedding",
                    document_kind: "document",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-different",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.openai.com",
                    effective_port: 443,
                    base_path_segments: &["v1"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 1536,
                }),
            ),
            (
                "transport_target_kind",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "embedding",
                    document_kind: "document",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-openai",
                    transport_target_kind: "loopback_http",
                    host_ascii: "api.openai.com",
                    effective_port: 443,
                    base_path_segments: &["v1"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 1536,
                }),
            ),
            (
                "host_ascii",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "embedding",
                    document_kind: "document",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-openai",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.custom.com",
                    effective_port: 443,
                    base_path_segments: &["v1"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 1536,
                }),
            ),
            (
                "effective_port",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "embedding",
                    document_kind: "document",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-openai",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.openai.com",
                    effective_port: 8443,
                    base_path_segments: &["v1"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 1536,
                }),
            ),
            (
                "base_path_segments_count",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "embedding",
                    document_kind: "document",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-openai",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.openai.com",
                    effective_port: 443,
                    base_path_segments: &["v1", "extra"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 1536,
                }),
            ),
            (
                "base_path_segments_value",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "embedding",
                    document_kind: "document",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-openai",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.openai.com",
                    effective_port: 443,
                    base_path_segments: &["v2"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 1536,
                }),
            ),
            (
                "endpoint_kind",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "embedding",
                    document_kind: "document",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-openai",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.openai.com",
                    effective_port: 443,
                    base_path_segments: &["v1"],
                    endpoint_kind: "vectors",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 1536,
                }),
            ),
            (
                "model_name",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "embedding",
                    document_kind: "document",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-openai",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.openai.com",
                    effective_port: 443,
                    base_path_segments: &["v1"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-large",
                    dimension: 1536,
                }),
            ),
            (
                "dimension",
                compute_canonical_generation_descriptor_raw(&CanonicalGenerationDescriptorInput {
                    domain_separator: "digital-life-vector-generation-descriptor-v1",
                    memory_index_format_version: "memory-index-v1",
                    protocol_version: "openai-compatible-embedding-v1",
                    embedding_kind: "embedding",
                    document_kind: "document",
                    provider_kind_wire: "openai_compatible",
                    profile_id: "profile-openai",
                    transport_target_kind: "remote_https",
                    host_ascii: "api.openai.com",
                    effective_port: 443,
                    base_path_segments: &["v1"],
                    endpoint_kind: "embeddings",
                    trimmed_model_name: "text-embedding-3-small",
                    dimension: 3072,
                }),
            ),
        ];

        for (field_name, varied_digest) in variations {
            assert_ne!(
                base_digest, varied_digest,
                "Field change in '{field_name}' must produce distinct digest"
            );
        }
    }

    #[test]
    fn d9d2_existing_generation_binding_provider_dimension_none_fails_closed() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let _profile_id = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
        let resolved = runtime.resolve_active_embedding_provider().unwrap();

        // When provider model_info dimension is None -> must fail closed
        let mock_provider = MockEmbeddingProviderWithoutDimension;
        let res = verify_provider_facts(&resolved.profile, &mock_provider);
        assert!(res.is_err());
        let err = match res {
            Err(e) => e,
            Ok(_) => panic!("expected provider mismatch error on None dimension"),
        };
        assert_eq!(
            err.code(),
            ExistingGenerationBindingErrorCode::GenerationProviderMismatch
        );
    }

    #[test]
    fn d9d2_existing_generation_binding_zero_building_returns_no_existing_generation() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
        let registry = LanceDbVectorStoreRegistry::default();

        let res = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
            &storage, &runtime, &registry,
        ));
        let err = match res {
            Err(e) => e,
            Ok(_) => panic!("expected NoExistingGeneration error"),
        };
        assert_eq!(
            err.code(),
            ExistingGenerationBindingErrorCode::NoExistingGeneration
        );
    }

    #[test]
    fn d9d2_existing_generation_binding_one_exact_valid_binding_succeeds() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let profile_id = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );

        let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
        let canonical_desc = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            &profile_id,
            &target,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();

        insert_generation_fixture(
            &storage,
            "generation-1",
            &canonical_desc,
            1536,
            "building",
            1,
        );

        let registry = LanceDbVectorStoreRegistry::default();
        let _pre_created = tauri::async_runtime::block_on(setup_pre_existing_lance_store(
            &storage,
            &registry,
            "generation-1",
        ));

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

        let execution = tauri::async_runtime::block_on(
            resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
        )
        .unwrap();

        let report =
            tauri::async_runtime::block_on(execution.drain_bounded("test-worker-1", 32)).unwrap();

        assert_eq!(report.processed, 0);
        assert!(report.stopped_no_eligible);
    }

    #[test]
    fn d9d3_b_active_authority_loader_matrix_fails_closed_and_accepts_exact_ready_binding() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let profile_id = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );
        let descriptor = canonical_test_descriptor(&profile_id, 1536);

        // A1: the Schema17 singleton starts with no active pointer.
        assert!(storage.load_active_generation_authority().is_err());

        // A7: an active pointer without immutable binding or witness is never authority.
        insert_generation_fixture(&storage, "active-matrix", &descriptor, 1536, "active", 1);
        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        conn.execute(
            "UPDATE memory_vector_generation_authority SET active_generation_id='active-matrix' WHERE singleton=1",
            [],
        )
        .unwrap();
        assert!(storage.load_active_generation_authority().is_err());

        conn.execute(
            "INSERT INTO memory_vector_generation_binding (generation_id,descriptor_version,embedding_profile_id,created_at)
             VALUES ('active-matrix',?1,?2,'2026-01-01T00:00:00.000Z')",
            params![D9D2_GENERATION_DESCRIPTOR_VERSION, profile_id],
        )
        .unwrap();
        for witness in [
            "unverified",
            "absent",
            "create_started",
            "uncertain",
            "deleted",
        ] {
            conn.execute(
                "INSERT INTO memory_vector_generation_store_witness
                 (generation_id,create_operation_id,state,last_error_code,updated_at)
                 VALUES ('active-matrix',NULL,?1,NULL,'2026-01-01T00:00:00.000Z')
                 ON CONFLICT(generation_id) DO UPDATE SET state=excluded.state",
                [witness],
            )
            .unwrap();
            assert!(
                storage.load_active_generation_authority().is_err(),
                "{witness}"
            );
        }
        conn.execute(
            "UPDATE memory_vector_generation_store_witness SET state='ready' WHERE generation_id='active-matrix'",
            [],
        )
        .unwrap();
        assert!(storage.load_active_generation_authority().is_ok());
    }

    #[test]
    fn d9d3_b_active_resolver_uses_bound_profile_not_global_profile_and_requires_existing_store() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let profile_a = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );
        let profile_b = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            768,
        );
        let descriptor = canonical_test_descriptor(&profile_a, 1536);
        install_active_generation_fixture(
            &storage,
            "active-bound-profile",
            &descriptor,
            1536,
            &profile_a,
            D9D2_GENERATION_DESCRIPTOR_VERSION,
            "ready",
        );
        let registry = LanceDbVectorStoreRegistry::default();
        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
        // The global profile is B; before an exact existing store exists, B must
        // not be used as a fallback and resolution fails closed.
        assert_ne!(profile_a, profile_b);
        assert!(
            tauri::async_runtime::block_on(resolve_active_generation_fenced_execution(
                &storage, &runtime, &registry,
            ))
            .is_err()
        );
        let _store = tauri::async_runtime::block_on(setup_pre_existing_lance_store(
            &storage,
            &registry,
            "active-bound-profile",
        ));
        let execution = tauri::async_runtime::block_on(resolve_active_generation_fenced_execution(
            &storage, &runtime, &registry,
        ));
        assert!(execution.is_ok());
    }

    #[test]
    fn d9d3_b_active_claim_persists_generation_and_epoch_atomically() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let profile = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );
        let descriptor = canonical_test_descriptor(&profile, 1536);
        install_active_generation_fixture(
            &storage,
            "active-claim",
            &descriptor,
            1536,
            &profile,
            D9D2_GENERATION_DESCRIPTOR_VERSION,
            "ready",
        );
        insert_outbox_fixture(&storage, "active-claim-memory", "pending", 0, None, None);
        let claim = storage
            .claim_one_active_fenced_vector_sync_with_retry_cutoff(
                "active-claim",
                &descriptor,
                1536,
                1,
                "active-claim-worker",
                Some(0),
            )
            .unwrap();
        assert!(claim.is_some());
        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        let persisted: (Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT claimed_generation_id,claimed_generation_authority_epoch
                 FROM memory_vector_sync_outbox WHERE memory_id='active-claim-memory'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(persisted, (Some("active-claim".into()), Some(1)));
    }

    #[test]
    fn d9d3_b_historical_null_epoch_cannot_be_claimed_or_rebound() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let profile = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );
        let descriptor = canonical_test_descriptor(&profile, 1536);
        install_active_generation_fixture(
            &storage,
            "active-historical",
            &descriptor,
            1536,
            &profile,
            D9D2_GENERATION_DESCRIPTOR_VERSION,
            "ready",
        );
        insert_outbox_fixture(
            &storage,
            "historical-null-epoch",
            "retry_wait",
            1,
            Some("active-historical"),
            None,
        );
        assert!(storage
            .claim_one_active_fenced_vector_sync_with_retry_cutoff(
                "active-historical",
                &descriptor,
                1536,
                1,
                "historical-worker",
                Some(0),
            )
            .unwrap()
            .is_none());
        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        let persisted: (i64, Option<i64>) = conn
            .query_row(
                "SELECT attempt_count,claimed_generation_authority_epoch
             FROM memory_vector_sync_outbox WHERE memory_id='historical-null-epoch'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(persisted, (1, None));
    }

    #[test]
    fn d9d3_b_stale_active_authority_cannot_reserve_attempt() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let profile = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );
        let descriptor = canonical_test_descriptor(&profile, 1536);
        install_active_generation_fixture(
            &storage,
            "active-stale",
            &descriptor,
            1536,
            &profile,
            D9D2_GENERATION_DESCRIPTOR_VERSION,
            "ready",
        );
        insert_outbox_fixture(&storage, "stale-reservation", "pending", 0, None, None);
        let claim = storage
            .claim_one_active_fenced_vector_sync_with_retry_cutoff(
                "active-stale",
                &descriptor,
                1536,
                1,
                "stale-worker",
                Some(0),
            )
            .unwrap()
            .unwrap();
        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        conn.execute(
            "UPDATE memory_vector_generation_authority SET active_generation_id=NULL WHERE singleton=1",
            [],
        )
        .unwrap();
        assert!(matches!(
            storage.reserve_fenced_attempt(&claim).unwrap(),
            crate::storage::FencedAttemptReservation::LostLeaseOrSuperseded
        ));
        let attempts: i64 = conn.query_row(
            "SELECT attempt_count FROM memory_vector_sync_outbox WHERE memory_id='stale-reservation'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(attempts, 0);
    }

    #[test]
    fn d9d3_b_stale_active_token_cannot_success_or_failure_finalize_or_mark_delete_witness() {
        let make_active = |storage: &StorageService, generation_id: &str, profile: &str| {
            let descriptor = canonical_test_descriptor(profile, 1536);
            install_active_generation_fixture(
                storage,
                generation_id,
                &descriptor,
                1536,
                profile,
                D9D2_GENERATION_DESCRIPTOR_VERSION,
                "ready",
            );
            descriptor
        };

        // A stale Upsert token cannot create a generation item or delete its
        // outbox row as a successful completion.
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let profile = create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );
            let descriptor = make_active(&storage, "stale-success", &profile);
            insert_upsert_outbox_fixture(
                &storage,
                "stale-success-memory",
                "pending",
                0,
                None,
                None,
            );
            let claim = storage
                .claim_one_active_fenced_vector_sync_with_retry_cutoff(
                    "stale-success",
                    &descriptor,
                    1536,
                    1,
                    "stale-success-worker",
                    Some(0),
                )
                .unwrap()
                .unwrap();
            let token = match storage.reserve_fenced_attempt(&claim).unwrap() {
                crate::storage::FencedAttemptReservation::Reserved(token) => token,
                _ => panic!("expected reserved token"),
            };
            let conn = open_authorized_test_connection(&storage.test_database_main_path().unwrap())
                .unwrap();
            conn.execute(
                "UPDATE memory_vector_generation_authority SET active_generation_id=NULL WHERE singleton=1",
                [],
            )
            .unwrap();
            assert_eq!(
                storage.finalize_fenced_vector_sync(&token).unwrap(),
                crate::storage::FencedFinalizeResult::LostLeaseOrSuperseded
            );
            let item_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM memory_vector_generation_item WHERE generation_id='stale-success'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let outbox_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM memory_vector_sync_outbox WHERE memory_id='stale-success-memory'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(item_count, 0);
            assert_eq!(outbox_count, 1);
        }

        // A stale Upsert token cannot create a retry that could later run under
        // another authority world.
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let profile = create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );
            let descriptor = make_active(&storage, "stale-failure", &profile);
            insert_upsert_outbox_fixture(
                &storage,
                "stale-failure-memory",
                "pending",
                0,
                None,
                None,
            );
            let claim = storage
                .claim_one_active_fenced_vector_sync_with_retry_cutoff(
                    "stale-failure",
                    &descriptor,
                    1536,
                    1,
                    "stale-failure-worker",
                    Some(0),
                )
                .unwrap()
                .unwrap();
            let token = match storage.reserve_fenced_attempt(&claim).unwrap() {
                crate::storage::FencedAttemptReservation::Reserved(token) => token,
                _ => panic!("expected reserved token"),
            };
            let conn = open_authorized_test_connection(&storage.test_database_main_path().unwrap())
                .unwrap();
            conn.execute(
                "UPDATE memory_vector_generation_authority SET active_generation_id=NULL WHERE singleton=1",
                [],
            )
            .unwrap();
            assert_eq!(
                storage
                    .finalize_fenced_vector_failure(
                        &token,
                        "PROVIDER_UNAVAILABLE",
                        crate::storage::FencedFailureDecision::RetryAfter { delay_millis: 1 },
                        Some("definitely_not_sent"),
                        0,
                        0,
                    )
                    .unwrap(),
                crate::storage::FencedFailureFinalizeResult::LostLeaseOrSuperseded
            );
            let state: String = conn
                .query_row(
                    "SELECT state FROM memory_vector_sync_outbox WHERE memory_id='stale-failure-memory'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(state, "processing");
        }

        // A stale Delete token cannot write a pre-send witness or create a
        // Late Delete resolution anchor.
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let profile = create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );
            let descriptor = make_active(&storage, "stale-delete", &profile);
            insert_outbox_fixture(&storage, "stale-delete-memory", "pending", 0, None, None);
            let claim = storage
                .claim_one_active_fenced_vector_sync_with_retry_cutoff(
                    "stale-delete",
                    &descriptor,
                    1536,
                    1,
                    "stale-delete-worker",
                    Some(0),
                )
                .unwrap()
                .unwrap();
            let token = match storage.reserve_fenced_attempt(&claim).unwrap() {
                crate::storage::FencedAttemptReservation::Reserved(token) => token,
                _ => panic!("expected reserved token"),
            };
            let conn = open_authorized_test_connection(&storage.test_database_main_path().unwrap())
                .unwrap();
            conn.execute(
                "UPDATE memory_vector_generation_authority SET active_generation_id=NULL WHERE singleton=1",
                [],
            )
            .unwrap();
            assert_eq!(
                storage.mark_fenced_delete_send_witness(&token).unwrap(),
                crate::storage::FencedDeleteWitnessResult::LostLeaseOrSuperseded
            );
            let witness: (Option<String>, Option<String>) = conn
                .query_row(
                    "SELECT last_send_disposition,delete_witness_at
                     FROM memory_vector_sync_outbox WHERE memory_id='stale-delete-memory'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            let resolutions: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM memory_vector_late_delete_resolution",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(witness, (None, None));
            assert_eq!(resolutions, 0);
        }
    }

    #[test]
    fn d9d3_b_durable_retry_requires_exact_active_generation_and_epoch() {
        fn setup() -> (tempfile::TempDir, StorageService, String, String) {
            let (dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let profile = create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );
            let descriptor = canonical_test_descriptor(&profile, 1536);
            install_active_generation_fixture(
                &storage,
                "retry-g1",
                &descriptor,
                1536,
                &profile,
                D9D2_GENERATION_DESCRIPTOR_VERSION,
                "ready",
            );
            insert_upsert_outbox_fixture(
                &storage,
                "durable-retry",
                "retry_wait",
                1,
                Some("retry-g1"),
                Some(1),
            );
            (dir, storage, profile, descriptor)
        }

        // The one exact current world is eligible.
        {
            let (_dir, storage, _profile, descriptor) = setup();
            assert!(storage
                .claim_one_active_fenced_vector_sync_with_retry_cutoff(
                    "retry-g1",
                    &descriptor,
                    1536,
                    1,
                    "retry-exact",
                    Some(0),
                )
                .unwrap()
                .is_some());
        }

        // Schema-17 forbids an active generation from changing epoch in place;
        // even an attempted active claim at G@E+1 cannot repair or rebind G@E.
        {
            let (_dir, storage, _profile, descriptor) = setup();
            assert!(storage
                .claim_one_active_fenced_vector_sync_with_retry_cutoff(
                    "retry-g1",
                    &descriptor,
                    1536,
                    2,
                    "retry-newer-epoch",
                    Some(0),
                )
                .unwrap()
                .is_none());
        }

        // A different active generation cannot take over G1's durable retry.
        {
            let (_dir, storage, profile, descriptor) = setup();
            let conn = open_authorized_test_connection(&storage.test_database_main_path().unwrap())
                .unwrap();
            conn.execute(
                "UPDATE memory_vector_generation_authority SET active_generation_id=NULL WHERE singleton=1",
                [],
            )
            .unwrap();
            conn.execute(
                "UPDATE memory_vector_generation
                 SET state='retired', authority_epoch=2 WHERE generation_id='retry-g1'",
                [],
            )
            .unwrap();
            install_active_generation_fixture(
                &storage,
                "retry-g2",
                &descriptor,
                1536,
                &profile,
                D9D2_GENERATION_DESCRIPTOR_VERSION,
                "ready",
            );
            assert!(storage
                .claim_one_active_fenced_vector_sync_with_retry_cutoff(
                    "retry-g2",
                    &descriptor,
                    1536,
                    1,
                    "retry-g2",
                    Some(0),
                )
                .unwrap()
                .is_none());
        }

        // A retired old generation is never current, even if its descriptor
        // remains unchanged. `failed` is not a legal successor of `active` in
        // Schema-17, so it cannot be a stale active-retry world.
        for state in ["retired"] {
            let (_dir, storage, _profile, descriptor) = setup();
            let conn = open_authorized_test_connection(&storage.test_database_main_path().unwrap())
                .unwrap();
            conn.execute(
                "UPDATE memory_vector_generation_authority SET active_generation_id=NULL WHERE singleton=1",
                [],
            )
            .unwrap();
            conn.execute(
                "UPDATE memory_vector_generation
                 SET state=?1, authority_epoch=2 WHERE generation_id='retry-g1'",
                [state],
            )
            .unwrap();
            assert!(storage
                .claim_one_active_fenced_vector_sync_with_retry_cutoff(
                    "retry-g1",
                    &descriptor,
                    1536,
                    1,
                    state,
                    Some(0),
                )
                .unwrap()
                .is_none());
        }

        // No active pointer is likewise a non-current authority world.
        {
            let (_dir, storage, _profile, descriptor) = setup();
            let conn = open_authorized_test_connection(&storage.test_database_main_path().unwrap())
                .unwrap();
            conn.execute(
                "UPDATE memory_vector_generation_authority SET active_generation_id=NULL WHERE singleton=1",
                [],
            )
            .unwrap();
            assert!(storage
                .claim_one_active_fenced_vector_sync_with_retry_cutoff(
                    "retry-g1",
                    &descriptor,
                    1536,
                    1,
                    "retry-pointer-moved",
                    Some(0),
                )
                .unwrap()
                .is_none());
            let pair: (Option<String>, Option<i64>) = conn
                .query_row(
                    "SELECT claimed_generation_id,claimed_generation_authority_epoch
                     FROM memory_vector_sync_outbox WHERE memory_id='durable-retry'",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(pair, (Some("retry-g1".into()), Some(1)));
        }
    }

    #[test]
    fn d9d3_b_two_storage_service_authority_race_rejects_reserved_old_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let storage_a =
            StorageService::initialize_with_roots(dir.path().join("data"), None).unwrap();
        let storage_b =
            StorageService::initialize_with_roots(dir.path().join("data"), None).unwrap();
        let secrets = InMemorySecretStore::new();
        let profile = create_test_profile(
            &storage_a,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );
        let descriptor = canonical_test_descriptor(&profile, 1536);
        install_active_generation_fixture(
            &storage_a,
            "race-g1",
            &descriptor,
            1536,
            &profile,
            D9D2_GENERATION_DESCRIPTOR_VERSION,
            "ready",
        );
        insert_upsert_outbox_fixture(&storage_a, "race-memory", "pending", 0, None, None);
        let claim = storage_a
            .claim_one_active_fenced_vector_sync_with_retry_cutoff(
                "race-g1",
                &descriptor,
                1536,
                1,
                "race-a",
                Some(0),
            )
            .unwrap()
            .unwrap();
        let token = match storage_a.reserve_fenced_attempt(&claim).unwrap() {
            crate::storage::FencedAttemptReservation::Reserved(token) => token,
            _ => panic!("expected reserved token"),
        };
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let barrier_b = std::sync::Arc::clone(&barrier);
        let (changed_tx, changed_rx) = std::sync::mpsc::channel();
        let changer = std::thread::spawn(move || {
            barrier_b.wait();
            let conn =
                open_authorized_test_connection(&storage_b.test_database_main_path().unwrap())
                    .unwrap();
            conn.execute(
                "UPDATE memory_vector_generation_authority SET active_generation_id=NULL WHERE singleton=1",
                [],
            )
            .unwrap();
            changed_tx.send(()).unwrap();
        });
        barrier.wait();
        changed_rx.recv().unwrap();
        changer.join().unwrap();
        assert_eq!(
            storage_a.finalize_fenced_vector_sync(&token).unwrap(),
            crate::storage::FencedFinalizeResult::LostLeaseOrSuperseded
        );
        let conn =
            open_authorized_test_connection(&storage_a.test_database_main_path().unwrap()).unwrap();
        let final_state: (String, i64, Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT state,attempt_count,claimed_generation_id,claimed_generation_authority_epoch
                 FROM memory_vector_sync_outbox WHERE memory_id='race-memory'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            final_state,
            ("processing".into(), 1, Some("race-g1".into()), Some(1))
        );
    }

    #[test]
    fn d9d2_existing_generation_binding_second_building_is_rejected_by_lifecycle_guard() {
        let (_dir, storage) = test_storage();

        insert_generation_fixture(
            &storage,
            "generation-1",
            &"a".repeat(64),
            1536,
            "building",
            1,
        );
        assert_second_building_fixture_rejected(&storage, "generation-2", &"b".repeat(64), 1536);
    }

    #[test]
    fn d9d2_existing_generation_binding_ineligible_states_return_no_existing_generation() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );

        // Active only, retired only, failed only
        insert_generation_fixture(&storage, "gen-active", &"a".repeat(64), 1536, "active", 1);
        insert_generation_fixture(&storage, "gen-retired", &"b".repeat(64), 1536, "retired", 1);
        insert_generation_fixture(&storage, "gen-failed", &"c".repeat(64), 1536, "failed", 1);

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
        let registry = LanceDbVectorStoreRegistry::default();

        let res = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
            &storage, &runtime, &registry,
        ));
        let err = match res {
            Err(e) => e,
            Ok(_) => panic!("expected NoExistingGeneration error"),
        };
        assert_eq!(
            err.code(),
            ExistingGenerationBindingErrorCode::NoExistingGeneration
        );
    }

    #[test]
    fn d9d2_existing_generation_binding_invalid_metadata_rejected() {
        // Case 1: Invalid generation ID
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );
            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let registry = LanceDbVectorStoreRegistry::default();

            insert_generation_fixture(&storage, "invalid/id", &"a".repeat(64), 1536, "building", 1);
            let err = match tauri::async_runtime::block_on(
                resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
            ) {
                Err(e) => e,
                Ok(_) => panic!("expected error"),
            };
            assert_eq!(
                err.code(),
                ExistingGenerationBindingErrorCode::InvalidGenerationMetadata
            );
        }

        // Case 2: Descriptor not 64 chars
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );
            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let registry = LanceDbVectorStoreRegistry::default();

            insert_generation_fixture(&storage, "gen-1", &"a".repeat(63), 1536, "building", 1);
            let err = match tauri::async_runtime::block_on(
                resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
            ) {
                Err(e) => e,
                Ok(_) => panic!("expected error"),
            };
            assert_eq!(
                err.code(),
                ExistingGenerationBindingErrorCode::InvalidGenerationMetadata
            );
        }

        // Case 3: Descriptor uppercase
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );
            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let registry = LanceDbVectorStoreRegistry::default();

            insert_generation_fixture(
                &storage,
                "gen-1",
                &format!("{}A", "a".repeat(63)),
                1536,
                "building",
                1,
            );
            let err = match tauri::async_runtime::block_on(
                resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
            ) {
                Err(e) => e,
                Ok(_) => panic!("expected error"),
            };
            assert_eq!(
                err.code(),
                ExistingGenerationBindingErrorCode::InvalidGenerationMetadata
            );
        }

        // Case 4: Invalid dimension (> 65536)
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );
            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let registry = LanceDbVectorStoreRegistry::default();

            insert_generation_fixture(
                &storage,
                "gen-1",
                &"a".repeat(64),
                MAX_VECTOR_DIMENSION + 1,
                "building",
                1,
            );
            let err = match tauri::async_runtime::block_on(
                resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
            ) {
                Err(e) => e,
                Ok(_) => panic!("expected error"),
            };
            assert_eq!(
                err.code(),
                ExistingGenerationBindingErrorCode::InvalidGenerationMetadata
            );
        }
    }

    #[test]
    fn d9d2_existing_generation_binding_invalid_authority_epoch_stops_before_provider_or_store() {
        for authority_epoch in [0_i64, -1_i64] {
            let (_dir, storage) = test_storage();
            let (secrets, provider_resolution_count) = TrackingSecretStore::new();
            create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );
            let registry = LanceDbVectorStoreRegistry::default();
            let data_root = storage.active_data_root().unwrap();
            let expected_store_root = data_root
                .join("vectors")
                .join("generations")
                .join("invalid-authority-epoch")
                .join("lancedb");
            assert!(
                !expected_store_root.exists(),
                "the fixture starts without an existing generation store"
            );

            let conn = open_authorized_test_connection(&storage.test_database_main_path().unwrap())
                .unwrap();
            conn.execute_batch("PRAGMA ignore_check_constraints = ON;")
                .unwrap();
            conn.execute(
                "INSERT INTO memory_vector_generation (generation_id, descriptor_hash, dimension, state, authority_epoch)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    "invalid-authority-epoch",
                    "a".repeat(64),
                    1536_i64,
                    "building",
                    authority_epoch
                ],
            )
            .unwrap();
            conn.execute_batch("PRAGMA ignore_check_constraints = OFF;")
                .unwrap();

            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let err = match tauri::async_runtime::block_on(
                resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
            ) {
                Err(error) => error,
                Ok(_) => panic!("authority epoch corruption must fail closed"),
            };

            assert_eq!(
                err.code(),
                ExistingGenerationBindingErrorCode::InvalidGenerationMetadata
            );
            assert_eq!(
                provider_resolution_count.load(Ordering::SeqCst),
                0,
                "invalid authority epoch must stop before provider resolution"
            );
            assert!(
                !expected_store_root.exists(),
                "invalid authority epoch must stop before existing-store resolution"
            );
        }
    }

    #[test]
    fn d9d2_existing_generation_binding_provider_mismatch_matrix() {
        // Case 1: Descriptor mismatch in authority row
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let _profile_id = create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );

            insert_generation_fixture(
                &storage,
                "generation-1",
                &"0".repeat(64),
                1536,
                "building",
                1,
            );

            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let registry = LanceDbVectorStoreRegistry::default();

            let err = match tauri::async_runtime::block_on(
                resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
            ) {
                Err(e) => e,
                Ok(_) => panic!("expected error"),
            };
            assert_eq!(
                err.code(),
                ExistingGenerationBindingErrorCode::GenerationBindingMismatch
            );
        }

        // Case 2: Dimension mismatch between profile and authority
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let profile_id = create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );

            let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
            let canonical_desc = compute_canonical_generation_descriptor(
                &ModelProviderKind::OpenaiCompatible,
                &profile_id,
                &target,
                "text-embedding-3-small",
                1536,
            )
            .unwrap();

            insert_generation_fixture(
                &storage,
                "generation-1",
                &canonical_desc,
                768,
                "building",
                1,
            );

            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let registry = LanceDbVectorStoreRegistry::default();

            let err = match tauri::async_runtime::block_on(
                resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
            ) {
                Err(e) => e,
                Ok(_) => panic!("expected error"),
            };
            assert_eq!(
                err.code(),
                ExistingGenerationBindingErrorCode::GenerationBindingMismatch
            );
        }
    }

    #[test]
    fn d9d2_existing_generation_binding_no_active_profile_returns_provider_unavailable() {
        let (_dir, storage) = test_storage();
        insert_generation_fixture(
            &storage,
            "generation-1",
            &"a".repeat(64),
            1536,
            "building",
            1,
        );

        let secrets = InMemorySecretStore::new();
        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
        let registry = LanceDbVectorStoreRegistry::default();

        let err = match tauri::async_runtime::block_on(
            resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
        ) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            err.code(),
            ExistingGenerationBindingErrorCode::GenerationProviderUnavailable
        );
    }

    #[test]
    fn d9d2_existing_generation_binding_profile_rotation_does_not_silently_rebind() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let profile_id = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );

        let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
        let canonical_desc = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            &profile_id,
            &target,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();

        insert_generation_fixture(
            &storage,
            "generation-1",
            &canonical_desc,
            1536,
            "building",
            1,
        );

        let registry = LanceDbVectorStoreRegistry::default();
        let _pre_created = tauri::async_runtime::block_on(setup_pre_existing_lance_store(
            &storage,
            &registry,
            "generation-1",
        ));

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

        // Valid initially
        assert!(
            tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
                &storage, &runtime, &registry
            ))
            .is_ok()
        );

        // Rotate active profile to new profile with different model name
        let _new_id = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-large",
            1536,
        );

        // Resolving again must fail closed with GenerationBindingMismatch
        let err = match tauri::async_runtime::block_on(
            resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
        ) {
            Err(e) => e,
            Ok(_) => panic!("expected error"),
        };
        assert_eq!(
            err.code(),
            ExistingGenerationBindingErrorCode::GenerationBindingMismatch
        );
    }

    #[test]
    fn d9d2_existing_generation_binding_deterministic_concurrent_stale_barrier() {
        // Scenario 1: Epoch advancement concurrently detected via deterministic channel synchronization
        {
            let temp_dir = tempfile::tempdir().unwrap();
            let storage_a =
                StorageService::initialize_with_roots(temp_dir.path().join("data"), None).unwrap();
            let storage_b =
                StorageService::initialize_with_roots(temp_dir.path().join("data"), None).unwrap();
            let secrets = InMemorySecretStore::new();

            let profile_id = create_test_profile(
                &storage_a,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );

            let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
            let canonical_desc = compute_canonical_generation_descriptor(
                &ModelProviderKind::OpenaiCompatible,
                &profile_id,
                &target,
                "text-embedding-3-small",
                1536,
            )
            .unwrap();

            insert_generation_fixture(
                &storage_a,
                "generation-1",
                &canonical_desc,
                1536,
                "building",
                1,
            );

            let (tx_a_to_b, rx_b_from_a) = mpsc::sync_channel::<()>(0);
            let (tx_b_to_a, rx_a_from_b) = mpsc::sync_channel::<()>(0);

            let handle_b = std::thread::spawn(move || {
                // Wait for Thread A to load candidate authority
                rx_b_from_a.recv().unwrap();

                // Mutate epoch in independent connection B and commit
                let conn_b =
                    open_authorized_test_connection(&storage_b.test_database_main_path().unwrap())
                        .unwrap();
                conn_b
                    .execute(
                        "UPDATE memory_vector_generation SET state='active', authority_epoch=2 WHERE generation_id='generation-1' AND authority_epoch=1",
                        [],
                    )
                    .unwrap();

                // Signal Thread A to resume recheck
                tx_b_to_a.send(()).unwrap();
            });

            // Thread A: Loads candidate authority
            let authority = storage_a
                .load_existing_building_generation_candidate()
                .unwrap();
            assert!(authority
                .verify_descriptor_and_dimension(&canonical_desc, 1536)
                .is_ok());

            // Signal Thread B to mutate authority
            tx_a_to_b.send(()).unwrap();

            // Wait for Thread B to complete mutation
            rx_a_from_b.recv().unwrap();
            handle_b.join().unwrap();

            // Thread A: Exact recheck must detect stale epoch and fail closed
            let err = match authority.verify_current_and_seal(&storage_a) {
                Err(e) => e,
                Ok(_) => panic!("expected stale error"),
            };
            assert_eq!(
                err.code(),
                ExistingGenerationBindingErrorCode::GenerationBindingStale
            );
        }

        // Scenario 2: State transition to retired concurrently detected
        {
            let temp_dir = tempfile::tempdir().unwrap();
            let storage_a =
                StorageService::initialize_with_roots(temp_dir.path().join("data"), None).unwrap();
            let storage_b =
                StorageService::initialize_with_roots(temp_dir.path().join("data"), None).unwrap();
            let secrets = InMemorySecretStore::new();

            let profile_id = create_test_profile(
                &storage_a,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );

            let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
            let canonical_desc = compute_canonical_generation_descriptor(
                &ModelProviderKind::OpenaiCompatible,
                &profile_id,
                &target,
                "text-embedding-3-small",
                1536,
            )
            .unwrap();

            insert_generation_fixture(
                &storage_a,
                "generation-1",
                &canonical_desc,
                1536,
                "building",
                1,
            );

            let authority = storage_a
                .load_existing_building_generation_candidate()
                .unwrap();

            let conn_b =
                open_authorized_test_connection(&storage_b.test_database_main_path().unwrap())
                    .unwrap();
            conn_b
                .execute(
                    "UPDATE memory_vector_generation
                     SET state='active', authority_epoch=2
                     WHERE generation_id='generation-1' AND state='building' AND authority_epoch=1",
                    [],
                )
                .unwrap();
            conn_b
                .execute(
                    "UPDATE memory_vector_generation
                     SET state='retired', authority_epoch=3
                     WHERE generation_id='generation-1' AND state='active' AND authority_epoch=2",
                    [],
                )
                .unwrap();

            let err = match authority.verify_current_and_seal(&storage_a) {
                Err(e) => e,
                Ok(_) => panic!("expected stale error on retirement"),
            };
            assert_eq!(
                err.code(),
                ExistingGenerationBindingErrorCode::GenerationBindingStale
            );
        }
    }

    #[test]
    fn d9d2_existing_generation_binding_read_only_matrix_zero_mutations() {
        // Subcase 1: Successful resolution -> same-connection zero SQLite mutations
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let profile_id = create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );

            let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
            let canonical_desc = compute_canonical_generation_descriptor(
                &ModelProviderKind::OpenaiCompatible,
                &profile_id,
                &target,
                "text-embedding-3-small",
                1536,
            )
            .unwrap();

            insert_generation_fixture(
                &storage,
                "generation-1",
                &canonical_desc,
                1536,
                "building",
                1,
            );

            let registry = LanceDbVectorStoreRegistry::default();
            let _pre_created = tauri::async_runtime::block_on(setup_pre_existing_lance_store(
                &storage,
                &registry,
                "generation-1",
            ));

            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

            let token = storage
                .begin_existing_generation_binding_read_observation_for_test()
                .unwrap();

            let res = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
                &storage, &runtime, &registry,
            ));
            assert!(res.is_ok());

            let obs = storage
                .finish_existing_generation_binding_read_observation_for_test(token)
                .unwrap();
            assert_eq!(
                obs,
                ExistingGenerationBindingObservationResult::Unchanged,
                "Read bridge resolution must perform zero SQLite mutations on same connection"
            );
        }

        // Subcase 2: Zero building candidate -> same-connection zero SQLite mutations
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );

            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let registry = LanceDbVectorStoreRegistry::default();

            let token = storage
                .begin_existing_generation_binding_read_observation_for_test()
                .unwrap();

            let _ = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
                &storage, &runtime, &registry,
            ));

            let obs = storage
                .finish_existing_generation_binding_read_observation_for_test(token)
                .unwrap();
            assert_eq!(obs, ExistingGenerationBindingObservationResult::Unchanged);
        }

        // Subcase 3: Schema 17 rejects a second building candidate; the
        // surviving read bridge still performs zero SQLite mutations.
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );

            insert_generation_fixture(
                &storage,
                "generation-1",
                &"a".repeat(64),
                1536,
                "building",
                1,
            );
            assert_second_building_fixture_rejected(
                &storage,
                "generation-2",
                &"b".repeat(64),
                1536,
            );

            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let registry = LanceDbVectorStoreRegistry::default();

            let token = storage
                .begin_existing_generation_binding_read_observation_for_test()
                .unwrap();

            let _ = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
                &storage, &runtime, &registry,
            ));

            let obs = storage
                .finish_existing_generation_binding_read_observation_for_test(token)
                .unwrap();
            assert_eq!(obs, ExistingGenerationBindingObservationResult::Unchanged);
        }

        // Subcase 4: Binding mismatch -> same-connection zero SQLite mutations
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );

            insert_generation_fixture(
                &storage,
                "generation-1",
                &"0".repeat(64),
                1536,
                "building",
                1,
            );

            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let registry = LanceDbVectorStoreRegistry::default();

            let token = storage
                .begin_existing_generation_binding_read_observation_for_test()
                .unwrap();

            let _ = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
                &storage, &runtime, &registry,
            ));

            let obs = storage
                .finish_existing_generation_binding_read_observation_for_test(token)
                .unwrap();
            assert_eq!(obs, ExistingGenerationBindingObservationResult::Unchanged);
        }

        // Subcase 5: Stale epoch -> same-connection zero SQLite mutations
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let profile_id = create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );

            let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
            let canonical_desc = compute_canonical_generation_descriptor(
                &ModelProviderKind::OpenaiCompatible,
                &profile_id,
                &target,
                "text-embedding-3-small",
                1536,
            )
            .unwrap();

            insert_generation_fixture(
                &storage,
                "generation-1",
                &canonical_desc,
                1536,
                "building",
                1,
            );

            let authority = storage
                .load_existing_building_generation_candidate()
                .unwrap();

            // Direct mutation on raw connection to advance epoch with valid state
            let conn = open_authorized_test_connection(&storage.test_database_main_path().unwrap())
                .unwrap();
            conn.execute(
                "UPDATE memory_vector_generation SET state='active', authority_epoch=2 WHERE generation_id='generation-1' AND authority_epoch=1",
                [],
            )
            .unwrap();

            let token = storage
                .begin_existing_generation_binding_read_observation_for_test()
                .unwrap();

            let _ = authority.verify_current_and_seal(&storage);

            let obs = storage
                .finish_existing_generation_binding_read_observation_for_test(token)
                .unwrap();
            assert_eq!(obs, ExistingGenerationBindingObservationResult::Unchanged);
        }

        // Subcase 6: Existing store missing -> same-connection zero SQLite mutations
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let profile_id = create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );

            let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
            let canonical_desc = compute_canonical_generation_descriptor(
                &ModelProviderKind::OpenaiCompatible,
                &profile_id,
                &target,
                "text-embedding-3-small",
                1536,
            )
            .unwrap();

            insert_generation_fixture(
                &storage,
                "generation-missing",
                &canonical_desc,
                1536,
                "building",
                1,
            );

            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let registry = LanceDbVectorStoreRegistry::default();

            let token = storage
                .begin_existing_generation_binding_read_observation_for_test()
                .unwrap();

            let res = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
                &storage, &runtime, &registry,
            ));
            assert!(res.is_err());

            let obs = storage
                .finish_existing_generation_binding_read_observation_for_test(token)
                .unwrap();
            assert_eq!(obs, ExistingGenerationBindingObservationResult::Unchanged);
        }
    }

    #[test]
    fn d9d2_existing_generation_binding_owned_execution_drop_behavior() {
        // Case 1: Execution created then dropped without drain -> store Arc dropped
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let profile_id = create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );

            let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
            let canonical_desc = compute_canonical_generation_descriptor(
                &ModelProviderKind::OpenaiCompatible,
                &profile_id,
                &target,
                "text-embedding-3-small",
                1536,
            )
            .unwrap();

            insert_generation_fixture(
                &storage,
                "generation-drop-1",
                &canonical_desc,
                1536,
                "building",
                1,
            );

            let registry = LanceDbVectorStoreRegistry::default();
            let store = tauri::async_runtime::block_on(setup_pre_existing_lance_store(
                &storage,
                &registry,
                "generation-drop-1",
            ));

            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

            let execution = tauri::async_runtime::block_on(
                resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
            )
            .unwrap();

            // Count is 3: store local variable + registry cached store + execution.store
            assert_eq!(Arc::strong_count(&store), 3);
            drop(execution);
            // Count drops to 2: store local variable + registry cached store
            assert_eq!(
                Arc::strong_count(&store),
                2,
                "Execution must decrement store reference count on drop"
            );
        }

        // Case 2: Empty drain -> execution consumed and store Arc dropped
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let profile_id = create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );

            let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
            let canonical_desc = compute_canonical_generation_descriptor(
                &ModelProviderKind::OpenaiCompatible,
                &profile_id,
                &target,
                "text-embedding-3-small",
                1536,
            )
            .unwrap();

            insert_generation_fixture(
                &storage,
                "generation-drop-2",
                &canonical_desc,
                1536,
                "building",
                1,
            );

            let registry = LanceDbVectorStoreRegistry::default();
            let store = tauri::async_runtime::block_on(setup_pre_existing_lance_store(
                &storage,
                &registry,
                "generation-drop-2",
            ));

            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

            let execution = tauri::async_runtime::block_on(
                resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
            )
            .unwrap();

            assert_eq!(Arc::strong_count(&store), 3);

            let report =
                tauri::async_runtime::block_on(execution.drain_bounded("test-worker-drop", 32))
                    .unwrap();
            assert_eq!(report.processed, 0);
            assert_eq!(
                Arc::strong_count(&store),
                2,
                "Execution must decrement store reference count after drain execution"
            );
        }

        // Case 3: Drain returns error -> execution consumed and store Arc dropped
        {
            let (_dir, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let profile_id = create_test_profile(
                &storage,
                &secrets,
                "https://api.openai.com/v1",
                "text-embedding-3-small",
                1536,
            );

            let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
            let canonical_desc = compute_canonical_generation_descriptor(
                &ModelProviderKind::OpenaiCompatible,
                &profile_id,
                &target,
                "text-embedding-3-small",
                1536,
            )
            .unwrap();

            insert_generation_fixture(
                &storage,
                "generation-drop-3",
                &canonical_desc,
                1536,
                "building",
                1,
            );

            let registry = LanceDbVectorStoreRegistry::default();
            let store = tauri::async_runtime::block_on(setup_pre_existing_lance_store(
                &storage,
                &registry,
                "generation-drop-3",
            ));

            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

            let execution = tauri::async_runtime::block_on(
                resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
            )
            .unwrap();

            assert_eq!(Arc::strong_count(&store), 3);

            // Limit 0 is invalid and returns error
            let err =
                tauri::async_runtime::block_on(execution.drain_bounded("test-worker-drop", 0));
            assert!(err.is_err());
            assert_eq!(
                Arc::strong_count(&store),
                2,
                "Execution must decrement store reference count when drain returns error"
            );
        }
    }

    #[test]
    fn d9d2_existing_generation_binding_matching_store_resolution_success() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let profile_id = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );

        let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
        let canonical_desc = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            &profile_id,
            &target,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();

        insert_generation_fixture(
            &storage,
            "generation-match-1",
            &canonical_desc,
            1536,
            "building",
            1,
        );

        let registry = LanceDbVectorStoreRegistry::default();
        let _pre_created = tauri::async_runtime::block_on(setup_pre_existing_lance_store(
            &storage,
            &registry,
            "generation-match-1",
        ));

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

        let execution = tauri::async_runtime::block_on(
            resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
        )
        .unwrap();

        let report =
            tauri::async_runtime::block_on(execution.drain_bounded("test-worker-match", 10))
                .unwrap();

        assert_eq!(report.requested_limit, 10);
        assert_eq!(report.processed, 0);
        assert!(report.stopped_no_eligible);
    }

    #[test]
    fn d9d2_existing_generation_binding_missing_directory_fails_closed_no_create() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let profile_id = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );

        let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
        let canonical_desc = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            &profile_id,
            &target,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();

        insert_generation_fixture(
            &storage,
            "gen-uncreated",
            &canonical_desc,
            1536,
            "building",
            1,
        );

        let data_root = storage.active_data_root().unwrap();
        let gen_dir = data_root
            .join("vectors")
            .join("generations")
            .join("gen-uncreated");
        assert!(
            !gen_dir.exists(),
            "Generation directory must not exist before test"
        );

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
        let registry = LanceDbVectorStoreRegistry::default();

        let res = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
            &storage, &runtime, &registry,
        ));

        let err = match res {
            Err(e) => e,
            Ok(_) => panic!("expected existing_vector_store_unavailable error"),
        };
        assert_eq!(
            err.code(),
            ExistingGenerationBindingErrorCode::ExistingVectorStoreUnavailable
        );

        assert!(
            !gen_dir.exists(),
            "Resolver must fail closed without creating missing generation directory"
        );
    }

    #[test]
    fn d9d2_existing_generation_binding_invalid_store_path_fails_closed() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let profile_id = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );

        let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
        let canonical_desc = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            &profile_id,
            &target,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();

        insert_generation_fixture(
            &storage,
            "gen-file-path",
            &canonical_desc,
            1536,
            "building",
            1,
        );

        // Create a regular file at the generation directory path instead of a directory
        let data_root = storage.active_data_root().unwrap();
        let gen_parent = data_root.join("vectors").join("generations");
        std::fs::create_dir_all(&gen_parent).unwrap();
        std::fs::write(gen_parent.join("gen-file-path"), b"not a directory").unwrap();

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
        let registry = LanceDbVectorStoreRegistry::default();

        let res = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
            &storage, &runtime, &registry,
        ));

        let err = match res {
            Err(e) => e,
            Ok(_) => panic!("expected existing_vector_store_unavailable error"),
        };
        assert_eq!(
            err.code(),
            ExistingGenerationBindingErrorCode::ExistingVectorStoreUnavailable
        );
    }

    #[test]
    fn d9d2_existing_generation_binding_bounded_drain_limits() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let profile_id = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );

        let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
        let canonical_desc = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            &profile_id,
            &target,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();

        insert_generation_fixture(
            &storage,
            "generation-limits",
            &canonical_desc,
            1536,
            "building",
            1,
        );

        let registry = LanceDbVectorStoreRegistry::default();
        let _pre_created = tauri::async_runtime::block_on(setup_pre_existing_lance_store(
            &storage,
            &registry,
            "generation-limits",
        ));

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

        // Limit = 1 (using same worker owner so lease is renewed cleanly)
        let exec1 = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
            &storage, &runtime, &registry,
        ))
        .unwrap();
        let rep1 =
            tauri::async_runtime::block_on(exec1.drain_bounded("test-worker-limits", 1)).unwrap();
        assert_eq!(rep1.requested_limit, 1);

        // Limit = 3
        let exec3 = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
            &storage, &runtime, &registry,
        ))
        .unwrap();
        let rep3 =
            tauri::async_runtime::block_on(exec3.drain_bounded("test-worker-limits", 3)).unwrap();
        assert_eq!(rep3.requested_limit, 3);

        // Limit = 32
        let exec32 = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
            &storage, &runtime, &registry,
        ))
        .unwrap();
        let rep32 =
            tauri::async_runtime::block_on(exec32.drain_bounded("test-worker-limits", 32)).unwrap();
        assert_eq!(rep32.requested_limit, 32);

        // Limit = 0 (invalid)
        let exec0 = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
            &storage, &runtime, &registry,
        ))
        .unwrap();
        assert!(
            tauri::async_runtime::block_on(exec0.drain_bounded("test-worker-limits", 0)).is_err()
        );

        // Limit = 33 (invalid)
        let exec33 = tauri::async_runtime::block_on(resolve_existing_generation_fenced_execution(
            &storage, &runtime, &registry,
        ))
        .unwrap();
        assert!(
            tauri::async_runtime::block_on(exec33.drain_bounded("test-worker-limits", 33)).is_err()
        );
    }

    #[test]
    fn d9d2_existing_generation_binding_retry_g1_current_g2_stability() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let profile_id = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );

        let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
        let canonical_desc = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            &profile_id,
            &target,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();

        // Current building generation in SQLite is G2
        insert_generation_fixture(
            &storage,
            "generation-2",
            &canonical_desc,
            1536,
            "building",
            1,
        );

        // Insert retry outbox row previously claimed by G1 (migration_disposition is NULL)
        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        conn.execute(
            "INSERT INTO memory_vector_sync_outbox (
                life_id, memory_id, desired_action, state, attempt_count,
                claimed_generation_id, mutation_sequence, target_revision,
                target_content_hash, migration_disposition, created_at, updated_at
            ) VALUES (
                'life-1', 'mem-1', 'upsert', 'retry_wait', 1,
                'generation-1', 1, 1,
                'hash-1', NULL, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z'
            )",
            [],
        )
        .unwrap();

        let registry = LanceDbVectorStoreRegistry::default();
        let _pre_created = tauri::async_runtime::block_on(setup_pre_existing_lance_store(
            &storage,
            &registry,
            "generation-2",
        ));

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

        let execution = tauri::async_runtime::block_on(
            resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
        )
        .unwrap();

        let report =
            tauri::async_runtime::block_on(execution.drain_bounded("test-worker-retry", 32))
                .unwrap();

        // G1 retry row must not be processed or claimed by G2 execution
        assert_eq!(report.processed, 0);
        assert!(report.stopped_no_eligible);

        // Verify outbox row remains unchanged
        let (claimed_gen, attempt_cnt, st): (Option<String>, i64, String) = conn
            .query_row(
                "SELECT claimed_generation_id, attempt_count, state FROM memory_vector_sync_outbox WHERE memory_id='mem-1'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(claimed_gen.as_deref(), Some("generation-1"));
        assert_eq!(attempt_cnt, 1);
        assert_eq!(st, "retry_wait");
    }

    #[test]
    fn d9d2_existing_generation_binding_credential_timing_no_preflight() {
        let (_dir, storage) = test_storage();
        let (secrets, read_counter) = TrackingSecretStore::new();

        // Setup profile with credential in tracking store
        let created = ModelProfileService::new(&storage)
            .create(CreateModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "Test Embedding Profile".into(),
                base_url: "https://api.openai.com/v1".into(),
                model_name: "text-embedding-3-small".into(),
                temperature: None,
                max_tokens: None,
                embedding_dimension: Some(1536),
            })
            .unwrap();
        ModelProfileService::new(&storage)
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                profile_id: created.id.clone(),
            })
            .unwrap();
        secrets
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, &created.id).unwrap(),
                SecretValue::new("tracking-api-key".into()).unwrap(),
            )
            .unwrap();

        let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
        let canonical_desc = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            &created.id,
            &target,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();

        insert_generation_fixture(
            &storage,
            "generation-cred",
            &canonical_desc,
            1536,
            "building",
            1,
        );

        let registry = LanceDbVectorStoreRegistry::default();
        let _pre_created = tauri::async_runtime::block_on(setup_pre_existing_lance_store(
            &storage,
            &registry,
            "generation-cred",
        ));

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

        // 1. Resolution: Credential reads MUST be 0
        let execution = tauri::async_runtime::block_on(
            resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
        )
        .unwrap();

        assert_eq!(
            read_counter.load(Ordering::SeqCst),
            0,
            "Execution construction must not read credentials"
        );

        // 2. Empty drain: Credential reads MUST be 0
        let report =
            tauri::async_runtime::block_on(execution.drain_bounded("test-worker-cred", 32))
                .unwrap();

        assert_eq!(report.processed, 0);
        assert_eq!(
            read_counter.load(Ordering::SeqCst),
            0,
            "Empty drain must not read credentials"
        );
    }

    #[test]
    fn d9d2_existing_generation_binding_live_dry_run_composition() {
        let (_dir, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let profile_id = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-small",
            1536,
        );

        let target = validate_and_normalize_url("https://api.openai.com/v1").unwrap();
        let canonical_desc = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            &profile_id,
            &target,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();

        insert_generation_fixture(
            &storage,
            "generation-dry-run",
            &canonical_desc,
            1536,
            "building",
            1,
        );

        let registry = LanceDbVectorStoreRegistry::default();
        let _pre_created = tauri::async_runtime::block_on(setup_pre_existing_lance_store(
            &storage,
            &registry,
            "generation-dry-run",
        ));

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

        // Measure same-connection SQLite mutations
        let token = storage
            .begin_existing_generation_binding_read_observation_for_test()
            .unwrap();

        // 1. Dry run resolution
        let execution = tauri::async_runtime::block_on(
            resolve_existing_generation_fenced_execution(&storage, &runtime, &registry),
        )
        .unwrap();

        let obs = storage
            .finish_existing_generation_binding_read_observation_for_test(token)
            .unwrap();
        assert_eq!(
            obs,
            ExistingGenerationBindingObservationResult::Unchanged,
            "Dry run resolution must not mutate SQLite"
        );

        // 2. Dry run drain
        let report =
            tauri::async_runtime::block_on(execution.drain_bounded("dry-run-worker", 32)).unwrap();

        assert_eq!(report.processed, 0);
        assert!(report.stopped_no_eligible);
    }
}
