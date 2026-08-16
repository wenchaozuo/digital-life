//! D-9D2 Existing Generation Binding Read Bridge.
//!
//! Provides a sealed, read-only, non-IPC bridge from authoritative SQLite
//! generation metadata and active embedding provider configuration to a sealed
//! [`ExistingVectorGenerationBinding`].
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
//! - Consumption is strictly atomic and consuming via `consume_for_fenced_execution`.
//! - Absolutely NO generation creation, registration, activation, switching, retirement, or mutation.

use sha2::{Digest, Sha256};
use std::fmt::Write as _;

use crate::{
    embedding::{EmbeddingProvider, MAX_VECTOR_DIMENSION, PROTOCOL_VERSION},
    memory::vector_index::MEMORY_INDEX_FORMAT_VERSION,
    model::{
        profile::{ModelProfileRepository, ModelProviderKind},
        runtime::{
            ModelRuntimeErrorCode, ModelRuntimePurpose, ModelRuntimeService,
            ResolvedEmbeddingProvider, ResolvedModelProfile,
        },
        transport::url_policy::{
            validate_and_normalize_url, TransportTargetKind, ValidatedTransportTarget,
        },
    },
    secrets::SecretStore,
    storage::{ExistingBuildingGenerationAuthority, StorageService},
    vector_store::VectorGenerationContext,
};

/// Fixed redacted error codes for D-9D2 generation binding read bridge.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExistingGenerationBindingErrorCode {
    NoExistingGeneration,
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

#[allow(dead_code)]
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

/// Sealed binding combining authoritative generation context and active embedding provider.
///
/// Deliberately has NO `Clone`, NO `Copy`, NO `Debug`, NO `Serialize`, NO `Deserialize`,
/// NO IPC exposure, NO raw scalar getters, and NO split getters.
pub(crate) struct ExistingVectorGenerationBinding<'a> {
    context: VectorGenerationContext,
    provider: ResolvedEmbeddingProvider<'a>,
}

impl<'a> ExistingVectorGenerationBinding<'a> {
    /// Controlled atomic consumer for `ExistingVectorGenerationBinding`.
    ///
    /// Consumes `self` by value as an opaque bundle, ensuring callers cannot
    /// extract, clone, or decouple `VectorGenerationContext` and `dyn EmbeddingProvider`.
    #[allow(dead_code)]
    pub(crate) fn consume_for_fenced_execution<F, R>(self, consumer: F) -> R
    where
        F: FnOnce(&VectorGenerationContext, &dyn EmbeddingProvider) -> R,
    {
        consumer(&self.context, self.provider.provider())
    }
}

/// Pure raw calculation of the generation descriptor digest according to `D9D2_GENERATION_DESCRIPTOR_V1`.
#[allow(dead_code)]
pub(crate) fn compute_canonical_generation_descriptor_raw(
    domain_separator: &str,
    memory_index_format_version: &str,
    protocol_version: &str,
    embedding_kind: &str,
    document_kind: &str,
    provider_kind_wire: &str,
    profile_id: &str,
    transport_target_kind: &str,
    host_ascii: &str,
    effective_port: u16,
    base_path_segments: &[&str],
    endpoint_kind: &str,
    trimmed_model_name: &str,
    dimension: usize,
) -> String {
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
#[allow(dead_code)]
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
        "digital-life-vector-generation-descriptor-v1",
        MEMORY_INDEX_FORMAT_VERSION,
        PROTOCOL_VERSION,
        "embedding",
        "document",
        provider_kind.as_str(),
        profile_id,
        target_kind_str,
        transport_target.host_ascii(),
        transport_target.port(),
        &segments,
        "embeddings",
        model_name.trim(),
        dimension,
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

/// Resolves the existing vector generation binding from SQLite generation authority and active model runtime.
#[allow(dead_code)]
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

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
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
        secrets::{InMemorySecretStore, SecretIdentifier, SecretPurpose, SecretValue},
        storage::open_authorized_test_connection,
    };

    fn test_storage() -> (TempDir, StorageService) {
        let temp_dir = tempfile::tempdir().unwrap();
        let service =
            StorageService::initialize_with_roots(temp_dir.path().join("data"), None).unwrap();
        (temp_dir, service)
    }

    fn store_credential(secrets: &InMemorySecretStore, profile_id: &str) {
        secrets
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, profile_id).unwrap(),
                SecretValue::new("fake-api-key".into()).unwrap(),
            )
            .unwrap();
    }

    fn create_test_profile(
        storage: &StorageService,
        secrets: &InMemorySecretStore,
        base_url: &str,
        model_name: &str,
        dimension: u32,
    ) -> String {
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
        let base_digest = compute_canonical_generation_descriptor_raw(
            "digital-life-vector-generation-descriptor-v1",
            "memory-index-v1",
            "openai-compatible-embedding-v1",
            "embedding",
            "document",
            "openai_compatible",
            "profile-openai",
            "remote_https",
            "api.openai.com",
            443,
            &["v1"],
            "embeddings",
            "text-embedding-3-small",
            1536,
        );

        assert_eq!(
            base_digest,
            "b9b5e4d839faa4a74a0c2b302ecddeb8a474f416909c704327029f948c3d91b6"
        );

        // Matrix covering every individual field and constant
        let variations = vec![
            (
                "domain_separator",
                compute_canonical_generation_descriptor_raw(
                    "other-domain-separator",
                    "memory-index-v1",
                    "openai-compatible-embedding-v1",
                    "embedding",
                    "document",
                    "openai_compatible",
                    "profile-openai",
                    "remote_https",
                    "api.openai.com",
                    443,
                    &["v1"],
                    "embeddings",
                    "text-embedding-3-small",
                    1536,
                ),
            ),
            (
                "memory_index_format_version",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v2",
                    "openai-compatible-embedding-v1",
                    "embedding",
                    "document",
                    "openai_compatible",
                    "profile-openai",
                    "remote_https",
                    "api.openai.com",
                    443,
                    &["v1"],
                    "embeddings",
                    "text-embedding-3-small",
                    1536,
                ),
            ),
            (
                "protocol_version",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v1",
                    "openai-compatible-embedding-v2",
                    "embedding",
                    "document",
                    "openai_compatible",
                    "profile-openai",
                    "remote_https",
                    "api.openai.com",
                    443,
                    &["v1"],
                    "embeddings",
                    "text-embedding-3-small",
                    1536,
                ),
            ),
            (
                "embedding_kind",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v1",
                    "openai-compatible-embedding-v1",
                    "chat",
                    "document",
                    "openai_compatible",
                    "profile-openai",
                    "remote_https",
                    "api.openai.com",
                    443,
                    &["v1"],
                    "embeddings",
                    "text-embedding-3-small",
                    1536,
                ),
            ),
            (
                "document_kind",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v1",
                    "openai-compatible-embedding-v1",
                    "embedding",
                    "query",
                    "openai_compatible",
                    "profile-openai",
                    "remote_https",
                    "api.openai.com",
                    443,
                    &["v1"],
                    "embeddings",
                    "text-embedding-3-small",
                    1536,
                ),
            ),
            (
                "provider_kind_wire",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v1",
                    "openai-compatible-embedding-v1",
                    "embedding",
                    "document",
                    "custom_provider",
                    "profile-openai",
                    "remote_https",
                    "api.openai.com",
                    443,
                    &["v1"],
                    "embeddings",
                    "text-embedding-3-small",
                    1536,
                ),
            ),
            (
                "profile_id",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v1",
                    "openai-compatible-embedding-v1",
                    "embedding",
                    "document",
                    "openai_compatible",
                    "profile-different",
                    "remote_https",
                    "api.openai.com",
                    443,
                    &["v1"],
                    "embeddings",
                    "text-embedding-3-small",
                    1536,
                ),
            ),
            (
                "transport_target_kind",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v1",
                    "openai-compatible-embedding-v1",
                    "embedding",
                    "document",
                    "openai_compatible",
                    "profile-openai",
                    "loopback_http",
                    "api.openai.com",
                    443,
                    &["v1"],
                    "embeddings",
                    "text-embedding-3-small",
                    1536,
                ),
            ),
            (
                "host_ascii",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v1",
                    "openai-compatible-embedding-v1",
                    "embedding",
                    "document",
                    "openai_compatible",
                    "profile-openai",
                    "remote_https",
                    "api.custom.com",
                    443,
                    &["v1"],
                    "embeddings",
                    "text-embedding-3-small",
                    1536,
                ),
            ),
            (
                "effective_port",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v1",
                    "openai-compatible-embedding-v1",
                    "embedding",
                    "document",
                    "openai_compatible",
                    "profile-openai",
                    "remote_https",
                    "api.openai.com",
                    8443,
                    &["v1"],
                    "embeddings",
                    "text-embedding-3-small",
                    1536,
                ),
            ),
            (
                "base_path_segments_count",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v1",
                    "openai-compatible-embedding-v1",
                    "embedding",
                    "document",
                    "openai_compatible",
                    "profile-openai",
                    "remote_https",
                    "api.openai.com",
                    443,
                    &["v1", "extra"],
                    "embeddings",
                    "text-embedding-3-small",
                    1536,
                ),
            ),
            (
                "base_path_segments_value",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v1",
                    "openai-compatible-embedding-v1",
                    "embedding",
                    "document",
                    "openai_compatible",
                    "profile-openai",
                    "remote_https",
                    "api.openai.com",
                    443,
                    &["v2"],
                    "embeddings",
                    "text-embedding-3-small",
                    1536,
                ),
            ),
            (
                "endpoint_kind",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v1",
                    "openai-compatible-embedding-v1",
                    "embedding",
                    "document",
                    "openai_compatible",
                    "profile-openai",
                    "remote_https",
                    "api.openai.com",
                    443,
                    &["v1"],
                    "vectors",
                    "text-embedding-3-small",
                    1536,
                ),
            ),
            (
                "model_name",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v1",
                    "openai-compatible-embedding-v1",
                    "embedding",
                    "document",
                    "openai_compatible",
                    "profile-openai",
                    "remote_https",
                    "api.openai.com",
                    443,
                    &["v1"],
                    "embeddings",
                    "text-embedding-3-large",
                    1536,
                ),
            ),
            (
                "dimension",
                compute_canonical_generation_descriptor_raw(
                    "digital-life-vector-generation-descriptor-v1",
                    "memory-index-v1",
                    "openai-compatible-embedding-v1",
                    "embedding",
                    "document",
                    "openai_compatible",
                    "profile-openai",
                    "remote_https",
                    "api.openai.com",
                    443,
                    &["v1"],
                    "embeddings",
                    "text-embedding-3-small",
                    3072,
                ),
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
    fn d9d2_existing_generation_binding_sealed_consuming_api() {
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

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

        let binding = resolve_existing_generation_binding(&storage, &runtime).unwrap();

        // Binding is consumed as an atomic bundle
        let consumed_result = binding.consume_for_fenced_execution(|ctx, prov| {
            assert_eq!(ctx.dimension(), 1536);
            assert_eq!(ctx.descriptor_hash(), canonical_desc);
            assert_eq!(prov.model_info().model_name, "text-embedding-3-small");
            "consumption_success"
        });

        assert_eq!(consumed_result, "consumption_success");
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

        let res = resolve_existing_generation_binding(&storage, &runtime);
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

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

        let res = resolve_existing_generation_binding(&storage, &runtime);
        assert!(res.is_ok());

        let binding = match res {
            Ok(b) => b,
            Err(_) => panic!("expected successful binding"),
        };
        binding.consume_for_fenced_execution(|ctx, _prov| {
            assert_eq!(ctx.dimension(), 1536);
            assert_eq!(ctx.descriptor_hash(), canonical_desc);
        });
    }

    #[test]
    fn d9d2_existing_generation_binding_two_building_returns_ambiguous() {
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
        insert_generation_fixture(
            &storage,
            "generation-2",
            &"b".repeat(64),
            1536,
            "building",
            1,
        );

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

        let res = resolve_existing_generation_binding(&storage, &runtime);
        let err = match res {
            Err(e) => e,
            Ok(_) => panic!("expected AmbiguousExistingGeneration error"),
        };
        assert_eq!(
            err.code(),
            ExistingGenerationBindingErrorCode::AmbiguousExistingGeneration
        );
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

        let res = resolve_existing_generation_binding(&storage, &runtime);
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

            insert_generation_fixture(&storage, "invalid/id", &"a".repeat(64), 1536, "building", 1);
            let err = match resolve_existing_generation_binding(&storage, &runtime) {
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

            insert_generation_fixture(&storage, "gen-1", &"a".repeat(63), 1536, "building", 1);
            let err = match resolve_existing_generation_binding(&storage, &runtime) {
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

            insert_generation_fixture(
                &storage,
                "gen-1",
                &format!("{}A", "a".repeat(63)),
                1536,
                "building",
                1,
            );
            let err = match resolve_existing_generation_binding(&storage, &runtime) {
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

            insert_generation_fixture(
                &storage,
                "gen-1",
                &"a".repeat(64),
                MAX_VECTOR_DIMENSION + 1,
                "building",
                1,
            );
            let err = match resolve_existing_generation_binding(&storage, &runtime) {
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

            let err = match resolve_existing_generation_binding(&storage, &runtime) {
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

            let err = match resolve_existing_generation_binding(&storage, &runtime) {
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

        let err = match resolve_existing_generation_binding(&storage, &runtime) {
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

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

        // Valid initially
        assert!(resolve_existing_generation_binding(&storage, &runtime).is_ok());

        // Rotate active profile to new profile with different model name
        let _new_id = create_test_profile(
            &storage,
            &secrets,
            "https://api.openai.com/v1",
            "text-embedding-3-large",
            1536,
        );

        // Resolving again must fail closed with GenerationBindingMismatch
        let err = match resolve_existing_generation_binding(&storage, &runtime) {
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
                    "UPDATE memory_vector_generation SET state='retired', authority_epoch=2 WHERE generation_id='generation-1' AND authority_epoch=1",
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
        // Subcase 1: Successful resolution -> zero SQLite mutations
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

            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

            let conn = open_authorized_test_connection(&storage.test_database_main_path().unwrap())
                .unwrap();
            let data_version_before: i64 = conn
                .query_row("PRAGMA data_version", [], |r| r.get(0))
                .unwrap();
            let total_changes_before: i64 = conn
                .query_row("SELECT total_changes()", [], |r| r.get(0))
                .unwrap();

            let res = resolve_existing_generation_binding(&storage, &runtime);
            assert!(res.is_ok());

            let data_version_after: i64 = conn
                .query_row("PRAGMA data_version", [], |r| r.get(0))
                .unwrap();
            let total_changes_after: i64 = conn
                .query_row("SELECT total_changes()", [], |r| r.get(0))
                .unwrap();

            assert_eq!(
                data_version_before, data_version_after,
                "Read bridge must not modify SQLite data_version on success"
            );
            assert_eq!(
                total_changes_before, total_changes_after,
                "Read bridge must not execute SQLite mutations on success"
            );
        }

        // Subcase 2: Zero building candidate -> zero SQLite mutations
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

            let conn = open_authorized_test_connection(&storage.test_database_main_path().unwrap())
                .unwrap();
            let data_version_before: i64 = conn
                .query_row("PRAGMA data_version", [], |r| r.get(0))
                .unwrap();
            let total_changes_before: i64 = conn
                .query_row("SELECT total_changes()", [], |r| r.get(0))
                .unwrap();

            let _ = resolve_existing_generation_binding(&storage, &runtime);

            let data_version_after: i64 = conn
                .query_row("PRAGMA data_version", [], |r| r.get(0))
                .unwrap();
            let total_changes_after: i64 = conn
                .query_row("SELECT total_changes()", [], |r| r.get(0))
                .unwrap();

            assert_eq!(data_version_before, data_version_after);
            assert_eq!(total_changes_before, total_changes_after);
        }

        // Subcase 3: Ambiguous building candidate -> zero SQLite mutations
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
            insert_generation_fixture(
                &storage,
                "generation-2",
                &"b".repeat(64),
                1536,
                "building",
                1,
            );

            let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

            let conn = open_authorized_test_connection(&storage.test_database_main_path().unwrap())
                .unwrap();
            let data_version_before: i64 = conn
                .query_row("PRAGMA data_version", [], |r| r.get(0))
                .unwrap();
            let total_changes_before: i64 = conn
                .query_row("SELECT total_changes()", [], |r| r.get(0))
                .unwrap();

            let _ = resolve_existing_generation_binding(&storage, &runtime);

            let data_version_after: i64 = conn
                .query_row("PRAGMA data_version", [], |r| r.get(0))
                .unwrap();
            let total_changes_after: i64 = conn
                .query_row("SELECT total_changes()", [], |r| r.get(0))
                .unwrap();

            assert_eq!(data_version_before, data_version_after);
            assert_eq!(total_changes_before, total_changes_after);
        }

        // Subcase 4: Binding mismatch -> zero SQLite mutations
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

            let conn = open_authorized_test_connection(&storage.test_database_main_path().unwrap())
                .unwrap();
            let data_version_before: i64 = conn
                .query_row("PRAGMA data_version", [], |r| r.get(0))
                .unwrap();
            let total_changes_before: i64 = conn
                .query_row("SELECT total_changes()", [], |r| r.get(0))
                .unwrap();

            let _ = resolve_existing_generation_binding(&storage, &runtime);

            let data_version_after: i64 = conn
                .query_row("PRAGMA data_version", [], |r| r.get(0))
                .unwrap();
            let total_changes_after: i64 = conn
                .query_row("SELECT total_changes()", [], |r| r.get(0))
                .unwrap();

            assert_eq!(data_version_before, data_version_after);
            assert_eq!(total_changes_before, total_changes_after);
        }
    }
}
