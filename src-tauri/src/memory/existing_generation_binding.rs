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
//!   no IPC exposure, and no raw scalar getters.
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
            ResolvedEmbeddingProvider,
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

    #[allow(dead_code)]
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
/// NO IPC exposure, and NO raw scalar getters.
pub(crate) struct ExistingVectorGenerationBinding<'a> {
    context: VectorGenerationContext,
    provider: ResolvedEmbeddingProvider<'a>,
}

impl<'a> ExistingVectorGenerationBinding<'a> {
    /// Private access to the generation context for future fenced consumer construction.
    #[allow(dead_code)]
    pub(crate) fn generation_context(&self) -> &VectorGenerationContext {
        &self.context
    }

    /// Private access to the embedding provider for future fenced operations.
    #[allow(dead_code)]
    pub(crate) fn provider(&self) -> &dyn EmbeddingProvider {
        self.provider.provider()
    }
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
    let mut hasher = Sha256::new();

    // LP("digital-life-vector-generation-descriptor-v1")
    hash_length_prefixed(&mut hasher, "digital-life-vector-generation-descriptor-v1");
    // LP(MEMORY_INDEX_FORMAT_VERSION)
    hash_length_prefixed(&mut hasher, MEMORY_INDEX_FORMAT_VERSION);
    // LP(PROTOCOL_VERSION)
    hash_length_prefixed(&mut hasher, PROTOCOL_VERSION);
    // LP("embedding")
    hash_length_prefixed(&mut hasher, "embedding");
    // LP("document")
    hash_length_prefixed(&mut hasher, "document");
    // LP(provider_kind_wire)
    hash_length_prefixed(&mut hasher, provider_kind.as_str());
    // LP(profile_id)
    hash_length_prefixed(&mut hasher, profile_id);
    // LP(transport_target_kind)
    let target_kind_str = match transport_target.kind() {
        TransportTargetKind::RemoteHttps => "remote_https",
        TransportTargetKind::LoopbackHttp => "loopback_http",
    };
    hash_length_prefixed(&mut hasher, target_kind_str);
    // LP(host_ascii)
    hash_length_prefixed(&mut hasher, transport_target.host_ascii());
    // U16_BE(effective_port)
    hasher.update(transport_target.port().to_be_bytes());
    // U64_BE(base_path_segment_count)
    let segments_count = transport_target.base_path().segments().len() as u64;
    hasher.update(segments_count.to_be_bytes());
    // each LP(base_path_segment)
    for segment in transport_target.base_path().segments() {
        hash_length_prefixed(&mut hasher, segment);
    }
    // LP("embeddings")
    hash_length_prefixed(&mut hasher, "embeddings");
    // LP(trimmed_model_name)
    hash_length_prefixed(&mut hasher, model_name.trim());
    // U64_BE(dimension)
    hasher.update((dimension as u64).to_be_bytes());

    let digest = hasher.finalize();
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(result, "{byte:02x}");
    }
    Ok(result)
}

fn hash_length_prefixed(hasher: &mut Sha256, s: &str) {
    hasher.update((s.len() as u64).to_be_bytes());
    hasher.update(s.as_bytes());
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

    // 3. Inspect profile facts
    let profile = &resolved_provider.profile;
    if profile.purpose != ModelRuntimePurpose::Embedding {
        return Err(ExistingGenerationBindingError::generation_provider_mismatch());
    }

    let profile_dimension = match profile.embedding_dimension {
        Some(dim) if dim > 0 && dim <= MAX_VECTOR_DIMENSION as u32 => dim as usize,
        _ => return Err(ExistingGenerationBindingError::generation_provider_mismatch()),
    };

    let provider_model_info = resolved_provider.provider().model_info();
    if let Some(prov_dim) = provider_model_info.dimension {
        if prov_dim != profile_dimension {
            return Err(ExistingGenerationBindingError::generation_provider_mismatch());
        }
    }

    if provider_model_info.model_name.trim() != profile.model_name.trim() {
        return Err(ExistingGenerationBindingError::generation_provider_mismatch());
    }

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
    use std::time::Duration;

    use rusqlite::params;
    use tempfile::TempDir;

    use super::*;
    use crate::{
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

        assert_eq!(desc_a.len(), 64);
        assert!(desc_a.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')));

        // Golden vector stability: deterministic digest
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

        // Field change 1: Profile ID change
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

        // Field change 2: Path segmentation difference
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

        // Field change 3: Dimension difference
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

        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        let version_before: i64 = conn
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .unwrap();

        let res = resolve_existing_generation_binding(&storage, &runtime);

        let version_after: i64 = conn
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            version_before, version_after,
            "Resolver must not mutate SQLite"
        );

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

        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        let version_before: i64 = conn
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .unwrap();

        let res = resolve_existing_generation_binding(&storage, &runtime);

        let version_after: i64 = conn
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            version_before, version_after,
            "Resolver must not mutate SQLite"
        );

        assert!(res.is_ok());
        let binding = match res {
            Ok(b) => b,
            Err(_) => panic!("expected successful binding"),
        };
        assert_eq!(binding.generation_context().dimension(), 1536);
        assert_eq!(
            binding.generation_context().descriptor_hash(),
            canonical_desc
        );
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

        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        let version_before: i64 = conn
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .unwrap();

        let res = resolve_existing_generation_binding(&storage, &runtime);

        let version_after: i64 = conn
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            version_before, version_after,
            "Resolver must not mutate SQLite"
        );

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
    fn d9d2_existing_generation_binding_concurrency_stale_detection() {
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

        // Connection A loads candidate authority
        let authority = storage_a
            .load_existing_building_generation_candidate()
            .unwrap();
        assert!(authority
            .verify_descriptor_and_dimension(&canonical_desc, 1536)
            .is_ok());

        // Connection B updates authority in SQLite (transitioning to active and advancing epoch)
        let conn_b =
            open_authorized_test_connection(&storage_b.test_database_main_path().unwrap()).unwrap();
        conn_b
            .execute(
                "UPDATE memory_vector_generation SET state='active', authority_epoch=2 WHERE generation_id='generation-1' AND authority_epoch=1",
                [],
            )
            .unwrap();

        // Connection A attempts exact recheck and seal -> must detect stale epoch
        let err = match authority.verify_current_and_seal(&storage_a) {
            Err(e) => e,
            Ok(_) => panic!("expected stale error"),
        };
        assert_eq!(
            err.code(),
            ExistingGenerationBindingErrorCode::GenerationBindingStale
        );
    }

    #[test]
    fn d9d2_existing_generation_binding_read_only_guarantee_total_changes() {
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

        let conn =
            open_authorized_test_connection(&storage.test_database_main_path().unwrap()).unwrap();
        let version_before: i64 = conn
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .unwrap();

        let res = resolve_existing_generation_binding(&storage, &runtime);
        assert!(res.is_ok());

        let version_after: i64 = conn
            .query_row("PRAGMA data_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            version_before, version_after,
            "Read bridge must execute 0 SQLite mutations"
        );
    }
}
