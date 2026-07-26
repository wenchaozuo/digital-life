//! Production assembly for governed, read-only hybrid memory retrieval.
//!
//! It resolves a fresh embedding provider per request, but never creates an
//! index, writes a vector, opens SQLite independently, or exposes a command.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::{
    embedding::{
        EmbeddingBatch, EmbeddingError, EmbeddingErrorCode, EmbeddingFuture, EmbeddingModelInfo,
        EmbeddingProvider, EmbeddingRequest,
    },
    model::{
        profile::ModelProfileRepository,
        runtime::{ModelRuntimeCoordinator, ModelRuntimeErrorCode, ModelRuntimeService},
    },
    secrets::SecretStore,
    storage::StorageService,
    vector_store::{
        LanceDbVectorStoreRegistry, VectorRecord, VectorSearchHit, VectorSearchQuery, VectorSpace,
        VectorStore, VectorStoreError, VectorStoreFuture,
    },
};

use super::{
    retrieval_router::{
        HybridRetrievalRequest, KeywordRetrievalStatus, MemoryRetrievalRouter,
        MemoryRetrievalRouterErrorCode, MemoryRetrievalRouterRepository, RetrievalCandidate,
        RetrievalStrategy, VectorRetrievalStatus, DEFAULT_HYBRID_LIMIT,
    },
    MemoryKind,
};

pub const MAX_RETRIEVAL_QUERY_CHARACTERS: usize = 4_000;
pub const VECTOR_MIN_SCORE: f32 = 0.20;

pub trait MemoryRetrievalDataRootResolver: Send + Sync {
    fn active_data_root(&self) -> Result<PathBuf, RetrievalRuntimeError>;
}

impl MemoryRetrievalDataRootResolver for StorageService {
    fn active_data_root(&self) -> Result<PathBuf, RetrievalRuntimeError> {
        StorageService::active_data_root(self)
            .map_err(|_| runtime_error(RetrievalRuntimeErrorCode::RuntimeUnavailable))
    }
}

pub struct ResolvedRuntimeEmbeddingProvider<'a> {
    pub model_name: String,
    pub dimension: usize,
    provider: Box<dyn EmbeddingProvider + 'a>,
}

impl ResolvedRuntimeEmbeddingProvider<'_> {
    fn provider(&self) -> &dyn EmbeddingProvider {
        self.provider.as_ref()
    }
}

pub trait ActiveEmbeddingProviderFactory: Send + Sync {
    fn resolve_active_embedding_provider(
        &self,
    ) -> Result<ResolvedRuntimeEmbeddingProvider<'_>, RetrievalDegradationCode>;
}

pub struct ModelRuntimeEmbeddingProviderFactory<'a, P, S>
where
    P: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    profiles: &'a P,
    secrets: &'a S,
    coordinator: &'a ModelRuntimeCoordinator,
}

impl<'a, P, S> ModelRuntimeEmbeddingProviderFactory<'a, P, S>
where
    P: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    pub fn new(profiles: &'a P, secrets: &'a S, coordinator: &'a ModelRuntimeCoordinator) -> Self {
        Self {
            profiles,
            secrets,
            coordinator,
        }
    }
}

impl<P, S> ActiveEmbeddingProviderFactory for ModelRuntimeEmbeddingProviderFactory<'_, P, S>
where
    P: ModelProfileRepository + Send + Sync,
    S: SecretStore + ?Sized,
{
    fn resolve_active_embedding_provider(
        &self,
    ) -> Result<ResolvedRuntimeEmbeddingProvider<'_>, RetrievalDegradationCode> {
        let resolved = ModelRuntimeService::new(self.profiles, self.secrets, self.coordinator)
            .resolve_active_embedding_provider()
            .map_err(map_model_runtime_error)?;
        let dimension = resolved
            .profile
            .embedding_dimension
            .map(|value| value as usize)
            .ok_or(RetrievalDegradationCode::EmbeddingDimensionMismatch)?;
        let model_name = resolved.profile.model_name.clone();
        Ok(ResolvedRuntimeEmbeddingProvider {
            model_name,
            dimension,
            provider: resolved.into_provider(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernedRetrievalRequest {
    pub life_id: String,
    pub query: String,
    pub memory_kind_filter: Option<Vec<MemoryKind>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetrievalAvailability {
    Hybrid,
    KeywordOnly,
    VectorOnly,
    NoMemory,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetrievalDegradationCode {
    VectorSkippedSensitiveQuery,
    NoActiveEmbeddingProfile,
    EmbeddingProfileNotFound,
    EmbeddingCredentialNotFound,
    EmbeddingPurposeMismatch,
    UnsupportedEmbeddingProvider,
    EmbeddingProviderUnavailable,
    EmbeddingDimensionMismatch,
    IndexDirectoryMissing,
    VectorStoreUnavailable,
    VectorIndexUnavailable,
    VectorUnavailable,
    KeywordUnavailable,
    AuthoritativeReadUnavailable,
    BothRetrievalUnavailable,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedRetrievalResult {
    pub candidates: Vec<RetrievalCandidate>,
    pub retrieved_count: usize,
    pub used_count: usize,
    pub availability: RetrievalAvailability,
    pub degradation_codes: Vec<RetrievalDegradationCode>,
    pub rebuild_recommended: bool,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetrievalRuntimeErrorCode {
    InvalidRequest,
    LifeNotFound,
    RuntimeUnavailable,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RetrievalRuntimeError {
    pub code: RetrievalRuntimeErrorCode,
    pub message: String,
    pub recoverable: bool,
}

pub struct MemoryRetrievalRuntimeService<'a, R, F, D>
where
    R: MemoryRetrievalRouterRepository,
    F: ActiveEmbeddingProviderFactory + ?Sized,
    D: MemoryRetrievalDataRootResolver + ?Sized,
{
    memories: &'a R,
    provider_factory: &'a F,
    data_root: &'a D,
    registry: &'a LanceDbVectorStoreRegistry,
}

impl<'a, R, F, D> MemoryRetrievalRuntimeService<'a, R, F, D>
where
    R: MemoryRetrievalRouterRepository,
    F: ActiveEmbeddingProviderFactory + ?Sized,
    D: MemoryRetrievalDataRootResolver + ?Sized,
{
    pub fn new(
        memories: &'a R,
        provider_factory: &'a F,
        data_root: &'a D,
        registry: &'a LanceDbVectorStoreRegistry,
    ) -> Self {
        Self {
            memories,
            provider_factory,
            data_root,
            registry,
        }
    }

    pub async fn retrieve(
        &self,
        request: GovernedRetrievalRequest,
    ) -> Result<GovernedRetrievalResult, RetrievalRuntimeError> {
        validate_request(&request)?;
        if contains_high_risk_credential(&request.query) {
            return self
                .retrieve_keyword_only(
                    request,
                    vec![RetrievalDegradationCode::VectorSkippedSensitiveQuery],
                )
                .await;
        }

        let resolved = match self.provider_factory.resolve_active_embedding_provider() {
            Ok(resolved) => resolved,
            Err(code) => return self.retrieve_keyword_only(request, vec![code]).await,
        };
        let space = VectorSpace {
            embedding_model: resolved.model_name.clone(),
            dimension: resolved.dimension,
        };
        let root = match self.data_root.active_data_root() {
            Ok(root) => root,
            Err(_) => {
                return self
                    .retrieve_keyword_only(
                        request,
                        vec![RetrievalDegradationCode::VectorStoreUnavailable],
                    )
                    .await
            }
        };
        let Some(store) = self
            .registry
            .existing_store(&root)
            .await
            .map_err(|_| runtime_error(RetrievalRuntimeErrorCode::RuntimeUnavailable))?
        else {
            return self
                .retrieve_keyword_only(
                    request,
                    vec![RetrievalDegradationCode::IndexDirectoryMissing],
                )
                .await;
        };
        match store.count(&request.life_id, Some(&space)).await {
            Ok(0) => {
                return self
                    .retrieve_keyword_only(
                        request,
                        vec![RetrievalDegradationCode::VectorIndexUnavailable],
                    )
                    .await
            }
            Err(_) => {
                return self
                    .retrieve_keyword_only(
                        request,
                        vec![RetrievalDegradationCode::VectorStoreUnavailable],
                    )
                    .await
            }
            Ok(_) => {}
        }

        let router =
            MemoryRetrievalRouter::new(self.memories, resolved.provider(), store.as_ref(), space)
                .map_err(|_| runtime_error(RetrievalRuntimeErrorCode::RuntimeUnavailable))?;
        let result = router
            .retrieve(HybridRetrievalRequest {
                life_id: request.life_id,
                query: request.query,
                limit: DEFAULT_HYBRID_LIMIT,
                strategy: RetrievalStrategy::Hybrid,
                min_score: Some(VECTOR_MIN_SCORE),
                memory_kind_filter: request.memory_kind_filter,
            })
            .await;
        self.finish_router_result(result, Vec::new())
    }

    async fn retrieve_keyword_only(
        &self,
        request: GovernedRetrievalRequest,
        degradations: Vec<RetrievalDegradationCode>,
    ) -> Result<GovernedRetrievalResult, RetrievalRuntimeError> {
        let router = MemoryRetrievalRouter::new(
            self.memories,
            &KeywordOnlyEmbeddingProvider,
            &KeywordOnlyVectorStore,
            VectorSpace {
                embedding_model: "keyword-only".to_string(),
                dimension: 1,
            },
        )
        .map_err(|_| runtime_error(RetrievalRuntimeErrorCode::RuntimeUnavailable))?;
        let result = router
            .retrieve(HybridRetrievalRequest {
                life_id: request.life_id,
                query: request.query,
                limit: DEFAULT_HYBRID_LIMIT,
                strategy: RetrievalStrategy::KeywordOnly,
                min_score: None,
                memory_kind_filter: request.memory_kind_filter,
            })
            .await;
        self.finish_router_result(result, degradations)
    }

    fn finish_router_result(
        &self,
        result: Result<
            super::retrieval_router::HybridRetrievalResult,
            super::retrieval_router::MemoryRetrievalRouterError,
        >,
        mut degradations: Vec<RetrievalDegradationCode>,
    ) -> Result<GovernedRetrievalResult, RetrievalRuntimeError> {
        let result = match result {
            Ok(result) => result,
            Err(error) => match error.code {
                MemoryRetrievalRouterErrorCode::LifeNotFound => {
                    return Err(runtime_error(RetrievalRuntimeErrorCode::LifeNotFound));
                }
                MemoryRetrievalRouterErrorCode::RepositoryUnavailable => {
                    push_degradation(
                        &mut degradations,
                        RetrievalDegradationCode::AuthoritativeReadUnavailable,
                    );
                    push_degradation(
                        &mut degradations,
                        RetrievalDegradationCode::BothRetrievalUnavailable,
                    );
                    return Ok(empty_result(degradations));
                }
                MemoryRetrievalRouterErrorCode::KeywordUnavailable => {
                    push_degradation(
                        &mut degradations,
                        RetrievalDegradationCode::KeywordUnavailable,
                    );
                    push_degradation(
                        &mut degradations,
                        RetrievalDegradationCode::BothRetrievalUnavailable,
                    );
                    return Ok(empty_result(degradations));
                }
                _ => return Err(runtime_error(RetrievalRuntimeErrorCode::RuntimeUnavailable)),
            },
        };
        if result.keyword_status == KeywordRetrievalStatus::KeywordUnavailable {
            push_degradation(
                &mut degradations,
                RetrievalDegradationCode::KeywordUnavailable,
            );
        }
        if result.vector_status == VectorRetrievalStatus::VectorUnavailable {
            push_degradation(
                &mut degradations,
                RetrievalDegradationCode::VectorUnavailable,
            );
        }
        if result.keyword_status == KeywordRetrievalStatus::KeywordUnavailable
            && result.vector_status == VectorRetrievalStatus::VectorUnavailable
        {
            push_degradation(
                &mut degradations,
                RetrievalDegradationCode::BothRetrievalUnavailable,
            );
        }
        let availability = match (
            result.keyword_status,
            result.vector_status,
            result.candidates.is_empty(),
        ) {
            (_, _, true) => RetrievalAvailability::NoMemory,
            (KeywordRetrievalStatus::Available, VectorRetrievalStatus::Available, false) => {
                RetrievalAvailability::Hybrid
            }
            (
                KeywordRetrievalStatus::KeywordUnavailable,
                VectorRetrievalStatus::Available,
                false,
            ) => RetrievalAvailability::VectorOnly,
            _ => RetrievalAvailability::KeywordOnly,
        };
        Ok(GovernedRetrievalResult {
            retrieved_count: result.candidates.len(),
            used_count: result.candidates.len(),
            candidates: result.candidates,
            availability,
            degradation_codes: degradations,
            rebuild_recommended: false,
        })
    }
}

struct KeywordOnlyEmbeddingProvider;

impl EmbeddingProvider for KeywordOnlyEmbeddingProvider {
    fn model_info(&self) -> EmbeddingModelInfo {
        EmbeddingModelInfo {
            model_name: "keyword-only".to_string(),
            dimension: Some(1),
        }
    }

    fn model_name(&self) -> &str {
        "keyword-only"
    }

    fn vector_dimension(&self) -> Option<usize> {
        Some(1)
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

struct KeywordOnlyVectorStore;

impl VectorStore for KeywordOnlyVectorStore {
    fn upsert<'a>(
        &'a self,
        _record: VectorRecord,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async { Err(vector_store_error()) })
    }
    fn upsert_batch<'a>(
        &'a self,
        _records: Vec<VectorRecord>,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async { Err(vector_store_error()) })
    }
    fn search<'a>(
        &'a self,
        _query: VectorSearchQuery,
    ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>> {
        Box::pin(async { Err(vector_store_error()) })
    }
    fn delete<'a>(
        &'a self,
        _life_id: &'a str,
        _memory_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        Box::pin(async { Err(vector_store_error()) })
    }
    fn delete_from_space<'a>(
        &'a self,
        _life_id: &'a str,
        _memory_id: &'a str,
        _space: &'a VectorSpace,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        Box::pin(async { Err(vector_store_error()) })
    }
    fn delete_by_life<'a>(
        &'a self,
        _life_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        Box::pin(async { Err(vector_store_error()) })
    }
    fn clear_space<'a>(
        &'a self,
        _life_id: &'a str,
        _space: &'a VectorSpace,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        Box::pin(async { Err(vector_store_error()) })
    }
    fn count<'a>(
        &'a self,
        _life_id: &'a str,
        _space: Option<&'a VectorSpace>,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        Box::pin(async { Err(vector_store_error()) })
    }
    fn health_check<'a>(
        &'a self,
        _life_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async { Err(vector_store_error()) })
    }
}

fn vector_store_error() -> VectorStoreError {
    VectorStoreError::new(
        crate::vector_store::VectorStoreErrorCode::StoreUnavailable,
        "The keyword-only store is unavailable.",
        true,
    )
}

fn validate_request(request: &GovernedRetrievalRequest) -> Result<(), RetrievalRuntimeError> {
    if request.life_id.trim().is_empty()
        || request.query.trim().is_empty()
        || request.query.chars().count() > MAX_RETRIEVAL_QUERY_CHARACTERS
    {
        return Err(runtime_error(RetrievalRuntimeErrorCode::InvalidRequest));
    }
    Ok(())
}

fn map_model_runtime_error(
    error: crate::model::runtime::ModelRuntimeError,
) -> RetrievalDegradationCode {
    match error.code {
        ModelRuntimeErrorCode::NoActiveProfile => {
            RetrievalDegradationCode::NoActiveEmbeddingProfile
        }
        ModelRuntimeErrorCode::ProfileNotFound => {
            RetrievalDegradationCode::EmbeddingProfileNotFound
        }
        ModelRuntimeErrorCode::CredentialNotFound => {
            RetrievalDegradationCode::EmbeddingCredentialNotFound
        }
        ModelRuntimeErrorCode::ProfilePurposeMismatch => {
            RetrievalDegradationCode::EmbeddingPurposeMismatch
        }
        ModelRuntimeErrorCode::UnsupportedProvider => {
            RetrievalDegradationCode::UnsupportedEmbeddingProvider
        }
        ModelRuntimeErrorCode::DimensionMismatch => {
            RetrievalDegradationCode::EmbeddingDimensionMismatch
        }
        _ => RetrievalDegradationCode::EmbeddingProviderUnavailable,
    }
}

fn contains_high_risk_credential(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.contains("-----begin ") && lower.contains("private key-----") {
        return true;
    }
    if lower.contains("authorization:") && lower.contains("bearer ") {
        return true;
    }
    [
        "api_key=",
        "api-key=",
        "apikey=",
        "access_token=",
        "refresh_token=",
        "token=",
        "secret=",
        "password=",
    ]
    .iter()
    .any(|prefix| assignment_has_value(&lower, prefix))
        || contains_access_key(value)
}

fn assignment_has_value(value: &str, prefix: &str) -> bool {
    let Some(start) = value.find(prefix) else {
        return false;
    };
    value[start + prefix.len()..]
        .chars()
        .take_while(|character| !character.is_whitespace() && !matches!(character, '&' | ',' | ';'))
        .count()
        >= 8
}

fn contains_access_key(value: &str) -> bool {
    value
        .split(|character: char| {
            !character.is_ascii_alphanumeric() && character != '-' && character != '_'
        })
        .any(|token| {
            (token.starts_with("AKIA")
                && token.len() == 20
                && token[4..]
                    .chars()
                    .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit()))
                || ((token.starts_with("sk-") || token.starts_with("sk_"))
                    && token.len() >= 23
                    && token[3..]
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric()))
        })
}

fn push_degradation(values: &mut Vec<RetrievalDegradationCode>, value: RetrievalDegradationCode) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn empty_result(degradation_codes: Vec<RetrievalDegradationCode>) -> GovernedRetrievalResult {
    GovernedRetrievalResult {
        candidates: Vec::new(),
        retrieved_count: 0,
        used_count: 0,
        availability: RetrievalAvailability::NoMemory,
        degradation_codes,
        rebuild_recommended: false,
    }
}

fn runtime_error(code: RetrievalRuntimeErrorCode) -> RetrievalRuntimeError {
    let (message, recoverable) = match code {
        RetrievalRuntimeErrorCode::InvalidRequest => {
            ("The memory retrieval request is invalid.", false)
        }
        RetrievalRuntimeErrorCode::LifeNotFound => ("The specified life was not found.", true),
        RetrievalRuntimeErrorCode::RuntimeUnavailable => {
            ("Governed memory retrieval is unavailable.", true)
        }
    };
    RetrievalRuntimeError {
        code,
        message: message.to_string(),
        recoverable,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use crate::{
        embedding::EmbeddingBatch,
        memory::retrieval::MemoryRetrievalRepository,
        memory::{MemoryRecord, MemorySourceType, MemoryStatus},
        vector_store::LanceDbVectorStore,
    };

    use super::*;

    struct TestRoot(PathBuf);
    impl TestRoot {
        fn new() -> Self {
            let path = tempfile::tempdir().unwrap().keep();
            Self(path)
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    struct RootResolver(PathBuf);
    impl MemoryRetrievalDataRootResolver for RootResolver {
        fn active_data_root(&self) -> Result<PathBuf, RetrievalRuntimeError> {
            Ok(self.0.clone())
        }
    }

    struct Repository {
        records: Vec<MemoryRecord>,
        keyword_fails: bool,
        hydrate_fails: bool,
    }
    impl MemoryRetrievalRepository for Repository {
        fn retrieve_confirmed(
            &self,
            _query: &super::super::retrieval::RetrievalQuery,
        ) -> Result<Vec<super::super::retrieval::MemoryRetrievalResult>, super::super::MemoryError>
        {
            if self.keyword_fails {
                return Err(super::super::MemoryError::database());
            }
            Ok(self
                .records
                .iter()
                .filter(|record| record.status == MemoryStatus::Confirmed && !record.is_sensitive)
                .map(|record| super::super::retrieval::MemoryRetrievalResult {
                    memory_id: record.id.clone(),
                    kind: record.kind,
                    content: record.content.clone(),
                    summary: record.summary.clone(),
                    importance: record.importance,
                    confidence: record.confidence,
                    created_at: record.created_at.clone(),
                })
                .collect())
        }
    }
    impl MemoryRetrievalRouterRepository for Repository {
        fn life_exists(&self, life_id: &str) -> Result<bool, super::super::MemoryError> {
            Ok(life_id == "life-a")
        }
        fn load_authoritative_candidates(
            &self,
            life_id: &str,
            ids: &[String],
        ) -> Result<Vec<MemoryRecord>, super::super::MemoryError> {
            if self.hydrate_fails {
                return Err(super::super::MemoryError::database());
            }
            Ok(self
                .records
                .iter()
                .filter(|record| record.life_id == life_id && ids.contains(&record.id))
                .cloned()
                .collect())
        }
    }

    struct TestProvider {
        calls: Arc<AtomicUsize>,
    }
    impl EmbeddingProvider for TestProvider {
        fn model_info(&self) -> EmbeddingModelInfo {
            EmbeddingModelInfo {
                model_name: "model-a".into(),
                dimension: Some(2),
            }
        }
        fn model_name(&self) -> &str {
            "model-a"
        }
        fn vector_dimension(&self) -> Option<usize> {
            Some(2)
        }
        fn embed<'a>(
            &'a self,
            _request: EmbeddingRequest,
        ) -> EmbeddingFuture<'a, Result<EmbeddingBatch, EmbeddingError>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { EmbeddingBatch::from_test_vectors(vec![vec![1.0, 0.0]]) })
        }
    }
    struct Factory {
        calls: Arc<AtomicUsize>,
        error: Option<RetrievalDegradationCode>,
    }
    impl ActiveEmbeddingProviderFactory for Factory {
        fn resolve_active_embedding_provider(
            &self,
        ) -> Result<ResolvedRuntimeEmbeddingProvider<'_>, RetrievalDegradationCode> {
            if let Some(error) = self.error {
                return Err(error);
            }
            Ok(ResolvedRuntimeEmbeddingProvider {
                model_name: "model-a".into(),
                dimension: 2,
                provider: Box::new(TestProvider {
                    calls: Arc::clone(&self.calls),
                }),
            })
        }
    }

    fn record(id: &str, sensitive: bool, status: MemoryStatus) -> MemoryRecord {
        MemoryRecord {
            id: id.into(),
            life_id: "life-a".into(),
            kind: MemoryKind::Fact,
            status,
            content: format!("content-{id}"),
            summary: Some(format!("summary-{id}")),
            source_type: MemorySourceType::Manual,
            source_ref: None,
            source_created_at: "2026-07-13T00:00:00.000Z".into(),
            importance: 0.8,
            confidence: 0.9,
            is_sensitive: sensitive,
            created_at: "2026-07-13T00:00:00.000Z".into(),
            updated_at: "2026-07-13T00:00:00.000Z".into(),
            confirmed_at: Some("2026-07-13T00:00:00.000Z".into()),
        }
    }
    fn request(query: &str) -> GovernedRetrievalRequest {
        GovernedRetrievalRequest {
            life_id: "life-a".into(),
            query: query.into(),
            memory_kind_filter: None,
        }
    }

    #[test]
    fn sensitive_query_and_missing_profile_degrade_to_keyword_without_embedding() {
        tauri::async_runtime::block_on(async {
            let root = TestRoot::new();
            let resolver = RootResolver(root.0.clone());
            let registry = LanceDbVectorStoreRegistry::default();
            let repository = Repository {
                records: vec![record("m1", false, MemoryStatus::Confirmed)],
                keyword_fails: false,
                hydrate_fails: false,
            };
            let calls = Arc::new(AtomicUsize::new(0));
            let factory = Factory {
                calls: Arc::clone(&calls),
                error: None,
            };
            let service =
                MemoryRetrievalRuntimeService::new(&repository, &factory, &resolver, &registry);
            let result = service
                .retrieve(request("Authorization: Bearer fixture-value-123"))
                .await
                .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(result.availability, RetrievalAvailability::KeywordOnly);
            assert!(result
                .degradation_codes
                .contains(&RetrievalDegradationCode::VectorSkippedSensitiveQuery));
            let missing = Factory {
                calls: Arc::new(AtomicUsize::new(0)),
                error: Some(RetrievalDegradationCode::NoActiveEmbeddingProfile),
            };
            let service =
                MemoryRetrievalRuntimeService::new(&repository, &missing, &resolver, &registry);
            let result = service.retrieve(request("what is a token?")).await.unwrap();
            assert!(result
                .degradation_codes
                .contains(&RetrievalDegradationCode::NoActiveEmbeddingProfile));
        });
    }

    #[test]
    fn missing_index_does_not_create_directory_or_write_vectors() {
        tauri::async_runtime::block_on(async {
            let root = TestRoot::new();
            let resolver = RootResolver(root.0.clone());
            let registry = LanceDbVectorStoreRegistry::default();
            let repository = Repository {
                records: vec![record("m1", false, MemoryStatus::Confirmed)],
                keyword_fails: false,
                hydrate_fails: false,
            };
            let factory = Factory {
                calls: Arc::new(AtomicUsize::new(0)),
                error: None,
            };
            let service =
                MemoryRetrievalRuntimeService::new(&repository, &factory, &resolver, &registry);
            let result = service.retrieve(request("hello")).await.unwrap();
            assert_eq!(result.availability, RetrievalAvailability::KeywordOnly);
            assert!(result
                .degradation_codes
                .contains(&RetrievalDegradationCode::IndexDirectoryMissing));
            assert!(!root.0.join("vectors").exists());
        });
    }

    #[test]
    fn hybrid_and_controlled_vector_only_hydrate_authoritative_records() {
        tauri::async_runtime::block_on(async {
            let root = TestRoot::new();
            let resolver = RootResolver(root.0.clone());
            let index = root.0.join("vectors").join("lancedb");
            let store = LanceDbVectorStore::open(&index).await.unwrap();
            store
                .upsert(VectorRecord {
                    life_id: "life-a".into(),
                    memory_id: "m1".into(),
                    embedding_model: "model-a".into(),
                    dimension: 2,
                    vector: vec![1.0, 0.0],
                    content_hash: "hash".into(),
                })
                .await
                .unwrap();
            let registry = LanceDbVectorStoreRegistry::default();
            let calls = Arc::new(AtomicUsize::new(0));
            let factory = Factory {
                calls: Arc::clone(&calls),
                error: None,
            };
            let repository = Repository {
                records: vec![
                    record("m1", false, MemoryStatus::Confirmed),
                    record("candidate", false, MemoryStatus::Candidate),
                    record("sensitive", true, MemoryStatus::Confirmed),
                ],
                keyword_fails: false,
                hydrate_fails: false,
            };
            let service =
                MemoryRetrievalRuntimeService::new(&repository, &factory, &resolver, &registry);
            let result = service.retrieve(request("coffee")).await.unwrap();
            assert_eq!(result.availability, RetrievalAvailability::Hybrid);
            assert_eq!(result.candidates.len(), 1);
            assert_eq!(result.candidates[0].memory_id, "m1");
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let failing_keyword = Repository {
                records: vec![record("m1", false, MemoryStatus::Confirmed)],
                keyword_fails: true,
                hydrate_fails: false,
            };
            let service = MemoryRetrievalRuntimeService::new(
                &failing_keyword,
                &factory,
                &resolver,
                &registry,
            );
            let result = service.retrieve(request("coffee")).await.unwrap();
            assert_eq!(result.availability, RetrievalAvailability::VectorOnly);
            assert!(result
                .degradation_codes
                .contains(&RetrievalDegradationCode::KeywordUnavailable));
        });
    }

    #[test]
    fn failed_authoritative_hydration_never_returns_lance_hits() {
        tauri::async_runtime::block_on(async {
            let root = TestRoot::new();
            let resolver = RootResolver(root.0.clone());
            let index = root.0.join("vectors").join("lancedb");
            let store = LanceDbVectorStore::open(&index).await.unwrap();
            store
                .upsert(VectorRecord {
                    life_id: "life-a".into(),
                    memory_id: "forged".into(),
                    embedding_model: "model-a".into(),
                    dimension: 2,
                    vector: vec![1.0, 0.0],
                    content_hash: "hash".into(),
                })
                .await
                .unwrap();
            let registry = LanceDbVectorStoreRegistry::default();
            let factory = Factory {
                calls: Arc::new(AtomicUsize::new(0)),
                error: None,
            };
            let repository = Repository {
                records: Vec::new(),
                keyword_fails: true,
                hydrate_fails: true,
            };
            let service =
                MemoryRetrievalRuntimeService::new(&repository, &factory, &resolver, &registry);
            let result = service.retrieve(request("coffee")).await.unwrap();
            assert!(result.candidates.is_empty());
            assert!(result
                .degradation_codes
                .contains(&RetrievalDegradationCode::AuthoritativeReadUnavailable));
        });
    }

    #[test]
    fn ordinary_token_query_is_not_sensitive_and_invalid_requests_are_rejected() {
        assert!(!contains_high_risk_credential(
            "What is an access token used for?"
        ));
        assert!(contains_high_risk_credential("api_key=fixture-value-123"));
        assert_eq!(
            validate_request(&GovernedRetrievalRequest {
                life_id: "life".into(),
                query: " ".into(),
                memory_kind_filter: None
            })
            .unwrap_err()
            .code,
            RetrievalRuntimeErrorCode::InvalidRequest
        );
    }
}
