//! Production assembly for governed, generation-aware hybrid memory retrieval.
//!
//! Semantic retrieval is supplied only by the sealed D10-B2 capability. This
//! runtime owns query governance, keyword/semantic degradation, and the final
//! governed result boundary; it does not own a provider, vector space, or
//! vector store.

use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};

use crate::{
    memory::{
        active_generation_retrieval::ActiveGenerationRetrievalErrorCode,
        retrieval_router::{
            retrieve_generation_aware, AuthoritativeMemoryRetrievalRepository,
            HybridRetrievalRequest, KeywordRetrievalStatus, MemoryRetrievalRouterErrorCode,
            RetrievalCandidate, RetrievalStrategy, SemanticRetrievalOutcome, VectorRetrievalStatus,
            DEFAULT_HYBRID_LIMIT,
        },
        MemoryKind,
    },
    model::{profile::ModelProfileRepository, runtime::ModelRuntimeService},
    secrets::SecretStore,
    storage::StorageService,
    vector_store::{GenerationVectorSearchHit, LanceDbVectorStoreRegistry},
};

pub const MAX_RETRIEVAL_QUERY_CHARACTERS: usize = 4_000;
pub const VECTOR_MIN_SCORE: f32 = 0.20;

pub(crate) type SemanticRetrievalFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<Vec<GenerationVectorSearchHit>, ActiveGenerationRetrievalErrorCode>,
            > + Send
            + 'a,
    >,
>;

pub(crate) trait SemanticRetrievalProvider {
    fn semantic_search<'a>(
        &'a self,
        life_id: &'a str,
        query: &'a str,
        limit: usize,
        min_score: Option<f32>,
    ) -> SemanticRetrievalFuture<'a>;
}

/// Canonical production adapter from the runtime services to D10-B2.
pub(crate) struct GenerationAwareSemanticRetrieval<'a, P, S>
where
    P: ModelProfileRepository + Sync,
    S: SecretStore + ?Sized,
{
    storage: &'a StorageService,
    runtime: &'a ModelRuntimeService<'a, P, S>,
    registry: &'a LanceDbVectorStoreRegistry,
}

impl<'a, P, S> GenerationAwareSemanticRetrieval<'a, P, S>
where
    P: ModelProfileRepository + Sync,
    S: SecretStore + ?Sized,
{
    pub(crate) fn new(
        storage: &'a StorageService,
        runtime: &'a ModelRuntimeService<'a, P, S>,
        registry: &'a LanceDbVectorStoreRegistry,
    ) -> Self {
        Self {
            storage,
            runtime,
            registry,
        }
    }
}

impl<P, S> SemanticRetrievalProvider for GenerationAwareSemanticRetrieval<'_, P, S>
where
    P: ModelProfileRepository + Sync,
    S: SecretStore + ?Sized,
{
    fn semantic_search<'a>(
        &'a self,
        life_id: &'a str,
        query: &'a str,
        limit: usize,
        min_score: Option<f32>,
    ) -> SemanticRetrievalFuture<'a> {
        let life_id = life_id.to_owned();
        let query = query.to_owned();
        Box::pin(async move {
            let execution =
                super::active_generation_retrieval::resolve_active_generation_retrieval_execution(
                    self.storage,
                    self.runtime,
                    self.registry,
                )
                .await
                .map_err(|error| error.code())?;
            execution
                .semantic_search(&life_id, &query, limit, min_score)
                .await
                .map_err(|error| error.code())
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

pub(crate) struct MemoryRetrievalRuntimeService<'a, R, S>
where
    R: AuthoritativeMemoryRetrievalRepository,
    S: SemanticRetrievalProvider + ?Sized,
{
    memories: &'a R,
    semantic: &'a S,
}

impl<'a, R, S> MemoryRetrievalRuntimeService<'a, R, S>
where
    R: AuthoritativeMemoryRetrievalRepository,
    S: SemanticRetrievalProvider + ?Sized,
{
    pub(crate) fn new(memories: &'a R, semantic: &'a S) -> Self {
        Self { memories, semantic }
    }

    pub async fn retrieve(
        &self,
        request: GovernedRetrievalRequest,
    ) -> Result<GovernedRetrievalResult, RetrievalRuntimeError> {
        validate_request(&request)?;
        if contains_high_risk_credential(&request.query) {
            return self
                .retrieve_with_semantic(
                    request,
                    SemanticRetrievalOutcome::NotRequested,
                    vec![RetrievalDegradationCode::VectorSkippedSensitiveQuery],
                )
                .await;
        }

        let semantic_limit = DEFAULT_HYBRID_LIMIT.saturating_mul(4).min(100);
        let (semantic, degradations) = match self
            .semantic
            .semantic_search(
                &request.life_id,
                &request.query,
                semantic_limit,
                Some(VECTOR_MIN_SCORE),
            )
            .await
        {
            Ok(hits) => (SemanticRetrievalOutcome::Available(hits), Vec::new()),
            Err(code) => (
                SemanticRetrievalOutcome::Unavailable,
                vec![map_generation_error(code)],
            ),
        };
        self.retrieve_with_semantic(request, semantic, degradations)
            .await
    }

    async fn retrieve_with_semantic(
        &self,
        request: GovernedRetrievalRequest,
        semantic: SemanticRetrievalOutcome,
        degradations: Vec<RetrievalDegradationCode>,
    ) -> Result<GovernedRetrievalResult, RetrievalRuntimeError> {
        let strategy = if matches!(semantic, SemanticRetrievalOutcome::NotRequested) {
            RetrievalStrategy::KeywordOnly
        } else {
            RetrievalStrategy::Hybrid
        };
        let result = retrieve_generation_aware(
            self.memories,
            HybridRetrievalRequest {
                life_id: request.life_id,
                query: request.query,
                limit: DEFAULT_HYBRID_LIMIT,
                strategy,
                min_score: Some(VECTOR_MIN_SCORE),
                memory_kind_filter: request.memory_kind_filter,
            },
            semantic,
        )
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

fn map_generation_error(code: ActiveGenerationRetrievalErrorCode) -> RetrievalDegradationCode {
    match code {
        ActiveGenerationRetrievalErrorCode::NoActiveGeneration => {
            RetrievalDegradationCode::VectorIndexUnavailable
        }
        ActiveGenerationRetrievalErrorCode::GenerationProviderUnavailable
        | ActiveGenerationRetrievalErrorCode::EmbeddingFailed => {
            RetrievalDegradationCode::EmbeddingProviderUnavailable
        }
        ActiveGenerationRetrievalErrorCode::EmbeddingDimensionMismatch => {
            RetrievalDegradationCode::EmbeddingDimensionMismatch
        }
        ActiveGenerationRetrievalErrorCode::GenerationStoreUnavailable
        | ActiveGenerationRetrievalErrorCode::VectorSearchFailed => {
            RetrievalDegradationCode::VectorStoreUnavailable
        }
        ActiveGenerationRetrievalErrorCode::GenerationStale
        | ActiveGenerationRetrievalErrorCode::GenerationProviderMismatch
        | ActiveGenerationRetrievalErrorCode::InvalidQuery => {
            RetrievalDegradationCode::VectorUnavailable
        }
    }
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
        Arc, Mutex,
    };

    use crate::{
        memory::{
            retrieval::{MemoryRetrievalRepository, MemoryRetrievalResult, RetrievalQuery},
            retrieval_router::{
                AuthoritativeMemoryRetrievalRepository, AuthoritativeRetrievalRecord,
                RetrievalSource,
            },
            vector_index::{canonical_index_text, canonical_memory_index_hash},
            MemoryError, MemoryRecord, MemorySourceType, MemoryStatus,
        },
        vector_store::GenerationVectorSearchHit,
    };

    use super::*;

    struct Repository {
        records: Vec<MemoryRecord>,
        authoritative: Vec<AuthoritativeRetrievalRecord>,
        keyword_fails: bool,
        hydrate_fails: bool,
    }

    impl MemoryRetrievalRepository for Repository {
        fn retrieve_confirmed(
            &self,
            _query: &RetrievalQuery,
        ) -> Result<Vec<MemoryRetrievalResult>, MemoryError> {
            if self.keyword_fails {
                return Err(MemoryError::database());
            }
            Ok(self
                .records
                .iter()
                .filter(|record| record.status == MemoryStatus::Confirmed && !record.is_sensitive)
                .map(|record| MemoryRetrievalResult {
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

    impl AuthoritativeMemoryRetrievalRepository for Repository {
        fn life_exists(&self, life_id: &str) -> Result<bool, MemoryError> {
            Ok(life_id == "life-a")
        }

        fn load_authoritative_retrieval_records(
            &self,
            _life_id: &str,
            _memory_ids: &[String],
        ) -> Result<Vec<AuthoritativeRetrievalRecord>, MemoryError> {
            if self.hydrate_fails {
                return Err(MemoryError::database());
            }
            Ok(self.authoritative.clone())
        }
    }

    struct Semantic {
        calls: Arc<AtomicUsize>,
        outcome: Mutex<Result<Vec<GenerationVectorSearchHit>, ActiveGenerationRetrievalErrorCode>>,
    }

    impl SemanticRetrievalProvider for Semantic {
        fn semantic_search<'a>(
            &'a self,
            _life_id: &'a str,
            _query: &'a str,
            _limit: usize,
            _min_score: Option<f32>,
        ) -> SemanticRetrievalFuture<'a> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let outcome = self.outcome.lock().unwrap().clone();
            Box::pin(async move { outcome })
        }
    }

    fn record(id: &str, life_id: &str, content: &str, summary: Option<&str>) -> MemoryRecord {
        MemoryRecord {
            id: id.into(),
            life_id: life_id.into(),
            kind: MemoryKind::Fact,
            status: MemoryStatus::Confirmed,
            content: content.into(),
            summary: summary.map(str::to_owned),
            source_type: MemorySourceType::Manual,
            source_ref: None,
            source_created_at: "2026-07-13T00:00:00.000Z".into(),
            importance: 0.8,
            confidence: 0.9,
            is_sensitive: false,
            created_at: "2026-07-13T00:00:00.000Z".into(),
            updated_at: "2026-07-13T00:00:00.000Z".into(),
            confirmed_at: Some("2026-07-13T00:00:00.000Z".into()),
        }
    }

    fn authoritative(memory: MemoryRecord, revision: i64) -> AuthoritativeRetrievalRecord {
        AuthoritativeRetrievalRecord::from_current(memory, revision).unwrap()
    }

    fn current_hash(memory: &MemoryRecord) -> String {
        let selected = canonical_index_text(memory.summary.as_deref(), &memory.content).unwrap();
        canonical_memory_index_hash(
            memory.kind.as_str(),
            selected,
            &memory.content,
            memory.summary.as_deref(),
        )
    }

    fn hit(memory: &MemoryRecord, revision: i64, score: f32) -> GenerationVectorSearchHit {
        GenerationVectorSearchHit::from_test_parts(
            memory.id.clone(),
            revision,
            current_hash(memory),
            score,
        )
    }

    fn semantic(
        calls: &Arc<AtomicUsize>,
        outcome: Result<Vec<GenerationVectorSearchHit>, ActiveGenerationRetrievalErrorCode>,
    ) -> Semantic {
        Semantic {
            calls: Arc::clone(calls),
            outcome: Mutex::new(outcome),
        }
    }

    fn request(query: &str) -> GovernedRetrievalRequest {
        GovernedRetrievalRequest {
            life_id: "life-a".into(),
            query: query.into(),
            memory_kind_filter: None,
        }
    }

    fn service<'a>(
        repository: &'a Repository,
        semantic: &'a Semantic,
    ) -> MemoryRetrievalRuntimeService<'a, Repository, Semantic> {
        MemoryRetrievalRuntimeService::new(repository, semantic)
    }

    #[test]
    fn sensitive_query_skips_semantic_and_preserves_keyword_retrieval() {
        let memory = record("m1", "life-a", "credential discussion", None);
        let repository = Repository {
            records: vec![memory.clone()],
            authoritative: vec![authoritative(memory, 1)],
            keyword_fails: false,
            hydrate_fails: false,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let semantic = semantic(
            &calls,
            Ok(vec![GenerationVectorSearchHit::from_test_parts(
                "m1", 1, "unused", 0.9,
            )]),
        );
        let result = tauri::async_runtime::block_on(
            service(&repository, &semantic)
                .retrieve(request("Authorization: Bearer fixture-value-123")),
        )
        .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(result.availability, RetrievalAvailability::KeywordOnly);
        assert_eq!(result.candidates[0].sources, RetrievalSource::Keyword);
        assert!(result
            .degradation_codes
            .contains(&RetrievalDegradationCode::VectorSkippedSensitiveQuery));
    }

    #[test]
    fn hybrid_happy_path_uses_current_identity_and_sqlite_content() {
        let memory = record("m1", "life-a", "SQLite authoritative body", Some("summary"));
        let repository = Repository {
            records: vec![memory.clone()],
            authoritative: vec![authoritative(memory.clone(), 4)],
            keyword_fails: false,
            hydrate_fails: false,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let semantic = semantic(&calls, Ok(vec![hit(&memory, 4, 0.8)]));
        let result = tauri::async_runtime::block_on(
            service(&repository, &semantic).retrieve(request("authoritative")),
        )
        .unwrap();
        assert_eq!(result.availability, RetrievalAvailability::Hybrid);
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].sources, RetrievalSource::Both);
        assert_eq!(result.candidates[0].keyword_score, Some(1.0));
        assert_eq!(result.candidates[0].vector_score, Some(f64::from(0.8_f32)));
        assert_eq!(result.candidates[0].content, "SQLite authoritative body");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn current_vector_hit_can_supply_vector_only_candidate() {
        let memory = record("m1", "life-a", "semantic-only body", None);
        let repository = Repository {
            records: Vec::new(),
            authoritative: vec![authoritative(memory.clone(), 1)],
            keyword_fails: false,
            hydrate_fails: false,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let semantic = semantic(&calls, Ok(vec![hit(&memory, 1, 0.9)]));
        let result = tauri::async_runtime::block_on(
            service(&repository, &semantic).retrieve(request("no lexical match")),
        )
        .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].sources, RetrievalSource::Vector);
        assert_eq!(result.candidates[0].keyword_score, None);
        assert_eq!(result.candidates[0].vector_score, Some(f64::from(0.9_f32)));
    }

    #[test]
    fn stale_revision_drops_only_vector_score_and_keeps_keyword_candidate() {
        let memory = record("m1", "life-a", "current body", None);
        let repository = Repository {
            records: vec![memory.clone()],
            authoritative: vec![authoritative(memory.clone(), 5)],
            keyword_fails: false,
            hydrate_fails: false,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let semantic = semantic(&calls, Ok(vec![hit(&memory, 4, 0.99)]));
        let result = tauri::async_runtime::block_on(
            service(&repository, &semantic).retrieve(request("current body")),
        )
        .unwrap();
        assert_eq!(result.candidates[0].sources, RetrievalSource::Keyword);
        assert_eq!(result.candidates[0].vector_score, None);
    }

    #[test]
    fn stale_hash_drops_vector_score_even_when_revision_matches() {
        let memory = record("m1", "life-a", "current body", None);
        let repository = Repository {
            records: vec![memory.clone()],
            authoritative: vec![authoritative(memory.clone(), 5)],
            keyword_fails: false,
            hydrate_fails: false,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let semantic = semantic(
            &calls,
            Ok(vec![GenerationVectorSearchHit::from_test_parts(
                "m1",
                5,
                "stale-hash",
                0.99,
            )]),
        );
        let result = tauri::async_runtime::block_on(
            service(&repository, &semantic).retrieve(request("current body")),
        )
        .unwrap();
        assert_eq!(result.candidates[0].sources, RetrievalSource::Keyword);
        assert_eq!(result.candidates[0].vector_score, None);
    }

    #[test]
    fn deleted_sensitive_and_cross_life_hits_do_not_become_candidates() {
        let sensitive = MemoryRecord {
            is_sensitive: true,
            ..record("sensitive", "life-a", "sensitive body", None)
        };
        let other_life = record("other", "life-b", "other body", None);
        let repository = Repository {
            records: Vec::new(),
            authoritative: vec![
                authoritative(sensitive.clone(), 1),
                authoritative(other_life.clone(), 1),
            ],
            keyword_fails: false,
            hydrate_fails: false,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let semantic = semantic(
            &calls,
            Ok(vec![
                hit(&sensitive, 1, 0.9),
                hit(&other_life, 1, 0.9),
                GenerationVectorSearchHit::from_test_parts("deleted", 1, "gone", 0.9),
            ]),
        );
        let result = tauri::async_runtime::block_on(
            service(&repository, &semantic).retrieve(request("no keyword")),
        )
        .unwrap();
        assert!(result.candidates.is_empty());
    }

    #[test]
    fn hard_secret_content_and_summary_are_blocked_after_hydration() {
        for (content, summary) in [
            ("api_key=fixture-secret-123", None),
            ("ordinary content", Some("password=fixture-secret-123")),
        ] {
            let memory = record("secret", "life-a", content, summary);
            let repository = Repository {
                records: vec![memory.clone()],
                authoritative: vec![authoritative(memory.clone(), 1)],
                keyword_fails: false,
                hydrate_fails: false,
            };
            let calls = Arc::new(AtomicUsize::new(0));
            let semantic = semantic(&calls, Ok(vec![hit(&memory, 1, 0.9)]));
            let result = tauri::async_runtime::block_on(
                service(&repository, &semantic).retrieve(request("secret")),
            )
            .unwrap();
            assert!(result.candidates.is_empty());
        }
    }

    #[test]
    fn conflicting_duplicate_identity_disables_semantic_channel() {
        let memory = record("m1", "life-a", "current", None);
        let repository = Repository {
            records: vec![memory.clone()],
            authoritative: vec![authoritative(memory.clone(), 2)],
            keyword_fails: false,
            hydrate_fails: false,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let semantic = semantic(
            &calls,
            Ok(vec![
                hit(&memory, 2, 0.8),
                GenerationVectorSearchHit::from_test_parts("m1", 3, "conflict", 0.99),
            ]),
        );
        let result = tauri::async_runtime::block_on(
            service(&repository, &semantic).retrieve(request("current")),
        )
        .unwrap();
        assert_eq!(result.candidates[0].sources, RetrievalSource::Keyword);
        assert!(result
            .degradation_codes
            .contains(&RetrievalDegradationCode::VectorUnavailable));
    }

    #[test]
    fn generation_failures_degrade_to_keyword_without_requery() {
        let memory = record("m1", "life-a", "keyword body", None);
        for (error, expected) in [
            (
                ActiveGenerationRetrievalErrorCode::NoActiveGeneration,
                RetrievalDegradationCode::VectorIndexUnavailable,
            ),
            (
                ActiveGenerationRetrievalErrorCode::GenerationStoreUnavailable,
                RetrievalDegradationCode::VectorStoreUnavailable,
            ),
            (
                ActiveGenerationRetrievalErrorCode::GenerationStale,
                RetrievalDegradationCode::VectorUnavailable,
            ),
        ] {
            let repository = Repository {
                records: vec![memory.clone()],
                authoritative: vec![authoritative(memory.clone(), 1)],
                keyword_fails: false,
                hydrate_fails: false,
            };
            let calls = Arc::new(AtomicUsize::new(0));
            let semantic = semantic(&calls, Err(error));
            let result = tauri::async_runtime::block_on(
                service(&repository, &semantic).retrieve(request("keyword body")),
            )
            .unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            assert_eq!(result.availability, RetrievalAvailability::KeywordOnly);
            assert!(result.degradation_codes.contains(&expected));
            assert_eq!(result.candidates[0].vector_score, None);
        }
    }

    #[test]
    fn authoritative_read_failure_never_returns_unverified_vector_content() {
        let memory = record("m1", "life-a", "not trusted from lance", None);
        let repository = Repository {
            records: vec![memory.clone()],
            authoritative: Vec::new(),
            keyword_fails: true,
            hydrate_fails: true,
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let semantic = semantic(&calls, Ok(vec![hit(&memory, 1, 0.99)]));
        let result = tauri::async_runtime::block_on(
            service(&repository, &semantic).retrieve(request("not keyword")),
        )
        .unwrap();
        assert!(result.candidates.is_empty());
        assert!(result
            .degradation_codes
            .contains(&RetrievalDegradationCode::AuthoritativeReadUnavailable));
    }
}
