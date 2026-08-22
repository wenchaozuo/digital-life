//! Governed hybrid retrieval boundary. SQLite remains authoritative: vector
//! hits are hydrated and safety-checked through the repository before return.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::{
    memory::{
        candidate_service::contains_prohibited_content,
        vector_index::{canonical_index_text, canonical_memory_index_hash},
    },
    vector_store::GenerationVectorSearchHit,
};

#[cfg(test)]
use crate::{
    embedding::{EmbeddingProvider, EmbeddingPurpose, EmbeddingRequest},
    vector_store::{VectorSearchHit, VectorSearchQuery, VectorSpace, VectorStore},
};

use super::{MemoryError, MemoryKind, MemoryRecord, MemoryStatus};

#[cfg(test)]
use super::retrieval::{MemoryRetrievalRepository, MemoryRetriever, RetrievalQuery};

pub const DEFAULT_HYBRID_LIMIT: usize = 10;
pub const MAX_HYBRID_LIMIT: usize = 10;
pub const MIN_FINAL_SCORE: f64 = 0.20;
const MAX_QUERY_CHARACTERS: usize = 4000;
const CANDIDATE_POOL_MULTIPLIER: usize = 4;
// Relevance has equal fixed weight across both retrieval channels. Importance
// is deliberately capped at 0.1 so it cannot dominate relevance.
const KEYWORD_WEIGHT: f64 = 0.5;
const VECTOR_WEIGHT: f64 = 0.5;
const MAX_IMPORTANCE_BONUS: f64 = 0.1;

/// Internal keyword retrieval input used only by the governed router. The
/// caller has already passed `HybridRetrievalRequest` validation, so this
/// cannot become a second public retrieval API.
pub(crate) struct KeywordRetrievalQuery {
    pub(crate) life_id: String,
    pub(crate) query_text: String,
    pub(crate) kinds: Option<Vec<MemoryKind>>,
    pub(crate) limit: usize,
}

pub(crate) trait KeywordRetrievalRepository {
    fn retrieve_keyword_ids(
        &self,
        query: &KeywordRetrievalQuery,
    ) -> Result<Vec<String>, MemoryError>;
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RetrievalStrategy {
    KeywordOnly,
    VectorOnly,
    #[default]
    Hybrid,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HybridRetrievalRequest {
    pub life_id: String,
    pub query: String,
    pub limit: usize,
    #[serde(default)]
    pub strategy: RetrievalStrategy,
    pub min_score: Option<f32>,
    pub memory_kind_filter: Option<Vec<MemoryKind>>,
}

impl Default for HybridRetrievalRequest {
    fn default() -> Self {
        Self {
            life_id: String::new(),
            query: String::new(),
            limit: DEFAULT_HYBRID_LIMIT,
            strategy: RetrievalStrategy::Hybrid,
            min_score: None,
            memory_kind_filter: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RetrievalSource {
    Keyword,
    Vector,
    Both,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VectorRetrievalStatus {
    NotRequested,
    Available,
    VectorUnavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeywordRetrievalStatus {
    NotRequested,
    Available,
    KeywordUnavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RetrievalCandidate {
    pub memory_id: String,
    pub life_id: String,
    pub content: String,
    pub summary: Option<String>,
    pub kind: MemoryKind,
    pub importance: f64,
    pub confidence: f64,
    pub keyword_score: Option<f64>,
    pub vector_score: Option<f64>,
    pub final_score: f64,
    pub sources: RetrievalSource,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RetrievalTrace {
    pub keyword_candidate_count: usize,
    pub vector_candidate_count: usize,
    pub authoritative_candidate_count: usize,
    pub keyword_status: KeywordRetrievalStatus,
    pub vector_status: VectorRetrievalStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct HybridRetrievalResult {
    pub candidates: Vec<RetrievalCandidate>,
    pub keyword_status: KeywordRetrievalStatus,
    pub vector_status: VectorRetrievalStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace: Option<RetrievalTrace>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryRetrievalRouterErrorCode {
    InvalidRequest,
    LifeNotFound,
    KeywordUnavailable,
    VectorUnavailable,
    RepositoryUnavailable,
    InternalError,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRetrievalRouterError {
    pub code: MemoryRetrievalRouterErrorCode,
    pub message: String,
    pub recoverable: bool,
}

impl MemoryRetrievalRouterError {
    fn new(
        code: MemoryRetrievalRouterErrorCode,
        message: impl Into<String>,
        recoverable: bool,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable,
        }
    }
}

#[cfg(test)]
pub trait MemoryRetrievalRouterRepository: MemoryRetrievalRepository + Send + Sync {
    fn life_exists(&self, life_id: &str) -> Result<bool, MemoryError>;

    /// Loads authoritative, confirmed, non-sensitive records for the supplied
    /// IDs. Implementations must not infer content from the vector index.
    fn load_authoritative_candidates(
        &self,
        life_id: &str,
        memory_ids: &[String],
    ) -> Result<Vec<MemoryRecord>, MemoryError>;
}

/// Current SQLite identity evidence used by the generation-aware retrieval
/// path. It is deliberately internal and does not cross the IPC boundary.
#[derive(Clone)]
pub(crate) struct AuthoritativeRetrievalRecord {
    memory: MemoryRecord,
    revision: i64,
    content_hash: String,
}

impl AuthoritativeRetrievalRecord {
    pub(crate) fn from_current(memory: MemoryRecord, revision: i64) -> Result<Self, MemoryError> {
        if revision <= 0 {
            return Err(MemoryError::database());
        }
        let selected_text = canonical_index_text(memory.summary.as_deref(), &memory.content)
            .ok_or_else(MemoryError::database)?;
        let content_hash = canonical_memory_index_hash(
            memory.kind.as_str(),
            selected_text,
            &memory.content,
            memory.summary.as_deref(),
        );
        Ok(Self {
            memory,
            revision,
            content_hash,
        })
    }

    pub(crate) fn into_memory(self) -> MemoryRecord {
        self.memory
    }
}

/// Production retrieval repository boundary. Unlike the legacy router
/// boundary, this path returns the current revision and canonical hash along
/// with the current governed memory record.
pub(crate) trait AuthoritativeMemoryRetrievalRepository:
    KeywordRetrievalRepository + Send + Sync
{
    fn life_exists(&self, life_id: &str) -> Result<bool, MemoryError>;

    fn load_authoritative_retrieval_records(
        &self,
        life_id: &str,
        memory_ids: &[String],
    ) -> Result<Vec<AuthoritativeRetrievalRecord>, MemoryError>;
}

pub struct MemoryCandidateMerger;

impl MemoryCandidateMerger {
    pub fn merge(
        records: Vec<MemoryRecord>,
        life_id: &str,
        kinds: Option<&[MemoryKind]>,
        keyword_scores: &HashMap<String, f64>,
        vector_scores: &HashMap<String, f64>,
        limit: usize,
    ) -> Vec<RetrievalCandidate> {
        let mut candidates: Vec<_> = records
            .into_iter()
            .filter(|record| {
                record.life_id == life_id
                    && record.status == MemoryStatus::Confirmed
                    && !record.is_sensitive
                    && !contains_prohibited_content(&record.content)
                    && !record
                        .summary
                        .as_deref()
                        .is_some_and(contains_prohibited_content)
                    && canonical_index_text(record.summary.as_deref(), &record.content).is_some()
                    && kinds.is_none_or(|allowed| allowed.contains(&record.kind))
            })
            .filter_map(|record| {
                let keyword_score = keyword_scores.get(&record.id).copied();
                let vector_score = vector_scores.get(&record.id).copied();
                let sources = match (keyword_score, vector_score) {
                    (Some(_), Some(_)) => RetrievalSource::Both,
                    (Some(_), None) => RetrievalSource::Keyword,
                    (None, Some(_)) => RetrievalSource::Vector,
                    (None, None) => return None,
                };
                let importance_bonus = record.importance.clamp(0.0, 1.0) * MAX_IMPORTANCE_BONUS;
                let final_score = keyword_score.unwrap_or(0.0) * KEYWORD_WEIGHT
                    + vector_score.unwrap_or(0.0) * VECTOR_WEIGHT
                    + importance_bonus;
                Some(RetrievalCandidate {
                    memory_id: record.id,
                    life_id: record.life_id,
                    content: record.content,
                    summary: record.summary,
                    kind: record.kind,
                    importance: record.importance,
                    confidence: record.confidence,
                    keyword_score,
                    vector_score,
                    final_score,
                    sources,
                })
            })
            .collect();

        candidates.retain(|candidate| candidate.final_score >= MIN_FINAL_SCORE);
        candidates.sort_by(|left, right| {
            right
                .final_score
                .total_cmp(&left.final_score)
                .then_with(|| right.importance.total_cmp(&left.importance))
                .then_with(|| left.memory_id.cmp(&right.memory_id))
        });
        candidates.truncate(limit);
        candidates
    }

    pub(crate) fn merge_authoritative(
        records: Vec<AuthoritativeRetrievalRecord>,
        life_id: &str,
        kinds: Option<&[MemoryKind]>,
        keyword_scores: &HashMap<String, f64>,
        vector_scores: &HashMap<String, f64>,
        limit: usize,
    ) -> Vec<RetrievalCandidate> {
        Self::merge(
            records
                .into_iter()
                .map(AuthoritativeRetrievalRecord::into_memory)
                .collect(),
            life_id,
            kinds,
            keyword_scores,
            vector_scores,
            limit,
        )
    }
}

pub(crate) enum SemanticRetrievalOutcome {
    NotRequested,
    Available(Vec<GenerationVectorSearchHit>),
    Unavailable,
}

pub(crate) async fn retrieve_generation_aware<R>(
    repository: &R,
    request: HybridRetrievalRequest,
    semantic: SemanticRetrievalOutcome,
) -> Result<HybridRetrievalResult, MemoryRetrievalRouterError>
where
    R: AuthoritativeMemoryRetrievalRepository,
{
    validate_request(&request)?;
    match repository.life_exists(&request.life_id) {
        Ok(true) => {}
        Ok(false) => {
            return Err(MemoryRetrievalRouterError::new(
                MemoryRetrievalRouterErrorCode::LifeNotFound,
                "The specified life was not found.",
                true,
            ))
        }
        Err(_) => return Err(repository_unavailable()),
    }

    let pool_limit = request
        .limit
        .saturating_mul(CANDIDATE_POOL_MULTIPLIER)
        .min(100);
    let mut keyword_scores = HashMap::new();
    let mut keyword_status = KeywordRetrievalStatus::NotRequested;
    if request.strategy != RetrievalStrategy::VectorOnly {
        match repository.retrieve_keyword_ids(&KeywordRetrievalQuery {
            life_id: request.life_id.clone(),
            query_text: request.query.clone(),
            kinds: request.memory_kind_filter.clone(),
            limit: pool_limit,
        }) {
            Ok(results) => {
                keyword_status = KeywordRetrievalStatus::Available;
                for (rank, result) in results.into_iter().enumerate() {
                    let score = 1.0 / (rank + 1) as f64;
                    keyword_scores
                        .entry(result)
                        .and_modify(|current: &mut f64| *current = current.max(score))
                        .or_insert(score);
                }
            }
            Err(_) if request.strategy == RetrievalStrategy::Hybrid => {
                keyword_status = KeywordRetrievalStatus::KeywordUnavailable;
            }
            Err(_) => {
                return Err(MemoryRetrievalRouterError::new(
                    MemoryRetrievalRouterErrorCode::KeywordUnavailable,
                    "Keyword memory retrieval is unavailable.",
                    true,
                ));
            }
        }
    }

    let (mut vector_status, semantic_hits) = match (request.strategy, semantic) {
        (RetrievalStrategy::KeywordOnly, _) | (_, SemanticRetrievalOutcome::NotRequested) => {
            (VectorRetrievalStatus::NotRequested, Vec::new())
        }
        (_, SemanticRetrievalOutcome::Available(hits)) => (VectorRetrievalStatus::Available, hits),
        (_, SemanticRetrievalOutcome::Unavailable) => {
            (VectorRetrievalStatus::VectorUnavailable, Vec::new())
        }
    };

    let memory_ids: Vec<_> = keyword_scores
        .keys()
        .cloned()
        .chain(semantic_hits.iter().map(|hit| hit.memory_id().to_owned()))
        .collect::<HashSet<_>>()
        .into_iter()
        .collect();
    let records = repository
        .load_authoritative_retrieval_records(&request.life_id, &memory_ids)
        .map_err(|_| repository_unavailable())?;
    let authoritative_count = records.len();

    let vector_scores = if vector_status == VectorRetrievalStatus::Available {
        match validate_generation_hits(&records, &request.life_id, &semantic_hits) {
            Ok(scores) => scores,
            Err(()) => {
                vector_status = VectorRetrievalStatus::VectorUnavailable;
                HashMap::new()
            }
        }
    } else {
        HashMap::new()
    };
    let candidates = MemoryCandidateMerger::merge_authoritative(
        records,
        &request.life_id,
        request.memory_kind_filter.as_deref(),
        &keyword_scores,
        &vector_scores,
        request.limit,
    );
    Ok(HybridRetrievalResult {
        candidates,
        keyword_status,
        vector_status,
        trace: Some(RetrievalTrace {
            keyword_candidate_count: keyword_scores.len(),
            vector_candidate_count: vector_scores.len(),
            authoritative_candidate_count: authoritative_count,
            keyword_status,
            vector_status,
        }),
    })
}

fn validate_generation_hits(
    records: &[AuthoritativeRetrievalRecord],
    life_id: &str,
    hits: &[GenerationVectorSearchHit],
) -> Result<HashMap<String, f64>, ()> {
    let mut identities = HashMap::<String, (i64, String)>::new();
    for hit in hits {
        if !hit.score().is_finite() {
            return Err(());
        }
        let identity = (hit.memory_revision(), hit.content_hash().to_owned());
        if let Some(previous) = identities.get(hit.memory_id()) {
            if previous != &identity {
                return Err(());
            }
        } else {
            identities.insert(hit.memory_id().to_owned(), identity);
        }
    }

    let records_by_id: HashMap<_, _> = records
        .iter()
        .map(|record| (record.memory.id.as_str(), record))
        .collect();
    let mut scores = HashMap::new();
    for hit in hits {
        let Some(record) = records_by_id.get(hit.memory_id()) else {
            continue;
        };
        if record.memory.life_id != life_id
            || record.memory.status != MemoryStatus::Confirmed
            || record.memory.is_sensitive
            || contains_prohibited_content(&record.memory.content)
            || record
                .memory
                .summary
                .as_deref()
                .is_some_and(contains_prohibited_content)
            || record.revision != hit.memory_revision()
            || record.content_hash != hit.content_hash()
        {
            continue;
        }
        scores
            .entry(hit.memory_id().to_owned())
            .and_modify(|current: &mut f64| *current = current.max(f64::from(hit.score())))
            .or_insert_with(|| f64::from(hit.score()));
    }
    Ok(scores)
}

#[cfg(test)]
pub(crate) struct MemoryRetrievalRouter<'a, R, E, V>
where
    R: MemoryRetrievalRouterRepository,
    E: EmbeddingProvider + ?Sized,
    V: VectorStore + ?Sized,
{
    repository: &'a R,
    embedding_provider: &'a E,
    vector_store: &'a V,
    vector_space: VectorSpace,
}

#[cfg(test)]
impl<'a, R, E, V> MemoryRetrievalRouter<'a, R, E, V>
where
    R: MemoryRetrievalRouterRepository,
    E: EmbeddingProvider + ?Sized,
    V: VectorStore + ?Sized,
{
    pub(crate) fn new(
        repository: &'a R,
        embedding_provider: &'a E,
        vector_store: &'a V,
        vector_space: VectorSpace,
    ) -> Result<Self, MemoryRetrievalRouterError> {
        if vector_space.embedding_model.trim().is_empty()
            || vector_space.dimension == 0
            || vector_space.embedding_model != embedding_provider.model_name()
            || embedding_provider
                .vector_dimension()
                .is_some_and(|dimension| dimension != vector_space.dimension)
        {
            return Err(invalid_request(
                "Embedding provider and vector space must match.",
            ));
        }
        Ok(Self {
            repository,
            embedding_provider,
            vector_store,
            vector_space,
        })
    }

    pub(crate) async fn retrieve(
        &self,
        request: HybridRetrievalRequest,
    ) -> Result<HybridRetrievalResult, MemoryRetrievalRouterError> {
        self.retrieve_internal(request, false).await
    }

    #[cfg(test)]
    pub(crate) async fn retrieve_with_trace(
        &self,
        request: HybridRetrievalRequest,
    ) -> Result<HybridRetrievalResult, MemoryRetrievalRouterError> {
        self.retrieve_internal(request, true).await
    }

    async fn retrieve_internal(
        &self,
        request: HybridRetrievalRequest,
        include_trace: bool,
    ) -> Result<HybridRetrievalResult, MemoryRetrievalRouterError> {
        validate_request(&request)?;
        match self.repository.life_exists(&request.life_id) {
            Ok(true) => {}
            Ok(false) => {
                return Err(MemoryRetrievalRouterError::new(
                    MemoryRetrievalRouterErrorCode::LifeNotFound,
                    "The specified life was not found.",
                    true,
                ))
            }
            Err(_) => return Err(repository_unavailable()),
        }

        let pool_limit = request
            .limit
            .saturating_mul(CANDIDATE_POOL_MULTIPLIER)
            .min(100);
        let mut keyword_scores = HashMap::new();
        let mut keyword_status = KeywordRetrievalStatus::NotRequested;
        if request.strategy != RetrievalStrategy::VectorOnly {
            match MemoryRetriever::new(self.repository).retrieve(RetrievalQuery {
                life_id: request.life_id.clone(),
                query_text: request.query.clone(),
                kinds: request.memory_kind_filter.clone(),
                limit: pool_limit as u32,
            }) {
                Ok(results) => {
                    keyword_status = KeywordRetrievalStatus::Available;
                    for (rank, result) in results.into_iter().enumerate() {
                        let score = 1.0 / (rank + 1) as f64;
                        keyword_scores
                            .entry(result.memory_id)
                            .and_modify(|current: &mut f64| *current = current.max(score))
                            .or_insert(score);
                    }
                }
                Err(_) if request.strategy == RetrievalStrategy::Hybrid => {
                    keyword_status = KeywordRetrievalStatus::KeywordUnavailable;
                }
                Err(_) => {
                    return Err(MemoryRetrievalRouterError::new(
                        MemoryRetrievalRouterErrorCode::KeywordUnavailable,
                        "Keyword memory retrieval is unavailable.",
                        true,
                    ));
                }
            }
        }

        let mut vector_scores = HashMap::new();
        let mut vector_status = VectorRetrievalStatus::NotRequested;
        if request.strategy != RetrievalStrategy::KeywordOnly {
            match self.vector_hits(&request, pool_limit).await {
                Ok(hits) => {
                    vector_status = VectorRetrievalStatus::Available;
                    for hit in hits {
                        vector_scores
                            .entry(hit.memory_id)
                            .and_modify(|current: &mut f64| {
                                *current = current.max(f64::from(hit.score))
                            })
                            .or_insert_with(|| f64::from(hit.score));
                    }
                }
                Err(_) if request.strategy == RetrievalStrategy::Hybrid => {
                    vector_status = VectorRetrievalStatus::VectorUnavailable;
                }
                Err(error) => return Err(error),
            }
        }

        let memory_ids: Vec<_> = keyword_scores
            .keys()
            .chain(vector_scores.keys())
            .cloned()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let records = self
            .repository
            .load_authoritative_candidates(&request.life_id, &memory_ids)
            .map_err(|_| repository_unavailable())?;
        let authoritative_count = records.len();
        let candidates = MemoryCandidateMerger::merge(
            records,
            &request.life_id,
            request.memory_kind_filter.as_deref(),
            &keyword_scores,
            &vector_scores,
            request.limit,
        );
        let trace = include_trace.then_some(RetrievalTrace {
            keyword_candidate_count: keyword_scores.len(),
            vector_candidate_count: vector_scores.len(),
            authoritative_candidate_count: authoritative_count,
            keyword_status,
            vector_status,
        });
        Ok(HybridRetrievalResult {
            candidates,
            keyword_status,
            vector_status,
            trace,
        })
    }

    async fn vector_hits(
        &self,
        request: &HybridRetrievalRequest,
        limit: usize,
    ) -> Result<Vec<VectorSearchHit>, MemoryRetrievalRouterError> {
        let response = self
            .embedding_provider
            .embed(EmbeddingRequest {
                texts: vec![request.query.clone()],
                purpose: EmbeddingPurpose::Query,
            })
            .await
            .map_err(|_| vector_unavailable())?;
        if response.len() != 1
            || response.vectors()[0].input_index() != 0
            || response.dimension() != self.vector_space.dimension
            || response.vectors()[0].dimension() != self.vector_space.dimension
            || response.vectors()[0]
                .values()
                .iter()
                .any(|value| !value.is_finite())
        {
            return Err(vector_unavailable());
        }
        self.vector_store
            .search(VectorSearchQuery {
                life_id: request.life_id.clone(),
                space: self.vector_space.clone(),
                vector: response.vectors()[0].values().to_vec(),
                limit,
                min_score: request.min_score,
            })
            .await
            .map_err(|_| vector_unavailable())
    }
}

fn validate_request(request: &HybridRetrievalRequest) -> Result<(), MemoryRetrievalRouterError> {
    if request.life_id.trim().is_empty() {
        return Err(invalid_request("lifeId must not be empty."));
    }
    if request.query.trim().is_empty() || request.query.chars().count() > MAX_QUERY_CHARACTERS {
        return Err(invalid_request(
            "query must be non-empty and within the supported length.",
        ));
    }
    if request.limit == 0 || request.limit > MAX_HYBRID_LIMIT {
        return Err(invalid_request("limit must be between 1 and 10."));
    }
    if request
        .min_score
        .is_some_and(|score| !score.is_finite() || !(-1.0..=1.0).contains(&score))
    {
        return Err(invalid_request(
            "minScore must be finite and between -1 and 1.",
        ));
    }
    Ok(())
}

fn invalid_request(message: &str) -> MemoryRetrievalRouterError {
    MemoryRetrievalRouterError::new(
        MemoryRetrievalRouterErrorCode::InvalidRequest,
        message,
        false,
    )
}

#[cfg(test)]
fn vector_unavailable() -> MemoryRetrievalRouterError {
    MemoryRetrievalRouterError::new(
        MemoryRetrievalRouterErrorCode::VectorUnavailable,
        "Vector memory retrieval is unavailable.",
        true,
    )
}

fn repository_unavailable() -> MemoryRetrievalRouterError {
    MemoryRetrievalRouterError::new(
        MemoryRetrievalRouterErrorCode::RepositoryUnavailable,
        "Authoritative memory retrieval is unavailable.",
        true,
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    };

    use crate::{
        embedding::{
            EmbeddingBatch, EmbeddingError, EmbeddingErrorCode, EmbeddingFuture, EmbeddingModelInfo,
        },
        memory::{MemorySourceType, MemoryStatus},
        vector_store::{VectorRecord, VectorStoreError, VectorStoreErrorCode, VectorStoreFuture},
    };

    use super::*;

    struct MockRepository {
        records: Vec<MemoryRecord>,
        keyword_ids: Vec<String>,
    }

    impl MemoryRetrievalRepository for MockRepository {
        fn retrieve_confirmed(
            &self,
            _query: &RetrievalQuery,
        ) -> Result<Vec<super::super::retrieval::MemoryRetrievalResult>, MemoryError> {
            Ok(self
                .keyword_ids
                .iter()
                .filter_map(|id| self.records.iter().find(|record| &record.id == id))
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

    impl MemoryRetrievalRouterRepository for MockRepository {
        fn life_exists(&self, life_id: &str) -> Result<bool, MemoryError> {
            Ok(life_id == "life-a")
        }

        fn load_authoritative_candidates(
            &self,
            _life_id: &str,
            memory_ids: &[String],
        ) -> Result<Vec<MemoryRecord>, MemoryError> {
            Ok(self
                .records
                .iter()
                .filter(|record| memory_ids.contains(&record.id))
                .cloned()
                .collect())
        }
    }

    struct MockEmbeddingProvider {
        fail: AtomicBool,
        purposes: Mutex<Vec<EmbeddingPurpose>>,
    }

    impl MockEmbeddingProvider {
        fn new() -> Self {
            Self {
                fail: AtomicBool::new(false),
                purposes: Mutex::new(Vec::new()),
            }
        }
    }

    impl EmbeddingProvider for MockEmbeddingProvider {
        fn model_info(&self) -> EmbeddingModelInfo {
            EmbeddingModelInfo {
                model_name: "test-model".into(),
                dimension: Some(2),
            }
        }

        fn model_name(&self) -> &str {
            "test-model"
        }

        fn vector_dimension(&self) -> Option<usize> {
            Some(2)
        }

        fn embed<'a>(
            &'a self,
            request: EmbeddingRequest,
        ) -> EmbeddingFuture<'a, Result<EmbeddingBatch, EmbeddingError>> {
            Box::pin(async move {
                self.purposes.lock().unwrap().push(request.purpose);
                if self.fail.load(Ordering::SeqCst) {
                    return Err(EmbeddingError::possibly_sent(
                        EmbeddingErrorCode::NetworkError,
                    ));
                }
                EmbeddingBatch::from_test_vectors(vec![vec![1.0, 0.0]])
            })
        }
    }

    struct MockVectorStore {
        hits: Mutex<Vec<VectorSearchHit>>,
        fail: AtomicBool,
        searches: AtomicUsize,
        writes: AtomicUsize,
    }

    impl MockVectorStore {
        fn new(hits: Vec<VectorSearchHit>) -> Self {
            Self {
                hits: Mutex::new(hits),
                fail: AtomicBool::new(false),
                searches: AtomicUsize::new(0),
                writes: AtomicUsize::new(0),
            }
        }

        fn unavailable() -> VectorStoreError {
            VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "Test store unavailable.",
                true,
            )
        }
    }

    impl VectorStore for MockVectorStore {
        fn upsert<'a>(
            &'a self,
            _record: VectorRecord,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }

        fn upsert_batch<'a>(
            &'a self,
            _records: Vec<VectorRecord>,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }

        fn search<'a>(
            &'a self,
            _query: VectorSearchQuery,
        ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>> {
            self.searches.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if self.fail.load(Ordering::SeqCst) {
                    Err(Self::unavailable())
                } else {
                    Ok(self.hits.lock().unwrap().clone())
                }
            })
        }

        fn delete<'a>(
            &'a self,
            _life_id: &'a str,
            _memory_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(0) })
        }

        fn delete_from_space<'a>(
            &'a self,
            _life_id: &'a str,
            _memory_id: &'a str,
            _space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(0) })
        }

        fn delete_by_life<'a>(
            &'a self,
            _life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(0) })
        }

        fn clear_space<'a>(
            &'a self,
            _life_id: &'a str,
            _space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(0) })
        }

        fn count<'a>(
            &'a self,
            _life_id: &'a str,
            _space: Option<&'a VectorSpace>,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { Ok(0) })
        }

        fn health_check<'a>(
            &'a self,
            _life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn memory(id: &str, life_id: &str, status: MemoryStatus, sensitive: bool) -> MemoryRecord {
        MemoryRecord {
            id: id.into(),
            life_id: life_id.into(),
            kind: MemoryKind::Fact,
            status,
            content: format!("content-{id}"),
            summary: Some(format!("summary-{id}")),
            source_type: MemorySourceType::Manual,
            source_ref: None,
            source_created_at: "2026-07-13T00:00:00.000Z".into(),
            importance: 0.5,
            confidence: 0.8,
            is_sensitive: sensitive,
            created_at: "2026-07-13T00:00:00.000Z".into(),
            updated_at: "2026-07-13T00:00:00.000Z".into(),
            confirmed_at: (status == MemoryStatus::Confirmed)
                .then(|| "2026-07-13T00:00:00.000Z".into()),
        }
    }

    fn request(strategy: RetrievalStrategy) -> HybridRetrievalRequest {
        HybridRetrievalRequest {
            life_id: "life-a".into(),
            query: "coffee".into(),
            limit: 10,
            strategy,
            min_score: None,
            memory_kind_filter: None,
        }
    }

    fn space() -> VectorSpace {
        VectorSpace {
            embedding_model: "test-model".into(),
            dimension: 2,
        }
    }

    fn run(
        repository: &MockRepository,
        embedding: &MockEmbeddingProvider,
        store: &MockVectorStore,
        request: HybridRetrievalRequest,
    ) -> Result<HybridRetrievalResult, MemoryRetrievalRouterError> {
        tauri::async_runtime::block_on(
            MemoryRetrievalRouter::new(repository, embedding, store, space())
                .unwrap()
                .retrieve(request),
        )
    }

    #[test]
    fn keyword_only_uses_existing_retrieval_without_vector_work() {
        let repository = MockRepository {
            records: vec![memory("m1", "life-a", MemoryStatus::Confirmed, false)],
            keyword_ids: vec!["m1".into()],
        };
        let embedding = MockEmbeddingProvider::new();
        let store = MockVectorStore::new(Vec::new());
        let result = run(
            &repository,
            &embedding,
            &store,
            request(RetrievalStrategy::KeywordOnly),
        )
        .unwrap();
        assert_eq!(result.candidates[0].sources, RetrievalSource::Keyword);
        assert_eq!(result.vector_status, VectorRetrievalStatus::NotRequested);
        assert!(embedding.purposes.lock().unwrap().is_empty());
        assert_eq!(store.searches.load(Ordering::SeqCst), 0);
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
        assert!(result.trace.is_none());
    }

    #[test]
    fn vector_only_uses_query_embedding_and_never_writes() {
        let repository = MockRepository {
            records: vec![memory("m1", "life-a", MemoryStatus::Confirmed, false)],
            keyword_ids: Vec::new(),
        };
        let embedding = MockEmbeddingProvider::new();
        let store = MockVectorStore::new(vec![VectorSearchHit {
            memory_id: "m1".into(),
            score: 0.75,
        }]);
        let result = run(
            &repository,
            &embedding,
            &store,
            request(RetrievalStrategy::VectorOnly),
        )
        .unwrap();
        assert_eq!(result.candidates[0].sources, RetrievalSource::Vector);
        assert_eq!(result.candidates[0].vector_score, Some(0.75));
        assert_eq!(
            *embedding.purposes.lock().unwrap(),
            vec![EmbeddingPurpose::Query]
        );
        assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn hybrid_deduplicates_and_marks_both_sources() {
        let repository = MockRepository {
            records: vec![memory("m1", "life-a", MemoryStatus::Confirmed, false)],
            keyword_ids: vec!["m1".into()],
        };
        let embedding = MockEmbeddingProvider::new();
        let store = MockVectorStore::new(vec![VectorSearchHit {
            memory_id: "m1".into(),
            score: 0.8,
        }]);
        let result = run(
            &repository,
            &embedding,
            &store,
            request(RetrievalStrategy::Hybrid),
        )
        .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].sources, RetrievalSource::Both);
        assert!((result.candidates[0].final_score - 0.95).abs() < 0.000_001);
    }

    #[test]
    fn merger_score_and_sort_are_deterministic_and_importance_is_bounded() {
        let mut high_id = memory("z", "life-a", MemoryStatus::Confirmed, false);
        high_id.importance = 1.0;
        let mut low_id = memory("a", "life-a", MemoryStatus::Confirmed, false);
        low_id.importance = 1.0;
        let scores = HashMap::from([("z".into(), 1.0), ("a".into(), 1.0)]);
        let merged = MemoryCandidateMerger::merge(
            vec![high_id, low_id],
            "life-a",
            None,
            &scores,
            &HashMap::new(),
            10,
        );
        assert_eq!(merged[0].memory_id, "a");
        assert_eq!(merged[0].final_score, 0.6);
        assert!(merged[0].final_score - 0.5 <= MAX_IMPORTANCE_BONUS);
    }

    #[test]
    fn keyword_and_vector_scores_are_combined_before_stable_sorting() {
        let records = vec![
            memory("keyword", "life-a", MemoryStatus::Confirmed, false),
            memory("vector", "life-a", MemoryStatus::Confirmed, false),
            memory("both", "life-a", MemoryStatus::Confirmed, false),
        ];
        let keyword_scores = HashMap::from([("keyword".into(), 0.9), ("both".into(), 0.8)]);
        let vector_scores = HashMap::from([("vector".into(), 0.9), ("both".into(), 0.8)]);
        let merged = MemoryCandidateMerger::merge(
            records,
            "life-a",
            None,
            &keyword_scores,
            &vector_scores,
            10,
        );
        assert_eq!(
            merged
                .iter()
                .map(|candidate| candidate.memory_id.as_str())
                .collect::<Vec<_>>(),
            vec!["both", "keyword", "vector"]
        );
    }

    #[test]
    fn final_authoritative_filter_blocks_candidate_sensitive_and_other_life() {
        let repository = MockRepository {
            records: vec![
                memory("ok", "life-a", MemoryStatus::Confirmed, false),
                memory("candidate", "life-a", MemoryStatus::Candidate, false),
                memory("sensitive", "life-a", MemoryStatus::Confirmed, true),
                memory("other", "life-b", MemoryStatus::Confirmed, false),
            ],
            keyword_ids: vec![
                "ok".into(),
                "candidate".into(),
                "sensitive".into(),
                "other".into(),
            ],
        };
        let result = run(
            &repository,
            &MockEmbeddingProvider::new(),
            &MockVectorStore::new(Vec::new()),
            request(RetrievalStrategy::KeywordOnly),
        )
        .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].memory_id, "ok");
    }

    #[test]
    fn hybrid_degrades_when_embedding_or_store_is_unavailable() {
        let repository = MockRepository {
            records: vec![memory("m1", "life-a", MemoryStatus::Confirmed, false)],
            keyword_ids: vec!["m1".into()],
        };
        let embedding = MockEmbeddingProvider::new();
        embedding.fail.store(true, Ordering::SeqCst);
        let store = MockVectorStore::new(Vec::new());
        let result = run(
            &repository,
            &embedding,
            &store,
            request(RetrievalStrategy::Hybrid),
        )
        .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(
            result.vector_status,
            VectorRetrievalStatus::VectorUnavailable
        );

        embedding.fail.store(false, Ordering::SeqCst);
        store.fail.store(true, Ordering::SeqCst);
        let result = run(
            &repository,
            &embedding,
            &store,
            request(RetrievalStrategy::Hybrid),
        )
        .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(
            result.vector_status,
            VectorRetrievalStatus::VectorUnavailable
        );
    }

    #[test]
    fn vector_only_failure_is_structured() {
        let repository = MockRepository {
            records: Vec::new(),
            keyword_ids: Vec::new(),
        };
        let embedding = MockEmbeddingProvider::new();
        embedding.fail.store(true, Ordering::SeqCst);
        let error = run(
            &repository,
            &embedding,
            &MockVectorStore::new(Vec::new()),
            request(RetrievalStrategy::VectorOnly),
        )
        .unwrap_err();
        assert_eq!(
            error.code,
            MemoryRetrievalRouterErrorCode::VectorUnavailable
        );
    }

    #[test]
    fn invalid_query_limit_threshold_and_life_are_rejected() {
        let repository = MockRepository {
            records: Vec::new(),
            keyword_ids: Vec::new(),
        };
        let embedding = MockEmbeddingProvider::new();
        let store = MockVectorStore::new(Vec::new());
        let mut invalid = request(RetrievalStrategy::Hybrid);
        invalid.query = " ".into();
        assert_eq!(
            run(&repository, &embedding, &store, invalid)
                .unwrap_err()
                .code,
            MemoryRetrievalRouterErrorCode::InvalidRequest
        );
        let mut invalid = request(RetrievalStrategy::Hybrid);
        invalid.limit = MAX_HYBRID_LIMIT + 1;
        assert_eq!(
            run(&repository, &embedding, &store, invalid)
                .unwrap_err()
                .code,
            MemoryRetrievalRouterErrorCode::InvalidRequest
        );
        let mut invalid = request(RetrievalStrategy::Hybrid);
        invalid.min_score = Some(f32::NAN);
        assert_eq!(
            run(&repository, &embedding, &store, invalid)
                .unwrap_err()
                .code,
            MemoryRetrievalRouterErrorCode::InvalidRequest
        );
        let mut invalid = request(RetrievalStrategy::Hybrid);
        invalid.life_id = "missing".into();
        assert_eq!(
            run(&repository, &embedding, &store, invalid)
                .unwrap_err()
                .code,
            MemoryRetrievalRouterErrorCode::LifeNotFound
        );
    }

    #[test]
    fn kind_filter_and_result_limit_are_enforced_after_hydration() {
        let mut fact = memory("fact", "life-a", MemoryStatus::Confirmed, false);
        fact.kind = MemoryKind::Fact;
        let mut goal = memory("goal", "life-a", MemoryStatus::Confirmed, false);
        goal.kind = MemoryKind::Goal;
        let repository = MockRepository {
            records: vec![fact, goal],
            keyword_ids: vec!["fact".into(), "goal".into()],
        };
        let mut query = request(RetrievalStrategy::KeywordOnly);
        query.limit = 1;
        query.memory_kind_filter = Some(vec![MemoryKind::Goal]);
        let result = run(
            &repository,
            &MockEmbeddingProvider::new(),
            &MockVectorStore::new(Vec::new()),
            query,
        )
        .unwrap();
        assert_eq!(result.candidates.len(), 1);
        assert_eq!(result.candidates[0].kind, MemoryKind::Goal);
    }

    #[test]
    fn trace_is_only_returned_by_explicit_debug_path() {
        let repository = MockRepository {
            records: Vec::new(),
            keyword_ids: Vec::new(),
        };
        let embedding = MockEmbeddingProvider::new();
        let store = MockVectorStore::new(Vec::new());
        let router = MemoryRetrievalRouter::new(&repository, &embedding, &store, space()).unwrap();
        let result = tauri::async_runtime::block_on(
            router.retrieve_with_trace(request(RetrievalStrategy::KeywordOnly)),
        )
        .unwrap();
        assert!(result.trace.is_some());
    }
}
