//! Governed orchestration from authoritative SQLite memory records to a
//! rebuildable vector index. This module has no Tauri command and creates no
//! concrete embedding provider or vector store.

use std::{
    collections::HashSet,
    fmt::Write,
    sync::{Mutex, MutexGuard},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    embedding::{
        EmbeddingError, EmbeddingErrorCode, EmbeddingProvider, EmbeddingPurpose, EmbeddingRequest,
        EmbeddingResponse,
    },
    vector_store::{VectorRecord, VectorSpace, VectorStore},
};

use super::{MemoryError, MemoryRecord, MemoryStatus};

pub const MEMORY_INDEX_FORMAT_VERSION: &str = "memory-index-v1";
const REBUILD_PAGE_SIZE: usize = 128;

pub trait MemoryVectorIndexRepository: Send + Sync {
    fn get_authoritative(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<MemoryRecord, MemoryError>;

    fn list_page(
        &self,
        life_id: &str,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<MemoryRecord>, MemoryError>;
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryIndexRequest {
    pub life_id: String,
    pub memory_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRebuildRequest {
    pub life_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryIndexStatus {
    Indexed,
    Removed,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryIndexResult {
    pub memory_id: String,
    pub status: MemoryIndexStatus,
    pub embedding_model: String,
    pub dimension: usize,
    pub content_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRebuildReport {
    pub scanned_count: usize,
    pub eligible_count: usize,
    pub indexed_count: usize,
    pub skipped_candidate_count: usize,
    pub skipped_sensitive_count: usize,
    pub failed_count: usize,
    pub embedding_model: String,
    pub dimension: usize,
    pub vector_space: VectorSpace,
    pub completed: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryIndexErrorCode {
    InvalidRequest,
    MemoryNotFound,
    LifeMismatch,
    MemoryNotConfirmed,
    SensitiveMemoryNotIndexable,
    EmptyIndexText,
    RepositoryUnavailable,
    EmbeddingFailed,
    AuthenticationFailed,
    RateLimited,
    NetworkUnavailable,
    RequestTimeout,
    InvalidProviderResponse,
    DimensionMismatch,
    VectorStoreFailed,
    PartialIndexFailure,
    IndexOperationInProgress,
    RebuildCancelled,
    InternalError,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryIndexError {
    pub code: MemoryIndexErrorCode,
    pub message: String,
    pub recoverable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryRebuildPhase {
    Scanning,
    Embedding,
    Writing,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRebuildProgress {
    pub phase: MemoryRebuildPhase,
    pub scanned_count: usize,
    pub eligible_count: usize,
    pub embedded_count: usize,
    pub indexed_count: usize,
    pub skipped_candidate_count: usize,
    pub skipped_sensitive_count: usize,
    pub current_batch: usize,
    pub total_batches: usize,
}

/// Runtime-owned cooperative cancellation and progress boundary. Implementors
/// must never retain memory text or vectors from a callback.
pub trait MemoryRebuildObserver: Send + Sync {
    fn is_cancelled(&self) -> bool;
    fn on_model_resolved(&self, _embedding_model: &str, _dimension: usize) {}
    fn on_progress(&self, progress: MemoryRebuildProgress);
}

struct NoopRebuildObserver;

impl MemoryRebuildObserver for NoopRebuildObserver {
    fn is_cancelled(&self) -> bool {
        false
    }

    fn on_progress(&self, _progress: MemoryRebuildProgress) {}
}

impl MemoryIndexError {
    fn new(code: MemoryIndexErrorCode, message: impl Into<String>, recoverable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct IndexOperationKey {
    life_id: String,
    space: VectorSpace,
}

struct IndexOperationPermit<'a> {
    operations: &'a Mutex<HashSet<IndexOperationKey>>,
    key: IndexOperationKey,
}

impl Drop for IndexOperationPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut operations) = self.operations.lock() {
            operations.remove(&self.key);
        }
    }
}

struct IndexPayload {
    memory_id: String,
    life_id: String,
    text: String,
    content_hash: String,
}

pub struct MemoryVectorIndexService<'a, R, E, V>
where
    R: MemoryVectorIndexRepository + ?Sized,
    E: EmbeddingProvider + ?Sized,
    V: VectorStore + ?Sized,
{
    repository: &'a R,
    embedding_provider: &'a E,
    vector_store: &'a V,
    vector_space: VectorSpace,
    active_operations: Mutex<HashSet<IndexOperationKey>>,
}

impl<'a, R, E, V> MemoryVectorIndexService<'a, R, E, V>
where
    R: MemoryVectorIndexRepository + ?Sized,
    E: EmbeddingProvider + ?Sized,
    V: VectorStore + ?Sized,
{
    pub fn new(
        repository: &'a R,
        embedding_provider: &'a E,
        vector_store: &'a V,
        vector_space: VectorSpace,
    ) -> Result<Self, MemoryIndexError> {
        vector_space
            .validate()
            .map_err(|_| invalid_configuration())?;
        if vector_space.embedding_model != embedding_provider.model_name()
            || embedding_provider
                .vector_dimension()
                .is_some_and(|dimension| dimension != vector_space.dimension)
            || embedding_provider.max_batch_size() == 0
        {
            return Err(invalid_configuration());
        }
        Ok(Self {
            repository,
            embedding_provider,
            vector_store,
            vector_space,
            active_operations: Mutex::new(HashSet::new()),
        })
    }

    pub fn vector_space(&self) -> &VectorSpace {
        &self.vector_space
    }

    pub async fn index_memory(
        &self,
        request: MemoryIndexRequest,
    ) -> Result<MemoryIndexResult, MemoryIndexError> {
        validate_ids(&request.life_id, &request.memory_id)?;
        let _permit = self.acquire_operation(&request.life_id, &self.vector_space)?;
        let memory = self
            .repository
            .get_authoritative(&request.life_id, &request.memory_id)
            .map_err(map_repository_error)?;
        validate_eligible_memory(&memory, &request.life_id)?;
        let text = selected_index_text(&memory)?.to_owned();
        let content_hash = content_hash(&memory, &text);
        let response = self
            .embedding_provider
            .embed(EmbeddingRequest {
                texts: vec![text],
                purpose: EmbeddingPurpose::Document,
            })
            .await
            .map_err(map_embedding_error)?;
        validate_embedding_response(&response, 1, &self.vector_space)?;
        let vector = response
            .vectors
            .into_iter()
            .next()
            .ok_or_else(embedding_failed)?;
        self.vector_store
            .upsert(VectorRecord {
                life_id: memory.life_id,
                memory_id: memory.id.clone(),
                embedding_model: self.vector_space.embedding_model.clone(),
                dimension: self.vector_space.dimension,
                vector: vector.values,
                content_hash: content_hash.clone(),
            })
            .await
            .map_err(|_| vector_store_failed())?;
        Ok(MemoryIndexResult {
            memory_id: memory.id,
            status: MemoryIndexStatus::Indexed,
            embedding_model: self.vector_space.embedding_model.clone(),
            dimension: self.vector_space.dimension,
            content_hash: Some(content_hash),
        })
    }

    pub async fn remove_memory_index(
        &self,
        life_id: &str,
        memory_id: &str,
        vector_space: &VectorSpace,
    ) -> Result<MemoryIndexResult, MemoryIndexError> {
        validate_ids(life_id, memory_id)?;
        vector_space
            .validate()
            .map_err(|_| invalid_configuration())?;
        let _permit = self.acquire_operation(life_id, vector_space)?;
        self.vector_store
            .delete_from_space(life_id, memory_id, vector_space)
            .await
            .map_err(|_| vector_store_failed())?;
        Ok(MemoryIndexResult {
            memory_id: memory_id.to_owned(),
            status: MemoryIndexStatus::Removed,
            embedding_model: vector_space.embedding_model.clone(),
            dimension: vector_space.dimension,
            content_hash: None,
        })
    }

    pub async fn rebuild_life_index(
        &self,
        request: MemoryRebuildRequest,
    ) -> Result<MemoryRebuildReport, MemoryIndexError> {
        self.rebuild_life_index_observed(request, &NoopRebuildObserver)
            .await
    }

    pub async fn rebuild_life_index_observed(
        &self,
        request: MemoryRebuildRequest,
        observer: &dyn MemoryRebuildObserver,
    ) -> Result<MemoryRebuildReport, MemoryIndexError> {
        validate_life_id(&request.life_id)?;
        let _permit = self.acquire_operation(&request.life_id, &self.vector_space)?;
        let mut report = MemoryRebuildReport {
            scanned_count: 0,
            eligible_count: 0,
            indexed_count: 0,
            skipped_candidate_count: 0,
            skipped_sensitive_count: 0,
            failed_count: 0,
            embedding_model: self.vector_space.embedding_model.clone(),
            dimension: self.vector_space.dimension,
            vector_space: self.vector_space.clone(),
            completed: false,
        };
        let mut payloads = Vec::new();
        let mut offset = 0usize;
        loop {
            ensure_not_cancelled(observer)?;
            let page = self
                .repository
                .list_page(&request.life_id, offset, REBUILD_PAGE_SIZE)
                .map_err(map_repository_error)?;
            if page.is_empty() {
                break;
            }
            let page_len = page.len();
            report.scanned_count = report.scanned_count.saturating_add(page_len);
            for memory in page {
                if memory.life_id != request.life_id {
                    return Err(MemoryIndexError::new(
                        MemoryIndexErrorCode::LifeMismatch,
                        "A repository page contained memory from another life.",
                        false,
                    ));
                }
                if memory.status == MemoryStatus::Candidate {
                    report.skipped_candidate_count += 1;
                    continue;
                }
                if memory.is_sensitive {
                    report.skipped_sensitive_count += 1;
                    continue;
                }
                let text = selected_index_text(&memory)?.to_owned();
                let content_hash = content_hash(&memory, &text);
                payloads.push(IndexPayload {
                    memory_id: memory.id,
                    life_id: memory.life_id,
                    content_hash,
                    text,
                });
            }
            observer.on_progress(progress_from_report(
                MemoryRebuildPhase::Scanning,
                &report,
                0,
                0,
                0,
            ));
            offset = offset.saturating_add(page_len);
            if page_len < REBUILD_PAGE_SIZE {
                break;
            }
        }
        report.eligible_count = payloads.len();

        let batch_size = self.embedding_provider.max_batch_size();
        let total_batches = payloads.len().div_ceil(batch_size);
        let mut records = Vec::with_capacity(payloads.len());
        for (batch_index, batch) in payloads.chunks(batch_size).enumerate() {
            ensure_not_cancelled(observer)?;
            observer.on_progress(progress_from_report(
                MemoryRebuildPhase::Embedding,
                &report,
                records.len(),
                batch_index + 1,
                total_batches,
            ));
            let response = self
                .embedding_provider
                .embed(EmbeddingRequest {
                    texts: batch.iter().map(|payload| payload.text.clone()).collect(),
                    purpose: EmbeddingPurpose::Document,
                })
                .await
                .map_err(map_embedding_error)?;
            validate_embedding_response(&response, batch.len(), &self.vector_space)?;
            for (payload, vector) in batch.iter().zip(response.vectors) {
                records.push(VectorRecord {
                    life_id: payload.life_id.clone(),
                    memory_id: payload.memory_id.clone(),
                    embedding_model: self.vector_space.embedding_model.clone(),
                    dimension: self.vector_space.dimension,
                    vector: vector.values,
                    content_hash: payload.content_hash.clone(),
                });
            }
            observer.on_progress(progress_from_report(
                MemoryRebuildPhase::Embedding,
                &report,
                records.len(),
                batch_index + 1,
                total_batches,
            ));
        }

        ensure_not_cancelled(observer)?;
        observer.on_progress(progress_from_report(
            MemoryRebuildPhase::Writing,
            &report,
            records.len(),
            total_batches,
            total_batches,
        ));
        self.vector_store
            .clear_space(&request.life_id, &self.vector_space)
            .await
            .map_err(|_| partial_index_failure())?;
        ensure_not_cancelled(observer)?;
        if !records.is_empty() {
            self.vector_store
                .upsert_batch(records)
                .await
                .map_err(|_| partial_index_failure())?;
        }
        report.indexed_count = payloads.len();
        report.completed = true;
        observer.on_progress(progress_from_report(
            MemoryRebuildPhase::Writing,
            &report,
            payloads.len(),
            total_batches,
            total_batches,
        ));
        Ok(report)
    }

    fn acquire_operation<'service>(
        &'service self,
        life_id: &str,
        space: &VectorSpace,
    ) -> Result<IndexOperationPermit<'service>, MemoryIndexError> {
        let key = IndexOperationKey {
            life_id: life_id.to_owned(),
            space: space.clone(),
        };
        let mut operations = lock_operations(&self.active_operations)?;
        if !operations.insert(key.clone()) {
            return Err(MemoryIndexError::new(
                MemoryIndexErrorCode::IndexOperationInProgress,
                "An index operation is already running for this life and vector space.",
                true,
            ));
        }
        drop(operations);
        Ok(IndexOperationPermit {
            operations: &self.active_operations,
            key,
        })
    }
}

fn ensure_not_cancelled(observer: &dyn MemoryRebuildObserver) -> Result<(), MemoryIndexError> {
    if observer.is_cancelled() {
        return Err(MemoryIndexError::new(
            MemoryIndexErrorCode::RebuildCancelled,
            "The memory vector index rebuild was cancelled.",
            true,
        ));
    }
    Ok(())
}

fn progress_from_report(
    phase: MemoryRebuildPhase,
    report: &MemoryRebuildReport,
    embedded_count: usize,
    current_batch: usize,
    total_batches: usize,
) -> MemoryRebuildProgress {
    MemoryRebuildProgress {
        phase,
        scanned_count: report.scanned_count,
        eligible_count: report.eligible_count,
        embedded_count,
        indexed_count: report.indexed_count,
        skipped_candidate_count: report.skipped_candidate_count,
        skipped_sensitive_count: report.skipped_sensitive_count,
        current_batch,
        total_batches,
    }
}

fn lock_operations(
    operations: &Mutex<HashSet<IndexOperationKey>>,
) -> Result<MutexGuard<'_, HashSet<IndexOperationKey>>, MemoryIndexError> {
    operations.lock().map_err(|_| {
        MemoryIndexError::new(
            MemoryIndexErrorCode::InternalError,
            "The memory index operation coordinator is unavailable.",
            true,
        )
    })
}

fn validate_ids(life_id: &str, memory_id: &str) -> Result<(), MemoryIndexError> {
    validate_life_id(life_id)?;
    if memory_id.trim().is_empty() {
        return Err(invalid_request());
    }
    Ok(())
}

fn validate_life_id(life_id: &str) -> Result<(), MemoryIndexError> {
    if life_id.trim().is_empty() {
        return Err(invalid_request());
    }
    Ok(())
}

fn validate_eligible_memory(
    memory: &MemoryRecord,
    expected_life_id: &str,
) -> Result<(), MemoryIndexError> {
    if memory.life_id != expected_life_id {
        return Err(MemoryIndexError::new(
            MemoryIndexErrorCode::LifeMismatch,
            "The memory does not belong to the requested life.",
            false,
        ));
    }
    if memory.status != MemoryStatus::Confirmed {
        return Err(MemoryIndexError::new(
            MemoryIndexErrorCode::MemoryNotConfirmed,
            "Only confirmed memory can be indexed.",
            false,
        ));
    }
    if memory.is_sensitive {
        return Err(MemoryIndexError::new(
            MemoryIndexErrorCode::SensitiveMemoryNotIndexable,
            "Sensitive memory cannot be sent to an embedding provider.",
            false,
        ));
    }
    selected_index_text(memory).map(|_| ())
}

fn selected_index_text(memory: &MemoryRecord) -> Result<&str, MemoryIndexError> {
    let text = memory
        .summary
        .as_deref()
        .filter(|summary| !summary.trim().is_empty())
        .unwrap_or(memory.content.as_str());
    if text.trim().is_empty() {
        return Err(MemoryIndexError::new(
            MemoryIndexErrorCode::EmptyIndexText,
            "The memory has no usable index text.",
            false,
        ));
    }
    Ok(text)
}

fn content_hash(memory: &MemoryRecord, selected_text: &str) -> String {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, MEMORY_INDEX_FORMAT_VERSION.as_bytes());
    hash_field(&mut hasher, memory.kind.as_str().as_bytes());
    hash_field(&mut hasher, selected_text.as_bytes());
    hash_field(&mut hasher, memory.content.as_bytes());
    hash_field(
        &mut hasher,
        memory.summary.as_deref().unwrap_or_default().as_bytes(),
    );
    let digest = hasher.finalize();
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn validate_embedding_response(
    response: &EmbeddingResponse,
    input_count: usize,
    space: &VectorSpace,
) -> Result<(), MemoryIndexError> {
    if response.model_name != space.embedding_model
        || response.dimension != space.dimension
        || response.input_count != input_count
        || response.vectors.len() != input_count
    {
        return Err(MemoryIndexError::new(
            MemoryIndexErrorCode::DimensionMismatch,
            "The embedding response does not match the configured vector space.",
            true,
        ));
    }
    for (expected_index, vector) in response.vectors.iter().enumerate() {
        if vector.input_index != expected_index
            || vector.values.len() != space.dimension
            || vector.values.is_empty()
            || vector.values.iter().any(|value| !value.is_finite())
        {
            return Err(embedding_failed());
        }
    }
    Ok(())
}

fn map_repository_error(error: MemoryError) -> MemoryIndexError {
    match error.code.as_str() {
        "MEMORY_NOT_FOUND" => MemoryIndexError::new(
            MemoryIndexErrorCode::MemoryNotFound,
            "The requested memory was not found.",
            true,
        ),
        "MEMORY_LIFE_MISMATCH" => MemoryIndexError::new(
            MemoryIndexErrorCode::LifeMismatch,
            "The memory does not belong to the requested life.",
            false,
        ),
        _ => MemoryIndexError::new(
            MemoryIndexErrorCode::RepositoryUnavailable,
            "The authoritative memory repository is unavailable.",
            true,
        ),
    }
}

fn invalid_request() -> MemoryIndexError {
    MemoryIndexError::new(
        MemoryIndexErrorCode::InvalidRequest,
        "Life ID and memory ID must be valid.",
        false,
    )
}

fn invalid_configuration() -> MemoryIndexError {
    MemoryIndexError::new(
        MemoryIndexErrorCode::InvalidRequest,
        "The memory index vector-space configuration is invalid.",
        false,
    )
}

fn embedding_failed() -> MemoryIndexError {
    MemoryIndexError::new(
        MemoryIndexErrorCode::EmbeddingFailed,
        "Memory embedding generation failed.",
        true,
    )
}

fn map_embedding_error(error: EmbeddingError) -> MemoryIndexError {
    let code = match error.code {
        EmbeddingErrorCode::AuthenticationFailed => MemoryIndexErrorCode::AuthenticationFailed,
        EmbeddingErrorCode::RateLimited => MemoryIndexErrorCode::RateLimited,
        EmbeddingErrorCode::NetworkError => MemoryIndexErrorCode::NetworkUnavailable,
        EmbeddingErrorCode::RequestTimeout => MemoryIndexErrorCode::RequestTimeout,
        EmbeddingErrorCode::InvalidProviderResponse => {
            MemoryIndexErrorCode::InvalidProviderResponse
        }
        EmbeddingErrorCode::DimensionMismatch => MemoryIndexErrorCode::DimensionMismatch,
        EmbeddingErrorCode::InvalidRequest
        | EmbeddingErrorCode::EmptyText
        | EmbeddingErrorCode::BatchLimitExceeded
        | EmbeddingErrorCode::TextLimitExceeded => MemoryIndexErrorCode::EmbeddingFailed,
    };
    MemoryIndexError::new(
        code,
        "Memory embedding generation failed.",
        error.recoverable,
    )
}

fn vector_store_failed() -> MemoryIndexError {
    MemoryIndexError::new(
        MemoryIndexErrorCode::VectorStoreFailed,
        "The derived memory vector index operation failed.",
        true,
    )
}

fn partial_index_failure() -> MemoryIndexError {
    MemoryIndexError::new(
        MemoryIndexErrorCode::PartialIndexFailure,
        "The memory vector rebuild did not complete and can be retried.",
        true,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        sync::{
            atomic::{AtomicBool, Ordering},
            Mutex,
        },
        task::{Context, Poll},
    };

    use futures::{future::poll_fn, task::noop_waker};
    use rusqlite::{params, Connection, OptionalExtension};

    use crate::{
        embedding::{
            DeterministicEmbeddingProvider, EmbeddingError, EmbeddingErrorCode, EmbeddingFuture,
            EmbeddingModelInfo, EmbeddingUsage, EmbeddingVector,
        },
        memory::{MemoryKind, MemorySourceType},
        vector_store::{
            InMemoryVectorStore, LanceDbVectorStore, VectorSearchHit, VectorSearchQuery,
            VectorStoreError, VectorStoreErrorCode, VectorStoreFuture,
        },
    };

    use super::*;

    struct TestSqliteRepository {
        _temp: tempfile::TempDir,
        connection: Mutex<Connection>,
    }

    impl TestSqliteRepository {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let connection =
                Connection::open(temp.path().join("memory-index-test.sqlite3")).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE memory (
                        id TEXT PRIMARY KEY,
                        life_id TEXT NOT NULL,
                        kind TEXT NOT NULL,
                        status TEXT NOT NULL,
                        content TEXT NOT NULL,
                        summary TEXT,
                        is_sensitive INTEGER NOT NULL,
                        sequence INTEGER NOT NULL
                    );",
                )
                .unwrap();
            Self {
                _temp: temp,
                connection: Mutex::new(connection),
            }
        }

        fn put(&self, memory: &MemoryRecord, sequence: i64) {
            self.connection
                .lock()
                .unwrap()
                .execute(
                    "INSERT OR REPLACE INTO memory
                     (id, life_id, kind, status, content, summary, is_sensitive, sequence)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        memory.id,
                        memory.life_id,
                        memory.kind.as_str(),
                        memory.status.as_str(),
                        memory.content,
                        memory.summary,
                        memory.is_sensitive,
                        sequence,
                    ],
                )
                .unwrap();
        }

        fn count_rows(&self, life_id: &str) -> usize {
            self.connection
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM memory WHERE life_id = ?1",
                    params![life_id],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap() as usize
        }

        fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<MemoryRecord> {
            let kind: String = row.get(2)?;
            let status: String = row.get(3)?;
            Ok(MemoryRecord {
                id: row.get(0)?,
                life_id: row.get(1)?,
                kind: MemoryKind::parse(&kind).map_err(|_| rusqlite::Error::InvalidQuery)?,
                status: MemoryStatus::parse(&status).map_err(|_| rusqlite::Error::InvalidQuery)?,
                content: row.get(4)?,
                summary: row.get(5)?,
                source_type: MemorySourceType::Manual,
                source_ref: None,
                source_created_at: "2026-07-13T00:00:00.000Z".into(),
                importance: 0.5,
                confidence: 0.9,
                is_sensitive: row.get(6)?,
                created_at: "2026-07-13T00:00:00.000Z".into(),
                updated_at: "2026-07-13T00:00:00.000Z".into(),
                confirmed_at: Some("2026-07-13T00:00:00.000Z".into()),
            })
        }
    }

    impl MemoryVectorIndexRepository for TestSqliteRepository {
        fn get_authoritative(
            &self,
            life_id: &str,
            memory_id: &str,
        ) -> Result<MemoryRecord, MemoryError> {
            let connection = self.connection.lock().unwrap();
            let memory = connection
                .query_row(
                    "SELECT id, life_id, kind, status, content, summary, is_sensitive
                     FROM memory WHERE id = ?1",
                    params![memory_id],
                    Self::read,
                )
                .optional()
                .map_err(|_| MemoryError::database())?
                .ok_or_else(MemoryError::not_found)?;
            if memory.life_id != life_id {
                return Err(MemoryError::life_mismatch());
            }
            Ok(memory)
        }

        fn list_page(
            &self,
            life_id: &str,
            offset: usize,
            limit: usize,
        ) -> Result<Vec<MemoryRecord>, MemoryError> {
            let connection = self.connection.lock().unwrap();
            let mut statement = connection
                .prepare(
                    "SELECT id, life_id, kind, status, content, summary, is_sensitive
                     FROM memory WHERE life_id = ?1
                     ORDER BY sequence ASC, id ASC LIMIT ?2 OFFSET ?3",
                )
                .map_err(|_| MemoryError::database())?;
            let rows = statement
                .query_map(params![life_id, limit as i64, offset as i64], Self::read)
                .map_err(|_| MemoryError::database())?;
            rows.map(|row| row.map_err(|_| MemoryError::database()))
                .collect()
        }
    }

    struct RecordingEmbeddingProvider {
        calls: Mutex<Vec<Vec<String>>>,
        fail: AtomicBool,
        yield_once: bool,
        dimension: usize,
        max_batch_size: usize,
    }

    impl RecordingEmbeddingProvider {
        fn new(dimension: usize, max_batch_size: usize) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                fail: AtomicBool::new(false),
                yield_once: false,
                dimension,
                max_batch_size,
            }
        }

        fn failing(dimension: usize) -> Self {
            let provider = Self::new(dimension, 2);
            provider.fail.store(true, Ordering::SeqCst);
            provider
        }

        fn yielding(dimension: usize) -> Self {
            Self {
                yield_once: true,
                ..Self::new(dimension, 2)
            }
        }

        fn call_count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }

        fn flattened_texts(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .flatten()
                .cloned()
                .collect()
        }

        fn response(
            dimension: usize,
            request: EmbeddingRequest,
        ) -> Result<EmbeddingResponse, EmbeddingError> {
            let input_count = request.texts.len();
            let vectors = request
                .texts
                .iter()
                .enumerate()
                .map(|(input_index, text)| {
                    let seed = text.bytes().fold(1u32, |state, byte| {
                        state.wrapping_mul(31).wrapping_add(byte as u32)
                    });
                    EmbeddingVector {
                        input_index,
                        values: (0..dimension)
                            .map(|index| ((seed.wrapping_add(index as u32) % 997) + 1) as f32)
                            .collect(),
                    }
                })
                .collect();
            Ok(EmbeddingResponse {
                model_name: "test-model".into(),
                dimension,
                vectors,
                input_count,
                usage: Some(EmbeddingUsage::default()),
            })
        }
    }

    impl EmbeddingProvider for RecordingEmbeddingProvider {
        fn model_info(&self) -> EmbeddingModelInfo {
            EmbeddingModelInfo {
                model_name: "test-model".into(),
                dimension: Some(self.dimension),
            }
        }

        fn model_name(&self) -> &str {
            "test-model"
        }

        fn vector_dimension(&self) -> Option<usize> {
            Some(self.dimension)
        }

        fn max_batch_size(&self) -> usize {
            self.max_batch_size
        }

        fn embed<'a>(
            &'a self,
            request: EmbeddingRequest,
        ) -> EmbeddingFuture<'a, Result<EmbeddingResponse, EmbeddingError>> {
            self.calls.lock().unwrap().push(request.texts.clone());
            if self.fail.load(Ordering::SeqCst) {
                return Box::pin(async {
                    Err(EmbeddingError::new(
                        EmbeddingErrorCode::NetworkError,
                        "Synthetic test failure.",
                        true,
                    ))
                });
            }
            let mut response = Some(Self::response(self.dimension, request));
            let mut yielded = !self.yield_once;
            Box::pin(poll_fn(move |context| {
                if !yielded {
                    yielded = true;
                    context.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(response.take().unwrap())
                }
            }))
        }
    }

    #[derive(Default)]
    struct CapturingVectorStore {
        inner: InMemoryVectorStore,
        records: Mutex<Vec<VectorRecord>>,
        fail_batch: AtomicBool,
    }

    impl VectorStore for CapturingVectorStore {
        fn upsert<'a>(
            &'a self,
            record: VectorRecord,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async move {
                self.records.lock().unwrap().push(record.clone());
                self.inner.upsert(record).await
            })
        }

        fn upsert_batch<'a>(
            &'a self,
            records: Vec<VectorRecord>,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async move {
                if self.fail_batch.load(Ordering::SeqCst) {
                    return Err(VectorStoreError::new(
                        VectorStoreErrorCode::InternalError,
                        "Synthetic test failure.",
                        true,
                    ));
                }
                self.records.lock().unwrap().extend(records.clone());
                self.inner.upsert_batch(records).await
            })
        }

        fn search<'a>(
            &'a self,
            query: VectorSearchQuery,
        ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>> {
            self.inner.search(query)
        }

        fn delete<'a>(
            &'a self,
            life_id: &'a str,
            memory_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.inner.delete(life_id, memory_id)
        }

        fn delete_from_space<'a>(
            &'a self,
            life_id: &'a str,
            memory_id: &'a str,
            space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.inner.delete_from_space(life_id, memory_id, space)
        }

        fn delete_by_life<'a>(
            &'a self,
            life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.inner.delete_by_life(life_id)
        }

        fn clear_space<'a>(
            &'a self,
            life_id: &'a str,
            space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.inner.clear_space(life_id, space)
        }

        fn count<'a>(
            &'a self,
            life_id: &'a str,
            space: Option<&'a VectorSpace>,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.inner.count(life_id, space)
        }

        fn health_check<'a>(
            &'a self,
            life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.inner.health_check(life_id)
        }
    }

    fn memory(
        id: &str,
        life_id: &str,
        status: MemoryStatus,
        sensitive: bool,
        content: &str,
        summary: Option<&str>,
        kind: MemoryKind,
    ) -> MemoryRecord {
        MemoryRecord {
            id: id.into(),
            life_id: life_id.into(),
            kind,
            status,
            content: content.into(),
            summary: summary.map(str::to_owned),
            source_type: MemorySourceType::Manual,
            source_ref: None,
            source_created_at: "2026-07-13T00:00:00.000Z".into(),
            importance: 0.5,
            confidence: 0.9,
            is_sensitive: sensitive,
            created_at: "2026-07-13T00:00:00.000Z".into(),
            updated_at: "2026-07-13T00:00:00.000Z".into(),
            confirmed_at: (status == MemoryStatus::Confirmed)
                .then(|| "2026-07-13T00:00:00.000Z".into()),
        }
    }

    fn test_space() -> VectorSpace {
        VectorSpace {
            embedding_model: "test-model".into(),
            dimension: 3,
        }
    }

    fn block_on<T>(future: impl Future<Output = T>) -> T {
        tauri::async_runtime::block_on(future)
    }

    #[test]
    fn confirmed_memory_prefers_summary_and_hash_tracks_all_authoritative_fields() {
        block_on(async {
            let repository = TestSqliteRepository::new();
            let mut record = memory(
                "memory-1",
                "life-a",
                MemoryStatus::Confirmed,
                false,
                "Full content",
                Some("Preferred summary"),
                MemoryKind::Fact,
            );
            repository.put(&record, 1);
            let provider = RecordingEmbeddingProvider::new(3, 2);
            let store = CapturingVectorStore::default();
            let service =
                MemoryVectorIndexService::new(&repository, &provider, &store, test_space())
                    .unwrap();
            let request = MemoryIndexRequest {
                life_id: "life-a".into(),
                memory_id: "memory-1".into(),
            };
            let first = service.index_memory(request.clone()).await.unwrap();
            let repeated = service.index_memory(request.clone()).await.unwrap();
            assert_eq!(first.content_hash, repeated.content_hash);
            assert_eq!(
                provider.flattened_texts(),
                vec!["Preferred summary", "Preferred summary"]
            );
            assert_eq!(store.inner.count("life-a", None).await.unwrap(), 1);
            let stored_json = serde_json::to_value(&store.records.lock().unwrap()[0]).unwrap();
            assert!(stored_json.get("content").is_none());
            assert!(stored_json.get("summary").is_none());

            record.content = "Changed full content".into();
            repository.put(&record, 1);
            let changed_content = service.index_memory(request.clone()).await.unwrap();
            assert_ne!(first.content_hash, changed_content.content_hash);
            record.summary = Some("Changed summary".into());
            repository.put(&record, 1);
            let changed_summary = service.index_memory(request.clone()).await.unwrap();
            assert_ne!(changed_content.content_hash, changed_summary.content_hash);
            record.kind = MemoryKind::Preference;
            repository.put(&record, 1);
            let changed_kind = service.index_memory(request).await.unwrap();
            assert_ne!(changed_summary.content_hash, changed_kind.content_hash);
        });
    }

    #[test]
    fn confirmed_memory_indexes_with_deterministic_embedding_provider() {
        block_on(async {
            let repository = TestSqliteRepository::new();
            repository.put(
                &memory(
                    "memory",
                    "life",
                    MemoryStatus::Confirmed,
                    false,
                    "content",
                    None,
                    MemoryKind::Fact,
                ),
                1,
            );
            let provider = DeterministicEmbeddingProvider::new(3);
            let store = InMemoryVectorStore::new();
            let space = VectorSpace {
                embedding_model: provider.model_name().into(),
                dimension: 3,
            };
            let service =
                MemoryVectorIndexService::new(&repository, &provider, &store, space.clone())
                    .unwrap();
            service
                .index_memory(MemoryIndexRequest {
                    life_id: "life".into(),
                    memory_id: "memory".into(),
                })
                .await
                .unwrap();
            assert_eq!(store.count("life", Some(&space)).await.unwrap(), 1);
        });
    }

    #[test]
    fn content_is_used_only_when_summary_is_blank() {
        block_on(async {
            let repository = TestSqliteRepository::new();
            repository.put(
                &memory(
                    "memory",
                    "life",
                    MemoryStatus::Confirmed,
                    false,
                    "Exact content",
                    Some("   "),
                    MemoryKind::Experience,
                ),
                1,
            );
            let provider = RecordingEmbeddingProvider::new(3, 2);
            let store = InMemoryVectorStore::new();
            let service =
                MemoryVectorIndexService::new(&repository, &provider, &store, test_space())
                    .unwrap();
            service
                .index_memory(MemoryIndexRequest {
                    life_id: "life".into(),
                    memory_id: "memory".into(),
                })
                .await
                .unwrap();
            assert_eq!(provider.flattened_texts(), vec!["Exact content"]);
        });
    }

    #[test]
    fn candidate_sensitive_and_other_life_never_reach_embedding() {
        block_on(async {
            let repository = TestSqliteRepository::new();
            repository.put(
                &memory(
                    "candidate",
                    "life",
                    MemoryStatus::Candidate,
                    false,
                    "candidate text",
                    None,
                    MemoryKind::Fact,
                ),
                1,
            );
            repository.put(
                &memory(
                    "sensitive",
                    "life",
                    MemoryStatus::Confirmed,
                    true,
                    "secret text",
                    None,
                    MemoryKind::Fact,
                ),
                2,
            );
            repository.put(
                &memory(
                    "other",
                    "other-life",
                    MemoryStatus::Confirmed,
                    false,
                    "other text",
                    None,
                    MemoryKind::Fact,
                ),
                3,
            );
            let provider = RecordingEmbeddingProvider::new(3, 2);
            let store = InMemoryVectorStore::new();
            let service =
                MemoryVectorIndexService::new(&repository, &provider, &store, test_space())
                    .unwrap();
            for (memory_id, expected) in [
                ("candidate", MemoryIndexErrorCode::MemoryNotConfirmed),
                (
                    "sensitive",
                    MemoryIndexErrorCode::SensitiveMemoryNotIndexable,
                ),
                ("other", MemoryIndexErrorCode::LifeMismatch),
            ] {
                let error = service
                    .index_memory(MemoryIndexRequest {
                        life_id: "life".into(),
                        memory_id: memory_id.into(),
                    })
                    .await
                    .unwrap_err();
                assert_eq!(error.code, expected);
            }
            assert_eq!(provider.call_count(), 0);
        });
    }

    #[test]
    fn remove_deletes_only_requested_space_and_never_sqlite_memory() {
        block_on(async {
            let repository = TestSqliteRepository::new();
            repository.put(
                &memory(
                    "memory",
                    "life",
                    MemoryStatus::Confirmed,
                    false,
                    "text",
                    None,
                    MemoryKind::Fact,
                ),
                1,
            );
            let provider = RecordingEmbeddingProvider::new(3, 2);
            let store = InMemoryVectorStore::new();
            store
                .upsert(VectorRecord {
                    life_id: "life".into(),
                    memory_id: "memory".into(),
                    embedding_model: "other-model".into(),
                    dimension: 2,
                    vector: vec![1.0, 0.0],
                    content_hash: "other".into(),
                })
                .await
                .unwrap();
            let service =
                MemoryVectorIndexService::new(&repository, &provider, &store, test_space())
                    .unwrap();
            service
                .index_memory(MemoryIndexRequest {
                    life_id: "life".into(),
                    memory_id: "memory".into(),
                })
                .await
                .unwrap();
            service
                .remove_memory_index("life", "memory", &test_space())
                .await
                .unwrap();
            assert_eq!(store.count("life", None).await.unwrap(), 1);
            assert_eq!(repository.count_rows("life"), 1);
        });
    }

    #[test]
    fn rebuild_pages_batches_and_indexes_only_eligible_memory() {
        block_on(async {
            let repository = TestSqliteRepository::new();
            for index in 0..130 {
                repository.put(
                    &memory(
                        &format!("eligible-{index}"),
                        "life-a",
                        MemoryStatus::Confirmed,
                        false,
                        &format!("eligible text {index}"),
                        None,
                        MemoryKind::Fact,
                    ),
                    index,
                );
            }
            repository.put(
                &memory(
                    "candidate",
                    "life-a",
                    MemoryStatus::Candidate,
                    false,
                    "candidate text",
                    None,
                    MemoryKind::Fact,
                ),
                130,
            );
            repository.put(
                &memory(
                    "sensitive",
                    "life-a",
                    MemoryStatus::Confirmed,
                    true,
                    "sensitive text",
                    None,
                    MemoryKind::Fact,
                ),
                131,
            );
            repository.put(
                &memory(
                    "other-life",
                    "life-b",
                    MemoryStatus::Confirmed,
                    false,
                    "other life text",
                    None,
                    MemoryKind::Fact,
                ),
                132,
            );
            let provider = RecordingEmbeddingProvider::new(3, 32);
            let store = InMemoryVectorStore::new();
            let service =
                MemoryVectorIndexService::new(&repository, &provider, &store, test_space())
                    .unwrap();
            let report = service
                .rebuild_life_index(MemoryRebuildRequest {
                    life_id: "life-a".into(),
                })
                .await
                .unwrap();
            assert_eq!(report.scanned_count, 132);
            assert_eq!(report.eligible_count, 130);
            assert_eq!(report.indexed_count, 130);
            assert_eq!(report.skipped_candidate_count, 1);
            assert_eq!(report.skipped_sensitive_count, 1);
            assert_eq!(report.failed_count, 0);
            assert!(report.completed);
            assert_eq!(provider.call_count(), 5);
            let sent = provider.flattened_texts();
            assert!(sent.iter().all(|text| text.starts_with("eligible text")));
            assert_eq!(
                store.count("life-a", Some(&test_space())).await.unwrap(),
                130
            );
            assert_eq!(store.count("life-b", None).await.unwrap(), 0);
        });
    }

    #[test]
    fn embedding_failure_preserves_old_index_and_sqlite() {
        block_on(async {
            let repository = TestSqliteRepository::new();
            repository.put(
                &memory(
                    "new",
                    "life",
                    MemoryStatus::Confirmed,
                    false,
                    "new text",
                    None,
                    MemoryKind::Fact,
                ),
                1,
            );
            let provider = RecordingEmbeddingProvider::failing(3);
            let store = InMemoryVectorStore::new();
            store
                .upsert(VectorRecord {
                    life_id: "life".into(),
                    memory_id: "old".into(),
                    embedding_model: "test-model".into(),
                    dimension: 3,
                    vector: vec![1.0, 0.0, 0.0],
                    content_hash: "old".into(),
                })
                .await
                .unwrap();
            let service =
                MemoryVectorIndexService::new(&repository, &provider, &store, test_space())
                    .unwrap();
            let error = service
                .rebuild_life_index(MemoryRebuildRequest {
                    life_id: "life".into(),
                })
                .await
                .unwrap_err();
            assert_eq!(error.code, MemoryIndexErrorCode::NetworkUnavailable);
            assert_eq!(store.count("life", Some(&test_space())).await.unwrap(), 1);
            assert_eq!(repository.count_rows("life"), 1);
        });
    }

    #[test]
    fn empty_life_clears_old_space_without_embedding() {
        block_on(async {
            let repository = TestSqliteRepository::new();
            let provider = RecordingEmbeddingProvider::new(3, 2);
            let store = InMemoryVectorStore::new();
            store
                .upsert(VectorRecord {
                    life_id: "life".into(),
                    memory_id: "old".into(),
                    embedding_model: "test-model".into(),
                    dimension: 3,
                    vector: vec![1.0, 0.0, 0.0],
                    content_hash: "old".into(),
                })
                .await
                .unwrap();
            let service =
                MemoryVectorIndexService::new(&repository, &provider, &store, test_space())
                    .unwrap();
            let report = service
                .rebuild_life_index(MemoryRebuildRequest {
                    life_id: "life".into(),
                })
                .await
                .unwrap();
            assert!(report.completed);
            assert_eq!(report.indexed_count, 0);
            assert_eq!(provider.call_count(), 0);
            assert_eq!(store.count("life", Some(&test_space())).await.unwrap(), 0);
            assert_eq!(repository.count_rows("life"), 0);
        });
    }

    #[test]
    fn vector_write_failure_is_reported_as_partial_and_sqlite_survives() {
        block_on(async {
            let repository = TestSqliteRepository::new();
            repository.put(
                &memory(
                    "memory",
                    "life",
                    MemoryStatus::Confirmed,
                    false,
                    "text",
                    None,
                    MemoryKind::Fact,
                ),
                1,
            );
            let provider = RecordingEmbeddingProvider::new(3, 2);
            let store = CapturingVectorStore::default();
            store.fail_batch.store(true, Ordering::SeqCst);
            let service =
                MemoryVectorIndexService::new(&repository, &provider, &store, test_space())
                    .unwrap();
            let error = service
                .rebuild_life_index(MemoryRebuildRequest {
                    life_id: "life".into(),
                })
                .await
                .unwrap_err();
            assert_eq!(error.code, MemoryIndexErrorCode::PartialIndexFailure);
            assert_eq!(repository.count_rows("life"), 1);
        });
    }

    #[test]
    fn concurrent_rebuild_for_same_life_and_space_is_rejected() {
        let repository = TestSqliteRepository::new();
        repository.put(
            &memory(
                "memory",
                "life",
                MemoryStatus::Confirmed,
                false,
                "text",
                None,
                MemoryKind::Fact,
            ),
            1,
        );
        repository.put(
            &memory(
                "memory-b",
                "life-b",
                MemoryStatus::Confirmed,
                false,
                "text b",
                None,
                MemoryKind::Fact,
            ),
            2,
        );
        let provider = RecordingEmbeddingProvider::yielding(3);
        let store = InMemoryVectorStore::new();
        let service =
            MemoryVectorIndexService::new(&repository, &provider, &store, test_space()).unwrap();
        let request = MemoryRebuildRequest {
            life_id: "life".into(),
        };
        let mut first = Box::pin(service.rebuild_life_index(request.clone()));
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(matches!(first.as_mut().poll(&mut context), Poll::Pending));
        let second = block_on(service.rebuild_life_index(request)).unwrap_err();
        assert_eq!(second.code, MemoryIndexErrorCode::IndexOperationInProgress);
        assert!(
            block_on(service.rebuild_life_index(MemoryRebuildRequest {
                life_id: "life-b".into(),
            }))
            .unwrap()
            .completed
        );
        assert!(block_on(first).unwrap().completed);
    }

    #[test]
    fn service_indexes_into_temporary_lancedb_without_real_api() {
        block_on(async {
            let repository = TestSqliteRepository::new();
            repository.put(
                &memory(
                    "memory",
                    "life",
                    MemoryStatus::Confirmed,
                    false,
                    "text",
                    None,
                    MemoryKind::Fact,
                ),
                1,
            );
            let provider = RecordingEmbeddingProvider::new(3, 2);
            let lance_root = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(lance_root.path()).await.unwrap();
            let service =
                MemoryVectorIndexService::new(&repository, &provider, &store, test_space())
                    .unwrap();
            service
                .index_memory(MemoryIndexRequest {
                    life_id: "life".into(),
                    memory_id: "memory".into(),
                })
                .await
                .unwrap();
            assert_eq!(store.count("life", Some(&test_space())).await.unwrap(), 1);
            service
                .remove_memory_index("life", "memory", &test_space())
                .await
                .unwrap();
            assert_eq!(store.count("life", Some(&test_space())).await.unwrap(), 0);
            assert_eq!(repository.count_rows("life"), 1);
        });
    }

    #[test]
    fn cancellation_before_scan_preserves_existing_index() {
        struct Cancelled;

        impl MemoryRebuildObserver for Cancelled {
            fn is_cancelled(&self) -> bool {
                true
            }

            fn on_progress(&self, _progress: MemoryRebuildProgress) {}
        }

        block_on(async {
            let repository = TestSqliteRepository::new();
            repository.put(
                &memory(
                    "memory-new",
                    "life",
                    MemoryStatus::Confirmed,
                    false,
                    "new text",
                    None,
                    MemoryKind::Fact,
                ),
                1,
            );
            let provider = RecordingEmbeddingProvider::new(3, 2);
            let store = InMemoryVectorStore::new();
            store
                .upsert(VectorRecord {
                    life_id: "life".into(),
                    memory_id: "memory-old".into(),
                    embedding_model: "test-model".into(),
                    dimension: 3,
                    vector: vec![1.0, 0.0, 0.0],
                    content_hash: "old-hash".into(),
                })
                .await
                .unwrap();
            let service =
                MemoryVectorIndexService::new(&repository, &provider, &store, test_space())
                    .unwrap();
            let error = service
                .rebuild_life_index_observed(
                    MemoryRebuildRequest {
                        life_id: "life".into(),
                    },
                    &Cancelled,
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, MemoryIndexErrorCode::RebuildCancelled);
            assert_eq!(store.count("life", Some(&test_space())).await.unwrap(), 1);
            assert!(store
                .search(VectorSearchQuery {
                    life_id: "life".into(),
                    space: test_space(),
                    vector: vec![1.0, 0.0, 0.0],
                    limit: 10,
                    min_score: None,
                })
                .await
                .unwrap()
                .iter()
                .any(|hit| hit.memory_id == "memory-old"));
        });
    }
}
