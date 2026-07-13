//! Replaceable vector-index boundary.
//!
//! SQLite remains authoritative. Implementations store only rebuildable index
//! data and search results intentionally contain no memory content.

#[cfg(any(test, debug_assertions))]
mod in_memory;
mod lancedb;

#[cfg(any(test, debug_assertions))]
pub use in_memory::InMemoryVectorStore;
pub use lancedb::LanceDbVectorStore;

use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};

pub const MAX_SEARCH_LIMIT: usize = 100;

pub type VectorStoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct VectorSpace {
    pub embedding_model: String,
    pub dimension: usize,
}

impl VectorSpace {
    pub(crate) fn validate(&self) -> Result<(), VectorStoreError> {
        if self.embedding_model.trim().is_empty() || self.dimension == 0 {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::InvalidVector,
                "Vector space model and dimension must be valid.",
                false,
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VectorRecord {
    pub life_id: String,
    pub memory_id: String,
    pub embedding_model: String,
    pub dimension: usize,
    pub vector: Vec<f32>,
    pub content_hash: String,
}

impl VectorRecord {
    pub fn space(&self) -> VectorSpace {
        VectorSpace {
            embedding_model: self.embedding_model.clone(),
            dimension: self.dimension,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), VectorStoreError> {
        validate_identifier(&self.life_id, "Life ID")?;
        validate_identifier(&self.memory_id, "Memory ID")?;
        validate_identifier(&self.content_hash, "Content hash")?;
        self.space().validate()?;
        validate_vector(&self.vector, self.dimension)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VectorSearchQuery {
    pub life_id: String,
    pub space: VectorSpace,
    pub vector: Vec<f32>,
    pub limit: usize,
    pub min_score: Option<f32>,
}

impl VectorSearchQuery {
    pub(crate) fn validate(&self) -> Result<(), VectorStoreError> {
        validate_identifier(&self.life_id, "Life ID")?;
        self.space.validate()?;
        if self.limit == 0 || self.limit > MAX_SEARCH_LIMIT {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::InvalidLimit,
                "Vector search limit must be within the supported range.",
                false,
            ));
        }
        if self
            .min_score
            .is_some_and(|score| !score.is_finite() || !(-1.0..=1.0).contains(&score))
        {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::InvalidScoreThreshold,
                "Vector search score threshold must be finite and between -1 and 1.",
                false,
            ));
        }
        validate_vector(&self.vector, self.space.dimension)
    }
}

/// A hit is only an index reference. Memory content must be loaded from SQLite.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VectorSearchHit {
    pub memory_id: String,
    pub score: f32,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VectorStoreErrorCode {
    InvalidVector,
    DimensionMismatch,
    InvalidLimit,
    InvalidScoreThreshold,
    VectorNotFound,
    StoreUnavailable,
    InternalError,
    InvalidIdentifier,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VectorStoreError {
    pub code: VectorStoreErrorCode,
    pub message: String,
    pub recoverable: bool,
}

impl VectorStoreError {
    pub(crate) fn new(
        code: VectorStoreErrorCode,
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

/// Internal derived-index API. No implementation may mutate authoritative
/// memory records as part of these operations.
pub trait VectorStore: Send + Sync {
    fn upsert<'a>(
        &'a self,
        record: VectorRecord,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>>;

    fn upsert_batch<'a>(
        &'a self,
        records: Vec<VectorRecord>,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>>;

    fn search<'a>(
        &'a self,
        query: VectorSearchQuery,
    ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>>;

    /// Removes every derived vector space for this life/memory pair.
    fn delete<'a>(
        &'a self,
        life_id: &'a str,
        memory_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>>;

    fn delete_from_space<'a>(
        &'a self,
        life_id: &'a str,
        memory_id: &'a str,
        space: &'a VectorSpace,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>>;

    fn delete_by_life<'a>(
        &'a self,
        life_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>>;

    fn clear_space<'a>(
        &'a self,
        life_id: &'a str,
        space: &'a VectorSpace,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>>;

    fn count<'a>(
        &'a self,
        life_id: &'a str,
        space: Option<&'a VectorSpace>,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>>;

    fn health_check<'a>(
        &'a self,
        life_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>>;
}

pub(crate) fn validate_identifier(value: &str, name: &str) -> Result<(), VectorStoreError> {
    if value.trim().is_empty() {
        return Err(VectorStoreError::new(
            VectorStoreErrorCode::InvalidIdentifier,
            format!("{name} must not be empty."),
            false,
        ));
    }
    Ok(())
}

pub(crate) fn validate_vector(
    vector: &[f32],
    expected_dimension: usize,
) -> Result<(), VectorStoreError> {
    if vector.is_empty() || vector.iter().any(|value| !value.is_finite()) {
        return Err(VectorStoreError::new(
            VectorStoreErrorCode::InvalidVector,
            "Vector values must be non-empty and finite.",
            false,
        ));
    }
    if vector.len() != expected_dimension {
        return Err(VectorStoreError::new(
            VectorStoreErrorCode::DimensionMismatch,
            "Vector dimension does not match its vector space.",
            false,
        ));
    }
    if vector.iter().all(|value| *value == 0.0) {
        return Err(VectorStoreError::new(
            VectorStoreErrorCode::InvalidVector,
            "A zero-magnitude vector cannot be indexed or searched.",
            false,
        ));
    }
    Ok(())
}
