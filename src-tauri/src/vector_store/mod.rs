//! Replaceable vector-index boundary.
//!
//! SQLite remains authoritative. Implementations store only rebuildable index
//! data and search results intentionally contain no memory content.

#[cfg(any(test, debug_assertions))]
mod in_memory;
mod lancedb;
mod registry;

#[cfg(any(test, debug_assertions))]
pub use in_memory::InMemoryVectorStore;
pub use lancedb::LanceDbVectorStore;
pub use registry::{
    LanceDbVectorStoreRegistry, LanceDbVectorStoreRegistryError,
    LanceDbVectorStoreRegistryErrorCode, DEFAULT_MAX_CACHED_STORES,
};

use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};

pub const MAX_SEARCH_LIMIT: usize = 100;
pub const MAX_VECTOR_DIMENSION: usize = 4096;
pub const MAX_DESCRIPTOR_HASH_BYTES: usize = 128;
pub const MAX_CONTENT_HASH_BYTES: usize = 128;
pub const MAX_GENERATION_ID_BYTES: usize = 64;

pub type VectorStoreFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Controlled generation directory identity. Rejects path traversal and device names.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VectorGenerationId(String);

impl VectorGenerationId {
    pub fn parse(raw: impl AsRef<str>) -> Result<Self, VectorStoreError> {
        let raw = raw.as_ref();
        if raw.is_empty() || raw.len() > MAX_GENERATION_ID_BYTES {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationIdInvalid,
                "The vector generation identifier is invalid.",
                false,
            ));
        }
        if raw == "." || raw == ".." {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationIdInvalid,
                "The vector generation identifier is invalid.",
                false,
            ));
        }
        if raw.contains('/')
            || raw.contains('\\')
            || raw.contains(':')
            || raw.contains('\0')
            || raw.chars().any(|c| c.is_control())
        {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationIdInvalid,
                "The vector generation identifier is invalid.",
                false,
            ));
        }
        if !raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationIdInvalid,
                "The vector generation identifier is invalid.",
                false,
            ));
        }
        let upper = raw.to_ascii_uppercase();
        const RESERVED: &[&str] = &[
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        if RESERVED
            .iter()
            .any(|name| upper == *name || upper.starts_with(&format!("{name}.")))
        {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationIdInvalid,
                "The vector generation identifier is invalid.",
                false,
            ));
        }
        Ok(Self(raw.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for VectorGenerationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VectorGenerationId")
            .field("len", &self.0.len())
            .finish()
    }
}

impl std::fmt::Display for VectorGenerationId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Explicit generation target. Callers supply this; VectorStore never reads SQLite active state.
#[derive(Clone, PartialEq, Eq)]
pub struct VectorGenerationContext {
    generation_id: VectorGenerationId,
    descriptor_hash: String,
    dimension: usize,
}

impl VectorGenerationContext {
    pub fn new(
        generation_id: VectorGenerationId,
        descriptor_hash: impl Into<String>,
        dimension: usize,
    ) -> Result<Self, VectorStoreError> {
        let descriptor_hash = descriptor_hash.into();
        validate_hash(&descriptor_hash, "Descriptor hash")?;
        if dimension == 0 || dimension > MAX_VECTOR_DIMENSION {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationDimensionMismatch,
                "The vector generation dimension is invalid.",
                false,
            ));
        }
        Ok(Self {
            generation_id,
            descriptor_hash,
            dimension,
        })
    }

    pub fn generation_id(&self) -> &VectorGenerationId {
        &self.generation_id
    }

    pub fn descriptor_hash(&self) -> &str {
        &self.descriptor_hash
    }

    pub fn dimension(&self) -> usize {
        self.dimension
    }
}

impl std::fmt::Debug for VectorGenerationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VectorGenerationContext")
            .field("generation_id", &self.generation_id)
            .field("descriptor_hash_len", &self.descriptor_hash.len())
            .field("dimension", &self.dimension)
            .finish()
    }
}

/// Controlled generation write record. Fields are private; no Deserialize.
#[derive(Clone, PartialEq)]
pub struct GenerationVectorRecord {
    generation_id: VectorGenerationId,
    life_id: String,
    memory_id: String,
    memory_revision: i64,
    content_hash: String,
    descriptor_hash: String,
    vector: Vec<f32>,
}

impl GenerationVectorRecord {
    pub fn try_new(
        generation_id: VectorGenerationId,
        life_id: impl Into<String>,
        memory_id: impl Into<String>,
        memory_revision: i64,
        content_hash: impl Into<String>,
        descriptor_hash: impl Into<String>,
        vector: Vec<f32>,
    ) -> Result<Self, VectorStoreError> {
        let life_id = life_id.into();
        let memory_id = memory_id.into();
        let content_hash = content_hash.into();
        let descriptor_hash = descriptor_hash.into();
        validate_identifier(&life_id, "Life ID")?;
        validate_identifier(&memory_id, "Memory ID")?;
        validate_hash(&content_hash, "Content hash")?;
        validate_hash(&descriptor_hash, "Descriptor hash")?;
        if memory_revision < 0 {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::RecordInvalid,
                "The memory revision is invalid.",
                false,
            ));
        }
        validate_vector(&vector, vector.len())?;
        if vector.len() > MAX_VECTOR_DIMENSION {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::VectorDimensionMismatch,
                "Vector dimension does not match its vector space.",
                false,
            ));
        }
        Ok(Self {
            generation_id,
            life_id,
            memory_id,
            memory_revision,
            content_hash,
            descriptor_hash,
            vector,
        })
    }

    pub fn generation_id(&self) -> &VectorGenerationId {
        &self.generation_id
    }
    pub fn life_id(&self) -> &str {
        &self.life_id
    }
    pub fn memory_id(&self) -> &str {
        &self.memory_id
    }
    pub fn memory_revision(&self) -> i64 {
        self.memory_revision
    }
    pub fn content_hash(&self) -> &str {
        &self.content_hash
    }
    pub fn descriptor_hash(&self) -> &str {
        &self.descriptor_hash
    }
    pub fn dimension(&self) -> usize {
        self.vector.len()
    }
    pub fn vector(&self) -> &[f32] {
        &self.vector
    }

    pub(crate) fn validate_against(
        &self,
        context: &VectorGenerationContext,
    ) -> Result<(), VectorStoreError> {
        if self.generation_id != context.generation_id {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationIdInvalid,
                "The vector record generation does not match the target generation.",
                false,
            ));
        }
        if self.descriptor_hash != context.descriptor_hash {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationDescriptorMismatch,
                "The vector record descriptor does not match the target generation.",
                false,
            ));
        }
        if self.vector.len() != context.dimension {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationDimensionMismatch,
                "The vector record dimension does not match the target generation.",
                false,
            ));
        }
        validate_vector(&self.vector, context.dimension)
    }
}

impl std::fmt::Debug for GenerationVectorRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerationVectorRecord")
            .field("generation_id", &self.generation_id)
            .field("life_id_len", &self.life_id.len())
            .field("memory_id_len", &self.memory_id.len())
            .field("memory_revision", &self.memory_revision)
            .field("content_hash_len", &self.content_hash.len())
            .field("descriptor_hash_len", &self.descriptor_hash.len())
            .field("dimension", &self.vector.len())
            .finish()
    }
}

/// Metadata-only sample; never includes vector values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorMetadataSample {
    pub generation_id: String,
    pub life_id: String,
    pub memory_id: String,
    pub memory_revision: i64,
    pub content_hash: String,
    pub descriptor_hash: String,
    pub dimension: usize,
}

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

/// Legacy space-keyed record used by current production index paths.
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
    GenerationIdInvalid,
    GenerationNotFound,
    GenerationSchemaMismatch,
    GenerationDimensionMismatch,
    GenerationDescriptorMismatch,
    RecordInvalid,
    VectorInvalid,
    VectorDimensionMismatch,
    VectorWriteFailed,
    VectorDeleteFailed,
    VectorReadFailed,
    GenerationDropFailed,
    GenerationLocked,
    GenerationCorrupt,
    GenerationDropRequiresRegistry,
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
///
/// Generation methods are additive. Legacy space-keyed methods remain for
/// production retrieval/index paths and must not silently switch directories.
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

    fn create_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        let _ = context;
        Box::pin(async {
            Err(VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "Generation-aware storage is unavailable for this vector store.",
                false,
            ))
        })
    }

    fn upsert_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        record: GenerationVectorRecord,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        let _ = (context, record);
        Box::pin(async {
            Err(VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "Generation-aware storage is unavailable for this vector store.",
                false,
            ))
        })
    }

    fn delete_generation_memory<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        life_id: &'a str,
        memory_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        let _ = (context, life_id, memory_id);
        Box::pin(async {
            Err(VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "Generation-aware storage is unavailable for this vector store.",
                false,
            ))
        })
    }

    fn delete_generation_life<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        life_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        let _ = (context, life_id);
        Box::pin(async {
            Err(VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "Generation-aware storage is unavailable for this vector store.",
                false,
            ))
        })
    }

    fn count_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        life_id: Option<&'a str>,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        let _ = (context, life_id);
        Box::pin(async {
            Err(VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "Generation-aware storage is unavailable for this vector store.",
                false,
            ))
        })
    }

    fn sample_generation_metadata<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        limit: usize,
    ) -> VectorStoreFuture<'a, Result<Vec<VectorMetadataSample>, VectorStoreError>> {
        let _ = (context, limit);
        Box::pin(async {
            Err(VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "Generation-aware storage is unavailable for this vector store.",
                false,
            ))
        })
    }

    fn health_check_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        let _ = context;
        Box::pin(async {
            Err(VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "Generation-aware storage is unavailable for this vector store.",
                false,
            ))
        })
    }

    fn drop_generation<'a>(
        &'a self,
        generation_id: &'a VectorGenerationId,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        let _ = generation_id;
        Box::pin(async {
            Err(VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "Generation-aware storage is unavailable for this vector store.",
                false,
            ))
        })
    }

    fn get_generation_metadata<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        life_id: &'a str,
        memory_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<Option<VectorMetadataSample>, VectorStoreError>> {
        let _ = (context, life_id, memory_id);
        Box::pin(async {
            Err(VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "Generation-aware storage is unavailable for this vector store.",
                false,
            ))
        })
    }
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

pub(crate) fn validate_hash(value: &str, name: &str) -> Result<(), VectorStoreError> {
    if value.is_empty()
        || value.len() > MAX_CONTENT_HASH_BYTES.max(MAX_DESCRIPTOR_HASH_BYTES)
        || !value
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == '-' || c == '_' || c.is_ascii_alphanumeric())
    {
        return Err(VectorStoreError::new(
            VectorStoreErrorCode::RecordInvalid,
            format!("{name} is invalid."),
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

/// Root path for generation-aware Lance directories under an active data root.
pub fn generation_store_root(
    data_root: &std::path::Path,
    generation_id: &VectorGenerationId,
) -> std::path::PathBuf {
    data_root
        .join("vectors")
        .join("generations")
        .join(generation_id.as_str())
        .join("lancedb")
}

#[cfg(test)]
mod generation_id_tests {
    use super::*;

    #[test]
    fn generation_id_rejects_path_traversal_and_reserved_names() {
        let too_long = "x".repeat(MAX_GENERATION_ID_BYTES + 1);
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "C:gen",
            "con",
            "COM1",
            "aux.txt",
            "has space",
            too_long.as_str(),
        ] {
            assert!(
                VectorGenerationId::parse(bad).is_err(),
                "expected rejection for {bad:?}"
            );
        }
        assert!(VectorGenerationId::parse("gen-abc_01").is_ok());
    }

    #[test]
    fn generation_record_debug_hides_vector_values() {
        let id = VectorGenerationId::parse("gen-1").unwrap();
        let record = GenerationVectorRecord::try_new(
            id,
            "life",
            "mem",
            1,
            "hash1",
            "desc1",
            vec![1.0, 2.0, 3.0],
        )
        .unwrap();
        let debug = format!("{record:?}");
        assert!(!debug.contains("1.0"));
        assert!(!debug.contains("2.0"));
        assert!(debug.contains("dimension"));
    }
}
