use std::{
    collections::HashMap,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use super::{
    validate_generation_search_metadata, validate_hash, validate_identifier,
    ConditionalGenerationDeleteOutcome, GenerationVectorRecord, GenerationVectorSearchHit,
    GenerationVectorSearchQuery, VectorGenerationContext, VectorGenerationId, VectorMetadataSample,
    VectorRecord, VectorSearchHit, VectorSearchQuery, VectorSpace, VectorStore, VectorStoreError,
    VectorStoreErrorCode, VectorStoreFuture,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RecordKey {
    life_id: String,
    memory_id: String,
    embedding_model: String,
}

impl From<&VectorRecord> for RecordKey {
    fn from(record: &VectorRecord) -> Self {
        Self {
            life_id: record.life_id.clone(),
            memory_id: record.memory_id.clone(),
            embedding_model: record.embedding_model.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct GenerationRecordKey {
    generation_id: String,
    life_id: String,
    memory_id: String,
}

#[derive(Clone)]
struct GenerationMeta {
    descriptor_hash: String,
    dimension: usize,
}

#[cfg(test)]
#[derive(Clone)]
struct ConditionalDeleteTestHook {
    entered_atomic_section: std::sync::Arc<std::sync::Barrier>,
    release_atomic_section: std::sync::Arc<std::sync::Barrier>,
}

/// Deterministic, non-persistent implementation for tests and development.
/// It is exported only in test/debug builds and is never selected by default.
#[derive(Default)]
pub struct InMemoryVectorStore {
    records: RwLock<HashMap<RecordKey, VectorRecord>>,
    generations: RwLock<HashMap<String, GenerationMeta>>,
    generation_records: RwLock<HashMap<GenerationRecordKey, GenerationVectorRecord>>,
    #[cfg(test)]
    conditional_delete_after_atomic_locks: std::sync::Mutex<Option<ConditionalDeleteTestHook>>,
}

impl InMemoryVectorStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn read_records(
        &self,
    ) -> Result<RwLockReadGuard<'_, HashMap<RecordKey, VectorRecord>>, VectorStoreError> {
        self.records.read().map_err(|_| {
            VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "The in-memory vector store is unavailable.",
                true,
            )
        })
    }

    fn write_records(
        &self,
    ) -> Result<RwLockWriteGuard<'_, HashMap<RecordKey, VectorRecord>>, VectorStoreError> {
        self.records.write().map_err(|_| {
            VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "The in-memory vector store is unavailable.",
                true,
            )
        })
    }

    fn cosine_similarity(left: &[f32], right: &[f32]) -> f32 {
        let (mut dot, mut left_norm, mut right_norm) = (0.0f64, 0.0f64, 0.0f64);
        for (left_value, right_value) in left.iter().zip(right) {
            let left_value = f64::from(*left_value);
            let right_value = f64::from(*right_value);
            dot += left_value * right_value;
            left_norm += left_value * left_value;
            right_norm += right_value * right_value;
        }
        (dot / (left_norm.sqrt() * right_norm.sqrt())) as f32
    }
}

impl VectorStore for InMemoryVectorStore {
    fn upsert<'a>(
        &'a self,
        record: VectorRecord,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move {
            record.validate()?;
            self.write_records()?
                .insert(RecordKey::from(&record), record);
            Ok(())
        })
    }

    fn upsert_batch<'a>(
        &'a self,
        records: Vec<VectorRecord>,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move {
            if records.is_empty() {
                return Err(VectorStoreError::new(
                    VectorStoreErrorCode::InvalidVector,
                    "A vector upsert batch must not be empty.",
                    false,
                ));
            }
            for record in &records {
                record.validate()?;
            }
            let mut stored_records = self.write_records()?;
            for record in records {
                stored_records.insert(RecordKey::from(&record), record);
            }
            Ok(())
        })
    }

    fn search<'a>(
        &'a self,
        query: VectorSearchQuery,
    ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>> {
        Box::pin(async move {
            query.validate()?;
            let records = self.read_records()?;
            let mut hits = records
                .values()
                .filter(|record| record.life_id == query.life_id && record.space() == query.space)
                .map(|record| VectorSearchHit {
                    memory_id: record.memory_id.clone(),
                    score: Self::cosine_similarity(&query.vector, &record.vector),
                })
                .filter(|hit| query.min_score.is_none_or(|minimum| hit.score >= minimum))
                .collect::<Vec<_>>();
            hits.sort_by(|left, right| {
                right
                    .score
                    .total_cmp(&left.score)
                    .then_with(|| left.memory_id.cmp(&right.memory_id))
            });
            hits.truncate(query.limit);
            Ok(hits)
        })
    }

    fn search_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        query: GenerationVectorSearchQuery,
    ) -> VectorStoreFuture<'a, Result<Vec<GenerationVectorSearchHit>, VectorStoreError>> {
        Box::pin(async move {
            query.validate_against(context)?;
            self.validate_existing_generation(context)?;
            let generation_id = context.generation_id().as_str();
            let records = self.generation_records.read().map_err(|_| {
                VectorStoreError::new(
                    VectorStoreErrorCode::StoreUnavailable,
                    "The in-memory vector store is unavailable.",
                    true,
                )
            })?;
            let mut hits = Vec::new();
            for record in records.values().filter(|record| {
                record.generation_id().as_str() == generation_id
                    && record.life_id() == query.life_id()
            }) {
                record.validate_against(context)?;
                validate_generation_search_metadata(
                    context,
                    record.generation_id().as_str(),
                    record.life_id(),
                    record.memory_id(),
                    record.memory_revision(),
                    record.content_hash(),
                    record.descriptor_hash(),
                    record.dimension(),
                )?;
                let score = Self::cosine_similarity(query.vector(), record.vector());
                if !score.is_finite() {
                    return Err(VectorStoreError::new(
                        VectorStoreErrorCode::GenerationCorrupt,
                        "The vector generation is corrupt.",
                        true,
                    ));
                }
                if query.min_score().is_none_or(|minimum| score >= minimum) {
                    hits.push(GenerationVectorSearchHit {
                        memory_id: record.memory_id().to_owned(),
                        memory_revision: record.memory_revision(),
                        content_hash: record.content_hash().to_owned(),
                        score,
                    });
                }
            }
            hits.sort_by(|left, right| {
                right
                    .score
                    .total_cmp(&left.score)
                    .then_with(|| left.memory_id.cmp(&right.memory_id))
            });
            hits.truncate(query.limit());
            Ok(hits)
        })
    }

    fn delete<'a>(
        &'a self,
        life_id: &'a str,
        memory_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        Box::pin(async move {
            validate_identifier(life_id, "Life ID")?;
            validate_identifier(memory_id, "Memory ID")?;
            let mut records = self.write_records()?;
            let before = records.len();
            records.retain(|key, _| key.life_id != life_id || key.memory_id != memory_id);
            let removed = before - records.len();
            if removed == 0 {
                return Err(VectorStoreError::new(
                    VectorStoreErrorCode::VectorNotFound,
                    "No vector index exists for this life and memory.",
                    false,
                ));
            }
            Ok(removed)
        })
    }

    fn delete_by_life<'a>(
        &'a self,
        life_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        Box::pin(async move {
            validate_identifier(life_id, "Life ID")?;
            let mut records = self.write_records()?;
            let before = records.len();
            records.retain(|key, _| key.life_id != life_id);
            Ok(before - records.len())
        })
    }

    fn delete_from_space<'a>(
        &'a self,
        life_id: &'a str,
        memory_id: &'a str,
        space: &'a VectorSpace,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        Box::pin(async move {
            validate_identifier(life_id, "Life ID")?;
            validate_identifier(memory_id, "Memory ID")?;
            space.validate()?;
            let mut records = self.write_records()?;
            let before = records.len();
            records.retain(|_, record| {
                record.life_id != life_id
                    || record.memory_id != memory_id
                    || record.space() != *space
            });
            let removed = before - records.len();
            if removed == 0 {
                return Err(VectorStoreError::new(
                    VectorStoreErrorCode::VectorNotFound,
                    "No vector index exists for this life, memory, and vector space.",
                    false,
                ));
            }
            Ok(removed)
        })
    }

    fn clear_space<'a>(
        &'a self,
        life_id: &'a str,
        space: &'a VectorSpace,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        Box::pin(async move {
            validate_identifier(life_id, "Life ID")?;
            space.validate()?;
            let mut records = self.write_records()?;
            let before = records.len();
            records.retain(|_, record| record.life_id != life_id || record.space() != *space);
            Ok(before - records.len())
        })
    }

    fn count<'a>(
        &'a self,
        life_id: &'a str,
        space: Option<&'a VectorSpace>,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        Box::pin(async move {
            validate_identifier(life_id, "Life ID")?;
            if let Some(space) = space {
                space.validate()?;
            }
            let records = self.read_records()?;
            Ok(records
                .values()
                .filter(|record| {
                    record.life_id == life_id && space.is_none_or(|space| record.space() == *space)
                })
                .count())
        })
    }

    fn health_check<'a>(
        &'a self,
        life_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move {
            validate_identifier(life_id, "Life ID")?;
            drop(self.read_records()?);
            Ok(())
        })
    }

    fn create_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move {
            let mut generations = self.generations.write().map_err(|_| {
                VectorStoreError::new(
                    VectorStoreErrorCode::StoreUnavailable,
                    "The in-memory vector store is unavailable.",
                    true,
                )
            })?;
            let id = context.generation_id().as_str().to_owned();
            if let Some(existing) = generations.get(&id) {
                if existing.descriptor_hash != context.descriptor_hash()
                    || existing.dimension != context.dimension()
                {
                    return Err(VectorStoreError::new(
                        VectorStoreErrorCode::GenerationSchemaMismatch,
                        "The vector generation schema does not match.",
                        false,
                    ));
                }
                return Ok(());
            }
            generations.insert(
                id,
                GenerationMeta {
                    descriptor_hash: context.descriptor_hash().to_owned(),
                    dimension: context.dimension(),
                },
            );
            Ok(())
        })
    }

    fn upsert_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        record: GenerationVectorRecord,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move {
            record.validate_against(context)?;
            self.create_generation(context).await?;
            let key = GenerationRecordKey {
                generation_id: record.generation_id().as_str().to_owned(),
                life_id: record.life_id().to_owned(),
                memory_id: record.memory_id().to_owned(),
            };
            self.generation_records
                .write()
                .map_err(|_| {
                    VectorStoreError::new(
                        VectorStoreErrorCode::StoreUnavailable,
                        "The in-memory vector store is unavailable.",
                        true,
                    )
                })?
                .insert(key, record);
            Ok(())
        })
    }

    fn delete_generation_memory<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        life_id: &'a str,
        memory_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move {
            validate_identifier(life_id, "Life ID")?;
            validate_identifier(memory_id, "Memory ID")?;
            let key = GenerationRecordKey {
                generation_id: context.generation_id().as_str().to_owned(),
                life_id: life_id.to_owned(),
                memory_id: memory_id.to_owned(),
            };
            let _ = self
                .generation_records
                .write()
                .map_err(|_| {
                    VectorStoreError::new(
                        VectorStoreErrorCode::StoreUnavailable,
                        "The in-memory vector store is unavailable.",
                        true,
                    )
                })?
                .remove(&key);
            Ok(())
        })
    }

    fn delete_generation_memory_if_matches<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        life_id: &'a str,
        memory_id: &'a str,
        expected_revision: i64,
        expected_content_hash: &'a str,
    ) -> VectorStoreFuture<'a, Result<ConditionalGenerationDeleteOutcome, VectorStoreError>> {
        Box::pin(async move {
            validate_identifier(life_id, "Life ID")?;
            validate_identifier(memory_id, "Memory ID")?;
            validate_hash(expected_content_hash, "Content hash")?;
            if expected_revision < 0 {
                return Err(VectorStoreError::new(
                    VectorStoreErrorCode::RecordInvalid,
                    "The expected memory revision is invalid.",
                    false,
                ));
            }
            let generation = self.generations.read().map_err(|_| {
                VectorStoreError::new(
                    VectorStoreErrorCode::StoreUnavailable,
                    "The in-memory vector store is unavailable.",
                    true,
                )
            })?;
            match generation.get(context.generation_id().as_str()) {
                None => return Ok(ConditionalGenerationDeleteOutcome::Absent),
                Some(meta)
                    if meta.descriptor_hash != context.descriptor_hash()
                        || meta.dimension != context.dimension() =>
                {
                    return Err(VectorStoreError::new(
                        VectorStoreErrorCode::GenerationCorrupt,
                        "The vector generation is corrupt.",
                        true,
                    ));
                }
                Some(_) => {}
            }
            let key = GenerationRecordKey {
                generation_id: context.generation_id().as_str().to_owned(),
                life_id: life_id.to_owned(),
                memory_id: memory_id.to_owned(),
            };
            // The global generation-before-records lock order is held through
            // validation, lookup, comparison, removal, and postcondition.
            let mut records = self.generation_records.write().map_err(|_| {
                VectorStoreError::new(
                    VectorStoreErrorCode::StoreUnavailable,
                    "The in-memory vector store is unavailable.",
                    true,
                )
            })?;
            #[cfg(test)]
            if let Some(hook) = self
                .conditional_delete_after_atomic_locks
                .lock()
                .unwrap()
                .clone()
            {
                hook.entered_atomic_section.wait();
                hook.release_atomic_section.wait();
            }
            let Some(record) = records.get(&key) else {
                return Ok(ConditionalGenerationDeleteOutcome::Absent);
            };
            if record.generation_id() != context.generation_id()
                || record.life_id() != life_id
                || record.memory_id() != memory_id
                || record.descriptor_hash() != context.descriptor_hash()
                || record.dimension() != context.dimension()
            {
                return Err(VectorStoreError::new(
                    VectorStoreErrorCode::GenerationCorrupt,
                    "The vector generation is corrupt.",
                    true,
                ));
            }
            if record.memory_revision() != expected_revision
                || record.content_hash() != expected_content_hash
            {
                return Ok(ConditionalGenerationDeleteOutcome::IdentityMismatch);
            }
            if records.remove(&key).is_none() || records.contains_key(&key) {
                return Err(VectorStoreError::new(
                    VectorStoreErrorCode::GenerationCorrupt,
                    "The vector generation is corrupt.",
                    true,
                ));
            }
            Ok(ConditionalGenerationDeleteOutcome::Deleted)
        })
    }

    fn delete_generation_life<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        life_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move {
            validate_identifier(life_id, "Life ID")?;
            let gen = context.generation_id().as_str();
            self.generation_records
                .write()
                .map_err(|_| {
                    VectorStoreError::new(
                        VectorStoreErrorCode::StoreUnavailable,
                        "The in-memory vector store is unavailable.",
                        true,
                    )
                })?
                .retain(|key, _| !(key.generation_id == gen && key.life_id == life_id));
            Ok(())
        })
    }

    fn count_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        life_id: Option<&'a str>,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        Box::pin(async move {
            if let Some(life_id) = life_id {
                validate_identifier(life_id, "Life ID")?;
            }
            self.validate_existing_generation(context)?;
            let gen = context.generation_id().as_str();
            let records = self.generation_records.read().map_err(|_| {
                VectorStoreError::new(
                    VectorStoreErrorCode::StoreUnavailable,
                    "The in-memory vector store is unavailable.",
                    true,
                )
            })?;
            Ok(records
                .keys()
                .filter(|key| {
                    key.generation_id == gen && life_id.is_none_or(|life| key.life_id == life)
                })
                .count())
        })
    }

    fn sample_generation_metadata<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        limit: usize,
    ) -> VectorStoreFuture<'a, Result<Vec<VectorMetadataSample>, VectorStoreError>> {
        Box::pin(async move {
            if limit == 0 || limit > super::MAX_SEARCH_LIMIT {
                return Err(VectorStoreError::new(
                    VectorStoreErrorCode::InvalidLimit,
                    "Metadata sample limit must be within the supported range.",
                    false,
                ));
            }
            self.validate_existing_generation(context)?;
            let gen = context.generation_id().as_str();
            let records = self.generation_records.read().map_err(|_| {
                VectorStoreError::new(
                    VectorStoreErrorCode::StoreUnavailable,
                    "The in-memory vector store is unavailable.",
                    true,
                )
            })?;
            let mut samples = records
                .values()
                .filter(|record| record.generation_id().as_str() == gen)
                .map(|record| VectorMetadataSample {
                    generation_id: record.generation_id().as_str().to_owned(),
                    life_id: record.life_id().to_owned(),
                    memory_id: record.memory_id().to_owned(),
                    memory_revision: record.memory_revision(),
                    content_hash: record.content_hash().to_owned(),
                    descriptor_hash: record.descriptor_hash().to_owned(),
                    dimension: record.dimension(),
                })
                .collect::<Vec<_>>();
            samples.sort_by(|a, b| {
                a.life_id
                    .cmp(&b.life_id)
                    .then_with(|| a.memory_id.cmp(&b.memory_id))
            });
            samples.truncate(limit);
            Ok(samples)
        })
    }

    fn list_generation_metadata<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
    ) -> VectorStoreFuture<'a, Result<Vec<VectorMetadataSample>, VectorStoreError>> {
        Box::pin(async move {
            self.validate_existing_generation(context)?;
            let gen = context.generation_id().as_str();
            let records = self.generation_records.read().map_err(|_| {
                VectorStoreError::new(
                    VectorStoreErrorCode::StoreUnavailable,
                    "The in-memory vector store is unavailable.",
                    true,
                )
            })?;
            let mut samples = records
                .values()
                .filter(|record| record.generation_id().as_str() == gen)
                .map(|record| VectorMetadataSample {
                    generation_id: record.generation_id().as_str().to_owned(),
                    life_id: record.life_id().to_owned(),
                    memory_id: record.memory_id().to_owned(),
                    memory_revision: record.memory_revision(),
                    content_hash: record.content_hash().to_owned(),
                    descriptor_hash: record.descriptor_hash().to_owned(),
                    dimension: record.dimension(),
                })
                .collect::<Vec<_>>();
            samples.sort_by(|left, right| {
                left.life_id
                    .cmp(&right.life_id)
                    .then_with(|| left.memory_id.cmp(&right.memory_id))
            });
            Ok(samples)
        })
    }

    fn health_check_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move {
            self.validate_existing_generation(context)?;
            Ok(())
        })
    }

    fn drop_generation<'a>(
        &'a self,
        generation_id: &'a VectorGenerationId,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move {
            let id = generation_id.as_str();
            let _ = self
                .generations
                .write()
                .map_err(|_| {
                    VectorStoreError::new(
                        VectorStoreErrorCode::StoreUnavailable,
                        "The in-memory vector store is unavailable.",
                        true,
                    )
                })?
                .remove(id);
            self.generation_records
                .write()
                .map_err(|_| {
                    VectorStoreError::new(
                        VectorStoreErrorCode::StoreUnavailable,
                        "The in-memory vector store is unavailable.",
                        true,
                    )
                })?
                .retain(|key, _| key.generation_id != id);
            Ok(())
        })
    }

    fn get_generation_metadata<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        life_id: &'a str,
        memory_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<Option<VectorMetadataSample>, VectorStoreError>> {
        use super::VectorMetadataSample;
        Box::pin(async move {
            validate_identifier(life_id, "Life ID")?;
            validate_identifier(memory_id, "Memory ID")?;
            let key = GenerationRecordKey {
                generation_id: context.generation_id().as_str().to_owned(),
                life_id: life_id.to_owned(),
                memory_id: memory_id.to_owned(),
            };
            let records = self.generation_records.read().map_err(|_| {
                VectorStoreError::new(
                    VectorStoreErrorCode::StoreUnavailable,
                    "The in-memory vector store is unavailable.",
                    true,
                )
            })?;
            let Some(record) = records.get(&key) else {
                return Ok(None);
            };
            Ok(Some(VectorMetadataSample {
                generation_id: record.generation_id().as_str().to_owned(),
                life_id: record.life_id().to_owned(),
                memory_id: record.memory_id().to_owned(),
                memory_revision: record.memory_revision(),
                content_hash: record.content_hash().to_owned(),
                descriptor_hash: record.descriptor_hash().to_owned(),
                dimension: record.dimension(),
            }))
        })
    }
}

impl InMemoryVectorStore {
    fn validate_existing_generation(
        &self,
        context: &VectorGenerationContext,
    ) -> Result<(), VectorStoreError> {
        let generations = self.generations.read().map_err(|_| {
            VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "The in-memory vector store is unavailable.",
                true,
            )
        })?;
        let Some(meta) = generations.get(context.generation_id().as_str()) else {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationNotFound,
                "The vector generation was not found.",
                true,
            ));
        };
        if meta.descriptor_hash != context.descriptor_hash()
            || meta.dimension != context.dimension()
        {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationSchemaMismatch,
                "The vector generation schema does not match.",
                false,
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, thread};

    fn block_on<T>(future: VectorStoreFuture<'_, T>) -> T {
        tauri::async_runtime::block_on(future)
    }

    fn space(model: &str, dimension: usize) -> VectorSpace {
        VectorSpace {
            embedding_model: model.into(),
            dimension,
        }
    }

    fn record(life_id: &str, memory_id: &str, model: &str, vector: Vec<f32>) -> VectorRecord {
        VectorRecord {
            life_id: life_id.into(),
            memory_id: memory_id.into(),
            embedding_model: model.into(),
            dimension: vector.len(),
            vector,
            content_hash: format!("hash-{memory_id}"),
        }
    }

    fn query(life_id: &str, model: &str, vector: Vec<f32>, limit: usize) -> VectorSearchQuery {
        VectorSearchQuery {
            life_id: life_id.into(),
            space: space(model, vector.len()),
            vector,
            limit,
            min_score: None,
        }
    }

    #[test]
    fn upsert_count_and_replacement_are_deterministic() {
        let store = InMemoryVectorStore::new();
        block_on(store.upsert(record("life-a", "memory-1", "model-a", vec![1.0, 0.0]))).unwrap();
        block_on(store.upsert(record("life-a", "memory-1", "model-a", vec![0.0, 1.0]))).unwrap();
        assert_eq!(block_on(store.count("life-a", None)).unwrap(), 1);
        let hits = block_on(store.search(query("life-a", "model-a", vec![0.0, 1.0], 10))).unwrap();
        assert_eq!(hits[0].score, 1.0);

        block_on(store.upsert(record("life-a", "memory-1", "model-a", vec![0.0, 1.0, 0.0])))
            .unwrap();
        assert_eq!(block_on(store.count("life-a", None)).unwrap(), 1);
        assert!(
            block_on(store.search(query("life-a", "model-a", vec![0.0, 1.0], 10,)))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn batch_upsert_is_complete() {
        let store = InMemoryVectorStore::new();
        block_on(store.upsert_batch(vec![
            record("life-a", "memory-1", "model-a", vec![1.0, 0.0]),
            record("life-a", "memory-2", "model-a", vec![0.0, 1.0]),
        ]))
        .unwrap();
        assert_eq!(block_on(store.count("life-a", None)).unwrap(), 2);
    }

    #[test]
    fn cosine_sorting_ties_limit_and_threshold_are_stable() {
        let store = InMemoryVectorStore::new();
        block_on(store.upsert_batch(vec![
            record("life-a", "memory-b", "model-a", vec![1.0, 0.0]),
            record("life-a", "memory-a", "model-a", vec![1.0, 0.0]),
            record("life-a", "memory-c", "model-a", vec![0.0, 1.0]),
        ]))
        .unwrap();

        let mut search = query("life-a", "model-a", vec![1.0, 0.0], 2);
        search.min_score = Some(0.5);
        let hits = block_on(store.search(search)).unwrap();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].memory_id, "memory-a");
        assert_eq!(hits[1].memory_id, "memory-b");
        assert!(hits.iter().all(|hit| hit.score >= 0.5));
    }

    #[test]
    fn search_isolated_by_life_model_and_dimension() {
        let store = InMemoryVectorStore::new();
        block_on(store.upsert_batch(vec![
            record("life-a", "a", "model-a", vec![1.0, 0.0]),
            record("life-b", "b", "model-a", vec![1.0, 0.0]),
            record("life-a", "other-model", "model-b", vec![1.0, 0.0]),
            record("life-a", "other-dimension", "model-a", vec![1.0, 0.0, 0.0]),
        ]))
        .unwrap();
        let hits = block_on(store.search(query("life-a", "model-a", vec![1.0, 0.0], 10))).unwrap();
        assert_eq!(
            hits,
            vec![VectorSearchHit {
                memory_id: "a".into(),
                score: 1.0
            }]
        );
    }

    #[test]
    fn invalid_dimensions_vectors_limits_and_thresholds_are_rejected() {
        let store = InMemoryVectorStore::new();
        let mut mismatched = record("life-a", "memory", "model", vec![1.0, 0.0]);
        mismatched.dimension = 3;
        assert_eq!(
            block_on(store.upsert(mismatched)).unwrap_err().code,
            VectorStoreErrorCode::DimensionMismatch
        );
        let mut mismatched_query = query("life-a", "model", vec![1.0], 1);
        mismatched_query.space.dimension = 2;
        assert_eq!(
            block_on(store.search(mismatched_query)).unwrap_err().code,
            VectorStoreErrorCode::DimensionMismatch
        );
        for vector in [vec![], vec![f32::NAN], vec![f32::INFINITY]] {
            assert_eq!(
                block_on(store.upsert(record("life-a", "memory", "model", vector)))
                    .unwrap_err()
                    .code,
                VectorStoreErrorCode::InvalidVector
            );
        }
        let mut invalid_limit = query("life-a", "model", vec![1.0], 0);
        assert_eq!(
            block_on(store.search(invalid_limit.clone()))
                .unwrap_err()
                .code,
            VectorStoreErrorCode::InvalidLimit
        );
        invalid_limit.limit = 1;
        invalid_limit.min_score = Some(f32::NAN);
        assert_eq!(
            block_on(store.search(invalid_limit)).unwrap_err().code,
            VectorStoreErrorCode::InvalidScoreThreshold
        );
    }

    #[test]
    fn deletion_checks_life_and_memory_and_delete_by_life_is_scoped() {
        let store = InMemoryVectorStore::new();
        block_on(store.upsert_batch(vec![
            record("life-a", "shared", "model-a", vec![1.0]),
            record("life-b", "shared", "model-a", vec![1.0]),
            record("life-a", "other", "model-a", vec![1.0]),
        ]))
        .unwrap();
        assert_eq!(
            block_on(store.delete("life-c", "shared")).unwrap_err().code,
            VectorStoreErrorCode::VectorNotFound
        );
        assert_eq!(block_on(store.delete("life-a", "shared")).unwrap(), 1);
        assert_eq!(block_on(store.delete_by_life("life-a")).unwrap(), 1);
        assert_eq!(block_on(store.count("life-b", None)).unwrap(), 1);
    }

    #[test]
    fn clear_space_preserves_other_spaces_and_lives() {
        let store = InMemoryVectorStore::new();
        block_on(store.upsert_batch(vec![
            record("life-a", "a", "model-a", vec![1.0]),
            record("life-a", "b", "model-b", vec![1.0]),
            record("life-b", "c", "model-a", vec![1.0]),
        ]))
        .unwrap();
        assert_eq!(
            block_on(store.clear_space("life-a", &space("model-a", 1))).unwrap(),
            1
        );
        assert_eq!(block_on(store.count("life-a", None)).unwrap(), 1);
        assert_eq!(block_on(store.count("life-b", None)).unwrap(), 1);
    }

    #[test]
    fn hits_expose_only_memory_id_and_score_and_store_is_healthy() {
        let store = InMemoryVectorStore::new();
        block_on(store.upsert(record("life-a", "memory", "model", vec![1.0]))).unwrap();
        block_on(store.health_check("life-a")).unwrap();
        let hits = block_on(store.search(query("life-a", "model", vec![1.0], 1))).unwrap();
        let serialized = serde_json::to_value(&hits[0]).unwrap();
        assert_eq!(serialized.as_object().unwrap().len(), 2);
        assert_eq!(serialized["memoryId"], "memory");
        assert!(serialized.get("content").is_none());
    }

    #[test]
    fn generation_existence_distinguishes_missing_created_empty_and_dropped() {
        let store = InMemoryVectorStore::new();
        let context = VectorGenerationContext::new(
            VectorGenerationId::parse("memory-existence").unwrap(),
            "descriptor-memory-existence",
            2,
        )
        .unwrap();

        for error in [
            block_on(store.count_generation(&context, None)).unwrap_err(),
            block_on(store.sample_generation_metadata(&context, 1)).unwrap_err(),
            block_on(store.health_check_generation(&context)).unwrap_err(),
        ] {
            assert_eq!(error.code, VectorStoreErrorCode::GenerationNotFound);
        }

        block_on(store.create_generation(&context)).unwrap();
        assert_eq!(block_on(store.count_generation(&context, None)).unwrap(), 0);
        assert!(block_on(store.sample_generation_metadata(&context, 1))
            .unwrap()
            .is_empty());
        block_on(store.health_check_generation(&context)).unwrap();

        block_on(store.drop_generation(context.generation_id())).unwrap();
        assert_eq!(
            block_on(store.count_generation(&context, None))
                .unwrap_err()
                .code,
            VectorStoreErrorCode::GenerationNotFound
        );
    }

    fn gen_context(id: &str) -> VectorGenerationContext {
        VectorGenerationContext::new(
            VectorGenerationId::parse(id).unwrap(),
            format!("desc-{id}"),
            3,
        )
        .unwrap()
    }

    fn gen_record(
        ctx: &VectorGenerationContext,
        life: &str,
        memory: &str,
        revision: i64,
        content: &str,
    ) -> GenerationVectorRecord {
        GenerationVectorRecord::try_new(
            ctx.generation_id().clone(),
            life,
            memory,
            revision,
            content,
            ctx.descriptor_hash(),
            vec![0.1, 0.2, 0.3],
        )
        .unwrap()
    }

    fn gen_record_with_vector(
        ctx: &VectorGenerationContext,
        life: &str,
        memory: &str,
        revision: i64,
        content: &str,
        vector: Vec<f32>,
    ) -> GenerationVectorRecord {
        GenerationVectorRecord::try_new(
            ctx.generation_id().clone(),
            life,
            memory,
            revision,
            content,
            ctx.descriptor_hash(),
            vector,
        )
        .unwrap()
    }

    #[test]
    fn generation_search_is_context_bound_and_read_only() {
        let store = InMemoryVectorStore::new();
        let context_a = VectorGenerationContext::new(
            VectorGenerationId::parse("search-generation-a").unwrap(),
            "descriptor-search-a",
            3,
        )
        .unwrap();
        let context_b = VectorGenerationContext::new(
            VectorGenerationId::parse("search-generation-b").unwrap(),
            "descriptor-search-b",
            3,
        )
        .unwrap();
        block_on(store.create_generation(&context_a)).unwrap();
        block_on(store.create_generation(&context_b)).unwrap();
        for record in [
            gen_record_with_vector(
                &context_a,
                "life-a",
                "memory-b",
                2,
                "content-b",
                vec![1.0, 0.0, 0.0],
            ),
            gen_record_with_vector(
                &context_a,
                "life-a",
                "memory-a",
                1,
                "content-a",
                vec![1.0, 0.0, 0.0],
            ),
            gen_record_with_vector(
                &context_a,
                "life-b",
                "memory-other-life",
                1,
                "content-other-life",
                vec![1.0, 0.0, 0.0],
            ),
        ] {
            block_on(store.upsert_generation(&context_a, record)).unwrap();
        }
        block_on(store.upsert_generation(
            &context_b,
            gen_record_with_vector(
                &context_b,
                "life-a",
                "memory-a",
                9,
                "content-generation-b",
                vec![1.0, 0.0, 0.0],
            ),
        ))
        .unwrap();

        let before_count = block_on(store.count_generation(&context_a, Some("life-a"))).unwrap();
        let before_metadata = block_on(store.list_generation_metadata(&context_a)).unwrap();
        let top_hit = block_on(store.search_generation(
            &context_a,
            GenerationVectorSearchQuery::new("life-a", vec![1.0, 0.0, 0.0], 1, Some(0.5)),
        ))
        .unwrap();
        assert_eq!(top_hit.len(), 1);
        assert_eq!(top_hit[0].memory_id(), "memory-a");
        assert_eq!(top_hit[0].memory_revision(), 1);
        assert_eq!(top_hit[0].content_hash(), "content-a");
        assert_eq!(top_hit[0].score(), 1.0);

        let all_hits = block_on(store.search_generation(
            &context_a,
            GenerationVectorSearchQuery::new("life-a", vec![1.0, 0.0, 0.0], 10, None),
        ))
        .unwrap();
        assert_eq!(
            all_hits
                .iter()
                .map(|hit| hit.memory_id())
                .collect::<Vec<_>>(),
            vec!["memory-a", "memory-b"]
        );
        let generation_b_hits = block_on(store.search_generation(
            &context_b,
            GenerationVectorSearchQuery::new("life-a", vec![1.0, 0.0, 0.0], 10, None),
        ))
        .unwrap();
        assert_eq!(generation_b_hits[0].content_hash(), "content-generation-b");
        assert_eq!(
            block_on(store.count_generation(&context_a, Some("life-a"))).unwrap(),
            before_count
        );
        assert_eq!(
            block_on(store.list_generation_metadata(&context_a)).unwrap(),
            before_metadata
        );
    }

    #[test]
    fn generation_search_rejects_invalid_queries_and_never_falls_back() {
        let store = InMemoryVectorStore::new();
        let context = gen_context("search-validation");
        let missing = block_on(store.search_generation(
            &context,
            GenerationVectorSearchQuery::new("life", vec![1.0, 0.0, 0.0], 1, None),
        ))
        .unwrap_err();
        assert_eq!(missing.code, VectorStoreErrorCode::GenerationNotFound);

        block_on(store.upsert(record("life", "legacy", "model", vec![1.0, 0.0, 0.0]))).unwrap();
        let no_fallback = block_on(store.search_generation(
            &context,
            GenerationVectorSearchQuery::new("life", vec![1.0, 0.0, 0.0], 1, None),
        ))
        .unwrap_err();
        assert_eq!(no_fallback.code, VectorStoreErrorCode::GenerationNotFound);

        block_on(store.create_generation(&context)).unwrap();
        for (query, code) in [
            (
                GenerationVectorSearchQuery::new("life", vec![1.0, 0.0], 1, None),
                VectorStoreErrorCode::DimensionMismatch,
            ),
            (
                GenerationVectorSearchQuery::new("life", vec![0.0, 0.0, 0.0], 1, None),
                VectorStoreErrorCode::InvalidVector,
            ),
            (
                GenerationVectorSearchQuery::new("life", vec![1.0, 0.0, 0.0], 0, None),
                VectorStoreErrorCode::InvalidLimit,
            ),
            (
                GenerationVectorSearchQuery::new("life", vec![1.0, 0.0, 0.0], 1, Some(2.0)),
                VectorStoreErrorCode::InvalidScoreThreshold,
            ),
        ] {
            assert_eq!(
                block_on(store.search_generation(&context, query))
                    .unwrap_err()
                    .code,
                code
            );
        }
    }

    #[test]
    fn get_generation_metadata_exact_hit() {
        let store = InMemoryVectorStore::new();
        let ctx = gen_context("exact-hit");
        let rec = gen_record(&ctx, "life-a", "mem-1", 2, "hash-content");
        block_on(store.create_generation(&ctx)).unwrap();
        block_on(store.upsert_generation(&ctx, rec)).unwrap();
        let meta = block_on(store.get_generation_metadata(&ctx, "life-a", "mem-1"))
            .unwrap()
            .expect("exact hit must return Some");
        assert_eq!(meta.generation_id, "exact-hit");
        assert_eq!(meta.life_id, "life-a");
        assert_eq!(meta.memory_id, "mem-1");
        assert_eq!(meta.memory_revision, 2);
        assert_eq!(meta.content_hash, "hash-content");
        assert_eq!(meta.descriptor_hash, "desc-exact-hit");
        assert_eq!(meta.dimension, 3);
    }

    #[test]
    fn get_generation_metadata_missing() {
        let store = InMemoryVectorStore::new();
        let ctx = gen_context("missing");
        block_on(store.create_generation(&ctx)).unwrap();
        let meta = block_on(store.get_generation_metadata(&ctx, "life-x", "mem-x")).unwrap();
        assert!(meta.is_none());
    }

    #[test]
    fn get_generation_metadata_generation_isolation() {
        let store = InMemoryVectorStore::new();
        let ctx_a = gen_context("gen-a");
        let ctx_b = gen_context("gen-b");
        block_on(store.create_generation(&ctx_a)).unwrap();
        block_on(store.create_generation(&ctx_b)).unwrap();
        let rec_a = gen_record(&ctx_a, "life", "mem", 1, "hash-a");
        let rec_b = gen_record(&ctx_b, "life", "mem", 2, "hash-b");
        block_on(store.upsert_generation(&ctx_a, rec_a)).unwrap();
        block_on(store.upsert_generation(&ctx_b, rec_b)).unwrap();

        let meta_a = block_on(store.get_generation_metadata(&ctx_a, "life", "mem"))
            .unwrap()
            .expect("gen-a must have record");
        assert_eq!(meta_a.memory_revision, 1);
        assert_eq!(meta_a.content_hash, "hash-a");

        let meta_b = block_on(store.get_generation_metadata(&ctx_b, "life", "mem"))
            .unwrap()
            .expect("gen-b must have record");
        assert_eq!(meta_b.memory_revision, 2);
        assert_eq!(meta_b.content_hash, "hash-b");

        // Query gen-a for a record only in gen-b -> None
        let meta = block_on(store.get_generation_metadata(&ctx_a, "life", "mem-only-b")).unwrap();
        assert!(meta.is_none());
    }

    #[test]
    fn delete_generation_memory_generation_metadata_after_delete() {
        let store = InMemoryVectorStore::new();
        let ctx = gen_context("after-delete");
        let rec = gen_record(&ctx, "life", "mem", 1, "hash");
        block_on(store.create_generation(&ctx)).unwrap();
        block_on(store.upsert_generation(&ctx, rec)).unwrap();
        block_on(store.delete_generation_memory(&ctx, "life", "mem")).unwrap();
        let meta = block_on(store.get_generation_metadata(&ctx, "life", "mem")).unwrap();
        assert!(meta.is_none());
    }

    #[test]
    fn get_generation_metadata_after_update() {
        let store = InMemoryVectorStore::new();
        let ctx = gen_context("after-update");
        block_on(store.create_generation(&ctx)).unwrap();
        let rec1 = gen_record(&ctx, "life", "mem", 1, "hash-1");
        block_on(store.upsert_generation(&ctx, rec1)).unwrap();
        let rec2 = gen_record(&ctx, "life", "mem", 2, "hash-2");
        block_on(store.upsert_generation(&ctx, rec2)).unwrap();
        let meta = block_on(store.get_generation_metadata(&ctx, "life", "mem"))
            .unwrap()
            .expect("updated record must exist");
        assert_eq!(meta.memory_revision, 2);
        assert_eq!(meta.content_hash, "hash-2");
    }

    #[test]
    fn conditional_delete_absent_and_deleted_trait_object_contract() {
        let store = InMemoryVectorStore::new();
        let ctx = gen_context("conditional-delete");
        assert_eq!(
            block_on(store.delete_generation_memory_if_matches(&ctx, "life", "mem", 4, "hash-a"))
                .unwrap(),
            ConditionalGenerationDeleteOutcome::Absent
        );
        block_on(store.create_generation(&ctx)).unwrap();
        block_on(store.upsert_generation(&ctx, gen_record(&ctx, "life", "mem", 4, "hash-a")))
            .unwrap();
        let trait_store: &dyn VectorStore = &store;
        assert_eq!(
            block_on(
                trait_store.delete_generation_memory_if_matches(&ctx, "life", "mem", 4, "hash-a")
            )
            .unwrap(),
            ConditionalGenerationDeleteOutcome::Deleted
        );
        assert!(block_on(store.get_generation_metadata(&ctx, "life", "mem"))
            .unwrap()
            .is_none());
        assert_eq!(
            block_on(store.delete_generation_memory_if_matches(&ctx, "life", "mem", 4, "hash-a"))
                .unwrap(),
            ConditionalGenerationDeleteOutcome::Absent
        );
    }

    #[test]
    fn conditional_delete_identity_mismatch_keeps_in_memory_record() {
        for (revision, hash) in [(5, "hash-a"), (4, "hash-b")] {
            let store = InMemoryVectorStore::new();
            let ctx = gen_context("conditional-mismatch");
            block_on(store.create_generation(&ctx)).unwrap();
            block_on(store.upsert_generation(&ctx, gen_record(&ctx, "life", "mem", 4, "hash-a")))
                .unwrap();
            assert_eq!(
                block_on(
                    store.delete_generation_memory_if_matches(&ctx, "life", "mem", revision, hash)
                )
                .unwrap(),
                ConditionalGenerationDeleteOutcome::IdentityMismatch
            );
            let current = block_on(store.get_generation_metadata(&ctx, "life", "mem"))
                .unwrap()
                .unwrap();
            assert_eq!(
                (current.memory_revision, current.content_hash.as_str()),
                (4, "hash-a")
            );
        }
    }

    #[test]
    fn conditional_delete_descriptor_and_dimension_corruption_fail_closed() {
        for corrupt_descriptor in [true, false] {
            let store = InMemoryVectorStore::new();
            let ctx = gen_context("conditional-corrupt");
            block_on(store.create_generation(&ctx)).unwrap();
            block_on(store.upsert_generation(&ctx, gen_record(&ctx, "life", "mem", 4, "hash-a")))
                .unwrap();
            let key = GenerationRecordKey {
                generation_id: ctx.generation_id().as_str().to_owned(),
                life_id: "life".into(),
                memory_id: "mem".into(),
            };
            let mut records = store.generation_records.write().unwrap();
            let record = records.get_mut(&key).unwrap();
            if corrupt_descriptor {
                record.descriptor_hash = "other-descriptor".into();
            } else {
                record.vector = vec![0.1, 0.2];
            }
            drop(records);
            assert_eq!(
                block_on(
                    store.delete_generation_memory_if_matches(&ctx, "life", "mem", 4, "hash-a")
                )
                .unwrap_err()
                .code,
                VectorStoreErrorCode::GenerationCorrupt
            );
            assert!(store.generation_records.read().unwrap().contains_key(&key));
        }
    }

    #[test]
    fn conditional_delete_in_memory_atomic_postcondition() {
        let store = Arc::new(InMemoryVectorStore::new());
        let ctx = gen_context("conditional-atomic");
        block_on(store.create_generation(&ctx)).unwrap();
        block_on(store.upsert_generation(&ctx, gen_record(&ctx, "life", "mem", 4, "hash-a")))
            .unwrap();
        let entered_atomic_section = Arc::new(std::sync::Barrier::new(2));
        let release_atomic_section = Arc::new(std::sync::Barrier::new(2));
        *store.conditional_delete_after_atomic_locks.lock().unwrap() =
            Some(ConditionalDeleteTestHook {
                entered_atomic_section: Arc::clone(&entered_atomic_section),
                release_atomic_section: Arc::clone(&release_atomic_section),
            });
        let delete_store = Arc::clone(&store);
        let delete_context = ctx.clone();
        let delete = thread::spawn(move || {
            tauri::async_runtime::block_on(delete_store.delete_generation_memory_if_matches(
                &delete_context,
                "life",
                "mem",
                4,
                "hash-a",
            ))
        });
        entered_atomic_section.wait();
        assert!(store.generations.try_write().is_err());
        assert!(store.generation_records.try_write().is_err());
        release_atomic_section.wait();
        assert_eq!(
            delete.join().unwrap().unwrap(),
            ConditionalGenerationDeleteOutcome::Deleted
        );
        assert!(block_on(store.get_generation_metadata(&ctx, "life", "mem"))
            .unwrap()
            .is_none());
    }
}
