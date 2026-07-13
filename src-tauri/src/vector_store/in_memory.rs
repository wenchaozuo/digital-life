use std::{
    collections::HashMap,
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

use super::{
    validate_identifier, VectorRecord, VectorSearchHit, VectorSearchQuery, VectorSpace,
    VectorStore, VectorStoreError, VectorStoreErrorCode, VectorStoreFuture,
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

/// Deterministic, non-persistent implementation for tests and development.
/// It is exported only in test/debug builds and is never selected by default.
#[derive(Default)]
pub struct InMemoryVectorStore {
    records: RwLock<HashMap<RecordKey, VectorRecord>>,
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
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
