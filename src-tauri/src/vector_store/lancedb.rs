use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::Arc,
};

use arrow_array::{
    types::Float32Type, Array, FixedSizeListArray, Float32Array, RecordBatch, RecordBatchIterator,
    StringArray, UInt32Array,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use futures::{lock::Mutex, TryStreamExt};
use lancedb::{
    connection::Connection,
    query::{ExecutableQuery, QueryBase, Select},
    DistanceType, Table,
};

use super::{
    validate_identifier, VectorRecord, VectorSearchHit, VectorSearchQuery, VectorSpace,
    VectorStore, VectorStoreError, VectorStoreErrorCode, VectorStoreFuture,
};

const TABLE_PREFIX: &str = "vs_";
const SPACE_MODEL_METADATA: &str = "digital_life.embedding_model";
const SPACE_DIMENSION_METADATA: &str = "digital_life.dimension";

/// Persistent, rebuildable LanceDB vector index.
///
/// Construction receives an explicit derived-data directory. It never opens
/// SQLite and is not registered as an application-global default.
pub struct LanceDbVectorStore {
    connection: Connection,
    table_init_lock: Mutex<()>,
    mutation_lock: Mutex<()>,
}

impl LanceDbVectorStore {
    pub async fn open(root: impl AsRef<Path>) -> Result<Self, VectorStoreError> {
        let root = root.as_ref();
        if root.exists() && !root.is_dir() {
            return Err(store_unavailable());
        }
        std::fs::create_dir_all(root).map_err(|_| store_unavailable())?;
        let uri = root.to_string_lossy().into_owned();
        let connection = lancedb::connect(&uri)
            .execute()
            .await
            .map_err(|_| store_unavailable())?;
        Ok(Self {
            connection,
            table_init_lock: Mutex::new(()),
            mutation_lock: Mutex::new(()),
        })
    }

    fn table_name(space: &VectorSpace) -> String {
        // Stable FNV-1a over model + separator + dimension. No user-controlled
        // model text is included directly in the table identifier.
        let mut hash = 0xcbf2_9ce4_8422_2325u64;
        for byte in space
            .embedding_model
            .as_bytes()
            .iter()
            .copied()
            .chain(std::iter::once(0xff))
            .chain(space.dimension.to_le_bytes())
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        format!("{TABLE_PREFIX}{hash:016x}")
    }

    fn schema(space: &VectorSpace) -> Result<SchemaRef, VectorStoreError> {
        validate_lance_space(space)?;
        let mut metadata = HashMap::new();
        metadata.insert(
            SPACE_MODEL_METADATA.to_owned(),
            space.embedding_model.clone(),
        );
        metadata.insert(
            SPACE_DIMENSION_METADATA.to_owned(),
            space.dimension.to_string(),
        );
        Ok(Arc::new(Schema::new_with_metadata(
            vec![
                Field::new("life_id", DataType::Utf8, false),
                Field::new("memory_id", DataType::Utf8, false),
                Field::new("embedding_model", DataType::Utf8, false),
                Field::new("dimension", DataType::UInt32, false),
                Field::new("content_hash", DataType::Utf8, false),
                Field::new(
                    "vector",
                    DataType::FixedSizeList(
                        Arc::new(Field::new("item", DataType::Float32, true)),
                        space.dimension as i32,
                    ),
                    false,
                ),
            ],
            metadata,
        )))
    }

    fn records_batch(
        records: &[VectorRecord],
        space: &VectorSpace,
    ) -> Result<(SchemaRef, RecordBatch), VectorStoreError> {
        let schema = Self::schema(space)?;
        let vectors = FixedSizeListArray::from_iter_primitive::<Float32Type, _, _>(
            records
                .iter()
                .map(|record| Some(record.vector.iter().copied().map(Some).collect::<Vec<_>>())),
            space.dimension as i32,
        );
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(StringArray::from_iter_values(
                    records.iter().map(|record| record.life_id.as_str()),
                )),
                Arc::new(StringArray::from_iter_values(
                    records.iter().map(|record| record.memory_id.as_str()),
                )),
                Arc::new(StringArray::from_iter_values(
                    records.iter().map(|record| record.embedding_model.as_str()),
                )),
                Arc::new(UInt32Array::from_iter_values(
                    records.iter().map(|record| record.dimension as u32),
                )),
                Arc::new(StringArray::from_iter_values(
                    records.iter().map(|record| record.content_hash.as_str()),
                )),
                Arc::new(vectors),
            ],
        )
        .map_err(|_| internal_error())?;
        Ok((schema, batch))
    }

    async fn table_names(&self) -> Result<Vec<String>, VectorStoreError> {
        self.connection
            .table_names()
            .execute()
            .await
            .map_err(|_| internal_error())
            .map(|names| {
                names
                    .into_iter()
                    .filter(|name| name.starts_with(TABLE_PREFIX))
                    .collect()
            })
    }

    async fn open_existing_space(
        &self,
        space: &VectorSpace,
    ) -> Result<Option<Table>, VectorStoreError> {
        validate_lance_space(space)?;
        let name = Self::table_name(space);
        if !self.table_names().await?.contains(&name) {
            return Ok(None);
        }
        let table = self
            .connection
            .open_table(&name)
            .execute()
            .await
            .map_err(|_| internal_error())?;
        self.validate_table(&name, &table, space).await?;
        Ok(Some(table))
    }

    async fn ensure_space(&self, space: &VectorSpace) -> Result<Table, VectorStoreError> {
        validate_lance_space(space)?;
        let _guard = self.table_init_lock.lock().await;
        if let Some(table) = self.open_existing_space(space).await? {
            return Ok(table);
        }
        let name = Self::table_name(space);
        let table = self
            .connection
            .create_empty_table(&name, Self::schema(space)?)
            .execute()
            .await
            .map_err(|_| store_unavailable())?;
        self.validate_table(&name, &table, space).await?;
        Ok(table)
    }

    async fn validate_table(
        &self,
        name: &str,
        table: &Table,
        expected_space: &VectorSpace,
    ) -> Result<(), VectorStoreError> {
        let schema = table.schema().await.map_err(|_| internal_error())?;
        let model = schema.metadata().get(SPACE_MODEL_METADATA);
        let dimension = schema
            .metadata()
            .get(SPACE_DIMENSION_METADATA)
            .and_then(|value| value.parse::<usize>().ok());
        let vector_dimension = match schema
            .field_with_name("vector")
            .map(|field| field.data_type())
        {
            Ok(DataType::FixedSizeList(item, dimension))
                if item.data_type() == &DataType::Float32 && *dimension > 0 =>
            {
                *dimension as usize
            }
            _ => return Err(internal_error()),
        };
        if model != Some(&expected_space.embedding_model)
            || dimension != Some(expected_space.dimension)
            || vector_dimension != expected_space.dimension
            || name != Self::table_name(expected_space)
        {
            return Err(internal_error());
        }
        Ok(())
    }

    async fn all_space_tables(&self) -> Result<Vec<(VectorSpace, Table)>, VectorStoreError> {
        let mut result = Vec::new();
        for name in self.table_names().await? {
            let table = self
                .connection
                .open_table(&name)
                .execute()
                .await
                .map_err(|_| internal_error())?;
            let schema = table.schema().await.map_err(|_| internal_error())?;
            let space = VectorSpace {
                embedding_model: schema
                    .metadata()
                    .get(SPACE_MODEL_METADATA)
                    .cloned()
                    .ok_or_else(internal_error)?,
                dimension: schema
                    .metadata()
                    .get(SPACE_DIMENSION_METADATA)
                    .and_then(|value| value.parse::<usize>().ok())
                    .ok_or_else(internal_error)?,
            };
            self.validate_table(&name, &table, &space).await?;
            result.push((space, table));
        }
        Ok(result)
    }

    async fn upsert_records(&self, records: Vec<VectorRecord>) -> Result<(), VectorStoreError> {
        if records.is_empty() {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::InvalidVector,
                "A vector upsert batch must not be empty.",
                false,
            ));
        }
        for record in &records {
            record.validate()?;
            validate_lance_space(&record.space())?;
        }

        // Last item wins for duplicate life + memory + model keys.
        let mut deduplicated = BTreeMap::new();
        for record in records {
            deduplicated.insert(
                (
                    record.life_id.clone(),
                    record.memory_id.clone(),
                    record.embedding_model.clone(),
                ),
                record,
            );
        }
        let records = deduplicated.into_values().collect::<Vec<_>>();
        let mut groups: BTreeMap<(String, usize), Vec<VectorRecord>> = BTreeMap::new();
        for record in records.iter().cloned() {
            groups
                .entry((record.embedding_model.clone(), record.dimension))
                .or_default()
                .push(record);
        }

        let _guard = self.mutation_lock.lock().await;
        self.delete_superseded_dimensions(&records).await?;
        for ((embedding_model, dimension), group) in groups {
            let space = VectorSpace {
                embedding_model,
                dimension,
            };
            let table = self.ensure_space(&space).await?;
            let (schema, batch) = Self::records_batch(&group, &space)?;
            let reader = RecordBatchIterator::new(vec![Ok(batch)], schema);
            let mut merge = table.merge_insert(&["life_id", "memory_id", "embedding_model"]);
            merge
                .when_matched_update_all(None)
                .when_not_matched_insert_all();
            merge
                .execute(Box::new(reader))
                .await
                .map_err(|_| internal_error())?;
        }
        Ok(())
    }

    async fn delete_superseded_dimensions(
        &self,
        records: &[VectorRecord],
    ) -> Result<(), VectorStoreError> {
        for (space, table) in self.all_space_tables().await? {
            let clauses = records
                .iter()
                .filter(|record| {
                    record.embedding_model == space.embedding_model
                        && record.dimension != space.dimension
                })
                .map(|record| {
                    format!(
                        "(life_id = {} AND memory_id = {} AND embedding_model = {})",
                        sql_literal(&record.life_id),
                        sql_literal(&record.memory_id),
                        sql_literal(&record.embedding_model)
                    )
                })
                .collect::<Vec<_>>();
            if !clauses.is_empty() {
                let predicate = clauses.join(" OR ");
                table
                    .delete(&predicate)
                    .await
                    .map_err(|_| internal_error())?;
            }
        }
        Ok(())
    }

    async fn delete_matching_all_spaces(&self, predicate: &str) -> Result<usize, VectorStoreError> {
        let mut removed = 0usize;
        for (_, table) in self.all_space_tables().await? {
            let count = table
                .count_rows(Some(predicate.to_owned()))
                .await
                .map_err(|_| internal_error())?;
            if count > 0 {
                table
                    .delete(predicate)
                    .await
                    .map_err(|_| internal_error())?;
                removed = removed.saturating_add(count);
            }
        }
        Ok(removed)
    }

    #[cfg(test)]
    async fn read_record_for_test(
        &self,
        life_id: &str,
        memory_id: &str,
        space: &VectorSpace,
    ) -> Result<Option<(String, Vec<f32>)>, VectorStoreError> {
        let Some(table) = self.open_existing_space(space).await? else {
            return Ok(None);
        };
        let filter = format!(
            "life_id = {} AND memory_id = {} AND embedding_model = {} AND dimension = {}",
            sql_literal(life_id),
            sql_literal(memory_id),
            sql_literal(&space.embedding_model),
            space.dimension
        );
        let batches = table
            .query()
            .only_if(filter)
            .limit(1)
            .select(Select::columns(&["content_hash", "vector"]))
            .execute()
            .await
            .map_err(|_| internal_error())?
            .try_collect::<Vec<_>>()
            .await
            .map_err(|_| internal_error())?;
        let Some(batch) = batches.first().filter(|batch| batch.num_rows() > 0) else {
            return Ok(None);
        };
        let hashes = batch
            .column_by_name("content_hash")
            .and_then(|array| array.as_any().downcast_ref::<StringArray>())
            .ok_or_else(internal_error)?;
        let vectors = batch
            .column_by_name("vector")
            .and_then(|array| array.as_any().downcast_ref::<FixedSizeListArray>())
            .ok_or_else(internal_error)?;
        let values = vectors.value(0);
        let values = values
            .as_any()
            .downcast_ref::<Float32Array>()
            .ok_or_else(internal_error)?;
        Ok(Some((hashes.value(0).to_owned(), values.values().to_vec())))
    }
}

impl VectorStore for LanceDbVectorStore {
    fn upsert<'a>(
        &'a self,
        record: VectorRecord,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move { self.upsert_records(vec![record]).await })
    }

    fn upsert_batch<'a>(
        &'a self,
        records: Vec<VectorRecord>,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move { self.upsert_records(records).await })
    }

    fn search<'a>(
        &'a self,
        query: VectorSearchQuery,
    ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>> {
        Box::pin(async move {
            query.validate()?;
            validate_lance_space(&query.space)?;
            let Some(table) = self.open_existing_space(&query.space).await? else {
                return Ok(Vec::new());
            };
            let filter = format!(
                "life_id = {} AND embedding_model = {} AND dimension = {}",
                sql_literal(&query.life_id),
                sql_literal(&query.space.embedding_model),
                query.space.dimension
            );
            let candidate_count = table
                .count_rows(Some(filter.clone()))
                .await
                .map_err(|_| internal_error())?;
            if candidate_count == 0 {
                return Ok(Vec::new());
            }
            let batches = table
                .vector_search(query.vector.clone())
                .map_err(|_| internal_error())?
                .distance_type(DistanceType::Cosine)
                .only_if(filter)
                .limit(candidate_count)
                .select(Select::columns(&["memory_id", "_distance"]))
                .execute()
                .await
                .map_err(|_| internal_error())?
                .try_collect::<Vec<_>>()
                .await
                .map_err(|_| internal_error())?;
            let mut hits = Vec::with_capacity(candidate_count);
            for batch in batches {
                let memory_ids = batch
                    .column_by_name("memory_id")
                    .and_then(|array| array.as_any().downcast_ref::<StringArray>())
                    .ok_or_else(internal_error)?;
                let distances = batch
                    .column_by_name("_distance")
                    .and_then(|array| array.as_any().downcast_ref::<Float32Array>())
                    .ok_or_else(internal_error)?;
                for row in 0..batch.num_rows() {
                    let score = (1.0 - distances.value(row)).clamp(-1.0, 1.0);
                    if !score.is_finite() {
                        return Err(internal_error());
                    }
                    if query.min_score.is_none_or(|minimum| score >= minimum) {
                        hits.push(VectorSearchHit {
                            memory_id: memory_ids.value(row).to_owned(),
                            score,
                        });
                    }
                }
            }
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
            let predicate = format!(
                "life_id = {} AND memory_id = {}",
                sql_literal(life_id),
                sql_literal(memory_id)
            );
            let _guard = self.mutation_lock.lock().await;
            let removed = self.delete_matching_all_spaces(&predicate).await?;
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
            let _guard = self.mutation_lock.lock().await;
            self.delete_matching_all_spaces(&format!("life_id = {}", sql_literal(life_id)))
                .await
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
            validate_lance_space(space)?;
            let _guard = self.mutation_lock.lock().await;
            let Some(table) = self.open_existing_space(space).await? else {
                return Err(VectorStoreError::new(
                    VectorStoreErrorCode::VectorNotFound,
                    "No vector index exists for this life, memory, and vector space.",
                    false,
                ));
            };
            let predicate = format!(
                "life_id = {} AND memory_id = {} AND embedding_model = {} AND dimension = {}",
                sql_literal(life_id),
                sql_literal(memory_id),
                sql_literal(&space.embedding_model),
                space.dimension
            );
            let count = table
                .count_rows(Some(predicate.clone()))
                .await
                .map_err(|_| internal_error())?;
            if count == 0 {
                return Err(VectorStoreError::new(
                    VectorStoreErrorCode::VectorNotFound,
                    "No vector index exists for this life, memory, and vector space.",
                    false,
                ));
            }
            table
                .delete(&predicate)
                .await
                .map_err(|_| internal_error())?;
            Ok(count)
        })
    }

    fn clear_space<'a>(
        &'a self,
        life_id: &'a str,
        space: &'a VectorSpace,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        Box::pin(async move {
            validate_identifier(life_id, "Life ID")?;
            validate_lance_space(space)?;
            let _guard = self.mutation_lock.lock().await;
            let Some(table) = self.open_existing_space(space).await? else {
                return Ok(0);
            };
            let predicate = format!(
                "life_id = {} AND embedding_model = {} AND dimension = {}",
                sql_literal(life_id),
                sql_literal(&space.embedding_model),
                space.dimension
            );
            let count = table
                .count_rows(Some(predicate.clone()))
                .await
                .map_err(|_| internal_error())?;
            if count > 0 {
                table
                    .delete(&predicate)
                    .await
                    .map_err(|_| internal_error())?;
            }
            Ok(count)
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
                validate_lance_space(space)?;
                let Some(table) = self.open_existing_space(space).await? else {
                    return Ok(0);
                };
                return table
                    .count_rows(Some(format!(
                        "life_id = {} AND embedding_model = {} AND dimension = {}",
                        sql_literal(life_id),
                        sql_literal(&space.embedding_model),
                        space.dimension
                    )))
                    .await
                    .map_err(|_| internal_error());
            }
            let mut count = 0usize;
            for (_, table) in self.all_space_tables().await? {
                count = count.saturating_add(
                    table
                        .count_rows(Some(format!("life_id = {}", sql_literal(life_id))))
                        .await
                        .map_err(|_| internal_error())?,
                );
            }
            Ok(count)
        })
    }

    fn health_check<'a>(
        &'a self,
        life_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move {
            validate_identifier(life_id, "Life ID")?;
            self.all_space_tables().await?;
            Ok(())
        })
    }
}

fn validate_lance_space(space: &VectorSpace) -> Result<(), VectorStoreError> {
    space.validate()?;
    if space.dimension > i32::MAX as usize || space.dimension > u32::MAX as usize {
        return Err(VectorStoreError::new(
            VectorStoreErrorCode::DimensionMismatch,
            "Vector dimension is not supported by the persistent vector store.",
            false,
        ));
    }
    Ok(())
}

fn sql_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn store_unavailable() -> VectorStoreError {
    VectorStoreError::new(
        VectorStoreErrorCode::StoreUnavailable,
        "The persistent vector store is unavailable.",
        true,
    )
}

fn internal_error() -> VectorStoreError {
    VectorStoreError::new(
        VectorStoreErrorCode::InternalError,
        "The persistent vector store operation failed.",
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector_store::InMemoryVectorStore;

    fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
        tauri::async_runtime::block_on(future)
    }

    fn space(model: &str, dimension: usize) -> VectorSpace {
        VectorSpace {
            embedding_model: model.to_owned(),
            dimension,
        }
    }

    fn record(life_id: &str, memory_id: &str, model: &str, vector: Vec<f32>) -> VectorRecord {
        VectorRecord {
            life_id: life_id.to_owned(),
            memory_id: memory_id.to_owned(),
            embedding_model: model.to_owned(),
            dimension: vector.len(),
            vector,
            content_hash: format!("hash-{memory_id}"),
        }
    }

    fn query(
        life_id: &str,
        model: &str,
        vector: Vec<f32>,
        limit: usize,
        min_score: Option<f32>,
    ) -> VectorSearchQuery {
        VectorSearchQuery {
            life_id: life_id.to_owned(),
            space: space(model, vector.len()),
            vector,
            limit,
            min_score,
        }
    }

    async fn contract(store: &dyn VectorStore) {
        store
            .upsert_batch(vec![
                record("life-a", "memory-b", "model-a", vec![1.0, 0.0]),
                record("life-a", "memory-a", "model-a", vec![1.0, 0.0]),
                record("life-a", "memory-c", "model-a", vec![0.0, 1.0]),
                record("life-b", "memory-z", "model-a", vec![1.0, 0.0]),
                record("life-a", "memory-model", "model-b", vec![1.0, 0.0]),
                record("life-a", "memory-dim", "model-a", vec![1.0, 0.0, 0.0]),
            ])
            .await
            .unwrap();
        let hits = store
            .search(query("life-a", "model-a", vec![1.0, 0.0], 2, Some(0.5)))
            .await
            .unwrap();
        assert_eq!(
            hits.iter()
                .map(|hit| hit.memory_id.as_str())
                .collect::<Vec<_>>(),
            vec!["memory-a", "memory-b"]
        );
        assert!(hits.iter().all(|hit| hit.score >= 0.5));
        let serialized_hit = serde_json::to_value(&hits[0]).unwrap();
        assert_eq!(serialized_hit.as_object().unwrap().len(), 2);
        assert!(serialized_hit.get("content").is_none());
        assert!(serialized_hit.get("vector").is_none());
        assert_eq!(store.count("life-a", None).await.unwrap(), 5);
        assert_eq!(store.delete("life-a", "memory-a").await.unwrap(), 1);
        assert_eq!(
            store.delete("life-a", "missing").await.unwrap_err().code,
            VectorStoreErrorCode::VectorNotFound
        );
        assert_eq!(
            store
                .clear_space("life-a", &space("model-b", 2))
                .await
                .unwrap(),
            1
        );
        assert_eq!(store.delete_by_life("life-a").await.unwrap(), 3);
        assert_eq!(store.count("life-b", None).await.unwrap(), 1);
    }

    #[test]
    fn first_open_creates_directory_and_reopen_preserves_vectors() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("vectors").join("lancedb");
            assert!(!root.exists());
            {
                let store = LanceDbVectorStore::open(&root).await.unwrap();
                assert!(root.is_dir());
                store
                    .upsert(record("life", "memory", "model", vec![1.0, 0.0]))
                    .await
                    .unwrap();
                assert_eq!(store.count("life", None).await.unwrap(), 1);
            }
            let reopened = LanceDbVectorStore::open(&root).await.unwrap();
            assert_eq!(reopened.count("life", None).await.unwrap(), 1);
            let hits = reopened
                .search(query("life", "model", vec![1.0, 0.0], 1, None))
                .await
                .unwrap();
            assert_eq!(hits[0].memory_id, "memory");
            assert_eq!(hits[0].score, 1.0);
            reopened.health_check("life").await.unwrap();
        });
    }

    #[test]
    fn upsert_replaces_vector_hash_and_dimension_without_duplicates() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let mut first = record("life", "memory", "model", vec![1.0, 0.0]);
            first.content_hash = "old-hash".into();
            store.upsert(first).await.unwrap();
            let mut replacement = record("life", "memory", "model", vec![0.0, 1.0]);
            replacement.content_hash = "new-hash".into();
            store.upsert(replacement).await.unwrap();
            assert_eq!(store.count("life", None).await.unwrap(), 1);
            assert_eq!(
                store
                    .read_record_for_test("life", "memory", &space("model", 2))
                    .await
                    .unwrap(),
                Some(("new-hash".into(), vec![0.0, 1.0]))
            );

            store
                .upsert(record("life", "memory", "model", vec![1.0, 0.0, 0.0]))
                .await
                .unwrap();
            assert_eq!(store.count("life", None).await.unwrap(), 1);
            assert_eq!(
                store.count("life", Some(&space("model", 2))).await.unwrap(),
                0
            );
            assert_eq!(
                store.count("life", Some(&space("model", 3))).await.unwrap(),
                1
            );
        });
    }

    #[test]
    fn batch_validation_is_atomic_and_duplicate_key_uses_last_record() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let mut invalid = record("life", "invalid", "model", vec![1.0, 0.0]);
            invalid.vector[0] = f32::NAN;
            let error = store
                .upsert_batch(vec![
                    record("life", "valid", "model", vec![1.0, 0.0]),
                    invalid,
                ])
                .await
                .unwrap_err();
            assert_eq!(error.code, VectorStoreErrorCode::InvalidVector);
            assert_eq!(store.count("life", None).await.unwrap(), 0);

            let mut last = record("life", "same", "model", vec![0.0, 1.0]);
            last.content_hash = "last".into();
            store
                .upsert_batch(vec![record("life", "same", "model", vec![1.0, 0.0]), last])
                .await
                .unwrap();
            assert_eq!(store.count("life", None).await.unwrap(), 1);
            assert_eq!(
                store
                    .read_record_for_test("life", "same", &space("model", 2))
                    .await
                    .unwrap(),
                Some(("last".into(), vec![0.0, 1.0]))
            );
        });
    }

    #[test]
    fn lance_and_in_memory_share_behavior_contract() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let lance = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let memory = InMemoryVectorStore::new();
            contract(&memory).await;
            contract(&lance).await;
        });
    }

    #[test]
    fn model_dimension_life_and_space_cleanup_are_isolated_after_reopen() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            {
                let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
                store
                    .upsert_batch(vec![
                        record("life-a", "a", "model-a", vec![1.0, 0.0]),
                        record("life-a", "b", "model-b", vec![1.0, 0.0]),
                        record("life-a", "c", "model-a", vec![1.0, 0.0, 0.0]),
                        record("life-b", "d", "model-a", vec![1.0, 0.0]),
                    ])
                    .await
                    .unwrap();
                assert_eq!(
                    store
                        .clear_space("life-a", &space("model-a", 2))
                        .await
                        .unwrap(),
                    1
                );
                assert_eq!(store.count("life-a", None).await.unwrap(), 2);
                assert_eq!(store.count("life-b", None).await.unwrap(), 1);
            }
            let reopened = LanceDbVectorStore::open(temp.path()).await.unwrap();
            assert_eq!(reopened.count("life-a", None).await.unwrap(), 2);
            assert_eq!(reopened.count("life-b", None).await.unwrap(), 1);
        });
    }

    #[test]
    fn file_path_returns_sanitized_store_unavailable_error() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let file = temp.path().join("not-a-directory");
            std::fs::write(&file, b"file").unwrap();
            let error = LanceDbVectorStore::open(&file).await.err().unwrap();
            assert_eq!(error.code, VectorStoreErrorCode::StoreUnavailable);
            assert!(!error.message.contains(file.to_string_lossy().as_ref()));
        });
    }

    #[test]
    fn invalid_vectors_are_rejected_before_table_creation() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            for vector in [vec![], vec![f32::NAN], vec![f32::INFINITY]] {
                assert_eq!(
                    store
                        .upsert(record("life", "memory", "model", vector))
                        .await
                        .unwrap_err()
                        .code,
                    VectorStoreErrorCode::InvalidVector
                );
            }
            let mut wrong_dimension = record("life", "memory", "model", vec![1.0]);
            wrong_dimension.dimension = 2;
            assert_eq!(
                store.upsert(wrong_dimension).await.unwrap_err().code,
                VectorStoreErrorCode::DimensionMismatch
            );
            assert!(store.table_names().await.unwrap().is_empty());
        });
    }

    #[test]
    fn concurrent_first_writes_initialize_one_space_safely() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let writes = (0..8).map(|index| {
                store.upsert(record(
                    "life",
                    &format!("memory-{index}"),
                    "model",
                    vec![1.0, index as f32 + 1.0],
                ))
            });
            for result in futures::future::join_all(writes).await {
                result.unwrap();
            }
            assert_eq!(store.count("life", None).await.unwrap(), 8);
            assert_eq!(store.table_names().await.unwrap().len(), 1);
        });
    }

    #[test]
    fn table_name_is_stable_and_contains_no_model_text() {
        let dangerous = space("model/name'; DROP TABLE memory;--", 384);
        let first = LanceDbVectorStore::table_name(&dangerous);
        assert_eq!(first, LanceDbVectorStore::table_name(&dangerous));
        assert!(first.starts_with(TABLE_PREFIX));
        assert!(!first.contains("model"));
        assert!(first.chars().all(|character| character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || character == '_'));
        assert_ne!(first, LanceDbVectorStore::table_name(&space("other", 384)));
        assert_ne!(
            first,
            LanceDbVectorStore::table_name(&space("model/name'; DROP TABLE memory;--", 768))
        );
    }
}
