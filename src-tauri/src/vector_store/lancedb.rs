use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use arrow_array::{
    types::Float32Type, Array, FixedSizeListArray, Float32Array, Int32Array, Int64Array,
    RecordBatch, RecordBatchIterator, StringArray, UInt32Array,
};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use futures::{lock::Mutex, TryStreamExt};
use lancedb::{
    connection::Connection,
    query::{ExecutableQuery, QueryBase, Select},
    DistanceType, Table,
};

use super::{
    validate_generation_search_metadata, validate_hash, validate_identifier,
    ConditionalGenerationDeleteOutcome, GenerationSearchMetadata, GenerationVectorRecord,
    GenerationVectorSearchHit, GenerationVectorSearchQuery, VectorGenerationContext,
    VectorGenerationId, VectorMetadataSample, VectorRecord, VectorSpace, VectorStore,
    VectorStoreError, VectorStoreErrorCode, VectorStoreFuture,
};

#[cfg(test)]
use super::{VectorSearchHit, VectorSearchQuery};

const TABLE_PREFIX: &str = "vs_";
const SPACE_MODEL_METADATA: &str = "digital_life.embedding_model";
const SPACE_DIMENSION_METADATA: &str = "digital_life.dimension";
const GENERATION_TABLE: &str = "vs_generation";
const GENERATION_ID_METADATA: &str = "digital_life.generation_id";
const GENERATION_DESCRIPTOR_METADATA: &str = "digital_life.descriptor_hash";
const GENERATION_DIMENSION_METADATA: &str = "digital_life.generation_dimension";
const GENERATION_MARKER_FILE: &str = ".digital_life_generation_v1";
const GENERATION_MARKER_CONTENT: &[u8] = b"digital-life-generation-v1\n";

/// Persistent, rebuildable LanceDB vector index.
///
/// Construction receives an explicit derived-data directory. It never opens
/// SQLite and is not registered as an application-global default.
///
/// Legacy space-keyed tables and generation-aware tables may coexist in
/// different directories. A generation store is one Lance directory per generation.
pub struct LanceDbVectorStore {
    connection: Connection,
    root: PathBuf,
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
            root: root.to_path_buf(),
            table_init_lock: Mutex::new(()),
            mutation_lock: Mutex::new(()),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
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

    fn generation_schema(context: &VectorGenerationContext) -> Result<SchemaRef, VectorStoreError> {
        if context.dimension() == 0 || context.dimension() > super::MAX_VECTOR_DIMENSION {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationDimensionMismatch,
                "The vector generation dimension is invalid.",
                false,
            ));
        }
        if context.dimension() > i32::MAX as usize {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationDimensionMismatch,
                "The vector generation dimension is invalid.",
                false,
            ));
        }
        let mut metadata = HashMap::new();
        metadata.insert(
            GENERATION_ID_METADATA.to_owned(),
            context.generation_id().as_str().to_owned(),
        );
        metadata.insert(
            GENERATION_DESCRIPTOR_METADATA.to_owned(),
            context.descriptor_hash().to_owned(),
        );
        metadata.insert(
            GENERATION_DIMENSION_METADATA.to_owned(),
            context.dimension().to_string(),
        );
        Ok(Arc::new(Schema::new_with_metadata(
            vec![
                Field::new("generation_id", DataType::Utf8, false),
                Field::new("life_id", DataType::Utf8, false),
                Field::new("memory_id", DataType::Utf8, false),
                Field::new("memory_revision", DataType::Int64, false),
                Field::new("content_hash", DataType::Utf8, false),
                Field::new("descriptor_hash", DataType::Utf8, false),
                Field::new("dimension", DataType::Int32, false),
                Field::new(
                    "vector",
                    DataType::FixedSizeList(
                        Arc::new(Field::new("item", DataType::Float32, true)),
                        context.dimension() as i32,
                    ),
                    false,
                ),
            ],
            metadata,
        )))
    }

    fn generation_records_batch(
        records: &[GenerationVectorRecord],
        context: &VectorGenerationContext,
    ) -> Result<(SchemaRef, RecordBatch), VectorStoreError> {
        let schema = Self::generation_schema(context)?;
        let vectors = FixedSizeListArray::from_iter_primitive::<Float32Type, _, _>(
            records.iter().map(|record| {
                Some(
                    record
                        .vector()
                        .iter()
                        .copied()
                        .map(Some)
                        .collect::<Vec<_>>(),
                )
            }),
            context.dimension() as i32,
        );
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(StringArray::from_iter_values(
                    records.iter().map(|r| r.generation_id().as_str()),
                )),
                Arc::new(StringArray::from_iter_values(
                    records.iter().map(|r| r.life_id()),
                )),
                Arc::new(StringArray::from_iter_values(
                    records.iter().map(|r| r.memory_id()),
                )),
                Arc::new(Int64Array::from_iter_values(
                    records.iter().map(|r| r.memory_revision()),
                )),
                Arc::new(StringArray::from_iter_values(
                    records.iter().map(|r| r.content_hash()),
                )),
                Arc::new(StringArray::from_iter_values(
                    records.iter().map(|r| r.descriptor_hash()),
                )),
                Arc::new(Int32Array::from_iter_values(
                    records.iter().map(|r| r.dimension() as i32),
                )),
                Arc::new(vectors),
            ],
        )
        .map_err(|_| write_failed())?;
        Ok((schema, batch))
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

    async fn open_generation_table(
        &self,
        context: &VectorGenerationContext,
    ) -> Result<Table, VectorStoreError> {
        let marker = self.generation_marker_state()?;
        let names = self
            .connection
            .table_names()
            .execute()
            .await
            .map_err(|_| corrupt())?;
        let has_table = names.iter().any(|n| n == GENERATION_TABLE);
        if !marker {
            return if has_table {
                Err(corrupt())
            } else {
                Err(generation_not_found())
            };
        }
        if !has_table {
            return Err(corrupt());
        }
        let table = self
            .connection
            .open_table(GENERATION_TABLE)
            .execute()
            .await
            .map_err(|_| corrupt())?;
        self.validate_generation_table(&table, context).await?;
        Ok(table)
    }

    async fn ensure_generation_table(
        &self,
        context: &VectorGenerationContext,
    ) -> Result<Table, VectorStoreError> {
        let _guard = self.table_init_lock.lock().await;
        match self.open_generation_table(context).await {
            Ok(table) => return Ok(table),
            Err(error) if error.code != VectorStoreErrorCode::GenerationNotFound => {
                return Err(error)
            }
            Err(_) => {}
        }
        self.write_generation_marker()?;
        let table = self
            .connection
            .create_empty_table(GENERATION_TABLE, Self::generation_schema(context)?)
            .execute()
            .await
            .map_err(|_| store_unavailable())?;
        self.validate_generation_table(&table, context).await?;
        Ok(table)
    }

    fn generation_marker_path(&self) -> PathBuf {
        self.root.join(GENERATION_MARKER_FILE)
    }

    fn generation_marker_state(&self) -> Result<bool, VectorStoreError> {
        if !self.root.exists() {
            return Ok(false);
        }
        if !self.root.is_dir() {
            return Err(corrupt());
        }
        match std::fs::read(self.generation_marker_path()) {
            Ok(content) if content == GENERATION_MARKER_CONTENT => Ok(true),
            Ok(_) => Err(corrupt()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(_) => Err(corrupt()),
        }
    }

    fn write_generation_marker(&self) -> Result<(), VectorStoreError> {
        std::fs::write(self.generation_marker_path(), GENERATION_MARKER_CONTENT)
            .map_err(|_| store_unavailable())
    }

    async fn validate_generation_table(
        &self,
        table: &Table,
        expected: &VectorGenerationContext,
    ) -> Result<(), VectorStoreError> {
        let schema = table.schema().await.map_err(|_| corrupt())?;
        let expected_schema = Self::generation_schema(expected)?;
        if schema.fields() != expected_schema.fields()
            || schema.metadata() != expected_schema.metadata()
        {
            return Err(schema_mismatch());
        }
        Ok(())
    }

    async fn create_generation_inner(
        &self,
        context: &VectorGenerationContext,
    ) -> Result<(), VectorStoreError> {
        let _ = self.ensure_generation_table(context).await?;
        Ok(())
    }

    async fn upsert_generation_inner(
        &self,
        context: &VectorGenerationContext,
        record: GenerationVectorRecord,
    ) -> Result<(), VectorStoreError> {
        record.validate_against(context)?;
        let _guard = self.mutation_lock.lock().await;
        let table = self.ensure_generation_table(context).await?;
        let (schema, batch) =
            Self::generation_records_batch(std::slice::from_ref(&record), context)?;
        let reader = RecordBatchIterator::new(vec![Ok(batch)], schema);
        let mut merge = table.merge_insert(&["generation_id", "life_id", "memory_id"]);
        merge
            .when_matched_update_all(None)
            .when_not_matched_insert_all();
        merge
            .execute(Box::new(reader))
            .await
            .map_err(|_| write_failed())?;
        Ok(())
    }

    async fn delete_generation_memory_inner(
        &self,
        context: &VectorGenerationContext,
        life_id: &str,
        memory_id: &str,
    ) -> Result<(), VectorStoreError> {
        validate_identifier(life_id, "Life ID")?;
        validate_identifier(memory_id, "Memory ID")?;
        let _guard = self.mutation_lock.lock().await;
        let table = match self.open_generation_table(context).await {
            Ok(table) => table,
            Err(error) if error.code == VectorStoreErrorCode::GenerationNotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let predicate = format!(
            "generation_id = {} AND life_id = {} AND memory_id = {}",
            sql_literal(context.generation_id().as_str()),
            sql_literal(life_id),
            sql_literal(memory_id)
        );
        table
            .delete(&predicate)
            .await
            .map_err(|_| delete_failed())?;
        Ok(())
    }

    async fn delete_generation_memory_if_matches_inner(
        &self,
        context: &VectorGenerationContext,
        life_id: &str,
        memory_id: &str,
        expected_revision: i64,
        expected_content_hash: &str,
    ) -> Result<ConditionalGenerationDeleteOutcome, VectorStoreError> {
        // This one guard remains live through exact requery, validation, full
        // predicate Delete, and the postcondition requery.
        let _guard = self.mutation_lock.lock().await;
        self.delete_generation_memory_if_matches_under_lock(
            context,
            life_id,
            memory_id,
            expected_revision,
            expected_content_hash,
        )
        .await
    }

    async fn delete_generation_memory_if_matches_under_lock(
        &self,
        context: &VectorGenerationContext,
        life_id: &str,
        memory_id: &str,
        expected_revision: i64,
        expected_content_hash: &str,
    ) -> Result<ConditionalGenerationDeleteOutcome, VectorStoreError> {
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
        let current = self
            .get_generation_metadata_inner(context, life_id, memory_id)
            .await?;
        let Some(current) = current else {
            return Ok(ConditionalGenerationDeleteOutcome::Absent);
        };
        if current.generation_id != context.generation_id().as_str()
            || current.life_id != life_id
            || current.memory_id != memory_id
            || current.descriptor_hash != context.descriptor_hash()
            || current.dimension != context.dimension()
        {
            return Err(corrupt());
        }
        if current.memory_revision != expected_revision
            || current.content_hash != expected_content_hash
        {
            return Ok(ConditionalGenerationDeleteOutcome::IdentityMismatch);
        }
        let table = match self.open_generation_table(context).await {
            Ok(table) => table,
            Err(error) if error.code == VectorStoreErrorCode::GenerationNotFound => {
                return Ok(ConditionalGenerationDeleteOutcome::Absent)
            }
            Err(error) => return Err(error),
        };
        let predicate = format!(
            "generation_id = {} AND life_id = {} AND memory_id = {} \
             AND memory_revision = {} AND content_hash = {} \
             AND descriptor_hash = {} AND dimension = {}",
            sql_literal(context.generation_id().as_str()),
            sql_literal(life_id),
            sql_literal(memory_id),
            expected_revision,
            sql_literal(expected_content_hash),
            sql_literal(context.descriptor_hash()),
            context.dimension(),
        );
        table
            .delete(&predicate)
            .await
            .map_err(|_| delete_failed())?;
        match self
            .get_generation_metadata_inner(context, life_id, memory_id)
            .await?
        {
            None => Ok(ConditionalGenerationDeleteOutcome::Deleted),
            Some(_) => Err(delete_failed()),
        }
    }

    async fn delete_generation_life_inner(
        &self,
        context: &VectorGenerationContext,
        life_id: &str,
    ) -> Result<(), VectorStoreError> {
        validate_identifier(life_id, "Life ID")?;
        let _guard = self.mutation_lock.lock().await;
        let table = match self.open_generation_table(context).await {
            Ok(table) => table,
            Err(error) if error.code == VectorStoreErrorCode::GenerationNotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let predicate = format!(
            "generation_id = {} AND life_id = {}",
            sql_literal(context.generation_id().as_str()),
            sql_literal(life_id)
        );
        table
            .delete(&predicate)
            .await
            .map_err(|_| delete_failed())?;
        Ok(())
    }

    async fn search_generation_inner(
        &self,
        context: &VectorGenerationContext,
        query: GenerationVectorSearchQuery,
    ) -> Result<Vec<GenerationVectorSearchHit>, VectorStoreError> {
        query.validate_against(context)?;
        let table = self.open_generation_table(context).await?;
        let filter = format!(
            "generation_id = {} AND life_id = {}",
            sql_literal(context.generation_id().as_str()),
            sql_literal(query.life_id())
        );
        let candidate_count = table
            .count_rows(Some(filter.clone()))
            .await
            .map_err(|_| read_failed())?;
        if candidate_count == 0 {
            return Ok(Vec::new());
        }
        let batches = table
            .vector_search(query.vector().to_vec())
            .map_err(|_| read_failed())?
            .distance_type(DistanceType::Cosine)
            .only_if(filter)
            .limit(candidate_count)
            .select(Select::columns(&[
                "generation_id",
                "life_id",
                "memory_id",
                "memory_revision",
                "content_hash",
                "descriptor_hash",
                "dimension",
                "_distance",
            ]))
            .execute()
            .await
            .map_err(|_| read_failed())?
            .try_collect::<Vec<_>>()
            .await
            .map_err(|_| read_failed())?;
        let mut hits = Vec::with_capacity(candidate_count);
        for batch in batches {
            let generation_ids = column_string(&batch, "generation_id")?;
            let life_ids = column_string(&batch, "life_id")?;
            let memory_ids = column_string(&batch, "memory_id")?;
            let revisions = batch
                .column_by_name("memory_revision")
                .and_then(|array| array.as_any().downcast_ref::<Int64Array>())
                .ok_or_else(read_failed)?;
            let content_hashes = column_string(&batch, "content_hash")?;
            let descriptor_hashes = column_string(&batch, "descriptor_hash")?;
            let dimensions = batch
                .column_by_name("dimension")
                .and_then(|array| array.as_any().downcast_ref::<Int32Array>())
                .ok_or_else(read_failed)?;
            let distances = batch
                .column_by_name("_distance")
                .and_then(|array| array.as_any().downcast_ref::<Float32Array>())
                .ok_or_else(read_failed)?;
            for row in 0..batch.num_rows() {
                let dimension = dimensions.value(row);
                if dimension < 0 || life_ids.value(row) != query.life_id() {
                    return Err(corrupt());
                }
                validate_generation_search_metadata(&GenerationSearchMetadata {
                    context,
                    generation_id: generation_ids.value(row),
                    life_id: life_ids.value(row),
                    memory_id: memory_ids.value(row),
                    memory_revision: revisions.value(row),
                    content_hash: content_hashes.value(row),
                    descriptor_hash: descriptor_hashes.value(row),
                    dimension: dimension as usize,
                })?;
                let score = (1.0 - distances.value(row)).clamp(-1.0, 1.0);
                if !score.is_finite() {
                    return Err(read_failed());
                }
                if query.min_score().is_none_or(|minimum| score >= minimum) {
                    hits.push(GenerationVectorSearchHit {
                        memory_id: memory_ids.value(row).to_owned(),
                        memory_revision: revisions.value(row),
                        content_hash: content_hashes.value(row).to_owned(),
                        score,
                    });
                }
            }
        }
        hits.sort_by(|left, right| {
            right
                .score()
                .total_cmp(&left.score())
                .then_with(|| left.memory_id().cmp(right.memory_id()))
        });
        hits.truncate(query.limit());
        Ok(hits)
    }

    async fn count_generation_inner(
        &self,
        context: &VectorGenerationContext,
        life_id: Option<&str>,
    ) -> Result<usize, VectorStoreError> {
        if let Some(life_id) = life_id {
            validate_identifier(life_id, "Life ID")?;
        }
        let table = self.open_generation_table(context).await?;
        let predicate = match life_id {
            Some(life_id) => format!(
                "generation_id = {} AND life_id = {}",
                sql_literal(context.generation_id().as_str()),
                sql_literal(life_id)
            ),
            None => format!(
                "generation_id = {}",
                sql_literal(context.generation_id().as_str())
            ),
        };
        table
            .count_rows(Some(predicate))
            .await
            .map_err(|_| read_failed())
    }

    async fn sample_generation_metadata_inner(
        &self,
        context: &VectorGenerationContext,
        limit: usize,
    ) -> Result<Vec<VectorMetadataSample>, VectorStoreError> {
        if limit == 0 || limit > super::MAX_SEARCH_LIMIT {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::InvalidLimit,
                "Metadata sample limit must be within the supported range.",
                false,
            ));
        }
        let table = self.open_generation_table(context).await?;
        let filter = format!(
            "generation_id = {}",
            sql_literal(context.generation_id().as_str())
        );
        let batches = table
            .query()
            .only_if(filter)
            .limit(limit)
            .select(Select::columns(&[
                "generation_id",
                "life_id",
                "memory_id",
                "memory_revision",
                "content_hash",
                "descriptor_hash",
                "dimension",
            ]))
            .execute()
            .await
            .map_err(|_| read_failed())?
            .try_collect::<Vec<_>>()
            .await
            .map_err(|_| read_failed())?;
        let mut samples = Vec::new();
        for batch in batches {
            let generation_ids = column_string(&batch, "generation_id")?;
            let life_ids = column_string(&batch, "life_id")?;
            let memory_ids = column_string(&batch, "memory_id")?;
            let revisions = batch
                .column_by_name("memory_revision")
                .and_then(|a| a.as_any().downcast_ref::<Int64Array>())
                .ok_or_else(read_failed)?;
            let content_hashes = column_string(&batch, "content_hash")?;
            let descriptor_hashes = column_string(&batch, "descriptor_hash")?;
            let dimensions = batch
                .column_by_name("dimension")
                .and_then(|a| a.as_any().downcast_ref::<Int32Array>())
                .ok_or_else(read_failed)?;
            for row in 0..batch.num_rows() {
                samples.push(VectorMetadataSample {
                    generation_id: generation_ids.value(row).to_owned(),
                    life_id: life_ids.value(row).to_owned(),
                    memory_id: memory_ids.value(row).to_owned(),
                    memory_revision: revisions.value(row),
                    content_hash: content_hashes.value(row).to_owned(),
                    descriptor_hash: descriptor_hashes.value(row).to_owned(),
                    dimension: dimensions.value(row) as usize,
                });
                if samples.len() >= limit {
                    break;
                }
            }
            if samples.len() >= limit {
                break;
            }
        }
        Ok(samples)
    }

    async fn list_generation_metadata_inner(
        &self,
        context: &VectorGenerationContext,
    ) -> Result<Vec<VectorMetadataSample>, VectorStoreError> {
        let table = self.open_generation_table(context).await?;
        let filter = format!(
            "generation_id = {}",
            sql_literal(context.generation_id().as_str())
        );
        let batches = table
            .query()
            .only_if(filter)
            .select(Select::columns(&[
                "generation_id",
                "life_id",
                "memory_id",
                "memory_revision",
                "content_hash",
                "descriptor_hash",
                "dimension",
            ]))
            .execute()
            .await
            .map_err(|_| read_failed())?
            .try_collect::<Vec<_>>()
            .await
            .map_err(|_| read_failed())?;
        let mut samples = Vec::new();
        for batch in batches {
            let generation_ids = column_string(&batch, "generation_id")?;
            let life_ids = column_string(&batch, "life_id")?;
            let memory_ids = column_string(&batch, "memory_id")?;
            let revisions = batch
                .column_by_name("memory_revision")
                .and_then(|a| a.as_any().downcast_ref::<Int64Array>())
                .ok_or_else(read_failed)?;
            let content_hashes = column_string(&batch, "content_hash")?;
            let descriptor_hashes = column_string(&batch, "descriptor_hash")?;
            let dimensions = batch
                .column_by_name("dimension")
                .and_then(|a| a.as_any().downcast_ref::<Int32Array>())
                .ok_or_else(read_failed)?;
            for row in 0..batch.num_rows() {
                samples.push(VectorMetadataSample {
                    generation_id: generation_ids.value(row).to_owned(),
                    life_id: life_ids.value(row).to_owned(),
                    memory_id: memory_ids.value(row).to_owned(),
                    memory_revision: revisions.value(row),
                    content_hash: content_hashes.value(row).to_owned(),
                    descriptor_hash: descriptor_hashes.value(row).to_owned(),
                    dimension: dimensions.value(row) as usize,
                });
            }
        }
        samples.sort_by(|left, right| {
            left.life_id
                .cmp(&right.life_id)
                .then_with(|| left.memory_id.cmp(&right.memory_id))
        });
        Ok(samples)
    }

    async fn health_check_generation_inner(
        &self,
        context: &VectorGenerationContext,
    ) -> Result<(), VectorStoreError> {
        let table = self.open_generation_table(context).await?;
        let mut stream = table
            .query()
            .select(Select::columns(&[
                "generation_id",
                "life_id",
                "memory_id",
                "memory_revision",
                "content_hash",
                "descriptor_hash",
                "dimension",
            ]))
            .execute()
            .await
            .map_err(|_| corrupt())?;
        let mut keys = HashSet::new();
        while let Some(batch) = stream.try_next().await.map_err(|_| corrupt())? {
            let generation_ids = column_string(&batch, "generation_id").map_err(|_| corrupt())?;
            let life_ids = column_string(&batch, "life_id").map_err(|_| corrupt())?;
            let memory_ids = column_string(&batch, "memory_id").map_err(|_| corrupt())?;
            let revisions = batch
                .column_by_name("memory_revision")
                .and_then(|array| array.as_any().downcast_ref::<Int64Array>())
                .ok_or_else(corrupt)?;
            let content_hashes = column_string(&batch, "content_hash").map_err(|_| corrupt())?;
            let descriptor_hashes =
                column_string(&batch, "descriptor_hash").map_err(|_| corrupt())?;
            let dimensions = batch
                .column_by_name("dimension")
                .and_then(|array| array.as_any().downcast_ref::<Int32Array>())
                .ok_or_else(corrupt)?;
            for row in 0..batch.num_rows() {
                if generation_ids.is_null(row)
                    || life_ids.is_null(row)
                    || memory_ids.is_null(row)
                    || revisions.is_null(row)
                    || content_hashes.is_null(row)
                    || descriptor_hashes.is_null(row)
                    || dimensions.is_null(row)
                {
                    return Err(corrupt());
                }
                let generation_id = generation_ids.value(row);
                let life_id = life_ids.value(row);
                let memory_id = memory_ids.value(row);
                let descriptor_hash = descriptor_hashes.value(row);
                if generation_id != context.generation_id().as_str()
                    || descriptor_hash != context.descriptor_hash()
                    || dimensions.value(row) != context.dimension() as i32
                    || revisions.value(row) < 0
                    || validate_identifier(life_id, "Life ID").is_err()
                    || validate_identifier(memory_id, "Memory ID").is_err()
                    || super::validate_hash(content_hashes.value(row), "Content hash").is_err()
                {
                    return Err(corrupt());
                }
                if !keys.insert((
                    generation_id.to_owned(),
                    life_id.to_owned(),
                    memory_id.to_owned(),
                )) {
                    return Err(corrupt());
                }
            }
        }
        Ok(())
    }

    pub(crate) async fn drop_generation_directory(root: &Path) -> Result<(), VectorStoreError> {
        if !root.exists() {
            return Ok(());
        }
        if !root.is_dir() {
            return Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationDropFailed,
                "The vector generation could not be dropped.",
                true,
            ));
        }
        // Best-effort recursive delete without surfacing absolute paths.
        match std::fs::remove_dir_all(root) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error)
                if error.kind() == std::io::ErrorKind::PermissionDenied
                    || error.raw_os_error() == Some(32) /* Windows sharing violation */ =>
            {
                Err(VectorStoreError::new(
                    VectorStoreErrorCode::GenerationLocked,
                    "The vector generation is locked by an open handle.",
                    true,
                ))
            }
            Err(_) => Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationDropFailed,
                "The vector generation could not be dropped.",
                true,
            )),
        }
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

    async fn get_generation_metadata_inner(
        &self,
        context: &VectorGenerationContext,
        life_id: &str,
        memory_id: &str,
    ) -> Result<Option<VectorMetadataSample>, VectorStoreError> {
        validate_identifier(life_id, "Life ID")?;
        validate_identifier(memory_id, "Memory ID")?;
        let table = match self.open_generation_table(context).await {
            Ok(table) => table,
            Err(error) if error.code == VectorStoreErrorCode::GenerationNotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let predicate = format!(
            "generation_id = {} AND life_id = {} AND memory_id = {}",
            sql_literal(context.generation_id().as_str()),
            sql_literal(life_id),
            sql_literal(memory_id)
        );
        let batches = table
            .query()
            .only_if(predicate)
            .limit(2)
            .select(Select::columns(&[
                "generation_id",
                "life_id",
                "memory_id",
                "memory_revision",
                "content_hash",
                "descriptor_hash",
                "dimension",
            ]))
            .execute()
            .await
            .map_err(|_| read_failed())?
            .try_collect::<Vec<_>>()
            .await
            .map_err(|_| read_failed())?;
        let mut total = 0usize;
        let mut result = None;
        for batch in &batches {
            total += batch.num_rows();
            if total > 1 {
                return Err(VectorStoreError::new(
                    VectorStoreErrorCode::GenerationCorrupt,
                    "Duplicate generation vector identity detected.",
                    false,
                ));
            }
            let generation_ids = column_string(batch, "generation_id")?;
            let life_ids = column_string(batch, "life_id")?;
            let memory_ids = column_string(batch, "memory_id")?;
            let revisions = batch
                .column_by_name("memory_revision")
                .and_then(|a| a.as_any().downcast_ref::<Int64Array>())
                .ok_or_else(read_failed)?;
            let content_hashes = column_string(batch, "content_hash")?;
            let descriptor_hashes = column_string(batch, "descriptor_hash")?;
            let dimensions = batch
                .column_by_name("dimension")
                .and_then(|a| a.as_any().downcast_ref::<Int32Array>())
                .ok_or_else(read_failed)?;
            for row in 0..batch.num_rows() {
                result = Some(VectorMetadataSample {
                    generation_id: generation_ids.value(row).to_owned(),
                    life_id: life_ids.value(row).to_owned(),
                    memory_id: memory_ids.value(row).to_owned(),
                    memory_revision: revisions.value(row),
                    content_hash: content_hashes.value(row).to_owned(),
                    descriptor_hash: descriptor_hashes.value(row).to_owned(),
                    dimension: dimensions.value(row) as usize,
                });
            }
        }
        Ok(result)
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

    #[cfg(test)]
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

    fn search_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        query: GenerationVectorSearchQuery,
    ) -> VectorStoreFuture<'a, Result<Vec<GenerationVectorSearchHit>, VectorStoreError>> {
        Box::pin(async move { self.search_generation_inner(context, query).await })
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

    fn create_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move { self.create_generation_inner(context).await })
    }

    fn upsert_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        record: GenerationVectorRecord,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move { self.upsert_generation_inner(context, record).await })
    }

    fn delete_generation_memory<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        life_id: &'a str,
        memory_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move {
            self.delete_generation_memory_inner(context, life_id, memory_id)
                .await
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
            self.delete_generation_memory_if_matches_inner(
                context,
                life_id,
                memory_id,
                expected_revision,
                expected_content_hash,
            )
            .await
        })
    }

    fn delete_generation_life<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        life_id: &'a str,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move { self.delete_generation_life_inner(context, life_id).await })
    }

    fn count_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        life_id: Option<&'a str>,
    ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
        Box::pin(async move { self.count_generation_inner(context, life_id).await })
    }

    fn sample_generation_metadata<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
        limit: usize,
    ) -> VectorStoreFuture<'a, Result<Vec<VectorMetadataSample>, VectorStoreError>> {
        Box::pin(async move { self.sample_generation_metadata_inner(context, limit).await })
    }

    fn list_generation_metadata<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
    ) -> VectorStoreFuture<'a, Result<Vec<VectorMetadataSample>, VectorStoreError>> {
        Box::pin(async move { self.list_generation_metadata_inner(context).await })
    }

    fn health_check_generation<'a>(
        &'a self,
        context: &'a VectorGenerationContext,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        Box::pin(async move { self.health_check_generation_inner(context).await })
    }

    fn drop_generation<'a>(
        &'a self,
        generation_id: &'a VectorGenerationId,
    ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
        // Complete persistent drops are registry-owned so cached handles are released
        // before the generation directory is removed.
        Box::pin(async move {
            let _ = generation_id;
            Err(VectorStoreError::new(
                VectorStoreErrorCode::GenerationDropRequiresRegistry,
                "Persistent vector generation drop requires the registry.",
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
        Box::pin(async move {
            self.get_generation_metadata_inner(context, life_id, memory_id)
                .await
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

fn write_failed() -> VectorStoreError {
    VectorStoreError::new(
        VectorStoreErrorCode::VectorWriteFailed,
        "The vector write failed.",
        true,
    )
}

fn delete_failed() -> VectorStoreError {
    VectorStoreError::new(
        VectorStoreErrorCode::VectorDeleteFailed,
        "The vector delete failed.",
        true,
    )
}

fn read_failed() -> VectorStoreError {
    VectorStoreError::new(
        VectorStoreErrorCode::VectorReadFailed,
        "The vector read failed.",
        true,
    )
}

fn schema_mismatch() -> VectorStoreError {
    VectorStoreError::new(
        VectorStoreErrorCode::GenerationSchemaMismatch,
        "The vector generation schema does not match.",
        false,
    )
}

fn corrupt() -> VectorStoreError {
    VectorStoreError::new(
        VectorStoreErrorCode::GenerationCorrupt,
        "The vector generation is corrupt.",
        true,
    )
}

fn generation_not_found() -> VectorStoreError {
    VectorStoreError::new(
        VectorStoreErrorCode::GenerationNotFound,
        "The vector generation was not found.",
        true,
    )
}

fn column_string<'a>(
    batch: &'a RecordBatch,
    name: &str,
) -> Result<&'a StringArray, VectorStoreError> {
    batch
        .column_by_name(name)
        .and_then(|array| array.as_any().downcast_ref::<StringArray>())
        .ok_or_else(read_failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vector_store::InMemoryVectorStore;
    use std::{
        sync::{mpsc, Arc},
        thread,
    };

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

    fn gen_context(id: &str, dim: usize) -> VectorGenerationContext {
        VectorGenerationContext::new(
            VectorGenerationId::parse(id).unwrap(),
            format!("desc-{id}"),
            dim,
        )
        .unwrap()
    }

    fn gen_record(
        context: &VectorGenerationContext,
        life: &str,
        memory: &str,
        revision: i64,
        vector: Vec<f32>,
    ) -> GenerationVectorRecord {
        GenerationVectorRecord::try_new(
            context.generation_id().clone(),
            life,
            memory,
            revision,
            format!("content-{memory}"),
            context.descriptor_hash(),
            vector,
        )
        .unwrap()
    }

    async fn append_generation_records(
        store: &LanceDbVectorStore,
        context: &VectorGenerationContext,
        records: &[GenerationVectorRecord],
    ) {
        let table = store.open_generation_table(context).await.unwrap();
        let (_, batch) = LanceDbVectorStore::generation_records_batch(records, context).unwrap();
        table.add(vec![batch]).execute().await.unwrap();
    }

    async fn append_generation_dimension_corruption(
        store: &LanceDbVectorStore,
        context: &VectorGenerationContext,
    ) {
        let table = store.open_generation_table(context).await.unwrap();
        let record = gen_record(context, "life", "mem", 4, vec![1.0, 0.0]);
        let (schema, batch) =
            LanceDbVectorStore::generation_records_batch(&[record], context).unwrap();
        let mut columns = batch.columns().to_vec();
        columns[6] = Arc::new(Int32Array::from(vec![context.dimension() as i32 + 1]));
        table
            .add(vec![RecordBatch::try_new(schema, columns).unwrap()])
            .execute()
            .await
            .unwrap();
    }

    #[test]
    fn generation_search_returns_bound_identity_hits_and_preserves_store_state() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let context = gen_context("search-lance", 3);
            store.create_generation(&context).await.unwrap();
            for record in [
                gen_record(&context, "life-a", "memory-b", 2, vec![1.0, 0.0, 0.0]),
                gen_record(&context, "life-a", "memory-a", 1, vec![1.0, 0.0, 0.0]),
                gen_record(
                    &context,
                    "life-b",
                    "memory-other-life",
                    1,
                    vec![1.0, 0.0, 0.0],
                ),
            ] {
                store.upsert_generation(&context, record).await.unwrap();
            }

            let before_count = store
                .count_generation(&context, Some("life-a"))
                .await
                .unwrap();
            let before_metadata = store.list_generation_metadata(&context).await.unwrap();
            let top_hit = store
                .search_generation(
                    &context,
                    GenerationVectorSearchQuery::new("life-a", vec![1.0, 0.0, 0.0], 1, Some(0.5)),
                )
                .await
                .unwrap();
            assert_eq!(top_hit.len(), 1);
            assert_eq!(top_hit[0].memory_id(), "memory-a");
            assert_eq!(top_hit[0].memory_revision(), 1);
            assert_eq!(top_hit[0].content_hash(), "content-memory-a");
            assert_eq!(top_hit[0].score(), 1.0);

            let all_hits = store
                .search_generation(
                    &context,
                    GenerationVectorSearchQuery::new("life-a", vec![1.0, 0.0, 0.0], 10, None),
                )
                .await
                .unwrap();
            assert_eq!(
                all_hits
                    .iter()
                    .map(|hit| hit.memory_id())
                    .collect::<Vec<_>>(),
                vec!["memory-a", "memory-b"]
            );
            assert_eq!(
                store
                    .count_generation(&context, Some("life-a"))
                    .await
                    .unwrap(),
                before_count
            );
            assert_eq!(
                store.list_generation_metadata(&context).await.unwrap(),
                before_metadata
            );

            let wrong_context = VectorGenerationContext::new(
                context.generation_id().clone(),
                context.descriptor_hash(),
                2,
            )
            .unwrap();
            let mismatch = store
                .search_generation(
                    &wrong_context,
                    GenerationVectorSearchQuery::new("life-a", vec![1.0, 0.0], 1, None),
                )
                .await
                .unwrap_err();
            assert_eq!(
                mismatch.code,
                VectorStoreErrorCode::GenerationSchemaMismatch
            );
        });
    }

    #[test]
    fn generation_search_missing_generation_does_not_create_or_use_legacy_rows() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let context = gen_context("search-missing", 3);
            let missing = store
                .search_generation(
                    &context,
                    GenerationVectorSearchQuery::new("life", vec![1.0, 0.0, 0.0], 1, None),
                )
                .await
                .unwrap_err();
            assert_eq!(missing.code, VectorStoreErrorCode::GenerationNotFound);
            assert!(!store.generation_marker_path().exists());
            assert!(store.table_names().await.unwrap().is_empty());

            store
                .upsert(record("life", "legacy", "model", vec![1.0, 0.0, 0.0]))
                .await
                .unwrap();
            let no_fallback = store
                .search_generation(
                    &context,
                    GenerationVectorSearchQuery::new("life", vec![1.0, 0.0, 0.0], 1, None),
                )
                .await
                .unwrap_err();
            assert_eq!(no_fallback.code, VectorStoreErrorCode::GenerationNotFound);
            assert!(!store
                .table_names()
                .await
                .unwrap()
                .iter()
                .any(|name| name == GENERATION_TABLE));
        });
    }

    #[test]
    fn generation_search_fails_closed_on_malformed_metadata() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let context = gen_context("search-corrupt", 2);
            store.create_generation(&context).await.unwrap();
            append_generation_dimension_corruption(&store, &context).await;

            let error = store
                .search_generation(
                    &context,
                    GenerationVectorSearchQuery::new("life", vec![1.0, 0.0], 1, None),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, VectorStoreErrorCode::GenerationCorrupt);
            assert!(!error
                .message
                .contains(temp.path().to_string_lossy().as_ref()));
        });
    }

    /// Test-only low-level Lance inspection: counts the exact
    /// `generation_id + life_id + memory_id` predicate rows directly from the
    /// Lance table, independent of the public metadata/health queries.
    async fn count_generation_memory_rows(
        store: &LanceDbVectorStore,
        context: &VectorGenerationContext,
        life: &str,
        memory: &str,
    ) -> usize {
        let table = store.open_generation_table(context).await.unwrap();
        let predicate = format!(
            "generation_id = {} AND life_id = {} AND memory_id = {}",
            sql_literal(context.generation_id().as_str()),
            sql_literal(life),
            sql_literal(memory)
        );
        table.count_rows(Some(predicate)).await.unwrap()
    }

    #[test]
    fn generation_create_upsert_delete_count_sample_and_health_are_idempotent() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let context = gen_context("gen-a", 2);
            store.create_generation(&context).await.unwrap();
            store.create_generation(&context).await.unwrap();
            store
                .upsert_generation(
                    &context,
                    gen_record(&context, "life-a", "m1", 1, vec![1.0, 0.0]),
                )
                .await
                .unwrap();
            store
                .upsert_generation(
                    &context,
                    gen_record(&context, "life-a", "m1", 2, vec![0.0, 1.0]),
                )
                .await
                .unwrap();
            assert_eq!(
                store
                    .count_generation(&context, Some("life-a"))
                    .await
                    .unwrap(),
                1
            );
            let samples = store
                .sample_generation_metadata(&context, 10)
                .await
                .unwrap();
            assert_eq!(samples.len(), 1);
            assert_eq!(samples[0].memory_revision, 2);
            assert!(!format!("{:?}", samples[0]).contains("1.0"));
            store
                .delete_generation_memory(&context, "life-a", "m1")
                .await
                .unwrap();
            store
                .delete_generation_memory(&context, "life-a", "m1")
                .await
                .unwrap();
            assert_eq!(store.count_generation(&context, None).await.unwrap(), 0);
            store.health_check_generation(&context).await.unwrap();
        });
    }

    #[test]
    fn generation_life_and_generation_isolation_hold() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let a = gen_context("gen-a", 2);
            let b = gen_context("gen-b", 2);
            // Separate directories needed for true generation isolation at directory level.
            let temp_a = tempfile::tempdir().unwrap();
            let temp_b = tempfile::tempdir().unwrap();
            let store_a = LanceDbVectorStore::open(temp_a.path()).await.unwrap();
            let store_b = LanceDbVectorStore::open(temp_b.path()).await.unwrap();
            store_a.create_generation(&a).await.unwrap();
            store_b.create_generation(&b).await.unwrap();
            store_a
                .upsert_generation(&a, gen_record(&a, "life-a", "m1", 1, vec![1.0, 0.0]))
                .await
                .unwrap();
            store_a
                .upsert_generation(&a, gen_record(&a, "life-b", "m1", 1, vec![0.0, 1.0]))
                .await
                .unwrap();
            store_b
                .upsert_generation(&b, gen_record(&b, "life-a", "m1", 1, vec![1.0, 0.0]))
                .await
                .unwrap();
            store_a.delete_generation_life(&a, "life-a").await.unwrap();
            assert_eq!(store_a.count_generation(&a, None).await.unwrap(), 1);
            assert_eq!(
                store_a.count_generation(&a, Some("life-b")).await.unwrap(),
                1
            );
            assert_eq!(store_b.count_generation(&b, None).await.unwrap(), 1);
            let _ = store;
        });
    }

    #[test]
    fn generation_rejects_bad_dimension_descriptor_and_invalid_vectors() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let context = gen_context("gen-a", 2);
            store.create_generation(&context).await.unwrap();
            let bad_dim = VectorGenerationContext::new(
                context.generation_id().clone(),
                context.descriptor_hash(),
                3,
            )
            .unwrap();
            assert_eq!(
                store.create_generation(&bad_dim).await.unwrap_err().code,
                VectorStoreErrorCode::GenerationSchemaMismatch
            );
            let bad_desc =
                VectorGenerationContext::new(context.generation_id().clone(), "other-desc", 2)
                    .unwrap();
            assert_eq!(
                store.create_generation(&bad_desc).await.unwrap_err().code,
                VectorStoreErrorCode::GenerationSchemaMismatch
            );
            assert!(GenerationVectorRecord::try_new(
                context.generation_id().clone(),
                "life",
                "m",
                1,
                "hash",
                context.descriptor_hash(),
                vec![0.0, 0.0],
            )
            .is_err());
            assert!(GenerationVectorRecord::try_new(
                context.generation_id().clone(),
                "life",
                "m",
                1,
                "hash",
                context.descriptor_hash(),
                vec![f32::NAN, 1.0],
            )
            .is_err());
        });
    }

    #[test]
    fn generation_schema_contains_only_approved_fields() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let context = gen_context("gen-schema", 3);
            store.create_generation(&context).await.unwrap();
            let table = store.open_generation_table(&context).await.unwrap();
            let schema = table.schema().await.unwrap();
            let names: Vec<_> = schema.fields().iter().map(|f| f.name().as_str()).collect();
            assert_eq!(
                names,
                vec![
                    "generation_id",
                    "life_id",
                    "memory_id",
                    "memory_revision",
                    "content_hash",
                    "descriptor_hash",
                    "dimension",
                    "vector"
                ]
            );
            assert!(schema.field_with_name("content").is_err());
            assert!(schema.field_with_name("summary").is_err());
        });
    }

    #[test]
    fn generation_corrupt_directory_fails_health_without_path_leak() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let context = gen_context("gen-missing", 2);
            let error = store.health_check_generation(&context).await.unwrap_err();
            assert_eq!(error.code, VectorStoreErrorCode::GenerationNotFound);
            assert!(!error
                .message
                .contains(temp.path().to_string_lossy().as_ref()));
        });
    }

    #[test]
    fn generation_existence_distinguishes_missing_empty_and_corrupt_table() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let context = gen_context("gen-existence", 2);

            for error in [
                store.count_generation(&context, None).await.unwrap_err(),
                store
                    .sample_generation_metadata(&context, 1)
                    .await
                    .unwrap_err(),
                store.health_check_generation(&context).await.unwrap_err(),
            ] {
                assert_eq!(error.code, VectorStoreErrorCode::GenerationNotFound);
            }

            store.create_generation(&context).await.unwrap();
            assert_eq!(store.count_generation(&context, None).await.unwrap(), 0);
            assert!(store
                .sample_generation_metadata(&context, 1)
                .await
                .unwrap()
                .is_empty());
            store.health_check_generation(&context).await.unwrap();

            store
                .connection
                .drop_table(GENERATION_TABLE, &[])
                .await
                .unwrap();
            for error in [
                store.count_generation(&context, None).await.unwrap_err(),
                store
                    .sample_generation_metadata(&context, 1)
                    .await
                    .unwrap_err(),
                store.health_check_generation(&context).await.unwrap_err(),
            ] {
                assert_eq!(error.code, VectorStoreErrorCode::GenerationCorrupt);
            }
        });
    }

    #[test]
    fn generation_health_rejects_extra_type_and_nullability_schema_changes() {
        block_on(async {
            type SchemaModifier = Box<dyn Fn(SchemaRef) -> SchemaRef>;
            let cases: Vec<(&str, SchemaModifier)> = vec![
                (
                    "extra",
                    Box::new(|expected| {
                        let mut fields = expected.fields().to_vec();
                        fields.push(Arc::new(Field::new("unexpected", DataType::Utf8, false)));
                        Arc::new(Schema::new_with_metadata(
                            fields,
                            expected.metadata().clone(),
                        ))
                    }),
                ),
                (
                    "type",
                    Box::new(|expected| {
                        let mut fields = expected.fields().to_vec();
                        fields[6] = Arc::new(Field::new("dimension", DataType::Int64, false));
                        Arc::new(Schema::new_with_metadata(
                            fields,
                            expected.metadata().clone(),
                        ))
                    }),
                ),
                (
                    "nullable",
                    Box::new(|expected| {
                        let mut fields = expected.fields().to_vec();
                        fields[0] = Arc::new(Field::new("generation_id", DataType::Utf8, true));
                        Arc::new(Schema::new_with_metadata(
                            fields,
                            expected.metadata().clone(),
                        ))
                    }),
                ),
            ];
            for (name, modify) in cases {
                let temp = tempfile::tempdir().unwrap();
                let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
                let context = gen_context(&format!("gen-schema-{name}"), 2);
                store.write_generation_marker().unwrap();
                store
                    .connection
                    .create_empty_table(
                        GENERATION_TABLE,
                        modify(LanceDbVectorStore::generation_schema(&context).unwrap()),
                    )
                    .execute()
                    .await
                    .unwrap();
                assert_eq!(
                    store
                        .health_check_generation(&context)
                        .await
                        .unwrap_err()
                        .code,
                    VectorStoreErrorCode::GenerationSchemaMismatch
                );
            }
        });
    }

    #[test]
    fn generation_health_scans_past_one_hundred_rows_for_corrupt_records_and_duplicates() {
        block_on(async {
            let make_records = |context: &VectorGenerationContext| {
                (0..121)
                    .map(|index| {
                        gen_record(
                            context,
                            "life-a",
                            &format!("memory-{index}"),
                            1,
                            vec![index as f32, 1.0],
                        )
                    })
                    .collect::<Vec<_>>()
            };

            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let context = gen_context("gen-late-corrupt", 2);
            store.create_generation(&context).await.unwrap();
            let mut records = make_records(&context);
            records[120] = GenerationVectorRecord::try_new(
                context.generation_id().clone(),
                "life-a",
                "memory-120",
                1,
                "content-memory-120",
                "wrong-descriptor",
                vec![120.0, 1.0],
            )
            .unwrap();
            append_generation_records(&store, &context, &records).await;
            assert_eq!(
                store
                    .health_check_generation(&context)
                    .await
                    .unwrap_err()
                    .code,
                VectorStoreErrorCode::GenerationCorrupt
            );

            let duplicate_temp = tempfile::tempdir().unwrap();
            let duplicate_store = LanceDbVectorStore::open(duplicate_temp.path())
                .await
                .unwrap();
            let duplicate_context = gen_context("gen-late-duplicate", 2);
            duplicate_store
                .create_generation(&duplicate_context)
                .await
                .unwrap();
            let mut duplicate_records = make_records(&duplicate_context);
            duplicate_records[120] = gen_record(
                &duplicate_context,
                "life-a",
                "memory-0",
                2,
                vec![120.0, 1.0],
            );
            append_generation_records(&duplicate_store, &duplicate_context, &duplicate_records)
                .await;
            assert_eq!(
                duplicate_store
                    .health_check_generation(&duplicate_context)
                    .await
                    .unwrap_err()
                    .code,
                VectorStoreErrorCode::GenerationCorrupt
            );
        });
    }

    #[test]
    fn direct_lance_generation_drop_requires_registry_and_preserves_data() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let context = gen_context("gen-direct-drop", 2);
            store.create_generation(&context).await.unwrap();
            store
                .upsert_generation(
                    &context,
                    gen_record(&context, "life-a", "memory-a", 1, vec![1.0, 0.0]),
                )
                .await
                .unwrap();
            assert_eq!(
                store
                    .drop_generation(context.generation_id())
                    .await
                    .unwrap_err()
                    .code,
                VectorStoreErrorCode::GenerationDropRequiresRegistry
            );
            assert_eq!(store.count_generation(&context, None).await.unwrap(), 1);
            assert!(temp.path().is_dir());
        });
    }

    #[test]
    fn in_memory_generation_matches_lance_isolation_contract() {
        block_on(async {
            let memory = InMemoryVectorStore::new();
            let a = gen_context("gen-a", 2);
            let b = gen_context("gen-b", 2);
            memory.create_generation(&a).await.unwrap();
            memory.create_generation(&b).await.unwrap();
            memory
                .upsert_generation(&a, gen_record(&a, "life-a", "m1", 1, vec![1.0, 0.0]))
                .await
                .unwrap();
            memory
                .upsert_generation(&b, gen_record(&b, "life-a", "m1", 1, vec![0.0, 1.0]))
                .await
                .unwrap();
            assert_eq!(memory.count_generation(&a, None).await.unwrap(), 1);
            assert_eq!(memory.count_generation(&b, None).await.unwrap(), 1);
            memory.drop_generation(a.generation_id()).await.unwrap();
            assert_eq!(
                memory.health_check_generation(&a).await.unwrap_err().code,
                VectorStoreErrorCode::GenerationNotFound
            );
            assert_eq!(memory.count_generation(&b, None).await.unwrap(), 1);
        });
    }

    #[test]
    fn get_generation_metadata_exact_hit() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let ctx = gen_context("meta-exact-hit", 3);
            store.create_generation(&ctx).await.unwrap();
            let rec = gen_record(&ctx, "life-a", "mem-1", 2, vec![0.1, 0.2, 0.3]);
            store.upsert_generation(&ctx, rec).await.unwrap();
            let meta = store
                .get_generation_metadata(&ctx, "life-a", "mem-1")
                .await
                .unwrap()
                .expect("exact hit must return Some");
            assert_eq!(meta.generation_id, "meta-exact-hit");
            assert_eq!(meta.life_id, "life-a");
            assert_eq!(meta.memory_id, "mem-1");
            assert_eq!(meta.memory_revision, 2);
            assert_eq!(meta.content_hash, "content-mem-1");
            assert_eq!(meta.descriptor_hash, "desc-meta-exact-hit");
            assert_eq!(meta.dimension, 3);
        });
    }

    #[test]
    fn get_generation_metadata_missing() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let ctx = gen_context("meta-missing", 3);
            store.create_generation(&ctx).await.unwrap();
            let meta = store
                .get_generation_metadata(&ctx, "life-x", "mem-x")
                .await
                .unwrap();
            assert!(meta.is_none());
        });
    }

    #[test]
    fn get_generation_metadata_generation_isolation() {
        // LanceDB stores one generation per directory; use separate stores
        block_on(async {
            let temp_a = tempfile::tempdir().unwrap();
            let temp_b = tempfile::tempdir().unwrap();
            let store_a = LanceDbVectorStore::open(temp_a.path()).await.unwrap();
            let store_b = LanceDbVectorStore::open(temp_b.path()).await.unwrap();
            let ctx_a = gen_context("meta-gen-a", 3);
            let ctx_b = gen_context("meta-gen-b", 3);
            store_a.create_generation(&ctx_a).await.unwrap();
            store_b.create_generation(&ctx_b).await.unwrap();
            let rec_a = gen_record(&ctx_a, "life", "mem", 1, vec![0.1, 0.2, 0.3]);
            let rec_b = gen_record(&ctx_b, "life", "mem", 2, vec![0.4, 0.5, 0.6]);
            store_a.upsert_generation(&ctx_a, rec_a).await.unwrap();
            store_b.upsert_generation(&ctx_b, rec_b).await.unwrap();

            let meta_a = store_a
                .get_generation_metadata(&ctx_a, "life", "mem")
                .await
                .unwrap()
                .expect("gen-a must have record");
            assert_eq!(meta_a.memory_revision, 1);

            let meta_b = store_b
                .get_generation_metadata(&ctx_b, "life", "mem")
                .await
                .unwrap()
                .expect("gen-b must have record");
            assert_eq!(meta_b.memory_revision, 2);

            // Query A for a record only in B -> None
            let meta = store_a
                .get_generation_metadata(&ctx_a, "life", "mem-only-b")
                .await
                .unwrap();
            assert!(meta.is_none());
        });
    }

    #[test]
    fn delete_generation_memory_generation_metadata_after_delete() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let ctx = gen_context("meta-after-del", 3);
            store.create_generation(&ctx).await.unwrap();
            let rec = gen_record(&ctx, "life", "mem", 1, vec![0.1, 0.2, 0.3]);
            store.upsert_generation(&ctx, rec).await.unwrap();
            store
                .delete_generation_memory(&ctx, "life", "mem")
                .await
                .unwrap();
            let meta = store
                .get_generation_metadata(&ctx, "life", "mem")
                .await
                .unwrap();
            assert!(meta.is_none());
        });
    }

    #[test]
    fn get_generation_metadata_after_update() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let ctx = gen_context("meta-after-upd", 3);
            store.create_generation(&ctx).await.unwrap();
            let rec1 = gen_record(&ctx, "life", "mem", 1, vec![0.1, 0.2, 0.3]);
            store.upsert_generation(&ctx, rec1).await.unwrap();
            let rec2 = gen_record(&ctx, "life", "mem", 2, vec![0.4, 0.5, 0.6]);
            store.upsert_generation(&ctx, rec2).await.unwrap();
            let meta = store
                .get_generation_metadata(&ctx, "life", "mem")
                .await
                .unwrap()
                .expect("updated record must exist");
            assert_eq!(meta.memory_revision, 2);
        });
    }

    #[test]
    fn conditional_delete_absent_and_deleted_trait_object_contract() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let ctx = gen_context("conditional-delete", 2);
            assert_eq!(
                store
                    .delete_generation_memory_if_matches(&ctx, "life", "mem", 4, "content-mem")
                    .await
                    .unwrap(),
                ConditionalGenerationDeleteOutcome::Absent
            );
            store.create_generation(&ctx).await.unwrap();
            store
                .upsert_generation(&ctx, gen_record(&ctx, "life", "mem", 4, vec![1.0, 0.0]))
                .await
                .unwrap();
            let trait_store: &dyn VectorStore = &store;
            assert_eq!(
                trait_store
                    .delete_generation_memory_if_matches(&ctx, "life", "mem", 4, "content-mem")
                    .await
                    .unwrap(),
                ConditionalGenerationDeleteOutcome::Deleted
            );
            assert!(store
                .get_generation_metadata(&ctx, "life", "mem")
                .await
                .unwrap()
                .is_none());
            assert_eq!(
                store
                    .delete_generation_memory_if_matches(&ctx, "life", "mem", 4, "content-mem")
                    .await
                    .unwrap(),
                ConditionalGenerationDeleteOutcome::Absent
            );
        });
    }

    #[test]
    fn conditional_delete_identity_mismatch_keeps_lance_record() {
        block_on(async {
            for (revision, hash) in [(5, "content-mem"), (4, "other-hash")] {
                let temp = tempfile::tempdir().unwrap();
                let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
                let ctx = gen_context("conditional-mismatch", 2);
                store.create_generation(&ctx).await.unwrap();
                store
                    .upsert_generation(&ctx, gen_record(&ctx, "life", "mem", 4, vec![1.0, 0.0]))
                    .await
                    .unwrap();
                assert_eq!(
                    store
                        .delete_generation_memory_if_matches(&ctx, "life", "mem", revision, hash)
                        .await
                        .unwrap(),
                    ConditionalGenerationDeleteOutcome::IdentityMismatch
                );
                let current = store
                    .get_generation_metadata(&ctx, "life", "mem")
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    (current.memory_revision, current.content_hash.as_str()),
                    (4, "content-mem")
                );
            }
        });
    }

    #[test]
    fn conditional_delete_descriptor_and_dimension_corruption_fail_closed() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let ctx = gen_context("conditional-descriptor-corrupt", 2);
            store.create_generation(&ctx).await.unwrap();
            let mut record = gen_record(&ctx, "life", "mem", 4, vec![1.0, 0.0]);
            record.descriptor_hash = "other-descriptor".into();
            append_generation_records(&store, &ctx, &[record]).await;
            assert_eq!(
                store
                    .delete_generation_memory_if_matches(&ctx, "life", "mem", 4, "content-mem")
                    .await
                    .unwrap_err()
                    .code,
                VectorStoreErrorCode::GenerationCorrupt
            );
            assert!(store
                .get_generation_metadata(&ctx, "life", "mem")
                .await
                .unwrap()
                .is_some());

            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let ctx = gen_context("conditional-dimension-corrupt", 2);
            store.create_generation(&ctx).await.unwrap();
            append_generation_dimension_corruption(&store, &ctx).await;
            assert_eq!(
                store
                    .delete_generation_memory_if_matches(&ctx, "life", "mem", 4, "content-mem")
                    .await
                    .unwrap_err()
                    .code,
                VectorStoreErrorCode::GenerationCorrupt
            );
            assert!(store
                .get_generation_metadata(&ctx, "life", "mem")
                .await
                .unwrap()
                .is_some());
        });
    }

    /// BLOCKER-2: a real Lance duplicate of the exact identity key
    /// `generation + life + memory`. The conditional delete must fail closed with
    /// `GenerationCorrupt` at its internal exact requery and must delete zero
    /// rows (both duplicate rows survive).
    #[test]
    fn conditional_delete_duplicate_identity_returns_generation_corrupt_without_delete() {
        block_on(async {
            let temp = tempfile::tempdir().unwrap();
            let store = LanceDbVectorStore::open(temp.path()).await.unwrap();
            let ctx = gen_context("conditional-duplicate-identity", 2);
            store.create_generation(&ctx).await.unwrap();

            // Two real Lance rows with an identical exact identity key, appended
            // through the low-level table fixture so the production upsert
            // dedup semantics cannot hide the duplicate.
            let row_a = gen_record(&ctx, "life", "mem", 4, vec![1.0, 0.0]);
            let row_b = gen_record(&ctx, "life", "mem", 4, vec![0.0, 1.0]);
            append_generation_records(&store, &ctx, &[row_a, row_b]).await;

            let before = count_generation_memory_rows(&store, &ctx, "life", "mem").await;
            assert_eq!(before, 2, "the duplicate fixture must place two rows");

            // Call through the real trait-object conditional primitive with a
            // fully valid expected identity, so the internal exact requery is
            // what detects the 2+ rows and fails closed.
            let trait_store: &dyn VectorStore = &store;
            let error = trait_store
                .delete_generation_memory_if_matches(&ctx, "life", "mem", 4, "content-mem")
                .await
                .unwrap_err();
            assert_eq!(error.code, VectorStoreErrorCode::GenerationCorrupt);

            let after = count_generation_memory_rows(&store, &ctx, "life", "mem").await;
            assert_eq!(
                after, before,
                "conditional delete on a duplicate identity must perform zero deletions"
            );
            assert_eq!(after, 2);
        });
    }

    #[test]
    fn conditional_delete_race_new_mutation_first_preserves_new_identity() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(block_on(LanceDbVectorStore::open(temp.path())).unwrap());
        let ctx = gen_context("conditional-race-first", 2);
        block_on(store.create_generation(&ctx)).unwrap();
        block_on(store.upsert_generation(&ctx, gen_record(&ctx, "life", "mem", 4, vec![1.0, 0.0])))
            .unwrap();
        let stale = block_on(store.get_generation_metadata(&ctx, "life", "mem"))
            .unwrap()
            .unwrap();
        let guard = block_on(store.mutation_lock.lock());
        let (started_tx, started_rx) = mpsc::channel();
        let update_store = Arc::clone(&store);
        let update_context = ctx.clone();
        let update = thread::spawn(move || {
            started_tx.send(()).unwrap();
            block_on(update_store.upsert_generation(
                &update_context,
                gen_record(&update_context, "life", "mem", 5, vec![0.0, 1.0]),
            ))
        });
        started_rx.recv().unwrap();
        drop(guard);
        update.join().unwrap().unwrap();
        assert_eq!(
            block_on(store.delete_generation_memory_if_matches(
                &ctx,
                "life",
                "mem",
                stale.memory_revision,
                &stale.content_hash,
            ))
            .unwrap(),
            ConditionalGenerationDeleteOutcome::IdentityMismatch
        );
        let current = block_on(store.get_generation_metadata(&ctx, "life", "mem"))
            .unwrap()
            .unwrap();
        assert_eq!(
            (current.memory_revision, current.content_hash.as_str()),
            (5, "content-mem")
        );
    }

    #[test]
    fn conditional_delete_race_delete_first_allows_later_new_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let store = Arc::new(block_on(LanceDbVectorStore::open(temp.path())).unwrap());
        let ctx = gen_context("conditional-race-delete", 2);
        block_on(store.create_generation(&ctx)).unwrap();
        block_on(store.upsert_generation(&ctx, gen_record(&ctx, "life", "mem", 4, vec![1.0, 0.0])))
            .unwrap();
        let guard = block_on(store.mutation_lock.lock());
        let (started_tx, started_rx) = mpsc::channel();
        let update_store = Arc::clone(&store);
        let update_context = ctx.clone();
        let update = thread::spawn(move || {
            started_tx.send(()).unwrap();
            block_on(update_store.upsert_generation(
                &update_context,
                gen_record(&update_context, "life", "mem", 5, vec![0.0, 1.0]),
            ))
        });
        started_rx.recv().unwrap();
        assert_eq!(
            block_on(store.delete_generation_memory_if_matches_under_lock(
                &ctx,
                "life",
                "mem",
                4,
                "content-mem",
            ))
            .unwrap(),
            ConditionalGenerationDeleteOutcome::Deleted
        );
        drop(guard);
        update.join().unwrap().unwrap();
        let current = block_on(store.get_generation_metadata(&ctx, "life", "mem"))
            .unwrap()
            .unwrap();
        assert_eq!(
            (current.memory_revision, current.content_hash.as_str()),
            (5, "content-mem")
        );
    }
}
