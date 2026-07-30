//! Read-only, bounded, no-sensitive-data health snapshot for vector sync.
//!
//! SQLite is the only authority. LanceDB is a rebuildable derived index.
//! This module never claims, recovers, finalizes, embeds, or writes.

#![allow(dead_code)]

use crate::{
    storage::StorageService,
    vector_store::{VectorGenerationContext, VectorStore, VectorStoreErrorCode},
};

use super::vector_sync_worker::MAX_VECTOR_SYNC_ATTEMPTS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VectorStoreHealth {
    Available,
    GenerationMissing,
    Unavailable,
    Corrupt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VectorSyncHealthSnapshot {
    pub generation_id: String,
    pub pending_count: usize,
    pub retry_wait_count: usize,
    pub blocked_count: usize,
    pub processing_count: usize,
    pub expired_processing_count: usize,
    pub provider_result_unknown_count: usize,
    pub internal_invariant_count: usize,
    pub attempts_at_limit_count: usize,
    pub oldest_pending_age_ms: Option<u64>,
    pub oldest_retry_wait_age_ms: Option<u64>,
    pub oldest_blocked_age_ms: Option<u64>,
    pub sqlite_generation_item_count: usize,
    pub vector_store_health: VectorStoreHealth,
    pub vector_store_item_count: Option<usize>,
    pub count_mismatch: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VectorSyncHealthErrorCode {
    StorageUnavailable,
    ClockFailure,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VectorSyncHealthError {
    pub code: VectorSyncHealthErrorCode,
    pub message: String,
}

impl VectorSyncHealthError {
    fn new(code: VectorSyncHealthErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

pub(crate) trait HealthClock: Send + Sync {
    fn now_utc_millis(&self) -> Result<i64, VectorSyncHealthError>;
}

pub(crate) struct SystemHealthClock;

impl HealthClock for SystemHealthClock {
    fn now_utc_millis(&self) -> Result<i64, VectorSyncHealthError> {
        let duration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| {
                VectorSyncHealthError::new(
                    VectorSyncHealthErrorCode::ClockFailure,
                    "System clock is unavailable.",
                )
            })?;
        i64::try_from(duration.as_millis()).map_err(|_| {
            VectorSyncHealthError::new(
                VectorSyncHealthErrorCode::ClockFailure,
                "System clock value is invalid.",
            )
        })
    }
}

fn age_ms_at(snapshot_now_millis: i64, timestamp_millis: Option<i64>) -> Option<u64> {
    let ts = timestamp_millis?;
    if ts > snapshot_now_millis {
        return Some(0);
    }
    let diff = snapshot_now_millis - ts;
    Some(diff as u64)
}

fn sqlite_now_from_millis(millis: i64) -> String {
    format!(
        "strftime('%Y-%m-%dT%H:%M:%fZ', {}.0 / 1000, 'unixepoch')",
        millis
    )
}

pub(crate) async fn inspect_vector_sync_health(
    storage: &StorageService,
    vector_store: &dyn VectorStore,
    generation: &VectorGenerationContext,
    clock: &dyn HealthClock,
) -> Result<VectorSyncHealthSnapshot, VectorSyncHealthError> {
    let snapshot_now_millis = clock.now_utc_millis()?;

    let cutoff_expr = sqlite_now_from_millis(snapshot_now_millis);

    let (counts_data, gen_item_count) = {
        let state = storage.state().map_err(|_| {
            VectorSyncHealthError::new(
                VectorSyncHealthErrorCode::StorageUnavailable,
                "The vector sync outbox is unavailable.",
            )
        })?;
        let conn = &state.connection;

        let sql = format!(
            "SELECT
            COALESCE(SUM(CASE WHEN state='pending' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN state='retry_wait' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN state='blocked' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN state='processing' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN state='processing' AND lease_expires_at IS NOT NULL AND lease_expires_at <= {cutoff_expr} THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN state='blocked' AND last_error_code='PROVIDER_RESULT_UNKNOWN' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN state='blocked' AND last_error_code='INTERNAL_INVARIANT' THEN 1 ELSE 0 END), 0),
            COALESCE(SUM(CASE WHEN attempt_count >= {max_attempts} AND state IN ('blocked', 'processing', 'retry_wait') THEN 1 ELSE 0 END), 0),
            CAST(MIN(CASE WHEN state='pending' THEN CAST(strftime('%s', created_at) AS INTEGER) * 1000 ELSE NULL END) AS INTEGER),
            CAST(MIN(CASE WHEN state='retry_wait' THEN CAST(strftime('%s', updated_at) AS INTEGER) * 1000 ELSE NULL END) AS INTEGER),
            CAST(MIN(CASE WHEN state='blocked' THEN CAST(strftime('%s', updated_at) AS INTEGER) * 1000 ELSE NULL END) AS INTEGER)
         FROM memory_vector_sync_outbox",
            max_attempts = MAX_VECTOR_SYNC_ATTEMPTS,
            cutoff_expr = cutoff_expr,
        );

        let counts = conn
            .query_row(&sql, [], |row| {
                Ok((
                    row.get::<_, i64>(0)? as usize,
                    row.get::<_, i64>(1)? as usize,
                    row.get::<_, i64>(2)? as usize,
                    row.get::<_, i64>(3)? as usize,
                    row.get::<_, i64>(4)? as usize,
                    row.get::<_, i64>(5)? as usize,
                    row.get::<_, i64>(6)? as usize,
                    row.get::<_, i64>(7)? as usize,
                    row.get::<_, Option<i64>>(8)?,
                    row.get::<_, Option<i64>>(9)?,
                    row.get::<_, Option<i64>>(10)?,
                ))
            })
            .map_err(|_| {
                VectorSyncHealthError::new(
                    VectorSyncHealthErrorCode::StorageUnavailable,
                    "The vector sync outbox is unavailable.",
                )
            })?;

        let gen_items: usize = conn
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_generation_item WHERE generation_id=?1",
                rusqlite::params![generation.generation_id().as_str()],
                |row| row.get::<_, i64>(0).map(|v| v as usize),
            )
            .map_err(|_| {
                VectorSyncHealthError::new(
                    VectorSyncHealthErrorCode::StorageUnavailable,
                    "The vector generation item store is unavailable.",
                )
            })?;

        (counts, gen_items)
    }; // MutexGuard dropped here

    let oldest_pending = counts_data.8;
    let oldest_retry = counts_data.9;
    let oldest_blocked = counts_data.10;

    let (vs_health, vs_item_count, count_mismatch) = match vector_store
        .count_generation(generation, None)
        .await
    {
        Ok(count) => {
            let mism = Some(count != gen_item_count);
            (VectorStoreHealth::Available, Some(count), mism)
        }
        Err(error) => {
            let health = match error.code {
                VectorStoreErrorCode::GenerationNotFound => VectorStoreHealth::GenerationMissing,
                VectorStoreErrorCode::GenerationCorrupt => VectorStoreHealth::Corrupt,
                _ => VectorStoreHealth::Unavailable,
            };
            (health, None, None)
        }
    };

    Ok(VectorSyncHealthSnapshot {
        generation_id: generation.generation_id().as_str().to_owned(),
        pending_count: counts_data.0,
        retry_wait_count: counts_data.1,
        blocked_count: counts_data.2,
        processing_count: counts_data.3,
        expired_processing_count: counts_data.4,
        provider_result_unknown_count: counts_data.5,
        internal_invariant_count: counts_data.6,
        attempts_at_limit_count: counts_data.7,
        oldest_pending_age_ms: age_ms_at(snapshot_now_millis, oldest_pending),
        oldest_retry_wait_age_ms: age_ms_at(snapshot_now_millis, oldest_retry),
        oldest_blocked_age_ms: age_ms_at(snapshot_now_millis, oldest_blocked),
        sqlite_generation_item_count: gen_item_count,
        vector_store_health: vs_health,
        vector_store_item_count: vs_item_count,
        count_mismatch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        storage::{LifeIdentityRecord, PersonaTemplateRecord},
        vector_store::{VectorStoreError, VectorStoreErrorCode},
    };
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    };

    fn test_storage() -> (tempfile::TempDir, StorageService) {
        let temp = tempfile::tempdir().unwrap();
        let storage =
            StorageService::initialize_with_roots(temp.path().join("data"), None).unwrap();
        storage
            .save_persona(PersonaTemplateRecord {
                id: "persona".into(),
                name: "Persona".into(),
                version: 1,
                persona_json: "{\"id\":\"persona\"}".into(),
            })
            .unwrap();
        storage
            .save_life(LifeIdentityRecord {
                id: "life".into(),
                name: "Life".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                version: 1,
                body_id: "body".into(),
                persona_id: "persona".into(),
                persona_version: 1,
            })
            .unwrap();
        (temp, storage)
    }

    fn health_context() -> VectorGenerationContext {
        VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-health").unwrap(),
            "desc-gen-health",
            3,
        )
        .unwrap()
    }

    #[derive(Clone)]
    struct FixedHealthClock {
        now_millis: Arc<Mutex<i64>>,
    }

    impl FixedHealthClock {
        fn new(now_millis: i64) -> Self {
            Self {
                now_millis: Arc::new(Mutex::new(now_millis)),
            }
        }
        fn set(&self, now_millis: i64) {
            *self.now_millis.lock().unwrap() = now_millis;
        }
    }

    impl HealthClock for FixedHealthClock {
        fn now_utc_millis(&self) -> Result<i64, VectorSyncHealthError> {
            Ok(*self.now_millis.lock().unwrap())
        }
    }

    struct CountingHealthVectorStore {
        inner: crate::vector_store::InMemoryVectorStore,
        upsert_calls: Arc<AtomicUsize>,
        delete_calls: Arc<AtomicUsize>,
        get_meta_calls: Arc<AtomicUsize>,
    }

    impl VectorStore for CountingHealthVectorStore {
        fn upsert<'a>(
            &'a self,
            r: crate::vector_store::VectorRecord,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.inner.upsert(r)
        }
        fn upsert_batch<'a>(
            &'a self,
            r: Vec<crate::vector_store::VectorRecord>,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.inner.upsert_batch(r)
        }
        fn search<'a>(
            &'a self,
            q: crate::vector_store::VectorSearchQuery,
        ) -> crate::vector_store::VectorStoreFuture<
            'a,
            Result<Vec<crate::vector_store::VectorSearchHit>, VectorStoreError>,
        > {
            self.inner.search(q)
        }
        fn delete<'a>(
            &'a self,
            lid: &'a str,
            mid: &'a str,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.inner.delete(lid, mid)
        }
        fn delete_from_space<'a>(
            &'a self,
            lid: &'a str,
            mid: &'a str,
            s: &'a crate::vector_store::VectorSpace,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.inner.delete_from_space(lid, mid, s)
        }
        fn delete_by_life<'a>(
            &'a self,
            lid: &'a str,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.inner.delete_by_life(lid)
        }
        fn clear_space<'a>(
            &'a self,
            lid: &'a str,
            s: &'a crate::vector_store::VectorSpace,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.inner.clear_space(lid, s)
        }
        fn count<'a>(
            &'a self,
            lid: &'a str,
            s: Option<&'a crate::vector_store::VectorSpace>,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.inner.count(lid, s)
        }
        fn health_check<'a>(
            &'a self,
            lid: &'a str,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.inner.health_check(lid)
        }
        fn create_generation<'a>(
            &'a self,
            ctx: &'a VectorGenerationContext,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.inner.create_generation(ctx)
        }
        fn upsert_generation<'a>(
            &'a self,
            ctx: &'a VectorGenerationContext,
            record: crate::vector_store::GenerationVectorRecord,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.upsert_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.upsert_generation(ctx, record)
        }
        fn delete_generation_memory<'a>(
            &'a self,
            ctx: &'a VectorGenerationContext,
            lid: &'a str,
            mid: &'a str,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.delete_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.delete_generation_memory(ctx, lid, mid)
        }
        fn delete_generation_life<'a>(
            &'a self,
            ctx: &'a VectorGenerationContext,
            lid: &'a str,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.inner.delete_generation_life(ctx, lid)
        }
        fn count_generation<'a>(
            &'a self,
            ctx: &'a VectorGenerationContext,
            lid: Option<&'a str>,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.inner.count_generation(ctx, lid)
        }
        fn sample_generation_metadata<'a>(
            &'a self,
            ctx: &'a VectorGenerationContext,
            limit: usize,
        ) -> crate::vector_store::VectorStoreFuture<
            'a,
            Result<Vec<crate::vector_store::VectorMetadataSample>, VectorStoreError>,
        > {
            self.inner.sample_generation_metadata(ctx, limit)
        }
        fn health_check_generation<'a>(
            &'a self,
            ctx: &'a VectorGenerationContext,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.inner.health_check_generation(ctx)
        }
        fn drop_generation<'a>(
            &'a self,
            gid: &'a crate::vector_store::VectorGenerationId,
        ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.inner.drop_generation(gid)
        }
        fn get_generation_metadata<'a>(
            &'a self,
            ctx: &'a VectorGenerationContext,
            lid: &'a str,
            mid: &'a str,
        ) -> crate::vector_store::VectorStoreFuture<
            'a,
            Result<Option<crate::vector_store::VectorMetadataSample>, VectorStoreError>,
        > {
            self.get_meta_calls.fetch_add(1, Ordering::SeqCst);
            self.inner.get_generation_metadata(ctx, lid, mid)
        }
    }

    #[test]
    fn empty_outbox_all_zero() {
        let (_temp, storage) = test_storage();
        let ctx = health_context();
        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
        let vs = CountingHealthVectorStore {
            inner: raw_vs,
            upsert_calls: Arc::new(AtomicUsize::new(0)),
            delete_calls: Arc::new(AtomicUsize::new(0)),
            get_meta_calls: Arc::new(AtomicUsize::new(0)),
        };
        let clock = FixedHealthClock::new(1_700_000_000_000);
        let snap =
            tauri::async_runtime::block_on(inspect_vector_sync_health(&storage, &vs, &ctx, &clock))
                .unwrap();
        assert_eq!(snap.pending_count, 0);
        assert_eq!(snap.retry_wait_count, 0);
        assert_eq!(snap.blocked_count, 0);
        assert_eq!(snap.processing_count, 0);
        assert_eq!(snap.expired_processing_count, 0);
        assert_eq!(snap.provider_result_unknown_count, 0);
        assert_eq!(snap.internal_invariant_count, 0);
        assert_eq!(snap.attempts_at_limit_count, 0);
        assert_eq!(snap.oldest_pending_age_ms, None);
        assert_eq!(snap.oldest_retry_wait_age_ms, None);
        assert_eq!(snap.oldest_blocked_age_ms, None);
        assert_eq!(snap.vector_store_health, VectorStoreHealth::Available);
        assert_eq!(vs.upsert_calls.load(Ordering::SeqCst), 0);
        assert_eq!(vs.delete_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn mixed_states_precise_counts() {
        let (_temp, storage) = test_storage();
        let ctx = health_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();

        let db_path = storage.test_database_main_path().unwrap();
        let conn = rusqlite::Connection::open(&db_path).unwrap();

        for i in 0..2 {
            conn.execute(
                "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, created_at, updated_at)
                 VALUES (?1, ?2, 'upsert', 'pending', 0, '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
                rusqlite::params![format!("life-a"), format!("pending-{i}")],
            )
            .unwrap();
            conn.execute(
                "UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1",
                [],
            )
            .unwrap();
        }

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, created_at, updated_at, next_attempt_at)
             VALUES ('life-a', 'retry-1', 'upsert', 'retry_wait', 1, '2024-01-01T00:00:00.000Z', '2024-06-01T00:00:00.000Z', '2024-07-01T00:00:00.000Z')",
            [],
        )
        .unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, last_send_disposition, created_at, updated_at)
             VALUES ('life-a', 'blocked-unk', 'upsert', 'blocked', 1, 'PROVIDER_RESULT_UNKNOWN', 'possibly_sent', '2024-01-01T00:00:00.000Z', '2024-03-01T00:00:00.000Z')",
            [],
        )
        .unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, created_at, updated_at)
             VALUES ('life-a', 'blocked-inv', 'upsert', 'blocked', 1, 'INTERNAL_INVARIANT', '2024-01-01T00:00:00.000Z', '2024-03-01T00:00:00.000Z')",
            [],
        )
        .unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, lease_owner, lease_expires_at, lease_fence_epoch, claimed_generation_id, created_at, updated_at)
             VALUES ('life-a', 'proc-alive', 'upsert', 'processing', 1, 'owner-a', '2099-01-01T00:00:00.000Z', 1, 'gen-health', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        )
        .unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, lease_owner, lease_expires_at, lease_fence_epoch, claimed_generation_id, created_at, updated_at)
             VALUES ('life-a', 'proc-expired', 'upsert', 'processing', 2, 'owner-b', '2020-01-01T00:00:00.000Z', 2, 'gen-health', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        )
        .unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, created_at, updated_at)
             VALUES ('life-a', 'att5', 'upsert', 'blocked', 5, 'LANCE_PERMANENT', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        )
        .unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, created_at, updated_at)
             VALUES ('life-a', 'att6', 'upsert', 'blocked', 6, 'LANCE_PERMANENT', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        )
        .unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
        let vs = CountingHealthVectorStore {
            inner: raw_vs,
            upsert_calls: Arc::new(AtomicUsize::new(0)),
            delete_calls: Arc::new(AtomicUsize::new(0)),
            get_meta_calls: Arc::new(AtomicUsize::new(0)),
        };
        let clock = FixedHealthClock::new(1_700_000_000_000);
        let snap =
            tauri::async_runtime::block_on(inspect_vector_sync_health(&storage, &vs, &ctx, &clock))
                .unwrap();

        assert_eq!(snap.pending_count, 2);
        assert_eq!(snap.retry_wait_count, 1);
        assert_eq!(snap.blocked_count, 4);
        assert_eq!(snap.processing_count, 2);
        assert_eq!(snap.expired_processing_count, 1);
        assert_eq!(snap.provider_result_unknown_count, 1);
        assert_eq!(snap.internal_invariant_count, 1);
        assert_eq!(snap.attempts_at_limit_count, 2);
    }
}
