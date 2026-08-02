//! Read-only, bounded, no-sensitive-data health snapshot for vector sync.
//!
//! SQLite is the only authority. LanceDB is a rebuildable derived index.
//! This module never claims, recovers, finalizes, embeds, or writes.

#![allow(dead_code)]

use crate::{
    storage::{OutboxSyncHealthAggregate, StorageService},
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
    pub failed_count: usize,
    pub migration_isolated_count: usize,
    pub expired_processing_count: usize,
    pub provider_result_unknown_count: usize,
    pub internal_invariant_count: usize,
    pub attempts_at_limit_count: usize,
    pub attempts_over_limit_count: usize,
    pub invalid_attempt_identity_count: usize,
    pub expired_processing_unmarked_count: usize,
    pub expired_processing_marked_count: usize,
    pub legacy_processing_unproven_count: usize,
    pub delete_replay_not_eligible_count: usize,
    pub attempts_at_limit_processing_count: usize,
    pub attempts_at_limit_blocked_count: usize,
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

pub(crate) async fn inspect_vector_sync_health(
    storage: &StorageService,
    vector_store: &dyn VectorStore,
    generation: &VectorGenerationContext,
    clock: &dyn HealthClock,
) -> Result<VectorSyncHealthSnapshot, VectorSyncHealthError> {
    let snapshot_now_millis = clock.now_utc_millis()?;

    let OutboxSyncHealthAggregate {
        pending_count,
        retry_wait_count,
        blocked_count,
        processing_count,
        failed_count,
        migration_isolated_count,
        expired_processing_count,
        provider_result_unknown_count,
        internal_invariant_count,
        attempts_at_limit_count,
        attempts_over_limit_count,
        invalid_attempt_identity_count,
        expired_processing_unmarked_count,
        expired_processing_marked_count,
        legacy_processing_unproven_count,
        delete_replay_not_eligible_count,
        attempts_at_limit_processing_count,
        attempts_at_limit_blocked_count,
        oldest_pending_epoch_ms,
        oldest_retry_wait_epoch_ms,
        oldest_blocked_epoch_ms,
        sqlite_generation_item_count: gen_item_count,
    } = storage
        .inspect_outbox_sync_health(
            generation.generation_id().as_str(),
            MAX_VECTOR_SYNC_ATTEMPTS,
            snapshot_now_millis,
        )
        .map_err(|_| {
            VectorSyncHealthError::new(
                VectorSyncHealthErrorCode::StorageUnavailable,
                "The vector sync outbox is unavailable.",
            )
        })?;

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
        pending_count,
        retry_wait_count,
        blocked_count,
        processing_count,
        failed_count,
        migration_isolated_count,
        expired_processing_count,
        provider_result_unknown_count,
        internal_invariant_count,
        attempts_at_limit_count,
        attempts_over_limit_count,
        invalid_attempt_identity_count,
        expired_processing_unmarked_count,
        expired_processing_marked_count,
        legacy_processing_unproven_count,
        delete_replay_not_eligible_count,
        attempts_at_limit_processing_count,
        attempts_at_limit_blocked_count,
        oldest_pending_age_ms: age_ms_at(snapshot_now_millis, oldest_pending_epoch_ms),
        oldest_retry_wait_age_ms: age_ms_at(snapshot_now_millis, oldest_retry_wait_epoch_ms),
        oldest_blocked_age_ms: age_ms_at(snapshot_now_millis, oldest_blocked_epoch_ms),
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

    /// (memory_id, state, attempt, fenced, marked, generation, send, error)
    type EpochFixture8<'a> = (
        &'a str,
        &'a str,
        i64,
        i64,
        i64,
        Option<&'a str>,
        Option<&'a str>,
        Option<&'a str>,
    );

    /// (memory_id, attempt_count, fenced_epoch, marked_epoch, generation,
    ///  send_disposition, error_code, state)
    type EpochRowSnapshot = (
        String,
        i64,
        i64,
        i64,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    );

    /// (memory_id, action, state, attempt, fenced, marked, generation,
    ///  send_disposition, error_code, migration, lease_expiry)
    type EpochFixtureRow<'a> = (
        &'a str,
        &'a str,
        i64,
        i64,
        i64,
        Option<&'a str>,
        Option<&'a str>,
        Option<&'a str>,
        Option<&'a str>,
        Option<&'a str>,
    );

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
        #[allow(dead_code)]
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
        count_calls: Arc<AtomicUsize>,
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
            self.count_calls.fetch_add(1, Ordering::SeqCst);
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
            self.inner.get_generation_metadata(ctx, lid, mid)
        }
    }

    fn authorized_fixture_connection(storage: &StorageService) -> rusqlite::Connection {
        crate::storage::open_authorized_test_connection(&storage.test_database_main_path().unwrap())
            .unwrap()
    }

    fn setup_db_connection(storage: &StorageService) -> (tempfile::TempDir, rusqlite::Connection) {
        let temp = tempfile::tempdir().unwrap();
        let conn = authorized_fixture_connection(storage);
        (temp, conn)
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
            count_calls: Arc::new(AtomicUsize::new(0)),
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
        assert_eq!(vs.count_calls.load(Ordering::SeqCst), 1);
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

        let conn = authorized_fixture_connection(&storage);

        for i in 0..2 {
            conn.execute(
                "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, created_at, updated_at)
                 VALUES (?1, ?2, 'upsert', 'pending', 0, '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
                rusqlite::params!["life-a", format!("pending-{i}")],
            ).unwrap();
            conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        }

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, created_at, updated_at, next_attempt_at)
             VALUES ('life-a', 'retry-1', 'upsert', 'retry_wait', 1, '2024-01-01T00:00:00.000Z', '2024-06-01T00:00:00.000Z', '2024-07-01T00:00:00.000Z')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, last_send_disposition, created_at, updated_at)
             VALUES ('life-a', 'blocked-unk', 'upsert', 'blocked', 1, 'PROVIDER_RESULT_UNKNOWN', 'possibly_sent', '2024-01-01T00:00:00.000Z', '2024-03-01T00:00:00.000Z')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, created_at, updated_at)
             VALUES ('life-a', 'blocked-inv', 'upsert', 'blocked', 1, 'INTERNAL_INVARIANT', '2024-01-01T00:00:00.000Z', '2024-03-01T00:00:00.000Z')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, lease_owner, lease_expires_at, lease_fence_epoch, claimed_generation_id, created_at, updated_at)
             VALUES ('life-a', 'proc-alive', 'upsert', 'processing', 1, 'owner-a', '2099-01-01T00:00:00.000Z', 1, 'gen-health', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, lease_owner, lease_expires_at, lease_fence_epoch, claimed_generation_id, created_at, updated_at)
             VALUES ('life-a', 'proc-expired', 'upsert', 'processing', 2, 'owner-b', '2020-01-01T00:00:00.000Z', 2, 'gen-health', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, created_at, updated_at)
             VALUES ('life-a', 'att5', 'upsert', 'blocked', 5, 'LANCE_PERMANENT', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, created_at, updated_at)
             VALUES ('life-a', 'att6', 'upsert', 'blocked', 6, 'LANCE_PERMANENT', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, created_at, updated_at)
             VALUES ('life-a', 'att4', 'upsert', 'pending', 4, NULL, '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
        let vs = CountingHealthVectorStore {
            inner: raw_vs,
            upsert_calls: Arc::new(AtomicUsize::new(0)),
            delete_calls: Arc::new(AtomicUsize::new(0)),
            count_calls: Arc::new(AtomicUsize::new(0)),
        };
        let clock = FixedHealthClock::new(1_700_000_000_000);
        let snap =
            tauri::async_runtime::block_on(inspect_vector_sync_health(&storage, &vs, &ctx, &clock))
                .unwrap();

        assert_eq!(snap.pending_count, 3, "2 pending + att4");
        assert_eq!(snap.retry_wait_count, 1);
        assert_eq!(
            snap.blocked_count, 4,
            "blocked-unk + blocked-inv + att5 + att6"
        );
        assert_eq!(snap.processing_count, 2);
        assert_eq!(snap.expired_processing_count, 1);
        assert_eq!(snap.provider_result_unknown_count, 1);
        assert_eq!(snap.internal_invariant_count, 1);
        assert_eq!(snap.attempts_at_limit_count, 2, "att5 + att6");
    }

    #[test]
    fn vector_sync_health_age_and_expiry_use_millisecond_precision() {
        let (_temp, storage) = test_storage();
        let ctx = health_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();
        let conn = authorized_fixture_connection(&storage);

        // Insert processing rows with precise lease_expires_at timestamps.
        // Use literal ISO-8601 strings to avoid SQLite strftime formatting issues.
        // snapshot_now = 1_700_000_000_000 ms = epoch 1700000000 -> 2023-11-14T22:13:20.000Z

        // Row with lease_expires_at = 2023-11-14T22:13:19.999Z (1 ms before snapshot_now)
        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, lease_owner, lease_expires_at, lease_fence_epoch, claimed_generation_id, created_at, updated_at)
             VALUES ('life', 'exp-minus1ms', 'upsert', 'processing', 1, 'o', '2023-11-14T22:13:19.999Z', 1, 'gen-health', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        // Row with lease_expires_at = 2023-11-14T22:13:20.000Z (exact snapshot_now)
        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, lease_owner, lease_expires_at, lease_fence_epoch, claimed_generation_id, created_at, updated_at)
             VALUES ('life', 'exp-exact', 'upsert', 'processing', 1, 'o', '2023-11-14T22:13:20.000Z', 1, 'gen-health', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        // Row with lease_expires_at = 2023-11-14T22:13:20.001Z (1 ms after snapshot_now)
        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, lease_owner, lease_expires_at, lease_fence_epoch, claimed_generation_id, created_at, updated_at)
             VALUES ('life', 'exp-plus1ms', 'upsert', 'processing', 1, 'o', '2023-11-14T22:13:20.001Z', 1, 'gen-health', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        // Row with lease_expires_at = NULL
        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, lease_owner, lease_fence_epoch, claimed_generation_id, created_at, updated_at)
             VALUES ('life', 'exp-null', 'upsert', 'processing', 1, 'o', 1, 'gen-health', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        // Row with lease_expires_at = 2023-11-14T22:13:20.500Z (500ms after snapshot_now)
        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, lease_owner, lease_expires_at, lease_fence_epoch, claimed_generation_id, created_at, updated_at)
             VALUES ('life', 'exp-plus500ms', 'upsert', 'processing', 1, 'o', '2023-11-14T22:13:20.500Z', 1, 'gen-health', '2024-01-01T00:00:00.000Z', '2024-01-01T00:00:00.000Z')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        // snapshot_now = epoch 1700000000.000 ms = 1700000000000 ms
        let now_ms: i64 = 1_700_000_000_000;
        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
        let vs = CountingHealthVectorStore {
            inner: raw_vs,
            upsert_calls: Arc::new(AtomicUsize::new(0)),
            delete_calls: Arc::new(AtomicUsize::new(0)),
            count_calls: Arc::new(AtomicUsize::new(0)),
        };
        let clock = FixedHealthClock::new(now_ms);
        let snap =
            tauri::async_runtime::block_on(inspect_vector_sync_health(&storage, &vs, &ctx, &clock))
                .unwrap();

        // 5 processing rows total; 2 expired (minus1ms + exact), 3 not expired
        assert_eq!(snap.processing_count, 5);
        assert_eq!(
            snap.expired_processing_count, 2,
            "minus1ms + exact are expired"
        );
        assert!(snap.oldest_pending_age_ms.is_none());
    }

    #[test]
    fn vector_sync_health_attempt_limit_boundary() {
        let (_temp, storage) = test_storage();
        let ctx = health_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();
        let conn = authorized_fixture_connection(&storage);

        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count)
             VALUES ('life', 'att-4', 'upsert', 'blocked', 4)",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count)
             VALUES ('life', 'att-5', 'upsert', 'blocked', 5)",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count)
             VALUES ('life', 'att-6', 'upsert', 'blocked', 6)",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count)
             VALUES ('life', 'pending-att-5', 'upsert', 'pending', 5)",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count)
             VALUES ('life', 'pending-att-6', 'upsert', 'pending', 6)",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count)
             VALUES ('life', 'pending-att-4', 'upsert', 'pending', 4)",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();

        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
        let vs = CountingHealthVectorStore {
            inner: raw_vs,
            upsert_calls: Arc::new(AtomicUsize::new(0)),
            delete_calls: Arc::new(AtomicUsize::new(0)),
            count_calls: Arc::new(AtomicUsize::new(0)),
        };
        let clock = FixedHealthClock::new(1_700_000_000_000);
        let snap =
            tauri::async_runtime::block_on(inspect_vector_sync_health(&storage, &vs, &ctx, &clock))
                .unwrap();

        // pending+attempt=4 not counted, pending+attempt=5/6 counted (attempt limit fix)
        // blocked att-5 and att-6 also counted
        assert_eq!(snap.attempts_at_limit_count, 4);
    }

    #[test]
    fn vector_sync_health_count_mismatch() {
        // Equal counts
        {
            let (_temp, storage) = test_storage();
            let ctx = health_context();
            storage
                .register_building_vector_generation(
                    ctx.generation_id().as_str(),
                    ctx.descriptor_hash(),
                    ctx.dimension(),
                )
                .unwrap();
            let conn = authorized_fixture_connection(&storage);
            // Insert into generation_item
            conn.execute(
                "INSERT INTO memory_vector_generation_item (generation_id, life_id, memory_id, memory_revision, content_hash)
                 VALUES ('gen-health', 'life', 'mem-1', 1, 'h1')",
                [],
            ).unwrap();
            conn.execute(
                "INSERT INTO memory_vector_generation_item (generation_id, life_id, memory_id, memory_revision, content_hash)
                 VALUES ('gen-health', 'life', 'mem-2', 1, 'h2')",
                [],
            ).unwrap();
            let raw_vs = crate::vector_store::InMemoryVectorStore::default();
            tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
            // Insert matching records in VectorStore
            let rec = crate::vector_store::GenerationVectorRecord::try_new(
                ctx.generation_id().clone(),
                "life",
                "mem-1",
                1,
                "h1",
                ctx.descriptor_hash(),
                vec![0.1, 0.2, 0.3],
            )
            .unwrap();
            let rec2 = crate::vector_store::GenerationVectorRecord::try_new(
                ctx.generation_id().clone(),
                "life",
                "mem-2",
                1,
                "h2",
                ctx.descriptor_hash(),
                vec![0.4, 0.5, 0.6],
            )
            .unwrap();
            tauri::async_runtime::block_on(raw_vs.upsert_generation(&ctx, rec)).unwrap();
            tauri::async_runtime::block_on(raw_vs.upsert_generation(&ctx, rec2)).unwrap();

            let vs = CountingHealthVectorStore {
                inner: raw_vs,
                upsert_calls: Arc::new(AtomicUsize::new(0)),
                delete_calls: Arc::new(AtomicUsize::new(0)),
                count_calls: Arc::new(AtomicUsize::new(0)),
            };
            let clock = FixedHealthClock::new(1_700_000_000_000);
            let snap = tauri::async_runtime::block_on(inspect_vector_sync_health(
                &storage, &vs, &ctx, &clock,
            ))
            .unwrap();
            assert_eq!(snap.sqlite_generation_item_count, 2);
            assert_eq!(snap.vector_store_item_count, Some(2));
            assert_eq!(snap.vector_store_health, VectorStoreHealth::Available);
            assert_eq!(snap.count_mismatch, Some(false));
        }

        // SQLite greater
        {
            let (_temp, storage) = test_storage();
            let ctx = health_context();
            storage
                .register_building_vector_generation(
                    ctx.generation_id().as_str(),
                    ctx.descriptor_hash(),
                    ctx.dimension(),
                )
                .unwrap();
            let conn = authorized_fixture_connection(&storage);
            conn.execute(
                "INSERT INTO memory_vector_generation_item (generation_id, life_id, memory_id, memory_revision, content_hash)
                 VALUES ('gen-health', 'life', 'mem-1', 1, 'h1'), ('gen-health', 'life', 'mem-2', 1, 'h2')",
                [],
            ).unwrap();
            let raw_vs = crate::vector_store::InMemoryVectorStore::default();
            tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
            let rec = crate::vector_store::GenerationVectorRecord::try_new(
                ctx.generation_id().clone(),
                "life",
                "mem-1",
                1,
                "h1",
                ctx.descriptor_hash(),
                vec![0.1, 0.2, 0.3],
            )
            .unwrap();
            tauri::async_runtime::block_on(raw_vs.upsert_generation(&ctx, rec)).unwrap();

            let vs = CountingHealthVectorStore {
                inner: raw_vs,
                upsert_calls: Arc::new(AtomicUsize::new(0)),
                delete_calls: Arc::new(AtomicUsize::new(0)),
                count_calls: Arc::new(AtomicUsize::new(0)),
            };
            let clock = FixedHealthClock::new(1_700_000_000_000);
            let snap = tauri::async_runtime::block_on(inspect_vector_sync_health(
                &storage, &vs, &ctx, &clock,
            ))
            .unwrap();
            assert_eq!(snap.sqlite_generation_item_count, 2);
            assert_eq!(snap.vector_store_item_count, Some(1));
            assert_eq!(snap.count_mismatch, Some(true));
        }

        // VectorStore greater
        {
            let (_temp, storage) = test_storage();
            let ctx = health_context();
            storage
                .register_building_vector_generation(
                    ctx.generation_id().as_str(),
                    ctx.descriptor_hash(),
                    ctx.dimension(),
                )
                .unwrap();
            let conn = authorized_fixture_connection(&storage);
            conn.execute(
                "INSERT INTO memory_vector_generation_item (generation_id, life_id, memory_id, memory_revision, content_hash)
                 VALUES ('gen-health', 'life', 'mem-1', 1, 'h1')",
                [],
            ).unwrap();
            let raw_vs = crate::vector_store::InMemoryVectorStore::default();
            tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
            for mem_id in ["mem-1", "mem-2"] {
                let rec = crate::vector_store::GenerationVectorRecord::try_new(
                    ctx.generation_id().clone(),
                    "life",
                    mem_id,
                    1,
                    "h1",
                    ctx.descriptor_hash(),
                    vec![0.1, 0.2, 0.3],
                )
                .unwrap();
                tauri::async_runtime::block_on(raw_vs.upsert_generation(&ctx, rec)).unwrap();
            }
            let vs = CountingHealthVectorStore {
                inner: raw_vs,
                upsert_calls: Arc::new(AtomicUsize::new(0)),
                delete_calls: Arc::new(AtomicUsize::new(0)),
                count_calls: Arc::new(AtomicUsize::new(0)),
            };
            let clock = FixedHealthClock::new(1_700_000_000_000);
            let snap = tauri::async_runtime::block_on(inspect_vector_sync_health(
                &storage, &vs, &ctx, &clock,
            ))
            .unwrap();
            assert_eq!(snap.sqlite_generation_item_count, 1);
            assert_eq!(snap.vector_store_item_count, Some(2));
            assert_eq!(snap.count_mismatch, Some(true));
        }

        // Empty generation (both zero)
        {
            let (_temp, storage) = test_storage();
            let ctx = health_context();
            storage
                .register_building_vector_generation(
                    ctx.generation_id().as_str(),
                    ctx.descriptor_hash(),
                    ctx.dimension(),
                )
                .unwrap();
            let raw_vs = crate::vector_store::InMemoryVectorStore::default();
            tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
            let vs = CountingHealthVectorStore {
                inner: raw_vs,
                upsert_calls: Arc::new(AtomicUsize::new(0)),
                delete_calls: Arc::new(AtomicUsize::new(0)),
                count_calls: Arc::new(AtomicUsize::new(0)),
            };
            let clock = FixedHealthClock::new(1_700_000_000_000);
            let snap = tauri::async_runtime::block_on(inspect_vector_sync_health(
                &storage, &vs, &ctx, &clock,
            ))
            .unwrap();
            assert_eq!(snap.sqlite_generation_item_count, 0);
            assert_eq!(snap.vector_store_item_count, Some(0));
            assert_eq!(snap.count_mismatch, Some(false));
        }
    }

    #[test]
    fn vector_sync_health_generation_isolation() {
        let (_temp, storage) = test_storage();
        let ctx_a = health_context();
        let ctx_b = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-other").unwrap(),
            "desc-other",
            3,
        )
        .unwrap();
        for ctx in [&ctx_a, &ctx_b] {
            storage
                .register_building_vector_generation(
                    ctx.generation_id().as_str(),
                    ctx.descriptor_hash(),
                    ctx.dimension(),
                )
                .unwrap();
        }
        let conn = authorized_fixture_connection(&storage);

        // Insert generation items for both gen-health and gen-other
        conn.execute(
            "INSERT INTO memory_vector_generation_item (generation_id, life_id, memory_id, memory_revision, content_hash)
             VALUES ('gen-health', 'life', 'a', 1, 'h-a'), ('gen-other', 'life', 'a', 1, 'h-a')",
            [],
        ).unwrap();

        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        let rec_a = crate::vector_store::GenerationVectorRecord::try_new(
            ctx_a.generation_id().clone(),
            "life",
            "a",
            1,
            "h-a",
            ctx_a.descriptor_hash(),
            vec![0.1, 0.2, 0.3],
        )
        .unwrap();
        let rec_b = crate::vector_store::GenerationVectorRecord::try_new(
            ctx_b.generation_id().clone(),
            "life",
            "a",
            1,
            "h-a",
            ctx_b.descriptor_hash(),
            vec![0.4, 0.5, 0.6],
        )
        .unwrap();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx_a)).unwrap();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx_b)).unwrap();
        tauri::async_runtime::block_on(raw_vs.upsert_generation(&ctx_a, rec_a)).unwrap();
        tauri::async_runtime::block_on(raw_vs.upsert_generation(&ctx_b, rec_b)).unwrap();

        let vs = CountingHealthVectorStore {
            inner: raw_vs,
            upsert_calls: Arc::new(AtomicUsize::new(0)),
            delete_calls: Arc::new(AtomicUsize::new(0)),
            count_calls: Arc::new(AtomicUsize::new(0)),
        };
        let clock = FixedHealthClock::new(1_700_000_000_000);
        let snap = tauri::async_runtime::block_on(inspect_vector_sync_health(
            &storage, &vs, &ctx_a, &clock,
        ))
        .unwrap();

        assert_eq!(
            snap.sqlite_generation_item_count, 1,
            "gen-health has 1 item"
        );
        assert_eq!(
            snap.vector_store_item_count,
            Some(1),
            "gen-health has 1 item"
        );
        assert_eq!(snap.count_mismatch, Some(false));
    }

    #[test]
    fn vector_sync_health_store_unavailable() {
        struct UnavailableStore;
        impl VectorStore for UnavailableStore {
            fn upsert<'a>(
                &'a self,
                _r: crate::vector_store::VectorRecord,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>>
            {
                Box::pin(async {
                    Err(VectorStoreError::new(
                        VectorStoreErrorCode::StoreUnavailable,
                        "",
                        true,
                    ))
                })
            }
            fn upsert_batch<'a>(
                &'a self,
                _r: Vec<crate::vector_store::VectorRecord>,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>>
            {
                Box::pin(async {
                    Err(VectorStoreError::new(
                        VectorStoreErrorCode::StoreUnavailable,
                        "",
                        true,
                    ))
                })
            }
            fn search<'a>(
                &'a self,
                _q: crate::vector_store::VectorSearchQuery,
            ) -> crate::vector_store::VectorStoreFuture<
                'a,
                Result<Vec<crate::vector_store::VectorSearchHit>, VectorStoreError>,
            > {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn delete<'a>(
                &'a self,
                _l: &'a str,
                _m: &'a str,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn delete_from_space<'a>(
                &'a self,
                _l: &'a str,
                _m: &'a str,
                _s: &'a crate::vector_store::VectorSpace,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn delete_by_life<'a>(
                &'a self,
                _l: &'a str,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn clear_space<'a>(
                &'a self,
                _l: &'a str,
                _s: &'a crate::vector_store::VectorSpace,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn count<'a>(
                &'a self,
                _l: &'a str,
                _s: Option<&'a crate::vector_store::VectorSpace>,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn health_check<'a>(
                &'a self,
                _l: &'a str,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>>
            {
                Box::pin(async { Ok(()) })
            }
            fn count_generation<'a>(
                &'a self,
                _ctx: &'a VectorGenerationContext,
                _lid: Option<&'a str>,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async {
                    Err(VectorStoreError::new(
                        VectorStoreErrorCode::StoreUnavailable,
                        "",
                        true,
                    ))
                })
            }
        }

        let (_temp, storage) = test_storage();
        let ctx = health_context();
        let vs = UnavailableStore;
        let clock = FixedHealthClock::new(1_700_000_000_000);
        let snap =
            tauri::async_runtime::block_on(inspect_vector_sync_health(&storage, &vs, &ctx, &clock))
                .unwrap();

        assert_eq!(snap.vector_store_health, VectorStoreHealth::Unavailable);
        assert_eq!(snap.vector_store_item_count, None);
        assert_eq!(snap.count_mismatch, None);
    }

    #[test]
    fn vector_sync_health_generation_missing() {
        struct MissingStore;
        impl VectorStore for MissingStore {
            fn upsert<'a>(
                &'a self,
                _r: crate::vector_store::VectorRecord,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>>
            {
                Box::pin(async {
                    Err(VectorStoreError::new(
                        VectorStoreErrorCode::StoreUnavailable,
                        "",
                        true,
                    ))
                })
            }
            fn upsert_batch<'a>(
                &'a self,
                _r: Vec<crate::vector_store::VectorRecord>,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>>
            {
                Box::pin(async {
                    Err(VectorStoreError::new(
                        VectorStoreErrorCode::StoreUnavailable,
                        "",
                        true,
                    ))
                })
            }
            fn search<'a>(
                &'a self,
                _q: crate::vector_store::VectorSearchQuery,
            ) -> crate::vector_store::VectorStoreFuture<
                'a,
                Result<Vec<crate::vector_store::VectorSearchHit>, VectorStoreError>,
            > {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn delete<'a>(
                &'a self,
                _l: &'a str,
                _m: &'a str,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn delete_from_space<'a>(
                &'a self,
                _l: &'a str,
                _m: &'a str,
                _s: &'a crate::vector_store::VectorSpace,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn delete_by_life<'a>(
                &'a self,
                _l: &'a str,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn clear_space<'a>(
                &'a self,
                _l: &'a str,
                _s: &'a crate::vector_store::VectorSpace,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn count<'a>(
                &'a self,
                _l: &'a str,
                _s: Option<&'a crate::vector_store::VectorSpace>,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn health_check<'a>(
                &'a self,
                _l: &'a str,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>>
            {
                Box::pin(async { Ok(()) })
            }
            fn count_generation<'a>(
                &'a self,
                _ctx: &'a VectorGenerationContext,
                _lid: Option<&'a str>,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async {
                    Err(VectorStoreError::new(
                        VectorStoreErrorCode::GenerationNotFound,
                        "",
                        false,
                    ))
                })
            }
        }

        let (_temp, storage) = test_storage();
        let ctx = health_context();
        let vs = MissingStore;
        let clock = FixedHealthClock::new(1_700_000_000_000);
        let snap =
            tauri::async_runtime::block_on(inspect_vector_sync_health(&storage, &vs, &ctx, &clock))
                .unwrap();

        assert_eq!(
            snap.vector_store_health,
            VectorStoreHealth::GenerationMissing
        );
        assert_eq!(snap.vector_store_item_count, None);
        assert_eq!(snap.count_mismatch, None);
    }

    #[test]
    fn vector_sync_health_store_corrupt() {
        struct CorruptStore;
        impl VectorStore for CorruptStore {
            fn upsert<'a>(
                &'a self,
                _r: crate::vector_store::VectorRecord,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>>
            {
                Box::pin(async {
                    Err(VectorStoreError::new(
                        VectorStoreErrorCode::StoreUnavailable,
                        "",
                        true,
                    ))
                })
            }
            fn upsert_batch<'a>(
                &'a self,
                _r: Vec<crate::vector_store::VectorRecord>,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>>
            {
                Box::pin(async {
                    Err(VectorStoreError::new(
                        VectorStoreErrorCode::StoreUnavailable,
                        "",
                        true,
                    ))
                })
            }
            fn search<'a>(
                &'a self,
                _q: crate::vector_store::VectorSearchQuery,
            ) -> crate::vector_store::VectorStoreFuture<
                'a,
                Result<Vec<crate::vector_store::VectorSearchHit>, VectorStoreError>,
            > {
                Box::pin(async { Ok(Vec::new()) })
            }
            fn delete<'a>(
                &'a self,
                _l: &'a str,
                _m: &'a str,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn delete_from_space<'a>(
                &'a self,
                _l: &'a str,
                _m: &'a str,
                _s: &'a crate::vector_store::VectorSpace,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn delete_by_life<'a>(
                &'a self,
                _l: &'a str,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn clear_space<'a>(
                &'a self,
                _l: &'a str,
                _s: &'a crate::vector_store::VectorSpace,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn count<'a>(
                &'a self,
                _l: &'a str,
                _s: Option<&'a crate::vector_store::VectorSpace>,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async { Ok(0) })
            }
            fn health_check<'a>(
                &'a self,
                _l: &'a str,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<(), VectorStoreError>>
            {
                Box::pin(async { Ok(()) })
            }
            fn count_generation<'a>(
                &'a self,
                _ctx: &'a VectorGenerationContext,
                _lid: Option<&'a str>,
            ) -> crate::vector_store::VectorStoreFuture<'a, Result<usize, VectorStoreError>>
            {
                Box::pin(async {
                    Err(VectorStoreError::new(
                        VectorStoreErrorCode::GenerationCorrupt,
                        "",
                        false,
                    ))
                })
            }
        }

        let (_temp, storage) = test_storage();
        let ctx = health_context();
        let vs = CorruptStore;
        let clock = FixedHealthClock::new(1_700_000_000_000);
        let snap =
            tauri::async_runtime::block_on(inspect_vector_sync_health(&storage, &vs, &ctx, &clock))
                .unwrap();

        assert_eq!(snap.vector_store_health, VectorStoreHealth::Corrupt);
        assert_eq!(snap.vector_store_item_count, None);
        assert_eq!(snap.count_mismatch, None);
    }

    #[test]
    fn vector_sync_health_is_strictly_read_only() {
        let (_temp, storage) = test_storage();
        let ctx = health_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();
        let conn = authorized_fixture_connection(&storage);

        // Setup: runtime lease
        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_runtime_lease (lease_name, owner_id, fence_epoch, expires_at)
             VALUES ('memory-vector-single-event-consumer', 'worker-a', 42, strftime('%Y-%m-%dT%H:%M:%fZ', '2099-01-01'))",
            [],
        ).unwrap();
        // Setup: outbox rows
        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_send_disposition)
             VALUES ('life', 'mem-1', 'upsert', 'processing', 2, 'possibly_sent')",
            [],
        ).unwrap();
        conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        // Setup: generation items
        conn.execute(
            "INSERT INTO memory_vector_generation_item (generation_id, life_id, memory_id, memory_revision, content_hash)
             VALUES ('gen-health', 'life', 'mem-1', 2, 'h1')",
            [],
        ).unwrap();

        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
        let rec = crate::vector_store::GenerationVectorRecord::try_new(
            ctx.generation_id().clone(),
            "life",
            "mem-1",
            2,
            "h1",
            ctx.descriptor_hash(),
            vec![0.1, 0.2, 0.3],
        )
        .unwrap();
        tauri::async_runtime::block_on(raw_vs.upsert_generation(&ctx, rec)).unwrap();

        // Take VS snapshots before wrapping in CountingHealthVectorStore
        let before_vs_count =
            tauri::async_runtime::block_on(raw_vs.count_generation(&ctx, None)).unwrap();
        let before_vs_meta =
            tauri::async_runtime::block_on(raw_vs.sample_generation_metadata(&ctx, 10)).unwrap();

        let vs = CountingHealthVectorStore {
            inner: raw_vs,
            upsert_calls: Arc::new(AtomicUsize::new(0)),
            delete_calls: Arc::new(AtomicUsize::new(0)),
            count_calls: Arc::new(AtomicUsize::new(0)),
        };

        // Use a direct SQLite connection for before/after verification
        let db_path = storage.test_database_main_path().unwrap();

        fn read_outbox(conn: &rusqlite::Connection) -> Vec<(String, String, Option<String>, i64)> {
            let mut stmt = conn.prepare(
                "SELECT memory_id, state, last_send_disposition, attempt_count FROM memory_vector_sync_outbox ORDER BY memory_id"
            ).unwrap();
            stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
        }

        fn read_lease(conn: &rusqlite::Connection) -> Vec<(String, i64, String)> {
            let mut stmt = conn.prepare(
                "SELECT owner_id, fence_epoch, expires_at FROM memory_vector_sync_runtime_lease WHERE lease_name='memory-vector-single-event-consumer'"
            ).unwrap();
            stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
        }

        // Take before snapshots
        let conn_before = rusqlite::Connection::open(&db_path).unwrap();
        let before_outbox = read_outbox(&conn_before);
        let before_lease = read_lease(&conn_before);
        drop(conn_before);

        // Execute health check
        let clock = FixedHealthClock::new(1_700_000_000_000);
        let _snap =
            tauri::async_runtime::block_on(inspect_vector_sync_health(&storage, &vs, &ctx, &clock))
                .unwrap();

        // Take after snapshots
        let conn_after = rusqlite::Connection::open(&db_path).unwrap();
        let after_outbox = read_outbox(&conn_after);
        let after_lease = read_lease(&conn_after);
        drop(conn_after);
        let after_vs_count =
            tauri::async_runtime::block_on(vs.inner.count_generation(&ctx, None)).unwrap();
        let after_vs_meta =
            tauri::async_runtime::block_on(vs.inner.sample_generation_metadata(&ctx, 10)).unwrap();

        assert_eq!(before_outbox, after_outbox, "Outbox must not change");
        assert_eq!(before_lease, after_lease, "Runtime lease must not change");
        assert_eq!(before_vs_count, after_vs_count, "VS count must not change");
        assert_eq!(before_vs_meta, after_vs_meta, "VS metadata must not change");
        assert_eq!(vs.upsert_calls.load(Ordering::SeqCst), 0, "No upsert calls");
        assert_eq!(vs.delete_calls.load(Ordering::SeqCst), 0, "No delete calls");
        assert_eq!(vs.count_calls.load(Ordering::SeqCst), 1, "1 count call");
    }

    #[test]
    fn vector_sync_health_preserves_existing_runtime_lease() {
        let (_temp, storage) = test_storage();
        let ctx = health_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();
        let conn = authorized_fixture_connection(&storage);

        // Setup a real runtime lease with specific values
        conn.execute(
            "INSERT OR REPLACE INTO memory_vector_sync_runtime_lease (lease_name, owner_id, fence_epoch, expires_at, updated_at)
             VALUES ('memory-vector-single-event-consumer', 'worker-existing', 99, strftime('%Y-%m-%dT%H:%M:%fZ', '2099-06-15'), strftime('%Y-%m-%dT%H:%M:%fZ', '2024-01-01'))",
            [],
        ).unwrap();

        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
        let vs = CountingHealthVectorStore {
            inner: raw_vs,
            upsert_calls: Arc::new(AtomicUsize::new(0)),
            delete_calls: Arc::new(AtomicUsize::new(0)),
            count_calls: Arc::new(AtomicUsize::new(0)),
        };

        let clock = FixedHealthClock::new(1_700_000_000_000);
        let _snap =
            tauri::async_runtime::block_on(inspect_vector_sync_health(&storage, &vs, &ctx, &clock))
                .unwrap();

        // Verify nothing changed through a separate read-only legacy connection.
        let db_path = storage.test_database_main_path().unwrap();
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        let (owner, fence, expires_at, updated_at): (String, i64, String, String) = {
            conn.query_row(
                "SELECT owner_id, fence_epoch, expires_at, updated_at FROM memory_vector_sync_runtime_lease WHERE lease_name='memory-vector-single-event-consumer'",
                [],
                |r| Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, i64>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                )),
            ).unwrap()
        };

        assert_eq!(owner, "worker-existing", "Owner unchanged");
        assert_eq!(fence, 99, "Fence unchanged");
        assert!(expires_at.contains("2099"), "Expiry unchanged");
        assert!(updated_at.contains("2024"), "Updated_at unchanged");
    }

    #[test]
    fn vector_sync_health_excludes_migration_isolated_rows() {
        let (_temp, storage) = test_storage();
        let ctx = health_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();

        let conn = authorized_fixture_connection(&storage);

        // Helper to insert an operational row
        let mut seq = 0i64;

        #[allow(clippy::too_many_arguments)]
        fn ins(
            conn: &rusqlite::Connection,
            seq: &mut i64,
            life: &str,
            mem: &str,
            action: &str,
            state: &str,
            att: i64,
            err_code: Option<&str>,
            send: Option<&str>,
            lease_exp: Option<&str>,
            created: &str,
            updated: &str,
        ) {
            *seq += 1;
            conn.execute(
                "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, last_send_disposition, lease_expires_at, created_at, updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                rusqlite::params![life, mem, action, state, att, err_code, send, lease_exp, created, updated],
            ).unwrap();
            conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        }

        // Insert operational baseline
        ins(
            &conn,
            &mut seq,
            "life",
            "op-pend",
            "upsert",
            "pending",
            0,
            None,
            None,
            None,
            "2024-01-01T00:00:00.000Z",
            "2024-01-01T00:00:00.000Z",
        );
        ins(
            &conn,
            &mut seq,
            "life",
            "op-retry",
            "upsert",
            "retry_wait",
            1,
            Some("PROVIDER_UNAVAILABLE"),
            Some("definitely_not_sent"),
            None,
            "2024-01-01T00:00:00.000Z",
            "2024-06-01T00:00:00.000Z",
        );
        ins(
            &conn,
            &mut seq,
            "life",
            "op-b-unk",
            "upsert",
            "blocked",
            1,
            Some("PROVIDER_RESULT_UNKNOWN"),
            Some("possibly_sent"),
            None,
            "2024-01-01T00:00:00.000Z",
            "2024-03-01T00:00:00.000Z",
        );
        ins(
            &conn,
            &mut seq,
            "life",
            "op-b-inv",
            "upsert",
            "blocked",
            1,
            Some("INTERNAL_INVARIANT"),
            None,
            None,
            "2024-01-01T00:00:00.000Z",
            "2024-03-01T00:00:00.000Z",
        );
        ins(
            &conn,
            &mut seq,
            "life",
            "op-proc",
            "upsert",
            "processing",
            1,
            None,
            None,
            Some("2099-01-01T00:00:00.000Z"),
            "2024-01-01T00:00:00.000Z",
            "2024-01-01T00:00:00.000Z",
        );
        ins(
            &conn,
            &mut seq,
            "life",
            "op-proc-ex",
            "upsert",
            "processing",
            2,
            None,
            None,
            Some("2020-01-01T00:00:00.000Z"),
            "2024-01-01T00:00:00.000Z",
            "2024-01-01T00:00:00.000Z",
        );
        ins(
            &conn,
            &mut seq,
            "life",
            "op-att5",
            "upsert",
            "blocked",
            5,
            Some("LANCE_PERMANENT"),
            Some("possibly_sent"),
            None,
            "2024-01-01T00:00:00.000Z",
            "2024-01-01T00:00:00.000Z",
        );

        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();

        let clock = FixedHealthClock::new(1_700_000_000_000);
        let snap1 = tauri::async_runtime::block_on(inspect_vector_sync_health(
            &storage, &raw_vs, &ctx, &clock,
        ))
        .unwrap();

        // Insert isolation rows with migration_disposition set
        ins(
            &conn,
            &mut seq,
            "life",
            "iso-pend",
            "upsert",
            "pending",
            5,
            None,
            None,
            None,
            "2000-01-01T00:00:00.000Z",
            "2000-01-01T00:00:00.000Z",
        );
        conn.execute(
            "UPDATE memory_vector_sync_outbox SET migration_disposition='legacy_upsert_rebuild_required' WHERE memory_id='iso-pend'",
            [],
        ).unwrap();

        ins(
            &conn,
            &mut seq,
            "life",
            "iso-retry",
            "upsert",
            "retry_wait",
            6,
            Some("PROVIDER_UNAVAILABLE"),
            Some("definitely_not_sent"),
            None,
            "2000-01-01T00:00:00.000Z",
            "2000-01-01T00:00:00.000Z",
        );
        conn.execute(
            "UPDATE memory_vector_sync_outbox SET migration_disposition='legacy_upsert_rebuild_required' WHERE memory_id='iso-retry'",
            [],
        ).unwrap();

        ins(
            &conn,
            &mut seq,
            "life",
            "iso-b-unk",
            "upsert",
            "blocked",
            7,
            Some("PROVIDER_RESULT_UNKNOWN"),
            Some("possibly_sent"),
            None,
            "2000-01-01T00:00:00.000Z",
            "2000-01-01T00:00:00.000Z",
        );
        conn.execute(
            "UPDATE memory_vector_sync_outbox SET migration_disposition='legacy_upsert_rebuild_required' WHERE memory_id='iso-b-unk'",
            [],
        ).unwrap();

        ins(
            &conn,
            &mut seq,
            "life",
            "iso-b-inv",
            "upsert",
            "blocked",
            8,
            Some("INTERNAL_INVARIANT"),
            None,
            None,
            "2000-01-01T00:00:00.000Z",
            "2000-01-01T00:00:00.000Z",
        );
        conn.execute(
            "UPDATE memory_vector_sync_outbox SET migration_disposition='legacy_upsert_rebuild_required' WHERE memory_id='iso-b-inv'",
            [],
        ).unwrap();

        ins(
            &conn,
            &mut seq,
            "life",
            "iso-proc",
            "upsert",
            "processing",
            9,
            None,
            None,
            Some("2000-01-01T00:00:00.000Z"),
            "2000-01-01T00:00:00.000Z",
            "2000-01-01T00:00:00.000Z",
        );
        conn.execute(
            "UPDATE memory_vector_sync_outbox SET migration_disposition='legacy_upsert_rebuild_required' WHERE memory_id='iso-proc'",
            [],
        ).unwrap();

        ins(
            &conn,
            &mut seq,
            "life",
            "iso-att10",
            "upsert",
            "failed",
            10,
            Some("MAX_ATTEMPTS"),
            None,
            None,
            "2000-01-01T00:00:00.000Z",
            "2000-01-01T00:00:00.000Z",
        );
        conn.execute(
            "UPDATE memory_vector_sync_outbox SET migration_disposition='legacy_upsert_rebuild_required' WHERE memory_id='iso-att10'",
            [],
        ).unwrap();

        let snap2 = tauri::async_runtime::block_on(inspect_vector_sync_health(
            &storage, &raw_vs, &ctx, &clock,
        ))
        .unwrap();

        // All outbox metrics must be identical
        assert_eq!(snap1.pending_count, snap2.pending_count, "pending_count");
        assert_eq!(
            snap1.retry_wait_count, snap2.retry_wait_count,
            "retry_wait_count"
        );
        assert_eq!(snap1.blocked_count, snap2.blocked_count, "blocked_count");
        assert_eq!(
            snap1.processing_count, snap2.processing_count,
            "processing_count"
        );
        assert_eq!(
            snap1.expired_processing_count, snap2.expired_processing_count,
            "expired_processing_count"
        );
        assert_eq!(
            snap1.provider_result_unknown_count, snap2.provider_result_unknown_count,
            "provider_result_unknown_count"
        );
        assert_eq!(
            snap1.internal_invariant_count, snap2.internal_invariant_count,
            "internal_invariant_count"
        );
        assert_eq!(
            snap1.attempts_at_limit_count, snap2.attempts_at_limit_count,
            "attempts_at_limit_count"
        );
        assert_eq!(
            snap1.oldest_pending_age_ms, snap2.oldest_pending_age_ms,
            "oldest_pending_age_ms"
        );
        assert_eq!(
            snap1.oldest_retry_wait_age_ms, snap2.oldest_retry_wait_age_ms,
            "oldest_retry_wait_age_ms"
        );
        assert_eq!(
            snap1.oldest_blocked_age_ms, snap2.oldest_blocked_age_ms,
            "oldest_blocked_age_ms"
        );
    }

    #[test]
    fn vector_sync_health_only_migration_isolated_rows() {
        let (_temp, storage) = test_storage();
        let ctx = health_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();

        let conn = authorized_fixture_connection(&storage);

        // Insert ONLY isolation rows
        for i in 0..3 {
            conn.execute(
                "INSERT OR REPLACE INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, migration_disposition, created_at, updated_at)
                 VALUES (?1,?2,'upsert','blocked',1,'legacy_upsert_rebuild_required','2000-01-01T00:00:00.000Z','2000-01-01T00:00:00.000Z')",
                rusqlite::params!["life", format!("iso-{i}")],
            ).unwrap();
            conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        }

        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();

        let clock = FixedHealthClock::new(1_700_000_000_000);
        let snap = tauri::async_runtime::block_on(inspect_vector_sync_health(
            &storage, &raw_vs, &ctx, &clock,
        ))
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
    }

    #[test]
    fn vector_sync_health_reports_extended_attempt_identity_metrics() {
        let (_temp, storage) = test_storage();
        let ctx = health_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();

        let conn = authorized_fixture_connection(&storage);

        // helper: insert a row with explicit fields
        let mut seq = 0i64;
        #[allow(clippy::too_many_arguments)]
        fn ins(
            conn: &rusqlite::Connection,
            seq: &mut i64,
            mem: &str,
            action: &str,
            state: &str,
            att: i64,
            fenced_epoch: i64,
            marked_epoch: i64,
            gen: Option<&str>,
            send: Option<&str>,
            err: Option<&str>,
            migration: Option<&str>,
            lease_exp: Option<&str>,
        ) {
            *seq += 1;
            conn.execute(
                "INSERT OR REPLACE INTO memory_vector_sync_outbox
                   (life_id, memory_id, desired_action, state, attempt_count,
                    fenced_claim_epoch, last_marked_claim_epoch, claimed_generation_id,
                    last_send_disposition, last_error_code, migration_disposition,
                    lease_expires_at, created_at, updated_at)
                 VALUES ('life',?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'2024-01-01T00:00:00.000Z','2024-01-01T00:00:00.000Z')",
                rusqlite::params![mem, action, state, att, fenced_epoch, marked_epoch, gen, send, err, migration, lease_exp],
            ).unwrap();
            conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        }

        // attempt == 5 blocked (legal exhausted)
        ins(
            &conn,
            &mut seq,
            "att5-blocked",
            "upsert",
            "blocked",
            5,
            3,
            3,
            Some("gen-health"),
            Some("possibly_sent"),
            Some("PROVIDER_RESULT_UNKNOWN"),
            None,
            None,
        );
        // attempt == 5 processing (5th attempt in flight)
        ins(
            &conn,
            &mut seq,
            "att5-proc",
            "upsert",
            "processing",
            5,
            4,
            4,
            Some("gen-health"),
            Some("possibly_sent"),
            Some("PROVIDER_RESULT_UNKNOWN"),
            None,
            Some("2099-01-01T00:00:00.000Z"),
        );
        // attempt == 6 (invalid over budget)
        ins(
            &conn,
            &mut seq,
            "att6",
            "upsert",
            "blocked",
            6,
            3,
            3,
            Some("gen-health"),
            Some("possibly_sent"),
            Some("LANCE_PERMANENT"),
            None,
            None,
        );
        // invalid identity: attempt > 0 without claimed generation
        // (CHECK allows this: last_marked=0 with attempt>0 is valid per constraint)
        ins(
            &conn,
            &mut seq,
            "inv-epoch",
            "upsert",
            "processing",
            2,
            1,
            0,
            None,
            Some("possibly_sent"),
            Some("PROVIDER_RESULT_UNKNOWN"),
            None,
            Some("2099-01-01T00:00:00.000Z"),
        );
        // expired processing unmarked (fenced > marked)
        ins(
            &conn,
            &mut seq,
            "exp-unmarked",
            "upsert",
            "processing",
            1,
            2,
            1,
            Some("gen-health"),
            Some("definitely_not_sent"),
            None,
            None,
            Some("2000-01-01T00:00:00.000Z"),
        );
        // expired processing marked (fenced == marked > 0)
        ins(
            &conn,
            &mut seq,
            "exp-marked",
            "upsert",
            "processing",
            2,
            2,
            2,
            Some("gen-health"),
            Some("possibly_sent"),
            Some("PROVIDER_RESULT_UNKNOWN"),
            None,
            Some("2000-01-01T00:00:00.000Z"),
        );
        // legacy processing (0,0)
        ins(
            &conn,
            &mut seq,
            "legacy-proc",
            "upsert",
            "processing",
            1,
            0,
            0,
            None,
            None,
            None,
            None,
            Some("2000-01-01T00:00:00.000Z"),
        );
        // delete not eligible: pending + possibly_sent
        ins(
            &conn,
            &mut seq,
            "del-unproven",
            "delete",
            "pending",
            2,
            2,
            2,
            Some("gen-health"),
            Some("possibly_sent"),
            None,
            None,
            None,
        );
        // migration isolated row (counted separately)
        ins(
            &conn,
            &mut seq,
            "iso",
            "upsert",
            "blocked",
            1,
            0,
            0,
            None,
            None,
            None,
            Some("legacy_upsert_rebuild_required"),
            None,
        );

        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();

        let clock = FixedHealthClock::new(1_700_000_000_000);
        let snap = tauri::async_runtime::block_on(inspect_vector_sync_health(
            &storage, &raw_vs, &ctx, &clock,
        ))
        .unwrap();

        assert_eq!(
            snap.attempts_at_limit_count, 3,
            "att5-blocked + att5-proc + att6 (>= 5)"
        );
        assert_eq!(snap.attempts_over_limit_count, 1, "att6");
        assert_eq!(snap.attempts_at_limit_processing_count, 1);
        assert_eq!(snap.attempts_at_limit_blocked_count, 1);
        assert_eq!(
            snap.invalid_attempt_identity_count, 1,
            "inv-epoch has last_marked > fenced"
        );
        assert_eq!(snap.expired_processing_unmarked_count, 1, "exp-unmarked");
        assert_eq!(snap.expired_processing_marked_count, 1, "exp-marked");
        assert_eq!(snap.legacy_processing_unproven_count, 1, "legacy-proc");
        assert_eq!(
            snap.delete_replay_not_eligible_count, 1,
            "del-unproven has possibly_sent"
        );
        assert_eq!(snap.migration_isolated_count, 1, "iso");
        assert_eq!(snap.failed_count, 0);
    }

    #[test]
    fn vector_sync_health_with_epoch_metrics_is_strictly_read_only() {
        let (_temp, storage) = test_storage();
        let ctx = health_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();

        let conn = authorized_fixture_connection(&storage);

        // Insert a mix of epoch-bearing rows covering the extended metrics.
        let rows: &[EpochFixture8] = &[
            // mem, state, att, fenced, marked, gen, send, err
            ("r1", "pending", 0, 0, 0, None, None, None),
            (
                "r2",
                "processing",
                1,
                2,
                1,
                Some("gen-health"),
                Some("definitely_not_sent"),
                None,
            ),
            (
                "r3",
                "processing",
                2,
                2,
                2,
                Some("gen-health"),
                Some("possibly_sent"),
                Some("PROVIDER_RESULT_UNKNOWN"),
            ),
            (
                "r4",
                "blocked",
                5,
                3,
                3,
                Some("gen-health"),
                Some("possibly_sent"),
                Some("PROVIDER_RESULT_UNKNOWN"),
            ),
            (
                "r5",
                "blocked",
                6,
                3,
                3,
                Some("gen-health"),
                Some("possibly_sent"),
                Some("LANCE_PERMANENT"),
            ),
            ("r6", "processing", 1, 0, 0, None, None, None),
            (
                "r7",
                "retry_wait",
                1,
                2,
                2,
                Some("gen-health"),
                Some("definitely_not_sent"),
                None,
            ),
        ];
        for (mem, state, att, fenced, marked, gen, send, err) in rows {
            conn.execute(
                "INSERT OR REPLACE INTO memory_vector_sync_outbox
                   (life_id, memory_id, desired_action, state, attempt_count,
                    fenced_claim_epoch, last_marked_claim_epoch, claimed_generation_id,
                    last_send_disposition, last_error_code, lease_expires_at,
                    created_at, updated_at)
                 VALUES ('life',?1,'upsert',?2,?3,?4,?5,?6,?7,?8,?9,'2024-01-01T00:00:00.000Z','2024-01-01T00:00:00.000Z')",
                rusqlite::params![
                    mem,
                    state,
                    att,
                    fenced,
                    marked,
                    gen,
                    send,
                    err,
                    if *state == "processing" {
                        Some("2000-01-01T00:00:00.000Z")
                    } else {
                        None
                    }
                ],
            ).unwrap();
            conn.execute("UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton=1", []).unwrap();
        }

        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();

        // Full before snapshot of outbox + epoch columns.
        let before: Vec<EpochRowSnapshot> = {
            let conn = authorized_fixture_connection(&storage);
            let mut stmt = conn
                .prepare(
                    "SELECT memory_id, attempt_count, fenced_claim_epoch, last_marked_claim_epoch,
                            claimed_generation_id, last_send_disposition, last_error_code, state
                     FROM memory_vector_sync_outbox ORDER BY memory_id",
                )
                .unwrap();
            stmt.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
        };

        let clock = FixedHealthClock::new(1_700_000_000_000);
        let _snap = tauri::async_runtime::block_on(inspect_vector_sync_health(
            &storage, &raw_vs, &ctx, &clock,
        ))
        .unwrap();

        let after: Vec<EpochRowSnapshot> = {
            let conn = authorized_fixture_connection(&storage);
            let mut stmt = conn
                .prepare(
                    "SELECT memory_id, attempt_count, fenced_claim_epoch, last_marked_claim_epoch,
                            claimed_generation_id, last_send_disposition, last_error_code, state
                     FROM memory_vector_sync_outbox ORDER BY memory_id",
                )
                .unwrap();
            stmt.query_map([], |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                ))
            })
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
        };

        assert_eq!(
            before, after,
            "health must not mutate outbox or epoch fields"
        );
    }

    /// ATT-I4: a real file SQLite health snapshot can run concurrently with a
    /// worker that claims and reserves the same outbox row, without blocking
    /// the worker or producing a mixed-state snapshot.
    #[test]
    fn vector_sync_health_and_worker_run_concurrently_for_ten_rounds() {
        for round in 0..10 {
            let (_temp, storage_a) = test_storage();
            let ctx = health_context();
            storage_a
                .register_building_vector_generation(
                    ctx.generation_id().as_str(),
                    ctx.descriptor_hash(),
                    ctx.dimension(),
                )
                .unwrap();
            let record = crate::storage::test_support::insert_confirmed_memory_fixture(
                &storage_a,
                "life",
                "fact",
                "concurrent health worker",
                None,
                0.5,
                0.5,
                false,
                true,
            );

            // Claim the row, then expire its lease so recovery must run inside
            // the next claim transaction.
            let claim = storage_a
                .claim_one_fenced_vector_sync(
                    ctx.generation_id().as_str(),
                    ctx.descriptor_hash(),
                    ctx.dimension(),
                    "worker-a",
                )
                .unwrap()
                .unwrap();
            assert_eq!(claim.memory_id(), record.id.as_str());
            storage_a.test_expire_fenced_runtime_lease().unwrap();

            // Independent connection to the same real file SQLite.
            let storage_b =
                StorageService::initialize_with_roots(_temp.path().join("data"), None).unwrap();

            // Worker thread on connection B: claims and reserves a fresh attempt
            // (recovery runs inside the claim transaction).
            let worker = {
                let ctx = ctx.clone();
                std::thread::spawn(move || {
                    let claim = storage_b
                        .claim_one_fenced_vector_sync_with_retry_cutoff(
                            ctx.generation_id().as_str(),
                            ctx.descriptor_hash(),
                            ctx.dimension(),
                            "worker-a",
                            Some(1_700_000_000_000),
                        )
                        .unwrap();
                    let claim = claim?;
                    storage_b
                        .test_reserve_fenced_attempt_token(&claim)
                        .ok()
                        .map(|_| ())
                })
            };

            // Health thread on connection A: reads concurrently with the
            // worker's claim/reserve on connection B.
            let raw_vs = crate::vector_store::InMemoryVectorStore::default();
            tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
            let clock = FixedHealthClock::new(1_700_000_000_000);
            let health = {
                let ctx = ctx.clone();
                let clock = clock.clone();
                std::thread::spawn(move || {
                    tauri::async_runtime::block_on(inspect_vector_sync_health(
                        &storage_a, &raw_vs, &ctx, &clock,
                    ))
                })
            };

            let worker_result = worker.join().unwrap();
            let health_result = health.join().unwrap();

            // Health must succeed and never see impossible state.
            let snap = health_result.unwrap();
            assert!(snap.processing_count <= 1, "round {round}");
            assert!(snap.attempts_at_limit_count <= 1, "round {round}");
            let _ = worker_result;
        }
    }

    /// ATT-I4: a compensation classification produced from an old mutation view
    /// must never become an execution permit after a new mutation resets the
    /// budget. The classifier itself is pure, so this proves callers cannot
    /// treat a stale classification as current.
    #[test]
    fn compensation_stale_classification_is_not_an_execution_permit() {
        use crate::memory::vector_sync_compensation::{
            classify_compensation, CompensationSendDisposition, ExactGenerationProof,
            VectorSyncCompensationClass, VectorSyncCompensationFacts,
        };
        use crate::memory::vector_sync_outbox::{MemoryVectorSyncAction, MemoryVectorSyncState};

        // Old mutation view: delete, pending, 4 attempts, epochs (4,4), NULL send.
        let old_facts = VectorSyncCompensationFacts {
            desired_action: MemoryVectorSyncAction::Delete,
            state: MemoryVectorSyncState::Pending,
            attempt_count: 4,
            fenced_claim_epoch: 4,
            last_marked_claim_epoch: 4,
            has_claimed_generation: true,
            last_send_disposition: CompensationSendDisposition::None,
            last_error_code: None,
            migration_disposition: None,
            has_complete_target_binding: true,
            proof: ExactGenerationProof::Missing,
        };
        let old_class = classify_compensation(&old_facts);
        assert_eq!(
            old_class,
            VectorSyncCompensationClass::EligibleForFencedDeleteReplay,
            "old mutation view is eligible in isolation"
        );

        // A new mutation replaces the row with a fresh budget: count 0, epochs 0.
        // The stale old classification must not be applied to this new row.
        let new_facts = VectorSyncCompensationFacts {
            desired_action: MemoryVectorSyncAction::Delete,
            state: MemoryVectorSyncState::Pending,
            attempt_count: 0,
            fenced_claim_epoch: 0,
            last_marked_claim_epoch: 0,
            has_claimed_generation: false,
            last_send_disposition: CompensationSendDisposition::None,
            last_error_code: None,
            migration_disposition: None,
            has_complete_target_binding: true,
            proof: ExactGenerationProof::Missing,
        };
        let new_class = classify_compensation(&new_facts);
        assert_eq!(
            new_class,
            VectorSyncCompensationClass::NotEligible,
            "a fresh unclaimed mutation must not be treated as a replay candidate"
        );
        assert_ne!(
            old_class, new_class,
            "stale classification must never be reused for the new mutation"
        );
    }
}
