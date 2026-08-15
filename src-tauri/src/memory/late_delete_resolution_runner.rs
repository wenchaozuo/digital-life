//! One-shot orchestration for durable late Delete resolution.
//!
//! Storage retains every authority-bearing capability. This module only owns
//! application composition, one bounded pass, and the runtime-lease lifetime.

use tauri::{AppHandle, Manager};

use crate::{
    storage::{
        LateDeleteDeleteHandoffOutcome, LateDeleteDeletePermitRunnerIssuance,
        LateDeleteQueryHandoffOutcome, LateDeleteQueryReservation, LateDeleteResolutionClaimResult,
        StorageError, StorageService,
    },
    vector_store::{
        ExistingGenerationVectorStoreProvider, LanceDbVectorStoreRegistry, VectorStoreError,
    },
};

/// The deliberately small result of one bounded runner invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LateDeleteRunEnd {
    LeaseBusy,
    NoWork { recovered: usize },
    Processed { recovered: usize },
}

/// The runner preserves storage and provider failures without adding a second
/// error domain or any durable diagnostic state.
#[derive(Debug)]
pub(crate) enum LateDeleteRunnerError {
    Storage(StorageError),
    Provider(VectorStoreError),
}

impl From<StorageError> for LateDeleteRunnerError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<VectorStoreError> for LateDeleteRunnerError {
    fn from(error: VectorStoreError) -> Self {
        Self::Provider(error)
    }
}

/// Production composition. The registry and canonical root stay here; the
/// core receives only the sealed-provider dependency it needs.
pub(crate) async fn run_one_late_delete_from_app(
    app: &AppHandle,
    owner: &str,
) -> Result<LateDeleteRunEnd, LateDeleteRunnerError> {
    let storage = app.state::<StorageService>();
    let registry = app.state::<LanceDbVectorStoreRegistry>();
    let data_root = storage.active_data_root()?;
    let provider = registry.bind_existing_generation_provider(&data_root)?;
    run_one_late_delete(storage.inner(), &provider, owner).await
}

/// Runs exactly one late-Delete resolution after acquiring at most one lease.
pub(crate) async fn run_one_late_delete(
    storage: &StorageService,
    provider: &dyn ExistingGenerationVectorStoreProvider,
    owner: &str,
) -> Result<LateDeleteRunEnd, LateDeleteRunnerError> {
    let Some(lease) = storage.acquire_late_delete_runtime_lease(owner)? else {
        return Ok(LateDeleteRunEnd::LeaseBusy);
    };

    let body = run_one_while_leased(storage, provider, &lease).await;
    let release = storage.release_late_delete_runtime_lease(&lease);
    match (body, release) {
        (Ok(end), Ok(_)) => Ok(end),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Err(error), Err(_)) => Err(error),
    }
}

async fn run_one_while_leased(
    storage: &StorageService,
    provider: &dyn ExistingGenerationVectorStoreProvider,
    lease: &crate::storage::LateDeleteRuntimeLease,
) -> Result<LateDeleteRunEnd, LateDeleteRunnerError> {
    let recovered = storage.recover_expired_late_delete_resolutions()?;
    let claim = match storage.claim_one_late_delete_resolution(lease)? {
        LateDeleteResolutionClaimResult::Claimed(claim) => claim,
        LateDeleteResolutionClaimResult::NoEligibleResolution => {
            return Ok(LateDeleteRunEnd::NoWork { recovered });
        }
    };
    let query_permit = match storage.reserve_late_delete_resolution_for_query(&claim)? {
        LateDeleteQueryReservation::Reserved(permit) => permit,
        LateDeleteQueryReservation::AlreadyReserved { .. }
        | LateDeleteQueryReservation::LostLeaseOrSuperseded
        | LateDeleteQueryReservation::ResolutionLimitReached => {
            return Ok(LateDeleteRunEnd::Processed { recovered });
        }
    };

    match query_permit
        .execute_exact_query_once_with_provider(storage, provider)
        .await?
    {
        LateDeleteQueryHandoffOutcome::LostLeaseOrSuperseded => {
            Ok(LateDeleteRunEnd::Processed { recovered })
        }
        LateDeleteQueryHandoffOutcome::Absent(capability) => {
            storage.finalize_late_delete_query_absent(capability)?;
            Ok(LateDeleteRunEnd::Processed { recovered })
        }
        LateDeleteQueryHandoffOutcome::Failure(capability) => {
            storage.finalize_late_delete_query_failure(capability)?;
            Ok(LateDeleteRunEnd::Processed { recovered })
        }
        LateDeleteQueryHandoffOutcome::Corrupt(capability) => {
            storage.finalize_late_delete_query_corrupt(capability)?;
            Ok(LateDeleteRunEnd::Processed { recovered })
        }
        LateDeleteQueryHandoffOutcome::Present(capability) => {
            run_one_after_query_present(storage, provider, capability, recovered).await
        }
    }
}

async fn run_one_after_query_present(
    storage: &StorageService,
    provider: &dyn ExistingGenerationVectorStoreProvider,
    capability: crate::storage::PresentPostQueryCapability,
    recovered: usize,
) -> Result<LateDeleteRunEnd, LateDeleteRunnerError> {
    let delete_permit = match storage.issue_late_delete_permit_for_runner(capability)? {
        LateDeleteDeletePermitRunnerIssuance::Issued(permit) => permit,
        LateDeleteDeletePermitRunnerIssuance::LostLeaseOrSuperseded
        | LateDeleteDeletePermitRunnerIssuance::WaitingRebuild
        | LateDeleteDeletePermitRunnerIssuance::CommitUnknownRecoveryRequired(_) => {
            return Ok(LateDeleteRunEnd::Processed { recovered });
        }
    };

    match delete_permit
        .execute_conditional_delete_once_with_provider(storage, provider)
        .await?
    {
        LateDeleteDeleteHandoffOutcome::LostLeaseOrSuperseded => {
            Ok(LateDeleteRunEnd::Processed { recovered })
        }
        LateDeleteDeleteHandoffOutcome::PreDeleteCorrupt(capability) => {
            storage.finalize_pre_delete_corrupt(capability)?;
            Ok(LateDeleteRunEnd::Processed { recovered })
        }
        LateDeleteDeleteHandoffOutcome::Deleted(capability) => {
            storage.finalize_deleted_post_delete(capability)?;
            Ok(LateDeleteRunEnd::Processed { recovered })
        }
        LateDeleteDeleteHandoffOutcome::Absent(capability) => {
            storage.finalize_absent_post_delete(capability)?;
            Ok(LateDeleteRunEnd::Processed { recovered })
        }
        LateDeleteDeleteHandoffOutcome::IdentityMismatch(capability) => {
            storage.finalize_identity_mismatch_post_delete(capability)?;
            Ok(LateDeleteRunEnd::Processed { recovered })
        }
        LateDeleteDeleteHandoffOutcome::Failure(capability) => {
            storage.finalize_failed_post_delete(capability)?;
            Ok(LateDeleteRunEnd::Processed { recovered })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        memory::vector_sync_outbox::{
            EnqueueMemoryVectorSyncRequest, MemoryVectorSyncAction,
            MemoryVectorSyncOutboxRepository,
        },
        storage::{
            test_support::{insert_confirmed_memory_fixture, LateDeleteTestHarness},
            FencedAttemptReservation, FencedDeleteWitnessResult, LifeIdentityRecord,
            PersonaTemplateRecord,
        },
        vector_store::{
            ConditionalGenerationDeleteOutcome, ExistingGenerationVectorStoreProvider,
            GenerationVectorRecord, InMemoryVectorStore, VectorGenerationContext,
            VectorGenerationId, VectorMetadataSample, VectorRecord, VectorSearchHit,
            VectorSearchQuery, VectorSpace, VectorStore, VectorStoreErrorCode, VectorStoreFuture,
        },
    };
    use std::{
        collections::VecDeque,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
    };

    fn storage() -> (tempfile::TempDir, StorageService) {
        let root = tempfile::tempdir().unwrap();
        let storage =
            StorageService::initialize_with_roots(root.path().join("data"), None).unwrap();
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
        (root, storage)
    }

    fn seed_resolution(storage: &StorageService) -> String {
        let memory = insert_confirmed_memory_fixture(
            storage,
            "life",
            "fact",
            "late delete runner fixture",
            None,
            0.5,
            0.5,
            false,
            false,
        );
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: memory.life_id.clone(),
                memory_id: memory.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "fixture")
            .unwrap()
            .unwrap();
        let token = match storage.reserve_fenced_attempt(&claim).unwrap() {
            FencedAttemptReservation::Reserved(token) => token,
            _ => panic!("fixture must reserve one Delete attempt"),
        };
        assert_eq!(
            storage.mark_fenced_delete_send_witness(&token).unwrap(),
            FencedDeleteWitnessResult::Marked
        );
        memory.id
    }

    fn resolution_state(storage: &StorageService) -> (String, Option<String>) {
        let database = crate::storage::open_authorized_test_connection(
            &storage.test_database_main_path().unwrap(),
        )
        .unwrap();
        database
            .query_row(
                "SELECT state,last_resolution_disposition
                 FROM memory_vector_late_delete_resolution",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    fn context() -> VectorGenerationContext {
        VectorGenerationContext::new(
            VectorGenerationId::parse("generation-a").unwrap(),
            "descriptor-a",
            2,
        )
        .unwrap()
    }

    fn sample(memory_id: &str) -> VectorMetadataSample {
        VectorMetadataSample {
            generation_id: "generation-a".into(),
            life_id: "life".into(),
            memory_id: memory_id.into(),
            memory_revision: 7,
            content_hash: "hash-7".into(),
            descriptor_hash: "descriptor-a".into(),
            dimension: 2,
        }
    }

    #[derive(Clone)]
    struct ScriptedStore {
        query: Result<Option<VectorMetadataSample>, VectorStoreError>,
        delete: Result<ConditionalGenerationDeleteOutcome, VectorStoreError>,
        query_count: Arc<AtomicUsize>,
        delete_count: Arc<AtomicUsize>,
    }

    impl ScriptedStore {
        fn new(
            query: Result<Option<VectorMetadataSample>, VectorStoreError>,
            delete: Result<ConditionalGenerationDeleteOutcome, VectorStoreError>,
        ) -> Self {
            Self {
                query,
                delete,
                query_count: Arc::new(AtomicUsize::new(0)),
                delete_count: Arc::new(AtomicUsize::new(0)),
            }
        }

        fn unsupported<T>() -> Result<T, VectorStoreError> {
            Err(VectorStoreError::new(
                VectorStoreErrorCode::StoreUnavailable,
                "scripted runner store does not implement legacy operations",
                false,
            ))
        }
    }

    impl VectorStore for ScriptedStore {
        fn upsert<'a>(
            &'a self,
            _record: VectorRecord,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }
        fn upsert_batch<'a>(
            &'a self,
            _records: Vec<VectorRecord>,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }
        fn search<'a>(
            &'a self,
            _query: VectorSearchQuery,
        ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }
        fn delete<'a>(
            &'a self,
            _life_id: &'a str,
            _memory_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }
        fn delete_from_space<'a>(
            &'a self,
            _life_id: &'a str,
            _memory_id: &'a str,
            _space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }
        fn delete_by_life<'a>(
            &'a self,
            _life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }
        fn clear_space<'a>(
            &'a self,
            _life_id: &'a str,
            _space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }
        fn count<'a>(
            &'a self,
            _life_id: &'a str,
            _space: Option<&'a VectorSpace>,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }
        fn health_check<'a>(
            &'a self,
            _life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async { Self::unsupported() })
        }
        fn get_generation_metadata<'a>(
            &'a self,
            _context: &'a VectorGenerationContext,
            _life_id: &'a str,
            _memory_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<Option<VectorMetadataSample>, VectorStoreError>> {
            self.query_count.fetch_add(1, Ordering::SeqCst);
            let result = self.query.clone();
            Box::pin(async move { result })
        }
        fn delete_generation_memory_if_matches<'a>(
            &'a self,
            _context: &'a VectorGenerationContext,
            _life_id: &'a str,
            _memory_id: &'a str,
            _revision: i64,
            _hash: &'a str,
        ) -> VectorStoreFuture<'a, Result<ConditionalGenerationDeleteOutcome, VectorStoreError>>
        {
            self.delete_count.fetch_add(1, Ordering::SeqCst);
            let result = self.delete.clone();
            Box::pin(async move { result })
        }
    }

    struct ScriptedProvider {
        results: Mutex<VecDeque<Result<Arc<dyn VectorStore>, VectorStoreError>>>,
        resolves: AtomicUsize,
    }

    impl ScriptedProvider {
        fn new(
            results: impl IntoIterator<Item = Result<Arc<dyn VectorStore>, VectorStoreError>>,
        ) -> Self {
            Self {
                results: Mutex::new(results.into_iter().collect()),
                resolves: AtomicUsize::new(0),
            }
        }
    }

    impl ExistingGenerationVectorStoreProvider for ScriptedProvider {
        fn existing_for_generation<'a>(
            &'a self,
            _generation: &'a VectorGenerationId,
        ) -> VectorStoreFuture<'a, Result<Arc<dyn VectorStore>, VectorStoreError>> {
            self.resolves.fetch_add(1, Ordering::SeqCst);
            let result = self.results.lock().unwrap().pop_front().unwrap_or_else(|| {
                Err(VectorStoreError::new(
                    VectorStoreErrorCode::StoreUnavailable,
                    "provider was resolved more than once per phase",
                    false,
                ))
            });
            Box::pin(async move { result })
        }
    }

    fn runner_error(code: VectorStoreErrorCode) -> VectorStoreError {
        VectorStoreError::new(code, "scripted provider failure", true)
    }

    #[test]
    fn late_delete_resolution_runner_routes_query_endings_without_delete() {
        for (query, expected_state, expected_disposition) in [
            (Ok(None), "resolved_absent", Some("query_absent")),
            (
                Err(runner_error(VectorStoreErrorCode::StoreUnavailable)),
                "unknown",
                Some("query_unknown"),
            ),
            (
                Err(runner_error(VectorStoreErrorCode::GenerationCorrupt)),
                "waiting_rebuild",
                Some("waiting_rebuild"),
            ),
        ] {
            let (_root, storage) = storage();
            let _memory_id = seed_resolution(&storage);
            let store: Arc<dyn VectorStore> = Arc::new(ScriptedStore::new(
                query,
                Ok(ConditionalGenerationDeleteOutcome::Deleted),
            ));
            let provider = ScriptedProvider::new([Ok(store)]);
            let end = tauri::async_runtime::block_on(run_one_late_delete(
                &storage, &provider, "runner-a",
            ))
            .unwrap();
            assert!(matches!(end, LateDeleteRunEnd::Processed { .. }));
            assert_eq!(
                resolution_state(&storage),
                (
                    expected_state.into(),
                    expected_disposition.map(str::to_string)
                )
            );
            assert_eq!(provider.resolves.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn late_delete_resolution_runner_routes_provider_query_errors_without_query_io() {
        for (code, expected_state, expected_disposition) in [
            (
                VectorStoreErrorCode::GenerationNotFound,
                "waiting_rebuild",
                "waiting_rebuild",
            ),
            (
                VectorStoreErrorCode::StoreUnavailable,
                "unknown",
                "query_unknown",
            ),
            (
                VectorStoreErrorCode::GenerationCorrupt,
                "waiting_rebuild",
                "waiting_rebuild",
            ),
        ] {
            let (_root, storage) = storage();
            let _memory_id = seed_resolution(&storage);
            let provider = ScriptedProvider::new([Err(runner_error(code))]);
            tauri::async_runtime::block_on(run_one_late_delete(&storage, &provider, "runner-a"))
                .unwrap();
            assert_eq!(
                resolution_state(&storage),
                (expected_state.into(), Some(expected_disposition.into()))
            );
            assert_eq!(provider.resolves.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn late_delete_resolution_runner_routes_delete_endings_once() {
        for (delete, expected_state, expected_disposition) in [
            (
                Ok(ConditionalGenerationDeleteOutcome::Deleted),
                "resolved_deleted",
                "delete_deleted",
            ),
            (
                Ok(ConditionalGenerationDeleteOutcome::Absent),
                "resolved_deleted",
                "delete_absent",
            ),
            (
                Ok(ConditionalGenerationDeleteOutcome::IdentityMismatch),
                "waiting_rebuild",
                "identity_mismatch",
            ),
            (
                Err(runner_error(VectorStoreErrorCode::VectorDeleteFailed)),
                "unknown",
                "delete_unknown",
            ),
        ] {
            let (_root, storage) = storage();
            let memory_id = seed_resolution(&storage);
            let scripted = Arc::new(ScriptedStore::new(Ok(Some(sample(&memory_id))), delete));
            let store: Arc<dyn VectorStore> = scripted.clone();
            let provider = ScriptedProvider::new([Ok(Arc::clone(&store)), Ok(store)]);
            tauri::async_runtime::block_on(run_one_late_delete(&storage, &provider, "runner-a"))
                .unwrap();
            assert_eq!(
                resolution_state(&storage),
                (expected_state.into(), Some(expected_disposition.into()))
            );
            assert_eq!(scripted.query_count.load(Ordering::SeqCst), 1);
            assert_eq!(scripted.delete_count.load(Ordering::SeqCst), 1);
            assert_eq!(provider.resolves.load(Ordering::SeqCst), 2);
        }
    }

    #[test]
    fn late_delete_resolution_runner_harness_commit_unknowns_never_replay_external_io() {
        for arm in [0_u8, 1, 2, 3, 4] {
            let (_root, storage) = storage();
            let memory_id = seed_resolution(&storage);
            let scripted = Arc::new(ScriptedStore::new(
                Ok(Some(sample(&memory_id))),
                Ok(ConditionalGenerationDeleteOutcome::Deleted),
            ));
            let store: Arc<dyn VectorStore> = scripted.clone();
            let provider = ScriptedProvider::new([Ok(Arc::clone(&store)), Ok(store)]);
            let mut harness = LateDeleteTestHarness::new(&storage);
            match arm {
                0 => harness.arm_reserve_after_commit_unknown().unwrap(),
                1 => harness.arm_delete_started_before_commit_unknown().unwrap(),
                2 => harness.arm_delete_started_after_commit_unknown().unwrap(),
                3 => harness.arm_post_delete_before_commit_unknown().unwrap(),
                4 => harness.arm_post_delete_after_commit_unknown().unwrap(),
                _ => unreachable!(),
            }
            let result = tauri::async_runtime::block_on(run_one_late_delete(
                &storage, &provider, "runner-a",
            ));
            if arm == 0 {
                assert!(matches!(
                    result,
                    Err(LateDeleteRunnerError::Storage(StorageError { ref code, .. }))
                        if code == "LATE_DELETE_QUERY_RESERVATION_COMMIT_RESULT_UNKNOWN"
                ));
            } else {
                result.unwrap();
            }
            assert!(scripted.query_count.load(Ordering::SeqCst) <= 1);
            assert!(scripted.delete_count.load(Ordering::SeqCst) <= 1);
            assert!(provider.resolves.load(Ordering::SeqCst) <= 2);
            assert!(storage
                .acquire_late_delete_runtime_lease("runner-b")
                .unwrap()
                .is_some());
        }
    }

    #[test]
    fn late_delete_resolution_runner_no_work_and_provider_predelete_corrupt_release_lease() {
        let (_root, storage) = storage();
        let provider = ScriptedProvider::new([]);
        assert_eq!(
            tauri::async_runtime::block_on(run_one_late_delete(&storage, &provider, "runner-a"))
                .unwrap(),
            LateDeleteRunEnd::NoWork { recovered: 0 }
        );
        let verification_lease = storage
            .acquire_late_delete_runtime_lease("runner-b")
            .unwrap()
            .unwrap();
        storage
            .release_late_delete_runtime_lease(&verification_lease)
            .unwrap();

        let memory_id = seed_resolution(&storage);
        let scripted: Arc<dyn VectorStore> = Arc::new(ScriptedStore::new(
            Ok(Some(sample(&memory_id))),
            Ok(ConditionalGenerationDeleteOutcome::Deleted),
        ));
        let provider = ScriptedProvider::new([
            Ok(scripted),
            Err(runner_error(VectorStoreErrorCode::StoreUnavailable)),
        ]);
        tauri::async_runtime::block_on(run_one_late_delete(&storage, &provider, "runner-a"))
            .unwrap();
        assert_eq!(
            resolution_state(&storage),
            ("waiting_rebuild".into(), Some("waiting_rebuild".into()))
        );
        assert!(storage
            .acquire_late_delete_runtime_lease("runner-b")
            .unwrap()
            .is_some());
    }

    #[test]
    fn late_delete_resolution_runner_real_in_memory_provider_deletes_one_record() {
        tauri::async_runtime::block_on(async {
            let (_root, storage) = storage();
            let memory_id = seed_resolution(&storage);
            let store = Arc::new(InMemoryVectorStore::default());
            let vector_context = context();
            store.create_generation(&vector_context).await.unwrap();
            store
                .upsert_generation(
                    &vector_context,
                    GenerationVectorRecord::try_new(
                        VectorGenerationId::parse("generation-a").unwrap(),
                        "life",
                        &memory_id,
                        7,
                        "hash-7",
                        "descriptor-a",
                        vec![1.0, 0.0],
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let store_for_provider: Arc<dyn VectorStore> = store.clone();
            let provider = ScriptedProvider::new([
                Ok(Arc::clone(&store_for_provider)),
                Ok(store_for_provider),
            ]);
            assert!(matches!(
                run_one_late_delete(&storage, &provider, "runner-a")
                    .await
                    .unwrap(),
                LateDeleteRunEnd::Processed { .. }
            ));
            assert!(store
                .get_generation_metadata(&vector_context, "life", &memory_id)
                .await
                .unwrap()
                .is_none());
            assert_eq!(
                resolution_state(&storage),
                ("resolved_deleted".into(), Some("delete_deleted".into()))
            );
        });
    }
}
