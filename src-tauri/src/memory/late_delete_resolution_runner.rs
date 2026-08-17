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
    use futures::task::noop_waker;
    use std::{
        collections::VecDeque,
        future::Future,
        pin::Pin,
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc, Mutex,
        },
        task::{Context, Poll},
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

    /// Shared gate that delivers a pending replacement store for a
    /// suspended generation resolution (crash / supersede cut points).
    type PendingStoreDelivery =
        Arc<Mutex<mpsc::Receiver<Result<Arc<dyn VectorStore>, VectorStoreError>>>>;

    struct GateFuture<T> {
        rx: Arc<Mutex<mpsc::Receiver<T>>>,
    }

    impl<T> Future for GateFuture<T> {
        type Output = T;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.rx.lock().unwrap().try_recv() {
                Ok(value) => Poll::Ready(value),
                Err(mpsc::TryRecvError::Empty) => Poll::Pending,
                Err(mpsc::TryRecvError::Disconnected) => panic!("gate sender disconnected"),
            }
        }
    }

    struct CrashAProvider {
        query_store: Arc<dyn VectorStore>,
        entered_tx: mpsc::Sender<()>,
        delete_store_rx: PendingStoreDelivery,
        resolves: AtomicUsize,
    }

    impl ExistingGenerationVectorStoreProvider for CrashAProvider {
        fn existing_for_generation<'a>(
            &'a self,
            _generation: &'a VectorGenerationId,
        ) -> VectorStoreFuture<'a, Result<Arc<dyn VectorStore>, VectorStoreError>> {
            let ordinal = self.resolves.fetch_add(1, Ordering::SeqCst);
            if ordinal == 0 {
                let store = Arc::clone(&self.query_store);
                Box::pin(async move { Ok(store) })
            } else {
                let _ = self.entered_tx.send(());
                let rx = Arc::clone(&self.delete_store_rx);
                Box::pin(GateFuture { rx })
            }
        }
    }

    #[derive(Clone)]
    struct CrashBStore {
        query: Result<Option<VectorMetadataSample>, VectorStoreError>,
        entered_tx: mpsc::Sender<()>,
        finish_rx: Arc<
            Mutex<mpsc::Receiver<Result<ConditionalGenerationDeleteOutcome, VectorStoreError>>>,
        >,
        query_count: Arc<AtomicUsize>,
        delete_count: Arc<AtomicUsize>,
    }

    impl CrashBStore {
        fn new(
            query: Result<Option<VectorMetadataSample>, VectorStoreError>,
            entered_tx: mpsc::Sender<()>,
            finish_rx: mpsc::Receiver<Result<ConditionalGenerationDeleteOutcome, VectorStoreError>>,
        ) -> Self {
            Self {
                query,
                entered_tx,
                finish_rx: Arc::new(Mutex::new(finish_rx)),
                query_count: Arc::new(AtomicUsize::new(0)),
                delete_count: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl VectorStore for CrashBStore {
        fn upsert<'a>(
            &'a self,
            _record: VectorRecord,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn upsert_batch<'a>(
            &'a self,
            _records: Vec<VectorRecord>,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn search<'a>(
            &'a self,
            _query: VectorSearchQuery,
        ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn delete<'a>(
            &'a self,
            _life_id: &'a str,
            _memory_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn delete_from_space<'a>(
            &'a self,
            _life_id: &'a str,
            _memory_id: &'a str,
            _space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn delete_by_life<'a>(
            &'a self,
            _life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn clear_space<'a>(
            &'a self,
            _life_id: &'a str,
            _space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn count<'a>(
            &'a self,
            _life_id: &'a str,
            _space: Option<&'a VectorSpace>,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn health_check<'a>(
            &'a self,
            _life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
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
            let _ = self.entered_tx.send(());
            let rx = Arc::clone(&self.finish_rx);
            Box::pin(GateFuture { rx })
        }
    }

    #[derive(Clone)]
    struct CrashCStore {
        query: Result<Option<VectorMetadataSample>, VectorStoreError>,
        side_effect_count: Arc<AtomicUsize>,
        side_effect_done_tx: mpsc::Sender<()>,
        finish_rx: Arc<
            Mutex<mpsc::Receiver<Result<ConditionalGenerationDeleteOutcome, VectorStoreError>>>,
        >,
        query_count: Arc<AtomicUsize>,
    }

    impl CrashCStore {
        fn new(
            query: Result<Option<VectorMetadataSample>, VectorStoreError>,
            side_effect_done_tx: mpsc::Sender<()>,
            finish_rx: mpsc::Receiver<Result<ConditionalGenerationDeleteOutcome, VectorStoreError>>,
        ) -> Self {
            Self {
                query,
                side_effect_count: Arc::new(AtomicUsize::new(0)),
                side_effect_done_tx,
                finish_rx: Arc::new(Mutex::new(finish_rx)),
                query_count: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl VectorStore for CrashCStore {
        fn upsert<'a>(
            &'a self,
            _record: VectorRecord,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn upsert_batch<'a>(
            &'a self,
            _records: Vec<VectorRecord>,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn search<'a>(
            &'a self,
            _query: VectorSearchQuery,
        ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn delete<'a>(
            &'a self,
            _life_id: &'a str,
            _memory_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn delete_from_space<'a>(
            &'a self,
            _life_id: &'a str,
            _memory_id: &'a str,
            _space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn delete_by_life<'a>(
            &'a self,
            _life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn clear_space<'a>(
            &'a self,
            _life_id: &'a str,
            _space: &'a VectorSpace,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn count<'a>(
            &'a self,
            _life_id: &'a str,
            _space: Option<&'a VectorSpace>,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
        }
        fn health_check<'a>(
            &'a self,
            _life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            Box::pin(async { ScriptedStore::unsupported() })
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
            self.side_effect_count.fetch_add(1, Ordering::SeqCst);
            let _ = self.side_effect_done_tx.send(());
            let rx = Arc::clone(&self.finish_rx);
            Box::pin(GateFuture { rx })
        }
    }

    struct SuspendingProvider {
        entered_tx: mpsc::Sender<()>,
        resume_rx: PendingStoreDelivery,
        resolves: AtomicUsize,
    }

    impl ExistingGenerationVectorStoreProvider for SuspendingProvider {
        fn existing_for_generation<'a>(
            &'a self,
            _generation: &'a VectorGenerationId,
        ) -> VectorStoreFuture<'a, Result<Arc<dyn VectorStore>, VectorStoreError>> {
            self.resolves.fetch_add(1, Ordering::SeqCst);
            let _ = self.entered_tx.send(());
            let rx = Arc::clone(&self.resume_rx);
            Box::pin(GateFuture { rx })
        }
    }

    struct GatedDeleteStore {
        inner: Arc<InMemoryVectorStore>,
        entered_tx: mpsc::Sender<()>,
        resume_rx: Arc<Mutex<mpsc::Receiver<()>>>,
    }

    impl VectorStore for GatedDeleteStore {
        fn upsert<'a>(
            &'a self,
            record: VectorRecord,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.inner.upsert(record)
        }
        fn upsert_batch<'a>(
            &'a self,
            records: Vec<VectorRecord>,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.inner.upsert_batch(records)
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
        fn get_generation_metadata<'a>(
            &'a self,
            context: &'a VectorGenerationContext,
            life_id: &'a str,
            memory_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<Option<VectorMetadataSample>, VectorStoreError>> {
            self.inner
                .get_generation_metadata(context, life_id, memory_id)
        }
        fn delete_generation_memory_if_matches<'a>(
            &'a self,
            context: &'a VectorGenerationContext,
            life_id: &'a str,
            memory_id: &'a str,
            revision: i64,
            hash: &'a str,
        ) -> VectorStoreFuture<'a, Result<ConditionalGenerationDeleteOutcome, VectorStoreError>>
        {
            let _ = self.entered_tx.send(());
            let rx = Arc::clone(&self.resume_rx);
            let inner = Arc::clone(&self.inner);
            let life_id = life_id.to_string();
            let memory_id = memory_id.to_string();
            let hash = hash.to_string();
            let context = context.clone();
            Box::pin(async move {
                GateFuture { rx }.await;
                inner
                    .delete_generation_memory_if_matches(
                        &context, &life_id, &memory_id, revision, &hash,
                    )
                    .await
            })
        }
    }

    #[test]
    fn late_delete_resolution_runner_crash_a_before_delete_keeps_d_zero_and_recovers() {
        let (_root, storage) = storage();
        let memory_id = seed_resolution(&storage);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (_dummy_tx, delete_store_rx) = mpsc::channel();
        let scripted = Arc::new(ScriptedStore::new(
            Ok(Some(sample(&memory_id))),
            Ok(ConditionalGenerationDeleteOutcome::Deleted),
        ));
        let provider = CrashAProvider {
            query_store: Arc::clone(&scripted) as Arc<dyn VectorStore>,
            entered_tx,
            delete_store_rx: Arc::new(Mutex::new(delete_store_rx)),
            resolves: AtomicUsize::new(0),
        };

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut runner_future = Box::pin(run_one_late_delete(&storage, &provider, "runner-a"));
        assert!(matches!(
            runner_future.as_mut().poll(&mut cx),
            Poll::Pending
        ));
        entered_rx.recv().unwrap();

        assert_eq!(scripted.query_count.load(Ordering::SeqCst), 1);
        assert_eq!(scripted.delete_count.load(Ordering::SeqCst), 0);
        assert_eq!(provider.resolves.load(Ordering::SeqCst), 2);
        assert_eq!(
            resolution_state(&storage),
            ("processing".into(), Some("delete_started".into()))
        );

        drop(runner_future);

        LateDeleteTestHarness::new(&storage)
            .expire_leases_for_recovery()
            .unwrap();

        let ordinal2_store = Arc::new(ScriptedStore::new(
            Ok(Some(sample(&memory_id))),
            Ok(ConditionalGenerationDeleteOutcome::Deleted),
        ));
        let ordinal2_provider = ScriptedProvider::new([
            Ok(Arc::clone(&ordinal2_store) as Arc<dyn VectorStore>),
            Ok(Arc::clone(&ordinal2_store) as Arc<dyn VectorStore>),
        ]);

        let end = tauri::async_runtime::block_on(run_one_late_delete(
            &storage,
            &ordinal2_provider,
            "runner-b",
        ))
        .unwrap();

        assert_eq!(end, LateDeleteRunEnd::Processed { recovered: 1 });
        assert_eq!(ordinal2_store.query_count.load(Ordering::SeqCst), 1);
        assert_eq!(ordinal2_store.delete_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            resolution_state(&storage),
            ("resolved_deleted".into(), Some("delete_deleted".into()))
        );
    }

    #[test]
    fn late_delete_resolution_runner_crash_b_after_delete_entered_never_replays() {
        let (_root, storage) = storage();
        let memory_id = seed_resolution(&storage);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (_dummy_tx, finish_rx) = mpsc::channel();
        let crash_store = Arc::new(CrashBStore::new(
            Ok(Some(sample(&memory_id))),
            entered_tx,
            finish_rx,
        ));
        let provider = ScriptedProvider::new([
            Ok(Arc::clone(&crash_store) as Arc<dyn VectorStore>),
            Ok(Arc::clone(&crash_store) as Arc<dyn VectorStore>),
        ]);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut runner_future = Box::pin(run_one_late_delete(&storage, &provider, "runner-a"));
        assert!(matches!(
            runner_future.as_mut().poll(&mut cx),
            Poll::Pending
        ));
        entered_rx.recv().unwrap();

        assert_eq!(crash_store.query_count.load(Ordering::SeqCst), 1);
        assert_eq!(crash_store.delete_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            resolution_state(&storage),
            ("processing".into(), Some("delete_started".into()))
        );

        drop(runner_future);

        assert_eq!(crash_store.delete_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn late_delete_resolution_runner_crash_c_after_side_effect_does_not_redelete() {
        let (_root, storage) = storage();
        let memory_id = seed_resolution(&storage);
        let (side_effect_done_tx, side_effect_done_rx) = mpsc::channel();
        let (_dummy_tx, finish_rx) = mpsc::channel();
        let crash_store = Arc::new(CrashCStore::new(
            Ok(Some(sample(&memory_id))),
            side_effect_done_tx,
            finish_rx,
        ));
        let provider = ScriptedProvider::new([
            Ok(Arc::clone(&crash_store) as Arc<dyn VectorStore>),
            Ok(Arc::clone(&crash_store) as Arc<dyn VectorStore>),
        ]);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut runner_future = Box::pin(run_one_late_delete(&storage, &provider, "runner-a"));
        assert!(matches!(
            runner_future.as_mut().poll(&mut cx),
            Poll::Pending
        ));
        side_effect_done_rx.recv().unwrap();

        assert_eq!(crash_store.side_effect_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            resolution_state(&storage),
            ("processing".into(), Some("delete_started".into()))
        );

        drop(runner_future);

        LateDeleteTestHarness::new(&storage)
            .expire_leases_for_recovery()
            .unwrap();

        let ordinal2_store = Arc::new(ScriptedStore::new(
            Ok(None),
            Ok(ConditionalGenerationDeleteOutcome::Deleted),
        ));
        let ordinal2_provider =
            ScriptedProvider::new([Ok(Arc::clone(&ordinal2_store) as Arc<dyn VectorStore>)]);

        let end = tauri::async_runtime::block_on(run_one_late_delete(
            &storage,
            &ordinal2_provider,
            "runner-b",
        ))
        .unwrap();

        assert_eq!(end, LateDeleteRunEnd::Processed { recovered: 1 });
        assert_eq!(ordinal2_store.query_count.load(Ordering::SeqCst), 1);
        assert_eq!(ordinal2_store.delete_count.load(Ordering::SeqCst), 0);
        assert_eq!(crash_store.side_effect_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            resolution_state(&storage),
            ("resolved_absent".into(), Some("query_absent".into()))
        );
    }

    #[test]
    fn late_delete_resolution_runner_resolution_budget_exhaustion_waits_for_rebuild() {
        let (_root, storage) = storage();
        let _memory_id = seed_resolution(&storage);

        for _ordinal in 1..=3 {
            let provider =
                ScriptedProvider::new([Err(runner_error(VectorStoreErrorCode::StoreUnavailable))]);
            let end = tauri::async_runtime::block_on(run_one_late_delete(
                &storage, &provider, "runner-a",
            ))
            .unwrap();
            assert!(matches!(end, LateDeleteRunEnd::Processed { .. }));
            assert_eq!(
                resolution_state(&storage),
                ("unknown".into(), Some("query_unknown".into()))
            );
        }

        let scripted = Arc::new(ScriptedStore::new(
            Ok(None),
            Ok(ConditionalGenerationDeleteOutcome::Deleted),
        ));
        let provider = ScriptedProvider::new([Ok(scripted.clone() as Arc<dyn VectorStore>)]);
        let end =
            tauri::async_runtime::block_on(run_one_late_delete(&storage, &provider, "runner-b"))
                .unwrap();

        assert_eq!(end, LateDeleteRunEnd::NoWork { recovered: 0 });
        assert_eq!(scripted.query_count.load(Ordering::SeqCst), 0);
        assert_eq!(scripted.delete_count.load(Ordering::SeqCst), 0);
        assert_eq!(
            resolution_state(&storage),
            ("waiting_rebuild".into(), Some("waiting_rebuild".into()))
        );
    }

    #[test]
    fn late_delete_resolution_runner_superseded_before_query_io_keeps_qd_zero() {
        let (_root, storage) = storage();
        let memory_id = seed_resolution(&storage);

        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let scripted = Arc::new(ScriptedStore::new(
            Ok(Some(sample(&memory_id))),
            Ok(ConditionalGenerationDeleteOutcome::Deleted),
        ));
        let store: Arc<dyn VectorStore> = scripted.clone();
        let provider = SuspendingProvider {
            entered_tx,
            resume_rx: Arc::new(Mutex::new(resume_rx)),
            resolves: AtomicUsize::new(0),
        };

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut runner_future = Box::pin(run_one_late_delete(&storage, &provider, "runner-a"));
        assert!(matches!(
            runner_future.as_mut().poll(&mut cx),
            Poll::Pending
        ));
        entered_rx.recv().unwrap();

        <StorageService as MemoryVectorSyncOutboxRepository>::enqueue(
            &storage,
            EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: memory_id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            },
        )
        .unwrap();

        resume_tx.send(Ok(store)).unwrap();
        assert!(matches!(
            runner_future.as_mut().poll(&mut cx),
            Poll::Ready(Ok(_))
        ));

        assert_eq!(scripted.query_count.load(Ordering::SeqCst), 0);
        assert_eq!(scripted.delete_count.load(Ordering::SeqCst), 0);
        assert_eq!(provider.resolves.load(Ordering::SeqCst), 1);
        assert_eq!(
            resolution_state(&storage),
            ("superseded".into(), Some("superseded".into()))
        );
    }

    #[test]
    fn late_delete_resolution_runner_same_generation_newer_vector_survives() {
        let (_root, storage) = storage();
        let memory_id = seed_resolution(&storage);
        let vector_context = context();
        let in_memory = Arc::new(InMemoryVectorStore::default());

        tauri::async_runtime::block_on(in_memory.create_generation(&vector_context)).unwrap();
        tauri::async_runtime::block_on(
            in_memory.upsert_generation(
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
            ),
        )
        .unwrap();

        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();

        let gated_store = Arc::new(GatedDeleteStore {
            inner: Arc::clone(&in_memory),
            entered_tx,
            resume_rx: Arc::new(Mutex::new(resume_rx)),
        });

        let provider = ScriptedProvider::new([
            Ok(Arc::clone(&gated_store) as Arc<dyn VectorStore>),
            Ok(Arc::clone(&gated_store) as Arc<dyn VectorStore>),
        ]);

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut runner_future = Box::pin(run_one_late_delete(&storage, &provider, "runner-a"));
        assert!(matches!(
            runner_future.as_mut().poll(&mut cx),
            Poll::Pending
        ));
        entered_rx.recv().unwrap();

        tauri::async_runtime::block_on(
            in_memory.upsert_generation(
                &vector_context,
                GenerationVectorRecord::try_new(
                    VectorGenerationId::parse("generation-a").unwrap(),
                    "life",
                    &memory_id,
                    8,
                    "hash-8",
                    "descriptor-a",
                    vec![0.0, 1.0],
                )
                .unwrap(),
            ),
        )
        .unwrap();

        resume_tx.send(()).unwrap();
        assert!(matches!(
            runner_future.as_mut().poll(&mut cx),
            Poll::Ready(Ok(_))
        ));

        assert_eq!(
            resolution_state(&storage),
            ("waiting_rebuild".into(), Some("identity_mismatch".into()))
        );

        let surviving_sample = tauri::async_runtime::block_on(in_memory.get_generation_metadata(
            &vector_context,
            "life",
            &memory_id,
        ))
        .unwrap()
        .unwrap();

        assert_eq!(surviving_sample.memory_revision, 8);
        assert_eq!(surviving_sample.content_hash, "hash-8");
    }
}
