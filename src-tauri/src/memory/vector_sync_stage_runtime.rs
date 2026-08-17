//! Production composition entrypoints for the sealed D-9D2 vector-sync drain.
//!
//! This module owns process-global arbitration and redacted IPC mapping.  It
//! deliberately never accepts or exposes generation, provider, store, or path
//! authority: the fenced execution resolver retains those details.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use tokio::sync::{Mutex, MutexGuard};

use crate::{
    model::runtime::{ModelRuntimeCoordinator, ModelRuntimeService},
    secrets::{SecretStore, WindowsCredentialSecretStore},
    storage::StorageService,
    vector_store::LanceDbVectorStoreRegistry,
};

use super::{
    existing_generation_binding::resolve_existing_generation_fenced_execution,
    late_delete_resolution_runner::{run_one_late_delete_from_app, LateDeleteRunEnd},
    vector_sync_worker::VectorSyncDrainReport,
};

/// Process-global RAII gate for the complete fenced composition lifecycle.
///
/// The guard is acquired before authority resolution and remains held through
/// matching-store acquisition, bounded drain, and drop of the owned execution.
pub struct FencedVectorSyncCompositionGate {
    gate: Mutex<()>,
}

impl Default for FencedVectorSyncCompositionGate {
    fn default() -> Self {
        Self {
            gate: Mutex::new(()),
        }
    }
}

impl FencedVectorSyncCompositionGate {
    pub(crate) async fn acquire(&self) -> MutexGuard<'_, ()> {
        self.gate.lock().await
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartFencedVectorSyncDrainRequest {
    pub lease_owner: String,
    pub limit: usize,
}

/// Redacted count-only result of one bounded fenced drain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FencedVectorSyncDrainResult {
    pub requested_limit: usize,
    pub processed: usize,
    pub applied_upserts: usize,
    pub applied_deletes: usize,
    pub retry_scheduled: usize,
    pub blocked: usize,
    pub failed: usize,
    pub stopped_no_eligible: bool,
    pub stopped_lost_lease: bool,
}

impl From<VectorSyncDrainReport> for FencedVectorSyncDrainResult {
    fn from(report: VectorSyncDrainReport) -> Self {
        Self {
            requested_limit: report.requested_limit,
            processed: report.processed,
            applied_upserts: report.applied_upserts,
            applied_deletes: report.applied_deletes,
            retry_scheduled: report.retry_scheduled,
            blocked: report.blocked,
            failed: report.failed,
            stopped_no_eligible: report.stopped_no_eligible,
            stopped_lost_lease: report.stopped_lost_lease,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FencedVectorSyncDrainErrorCode {
    Unavailable,
    DrainFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FencedVectorSyncDrainError {
    pub code: FencedVectorSyncDrainErrorCode,
    pub message: &'static str,
    pub recoverable: bool,
}

fn fenced_error(code: FencedVectorSyncDrainErrorCode) -> FencedVectorSyncDrainError {
    let (message, recoverable) = match code {
        FencedVectorSyncDrainErrorCode::Unavailable => {
            ("The fenced vector sync execution is unavailable.", true)
        }
        FencedVectorSyncDrainErrorCode::DrainFailed => {
            ("The fenced vector sync drain could not complete.", true)
        }
    };
    FencedVectorSyncDrainError {
        code,
        message,
        recoverable,
    }
}

fn map_binding_error(
    error: super::existing_generation_binding::ExistingGenerationBindingError,
) -> FencedVectorSyncDrainError {
    use super::existing_generation_binding::ExistingGenerationBindingErrorCode;

    match error.code() {
        ExistingGenerationBindingErrorCode::InvalidGenerationMetadata
        | ExistingGenerationBindingErrorCode::GenerationBindingMismatch
        | ExistingGenerationBindingErrorCode::GenerationBindingStale => {
            fenced_error(FencedVectorSyncDrainErrorCode::Unavailable)
        }
        ExistingGenerationBindingErrorCode::NoExistingGeneration
        | ExistingGenerationBindingErrorCode::AmbiguousExistingGeneration
        | ExistingGenerationBindingErrorCode::GenerationProviderUnavailable
        | ExistingGenerationBindingErrorCode::GenerationProviderMismatch
        | ExistingGenerationBindingErrorCode::ExistingVectorStoreUnavailable => {
            fenced_error(FencedVectorSyncDrainErrorCode::Unavailable)
        }
    }
}

/// Production IPC entrypoint for exactly one bounded sealed fenced drain.
#[tauri::command]
pub fn start_fenced_vector_sync_drain(
    storage: State<'_, StorageService>,
    secrets: State<'_, WindowsCredentialSecretStore>,
    model_runtime: State<'_, ModelRuntimeCoordinator>,
    registry: State<'_, LanceDbVectorStoreRegistry>,
    gate: State<'_, FencedVectorSyncCompositionGate>,
    request: StartFencedVectorSyncDrainRequest,
) -> Result<FencedVectorSyncDrainResult, FencedVectorSyncDrainError> {
    tauri::async_runtime::block_on(run_fenced_vector_sync_drain(
        storage.inner(),
        secrets.inner(),
        model_runtime.inner(),
        registry.inner(),
        gate.inner(),
        &request.lease_owner,
        request.limit,
    ))
}

/// Canonical production composition path shared by the IPC entrypoint and
/// isolated integration tests.  Inputs are authority services only.
pub(crate) async fn run_fenced_vector_sync_drain<S>(
    storage: &StorageService,
    secrets: &S,
    model_runtime: &ModelRuntimeCoordinator,
    registry: &LanceDbVectorStoreRegistry,
    gate: &FencedVectorSyncCompositionGate,
    lease_owner: &str,
    limit: usize,
) -> Result<FencedVectorSyncDrainResult, FencedVectorSyncDrainError>
where
    S: SecretStore + ?Sized,
{
    let report = {
        let _guard = gate.acquire().await;
        let runtime = ModelRuntimeService::new(storage, secrets, model_runtime);
        let execution = resolve_existing_generation_fenced_execution(storage, &runtime, registry)
            .await
            .map_err(map_binding_error)?;
        execution
            .drain_bounded(lease_owner, limit)
            .await
            .map_err(|_| fenced_error(FencedVectorSyncDrainErrorCode::DrainFailed))?
    };

    Ok(report.into())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunLateDeleteResolutionOnceRequest {
    pub lease_owner: String,
}

/// Redacted result of exactly one Late Delete runner invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LateDeleteResolutionOnceResult {
    LeaseBusy,
    NoWork { recovered: usize },
    Processed { recovered: usize },
}

impl From<LateDeleteRunEnd> for LateDeleteResolutionOnceResult {
    fn from(end: LateDeleteRunEnd) -> Self {
        match end {
            LateDeleteRunEnd::LeaseBusy => Self::LeaseBusy,
            LateDeleteRunEnd::NoWork { recovered } => Self::NoWork { recovered },
            LateDeleteRunEnd::Processed { recovered } => Self::Processed { recovered },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LateDeleteResolutionOnceErrorCode {
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LateDeleteResolutionOnceError {
    pub code: LateDeleteResolutionOnceErrorCode,
    pub message: &'static str,
    pub recoverable: bool,
}

fn map_late_delete_error(
    error: super::late_delete_resolution_runner::LateDeleteRunnerError,
) -> LateDeleteResolutionOnceError {
    let recoverable = match error {
        super::late_delete_resolution_runner::LateDeleteRunnerError::Storage(error) => {
            error.recoverable
        }
        super::late_delete_resolution_runner::LateDeleteRunnerError::Provider(error) => {
            error.recoverable
        }
    };
    LateDeleteResolutionOnceError {
        code: LateDeleteResolutionOnceErrorCode::Unavailable,
        message: "The Late Delete resolution could not complete.",
        recoverable,
    }
}

/// Production IPC entrypoint that composes exactly one runner invocation.
#[tauri::command]
pub async fn run_late_delete_resolution_once(
    app: AppHandle,
    request: RunLateDeleteResolutionOnceRequest,
) -> Result<LateDeleteResolutionOnceResult, LateDeleteResolutionOnceError> {
    run_one_late_delete_from_app(&app, &request.lease_owner)
        .await
        .map(LateDeleteResolutionOnceResult::from)
        .map_err(map_late_delete_error)
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            mpsc, Arc,
        },
        time::Duration,
    };

    use super::*;
    use crate::{
        memory::existing_generation_binding::compute_canonical_generation_descriptor,
        model::profile::{
            CreateModelProfileRequest, ModelProfileService, ModelProviderKind, ModelPurpose,
            SetActiveModelProfileRequest,
        },
        secrets::{
            InMemorySecretStore, SecretIdentifier, SecretPurpose, SecretStatus, SecretStoreError,
            SecretValue,
        },
        vector_store::VectorGenerationId,
    };

    struct TrackingSecretStore {
        inner: InMemorySecretStore,
        reads: Arc<AtomicUsize>,
    }

    impl TrackingSecretStore {
        fn new() -> (Self, Arc<AtomicUsize>) {
            let reads = Arc::new(AtomicUsize::new(0));
            (
                Self {
                    inner: InMemorySecretStore::new(),
                    reads: Arc::clone(&reads),
                },
                reads,
            )
        }
    }

    impl SecretStore for TrackingSecretStore {
        fn set_secret(
            &self,
            identifier: &SecretIdentifier,
            value: SecretValue,
        ) -> Result<SecretStatus, SecretStoreError> {
            self.inner.set_secret(identifier, value)
        }

        fn get_secret(
            &self,
            identifier: &SecretIdentifier,
        ) -> Result<SecretValue, SecretStoreError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.get_secret(identifier)
        }

        fn has_secret(&self, identifier: &SecretIdentifier) -> Result<bool, SecretStoreError> {
            self.inner.has_secret(identifier)
        }

        fn delete_secret(
            &self,
            identifier: &SecretIdentifier,
        ) -> Result<SecretStatus, SecretStoreError> {
            self.inner.delete_secret(identifier)
        }
    }

    fn generation_snapshot(storage: &StorageService) -> (String, i64, String, i64) {
        let connection = crate::storage::open_authorized_test_connection(
            &storage.test_database_main_path().unwrap(),
        )
        .unwrap();
        connection
            .query_row(
                "SELECT descriptor_hash, dimension, state, authority_epoch
                 FROM memory_vector_generation WHERE generation_id = 'group1-dry-run'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap()
    }

    #[test]
    fn d9d2_group1_global_gate_serializes_two_fenced_execution_regions() {
        let gate = Arc::new(FencedVectorSyncCompositionGate::default());
        let (first_entered_tx, first_entered_rx) = mpsc::sync_channel(0);
        let (release_first_tx, release_first_rx) = mpsc::sync_channel(0);
        let (second_attempted_tx, second_attempted_rx) = mpsc::sync_channel(0);
        let (second_entered_tx, second_entered_rx) = mpsc::sync_channel(0);

        let first_gate = Arc::clone(&gate);
        let first = std::thread::spawn(move || {
            tauri::async_runtime::block_on(async {
                let _guard = first_gate.acquire().await;
                first_entered_tx.send(()).unwrap();
                release_first_rx.recv().unwrap();
            });
        });
        first_entered_rx.recv().unwrap();

        let second_gate = Arc::clone(&gate);
        let second = std::thread::spawn(move || {
            second_attempted_tx.send(()).unwrap();
            tauri::async_runtime::block_on(async {
                let _guard = second_gate.acquire().await;
                second_entered_tx.send(()).unwrap();
            });
        });
        second_attempted_rx.recv().unwrap();
        assert!(second_entered_rx.try_recv().is_err());

        release_first_tx.send(()).unwrap();
        second_entered_rx.recv().unwrap();
        first.join().unwrap();
        second.join().unwrap();
    }

    #[test]
    fn d9d2_group1_invoke_registration_replaces_legacy_sync_route() {
        let library_source = include_str!("../lib.rs");
        assert!(
            library_source.contains("vector_sync_stage_runtime::start_fenced_vector_sync_drain")
        );
        assert!(
            library_source.contains("vector_sync_stage_runtime::run_late_delete_resolution_once")
        );
        assert!(!library_source.contains("vector_sync_worker::start_memory_vector_sync"));

        let legacy_source = include_str!("vector_sync_worker.rs");
        assert!(legacy_source.contains("pub fn start_memory_vector_sync"));

        let rebuild_source = include_str!("vector_index_runtime.rs");
        assert!(rebuild_source.contains("FencedVectorSyncCompositionGate"));
        assert!(
            rebuild_source.contains("let _composition_guard = composition_gate.acquire().await")
        );
    }

    #[test]
    fn d9d2_group1_late_delete_command_maps_one_runner_end() {
        let stage_source = include_str!("vector_sync_stage_runtime.rs");
        let command_body = stage_source
            .split("pub async fn run_late_delete_resolution_once")
            .nth(1)
            .unwrap()
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert_eq!(
            command_body
                .matches("run_one_late_delete_from_app(")
                .count(),
            1,
            "one command invocation must compose exactly one runner call"
        );
        assert!(!command_body.contains("tauri::async_runtime::spawn"));

        assert_eq!(
            LateDeleteResolutionOnceResult::from(LateDeleteRunEnd::NoWork { recovered: 0 }),
            LateDeleteResolutionOnceResult::NoWork { recovered: 0 }
        );
        assert_eq!(
            LateDeleteResolutionOnceResult::from(LateDeleteRunEnd::Processed { recovered: 2 }),
            LateDeleteResolutionOnceResult::Processed { recovered: 2 }
        );
    }

    #[test]
    fn d9d2_group1_fenced_composition_live_dry_run_is_empty_and_read_only() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage =
            StorageService::initialize_with_roots(temp_dir.path().join("data"), None).unwrap();
        let (secrets, credential_reads) = TrackingSecretStore::new();
        let profile = ModelProfileService::new(&storage)
            .create(CreateModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "D9D2 dry-run embedding profile".into(),
                base_url: "https://api.openai.com/v1".into(),
                model_name: "text-embedding-3-small".into(),
                temperature: None,
                max_tokens: None,
                embedding_dimension: Some(1536),
            })
            .unwrap();
        ModelProfileService::new(&storage)
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                profile_id: profile.id.clone(),
            })
            .unwrap();
        secrets
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, &profile.id).unwrap(),
                SecretValue::new("test-api-key".into()).unwrap(),
            )
            .unwrap();

        let target = crate::model::transport::url_policy::validate_and_normalize_url(
            "https://api.openai.com/v1",
        )
        .unwrap();
        let descriptor = compute_canonical_generation_descriptor(
            &ModelProviderKind::OpenaiCompatible,
            &profile.id,
            &target,
            "text-embedding-3-small",
            1536,
        )
        .unwrap();
        storage
            .register_building_vector_generation("group1-dry-run", &descriptor, 1536)
            .unwrap();

        let registry = LanceDbVectorStoreRegistry::default();
        let data_root = storage.active_data_root().unwrap();
        let generation_id = VectorGenerationId::parse("group1-dry-run").unwrap();
        let _store = tauri::async_runtime::block_on(
            registry.generation_store_for_write(&data_root, &generation_id),
        )
        .unwrap();

        let coordinator = ModelRuntimeCoordinator::new(Duration::from_secs(5));
        let gate = FencedVectorSyncCompositionGate::default();
        let generation_before = generation_snapshot(&storage);
        let result = tauri::async_runtime::block_on(run_fenced_vector_sync_drain(
            &storage,
            &secrets,
            &coordinator,
            &registry,
            &gate,
            "group1-dry-run-owner",
            1,
        ))
        .unwrap();

        assert_eq!(result.requested_limit, 1);
        assert_eq!(result.processed, 0);
        assert!(result.stopped_no_eligible);
        assert_eq!(credential_reads.load(Ordering::SeqCst), 0);
        assert_eq!(generation_snapshot(&storage), generation_before);
    }
}
