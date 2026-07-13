//! Explicitly authorized, bounded convergence from the durable SQLite outbox
//! to the rebuildable LanceDB index. Nothing in this module auto-starts.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, MutexGuard,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};

use crate::{
    model::{
        profile::ModelProfileRepository,
        runtime::{ModelRuntimeCoordinator, ModelRuntimeErrorCode, ModelRuntimeService},
    },
    secrets::{SecretStore, WindowsCredentialSecretStore},
    storage::StorageService,
    vector_store::{LanceDbVectorStoreRegistry, VectorStore, VectorStoreErrorCode},
};

use super::{
    vector_index::{
        MemoryIndexErrorCode, MemoryIndexRequest, MemoryVectorIndexRepository,
        MemoryVectorIndexService,
    },
    vector_index_runtime::{ActiveDataRootResolver, MemoryVectorIndexRuntimeCoordinator},
    vector_sync_outbox::{
        ClaimMemoryVectorSyncLeaseRequest, MemoryVectorSyncAction, MemoryVectorSyncJob,
        MemoryVectorSyncOutboxRepository, MemoryVectorSyncState,
    },
    MemoryStatus,
};

const DEFAULT_DRAIN_LIMIT: usize = 32;
const DEFAULT_LEASE_SECONDS: u32 = 120;
const MAX_ATTEMPTS: u32 = 5;
const INITIAL_RETRY_SECONDS: u32 = 30;
const MAX_RETRY_SECONDS: u32 = 3_600;
const MAX_FINISHED_RUNS: usize = 20;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryVectorSyncSettings {
    pub life_id: String,
    pub enabled: bool,
    pub updated_at: Option<String>,
}

pub trait MemoryVectorSyncSettingsRepository: Send + Sync {
    fn get_vector_sync_settings(
        &self,
        life_id: &str,
    ) -> Result<MemoryVectorSyncSettings, MemoryVectorSyncWorkerError>;
    fn set_vector_sync_enabled(
        &self,
        life_id: &str,
        enabled: bool,
    ) -> Result<MemoryVectorSyncSettings, MemoryVectorSyncWorkerError>;
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum MemoryVectorSyncWorkerState {
    #[default]
    Stopped,
    Running,
    Pausing,
    Paused,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryVectorSyncFailureClass {
    Retriable,
    Blocked,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryVectorSyncWorkerErrorCode {
    InvalidRequest,
    SyncDisabled,
    SyncAlreadyRunning,
    SyncNotRunning,
    IndexOperationBusy,
    OutboxUnavailable,
    RepositoryUnavailable,
    NoActiveEmbeddingProfile,
    EmbeddingProfileNotFound,
    EmbeddingCredentialNotFound,
    EmbeddingPurposeMismatch,
    InvalidEmbeddingProfile,
    UnsupportedEmbeddingProvider,
    AuthenticationFailed,
    RateLimited,
    NetworkUnavailable,
    RequestTimeout,
    InvalidProviderResponse,
    VectorStoreUnavailable,
    InternalError,
}

impl MemoryVectorSyncWorkerErrorCode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::SyncDisabled => "SYNC_DISABLED",
            Self::SyncAlreadyRunning => "SYNC_ALREADY_RUNNING",
            Self::SyncNotRunning => "SYNC_NOT_RUNNING",
            Self::IndexOperationBusy => "INDEX_OPERATION_BUSY",
            Self::OutboxUnavailable => "OUTBOX_UNAVAILABLE",
            Self::RepositoryUnavailable => "REPOSITORY_UNAVAILABLE",
            Self::NoActiveEmbeddingProfile => "NO_ACTIVE_EMBEDDING_PROFILE",
            Self::EmbeddingProfileNotFound => "EMBEDDING_PROFILE_NOT_FOUND",
            Self::EmbeddingCredentialNotFound => "EMBEDDING_CREDENTIAL_NOT_FOUND",
            Self::EmbeddingPurposeMismatch => "EMBEDDING_PURPOSE_MISMATCH",
            Self::InvalidEmbeddingProfile => "INVALID_EMBEDDING_PROFILE",
            Self::UnsupportedEmbeddingProvider => "UNSUPPORTED_EMBEDDING_PROVIDER",
            Self::AuthenticationFailed => "AUTHENTICATION_FAILED",
            Self::RateLimited => "RATE_LIMITED",
            Self::NetworkUnavailable => "NETWORK_UNAVAILABLE",
            Self::RequestTimeout => "REQUEST_TIMEOUT",
            Self::InvalidProviderResponse => "INVALID_PROVIDER_RESPONSE",
            Self::VectorStoreUnavailable => "VECTOR_STORE_UNAVAILABLE",
            Self::InternalError => "INTERNAL_ERROR",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryVectorSyncWorkerError {
    pub code: MemoryVectorSyncWorkerErrorCode,
    pub message: String,
    pub recoverable: bool,
    pub failure_class: Option<MemoryVectorSyncFailureClass>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryVectorSyncWorkerConfig {
    pub drain_limit: usize,
    pub lease_seconds: u32,
}

impl Default for MemoryVectorSyncWorkerConfig {
    fn default() -> Self {
        Self {
            drain_limit: DEFAULT_DRAIN_LIMIT,
            lease_seconds: DEFAULT_LEASE_SECONDS,
        }
    }
}

impl MemoryVectorSyncWorkerConfig {
    fn validate(self) -> Result<Self, MemoryVectorSyncWorkerError> {
        if self.drain_limit == 0
            || self.drain_limit > DEFAULT_DRAIN_LIMIT
            || self.lease_seconds == 0
            || self.lease_seconds > MAX_RETRY_SECONDS
        {
            return Err(worker_error(
                MemoryVectorSyncWorkerErrorCode::InvalidRequest,
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct MemoryVectorSyncRunId(pub String);

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryVectorSyncWorkerStatus {
    pub life_id: String,
    pub enabled: bool,
    pub worker_state: MemoryVectorSyncWorkerState,
    pub run_id: Option<MemoryVectorSyncRunId>,
    pub pending_count: usize,
    pub processing_count: usize,
    pub retry_wait_count: usize,
    pub blocked_count: usize,
    pub failed_count: usize,
    pub last_run_at: Option<u64>,
    pub last_success_at: Option<u64>,
    pub last_safe_error_code: Option<MemoryVectorSyncWorkerErrorCode>,
    pub current_action: Option<MemoryVectorSyncAction>,
    pub next_retry_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StartMemoryVectorSyncResult {
    pub run_id: MemoryVectorSyncRunId,
    pub accepted: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryVectorSyncLifeRequest {
    pub life_id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetMemoryVectorSyncEnabledRequest {
    pub life_id: String,
    pub enabled: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryVectorSyncProcessDisposition {
    Completed,
    RetryWait,
    Blocked,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryVectorSyncProcessResult {
    pub action: MemoryVectorSyncAction,
    pub disposition: MemoryVectorSyncProcessDisposition,
    pub error_code: Option<MemoryVectorSyncWorkerErrorCode>,
}

pub struct MemoryVectorSyncWorker<'a, R, O, C, P, S, D>
where
    R: MemoryVectorIndexRepository + ?Sized,
    O: MemoryVectorSyncOutboxRepository + ?Sized,
    C: MemoryVectorSyncSettingsRepository + ?Sized,
    P: ModelProfileRepository,
    S: SecretStore + ?Sized,
    D: ActiveDataRootResolver + ?Sized,
{
    memories: &'a R,
    outbox: &'a O,
    settings: &'a C,
    profiles: &'a P,
    secrets: &'a S,
    data_root: &'a D,
    model_runtime: &'a ModelRuntimeCoordinator,
    stores: &'a LanceDbVectorStoreRegistry,
}

impl<'a, R, O, C, P, S, D> MemoryVectorSyncWorker<'a, R, O, C, P, S, D>
where
    R: MemoryVectorIndexRepository + ?Sized,
    O: MemoryVectorSyncOutboxRepository + ?Sized,
    C: MemoryVectorSyncSettingsRepository + ?Sized,
    P: ModelProfileRepository,
    S: SecretStore + ?Sized,
    D: ActiveDataRootResolver + ?Sized,
{
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        memories: &'a R,
        outbox: &'a O,
        settings: &'a C,
        profiles: &'a P,
        secrets: &'a S,
        data_root: &'a D,
        model_runtime: &'a ModelRuntimeCoordinator,
        stores: &'a LanceDbVectorStoreRegistry,
    ) -> Self {
        Self {
            memories,
            outbox,
            settings,
            profiles,
            secrets,
            data_root,
            model_runtime,
            stores,
        }
    }

    pub async fn process_next(
        &self,
        life_id: &str,
        lease_owner: &str,
        config: MemoryVectorSyncWorkerConfig,
    ) -> Result<Option<MemoryVectorSyncProcessResult>, MemoryVectorSyncWorkerError> {
        validate_life_id(life_id)?;
        if !self.settings.get_vector_sync_settings(life_id)?.enabled {
            return Err(worker_error(MemoryVectorSyncWorkerErrorCode::SyncDisabled));
        }
        let job = self
            .outbox
            .claim_next_with_lease(ClaimMemoryVectorSyncLeaseRequest {
                life_id: life_id.to_string(),
                lease_owner: lease_owner.to_string(),
                lease_seconds: config.lease_seconds,
            })
            .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?;
        let Some(job) = job else {
            return Ok(None);
        };
        let action = job.desired_action;
        match self.process_claimed(&job).await {
            Ok(()) => {
                self.outbox
                    .complete(life_id, &job.memory_id, lease_owner)
                    .map_err(|_| {
                        worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable)
                    })?;
                Ok(Some(MemoryVectorSyncProcessResult {
                    action,
                    disposition: MemoryVectorSyncProcessDisposition::Completed,
                    error_code: None,
                }))
            }
            Err(failure) => {
                let disposition = self.record_failure(&job, lease_owner, &failure)?;
                Ok(Some(MemoryVectorSyncProcessResult {
                    action,
                    disposition,
                    error_code: Some(failure.code),
                }))
            }
        }
    }

    pub async fn drain<F>(
        &self,
        life_id: &str,
        lease_owner: &str,
        config: MemoryVectorSyncWorkerConfig,
        should_pause: F,
    ) -> Result<Vec<MemoryVectorSyncProcessResult>, MemoryVectorSyncWorkerError>
    where
        F: Fn() -> bool,
    {
        let config = config.validate()?;
        let mut results = Vec::new();
        while results.len() < config.drain_limit && !should_pause() {
            match self.process_next(life_id, lease_owner, config).await? {
                Some(result) => results.push(result),
                None => break,
            }
        }
        Ok(results)
    }

    async fn process_claimed(
        &self,
        job: &MemoryVectorSyncJob,
    ) -> Result<(), MemoryVectorSyncWorkerError> {
        match job.desired_action {
            MemoryVectorSyncAction::Delete => self.delete_derived(job).await,
            MemoryVectorSyncAction::Upsert => {
                let memory = match self
                    .memories
                    .get_authoritative(&job.life_id, &job.memory_id)
                {
                    Ok(memory) => memory,
                    Err(error) if error.code == "MEMORY_NOT_FOUND" => {
                        return self.delete_derived(job).await;
                    }
                    Err(error) if error.code == "MEMORY_LIFE_MISMATCH" => {
                        return Err(failure_error(
                            MemoryVectorSyncWorkerErrorCode::RepositoryUnavailable,
                            MemoryVectorSyncFailureClass::Failed,
                        ));
                    }
                    Err(_) => {
                        return Err(failure_error(
                            MemoryVectorSyncWorkerErrorCode::RepositoryUnavailable,
                            MemoryVectorSyncFailureClass::Retriable,
                        ));
                    }
                };
                if memory.status != MemoryStatus::Confirmed || memory.is_sensitive {
                    return self.delete_derived(job).await;
                }
                self.upsert_current(job).await
            }
        }
    }

    async fn upsert_current(
        &self,
        job: &MemoryVectorSyncJob,
    ) -> Result<(), MemoryVectorSyncWorkerError> {
        let resolved = ModelRuntimeService::new(self.profiles, self.secrets, self.model_runtime)
            .resolve_active_embedding_provider()
            .map_err(map_model_runtime_error)?;
        let info = resolved.provider().model_info();
        let dimension = info.dimension.ok_or_else(|| {
            failure_error(
                MemoryVectorSyncWorkerErrorCode::InvalidEmbeddingProfile,
                MemoryVectorSyncFailureClass::Blocked,
            )
        })?;
        if resolved
            .profile
            .embedding_dimension
            .map(|value| value as usize)
            != Some(dimension)
        {
            return Err(failure_error(
                MemoryVectorSyncWorkerErrorCode::InvalidEmbeddingProfile,
                MemoryVectorSyncFailureClass::Blocked,
            ));
        }
        let space = crate::vector_store::VectorSpace {
            embedding_model: info.model_name,
            dimension,
        };
        let root = self.data_root.active_data_root().map_err(|_| {
            failure_error(
                MemoryVectorSyncWorkerErrorCode::VectorStoreUnavailable,
                MemoryVectorSyncFailureClass::Blocked,
            )
        })?;
        let store = self.stores.store_for_write(&root).await.map_err(|_| {
            failure_error(
                MemoryVectorSyncWorkerErrorCode::VectorStoreUnavailable,
                MemoryVectorSyncFailureClass::Retriable,
            )
        })?;
        let service = MemoryVectorIndexService::new(
            self.memories,
            resolved.provider(),
            store.as_ref(),
            space,
        )
        .map_err(map_index_error)?;
        match service
            .index_memory(MemoryIndexRequest {
                life_id: job.life_id.clone(),
                memory_id: job.memory_id.clone(),
            })
            .await
        {
            Ok(_) => Ok(()),
            Err(error)
                if matches!(
                    error.code,
                    MemoryIndexErrorCode::MemoryNotFound
                        | MemoryIndexErrorCode::MemoryNotConfirmed
                        | MemoryIndexErrorCode::SensitiveMemoryNotIndexable
                ) =>
            {
                self.delete_derived(job).await
            }
            Err(error) => Err(map_index_error(error)),
        }
    }

    async fn delete_derived(
        &self,
        job: &MemoryVectorSyncJob,
    ) -> Result<(), MemoryVectorSyncWorkerError> {
        let root = self.data_root.active_data_root().map_err(|_| {
            failure_error(
                MemoryVectorSyncWorkerErrorCode::VectorStoreUnavailable,
                MemoryVectorSyncFailureClass::Blocked,
            )
        })?;
        let Some(store) = self.stores.existing_store(&root).await.map_err(|_| {
            failure_error(
                MemoryVectorSyncWorkerErrorCode::VectorStoreUnavailable,
                MemoryVectorSyncFailureClass::Retriable,
            )
        })?
        else {
            return Ok(());
        };
        match store.delete(&job.life_id, &job.memory_id).await {
            Ok(_) => Ok(()),
            Err(error) if error.code == VectorStoreErrorCode::VectorNotFound => Ok(()),
            Err(error) if error.code == VectorStoreErrorCode::StoreUnavailable => {
                Err(failure_error(
                    MemoryVectorSyncWorkerErrorCode::VectorStoreUnavailable,
                    MemoryVectorSyncFailureClass::Retriable,
                ))
            }
            Err(_) => Err(failure_error(
                MemoryVectorSyncWorkerErrorCode::InternalError,
                MemoryVectorSyncFailureClass::Retriable,
            )),
        }
    }

    fn record_failure(
        &self,
        job: &MemoryVectorSyncJob,
        lease_owner: &str,
        failure: &MemoryVectorSyncWorkerError,
    ) -> Result<MemoryVectorSyncProcessDisposition, MemoryVectorSyncWorkerError> {
        let code = failure.code.as_str();
        match failure.failure_class {
            Some(MemoryVectorSyncFailureClass::Retriable) if job.attempt_count < MAX_ATTEMPTS => {
                self.outbox
                    .mark_retry_after(
                        &job.life_id,
                        &job.memory_id,
                        lease_owner,
                        retry_delay(job.attempt_count),
                        code,
                    )
                    .map_err(|_| {
                        worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable)
                    })?;
                Ok(MemoryVectorSyncProcessDisposition::RetryWait)
            }
            Some(MemoryVectorSyncFailureClass::Retriable) => {
                self.outbox
                    .mark_failed(&job.life_id, &job.memory_id, lease_owner, "MAX_ATTEMPTS")
                    .map_err(|_| {
                        worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable)
                    })?;
                Ok(MemoryVectorSyncProcessDisposition::Failed)
            }
            Some(MemoryVectorSyncFailureClass::Blocked) => {
                self.outbox
                    .mark_blocked(&job.life_id, &job.memory_id, lease_owner, code)
                    .map_err(|_| {
                        worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable)
                    })?;
                Ok(MemoryVectorSyncProcessDisposition::Blocked)
            }
            Some(MemoryVectorSyncFailureClass::Failed) | None => {
                self.outbox
                    .mark_failed(&job.life_id, &job.memory_id, lease_owner, code)
                    .map_err(|_| {
                        worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable)
                    })?;
                Ok(MemoryVectorSyncProcessDisposition::Failed)
            }
        }
    }
}

struct WorkerRun {
    run_id: MemoryVectorSyncRunId,
    state: MemoryVectorSyncWorkerState,
    pause: Arc<AtomicBool>,
    last_run_at: u64,
    last_success_at: Option<u64>,
    last_error: Option<MemoryVectorSyncWorkerErrorCode>,
    current_action: Option<MemoryVectorSyncAction>,
}

#[derive(Default)]
struct WorkerRegistry {
    runs: HashMap<String, WorkerRun>,
    finished_order: VecDeque<String>,
}

pub struct MemoryVectorSyncWorkerCoordinator {
    sequence: AtomicU64,
    registry: Mutex<WorkerRegistry>,
}

impl Default for MemoryVectorSyncWorkerCoordinator {
    fn default() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            registry: Mutex::new(WorkerRegistry::default()),
        }
    }
}

impl MemoryVectorSyncWorkerCoordinator {
    fn begin(
        &self,
        life_id: &str,
    ) -> Result<(MemoryVectorSyncRunId, Arc<AtomicBool>), MemoryVectorSyncWorkerError> {
        validate_life_id(life_id)?;
        let mut registry = self.registry()?;
        if registry.runs.get(life_id).is_some_and(|run| {
            matches!(
                run.state,
                MemoryVectorSyncWorkerState::Running | MemoryVectorSyncWorkerState::Pausing
            )
        }) {
            return Err(worker_error(
                MemoryVectorSyncWorkerErrorCode::SyncAlreadyRunning,
            ));
        }
        let run_id = MemoryVectorSyncRunId(format!(
            "sync-{:016x}-{:016x}",
            now_millis(),
            self.sequence.fetch_add(1, Ordering::Relaxed)
        ));
        let pause = Arc::new(AtomicBool::new(false));
        registry.runs.insert(
            life_id.to_string(),
            WorkerRun {
                run_id: run_id.clone(),
                state: MemoryVectorSyncWorkerState::Running,
                pause: Arc::clone(&pause),
                last_run_at: now_millis(),
                last_success_at: None,
                last_error: None,
                current_action: None,
            },
        );
        Ok((run_id, pause))
    }

    fn pause(&self, life_id: &str) -> Result<(), MemoryVectorSyncWorkerError> {
        let mut registry = self.registry()?;
        let run = registry
            .runs
            .get_mut(life_id)
            .ok_or_else(|| worker_error(MemoryVectorSyncWorkerErrorCode::SyncNotRunning))?;
        if !matches!(
            run.state,
            MemoryVectorSyncWorkerState::Running | MemoryVectorSyncWorkerState::Pausing
        ) {
            return Err(worker_error(
                MemoryVectorSyncWorkerErrorCode::SyncNotRunning,
            ));
        }
        run.pause.store(true, Ordering::Release);
        run.state = MemoryVectorSyncWorkerState::Pausing;
        Ok(())
    }

    fn finish(
        &self,
        life_id: &str,
        paused: bool,
        action: Option<MemoryVectorSyncAction>,
        error: Option<MemoryVectorSyncWorkerErrorCode>,
    ) {
        if let Ok(mut registry) = self.registry.lock() {
            if let Some(run) = registry.runs.get_mut(life_id) {
                run.state = if paused {
                    MemoryVectorSyncWorkerState::Paused
                } else {
                    MemoryVectorSyncWorkerState::Stopped
                };
                run.current_action = action;
                run.last_error = error;
                if error.is_none() {
                    run.last_success_at = Some(now_millis());
                }
                registry.finished_order.retain(|entry| entry != life_id);
                registry.finished_order.push_back(life_id.to_string());
            }
            while registry.finished_order.len() > MAX_FINISHED_RUNS {
                if let Some(oldest) = registry.finished_order.pop_front() {
                    registry.runs.remove(&oldest);
                }
            }
        }
    }

    fn snapshot(&self, life_id: &str) -> WorkerSnapshot {
        self.registry
            .lock()
            .ok()
            .and_then(|registry| {
                registry.runs.get(life_id).map(|run| WorkerSnapshot {
                    state: run.state,
                    run_id: Some(run.run_id.clone()),
                    last_run_at: Some(run.last_run_at),
                    last_success_at: run.last_success_at,
                    last_error: run.last_error,
                    current_action: run.current_action,
                })
            })
            .unwrap_or_default()
    }

    fn registry(&self) -> Result<MutexGuard<'_, WorkerRegistry>, MemoryVectorSyncWorkerError> {
        self.registry
            .lock()
            .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::InternalError))
    }
}

#[derive(Default)]
struct WorkerSnapshot {
    state: MemoryVectorSyncWorkerState,
    run_id: Option<MemoryVectorSyncRunId>,
    last_run_at: Option<u64>,
    last_success_at: Option<u64>,
    last_error: Option<MemoryVectorSyncWorkerErrorCode>,
    current_action: Option<MemoryVectorSyncAction>,
}

#[tauri::command]
pub fn get_memory_vector_sync_settings(
    storage: State<'_, StorageService>,
    request: MemoryVectorSyncLifeRequest,
) -> Result<MemoryVectorSyncSettings, MemoryVectorSyncWorkerError> {
    storage.get_vector_sync_settings(&request.life_id)
}

#[tauri::command]
pub fn set_memory_vector_sync_enabled(
    storage: State<'_, StorageService>,
    workers: State<'_, MemoryVectorSyncWorkerCoordinator>,
    request: SetMemoryVectorSyncEnabledRequest,
) -> Result<MemoryVectorSyncSettings, MemoryVectorSyncWorkerError> {
    let settings = storage.set_vector_sync_enabled(&request.life_id, request.enabled)?;
    if !request.enabled {
        let _ = workers.pause(&request.life_id);
    }
    Ok(settings)
}

#[tauri::command]
pub fn get_memory_vector_sync_status(
    storage: State<'_, StorageService>,
    workers: State<'_, MemoryVectorSyncWorkerCoordinator>,
    request: MemoryVectorSyncLifeRequest,
) -> Result<MemoryVectorSyncWorkerStatus, MemoryVectorSyncWorkerError> {
    build_status(storage.inner(), workers.inner(), &request.life_id)
}

#[tauri::command]
pub fn start_memory_vector_sync(
    app: AppHandle,
    storage: State<'_, StorageService>,
    workers: State<'_, MemoryVectorSyncWorkerCoordinator>,
    index_operations: State<'_, MemoryVectorIndexRuntimeCoordinator>,
    request: MemoryVectorSyncLifeRequest,
) -> Result<StartMemoryVectorSyncResult, MemoryVectorSyncWorkerError> {
    let life_id = request.life_id;
    if !storage.get_vector_sync_settings(&life_id)?.enabled {
        return Err(worker_error(MemoryVectorSyncWorkerErrorCode::SyncDisabled));
    }
    index_operations
        .begin_sync_worker(&life_id)
        .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::IndexOperationBusy))?;
    let (run_id, pause) = match workers.begin(&life_id) {
        Ok(value) => value,
        Err(error) => {
            index_operations.finish_sync_worker(&life_id);
            return Err(error);
        }
    };
    let spawned_run_id = run_id.clone();
    tauri::async_runtime::spawn(async move {
        run_worker(app, life_id, spawned_run_id, pause).await;
    });
    Ok(StartMemoryVectorSyncResult {
        run_id,
        accepted: true,
    })
}

#[tauri::command]
pub fn pause_memory_vector_sync(
    storage: State<'_, StorageService>,
    workers: State<'_, MemoryVectorSyncWorkerCoordinator>,
    request: MemoryVectorSyncLifeRequest,
) -> Result<MemoryVectorSyncWorkerStatus, MemoryVectorSyncWorkerError> {
    workers.pause(&request.life_id)?;
    build_status(storage.inner(), workers.inner(), &request.life_id)
}

#[tauri::command]
pub fn retry_memory_vector_sync_failures(
    storage: State<'_, StorageService>,
    request: MemoryVectorSyncLifeRequest,
) -> Result<usize, MemoryVectorSyncWorkerError> {
    validate_life_id(&request.life_id)?;
    storage
        .retry_failures(&request.life_id)
        .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))
}

async fn run_worker(
    app: AppHandle,
    life_id: String,
    run_id: MemoryVectorSyncRunId,
    pause: Arc<AtomicBool>,
) {
    let storage = app.state::<StorageService>();
    let secrets = app.state::<WindowsCredentialSecretStore>();
    let model_runtime = app.state::<ModelRuntimeCoordinator>();
    let stores = app.state::<LanceDbVectorStoreRegistry>();
    let workers = app.state::<MemoryVectorSyncWorkerCoordinator>();
    let index_operations = app.state::<MemoryVectorIndexRuntimeCoordinator>();
    let worker = MemoryVectorSyncWorker::new(
        storage.inner(),
        storage.inner(),
        storage.inner(),
        storage.inner(),
        secrets.inner(),
        storage.inner(),
        model_runtime.inner(),
        stores.inner(),
    );
    let result = worker
        .drain(
            &life_id,
            &run_id.0,
            MemoryVectorSyncWorkerConfig::default(),
            || pause.load(Ordering::Acquire),
        )
        .await;
    let action = result
        .as_ref()
        .ok()
        .and_then(|results| results.last().map(|result| result.action));
    let error = result
        .as_ref()
        .ok()
        .and_then(|results| results.last().and_then(|result| result.error_code))
        .or_else(|| result.as_ref().err().map(|error| error.code));
    workers.finish(&life_id, pause.load(Ordering::Acquire), action, error);
    index_operations.finish_sync_worker(&life_id);
}

fn build_status(
    storage: &StorageService,
    workers: &MemoryVectorSyncWorkerCoordinator,
    life_id: &str,
) -> Result<MemoryVectorSyncWorkerStatus, MemoryVectorSyncWorkerError> {
    validate_life_id(life_id)?;
    let enabled = storage.get_vector_sync_settings(life_id)?.enabled;
    let snapshot = workers.snapshot(life_id);
    let jobs = storage
        .list(life_id)
        .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?;
    let count = |state| jobs.iter().filter(|job| job.state == state).count();
    let next_retry_at = jobs
        .iter()
        .filter(|job| job.state == MemoryVectorSyncState::RetryWait)
        .filter_map(|job| job.next_attempt_at.clone())
        .min();
    Ok(MemoryVectorSyncWorkerStatus {
        life_id: life_id.to_string(),
        enabled,
        worker_state: snapshot.state,
        run_id: snapshot.run_id,
        pending_count: count(MemoryVectorSyncState::Pending),
        processing_count: count(MemoryVectorSyncState::Processing),
        retry_wait_count: count(MemoryVectorSyncState::RetryWait),
        blocked_count: count(MemoryVectorSyncState::Blocked),
        failed_count: count(MemoryVectorSyncState::Failed),
        last_run_at: snapshot.last_run_at,
        last_success_at: snapshot.last_success_at,
        last_safe_error_code: snapshot.last_error,
        current_action: snapshot.current_action,
        next_retry_at,
    })
}

fn retry_delay(attempt_count: u32) -> u32 {
    let shift = attempt_count.saturating_sub(1).min(7);
    INITIAL_RETRY_SECONDS
        .saturating_mul(1_u32 << shift)
        .min(MAX_RETRY_SECONDS)
}

fn validate_life_id(life_id: &str) -> Result<(), MemoryVectorSyncWorkerError> {
    if life_id.trim().is_empty() || life_id.chars().any(char::is_control) {
        Err(worker_error(
            MemoryVectorSyncWorkerErrorCode::InvalidRequest,
        ))
    } else {
        Ok(())
    }
}

fn map_model_runtime_error(
    error: crate::model::runtime::ModelRuntimeError,
) -> MemoryVectorSyncWorkerError {
    match error.code {
        ModelRuntimeErrorCode::NoActiveProfile => failure_error(
            MemoryVectorSyncWorkerErrorCode::NoActiveEmbeddingProfile,
            MemoryVectorSyncFailureClass::Blocked,
        ),
        ModelRuntimeErrorCode::ProfileNotFound => failure_error(
            MemoryVectorSyncWorkerErrorCode::EmbeddingProfileNotFound,
            MemoryVectorSyncFailureClass::Blocked,
        ),
        ModelRuntimeErrorCode::CredentialNotFound => failure_error(
            MemoryVectorSyncWorkerErrorCode::EmbeddingCredentialNotFound,
            MemoryVectorSyncFailureClass::Blocked,
        ),
        ModelRuntimeErrorCode::ProfilePurposeMismatch => failure_error(
            MemoryVectorSyncWorkerErrorCode::EmbeddingPurposeMismatch,
            MemoryVectorSyncFailureClass::Blocked,
        ),
        ModelRuntimeErrorCode::UnsupportedProvider => failure_error(
            MemoryVectorSyncWorkerErrorCode::UnsupportedEmbeddingProvider,
            MemoryVectorSyncFailureClass::Failed,
        ),
        _ => failure_error(
            MemoryVectorSyncWorkerErrorCode::InvalidEmbeddingProfile,
            MemoryVectorSyncFailureClass::Blocked,
        ),
    }
}

fn map_index_error(error: super::vector_index::MemoryIndexError) -> MemoryVectorSyncWorkerError {
    match error.code {
        MemoryIndexErrorCode::AuthenticationFailed => failure_error(
            MemoryVectorSyncWorkerErrorCode::AuthenticationFailed,
            MemoryVectorSyncFailureClass::Blocked,
        ),
        MemoryIndexErrorCode::RateLimited => failure_error(
            MemoryVectorSyncWorkerErrorCode::RateLimited,
            MemoryVectorSyncFailureClass::Retriable,
        ),
        MemoryIndexErrorCode::NetworkUnavailable => failure_error(
            MemoryVectorSyncWorkerErrorCode::NetworkUnavailable,
            MemoryVectorSyncFailureClass::Retriable,
        ),
        MemoryIndexErrorCode::RequestTimeout => failure_error(
            MemoryVectorSyncWorkerErrorCode::RequestTimeout,
            MemoryVectorSyncFailureClass::Retriable,
        ),
        MemoryIndexErrorCode::InvalidProviderResponse => failure_error(
            MemoryVectorSyncWorkerErrorCode::InvalidProviderResponse,
            MemoryVectorSyncFailureClass::Failed,
        ),
        MemoryIndexErrorCode::VectorStoreFailed => failure_error(
            MemoryVectorSyncWorkerErrorCode::VectorStoreUnavailable,
            MemoryVectorSyncFailureClass::Retriable,
        ),
        MemoryIndexErrorCode::DimensionMismatch | MemoryIndexErrorCode::InvalidRequest => {
            failure_error(
                MemoryVectorSyncWorkerErrorCode::InvalidEmbeddingProfile,
                MemoryVectorSyncFailureClass::Blocked,
            )
        }
        MemoryIndexErrorCode::EmbeddingFailed => failure_error(
            MemoryVectorSyncWorkerErrorCode::InvalidProviderResponse,
            MemoryVectorSyncFailureClass::Failed,
        ),
        _ => failure_error(
            MemoryVectorSyncWorkerErrorCode::InternalError,
            MemoryVectorSyncFailureClass::Failed,
        ),
    }
}

fn worker_error(code: MemoryVectorSyncWorkerErrorCode) -> MemoryVectorSyncWorkerError {
    let recoverable = !matches!(
        code,
        MemoryVectorSyncWorkerErrorCode::InvalidRequest
            | MemoryVectorSyncWorkerErrorCode::UnsupportedEmbeddingProvider
            | MemoryVectorSyncWorkerErrorCode::InvalidProviderResponse
    );
    MemoryVectorSyncWorkerError {
        code,
        message: safe_message(code).to_string(),
        recoverable,
        failure_class: None,
    }
}

fn failure_error(
    code: MemoryVectorSyncWorkerErrorCode,
    class: MemoryVectorSyncFailureClass,
) -> MemoryVectorSyncWorkerError {
    let mut error = worker_error(code);
    error.failure_class = Some(class);
    error
}

fn safe_message(code: MemoryVectorSyncWorkerErrorCode) -> &'static str {
    match code {
        MemoryVectorSyncWorkerErrorCode::InvalidRequest => "The vector sync request is invalid.",
        MemoryVectorSyncWorkerErrorCode::SyncDisabled => "Memory vector sync is disabled.",
        MemoryVectorSyncWorkerErrorCode::SyncAlreadyRunning => {
            "Memory vector sync is already running for this life."
        }
        MemoryVectorSyncWorkerErrorCode::SyncNotRunning => {
            "Memory vector sync is not running for this life."
        }
        MemoryVectorSyncWorkerErrorCode::IndexOperationBusy => {
            "Another index operation is active for this life."
        }
        MemoryVectorSyncWorkerErrorCode::OutboxUnavailable => {
            "The memory vector sync queue is unavailable."
        }
        MemoryVectorSyncWorkerErrorCode::RepositoryUnavailable => {
            "The authoritative memory repository is unavailable."
        }
        MemoryVectorSyncWorkerErrorCode::NoActiveEmbeddingProfile => {
            "No active embedding profile is configured."
        }
        MemoryVectorSyncWorkerErrorCode::EmbeddingProfileNotFound => {
            "The active embedding profile was not found."
        }
        MemoryVectorSyncWorkerErrorCode::EmbeddingCredentialNotFound => {
            "The active embedding profile has no credential."
        }
        MemoryVectorSyncWorkerErrorCode::EmbeddingPurposeMismatch => {
            "The active profile is not an embedding profile."
        }
        MemoryVectorSyncWorkerErrorCode::InvalidEmbeddingProfile => {
            "The active embedding profile is invalid."
        }
        MemoryVectorSyncWorkerErrorCode::UnsupportedEmbeddingProvider => {
            "The embedding provider is unsupported."
        }
        MemoryVectorSyncWorkerErrorCode::AuthenticationFailed => "Embedding authentication failed.",
        MemoryVectorSyncWorkerErrorCode::RateLimited => {
            "The embedding service rate limited the request."
        }
        MemoryVectorSyncWorkerErrorCode::NetworkUnavailable => {
            "The embedding service is unavailable."
        }
        MemoryVectorSyncWorkerErrorCode::RequestTimeout => "The embedding request timed out.",
        MemoryVectorSyncWorkerErrorCode::InvalidProviderResponse => {
            "The embedding provider returned an invalid response."
        }
        MemoryVectorSyncWorkerErrorCode::VectorStoreUnavailable => {
            "The derived vector store is unavailable."
        }
        MemoryVectorSyncWorkerErrorCode::InternalError => {
            "The memory vector sync operation failed."
        }
    }
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        thread,
        time::Duration,
    };

    use crate::{
        memory::{
            vector_sync_outbox::EnqueueMemoryVectorSyncRequest, ConfirmMemoryRequest,
            CreateMemoryCandidateRequest, MemoryKind, MemoryService, MemorySourceType,
        },
        model::profile::{
            CreateModelProfileRequest, ModelProfileService, ModelProviderKind, ModelPurpose,
            SetActiveModelProfileRequest, UpdateModelProfileRequest,
        },
        secrets::{InMemorySecretStore, SecretIdentifier, SecretPurpose, SecretStore, SecretValue},
        storage::{LifeIdentityRecord, PersonaTemplateRecord},
    };

    use super::*;

    struct TestServer {
        base_url: String,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl TestServer {
        fn response(status: &'static str, body: &'static str) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let handle = thread::spawn(move || {
                let mut stream = (0..500)
                    .find_map(|_| match listener.accept() {
                        Ok((stream, _)) => Some(stream),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(10));
                            None
                        }
                        Err(error) => panic!("mock listener failed: {error}"),
                    })
                    .expect("mock embedding request was not received");
                stream.set_nonblocking(false).unwrap();
                read_request(&mut stream);
                let reply = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(reply.as_bytes()).unwrap();
            });
            Self {
                base_url: format!("http://{address}/v1"),
                handle: Some(handle),
            }
        }

        fn success() -> Self {
            Self::response(
                "200 OK",
                r#"{"model":"test-embedding-model","data":[{"index":0,"embedding":[1.0,0.0,0.0]}]}"#,
            )
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                handle.join().unwrap();
            }
        }
    }

    fn read_request(stream: &mut TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 1024];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            let Some(header_end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let body_start = header_end + 4;
            let headers = String::from_utf8_lossy(&bytes[..body_start]);
            let length = headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .and_then(|value| value.trim().parse::<usize>().ok())
                })
                .unwrap_or(0);
            if bytes.len() >= body_start + length {
                break;
            }
        }
    }

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

    fn candidate(storage: &StorageService, sensitive: bool) -> super::super::MemoryRecord {
        MemoryService::new(storage)
            .create_candidate(CreateMemoryCandidateRequest {
                life_id: "life".into(),
                kind: MemoryKind::Fact,
                content: "temporary worker fixture".into(),
                summary: Some("worker summary".into()),
                source_type: MemorySourceType::Manual,
                source_ref: None,
                source_created_at: "2026-01-01T00:00:00Z".into(),
                importance: 0.5,
                confidence: 0.8,
                is_sensitive: sensitive,
            })
            .unwrap()
    }

    fn confirmed(storage: &StorageService, sensitive: bool) -> super::super::MemoryRecord {
        let memory = candidate(storage, sensitive);
        MemoryService::new(storage)
            .confirm(ConfirmMemoryRequest {
                life_id: "life".into(),
                memory_id: memory.id,
                user_confirmed: true,
                sensitive_consent: sensitive,
            })
            .unwrap()
    }

    fn activate_profile(storage: &StorageService, base_url: &str) -> String {
        let service = ModelProfileService::new(storage);
        let profile = service
            .create(CreateModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "Test embedding".into(),
                base_url: base_url.into(),
                model_name: "test-embedding-model".into(),
                temperature: None,
                max_tokens: None,
                embedding_dimension: Some(3),
            })
            .unwrap();
        service
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                profile_id: profile.id.clone(),
            })
            .unwrap();
        profile.id
    }

    fn update_profile_base(storage: &StorageService, profile_id: &str, base_url: &str) {
        ModelProfileService::new(storage)
            .update(UpdateModelProfileRequest {
                profile_id: profile_id.to_string(),
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "Test embedding".into(),
                base_url: base_url.to_string(),
                model_name: "test-embedding-model".into(),
                temperature: None,
                max_tokens: None,
                embedding_dimension: Some(3),
            })
            .unwrap();
    }

    fn secret(secrets: &InMemorySecretStore, profile_id: String, purpose: SecretPurpose) {
        secrets
            .set_secret(
                &SecretIdentifier::new(purpose, profile_id).unwrap(),
                SecretValue::new("test-placeholder".into()).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn disabled_is_the_default_and_never_claims_or_calls_embedding() {
        let (temp, storage) = test_storage();
        confirmed(&storage, false);
        let secrets = InMemorySecretStore::new();
        let runtime = ModelRuntimeCoordinator::default();
        let stores = LanceDbVectorStoreRegistry::default();
        let worker = MemoryVectorSyncWorker::new(
            &storage, &storage, &storage, &storage, &secrets, &storage, &runtime, &stores,
        );
        let error = tauri::async_runtime::block_on(worker.process_next(
            "life",
            "worker",
            MemoryVectorSyncWorkerConfig::default(),
        ))
        .unwrap_err();
        assert_eq!(error.code, MemoryVectorSyncWorkerErrorCode::SyncDisabled);
        let job = storage.list("life").unwrap().remove(0);
        assert_eq!(job.state, MemoryVectorSyncState::Pending);
        assert_eq!(job.attempt_count, 0);
        assert!(!temp.path().join("data/vectors/lancedb").exists());
    }

    #[test]
    fn missing_profile_and_embedding_credential_are_blocked_without_fallback() {
        let (_temp, storage) = test_storage();
        storage.set_vector_sync_enabled("life", true).unwrap();
        confirmed(&storage, false);
        let secrets = InMemorySecretStore::new();
        let runtime = ModelRuntimeCoordinator::default();
        let stores = LanceDbVectorStoreRegistry::default();
        let worker = MemoryVectorSyncWorker::new(
            &storage, &storage, &storage, &storage, &secrets, &storage, &runtime, &stores,
        );
        let result = tauri::async_runtime::block_on(worker.process_next(
            "life",
            "worker",
            MemoryVectorSyncWorkerConfig::default(),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            result.disposition,
            MemoryVectorSyncProcessDisposition::Blocked
        );
        assert_eq!(
            storage.list("life").unwrap()[0].state,
            MemoryVectorSyncState::Blocked
        );

        storage.retry_failures("life").unwrap();
        let profile = activate_profile(&storage, "http://127.0.0.1:9/v1");
        secret(&secrets, profile, SecretPurpose::ChatModelApiKey);
        let result = tauri::async_runtime::block_on(worker.process_next(
            "life",
            "worker",
            MemoryVectorSyncWorkerConfig::default(),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            result.disposition,
            MemoryVectorSyncProcessDisposition::Blocked
        );
        assert_eq!(
            storage.list("life").unwrap()[0].state,
            MemoryVectorSyncState::Blocked
        );
    }

    #[test]
    fn confirmed_non_sensitive_upsert_uses_mock_and_persists_only_derived_index() {
        let server = TestServer::success();
        let (temp, storage) = test_storage();
        storage.set_vector_sync_enabled("life", true).unwrap();
        confirmed(&storage, false);
        let profile = activate_profile(&storage, &server.base_url);
        let secrets = InMemorySecretStore::new();
        secret(&secrets, profile, SecretPurpose::EmbeddingModelApiKey);
        let runtime = ModelRuntimeCoordinator::default();
        let stores = LanceDbVectorStoreRegistry::default();
        let worker = MemoryVectorSyncWorker::new(
            &storage, &storage, &storage, &storage, &secrets, &storage, &runtime, &stores,
        );
        let result = tauri::async_runtime::block_on(worker.process_next(
            "life",
            "worker",
            MemoryVectorSyncWorkerConfig::default(),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            result.disposition,
            MemoryVectorSyncProcessDisposition::Completed
        );
        assert!(storage.list("life").unwrap().is_empty());
        assert!(temp.path().join("data/vectors/lancedb").is_dir());
    }

    #[test]
    fn candidate_sensitive_and_delete_jobs_never_need_embedding() {
        let (temp, storage) = test_storage();
        storage.set_vector_sync_enabled("life", true).unwrap();
        let candidate = candidate(&storage, false);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: candidate.id,
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        let sensitive = confirmed(&storage, true);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: sensitive.id,
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        let deleted = confirmed(&storage, false);
        MemoryService::new(&storage)
            .delete("life", &deleted.id)
            .unwrap();
        let secrets = InMemorySecretStore::new();
        let runtime = ModelRuntimeCoordinator::default();
        let stores = LanceDbVectorStoreRegistry::default();
        let worker = MemoryVectorSyncWorker::new(
            &storage, &storage, &storage, &storage, &secrets, &storage, &runtime, &stores,
        );
        let results = tauri::async_runtime::block_on(worker.drain(
            "life",
            "worker",
            MemoryVectorSyncWorkerConfig::default(),
            || false,
        ))
        .unwrap();
        assert_eq!(results.len(), 3);
        assert!(results
            .iter()
            .all(|result| { result.disposition == MemoryVectorSyncProcessDisposition::Completed }));
        assert!(storage.list("life").unwrap().is_empty());
        assert!(!temp.path().join("data/vectors/lancedb").exists());
    }

    #[test]
    fn network_and_rate_limit_failures_wait_and_max_attempts_fail() {
        let (_temp, storage) = test_storage();
        storage.set_vector_sync_enabled("life", true).unwrap();
        let memory = confirmed(&storage, false);
        let profile = activate_profile(&storage, "http://127.0.0.1:9/v1");
        let secrets = InMemorySecretStore::new();
        secret(&secrets, profile, SecretPurpose::EmbeddingModelApiKey);
        let runtime = ModelRuntimeCoordinator::default();
        let stores = LanceDbVectorStoreRegistry::default();
        let worker = MemoryVectorSyncWorker::new(
            &storage, &storage, &storage, &storage, &secrets, &storage, &runtime, &stores,
        );
        let result = tauri::async_runtime::block_on(worker.process_next(
            "life",
            "worker",
            MemoryVectorSyncWorkerConfig::default(),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            result.disposition,
            MemoryVectorSyncProcessDisposition::RetryWait
        );
        assert_eq!(
            storage.list("life").unwrap()[0].state,
            MemoryVectorSyncState::RetryWait
        );

        storage.retry_failures("life").unwrap();
        for attempt in 0..4 {
            storage
                .claim_next(
                    super::super::vector_sync_outbox::ClaimMemoryVectorSyncRequest {
                        life_id: "life".into(),
                        lease_owner: format!("attempt-{attempt}"),
                        lease_expires_at: "2999-01-01T00:00:00.000Z".into(),
                    },
                )
                .unwrap()
                .unwrap();
            storage
                .mark_retry(
                    "life",
                    &memory.id,
                    &format!("attempt-{attempt}"),
                    "2000-01-01T00:00:00.000Z",
                    "NETWORK_UNAVAILABLE",
                )
                .unwrap();
        }
        let result = tauri::async_runtime::block_on(worker.process_next(
            "life",
            "worker",
            MemoryVectorSyncWorkerConfig::default(),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            result.disposition,
            MemoryVectorSyncProcessDisposition::Failed
        );
        assert_eq!(
            storage.list("life").unwrap()[0].state,
            MemoryVectorSyncState::Failed
        );

        let rate_server = TestServer::response("429 Too Many Requests", "{}");
        let active = ModelProfileService::new(&storage)
            .get_active(ModelPurpose::Embedding)
            .unwrap()
            .unwrap();
        update_profile_base(&storage, &active.profile_id, &rate_server.base_url);
        storage.retry_failures("life").unwrap();
        let result = tauri::async_runtime::block_on(worker.process_next(
            "life",
            "worker",
            MemoryVectorSyncWorkerConfig::default(),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            result.disposition,
            MemoryVectorSyncProcessDisposition::RetryWait
        );

        let invalid_server = TestServer::response("200 OK", "{}");
        storage.retry_failures("life").unwrap();
        update_profile_base(&storage, &active.profile_id, &invalid_server.base_url);
        let result = tauri::async_runtime::block_on(worker.process_next(
            "life",
            "worker",
            MemoryVectorSyncWorkerConfig::default(),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            result.disposition,
            MemoryVectorSyncProcessDisposition::Failed
        );

        let auth_server = TestServer::response("401 Unauthorized", "{}");
        storage.retry_failures("life").unwrap();
        update_profile_base(&storage, &active.profile_id, &auth_server.base_url);
        let result = tauri::async_runtime::block_on(worker.process_next(
            "life",
            "worker",
            MemoryVectorSyncWorkerConfig::default(),
        ))
        .unwrap()
        .unwrap();
        assert_eq!(
            result.disposition,
            MemoryVectorSyncProcessDisposition::Blocked
        );
        assert_eq!(retry_delay(1), 30);
        assert_eq!(retry_delay(5), 480);
    }

    #[test]
    fn coordinator_pause_and_shared_rebuild_exclusion_are_deterministic() {
        let workers = MemoryVectorSyncWorkerCoordinator::default();
        let index = MemoryVectorIndexRuntimeCoordinator::default();
        index.begin_sync_worker("life").unwrap();
        let (_run, pause) = workers.begin("life").unwrap();
        assert!(workers.begin("life").is_err());
        workers.pause("life").unwrap();
        assert!(pause.load(Ordering::Acquire));
        assert_eq!(
            workers.snapshot("life").state,
            MemoryVectorSyncWorkerState::Pausing
        );
        workers.finish("life", true, None, None);
        index.finish_sync_worker("life");
        assert_eq!(
            workers.snapshot("life").state,
            MemoryVectorSyncWorkerState::Paused
        );
    }

    #[test]
    fn status_payload_and_strict_requests_expose_no_secret_text_vector_or_path() {
        let (_temp, storage) = test_storage();
        let workers = MemoryVectorSyncWorkerCoordinator::default();
        let status = build_status(&storage, &workers, "life").unwrap();
        let json = serde_json::to_string(&status).unwrap().to_ascii_lowercase();
        for forbidden in [
            "apikey",
            "summary",
            "content",
            "vector",
            "credential",
            "path",
        ] {
            assert!(!json.contains(forbidden));
        }
        assert!(serde_json::from_str::<MemoryVectorSyncLifeRequest>(
            r#"{"lifeId":"life","modelName":"forbidden"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<SetMemoryVectorSyncEnabledRequest>(
            r#"{"lifeId":"life","enabled":true,"apiKey":"forbidden"}"#
        )
        .is_err());
    }
}
