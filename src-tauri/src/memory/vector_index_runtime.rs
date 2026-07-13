//! Manual, task-based runtime assembly for governed memory vector rebuilds.
//! Status queries never initialize LanceDB or call an embedding provider.

use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
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
        profile::{ModelProfileRepository, ModelPurpose},
        runtime::{ModelRuntimeCoordinator, ModelRuntimeErrorCode, ModelRuntimeService},
    },
    secrets::{
        SecretIdentifier, SecretPurpose, SecretStore, SecretStoreErrorCode,
        WindowsCredentialSecretStore,
    },
    storage::StorageService,
    vector_store::{LanceDbVectorStore, VectorSpace, VectorStore},
};

use super::{
    vector_index::{
        MemoryIndexErrorCode, MemoryRebuildObserver, MemoryRebuildPhase, MemoryRebuildProgress,
        MemoryRebuildReport, MemoryRebuildRequest, MemoryVectorIndexRepository,
        MemoryVectorIndexService,
    },
    MemoryStatus,
};

const STATUS_PAGE_SIZE: usize = 256;
const MAX_COMPLETED_JOBS: usize = 20;

pub trait ActiveDataRootResolver: Send + Sync {
    fn active_data_root(&self) -> Result<PathBuf, VectorIndexRuntimeError>;
}

impl ActiveDataRootResolver for StorageService {
    fn active_data_root(&self) -> Result<PathBuf, VectorIndexRuntimeError> {
        StorageService::active_data_root(self)
            .map_err(|_| runtime_error(VectorIndexRuntimeErrorCode::VectorStoreUnavailable))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct VectorIndexJobId(pub String);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum VectorIndexJobStatus {
    Queued,
    ResolvingProfile,
    Scanning,
    Embedding,
    Writing,
    Completed,
    Failed,
    Cancelled,
}

impl VectorIndexJobStatus {
    fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VectorIndexJobProgress {
    pub scanned_count: usize,
    pub eligible_count: usize,
    pub embedded_count: usize,
    pub indexed_count: usize,
    pub skipped_candidate_count: usize,
    pub skipped_sensitive_count: usize,
    pub current_batch: usize,
    pub total_batches: usize,
    pub embedding_model: Option<String>,
    pub dimension: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VectorIndexJobResult {
    pub job_id: VectorIndexJobId,
    pub life_id: String,
    pub status: VectorIndexJobStatus,
    pub progress: VectorIndexJobProgress,
    pub report: Option<MemoryRebuildReport>,
    pub error_code: Option<VectorIndexRuntimeErrorCode>,
    pub error_message: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryVectorIndexStatus {
    pub life_id: String,
    pub active_embedding_profile_exists: bool,
    pub credential_exists: bool,
    pub embedding_model: Option<String>,
    pub configured_dimension: Option<usize>,
    pub index_directory_exists: bool,
    pub indexed_count: usize,
    pub eligible_memory_count: usize,
    pub rebuild_running: bool,
    pub last_job: Option<VectorIndexJobResult>,
    pub rebuild_recommended: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VectorIndexRuntimeErrorCode {
    InvalidRequest,
    NoActiveEmbeddingProfile,
    EmbeddingProfileNotFound,
    EmbeddingCredentialNotFound,
    EmbeddingPurposeMismatch,
    UnsupportedEmbeddingProvider,
    EmbeddingDimensionMismatch,
    VectorStoreUnavailable,
    RebuildAlreadyRunning,
    RebuildCancelled,
    RebuildFailed,
    JobNotFound,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VectorIndexRuntimeError {
    pub code: VectorIndexRuntimeErrorCode,
    pub message: String,
    pub recoverable: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryVectorIndexStatusRequest {
    pub life_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartMemoryVectorIndexRebuildRequest {
    pub life_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MemoryVectorIndexJobRequest {
    pub job_id: VectorIndexJobId,
}

struct JobEntry {
    result: VectorIndexJobResult,
    cancel: Arc<AtomicBool>,
}

#[derive(Default)]
struct JobRegistry {
    jobs: HashMap<VectorIndexJobId, JobEntry>,
    active_lives: HashMap<String, VectorIndexJobId>,
    completed_order: VecDeque<VectorIndexJobId>,
}

pub struct MemoryVectorIndexRuntimeCoordinator {
    sequence: AtomicU64,
    registry: Mutex<JobRegistry>,
}

impl Default for MemoryVectorIndexRuntimeCoordinator {
    fn default() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            registry: Mutex::new(JobRegistry::default()),
        }
    }
}

impl MemoryVectorIndexRuntimeCoordinator {
    fn start_job(&self, life_id: String) -> Result<VectorIndexJobId, VectorIndexRuntimeError> {
        validate_life_id(&life_id)?;
        let mut registry = self.registry()?;
        if registry.active_lives.contains_key(&life_id) {
            return Err(runtime_error(
                VectorIndexRuntimeErrorCode::RebuildAlreadyRunning,
            ));
        }
        let job_id = generate_job_id(&self.sequence);
        registry
            .active_lives
            .insert(life_id.clone(), job_id.clone());
        registry.jobs.insert(
            job_id.clone(),
            JobEntry {
                result: VectorIndexJobResult {
                    job_id: job_id.clone(),
                    life_id,
                    status: VectorIndexJobStatus::Queued,
                    progress: VectorIndexJobProgress::default(),
                    report: None,
                    error_code: None,
                    error_message: None,
                },
                cancel: Arc::new(AtomicBool::new(false)),
            },
        );
        Ok(job_id)
    }

    pub fn get_job(
        &self,
        job_id: &VectorIndexJobId,
    ) -> Result<VectorIndexJobResult, VectorIndexRuntimeError> {
        self.registry()?
            .jobs
            .get(job_id)
            .map(|entry| entry.result.clone())
            .ok_or_else(|| runtime_error(VectorIndexRuntimeErrorCode::JobNotFound))
    }

    pub fn cancel_job(
        &self,
        job_id: &VectorIndexJobId,
    ) -> Result<VectorIndexJobResult, VectorIndexRuntimeError> {
        let mut registry = self.registry()?;
        let entry = registry
            .jobs
            .get_mut(job_id)
            .ok_or_else(|| runtime_error(VectorIndexRuntimeErrorCode::JobNotFound))?;
        if entry.result.status.terminal() || entry.cancel.swap(true, Ordering::AcqRel) {
            return Err(runtime_error(VectorIndexRuntimeErrorCode::RebuildCancelled));
        }
        Ok(entry.result.clone())
    }

    fn cancellation(
        &self,
        job_id: &VectorIndexJobId,
    ) -> Result<Arc<AtomicBool>, VectorIndexRuntimeError> {
        self.registry()?
            .jobs
            .get(job_id)
            .map(|entry| Arc::clone(&entry.cancel))
            .ok_or_else(|| runtime_error(VectorIndexRuntimeErrorCode::JobNotFound))
    }

    fn update_status(&self, job_id: &VectorIndexJobId, status: VectorIndexJobStatus) {
        if let Ok(mut registry) = self.registry.lock() {
            if let Some(entry) = registry.jobs.get_mut(job_id) {
                if !entry.result.status.terminal() {
                    entry.result.status = status;
                }
            }
        }
    }

    fn update_profile(&self, job_id: &VectorIndexJobId, model: String, dimension: usize) {
        if let Ok(mut registry) = self.registry.lock() {
            if let Some(entry) = registry.jobs.get_mut(job_id) {
                entry.result.progress.embedding_model = Some(model);
                entry.result.progress.dimension = Some(dimension);
            }
        }
    }

    fn update_progress(&self, job_id: &VectorIndexJobId, progress: MemoryRebuildProgress) {
        if let Ok(mut registry) = self.registry.lock() {
            if let Some(entry) = registry.jobs.get_mut(job_id) {
                entry.result.status = match progress.phase {
                    MemoryRebuildPhase::Scanning => VectorIndexJobStatus::Scanning,
                    MemoryRebuildPhase::Embedding => VectorIndexJobStatus::Embedding,
                    MemoryRebuildPhase::Writing => VectorIndexJobStatus::Writing,
                };
                let public = &mut entry.result.progress;
                public.scanned_count = progress.scanned_count;
                public.eligible_count = progress.eligible_count;
                public.embedded_count = progress.embedded_count;
                public.indexed_count = progress.indexed_count;
                public.skipped_candidate_count = progress.skipped_candidate_count;
                public.skipped_sensitive_count = progress.skipped_sensitive_count;
                public.current_batch = progress.current_batch;
                public.total_batches = progress.total_batches;
            }
        }
    }

    fn finish(
        &self,
        job_id: &VectorIndexJobId,
        status: VectorIndexJobStatus,
        report: Option<MemoryRebuildReport>,
        error: Option<VectorIndexRuntimeError>,
    ) {
        if let Ok(mut registry) = self.registry.lock() {
            let life_id = if let Some(entry) = registry.jobs.get_mut(job_id) {
                if entry.result.status.terminal() {
                    return;
                }
                entry.result.status = status;
                entry.result.report = report;
                if let Some(error) = error {
                    entry.result.error_code = Some(error.code);
                    entry.result.error_message = Some(error.message);
                }
                Some(entry.result.life_id.clone())
            } else {
                None
            };
            if let Some(life_id) = life_id {
                registry.active_lives.remove(&life_id);
                registry.completed_order.push_back(job_id.clone());
                while registry.completed_order.len() > MAX_COMPLETED_JOBS {
                    if let Some(oldest) = registry.completed_order.pop_front() {
                        registry.jobs.remove(&oldest);
                    }
                }
            }
        }
    }

    fn latest_for_life(&self, life_id: &str) -> Option<VectorIndexJobResult> {
        let registry = self.registry.lock().ok()?;
        registry
            .jobs
            .values()
            .filter(|entry| entry.result.life_id == life_id)
            .max_by(|left, right| left.result.job_id.0.cmp(&right.result.job_id.0))
            .map(|entry| entry.result.clone())
    }

    fn is_running(&self, life_id: &str) -> bool {
        self.registry
            .lock()
            .is_ok_and(|registry| registry.active_lives.contains_key(life_id))
    }

    fn registry(&self) -> Result<MutexGuard<'_, JobRegistry>, VectorIndexRuntimeError> {
        self.registry
            .lock()
            .map_err(|_| runtime_error(VectorIndexRuntimeErrorCode::RebuildFailed))
    }
}

pub struct MemoryVectorIndexRuntimeService<'a, R, P, S, D>
where
    R: MemoryVectorIndexRepository + ?Sized,
    P: ModelProfileRepository,
    S: SecretStore + ?Sized,
    D: ActiveDataRootResolver + ?Sized,
{
    memories: &'a R,
    profiles: &'a P,
    secrets: &'a S,
    data_root: &'a D,
    model_runtime: &'a ModelRuntimeCoordinator,
}

impl<'a, R, P, S, D> MemoryVectorIndexRuntimeService<'a, R, P, S, D>
where
    R: MemoryVectorIndexRepository + ?Sized,
    P: ModelProfileRepository,
    S: SecretStore + ?Sized,
    D: ActiveDataRootResolver + ?Sized,
{
    pub fn new(
        memories: &'a R,
        profiles: &'a P,
        secrets: &'a S,
        data_root: &'a D,
        model_runtime: &'a ModelRuntimeCoordinator,
    ) -> Self {
        Self {
            memories,
            profiles,
            secrets,
            data_root,
            model_runtime,
        }
    }

    pub async fn rebuild(
        &self,
        life_id: &str,
        observer: &dyn MemoryRebuildObserver,
    ) -> Result<MemoryRebuildReport, VectorIndexRuntimeError> {
        validate_life_id(life_id)?;
        let resolved = ModelRuntimeService::new(self.profiles, self.secrets, self.model_runtime)
            .resolve_active_embedding_provider()
            .map_err(map_model_runtime_error)?;
        let info = resolved.provider().model_info();
        let dimension = info.dimension.ok_or_else(|| {
            runtime_error(VectorIndexRuntimeErrorCode::EmbeddingDimensionMismatch)
        })?;
        if resolved
            .profile
            .embedding_dimension
            .map(|value| value as usize)
            != Some(dimension)
        {
            return Err(runtime_error(
                VectorIndexRuntimeErrorCode::EmbeddingDimensionMismatch,
            ));
        }
        let space = VectorSpace {
            embedding_model: info.model_name,
            dimension,
        };
        observer.on_model_resolved(&space.embedding_model, space.dimension);
        if observer.is_cancelled() {
            return Err(runtime_error(VectorIndexRuntimeErrorCode::RebuildCancelled));
        }
        let root = self.data_root.active_data_root()?;
        let store = LanceDbVectorStore::open(root.join("vectors").join("lancedb"))
            .await
            .map_err(|_| runtime_error(VectorIndexRuntimeErrorCode::VectorStoreUnavailable))?;
        let service =
            MemoryVectorIndexService::new(self.memories, resolved.provider(), &store, space)
                .map_err(map_index_error)?;
        service
            .rebuild_life_index_observed(
                MemoryRebuildRequest {
                    life_id: life_id.to_string(),
                },
                observer,
            )
            .await
            .map_err(map_index_error)
    }

    pub async fn status(
        &self,
        life_id: &str,
        jobs: &MemoryVectorIndexRuntimeCoordinator,
    ) -> Result<MemoryVectorIndexStatus, VectorIndexRuntimeError> {
        validate_life_id(life_id)?;
        let active = self
            .profiles
            .get_active_profile(ModelPurpose::Embedding)
            .map_err(|_| runtime_error(VectorIndexRuntimeErrorCode::RebuildFailed))?;
        let mut active_exists = false;
        let mut credential_exists = false;
        let mut embedding_model = None;
        let mut configured_dimension = None;
        let mut space = None;
        if let Some(active) = active {
            if let Some(profile) = self
                .profiles
                .get_profile(&active.profile_id)
                .map_err(|_| runtime_error(VectorIndexRuntimeErrorCode::RebuildFailed))?
            {
                if profile.purpose == ModelPurpose::Embedding {
                    active_exists = true;
                    embedding_model = Some(profile.model_name.clone());
                    configured_dimension = profile.embedding_dimension.map(|value| value as usize);
                    space = configured_dimension.map(|dimension| VectorSpace {
                        embedding_model: profile.model_name,
                        dimension,
                    });
                    let identifier = SecretIdentifier::new(
                        SecretPurpose::EmbeddingModelApiKey,
                        active.profile_id,
                    )
                    .map_err(|_| {
                        runtime_error(VectorIndexRuntimeErrorCode::EmbeddingProfileNotFound)
                    })?;
                    credential_exists = self.secrets.has_secret(&identifier).map_err(|error| {
                        if error.code == SecretStoreErrorCode::NotFound {
                            runtime_error(VectorIndexRuntimeErrorCode::EmbeddingCredentialNotFound)
                        } else {
                            runtime_error(VectorIndexRuntimeErrorCode::RebuildFailed)
                        }
                    })?;
                }
            }
        }

        let root = self.data_root.active_data_root()?;
        let index_root = root.join("vectors").join("lancedb");
        let index_directory_exists = index_root.is_dir();
        let indexed_count = if index_directory_exists {
            if let Some(space) = space.as_ref() {
                LanceDbVectorStore::open(&index_root)
                    .await
                    .map_err(|_| {
                        runtime_error(VectorIndexRuntimeErrorCode::VectorStoreUnavailable)
                    })?
                    .count(life_id, Some(space))
                    .await
                    .map_err(|_| runtime_error(VectorIndexRuntimeErrorCode::RebuildFailed))?
            } else {
                0
            }
        } else {
            0
        };
        let eligible_memory_count = count_eligible(self.memories, life_id)?;
        let reason = if !active_exists {
            Some("No active embedding profile is configured.".to_string())
        } else if !credential_exists {
            Some("The active embedding profile has no credential.".to_string())
        } else if !index_directory_exists {
            Some("The derived vector index directory does not exist.".to_string())
        } else if indexed_count != eligible_memory_count {
            Some(
                "Index and eligible-memory counts differ; a rebuild is conservatively recommended."
                    .to_string(),
            )
        } else {
            None
        };
        Ok(MemoryVectorIndexStatus {
            life_id: life_id.to_string(),
            active_embedding_profile_exists: active_exists,
            credential_exists,
            embedding_model,
            configured_dimension,
            index_directory_exists,
            indexed_count,
            eligible_memory_count,
            rebuild_running: jobs.is_running(life_id),
            last_job: jobs.latest_for_life(life_id),
            rebuild_recommended: reason.is_some(),
            reason,
        })
    }
}

struct RuntimeObserver<'a> {
    jobs: &'a MemoryVectorIndexRuntimeCoordinator,
    job_id: VectorIndexJobId,
    cancel: Arc<AtomicBool>,
}

impl MemoryRebuildObserver for RuntimeObserver<'_> {
    fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }

    fn on_model_resolved(&self, embedding_model: &str, dimension: usize) {
        self.jobs
            .update_profile(&self.job_id, embedding_model.to_string(), dimension);
    }

    fn on_progress(&self, progress: MemoryRebuildProgress) {
        self.jobs.update_progress(&self.job_id, progress);
    }
}

#[tauri::command]
pub async fn get_memory_vector_index_status(
    storage: State<'_, StorageService>,
    secrets: State<'_, WindowsCredentialSecretStore>,
    model_runtime: State<'_, ModelRuntimeCoordinator>,
    jobs: State<'_, MemoryVectorIndexRuntimeCoordinator>,
    request: MemoryVectorIndexStatusRequest,
) -> Result<MemoryVectorIndexStatus, VectorIndexRuntimeError> {
    MemoryVectorIndexRuntimeService::new(
        storage.inner(),
        storage.inner(),
        secrets.inner(),
        storage.inner(),
        model_runtime.inner(),
    )
    .status(&request.life_id, jobs.inner())
    .await
}

#[tauri::command]
pub fn start_memory_vector_index_rebuild(
    app: AppHandle,
    jobs: State<'_, MemoryVectorIndexRuntimeCoordinator>,
    request: StartMemoryVectorIndexRebuildRequest,
) -> Result<VectorIndexJobId, VectorIndexRuntimeError> {
    let life_id = request.life_id;
    let job_id = jobs.start_job(life_id.clone())?;
    let spawned_job_id = job_id.clone();
    tauri::async_runtime::spawn(async move {
        run_job(app, spawned_job_id, life_id).await;
    });
    Ok(job_id)
}

#[tauri::command]
pub fn get_memory_vector_index_job(
    jobs: State<'_, MemoryVectorIndexRuntimeCoordinator>,
    request: MemoryVectorIndexJobRequest,
) -> Result<VectorIndexJobResult, VectorIndexRuntimeError> {
    jobs.get_job(&request.job_id)
}

#[tauri::command]
pub fn cancel_memory_vector_index_job(
    jobs: State<'_, MemoryVectorIndexRuntimeCoordinator>,
    request: MemoryVectorIndexJobRequest,
) -> Result<VectorIndexJobResult, VectorIndexRuntimeError> {
    jobs.cancel_job(&request.job_id)
}

async fn run_job(app: AppHandle, job_id: VectorIndexJobId, life_id: String) {
    let jobs = app.state::<MemoryVectorIndexRuntimeCoordinator>();
    jobs.update_status(&job_id, VectorIndexJobStatus::ResolvingProfile);
    let cancel = match jobs.cancellation(&job_id) {
        Ok(cancel) => cancel,
        Err(_) => return,
    };
    if cancel.load(Ordering::Acquire) {
        jobs.finish(
            &job_id,
            VectorIndexJobStatus::Cancelled,
            None,
            Some(runtime_error(VectorIndexRuntimeErrorCode::RebuildCancelled)),
        );
        return;
    }
    let storage = app.state::<StorageService>();
    let secrets = app.state::<WindowsCredentialSecretStore>();
    let model_runtime = app.state::<ModelRuntimeCoordinator>();
    let service = MemoryVectorIndexRuntimeService::new(
        storage.inner(),
        storage.inner(),
        secrets.inner(),
        storage.inner(),
        model_runtime.inner(),
    );
    let observer = RuntimeObserver {
        jobs: jobs.inner(),
        job_id: job_id.clone(),
        cancel,
    };
    let result = service.rebuild(&life_id, &observer).await;
    match result {
        Ok(report) => {
            jobs.update_profile(&job_id, report.embedding_model.clone(), report.dimension);
            jobs.finish(&job_id, VectorIndexJobStatus::Completed, Some(report), None);
        }
        Err(error) if error.code == VectorIndexRuntimeErrorCode::RebuildCancelled => {
            jobs.finish(&job_id, VectorIndexJobStatus::Cancelled, None, Some(error))
        }
        Err(error) => jobs.finish(&job_id, VectorIndexJobStatus::Failed, None, Some(error)),
    }
}

fn count_eligible<R: MemoryVectorIndexRepository + ?Sized>(
    memories: &R,
    life_id: &str,
) -> Result<usize, VectorIndexRuntimeError> {
    let mut offset = 0usize;
    let mut count = 0usize;
    loop {
        let page = memories
            .list_page(life_id, offset, STATUS_PAGE_SIZE)
            .map_err(|_| runtime_error(VectorIndexRuntimeErrorCode::RebuildFailed))?;
        if page.is_empty() {
            break;
        }
        let page_len = page.len();
        count += page
            .iter()
            .filter(|memory| {
                memory.life_id == life_id
                    && memory.status == MemoryStatus::Confirmed
                    && !memory.is_sensitive
                    && !memory
                        .summary
                        .as_deref()
                        .filter(|summary| !summary.trim().is_empty())
                        .unwrap_or(&memory.content)
                        .trim()
                        .is_empty()
            })
            .count();
        offset = offset.saturating_add(page_len);
        if page_len < STATUS_PAGE_SIZE {
            break;
        }
    }
    Ok(count)
}

fn validate_life_id(life_id: &str) -> Result<(), VectorIndexRuntimeError> {
    if life_id.trim().is_empty() || life_id.chars().any(char::is_control) {
        return Err(runtime_error(VectorIndexRuntimeErrorCode::InvalidRequest));
    }
    Ok(())
}

fn map_model_runtime_error(
    error: crate::model::runtime::ModelRuntimeError,
) -> VectorIndexRuntimeError {
    let code = match error.code {
        ModelRuntimeErrorCode::NoActiveProfile => {
            VectorIndexRuntimeErrorCode::NoActiveEmbeddingProfile
        }
        ModelRuntimeErrorCode::ProfileNotFound => {
            VectorIndexRuntimeErrorCode::EmbeddingProfileNotFound
        }
        ModelRuntimeErrorCode::CredentialNotFound => {
            VectorIndexRuntimeErrorCode::EmbeddingCredentialNotFound
        }
        ModelRuntimeErrorCode::ProfilePurposeMismatch => {
            VectorIndexRuntimeErrorCode::EmbeddingPurposeMismatch
        }
        ModelRuntimeErrorCode::UnsupportedProvider => {
            VectorIndexRuntimeErrorCode::UnsupportedEmbeddingProvider
        }
        ModelRuntimeErrorCode::DimensionMismatch => {
            VectorIndexRuntimeErrorCode::EmbeddingDimensionMismatch
        }
        _ => VectorIndexRuntimeErrorCode::RebuildFailed,
    };
    runtime_error(code)
}

fn map_index_error(error: super::vector_index::MemoryIndexError) -> VectorIndexRuntimeError {
    let code = match error.code {
        MemoryIndexErrorCode::RebuildCancelled => VectorIndexRuntimeErrorCode::RebuildCancelled,
        MemoryIndexErrorCode::DimensionMismatch => {
            VectorIndexRuntimeErrorCode::EmbeddingDimensionMismatch
        }
        MemoryIndexErrorCode::IndexOperationInProgress => {
            VectorIndexRuntimeErrorCode::RebuildAlreadyRunning
        }
        _ => VectorIndexRuntimeErrorCode::RebuildFailed,
    };
    runtime_error(code)
}

fn runtime_error(code: VectorIndexRuntimeErrorCode) -> VectorIndexRuntimeError {
    let (message, recoverable) = match code {
        VectorIndexRuntimeErrorCode::InvalidRequest => {
            ("The vector index request is invalid.", false)
        }
        VectorIndexRuntimeErrorCode::NoActiveEmbeddingProfile => {
            ("No active embedding model profile is configured.", true)
        }
        VectorIndexRuntimeErrorCode::EmbeddingProfileNotFound => {
            ("The active embedding model profile was not found.", true)
        }
        VectorIndexRuntimeErrorCode::EmbeddingCredentialNotFound => {
            ("The active embedding profile has no credential.", true)
        }
        VectorIndexRuntimeErrorCode::EmbeddingPurposeMismatch => (
            "The active model profile is not an embedding profile.",
            false,
        ),
        VectorIndexRuntimeErrorCode::UnsupportedEmbeddingProvider => {
            ("The embedding provider is not supported.", false)
        }
        VectorIndexRuntimeErrorCode::EmbeddingDimensionMismatch => (
            "The embedding dimension does not match the configured vector space.",
            true,
        ),
        VectorIndexRuntimeErrorCode::VectorStoreUnavailable => {
            ("The derived vector index store is unavailable.", true)
        }
        VectorIndexRuntimeErrorCode::RebuildAlreadyRunning => {
            ("A rebuild is already running for this life.", true)
        }
        VectorIndexRuntimeErrorCode::RebuildCancelled => {
            ("The vector index rebuild was cancelled.", true)
        }
        VectorIndexRuntimeErrorCode::RebuildFailed => ("The vector index rebuild failed.", true),
        VectorIndexRuntimeErrorCode::JobNotFound => ("The vector index job was not found.", true),
    };
    VectorIndexRuntimeError {
        code,
        message: message.to_string(),
        recoverable,
    }
}

fn generate_job_id(sequence: &AtomicU64) -> VectorIndexJobId {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or_default();
    let sequence = sequence.fetch_add(1, Ordering::Relaxed);
    VectorIndexJobId(format!("vector-index-{millis:032x}-{sequence:016x}"))
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
            ConfirmMemoryRequest, CreateMemoryCandidateRequest, MemoryKind, MemoryService,
            MemorySourceType,
        },
        model::profile::{
            CreateModelProfileRequest, ModelProfileService, ModelProviderKind,
            SetActiveModelProfileRequest,
        },
        secrets::{InMemorySecretStore, SecretValue},
        storage::{LifeIdentityRecord, PersonaTemplateRecord},
    };

    use super::*;

    struct TestServer {
        base_url: String,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl TestServer {
        fn embeddings(response: &'static str) -> Self {
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
                read_request(&mut stream);
                let reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response.len(),
                    response
                );
                stream.write_all(reply.as_bytes()).unwrap();
            });
            Self {
                base_url: format!("http://{address}/v1"),
                handle: Some(handle),
            }
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
                id: "persona-a".into(),
                name: "Test persona".into(),
                version: 1,
                persona_json: "{\"id\":\"persona-a\"}".into(),
            })
            .unwrap();
        storage
            .save_life(LifeIdentityRecord {
                id: "life-a".into(),
                name: "Test life".into(),
                created_at: "2026-07-13T00:00:00Z".into(),
                version: 1,
                body_id: "test-body".into(),
                persona_id: "persona-a".into(),
                persona_version: 1,
            })
            .unwrap();
        (temp, storage)
    }

    fn active_embedding_profile(
        storage: &StorageService,
        base_url: &str,
        dimension: u32,
    ) -> String {
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
                embedding_dimension: Some(dimension),
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

    fn create_memory(storage: &StorageService, status: MemoryStatus, sensitive: bool) {
        let service = MemoryService::new(storage);
        let memory = service
            .create_candidate(CreateMemoryCandidateRequest {
                life_id: "life-a".into(),
                kind: MemoryKind::Fact,
                content: "temporary authoritative memory".into(),
                summary: Some("temporary summary".into()),
                source_type: MemorySourceType::Manual,
                source_ref: None,
                source_created_at: "2026-07-13T00:00:00Z".into(),
                importance: 0.5,
                confidence: 0.9,
                is_sensitive: sensitive,
            })
            .unwrap();
        if status == MemoryStatus::Confirmed {
            service
                .confirm(ConfirmMemoryRequest {
                    life_id: "life-a".into(),
                    memory_id: memory.id,
                    user_confirmed: true,
                    sensitive_consent: sensitive,
                })
                .unwrap();
        }
    }

    struct NeverCancel;

    impl MemoryRebuildObserver for NeverCancel {
        fn is_cancelled(&self) -> bool {
            false
        }

        fn on_progress(&self, _progress: MemoryRebuildProgress) {}
    }

    #[test]
    fn coordinator_rejects_same_life_and_allows_different_lives() {
        let jobs = MemoryVectorIndexRuntimeCoordinator::default();
        let first = jobs.start_job("life-a".into()).unwrap();
        assert_eq!(
            jobs.start_job("life-a".into()).unwrap_err().code,
            VectorIndexRuntimeErrorCode::RebuildAlreadyRunning
        );
        assert!(jobs.start_job("life-b".into()).is_ok());
        jobs.finish(
            &first,
            VectorIndexJobStatus::Cancelled,
            None,
            Some(runtime_error(VectorIndexRuntimeErrorCode::RebuildCancelled)),
        );
        assert!(jobs.start_job("life-a".into()).is_ok());
    }

    #[test]
    fn cancellation_is_single_use_and_never_completes_job() {
        let jobs = MemoryVectorIndexRuntimeCoordinator::default();
        let job = jobs.start_job("life-a".into()).unwrap();
        jobs.cancel_job(&job).unwrap();
        assert_eq!(
            jobs.cancel_job(&job).unwrap_err().code,
            VectorIndexRuntimeErrorCode::RebuildCancelled
        );
        jobs.finish(
            &job,
            VectorIndexJobStatus::Cancelled,
            None,
            Some(runtime_error(VectorIndexRuntimeErrorCode::RebuildCancelled)),
        );
        assert_eq!(
            jobs.get_job(&job).unwrap().status,
            VectorIndexJobStatus::Cancelled
        );
    }

    #[test]
    fn public_job_payload_has_no_sensitive_fields() {
        let jobs = MemoryVectorIndexRuntimeCoordinator::default();
        let job = jobs.start_job("life-a".into()).unwrap();
        let json = serde_json::to_value(jobs.get_job(&job).unwrap()).unwrap();
        let text = json.to_string().to_ascii_lowercase();
        assert!(!text.contains("apikey"));
        assert!(!text.contains("content"));
        assert!(!json["progress"]
            .as_object()
            .unwrap()
            .contains_key("vectors"));
        assert!(!text.contains("credential"));
    }

    #[test]
    fn request_dtos_reject_model_and_path_overrides() {
        assert!(
            serde_json::from_str::<StartMemoryVectorIndexRebuildRequest>(
                r#"{"lifeId":"life-a","modelName":"forbidden"}"#
            )
            .is_err()
        );
        assert!(serde_json::from_str::<MemoryVectorIndexStatusRequest>(
            r#"{"lifeId":"life-a","path":"C:/forbidden"}"#
        )
        .is_err());
    }

    #[test]
    fn missing_active_profile_fails_without_creating_vector_directory() {
        let (temp, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let runtime = ModelRuntimeCoordinator::default();
        let service =
            MemoryVectorIndexRuntimeService::new(&storage, &storage, &secrets, &storage, &runtime);
        let error =
            tauri::async_runtime::block_on(service.rebuild("life-a", &NeverCancel)).unwrap_err();
        assert_eq!(
            error.code,
            VectorIndexRuntimeErrorCode::NoActiveEmbeddingProfile
        );
        assert!(!temp.path().join("data/vectors/lancedb").exists());
    }

    #[test]
    fn chat_credential_is_not_accepted_for_embedding() {
        let (temp, storage) = test_storage();
        let profile_id = active_embedding_profile(&storage, "http://127.0.0.1:9/v1", 3);
        let secrets = InMemorySecretStore::new();
        secrets
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::ChatModelApiKey, profile_id).unwrap(),
                SecretValue::new("test-placeholder".into()).unwrap(),
            )
            .unwrap();
        let runtime = ModelRuntimeCoordinator::default();
        let service =
            MemoryVectorIndexRuntimeService::new(&storage, &storage, &secrets, &storage, &runtime);
        let error =
            tauri::async_runtime::block_on(service.rebuild("life-a", &NeverCancel)).unwrap_err();
        assert_eq!(
            error.code,
            VectorIndexRuntimeErrorCode::EmbeddingCredentialNotFound
        );
        assert!(!temp.path().join("data/vectors/lancedb").exists());
    }

    #[test]
    fn status_query_does_not_create_index_or_call_provider() {
        let (temp, storage) = test_storage();
        let profile_id = active_embedding_profile(&storage, "http://127.0.0.1:9/v1", 3);
        let secrets = InMemorySecretStore::new();
        secrets
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, profile_id).unwrap(),
                SecretValue::new("test-placeholder".into()).unwrap(),
            )
            .unwrap();
        create_memory(&storage, MemoryStatus::Confirmed, false);
        let runtime = ModelRuntimeCoordinator::default();
        let jobs = MemoryVectorIndexRuntimeCoordinator::default();
        let service =
            MemoryVectorIndexRuntimeService::new(&storage, &storage, &secrets, &storage, &runtime);
        let status = tauri::async_runtime::block_on(service.status("life-a", &jobs)).unwrap();
        assert!(status.active_embedding_profile_exists);
        assert!(status.credential_exists);
        assert_eq!(status.eligible_memory_count, 1);
        assert!(!status.index_directory_exists);
        assert!(!temp.path().join("data/vectors/lancedb").exists());
    }

    #[test]
    fn runtime_rebuild_indexes_only_confirmed_non_sensitive_memory() {
        let server = TestServer::embeddings(
            r#"{"model":"test-embedding-model","data":[{"index":0,"embedding":[1.0,0.0,0.0]}],"usage":{"prompt_tokens":2,"total_tokens":2}}"#,
        );
        let (temp, storage) = test_storage();
        let profile_id = active_embedding_profile(&storage, &server.base_url, 3);
        let secrets = InMemorySecretStore::new();
        secrets
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, profile_id).unwrap(),
                SecretValue::new("test-placeholder".into()).unwrap(),
            )
            .unwrap();
        create_memory(&storage, MemoryStatus::Confirmed, false);
        create_memory(&storage, MemoryStatus::Candidate, false);
        create_memory(&storage, MemoryStatus::Confirmed, true);
        let runtime = ModelRuntimeCoordinator::default();
        let service =
            MemoryVectorIndexRuntimeService::new(&storage, &storage, &secrets, &storage, &runtime);
        let report =
            tauri::async_runtime::block_on(service.rebuild("life-a", &NeverCancel)).unwrap();
        assert!(report.completed);
        assert_eq!(report.scanned_count, 3);
        assert_eq!(report.eligible_count, 1);
        assert_eq!(report.indexed_count, 1);
        assert_eq!(report.skipped_candidate_count, 1);
        assert_eq!(report.skipped_sensitive_count, 1);
        assert!(temp.path().join("data/vectors/lancedb").is_dir());
    }
}
