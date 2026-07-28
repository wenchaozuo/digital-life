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
    embedding::{EmbeddingProvider, EmbeddingPurpose, EmbeddingRequest},
    model::transport::http1::SendDisposition,
    model::{
        profile::ModelProfileRepository,
        runtime::{ModelRuntimeCoordinator, ModelRuntimeErrorCode, ModelRuntimeService},
    },
    secrets::{SecretStore, WindowsCredentialSecretStore},
    storage::{FencedFinalizeResult, FencedVectorSyncClaim, StorageService},
    vector_store::{
        GenerationVectorRecord, LanceDbVectorStoreRegistry, VectorGenerationContext, VectorStore,
        VectorStoreErrorCode,
    },
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

#[cfg(test)]
static STOP_AFTER_LANCE_UPSERT_FOR_TEST: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
fn stop_after_lance_upsert_for_test() -> bool {
    STOP_AFTER_LANCE_UPSERT_FOR_TEST.swap(false, Ordering::AcqRel)
}

#[cfg(test)]
fn set_stop_after_lance_upsert_for_test() {
    STOP_AFTER_LANCE_UPSERT_FOR_TEST.store(true, Ordering::Release);
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VectorSyncTestPausePoint {
    BeforeEmbedding,
    AfterEmbeddingBeforeLance,
    AfterLanceBeforeFinalize,
}

#[cfg(test)]
type TestPauseHookFn = Box<dyn Fn(VectorSyncTestPausePoint) + Send + Sync>;

#[cfg(test)]
static TEST_PAUSE_HOOK: std::sync::Mutex<Option<Arc<TestPauseHookFn>>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
pub(crate) fn set_test_pause_hook(hook: Option<Arc<TestPauseHookFn>>) {
    let mut guard = TEST_PAUSE_HOOK.lock().unwrap();
    *guard = hook;
}

#[cfg(test)]
async fn check_test_pause_point(point: VectorSyncTestPausePoint) {
    let hook = {
        let guard = TEST_PAUSE_HOOK.lock().unwrap();
        guard.clone()
    };
    if let Some(hook) = hook {
        hook(point);
    }
}

/// One explicit D-9D1 outbox operation.  This is deliberately separate from
/// the legacy life-scoped drain worker: it has no loop, no profile discovery,
/// and no authority write transaction around embedding or LanceDB I/O.
#[allow(dead_code)]
pub(crate) struct FencedVectorSyncSingleEventConsumer<'a> {
    storage: &'a StorageService,
    embedding: &'a dyn EmbeddingProvider,
    vectors: &'a dyn VectorStore,
    generation: VectorGenerationContext,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum FencedVectorSyncSingleEventResult {
    NoEligibleEvent,
    Completed,
    Stale,
    RetryWait,
    Blocked,
    LostLeaseOrSuperseded,
}

#[allow(dead_code)]
impl<'a> FencedVectorSyncSingleEventConsumer<'a> {
    pub(crate) fn new(
        storage: &'a StorageService,
        embedding: &'a dyn EmbeddingProvider,
        vectors: &'a dyn VectorStore,
        generation: VectorGenerationContext,
    ) -> Self {
        Self {
            storage,
            embedding,
            vectors,
            generation,
        }
    }

    pub(crate) async fn process_one(
        &self,
        lease_owner: &str,
    ) -> Result<FencedVectorSyncSingleEventResult, MemoryVectorSyncWorkerError> {
        let claim = self
            .storage
            .claim_one_fenced_vector_sync(
                self.generation.generation_id().as_str(),
                self.generation.descriptor_hash(),
                self.generation.dimension(),
                lease_owner,
            )
            .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?;
        let Some(claim) = claim else {
            return Ok(FencedVectorSyncSingleEventResult::NoEligibleEvent);
        };
        self.execute_claim(claim).await
    }

    async fn execute_claim(
        &self,
        claim: FencedVectorSyncClaim,
    ) -> Result<FencedVectorSyncSingleEventResult, MemoryVectorSyncWorkerError> {
        match claim.action() {
            MemoryVectorSyncAction::Delete => {
                if !self
                    .storage
                    .fenced_vector_claim_is_current(&claim)
                    .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
                {
                    return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
                }
                if !self
                    .storage
                    .mark_fenced_attempt_started(&claim)
                    .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
                {
                    return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
                }
                let outcome = self
                    .vectors
                    .delete_generation_memory(&self.generation, claim.life_id(), claim.memory_id())
                    .await;
                match outcome {
                    Ok(()) => self.finalize(&claim, None, None, false, None),
                    Err(error) if error.code == VectorStoreErrorCode::VectorNotFound => {
                        self.finalize(&claim, None, None, false, None)
                    }
                    Err(_) => {
                        self.finalize(&claim, None, Some("VECTOR_STORE_UNAVAILABLE"), true, None)
                    }
                }
            }
            MemoryVectorSyncAction::Upsert => {
                let Some(document) =
                    self.storage
                        .read_fenced_vector_document(&claim)
                        .map_err(|_| {
                            worker_error(MemoryVectorSyncWorkerErrorCode::RepositoryUnavailable)
                        })?
                else {
                    return self
                        .finalize(&claim, None, Some("VECTOR_TARGET_STALE"), false, None)
                        .map(|_| FencedVectorSyncSingleEventResult::Stale);
                };
                #[cfg(test)]
                check_test_pause_point(VectorSyncTestPausePoint::BeforeEmbedding).await;
                if !self
                    .storage
                    .fenced_vector_claim_is_current(&claim)
                    .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
                {
                    return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
                }
                if !self
                    .storage
                    .mark_fenced_attempt_started(&claim)
                    .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
                {
                    return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
                }
                let response = self
                    .embedding
                    .embed(EmbeddingRequest {
                        texts: vec![document],
                        purpose: EmbeddingPurpose::Document,
                    })
                    .await;
                #[cfg(test)]
                check_test_pause_point(VectorSyncTestPausePoint::AfterEmbeddingBeforeLance).await;
                let batch = match response {
                    Ok(batch) => batch,
                    Err(error) => {
                        return self.finalize(
                            &claim,
                            None,
                            Some(embedding_error_code(error.code())),
                            error.is_recoverable(),
                            Some(send_disposition_code(error.send_disposition())),
                        )
                    }
                };
                let vector = batch.vectors().first().filter(|v| {
                    batch.len() == 1
                        && v.input_index() == 0
                        && v.dimension() == self.generation.dimension()
                });
                let Some(vector) = vector else {
                    return self.finalize(
                        &claim,
                        None,
                        Some("INVALID_PROVIDER_RESPONSE"),
                        false,
                        None,
                    );
                };
                let Some(target_revision) = claim.target_revision() else {
                    return self.finalize(
                        &claim,
                        None,
                        Some("VECTOR_TARGET_BINDING_MISSING"),
                        false,
                        None,
                    );
                };
                let Some(target_content_hash) = claim.target_content_hash() else {
                    return self.finalize(
                        &claim,
                        None,
                        Some("VECTOR_TARGET_BINDING_MISSING"),
                        false,
                        None,
                    );
                };
                let record = GenerationVectorRecord::try_new(
                    self.generation.generation_id().clone(),
                    claim.life_id(),
                    claim.memory_id(),
                    target_revision,
                    target_content_hash,
                    self.generation.descriptor_hash(),
                    vector.values().to_vec(),
                );
                let record = match record {
                    Ok(record) => record,
                    Err(_) => {
                        return self.finalize(
                            &claim,
                            None,
                            Some("INVALID_PROVIDER_RESPONSE"),
                            false,
                            None,
                        )
                    }
                };
                if !self
                    .storage
                    .fenced_vector_claim_is_current(&claim)
                    .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
                {
                    return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
                }
                match self
                    .vectors
                    .upsert_generation(&self.generation, record)
                    .await
                {
                    Ok(()) => {
                        #[cfg(test)]
                        if stop_after_lance_upsert_for_test() {
                            return Err(worker_error(
                                MemoryVectorSyncWorkerErrorCode::InternalError,
                            ));
                        }
                        #[cfg(test)]
                        check_test_pause_point(VectorSyncTestPausePoint::AfterLanceBeforeFinalize)
                            .await;
                        self.finalize(&claim, claim.target_content_hash(), None, false, None)
                    }
                    Err(_) => {
                        self.finalize(&claim, None, Some("VECTOR_STORE_UNAVAILABLE"), true, None)
                    }
                }
            }
        }
    }

    fn finalize(
        &self,
        claim: &FencedVectorSyncClaim,
        hash: Option<&str>,
        error: Option<&str>,
        retry: bool,
        send_disposition: Option<&str>,
    ) -> Result<FencedVectorSyncSingleEventResult, MemoryVectorSyncWorkerError> {
        let result = self
            .storage
            .finalize_fenced_vector_sync(claim, hash, error, retry, send_disposition)
            .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?;
        Ok(match result {
            FencedFinalizeResult::LostLeaseOrSuperseded => {
                FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded
            }
            FencedFinalizeResult::Applied if error.is_some() && retry => {
                FencedVectorSyncSingleEventResult::RetryWait
            }
            FencedFinalizeResult::Applied if error.is_some() => {
                FencedVectorSyncSingleEventResult::Blocked
            }
            FencedFinalizeResult::Applied => FencedVectorSyncSingleEventResult::Completed,
        })
    }
}

#[allow(dead_code)]
fn embedding_error_code(code: crate::embedding::EmbeddingErrorCode) -> &'static str {
    use crate::embedding::EmbeddingErrorCode::*;
    match code {
        AuthenticationFailed => "AUTHENTICATION_FAILED",
        RateLimited => "RATE_LIMITED",
        RequestTimeout => "REQUEST_TIMEOUT",
        NetworkError => "NETWORK_UNAVAILABLE",
        InvalidProviderResponse | DimensionMismatch => "INVALID_PROVIDER_RESPONSE",
        InvalidRequest | EmptyText | BatchLimitExceeded | TextLimitExceeded => "INVALID_REQUEST",
    }
}

fn send_disposition_code(disposition: SendDisposition) -> &'static str {
    match disposition {
        SendDisposition::DefinitelyNotSent => "definitely_not_sent",
        SendDisposition::PossiblySent => "possibly_sent",
    }
}

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
    use crate::{
        memory::{
            revisions::{DeleteMemoryPermanentlyRequest, MemoryRevisionService},
            vector_sync_outbox::EnqueueMemoryVectorSyncRequest,
        },
        model::profile::{
            CreateModelProfileRequest, ModelProfile, ModelProfileService, ModelProviderKind,
            ModelPurpose, SetActiveModelProfileRequest,
        },
        secrets::{InMemorySecretStore, SecretIdentifier, SecretPurpose, SecretStore, SecretValue},
        storage::{LifeIdentityRecord, PersonaTemplateRecord},
    };
    use std::{io::Read, net::TcpListener, thread};

    use super::*;

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

    fn confirmed(storage: &StorageService, sensitive: bool) -> super::super::MemoryRecord {
        crate::storage::test_support::insert_confirmed_memory_fixture(
            storage,
            "life",
            "fact",
            "temporary worker fixture",
            Some("worker summary"),
            0.5,
            0.8,
            sensitive,
            !sensitive,
        )
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
    fn after_lance_test_failpoint_is_one_shot_and_test_only() {
        let _hook_guard = TEST_HOOK_MUTEX.lock().unwrap();
        set_stop_after_lance_upsert_for_test();
        assert!(stop_after_lance_upsert_for_test());
        assert!(!stop_after_lance_upsert_for_test());
    }

    #[test]
    fn worker_persists_real_definitely_not_sent_from_embedding_provider() {
        let (_temp, storage) = test_storage();
        confirmed(&storage, false);
        let descriptor = "a".repeat(64);
        storage
            .register_building_vector_generation("gen-dnf", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-dnf").unwrap(),
            descriptor,
            3,
        )
        .unwrap();
        let vectors = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(vectors.create_generation(&context)).unwrap();
        let profile = ModelProfile {
            id: "profile-dnf".into(),
            purpose: ModelPurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "test".into(),
            base_url: "http://127.0.0.1:9/v1".into(),
            model_name: "test-embedding-model".into(),
            temperature: None,
            max_tokens: None,
            embedding_dimension: Some(3),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let secrets = InMemorySecretStore::new();
        let provider =
            crate::embedding::build_openai_compatible_embedding_provider(&profile, &secrets)
                .unwrap();
        let consumer = FencedVectorSyncSingleEventConsumer::new(
            &storage,
            provider.as_ref(),
            &vectors,
            context,
        );
        let result = tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap();
        assert_eq!(result, FencedVectorSyncSingleEventResult::Blocked);
        let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
        assert_eq!(
            row,
            (
                1,
                Some("definitely_not_sent".into()),
                "AUTHENTICATION_FAILED".into()
            )
        );
    }

    #[test]
    fn worker_persists_real_possibly_sent_from_loopback_transport() {
        let (_temp, storage) = test_storage();
        confirmed(&storage, false);
        let descriptor = "b".repeat(64);
        storage
            .register_building_vector_generation("gen-ps", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-ps").unwrap(),
            descriptor,
            3,
        )
        .unwrap();
        let vectors = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(vectors.create_generation(&context)).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 2048];
            let _ = stream.read(&mut buffer);
        });
        let profile = ModelProfile {
            id: "profile-ps".into(),
            purpose: ModelPurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "test".into(),
            base_url: format!("http://127.0.0.1:{port}/v1"),
            model_name: "test-embedding-model".into(),
            temperature: None,
            max_tokens: None,
            embedding_dimension: Some(3),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let secrets = InMemorySecretStore::new();
        secrets
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, profile.id.clone())
                    .unwrap(),
                SecretValue::new("test-placeholder".into()).unwrap(),
            )
            .unwrap();
        let provider =
            crate::embedding::build_openai_compatible_embedding_provider(&profile, &secrets)
                .unwrap();
        let consumer = FencedVectorSyncSingleEventConsumer::new(
            &storage,
            provider.as_ref(),
            &vectors,
            context,
        );
        let result = tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap();
        server.join().unwrap();
        assert_eq!(result, FencedVectorSyncSingleEventResult::RetryWait);
        let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
        assert_eq!(row.0, 1);
        assert_eq!(row.1.as_deref(), Some("possibly_sent"));
        assert_eq!(row.2, "NETWORK_UNAVAILABLE");
    }

    #[test]
    fn lance_success_before_finalize_recovers_idempotently() {
        let _hook_guard = TEST_HOOK_MUTEX.lock().unwrap();
        let (temp, storage) = test_storage();
        confirmed(&storage, false);
        let descriptor = "c".repeat(64);
        storage
            .register_building_vector_generation("gen-crash", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-crash").unwrap(),
            descriptor,
            3,
        )
        .unwrap();
        let vectors = tauri::async_runtime::block_on(
            crate::vector_store::LanceDbVectorStore::open(temp.path().join("lance")),
        )
        .unwrap();
        tauri::async_runtime::block_on(vectors.create_generation(&context)).unwrap();
        let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let consumer = FencedVectorSyncSingleEventConsumer::new(
            &storage,
            &provider,
            &vectors,
            context.clone(),
        );
        set_stop_after_lance_upsert_for_test();
        let error = tauri::async_runtime::block_on(consumer.process_one("owner-a")).unwrap_err();
        assert_eq!(error.code, MemoryVectorSyncWorkerErrorCode::InternalError);
        assert_eq!(
            storage.test_fenced_completion_snapshot().unwrap(),
            ("processing".into(), 1, 0)
        );
        assert_eq!(
            tauri::async_runtime::block_on(vectors.count_generation(&context, Some("life")))
                .unwrap(),
            1
        );
        storage.test_expire_fenced_runtime_lease().unwrap();
        let result = tauri::async_runtime::block_on(consumer.process_one("owner-b")).unwrap();
        assert_eq!(result, FencedVectorSyncSingleEventResult::Completed);
        assert_eq!(
            tauri::async_runtime::block_on(vectors.count_generation(&context, Some("life")))
                .unwrap(),
            1
        );
        assert!(storage.list("life").unwrap().is_empty());
    }

    #[test]
    fn legacy_worker_never_resolves_profile_or_credential_for_post_012_outbox() {
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
        .unwrap();
        assert!(result.is_none());
        assert_eq!(
            storage.list("life").unwrap()[0].state,
            MemoryVectorSyncState::Pending
        );
        assert_eq!(storage.list("life").unwrap()[0].attempt_count, 0);

        let profile = activate_profile(&storage, "http://127.0.0.1:9/v1");
        secret(&secrets, profile, SecretPurpose::ChatModelApiKey);
        let result = tauri::async_runtime::block_on(worker.process_next(
            "life",
            "worker",
            MemoryVectorSyncWorkerConfig::default(),
        ))
        .unwrap();
        assert!(result.is_none());
        assert_eq!(
            storage.list("life").unwrap()[0].state,
            MemoryVectorSyncState::Pending
        );
    }

    #[test]
    fn legacy_worker_never_calls_provider_or_creates_a_legacy_index() {
        let (temp, storage) = test_storage();
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
        .unwrap();
        assert!(result.is_none());
        assert_eq!(storage.list("life").unwrap().len(), 1);
        assert!(!temp.path().join("data/vectors/lancedb").exists());
    }

    #[test]
    fn legacy_worker_drain_leaves_post_012_jobs_untouched() {
        let (temp, storage) = test_storage();
        storage.set_vector_sync_enabled("life", true).unwrap();
        // Sensitive confirmed — manually enqueue upsert (fixture skips outbox for sensitive).
        let sensitive = confirmed(&storage, true);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: sensitive.id,
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        // Non-sensitive confirmed — delete creates outbox delete entry.
        let deleted = confirmed(&storage, false);
        MemoryRevisionService::new(&storage)
            .delete_permanently(DeleteMemoryPermanentlyRequest {
                life_id: "life".into(),
                memory_id: deleted.id.clone(),
                expected_revision: 1,
            })
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
        assert!(results.is_empty());
        assert_eq!(storage.list("life").unwrap().len(), 2);
        assert!(!temp.path().join("data/vectors/lancedb").exists());
    }

    #[test]
    fn legacy_worker_never_starts_an_external_attempt() {
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
        .unwrap();
        assert!(result.is_none());
        let job = storage.list("life").unwrap().remove(0);
        assert_eq!(job.state, MemoryVectorSyncState::Pending);
        assert_eq!(job.attempt_count, 0);
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

    use crate::embedding::{EmbeddingBatch, EmbeddingError, EmbeddingFuture, EmbeddingModelInfo};
    use crate::vector_store::{
        VectorRecord, VectorSearchHit, VectorSearchQuery, VectorSpace, VectorStoreError,
        VectorStoreFuture,
    };
    use std::sync::atomic::AtomicUsize;

    struct CountingEmbeddingProvider<'a> {
        inner: &'a dyn EmbeddingProvider,
        provider_requests: Arc<AtomicUsize>,
        embedding_successes: Arc<AtomicUsize>,
    }

    impl EmbeddingProvider for CountingEmbeddingProvider<'_> {
        fn model_info(&self) -> EmbeddingModelInfo {
            self.inner.model_info()
        }

        fn model_name(&self) -> &str {
            self.inner.model_name()
        }

        fn vector_dimension(&self) -> Option<usize> {
            self.inner.vector_dimension()
        }

        fn max_batch_size(&self) -> usize {
            self.inner.max_batch_size()
        }

        fn embed<'a>(
            &'a self,
            request: EmbeddingRequest,
        ) -> EmbeddingFuture<'a, Result<EmbeddingBatch, EmbeddingError>> {
            self.provider_requests.fetch_add(1, Ordering::SeqCst);
            let successes = Arc::clone(&self.embedding_successes);
            let fut = self.inner.embed(request);
            Box::pin(async move {
                let res = fut.await;
                if res.is_ok() {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
                res
            })
        }
    }

    struct CountingVectorStore<V> {
        inner: V,
        lance_upserts: Arc<AtomicUsize>,
        lance_deletes: Arc<AtomicUsize>,
    }

    impl<V: VectorStore> VectorStore for CountingVectorStore<V> {
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

        fn create_generation<'a>(
            &'a self,
            context: &'a VectorGenerationContext,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.inner.create_generation(context)
        }

        fn upsert_generation<'a>(
            &'a self,
            context: &'a VectorGenerationContext,
            record: GenerationVectorRecord,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.lance_upserts.fetch_add(1, Ordering::SeqCst);
            self.inner.upsert_generation(context, record)
        }

        fn delete_generation_memory<'a>(
            &'a self,
            context: &'a VectorGenerationContext,
            life_id: &'a str,
            memory_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.lance_deletes.fetch_add(1, Ordering::SeqCst);
            self.inner
                .delete_generation_memory(context, life_id, memory_id)
        }

        fn delete_generation_life<'a>(
            &'a self,
            context: &'a VectorGenerationContext,
            life_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.inner.delete_generation_life(context, life_id)
        }

        fn count_generation<'a>(
            &'a self,
            context: &'a VectorGenerationContext,
            life_id: Option<&'a str>,
        ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
            self.inner.count_generation(context, life_id)
        }
    }

    struct CountingSecretStore<S> {
        inner: S,
        credential_reads: Arc<AtomicUsize>,
    }

    impl<S> CountingSecretStore<S> {
        fn new(inner: S, credential_reads: Arc<AtomicUsize>) -> Self {
            Self {
                inner,
                credential_reads,
            }
        }
    }

    impl<S: SecretStore> SecretStore for CountingSecretStore<S> {
        fn set_secret(
            &self,
            id: &SecretIdentifier,
            value: crate::secrets::SecretValue,
        ) -> Result<crate::secrets::SecretStatus, crate::secrets::SecretStoreError> {
            self.inner.set_secret(id, value)
        }

        fn get_secret(
            &self,
            id: &SecretIdentifier,
        ) -> Result<crate::secrets::SecretValue, crate::secrets::SecretStoreError> {
            self.credential_reads.fetch_add(1, Ordering::SeqCst);
            self.inner.get_secret(id)
        }

        fn has_secret(
            &self,
            id: &SecretIdentifier,
        ) -> Result<bool, crate::secrets::SecretStoreError> {
            self.inner.has_secret(id)
        }

        fn delete_secret(
            &self,
            id: &SecretIdentifier,
        ) -> Result<crate::secrets::SecretStatus, crate::secrets::SecretStoreError> {
            self.inner.delete_secret(id)
        }
    }

    static TEST_HOOK_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn fence_lost_before_embedding_has_zero_io() {
        let _hook_guard = TEST_HOOK_MUTEX.lock().unwrap();
        let (_temp, storage) = test_storage();
        let storage = Arc::new(storage);
        confirmed(&storage, false);
        let descriptor = "a".repeat(64);
        storage
            .register_building_vector_generation("gen-pa", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-pa").unwrap(),
            descriptor.clone(),
            3,
        )
        .unwrap();

        let raw_vectors = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vectors.create_generation(&context)).unwrap();

        let lance_upserts = Arc::new(AtomicUsize::new(0));
        let lance_deletes = Arc::new(AtomicUsize::new(0));
        let vectors = CountingVectorStore {
            inner: raw_vectors,
            lance_upserts: Arc::clone(&lance_upserts),
            lance_deletes: Arc::clone(&lance_deletes),
        };

        let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let provider_requests = Arc::new(AtomicUsize::new(0));
        let embedding_successes = Arc::new(AtomicUsize::new(0));
        let provider = CountingEmbeddingProvider {
            inner: &raw_provider,
            provider_requests: Arc::clone(&provider_requests),
            embedding_successes: Arc::clone(&embedding_successes),
        };

        let raw_secrets = InMemorySecretStore::new();
        let credential_reads = Arc::new(AtomicUsize::new(0));
        let _secrets = CountingSecretStore::new(raw_secrets, Arc::clone(&credential_reads));

        let claim_b_slot = Arc::new(std::sync::Mutex::new(None));
        let snap_b_takeover_slot = Arc::new(std::sync::Mutex::new(None));
        let claim_b_slot_clone = Arc::clone(&claim_b_slot);
        let snap_b_takeover_slot_clone = Arc::clone(&snap_b_takeover_slot);
        let storage_clone = Arc::clone(&storage);
        let context_clone = context.clone();
        set_test_pause_hook(Some(Arc::new(Box::new(move |point| {
            if point == VectorSyncTestPausePoint::BeforeEmbedding {
                storage_clone.test_expire_fenced_runtime_lease().unwrap();
                let cb = storage_clone
                    .claim_one_fenced_vector_sync(
                        context_clone.generation_id().as_str(),
                        context_clone.descriptor_hash(),
                        context_clone.dimension(),
                        "worker-b",
                    )
                    .unwrap()
                    .expect("worker-b claim must succeed");
                let snap = storage_clone
                    .test_get_outbox_snapshot_detailed("life", cb.memory_id())
                    .unwrap();
                *snap_b_takeover_slot_clone.lock().unwrap() = Some(snap);
                *claim_b_slot_clone.lock().unwrap() = Some(cb);
            }
        }))));

        let consumer = FencedVectorSyncSingleEventConsumer::new(
            storage.as_ref(),
            &provider,
            &vectors,
            context.clone(),
        );

        let result = tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap();
        set_test_pause_hook(None);

        assert_eq!(
            result,
            FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded
        );
        assert_eq!(provider_requests.load(Ordering::SeqCst), 0);
        assert_eq!(credential_reads.load(Ordering::SeqCst), 0);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 0);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);
        assert_eq!(storage.test_generation_item_count().unwrap(), 0);

        let claim_b = claim_b_slot.lock().unwrap().take().unwrap();
        let snap_b_takeover = snap_b_takeover_slot.lock().unwrap().take().unwrap();
        let snap_after_worker_a = storage
            .test_get_outbox_snapshot_detailed("life", claim_b.memory_id())
            .unwrap();
        assert_eq!(
            snap_b_takeover, snap_after_worker_a,
            "Phase A: Worker A produced ZERO side-effects on Outbox snapshot"
        );

        let result_b = tauri::async_runtime::block_on(consumer.execute_claim(claim_b)).unwrap();
        assert_eq!(result_b, FencedVectorSyncSingleEventResult::Completed);
        assert_eq!(storage.test_generation_item_count().unwrap(), 1);
    }

    #[test]
    fn fence_lost_after_embedding_before_lance_has_zero_lance_writes() {
        let _hook_guard = TEST_HOOK_MUTEX.lock().unwrap();
        let (_temp, storage) = test_storage();
        let storage = Arc::new(storage);
        confirmed(&storage, false);
        let descriptor = "b".repeat(64);
        storage
            .register_building_vector_generation("gen-pb", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-pb").unwrap(),
            descriptor.clone(),
            3,
        )
        .unwrap();

        let raw_vectors = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vectors.create_generation(&context)).unwrap();

        let lance_upserts = Arc::new(AtomicUsize::new(0));
        let lance_deletes = Arc::new(AtomicUsize::new(0));
        let vectors = CountingVectorStore {
            inner: raw_vectors,
            lance_upserts: Arc::clone(&lance_upserts),
            lance_deletes: Arc::clone(&lance_deletes),
        };

        // Real D-8 Loopback HTTP Server
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let provider_requests = Arc::new(AtomicUsize::new(0));
        let transport_requests = Arc::new(AtomicUsize::new(0));
        let transport_requests_clone = Arc::clone(&transport_requests);

        let server_handle = std::thread::spawn(move || {
            use std::io::{Read, Write};
            for _ in 0..2 {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let mut buffer = [0_u8; 2048];
                let _ = stream.read(&mut buffer);
                transport_requests_clone.fetch_add(1, Ordering::SeqCst);
                let body = r#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]}],"model":"test-embedding-model","usage":{"prompt_tokens":1,"total_tokens":1}}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });

        let profile = ModelProfile {
            id: "profile-pb".into(),
            purpose: ModelPurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "Phase B Loopback".into(),
            base_url: format!("http://127.0.0.1:{port}/v1"),
            model_name: "test-embedding-model".into(),
            temperature: None,
            max_tokens: None,
            embedding_dimension: Some(3),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };

        let raw_secrets = InMemorySecretStore::new();
        let secret_id = crate::secrets::SecretIdentifier::new(
            crate::secrets::SecretPurpose::EmbeddingModelApiKey,
            profile.id.clone(),
        )
        .unwrap();
        raw_secrets
            .set_secret(
                &secret_id,
                crate::secrets::SecretValue::new("test-key".into()).unwrap(),
            )
            .unwrap();

        let credential_reads = Arc::new(AtomicUsize::new(0));
        let counting_secrets = CountingSecretStore::new(raw_secrets, Arc::clone(&credential_reads));

        let raw_provider = crate::embedding::build_openai_compatible_embedding_provider(
            &profile,
            &counting_secrets,
        )
        .unwrap();
        let embedding_successes = Arc::new(AtomicUsize::new(0));
        let provider = CountingEmbeddingProvider {
            inner: raw_provider.as_ref(),
            provider_requests: Arc::clone(&provider_requests),
            embedding_successes: Arc::clone(&embedding_successes),
        };

        let claim_b_slot = Arc::new(std::sync::Mutex::new(None));
        let claim_b_slot_clone = Arc::clone(&claim_b_slot);
        let storage_clone = Arc::clone(&storage);
        let context_clone = context.clone();
        set_test_pause_hook(Some(Arc::new(Box::new(move |point| {
            if point == VectorSyncTestPausePoint::AfterEmbeddingBeforeLance {
                storage_clone.test_expire_fenced_runtime_lease().unwrap();
                let cb = storage_clone
                    .claim_one_fenced_vector_sync(
                        context_clone.generation_id().as_str(),
                        context_clone.descriptor_hash(),
                        context_clone.dimension(),
                        "worker-b",
                    )
                    .unwrap()
                    .expect("worker-b claim must succeed");
                *claim_b_slot_clone.lock().unwrap() = Some(cb);
                set_test_pause_hook(None);
            }
        }))));

        let consumer = FencedVectorSyncSingleEventConsumer::new(
            storage.as_ref(),
            &provider,
            &vectors,
            context.clone(),
        );

        let result = tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap();
        set_test_pause_hook(None);

        assert_eq!(
            result,
            FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded
        );
        assert_eq!(credential_reads.load(Ordering::SeqCst), 1);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
        assert_eq!(transport_requests.load(Ordering::SeqCst), 1);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 1);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);
        assert_eq!(storage.test_generation_item_count().unwrap(), 0);

        let claim_b = claim_b_slot.lock().unwrap().take().unwrap();
        let snap_mid = storage
            .test_get_outbox_snapshot_detailed("life", claim_b.memory_id())
            .unwrap();
        assert_eq!(snap_mid.total_count, 1, "Phase B: Outbox event intact");
        assert_eq!(
            snap_mid.state, "processing",
            "Phase B: State remains processing for worker-b"
        );
        assert_eq!(
            snap_mid.lease_owner.as_deref(),
            Some("worker-b"),
            "Phase B: Owner is worker-b"
        );
        assert_eq!(
            snap_mid.last_error_code, None,
            "Phase B: No error code written by old owner"
        );
        assert_eq!(
            snap_mid.last_send_disposition, None,
            "Phase B: No send disposition written by old owner"
        );
        assert_eq!(
            snap_mid.attempt_count, 1,
            "Phase B: attempt_count not extra incremented"
        );

        let result_b = tauri::async_runtime::block_on(consumer.execute_claim(claim_b)).unwrap();
        server_handle.join().unwrap();
        assert_eq!(result_b, FencedVectorSyncSingleEventResult::Completed);
        assert_eq!(storage.test_generation_item_count().unwrap(), 1);
        assert_eq!(credential_reads.load(Ordering::SeqCst), 2);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 2);
        assert_eq!(transport_requests.load(Ordering::SeqCst), 2);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn stale_token_cannot_write_after_lance_and_fence_takeover() {
        let _hook_guard = TEST_HOOK_MUTEX.lock().unwrap();
        let (temp, storage) = test_storage();
        confirmed(&storage, false);
        let descriptor = "c".repeat(64);
        storage
            .register_building_vector_generation("gen-pc", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-pc").unwrap(),
            descriptor.clone(),
            3,
        )
        .unwrap();

        let vectors = tauri::async_runtime::block_on(
            crate::vector_store::LanceDbVectorStore::open(temp.path().join("lance")),
        )
        .unwrap();
        tauri::async_runtime::block_on(vectors.create_generation(&context)).unwrap();

        let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);

        let claim_a = storage
            .claim_one_fenced_vector_sync(
                context.generation_id().as_str(),
                context.descriptor_hash(),
                context.dimension(),
                "worker-a",
            )
            .unwrap()
            .unwrap();

        let doc = storage
            .read_fenced_vector_document(&claim_a)
            .unwrap()
            .unwrap();
        let batch = tauri::async_runtime::block_on(provider.embed(EmbeddingRequest {
            texts: vec![doc],
            purpose: EmbeddingPurpose::Document,
        }))
        .unwrap();
        let vec_vals = batch.vectors()[0].values().to_vec();

        let record = GenerationVectorRecord::try_new(
            context.generation_id().clone(),
            claim_a.life_id(),
            claim_a.memory_id(),
            claim_a.target_revision().unwrap(),
            claim_a.target_content_hash().unwrap(),
            context.descriptor_hash(),
            vec_vals,
        )
        .unwrap();

        tauri::async_runtime::block_on(vectors.upsert_generation(&context, record)).unwrap();
        assert_eq!(
            tauri::async_runtime::block_on(vectors.count_generation(&context, Some("life")))
                .unwrap(),
            1
        );

        storage.test_expire_fenced_runtime_lease().unwrap();
        let claim_b = storage
            .claim_one_fenced_vector_sync(
                context.generation_id().as_str(),
                context.descriptor_hash(),
                context.dimension(),
                "worker-b",
            )
            .unwrap()
            .unwrap();
        assert_ne!(claim_a.fence_epoch(), claim_b.fence_epoch());

        assert!(!storage.mark_fenced_attempt_started(&claim_a).unwrap());
        assert_eq!(
            storage
                .finalize_fenced_vector_sync(
                    &claim_a,
                    claim_a.target_content_hash(),
                    None,
                    false,
                    None
                )
                .unwrap(),
            FencedFinalizeResult::LostLeaseOrSuperseded
        );
        assert_eq!(
            storage
                .finalize_fenced_vector_sync(
                    &claim_a,
                    None,
                    Some("TEST_ERROR"),
                    true,
                    Some("definitely_not_sent")
                )
                .unwrap(),
            FencedFinalizeResult::LostLeaseOrSuperseded
        );

        assert_eq!(storage.test_generation_item_count().unwrap(), 0);
        let snap = storage
            .test_get_outbox_snapshot_detailed("life", claim_a.memory_id())
            .unwrap();
        assert_eq!(snap.total_count, 1);
        assert_eq!(snap.state, "processing");
        assert_eq!(snap.lease_owner.as_deref(), Some("worker-b"));
        assert_eq!(snap.attempt_count, 0);
        assert_eq!(snap.last_error_code, None);
        assert_eq!(snap.last_send_disposition, None);
        assert_eq!(snap.mutation_sequence, claim_a.mutation_sequence());
        assert_eq!(snap.desired_action, "upsert");
        assert_eq!(snap.target_revision, claim_a.target_revision());
        assert_eq!(
            snap.target_content_hash.as_deref(),
            claim_a.target_content_hash()
        );
        assert_eq!(snap.claimed_generation_id.as_deref(), Some("gen-pc"));

        let consumer_b = FencedVectorSyncSingleEventConsumer::new(
            &storage,
            &provider,
            &vectors,
            context.clone(),
        );
        let res = tauri::async_runtime::block_on(consumer_b.execute_claim(claim_b)).unwrap();
        assert_eq!(res, FencedVectorSyncSingleEventResult::Completed);
        assert_eq!(storage.test_generation_item_count().unwrap(), 1);
    }
}
