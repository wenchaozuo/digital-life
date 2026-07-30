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
    embedding::{
        EmbeddingProvider, EmbeddingPurpose, EmbeddingRequest, EmbeddingRetryClass,
        EmbeddingRetrySafety,
    },
    model::{
        profile::ModelProfileRepository,
        runtime::{ModelRuntimeCoordinator, ModelRuntimeErrorCode, ModelRuntimeService},
    },
    secrets::{SecretStore, WindowsCredentialSecretStore},
    storage::{
        FencedAttemptStartResult, FencedFailureDecision, FencedFailureFinalizeResult,
        FencedFinalizeResult, FencedVectorSyncClaim, StorageService,
    },
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
#[allow(dead_code)]
const MIN_DRAIN_LIMIT: usize = 1;
#[allow(dead_code)]
const MAX_DRAIN_LIMIT: usize = 32;
const DEFAULT_LEASE_SECONDS: u32 = 120;
pub(crate) const MAX_VECTOR_SYNC_ATTEMPTS: u32 = 5;
const INITIAL_RETRY_SECONDS: u32 = 30;
const MAX_RETRY_SECONDS: u32 = 3_600;
const INITIAL_RETRY_MILLIS: u64 = (INITIAL_RETRY_SECONDS as u64) * 1_000;
const MAX_RETRY_MILLIS: u64 = (MAX_RETRY_SECONDS as u64) * 1_000;
const MAX_FINISHED_RUNS: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetryClockError {
    Unavailable,
}

pub(crate) trait RetryClock {
    fn now_utc_millis(&self) -> Result<i64, RetryClockError>;
}

struct SystemRetryClock;

impl RetryClock for SystemRetryClock {
    fn now_utc_millis(&self) -> Result<i64, RetryClockError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RetryClockError::Unavailable)?;
        i64::try_from(duration.as_millis()).map_err(|_| RetryClockError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetryDelayDecision {
    RetryAfter { delay_millis: u64 },
    BlockedAtAttemptLimit,
    InvalidOrOverflow,
}

pub(crate) const fn retry_delay_millis(attempt_count: u32) -> RetryDelayDecision {
    if attempt_count == 0 {
        return RetryDelayDecision::InvalidOrOverflow;
    }
    if attempt_count >= MAX_VECTOR_SYNC_ATTEMPTS {
        return RetryDelayDecision::BlockedAtAttemptLimit;
    }
    let shift = attempt_count - 1;
    let multiplier = match 1_u64.checked_shl(shift) {
        Some(value) => value,
        None => return RetryDelayDecision::InvalidOrOverflow,
    };
    match INITIAL_RETRY_MILLIS.checked_mul(multiplier) {
        Some(delay_millis) if delay_millis <= MAX_RETRY_MILLIS => {
            RetryDelayDecision::RetryAfter { delay_millis }
        }
        Some(_) => RetryDelayDecision::RetryAfter {
            delay_millis: MAX_RETRY_MILLIS,
        },
        None => RetryDelayDecision::InvalidOrOverflow,
    }
}

/// Pure retry-policy input.  Authority, lease, quarantine, completion, and
/// no-eligible outcomes never enter this classifier.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetryErrorClass {
    Embedding(EmbeddingRetryClass),
    EmbeddingInvalidVector,
    LanceTransient,
    LancePermanent,
    InternalInvariant,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetryOperation {
    Upsert,
    Delete,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetryDisposition {
    Retryable,
    Blocked,
    ProviderResultUnknown,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StableVectorSyncErrorCode {
    AuthenticationFailed,
    ProviderResultUnknown,
    RateLimited,
    RequestTimeout,
    ProviderUnavailable,
    InvalidRequest,
    InvalidProviderResponse,
    EmbeddingDimensionMismatch,
    EmbeddingInvalidVector,
    LanceTransient,
    LancePermanent,
    InternalInvariant,
}

#[allow(dead_code)]
impl StableVectorSyncErrorCode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "AUTHENTICATION_FAILED",
            Self::ProviderResultUnknown => "PROVIDER_RESULT_UNKNOWN",
            Self::RateLimited => "RATE_LIMITED",
            Self::RequestTimeout => "REQUEST_TIMEOUT",
            Self::ProviderUnavailable => "PROVIDER_UNAVAILABLE",
            Self::InvalidRequest => "INVALID_REQUEST",
            Self::InvalidProviderResponse => "INVALID_PROVIDER_RESPONSE",
            Self::EmbeddingDimensionMismatch => "EMBEDDING_DIMENSION_MISMATCH",
            Self::EmbeddingInvalidVector => "EMBEDDING_INVALID_VECTOR",
            Self::LanceTransient => "LANCE_TRANSIENT",
            Self::LancePermanent => "LANCE_PERMANENT",
            Self::InternalInvariant => "INTERNAL_INVARIANT",
        }
    }
}

/// No-I/O, no-clock classification for a failure after an attempt marker is
/// durably written.  It does not schedule retries or mutate an outbox row.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RetryDecision {
    pub(crate) disposition: RetryDisposition,
    pub(crate) stable_error_code: StableVectorSyncErrorCode,
    pub(crate) retry_safety: EmbeddingRetrySafety,
    pub(crate) consumes_attempt: bool,
    pub(crate) consumes_provider_slot: bool,
    pub(crate) blocked_by_attempt_limit: bool,
    pub(crate) requires_follow_up: bool,
}

#[allow(dead_code)]
pub(crate) const fn retry_decision(
    error: RetryErrorClass,
    retry_safety: EmbeddingRetrySafety,
    attempt_count: u32,
    operation: RetryOperation,
) -> RetryDecision {
    let blocked_by_attempt_limit = attempt_count >= MAX_VECTOR_SYNC_ATTEMPTS;
    let stable_error_code = stable_error_code_for(error);
    let consumes_provider_slot = matches!(
        (operation, error),
        (RetryOperation::Upsert, RetryErrorClass::Embedding(_))
    );
    let provider_result_unknown = matches!(retry_safety, EmbeddingRetrySafety::PossiblySent)
        && matches!(error, RetryErrorClass::Embedding(_));
    let disposition = if provider_result_unknown {
        RetryDisposition::ProviderResultUnknown
    } else if blocked_by_attempt_limit || !retryable_error(error) {
        RetryDisposition::Blocked
    } else {
        RetryDisposition::Retryable
    };
    RetryDecision {
        disposition,
        stable_error_code: if provider_result_unknown {
            StableVectorSyncErrorCode::ProviderResultUnknown
        } else {
            stable_error_code
        },
        retry_safety,
        consumes_attempt: true,
        consumes_provider_slot,
        blocked_by_attempt_limit,
        requires_follow_up: matches!(disposition, RetryDisposition::ProviderResultUnknown),
    }
}

#[allow(dead_code)]
const fn stable_error_code_for(error: RetryErrorClass) -> StableVectorSyncErrorCode {
    match error {
        RetryErrorClass::Embedding(EmbeddingRetryClass::CredentialNotConfigured)
        | RetryErrorClass::Embedding(EmbeddingRetryClass::AuthenticationRejected) => {
            StableVectorSyncErrorCode::AuthenticationFailed
        }
        RetryErrorClass::Embedding(EmbeddingRetryClass::CredentialUnavailable)
        | RetryErrorClass::Embedding(EmbeddingRetryClass::CredentialReadFailed)
        | RetryErrorClass::Embedding(EmbeddingRetryClass::TransportUnavailable)
        | RetryErrorClass::Embedding(EmbeddingRetryClass::ProviderUnavailable) => {
            StableVectorSyncErrorCode::ProviderUnavailable
        }
        RetryErrorClass::Embedding(EmbeddingRetryClass::RequestTimeout) => {
            StableVectorSyncErrorCode::RequestTimeout
        }
        RetryErrorClass::Embedding(EmbeddingRetryClass::RateLimited) => {
            StableVectorSyncErrorCode::RateLimited
        }
        RetryErrorClass::Embedding(EmbeddingRetryClass::InvalidRequest)
        | RetryErrorClass::Embedding(EmbeddingRetryClass::OtherClientError) => {
            StableVectorSyncErrorCode::InvalidRequest
        }
        RetryErrorClass::Embedding(EmbeddingRetryClass::InvalidProviderResponse) => {
            StableVectorSyncErrorCode::InvalidProviderResponse
        }
        RetryErrorClass::Embedding(EmbeddingRetryClass::DimensionMismatch) => {
            StableVectorSyncErrorCode::EmbeddingDimensionMismatch
        }
        RetryErrorClass::EmbeddingInvalidVector => {
            StableVectorSyncErrorCode::EmbeddingInvalidVector
        }
        RetryErrorClass::LanceTransient => StableVectorSyncErrorCode::LanceTransient,
        RetryErrorClass::LancePermanent => StableVectorSyncErrorCode::LancePermanent,
        RetryErrorClass::InternalInvariant => StableVectorSyncErrorCode::InternalInvariant,
    }
}

#[allow(dead_code)]
const fn retryable_error(error: RetryErrorClass) -> bool {
    matches!(
        error,
        RetryErrorClass::Embedding(EmbeddingRetryClass::CredentialUnavailable)
            | RetryErrorClass::Embedding(EmbeddingRetryClass::CredentialReadFailed)
            | RetryErrorClass::Embedding(EmbeddingRetryClass::TransportUnavailable)
            | RetryErrorClass::Embedding(EmbeddingRetryClass::RequestTimeout)
            | RetryErrorClass::Embedding(EmbeddingRetryClass::RateLimited)
            | RetryErrorClass::Embedding(EmbeddingRetryClass::ProviderUnavailable)
            | RetryErrorClass::LanceTransient
    )
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VectorSyncTestPausePoint {
    BeforeEmbedding,
    AfterEmbeddingBeforeLance,
    AfterLanceBeforeFinalize,
}

#[cfg(test)]
type TestPauseHook<'a> = Box<dyn Fn(VectorSyncTestPausePoint) + 'a>;
#[cfg(test)]
type TestClaimObserver<'a> = Box<dyn Fn(&FencedVectorSyncClaim) + 'a>;

/// One explicit D-9D1 outbox operation.  This is deliberately separate from
/// the legacy life-scoped drain worker: it has no loop, no profile discovery,
/// and no authority write transaction around embedding or LanceDB I/O.
#[allow(dead_code)]
pub(crate) struct FencedVectorSyncSingleEventConsumer<'a> {
    storage: &'a StorageService,
    embedding: &'a dyn EmbeddingProvider,
    vectors: &'a dyn VectorStore,
    generation: VectorGenerationContext,
    retry_clock: Box<dyn RetryClock>,
    #[cfg(test)]
    force_stale_result_for_test: std::cell::Cell<bool>,
    #[cfg(test)]
    forced_event_results_for_test: std::cell::RefCell<Vec<FencedVectorSyncSingleEventResult>>,
    #[allow(clippy::type_complexity)]
    #[cfg(test)]
    drain_iteration_hook_for_test: std::cell::RefCell<
        Option<Box<dyn FnMut(usize, &VectorSyncDrainReport, &StorageService, usize) + 'a>>,
    >,
    #[cfg(test)]
    pause_hook_for_test: std::cell::RefCell<Option<TestPauseHook<'a>>>,
    #[cfg(test)]
    claim_observer_for_test: std::cell::RefCell<Option<TestClaimObserver<'a>>>,
    #[cfg(test)]
    force_no_progress_for_test: std::cell::Cell<bool>,
    #[cfg(test)]
    stop_after_lance_upsert_for_test: std::cell::Cell<bool>,
    #[cfg(test)]
    stale_on_claim_for_test: std::cell::Cell<Option<usize>>,
    #[cfg(test)]
    claimed_events_for_test: std::cell::Cell<usize>,
    #[cfg(test)]
    process_one_invocations_for_test: std::cell::Cell<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum FencedVectorSyncSingleEventResult {
    NoEligibleEvent,
    CompletedUpsert,
    CompletedDelete,
    Stale,
    RetryWait,
    Blocked,
    Failed,
    LostLeaseOrSuperseded,
    #[cfg(test)]
    NoProgressForTest,
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
            retry_clock: Box::new(SystemRetryClock),
            #[cfg(test)]
            force_stale_result_for_test: std::cell::Cell::new(false),
            #[cfg(test)]
            forced_event_results_for_test: std::cell::RefCell::new(Vec::new()),
            #[cfg(test)]
            drain_iteration_hook_for_test: std::cell::RefCell::new(None),
            #[cfg(test)]
            pause_hook_for_test: std::cell::RefCell::new(None),
            #[cfg(test)]
            claim_observer_for_test: std::cell::RefCell::new(None),
            #[cfg(test)]
            force_no_progress_for_test: std::cell::Cell::new(false),
            #[cfg(test)]
            stop_after_lance_upsert_for_test: std::cell::Cell::new(false),
            #[cfg(test)]
            stale_on_claim_for_test: std::cell::Cell::new(None),
            #[cfg(test)]
            claimed_events_for_test: std::cell::Cell::new(0),
            #[cfg(test)]
            process_one_invocations_for_test: std::cell::Cell::new(0),
        }
    }

    #[cfg(test)]
    fn with_retry_clock_for_test(mut self, retry_clock: Box<dyn RetryClock>) -> Self {
        self.retry_clock = retry_clock;
        self
    }

    #[cfg(test)]
    fn with_forced_stale_result_for_test(mut self) -> Self {
        self.force_stale_result_for_test = std::cell::Cell::new(true);
        self
    }

    #[cfg(test)]
    fn with_forced_results_for_test(
        mut self,
        results: Vec<FencedVectorSyncSingleEventResult>,
    ) -> Self {
        self.forced_event_results_for_test = std::cell::RefCell::new(results);
        self
    }

    #[allow(clippy::type_complexity)]
    #[cfg(test)]
    fn set_drain_iteration_hook_for_test(
        &mut self,
        hook: Option<Box<dyn FnMut(usize, &VectorSyncDrainReport, &StorageService, usize) + 'a>>,
    ) {
        *self.drain_iteration_hook_for_test.borrow_mut() = hook;
    }

    #[cfg(test)]
    fn set_test_pause_hook_for_test(&self, hook: Option<TestPauseHook<'a>>) {
        *self.pause_hook_for_test.borrow_mut() = hook;
    }

    #[cfg(test)]
    fn set_claim_observer_for_test(&self, observer: Option<TestClaimObserver<'a>>) {
        *self.claim_observer_for_test.borrow_mut() = observer;
    }

    #[cfg(test)]
    fn set_force_stale_result_for_test(&self, enabled: bool) {
        self.force_stale_result_for_test.set(enabled);
    }

    #[cfg(test)]
    fn set_force_no_progress_for_test(&self, enabled: bool) {
        self.force_no_progress_for_test.set(enabled);
    }

    #[cfg(test)]
    fn set_stop_after_lance_upsert_for_test(&self) {
        self.stop_after_lance_upsert_for_test.set(true);
    }

    #[cfg(test)]
    fn stop_after_lance_upsert_for_test(&self) -> bool {
        self.stop_after_lance_upsert_for_test.replace(false)
    }

    #[cfg(test)]
    fn set_stale_on_claim_for_test(&self, claim_number: usize) {
        self.stale_on_claim_for_test.set(Some(claim_number));
    }

    #[cfg(test)]
    fn check_test_pause_point(&self, point: VectorSyncTestPausePoint) {
        if let Some(hook) = self.pause_hook_for_test.borrow().as_ref() {
            hook(point);
        }
    }

    #[cfg(test)]
    fn process_one_invocations_for_test(&self) -> usize {
        self.process_one_invocations_for_test.get()
    }

    pub(crate) async fn process_one(
        &self,
        lease_owner: &str,
    ) -> Result<FencedVectorSyncSingleEventResult, MemoryVectorSyncWorkerError> {
        let retry_cutoff = self.capture_retry_cutoff()?;
        self.process_one_with_retry_cutoff(lease_owner, retry_cutoff)
            .await
    }

    fn capture_retry_cutoff(&self) -> Result<i64, MemoryVectorSyncWorkerError> {
        self.retry_clock
            .now_utc_millis()
            .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::InternalError))
    }

    async fn process_one_with_retry_cutoff(
        &self,
        lease_owner: &str,
        retry_cutoff: i64,
    ) -> Result<FencedVectorSyncSingleEventResult, MemoryVectorSyncWorkerError> {
        #[cfg(test)]
        self.process_one_invocations_for_test
            .set(self.process_one_invocations_for_test.get() + 1);
        #[cfg(test)]
        if self.force_no_progress_for_test.get() {
            return Ok(FencedVectorSyncSingleEventResult::NoProgressForTest);
        }
        #[cfg(test)]
        if !self.forced_event_results_for_test.borrow().is_empty() {
            let forced = self.forced_event_results_for_test.borrow_mut().remove(0);
            if forced == FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded {
                return Ok(forced);
            }
            return Ok(forced);
        }
        let claim = self
            .storage
            .claim_one_fenced_vector_sync_with_retry_cutoff(
                self.generation.generation_id().as_str(),
                self.generation.descriptor_hash(),
                self.generation.dimension(),
                lease_owner,
                Some(retry_cutoff),
            )
            .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?;
        let Some(claim) = claim else {
            return Ok(FencedVectorSyncSingleEventResult::NoEligibleEvent);
        };
        #[cfg(test)]
        self.claimed_events_for_test
            .set(self.claimed_events_for_test.get() + 1);
        #[cfg(test)]
        if let Some(observer) = self.claim_observer_for_test.borrow().as_ref() {
            observer(&claim);
        }
        self.execute_claim(claim, retry_cutoff).await
    }

    async fn execute_claim(
        &self,
        claim: FencedVectorSyncClaim,
        retry_cutoff: i64,
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
                let Some(attempt_count) = self.start_attempt(&claim)? else {
                    return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
                };
                let outcome = self
                    .vectors
                    .delete_generation_memory(&self.generation, claim.life_id(), claim.memory_id())
                    .await;
                match outcome {
                    Ok(()) => self.finalize(&claim, None, None, false, None),
                    Err(error) if error.code == VectorStoreErrorCode::VectorNotFound => {
                        self.finalize(&claim, None, None, false, None)
                    }
                    Err(error) => self.finalize_failure(
                        &claim,
                        attempt_count,
                        if error.recoverable {
                            RetryErrorClass::LanceTransient
                        } else {
                            RetryErrorClass::LancePermanent
                        },
                        EmbeddingRetrySafety::ResponseReceived,
                        RetryOperation::Delete,
                        None,
                        retry_cutoff,
                    ),
                }
            }
            MemoryVectorSyncAction::Upsert => {
                #[cfg(test)]
                if self.force_stale_result_for_test.get()
                    || self.stale_on_claim_for_test.get()
                        == Some(self.claimed_events_for_test.get())
                {
                    return self
                        .finalize(&claim, None, Some("VECTOR_TARGET_STALE"), false, None)
                        .map(|_| FencedVectorSyncSingleEventResult::Stale);
                }
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
                self.check_test_pause_point(VectorSyncTestPausePoint::BeforeEmbedding);
                if !self
                    .storage
                    .fenced_vector_claim_is_current(&claim)
                    .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
                {
                    return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
                }
                let Some(attempt_count) = self.start_attempt(&claim)? else {
                    return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
                };
                let response = self
                    .embedding
                    .embed(EmbeddingRequest {
                        texts: vec![document],
                        purpose: EmbeddingPurpose::Document,
                    })
                    .await;
                #[cfg(test)]
                self.check_test_pause_point(VectorSyncTestPausePoint::AfterEmbeddingBeforeLance);
                let batch = match response {
                    Ok(batch) => batch,
                    Err(error) => {
                        return self.finalize_failure(
                            &claim,
                            attempt_count,
                            RetryErrorClass::Embedding(error.retry_class()),
                            error.retry_safety(),
                            RetryOperation::Upsert,
                            Some(send_disposition_for_retry_safety(error.retry_safety())),
                            retry_cutoff,
                        )
                    }
                };
                let vector = batch.vectors().first().filter(|v| {
                    batch.len() == 1
                        && v.input_index() == 0
                        && v.dimension() == self.generation.dimension()
                });
                let Some(vector) = vector else {
                    return self.finalize_failure(
                        &claim,
                        attempt_count,
                        RetryErrorClass::EmbeddingInvalidVector,
                        EmbeddingRetrySafety::ResponseReceived,
                        RetryOperation::Upsert,
                        Some("possibly_sent"),
                        retry_cutoff,
                    );
                };
                let Some(target_revision) = claim.target_revision() else {
                    return self.finalize_failure(
                        &claim,
                        attempt_count,
                        RetryErrorClass::InternalInvariant,
                        EmbeddingRetrySafety::ResponseReceived,
                        RetryOperation::Upsert,
                        Some("possibly_sent"),
                        retry_cutoff,
                    );
                };
                let Some(target_content_hash) = claim.target_content_hash() else {
                    return self.finalize_failure(
                        &claim,
                        attempt_count,
                        RetryErrorClass::InternalInvariant,
                        EmbeddingRetrySafety::ResponseReceived,
                        RetryOperation::Upsert,
                        Some("possibly_sent"),
                        retry_cutoff,
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
                        return self.finalize_failure(
                            &claim,
                            attempt_count,
                            RetryErrorClass::EmbeddingInvalidVector,
                            EmbeddingRetrySafety::ResponseReceived,
                            RetryOperation::Upsert,
                            Some("possibly_sent"),
                            retry_cutoff,
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
                        if self.stop_after_lance_upsert_for_test() {
                            return Err(worker_error(
                                MemoryVectorSyncWorkerErrorCode::InternalError,
                            ));
                        }
                        #[cfg(test)]
                        self.check_test_pause_point(
                            VectorSyncTestPausePoint::AfterLanceBeforeFinalize,
                        );
                        self.finalize(&claim, claim.target_content_hash(), None, false, None)
                    }
                    Err(error) => self.finalize_failure(
                        &claim,
                        attempt_count,
                        if error.recoverable {
                            RetryErrorClass::LanceTransient
                        } else {
                            RetryErrorClass::LancePermanent
                        },
                        EmbeddingRetrySafety::ResponseReceived,
                        RetryOperation::Upsert,
                        Some("possibly_sent"),
                        retry_cutoff,
                    ),
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
        let is_upsert = claim.action() == MemoryVectorSyncAction::Upsert;
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
            FencedFinalizeResult::Applied if is_upsert => {
                FencedVectorSyncSingleEventResult::CompletedUpsert
            }
            FencedFinalizeResult::Applied => FencedVectorSyncSingleEventResult::CompletedDelete,
        })
    }

    fn start_attempt(
        &self,
        claim: &FencedVectorSyncClaim,
    ) -> Result<Option<u32>, MemoryVectorSyncWorkerError> {
        match self
            .storage
            .mark_fenced_attempt_started(claim)
            .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
        {
            FencedAttemptStartResult::Started { attempt_count } => Ok(Some(attempt_count)),
            FencedAttemptStartResult::LostLeaseOrSuperseded => Ok(None),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_failure(
        &self,
        claim: &FencedVectorSyncClaim,
        attempt_count: u32,
        error: RetryErrorClass,
        retry_safety: EmbeddingRetrySafety,
        operation: RetryOperation,
        send_disposition: Option<&str>,
        retry_cutoff: i64,
    ) -> Result<FencedVectorSyncSingleEventResult, MemoryVectorSyncWorkerError> {
        let retry = retry_decision(error, retry_safety, attempt_count, operation);
        let failure_decision = match retry.disposition {
            RetryDisposition::Retryable => match retry_delay_millis(attempt_count) {
                RetryDelayDecision::RetryAfter { delay_millis } => {
                    FencedFailureDecision::RetryAfter { delay_millis }
                }
                RetryDelayDecision::BlockedAtAttemptLimit
                | RetryDelayDecision::InvalidOrOverflow => FencedFailureDecision::Blocked,
            },
            RetryDisposition::Blocked | RetryDisposition::ProviderResultUnknown => {
                FencedFailureDecision::Blocked
            }
        };
        let clock_now = match failure_decision {
            FencedFailureDecision::RetryAfter { .. } => self.retry_clock.now_utc_millis().ok(),
            FencedFailureDecision::Blocked => Some(retry_cutoff),
        };
        let result = self
            .storage
            .finalize_fenced_vector_failure(
                claim,
                retry.stable_error_code.as_str(),
                if clock_now.is_some() {
                    failure_decision
                } else {
                    FencedFailureDecision::Blocked
                },
                send_disposition,
                clock_now.unwrap_or(retry_cutoff),
                retry_cutoff,
            )
            .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?;
        Ok(match result {
            FencedFailureFinalizeResult::RetryScheduled { .. } => {
                FencedVectorSyncSingleEventResult::RetryWait
            }
            FencedFailureFinalizeResult::Blocked => FencedVectorSyncSingleEventResult::Blocked,
            FencedFailureFinalizeResult::LostLeaseOrSuperseded => {
                FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded
            }
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

fn send_disposition_for_retry_safety(retry_safety: EmbeddingRetrySafety) -> &'static str {
    match retry_safety {
        EmbeddingRetrySafety::DefinitelyNotSent => "definitely_not_sent",
        EmbeddingRetrySafety::ResponseReceived | EmbeddingRetrySafety::PossiblySent => {
            "possibly_sent"
        }
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

/// Bounded serial drain report. Counts only; no identifiers, paths, or values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorSyncDrainReport {
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

#[allow(dead_code)]
impl VectorSyncDrainReport {
    fn new(limit: usize) -> Self {
        Self {
            requested_limit: limit,
            processed: 0,
            applied_upserts: 0,
            applied_deletes: 0,
            retry_scheduled: 0,
            blocked: 0,
            failed: 0,
            stopped_no_eligible: false,
            stopped_lost_lease: false,
        }
    }

    fn record(&mut self, result: FencedVectorSyncSingleEventResult) {
        match result {
            FencedVectorSyncSingleEventResult::CompletedUpsert => {
                self.applied_upserts += 1;
                self.applied_deletes += 0;
                self.processed += 1;
            }
            FencedVectorSyncSingleEventResult::CompletedDelete => {
                self.applied_upserts += 0;
                self.applied_deletes += 1;
                self.processed += 1;
            }
            FencedVectorSyncSingleEventResult::RetryWait => {
                self.retry_scheduled += 1;
                self.processed += 1;
            }
            FencedVectorSyncSingleEventResult::Blocked => {
                self.blocked += 1;
                self.processed += 1;
            }
            FencedVectorSyncSingleEventResult::Stale
            | FencedVectorSyncSingleEventResult::Failed => {
                self.failed += 1;
                self.processed += 1;
            }
            FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded => {
                self.stopped_lost_lease = true;
            }
            FencedVectorSyncSingleEventResult::NoEligibleEvent => {
                self.stopped_no_eligible = true;
            }
            #[cfg(test)]
            FencedVectorSyncSingleEventResult::NoProgressForTest => {}
        }
    }

    fn is_stopped(&self) -> bool {
        self.stopped_no_eligible || self.stopped_lost_lease
    }
}

/// Serial, bounded drain over the fenced single-event consumer.
///
/// Repeats `process_one` up to `limit` times (or until no eligible event or
/// lost lease).  Each round is strictly sequential: claim → I/O → finalize.
/// Does not auto-start, spawn, or create background tasks.
///
/// # Errors
/// - `InvalidRequest` when `limit` is 0 or > 32.
/// - `OutboxUnavailable` on persistent store failure (propagated from consumer).
#[allow(dead_code)]
pub(crate) async fn drain_fenced_vector_sync(
    consumer: &FencedVectorSyncSingleEventConsumer<'_>,
    lease_owner: &str,
    limit: usize,
) -> Result<VectorSyncDrainReport, MemoryVectorSyncWorkerError> {
    if !(MIN_DRAIN_LIMIT..=MAX_DRAIN_LIMIT).contains(&limit) {
        return Err(worker_error(
            MemoryVectorSyncWorkerErrorCode::InvalidRequest,
        ));
    }

    let mut report = VectorSyncDrainReport::new(limit);
    let drain_retry_cutoff = consumer.capture_retry_cutoff()?;

    while report.processed < limit && !report.is_stopped() {
        let result = consumer
            .process_one_with_retry_cutoff(lease_owner, drain_retry_cutoff)
            .await?;
        let before = report.processed;
        report.record(result);
        // Must make progress or stop — prevent infinite busy loop if
        // process_one returns a result that didn't advance anything.
        if report.processed == before && !report.is_stopped() {
            return Err(worker_error(MemoryVectorSyncWorkerErrorCode::InternalError));
        }
        #[cfg(test)]
        if let Some(ref mut hook) = *consumer.drain_iteration_hook_for_test.borrow_mut() {
            hook(
                report.processed,
                &report,
                consumer.storage,
                consumer.process_one_invocations_for_test(),
            );
        }
    }

    Ok(report)
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
            Some(MemoryVectorSyncFailureClass::Retriable)
                if job.attempt_count < MAX_VECTOR_SYNC_ATTEMPTS =>
            {
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
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
        consumer.set_stop_after_lance_upsert_for_test();
        assert!(consumer.stop_after_lance_upsert_for_test());
        assert!(!consumer.stop_after_lance_upsert_for_test());
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
    fn provider_result_unknown_blocks_without_resend() {
        let (_temp, storage) = test_storage();
        let record = confirmed(&storage, false);
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
        let transport_requests = Arc::new(AtomicUsize::new(0));
        let transport_requests_for_server = Arc::clone(&transport_requests);
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 2048];
            let _ = stream.read(&mut buffer);
            transport_requests_for_server.fetch_add(1, Ordering::SeqCst);
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
        let raw_provider =
            crate::embedding::build_openai_compatible_embedding_provider(&profile, &secrets)
                .unwrap();
        let provider_requests = Arc::new(AtomicUsize::new(0));
        let embedding_successes = Arc::new(AtomicUsize::new(0));
        let provider = CountingEmbeddingProvider {
            inner: raw_provider.as_ref(),
            provider_requests: Arc::clone(&provider_requests),
            embedding_successes,
        };
        let clock = FixedRetryClock::new(100_000);
        let advanced_clock = clock.clone();
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                .with_retry_clock_for_test(Box::new(clock));
        let first =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "worker-a", 1))
                .unwrap();
        server.join().unwrap();
        assert_eq!(first.processed, 1);
        assert_eq!(first.blocked, 1);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
        assert_eq!(transport_requests.load(Ordering::SeqCst), 1);
        assert_eq!(consumer.claimed_events_for_test.get(), 1);
        let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
        assert_eq!(row.0, 1);
        assert_eq!(row.1.as_deref(), Some("possibly_sent"));
        assert_eq!(row.2, "PROVIDER_RESULT_UNKNOWN");
        let before_second_drain = storage
            .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
            .unwrap();
        assert_eq!(before_second_drain.next_attempt_at, None);

        advanced_clock.set(200_000);
        let second =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "worker-a", 1))
                .unwrap();
        assert_eq!(second.processed, 0);
        assert!(second.stopped_no_eligible);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
        assert_eq!(transport_requests.load(Ordering::SeqCst), 1);
        assert_eq!(consumer.claimed_events_for_test.get(), 1);
        let after_second_drain = storage
            .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
            .unwrap();
        assert_eq!(after_second_drain.state, "blocked");
        assert_eq!(after_second_drain.attempt_count, 1);
        assert_eq!(
            after_second_drain.last_error_code.as_deref(),
            Some("PROVIDER_RESULT_UNKNOWN")
        );
        assert_eq!(
            after_second_drain.last_send_disposition.as_deref(),
            Some("possibly_sent")
        );
        assert_eq!(after_second_drain.next_attempt_at, None);
    }

    #[test]
    fn lance_success_before_finalize_is_not_automatically_replayed() {
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
        consumer.set_stop_after_lance_upsert_for_test();
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
        assert_eq!(result, FencedVectorSyncSingleEventResult::NoEligibleEvent);
        assert_eq!(
            tauri::async_runtime::block_on(vectors.count_generation(&context, Some("life")))
                .unwrap(),
            1
        );
        let job = storage.list("life").unwrap().remove(0);
        assert_eq!(job.state, MemoryVectorSyncState::Blocked);
        assert_eq!(job.attempt_count, 1);
        assert_eq!(
            job.last_error_code.as_deref(),
            Some("PROVIDER_RESULT_UNKNOWN")
        );
        assert_eq!(
            storage
                .test_get_outbox_snapshot_detailed(&job.life_id, &job.memory_id)
                .unwrap()
                .last_send_disposition
                .as_deref(),
            Some("possibly_sent")
        );
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
    use std::sync::atomic::{AtomicI64, AtomicUsize};

    #[derive(Clone)]
    struct FixedRetryClock {
        now_millis: Arc<AtomicI64>,
    }

    impl FixedRetryClock {
        fn new(now_millis: i64) -> Self {
            Self {
                now_millis: Arc::new(AtomicI64::new(now_millis)),
            }
        }

        fn set(&self, now_millis: i64) {
            self.now_millis.store(now_millis, Ordering::SeqCst);
        }
    }

    impl RetryClock for FixedRetryClock {
        fn now_utc_millis(&self) -> Result<i64, RetryClockError> {
            Ok(self.now_millis.load(Ordering::SeqCst))
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct IoCounterSnapshot {
        credential_reads: usize,
        provider_requests: usize,
        transport_requests: usize,
        embedding_successes: usize,
        lance_upserts: usize,
        lance_deletes: usize,
        generation_item_writes: usize,
        process_one_invocations: usize,
    }

    macro_rules! assert_same_outbox_row {
        ($before:expr, $after:expr) => {{
            let before = &$before;
            let after = &$after;
            assert_eq!(before.id, after.id, "outbox row identity must not change");
            assert_eq!(before.desired_action, after.desired_action);
            assert_eq!(before.mutation_sequence, after.mutation_sequence);
            assert_eq!(before.target_revision, after.target_revision);
            assert_eq!(before.target_content_hash, after.target_content_hash);
            assert_eq!(before.state, after.state);
            assert_eq!(before.attempt_count, after.attempt_count);
            assert_eq!(before.lease_owner, after.lease_owner);
            assert_eq!(before.lease_fence_epoch, after.lease_fence_epoch);
            assert_eq!(before.lease_expires_at, after.lease_expires_at);
            assert_eq!(before.claimed_generation_id, after.claimed_generation_id);
            assert_eq!(
                before.claimed_generation_id_is_null,
                after.claimed_generation_id_is_null
            );
            assert_eq!(before.migration_disposition, after.migration_disposition);
            assert_eq!(before.last_error_code, after.last_error_code);
            assert_eq!(before.last_send_disposition, after.last_send_disposition);
            assert_eq!(before.next_attempt_at, after.next_attempt_at);
        }};
    }

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

    struct MixedOutcomeEmbeddingProvider {
        inner: crate::embedding::DeterministicEmbeddingProvider,
        requests: AtomicUsize,
    }

    struct PossiblySentEmbeddingProvider {
        inner: crate::embedding::DeterministicEmbeddingProvider,
        requests: AtomicUsize,
    }

    impl EmbeddingProvider for PossiblySentEmbeddingProvider {
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
            _request: EmbeddingRequest,
        ) -> EmbeddingFuture<'a, Result<EmbeddingBatch, EmbeddingError>> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(EmbeddingError::possibly_sent(
                    crate::embedding::EmbeddingErrorCode::NetworkError,
                ))
            })
        }
    }

    impl EmbeddingProvider for MixedOutcomeEmbeddingProvider {
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
            let number = self.requests.fetch_add(1, Ordering::SeqCst) + 1;
            match number {
                1 => Box::pin(async {
                    Err(EmbeddingError::definitely_not_sent(
                        crate::embedding::EmbeddingErrorCode::NetworkError,
                    ))
                }),
                2 => Box::pin(async {
                    Err(EmbeddingError::definitely_not_sent(
                        crate::embedding::EmbeddingErrorCode::AuthenticationFailed,
                    ))
                }),
                _ => self.inner.embed(request),
            }
        }
    }

    struct CountingVectorStore<V> {
        inner: V,
        lance_upserts: Arc<AtomicUsize>,
        lance_deletes: Arc<AtomicUsize>,
        current_lance_writes: Arc<AtomicUsize>,
        max_concurrent_lance_writes: Arc<AtomicUsize>,
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
            let current = Arc::clone(&self.current_lance_writes);
            let max = Arc::clone(&self.max_concurrent_lance_writes);
            let value = current.fetch_add(1, Ordering::SeqCst) + 1;
            max.fetch_max(value, Ordering::SeqCst);
            let future = self.inner.upsert_generation(context, record);
            Box::pin(async move {
                let result = future.await;
                current.fetch_sub(1, Ordering::SeqCst);
                result
            })
        }

        fn delete_generation_memory<'a>(
            &'a self,
            context: &'a VectorGenerationContext,
            life_id: &'a str,
            memory_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.lance_deletes.fetch_add(1, Ordering::SeqCst);
            let current = Arc::clone(&self.current_lance_writes);
            let max = Arc::clone(&self.max_concurrent_lance_writes);
            let value = current.fetch_add(1, Ordering::SeqCst) + 1;
            max.fetch_max(value, Ordering::SeqCst);
            let future = self
                .inner
                .delete_generation_memory(context, life_id, memory_id);
            Box::pin(async move {
                let result = future.await;
                current.fetch_sub(1, Ordering::SeqCst);
                result
            })
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

        fn sample_generation_metadata<'a>(
            &'a self,
            context: &'a VectorGenerationContext,
            limit: usize,
        ) -> VectorStoreFuture<
            'a,
            Result<Vec<crate::vector_store::VectorMetadataSample>, VectorStoreError>,
        > {
            self.inner.sample_generation_metadata(context, limit)
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

    #[test]
    fn fence_lost_before_embedding_has_zero_io() {
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
        let current_lance_writes = Arc::new(AtomicUsize::new(0));
        let max_concurrent_lance_writes = Arc::new(AtomicUsize::new(0));
        let vectors = CountingVectorStore {
            inner: raw_vectors,
            lance_upserts: Arc::clone(&lance_upserts),
            lance_deletes: Arc::clone(&lance_deletes),
            current_lance_writes: Arc::clone(&current_lance_writes),
            max_concurrent_lance_writes: Arc::clone(&max_concurrent_lance_writes),
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
        let consumer = FencedVectorSyncSingleEventConsumer::new(
            storage.as_ref(),
            &provider,
            &vectors,
            context.clone(),
        );
        consumer.set_test_pause_hook_for_test(Some(Box::new(move |point| {
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
        })));

        let result = tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap();
        consumer.set_test_pause_hook_for_test(None);

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
        // Worker A's claim was never attempt-started: Provider=0, Lance=0.
        // The LostLease return from before start_attempt guarantees attempt_count remains 0
        // because the code only marks the attempt AFTER the second fenced_vector_claim_is_current
        // check (which fails).  The Outbox was not mutated by worker A.
        // Verify by checking the takeover event's snapshot: worker A never touched it.

        let claim_b = claim_b_slot.lock().unwrap().take().unwrap();
        let snap_b_takeover = snap_b_takeover_slot.lock().unwrap().take().unwrap();
        let snap_after_worker_a = storage
            .test_get_outbox_snapshot_detailed("life", claim_b.memory_id())
            .unwrap();
        assert_eq!(
            snap_b_takeover, snap_after_worker_a,
            "Phase A: Worker A produced ZERO side-effects on Outbox snapshot"
        );

        let result_b = tauri::async_runtime::block_on(consumer.execute_claim(claim_b, 0)).unwrap();
        assert_eq!(result_b, FencedVectorSyncSingleEventResult::CompletedUpsert);
        assert_eq!(storage.test_generation_item_count().unwrap(), 1);
    }

    #[test]
    fn lost_lease_after_provider_preserves_possible_send() {
        let (temp, storage) = test_storage();
        let storage_b =
            StorageService::initialize_with_roots(temp.path().join("data"), None).unwrap();
        let storage = Arc::new(storage);
        let record = confirmed(&storage, false);
        let takeover_record = confirmed(&storage, false);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: takeover_record.life_id.clone(),
                memory_id: takeover_record.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
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
        let current_lance_writes = Arc::new(AtomicUsize::new(0));
        let max_concurrent_lance_writes = Arc::new(AtomicUsize::new(0));
        let vectors = CountingVectorStore {
            inner: raw_vectors,
            lance_upserts: Arc::clone(&lance_upserts),
            lance_deletes: Arc::clone(&lance_deletes),
            current_lance_writes: Arc::clone(&current_lance_writes),
            max_concurrent_lance_writes: Arc::clone(&max_concurrent_lance_writes),
        };

        // Real D-8 Loopback HTTP Server
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let provider_requests = Arc::new(AtomicUsize::new(0));
        let transport_requests = Arc::new(AtomicUsize::new(0));
        let transport_requests_clone = Arc::clone(&transport_requests);

        let server_handle = std::thread::spawn(move || {
            use std::io::{Read, Write};
            for _ in 0..1 {
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

        let owner_a = Arc::new(Mutex::new(None));
        let fence_a = Arc::new(Mutex::new(None));
        let owner_a_for_observer = Arc::clone(&owner_a);
        let fence_a_for_observer = Arc::clone(&fence_a);
        let fence_a_for_pause = Arc::clone(&fence_a);
        let owner_b = Arc::new(Mutex::new(None));
        let fence_b = Arc::new(Mutex::new(None));
        let owner_b_for_pause = Arc::clone(&owner_b);
        let fence_b_for_pause = Arc::clone(&fence_b);
        let storage_b_capture = storage_b;
        let context_clone = context.clone();
        let consumer = FencedVectorSyncSingleEventConsumer::new(
            storage.as_ref(),
            &provider,
            &vectors,
            context.clone(),
        );
        consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
            *owner_a_for_observer.lock().unwrap() = Some(claim.lease_owner().to_string());
            *fence_a_for_observer.lock().unwrap() = Some(claim.fence_epoch());
        })));
        consumer.set_test_pause_hook_for_test(Some(Box::new(move |point| {
            if point == VectorSyncTestPausePoint::AfterEmbeddingBeforeLance {
                storage_b_capture
                    .test_expire_fenced_runtime_lease()
                    .unwrap();
                let claim_b = storage_b_capture
                    .claim_one_fenced_vector_sync(
                        context_clone.generation_id().as_str(),
                        context_clone.descriptor_hash(),
                        context_clone.dimension(),
                        "worker-b",
                    )
                    .unwrap()
                    .expect("worker-b must claim the independent delete event");
                assert_eq!(claim_b.action(), MemoryVectorSyncAction::Delete);
                assert_eq!(claim_b.lease_owner(), "worker-b");
                let observed_fence_a = fence_a_for_pause.lock().unwrap().unwrap();
                assert!(claim_b.fence_epoch() > observed_fence_a);
                *owner_b_for_pause.lock().unwrap() = Some(claim_b.lease_owner().to_string());
                *fence_b_for_pause.lock().unwrap() = Some(claim_b.fence_epoch());
            }
        })));

        let result = tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap();
        consumer.set_test_pause_hook_for_test(None);

        assert_eq!(
            result,
            FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded
        );
        assert_eq!(owner_a.lock().unwrap().as_deref(), Some("worker-a"));
        assert_eq!(owner_b.lock().unwrap().as_deref(), Some("worker-b"));
        assert!(fence_b.lock().unwrap().unwrap() > fence_a.lock().unwrap().unwrap());
        assert_eq!(credential_reads.load(Ordering::SeqCst), 1);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
        assert_eq!(transport_requests.load(Ordering::SeqCst), 1);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 1);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);
        assert_eq!(storage.test_generation_item_count().unwrap(), 0);

        let snap_mid = storage
            .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
            .unwrap();
        assert_eq!(
            snap_mid.total_count, 2,
            "both the blocked upsert and B's delete remain durable"
        );
        assert_eq!(
            snap_mid.state, "blocked",
            "expired recovery must fail closed after a provider result"
        );
        assert_eq!(
            snap_mid.last_error_code.as_deref(),
            Some("PROVIDER_RESULT_UNKNOWN"),
            "expired recovery records the unknown provider result"
        );
        assert_eq!(
            snap_mid.last_send_disposition.as_deref(),
            Some("possibly_sent"),
            "old owner cannot overwrite the attempt marker"
        );
        assert_eq!(
            snap_mid.attempt_count, 1,
            "Phase B: attempt_count not extra incremented"
        );

        server_handle.join().unwrap();
        assert_eq!(storage.test_generation_item_count().unwrap(), 0);
        assert_eq!(credential_reads.load(Ordering::SeqCst), 1);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
        assert_eq!(transport_requests.load(Ordering::SeqCst), 1);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 1);

        // B's official claim still owns the runtime lease. Expire it only to
        // let an explicit consumer run recovery and prove A remains blocked.
        storage.test_expire_fenced_runtime_lease().unwrap();
        let after_recovery =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "worker-a", 1))
                .unwrap();
        assert_eq!(after_recovery.processed, 1);
        let after_recovery_a = storage
            .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
            .unwrap();
        assert_eq!(after_recovery_a.state, "blocked");
        assert_eq!(
            after_recovery_a.last_error_code.as_deref(),
            Some("PROVIDER_RESULT_UNKNOWN")
        );
        assert_eq!(
            after_recovery_a.last_send_disposition.as_deref(),
            Some("possibly_sent")
        );
        assert_eq!(after_recovery_a.attempt_count, 1);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
        assert_eq!(transport_requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn stale_token_cannot_write_after_lance_and_fence_takeover() {
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
        let res = tauri::async_runtime::block_on(consumer_b.execute_claim(claim_b, 0)).unwrap();
        assert_eq!(res, FencedVectorSyncSingleEventResult::CompletedUpsert);
        assert_eq!(storage.test_generation_item_count().unwrap(), 1);
    }

    fn drained_context() -> (
        VectorGenerationContext,
        crate::vector_store::InMemoryVectorStore,
    ) {
        let desc = "d".repeat(64);
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-drain").unwrap(),
            desc.clone(),
            3,
        )
        .unwrap();
        let vectors = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(vectors.create_generation(&context)).unwrap();
        (context, vectors)
    }

    fn drain_upsert_fixture(storage: &StorageService, gen_id: &str) -> String {
        storage
            .register_building_vector_generation(gen_id, &"d".repeat(64), 3)
            .unwrap();
        let mem = confirmed(storage, false);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: mem.life_id.clone(),
                memory_id: mem.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        mem.life_id
    }

    fn drain_delete_fixture(storage: &StorageService, gen_id: &str) -> String {
        storage
            .register_building_vector_generation(gen_id, &"d".repeat(64), 3)
            .unwrap();
        let mem = confirmed(storage, false);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: mem.life_id.clone(),
                memory_id: mem.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
        mem.life_id
    }

    #[test]
    fn drain_rejects_invalid_limits() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
        for bad in [0, 33] {
            let err = tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w", bad))
                .unwrap_err();
            assert_eq!(
                err.code,
                MemoryVectorSyncWorkerErrorCode::InvalidRequest,
                "limit {bad}"
            );
        }
    }

    #[test]
    fn drain_stops_at_limit() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        drain_upsert_fixture(&storage, context.generation_id().as_str());
        // Enqueue exactly 5 events; limit 3 must leave exactly 2 untouched.
        let _l1 = drain_delete_fixture(&storage, context.generation_id().as_str());
        let _l2 = drain_delete_fixture(&storage, context.generation_id().as_str());
        let _l3 = drain_delete_fixture(&storage, context.generation_id().as_str());
        let _l4 = drain_delete_fixture(&storage, context.generation_id().as_str());
        let pending_before: Vec<_> = storage
            .list("life")
            .unwrap()
            .into_iter()
            .filter(|job| job.state == MemoryVectorSyncState::Pending)
            .map(|job| {
                let snapshot = storage
                    .test_get_outbox_snapshot_detailed(&job.life_id, &job.memory_id)
                    .unwrap();
                (job.life_id, job.memory_id, snapshot)
            })
            .collect();
        assert_eq!(
            pending_before.len(),
            5,
            "fixture must start with 5 eligible events"
        );
        let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-limit", 3))
                .unwrap();
        assert_eq!(report.requested_limit, 3);
        assert_eq!(report.processed, 3);
        assert!(!report.stopped_no_eligible);
        assert!(!report.stopped_lost_lease);
        assert_eq!(
            consumer.process_one_invocations_for_test(),
            3,
            "must call process_one exactly 3 times, not 4"
        );
        let remaining = storage.list("life").unwrap();
        let pending_after: Vec<_> = remaining
            .iter()
            .filter(|j| j.state == MemoryVectorSyncState::Pending)
            .collect();
        // limit=3: 1 upsert + 2 deletes processed (deleted from outbox on success).
        // Remaining in outbox: 2 untouched deletes (still pending).
        assert_eq!(
            remaining.len(),
            2,
            "outbox must have exactly 2 remaining rows (all untouched deletes)"
        );
        assert_eq!(
            pending_after.len(),
            2,
            "all 2 remaining rows must be pending"
        );
        // Check that remaining pending events have untouched state.
        for job in &pending_after {
            let (_, _, before) = pending_before
                .iter()
                .find(|(life_id, memory_id, _)| {
                    life_id == &job.life_id && memory_id == &job.memory_id
                })
                .expect("remaining event must be one of the initial eligible events");
            let after = storage
                .test_get_outbox_snapshot_detailed(&job.life_id, &job.memory_id)
                .unwrap();
            assert_eq!(after.state, "pending");
            assert_eq!(after.attempt_count, 0);
            assert_eq!(after.lease_owner, None);
            assert_eq!(after.lease_fence_epoch, None);
            assert_eq!(after.lease_expires_at, None);
            assert_eq!(after.claimed_generation_id, None);
            assert_same_outbox_row!(before, &after);
        }
    }

    #[test]
    fn drain_stops_when_no_event_is_eligible() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        storage
            .register_building_vector_generation(
                context.generation_id().as_str(),
                &"d".repeat(64),
                3,
            )
            .unwrap();
        let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-empty", 5))
                .unwrap();
        assert_eq!(report.processed, 0);
        assert!(report.stopped_no_eligible);
    }

    #[test]
    fn drain_fails_closed_on_no_progress() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
        consumer.set_force_no_progress_for_test(true);
        let error =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-no-progress", 5))
                .unwrap_err();
        assert_eq!(error.code, MemoryVectorSyncWorkerErrorCode::InternalError);
        assert_eq!(storage.list("life").unwrap().len(), 0);
    }

    #[test]
    fn drain_classifies_blocked_without_failed() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        // First event: no credential → blocked.
        drain_upsert_fixture(&storage, context.generation_id().as_str());
        let profile = ModelProfile {
            id: "prof-drain-err".into(),
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
            context.clone(),
        );
        // No credential is a blocked event, then no more eligible events remain.
        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-err", 5))
                .unwrap();
        assert_eq!(report.processed, 1);
        assert_eq!(report.applied_upserts, 0);
        assert_eq!(report.applied_deletes, 0);
        assert_eq!(report.retry_scheduled, 0);
        assert_eq!(report.blocked, 1);
        assert_eq!(report.failed, 0);
        assert!(report.stopped_no_eligible);
        assert!(!report.stopped_lost_lease);
    }

    #[test]
    fn drain_classifies_stale_as_failed() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        drain_upsert_fixture(&storage, context.generation_id().as_str());
        let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                .with_forced_stale_result_for_test();

        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-stale", 2))
                .unwrap();

        assert_eq!(report.processed, 1);
        assert_eq!(report.applied_upserts, 0);
        assert_eq!(report.applied_deletes, 0);
        assert_eq!(report.retry_scheduled, 0);
        assert_eq!(report.blocked, 0);
        assert_eq!(report.failed, 1);
        assert!(report.stopped_no_eligible);
        assert!(!report.stopped_lost_lease);
        let job = storage.list("life").unwrap().remove(0);
        assert_eq!(job.state, MemoryVectorSyncState::Blocked);
        assert_eq!(job.attempt_count, 0);
    }

    #[test]
    fn drain_keeps_same_fence_for_same_owner() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        drain_delete_fixture(&storage, context.generation_id().as_str());
        let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let consumer = FencedVectorSyncSingleEventConsumer::new(
            &storage,
            &provider,
            &vectors,
            context.clone(),
        );
        // Same owner draining twice uses the same fence (no increment).
        let report_a =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-a", 5)).unwrap();
        assert_eq!(report_a.processed, 1);
        assert!(report_a.stopped_no_eligible);
        // Enqueue another event; same owner can drain again.
        drain_delete_fixture(&storage, context.generation_id().as_str());
        let report_b =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-a", 5)).unwrap();
        assert_eq!(report_b.processed, 1);
        assert!(!report_b.stopped_lost_lease);
    }

    #[test]
    fn drain_is_strictly_serial() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (_temp, storage) = test_storage();
        let (context, raw_vectors) = drained_context();
        for _ in 0..4 {
            drain_upsert_fixture(&storage, context.generation_id().as_str());
        }
        let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let concurrent = Arc::new(AtomicUsize::new(0));
        let max_seen = Arc::new(AtomicUsize::new(0));
        let lance_upserts = Arc::new(AtomicUsize::new(0));
        let lance_deletes = Arc::new(AtomicUsize::new(0));
        let current_lance_writes = Arc::new(AtomicUsize::new(0));
        let max_concurrent_lance_writes = Arc::new(AtomicUsize::new(0));
        let vectors = CountingVectorStore {
            inner: raw_vectors,
            lance_upserts,
            lance_deletes,
            current_lance_writes,
            max_concurrent_lance_writes: Arc::clone(&max_concurrent_lance_writes),
        };
        struct Tracker {
            inner: Box<dyn EmbeddingProvider>,
            current: Arc<AtomicUsize>,
            max: Arc<AtomicUsize>,
        }
        impl EmbeddingProvider for Tracker {
            fn model_info(&self) -> crate::embedding::EmbeddingModelInfo {
                self.inner.model_info()
            }
            fn model_name(&self) -> &str {
                self.inner.model_name()
            }
            fn vector_dimension(&self) -> Option<usize> {
                self.inner.vector_dimension()
            }
            fn embed<'a>(
                &'a self,
                request: crate::embedding::EmbeddingRequest,
            ) -> crate::embedding::EmbeddingFuture<
                'a,
                Result<crate::embedding::EmbeddingBatch, crate::embedding::EmbeddingError>,
            > {
                let prev = self.current.fetch_add(1, Ordering::SeqCst);
                let cur = prev + 1;
                self.max.fetch_max(cur, Ordering::SeqCst);
                Box::pin(async move {
                    let _ = self.current.fetch_sub(1, Ordering::SeqCst);
                    self.inner.embed(request).await
                })
            }
        }
        let tracker = Tracker {
            inner: Box::new(provider),
            current: Arc::clone(&concurrent),
            max: Arc::clone(&max_seen),
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &tracker, &vectors, context);
        tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-serial", 4)).unwrap();
        assert_eq!(
            max_seen.load(Ordering::SeqCst),
            1,
            "max concurrent embedding calls must be 1"
        );
        assert_eq!(
            max_concurrent_lance_writes.load(Ordering::SeqCst),
            1,
            "max concurrent Lance writes must be 1"
        );
    }

    #[test]
    fn drain_skips_legacy_quarantine() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        storage
            .register_building_vector_generation(
                context.generation_id().as_str(),
                &"d".repeat(64),
                3,
            )
            .unwrap();
        storage
            .test_insert_legacy_quarantine_fixture("legacy-quar", "upsert")
            .unwrap();
        // Now also enqueue a post-012 delete.
        let mem = confirmed(&storage, false);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: mem.life_id.clone(),
                memory_id: mem.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
        let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-quar", 5))
                .unwrap();
        assert_eq!(report.processed, 1);
        assert_eq!(report.applied_deletes, 1);
    }

    #[test]
    fn drain_stops_immediately_after_lost_lease() {
        let (temp, storage_a) = test_storage();
        let storage_a = Arc::new(storage_a);
        let descriptor = "d".repeat(64);
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-lost-drain").unwrap(),
            descriptor.clone(),
            3,
        )
        .unwrap();
        storage_a
            .register_building_vector_generation(context.generation_id().as_str(), &descriptor, 3)
            .unwrap();
        let raw_vectors = tauri::async_runtime::block_on(
            crate::vector_store::LanceDbVectorStore::open(temp.path().join("lance")),
        )
        .unwrap();
        tauri::async_runtime::block_on(raw_vectors.create_generation(&context)).unwrap();
        let lance_upserts = Arc::new(AtomicUsize::new(0));
        let lance_deletes = Arc::new(AtomicUsize::new(0));
        let current_lance_writes = Arc::new(AtomicUsize::new(0));
        let max_concurrent_lance_writes = Arc::new(AtomicUsize::new(0));
        let vectors = CountingVectorStore {
            inner: raw_vectors,
            lance_upserts: Arc::clone(&lance_upserts),
            lance_deletes: Arc::clone(&lance_deletes),
            current_lance_writes: Arc::clone(&current_lance_writes),
            max_concurrent_lance_writes: Arc::clone(&max_concurrent_lance_writes),
        };
        // First event completes a real delete; second loses its fence after a
        // real embedding response, and the third must remain unclaimed.
        drain_delete_fixture(storage_a.as_ref(), context.generation_id().as_str());
        drain_upsert_fixture(storage_a.as_ref(), context.generation_id().as_str());
        drain_upsert_fixture(storage_a.as_ref(), context.generation_id().as_str());
        // Capture the third event's identity before the drain.
        let all_before = storage_a.list("life").unwrap();
        let mut pending_events: Vec<_> = all_before
            .iter()
            .filter(|j| j.state == MemoryVectorSyncState::Pending)
            .collect();
        let third_event = pending_events
            .pop()
            .expect("third event must exist before drain");
        let third_life = third_event.life_id.clone();
        let third_memory = third_event.memory_id.clone();
        let third_before = storage_a
            .test_get_outbox_snapshot_detailed(&third_life, &third_memory)
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let transport_requests = Arc::new(AtomicUsize::new(0));
        let transport_counter = Arc::clone(&transport_requests);
        let server = thread::spawn(move || {
            use std::io::Write;
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            transport_counter.fetch_add(1, Ordering::SeqCst);
            let body = r#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]}],"model":"test-embedding-model","usage":{"prompt_tokens":1,"total_tokens":1}}"#;
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            stream.write_all(response.as_bytes()).unwrap();
        });
        let profile = ModelProfile {
            id: "profile-lost-drain".into(),
            purpose: ModelPurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "lost drain".into(),
            base_url: format!("http://127.0.0.1:{port}/v1"),
            model_name: "test-embedding-model".into(),
            temperature: None,
            max_tokens: None,
            embedding_dimension: Some(3),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        let raw_secrets = InMemorySecretStore::new();
        raw_secrets
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, profile.id.clone())
                    .unwrap(),
                SecretValue::new("test-key".into()).unwrap(),
            )
            .unwrap();
        let credential_reads = Arc::new(AtomicUsize::new(0));
        let secrets = CountingSecretStore::new(raw_secrets, Arc::clone(&credential_reads));
        let raw_provider =
            crate::embedding::build_openai_compatible_embedding_provider(&profile, &secrets)
                .unwrap();
        let provider_requests = Arc::new(AtomicUsize::new(0));
        let embedding_successes = Arc::new(AtomicUsize::new(0));
        let provider = CountingEmbeddingProvider {
            inner: raw_provider.as_ref(),
            provider_requests: Arc::clone(&provider_requests),
            embedding_successes: Arc::clone(&embedding_successes),
        };
        let mut consumer = FencedVectorSyncSingleEventConsumer::new(
            storage_a.as_ref(),
            &provider,
            &vectors,
            context.clone(),
        );
        let storage_for_pause = Arc::clone(&storage_a);
        consumer.set_test_pause_hook_for_test(Some(Box::new(move |point| {
            if point == VectorSyncTestPausePoint::AfterEmbeddingBeforeLance {
                storage_for_pause
                    .test_expire_fenced_runtime_lease()
                    .unwrap();
            }
        })));
        let frozen_counters = Arc::new(Mutex::new(None));
        let frozen_counters_capture = Arc::clone(&frozen_counters);
        let frozen_credential_reads = Arc::clone(&credential_reads);
        let frozen_provider_requests = Arc::clone(&provider_requests);
        let frozen_transport_requests = Arc::clone(&transport_requests);
        let frozen_embedding_successes = Arc::clone(&embedding_successes);
        let frozen_lance_upserts = Arc::clone(&lance_upserts);
        let frozen_lance_deletes = Arc::clone(&lance_deletes);
        consumer.set_drain_iteration_hook_for_test(Some(Box::new(
            move |_processed, report, storage, process_one_invocations| {
                if report.stopped_lost_lease {
                    *frozen_counters_capture.lock().unwrap() = Some(IoCounterSnapshot {
                        credential_reads: frozen_credential_reads.load(Ordering::SeqCst),
                        provider_requests: frozen_provider_requests.load(Ordering::SeqCst),
                        transport_requests: frozen_transport_requests.load(Ordering::SeqCst),
                        embedding_successes: frozen_embedding_successes.load(Ordering::SeqCst),
                        lance_upserts: frozen_lance_upserts.load(Ordering::SeqCst),
                        lance_deletes: frozen_lance_deletes.load(Ordering::SeqCst),
                        generation_item_writes: storage.test_generation_item_count().unwrap(),
                        process_one_invocations,
                    });
                }
            },
        )));
        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "owner-a", 5))
                .unwrap();
        consumer.set_test_pause_hook_for_test(None);
        consumer.set_drain_iteration_hook_for_test(None);
        server.join().unwrap();
        assert_eq!(report.processed, 1);
        assert!(report.stopped_lost_lease);
        assert!(!report.stopped_no_eligible);
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 1);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
        assert_eq!(credential_reads.load(Ordering::SeqCst), 1);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 1);
        assert_eq!(transport_requests.load(Ordering::SeqCst), 1);
        assert_eq!(storage_a.test_generation_item_count().unwrap(), 0);
        let remaining = storage_a.list("life").unwrap();
        assert_eq!(
            remaining.len(),
            2,
            "old token cannot finalize second or touch third"
        );
        let processing = remaining
            .iter()
            .find(|job| job.state == MemoryVectorSyncState::Processing)
            .unwrap();
        assert_eq!(
            storage_a
                .test_get_outbox_snapshot_detailed(&processing.life_id, &processing.memory_id)
                .unwrap()
                .last_send_disposition
                .as_deref(),
            Some("possibly_sent")
        );
        // Third event detailed snapshot: completely untouched.
        let third_after = storage_a
            .test_get_outbox_snapshot_detailed(&third_life, &third_memory)
            .unwrap();
        assert_same_outbox_row!(&third_before, &third_after);
        let database =
            rusqlite::Connection::open(storage_a.test_database_main_path().unwrap()).unwrap();
        let third_generation_items: usize = database
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_generation_item WHERE generation_id=?1 AND life_id=?2 AND memory_id=?3",
                rusqlite::params![context.generation_id().as_str(), &third_life, &third_memory],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            third_generation_items, 0,
            "third event must have no generation item"
        );
        let lance_metadata =
            tauri::async_runtime::block_on(vectors.sample_generation_metadata(&context, 32))
                .unwrap();
        assert!(
            lance_metadata
                .iter()
                .all(|row| row.life_id != third_life || row.memory_id != third_memory),
            "third event must have no Lance row"
        );
        // No generation item or Lance write was committed before the fence loss.
        assert_eq!(
            storage_a.test_generation_item_count().unwrap(),
            0,
            "no generation items exist (the pending third event was never touched)"
        );
        // I/O counters freeze: after LostLease, no additional I/O occurred.
        // The counters below are for the first event only.  The test's pause hook
        // ensures owner B takes over at AfterEmbeddingBeforeLance of the second event.
        // No processing of the third event ever began.
        let after_counters = IoCounterSnapshot {
            credential_reads: credential_reads.load(Ordering::SeqCst),
            provider_requests: provider_requests.load(Ordering::SeqCst),
            transport_requests: transport_requests.load(Ordering::SeqCst),
            embedding_successes: embedding_successes.load(Ordering::SeqCst),
            lance_upserts: lance_upserts.load(Ordering::SeqCst),
            lance_deletes: lance_deletes.load(Ordering::SeqCst),
            generation_item_writes: storage_a.test_generation_item_count().unwrap(),
            process_one_invocations: consumer.process_one_invocations_for_test(),
        };
        let frozen_counters = frozen_counters
            .lock()
            .unwrap()
            .take()
            .expect("must snapshot counters at the LostLease stop point");
        assert_eq!(
            frozen_counters, after_counters,
            "all I/O must freeze after LostLease"
        );
        assert_eq!(
            after_counters,
            IoCounterSnapshot {
                credential_reads: 1,
                provider_requests: 1,
                transport_requests: 1,
                embedding_successes: 1,
                lance_upserts: 0,
                lance_deletes: 1,
                generation_item_writes: 0,
                process_one_invocations: 2,
            }
        );
    }

    #[test]
    fn drain_uses_only_explicit_generation() {
        let (temp, storage) = test_storage();
        let desc_a = "a".repeat(64);
        let desc_b = "b".repeat(64);
        let gen_a = crate::vector_store::VectorGenerationId::parse("gen-a").unwrap();
        let gen_b = crate::vector_store::VectorGenerationId::parse("gen-b").unwrap();
        let context_a = VectorGenerationContext::new(gen_a.clone(), desc_a.clone(), 3).unwrap();
        let context_b = VectorGenerationContext::new(gen_b.clone(), desc_b.clone(), 3).unwrap();
        // Register both generations.
        storage
            .register_building_vector_generation("gen-a", &desc_a, 3)
            .unwrap();
        storage
            .register_building_vector_generation("gen-b", &desc_b, 3)
            .unwrap();
        let vectors_a = tauri::async_runtime::block_on(
            crate::vector_store::LanceDbVectorStore::open(temp.path().join("lance-a")),
        )
        .unwrap();
        let vectors_b = tauri::async_runtime::block_on(
            crate::vector_store::LanceDbVectorStore::open(temp.path().join("lance-b")),
        )
        .unwrap();
        tauri::async_runtime::block_on(vectors_a.create_generation(&context_a)).unwrap();
        tauri::async_runtime::block_on(vectors_b.create_generation(&context_b)).unwrap();
        // Two real upserts are claimed under A. No worker may consult or write B.
        for _ in 0..2 {
            let memory = confirmed(&storage, false);
            storage
                .enqueue(EnqueueMemoryVectorSyncRequest {
                    life_id: memory.life_id.clone(),
                    memory_id: memory.id.clone(),
                    desired_action: MemoryVectorSyncAction::Upsert,
                })
                .unwrap();
        }
        let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let claims = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&claims);
        let consumer_a = FencedVectorSyncSingleEventConsumer::new(
            &storage,
            &provider,
            &vectors_a,
            context_a.clone(),
        );
        consumer_a.set_claim_observer_for_test(Some(Box::new(move |claim| {
            observed
                .lock()
                .unwrap()
                .push(claim.generation_id().to_owned());
        })));
        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer_a, "w-gen-a", 5))
                .unwrap();
        assert_eq!(report.processed, 2);
        assert_eq!(report.applied_upserts, 2);
        assert_eq!(claims.lock().unwrap().as_slice(), ["gen-a", "gen-a"]);
        assert_eq!(storage.test_generation_item_count().unwrap(), 2);
        assert_eq!(
            tauri::async_runtime::block_on(vectors_a.count_generation(&context_a, None)).unwrap(),
            2,
            "generation A must receive real Lance rows"
        );
        assert_eq!(
            tauri::async_runtime::block_on(vectors_b.count_generation(&context_b, None)).unwrap(),
            0,
            "generation B must have no Lance rows"
        );
    }

    #[test]
    fn drain_can_observe_new_mutation_between_iterations() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        storage
            .register_building_vector_generation(
                context.generation_id().as_str(),
                &"d".repeat(64),
                3,
            )
            .unwrap();
        // First event — drain will process it in iteration 1.
        let mem1 = confirmed(&storage, false);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: mem1.life_id.clone(),
                memory_id: mem1.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
        let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let mut consumer = FencedVectorSyncSingleEventConsumer::new(
            &storage,
            &provider,
            &vectors,
            context.clone(),
        );
        let enqueued = std::cell::Cell::new(false);
        // Hook fires after each iteration with access to storage.
        consumer.set_drain_iteration_hook_for_test(Some(Box::new(
            move |processed: usize,
                  _report: &VectorSyncDrainReport,
                  storage: &StorageService,
                  _process_one_invocations: usize| {
                if processed == 1 && !enqueued.get() {
                    enqueued.set(true);
                    let mem2 = confirmed(storage, false);
                    storage
                        .enqueue(EnqueueMemoryVectorSyncRequest {
                            life_id: mem2.life_id.clone(),
                            memory_id: mem2.id.clone(),
                            desired_action: MemoryVectorSyncAction::Delete,
                        })
                        .unwrap();
                }
            },
        )));
        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-new", 5))
                .unwrap();
        assert_eq!(
            report.processed, 2,
            "must process both events: first iteration + second after hook"
        );
        assert!(report.stopped_no_eligible, "must stop when no more events");
    }

    #[test]
    fn drain_continues_after_event_level_failures() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        storage
            .register_building_vector_generation(
                context.generation_id().as_str(),
                &"d".repeat(64),
                3,
            )
            .unwrap();
        // Each result is produced by a claim and the normal finalize path:
        // recoverable provider error, non-recoverable provider error, stale
        // authority seam, then a real delete.
        for _ in 0..3 {
            drain_upsert_fixture(&storage, context.generation_id().as_str());
        }
        drain_delete_fixture(&storage, context.generation_id().as_str());
        let provider = MixedOutcomeEmbeddingProvider {
            inner: crate::embedding::DeterministicEmbeddingProvider::new(3),
            requests: AtomicUsize::new(0),
        };
        let claims = Arc::new(Mutex::new(Vec::new()));
        let claims_capture = Arc::clone(&claims);
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
        consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
            claims_capture
                .lock()
                .unwrap()
                .push((claim.life_id().to_owned(), claim.memory_id().to_owned()));
        })));
        consumer.set_stale_on_claim_for_test(3);
        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-mix", 10))
                .unwrap();
        assert_eq!(report.processed, 4);
        assert_eq!(report.retry_scheduled, 1);
        assert_eq!(report.blocked, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.applied_deletes, 1);
        assert_eq!(report.applied_upserts, 0);
        assert!(report.stopped_no_eligible);
        assert!(!report.stopped_lost_lease);
        assert_eq!(provider.requests.load(Ordering::SeqCst), 2);
        assert_eq!(consumer.process_one_invocations_for_test(), 5);
        let claims = claims.lock().unwrap().clone();
        assert_eq!(
            claims.len(),
            4,
            "each fixture event must be claimed exactly once"
        );
        for (index, claim) in claims.iter().enumerate() {
            assert!(
                !claims[..index].contains(claim),
                "event {claim:?} was claimed more than once in one drain"
            );
        }
        let jobs = storage.list("life").unwrap();
        assert_eq!(jobs.len(), 3);
        let retry = storage
            .test_get_outbox_snapshot_detailed(&claims[0].0, &claims[0].1)
            .unwrap();
        assert_eq!(retry.state, "retry_wait");
        assert_eq!(retry.attempt_count, 1);
        let blocked = storage
            .test_get_outbox_snapshot_detailed(&claims[1].0, &claims[1].1)
            .unwrap();
        assert_eq!(blocked.state, "blocked");
        assert_eq!(blocked.attempt_count, 1);
        let stale = storage
            .test_get_outbox_snapshot_detailed(&claims[2].0, &claims[2].1)
            .unwrap();
        assert_eq!(stale.state, "blocked");
        assert_eq!(
            stale.last_error_code.as_deref(),
            Some("VECTOR_TARGET_STALE")
        );
        assert!(
            !jobs
                .iter()
                .any(|job| job.life_id == claims[3].0 && job.memory_id == claims[3].1),
            "completed delete must remove its outbox row"
        );
    }

    #[test]
    fn drain_strengthened_quarantine_zero_io() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        storage
            .register_building_vector_generation(
                context.generation_id().as_str(),
                &"d".repeat(64),
                3,
            )
            .unwrap();
        // Insert a legacy quarantine fixture for life="life" so list("life") finds it.
        storage
            .test_insert_legacy_quarantine_fixture("life", "legacy-qz")
            .unwrap();
        let before_quarantine = storage
            .test_get_outbox_snapshot_detailed("life", "legacy-qz")
            .unwrap();
        assert_eq!(before_quarantine.state, "blocked");
        assert_eq!(
            before_quarantine.migration_disposition.as_deref(),
            Some("legacy_upsert_rebuild_required")
        );
        let credential_reads = Arc::new(AtomicUsize::new(0));
        let raw_secrets = InMemorySecretStore::new();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let profile = ModelProfile {
            id: "profile-quarantine-zero-io".into(),
            purpose: ModelPurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "quarantine zero io".into(),
            base_url: format!("http://{}", listener.local_addr().unwrap()),
            model_name: "test-embedding-model".into(),
            temperature: None,
            max_tokens: None,
            embedding_dimension: Some(3),
            created_at: "2026-01-01T00:00:00Z".into(),
            updated_at: "2026-01-01T00:00:00Z".into(),
        };
        raw_secrets
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, profile.id.clone())
                    .unwrap(),
                SecretValue::new("test-key".into()).unwrap(),
            )
            .unwrap();
        let secrets = CountingSecretStore::new(raw_secrets, Arc::clone(&credential_reads));
        let raw_provider =
            crate::embedding::build_openai_compatible_embedding_provider(&profile, &secrets)
                .unwrap();
        let provider_requests = Arc::new(AtomicUsize::new(0));
        let embedding_successes = Arc::new(AtomicUsize::new(0));
        let provider = CountingEmbeddingProvider {
            inner: raw_provider.as_ref(),
            provider_requests: Arc::clone(&provider_requests),
            embedding_successes: Arc::clone(&embedding_successes),
        };
        let lance_upserts = Arc::new(AtomicUsize::new(0));
        let lance_deletes = Arc::new(AtomicUsize::new(0));
        let vectors = CountingVectorStore {
            inner: vectors,
            lance_upserts: Arc::clone(&lance_upserts),
            lance_deletes: Arc::clone(&lance_deletes),
            current_lance_writes: Arc::new(AtomicUsize::new(0)),
            max_concurrent_lance_writes: Arc::new(AtomicUsize::new(0)),
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-qz", 5)).unwrap();
        assert_eq!(
            report.processed, 0,
            "quarantine events must not count as processed"
        );
        assert!(
            report.stopped_no_eligible,
            "must stop when nothing is eligible"
        );
        assert!(!report.stopped_lost_lease);
        assert_eq!(consumer.process_one_invocations_for_test(), 1);
        assert_eq!(
            credential_reads.load(Ordering::SeqCst),
            0,
            "no credential reads must occur for quarantine-only outbox"
        );
        assert_eq!(provider_requests.load(Ordering::SeqCst), 0);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 0);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);
        assert_eq!(storage.test_generation_item_count().unwrap(), 0);
        let transport_requests = match listener.accept() {
            Ok(_) => 1,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => 0,
            Err(error) => panic!("failed to observe quarantine test transport: {error}"),
        };
        assert_eq!(transport_requests, 0, "no D-8 transport request is allowed");
        let after_quarantine = storage
            .test_get_outbox_snapshot_detailed("life", "legacy-qz")
            .unwrap();
        assert_same_outbox_row!(&before_quarantine, &after_quarantine);
        assert_eq!(after_quarantine.state, "blocked");
        assert_eq!(
            after_quarantine.migration_disposition.as_deref(),
            Some("legacy_upsert_rebuild_required")
        );
    }

    #[test]
    fn retry_decision_classifies_the_fenced_failure_matrix_without_io() {
        struct Case {
            error: RetryErrorClass,
            safety: EmbeddingRetrySafety,
            operation: RetryOperation,
            disposition: RetryDisposition,
            code: StableVectorSyncErrorCode,
            provider_slot: bool,
        }

        let cases = [
            Case {
                error: RetryErrorClass::Embedding(EmbeddingRetryClass::CredentialUnavailable),
                safety: EmbeddingRetrySafety::DefinitelyNotSent,
                operation: RetryOperation::Upsert,
                disposition: RetryDisposition::Retryable,
                code: StableVectorSyncErrorCode::ProviderUnavailable,
                provider_slot: true,
            },
            Case {
                error: RetryErrorClass::Embedding(EmbeddingRetryClass::CredentialReadFailed),
                safety: EmbeddingRetrySafety::DefinitelyNotSent,
                operation: RetryOperation::Upsert,
                disposition: RetryDisposition::Retryable,
                code: StableVectorSyncErrorCode::ProviderUnavailable,
                provider_slot: true,
            },
            Case {
                error: RetryErrorClass::Embedding(EmbeddingRetryClass::TransportUnavailable),
                safety: EmbeddingRetrySafety::DefinitelyNotSent,
                operation: RetryOperation::Upsert,
                disposition: RetryDisposition::Retryable,
                code: StableVectorSyncErrorCode::ProviderUnavailable,
                provider_slot: true,
            },
            Case {
                error: RetryErrorClass::Embedding(EmbeddingRetryClass::RequestTimeout),
                safety: EmbeddingRetrySafety::DefinitelyNotSent,
                operation: RetryOperation::Upsert,
                disposition: RetryDisposition::Retryable,
                code: StableVectorSyncErrorCode::RequestTimeout,
                provider_slot: true,
            },
            Case {
                error: RetryErrorClass::Embedding(EmbeddingRetryClass::RequestTimeout),
                safety: EmbeddingRetrySafety::PossiblySent,
                operation: RetryOperation::Upsert,
                disposition: RetryDisposition::ProviderResultUnknown,
                code: StableVectorSyncErrorCode::ProviderResultUnknown,
                provider_slot: true,
            },
            Case {
                error: RetryErrorClass::Embedding(EmbeddingRetryClass::RateLimited),
                safety: EmbeddingRetrySafety::ResponseReceived,
                operation: RetryOperation::Upsert,
                disposition: RetryDisposition::Retryable,
                code: StableVectorSyncErrorCode::RateLimited,
                provider_slot: true,
            },
            Case {
                error: RetryErrorClass::Embedding(EmbeddingRetryClass::CredentialNotConfigured),
                safety: EmbeddingRetrySafety::DefinitelyNotSent,
                operation: RetryOperation::Upsert,
                disposition: RetryDisposition::Blocked,
                code: StableVectorSyncErrorCode::AuthenticationFailed,
                provider_slot: true,
            },
            Case {
                error: RetryErrorClass::Embedding(EmbeddingRetryClass::AuthenticationRejected),
                safety: EmbeddingRetrySafety::ResponseReceived,
                operation: RetryOperation::Upsert,
                disposition: RetryDisposition::Blocked,
                code: StableVectorSyncErrorCode::AuthenticationFailed,
                provider_slot: true,
            },
            Case {
                error: RetryErrorClass::Embedding(EmbeddingRetryClass::OtherClientError),
                safety: EmbeddingRetrySafety::ResponseReceived,
                operation: RetryOperation::Upsert,
                disposition: RetryDisposition::Blocked,
                code: StableVectorSyncErrorCode::InvalidRequest,
                provider_slot: true,
            },
            Case {
                error: RetryErrorClass::Embedding(EmbeddingRetryClass::ProviderUnavailable),
                safety: EmbeddingRetrySafety::ResponseReceived,
                operation: RetryOperation::Upsert,
                disposition: RetryDisposition::Retryable,
                code: StableVectorSyncErrorCode::ProviderUnavailable,
                provider_slot: true,
            },
            Case {
                error: RetryErrorClass::Embedding(EmbeddingRetryClass::InvalidProviderResponse),
                safety: EmbeddingRetrySafety::ResponseReceived,
                operation: RetryOperation::Upsert,
                disposition: RetryDisposition::Blocked,
                code: StableVectorSyncErrorCode::InvalidProviderResponse,
                provider_slot: true,
            },
            Case {
                error: RetryErrorClass::Embedding(EmbeddingRetryClass::DimensionMismatch),
                safety: EmbeddingRetrySafety::ResponseReceived,
                operation: RetryOperation::Upsert,
                disposition: RetryDisposition::Blocked,
                code: StableVectorSyncErrorCode::EmbeddingDimensionMismatch,
                provider_slot: true,
            },
            Case {
                error: RetryErrorClass::EmbeddingInvalidVector,
                safety: EmbeddingRetrySafety::ResponseReceived,
                operation: RetryOperation::Upsert,
                disposition: RetryDisposition::Blocked,
                code: StableVectorSyncErrorCode::EmbeddingInvalidVector,
                provider_slot: false,
            },
            Case {
                error: RetryErrorClass::LanceTransient,
                safety: EmbeddingRetrySafety::ResponseReceived,
                operation: RetryOperation::Delete,
                disposition: RetryDisposition::Retryable,
                code: StableVectorSyncErrorCode::LanceTransient,
                provider_slot: false,
            },
            Case {
                error: RetryErrorClass::LancePermanent,
                safety: EmbeddingRetrySafety::ResponseReceived,
                operation: RetryOperation::Delete,
                disposition: RetryDisposition::Blocked,
                code: StableVectorSyncErrorCode::LancePermanent,
                provider_slot: false,
            },
            Case {
                error: RetryErrorClass::InternalInvariant,
                safety: EmbeddingRetrySafety::DefinitelyNotSent,
                operation: RetryOperation::Delete,
                disposition: RetryDisposition::Blocked,
                code: StableVectorSyncErrorCode::InternalInvariant,
                provider_slot: false,
            },
        ];

        for case in cases {
            let decision = retry_decision(case.error, case.safety, 1, case.operation);
            assert_eq!(decision.retry_safety, case.safety);
            assert_eq!(decision.disposition, case.disposition);
            assert_eq!(decision.stable_error_code, case.code);
            assert!(decision.consumes_attempt);
            assert_eq!(decision.consumes_provider_slot, case.provider_slot);
            assert_eq!(
                decision.requires_follow_up,
                case.disposition == RetryDisposition::ProviderResultUnknown
            );
        }
    }

    #[test]
    fn retry_decision_fails_closed_at_and_above_the_attempt_limit() {
        for attempt_count in [1, 4] {
            let decision = retry_decision(
                RetryErrorClass::Embedding(EmbeddingRetryClass::RateLimited),
                EmbeddingRetrySafety::ResponseReceived,
                attempt_count,
                RetryOperation::Upsert,
            );
            assert_eq!(decision.disposition, RetryDisposition::Retryable);
            assert!(!decision.blocked_by_attempt_limit);
        }
        for attempt_count in [MAX_VECTOR_SYNC_ATTEMPTS, 6, u32::MAX] {
            let decision = retry_decision(
                RetryErrorClass::Embedding(EmbeddingRetryClass::RateLimited),
                EmbeddingRetrySafety::ResponseReceived,
                attempt_count,
                RetryOperation::Upsert,
            );
            assert_eq!(decision.disposition, RetryDisposition::Blocked);
            assert!(decision.blocked_by_attempt_limit);
            assert!(decision.consumes_attempt);
            assert!(decision.consumes_provider_slot);
        }
    }

    #[test]
    fn retry_classification_is_redacted_and_never_parses_dynamic_error_text() {
        let decision = retry_decision(
            RetryErrorClass::Embedding(EmbeddingRetryClass::InvalidProviderResponse),
            EmbeddingRetrySafety::ResponseReceived,
            1,
            RetryOperation::Upsert,
        );
        let rendered = format!("{decision:?}");
        for canary in [
            "https://provider.invalid/v1",
            "Authorization",
            "credential-canary",
            "response-body-canary",
            "vector-canary",
        ] {
            assert!(!rendered.contains(canary));
        }
        assert_eq!(
            decision.stable_error_code.as_str(),
            "INVALID_PROVIDER_RESPONSE"
        );
    }

    #[test]
    fn retry_delay_is_deterministic_and_fails_closed_at_invalid_attempts() {
        let cases = [
            (0, RetryDelayDecision::InvalidOrOverflow),
            (
                1,
                RetryDelayDecision::RetryAfter {
                    delay_millis: 30_000,
                },
            ),
            (
                2,
                RetryDelayDecision::RetryAfter {
                    delay_millis: 60_000,
                },
            ),
            (
                3,
                RetryDelayDecision::RetryAfter {
                    delay_millis: 120_000,
                },
            ),
            (
                4,
                RetryDelayDecision::RetryAfter {
                    delay_millis: 240_000,
                },
            ),
            (5, RetryDelayDecision::BlockedAtAttemptLimit),
            (6, RetryDelayDecision::BlockedAtAttemptLimit),
            (u32::MAX, RetryDelayDecision::BlockedAtAttemptLimit),
        ];
        for (attempt_count, expected) in cases {
            assert_eq!(retry_delay_millis(attempt_count), expected);
        }
    }

    #[test]
    fn retry_clock_is_instance_scoped_and_can_move_backward_or_forward() {
        let clock = FixedRetryClock::new(100_000);
        assert_eq!(clock.now_utc_millis().unwrap(), 100_000);
        clock.set(90_000);
        assert_eq!(clock.now_utc_millis().unwrap(), 90_000);
        clock.set(150_000);
        assert_eq!(clock.now_utc_millis().unwrap(), 150_000);
    }

    #[test]
    fn failure_finalize_uses_persisted_attempt_count_for_retry_and_blocked_outcomes() {
        for (prior_attempts, expected_result, expected_state, expected_time) in [
            (
                0_i64,
                FencedVectorSyncSingleEventResult::RetryWait,
                MemoryVectorSyncState::RetryWait,
                Some("1970-01-01T00:02:10.000Z"),
            ),
            (
                1_i64,
                FencedVectorSyncSingleEventResult::RetryWait,
                MemoryVectorSyncState::RetryWait,
                Some("1970-01-01T00:02:40.000Z"),
            ),
            (
                3_i64,
                FencedVectorSyncSingleEventResult::RetryWait,
                MemoryVectorSyncState::RetryWait,
                Some("1970-01-01T00:05:40.000Z"),
            ),
            (
                4_i64,
                FencedVectorSyncSingleEventResult::Blocked,
                MemoryVectorSyncState::Blocked,
                None,
            ),
            (
                5_i64,
                FencedVectorSyncSingleEventResult::Blocked,
                MemoryVectorSyncState::Blocked,
                None,
            ),
        ] {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            storage
                .register_building_vector_generation(
                    context.generation_id().as_str(),
                    &"d".repeat(64),
                    3,
                )
                .unwrap();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            storage
                .test_set_fenced_attempt_count(prior_attempts)
                .unwrap();
            let provider = MixedOutcomeEmbeddingProvider {
                inner: crate::embedding::DeterministicEmbeddingProvider::new(3),
                requests: AtomicUsize::new(0),
            };
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                    .with_retry_clock_for_test(Box::new(FixedRetryClock::new(100_000)));

            assert_eq!(
                tauri::async_runtime::block_on(consumer.process_one("attempt-boundary")).unwrap(),
                expected_result
            );
            let job = storage.list("life").unwrap().remove(0);
            assert_eq!(job.state, expected_state);
            assert_eq!(job.attempt_count as i64, prior_attempts + 1);
            assert_eq!(job.next_attempt_at.as_deref(), expected_time);
            assert_eq!(job.last_error_code.as_deref(), Some("PROVIDER_UNAVAILABLE"));
        }
    }

    #[test]
    fn same_drain_uses_one_retry_cutoff_and_does_not_reclaim_its_retry_wait_row() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        storage
            .register_building_vector_generation(
                context.generation_id().as_str(),
                &"d".repeat(64),
                3,
            )
            .unwrap();
        drain_upsert_fixture(&storage, context.generation_id().as_str());
        drain_delete_fixture(&storage, context.generation_id().as_str());
        let provider = MixedOutcomeEmbeddingProvider {
            inner: crate::embedding::DeterministicEmbeddingProvider::new(3),
            requests: AtomicUsize::new(0),
        };
        let clock = FixedRetryClock::new(100_000);
        let advance_clock = clock.clone();
        let mut consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                .with_retry_clock_for_test(Box::new(clock));
        consumer.set_drain_iteration_hook_for_test(Some(Box::new(move |processed, _, _, _| {
            if processed == 1 {
                advance_clock.set(200_000);
            }
        })));

        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "retry-cutoff", 5))
                .unwrap();
        assert_eq!(report.retry_scheduled, 1);
        assert_eq!(report.applied_deletes, 1);
        assert_eq!(report.processed, 2);
        assert!(report.stopped_no_eligible);
        assert_eq!(provider.requests.load(Ordering::SeqCst), 1);
        let retry = storage.list("life").unwrap().remove(0);
        assert_eq!(retry.state, MemoryVectorSyncState::RetryWait);
        assert_eq!(retry.attempt_count, 1);
        assert_eq!(
            retry.next_attempt_at.as_deref(),
            Some("1970-01-01T00:02:10.000Z")
        );
    }

    #[test]
    fn cost_budget_caps_provider_invocations_at_drain_limit() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        for _ in 0..MAX_DRAIN_LIMIT {
            drain_upsert_fixture(&storage, context.generation_id().as_str());
        }
        let provider_requests = Arc::new(AtomicUsize::new(0));
        let embedding_successes = Arc::new(AtomicUsize::new(0));
        let inner = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let provider = CountingEmbeddingProvider {
            inner: &inner,
            provider_requests: Arc::clone(&provider_requests),
            embedding_successes: Arc::clone(&embedding_successes),
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                .with_retry_clock_for_test(Box::new(FixedRetryClock::new(100_000)));

        let report = tauri::async_runtime::block_on(drain_fenced_vector_sync(
            &consumer,
            "cost-budget",
            MAX_DRAIN_LIMIT,
        ))
        .unwrap();
        assert_eq!(report.processed, MAX_DRAIN_LIMIT);
        assert_eq!(report.applied_upserts, MAX_DRAIN_LIMIT);
        assert_eq!(report.requested_limit, MAX_DRAIN_LIMIT);
        assert_eq!(consumer.process_one_invocations_for_test(), MAX_DRAIN_LIMIT);
        assert_eq!(provider_requests.load(Ordering::SeqCst), MAX_DRAIN_LIMIT);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), MAX_DRAIN_LIMIT);
        assert!(storage.list("life").unwrap().is_empty());
    }

    #[test]
    fn same_drain_unknown_result_never_reclaims() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        drain_upsert_fixture(&storage, context.generation_id().as_str());
        drain_delete_fixture(&storage, context.generation_id().as_str());
        let provider = PossiblySentEmbeddingProvider {
            inner: crate::embedding::DeterministicEmbeddingProvider::new(3),
            requests: AtomicUsize::new(0),
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                .with_retry_clock_for_test(Box::new(FixedRetryClock::new(100_000)));

        let first = tauri::async_runtime::block_on(drain_fenced_vector_sync(
            &consumer,
            "unknown-same-drain",
            2,
        ))
        .unwrap();
        assert_eq!(first.processed, 2);
        assert_eq!(first.blocked, 1);
        assert_eq!(first.applied_deletes, 1);
        assert_eq!(provider.requests.load(Ordering::SeqCst), 1);

        let second = tauri::async_runtime::block_on(drain_fenced_vector_sync(
            &consumer,
            "unknown-same-drain",
            2,
        ))
        .unwrap();
        assert_eq!(second.processed, 0);
        assert!(second.stopped_no_eligible);
        assert_eq!(provider.requests.load(Ordering::SeqCst), 1);
    }
}
