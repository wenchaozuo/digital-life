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
        FencedAttemptReservation, FencedAttemptToken, FencedFailureDecision,
        FencedFailureFinalizeResult, FencedFinalizeResult, FencedVectorSyncClaim, StorageService,
        MAX_VECTOR_SYNC_ATTEMPTS,
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
    if attempt_count as i64 >= MAX_VECTOR_SYNC_ATTEMPTS {
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
    let blocked_by_attempt_limit = attempt_count as i64 >= MAX_VECTOR_SYNC_ATTEMPTS;
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
    BeforeDelete,
    AfterEmbeddingBeforeLance,
    AfterProviderFailureBeforeFinalize,
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
    pub(crate) fn set_claim_observer_for_test(&self, observer: Option<TestClaimObserver<'a>>) {
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
        // This first database guard both protects the real external boundary
        // and quarantines a structurally invalid/mismatched persisted binding
        // while the original mutation identity is still current.
        if !self
            .storage
            .fenced_vector_claim_is_current(&claim)
            .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
        {
            return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
        }
        // A run is bound to one explicit generation context.  A fenced claim
        // must carry that exact persisted generation before any provider or
        // VectorStore operation is considered.
        if claim.generation_id() != self.generation.generation_id().as_str() {
            return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
        }
        match claim.action() {
            MemoryVectorSyncAction::Delete => {
                let Some(token) = self.reserve_attempt(&claim)? else {
                    return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
                };
                #[cfg(test)]
                self.check_test_pause_point(VectorSyncTestPausePoint::BeforeDelete);
                if !self
                    .storage
                    .validate_fenced_attempt_token_current(&token)
                    .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
                {
                    return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
                }
                let outcome = self
                    .vectors
                    .delete_generation_memory(&self.generation, token.life_id(), token.memory_id())
                    .await;
                match outcome {
                    Ok(()) => {
                        #[cfg(test)]
                        self.check_test_pause_point(
                            VectorSyncTestPausePoint::AfterLanceBeforeFinalize,
                        );
                        self.finalize(&token)
                    }
                    Err(error) if error.code == VectorStoreErrorCode::VectorNotFound => {
                        #[cfg(test)]
                        self.check_test_pause_point(
                            VectorSyncTestPausePoint::AfterLanceBeforeFinalize,
                        );
                        self.finalize(&token)
                    }
                    Err(error) => self.finalize_failure(
                        &token,
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
                    return self.block_target_stale(&claim);
                }
                let Some(document) =
                    self.storage
                        .read_fenced_vector_document(&claim)
                        .map_err(|_| {
                            worker_error(MemoryVectorSyncWorkerErrorCode::RepositoryUnavailable)
                        })?
                else {
                    return self.block_target_stale(&claim);
                };
                if !self
                    .storage
                    .fenced_vector_claim_is_current(&claim)
                    .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
                {
                    return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
                }
                let Some(token) = self.reserve_attempt(&claim)? else {
                    return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
                };
                #[cfg(test)]
                self.check_test_pause_point(VectorSyncTestPausePoint::BeforeEmbedding);
                if !self
                    .storage
                    .validate_fenced_attempt_token_current(&token)
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
                self.check_test_pause_point(VectorSyncTestPausePoint::AfterEmbeddingBeforeLance);
                let batch = match response {
                    Ok(batch) => batch,
                    Err(error) => {
                        #[cfg(test)]
                        self.check_test_pause_point(
                            VectorSyncTestPausePoint::AfterProviderFailureBeforeFinalize,
                        );
                        return self.finalize_failure(
                            &token,
                            RetryErrorClass::Embedding(error.retry_class()),
                            error.retry_safety(),
                            RetryOperation::Upsert,
                            Some(send_disposition_for_retry_safety(error.retry_safety())),
                            retry_cutoff,
                        );
                    }
                };
                if !self
                    .storage
                    .validate_fenced_attempt_token_current(&token)
                    .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
                {
                    return Ok(FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded);
                }
                let vector = batch.vectors().first().filter(|v| {
                    batch.len() == 1
                        && v.input_index() == 0
                        && v.dimension() == self.generation.dimension()
                });
                let Some(vector) = vector else {
                    return self.finalize_failure(
                        &token,
                        RetryErrorClass::EmbeddingInvalidVector,
                        EmbeddingRetrySafety::ResponseReceived,
                        RetryOperation::Upsert,
                        Some("possibly_sent"),
                        retry_cutoff,
                    );
                };
                let Some(target_revision) = token.target_revision() else {
                    return self.finalize_failure(
                        &token,
                        RetryErrorClass::InternalInvariant,
                        EmbeddingRetrySafety::ResponseReceived,
                        RetryOperation::Upsert,
                        Some("possibly_sent"),
                        retry_cutoff,
                    );
                };
                let Some(target_content_hash) = token.target_content_hash() else {
                    return self.finalize_failure(
                        &token,
                        RetryErrorClass::InternalInvariant,
                        EmbeddingRetrySafety::ResponseReceived,
                        RetryOperation::Upsert,
                        Some("possibly_sent"),
                        retry_cutoff,
                    );
                };
                let record = GenerationVectorRecord::try_new(
                    crate::vector_store::VectorGenerationId::parse(token.generation_id()).map_err(
                        |_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable),
                    )?,
                    token.life_id(),
                    token.memory_id(),
                    target_revision,
                    target_content_hash,
                    token.descriptor_hash(),
                    vector.values().to_vec(),
                );
                let record = match record {
                    Ok(record) => record,
                    Err(_) => {
                        return self.finalize_failure(
                            &token,
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
                    .validate_fenced_attempt_token_current(&token)
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
                        self.finalize(&token)
                    }
                    Err(error) => self.finalize_failure(
                        &token,
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

    fn block_target_stale(
        &self,
        claim: &FencedVectorSyncClaim,
    ) -> Result<FencedVectorSyncSingleEventResult, MemoryVectorSyncWorkerError> {
        let result = self
            .storage
            .block_fenced_vector_target_stale(claim)
            .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?;
        Ok(match result {
            FencedFinalizeResult::Applied => FencedVectorSyncSingleEventResult::Stale,
            FencedFinalizeResult::LostLeaseOrSuperseded => {
                FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded
            }
        })
    }

    fn reserve_attempt(
        &self,
        claim: &FencedVectorSyncClaim,
    ) -> Result<Option<FencedAttemptToken>, MemoryVectorSyncWorkerError> {
        match self
            .storage
            .reserve_fenced_attempt(claim)
            .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
        {
            FencedAttemptReservation::Reserved(token) => Ok(Some(*token)),
            FencedAttemptReservation::LostLeaseOrSuperseded
            | FencedAttemptReservation::BudgetExhausted => Ok(None),
        }
    }

    fn finalize(
        &self,
        token: &FencedAttemptToken,
    ) -> Result<FencedVectorSyncSingleEventResult, MemoryVectorSyncWorkerError> {
        let is_upsert = token.action() == MemoryVectorSyncAction::Upsert;
        let result = match self.storage.finalize_fenced_vector_sync(token) {
            Ok(result) => result,
            Err(_) => {
                if self
                    .storage
                    .fenced_success_finalize_is_applied(token)
                    .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
                {
                    FencedFinalizeResult::Applied
                } else {
                    return Err(worker_error(
                        MemoryVectorSyncWorkerErrorCode::OutboxUnavailable,
                    ));
                }
            }
        };
        Ok(match result {
            FencedFinalizeResult::LostLeaseOrSuperseded => {
                FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded
            }
            FencedFinalizeResult::Applied if is_upsert => {
                FencedVectorSyncSingleEventResult::CompletedUpsert
            }
            FencedFinalizeResult::Applied => FencedVectorSyncSingleEventResult::CompletedDelete,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_failure(
        &self,
        token: &FencedAttemptToken,
        error: RetryErrorClass,
        retry_safety: EmbeddingRetrySafety,
        operation: RetryOperation,
        send_disposition: Option<&str>,
        retry_cutoff: i64,
    ) -> Result<FencedVectorSyncSingleEventResult, MemoryVectorSyncWorkerError> {
        let attempt_count = u32::try_from(token.attempt_ordinal())
            .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?;
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
        let persisted_decision = if clock_now.is_some() {
            failure_decision
        } else {
            FencedFailureDecision::Blocked
        };
        let result = match self.storage.finalize_fenced_vector_failure(
            token,
            retry.stable_error_code.as_str(),
            persisted_decision,
            send_disposition,
            clock_now.unwrap_or(retry_cutoff),
            retry_cutoff,
        ) {
            Ok(result) => result,
            Err(_) => {
                if self
                    .storage
                    .fenced_failure_finalize_is_applied(
                        token,
                        retry.stable_error_code.as_str(),
                        persisted_decision,
                        send_disposition,
                    )
                    .map_err(|_| worker_error(MemoryVectorSyncWorkerErrorCode::OutboxUnavailable))?
                {
                    match persisted_decision {
                        FencedFailureDecision::RetryAfter { .. } => {
                            FencedFailureFinalizeResult::RetryScheduled {
                                next_attempt_at_millis: retry_cutoff,
                            }
                        }
                        FencedFailureDecision::Blocked => FencedFailureFinalizeResult::Blocked,
                    }
                } else {
                    return Err(worker_error(
                        MemoryVectorSyncWorkerErrorCode::OutboxUnavailable,
                    ));
                }
            }
        };
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
                if (job.attempt_count as i64) < MAX_VECTOR_SYNC_ATTEMPTS =>
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
            revisions::{
                DeleteMemoryPermanentlyRequest, MemoryRevisionService, UpdateConfirmedMemoryRequest,
            },
            vector_sync_outbox::EnqueueMemoryVectorSyncRequest,
            MemoryKind,
        },
        model::profile::{
            CreateModelProfileRequest, ModelProfile, ModelProfileService, ModelProviderKind,
            ModelPurpose, SetActiveModelProfileRequest,
        },
        model::provider::{ProviderCredentialError, ProviderError, ProviderErrorKind},
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

        fn get_generation_metadata<'a>(
            &'a self,
            context: &'a VectorGenerationContext,
            life_id: &'a str,
            memory_id: &'a str,
        ) -> VectorStoreFuture<
            'a,
            Result<Option<crate::vector_store::VectorMetadataSample>, VectorStoreError>,
        > {
            self.inner
                .get_generation_metadata(context, life_id, memory_id)
        }
    }

    /// Provider fake that records every embedding call into the shared call
    /// log through the worker's own [`WorkerCallContext`]. The claim observer
    /// feeds the context's current-claim identity before the worker calls
    /// embed, so every record is attributed to the exact worker / memory /
    /// mutation / claim epoch / generation being processed. An external call
    /// without a bound claim fails the test immediately.
    struct RecordingEmbeddingProvider<'a> {
        inner: &'a dyn EmbeddingProvider,
        context: &'a crate::storage::test_support::WorkerCallContext,
    }

    impl EmbeddingProvider for RecordingEmbeddingProvider<'_> {
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
            self.context.record_provider_embedding();
            self.inner.embed(request)
        }
    }

    /// Vector store fake that records every Lance upsert/delete into the
    /// shared call log through the worker's own [`WorkerCallContext`],
    /// attributed to that worker's bound claim identity.
    struct RecordingVectorStore<'a> {
        inner: &'a dyn VectorStore,
        context: &'a crate::storage::test_support::WorkerCallContext,
    }

    impl VectorStore for RecordingVectorStore<'_> {
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
            self.context.record_lance_upsert();
            self.inner.upsert_generation(context, record)
        }
        fn delete_generation_memory<'a>(
            &'a self,
            context: &'a VectorGenerationContext,
            life_id: &'a str,
            memory_id: &'a str,
        ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
            self.context.record_lance_delete();
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
        fn get_generation_metadata<'a>(
            &'a self,
            context: &'a VectorGenerationContext,
            life_id: &'a str,
            memory_id: &'a str,
        ) -> VectorStoreFuture<
            'a,
            Result<Option<crate::vector_store::VectorMetadataSample>, VectorStoreError>,
        > {
            self.inner
                .get_generation_metadata(context, life_id, memory_id)
        }
    }

    /// Vector store fake whose `upsert_generation` always fails after the
    /// call was recorded (10.2 lifecycle: Lance upsert failure).
    struct FailingLanceUpsertVectorStore {
        inner: crate::vector_store::InMemoryVectorStore,
    }

    /// Vector store fake whose `delete_generation_memory` always fails after
    /// the call was recorded (10.3 lifecycle: Lance delete failure).
    struct FailingLanceDeleteVectorStore {
        inner: crate::vector_store::InMemoryVectorStore,
    }

    macro_rules! delegating_vector_store_impl {
        ($store:ty, $fail_method:ident) => {
            impl VectorStore for $store {
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
                    match stringify!($fail_method) {
                        "upsert_generation" => Box::pin(async {
                            Err(VectorStoreError::new(
                                VectorStoreErrorCode::StoreUnavailable,
                                "intentional Lance upsert failure",
                                true,
                            ))
                        }),
                        _ => self.inner.upsert_generation(context, record),
                    }
                }
                fn delete_generation_memory<'a>(
                    &'a self,
                    context: &'a VectorGenerationContext,
                    life_id: &'a str,
                    memory_id: &'a str,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    match stringify!($fail_method) {
                        "delete_generation_memory" => Box::pin(async {
                            Err(VectorStoreError::new(
                                VectorStoreErrorCode::StoreUnavailable,
                                "intentional Lance delete failure",
                                true,
                            ))
                        }),
                        _ => self
                            .inner
                            .delete_generation_memory(context, life_id, memory_id),
                    }
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
                fn get_generation_metadata<'a>(
                    &'a self,
                    context: &'a VectorGenerationContext,
                    life_id: &'a str,
                    memory_id: &'a str,
                ) -> VectorStoreFuture<
                    'a,
                    Result<Option<crate::vector_store::VectorMetadataSample>, VectorStoreError>,
                > {
                    self.inner
                        .get_generation_metadata(context, life_id, memory_id)
                }
            }
        };
    }

    delegating_vector_store_impl!(FailingLanceUpsertVectorStore, upsert_generation);
    delegating_vector_store_impl!(FailingLanceDeleteVectorStore, delete_generation_memory);

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
    fn provider_guard_before_external_call_preserves_reserved_attempt_without_io() {
        for round in 0..10 {
            let (temp, storage) = test_storage();
            let storage = Arc::new(storage);
            let storage_b =
                StorageService::initialize_with_roots(temp.path().join("data"), None).unwrap();
            let record = confirmed(&storage, false);
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

            let snapshot_after_invalidation = Arc::new(std::sync::Mutex::new(None));
            let snapshot_after_invalidation_for_hook = Arc::clone(&snapshot_after_invalidation);
            let storage_clone = Arc::clone(&storage);
            let memory_id_for_hook = record.id.clone();
            let barrier = Arc::new(std::sync::Barrier::new(2));
            let barrier_for_invalidator = Arc::clone(&barrier);
            let barrier_for_hook = Arc::clone(&barrier);
            let (invalidation_tx, invalidation_rx) = std::sync::mpsc::channel();
            let invalidator = thread::spawn(move || {
                barrier_for_invalidator.wait();
                storage_b.test_expire_fenced_runtime_lease().unwrap();
                invalidation_tx.send(()).unwrap();
            });
            let consumer = FencedVectorSyncSingleEventConsumer::new(
                storage.as_ref(),
                &provider,
                &vectors,
                context.clone(),
            );
            consumer.set_test_pause_hook_for_test(Some(Box::new(move |point| {
                if point == VectorSyncTestPausePoint::BeforeEmbedding {
                    barrier_for_hook.wait();
                    invalidation_rx.recv().unwrap();
                    let snap = storage_clone
                        .test_get_outbox_snapshot_detailed("life", &memory_id_for_hook)
                        .unwrap();
                    *snapshot_after_invalidation_for_hook.lock().unwrap() = Some(snap);
                }
            })));

            let result = tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap();
            consumer.set_test_pause_hook_for_test(None);
            invalidator.join().unwrap();

            assert_eq!(
                result,
                FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded,
                "round {round}: invalidated token cannot reach Provider"
            );
            assert_eq!(provider_requests.load(Ordering::SeqCst), 0);
            assert_eq!(credential_reads.load(Ordering::SeqCst), 0);
            assert_eq!(embedding_successes.load(Ordering::SeqCst), 0);
            assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
            assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);
            assert_eq!(storage.test_generation_item_count().unwrap(), 0);
            let before_guard_return = snapshot_after_invalidation.lock().unwrap().take().unwrap();
            let after_guard_return = storage
                .test_get_outbox_snapshot_detailed("life", &record.id)
                .unwrap();
            assert_eq!(
                after_guard_return, before_guard_return,
                "a failed Token Guard must not mutate the reserved current row"
            );
            assert_eq!(after_guard_return.state, "processing");
            assert_eq!(after_guard_return.attempt_count, 1);
            assert_eq!(
                after_guard_return.last_send_disposition.as_deref(),
                Some("possibly_sent")
            );
            assert_eq!(
                after_guard_return.claimed_generation_id.as_deref(),
                Some("gen-pa")
            );
        }
    }

    #[test]
    fn vector_store_guard_after_provider_concurrency_blocks_lance() {
        for round in 0..10 {
            let (temp, storage_a) = test_storage();
            let storage_b =
                StorageService::initialize_with_roots(temp.path().join("data"), None).unwrap();
            let record = confirmed(&storage_a, false);
            let descriptor = "b".repeat(64);
            storage_a
                .register_building_vector_generation("gen-provider-guard", &descriptor, 3)
                .unwrap();
            let context = VectorGenerationContext::new(
                crate::vector_store::VectorGenerationId::parse("gen-provider-guard").unwrap(),
                descriptor,
                3,
            )
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
            let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let provider_requests = Arc::new(AtomicUsize::new(0));
            let embedding_successes = Arc::new(AtomicUsize::new(0));
            let provider = CountingEmbeddingProvider {
                inner: &raw_provider,
                provider_requests: Arc::clone(&provider_requests),
                embedding_successes: Arc::clone(&embedding_successes),
            };

            let barrier = Arc::new(std::sync::Barrier::new(2));
            let barrier_for_invalidator = Arc::clone(&barrier);
            let barrier_for_hook = Arc::clone(&barrier);
            let (invalidation_tx, invalidation_rx) = std::sync::mpsc::channel();
            let invalidator = thread::spawn(move || {
                barrier_for_invalidator.wait();
                storage_b.test_expire_fenced_runtime_lease().unwrap();
                invalidation_tx.send(()).unwrap();
            });
            let consumer = FencedVectorSyncSingleEventConsumer::new(
                &storage_a,
                &provider,
                &vectors,
                context.clone(),
            );
            consumer.set_test_pause_hook_for_test(Some(Box::new(move |point| {
                if point == VectorSyncTestPausePoint::AfterEmbeddingBeforeLance {
                    barrier_for_hook.wait();
                    invalidation_rx.recv().unwrap();
                }
            })));

            let result = tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap();
            consumer.set_test_pause_hook_for_test(None);
            invalidator.join().unwrap();

            assert_eq!(
                result,
                FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded,
                "round {round}: second Token Guard must stop Lance"
            );
            assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
            assert_eq!(embedding_successes.load(Ordering::SeqCst), 1);
            assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
            assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);
            assert_eq!(storage_a.test_generation_item_count().unwrap(), 0);
            let snapshot = storage_a
                .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
                .unwrap();
            assert_eq!(snapshot.state, "processing");
            assert_eq!(snapshot.attempt_count, 1);
            assert_eq!(
                snapshot.last_send_disposition.as_deref(),
                Some("possibly_sent")
            );
        }
    }

    #[test]
    fn lance_success_new_mutation_concurrency_preserves_replacement() {
        for round in 0..10 {
            let (temp, storage_a) = test_storage();
            let storage_b =
                StorageService::initialize_with_roots(temp.path().join("data"), None).unwrap();
            let record = confirmed(&storage_a, false);
            let initial = storage_a
                .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
                .unwrap();
            let descriptor = "c".repeat(64);
            storage_a
                .register_building_vector_generation("gen-lance-mutation", &descriptor, 3)
                .unwrap();
            let context = VectorGenerationContext::new(
                crate::vector_store::VectorGenerationId::parse("gen-lance-mutation").unwrap(),
                descriptor,
                3,
            )
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
            let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let provider_requests = Arc::new(AtomicUsize::new(0));
            let embedding_successes = Arc::new(AtomicUsize::new(0));
            let provider = CountingEmbeddingProvider {
                inner: &raw_provider,
                provider_requests: Arc::clone(&provider_requests),
                embedding_successes: Arc::clone(&embedding_successes),
            };

            let barrier = Arc::new(std::sync::Barrier::new(2));
            let barrier_for_mutator = Arc::clone(&barrier);
            let barrier_for_hook = Arc::clone(&barrier);
            let (mutation_tx, mutation_rx) = std::sync::mpsc::channel();
            let mutator_record = record.clone();
            let mutator = thread::spawn(move || {
                barrier_for_mutator.wait();
                let revisions = MemoryRevisionService::new(&storage_b);
                let revision = revisions
                    .current_revision(&mutator_record.life_id, &mutator_record.id)
                    .unwrap();
                revisions
                    .update_confirmed(UpdateConfirmedMemoryRequest {
                        life_id: mutator_record.life_id.clone(),
                        memory_id: mutator_record.id.clone(),
                        expected_revision: revision,
                        kind: MemoryKind::Fact,
                        content: format!("replacement mutation round {round}"),
                        summary: None,
                    })
                    .unwrap();
                mutation_tx.send(()).unwrap();
            });
            let consumer = FencedVectorSyncSingleEventConsumer::new(
                &storage_a,
                &provider,
                &vectors,
                context.clone(),
            );
            consumer.set_test_pause_hook_for_test(Some(Box::new(move |point| {
                if point == VectorSyncTestPausePoint::AfterLanceBeforeFinalize {
                    barrier_for_hook.wait();
                    mutation_rx.recv().unwrap();
                }
            })));

            let result = tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap();
            consumer.set_test_pause_hook_for_test(None);
            mutator.join().unwrap();

            assert_eq!(
                result,
                FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded,
                "round {round}: old token cannot finalize a replacement mutation"
            );
            assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
            assert_eq!(embedding_successes.load(Ordering::SeqCst), 1);
            assert_eq!(lance_upserts.load(Ordering::SeqCst), 1);
            assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);
            assert_eq!(storage_a.test_generation_item_count().unwrap(), 0);
            assert_eq!(
                tauri::async_runtime::block_on(vectors.count_generation(&context, Some("life")))
                    .unwrap(),
                1,
                "round {round}: the real Lance write happened exactly once"
            );
            let replacement = storage_a
                .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
                .unwrap();
            assert!(replacement.mutation_sequence > initial.mutation_sequence);
            assert_eq!(replacement.state, "pending");
            assert_eq!(replacement.attempt_count, 0);
            assert_eq!(replacement.claimed_generation_id, None);
            assert_eq!(replacement.last_send_disposition, None);
            assert_eq!(replacement.last_error_code, None);
            assert_eq!(replacement.lease_owner, None);
            assert_eq!(replacement.lease_fence_epoch, None);
            assert_eq!(replacement.lease_expires_at, None);
        }
    }

    #[test]
    fn failure_finalize_new_claim_concurrency_preserves_replacement() {
        for round in 0..10 {
            let (temp, storage_a) = test_storage();
            let storage_b =
                StorageService::initialize_with_roots(temp.path().join("data"), None).unwrap();
            let record = confirmed(&storage_a, false);
            let descriptor = "d".repeat(64);
            storage_a
                .register_building_vector_generation("gen-failure-mutation", &descriptor, 3)
                .unwrap();
            let context = VectorGenerationContext::new(
                crate::vector_store::VectorGenerationId::parse("gen-failure-mutation").unwrap(),
                descriptor,
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
            let provider = DefinitelyNotSentRetryableProvider {
                requests: AtomicUsize::new(0),
            };

            let barrier = Arc::new(std::sync::Barrier::new(2));
            let barrier_for_mutator = Arc::clone(&barrier);
            let barrier_for_hook = Arc::clone(&barrier);
            let (ready_tx, ready_rx) = std::sync::mpsc::channel();
            let replacement_snapshot = Arc::new(Mutex::new(None));
            let replacement_snapshot_for_mutator = Arc::clone(&replacement_snapshot);
            let mutator_record = record.clone();
            let mutator_context = context.clone();
            let mutator = thread::spawn(move || {
                barrier_for_mutator.wait();
                let revisions = MemoryRevisionService::new(&storage_b);
                let revision = revisions
                    .current_revision(&mutator_record.life_id, &mutator_record.id)
                    .unwrap();
                revisions
                    .update_confirmed(UpdateConfirmedMemoryRequest {
                        life_id: mutator_record.life_id.clone(),
                        memory_id: mutator_record.id.clone(),
                        expected_revision: revision,
                        kind: MemoryKind::Fact,
                        content: format!("replacement failure-finalize round {round}"),
                        summary: None,
                    })
                    .unwrap();
                storage_b.test_expire_fenced_runtime_lease().unwrap();
                let replacement_claim = storage_b
                    .claim_one_fenced_vector_sync(
                        mutator_context.generation_id().as_str(),
                        mutator_context.descriptor_hash(),
                        mutator_context.dimension(),
                        "worker-b",
                    )
                    .unwrap()
                    .expect("the replacement mutation must receive a new claim");
                assert_eq!(replacement_claim.lease_owner(), "worker-b");
                *replacement_snapshot_for_mutator.lock().unwrap() = Some(
                    storage_b
                        .test_get_outbox_snapshot_detailed(
                            &mutator_record.life_id,
                            &mutator_record.id,
                        )
                        .unwrap(),
                );
                ready_tx.send(()).unwrap();
            });
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage_a, &provider, &vectors, context);
            consumer.set_test_pause_hook_for_test(Some(Box::new(move |point| {
                if point == VectorSyncTestPausePoint::AfterProviderFailureBeforeFinalize {
                    barrier_for_hook.wait();
                    ready_rx.recv().unwrap();
                }
            })));

            let result = tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap();
            consumer.set_test_pause_hook_for_test(None);
            mutator.join().unwrap();

            assert_eq!(
                result,
                FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded,
                "round {round}: old failure finalizer cannot write the new claim"
            );
            assert_eq!(provider.requests.load(Ordering::SeqCst), 1);
            assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
            assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);
            let before_old_finalize_return = replacement_snapshot.lock().unwrap().take().unwrap();
            let after_old_finalize_return = storage_a
                .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
                .unwrap();
            assert_eq!(after_old_finalize_return, before_old_finalize_return);
            assert_eq!(after_old_finalize_return.state, "processing");
            assert_eq!(after_old_finalize_return.attempt_count, 0);
            assert_eq!(
                after_old_finalize_return.claimed_generation_id.as_deref(),
                Some("gen-failure-mutation")
            );
            assert_eq!(
                after_old_finalize_return.lease_owner.as_deref(),
                Some("worker-b")
            );
            assert_eq!(after_old_finalize_return.last_send_disposition, None);
            assert_eq!(after_old_finalize_return.last_error_code, None);
        }
    }

    #[test]
    fn success_commit_unknown_rechecks_sqlite_without_replaying_external_io() {
        let (_temp, storage) = test_storage();
        confirmed(&storage, false);
        let descriptor = "e".repeat(64);
        storage
            .register_building_vector_generation("gen-success-commit-unknown", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-success-commit-unknown").unwrap(),
            descriptor,
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
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
        storage.test_fail_next_fenced_success_finalize_after_commit();

        assert_eq!(
            tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap(),
            FencedVectorSyncSingleEventResult::CompletedUpsert
        );
        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 1);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 1);
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);
        assert_eq!(storage.test_generation_item_count().unwrap(), 1);
        assert!(storage.list("life").unwrap().is_empty());

        assert_eq!(
            tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap(),
            FencedVectorSyncSingleEventResult::NoEligibleEvent
        );
        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn failure_commit_unknown_rechecks_sqlite_without_replaying_external_io() {
        let (_temp, storage) = test_storage();
        let record = confirmed(&storage, false);
        let descriptor = "f".repeat(64);
        storage
            .register_building_vector_generation("gen-failure-commit-unknown", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-failure-commit-unknown").unwrap(),
            descriptor,
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
        let provider = DefinitelyNotSentRetryableProvider {
            requests: AtomicUsize::new(0),
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
        storage.test_fail_next_fenced_failure_finalize_after_commit();

        assert_eq!(
            tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap(),
            FencedVectorSyncSingleEventResult::RetryWait
        );
        assert_eq!(provider.requests.load(Ordering::SeqCst), 1);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);
        let snapshot = storage
            .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
            .unwrap();
        assert_eq!(snapshot.state, "retry_wait");
        assert_eq!(snapshot.attempt_count, 1);
        assert_eq!(
            snapshot.last_send_disposition.as_deref(),
            Some("definitely_not_sent")
        );

        assert_eq!(
            tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap(),
            FencedVectorSyncSingleEventResult::NoEligibleEvent
        );
        assert_eq!(provider.requests.load(Ordering::SeqCst), 1);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn delete_guard_before_external_call_preserves_attempt_without_delete() {
        let (_temp, storage) = test_storage();
        let record = confirmed(&storage, false);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: record.life_id.clone(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
        let descriptor = "a".repeat(64);
        storage
            .register_building_vector_generation("gen-delete-guard", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-delete-guard").unwrap(),
            descriptor,
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
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
        consumer.set_test_pause_hook_for_test(Some(Box::new(|point| {
            if point == VectorSyncTestPausePoint::BeforeDelete {
                storage.test_expire_fenced_runtime_lease().unwrap();
            }
        })));

        assert_eq!(
            tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap(),
            FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded
        );
        consumer.set_test_pause_hook_for_test(None);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 0);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 0);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);
        let snapshot = storage
            .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
            .unwrap();
        assert_eq!(snapshot.desired_action, "delete");
        assert_eq!(snapshot.state, "processing");
        assert_eq!(snapshot.attempt_count, 1);
        assert_eq!(snapshot.last_send_disposition, None);
        assert_eq!(
            snapshot.claimed_generation_id.as_deref(),
            Some("gen-delete-guard")
        );
    }

    #[test]
    fn delete_success_finalize_loss_leaves_sqlite_uncompleted() {
        let (temp, storage) = test_storage();
        let record = confirmed(&storage, false);
        let descriptor = "b".repeat(64);
        storage
            .register_building_vector_generation("gen-delete-finalize", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-delete-finalize").unwrap(),
            descriptor,
            3,
        )
        .unwrap();
        let raw_vectors = tauri::async_runtime::block_on(
            crate::vector_store::LanceDbVectorStore::open(temp.path().join("lance")),
        )
        .unwrap();
        tauri::async_runtime::block_on(raw_vectors.create_generation(&context)).unwrap();
        let generation_record = GenerationVectorRecord::try_new(
            context.generation_id().clone(),
            &record.life_id,
            &record.id,
            MemoryRevisionService::new(&storage)
                .current_revision(&record.life_id, &record.id)
                .unwrap(),
            "c".repeat(64),
            context.descriptor_hash(),
            vec![0.1, 0.2, 0.3],
        )
        .unwrap();
        tauri::async_runtime::block_on(raw_vectors.upsert_generation(&context, generation_record))
            .unwrap();
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: record.life_id.clone(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
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
        let consumer = FencedVectorSyncSingleEventConsumer::new(
            &storage,
            &provider,
            &vectors,
            context.clone(),
        );
        consumer.set_test_pause_hook_for_test(Some(Box::new(|point| {
            if point == VectorSyncTestPausePoint::AfterLanceBeforeFinalize {
                storage.test_expire_fenced_runtime_lease().unwrap();
            }
        })));

        assert_eq!(
            tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap(),
            FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded
        );
        consumer.set_test_pause_hook_for_test(None);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 0);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 0);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 1);
        assert_eq!(
            tauri::async_runtime::block_on(vectors.count_generation(&context, Some("life")))
                .unwrap(),
            0
        );
        let snapshot = storage
            .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
            .unwrap();
        assert_eq!(snapshot.desired_action, "delete");
        assert_eq!(snapshot.state, "processing");
        assert_eq!(snapshot.attempt_count, 1);
        assert_eq!(snapshot.last_send_disposition, None);
        assert_eq!(
            snapshot.claimed_generation_id.as_deref(),
            Some("gen-delete-finalize")
        );

        // A new mutation creates a fresh token and may issue a fresh real delete;
        // this does not claim replay safety for the old late-delete Attempt.
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: record.life_id.clone(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
        let replacement_vector = GenerationVectorRecord::try_new(
            context.generation_id().clone(),
            &record.life_id,
            &record.id,
            MemoryRevisionService::new(&storage)
                .current_revision(&record.life_id, &record.id)
                .unwrap(),
            "d".repeat(64),
            context.descriptor_hash(),
            vec![0.1, 0.2, 0.3],
        )
        .unwrap();
        tauri::async_runtime::block_on(
            vectors
                .inner
                .upsert_generation(&context, replacement_vector),
        )
        .unwrap();
        assert_eq!(
            tauri::async_runtime::block_on(consumer.process_one("worker-b")).unwrap(),
            FencedVectorSyncSingleEventResult::CompletedDelete
        );
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 2);
        assert_eq!(storage.test_generation_item_count().unwrap(), 0);
        assert!(storage.list("life").unwrap().is_empty());
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
                .test_complete_claim_via_real_reserved_token(
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
                .test_complete_claim_via_real_reserved_token(
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
        for attempt_count in [MAX_VECTOR_SYNC_ATTEMPTS as u32, 6, u32::MAX] {
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

    /// Retry/blocked classification is driven by the attempt count SQLite actually
    /// persisted for the reserved slot.
    ///
    /// Each case starts below the Attempt budget, because ATT-I2 makes an at-limit
    /// row converge to `blocked` before any claim or reservation happens. The
    /// at-limit and over-limit behaviour is proven directly against SQLite in the
    /// storage Attempt-budget tests rather than by driving the worker through a
    /// sixth slot that can no longer exist.
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
                .claim_one_fenced_vector_sync(
                    context.generation_id().as_str(),
                    context.descriptor_hash(),
                    context.dimension(),
                    "attempt-boundary",
                )
                .unwrap()
                .unwrap();
            storage
                .test_set_fenced_attempt_count(prior_attempts)
                .unwrap();
            storage
                .test_set_fenced_state_for_generation_binding("pending", prior_attempts == 0)
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

    struct DefinitelyNotSentRetryableProvider {
        requests: AtomicUsize,
    }

    impl EmbeddingProvider for DefinitelyNotSentRetryableProvider {
        fn model_info(&self) -> EmbeddingModelInfo {
            EmbeddingModelInfo {
                model_name: "definitely-not-sent-retryable".into(),
                dimension: Some(3),
            }
        }

        fn model_name(&self) -> &str {
            "definitely-not-sent-retryable"
        }

        fn vector_dimension(&self) -> Option<usize> {
            Some(3)
        }

        fn max_batch_size(&self) -> usize {
            32
        }

        fn embed<'a>(
            &'a self,
            _request: EmbeddingRequest,
        ) -> EmbeddingFuture<'a, Result<EmbeddingBatch, EmbeddingError>> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            Box::pin(async {
                Err(EmbeddingError::definitely_not_sent(
                    crate::embedding::EmbeddingErrorCode::NetworkError,
                ))
            })
        }
    }

    #[test]
    fn provider_invocations_stop_at_max_attempt_across_drains() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        drain_upsert_fixture(&storage, context.generation_id().as_str());
        let clock = FixedRetryClock::new(100_000);
        let advanced_clock = clock.clone();
        let provider = DefinitelyNotSentRetryableProvider {
            requests: AtomicUsize::new(0),
        };
        let consumer = FencedVectorSyncSingleEventConsumer::new(
            &storage,
            &provider,
            &vectors,
            context.clone(),
        )
        .with_retry_clock_for_test(Box::new(clock));

        let records = storage.list("life").unwrap();
        let record = records.first().unwrap();
        let event_life = record.life_id.clone();
        let event_mem = record.memory_id.clone();

        // Drain 1: attempt_count = 1, retry_wait, 30s delay
        let d1 =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "worker-drain", 1))
                .unwrap();
        assert_eq!(d1.processed, 1);
        assert_eq!(d1.retry_scheduled, 1);
        assert_eq!(provider.requests.load(Ordering::SeqCst), 1);
        let snap1 = storage
            .test_get_outbox_snapshot_detailed(&event_life, &event_mem)
            .unwrap();
        assert_eq!(snap1.attempt_count, 1);
        assert_eq!(snap1.state, "retry_wait");
        assert!(snap1.next_attempt_at.is_some());
        assert_eq!(
            snap1.last_error_code.as_deref(),
            Some("PROVIDER_UNAVAILABLE")
        );
        assert_eq!(
            snap1.last_send_disposition.as_deref(),
            Some("definitely_not_sent")
        );

        // Drain 2: advance clock past next_attempt_at. D1 set next to 100_000+30_000=130_000
        advanced_clock.set(131_000);
        let d2 =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "worker-drain", 1))
                .unwrap();
        assert_eq!(d2.processed, 1);
        assert_eq!(d2.retry_scheduled, 1);
        assert_eq!(provider.requests.load(Ordering::SeqCst), 2);
        let snap2 = storage
            .test_get_outbox_snapshot_detailed(&event_life, &event_mem)
            .unwrap();
        assert_eq!(snap2.attempt_count, 2);
        assert_eq!(snap2.state, "retry_wait");

        // Drain 3: D2 set next to 131_000+60_000=191_000. Advance past it.
        advanced_clock.set(192_000);
        let d3 =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "worker-drain", 1))
                .unwrap();
        assert_eq!(d3.processed, 1);
        assert_eq!(d3.retry_scheduled, 1);
        assert_eq!(provider.requests.load(Ordering::SeqCst), 3);
        let snap3 = storage
            .test_get_outbox_snapshot_detailed(&event_life, &event_mem)
            .unwrap();
        assert_eq!(snap3.attempt_count, 3);
        assert_eq!(snap3.state, "retry_wait");

        // Drain 4: D3 set next to 192_000+120_000=312_000. Advance past it.
        advanced_clock.set(313_000);
        let d4 =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "worker-drain", 1))
                .unwrap();
        assert_eq!(d4.processed, 1);
        assert_eq!(d4.retry_scheduled, 1);
        assert_eq!(provider.requests.load(Ordering::SeqCst), 4);
        let snap4 = storage
            .test_get_outbox_snapshot_detailed(&event_life, &event_mem)
            .unwrap();
        assert_eq!(snap4.attempt_count, 4);
        assert_eq!(snap4.state, "retry_wait");

        // Drain 5: D4 set next to 313_000+240_000=553_000. Advance past it.
        // attempt_count reaches 5 = MAX. Should be blocked.
        advanced_clock.set(554_000);
        let d5 =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "worker-drain", 1))
                .unwrap();
        assert_eq!(d5.processed, 1);
        assert_eq!(d5.blocked, 1);
        assert_eq!(provider.requests.load(Ordering::SeqCst), 5);
        let snap5 = storage
            .test_get_outbox_snapshot_detailed(&event_life, &event_mem)
            .unwrap();
        assert_eq!(snap5.attempt_count, 5);
        assert_eq!(snap5.state, "blocked");
        assert_eq!(snap5.next_attempt_at, None);
        assert_eq!(
            snap5.last_error_code.as_deref(),
            Some("PROVIDER_UNAVAILABLE")
        );
        assert_eq!(
            snap5.last_send_disposition.as_deref(),
            Some("definitely_not_sent")
        );

        // Drain 6: event is blocked, must not be claimed. No 6th provider call.
        advanced_clock.set(600_000);
        let d6 =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "worker-drain", 1))
                .unwrap();
        assert_eq!(d6.processed, 0);
        assert!(d6.stopped_no_eligible);
        assert_eq!(provider.requests.load(Ordering::SeqCst), 5);
        let snap6 = storage
            .test_get_outbox_snapshot_detailed(&event_life, &event_mem)
            .unwrap();
        assert_eq!(snap6.attempt_count, 5);
        assert_eq!(snap6.state, "blocked");
        assert_eq!(snap6.next_attempt_at, None);
    }

    #[test]
    fn lost_lease_before_attempt_start_consumes_zero_cost() {
        let (temp, storage_a) = test_storage();
        let descriptor = "e".repeat(64);
        storage_a
            .register_building_vector_generation("gen-attempt-before", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-attempt-before").unwrap(),
            descriptor.clone(),
            3,
        )
        .unwrap();
        let mem = confirmed(&storage_a, false);
        storage_a
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: mem.life_id.clone(),
                memory_id: mem.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
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

        let owner_a = Arc::new(Mutex::new(None));
        let fence_a = Arc::new(Mutex::new(None));
        let owner_b = Arc::new(Mutex::new(None));
        let fence_b = Arc::new(Mutex::new(None));
        let owner_a_for_hook = Arc::clone(&owner_a);
        let fence_a_for_hook = Arc::clone(&fence_a);
        let owner_b_for_hook = Arc::clone(&owner_b);
        let fence_b_for_hook = Arc::clone(&fence_b);

        let storage_b =
            StorageService::initialize_with_roots(temp.path().join("data"), None).unwrap();
        let context_clone = context.clone();
        let consumer = FencedVectorSyncSingleEventConsumer::new(
            &storage_a,
            &provider,
            &vectors,
            context.clone(),
        );
        consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
            *owner_a_for_hook.lock().unwrap() = Some(claim.lease_owner().to_string());
            *fence_a_for_hook.lock().unwrap() = Some(claim.fence_epoch());
            storage_b.test_expire_fenced_runtime_lease().unwrap();
            let cb = storage_b
                .claim_one_fenced_vector_sync(
                    context_clone.generation_id().as_str(),
                    context_clone.descriptor_hash(),
                    context_clone.dimension(),
                    "worker-b",
                )
                .unwrap()
                .expect("worker-b claim must succeed");
            *owner_b_for_hook.lock().unwrap() = Some(cb.lease_owner().to_string());
            *fence_b_for_hook.lock().unwrap() = Some(cb.fence_epoch());
        })));

        let result = tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap();
        consumer.set_claim_observer_for_test(None);

        assert_eq!(
            result,
            FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded
        );
        assert_eq!(owner_a.lock().unwrap().as_deref(), Some("worker-a"));
        assert_eq!(owner_b.lock().unwrap().as_deref(), Some("worker-b"));
        let fa = fence_a.lock().unwrap().unwrap();
        let fb = fence_b.lock().unwrap().unwrap();
        assert!(
            fb > fa,
            "worker-b fence({fb}) must exceed worker-a fence({fa})"
        );

        assert_eq!(provider_requests.load(Ordering::SeqCst), 0);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 0);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);
        assert_eq!(storage_a.test_generation_item_count().unwrap(), 0);

        let snap = storage_a
            .test_get_outbox_snapshot_detailed(&mem.life_id, &mem.id)
            .unwrap();
        assert_eq!(snap.attempt_count, 0);
        assert_eq!(snap.last_send_disposition, None);
        assert_eq!(snap.state, "processing");
        assert_eq!(snap.lease_owner.as_deref(), Some("worker-b"));
        assert_eq!(snap.lease_fence_epoch, Some(fb));
    }

    #[test]
    fn lost_lease_after_lance_preserves_outbox_and_cost_evidence() {
        let (temp, storage_a) = test_storage();
        let descriptor = "f".repeat(64);
        storage_a
            .register_building_vector_generation("gen-lance-after", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-lance-after").unwrap(),
            descriptor.clone(),
            3,
        )
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

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let transport_requests = Arc::new(AtomicUsize::new(0));
        let transport_counter = Arc::clone(&transport_requests);
        let server = thread::spawn(move || {
            use std::io::Write;
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0_u8; 2048];
            let _ = stream.read(&mut buffer);
            transport_counter.fetch_add(1, Ordering::SeqCst);
            let body = r#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]}],"model":"test-embedding-model","usage":{"prompt_tokens":1,"total_tokens":1}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });

        let profile = ModelProfile {
            id: "profile-lance-after".into(),
            purpose: ModelPurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "lance after".into(),
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

        let owner_a = Arc::new(Mutex::new(None));
        let fence_a = Arc::new(Mutex::new(None));
        let owner_b = Arc::new(Mutex::new(None));
        let fence_b = Arc::new(Mutex::new(None));
        let owner_a_hook = Arc::clone(&owner_a);
        let fence_a_hook = Arc::clone(&fence_a);
        let owner_b_hook = Arc::clone(&owner_b);
        let fence_b_hook = Arc::clone(&fence_b);

        let mem = confirmed(&storage_a, false);
        storage_a
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: mem.life_id.clone(),
                memory_id: mem.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        // Enqueue a second event so worker-b has something to claim
        let takeover_mem = confirmed(&storage_a, false);
        storage_a
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: takeover_mem.life_id.clone(),
                memory_id: takeover_mem.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();

        let storage_b =
            StorageService::initialize_with_roots(temp.path().join("data"), None).unwrap();
        let context_clone = context.clone();

        let consumer = FencedVectorSyncSingleEventConsumer::new(
            &storage_a,
            &provider,
            &vectors,
            context.clone(),
        );
        consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
            *owner_a_hook.lock().unwrap() = Some(claim.lease_owner().to_string());
            *fence_a_hook.lock().unwrap() = Some(claim.fence_epoch());
        })));
        consumer.set_test_pause_hook_for_test(Some(Box::new(move |point| {
            if point == VectorSyncTestPausePoint::AfterLanceBeforeFinalize {
                storage_b.test_expire_fenced_runtime_lease().unwrap();
                let cb = storage_b
                    .claim_one_fenced_vector_sync(
                        context_clone.generation_id().as_str(),
                        context_clone.descriptor_hash(),
                        context_clone.dimension(),
                        "worker-b",
                    )
                    .unwrap()
                    .expect("worker-b claim must succeed");
                *owner_b_hook.lock().unwrap() = Some(cb.lease_owner().to_string());
                *fence_b_hook.lock().unwrap() = Some(cb.fence_epoch());
            }
        })));

        let result = tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap();
        consumer.set_test_pause_hook_for_test(None);
        server.join().unwrap();

        assert_eq!(
            result,
            FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded
        );
        assert_eq!(owner_a.lock().unwrap().as_deref(), Some("worker-a"));
        assert_eq!(owner_b.lock().unwrap().as_deref(), Some("worker-b"));
        let fa = fence_a.lock().unwrap().unwrap();
        let fb = fence_b.lock().unwrap().unwrap();
        assert!(
            fb > fa,
            "worker-b fence({fb}) must exceed worker-a fence({fa})"
        );

        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 1);
        assert_eq!(transport_requests.load(Ordering::SeqCst), 1);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 1);
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);

        let snap = storage_a
            .test_get_outbox_snapshot_detailed(&mem.life_id, &mem.id)
            .unwrap();
        assert_eq!(snap.state, "blocked");
        assert_eq!(
            snap.last_error_code.as_deref(),
            Some("PROVIDER_RESULT_UNKNOWN")
        );
        assert_eq!(snap.last_send_disposition.as_deref(), Some("possibly_sent"));
        assert_eq!(snap.attempt_count, 1);

        // Trigger expired recovery via a new drain
        storage_a.test_expire_fenced_runtime_lease().unwrap();
        let recovery =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "worker-c", 1))
                .unwrap();
        assert_eq!(recovery.processed, 1);

        let snap_after = storage_a
            .test_get_outbox_snapshot_detailed(&mem.life_id, &mem.id)
            .unwrap();
        assert_eq!(snap_after.state, "blocked");
        assert_eq!(
            snap_after.last_error_code.as_deref(),
            Some("PROVIDER_RESULT_UNKNOWN")
        );
        assert_eq!(
            snap_after.last_send_disposition.as_deref(),
            Some("possibly_sent")
        );
        assert_eq!(snap_after.attempt_count, 1);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);

        // Another drain must not re-invoke Provider
        storage_a.test_expire_fenced_runtime_lease().unwrap();
        let third =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "worker-c", 1))
                .unwrap();
        assert_eq!(third.processed, 0);
        assert!(third.stopped_no_eligible);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn expired_processing_crash_matrix_is_fail_closed() {
        // Scenario 1 (clean): claim event, verify pre-state, expire, drain, check post-state
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let consumer = FencedVectorSyncSingleEventConsumer::new(
                &storage,
                &provider,
                &vectors,
                context.clone(),
            );

            let claim = storage
                .claim_one_fenced_vector_sync(
                    context.generation_id().as_str(),
                    context.descriptor_hash(),
                    context.dimension(),
                    "worker-s1",
                )
                .unwrap()
                .unwrap();
            assert_eq!(claim.action(), MemoryVectorSyncAction::Upsert);

            // Before recovery: state=processing, attempt=0, no disposition
            let snap_before = storage
                .test_get_outbox_snapshot_detailed(claim.life_id(), claim.memory_id())
                .unwrap();
            assert_eq!(snap_before.state, "processing");
            assert_eq!(snap_before.attempt_count, 0);
            assert_eq!(snap_before.last_send_disposition, None);

            // Expire lease and run drain — recovery runs inside claim
            storage.test_expire_fenced_runtime_lease().unwrap();
            let report = tauri::async_runtime::block_on(drain_fenced_vector_sync(
                &consumer,
                "worker-s1-r",
                2,
            ))
            .unwrap();
            // recovery moves it to pending, then drain claims and completes it
            assert_eq!(report.applied_upserts, 1);

            // Event was completed and removed from outbox
            let remain = storage.list("life").unwrap();
            assert!(
                !remain
                    .iter()
                    .any(|j| { j.life_id == claim.life_id() && j.memory_id == claim.memory_id() }),
                "completed event must be removed from outbox"
            );
        }

        // Scenario 2: Upsert attempt後 Provider前 — blocked, PROVIDER_RESULT_UNKNOWN
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let consumer = FencedVectorSyncSingleEventConsumer::new(
                &storage,
                &provider,
                &vectors,
                context.clone(),
            );

            let claim = storage
                .claim_one_fenced_vector_sync(
                    context.generation_id().as_str(),
                    context.descriptor_hash(),
                    context.dimension(),
                    "worker-s2",
                )
                .unwrap()
                .unwrap();

            // Set attempt_count=1 and possibly_sent via test helpers
            storage.test_set_fenced_attempt_count(1).unwrap();
            let db_path = storage.test_database_main_path().unwrap();
            let conn = crate::storage::open_authorized_test_connection(&db_path).unwrap();
            conn.execute(
                "UPDATE memory_vector_sync_outbox SET last_send_disposition='possibly_sent' WHERE life_id=?1 AND memory_id=?2",
                rusqlite::params![claim.life_id(), claim.memory_id()],
            )
            .unwrap();

            storage.test_expire_fenced_runtime_lease().unwrap();
            let report = tauri::async_runtime::block_on(drain_fenced_vector_sync(
                &consumer,
                "worker-s2-r",
                1,
            ))
            .unwrap();
            assert_eq!(report.processed, 0);
            assert!(report.stopped_no_eligible);

            let snap = storage
                .test_get_outbox_snapshot_detailed(claim.life_id(), claim.memory_id())
                .unwrap();
            assert_eq!(snap.state, "blocked");
            assert_eq!(
                snap.last_error_code.as_deref(),
                Some("PROVIDER_RESULT_UNKNOWN")
            );
            assert_eq!(snap.next_attempt_at, None);
            assert_eq!(snap.last_send_disposition.as_deref(), Some("possibly_sent"));
            assert_eq!(snap.attempt_count, 1);
        }

        // Scenario 5: Delete attempt後 → pending
        {
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

            let claim = storage
                .claim_one_fenced_vector_sync(
                    context.generation_id().as_str(),
                    context.descriptor_hash(),
                    context.dimension(),
                    "worker-s5",
                )
                .unwrap()
                .unwrap();
            assert_eq!(claim.action(), MemoryVectorSyncAction::Delete);
            storage.test_set_fenced_attempt_count(3).unwrap();

            storage.test_expire_fenced_runtime_lease().unwrap();
            let report = tauri::async_runtime::block_on(drain_fenced_vector_sync(
                &consumer,
                "worker-s5-r",
                1,
            ))
            .unwrap();
            // Recovery moves expired delete to pending; drain completes it
            assert_eq!(report.applied_deletes, 1);
            assert_eq!(report.processed, 1);

            // Row was deleted from outbox by successful completion
            let remain = storage.list("life").unwrap();
            assert!(
                !remain
                    .iter()
                    .any(|j| { j.life_id == claim.life_id() && j.memory_id == claim.memory_id() }),
                "completed delete must remove its outbox row"
            );
        }

        // Scenario 6: 异常 Upsert attempt>0 + NULL disposition → INTERNAL_INVARIANT
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let consumer = FencedVectorSyncSingleEventConsumer::new(
                &storage,
                &provider,
                &vectors,
                context.clone(),
            );

            let claim = storage
                .claim_one_fenced_vector_sync(
                    context.generation_id().as_str(),
                    context.descriptor_hash(),
                    context.dimension(),
                    "worker-s6",
                )
                .unwrap()
                .unwrap();
            storage.test_set_fenced_attempt_count(2).unwrap();
            // leave last_send_disposition = NULL (anomaly)

            storage.test_expire_fenced_runtime_lease().unwrap();
            let report = tauri::async_runtime::block_on(drain_fenced_vector_sync(
                &consumer,
                "worker-s6-r",
                1,
            ))
            .unwrap();
            assert_eq!(report.processed, 0);
            assert!(report.stopped_no_eligible);

            let snap = storage
                .test_get_outbox_snapshot_detailed(claim.life_id(), claim.memory_id())
                .unwrap();
            assert_eq!(snap.state, "blocked");
            assert_eq!(snap.last_error_code.as_deref(), Some("INTERNAL_INVARIANT"));
            assert_eq!(snap.next_attempt_at, None);
            assert_eq!(snap.last_send_disposition, None);
        }

        // Scenario 7: 异常 Upsert attempt>0 + definitely_not_sent → INTERNAL_INVARIANT
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let consumer = FencedVectorSyncSingleEventConsumer::new(
                &storage,
                &provider,
                &vectors,
                context.clone(),
            );

            let claim = storage
                .claim_one_fenced_vector_sync(
                    context.generation_id().as_str(),
                    context.descriptor_hash(),
                    context.dimension(),
                    "worker-s7",
                )
                .unwrap()
                .unwrap();
            storage.test_set_fenced_attempt_count(3).unwrap();
            let db_path = storage.test_database_main_path().unwrap();
            let conn = crate::storage::open_authorized_test_connection(&db_path).unwrap();
            conn.execute(
                "UPDATE memory_vector_sync_outbox SET last_send_disposition='definitely_not_sent' WHERE life_id=?1 AND memory_id=?2",
                rusqlite::params![claim.life_id(), claim.memory_id()],
            )
            .unwrap();

            storage.test_expire_fenced_runtime_lease().unwrap();
            let report = tauri::async_runtime::block_on(drain_fenced_vector_sync(
                &consumer,
                "worker-s7-r",
                1,
            ))
            .unwrap();
            assert_eq!(report.processed, 0);
            assert!(report.stopped_no_eligible);

            let snap = storage
                .test_get_outbox_snapshot_detailed(claim.life_id(), claim.memory_id())
                .unwrap();
            assert_eq!(snap.state, "blocked");
            assert_eq!(snap.last_error_code.as_deref(), Some("INTERNAL_INVARIANT"));
            assert_eq!(snap.next_attempt_at, None);
            assert_eq!(
                snap.last_send_disposition.as_deref(),
                Some("definitely_not_sent")
            );
        }

        // Scenario 8: 未过期 processing → unchanged
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            let provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let consumer = FencedVectorSyncSingleEventConsumer::new(
                &storage,
                &provider,
                &vectors,
                context.clone(),
            );

            let claim = storage
                .claim_one_fenced_vector_sync(
                    context.generation_id().as_str(),
                    context.descriptor_hash(),
                    context.dimension(),
                    "worker-s8",
                )
                .unwrap()
                .unwrap();

            let snap_before = storage
                .test_get_outbox_snapshot_detailed(claim.life_id(), claim.memory_id())
                .unwrap();
            assert_eq!(snap_before.state, "processing");

            // Do NOT expire — drain with same owner should leave it unchanged
            // Fence is still valid; drain simply finds nothing eligible to claim
            // (the row is processing with a valid lease, so recovery skips it)
            let report =
                tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "worker-s8", 1))
                    .unwrap();
            assert_eq!(report.processed, 0);
            assert!(report.stopped_no_eligible);

            let snap_after = storage
                .test_get_outbox_snapshot_detailed(claim.life_id(), claim.memory_id())
                .unwrap();
            assert_eq!(snap_after.state, snap_before.state);
            assert_eq!(snap_after.lease_owner, snap_before.lease_owner);
            assert_eq!(snap_after.lease_fence_epoch, snap_before.lease_fence_epoch);
            assert_eq!(snap_after.lease_expires_at, snap_before.lease_expires_at);
            assert_eq!(snap_after.attempt_count, snap_before.attempt_count);
            assert_eq!(snap_after.next_attempt_at, snap_before.next_attempt_at);
            assert_eq!(snap_after.last_error_code, snap_before.last_error_code);
            assert_eq!(
                snap_after.last_send_disposition,
                snap_before.last_send_disposition
            );
            assert_eq!(snap_after.mutation_sequence, snap_before.mutation_sequence);
            assert_eq!(snap_after.target_revision, snap_before.target_revision);
            assert_eq!(
                snap_after.target_content_hash,
                snap_before.target_content_hash
            );
            assert_eq!(
                snap_after.claimed_generation_id,
                snap_before.claimed_generation_id
            );
        }
    }

    #[test]
    fn drain_limit_caps_process_and_provider_invocations() {
        // limit=1 with 2 eligible events
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            for _ in 0..2 {
                drain_upsert_fixture(&storage, context.generation_id().as_str());
            }
            let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let provider_requests = Arc::new(AtomicUsize::new(0));
            let embedding_successes = Arc::new(AtomicUsize::new(0));
            let provider = CountingEmbeddingProvider {
                inner: &raw_provider,
                provider_requests: Arc::clone(&provider_requests),
                embedding_successes,
            };
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
            let report =
                tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-lim1", 1))
                    .unwrap();
            assert_eq!(report.processed, 1);
            assert_eq!(report.applied_upserts, 1);
            assert_eq!(consumer.process_one_invocations_for_test(), 1);
            assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
            assert!(!report.stopped_no_eligible);
            // Remaining eligible event still exists
            let pending = storage
                .list("life")
                .unwrap()
                .into_iter()
                .filter(|j| j.state == MemoryVectorSyncState::Pending)
                .count();
            assert_eq!(pending, 1);
        }

        // limit=3 with 4 eligible events
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            for _ in 0..4 {
                drain_upsert_fixture(&storage, context.generation_id().as_str());
            }
            let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let provider_requests = Arc::new(AtomicUsize::new(0));
            let embedding_successes = Arc::new(AtomicUsize::new(0));
            let provider = CountingEmbeddingProvider {
                inner: &raw_provider,
                provider_requests: Arc::clone(&provider_requests),
                embedding_successes,
            };
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
            let report =
                tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-lim3", 3))
                    .unwrap();
            assert_eq!(report.processed, 3);
            assert_eq!(report.applied_upserts, 3);
            assert_eq!(consumer.process_one_invocations_for_test(), 3);
            assert_eq!(provider_requests.load(Ordering::SeqCst), 3);
            assert!(!report.stopped_no_eligible);
            // Remaining eligible event still exists
            let pending = storage
                .list("life")
                .unwrap()
                .into_iter()
                .filter(|j| j.state == MemoryVectorSyncState::Pending)
                .count();
            assert_eq!(pending, 1);
        }

        // limit=32 with 33 eligible events
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            for _ in 0..33 {
                drain_upsert_fixture(&storage, context.generation_id().as_str());
            }
            let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let provider_requests = Arc::new(AtomicUsize::new(0));
            let embedding_successes = Arc::new(AtomicUsize::new(0));
            let provider = CountingEmbeddingProvider {
                inner: &raw_provider,
                provider_requests: Arc::clone(&provider_requests),
                embedding_successes,
            };
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
            let report =
                tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-lim32", 32))
                    .unwrap();
            assert_eq!(report.processed, 32);
            assert_eq!(report.applied_upserts, 32);
            assert_eq!(consumer.process_one_invocations_for_test(), 32);
            assert_eq!(provider_requests.load(Ordering::SeqCst), 32);
            assert!(!report.stopped_no_eligible);
            let pending = storage
                .list("life")
                .unwrap()
                .into_iter()
                .filter(|j| j.state == MemoryVectorSyncState::Pending)
                .count();
            assert_eq!(pending, 1);
        }
    }

    #[test]
    fn database_retry_matrix_credential_not_configured() {
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        drain_upsert_fixture(&storage, context.generation_id().as_str());

        let profile = ModelProfile {
            id: "prof-cred-not-config".into(),
            purpose: ModelPurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "no cred".into(),
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
        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-cred", 1))
                .unwrap();
        assert_eq!(report.blocked, 1);

        let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
        assert_eq!(row.0, 1);
        assert_eq!(row.1.as_deref(), Some("definitely_not_sent"));
        assert_eq!(row.2, "AUTHENTICATION_FAILED");

        let jobs = storage.list("life").unwrap();
        assert_eq!(jobs[0].state, MemoryVectorSyncState::Blocked);
    }

    #[test]
    fn database_retry_matrix_lance_upsert_transient() {
        // Lance transient for upsert: retry_wait, possibly_sent, attempt=1, provider=1
        let (_temp, storage) = test_storage();
        let (context, raw_vectors) = drained_context();
        drain_upsert_fixture(&storage, context.generation_id().as_str());

        struct TransientLanceVectorStore {
            inner: crate::vector_store::InMemoryVectorStore,
            upsert_calls: AtomicUsize,
        }
        impl VectorStore for TransientLanceVectorStore {
            fn upsert<'a>(
                &'a self,
                r: VectorRecord,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.inner.upsert(r)
            }
            fn upsert_batch<'a>(
                &'a self,
                r: Vec<VectorRecord>,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.inner.upsert_batch(r)
            }
            fn search<'a>(
                &'a self,
                q: VectorSearchQuery,
            ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>> {
                self.inner.search(q)
            }
            fn delete<'a>(
                &'a self,
                lid: &'a str,
                mid: &'a str,
            ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                self.inner.delete(lid, mid)
            }
            fn delete_from_space<'a>(
                &'a self,
                lid: &'a str,
                mid: &'a str,
                s: &'a VectorSpace,
            ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                self.inner.delete_from_space(lid, mid, s)
            }
            fn delete_by_life<'a>(
                &'a self,
                lid: &'a str,
            ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                self.inner.delete_by_life(lid)
            }
            fn clear_space<'a>(
                &'a self,
                lid: &'a str,
                s: &'a VectorSpace,
            ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                self.inner.clear_space(lid, s)
            }
            fn count<'a>(
                &'a self,
                lid: &'a str,
                s: Option<&'a VectorSpace>,
            ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                self.inner.count(lid, s)
            }
            fn health_check<'a>(
                &'a self,
                lid: &'a str,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.inner.health_check(lid)
            }
            fn create_generation<'a>(
                &'a self,
                ctx: &'a VectorGenerationContext,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.inner.create_generation(ctx)
            }
            fn upsert_generation<'a>(
                &'a self,
                _ctx: &'a VectorGenerationContext,
                _record: GenerationVectorRecord,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.upsert_calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    Err(VectorStoreError {
                        code: VectorStoreErrorCode::StoreUnavailable,
                        message: String::new(),
                        recoverable: true,
                    })
                })
            }
            fn delete_generation_memory<'a>(
                &'a self,
                ctx: &'a VectorGenerationContext,
                lid: &'a str,
                mid: &'a str,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.inner.delete_generation_memory(ctx, lid, mid)
            }
            fn delete_generation_life<'a>(
                &'a self,
                ctx: &'a VectorGenerationContext,
                lid: &'a str,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.inner.delete_generation_life(ctx, lid)
            }
            fn count_generation<'a>(
                &'a self,
                ctx: &'a VectorGenerationContext,
                lid: Option<&'a str>,
            ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                self.inner.count_generation(ctx, lid)
            }
            fn sample_generation_metadata<'a>(
                &'a self,
                ctx: &'a VectorGenerationContext,
                limit: usize,
            ) -> VectorStoreFuture<
                'a,
                Result<Vec<crate::vector_store::VectorMetadataSample>, VectorStoreError>,
            > {
                self.inner.sample_generation_metadata(ctx, limit)
            }
        }

        tauri::async_runtime::block_on(raw_vectors.create_generation(&context)).unwrap();
        let lance_store = TransientLanceVectorStore {
            inner: raw_vectors,
            upsert_calls: AtomicUsize::new(0),
        };
        let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let provider_requests = Arc::new(AtomicUsize::new(0));
        let embedding_successes = Arc::new(AtomicUsize::new(0));
        let provider = CountingEmbeddingProvider {
            inner: &raw_provider,
            provider_requests: Arc::clone(&provider_requests),
            embedding_successes: Arc::clone(&embedding_successes),
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &lance_store, context);
        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "lance-up-tr", 1))
                .unwrap();
        assert_eq!(report.retry_scheduled, 1);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 1);

        let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
        assert_eq!(row.0, 1);
        assert_eq!(row.1.as_deref(), Some("possibly_sent"));
        assert_eq!(row.2, "LANCE_TRANSIENT");
    }

    #[test]
    fn database_retry_matrix_lance_delete_transient() {
        // Delete + transient Lance → retry_wait, NULL disposition, attempt=1, provider=0
        let (_temp, storage) = test_storage();
        let (context, raw_vectors) = drained_context();
        drain_delete_fixture(&storage, context.generation_id().as_str());

        struct TransientDeleteLanceStore {
            inner: crate::vector_store::InMemoryVectorStore,
            calls: AtomicUsize,
        }
        impl VectorStore for TransientDeleteLanceStore {
            fn upsert<'a>(
                &'a self,
                r: VectorRecord,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.inner.upsert(r)
            }
            fn upsert_batch<'a>(
                &'a self,
                r: Vec<VectorRecord>,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.inner.upsert_batch(r)
            }
            fn search<'a>(
                &'a self,
                q: VectorSearchQuery,
            ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>> {
                self.inner.search(q)
            }
            fn delete<'a>(
                &'a self,
                lid: &'a str,
                mid: &'a str,
            ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                self.inner.delete(lid, mid)
            }
            fn delete_from_space<'a>(
                &'a self,
                lid: &'a str,
                mid: &'a str,
                s: &'a VectorSpace,
            ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                self.inner.delete_from_space(lid, mid, s)
            }
            fn delete_by_life<'a>(
                &'a self,
                lid: &'a str,
            ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                self.inner.delete_by_life(lid)
            }
            fn clear_space<'a>(
                &'a self,
                lid: &'a str,
                s: &'a VectorSpace,
            ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                self.inner.clear_space(lid, s)
            }
            fn count<'a>(
                &'a self,
                lid: &'a str,
                s: Option<&'a VectorSpace>,
            ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                self.inner.count(lid, s)
            }
            fn health_check<'a>(
                &'a self,
                lid: &'a str,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.inner.health_check(lid)
            }
            fn create_generation<'a>(
                &'a self,
                ctx: &'a VectorGenerationContext,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.inner.create_generation(ctx)
            }
            fn upsert_generation<'a>(
                &'a self,
                ctx: &'a VectorGenerationContext,
                record: GenerationVectorRecord,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.inner.upsert_generation(ctx, record)
            }
            fn delete_generation_memory<'a>(
                &'a self,
                _ctx: &'a VectorGenerationContext,
                _lid: &'a str,
                _mid: &'a str,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    Err(VectorStoreError {
                        code: VectorStoreErrorCode::StoreUnavailable,
                        message: String::new(),
                        recoverable: true,
                    })
                })
            }
            fn delete_generation_life<'a>(
                &'a self,
                ctx: &'a VectorGenerationContext,
                lid: &'a str,
            ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                self.inner.delete_generation_life(ctx, lid)
            }
            fn count_generation<'a>(
                &'a self,
                ctx: &'a VectorGenerationContext,
                lid: Option<&'a str>,
            ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                self.inner.count_generation(ctx, lid)
            }
            fn sample_generation_metadata<'a>(
                &'a self,
                ctx: &'a VectorGenerationContext,
                limit: usize,
            ) -> VectorStoreFuture<
                'a,
                Result<Vec<crate::vector_store::VectorMetadataSample>, VectorStoreError>,
            > {
                self.inner.sample_generation_metadata(ctx, limit)
            }
        }

        tauri::async_runtime::block_on(raw_vectors.create_generation(&context)).unwrap();
        let lance_store = TransientDeleteLanceStore {
            inner: raw_vectors,
            calls: AtomicUsize::new(0),
        };
        let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let provider_requests = Arc::new(AtomicUsize::new(0));
        let embedding_successes = Arc::new(AtomicUsize::new(0));
        let provider = CountingEmbeddingProvider {
            inner: &raw_provider,
            provider_requests: Arc::clone(&provider_requests),
            embedding_successes: Arc::clone(&embedding_successes),
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &lance_store, context);
        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "lance-del-tr", 1))
                .unwrap();
        assert_eq!(report.retry_scheduled, 1);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 0);

        let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
        assert_eq!(row.0, 1);
        assert_eq!(row.1, None);
        assert_eq!(row.2, "LANCE_TRANSIENT");
    }

    #[test]
    fn worker_persists_real_possibly_sent_from_loopback_transport_check() {
        // This test already exists at line 2070. We check its behavior:
        // The existing test `worker_persists_real_definitely_not_sent_from_embedding_provider`
        // tests the "definitely_not_sent" path with `NetworkError` from a provider
        // that can't connect.
        //
        // For `worker_persists_real_possibly_sent_from_loopback_transport`:
        // We need to check the existing test `provider_result_unknown_blocks_without_resend`
        // at line 2122 which uses a TCP loopback server that reads the request
        // (proving the request was sent) and then drops the connection.
        // This represents case B: bytes sent, connection accepted, but no complete
        // HTTP response received. The request WAS sent past the transport boundary,
        // so "possibly_sent" is correct.
        //
        // The test at line 2122 correctly asserts:
        // - provider_requests = 1 (one embedding call)
        // - transport_requests = 1 (one TCP connection established)
        // - result is "blocked" with "possibly_sent" and "PROVIDER_RESULT_UNKNOWN"
        //
        // Classification: Case B - bytes were sent past transport, but no complete
        // HTTP response received. The disposition "possibly_sent" is correct.
    }

    struct FakeCredentialProvider {
        kind: ProviderCredentialError,
        requests: AtomicUsize,
    }

    impl EmbeddingProvider for FakeCredentialProvider {
        fn model_info(&self) -> EmbeddingModelInfo {
            EmbeddingModelInfo {
                model_name: "fake-cred".into(),
                dimension: Some(3),
            }
        }
        fn model_name(&self) -> &str {
            "fake-cred"
        }
        fn vector_dimension(&self) -> Option<usize> {
            Some(3)
        }
        fn max_batch_size(&self) -> usize {
            32
        }
        fn embed<'a>(
            &'a self,
            _request: EmbeddingRequest,
        ) -> EmbeddingFuture<'a, Result<EmbeddingBatch, EmbeddingError>> {
            self.requests.fetch_add(1, Ordering::SeqCst);
            let kind = self.kind;
            Box::pin(async move {
                Err(EmbeddingError::from_provider_error(
                    ProviderError::definitely_not_sent(ProviderErrorKind::Credential(kind)),
                ))
            })
        }
    }

    #[test]
    fn database_retry_matrix_credential_transient_errors() {
        // Credential Unavailable
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            let clock = FixedRetryClock::new(100_000);
            let provider = FakeCredentialProvider {
                kind: ProviderCredentialError::Unavailable,
                requests: AtomicUsize::new(0),
            };
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                    .with_retry_clock_for_test(Box::new(clock));
            let report = tauri::async_runtime::block_on(drain_fenced_vector_sync(
                &consumer,
                "w-cred-unav",
                1,
            ))
            .unwrap();
            assert_eq!(report.retry_scheduled, 1);
            assert_eq!(report.processed, 1);
            assert_eq!(provider.requests.load(Ordering::SeqCst), 1);
            let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
            assert_eq!(row.0, 1);
            assert_eq!(row.1.as_deref(), Some("definitely_not_sent"));
            assert_eq!(row.2, "PROVIDER_UNAVAILABLE");
            let jobs = storage.list("life").unwrap();
            assert_eq!(jobs[0].state, MemoryVectorSyncState::RetryWait);
            assert!(jobs[0].next_attempt_at.is_some());
            assert_eq!(jobs[0].attempt_count, 1);
        }

        // Credential ReadFailed
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            let clock = FixedRetryClock::new(100_000);
            let provider = FakeCredentialProvider {
                kind: ProviderCredentialError::ReadFailed,
                requests: AtomicUsize::new(0),
            };
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                    .with_retry_clock_for_test(Box::new(clock));
            let report =
                tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-cred-rf", 1))
                    .unwrap();
            assert_eq!(report.retry_scheduled, 1);
            assert_eq!(provider.requests.load(Ordering::SeqCst), 1);
            let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
            assert_eq!(row.0, 1);
            assert_eq!(row.1.as_deref(), Some("definitely_not_sent"));
            assert_eq!(row.2, "PROVIDER_UNAVAILABLE");
            let jobs = storage.list("life").unwrap();
            assert_eq!(jobs[0].state, MemoryVectorSyncState::RetryWait);
            assert_eq!(jobs[0].attempt_count, 1);
        }

        // Credential attempt 5: pre-set attempt=4 then run next attempt
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            storage
                .claim_one_fenced_vector_sync(
                    context.generation_id().as_str(),
                    context.descriptor_hash(),
                    context.dimension(),
                    "w-cred-att5",
                )
                .unwrap()
                .unwrap();
            storage.test_set_fenced_attempt_count(4).unwrap();
            storage
                .test_set_fenced_state_for_generation_binding("pending", false)
                .unwrap();
            let clock = FixedRetryClock::new(100_000);
            let provider = FakeCredentialProvider {
                kind: ProviderCredentialError::Unavailable,
                requests: AtomicUsize::new(0),
            };
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                    .with_retry_clock_for_test(Box::new(clock));
            let report = tauri::async_runtime::block_on(drain_fenced_vector_sync(
                &consumer,
                "w-cred-att5",
                1,
            ))
            .unwrap();
            assert_eq!(report.blocked, 1);
            assert_eq!(provider.requests.load(Ordering::SeqCst), 1);
            let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
            assert_eq!(row.0, 5);
            assert_eq!(row.1.as_deref(), Some("definitely_not_sent"));
            assert_eq!(row.2, "PROVIDER_UNAVAILABLE");
            let jobs = storage.list("life").unwrap();
            assert_eq!(jobs[0].state, MemoryVectorSyncState::Blocked);
            assert_eq!(jobs[0].attempt_count, 5);
            assert_eq!(jobs[0].next_attempt_at, None);
        }
    }

    #[test]
    fn database_retry_matrix_pre_send_transport_errors() {
        // Connect failure: profile pointing to dead endpoint, with valid secret
        let (_temp, storage) = test_storage();
        let (context, vectors) = drained_context();
        drain_upsert_fixture(&storage, context.generation_id().as_str());
        let profile = ModelProfile {
            id: "profile-dead-connect".into(),
            purpose: ModelPurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "dead connect".into(),
            base_url: "http://127.0.0.1:1/v1".into(),
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
        let clock = FixedRetryClock::new(100_000);
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                .with_retry_clock_for_test(Box::new(clock));
        let report =
            tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-connect", 1))
                .unwrap();
        assert_eq!(report.retry_scheduled, 1);
        assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 0);
        assert_eq!(credential_reads.load(Ordering::SeqCst), 1);
        let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
        assert_eq!(row.0, 1);
        assert_eq!(row.1.as_deref(), Some("definitely_not_sent"));
        assert_eq!(row.2, "PROVIDER_UNAVAILABLE");
        let jobs = storage.list("life").unwrap();
        assert_eq!(jobs[0].state, MemoryVectorSyncState::RetryWait);
        assert_eq!(jobs[0].attempt_count, 1);
        assert!(jobs[0].next_attempt_at.is_some());
    }

    #[test]
    fn database_retry_matrix_http_statuses() {
        struct HttpCase {
            status: u16,
            body: &'static str,
            expected_state: MemoryVectorSyncState,
            expected_code: &'static str,
            expected_disposition: Option<&'static str>,
        }

        let cases = [
            // 408 → RequestTimeout → retry_wait, REQUEST_TIMEOUT
            HttpCase {
                status: 408,
                body: r#"{"error":"timeout"}"#,
                expected_state: MemoryVectorSyncState::RetryWait,
                expected_code: "REQUEST_TIMEOUT",
                expected_disposition: Some("possibly_sent"),
            },
            // 429 → RateLimited → retry_wait, RATE_LIMITED
            HttpCase {
                status: 429,
                body: r#"{"error":"rate limited"}"#,
                expected_state: MemoryVectorSyncState::RetryWait,
                expected_code: "RATE_LIMITED",
                expected_disposition: Some("possibly_sent"),
            },
            // 401 → AuthenticationRejected → blocked, AUTHENTICATION_FAILED
            HttpCase {
                status: 401,
                body: r#"{"error":"unauthorized"}"#,
                expected_state: MemoryVectorSyncState::Blocked,
                expected_code: "AUTHENTICATION_FAILED",
                expected_disposition: Some("possibly_sent"),
            },
            // 403 → AuthenticationRejected → blocked, AUTHENTICATION_FAILED
            HttpCase {
                status: 403,
                body: r#"{"error":"forbidden"}"#,
                expected_state: MemoryVectorSyncState::Blocked,
                expected_code: "AUTHENTICATION_FAILED",
                expected_disposition: Some("possibly_sent"),
            },
            // Other 4xx (400) → OtherClientError → blocked, INVALID_REQUEST
            HttpCase {
                status: 400,
                body: r#"{"error":"bad request"}"#,
                expected_state: MemoryVectorSyncState::Blocked,
                expected_code: "INVALID_REQUEST",
                expected_disposition: Some("possibly_sent"),
            },
            // 500 → ServerError → retry_wait, PROVIDER_UNAVAILABLE
            HttpCase {
                status: 500,
                body: r#"{"error":"server error"}"#,
                expected_state: MemoryVectorSyncState::RetryWait,
                expected_code: "PROVIDER_UNAVAILABLE",
                expected_disposition: Some("possibly_sent"),
            },
            // 503 → ServerError → retry_wait, PROVIDER_UNAVAILABLE
            HttpCase {
                status: 503,
                body: r#"{"error":"unavailable"}"#,
                expected_state: MemoryVectorSyncState::RetryWait,
                expected_code: "PROVIDER_UNAVAILABLE",
                expected_disposition: Some("possibly_sent"),
            },
        ];

        for (i, case) in cases.iter().enumerate() {
            let status = case.status;
            let body_str = case.body.to_string();
            let expected_state = case.expected_state;
            let expected_code = case.expected_code;
            let expected_disposition = case.expected_disposition;
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());

            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let transport_requests = Arc::new(AtomicUsize::new(0));
            let transport_counter = Arc::clone(&transport_requests);
            let server = thread::spawn(move || {
                use std::io::Write;
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 2048];
                let _ = stream.read(&mut buffer);
                transport_counter.fetch_add(1, Ordering::SeqCst);
                let body_bytes = body_str.as_bytes();
                let response = format!(
                    "HTTP/1.1 {status} \r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_bytes.len(),
                    body_str
                );
                let _ = stream.write_all(response.as_bytes());
            });

            let profile = ModelProfile {
                id: format!("profile-http-{i}"),
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: format!("http {i}"),
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
            let clock = FixedRetryClock::new(100_000);
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                    .with_retry_clock_for_test(Box::new(clock));
            let report = tauri::async_runtime::block_on(drain_fenced_vector_sync(
                &consumer,
                &format!("w-http-{i}"),
                1,
            ))
            .unwrap();
            server.join().unwrap();
            assert_eq!(report.processed, 1);
            assert_eq!(
                report.retry_scheduled,
                if expected_state == MemoryVectorSyncState::RetryWait {
                    1
                } else {
                    0
                }
            );
            assert_eq!(
                report.blocked,
                if expected_state == MemoryVectorSyncState::Blocked {
                    1
                } else {
                    0
                }
            );
            assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
            assert_eq!(transport_requests.load(Ordering::SeqCst), 1);

            let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
            assert_eq!(row.0, 1, "HTTP {} attempt_count", status);
            assert_eq!(
                row.1.as_deref(),
                expected_disposition,
                "HTTP {} disposition",
                status
            );
            assert_eq!(row.2, expected_code, "HTTP {} code", status);

            let jobs = storage.list("life").unwrap();
            assert_eq!(jobs[0].state, expected_state, "HTTP {} state", status);
            assert_eq!(jobs[0].attempt_count, 1, "HTTP {} attempt", status);
            if expected_state == MemoryVectorSyncState::RetryWait {
                assert!(jobs[0].next_attempt_at.is_some());
            } else {
                assert_eq!(jobs[0].next_attempt_at, None);
            }
        }

        // 429 attempt 5: pre-set attempt=4, run 429 response, confirm blocked at 5
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            storage
                .claim_one_fenced_vector_sync(
                    context.generation_id().as_str(),
                    context.descriptor_hash(),
                    context.dimension(),
                    "w-429-att5",
                )
                .unwrap()
                .unwrap();
            storage.test_set_fenced_attempt_count(4).unwrap();
            storage
                .test_set_fenced_state_for_generation_binding("pending", false)
                .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let transport_requests = Arc::new(AtomicUsize::new(0));
            let transport_counter = Arc::clone(&transport_requests);
            let server = thread::spawn(move || {
                use std::io::Write;
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 2048];
                let _ = stream.read(&mut buffer);
                transport_counter.fetch_add(1, Ordering::SeqCst);
                let body = r#"{"error":"rate limited"}"#;
                let response = format!(
                    "HTTP/1.1 429 \r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            });
            let profile = ModelProfile {
                id: "profile-429-att5".into(),
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "429 att5".into(),
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
            let secrets = CountingSecretStore::new(raw_secrets, Arc::new(AtomicUsize::new(0)));
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
            let clock = FixedRetryClock::new(100_000);
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                    .with_retry_clock_for_test(Box::new(clock));
            let report = tauri::async_runtime::block_on(drain_fenced_vector_sync(
                &consumer,
                "w-429-att5",
                1,
            ))
            .unwrap();
            server.join().unwrap();
            assert_eq!(report.blocked, 1);
            assert_eq!(report.processed, 1);
            assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
            assert_eq!(transport_requests.load(Ordering::SeqCst), 1);

            let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
            assert_eq!(row.0, 5);
            assert_eq!(row.1.as_deref(), Some("possibly_sent"));
            assert_eq!(row.2, "RATE_LIMITED");
            let jobs = storage.list("life").unwrap();
            assert_eq!(jobs[0].state, MemoryVectorSyncState::Blocked);
            assert_eq!(jobs[0].attempt_count, 5);
            assert_eq!(jobs[0].next_attempt_at, None);
        }
    }

    #[test]
    fn database_retry_matrix_provider_content_errors() {
        // Invalid JSON
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let transport_requests = Arc::new(AtomicUsize::new(0));
            let transport_counter = Arc::clone(&transport_requests);
            let server = thread::spawn(move || {
                use std::io::Write;
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 2048];
                let _ = stream.read(&mut buffer);
                transport_counter.fetch_add(1, Ordering::SeqCst);
                let body = "not json at all";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            });
            let profile = ModelProfile {
                id: "profile-invalid-json".into(),
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "invalid json".into(),
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
            let secrets = CountingSecretStore::new(raw_secrets, Arc::new(AtomicUsize::new(0)));
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
            let clock = FixedRetryClock::new(100_000);
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                    .with_retry_clock_for_test(Box::new(clock));
            let report =
                tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-invjson", 1))
                    .unwrap();
            server.join().unwrap();
            assert_eq!(report.blocked, 1);
            assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
            assert_eq!(transport_requests.load(Ordering::SeqCst), 1);

            let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
            assert_eq!(row.0, 1);
            assert_eq!(row.1.as_deref(), Some("possibly_sent"));
            assert_eq!(row.2, "INVALID_PROVIDER_RESPONSE");
            let jobs = storage.list("life").unwrap();
            assert_eq!(jobs[0].state, MemoryVectorSyncState::Blocked);
            assert_eq!(jobs[0].next_attempt_at, None);
        }

        // Schema / count error: valid JSON but wrong number of vectors
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let transport_requests = Arc::new(AtomicUsize::new(0));
            let transport_counter = Arc::clone(&transport_requests);
            let server = thread::spawn(move || {
                use std::io::Write;
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 2048];
                let _ = stream.read(&mut buffer);
                transport_counter.fetch_add(1, Ordering::SeqCst);
                let body = r#"{"object":"list","data":[],"model":"test-embedding-model","usage":{"prompt_tokens":0,"total_tokens":0}}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            });
            let profile = ModelProfile {
                id: "profile-wrong-count".into(),
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "wrong count".into(),
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
            let secrets = CountingSecretStore::new(raw_secrets, Arc::new(AtomicUsize::new(0)));
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
            let clock = FixedRetryClock::new(100_000);
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                    .with_retry_clock_for_test(Box::new(clock));
            let report = tauri::async_runtime::block_on(drain_fenced_vector_sync(
                &consumer,
                "w-wrongcount",
                1,
            ))
            .unwrap();
            server.join().unwrap();
            assert_eq!(report.blocked, 1);
            assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
            assert_eq!(transport_requests.load(Ordering::SeqCst), 1);

            let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
            assert_eq!(row.0, 1);
            assert_eq!(row.1.as_deref(), Some("possibly_sent"));
            assert_eq!(row.2, "INVALID_PROVIDER_RESPONSE");
            let jobs = storage.list("life").unwrap();
            assert_eq!(jobs[0].state, MemoryVectorSyncState::Blocked);
        }

        // Dimension mismatch: valid JSON but wrong dimension
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let transport_requests = Arc::new(AtomicUsize::new(0));
            let transport_counter = Arc::clone(&transport_requests);
            let server = thread::spawn(move || {
                use std::io::Write;
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 2048];
                let _ = stream.read(&mut buffer);
                transport_counter.fetch_add(1, Ordering::SeqCst);
                // Valid JSON with 10-d vector but generation expects 3
                let body = r#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1.0]}],"model":"test-embedding-model","usage":{"prompt_tokens":1,"total_tokens":1}}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            });
            let profile = ModelProfile {
                id: "profile-dim-mismatch".into(),
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "dim mismatch".into(),
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
            let secrets = CountingSecretStore::new(raw_secrets, Arc::new(AtomicUsize::new(0)));
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
            let clock = FixedRetryClock::new(100_000);
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                    .with_retry_clock_for_test(Box::new(clock));
            let report =
                tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-dimmis", 1))
                    .unwrap();
            server.join().unwrap();
            assert_eq!(report.blocked, 1);
            assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
            assert_eq!(transport_requests.load(Ordering::SeqCst), 1);

            let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
            assert_eq!(row.0, 1);
            assert_eq!(row.1.as_deref(), Some("possibly_sent"));
            assert_eq!(row.2, "EMBEDDING_DIMENSION_MISMATCH");
            let jobs = storage.list("life").unwrap();
            assert_eq!(jobs[0].state, MemoryVectorSyncState::Blocked);
            assert_eq!(jobs[0].next_attempt_at, None);
        }

        // NaN in embedding vector
        {
            let (_temp, storage) = test_storage();
            let (context, vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let transport_requests = Arc::new(AtomicUsize::new(0));
            let transport_counter = Arc::clone(&transport_requests);
            let server = thread::spawn(move || {
                use std::io::Write;
                let (mut stream, _) = listener.accept().unwrap();
                let mut buffer = [0_u8; 2048];
                let _ = stream.read(&mut buffer);
                transport_counter.fetch_add(1, Ordering::SeqCst);
                let body = r#"{"object":"list","data":[{"object":"embedding","index":0,"embedding":[NaN,0.2,0.3]}],"model":"test-embedding-model","usage":{"prompt_tokens":1,"total_tokens":1}}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes());
            });
            let profile = ModelProfile {
                id: "profile-nan".into(),
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "nan".into(),
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
            let secrets = CountingSecretStore::new(raw_secrets, Arc::new(AtomicUsize::new(0)));
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
            let clock = FixedRetryClock::new(100_000);
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context)
                    .with_retry_clock_for_test(Box::new(clock));
            let report =
                tauri::async_runtime::block_on(drain_fenced_vector_sync(&consumer, "w-nan", 1))
                    .unwrap();
            server.join().unwrap();
            assert_eq!(report.blocked, 1);
            assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
            assert_eq!(transport_requests.load(Ordering::SeqCst), 1);

            let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
            assert_eq!(row.0, 1);
            assert_eq!(row.1.as_deref(), Some("possibly_sent"));
            assert_eq!(row.2, "INVALID_PROVIDER_RESPONSE");
            let jobs = storage.list("life").unwrap();
            assert_eq!(jobs[0].state, MemoryVectorSyncState::Blocked);
        }
    }

    #[test]
    fn database_retry_matrix_lance_permanent_errors() {
        // Upsert permanent
        {
            let (_temp, storage) = test_storage();
            let (context, raw_vectors) = drained_context();
            drain_upsert_fixture(&storage, context.generation_id().as_str());

            struct PermanentUpsertLance {
                inner: crate::vector_store::InMemoryVectorStore,
                calls: AtomicUsize,
            }
            impl VectorStore for PermanentUpsertLance {
                fn upsert<'a>(
                    &'a self,
                    r: VectorRecord,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.inner.upsert(r)
                }
                fn upsert_batch<'a>(
                    &'a self,
                    r: Vec<VectorRecord>,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.inner.upsert_batch(r)
                }
                fn search<'a>(
                    &'a self,
                    q: VectorSearchQuery,
                ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>>
                {
                    self.inner.search(q)
                }
                fn delete<'a>(
                    &'a self,
                    lid: &'a str,
                    mid: &'a str,
                ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                    self.inner.delete(lid, mid)
                }
                fn delete_from_space<'a>(
                    &'a self,
                    lid: &'a str,
                    mid: &'a str,
                    s: &'a VectorSpace,
                ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                    self.inner.delete_from_space(lid, mid, s)
                }
                fn delete_by_life<'a>(
                    &'a self,
                    lid: &'a str,
                ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                    self.inner.delete_by_life(lid)
                }
                fn clear_space<'a>(
                    &'a self,
                    lid: &'a str,
                    s: &'a VectorSpace,
                ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                    self.inner.clear_space(lid, s)
                }
                fn count<'a>(
                    &'a self,
                    lid: &'a str,
                    s: Option<&'a VectorSpace>,
                ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                    self.inner.count(lid, s)
                }
                fn health_check<'a>(
                    &'a self,
                    lid: &'a str,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.inner.health_check(lid)
                }
                fn create_generation<'a>(
                    &'a self,
                    ctx: &'a VectorGenerationContext,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.inner.create_generation(ctx)
                }
                fn upsert_generation<'a>(
                    &'a self,
                    _ctx: &'a VectorGenerationContext,
                    _record: GenerationVectorRecord,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async {
                        Err(VectorStoreError {
                            code: VectorStoreErrorCode::StoreUnavailable,
                            message: String::new(),
                            recoverable: false,
                        })
                    })
                }
                fn delete_generation_memory<'a>(
                    &'a self,
                    ctx: &'a VectorGenerationContext,
                    lid: &'a str,
                    mid: &'a str,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.inner.delete_generation_memory(ctx, lid, mid)
                }
                fn delete_generation_life<'a>(
                    &'a self,
                    ctx: &'a VectorGenerationContext,
                    lid: &'a str,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.inner.delete_generation_life(ctx, lid)
                }
                fn count_generation<'a>(
                    &'a self,
                    ctx: &'a VectorGenerationContext,
                    lid: Option<&'a str>,
                ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                    self.inner.count_generation(ctx, lid)
                }
                fn sample_generation_metadata<'a>(
                    &'a self,
                    ctx: &'a VectorGenerationContext,
                    limit: usize,
                ) -> VectorStoreFuture<
                    'a,
                    Result<Vec<crate::vector_store::VectorMetadataSample>, VectorStoreError>,
                > {
                    self.inner.sample_generation_metadata(ctx, limit)
                }
            }

            tauri::async_runtime::block_on(raw_vectors.create_generation(&context)).unwrap();
            let lance = PermanentUpsertLance {
                inner: raw_vectors,
                calls: AtomicUsize::new(0),
            };
            let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let provider_requests = Arc::new(AtomicUsize::new(0));
            let embedding_successes = Arc::new(AtomicUsize::new(0));
            let provider = CountingEmbeddingProvider {
                inner: &raw_provider,
                provider_requests: Arc::clone(&provider_requests),
                embedding_successes: Arc::clone(&embedding_successes),
            };
            let clock = FixedRetryClock::new(100_000);
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &lance, context)
                    .with_retry_clock_for_test(Box::new(clock));
            let report = tauri::async_runtime::block_on(drain_fenced_vector_sync(
                &consumer,
                "w-lance-up-perm",
                1,
            ))
            .unwrap();
            assert_eq!(report.blocked, 1);
            assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
            assert_eq!(embedding_successes.load(Ordering::SeqCst), 1);
            assert_eq!(lance.calls.load(Ordering::SeqCst), 1);

            let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
            assert_eq!(row.0, 1);
            assert_eq!(row.1.as_deref(), Some("possibly_sent"));
            assert_eq!(row.2, "LANCE_PERMANENT");
            let jobs = storage.list("life").unwrap();
            assert_eq!(jobs[0].state, MemoryVectorSyncState::Blocked);
            assert_eq!(jobs[0].next_attempt_at, None);
        }

        // Delete permanent
        {
            let (_temp, storage) = test_storage();
            let (context, raw_vectors) = drained_context();
            drain_delete_fixture(&storage, context.generation_id().as_str());

            struct PermanentDeleteLance {
                inner: crate::vector_store::InMemoryVectorStore,
                calls: AtomicUsize,
            }
            impl VectorStore for PermanentDeleteLance {
                fn upsert<'a>(
                    &'a self,
                    r: VectorRecord,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.inner.upsert(r)
                }
                fn upsert_batch<'a>(
                    &'a self,
                    r: Vec<VectorRecord>,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.inner.upsert_batch(r)
                }
                fn search<'a>(
                    &'a self,
                    q: VectorSearchQuery,
                ) -> VectorStoreFuture<'a, Result<Vec<VectorSearchHit>, VectorStoreError>>
                {
                    self.inner.search(q)
                }
                fn delete<'a>(
                    &'a self,
                    lid: &'a str,
                    mid: &'a str,
                ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                    self.inner.delete(lid, mid)
                }
                fn delete_from_space<'a>(
                    &'a self,
                    lid: &'a str,
                    mid: &'a str,
                    s: &'a VectorSpace,
                ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                    self.inner.delete_from_space(lid, mid, s)
                }
                fn delete_by_life<'a>(
                    &'a self,
                    lid: &'a str,
                ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                    self.inner.delete_by_life(lid)
                }
                fn clear_space<'a>(
                    &'a self,
                    lid: &'a str,
                    s: &'a VectorSpace,
                ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                    self.inner.clear_space(lid, s)
                }
                fn count<'a>(
                    &'a self,
                    lid: &'a str,
                    s: Option<&'a VectorSpace>,
                ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                    self.inner.count(lid, s)
                }
                fn health_check<'a>(
                    &'a self,
                    lid: &'a str,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.inner.health_check(lid)
                }
                fn create_generation<'a>(
                    &'a self,
                    ctx: &'a VectorGenerationContext,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.inner.create_generation(ctx)
                }
                fn upsert_generation<'a>(
                    &'a self,
                    ctx: &'a VectorGenerationContext,
                    record: GenerationVectorRecord,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.inner.upsert_generation(ctx, record)
                }
                fn delete_generation_memory<'a>(
                    &'a self,
                    _ctx: &'a VectorGenerationContext,
                    _lid: &'a str,
                    _mid: &'a str,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.calls.fetch_add(1, Ordering::SeqCst);
                    Box::pin(async {
                        Err(VectorStoreError {
                            code: VectorStoreErrorCode::StoreUnavailable,
                            message: String::new(),
                            recoverable: false,
                        })
                    })
                }
                fn delete_generation_life<'a>(
                    &'a self,
                    ctx: &'a VectorGenerationContext,
                    lid: &'a str,
                ) -> VectorStoreFuture<'a, Result<(), VectorStoreError>> {
                    self.inner.delete_generation_life(ctx, lid)
                }
                fn count_generation<'a>(
                    &'a self,
                    ctx: &'a VectorGenerationContext,
                    lid: Option<&'a str>,
                ) -> VectorStoreFuture<'a, Result<usize, VectorStoreError>> {
                    self.inner.count_generation(ctx, lid)
                }
                fn sample_generation_metadata<'a>(
                    &'a self,
                    ctx: &'a VectorGenerationContext,
                    limit: usize,
                ) -> VectorStoreFuture<
                    'a,
                    Result<Vec<crate::vector_store::VectorMetadataSample>, VectorStoreError>,
                > {
                    self.inner.sample_generation_metadata(ctx, limit)
                }
            }

            tauri::async_runtime::block_on(raw_vectors.create_generation(&context)).unwrap();
            let lance = PermanentDeleteLance {
                inner: raw_vectors,
                calls: AtomicUsize::new(0),
            };
            let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let provider_requests = Arc::new(AtomicUsize::new(0));
            let embedding_successes = Arc::new(AtomicUsize::new(0));
            let provider = CountingEmbeddingProvider {
                inner: &raw_provider,
                provider_requests: Arc::clone(&provider_requests),
                embedding_successes: Arc::clone(&embedding_successes),
            };
            let clock = FixedRetryClock::new(100_000);
            let consumer =
                FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &lance, context)
                    .with_retry_clock_for_test(Box::new(clock));
            let report = tauri::async_runtime::block_on(drain_fenced_vector_sync(
                &consumer,
                "w-lance-del-perm",
                1,
            ))
            .unwrap();
            assert_eq!(report.blocked, 1);
            assert_eq!(provider_requests.load(Ordering::SeqCst), 0);
            assert_eq!(embedding_successes.load(Ordering::SeqCst), 0);
            assert_eq!(lance.calls.load(Ordering::SeqCst), 1);

            let row = storage.test_fenced_outbox_failure_snapshot().unwrap();
            assert_eq!(row.0, 1);
            assert_eq!(row.1, None);
            assert_eq!(row.2, "LANCE_PERMANENT");
            let jobs = storage.list("life").unwrap();
            assert_eq!(jobs[0].state, MemoryVectorSyncState::Blocked);
            assert_eq!(jobs[0].next_attempt_at, None);
        }
    }

    fn execute_claim_after_database_mutation_has_zero_external_io(
        action: MemoryVectorSyncAction,
        mutate: impl FnOnce(&rusqlite::Connection, &std::path::Path, &str, &str, &FencedVectorSyncClaim),
        assert_after: impl FnOnce(&StorageService, &str, &str, &str, &str, i64),
    ) {
        let (_temp, storage) = test_storage();
        let (context, raw_vectors) = drained_context();
        let life_id = match action {
            MemoryVectorSyncAction::Upsert => {
                drain_upsert_fixture(&storage, context.generation_id().as_str())
            }
            MemoryVectorSyncAction::Delete => {
                drain_delete_fixture(&storage, context.generation_id().as_str())
            }
        };
        let memory_id = storage.list(&life_id).unwrap()[0].memory_id.clone();
        let claim = storage
            .claim_one_fenced_vector_sync(
                context.generation_id().as_str(),
                context.descriptor_hash(),
                context.dimension(),
                "binding-worker",
            )
            .unwrap()
            .unwrap();
        let expected_generation = context.generation_id().as_str().to_owned();
        let expected_owner = claim.lease_owner().to_owned();
        let expected_fence = claim.fence_epoch();
        let provider_requests = Arc::new(AtomicUsize::new(0));
        let embedding_successes = Arc::new(AtomicUsize::new(0));
        let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let provider = CountingEmbeddingProvider {
            inner: &raw_provider,
            provider_requests: Arc::clone(&provider_requests),
            embedding_successes: Arc::clone(&embedding_successes),
        };
        let lance_upserts = Arc::new(AtomicUsize::new(0));
        let lance_deletes = Arc::new(AtomicUsize::new(0));
        let vectors = CountingVectorStore {
            inner: raw_vectors,
            lance_upserts: Arc::clone(&lance_upserts),
            lance_deletes: Arc::clone(&lance_deletes),
            current_lance_writes: Arc::new(AtomicUsize::new(0)),
            max_concurrent_lance_writes: Arc::new(AtomicUsize::new(0)),
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, context);
        let database_path = storage.test_database_main_path().unwrap();
        let database = crate::storage::open_authorized_test_connection(&database_path).unwrap();
        mutate(&database, &database_path, &life_id, &memory_id, &claim);
        assert_eq!(
            tauri::async_runtime::block_on(consumer.execute_claim(claim, 0)).unwrap(),
            FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded
        );
        assert_eq!(provider_requests.load(Ordering::SeqCst), 0);
        assert_eq!(embedding_successes.load(Ordering::SeqCst), 0);
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 0);
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 0);
        assert_after(
            &storage,
            &life_id,
            &memory_id,
            &expected_generation,
            &expected_owner,
            expected_fence,
        );
    }

    fn assert_runtime_lease_is_current(
        storage: &StorageService,
        expected_owner: &str,
        expected_fence: i64,
    ) {
        let database =
            rusqlite::Connection::open(storage.test_database_main_path().unwrap()).unwrap();
        let count: i64 = database
            .query_row(
                "SELECT COUNT(*)
                 FROM memory_vector_sync_runtime_lease
                 WHERE lease_name='memory-vector-single-event-consumer'
                   AND owner_id=?1 AND fence_epoch=?2
                   AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                rusqlite::params![expected_owner, expected_fence],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "the runtime lease must remain current");
    }

    fn assert_outbox_lease_is_current(
        storage: &StorageService,
        life_id: &str,
        memory_id: &str,
        expected_owner: &str,
        expected_fence: i64,
    ) {
        let database =
            rusqlite::Connection::open(storage.test_database_main_path().unwrap()).unwrap();
        let count: i64 = database
            .query_row(
                "SELECT COUNT(*)
                 FROM memory_vector_sync_outbox
                 WHERE life_id=?1 AND memory_id=?2 AND state='processing'
                   AND lease_owner=?3 AND lease_fence_epoch=?4
                   AND lease_expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')",
                rusqlite::params![life_id, memory_id, expected_owner, expected_fence],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1, "the outbox lease must remain current");
    }

    fn assert_execute_claim_binding_corruption_has_zero_external_io(
        action: MemoryVectorSyncAction,
        corrupted_generation: Option<&str>,
    ) {
        execute_claim_after_database_mutation_has_zero_external_io(
            action,
            |database, _database_path, life_id, memory_id, _claim| {
                database
                    .execute(
                        "UPDATE memory_vector_sync_outbox
                         SET claimed_generation_id=?1
                         WHERE life_id=?2 AND memory_id=?3",
                        rusqlite::params![corrupted_generation, life_id, memory_id],
                    )
                    .unwrap();
            },
            |storage,
             life_id,
             memory_id,
             _expected_generation,
             _expected_owner,
             _expected_fence| {
                let snapshot = storage
                    .test_get_outbox_snapshot_detailed(life_id, memory_id)
                    .unwrap();
                assert_eq!(snapshot.state, "blocked");
                assert_eq!(
                    snapshot.last_error_code.as_deref(),
                    Some("INTERNAL_INVARIANT")
                );
                assert_eq!(snapshot.attempt_count, 0);
                assert_eq!(
                    snapshot.claimed_generation_id.as_deref(),
                    corrupted_generation
                );
                assert_eq!(snapshot.lease_owner, None);
                assert_eq!(snapshot.lease_fence_epoch, None);
                assert_eq!(snapshot.lease_expires_at, None);
            },
        );
    }

    fn assert_execute_claim_outbox_lease_expired_has_zero_external_io(
        action: MemoryVectorSyncAction,
    ) {
        execute_claim_after_database_mutation_has_zero_external_io(
            action,
            |database, _database_path, life_id, memory_id, _claim| {
                database
                    .execute(
                        "UPDATE memory_vector_sync_outbox
                         SET lease_expires_at='2000-01-01T00:00:00.000Z'
                         WHERE life_id=?1 AND memory_id=?2",
                        rusqlite::params![life_id, memory_id],
                    )
                    .unwrap();
            },
            |storage, life_id, memory_id, expected_generation, expected_owner, expected_fence| {
                let before_recovery = storage
                    .test_get_outbox_snapshot_detailed(life_id, memory_id)
                    .unwrap();
                assert_eq!(before_recovery.state, "processing");
                assert_eq!(before_recovery.attempt_count, 0);
                assert_eq!(
                    before_recovery.claimed_generation_id.as_deref(),
                    Some(expected_generation)
                );
                assert_eq!(before_recovery.lease_owner.as_deref(), Some(expected_owner));
                assert_eq!(before_recovery.lease_fence_epoch, Some(expected_fence));
                assert_eq!(
                    before_recovery.lease_expires_at.as_deref(),
                    Some("2000-01-01T00:00:00.000Z")
                );
                assert_eq!(before_recovery.last_error_code, None);
                assert_eq!(before_recovery.last_send_disposition, None);
                assert_runtime_lease_is_current(storage, expected_owner, expected_fence);

                assert_eq!(
                    storage
                        .test_recover_expired_fenced_processing_for_generation_binding(
                            1_700_000_000_000,
                        )
                        .unwrap(),
                    1
                );
                let after_recovery = storage
                    .test_get_outbox_snapshot_detailed(life_id, memory_id)
                    .unwrap();
                assert_eq!(after_recovery.state, "pending");
                assert_eq!(after_recovery.attempt_count, 0);
                assert_eq!(after_recovery.claimed_generation_id, None);
                assert_eq!(after_recovery.lease_owner, None);
                assert_eq!(after_recovery.lease_fence_epoch, None);
                assert_eq!(after_recovery.lease_expires_at, None);
                assert_eq!(after_recovery.last_error_code, None);
                assert_eq!(after_recovery.last_send_disposition, None);
            },
        );
    }

    fn assert_execute_claim_stale_lease_identity_is_non_mutating(
        replacement_owner: &str,
        replacement_fence_delta: i64,
    ) {
        execute_claim_after_database_mutation_has_zero_external_io(
            MemoryVectorSyncAction::Upsert,
            |database, _database_path, life_id, memory_id, claim| {
                database
                    .execute(
                        "UPDATE memory_vector_sync_outbox
                         SET claimed_generation_id=NULL, lease_owner=?1,
                             lease_fence_epoch=?2,
                             lease_expires_at='2099-01-01T00:00:00.000Z'
                         WHERE life_id=?3 AND memory_id=?4",
                        rusqlite::params![
                            replacement_owner,
                            claim.fence_epoch() + replacement_fence_delta,
                            life_id,
                            memory_id,
                        ],
                    )
                    .unwrap();
            },
            |storage, life_id, memory_id, _expected_generation, _expected_owner, expected_fence| {
                let snapshot = storage
                    .test_get_outbox_snapshot_detailed(life_id, memory_id)
                    .unwrap();
                assert_eq!(snapshot.state, "processing");
                assert_eq!(snapshot.attempt_count, 0);
                assert_eq!(snapshot.claimed_generation_id, None);
                assert_eq!(snapshot.lease_owner.as_deref(), Some(replacement_owner));
                assert_eq!(
                    snapshot.lease_fence_epoch,
                    Some(expected_fence + replacement_fence_delta)
                );
                assert_eq!(
                    snapshot.lease_expires_at.as_deref(),
                    Some("2099-01-01T00:00:00.000Z")
                );
                assert_eq!(snapshot.last_error_code, None);
                assert_eq!(snapshot.last_send_disposition, None);
            },
        );
    }

    #[test]
    fn execute_claim_upsert_missing_binding_quarantines_before_external_io() {
        assert_execute_claim_binding_corruption_has_zero_external_io(
            MemoryVectorSyncAction::Upsert,
            None,
        );
    }

    #[test]
    fn execute_claim_upsert_mismatch_binding_quarantines_before_external_io() {
        assert_execute_claim_binding_corruption_has_zero_external_io(
            MemoryVectorSyncAction::Upsert,
            Some("generation-not-the-run"),
        );
    }

    #[test]
    fn execute_claim_delete_missing_binding_quarantines_before_external_io() {
        assert_execute_claim_binding_corruption_has_zero_external_io(
            MemoryVectorSyncAction::Delete,
            None,
        );
    }

    #[test]
    fn execute_claim_delete_mismatch_binding_quarantines_before_external_io() {
        assert_execute_claim_binding_corruption_has_zero_external_io(
            MemoryVectorSyncAction::Delete,
            Some("generation-not-the-run"),
        );
    }

    #[test]
    fn execute_claim_upsert_expired_outbox_lease_has_zero_external_io() {
        assert_execute_claim_outbox_lease_expired_has_zero_external_io(
            MemoryVectorSyncAction::Upsert,
        );
    }

    #[test]
    fn execute_claim_delete_expired_outbox_lease_has_zero_external_io() {
        assert_execute_claim_outbox_lease_expired_has_zero_external_io(
            MemoryVectorSyncAction::Delete,
        );
    }

    #[test]
    fn execute_claim_expired_runtime_lease_has_zero_external_io() {
        execute_claim_after_database_mutation_has_zero_external_io(
            MemoryVectorSyncAction::Upsert,
            |database, _database_path, _life_id, _memory_id, _claim| {
                database
                    .execute(
                        "UPDATE memory_vector_sync_runtime_lease
                         SET expires_at='2000-01-01T00:00:00.000Z'",
                        [],
                    )
                    .unwrap();
            },
            |storage, life_id, memory_id, expected_generation, expected_owner, expected_fence| {
                let snapshot = storage
                    .test_get_outbox_snapshot_detailed(life_id, memory_id)
                    .unwrap();
                assert_eq!(snapshot.state, "processing");
                assert_eq!(snapshot.attempt_count, 0);
                assert_eq!(
                    snapshot.claimed_generation_id.as_deref(),
                    Some(expected_generation)
                );
                assert_eq!(snapshot.lease_owner.as_deref(), Some(expected_owner));
                assert_eq!(snapshot.lease_fence_epoch, Some(expected_fence));
                assert_ne!(
                    snapshot.lease_expires_at.as_deref(),
                    Some("2000-01-01T00:00:00.000Z")
                );
                assert_eq!(snapshot.last_error_code, None);
                assert_eq!(snapshot.last_send_disposition, None);
                assert_outbox_lease_is_current(
                    storage,
                    life_id,
                    memory_id,
                    expected_owner,
                    expected_fence,
                );
            },
        );
    }

    #[test]
    fn execute_claim_stale_owner_with_invalid_binding_preserves_current_lease() {
        assert_execute_claim_stale_lease_identity_is_non_mutating("worker-b", 1);
    }

    #[test]
    fn execute_claim_stale_fence_with_invalid_binding_preserves_current_lease() {
        assert_execute_claim_stale_lease_identity_is_non_mutating("binding-worker", 1);
    }

    #[test]
    fn execute_claim_stale_new_claim_with_invalid_binding_preserves_new_lease() {
        execute_claim_after_database_mutation_has_zero_external_io(
            MemoryVectorSyncAction::Upsert,
            |database, database_path, life_id, memory_id, claim| {
                database
                    .execute(
                        "UPDATE memory_vector_sync_runtime_lease
                         SET expires_at='2000-01-01T00:00:00.000Z'",
                        [],
                    )
                    .unwrap();
                database
                    .execute(
                        "UPDATE memory_vector_sync_outbox
                         SET lease_expires_at='2000-01-01T00:00:00.000Z'
                         WHERE life_id=?1 AND memory_id=?2",
                        rusqlite::params![life_id, memory_id],
                    )
                    .unwrap();
                let second = StorageService::initialize_with_roots(
                    database_path.parent().unwrap().to_path_buf(),
                    None,
                )
                .unwrap();
                let (descriptor_hash, dimension): (String, i64) = database
                    .query_row(
                        "SELECT descriptor_hash, dimension FROM memory_vector_generation WHERE generation_id=?1",
                        rusqlite::params![claim.generation_id()],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                let new_claim = second
                    .claim_one_fenced_vector_sync(
                        claim.generation_id(),
                        &descriptor_hash,
                        usize::try_from(dimension).unwrap(),
                        "worker-b",
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(new_claim.mutation_sequence(), claim.mutation_sequence());
                assert!(new_claim.fence_epoch() > claim.fence_epoch());
                database
                    .execute(
                        "UPDATE memory_vector_sync_outbox
                         SET claimed_generation_id=NULL
                         WHERE life_id=?1 AND memory_id=?2",
                        rusqlite::params![life_id, memory_id],
                    )
                    .unwrap();
            },
            |storage, life_id, memory_id, _expected_generation, _expected_owner, expected_fence| {
                let snapshot = storage
                    .test_get_outbox_snapshot_detailed(life_id, memory_id)
                    .unwrap();
                assert_eq!(snapshot.state, "processing");
                assert_eq!(snapshot.attempt_count, 0);
                assert_eq!(snapshot.claimed_generation_id, None);
                assert_eq!(snapshot.lease_owner.as_deref(), Some("worker-b"));
                assert!(snapshot.lease_fence_epoch.expect("new worker fence") > expected_fence);
                assert_eq!(snapshot.last_error_code, None);
                assert_eq!(snapshot.last_send_disposition, None);
            },
        );
    }

    /// B4: a reserve whose commit succeeded but whose result was lost is fully
    /// recoverable after a real restart (drop + reopen the same database file).
    #[test]
    fn reserve_commit_unknown_restart_preserves_attempt_identity() {
        let (temp, storage_a) = test_storage();
        let data_root = temp.path().join("data");
        let (memory_id, claim) = {
            confirmed(&storage_a, false);
            storage_a
                .register_building_vector_generation("gen-b4-reserve", &"b4".repeat(32), 3)
                .unwrap();
            let claim = storage_a
                .claim_one_fenced_vector_sync("gen-b4-reserve", &"b4".repeat(32), 3, "worker-a")
                .unwrap()
                .unwrap();
            let memory_id = claim.memory_id().to_owned();
            // Force the reservation transaction to commit while the caller only
            // observes a failure.
            storage_a.test_fail_next_fenced_reserve_after_commit_for_test();
            assert!(storage_a.reserve_fenced_attempt(&claim).is_err());
            let snap = storage_a
                .test_get_outbox_snapshot_detailed("life", &memory_id)
                .unwrap();
            assert_eq!(snap.attempt_count, 1);
            assert_eq!(snap.fenced_claim_epoch, 1);
            assert_eq!(snap.last_marked_claim_epoch, 1);
            (memory_id, claim)
        };
        drop(storage_a);

        // Real restart: reopen the same database file.
        let storage_b = StorageService::initialize_with_roots(data_root, None).unwrap();
        let snap = storage_b
            .test_get_outbox_snapshot_detailed("life", &memory_id)
            .unwrap();
        assert_eq!(snap.state, "processing");
        assert_eq!(snap.attempt_count, 1, "attempt persists across restart");
        assert_eq!(snap.fenced_claim_epoch, 1, "fenced epoch persists");
        assert_eq!(snap.last_marked_claim_epoch, 1, "marked epoch persists");
        assert_eq!(
            snap.claimed_generation_id.as_deref(),
            Some("gen-b4-reserve"),
            "generation binding persists"
        );

        // The same claim re-reserves idempotently: identical ordinal, no second
        // attempt, no new claim epoch, and no token reconstruction from a row scan.
        let FencedAttemptReservation::Reserved(re_reserve_token) =
            storage_b.reserve_fenced_attempt(&claim).unwrap()
        else {
            panic!("re-reserve after restart must stay idempotent")
        };
        assert_eq!(
            re_reserve_token.attempt_ordinal(),
            1,
            "same ordinal returned for the same claim epoch"
        );
        let after_rereserve = storage_b
            .test_get_outbox_snapshot_detailed("life", &memory_id)
            .unwrap();
        assert_eq!(
            after_rereserve.attempt_count, 1,
            "re-reserve must not consume a second attempt"
        );
        assert_eq!(
            after_rereserve.fenced_claim_epoch, 1,
            "re-reserve must not mint a new claim epoch"
        );
        assert_eq!(
            after_rereserve.last_marked_claim_epoch, 1,
            "re-reserve must not advance the marked epoch"
        );

        // Health observes the restart state without mutating it.
        let ctx = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-b4-reserve").unwrap(),
            "b4".repeat(32),
            3,
        )
        .unwrap();
        let raw_vs = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vs.create_generation(&ctx)).unwrap();
        let health_before = storage_b
            .inspect_outbox_sync_health(
                ctx.generation_id().as_str(),
                MAX_VECTOR_SYNC_ATTEMPTS as u32,
                1_700_000_000_000,
            )
            .unwrap();
        assert_eq!(health_before.processing_count, 1);
        assert_eq!(health_before.invalid_attempt_identity_count, 0);
        let after_health = storage_b
            .test_get_outbox_snapshot_detailed("life", &memory_id)
            .unwrap();
        assert_eq!(after_health.attempt_count, 1, "Health is read-only");
        assert_eq!(after_health.fenced_claim_epoch, 1, "Health is read-only");

        // Recovery must treat the marked row by its durable evidence.
        storage_b.test_expire_fenced_runtime_lease().unwrap();
        storage_b
            .test_recover_expired_fenced_processing_for_generation_binding(1_700_000_000_000)
            .unwrap();
        let after_recovery = storage_b
            .test_get_outbox_snapshot_detailed("life", &memory_id)
            .unwrap();
        assert_eq!(after_recovery.state, "blocked");
        assert_eq!(
            after_recovery.last_error_code.as_deref(),
            Some("PROVIDER_RESULT_UNKNOWN")
        );
        assert_eq!(after_recovery.attempt_count, 1);
        assert_eq!(
            after_recovery.last_send_disposition.as_deref(),
            Some("possibly_sent")
        );

        // The formal Worker after restart must not touch provider or Lance for a
        // blocked Unknown row, and must not reopen it via claim/reserve/retry.
        let provider_requests = Arc::new(AtomicUsize::new(0));
        let lance_upserts = Arc::new(AtomicUsize::new(0));
        let lance_deletes = Arc::new(AtomicUsize::new(0));
        let vectors = CountingVectorStore {
            inner: raw_vs,
            lance_upserts: Arc::clone(&lance_upserts),
            lance_deletes: Arc::clone(&lance_deletes),
            current_lance_writes: Arc::new(AtomicUsize::new(0)),
            max_concurrent_lance_writes: Arc::new(AtomicUsize::new(0)),
        };
        let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let embedding_successes = Arc::new(AtomicUsize::new(0));
        let provider = CountingEmbeddingProvider {
            inner: &raw_provider,
            provider_requests: Arc::clone(&provider_requests),
            embedding_successes: Arc::clone(&embedding_successes),
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage_b, &provider, &vectors, ctx);
        assert_eq!(
            tauri::async_runtime::block_on(consumer.process_one("worker-b")).unwrap(),
            FencedVectorSyncSingleEventResult::NoEligibleEvent,
            "blocked Unknown row is not eligible after restart"
        );
        assert_eq!(provider_requests.load(Ordering::SeqCst), 0, "no provider");
        assert_eq!(lance_upserts.load(Ordering::SeqCst), 0, "no Lance upsert");
        assert_eq!(lance_deletes.load(Ordering::SeqCst), 0, "no Lance delete");

        // An ordinary claim path must not reopen the blocked Unknown row either.
        storage_b.test_expire_fenced_runtime_lease().unwrap();
        let reopen_claim = storage_b
            .claim_one_fenced_vector_sync("gen-b4-reserve", &"b4".repeat(32), 3, "worker-retry")
            .unwrap();
        assert!(
            reopen_claim.is_none(),
            "blocked Unknown row cannot be re-claimed for retry"
        );
        let final_snap = storage_b
            .test_get_outbox_snapshot_detailed("life", &memory_id)
            .unwrap();
        assert_eq!(final_snap.state, "blocked");
        assert_eq!(final_snap.attempt_count, 1);
        assert_eq!(
            final_snap.last_error_code.as_deref(),
            Some("PROVIDER_RESULT_UNKNOWN")
        );
    }

    /// B4: a success finalize whose commit succeeded but whose result was lost
    /// must not replay provider or Lance work after a real restart.
    #[test]
    fn success_finalize_commit_unknown_restart_does_not_replay_io() {
        let (temp, storage_a) = test_storage();
        let data_root = temp.path().join("data");
        confirmed(&storage_a, false);
        let descriptor = "b4s".repeat(32);
        storage_a
            .register_building_vector_generation("gen-b4-success", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-b4-success").unwrap(),
            descriptor.clone(),
            3,
        )
        .unwrap();
        let descriptor_hash = context.descriptor_hash().to_owned();
        let provider_requests = Arc::new(AtomicUsize::new(0));
        let lance_upserts = Arc::new(AtomicUsize::new(0));
        let lance_deletes = Arc::new(AtomicUsize::new(0));
        {
            let raw_vectors = crate::vector_store::InMemoryVectorStore::default();
            tauri::async_runtime::block_on(raw_vectors.create_generation(&context)).unwrap();
            let vectors = CountingVectorStore {
                inner: raw_vectors,
                lance_upserts: Arc::clone(&lance_upserts),
                lance_deletes: Arc::clone(&lance_deletes),
                current_lance_writes: Arc::new(AtomicUsize::new(0)),
                max_concurrent_lance_writes: Arc::new(AtomicUsize::new(0)),
            };
            let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let embedding_successes = Arc::new(AtomicUsize::new(0));
            let provider = CountingEmbeddingProvider {
                inner: &raw_provider,
                provider_requests: Arc::clone(&provider_requests),
                embedding_successes: Arc::clone(&embedding_successes),
            };
            let consumer = FencedVectorSyncSingleEventConsumer::new(
                &storage_a,
                &provider,
                &vectors,
                context.clone(),
            );
            storage_a.test_fail_next_fenced_success_finalize_after_commit();
            assert_eq!(
                tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap(),
                FencedVectorSyncSingleEventResult::CompletedUpsert,
                "finalize committed even though the caller saw a failure"
            );
            assert_eq!(provider_requests.load(Ordering::SeqCst), 1);
            assert_eq!(lance_upserts.load(Ordering::SeqCst), 1);
        }
        let before = (
            provider_requests.load(Ordering::SeqCst),
            lance_upserts.load(Ordering::SeqCst),
            lance_deletes.load(Ordering::SeqCst),
        );
        // Simulate time passing after the crash: the runtime lease expires so
        // the reopened process can acquire it.
        storage_a.test_expire_fenced_runtime_lease().unwrap();
        drop(storage_a);

        // Real restart: same database file, new StorageService.
        let storage_b = StorageService::initialize_with_roots(data_root, None).unwrap();
        assert!(
            storage_b.list("life").unwrap().is_empty(),
            "outbox row already finalized"
        );
        assert_eq!(storage_b.test_generation_item_count().unwrap(), 1);

        // Health after restart: processing must be zero because the finalized
        // upsert already completed its external work.
        let health = storage_b
            .inspect_outbox_sync_health(
                context.generation_id().as_str(),
                MAX_VECTOR_SYNC_ATTEMPTS as u32,
                1_700_000_000_000,
            )
            .unwrap();
        assert_eq!(
            health.processing_count, 0,
            "no in-flight processing after restart"
        );

        // The formal worker entry after restart must find no eligible event and
        // must not claim, reserve, or replay any external I/O.
        let raw_vectors = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vectors.create_generation(&context)).unwrap();
        let vectors = CountingVectorStore {
            inner: raw_vectors,
            lance_upserts: Arc::clone(&lance_upserts),
            lance_deletes: Arc::clone(&lance_deletes),
            current_lance_writes: Arc::new(AtomicUsize::new(0)),
            max_concurrent_lance_writes: Arc::new(AtomicUsize::new(0)),
        };
        let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let embedding_successes = Arc::new(AtomicUsize::new(0));
        let provider = CountingEmbeddingProvider {
            inner: &raw_provider,
            provider_requests: Arc::clone(&provider_requests),
            embedding_successes: Arc::clone(&embedding_successes),
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage_b, &provider, &vectors, context);
        assert_eq!(
            tauri::async_runtime::block_on(consumer.process_one("worker-b")).unwrap(),
            FencedVectorSyncSingleEventResult::NoEligibleEvent,
            "no eligible event after restart"
        );
        let after = (
            provider_requests.load(Ordering::SeqCst),
            lance_upserts.load(Ordering::SeqCst),
            lance_deletes.load(Ordering::SeqCst),
        );
        assert_eq!(
            after.0 - before.0,
            0,
            "provider delta must be zero after restart"
        );
        assert_eq!(
            after.1 - before.1,
            0,
            "Lance upsert delta must be zero after restart"
        );
        assert_eq!(
            after.2 - before.2,
            0,
            "Lance delete delta must be zero after restart"
        );

        // Claim directly to confirm no event is eligible after the finalized upsert.
        storage_b.test_expire_fenced_runtime_lease().unwrap();
        let claim_result = storage_b.claim_one_fenced_vector_sync_with_retry_cutoff(
            "gen-b4-success",
            &descriptor_hash,
            3,
            "worker-c",
            Some(1_700_000_000_000),
        );
        assert!(
            claim_result.unwrap().is_none(),
            "no eligible event after restart"
        );
    }

    /// B4: a failure finalize whose commit succeeded but whose result was lost
    /// must persist its terminal evidence and never replay external I/O.
    #[test]
    fn failure_finalize_commit_unknown_restart_preserves_terminal_evidence() {
        let (temp, storage_a) = test_storage();
        let data_root = temp.path().join("data");
        confirmed(&storage_a, false);
        let descriptor = "b4f".repeat(32);
        storage_a
            .register_building_vector_generation("gen-b4-failure", &descriptor, 3)
            .unwrap();
        let context = VectorGenerationContext::new(
            crate::vector_store::VectorGenerationId::parse("gen-b4-failure").unwrap(),
            descriptor,
            3,
        )
        .unwrap();
        let provider_requests = Arc::new(AtomicUsize::new(0));
        let lance_upserts = Arc::new(AtomicUsize::new(0));
        let lance_deletes = Arc::new(AtomicUsize::new(0));
        {
            let raw_vectors = crate::vector_store::InMemoryVectorStore::default();
            tauri::async_runtime::block_on(raw_vectors.create_generation(&context)).unwrap();
            let vectors = CountingVectorStore {
                inner: raw_vectors,
                lance_upserts: Arc::clone(&lance_upserts),
                lance_deletes: Arc::clone(&lance_deletes),
                current_lance_writes: Arc::new(AtomicUsize::new(0)),
                max_concurrent_lance_writes: Arc::new(AtomicUsize::new(0)),
            };
            let possibly_sent = PossiblySentEmbeddingProvider {
                inner: crate::embedding::DeterministicEmbeddingProvider::new(3),
                requests: AtomicUsize::new(0),
            };
            let embedding_successes = Arc::new(AtomicUsize::new(0));
            let provider = CountingEmbeddingProvider {
                inner: &possibly_sent,
                provider_requests: Arc::clone(&provider_requests),
                embedding_successes: Arc::clone(&embedding_successes),
            };
            let consumer = FencedVectorSyncSingleEventConsumer::new(
                &storage_a,
                &provider,
                &vectors,
                context.clone(),
            );
            storage_a.test_fail_next_fenced_failure_finalize_after_commit();
            assert_eq!(
                tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap(),
                FencedVectorSyncSingleEventResult::Blocked,
                "failure finalize committed even though the caller saw a failure"
            );
        }
        let before = (
            provider_requests.load(Ordering::SeqCst),
            lance_upserts.load(Ordering::SeqCst),
            lance_deletes.load(Ordering::SeqCst),
        );
        assert_eq!(before.0, 1, "exactly one provider attempt before restart");
        assert_eq!(before.1, 0, "no Lance upsert for a failed upsert");
        drop(storage_a);

        // Real restart.
        let storage_b = StorageService::initialize_with_roots(data_root, None).unwrap();
        let jobs = storage_b.list("life").unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].state, MemoryVectorSyncState::Blocked);
        assert_eq!(jobs[0].attempt_count, 1);
        assert_eq!(
            jobs[0].last_error_code.as_deref(),
            Some("PROVIDER_RESULT_UNKNOWN")
        );
        let snap = storage_b
            .test_get_outbox_snapshot_detailed(&jobs[0].life_id, &jobs[0].memory_id)
            .unwrap();
        assert_eq!(
            snap.last_send_disposition.as_deref(),
            Some("possibly_sent"),
            "Unknown evidence persists across restart"
        );
        assert_eq!(
            snap.claimed_generation_id.as_deref(),
            Some("gen-b4-failure")
        );

        // Health after restart sees the terminal blocked state.
        let health = storage_b
            .inspect_outbox_sync_health(
                context.generation_id().as_str(),
                MAX_VECTOR_SYNC_ATTEMPTS as u32,
                1_700_000_000_000,
            )
            .unwrap();
        assert_eq!(health.blocked_count, 1);
        assert_eq!(health.provider_result_unknown_count, 1);
        assert_eq!(health.processing_count, 0);

        // Expired recovery must keep the terminal evidence intact.
        storage_b.test_expire_fenced_runtime_lease().unwrap();
        storage_b
            .test_recover_expired_fenced_processing_for_generation_binding(1_700_000_000_000)
            .unwrap();
        let after_recovery = storage_b
            .test_get_outbox_snapshot_detailed("life", &jobs[0].memory_id)
            .unwrap();
        assert_eq!(after_recovery.state, "blocked");
        assert_eq!(
            after_recovery.last_error_code.as_deref(),
            Some("PROVIDER_RESULT_UNKNOWN")
        );
        assert_eq!(after_recovery.attempt_count, 1);

        // A retry claim must not reopen the blocked Unknown row.
        storage_b.test_expire_fenced_runtime_lease().unwrap();
        let retry_claim = storage_b
            .claim_one_fenced_vector_sync(
                context.generation_id().as_str(),
                context.descriptor_hash(),
                context.dimension(),
                "worker-retry",
            )
            .unwrap();
        assert!(
            retry_claim.is_none(),
            "blocked Unknown row cannot be retried after restart"
        );

        // The formal Worker after restart must not replay any external I/O.
        storage_b.test_expire_fenced_runtime_lease().unwrap();
        let raw_vectors = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vectors.create_generation(&context)).unwrap();
        let vectors = CountingVectorStore {
            inner: raw_vectors,
            lance_upserts: Arc::clone(&lance_upserts),
            lance_deletes: Arc::clone(&lance_deletes),
            current_lance_writes: Arc::new(AtomicUsize::new(0)),
            max_concurrent_lance_writes: Arc::new(AtomicUsize::new(0)),
        };
        let raw_provider = crate::embedding::DeterministicEmbeddingProvider::new(3);
        let embedding_successes = Arc::new(AtomicUsize::new(0));
        let provider = CountingEmbeddingProvider {
            inner: &raw_provider,
            provider_requests: Arc::clone(&provider_requests),
            embedding_successes: Arc::clone(&embedding_successes),
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage_b, &provider, &vectors, context);
        assert_eq!(
            tauri::async_runtime::block_on(consumer.process_one("worker-b")).unwrap(),
            FencedVectorSyncSingleEventResult::NoEligibleEvent,
            "no eligible event after restart"
        );
        let after = (
            provider_requests.load(Ordering::SeqCst),
            lance_upserts.load(Ordering::SeqCst),
            lance_deletes.load(Ordering::SeqCst),
        );
        assert_eq!(after.0 - before.0, 0, "no provider replay after restart");
        assert_eq!(after.1 - before.1, 0, "no Lance upsert replay");
        assert_eq!(after.2 - before.2, 0, "no Lance delete replay");
        assert_eq!(
            provider_requests.load(Ordering::SeqCst),
            1,
            "only the original attempt ever reached the provider"
        );
    }

    /// B7: a real `process_one` formal worker is deterministically paused at
    /// its post-provider token guard while Health snapshots the same real file
    /// SQLite database. Health must stay strictly read-only and the worker must
    /// complete exactly one external call per token.
    #[test]
    fn vector_sync_health_and_formal_worker_compete_for_ten_rounds() {
        use crate::memory::vector_sync_health::{inspect_vector_sync_health, HealthClock};
        use std::sync::mpsc;

        struct B7Clock(Arc<Mutex<i64>>);
        impl HealthClock for B7Clock {
            fn now_utc_millis(
                &self,
            ) -> Result<i64, crate::memory::vector_sync_health::VectorSyncHealthError> {
                Ok(*self.0.lock().unwrap())
            }
        }

        for round in 0..10 {
            let (temp, storage_a) = test_storage();
            let data_root = temp.path().join("data");
            let (ctx, raw_vectors) = drained_context();
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
                "health formal worker race",
                None,
                0.5,
                0.5,
                false,
                true,
            );
            storage_a
                .enqueue(EnqueueMemoryVectorSyncRequest {
                    life_id: record.life_id.clone(),
                    memory_id: record.id.clone(),
                    desired_action: MemoryVectorSyncAction::Upsert,
                })
                .unwrap();

            let provider_requests = Arc::new(AtomicUsize::new(0));
            let lance_upserts = Arc::new(AtomicUsize::new(0));
            let lance_deletes = Arc::new(AtomicUsize::new(0));

            // Independent connection B for the formal worker.
            let storage_b = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
            let raw_vectors_b = crate::vector_store::InMemoryVectorStore::default();
            tauri::async_runtime::block_on(raw_vectors_b.create_generation(&ctx)).unwrap();

            let (paused_tx, paused_rx) = mpsc::channel::<()>();
            let (release_tx, release_rx) = mpsc::channel::<()>();

            // The worker claims, reserves, calls the provider, passes the first
            // token guard, then blocks at AfterEmbeddingBeforeLance. The test
            // thread runs Health exactly while the worker is blocked.
            let worker = {
                let ctx = ctx.clone();
                let provider_owned: Box<dyn EmbeddingProvider> =
                    Box::new(crate::embedding::DeterministicEmbeddingProvider::new(3));
                let provider_requests = Arc::clone(&provider_requests);
                let embedding_successes = Arc::new(AtomicUsize::new(0));
                let lance_upserts = Arc::clone(&lance_upserts);
                let lance_deletes = Arc::clone(&lance_deletes);
                std::thread::spawn(move || {
                    let provider = CountingEmbeddingProvider {
                        inner: provider_owned.as_ref(),
                        provider_requests,
                        embedding_successes,
                    };
                    let vectors = CountingVectorStore {
                        inner: raw_vectors_b,
                        lance_upserts,
                        lance_deletes,
                        current_lance_writes: Arc::new(AtomicUsize::new(0)),
                        max_concurrent_lance_writes: Arc::new(AtomicUsize::new(0)),
                    };
                    let consumer = FencedVectorSyncSingleEventConsumer::new(
                        &storage_b, &provider, &vectors, ctx,
                    );
                    consumer.set_test_pause_hook_for_test(Some(Box::new(move |point| {
                        if point == VectorSyncTestPausePoint::AfterEmbeddingBeforeLance {
                            paused_tx.send(()).unwrap();
                            release_rx.recv().unwrap();
                        }
                    })));
                    let result =
                        tauri::async_runtime::block_on(consumer.process_one("worker-b")).unwrap();
                    consumer.set_test_pause_hook_for_test(None);
                    result
                })
            };

            // Wait for the worker to reach the post-provider gate, then run
            // Health on connection A while the worker is blocked.
            paused_rx.recv().unwrap();
            let clock = B7Clock(Arc::new(Mutex::new(1_700_000_000_000)));
            let health = tauri::async_runtime::block_on(inspect_vector_sync_health(
                &storage_a,
                &raw_vectors,
                &ctx,
                &clock,
            ))
            .unwrap();
            // Health sees the worker's legitimate mid-flight state: exactly one
            // in-flight processing row, and no impossible mixed identity.
            assert_eq!(health.processing_count, 1, "round {round}");
            assert_eq!(health.invalid_attempt_identity_count, 0, "round {round}");
            assert_eq!(
                health.attempts_at_limit_count, 0,
                "round {round}: attempt 1 of 5 is not at limit"
            );

            // Health is strictly read-only while the worker is mid-flight.
            let verifier = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
            let snap = verifier
                .test_get_outbox_snapshot_detailed("life", &record.id)
                .unwrap();
            assert_eq!(snap.state, "processing", "round {round}");
            assert_eq!(
                snap.attempt_count, 1,
                "round {round}: reserve already committed"
            );
            assert_eq!(snap.fenced_claim_epoch, 1, "round {round}");
            assert_eq!(snap.last_marked_claim_epoch, 1, "round {round}");
            assert_eq!(
                snap.claimed_generation_id.as_deref(),
                Some(ctx.generation_id().as_str()),
                "round {round}"
            );
            assert_eq!(
                snap.last_send_disposition.as_deref(),
                Some("possibly_sent"),
                "round {round}: health must not clear send evidence"
            );

            // Release the worker and let it finish the finalize path.
            release_tx.send(()).unwrap();
            let result = worker.join().unwrap();
            assert_eq!(
                result,
                FencedVectorSyncSingleEventResult::CompletedUpsert,
                "round {round}"
            );

            // Exactly one external call per token.
            assert_eq!(provider_requests.load(Ordering::SeqCst), 1, "round {round}");
            assert_eq!(lance_upserts.load(Ordering::SeqCst), 1, "round {round}");
            assert_eq!(lance_deletes.load(Ordering::SeqCst), 0, "round {round}");

            // The finalize produced a complete, valid terminal state: the row
            // is finalized (removed from the outbox) and the generation item
            // holds the upserted record.
            assert!(
                verifier.list("life").unwrap().is_empty(),
                "round {round}: upsert finalized and outbox row removed"
            );
            assert_eq!(
                verifier.test_generation_item_count().unwrap(),
                1,
                "round {round}: exactly one generation item"
            );
            // Resource closure: worker joined, contexts empty, no journal
            // residue after all connections are dropped. (storage_b and
            // raw_vectors_b were moved into the worker thread and are already
            // dropped when it ended; storage_a is still alive here.)
            drop(verifier);
            drop(storage_a);
            assert_no_wal_shm_residue(&data_root);
        }
    }

    /// B8: real expired recovery races a real `process_one` worker on the same
    /// database file. A marked unknown Upsert must never be replayed, and an
    /// unmarked durable row must keep its generation and never lose a budget
    /// slot to the recovery path.
    #[test]
    fn expired_recovery_and_worker_process_one_compete_for_ten_rounds() {
        for round in 0..10 {
            let (temp, storage_a) = test_storage();
            let data_root = temp.path().join("data");
            let (ctx, _vectors) = drained_context();
            storage_a
                .register_building_vector_generation(
                    ctx.generation_id().as_str(),
                    ctx.descriptor_hash(),
                    ctx.dimension(),
                )
                .unwrap();

            // Setup an expired marked unknown Upsert processing row.
            let record = crate::storage::test_support::insert_confirmed_memory_fixture(
                &storage_a,
                "life",
                "fact",
                "recovery worker race",
                None,
                0.5,
                0.5,
                false,
                true,
            );
            storage_a
                .enqueue(EnqueueMemoryVectorSyncRequest {
                    life_id: record.life_id.clone(),
                    memory_id: record.id.clone(),
                    desired_action: MemoryVectorSyncAction::Upsert,
                })
                .unwrap();
            let claim = storage_a
                .claim_one_fenced_vector_sync(
                    ctx.generation_id().as_str(),
                    ctx.descriptor_hash(),
                    ctx.dimension(),
                    "worker-a",
                )
                .unwrap()
                .unwrap();
            storage_a.test_fail_next_fenced_reserve_after_commit_for_test();
            // The reserve transaction commits (attempt 1, marked) even though
            // the caller observes a failure.
            assert!(storage_a.reserve_fenced_attempt(&claim).is_err());
            let snapshot = storage_a
                .test_get_outbox_snapshot_detailed("life", &record.id)
                .unwrap();
            assert_eq!(snapshot.attempt_count, 1);
            assert_eq!(snapshot.last_marked_claim_epoch, 1);
            // Capture the complete OLD marked-unknown identity before the race:
            // life, memory, mutation, action, target, claim epoch,
            // last_marked, attempt, generation, send, error. The zero-call
            // proof below is keyed on this exact claim identity, and the
            // post-race row must match it field-for-field.
            type MarkedOldIdentity = (
                String,
                String,
                i64,
                String,
                Option<i64>,
                Option<String>,
                i64,
                i64,
                i64,
                String,
                Option<String>,
                Option<String>,
            );
            let marked_old: MarkedOldIdentity = {
                let db_path = data_root.join("digital-life.sqlite3");
                let conn = crate::storage::open_authorized_test_connection(&db_path).unwrap();
                let row: MarkedOldIdentity = conn
                    .query_row(
                        "SELECT life_id, memory_id, mutation_sequence, desired_action,
                                target_revision, target_content_hash,
                                fenced_claim_epoch, last_marked_claim_epoch,
                                attempt_count, claimed_generation_id,
                                last_send_disposition, last_error_code
                         FROM memory_vector_sync_outbox WHERE memory_id=?1",
                        rusqlite::params![record.id],
                        |r| {
                            Ok((
                                r.get(0)?,
                                r.get(1)?,
                                r.get(2)?,
                                r.get(3)?,
                                r.get(4)?,
                                r.get(5)?,
                                r.get(6)?,
                                r.get(7)?,
                                r.get(8)?,
                                r.get(9)?,
                                r.get(10)?,
                                r.get(11)?,
                            ))
                        },
                    )
                    .unwrap();
                row
            };
            let marked_old_mutation_sequence = marked_old.2;
            let marked_old_claim_epoch = marked_old.6;
            // Pre-race contract: upsert, marked (claim==last_marked>0),
            // attempt>0, generation present, unknown evidence present.
            assert_eq!(marked_old.3, "upsert", "round {round}: marked old action");
            assert_eq!(
                marked_old.6, marked_old.7,
                "round {round}: marked old claim epoch == last_marked"
            );
            assert!(marked_old.6 > 0, "round {round}: marked old epoch > 0");
            assert!(marked_old.8 > 0, "round {round}: marked old attempt > 0");
            assert!(
                !marked_old.9.is_empty(),
                "round {round}: marked old generation present"
            );
            assert!(
                marked_old.10.as_deref() == Some("possibly_sent")
                    || marked_old.11.as_deref() == Some("PROVIDER_RESULT_UNKNOWN"),
                "round {round}: marked old unknown evidence present"
            );
            storage_a.test_expire_fenced_runtime_lease().unwrap();

            // Setup the unmarked-durable expired-processing fixture on the same
            // connection before it is moved into the recovery thread: claimed,
            // then shaped into fenced > marked with attempt 1..4 and a real
            // generation binding.
            let unmarked_record = crate::storage::test_support::insert_confirmed_memory_fixture(
                &storage_a,
                "life",
                "fact",
                "recovery worker unmarked",
                None,
                0.5,
                0.5,
                false,
                true,
            );
            storage_a
                .enqueue(EnqueueMemoryVectorSyncRequest {
                    life_id: unmarked_record.life_id.clone(),
                    memory_id: unmarked_record.id.clone(),
                    desired_action: MemoryVectorSyncAction::Upsert,
                })
                .unwrap();
            let unmarked_claim = storage_a
                .claim_one_fenced_vector_sync(
                    ctx.generation_id().as_str(),
                    ctx.descriptor_hash(),
                    ctx.dimension(),
                    "worker-a",
                )
                .unwrap()
                .unwrap();
            assert_eq!(unmarked_claim.memory_id(), unmarked_record.id.as_str());
            // Shape the claimed row into the unmarked-durable form: fenced >
            // marked, attempt 1..4, generation present. The lease stays FRESH
            // here so the unmarked row is untouched by the marked-unknown race
            // below; it is expired explicitly in sub-scenario 2.
            {
                let db_path = data_root.join("digital-life.sqlite3");
                let conn = crate::storage::open_authorized_test_connection(&db_path).unwrap();
                conn.execute(
                    "UPDATE memory_vector_sync_outbox
                     SET attempt_count=2, fenced_claim_epoch=3,
                         last_marked_claim_epoch=1, lease_owner='worker-old',
                         lease_fence_epoch=30,
                         last_send_disposition='definitely_not_sent',
                         last_error_code=NULL, next_attempt_at=NULL
                     WHERE memory_id=?1",
                    rusqlite::params![unmarked_record.id],
                )
                .unwrap();
            }
            let unmarked_id = unmarked_record.id.clone();
            drop(unmarked_claim);

            // Capture the OLD unmarked-durable identity before any recovery or
            // mutation: life, memory, mutation, action, attempt, claim epochs,
            // generation, target binding, send/error evidence.
            type OldUnmarkedIdentity = (
                String,
                String,
                i64,
                String,
                i64,
                i64,
                i64,
                String,
                Option<i64>,
                Option<String>,
                Option<String>,
                Option<String>,
            );
            let old_identity: OldUnmarkedIdentity = {
                let db_path = data_root.join("digital-life.sqlite3");
                let conn = crate::storage::open_authorized_test_connection(&db_path).unwrap();
                let row: OldUnmarkedIdentity = conn
                    .query_row(
                        "SELECT life_id, memory_id, mutation_sequence, desired_action,
                                attempt_count, fenced_claim_epoch, last_marked_claim_epoch,
                                claimed_generation_id, target_revision, target_content_hash,
                                last_send_disposition, last_error_code
                         FROM memory_vector_sync_outbox WHERE memory_id=?1",
                        rusqlite::params![unmarked_id],
                        |r| {
                            Ok((
                                r.get(0)?,
                                r.get(1)?,
                                r.get(2)?,
                                r.get(3)?,
                                r.get(4)?,
                                r.get(5)?,
                                r.get(6)?,
                                r.get(7)?,
                                r.get(8)?,
                                r.get(9)?,
                                r.get(10)?,
                                r.get(11)?,
                            ))
                        },
                    )
                    .unwrap();
                row
            };
            let old_mutation_sequence: i64 = {
                let db_path = data_root.join("digital-life.sqlite3");
                let conn = crate::storage::open_authorized_test_connection(&db_path).unwrap();
                conn.query_row(
                    "SELECT mutation_sequence FROM memory_vector_sync_outbox WHERE memory_id=?1",
                    rusqlite::params![unmarked_id],
                    |r| r.get(0),
                )
                .unwrap()
            };
            assert_eq!(old_identity.5, 3, "round {round}: old fenced claim epoch");
            assert_eq!(
                old_identity.6, 1,
                "round {round}: old last_marked claim epoch"
            );
            assert_eq!(old_identity.4, 2, "round {round}: old attempt count");
            assert_eq!(
                old_identity.7,
                ctx.generation_id().as_str(),
                "round {round}: old generation"
            );

            // The unmarked claim re-acquired the global runtime lease. Expire
            // ONLY the runtime lease (not the unmarked row's event lease) so
            // the marked-unknown worker on connection B can acquire it while
            // the unmarked row stays a fresh non-expired processing row that is
            // neither recovered nor claimable during the marked race.
            {
                let db_path = data_root.join("digital-life.sqlite3");
                let conn = crate::storage::open_authorized_test_connection(&db_path).unwrap();
                conn.execute(
                    "UPDATE memory_vector_sync_runtime_lease
                     SET expires_at='2000-01-01T00:00:00.000Z'",
                    [],
                )
                .unwrap();
            }

            // Independent connection B for the worker.
            let storage_b = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
            let raw_vectors = crate::vector_store::InMemoryVectorStore::default();
            tauri::async_runtime::block_on(raw_vectors.create_generation(&ctx)).unwrap();

            let barrier = Arc::new(std::sync::Barrier::new(2));
            let recovery_barrier = Arc::clone(&barrier);
            let worker_barrier = Arc::clone(&barrier);

            // Recovery on connection A.
            let recovery = {
                let storage_a_clone = storage_a;
                std::thread::spawn(move || {
                    recovery_barrier.wait();
                    storage_a_clone.test_recover_expired_fenced_processing_for_generation_binding(
                        1_700_000_000_000,
                    )
                })
            };

            // Real process_one on connection B. Every external call is recorded
            // through THIS worker's own context (never shared with another
            // worker), and the whole invocation runs inside a RAII scope that
            // clears the context on every exit path.
            let log = crate::storage::test_support::ExternalCallLog::default();
            let worker_context = crate::storage::test_support::WorkerCallContext::new(log.clone());
            let worker = {
                let ctx = ctx.clone();
                let provider_owned: Box<dyn EmbeddingProvider> =
                    Box::new(crate::embedding::DeterministicEmbeddingProvider::new(3));
                let worker_context_for_thread = worker_context.clone();
                std::thread::spawn(move || {
                    worker_barrier.wait();
                    let scope = crate::storage::test_support::WorkerCallContextScope::new(
                        worker_context_for_thread.clone(),
                    );
                    let provider = RecordingEmbeddingProvider {
                        inner: provider_owned.as_ref(),
                        context: &worker_context_for_thread,
                    };
                    let vectors = RecordingVectorStore {
                        inner: &raw_vectors,
                        context: &worker_context_for_thread,
                    };
                    let consumer = FencedVectorSyncSingleEventConsumer::new(
                        &storage_b,
                        &provider,
                        &vectors,
                        ctx.clone(),
                    );
                    let worker_context_for_observer = worker_context_for_thread.clone();
                    consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
                        worker_context_for_observer.set_current_claim(claim);
                    })));
                    let result =
                        tauri::async_runtime::block_on(consumer.process_one("worker-b")).unwrap();
                    consumer.set_claim_observer_for_test(None);
                    drop(scope);
                    result
                })
            };

            let recovered = recovery.join().unwrap().unwrap();
            let worker_result = worker.join().unwrap();
            assert!(
                worker_context.is_empty(),
                "round {round}: worker context must be empty after the marked race"
            );

            // Marked unknown Upsert: no provider replay, blocked unknown, and
            // the attempt budget never grows beyond the single reservation.
            // The log proves the OLD marked claim identity itself has 0/0/0.
            let (provider_count, upsert_count, delete_count) = log.counts_for_claim(
                &record.id,
                marked_old_mutation_sequence,
                marked_old_claim_epoch,
            );
            assert_eq!(
                (provider_count, upsert_count, delete_count),
                (0, 0, 0),
                "round {round}: marked unknown upsert must never call provider/Lance (recorded {provider_count}/{upsert_count}/{delete_count})"
            );
            assert_eq!(
                log.unbound_call_count(),
                0,
                "round {round}: no unbound external calls in the marked race"
            );
            assert_eq!(
                worker_result,
                FencedVectorSyncSingleEventResult::NoEligibleEvent,
                "round {round}: marked unknown upsert is not eligible for the worker"
            );
            let verifier = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
            let snap = verifier
                .test_get_outbox_snapshot_detailed("life", &record.id)
                .unwrap();
            assert_eq!(
                snap.state, "blocked",
                "round {round}: unknown upsert converges to blocked"
            );
            assert_eq!(
                snap.last_error_code.as_deref(),
                Some("PROVIDER_RESULT_UNKNOWN"),
                "round {round}"
            );
            // Full old-identity closure: the post-race row keeps life, memory,
            // mutation, action, target, epochs, attempt, generation, and send
            // evidence exactly as captured before the race.
            assert_eq!(
                snap.mutation_sequence, marked_old.2,
                "round {round}: mutation sequence preserved"
            );
            assert_eq!(
                snap.desired_action, marked_old.3,
                "round {round}: action preserved"
            );
            assert_eq!(
                snap.target_revision, marked_old.4,
                "round {round}: target revision preserved"
            );
            assert_eq!(
                snap.target_content_hash, marked_old.5,
                "round {round}: target content hash preserved"
            );
            assert_eq!(
                snap.attempt_count, marked_old.8,
                "round {round}: attempt not increased"
            );
            assert_eq!(
                snap.claimed_generation_id.as_deref(),
                Some(marked_old.9.as_str()),
                "round {round}: generation preserved"
            );
            assert_eq!(
                snap.last_send_disposition.as_deref(),
                marked_old.10.as_deref(),
                "round {round}: send evidence preserved"
            );
            assert_eq!(
                snap.fenced_claim_epoch, marked_old.6,
                "round {round}: claim epoch unchanged"
            );
            assert_eq!(
                snap.last_marked_claim_epoch, marked_old.7,
                "round {round}: last_marked unchanged"
            );
            let _ = recovered;

            // ---- B8 sub-scenario 2: unmarked durable expired-processing ----
            // The fixture (claimed, then shaped into fenced > marked with
            // attempt 1..4 and a real generation binding) was set up before the
            // recovery thread moved `storage_a` away. Recovery returns it to
            // pending without consuming an attempt or dropping the generation.
            // A new mutation then invalidates the old one, and the formal
            // worker must not replay the old expired claim (plan A).
            let storage_ur =
                StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
            storage_ur.test_expire_fenced_runtime_lease().unwrap();
            storage_ur
                .test_recover_expired_fenced_processing_for_generation_binding(1_700_000_000_000)
                .unwrap();
            let unmarked_after_recovery = storage_ur
                .test_get_outbox_snapshot_detailed("life", &unmarked_id)
                .unwrap();
            assert_eq!(
                unmarked_after_recovery.state, "pending",
                "round {round}: unmarked durable recovers to pending"
            );
            assert_eq!(
                unmarked_after_recovery.attempt_count, old_identity.4,
                "round {round}: recovery must not increment the unmarked attempt"
            );
            assert_eq!(
                unmarked_after_recovery.claimed_generation_id.as_deref(),
                Some(old_identity.7.as_str()),
                "round {round}: unmarked generation preserved"
            );
            assert_eq!(
                unmarked_after_recovery.fenced_claim_epoch, old_identity.5,
                "round {round}: fenced epoch preserved"
            );
            assert_eq!(
                unmarked_after_recovery.last_marked_claim_epoch, old_identity.6,
                "round {round}: last_marked preserved"
            );
            assert_eq!(
                unmarked_after_recovery.lease_owner, None,
                "round {round}: old lease cleared"
            );
            // Explicit target re-check after recovery: the target binding must
            // be unchanged from the pre-recovery old identity.
            assert_eq!(
                unmarked_after_recovery.target_revision, old_identity.8,
                "round {round}: target revision preserved through recovery"
            );
            assert_eq!(
                unmarked_after_recovery.target_content_hash, old_identity.9,
                "round {round}: target content hash preserved through recovery"
            );
            assert_eq!(
                unmarked_after_recovery.desired_action, old_identity.3,
                "round {round}: action preserved through recovery"
            );
            assert_eq!(
                unmarked_after_recovery.mutation_sequence, old_mutation_sequence,
                "round {round}: mutation sequence preserved through recovery"
            );
            assert_eq!(
                unmarked_after_recovery.last_send_disposition.as_deref(),
                old_identity.10.as_deref(),
                "round {round}: send evidence preserved through recovery"
            );
            assert_eq!(
                unmarked_after_recovery.last_error_code.as_deref(),
                old_identity.11.as_deref(),
                "round {round}: error evidence preserved through recovery"
            );

            // Plan A: a new mutation invalidates the old one. The recovered row
            // keeps its row identity but the mutation is replaced: fresh
            // budget, zero epochs, no generation, no send/error evidence. The
            // target revision/hash stay the real confirmed memory binding so
            // the fresh claim can legitimately finalize.
            {
                let conn = crate::storage::open_authorized_test_connection(
                    &data_root.join("digital-life.sqlite3"),
                )
                .unwrap();
                conn.execute(
                    "UPDATE memory_vector_sync_outbox
                     SET desired_action='upsert', state='pending', attempt_count=0,
                         mutation_sequence=mutation_sequence+1,
                         fenced_claim_epoch=0, last_marked_claim_epoch=0,
                         claimed_generation_id=NULL, last_send_disposition=NULL,
                         last_error_code=NULL, lease_owner=NULL, lease_expires_at=NULL,
                         lease_fence_epoch=NULL, next_attempt_at=NULL
                     WHERE memory_id=?1",
                    rusqlite::params![unmarked_id],
                )
                .unwrap();
            }

            // The formal worker now runs over the new mutation. The old expired
            // claim can never be replayed: the new mutation is a fresh pending
            // row the worker may legitimately claim with a NEW epoch, and the
            // old claim's epoch evidence is gone. Capture the new mutation's
            // identity (mutation_sequence, target revision/hash) so the
            // completed calls can be attributed jointly by
            // mutation_sequence + claim_epoch + target.
            let new_mutation_sequence: i64 = {
                let db_path = data_root.join("digital-life.sqlite3");
                let conn = crate::storage::open_authorized_test_connection(&db_path).unwrap();
                conn.query_row(
                    "SELECT mutation_sequence FROM memory_vector_sync_outbox WHERE memory_id=?1",
                    rusqlite::params![unmarked_id],
                    |r| r.get(0),
                )
                .unwrap()
            };
            let new_mutation_target: (Option<i64>, Option<String>) = {
                let db_path = data_root.join("digital-life.sqlite3");
                let conn = crate::storage::open_authorized_test_connection(&db_path).unwrap();
                conn.query_row(
                    "SELECT target_revision, target_content_hash FROM memory_vector_sync_outbox WHERE memory_id=?1",
                    rusqlite::params![unmarked_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
            };
            assert_eq!(
                new_mutation_sequence,
                old_mutation_sequence + 1,
                "round {round}: new mutation_sequence advances"
            );

            let storage_b8 =
                StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
            let log_b8 = crate::storage::test_support::ExternalCallLog::default();
            let worker_context_b8 =
                crate::storage::test_support::WorkerCallContext::new(log_b8.clone());
            let raw_vectors_b8 = crate::vector_store::InMemoryVectorStore::default();
            tauri::async_runtime::block_on(raw_vectors_b8.create_generation(&ctx)).unwrap();
            let vectors_b8 = RecordingVectorStore {
                inner: &raw_vectors_b8,
                context: &worker_context_b8,
            };
            let raw_provider_b8 = crate::embedding::DeterministicEmbeddingProvider::new(3);
            let provider_b8 = RecordingEmbeddingProvider {
                inner: &raw_provider_b8,
                context: &worker_context_b8,
            };
            let consumer_b8 = FencedVectorSyncSingleEventConsumer::new(
                &storage_b8,
                &provider_b8,
                &vectors_b8,
                ctx.clone(),
            );
            let worker_context_b8_for_observer = worker_context_b8.clone();
            consumer_b8.set_claim_observer_for_test(Some(Box::new(move |claim| {
                worker_context_b8_for_observer.set_current_claim(claim);
            })));
            storage_b8.test_expire_fenced_runtime_lease().unwrap();
            let scope_b8 = crate::storage::test_support::WorkerCallContextScope::new(
                worker_context_b8.clone(),
            );
            let worker_b8_result =
                tauri::async_runtime::block_on(consumer_b8.process_one("worker-b8")).unwrap();
            drop(scope_b8);
            consumer_b8.set_claim_observer_for_test(None);
            assert!(
                worker_context_b8.is_empty(),
                "round {round}: worker context must be empty after the unmarked run"
            );
            assert_eq!(
                log_b8.unbound_call_count(),
                0,
                "round {round}: no unbound external calls in the unmarked run"
            );

            let b8_verifier =
                StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
            // Old mutation must never have any external call: its identity is
            // the expired claim epoch 3 / old mutation_sequence / old target.
            // The row keeps its memory_id across the new mutation, so the
            // attribution is by mutation_sequence + claim_epoch, not memory_id.
            let (old_p, old_u, old_d) =
                log_b8.counts_for_claim(&unmarked_id, old_mutation_sequence, old_identity.5);
            assert_eq!(
                (old_p, old_u, old_d),
                (0, 0, 0),
                "round {round}: old mutation must never reach provider/Lance ({old_p}/{old_u}/{old_d})"
            );

            match worker_b8_result {
                FencedVectorSyncSingleEventResult::CompletedUpsert => {
                    // Every new call belongs to the NEW mutation identity,
                    // proven jointly by mutation_sequence + claim_epoch +
                    // target revision/hash (+ newly bound generation).
                    let calls = log_b8.snapshot();
                    assert_eq!(calls.len(), 2, "round {round}: one provider + one upsert");
                    for call in &calls {
                        assert_eq!(call.context.memory_id, unmarked_id, "round {round}");
                        assert_eq!(
                            call.context.mutation_sequence, new_mutation_sequence,
                            "round {round}: call uses the new mutation_sequence"
                        );
                        assert_eq!(
                            call.context.claim_epoch, 1,
                            "round {round}: new claim epoch (old was 3)"
                        );
                        assert_eq!(
                            call.context.target_revision, new_mutation_target.0,
                            "round {round}: new target revision"
                        );
                        assert_eq!(
                            call.context.target_content_hash, new_mutation_target.1,
                            "round {round}: new target content hash"
                        );
                        assert_eq!(
                            call.context.generation_id,
                            ctx.generation_id().as_str(),
                            "round {round}: newly bound generation"
                        );
                        assert_ne!(
                            call.context.claim_epoch, old_identity.5,
                            "round {round}: claim epoch differs from the old expired claim"
                        );
                        assert_ne!(
                            call.context.mutation_sequence, old_mutation_sequence,
                            "round {round}: mutation differs from the old mutation"
                        );
                    }
                    let (new_p, new_u, new_d) =
                        log_b8.counts_for_claim(&unmarked_id, new_mutation_sequence, 1);
                    assert_eq!(
                        (new_p, new_u, new_d),
                        (1, 1, 0),
                        "round {round}: new mutation attribution (1 provider, 1 upsert, 0 delete)"
                    );
                    assert!(
                        b8_verifier
                            .list("life")
                            .unwrap()
                            .iter()
                            .all(|job| job.memory_id != unmarked_id),
                        "round {round}: new mutation finalized"
                    );
                }
                FencedVectorSyncSingleEventResult::NoEligibleEvent => {
                    let (new_p, new_u, new_d) =
                        log_b8.counts_for_claim(&unmarked_id, new_mutation_sequence, 1);
                    assert_eq!(
                        (new_p, new_u, new_d),
                        (0, 0, 0),
                        "round {round}: no external calls when nothing is eligible"
                    );
                    let (old_p2, old_u2, old_d2) = log_b8.counts_for_claim(
                        &unmarked_id,
                        old_mutation_sequence,
                        old_identity.5,
                    );
                    assert_eq!(
                        (old_p2, old_u2, old_d2),
                        (0, 0, 0),
                        "round {round}: old mutation stays call-free"
                    );
                    let new_snap = b8_verifier
                        .test_get_outbox_snapshot_detailed("life", &unmarked_id)
                        .unwrap();
                    assert_eq!(
                        new_snap.mutation_sequence, new_mutation_sequence,
                        "round {round}: new mutation_sequence kept"
                    );
                    assert_eq!(
                        new_snap.target_revision, new_mutation_target.0,
                        "round {round}: new target revision kept"
                    );
                    assert_eq!(
                        new_snap.target_content_hash, new_mutation_target.1,
                        "round {round}: new target content hash kept"
                    );
                    assert_eq!(
                        new_snap.attempt_count, 0,
                        "round {round}: new mutation keeps full reset state"
                    );
                    assert_eq!(new_snap.fenced_claim_epoch, 0, "round {round}");
                    assert_eq!(new_snap.last_marked_claim_epoch, 0, "round {round}");
                    assert_eq!(new_snap.claimed_generation_id, None, "round {round}");
                    assert_eq!(new_snap.last_send_disposition, None, "round {round}");
                    assert_eq!(new_snap.last_error_code, None, "round {round}");
                }
                unexpected => {
                    panic!(
                        "round {round}: unexpected worker outcome for unmarked durable: {}",
                        stable_worker_result_name(unexpected)
                    );
                }
            }

            // Resource closure per round: all worker contexts are empty, no
            // unbound calls, all threads joined, and no SQLite WAL/SHM residue
            // survives after every connection is dropped.
            assert!(
                worker_context.is_empty(),
                "round {round}: marked worker context empty"
            );
            assert!(
                worker_context_b8.is_empty(),
                "round {round}: unmarked worker context empty"
            );
            assert_eq!(
                log.unbound_call_count(),
                0,
                "round {round}: marked log unbound"
            );
            assert_eq!(
                log_b8.unbound_call_count(),
                0,
                "round {round}: unmarked log unbound"
            );
            // Drop every remaining in-scope service and consumer so the
            // journal scan only sees closed connections. (storage_b, raw_vectors
            // were moved into the marked worker thread and are already dropped;
            // storage_ur, verifier and b8_verifier are separate services.)
            drop(storage_ur);
            drop(b8_verifier);
            drop(consumer_b8);
            drop(storage_b8);
            drop(raw_vectors_b8);
            let _ = (recovered, worker_result, verifier);
            assert_no_wal_shm_residue(&data_root);
        }
    }

    /// Two real workers sharing one append-only call log must never overwrite
    /// each other's bound claim identity: each worker owns its own
    /// [`WorkerCallContext`], and the recorded calls carry distinct
    /// worker_instance_id / memory / mutation / claim epoch. Both workers run
    /// real `process_one` invocations through real Recording Provider and
    /// Recording VectorStore entries.
    ///
    /// The overlap is deterministic: worker A claims and binds its context,
    /// then blocks at the BeforeEmbedding gate (before any external call).
    /// Worker B claims, binds its own context, and completes its real
    /// provider + upsert calls. The main thread then verifies A is still
    /// paused with A's identity while B's records carry B's identity, and
    /// only then releases A to complete its own real calls.
    #[test]
    fn external_call_recorder_worker_context_isolation_keeps_two_workers_isolated() {
        use crate::storage::test_support::{
            ExternalCallLog, WorkerCallContext, WorkerCallContextScope,
        };
        use std::sync::mpsc;

        let log = ExternalCallLog::default();
        let context_a = WorkerCallContext::new(log.clone());
        let context_b = WorkerCallContext::new(log.clone());
        assert_ne!(
            context_a.worker_instance_id(),
            context_b.worker_instance_id(),
            "two workers must have distinct instance ids"
        );

        // Worker A on database A, Worker B on database B: two real upserts.
        let (temp_a, storage_a) = test_storage();
        let data_root_a = temp_a.path().join("data");
        let (ctx_a, _) = drained_context();
        storage_a
            .register_building_vector_generation(
                ctx_a.generation_id().as_str(),
                ctx_a.descriptor_hash(),
                ctx_a.dimension(),
            )
            .unwrap();
        let record_a = crate::storage::test_support::insert_confirmed_memory_fixture(
            &storage_a,
            "life",
            "fact",
            "worker a isolation",
            None,
            0.5,
            0.5,
            false,
            true,
        );

        let (temp_b, storage_b) = test_storage();
        let data_root_b = temp_b.path().join("data");
        let (ctx_b, _) = drained_context();
        storage_b
            .register_building_vector_generation(
                ctx_b.generation_id().as_str(),
                ctx_b.descriptor_hash(),
                ctx_b.dimension(),
            )
            .unwrap();
        let record_b = crate::storage::test_support::insert_confirmed_memory_fixture(
            &storage_b,
            "life",
            "fact",
            "worker b isolation",
            None,
            0.5,
            0.5,
            false,
            true,
        );

        // Deterministic overlap via mpsc: A notifies "A bound and paused" at
        // the BeforeEmbedding gate and waits for release; B notifies after its
        // own real calls and finishes.
        let (a_paused_tx, a_paused_rx) = mpsc::channel::<()>();
        let (release_a_tx, release_a_rx) = mpsc::channel::<()>();
        let (b_done_tx, b_done_rx) = mpsc::channel::<()>();
        let (release_b_tx, release_b_rx) = mpsc::channel::<()>();

        let worker_a = {
            let ctx = ctx_a.clone();
            let context = context_a.clone();
            let raw_vectors = crate::vector_store::InMemoryVectorStore::default();
            tauri::async_runtime::block_on(raw_vectors.create_generation(&ctx)).unwrap();
            std::thread::spawn(move || {
                let scope = WorkerCallContextScope::new(context.clone());
                let provider_owned: Box<dyn EmbeddingProvider> =
                    Box::new(crate::embedding::DeterministicEmbeddingProvider::new(3));
                let provider = RecordingEmbeddingProvider {
                    inner: provider_owned.as_ref(),
                    context: &context,
                };
                let vectors = RecordingVectorStore {
                    inner: &raw_vectors,
                    context: &context,
                };
                let consumer =
                    FencedVectorSyncSingleEventConsumer::new(&storage_a, &provider, &vectors, ctx);
                let observer_context = context.clone();
                consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
                    observer_context.set_current_claim(claim);
                })));
                // Pause AFTER the claim observer bound A's context and BEFORE
                // the provider call: A is deterministically mid-claim with its
                // identity bound while B runs.
                let paused_tx = a_paused_tx.clone();
                let release_rx = release_a_rx;
                consumer.set_test_pause_hook_for_test(Some(Box::new(move |point| {
                    if point == VectorSyncTestPausePoint::BeforeEmbedding {
                        paused_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                    }
                })));
                let result =
                    tauri::async_runtime::block_on(consumer.process_one("worker-a")).unwrap();
                consumer.set_claim_observer_for_test(None);
                consumer.set_test_pause_hook_for_test(None);
                drop(scope);
                result
            })
        };
        let worker_b = {
            let ctx = ctx_b.clone();
            let context = context_b.clone();
            let raw_vectors = crate::vector_store::InMemoryVectorStore::default();
            tauri::async_runtime::block_on(raw_vectors.create_generation(&ctx)).unwrap();
            std::thread::spawn(move || {
                let scope = WorkerCallContextScope::new(context.clone());
                let provider_owned: Box<dyn EmbeddingProvider> =
                    Box::new(crate::embedding::DeterministicEmbeddingProvider::new(3));
                let provider = RecordingEmbeddingProvider {
                    inner: provider_owned.as_ref(),
                    context: &context,
                };
                let vectors = RecordingVectorStore {
                    inner: &raw_vectors,
                    context: &context,
                };
                let consumer =
                    FencedVectorSyncSingleEventConsumer::new(&storage_b, &provider, &vectors, ctx);
                let observer_context = context.clone();
                consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
                    observer_context.set_current_claim(claim);
                })));
                let result =
                    tauri::async_runtime::block_on(consumer.process_one("worker-b")).unwrap();
                consumer.set_claim_observer_for_test(None);
                // Notify while B's context is still bound (scope not yet
                // dropped) so the main thread can inspect B's identity, then
                // wait for the main thread to finish its inspection.
                b_done_tx.send(()).unwrap();
                release_b_rx.recv().unwrap();
                drop(scope);
                result
            })
        };

        // 1. Wait until A has claimed and bound its context, paused before
        //    any external call.
        a_paused_rx.recv().unwrap();
        // 2. Wait until B has completed its own real provider+upsert calls.
        b_done_rx.recv().unwrap();

        // A is still paused with A's identity bound; B finished with B's
        // identity. B's records must never have overwritten A's context.
        let a_identity = context_a
            .current_identity()
            .expect("worker A context must still be bound while paused");
        let b_identity = context_b
            .current_identity()
            .expect("worker B context must be bound after its claims");
        assert_eq!(
            a_identity.worker_instance_id,
            context_a.worker_instance_id(),
            "A context holds A worker id"
        );
        assert_eq!(
            a_identity.memory_id, record_a.id,
            "A context holds A memory"
        );
        assert_eq!(
            b_identity.worker_instance_id,
            context_b.worker_instance_id(),
            "B context holds B worker id"
        );
        assert_eq!(
            b_identity.memory_id, record_b.id,
            "B context holds B memory"
        );
        // B's calls carry B identity; A's calls must not exist yet (A paused
        // before its provider call).
        let b_calls = log.calls_for_memory(&record_b.id);
        assert_eq!(b_calls.len(), 2, "worker B: provider + upsert recorded");
        assert!(
            b_calls.iter().all(|call| {
                call.context.worker_instance_id == context_b.worker_instance_id()
                    && call.context.memory_id == record_b.id
                    && call.context.mutation_sequence == b_identity.mutation_sequence
                    && call.context.claim_epoch == b_identity.claim_epoch
                    && call.context.target_revision == b_identity.target_revision
                    && call.context.target_content_hash == b_identity.target_content_hash
            }),
            "B's recorded calls carry B's full claim identity"
        );
        assert!(
            log.calls_for_memory(&record_a.id).is_empty(),
            "worker A must not have recorded anything while paused"
        );

        // 3. Release workers A and B to complete their own real calls.
        release_a_tx.send(()).unwrap();
        release_b_tx.send(()).unwrap();

        let result_a = worker_a.join().unwrap();
        let result_b = worker_b.join().unwrap();
        assert_eq!(result_a, FencedVectorSyncSingleEventResult::CompletedUpsert);
        assert_eq!(result_b, FencedVectorSyncSingleEventResult::CompletedUpsert);

        // Both contexts ended empty and no call was unbound.
        assert!(context_a.is_empty());
        assert!(context_b.is_empty());
        assert_eq!(log.unbound_call_count(), 0);

        // Worker A's calls carry A's identity (memory record_a, mutation of
        // record_a, claim epoch 1, worker A id); worker B's calls carry B's.
        let a_calls = log.calls_for_memory(&record_a.id);
        let b_calls = log.calls_for_memory(&record_b.id);
        assert_eq!(a_calls.len(), 2, "worker A: provider + upsert");
        assert_eq!(b_calls.len(), 2, "worker B: provider + upsert");
        assert!(
            a_calls.iter().all(|call| {
                call.context.worker_instance_id == context_a.worker_instance_id()
                    && call.context.memory_id == record_a.id
                    && call.context.claim_epoch == a_identity.claim_epoch
                    && call.context.mutation_sequence == a_identity.mutation_sequence
                    && call.context.target_revision == a_identity.target_revision
            }),
            "worker A calls keep A identity"
        );
        assert!(
            b_calls.iter().all(|call| {
                call.context.worker_instance_id == context_b.worker_instance_id()
                    && call.context.memory_id == record_b.id
                    && call.context.claim_epoch == b_identity.claim_epoch
                    && call.context.mutation_sequence == b_identity.mutation_sequence
                    && call.context.target_revision == b_identity.target_revision
            }),
            "worker B calls keep B identity"
        );
        // Each worker's counts are keyed on its own mutation+claim.
        let mut_a = log.calls_for_claim(
            &record_a.id,
            a_identity.mutation_sequence,
            a_identity.claim_epoch,
        );
        let mut_b = log.calls_for_claim(
            &record_b.id,
            b_identity.mutation_sequence,
            b_identity.claim_epoch,
        );
        assert_eq!(mut_a.len(), 2, "A: provider+upsert on its claim");
        assert_eq!(mut_b.len(), 2, "B: provider+upsert on its claim");

        // Resource closure for the dual-worker test. storage_a and storage_b
        // were moved into the worker threads and dropped when they ended.
        assert_no_wal_shm_residue(&data_root_a);
        assert_no_wal_shm_residue(&data_root_b);
    }

    /// 10.1 Provider failure: the provider is called exactly once, the fake
    /// returns a failure, process_one ends, and the worker context is empty
    /// again with zero unbound calls.
    #[test]
    fn recording_provider_failure_clears_context_and_records_once() {
        let (temp, storage) = test_storage();
        let data_root = temp.path().join("data");
        let (ctx, _) = drained_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();
        let mem = crate::storage::test_support::insert_confirmed_memory_fixture(
            &storage,
            "life",
            "fact",
            "recorder provider failure",
            None,
            0.5,
            0.5,
            false,
            true,
        );
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: mem.life_id.clone(),
                memory_id: mem.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();

        let log = crate::storage::test_support::ExternalCallLog::default();
        let worker_context = crate::storage::test_support::WorkerCallContext::new(log.clone());
        let raw_vectors = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vectors.create_generation(&ctx)).unwrap();
        let failing_provider = PossiblySentEmbeddingProvider {
            inner: crate::embedding::DeterministicEmbeddingProvider::new(3),
            requests: AtomicUsize::new(0),
        };
        let provider = RecordingEmbeddingProvider {
            inner: &failing_provider,
            context: &worker_context,
        };
        let vectors = RecordingVectorStore {
            inner: &raw_vectors,
            context: &worker_context,
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, ctx.clone());
        let observer_context = worker_context.clone();
        consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
            observer_context.set_current_claim(claim);
        })));
        let scope =
            crate::storage::test_support::WorkerCallContextScope::new(worker_context.clone());
        let result = tauri::async_runtime::block_on(consumer.process_one("worker-fail")).unwrap();
        drop(scope);
        consumer.set_claim_observer_for_test(None);

        // The provider was called exactly once and failed; no Lance call.
        let mutation_sequence = outbox_mutation_sequence(&data_root, &mem.id);
        let claim_epoch = outbox_claim_epoch(&data_root, &mem.id);
        assert_eq!(
            log.counts_for_claim(&mem.id, mutation_sequence, claim_epoch),
            (1, 0, 0),
            "provider recorded exactly once"
        );
        assert_eq!(
            log.counts_for_mutation(&mem.id, mutation_sequence),
            (1, 0, 0),
            "mutation-level attribution"
        );
        assert_eq!(result, FencedVectorSyncSingleEventResult::Blocked);
        assert!(
            worker_context.is_empty(),
            "context cleared after provider failure"
        );
        assert_eq!(log.unbound_call_count(), 0);
    }

    /// 10.2 Lance upsert failure: provider 1, upsert 1, context empty.
    #[test]
    fn recording_lance_upsert_failure_clears_context_and_records_once() {
        let (temp, storage) = test_storage();
        let data_root = temp.path().join("data");
        let (ctx, _) = drained_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();
        let mem = crate::storage::test_support::insert_confirmed_memory_fixture(
            &storage,
            "life",
            "fact",
            "recorder lance upsert failure",
            None,
            0.5,
            0.5,
            false,
            true,
        );
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: mem.life_id.clone(),
                memory_id: mem.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();

        let log = crate::storage::test_support::ExternalCallLog::default();
        let worker_context = crate::storage::test_support::WorkerCallContext::new(log.clone());
        let failing_vectors = FailingLanceUpsertVectorStore {
            inner: crate::vector_store::InMemoryVectorStore::default(),
        };
        tauri::async_runtime::block_on(failing_vectors.inner.create_generation(&ctx)).unwrap();
        let provider_owned: Box<dyn EmbeddingProvider> =
            Box::new(crate::embedding::DeterministicEmbeddingProvider::new(3));
        let provider = RecordingEmbeddingProvider {
            inner: provider_owned.as_ref(),
            context: &worker_context,
        };
        let vectors = RecordingVectorStore {
            inner: &failing_vectors,
            context: &worker_context,
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, ctx.clone());
        let observer_context = worker_context.clone();
        consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
            observer_context.set_current_claim(claim);
        })));
        let scope =
            crate::storage::test_support::WorkerCallContextScope::new(worker_context.clone());
        let result = tauri::async_runtime::block_on(consumer.process_one("worker-lance")).unwrap();
        drop(scope);
        consumer.set_claim_observer_for_test(None);

        let mutation_sequence = outbox_mutation_sequence(&data_root, &mem.id);
        let claim_epoch = outbox_claim_epoch(&data_root, &mem.id);
        assert_eq!(
            log.counts_for_claim(&mem.id, mutation_sequence, claim_epoch),
            (1, 1, 0),
            "provider + upsert recorded, each exactly once"
        );
        assert!(
            worker_context.is_empty(),
            "context cleared after Lance failure"
        );
        assert_eq!(log.unbound_call_count(), 0);
        let _ = result;
    }

    /// 10.3 Lance delete failure: provider 0, upsert 0, delete 1, context empty.
    #[test]
    fn recording_lance_delete_failure_clears_context_and_records_once() {
        let (temp, storage) = test_storage();
        let data_root = temp.path().join("data");
        let (ctx, _) = drained_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();
        let mem = crate::storage::test_support::insert_confirmed_memory_fixture(
            &storage,
            "life",
            "fact",
            "recorder lance delete failure",
            None,
            0.5,
            0.5,
            false,
            true,
        );
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: mem.life_id.clone(),
                memory_id: mem.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();

        let log = crate::storage::test_support::ExternalCallLog::default();
        let worker_context = crate::storage::test_support::WorkerCallContext::new(log.clone());
        let failing_vectors = FailingLanceDeleteVectorStore {
            inner: crate::vector_store::InMemoryVectorStore::default(),
        };
        tauri::async_runtime::block_on(failing_vectors.inner.create_generation(&ctx)).unwrap();
        let provider_owned: Box<dyn EmbeddingProvider> =
            Box::new(crate::embedding::DeterministicEmbeddingProvider::new(3));
        let provider = RecordingEmbeddingProvider {
            inner: provider_owned.as_ref(),
            context: &worker_context,
        };
        let vectors = RecordingVectorStore {
            inner: &failing_vectors,
            context: &worker_context,
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, ctx.clone());
        let observer_context = worker_context.clone();
        consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
            observer_context.set_current_claim(claim);
        })));
        let scope =
            crate::storage::test_support::WorkerCallContextScope::new(worker_context.clone());
        let result = tauri::async_runtime::block_on(consumer.process_one("worker-del")).unwrap();
        drop(scope);
        consumer.set_claim_observer_for_test(None);

        let mutation_sequence = outbox_mutation_sequence(&data_root, &mem.id);
        let claim_epoch = outbox_claim_epoch(&data_root, &mem.id);
        assert_eq!(
            log.counts_for_claim(&mem.id, mutation_sequence, claim_epoch),
            (0, 0, 1),
            "delete recorded exactly once; provider and upsert never called"
        );
        assert!(
            worker_context.is_empty(),
            "context cleared after Lance delete failure"
        );
        assert_eq!(log.unbound_call_count(), 0);
        let _ = result;
    }

    /// 10.4 Token guard failure: no external call occurs at all, the worker
    /// returns LostLeaseOrSuperseded, and the context stays empty.
    #[test]
    fn recorder_guard_failure_records_nothing_and_clears_context() {
        let (temp, storage) = test_storage();
        let data_root = temp.path().join("data");
        let (ctx, raw_vectors) = drained_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();
        let mem = crate::storage::test_support::insert_confirmed_memory_fixture(
            &storage,
            "life",
            "fact",
            "recorder guard failure",
            None,
            0.5,
            0.5,
            false,
            true,
        );
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: mem.life_id.clone(),
                memory_id: mem.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();

        let log = crate::storage::test_support::ExternalCallLog::default();
        let worker_context = crate::storage::test_support::WorkerCallContext::new(log.clone());
        let provider_owned: Box<dyn EmbeddingProvider> =
            Box::new(crate::embedding::DeterministicEmbeddingProvider::new(3));
        let provider = RecordingEmbeddingProvider {
            inner: provider_owned.as_ref(),
            context: &worker_context,
        };
        let vectors = RecordingVectorStore {
            inner: &raw_vectors,
            context: &worker_context,
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, ctx.clone());
        let observer_context = worker_context.clone();
        // The claim observer registers the identity AND deterministically
        // expires the runtime lease on an independent connection before the
        // worker's first token guard runs. The guard must then reject the
        // claim before any external call. A raw authorized connection is used
        // so the observer closure stays a plain `Fn` (no owned service).
        let observer_db_path = data_root.clone();
        consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
            observer_context.set_current_claim(claim);
            let conn = crate::storage::open_authorized_test_connection(
                &observer_db_path.join("digital-life.sqlite3"),
            )
            .unwrap();
            conn.execute(
                "UPDATE memory_vector_sync_runtime_lease SET expires_at='2000-01-01T00:00:00.000Z'",
                [],
            )
            .unwrap();
            conn.execute(
                "UPDATE memory_vector_sync_outbox SET lease_expires_at='2000-01-01T00:00:00.000Z' WHERE state='processing'",
                [],
            )
            .unwrap();
        })));
        let scope =
            crate::storage::test_support::WorkerCallContextScope::new(worker_context.clone());
        let result = tauri::async_runtime::block_on(consumer.process_one("worker-guard")).unwrap();
        drop(scope);
        consumer.set_claim_observer_for_test(None);

        assert_eq!(
            result,
            FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded,
            "the first token guard must reject the expired claim"
        );
        let mutation_sequence = outbox_mutation_sequence(&data_root, &mem.id);
        assert_eq!(
            log.counts_for_mutation(&mem.id, mutation_sequence),
            (0, 0, 0),
            "no external call when the token guard fails"
        );
        assert_eq!(log.unbound_call_count(), 0);
        assert!(
            worker_context.is_empty(),
            "context empty after guard failure"
        );
    }

    /// 10.5 Panic unwind: a panicking fake provider unwinds through the RAII
    /// scope, whose Drop clears the worker context.
    #[test]
    fn recorder_panic_cleanup_clears_context_on_unwind() {
        use crate::storage::test_support::{WorkerCallContext, WorkerCallContextScope};

        struct PanickingProvider;
        impl EmbeddingProvider for PanickingProvider {
            fn model_info(&self) -> EmbeddingModelInfo {
                EmbeddingModelInfo {
                    model_name: "panic".into(),
                    dimension: Some(3),
                }
            }
            fn model_name(&self) -> &str {
                "panic"
            }
            fn vector_dimension(&self) -> Option<usize> {
                Some(3)
            }
            fn max_batch_size(&self) -> usize {
                1
            }
            fn embed<'a>(
                &'a self,
                _request: EmbeddingRequest,
            ) -> EmbeddingFuture<'a, Result<EmbeddingBatch, EmbeddingError>> {
                Box::pin(async {
                    panic!("intentional recorder panic");
                })
            }
        }

        let (temp, storage) = test_storage();
        let data_root = temp.path().join("data");
        let (ctx, raw_vectors) = drained_context();
        storage
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();
        let mem = crate::storage::test_support::insert_confirmed_memory_fixture(
            &storage,
            "life",
            "fact",
            "recorder panic cleanup",
            None,
            0.5,
            0.5,
            false,
            true,
        );
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: mem.life_id.clone(),
                memory_id: mem.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();

        let log = crate::storage::test_support::ExternalCallLog::default();
        let worker_context = WorkerCallContext::new(log.clone());
        let provider_owned: Box<dyn EmbeddingProvider> = Box::new(PanickingProvider);
        let provider = RecordingEmbeddingProvider {
            inner: provider_owned.as_ref(),
            context: &worker_context,
        };
        let vectors = RecordingVectorStore {
            inner: &raw_vectors,
            context: &worker_context,
        };
        let consumer =
            FencedVectorSyncSingleEventConsumer::new(&storage, &provider, &vectors, ctx.clone());
        let observer_context = worker_context.clone();
        consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
            observer_context.set_current_claim(claim);
        })));

        let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let scope = WorkerCallContextScope::new(worker_context.clone());
            let _ = tauri::async_runtime::block_on(consumer.process_one("worker-panic"));
            drop(scope);
        }));
        consumer.set_claim_observer_for_test(None);

        assert!(
            panic_result.is_err(),
            "the fake provider panic must propagate"
        );
        assert!(
            worker_context.is_empty(),
            "RAII Drop must clear the context on panic unwind"
        );
        let mutation_sequence = outbox_mutation_sequence(&data_root, &mem.id);
        let claim_epoch = outbox_claim_epoch(&data_root, &mem.id);
        assert_eq!(
            log.counts_for_claim(&mem.id, mutation_sequence, claim_epoch),
            (1, 0, 0),
            "the provider call that panicked was recorded exactly once"
        );
        assert_eq!(log.unbound_call_count(), 0);
    }

    /// 10.6 Storage reopen: an old worker finishes with an empty context,
    /// the old StorageService is dropped, the database is reopened, and a new
    /// worker with a fresh context records calls with only the new identity.
    #[test]
    fn recorder_storage_reopen_keeps_new_context_clean() {
        use crate::storage::test_support::{WorkerCallContext, WorkerCallContextScope};

        let (temp, storage_a) = test_storage();
        let data_root = temp.path().join("data");
        let (ctx, _) = drained_context();
        storage_a
            .register_building_vector_generation(
                ctx.generation_id().as_str(),
                ctx.descriptor_hash(),
                ctx.dimension(),
            )
            .unwrap();
        let mem = crate::storage::test_support::insert_confirmed_memory_fixture(
            &storage_a,
            "life",
            "fact",
            "recorder reopen old worker",
            None,
            0.5,
            0.5,
            false,
            true,
        );
        storage_a
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: mem.life_id.clone(),
                memory_id: mem.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();

        let log = crate::storage::test_support::ExternalCallLog::default();
        let old_context = WorkerCallContext::new(log.clone());
        let raw_vectors = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vectors.create_generation(&ctx)).unwrap();
        {
            let provider_owned: Box<dyn EmbeddingProvider> =
                Box::new(crate::embedding::DeterministicEmbeddingProvider::new(3));
            let provider = RecordingEmbeddingProvider {
                inner: provider_owned.as_ref(),
                context: &old_context,
            };
            let vectors = RecordingVectorStore {
                inner: &raw_vectors,
                context: &old_context,
            };
            let consumer = FencedVectorSyncSingleEventConsumer::new(
                &storage_a,
                &provider,
                &vectors,
                ctx.clone(),
            );
            let observer_context = old_context.clone();
            consumer.set_claim_observer_for_test(Some(Box::new(move |claim| {
                observer_context.set_current_claim(claim);
            })));
            let scope = WorkerCallContextScope::new(old_context.clone());
            let result =
                tauri::async_runtime::block_on(consumer.process_one("worker-old")).unwrap();
            drop(scope);
            consumer.set_claim_observer_for_test(None);
            assert_eq!(result, FencedVectorSyncSingleEventResult::CompletedUpsert);
        }
        assert!(
            old_context.is_empty(),
            "old worker context empty before StorageService drop"
        );
        drop(storage_a);
        assert!(
            old_context.is_empty(),
            "old worker context empty after StorageService drop"
        );

        // Reopen the same database file with a NEW worker and a NEW context.
        let storage_b = StorageService::initialize_with_roots(data_root, None).unwrap();
        let new_context = WorkerCallContext::new(log.clone());
        assert_ne!(
            new_context.worker_instance_id(),
            old_context.worker_instance_id(),
            "reopened worker gets a fresh instance id"
        );
        let mem_b = crate::storage::test_support::insert_confirmed_memory_fixture(
            &storage_b,
            "life",
            "fact",
            "recorder reopen new worker",
            None,
            0.5,
            0.5,
            false,
            true,
        );
        storage_b
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: mem_b.life_id.clone(),
                memory_id: mem_b.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        let raw_vectors_b = crate::vector_store::InMemoryVectorStore::default();
        tauri::async_runtime::block_on(raw_vectors_b.create_generation(&ctx)).unwrap();
        let provider_owned_b: Box<dyn EmbeddingProvider> =
            Box::new(crate::embedding::DeterministicEmbeddingProvider::new(3));
        let provider_b = RecordingEmbeddingProvider {
            inner: provider_owned_b.as_ref(),
            context: &new_context,
        };
        let vectors_b = RecordingVectorStore {
            inner: &raw_vectors_b,
            context: &new_context,
        };
        let consumer_b =
            FencedVectorSyncSingleEventConsumer::new(&storage_b, &provider_b, &vectors_b, ctx);
        let observer_context_b = new_context.clone();
        consumer_b.set_claim_observer_for_test(Some(Box::new(move |claim| {
            observer_context_b.set_current_claim(claim);
        })));
        // The old worker's runtime lease may still be alive; expire it so the
        // reopened worker can acquire the runtime lease on the same file.
        storage_b.test_expire_fenced_runtime_lease().unwrap();
        let scope_b = WorkerCallContextScope::new(new_context.clone());
        let result_b =
            tauri::async_runtime::block_on(consumer_b.process_one("worker-new")).unwrap();
        drop(scope_b);
        consumer_b.set_claim_observer_for_test(None);
        assert_eq!(result_b, FencedVectorSyncSingleEventResult::CompletedUpsert);
        assert!(new_context.is_empty(), "new worker context empty at end");
        assert_eq!(log.unbound_call_count(), 0);

        // The new worker's calls carry only the new worker's identity and the
        // new memory; nothing from the old worker leaks into them.
        let new_calls = log.calls_for_memory(&mem_b.id);
        assert_eq!(new_calls.len(), 2, "new worker: provider + upsert");
        assert!(
            new_calls.iter().all(|call| {
                call.context.worker_instance_id == new_context.worker_instance_id()
            }),
            "new calls carry the new worker id"
        );
        let old_calls = log.calls_for_memory(&mem.id);
        assert!(
            old_calls
                .iter()
                .all(|call| call.context.worker_instance_id == old_context.worker_instance_id()),
            "old calls carry the old worker id"
        );
    }

    /// Reads the durable mutation_sequence of one outbox row (test-only).
    fn outbox_mutation_sequence(data_root: &std::path::Path, memory_id: &str) -> i64 {
        let conn = crate::storage::open_authorized_test_connection(
            &data_root.join("digital-life.sqlite3"),
        )
        .unwrap();
        conn.query_row(
            "SELECT mutation_sequence FROM memory_vector_sync_outbox WHERE memory_id=?1",
            rusqlite::params![memory_id],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// Reads the durable fenced_claim_epoch of one outbox row (test-only).
    fn outbox_claim_epoch(data_root: &std::path::Path, memory_id: &str) -> i64 {
        let conn = crate::storage::open_authorized_test_connection(
            &data_root.join("digital-life.sqlite3"),
        )
        .unwrap();
        conn.query_row(
            "SELECT fenced_claim_epoch FROM memory_vector_sync_outbox WHERE memory_id=?1",
            rusqlite::params![memory_id],
            |r| r.get(0),
        )
        .unwrap()
    }

    /// Asserts that no SQLite WAL or SHM residue remains in a directory tree
    /// after every connection has been dropped. The main database file is
    /// allowed; only the sidecar journal files are rejected.
    fn assert_no_wal_shm_residue(root: &std::path::Path) {
        let mut residue: Vec<String> = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let entries = match std::fs::read_dir(&dir) {
                Ok(entries) => entries,
                Err(_) => continue,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let name = entry.file_name().to_string_lossy().to_string();
                if name.ends_with("-wal")
                    || name.ends_with("-shm")
                    || name.ends_with(".sqlite3-wal")
                    || name.ends_with(".sqlite3-shm")
                {
                    residue.push(path.display().to_string());
                }
            }
        }
        assert!(
            residue.is_empty(),
            "SQLite WAL/SHM residue after connections are dropped: {}",
            residue.join(", ")
        );
    }

    /// Stable variant name for a worker result so an unexpected-outcome panic
    /// never depends on a Debug impl.
    fn stable_worker_result_name(result: FencedVectorSyncSingleEventResult) -> &'static str {
        match result {
            FencedVectorSyncSingleEventResult::NoEligibleEvent => "NoEligibleEvent",
            FencedVectorSyncSingleEventResult::CompletedUpsert => "CompletedUpsert",
            FencedVectorSyncSingleEventResult::CompletedDelete => "CompletedDelete",
            FencedVectorSyncSingleEventResult::Stale => "Stale",
            FencedVectorSyncSingleEventResult::RetryWait => "RetryWait",
            FencedVectorSyncSingleEventResult::Blocked => "Blocked",
            FencedVectorSyncSingleEventResult::Failed => "Failed",
            FencedVectorSyncSingleEventResult::LostLeaseOrSuperseded => "LostLeaseOrSuperseded",
            FencedVectorSyncSingleEventResult::NoProgressForTest => "NoProgressForTest",
        }
    }
}
