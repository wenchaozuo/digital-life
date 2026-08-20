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
    storage::{StorageError, StorageService},
    vector_store::LanceDbVectorStoreRegistry,
};

use super::{
    existing_generation_binding::resolve_active_generation_fenced_execution,
    late_delete_resolution_runner::{run_one_late_delete_from_app, LateDeleteRunEnd},
    vector_generation_rebuild::{run_generation_rebuild_c, run_generation_rebuild_d},
    vector_sync_worker::VectorSyncDrainReport,
};

/// Process-global RAII gate for the complete fenced composition lifecycle.
///
/// The guard is acquired before authority resolution and remains held through
/// matching-store acquisition, bounded drain, and drop of the owned execution.
pub struct FencedVectorSyncCompositionGate {
    gate: Mutex<()>,
}

/// The sole composition guard is intentionally shareable with staged,
/// private lifecycle phases. A phase must receive this guard from its future
/// full-pipeline orchestrator; it must not acquire and release a partial gate
/// around a live building job. The private field brands the guard to this
/// gate instead of accepting an arbitrary `MutexGuard<()>`.
pub(crate) struct FencedVectorSyncCompositionGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

impl Default for FencedVectorSyncCompositionGate {
    fn default() -> Self {
        Self {
            gate: Mutex::new(()),
        }
    }
}

impl FencedVectorSyncCompositionGate {
    pub(crate) async fn acquire(&self) -> FencedVectorSyncCompositionGuard<'_> {
        FencedVectorSyncCompositionGuard {
            _guard: self.gate.lock().await,
        }
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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartVectorGenerationRebuildRequest {
    pub request_id: String,
    pub timeout_millis: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VectorGenerationRebuildStatus {
    pub job_id: String,
    pub status: String,
    pub snapshot_sequence: Option<i64>,
    pub caught_up_sequence: Option<i64>,
    pub promotion_sequence: Option<i64>,
    pub cancel_requested: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VectorGenerationRebuildErrorCode {
    Unavailable,
    Conflict,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VectorGenerationRebuildError {
    pub code: VectorGenerationRebuildErrorCode,
    pub message: &'static str,
    pub recoverable: bool,
}

fn rebuild_status(
    job: crate::storage::GenerationRebuildJobRecord,
) -> VectorGenerationRebuildStatus {
    VectorGenerationRebuildStatus {
        job_id: job.job_id,
        status: job.status,
        snapshot_sequence: job.snapshot_sequence,
        caught_up_sequence: job.caught_up_sequence,
        promotion_sequence: job.promotion_sequence,
        cancel_requested: job.cancel_requested,
    }
}

fn map_rebuild_error(
    error: super::vector_generation_rebuild::GenerationRebuildCError,
) -> VectorGenerationRebuildError {
    let code = if error.code.contains("CONFLICT") {
        VectorGenerationRebuildErrorCode::Conflict
    } else if error.recoverable {
        VectorGenerationRebuildErrorCode::Unavailable
    } else {
        VectorGenerationRebuildErrorCode::Failed
    };
    VectorGenerationRebuildError {
        code,
        message: "The vector generation rebuild could not complete.",
        recoverable: error.recoverable,
    }
}

#[tauri::command]
pub fn start_vector_generation_rebuild(
    storage: State<'_, StorageService>,
    secrets: State<'_, WindowsCredentialSecretStore>,
    model_runtime: State<'_, ModelRuntimeCoordinator>,
    registry: State<'_, LanceDbVectorStoreRegistry>,
    gate: State<'_, FencedVectorSyncCompositionGate>,
    request: StartVectorGenerationRebuildRequest,
) -> Result<VectorGenerationRebuildStatus, VectorGenerationRebuildError> {
    if request.timeout_millis == 0 || request.request_id.trim().is_empty() {
        return Err(VectorGenerationRebuildError {
            code: VectorGenerationRebuildErrorCode::Failed,
            message: "The rebuild request is invalid.",
            recoverable: false,
        });
    }
    tauri::async_runtime::block_on(run_vector_generation_rebuild(
        storage.inner(),
        secrets.inner(),
        model_runtime.inner(),
        registry.inner(),
        gate.inner(),
        &request.request_id,
        std::time::Duration::from_millis(request.timeout_millis),
    ))
    .map(rebuild_status)
    .map_err(map_rebuild_error)
}

/// Shared status-resolution used by the production `get` IPC command.  A
/// persisted `completed` job is only reported as `completed` after the exact
/// promotion postimage classifies `Committed`; a mixed/invalid/unreadable
/// completed world returns the redacted Unavailable error surface (never a
/// false `completed`, and never any generation/epoch/resolution authority).
pub(crate) fn resolve_generation_rebuild_status(
    storage: &StorageService,
    job_id: &str,
) -> Result<VectorGenerationRebuildStatus, VectorGenerationRebuildError> {
    let unavailable = || VectorGenerationRebuildError {
        code: VectorGenerationRebuildErrorCode::Unavailable,
        message: "The vector generation rebuild is unavailable.",
        recoverable: true,
    };
    let job = storage
        .load_generation_rebuild_job(job_id)
        .map_err(|_| unavailable())?;
    if job.status == "completed" {
        match super::vector_generation_rebuild::classify_completed_generation_rebuild(storage, &job)
        {
            Ok(super::vector_generation_rebuild::CompletedRebuildClassification::Committed) => {}
            _ => return Err(unavailable()),
        }
    }
    Ok(rebuild_status(job))
}

#[tauri::command]
pub fn get_vector_generation_rebuild_job(
    storage: State<'_, StorageService>,
    job_id: String,
) -> Result<VectorGenerationRebuildStatus, VectorGenerationRebuildError> {
    resolve_generation_rebuild_status(storage.inner(), &job_id)
}

#[tauri::command]
pub fn cancel_vector_generation_rebuild(
    storage: State<'_, StorageService>,
    job_id: String,
) -> Result<(), VectorGenerationRebuildError> {
    storage
        .request_generation_rebuild_cancel(&job_id)
        .map_err(|_| VectorGenerationRebuildError {
            code: VectorGenerationRebuildErrorCode::Unavailable,
            message: "The vector generation rebuild is unavailable.",
            recoverable: true,
        })
}

pub(crate) async fn run_vector_generation_rebuild<S>(
    storage: &StorageService,
    secrets: &S,
    model_runtime: &ModelRuntimeCoordinator,
    registry: &LanceDbVectorStoreRegistry,
    gate: &FencedVectorSyncCompositionGate,
    request_id: &str,
    timeout: std::time::Duration,
) -> Result<
    crate::storage::GenerationRebuildJobRecord,
    super::vector_generation_rebuild::GenerationRebuildCError,
>
where
    S: SecretStore + ?Sized,
{
    let guard = gate.acquire().await;
    run_vector_generation_rebuild_guarded(
        storage,
        secrets,
        model_runtime,
        registry,
        &guard,
        request_id,
        timeout,
    )
    .await
}

/// The full pipeline body runs while the caller-owned composition guard is
/// held.  The guard is a dependency of this function, not something this
/// function acquires and releases around a live candidate: the caller decides
/// when the guard may be released after the candidate is durably terminal.
pub(crate) async fn run_vector_generation_rebuild_guarded<'a, S>(
    storage: &StorageService,
    secrets: &S,
    model_runtime: &ModelRuntimeCoordinator,
    registry: &LanceDbVectorStoreRegistry,
    guard: &FencedVectorSyncCompositionGuard<'a>,
    request_id: &str,
    timeout: std::time::Duration,
) -> Result<
    crate::storage::GenerationRebuildJobRecord,
    super::vector_generation_rebuild::GenerationRebuildCError,
>
where
    S: SecretStore + ?Sized,
{
    let deadline = std::time::Instant::now() + timeout;
    let runtime = ModelRuntimeService::new(storage, secrets, model_runtime);
    let owner = format!("generation-rebuild-{request_id}");
    let result = async {
        if let Some(job) = storage
            .load_generation_rebuild_job_by_request(request_id)
            .map_err(super::vector_generation_rebuild::GenerationRebuildCError::storage)?
        {
            if job.status == "completed" {
                // A persisted `completed` row is not completion authority.
                // Restart/resume must acquire the gate (already held here) and
                // exact-classify the promotion before returning success.  A
                // mixed world routes back to the fail-closed recovery path.
                return match super::vector_generation_rebuild::
                    classify_completed_generation_rebuild(storage, &job)
                {
                    Ok(
                        super::vector_generation_rebuild::CompletedRebuildClassification::Committed,
                    ) => Ok(job),
                    Ok(
                        super::vector_generation_rebuild::CompletedRebuildClassification::RecoveryRequired,
                    ) => Err(
                        super::vector_generation_rebuild::GenerationRebuildCError::promotion_recovery_required(
                            "A persisted completed rebuild is not an exact committed promotion.",
                        ),
                    ),
                    Err(error) => Err(
                        super::vector_generation_rebuild::GenerationRebuildCError::storage(error),
                    ),
                };
            }
        }
        let handoff = loop {
            if std::time::Instant::now() >= deadline {
                return Err(
                    super::vector_generation_rebuild::GenerationRebuildCError::failed(
                        "The generation rebuild deadline elapsed at a safe boundary.",
                    ),
                );
            }
            match run_generation_rebuild_c(storage, &runtime, registry, request_id, &owner, guard)
                .await
            {
                Ok(handoff) => break handoff,
                Err(error) if error.recoverable => {
                    let terminal = storage
                        .load_generation_rebuild_job_by_request(request_id)
                        .map_err(
                            super::vector_generation_rebuild::GenerationRebuildCError::storage,
                        )?
                        .is_none_or(|job| {
                            matches!(job.status.as_str(), "failed" | "cancelled" | "completed")
                        });
                    if terminal {
                        return Err(error);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                Err(error) => return Err(error),
            }
        };
        run_generation_rebuild_d(
            storage, &runtime, registry, &handoff, &owner, deadline, guard,
        )
        .await
    }
    .await;
    if let Err(ref error) = result {
        if error.code == "GENERATION_REBUILD_PROMOTION_RECOVERY_REQUIRED" {
            // A mixed promotion world: `job.status` may say `completed` while
            // pointer/generations/resolutions disagree.  The composition guard
            // must stay held, no failed-generation compensation may run against
            // a possibly-active G2, and safety is only proven by an exact
            // durable postimage classification.
            ensure_promotion_recovery_classified(storage, request_id).await;
            // The recovery loop returns only when the durable world is exactly
            // Committed again (or proven failed/cancelled by another exact
            // operation).  Resolve the authoritative outcome; once Committed is
            // proven, this resumed request may return authoritative completion.
            return match storage.load_generation_rebuild_job_by_request(request_id) {
                Ok(Some(job)) if job.status == "completed" => Ok(job),
                Ok(Some(_)) => {
                    Err(super::vector_generation_rebuild::GenerationRebuildCError::failed(
                        "The generation rebuild was terminated before exact completion.",
                    ))
                }
                _ => Err(
                    super::vector_generation_rebuild::GenerationRebuildCError::promotion_recovery_required(
                        "The promotion recovery world could not be resolved to an authoritative outcome.",
                    ),
                ),
            };
        }
        // The failed pipeline must not release the composition guard while the
        // candidate generation is still nonterminal.  Compensation is retried
        // and classified against durable SQLite state while this very scope
        // still holds the guard; the scope ends only after the world is
        // durably terminal (job failed/cancelled, or an exactly Committed
        // completed job).  Nobody else can acquire the gate during that window.
        ensure_durably_terminal_after_failure(storage, request_id, &owner, error).await;
    }
    result
}

/// Holds the composition guard through an exact promotion-recovery
/// reclassification.  A `RecoveryRequired` promotion world may have actually
/// committed, so the outer owner never runs the ordinary failed-generation
/// compensation and never infers safety from `job.status` alone.  This loop
/// returns only when the durable world is exactly Committed again (or has been
/// moved to a proven failed/cancelled terminal state by another exact
/// operation).  Absence of the durable job record is NOT treated as terminal:
/// once promotion recovery has begun, a missing job proves none of
/// Committed/failed/cancelled, so the composition guard stays held.  A
/// persistently mixed world parks fail-closed with the guard retained, which is
/// preferable to releasing authority into an unclassified world.
async fn ensure_promotion_recovery_classified(storage: &StorageService, request_id: &str) {
    #[cfg(test)]
    if let Some(tx) = PROMOTION_RECOVERY_ENTERED_SIGNAL.lock().unwrap().take() {
        let _ = tx.send(());
    }
    let mut attempt: u32 = 0;
    loop {
        attempt = attempt.saturating_add(1);
        // Test-only seam: simulate the durable job lookup becoming missing for
        // one iteration so the fail-closed job-absence branch is exercised.
        let hide_job = take_promotion_recovery_hide_job();
        if hide_job {
            #[cfg(test)]
            if let Some(tx) = PROMOTION_RECOVERY_MISSING_SIGNAL.lock().unwrap().take() {
                let _ = tx.send(());
            }
            // A missing durable job in a known PROMOTION_RECOVERY_REQUIRED world
            // is not proof of Committed, failed, or cancelled: fail closed and
            // keep the gate.  No replacement job, no new generation, no
            // compensation.
            let backoff_millis = u64::from(attempt.min(40)) * 5;
            tokio::time::sleep(std::time::Duration::from_millis(backoff_millis)).await;
            continue;
        }
        match storage.load_generation_rebuild_job_by_request(request_id) {
            Ok(Some(job)) => {
                if matches!(job.status.as_str(), "failed" | "cancelled") {
                    // Another exact durable operation already moved the world to
                    // a proven failed/cancelled terminal state; the scope may end.
                    return;
                }
                if job.status == "completed" {
                    match super::vector_generation_rebuild::
                        classify_completed_generation_rebuild(storage, &job)
                    {
                        Ok(
                            super::vector_generation_rebuild::CompletedRebuildClassification::Committed,
                        ) => {
                            // The exact durable postimage is proven again;
                            // releasing the guard is now legal.
                            return;
                        }
                        _ => {
                            // Still mixed/ambiguous or unreadable: fail closed.
                        }
                    }
                }
                // Else: a non-completed / non-failed job in a promotion-recovery
                // world -> fail closed (never a hidden promotion retry and never
                // a blind compensation).
            }
            Ok(None) => {
                // The durable job record disappeared on a known
                // PROMOTION_RECOVERY_REQUIRED world: absence is not proof of
                // Committed, failed, or cancelled.  Fail closed and retain the
                // composition guard.
            }
            Err(_) => {
                // Durable read failed while the guard is held: keep the guard and
                // retry; the scope must not end while the world is mixed.
            }
        }
        let backoff_millis = u64::from(attempt.min(40)) * 5;
        tokio::time::sleep(std::time::Duration::from_millis(backoff_millis)).await;
    }
}

/// Retries/classifies the failed-generation compensation while the composition
/// guard is held.  This function never returns while the job is nonterminal, so
/// the caller scope cannot end (and the guard cannot release) with a live
/// nonterminal G2.
async fn ensure_durably_terminal_after_failure(
    storage: &StorageService,
    request_id: &str,
    owner: &str,
    error: &super::vector_generation_rebuild::GenerationRebuildCError,
) {
    let mut attempt: u32 = 0;
    loop {
        attempt = attempt.saturating_add(1);
        match storage.load_generation_rebuild_job_by_request(request_id) {
            Ok(Some(job)) if matches!(job.status.as_str(), "failed" | "cancelled") => {
                // The durable world is already proven terminal even if this
                // local compensation result was lost; the scope may end.
                return;
            }
            Ok(Some(job)) if job.status == "completed" => {
                // `completed` is not completion authority.  An ordinary failure
                // may only release the guard after the exact classifier proves
                // Committed; a mixed completed world delegates to the fail-closed
                // promotion-recovery path.
                match super::vector_generation_rebuild::classify_completed_generation_rebuild(
                    storage, &job,
                ) {
                    Ok(
                        super::vector_generation_rebuild::CompletedRebuildClassification::Committed,
                    ) => return,
                    _ => {
                        ensure_promotion_recovery_classified(storage, request_id).await;
                        return;
                    }
                }
            }
            Ok(Some(job)) => {
                if let Ok(Some(lease)) =
                    storage.acquire_generation_rebuild_job_lease(&job.job_id, owner)
                {
                    let forced_failure = take_fail_next_outer_compensation();
                    let outcome = if forced_failure {
                        #[cfg(test)]
                        if let Some(tx) = OUTER_COMPENSATION_FAILURE_SIGNAL.lock().unwrap().take() {
                            let _ = tx.send(());
                        }
                        Err(StorageError::new(
                            "D9D3_D_F1_TRANSIENT_COMPENSATION_FAILURE",
                            "A transient compensation failure was injected by the test seam.",
                            true,
                        ))
                    } else {
                        storage.fail_generation_rebuild(
                            &job.job_id,
                            &lease,
                            &error.code,
                            job.candidate_authority_epoch,
                        )
                    };
                    // The cleanup result is deliberately not discarded: the
                    // next loop iteration re-inspects the durable job state
                    // and only ends this scope once the world is terminal.
                    let _ = outcome;
                }
            }
            Ok(None) => {
                // Ordinary failure with no durable job: there is nothing
                // nonterminal to compensate, so the scope may end.
                return;
            }
            Err(_) => {
                // A durable read failed while the guard is held: keep the guard
                // and retry.  The scope must not end while the candidate is
                // nonterminal, so a persistent storage failure parks the
                // pipeline fail-closed rather than releasing the gate.
            }
        }
        let backoff_millis = u64::from(attempt.min(40)) * 5;
        tokio::time::sleep(std::time::Duration::from_millis(backoff_millis)).await;
    }
}

#[cfg(test)]
static FAIL_NEXT_OUTER_COMPENSATION: std::sync::Mutex<bool> = std::sync::Mutex::new(false);
#[cfg(test)]
static OUTER_COMPENSATION_FAILURE_SIGNAL: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>> =
    std::sync::Mutex::new(None);

/// Test-only seam: the next compensation attempt performed by the full-pipeline
/// owner (after C/D failed) fails with a transient error, then the loop retries
/// while the same composition guard is held.
#[cfg(test)]
pub(super) fn fail_next_outer_compensation_for_test() {
    *FAIL_NEXT_OUTER_COMPENSATION.lock().unwrap() = true;
}

/// Test-only channel: notified when the injected transient compensation failure
/// has just occurred (the guard is still held and the job is still nonterminal).
#[cfg(test)]
pub(super) fn set_outer_compensation_failure_signal_for_test(sender: std::sync::mpsc::Sender<()>) {
    *OUTER_COMPENSATION_FAILURE_SIGNAL.lock().unwrap() = Some(sender);
}

#[cfg(test)]
static PROMOTION_RECOVERY_ENTERED_SIGNAL: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>> =
    std::sync::Mutex::new(None);

/// Test-only channel: notified just after the outer lifecycle owner entered the
/// promotion-recovery fail-closed path (the composition guard is still held and
/// no compensation has run).
#[cfg(test)]
pub(super) fn set_promotion_recovery_entered_signal_for_test(sender: std::sync::mpsc::Sender<()>) {
    *PROMOTION_RECOVERY_ENTERED_SIGNAL.lock().unwrap() = Some(sender);
}

#[cfg(test)]
static PROMOTION_RECOVERY_HIDE_JOB_ON_READ: std::sync::Mutex<bool> = std::sync::Mutex::new(false);
#[cfg(test)]
static PROMOTION_RECOVERY_MISSING_SIGNAL: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>> =
    std::sync::Mutex::new(None);

/// Test-only seam: the next promotion-recovery iteration treats the durable job
/// lookup as missing, proving that job absence is fail-closed (the composition
/// guard is retained, never a terminal release).
#[cfg(test)]
pub(super) fn arm_promotion_recovery_hide_job_for_test() {
    *PROMOTION_RECOVERY_HIDE_JOB_ON_READ.lock().unwrap() = true;
}

/// Test-only channel: notified just after the promotion-recovery loop observed a
/// missing/unavailable job and chose to fail closed (the guard is still held).
#[cfg(test)]
pub(super) fn set_promotion_recovery_missing_signal_for_test(sender: std::sync::mpsc::Sender<()>) {
    *PROMOTION_RECOVERY_MISSING_SIGNAL.lock().unwrap() = Some(sender);
}

#[cfg(test)]
fn take_promotion_recovery_hide_job() -> bool {
    std::mem::take(&mut *PROMOTION_RECOVERY_HIDE_JOB_ON_READ.lock().unwrap())
}

#[cfg(not(test))]
fn take_promotion_recovery_hide_job() -> bool {
    false
}

#[cfg(test)]
fn take_fail_next_outer_compensation() -> bool {
    std::mem::take(&mut *FAIL_NEXT_OUTER_COMPENSATION.lock().unwrap())
}

#[cfg(not(test))]
fn take_fail_next_outer_compensation() -> bool {
    false
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
        let execution = resolve_active_generation_fenced_execution(storage, &runtime, registry)
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
    fn d9d3_d_production_rebuild_ipc_routes_are_registered_and_redacted() {
        let library_source = include_str!("../lib.rs");
        for route in [
            "vector_sync_stage_runtime::start_vector_generation_rebuild",
            "vector_sync_stage_runtime::get_vector_generation_rebuild_job",
            "vector_sync_stage_runtime::cancel_vector_generation_rebuild",
        ] {
            assert!(
                library_source.contains(route),
                "missing registered route: {route}"
            );
        }

        let stage_source = include_str!("vector_sync_stage_runtime.rs");
        for signature in [
            "pub fn start_vector_generation_rebuild(",
            "pub fn get_vector_generation_rebuild_job(",
            "pub fn cancel_vector_generation_rebuild(",
        ] {
            assert!(
                stage_source.contains(signature),
                "missing IPC signature: {signature}"
            );
        }
        assert!(stage_source.contains("request.timeout_millis == 0"));
        assert!(stage_source.contains("request.request_id.trim().is_empty()"));

        let serialized = serde_json::to_value(VectorGenerationRebuildStatus {
            job_id: "job-a".into(),
            status: "completed".into(),
            snapshot_sequence: Some(11),
            caught_up_sequence: Some(11),
            promotion_sequence: Some(12),
            cancel_requested: false,
        })
        .unwrap();
        let fields = serialized.as_object().unwrap();
        assert_eq!(fields.len(), 6);
        for forbidden in [
            "generationId",
            "provider",
            "storePath",
            "descriptorHash",
            "apiKey",
        ] {
            assert!(!fields.contains_key(forbidden), "IPC leaked {forbidden}");
        }
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
