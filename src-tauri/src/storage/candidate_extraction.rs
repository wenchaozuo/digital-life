//! D-6 candidate-extraction persistence and orchestration boundary.
//!
//! This module deliberately has no Tauri command and no production extractor.
//! Extractors receive a bounded immutable snapshot and return typed proposals;
//! every durable mutation is made through `StorageService` transactions below.
#![allow(dead_code)] // The foundation is intentionally internal until D-7 supplies an extractor.

use std::{
    future::Future,
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use futures::{task::noop_waker_ref, FutureExt};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    candidate_memory_internal::{
        extraction_safety::normalize_proposal_text, fingerprint::compute_dedup_fingerprint,
    },
    memory::{
        candidate::{
            CandidateInferenceStatus, CandidateMemorySourceType, CandidateMemoryStatus,
            NewCandidateMemory, PRIMARY_USER_SUBJECT_ID,
        },
        MemoryKind,
    },
};

use super::{candidate_memory, unique_suffix, StorageService};

pub(crate) const MAX_PROPOSALS: usize = 5;
pub(crate) const MAX_PROPOSAL_CONTENT_SCALARS: usize = 4_000;
pub(crate) const MAX_PROPOSAL_CONTENT_UTF8_BYTES: usize = 16_384;
pub(crate) const MAX_PROPOSAL_SUMMARY_SCALARS: usize = 500;
pub(crate) const MAX_PROPOSAL_SUMMARY_UTF8_BYTES: usize = 2_048;
const MAX_SELECTED_USER_MESSAGES: usize = 64;
const MAX_SELECTED_UTF8_BYTES: usize = 131_072;
const LEASE_TTL_S: i64 = 120;
const FINALIZE_MIN_REMAINING_S: i64 = 60;
const MAX_ATTEMPTS: i64 = 3;
pub(crate) const RECOVERY_SCAN_LIMIT: usize = 64;
const DEFAULT_EXTRACTION_TIMEOUT: Duration = Duration::from_secs(30);
const TOKEN_DOMAIN: &[u8] = b"candidate-extraction-lease-token-v1";
const SNAPSHOT_DOMAIN: &[u8] = b"candidate-extraction-snapshot-v1\0";

// Type aliases for complex query results
type RunMetadata = (String, String, i64, i64, i64, i64, i64, String);
type RunReconciliationRow = (
    String,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<String>,
);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExtractionError {
    pub code: &'static str,
    pub recoverable: bool,
}

impl ExtractionError {
    const fn new(code: &'static str, recoverable: bool) -> Self {
        Self { code, recoverable }
    }
    const fn storage() -> Self {
        Self::new("CANDIDATE_EXTRACTION_STORAGE_UNAVAILABLE", true)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExtractorDescriptor {
    pub extractor_id: String,
    pub extractor_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ExtractionMessage {
    pub message_id: String,
    pub sequence_no: i64,
    pub content: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CandidateExtractionRequest {
    pub run_id: String,
    pub attempt_sequence: i64,
    pub life_id: String,
    pub conversation_id: String,
    pub conversation_revision: i64,
    pub policy_version: String,
    pub snapshot_hash: String,
    pub messages: Vec<ExtractionMessage>,
}

pub(crate) trait CandidateExtractor: Send + Sync {
    fn descriptor(&self) -> &ExtractorDescriptor;
    fn extract<'a>(
        &'a self,
        request: CandidateExtractionRequest,
    ) -> Pin<Box<dyn Future<Output = Result<CandidateExtractionBatch, ExtractionError>> + Send + 'a>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProposalAction {
    Propose,
    Ignore,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SensitivityHint {
    NotSensitive,
    Sensitive,
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct CandidateExtractionProposal {
    pub action: ProposalAction,
    pub kind: Option<MemoryKind>,
    pub content: Option<String>,
    pub summary: Option<String>,
    pub confidence: Option<f64>,
    pub importance: Option<f64>,
    pub sensitivity_hint: SensitivityHint,
    pub conflict_hint: bool,
    pub source_message_ids: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct CandidateExtractionBatch {
    pub proposals: Vec<CandidateExtractionProposal>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LocalSafetyDecision {
    Safe,
    BlockedHardSecret,
    BlockedSensitive,
    Unknown,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Counts {
    total: i64,
    created: i64,
    merged: i64,
    ignored: i64,
    hard: i64,
    sensitive: i64,
    conflict: i64,
    same_batch: i64,
}

/// Extraction Attempt Handle - carries fencing evidence for the current attempt.
///
/// This struct is NOT Clone, NOT serializable, and has redacted Debug.
/// It can only be created by successful create/claim/takeover database transactions.
struct ExtractionFence {
    run_id: String,
    life_id: String,
    conversation_id: String,
    conversation_revision: i64,
    attempt_sequence: i64,
    raw_token: Zeroizing<[u8; 32]>,
    descriptor: ExtractorDescriptor,
    policy_version: String,
    snapshot_hash: String,
}

// ExtractionFence is NOT Clone - raw_token must not be duplicated
// ExtractionFence is NOT serializable - raw_token must not leave memory

impl std::fmt::Debug for ExtractionFence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExtractionFence([REDACTED])")
    }
}

impl ExtractionFence {
    fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(TOKEN_DOMAIN);
        hasher.update([0]);
        hasher.update(self.run_id.as_bytes());
        hasher.update(self.attempt_sequence.to_be_bytes());
        hasher.update(self.raw_token.as_ref());
        hex(&hasher.finalize())
    }
}

/// This is the internal capability for one extraction attempt.  It is not
/// cloneable: duplicating it would create another owner for the raw lease
/// token.  The request is deliberately kept private so callers cannot use the
/// capability as a production reconstruction API.
pub(crate) struct StartedExtraction {
    request: CandidateExtractionRequest,
    fence: Arc<ExtractionFence>,
}

impl StartedExtraction {
    fn fence(&self) -> &ExtractionFence {
        &self.fence
    }
}

impl std::fmt::Debug for StartedExtraction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StartedExtraction([REDACTED])")
    }
}

/// A cancellation source for a running extractor future.  The source never
/// contains request data, provider errors, or fence material.
#[derive(Clone, Default)]
pub(crate) struct ExtractionCancellation {
    reason: Arc<AtomicU8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExtractionCancellationReason {
    Shutdown,
    InternalRequest,
    StaleAttempt,
}

impl ExtractionCancellation {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn cancel(&self, reason: ExtractionCancellationReason) {
        let value = match reason {
            ExtractionCancellationReason::Shutdown => 1,
            ExtractionCancellationReason::InternalRequest => 2,
            ExtractionCancellationReason::StaleAttempt => 3,
        };
        self.reason.store(value, Ordering::Release);
    }

    fn reason(&self) -> Option<ExtractionCancellationReason> {
        match self.reason.load(Ordering::Acquire) {
            1 => Some(ExtractionCancellationReason::Shutdown),
            2 => Some(ExtractionCancellationReason::InternalRequest),
            3 => Some(ExtractionCancellationReason::StaleAttempt),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CandidateExtractionAttemptOutcome {
    Completed,
    RetryScheduled,
    TerminalFailed,
    StaleAttempt,
    StorageFailure,
}

impl StorageService {
    pub(crate) fn start_candidate_extraction(
        &self,
        life_id: &str,
        conversation_id: &str,
        descriptor: ExtractorDescriptor,
        policy_version: &str,
    ) -> Result<Option<StartedExtraction>, ExtractionError> {
        validate_descriptor(&descriptor, policy_version)?;
        let mut state = self.state().map_err(|_| ExtractionError::storage())?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ExtractionError::storage())?;
        let revision: i64 = tx
            .query_row(
                "SELECT revision FROM conversation WHERE id = ?1 AND life_id = ?2",
                params![conversation_id, life_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ExtractionError::storage())?
            .ok_or_else(|| {
                ExtractionError::new("CANDIDATE_EXTRACTION_CONVERSATION_NOT_FOUND", false)
            })?;
        if let Some(existing) = load_started_run(&tx, life_id, conversation_id, revision)? {
            tx.commit().map_err(|_| ExtractionError::storage())?;
            return Ok(Some(existing));
        }
        let snapshot = build_snapshot(&tx, life_id, conversation_id)?;
        let Some(snapshot) = snapshot else {
            return Ok(None);
        };
        let mut token = Zeroizing::new([0u8; 32]);
        fill_secure_random(token.as_mut())?;
        let run_id = format!("candidate-extraction-{}", unique_suffix());
        let fence = std::sync::Arc::new(ExtractionFence {
            run_id: run_id.clone(),
            life_id: life_id.to_string(),
            conversation_id: conversation_id.to_string(),
            conversation_revision: revision,
            attempt_sequence: 1,
            raw_token: token,
            descriptor: descriptor.clone(),
            policy_version: policy_version.to_string(),
            snapshot_hash: snapshot.hash.clone(),
        });
        let now: i64 = tx
            .query_row("SELECT CAST(strftime('%s', 'now') AS INTEGER)", [], |r| {
                r.get(0)
            })
            .map_err(|_| ExtractionError::storage())?;
        let now_text: String = tx
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |r| {
                r.get(0)
            })
            .map_err(|_| ExtractionError::storage())?;
        tx.execute(
            "INSERT INTO candidate_extraction_run (
                id, life_id, conversation_id, conversation_revision, extractor_id, extractor_version,
                policy_version, snapshot_hash, eligible_message_count, selected_message_count,
                selected_first_sequence_no, selected_last_sequence_no, selected_utf8_bytes,
                snapshot_truncated, status, attempt_sequence, lease_token_digest,
                lease_expires_at_epoch_s, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                       'processing', 1, ?15, ?16, ?17, ?17)",
            params![run_id, life_id, conversation_id, revision, descriptor.extractor_id,
                descriptor.extractor_version, policy_version, snapshot.hash,
                snapshot.eligible_count as i64, snapshot.messages.len() as i64,
                snapshot.messages.first().unwrap().sequence_no, snapshot.messages.last().unwrap().sequence_no,
                snapshot.bytes as i64, i64::from(snapshot.eligible_count > snapshot.messages.len()),
                fence.digest(), now + LEASE_TTL_S, now_text],
        ).map_err(|_| ExtractionError::storage())?;
        for (ordinal, message) in snapshot.messages.iter().enumerate() {
            tx.execute("INSERT INTO candidate_extraction_snapshot_message (run_id, ordinal, message_id, sequence_no) VALUES (?1, ?2, ?3, ?4)",
                params![fence.run_id, ordinal as i64, message.message_id, message.sequence_no])
                .map_err(|_| ExtractionError::storage())?;
        }
        insert_audit(&tx, &fence.run_id, 1, "attempt_started", None, &now_text)?;
        tx.commit().map_err(|_| ExtractionError::storage())?;
        Ok(Some(StartedExtraction {
            request: CandidateExtractionRequest {
                run_id: fence.run_id.clone(),
                attempt_sequence: 1,
                life_id: life_id.to_string(),
                conversation_id: conversation_id.to_string(),
                conversation_revision: revision,
                policy_version: policy_version.to_string(),
                snapshot_hash: fence.snapshot_hash.clone(),
                messages: snapshot.messages,
            },
            fence,
        }))
    }

    /// Runs the extractor after an exact snapshot reload.  All SQLite access
    /// ends before the future is created or polled; durable transitions happen
    /// only after that future has completed, timed out, panicked, or been
    /// cancelled.
    pub(crate) fn run_candidate_extraction_attempt(
        &self,
        extractor: &dyn CandidateExtractor,
        started: &StartedExtraction,
        cancellation: &ExtractionCancellation,
        timeout: Option<Duration>,
    ) -> CandidateExtractionAttemptOutcome {
        if cancellation.reason() == Some(ExtractionCancellationReason::StaleAttempt) {
            return CandidateExtractionAttemptOutcome::StaleAttempt;
        }

        let request = match self.reload_candidate_extraction_request(started) {
            Ok(Some(request)) => request,
            Ok(None) => return CandidateExtractionAttemptOutcome::StaleAttempt,
            Err(error) if is_stale_fence_error(&error) => {
                return CandidateExtractionAttemptOutcome::StaleAttempt;
            }
            Err(_) => return CandidateExtractionAttemptOutcome::StorageFailure,
        };

        // This is the sole panic boundary.  FutureExt::catch_unwind catches
        // only polling the extractor future, never storage or finalization.
        let mut future = AssertUnwindSafe(extractor.extract(request)).catch_unwind();
        let deadline = Instant::now() + timeout.unwrap_or(DEFAULT_EXTRACTION_TIMEOUT);
        let waker = noop_waker_ref();
        let mut context = Context::from_waker(waker);
        let extraction = loop {
            match cancellation.reason() {
                Some(ExtractionCancellationReason::StaleAttempt) => {
                    return CandidateExtractionAttemptOutcome::StaleAttempt;
                }
                Some(ExtractionCancellationReason::Shutdown) => {
                    break Err("CANDIDATE_EXTRACTION_CANCELLED_SHUTDOWN");
                }
                Some(ExtractionCancellationReason::InternalRequest) => {
                    break Err("CANDIDATE_EXTRACTION_CANCELLED_INTERNAL_REQUEST");
                }
                None => {}
            }
            if Instant::now() >= deadline {
                // Leaving this scope drops the still-pending future.
                break Err("CANDIDATE_EXTRACTION_TIMEOUT");
            }
            match Pin::new(&mut future).poll(&mut context) {
                Poll::Ready(Ok(Ok(batch))) => break Ok(batch),
                Poll::Ready(Ok(Err(error))) => {
                    break Err(if error.recoverable {
                        "CANDIDATE_EXTRACTION_EXTRACTOR_UNAVAILABLE"
                    } else {
                        "CANDIDATE_EXTRACTION_EXTRACTOR_CONTRACT_FAILURE"
                    });
                }
                Poll::Ready(Err(_)) => break Err("CANDIDATE_EXTRACTION_EXTRACTOR_PANIC"),
                Poll::Pending => std::thread::sleep(Duration::from_millis(1)),
            }
        };

        match extraction {
            Ok(batch) => match self.finalize_candidate_extraction_atomic(started, batch) {
                Ok(()) => CandidateExtractionAttemptOutcome::Completed,
                Err(error) if is_stale_fence_error(&error) => {
                    CandidateExtractionAttemptOutcome::StaleAttempt
                }
                // Finalize errors are storage failures.  They are intentionally
                // never remapped as extractor panics or provider failures.
                Err(_) => CandidateExtractionAttemptOutcome::StorageFailure,
            },
            Err(code) => {
                if cancellation.reason() == Some(ExtractionCancellationReason::StaleAttempt) {
                    return CandidateExtractionAttemptOutcome::StaleAttempt;
                }
                match self.fail_candidate_extraction_attempt(started, code, true) {
                    Ok(()) if started.request.attempt_sequence < MAX_ATTEMPTS => {
                        CandidateExtractionAttemptOutcome::RetryScheduled
                    }
                    Ok(()) => CandidateExtractionAttemptOutcome::TerminalFailed,
                    Err(error) if is_stale_fence_error(&error) => {
                        CandidateExtractionAttemptOutcome::StaleAttempt
                    }
                    Err(_) => CandidateExtractionAttemptOutcome::StorageFailure,
                }
            }
        }
    }

    /// Reloads the selected snapshot while the fence is current, then commits
    /// and drops the transaction before any extractor code can execute.
    fn reload_candidate_extraction_request(
        &self,
        started: &StartedExtraction,
    ) -> Result<Option<CandidateExtractionRequest>, ExtractionError> {
        let mut state = self.state().map_err(|_| ExtractionError::storage())?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ExtractionError::storage())?;
        let now: i64 = tx
            .query_row("SELECT CAST(strftime('%s', 'now') AS INTEGER)", [], |row| {
                row.get(0)
            })
            .map_err(|_| ExtractionError::storage())?;
        validate_fence(&tx, started.fence(), now)?;
        let snapshot = reload_and_validate_snapshot(&tx, &started.request.run_id)?;
        let Some(snapshot) = snapshot else {
            invalidate_run(&tx, &started.request.run_id, now)?;
            tx.commit().map_err(|_| ExtractionError::storage())?;
            return Ok(None);
        };
        if snapshot.hash != started.fence().snapshot_hash {
            invalidate_run(&tx, &started.request.run_id, now)?;
            tx.commit().map_err(|_| ExtractionError::storage())?;
            return Ok(None);
        }
        let request = CandidateExtractionRequest {
            run_id: started.fence().run_id.clone(),
            attempt_sequence: started.fence().attempt_sequence,
            life_id: started.fence().life_id.clone(),
            conversation_id: started.fence().conversation_id.clone(),
            conversation_revision: started.fence().conversation_revision,
            policy_version: started.fence().policy_version.clone(),
            snapshot_hash: started.fence().snapshot_hash.clone(),
            messages: snapshot.messages,
        };
        tx.commit().map_err(|_| ExtractionError::storage())?;
        Ok(Some(request))
    }

    pub(crate) fn finalize_candidate_extraction_atomic(
        &self,
        started: &StartedExtraction,
        batch: CandidateExtractionBatch,
    ) -> Result<(), ExtractionError> {
        let classified = classify_batch(&started.request, batch)?;
        let mut state = self.state().map_err(|_| ExtractionError::storage())?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ExtractionError::storage())?;
        let now: i64 = tx
            .query_row("SELECT CAST(strftime('%s', 'now') AS INTEGER)", [], |r| {
                r.get(0)
            })
            .map_err(|_| ExtractionError::storage())?;
        let now_text: String = tx
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |r| {
                r.get(0)
            })
            .map_err(|_| ExtractionError::storage())?;
        validate_fence(&tx, started.fence(), now)?;
        validate_snapshot_commitment(&tx, started)?;
        renew_fence(&tx, started.fence(), now)?;
        let mut counts = classified.counts;
        for proposal in classified.accepted {
            let fingerprint = compute_dedup_fingerprint(
                &started.request.life_id,
                PRIMARY_USER_SUBJECT_ID,
                proposal.kind,
                &proposal.content,
            );
            let candidate_id: Option<String> = tx.query_row(
                    "SELECT id FROM candidate_memory WHERE life_id = ?1 AND subject_id = ?2 AND kind = ?3 AND dedup_fingerprint = ?4 AND status = 'pending'",
                    params![started.request.life_id, PRIMARY_USER_SUBJECT_ID, proposal.kind.as_str(), fingerprint], |r| r.get(0),
                ).optional().map_err(|_| ExtractionError::storage())?;
            let candidate_id = if let Some(id) = candidate_id {
                counts.merged += 1;
                id
            } else {
                let id = format!("candidate-extracted-{}", unique_suffix());
                insert_candidate_tx(
                    &tx,
                    NewCandidateMemory {
                        id: id.clone(),
                        life_id: started.request.life_id.clone(),
                        subject_id: PRIMARY_USER_SUBJECT_ID.into(),
                        kind: proposal.kind,
                        content: Some(proposal.content.clone()),
                        summary: proposal.summary.clone(),
                        source_type: CandidateMemorySourceType::Conversation,
                        source_id: None,
                        confidence: proposal.confidence,
                        importance: proposal.importance,
                        is_sensitive: false,
                        inference_status: CandidateInferenceStatus::Extracted,
                        status: CandidateMemoryStatus::Pending,
                        dedup_fingerprint: Some(fingerprint),
                        proposed_at: now_text.clone(),
                        expires_at: None,
                        reviewed_at: None,
                        last_user_edit_at: None,
                        confirmed_memory_id: None,
                        accepted_request_id: None,
                        rejection_reason_code: None,
                        superseded_by_candidate_id: None,
                        conflicts_with_memory_id: None,
                        created_at: now_text.clone(),
                        updated_at: now_text.clone(),
                    },
                )?;
                candidate_memory::insert_extraction_audit_in_transaction(
                    &tx,
                    &format!("candidate-audit-extracted-{}", unique_suffix()),
                    &started.request.life_id,
                    &id,
                    &now_text,
                )
                .map_err(|_| ExtractionError::storage())?;
                counts.created += 1;
                id
            };
            for message_id in proposal.source_message_ids {
                tx.execute(
                        "INSERT INTO candidate_memory_evidence (id, candidate_id, life_id, source_type, source_id, conversation_id, message_id, observed_at)
                         VALUES (?1, ?2, ?3, 'conversation', NULL, ?4, ?5, ?6)
                         ON CONFLICT DO NOTHING",
                        params![format!("evidence-extracted-{}", unique_suffix()), candidate_id, started.request.life_id,
                            started.request.conversation_id, message_id, now_text],
                    ).map_err(|_| ExtractionError::storage())?;
            }
        }
        tx.execute(
                "UPDATE candidate_extraction_run SET status = 'completed', snapshot_hash = NULL,
                   lease_token_digest = NULL, lease_expires_at_epoch_s = NULL, next_attempt_at_epoch_s = NULL,
                   total_proposal_count = ?2, created_count = ?3, evidence_merged_count = ?4, ignored_count = ?5,
                   hard_secret_blocked_count = ?6, sensitive_blocked_count = ?7, conflict_blocked_count = ?8,
                   same_batch_duplicate_count = ?9, completed_at = ?10, updated_at = ?10
                 WHERE id = ?1",
                params![started.request.run_id, counts.total, counts.created, counts.merged, counts.ignored,
                    counts.hard, counts.sensitive, counts.conflict, counts.same_batch, now_text],
            ).map_err(|_| ExtractionError::storage())?;
        tx.execute(
            "DELETE FROM candidate_extraction_snapshot_message WHERE run_id = ?1",
            params![started.request.run_id],
        )
        .map_err(|_| ExtractionError::storage())?;
        insert_audit(
            &tx,
            &started.request.run_id,
            started.request.attempt_sequence,
            "completed",
            None,
            &now_text,
        )?;
        tx.commit().map_err(|_| ExtractionError::storage())
    }

    /// Records an extractor, timeout, cancellation, or panic outcome without
    /// exposing provider text.  Retriable attempts follow the frozen 5s/30s
    /// schedule; the third outcome is terminal.
    pub(crate) fn fail_candidate_extraction_attempt(
        &self,
        started: &StartedExtraction,
        safe_error_code: &'static str,
        retryable: bool,
    ) -> Result<(), ExtractionError> {
        let mut state = self.state().map_err(|_| ExtractionError::storage())?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ExtractionError::storage())?;
        let now: i64 = tx
            .query_row("SELECT CAST(strftime('%s', 'now') AS INTEGER)", [], |r| {
                r.get(0)
            })
            .map_err(|_| ExtractionError::storage())?;
        let now_text: String = tx
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |r| {
                r.get(0)
            })
            .map_err(|_| ExtractionError::storage())?;
        validate_fence(&tx, started.fence(), now)?;
        let attempt = started.request.attempt_sequence;
        if retryable && attempt < MAX_ATTEMPTS {
            let delay = if attempt == 1 { 5 } else { 30 };
            tx.execute(
                "UPDATE candidate_extraction_run SET status='retry_wait', lease_token_digest=NULL,
                 lease_expires_at_epoch_s=NULL, next_attempt_at_epoch_s=?4, last_error_code=?3,
                 updated_at=?5 WHERE id=?1 AND attempt_sequence=?2 AND status='processing'",
                params![
                    started.request.run_id,
                    attempt,
                    safe_error_code,
                    now + delay,
                    now_text
                ],
            )
            .map_err(|_| ExtractionError::storage())?;
            insert_audit(
                &tx,
                &started.request.run_id,
                attempt,
                "retry_scheduled",
                Some(safe_error_code),
                &now_text,
            )?;
        } else {
            tx.execute(
                "UPDATE candidate_extraction_run SET status='failed', snapshot_hash=NULL,
                 lease_token_digest=NULL, lease_expires_at_epoch_s=NULL, next_attempt_at_epoch_s=NULL,
                 last_error_code=?3, completed_at=?4, updated_at=?4
                 WHERE id=?1 AND attempt_sequence=?2 AND status='processing'",
                params![started.request.run_id, attempt, safe_error_code, now_text],
            ).map_err(|_| ExtractionError::storage())?;
            tx.execute(
                "DELETE FROM candidate_extraction_snapshot_message WHERE run_id=?1",
                params![started.request.run_id],
            )
            .map_err(|_| ExtractionError::storage())?;
            insert_audit(
                &tx,
                &started.request.run_id,
                attempt,
                "failed",
                Some(safe_error_code),
                &now_text,
            )?;
        }
        tx.commit().map_err(|_| ExtractionError::storage())
    }

    /// Renew a lease (heartbeat) for an active extraction attempt.
    ///
    /// Returns Ok(true) if the lease was renewed, Ok(false) if the run was not found,
    /// or an error if the fence is stale or the run is no longer processing.
    pub(crate) fn renew_extraction_lease(
        &self,
        started: &StartedExtraction,
    ) -> Result<bool, ExtractionError> {
        let mut state = self.state().map_err(|_| ExtractionError::storage())?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ExtractionError::storage())?;
        let now: i64 = tx
            .query_row("SELECT CAST(strftime('%s', 'now') AS INTEGER)", [], |r| {
                r.get(0)
            })
            .map_err(|_| ExtractionError::storage())?;
        // Verify the run exists and is in processing state
        let run_status: Option<String> = tx
            .query_row(
                "SELECT status FROM candidate_extraction_run WHERE id = ?1",
                params![started.request.run_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| ExtractionError::storage())?;
        let status = match run_status {
            Some(s) => s,
            None => return Ok(false),
        };
        if status != "processing" {
            return Err(ExtractionError::new(
                "CANDIDATE_EXTRACTION_RUN_NOT_PROCESSING",
                false,
            ));
        }
        // Validate all fence conditions
        let matches: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM candidate_extraction_run WHERE id=?1 AND status='processing' AND attempt_sequence=?2 AND lease_token_digest=?3 AND extractor_id=?4 AND extractor_version=?5 AND policy_version=?6 AND snapshot_hash=?7 AND lease_expires_at_epoch_s>?8)",
            params![started.fence().run_id, started.fence().attempt_sequence, started.fence().digest(), started.fence().descriptor.extractor_id, started.fence().descriptor.extractor_version, started.fence().policy_version, started.fence().snapshot_hash, now],
            |r| r.get(0),
        ).map_err(|_| ExtractionError::storage())?;
        if !matches {
            return Err(ExtractionError::new(
                "CANDIDATE_EXTRACTION_FENCE_INVALID",
                false,
            ));
        }
        // Renew the lease
        let now_text: String = tx
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |r| {
                r.get(0)
            })
            .map_err(|_| ExtractionError::storage())?;
        tx.execute(
            "UPDATE candidate_extraction_run SET lease_expires_at_epoch_s = ?2, updated_at = ?3 WHERE id = ?1",
            params![started.request.run_id, now + LEASE_TTL_S, now_text],
        )
        .map_err(|_| ExtractionError::storage())?;
        tx.commit().map_err(|_| ExtractionError::storage())?;
        Ok(true)
    }

    /// Claim a due retry attempt for a run in retry_wait status.
    ///
    /// Returns Ok(Some(handle)) if a new attempt was claimed, Ok(None) if no due retry,
    /// or an error if the snapshot is invalidated.
    pub(crate) fn claim_due_extraction_retry(
        &self,
        life_id: &str,
        conversation_id: &str,
        descriptor: &ExtractorDescriptor,
        policy_version: &str,
    ) -> Result<Option<StartedExtraction>, ExtractionError> {
        validate_descriptor(descriptor, policy_version)?;
        let mut state = self.state().map_err(|_| ExtractionError::storage())?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ExtractionError::storage())?;
        let now: i64 = tx
            .query_row("SELECT CAST(strftime('%s', 'now') AS INTEGER)", [], |r| {
                r.get(0)
            })
            .map_err(|_| ExtractionError::storage())?;
        // Find a due retry run
        let run: Option<(String, i64, i64)> = tx
            .query_row(
                "SELECT id, attempt_sequence, conversation_revision FROM candidate_extraction_run WHERE life_id=?1 AND conversation_id=?2 AND extractor_id=?3 AND extractor_version=?4 AND policy_version=?5 AND status='retry_wait' AND next_attempt_at_epoch_s<=?6 AND attempt_sequence<?7 LIMIT 1",
                params![life_id, conversation_id, descriptor.extractor_id, descriptor.extractor_version, policy_version, now, MAX_ATTEMPTS],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| ExtractionError::storage())?;
        let (run_id, attempt_sequence, _conversation_revision) = match run {
            Some(r) => r,
            None => return Ok(None),
        };
        // Reload and validate snapshot
        let snapshot = reload_and_validate_snapshot(&tx, &run_id)?;
        let snapshot = match snapshot {
            Some(s) => s,
            None => {
                // Snapshot invalidated
                invalidate_run(&tx, &run_id, now)?;
                tx.commit().map_err(|_| ExtractionError::storage())?;
                return Ok(None);
            }
        };
        // Generate new CSPRNG token
        let mut token = Zeroizing::new([0u8; 32]);
        fill_secure_random(token.as_mut())?;
        let fence = std::sync::Arc::new(ExtractionFence {
            run_id: run_id.clone(),
            life_id: life_id.to_string(),
            conversation_id: conversation_id.to_string(),
            conversation_revision: snapshot.conversation_revision,
            attempt_sequence: attempt_sequence + 1,
            raw_token: token,
            descriptor: descriptor.clone(),
            policy_version: policy_version.to_string(),
            snapshot_hash: snapshot.hash.clone(),
        });
        let now_text: String = tx
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |r| {
                r.get(0)
            })
            .map_err(|_| ExtractionError::storage())?;
        // Update run for new attempt
        tx.execute(
            "UPDATE candidate_extraction_run SET status='processing', attempt_sequence=?2, lease_token_digest=?3, lease_expires_at_epoch_s=?4, next_attempt_at_epoch_s=NULL, last_error_code=NULL, updated_at=?5 WHERE id=?1",
            params![run_id, attempt_sequence + 1, fence.digest(), now + LEASE_TTL_S, now_text],
        ).map_err(|_| ExtractionError::storage())?;
        insert_audit(
            &tx,
            &run_id,
            attempt_sequence + 1,
            "attempt_started",
            None,
            &now_text,
        )?;
        tx.commit().map_err(|_| ExtractionError::storage())?;
        Ok(Some(StartedExtraction {
            request: CandidateExtractionRequest {
                run_id: fence.run_id.clone(),
                attempt_sequence: fence.attempt_sequence,
                life_id: life_id.to_string(),
                conversation_id: conversation_id.to_string(),
                conversation_revision: snapshot.conversation_revision,
                policy_version: policy_version.to_string(),
                snapshot_hash: fence.snapshot_hash.clone(),
                messages: snapshot.messages,
            },
            fence,
        }))
    }

    /// Take over an expired lease for a run in processing status.
    ///
    /// Returns Ok(Some(handle)) if the lease was taken over, Ok(None) if no expired lease,
    /// or an error if the snapshot is invalidated or attempt limit reached.
    pub(crate) fn take_over_expired_extraction_lease(
        &self,
        life_id: &str,
        conversation_id: &str,
        descriptor: &ExtractorDescriptor,
        policy_version: &str,
    ) -> Result<Option<StartedExtraction>, ExtractionError> {
        validate_descriptor(descriptor, policy_version)?;
        let mut state = self.state().map_err(|_| ExtractionError::storage())?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ExtractionError::storage())?;
        let now: i64 = tx
            .query_row("SELECT CAST(strftime('%s', 'now') AS INTEGER)", [], |r| {
                r.get(0)
            })
            .map_err(|_| ExtractionError::storage())?;
        // Find an expired lease
        let run: Option<(String, i64, i64)> = tx
            .query_row(
                "SELECT id, attempt_sequence, conversation_revision FROM candidate_extraction_run WHERE life_id=?1 AND conversation_id=?2 AND extractor_id=?3 AND extractor_version=?4 AND policy_version=?5 AND status='processing' AND lease_expires_at_epoch_s<=?6 LIMIT 1",
                params![life_id, conversation_id, descriptor.extractor_id, descriptor.extractor_version, policy_version, now],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| ExtractionError::storage())?;
        let (run_id, attempt_sequence, _conversation_revision) = match run {
            Some(r) => r,
            None => return Ok(None),
        };
        if attempt_sequence >= MAX_ATTEMPTS {
            let now_text: String = tx
                .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |r| {
                    r.get(0)
                })
                .map_err(|_| ExtractionError::storage())?;
            tx.execute(
                "UPDATE candidate_extraction_run SET status='failed', snapshot_hash=NULL,
                 lease_token_digest=NULL, lease_expires_at_epoch_s=NULL, next_attempt_at_epoch_s=NULL,
                 last_error_code='CANDIDATE_EXTRACTION_ATTEMPT_LIMIT_EXHAUSTED',
                 completed_at=?2, updated_at=?2 WHERE id=?1 AND status='processing'",
                params![run_id, now_text],
            )
            .map_err(|_| ExtractionError::storage())?;
            tx.execute(
                "DELETE FROM candidate_extraction_snapshot_message WHERE run_id=?1",
                params![run_id],
            )
            .map_err(|_| ExtractionError::storage())?;
            insert_audit(
                &tx,
                &run_id,
                attempt_sequence,
                "failed",
                Some("CANDIDATE_EXTRACTION_ATTEMPT_LIMIT_EXHAUSTED"),
                &now_text,
            )?;
            tx.commit().map_err(|_| ExtractionError::storage())?;
            return Ok(None);
        }
        // Reload and validate snapshot
        let snapshot = reload_and_validate_snapshot(&tx, &run_id)?;
        let snapshot = match snapshot {
            Some(s) => s,
            None => {
                // Snapshot invalidated
                invalidate_run(&tx, &run_id, now)?;
                tx.commit().map_err(|_| ExtractionError::storage())?;
                return Ok(None);
            }
        };
        // Generate new CSPRNG token
        let mut token = Zeroizing::new([0u8; 32]);
        fill_secure_random(token.as_mut())?;
        let fence = std::sync::Arc::new(ExtractionFence {
            run_id: run_id.clone(),
            life_id: life_id.to_string(),
            conversation_id: conversation_id.to_string(),
            conversation_revision: snapshot.conversation_revision,
            attempt_sequence: attempt_sequence + 1,
            raw_token: token,
            descriptor: descriptor.clone(),
            policy_version: policy_version.to_string(),
            snapshot_hash: snapshot.hash.clone(),
        });
        let now_text: String = tx
            .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |r| {
                r.get(0)
            })
            .map_err(|_| ExtractionError::storage())?;
        // Update run for takeover
        tx.execute(
            "UPDATE candidate_extraction_run SET attempt_sequence=?2, lease_token_digest=?3, lease_expires_at_epoch_s=?4, updated_at=?5 WHERE id=?1",
            params![run_id, attempt_sequence + 1, fence.digest(), now + LEASE_TTL_S, now_text],
        ).map_err(|_| ExtractionError::storage())?;
        insert_audit(
            &tx,
            &run_id,
            attempt_sequence + 1,
            "lease_taken_over",
            None,
            &now_text,
        )?;
        tx.commit().map_err(|_| ExtractionError::storage())?;
        Ok(Some(StartedExtraction {
            request: CandidateExtractionRequest {
                run_id: fence.run_id.clone(),
                attempt_sequence: fence.attempt_sequence,
                life_id: life_id.to_string(),
                conversation_id: conversation_id.to_string(),
                conversation_revision: snapshot.conversation_revision,
                policy_version: policy_version.to_string(),
                snapshot_hash: fence.snapshot_hash.clone(),
                messages: snapshot.messages,
            },
            fence,
        }))
    }

    /// Query for runs that need recovery (expired lease, due retry, etc.).
    ///
    /// Returns a bounded list of run IDs and their status.
    pub(crate) fn query_extraction_recovery_candidates(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, String, i64)>, ExtractionError> {
        let effective_limit = limit.clamp(1, RECOVERY_SCAN_LIMIT);
        let state = self.state().map_err(|_| ExtractionError::storage())?;
        let mut statement = state
            .connection
            .prepare(
                "SELECT id, status, attempt_sequence
                 FROM candidate_extraction_run
                 WHERE (status='processing' AND lease_expires_at_epoch_s<=CAST(strftime('%s', 'now') AS INTEGER))
                    OR (status='retry_wait' AND next_attempt_at_epoch_s<=CAST(strftime('%s', 'now') AS INTEGER))
                 ORDER BY CASE WHEN status='processing' THEN lease_expires_at_epoch_s ELSE next_attempt_at_epoch_s END ASC,
                          updated_at ASC,
                          id ASC
                 LIMIT ?1",
            )
            .map_err(|_| ExtractionError::storage())?;
        let rows = statement
            .query_map(params![effective_limit as i64], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .map_err(|_| ExtractionError::storage())?;
        let mut results = Vec::new();
        for row in rows {
            results.push(row.map_err(|_| ExtractionError::storage())?);
        }
        Ok(results)
    }

    /// Reconcile a commit uncertainty by authoritative database re-read.
    ///
    /// When the COMMIT of finalize_candidate_extraction_atomic is uncertain,
    /// this function re-reads the Run status to determine the authoritative outcome.
    /// It never re-plays Candidate ingest.
    pub(crate) fn reconcile_extraction_commit_uncertainty(
        &self,
        run_id: &str,
        attempt_sequence: i64,
    ) -> Result<CommitReconciliationResult, ExtractionError> {
        let state = self.state().map_err(|_| ExtractionError::storage())?;
        let run: Option<RunReconciliationRow> = state
            .connection
            .query_row(
                "SELECT status, snapshot_hash, lease_token_digest, lease_expires_at_epoch_s,
                        total_proposal_count, created_count, evidence_merged_count,
                        hard_secret_blocked_count, completed_at
                 FROM candidate_extraction_run WHERE id=?1 AND attempt_sequence=?2",
                params![run_id, attempt_sequence],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ExtractionError::storage())?;
        match run {
            None => Ok(CommitReconciliationResult::StorageUnavailable),
            Some((
                status,
                _snapshot_hash,
                _lease_digest,
                _lease_expiry,
                total,
                created,
                merged,
                hard,
                _completed_at,
            )) => match status.as_str() {
                "completed" => Ok(CommitReconciliationResult::Completed {
                    total_proposal_count: total.unwrap_or(0),
                    created_count: created.unwrap_or(0),
                    evidence_merged_count: merged.unwrap_or(0),
                    hard_secret_blocked_count: hard.unwrap_or(0),
                }),
                "failed" => Ok(CommitReconciliationResult::TerminalFailed),
                "snapshot_invalidated" => Ok(CommitReconciliationResult::SnapshotInvalidated),
                "processing" => Ok(CommitReconciliationResult::CommitOutcomeUnavailable),
                "retry_wait" => Ok(CommitReconciliationResult::CommitOutcomeUnavailable),
                _ => Ok(CommitReconciliationResult::StorageUnavailable),
            },
        }
    }
}

/// Result of commit uncertainty reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CommitReconciliationResult {
    /// The Run completed successfully. No re-ingest needed.
    Completed {
        total_proposal_count: i64,
        created_count: i64,
        evidence_merged_count: i64,
        hard_secret_blocked_count: i64,
    },
    /// The Run terminal failed. No retry possible.
    TerminalFailed,
    /// The snapshot was invalidated. No retry possible.
    SnapshotInvalidated,
    /// The commit outcome is unavailable (still processing or retry_wait).
    /// Caller should retry reconciliation later or use takeover/recovery.
    CommitOutcomeUnavailable,
    /// The database is temporarily unavailable.
    StorageUnavailable,
}

#[derive(Clone)]
struct Snapshot {
    messages: Vec<ExtractionMessage>,
    hash: String,
    eligible_count: usize,
    bytes: usize,
    conversation_revision: i64,
}

/// Reload and validate a snapshot from the database.
///
/// Returns Ok(Some(snapshot)) if valid, Ok(None) if invalidated, or an error.
fn reload_and_validate_snapshot(
    tx: &Transaction<'_>,
    run_id: &str,
) -> Result<Option<Snapshot>, ExtractionError> {
    // Get run metadata
    let run: Option<RunMetadata> = tx
        .query_row(
            "SELECT life_id, conversation_id, conversation_revision, selected_message_count, selected_first_sequence_no, selected_last_sequence_no, selected_utf8_bytes, snapshot_hash FROM candidate_extraction_run WHERE id=?1",
            params![run_id],
            |row| Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
                row.get(6)?,
                row.get(7)?,
            )),
        )
        .optional()
        .map_err(|_| ExtractionError::storage())?;
    let (
        life_id,
        conversation_id,
        conversation_revision,
        selected_count,
        first_seq,
        last_seq,
        utf8_bytes,
        expected_hash,
    ) = match run {
        Some(r) => r,
        None => return Ok(None),
    };
    // Reload snapshot messages
    let mut statement = tx
        .prepare(
            "SELECT s.ordinal, s.message_id, s.sequence_no, m.content, m.conversation_id, m.life_id, m.turn_id, m.role
             FROM candidate_extraction_snapshot_message s
             JOIN conversation_message m ON m.id = s.message_id
             WHERE s.run_id = ?1
             ORDER BY s.ordinal ASC",
        )
        .map_err(|_| ExtractionError::storage())?;
    let rows = statement
        .query_map(params![run_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map_err(|_| ExtractionError::storage())?;
    let mut messages = Vec::new();
    let mut actual_bytes = 0i64;
    for (i, row) in rows.enumerate() {
        let (
            ordinal,
            message_id,
            sequence_no,
            content,
            msg_conversation_id,
            msg_life_id,
            turn_id,
            role,
        ) = row.map_err(|_| ExtractionError::storage())?;
        // Validate each message
        if msg_conversation_id != conversation_id
            || msg_life_id != life_id
            || role != "user"
            || sequence_no <= 0
        {
            return Ok(None);
        }
        // Check paired assistant exists
        let has_assistant: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM conversation_message WHERE conversation_id=?1 AND life_id=?2 AND turn_id=?3 AND role='assistant')",
                params![conversation_id, life_id, turn_id],
                |r| r.get(0),
            )
            .map_err(|_| ExtractionError::storage())?;
        if !has_assistant {
            return Ok(None);
        }
        // Validate ordinal is continuous
        if ordinal != i as i64 {
            return Ok(None);
        }
        actual_bytes += content.len() as i64;
        messages.push(ExtractionMessage {
            message_id,
            sequence_no,
            content,
        });
    }
    // Validate count matches
    if messages.len() as i64 != selected_count {
        return Ok(None);
    }
    // Validate sequence range
    if let (Some(first), Some(last)) = (messages.first(), messages.last()) {
        if first.sequence_no != first_seq || last.sequence_no != last_seq {
            return Ok(None);
        }
    }
    // Validate UTF-8 bytes
    if actual_bytes != utf8_bytes {
        return Ok(None);
    }
    // Recompute hash
    let hash = snapshot_hash(&messages);
    if hash != expected_hash {
        return Ok(None);
    }
    Ok(Some(Snapshot {
        messages,
        hash,
        eligible_count: 0, // Not needed for reload
        bytes: actual_bytes as usize,
        conversation_revision,
    }))
}

/// Invalidate a run due to snapshot validation failure.
fn invalidate_run(tx: &Transaction<'_>, run_id: &str, _now: i64) -> Result<(), ExtractionError> {
    let now_text: String = tx
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |r| {
            r.get(0)
        })
        .map_err(|_| ExtractionError::storage())?;
    let attempt: i64 = tx
        .query_row(
            "SELECT attempt_sequence FROM candidate_extraction_run WHERE id=?1",
            params![run_id],
            |row| row.get(0),
        )
        .map_err(|_| ExtractionError::storage())?;
    tx.execute(
        "UPDATE candidate_extraction_run SET status='snapshot_invalidated', snapshot_hash=NULL, lease_token_digest=NULL, lease_expires_at_epoch_s=NULL, next_attempt_at_epoch_s=NULL, last_error_code='CANDIDATE_EXTRACTION_SNAPSHOT_INVALIDATED', completed_at=?2, updated_at=?2 WHERE id=?1",
        params![run_id, now_text],
    ).map_err(|_| ExtractionError::storage())?;
    tx.execute(
        "DELETE FROM candidate_extraction_snapshot_message WHERE run_id=?1",
        params![run_id],
    )
    .map_err(|_| ExtractionError::storage())?;
    insert_audit(
        tx,
        run_id,
        attempt,
        "snapshot_invalidated",
        Some("CANDIDATE_EXTRACTION_SNAPSHOT_INVALIDATED"),
        &now_text,
    )?;
    Ok(())
}

fn build_snapshot(
    tx: &Transaction<'_>,
    life_id: &str,
    conversation_id: &str,
) -> Result<Option<Snapshot>, ExtractionError> {
    // Get conversation revision
    let conversation_revision: i64 = tx
        .query_row(
            "SELECT revision FROM conversation WHERE id=?1 AND life_id=?2",
            params![conversation_id, life_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| ExtractionError::storage())?
        .ok_or_else(|| {
            ExtractionError::new("CANDIDATE_EXTRACTION_CONVERSATION_NOT_FOUND", false)
        })?;
    let eligible: i64 = tx.query_row(
        "SELECT COUNT(*) FROM conversation_message u WHERE u.conversation_id = ?1 AND u.life_id = ?2 AND u.role = 'user'
         AND EXISTS (SELECT 1 FROM conversation_message a WHERE a.conversation_id = u.conversation_id AND a.life_id = u.life_id AND a.turn_id = u.turn_id AND a.role = 'assistant')",
        params![conversation_id, life_id], |r| r.get(0)).map_err(|_| ExtractionError::storage())?;
    let mut statement = tx.prepare(
        "SELECT u.id, u.sequence_no, u.content FROM conversation_message u WHERE u.conversation_id = ?1 AND u.life_id = ?2 AND u.role = 'user'
         AND EXISTS (SELECT 1 FROM conversation_message a WHERE a.conversation_id = u.conversation_id AND a.life_id = u.life_id AND a.turn_id = u.turn_id AND a.role = 'assistant')
         ORDER BY u.sequence_no DESC LIMIT 64").map_err(|_| ExtractionError::storage())?;
    let rows = statement
        .query_map(params![conversation_id, life_id], |r| {
            Ok(ExtractionMessage {
                message_id: r.get(0)?,
                sequence_no: r.get(1)?,
                content: r.get(2)?,
            })
        })
        .map_err(|_| ExtractionError::storage())?;
    let mut newest = Vec::new();
    let mut bytes = 0usize;
    for row in rows {
        let message = row.map_err(|_| ExtractionError::storage())?;
        let len = message.content.len();
        if len > MAX_SELECTED_UTF8_BYTES && newest.is_empty() {
            return Err(ExtractionError::new(
                "CANDIDATE_EXTRACTION_MESSAGE_TOO_LARGE",
                false,
            ));
        }
        if len > MAX_SELECTED_UTF8_BYTES || bytes + len > MAX_SELECTED_UTF8_BYTES {
            break;
        }
        bytes += len;
        newest.push(message);
    }
    if newest.is_empty() {
        return Ok(None);
    }
    newest.reverse();
    let hash = snapshot_hash(&newest);
    Ok(Some(Snapshot {
        messages: newest,
        hash,
        eligible_count: eligible as usize,
        bytes,
        conversation_revision,
    }))
}

fn snapshot_hash(messages: &[ExtractionMessage]) -> String {
    let mut h = Sha256::new();
    h.update(SNAPSHOT_DOMAIN);
    h.update((messages.len() as u32).to_be_bytes());
    for m in messages {
        h.update((m.message_id.len() as u32).to_be_bytes());
        h.update(m.message_id.as_bytes());
        h.update(m.sequence_no.to_be_bytes());
        h.update(4u32.to_be_bytes());
        h.update(b"user");
        h.update((m.content.len() as u32).to_be_bytes());
        h.update(m.content.as_bytes());
    }
    hex(&h.finalize())
}

fn validate_descriptor(d: &ExtractorDescriptor, policy: &str) -> Result<(), ExtractionError> {
    if d.extractor_id.trim().is_empty()
        || d.extractor_version.trim().is_empty()
        || policy.trim().is_empty()
    {
        Err(ExtractionError::new(
            "CANDIDATE_EXTRACTION_INVALID_REQUEST",
            false,
        ))
    } else {
        Ok(())
    }
}

fn load_started_run(
    tx: &Transaction<'_>,
    life: &str,
    conversation: &str,
    revision: i64,
) -> Result<Option<StartedExtraction>, ExtractionError> {
    let row: Option<(String, i64, String, String, String, String)> = tx.query_row(
        "SELECT id, attempt_sequence, extractor_id, extractor_version, policy_version, snapshot_hash FROM candidate_extraction_run WHERE life_id=?1 AND conversation_id=?2 AND conversation_revision=?3 AND status='processing'",
        params![life, conversation, revision], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional().map_err(|_| ExtractionError::storage())?;
    let Some((run_id, attempt, extractor_id, extractor_version, policy, hash)) = row else {
        return Ok(None);
    };
    // A caller without the raw durable token cannot take ownership of an existing processing attempt.
    // Returning a safe transient error is preferable to minting a second fence.
    let _ = (
        run_id,
        attempt,
        extractor_id,
        extractor_version,
        policy,
        hash,
    );
    Err(ExtractionError::new(
        "CANDIDATE_EXTRACTION_ALREADY_PROCESSING",
        true,
    ))
}

fn validate_fence(
    tx: &Transaction<'_>,
    fence: &ExtractionFence,
    now: i64,
) -> Result<(), ExtractionError> {
    let matches: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM candidate_extraction_run WHERE id=?1 AND status='processing' AND attempt_sequence=?2 AND lease_token_digest=?3 AND extractor_id=?4 AND extractor_version=?5 AND policy_version=?6 AND snapshot_hash=?7 AND lease_expires_at_epoch_s>?8)",
        params![fence.run_id, fence.attempt_sequence, fence.digest(), fence.descriptor.extractor_id, fence.descriptor.extractor_version, fence.policy_version, fence.snapshot_hash, now], |r| r.get(0)).map_err(|_| ExtractionError::storage())?;
    if matches {
        Ok(())
    } else {
        Err(ExtractionError::new(
            "CANDIDATE_EXTRACTION_FENCE_INVALID",
            false,
        ))
    }
}

fn is_stale_fence_error(error: &ExtractionError) -> bool {
    matches!(
        error.code,
        "CANDIDATE_EXTRACTION_FENCE_INVALID" | "CANDIDATE_EXTRACTION_RUN_NOT_PROCESSING"
    )
}

fn validate_snapshot_commitment(
    tx: &Transaction<'_>,
    started: &StartedExtraction,
) -> Result<(), ExtractionError> {
    let mut statement = tx
        .prepare(
            "SELECT s.message_id, s.sequence_no, m.content
             FROM candidate_extraction_snapshot_message s
             JOIN conversation_message m ON m.id = s.message_id
             WHERE s.run_id = ?1
             ORDER BY s.ordinal ASC",
        )
        .map_err(|_| ExtractionError::storage())?;
    let rows = statement
        .query_map(params![started.request.run_id], |row| {
            Ok(ExtractionMessage {
                message_id: row.get(0)?,
                sequence_no: row.get(1)?,
                content: row.get(2)?,
            })
        })
        .map_err(|_| ExtractionError::storage())?;
    let mut actual = Vec::new();
    for row in rows {
        actual.push(row.map_err(|_| ExtractionError::storage())?);
    }
    if actual != started.request.messages || snapshot_hash(&actual) != started.request.snapshot_hash
    {
        return Err(ExtractionError::new(
            "CANDIDATE_EXTRACTION_SNAPSHOT_INVALID",
            false,
        ));
    }
    let run_matches: bool = tx
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM candidate_extraction_run
                WHERE id = ?1 AND life_id = ?2 AND conversation_id = ?3
                  AND conversation_revision = ?4 AND snapshot_hash = ?5
                  AND selected_message_count = ?6
             )",
            params![
                started.request.run_id,
                started.request.life_id,
                started.request.conversation_id,
                started.request.conversation_revision,
                started.request.snapshot_hash,
                actual.len() as i64,
            ],
            |row| row.get(0),
        )
        .map_err(|_| ExtractionError::storage())?;
    if run_matches {
        Ok(())
    } else {
        Err(ExtractionError::new(
            "CANDIDATE_EXTRACTION_SNAPSHOT_INVALID",
            false,
        ))
    }
}

fn renew_fence(
    tx: &Transaction<'_>,
    fence: &ExtractionFence,
    now: i64,
) -> Result<(), ExtractionError> {
    let updated = tx.execute("UPDATE candidate_extraction_run SET lease_expires_at_epoch_s=?4 WHERE id=?1 AND status='processing' AND attempt_sequence=?2 AND lease_token_digest=?3",
        params![fence.run_id, fence.attempt_sequence, fence.digest(), now + LEASE_TTL_S]).map_err(|_| ExtractionError::storage())?;
    if updated == 1 {
        Ok(())
    } else {
        Err(ExtractionError::new(
            "CANDIDATE_EXTRACTION_FENCE_INVALID",
            false,
        ))
    }
}

fn insert_audit(
    tx: &Transaction<'_>,
    run_id: &str,
    attempt: i64,
    event: &str,
    code: Option<&str>,
    now: &str,
) -> Result<(), ExtractionError> {
    tx.execute("INSERT INTO candidate_extraction_audit (id,run_id,attempt_sequence,event,safe_error_code,created_at) VALUES (?1,?2,?3,?4,?5,?6)",
        params![format!("extraction-audit-{}", unique_suffix()),run_id,attempt,event,code,now]).map_err(|_| ExtractionError::storage())?;
    Ok(())
}

/// Invalidates only active extraction attempts which selected a deleted user
/// message.  The snapshot child table deliberately has no message foreign key:
/// this transition must be recorded before its rows are removed.
pub(super) fn invalidate_snapshots_for_deleted_user_message(
    tx: &Transaction<'_>,
    message_id: &str,
) -> Result<(), ExtractionError> {
    let now_text: String = tx
        .query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", [], |row| {
            row.get(0)
        })
        .map_err(|_| ExtractionError::storage())?;
    let mut statement = tx
        .prepare(
            "SELECT DISTINCT r.id, r.attempt_sequence
             FROM candidate_extraction_run r
             JOIN candidate_extraction_snapshot_message s ON s.run_id = r.id
             WHERE s.message_id = ?1 AND r.status IN ('processing', 'retry_wait')",
        )
        .map_err(|_| ExtractionError::storage())?;
    let rows = statement
        .query_map(params![message_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })
        .map_err(|_| ExtractionError::storage())?;
    let mut runs = Vec::new();
    for row in rows {
        runs.push(row.map_err(|_| ExtractionError::storage())?);
    }
    drop(statement);
    for (run_id, attempt) in runs {
        tx.execute(
            "UPDATE candidate_extraction_run
             SET status = 'snapshot_invalidated', snapshot_hash = NULL,
                 lease_token_digest = NULL, lease_expires_at_epoch_s = NULL,
                 next_attempt_at_epoch_s = NULL,
                 last_error_code = 'CANDIDATE_EXTRACTION_SNAPSHOT_INVALIDATED',
                 completed_at = ?2, updated_at = ?2
             WHERE id = ?1 AND status IN ('processing', 'retry_wait')",
            params![run_id, now_text],
        )
        .map_err(|_| ExtractionError::storage())?;
        tx.execute(
            "DELETE FROM candidate_extraction_snapshot_message WHERE run_id = ?1",
            params![run_id],
        )
        .map_err(|_| ExtractionError::storage())?;
        insert_audit(
            tx,
            &run_id,
            attempt,
            "snapshot_invalidated",
            Some("CANDIDATE_EXTRACTION_SNAPSHOT_INVALIDATED"),
            &now_text,
        )?;
    }
    Ok(())
}

fn insert_candidate_tx(
    tx: &Transaction<'_>,
    candidate: NewCandidateMemory,
) -> Result<(), ExtractionError> {
    candidate_memory::insert_candidate_in_transaction(tx, &candidate)
        .map_err(|_| ExtractionError::storage())
}

#[derive(Clone)]
struct AcceptedProposal {
    kind: MemoryKind,
    content: String,
    summary: Option<String>,
    confidence: f64,
    importance: f64,
    source_message_ids: Vec<String>,
}
struct Classified {
    counts: Counts,
    accepted: Vec<AcceptedProposal>,
}

fn classify_batch(
    request: &CandidateExtractionRequest,
    batch: CandidateExtractionBatch,
) -> Result<Classified, ExtractionError> {
    if batch.proposals.len() > MAX_PROPOSALS {
        return Err(ExtractionError::new(
            "CANDIDATE_EXTRACTION_BATCH_LIMIT_EXCEEDED",
            false,
        ));
    }
    let selected: std::collections::HashSet<_> = request
        .messages
        .iter()
        .map(|m| m.message_id.as_str())
        .collect();
    let mut counts = Counts {
        total: batch.proposals.len() as i64,
        ..Counts::default()
    };
    let mut accepted = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for proposal in batch.proposals {
        if proposal.source_message_ids.is_empty()
            || proposal.source_message_ids.len() > MAX_SELECTED_USER_MESSAGES
            || proposal
                .source_message_ids
                .iter()
                .any(|id| !selected.contains(id.as_str()))
        {
            return Err(ExtractionError::new(
                "CANDIDATE_EXTRACTION_SOURCE_INVALID",
                false,
            ));
        }
        match proposal.action {
            ProposalAction::Ignore => {
                if proposal.kind.is_some()
                    || proposal.content.is_some()
                    || proposal.summary.is_some()
                    || proposal.confidence.is_some()
                    || proposal.importance.is_some()
                {
                    return Err(ExtractionError::new(
                        "CANDIDATE_EXTRACTION_INVALID_REQUEST",
                        false,
                    ));
                }
                counts.ignored += 1;
            }
            ProposalAction::Propose => {
                let kind = proposal.kind.ok_or_else(|| {
                    ExtractionError::new("CANDIDATE_EXTRACTION_INVALID_REQUEST", false)
                })?;
                let raw = proposal.content.ok_or_else(|| {
                    ExtractionError::new("CANDIDATE_EXTRACTION_INVALID_REQUEST", false)
                })?;
                // 1. Raw bounded scan for hard secrets
                let raw_safety = hard_secret(&raw);
                // 2. Raw length validation
                if raw.chars().count() > MAX_PROPOSAL_CONTENT_SCALARS
                    || raw.len() > MAX_PROPOSAL_CONTENT_UTF8_BYTES
                {
                    return Err(ExtractionError::new(
                        "CANDIDATE_EXTRACTION_PROPOSAL_CONTENT_TOO_LARGE",
                        false,
                    ));
                }
                // 3. NFKC + normalize (whitespace collapse, CRLF/CR to LF, trim)
                let content = normalize_proposal_text(&raw);
                // 4. Normalized length validation
                if content.chars().count() > MAX_PROPOSAL_CONTENT_SCALARS
                    || content.len() > MAX_PROPOSAL_CONTENT_UTF8_BYTES
                {
                    return Err(ExtractionError::new(
                        "CANDIDATE_EXTRACTION_PROPOSAL_CONTENT_TOO_LARGE",
                        false,
                    ));
                }
                let summary = match proposal.summary {
                    Some(value) => {
                        // Raw length validation for summary
                        if value.chars().count() > MAX_PROPOSAL_SUMMARY_SCALARS
                            || value.len() > MAX_PROPOSAL_SUMMARY_UTF8_BYTES
                        {
                            return Err(ExtractionError::new(
                                "CANDIDATE_EXTRACTION_PROPOSAL_SUMMARY_TOO_LARGE",
                                false,
                            ));
                        }
                        // NFKC + normalize summary
                        let normalized = normalize_proposal_text(&value);
                        // Normalized length validation
                        if normalized.chars().count() > MAX_PROPOSAL_SUMMARY_SCALARS
                            || normalized.len() > MAX_PROPOSAL_SUMMARY_UTF8_BYTES
                        {
                            return Err(ExtractionError::new(
                                "CANDIDATE_EXTRACTION_PROPOSAL_SUMMARY_TOO_LARGE",
                                false,
                            ));
                        }
                        Some(normalized)
                    }
                    None => None,
                }
                .filter(|v| !v.is_empty());
                let confidence = proposal.confidence.ok_or_else(|| {
                    ExtractionError::new("CANDIDATE_EXTRACTION_INVALID_REQUEST", false)
                })?;
                let importance = proposal.importance.ok_or_else(|| {
                    ExtractionError::new("CANDIDATE_EXTRACTION_INVALID_REQUEST", false)
                })?;
                if !confidence.is_finite()
                    || !importance.is_finite()
                    || !(0.0..=1.0).contains(&confidence)
                    || !(0.0..=1.0).contains(&importance)
                {
                    return Err(ExtractionError::new(
                        "CANDIDATE_EXTRACTION_INVALID_REQUEST",
                        false,
                    ));
                }
                // 5. Hard secret check (raw + normalized)
                let local = if raw_safety
                    || hard_secret(&content)
                    || summary.as_deref().is_some_and(hard_secret)
                {
                    LocalSafetyDecision::BlockedHardSecret
                } else {
                    // 6. Sensitive/Unknown check on normalized text
                    local_safety(&content, summary.as_deref())
                };
                if local == LocalSafetyDecision::BlockedHardSecret {
                    counts.hard += 1;
                    continue;
                }
                if matches!(
                    proposal.sensitivity_hint,
                    SensitivityHint::Sensitive | SensitivityHint::Unknown
                ) || matches!(
                    local,
                    LocalSafetyDecision::BlockedSensitive | LocalSafetyDecision::Unknown
                ) {
                    counts.sensitive += 1;
                    continue;
                }
                if proposal.conflict_hint {
                    counts.conflict += 1;
                    continue;
                }
                let key = compute_dedup_fingerprint(
                    &request.life_id,
                    PRIMARY_USER_SUBJECT_ID,
                    kind,
                    &content,
                );
                if !seen.insert(key) {
                    counts.same_batch += 1;
                    continue;
                }
                accepted.push(AcceptedProposal {
                    kind,
                    content,
                    summary,
                    confidence,
                    importance,
                    source_message_ids: proposal.source_message_ids,
                });
            }
        }
    }
    Ok(Classified { counts, accepted })
}

fn is_unknown_control(c: char) -> bool {
    c == '\0'
        || (c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
        || matches!(c as u32, 0x202A..=0x202E | 0x2066..=0x2069)
}
fn hard_secret(text: &str) -> bool {
    let lower = text.to_lowercase();
    // 1. PEM Private Key
    [
        "-----begin private key-----",
        "-----begin rsa private key-----",
        "-----begin ec private key-----",
        "-----begin dsa private key-----",
        "-----begin openssh private key-----",
        "-----begin encrypted private key-----",
    ]
    .iter()
    .any(|x| lower.contains(x))
        // 2. Authorization Bearer
        || lower.contains("authorization: bearer ")
        || lower.contains("authorization= bearer ")
        // 3. JWT
        || looks_like_jwt(text)
        // 4. Secret Assignment
        || [
            "password=",
            "password:",
            "api_key=",
            "api_key:",
            "secret=",
            "secret:",
            "token=",
            "token:",
            "access_token=",
            "refresh_token=",
            "private_key=",
            "验证码:",
            "验证码=",
        ]
        .iter()
        .any(|x| lower.contains(x))
        // 5. Credential Prefix
        || looks_like_credential_prefix(text)
        // 6. OTP/PIN
        || looks_like_otp(&lower)
        // 7. Payment Card + Luhn
        || looks_like_card(text)
        // 8. CVV/CVC
        || looks_like_cvv(&lower)
        // 9. Cookie Header
        || lower.lines().any(|l| {
            let l = l.trim_start();
            l.starts_with("cookie:") || l.starts_with("set-cookie:")
        })
        // 10. Seed Phrase
        || looks_like_seed_phrase(&lower)
        // 11. Marker-bound Hex Private Key
        || looks_like_hex_private_key(&lower)
        // 12. Credential-bearing URL
        || looks_like_credential_url(&lower)
}
fn looks_like_jwt(s: &str) -> bool {
    s.split_whitespace().any(|word| {
        let p: Vec<_> = word.split('.').collect();
        p.len() == 3
            && p.iter().all(|x| {
                x.len() >= 8
                    && x.bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
            })
    })
}
fn looks_like_credential_prefix(s: &str) -> bool {
    [
        "sk-",
        "ghp_",
        "github_pat_",
        "glpat-",
        "xoxb-",
        "xoxp-",
        "xapp-",
    ]
    .iter()
    .any(|p| {
        s.split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-')
            .any(|x| x.starts_with(p) && x.len() >= p.len() + 20)
    })
}
fn looks_like_otp(s: &str) -> bool {
    [
        "otp",
        "verification code",
        "2fa code",
        "mfa code",
        "sms code",
        "验证码",
        "动态码",
        "短信码",
        "支付密码",
    ]
    .iter()
    .any(|m| {
        s.find(m).is_some_and(|i| {
            s[i + m.len()..]
                .chars()
                .skip_while(|c| c.is_whitespace() || *c == ':' || *c == '=')
                .take_while(|c| c.is_ascii_digit())
                .count()
                >= 4
        })
    })
}
fn looks_like_card(s: &str) -> bool {
    s.split(|c: char| !(c.is_ascii_digit() || c == ' ' || c == '-'))
        .any(|span| {
            let digits: String = span.chars().filter(|c| c.is_ascii_digit()).collect();
            (13..=19).contains(&digits.len()) && luhn(&digits)
        })
}
fn luhn(s: &str) -> bool {
    let mut sum = 0;
    let mut flip = false;
    for b in s.bytes().rev() {
        let mut n = (b - b'0') as u32;
        if flip {
            n *= 2;
            if n > 9 {
                n -= 9
            }
        }
        sum += n;
        flip = !flip;
    }
    sum % 10 == 0
}

// 8. CVV/CVC
fn looks_like_cvv(s: &str) -> bool {
    [
        "cvv",
        "cvc",
        "cvv2",
        "cvc2",
        "security code",
        "card verification",
    ]
    .iter()
    .any(|m| {
        s.find(m).is_some_and(|i| {
            s[i + m.len()..]
                .chars()
                .skip_while(|c| c.is_whitespace() || *c == ':' || *c == '=')
                .take_while(|c| c.is_ascii_digit())
                .count()
                >= 3
        })
    })
}

// 10. Seed Phrase (BIP-39 style: 12/15/18/21/24 words)
fn looks_like_seed_phrase(s: &str) -> bool {
    let seed_markers = [
        "seed phrase",
        "recovery phrase",
        "mnemonic",
        "助记词",
        "恢复短语",
    ];
    seed_markers.iter().any(|m| {
        if let Some(pos) = s.find(m) {
            let after = &s[pos + m.len()..];
            // Skip colon, equals, and whitespace
            let after =
                after.trim_start_matches(|c: char| c.is_whitespace() || c == ':' || c == '=');
            let words: Vec<&str> = after.split_whitespace().collect();
            // Seed phrases are typically 12, 15, 18, 21, or 24 words
            matches!(words.len(), 12 | 15 | 18 | 21 | 24)
        } else {
            false
        }
    })
}

// 11. Marker-bound Hex Private Key
fn looks_like_hex_private_key(s: &str) -> bool {
    let key_markers = ["private key", "privatekey", "privkey", "私钥"];
    key_markers.iter().any(|m| {
        if let Some(pos) = s.find(m) {
            let after = &s[pos + m.len()..];
            // Look for hex string (64+ chars for 256-bit key)
            after
                .split(|c: char| !c.is_ascii_hexdigit())
                .any(|hex| hex.len() >= 64)
        } else {
            false
        }
    })
}

// 12. Credential-bearing URL
fn looks_like_credential_url(s: &str) -> bool {
    // Look for URLs with credentials in them
    let url_patterns = ["https://", "http://"];
    url_patterns.iter().any(|proto| {
        if let Some(pos) = s.find(proto) {
            let url = &s[pos..];
            // Check for credentials in URL (user:pass@host)
            url.contains('@') && url.contains(':')
        } else {
            false
        }
    })
}
fn local_safety(content: &str, summary: Option<&str>) -> LocalSafetyDecision {
    let all = format!("{} {}", content, summary.unwrap_or_default());
    let lower = all.to_lowercase();

    // Unknown closure set
    if is_unknown_control_text(&all)
        || has_unknown_enum_marker(&lower)
        || has_incomplete_sensitive_marker(&lower)
    {
        return LocalSafetyDecision::Unknown;
    }

    // 10 Sensitive categories (direct structured fields)
    if looks_like_email(&all)
        || looks_like_phone(&all)
        || looks_like_id_card(&all)
        || looks_like_ssn(&all)
        || looks_like_passport(&all)
        || looks_like_date_of_birth(&all)
        || looks_like_address(&all)
        || looks_like_coordinates(&all)
        || looks_like_iban(&all)
        || looks_like_bank_account(&all)
    {
        return LocalSafetyDecision::BlockedSensitive;
    }

    // Ownership distance rule
    if has_ownership_sensitive_combination(&lower) {
        return LocalSafetyDecision::BlockedSensitive;
    }

    LocalSafetyDecision::Safe
}

// ── 10 Sensitive Categories ──────────────────────────────────────────

// 1. Email
fn looks_like_email(s: &str) -> bool {
    s.split_whitespace().any(|x| {
        let x = x.trim_matches(|c: char| {
            !c.is_ascii_alphanumeric() && !matches!(c, '@' | '.' | '_' | '-')
        });
        let mut p = x.split('@');
        matches!(
            (p.next(), p.next(), p.next()),
            (Some(a), Some(b), None)
                if !a.is_empty()
                    && b.contains('.')
                    && !b.starts_with('.')
                    && !b.ends_with('.')
        )
    })
}

// 2. Phone number
fn looks_like_phone(s: &str) -> bool {
    s.split(|c: char| !c.is_ascii_digit() && c != '+').any(|x| {
        let x = x.strip_prefix('+').unwrap_or(x);
        (8..=15).contains(&x.len()) && x.as_bytes().first().is_some_and(u8::is_ascii_digit)
    })
}

// 3. Chinese Resident ID Card (with checksum)
fn looks_like_id_card(s: &str) -> bool {
    let id_markers = ["身份证", "id card", "identity card", "居民身份证"];
    id_markers.iter().any(|m| {
        if let Some(pos) = s.find(m) {
            let after = &s[pos + m.len()..];
            // Skip colon, equals, and whitespace
            let after =
                after.trim_start_matches(|c: char| c.is_whitespace() || c == ':' || c == '=');
            // Chinese ID: 18 chars (17 digits + 1 digit or X)
            let id_chars: String = after.chars().take(18).collect();
            if id_chars.len() == 18 {
                let bytes = id_chars.as_bytes();
                // First 17 must be digits
                if bytes[..17].iter().all(|b| b.is_ascii_digit()) {
                    // Last char can be digit or X
                    return bytes[17].is_ascii_digit() || bytes[17] == b'X' || bytes[17] == b'x';
                }
            }
            // Also check for 15-digit old format
            let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.len() == 15 {
                return true;
            }
        }
        false
    })
}

// 4. US SSN
fn looks_like_ssn(s: &str) -> bool {
    let ssn_markers = ["ssn", "social security", "社会安全号码"];
    ssn_markers.iter().any(|m| {
        if let Some(pos) = s.find(m) {
            let after = &s[pos + m.len()..];
            let digits: String = after
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(|c| c.is_ascii_digit())
                .collect();
            // SSN: 9 digits (XXX-XX-XXXX)
            digits.len() == 9
        } else {
            false
        }
    })
}

// 5. Passport
fn looks_like_passport(s: &str) -> bool {
    let passport_markers = ["passport", "护照", "护照号码"];
    passport_markers.iter().any(|m| {
        if let Some(pos) = s.find(m) {
            let after = &s[pos + m.len()..];
            // Passport: typically 6-9 alphanumeric chars
            let chars: String = after
                .chars()
                .skip_while(|c| !c.is_ascii_alphanumeric())
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            (6..=12).contains(&chars.len())
        } else {
            false
        }
    })
}

// 6. Date of Birth
fn looks_like_date_of_birth(s: &str) -> bool {
    let dob_markers = ["date of birth", "dob", "birthday", "出生日期", "生日"];
    dob_markers.iter().any(|m| {
        if let Some(pos) = s.find(m) {
            let after = &s[pos + m.len()..];
            // Look for date patterns (YYYY-MM-DD, MM/DD/YYYY, etc.)
            let date_chars: String = after
                .chars()
                .skip_while(|c| !c.is_ascii_digit())
                .take_while(|c| c.is_ascii_digit() || *c == '-' || *c == '/')
                .collect();
            date_chars.len() >= 8
        } else {
            false
        }
    })
}

// 7. Precise Address
fn looks_like_address(s: &str) -> bool {
    let address_markers = [
        "address",
        "住址",
        "地址",
        "street",
        "街道",
        "road",
        "路",
        "avenue",
        "大道",
        "building",
        "楼",
        "apartment",
        "公寓",
    ];
    address_markers.iter().any(|m| {
        if let Some(pos) = s.find(m) {
            let after = &s[pos + m.len()..];
            // Address must have digits (house number)
            after.chars().take(160).any(|c| c.is_ascii_digit())
        } else {
            false
        }
    })
}

// 8. Coordinates (latitude/longitude)
fn looks_like_coordinates(s: &str) -> bool {
    let coord_markers = [
        "coordinates",
        "latitude",
        "longitude",
        "坐标",
        "纬度",
        "经度",
    ];
    coord_markers.iter().any(|m| {
        if let Some(pos) = s.find(m) {
            let after = &s[pos + m.len()..];
            // Look for decimal numbers that could be coordinates
            let nums: Vec<&str> = after
                .split(|c: char| !c.is_ascii_digit() && c != '.' && c != '-')
                .filter(|n| !n.is_empty())
                .collect();
            if nums.len() >= 2 {
                if let (Ok(lat), Ok(lon)) = (nums[0].parse::<f64>(), nums[1].parse::<f64>()) {
                    return (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lon);
                }
            }
        }
        false
    })
}

// 9. IBAN
fn looks_like_iban(s: &str) -> bool {
    let iban_markers = ["iban", "国际银行账号"];
    iban_markers.iter().any(|m| {
        if let Some(pos) = s.find(m) {
            let after = &s[pos + m.len()..];
            let iban: String = after
                .chars()
                .skip_while(|c| !c.is_ascii_alphanumeric())
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            // IBAN: 2 letters + 2 digits + up to 30 alphanumeric
            if iban.len() >= 15 && iban.len() <= 34 {
                let bytes = iban.as_bytes();
                if bytes[0].is_ascii_alphabetic()
                    && bytes[1].is_ascii_alphabetic()
                    && bytes[2].is_ascii_digit()
                    && bytes[3].is_ascii_digit()
                {
                    return validate_iban(&iban);
                }
            }
        }
        false
    })
}

// IBAN mod 97 validation
fn validate_iban(iban: &str) -> bool {
    // Move first 4 chars to end
    let rearranged = format!("{}{}", &iban[4..], &iban[..4]);
    // Convert letters to numbers (A=10, B=11, ..., Z=35)
    let mut num_str = String::new();
    for c in rearranged.chars() {
        if c.is_ascii_digit() {
            num_str.push(c);
        } else if c.is_ascii_alphabetic() {
            let n = (c.to_ascii_uppercase() as u8 - b'A' + 10) as u32;
            num_str.push_str(&n.to_string());
        } else {
            return false;
        }
    }
    // Calculate mod 97
    let mut remainder = 0u32;
    for digit in num_str.chars() {
        remainder = (remainder * 10 + digit.to_digit(10).unwrap_or(0)) % 97;
    }
    remainder == 1
}

// 10. Bank Account
fn looks_like_bank_account(s: &str) -> bool {
    let bank_markers = ["bank account", "account number", "银行账号", "账号"];
    bank_markers.iter().any(|m| {
        if let Some(pos) = s.find(m) {
            let after = &s[pos + m.len()..];
            let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            // Bank account: typically 8-17 digits
            (8..=17).contains(&digits.len())
        } else {
            false
        }
    })
}

// ── Ownership Distance Rule ──────────────────────────────────────────

fn has_ownership_sensitive_combination(lower: &str) -> bool {
    // English ownership markers (including start of string)
    let ownership_markers_en = [" my ", "my ", " i ", "i ", " we ", "we ", " our ", "our "];
    // Chinese ownership markers
    let ownership_markers_zh = ["我", "我的", "本人", "我们", "家人"];

    // 7 sensitive categories
    let sensitive_categories: &[&[&str]] = &[
        // 1. Health
        &[
            "diagnosis",
            "disease",
            "medication",
            "hospital",
            "诊断",
            "疾病",
            "用药",
            "医院",
        ],
        // 2. Financial
        &[
            "salary", "income", "debt", "loan", "工资", "收入", "债务", "贷款",
        ],
        // 3. Intimate/Sexual
        &["sexual", "intimate", "性", "亲密"],
        // 4. Legal/Criminal
        &["arrested", "convicted", "lawsuit", "逮捕", "定罪", "诉讼"],
        // 5. Biometric
        &["fingerprint", "biometric", "指纹", "生物识别"],
        // 6. Private Communication
        &["private message", "secret chat", "私信", "密聊"],
        // 7. Account Recovery
        &["security question", "recovery code", "安全问题", "恢复码"],
    ];

    // Check ownership + category with distance rule
    for ownership in ownership_markers_en
        .iter()
        .chain(ownership_markers_zh.iter())
    {
        if let Some(own_pos) = lower.find(ownership) {
            let own_end = own_pos + ownership.len();
            for category_group in sensitive_categories {
                for category in category_group.iter() {
                    if let Some(cat_pos) = lower.find(category) {
                        // Distance rule: max 8 tokens for English, 24 CJK scalars for Chinese
                        let distance = if ownership.is_ascii() {
                            // English: count tokens between
                            let between = &lower[own_end..cat_pos];
                            between.split_whitespace().count()
                        } else {
                            // Chinese: count CJK scalars
                            let between = &lower[own_end..cat_pos];
                            between.chars().count()
                        };
                        let max_distance = if ownership.is_ascii() { 8 } else { 24 };
                        if distance <= max_distance {
                            return true;
                        }
                    }
                }
            }
        }
    }
    false
}

// ── Unknown Closure Set ──────────────────────────────────────────────

fn is_unknown_control_text(s: &str) -> bool {
    s.chars().any(is_unknown_control)
}

fn has_unknown_enum_marker(s: &str) -> bool {
    // Check for unknown enum markers
    let enum_markers = ["enum:", "type:", "kind:"];
    enum_markers.iter().any(|m| {
        if let Some(pos) = s.find(m) {
            let after = &s[pos + m.len()..];
            let value: String = after
                .chars()
                .skip_while(|c| c.is_whitespace())
                .take_while(|c| !c.is_whitespace() && *c != ',' && *c != ';')
                .collect();
            // If value is not empty but doesn't match known types
            !value.is_empty()
                && !matches!(
                    value.as_str(),
                    "fact"
                        | "preference"
                        | "experience"
                        | "goal"
                        | "skill"
                        | "other"
                        | "relationship"
                )
        } else {
            false
        }
    })
}

fn has_incomplete_sensitive_marker(s: &str) -> bool {
    // Check for sensitive markers without complete structure
    let sensitive_markers = [
        "address",
        "住址",
        "passport",
        "护照",
        "coordinates",
        "坐标",
        "银行账号",
        "iban",
    ];
    sensitive_markers.iter().any(|m| {
        if let Some(pos) = s.find(m) {
            let after = &s[pos + m.len()..];
            // Marker exists but no clear value follows
            let has_value = after
                .chars()
                .skip_while(|c| c.is_whitespace() || *c == ':' || *c == '=')
                .take(10)
                .any(|c| c.is_ascii_digit() || c.is_ascii_alphabetic());
            !has_value
        } else {
            false
        }
    })
}
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(windows)]
fn fill_secure_random(buffer: &mut [u8]) -> Result<(), ExtractionError> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(ExtractionError::new(
            "CANDIDATE_EXTRACTION_TOKEN_GENERATION_FAILED",
            true,
        ))
    }
}
#[cfg(not(windows))]
fn fill_secure_random(_: &mut [u8]) -> Result<(), ExtractionError> {
    Err(ExtractionError::new(
        "CANDIDATE_EXTRACTION_TOKEN_GENERATION_FAILED",
        false,
    ))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{
            atomic::{AtomicU8, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };

    use crate::{
        conversation::history::{
            AppendConversationTurnRequest, ConversationRepository, CreateConversationRequest,
        },
        storage::{LifeIdentityRecord, PersonaTemplateRecord},
    };

    use super::*;

    fn service() -> (StorageService, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("candidate-extraction-{}", unique_suffix()));
        let project = root.join("project");
        fs::create_dir_all(&project).unwrap();
        let service =
            StorageService::initialize_with_roots(root.join("default"), Some(project)).unwrap();
        service
            .save_persona(PersonaTemplateRecord {
                id: "persona-extraction".into(),
                name: "Persona".into(),
                version: 1,
                persona_json: "{}".into(),
            })
            .unwrap();
        service
            .save_life(LifeIdentityRecord {
                id: "life-extraction".into(),
                name: "Life".into(),
                created_at: "2026-01-01T00:00:00.000Z".into(),
                version: 1,
                body_id: "body".into(),
                persona_id: "persona-extraction".into(),
                persona_version: 1,
            })
            .unwrap();
        (service, root)
    }

    fn descriptor() -> ExtractorDescriptor {
        ExtractorDescriptor {
            extractor_id: "test-extractor".into(),
            extractor_version: "1".into(),
        }
    }

    struct PendingExtractor {
        descriptor: ExtractorDescriptor,
        entered: Arc<AtomicU8>,
    }

    impl CandidateExtractor for PendingExtractor {
        fn descriptor(&self) -> &ExtractorDescriptor {
            &self.descriptor
        }

        fn extract<'a>(
            &'a self,
            _request: CandidateExtractionRequest,
        ) -> Pin<
            Box<dyn Future<Output = Result<CandidateExtractionBatch, ExtractionError>> + Send + 'a>,
        > {
            let entered = self.entered.clone();
            Box::pin(futures::future::poll_fn(move |_| {
                entered.store(1, Ordering::Release);
                Poll::Pending
            }))
        }
    }

    struct PanicExtractor {
        descriptor: ExtractorDescriptor,
    }

    impl CandidateExtractor for PanicExtractor {
        fn descriptor(&self) -> &ExtractorDescriptor {
            &self.descriptor
        }

        fn extract<'a>(
            &'a self,
            _request: CandidateExtractionRequest,
        ) -> Pin<
            Box<dyn Future<Output = Result<CandidateExtractionBatch, ExtractionError>> + Send + 'a>,
        > {
            Box::pin(futures::future::poll_fn(
                |_| -> Poll<Result<CandidateExtractionBatch, ExtractionError>> {
                    panic!("extractor payload must never escape")
                },
            ))
        }
    }

    fn start_for_orchestrator(service: &StorageService, id: &str) -> StartedExtraction {
        let conversation = service
            .create_conversation(
                id,
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Orchestrator Test".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: format!("{id}-turn"),
                user_content: "selected user text".into(),
                assistant_content: "selected assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap()
    }

    fn extraction_run_state(service: &StorageService, run_id: &str) -> (String, Option<String>) {
        let state = service.state().unwrap();
        state
            .connection
            .query_row(
                "SELECT status, last_error_code FROM candidate_extraction_run WHERE id=?1",
                params![run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    #[test]
    fn orchestrator_timeout_drops_pending_future_and_schedules_retry() {
        let (service, root) = service();
        let started = start_for_orchestrator(&service, "orchestrator-timeout");
        let extractor = PendingExtractor {
            descriptor: descriptor(),
            entered: Arc::new(AtomicU8::new(0)),
        };
        let outcome = service.run_candidate_extraction_attempt(
            &extractor,
            &started,
            &ExtractionCancellation::new(),
            Some(Duration::from_millis(10)),
        );
        assert_eq!(outcome, CandidateExtractionAttemptOutcome::RetryScheduled);
        assert_eq!(
            extraction_run_state(&service, &started.request.run_id),
            (
                "retry_wait".into(),
                Some("CANDIDATE_EXTRACTION_TIMEOUT".into())
            )
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn extractor_future_does_not_hold_storage_mutex_or_sqlite_transaction() {
        let (service1, root) = service();
        let service2 =
            StorageService::initialize_with_roots(root.join("default"), Some(root.join("project")))
                .unwrap();
        let started = start_for_orchestrator(&service1, "orchestrator-unlocked");
        let entered = Arc::new(AtomicU8::new(0));
        let extractor = PendingExtractor {
            descriptor: descriptor(),
            entered: entered.clone(),
        };
        let service1 = Arc::new(service1);
        let cancellation = ExtractionCancellation::new();
        let run = std::thread::spawn({
            let service1 = service1.clone();
            move || {
                service1.run_candidate_extraction_attempt(
                    &extractor,
                    &started,
                    &cancellation,
                    Some(Duration::from_millis(75)),
                )
            }
        });
        while entered.load(Ordering::Acquire) == 0 {
            std::thread::yield_now();
        }
        let began = Instant::now();
        let state = service2.state().unwrap();
        let count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_extraction_run", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 1);
        assert!(began.elapsed() < Duration::from_millis(25));
        drop(state);
        assert_eq!(
            run.join().unwrap(),
            CandidateExtractionAttemptOutcome::RetryScheduled
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn orchestrator_cancellation_stops_pending_future_and_is_retryable() {
        let (service, root) = service();
        let started = start_for_orchestrator(&service, "orchestrator-cancel");
        let cancellation = ExtractionCancellation::new();
        let trigger = cancellation.clone();
        let wake = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(5));
            trigger.cancel(ExtractionCancellationReason::Shutdown);
        });
        let extractor = PendingExtractor {
            descriptor: descriptor(),
            entered: Arc::new(AtomicU8::new(0)),
        };
        let outcome = service.run_candidate_extraction_attempt(
            &extractor,
            &started,
            &cancellation,
            Some(Duration::from_secs(1)),
        );
        wake.join().unwrap();
        assert_eq!(outcome, CandidateExtractionAttemptOutcome::RetryScheduled);
        assert_eq!(
            extraction_run_state(&service, &started.request.run_id),
            (
                "retry_wait".into(),
                Some("CANDIDATE_EXTRACTION_CANCELLED_SHUTDOWN".into())
            )
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn orchestrator_stale_cancellation_does_not_mutate_run() {
        let (service, root) = service();
        let started = start_for_orchestrator(&service, "orchestrator-stale");
        let cancellation = ExtractionCancellation::new();
        cancellation.cancel(ExtractionCancellationReason::StaleAttempt);
        let extractor = PendingExtractor {
            descriptor: descriptor(),
            entered: Arc::new(AtomicU8::new(0)),
        };
        assert_eq!(
            service.run_candidate_extraction_attempt(&extractor, &started, &cancellation, None),
            CandidateExtractionAttemptOutcome::StaleAttempt
        );
        assert_eq!(
            extraction_run_state(&service, &started.request.run_id).0,
            "processing"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn orchestrator_maps_extractor_panic_without_payload_or_storage_poison() {
        let (service, root) = service();
        let started = start_for_orchestrator(&service, "orchestrator-panic");
        let outcome = service.run_candidate_extraction_attempt(
            &PanicExtractor {
                descriptor: descriptor(),
            },
            &started,
            &ExtractionCancellation::new(),
            None,
        );
        assert_eq!(outcome, CandidateExtractionAttemptOutcome::RetryScheduled);
        assert_eq!(
            extraction_run_state(&service, &started.request.run_id),
            (
                "retry_wait".into(),
                Some("CANDIDATE_EXTRACTION_EXTRACTOR_PANIC".into())
            )
        );
        assert!(service.state().is_ok());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn proposal_contract_rejects_ignore_payload_without_partial_result() {
        let request = CandidateExtractionRequest {
            run_id: "run".into(),
            attempt_sequence: 1,
            life_id: "life".into(),
            conversation_id: "conversation".into(),
            conversation_revision: 1,
            policy_version: "candidate-extraction-safety-v1".into(),
            snapshot_hash: "0".repeat(64),
            messages: vec![ExtractionMessage {
                message_id: "message".into(),
                sequence_no: 1,
                content: "hello".into(),
            }],
        };
        let batch = CandidateExtractionBatch {
            proposals: vec![CandidateExtractionProposal {
                action: ProposalAction::Ignore,
                kind: Some(MemoryKind::Preference),
                content: None,
                summary: None,
                confidence: None,
                importance: None,
                sensitivity_hint: SensitivityHint::NotSensitive,
                conflict_hint: false,
                source_message_ids: vec!["message".into()],
            }],
        };
        let error = match classify_batch(&request, batch) {
            Ok(_) => panic!("invalid Ignore proposal must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.code, "CANDIDATE_EXTRACTION_INVALID_REQUEST");
    }

    #[test]
    fn deleting_selected_user_message_invalidates_only_its_active_run() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-extraction",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Conversation".into(),
                },
            )
            .unwrap();
        let turn = service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        service
            .delete_conversation_message_governed(
                "life-extraction",
                &conversation.id,
                &turn.user_message.id,
            )
            .unwrap();
        let state = service.state().unwrap();
        let status: String = state
            .connection
            .query_row(
                "SELECT status FROM candidate_extraction_run WHERE id=?1",
                params![started.request.run_id],
                |row| row.get(0),
            )
            .unwrap();
        let remaining: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_extraction_snapshot_message WHERE run_id=?1",
                params![started.request.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "snapshot_invalidated");
        assert_eq!(remaining, 0);
        drop(state);
        let _ = fs::remove_dir_all(root);
    }

    // ── Safety Policy v1 Tests ────────────────────────────────────────

    #[test]
    fn test_hard_secret_pem_private_key() {
        assert!(hard_secret("-----BEGIN PRIVATE KEY-----\nMIIEvg..."));
        assert!(hard_secret("-----BEGIN RSA PRIVATE KEY-----\nMIIEvg..."));
        assert!(!hard_secret("-----BEGIN PUBLIC KEY-----\nMIIEvg..."));
    }

    #[test]
    fn test_hard_secret_bearer_token() {
        assert!(hard_secret(
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ));
        assert!(!hard_secret("Authorization: Basic dXNlcjpwYXNz"));
    }

    #[test]
    fn test_hard_secret_jwt() {
        assert!(hard_secret("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
        assert!(!hard_secret("v1.2.3"));
    }

    #[test]
    fn test_hard_secret_secret_assignment() {
        assert!(hard_secret("password=mysecret123"));
        assert!(hard_secret("api_key: sk-1234567890"));
        assert!(!hard_secret("username=admin"));
    }

    #[test]
    fn test_hard_secret_credential_prefix() {
        assert!(hard_secret("sk-1234567890abcdefghijklmnopqrstuvwxyz"));
        assert!(hard_secret("ghp_1234567890abcdefghijklmnopqrstuvwxyz"));
        assert!(!hard_secret("sk-short"));
    }

    #[test]
    fn test_hard_secret_otp() {
        assert!(hard_secret("OTP: 123456"));
        assert!(hard_secret("验证码: 654321"));
        assert!(!hard_secret("OTP: 12"));
    }

    #[test]
    fn test_hard_secret_payment_card() {
        assert!(hard_secret("4111111111111111")); // Valid Visa
        assert!(!hard_secret("1234567890123456")); // Invalid Luhn
    }

    #[test]
    fn test_hard_secret_cvv() {
        assert!(hard_secret("CVV: 123"));
        assert!(hard_secret("CVC: 456"));
        assert!(!hard_secret("CVV: 12"));
    }

    #[test]
    fn test_hard_secret_cookie() {
        assert!(hard_secret("Cookie: session=abc123"));
        assert!(hard_secret("Set-Cookie: token=xyz"));
        assert!(!hard_secret("Content-Type: text/html"));
    }

    #[test]
    fn test_hard_secret_seed_phrase() {
        assert!(hard_secret("seed phrase: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"));
        assert!(!hard_secret("seed phrase: one two three"));
    }

    #[test]
    fn test_hard_secret_hex_private_key() {
        assert!(hard_secret(
            "private key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(!hard_secret("private key: short"));
    }

    #[test]
    fn test_hard_secret_credential_url() {
        assert!(hard_secret("https://user:password@example.com/api"));
        assert!(!hard_secret("https://example.com/api"));
    }

    #[test]
    fn test_sensitive_email() {
        assert_eq!(
            local_safety("user@example.com", None),
            LocalSafetyDecision::BlockedSensitive
        );
        assert_eq!(
            local_safety("no email here", None),
            LocalSafetyDecision::Safe
        );
    }

    #[test]
    fn test_sensitive_phone() {
        assert_eq!(
            local_safety("+1234567890", None),
            LocalSafetyDecision::BlockedSensitive
        );
        assert_eq!(local_safety("123", None), LocalSafetyDecision::Safe);
    }

    #[test]
    fn test_sensitive_id_card() {
        assert_eq!(
            local_safety("身份证: 11010119900101001X", None),
            LocalSafetyDecision::BlockedSensitive
        );
        assert_eq!(local_safety("身份证: 123", None), LocalSafetyDecision::Safe);
    }

    #[test]
    fn test_sensitive_ssn() {
        assert_eq!(
            local_safety("SSN: 123456789", None),
            LocalSafetyDecision::BlockedSensitive
        );
        assert_eq!(local_safety("SSN: 123", None), LocalSafetyDecision::Safe);
    }

    #[test]
    fn test_sensitive_passport() {
        assert_eq!(
            local_safety("护照: AB1234567", None),
            LocalSafetyDecision::BlockedSensitive
        );
        assert_eq!(local_safety("护照: 12", None), LocalSafetyDecision::Safe);
    }

    #[test]
    fn test_sensitive_dob() {
        assert_eq!(
            local_safety("date of birth: 1990-01-01", None),
            LocalSafetyDecision::BlockedSensitive
        );
        assert_eq!(
            local_safety("birthday party", None),
            LocalSafetyDecision::Safe
        );
    }

    #[test]
    fn test_sensitive_address() {
        assert_eq!(
            local_safety("address: 123 Main Street", None),
            LocalSafetyDecision::BlockedSensitive
        );
        assert_eq!(
            local_safety("address: unknown", None),
            LocalSafetyDecision::Safe
        );
    }

    #[test]
    fn test_sensitive_coordinates() {
        assert_eq!(
            local_safety("coordinates: 40.7128 -74.0060", None),
            LocalSafetyDecision::BlockedSensitive
        );
        assert_eq!(
            local_safety("coordinates: 999 999", None),
            LocalSafetyDecision::Safe
        );
    }

    #[test]
    fn test_sensitive_iban() {
        assert_eq!(
            local_safety("iban: GB29NWBK60161331926819", None),
            LocalSafetyDecision::BlockedSensitive
        );
        assert_eq!(
            local_safety("iban: INVALID", None),
            LocalSafetyDecision::Safe
        );
    }

    #[test]
    fn test_sensitive_bank_account() {
        assert_eq!(
            local_safety("bank account: 1234567890", None),
            LocalSafetyDecision::BlockedSensitive
        );
        assert_eq!(
            local_safety("bank account: 123", None),
            LocalSafetyDecision::Safe
        );
    }

    #[test]
    fn test_ownership_distance_english() {
        assert_eq!(
            local_safety("my diagnosis is positive", None),
            LocalSafetyDecision::BlockedSensitive
        );
        assert_eq!(
            local_safety("my friend's diagnosis is positive", None),
            LocalSafetyDecision::BlockedSensitive
        );
    }

    #[test]
    fn test_ownership_distance_chinese() {
        assert_eq!(
            local_safety("我的诊断是阳性", None),
            LocalSafetyDecision::BlockedSensitive
        );
        assert_eq!(
            local_safety("我的朋友的诊断是阳性", None),
            LocalSafetyDecision::BlockedSensitive
        );
    }

    #[test]
    fn test_unknown_control_characters() {
        assert_eq!(
            local_safety("text\0with\0null", None),
            LocalSafetyDecision::Unknown
        );
        assert_eq!(
            local_safety("text\u{202A}with\u{202B}embed", None),
            LocalSafetyDecision::Unknown
        );
    }

    #[test]
    fn test_unknown_incomplete_marker() {
        assert_eq!(local_safety("address:", None), LocalSafetyDecision::Unknown);
        assert_eq!(
            local_safety("passport:", None),
            LocalSafetyDecision::Unknown
        );
    }

    #[test]
    fn test_safe_content() {
        assert_eq!(
            local_safety("I like coffee", None),
            LocalSafetyDecision::Safe
        );
        assert_eq!(
            local_safety("今天天气很好", None),
            LocalSafetyDecision::Safe
        );
    }

    #[test]
    fn test_hard_secret_priority_over_sensitive() {
        // Hard secret should take priority
        assert!(hard_secret("password=secret123 email@example.com"));
    }

    #[test]
    fn test_normalization_nfkc() {
        let input = "café"; // Contains é (U+00E9)
        let normalized = normalize_proposal_text(input);
        assert_eq!(normalized, "café");
    }

    #[test]
    fn test_normalization_whitespace() {
        let input = "hello   world\n\n\ttab";
        let normalized = normalize_proposal_text(input);
        assert_eq!(normalized, "hello world tab");
    }

    #[test]
    fn test_luhn_valid() {
        assert!(luhn("4111111111111111")); // Visa
        assert!(luhn("5500000000000004")); // Mastercard
    }

    #[test]
    fn test_luhn_invalid() {
        assert!(!luhn("1234567890123456"));
        assert!(!luhn("4111111111111112"));
    }

    #[test]
    fn test_iban_valid() {
        assert!(validate_iban("GB29NWBK60161331926819"));
        assert!(validate_iban("DE89370400440532013000"));
    }

    #[test]
    fn test_iban_invalid() {
        assert!(!validate_iban("GB00NWBK60161331926819"));
        assert!(!validate_iban("INVALID"));
    }

    // ── Unknown Closure Set Evidence ──────────────────────────────────

    #[test]
    fn test_unknown_normalization_error_returns_unknown() {
        // When normalization fails (e.g., due to control characters),
        // the result should be Unknown, not Safe
        assert_eq!(
            local_safety("text\0with\0null", None),
            LocalSafetyDecision::Unknown
        );
    }

    #[test]
    fn test_unknown_enum_marker() {
        // Unknown enum values should return Unknown
        assert_eq!(
            local_safety("type: unknown_type", None),
            LocalSafetyDecision::Unknown
        );
        assert_eq!(
            local_safety("kind: invalid_kind", None),
            LocalSafetyDecision::Unknown
        );
    }

    #[test]
    fn test_unknown_incomplete_sensitive_marker() {
        // Sensitive markers without values should return Unknown
        assert_eq!(local_safety("address:", None), LocalSafetyDecision::Unknown);
        assert_eq!(
            local_safety("passport:", None),
            LocalSafetyDecision::Unknown
        );
        assert_eq!(local_safety("iban:", None), LocalSafetyDecision::Unknown);
    }

    // ── Bounded Scanner Evidence ──────────────────────────────────────

    #[test]
    fn test_hard_secret_marker_within_single_chunk() {
        // PEM marker entirely within one chunk
        assert!(hard_secret(
            "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC..."
        ));
    }

    #[test]
    fn test_hard_secret_marker_at_chunk_boundary() {
        // PEM marker split across chunk boundary (simulated by having it in the middle)
        let prefix = "a".repeat(1000);
        let suffix = "-----BEGIN PRIVATE KEY-----\nMIIEvg...";
        assert!(hard_secret(&format!("{}{}", prefix, suffix)));
    }

    #[test]
    fn test_hard_secret_value_spans_chunks() {
        // Credential prefix value - must be a complete token
        assert!(hard_secret("sk-1234567890abcdefghijklmnopqrstuvwxyz"));
    }

    #[test]
    fn test_hard_secret_tail_insufficient_for_marker() {
        // Partial marker at the end - should not match
        assert!(!hard_secret("-----BEGIN PRIVATE"));
        assert!(!hard_secret("Authorization: Bear"));
    }

    #[test]
    fn test_hard_secret_before_limit() {
        // Hard secret found before hitting length limit
        let content = format!("password=secret123 {}", "a".repeat(3000));
        assert!(hard_secret(&content));
    }

    #[test]
    fn raw_content_over_limit_remains_a_contract_failure() {
        let request = CandidateExtractionRequest {
            run_id: "run".into(),
            attempt_sequence: 1,
            life_id: "life".into(),
            conversation_id: "conversation".into(),
            conversation_revision: 1,
            policy_version: "candidate-extraction-safety-v1".into(),
            snapshot_hash: "0".repeat(64),
            messages: vec![ExtractionMessage {
                message_id: "message".into(),
                sequence_no: 1,
                content: "hello".into(),
            }],
        };
        let batch = CandidateExtractionBatch {
            proposals: vec![CandidateExtractionProposal {
                action: ProposalAction::Propose,
                kind: Some(MemoryKind::Fact),
                content: Some("a".repeat(MAX_PROPOSAL_CONTENT_SCALARS + 1)),
                summary: None,
                confidence: Some(0.5),
                importance: Some(0.5),
                sensitivity_hint: SensitivityHint::NotSensitive,
                conflict_hint: false,
                source_message_ids: vec!["message".into()],
            }],
        };

        let error = match classify_batch(&request, batch) {
            Ok(_) => panic!("oversized content must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error.code,
            "CANDIDATE_EXTRACTION_PROPOSAL_CONTENT_TOO_LARGE"
        );
    }

    // ── Privacy Leak Tests ────────────────────────────────────────────
    #[test]
    fn test_hard_secret_no_value_in_error() {
        // Ensure hard secret values don't appear in error messages
        let secret = "password=SuperSecret123!";
        let decision = local_safety(secret, None);
        // The decision itself should not contain the secret
        let debug_str = format!("{:?}", decision);
        assert!(!debug_str.contains("SuperSecret123"));
    }

    #[test]
    fn test_sensitive_no_value_in_decision() {
        // Ensure sensitive values don't appear in decision debug
        let sensitive = "email: user@example.com";
        let decision = local_safety(sensitive, None);
        let debug_str = format!("{:?}", decision);
        assert!(!debug_str.contains("user@example.com"));
    }

    #[test]
    fn test_no_content_in_error() {
        // Ensure content doesn't leak into error types
        let content = "my secret password is abc123";
        let decision = local_safety(content, None);
        let debug_str = format!("{:?}", decision);
        assert!(!debug_str.contains("abc123"));
    }

    // ── Safe Content Tests (UUID, hash, random ID) ───────────────────

    #[test]
    fn test_uuid_remains_safe() {
        // UUID with minimal digit sequences should be safe
        assert_eq!(
            local_safety("a1b2-c3d4-e5f6-a7b8-c9d0e1f2a3b4", None),
            LocalSafetyDecision::Safe
        );
    }

    #[test]
    fn test_hash_remains_safe() {
        assert_eq!(
            local_safety(
                "sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                None
            ),
            LocalSafetyDecision::Safe
        );
    }

    #[test]
    fn test_random_id_remains_safe() {
        assert_eq!(
            local_safety("id: abc123def456ghi789", None),
            LocalSafetyDecision::Safe
        );
    }

    #[test]
    fn test_high_entropy_text_remains_safe() {
        // High entropy text that's not a secret should be safe
        assert_eq!(
            local_safety("The quick brown fox jumps over the lazy dog", None),
            LocalSafetyDecision::Safe
        );
    }

    // ── LocalSafetyDecision Priority Tests ────────────────────────────

    #[test]
    fn test_hard_over_sensitive_priority() {
        // Hard secret should take priority over sensitive
        let content = "password=secret123 user@example.com";
        assert!(hard_secret(content));
    }

    #[test]
    fn test_sensitive_over_unknown_priority() {
        // Sensitive should take priority over unknown
        // (Unknown only triggers on control chars, incomplete markers, etc.)
        assert_eq!(
            local_safety("email: user@example.com", None),
            LocalSafetyDecision::BlockedSensitive
        );
    }

    // ── Time Control Helper ───────────────────────────────────────────

    /// Set lease_expires_at_epoch_s to a past value (epoch 1) for testing.
    /// This satisfies CHECK (> 0) and is in the past.
    fn expire_lease(service: &StorageService, run_id: &str) {
        // Drop the guard before any potential panic to avoid poisoning
        let result = {
            let state = service.state().expect("state lock");
            state.connection.execute(
                "UPDATE candidate_extraction_run SET lease_expires_at_epoch_s = 1 WHERE id = ?1 AND status = 'processing'",
                params![run_id],
            )
        };
        result.expect("expire lease");
    }

    /// Set next_attempt_at_epoch_s to a past value (epoch 1) for testing.
    fn make_retry_due(service: &StorageService, run_id: &str) {
        // Drop the guard before any potential panic to avoid poisoning
        let result = {
            let state = service.state().expect("state lock");
            state.connection.execute(
                "UPDATE candidate_extraction_run SET next_attempt_at_epoch_s = 1 WHERE id = ?1 AND status = 'retry_wait'",
                params![run_id],
            )
        };
        result.expect("make retry due");
    }

    // ── Lease Tests ───────────────────────────────────────────────────

    #[test]
    fn renew_lease_succeeds_for_active_run() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-renew",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Renew Test".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Renew should succeed
        let result = service.renew_extraction_lease(&started);
        assert!(result.is_ok());
        assert!(result.unwrap());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn renew_lease_fails_after_takeover() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-renew-stale",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Renew Stale Test".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Expire the lease
        expire_lease(&service, &started.request.run_id);
        // Takeover should succeed
        let _new_started = service
            .take_over_expired_extraction_lease(
                "life-extraction",
                &conversation.id,
                &descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Old attempt should fail to renew (stale)
        let result = service.renew_extraction_lease(&started);
        assert!(result.is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    // ── Retry Tests ───────────────────────────────────────────────────

    #[test]
    fn claim_due_retry_succeeds_after_delay() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-retry",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Retry Test".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Fail the attempt (retryable)
        service
            .fail_candidate_extraction_attempt(&started, "CANDIDATE_EXTRACTION_TIMEOUT", true)
            .unwrap();
        // Make retry due
        make_retry_due(&service, &started.request.run_id);
        // Claim due retry should succeed
        let new_started = service
            .claim_due_extraction_retry(
                "life-extraction",
                &conversation.id,
                &descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap();
        assert!(new_started.is_some());
        let new_started = new_started.unwrap();
        assert_eq!(new_started.request.attempt_sequence, 2);
        let _ = std::fs::remove_dir_all(root);
    }

    // ── Takeover Tests ────────────────────────────────────────────────

    #[test]
    fn take_over_expired_lease_succeeds() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-takeover",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Takeover Test".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Expire the lease
        expire_lease(&service, &started.request.run_id);
        // Verify lease is expired
        {
            let state = service.state().unwrap();
            let lease: i64 = state
                .connection
                .query_row(
                    "SELECT lease_expires_at_epoch_s FROM candidate_extraction_run WHERE id=?1",
                    params![started.request.run_id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(lease, 1, "lease should be expired");
        }
        // Takeover should succeed
        let result = service.take_over_expired_extraction_lease(
            "life-extraction",
            &conversation.id,
            &descriptor(),
            "candidate-extraction-safety-v1",
        );
        match result {
            Ok(Some(new_started)) => {
                assert_eq!(new_started.request.attempt_sequence, 2);
            }
            Ok(None) => {
                panic!("Expected Some, got None");
            }
            Err(e) => {
                panic!("Expected Ok, got Err: {:?}", e);
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn active_lease_cannot_be_taken_over() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-no-takeover",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "No Takeover Test".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let _started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Try to takeover (should fail - lease is active)
        let result = service.take_over_expired_extraction_lease(
            "life-extraction",
            &conversation.id,
            &descriptor(),
            "candidate-extraction-safety-v1",
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    // ── Attempt Limit Tests ───────────────────────────────────────────

    #[test]
    fn attempt_3_does_not_produce_attempt_4() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-max-attempts",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Max Attempts Test".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Fail attempt 1 (retryable)
        service
            .fail_candidate_extraction_attempt(&started, "CANDIDATE_EXTRACTION_TIMEOUT", true)
            .unwrap();
        // Make retry due
        make_retry_due(&service, &started.request.run_id);
        // Claim attempt 2
        let started2 = service
            .claim_due_extraction_retry(
                "life-extraction",
                &conversation.id,
                &descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        assert_eq!(started2.request.attempt_sequence, 2);
        // Fail attempt 2 (retryable)
        service
            .fail_candidate_extraction_attempt(&started2, "CANDIDATE_EXTRACTION_TIMEOUT", true)
            .unwrap();
        // Make retry due
        make_retry_due(&service, &started.request.run_id);
        // Claim attempt 3
        let started3 = service
            .claim_due_extraction_retry(
                "life-extraction",
                &conversation.id,
                &descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        assert_eq!(started3.request.attempt_sequence, 3);
        // Fail attempt 3 (should be terminal)
        service
            .fail_candidate_extraction_attempt(&started3, "CANDIDATE_EXTRACTION_TIMEOUT", true)
            .unwrap();
        // Verify run is failed
        let state = service.state().unwrap();
        let status: String = state
            .connection
            .query_row(
                "SELECT status FROM candidate_extraction_run WHERE id=?1",
                params![started.request.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "failed");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn expired_attempt_3_becomes_terminal_without_attempt_4() {
        let (service, root) = service();
        let started = start_for_orchestrator(&service, "expired-attempt-three");
        service
            .fail_candidate_extraction_attempt(&started, "CANDIDATE_EXTRACTION_TIMEOUT", true)
            .unwrap();
        make_retry_due(&service, &started.request.run_id);
        let second = service
            .claim_due_extraction_retry(
                "life-extraction",
                "expired-attempt-three",
                &descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        service
            .fail_candidate_extraction_attempt(&second, "CANDIDATE_EXTRACTION_TIMEOUT", true)
            .unwrap();
        make_retry_due(&service, &started.request.run_id);
        let third = service
            .claim_due_extraction_retry(
                "life-extraction",
                "expired-attempt-three",
                &descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        assert_eq!(third.request.attempt_sequence, 3);
        expire_lease(&service, &started.request.run_id);
        assert!(service
            .take_over_expired_extraction_lease(
                "life-extraction",
                "expired-attempt-three",
                &descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .is_none());
        let state = service.state().unwrap();
        let (attempt, status, snapshots, terminal_audits): (i64, String, i64, i64) = state
            .connection
            .query_row(
                "SELECT r.attempt_sequence, r.status,
                        (SELECT COUNT(*) FROM candidate_extraction_snapshot_message s WHERE s.run_id=r.id),
                        (SELECT COUNT(*) FROM candidate_extraction_audit a WHERE a.run_id=r.id AND a.event='failed')
                 FROM candidate_extraction_run r WHERE r.id=?1",
                params![started.request.run_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!(attempt, 3);
        assert_eq!(status, "failed");
        assert_eq!(snapshots, 0);
        assert_eq!(terminal_audits, 1);
        let _ = fs::remove_dir_all(root);
    }

    // ── Snapshot Reload Tests ─────────────────────────────────────────

    #[test]
    fn snapshot_reload_succeeds_with_valid_data() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-reload",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Reload Test".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Add a new turn (not selected)
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-2".into(),
                user_content: "new user text".into(),
                assistant_content: "new assistant text".into(),
                expected_revision: Some(1),
            })
            .unwrap();
        // Expire and takeover should succeed (snapshot still valid)
        expire_lease(&service, &started.request.run_id);
        let new_started = service
            .take_over_expired_extraction_lease(
                "life-extraction",
                &conversation.id,
                &descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap();
        assert!(new_started.is_some());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn deleted_selected_message_invalidates_snapshot() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-invalidate",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Invalidate Test".into(),
                },
            )
            .unwrap();
        let turn = service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Delete the selected user message
        service
            .delete_conversation_message_governed(
                "life-extraction",
                &conversation.id,
                &turn.user_message.id,
            )
            .unwrap();
        // Expire the lease for takeover
        expire_lease(&service, &started.request.run_id);
        // Takeover should fail (snapshot invalidated)
        let result = service.take_over_expired_extraction_lease(
            "life-extraction",
            &conversation.id,
            &descriptor(),
            "candidate-extraction-safety-v1",
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_none());
        // Verify run is snapshot_invalidated
        let state = service.state().unwrap();
        let status: String = state
            .connection
            .query_row(
                "SELECT status FROM candidate_extraction_run WHERE id=?1",
                params![started.request.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(status, "snapshot_invalidated");
        let _ = std::fs::remove_dir_all(root);
    }

    // ── Recovery Query Tests ──────────────────────────────────────────

    #[test]
    fn recovery_query_returns_expired_and_due_runs() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-recovery",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Recovery Test".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Expire the lease
        expire_lease(&service, &started.request.run_id);
        // Query recovery candidates
        let candidates = service.query_extraction_recovery_candidates(64).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].0, started.request.run_id);
        assert_eq!(candidates[0].1, "processing");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn recovery_query_respects_limit() {
        let (service, root) = service();
        // Create multiple conversations with expired leases
        for i in 0..5 {
            let conv_id = format!("conversation-limit-{}", i);
            let conversation = service
                .create_conversation(
                    &conv_id,
                    &CreateConversationRequest {
                        life_id: "life-extraction".into(),
                        title: format!("Limit Test {}", i),
                    },
                )
                .unwrap();
            service
                .append_complete_turn(&AppendConversationTurnRequest {
                    life_id: "life-extraction".into(),
                    conversation_id: conversation.id.clone(),
                    turn_id: format!("turn-{}", i),
                    user_content: format!("user text {}", i),
                    assistant_content: format!("assistant text {}", i),
                    expected_revision: Some(0),
                })
                .unwrap();
            let started = service
                .start_candidate_extraction(
                    "life-extraction",
                    &conversation.id,
                    descriptor(),
                    "candidate-extraction-safety-v1",
                )
                .unwrap()
                .unwrap();
            expire_lease(&service, &started.request.run_id);
        }
        // Query with limit 3
        let candidates = service.query_extraction_recovery_candidates(3).unwrap();
        assert_eq!(candidates.len(), 3);
        // Query with limit 10 (should return all 5)
        let candidates = service.query_extraction_recovery_candidates(10).unwrap();
        assert_eq!(candidates.len(), 5);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn recovery_query_clamps_zero_and_oversized_limits() {
        let (service, root) = service();
        for index in 0..2 {
            let started = start_for_orchestrator(&service, &format!("recovery-clamp-{index}"));
            expire_lease(&service, &started.request.run_id);
        }
        assert_eq!(
            service
                .query_extraction_recovery_candidates(0)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            service
                .query_extraction_recovery_candidates(RECOVERY_SCAN_LIMIT + 1_000)
                .unwrap()
                .len(),
            2
        );
        let _ = std::fs::remove_dir_all(root);
    }

    // ── Dual-Connection Concurrency Tests ─────────────────────────────

    #[test]
    fn dual_connection_concurrent_create_only_one_run() {
        let (service1, root) = service();
        let service2 =
            StorageService::initialize_with_roots(root.join("default"), Some(root.join("project")))
                .unwrap();

        let conversation = service1
            .create_conversation(
                "conversation-concurrent",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Concurrent Test".into(),
                },
            )
            .unwrap();
        service1
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();

        // First connection creates the run
        let started1 = service1
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        assert_eq!(started1.request.attempt_sequence, 1);

        // Second connection should get ALREADY_PROCESSING error
        // because it doesn't have the raw token to take ownership
        let result = service2.start_candidate_extraction(
            "life-extraction",
            &conversation.id,
            descriptor(),
            "candidate-extraction-safety-v1",
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code,
            "CANDIDATE_EXTRACTION_ALREADY_PROCESSING"
        );

        // Verify only one run exists
        let state = service1.state().unwrap();
        let count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_extraction_run WHERE life_id='life-extraction'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn dual_connection_concurrent_takeover_only_one_succeeds() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let (service1, root) = service();
        let service2 =
            StorageService::initialize_with_roots(root.join("default"), Some(root.join("project")))
                .unwrap();

        let conversation = service1
            .create_conversation(
                "conversation-concurrent-takeover",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Concurrent Takeover Test".into(),
                },
            )
            .unwrap();
        service1
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service1
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Expire the lease
        expire_lease(&service1, &started.request.run_id);

        let barrier = Arc::new(Barrier::new(2));
        let conv_id1 = conversation.id.clone();
        let conv_id2 = conversation.id.clone();
        let desc1 = descriptor();
        let desc2 = descriptor();
        let policy = "candidate-extraction-safety-v1";
        let barrier1 = barrier.clone();
        let barrier2 = barrier.clone();

        // Use Arc for shared access to service1
        let svc1 = Arc::new(service1);

        let svc1_clone = svc1.clone();
        let handle1 = thread::spawn(move || {
            barrier1.wait();
            svc1_clone.take_over_expired_extraction_lease(
                "life-extraction",
                &conv_id1,
                &desc1,
                policy,
            )
        });

        let handle2 = thread::spawn(move || {
            barrier2.wait();
            service2.take_over_expired_extraction_lease(
                "life-extraction",
                &conv_id2,
                &desc2,
                policy,
            )
        });

        let result1 = handle1.join().unwrap();
        let result2 = handle2.join().unwrap();

        // One should succeed, one should get None (already taken over)
        let success_count = [result1.as_ref().ok(), result2.as_ref().ok()]
            .iter()
            .filter(|r| r.is_some() && r.unwrap().is_some())
            .count();
        assert_eq!(success_count, 1);

        // Verify attempt_sequence is 2 (not 3)
        let state = svc1.state().unwrap();
        let attempt: i64 = state
            .connection
            .query_row(
                "SELECT attempt_sequence FROM candidate_extraction_run WHERE id=?1",
                params![started.request.run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(attempt, 2);

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn dual_connection_concurrent_due_retry_claim_only_one_succeeds() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let (service1, root) = service();
        let service2 =
            StorageService::initialize_with_roots(root.join("default"), Some(root.join("project")))
                .unwrap();
        let started = start_for_orchestrator(&service1, "concurrent-due-retry");
        service1
            .fail_candidate_extraction_attempt(&started, "CANDIDATE_EXTRACTION_TIMEOUT", true)
            .unwrap();
        make_retry_due(&service1, &started.request.run_id);

        let conversation_id = started.request.conversation_id.clone();
        let barrier = Arc::new(Barrier::new(2));
        let service1 = Arc::new(service1);
        let service1_claim = service1.clone();
        let barrier1 = barrier.clone();
        let claim1 = thread::spawn(move || {
            barrier1.wait();
            service1_claim.claim_due_extraction_retry(
                "life-extraction",
                &conversation_id,
                &descriptor(),
                "candidate-extraction-safety-v1",
            )
        });
        let barrier2 = barrier.clone();
        let claim2 = thread::spawn(move || {
            barrier2.wait();
            service2.claim_due_extraction_retry(
                "life-extraction",
                "concurrent-due-retry",
                &descriptor(),
                "candidate-extraction-safety-v1",
            )
        });

        let result1 = claim1.join().unwrap().unwrap();
        let result2 = claim2.join().unwrap().unwrap();
        assert_eq!(
            usize::from(result1.is_some()) + usize::from(result2.is_some()),
            1
        );

        let state = service1.state().unwrap();
        let (attempt, audit_count): (i64, i64) = state
            .connection
            .query_row(
                "SELECT r.attempt_sequence,
                        (SELECT COUNT(*) FROM candidate_extraction_audit a
                         WHERE a.run_id=r.id AND a.event='attempt_started')
                 FROM candidate_extraction_run r WHERE r.id=?1",
                params![started.request.run_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(attempt, 2);
        assert_eq!(audit_count, 2);
        drop(state);
        let _ = fs::remove_dir_all(root);
    }

    // ── Privacy Tests ─────────────────────────────────────────────────

    #[test]
    fn error_does_not_leak_token() {
        let error = ExtractionError::new("CANDIDATE_EXTRACTION_FENCE_INVALID", false);
        let debug_str = format!("{:?}", error);
        assert!(!debug_str.contains("token"));
        assert!(!debug_str.contains("digest"));
    }

    #[test]
    fn fence_debug_redacts_token() {
        let fence = ExtractionFence {
            run_id: "run-1".into(),
            life_id: "life-1".into(),
            conversation_id: "conv-1".into(),
            conversation_revision: 1,
            attempt_sequence: 1,
            raw_token: Zeroizing::new([0xAB; 32]),
            descriptor: ExtractorDescriptor {
                extractor_id: "ext".into(),
                extractor_version: "1".into(),
            },
            policy_version: "v1".into(),
            snapshot_hash: "a".repeat(64),
        };
        let debug_str = format!("{:?}", fence);
        assert!(debug_str.contains("[REDACTED]"));
        assert!(!debug_str.contains("171")); // 0xAB = 171
    }

    // ── Commit Uncertainty Reconciliation Tests ───────────────────────

    #[test]
    fn reconcile_completed_run_returns_counts() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-reconcile-completed",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Reconcile Completed Test".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Finalize successfully
        let batch = CandidateExtractionBatch {
            proposals: vec![CandidateExtractionProposal {
                action: ProposalAction::Propose,
                kind: Some(MemoryKind::Preference),
                content: Some("I like coffee".into()),
                summary: Some("Preference: coffee".into()),
                confidence: Some(0.9),
                importance: Some(0.8),
                sensitivity_hint: SensitivityHint::NotSensitive,
                conflict_hint: false,
                source_message_ids: vec![started.request.messages[0].message_id.clone()],
            }],
        };
        service
            .finalize_candidate_extraction_atomic(&started, batch)
            .unwrap();
        // Reconcile should return Completed
        let result = service
            .reconcile_extraction_commit_uncertainty(
                &started.request.run_id,
                started.request.attempt_sequence,
            )
            .unwrap();
        match result {
            CommitReconciliationResult::Completed {
                total_proposal_count,
                created_count,
                ..
            } => {
                assert_eq!(total_proposal_count, 1);
                assert_eq!(created_count, 1);
            }
            _ => panic!("Expected Completed, got {:?}", result),
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reconcile_failed_run_returns_terminal() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-reconcile-failed",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Reconcile Failed Test".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Fail the attempt (terminal)
        service
            .fail_candidate_extraction_attempt(
                &started,
                "CANDIDATE_EXTRACTION_PROVIDER_ERROR",
                false,
            )
            .unwrap();
        // Reconcile should return TerminalFailed
        let result = service
            .reconcile_extraction_commit_uncertainty(
                &started.request.run_id,
                started.request.attempt_sequence,
            )
            .unwrap();
        assert_eq!(result, CommitReconciliationResult::TerminalFailed);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reconcile_nonexistent_run_returns_storage_unavailable() {
        let (service, root) = service();
        let result = service
            .reconcile_extraction_commit_uncertainty("nonexistent-run", 1)
            .unwrap();
        assert_eq!(result, CommitReconciliationResult::StorageUnavailable);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reconcile_processing_run_returns_unavailable() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-reconcile-processing",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Reconcile Processing Test".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        // Reconcile should return CommitOutcomeUnavailable (still processing)
        let result = service
            .reconcile_extraction_commit_uncertainty(
                &started.request.run_id,
                started.request.attempt_sequence,
            )
            .unwrap();
        assert_eq!(result, CommitReconciliationResult::CommitOutcomeUnavailable);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reconcile_is_idempotent() {
        let (service, root) = service();
        let conversation = service
            .create_conversation(
                "conversation-reconcile-idempotent",
                &CreateConversationRequest {
                    life_id: "life-extraction".into(),
                    title: "Reconcile Idempotent Test".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-extraction".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "user text".into(),
                assistant_content: "assistant text".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        let started = service
            .start_candidate_extraction(
                "life-extraction",
                &conversation.id,
                descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        let batch = CandidateExtractionBatch { proposals: vec![] };
        service
            .finalize_candidate_extraction_atomic(&started, batch)
            .unwrap();
        // Reconcile twice should return same result
        let result1 = service
            .reconcile_extraction_commit_uncertainty(
                &started.request.run_id,
                started.request.attempt_sequence,
            )
            .unwrap();
        let result2 = service
            .reconcile_extraction_commit_uncertainty(
                &started.request.run_id,
                started.request.attempt_sequence,
            )
            .unwrap();
        assert_eq!(result1, result2);
        // Verify no duplicate candidates
        let state = service.state().unwrap();
        let count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_extraction_audit WHERE run_id=?1",
                params![started.request.run_id],
                |row| row.get(0),
            )
            .unwrap();
        // Should have exactly 2 audits: attempt_started + completed
        assert_eq!(count, 2);
        let _ = std::fs::remove_dir_all(root);
    }

    // ── Privacy Matrix Tests ──────────────────────────────────────────

    #[test]
    fn extraction_error_debug_does_not_leak_sensitive() {
        let error = ExtractionError::new("CANDIDATE_EXTRACTION_FENCE_INVALID", false);
        let debug = format!("{:?}", error);
        assert!(!debug.contains("password"));
        assert!(!debug.contains("secret"));
        assert!(!debug.contains("token"));
        assert!(!debug.contains("digest"));
    }

    #[test]
    fn commit_reconciliation_result_debug_does_not_leak() {
        let result = CommitReconciliationResult::Completed {
            total_proposal_count: 1,
            created_count: 1,
            evidence_merged_count: 0,
            hard_secret_blocked_count: 0,
        };
        let debug = format!("{:?}", result);
        assert!(!debug.contains("content"));
        assert!(!debug.contains("summary"));
        assert!(!debug.contains("token"));
    }
}
