//! D-7's narrow, safe entry point for deterministic candidate extraction.
//!
//! This module owns the D-7 integration.  The frozen D-6 extraction module
//! remains private; no Command can receive its lease, token, snapshot, run, or
//! attempt objects.

#[path = "../memory/deterministic_extractor.rs"]
mod deterministic_extractor;

use rusqlite::{params, OptionalExtension};
use serde::Serialize;

use super::candidate_extraction::{
    CandidateExtractionAttemptOutcome, CommitReconciliationResult, ExtractionCancellation,
};
use super::StorageService;
use deterministic_extractor::{deterministic_descriptor, DeterministicCandidateExtractor};

const SAFETY_POLICY_VERSION: &str = "candidate-extraction-safety-v1";

#[cfg(test)]
thread_local! {
    static BEFORE_START_HOOK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static DETERMINISTIC_ATTEMPT_CALLS: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn set_before_start_hook_for_test(hook: impl FnOnce() + 'static) {
    BEFORE_START_HOOK.with(|slot| {
        assert!(slot.borrow_mut().replace(Box::new(hook)).is_none());
    });
}

#[cfg(test)]
fn run_before_start_hook() {
    BEFORE_START_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
fn reset_deterministic_attempt_calls_for_test() {
    DETERMINISTIC_ATTEMPT_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
fn deterministic_attempt_calls_for_test() -> usize {
    DETERMINISTIC_ATTEMPT_CALLS.with(std::cell::Cell::get)
}

#[cfg(test)]
fn record_deterministic_attempt_call() {
    DETERMINISTIC_ATTEMPT_CALLS.with(|calls| calls.set(calls.get() + 1));
}

/// The complete set of user-visible states.  These values are intentionally
/// independent of D-6's Rust enums and database error strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionTriggerStatus {
    Completed,
    Processing,
    RetryWait,
    Failed,
    SnapshotInvalidated,
    NoEligibleSnapshot,
    StaleOrConflict,
}

/// The only successful IPC payload for a D-7 manual trigger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractionTriggerResponse {
    pub status: ExtractionTriggerStatus,
    pub created_count: Option<i64>,
    pub merged_evidence_count: Option<i64>,
    pub blocked_count: Option<i64>,
    pub safe_message_code: &'static str,
}

/// A deliberately non-diagnostic error suitable for Tauri IPC.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeCommandError {
    pub code: &'static str,
    pub message: &'static str,
}

impl SafeCommandError {
    pub(crate) const fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

struct ExistingRun {
    status: ExtractionTriggerStatus,
    created_count: i64,
    merged_evidence_count: i64,
    blocked_count: i64,
    extractor_id: String,
    extractor_version: String,
    policy_version: String,
}

/// Trigger D-6's exact-snapshot orchestration with D-7's fixed extractor.
///
/// The facade may read the authoritative run summary to enforce idempotency and
/// return safe aggregate counts.  It never writes Candidate, Evidence, Audit,
/// or Run rows directly.
pub(crate) fn trigger_deterministic_candidate_extraction(
    storage: &StorageService,
    life_id: &str,
    conversation_id: &str,
) -> Result<ExtractionTriggerResponse, SafeCommandError> {
    if life_id.trim().is_empty() || conversation_id.trim().is_empty() {
        return Err(SafeCommandError::new(
            "CANDIDATE_EXTRACTION_INVALID_REQUEST",
            "A current life and conversation are required.",
        ));
    }

    if let Some(existing) = read_existing_run(storage, life_id, conversation_id)? {
        return Ok(response_from_existing(existing));
    }

    #[cfg(test)]
    run_before_start_hook();
    let extractor = DeterministicCandidateExtractor::new();
    let started = match storage.start_candidate_extraction(
        life_id,
        conversation_id,
        deterministic_descriptor(),
        SAFETY_POLICY_VERSION,
    ) {
        Ok(Some(started)) => started,
        Ok(None) => return Ok(simple_response(ExtractionTriggerStatus::NoEligibleSnapshot)),
        Err(error) => {
            if let Some(existing) = read_existing_run(storage, life_id, conversation_id)? {
                return Ok(response_from_existing(existing));
            }
            return Err(map_start_error(error.code()));
        }
    };

    let cancellation = ExtractionCancellation::new();
    #[cfg(test)]
    record_deterministic_attempt_call();
    response_from_attempt_outcome(
        storage,
        life_id,
        conversation_id,
        storage.run_candidate_extraction_attempt(&extractor, &started, &cancellation, None),
    )
}

fn response_from_attempt_outcome(
    storage: &StorageService,
    life_id: &str,
    conversation_id: &str,
    outcome: CandidateExtractionAttemptOutcome,
) -> Result<ExtractionTriggerResponse, SafeCommandError> {
    match outcome {
        CandidateExtractionAttemptOutcome::Completed => {
            read_existing_run(storage, life_id, conversation_id)?
                .map(response_from_existing)
                .ok_or_else(storage_unavailable)
        }
        CandidateExtractionAttemptOutcome::CommitOutcomeUncertain(identity) => {
            response_from_commit_reconciliation(
                storage,
                life_id,
                conversation_id,
                storage
                    .reconcile_candidate_extraction_attempt_uncertainty(identity)
                    .map_err(|_| storage_unavailable())?,
            )
        }
        // Ordinary storage failures must never be treated as proof that a
        // committed run exists. Only D-6's typed uncertainty variant may
        // enter authoritative commit reconciliation.
        CandidateExtractionAttemptOutcome::StorageFailure => Err(storage_unavailable()),
        CandidateExtractionAttemptOutcome::RetryScheduled => {
            Ok(simple_response(ExtractionTriggerStatus::RetryWait))
        }
        CandidateExtractionAttemptOutcome::TerminalFailed => {
            Ok(simple_response(ExtractionTriggerStatus::Failed))
        }
        CandidateExtractionAttemptOutcome::StaleAttempt => {
            Ok(simple_response(ExtractionTriggerStatus::StaleOrConflict))
        }
    }
}

fn response_from_commit_reconciliation(
    storage: &StorageService,
    life_id: &str,
    conversation_id: &str,
    result: CommitReconciliationResult,
) -> Result<ExtractionTriggerResponse, SafeCommandError> {
    match result {
        CommitReconciliationResult::Completed { .. } => {
            read_existing_run(storage, life_id, conversation_id)?
                .map(response_from_existing)
                .ok_or_else(storage_unavailable)
        }
        CommitReconciliationResult::TerminalFailed => {
            Ok(simple_response(ExtractionTriggerStatus::Failed))
        }
        CommitReconciliationResult::SnapshotInvalidated => Ok(simple_response(
            ExtractionTriggerStatus::SnapshotInvalidated,
        )),
        CommitReconciliationResult::CommitOutcomeUnavailable => {
            Ok(simple_response(ExtractionTriggerStatus::Processing))
        }
        CommitReconciliationResult::StorageUnavailable => Err(storage_unavailable()),
    }
}

fn read_existing_run(
    storage: &StorageService,
    life_id: &str,
    conversation_id: &str,
) -> Result<Option<ExistingRun>, SafeCommandError> {
    let state = storage.state().map_err(|_| storage_unavailable())?;
    let revision: Option<i64> = state
        .connection
        .query_row(
            "SELECT revision FROM conversation WHERE id = ?1 AND life_id = ?2",
            params![conversation_id, life_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| storage_unavailable())?;
    let revision = revision.ok_or_else(conversation_not_found)?;

    state
        .connection
        .query_row(
            "SELECT status, created_count, evidence_merged_count,
                    hard_secret_blocked_count + sensitive_blocked_count,
                    extractor_id, extractor_version, policy_version
             FROM candidate_extraction_run
             WHERE life_id = ?1 AND conversation_id = ?2 AND conversation_revision = ?3",
            params![life_id, conversation_id, revision],
            |row| {
                let status: String = row.get(0)?;
                let status = match status.as_str() {
                    "processing" => ExtractionTriggerStatus::Processing,
                    "retry_wait" => ExtractionTriggerStatus::RetryWait,
                    "completed" => ExtractionTriggerStatus::Completed,
                    "failed" => ExtractionTriggerStatus::Failed,
                    "snapshot_invalidated" => ExtractionTriggerStatus::SnapshotInvalidated,
                    _ => ExtractionTriggerStatus::StaleOrConflict,
                };
                Ok(ExistingRun {
                    status,
                    created_count: row.get(1)?,
                    merged_evidence_count: row.get(2)?,
                    blocked_count: row.get(3)?,
                    extractor_id: row.get(4)?,
                    extractor_version: row.get(5)?,
                    policy_version: row.get(6)?,
                })
            },
        )
        .optional()
        .map_err(|_| storage_unavailable())
}

fn response_from_existing(existing: ExistingRun) -> ExtractionTriggerResponse {
    let expected = deterministic_descriptor();
    if existing.extractor_id != expected.extractor_id
        || existing.extractor_version != expected.extractor_version
        || existing.policy_version != SAFETY_POLICY_VERSION
    {
        return simple_response(ExtractionTriggerStatus::StaleOrConflict);
    }

    match existing.status {
        ExtractionTriggerStatus::Completed => ExtractionTriggerResponse {
            status: existing.status,
            created_count: Some(existing.created_count),
            merged_evidence_count: Some(existing.merged_evidence_count),
            blocked_count: Some(existing.blocked_count),
            safe_message_code: "CANDIDATE_EXTRACTION_COMPLETED",
        },
        status => simple_response(status),
    }
}

fn simple_response(status: ExtractionTriggerStatus) -> ExtractionTriggerResponse {
    let safe_message_code = match status {
        ExtractionTriggerStatus::Completed => "CANDIDATE_EXTRACTION_COMPLETED",
        ExtractionTriggerStatus::Processing => "CANDIDATE_EXTRACTION_PROCESSING",
        ExtractionTriggerStatus::RetryWait => "CANDIDATE_EXTRACTION_RETRY_WAIT",
        ExtractionTriggerStatus::Failed => "CANDIDATE_EXTRACTION_FAILED",
        ExtractionTriggerStatus::SnapshotInvalidated => "CANDIDATE_EXTRACTION_SNAPSHOT_INVALIDATED",
        ExtractionTriggerStatus::NoEligibleSnapshot => "CANDIDATE_EXTRACTION_NO_ELIGIBLE_SNAPSHOT",
        ExtractionTriggerStatus::StaleOrConflict => "CANDIDATE_EXTRACTION_STALE_OR_CONFLICT",
    };
    ExtractionTriggerResponse {
        status,
        created_count: None,
        merged_evidence_count: None,
        blocked_count: None,
        safe_message_code,
    }
}

fn map_start_error(code: &str) -> SafeCommandError {
    match code {
        "CANDIDATE_EXTRACTION_CONVERSATION_NOT_FOUND" => conversation_not_found(),
        "CANDIDATE_EXTRACTION_ALREADY_PROCESSING" => SafeCommandError::new(
            "CANDIDATE_EXTRACTION_PROCESSING",
            "Candidate memory extraction is already in progress for this conversation.",
        ),
        _ => storage_unavailable(),
    }
}

const fn conversation_not_found() -> SafeCommandError {
    SafeCommandError::new(
        "CANDIDATE_EXTRACTION_CONVERSATION_NOT_FOUND",
        "The current conversation was not found.",
    )
}

const fn storage_unavailable() -> SafeCommandError {
    SafeCommandError::new(
        "CANDIDATE_EXTRACTION_UNAVAILABLE",
        "Candidate memory extraction is temporarily unavailable.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::history::{
        AppendConversationTurnRequest, ConversationRepository, CreateConversationRequest,
    };
    use crate::storage::candidate_extraction::{
        commit_reconciliation_calls_for_test, reset_commit_reconciliation_calls_for_test,
        set_finalize_failpoint_for_test, set_reconciliation_read_unavailable_for_test,
        CandidateExtractionAttemptOutcome, CandidateExtractionBatch, CandidateExtractionRequest,
        CandidateExtractor, ExtractionError, ExtractorDescriptor, FinalizeFailpoint,
    };
    use crate::storage::{LifeIdentityRecord, PersonaTemplateRecord};
    use std::fs;

    fn setup() -> (StorageService, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "d7-trigger-facade-{}",
            crate::storage::unique_suffix()
        ));
        let project = root.join("project");
        fs::create_dir_all(&project).unwrap();
        let storage =
            StorageService::initialize_with_roots(root.join("default"), Some(project)).unwrap();
        storage
            .save_persona(PersonaTemplateRecord {
                id: "persona-d7".into(),
                name: "Persona".into(),
                version: 1,
                persona_json: "{}".into(),
            })
            .unwrap();
        storage
            .save_life(LifeIdentityRecord {
                id: "life-d7".into(),
                name: "Life".into(),
                created_at: "2026-01-01T00:00:00.000Z".into(),
                version: 1,
                body_id: "body".into(),
                persona_id: "persona-d7".into(),
                persona_version: 1,
            })
            .unwrap();
        (storage, root)
    }

    fn create_conversation(storage: &StorageService, id: &str) -> String {
        storage
            .create_conversation(
                id,
                &CreateConversationRequest {
                    life_id: "life-d7".into(),
                    title: "D7 test".into(),
                },
            )
            .unwrap()
            .id
    }

    fn append_turn(
        storage: &StorageService,
        conversation_id: &str,
        expected_revision: i64,
        turn_id: &str,
        user: &str,
    ) {
        storage
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-d7".into(),
                conversation_id: conversation_id.into(),
                turn_id: turn_id.into(),
                user_content: user.into(),
                assistant_content: "Acknowledged.".into(),
                expected_revision: Some(expected_revision),
            })
            .unwrap();
    }

    fn persisted_counts(storage: &StorageService) -> (i64, i64, i64, i64, i64) {
        let state = storage.state().unwrap();
        let run_count = state
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_extraction_run", [], |row| {
                row.get(0)
            })
            .unwrap();
        let candidate_count = state
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_memory", [], |row| {
                row.get(0)
            })
            .unwrap();
        let evidence_count = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory_evidence",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let candidate_audit_count = state
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_memory_audit", [], |row| {
                row.get(0)
            })
            .unwrap();
        let extraction_audit_count = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_extraction_audit",
                [],
                |row| row.get(0),
            )
            .unwrap();
        (
            run_count,
            candidate_count,
            evidence_count,
            candidate_audit_count,
            extraction_audit_count,
        )
    }

    #[derive(Debug, PartialEq, Eq)]
    struct RunObservation {
        id: String,
        status: String,
        attempt_sequence: i64,
        extractor_id: String,
        extractor_version: String,
        policy_version: String,
        created_count: i64,
        merged_evidence_count: i64,
        blocked_count: i64,
        last_error_code: Option<String>,
        updated_at: String,
        completed_at: Option<String>,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct DurableObservation {
        run: RunObservation,
        persisted_counts: (i64, i64, i64, i64, i64),
        snapshot_message_count: i64,
    }

    fn durable_observation(storage: &StorageService, conversation_id: &str) -> DurableObservation {
        let state = storage.state().unwrap();
        let run = state
            .connection
            .query_row(
                "SELECT id, status, attempt_sequence, extractor_id, extractor_version,
                        policy_version, created_count, evidence_merged_count,
                        hard_secret_blocked_count + sensitive_blocked_count,
                        last_error_code, updated_at, completed_at
                 FROM candidate_extraction_run
                 WHERE life_id = 'life-d7' AND conversation_id = ?1",
                params![conversation_id],
                |row| {
                    Ok(RunObservation {
                        id: row.get(0)?,
                        status: row.get(1)?,
                        attempt_sequence: row.get(2)?,
                        extractor_id: row.get(3)?,
                        extractor_version: row.get(4)?,
                        policy_version: row.get(5)?,
                        created_count: row.get(6)?,
                        merged_evidence_count: row.get(7)?,
                        blocked_count: row.get(8)?,
                        last_error_code: row.get(9)?,
                        updated_at: row.get(10)?,
                        completed_at: row.get(11)?,
                    })
                },
            )
            .unwrap();
        let snapshot_message_count = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_extraction_snapshot_message",
                [],
                |row| row.get(0),
            )
            .unwrap();
        drop(state);
        DurableObservation {
            run,
            persisted_counts: persisted_counts(storage),
            snapshot_message_count,
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum ExistingFixtureState {
        Processing,
        Completed,
        Failed,
    }

    #[derive(Clone, Copy, Debug)]
    enum DescriptorMismatch {
        ExtractorId,
        ExtractorVersion,
        PolicyVersion,
        Multiple,
    }

    struct FixedBatchExtractor {
        descriptor: ExtractorDescriptor,
    }

    impl CandidateExtractor for FixedBatchExtractor {
        fn descriptor(&self) -> &ExtractorDescriptor {
            &self.descriptor
        }

        fn extract<'a>(
            &'a self,
            _request: CandidateExtractionRequest,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<CandidateExtractionBatch, ExtractionError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(CandidateExtractionBatch::default()) })
        }
    }

    fn create_existing_run(
        storage: &StorageService,
        conversation_id: &str,
        state: ExistingFixtureState,
        descriptor: ExtractorDescriptor,
        policy_version: &str,
    ) {
        match state {
            ExistingFixtureState::Processing => {
                let _started = storage
                    .start_candidate_extraction(
                        "life-d7",
                        conversation_id,
                        descriptor,
                        policy_version,
                    )
                    .unwrap()
                    .unwrap();
            }
            ExistingFixtureState::Completed => {
                let started = storage
                    .start_candidate_extraction(
                        "life-d7",
                        conversation_id,
                        descriptor.clone(),
                        policy_version,
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    storage.run_candidate_extraction_attempt(
                        &FixedBatchExtractor { descriptor },
                        &started,
                        &ExtractionCancellation::new(),
                        None,
                    ),
                    CandidateExtractionAttemptOutcome::Completed
                );
            }
            ExistingFixtureState::Failed => {
                let started = storage
                    .start_candidate_extraction(
                        "life-d7",
                        conversation_id,
                        descriptor,
                        policy_version,
                    )
                    .unwrap()
                    .unwrap();
                storage
                    .fail_candidate_extraction_attempt(
                        &started,
                        "CANDIDATE_EXTRACTION_EXTRACTOR_CONTRACT_FAILURE",
                        false,
                    )
                    .unwrap();
            }
        }
    }

    fn mismatched_descriptor(mismatch: DescriptorMismatch) -> (ExtractorDescriptor, String) {
        let mut descriptor = deterministic_descriptor();
        let mut policy_version = SAFETY_POLICY_VERSION.to_owned();
        match mismatch {
            DescriptorMismatch::ExtractorId => descriptor.extractor_id = "old-extractor".into(),
            DescriptorMismatch::ExtractorVersion => {
                descriptor.extractor_version = "old-version".into();
            }
            DescriptorMismatch::PolicyVersion => policy_version = "old-policy".into(),
            DescriptorMismatch::Multiple => {
                descriptor.extractor_id = "old-extractor".into();
                descriptor.extractor_version = "old-version".into();
                policy_version = "old-policy".into();
            }
        }
        (descriptor, policy_version)
    }

    fn reopen(root: &std::path::Path) -> StorageService {
        StorageService::initialize_with_roots(root.join("default"), Some(root.join("project")))
            .unwrap()
    }

    #[test]
    fn facade_executes_d6_pipeline_and_persists_exact_sqlite_counts() {
        let (storage, root) = setup();
        let conversation_id = create_conversation(&storage, "conv-e2e");
        append_turn(&storage, &conversation_id, 0, "turn-1", "我喜欢喝茶");

        let response =
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap();
        assert_eq!(response.status, ExtractionTriggerStatus::Completed);
        assert_eq!(response.created_count, Some(1));
        assert_eq!(response.merged_evidence_count, Some(0));

        let state = storage.state().unwrap();
        let run_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_extraction_run", [], |row| {
                row.get(0)
            })
            .unwrap();
        let candidate_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_memory", [], |row| {
                row.get(0)
            })
            .unwrap();
        let evidence_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_memory_evidence",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let candidate_audit_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_memory_audit", [], |row| {
                row.get(0)
            })
            .unwrap();
        let extraction_audit_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM candidate_extraction_audit",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            (
                run_count,
                candidate_count,
                evidence_count,
                candidate_audit_count,
                extraction_audit_count
            ),
            (1, 1, 1, 1, 2)
        );
        drop(state);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn same_revision_is_idempotent_and_new_revision_creates_one_new_run() {
        let (storage, root) = setup();
        let conversation_id = create_conversation(&storage, "conv-idempotent");
        append_turn(&storage, &conversation_id, 0, "turn-1", "I like tea.");
        let first =
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap();
        let replay =
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap();
        assert_eq!(first, replay);
        append_turn(&storage, &conversation_id, 1, "turn-2", "I prefer coffee.");
        let next =
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap();
        assert_eq!(next.status, ExtractionTriggerStatus::Completed);
        let state = storage.state().unwrap();
        let run_count: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_extraction_run", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(run_count, 2);
        drop(state);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn matching_completed_descriptor_reuses_counts_without_another_attempt() {
        let (storage, root) = setup();
        let conversation_id = create_conversation(&storage, "conv-matching-descriptor");
        append_turn(&storage, &conversation_id, 0, "turn-1", "I like tea.");

        reset_deterministic_attempt_calls_for_test();
        let first =
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap();
        assert_eq!(first.status, ExtractionTriggerStatus::Completed);
        assert_eq!(deterministic_attempt_calls_for_test(), 1);
        let before = durable_observation(&storage, &conversation_id);

        reset_deterministic_attempt_calls_for_test();
        reset_commit_reconciliation_calls_for_test();
        let replay =
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap();

        assert_eq!(replay, first);
        assert_eq!(deterministic_attempt_calls_for_test(), 0);
        assert_eq!(commit_reconciliation_calls_for_test(), 0);
        assert_eq!(durable_observation(&storage, &conversation_id), before);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn descriptor_mismatches_are_stale_across_fields_and_run_states() {
        for (name, state, mismatch) in [
            (
                "id-completed",
                ExistingFixtureState::Completed,
                DescriptorMismatch::ExtractorId,
            ),
            (
                "version-processing",
                ExistingFixtureState::Processing,
                DescriptorMismatch::ExtractorVersion,
            ),
            (
                "policy-failed",
                ExistingFixtureState::Failed,
                DescriptorMismatch::PolicyVersion,
            ),
            (
                "multiple-completed",
                ExistingFixtureState::Completed,
                DescriptorMismatch::Multiple,
            ),
        ] {
            let (storage, root) = setup();
            let conversation_id = create_conversation(&storage, &format!("conv-{name}"));
            append_turn(&storage, &conversation_id, 0, "turn-1", "I like tea.");
            let (descriptor, policy_version) = mismatched_descriptor(mismatch);
            create_existing_run(
                &storage,
                &conversation_id,
                state,
                descriptor,
                &policy_version,
            );
            let before = durable_observation(&storage, &conversation_id);

            reset_deterministic_attempt_calls_for_test();
            reset_commit_reconciliation_calls_for_test();
            let response =
                trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                    .unwrap();

            assert_eq!(
                response,
                simple_response(ExtractionTriggerStatus::StaleOrConflict),
                "{name}: descriptor mismatch must fail closed"
            );
            assert_eq!(
                deterministic_attempt_calls_for_test(),
                0,
                "{name}: extractor attempt must not run"
            );
            assert_eq!(
                commit_reconciliation_calls_for_test(),
                0,
                "{name}: reconciliation must not run"
            );
            assert_eq!(
                durable_observation(&storage, &conversation_id),
                before,
                "{name}: mismatch must not mutate durable state"
            );
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn processing_start_race_rereads_and_compares_the_winning_descriptor() {
        for (name, mismatched) in [("matching", false), ("mismatched", true)] {
            let (storage, root) = setup();
            let conversation_id = create_conversation(&storage, &format!("conv-race-{name}"));
            append_turn(&storage, &conversation_id, 0, "turn-1", "I like tea.");
            let competing_storage = reopen(&root);
            let competing_conversation_id = conversation_id.clone();
            let mut competing_descriptor = deterministic_descriptor();
            if mismatched {
                competing_descriptor.extractor_id = "competing-extractor".into();
            }
            set_before_start_hook_for_test(move || {
                let _winning_attempt = competing_storage
                    .start_candidate_extraction(
                        "life-d7",
                        &competing_conversation_id,
                        competing_descriptor,
                        SAFETY_POLICY_VERSION,
                    )
                    .unwrap()
                    .unwrap();
            });

            reset_deterministic_attempt_calls_for_test();
            reset_commit_reconciliation_calls_for_test();
            let response =
                trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                    .unwrap();

            assert_eq!(
                response.status,
                if mismatched {
                    ExtractionTriggerStatus::StaleOrConflict
                } else {
                    ExtractionTriggerStatus::Processing
                }
            );
            assert_eq!(deterministic_attempt_calls_for_test(), 0);
            assert_eq!(commit_reconciliation_calls_for_test(), 0);
            let observation = durable_observation(&storage, &conversation_id);
            assert_eq!(observation.run.attempt_sequence, 1);
            assert_eq!(observation.persisted_counts, (1, 0, 0, 0, 1));
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn completed_unique_race_rereads_without_a_second_candidate_chain() {
        for (name, mismatched) in [("matching", false), ("mismatched", true)] {
            let (storage, root) = setup();
            let conversation_id =
                create_conversation(&storage, &format!("conv-completed-race-{name}"));
            append_turn(&storage, &conversation_id, 0, "turn-1", "I like tea.");
            let competing_storage = reopen(&root);
            let competing_conversation_id = conversation_id.clone();
            let (competing_descriptor, competing_policy_version) = if mismatched {
                mismatched_descriptor(DescriptorMismatch::ExtractorId)
            } else {
                (deterministic_descriptor(), SAFETY_POLICY_VERSION.to_owned())
            };
            set_before_start_hook_for_test(move || {
                let started = competing_storage
                    .start_candidate_extraction(
                        "life-d7",
                        &competing_conversation_id,
                        competing_descriptor.clone(),
                        &competing_policy_version,
                    )
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    competing_storage.run_candidate_extraction_attempt(
                        &FixedBatchExtractor {
                            descriptor: competing_descriptor,
                        },
                        &started,
                        &ExtractionCancellation::new(),
                        None,
                    ),
                    CandidateExtractionAttemptOutcome::Completed
                );
            });

            reset_deterministic_attempt_calls_for_test();
            reset_commit_reconciliation_calls_for_test();
            let response =
                trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                    .unwrap();

            assert_eq!(
                response.status,
                if mismatched {
                    ExtractionTriggerStatus::StaleOrConflict
                } else {
                    ExtractionTriggerStatus::Completed
                }
            );
            assert_eq!(deterministic_attempt_calls_for_test(), 0);
            assert_eq!(commit_reconciliation_calls_for_test(), 0);
            let observation = durable_observation(&storage, &conversation_id);
            assert_eq!(observation.run.attempt_sequence, 1);
            assert_eq!(observation.persisted_counts, (1, 0, 0, 0, 2));
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn facade_returns_safe_statuses_and_never_serializes_internal_material() {
        let (storage, root) = setup();
        let conversation_id = create_conversation(&storage, "conv-safe");
        assert_eq!(
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap()
                .status,
            ExtractionTriggerStatus::NoEligibleSnapshot
        );
        let error =
            trigger_deterministic_candidate_extraction(&storage, "other-life", &conversation_id)
                .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_EXTRACTION_CONVERSATION_NOT_FOUND");
        let response = simple_response(ExtractionTriggerStatus::RetryWait);
        let exposed = format!(
            "{}{:?}",
            serde_json::to_string(&response).unwrap(),
            response
        );
        for forbidden in [
            "run_id",
            "attempt_sequence",
            "token",
            "digest",
            "snapshot",
            "message_id",
            "select",
            "sqlite",
        ] {
            assert!(!exposed.to_lowercase().contains(forbidden));
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn post_commit_uncertainty_reconciles_through_the_real_d7_facade() {
        let (storage, root) = setup();
        let conversation_id = create_conversation(&storage, "conv-uncertain");
        append_turn(&storage, &conversation_id, 0, "turn-1", "I like tea.");

        reset_commit_reconciliation_calls_for_test();
        set_finalize_failpoint_for_test(Some(FinalizeFailpoint::PostCommitResponseUncertain));
        let response =
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap();
        assert_eq!(response.status, ExtractionTriggerStatus::Completed);
        assert_eq!(response.created_count, Some(1));
        assert_eq!(commit_reconciliation_calls_for_test(), 1);
        assert_eq!(persisted_counts(&storage), (1, 1, 1, 1, 2));

        let replay =
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap();
        assert_eq!(replay, response);
        assert_eq!(commit_reconciliation_calls_for_test(), 1);
        assert_eq!(persisted_counts(&storage), (1, 1, 1, 1, 2));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ordinary_storage_failure_never_reconciles_or_uses_a_completed_run_as_proof() {
        let (storage, root) = setup();
        let conversation_id = create_conversation(&storage, "conv-storage-failure");
        append_turn(&storage, &conversation_id, 0, "turn-1", "I like tea.");
        trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id).unwrap();
        let before = persisted_counts(&storage);

        reset_commit_reconciliation_calls_for_test();
        let error = response_from_attempt_outcome(
            &storage,
            "life-d7",
            &conversation_id,
            CandidateExtractionAttemptOutcome::StorageFailure,
        )
        .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_EXTRACTION_UNAVAILABLE");
        assert_eq!(commit_reconciliation_calls_for_test(), 0);
        assert_eq!(persisted_counts(&storage), before);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ordinary_storage_failure_from_the_real_pipeline_never_reconciles() {
        let (storage, root) = setup();
        let conversation_id = create_conversation(&storage, "conv-ordinary-failure");
        append_turn(&storage, &conversation_id, 0, "turn-1", "I like tea.");

        reset_commit_reconciliation_calls_for_test();
        set_finalize_failpoint_for_test(Some(FinalizeFailpoint::BeforeCommit));
        let error =
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_EXTRACTION_UNAVAILABLE");
        assert_eq!(commit_reconciliation_calls_for_test(), 0);
        assert_eq!(persisted_counts(&storage).1, 0);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn uncertainty_reconciliation_read_failure_returns_unavailable_without_replay() {
        let (storage, root) = setup();
        let conversation_id = create_conversation(&storage, "conv-reconcile-read-failure");
        append_turn(&storage, &conversation_id, 0, "turn-1", "I like tea.");

        reset_commit_reconciliation_calls_for_test();
        set_finalize_failpoint_for_test(Some(FinalizeFailpoint::PostCommitResponseUncertain));
        set_reconciliation_read_unavailable_for_test(true);
        let error =
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap_err();
        set_reconciliation_read_unavailable_for_test(false);
        assert_eq!(error.code, "CANDIDATE_EXTRACTION_UNAVAILABLE");
        assert_eq!(commit_reconciliation_calls_for_test(), 1);
        assert_eq!(persisted_counts(&storage), (1, 1, 1, 1, 2));

        let retry =
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap();
        assert_eq!(retry.status, ExtractionTriggerStatus::Completed);
        assert_eq!(persisted_counts(&storage), (1, 1, 1, 1, 2));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn typed_uncertainty_debug_output_redacts_internal_identity() {
        let (storage, root) = setup();
        let conversation_id = create_conversation(&storage, "conv-private-run-id");
        append_turn(&storage, &conversation_id, 0, "turn-private", "I like tea.");
        let started = storage
            .start_candidate_extraction(
                "life-d7",
                &conversation_id,
                deterministic_descriptor(),
                SAFETY_POLICY_VERSION,
            )
            .unwrap()
            .unwrap();
        set_finalize_failpoint_for_test(Some(FinalizeFailpoint::PostCommitResponseUncertain));
        let outcome = storage.run_candidate_extraction_attempt(
            &DeterministicCandidateExtractor::new(),
            &started,
            &ExtractionCancellation::new(),
            None,
        );
        assert!(matches!(
            &outcome,
            CandidateExtractionAttemptOutcome::CommitOutcomeUncertain(_)
        ));
        let debug = format!("{outcome:?}").to_lowercase();
        for forbidden in [
            "conv-private-run-id",
            "turn-private",
            "token",
            "digest",
            "snapshot",
            "message",
            "select",
            "sqlite",
        ] {
            assert!(!debug.contains(forbidden));
        }
        let _ = fs::remove_dir_all(root);
    }
}
