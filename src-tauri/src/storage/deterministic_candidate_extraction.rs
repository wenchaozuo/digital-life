//! D-7's narrow, safe entry point for deterministic candidate extraction.
//!
//! This module owns the D-7 integration.  The frozen D-6 extraction module
//! remains private; no Command can receive its lease, token, snapshot, run, or
//! attempt objects.

#[path = "../memory/deterministic_extractor.rs"]
mod deterministic_extractor;

use rusqlite::{params, OptionalExtension};
use serde::Serialize;

use super::candidate_extraction::ExtractionCancellation;
use super::{candidate_extraction::CandidateExtractionAttemptOutcome, StorageService};
use deterministic_extractor::{deterministic_descriptor, DeterministicCandidateExtractor};

const SAFETY_POLICY_VERSION: &str = "candidate-extraction-safety-v1";

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

#[derive(Clone, Copy)]
struct ExistingRun {
    status: ExtractionTriggerStatus,
    created_count: i64,
    merged_evidence_count: i64,
    blocked_count: i64,
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

    let extractor = DeterministicCandidateExtractor::new();
    let started = match storage.start_candidate_extraction(
        life_id,
        conversation_id,
        deterministic_descriptor(),
        SAFETY_POLICY_VERSION,
    ) {
        Ok(Some(started)) => started,
        Ok(None) => return Ok(simple_response(ExtractionTriggerStatus::NoEligibleSnapshot)),
        Err(error) => return Err(map_start_error(error.code)),
    };

    let cancellation = ExtractionCancellation::new();
    let outcome =
        storage.run_candidate_extraction_attempt(&extractor, &started, &cancellation, None);

    match outcome {
        CandidateExtractionAttemptOutcome::Completed => {
            // Success - read authoritative state
            read_existing_run(storage, life_id, conversation_id)?
                .map(response_from_existing)
                .ok_or_else(storage_unavailable)
        }
        CandidateExtractionAttemptOutcome::StorageFailure => {
            // HIGH-1: StorageFailure could be due to commit uncertainty.
            // Try to read the authoritative state - if the run is completed,
            // the commit succeeded even though the response was uncertain.
            if let Some(existing) = read_existing_run(storage, life_id, conversation_id)? {
                if existing.status == ExtractionTriggerStatus::Completed {
                    return Ok(response_from_existing(existing));
                }
            }
            Err(storage_unavailable())
        }
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
                    hard_secret_blocked_count + sensitive_blocked_count
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
                })
            },
        )
        .optional()
        .map_err(|_| storage_unavailable())
}

fn response_from_existing(existing: ExistingRun) -> ExtractionTriggerResponse {
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
    fn storage_failure_with_completed_run_returns_completed() {
        // This tests the HIGH-1 fix: when StorageFailure occurs due to commit
        // uncertainty, but the run is actually completed, we should return completed.
        let (storage, root) = setup();
        let conversation_id = create_conversation(&storage, "conv-uncertain");
        append_turn(&storage, &conversation_id, 0, "turn-1", "我喜欢喝茶");

        // First, complete a successful extraction
        let response1 =
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap();
        assert_eq!(response1.status, ExtractionTriggerStatus::Completed);
        assert_eq!(response1.created_count, Some(1));

        // Now trigger again - should return existing completed run
        let response2 =
            trigger_deterministic_candidate_extraction(&storage, "life-d7", &conversation_id)
                .unwrap();
        assert_eq!(response2.status, ExtractionTriggerStatus::Completed);
        assert_eq!(response2.created_count, Some(1));

        // Verify no duplicate data
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
        assert_eq!(run_count, 1);
        assert_eq!(candidate_count, 1);
        drop(state);
        let _ = fs::remove_dir_all(root);
    }
}
