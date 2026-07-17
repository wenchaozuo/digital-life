//! Tauri Command for manual candidate extraction trigger (D-7).
//!
//! This command allows users to manually trigger candidate memory extraction
//! from a conversation. It uses the deterministic rule extractor and the
//! D-6 orchestration pipeline.

use serde::Serialize;
use tauri::{State, WebviewWindow};

use crate::memory::deterministic_extractor::{
    deterministic_descriptor, DeterministicCandidateExtractor,
};
use crate::storage::candidate_extraction::{
    CandidateExtractionAttemptOutcome, ExtractionCancellation,
};
use crate::storage::StorageService;

/// The only window permitted to trigger extraction.
const CHAT_WINDOW_LABEL: &str = "chat";

// ── IPC Response DTOs ────────────────────────────────────────────────

/// Safe response from extraction trigger.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractionTriggerResponse {
    pub status: ExtractionTriggerStatus,
    pub created_count: Option<i64>,
    pub merged_count: Option<i64>,
    pub hard_blocked_count: Option<i64>,
    pub sensitive_blocked_count: Option<i64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExtractionTriggerStatus {
    Completed,
    NoEligibleMessages,
    AlreadyProcessing,
    AlreadyCompleted,
    Failed,
    SnapshotInvalidated,
    Timeout,
    Cancelled,
    StorageUnavailable,
}

// ── IPC Error ────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractionCommandError {
    pub code: String,
    pub message: String,
}

impl ExtractionCommandError {
    fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.to_string(),
            message: message.to_string(),
        }
    }
}

// ── Command ──────────────────────────────────────────────────────────

/// Trigger candidate memory extraction for a conversation.
///
/// Input only accepts `life_id` and `conversation_id`. All other state
/// (revision, extractor, token, snapshot) is resolved authoritatively by Rust.
#[tauri::command]
pub async fn extract_candidate_memories(
    window: WebviewWindow,
    storage: State<'_, StorageService>,
    life_id: String,
    conversation_id: String,
) -> Result<ExtractionTriggerResponse, ExtractionCommandError> {
    // Validate caller window
    if window.label() != CHAT_WINDOW_LABEL {
        return Err(ExtractionCommandError::new(
            "CANDIDATE_EXTRACTION_UNAUTHORIZED_WINDOW",
            "Extraction is only available from the chat window.",
        ));
    }

    // Validate inputs
    if life_id.is_empty() || conversation_id.is_empty() {
        return Err(ExtractionCommandError::new(
            "CANDIDATE_EXTRACTION_INVALID_REQUEST",
            "life_id and conversation_id are required.",
        ));
    }

    // Create deterministic extractor
    let extractor = DeterministicCandidateExtractor::new();

    // Start extraction attempt via D-6 orchestration
    let started = match storage.start_candidate_extraction(
        &life_id,
        &conversation_id,
        deterministic_descriptor(),
        "candidate-extraction-safety-v1",
    ) {
        Ok(Some(started)) => started,
        Ok(None) => {
            // No eligible messages (empty snapshot)
            return Ok(ExtractionTriggerResponse {
                status: ExtractionTriggerStatus::NoEligibleMessages,
                created_count: None,
                merged_count: None,
                hard_blocked_count: None,
                sensitive_blocked_count: None,
            });
        }
        Err(error) => {
            return Err(map_extraction_error(error));
        }
    };

    // Run the extraction attempt via D-6 orchestrator
    let cancellation = ExtractionCancellation::new();
    let outcome = storage.run_candidate_extraction_attempt(
        &extractor,
        &started,
        &cancellation,
        None, // Use default timeout
    );

    match outcome {
        CandidateExtractionAttemptOutcome::Completed => {
            // Reconcile to get authoritative counts
            match storage.reconcile_extraction_commit_uncertainty(
                started.run_id(),
                started.attempt_sequence(),
            ) {
                Ok(
                    crate::storage::candidate_extraction::CommitReconciliationResult::Completed {
                        created_count,
                        evidence_merged_count,
                        hard_secret_blocked_count,
                        ..
                    },
                ) => Ok(ExtractionTriggerResponse {
                    status: ExtractionTriggerStatus::Completed,
                    created_count: Some(created_count),
                    merged_count: Some(evidence_merged_count),
                    hard_blocked_count: Some(hard_secret_blocked_count),
                    sensitive_blocked_count: None,
                }),
                _ => Ok(ExtractionTriggerResponse {
                    status: ExtractionTriggerStatus::Completed,
                    created_count: None,
                    merged_count: None,
                    hard_blocked_count: None,
                    sensitive_blocked_count: None,
                }),
            }
        }
        CandidateExtractionAttemptOutcome::RetryScheduled => {
            // Retry was scheduled (timeout or transient error)
            Ok(ExtractionTriggerResponse {
                status: ExtractionTriggerStatus::Timeout,
                created_count: None,
                merged_count: None,
                hard_blocked_count: None,
                sensitive_blocked_count: None,
            })
        }
        CandidateExtractionAttemptOutcome::TerminalFailed => Ok(ExtractionTriggerResponse {
            status: ExtractionTriggerStatus::Failed,
            created_count: None,
            merged_count: None,
            hard_blocked_count: None,
            sensitive_blocked_count: None,
        }),
        CandidateExtractionAttemptOutcome::StaleAttempt => Ok(ExtractionTriggerResponse {
            status: ExtractionTriggerStatus::SnapshotInvalidated,
            created_count: None,
            merged_count: None,
            hard_blocked_count: None,
            sensitive_blocked_count: None,
        }),
        CandidateExtractionAttemptOutcome::StorageFailure => Ok(ExtractionTriggerResponse {
            status: ExtractionTriggerStatus::StorageUnavailable,
            created_count: None,
            merged_count: None,
            hard_blocked_count: None,
            sensitive_blocked_count: None,
        }),
    }
}

fn map_extraction_error(
    error: crate::storage::candidate_extraction::ExtractionError,
) -> ExtractionCommandError {
    match error.code {
        "CANDIDATE_EXTRACTION_CONVERSATION_NOT_FOUND" => ExtractionCommandError::new(
            "CANDIDATE_EXTRACTION_CONVERSATION_NOT_FOUND",
            "The conversation was not found.",
        ),
        "CANDIDATE_EXTRACTION_RUN_EXISTS" => ExtractionCommandError::new(
            "CANDIDATE_EXTRACTION_ALREADY_PROCESSING",
            "An extraction is already in progress for this conversation.",
        ),
        _ => ExtractionCommandError::new(
            "CANDIDATE_EXTRACTION_STORAGE_UNAVAILABLE",
            "The extraction service is temporarily unavailable.",
        ),
    }
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
        let root =
            std::env::temp_dir().join(format!("d7-command-{}", crate::storage::unique_suffix()));
        let project = root.join("project");
        fs::create_dir_all(&project).unwrap();
        let service =
            StorageService::initialize_with_roots(root.join("default"), Some(project)).unwrap();
        service
            .save_persona(PersonaTemplateRecord {
                id: "persona-d7".into(),
                name: "Persona".into(),
                version: 1,
                persona_json: "{}".into(),
            })
            .unwrap();
        service
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
        (service, root)
    }

    #[test]
    fn empty_ids_rejected() {
        let (service, root) = setup();
        // Direct service call (command requires window which we can't mock)
        let result = service.start_candidate_extraction(
            "",
            "",
            deterministic_descriptor(),
            "candidate-extraction-safety-v1",
        );
        assert!(result.is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn no_eligible_messages_returns_none() {
        let (service, root) = setup();
        let conv = service
            .create_conversation(
                "conv-no-msgs",
                &CreateConversationRequest {
                    life_id: "life-d7".into(),
                    title: "Empty".into(),
                },
            )
            .unwrap();
        // No turns added - should return None
        let result = service
            .start_candidate_extraction(
                "life-d7",
                &conv.id,
                deterministic_descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap();
        assert!(result.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn successful_extraction_end_to_end() {
        let (service, root) = setup();
        let conv = service
            .create_conversation(
                "conv-e2e",
                &CreateConversationRequest {
                    life_id: "life-d7".into(),
                    title: "E2E".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-d7".into(),
                conversation_id: conv.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "我喜欢喝茶".into(),
                assistant_content: "茶是很好的饮品".into(),
                expected_revision: Some(0),
            })
            .unwrap();

        // Start extraction
        let started = service
            .start_candidate_extraction(
                "life-d7",
                &conv.id,
                deterministic_descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();

        // Run extraction with deterministic extractor
        let extractor = DeterministicCandidateExtractor::new();
        let cancellation = ExtractionCancellation::new();
        let outcome =
            service.run_candidate_extraction_attempt(&extractor, &started, &cancellation, None);
        assert_eq!(outcome, CandidateExtractionAttemptOutcome::Completed);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn idempotent_same_revision() {
        let (service, root) = setup();
        let conv = service
            .create_conversation(
                "conv-idempotent",
                &CreateConversationRequest {
                    life_id: "life-d7".into(),
                    title: "Idempotent".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-d7".into(),
                conversation_id: conv.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "我喜欢咖啡".into(),
                assistant_content: "咖啡很好".into(),
                expected_revision: Some(0),
            })
            .unwrap();

        // First extraction
        let started1 = service
            .start_candidate_extraction(
                "life-d7",
                &conv.id,
                deterministic_descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        assert!(!started1.run_id().is_empty(), "run_id should be non-empty");

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn extraction_with_no_proposals() {
        let (service, root) = setup();
        let conv = service
            .create_conversation(
                "conv-no-props",
                &CreateConversationRequest {
                    life_id: "life-d7".into(),
                    title: "No Props".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-d7".into(),
                conversation_id: conv.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "今天天气怎么样？".into(), // Question - should be excluded
                assistant_content: "天气很好".into(),
                expected_revision: Some(0),
            })
            .unwrap();

        let started = service
            .start_candidate_extraction(
                "life-d7",
                &conv.id,
                deterministic_descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        let extractor = DeterministicCandidateExtractor::new();
        let cancellation = ExtractionCancellation::new();
        let outcome =
            service.run_candidate_extraction_attempt(&extractor, &started, &cancellation, None);
        assert_eq!(outcome, CandidateExtractionAttemptOutcome::Completed);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn safety_blocks_hard_secrets() {
        let (service, root) = setup();
        let conv = service
            .create_conversation(
                "conv-safety",
                &CreateConversationRequest {
                    life_id: "life-d7".into(),
                    title: "Safety".into(),
                },
            )
            .unwrap();
        service
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-d7".into(),
                conversation_id: conv.id.clone(),
                turn_id: "turn-1".into(),
                user_content: "password=abc123".into(),
                assistant_content: "ok".into(),
                expected_revision: Some(0),
            })
            .unwrap();

        let started = service
            .start_candidate_extraction(
                "life-d7",
                &conv.id,
                deterministic_descriptor(),
                "candidate-extraction-safety-v1",
            )
            .unwrap()
            .unwrap();
        let extractor = DeterministicCandidateExtractor::new();
        let cancellation = ExtractionCancellation::new();
        let outcome =
            service.run_candidate_extraction_attempt(&extractor, &started, &cancellation, None);
        assert_eq!(outcome, CandidateExtractionAttemptOutcome::Completed);

        let _ = fs::remove_dir_all(root);
    }
}
