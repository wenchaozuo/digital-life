//! Tauri command for the D-7 manual candidate-extraction action.
//!
//! The Command validates its caller and delegates every extraction decision to
//! the D-7 storage facade.  It deliberately cannot name any D-6 run, token,
//! fence, snapshot, or extractor capability type.

use tauri::{State, WebviewWindow};

use crate::storage::deterministic_candidate_extraction::{
    trigger_deterministic_candidate_extraction, ExtractionTriggerResponse, SafeCommandError,
};
use crate::storage::StorageService;

const CHAT_WINDOW_LABEL: &str = "chat";

#[tauri::command]
pub async fn extract_candidate_memories(
    window: WebviewWindow,
    storage: State<'_, StorageService>,
    life_id: String,
    conversation_id: String,
) -> Result<ExtractionTriggerResponse, SafeCommandError> {
    if window.label() != CHAT_WINDOW_LABEL {
        return Err(SafeCommandError::new(
            "CANDIDATE_EXTRACTION_UNAUTHORIZED_WINDOW",
            "Candidate memory extraction is only available from the chat window.",
        ));
    }
    trigger_deterministic_candidate_extraction(&storage, &life_id, &conversation_id)
}
