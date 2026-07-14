use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::storage::StorageService;

pub mod candidate;
pub mod candidate_service;
pub mod context_builder;
pub mod management;
pub mod retrieval;
pub mod retrieval_router;
pub mod retrieval_runtime;
pub mod revisions;
pub mod vector_index;
pub mod vector_index_runtime;
pub mod vector_sync_outbox;
pub mod vector_sync_worker;

#[cfg(test)]
mod vector_conversation_integration_tests;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    Experience,
    Preference,
    Fact,
    Relationship,
    Goal,
    Skill,
    Other,
}

impl MemoryKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Experience => "experience",
            Self::Preference => "preference",
            Self::Fact => "fact",
            Self::Relationship => "relationship",
            Self::Goal => "goal",
            Self::Skill => "skill",
            Self::Other => "other",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, MemoryError> {
        match value {
            "experience" => Ok(Self::Experience),
            "preference" => Ok(Self::Preference),
            "fact" => Ok(Self::Fact),
            "relationship" => Ok(Self::Relationship),
            "goal" => Ok(Self::Goal),
            "skill" => Ok(Self::Skill),
            "other" => Ok(Self::Other),
            _ => Err(MemoryError::database()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryStatus {
    Candidate,
    Confirmed,
}

impl MemoryStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Confirmed => "confirmed",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, MemoryError> {
        match value {
            "candidate" => Ok(Self::Candidate),
            "confirmed" => Ok(Self::Confirmed),
            _ => Err(MemoryError::database()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemorySourceType {
    Manual,
    Conversation,
    System,
    Import,
}

impl MemorySourceType {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Conversation => "conversation",
            Self::System => "system",
            Self::Import => "import",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, MemoryError> {
        match value {
            "manual" => Ok(Self::Manual),
            "conversation" => Ok(Self::Conversation),
            "system" => Ok(Self::System),
            "import" => Ok(Self::Import),
            _ => Err(MemoryError::database()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRecord {
    pub id: String,
    pub life_id: String,
    pub kind: MemoryKind,
    pub status: MemoryStatus,
    pub content: String,
    pub summary: Option<String>,
    pub source_type: MemorySourceType,
    pub source_ref: Option<String>,
    pub source_created_at: String,
    pub importance: f64,
    pub confidence: f64,
    pub is_sensitive: bool,
    pub created_at: String,
    pub updated_at: String,
    pub confirmed_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateMemoryCandidateRequest {
    pub life_id: String,
    pub kind: MemoryKind,
    pub content: String,
    pub summary: Option<String>,
    pub source_type: MemorySourceType,
    pub source_ref: Option<String>,
    pub source_created_at: String,
    pub importance: f64,
    pub confidence: f64,
    pub is_sensitive: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateMemoryRequest {
    pub life_id: String,
    pub memory_id: String,
    pub kind: MemoryKind,
    pub content: String,
    pub summary: Option<String>,
    pub source_type: MemorySourceType,
    pub source_ref: Option<String>,
    pub source_created_at: String,
    pub importance: f64,
    pub confidence: f64,
    pub is_sensitive: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmMemoryRequest {
    pub life_id: String,
    pub memory_id: String,
    pub user_confirmed: bool,
    pub sensitive_consent: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryQuery {
    pub life_id: String,
    pub status: Option<MemoryStatus>,
    pub kind: Option<MemoryKind>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteMemoryResult {
    pub memory_id: String,
    pub deleted: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryError {
    pub code: String,
    pub message: String,
    pub recoverable: bool,
}

impl MemoryError {
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::new("INVALID_ARGUMENT", message, true)
    }

    pub(crate) fn not_found() -> Self {
        Self::new(
            "MEMORY_NOT_FOUND",
            "The requested memory was not found.",
            true,
        )
    }

    pub(crate) fn life_mismatch() -> Self {
        Self::new(
            "MEMORY_LIFE_MISMATCH",
            "The memory does not belong to the specified life.",
            false,
        )
    }

    pub(crate) fn invalid_transition() -> Self {
        Self::new(
            "INVALID_STATE_TRANSITION",
            "Only candidate memories can be updated or confirmed.",
            true,
        )
    }

    pub(crate) fn database() -> Self {
        Self::new(
            "DATABASE_ERROR",
            "The memory storage operation failed.",
            true,
        )
    }

    pub(crate) fn not_confirmed() -> Self {
        Self::new(
            "MEMORY_NOT_CONFIRMED",
            "Only confirmed memories can be revised.",
            true,
        )
    }

    pub(crate) fn revision_conflict() -> Self {
        Self::new(
            "MEMORY_REVISION_CONFLICT",
            "The memory changed after it was loaded. Refresh and try again.",
            true,
        )
    }

    pub(crate) fn delete_conflict() -> Self {
        Self::new(
            "MEMORY_DELETE_CONFLICT",
            "The memory changed after it was loaded and was not deleted.",
            true,
        )
    }

    pub(crate) fn new(code: &str, message: impl Into<String>, recoverable: bool) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
            recoverable,
        }
    }
}

pub trait MemoryRepository {
    fn create_candidate(
        &self,
        id: &str,
        request: CreateMemoryCandidateRequest,
    ) -> Result<MemoryRecord, MemoryError>;
    fn list(&self, query: MemoryQuery) -> Result<Vec<MemoryRecord>, MemoryError>;
    fn get(&self, life_id: &str, memory_id: &str) -> Result<MemoryRecord, MemoryError>;
    fn update_candidate(&self, request: UpdateMemoryRequest) -> Result<MemoryRecord, MemoryError>;
    fn confirm(&self, request: ConfirmMemoryRequest) -> Result<MemoryRecord, MemoryError>;
    fn delete(&self, life_id: &str, memory_id: &str) -> Result<DeleteMemoryResult, MemoryError>;
}

pub struct MemoryService<'a, R: MemoryRepository> {
    repository: &'a R,
}

impl<'a, R: MemoryRepository> MemoryService<'a, R> {
    pub fn new(repository: &'a R) -> Self {
        Self { repository }
    }

    pub fn create_candidate(
        &self,
        request: CreateMemoryCandidateRequest,
    ) -> Result<MemoryRecord, MemoryError> {
        validate_life_id(&request.life_id)?;
        validate_memory_content(
            &request.content,
            &request.source_created_at,
            request.importance,
            request.confidence,
        )?;
        validate_source_ref(request.source_ref.as_deref())?;
        self.repository
            .create_candidate(&generate_memory_id(), request)
    }

    pub fn list(&self, query: MemoryQuery) -> Result<Vec<MemoryRecord>, MemoryError> {
        validate_life_id(&query.life_id)?;
        self.repository.list(query)
    }

    pub fn get(&self, life_id: &str, memory_id: &str) -> Result<MemoryRecord, MemoryError> {
        validate_identifiers(life_id, memory_id)?;
        self.repository.get(life_id, memory_id)
    }

    pub fn update_candidate(
        &self,
        request: UpdateMemoryRequest,
    ) -> Result<MemoryRecord, MemoryError> {
        validate_identifiers(&request.life_id, &request.memory_id)?;
        validate_memory_content(
            &request.content,
            &request.source_created_at,
            request.importance,
            request.confidence,
        )?;
        validate_source_ref(request.source_ref.as_deref())?;
        self.repository.update_candidate(request)
    }

    pub fn confirm(&self, request: ConfirmMemoryRequest) -> Result<MemoryRecord, MemoryError> {
        validate_identifiers(&request.life_id, &request.memory_id)?;
        if !request.user_confirmed {
            return Err(MemoryError::new(
                "USER_CONFIRMATION_REQUIRED",
                "Explicit user confirmation is required.",
                true,
            ));
        }
        self.repository.confirm(request)
    }

    pub fn delete(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<DeleteMemoryResult, MemoryError> {
        validate_identifiers(life_id, memory_id)?;
        self.repository.delete(life_id, memory_id)
    }
}

fn validate_life_id(life_id: &str) -> Result<(), MemoryError> {
    if life_id.trim().is_empty() {
        return Err(MemoryError::invalid("lifeId must not be empty."));
    }
    Ok(())
}

fn validate_identifiers(life_id: &str, memory_id: &str) -> Result<(), MemoryError> {
    validate_life_id(life_id)?;
    if memory_id.trim().is_empty() {
        return Err(MemoryError::invalid("memoryId must not be empty."));
    }
    Ok(())
}

fn validate_memory_content(
    content: &str,
    source_created_at: &str,
    importance: f64,
    confidence: f64,
) -> Result<(), MemoryError> {
    if content.trim().is_empty() {
        return Err(MemoryError::invalid("Memory content must not be empty."));
    }
    if source_created_at.trim().is_empty() {
        return Err(MemoryError::invalid("sourceCreatedAt must not be empty."));
    }
    if !importance.is_finite() || !(0.0..=1.0).contains(&importance) {
        return Err(MemoryError::invalid(
            "importance must be between 0.0 and 1.0.",
        ));
    }
    if !confidence.is_finite() || !(0.0..=1.0).contains(&confidence) {
        return Err(MemoryError::invalid(
            "confidence must be between 0.0 and 1.0.",
        ));
    }
    Ok(())
}

fn validate_source_ref(source_ref: Option<&str>) -> Result<(), MemoryError> {
    let Some(source_ref) = source_ref else {
        return Ok(());
    };
    let normalized = source_ref.to_ascii_lowercase();
    let credential_markers = [
        "authorization",
        "bearer ",
        "api_key",
        "api-key",
        "apikey",
        "x-api-key",
        "sk-",
        "tp-",
    ];
    if credential_markers
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        return Err(MemoryError::invalid(
            "sourceRef must not contain credentials or request headers.",
        ));
    }
    Ok(())
}

fn generate_memory_id() -> String {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("memory-{nanos}-{sequence}")
}

#[tauri::command]
pub fn create_memory_candidate(
    storage: State<'_, StorageService>,
    request: CreateMemoryCandidateRequest,
) -> Result<MemoryRecord, MemoryError> {
    MemoryService::new(storage.inner()).create_candidate(request)
}

#[tauri::command]
pub fn list_memories(
    storage: State<'_, StorageService>,
    query: MemoryQuery,
) -> Result<Vec<MemoryRecord>, MemoryError> {
    MemoryService::new(storage.inner()).list(query)
}

#[tauri::command]
pub fn get_memory(
    storage: State<'_, StorageService>,
    life_id: String,
    memory_id: String,
) -> Result<MemoryRecord, MemoryError> {
    MemoryService::new(storage.inner()).get(&life_id, &memory_id)
}

#[tauri::command]
pub fn update_memory_candidate(
    storage: State<'_, StorageService>,
    request: UpdateMemoryRequest,
) -> Result<MemoryRecord, MemoryError> {
    MemoryService::new(storage.inner()).update_candidate(request)
}

#[tauri::command]
pub fn confirm_memory(
    storage: State<'_, StorageService>,
    request: ConfirmMemoryRequest,
) -> Result<MemoryRecord, MemoryError> {
    MemoryService::new(storage.inner()).confirm(request)
}

#[tauri::command]
pub fn delete_memory(
    storage: State<'_, StorageService>,
    life_id: String,
    memory_id: String,
) -> Result<DeleteMemoryResult, MemoryError> {
    MemoryService::new(storage.inner()).delete(&life_id, &memory_id)
}

#[cfg(test)]
mod type_tests {
    use super::*;

    #[test]
    fn invalid_kind_and_status_are_rejected() {
        assert!(serde_json::from_str::<MemoryKind>("\"unknown\"").is_err());
        assert!(serde_json::from_str::<MemoryStatus>("\"archived\"").is_err());
    }
}
