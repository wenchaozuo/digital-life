use serde::{Deserialize, Serialize};

use super::{DeleteMemoryResult, MemoryError, MemoryKind, MemoryRecord};

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryRevisionChangeType {
    Confirmed,
    Edited,
    SensitivityChanged,
}

impl MemoryRevisionChangeType {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Edited => "edited",
            Self::SensitivityChanged => "sensitivity_changed",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, MemoryError> {
        match value {
            "confirmed" => Ok(Self::Confirmed),
            "edited" => Ok(Self::Edited),
            "sensitivity_changed" => Ok(Self::SensitivityChanged),
            _ => Err(MemoryError::database()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryRevisionRecord {
    pub revision: i64,
    pub kind: MemoryKind,
    pub content: String,
    pub summary: Option<String>,
    pub is_sensitive: bool,
    pub change_type: MemoryRevisionChangeType,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateConfirmedMemoryRequest {
    pub life_id: String,
    pub memory_id: String,
    pub expected_revision: i64,
    pub kind: MemoryKind,
    pub content: String,
    pub summary: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetMemorySensitivityRequest {
    pub life_id: String,
    pub memory_id: String,
    pub expected_revision: i64,
    pub is_sensitive: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteMemoryPermanentlyRequest {
    pub life_id: String,
    pub memory_id: String,
    pub expected_revision: i64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryUpdateResult {
    pub memory: MemoryRecord,
    pub revision: i64,
    pub changed: bool,
}

pub trait MemoryRevisionRepository {
    fn current_revision(&self, life_id: &str, memory_id: &str) -> Result<i64, MemoryError>;
    fn update_confirmed(
        &self,
        request: UpdateConfirmedMemoryRequest,
    ) -> Result<MemoryUpdateResult, MemoryError>;
    fn set_sensitivity(
        &self,
        request: SetMemorySensitivityRequest,
    ) -> Result<MemoryUpdateResult, MemoryError>;
    fn list_revisions(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<Vec<MemoryRevisionRecord>, MemoryError>;
    fn delete_permanently(
        &self,
        request: DeleteMemoryPermanentlyRequest,
    ) -> Result<DeleteMemoryResult, MemoryError>;
}

pub struct MemoryRevisionService<'a, R: MemoryRevisionRepository> {
    repository: &'a R,
}

impl<'a, R: MemoryRevisionRepository> MemoryRevisionService<'a, R> {
    pub fn new(repository: &'a R) -> Self {
        Self { repository }
    }

    pub fn current_revision(&self, life_id: &str, memory_id: &str) -> Result<i64, MemoryError> {
        validate_revision_request(life_id, memory_id, 1)?;
        self.repository.current_revision(life_id, memory_id)
    }

    pub fn update_confirmed(
        &self,
        mut request: UpdateConfirmedMemoryRequest,
    ) -> Result<MemoryUpdateResult, MemoryError> {
        validate_revision_request(
            &request.life_id,
            &request.memory_id,
            request.expected_revision,
        )?;
        let content = request.content.trim();
        if content.is_empty() || content.chars().count() > 32_000 {
            return Err(MemoryError::new(
                "INVALID_MEMORY_CONTENT",
                "Memory content must contain between 1 and 32000 characters.",
                true,
            ));
        }
        request.content = content.to_string();
        request.summary = normalize_optional(request.summary);
        self.repository.update_confirmed(request)
    }

    pub fn set_sensitivity(
        &self,
        request: SetMemorySensitivityRequest,
    ) -> Result<MemoryUpdateResult, MemoryError> {
        validate_revision_request(
            &request.life_id,
            &request.memory_id,
            request.expected_revision,
        )?;
        self.repository.set_sensitivity(request)
    }

    pub fn list_revisions(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<Vec<MemoryRevisionRecord>, MemoryError> {
        validate_revision_request(life_id, memory_id, 1)?;
        self.repository.list_revisions(life_id, memory_id)
    }

    pub fn delete_permanently(
        &self,
        request: DeleteMemoryPermanentlyRequest,
    ) -> Result<DeleteMemoryResult, MemoryError> {
        validate_revision_request(
            &request.life_id,
            &request.memory_id,
            request.expected_revision,
        )?;
        self.repository.delete_permanently(request)
    }
}

fn validate_revision_request(
    life_id: &str,
    memory_id: &str,
    expected_revision: i64,
) -> Result<(), MemoryError> {
    if life_id.trim().is_empty() || memory_id.trim().is_empty() || expected_revision <= 0 {
        return Err(MemoryError::new(
            "INVALID_ARGUMENT",
            "Memory identifiers and revision must be valid.",
            true,
        ));
    }
    Ok(())
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_string())
    })
}
