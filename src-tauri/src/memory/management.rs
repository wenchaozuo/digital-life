use serde::{Deserialize, Serialize};
use tauri::State;

use crate::storage::StorageService;

use super::{
    revisions::{
        DeleteMemoryPermanentlyRequest, MemoryRevisionRecord, MemoryRevisionRepository,
        MemoryRevisionService, SetMemorySensitivityRequest, UpdateConfirmedMemoryRequest,
    },
    DeleteMemoryResult, MemoryError, MemoryKind, MemorySourceType, MemoryStatus,
};

pub const DEFAULT_MEMORY_PAGE_SIZE: usize = 30;
pub const MAX_MEMORY_PAGE_SIZE: usize = 100;
const MAX_MEMORY_QUERY_CHARACTERS: usize = 200;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedMemoryStatus {
    Candidate,
    Confirmed,
    #[default]
    All,
}

impl ManagedMemoryStatus {
    pub(crate) const fn as_filter(self) -> Option<&'static str> {
        match self {
            Self::Candidate => Some("candidate"),
            Self::Confirmed => Some("confirmed"),
            Self::All => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryListCursor {
    pub updated_at: String,
    pub id: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryListRequest {
    #[serde(default)]
    pub status: ManagedMemoryStatus,
    pub kind: Option<MemoryKind>,
    pub sensitive: Option<bool>,
    pub query: Option<String>,
    pub page_size: Option<usize>,
    pub cursor: Option<MemoryListCursor>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedMemory {
    pub id: String,
    pub status: MemoryStatus,
    pub kind: MemoryKind,
    pub summary: Option<String>,
    pub is_sensitive: bool,
    pub revision: i64,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManagedMemoryDetail {
    pub id: String,
    pub status: MemoryStatus,
    pub kind: MemoryKind,
    pub content: String,
    pub summary: Option<String>,
    pub is_sensitive: bool,
    pub source: MemorySourceType,
    pub importance: f64,
    pub confidence: f64,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
    pub revision_count: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryListResult {
    pub items: Vec<ManagedMemory>,
    pub next_cursor: Option<MemoryListCursor>,
}

#[derive(Clone, Debug)]
pub struct ManagedMemoryListQuery {
    pub life_id: String,
    pub status: ManagedMemoryStatus,
    pub kind: Option<MemoryKind>,
    pub sensitive: Option<bool>,
    pub query: Option<String>,
    pub page_size: usize,
    pub cursor: Option<MemoryListCursor>,
}

pub trait MemoryManagementRepository: MemoryRevisionRepository {
    fn list_managed_memories(
        &self,
        query: ManagedMemoryListQuery,
    ) -> Result<MemoryListResult, MemoryError>;
    fn get_managed_memory(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<ManagedMemoryDetail, MemoryError>;
}

pub struct MemoryManagementService<'a, R: MemoryManagementRepository> {
    repository: &'a R,
}

impl<'a, R: MemoryManagementRepository> MemoryManagementService<'a, R> {
    pub fn new(repository: &'a R) -> Self {
        Self { repository }
    }

    pub fn list(
        &self,
        life_id: &str,
        request: MemoryListRequest,
    ) -> Result<MemoryListResult, MemoryError> {
        validate_id(life_id, "lifeId")?;
        let page_size = request.page_size.unwrap_or(DEFAULT_MEMORY_PAGE_SIZE);
        if page_size == 0 || page_size > MAX_MEMORY_PAGE_SIZE {
            return Err(management_error(
                "INVALID_MEMORY_QUERY",
                "Memory page size must be between 1 and 100.",
            ));
        }
        let query = match request.query {
            Some(query) => {
                let query = query.trim();
                if query.is_empty() || query.chars().count() > MAX_MEMORY_QUERY_CHARACTERS {
                    return Err(management_error(
                        "INVALID_MEMORY_QUERY",
                        "Memory query must contain between 1 and 200 characters.",
                    ));
                }
                Some(query.to_string())
            }
            None => None,
        };
        if request.cursor.as_ref().is_some_and(|cursor| {
            cursor.updated_at.trim().is_empty() || cursor.id.trim().is_empty()
        }) {
            return Err(management_error(
                "INVALID_MEMORY_QUERY",
                "Memory cursor is invalid.",
            ));
        }
        self.repository
            .list_managed_memories(ManagedMemoryListQuery {
                life_id: life_id.to_string(),
                status: request.status,
                kind: request.kind,
                sensitive: request.sensitive,
                query,
                page_size,
                cursor: request.cursor,
            })
            .map_err(map_management_error)
    }

    pub fn get(&self, life_id: &str, memory_id: &str) -> Result<ManagedMemoryDetail, MemoryError> {
        validate_ids(life_id, memory_id)?;
        self.repository
            .get_managed_memory(life_id, memory_id)
            .map_err(map_management_error)
    }

    pub fn revisions(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<Vec<MemoryRevisionRecord>, MemoryError> {
        validate_ids(life_id, memory_id)?;
        MemoryRevisionService::new(self.repository)
            .list_revisions(life_id, memory_id)
            .map_err(map_management_error)
    }

    pub fn update(
        &self,
        request: UpdateConfirmedMemoryRequest,
    ) -> Result<ManagedMemoryDetail, MemoryError> {
        let life_id = request.life_id.clone();
        let memory_id = request.memory_id.clone();
        MemoryRevisionService::new(self.repository)
            .update_confirmed(request)
            .map_err(map_management_error)?;
        self.get(&life_id, &memory_id)
    }

    pub fn set_sensitive(
        &self,
        request: SetMemorySensitivityRequest,
    ) -> Result<ManagedMemoryDetail, MemoryError> {
        let life_id = request.life_id.clone();
        let memory_id = request.memory_id.clone();
        MemoryRevisionService::new(self.repository)
            .set_sensitivity(request)
            .map_err(map_management_error)?;
        self.get(&life_id, &memory_id)
    }

    pub fn delete(
        &self,
        request: DeleteMemoryPermanentlyRequest,
    ) -> Result<DeleteMemoryResult, MemoryError> {
        MemoryRevisionService::new(self.repository)
            .delete_permanently(request)
            .map_err(map_management_error)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryIdRequest {
    pub memory_id: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateConfirmedMemoryCommandRequest {
    pub memory_id: String,
    pub expected_revision: i64,
    pub kind: MemoryKind,
    pub content: String,
    pub summary: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetMemorySensitiveCommandRequest {
    pub memory_id: String,
    pub expected_revision: i64,
    pub is_sensitive: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteMemoryCommandRequest {
    pub memory_id: String,
    pub expected_revision: i64,
}

#[tauri::command]
pub fn list_managed_memories(
    storage: State<'_, StorageService>,
    request: MemoryListRequest,
) -> Result<MemoryListResult, MemoryError> {
    let life_id = current_life_id(storage.inner())?;
    MemoryManagementService::new(storage.inner()).list(&life_id, request)
}

#[tauri::command]
pub fn get_managed_memory(
    storage: State<'_, StorageService>,
    request: MemoryIdRequest,
) -> Result<ManagedMemoryDetail, MemoryError> {
    let life_id = current_life_id(storage.inner())?;
    MemoryManagementService::new(storage.inner()).get(&life_id, &request.memory_id)
}

#[tauri::command]
pub fn list_memory_revisions(
    storage: State<'_, StorageService>,
    request: MemoryIdRequest,
) -> Result<Vec<MemoryRevisionRecord>, MemoryError> {
    let life_id = current_life_id(storage.inner())?;
    MemoryManagementService::new(storage.inner()).revisions(&life_id, &request.memory_id)
}

#[tauri::command]
pub fn update_confirmed_memory(
    storage: State<'_, StorageService>,
    request: UpdateConfirmedMemoryCommandRequest,
) -> Result<ManagedMemoryDetail, MemoryError> {
    let life_id = current_life_id(storage.inner())?;
    MemoryManagementService::new(storage.inner()).update(UpdateConfirmedMemoryRequest {
        life_id,
        memory_id: request.memory_id,
        expected_revision: request.expected_revision,
        kind: request.kind,
        content: request.content,
        summary: request.summary,
    })
}

#[tauri::command]
pub fn set_memory_sensitive(
    storage: State<'_, StorageService>,
    request: SetMemorySensitiveCommandRequest,
) -> Result<ManagedMemoryDetail, MemoryError> {
    let life_id = current_life_id(storage.inner())?;
    MemoryManagementService::new(storage.inner()).set_sensitive(SetMemorySensitivityRequest {
        life_id,
        memory_id: request.memory_id,
        expected_revision: request.expected_revision,
        is_sensitive: request.is_sensitive,
    })
}

#[tauri::command]
pub fn delete_memory_permanently(
    storage: State<'_, StorageService>,
    request: DeleteMemoryCommandRequest,
) -> Result<DeleteMemoryResult, MemoryError> {
    let life_id = current_life_id(storage.inner())?;
    MemoryManagementService::new(storage.inner()).delete(DeleteMemoryPermanentlyRequest {
        life_id,
        memory_id: request.memory_id,
        expected_revision: request.expected_revision,
    })
}

fn current_life_id(storage: &StorageService) -> Result<String, MemoryError> {
    storage
        .get_current_life()
        .map_err(|_| management_storage_error())?
        .map(|life| life.id)
        .ok_or_else(|| management_error("MEMORY_NOT_FOUND", "No current life is available."))
}

fn validate_ids(life_id: &str, memory_id: &str) -> Result<(), MemoryError> {
    validate_id(life_id, "lifeId")?;
    validate_id(memory_id, "memoryId")
}

fn validate_id(value: &str, name: &str) -> Result<(), MemoryError> {
    if value.trim().is_empty() {
        return Err(management_error(
            "INVALID_MEMORY_QUERY",
            format!("{name} must not be empty."),
        ));
    }
    Ok(())
}

fn map_management_error(error: MemoryError) -> MemoryError {
    if error.code == "DATABASE_ERROR" {
        management_storage_error()
    } else if error.code == "INVALID_ARGUMENT" {
        management_error("INVALID_MEMORY_CONTENT", "The memory request is invalid.")
    } else {
        error
    }
}

fn management_storage_error() -> MemoryError {
    management_error(
        "MEMORY_STORAGE_UNAVAILABLE",
        "Memory storage is temporarily unavailable.",
    )
}

fn management_error(code: &str, message: impl Into<String>) -> MemoryError {
    MemoryError::new(code, message, true)
}
