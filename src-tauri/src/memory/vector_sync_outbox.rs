use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryVectorSyncAction {
    Upsert,
    Delete,
}
impl MemoryVectorSyncAction {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Delete => "delete",
        }
    }
    pub(crate) fn parse(value: &str) -> Result<Self, MemoryVectorSyncOutboxError> {
        match value {
            "upsert" => Ok(Self::Upsert),
            "delete" => Ok(Self::Delete),
            _ => Err(MemoryVectorSyncOutboxError::new(
                MemoryVectorSyncOutboxErrorCode::InvalidSyncAction,
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryVectorSyncState {
    Pending,
    Processing,
    RetryWait,
    Blocked,
    Failed,
}
impl MemoryVectorSyncState {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Processing => "processing",
            Self::RetryWait => "retry_wait",
            Self::Blocked => "blocked",
            Self::Failed => "failed",
        }
    }
    pub(crate) fn parse(value: &str) -> Result<Self, MemoryVectorSyncOutboxError> {
        match value {
            "pending" => Ok(Self::Pending),
            "processing" => Ok(Self::Processing),
            "retry_wait" => Ok(Self::RetryWait),
            "blocked" => Ok(Self::Blocked),
            "failed" => Ok(Self::Failed),
            _ => Err(MemoryVectorSyncOutboxError::new(
                MemoryVectorSyncOutboxErrorCode::InvalidSyncState,
            )),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryVectorSyncJob {
    pub id: i64,
    pub life_id: String,
    pub memory_id: String,
    pub desired_action: MemoryVectorSyncAction,
    pub state: MemoryVectorSyncState,
    pub attempt_count: u32,
    pub next_attempt_at: Option<String>,
    pub lease_owner: Option<String>,
    pub lease_expires_at: Option<String>,
    pub last_error_code: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnqueueMemoryVectorSyncRequest {
    pub life_id: String,
    pub memory_id: String,
    pub desired_action: MemoryVectorSyncAction,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimMemoryVectorSyncRequest {
    pub life_id: String,
    pub lease_owner: String,
    pub lease_expires_at: String,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemoryVectorSyncOutboxErrorCode {
    OutboxUnavailable,
    InvalidSyncAction,
    InvalidSyncState,
    SyncJobNotFound,
    SyncJobLeaseConflict,
    SyncJobLifeMismatch,
    InternalError,
}
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct MemoryVectorSyncOutboxError {
    pub code: MemoryVectorSyncOutboxErrorCode,
    pub message: String,
    pub recoverable: bool,
}
impl MemoryVectorSyncOutboxError {
    pub(crate) fn new(code: MemoryVectorSyncOutboxErrorCode) -> Self {
        let (message, recoverable) = match code {
            MemoryVectorSyncOutboxErrorCode::OutboxUnavailable => {
                ("The memory vector sync outbox is unavailable.", true)
            }
            MemoryVectorSyncOutboxErrorCode::InvalidSyncAction => {
                ("The vector sync action is invalid.", false)
            }
            MemoryVectorSyncOutboxErrorCode::InvalidSyncState => {
                ("The vector sync state is invalid.", false)
            }
            MemoryVectorSyncOutboxErrorCode::SyncJobNotFound => {
                ("The vector sync job was not found.", true)
            }
            MemoryVectorSyncOutboxErrorCode::SyncJobLeaseConflict => (
                "The vector sync job lease is owned by another worker.",
                true,
            ),
            MemoryVectorSyncOutboxErrorCode::SyncJobLifeMismatch => {
                ("The vector sync job does not belong to this life.", false)
            }
            MemoryVectorSyncOutboxErrorCode::InternalError => {
                ("The vector sync operation failed.", true)
            }
        };
        Self {
            code,
            message: message.into(),
            recoverable,
        }
    }
}

pub trait MemoryVectorSyncOutboxRepository: Send + Sync {
    fn enqueue(
        &self,
        request: EnqueueMemoryVectorSyncRequest,
    ) -> Result<MemoryVectorSyncJob, MemoryVectorSyncOutboxError>;
    fn claim_next(
        &self,
        request: ClaimMemoryVectorSyncRequest,
    ) -> Result<Option<MemoryVectorSyncJob>, MemoryVectorSyncOutboxError>;
    fn mark_retry(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
        next_attempt_at: &str,
        error_code: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError>;
    fn mark_blocked(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
        error_code: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError>;
    fn mark_failed(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
        error_code: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError>;
    fn complete(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError>;
    fn release_expired_leases(&self, life_id: &str) -> Result<usize, MemoryVectorSyncOutboxError>;
    fn list(&self, life_id: &str) -> Result<Vec<MemoryVectorSyncJob>, MemoryVectorSyncOutboxError>;
    fn count(
        &self,
        life_id: &str,
        state: MemoryVectorSyncState,
    ) -> Result<usize, MemoryVectorSyncOutboxError>;
}
