use serde::{Deserialize, Serialize};

use super::MemoryKind;

pub const PRIMARY_USER_SUBJECT_ID: &str = "primary_user";
pub const DEFAULT_CANDIDATE_PAGE_SIZE: usize = 30;
pub const MAX_CANDIDATE_PAGE_SIZE: usize = 100;

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateMemoryStatus {
    Pending,
    Accepted,
    Rejected,
    Expired,
    Superseded,
}

impl CandidateMemoryStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Superseded => "superseded",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CandidateMemoryError> {
        match value {
            "pending" => Ok(Self::Pending),
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            "expired" => Ok(Self::Expired),
            "superseded" => Ok(Self::Superseded),
            _ => Err(CandidateMemoryError::invalid_stored_enum()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateMemorySourceType {
    Manual,
    ExplicitUserRequest,
    Conversation,
    LifeEvent,
    Reflection,
    AgentProposal,
    PluginProposal,
    Import,
}

impl CandidateMemorySourceType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::ExplicitUserRequest => "explicit_user_request",
            Self::Conversation => "conversation",
            Self::LifeEvent => "life_event",
            Self::Reflection => "reflection",
            Self::AgentProposal => "agent_proposal",
            Self::PluginProposal => "plugin_proposal",
            Self::Import => "import",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CandidateMemoryError> {
        match value {
            "manual" => Ok(Self::Manual),
            "explicit_user_request" => Ok(Self::ExplicitUserRequest),
            "conversation" => Ok(Self::Conversation),
            "life_event" => Ok(Self::LifeEvent),
            "reflection" => Ok(Self::Reflection),
            "agent_proposal" => Ok(Self::AgentProposal),
            "plugin_proposal" => Ok(Self::PluginProposal),
            "import" => Ok(Self::Import),
            _ => Err(CandidateMemoryError::invalid_stored_enum()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateInferenceStatus {
    Explicit,
    Extracted,
    Inferred,
}

impl CandidateInferenceStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Explicit => "explicit",
            Self::Extracted => "extracted",
            Self::Inferred => "inferred",
        }
    }

    pub fn parse(value: &str) -> Result<Self, CandidateMemoryError> {
        match value {
            "explicit" => Ok(Self::Explicit),
            "extracted" => Ok(Self::Extracted),
            "inferred" => Ok(Self::Inferred),
            _ => Err(CandidateMemoryError::invalid_stored_enum()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateMemoryRecord {
    pub id: String,
    pub life_id: String,
    pub subject_id: String,
    pub kind: MemoryKind,
    pub content: Option<String>,
    pub summary: Option<String>,
    pub source_type: CandidateMemorySourceType,
    pub source_id: Option<String>,
    pub confidence: f64,
    pub importance: f64,
    pub is_sensitive: bool,
    pub inference_status: CandidateInferenceStatus,
    pub status: CandidateMemoryStatus,
    pub revision: i64,
    pub dedup_fingerprint: Option<String>,
    pub proposed_at: String,
    pub expires_at: Option<String>,
    pub reviewed_at: Option<String>,
    pub last_user_edit_at: Option<String>,
    pub confirmed_memory_id: Option<String>,
    pub accepted_request_id: Option<String>,
    pub rejection_reason_code: Option<String>,
    pub superseded_by_candidate_id: Option<String>,
    pub conflicts_with_memory_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateMemoryEvidenceRecord {
    pub id: String,
    pub candidate_id: String,
    pub life_id: String,
    pub source_type: CandidateMemorySourceType,
    pub source_id: Option<String>,
    pub conversation_id: Option<String>,
    pub message_id: Option<String>,
    pub observed_at: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateMemoryAuditRecord {
    pub id: String,
    pub candidate_id: String,
    pub life_id: String,
    pub action: String,
    pub actor_type: String,
    pub request_id: Option<String>,
    pub result_status: String,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateMemoryCursor {
    pub proposed_at: String,
    pub id: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CandidateMemoryListFilter {
    pub life_id: String,
    pub status: Option<CandidateMemoryStatus>,
    pub kind: Option<MemoryKind>,
    pub is_sensitive: Option<bool>,
    pub query: Option<String>,
    pub source_type: Option<CandidateMemorySourceType>,
    pub inference_status: Option<CandidateInferenceStatus>,
    pub page_size: Option<usize>,
    pub cursor: Option<CandidateMemoryCursor>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NewCandidateMemory {
    pub id: String,
    pub life_id: String,
    pub subject_id: String,
    pub kind: MemoryKind,
    pub content: Option<String>,
    pub summary: Option<String>,
    pub source_type: CandidateMemorySourceType,
    pub source_id: Option<String>,
    pub confidence: f64,
    pub importance: f64,
    pub is_sensitive: bool,
    pub inference_status: CandidateInferenceStatus,
    pub status: CandidateMemoryStatus,
    pub dedup_fingerprint: Option<String>,
    pub proposed_at: String,
    pub expires_at: Option<String>,
    pub reviewed_at: Option<String>,
    pub last_user_edit_at: Option<String>,
    pub confirmed_memory_id: Option<String>,
    pub accepted_request_id: Option<String>,
    pub rejection_reason_code: Option<String>,
    pub superseded_by_candidate_id: Option<String>,
    pub conflicts_with_memory_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CandidateMemoryStorageUpdate {
    pub kind: MemoryKind,
    pub content: Option<String>,
    pub summary: Option<String>,
    pub source_type: CandidateMemorySourceType,
    pub source_id: Option<String>,
    pub confidence: f64,
    pub importance: f64,
    pub is_sensitive: bool,
    pub inference_status: CandidateInferenceStatus,
    pub status: CandidateMemoryStatus,
    pub dedup_fingerprint: Option<String>,
    pub proposed_at: String,
    pub expires_at: Option<String>,
    pub reviewed_at: Option<String>,
    pub last_user_edit_at: Option<String>,
    pub confirmed_memory_id: Option<String>,
    pub accepted_request_id: Option<String>,
    pub rejection_reason_code: Option<String>,
    pub superseded_by_candidate_id: Option<String>,
    pub conflicts_with_memory_id: Option<String>,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NewCandidateMemoryEvidence {
    pub id: String,
    pub candidate_id: String,
    pub life_id: String,
    pub source_type: CandidateMemorySourceType,
    pub source_id: Option<String>,
    pub conversation_id: Option<String>,
    pub message_id: Option<String>,
    pub observed_at: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct NewCandidateMemoryAudit {
    pub id: String,
    pub candidate_id: String,
    pub life_id: String,
    pub action: String,
    pub actor_type: String,
    pub request_id: Option<String>,
    pub result_status: String,
    pub created_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CandidateMemoryError {
    pub code: String,
    pub message: String,
    pub recoverable: bool,
}

impl CandidateMemoryError {
    pub fn not_found() -> Self {
        Self::new(
            "CANDIDATE_MEMORY_NOT_FOUND",
            "The requested candidate memory was not found.",
            true,
        )
    }

    pub fn life_mismatch() -> Self {
        Self::new(
            "CANDIDATE_MEMORY_LIFE_MISMATCH",
            "The candidate memory is not available for this life.",
            false,
        )
    }

    pub fn revision_conflict() -> Self {
        Self::new(
            "CANDIDATE_MEMORY_REVISION_CONFLICT",
            "The candidate memory changed after it was loaded. Refresh and try again.",
            true,
        )
    }

    pub fn duplicate() -> Self {
        Self::new(
            "CANDIDATE_MEMORY_DUPLICATE",
            "An equivalent pending candidate memory already exists.",
            true,
        )
    }

    pub fn invalid_stored_enum() -> Self {
        Self::new(
            "CANDIDATE_MEMORY_INVALID_STORED_ENUM",
            "Stored candidate memory data is invalid.",
            false,
        )
    }

    pub fn constraint() -> Self {
        Self::new(
            "CANDIDATE_MEMORY_CONSTRAINT_VIOLATION",
            "The candidate memory request violates a storage constraint.",
            true,
        )
    }

    pub fn invalid_query() -> Self {
        Self::new(
            "CANDIDATE_MEMORY_INVALID_QUERY",
            "The candidate memory query is invalid.",
            true,
        )
    }

    pub fn storage_unavailable() -> Self {
        Self::new(
            "CANDIDATE_MEMORY_STORAGE_UNAVAILABLE",
            "Candidate memory storage is unavailable.",
            true,
        )
    }

    pub fn new(code: &str, message: impl Into<String>, recoverable: bool) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
            recoverable,
        }
    }
}

impl From<CandidateMemoryError> for crate::storage::StorageError {
    fn from(error: CandidateMemoryError) -> Self {
        Self::new(&error.code, error.message, error.recoverable)
    }
}

pub trait CandidateMemoryRepository {
    fn insert_candidate(
        &self,
        candidate: NewCandidateMemory,
    ) -> Result<CandidateMemoryRecord, CandidateMemoryError>;
    fn get_candidate(
        &self,
        life_id: &str,
        candidate_id: &str,
    ) -> Result<CandidateMemoryRecord, CandidateMemoryError>;
    fn list_candidates(
        &self,
        filter: CandidateMemoryListFilter,
    ) -> Result<(Vec<CandidateMemoryRecord>, Option<CandidateMemoryCursor>), CandidateMemoryError>;
    fn update_candidate_guarded(
        &self,
        life_id: &str,
        candidate_id: &str,
        expected_revision: i64,
        update: CandidateMemoryStorageUpdate,
    ) -> Result<CandidateMemoryRecord, CandidateMemoryError>;
    fn delete_candidate_permanently(
        &self,
        life_id: &str,
        candidate_id: &str,
    ) -> Result<bool, CandidateMemoryError>;
    fn insert_evidence(
        &self,
        evidence: NewCandidateMemoryEvidence,
    ) -> Result<CandidateMemoryEvidenceRecord, CandidateMemoryError>;
    fn list_evidence(
        &self,
        life_id: &str,
        candidate_id: &str,
    ) -> Result<Vec<CandidateMemoryEvidenceRecord>, CandidateMemoryError>;
    fn count_evidence(
        &self,
        life_id: &str,
        candidate_id: &str,
    ) -> Result<usize, CandidateMemoryError>;
    fn delete_evidence(
        &self,
        life_id: &str,
        evidence_id: &str,
    ) -> Result<bool, CandidateMemoryError>;
    fn append_audit(
        &self,
        audit: NewCandidateMemoryAudit,
    ) -> Result<CandidateMemoryAuditRecord, CandidateMemoryError>;
    fn purge_audit_before(
        &self,
        life_id: &str,
        before: &str,
    ) -> Result<usize, CandidateMemoryError>;
}

#[cfg(test)]
mod tests {
    use super::{CandidateInferenceStatus, CandidateMemorySourceType, CandidateMemoryStatus};

    #[test]
    fn unknown_stored_enum_values_fail_closed() {
        assert_eq!(
            CandidateMemoryStatus::parse("future").unwrap_err().code,
            "CANDIDATE_MEMORY_INVALID_STORED_ENUM"
        );
        assert_eq!(
            CandidateMemorySourceType::parse("unknown")
                .unwrap_err()
                .code,
            "CANDIDATE_MEMORY_INVALID_STORED_ENUM"
        );
        assert_eq!(
            CandidateInferenceStatus::parse("opaque").unwrap_err().code,
            "CANDIDATE_MEMORY_INVALID_STORED_ENUM"
        );
    }
}
