use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::storage::StorageService;

pub const MAX_CONVERSATION_TITLE_CHARACTERS: usize = 120;
pub const MAX_CONVERSATION_MESSAGE_CHARACTERS: usize = 32_000;
pub const MAX_RECENT_CONVERSATION_MESSAGES: usize = 20;
pub const MAX_CONVERSATION_PAGE_SIZE: usize = 100;
const MAX_TURN_ID_CHARACTERS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConversationRole {
    User,
    Assistant,
}

impl ConversationRole {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ConversationHistoryError> {
        match value {
            "user" => Ok(Self::User),
            "assistant" => Ok(Self::Assistant),
            _ => Err(ConversationHistoryError::new(
                ConversationHistoryErrorCode::InvalidMessageRole,
            )),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConversationRecord {
    pub id: String,
    pub life_id: String,
    pub title: String,
    pub revision: i64,
    pub created_at: String,
    pub updated_at: String,
    pub last_message_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConversationMessageRecord {
    pub id: String,
    pub conversation_id: String,
    pub life_id: String,
    pub turn_id: String,
    pub role: ConversationRole,
    pub content: String,
    pub sequence_no: i64,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateConversationRequest {
    pub life_id: String,
    pub title: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenameConversationRequest {
    pub life_id: String,
    pub conversation_id: String,
    pub title: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppendConversationTurnRequest {
    pub life_id: String,
    pub conversation_id: String,
    pub turn_id: String,
    pub user_content: String,
    pub assistant_content: String,
    pub expected_revision: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationPageRequest {
    pub life_id: String,
    pub conversation_id: String,
    pub after_sequence_no: Option<i64>,
    pub limit: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConversationMessagePage {
    pub messages: Vec<ConversationMessageRecord>,
    pub next_after_sequence_no: Option<i64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppendConversationTurnResult {
    pub user_message: ConversationMessageRecord,
    pub assistant_message: ConversationMessageRecord,
    pub conversation_revision: i64,
    pub replayed: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConversationSummary {
    pub id: String,
    pub title: String,
    pub created_at: String,
    pub updated_at: String,
    pub last_message_at: String,
}

impl From<ConversationRecord> for ConversationSummary {
    fn from(value: ConversationRecord) -> Self {
        Self {
            id: value.id,
            title: value.title,
            created_at: value.created_at,
            updated_at: value.updated_at,
            last_message_at: value.last_message_at,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateConversationCommandRequest {
    pub title: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationIdRequest {
    pub conversation_id: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenameConversationCommandRequest {
    pub conversation_id: String,
    pub title: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PersistedConversationMessage {
    pub role: ConversationRole,
    pub content: String,
    pub sequence_no: i64,
    pub created_at: String,
}

impl From<ConversationMessageRecord> for PersistedConversationMessage {
    fn from(value: ConversationMessageRecord) -> Self {
        Self {
            role: value.role,
            content: value.content,
            sequence_no: value.sequence_no,
            created_at: value.created_at,
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeleteConversationResult {
    pub conversation_id: String,
    pub deleted: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConversationHistoryErrorCode {
    ConversationNotFound,
    ConversationLifeMismatch,
    InvalidConversationTitle,
    InvalidMessageContent,
    InvalidMessageRole,
    InvalidRequest,
    TurnIdConflict,
    IncompleteTurn,
    ConversationChangedDuringRequest,
    ConversationStorageUnavailable,
    InternalError,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConversationHistoryError {
    pub code: ConversationHistoryErrorCode,
    pub message: String,
    pub recoverable: bool,
}

impl ConversationHistoryError {
    pub(crate) fn new(code: ConversationHistoryErrorCode) -> Self {
        let (message, recoverable) = match code {
            ConversationHistoryErrorCode::ConversationNotFound => {
                ("The conversation was not found.", true)
            }
            ConversationHistoryErrorCode::ConversationLifeMismatch => (
                "The conversation does not belong to the current life.",
                false,
            ),
            ConversationHistoryErrorCode::InvalidConversationTitle => {
                ("The conversation title is invalid.", true)
            }
            ConversationHistoryErrorCode::InvalidMessageContent => {
                ("The conversation message content is invalid.", true)
            }
            ConversationHistoryErrorCode::InvalidMessageRole => {
                ("The conversation message role is invalid.", false)
            }
            ConversationHistoryErrorCode::InvalidRequest => {
                ("The conversation history request is invalid.", true)
            }
            ConversationHistoryErrorCode::TurnIdConflict => (
                "The turn identifier conflicts with committed history.",
                false,
            ),
            ConversationHistoryErrorCode::IncompleteTurn => {
                ("The stored conversation turn is incomplete.", false)
            }
            ConversationHistoryErrorCode::ConversationChangedDuringRequest => (
                "The conversation changed while the response was being generated.",
                true,
            ),
            ConversationHistoryErrorCode::ConversationStorageUnavailable => {
                ("Conversation storage is unavailable.", true)
            }
            ConversationHistoryErrorCode::InternalError => {
                ("The conversation history operation failed.", true)
            }
        };
        Self {
            code,
            message: message.to_string(),
            recoverable,
        }
    }
}

pub trait ConversationRepository: Send + Sync {
    fn create_conversation(
        &self,
        id: &str,
        request: &CreateConversationRequest,
    ) -> Result<ConversationRecord, ConversationHistoryError>;
    fn get_conversation(
        &self,
        life_id: &str,
        conversation_id: &str,
    ) -> Result<ConversationRecord, ConversationHistoryError>;
    fn list_conversations(
        &self,
        life_id: &str,
    ) -> Result<Vec<ConversationRecord>, ConversationHistoryError>;
    fn rename_conversation(
        &self,
        request: &RenameConversationRequest,
    ) -> Result<ConversationRecord, ConversationHistoryError>;
    fn delete_conversation(
        &self,
        life_id: &str,
        conversation_id: &str,
    ) -> Result<(), ConversationHistoryError>;
    fn load_recent_messages(
        &self,
        life_id: &str,
        conversation_id: &str,
        limit: usize,
    ) -> Result<Vec<ConversationMessageRecord>, ConversationHistoryError>;
    fn load_message_page(
        &self,
        request: &ConversationPageRequest,
    ) -> Result<ConversationMessagePage, ConversationHistoryError>;
    fn append_complete_turn(
        &self,
        request: &AppendConversationTurnRequest,
    ) -> Result<AppendConversationTurnResult, ConversationHistoryError>;
    fn find_committed_turn(
        &self,
        life_id: &str,
        conversation_id: &str,
        turn_id: &str,
    ) -> Result<Option<AppendConversationTurnResult>, ConversationHistoryError>;
    fn count_conversations(&self, life_id: &str) -> Result<usize, ConversationHistoryError>;
    fn count_messages(
        &self,
        life_id: &str,
        conversation_id: &str,
    ) -> Result<usize, ConversationHistoryError>;
}

pub struct ConversationHistoryService<'a, R>
where
    R: ConversationRepository + ?Sized,
{
    repository: &'a R,
}

impl<'a, R> ConversationHistoryService<'a, R>
where
    R: ConversationRepository + ?Sized,
{
    pub fn new(repository: &'a R) -> Self {
        Self { repository }
    }

    pub fn create(
        &self,
        mut request: CreateConversationRequest,
    ) -> Result<ConversationRecord, ConversationHistoryError> {
        validate_life_id(&request.life_id)?;
        request.title = normalize_title(&request.title)?;
        self.repository
            .create_conversation(&generate_id("conversation"), &request)
    }

    pub fn get(
        &self,
        life_id: &str,
        conversation_id: &str,
    ) -> Result<ConversationRecord, ConversationHistoryError> {
        validate_identifiers(life_id, conversation_id)?;
        self.repository.get_conversation(life_id, conversation_id)
    }

    pub fn list(&self, life_id: &str) -> Result<Vec<ConversationRecord>, ConversationHistoryError> {
        validate_life_id(life_id)?;
        self.repository.list_conversations(life_id)
    }

    pub fn rename(
        &self,
        mut request: RenameConversationRequest,
    ) -> Result<ConversationRecord, ConversationHistoryError> {
        validate_identifiers(&request.life_id, &request.conversation_id)?;
        request.title = normalize_title(&request.title)?;
        self.repository.rename_conversation(&request)
    }

    pub fn delete(
        &self,
        life_id: &str,
        conversation_id: &str,
    ) -> Result<(), ConversationHistoryError> {
        validate_identifiers(life_id, conversation_id)?;
        self.repository
            .delete_conversation(life_id, conversation_id)
    }

    pub fn recent_messages(
        &self,
        life_id: &str,
        conversation_id: &str,
    ) -> Result<Vec<ConversationMessageRecord>, ConversationHistoryError> {
        validate_identifiers(life_id, conversation_id)?;
        self.repository.load_recent_messages(
            life_id,
            conversation_id,
            MAX_RECENT_CONVERSATION_MESSAGES,
        )
    }

    pub fn page(
        &self,
        request: ConversationPageRequest,
    ) -> Result<ConversationMessagePage, ConversationHistoryError> {
        validate_identifiers(&request.life_id, &request.conversation_id)?;
        if request.limit == 0
            || request.limit > MAX_CONVERSATION_PAGE_SIZE
            || request.after_sequence_no.is_some_and(|value| value < 0)
        {
            return Err(ConversationHistoryError::new(
                ConversationHistoryErrorCode::InvalidRequest,
            ));
        }
        self.repository.load_message_page(&request)
    }

    pub fn append_turn(
        &self,
        request: AppendConversationTurnRequest,
    ) -> Result<AppendConversationTurnResult, ConversationHistoryError> {
        validate_append_turn_request(&request)?;
        self.repository.append_complete_turn(&request)
    }

    pub fn find_turn(
        &self,
        life_id: &str,
        conversation_id: &str,
        turn_id: &str,
    ) -> Result<Option<AppendConversationTurnResult>, ConversationHistoryError> {
        validate_identifiers(life_id, conversation_id)?;
        validate_turn_id(turn_id)?;
        self.repository
            .find_committed_turn(life_id, conversation_id, turn_id)
    }

    pub fn count_conversations(&self, life_id: &str) -> Result<usize, ConversationHistoryError> {
        validate_life_id(life_id)?;
        self.repository.count_conversations(life_id)
    }

    pub fn count_messages(
        &self,
        life_id: &str,
        conversation_id: &str,
    ) -> Result<usize, ConversationHistoryError> {
        validate_identifiers(life_id, conversation_id)?;
        self.repository.count_messages(life_id, conversation_id)
    }
}

fn normalize_title(title: &str) -> Result<String, ConversationHistoryError> {
    let value = title.trim();
    if value.is_empty() || value.chars().count() > MAX_CONVERSATION_TITLE_CHARACTERS {
        return Err(ConversationHistoryError::new(
            ConversationHistoryErrorCode::InvalidConversationTitle,
        ));
    }
    Ok(value.to_string())
}

/// The ONE append-turn request validation, shared by the legacy
/// ConversationHistoryService::append_turn path AND the D11 composite
/// conversation+emotion primitive, so neither can bypass the other's rules.
pub(crate) fn validate_append_turn_request(
    request: &AppendConversationTurnRequest,
) -> Result<(), ConversationHistoryError> {
    validate_identifiers(&request.life_id, &request.conversation_id)?;
    validate_turn_id(&request.turn_id)?;
    validate_message(&request.user_content)?;
    validate_message(&request.assistant_content)?;
    if request.expected_revision.is_some_and(|value| value < 0) {
        return Err(ConversationHistoryError::new(
            ConversationHistoryErrorCode::InvalidRequest,
        ));
    }
    Ok(())
}

fn validate_message(content: &str) -> Result<(), ConversationHistoryError> {
    if content.trim().is_empty() || content.chars().count() > MAX_CONVERSATION_MESSAGE_CHARACTERS {
        return Err(ConversationHistoryError::new(
            ConversationHistoryErrorCode::InvalidMessageContent,
        ));
    }
    Ok(())
}

fn validate_turn_id(turn_id: &str) -> Result<(), ConversationHistoryError> {
    if turn_id.trim().is_empty() || turn_id.chars().count() > MAX_TURN_ID_CHARACTERS {
        return Err(ConversationHistoryError::new(
            ConversationHistoryErrorCode::InvalidRequest,
        ));
    }
    Ok(())
}

fn validate_life_id(life_id: &str) -> Result<(), ConversationHistoryError> {
    if life_id.trim().is_empty() {
        return Err(ConversationHistoryError::new(
            ConversationHistoryErrorCode::InvalidRequest,
        ));
    }
    Ok(())
}

fn validate_identifiers(
    life_id: &str,
    conversation_id: &str,
) -> Result<(), ConversationHistoryError> {
    validate_life_id(life_id)?;
    if conversation_id.trim().is_empty() {
        return Err(ConversationHistoryError::new(
            ConversationHistoryErrorCode::InvalidRequest,
        ));
    }
    Ok(())
}

static ID_SEQUENCE: AtomicU64 = AtomicU64::new(1);

pub(crate) fn generate_id(prefix: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let sequence = ID_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{timestamp:032x}-{sequence:016x}")
}

fn current_life_id(storage: &StorageService) -> Result<String, ConversationHistoryError> {
    storage
        .get_current_life()
        .map_err(|_| {
            ConversationHistoryError::new(
                ConversationHistoryErrorCode::ConversationStorageUnavailable,
            )
        })?
        .map(|life| life.id)
        .ok_or_else(|| {
            ConversationHistoryError::new(ConversationHistoryErrorCode::ConversationNotFound)
        })
}

#[tauri::command]
pub fn create_conversation(
    storage: State<'_, StorageService>,
    request: CreateConversationCommandRequest,
) -> Result<ConversationSummary, ConversationHistoryError> {
    let life_id = current_life_id(storage.inner())?;
    ConversationHistoryService::new(storage.inner())
        .create(CreateConversationRequest {
            life_id,
            title: request.title,
        })
        .map(Into::into)
}

#[tauri::command]
pub fn list_conversations(
    storage: State<'_, StorageService>,
) -> Result<Vec<ConversationSummary>, ConversationHistoryError> {
    let life_id = current_life_id(storage.inner())?;
    ConversationHistoryService::new(storage.inner())
        .list(&life_id)
        .map(|values| values.into_iter().map(Into::into).collect())
}

#[tauri::command]
pub fn get_conversation_messages(
    storage: State<'_, StorageService>,
    request: ConversationIdRequest,
) -> Result<Vec<PersistedConversationMessage>, ConversationHistoryError> {
    let life_id = current_life_id(storage.inner())?;
    ConversationHistoryService::new(storage.inner())
        .recent_messages(&life_id, &request.conversation_id)
        .map(|values| values.into_iter().map(Into::into).collect())
}

#[tauri::command]
pub fn rename_conversation(
    storage: State<'_, StorageService>,
    request: RenameConversationCommandRequest,
) -> Result<ConversationSummary, ConversationHistoryError> {
    let life_id = current_life_id(storage.inner())?;
    ConversationHistoryService::new(storage.inner())
        .rename(RenameConversationRequest {
            life_id,
            conversation_id: request.conversation_id,
            title: request.title,
        })
        .map(Into::into)
}

#[tauri::command]
pub fn delete_conversation(
    storage: State<'_, StorageService>,
    request: ConversationIdRequest,
) -> Result<DeleteConversationResult, ConversationHistoryError> {
    let life_id = current_life_id(storage.inner())?;
    ConversationHistoryService::new(storage.inner()).delete(&life_id, &request.conversation_id)?;
    Ok(DeleteConversationResult {
        conversation_id: request.conversation_id,
        deleted: true,
    })
}
