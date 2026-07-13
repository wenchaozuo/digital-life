//! Governed conversation orchestration and SQLite-backed history boundaries.

pub mod history;
pub mod service;

pub use history::{
    AppendConversationTurnRequest, AppendConversationTurnResult, ConversationHistoryError,
    ConversationHistoryErrorCode, ConversationHistoryService, ConversationMessagePage,
    ConversationMessageRecord, ConversationPageRequest, ConversationRecord, ConversationRepository,
    ConversationRole as PersistedConversationRole, CreateConversationRequest,
    RenameConversationRequest,
};

pub use service::{
    chat_with_governed_context, ConversationCognitionCoordinator, ConversationCognitionError,
    ConversationCognitionErrorCode, ConversationDegradationCode, ConversationMemoryMetadata,
    ConversationRole, GovernedConversationMessage, GovernedConversationRequest,
    GovernedConversationResponse,
};
