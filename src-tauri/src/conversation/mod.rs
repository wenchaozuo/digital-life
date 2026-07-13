//! Governed conversation orchestration and SQLite-backed history boundaries.

pub mod history;
pub mod service;

#[cfg(test)]
mod integration_tests;

pub use history::{
    AppendConversationTurnRequest, AppendConversationTurnResult, ConversationHistoryError,
    ConversationHistoryErrorCode, ConversationHistoryService, ConversationMessagePage,
    ConversationMessageRecord, ConversationPageRequest, ConversationRecord, ConversationRepository,
    ConversationRole as PersistedConversationRole, ConversationSummary,
    CreateConversationCommandRequest, CreateConversationRequest, DeleteConversationResult,
    PersistedConversationMessage, RenameConversationCommandRequest, RenameConversationRequest,
};

pub use service::{
    chat_with_governed_context, ConversationCognitionCoordinator, ConversationCognitionError,
    ConversationCognitionErrorCode, ConversationDegradationCode, ConversationMemoryMetadata,
    GovernedConversationRequest, GovernedConversationResponse,
};
