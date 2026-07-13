//! Governed conversation orchestration. This module owns the Rust-side
//! cognition boundary; it does not persist conversation history.

pub mod service;

pub use service::{
    chat_with_governed_context, ConversationCognitionCoordinator, ConversationCognitionError,
    ConversationCognitionErrorCode, ConversationDegradationCode, ConversationMemoryMetadata,
    ConversationRole, GovernedConversationMessage, GovernedConversationRequest,
    GovernedConversationResponse,
};
