//! Deterministic, governed system-context construction.
//!
//! This module deliberately has no model, credential, or provider dependency.

mod compiler;

pub use compiler::{
    InitiativeLevel, PromptCommunicationStyle, PromptCompilationRequest, PromptCompilationResult,
    PromptCompiler, PromptCompilerError, PromptCompilerErrorCode, PromptEmotion,
    PromptLifeIdentity, PromptPersona, PromptRelationship, SafetyRulesVersion,
    PROMPT_COMPILER_VERSION,
};
