use std::{collections::HashSet, sync::Mutex, time::Instant};

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::{
    memory::{
        context_builder::{
            MemoryContextBuildRequest, MemoryContextBuilder, MemoryContextEntry,
            MemoryContextSource,
        },
        retrieval_router::RetrievalSource,
        retrieval_runtime::{
            GovernedRetrievalRequest, MemoryRetrievalRuntimeService,
            ModelRuntimeEmbeddingProviderFactory, RetrievalAvailability, RetrievalDegradationCode,
        },
    },
    model::{
        runtime::{
            ActiveModelChatRequest, ModelRuntimeCoordinator, ModelRuntimeError,
            ModelRuntimeErrorCode, ModelRuntimeService,
        },
        ModelMessage, ModelMessageRole,
    },
    prompt::{
        InitiativeLevel, PromptCommunicationStyle, PromptCompilationRequest, PromptCompiler,
        PromptLifeIdentity, PromptPersona, SafetyRulesVersion,
    },
    secrets::WindowsCredentialSecretStore,
    storage::{LifeIdentityRecord, PersonaTemplateRecord, StorageService},
    vector_store::LanceDbVectorStoreRegistry,
};

const MAX_HISTORY_MESSAGES: usize = 20;
const MAX_HISTORY_MESSAGE_CHARACTERS: usize = 4_000;
const MAX_HISTORY_TOTAL_CHARACTERS: usize = 20_000;
const MAX_USER_MESSAGE_CHARACTERS: usize = 4_000;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConversationRole {
    User,
    Assistant,
}

impl ConversationRole {
    fn model_role(self) -> ModelMessageRole {
        match self {
            Self::User => ModelMessageRole::User,
            Self::Assistant => ModelMessageRole::Assistant,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernedConversationMessage {
    pub role: ConversationRole,
    pub content: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernedConversationRequest {
    pub request_id: String,
    pub user_message: String,
    pub history: Vec<GovernedConversationMessage>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConversationDegradationCode {
    VectorSkippedSensitiveQuery,
    NoActiveEmbeddingProfile,
    EmbeddingCredentialNotFound,
    EmbeddingProviderUnavailable,
    IndexDirectoryMissing,
    VectorStoreUnavailable,
    VectorIndexUnavailable,
    VectorUnavailable,
    KeywordUnavailable,
    BothRetrievalUnavailable,
    AuthoritativeReadUnavailable,
    MemoryContextUnavailable,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConversationMemoryMetadata {
    pub retrieved_count: usize,
    pub used_count: usize,
    pub truncated: bool,
    pub degradation_codes: Vec<ConversationDegradationCode>,
    pub vector_availability: RetrievalAvailability,
    pub rebuild_recommended: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GovernedConversationResponse {
    pub request_id: String,
    pub assistant_message: String,
    pub profile_display_name: String,
    pub model_name: String,
    pub memory: ConversationMemoryMetadata,
    pub latency_ms: u64,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConversationCognitionErrorCode {
    LifeIdentityNotFound,
    PersonaNotFound,
    PersonaLifeMismatch,
    InvalidConversationRequest,
    InvalidHistoryRole,
    ConversationInProgress,
    NoActiveProfile,
    CredentialNotFound,
    ProviderInitializationFailed,
    AuthenticationFailed,
    RateLimited,
    NetworkUnavailable,
    RequestTimeout,
    InvalidProviderResponse,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ConversationCognitionError {
    pub code: ConversationCognitionErrorCode,
    pub message: String,
    pub recoverable: bool,
}

impl ConversationCognitionError {
    fn new(code: ConversationCognitionErrorCode, message: &'static str, recoverable: bool) -> Self {
        Self {
            code,
            message: message.to_string(),
            recoverable,
        }
    }
}

/// Limits concurrent request ids and life contexts without retaining prompts,
/// providers, credentials, or response bodies.
#[derive(Default)]
pub struct ConversationCognitionCoordinator {
    active: Mutex<HashSet<String>>,
}

impl ConversationCognitionCoordinator {
    fn acquire(
        &self,
        request_id: &str,
        life_id: &str,
    ) -> Result<ConversationPermit<'_>, ConversationCognitionError> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| error(ConversationCognitionErrorCode::ConversationInProgress))?;
        let request_key = format!("request:{request_id}");
        let life_key = format!("life:{life_id}");
        if request_id.trim().is_empty()
            || active.contains(&request_key)
            || active.contains(&life_key)
        {
            return Err(error(
                ConversationCognitionErrorCode::ConversationInProgress,
            ));
        }
        active.insert(request_key.clone());
        active.insert(life_key.clone());
        Ok(ConversationPermit {
            coordinator: self,
            request_key,
            life_key,
        })
    }
}

struct ConversationPermit<'a> {
    coordinator: &'a ConversationCognitionCoordinator,
    request_key: String,
    life_key: String,
}
impl Drop for ConversationPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.coordinator.active.lock() {
            active.remove(&self.request_key);
            active.remove(&self.life_key);
        }
    }
}

pub struct ConversationCognitionService<'a> {
    storage: &'a StorageService,
    secrets: &'a WindowsCredentialSecretStore,
    model_coordinator: &'a ModelRuntimeCoordinator,
    retrieval_registry: &'a LanceDbVectorStoreRegistry,
    coordinator: &'a ConversationCognitionCoordinator,
}

impl<'a> ConversationCognitionService<'a> {
    pub fn new(
        storage: &'a StorageService,
        secrets: &'a WindowsCredentialSecretStore,
        model_coordinator: &'a ModelRuntimeCoordinator,
        retrieval_registry: &'a LanceDbVectorStoreRegistry,
        coordinator: &'a ConversationCognitionCoordinator,
    ) -> Self {
        Self {
            storage,
            secrets,
            model_coordinator,
            retrieval_registry,
            coordinator,
        }
    }

    pub async fn chat(
        &self,
        request: GovernedConversationRequest,
    ) -> Result<GovernedConversationResponse, ConversationCognitionError> {
        validate_request(&request)?;
        let life = self
            .storage
            .get_current_life()
            .map_err(|_| error(ConversationCognitionErrorCode::LifeIdentityNotFound))?
            .ok_or_else(|| error(ConversationCognitionErrorCode::LifeIdentityNotFound))?;
        let _permit = self.coordinator.acquire(&request.request_id, &life.id)?;
        let persona_record = self
            .storage
            .get_persona(&life.persona_id)
            .map_err(|_| error(ConversationCognitionErrorCode::PersonaNotFound))?
            .ok_or_else(|| error(ConversationCognitionErrorCode::PersonaNotFound))?;
        let persona = parse_persona(&life, &persona_record)?;
        let started = Instant::now();

        let factory = ModelRuntimeEmbeddingProviderFactory::new(
            self.storage,
            self.secrets,
            self.model_coordinator,
        );
        let retrieval = MemoryRetrievalRuntimeService::new(
            self.storage,
            &factory,
            self.storage,
            self.retrieval_registry,
        );
        let retrieval_result = retrieval
            .retrieve(GovernedRetrievalRequest {
                life_id: life.id.clone(),
                query: request.user_message.clone(),
                memory_kind_filter: None,
            })
            .await
            .map_err(|_| error(ConversationCognitionErrorCode::InvalidConversationRequest))?;
        let entries = retrieval_result
            .candidates
            .iter()
            .map(|candidate| MemoryContextEntry {
                memory_id: candidate.memory_id.clone(),
                kind: candidate.kind,
                content: candidate.content.clone(),
                summary: candidate.summary.clone(),
                importance: candidate.importance,
                confidence: candidate.confidence,
                final_score: candidate.final_score,
                source: match candidate.sources {
                    RetrievalSource::Keyword => MemoryContextSource::Keyword,
                    RetrievalSource::Vector => MemoryContextSource::Vector,
                    RetrievalSource::Both => MemoryContextSource::Both,
                },
            })
            .collect();
        let memory_context = MemoryContextBuilder
            .build(MemoryContextBuildRequest { entries })
            .map_err(|_| error(ConversationCognitionErrorCode::InvalidConversationRequest))?;
        let compilation = PromptCompiler
            .compile(PromptCompilationRequest {
                safety_rules_version: SafetyRulesVersion::V1,
                life_identity: PromptLifeIdentity {
                    display_name: life.name.clone(),
                    identity_version: life.version,
                },
                persona,
                memory_context: memory_context.context.clone(),
            })
            .map_err(|_| error(ConversationCognitionErrorCode::PersonaNotFound))?;
        let messages = request
            .history
            .iter()
            .map(|message| ModelMessage {
                role: message.role.model_role(),
                content: message.content.trim().to_string(),
            })
            .chain(std::iter::once(ModelMessage {
                role: ModelMessageRole::User,
                content: request.user_message.trim().to_string(),
            }))
            .collect();
        let runtime = ModelRuntimeService::new(self.storage, self.secrets, self.model_coordinator);
        let resolved = runtime
            .resolve_active_chat_provider()
            .map_err(map_model_error)?;
        let profile_display_name = resolved.profile.display_name.clone();
        let model_name = resolved.profile.model_name.clone();
        let response = runtime
            .chat_with_resolved_provider(
                resolved,
                ActiveModelChatRequest {
                    messages,
                    system_context: Some(compilation.system_context),
                },
            )
            .await
            .map_err(map_model_error)?;
        let mut degradations = retrieval_result
            .degradation_codes
            .iter()
            .filter_map(map_retrieval_degradation)
            .collect::<Vec<_>>();
        if !memory_context.degradation_codes.is_empty()
            && !degradations.contains(&ConversationDegradationCode::MemoryContextUnavailable)
        {
            degradations.push(ConversationDegradationCode::MemoryContextUnavailable);
        }
        Ok(GovernedConversationResponse {
            request_id: request.request_id,
            assistant_message: response.text,
            profile_display_name,
            model_name,
            memory: ConversationMemoryMetadata {
                retrieved_count: retrieval_result.retrieved_count,
                used_count: memory_context.used_count,
                truncated: memory_context.truncated,
                degradation_codes: degradations,
                vector_availability: retrieval_result.availability,
                rebuild_recommended: retrieval_result.rebuild_recommended,
            },
            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

#[cfg(windows)]
#[tauri::command]
pub async fn chat_with_governed_context(
    storage: State<'_, StorageService>,
    secrets: State<'_, WindowsCredentialSecretStore>,
    model_coordinator: State<'_, ModelRuntimeCoordinator>,
    retrieval_registry: State<'_, LanceDbVectorStoreRegistry>,
    coordinator: State<'_, ConversationCognitionCoordinator>,
    request: GovernedConversationRequest,
) -> Result<GovernedConversationResponse, ConversationCognitionError> {
    ConversationCognitionService::new(
        storage.inner(),
        secrets.inner(),
        model_coordinator.inner(),
        retrieval_registry.inner(),
        coordinator.inner(),
    )
    .chat(request)
    .await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredPersona {
    id: String,
    name: String,
    version: i64,
    #[serde(default)]
    core_values: Vec<String>,
    #[serde(default)]
    personality_traits: Vec<String>,
    #[serde(default)]
    communication_style: StoredCommunicationStyle,
    #[serde(default)]
    background: String,
    #[serde(default)]
    interests: Vec<String>,
    #[serde(default)]
    initiative_level: StoredInitiative,
    #[serde(default)]
    boundaries: Vec<String>,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StoredCommunicationStyle {
    tone: String,
    preferred_expressions: Vec<String>,
    avoided_expressions: Vec<String>,
}
#[derive(Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum StoredInitiative {
    Low,
    #[default]
    Balanced,
    High,
}
fn parse_persona(
    life: &LifeIdentityRecord,
    record: &PersonaTemplateRecord,
) -> Result<PromptPersona, ConversationCognitionError> {
    if record.id != life.persona_id || record.version != life.persona_version {
        return Err(error(ConversationCognitionErrorCode::PersonaLifeMismatch));
    }
    let stored: StoredPersona = serde_json::from_str(&record.persona_json)
        .map_err(|_| error(ConversationCognitionErrorCode::PersonaNotFound))?;
    if stored.id != life.persona_id
        || stored.version != life.persona_version
        || stored.name.trim().is_empty()
    {
        return Err(error(ConversationCognitionErrorCode::PersonaLifeMismatch));
    }
    Ok(PromptPersona {
        name: stored.name,
        version: stored.version,
        core_values: stored.core_values,
        personality_traits: stored.personality_traits,
        communication_style: PromptCommunicationStyle {
            tone: stored.communication_style.tone,
            preferred_expressions: stored.communication_style.preferred_expressions,
            avoided_expressions: stored.communication_style.avoided_expressions,
        },
        background: stored.background,
        interests: stored.interests,
        initiative_level: match stored.initiative_level {
            StoredInitiative::Low => InitiativeLevel::Low,
            StoredInitiative::Balanced => InitiativeLevel::Balanced,
            StoredInitiative::High => InitiativeLevel::High,
        },
        boundaries: stored.boundaries,
    })
}
fn validate_request(
    request: &GovernedConversationRequest,
) -> Result<(), ConversationCognitionError> {
    if request.request_id.trim().is_empty()
        || request.user_message.trim().is_empty()
        || request.user_message.chars().count() > MAX_USER_MESSAGE_CHARACTERS
        || request.history.len() > MAX_HISTORY_MESSAGES
    {
        return Err(error(
            ConversationCognitionErrorCode::InvalidConversationRequest,
        ));
    }
    let mut total = 0usize;
    for message in &request.history {
        let text = message.content.trim();
        if text.is_empty() || text.chars().count() > MAX_HISTORY_MESSAGE_CHARACTERS {
            return Err(error(
                ConversationCognitionErrorCode::InvalidConversationRequest,
            ));
        }
        total += text.chars().count();
    }
    if total > MAX_HISTORY_TOTAL_CHARACTERS {
        return Err(error(
            ConversationCognitionErrorCode::InvalidConversationRequest,
        ));
    }
    Ok(())
}
fn map_model_error(runtime_error: ModelRuntimeError) -> ConversationCognitionError {
    error(match runtime_error.code {
        ModelRuntimeErrorCode::NoActiveProfile => ConversationCognitionErrorCode::NoActiveProfile,
        ModelRuntimeErrorCode::CredentialNotFound => {
            ConversationCognitionErrorCode::CredentialNotFound
        }
        ModelRuntimeErrorCode::ProviderInitializationFailed => {
            ConversationCognitionErrorCode::ProviderInitializationFailed
        }
        ModelRuntimeErrorCode::AuthenticationFailed => {
            ConversationCognitionErrorCode::AuthenticationFailed
        }
        ModelRuntimeErrorCode::RateLimited => ConversationCognitionErrorCode::RateLimited,
        ModelRuntimeErrorCode::NetworkUnavailable => {
            ConversationCognitionErrorCode::NetworkUnavailable
        }
        ModelRuntimeErrorCode::RequestTimeout => ConversationCognitionErrorCode::RequestTimeout,
        _ => ConversationCognitionErrorCode::InvalidProviderResponse,
    })
}
fn map_retrieval_degradation(
    code: &RetrievalDegradationCode,
) -> Option<ConversationDegradationCode> {
    Some(match code {
        RetrievalDegradationCode::VectorSkippedSensitiveQuery => {
            ConversationDegradationCode::VectorSkippedSensitiveQuery
        }
        RetrievalDegradationCode::NoActiveEmbeddingProfile => {
            ConversationDegradationCode::NoActiveEmbeddingProfile
        }
        RetrievalDegradationCode::EmbeddingCredentialNotFound => {
            ConversationDegradationCode::EmbeddingCredentialNotFound
        }
        RetrievalDegradationCode::IndexDirectoryMissing => {
            ConversationDegradationCode::IndexDirectoryMissing
        }
        RetrievalDegradationCode::VectorStoreUnavailable => {
            ConversationDegradationCode::VectorStoreUnavailable
        }
        RetrievalDegradationCode::VectorIndexUnavailable => {
            ConversationDegradationCode::VectorIndexUnavailable
        }
        RetrievalDegradationCode::VectorUnavailable => {
            ConversationDegradationCode::VectorUnavailable
        }
        RetrievalDegradationCode::KeywordUnavailable => {
            ConversationDegradationCode::KeywordUnavailable
        }
        RetrievalDegradationCode::BothRetrievalUnavailable => {
            ConversationDegradationCode::BothRetrievalUnavailable
        }
        RetrievalDegradationCode::AuthoritativeReadUnavailable => {
            ConversationDegradationCode::AuthoritativeReadUnavailable
        }
        _ => ConversationDegradationCode::EmbeddingProviderUnavailable,
    })
}
fn error(code: ConversationCognitionErrorCode) -> ConversationCognitionError {
    let (message, recoverable) = match code {
        ConversationCognitionErrorCode::LifeIdentityNotFound => {
            ("No current LifeIdentity is available.", false)
        }
        ConversationCognitionErrorCode::PersonaNotFound => {
            ("The current Persona could not be loaded.", false)
        }
        ConversationCognitionErrorCode::PersonaLifeMismatch => (
            "The current Persona is not bound to this LifeIdentity.",
            false,
        ),
        ConversationCognitionErrorCode::InvalidConversationRequest => {
            ("The conversation request is invalid.", true)
        }
        ConversationCognitionErrorCode::InvalidHistoryRole => {
            ("Conversation history roles are invalid.", true)
        }
        ConversationCognitionErrorCode::ConversationInProgress => {
            ("A conversation request is already in progress.", true)
        }
        ConversationCognitionErrorCode::NoActiveProfile => {
            ("No active chat model profile is configured.", true)
        }
        ConversationCognitionErrorCode::CredentialNotFound => {
            ("No credential is stored for the active chat profile.", true)
        }
        ConversationCognitionErrorCode::ProviderInitializationFailed => {
            ("The chat provider could not be initialized.", true)
        }
        ConversationCognitionErrorCode::AuthenticationFailed => {
            ("The chat service rejected authentication.", false)
        }
        ConversationCognitionErrorCode::RateLimited => {
            ("The chat service rate limit was reached.", true)
        }
        ConversationCognitionErrorCode::NetworkUnavailable => {
            ("The chat service is unavailable.", true)
        }
        ConversationCognitionErrorCode::RequestTimeout => ("The chat request timed out.", true),
        ConversationCognitionErrorCode::InvalidProviderResponse => {
            ("The chat service returned an invalid response.", true)
        }
    };
    ConversationCognitionError::new(code, message, recoverable)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_is_strict_and_bounded() {
        let request = GovernedConversationRequest {
            request_id: "r".into(),
            user_message: "hello".into(),
            history: vec![],
        };
        assert!(validate_request(&request).is_ok());
        let invalid = serde_json::json!({"requestId":"r","userMessage":"x","history":[{"role":"system","content":"no"}]});
        assert!(serde_json::from_value::<GovernedConversationRequest>(invalid).is_err());
    }
    #[test]
    fn coordinator_rejects_duplicate_life_and_releases() {
        let coordinator = ConversationCognitionCoordinator::default();
        let permit = coordinator.acquire("one", "life").unwrap();
        let duplicate = match coordinator.acquire("two", "life") {
            Err(error) => error,
            Ok(_) => panic!("duplicate life requests must be rejected"),
        };
        assert_eq!(
            duplicate.code,
            ConversationCognitionErrorCode::ConversationInProgress
        );
        drop(permit);
        assert!(coordinator.acquire("two", "life").is_ok());
    }
}
