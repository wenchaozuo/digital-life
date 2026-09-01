use std::{collections::HashSet, sync::Mutex, time::Instant};

use serde::{Deserialize, Serialize};
use tauri::State;

use crate::{
    conversation::history::{
        AppendConversationTurnRequest, AppendConversationTurnResult, ConversationHistoryError,
        ConversationHistoryErrorCode, ConversationHistoryService,
        ConversationRole as PersistedConversationRole, PersistedConversationMessage,
    },
    emotion::{
        policy::{self, EmotionPolicyRequest, EmotionStimulus},
        EmotionCommitOutcome, EmotionError, EmotionErrorCode, EmotionEventSource,
    },
    experience::{ExperienceEpisodeError, ExperienceEpisodeErrorCode},
    memory::{
        context_builder::{
            MemoryContextBuildRequest, MemoryContextBuilder, MemoryContextEntry,
            MemoryContextSource,
        },
        retrieval_router::RetrievalSource,
        retrieval_runtime::{
            GenerationAwareSemanticRetrieval, GovernedRetrievalRequest,
            MemoryRetrievalRuntimeService, RetrievalAvailability, RetrievalDegradationCode,
        },
    },
    model::{
        profile::{ModelProfileService, ModelPurpose},
        runtime::{
            ActiveModelChatRequest, ModelRuntimeCoordinator, ModelRuntimeError,
            ModelRuntimeErrorCode, ModelRuntimeService,
        },
        ModelMessage, ModelMessageRole,
    },
    perception::{
        screen_chat_attachment::ScreenContextChatAttachmentBroker,
        screen_context::{
            ScreenContextErrorCode, ScreenContextHandoffBroker, ScreenContextIds,
            ScreenContextPayload, ScreenContextSessionFence, ScreenContextTextStatus,
        },
        screen_policy::{
            authorize_screen_perception, ScreenPerceptionRepository, ScreenPerceptionSessionGate,
        },
        screen_vision_context_handoff::ScreenVisionContextHandoffBroker,
        CurrentLifeAuthority,
    },
    prompt::{
        InitiativeLevel, PromptCommunicationStyle, PromptCompilationRequest, PromptCompiler,
        PromptCompilerErrorCode, PromptCurrentPerception, PromptEmotion, PromptLifeIdentity,
        PromptPersona, PromptRelationship, SafetyRulesVersion,
    },
    relationship::{
        policy::{self as relationship_policy, RelationshipPolicyRequest},
        RelationshipCommitOutcome, RelationshipError, RelationshipErrorCode,
        RelationshipEventSource, RelationshipState, PRIMARY_USER_SUBJECT_ID,
    },
    secrets::{SecretStore, WindowsCredentialSecretStore},
    storage::conversation_emotion::{
        conversation_emotion_event_id, conversation_emotion_source_ref,
        CONVERSATION_EMOTION_SOURCE_KIND,
    },
    storage::conversation_experience::ConversationEmotionRelationshipExperienceCommitError,
    storage::conversation_relationship::{
        conversation_relationship_event_id, conversation_relationship_source_ref,
        CONVERSATION_RELATIONSHIP_CHANGE_REASON, CONVERSATION_RELATIONSHIP_SOURCE_KIND,
    },
    storage::{LifeIdentityRecord, PersonaTemplateRecord, StorageService},
    vector_store::LanceDbVectorStoreRegistry,
};

const MAX_USER_MESSAGE_CHARACTERS: usize = 32_000;
const MAX_PERCEPTION_ATTACHMENT_ID_CHARACTERS: usize = 128;

/// TEST-ONLY deterministic seam type owned by a service INSTANCE (never
/// process-global): invoked exactly before EACH composite attempt (first and
/// the single retry), receiving `(life_id, turn_id, original_observed_at)` so
/// a focused test can perform one real independent emotion mutation and force
/// the typed revision race. Installed via
/// [`ConversationCognitionService::new_with_pre_composite_hook`].
#[cfg(test)]
pub(crate) type PreCompositeHook = Box<dyn Fn(&str, &str, &str) + Send + Sync>;

/// TEST-ONLY mapper surface for the observation boundary proof.
#[cfg(test)]
pub(crate) fn test_map_observation_error(
    emotion_error: EmotionError,
) -> ConversationCognitionError {
    map_emotion_observation_error(emotion_error)
}

/// TEST-ONLY mapper surface for the general policy/commit boundary proof.
#[cfg(test)]
pub(crate) fn test_map_general_error(emotion_error: EmotionError) -> ConversationCognitionError {
    map_emotion_error(emotion_error)
}

/// TEST-ONLY mapper surface for the four-domain persistence boundary proof.
#[cfg(test)]
pub(crate) fn test_map_four_domain_error(
    commit_error: ConversationEmotionRelationshipExperienceCommitError,
) -> ConversationCognitionError {
    map_four_domain_composite_commit_error(commit_error)
}

/// TEST-ONLY retry-classifier surface for the four-domain persistence proof.
#[cfg(test)]
pub(crate) fn test_four_domain_error_is_revision_conflict(
    commit_error: &ConversationEmotionRelationshipExperienceCommitError,
) -> bool {
    four_domain_commit_error_is_revision_conflict(commit_error)
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GovernedConversationRequest {
    pub request_id: String,
    pub conversation_id: String,
    pub current_message: String,
    #[serde(default)]
    pub perception_attachment_id: Option<String>,
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
    pub conversation_id: String,
    pub assistant_message: String,
    pub persisted_messages: Vec<PersistedConversationMessage>,
    pub profile_display_name: Option<String>,
    pub model_name: Option<String>,
    pub memory: ConversationMemoryMetadata,
    pub latency_ms: u64,
    pub replayed: bool,
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
    ConversationNotFound,
    ConversationLifeMismatch,
    TurnIdConflict,
    ConversationChangedDuringRequest,
    ConversationStorageUnavailable,
    NoActiveProfile,
    CredentialNotFound,
    ProviderInitializationFailed,
    AuthenticationFailed,
    RateLimited,
    NetworkUnavailable,
    RequestTimeout,
    InvalidProviderResponse,
    EmotionStateUnavailable,
    EmotionChangedDuringRequest,
    EmotionCommitConflict,
    EmotionIntegrationFailure,
    RelationshipStateUnavailable,
    RelationshipChangedDuringRequest,
    RelationshipCommitConflict,
    RelationshipIntegrationFailure,
    ExperienceCommitConflict,
    ExperienceIntegrationFailure,
    PerceptionContextUnavailable,
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
        conversation_id: &str,
    ) -> Result<ConversationPermit<'_>, ConversationCognitionError> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| error(ConversationCognitionErrorCode::ConversationInProgress))?;
        let request_key = format!("request:{request_id}");
        let conversation_key = format!("conversation:{life_id}:{conversation_id}");
        if request_id.trim().is_empty()
            || conversation_id.trim().is_empty()
            || active.contains(&request_key)
            || active.contains(&conversation_key)
        {
            return Err(error(
                ConversationCognitionErrorCode::ConversationInProgress,
            ));
        }
        active.insert(request_key.clone());
        active.insert(conversation_key.clone());
        Ok(ConversationPermit {
            coordinator: self,
            request_key,
            conversation_key,
        })
    }
}

struct ConversationPermit<'a> {
    coordinator: &'a ConversationCognitionCoordinator,
    request_key: String,
    conversation_key: String,
}
impl Drop for ConversationPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.coordinator.active.lock() {
            active.remove(&self.request_key);
            active.remove(&self.conversation_key);
        }
    }
}

pub struct ConversationCognitionService<'a, S>
where
    S: SecretStore + ?Sized,
{
    storage: &'a StorageService,
    secrets: &'a S,
    model_coordinator: &'a ModelRuntimeCoordinator,
    retrieval_registry: &'a LanceDbVectorStoreRegistry,
    coordinator: &'a ConversationCognitionCoordinator,
    screen_perception: Option<ScreenPerceptionAuthorities<'a>>,
    /// TEST-ONLY deterministic seam owned by THIS service instance, compiled
    /// out of production builds entirely: invoked exactly before EACH
    /// composite attempt (first and the single retry), receiving
    /// `(life_id, turn_id, original_observed_at)` so a focused test can
    /// perform one real independent emotion mutation and force the typed
    /// revision race. Not fault injection — a hook-free instance behaves
    /// identically to the previous layout.
    #[cfg(test)]
    pre_composite_hook: Option<PreCompositeHook>,
}

struct ScreenPerceptionAuthorities<'a> {
    current_life: &'a dyn CurrentLifeAuthority,
    repository: &'a dyn ScreenPerceptionRepository,
    session_gate: &'a ScreenPerceptionSessionGate,
    handoff_broker: &'a ScreenContextHandoffBroker,
    attachment_broker: &'a ScreenContextChatAttachmentBroker,
    vision_handoff_broker: Option<&'a ScreenVisionContextHandoffBroker>,
}

enum ClaimedPerceptionAuthority {
    LocalOcr {
        attachment_id: String,
        grant_id: String,
        life_id: String,
        prompt: PromptCurrentPerception,
    },
    CloudVision {
        attachment_id: String,
        prompt: PromptCurrentPerception,
    },
}

impl ClaimedPerceptionAuthority {
    fn prompt(&self) -> PromptCurrentPerception {
        match self {
            Self::LocalOcr { prompt, .. } | Self::CloudVision { prompt, .. } => prompt.clone(),
        }
    }
}

impl<'a, S> ConversationCognitionService<'a, S>
where
    S: SecretStore + ?Sized,
{
    pub fn new(
        storage: &'a StorageService,
        secrets: &'a S,
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
            screen_perception: None,
            #[cfg(test)]
            pre_composite_hook: None,
        }
    }

    pub(crate) fn new_with_screen_perception(
        storage: &'a StorageService,
        secrets: &'a S,
        model_coordinator: &'a ModelRuntimeCoordinator,
        retrieval_registry: &'a LanceDbVectorStoreRegistry,
        coordinator: &'a ConversationCognitionCoordinator,
        current_life: &'a dyn CurrentLifeAuthority,
        repository: &'a dyn ScreenPerceptionRepository,
        session_gate: &'a ScreenPerceptionSessionGate,
        handoff_broker: &'a ScreenContextHandoffBroker,
        attachment_broker: &'a ScreenContextChatAttachmentBroker,
    ) -> Self {
        Self::new_with_screen_perception_and_vision(
            storage,
            secrets,
            model_coordinator,
            retrieval_registry,
            coordinator,
            current_life,
            repository,
            session_gate,
            handoff_broker,
            attachment_broker,
            None,
        )
    }

    pub(crate) fn new_with_screen_perception_and_vision(
        storage: &'a StorageService,
        secrets: &'a S,
        model_coordinator: &'a ModelRuntimeCoordinator,
        retrieval_registry: &'a LanceDbVectorStoreRegistry,
        coordinator: &'a ConversationCognitionCoordinator,
        current_life: &'a dyn CurrentLifeAuthority,
        repository: &'a dyn ScreenPerceptionRepository,
        session_gate: &'a ScreenPerceptionSessionGate,
        handoff_broker: &'a ScreenContextHandoffBroker,
        attachment_broker: &'a ScreenContextChatAttachmentBroker,
        vision_handoff_broker: Option<&'a ScreenVisionContextHandoffBroker>,
    ) -> Self {
        Self {
            storage,
            secrets,
            model_coordinator,
            retrieval_registry,
            coordinator,
            screen_perception: Some(ScreenPerceptionAuthorities {
                current_life,
                repository,
                session_gate,
                handoff_broker,
                attachment_broker,
                vision_handoff_broker,
            }),
            #[cfg(test)]
            pre_composite_hook: None,
        }
    }

    /// TEST-ONLY constructor: identical to [`Self::new`] except the returned
    /// instance owns `hook`, invoked before each composite attempt. No static
    /// state, no global mutex — parallel tests each drive their own instance.
    #[cfg(test)]
    pub(crate) fn new_with_pre_composite_hook(
        storage: &'a StorageService,
        secrets: &'a S,
        model_coordinator: &'a ModelRuntimeCoordinator,
        retrieval_registry: &'a LanceDbVectorStoreRegistry,
        coordinator: &'a ConversationCognitionCoordinator,
        hook: PreCompositeHook,
    ) -> Self {
        Self {
            storage,
            secrets,
            model_coordinator,
            retrieval_registry,
            coordinator,
            screen_perception: None,
            pre_composite_hook: Some(hook),
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
        let _permit =
            self.coordinator
                .acquire(&request.request_id, &life.id, &request.conversation_id)?;
        let started = Instant::now();
        let history = ConversationHistoryService::new(self.storage);
        if let Some(existing) = history
            .find_turn(&life.id, &request.conversation_id, &request.request_id)
            .map_err(map_history_error)?
        {
            if existing.user_message.content != request.current_message {
                return Err(error(ConversationCognitionErrorCode::TurnIdConflict));
            }
            return Ok(replayed_response(request, existing, started));
        }
        if request.perception_attachment_id.is_some() && self.screen_perception.is_none() {
            return Err(error(
                ConversationCognitionErrorCode::PerceptionContextUnavailable,
            ));
        }
        let conversation = history
            .get(&life.id, &request.conversation_id)
            .map_err(map_history_error)?;
        let persisted_history = history
            .recent_messages(&life.id, &request.conversation_id)
            .map_err(map_history_error)?;
        let persona_record = self
            .storage
            .get_persona(&life.persona_id)
            .map_err(|_| error(ConversationCognitionErrorCode::PersonaNotFound))?
            .ok_or_else(|| error(ConversationCognitionErrorCode::PersonaNotFound))?;
        let persona = parse_persona(&life, &persona_record)?;

        // D11-D PRE-TURN emotion projection. This READ happens before memory
        // retrieval and before the model call: the prompt must see the
        // effective emotion that existed BEFORE this turn's model response
        // and BEFORE the post-model C2 mutation. Pure read: no revision
        // advance, no event, no timestamp change. Any observation or policy
        // failure fails closed here — the model is never called without
        // governed current-emotion evidence.
        let pre_turn_observation = self
            .storage
            .load_emotion_runtime_observation(&life.id)
            .map_err(map_emotion_observation_error)?;
        let effective = policy::effective_after_decay(
            &pre_turn_observation.state,
            pre_turn_observation.elapsed_seconds,
        )
        .map_err(map_emotion_error)?;
        let prompt_emotion = PromptEmotion {
            valence: effective.valence,
            activation: effective.activation,
        };

        // D12-D PRE-TURN relationship projection. The SAME boundary rule as
        // emotion: this READ happens BEFORE the model call and its bounded
        // dimensions feed ONLY PromptRelationship. It is NEVER reused as the
        // post-model mutation base — C2's own post-model load + shared retry
        // remains the frozen mutation authority, so a relationship change
        // during generation can never reflect into this turn's own prompt.
        let pre_turn_relationship =
            <StorageService as crate::relationship::RelationshipRepository>::load_current_state(
                self.storage,
                &life.id,
                PRIMARY_USER_SUBJECT_ID,
            )
            .map_err(map_relationship_state_load_error)?
            .ok_or_else(|| error(ConversationCognitionErrorCode::RelationshipStateUnavailable))?;
        let prompt_relationship = PromptRelationship {
            familiarity: pre_turn_relationship.values.familiarity,
            trust: pre_turn_relationship.values.trust,
            emotional_closeness: pre_turn_relationship.values.emotional_closeness,
            collaboration: pre_turn_relationship.values.collaboration,
            safety: pre_turn_relationship.values.safety,
            dependency_tendency: pre_turn_relationship.values.dependency_tendency,
            boundary_comfort: pre_turn_relationship.values.boundary_comfort,
            tension: pre_turn_relationship.values.tension,
        };

        let model_runtime =
            ModelRuntimeService::new(self.storage, self.secrets, self.model_coordinator);
        let semantic = GenerationAwareSemanticRetrieval::new(
            self.storage,
            &model_runtime,
            self.retrieval_registry,
        );
        let retrieval = MemoryRetrievalRuntimeService::new(self.storage, &semantic);
        let retrieval_result = retrieval
            .retrieve(GovernedRetrievalRequest {
                life_id: life.id.clone(),
                query: request.current_message.clone(),
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
        let prompt_request = PromptCompilationRequest {
            safety_rules_version: SafetyRulesVersion::V1,
            life_identity: PromptLifeIdentity {
                display_name: life.name.clone(),
                identity_version: life.version,
            },
            persona,
            relationship: prompt_relationship,
            emotion: prompt_emotion,
            memory_context: memory_context.context.clone(),
            current_perception: None,
        };
        let messages = persisted_history
            .into_iter()
            .map(|message| ModelMessage {
                role: match message.role {
                    PersistedConversationRole::User => ModelMessageRole::User,
                    PersistedConversationRole::Assistant => ModelMessageRole::Assistant,
                },
                content: message.content,
            })
            .chain(std::iter::once(ModelMessage {
                role: ModelMessageRole::User,
                content: request.current_message.clone(),
            }))
            .collect();
        let no_active_embedding_profile = retrieval_result
            .degradation_codes
            .contains(&RetrievalDegradationCode::VectorIndexUnavailable)
            && matches!(
                ModelProfileService::new(self.storage).get_active(ModelPurpose::Embedding),
                Ok(None)
            );
        let runtime = ModelRuntimeService::new(self.storage, self.secrets, self.model_coordinator);
        let compile_prompt = |request: PromptCompilationRequest| {
            PromptCompiler.compile(request).map_err(|compile_error| {
                if compile_error.code == PromptCompilerErrorCode::InvalidEmotion {
                    error(ConversationCognitionErrorCode::EmotionIntegrationFailure)
                } else if compile_error.code == PromptCompilerErrorCode::InvalidRelationship {
                    error(ConversationCognitionErrorCode::RelationshipIntegrationFailure)
                } else if compile_error.code == PromptCompilerErrorCode::InvalidPerception {
                    error(ConversationCognitionErrorCode::PerceptionContextUnavailable)
                } else {
                    error(ConversationCognitionErrorCode::PersonaNotFound)
                }
            })
        };
        let (resolved, compilation, claimed_perception) =
            if let Some(attachment_id) = request.perception_attachment_id.as_deref() {
                // All potentially failing or slow preparation, including
                // credential lookup and Provider construction, finishes
                // before this final perception claim. After claim the only
                // pre-Provider work is bounded in-memory prompt compilation.
                let resolved = runtime
                    .resolve_active_chat_provider()
                    .map_err(map_model_error)?;
                let authorities = self.screen_perception.as_ref().ok_or_else(|| {
                    error(ConversationCognitionErrorCode::PerceptionContextUnavailable)
                })?;
                let claimed = claim_perception(
                    authorities,
                    attachment_id,
                    &life.id,
                    &request.conversation_id,
                    &request.request_id,
                )?;
                let compilation = compile_prompt(PromptCompilationRequest {
                    current_perception: Some(claimed.prompt()),
                    ..prompt_request
                })?;
                (resolved, compilation, Some(claimed))
            } else {
                // Preserve the existing no-perception path: compilation is
                // still performed before Provider resolution and no screen
                // authority is touched.
                let compilation = compile_prompt(prompt_request)?;
                let resolved = runtime
                    .resolve_active_chat_provider()
                    .map_err(map_model_error)?;
                (resolved, compilation, None)
            };
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
        // MODEL SUCCESS boundary: everything below persists; nothing above
        // this point has touched emotion or conversation state.
        //
        // One time observation drives BOTH the policy elapsed calculation and
        // the transition event_time, so decay and persisted evidence cannot
        // drift. The observation happens only after model success. The SAME
        // fixed timestamp anchors BOTH transitions' event_time — one
        // deterministic turn evidence anchor; relationship never reads a
        // clock of its own.
        let first_observation = self
            .storage
            .load_emotion_runtime_observation(&life.id)
            .map_err(map_emotion_observation_error)?;
        let append_request = AppendConversationTurnRequest {
            life_id: life.id.clone(),
            conversation_id: request.conversation_id.clone(),
            turn_id: request.request_id.clone(),
            user_content: request.current_message.clone(),
            assistant_content: response.text.clone(),
            expected_revision: Some(conversation.revision),
        };
        let build_transition = |state: &crate::emotion::EmotionState,
                                elapsed_seconds: u64,
                                event_time: &str|
         -> Result<
            crate::emotion::EmotionTransition,
            ConversationCognitionError,
        > {
            let policy_request = EmotionPolicyRequest::new(
                conversation_emotion_event_id(
                    &life.id,
                    &request.conversation_id,
                    &request.request_id,
                ),
                EmotionEventSource::new(
                    CONVERSATION_EMOTION_SOURCE_KIND,
                    conversation_emotion_source_ref(&request.conversation_id, &request.request_id),
                ),
                conversation_interaction_stimulus_v1(),
                elapsed_seconds,
                event_time,
            )
            .map_err(map_emotion_error)?;
            policy::evolve(state, policy_request).map_err(map_emotion_error)
        };
        let build_relationship_transition = |state: &RelationshipState,
                                             event_time: &str|
         -> Result<
            crate::relationship::RelationshipTransition,
            ConversationCognitionError,
        > {
            // Frozen B2 policy request: canonical identity derived from
            // this exact turn + the primary-user counterpart from the
            // authoritative state. No manual familiarity math, no
            // sentiment inspection, no clock read (T is injected).
            let policy_request = RelationshipPolicyRequest::new(
                conversation_relationship_event_id(
                    &life.id,
                    PRIMARY_USER_SUBJECT_ID,
                    &request.conversation_id,
                    &request.request_id,
                ),
                RelationshipEventSource::new(
                    CONVERSATION_RELATIONSHIP_SOURCE_KIND,
                    conversation_relationship_source_ref(
                        &request.conversation_id,
                        &request.request_id,
                    ),
                ),
                CONVERSATION_RELATIONSHIP_CHANGE_REASON,
                relationship_policy::RelationshipStimulusV1::SuccessfulConversationTurn,
                event_time,
            )
            .map_err(map_relationship_error)?;
            relationship_policy::evolve(state, policy_request).map_err(map_relationship_error)
        };

        // ONE atomic four-domain composite commit for conversation + emotion
        // + relationship + experience, with ONE SHARED retry budget: at most
        // TWO total composite attempts. Either revision authority's typed
        // RevisionConflict opens the single retry; the retry refreshes BOTH
        // authorities against the SAME fixed observation time and rebuilds
        // both transitions without calling the model again. Experience is
        // immutable occurrence evidence and never opens retry. The second
        // attempt is final.
        let first_observed_at = first_observation.observed_at.clone();
        let mut transition = build_transition(
            &first_observation.state,
            first_observation.elapsed_seconds,
            &first_observed_at,
        )?;
        // The primary-user relationship authority is loaded only after model
        // success. Absence is a typed failure — no state may be synthesized.
        let mut relationship_state =
            <StorageService as crate::relationship::RelationshipRepository>::load_current_state(
                self.storage,
                &life.id,
                PRIMARY_USER_SUBJECT_ID,
            )
            .map_err(map_relationship_state_load_error)?
            .ok_or_else(|| error(ConversationCognitionErrorCode::RelationshipStateUnavailable))?;
        let mut relationship_transition =
            build_relationship_transition(&relationship_state, &first_observed_at)?;

        #[cfg(test)]
        if let Some(hook) = self.pre_composite_hook.as_ref() {
            hook(&life.id, &request.request_id, &first_observed_at);
        }
        let composite = match self
            .storage
            .append_complete_turn_with_emotion_and_relationship_and_experience(
                &append_request,
                transition,
                relationship_transition,
            ) {
            Ok(outcome) => outcome,
            Err(commit_error) if four_domain_commit_error_is_revision_conflict(&commit_error) => {
                // Single shared retry: refresh BOTH authorities. Emotion uses
                // the frozen explicit-timestamp observation so the SAME fixed
                // T stays the evidence anchor; relationship reloads its
                // current authoritative revision. Same model output, same
                // content, same expected conversation revision, same event
                // identities, same stimulus values, same T.
                let retry_observation = self
                    .storage
                    .load_emotion_runtime_observation_at(&life.id, &first_observed_at)
                    .map_err(map_emotion_observation_error)?;
                transition = build_transition(
                    &retry_observation.state,
                    // Elapsed recomputed against the NEWER last_applied_at but
                    // with the SAME fixed observation: a later applied time
                    // clamps to zero inside the shared calculation.
                    retry_observation.elapsed_seconds,
                    &first_observed_at,
                )?;
                relationship_state = <StorageService as crate::relationship::RelationshipRepository>::load_current_state(
                    self.storage,
                    &life.id,
                    PRIMARY_USER_SUBJECT_ID,
                )
                .map_err(map_relationship_state_load_error)?
                .ok_or_else(|| error(ConversationCognitionErrorCode::RelationshipStateUnavailable))?;
                relationship_transition =
                    build_relationship_transition(&relationship_state, &first_observed_at)?;
                #[cfg(test)]
                if let Some(hook) = self.pre_composite_hook.as_ref() {
                    hook(&life.id, &request.request_id, &first_observed_at);
                }
                // Attempt #2 is FINAL: any error here maps straight through.
                self.storage
                    .append_complete_turn_with_emotion_and_relationship_and_experience(
                        &append_request,
                        transition,
                        relationship_transition,
                    )
                    .map_err(map_four_domain_composite_commit_error)?
            }
            Err(commit_error) => {
                return Err(map_four_domain_composite_commit_error(commit_error));
            }
        };
        let appended = composite.turn;
        debug_assert!(matches!(
            composite.emotion,
            EmotionCommitOutcome::Committed { .. }
        ));
        debug_assert!(matches!(
            composite.relationship,
            RelationshipCommitOutcome::Committed { .. }
        ));
        debug_assert!(matches!(
            composite.experience,
            crate::experience::ExperienceEpisodeCommitOutcome::Applied { .. }
        ));
        if let Some(claimed) = claimed_perception.as_ref() {
            if let Some(authorities) = self.screen_perception.as_ref() {
                retire_claimed_perception(
                    claimed,
                    &request.conversation_id,
                    &request.request_id,
                    authorities,
                );
            }
        }
        let mut degradations = retrieval_result
            .degradation_codes
            .iter()
            .filter_map(map_retrieval_degradation)
            .collect::<Vec<_>>();
        if no_active_embedding_profile {
            degradations.push(ConversationDegradationCode::NoActiveEmbeddingProfile);
        }
        if !memory_context.degradation_codes.is_empty()
            && !degradations.contains(&ConversationDegradationCode::MemoryContextUnavailable)
        {
            degradations.push(ConversationDegradationCode::MemoryContextUnavailable);
        }
        Ok(GovernedConversationResponse {
            request_id: request.request_id,
            conversation_id: request.conversation_id,
            assistant_message: appended.assistant_message.content.clone(),
            persisted_messages: persisted_messages(&appended),
            profile_display_name: Some(profile_display_name),
            model_name: Some(model_name),
            memory: ConversationMemoryMetadata {
                retrieved_count: retrieval_result.retrieved_count,
                used_count: memory_context.used_count,
                truncated: memory_context.truncated,
                degradation_codes: degradations,
                vector_availability: retrieval_result.availability,
                rebuild_recommended: retrieval_result.rebuild_recommended,
            },
            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            replayed: false,
        })
    }
}

#[cfg(windows)]
#[tauri::command]
#[allow(private_interfaces)]
pub async fn chat_with_governed_context(
    storage: State<'_, StorageService>,
    secrets: State<'_, WindowsCredentialSecretStore>,
    model_coordinator: State<'_, ModelRuntimeCoordinator>,
    retrieval_registry: State<'_, LanceDbVectorStoreRegistry>,
    coordinator: State<'_, ConversationCognitionCoordinator>,
    session_gate: State<'_, ScreenPerceptionSessionGate>,
    handoff_broker: State<'_, ScreenContextHandoffBroker>,
    attachment_broker: State<'_, ScreenContextChatAttachmentBroker>,
    vision_handoff_broker: State<'_, ScreenVisionContextHandoffBroker>,
    request: GovernedConversationRequest,
) -> Result<GovernedConversationResponse, ConversationCognitionError> {
    ConversationCognitionService::new_with_screen_perception_and_vision(
        storage.inner(),
        secrets.inner(),
        model_coordinator.inner(),
        retrieval_registry.inner(),
        coordinator.inner(),
        storage.inner(),
        storage.inner(),
        session_gate.inner(),
        handoff_broker.inner(),
        attachment_broker.inner(),
        Some(vision_handoff_broker.inner()),
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

fn claim_perception(
    authorities: &ScreenPerceptionAuthorities<'_>,
    attachment_id: &str,
    original_life_id: &str,
    conversation_id: &str,
    request_id: &str,
) -> Result<ClaimedPerceptionAuthority, ConversationCognitionError> {
    let current_life_id = authorities
        .current_life
        .current_life_id()
        .map_err(|_| error(ConversationCognitionErrorCode::PerceptionContextUnavailable))?;
    if current_life_id.as_deref() != Some(original_life_id) {
        return Err(error(
            ConversationCognitionErrorCode::PerceptionContextUnavailable,
        ));
    }

    authorize_screen_perception(
        authorities.repository,
        authorities.session_gate,
        original_life_id,
    )
    .map_err(|_| error(ConversationCognitionErrorCode::PerceptionContextUnavailable))?;
    let session_fence = authorities
        .session_gate
        .life_fence_for(original_life_id)
        .ok_or_else(|| error(ConversationCognitionErrorCode::PerceptionContextUnavailable))?;
    let expected_fence = ScreenContextSessionFence(session_fence);
    let ocr_attachment = match authorities.attachment_broker.get_exact(attachment_id) {
        Ok(attachment) => Some(attachment),
        Err(error)
            if error.code
                == crate::perception::screen_chat_attachment::
                    ScreenContextChatAttachmentErrorCode::AttachmentNotFound => None,
        Err(_) => {
            return Err(error(
                ConversationCognitionErrorCode::PerceptionContextUnavailable,
            ));
        }
    };
    let vision_attachment = match authorities.vision_handoff_broker {
        Some(broker) => match broker.get_exact(attachment_id) {
            Ok(status) => Some(status),
            Err(error)
                if error.code
                    == crate::perception::screen_vision_context_handoff::
                        ScreenVisionContextHandoffErrorCode::AttachmentNotFound => None,
            Err(_) => {
                return Err(error(
                    ConversationCognitionErrorCode::PerceptionContextUnavailable,
                ));
            }
        },
        None => None,
    };
    if ocr_attachment.is_some() && vision_attachment.is_some() {
        return Err(error(
            ConversationCognitionErrorCode::PerceptionContextUnavailable,
        ));
    }

    if let Some(attachment) = ocr_attachment {
        if attachment.life_id != original_life_id || attachment.session_fence != expected_fence {
            return Err(error(
                ConversationCognitionErrorCode::PerceptionContextUnavailable,
            ));
        }

        let payload = authorities
            .handoff_broker
            .claim_grant(ScreenContextIds {
                grant_id: attachment.grant_id.clone(),
                life_id: original_life_id.to_string(),
                session_fence: expected_fence,
                conversation_id: conversation_id.to_string(),
                request_id: request_id.to_string(),
            })
            .map_err(|_| error(ConversationCognitionErrorCode::PerceptionContextUnavailable))?;
        let prompt = prompt_perception_from_payload(payload)?;
        authorities
            .attachment_broker
            .mark_bound(&attachment.attachment_id)
            .map_err(|_| error(ConversationCognitionErrorCode::PerceptionContextUnavailable))?;

        return Ok(ClaimedPerceptionAuthority::LocalOcr {
            attachment_id: attachment.attachment_id,
            grant_id: attachment.grant_id,
            life_id: original_life_id.to_string(),
            prompt,
        });
    }

    let Some(vision_handoff_broker) = authorities.vision_handoff_broker else {
        return Err(error(
            ConversationCognitionErrorCode::PerceptionContextUnavailable,
        ));
    };
    let vision = vision_handoff_broker
        .claim_exact(
            attachment_id,
            original_life_id,
            &session_fence.to_string(),
            conversation_id,
            request_id,
        )
        .map_err(|_| error(ConversationCognitionErrorCode::PerceptionContextUnavailable))?;
    Ok(ClaimedPerceptionAuthority::CloudVision {
        attachment_id: vision.attachment_id,
        prompt: PromptCurrentPerception::CloudVision {
            summary: vision.summary,
            observations: vision.observations,
        },
    })
}

fn prompt_perception_from_payload(
    payload: ScreenContextPayload,
) -> Result<PromptCurrentPerception, ConversationCognitionError> {
    if payload.status != ScreenContextTextStatus::Recognized {
        return Err(error(
            ConversationCognitionErrorCode::PerceptionContextUnavailable,
        ));
    }
    Ok(PromptCurrentPerception::LocalOcr {
        text: payload.text,
        truncated: payload.truncated,
    })
}

fn retire_claimed_perception(
    claimed: &ClaimedPerceptionAuthority,
    conversation_id: &str,
    request_id: &str,
    authorities: &ScreenPerceptionAuthorities<'_>,
) {
    match claimed {
        ClaimedPerceptionAuthority::LocalOcr {
            attachment_id,
            grant_id,
            life_id,
            ..
        } => {
            let may_remove_attachment = match authorities.handoff_broker.retire_bound_grant(
                grant_id,
                life_id,
                conversation_id,
                request_id,
            ) {
                Ok(()) => true,
                // A newer Observe may have replaced the old bound grant. The
                // old grant is then definitively absent; exact attachment
                // removal still cannot touch a newer attachment ID.
                Err(error) => error.code == ScreenContextErrorCode::NoCurrentContext,
            };
            if may_remove_attachment {
                let _ = authorities
                    .attachment_broker
                    .clear_bound_exact(attachment_id);
                let _ = authorities.attachment_broker.remove_exact(attachment_id);
            }
        }
        ClaimedPerceptionAuthority::CloudVision { attachment_id, .. } => {
            if let Some(vision_handoff_broker) = authorities.vision_handoff_broker {
                let _ = vision_handoff_broker.retire_bound_exact(
                    attachment_id,
                    conversation_id,
                    request_id,
                );
            }
        }
    }
}

fn validate_request(
    request: &GovernedConversationRequest,
) -> Result<(), ConversationCognitionError> {
    if request.request_id.trim().is_empty()
        || request.conversation_id.trim().is_empty()
        || request.current_message.trim().is_empty()
        || request.current_message.chars().count() > MAX_USER_MESSAGE_CHARACTERS
        || request
            .perception_attachment_id
            .as_deref()
            .is_some_and(|value| {
                value.trim().is_empty()
                    || value.chars().count() > MAX_PERCEPTION_ATTACHMENT_ID_CHARACTERS
            })
    {
        return Err(error(
            ConversationCognitionErrorCode::InvalidConversationRequest,
        ));
    }
    Ok(())
}

fn persisted_messages(result: &AppendConversationTurnResult) -> Vec<PersistedConversationMessage> {
    vec![
        result.user_message.clone().into(),
        result.assistant_message.clone().into(),
    ]
}

fn replayed_response(
    request: GovernedConversationRequest,
    existing: AppendConversationTurnResult,
    started: Instant,
) -> GovernedConversationResponse {
    GovernedConversationResponse {
        request_id: request.request_id,
        conversation_id: request.conversation_id,
        assistant_message: existing.assistant_message.content.clone(),
        persisted_messages: persisted_messages(&existing),
        profile_display_name: None,
        model_name: None,
        memory: ConversationMemoryMetadata {
            retrieved_count: 0,
            used_count: 0,
            truncated: false,
            degradation_codes: Vec::new(),
            vector_availability: RetrievalAvailability::NoMemory,
            rebuild_recommended: false,
        },
        latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        replayed: true,
    }
}

fn map_history_error(history_error: ConversationHistoryError) -> ConversationCognitionError {
    error(match history_error.code {
        ConversationHistoryErrorCode::ConversationNotFound => {
            ConversationCognitionErrorCode::ConversationNotFound
        }
        ConversationHistoryErrorCode::ConversationLifeMismatch => {
            ConversationCognitionErrorCode::ConversationLifeMismatch
        }
        ConversationHistoryErrorCode::TurnIdConflict => {
            ConversationCognitionErrorCode::TurnIdConflict
        }
        ConversationHistoryErrorCode::ConversationChangedDuringRequest => {
            ConversationCognitionErrorCode::ConversationChangedDuringRequest
        }
        _ => ConversationCognitionErrorCode::ConversationStorageUnavailable,
    })
}

/// Conversation Interaction Stimulus V1: the frozen bounded signal applied to
/// every successfully generated NEW governed turn. Deliberately makes NO
/// positive/negative valence claim and infers nothing from message text; a
/// successful interaction only contributes a small engagement impulse. With
/// the B2 activation gain (7/10) this yields +7 activation before decay.
fn conversation_interaction_stimulus_v1() -> EmotionStimulus {
    EmotionStimulus::new(0, 10).expect("the frozen conversation stimulus is in range")
}

fn map_emotion_error(emotion_error: EmotionError) -> ConversationCognitionError {
    error(match emotion_error.code {
        EmotionErrorCode::LifeNotFound | EmotionErrorCode::StateNotFound => {
            ConversationCognitionErrorCode::EmotionStateUnavailable
        }
        EmotionErrorCode::RevisionConflict => {
            ConversationCognitionErrorCode::EmotionChangedDuringRequest
        }
        EmotionErrorCode::EventConflict => ConversationCognitionErrorCode::EmotionCommitConflict,
        EmotionErrorCode::InvalidArgument | EmotionErrorCode::DatabaseUnavailable => {
            ConversationCognitionErrorCode::EmotionIntegrationFailure
        }
    })
}

/// Mapper for the READ-ONLY emotion runtime observation specifically. A
/// database hiccup while READING the authoritative state is ordinary
/// transient absence (retryable), whereas an invalid persisted timestamp or
/// unsupported observation input is an integration/invariant problem.
fn map_emotion_observation_error(emotion_error: EmotionError) -> ConversationCognitionError {
    error(match emotion_error.code {
        EmotionErrorCode::LifeNotFound
        | EmotionErrorCode::StateNotFound
        | EmotionErrorCode::DatabaseUnavailable => {
            ConversationCognitionErrorCode::EmotionStateUnavailable
        }
        EmotionErrorCode::InvalidArgument => {
            ConversationCognitionErrorCode::EmotionIntegrationFailure
        }
        // The observation reader never mutates, so conflict codes cannot
        // legitimately surface here; map them through the general boundary.
        EmotionErrorCode::RevisionConflict => {
            ConversationCognitionErrorCode::EmotionChangedDuringRequest
        }
        EmotionErrorCode::EventConflict => ConversationCognitionErrorCode::EmotionCommitConflict,
    })
}

/// Mapper for the READ-ONLY primary-user relationship state load. Absence or
/// a database hiccup is ordinary transient unavailability; an invariant
/// violation on the read path is an integration problem.
fn map_relationship_state_load_error(
    relationship_error: RelationshipError,
) -> ConversationCognitionError {
    error(match relationship_error.code {
        RelationshipErrorCode::LifeNotFound
        | RelationshipErrorCode::StateNotFound
        | RelationshipErrorCode::DatabaseUnavailable => {
            ConversationCognitionErrorCode::RelationshipStateUnavailable
        }
        RelationshipErrorCode::RevisionConflict => {
            ConversationCognitionErrorCode::RelationshipChangedDuringRequest
        }
        RelationshipErrorCode::EventConflict => {
            ConversationCognitionErrorCode::RelationshipCommitConflict
        }
        // The reader never mutates, so conflict codes cannot legitimately
        // surface here; an invalid-argument read is an integration failure.
        RelationshipErrorCode::InvalidArgument => {
            ConversationCognitionErrorCode::RelationshipIntegrationFailure
        }
    })
}

/// Mapper for the general relationship policy/commit boundary.
fn map_relationship_error(relationship_error: RelationshipError) -> ConversationCognitionError {
    error(match relationship_error.code {
        RelationshipErrorCode::LifeNotFound | RelationshipErrorCode::StateNotFound => {
            ConversationCognitionErrorCode::RelationshipStateUnavailable
        }
        RelationshipErrorCode::RevisionConflict => {
            ConversationCognitionErrorCode::RelationshipChangedDuringRequest
        }
        RelationshipErrorCode::EventConflict => {
            ConversationCognitionErrorCode::RelationshipCommitConflict
        }
        RelationshipErrorCode::InvalidArgument | RelationshipErrorCode::DatabaseUnavailable => {
            ConversationCognitionErrorCode::RelationshipIntegrationFailure
        }
    })
}

/// Intentional mapper for the D13-C1 four-domain composite error boundary.
/// Each cause domain keeps its own mapping; binding/missing-event failures are
/// internal governed-path invariant violations, never user problems.
fn map_four_domain_composite_commit_error(
    commit_error: ConversationEmotionRelationshipExperienceCommitError,
) -> ConversationCognitionError {
    use ConversationEmotionRelationshipExperienceCommitError as Composite;
    match commit_error {
        Composite::Conversation(history_error) => map_history_error(history_error),
        Composite::Emotion(emotion_error) => map_emotion_error(emotion_error),
        Composite::Relationship(relationship_error) => map_relationship_error(relationship_error),
        Composite::EmotionBindingMismatch(_) | Composite::EmotionEventMissing(_) => {
            error(ConversationCognitionErrorCode::EmotionIntegrationFailure)
        }
        Composite::RelationshipBindingMismatch(_) | Composite::RelationshipEventMissing(_) => {
            error(ConversationCognitionErrorCode::RelationshipIntegrationFailure)
        }
        Composite::Experience(experience_error) => map_experience_error(experience_error),
        Composite::ExperienceEpisodeMissing(_) => {
            error(ConversationCognitionErrorCode::ExperienceIntegrationFailure)
        }
    }
}

fn map_experience_error(experience_error: ExperienceEpisodeError) -> ConversationCognitionError {
    error(match experience_error.code {
        ExperienceEpisodeErrorCode::EpisodeConflict => {
            ConversationCognitionErrorCode::ExperienceCommitConflict
        }
        ExperienceEpisodeErrorCode::InvalidArgument
        | ExperienceEpisodeErrorCode::LifeNotFound
        | ExperienceEpisodeErrorCode::SourceNotFound
        | ExperienceEpisodeErrorCode::SourceBindingMismatch
        | ExperienceEpisodeErrorCode::DatabaseUnavailable => {
            ConversationCognitionErrorCode::ExperienceIntegrationFailure
        }
    })
}

/// True only for the typed emotion/relationship RevisionConflict produced by
/// the C1 four-domain composite — the ONLY retryable conditions sharing one
/// composite retry budget. Retry decisions inspect typed error codes directly;
/// no string parsing of `code()` or recoverable flags.
fn four_domain_commit_error_is_revision_conflict(
    commit_error: &ConversationEmotionRelationshipExperienceCommitError,
) -> bool {
    use ConversationEmotionRelationshipExperienceCommitError as Composite;
    match commit_error {
        Composite::Emotion(emotion) => emotion.code == EmotionErrorCode::RevisionConflict,
        Composite::Relationship(relationship) => {
            relationship.code == RelationshipErrorCode::RevisionConflict
        }
        _ => false,
    }
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
        RetrievalDegradationCode::EmbeddingProviderUnavailable
        | RetrievalDegradationCode::EmbeddingProfileNotFound
        | RetrievalDegradationCode::EmbeddingPurposeMismatch
        | RetrievalDegradationCode::UnsupportedEmbeddingProvider
        | RetrievalDegradationCode::EmbeddingDimensionMismatch => {
            ConversationDegradationCode::EmbeddingProviderUnavailable
        }
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
        ConversationCognitionErrorCode::ConversationNotFound => {
            ("The conversation was not found.", true)
        }
        ConversationCognitionErrorCode::ConversationLifeMismatch => (
            "The conversation does not belong to the current life.",
            false,
        ),
        ConversationCognitionErrorCode::TurnIdConflict => (
            "The request identifier conflicts with committed history.",
            false,
        ),
        ConversationCognitionErrorCode::ConversationChangedDuringRequest => (
            "The conversation changed while the response was being generated.",
            true,
        ),
        ConversationCognitionErrorCode::ConversationStorageUnavailable => {
            ("Conversation history is unavailable.", true)
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
        ConversationCognitionErrorCode::EmotionStateUnavailable => (
            "The authoritative emotion state is currently unavailable.",
            true,
        ),
        ConversationCognitionErrorCode::EmotionChangedDuringRequest => (
            "The emotion state changed while the response was being generated.",
            true,
        ),
        ConversationCognitionErrorCode::EmotionCommitConflict => (
            "The governed conversation turn conflicts with committed emotion evidence.",
            false,
        ),
        ConversationCognitionErrorCode::EmotionIntegrationFailure => {
            ("The governed emotion integration failed.", false)
        }
        ConversationCognitionErrorCode::RelationshipStateUnavailable => (
            "The authoritative relationship state is currently unavailable.",
            true,
        ),
        ConversationCognitionErrorCode::RelationshipChangedDuringRequest => (
            "The relationship state changed while the response was being generated.",
            true,
        ),
        ConversationCognitionErrorCode::RelationshipCommitConflict => (
            "The governed conversation turn conflicts with committed relationship evidence.",
            false,
        ),
        ConversationCognitionErrorCode::RelationshipIntegrationFailure => {
            ("The governed relationship integration failed.", false)
        }
        ConversationCognitionErrorCode::ExperienceCommitConflict => (
            "The governed conversation turn conflicts with committed experience evidence.",
            false,
        ),
        ConversationCognitionErrorCode::ExperienceIntegrationFailure => {
            ("The governed experience integration failed.", false)
        }
        ConversationCognitionErrorCode::PerceptionContextUnavailable => (
            "The attached screen context is no longer available. Observe the screen again and reattach it.",
            true,
        ),
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
            conversation_id: "conversation".into(),
            current_message: "hello".into(),
            perception_attachment_id: None,
        };
        assert!(validate_request(&request).is_ok());
        let decoded = serde_json::from_value::<GovernedConversationRequest>(serde_json::json!({
            "requestId": "r",
            "conversationId": "conversation",
            "currentMessage": "hello"
        }))
        .unwrap();
        assert_eq!(decoded.perception_attachment_id, None);
        let decoded = serde_json::from_value::<GovernedConversationRequest>(serde_json::json!({
            "requestId": "r",
            "conversationId": "conversation",
            "currentMessage": "hello",
            "perceptionAttachmentId": "opaque-attachment"
        }))
        .unwrap();
        assert_eq!(
            decoded.perception_attachment_id.as_deref(),
            Some("opaque-attachment")
        );
        let mut invalid_attachment = request.clone();
        invalid_attachment.perception_attachment_id = Some("  ".into());
        assert_eq!(
            validate_request(&invalid_attachment).unwrap_err().code,
            ConversationCognitionErrorCode::InvalidConversationRequest
        );
        invalid_attachment.perception_attachment_id = Some("x".repeat(129));
        assert_eq!(
            validate_request(&invalid_attachment).unwrap_err().code,
            ConversationCognitionErrorCode::InvalidConversationRequest
        );
        let invalid = serde_json::json!({"requestId":"r","conversationId":"conversation","currentMessage":"x","history":[]});
        assert!(serde_json::from_value::<GovernedConversationRequest>(invalid).is_err());
    }

    #[test]
    fn perception_unavailable_error_is_static_bounded_and_recoverable() {
        let error = error(ConversationCognitionErrorCode::PerceptionContextUnavailable);
        assert_eq!(
            error.message,
            "The attached screen context is no longer available. Observe the screen again and reattach it."
        );
        assert!(error.recoverable);
        assert_eq!(
            serde_json::to_value(error.code).unwrap(),
            serde_json::json!("PERCEPTION_CONTEXT_UNAVAILABLE")
        );
    }

    #[test]
    fn retrieval_query_source_is_exactly_the_current_message() {
        let source = include_str!("service.rs");
        let start = source.find("let retrieval_result =").unwrap();
        let end = source[start..].find("let entries =").unwrap() + start;
        let retrieval_source = &source[start..end];
        assert!(retrieval_source.contains("query: request.current_message.clone(),"));
        assert!(!retrieval_source.contains("perception_attachment_id"));
    }
    #[test]
    fn coordinator_scopes_concurrency_to_conversation_and_request_id() {
        let coordinator = ConversationCognitionCoordinator::default();
        let permit = coordinator
            .acquire("one", "life", "conversation-a")
            .unwrap();
        let duplicate = match coordinator.acquire("two", "life", "conversation-a") {
            Err(error) => error,
            Ok(_) => panic!("duplicate life requests must be rejected"),
        };
        assert_eq!(
            duplicate.code,
            ConversationCognitionErrorCode::ConversationInProgress
        );
        let duplicate_request = match coordinator.acquire("one", "life", "conversation-b") {
            Err(error) => error,
            Ok(_) => panic!("duplicate request ids must be rejected"),
        };
        assert_eq!(
            duplicate_request.code,
            ConversationCognitionErrorCode::ConversationInProgress
        );
        let independent = coordinator
            .acquire("three", "life", "conversation-b")
            .unwrap();
        drop(independent);
        drop(permit);
        assert!(coordinator.acquire("two", "life", "conversation-a").is_ok());
    }

    #[test]
    fn retrieval_degradation_mapping_is_explicit_and_stable() {
        let expected = [
            (
                RetrievalDegradationCode::VectorSkippedSensitiveQuery,
                ConversationDegradationCode::VectorSkippedSensitiveQuery,
            ),
            (
                RetrievalDegradationCode::NoActiveEmbeddingProfile,
                ConversationDegradationCode::NoActiveEmbeddingProfile,
            ),
            (
                RetrievalDegradationCode::EmbeddingCredentialNotFound,
                ConversationDegradationCode::EmbeddingCredentialNotFound,
            ),
            (
                RetrievalDegradationCode::EmbeddingProfileNotFound,
                ConversationDegradationCode::EmbeddingProviderUnavailable,
            ),
            (
                RetrievalDegradationCode::EmbeddingPurposeMismatch,
                ConversationDegradationCode::EmbeddingProviderUnavailable,
            ),
            (
                RetrievalDegradationCode::UnsupportedEmbeddingProvider,
                ConversationDegradationCode::EmbeddingProviderUnavailable,
            ),
            (
                RetrievalDegradationCode::EmbeddingProviderUnavailable,
                ConversationDegradationCode::EmbeddingProviderUnavailable,
            ),
            (
                RetrievalDegradationCode::EmbeddingDimensionMismatch,
                ConversationDegradationCode::EmbeddingProviderUnavailable,
            ),
            (
                RetrievalDegradationCode::IndexDirectoryMissing,
                ConversationDegradationCode::IndexDirectoryMissing,
            ),
            (
                RetrievalDegradationCode::VectorStoreUnavailable,
                ConversationDegradationCode::VectorStoreUnavailable,
            ),
            (
                RetrievalDegradationCode::VectorIndexUnavailable,
                ConversationDegradationCode::VectorIndexUnavailable,
            ),
            (
                RetrievalDegradationCode::VectorUnavailable,
                ConversationDegradationCode::VectorUnavailable,
            ),
            (
                RetrievalDegradationCode::KeywordUnavailable,
                ConversationDegradationCode::KeywordUnavailable,
            ),
            (
                RetrievalDegradationCode::AuthoritativeReadUnavailable,
                ConversationDegradationCode::AuthoritativeReadUnavailable,
            ),
            (
                RetrievalDegradationCode::BothRetrievalUnavailable,
                ConversationDegradationCode::BothRetrievalUnavailable,
            ),
        ];
        for (retrieval, conversation) in expected {
            assert_eq!(map_retrieval_degradation(&retrieval), Some(conversation));
        }
    }
}
