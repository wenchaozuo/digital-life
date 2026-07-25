//! Private D-8C6 integration between the sealed LLM wire protocol and D-6.
//!
//! This module owns configuration-time dispatch only. It does not expose D-6
//! capabilities, write domain records itself, or provide a fallback after LLM
//! mode has been selected.

use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use rusqlite::{params, OptionalExtension};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    memory::MemoryKind,
    model::{
        extraction::{
            execute_llm_extraction, ExtractionWireInputV1, LlmExtractorDescriptor,
            ValidatedExtractionWireResultV1, WireMemoryKindV1, WireProposalActionV1,
            WireSensitivityHintV1,
        },
        profile::{ModelProfile, ModelProfileService, ModelPurpose},
        transport::http1::SendDisposition,
    },
    secrets::SecretStore,
};

use super::{
    candidate_extraction::{
        CandidateExtractionAttemptOutcome, CandidateExtractionBatch, CandidateExtractionProposal,
        CandidateExtractionRequest, CandidateExtractor, CommitReconciliationResult,
        ExtractionError, ExtractorDescriptor, ProposalAction, SensitivityHint, StartedExtraction,
    },
    deterministic_candidate_extraction::{
        trigger_deterministic_candidate_extraction, ExtractionTriggerResponse,
        ExtractionTriggerStatus, SafeCommandError,
    },
    StorageService,
};

const LLM_CONCURRENCY: usize = 4;
const PERMIT_WAIT_TIMEOUT: Duration = Duration::from_secs(20);

/// Process-wide, app-managed LLM admission controller. Its capacity is fixed
/// and its Debug implementation deliberately contains no request or profile
/// material.
pub(crate) struct LlmCandidateExtractionCoordinator {
    semaphore: Arc<Semaphore>,
}

impl Default for LlmCandidateExtractionCoordinator {
    fn default() -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(LLM_CONCURRENCY)),
        }
    }
}

impl fmt::Debug for LlmCandidateExtractionCoordinator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LlmCandidateExtractionCoordinator([REDACTED])")
    }
}

impl LlmCandidateExtractionCoordinator {
    /// Private only: tests can avoid a real twenty-second wait without
    /// turning the production admission duration into a configuration input.
    async fn acquire_with_timeout(&self, timeout: Duration) -> Option<OwnedSemaphorePermit> {
        tokio::time::timeout(timeout, self.semaphore.clone().acquire_owned())
            .await
            .ok()
            .and_then(Result::ok)
    }
}

struct ExistingRun {
    status: ExtractionTriggerStatus,
    created_count: i64,
    merged_evidence_count: i64,
    blocked_count: i64,
    extractor_id: String,
    extractor_version: String,
    policy_version: String,
    lease_expired: bool,
}

/// The only command-facing candidate-extraction entry point. Callers cannot
/// select an extractor, profile, endpoint, credential, or concurrency value.
pub(crate) async fn trigger_candidate_extraction<S: SecretStore + ?Sized>(
    storage: &StorageService,
    coordinator: &LlmCandidateExtractionCoordinator,
    secrets: &S,
    life_id: &str,
    conversation_id: &str,
) -> Result<ExtractionTriggerResponse, SafeCommandError> {
    trigger_candidate_extraction_with_permit_timeout(
        storage,
        coordinator,
        secrets,
        life_id,
        conversation_id,
        PERMIT_WAIT_TIMEOUT,
    )
    .await
}

/// Private test seam for permit admission only. Production always calls the
/// public facade above with the frozen twenty-second duration.
async fn trigger_candidate_extraction_with_permit_timeout<S: SecretStore + ?Sized>(
    storage: &StorageService,
    coordinator: &LlmCandidateExtractionCoordinator,
    secrets: &S,
    life_id: &str,
    conversation_id: &str,
    permit_timeout: Duration,
) -> Result<ExtractionTriggerResponse, SafeCommandError> {
    if life_id.trim().is_empty() || conversation_id.trim().is_empty() {
        return Err(invalid_request());
    }

    if let Some(existing) = read_existing_run(storage, life_id, conversation_id)? {
        return handle_existing_run(storage, coordinator, life_id, conversation_id, existing).await;
    }

    let profiles = ModelProfileService::new(storage);
    let active = profiles
        .get_active(ModelPurpose::CandidateExtraction)
        .map_err(|_| storage_unavailable())?;
    let Some(active) = active else {
        return trigger_deterministic_candidate_extraction(storage, life_id, conversation_id);
    };

    // The active mapping itself selects LLM mode. A missing or invalid profile
    // never redirects to the deterministic extractor.
    let profile = profiles.get(&active.profile_id).ok();
    let descriptor = llm_descriptor();
    let started = match storage.start_candidate_extraction(
        life_id,
        conversation_id,
        descriptor.clone(),
        LlmExtractorDescriptor::v1().policy_version(),
    ) {
        Ok(Some(started)) => started,
        Ok(None) => return Ok(simple_response(ExtractionTriggerStatus::NoEligibleSnapshot)),
        Err(_) => {
            if let Some(existing) = read_existing_run(storage, life_id, conversation_id)? {
                return handle_existing_run(
                    storage,
                    coordinator,
                    life_id,
                    conversation_id,
                    existing,
                )
                .await;
            }
            return Err(storage_unavailable());
        }
    };

    let Some(profile) =
        profile.filter(|profile| profile.purpose == ModelPurpose::CandidateExtraction)
    else {
        return finish_attempt(
            storage,
            life_id,
            conversation_id,
            &ImmediateLlmFailureExtractor::definitely_not_sent(descriptor),
            &started,
        )
        .await;
    };

    let Some(permit) = coordinator.acquire_with_timeout(permit_timeout).await else {
        return finish_attempt(
            storage,
            life_id,
            conversation_id,
            &ImmediateLlmFailureExtractor::definitely_not_sent(descriptor),
            &started,
        )
        .await;
    };

    let extractor = LlmCandidateExtractor::new(descriptor, profile, secrets, permit);
    finish_attempt(storage, life_id, conversation_id, &extractor, &started).await
}

async fn handle_existing_run(
    storage: &StorageService,
    _coordinator: &LlmCandidateExtractionCoordinator,
    life_id: &str,
    conversation_id: &str,
    existing: ExistingRun,
) -> Result<ExtractionTriggerResponse, SafeCommandError> {
    let descriptor = llm_descriptor();
    if existing_matches_llm(&existing) {
        if existing.status == ExtractionTriggerStatus::Processing && existing.lease_expired {
            let started = storage
                .take_over_expired_extraction_lease(
                    life_id,
                    conversation_id,
                    &descriptor,
                    LlmExtractorDescriptor::v1().policy_version(),
                )
                .map_err(|_| storage_unavailable())?;
            if let Some(started) = started {
                // A process crash after an LLM attempt cannot prove that the
                // request was not sent. Recovery must never replay it.
                return finish_attempt(
                    storage,
                    life_id,
                    conversation_id,
                    &ImmediateLlmFailureExtractor::possibly_sent(descriptor),
                    &started,
                )
                .await;
            }
            return read_existing_run(storage, life_id, conversation_id)?
                .map(response_from_existing)
                .ok_or_else(storage_unavailable);
        }
        return Ok(response_from_existing(existing));
    }

    // Existing non-LLM runs remain entirely in D-7. Configuration is not read
    // here, so a later active mapping cannot reinterpret a persisted run.
    trigger_deterministic_candidate_extraction(storage, life_id, conversation_id)
}

async fn finish_attempt(
    storage: &StorageService,
    life_id: &str,
    conversation_id: &str,
    extractor: &dyn CandidateExtractor,
    started: &StartedExtraction,
) -> Result<ExtractionTriggerResponse, SafeCommandError> {
    let outcome = storage
        .run_candidate_extraction_attempt_once_async(extractor, started)
        .await;
    response_from_attempt_outcome(storage, life_id, conversation_id, outcome)
}

fn response_from_attempt_outcome(
    storage: &StorageService,
    life_id: &str,
    conversation_id: &str,
    outcome: CandidateExtractionAttemptOutcome,
) -> Result<ExtractionTriggerResponse, SafeCommandError> {
    match outcome {
        CandidateExtractionAttemptOutcome::Completed => {
            read_existing_run(storage, life_id, conversation_id)?
                .map(response_from_existing)
                .ok_or_else(storage_unavailable)
        }
        CandidateExtractionAttemptOutcome::CommitOutcomeUncertain(identity) => {
            match storage
                .reconcile_candidate_extraction_attempt_uncertainty(identity)
                .map_err(|_| storage_unavailable())?
            {
                CommitReconciliationResult::Completed { .. } => {
                    read_existing_run(storage, life_id, conversation_id)?
                        .map(response_from_existing)
                        .ok_or_else(storage_unavailable)
                }
                CommitReconciliationResult::TerminalFailed => {
                    Ok(simple_response(ExtractionTriggerStatus::Failed))
                }
                CommitReconciliationResult::SnapshotInvalidated => Ok(simple_response(
                    ExtractionTriggerStatus::SnapshotInvalidated,
                )),
                CommitReconciliationResult::CommitOutcomeUnavailable => {
                    Ok(simple_response(ExtractionTriggerStatus::Processing))
                }
                CommitReconciliationResult::StorageUnavailable => Err(storage_unavailable()),
            }
        }
        CandidateExtractionAttemptOutcome::TerminalFailed => {
            Ok(simple_response(ExtractionTriggerStatus::Failed))
        }
        CandidateExtractionAttemptOutcome::StaleAttempt => {
            Ok(simple_response(ExtractionTriggerStatus::StaleOrConflict))
        }
        // S1's LLM runner cannot schedule retry, but retain a safe response if
        // a future D-6 invariant violation ever returns this variant.
        CandidateExtractionAttemptOutcome::RetryScheduled => {
            Ok(simple_response(ExtractionTriggerStatus::RetryWait))
        }
        CandidateExtractionAttemptOutcome::StorageFailure => Err(storage_unavailable()),
    }
}

struct ImmediateLlmFailureExtractor {
    descriptor: ExtractorDescriptor,
    error: ExtractionError,
}

impl ImmediateLlmFailureExtractor {
    fn definitely_not_sent(descriptor: ExtractorDescriptor) -> Self {
        Self {
            descriptor,
            error: ExtractionError::llm_definitely_not_sent(),
        }
    }

    fn possibly_sent(descriptor: ExtractorDescriptor) -> Self {
        Self {
            descriptor,
            error: ExtractionError::llm_possibly_sent(),
        }
    }
}

impl CandidateExtractor for ImmediateLlmFailureExtractor {
    fn descriptor(&self) -> &ExtractorDescriptor {
        &self.descriptor
    }

    fn extract<'a>(
        &'a self,
        _request: CandidateExtractionRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<CandidateExtractionBatch, ExtractionError>>
                + Send
                + 'a,
        >,
    > {
        let error = self.error.clone();
        Box::pin(async move { Err(error) })
    }
}

struct LlmCandidateExtractor<'a, S: SecretStore + ?Sized> {
    descriptor: ExtractorDescriptor,
    protocol_descriptor: LlmExtractorDescriptor,
    profile: ModelProfile,
    secrets: &'a S,
    permit: Mutex<Option<OwnedSemaphorePermit>>,
}

impl<'a, S: SecretStore + ?Sized> LlmCandidateExtractor<'a, S> {
    fn new(
        descriptor: ExtractorDescriptor,
        profile: ModelProfile,
        secrets: &'a S,
        permit: OwnedSemaphorePermit,
    ) -> Self {
        Self {
            descriptor,
            protocol_descriptor: LlmExtractorDescriptor::v1(),
            profile,
            secrets,
            permit: Mutex::new(Some(permit)),
        }
    }
}

impl<S: SecretStore + ?Sized> CandidateExtractor for LlmCandidateExtractor<'_, S> {
    fn descriptor(&self) -> &ExtractorDescriptor {
        &self.descriptor
    }

    fn extract<'a>(
        &'a self,
        request: CandidateExtractionRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<CandidateExtractionBatch, ExtractionError>>
                + Send
                + 'a,
        >,
    > {
        let permit = match self.permit.lock() {
            Ok(mut permit) => permit.take(),
            Err(_) => None,
        };
        let protocol_descriptor = self.protocol_descriptor.clone();
        let profile = self.profile.clone();
        let secrets = self.secrets;
        Box::pin(async move {
            let Some(permit) = permit else {
                return Err(ExtractionError::llm_possibly_sent());
            };
            let input = ExtractionWireInputV1::from_messages(
                request
                    .messages
                    .into_iter()
                    .map(|message| (message.message_id, message.sequence_no, message.content))
                    .collect(),
            )
            .map_err(|_| ExtractionError::llm_possibly_sent())?;
            let result = execute_llm_extraction(&protocol_descriptor, &input, &profile, secrets)
                .await
                .map_err(map_llm_error)
                .and_then(map_wire_result);
            // Release before S1 re-enters D-6 classify/finalize persistence.
            drop(permit);
            result
        })
    }
}

fn map_llm_error(error: crate::model::extraction::LlmExtractionError) -> ExtractionError {
    match error.disposition() {
        SendDisposition::DefinitelyNotSent => ExtractionError::llm_definitely_not_sent(),
        SendDisposition::PossiblySent => ExtractionError::llm_possibly_sent(),
    }
}

fn map_wire_result(
    result: ValidatedExtractionWireResultV1,
) -> Result<CandidateExtractionBatch, ExtractionError> {
    let proposals = result
        .into_proposals()
        .into_iter()
        .map(|proposal| match proposal.action() {
            WireProposalActionV1::Propose => Ok(CandidateExtractionProposal {
                action: ProposalAction::Propose,
                kind: Some(map_memory_kind(
                    proposal
                        .kind()
                        .ok_or_else(ExtractionError::llm_possibly_sent)?,
                )),
                content: Some(
                    proposal
                        .content()
                        .ok_or_else(ExtractionError::llm_possibly_sent)?
                        .to_string(),
                ),
                summary: Some(
                    proposal
                        .summary()
                        .ok_or_else(ExtractionError::llm_possibly_sent)?
                        .to_string(),
                ),
                confidence: Some(
                    proposal
                        .confidence()
                        .ok_or_else(ExtractionError::llm_possibly_sent)?,
                ),
                importance: Some(
                    proposal
                        .importance()
                        .ok_or_else(ExtractionError::llm_possibly_sent)?,
                ),
                sensitivity_hint: map_sensitivity_hint(
                    proposal
                        .sensitivity_hint()
                        .ok_or_else(ExtractionError::llm_possibly_sent)?,
                ),
                conflict_hint: proposal
                    .conflict_hint()
                    .ok_or_else(ExtractionError::llm_possibly_sent)?,
                source_message_ids: proposal.source_message_ids().to_vec(),
            }),
            WireProposalActionV1::Ignore => Ok(CandidateExtractionProposal {
                action: ProposalAction::Ignore,
                kind: None,
                content: None,
                summary: None,
                confidence: None,
                importance: None,
                sensitivity_hint: SensitivityHint::Unknown,
                conflict_hint: false,
                source_message_ids: proposal.source_message_ids().to_vec(),
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CandidateExtractionBatch { proposals })
}

const fn map_memory_kind(kind: WireMemoryKindV1) -> MemoryKind {
    match kind {
        WireMemoryKindV1::Preference => MemoryKind::Preference,
        WireMemoryKindV1::Goal => MemoryKind::Goal,
        WireMemoryKindV1::Experience => MemoryKind::Experience,
        WireMemoryKindV1::Fact => MemoryKind::Fact,
        WireMemoryKindV1::Relationship => MemoryKind::Relationship,
        WireMemoryKindV1::Skill => MemoryKind::Skill,
        WireMemoryKindV1::Other => MemoryKind::Other,
    }
}

const fn map_sensitivity_hint(hint: WireSensitivityHintV1) -> SensitivityHint {
    match hint {
        WireSensitivityHintV1::NotSensitive => SensitivityHint::NotSensitive,
        WireSensitivityHintV1::Sensitive => SensitivityHint::Sensitive,
        WireSensitivityHintV1::Unknown => SensitivityHint::Unknown,
    }
}

fn llm_descriptor() -> ExtractorDescriptor {
    let descriptor = LlmExtractorDescriptor::v1();
    ExtractorDescriptor {
        extractor_id: descriptor.extractor_id().to_string(),
        extractor_version: descriptor.extractor_version().to_string(),
    }
}

fn existing_matches_llm(existing: &ExistingRun) -> bool {
    let descriptor = LlmExtractorDescriptor::v1();
    existing.extractor_id == descriptor.extractor_id()
        && existing.extractor_version == descriptor.extractor_version()
        && existing.policy_version == descriptor.policy_version()
}

fn read_existing_run(
    storage: &StorageService,
    life_id: &str,
    conversation_id: &str,
) -> Result<Option<ExistingRun>, SafeCommandError> {
    let state = storage.state().map_err(|_| storage_unavailable())?;
    let revision: Option<i64> = state
        .connection
        .query_row(
            "SELECT revision FROM conversation WHERE id=?1 AND life_id=?2",
            params![conversation_id, life_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| storage_unavailable())?;
    let revision = revision.ok_or_else(conversation_not_found)?;
    let now: i64 = state
        .connection
        .query_row("SELECT CAST(strftime('%s', 'now') AS INTEGER)", [], |row| {
            row.get(0)
        })
        .map_err(|_| storage_unavailable())?;
    state
        .connection
        .query_row(
            "SELECT status, created_count, evidence_merged_count,
                    hard_secret_blocked_count + sensitive_blocked_count,
                    extractor_id, extractor_version, policy_version, lease_expires_at_epoch_s
             FROM candidate_extraction_run
             WHERE life_id=?1 AND conversation_id=?2 AND conversation_revision=?3",
            params![life_id, conversation_id, revision],
            |row| {
                let status: String = row.get(0)?;
                let status = match status.as_str() {
                    "processing" => ExtractionTriggerStatus::Processing,
                    "retry_wait" => ExtractionTriggerStatus::RetryWait,
                    "completed" => ExtractionTriggerStatus::Completed,
                    "failed" => ExtractionTriggerStatus::Failed,
                    "snapshot_invalidated" => ExtractionTriggerStatus::SnapshotInvalidated,
                    _ => ExtractionTriggerStatus::StaleOrConflict,
                };
                let lease_expires_at_epoch_s: Option<i64> = row.get(7)?;
                Ok(ExistingRun {
                    status,
                    created_count: row.get(1)?,
                    merged_evidence_count: row.get(2)?,
                    blocked_count: row.get(3)?,
                    extractor_id: row.get(4)?,
                    extractor_version: row.get(5)?,
                    policy_version: row.get(6)?,
                    lease_expired: lease_expires_at_epoch_s.is_some_and(|expires| expires <= now),
                })
            },
        )
        .optional()
        .map_err(|_| storage_unavailable())
}

fn response_from_existing(existing: ExistingRun) -> ExtractionTriggerResponse {
    match existing.status {
        ExtractionTriggerStatus::Completed => ExtractionTriggerResponse {
            status: ExtractionTriggerStatus::Completed,
            created_count: Some(existing.created_count),
            merged_evidence_count: Some(existing.merged_evidence_count),
            blocked_count: Some(existing.blocked_count),
            safe_message_code: "CANDIDATE_EXTRACTION_COMPLETED",
        },
        status => simple_response(status),
    }
}

fn simple_response(status: ExtractionTriggerStatus) -> ExtractionTriggerResponse {
    let safe_message_code = match status {
        ExtractionTriggerStatus::Completed => "CANDIDATE_EXTRACTION_COMPLETED",
        ExtractionTriggerStatus::Processing => "CANDIDATE_EXTRACTION_PROCESSING",
        ExtractionTriggerStatus::RetryWait => "CANDIDATE_EXTRACTION_RETRY_WAIT",
        ExtractionTriggerStatus::Failed => "CANDIDATE_EXTRACTION_FAILED",
        ExtractionTriggerStatus::SnapshotInvalidated => "CANDIDATE_EXTRACTION_SNAPSHOT_INVALIDATED",
        ExtractionTriggerStatus::NoEligibleSnapshot => "CANDIDATE_EXTRACTION_NO_ELIGIBLE_SNAPSHOT",
        ExtractionTriggerStatus::StaleOrConflict => "CANDIDATE_EXTRACTION_STALE_OR_CONFLICT",
    };
    ExtractionTriggerResponse {
        status,
        created_count: None,
        merged_evidence_count: None,
        blocked_count: None,
        safe_message_code,
    }
}

const fn invalid_request() -> SafeCommandError {
    SafeCommandError::new(
        "CANDIDATE_EXTRACTION_INVALID_REQUEST",
        "A current life and conversation are required.",
    )
}

const fn conversation_not_found() -> SafeCommandError {
    SafeCommandError::new(
        "CANDIDATE_EXTRACTION_CONVERSATION_NOT_FOUND",
        "The current conversation was not found.",
    )
}

const fn storage_unavailable() -> SafeCommandError {
    SafeCommandError::new(
        "CANDIDATE_EXTRACTION_UNAVAILABLE",
        "Candidate memory extraction is temporarily unavailable.",
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::{
        conversation::history::{
            AppendConversationTurnRequest, ConversationRepository, CreateConversationRequest,
        },
        model::profile::{
            delete_model_profile_with_store, CreateModelProfileRequest, ModelProfileService,
            ModelProviderKind, SetActiveModelProfileRequest,
        },
        secrets::InMemorySecretStore,
        storage::{LifeIdentityRecord, PersonaTemplateRecord},
    };

    fn setup() -> (StorageService, std::path::PathBuf, String) {
        let root = std::env::temp_dir().join(format!("d8c6-s2-{}", super::super::unique_suffix()));
        let project = root.join("project");
        fs::create_dir_all(&project).unwrap();
        let storage =
            StorageService::initialize_with_roots(root.join("default"), Some(project)).unwrap();
        storage
            .save_persona(PersonaTemplateRecord {
                id: "persona-d8c6".into(),
                name: "Persona".into(),
                version: 1,
                persona_json: "{}".into(),
            })
            .unwrap();
        storage
            .save_life(LifeIdentityRecord {
                id: "life-d8c6".into(),
                name: "Life".into(),
                created_at: "2026-01-01T00:00:00.000Z".into(),
                version: 1,
                body_id: "body".into(),
                persona_id: "persona-d8c6".into(),
                persona_version: 1,
            })
            .unwrap();
        let conversation = storage
            .create_conversation(
                "conversation-d8c6",
                &CreateConversationRequest {
                    life_id: "life-d8c6".into(),
                    title: "D-8C6".into(),
                },
            )
            .unwrap();
        storage
            .append_complete_turn(&AppendConversationTurnRequest {
                life_id: "life-d8c6".into(),
                conversation_id: conversation.id.clone(),
                turn_id: "turn-d8c6".into(),
                user_content: "I like tea".into(),
                assistant_content: "Acknowledged.".into(),
                expected_revision: Some(0),
            })
            .unwrap();
        (storage, root, conversation.id)
    }

    fn activate_http_profile(storage: &StorageService) -> String {
        let profiles = ModelProfileService::new(storage);
        let profile = profiles
            .create(CreateModelProfileRequest {
                purpose: ModelPurpose::CandidateExtraction,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: "Candidate".into(),
                base_url: "http://provider.invalid/v1".into(),
                model_name: "candidate-model".into(),
                temperature: Some(0.0),
                max_tokens: Some(32),
                embedding_dimension: None,
            })
            .unwrap();
        profiles
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::CandidateExtraction,
                profile_id: profile.id.clone(),
            })
            .unwrap();
        profile.id
    }

    fn run_error_code(storage: &StorageService) -> Option<String> {
        let state = storage.state().unwrap();
        state
            .connection
            .query_row(
                "SELECT last_error_code FROM candidate_extraction_run",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[tokio::test]
    async fn no_active_mapping_uses_the_existing_deterministic_facade() {
        let (storage, root, conversation_id) = setup();
        let response = trigger_candidate_extraction(
            &storage,
            &LlmCandidateExtractionCoordinator::default(),
            &InMemorySecretStore::new(),
            "life-d8c6",
            &conversation_id,
        )
        .await
        .unwrap();
        assert_eq!(response.status, ExtractionTriggerStatus::Completed);
        assert_eq!(response.created_count, Some(1));
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn active_llm_profile_failure_is_terminal_without_deterministic_fallback() {
        let (storage, root, conversation_id) = setup();
        activate_http_profile(&storage);
        let response = trigger_candidate_extraction(
            &storage,
            &LlmCandidateExtractionCoordinator::default(),
            &InMemorySecretStore::new(),
            "life-d8c6",
            &conversation_id,
        )
        .await
        .unwrap();
        assert_eq!(response.status, ExtractionTriggerStatus::Failed);
        assert_eq!(
            run_error_code(&storage),
            Some("CANDIDATE_EXTRACTION_LLM_DEFINITELY_NOT_SENT".into())
        );
        let state = storage.state().unwrap();
        let candidates: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_memory", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(candidates, 0);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn existing_deterministic_run_wins_over_a_later_llm_mapping() {
        let (storage, root, conversation_id) = setup();
        let first =
            trigger_deterministic_candidate_extraction(&storage, "life-d8c6", &conversation_id)
                .unwrap();
        activate_http_profile(&storage);
        let replay = trigger_candidate_extraction(
            &storage,
            &LlmCandidateExtractionCoordinator::default(),
            &InMemorySecretStore::new(),
            "life-d8c6",
            &conversation_id,
        )
        .await
        .unwrap();
        assert_eq!(replay, first);
        let state = storage.state().unwrap();
        let runs: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_extraction_run", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(runs, 1);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn existing_llm_run_remains_authoritative_after_its_active_mapping_is_removed() {
        let (storage, root, conversation_id) = setup();
        let profile_id = activate_http_profile(&storage);
        let descriptor = llm_descriptor();
        storage
            .start_candidate_extraction(
                "life-d8c6",
                &conversation_id,
                descriptor,
                LlmExtractorDescriptor::v1().policy_version(),
            )
            .unwrap()
            .unwrap();
        delete_model_profile_with_store(&storage, &InMemorySecretStore::new(), &profile_id)
            .unwrap();
        assert!(ModelProfileService::new(&storage)
            .get_active(ModelPurpose::CandidateExtraction)
            .unwrap()
            .is_none());

        let response = trigger_candidate_extraction(
            &storage,
            &LlmCandidateExtractionCoordinator::default(),
            &InMemorySecretStore::new(),
            "life-d8c6",
            &conversation_id,
        )
        .await
        .unwrap();
        assert_eq!(response.status, ExtractionTriggerStatus::Processing);
        let state = storage.state().unwrap();
        let runs: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_extraction_run", [], |row| {
                row.get(0)
            })
            .unwrap();
        let candidates: i64 = state
            .connection
            .query_row("SELECT COUNT(*) FROM candidate_memory", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(runs, 1);
        assert_eq!(candidates, 0);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn existing_failed_llm_run_is_returned_without_another_attempt() {
        let (storage, root, conversation_id) = setup();
        let descriptor = llm_descriptor();
        let started = storage
            .start_candidate_extraction(
                "life-d8c6",
                &conversation_id,
                descriptor.clone(),
                LlmExtractorDescriptor::v1().policy_version(),
            )
            .unwrap()
            .unwrap();
        let terminalized = finish_attempt(
            &storage,
            "life-d8c6",
            &conversation_id,
            &ImmediateLlmFailureExtractor::definitely_not_sent(descriptor),
            &started,
        )
        .await
        .unwrap();
        assert_eq!(terminalized.status, ExtractionTriggerStatus::Failed);

        let replay = trigger_candidate_extraction(
            &storage,
            &LlmCandidateExtractionCoordinator::default(),
            &InMemorySecretStore::new(),
            "life-d8c6",
            &conversation_id,
        )
        .await
        .unwrap();
        assert_eq!(replay.status, ExtractionTriggerStatus::Failed);
        assert_eq!(
            run_error_code(&storage),
            Some("CANDIDATE_EXTRACTION_LLM_DEFINITELY_NOT_SENT".into())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn permit_timeout_is_definitely_not_sent_without_provider_execution() {
        let (storage, root, conversation_id) = setup();
        activate_http_profile(&storage);
        let coordinator = LlmCandidateExtractionCoordinator::default();
        let permits = (0..LLM_CONCURRENCY)
            .map(|_| coordinator.semaphore.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        let response = trigger_candidate_extraction_with_permit_timeout(
            &storage,
            &coordinator,
            &InMemorySecretStore::new(),
            "life-d8c6",
            &conversation_id,
            Duration::from_millis(1),
        )
        .await
        .unwrap();
        assert_eq!(response.status, ExtractionTriggerStatus::Failed);
        assert_eq!(
            run_error_code(&storage),
            Some("CANDIDATE_EXTRACTION_LLM_DEFINITELY_NOT_SENT".into())
        );
        drop(permits);
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn coordinator_limits_to_four_and_releases_waiters() {
        let coordinator = LlmCandidateExtractionCoordinator::default();
        let mut permits = (0..LLM_CONCURRENCY)
            .map(|_| coordinator.semaphore.clone().try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        assert!(coordinator
            .acquire_with_timeout(Duration::from_millis(1))
            .await
            .is_none());
        drop(permits.pop());
        assert!(coordinator
            .acquire_with_timeout(Duration::from_millis(1))
            .await
            .is_some());
    }

    #[tokio::test]
    async fn expired_llm_run_is_terminalized_as_possibly_sent_without_profile_lookup() {
        let (storage, root, conversation_id) = setup();
        let descriptor = llm_descriptor();
        let _started = storage
            .start_candidate_extraction(
                "life-d8c6",
                &conversation_id,
                descriptor,
                LlmExtractorDescriptor::v1().policy_version(),
            )
            .unwrap()
            .unwrap();
        {
            let state = storage.state().unwrap();
            state
                .connection
                .execute(
                    "UPDATE candidate_extraction_run SET lease_expires_at_epoch_s=1
                     WHERE life_id='life-d8c6' AND conversation_id=?1",
                    params![conversation_id],
                )
                .unwrap();
        }
        let response = trigger_candidate_extraction(
            &storage,
            &LlmCandidateExtractionCoordinator::default(),
            &InMemorySecretStore::new(),
            "life-d8c6",
            &conversation_id,
        )
        .await
        .unwrap();
        assert_eq!(response.status, ExtractionTriggerStatus::Failed);
        assert_eq!(
            run_error_code(&storage),
            Some("CANDIDATE_EXTRACTION_LLM_POSSIBLY_SENT".into())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn wire_enums_are_exhaustively_mapped_without_domain_fallbacks() {
        assert_eq!(
            map_memory_kind(WireMemoryKindV1::Preference),
            MemoryKind::Preference
        );
        assert_eq!(map_memory_kind(WireMemoryKindV1::Goal), MemoryKind::Goal);
        assert_eq!(
            map_memory_kind(WireMemoryKindV1::Experience),
            MemoryKind::Experience
        );
        assert_eq!(map_memory_kind(WireMemoryKindV1::Fact), MemoryKind::Fact);
        assert_eq!(
            map_memory_kind(WireMemoryKindV1::Relationship),
            MemoryKind::Relationship
        );
        assert_eq!(map_memory_kind(WireMemoryKindV1::Skill), MemoryKind::Skill);
        assert_eq!(map_memory_kind(WireMemoryKindV1::Other), MemoryKind::Other);
        assert_eq!(
            map_sensitivity_hint(WireSensitivityHintV1::NotSensitive),
            SensitivityHint::NotSensitive
        );
        assert_eq!(
            map_sensitivity_hint(WireSensitivityHintV1::Sensitive),
            SensitivityHint::Sensitive
        );
        assert_eq!(
            map_sensitivity_hint(WireSensitivityHintV1::Unknown),
            SensitivityHint::Unknown
        );
    }
}
