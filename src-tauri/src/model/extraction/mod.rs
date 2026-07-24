#![allow(dead_code)]

pub(crate) mod decoder;
pub(crate) mod descriptor;
pub(crate) mod error;
pub(crate) mod protocol;

use std::fmt;

use crate::{
    model::{
        profile::ModelProfile,
        provider::{OpenAiCompatibleProvider, OpenAiCompatibleProviderConfig},
    },
    secrets::SecretStore,
    storage::candidate_extraction::{CandidateExtractionBatch, CandidateExtractionRequest},
};

pub(crate) use descriptor::LlmExtractorDescriptor;
#[allow(unused_imports)]
pub(crate) use error::{LlmExtractionError, LlmExtractionErrorKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LlmExtractionStats {
    pub input_message_count: usize,
    pub input_total_bytes: usize,
    pub proposal_count: usize,
}

#[derive(Clone)]
pub(crate) struct LlmExtractionResult {
    pub descriptor_extractor_id: &'static str,
    pub descriptor_extractor_version: &'static str,
    pub policy_version: &'static str,
    pub batch: CandidateExtractionBatch,
    pub stats: LlmExtractionStats,
}

impl fmt::Debug for LlmExtractionResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LlmExtractionResult")
            .field("descriptor_extractor_id", &self.descriptor_extractor_id)
            .field(
                "descriptor_extractor_version",
                &self.descriptor_extractor_version,
            )
            .field("policy_version", &self.policy_version)
            .field("stats", &self.stats)
            .finish()
    }
}

pub(crate) async fn execute_llm_extraction<S: SecretStore + ?Sized>(
    descriptor: &LlmExtractorDescriptor,
    request: &CandidateExtractionRequest,
    profile: &ModelProfile,
    secrets: &S,
) -> Result<LlmExtractionResult, LlmExtractionError> {
    descriptor.validate_request(request)?;

    let input_total_bytes = request
        .messages
        .iter()
        .map(|m| m.content.len())
        .fold(0usize, |a, b| a.saturating_add(b));

    let provider_request = protocol::build_provider_request(descriptor, request, profile)?;
    let provider_config = OpenAiCompatibleProviderConfig::from_profile(profile)
        .map_err(LlmExtractionError::from_provider_error)?;

    let provider = OpenAiCompatibleProvider::new(secrets);
    let response = provider
        .execute(&provider_config, provider_request)
        .await
        .map_err(LlmExtractionError::from_provider_error)?;

    let batch = decoder::decode_response_envelope(response.body())?;

    let stats = LlmExtractionStats {
        input_message_count: request.messages.len(),
        input_total_bytes,
        proposal_count: batch.proposals.len(),
    };

    Ok(LlmExtractionResult {
        descriptor_extractor_id: descriptor.extractor_id(),
        descriptor_extractor_version: descriptor.extractor_version(),
        policy_version: descriptor.policy_version(),
        batch,
        stats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::{
            profile::{ModelProfile, ModelProviderKind, ModelPurpose},
            transport::http1::SendDisposition,
        },
        secrets::InMemorySecretStore,
        storage::candidate_extraction::{ExtractionMessage, ProposalAction},
    };

    fn make_test_profile(base_url: &str) -> ModelProfile {
        ModelProfile {
            id: "profile-extract-1".into(),
            purpose: ModelPurpose::CandidateExtraction,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "Extraction Test Profile".into(),
            base_url: base_url.into(),
            model_name: "gpt-4o-mini".into(),
            temperature: Some(0.0),
            max_tokens: Some(2048),
            embedding_dimension: None,
            created_at: "2026-07-24T10:00:00Z".into(),
            updated_at: "2026-07-24T10:00:00Z".into(),
        }
    }

    fn make_test_request(
        policy_version: &str,
        messages: Vec<ExtractionMessage>,
    ) -> CandidateExtractionRequest {
        CandidateExtractionRequest {
            run_id: "run-1".into(),
            attempt_sequence: 1,
            life_id: "life-1".into(),
            conversation_id: "conv-1".into(),
            conversation_revision: 1,
            policy_version: policy_version.into(),
            snapshot_hash: "hash-1".into(),
            messages,
        }
    }

    #[test]
    fn descriptor_version_mismatch_fails_definitely_not_sent() {
        let descriptor = LlmExtractorDescriptor::v1();
        let req = make_test_request(
            "wrong-policy",
            vec![ExtractionMessage {
                message_id: "msg-1".into(),
                sequence_no: 1,
                content: "I love coding in Rust.".into(),
            }],
        );

        let err = descriptor.validate_request(&req).unwrap_err();
        assert_eq!(
            err.kind(),
            LlmExtractionErrorKind::DescriptorVersionMismatch
        );
        assert_eq!(err.disposition(), SendDisposition::DefinitelyNotSent);
    }

    #[test]
    fn empty_messages_fails_definitely_not_sent() {
        let descriptor = LlmExtractorDescriptor::v1();
        let req = make_test_request("candidate-extraction-v1", vec![]);

        let err = descriptor.validate_request(&req).unwrap_err();
        assert_eq!(err.kind(), LlmExtractionErrorKind::ExtractionInputInvalid);
        assert_eq!(err.disposition(), SendDisposition::DefinitelyNotSent);
    }

    #[test]
    fn request_building_verifies_non_streaming_and_no_tools() {
        let descriptor = LlmExtractorDescriptor::v1();
        let profile = make_test_profile("https://api.openai.com/v1");
        let req = make_test_request(
            "candidate-extraction-v1",
            vec![ExtractionMessage {
                message_id: "msg-1".into(),
                sequence_no: 1,
                content: "CANARY_USER_TEXT: I prefer dark mode.".into(),
            }],
        );

        let provider_req = protocol::build_provider_request(&descriptor, &req, &profile).unwrap();
        let debug_str = format!("{provider_req:?}");
        assert!(!debug_str.contains("CANARY_USER_TEXT"));
        assert!(!debug_str.contains("V1_SYSTEM_PROMPT"));
    }

    #[test]
    fn envelope_decoding_valid_single_choice_succeeds() {
        let response_body = br#"{
            "id": "chatcmpl-123",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "{\"proposals\":[{\"action\":\"propose\",\"kind\":\"preference\",\"content\":\"User prefers dark mode\",\"confidence\":0.9,\"importance\":0.8,\"sensitivity_hint\":\"not_sensitive\",\"conflict_hint\":false,\"source_message_ids\":[\"msg-1\"]}]}"
                    }
                }
            ]
        }"#;

        let batch = decoder::decode_response_envelope(response_body).unwrap();
        assert_eq!(batch.proposals.len(), 1);
        assert_eq!(batch.proposals[0].action, ProposalAction::Propose);
        assert_eq!(
            batch.proposals[0].content.as_deref(),
            Some("User prefers dark mode")
        );
    }

    #[test]
    fn envelope_decoding_multiple_choices_rejected_possibly_sent() {
        let response_body = br#"{
            "choices": [
                {"message": {"role": "assistant", "content": "{\"proposals\":[]}"}},
                {"message": {"role": "assistant", "content": "{\"proposals\":[]}"}}
            ]
        }"#;

        let err = decoder::decode_response_envelope(response_body).unwrap_err();
        assert_eq!(err.kind(), LlmExtractionErrorKind::ProviderEnvelopeInvalid);
        assert_eq!(err.disposition(), SendDisposition::PossiblySent);
    }

    #[test]
    fn envelope_decoding_markdown_fence_rejected_possibly_sent() {
        let response_body = br#"{
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "```json\n{\"proposals\":[]}\n```"
                    }
                }
            ]
        }"#;

        let err = decoder::decode_response_envelope(response_body).unwrap_err();
        assert_eq!(err.kind(), LlmExtractionErrorKind::ExtractionJsonInvalid);
        assert_eq!(err.disposition(), SendDisposition::PossiblySent);
    }

    #[test]
    fn envelope_decoding_tool_calls_rejected_possibly_sent() {
        let response_body = br#"{
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "{\"proposals\":[]}",
                        "tool_calls": [{"id": "call_1"}]
                    }
                }
            ]
        }"#;

        let err = decoder::decode_response_envelope(response_body).unwrap_err();
        assert_eq!(
            err.kind(),
            LlmExtractionErrorKind::ProviderContentUnsupported
        );
        assert_eq!(err.disposition(), SendDisposition::PossiblySent);
    }

    #[test]
    fn schema_decoding_unknown_fields_rejected_possibly_sent() {
        let response_body = br#"{
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "{\"proposals\":[{\"action\":\"propose\",\"unknown_field\":\"invalid\"}]}"
                    }
                }
            ]
        }"#;

        let err = decoder::decode_response_envelope(response_body).unwrap_err();
        assert_eq!(err.kind(), LlmExtractionErrorKind::ExtractionSchemaInvalid);
        assert_eq!(err.disposition(), SendDisposition::PossiblySent);
    }

    #[test]
    fn schema_decoding_server_identity_fields_rejected_possibly_sent() {
        let response_body = br#"{
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "{\"proposals\":[{\"action\":\"propose\",\"id\":\"db-id-injected\",\"revision\":10}]}"
                    }
                }
            ]
        }"#;

        let err = decoder::decode_response_envelope(response_body).unwrap_err();
        assert_eq!(err.kind(), LlmExtractionErrorKind::ExtractionSchemaInvalid);
        assert_eq!(err.disposition(), SendDisposition::PossiblySent);
    }

    #[test]
    fn candidate_limit_exceeded_rejected_possibly_sent() {
        let response_body = br#"{
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "{\"proposals\":[{\"action\":\"ignore\"},{\"action\":\"ignore\"},{\"action\":\"ignore\"},{\"action\":\"ignore\"},{\"action\":\"ignore\"},{\"action\":\"ignore\"}]}"
                    }
                }
            ]
        }"#;

        let err = decoder::decode_response_envelope(response_body).unwrap_err();
        assert_eq!(
            err.kind(),
            LlmExtractionErrorKind::ExtractionCandidateLimitExceeded
        );
        assert_eq!(err.disposition(), SendDisposition::PossiblySent);
    }

    #[test]
    fn error_and_result_debug_does_not_leak_canary() {
        let canary = "CANARY_SECRET_DATA_123";
        let err =
            LlmExtractionError::definitely_not_sent(LlmExtractionErrorKind::ExtractionInputInvalid);
        let debug_err = format!("{err:?} {err}");
        assert!(!debug_err.contains(canary));

        let res = LlmExtractionResult {
            descriptor_extractor_id: "id",
            descriptor_extractor_version: "v1",
            policy_version: "pol",
            batch: CandidateExtractionBatch::default(),
            stats: LlmExtractionStats {
                input_message_count: 1,
                input_total_bytes: 10,
                proposal_count: 0,
            },
        };
        let debug_res = format!("{res:?}");
        assert!(!debug_res.contains(canary));
    }

    #[tokio::test]
    async fn execute_llm_extraction_http_base_url_rejected_definitely_not_sent() {
        let profile = make_test_profile("http://api.openai.com/v1");
        let secrets = InMemorySecretStore::new();
        let descriptor = LlmExtractorDescriptor::v1();
        let req = make_test_request(
            "candidate-extraction-v1",
            vec![ExtractionMessage {
                message_id: "msg-1".into(),
                sequence_no: 1,
                content: "I like coding.".into(),
            }],
        );

        let err = execute_llm_extraction(&descriptor, &req, &profile, &secrets)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), LlmExtractionErrorKind::ProviderFailure);
        assert_eq!(err.disposition(), SendDisposition::DefinitelyNotSent);
    }

    #[tokio::test]
    async fn execute_llm_extraction_no_credential_fails_definitely_not_sent() {
        let profile = make_test_profile("https://api.openai.com/v1");
        let secrets = InMemorySecretStore::new();
        let descriptor = LlmExtractorDescriptor::v1();
        let req = make_test_request(
            "candidate-extraction-v1",
            vec![ExtractionMessage {
                message_id: "msg-1".into(),
                sequence_no: 1,
                content: "I like coding.".into(),
            }],
        );

        let err = execute_llm_extraction(&descriptor, &req, &profile, &secrets)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), LlmExtractionErrorKind::ProviderFailure);
        assert_eq!(err.disposition(), SendDisposition::DefinitelyNotSent);
    }
}
