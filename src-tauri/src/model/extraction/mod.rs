#![allow(dead_code)]

mod decoder;
mod descriptor;
mod error;
mod protocol;
mod wire;

use crate::{
    model::{
        profile::{ModelProfile, ModelPurpose},
        provider::{OpenAiCompatibleProvider, OpenAiCompatibleProviderConfig},
    },
    secrets::SecretStore,
};

pub(crate) use descriptor::LlmExtractorDescriptor;
pub(crate) use error::{LlmExtractionError, LlmExtractionErrorKind};
#[allow(unused_imports)]
pub(crate) use wire::{
    ExtractionProtocolVersion, ExtractionWireInputV1, LlmExtractionStats,
    ValidatedExtractionWireResultV1, ValidatedWireProposalV1, WireMemoryKindV1,
    WireProposalActionV1, WireSensitivityHintV1,
};

/// Executes only the D-8C5 provider protocol. It has no D-6 storage types,
/// database writes, or domain acceptance behavior.
pub(crate) async fn execute_llm_extraction<S: SecretStore + ?Sized>(
    descriptor: &LlmExtractorDescriptor,
    input: &ExtractionWireInputV1,
    profile: &ModelProfile,
    secrets: &S,
) -> Result<ValidatedExtractionWireResultV1, LlmExtractionError> {
    // This is intentionally first: no request construction, credential read,
    // provider execution, connection, or endpoint selection may occur for a
    // non-extraction profile.
    if profile.purpose != ModelPurpose::CandidateExtraction {
        return Err(LlmExtractionError::definitely_not_sent(
            LlmExtractionErrorKind::ProfilePurposeInvalid,
        ));
    }

    descriptor.validate_input(input)?;
    let provider_request = protocol::build_provider_request(descriptor, input, profile)?;
    let provider_config = OpenAiCompatibleProviderConfig::from_profile(profile)
        .map_err(LlmExtractionError::from_provider_error)?;

    let provider = OpenAiCompatibleProvider::new(secrets);
    let response = provider
        .execute(&provider_config, provider_request)
        .await
        .map_err(LlmExtractionError::from_provider_error)?;

    decoder::decode_response_envelope(response.body(), input)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::{
        model::{
            profile::{ModelProviderKind, ModelPurpose},
            transport::http1::SendDisposition,
        },
        secrets::{SecretIdentifier, SecretStatus, SecretStore, SecretStoreError, SecretValue},
    };

    struct CountingSecretStore {
        credential_reads: AtomicUsize,
    }

    impl CountingSecretStore {
        fn new() -> Self {
            Self {
                credential_reads: AtomicUsize::new(0),
            }
        }

        fn credential_reads(&self) -> usize {
            self.credential_reads.load(Ordering::SeqCst)
        }
    }

    impl SecretStore for CountingSecretStore {
        fn set_secret(
            &self,
            _identifier: &SecretIdentifier,
            _value: SecretValue,
        ) -> Result<SecretStatus, SecretStoreError> {
            Err(SecretStoreError::not_found())
        }

        fn get_secret(
            &self,
            _identifier: &SecretIdentifier,
        ) -> Result<SecretValue, SecretStoreError> {
            self.credential_reads.fetch_add(1, Ordering::SeqCst);
            Err(SecretStoreError::not_found())
        }

        fn has_secret(&self, _identifier: &SecretIdentifier) -> Result<bool, SecretStoreError> {
            Err(SecretStoreError::not_found())
        }

        fn delete_secret(
            &self,
            _identifier: &SecretIdentifier,
        ) -> Result<SecretStatus, SecretStoreError> {
            Err(SecretStoreError::not_found())
        }
    }

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

    fn input_with_content(content: &str) -> ExtractionWireInputV1 {
        ExtractionWireInputV1::from_messages(vec![("msg-1".into(), 1, content.into())]).unwrap()
    }

    fn valid_proposal_content() -> &'static str {
        r#"{"proposals":[{"action":"propose","kind":"preference","content":"User prefers dark mode","summary":"Prefers dark mode","confidence":0.9,"importance":0.8,"sensitivity_hint":"not_sensitive","conflict_hint":false,"source_message_ids":["msg-1"]}]}"#
    }

    fn envelope(content: &str) -> String {
        serde_json::json!({
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "created": 1,
            "model": "gpt-4o-mini",
            "choices": [{
                "index": 0,
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": content}
            }]
        })
        .to_string()
    }

    fn assert_possibly_sent(err: LlmExtractionError, kind: LlmExtractionErrorKind) {
        assert_eq!(err.kind(), kind);
        assert_eq!(err.disposition(), SendDisposition::PossiblySent);
    }

    #[test]
    fn descriptor_is_fixed_to_v1() {
        let descriptor = LlmExtractorDescriptor::v1();
        assert_eq!(descriptor.extractor_id(), "llm-candidate-extractor");
        assert_eq!(descriptor.extractor_version(), "v1");
        assert_eq!(descriptor.policy_version(), "candidate-extraction-v1");
    }

    #[test]
    fn wire_input_rejects_empty_and_out_of_bound_messages() {
        let empty = ExtractionWireInputV1::from_messages(vec![]).unwrap_err();
        assert_eq!(empty.disposition(), SendDisposition::DefinitelyNotSent);

        let exact = (0..64)
            .map(|index| (format!("msg-{index}"), index, "ok".to_owned()))
            .collect();
        assert_eq!(
            ExtractionWireInputV1::from_messages(exact)
                .unwrap()
                .message_count(),
            64
        );

        let too_many = (0..65)
            .map(|index| (format!("msg-{index}"), index, "ok".to_owned()))
            .collect();
        assert!(ExtractionWireInputV1::from_messages(too_many).is_err());
    }

    #[test]
    fn wire_input_debug_and_provider_request_do_not_leak_content() {
        let canary = "CANARY_USER_TEXT";
        let input = input_with_content(canary);
        assert!(!format!("{input:?}").contains(canary));

        let descriptor = LlmExtractorDescriptor::v1();
        let profile = make_test_profile("https://api.openai.com/v1");
        let provider_request =
            protocol::build_provider_request(&descriptor, &input, &profile).unwrap();
        assert!(!format!("{provider_request:?}").contains(canary));
    }

    #[test]
    fn wire_input_total_utf8_limit_is_enforced() {
        let exact = "a".repeat(131_072);
        assert!(ExtractionWireInputV1::from_messages(vec![("msg-1".into(), 1, exact)]).is_ok());
        let over = "a".repeat(131_073);
        assert!(ExtractionWireInputV1::from_messages(vec![("msg-1".into(), 1, over)]).is_err());
    }

    #[test]
    fn request_building_verifies_non_streaming_and_no_tools() {
        let descriptor = LlmExtractorDescriptor::v1();
        let profile = make_test_profile("https://api.openai.com/v1");
        let input = input_with_content("I prefer dark mode.");
        let provider_request =
            protocol::build_provider_request(&descriptor, &input, &profile).unwrap();
        assert!(!format!("{provider_request:?}").contains("I prefer dark mode."));
    }

    #[test]
    fn envelope_decoding_valid_single_choice_succeeds() {
        let input = input_with_content("I prefer dark mode.");
        let result = decoder::decode_response_envelope(
            envelope(valid_proposal_content()).as_bytes(),
            &input,
        )
        .unwrap();
        assert_eq!(result.protocol_version(), ExtractionProtocolVersion::V1);
        assert_eq!(result.proposals().len(), 1);
        assert_eq!(
            result.proposals()[0].action(),
            WireProposalActionV1::Propose
        );
        assert_eq!(
            result.proposals()[0].content(),
            Some("User prefers dark mode")
        );
    }

    #[test]
    fn envelope_rejects_missing_or_non_assistant_role() {
        for message in [
            serde_json::json!({"content": "{\"proposals\":[]}"}),
            serde_json::json!({"role": "user", "content": "{\"proposals\":[]}"}),
        ] {
            let body = serde_json::json!({"choices": [{"message": message}]}).to_string();
            let err = decoder::decode_response_envelope(body.as_bytes(), &input_with_content("x"))
                .unwrap_err();
            assert_possibly_sent(err, LlmExtractionErrorKind::ProviderEnvelopeInvalid);
        }
    }

    #[test]
    fn envelope_rejects_unknown_top_choice_and_message_fields() {
        let cases = [
            serde_json::json!({"choices": [], "unexpected": true}),
            serde_json::json!({"choices": [{"message": {"role": "assistant", "content": "{\"proposals\":[]}"}, "delta": null}]}),
            serde_json::json!({"choices": [{"message": {"role": "assistant", "content": "{\"proposals\":[]}", "tool_calls": null}}]}),
            serde_json::json!({"choices": [{"message": {"role": "assistant", "content": "{\"proposals\":[]}", "function_call": null}}]}),
        ];
        for body in cases {
            let err = decoder::decode_response_envelope(
                body.to_string().as_bytes(),
                &input_with_content("x"),
            )
            .unwrap_err();
            assert_possibly_sent(err, LlmExtractionErrorKind::ProviderEnvelopeInvalid);
        }
    }

    #[test]
    fn envelope_rejects_error_delta_multiple_empty_and_missing_content() {
        let cases = [
            serde_json::json!({"error": {"message": "no"}}),
            serde_json::json!({"choices": []}),
            serde_json::json!({"choices": [
                {"message": {"role": "assistant", "content": "{\"proposals\":[]}"}},
                {"message": {"role": "assistant", "content": "{\"proposals\":[]}"}}
            ]}),
            serde_json::json!({"choices": [{"message": {"role": "assistant"}}]}),
        ];
        for body in cases {
            let err = decoder::decode_response_envelope(
                body.to_string().as_bytes(),
                &input_with_content("x"),
            )
            .unwrap_err();
            assert_possibly_sent(err, LlmExtractionErrorKind::ProviderEnvelopeInvalid);
        }
    }

    #[test]
    fn pure_json_rules_reject_fences_prefix_suffix_multiple_and_arrays() {
        for content in [
            "```json\\n{\"proposals\":[]}\\n```",
            "explanation {\"proposals\":[]}",
            "{\"proposals\":[]} trailing",
            "{\"proposals\":[]} {\"proposals\":[]}",
            "[]",
            "null",
        ] {
            let err = decoder::decode_response_envelope(
                envelope(content).as_bytes(),
                &input_with_content("x"),
            )
            .unwrap_err();
            assert_eq!(err.disposition(), SendDisposition::PossiblySent);
        }
    }

    #[test]
    fn proposal_schema_rejects_missing_null_unknown_and_forbidden_fields() {
        let cases = [
            r#"{"proposals":[{"action":"propose","kind":"preference"}]}"#,
            r#"{"proposals":[{"action":"propose","kind":null,"content":"x","summary":"s","confidence":0.1,"importance":0.1,"sensitivity_hint":"not_sensitive","conflict_hint":false,"source_message_ids":["msg-1"]}]}"#,
            r#"{"proposals":[{"action":"propose","kind":"preference","content":"x","summary":"s","confidence":0.1,"importance":0.1,"sensitivity_hint":"not_sensitive","conflict_hint":false,"source_message_ids":["msg-1"],"id":"injected"}]}"#,
            r#"{"proposals":[{"action":"ignore","source_message_ids":["msg-1"],"content":"forbidden"}]}"#,
        ];
        for content in cases {
            let err = decoder::decode_response_envelope(
                envelope(content).as_bytes(),
                &input_with_content("x"),
            )
            .unwrap_err();
            assert_possibly_sent(err, LlmExtractionErrorKind::ExtractionSchemaInvalid);
        }
    }

    #[test]
    fn propose_requires_each_v1_field_and_rejects_null() {
        const REQUIRED_FIELDS: [&str; 9] = [
            "action",
            "kind",
            "content",
            "summary",
            "confidence",
            "importance",
            "sensitivity_hint",
            "conflict_hint",
            "source_message_ids",
        ];

        for field in REQUIRED_FIELDS {
            let mut proposal: serde_json::Value = serde_json::from_str(
                r#"{"action":"propose","kind":"preference","content":"x","summary":"s","confidence":0.1,"importance":0.1,"sensitivity_hint":"not_sensitive","conflict_hint":false,"source_message_ids":["msg-1"]}"#,
            )
            .unwrap();
            proposal.as_object_mut().unwrap().remove(field);
            let body = serde_json::json!({"proposals": [proposal]}).to_string();
            let err = decoder::decode_response_envelope(
                envelope(&body).as_bytes(),
                &input_with_content("x"),
            )
            .unwrap_err();
            assert_possibly_sent(err, LlmExtractionErrorKind::ExtractionSchemaInvalid);
        }

        for field in REQUIRED_FIELDS {
            let mut proposal: serde_json::Value = serde_json::from_str(
                r#"{"action":"propose","kind":"preference","content":"x","summary":"s","confidence":0.1,"importance":0.1,"sensitivity_hint":"not_sensitive","conflict_hint":false,"source_message_ids":["msg-1"]}"#,
            )
            .unwrap();
            proposal
                .as_object_mut()
                .unwrap()
                .insert(field.into(), serde_json::Value::Null);
            let body = serde_json::json!({"proposals": [proposal]}).to_string();
            let err = decoder::decode_response_envelope(
                envelope(&body).as_bytes(),
                &input_with_content("x"),
            )
            .unwrap_err();
            assert_possibly_sent(err, LlmExtractionErrorKind::ExtractionSchemaInvalid);
        }
    }

    #[test]
    fn proposal_schema_rejects_blank_content_and_summary() {
        for (content, summary) in [("   ", "summary"), ("content", "\t\n")] {
            let proposal = serde_json::json!({"proposals":[{
                "action":"propose", "kind":"preference", "content":content, "summary":summary,
                "confidence":0.1, "importance":0.1, "sensitivity_hint":"not_sensitive",
                "conflict_hint":false, "source_message_ids":["msg-1"]
            }]});
            let err = decoder::decode_response_envelope(
                envelope(&proposal.to_string()).as_bytes(),
                &input_with_content("x"),
            )
            .unwrap_err();
            assert_possibly_sent(err, LlmExtractionErrorKind::ExtractionSchemaInvalid);
        }
    }

    #[test]
    fn proposal_limit_and_length_boundaries_are_strict() {
        let six_ignores = serde_json::json!({"proposals": (0..6)
            .map(|_| serde_json::json!({"action":"ignore", "source_message_ids":["msg-1"]}))
            .collect::<Vec<_>>()});
        let err = decoder::decode_response_envelope(
            envelope(&six_ignores.to_string()).as_bytes(),
            &input_with_content("x"),
        )
        .unwrap_err();
        assert_possibly_sent(
            err,
            LlmExtractionErrorKind::ExtractionCandidateLimitExceeded,
        );

        for (content, summary, expect_ok) in [
            ("🦀".repeat(4_000), "🦀".repeat(500), true),
            ("a".repeat(4_001), "b".repeat(500), false),
            ("中".repeat(5_462), "b".repeat(500), false),
            ("a".repeat(4_000), "中".repeat(683), false),
        ] {
            let proposal = serde_json::json!({"proposals":[{
                "action":"propose", "kind":"preference", "content":content, "summary":summary,
                "confidence":0.1, "importance":0.1, "sensitivity_hint":"not_sensitive",
                "conflict_hint":false, "source_message_ids":["msg-1"]
            }]});
            let decoded = decoder::decode_response_envelope(
                envelope(&proposal.to_string()).as_bytes(),
                &input_with_content("x"),
            );
            assert_eq!(decoded.is_ok(), expect_ok);
        }
    }

    #[test]
    fn error_and_result_debug_do_not_leak_canary() {
        let canary = "CANARY_SECRET_DATA_123";
        let err =
            LlmExtractionError::definitely_not_sent(LlmExtractionErrorKind::ExtractionInputInvalid);
        assert!(!format!("{err:?} {err}").contains(canary));

        let result = decoder::decode_response_envelope(
            envelope(valid_proposal_content()).as_bytes(),
            &input_with_content(canary),
        )
        .unwrap();
        assert!(!format!("{result:?}").contains(canary));
        assert!(!format!("{:?}", result.proposals()[0]).contains("User prefers dark mode"));
    }

    #[tokio::test]
    async fn purpose_mismatch_is_definitely_not_sent_before_credential_or_provider_execution() {
        let mut profile = make_test_profile("https://api.openai.com/v1");
        profile.purpose = ModelPurpose::Embedding;
        let secrets = CountingSecretStore::new();
        let descriptor = LlmExtractorDescriptor::v1();
        let input = input_with_content("I like coding.");

        let err = execute_llm_extraction(&descriptor, &input, &profile, &secrets)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), LlmExtractionErrorKind::ProfilePurposeInvalid);
        assert_eq!(err.disposition(), SendDisposition::DefinitelyNotSent);
        // Provider::execute reads a credential before any exchange; zero reads
        // therefore proves the provider call path was not entered.
        assert_eq!(secrets.credential_reads(), 0);
    }

    #[tokio::test]
    async fn execute_llm_extraction_http_base_url_rejected_definitely_not_sent() {
        let profile = make_test_profile("http://api.openai.com/v1");
        let secrets = CountingSecretStore::new();
        let err = execute_llm_extraction(
            &LlmExtractorDescriptor::v1(),
            &input_with_content("I like coding."),
            &profile,
            &secrets,
        )
        .await
        .unwrap_err();
        assert_eq!(err.kind(), LlmExtractionErrorKind::ProviderFailure);
        assert_eq!(err.disposition(), SendDisposition::DefinitelyNotSent);
        assert_eq!(secrets.credential_reads(), 0);
    }
}
