use std::fmt;

use super::{
    error::{LlmExtractionError, LlmExtractionErrorKind},
    wire::ExtractionWireInputV1,
};

const V1_SYSTEM_PROMPT: &str = "\
You are a memory extraction assistant. Your task is to extract user candidate memories from user messages.
Extract candidate memories representing the user's preferences, habits, goals, or experiences.
You must return ONLY a JSON object conforming to the following structure:
{
  \"proposals\": [
    {
      \"action\": \"propose\" | \"ignore\",
      \"kind\": \"preference\" | \"goal\" | \"experience\" | \"fact\" | \"relationship\" | \"skill\" | \"other\",
      \"content\": \"string\",
      \"summary\": \"string\",
      \"confidence\": number between 0.0 and 1.0,
      \"importance\": number between 0.0 and 1.0,
      \"sensitivity_hint\": \"not_sensitive\" | \"sensitive\" | \"unknown\",
      \"conflict_hint\": boolean,
      \"source_message_ids\": [\"string\"]
    }
  ]
}
For \"propose\", every listed field except \"action\" is required and non-null.
For \"ignore\", provide only \"action\" and non-empty \"source_message_ids\".
Do NOT include markdown formatting or ```json fences. Return ONLY the raw JSON object. Maximum 5 proposals.";

/// Version-bound extractor descriptor.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LlmExtractorDescriptor {
    extractor_id: &'static str,
    extractor_version: &'static str,
    policy_version: &'static str,
    system_prompt: &'static str,
}

impl LlmExtractorDescriptor {
    /// Factory for descriptor version v1.
    pub(crate) const fn v1() -> Self {
        Self {
            extractor_id: "llm-candidate-extractor",
            extractor_version: "v1",
            policy_version: "candidate-extraction-v1",
            system_prompt: V1_SYSTEM_PROMPT,
        }
    }

    pub(crate) const fn extractor_id(&self) -> &'static str {
        self.extractor_id
    }

    pub(crate) const fn extractor_version(&self) -> &'static str {
        self.extractor_version
    }

    pub(crate) const fn policy_version(&self) -> &'static str {
        self.policy_version
    }

    pub(super) const fn system_prompt(&self) -> &'static str {
        self.system_prompt
    }

    /// The input is already bounded by its sealed constructor. Keep this
    /// check at the descriptor boundary so malformed internal values fail
    /// before request construction or any provider interaction.
    pub(super) fn validate_input(
        &self,
        input: &ExtractionWireInputV1,
    ) -> Result<(), LlmExtractionError> {
        if input.message_count() == 0 {
            return Err(LlmExtractionError::definitely_not_sent(
                LlmExtractionErrorKind::ExtractionInputInvalid,
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for LlmExtractorDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LlmExtractorDescriptor")
            .field("extractor_id", &self.extractor_id)
            .field("extractor_version", &self.extractor_version)
            .field("policy_version", &self.policy_version)
            .finish()
    }
}
