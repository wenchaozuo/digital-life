use std::fmt;

use crate::storage::candidate_extraction::CandidateExtractionRequest;

use super::error::{LlmExtractionError, LlmExtractionErrorKind};

const MAX_SELECTED_USER_MESSAGES: usize = 64;
const MAX_SELECTED_UTF8_BYTES: usize = 131_072;

const V1_SYSTEM_PROMPT: &str = "\
You are a memory extraction assistant. Your task is to extract user candidate memories from user messages.
Extract candidate memories representing the user's preferences, habits, goals, or experiences.
You must return ONLY a JSON object conforming to the following structure:
{
  \"proposals\": [
    {
      \"action\": \"propose\" | \"ignore\",
      \"kind\": \"preference\" | \"goal\" | \"experience\" | \"profile\",
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

    pub(crate) const fn system_prompt(&self) -> &'static str {
        self.system_prompt
    }

    /// Validate the descriptor against an extraction request before construction/sending.
    pub(crate) fn validate_request(
        &self,
        request: &CandidateExtractionRequest,
    ) -> Result<(), LlmExtractionError> {
        if request.policy_version.trim() != self.policy_version {
            return Err(LlmExtractionError::definitely_not_sent(
                LlmExtractionErrorKind::DescriptorVersionMismatch,
            ));
        }

        if request.messages.is_empty() || request.messages.len() > MAX_SELECTED_USER_MESSAGES {
            return Err(LlmExtractionError::definitely_not_sent(
                LlmExtractionErrorKind::ExtractionInputInvalid,
            ));
        }

        let mut total_bytes: usize = 0;
        for msg in &request.messages {
            if msg.content.trim().is_empty() {
                return Err(LlmExtractionError::definitely_not_sent(
                    LlmExtractionErrorKind::ExtractionInputInvalid,
                ));
            }
            total_bytes = total_bytes.saturating_add(msg.content.len());
        }

        if total_bytes > MAX_SELECTED_UTF8_BYTES {
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
