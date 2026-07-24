use serde::Deserialize;

use crate::{
    memory::MemoryKind,
    storage::candidate_extraction::{
        CandidateExtractionBatch, CandidateExtractionProposal, ProposalAction, SensitivityHint,
        MAX_PROPOSALS, MAX_PROPOSAL_CONTENT_SCALARS, MAX_PROPOSAL_CONTENT_UTF8_BYTES,
        MAX_PROPOSAL_SUMMARY_SCALARS, MAX_PROPOSAL_SUMMARY_UTF8_BYTES,
    },
};

use super::error::{LlmExtractionError, LlmExtractionErrorKind};

#[derive(Deserialize)]
struct OpenAiChoiceMessageDto {
    role: Option<String>,
    content: Option<String>,
    tool_calls: Option<serde_json::Value>,
    function_call: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct OpenAiChoiceDto {
    message: Option<OpenAiChoiceMessageDto>,
    delta: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct OpenAiEnvelopeDto {
    error: Option<serde_json::Value>,
    choices: Option<Vec<OpenAiChoiceDto>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LlmBatchDto {
    proposals: Vec<LlmProposalDto>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LlmProposalDto {
    action: LlmActionDto,
    kind: Option<LlmMemoryKindDto>,
    content: Option<String>,
    summary: Option<String>,
    confidence: Option<f64>,
    importance: Option<f64>,
    sensitivity_hint: Option<LlmSensitivityDto>,
    conflict_hint: Option<bool>,
    source_message_ids: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum LlmActionDto {
    Propose,
    Ignore,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum LlmMemoryKindDto {
    Preference,
    Goal,
    Experience,
    Fact,
    Relationship,
    Skill,
    Other,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum LlmSensitivityDto {
    NotSensitive,
    Sensitive,
    Unknown,
}

pub(crate) fn decode_response_envelope(
    body: &[u8],
) -> Result<CandidateExtractionBatch, LlmExtractionError> {
    if body.is_empty() {
        return Err(LlmExtractionError::possibly_sent(
            LlmExtractionErrorKind::ProviderContentMissing,
        ));
    }

    let envelope: OpenAiEnvelopeDto = serde_json::from_slice(body).map_err(|_| {
        LlmExtractionError::possibly_sent(LlmExtractionErrorKind::ProviderEnvelopeInvalid)
    })?;

    if envelope.error.is_some() {
        return Err(LlmExtractionError::possibly_sent(
            LlmExtractionErrorKind::ProviderEnvelopeInvalid,
        ));
    }

    let choices = envelope.choices.ok_or_else(|| {
        LlmExtractionError::possibly_sent(LlmExtractionErrorKind::ProviderContentMissing)
    })?;

    if choices.is_empty() {
        return Err(LlmExtractionError::possibly_sent(
            LlmExtractionErrorKind::ProviderContentMissing,
        ));
    }

    if choices.len() > 1 {
        return Err(LlmExtractionError::possibly_sent(
            LlmExtractionErrorKind::ProviderEnvelopeInvalid,
        ));
    }

    let choice = &choices[0];
    if choice.delta.is_some() {
        return Err(LlmExtractionError::possibly_sent(
            LlmExtractionErrorKind::ProviderEnvelopeInvalid,
        ));
    }

    let message = choice.message.as_ref().ok_or_else(|| {
        LlmExtractionError::possibly_sent(LlmExtractionErrorKind::ProviderContentMissing)
    })?;

    if let Some(ref role) = message.role {
        if role != "assistant" {
            return Err(LlmExtractionError::possibly_sent(
                LlmExtractionErrorKind::ProviderEnvelopeInvalid,
            ));
        }
    }

    if message.tool_calls.is_some() || message.function_call.is_some() {
        return Err(LlmExtractionError::possibly_sent(
            LlmExtractionErrorKind::ProviderContentUnsupported,
        ));
    }

    let raw_content = message.content.as_deref().ok_or_else(|| {
        LlmExtractionError::possibly_sent(LlmExtractionErrorKind::ProviderContentMissing)
    })?;

    let trimmed = raw_content.trim();
    if trimmed.is_empty() {
        return Err(LlmExtractionError::possibly_sent(
            LlmExtractionErrorKind::ProviderContentMissing,
        ));
    }

    // Strict model content check: MUST NOT contain Markdown fences or extra text
    if trimmed.starts_with("```") || !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return Err(LlmExtractionError::possibly_sent(
            LlmExtractionErrorKind::ExtractionJsonInvalid,
        ));
    }

    let batch_dto: LlmBatchDto = serde_json::from_str(trimmed).map_err(|_| {
        LlmExtractionError::possibly_sent(LlmExtractionErrorKind::ExtractionSchemaInvalid)
    })?;

    if batch_dto.proposals.len() > MAX_PROPOSALS {
        return Err(LlmExtractionError::possibly_sent(
            LlmExtractionErrorKind::ExtractionCandidateLimitExceeded,
        ));
    }

    let mut proposals = Vec::with_capacity(batch_dto.proposals.len());

    for prop in batch_dto.proposals {
        let action = match prop.action {
            LlmActionDto::Propose => ProposalAction::Propose,
            LlmActionDto::Ignore => ProposalAction::Ignore,
        };

        let kind = prop.kind.map(|k| match k {
            LlmMemoryKindDto::Preference => MemoryKind::Preference,
            LlmMemoryKindDto::Goal => MemoryKind::Goal,
            LlmMemoryKindDto::Experience => MemoryKind::Experience,
            LlmMemoryKindDto::Fact => MemoryKind::Fact,
            LlmMemoryKindDto::Relationship => MemoryKind::Relationship,
            LlmMemoryKindDto::Skill => MemoryKind::Skill,
            LlmMemoryKindDto::Other => MemoryKind::Other,
        });

        if action == ProposalAction::Propose {
            let content = prop.content.as_deref().unwrap_or("").trim();
            if content.is_empty() {
                return Err(LlmExtractionError::possibly_sent(
                    LlmExtractionErrorKind::ExtractionSchemaInvalid,
                ));
            }
            if content.len() > MAX_PROPOSAL_CONTENT_UTF8_BYTES
                || content.chars().count() > MAX_PROPOSAL_CONTENT_SCALARS
            {
                return Err(LlmExtractionError::possibly_sent(
                    LlmExtractionErrorKind::ExtractionFieldLimitExceeded,
                ));
            }
        }

        if let Some(ref s) = prop.summary {
            if s.len() > MAX_PROPOSAL_SUMMARY_UTF8_BYTES
                || s.chars().count() > MAX_PROPOSAL_SUMMARY_SCALARS
            {
                return Err(LlmExtractionError::possibly_sent(
                    LlmExtractionErrorKind::ExtractionFieldLimitExceeded,
                ));
            }
        }

        if let Some(conf) = prop.confidence {
            if !(0.0..=1.0).contains(&conf) || conf.is_nan() {
                return Err(LlmExtractionError::possibly_sent(
                    LlmExtractionErrorKind::ExtractionSchemaInvalid,
                ));
            }
        }

        if let Some(imp) = prop.importance {
            if !(0.0..=1.0).contains(&imp) || imp.is_nan() {
                return Err(LlmExtractionError::possibly_sent(
                    LlmExtractionErrorKind::ExtractionSchemaInvalid,
                ));
            }
        }

        let sensitivity_hint = match prop.sensitivity_hint {
            Some(LlmSensitivityDto::NotSensitive) => SensitivityHint::NotSensitive,
            Some(LlmSensitivityDto::Sensitive) => SensitivityHint::Sensitive,
            Some(LlmSensitivityDto::Unknown) | None => SensitivityHint::Unknown,
        };

        proposals.push(CandidateExtractionProposal {
            action,
            kind,
            content: prop.content,
            summary: prop.summary,
            confidence: prop.confidence,
            importance: prop.importance,
            sensitivity_hint,
            conflict_hint: prop.conflict_hint.unwrap_or(false),
            source_message_ids: prop.source_message_ids.unwrap_or_default(),
        });
    }

    Ok(CandidateExtractionBatch { proposals })
}
