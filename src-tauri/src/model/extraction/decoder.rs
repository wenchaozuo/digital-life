use serde::Deserialize;

use super::{
    error::{LlmExtractionError, LlmExtractionErrorKind},
    wire::{
        ExtractionWireInputV1, ValidatedExtractionWireResultV1, ValidatedWireProposalV1,
        WireMemoryKindV1, WireSensitivityHintV1, V1_MAX_PROPOSALS, V1_MAX_PROPOSAL_CONTENT_SCALARS,
        V1_MAX_PROPOSAL_CONTENT_UTF8_BYTES, V1_MAX_PROPOSAL_SUMMARY_SCALARS,
        V1_MAX_PROPOSAL_SUMMARY_UTF8_BYTES, V1_MAX_SELECTED_USER_MESSAGES,
    },
};

/// V1 accepts only the explicitly modeled non-streaming chat-completions
/// envelope. Fields are parsed only to make the compatibility contract
/// explicit; none are retained after decoding.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenAiEnvelopeDto {
    id: Option<String>,
    object: Option<String>,
    created: Option<i64>,
    model: Option<String>,
    choices: Vec<OpenAiChoiceDto>,
    usage: Option<OpenAiUsageDto>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenAiUsageDto {
    prompt_tokens: Option<u64>,
    completion_tokens: Option<u64>,
    total_tokens: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenAiChoiceDto {
    index: Option<u64>,
    finish_reason: Option<String>,
    message: OpenAiChoiceMessageDto,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenAiChoiceMessageDto {
    role: OpenAiAssistantRoleDto,
    content: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum OpenAiAssistantRoleDto {
    Assistant,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LlmBatchDto {
    proposals: Vec<LlmProposalDto>,
}

#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "lowercase", deny_unknown_fields)]
enum LlmProposalDto {
    Propose {
        kind: LlmMemoryKindDto,
        content: String,
        summary: String,
        confidence: f64,
        importance: f64,
        sensitivity_hint: LlmSensitivityDto,
        conflict_hint: bool,
        source_message_ids: Vec<String>,
    },
    Ignore {
        source_message_ids: Vec<String>,
    },
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

pub(super) fn decode_response_envelope(
    body: &[u8],
    input: &ExtractionWireInputV1,
) -> Result<ValidatedExtractionWireResultV1, LlmExtractionError> {
    if body.is_empty() {
        return Err(possibly_sent(
            LlmExtractionErrorKind::ProviderContentMissing,
        ));
    }

    let envelope: OpenAiEnvelopeDto = serde_json::from_slice(body)
        .map_err(|_| possibly_sent(LlmExtractionErrorKind::ProviderEnvelopeInvalid))?;
    let _known_standard_fields = (
        envelope.id,
        envelope.object,
        envelope.created,
        envelope.model,
        envelope.usage,
    );

    if envelope.choices.len() != 1 {
        return Err(possibly_sent(
            LlmExtractionErrorKind::ProviderEnvelopeInvalid,
        ));
    }

    let choice = envelope
        .choices
        .into_iter()
        .next()
        .expect("choices length checked to be one");
    let _known_choice_fields = (choice.index, choice.finish_reason);
    let raw_content = choice.message.content;

    let trimmed = raw_content.trim();
    if trimmed.is_empty() {
        return Err(possibly_sent(
            LlmExtractionErrorKind::ProviderContentMissing,
        ));
    }

    // `serde_json::from_str` consumes the complete non-whitespace input. The
    // outer object check also rejects arrays, scalars, and Markdown fences.
    if trimmed.starts_with("```") || !trimmed.starts_with('{') || !trimmed.ends_with('}') {
        return Err(possibly_sent(LlmExtractionErrorKind::ExtractionJsonInvalid));
    }

    let batch: LlmBatchDto = serde_json::from_str(trimmed)
        .map_err(|_| possibly_sent(LlmExtractionErrorKind::ExtractionSchemaInvalid))?;
    if batch.proposals.len() > V1_MAX_PROPOSALS {
        return Err(possibly_sent(
            LlmExtractionErrorKind::ExtractionCandidateLimitExceeded,
        ));
    }

    let mut proposals = Vec::with_capacity(batch.proposals.len());
    for proposal in batch.proposals {
        match proposal {
            LlmProposalDto::Propose {
                kind,
                content,
                summary,
                confidence,
                importance,
                sensitivity_hint,
                conflict_hint,
                source_message_ids,
            } => {
                validate_text(
                    &content,
                    V1_MAX_PROPOSAL_CONTENT_SCALARS,
                    V1_MAX_PROPOSAL_CONTENT_UTF8_BYTES,
                )?;
                validate_text(
                    &summary,
                    V1_MAX_PROPOSAL_SUMMARY_SCALARS,
                    V1_MAX_PROPOSAL_SUMMARY_UTF8_BYTES,
                )?;
                validate_probability(confidence)?;
                validate_probability(importance)?;
                validate_source_message_ids(&source_message_ids)?;
                proposals.push(ValidatedWireProposalV1::propose(
                    wire_kind(kind),
                    content,
                    summary,
                    confidence,
                    importance,
                    wire_sensitivity(sensitivity_hint),
                    conflict_hint,
                    source_message_ids,
                ));
            }
            LlmProposalDto::Ignore { source_message_ids } => {
                validate_source_message_ids(&source_message_ids)?;
                proposals.push(ValidatedWireProposalV1::ignore(source_message_ids));
            }
        }
    }

    Ok(ValidatedExtractionWireResultV1::new(proposals, input))
}

fn validate_text(
    value: &str,
    scalar_limit: usize,
    byte_limit: usize,
) -> Result<(), LlmExtractionError> {
    if value.trim().is_empty() {
        return Err(possibly_sent(
            LlmExtractionErrorKind::ExtractionSchemaInvalid,
        ));
    }
    if value.chars().count() > scalar_limit || value.len() > byte_limit {
        return Err(possibly_sent(
            LlmExtractionErrorKind::ExtractionFieldLimitExceeded,
        ));
    }
    Ok(())
}

fn validate_probability(value: f64) -> Result<(), LlmExtractionError> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(possibly_sent(
            LlmExtractionErrorKind::ExtractionSchemaInvalid,
        ));
    }
    Ok(())
}

fn validate_source_message_ids(ids: &[String]) -> Result<(), LlmExtractionError> {
    if ids.is_empty()
        || ids.len() > V1_MAX_SELECTED_USER_MESSAGES
        || ids.iter().any(|id| id.trim().is_empty())
    {
        return Err(possibly_sent(
            LlmExtractionErrorKind::ExtractionSchemaInvalid,
        ));
    }
    Ok(())
}

fn wire_kind(value: LlmMemoryKindDto) -> WireMemoryKindV1 {
    match value {
        LlmMemoryKindDto::Preference => WireMemoryKindV1::Preference,
        LlmMemoryKindDto::Goal => WireMemoryKindV1::Goal,
        LlmMemoryKindDto::Experience => WireMemoryKindV1::Experience,
        LlmMemoryKindDto::Fact => WireMemoryKindV1::Fact,
        LlmMemoryKindDto::Relationship => WireMemoryKindV1::Relationship,
        LlmMemoryKindDto::Skill => WireMemoryKindV1::Skill,
        LlmMemoryKindDto::Other => WireMemoryKindV1::Other,
    }
}

fn wire_sensitivity(value: LlmSensitivityDto) -> WireSensitivityHintV1 {
    match value {
        LlmSensitivityDto::NotSensitive => WireSensitivityHintV1::NotSensitive,
        LlmSensitivityDto::Sensitive => WireSensitivityHintV1::Sensitive,
        LlmSensitivityDto::Unknown => WireSensitivityHintV1::Unknown,
    }
}

fn possibly_sent(kind: LlmExtractionErrorKind) -> LlmExtractionError {
    LlmExtractionError::possibly_sent(kind)
}
