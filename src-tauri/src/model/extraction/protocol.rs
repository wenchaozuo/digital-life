use serde::Serialize;

use crate::{
    model::{
        profile::ModelProfile, provider::ProviderJsonRequest, transport::MAX_REQUEST_BODY_BYTES,
    },
    storage::candidate_extraction::CandidateExtractionRequest,
};

use super::{
    descriptor::LlmExtractorDescriptor,
    error::{LlmExtractionError, LlmExtractionErrorKind},
};

#[derive(Serialize)]
struct OpenAiMessageDto<'a> {
    role: &'static str,
    content: &'a str,
}

#[derive(Serialize)]
struct OpenAiChatRequestDto<'a> {
    model: &'a str,
    messages: Vec<OpenAiMessageDto<'a>>,
    stream: bool,
    temperature: f32,
    max_tokens: u32,
}

#[derive(Serialize)]
struct UserMessageContentItemDto<'a> {
    message_id: &'a str,
    sequence_no: i64,
    content: &'a str,
}

pub(crate) fn build_provider_request(
    descriptor: &LlmExtractorDescriptor,
    request: &CandidateExtractionRequest,
    profile: &ModelProfile,
) -> Result<ProviderJsonRequest, LlmExtractionError> {
    descriptor.validate_request(request)?;

    let user_items: Vec<UserMessageContentItemDto<'_>> = request
        .messages
        .iter()
        .map(|m| UserMessageContentItemDto {
            message_id: &m.message_id,
            sequence_no: m.sequence_no,
            content: &m.content,
        })
        .collect();

    let user_json_content = serde_json::to_string(&user_items).map_err(|_| {
        LlmExtractionError::definitely_not_sent(LlmExtractionErrorKind::ExtractionInputInvalid)
    })?;

    let messages = vec![
        OpenAiMessageDto {
            role: "system",
            content: descriptor.system_prompt(),
        },
        OpenAiMessageDto {
            role: "user",
            content: &user_json_content,
        },
    ];

    let chat_req = OpenAiChatRequestDto {
        model: profile.model_name.as_str(),
        messages,
        stream: false,
        temperature: 0.0,
        max_tokens: 2048,
    };

    let body_bytes = serde_json::to_vec(&chat_req).map_err(|_| {
        LlmExtractionError::definitely_not_sent(LlmExtractionErrorKind::ExtractionInputInvalid)
    })?;

    if body_bytes.len() as u64 > MAX_REQUEST_BODY_BYTES {
        return Err(LlmExtractionError::definitely_not_sent(
            LlmExtractionErrorKind::ExtractionRequestTooLarge,
        ));
    }

    ProviderJsonRequest::new(body_bytes).map_err(|err| {
        LlmExtractionError::new(
            LlmExtractionErrorKind::ExtractionRequestTooLarge,
            err.disposition(),
        )
    })
}
