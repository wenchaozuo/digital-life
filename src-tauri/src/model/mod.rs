mod openai_compatible;

use std::{future::Future, pin::Pin};

pub use openai_compatible::OpenAICompatibleProvider;
use serde::{Deserialize, Serialize};

pub const MODEL_STREAM_EVENT_NAME: &str = "model:stream";

pub type ModelFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelConfig {
    pub base_url: String,
    pub api_key: String,
    pub model_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ModelMessageRole {
    User,
    Assistant,
    System,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModelMessage {
    pub role: ModelMessageRole,
    pub content: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelRequest {
    pub messages: Vec<ModelMessage>,
    pub system_context: Option<String>,
    pub temperature: f32,
    pub max_tokens: u32,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModelUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub total_tokens: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ModelFinishReason {
    Stop,
    Length,
    ContentFilter,
    ToolCalls,
    Other,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModelResponse {
    pub text: String,
    pub model_name: String,
    pub usage: ModelUsage,
    pub finish_reason: ModelFinishReason,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModelError {
    pub code: String,
    pub message: String,
    pub recoverable: bool,
}

impl ModelError {
    pub(crate) fn new(code: &str, message: impl Into<String>, recoverable: bool) -> Self {
        Self {
            code: code.to_string(),
            message: message.into(),
            recoverable,
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModelStreamEvent {
    pub request_id: String,
    pub event: ModelStreamEventKind,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ModelStreamEventKind {
    Started { model_name: String },
    Delta { text: String },
    Completed { response: ModelResponse },
    Failed { error: ModelError },
}

pub trait ModelProvider: Send + Sync {
    fn chat<'a>(
        &'a self,
        request: ModelRequest,
    ) -> ModelFuture<'a, Result<ModelResponse, ModelError>>;

    fn stream_chat<'a>(
        &'a self,
        request_id: &'a str,
        request: ModelRequest,
    ) -> ModelFuture<'a, Result<(), ModelError>>;
}

#[tauri::command]
pub async fn chat_with_model(
    config: ModelConfig,
    request: ModelRequest,
) -> Result<ModelResponse, ModelError> {
    let provider = OpenAICompatibleProvider::new(config)?;
    provider.chat(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_config_is_deserializable_without_being_serializable() {
        let config: ModelConfig = serde_json::from_value(serde_json::json!({
            "baseUrl": "https://example.invalid/v1",
            "apiKey": "runtime-only-test-key",
            "modelName": "test-model"
        }))
        .unwrap();

        assert_eq!(config.model_name, "test-model");
    }

    #[test]
    fn stream_event_name_is_stable() {
        assert_eq!(MODEL_STREAM_EVENT_NAME, "model:stream");
    }
}
