use std::time::Duration;

use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};

use crate::secrets::SecretValue;

use super::{
    ModelConfig, ModelError, ModelFinishReason, ModelFuture, ModelMessageRole, ModelProvider,
    ModelRequest, ModelResponse, ModelUsage,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

pub struct OpenAICompatibleProvider {
    client: Client,
    endpoint: Url,
    api_key: SecretValue,
    model_name: String,
}

impl OpenAICompatibleProvider {
    pub fn new(config: ModelConfig) -> Result<Self, ModelError> {
        let api_key = SecretValue::new(config.api_key).map_err(|_| {
            ModelError::new(
                "MODEL_API_KEY_REQUIRED",
                "An API key is required for this model provider.",
                true,
            )
        })?;

        Self::new_with_secret(config.base_url, config.model_name, api_key, REQUEST_TIMEOUT)
    }

    pub(crate) fn new_with_secret(
        base_url: String,
        model_name: String,
        api_key: SecretValue,
        timeout: Duration,
    ) -> Result<Self, ModelError> {
        if timeout.is_zero() {
            return Err(ModelError::new(
                "MODEL_HTTP_CLIENT_ERROR",
                "The model HTTP timeout is invalid.",
                false,
            ));
        }

        if model_name.trim().is_empty() {
            return Err(ModelError::new(
                "MODEL_NAME_REQUIRED",
                "A model name is required.",
                true,
            ));
        }

        let endpoint = Self::chat_endpoint(&base_url)?;
        let client = Client::builder().timeout(timeout).build().map_err(|_| {
            ModelError::new(
                "MODEL_HTTP_CLIENT_ERROR",
                "The model HTTP client could not be initialized.",
                false,
            )
        })?;

        Ok(Self {
            client,
            endpoint,
            api_key,
            model_name,
        })
    }

    fn chat_endpoint(base_url: &str) -> Result<Url, ModelError> {
        let mut url = Url::parse(base_url.trim()).map_err(|_| {
            ModelError::new(
                "MODEL_BASE_URL_INVALID",
                "The model base URL is invalid.",
                true,
            )
        })?;

        if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
            return Err(ModelError::new(
                "MODEL_BASE_URL_INVALID",
                "The model base URL must be an absolute HTTP or HTTPS URL.",
                true,
            ));
        }

        if !url.username().is_empty() || url.password().is_some() {
            return Err(ModelError::new(
                "MODEL_BASE_URL_INVALID",
                "Credentials must not be embedded in the model base URL.",
                true,
            ));
        }

        let path = format!("{}/chat/completions", url.path().trim_end_matches('/'));
        url.set_path(&path);
        url.set_query(None);
        url.set_fragment(None);
        Ok(url)
    }

    fn request_payload(&self, request: ModelRequest) -> Result<OpenAIChatRequest, ModelError> {
        if request.messages.is_empty() {
            return Err(ModelError::new(
                "MODEL_MESSAGES_REQUIRED",
                "At least one model message is required.",
                true,
            ));
        }

        if !request.temperature.is_finite() || !(0.0..=2.0).contains(&request.temperature) {
            return Err(ModelError::new(
                "MODEL_TEMPERATURE_INVALID",
                "Temperature must be between 0 and 2.",
                true,
            ));
        }

        if request.max_tokens == 0 {
            return Err(ModelError::new(
                "MODEL_MAX_TOKENS_INVALID",
                "maxTokens must be greater than zero.",
                true,
            ));
        }

        let mut messages = Vec::with_capacity(request.messages.len() + 1);
        if let Some(system_context) = request
            .system_context
            .filter(|context| !context.trim().is_empty())
        {
            messages.push(OpenAIMessage {
                role: "system",
                content: system_context,
            });
        }
        messages.extend(request.messages.into_iter().map(|message| OpenAIMessage {
            role: match message.role {
                ModelMessageRole::User => "user",
                ModelMessageRole::Assistant => "assistant",
                ModelMessageRole::System => "system",
            },
            content: message.content,
        }));

        Ok(OpenAIChatRequest {
            model: self.model_name.clone(),
            messages,
            temperature: request.temperature,
            max_tokens: request.max_tokens,
            stream: false,
        })
    }

    fn map_response(&self, response: OpenAIChatResponse) -> Result<ModelResponse, ModelError> {
        let choice = response.choices.into_iter().next().ok_or_else(|| {
            ModelError::new(
                "MODEL_RESPONSE_EMPTY",
                "The model response did not contain a completion choice.",
                true,
            )
        })?;

        let usage = response.usage.unwrap_or_default();
        Ok(ModelResponse {
            text: choice.message.content.unwrap_or_default(),
            model_name: if response.model.trim().is_empty() {
                self.model_name.clone()
            } else {
                response.model
            },
            usage: ModelUsage {
                input_tokens: usage.prompt_tokens,
                output_tokens: usage.completion_tokens,
                total_tokens: usage.total_tokens,
            },
            finish_reason: ModelFinishReason::from_provider(choice.finish_reason.as_deref()),
        })
    }
}

impl ModelProvider for OpenAICompatibleProvider {
    fn chat<'a>(
        &'a self,
        request: ModelRequest,
    ) -> ModelFuture<'a, Result<ModelResponse, ModelError>> {
        Box::pin(async move {
            let payload = self.request_payload(request)?;
            let response = self
                .client
                .post(self.endpoint.clone())
                .bearer_auth(self.api_key.expose_secret())
                .json(&payload)
                .send()
                .await
                .map_err(|error| {
                    if error.is_connect() {
                        ModelError::new(
                            "MODEL_NETWORK_UNAVAILABLE",
                            "The model service is unavailable.",
                            true,
                        )
                    } else if error.is_timeout() {
                        ModelError::new(
                            "MODEL_REQUEST_TIMEOUT",
                            "The model request timed out.",
                            true,
                        )
                    } else {
                        ModelError::new(
                            "MODEL_NETWORK_UNAVAILABLE",
                            "The model service is unavailable.",
                            true,
                        )
                    }
                })?;

            if !response.status().is_success() {
                let (code, message, recoverable) = match response.status() {
                    reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => (
                        "MODEL_AUTHENTICATION_FAILED",
                        "The model service rejected authentication.",
                        false,
                    ),
                    reqwest::StatusCode::TOO_MANY_REQUESTS => (
                        "MODEL_RATE_LIMITED",
                        "The model service rate limit was reached.",
                        true,
                    ),
                    _ => (
                        "MODEL_HTTP_ERROR",
                        "The model service returned an unsuccessful HTTP status.",
                        true,
                    ),
                };
                return Err(ModelError::new(code, message, recoverable));
            }

            let response = response.json::<OpenAIChatResponse>().await.map_err(|_| {
                ModelError::new(
                    "MODEL_RESPONSE_INVALID",
                    "The model service returned an invalid response.",
                    true,
                )
            })?;
            self.map_response(response)
        })
    }

    fn stream_chat<'a>(
        &'a self,
        _request_id: &'a str,
        _request: ModelRequest,
    ) -> ModelFuture<'a, Result<(), ModelError>> {
        Box::pin(async {
            Err(ModelError::new(
                "MODEL_STREAM_NOT_IMPLEMENTED",
                "Streaming transport is reserved for a later task.",
                true,
            ))
        })
    }
}

impl ModelFinishReason {
    fn from_provider(value: Option<&str>) -> Self {
        match value {
            Some("stop") => Self::Stop,
            Some("length") => Self::Length,
            Some("content_filter") => Self::ContentFilter,
            Some("tool_calls") => Self::ToolCalls,
            _ => Self::Other,
        }
    }
}

#[derive(Serialize)]
struct OpenAIChatRequest {
    model: String,
    messages: Vec<OpenAIMessage>,
    temperature: f32,
    max_tokens: u32,
    stream: bool,
}

#[derive(Serialize)]
struct OpenAIMessage {
    role: &'static str,
    content: String,
}

#[derive(Deserialize)]
struct OpenAIChatResponse {
    #[serde(default)]
    model: String,
    choices: Vec<OpenAIChoice>,
    usage: Option<OpenAIUsage>,
}

#[derive(Deserialize)]
struct OpenAIChoice {
    message: OpenAIResponseMessage,
    finish_reason: Option<String>,
}

#[derive(Deserialize)]
struct OpenAIResponseMessage {
    content: Option<String>,
}

#[derive(Default, Deserialize)]
struct OpenAIUsage {
    #[serde(default)]
    prompt_tokens: u32,
    #[serde(default)]
    completion_tokens: u32,
    #[serde(default)]
    total_tokens: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ModelMessage, ModelMessageRole};

    fn provider() -> OpenAICompatibleProvider {
        OpenAICompatibleProvider::new(ModelConfig {
            base_url: "https://example.invalid/v1/".into(),
            api_key: "runtime-only-test-key".into(),
            model_name: "test-model".into(),
        })
        .unwrap()
    }

    #[test]
    fn builds_chat_completions_endpoint() {
        let endpoint =
            OpenAICompatibleProvider::chat_endpoint("https://example.invalid/v1/").unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://example.invalid/v1/chat/completions"
        );
    }

    #[test]
    fn system_context_is_prepended_to_messages() {
        let payload = provider()
            .request_payload(ModelRequest {
                messages: vec![ModelMessage {
                    role: ModelMessageRole::User,
                    content: "Hello".into(),
                }],
                system_context: Some("Runtime system context".into()),
                temperature: 0.7,
                max_tokens: 128,
            })
            .unwrap();

        assert_eq!(payload.messages.len(), 2);
        assert_eq!(payload.messages[0].role, "system");
        assert_eq!(payload.messages[1].role, "user");
    }

    #[test]
    fn invalid_url_error_does_not_expose_api_key() {
        let secret = "runtime-only-test-key";
        let error = OpenAICompatibleProvider::new(ModelConfig {
            base_url: "not a url".into(),
            api_key: secret.into(),
            model_name: "test-model".into(),
        })
        .err()
        .unwrap();

        assert!(!error.message.contains(secret));
    }

    #[test]
    fn maps_openai_response_to_model_response() {
        let response = provider()
            .map_response(OpenAIChatResponse {
                model: "test-model".into(),
                choices: vec![OpenAIChoice {
                    message: OpenAIResponseMessage {
                        content: Some("Hello".into()),
                    },
                    finish_reason: Some("stop".into()),
                }],
                usage: Some(OpenAIUsage {
                    prompt_tokens: 4,
                    completion_tokens: 2,
                    total_tokens: 6,
                }),
            })
            .unwrap();

        assert_eq!(response.text, "Hello");
        assert_eq!(response.finish_reason, ModelFinishReason::Stop);
        assert_eq!(response.usage.total_tokens, 6);
    }
}
