use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};

use crate::secrets::SecretValue;

use super::{
    validate_request, validate_response, EmbeddingError, EmbeddingErrorCode, EmbeddingFuture,
    EmbeddingModelInfo, EmbeddingProvider, EmbeddingRequest, EmbeddingResponse,
    EmbeddingRuntimeOptions, EmbeddingUsage, EmbeddingVector,
};

/// Serializable non-secret settings. The runtime API key is supplied separately.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenAICompatibleEmbeddingConfig {
    pub base_url: String,
    pub model_name: String,
    #[serde(default)]
    pub expected_dimension: Option<usize>,
}

/// A runtime-only secret. It deliberately implements neither `Debug` nor serde.
pub struct RuntimeEmbeddingApiKey(SecretValue);

impl RuntimeEmbeddingApiKey {
    pub fn new(value: String) -> Result<Self, EmbeddingError> {
        SecretValue::new(value).map(Self).map_err(|_| {
            EmbeddingError::new(
                EmbeddingErrorCode::InvalidRequest,
                "An embedding API key is required.",
                false,
            )
        })
    }

    pub(crate) fn from_secret(value: SecretValue) -> Self {
        Self(value)
    }
}

pub struct OpenAICompatibleEmbeddingProvider {
    client: Client,
    endpoint: Url,
    api_key: RuntimeEmbeddingApiKey,
    config: OpenAICompatibleEmbeddingConfig,
    options: EmbeddingRuntimeOptions,
}

impl OpenAICompatibleEmbeddingProvider {
    pub fn new(
        config: OpenAICompatibleEmbeddingConfig,
        api_key: RuntimeEmbeddingApiKey,
        options: EmbeddingRuntimeOptions,
    ) -> Result<Self, EmbeddingError> {
        if config.model_name.trim().is_empty() {
            return Err(EmbeddingError::new(
                EmbeddingErrorCode::InvalidRequest,
                "An embedding model name is required.",
                false,
            ));
        }
        if matches!(config.expected_dimension, Some(0)) {
            return Err(EmbeddingError::new(
                EmbeddingErrorCode::InvalidRequest,
                "The expected embedding dimension must be greater than zero.",
                false,
            ));
        }
        let options = EmbeddingRuntimeOptions {
            limits: options.limits.validate()?,
            ..options
        };
        if options.timeout.is_zero() {
            return Err(EmbeddingError::new(
                EmbeddingErrorCode::InvalidRequest,
                "The embedding request timeout must be greater than zero.",
                false,
            ));
        }
        let endpoint = Self::embeddings_endpoint(&config.base_url)?;
        let client = Client::builder()
            .timeout(options.timeout)
            .build()
            .map_err(|_| {
                EmbeddingError::new(
                    EmbeddingErrorCode::NetworkError,
                    "The embedding HTTP client could not be initialized.",
                    false,
                )
            })?;
        Ok(Self {
            client,
            endpoint,
            api_key,
            config,
            options,
        })
    }

    fn embeddings_endpoint(base_url: &str) -> Result<Url, EmbeddingError> {
        let mut url = Url::parse(base_url.trim()).map_err(|_| {
            EmbeddingError::new(
                EmbeddingErrorCode::InvalidRequest,
                "The embedding base URL is invalid.",
                false,
            )
        })?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            return Err(EmbeddingError::new(
                EmbeddingErrorCode::InvalidRequest,
                "The embedding base URL must be an absolute HTTP or HTTPS URL without credentials.",
                false,
            ));
        }
        let path = format!("{}/embeddings", url.path().trim_end_matches('/'));
        url.set_path(&path);
        url.set_query(None);
        url.set_fragment(None);
        Ok(url)
    }

    fn map_http_error(status: StatusCode) -> EmbeddingError {
        let (code, message, recoverable) = match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => (
                EmbeddingErrorCode::AuthenticationFailed,
                "The embedding service rejected authentication.",
                false,
            ),
            StatusCode::TOO_MANY_REQUESTS => (
                EmbeddingErrorCode::RateLimited,
                "The embedding service rate limit was reached.",
                true,
            ),
            _ => (
                EmbeddingErrorCode::NetworkError,
                "The embedding service returned an unsuccessful HTTP status.",
                true,
            ),
        };
        EmbeddingError::new(code, message, recoverable)
    }

    fn map_response(
        &self,
        response: OpenAIEmbeddingResponse,
        expected_input_count: usize,
    ) -> Result<EmbeddingResponse, EmbeddingError> {
        let vectors = response
            .data
            .into_iter()
            .map(|data| {
                let input_index = data.index.ok_or_else(|| {
                    EmbeddingError::new(
                        EmbeddingErrorCode::InvalidProviderResponse,
                        "The embedding service omitted a vector index.",
                        true,
                    )
                })?;
                Ok(EmbeddingVector {
                    input_index,
                    values: data.embedding,
                })
            })
            .collect::<Result<Vec<_>, EmbeddingError>>()?;
        let dimension = vectors
            .first()
            .map(|vector| vector.values.len())
            .unwrap_or(0);
        let model_name = if response.model.trim().is_empty() {
            self.config.model_name.clone()
        } else {
            response.model
        };
        validate_response(
            EmbeddingResponse {
                model_name,
                dimension,
                vectors,
                input_count: expected_input_count,
                usage: response.usage.map(|usage| EmbeddingUsage {
                    prompt_tokens: usage.prompt_tokens,
                    total_tokens: usage.total_tokens,
                }),
            },
            expected_input_count,
            self.config.expected_dimension,
        )
    }
}

impl EmbeddingProvider for OpenAICompatibleEmbeddingProvider {
    fn model_info(&self) -> EmbeddingModelInfo {
        EmbeddingModelInfo {
            model_name: self.config.model_name.clone(),
            dimension: self.config.expected_dimension,
        }
    }

    fn model_name(&self) -> &str {
        &self.config.model_name
    }

    fn vector_dimension(&self) -> Option<usize> {
        self.config.expected_dimension
    }

    fn max_batch_size(&self) -> usize {
        self.options.limits.max_batch_size
    }

    fn embed<'a>(
        &'a self,
        request: EmbeddingRequest,
    ) -> EmbeddingFuture<'a, Result<EmbeddingResponse, EmbeddingError>> {
        Box::pin(async move {
            validate_request(&request, self.options.limits)?;
            let input_count = request.texts.len();
            let payload = OpenAIEmbeddingRequest {
                model: &self.config.model_name,
                input: request.texts,
            };
            let response = self
                .client
                .post(self.endpoint.clone())
                .bearer_auth(self.api_key.0.expose_secret())
                .json(&payload)
                .send()
                .await
                .map_err(|error| {
                    if error.is_connect() {
                        EmbeddingError::new(
                            EmbeddingErrorCode::NetworkError,
                            "The embedding service is unavailable.",
                            true,
                        )
                    } else if error.is_timeout() {
                        EmbeddingError::new(
                            EmbeddingErrorCode::RequestTimeout,
                            "The embedding request timed out.",
                            true,
                        )
                    } else {
                        EmbeddingError::new(
                            EmbeddingErrorCode::NetworkError,
                            "The embedding service is unavailable.",
                            true,
                        )
                    }
                })?;
            if !response.status().is_success() {
                return Err(Self::map_http_error(response.status()));
            }
            let body = response
                .json::<OpenAIEmbeddingResponse>()
                .await
                .map_err(|_| {
                    EmbeddingError::new(
                        EmbeddingErrorCode::InvalidProviderResponse,
                        "The embedding service returned an invalid response.",
                        true,
                    )
                })?;
            self.map_response(body, input_count)
        })
    }
}

#[derive(Serialize)]
struct OpenAIEmbeddingRequest<'a> {
    model: &'a str,
    input: Vec<String>,
}

#[derive(Deserialize)]
struct OpenAIEmbeddingResponse {
    #[serde(default)]
    model: String,
    data: Vec<OpenAIEmbeddingData>,
    usage: Option<OpenAIEmbeddingUsage>,
}

#[derive(Deserialize)]
struct OpenAIEmbeddingData {
    index: Option<usize>,
    embedding: Vec<f32>,
}

#[derive(Deserialize)]
struct OpenAIEmbeddingUsage {
    #[serde(default)]
    prompt_tokens: Option<u64>,
    #[serde(default)]
    total_tokens: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embedding::{EmbeddingPurpose, EmbeddingRequest, EmbeddingRuntimeOptions};

    fn provider(expected_dimension: Option<usize>) -> OpenAICompatibleEmbeddingProvider {
        OpenAICompatibleEmbeddingProvider::new(
            OpenAICompatibleEmbeddingConfig {
                base_url: "https://example.invalid/v1/".into(),
                model_name: "test-model".into(),
                expected_dimension,
            },
            RuntimeEmbeddingApiKey::new("test-secret".into()).unwrap(),
            EmbeddingRuntimeOptions::default(),
        )
        .unwrap()
    }

    fn parsed(body: serde_json::Value) -> OpenAIEmbeddingResponse {
        serde_json::from_value(body).unwrap()
    }

    #[test]
    fn builds_embeddings_endpoint() {
        assert_eq!(
            OpenAICompatibleEmbeddingProvider::embeddings_endpoint("https://example.invalid/v1/")
                .unwrap()
                .as_str(),
            "https://example.invalid/v1/embeddings"
        );
    }

    #[test]
    fn restores_response_order_using_indexes() {
        let response = provider(None)
            .map_response(
                parsed(serde_json::json!({
                    "model": "test-model",
                    "data": [
                        { "index": 1, "embedding": [2.0, 3.0] },
                        { "index": 0, "embedding": [0.0, 1.0] }
                    ]
                })),
                2,
            )
            .unwrap();
        assert_eq!(response.vectors[0].values, vec![0.0, 1.0]);
        assert_eq!(response.vectors[1].values, vec![2.0, 3.0]);
    }

    #[test]
    fn rejects_missing_duplicate_count_and_dimension_errors() {
        let missing = provider(None)
            .map_response(
                parsed(serde_json::json!({ "data": [{ "embedding": [1.0] }] })),
                1,
            )
            .unwrap_err();
        assert_eq!(missing.code, EmbeddingErrorCode::InvalidProviderResponse);

        let duplicate = provider(None)
            .map_response(
                parsed(serde_json::json!({ "data": [
                { "index": 0, "embedding": [1.0] }, { "index": 0, "embedding": [1.0] }
            ] })),
                2,
            )
            .unwrap_err();
        assert_eq!(duplicate.code, EmbeddingErrorCode::InvalidProviderResponse);

        let count = provider(None)
            .map_response(
                parsed(serde_json::json!({ "data": [{ "index": 0, "embedding": [1.0] }] })),
                2,
            )
            .unwrap_err();
        assert_eq!(count.code, EmbeddingErrorCode::InvalidProviderResponse);

        let dimensions = provider(None)
            .map_response(
                parsed(serde_json::json!({ "data": [
                { "index": 0, "embedding": [1.0] }, { "index": 1, "embedding": [1.0, 2.0] }
            ] })),
                2,
            )
            .unwrap_err();
        assert_eq!(dimensions.code, EmbeddingErrorCode::DimensionMismatch);
    }

    #[test]
    fn maps_authentication_and_rate_limit_errors_without_secret_disclosure() {
        let secret = "test-secret";
        let authentication =
            OpenAICompatibleEmbeddingProvider::map_http_error(StatusCode::UNAUTHORIZED);
        let rate_limit =
            OpenAICompatibleEmbeddingProvider::map_http_error(StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            authentication.code,
            EmbeddingErrorCode::AuthenticationFailed
        );
        assert_eq!(rate_limit.code, EmbeddingErrorCode::RateLimited);
        assert!(!authentication.message.contains(secret));
        assert!(!rate_limit.message.contains(secret));
    }

    #[test]
    fn response_has_no_input_text_and_provider_has_no_storage_dependency() {
        let request = EmbeddingRequest {
            texts: vec!["private text".into()],
            purpose: EmbeddingPurpose::Query,
        };
        let response = provider(None)
            .map_response(
                parsed(serde_json::json!({
                    "data": [{ "index": 0, "embedding": [1.0] }]
                })),
                request.texts.len(),
            )
            .unwrap();
        assert!(!serde_json::to_string(&response)
            .unwrap()
            .contains("private text"));
    }
}
