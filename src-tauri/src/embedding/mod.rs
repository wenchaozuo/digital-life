//! Internal embedding capability for future vector-index work.
//!
//! It deliberately has no Tauri command and no SQLite, LanceDB, file, or memory
//! access. Embeddings are derived data only, never the authority for memory.

mod openai_compatible;

pub use openai_compatible::{
    OpenAICompatibleEmbeddingConfig, OpenAICompatibleEmbeddingProvider, RuntimeEmbeddingApiKey,
};

use std::{future::Future, pin::Pin, time::Duration};

use serde::{Deserialize, Serialize};

pub const DEFAULT_MAX_BATCH_SIZE: usize = 32;
pub const DEFAULT_MAX_TEXT_CHARACTERS: usize = 16_000;
pub const DEFAULT_MAX_TOTAL_CHARACTERS: usize = 128_000;

pub type EmbeddingFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EmbeddingPurpose {
    Query,
    Document,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddingRequest {
    pub texts: Vec<String>,
    pub purpose: EmbeddingPurpose,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddingVector {
    pub input_index: usize,
    pub values: Vec<f32>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddingUsage {
    pub prompt_tokens: Option<u64>,
    pub total_tokens: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddingResponse {
    pub model_name: String,
    pub dimension: usize,
    pub vectors: Vec<EmbeddingVector>,
    pub input_count: usize,
    pub usage: Option<EmbeddingUsage>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddingModelInfo {
    pub model_name: String,
    /// `None` means an OpenAI-compatible service has not supplied a known
    /// dimension yet and no expected dimension was configured.
    pub dimension: Option<usize>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EmbeddingErrorCode {
    InvalidRequest,
    EmptyText,
    BatchLimitExceeded,
    TextLimitExceeded,
    NetworkError,
    AuthenticationFailed,
    RateLimited,
    InvalidProviderResponse,
    DimensionMismatch,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddingError {
    pub code: EmbeddingErrorCode,
    pub message: String,
    pub recoverable: bool,
}

impl EmbeddingError {
    pub(crate) fn new(
        code: EmbeddingErrorCode,
        message: impl Into<String>,
        recoverable: bool,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmbeddingLimits {
    pub max_batch_size: usize,
    pub max_text_characters: usize,
    pub max_total_characters: usize,
}

impl Default for EmbeddingLimits {
    fn default() -> Self {
        Self {
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_text_characters: DEFAULT_MAX_TEXT_CHARACTERS,
            max_total_characters: DEFAULT_MAX_TOTAL_CHARACTERS,
        }
    }
}

impl EmbeddingLimits {
    pub fn validate(self) -> Result<Self, EmbeddingError> {
        if self.max_batch_size == 0
            || self.max_batch_size > DEFAULT_MAX_BATCH_SIZE
            || self.max_text_characters == 0
            || self.max_total_characters == 0
            || self.max_total_characters < self.max_text_characters
        {
            return Err(EmbeddingError::new(
                EmbeddingErrorCode::InvalidRequest,
                "Embedding limits are invalid.",
                false,
            ));
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmbeddingRuntimeOptions {
    pub limits: EmbeddingLimits,
    pub timeout: Duration,
}

impl Default for EmbeddingRuntimeOptions {
    fn default() -> Self {
        Self {
            limits: EmbeddingLimits::default(),
            timeout: Duration::from_secs(30),
        }
    }
}

/// Rust-internal provider boundary. Implementations must not persist requests,
/// responses, or vectors; future storage is a separate derived-data concern.
pub trait EmbeddingProvider: Send + Sync {
    fn model_info(&self) -> EmbeddingModelInfo;
    fn model_name(&self) -> &str;
    fn vector_dimension(&self) -> Option<usize>;
    fn max_batch_size(&self) -> usize {
        DEFAULT_MAX_BATCH_SIZE
    }
    fn embed<'a>(
        &'a self,
        request: EmbeddingRequest,
    ) -> EmbeddingFuture<'a, Result<EmbeddingResponse, EmbeddingError>>;
}

pub(crate) fn validate_request(
    request: &EmbeddingRequest,
    limits: EmbeddingLimits,
) -> Result<(), EmbeddingError> {
    if request.texts.is_empty() {
        return Err(EmbeddingError::new(
            EmbeddingErrorCode::InvalidRequest,
            "An embedding batch must contain at least one text.",
            false,
        ));
    }
    if request.texts.len() > limits.max_batch_size {
        return Err(EmbeddingError::new(
            EmbeddingErrorCode::BatchLimitExceeded,
            "The embedding batch exceeds the configured maximum size.",
            false,
        ));
    }

    let mut total_characters = 0usize;
    for text in &request.texts {
        if text.trim().is_empty() {
            return Err(EmbeddingError::new(
                EmbeddingErrorCode::EmptyText,
                "Embedding text must not be empty or whitespace only.",
                false,
            ));
        }
        let character_count = text.chars().count();
        if character_count > limits.max_text_characters {
            return Err(EmbeddingError::new(
                EmbeddingErrorCode::TextLimitExceeded,
                "An embedding text exceeds the configured character limit.",
                false,
            ));
        }
        total_characters = total_characters.saturating_add(character_count);
        if total_characters > limits.max_total_characters {
            return Err(EmbeddingError::new(
                EmbeddingErrorCode::TextLimitExceeded,
                "The embedding batch exceeds the configured total character limit.",
                false,
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_response(
    mut response: EmbeddingResponse,
    expected_input_count: usize,
    expected_dimension: Option<usize>,
) -> Result<EmbeddingResponse, EmbeddingError> {
    if response.input_count != expected_input_count
        || response.vectors.len() != expected_input_count
    {
        return Err(EmbeddingError::new(
            EmbeddingErrorCode::InvalidProviderResponse,
            "The embedding service returned an unexpected number of vectors.",
            true,
        ));
    }
    if response.model_name.trim().is_empty() || response.dimension == 0 {
        return Err(EmbeddingError::new(
            EmbeddingErrorCode::InvalidProviderResponse,
            "The embedding service returned invalid model metadata.",
            true,
        ));
    }
    if expected_dimension.is_some_and(|dimension| response.dimension != dimension) {
        return Err(EmbeddingError::new(
            EmbeddingErrorCode::DimensionMismatch,
            "The embedding service returned a dimension different from the configured model dimension.",
            true,
        ));
    }

    response.vectors.sort_by_key(|vector| vector.input_index);
    for (expected_index, vector) in response.vectors.iter().enumerate() {
        if vector.input_index != expected_index {
            return Err(EmbeddingError::new(
                EmbeddingErrorCode::InvalidProviderResponse,
                "The embedding service returned missing, duplicate, or invalid vector indexes.",
                true,
            ));
        }
        if vector.values.len() != response.dimension {
            return Err(EmbeddingError::new(
                EmbeddingErrorCode::DimensionMismatch,
                "The embedding service returned vectors with inconsistent dimensions.",
                true,
            ));
        }
        if vector.values.is_empty() || vector.values.iter().any(|value| !value.is_finite()) {
            return Err(EmbeddingError::new(
                EmbeddingErrorCode::InvalidProviderResponse,
                "The embedding service returned an invalid vector value.",
                true,
            ));
        }
    }
    Ok(response)
}

#[cfg(test)]
pub(crate) struct DeterministicEmbeddingProvider {
    model_name: String,
    dimension: usize,
    limits: EmbeddingLimits,
}

#[cfg(test)]
impl DeterministicEmbeddingProvider {
    pub(crate) fn new(dimension: usize) -> Self {
        assert!(dimension > 0, "test provider dimension must be positive");
        Self {
            model_name: "deterministic-test-embedding".into(),
            dimension,
            limits: EmbeddingLimits::default(),
        }
    }

    fn values_for(&self, text: &str) -> Vec<f32> {
        // A stable fixture only; it deliberately does not represent semantic similarity.
        let mut state = 0x811c_9dc5u32;
        for byte in text.as_bytes() {
            state ^= u32::from(*byte);
            state = state.wrapping_mul(0x0100_0193);
        }
        (0..self.dimension)
            .map(|index| {
                state ^= index as u32;
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                state as f32 / u32::MAX as f32
            })
            .collect()
    }
}

#[cfg(test)]
impl EmbeddingProvider for DeterministicEmbeddingProvider {
    fn model_info(&self) -> EmbeddingModelInfo {
        EmbeddingModelInfo {
            model_name: self.model_name.clone(),
            dimension: Some(self.dimension),
        }
    }

    fn model_name(&self) -> &str {
        &self.model_name
    }

    fn vector_dimension(&self) -> Option<usize> {
        Some(self.dimension)
    }

    fn max_batch_size(&self) -> usize {
        self.limits.max_batch_size
    }

    fn embed<'a>(
        &'a self,
        request: EmbeddingRequest,
    ) -> EmbeddingFuture<'a, Result<EmbeddingResponse, EmbeddingError>> {
        Box::pin(async move {
            validate_request(&request, self.limits)?;
            let input_count = request.texts.len();
            let response = EmbeddingResponse {
                model_name: self.model_name.clone(),
                dimension: self.dimension,
                vectors: request
                    .texts
                    .iter()
                    .enumerate()
                    .map(|(input_index, text)| EmbeddingVector {
                        input_index,
                        values: self.values_for(text),
                    })
                    .collect(),
                input_count,
                usage: None,
            };
            validate_response(response, input_count, Some(self.dimension))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(texts: Vec<&str>) -> EmbeddingRequest {
        EmbeddingRequest {
            texts: texts.into_iter().map(str::to_owned).collect(),
            purpose: EmbeddingPurpose::Document,
        }
    }

    #[test]
    fn empty_batch_is_rejected() {
        let error = validate_request(&request(vec![]), EmbeddingLimits::default()).unwrap_err();
        assert_eq!(error.code, EmbeddingErrorCode::InvalidRequest);
    }

    #[test]
    fn empty_text_is_rejected() {
        let error =
            validate_request(&request(vec![" \t"]), EmbeddingLimits::default()).unwrap_err();
        assert_eq!(error.code, EmbeddingErrorCode::EmptyText);
    }

    #[test]
    fn batch_limit_is_enforced() {
        let texts = vec!["text"; DEFAULT_MAX_BATCH_SIZE + 1];
        let error = validate_request(&request(texts), EmbeddingLimits::default()).unwrap_err();
        assert_eq!(error.code, EmbeddingErrorCode::BatchLimitExceeded);
    }

    #[test]
    fn text_and_total_limits_are_enforced_without_truncation() {
        let too_long = "x".repeat(DEFAULT_MAX_TEXT_CHARACTERS + 1);
        let error =
            validate_request(&request(vec![&too_long]), EmbeddingLimits::default()).unwrap_err();
        assert_eq!(error.code, EmbeddingErrorCode::TextLimitExceeded);

        let limits = EmbeddingLimits {
            max_batch_size: 2,
            max_text_characters: 3,
            max_total_characters: 3,
        };
        let error = validate_request(&request(vec!["ab", "cd"]), limits).unwrap_err();
        assert_eq!(error.code, EmbeddingErrorCode::TextLimitExceeded);
    }

    #[test]
    fn deterministic_provider_is_repeatable_and_preserves_input_order() {
        let provider = DeterministicEmbeddingProvider::new(4);
        let first =
            tauri::async_runtime::block_on(provider.embed(request(vec!["first", "second"])))
                .unwrap();
        let second =
            tauri::async_runtime::block_on(provider.embed(request(vec!["first", "second"])))
                .unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first
                .vectors
                .iter()
                .map(|vector| vector.input_index)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        assert!(first.vectors.iter().all(|vector| vector.values.len() == 4));
    }

    #[test]
    fn non_finite_vector_values_are_rejected() {
        for invalid_value in [f32::NAN, f32::INFINITY] {
            let response = EmbeddingResponse {
                model_name: "test".into(),
                dimension: 2,
                vectors: vec![EmbeddingVector {
                    input_index: 0,
                    values: vec![invalid_value, 1.0],
                }],
                input_count: 1,
                usage: None,
            };
            let error = validate_response(response, 1, None).unwrap_err();
            assert_eq!(error.code, EmbeddingErrorCode::InvalidProviderResponse);
        }
    }
}
