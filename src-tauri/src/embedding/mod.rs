//! Internal embedding capability for future vector-index work.
//!
//! It deliberately has no Tauri command and no SQLite, LanceDB, file, or memory
//! access. Embeddings are derived data only, never the authority for memory.

mod openai_compatible;
mod protocol;

pub(crate) use openai_compatible::build_openai_compatible_embedding_provider;
pub use openai_compatible::OpenAiCompatibleEmbeddingProvider;
#[allow(unused_imports)]
pub(crate) use protocol::{
    EmbeddingBatch, MAX_EMBEDDING_BATCH_MEMORIES, MAX_VECTOR_DIMENSION, PROTOCOL_VERSION,
};

use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};

use crate::model::transport::http1::SendDisposition;

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
    /// `None` means dimension is not yet known for a non-profile fixture provider.
    pub dimension: Option<usize>,
}

/// Fixed embedding boundary codes. Newer D-9B semantic names map onto these
/// stable variants so out-of-scope call-site matches remain exhaustive.
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
    RequestTimeout,
    InvalidProviderResponse,
    DimensionMismatch,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EmbeddingError {
    pub code: EmbeddingErrorCode,
    pub message: String,
    pub recoverable: bool,
    disposition: SendDisposition,
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
            disposition: if recoverable {
                SendDisposition::PossiblySent
            } else {
                SendDisposition::DefinitelyNotSent
            },
        }
    }

    pub(crate) fn definitely_not_sent(
        code: EmbeddingErrorCode,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable: false,
            disposition: SendDisposition::DefinitelyNotSent,
        }
    }

    pub(crate) fn possibly_sent(code: EmbeddingErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable: true,
            disposition: SendDisposition::PossiblySent,
        }
    }

    pub(crate) fn from_provider_error(error: crate::model::provider::ProviderError) -> Self {
        use crate::model::provider::{ProviderCredentialError, ProviderErrorKind};
        let (code, recoverable) = match error.kind() {
            ProviderErrorKind::Credential(ProviderCredentialError::NotConfigured) => {
                // Missing embedding credential: blocked-class at worker via AuthenticationFailed.
                (EmbeddingErrorCode::AuthenticationFailed, false)
            }
            ProviderErrorKind::AuthenticationRejected => {
                (EmbeddingErrorCode::AuthenticationFailed, false)
            }
            ProviderErrorKind::RateLimited => (EmbeddingErrorCode::RateLimited, true),
            ProviderErrorKind::TransportTimeout | ProviderErrorKind::RemoteTimeoutResponse => {
                (EmbeddingErrorCode::RequestTimeout, true)
            }
            ProviderErrorKind::TransportUnavailable
            | ProviderErrorKind::ProviderUnavailable
            | ProviderErrorKind::UnexpectedStatus
            | ProviderErrorKind::ResponseRejected
            | ProviderErrorKind::ResponseTooLarge
            | ProviderErrorKind::RequestRejected
            | ProviderErrorKind::Credential(_) => (EmbeddingErrorCode::NetworkError, true),
            ProviderErrorKind::InvalidConfiguration
            | ProviderErrorKind::InvalidJsonRequest
            | ProviderErrorKind::RequestTooLarge => (EmbeddingErrorCode::InvalidRequest, false),
        };
        Self {
            code,
            message: error.to_string(),
            recoverable,
            disposition: error.disposition(),
        }
    }

    #[allow(dead_code)]
    pub(crate) const fn disposition(&self) -> SendDisposition {
        self.disposition
    }
}

impl std::fmt::Debug for EmbeddingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingError")
            .field("code", &self.code)
            .field("recoverable", &self.recoverable)
            .field("disposition", &self.disposition)
            .finish()
    }
}

impl std::fmt::Display for EmbeddingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EmbeddingError {}

impl Serialize for EmbeddingError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("EmbeddingError", 3)?;
        state.serialize_field("code", &self.code)?;
        state.serialize_field("message", &self.message)?;
        state.serialize_field("recoverable", &self.recoverable)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for EmbeddingError {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            code: EmbeddingErrorCode,
            message: String,
            recoverable: bool,
        }
        let wire = Wire::deserialize(deserializer)?;
        Ok(Self::new(wire.code, wire.message, wire.recoverable))
    }
}

/// Rust-internal provider boundary. Implementations must not persist requests,
/// responses, or vectors; future storage is a separate derived-data concern.
pub trait EmbeddingProvider: Send + Sync {
    fn model_info(&self) -> EmbeddingModelInfo;
    fn model_name(&self) -> &str;
    fn vector_dimension(&self) -> Option<usize>;
    fn max_batch_size(&self) -> usize {
        MAX_EMBEDDING_BATCH_MEMORIES
    }
    fn embed<'a>(
        &'a self,
        request: EmbeddingRequest,
    ) -> EmbeddingFuture<'a, Result<EmbeddingResponse, EmbeddingError>>;
}

#[cfg(test)]
pub(crate) struct DeterministicEmbeddingProvider {
    model_name: String,
    dimension: usize,
}

#[cfg(test)]
impl DeterministicEmbeddingProvider {
    pub(crate) fn new(dimension: usize) -> Self {
        assert!(dimension > 0, "test provider dimension must be positive");
        Self {
            model_name: "deterministic-test-embedding".into(),
            dimension,
        }
    }

    fn values_for(&self, text: &str) -> Vec<f32> {
        let mut state = 0x811c_9dc5u32;
        for byte in text.as_bytes() {
            state ^= u32::from(*byte);
            state = state.wrapping_mul(0x0100_0193);
        }
        (0..self.dimension)
            .map(|index| {
                state ^= index as u32;
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let value = state as f32 / u32::MAX as f32;
                if value == 0.0 {
                    1.0
                } else {
                    value
                }
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
        MAX_EMBEDDING_BATCH_MEMORIES
    }

    fn embed<'a>(
        &'a self,
        request: EmbeddingRequest,
    ) -> EmbeddingFuture<'a, Result<EmbeddingResponse, EmbeddingError>> {
        Box::pin(async move {
            protocol::validate_documents(&request.texts)?;
            protocol::validate_dimension_limits(self.dimension, request.texts.len())?;
            let input_count = request.texts.len();
            Ok(EmbeddingResponse {
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
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::transport::http1::SendDisposition;

    #[test]
    fn error_debug_omits_message_payload() {
        let canary = "CANARY_SECRET_PAYLOAD";
        let error =
            EmbeddingError::possibly_sent(EmbeddingErrorCode::InvalidProviderResponse, canary);
        assert!(!format!("{error:?}").contains(canary));
        assert_eq!(error.disposition(), SendDisposition::PossiblySent);
    }

    #[test]
    fn deterministic_provider_is_repeatable_and_preserves_input_order() {
        let provider = DeterministicEmbeddingProvider::new(4);
        let request = EmbeddingRequest {
            texts: vec!["first".into(), "second".into()],
            purpose: EmbeddingPurpose::Document,
        };
        let first = tauri::async_runtime::block_on(provider.embed(request.clone())).unwrap();
        let second = tauri::async_runtime::block_on(provider.embed(request)).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first
                .vectors
                .iter()
                .map(|vector| vector.input_index)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
    }
}
