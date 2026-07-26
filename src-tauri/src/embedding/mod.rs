//! Internal embedding capability for future vector-index work.
//!
//! It deliberately has no Tauri command and no SQLite, LanceDB, file, or memory
//! access. Embeddings are derived data only, never the authority for memory.

mod openai_compatible;
mod protocol;

pub(crate) use openai_compatible::build_openai_compatible_embedding_provider;
#[allow(unused_imports)]
pub(crate) use protocol::{
    EmbeddingBatch, EmbeddingVector, MAX_EMBEDDING_BATCH_MEMORIES, MAX_VECTOR_DIMENSION,
    PROTOCOL_VERSION,
};

use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};

use crate::model::transport::http1::SendDisposition;

pub(crate) type EmbeddingFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddingModelInfo {
    pub model_name: String,
    /// `None` means dimension is not yet known for a non-profile fixture provider.
    pub dimension: Option<usize>,
}

/// Fixed embedding boundary codes. Newer D-9B semantic names map onto these
/// stable variants so out-of-scope call-site matches remain exhaustive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EmbeddingErrorCode {
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct EmbeddingError {
    code: EmbeddingErrorCode,
    recoverable: bool,
    disposition: SendDisposition,
}

impl EmbeddingError {
    pub(crate) const fn definitely_not_sent(code: EmbeddingErrorCode) -> Self {
        Self {
            code,
            recoverable: false,
            disposition: SendDisposition::DefinitelyNotSent,
        }
    }

    pub(crate) const fn possibly_sent(code: EmbeddingErrorCode) -> Self {
        Self {
            code,
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
            recoverable,
            disposition: error.disposition(),
        }
    }

    pub(crate) const fn code(&self) -> EmbeddingErrorCode {
        self.code
    }

    pub(crate) const fn is_recoverable(&self) -> bool {
        self.recoverable
    }

    #[allow(dead_code)]
    pub(crate) const fn send_disposition(&self) -> SendDisposition {
        self.disposition
    }

    const fn safe_message(&self) -> &'static str {
        match self.code {
            EmbeddingErrorCode::InvalidRequest => "Embedding request is invalid.",
            EmbeddingErrorCode::EmptyText => "Embedding text is invalid.",
            EmbeddingErrorCode::BatchLimitExceeded => "Embedding batch is too large.",
            EmbeddingErrorCode::TextLimitExceeded => "Embedding text exceeds limits.",
            EmbeddingErrorCode::NetworkError => "Embedding network operation failed.",
            EmbeddingErrorCode::AuthenticationFailed => "Embedding authentication failed.",
            EmbeddingErrorCode::RateLimited => "Embedding service rate limit was reached.",
            EmbeddingErrorCode::RequestTimeout => "Embedding request timed out.",
            EmbeddingErrorCode::InvalidProviderResponse => {
                "Embedding provider response is invalid."
            }
            EmbeddingErrorCode::DimensionMismatch => "Embedding dimension does not match.",
        }
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
        f.write_str(self.safe_message())
    }
}

impl std::error::Error for EmbeddingError {}

/// Rust-internal provider boundary. Implementations must not persist requests,
/// responses, or vectors; future storage is a separate derived-data concern.
pub(crate) trait EmbeddingProvider: Send + Sync {
    fn model_info(&self) -> EmbeddingModelInfo;
    fn model_name(&self) -> &str;
    fn vector_dimension(&self) -> Option<usize>;
    fn max_batch_size(&self) -> usize {
        MAX_EMBEDDING_BATCH_MEMORIES
    }
    fn embed<'a>(
        &'a self,
        request: EmbeddingRequest,
    ) -> EmbeddingFuture<'a, Result<EmbeddingBatch, EmbeddingError>>;
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
    ) -> EmbeddingFuture<'a, Result<EmbeddingBatch, EmbeddingError>> {
        Box::pin(async move {
            protocol::validate_documents(&request.texts)?;
            protocol::validate_dimension_limits(self.dimension, request.texts.len())?;
            EmbeddingBatch::from_test_vectors(
                request
                    .texts
                    .iter()
                    .map(|text| self.values_for(text))
                    .collect(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::transport::http1::SendDisposition;

    #[test]
    fn error_rendering_is_fixed_and_has_no_source() {
        let error = EmbeddingError::possibly_sent(EmbeddingErrorCode::InvalidProviderResponse);
        for canary in ["API_KEY_CANARY", "DOCUMENT_CANARY", "RESPONSE_BODY_CANARY"] {
            assert!(!format!("{error:?}").contains(canary));
            assert!(!error.to_string().contains(canary));
        }
        assert!(std::error::Error::source(&error).is_none());
        assert_eq!(error.send_disposition(), SendDisposition::PossiblySent);
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
                .vectors()
                .iter()
                .map(|vector| vector.input_index())
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
    }
}
