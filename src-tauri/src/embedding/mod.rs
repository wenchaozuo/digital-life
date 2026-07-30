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

use crate::model::{
    provider::{ProviderCredentialError, ProviderErrorKind, ProviderResponseClass},
    transport::http1::SendDisposition,
};

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

/// Evidence retained for retry policy without exposing provider response data
/// or transport internals to consumers of the embedding boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EmbeddingRetrySafety {
    DefinitelyNotSent,
    ResponseReceived,
    PossiblySent,
}

/// Stable origin categories used by the bounded vector-sync retry policy.
/// They contain no credential reference, endpoint, request payload, response
/// body, or embedding vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EmbeddingRetryClass {
    InvalidRequest,
    CredentialNotConfigured,
    CredentialUnavailable,
    CredentialReadFailed,
    TransportUnavailable,
    RequestTimeout,
    RateLimited,
    AuthenticationRejected,
    OtherClientError,
    ProviderUnavailable,
    InvalidProviderResponse,
    DimensionMismatch,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct EmbeddingError {
    code: EmbeddingErrorCode,
    recoverable: bool,
    disposition: SendDisposition,
    retry_safety: EmbeddingRetrySafety,
    retry_class: EmbeddingRetryClass,
}

impl EmbeddingError {
    pub(crate) const fn definitely_not_sent(code: EmbeddingErrorCode) -> Self {
        Self {
            code,
            recoverable: false,
            disposition: SendDisposition::DefinitelyNotSent,
            retry_safety: EmbeddingRetrySafety::DefinitelyNotSent,
            retry_class: retry_class_for_code(code),
        }
    }

    pub(crate) const fn possibly_sent(code: EmbeddingErrorCode) -> Self {
        Self {
            code,
            recoverable: true,
            disposition: SendDisposition::PossiblySent,
            retry_safety: retry_safety_for_complete_embedding_result(code),
            retry_class: retry_class_for_code(code),
        }
    }

    pub(crate) fn from_provider_error(error: crate::model::provider::ProviderError) -> Self {
        let (code, recoverable, retry_class) = match error.response_class() {
            Some(response_class) => match response_class {
                ProviderResponseClass::RequestTimeout => (
                    EmbeddingErrorCode::RequestTimeout,
                    true,
                    EmbeddingRetryClass::RequestTimeout,
                ),
                ProviderResponseClass::RateLimited => (
                    EmbeddingErrorCode::RateLimited,
                    true,
                    EmbeddingRetryClass::RateLimited,
                ),
                ProviderResponseClass::AuthenticationRejected => (
                    EmbeddingErrorCode::AuthenticationFailed,
                    false,
                    EmbeddingRetryClass::AuthenticationRejected,
                ),
                ProviderResponseClass::OtherClientError => (
                    EmbeddingErrorCode::NetworkError,
                    true,
                    EmbeddingRetryClass::OtherClientError,
                ),
                ProviderResponseClass::ServerError => (
                    EmbeddingErrorCode::NetworkError,
                    true,
                    EmbeddingRetryClass::ProviderUnavailable,
                ),
                ProviderResponseClass::InvalidResponse => (
                    EmbeddingErrorCode::NetworkError,
                    true,
                    EmbeddingRetryClass::InvalidProviderResponse,
                ),
            },
            None => match error.kind() {
                ProviderErrorKind::Credential(ProviderCredentialError::NotConfigured) => {
                    // Missing embedding credential: blocked-class at worker via AuthenticationFailed.
                    (
                        EmbeddingErrorCode::AuthenticationFailed,
                        false,
                        EmbeddingRetryClass::CredentialNotConfigured,
                    )
                }
                ProviderErrorKind::Credential(ProviderCredentialError::Unavailable) => (
                    EmbeddingErrorCode::NetworkError,
                    true,
                    EmbeddingRetryClass::CredentialUnavailable,
                ),
                ProviderErrorKind::Credential(ProviderCredentialError::ReadFailed) => (
                    EmbeddingErrorCode::NetworkError,
                    true,
                    EmbeddingRetryClass::CredentialReadFailed,
                ),
                ProviderErrorKind::TransportTimeout => (
                    EmbeddingErrorCode::RequestTimeout,
                    true,
                    EmbeddingRetryClass::RequestTimeout,
                ),
                ProviderErrorKind::TransportUnavailable
                | ProviderErrorKind::ResponseRejected
                | ProviderErrorKind::ResponseTooLarge => (
                    EmbeddingErrorCode::NetworkError,
                    true,
                    EmbeddingRetryClass::TransportUnavailable,
                ),
                ProviderErrorKind::InvalidConfiguration
                | ProviderErrorKind::InvalidJsonRequest
                | ProviderErrorKind::RequestTooLarge
                | ProviderErrorKind::RequestRejected => (
                    EmbeddingErrorCode::InvalidRequest,
                    false,
                    EmbeddingRetryClass::InvalidRequest,
                ),
                ProviderErrorKind::AuthenticationRejected
                | ProviderErrorKind::RemoteTimeoutResponse
                | ProviderErrorKind::RateLimited
                | ProviderErrorKind::ProviderUnavailable
                | ProviderErrorKind::UnexpectedStatus => {
                    unreachable!("response classes are exhaustive")
                }
            },
        };
        Self {
            code,
            recoverable,
            disposition: error.disposition(),
            retry_safety: match error.response_class() {
                Some(_) => EmbeddingRetrySafety::ResponseReceived,
                None => retry_safety_from_disposition(error.disposition()),
            },
            retry_class,
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

    #[allow(dead_code)]
    pub(crate) const fn retry_safety(&self) -> EmbeddingRetrySafety {
        self.retry_safety
    }

    #[allow(dead_code)]
    pub(crate) const fn retry_class(&self) -> EmbeddingRetryClass {
        self.retry_class
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
            .field("retry_safety", &self.retry_safety)
            .field("retry_class", &self.retry_class)
            .finish()
    }
}

const fn retry_safety_from_disposition(disposition: SendDisposition) -> EmbeddingRetrySafety {
    match disposition {
        SendDisposition::DefinitelyNotSent => EmbeddingRetrySafety::DefinitelyNotSent,
        SendDisposition::PossiblySent => EmbeddingRetrySafety::PossiblySent,
    }
}

const fn retry_safety_for_complete_embedding_result(
    code: EmbeddingErrorCode,
) -> EmbeddingRetrySafety {
    match code {
        EmbeddingErrorCode::InvalidProviderResponse | EmbeddingErrorCode::DimensionMismatch => {
            EmbeddingRetrySafety::ResponseReceived
        }
        _ => EmbeddingRetrySafety::PossiblySent,
    }
}

const fn retry_class_for_code(code: EmbeddingErrorCode) -> EmbeddingRetryClass {
    match code {
        EmbeddingErrorCode::InvalidRequest
        | EmbeddingErrorCode::EmptyText
        | EmbeddingErrorCode::BatchLimitExceeded
        | EmbeddingErrorCode::TextLimitExceeded => EmbeddingRetryClass::InvalidRequest,
        EmbeddingErrorCode::NetworkError => EmbeddingRetryClass::TransportUnavailable,
        EmbeddingErrorCode::AuthenticationFailed => EmbeddingRetryClass::AuthenticationRejected,
        EmbeddingErrorCode::RateLimited => EmbeddingRetryClass::RateLimited,
        EmbeddingErrorCode::RequestTimeout => EmbeddingRetryClass::RequestTimeout,
        EmbeddingErrorCode::InvalidProviderResponse => EmbeddingRetryClass::InvalidProviderResponse,
        EmbeddingErrorCode::DimensionMismatch => EmbeddingRetryClass::DimensionMismatch,
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
        assert_eq!(error.retry_safety(), EmbeddingRetrySafety::ResponseReceived);
        assert_eq!(
            error.retry_class(),
            EmbeddingRetryClass::InvalidProviderResponse
        );
    }

    #[test]
    fn embedding_retry_classification_preserves_structured_provider_evidence() {
        use crate::model::provider::{ProviderCredentialError, ProviderError, ProviderErrorKind};

        let cases = [
            (
                ProviderError::definitely_not_sent(ProviderErrorKind::Credential(
                    ProviderCredentialError::NotConfigured,
                )),
                EmbeddingRetrySafety::DefinitelyNotSent,
                EmbeddingRetryClass::CredentialNotConfigured,
            ),
            (
                ProviderError::definitely_not_sent(ProviderErrorKind::Credential(
                    ProviderCredentialError::Unavailable,
                )),
                EmbeddingRetrySafety::DefinitelyNotSent,
                EmbeddingRetryClass::CredentialUnavailable,
            ),
            (
                ProviderError::definitely_not_sent(ProviderErrorKind::Credential(
                    ProviderCredentialError::ReadFailed,
                )),
                EmbeddingRetrySafety::DefinitelyNotSent,
                EmbeddingRetryClass::CredentialReadFailed,
            ),
            (
                ProviderError::definitely_not_sent(ProviderErrorKind::TransportUnavailable),
                EmbeddingRetrySafety::DefinitelyNotSent,
                EmbeddingRetryClass::TransportUnavailable,
            ),
            (
                ProviderError::from_status(ProviderErrorKind::RemoteTimeoutResponse, 408),
                EmbeddingRetrySafety::ResponseReceived,
                EmbeddingRetryClass::RequestTimeout,
            ),
            (
                ProviderError::from_status(ProviderErrorKind::RateLimited, 429),
                EmbeddingRetrySafety::ResponseReceived,
                EmbeddingRetryClass::RateLimited,
            ),
            (
                ProviderError::from_status(ProviderErrorKind::AuthenticationRejected, 401),
                EmbeddingRetrySafety::ResponseReceived,
                EmbeddingRetryClass::AuthenticationRejected,
            ),
            (
                ProviderError::from_status(ProviderErrorKind::RequestRejected, 422),
                EmbeddingRetrySafety::ResponseReceived,
                EmbeddingRetryClass::OtherClientError,
            ),
            (
                ProviderError::from_status(ProviderErrorKind::ProviderUnavailable, 503),
                EmbeddingRetrySafety::ResponseReceived,
                EmbeddingRetryClass::ProviderUnavailable,
            ),
        ];

        for (provider_error, expected_safety, expected_class) in cases {
            let error = EmbeddingError::from_provider_error(provider_error);
            assert_eq!(error.retry_safety(), expected_safety);
            assert_eq!(error.retry_class(), expected_class);
        }
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
