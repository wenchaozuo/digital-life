//! Strict openai-compatible-embedding-v1 request/response protocol.

use serde::{Deserialize, Serialize};

use crate::model::provider::ProviderJsonRequest;

#[cfg(test)]
use crate::model::transport::http1::SendDisposition;

use super::{
    EmbeddingError, EmbeddingErrorCode, EmbeddingResponse, EmbeddingVector as PublicEmbeddingVector,
};

pub(crate) const PROTOCOL_VERSION: &str = "openai-compatible-embedding-v1";
pub(crate) const MAX_EMBEDDING_BATCH_MEMORIES: usize = 32;
pub(crate) const MAX_CANONICAL_DOCUMENT_UTF8_BYTES: usize = 131_072;
pub(crate) const MAX_BATCH_INPUT_UTF8_BYTES: usize = 196_608;
pub(crate) const MAX_SERIALIZED_REQUEST_BYTES: usize = 262_144;
pub(crate) const MAX_RESPONSE_BODY_BYTES: usize = 1_048_576;
pub(crate) const MAX_VECTOR_DIMENSION: usize = 4_096;
pub(crate) const MAX_RESPONSE_FLOATS: usize = 65_536;

#[derive(Serialize)]
struct EmbeddingRequestDto<'a> {
    model: &'a str,
    input: &'a [String],
    encoding_format: &'static str,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingEnvelopeDto {
    object: String,
    data: Vec<EmbeddingDataItemDto>,
    model: String,
    #[serde(default)]
    usage: Option<EmbeddingUsageDto>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingDataItemDto {
    object: String,
    index: u64,
    embedding: Vec<f64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmbeddingUsageDto {
    prompt_tokens: u64,
    total_tokens: u64,
}

/// Controlled successful batch. Fields are private; Debug never prints floats.
pub(crate) struct EmbeddingBatch {
    vectors: Vec<Vec<f32>>,
    dimension: usize,
}

impl EmbeddingBatch {
    #[allow(dead_code)]
    pub(crate) fn dimension(&self) -> usize {
        self.dimension
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.vectors.len()
    }

    #[allow(dead_code)]
    pub(crate) fn vectors(&self) -> &[Vec<f32>] {
        &self.vectors
    }

    pub(crate) fn into_public_response(self, model_name: String) -> EmbeddingResponse {
        let input_count = self.vectors.len();
        EmbeddingResponse {
            model_name,
            dimension: self.dimension,
            vectors: self
                .vectors
                .into_iter()
                .enumerate()
                .map(|(input_index, values)| PublicEmbeddingVector {
                    input_index,
                    values,
                })
                .collect(),
            input_count,
            usage: None,
        }
    }
}

impl std::fmt::Debug for EmbeddingBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmbeddingBatch")
            .field("vector_count", &self.vectors.len())
            .field("dimension", &self.dimension)
            .finish()
    }
}

pub(crate) fn validate_documents(documents: &[String]) -> Result<(), EmbeddingError> {
    if documents.is_empty() {
        return Err(EmbeddingError::definitely_not_sent(
            EmbeddingErrorCode::InvalidRequest,
            "An embedding batch must contain at least one document.",
        ));
    }
    if documents.len() > MAX_EMBEDDING_BATCH_MEMORIES {
        return Err(EmbeddingError::definitely_not_sent(
            EmbeddingErrorCode::BatchLimitExceeded,
            "The embedding batch exceeds the maximum memory count.",
        ));
    }

    let mut total_bytes = 0usize;
    for document in documents {
        if document.is_empty() || document.chars().all(char::is_whitespace) {
            return Err(EmbeddingError::definitely_not_sent(
                EmbeddingErrorCode::EmptyText,
                "Embedding documents must not be empty or whitespace only.",
            ));
        }
        let bytes = document.len();
        if bytes > MAX_CANONICAL_DOCUMENT_UTF8_BYTES {
            return Err(EmbeddingError::definitely_not_sent(
                EmbeddingErrorCode::TextLimitExceeded,
                "An embedding document exceeds the UTF-8 byte limit.",
            ));
        }
        total_bytes = total_bytes.saturating_add(bytes);
        if total_bytes > MAX_BATCH_INPUT_UTF8_BYTES {
            return Err(EmbeddingError::definitely_not_sent(
                EmbeddingErrorCode::TextLimitExceeded,
                "The embedding batch exceeds the total UTF-8 byte limit.",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_dimension_limits(
    dimension: usize,
    batch_len: usize,
) -> Result<(), EmbeddingError> {
    if dimension == 0 || dimension > MAX_VECTOR_DIMENSION {
        return Err(EmbeddingError::definitely_not_sent(
            EmbeddingErrorCode::InvalidRequest,
            "The embedding dimension is invalid.",
        ));
    }
    let float_count = batch_len.saturating_mul(dimension);
    if float_count > MAX_RESPONSE_FLOATS {
        return Err(EmbeddingError::definitely_not_sent(
            EmbeddingErrorCode::InvalidRequest,
            "The embedding float budget is exceeded.",
        ));
    }
    Ok(())
}

pub(crate) fn build_provider_request(
    model_name: &str,
    documents: &[String],
) -> Result<ProviderJsonRequest, EmbeddingError> {
    let dto = EmbeddingRequestDto {
        model: model_name,
        input: documents,
        encoding_format: "float",
    };
    let body = serde_json::to_vec(&dto).map_err(|_| {
        EmbeddingError::definitely_not_sent(
            EmbeddingErrorCode::InvalidRequest,
            "The embedding request could not be serialized.",
        )
    })?;
    if body.len() > MAX_SERIALIZED_REQUEST_BYTES {
        return Err(EmbeddingError::definitely_not_sent(
            EmbeddingErrorCode::InvalidRequest,
            "The embedding request exceeds the serialized size limit.",
        ));
    }
    ProviderJsonRequest::new(body).map_err(|error| match error.kind() {
        crate::model::provider::ProviderErrorKind::RequestTooLarge
        | crate::model::provider::ProviderErrorKind::InvalidJsonRequest => {
            EmbeddingError::definitely_not_sent(
                EmbeddingErrorCode::InvalidRequest,
                "The embedding request exceeds the transport limit.",
            )
        }
        _ => EmbeddingError::from_provider_error(error),
    })
}

pub(crate) fn decode_response_envelope(
    body: &[u8],
    expected_model: &str,
    expected_count: usize,
    expected_dimension: usize,
) -> Result<EmbeddingBatch, EmbeddingError> {
    if body.is_empty() || body.len() > MAX_RESPONSE_BODY_BYTES {
        return Err(EmbeddingError::possibly_sent(
            EmbeddingErrorCode::InvalidProviderResponse,
            "The embedding response envelope is invalid.",
        ));
    }

    let envelope: EmbeddingEnvelopeDto = serde_json::from_slice(body).map_err(|_| {
        EmbeddingError::possibly_sent(
            EmbeddingErrorCode::InvalidProviderResponse,
            "The embedding response envelope is invalid.",
        )
    })?;

    if envelope.object != "list" {
        return Err(EmbeddingError::possibly_sent(
            EmbeddingErrorCode::InvalidProviderResponse,
            "The embedding response object is invalid.",
        ));
    }
    if envelope.model != expected_model {
        return Err(EmbeddingError::possibly_sent(
            EmbeddingErrorCode::InvalidProviderResponse,
            "The embedding response model does not match the request.",
        ));
    }
    if let Some(usage) = envelope.usage.as_ref() {
        if usage.total_tokens < usage.prompt_tokens {
            return Err(EmbeddingError::possibly_sent(
                EmbeddingErrorCode::InvalidProviderResponse,
                "The embedding response usage is invalid.",
            ));
        }
    }
    if envelope.data.len() != expected_count {
        return Err(EmbeddingError::possibly_sent(
            EmbeddingErrorCode::InvalidProviderResponse,
            "The embedding response count does not match the request.",
        ));
    }

    let mut slots: Vec<Option<Vec<f32>>> = vec![None; expected_count];
    let mut total_floats = 0usize;

    for item in envelope.data {
        if item.object != "embedding" {
            return Err(EmbeddingError::possibly_sent(
                EmbeddingErrorCode::InvalidProviderResponse,
                "The embedding response item object is invalid.",
            ));
        }
        let index = usize::try_from(item.index).map_err(|_| {
            EmbeddingError::possibly_sent(
                EmbeddingErrorCode::InvalidProviderResponse,
                "The embedding response index is invalid.",
            )
        })?;
        if index >= expected_count {
            return Err(EmbeddingError::possibly_sent(
                EmbeddingErrorCode::InvalidProviderResponse,
                "The embedding response index is out of range.",
            ));
        }
        if slots[index].is_some() {
            return Err(EmbeddingError::possibly_sent(
                EmbeddingErrorCode::InvalidProviderResponse,
                "The embedding response contains a duplicate index.",
            ));
        }
        if item.embedding.is_empty() {
            return Err(EmbeddingError::possibly_sent(
                EmbeddingErrorCode::InvalidProviderResponse,
                "The embedding response vector is empty.",
            ));
        }
        if item.embedding.len() != expected_dimension {
            return Err(EmbeddingError::possibly_sent(
                EmbeddingErrorCode::DimensionMismatch,
                "The embedding response dimension does not match the profile.",
            ));
        }
        total_floats = total_floats.saturating_add(item.embedding.len());
        if total_floats > MAX_RESPONSE_FLOATS {
            return Err(EmbeddingError::possibly_sent(
                EmbeddingErrorCode::InvalidProviderResponse,
                "The embedding response exceeds the float budget.",
            ));
        }

        let mut values = Vec::with_capacity(item.embedding.len());
        let mut all_zero = true;
        for value in item.embedding {
            if !value.is_finite() {
                return Err(EmbeddingError::possibly_sent(
                    EmbeddingErrorCode::InvalidProviderResponse,
                    "The embedding response contains a non-finite value.",
                ));
            }
            let mapped = value as f32;
            if !mapped.is_finite() {
                return Err(EmbeddingError::possibly_sent(
                    EmbeddingErrorCode::InvalidProviderResponse,
                    "The embedding response contains a value outside f32 range.",
                ));
            }
            if mapped != 0.0 {
                all_zero = false;
            }
            values.push(mapped);
        }
        if all_zero {
            return Err(EmbeddingError::possibly_sent(
                EmbeddingErrorCode::InvalidProviderResponse,
                "The embedding response contains an all-zero vector.",
            ));
        }
        slots[index] = Some(values);
    }

    let mut vectors = Vec::with_capacity(expected_count);
    for slot in slots {
        match slot {
            Some(values) => vectors.push(values),
            None => {
                return Err(EmbeddingError::possibly_sent(
                    EmbeddingErrorCode::InvalidProviderResponse,
                    "The embedding response is missing an index.",
                ));
            }
        }
    }

    Ok(EmbeddingBatch {
        vectors,
        dimension: expected_dimension,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_dto_is_strict_and_bounded() {
        let docs = vec!["alpha".to_string(), "beta".to_string()];
        validate_documents(&docs).unwrap();
        let request = build_provider_request("model-a", &docs).unwrap();
        let raw = serde_json::to_vec(&EmbeddingRequestDto {
            model: "model-a",
            input: &docs,
            encoding_format: "float",
        })
        .unwrap();
        let body = String::from_utf8_lossy(&raw);
        assert!(body.contains(r#""encoding_format":"float""#));
        assert!(body.contains(r#""model":"model-a""#));
        assert!(!body.contains("dimensions"));
        assert!(!body.contains("stream"));
        assert!(!body.contains("tools"));
        assert!(!body.contains("user"));
        let _ = request;
    }

    #[test]
    fn document_limits_are_enforced_before_any_network() {
        assert_eq!(
            validate_documents(&[]).unwrap_err().code,
            EmbeddingErrorCode::InvalidRequest
        );
        assert_eq!(
            validate_documents(&[String::new()]).unwrap_err().code,
            EmbeddingErrorCode::EmptyText
        );
        assert_eq!(
            validate_documents(&[" \t".into()]).unwrap_err().code,
            EmbeddingErrorCode::EmptyText
        );
        let too_many = vec!["x".to_string(); MAX_EMBEDDING_BATCH_MEMORIES + 1];
        assert_eq!(
            validate_documents(&too_many).unwrap_err().code,
            EmbeddingErrorCode::BatchLimitExceeded
        );
        let too_long = "a".repeat(MAX_CANONICAL_DOCUMENT_UTF8_BYTES + 1);
        assert_eq!(
            validate_documents(&[too_long]).unwrap_err().code,
            EmbeddingErrorCode::TextLimitExceeded
        );
        let boundary = "a".repeat(MAX_CANONICAL_DOCUMENT_UTF8_BYTES);
        validate_documents(&[boundary]).unwrap();
    }

    #[test]
    fn decode_restores_order_and_rejects_invalid_vectors() {
        let body = br#"{
            "object":"list",
            "model":"m",
            "data":[
                {"object":"embedding","index":1,"embedding":[0.0,1.0]},
                {"object":"embedding","index":0,"embedding":[1.0,0.0]}
            ]
        }"#;
        let batch = decode_response_envelope(body, "m", 2, 2).unwrap();
        assert_eq!(batch.vectors()[0], vec![1.0, 0.0]);
        assert_eq!(batch.vectors()[1], vec![0.0, 1.0]);
        assert!(!format!("{batch:?}").contains("1.0"));

        let zero = br#"{
            "object":"list","model":"m",
            "data":[{"object":"embedding","index":0,"embedding":[0.0,0.0]}]
        }"#;
        assert_eq!(
            decode_response_envelope(zero, "m", 1, 2).unwrap_err().code,
            EmbeddingErrorCode::InvalidProviderResponse
        );
    }

    #[test]
    fn unknown_fields_and_model_mismatch_are_possibly_sent() {
        let unknown = br#"{"object":"list","model":"m","data":[],"extra":1}"#;
        let err = decode_response_envelope(unknown, "m", 0, 1).unwrap_err();
        assert_eq!(err.disposition(), SendDisposition::PossiblySent);

        let mismatch = br#"{
            "object":"list","model":"other",
            "data":[{"object":"embedding","index":0,"embedding":[1.0]}]
        }"#;
        assert_eq!(
            decode_response_envelope(mismatch, "m", 1, 1)
                .unwrap_err()
                .code,
            EmbeddingErrorCode::InvalidProviderResponse
        );
    }
}
