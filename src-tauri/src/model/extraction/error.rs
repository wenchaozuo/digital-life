use std::fmt;

use crate::model::{provider::ProviderError, transport::http1::SendDisposition};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LlmExtractionErrorKind {
    DescriptorUnavailable,
    DescriptorVersionMismatch,
    ProfilePurposeInvalid,
    ExtractionInputInvalid,
    ExtractionRequestTooLarge,
    ProviderFailure,
    ProviderEnvelopeInvalid,
    ProviderContentMissing,
    ProviderContentUnsupported,
    ExtractionJsonInvalid,
    ExtractionSchemaInvalid,
    ExtractionCandidateLimitExceeded,
    ExtractionFieldLimitExceeded,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct LlmExtractionError {
    kind: LlmExtractionErrorKind,
    disposition: SendDisposition,
}

impl LlmExtractionError {
    pub(crate) const fn new(kind: LlmExtractionErrorKind, disposition: SendDisposition) -> Self {
        Self { kind, disposition }
    }

    pub(crate) const fn definitely_not_sent(kind: LlmExtractionErrorKind) -> Self {
        Self {
            kind,
            disposition: SendDisposition::DefinitelyNotSent,
        }
    }

    pub(crate) const fn possibly_sent(kind: LlmExtractionErrorKind) -> Self {
        Self {
            kind,
            disposition: SendDisposition::PossiblySent,
        }
    }

    pub(crate) const fn from_provider_error(err: ProviderError) -> Self {
        Self {
            kind: LlmExtractionErrorKind::ProviderFailure,
            disposition: err.disposition(),
        }
    }

    pub(crate) const fn kind(&self) -> LlmExtractionErrorKind {
        self.kind
    }

    pub(crate) const fn disposition(&self) -> SendDisposition {
        self.disposition
    }
}

impl fmt::Display for LlmExtractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self.kind {
            LlmExtractionErrorKind::DescriptorUnavailable => {
                "The extraction descriptor is unavailable."
            }
            LlmExtractionErrorKind::DescriptorVersionMismatch => {
                "The extraction descriptor version mismatch."
            }
            LlmExtractionErrorKind::ProfilePurposeInvalid => {
                "The model profile purpose is not valid for extraction."
            }
            LlmExtractionErrorKind::ExtractionInputInvalid => {
                "The extraction input is invalid or out of bounds."
            }
            LlmExtractionErrorKind::ExtractionRequestTooLarge => {
                "The extraction request exceeds body limits."
            }
            LlmExtractionErrorKind::ProviderFailure => "The provider call failed.",
            LlmExtractionErrorKind::ProviderEnvelopeInvalid => {
                "The provider response envelope is invalid."
            }
            LlmExtractionErrorKind::ProviderContentMissing => {
                "The provider response content is missing."
            }
            LlmExtractionErrorKind::ProviderContentUnsupported => {
                "The provider response content format is unsupported."
            }
            LlmExtractionErrorKind::ExtractionJsonInvalid => {
                "The extracted model content is not valid JSON."
            }
            LlmExtractionErrorKind::ExtractionSchemaInvalid => {
                "The extracted model JSON does not match the schema."
            }
            LlmExtractionErrorKind::ExtractionCandidateLimitExceeded => {
                "The extracted candidate count exceeds the maximum limit."
            }
            LlmExtractionErrorKind::ExtractionFieldLimitExceeded => {
                "An extracted candidate field exceeds maximum length."
            }
        };
        f.write_str(msg)
    }
}

impl fmt::Debug for LlmExtractionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LlmExtractionError")
            .field("kind", &self.kind)
            .field("disposition", &self.disposition)
            .finish()
    }
}

impl std::error::Error for LlmExtractionError {}
