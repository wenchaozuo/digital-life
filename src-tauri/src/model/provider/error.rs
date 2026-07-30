use std::fmt;

use crate::{
    model::transport::http1::{Http1ErrorKind, Http1TransportError, SendDisposition},
    secrets::SecretStoreErrorCode,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderCredentialError {
    NotConfigured,
    Unavailable,
    ReadFailed,
}

/// A redacted, stable classification for a complete provider response.  It
/// deliberately retains neither the response body nor the raw status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderResponseClass {
    RequestTimeout,
    RateLimited,
    AuthenticationRejected,
    OtherClientError,
    ServerError,
    InvalidResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProviderErrorKind {
    InvalidConfiguration,
    InvalidJsonRequest,
    RequestTooLarge,
    RequestRejected,
    Credential(ProviderCredentialError),
    TransportUnavailable,
    TransportTimeout,
    ResponseRejected,
    ResponseTooLarge,
    AuthenticationRejected,
    RemoteTimeoutResponse,
    RateLimited,
    ProviderUnavailable,
    UnexpectedStatus,
}

/// A fixed provider-boundary error. It contains no secret, endpoint, request,
/// response, credential reference, or lower-level error material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProviderError {
    kind: ProviderErrorKind,
    disposition: SendDisposition,
    status: Option<u16>,
}

impl ProviderError {
    pub(crate) const fn kind(self) -> ProviderErrorKind {
        self.kind
    }

    pub(crate) const fn disposition(self) -> SendDisposition {
        self.disposition
    }

    pub(crate) const fn status(self) -> Option<u16> {
        self.status
    }

    pub(crate) const fn response_class(self) -> Option<ProviderResponseClass> {
        match self.kind {
            ProviderErrorKind::RemoteTimeoutResponse => Some(ProviderResponseClass::RequestTimeout),
            ProviderErrorKind::RateLimited => Some(ProviderResponseClass::RateLimited),
            ProviderErrorKind::AuthenticationRejected => {
                Some(ProviderResponseClass::AuthenticationRejected)
            }
            ProviderErrorKind::ProviderUnavailable => Some(ProviderResponseClass::ServerError),
            ProviderErrorKind::RequestRejected if self.status.is_some() => {
                Some(ProviderResponseClass::OtherClientError)
            }
            ProviderErrorKind::UnexpectedStatus => Some(ProviderResponseClass::InvalidResponse),
            _ => None,
        }
    }

    pub(crate) const fn definitely_not_sent(kind: ProviderErrorKind) -> Self {
        Self {
            kind,
            disposition: SendDisposition::DefinitelyNotSent,
            status: None,
        }
    }

    pub(crate) const fn from_status(kind: ProviderErrorKind, status: u16) -> Self {
        Self {
            kind,
            disposition: SendDisposition::PossiblySent,
            status: Some(status),
        }
    }

    pub(super) const fn from_transport(error: Http1TransportError) -> Self {
        let kind = match error.kind() {
            Http1ErrorKind::RequestTooLarge => ProviderErrorKind::RequestTooLarge,
            Http1ErrorKind::RequestHeaderRejected | Http1ErrorKind::InvalidRequestTarget => {
                ProviderErrorKind::RequestRejected
            }
            Http1ErrorKind::TransportTimeout => ProviderErrorKind::TransportTimeout,
            Http1ErrorKind::ResponseBodyTooLarge => ProviderErrorKind::ResponseTooLarge,
            Http1ErrorKind::HttpHandshakeFailed
            | Http1ErrorKind::HttpSendFailed
            | Http1ErrorKind::ConnectionDriverFailed => ProviderErrorKind::TransportUnavailable,
            Http1ErrorKind::ResponseHeaderTooLarge
            | Http1ErrorKind::ResponseHeaderCountExceeded
            | Http1ErrorKind::ResponseHeaderMalformed
            | Http1ErrorKind::ProtocolUpgradeRejected
            | Http1ErrorKind::ContentEncodingRejected
            | Http1ErrorKind::ResponseBodyFailed => ProviderErrorKind::ResponseRejected,
        };
        Self {
            kind,
            disposition: error.disposition(),
            status: None,
        }
    }

    pub(super) const fn from_secret_error(code: SecretStoreErrorCode) -> Self {
        let credential = match code {
            SecretStoreErrorCode::NotFound => ProviderCredentialError::NotConfigured,
            SecretStoreErrorCode::StoreUnavailable => ProviderCredentialError::Unavailable,
            SecretStoreErrorCode::InvalidIdentifier
            | SecretStoreErrorCode::InvalidSecret
            | SecretStoreErrorCode::InternalError => ProviderCredentialError::ReadFailed,
        };
        Self::definitely_not_sent(ProviderErrorKind::Credential(credential))
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind {
            ProviderErrorKind::InvalidConfiguration => "The provider configuration is invalid.",
            ProviderErrorKind::InvalidJsonRequest => "The provider request must contain JSON.",
            ProviderErrorKind::RequestTooLarge => {
                "The provider request exceeds the transport limit."
            }
            ProviderErrorKind::RequestRejected => {
                "The provider request was rejected before sending."
            }
            ProviderErrorKind::Credential(ProviderCredentialError::NotConfigured) => {
                "No credential is configured for the provider profile."
            }
            ProviderErrorKind::Credential(ProviderCredentialError::Unavailable) => {
                "Secure credential storage is unavailable."
            }
            ProviderErrorKind::Credential(ProviderCredentialError::ReadFailed) => {
                "The provider credential could not be read."
            }
            ProviderErrorKind::TransportUnavailable => "The provider transport is unavailable.",
            ProviderErrorKind::TransportTimeout => "The provider transport timed out.",
            ProviderErrorKind::ResponseRejected => "The provider response was rejected.",
            ProviderErrorKind::ResponseTooLarge => {
                "The provider response exceeds the transport limit."
            }
            ProviderErrorKind::AuthenticationRejected => "The provider rejected authentication.",
            ProviderErrorKind::RemoteTimeoutResponse => "The provider returned a timeout response.",
            ProviderErrorKind::RateLimited => "The provider rate limited the request.",
            ProviderErrorKind::ProviderUnavailable => "The provider is unavailable.",
            ProviderErrorKind::UnexpectedStatus => "The provider returned an unexpected status.",
        };
        f.write_str(message)
    }
}

impl std::error::Error for ProviderError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_error_response_class_keeps_explicit_statuses_structured_and_redacted() {
        let cases = [
            (
                ProviderErrorKind::RemoteTimeoutResponse,
                408,
                ProviderResponseClass::RequestTimeout,
            ),
            (
                ProviderErrorKind::RateLimited,
                429,
                ProviderResponseClass::RateLimited,
            ),
            (
                ProviderErrorKind::AuthenticationRejected,
                401,
                ProviderResponseClass::AuthenticationRejected,
            ),
            (
                ProviderErrorKind::AuthenticationRejected,
                403,
                ProviderResponseClass::AuthenticationRejected,
            ),
            (
                ProviderErrorKind::RequestRejected,
                422,
                ProviderResponseClass::OtherClientError,
            ),
            (
                ProviderErrorKind::ProviderUnavailable,
                503,
                ProviderResponseClass::ServerError,
            ),
        ];
        for (kind, status, expected) in cases {
            let error = ProviderError::from_status(kind, status);
            assert_eq!(error.response_class(), Some(expected));
            assert!(!format!("{error:?}").contains("response-body-canary"));
        }
    }

    #[test]
    fn provider_error_transport_and_credential_errors_have_no_response_class() {
        for kind in [
            ProviderErrorKind::Credential(ProviderCredentialError::NotConfigured),
            ProviderErrorKind::Credential(ProviderCredentialError::Unavailable),
            ProviderErrorKind::Credential(ProviderCredentialError::ReadFailed),
            ProviderErrorKind::TransportUnavailable,
            ProviderErrorKind::TransportTimeout,
        ] {
            assert_eq!(
                ProviderError::definitely_not_sent(kind).response_class(),
                None
            );
        }
    }
}
