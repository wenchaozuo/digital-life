//! D25-D1 exact, process-local destination identity evidence.
//!
//! This module validates and retains only the structured configuration that a
//! future one-shot outbound authorization may bind to.  It does not resolve a
//! profile, inspect active-profile state, read a secret, encode an image, or
//! perform transport.

use reqwest::Url;

const MAX_PROFILE_ID_CHARACTERS: usize = 128;
const MAX_BASE_URL_CHARACTERS: usize = 2_048;
const MAX_MODEL_NAME_CHARACTERS: usize = 256;
const MAX_PROFILE_UPDATED_AT_CHARACTERS: usize = 128;

/// The only destination provider family recognized by D25-D1.  Keeping this
/// enum narrow prevents an arbitrary provider string from becoming authority
/// evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundDestinationProviderKind {
    OpenaiCompatible,
}

impl ScreenVisionOutboundDestinationProviderKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::OpenaiCompatible => "openai_compatible",
        }
    }

    /// Parses the narrow provider vocabulary for a later backend resolver.
    /// Unknown values are rejected rather than retained as free text.
    pub(crate) fn parse(value: &str) -> Result<Self, ScreenVisionOutboundDestinationBindingError> {
        match value {
            "openai_compatible" => Ok(Self::OpenaiCompatible),
            _ => Err(destination_error(
                ScreenVisionOutboundDestinationBindingErrorCode::InvalidProviderKind,
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundDestinationBindingErrorCode {
    InvalidProfileId,
    InvalidProviderKind,
    InvalidBaseUrl,
    InvalidModelName,
    InvalidProfileVersion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionOutboundDestinationBindingError {
    code: ScreenVisionOutboundDestinationBindingErrorCode,
}

impl ScreenVisionOutboundDestinationBindingError {
    pub(crate) const fn code(self) -> ScreenVisionOutboundDestinationBindingErrorCode {
        self.code
    }
}

fn destination_error(
    code: ScreenVisionOutboundDestinationBindingErrorCode,
) -> ScreenVisionOutboundDestinationBindingError {
    ScreenVisionOutboundDestinationBindingError { code }
}

/// Structured destination identity for a future outbound authorization.
///
/// All fields are private and validated/normalized by `new`.  Equality is
/// derived over every identity field; there is no display label or opaque
/// fingerprint that can replace the structured evidence.
#[must_use]
pub(crate) struct ScreenVisionOutboundDestinationBinding {
    profile_id: String,
    provider_kind: ScreenVisionOutboundDestinationProviderKind,
    base_url: String,
    model_name: String,
    profile_updated_at: String,
}

impl ScreenVisionOutboundDestinationBinding {
    pub(crate) fn new(
        profile_id: String,
        provider_kind: ScreenVisionOutboundDestinationProviderKind,
        base_url: String,
        model_name: String,
        profile_updated_at: String,
    ) -> Result<Self, ScreenVisionOutboundDestinationBindingError> {
        Ok(Self {
            profile_id: normalize_profile_id(profile_id)?,
            provider_kind,
            base_url: normalize_base_url(base_url)?,
            model_name: normalize_model_name(model_name)?,
            profile_updated_at: normalize_profile_updated_at(profile_updated_at)?,
        })
    }

    pub(crate) fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub(crate) const fn provider_kind(&self) -> ScreenVisionOutboundDestinationProviderKind {
        self.provider_kind
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    pub(crate) fn model_name(&self) -> &str {
        &self.model_name
    }

    pub(crate) fn profile_updated_at(&self) -> &str {
        &self.profile_updated_at
    }
}

impl PartialEq for ScreenVisionOutboundDestinationBinding {
    fn eq(&self, other: &Self) -> bool {
        self.profile_id == other.profile_id
            && self.provider_kind == other.provider_kind
            && self.base_url == other.base_url
            && self.model_name == other.model_name
            && self.profile_updated_at == other.profile_updated_at
    }
}

impl Eq for ScreenVisionOutboundDestinationBinding {}

fn normalize_profile_id(
    value: String,
) -> Result<String, ScreenVisionOutboundDestinationBindingError> {
    normalize_text(
        value,
        MAX_PROFILE_ID_CHARACTERS,
        ScreenVisionOutboundDestinationBindingErrorCode::InvalidProfileId,
        true,
    )
}

fn normalize_model_name(
    value: String,
) -> Result<String, ScreenVisionOutboundDestinationBindingError> {
    normalize_text(
        value,
        MAX_MODEL_NAME_CHARACTERS,
        ScreenVisionOutboundDestinationBindingErrorCode::InvalidModelName,
        false,
    )
}

fn normalize_profile_updated_at(
    value: String,
) -> Result<String, ScreenVisionOutboundDestinationBindingError> {
    normalize_text(
        value,
        MAX_PROFILE_UPDATED_AT_CHARACTERS,
        ScreenVisionOutboundDestinationBindingErrorCode::InvalidProfileVersion,
        false,
    )
}

fn normalize_text(
    value: String,
    max_characters: usize,
    error_code: ScreenVisionOutboundDestinationBindingErrorCode,
    reject_control: bool,
) -> Result<String, ScreenVisionOutboundDestinationBindingError> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > max_characters
        || (reject_control && value.chars().any(char::is_control))
    {
        return Err(destination_error(error_code));
    }
    Ok(value.to_string())
}

fn normalize_base_url(
    value: String,
) -> Result<String, ScreenVisionOutboundDestinationBindingError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > MAX_BASE_URL_CHARACTERS {
        return Err(destination_error(
            ScreenVisionOutboundDestinationBindingErrorCode::InvalidBaseUrl,
        ));
    }

    let url = Url::parse(value).map_err(|_| {
        destination_error(ScreenVisionOutboundDestinationBindingErrorCode::InvalidBaseUrl)
    })?;
    let authority = value
        .split_once("://")
        .and_then(|(_, remainder)| remainder.split(['/', '?', '#']).next())
        .unwrap_or_default();
    if !matches!(url.scheme(), "http" | "https")
        || authority.is_empty()
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path().contains('%')
    {
        return Err(destination_error(
            ScreenVisionOutboundDestinationBindingErrorCode::InvalidBaseUrl,
        ));
    }

    let lowercase = value.to_ascii_lowercase();
    if [
        "api_key",
        "api-key",
        "apikey",
        "authorization",
        "bearer ",
        "sk-",
    ]
    .iter()
    .any(|marker| lowercase.contains(marker))
    {
        return Err(destination_error(
            ScreenVisionOutboundDestinationBindingErrorCode::InvalidBaseUrl,
        ));
    }

    Ok(url.as_str().trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE_ID: &str = "profile-a";
    const BASE_URL: &str = "https://vision.example.invalid/v1";
    const MODEL_NAME: &str = "vision-model-a";
    const PROFILE_UPDATED_AT: &str = "2026-08-31T00:00:00Z";

    fn binding() -> ScreenVisionOutboundDestinationBinding {
        ScreenVisionOutboundDestinationBinding::new(
            format!(" {PROFILE_ID} "),
            ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible,
            format!(" {BASE_URL}/// "),
            format!(" {MODEL_NAME} "),
            format!(" {PROFILE_UPDATED_AT} "),
        )
        .expect("valid destination should construct")
    }

    fn assert_error<T>(
        result: Result<T, ScreenVisionOutboundDestinationBindingError>,
        expected: ScreenVisionOutboundDestinationBindingErrorCode,
    ) {
        match result {
            Ok(_) => panic!("destination should be rejected"),
            Err(error) => assert_eq!(error.code(), expected),
        }
    }

    fn with_profile_id(
        profile_id: String,
    ) -> Result<ScreenVisionOutboundDestinationBinding, ScreenVisionOutboundDestinationBindingError>
    {
        ScreenVisionOutboundDestinationBinding::new(
            profile_id,
            ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible,
            BASE_URL.to_string(),
            MODEL_NAME.to_string(),
            PROFILE_UPDATED_AT.to_string(),
        )
    }

    fn with_base_url(
        base_url: &str,
    ) -> Result<ScreenVisionOutboundDestinationBinding, ScreenVisionOutboundDestinationBindingError>
    {
        ScreenVisionOutboundDestinationBinding::new(
            PROFILE_ID.to_string(),
            ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible,
            base_url.to_string(),
            MODEL_NAME.to_string(),
            PROFILE_UPDATED_AT.to_string(),
        )
    }

    #[test]
    fn valid_openai_compatible_destination_constructs_and_normalizes() {
        let destination = binding();

        assert_eq!(destination.profile_id(), PROFILE_ID);
        assert_eq!(
            destination.provider_kind(),
            ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible
        );
        assert_eq!(destination.base_url(), BASE_URL);
        assert_eq!(destination.model_name(), MODEL_NAME);
        assert_eq!(destination.profile_updated_at(), PROFILE_UPDATED_AT);
    }

    #[test]
    fn empty_profile_id_is_rejected() {
        assert_error(
            with_profile_id(" ".to_string()),
            ScreenVisionOutboundDestinationBindingErrorCode::InvalidProfileId,
        );
    }

    #[test]
    fn oversized_profile_id_is_rejected() {
        assert_error(
            with_profile_id("x".repeat(MAX_PROFILE_ID_CHARACTERS + 1)),
            ScreenVisionOutboundDestinationBindingErrorCode::InvalidProfileId,
        );
    }

    #[test]
    fn unsupported_provider_is_rejected_and_not_representable() {
        assert_error(
            ScreenVisionOutboundDestinationProviderKind::parse("other_provider"),
            ScreenVisionOutboundDestinationBindingErrorCode::InvalidProviderKind,
        );
        assert_eq!(
            ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible.as_str(),
            "openai_compatible"
        );
    }

    #[test]
    fn invalid_urls_are_rejected() {
        for url in ["not-a-url", "https:///v1", "/v1"] {
            assert_error(
                with_base_url(url),
                ScreenVisionOutboundDestinationBindingErrorCode::InvalidBaseUrl,
            );
        }
    }

    #[test]
    fn oversized_base_url_is_rejected() {
        let url = format!(
            "https://example.invalid/{}",
            "x".repeat(MAX_BASE_URL_CHARACTERS)
        );
        assert_error(
            with_base_url(&url),
            ScreenVisionOutboundDestinationBindingErrorCode::InvalidBaseUrl,
        );
    }

    #[test]
    fn credential_bearing_urls_are_rejected() {
        for url in [
            "https://user@example.invalid/v1",
            "https://user:password@example.invalid/v1",
            "https://example.invalid/v1/sk-secret",
            "https://example.invalid/v1/authorization",
        ] {
            assert_error(
                with_base_url(url),
                ScreenVisionOutboundDestinationBindingErrorCode::InvalidBaseUrl,
            );
        }
    }

    #[test]
    fn query_and_fragment_urls_are_rejected() {
        for url in [
            "https://example.invalid/v1?key=hidden",
            "https://example.invalid/v1#fragment",
        ] {
            assert_error(
                with_base_url(url),
                ScreenVisionOutboundDestinationBindingErrorCode::InvalidBaseUrl,
            );
        }
    }

    #[test]
    fn unsupported_scheme_is_rejected() {
        assert_error(
            with_base_url("ftp://example.invalid/v1"),
            ScreenVisionOutboundDestinationBindingErrorCode::InvalidBaseUrl,
        );
    }

    #[test]
    fn surrounding_url_whitespace_is_trimmed_safely() {
        let destination = with_base_url("  HTTPS://Example.COM/v1  ")
            .expect("surrounding URL whitespace should normalize");
        assert_eq!(destination.base_url(), "https://example.com/v1");
    }

    #[test]
    fn trailing_slash_normalization_is_deterministic() {
        let first = with_base_url("https://example.invalid/v1///")
            .expect("trailing slashes should normalize");
        let second = with_base_url("https://example.invalid/v1")
            .expect("normalized URL should remain valid");
        assert!(first == second);
        assert_eq!(first.base_url(), "https://example.invalid/v1");
    }

    #[test]
    fn empty_model_name_is_rejected() {
        assert_error(
            ScreenVisionOutboundDestinationBinding::new(
                PROFILE_ID.to_string(),
                ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible,
                BASE_URL.to_string(),
                " ".to_string(),
                PROFILE_UPDATED_AT.to_string(),
            ),
            ScreenVisionOutboundDestinationBindingErrorCode::InvalidModelName,
        );
    }

    #[test]
    fn oversized_model_name_is_rejected() {
        assert_error(
            ScreenVisionOutboundDestinationBinding::new(
                PROFILE_ID.to_string(),
                ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible,
                BASE_URL.to_string(),
                "x".repeat(MAX_MODEL_NAME_CHARACTERS + 1),
                PROFILE_UPDATED_AT.to_string(),
            ),
            ScreenVisionOutboundDestinationBindingErrorCode::InvalidModelName,
        );
    }

    #[test]
    fn empty_profile_updated_at_is_rejected() {
        assert_error(
            ScreenVisionOutboundDestinationBinding::new(
                PROFILE_ID.to_string(),
                ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible,
                BASE_URL.to_string(),
                MODEL_NAME.to_string(),
                " ".to_string(),
            ),
            ScreenVisionOutboundDestinationBindingErrorCode::InvalidProfileVersion,
        );
    }

    #[test]
    fn oversized_profile_updated_at_is_rejected() {
        assert_error(
            ScreenVisionOutboundDestinationBinding::new(
                PROFILE_ID.to_string(),
                ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible,
                BASE_URL.to_string(),
                MODEL_NAME.to_string(),
                "x".repeat(MAX_PROFILE_UPDATED_AT_CHARACTERS + 1),
            ),
            ScreenVisionOutboundDestinationBindingErrorCode::InvalidProfileVersion,
        );
    }

    #[test]
    fn exact_normalized_destinations_compare_equal() {
        let first = binding();
        let second = ScreenVisionOutboundDestinationBinding::new(
            PROFILE_ID.to_string(),
            ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible,
            BASE_URL.to_string(),
            MODEL_NAME.to_string(),
            PROFILE_UPDATED_AT.to_string(),
        )
        .expect("same normalized destination should construct");

        assert!(first == second);
    }

    #[test]
    fn changing_profile_id_changes_identity() {
        let first = binding();
        let second = with_profile_id("profile-b".to_string())
            .expect("changed profile identity should construct");
        assert!(first != second);
    }

    #[test]
    fn changing_provider_is_not_representable() {
        assert!(ScreenVisionOutboundDestinationProviderKind::parse("another_family").is_err());
    }

    #[test]
    fn changing_base_url_changes_identity() {
        let first = binding();
        let second = with_base_url("https://other.example.invalid/v1")
            .expect("changed base URL should construct");
        assert!(first != second);
    }

    #[test]
    fn changing_model_name_changes_identity() {
        let first = binding();
        let second = ScreenVisionOutboundDestinationBinding::new(
            PROFILE_ID.to_string(),
            ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible,
            BASE_URL.to_string(),
            "vision-model-b".to_string(),
            PROFILE_UPDATED_AT.to_string(),
        )
        .expect("changed model should construct");
        assert!(first != second);
    }

    #[test]
    fn changing_profile_updated_at_changes_identity() {
        let first = binding();
        let second = ScreenVisionOutboundDestinationBinding::new(
            PROFILE_ID.to_string(),
            ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible,
            BASE_URL.to_string(),
            MODEL_NAME.to_string(),
            "2026-08-31T00:00:01Z".to_string(),
        )
        .expect("changed profile version evidence should construct");
        assert!(first != second);
    }

    #[test]
    fn production_surface_has_no_cosmetic_or_secret_fields() {
        let source = include_str!("screen_vision_outbound_destination.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source should precede tests");

        assert!(!source.contains("display_name"));
        assert!(!source.contains("credential"));
        assert!(!source.contains("SecretIdentifier"));
        assert!(!source.contains("Serialize"));
    }

    #[test]
    fn production_surface_has_no_network_or_model_transport_path() {
        let source = include_str!("screen_vision_outbound_destination.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source should precede tests");

        assert!(source.contains("reqwest::Url"));
        assert!(!source.contains("reqwest::Client"));
        assert!(!source.contains(".send("));
        assert!(!source.contains("std::net"));
        assert!(!source.contains("ModelPurpose"));
        assert!(!source.contains("VisionProvider"));
    }
}
