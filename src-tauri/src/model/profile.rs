use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::storage::StorageService;

const MAX_DISPLAY_NAME_CHARACTERS: usize = 128;
const MAX_MODEL_NAME_CHARACTERS: usize = 256;
const MAX_BASE_URL_CHARACTERS: usize = 2048;
const MAX_TOKENS: u32 = 1_000_000;
const MAX_EMBEDDING_DIMENSION: u32 = 65_536;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ModelPurpose {
    Chat,
    Embedding,
}

impl ModelPurpose {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Embedding => "embedding",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ModelProfileError> {
        match value {
            "chat" => Ok(Self::Chat),
            "embedding" => Ok(Self::Embedding),
            _ => Err(ModelProfileError::database()),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelProviderKind {
    OpenaiCompatible,
}

impl ModelProviderKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::OpenaiCompatible => "openai_compatible",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, ModelProfileError> {
        match value {
            "openai_compatible" => Ok(Self::OpenaiCompatible),
            _ => Err(ModelProfileError::unsupported_provider()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ModelProfile {
    pub id: String,
    pub purpose: ModelPurpose,
    pub provider_kind: ModelProviderKind,
    pub display_name: String,
    pub base_url: String,
    pub model_name: String,
    pub temperature: Option<f64>,
    pub max_tokens: Option<u32>,
    pub embedding_dimension: Option<u32>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateModelProfileRequest {
    pub purpose: ModelPurpose,
    pub provider_kind: ModelProviderKind,
    pub display_name: String,
    pub base_url: String,
    pub model_name: String,
    pub temperature: Option<f64>,
    pub max_tokens: Option<u32>,
    pub embedding_dimension: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateModelProfileRequest {
    pub profile_id: String,
    pub purpose: ModelPurpose,
    pub provider_kind: ModelProviderKind,
    pub display_name: String,
    pub base_url: String,
    pub model_name: String,
    pub temperature: Option<f64>,
    pub max_tokens: Option<u32>,
    pub embedding_dimension: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListModelProfilesRequest {
    pub purpose: Option<ModelPurpose>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SetActiveModelProfileRequest {
    pub purpose: ModelPurpose,
    pub profile_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ActiveModelProfile {
    pub purpose: ModelPurpose,
    pub profile_id: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeleteModelProfileResult {
    pub profile_id: String,
    pub deleted: bool,
    pub active_mapping_cleared: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModelProfileErrorCode {
    InvalidRequest,
    InvalidBaseUrl,
    InvalidParameters,
    ProfileNotFound,
    PurposeMismatch,
    UnsupportedProvider,
    DatabaseError,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModelProfileError {
    pub code: ModelProfileErrorCode,
    pub message: String,
    pub recoverable: bool,
}

impl ModelProfileError {
    fn new(code: ModelProfileErrorCode, message: impl Into<String>, recoverable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable,
        }
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::new(ModelProfileErrorCode::InvalidRequest, message, false)
    }

    pub(crate) fn not_found() -> Self {
        Self::new(
            ModelProfileErrorCode::ProfileNotFound,
            "The requested model profile was not found.",
            true,
        )
    }

    pub(crate) fn purpose_mismatch() -> Self {
        Self::new(
            ModelProfileErrorCode::PurposeMismatch,
            "The model profile purpose does not match the requested purpose.",
            false,
        )
    }

    pub(crate) fn unsupported_provider() -> Self {
        Self::new(
            ModelProfileErrorCode::UnsupportedProvider,
            "The model profile provider is not supported.",
            false,
        )
    }

    pub(crate) fn database() -> Self {
        Self::new(
            ModelProfileErrorCode::DatabaseError,
            "The model profile storage operation failed.",
            true,
        )
    }
}

pub trait ModelProfileRepository {
    fn create_profile(&self, profile: &ModelProfile) -> Result<ModelProfile, ModelProfileError>;
    fn get_profile(&self, profile_id: &str) -> Result<Option<ModelProfile>, ModelProfileError>;
    fn list_profiles(
        &self,
        purpose: Option<ModelPurpose>,
    ) -> Result<Vec<ModelProfile>, ModelProfileError>;
    fn update_profile(&self, profile: &ModelProfile) -> Result<ModelProfile, ModelProfileError>;
    fn delete_profile(
        &self,
        profile_id: &str,
    ) -> Result<DeleteModelProfileResult, ModelProfileError>;
    fn set_active_profile(
        &self,
        purpose: ModelPurpose,
        profile_id: &str,
    ) -> Result<ActiveModelProfile, ModelProfileError>;
    fn get_active_profile(
        &self,
        purpose: ModelPurpose,
    ) -> Result<Option<ActiveModelProfile>, ModelProfileError>;
}

pub struct ModelProfileService<'a, R: ModelProfileRepository> {
    repository: &'a R,
}

impl<'a, R: ModelProfileRepository> ModelProfileService<'a, R> {
    pub fn new(repository: &'a R) -> Self {
        Self { repository }
    }

    pub fn create(
        &self,
        request: CreateModelProfileRequest,
    ) -> Result<ModelProfile, ModelProfileError> {
        let normalized = NormalizedProfile::from_create(request)?;
        self.repository
            .create_profile(&normalized.into_profile(generate_profile_id(), String::new()))
    }

    pub fn get(&self, profile_id: &str) -> Result<ModelProfile, ModelProfileError> {
        validate_profile_id(profile_id)?;
        self.repository
            .get_profile(profile_id)?
            .ok_or_else(ModelProfileError::not_found)
    }

    pub fn list(
        &self,
        request: ListModelProfilesRequest,
    ) -> Result<Vec<ModelProfile>, ModelProfileError> {
        self.repository.list_profiles(request.purpose)
    }

    pub fn update(
        &self,
        request: UpdateModelProfileRequest,
    ) -> Result<ModelProfile, ModelProfileError> {
        validate_profile_id(&request.profile_id)?;
        let existing = self
            .repository
            .get_profile(&request.profile_id)?
            .ok_or_else(ModelProfileError::not_found)?;
        if existing.purpose != request.purpose {
            return Err(ModelProfileError::purpose_mismatch());
        }
        let profile_id = request.profile_id.clone();
        let normalized = NormalizedProfile::from_update(request)?;
        self.repository
            .update_profile(&normalized.into_profile(profile_id, existing.created_at))
    }

    pub fn delete(&self, profile_id: &str) -> Result<DeleteModelProfileResult, ModelProfileError> {
        validate_profile_id(profile_id)?;
        self.repository.delete_profile(profile_id)
    }

    pub fn set_active(
        &self,
        request: SetActiveModelProfileRequest,
    ) -> Result<ActiveModelProfile, ModelProfileError> {
        validate_profile_id(&request.profile_id)?;
        let profile = self
            .repository
            .get_profile(&request.profile_id)?
            .ok_or_else(ModelProfileError::not_found)?;
        if profile.purpose != request.purpose {
            return Err(ModelProfileError::purpose_mismatch());
        }
        self.repository
            .set_active_profile(request.purpose, &request.profile_id)
    }

    pub fn get_active(
        &self,
        purpose: ModelPurpose,
    ) -> Result<Option<ActiveModelProfile>, ModelProfileError> {
        self.repository.get_active_profile(purpose)
    }
}

#[derive(Debug)]
struct NormalizedProfile {
    purpose: ModelPurpose,
    provider_kind: ModelProviderKind,
    display_name: String,
    base_url: String,
    model_name: String,
    temperature: Option<f64>,
    max_tokens: Option<u32>,
    embedding_dimension: Option<u32>,
}

impl NormalizedProfile {
    fn from_create(request: CreateModelProfileRequest) -> Result<Self, ModelProfileError> {
        Self::new(
            request.purpose,
            request.provider_kind,
            request.display_name,
            request.base_url,
            request.model_name,
            request.temperature,
            request.max_tokens,
            request.embedding_dimension,
        )
    }

    fn from_update(request: UpdateModelProfileRequest) -> Result<Self, ModelProfileError> {
        Self::new(
            request.purpose,
            request.provider_kind,
            request.display_name,
            request.base_url,
            request.model_name,
            request.temperature,
            request.max_tokens,
            request.embedding_dimension,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        purpose: ModelPurpose,
        provider_kind: ModelProviderKind,
        display_name: String,
        base_url: String,
        model_name: String,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        embedding_dimension: Option<u32>,
    ) -> Result<Self, ModelProfileError> {
        let display_name =
            normalize_required(display_name, "displayName", MAX_DISPLAY_NAME_CHARACTERS)?;
        let model_name = normalize_required(model_name, "modelName", MAX_MODEL_NAME_CHARACTERS)?;
        let base_url = normalize_base_url(base_url)?;
        validate_parameters(purpose, temperature, max_tokens, embedding_dimension)?;
        Ok(Self {
            purpose,
            provider_kind,
            display_name,
            base_url,
            model_name,
            temperature,
            max_tokens,
            embedding_dimension,
        })
    }

    fn into_profile(self, id: String, created_at: String) -> ModelProfile {
        ModelProfile {
            id,
            purpose: self.purpose,
            provider_kind: self.provider_kind,
            display_name: self.display_name,
            base_url: self.base_url,
            model_name: self.model_name,
            temperature: self.temperature,
            max_tokens: self.max_tokens,
            embedding_dimension: self.embedding_dimension,
            created_at,
            updated_at: String::new(),
        }
    }
}

fn normalize_required(
    value: String,
    field: &str,
    max_characters: usize,
) -> Result<String, ModelProfileError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > max_characters {
        return Err(ModelProfileError::invalid(format!(
            "{field} must be non-empty and within its supported length."
        )));
    }
    Ok(value.to_string())
}

fn normalize_base_url(value: String) -> Result<String, ModelProfileError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > MAX_BASE_URL_CHARACTERS {
        return Err(invalid_base_url());
    }
    let url = Url::parse(value).map_err(|_| invalid_base_url())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
        || url.path().contains('%')
    {
        return Err(invalid_base_url());
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
        return Err(invalid_base_url());
    }
    Ok(url.as_str().trim_end_matches('/').to_string())
}

fn invalid_base_url() -> ModelProfileError {
    ModelProfileError::new(
        ModelProfileErrorCode::InvalidBaseUrl,
        "baseUrl must be an absolute HTTP or HTTPS URL without credentials, query, or fragment.",
        false,
    )
}

fn validate_parameters(
    purpose: ModelPurpose,
    temperature: Option<f64>,
    max_tokens: Option<u32>,
    embedding_dimension: Option<u32>,
) -> Result<(), ModelProfileError> {
    let valid = match purpose {
        ModelPurpose::Chat => {
            temperature.is_some_and(|value| value.is_finite() && (0.0..=2.0).contains(&value))
                && max_tokens.is_some_and(|value| (1..=MAX_TOKENS).contains(&value))
                && embedding_dimension.is_none()
        }
        ModelPurpose::Embedding => {
            temperature.is_none()
                && max_tokens.is_none()
                && embedding_dimension
                    .is_some_and(|value| (1..=MAX_EMBEDDING_DIMENSION).contains(&value))
        }
    };
    if !valid {
        return Err(ModelProfileError::new(
            ModelProfileErrorCode::InvalidParameters,
            "Model parameters are invalid or do not apply to this profile purpose.",
            false,
        ));
    }
    Ok(())
}

fn validate_profile_id(profile_id: &str) -> Result<(), ModelProfileError> {
    if profile_id.trim().is_empty() || profile_id.chars().any(char::is_control) {
        return Err(ModelProfileError::invalid("profileId is invalid."));
    }
    Ok(())
}

fn generate_profile_id() -> String {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    format!("model-profile-{nanos}-{sequence}")
}

#[tauri::command]
pub fn create_model_profile(
    storage: State<'_, StorageService>,
    request: CreateModelProfileRequest,
) -> Result<ModelProfile, ModelProfileError> {
    ModelProfileService::new(storage.inner()).create(request)
}

#[tauri::command]
pub fn list_model_profiles(
    storage: State<'_, StorageService>,
    request: ListModelProfilesRequest,
) -> Result<Vec<ModelProfile>, ModelProfileError> {
    ModelProfileService::new(storage.inner()).list(request)
}

#[tauri::command]
pub fn get_model_profile(
    storage: State<'_, StorageService>,
    profile_id: String,
) -> Result<ModelProfile, ModelProfileError> {
    ModelProfileService::new(storage.inner()).get(&profile_id)
}

#[tauri::command]
pub fn update_model_profile(
    storage: State<'_, StorageService>,
    request: UpdateModelProfileRequest,
) -> Result<ModelProfile, ModelProfileError> {
    ModelProfileService::new(storage.inner()).update(request)
}

#[tauri::command]
pub fn delete_model_profile(
    storage: State<'_, StorageService>,
    profile_id: String,
) -> Result<DeleteModelProfileResult, ModelProfileError> {
    ModelProfileService::new(storage.inner()).delete(&profile_id)
}

#[tauri::command]
pub fn set_active_model_profile(
    storage: State<'_, StorageService>,
    request: SetActiveModelProfileRequest,
) -> Result<ActiveModelProfile, ModelProfileError> {
    ModelProfileService::new(storage.inner()).set_active(request)
}

#[tauri::command]
pub fn get_active_model_profile(
    storage: State<'_, StorageService>,
    purpose: ModelPurpose,
) -> Result<Option<ActiveModelProfile>, ModelProfileError> {
    ModelProfileService::new(storage.inner()).get_active(purpose)
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    fn chat_request() -> CreateModelProfileRequest {
        CreateModelProfileRequest {
            purpose: ModelPurpose::Chat,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: " Chat Profile ".into(),
            base_url: "http://localhost:4000/v1///".into(),
            model_name: " chat-model ".into(),
            temperature: Some(0.7),
            max_tokens: Some(4096),
            embedding_dimension: None,
        }
    }

    #[test]
    fn validates_and_normalizes_names_and_base_url() {
        let normalized = NormalizedProfile::from_create(chat_request()).unwrap();
        assert_eq!(normalized.display_name, "Chat Profile");
        assert_eq!(normalized.model_name, "chat-model");
        assert_eq!(normalized.base_url, "http://localhost:4000/v1");
    }

    #[test]
    fn rejects_empty_fields_and_unsafe_urls() {
        for mutate in [
            |request: &mut CreateModelProfileRequest| request.display_name = " ".into(),
            |request: &mut CreateModelProfileRequest| request.base_url = " ".into(),
            |request: &mut CreateModelProfileRequest| request.model_name = " ".into(),
        ] {
            let mut request = chat_request();
            mutate(&mut request);
            assert!(NormalizedProfile::from_create(request).is_err());
        }
        for base_url in [
            "ftp://example.invalid/v1",
            "https://user@example.invalid/v1",
            "https://user:password@example.invalid/v1",
            "https://example.invalid/v1#fragment",
            "https://example.invalid/v1?api_key=hidden",
        ] {
            let mut request = chat_request();
            request.base_url = base_url.into();
            assert_eq!(
                NormalizedProfile::from_create(request).unwrap_err().code,
                ModelProfileErrorCode::InvalidBaseUrl
            );
        }
    }

    #[test]
    fn purpose_parameters_are_strict_and_bounded() {
        let mut chat = chat_request();
        chat.temperature = Some(2.1);
        assert_eq!(
            NormalizedProfile::from_create(chat).unwrap_err().code,
            ModelProfileErrorCode::InvalidParameters
        );
        let mut chat = chat_request();
        chat.embedding_dimension = Some(1536);
        assert!(NormalizedProfile::from_create(chat).is_err());
        let mut chat = chat_request();
        chat.max_tokens = Some(0);
        assert!(NormalizedProfile::from_create(chat).is_err());
        let mut chat = chat_request();
        chat.max_tokens = Some(MAX_TOKENS + 1);
        assert!(NormalizedProfile::from_create(chat).is_err());

        let embedding = CreateModelProfileRequest {
            purpose: ModelPurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "Embedding".into(),
            base_url: "https://example.invalid/v1".into(),
            model_name: "embedding-model".into(),
            temperature: None,
            max_tokens: None,
            embedding_dimension: Some(1536),
        };
        assert!(NormalizedProfile::from_create(embedding.clone()).is_ok());
        let mut invalid = embedding.clone();
        invalid.embedding_dimension = Some(MAX_EMBEDDING_DIMENSION + 1);
        assert!(NormalizedProfile::from_create(invalid).is_err());
        let mut invalid = embedding;
        invalid.max_tokens = Some(1);
        assert!(NormalizedProfile::from_create(invalid).is_err());
    }

    #[test]
    fn profile_request_rejects_unknown_secret_fields() {
        let value = serde_json::json!({
            "purpose": "chat",
            "providerKind": "openai_compatible",
            "displayName": "Chat",
            "baseUrl": "https://example.invalid/v1",
            "modelName": "chat-model",
            "temperature": 0.7,
            "maxTokens": 4096,
            "embeddingDimension": null,
            "apiKey": null
        });
        assert!(serde_json::from_value::<CreateModelProfileRequest>(value).is_err());
    }
}
