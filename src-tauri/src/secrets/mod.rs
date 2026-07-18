//! Secret storage boundary. API credentials never use SQLite, JSON, logs, or
//! application data files, and no command returns secret plaintext.

#[cfg(test)]
mod in_memory;
#[cfg(windows)]
mod windows_credential;

#[cfg(test)]
pub(crate) use in_memory::InMemorySecretStore;
#[cfg(windows)]
pub use windows_credential::WindowsCredentialSecretStore;

use std::fmt;

use serde::{Deserialize, Serialize};
use tauri::State;
use zeroize::Zeroizing;

const MAX_PROFILE_ID_CHARACTERS: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretPurpose {
    ChatModelApiKey,
    EmbeddingModelApiKey,
    CandidateExtractionModelApiKey,
}

impl SecretPurpose {
    pub(crate) const fn canonical_name(self) -> &'static str {
        match self {
            Self::ChatModelApiKey => "chat-model-api-key",
            Self::EmbeddingModelApiKey => "embedding-model-api-key",
            Self::CandidateExtractionModelApiKey => "candidate-extraction-model-api-key",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub struct SecretIdentifier {
    pub purpose: SecretPurpose,
    pub profile_id: String,
}

impl SecretIdentifier {
    pub fn new(
        purpose: SecretPurpose,
        profile_id: impl Into<String>,
    ) -> Result<Self, SecretStoreError> {
        let profile_id = profile_id.into();
        let trimmed = profile_id.trim();
        if trimmed.is_empty()
            || trimmed.chars().count() > MAX_PROFILE_ID_CHARACTERS
            || trimmed.chars().any(char::is_control)
        {
            return Err(SecretStoreError::invalid_identifier());
        }
        Ok(Self {
            purpose,
            profile_id: trimmed.to_string(),
        })
    }

    fn validate(&self) -> Result<(), SecretStoreError> {
        Self::new(self.purpose, self.profile_id.clone()).map(|_| ())
    }
}

/// An owned secret that zeroes its allocation on drop. It intentionally has no
/// `Clone`, `Serialize`, or `Display` implementation.
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    pub fn new(value: String) -> Result<Self, SecretStoreError> {
        let value = Zeroizing::new(value);
        if value.trim().is_empty() {
            return Err(SecretStoreError::invalid_secret());
        }
        Ok(Self(value))
    }

    pub(crate) fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretStatus {
    pub exists: bool,
    pub updated: bool,
    pub deleted: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecretStoreErrorCode {
    InvalidIdentifier,
    InvalidSecret,
    NotFound,
    StoreUnavailable,
    InternalError,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SecretStoreError {
    pub code: SecretStoreErrorCode,
    pub message: String,
    pub recoverable: bool,
}

impl SecretStoreError {
    pub(crate) fn new(
        code: SecretStoreErrorCode,
        message: impl Into<String>,
        recoverable: bool,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable,
        }
    }

    pub(crate) fn invalid_identifier() -> Self {
        Self::new(
            SecretStoreErrorCode::InvalidIdentifier,
            "The credential identifier is invalid.",
            false,
        )
    }

    pub(crate) fn invalid_secret() -> Self {
        Self::new(
            SecretStoreErrorCode::InvalidSecret,
            "The credential value must not be empty or whitespace only.",
            false,
        )
    }

    pub(crate) fn not_found() -> Self {
        Self::new(
            SecretStoreErrorCode::NotFound,
            "The requested credential was not found.",
            true,
        )
    }

    pub(crate) fn unavailable() -> Self {
        Self::new(
            SecretStoreErrorCode::StoreUnavailable,
            "Secure credential storage is unavailable.",
            true,
        )
    }

    pub(crate) fn internal() -> Self {
        Self::new(
            SecretStoreErrorCode::InternalError,
            "The secure credential operation failed.",
            true,
        )
    }
}

pub trait SecretStore: Send + Sync {
    fn set_secret(
        &self,
        identifier: &SecretIdentifier,
        value: SecretValue,
    ) -> Result<SecretStatus, SecretStoreError>;

    /// Rust-internal only. No Tauri command may expose this value.
    fn get_secret(&self, identifier: &SecretIdentifier) -> Result<SecretValue, SecretStoreError>;

    fn has_secret(&self, identifier: &SecretIdentifier) -> Result<bool, SecretStoreError>;

    /// Deleting an absent credential is an idempotent success with
    /// `deleted = false`.
    fn delete_secret(
        &self,
        identifier: &SecretIdentifier,
    ) -> Result<SecretStatus, SecretStoreError>;
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveApiCredentialRequest {
    pub purpose: SecretPurpose,
    pub profile_id: String,
    pub api_key: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SaveApiCredentialResponse {
    pub purpose: SecretPurpose,
    pub profile_id: String,
    pub exists: bool,
    pub updated: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiCredentialRequest {
    pub purpose: SecretPurpose,
    pub profile_id: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HasApiCredentialResponse {
    pub purpose: SecretPurpose,
    pub profile_id: String,
    pub exists: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeleteApiCredentialResponse {
    pub purpose: SecretPurpose,
    pub profile_id: String,
    pub exists: bool,
    pub deleted: bool,
}

fn save_with_store<S: SecretStore + ?Sized>(
    store: &S,
    request: SaveApiCredentialRequest,
) -> Result<SaveApiCredentialResponse, SecretStoreError> {
    let identifier = SecretIdentifier::new(request.purpose, request.profile_id)?;
    let status = store.set_secret(&identifier, SecretValue::new(request.api_key)?)?;
    Ok(SaveApiCredentialResponse {
        purpose: identifier.purpose,
        profile_id: identifier.profile_id,
        exists: status.exists,
        updated: status.updated,
    })
}

fn has_with_store<S: SecretStore + ?Sized>(
    store: &S,
    request: ApiCredentialRequest,
) -> Result<HasApiCredentialResponse, SecretStoreError> {
    let identifier = SecretIdentifier::new(request.purpose, request.profile_id)?;
    let exists = store.has_secret(&identifier)?;
    Ok(HasApiCredentialResponse {
        purpose: identifier.purpose,
        profile_id: identifier.profile_id,
        exists,
    })
}

fn delete_with_store<S: SecretStore + ?Sized>(
    store: &S,
    request: ApiCredentialRequest,
) -> Result<DeleteApiCredentialResponse, SecretStoreError> {
    let identifier = SecretIdentifier::new(request.purpose, request.profile_id)?;
    let status = store.delete_secret(&identifier)?;
    Ok(DeleteApiCredentialResponse {
        purpose: identifier.purpose,
        profile_id: identifier.profile_id,
        exists: status.exists,
        deleted: status.deleted,
    })
}

#[cfg(windows)]
#[tauri::command]
pub fn save_api_credential(
    store: State<'_, WindowsCredentialSecretStore>,
    request: SaveApiCredentialRequest,
) -> Result<SaveApiCredentialResponse, SecretStoreError> {
    save_with_store(store.inner(), request)
}

#[cfg(windows)]
#[tauri::command]
pub fn has_api_credential(
    store: State<'_, WindowsCredentialSecretStore>,
    request: ApiCredentialRequest,
) -> Result<HasApiCredentialResponse, SecretStoreError> {
    has_with_store(store.inner(), request)
}

#[cfg(windows)]
#[tauri::command]
pub fn delete_api_credential(
    store: State<'_, WindowsCredentialSecretStore>,
    request: ApiCredentialRequest,
) -> Result<DeleteApiCredentialResponse, SecretStoreError> {
    delete_with_store(store.inner(), request)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLACEHOLDER: &str = "unit-test-placeholder";

    fn identifier(purpose: SecretPurpose, profile_id: &str) -> SecretIdentifier {
        SecretIdentifier::new(purpose, profile_id).unwrap()
    }

    #[test]
    fn empty_secret_is_rejected_and_debug_is_redacted() {
        assert_eq!(
            SecretValue::new("  ".into()).unwrap_err().code,
            SecretStoreErrorCode::InvalidSecret
        );
        let value = SecretValue::new(PLACEHOLDER.into()).unwrap();
        let debug = format!("{value:?}");
        assert_eq!(debug, "[REDACTED]");
        assert!(!debug.contains(PLACEHOLDER));
    }

    #[test]
    fn in_memory_store_overwrites_and_isolates_identifiers() {
        let store = InMemorySecretStore::new();
        let chat_a = identifier(SecretPurpose::ChatModelApiKey, "profile-a");
        let chat_b = identifier(SecretPurpose::ChatModelApiKey, "profile-b");
        let embedding_a = identifier(SecretPurpose::EmbeddingModelApiKey, "profile-a");
        let candidate_a = identifier(SecretPurpose::CandidateExtractionModelApiKey, "profile-a");

        assert!(!store.has_secret(&chat_a).unwrap());
        assert!(
            store
                .set_secret(&chat_a, SecretValue::new(PLACEHOLDER.into()).unwrap())
                .unwrap()
                .updated
        );
        assert!(store.has_secret(&chat_a).unwrap());
        store
            .set_secret(
                &chat_a,
                SecretValue::new("replacement-placeholder".into()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store.get_secret(&chat_a).unwrap().expose_secret(),
            "replacement-placeholder"
        );
        assert!(!store.has_secret(&chat_b).unwrap());
        assert!(!store.has_secret(&embedding_a).unwrap());
        assert!(!store.has_secret(&candidate_a).unwrap());
    }

    #[test]
    fn candidate_credential_crud_and_wire_purpose_are_isolated() {
        let store = InMemorySecretStore::new();
        let profile_id = "shared-profile";
        let candidate = identifier(SecretPurpose::CandidateExtractionModelApiKey, profile_id);
        let chat = identifier(SecretPurpose::ChatModelApiKey, profile_id);
        let embedding = identifier(SecretPurpose::EmbeddingModelApiKey, profile_id);
        let placeholder = format!("placeholder-{}", std::process::id());

        assert_eq!(
            serde_json::to_string(&SecretPurpose::CandidateExtractionModelApiKey).unwrap(),
            "\"CANDIDATE_EXTRACTION_MODEL_API_KEY\""
        );
        assert_eq!(
            serde_json::from_str::<SecretPurpose>("\"CANDIDATE_EXTRACTION_MODEL_API_KEY\"")
                .unwrap(),
            SecretPurpose::CandidateExtractionModelApiKey
        );
        assert!(
            serde_json::from_str::<SecretPurpose>("\"candidate_extraction_model_api_key\"")
                .is_err()
        );

        assert!(!store.has_secret(&candidate).unwrap());
        store
            .set_secret(&candidate, SecretValue::new(placeholder.clone()).unwrap())
            .unwrap();
        assert!(store.has_secret(&candidate).unwrap());
        assert!(store.get_secret(&candidate).unwrap().expose_secret() == placeholder);
        assert!(!store.has_secret(&chat).unwrap());
        assert!(!store.has_secret(&embedding).unwrap());
        assert_eq!(
            format!("{:?}", store.get_secret(&candidate).unwrap()),
            "[REDACTED]"
        );
        assert!(store.delete_secret(&candidate).unwrap().deleted);
        assert!(!store.has_secret(&candidate).unwrap());
    }

    #[test]
    fn delete_is_idempotent_and_get_missing_is_structured() {
        let store = InMemorySecretStore::new();
        let id = identifier(SecretPurpose::ChatModelApiKey, "profile-a");
        store
            .set_secret(&id, SecretValue::new(PLACEHOLDER.into()).unwrap())
            .unwrap();
        let deleted = store.delete_secret(&id).unwrap();
        assert!(deleted.deleted);
        assert!(!deleted.exists);
        assert_eq!(
            store.get_secret(&id).unwrap_err().code,
            SecretStoreErrorCode::NotFound
        );
        assert!(!store.delete_secret(&id).unwrap().deleted);
    }

    #[test]
    fn errors_and_command_responses_never_contain_secret_plaintext() {
        let store = InMemorySecretStore::new();
        let response = save_with_store(
            &store,
            SaveApiCredentialRequest {
                purpose: SecretPurpose::EmbeddingModelApiKey,
                profile_id: "profile-a".into(),
                api_key: PLACEHOLDER.into(),
            },
        )
        .unwrap();
        let response_json = serde_json::to_string(&response).unwrap();
        assert!(!response_json.contains(PLACEHOLDER));
        assert!(!response_json.contains("apiKey"));

        let error_json = serde_json::to_string(&SecretStoreError::internal()).unwrap();
        assert!(!error_json.contains(PLACEHOLDER));
        assert!(
            has_with_store(
                &store,
                ApiCredentialRequest {
                    purpose: SecretPurpose::EmbeddingModelApiKey,
                    profile_id: "profile-a".into(),
                },
            )
            .unwrap()
            .exists
        );
        assert!(
            delete_with_store(
                &store,
                ApiCredentialRequest {
                    purpose: SecretPurpose::EmbeddingModelApiKey,
                    profile_id: "profile-a".into(),
                },
            )
            .unwrap()
            .deleted
        );
    }

    #[test]
    fn no_plaintext_read_command_is_registered() {
        let library_source = include_str!("../lib.rs");
        assert!(library_source.contains("secrets::save_api_credential"));
        assert!(library_source.contains("secrets::has_api_credential"));
        assert!(library_source.contains("secrets::delete_api_credential"));
        assert!(!library_source.contains("get_api_credential"));
    }
}
