//! Secure runtime assembly from non-secret SQLite profiles and runtime-only
//! credentials. This module does not persist, log, or expose credentials.

use std::{
    collections::HashSet,
    sync::Mutex,
    time::{Duration, Instant},
};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use tauri::State;

use crate::{
    embedding::{
        EmbeddingError, EmbeddingErrorCode, EmbeddingProvider, EmbeddingPurpose, EmbeddingRequest,
        EmbeddingRuntimeOptions, OpenAICompatibleEmbeddingConfig,
        OpenAICompatibleEmbeddingProvider, RuntimeEmbeddingApiKey,
    },
    secrets::{
        SecretIdentifier, SecretPurpose, SecretStore, SecretStoreErrorCode,
        WindowsCredentialSecretStore,
    },
    storage::StorageService,
};

use super::{
    profile::{
        ModelProfile, ModelProfileError, ModelProfileErrorCode, ModelProfileRepository,
        ModelProviderKind, ModelPurpose,
    },
    ModelError, ModelMessage, ModelMessageRole, ModelProvider, ModelRequest,
    OpenAICompatibleProvider,
};

const CONNECTION_TEST_TIMEOUT: Duration = Duration::from_secs(30);
const CHAT_TEST_MAX_TOKENS: u32 = 8;
const CHAT_TEST_TEXT: &str = "Reply with OK.";
const EMBEDDING_TEST_TEXT: &str = "connection test";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ModelRuntimePurpose {
    Chat,
    Embedding,
}

impl ModelRuntimePurpose {
    const fn profile_purpose(self) -> ModelPurpose {
        match self {
            Self::Chat => ModelPurpose::Chat,
            Self::Embedding => ModelPurpose::Embedding,
        }
    }

    const fn secret_purpose(self) -> SecretPurpose {
        match self {
            Self::Chat => SecretPurpose::ChatModelApiKey,
            Self::Embedding => SecretPurpose::EmbeddingModelApiKey,
        }
    }
}

#[derive(Clone)]
pub struct ResolvedModelProfile {
    pub profile_id: String,
    pub purpose: ModelRuntimePurpose,
    pub provider_kind: ModelProviderKind,
    pub display_name: String,
    pub base_url: String,
    pub model_name: String,
    pub temperature: Option<f64>,
    pub max_tokens: Option<u32>,
    pub embedding_dimension: Option<u32>,
}

pub struct ResolvedChatProvider {
    pub profile: ResolvedModelProfile,
    provider: OpenAICompatibleProvider,
}

pub struct ResolvedEmbeddingProvider {
    pub profile: ResolvedModelProfile,
    provider: OpenAICompatibleEmbeddingProvider,
}

impl ResolvedChatProvider {
    pub fn provider(&self) -> &dyn ModelProvider {
        &self.provider
    }
}

impl ResolvedEmbeddingProvider {
    pub fn provider(&self) -> &dyn EmbeddingProvider {
        &self.provider
    }

    /// Transfers the short-lived provider into another Rust-internal
    /// orchestrator without exposing its credential to IPC or serialization.
    pub(crate) fn into_provider(self) -> OpenAICompatibleEmbeddingProvider {
        self.provider
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModelConnectionTestRequest {
    pub profile_id: String,
    pub purpose: ModelRuntimePurpose,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveModelChatRequest {
    pub messages: Vec<ModelMessage>,
    pub system_context: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ModelRuntimeErrorCode {
    NoActiveProfile,
    ProfileNotFound,
    ProfilePurposeMismatch,
    CredentialNotFound,
    UnsupportedProvider,
    InvalidProfile,
    ProviderInitializationFailed,
    AuthenticationFailed,
    RateLimited,
    NetworkUnavailable,
    RequestTimeout,
    InvalidProviderResponse,
    DimensionMismatch,
    ConnectionTestFailed,
    ConnectionTestInProgress,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModelRuntimeError {
    pub code: ModelRuntimeErrorCode,
    pub message: String,
    pub recoverable: bool,
}

impl ModelRuntimeError {
    fn new(code: ModelRuntimeErrorCode, message: impl Into<String>, recoverable: bool) -> Self {
        Self {
            code,
            message: message.into(),
            recoverable,
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ModelConnectionTestResult {
    pub profile_id: String,
    pub purpose: ModelRuntimePurpose,
    pub success: bool,
    pub provider_kind: Option<ModelProviderKind>,
    pub model_name: Option<String>,
    pub latency_ms: u64,
    pub embedding_dimension: Option<u32>,
    pub error_code: Option<ModelRuntimeErrorCode>,
    pub error_message: Option<String>,
}

pub struct ModelRuntimeCoordinator {
    active_tests: Mutex<HashSet<String>>,
    request_timeout: Duration,
}

impl Default for ModelRuntimeCoordinator {
    fn default() -> Self {
        Self::new(CONNECTION_TEST_TIMEOUT)
    }
}

impl ModelRuntimeCoordinator {
    pub fn new(request_timeout: Duration) -> Self {
        Self {
            active_tests: Mutex::new(HashSet::new()),
            request_timeout,
        }
    }

    fn acquire(&self, profile_id: &str) -> Result<TestPermit<'_>, ModelRuntimeError> {
        let mut active = self
            .active_tests
            .lock()
            .map_err(|_| runtime_error(ModelRuntimeErrorCode::ConnectionTestFailed))?;
        if !active.insert(profile_id.to_string()) {
            return Err(runtime_error(
                ModelRuntimeErrorCode::ConnectionTestInProgress,
            ));
        }
        Ok(TestPermit {
            coordinator: self,
            profile_id: profile_id.to_string(),
        })
    }
}

struct TestPermit<'a> {
    coordinator: &'a ModelRuntimeCoordinator,
    profile_id: String,
}

impl Drop for TestPermit<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.coordinator.active_tests.lock() {
            active.remove(&self.profile_id);
        }
    }
}

pub struct ModelRuntimeService<'a, R, S>
where
    R: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    profiles: &'a R,
    secrets: &'a S,
    coordinator: &'a ModelRuntimeCoordinator,
}

impl<'a, R, S> ModelRuntimeService<'a, R, S>
where
    R: ModelProfileRepository,
    S: SecretStore + ?Sized,
{
    pub fn new(profiles: &'a R, secrets: &'a S, coordinator: &'a ModelRuntimeCoordinator) -> Self {
        Self {
            profiles,
            secrets,
            coordinator,
        }
    }

    pub fn resolve_active_chat_provider(&self) -> Result<ResolvedChatProvider, ModelRuntimeError> {
        let profile_id = self.active_profile_id(ModelRuntimePurpose::Chat)?;
        self.resolve_chat_provider(&profile_id)
    }

    pub fn resolve_active_embedding_provider(
        &self,
    ) -> Result<ResolvedEmbeddingProvider, ModelRuntimeError> {
        let profile_id = self.active_profile_id(ModelRuntimePurpose::Embedding)?;
        self.resolve_embedding_provider(&profile_id)
    }

    pub async fn chat_with_active_model(
        &self,
        request: ActiveModelChatRequest,
    ) -> Result<super::ModelResponse, ModelRuntimeError> {
        let resolved = self.resolve_active_chat_provider()?;
        let temperature = resolved
            .profile
            .temperature
            .ok_or_else(|| runtime_error(ModelRuntimeErrorCode::InvalidProfile))?;
        let max_tokens = resolved
            .profile
            .max_tokens
            .ok_or_else(|| runtime_error(ModelRuntimeErrorCode::InvalidProfile))?;
        resolved
            .provider
            .chat(ModelRequest {
                messages: request.messages,
                system_context: request.system_context,
                temperature: temperature as f32,
                max_tokens,
            })
            .await
            .map_err(map_chat_error)
    }

    pub fn resolve_chat_provider(
        &self,
        profile_id: &str,
    ) -> Result<ResolvedChatProvider, ModelRuntimeError> {
        let profile = self.load_profile(profile_id, ModelRuntimePurpose::Chat)?;
        self.build_chat_provider(profile)
    }

    pub fn resolve_embedding_provider(
        &self,
        profile_id: &str,
    ) -> Result<ResolvedEmbeddingProvider, ModelRuntimeError> {
        let profile = self.load_profile(profile_id, ModelRuntimePurpose::Embedding)?;
        self.build_embedding_provider(profile)
    }

    pub async fn test_connection(
        &self,
        request: ModelConnectionTestRequest,
    ) -> ModelConnectionTestResult {
        let started = Instant::now();
        let mut metadata = None;
        let result = match self.coordinator.acquire(&request.profile_id) {
            Ok(_permit) => match self.load_profile(&request.profile_id, request.purpose) {
                Ok(profile) => {
                    metadata = Some(ConnectionMetadata::from(&profile));
                    match request.purpose {
                        ModelRuntimePurpose::Chat => self.test_chat(profile).await,
                        ModelRuntimePurpose::Embedding => self.test_embedding(profile).await,
                    }
                }
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        };

        let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match result {
            Ok(dimension) => ModelConnectionTestResult {
                profile_id: request.profile_id,
                purpose: request.purpose,
                success: true,
                provider_kind: metadata.as_ref().map(|value| value.provider_kind),
                model_name: metadata.map(|value| value.model_name),
                latency_ms,
                embedding_dimension: dimension,
                error_code: None,
                error_message: None,
            },
            Err(error) => ModelConnectionTestResult {
                profile_id: request.profile_id,
                purpose: request.purpose,
                success: false,
                provider_kind: metadata.as_ref().map(|value| value.provider_kind),
                model_name: metadata.map(|value| value.model_name),
                latency_ms,
                embedding_dimension: None,
                error_code: Some(error.code),
                error_message: Some(error.message),
            },
        }
    }

    fn active_profile_id(&self, purpose: ModelRuntimePurpose) -> Result<String, ModelRuntimeError> {
        self.profiles
            .get_active_profile(purpose.profile_purpose())
            .map_err(map_profile_error)?
            .map(|active| active.profile_id)
            .ok_or_else(|| runtime_error(ModelRuntimeErrorCode::NoActiveProfile))
    }

    fn load_profile(
        &self,
        profile_id: &str,
        purpose: ModelRuntimePurpose,
    ) -> Result<ModelProfile, ModelRuntimeError> {
        if profile_id.trim().is_empty() {
            return Err(runtime_error(ModelRuntimeErrorCode::InvalidProfile));
        }
        let profile = self
            .profiles
            .get_profile(profile_id)
            .map_err(map_profile_error)?
            .ok_or_else(|| runtime_error(ModelRuntimeErrorCode::ProfileNotFound))?;
        if profile.purpose != purpose.profile_purpose() {
            return Err(runtime_error(ModelRuntimeErrorCode::ProfilePurposeMismatch));
        }
        validate_runtime_profile(&profile, purpose)?;
        Ok(profile)
    }

    fn secret_for(
        &self,
        profile_id: &str,
        purpose: ModelRuntimePurpose,
    ) -> Result<crate::secrets::SecretValue, ModelRuntimeError> {
        let identifier = SecretIdentifier::new(purpose.secret_purpose(), profile_id.to_string())
            .map_err(|_| runtime_error(ModelRuntimeErrorCode::InvalidProfile))?;
        self.secrets.get_secret(&identifier).map_err(|error| {
            if error.code == SecretStoreErrorCode::NotFound {
                runtime_error(ModelRuntimeErrorCode::CredentialNotFound)
            } else {
                runtime_error(ModelRuntimeErrorCode::ProviderInitializationFailed)
            }
        })
    }

    fn build_chat_provider(
        &self,
        profile: ModelProfile,
    ) -> Result<ResolvedChatProvider, ModelRuntimeError> {
        let secret = self.secret_for(&profile.id, ModelRuntimePurpose::Chat)?;
        let provider = OpenAICompatibleProvider::new_with_secret(
            profile.base_url.clone(),
            profile.model_name.clone(),
            secret,
            self.coordinator.request_timeout,
        )
        .map_err(|_| runtime_error(ModelRuntimeErrorCode::ProviderInitializationFailed))?;
        Ok(ResolvedChatProvider {
            profile: resolved_profile(&profile, ModelRuntimePurpose::Chat),
            provider,
        })
    }

    fn build_embedding_provider(
        &self,
        profile: ModelProfile,
    ) -> Result<ResolvedEmbeddingProvider, ModelRuntimeError> {
        let secret = self.secret_for(&profile.id, ModelRuntimePurpose::Embedding)?;
        let dimension = profile
            .embedding_dimension
            .ok_or_else(|| runtime_error(ModelRuntimeErrorCode::InvalidProfile))?;
        let expected_dimension = usize::try_from(dimension)
            .map_err(|_| runtime_error(ModelRuntimeErrorCode::InvalidProfile))?;
        let provider = OpenAICompatibleEmbeddingProvider::new(
            OpenAICompatibleEmbeddingConfig {
                base_url: profile.base_url.clone(),
                model_name: profile.model_name.clone(),
                expected_dimension: Some(expected_dimension),
            },
            RuntimeEmbeddingApiKey::from_secret(secret),
            EmbeddingRuntimeOptions {
                timeout: self.coordinator.request_timeout,
                ..EmbeddingRuntimeOptions::default()
            },
        )
        .map_err(|_| runtime_error(ModelRuntimeErrorCode::ProviderInitializationFailed))?;
        Ok(ResolvedEmbeddingProvider {
            profile: resolved_profile(&profile, ModelRuntimePurpose::Embedding),
            provider,
        })
    }

    async fn test_chat(&self, profile: ModelProfile) -> Result<Option<u32>, ModelRuntimeError> {
        let resolved = self.build_chat_provider(profile)?;
        let max_tokens = resolved
            .profile
            .max_tokens
            .unwrap_or(CHAT_TEST_MAX_TOKENS)
            .min(CHAT_TEST_MAX_TOKENS);
        resolved
            .provider
            .chat(ModelRequest {
                messages: vec![ModelMessage {
                    role: ModelMessageRole::User,
                    content: CHAT_TEST_TEXT.to_string(),
                }],
                system_context: None,
                temperature: 0.0,
                max_tokens,
            })
            .await
            .map_err(map_chat_error)?;
        Ok(None)
    }

    async fn test_embedding(
        &self,
        profile: ModelProfile,
    ) -> Result<Option<u32>, ModelRuntimeError> {
        let resolved = self.build_embedding_provider(profile)?;
        let response = resolved
            .provider
            .embed(EmbeddingRequest {
                texts: vec![EMBEDDING_TEST_TEXT.to_string()],
                purpose: EmbeddingPurpose::Query,
            })
            .await
            .map_err(map_embedding_error)?;
        let dimension = u32::try_from(response.dimension)
            .map_err(|_| runtime_error(ModelRuntimeErrorCode::DimensionMismatch))?;
        Ok(Some(dimension))
    }
}

struct ConnectionMetadata {
    provider_kind: ModelProviderKind,
    model_name: String,
}

impl From<&ModelProfile> for ConnectionMetadata {
    fn from(profile: &ModelProfile) -> Self {
        Self {
            provider_kind: profile.provider_kind,
            model_name: profile.model_name.clone(),
        }
    }
}

fn resolved_profile(profile: &ModelProfile, purpose: ModelRuntimePurpose) -> ResolvedModelProfile {
    ResolvedModelProfile {
        profile_id: profile.id.clone(),
        purpose,
        provider_kind: profile.provider_kind,
        display_name: profile.display_name.clone(),
        base_url: profile.base_url.clone(),
        model_name: profile.model_name.clone(),
        temperature: profile.temperature,
        max_tokens: profile.max_tokens,
        embedding_dimension: profile.embedding_dimension,
    }
}

fn validate_runtime_profile(
    profile: &ModelProfile,
    purpose: ModelRuntimePurpose,
) -> Result<(), ModelRuntimeError> {
    if profile.id.trim().is_empty()
        || profile.display_name.trim().is_empty()
        || profile.base_url.trim().is_empty()
        || profile.model_name.trim().is_empty()
    {
        return Err(runtime_error(ModelRuntimeErrorCode::InvalidProfile));
    }
    let base_url = Url::parse(&profile.base_url)
        .map_err(|_| runtime_error(ModelRuntimeErrorCode::InvalidProfile))?;
    if !matches!(base_url.scheme(), "http" | "https")
        || base_url.host_str().is_none()
        || !base_url.username().is_empty()
        || base_url.password().is_some()
        || base_url.query().is_some()
        || base_url.fragment().is_some()
    {
        return Err(runtime_error(ModelRuntimeErrorCode::InvalidProfile));
    }
    match profile.provider_kind {
        ModelProviderKind::OpenaiCompatible => {}
    }
    let valid_parameters = match purpose {
        ModelRuntimePurpose::Chat => {
            profile
                .temperature
                .is_some_and(|value| value.is_finite() && (0.0..=2.0).contains(&value))
                && profile
                    .max_tokens
                    .is_some_and(|value| (1..=1_000_000).contains(&value))
                && profile.embedding_dimension.is_none()
        }
        ModelRuntimePurpose::Embedding => {
            profile.temperature.is_none()
                && profile.max_tokens.is_none()
                && profile
                    .embedding_dimension
                    .is_some_and(|value| (1..=65_536).contains(&value))
        }
    };
    if !valid_parameters {
        return Err(runtime_error(ModelRuntimeErrorCode::InvalidProfile));
    }
    Ok(())
}

fn map_profile_error(error: ModelProfileError) -> ModelRuntimeError {
    let code = match error.code {
        ModelProfileErrorCode::ProfileNotFound => ModelRuntimeErrorCode::ProfileNotFound,
        ModelProfileErrorCode::PurposeMismatch => ModelRuntimeErrorCode::ProfilePurposeMismatch,
        ModelProfileErrorCode::UnsupportedProvider => ModelRuntimeErrorCode::UnsupportedProvider,
        _ => ModelRuntimeErrorCode::InvalidProfile,
    };
    runtime_error(code)
}

fn map_chat_error(error: ModelError) -> ModelRuntimeError {
    let code = match error.code.as_str() {
        "MODEL_AUTHENTICATION_FAILED" => ModelRuntimeErrorCode::AuthenticationFailed,
        "MODEL_RATE_LIMITED" => ModelRuntimeErrorCode::RateLimited,
        "MODEL_NETWORK_UNAVAILABLE" => ModelRuntimeErrorCode::NetworkUnavailable,
        "MODEL_REQUEST_TIMEOUT" => ModelRuntimeErrorCode::RequestTimeout,
        "MODEL_RESPONSE_INVALID" | "MODEL_RESPONSE_EMPTY" => {
            ModelRuntimeErrorCode::InvalidProviderResponse
        }
        _ => ModelRuntimeErrorCode::InvalidProviderResponse,
    };
    runtime_error(code)
}

fn map_embedding_error(error: EmbeddingError) -> ModelRuntimeError {
    let code = match error.code {
        EmbeddingErrorCode::AuthenticationFailed => ModelRuntimeErrorCode::AuthenticationFailed,
        EmbeddingErrorCode::RateLimited => ModelRuntimeErrorCode::RateLimited,
        EmbeddingErrorCode::NetworkError => ModelRuntimeErrorCode::NetworkUnavailable,
        EmbeddingErrorCode::RequestTimeout => ModelRuntimeErrorCode::RequestTimeout,
        EmbeddingErrorCode::InvalidProviderResponse => {
            ModelRuntimeErrorCode::InvalidProviderResponse
        }
        EmbeddingErrorCode::DimensionMismatch => ModelRuntimeErrorCode::DimensionMismatch,
        _ => ModelRuntimeErrorCode::ConnectionTestFailed,
    };
    runtime_error(code)
}

fn runtime_error(code: ModelRuntimeErrorCode) -> ModelRuntimeError {
    let (message, recoverable) = match code {
        ModelRuntimeErrorCode::NoActiveProfile => ("No active model profile is configured.", true),
        ModelRuntimeErrorCode::ProfileNotFound => ("The model profile was not found.", true),
        ModelRuntimeErrorCode::ProfilePurposeMismatch => (
            "The model profile purpose does not match the request.",
            false,
        ),
        ModelRuntimeErrorCode::CredentialNotFound => {
            ("No credential is stored for this model profile.", true)
        }
        ModelRuntimeErrorCode::UnsupportedProvider => {
            ("The model provider is not supported.", false)
        }
        ModelRuntimeErrorCode::InvalidProfile => ("The model profile is invalid.", false),
        ModelRuntimeErrorCode::ProviderInitializationFailed => {
            ("The model provider could not be initialized.", true)
        }
        ModelRuntimeErrorCode::AuthenticationFailed => {
            ("The model service rejected authentication.", false)
        }
        ModelRuntimeErrorCode::RateLimited => ("The model service rate limit was reached.", true),
        ModelRuntimeErrorCode::NetworkUnavailable => ("The model service is unavailable.", true),
        ModelRuntimeErrorCode::RequestTimeout => ("The model request timed out.", true),
        ModelRuntimeErrorCode::InvalidProviderResponse => {
            ("The model service returned an invalid response.", true)
        }
        ModelRuntimeErrorCode::DimensionMismatch => {
            ("The embedding dimension does not match the profile.", false)
        }
        ModelRuntimeErrorCode::ConnectionTestFailed => ("The model connection test failed.", true),
        ModelRuntimeErrorCode::ConnectionTestInProgress => (
            "A connection test is already running for this profile.",
            true,
        ),
    };
    ModelRuntimeError::new(code, message, recoverable)
}

#[cfg(windows)]
#[tauri::command]
pub async fn chat_with_active_model(
    storage: State<'_, StorageService>,
    secrets: State<'_, WindowsCredentialSecretStore>,
    coordinator: State<'_, ModelRuntimeCoordinator>,
    request: ActiveModelChatRequest,
) -> Result<super::ModelResponse, ModelRuntimeError> {
    ModelRuntimeService::new(storage.inner(), secrets.inner(), coordinator.inner())
        .chat_with_active_model(request)
        .await
}

#[cfg(windows)]
#[tauri::command]
pub async fn test_model_profile_connection(
    storage: State<'_, StorageService>,
    secrets: State<'_, WindowsCredentialSecretStore>,
    coordinator: State<'_, ModelRuntimeCoordinator>,
    request: ModelConnectionTestRequest,
) -> Result<ModelConnectionTestResult, ModelRuntimeError> {
    Ok(
        ModelRuntimeService::new(storage.inner(), secrets.inner(), coordinator.inner())
            .test_connection(request)
            .await,
    )
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        sync::mpsc::{self, Receiver},
        thread::{self, JoinHandle},
        time::Duration,
    };

    use tempfile::TempDir;

    use crate::{
        model::profile::{
            CreateModelProfileRequest, ListModelProfilesRequest, ModelProfileService,
            SetActiveModelProfileRequest,
        },
        secrets::{InMemorySecretStore, SecretStore, SecretValue},
    };

    use super::*;

    const TEST_CREDENTIAL_PLACEHOLDER: &str = "runtime-test-placeholder";

    struct MockHttpServer {
        pub base_url: String,
        body_receiver: Receiver<String>,
        handle: Option<JoinHandle<()>>,
    }

    impl MockHttpServer {
        fn start(status: u16, response_body: &str, delay: Duration) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let (body_sender, body_receiver) = mpsc::channel();
            let response_body = response_body.to_string();
            let handle = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let body = read_request_body(&mut stream);
                body_sender.send(body).unwrap();
                if status == 0 {
                    return;
                }
                thread::sleep(delay);
                let reason = match status {
                    200 => "OK",
                    401 => "Unauthorized",
                    429 => "Too Many Requests",
                    _ => "Error",
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    response_body.len(),
                    response_body
                );
                let _ = stream.write_all(response.as_bytes());
            });
            Self {
                base_url: format!("http://{address}/v1"),
                body_receiver,
                handle: Some(handle),
            }
        }

        fn request_body(&self) -> String {
            self.body_receiver
                .recv_timeout(Duration::from_secs(2))
                .unwrap()
        }
    }

    impl Drop for MockHttpServer {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                handle.join().unwrap();
            }
        }
    }

    fn read_request_body(stream: &mut TcpStream) -> String {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 1024];
        let mut expected_length = None;
        let mut body_start = None;
        loop {
            let read = stream.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read]);
            if body_start.is_none() {
                body_start = bytes
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                    .map(|position| position + 4);
                if let Some(start) = body_start {
                    let headers = String::from_utf8_lossy(&bytes[..start]);
                    expected_length = headers.lines().find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|value| value.trim().parse::<usize>().ok())
                    });
                }
            }
            if let (Some(start), Some(length)) = (body_start, expected_length) {
                if bytes.len() >= start + length {
                    return String::from_utf8(bytes[start..start + length].to_vec()).unwrap();
                }
            }
        }
        String::new()
    }

    fn test_storage() -> (TempDir, StorageService) {
        let root = tempfile::tempdir().unwrap();
        let storage =
            StorageService::initialize_with_roots(root.path().join("data"), None).unwrap();
        (root, storage)
    }

    fn create_chat(storage: &StorageService, name: &str, base_url: &str) -> ModelProfile {
        create_chat_with_config(storage, name, base_url, "chat-model", 0.7, 4096)
    }

    fn create_chat_with_config(
        storage: &StorageService,
        name: &str,
        base_url: &str,
        model_name: &str,
        temperature: f64,
        max_tokens: u32,
    ) -> ModelProfile {
        ModelProfileService::new(storage)
            .create(CreateModelProfileRequest {
                purpose: ModelPurpose::Chat,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: name.into(),
                base_url: base_url.into(),
                model_name: model_name.into(),
                temperature: Some(temperature),
                max_tokens: Some(max_tokens),
                embedding_dimension: None,
            })
            .unwrap()
    }

    fn create_embedding(
        storage: &StorageService,
        name: &str,
        base_url: &str,
        dimension: u32,
    ) -> ModelProfile {
        ModelProfileService::new(storage)
            .create(CreateModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                provider_kind: ModelProviderKind::OpenaiCompatible,
                display_name: name.into(),
                base_url: base_url.into(),
                model_name: "embedding-model".into(),
                temperature: None,
                max_tokens: None,
                embedding_dimension: Some(dimension),
            })
            .unwrap()
    }

    fn store_credential(
        secrets: &InMemorySecretStore,
        purpose: ModelRuntimePurpose,
        profile_id: &str,
    ) {
        secrets
            .set_secret(
                &SecretIdentifier::new(purpose.secret_purpose(), profile_id).unwrap(),
                SecretValue::new(TEST_CREDENTIAL_PLACEHOLDER.into()).unwrap(),
            )
            .unwrap();
    }

    fn request(profile: &ModelProfile, purpose: ModelRuntimePurpose) -> ModelConnectionTestRequest {
        ModelConnectionTestRequest {
            profile_id: profile.id.clone(),
            purpose,
        }
    }

    fn chat_response() -> &'static str {
        r#"{"model":"chat-model","choices":[{"message":{"content":"mock-response-body"},"finish_reason":"stop"}]}"#
    }

    fn active_chat_request() -> ActiveModelChatRequest {
        ActiveModelChatRequest {
            messages: vec![ModelMessage {
                role: ModelMessageRole::User,
                content: "hello active model".into(),
            }],
            system_context: Some("governed persona context".into()),
        }
    }

    fn embedding_response(dimension: usize) -> String {
        let values = (0..dimension)
            .map(|index| (index + 1).to_string())
            .collect::<Vec<_>>()
            .join(",");
        format!(r#"{{"model":"embedding-model","data":[{{"index":0,"embedding":[{values}]}}]}}"#)
    }

    #[test]
    fn resolves_active_chat_and_embedding_profiles_with_isolated_credentials() {
        let (_root, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let coordinator = ModelRuntimeCoordinator::default();
        let chat = create_chat(&storage, "Chat", "http://127.0.0.1:9/v1");
        let embedding = create_embedding(&storage, "Embedding", "http://127.0.0.1:9/v1", 2);
        let profiles = ModelProfileService::new(&storage);
        profiles
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Chat,
                profile_id: chat.id.clone(),
            })
            .unwrap();
        profiles
            .set_active(SetActiveModelProfileRequest {
                purpose: ModelPurpose::Embedding,
                profile_id: embedding.id.clone(),
            })
            .unwrap();
        store_credential(&secrets, ModelRuntimePurpose::Chat, &chat.id);
        store_credential(&secrets, ModelRuntimePurpose::Embedding, &embedding.id);

        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
        let resolved_chat = runtime.resolve_active_chat_provider().unwrap();
        let resolved_embedding = runtime.resolve_active_embedding_provider().unwrap();
        assert_eq!(resolved_chat.profile.profile_id, chat.id);
        assert_eq!(resolved_chat.profile.temperature, Some(0.7));
        assert_eq!(resolved_embedding.profile.profile_id, embedding.id);
        assert_eq!(resolved_embedding.profile.embedding_dimension, Some(2));
    }

    #[test]
    fn active_chat_uses_profile_configuration_and_returns_provider_response() {
        tauri::async_runtime::block_on(async {
            let server = MockHttpServer::start(200, chat_response(), Duration::ZERO);
            let (_root, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let chat = create_chat_with_config(
                &storage,
                "Active Chat",
                &server.base_url,
                "active-chat-model",
                0.35,
                321,
            );
            ModelProfileService::new(&storage)
                .set_active(SetActiveModelProfileRequest {
                    purpose: ModelPurpose::Chat,
                    profile_id: chat.id.clone(),
                })
                .unwrap();
            store_credential(&secrets, ModelRuntimePurpose::Chat, &chat.id);

            let response = ModelRuntimeService::new(&storage, &secrets, &coordinator)
                .chat_with_active_model(active_chat_request())
                .await
                .unwrap();
            let body = server.request_body();

            assert_eq!(response.text, "mock-response-body");
            assert!(body.contains(r#""model":"active-chat-model""#));
            assert!(body.contains(r#""temperature":0.35"#));
            assert!(body.contains(r#""max_tokens":321"#));
            assert!(body.contains("governed persona context"));
            assert!(body.contains("hello active model"));
            assert!(!body.contains(TEST_CREDENTIAL_PLACEHOLDER));
        });
    }

    #[test]
    fn active_chat_never_auto_selects_and_requires_chat_credential() {
        tauri::async_runtime::block_on(async {
            let (_root, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let chat = create_chat(&storage, "Unselected", "http://127.0.0.1:9/v1");
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);

            assert_eq!(
                runtime
                    .chat_with_active_model(active_chat_request())
                    .await
                    .unwrap_err()
                    .code,
                ModelRuntimeErrorCode::NoActiveProfile
            );

            ModelProfileService::new(&storage)
                .set_active(SetActiveModelProfileRequest {
                    purpose: ModelPurpose::Chat,
                    profile_id: chat.id.clone(),
                })
                .unwrap();
            store_credential(&secrets, ModelRuntimePurpose::Embedding, &chat.id);
            assert_eq!(
                runtime
                    .chat_with_active_model(active_chat_request())
                    .await
                    .unwrap_err()
                    .code,
                ModelRuntimeErrorCode::CredentialNotFound
            );
        });
    }

    #[test]
    fn deleting_active_chat_profile_leaves_no_implicit_fallback() {
        tauri::async_runtime::block_on(async {
            let (_root, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let active = create_chat(&storage, "Active", "http://127.0.0.1:9/v1");
            let _fallback = create_chat(&storage, "Not selected", "http://127.0.0.1:9/v1");
            let profiles = ModelProfileService::new(&storage);
            profiles
                .set_active(SetActiveModelProfileRequest {
                    purpose: ModelPurpose::Chat,
                    profile_id: active.id.clone(),
                })
                .unwrap();
            store_credential(&secrets, ModelRuntimePurpose::Chat, &active.id);
            profiles.delete(&active.id).unwrap();

            let error = ModelRuntimeService::new(&storage, &secrets, &coordinator)
                .chat_with_active_model(active_chat_request())
                .await
                .unwrap_err();
            assert_eq!(error.code, ModelRuntimeErrorCode::NoActiveProfile);
        });
    }

    #[test]
    fn active_chat_resolves_profile_again_after_switch() {
        tauri::async_runtime::block_on(async {
            let first_server = MockHttpServer::start(200, chat_response(), Duration::ZERO);
            let second_server = MockHttpServer::start(200, chat_response(), Duration::ZERO);
            let (_root, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let first = create_chat_with_config(
                &storage,
                "First",
                &first_server.base_url,
                "first-model",
                0.2,
                100,
            );
            let second = create_chat_with_config(
                &storage,
                "Second",
                &second_server.base_url,
                "second-model",
                0.8,
                200,
            );
            store_credential(&secrets, ModelRuntimePurpose::Chat, &first.id);
            store_credential(&secrets, ModelRuntimePurpose::Chat, &second.id);
            let profiles = ModelProfileService::new(&storage);
            profiles
                .set_active(SetActiveModelProfileRequest {
                    purpose: ModelPurpose::Chat,
                    profile_id: first.id.clone(),
                })
                .unwrap();
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            runtime
                .chat_with_active_model(active_chat_request())
                .await
                .unwrap();
            profiles
                .set_active(SetActiveModelProfileRequest {
                    purpose: ModelPurpose::Chat,
                    profile_id: second.id.clone(),
                })
                .unwrap();
            runtime
                .chat_with_active_model(active_chat_request())
                .await
                .unwrap();

            assert!(first_server
                .request_body()
                .contains(r#""model":"first-model""#));
            assert!(second_server
                .request_body()
                .contains(r#""model":"second-model""#));
        });
    }

    #[test]
    fn active_chat_request_rejects_frontend_model_and_secret_fields() {
        for forbidden in [
            "apiKey",
            "baseUrl",
            "modelName",
            "profileId",
            "providerKind",
            "authorization",
            "temperature",
            "maxTokens",
        ] {
            let mut value = serde_json::json!({
                "messages": [{"role": "user", "content": "hello"}],
                "systemContext": null
            });
            value[forbidden] = serde_json::Value::String("forbidden".into());
            assert!(serde_json::from_value::<ActiveModelChatRequest>(value).is_err());
        }
    }

    #[test]
    fn resolution_reports_missing_active_profile_profile_purpose_and_credential() {
        let (_root, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let coordinator = ModelRuntimeCoordinator::default();
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
        let chat = create_chat(&storage, "Chat", "http://127.0.0.1:9/v1");
        assert_eq!(
            runtime.resolve_active_chat_provider().err().unwrap().code,
            ModelRuntimeErrorCode::NoActiveProfile
        );
        assert_eq!(
            runtime.resolve_chat_provider("missing").err().unwrap().code,
            ModelRuntimeErrorCode::ProfileNotFound
        );

        assert_eq!(
            runtime
                .resolve_embedding_provider(&chat.id)
                .err()
                .unwrap()
                .code,
            ModelRuntimeErrorCode::ProfilePurposeMismatch
        );
        assert_eq!(
            runtime.resolve_chat_provider(&chat.id).err().unwrap().code,
            ModelRuntimeErrorCode::CredentialNotFound
        );
        store_credential(&secrets, ModelRuntimePurpose::Chat, &chat.id);
        let invalid_coordinator = ModelRuntimeCoordinator::new(Duration::ZERO);
        assert_eq!(
            ModelRuntimeService::new(&storage, &secrets, &invalid_coordinator)
                .resolve_chat_provider(&chat.id)
                .err()
                .unwrap()
                .code,
            ModelRuntimeErrorCode::ProviderInitializationFailed
        );
    }

    #[test]
    fn chat_and_embedding_credentials_cannot_be_reused_across_purposes() {
        let (_root, storage) = test_storage();
        let secrets = InMemorySecretStore::new();
        let coordinator = ModelRuntimeCoordinator::default();
        let embedding = create_embedding(&storage, "Embedding", "http://127.0.0.1:9/v1", 2);
        store_credential(&secrets, ModelRuntimePurpose::Chat, &embedding.id);
        let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
        assert_eq!(
            runtime
                .resolve_embedding_provider(&embedding.id)
                .err()
                .unwrap()
                .code,
            ModelRuntimeErrorCode::CredentialNotFound
        );
    }

    #[test]
    fn unsupported_provider_errors_are_not_silently_fallbacked() {
        let error = map_profile_error(ModelProfileError::unsupported_provider());
        assert_eq!(error.code, ModelRuntimeErrorCode::UnsupportedProvider);
    }

    #[test]
    fn chat_connection_test_is_minimal_and_returns_no_response_body() {
        tauri::async_runtime::block_on(async {
            let server = MockHttpServer::start(200, chat_response(), Duration::ZERO);
            let (_root, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let chat = create_chat(&storage, "Chat", &server.base_url);
            store_credential(&secrets, ModelRuntimePurpose::Chat, &chat.id);
            let before = ModelProfileService::new(&storage)
                .list(ListModelProfilesRequest { purpose: None })
                .unwrap();
            let result = ModelRuntimeService::new(&storage, &secrets, &coordinator)
                .test_connection(request(&chat, ModelRuntimePurpose::Chat))
                .await;
            let body = server.request_body();
            assert!(result.success);
            assert_eq!(result.embedding_dimension, None);
            assert!(body.contains(CHAT_TEST_TEXT));
            assert!(body.contains(r#""temperature":0.0"#));
            assert!(body.contains(r#""max_tokens":8"#));
            assert!(!body.contains("persona"));
            assert!(!body.contains("memory"));
            let serialized = serde_json::to_string(&result).unwrap();
            assert!(!serialized.contains("mock-response-body"));
            assert!(!serialized.contains(TEST_CREDENTIAL_PLACEHOLDER));
            let after = ModelProfileService::new(&storage)
                .list(ListModelProfilesRequest { purpose: None })
                .unwrap();
            assert_eq!(before, after);
        });
    }

    #[test]
    fn embedding_connection_test_returns_only_validated_dimension() {
        tauri::async_runtime::block_on(async {
            let server = MockHttpServer::start(200, &embedding_response(2), Duration::ZERO);
            let (_root, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let embedding = create_embedding(&storage, "Embedding", &server.base_url, 2);
            store_credential(&secrets, ModelRuntimePurpose::Embedding, &embedding.id);
            let result = ModelRuntimeService::new(&storage, &secrets, &coordinator)
                .test_connection(request(&embedding, ModelRuntimePurpose::Embedding))
                .await;
            let body = server.request_body();
            assert!(result.success);
            assert_eq!(result.embedding_dimension, Some(2));
            assert!(body.contains(EMBEDDING_TEST_TEXT));
            let serialized = serde_json::to_string(&result).unwrap();
            assert!(!serialized.contains("embedding\":["));
            assert!(!serialized.contains(TEST_CREDENTIAL_PLACEHOLDER));
        });
    }

    #[test]
    fn embedding_dimension_mismatch_is_rejected() {
        tauri::async_runtime::block_on(async {
            let server = MockHttpServer::start(200, &embedding_response(3), Duration::ZERO);
            let (_root, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let embedding = create_embedding(&storage, "Embedding", &server.base_url, 2);
            store_credential(&secrets, ModelRuntimePurpose::Embedding, &embedding.id);
            let result = ModelRuntimeService::new(&storage, &secrets, &coordinator)
                .test_connection(request(&embedding, ModelRuntimePurpose::Embedding))
                .await;
            assert!(!result.success);
            assert_eq!(
                result.error_code,
                Some(ModelRuntimeErrorCode::DimensionMismatch)
            );
        });
    }

    #[test]
    fn authentication_rate_limit_invalid_response_network_and_timeout_are_mapped() {
        tauri::async_runtime::block_on(async {
            for (status, body, expected) in [
                (401, "{}", ModelRuntimeErrorCode::AuthenticationFailed),
                (429, "{}", ModelRuntimeErrorCode::RateLimited),
                (
                    200,
                    "not-json",
                    ModelRuntimeErrorCode::InvalidProviderResponse,
                ),
            ] {
                let server = MockHttpServer::start(status, body, Duration::ZERO);
                let (_root, storage) = test_storage();
                let secrets = InMemorySecretStore::new();
                let coordinator = ModelRuntimeCoordinator::default();
                let chat = create_chat(&storage, "Chat", &server.base_url);
                store_credential(&secrets, ModelRuntimePurpose::Chat, &chat.id);
                let result = ModelRuntimeService::new(&storage, &secrets, &coordinator)
                    .test_connection(request(&chat, ModelRuntimePurpose::Chat))
                    .await;
                assert_eq!(result.error_code, Some(expected));
                assert!(!result
                    .error_message
                    .as_deref()
                    .unwrap_or_default()
                    .contains(TEST_CREDENTIAL_PLACEHOLDER));
            }

            let unavailable_server = MockHttpServer::start(0, "", Duration::ZERO);
            let (_root, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::new(Duration::from_millis(100));
            let chat = create_chat(&storage, "Network", &unavailable_server.base_url);
            store_credential(&secrets, ModelRuntimePurpose::Chat, &chat.id);
            let result = ModelRuntimeService::new(&storage, &secrets, &coordinator)
                .test_connection(request(&chat, ModelRuntimePurpose::Chat))
                .await;
            assert_eq!(
                result.error_code,
                Some(ModelRuntimeErrorCode::NetworkUnavailable)
            );

            let server = MockHttpServer::start(200, chat_response(), Duration::from_millis(200));
            let (_root, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::new(Duration::from_millis(30));
            let chat = create_chat(&storage, "Timeout", &server.base_url);
            store_credential(&secrets, ModelRuntimePurpose::Chat, &chat.id);
            let result = ModelRuntimeService::new(&storage, &secrets, &coordinator)
                .test_connection(request(&chat, ModelRuntimePurpose::Chat))
                .await;
            assert_eq!(
                result.error_code,
                Some(ModelRuntimeErrorCode::RequestTimeout)
            );
        });
    }

    #[test]
    fn concurrent_tests_are_limited_per_profile_but_independent_across_profiles() {
        tauri::async_runtime::block_on(async {
            let server = MockHttpServer::start(200, chat_response(), Duration::from_millis(100));
            let (_root, storage) = test_storage();
            let secrets = InMemorySecretStore::new();
            let coordinator = ModelRuntimeCoordinator::default();
            let chat = create_chat(&storage, "Same", &server.base_url);
            store_credential(&secrets, ModelRuntimePurpose::Chat, &chat.id);
            let runtime = ModelRuntimeService::new(&storage, &secrets, &coordinator);
            let (first, second) = futures::join!(
                runtime.test_connection(request(&chat, ModelRuntimePurpose::Chat)),
                runtime.test_connection(request(&chat, ModelRuntimePurpose::Chat))
            );
            let results = [first, second];
            assert_eq!(results.iter().filter(|result| result.success).count(), 1);
            assert_eq!(
                results
                    .iter()
                    .filter(|result| {
                        result.error_code == Some(ModelRuntimeErrorCode::ConnectionTestInProgress)
                    })
                    .count(),
                1
            );

            let first_server =
                MockHttpServer::start(200, chat_response(), Duration::from_millis(50));
            let second_server =
                MockHttpServer::start(200, chat_response(), Duration::from_millis(50));
            let first_profile = create_chat(&storage, "First", &first_server.base_url);
            let second_profile = create_chat(&storage, "Second", &second_server.base_url);
            store_credential(&secrets, ModelRuntimePurpose::Chat, &first_profile.id);
            store_credential(&secrets, ModelRuntimePurpose::Chat, &second_profile.id);
            let (first, second) = futures::join!(
                runtime.test_connection(request(&first_profile, ModelRuntimePurpose::Chat)),
                runtime.test_connection(request(&second_profile, ModelRuntimePurpose::Chat))
            );
            assert!(first.success);
            assert!(second.success);
        });
    }

    #[test]
    fn command_surface_has_no_plaintext_credential_reader() {
        let source = include_str!("../lib.rs");
        assert!(source.contains("model::runtime::chat_with_active_model"));
        assert!(source.contains("model::runtime::test_model_profile_connection"));
        assert!(!source.contains("model::chat_with_model"));
        assert!(!source.contains("get_api_key"));
        assert!(!source.contains("read_credential"));
    }
}
