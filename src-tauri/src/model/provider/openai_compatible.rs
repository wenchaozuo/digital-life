use hyper::http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderMap, HeaderValue, Method,
};
use zeroize::Zeroizing;

use crate::{
    model::{
        profile::{credential_purpose, ModelProfile, ModelProviderKind, ModelPurpose},
        transport::{
            http1::{
                exchange, exchange_sensitive, PreparedHttpRequest, PreparedSensitiveHttpRequest,
            },
            url_policy::{validate_and_normalize_url, ValidatedTransportTarget},
            MAX_REQUEST_BODY_BYTES, MAX_SENSITIVE_REQUEST_BODY_BYTES,
        },
    },
    secrets::{SecretIdentifier, SecretStore, SecretValue},
};

use super::{ProviderError, ProviderErrorKind, ProviderHttpResponse};

#[cfg(test)]
use crate::model::transport::url_policy::TransportTargetKind;

const CHAT_COMPLETIONS_PATH: &str = "chat/completions";
const EMBEDDINGS_PATH: &str = "embeddings";

/// A controlled, validated provider/profile binding. Its fields are private so
/// an endpoint and a credential reference cannot be supplied independently.
pub(crate) struct OpenAiCompatibleProviderConfig {
    target: ValidatedTransportTarget,
    origin_form: String,
    credential: SecretIdentifier,
    model_name: String,
    purpose: ModelPurpose,
}

impl OpenAiCompatibleProviderConfig {
    /// Resolves the provider binding from a profile while requiring the
    /// caller's intended model purpose to match the SQLite profile purpose.
    pub(crate) fn from_profile_for_purpose(
        profile: &ModelProfile,
        expected_purpose: ModelPurpose,
    ) -> Result<Self, ProviderError> {
        if profile.purpose != expected_purpose {
            return Err(ProviderError::definitely_not_sent(
                ProviderErrorKind::InvalidConfiguration,
            ));
        }
        Self::from_profile(profile)
    }

    pub(crate) fn from_vision_profile(profile: &ModelProfile) -> Result<Self, ProviderError> {
        Self::from_profile_for_purpose(profile, ModelPurpose::Vision)
    }

    pub(crate) fn from_profile(profile: &ModelProfile) -> Result<Self, ProviderError> {
        if profile.provider_kind != ModelProviderKind::OpenaiCompatible
            || profile.model_name.trim().is_empty()
        {
            return Err(ProviderError::definitely_not_sent(
                ProviderErrorKind::InvalidConfiguration,
            ));
        }

        let target = validate_and_normalize_url(&profile.base_url).map_err(|_| {
            ProviderError::definitely_not_sent(ProviderErrorKind::InvalidConfiguration)
        })?;
        if !target.allows_stored_api_key() {
            return Err(ProviderError::definitely_not_sent(
                ProviderErrorKind::InvalidConfiguration,
            ));
        }

        Self::assemble_from_validated_profile(profile, target)
    }

    /// Test-only Embedding LoopbackHttp seam. Production `from_profile` still
    /// rejects loopback stored keys; this constructor never ships in non-test builds.
    #[cfg(test)]
    pub(crate) fn from_embedding_loopback_profile_for_test(
        profile: &ModelProfile,
    ) -> Result<Self, ProviderError> {
        if profile.purpose != ModelPurpose::Embedding
            || profile.provider_kind != ModelProviderKind::OpenaiCompatible
            || profile.model_name.trim().is_empty()
        {
            return Err(ProviderError::definitely_not_sent(
                ProviderErrorKind::InvalidConfiguration,
            ));
        }

        let target = validate_and_normalize_url(&profile.base_url).map_err(|_| {
            ProviderError::definitely_not_sent(ProviderErrorKind::InvalidConfiguration)
        })?;
        if target.kind() != TransportTargetKind::LoopbackHttp {
            return Err(ProviderError::definitely_not_sent(
                ProviderErrorKind::InvalidConfiguration,
            ));
        }

        Self::assemble_from_validated_profile(profile, target)
    }

    fn assemble_from_validated_profile(
        profile: &ModelProfile,
        target: ValidatedTransportTarget,
    ) -> Result<Self, ProviderError> {
        let credential = SecretIdentifier::new(credential_purpose(profile.purpose), &profile.id)
            .map_err(|_| {
                ProviderError::definitely_not_sent(ProviderErrorKind::InvalidConfiguration)
            })?;
        let origin_form = origin_form_for(&target, profile);
        Ok(Self {
            target,
            origin_form,
            credential,
            model_name: profile.model_name.clone(),
            purpose: profile.purpose,
        })
    }
}

/// Prepared, bounded JSON bytes. This boundary deliberately has no API for
/// arbitrary paths, URLs, headers, or Authorization values.
pub(crate) struct ProviderJsonRequest {
    body: Vec<u8>,
}

impl ProviderJsonRequest {
    pub(crate) fn new(body: Vec<u8>) -> Result<Self, ProviderError> {
        if body.len() as u64 > MAX_REQUEST_BODY_BYTES {
            return Err(ProviderError::definitely_not_sent(
                ProviderErrorKind::RequestTooLarge,
            ));
        }
        std::str::from_utf8(&body)
            .ok()
            .and_then(|_| serde_json::from_slice::<serde_json::Value>(&body).ok())
            .ok_or_else(|| {
                ProviderError::definitely_not_sent(ProviderErrorKind::InvalidJsonRequest)
            })?;
        Ok(Self { body })
    }
}

impl std::fmt::Debug for ProviderJsonRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderJsonRequest")
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Prepared multimodal JSON bytes. The body is intentionally owned by a
/// zeroizing allocation and has no `Clone`, `Serialize`, or body-rendering
/// surface.
pub(crate) struct SensitiveProviderJsonRequest {
    body: Zeroizing<Vec<u8>>,
}

impl SensitiveProviderJsonRequest {
    pub(crate) fn new(body: Zeroizing<Vec<u8>>) -> Result<Self, ProviderError> {
        if body.len() as u64 > MAX_SENSITIVE_REQUEST_BODY_BYTES {
            return Err(ProviderError::definitely_not_sent(
                ProviderErrorKind::RequestTooLarge,
            ));
        }
        if std::str::from_utf8(&body).is_err()
            || serde_json::from_slice::<serde::de::IgnoredAny>(&body).is_err()
        {
            return Err(ProviderError::definitely_not_sent(
                ProviderErrorKind::InvalidJsonRequest,
            ));
        }
        Ok(Self { body })
    }

    pub(crate) fn into_body(self) -> Zeroizing<Vec<u8>> {
        self.body
    }
}

impl std::fmt::Debug for SensitiveProviderJsonRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SensitiveProviderJsonRequest")
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// Stateless provider adapter. API keys are never retained by this struct.
pub(crate) struct OpenAiCompatibleProvider<'a, S: SecretStore + ?Sized> {
    secrets: &'a S,
}

impl<'a, S: SecretStore + ?Sized> OpenAiCompatibleProvider<'a, S> {
    pub(crate) fn new(secrets: &'a S) -> Self {
        Self { secrets }
    }

    pub(crate) async fn execute(
        &self,
        config: &OpenAiCompatibleProviderConfig,
        request: ProviderJsonRequest,
    ) -> Result<ProviderHttpResponse, ProviderError> {
        if config.purpose == ModelPurpose::Vision {
            return Err(ProviderError::definitely_not_sent(
                ProviderErrorKind::InvalidConfiguration,
            ));
        }
        let secret = self
            .secrets
            .get_secret(&config.credential)
            .map_err(|error| ProviderError::from_secret_error(error.code))?;
        self.execute_with_secret(config, request, secret).await
    }

    pub(crate) async fn execute_sensitive(
        &self,
        config: &OpenAiCompatibleProviderConfig,
        request: SensitiveProviderJsonRequest,
    ) -> Result<ProviderHttpResponse, ProviderError> {
        if config.purpose != ModelPurpose::Vision {
            return Err(ProviderError::definitely_not_sent(
                ProviderErrorKind::InvalidConfiguration,
            ));
        }
        let secret = self
            .secrets
            .get_secret(&config.credential)
            .map_err(|error| ProviderError::from_secret_error(error.code))?;
        self.execute_sensitive_with_secret(config, request, secret)
            .await
    }

    async fn execute_with_secret(
        &self,
        config: &OpenAiCompatibleProviderConfig,
        request: ProviderJsonRequest,
        secret: SecretValue,
    ) -> Result<ProviderHttpResponse, ProviderError> {
        let mut authorization = Zeroizing::new(String::with_capacity(
            "Bearer ".len() + secret.expose_secret().len(),
        ));
        authorization.push_str("Bearer ");
        authorization.push_str(secret.expose_secret());
        let authorization_value = HeaderValue::from_str(&authorization)
            .map_err(|_| ProviderError::definitely_not_sent(ProviderErrorKind::RequestRejected))?;

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(AUTHORIZATION, authorization_value);
        let request = PreparedHttpRequest::new(
            Method::POST,
            config.origin_form.clone(),
            headers,
            request.body,
        )
        .map_err(ProviderError::from_transport)?;

        let response = exchange(&config.target, request)
            .await
            .map_err(ProviderError::from_transport)?;
        response_from_transport(response)
    }

    async fn execute_sensitive_with_secret(
        &self,
        config: &OpenAiCompatibleProviderConfig,
        request: SensitiveProviderJsonRequest,
        secret: SecretValue,
    ) -> Result<ProviderHttpResponse, ProviderError> {
        let mut authorization = Zeroizing::new(String::with_capacity(
            "Bearer ".len() + secret.expose_secret().len(),
        ));
        authorization.push_str("Bearer ");
        authorization.push_str(secret.expose_secret());
        let authorization_value = HeaderValue::from_str(&authorization)
            .map_err(|_| ProviderError::definitely_not_sent(ProviderErrorKind::RequestRejected))?;

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(AUTHORIZATION, authorization_value);
        let request = PreparedSensitiveHttpRequest::new(
            Method::POST,
            config.origin_form.clone(),
            headers,
            request.into_body(),
        )
        .map_err(ProviderError::from_transport)?;

        let response = exchange_sensitive(&config.target, request)
            .await
            .map_err(ProviderError::from_transport)?;
        response_from_transport(response)
    }
}

fn response_from_transport(
    response: crate::model::transport::http1::Http1Response,
) -> Result<ProviderHttpResponse, ProviderError> {
    let status = response.status().as_u16();
    if (200..300).contains(&status) {
        return Ok(ProviderHttpResponse::new(status, response.body().to_vec()));
    }
    Err(ProviderError::from_status(status_kind(status), status))
}

fn origin_form_for(target: &ValidatedTransportTarget, profile: &ModelProfile) -> String {
    let endpoint = match profile.purpose {
        crate::model::profile::ModelPurpose::Embedding => EMBEDDINGS_PATH,
        crate::model::profile::ModelPurpose::Chat
        | crate::model::profile::ModelPurpose::CandidateExtraction
        | crate::model::profile::ModelPurpose::Vision => CHAT_COMPLETIONS_PATH,
    };
    let mut origin_form = String::new();
    for segment in target.base_path().segments() {
        origin_form.push('/');
        origin_form.push_str(segment);
    }
    origin_form.push('/');
    origin_form.push_str(endpoint);
    origin_form
}

const fn status_kind(status: u16) -> ProviderErrorKind {
    match status {
        401 | 403 => ProviderErrorKind::AuthenticationRejected,
        408 => ProviderErrorKind::RemoteTimeoutResponse,
        429 => ProviderErrorKind::RateLimited,
        500..=599 => ProviderErrorKind::ProviderUnavailable,
        400..=499 => ProviderErrorKind::RequestRejected,
        _ => ProviderErrorKind::UnexpectedStatus,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        time::{timeout, Duration},
    };
    use zeroize::Zeroizing;

    use crate::{
        model::{
            profile::{ModelProviderKind, ModelPurpose},
            transport::url_policy::validate_and_normalize_url,
        },
        secrets::{
            InMemorySecretStore, SecretIdentifier, SecretPurpose, SecretStatus, SecretStore,
            SecretStoreError, SecretStoreErrorCode, SecretValue,
        },
    };

    use super::*;
    use crate::model::provider::ProviderCredentialError;
    use crate::model::transport::http1::SendDisposition;

    const CANARY: &str = "d8c4-test-canary-never-log";

    fn profile(base_url: String) -> ModelProfile {
        ModelProfile {
            id: "provider-profile".to_string(),
            purpose: ModelPurpose::CandidateExtraction,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "Provider profile".to_string(),
            base_url,
            model_name: "test-model".to_string(),
            temperature: None,
            max_tokens: None,
            embedding_dimension: None,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn json_request() -> ProviderJsonRequest {
        ProviderJsonRequest::new(br#"{"prepared":true}"#.to_vec()).unwrap()
    }

    fn vision_profile(base_url: String) -> ModelProfile {
        ModelProfile {
            id: "vision-provider-profile".to_string(),
            purpose: ModelPurpose::Vision,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "Vision provider profile".to_string(),
            base_url,
            model_name: "vision-model".to_string(),
            temperature: Some(0.0),
            max_tokens: Some(2048),
            embedding_dimension: None,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn test_loopback_config(listener: &TcpListener) -> OpenAiCompatibleProviderConfig {
        let target = validate_and_normalize_url(&format!(
            "http://127.0.0.1:{}/v1",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        OpenAiCompatibleProviderConfig {
            origin_form: origin_form_for(&target, &profile("unused".to_string())),
            target,
            credential: SecretIdentifier::new(
                SecretPurpose::CandidateExtractionModelApiKey,
                "provider-profile",
            )
            .unwrap(),
            model_name: "test-model".to_string(),
            purpose: ModelPurpose::CandidateExtraction,
        }
    }

    fn test_loopback_vision_config(listener: &TcpListener) -> OpenAiCompatibleProviderConfig {
        let target = validate_and_normalize_url(&format!(
            "http://127.0.0.1:{}/v1",
            listener.local_addr().unwrap().port()
        ))
        .unwrap();
        OpenAiCompatibleProviderConfig {
            origin_form: origin_form_for(&target, &vision_profile("unused".to_string())),
            target,
            credential: SecretIdentifier::new(
                SecretPurpose::VisionModelApiKey,
                "vision-provider-profile",
            )
            .unwrap(),
            model_name: "vision-model".to_string(),
            purpose: ModelPurpose::Vision,
        }
    }

    fn seed(store: &InMemorySecretStore) {
        store
            .set_secret(
                &SecretIdentifier::new(
                    SecretPurpose::CandidateExtractionModelApiKey,
                    "provider-profile",
                )
                .unwrap(),
                SecretValue::new(CANARY.to_string()).unwrap(),
            )
            .unwrap();
    }

    fn seed_vision(store: &InMemorySecretStore) {
        store
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::VisionModelApiKey, "vision-provider-profile")
                    .unwrap(),
                SecretValue::new(CANARY.to_string()).unwrap(),
            )
            .unwrap();
    }

    async fn serve_once(listener: TcpListener, status: u16, body: &'static [u8]) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0; 4096];
        let read = stream.read(&mut request).await.unwrap();
        let request = &request[..read];
        assert!(request
            .windows(b"authorization: bearer ".len() + CANARY.len())
            .any(|value| value
                .eq_ignore_ascii_case(format!("authorization: bearer {CANARY}").as_bytes())));
        assert!(request
            .windows(b"content-type: application/json".len())
            .any(|value| value.eq_ignore_ascii_case(b"content-type: application/json")));
        assert!(request
            .windows(b"accept: application/json".len())
            .any(|value| value.eq_ignore_ascii_case(b"accept: application/json")));
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        stream.write_all(body).await.unwrap();
        stream.shutdown().await.unwrap();
        assert!(timeout(Duration::from_millis(30), listener.accept())
            .await
            .is_err());
    }

    #[test]
    fn profile_binding_derives_target_path_and_credential_without_a_caller_reference() {
        let config = OpenAiCompatibleProviderConfig::from_profile(&profile(
            "https://provider.example.invalid/v1".to_string(),
        ))
        .unwrap();
        assert_eq!(config.origin_form, "/v1/chat/completions");
        assert_eq!(config.credential.profile_id, "provider-profile");
        assert_eq!(
            config.credential.purpose,
            SecretPurpose::CandidateExtractionModelApiKey
        );
        assert_eq!(config.model_name, "test-model");
        assert!(OpenAiCompatibleProviderConfig::from_profile(&profile(
            "http://127.0.0.1:8080/v1".to_string(),
        ))
        .is_err());
    }

    #[test]
    fn vision_profile_binding_uses_chat_completions_and_vision_credential_only() {
        let vision = vision_profile("https://vision.example.invalid/v1".to_string());
        let config = OpenAiCompatibleProviderConfig::from_vision_profile(&vision).unwrap();
        assert_eq!(config.origin_form, "/v1/chat/completions");
        assert_eq!(config.credential.profile_id, "vision-provider-profile");
        assert_eq!(config.credential.purpose, SecretPurpose::VisionModelApiKey);
        assert_eq!(config.model_name, "vision-model");
        assert_eq!(config.purpose, ModelPurpose::Vision);
        assert!(OpenAiCompatibleProviderConfig::from_profile_for_purpose(
            &vision,
            ModelPurpose::Chat,
        )
        .is_err());
        assert!(
            OpenAiCompatibleProviderConfig::from_vision_profile(&profile(
                "https://vision.example.invalid/v1".to_string(),
            ))
            .is_err()
        );
    }

    fn embedding_profile(base_url: String) -> ModelProfile {
        ModelProfile {
            id: "embedding-profile".to_string(),
            purpose: ModelPurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "Embedding profile".to_string(),
            base_url,
            model_name: "test-embedding-model".to_string(),
            temperature: None,
            max_tokens: None,
            embedding_dimension: Some(3),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn production_from_profile_rejects_embedding_loopback_stored_key() {
        let result = OpenAiCompatibleProviderConfig::from_profile(&embedding_profile(
            "http://127.0.0.1:9/v1".to_string(),
        ));
        assert!(result.is_err());
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("expected loopback stored-key rejection"),
        };
        assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
        assert_eq!(error.disposition(), SendDisposition::DefinitelyNotSent);
    }

    #[test]
    fn embedding_loopback_test_seam_accepts_only_embedding_loopback_http() {
        let config = OpenAiCompatibleProviderConfig::from_embedding_loopback_profile_for_test(
            &embedding_profile("http://127.0.0.1:9/v1".to_string()),
        )
        .unwrap();
        assert_eq!(config.origin_form, "/v1/embeddings");
        assert_eq!(config.credential.profile_id, "embedding-profile");
        assert_eq!(
            config.credential.purpose,
            SecretPurpose::EmbeddingModelApiKey
        );
        assert_eq!(config.model_name, "test-embedding-model");
        assert_eq!(config.target.kind(), TransportTargetKind::LoopbackHttp);

        assert!(
            OpenAiCompatibleProviderConfig::from_embedding_loopback_profile_for_test(
                &embedding_profile("https://provider.example.invalid/v1".to_string()),
            )
            .is_err()
        );
        assert!(
            OpenAiCompatibleProviderConfig::from_embedding_loopback_profile_for_test(&profile(
                "http://127.0.0.1:9/v1".to_string(),
            ))
            .is_err()
        );
        let mut chat = embedding_profile("http://127.0.0.1:9/v1".to_string());
        chat.purpose = ModelPurpose::Chat;
        assert!(
            OpenAiCompatibleProviderConfig::from_embedding_loopback_profile_for_test(&chat)
                .is_err()
        );
        let mut extraction = embedding_profile("http://127.0.0.1:9/v1".to_string());
        extraction.purpose = ModelPurpose::CandidateExtraction;
        assert!(
            OpenAiCompatibleProviderConfig::from_embedding_loopback_profile_for_test(&extraction)
                .is_err()
        );
    }

    #[test]
    fn json_requests_are_bounded_and_never_render_the_body() {
        let invalid = ProviderJsonRequest::new(b"not json".to_vec()).unwrap_err();
        assert_eq!(invalid.kind(), ProviderErrorKind::InvalidJsonRequest);
        assert_eq!(invalid.disposition(), SendDisposition::DefinitelyNotSent);
        let oversized =
            ProviderJsonRequest::new(vec![b' '; MAX_REQUEST_BODY_BYTES as usize + 1]).unwrap_err();
        assert_eq!(oversized.kind(), ProviderErrorKind::RequestTooLarge);
        assert_eq!(oversized.disposition(), SendDisposition::DefinitelyNotSent);
        assert!(!format!("{invalid:?} {invalid}").contains("not json"));
    }

    struct FailingStore {
        code: SecretStoreErrorCode,
        calls: AtomicUsize,
    }

    impl SecretStore for FailingStore {
        fn set_secret(
            &self,
            _identifier: &SecretIdentifier,
            _value: SecretValue,
        ) -> Result<SecretStatus, SecretStoreError> {
            unreachable!()
        }

        fn get_secret(
            &self,
            _identifier: &SecretIdentifier,
        ) -> Result<SecretValue, SecretStoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(SecretStoreError::new(self.code, CANARY, true))
        }

        fn has_secret(&self, _identifier: &SecretIdentifier) -> Result<bool, SecretStoreError> {
            unreachable!()
        }

        fn delete_secret(
            &self,
            _identifier: &SecretIdentifier,
        ) -> Result<SecretStatus, SecretStoreError> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn credential_errors_are_redacted_definitely_not_sent_and_read_once() {
        let config = OpenAiCompatibleProviderConfig::from_profile(&profile(
            "https://provider.example.invalid/v1".to_string(),
        ))
        .unwrap();
        for (code, expected) in [
            (
                SecretStoreErrorCode::NotFound,
                ProviderCredentialError::NotConfigured,
            ),
            (
                SecretStoreErrorCode::StoreUnavailable,
                ProviderCredentialError::Unavailable,
            ),
            (
                SecretStoreErrorCode::InternalError,
                ProviderCredentialError::ReadFailed,
            ),
        ] {
            let store = FailingStore {
                code,
                calls: AtomicUsize::new(0),
            };
            let error = OpenAiCompatibleProvider::new(&store)
                .execute(&config, json_request())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), ProviderErrorKind::Credential(expected));
            assert_eq!(error.disposition(), SendDisposition::DefinitelyNotSent);
            assert_eq!(store.calls.load(Ordering::SeqCst), 1);
            assert!(!format!("{error:?} {error}").contains(CANARY));
        }
    }

    #[tokio::test]
    async fn a_credential_for_another_purpose_is_not_a_provider_fallback() {
        let config = OpenAiCompatibleProviderConfig::from_profile(&profile(
            "https://provider.example.invalid/v1".to_string(),
        ))
        .unwrap();
        let store = InMemorySecretStore::new();
        store
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::ChatModelApiKey, "provider-profile").unwrap(),
                SecretValue::new(CANARY.to_string()).unwrap(),
            )
            .unwrap();

        let error = OpenAiCompatibleProvider::new(&store)
            .execute(&config, json_request())
            .await
            .unwrap_err();
        assert_eq!(
            error.kind(),
            ProviderErrorKind::Credential(ProviderCredentialError::NotConfigured)
        );
        assert_eq!(error.disposition(), SendDisposition::DefinitelyNotSent);
        assert!(!format!("{error:?} {error}").contains(CANARY));
    }

    #[tokio::test]
    async fn successful_exchange_uses_internal_headers_and_returns_a_bounded_response() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let config = test_loopback_config(&listener);
        let server = tokio::spawn(serve_once(listener, 200, br#"{"ok":true}"#));
        let store = InMemorySecretStore::new();
        seed(&store);
        let response = OpenAiCompatibleProvider::new(&store)
            .execute(&config, json_request())
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(response.body(), br#"{"ok":true}"#);
        assert!(!format!("{response:?}").contains("ok"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn sensitive_vision_exchange_uses_the_dedicated_credential_path() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let config = test_loopback_vision_config(&listener);
        let server = tokio::spawn(serve_once(listener, 200, br#"{"ok":true}"#));
        let store = InMemorySecretStore::new();
        seed_vision(&store);
        let request = SensitiveProviderJsonRequest::new(Zeroizing::new(
            br#"{"synthetic_image":"not-a-screen-pixel"}"#.to_vec(),
        ))
        .unwrap();
        let response = OpenAiCompatibleProvider::new(&store)
            .execute_sensitive(&config, request)
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn regular_provider_path_rejects_vision_before_secret_or_network() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let config = test_loopback_vision_config(&listener);
        let store = InMemorySecretStore::new();
        let request = ProviderJsonRequest::new(br#"{"synthetic":true}"#.to_vec()).unwrap();
        let error = OpenAiCompatibleProvider::new(&store)
            .execute(&config, request)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ProviderErrorKind::InvalidConfiguration);
        assert_eq!(
            error.disposition(),
            crate::model::transport::http1::SendDisposition::DefinitelyNotSent
        );
    }

    #[tokio::test]
    async fn non_success_statuses_are_classified_without_retrying_or_retaining_bodies() {
        for (status, expected) in [
            (401, ProviderErrorKind::AuthenticationRejected),
            (429, ProviderErrorKind::RateLimited),
            (500, ProviderErrorKind::ProviderUnavailable),
            (302, ProviderErrorKind::UnexpectedStatus),
        ] {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let config = test_loopback_config(&listener);
            let server = tokio::spawn(serve_once(listener, status, b"provider-body-canary"));
            let store = InMemorySecretStore::new();
            seed(&store);
            let error = OpenAiCompatibleProvider::new(&store)
                .execute(&config, json_request())
                .await
                .unwrap_err();
            assert_eq!(error.kind(), expected);
            assert_eq!(error.status(), Some(status));
            assert_eq!(error.disposition(), SendDisposition::PossiblySent);
            assert!(!format!("{error:?} {error}").contains("provider-body-canary"));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn post_send_disconnect_preserves_possibly_sent_without_a_second_exchange() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let config = test_loopback_config(&listener);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            drop(stream);
            assert!(timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err());
        });
        let store = InMemorySecretStore::new();
        seed(&store);
        let error = OpenAiCompatibleProvider::new(&store)
            .execute(&config, json_request())
            .await
            .unwrap_err();
        assert_eq!(error.disposition(), SendDisposition::PossiblySent);
        server.await.unwrap();
    }
}
