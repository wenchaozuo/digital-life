use hyper::http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE},
    HeaderMap, HeaderValue, Method,
};
use zeroize::Zeroizing;

use crate::{
    model::{
        profile::{credential_purpose, ModelProfile, ModelProviderKind},
        transport::{
            http1::{exchange, PreparedHttpRequest},
            url_policy::{validate_and_normalize_url, ValidatedTransportTarget},
            MAX_REQUEST_BODY_BYTES,
        },
    },
    secrets::{SecretIdentifier, SecretStore, SecretValue},
};

use super::{ProviderError, ProviderErrorKind, ProviderHttpResponse};

const CHAT_COMPLETIONS_PATH: &str = "chat/completions";
const EMBEDDINGS_PATH: &str = "embeddings";

/// A controlled, validated provider/profile binding. Its fields are private so
/// an endpoint and a credential reference cannot be supplied independently.
pub(crate) struct OpenAiCompatibleProviderConfig {
    target: ValidatedTransportTarget,
    origin_form: String,
    credential: SecretIdentifier,
    model_name: String,
}

impl OpenAiCompatibleProviderConfig {
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
        let secret = self
            .secrets
            .get_secret(&config.credential)
            .map_err(|error| ProviderError::from_secret_error(error.code))?;
        self.execute_with_secret(config, request, secret).await
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
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            return Ok(ProviderHttpResponse::new(status, response.body().to_vec()));
        }
        Err(ProviderError::from_status(status_kind(status), status))
    }
}

fn origin_form_for(target: &ValidatedTransportTarget, profile: &ModelProfile) -> String {
    let endpoint = match profile.purpose {
        crate::model::profile::ModelPurpose::Embedding => EMBEDDINGS_PATH,
        crate::model::profile::ModelPurpose::Chat
        | crate::model::profile::ModelPurpose::CandidateExtraction => CHAT_COMPLETIONS_PATH,
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
