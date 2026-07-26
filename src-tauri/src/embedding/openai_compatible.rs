//! Borrowed OpenAI-compatible embedding adapter over the D-8 provider chain.

use crate::{
    model::{
        profile::{ModelProfile, ModelPurpose},
        provider::{OpenAiCompatibleProvider, OpenAiCompatibleProviderConfig},
    },
    secrets::SecretStore,
};

use super::{
    protocol::{
        self, build_provider_request, decode_response_envelope, validate_dimension_limits,
        validate_documents, MAX_VECTOR_DIMENSION,
    },
    EmbeddingError, EmbeddingErrorCode, EmbeddingFuture, EmbeddingModelInfo, EmbeddingProvider,
    EmbeddingRequest, EmbeddingResponse,
};

/// Long-lived adapter: controlled config + SecretStore borrow only.
pub struct OpenAiCompatibleEmbeddingProvider<'s, S>
where
    S: SecretStore + ?Sized,
{
    config: OpenAiCompatibleProviderConfig,
    secrets: &'s S,
    model_name: String,
    expected_dimension: usize,
}

impl<'s, S> OpenAiCompatibleEmbeddingProvider<'s, S>
where
    S: SecretStore + ?Sized,
{
    fn try_new(profile: &ModelProfile, secrets: &'s S) -> Result<Self, EmbeddingError> {
        if profile.purpose != ModelPurpose::Embedding {
            return Err(EmbeddingError::definitely_not_sent(
                EmbeddingErrorCode::InvalidRequest,
                "The model profile purpose is not valid for embedding.",
            ));
        }
        if profile.model_name.trim().is_empty() {
            return Err(EmbeddingError::definitely_not_sent(
                EmbeddingErrorCode::InvalidRequest,
                "An embedding model name is required.",
            ));
        }
        let dimension = profile.embedding_dimension.ok_or_else(|| {
            EmbeddingError::definitely_not_sent(
                EmbeddingErrorCode::InvalidRequest,
                "The embedding dimension is required.",
            )
        })?;
        let expected_dimension = usize::try_from(dimension).map_err(|_| {
            EmbeddingError::definitely_not_sent(
                EmbeddingErrorCode::InvalidRequest,
                "The embedding dimension is invalid.",
            )
        })?;
        if expected_dimension == 0 || expected_dimension > MAX_VECTOR_DIMENSION {
            return Err(EmbeddingError::definitely_not_sent(
                EmbeddingErrorCode::InvalidRequest,
                "The embedding dimension is invalid.",
            ));
        }

        let config = build_provider_config(profile)?;
        Ok(Self {
            config,
            secrets,
            model_name: profile.model_name.clone(),
            expected_dimension,
        })
    }
}

impl<S> std::fmt::Debug for OpenAiCompatibleEmbeddingProvider<'_, S>
where
    S: SecretStore + ?Sized,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenAiCompatibleEmbeddingProvider")
            .field("protocol", &protocol::PROTOCOL_VERSION)
            .field("expected_dimension", &self.expected_dimension)
            .finish()
    }
}

impl<S> EmbeddingProvider for OpenAiCompatibleEmbeddingProvider<'_, S>
where
    S: SecretStore + ?Sized + Sync,
{
    fn model_info(&self) -> EmbeddingModelInfo {
        EmbeddingModelInfo {
            model_name: self.model_name.clone(),
            dimension: Some(self.expected_dimension),
        }
    }

    fn model_name(&self) -> &str {
        &self.model_name
    }

    fn vector_dimension(&self) -> Option<usize> {
        Some(self.expected_dimension)
    }

    fn max_batch_size(&self) -> usize {
        protocol::MAX_EMBEDDING_BATCH_MEMORIES
    }

    fn embed<'a>(
        &'a self,
        request: EmbeddingRequest,
    ) -> EmbeddingFuture<'a, Result<EmbeddingResponse, EmbeddingError>> {
        Box::pin(async move {
            validate_documents(&request.texts)?;
            validate_dimension_limits(self.expected_dimension, request.texts.len())?;
            let provider_request = build_provider_request(&self.model_name, &request.texts)?;
            let provider = OpenAiCompatibleProvider::new(self.secrets);
            let response = provider
                .execute(&self.config, provider_request)
                .await
                .map_err(EmbeddingError::from_provider_error)?;
            let batch = decode_response_envelope(
                response.body(),
                &self.model_name,
                request.texts.len(),
                self.expected_dimension,
            )?;
            Ok(batch.into_public_response(self.model_name.clone()))
        })
    }
}

/// Crate-internal factory. Lifetime is bound to the borrowed SecretStore.
pub(crate) fn build_openai_compatible_embedding_provider<'s, S>(
    profile: &ModelProfile,
    secrets: &'s S,
) -> Result<Box<dyn EmbeddingProvider + 's>, EmbeddingError>
where
    S: SecretStore + ?Sized + Sync,
{
    let provider = OpenAiCompatibleEmbeddingProvider::try_new(profile, secrets)?;
    Ok(Box::new(provider))
}

fn build_provider_config(
    profile: &ModelProfile,
) -> Result<OpenAiCompatibleProviderConfig, EmbeddingError> {
    match OpenAiCompatibleProviderConfig::from_profile(profile) {
        Ok(config) => Ok(config),
        Err(production_error) => {
            #[cfg(test)]
            {
                if let Ok(config) =
                    OpenAiCompatibleProviderConfig::from_embedding_loopback_profile_for_test(
                        profile,
                    )
                {
                    return Ok(config);
                }
            }
            Err(EmbeddingError::from_provider_error(production_error))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::{
        model::{
            profile::{ModelProviderKind, ModelPurpose},
            transport::http1::SendDisposition,
        },
        secrets::{
            InMemorySecretStore, SecretIdentifier, SecretPurpose, SecretStatus, SecretStore,
            SecretStoreError, SecretValue,
        },
    };

    struct CountingStore {
        inner: InMemorySecretStore,
        reads: AtomicUsize,
    }

    impl CountingStore {
        fn new() -> Self {
            Self {
                inner: InMemorySecretStore::new(),
                reads: AtomicUsize::new(0),
            }
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl SecretStore for CountingStore {
        fn set_secret(
            &self,
            identifier: &SecretIdentifier,
            value: SecretValue,
        ) -> Result<SecretStatus, SecretStoreError> {
            self.inner.set_secret(identifier, value)
        }

        fn get_secret(
            &self,
            identifier: &SecretIdentifier,
        ) -> Result<SecretValue, SecretStoreError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.inner.get_secret(identifier)
        }

        fn has_secret(&self, identifier: &SecretIdentifier) -> Result<bool, SecretStoreError> {
            self.inner.has_secret(identifier)
        }

        fn delete_secret(
            &self,
            identifier: &SecretIdentifier,
        ) -> Result<SecretStatus, SecretStoreError> {
            self.inner.delete_secret(identifier)
        }
    }

    fn embedding_profile(base_url: &str, dimension: u32) -> ModelProfile {
        ModelProfile {
            id: "emb-profile".into(),
            purpose: ModelPurpose::Embedding,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "Embedding".into(),
            base_url: base_url.into(),
            model_name: "test-embedding-model".into(),
            temperature: None,
            max_tokens: None,
            embedding_dimension: Some(dimension),
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    fn seed(store: &CountingStore, profile_id: &str) {
        store
            .set_secret(
                &SecretIdentifier::new(SecretPurpose::EmbeddingModelApiKey, profile_id).unwrap(),
                SecretValue::new("d9b-test-canary-never-log".into()).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn purpose_mismatch_reads_zero_credentials() {
        let store = CountingStore::new();
        let mut profile = embedding_profile("https://provider.example.invalid/v1", 3);
        profile.purpose = ModelPurpose::Chat;
        let err = OpenAiCompatibleEmbeddingProvider::try_new(&profile, &store).unwrap_err();
        assert_eq!(err.code, EmbeddingErrorCode::InvalidRequest);
        assert_eq!(err.disposition(), SendDisposition::DefinitelyNotSent);
        assert_eq!(store.reads(), 0);
    }

    #[test]
    fn invalid_input_reads_zero_credentials_and_never_executes() {
        let store = CountingStore::new();
        seed(&store, "emb-profile");
        let profile = embedding_profile("https://provider.example.invalid/v1", 3);
        let provider = OpenAiCompatibleEmbeddingProvider::try_new(&profile, &store).unwrap();
        let err = tauri::async_runtime::block_on(provider.embed(EmbeddingRequest {
            texts: vec![],
            purpose: super::super::EmbeddingPurpose::Document,
        }))
        .unwrap_err();
        assert_eq!(err.code, EmbeddingErrorCode::InvalidRequest);
        assert_eq!(err.disposition(), SendDisposition::DefinitelyNotSent);
        assert_eq!(store.reads(), 0);
        assert!(!format!("{provider:?}").contains("d9b-test-canary-never-log"));
        assert!(!format!("{provider:?}").contains("provider.example"));
    }

    #[test]
    fn dimension_over_limit_rejected_before_credential_read() {
        let store = CountingStore::new();
        seed(&store, "emb-profile");
        let profile = embedding_profile("https://provider.example.invalid/v1", 4097);
        let err = OpenAiCompatibleEmbeddingProvider::try_new(&profile, &store).unwrap_err();
        assert_eq!(err.code, EmbeddingErrorCode::InvalidRequest);
        assert_eq!(store.reads(), 0);
    }

    #[test]
    fn missing_credential_is_definitely_not_sent_and_reads_once_on_embed() {
        let store = CountingStore::new();
        let profile = embedding_profile("https://provider.example.invalid/v1", 3);
        let provider = OpenAiCompatibleEmbeddingProvider::try_new(&profile, &store).unwrap();
        assert_eq!(store.reads(), 0);
        let err = tauri::async_runtime::block_on(provider.embed(EmbeddingRequest {
            texts: vec!["hello".into()],
            purpose: super::super::EmbeddingPurpose::Query,
        }))
        .unwrap_err();
        assert_eq!(err.disposition(), SendDisposition::DefinitelyNotSent);
        assert_eq!(store.reads(), 1);
        assert!(!format!("{err:?}").contains("d9b-test-canary-never-log"));
    }

    #[test]
    fn loopback_test_seam_is_used_for_embedding_loopback_profiles() {
        let store = CountingStore::new();
        seed(&store, "emb-profile");
        let profile = embedding_profile("http://127.0.0.1:9/v1", 3);
        // Construction succeeds via cfg(test) seam without reading secrets.
        let provider = OpenAiCompatibleEmbeddingProvider::try_new(&profile, &store).unwrap();
        assert_eq!(store.reads(), 0);
        assert_eq!(provider.model_name(), "test-embedding-model");
        assert_eq!(provider.vector_dimension(), Some(3));
    }

    #[test]
    fn factory_returns_borrowed_trait_object() {
        let store = CountingStore::new();
        let profile = embedding_profile("http://127.0.0.1:9/v1", 2);
        let provider = build_openai_compatible_embedding_provider(&profile, &store).unwrap();
        assert_eq!(provider.model_name(), "test-embedding-model");
    }
}
