//! Backend-owned resolution of the active Vision model destination.
//!
//! This module binds the SQLite-authoritative active `vision` profile to the
//! exact D25-D1 destination identity. It intentionally reads no credential and
//! has no Tauri command or screen-pixel path.

use crate::model::profile::{ModelProfileError, ModelProfileErrorCode, ModelProfileRepository};

use super::screen_vision_outbound_destination::{
    ScreenVisionOutboundDestinationBinding, ScreenVisionOutboundDestinationProviderKind,
};
use crate::model::profile::{ModelProviderKind, ModelPurpose};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionDestinationResolverErrorCode {
    ProviderUnavailable,
    ProfileNotFound,
    PurposeMismatch,
    UnsupportedProvider,
    InvalidDestination,
    DatabaseUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionDestinationResolverError {
    code: ScreenVisionDestinationResolverErrorCode,
}

impl ScreenVisionDestinationResolverError {
    pub(crate) const fn code(self) -> ScreenVisionDestinationResolverErrorCode {
        self.code
    }

    fn new(code: ScreenVisionDestinationResolverErrorCode) -> Self {
        Self { code }
    }
}

/// Resolves the destination only from the backend's active Vision profile.
pub(crate) fn resolve_active_screen_vision_destination<R: ModelProfileRepository>(
    repository: &R,
) -> Result<ScreenVisionOutboundDestinationBinding, ScreenVisionDestinationResolverError> {
    let active = repository
        .get_active_profile(ModelPurpose::Vision)
        .map_err(map_profile_error)?
        .ok_or_else(|| {
            ScreenVisionDestinationResolverError::new(
                ScreenVisionDestinationResolverErrorCode::ProviderUnavailable,
            )
        })?;

    let profile = repository
        .get_profile(&active.profile_id)
        .map_err(map_profile_error)?
        .ok_or_else(|| {
            ScreenVisionDestinationResolverError::new(
                ScreenVisionDestinationResolverErrorCode::ProfileNotFound,
            )
        })?;
    if profile.purpose != ModelPurpose::Vision {
        return Err(ScreenVisionDestinationResolverError::new(
            ScreenVisionDestinationResolverErrorCode::PurposeMismatch,
        ));
    }

    let provider_kind = match profile.provider_kind {
        ModelProviderKind::OpenaiCompatible => {
            ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible
        }
    };
    ScreenVisionOutboundDestinationBinding::new(
        profile.id,
        provider_kind,
        profile.base_url,
        profile.model_name,
        profile.updated_at,
    )
    .map_err(|_| {
        ScreenVisionDestinationResolverError::new(
            ScreenVisionDestinationResolverErrorCode::InvalidDestination,
        )
    })
}

#[allow(dead_code)]
pub(crate) struct ScreenVisionOutboundDestinationResolver<'a, R: ModelProfileRepository> {
    repository: &'a R,
}

#[allow(dead_code)]
impl<'a, R: ModelProfileRepository> ScreenVisionOutboundDestinationResolver<'a, R> {
    pub(crate) fn new(repository: &'a R) -> Self {
        Self { repository }
    }

    pub(crate) fn resolve_active_screen_vision_destination(
        &self,
    ) -> Result<ScreenVisionOutboundDestinationBinding, ScreenVisionDestinationResolverError> {
        resolve_active_screen_vision_destination(self.repository)
    }
}

fn map_profile_error(error: ModelProfileError) -> ScreenVisionDestinationResolverError {
    let code = match error.code {
        ModelProfileErrorCode::ProfileNotFound => {
            ScreenVisionDestinationResolverErrorCode::ProfileNotFound
        }
        ModelProfileErrorCode::PurposeMismatch => {
            ScreenVisionDestinationResolverErrorCode::PurposeMismatch
        }
        ModelProfileErrorCode::UnsupportedProvider => {
            ScreenVisionDestinationResolverErrorCode::UnsupportedProvider
        }
        _ => ScreenVisionDestinationResolverErrorCode::DatabaseUnavailable,
    };
    ScreenVisionDestinationResolverError::new(code)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::model::profile::{
        ActiveModelProfile, DeleteModelProfileResult, ModelProfile, ModelProfileError,
    };

    struct FakeRepository {
        profile: RefCell<Option<ModelProfile>>,
        active: Option<ActiveModelProfile>,
        profile_error: Option<ModelProfileError>,
    }

    impl ModelProfileRepository for FakeRepository {
        fn create_profile(
            &self,
            _profile: &ModelProfile,
        ) -> Result<ModelProfile, ModelProfileError> {
            unreachable!()
        }

        fn get_profile(&self, profile_id: &str) -> Result<Option<ModelProfile>, ModelProfileError> {
            if let Some(error) = &self.profile_error {
                return Err(error.clone());
            }
            Ok(self
                .profile
                .borrow()
                .as_ref()
                .filter(|profile| profile.id == profile_id)
                .cloned())
        }

        fn list_profiles(
            &self,
            _purpose: Option<ModelPurpose>,
        ) -> Result<Vec<ModelProfile>, ModelProfileError> {
            unreachable!()
        }

        fn update_profile(
            &self,
            _profile: &ModelProfile,
        ) -> Result<ModelProfile, ModelProfileError> {
            unreachable!()
        }

        fn delete_profile(
            &self,
            _profile_id: &str,
        ) -> Result<DeleteModelProfileResult, ModelProfileError> {
            unreachable!()
        }

        fn set_active_profile(
            &self,
            _purpose: ModelPurpose,
            _profile_id: &str,
        ) -> Result<ActiveModelProfile, ModelProfileError> {
            unreachable!()
        }

        fn get_active_profile(
            &self,
            purpose: ModelPurpose,
        ) -> Result<Option<ActiveModelProfile>, ModelProfileError> {
            Ok(self
                .active
                .clone()
                .filter(|active| active.purpose == purpose))
        }
    }

    fn vision_profile() -> ModelProfile {
        ModelProfile {
            id: "vision-profile".into(),
            purpose: ModelPurpose::Vision,
            provider_kind: ModelProviderKind::OpenaiCompatible,
            display_name: "Vision".into(),
            base_url: "https://vision.example.invalid/v1".into(),
            model_name: "vision-model".into(),
            temperature: Some(0.0),
            max_tokens: Some(1024),
            embedding_dimension: None,
            created_at: "2026-08-31T00:00:00Z".into(),
            updated_at: "2026-08-31T01:00:00Z".into(),
        }
    }

    fn repository(
        profile: Option<ModelProfile>,
        active: Option<ActiveModelProfile>,
    ) -> FakeRepository {
        FakeRepository {
            profile: RefCell::new(profile),
            active,
            profile_error: None,
        }
    }

    #[test]
    fn missing_active_vision_profile_is_provider_unavailable() {
        let repository = repository(None, None);
        let error = match resolve_active_screen_vision_destination(&repository) {
            Ok(_) => panic!("missing active Vision profile must fail closed"),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            ScreenVisionDestinationResolverErrorCode::ProviderUnavailable
        );
    }

    #[test]
    fn chat_only_active_mapping_does_not_fallback_to_chat() {
        let repository = repository(
            Some(vision_profile()),
            Some(ActiveModelProfile {
                purpose: ModelPurpose::Chat,
                profile_id: "vision-profile".into(),
            }),
        );
        let error = match resolve_active_screen_vision_destination(&repository) {
            Ok(_) => panic!("Chat active mapping must not satisfy Vision resolution"),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            ScreenVisionDestinationResolverErrorCode::ProviderUnavailable
        );
    }

    #[test]
    fn valid_active_vision_profile_produces_exact_d1_binding() {
        let repository = repository(
            Some(vision_profile()),
            Some(ActiveModelProfile {
                purpose: ModelPurpose::Vision,
                profile_id: "vision-profile".into(),
            }),
        );
        let binding = resolve_active_screen_vision_destination(&repository).unwrap();
        assert_eq!(binding.profile_id(), "vision-profile");
        assert_eq!(binding.base_url(), "https://vision.example.invalid/v1");
        assert_eq!(binding.model_name(), "vision-model");
        assert_eq!(binding.profile_updated_at(), "2026-08-31T01:00:00Z");
        assert_eq!(
            binding.provider_kind(),
            ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible
        );
    }

    #[test]
    fn active_mapping_to_non_vision_profile_fails_closed() {
        let mut chat = vision_profile();
        chat.purpose = ModelPurpose::Chat;
        let repository = repository(
            Some(chat),
            Some(ActiveModelProfile {
                purpose: ModelPurpose::Vision,
                profile_id: "vision-profile".into(),
            }),
        );
        let error = match resolve_active_screen_vision_destination(&repository) {
            Ok(_) => panic!("a non-Vision profile must not resolve as Vision"),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            ScreenVisionDestinationResolverErrorCode::PurposeMismatch
        );
    }

    #[test]
    fn unsupported_provider_error_is_not_downgraded_to_unavailable() {
        let repository = FakeRepository {
            profile: RefCell::new(None),
            active: Some(ActiveModelProfile {
                purpose: ModelPurpose::Vision,
                profile_id: "vision-profile".into(),
            }),
            profile_error: Some(ModelProfileError::unsupported_provider()),
        };
        let error = match resolve_active_screen_vision_destination(&repository) {
            Ok(_) => panic!("unsupported provider must fail closed"),
            Err(error) => error,
        };
        assert_eq!(
            error.code(),
            ScreenVisionDestinationResolverErrorCode::UnsupportedProvider
        );
    }

    #[test]
    fn profile_update_timestamp_changes_resolved_binding_identity() {
        let repository = repository(
            Some(vision_profile()),
            Some(ActiveModelProfile {
                purpose: ModelPurpose::Vision,
                profile_id: "vision-profile".into(),
            }),
        );
        let first = resolve_active_screen_vision_destination(&repository).unwrap();
        repository.profile.borrow_mut().as_mut().unwrap().updated_at =
            "2026-08-31T02:00:00Z".into();
        let second = resolve_active_screen_vision_destination(&repository).unwrap();
        assert!(!(first == second));
    }
}
