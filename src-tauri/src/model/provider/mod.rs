#![allow(dead_code)]

//! Credential-safe, low-level provider request adapters.
//!
//! This module deliberately accepts prepared JSON bytes only. Prompt assembly,
//! provider response schemas, and retry policy remain outside this boundary.

mod error;
mod openai_compatible;
mod response;
mod vision;

#[allow(unused_imports)]
pub(crate) use error::{
    ProviderCredentialError, ProviderError, ProviderErrorKind, ProviderResponseClass,
};
#[allow(unused_imports)]
pub(crate) use openai_compatible::{
    OpenAiCompatibleProvider, OpenAiCompatibleProviderConfig, ProviderJsonRequest,
    SensitiveProviderExecutionError, SensitiveProviderJsonRequest,
};
pub(crate) use response::ProviderHttpResponse;
#[allow(unused_imports)]
pub(crate) use vision::{
    build_screen_vision_request, parse_screen_vision_analysis, validate_screen_vision_profile,
    ScreenVisionAnalysis, ScreenVisionResponseError, ScreenVisionResponseErrorCode,
    SCREEN_VISION_SAFETY_INSTRUCTION,
};
