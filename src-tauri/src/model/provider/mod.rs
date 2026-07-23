#![allow(dead_code)]

//! Credential-safe, low-level provider request adapters.
//!
//! This module deliberately accepts prepared JSON bytes only. Prompt assembly,
//! provider response schemas, and retry policy remain outside this boundary.

mod error;
mod openai_compatible;
mod response;

#[allow(unused_imports)]
pub(crate) use error::{ProviderCredentialError, ProviderError, ProviderErrorKind};
#[allow(unused_imports)]
pub(crate) use openai_compatible::{
    OpenAiCompatibleProvider, OpenAiCompatibleProviderConfig, ProviderJsonRequest,
};
pub(crate) use response::ProviderHttpResponse;
