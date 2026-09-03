#![allow(dead_code)]

//! Digital Life-owned provider authority and provider-neutral gateway.
//!
//! The module owns the provider boundary and its transport seams.  The
//! production HTTPS transport is library-only: it is not exposed through the
//! Tauri/frontend, Chat Completions route, or autonomy surfaces in this stage.

use std::fmt::{self, Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::{Host, Url};
use zeroize::Zeroizing;

use super::{VitaAgentError, VITA_AGENT_RUNTIME_ID, VITA_GATEWAY_PROVIDER_ID};

mod production_transport;

#[cfg(test)]
#[path = "d29f.rs"]
mod d29f;

#[cfg(test)]
#[path = "d29g2.rs"]
mod d29g2;

/// The provider wire protocols owned by Digital Life's provider domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderProtocol {
    OpenAiChatCompletions,
    OpenAiResponses,
}

impl Default for ProviderProtocol {
    fn default() -> Self {
        Self::OpenAiChatCompletions
    }
}

impl Display for ProviderProtocol {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::OpenAiChatCompletions => "openai-chat-completions",
            Self::OpenAiResponses => "openai-responses",
        })
    }
}

/// Provider capabilities recognized by the D29-E foundation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderCapability {
    Streaming,
    Tools,
    ParallelTools,
    JsonSchema,
    Images,
    DeveloperRole,
    Reasoning,
}

impl Display for ProviderCapability {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Streaming => "streaming",
            Self::Tools => "tools",
            Self::ParallelTools => "parallel_tools",
            Self::JsonSchema => "json_schema",
            Self::Images => "images",
            Self::DeveloperRole => "developer_role",
            Self::Reasoning => "reasoning",
        })
    }
}

/// Capability claims are part of the Digital Life provider profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCapabilities {
    pub streaming: bool,
    pub tools: bool,
    pub parallel_tools: bool,
    pub json_schema: bool,
    pub images: bool,
    pub developer_role: bool,
    pub reasoning: bool,
}

impl Default for ProviderCapabilities {
    fn default() -> Self {
        Self {
            streaming: false,
            tools: false,
            parallel_tools: false,
            json_schema: false,
            images: false,
            developer_role: false,
            reasoning: false,
        }
    }
}

impl ProviderCapabilities {
    pub const fn none() -> Self {
        Self {
            streaming: false,
            tools: false,
            parallel_tools: false,
            json_schema: false,
            images: false,
            developer_role: false,
            reasoning: false,
        }
    }

    pub const fn supports(&self, capability: ProviderCapability) -> bool {
        match capability {
            ProviderCapability::Streaming => self.streaming,
            ProviderCapability::Tools => self.tools,
            ProviderCapability::ParallelTools => self.parallel_tools,
            ProviderCapability::JsonSchema => self.json_schema,
            ProviderCapability::Images => self.images,
            ProviderCapability::DeveloperRole => self.developer_role,
            ProviderCapability::Reasoning => self.reasoning,
        }
    }
}

/// Bounded retry configuration for future-safe transport retries.  D29-G1-R1
/// permits it only for a connection failure before an HTTP request is
/// established; model-generation HTTP status responses are never replayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderRetryPolicy {
    pub max_retries: u8,
    pub backoff: Duration,
}

impl Default for ProviderRetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 0,
            backoff: Duration::ZERO,
        }
    }
}

impl ProviderRetryPolicy {
    pub const fn new(max_retries: u8, backoff: Duration) -> Self {
        Self {
            max_retries,
            backoff,
        }
    }
}

/// A reference to a Digital Life secret-store entry.
///
/// This type intentionally stores no secret material.  Its custom Debug
/// implementation also redacts the reference identifier so diagnostics do not
/// become an accidental credential inventory.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialRef {
    reference_id: String,
    provider_id: String,
    destination_base_url: String,
}

impl fmt::Debug for CredentialRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialRef")
            .field("reference_id", &"[redacted]")
            .field("provider_id", &self.provider_id)
            .field("destination_base_url", &self.destination_base_url)
            .finish()
    }
}

impl CredentialRef {
    /// Creates a reference bound to one provider and one normalized endpoint.
    pub fn new(
        reference_id: impl Into<String>,
        provider_id: impl Into<String>,
        destination_base_url: impl AsRef<str>,
    ) -> Result<Self, VitaAgentError> {
        let reference_id = reference_id.into();
        if reference_id.trim().is_empty() {
            return Err(VitaAgentError::InvalidProviderProfile {
                field: "credential_ref.reference_id",
                reason: "must not be empty",
            });
        }
        let provider_id = provider_id.into();
        if provider_id.trim().is_empty() {
            return Err(VitaAgentError::InvalidProviderProfile {
                field: "credential_ref.provider_id",
                reason: "must not be empty",
            });
        }

        let destination_base_url = normalize_base_url(destination_base_url.as_ref())?;
        Ok(Self {
            reference_id,
            provider_id,
            destination_base_url,
        })
    }

    pub fn reference_id(&self) -> &str {
        &self.reference_id
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn destination_base_url(&self) -> &str {
        &self.destination_base_url
    }
}

/// An explicit, Digital Life-owned provider profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderProfile {
    provider_id: String,
    display_name: String,
    protocol: ProviderProtocol,
    endpoint: ProviderEndpoint,
    model: String,
    credential_ref: Option<CredentialRef>,
    timeout: Duration,
    retry_policy: ProviderRetryPolicy,
    capabilities: ProviderCapabilities,
}

impl ProviderProfile {
    /// Creates a production provider profile.
    ///
    /// Production provider URLs must be HTTPS and must not be loopback,
    /// private, link-local, multicast, or otherwise non-routable IP targets.
    /// Local HTTP is available only through the test-scoped constructor below.
    pub fn new(
        provider_id: impl Into<String>,
        display_name: impl Into<String>,
        protocol: ProviderProtocol,
        base_url: impl AsRef<str>,
        model: impl Into<String>,
        credential_ref: Option<CredentialRef>,
        timeout: Duration,
        retry_policy: ProviderRetryPolicy,
        capabilities: ProviderCapabilities,
    ) -> Result<Self, VitaAgentError> {
        let endpoint = ProviderEndpoint::parse_production(base_url.as_ref())?;
        Self::from_endpoint(
            provider_id.into(),
            display_name.into(),
            protocol,
            endpoint,
            model.into(),
            credential_ref,
            timeout,
            retry_policy,
            capabilities,
        )
    }

    #[cfg(test)]
    fn new_for_test_localhost(
        provider_id: impl Into<String>,
        display_name: impl Into<String>,
        protocol: ProviderProtocol,
        base_url: impl AsRef<str>,
        model: impl Into<String>,
        credential_ref: Option<CredentialRef>,
        timeout: Duration,
        retry_policy: ProviderRetryPolicy,
        capabilities: ProviderCapabilities,
    ) -> Result<Self, VitaAgentError> {
        let endpoint = ProviderEndpoint::parse_test_localhost(base_url.as_ref())?;
        Self::from_endpoint(
            provider_id.into(),
            display_name.into(),
            protocol,
            endpoint,
            model.into(),
            credential_ref,
            timeout,
            retry_policy,
            capabilities,
        )
    }

    fn from_endpoint(
        provider_id: String,
        display_name: String,
        protocol: ProviderProtocol,
        endpoint: ProviderEndpoint,
        model: String,
        credential_ref: Option<CredentialRef>,
        timeout: Duration,
        retry_policy: ProviderRetryPolicy,
        capabilities: ProviderCapabilities,
    ) -> Result<Self, VitaAgentError> {
        let profile = Self {
            provider_id,
            display_name,
            protocol,
            endpoint,
            model,
            credential_ref,
            timeout,
            retry_policy,
            capabilities,
        };
        profile.validate()?;
        Ok(profile)
    }

    pub fn validate(&self) -> Result<(), VitaAgentError> {
        if self.provider_id.trim().is_empty() {
            return Err(VitaAgentError::InvalidProviderProfile {
                field: "provider_id",
                reason: "must not be empty",
            });
        }
        if self.display_name.trim().is_empty() {
            return Err(VitaAgentError::InvalidProviderProfile {
                field: "display_name",
                reason: "must not be empty",
            });
        }
        if self.model.trim().is_empty() {
            return Err(VitaAgentError::InvalidProviderProfile {
                field: "model",
                reason: "must not be empty",
            });
        }
        if self.timeout.is_zero() {
            return Err(VitaAgentError::InvalidProviderProfile {
                field: "timeout",
                reason: "must be greater than zero",
            });
        }
        if self.timeout > Duration::from_secs(300) {
            return Err(VitaAgentError::InvalidProviderProfile {
                field: "timeout",
                reason: "must be bounded to 300 seconds",
            });
        }
        if self.capabilities.parallel_tools && !self.capabilities.tools {
            return Err(VitaAgentError::InvalidProviderProfile {
                field: "capabilities.parallel_tools",
                reason: "requires capabilities.tools",
            });
        }
        if let Some(credential_ref) = &self.credential_ref {
            if credential_ref.provider_id != self.provider_id
                || credential_ref.destination_base_url != self.endpoint.normalized_base_url
            {
                return Err(VitaAgentError::CredentialBindingMismatch {
                    provider_id: self.provider_id.clone(),
                    endpoint: self.endpoint.normalized_base_url.clone(),
                });
            }
        }
        Ok(())
    }

    pub fn provider_id(&self) -> &str {
        &self.provider_id
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn protocol(&self) -> ProviderProtocol {
        self.protocol
    }

    pub fn base_url(&self) -> &str {
        &self.endpoint.normalized_base_url
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub fn credential_ref(&self) -> Option<&CredentialRef> {
        self.credential_ref.as_ref()
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    pub fn retry_policy(&self) -> ProviderRetryPolicy {
        self.retry_policy
    }

    pub fn capabilities(&self) -> ProviderCapabilities {
        self.capabilities
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointScope {
    Production,
    TestLocalhost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderEndpoint {
    normalized_base_url: String,
    scheme: String,
    host: String,
    port: u16,
    path: String,
    scope: EndpointScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedUrl {
    base_url: String,
    scheme: String,
    host: String,
    port: u16,
    path: String,
    explicit_port: bool,
}

impl ProviderEndpoint {
    fn parse_production(raw: &str) -> Result<Self, VitaAgentError> {
        let normalized = normalize_url(raw)?;
        if normalized.scheme != "https" {
            return Err(invalid_url(raw, "production provider URLs must use HTTPS"));
        }
        if normalized.port == 0 {
            return Err(invalid_url(raw, "provider port must be non-zero"));
        }
        if is_forbidden_network_host(&normalized.host) {
            return Err(invalid_url(
                raw,
                "production provider host is loopback, private, link-local, multicast, or non-routable",
            ));
        }
        Ok(Self::from_normalized(normalized, EndpointScope::Production))
    }

    #[cfg(test)]
    fn parse_test_localhost(raw: &str) -> Result<Self, VitaAgentError> {
        let normalized = normalize_url(raw)?;
        if normalized.scheme != "http"
            || normalized.host != "127.0.0.1"
            || !normalized.explicit_port
            || normalized.port == 0
        {
            return Err(invalid_url(
                raw,
                "test provider endpoint must be explicit http://127.0.0.1:<port>",
            ));
        }
        Ok(Self::from_normalized(
            normalized,
            EndpointScope::TestLocalhost,
        ))
    }

    fn from_normalized(normalized: NormalizedUrl, scope: EndpointScope) -> Self {
        Self {
            normalized_base_url: normalized.base_url,
            scheme: normalized.scheme,
            host: normalized.host,
            port: normalized.port,
            path: normalized.path,
            scope,
        }
    }

    fn request_path(&self, suffix: &str) -> String {
        let suffix = suffix.trim_start_matches('/');
        if self.path == "/" {
            format!("/{suffix}")
        } else {
            format!("{}/{suffix}", self.path.trim_end_matches('/'))
        }
    }

    fn host_header(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    fn is_test_localhost(&self) -> bool {
        self.scope == EndpointScope::TestLocalhost
    }
}

fn normalize_base_url(raw: &str) -> Result<String, VitaAgentError> {
    Ok(normalize_url(raw)?.base_url)
}

fn normalize_url(raw: &str) -> Result<NormalizedUrl, VitaAgentError> {
    if raw.trim() != raw || raw.contains('\\') {
        return Err(invalid_url(
            raw,
            "URL contains surrounding whitespace or backslash",
        ));
    }
    if raw.contains("/../") || raw.ends_with("/..") || raw.contains("/./") || raw.ends_with("/.") {
        return Err(invalid_url(
            raw,
            "URL path traversal segments are not allowed",
        ));
    }
    let parsed = Url::parse(raw).map_err(|_| invalid_url(raw, "URL syntax is invalid"))?;
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(invalid_url(raw, "URL scheme must be http or https"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid_url(raw, "URL userinfo is not allowed"));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid_url(raw, "URL query and fragment are not allowed"));
    }

    let host = match parsed.host() {
        Some(Host::Domain(value)) => value.to_ascii_lowercase(),
        Some(Host::Ipv4(value)) => value.to_string(),
        Some(Host::Ipv6(value)) => value.to_string().to_ascii_lowercase(),
        None => return Err(invalid_url(raw, "URL host is required")),
    };
    if host.ends_with('.') {
        return Err(invalid_url(
            raw,
            "ambiguous trailing-dot host is not allowed",
        ));
    }

    let raw_path = parsed.path();
    let path = if raw_path.is_empty() {
        "/".to_string()
    } else {
        validate_path(raw_path, raw)?;
        let trimmed = raw_path.trim_end_matches('/');
        if trimmed.is_empty() {
            "/".to_string()
        } else {
            trimmed.to_string()
        }
    };

    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| invalid_url(raw, "http or https provider port is required"))?;
    let explicit_port = parsed.port().is_some();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => unreachable!("scheme was checked above"),
    };
    let authority_host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let authority = if explicit_port && port != default_port {
        format!("{authority_host}:{port}")
    } else {
        authority_host
    };
    let base_url = if path == "/" {
        format!("{scheme}://{authority}/")
    } else {
        format!("{scheme}://{authority}{path}")
    };

    Ok(NormalizedUrl {
        base_url,
        scheme,
        host,
        port,
        path,
        explicit_port,
    })
}

fn validate_path(path: &str, raw: &str) -> Result<(), VitaAgentError> {
    let lowercase = path.to_ascii_lowercase();
    if path.contains('\\')
        || lowercase.contains("%2f")
        || lowercase.contains("%5c")
        || lowercase.contains("%2e")
    {
        return Err(invalid_url(
            raw,
            "URL path contains an ambiguous escaped separator",
        ));
    }
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return Err(invalid_url(
            raw,
            "URL path traversal segments are not allowed",
        ));
    }
    Ok(())
}

fn invalid_url(raw: &str, reason: &'static str) -> VitaAgentError {
    VitaAgentError::InvalidProviderUrl {
        url: redact_url_for_error(raw),
        reason,
    }
}

fn redact_url_for_error(raw: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return "<invalid-url>".to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

fn is_forbidden_network_host(host: &str) -> bool {
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    host.parse::<IpAddr>().is_ok_and(is_forbidden_ip)
}

fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(value) => is_forbidden_ipv4(value),
        IpAddr::V6(value) => is_forbidden_ipv6(value),
    }
}

fn is_forbidden_ipv4(value: Ipv4Addr) -> bool {
    let [a, b, c, _d] = value.octets();
    value.is_unspecified()
        || value.is_loopback()
        || value.is_private()
        || value.is_link_local()
        || value.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224
}

fn is_forbidden_ipv6(value: Ipv6Addr) -> bool {
    let segments = value.segments();
    let mapped_ipv4 = if segments[..5] == [0, 0, 0, 0, 0] && segments[5] == 0xffff {
        Some(Ipv4Addr::from([
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        ]))
    } else {
        None
    };
    value.is_unspecified()
        || value.is_loopback()
        || value.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || (segments[0] & 0xffc0) == 0xfec0
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || mapped_ipv4.is_some_and(is_forbidden_ipv4)
}

/// The provider policy state machine used by the gateway foundation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VitaProviderState {
    NotConfigured,
    ConfiguredValidated,
    GatewayReady,
}

impl Display for VitaProviderState {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotConfigured => "NotConfigured",
            Self::ConfiguredValidated => "ConfiguredValidated",
            Self::GatewayReady => "GatewayReady",
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct VitaProviderAuthority {
    state: VitaProviderState,
    profile: Option<ProviderProfile>,
}

impl VitaProviderAuthority {
    pub(crate) fn not_configured() -> Self {
        Self {
            state: VitaProviderState::NotConfigured,
            profile: None,
        }
    }

    pub(crate) fn configure(profile: ProviderProfile) -> Result<Self, VitaAgentError> {
        profile.validate()?;
        Ok(Self {
            state: VitaProviderState::ConfiguredValidated,
            profile: Some(profile),
        })
    }

    pub(crate) fn state(&self) -> VitaProviderState {
        self.state
    }

    pub(crate) fn profile(&self) -> Option<&ProviderProfile> {
        self.profile.as_ref()
    }

    pub(crate) fn prepare_gateway(
        &self,
        binding: VitaGatewayBinding,
    ) -> Result<GatewayReadyProvider, VitaAgentError> {
        let Some(profile) = &self.profile else {
            return Err(VitaAgentError::NotConfiguredProvider);
        };
        if self.state != VitaProviderState::ConfiguredValidated {
            return Err(VitaAgentError::ProviderStateViolation {
                expected: VitaProviderState::ConfiguredValidated,
                actual: self.state,
            });
        }
        profile.validate()?;
        Ok(GatewayReadyProvider::new(profile.clone(), binding))
    }
}

/// The private listener identity used by the derived Codex-facing provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VitaGatewayBinding {
    base_url: String,
    port: u16,
    runtime_identity: &'static str,
}

impl VitaGatewayBinding {
    pub(crate) fn for_owned_private_listener(port: u16) -> Result<Self, VitaAgentError> {
        if port == 0 {
            return Err(VitaAgentError::GatewayProtocol(
                "owned Vita gateway listener must have a non-zero port".to_string(),
            ));
        }
        Ok(Self {
            base_url: format!("http://127.0.0.1:{port}/v1"),
            port,
            runtime_identity: VITA_AGENT_RUNTIME_ID,
        })
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn runtime_identity(&self) -> &'static str {
        self.runtime_identity
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DerivedCodexProvider {
    model_provider_id: &'static str,
    model: String,
    base_url: String,
    wire_api: &'static str,
    requires_openai_auth: bool,
}

impl DerivedCodexProvider {
    fn new(model: &str, binding: &VitaGatewayBinding) -> Self {
        Self {
            model_provider_id: VITA_GATEWAY_PROVIDER_ID,
            model: model.to_string(),
            base_url: binding.base_url.clone(),
            wire_api: "responses",
            requires_openai_auth: false,
        }
    }

    pub(crate) fn model_provider_id(&self) -> &str {
        self.model_provider_id
    }

    pub(crate) fn model(&self) -> &str {
        &self.model
    }

    pub(crate) fn base_url(&self) -> &str {
        &self.base_url
    }

    pub(crate) fn wire_api(&self) -> &str {
        self.wire_api
    }

    pub(crate) fn requires_openai_auth(&self) -> bool {
        self.requires_openai_auth
    }
}

#[derive(Debug, Clone)]
pub(crate) struct GatewayReadyProvider {
    profile: ProviderProfile,
    binding: VitaGatewayBinding,
    derived: DerivedCodexProvider,
}

impl GatewayReadyProvider {
    fn new(profile: ProviderProfile, binding: VitaGatewayBinding) -> Self {
        let derived = DerivedCodexProvider::new(profile.model(), &binding);
        Self {
            profile,
            binding,
            derived,
        }
    }

    pub(crate) fn state(&self) -> VitaProviderState {
        VitaProviderState::GatewayReady
    }

    pub(crate) fn profile(&self) -> &ProviderProfile {
        &self.profile
    }

    pub(crate) fn binding(&self) -> &VitaGatewayBinding {
        &self.binding
    }

    pub(crate) fn derived_codex_provider(&self) -> &DerivedCodexProvider {
        &self.derived
    }
}

/// Resolves a Digital Life credential reference at request time.
///
/// Implementations must keep any resolved secret ephemeral.  The production
/// implementation is deliberately a seam for the future Digital Life Secret
/// Store; it does not read ambient process credentials or stock Codex state.
trait CredentialResolver {
    fn resolve(&self, credential_ref: &CredentialRef)
        -> Result<ResolvedCredential, VitaAgentError>;
}

/// A request-lifetime credential container.
///
/// The raw value is never serializable or persisted.  `zeroize` clears the
/// owned string when this value is dropped, and the custom Debug output keeps
/// the value out of diagnostics.  The HTTP transport creates a separate,
/// typed Authorization header only for the duration of the request.  Digital
/// Life-owned credential buffers are zeroized; reqwest/TLS internal transient
/// header buffers are not guaranteed to be zeroized by Digital Life, but remain
/// non-persistent and non-logged.
pub(crate) struct ResolvedCredential(Zeroizing<String>);

impl ResolvedCredential {
    pub(crate) fn new(secret: impl Into<String>) -> Self {
        Self(Zeroizing::new(secret.into()))
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn validate_header_safety(&self) -> Result<(), VitaAgentError> {
        if self
            .as_bytes()
            .iter()
            .any(|byte| *byte <= 0x20 || *byte == 0x7f)
        {
            return Err(VitaAgentError::CredentialResolution(
                "resolved credential contains unsafe HTTP header bytes",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ResolvedCredential {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ResolvedCredential")
            .field(&"[redacted]")
            .finish()
    }
}

/// The minimum outbound provider transport seam.
///
/// The endpoint and request-lifetime credential are supplied by the already
/// validated Digital Life profile and credential reference, never by ambient
/// process configuration.  Implementations must not follow redirects.
trait ProviderRequestTransport {
    fn post_json(
        &self,
        endpoint: &ProviderEndpoint,
        authorization: Option<&ResolvedCredential>,
        body: &[u8],
        timeout: Duration,
        retry_policy: ProviderRetryPolicy,
    ) -> Result<Vec<u8>, VitaAgentError>;
}

struct ProviderGateway<R, T> {
    ready: GatewayReadyProvider,
    credential_resolver: R,
    transport: T,
}

impl<R, T> ProviderGateway<R, T>
where
    R: CredentialResolver,
    T: ProviderRequestTransport,
{
    fn new(ready: GatewayReadyProvider, credential_resolver: R, transport: T) -> Self {
        Self {
            ready,
            credential_resolver,
            transport,
        }
    }

    fn execute_responses_request(
        &self,
        request: &VitaResponsesRequest,
    ) -> Result<VitaResponsesResult, VitaAgentError> {
        if self.ready.state() != VitaProviderState::GatewayReady {
            return Err(VitaAgentError::GatewayNotReady);
        }
        if request.model != self.ready.profile.model {
            return Err(VitaAgentError::GatewayProtocol(
                "request model must match the validated Digital Life provider profile".to_string(),
            ));
        }
        if self.ready.profile.protocol != ProviderProtocol::OpenAiChatCompletions {
            return Err(VitaAgentError::UnsupportedProviderProtocol {
                protocol: self.ready.profile.protocol,
            });
        }
        // Re-check the provider-to-endpoint binding immediately before any
        // credential lookup.  A future mutable profile store must not be able
        // to move a reference to another provider or destination between
        // configuration validation and request construction.
        self.ready.profile.validate()?;
        // Codex's Responses client requires a streaming Responses response, but
        // D29-F deliberately keeps the downstream Chat mock non-streaming.  The
        // Vita listener owns that protocol boundary: validate the Codex request
        // as streaming, then issue one bounded non-streaming Chat request and
        // re-emit its result as Responses SSE.
        let mut downstream_request = request.clone();
        downstream_request.options.stream = false;
        let mapped = map_responses_request_to_chat(&downstream_request, &self.ready.profile)?;
        let body = serde_json::to_vec(&mapped).map_err(|_| {
            VitaAgentError::GatewayProtocol(
                "could not serialize chat completion request".to_string(),
            )
        })?;
        let credential = self
            .ready
            .profile
            .credential_ref
            .as_ref()
            .map(|reference| self.credential_resolver.resolve(reference))
            .transpose()?;
        if credential
            .as_ref()
            .is_some_and(ResolvedCredential::is_empty)
        {
            return Err(VitaAgentError::CredentialResolution(
                "resolved credential is empty",
            ));
        }
        let response = self.transport.post_json(
            &self.ready.profile.endpoint,
            credential.as_ref(),
            &body,
            self.ready.profile.timeout,
            self.ready.profile.retry_policy,
        )?;
        let response =
            serde_json::from_slice::<ChatCompletionsResponse>(&response).map_err(|_| {
                VitaAgentError::GatewayProtocol(
                    "provider returned invalid chat completion JSON".to_string(),
                )
            })?;
        if response.model != self.ready.profile.model {
            return Err(VitaAgentError::GatewayProtocol(
                "provider response model must match the validated Digital Life provider profile"
                    .to_string(),
            ));
        }
        map_chat_response_to_responses(response)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VitaMessageRole {
    System,
    Developer,
    User,
    Assistant,
}

impl VitaMessageRole {
    fn as_chat_role(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Developer => "developer",
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VitaMessage {
    role: VitaMessageRole,
    content: String,
}

impl VitaMessage {
    pub(crate) fn text(role: VitaMessageRole, content: impl Into<String>) -> Self {
        Self {
            role,
            content: content.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct GatewayToolDefinition {
    pub(crate) name: String,
    pub(crate) description: Option<String>,
    pub(crate) parameters: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct VitaResponsesRequestOptions {
    pub(crate) stream: bool,
    pub(crate) tools: Vec<GatewayToolDefinition>,
    pub(crate) parallel_tools: bool,
    pub(crate) required_capabilities: Vec<ProviderCapability>,
}

impl Default for VitaResponsesRequestOptions {
    fn default() -> Self {
        Self {
            stream: false,
            tools: Vec::new(),
            parallel_tools: false,
            required_capabilities: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct VitaResponsesRequest {
    pub(crate) model: String,
    pub(crate) messages: Vec<VitaMessage>,
    pub(crate) options: VitaResponsesRequestOptions,
}

impl VitaResponsesRequest {
    pub(crate) fn new(
        model: impl Into<String>,
        messages: Vec<VitaMessage>,
        options: VitaResponsesRequestOptions,
    ) -> Self {
        Self {
            model: model.into(),
            messages,
            options,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ChatCompletionsRequest {
    model: String,
    messages: Vec<ChatCompletionsMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    tools: Vec<ChatCompletionsTool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parallel_tool_calls: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ChatCompletionsMessage {
    role: String,
    content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ChatCompletionsTool {
    #[serde(rename = "type")]
    tool_type: String,
    function: ChatCompletionsFunction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct ChatCompletionsFunction {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    parameters: Value,
}

fn map_responses_request_to_chat(
    request: &VitaResponsesRequest,
    profile: &ProviderProfile,
) -> Result<ChatCompletionsRequest, VitaAgentError> {
    if request.model.trim().is_empty() {
        return Err(VitaAgentError::InvalidProviderProfile {
            field: "request.model",
            reason: "must not be empty",
        });
    }

    for capability in request.options.required_capabilities.iter().copied() {
        require_capability(profile.capabilities, capability)?;
        require_gateway_capability(capability)?;
    }

    let has_developer_message = request
        .messages
        .iter()
        .any(|message| message.role == VitaMessageRole::Developer);
    if has_developer_message {
        require_capability(profile.capabilities, ProviderCapability::DeveloperRole)?;
        require_gateway_capability(ProviderCapability::DeveloperRole)?;
    }
    if request.options.stream {
        require_capability(profile.capabilities, ProviderCapability::Streaming)?;
        require_gateway_capability(ProviderCapability::Streaming)?;
    }
    if !request.options.tools.is_empty() {
        require_capability(profile.capabilities, ProviderCapability::Tools)?;
        require_gateway_capability(ProviderCapability::Tools)?;
    }
    if request.options.parallel_tools && !request.options.tools.is_empty() {
        require_capability(profile.capabilities, ProviderCapability::ParallelTools)?;
        require_gateway_capability(ProviderCapability::ParallelTools)?;
    }

    let messages = request
        .messages
        .iter()
        .map(|message| ChatCompletionsMessage {
            role: message.role.as_chat_role().to_string(),
            content: message.content.clone(),
        })
        .collect();
    let tools = request
        .options
        .tools
        .iter()
        .map(|tool| ChatCompletionsTool {
            tool_type: "function".to_string(),
            function: ChatCompletionsFunction {
                name: tool.name.clone(),
                description: tool.description.clone(),
                parameters: tool.parameters.clone(),
            },
        })
        .collect();

    Ok(ChatCompletionsRequest {
        model: request.model.clone(),
        messages,
        stream: request.options.stream,
        tools,
        // A parallel-tool flag has no meaning when there are no tools.  Do
        // not leak that Responses-only control to broad Chat Completions
        // providers on the ordinary no-tools path.
        parallel_tool_calls: (!request.options.tools.is_empty() && request.options.parallel_tools)
            .then_some(true),
    })
}

fn require_capability(
    capabilities: ProviderCapabilities,
    capability: ProviderCapability,
) -> Result<(), VitaAgentError> {
    if capabilities.supports(capability) {
        Ok(())
    } else {
        Err(VitaAgentError::UnsupportedProviderCapability { capability })
    }
}

fn require_gateway_capability(capability: ProviderCapability) -> Result<(), VitaAgentError> {
    if matches!(
        capability,
        ProviderCapability::Streaming
            | ProviderCapability::Tools
            | ProviderCapability::ParallelTools
            | ProviderCapability::DeveloperRole
    ) {
        Ok(())
    } else {
        Err(VitaAgentError::UnsupportedGatewayCapability { capability })
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct ChatCompletionsResponse {
    id: String,
    model: String,
    choices: Vec<ChatCompletionChoice>,
    #[serde(default)]
    usage: Option<ChatUsage>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct ChatCompletionChoice {
    index: u32,
    message: ChatCompletionMessage,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct ChatCompletionMessage {
    role: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct ChatUsage {
    prompt_tokens: u64,
    completion_tokens: u64,
    total_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VitaResponsesResult {
    pub(crate) id: String,
    pub(crate) model: String,
    pub(crate) output_text: String,
    pub(crate) finish_reason: Option<String>,
    pub(crate) usage: Option<VitaUsage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VitaUsage {
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) total_tokens: u64,
}

fn map_chat_response_to_responses(
    response: ChatCompletionsResponse,
) -> Result<VitaResponsesResult, VitaAgentError> {
    if response.choices.len() != 1 {
        return Err(VitaAgentError::GatewayProtocol(
            "chat completion response must contain exactly one choice".to_string(),
        ));
    }
    let choice = response.choices.into_iter().next().expect("length checked");
    if choice.message.role != "assistant" {
        return Err(VitaAgentError::GatewayProtocol(
            "chat completion response message role must be assistant".to_string(),
        ));
    }
    if !choice.message.tool_calls.is_empty() {
        return Err(VitaAgentError::UnsupportedGatewayCapability {
            capability: ProviderCapability::Tools,
        });
    }
    let usage = response.usage.map(|usage| VitaUsage {
        input_tokens: usage.prompt_tokens,
        output_tokens: usage.completion_tokens,
        total_tokens: usage.total_tokens,
    });
    Ok(VitaResponsesResult {
        id: response.id,
        model: response.model,
        output_text: choice.message.content.unwrap_or_default(),
        finish_reason: choice.finish_reason,
        usage,
    })
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct ChatCompletionsStreamChunk {
    id: String,
    model: String,
    #[serde(default)]
    choices: Vec<ChatCompletionChunkChoice>,
    #[serde(default)]
    usage: Option<ChatUsage>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct ChatCompletionChunkChoice {
    delta: ChatCompletionDelta,
    #[serde(default)]
    finish_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
struct ChatCompletionDelta {
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum VitaResponsesEvent {
    OutputTextDelta {
        id: String,
        model: String,
        delta: String,
    },
    Completed {
        id: String,
        model: String,
        finish_reason: Option<String>,
        usage: Option<VitaUsage>,
    },
}

fn map_chat_stream_chunk_to_responses_events(
    chunk: ChatCompletionsStreamChunk,
    capabilities: ProviderCapabilities,
) -> Result<Vec<VitaResponsesEvent>, VitaAgentError> {
    require_capability(capabilities, ProviderCapability::Streaming)?;
    if chunk.choices.len() > 1 {
        return Err(VitaAgentError::GatewayProtocol(
            "stream chunk must contain at most one choice".to_string(),
        ));
    }

    let mut events = Vec::new();
    if let Some(choice) = chunk.choices.into_iter().next() {
        if let Some(role) = choice.delta.role {
            if role != "assistant" {
                return Err(VitaAgentError::GatewayProtocol(
                    "stream delta role must be assistant".to_string(),
                ));
            }
        }
        if !choice.delta.tool_calls.is_empty() {
            return Err(VitaAgentError::UnsupportedGatewayCapability {
                capability: ProviderCapability::Tools,
            });
        }
        if let Some(delta) = choice.delta.content {
            events.push(VitaResponsesEvent::OutputTextDelta {
                id: chunk.id.clone(),
                model: chunk.model.clone(),
                delta,
            });
        }
        if choice.finish_reason.is_some() || chunk.usage.is_some() {
            events.push(VitaResponsesEvent::Completed {
                id: chunk.id.clone(),
                model: chunk.model.clone(),
                finish_reason: choice.finish_reason,
                usage: chunk.usage.map(|usage| VitaUsage {
                    input_tokens: usage.prompt_tokens,
                    output_tokens: usage.completion_tokens,
                    total_tokens: usage.total_tokens,
                }),
            });
        }
    } else if let Some(usage) = chunk.usage {
        events.push(VitaResponsesEvent::Completed {
            id: chunk.id,
            model: chunk.model,
            finish_reason: None,
            usage: Some(VitaUsage {
                input_tokens: usage.prompt_tokens,
                output_tokens: usage.completion_tokens,
                total_tokens: usage.total_tokens,
            }),
        });
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread;

    fn profile(
        base_url: &str,
        credential_ref: Option<CredentialRef>,
        capabilities: ProviderCapabilities,
    ) -> ProviderProfile {
        ProviderProfile::new(
            "provider-one",
            "Provider One",
            ProviderProtocol::OpenAiChatCompletions,
            base_url,
            "mock-model",
            credential_ref,
            Duration::from_secs(10),
            ProviderRetryPolicy::default(),
            capabilities,
        )
        .expect("valid production profile")
    }

    fn test_local_profile(
        base_url: &str,
        credential_ref: Option<CredentialRef>,
        capabilities: ProviderCapabilities,
    ) -> ProviderProfile {
        ProviderProfile::new_for_test_localhost(
            "provider-one",
            "Provider One",
            ProviderProtocol::OpenAiChatCompletions,
            base_url,
            "mock-model",
            credential_ref,
            Duration::from_secs(10),
            ProviderRetryPolicy::default(),
            capabilities,
        )
        .expect("valid test-localhost profile")
    }

    fn all_mapping_capabilities() -> ProviderCapabilities {
        ProviderCapabilities {
            streaming: true,
            tools: true,
            parallel_tools: true,
            json_schema: false,
            images: false,
            developer_role: true,
            reasoning: false,
        }
    }

    #[test]
    fn default_protocol_is_chat_completions_and_responses_is_representable() {
        assert_eq!(
            ProviderProtocol::default(),
            ProviderProtocol::OpenAiChatCompletions
        );
        let responses_profile = ProviderProfile::new(
            "responses-provider",
            "Responses Provider",
            ProviderProtocol::OpenAiResponses,
            "https://provider.example/v1",
            "responses-model",
            None,
            Duration::from_secs(10),
            ProviderRetryPolicy::default(),
            ProviderCapabilities::none(),
        )
        .expect("Responses-native profile is representable");
        assert_eq!(
            responses_profile.protocol(),
            ProviderProtocol::OpenAiResponses
        );
        let request = VitaResponsesRequest::new(
            "responses-model",
            vec![VitaMessage::text(VitaMessageRole::User, "hello")],
            VitaResponsesRequestOptions::default(),
        );
        assert_eq!(request.model, "responses-model");
        assert_eq!(request.messages.len(), 1);
    }

    #[test]
    fn provider_profile_is_authoritative_and_derived_codex_provider_is_gateway_only() {
        let credential = CredentialRef::new(
            "secret-store-entry",
            "provider-one",
            "https://provider.example/v1",
        )
        .unwrap();
        let profile = profile(
            "https://provider.example/v1",
            Some(credential),
            all_mapping_capabilities(),
        );
        assert_eq!(profile.provider_id(), "provider-one");
        assert_eq!(profile.base_url(), "https://provider.example/v1");
        assert_eq!(profile.model(), "mock-model");
        assert!(profile.credential_ref().is_some());

        let authority = VitaProviderAuthority::configure(profile).unwrap();
        assert_eq!(authority.state(), VitaProviderState::ConfiguredValidated);
        assert!(authority.profile().is_some());

        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let binding =
            VitaGatewayBinding::for_owned_private_listener(listener.local_addr().unwrap().port())
                .unwrap();
        let ready = authority.prepare_gateway(binding.clone()).unwrap();
        assert_eq!(ready.state(), VitaProviderState::GatewayReady);
        let derived = ready.derived_codex_provider();
        assert_eq!(derived.model_provider_id(), "vita-gateway");
        assert_eq!(derived.model(), "mock-model");
        assert_eq!(derived.base_url(), binding.base_url());
        assert_eq!(derived.wire_api(), "responses");
        assert!(!derived.requires_openai_auth());
        assert_eq!(binding.runtime_identity(), VITA_AGENT_RUNTIME_ID);
        let diagnostics = format!("{ready:?}");
        assert!(!diagnostics.contains("secret-store-entry"));
        assert!(!diagnostics.contains("sk-"));
    }

    #[test]
    fn credential_ref_contains_binding_only_and_never_raw_material() {
        let credential = CredentialRef::new(
            "named-credential",
            "provider-one",
            "https://provider.example/v1/",
        )
        .unwrap();
        assert_eq!(
            credential.destination_base_url(),
            "https://provider.example/v1"
        );
        let diagnostics = format!("{credential:?}");
        assert!(!diagnostics.contains("named-credential"));
        assert!(!diagnostics.contains("raw-secret-value"));
    }

    #[test]
    fn not_configured_execution_is_forbidden() {
        let authority = VitaProviderAuthority::not_configured();
        assert_eq!(authority.state(), VitaProviderState::NotConfigured);
        let binding = VitaGatewayBinding::for_owned_private_listener(43123).unwrap();
        let error = authority
            .prepare_gateway(binding)
            .expect_err("NotConfigured must not prepare a gateway");
        assert!(matches!(error, VitaAgentError::NotConfiguredProvider));
    }

    #[test]
    fn invalid_provider_urls_are_rejected_and_error_text_redacts_query_material() {
        let invalid_urls = [
            "http://provider.example/v1",
            "http://127.0.0.1:1234/v1",
            "https://user:password@provider.example/v1",
            "https://provider.example/v1?api_key=secret-token",
            "ftp://provider.example/v1",
            "https://provider.example/v1/../private",
        ];
        for raw in invalid_urls {
            let error = ProviderProfile::new(
                "provider-one",
                "Provider One",
                ProviderProtocol::OpenAiChatCompletions,
                raw,
                "mock-model",
                None,
                Duration::from_secs(10),
                ProviderRetryPolicy::default(),
                ProviderCapabilities::none(),
            )
            .expect_err("invalid provider URL must fail closed");
            assert!(matches!(error, VitaAgentError::InvalidProviderUrl { .. }));
            assert!(!error.to_string().contains("secret-token"));
        }
    }

    #[test]
    fn credential_binding_must_match_profile_provider_and_endpoint() {
        let credential = CredentialRef::new(
            "named-credential",
            "other-provider",
            "https://provider.example/v1",
        )
        .unwrap();
        let error = ProviderProfile::new(
            "provider-one",
            "Provider One",
            ProviderProtocol::OpenAiChatCompletions,
            "https://provider.example/v1",
            "mock-model",
            Some(credential),
            Duration::from_secs(10),
            ProviderRetryPolicy::default(),
            ProviderCapabilities::none(),
        )
        .expect_err("credential binding mismatch must fail closed");
        assert!(matches!(
            error,
            VitaAgentError::CredentialBindingMismatch { .. }
        ));
    }

    #[test]
    fn request_mapping_is_deterministic_and_preserves_roles_and_streaming() {
        let profile = profile(
            "https://provider.example/v1",
            None,
            all_mapping_capabilities(),
        );
        let request = VitaResponsesRequest::new(
            "mock-model",
            vec![
                VitaMessage::text(VitaMessageRole::System, "system"),
                VitaMessage::text(VitaMessageRole::Developer, "developer"),
                VitaMessage::text(VitaMessageRole::User, "user"),
                VitaMessage::text(VitaMessageRole::Assistant, "assistant"),
            ],
            VitaResponsesRequestOptions {
                stream: true,
                ..VitaResponsesRequestOptions::default()
            },
        );
        let first = map_responses_request_to_chat(&request, &profile).unwrap();
        let second = map_responses_request_to_chat(&request, &profile).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.model, "mock-model");
        assert!(first.stream);
        assert_eq!(
            first
                .messages
                .iter()
                .map(|message| (message.role.as_str(), message.content.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("system", "system"),
                ("developer", "developer"),
                ("user", "user"),
                ("assistant", "assistant"),
            ]
        );
        assert_eq!(
            serde_json::to_string(&first).unwrap(),
            r#"{"model":"mock-model","messages":[{"role":"system","content":"system"},{"role":"developer","content":"developer"},{"role":"user","content":"user"},{"role":"assistant","content":"assistant"}],"stream":true}"#
        );
    }

    #[test]
    fn tool_definition_mapping_is_explicit_and_deterministic() {
        let profile = profile(
            "https://provider.example/v1",
            None,
            all_mapping_capabilities(),
        );
        let request = VitaResponsesRequest::new(
            "mock-model",
            vec![VitaMessage::text(VitaMessageRole::User, "use the tool")],
            VitaResponsesRequestOptions {
                tools: vec![GatewayToolDefinition {
                    name: "lookup".to_string(),
                    description: Some("Look up a value".to_string()),
                    parameters: json!({"type":"object","properties":{}}),
                }],
                parallel_tools: true,
                ..VitaResponsesRequestOptions::default()
            },
        );
        let mapped = map_responses_request_to_chat(&request, &profile).unwrap();
        assert_eq!(mapped.tools.len(), 1);
        assert_eq!(mapped.tools[0].tool_type, "function");
        assert_eq!(mapped.tools[0].function.name, "lookup");
        assert_eq!(mapped.parallel_tool_calls, Some(true));
        assert_eq!(
            serde_json::to_string(&mapped).unwrap(),
            r#"{"model":"mock-model","messages":[{"role":"user","content":"use the tool"}],"stream":false,"tools":[{"type":"function","function":{"name":"lookup","description":"Look up a value","parameters":{"properties":{},"type":"object"}}}],"parallel_tool_calls":true}"#
        );
    }

    #[test]
    fn empty_tools_omit_parallel_tool_calls_even_when_requested() {
        let profile = profile(
            "https://provider.example/v1",
            None,
            all_mapping_capabilities(),
        );
        let request = VitaResponsesRequest::new(
            "mock-model",
            vec![VitaMessage::text(VitaMessageRole::User, "hello")],
            VitaResponsesRequestOptions {
                parallel_tools: true,
                ..VitaResponsesRequestOptions::default()
            },
        );

        let mapped = map_responses_request_to_chat(&request, &profile).unwrap();
        assert!(mapped.tools.is_empty());
        assert_eq!(mapped.parallel_tool_calls, None);
        assert_eq!(
            serde_json::to_string(&mapped).unwrap(),
            r#"{"model":"mock-model","messages":[{"role":"user","content":"hello"}],"stream":false}"#
        );
    }

    #[test]
    fn response_mapping_preserves_assistant_text_finish_reason_and_usage() {
        let response = ChatCompletionsResponse {
            id: "chatcmpl-1".to_string(),
            model: "mock-model".to_string(),
            choices: vec![ChatCompletionChoice {
                index: 0,
                message: ChatCompletionMessage {
                    role: "assistant".to_string(),
                    content: Some("hello from mock".to_string()),
                    tool_calls: Vec::new(),
                },
                finish_reason: Some("stop".to_string()),
            }],
            usage: Some(ChatUsage {
                prompt_tokens: 3,
                completion_tokens: 2,
                total_tokens: 5,
            }),
        };
        let result = map_chat_response_to_responses(response).unwrap();
        assert_eq!(result.output_text, "hello from mock");
        assert_eq!(result.finish_reason.as_deref(), Some("stop"));
        assert_eq!(
            result.usage,
            Some(VitaUsage {
                input_tokens: 3,
                output_tokens: 2,
                total_tokens: 5,
            })
        );
    }

    #[test]
    fn bounded_stream_chunk_mapping_is_deterministic() {
        let capabilities = ProviderCapabilities {
            streaming: true,
            ..ProviderCapabilities::none()
        };
        let delta = ChatCompletionsStreamChunk {
            id: "chatcmpl-stream".to_string(),
            model: "mock-model".to_string(),
            choices: vec![ChatCompletionChunkChoice {
                delta: ChatCompletionDelta {
                    role: Some("assistant".to_string()),
                    content: Some("chunk".to_string()),
                    tool_calls: Vec::new(),
                },
                finish_reason: None,
            }],
            usage: None,
        };
        let finish = ChatCompletionsStreamChunk {
            id: "chatcmpl-stream".to_string(),
            model: "mock-model".to_string(),
            choices: vec![ChatCompletionChunkChoice {
                delta: ChatCompletionDelta {
                    role: None,
                    content: None,
                    tool_calls: Vec::new(),
                },
                finish_reason: Some("stop".to_string()),
            }],
            usage: Some(ChatUsage {
                prompt_tokens: 3,
                completion_tokens: 2,
                total_tokens: 5,
            }),
        };
        assert_eq!(
            map_chat_stream_chunk_to_responses_events(delta, capabilities).unwrap(),
            vec![VitaResponsesEvent::OutputTextDelta {
                id: "chatcmpl-stream".to_string(),
                model: "mock-model".to_string(),
                delta: "chunk".to_string(),
            }]
        );
        assert_eq!(
            map_chat_stream_chunk_to_responses_events(finish, capabilities).unwrap(),
            vec![VitaResponsesEvent::Completed {
                id: "chatcmpl-stream".to_string(),
                model: "mock-model".to_string(),
                finish_reason: Some("stop".to_string()),
                usage: Some(VitaUsage {
                    input_tokens: 3,
                    output_tokens: 2,
                    total_tokens: 5,
                }),
            }]
        );
    }

    #[test]
    fn unsupported_capabilities_fail_explicitly_without_role_or_semantic_downgrade() {
        let unconfigured_profile = profile(
            "https://provider.example/v1",
            None,
            ProviderCapabilities::none(),
        );
        let developer_request = VitaResponsesRequest::new(
            "mock-model",
            vec![VitaMessage::text(VitaMessageRole::Developer, "developer")],
            VitaResponsesRequestOptions::default(),
        );
        assert!(matches!(
            map_responses_request_to_chat(&developer_request, &unconfigured_profile),
            Err(VitaAgentError::UnsupportedProviderCapability {
                capability: ProviderCapability::DeveloperRole
            })
        ));

        let tool_request = VitaResponsesRequest::new(
            "mock-model",
            vec![VitaMessage::text(VitaMessageRole::User, "tool")],
            VitaResponsesRequestOptions {
                tools: vec![GatewayToolDefinition {
                    name: "lookup".to_string(),
                    description: None,
                    parameters: json!({"type":"object"}),
                }],
                ..VitaResponsesRequestOptions::default()
            },
        );
        assert!(matches!(
            map_responses_request_to_chat(&tool_request, &unconfigured_profile),
            Err(VitaAgentError::UnsupportedProviderCapability {
                capability: ProviderCapability::Tools
            })
        ));

        let schema_profile = profile(
            "https://provider.example/v1",
            None,
            ProviderCapabilities {
                json_schema: true,
                ..ProviderCapabilities::none()
            },
        );
        let schema_request = VitaResponsesRequest::new(
            "mock-model",
            vec![VitaMessage::text(VitaMessageRole::User, "schema")],
            VitaResponsesRequestOptions {
                required_capabilities: vec![ProviderCapability::JsonSchema],
                ..VitaResponsesRequestOptions::default()
            },
        );
        assert!(matches!(
            map_responses_request_to_chat(&schema_request, &schema_profile),
            Err(VitaAgentError::UnsupportedGatewayCapability {
                capability: ProviderCapability::JsonSchema
            })
        ));
    }

    #[test]
    fn ambient_credentials_do_not_select_or_authorize_a_provider() {
        let before = std::env::vars_os().collect::<Vec<_>>();
        let authority = VitaProviderAuthority::not_configured();
        assert_eq!(authority.state(), VitaProviderState::NotConfigured);
        assert!(authority.profile().is_none());
        let after = std::env::vars_os().collect::<Vec<_>>();
        assert_eq!(before, after);
    }

    #[test]
    fn localhost_mock_proves_gateway_to_chat_completion_mapping_without_external_network() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local mock");
        let mock_address = listener.local_addr().expect("mock address");
        let mock_port = mock_address.port();
        let expected_path = "/v1/chat/completions".to_string();
        let server = thread::spawn(move || {
            let (mut stream, peer) = listener.accept().expect("accept mock request");
            let (target, authorization, body) = read_http_request(&mut stream);
            let response_body = serde_json::to_vec(&json!({
                "id": "chatcmpl-local-mock",
                "model": "mock-model",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "mock reply"},
                    "finish_reason": "stop"
                }],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}
            }))
            .expect("mock response JSON");
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                response_body.len()
            );
            stream
                .write_all(headers.as_bytes())
                .and_then(|_| stream.write_all(&response_body))
                .expect("write mock response");
            (peer, target, authorization, body)
        });

        let provider_base_url = format!("http://127.0.0.1:{mock_port}/v1");
        let credential = CredentialRef::new("mock-ref", "provider-one", &provider_base_url)
            .expect("test credential binding");
        let profile = test_local_profile(
            &provider_base_url,
            Some(credential.clone()),
            ProviderCapabilities {
                developer_role: true,
                ..ProviderCapabilities::none()
            },
        );
        let authority = VitaProviderAuthority::configure(profile).unwrap();
        let gateway_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind owned gateway");
        let gateway_binding = VitaGatewayBinding::for_owned_private_listener(
            gateway_listener.local_addr().unwrap().port(),
        )
        .unwrap();
        let ready = authority.prepare_gateway(gateway_binding).unwrap();
        let request = VitaResponsesRequest::new(
            "mock-model",
            vec![
                VitaMessage::text(VitaMessageRole::System, "system"),
                VitaMessage::text(VitaMessageRole::Developer, "developer"),
                VitaMessage::text(VitaMessageRole::User, "hello"),
            ],
            VitaResponsesRequestOptions::default(),
        );
        let expected_request = map_responses_request_to_chat(&request, ready.profile()).unwrap();
        let gateway = ProviderGateway::new(
            ready,
            InMemoryTestCredential {
                reference: credential,
                value: "fake-test-credential".to_string(),
            },
            TcpLocalTransport,
        );
        let result = gateway
            .execute_responses_request(&request)
            .expect("local mock gateway request");
        let (peer, target, authorization, body) = server.join().expect("mock server join");
        let observed_request: ChatCompletionsRequest =
            serde_json::from_slice(&body).expect("mapped request JSON");

        assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(target, expected_path);
        assert_eq!(
            authorization.as_deref(),
            Some("Bearer fake-test-credential")
        );
        assert_eq!(observed_request, expected_request);
        assert_eq!(result.output_text, "mock reply");
        assert_eq!(result.finish_reason.as_deref(), Some("stop"));
        assert_eq!(
            result.usage,
            Some(VitaUsage {
                input_tokens: 3,
                output_tokens: 2,
                total_tokens: 5,
            })
        );
        println!(
            "D29-E local mock bind=127.0.0.1:{mock_port} request_count=1 endpoint={expected_path} external_endpoint_calls=0"
        );
    }

    struct InMemoryTestCredential {
        reference: CredentialRef,
        value: String,
    }

    impl CredentialResolver for InMemoryTestCredential {
        fn resolve(
            &self,
            credential_ref: &CredentialRef,
        ) -> Result<ResolvedCredential, VitaAgentError> {
            if credential_ref != &self.reference {
                return Err(VitaAgentError::CredentialResolution(
                    "credential reference was not found in the test store",
                ));
            }
            Ok(ResolvedCredential::new(self.value.clone()))
        }
    }

    struct TcpLocalTransport;

    impl ProviderRequestTransport for TcpLocalTransport {
        fn post_json(
            &self,
            endpoint: &ProviderEndpoint,
            authorization: Option<&ResolvedCredential>,
            body: &[u8],
            timeout: Duration,
            _retry_policy: ProviderRetryPolicy,
        ) -> Result<Vec<u8>, VitaAgentError> {
            if !endpoint.is_test_localhost() {
                return Err(VitaAgentError::GatewayProtocol(
                    "test transport is authorized only for test-scoped localhost endpoints"
                        .to_string(),
                ));
            }
            let address = SocketAddr::from(([127, 0, 0, 1], endpoint.port));
            let mut stream = TcpStream::connect_timeout(&address, timeout)
                .map_err(VitaAgentError::GatewayTransport)?;
            stream
                .set_read_timeout(Some(timeout))
                .map_err(VitaAgentError::GatewayTransport)?;
            let path = endpoint.request_path("chat/completions");
            let mut request = format!(
                "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
                endpoint.host_header(),
                body.len()
            )
            .into_bytes();
            if let Some(authorization) = authorization {
                request.extend_from_slice(
                    format!("Authorization: Bearer {}\r\n", authorization.as_str()).as_bytes(),
                );
            }
            request.extend_from_slice(b"\r\n");
            request.extend_from_slice(body);
            stream
                .write_all(&request)
                .map_err(VitaAgentError::GatewayTransport)?;
            let mut response = Vec::new();
            stream
                .read_to_end(&mut response)
                .map_err(VitaAgentError::GatewayTransport)?;
            let header_end = find_header_end(&response).ok_or_else(|| {
                VitaAgentError::GatewayProtocol("mock response omitted HTTP headers".to_string())
            })?;
            let status_line = String::from_utf8_lossy(&response[..header_end]);
            if !status_line.starts_with("HTTP/1.1 200 ") {
                return Err(VitaAgentError::GatewayProtocol(
                    "mock provider returned a non-success status".to_string(),
                ));
            }
            Ok(response[header_end + 4..].to_vec())
        }
    }

    fn find_header_end(bytes: &[u8]) -> Option<usize> {
        bytes.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn read_http_request(stream: &mut TcpStream) -> (String, Option<String>, Vec<u8>) {
        let mut bytes = Vec::new();
        let header_end = loop {
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).expect("read mock request");
            assert!(read > 0, "mock request closed before headers");
            bytes.extend_from_slice(&buffer[..read]);
            assert!(
                bytes.len() <= 1024 * 1024,
                "mock request exceeded test bound"
            );
            if let Some(end) = find_header_end(&bytes) {
                break end;
            }
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]).into_owned();
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            })
            .expect("content length header");
        let total = header_end + 4 + content_length;
        while bytes.len() < total {
            let mut buffer = [0_u8; 1024];
            let read = stream.read(&mut buffer).expect("read mock request body");
            assert!(read > 0, "mock request closed before body");
            bytes.extend_from_slice(&buffer[..read]);
            assert!(
                bytes.len() <= 1024 * 1024,
                "mock request exceeded test bound"
            );
        }
        let request_line = headers.lines().next().expect("request line");
        let target = request_line
            .split_whitespace()
            .nth(1)
            .expect("request target")
            .to_string();
        let authorization = headers.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_string())
        });
        (target, authorization, bytes[header_end + 4..total].to_vec())
    }
}
