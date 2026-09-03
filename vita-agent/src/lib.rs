//! Digital Life-owned Vita Agent boundary over the pinned Codex execution kernel.
//!
//! D29-E adds a provider-neutral Digital Life gateway foundation on top of the
//! certified D29-D2 private Vita runtime.  It does not start a model turn,
//! authenticate an account, expose production tools, or add a Tauri/frontend
//! caller.  The user provider remains Digital Life authority; Codex stays a
//! pinned Responses execution kernel.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use codex_app_server_protocol::{ClientInfo, InitializeCapabilities, InitializeParams};
use codex_config::LoaderOverrides;
use codex_core::config::{ConfigBuilder, ThreadStoreConfig};
use codex_core::StartThreadOptions;
use toml::map::Map;
use toml::Value as TomlValue;

mod provider_gateway;
mod tool_authority;

pub use provider_gateway::{
    CredentialRef, ProviderCapabilities, ProviderCapability, ProviderInstructionRolePolicy,
    ProviderModelIdentityPolicy, ProviderProfile, ProviderProtocol, ProviderRetryPolicy,
    VitaProviderState,
};
pub use tool_authority::{
    VitaAuthorityError, VitaAuthorityEvidenceSource, VitaAuthorityFuture, VitaAuthorityOutcome,
    VitaAuthorityReason, VitaAuthorityVerdict, VitaBrokerSnapshot, VitaExecutionContext,
    VitaRequestedScope, VitaToolAuthorityPort, VitaToolAuthorityRequest, VitaToolBroker,
    VitaToolContributor, VITA_GOVERNED_ACTION_CAPABILITY_ID, VITA_GOVERNED_ACTION_TOOL_NAME,
};

pub const VITA_AGENT_RUNTIME_ID: &str = "vita-agent";
pub const VITA_UNCONFIGURED_PROVIDER_ID: &str = "vita-unconfigured";
pub const VITA_GATEWAY_PROVIDER_ID: &str = "vita-gateway";
pub const VITA_PLACEHOLDER_MODEL_ID: &str = "vita-unconfigured-model";
pub const VITA_PLACEHOLDER_BASE_URL: &str = "http://127.0.0.1:9/v1";
pub const VITA_OWNERSHIP_MARKER_FILE: &str = ".vita-agent-runtime";
pub const CODEX_UPSTREAM_REPOSITORY: &str = "https://github.com/openai/codex.git";
pub const CODEX_UPSTREAM_RELEASE: &str = "rust-v0.152.0";
pub const CODEX_UPSTREAM_COMMIT: &str = "316795b3cf2a45e90d121d9f46499d4658b2645c";
pub const CODEX_PROTOCOL_SCHEMA_HASH: &str =
    "d8faa38d5f00aa7ddfe635a2d374ee5f871ffd217d4d175c72fbe7f009f4f669";

const MAX_PROVIDER_ERROR_FIELD_CHARS: usize = 256;
const REDACTED_PROVIDER_ERROR_VALUE: &str = "[redacted]";

/// A bounded, allowlisted representation of a provider's error envelope.
///
/// This type intentionally contains no arbitrary JSON and no request
/// material.  Values are sanitized at construction time.  Generic
/// Debug/Display output remains conservative; the explicit accessors are
/// reserved for the bounded D29-G2 diagnostic path.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderErrorDetail {
    status: u16,
    code: Option<String>,
    kind: Option<String>,
    param: Option<String>,
    message: Option<String>,
}

impl ProviderErrorDetail {
    pub(crate) fn from_parts(
        status: u16,
        code: Option<&str>,
        kind: Option<&str>,
        param: Option<&str>,
        message: Option<&str>,
        credential: Option<&str>,
    ) -> Self {
        Self {
            status,
            code: sanitize_provider_error_field(code, credential),
            kind: sanitize_provider_error_field(kind, credential),
            param: sanitize_provider_error_field(param, credential),
            message: sanitize_provider_error_field(message, credential),
        }
    }

    pub fn status(&self) -> u16 {
        self.status
    }

    pub fn code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    pub fn kind(&self) -> Option<&str> {
        self.kind.as_deref()
    }

    pub fn param(&self) -> Option<&str> {
        self.param.as_deref()
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

impl std::fmt::Debug for ProviderErrorDetail {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderErrorDetail")
            .field("status", &self.status)
            .field("code", &self.code)
            .field("kind_present", &self.kind.is_some())
            .field("param_present", &self.param.is_some())
            .field("message_present", &self.message.is_some())
            .finish()
    }
}

impl Display for ProviderErrorDetail {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "provider error status={} code={}",
            self.status,
            self.code.as_deref().unwrap_or("none"),
        )
    }
}

fn sanitize_provider_error_field(value: Option<&str>, credential: Option<&str>) -> Option<String> {
    let value = value?;
    if credential.is_some_and(|credential| !credential.is_empty() && value.contains(credential)) {
        return Some(REDACTED_PROVIDER_ERROR_VALUE.to_string());
    }

    Some(
        value
            .chars()
            .take(MAX_PROVIDER_ERROR_FIELD_CHARS)
            .map(|character| {
                if character.is_control() {
                    ' '
                } else {
                    character
                }
            })
            .collect(),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VitaProviderPolicy {
    NotConfigured,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VitaCredentialPolicy {
    NoLogin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VitaNetworkPolicy {
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VitaAgentRuntimeProfile {
    app_data_root: PathBuf,
    vita_root: PathBuf,
    kernel_home: PathBuf,
    state_root: PathBuf,
    runtime_root: PathBuf,
    config_root: PathBuf,
    tmp_root: PathBuf,
    runs_root: PathBuf,
    workspace_root: PathBuf,
    runtime_identity: &'static str,
    provider_policy: VitaProviderPolicy,
    credential_policy: VitaCredentialPolicy,
    network_policy: VitaNetworkPolicy,
}

impl VitaAgentRuntimeProfile {
    /// Creates a profile only from roots explicitly supplied by Digital Life.
    ///
    /// No environment variable, stock Codex home, or system-wide OpenAI path
    /// is consulted here.  Both the app-data and workspace roots are checked
    /// before the upstream config builder is reached, even though the Codex
    /// project layer is later disabled by `loader_overrides`.
    pub fn from_explicit_app_data_root(
        app_data_root: PathBuf,
        workspace_root: PathBuf,
    ) -> Result<Self, VitaAgentError> {
        validate_absolute_root("app_data_root", &app_data_root)?;
        validate_absolute_root("workspace_root", &workspace_root)?;
        validate_trusted_path("app_data_root", &app_data_root)?;
        validate_trusted_path("workspace_root", &workspace_root)?;

        let vita_root = app_data_root.join("agent");
        validate_trusted_path("vita_root", &vita_root)?;

        Ok(Self {
            kernel_home: vita_root.join("kernel"),
            state_root: vita_root.join("state"),
            runtime_root: vita_root.join("runtime"),
            config_root: vita_root.join("config"),
            tmp_root: vita_root.join("tmp"),
            runs_root: vita_root.join("runs"),
            app_data_root,
            vita_root,
            workspace_root,
            runtime_identity: VITA_AGENT_RUNTIME_ID,
            provider_policy: VitaProviderPolicy::NotConfigured,
            credential_policy: VitaCredentialPolicy::NoLogin,
            network_policy: VitaNetworkPolicy::Closed,
        })
    }

    pub fn app_data_root(&self) -> &Path {
        &self.app_data_root
    }

    pub fn vita_root(&self) -> &Path {
        &self.vita_root
    }

    pub fn kernel_home(&self) -> &Path {
        &self.kernel_home
    }

    pub fn state_root(&self) -> &Path {
        &self.state_root
    }

    pub fn runtime_root(&self) -> &Path {
        &self.runtime_root
    }

    pub fn config_root(&self) -> &Path {
        &self.config_root
    }

    pub fn tmp_root(&self) -> &Path {
        &self.tmp_root
    }

    pub fn runs_root(&self) -> &Path {
        &self.runs_root
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn runtime_identity(&self) -> &'static str {
        self.runtime_identity
    }

    pub fn provider_policy(&self) -> VitaProviderPolicy {
        self.provider_policy
    }

    pub fn credential_policy(&self) -> VitaCredentialPolicy {
        self.credential_policy
    }

    pub fn network_policy(&self) -> VitaNetworkPolicy {
        self.network_policy
    }

    pub fn ownership_marker_path(&self) -> PathBuf {
        self.vita_root.join(VITA_OWNERSHIP_MARKER_FILE)
    }

    /// Re-checks every path component that can participate in the private
    /// namespace before the runtime is opened or created.
    pub fn validate_private_namespace(&self) -> Result<(), VitaAgentError> {
        for (field, path) in [
            ("app_data_root", self.app_data_root.as_path()),
            ("vita_root", self.vita_root.as_path()),
            ("kernel_home", self.kernel_home.as_path()),
            ("state_root", self.state_root.as_path()),
            ("runtime_root", self.runtime_root.as_path()),
            ("config_root", self.config_root.as_path()),
            ("tmp_root", self.tmp_root.as_path()),
            ("runs_root", self.runs_root.as_path()),
            ("workspace_root", self.workspace_root.as_path()),
        ] {
            validate_trusted_path(field, path)?;
        }

        for (field, path) in [
            ("kernel_home", self.kernel_home.as_path()),
            ("state_root", self.state_root.as_path()),
            ("runtime_root", self.runtime_root.as_path()),
            ("config_root", self.config_root.as_path()),
            ("tmp_root", self.tmp_root.as_path()),
            ("runs_root", self.runs_root.as_path()),
        ] {
            if !is_strict_descendant(path, &self.vita_root) {
                return Err(VitaAgentError::UnsafePath {
                    field,
                    path: path.to_path_buf(),
                    reason: "layout path is outside the Vita root",
                });
            }
        }
        if !is_strict_descendant(&self.vita_root, &self.app_data_root) {
            return Err(VitaAgentError::UnsafePath {
                field: "vita_root",
                path: self.vita_root.clone(),
                reason: "Vita root is not a child of the explicit app-data root",
            });
        }
        Ok(())
    }

    /// Creates only the fixed Vita-owned directories and their ownership
    /// marker after the trusted namespace has been established.
    pub fn ensure_private_runtime_layout(&self) -> Result<(), VitaAgentError> {
        self.validate_private_namespace()?;
        for path in [
            &self.vita_root,
            &self.kernel_home,
            &self.state_root,
            &self.runtime_root,
            &self.config_root,
            &self.tmp_root,
            &self.runs_root,
        ] {
            fs::create_dir_all(path).map_err(VitaAgentError::KernelConfig)?;
        }
        fs::create_dir_all(self.runtime_root.join("log")).map_err(VitaAgentError::KernelConfig)?;
        self.validate_private_namespace()?;
        self.ensure_ownership_marker()?;
        self.validate_private_namespace()?;
        self.verify_ownership_marker()
    }

    /// Removes one empty test-owned run directory.  This intentionally is not
    /// a general recursive cleanup facility.
    pub fn cleanup_owned_test_dir(&self, target: &Path) -> Result<(), VitaAgentError> {
        self.validate_private_namespace()?;
        self.verify_ownership_marker()?;
        validate_trusted_path("cleanup_target", target)?;

        let trusted_runs_root =
            fs::canonicalize(&self.runs_root).map_err(VitaAgentError::KernelConfig)?;
        let trusted_target = fs::canonicalize(target).map_err(VitaAgentError::KernelConfig)?;
        if !is_strict_descendant(&trusted_target, &trusted_runs_root) {
            return Err(VitaAgentError::CleanupRejected {
                path: target.to_path_buf(),
                reason: "cleanup target is outside the Vita-owned runs root",
            });
        }

        let metadata = fs::symlink_metadata(target).map_err(VitaAgentError::KernelConfig)?;
        if !metadata.is_dir() || is_reparse_point(&metadata) {
            return Err(VitaAgentError::CleanupRejected {
                path: target.to_path_buf(),
                reason: "cleanup target must be a non-reparse directory",
            });
        }
        fs::remove_dir(target).map_err(|_| VitaAgentError::CleanupRejected {
            path: target.to_path_buf(),
            reason: "cleanup target must be an empty Vita-owned directory",
        })
    }

    fn ensure_ownership_marker(&self) -> Result<(), VitaAgentError> {
        let marker_path = self.ownership_marker_path();
        match fs::symlink_metadata(&marker_path) {
            Ok(metadata) => {
                if is_reparse_point(&metadata) {
                    return Err(VitaAgentError::OwnershipViolation {
                        path: marker_path,
                        reason: "ownership marker is a reparse point",
                    });
                }
                self.verify_ownership_marker()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut marker = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&marker_path)
                    .map_err(VitaAgentError::KernelConfig)?;
                marker
                    .write_all(ownership_marker_contents())
                    .map_err(VitaAgentError::KernelConfig)?;
                marker.flush().map_err(VitaAgentError::KernelConfig)?;
                self.verify_ownership_marker()
            }
            Err(error) => Err(VitaAgentError::KernelConfig(error)),
        }
    }

    fn verify_ownership_marker(&self) -> Result<(), VitaAgentError> {
        let marker_path = self.ownership_marker_path();
        let metadata = match fs::symlink_metadata(&marker_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(VitaAgentError::OwnershipViolation {
                    path: marker_path,
                    reason: "ownership marker is missing",
                });
            }
            Err(error) => return Err(VitaAgentError::KernelConfig(error)),
        };
        if is_reparse_point(&metadata) || !metadata.is_file() {
            return Err(VitaAgentError::OwnershipViolation {
                path: marker_path,
                reason: "ownership marker is not a regular file",
            });
        }
        let contents = fs::read(&marker_path).map_err(VitaAgentError::KernelConfig)?;
        if contents != ownership_marker_contents() {
            return Err(VitaAgentError::OwnershipViolation {
                path: marker_path,
                reason: "ownership marker identity does not match Vita Agent",
            });
        }
        Ok(())
    }

    fn system_config_path(&self) -> PathBuf {
        self.config_root.join("system.config.toml")
    }

    fn auth_path(&self) -> PathBuf {
        self.kernel_home.join("auth.json")
    }

    fn system_requirements_path(&self) -> PathBuf {
        self.config_root.join("system.requirements.toml")
    }

    fn managed_config_path(&self) -> PathBuf {
        self.config_root.join("managed.config.toml")
    }

    fn loader_overrides(&self) -> LoaderOverrides {
        LoaderOverrides {
            // These are explicit Vita-owned non-existent inputs.  They
            // prevent the upstream loader from falling back to the Windows
            // system path while keeping the host's files untouched.
            managed_config_path: Some(self.managed_config_path()),
            system_config_path: Some(self.system_config_path()),
            system_requirements_path: Some(self.system_requirements_path()),
            ignore_managed_requirements: true,
            ignore_login_requirements: true,
            ignore_user_config: true,
            ignore_project_config: true,
            ignore_user_and_project_exec_policy_rules: true,
            ..LoaderOverrides::default()
        }
    }

    fn cli_overrides(&self) -> Vec<(String, TomlValue)> {
        let mut features = Map::new();
        for feature in [
            "apps",
            "plugins",
            "enable_mcp_apps",
            "mcp_2026_07_28",
            "tool_suggest",
            "goals",
            "multi_agent",
            "multi_agent_v2",
            "multi_agent_mode",
            "enable_fanout",
            "shell_tool",
            "unified_exec",
            "apply_patch_freeform",
            "hooks",
            "request_permissions_tool",
            "view_image",
            "sleep_tool",
            "deferred_executor",
            "standalone_web_search",
            "token_budget",
            "current_time_reminder",
            "memories",
            "artifact",
            "remote_control",
            "remote_models",
            "network_proxy",
            "respect_system_proxy",
            "image_generation",
            "workspace_dependencies",
            "in_app_browser",
            "in_app_chat",
            "in_app_dictation",
            "in_app_local_automation",
            "in_app_updates",
            "browser_use",
            "browser_use_full_cdp_access",
            "browser_use_external",
            "computer_use",
            "remote_plugin",
            "plugin_sharing",
            "external_agent_memory_import",
            "guardian_approval",
            "auth_elicitation",
            "tool_call_mcp_elicitation",
            "skill_mcp_dependency_install",
            "skill_search",
            "personality",
            "fast_mode",
        ] {
            features.insert(feature.to_string(), TomlValue::Boolean(false));
        }

        let mut thread_store = Map::new();
        thread_store.insert(
            "type".to_string(),
            TomlValue::String("in_memory".to_string()),
        );
        thread_store.insert(
            "id".to_string(),
            TomlValue::String(VITA_AGENT_RUNTIME_ID.to_string()),
        );

        let mut vita_provider = Map::new();
        vita_provider.insert(
            "name".to_string(),
            TomlValue::String("Vita Unconfigured Provider".to_string()),
        );
        vita_provider.insert(
            "base_url".to_string(),
            TomlValue::String(VITA_PLACEHOLDER_BASE_URL.to_string()),
        );
        vita_provider.insert(
            "wire_api".to_string(),
            TomlValue::String("responses".to_string()),
        );
        vita_provider.insert(
            "requires_openai_auth".to_string(),
            TomlValue::Boolean(false),
        );
        let mut model_providers = Map::new();
        model_providers.insert(
            VITA_UNCONFIGURED_PROVIDER_ID.to_string(),
            TomlValue::Table(vita_provider),
        );

        vec![
            (
                "model_provider".to_string(),
                TomlValue::String(VITA_UNCONFIGURED_PROVIDER_ID.to_string()),
            ),
            (
                "model".to_string(),
                TomlValue::String(VITA_PLACEHOLDER_MODEL_ID.to_string()),
            ),
            (
                "model_providers".to_string(),
                TomlValue::Table(model_providers),
            ),
            (
                "sandbox_mode".to_string(),
                TomlValue::String("read-only".to_string()),
            ),
            (
                "web_search".to_string(),
                TomlValue::String("disabled".to_string()),
            ),
            (
                "check_for_update_on_startup".to_string(),
                TomlValue::Boolean(false),
            ),
            (
                "analytics".to_string(),
                table([("enabled", TomlValue::Boolean(false))]),
            ),
            (
                "feedback".to_string(),
                table([("enabled", TomlValue::Boolean(false))]),
            ),
            ("mcp_servers".to_string(), TomlValue::Table(Map::new())),
            (
                "tools".to_string(),
                table([
                    (
                        "experimental_request_user_input",
                        table([("enabled", TomlValue::Boolean(false))]),
                    ),
                    (
                        "update_plan",
                        table([("enabled", TomlValue::Boolean(false))]),
                    ),
                ]),
            ),
            ("plugins".to_string(), TomlValue::Table(Map::new())),
            ("marketplaces".to_string(), TomlValue::Table(Map::new())),
            (
                "history".to_string(),
                table([("persistence", TomlValue::String("none".to_string()))]),
            ),
            (
                "experimental_thread_store".to_string(),
                TomlValue::Table(thread_store),
            ),
            (
                "sqlite_home".to_string(),
                TomlValue::String(self.state_root.display().to_string()),
            ),
            (
                "log_dir".to_string(),
                TomlValue::String(self.runtime_root.join("log").display().to_string()),
            ),
            (
                "include_apps_instructions".to_string(),
                TomlValue::Boolean(false),
            ),
            (
                "skills".to_string(),
                table([("include_instructions", TomlValue::Boolean(false))]),
            ),
            (
                "include_collaboration_mode_instructions".to_string(),
                TomlValue::Boolean(false),
            ),
            (
                "include_environment_context".to_string(),
                TomlValue::Boolean(false),
            ),
            ("features".to_string(), TomlValue::Table(features)),
        ]
    }

    #[cfg(test)]
    fn cli_overrides_for_gateway(
        &self,
        provider: &provider_gateway::DerivedCodexProvider,
    ) -> Vec<(String, TomlValue)> {
        let mut overrides = self.cli_overrides();
        let mut vita_provider = Map::new();
        vita_provider.insert(
            "name".to_string(),
            TomlValue::String("Vita Gateway".to_string()),
        );
        vita_provider.insert(
            "base_url".to_string(),
            TomlValue::String(provider.base_url().to_string()),
        );
        vita_provider.insert(
            "wire_api".to_string(),
            TomlValue::String(provider.wire_api().to_string()),
        );
        vita_provider.insert(
            "requires_openai_auth".to_string(),
            TomlValue::Boolean(provider.requires_openai_auth()),
        );
        vita_provider.insert("request_max_retries".to_string(), TomlValue::Integer(0));
        vita_provider.insert("stream_max_retries".to_string(), TomlValue::Integer(0));
        vita_provider.insert(
            "stream_idle_timeout_ms".to_string(),
            TomlValue::Integer(500),
        );
        vita_provider.insert("supports_websockets".to_string(), TomlValue::Boolean(false));
        vita_provider.insert(
            "supports_standalone_web_search".to_string(),
            TomlValue::Boolean(false),
        );

        for (key, value) in &mut overrides {
            match key.as_str() {
                "model_provider" => {
                    *value = TomlValue::String(provider.model_provider_id().to_string());
                }
                "model" => {
                    *value = TomlValue::String(provider.model().to_string());
                }
                "model_providers" => {
                    let mut model_providers = Map::new();
                    model_providers.insert(
                        provider.model_provider_id().to_string(),
                        TomlValue::Table(vita_provider.clone()),
                    );
                    *value = TomlValue::Table(model_providers);
                }
                _ => {}
            }
        }
        overrides
    }
}

#[derive(Debug)]
pub enum VitaAgentError {
    InvalidPath {
        field: &'static str,
        path: PathBuf,
    },
    ForbiddenStockPath {
        field: &'static str,
        path: PathBuf,
    },
    UnsafePath {
        field: &'static str,
        path: PathBuf,
        reason: &'static str,
    },
    UnexpectedVitaConfigSource {
        path: PathBuf,
    },
    UnexpectedVitaAuthSource {
        path: PathBuf,
    },
    InvalidProviderProfile {
        field: &'static str,
        reason: &'static str,
    },
    InvalidProviderUrl {
        url: String,
        reason: &'static str,
    },
    CredentialBindingMismatch {
        provider_id: String,
        endpoint: String,
    },
    UnsupportedProviderCapability {
        capability: ProviderCapability,
    },
    UnsupportedGatewayCapability {
        capability: ProviderCapability,
    },
    UnsupportedProviderProtocol {
        protocol: ProviderProtocol,
    },
    ProviderStateViolation {
        expected: VitaProviderState,
        actual: VitaProviderState,
    },
    GatewayNotReady,
    GatewayProtocol(String),
    GatewayTransport(std::io::Error),
    CredentialResolution(&'static str),
    ProviderTransportRejected {
        reason: &'static str,
    },
    ProviderTransportTimeout {
        phase: &'static str,
    },
    ProviderRequestTooLarge {
        limit: usize,
    },
    ProviderResponseTooLarge {
        limit: usize,
    },
    ProviderHttpStatus {
        status: u16,
        detail: Option<ProviderErrorDetail>,
    },
    OwnershipViolation {
        path: PathBuf,
        reason: &'static str,
    },
    CleanupRejected {
        path: PathBuf,
        reason: &'static str,
    },
    NotConfiguredProvider,
    KernelConfig(std::io::Error),
    KernelInvariant(&'static str),
}

impl Display for VitaAgentError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidPath { field, path } => {
                write!(f, "{field} must be an absolute path: {}", path.display())
            }
            Self::ForbiddenStockPath { field, path } => write!(
                f,
                "{field} must not select stock Codex/OpenAI state: {}",
                path.display()
            ),
            Self::UnsafePath {
                field,
                path,
                reason,
            } => write!(
                f,
                "{field} is not a trusted Vita path ({}): {}",
                reason,
                path.display()
            ),
            Self::UnexpectedVitaConfigSource { path } => write!(
                f,
                "Vita configuration source must not exist before governed compilation: {}",
                path.display()
            ),
            Self::UnexpectedVitaAuthSource { path } => write!(
                f,
                "Vita auth source must not exist before governed compilation: {}",
                path.display()
            ),
            Self::InvalidProviderProfile { field, reason } => {
                write!(f, "invalid Digital Life provider profile {field}: {reason}")
            }
            Self::InvalidProviderUrl { url, reason } => {
                write!(f, "invalid provider URL ({reason}): {url}")
            }
            Self::CredentialBindingMismatch {
                provider_id,
                endpoint,
            } => write!(
                f,
                "credential reference is not bound to provider {provider_id} at {endpoint}"
            ),
            Self::UnsupportedProviderCapability { capability } => write!(
                f,
                "provider does not support requested capability: {capability}"
            ),
            Self::UnsupportedGatewayCapability { capability } => write!(
                f,
                "gateway mapping is not implemented for capability: {capability}"
            ),
            Self::UnsupportedProviderProtocol { protocol } => {
                write!(
                    f,
                    "provider protocol is not enabled by this gateway: {protocol}"
                )
            }
            Self::ProviderStateViolation { expected, actual } => write!(
                f,
                "provider state transition requires {expected}, found {actual}"
            ),
            Self::GatewayNotReady => write!(f, "Vita provider gateway is not ready"),
            Self::GatewayProtocol(message) => {
                write!(f, "provider gateway protocol error: {message}")
            }
            Self::GatewayTransport(error) => {
                write!(f, "provider gateway transport error: {error}")
            }
            Self::CredentialResolution(reason) => {
                write!(f, "provider credential resolution failed: {reason}")
            }
            Self::ProviderTransportRejected { reason } => {
                write!(f, "provider HTTPS transport rejected the request: {reason}")
            }
            Self::ProviderTransportTimeout { phase } => {
                write!(f, "provider HTTPS transport timed out during {phase}")
            }
            Self::ProviderRequestTooLarge { limit } => {
                write!(f, "provider request exceeds the {limit}-byte limit")
            }
            Self::ProviderResponseTooLarge { limit } => {
                write!(f, "provider response exceeds the {limit}-byte limit")
            }
            Self::ProviderHttpStatus { status, detail } => {
                write!(f, "provider returned HTTP status {status}")?;
                if let Some(detail) = detail {
                    write!(f, " (code={})", detail.code().unwrap_or("none"))?;
                }
                Ok(())
            }
            Self::OwnershipViolation { path, reason } => write!(
                f,
                "Vita ownership check failed ({reason}): {}",
                path.display()
            ),
            Self::CleanupRejected { path, reason } => {
                write!(f, "Vita cleanup rejected ({reason}): {}", path.display())
            }
            Self::NotConfiguredProvider => write!(
                f,
                "model execution is forbidden while Vita provider policy is NotConfigured"
            ),
            Self::KernelConfig(error) => write!(f, "Vita kernel config failed: {error}"),
            Self::KernelInvariant(message) => write!(f, "Vita kernel invariant failed: {message}"),
        }
    }
}

impl Error for VitaAgentError {}

/// The minimum Digital Life-owned entrypoint into the pinned Codex kernel.
pub struct VitaAgentEntrypoint {
    profile: VitaAgentRuntimeProfile,
    config: Arc<codex_core::config::Config>,
    initialize: InitializeParams,
}

impl VitaAgentEntrypoint {
    /// Resolve Vita-only configuration and prepare the official kernel boundary.
    ///
    /// This deliberately stops before `ThreadManager` construction: that
    /// constructor also wires plugins, MCP, skills, and other host surfaces.
    /// The private layout is established before config loading, while the
    /// `NotConfigured` provider policy still blocks thread execution.
    pub async fn initialize(profile: VitaAgentRuntimeProfile) -> Result<Self, VitaAgentError> {
        profile.validate_private_namespace()?;
        ensure_vita_config_sources_absent(&profile)?;
        ensure_vita_auth_source_absent(&profile)?;
        profile.ensure_private_runtime_layout()?;

        let config = ConfigBuilder::default()
            .codex_home(profile.kernel_home().to_path_buf())
            .fallback_cwd(Some(profile.workspace_root().to_path_buf()))
            .cli_overrides(profile.cli_overrides())
            .loader_overrides(profile.loader_overrides())
            .strict_config(true)
            .build()
            .await
            .map_err(VitaAgentError::KernelConfig)?;

        if config.model_provider_id != VITA_UNCONFIGURED_PROVIDER_ID {
            return Err(VitaAgentError::KernelInvariant(
                "Vita must select the fixed unconfigured provider",
            ));
        }
        if config.model.as_deref() != Some(VITA_PLACEHOLDER_MODEL_ID) {
            return Err(VitaAgentError::KernelInvariant(
                "Vita must select the fixed placeholder model",
            ));
        }
        if config.model_provider.name != "Vita Unconfigured Provider"
            || config.model_provider.base_url.as_deref() != Some(VITA_PLACEHOLDER_BASE_URL)
            || config.model_provider.wire_api.to_string() != "responses"
        {
            return Err(VitaAgentError::KernelInvariant(
                "Vita provider definition must remain fixed and non-production",
            ));
        }
        if config.model_provider.requires_openai_auth
            || config.model_provider.env_key.is_some()
            || config.model_provider.experimental_bearer_token.is_some()
            || config.model_provider.auth.is_some()
            || config.model_provider.aws.is_some()
        {
            return Err(VitaAgentError::KernelInvariant(
                "Vita provider must not use OpenAI or alternate credential sources",
            ));
        }
        if config.codex_home.as_path() != profile.kernel_home()
            || config.cwd.as_path() != profile.workspace_root()
        {
            return Err(VitaAgentError::KernelInvariant(
                "Codex resolved a root outside the explicit Vita profile",
            ));
        }
        if config.check_for_update_on_startup {
            return Err(VitaAgentError::KernelInvariant(
                "update checks must remain disabled",
            ));
        }
        if config.analytics_enabled != Some(false) || config.feedback_enabled {
            return Err(VitaAgentError::KernelInvariant(
                "telemetry and feedback must remain disabled",
            ));
        }
        if !matches!(
            &config.experimental_thread_store,
            ThreadStoreConfig::InMemory { id } if id == VITA_AGENT_RUNTIME_ID
        ) {
            return Err(VitaAgentError::KernelInvariant(
                "Vita thread state must remain in-memory and scoped",
            ));
        }
        if config.permissions.network_sandbox_policy().is_enabled() {
            return Err(VitaAgentError::KernelInvariant(
                "Vita network policy must remain closed",
            ));
        }

        Ok(Self {
            profile,
            config: Arc::new(config),
            initialize: InitializeParams {
                client_info: ClientInfo {
                    name: VITA_AGENT_RUNTIME_ID.to_string(),
                    title: Some("Vita Agent".to_string()),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                capabilities: Some(InitializeCapabilities::default()),
            },
        })
    }

    /// Builds the same private Codex configuration boundary for the D29-F
    /// localhost proof.  The provider is already validated and the listener
    /// binding is owned by the caller; this helper only compiles the derived
    /// provider into the real upstream `Config` used by `ThreadManager`.
    #[cfg(test)]
    pub(crate) async fn initialize_with_gateway_for_tests(
        profile: VitaAgentRuntimeProfile,
        ready: &provider_gateway::GatewayReadyProvider,
    ) -> Result<Self, VitaAgentError> {
        let provider = ready.derived_codex_provider();
        profile.validate_private_namespace()?;
        ensure_vita_config_sources_absent(&profile)?;
        ensure_vita_auth_source_absent(&profile)?;
        profile.ensure_private_runtime_layout()?;

        let config = ConfigBuilder::default()
            .codex_home(profile.kernel_home().to_path_buf())
            .fallback_cwd(Some(profile.workspace_root().to_path_buf()))
            .cli_overrides(profile.cli_overrides_for_gateway(provider))
            .loader_overrides(profile.loader_overrides())
            .strict_config(true)
            .build()
            .await
            .map_err(VitaAgentError::KernelConfig)?;

        if config.model_provider_id != provider.model_provider_id()
            || config.model.as_deref() != Some(provider.model())
            || config.model_provider.base_url.as_deref() != Some(provider.base_url())
            || config.model_provider.wire_api.to_string() != provider.wire_api()
            || config.model_provider.requires_openai_auth != provider.requires_openai_auth()
        {
            return Err(VitaAgentError::KernelInvariant(
                "derived Vita gateway provider was not compiled into Codex config",
            ));
        }
        if config.model_provider.env_key.is_some()
            || config.model_provider.experimental_bearer_token.is_some()
            || config.model_provider.auth.is_some()
            || config.model_provider.aws.is_some()
        {
            return Err(VitaAgentError::KernelInvariant(
                "Vita gateway provider must not use ambient or stock credential sources",
            ));
        }
        if config.codex_home.as_path() != profile.kernel_home()
            || config.cwd.as_path() != profile.workspace_root()
            || config.check_for_update_on_startup
            || config.analytics_enabled != Some(false)
            || config.feedback_enabled
            || !matches!(
                &config.experimental_thread_store,
                ThreadStoreConfig::InMemory { id } if id == VITA_AGENT_RUNTIME_ID
            )
            || config.permissions.network_sandbox_policy().is_enabled()
        {
            return Err(VitaAgentError::KernelInvariant(
                "D29-F Codex config escaped the bounded Vita runtime profile",
            ));
        }

        Ok(Self {
            profile,
            config: Arc::new(config),
            initialize: InitializeParams {
                client_info: ClientInfo {
                    name: VITA_AGENT_RUNTIME_ID.to_string(),
                    title: Some("Vita Agent".to_string()),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                },
                capabilities: Some(InitializeCapabilities::default()),
            },
        })
    }

    pub fn profile(&self) -> &VitaAgentRuntimeProfile {
        &self.profile
    }

    pub fn config(&self) -> &codex_core::config::Config {
        &self.config
    }

    /// Returns the pinned protocol handshake value without sending it.
    pub fn initialize_params(&self) -> &InitializeParams {
        &self.initialize
    }

    /// Checks the future execution seam without allowing `NotConfigured` to
    /// reach a thread manager, model client, or HTTP request.
    pub fn prepare_thread_start(&self) -> Result<StartThreadOptions, VitaAgentError> {
        if matches!(
            self.profile.provider_policy(),
            VitaProviderPolicy::NotConfigured
        ) {
            return Err(VitaAgentError::NotConfiguredProvider);
        }
        Ok(StartThreadOptions::new((*self.config).clone()))
    }
}

fn validate_absolute_root(field: &'static str, path: &Path) -> Result<(), VitaAgentError> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(VitaAgentError::InvalidPath {
            field,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn validate_trusted_path(field: &'static str, path: &Path) -> Result<(), VitaAgentError> {
    validate_absolute_root(field, path)?;
    if path
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(VitaAgentError::UnsafePath {
            field,
            path: path.to_path_buf(),
            reason: "dot path components are ambiguous",
        });
    }
    if contains_stock_codex_state(path) {
        return Err(VitaAgentError::ForbiddenStockPath {
            field,
            path: path.to_path_buf(),
        });
    }

    let canonical_prefix = canonical_trusted_prefix(field, path)?;
    if contains_stock_codex_state(&canonical_prefix) {
        return Err(VitaAgentError::ForbiddenStockPath {
            field,
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn canonical_trusted_prefix(field: &'static str, path: &Path) -> Result<PathBuf, VitaAgentError> {
    let mut cursor = path.to_path_buf();
    let mut nearest_existing: Option<(PathBuf, bool)> = None;

    loop {
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) => {
                if is_reparse_point(&metadata) {
                    return Err(VitaAgentError::UnsafePath {
                        field,
                        path: cursor,
                        reason: "reparse point or link component is not trusted",
                    });
                }
                if nearest_existing.is_none() {
                    nearest_existing = Some((cursor.clone(), metadata.is_dir()));
                }
                if cursor == path && !metadata.is_dir() {
                    return Err(VitaAgentError::UnsafePath {
                        field,
                        path: path.to_path_buf(),
                        reason: "trusted root must be a directory",
                    });
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(VitaAgentError::KernelConfig(error)),
        }

        let Some(parent) = cursor.parent() else {
            break;
        };
        if parent == cursor {
            break;
        }
        cursor = parent.to_path_buf();
    }

    let Some((nearest, is_directory)) = nearest_existing else {
        return Err(VitaAgentError::UnsafePath {
            field,
            path: path.to_path_buf(),
            reason: "no existing trusted ancestor could be established",
        });
    };
    if !is_directory {
        return Err(VitaAgentError::UnsafePath {
            field,
            path: nearest,
            reason: "trusted ancestor is not a directory",
        });
    }
    fs::canonicalize(nearest).map_err(VitaAgentError::KernelConfig)
}

fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;

        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn is_strict_descendant(child: &Path, parent: &Path) -> bool {
    let child = normalized_path_for_relationship(child);
    let parent = normalized_path_for_relationship(parent);
    child.len() > parent.len() && child.starts_with(&(parent + "/"))
}

fn normalized_path_for_relationship(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "/")
        .trim_end_matches('/')
        .to_ascii_lowercase()
}

fn ownership_marker_contents() -> &'static [u8] {
    b"runtime_id=vita-agent\nlayout=v1\n"
}

fn ensure_vita_config_sources_absent(
    profile: &VitaAgentRuntimeProfile,
) -> Result<(), VitaAgentError> {
    for path in [
        profile.system_config_path(),
        profile.system_requirements_path(),
        profile.managed_config_path(),
    ] {
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return Err(VitaAgentError::UnexpectedVitaConfigSource { path }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(VitaAgentError::KernelConfig(error)),
        }
    }
    Ok(())
}

fn ensure_vita_auth_source_absent(profile: &VitaAgentRuntimeProfile) -> Result<(), VitaAgentError> {
    match fs::symlink_metadata(profile.auth_path()) {
        Ok(_) => Err(VitaAgentError::UnexpectedVitaAuthSource {
            path: profile.auth_path(),
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(VitaAgentError::KernelConfig(error)),
    }
}

fn contains_stock_codex_state(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    let has_dot_codex_component = path.components().any(|component| {
        matches!(component, Component::Normal(value) if value.eq_ignore_ascii_case(".codex"))
    }) || parts.iter().any(|part| *part == ".codex");
    let has_openai_codex_component = parts.windows(2).any(|window| window == ["openai", "codex"]);
    let has_programdata_openai_codex = parts
        .windows(3)
        .any(|window| window == ["programdata", "openai", "codex"]);
    has_dot_codex_component || has_programdata_openai_codex || has_openai_codex_component
}

fn table<const N: usize>(entries: [(&str, TomlValue); N]) -> TomlValue {
    TomlValue::Table(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_profile() -> (
        tempfile::TempDir,
        tempfile::TempDir,
        VitaAgentRuntimeProfile,
    ) {
        let app_data = tempdir().expect("app-data temp root");
        let workspace = tempdir().expect("workspace temp root");
        let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
            app_data.path().to_path_buf(),
            workspace.path().to_path_buf(),
        )
        .expect("valid explicit Vita profile");
        (app_data, workspace, profile)
    }

    #[test]
    fn exact_codex_pin_and_vita_identity_are_frozen() {
        assert_eq!(VITA_AGENT_RUNTIME_ID, "vita-agent");
        assert_eq!(VITA_UNCONFIGURED_PROVIDER_ID, "vita-unconfigured");
        assert_eq!(VITA_PLACEHOLDER_MODEL_ID, "vita-unconfigured-model");
        assert_eq!(VITA_PLACEHOLDER_BASE_URL, "http://127.0.0.1:9/v1");
        assert_eq!(
            CODEX_UPSTREAM_REPOSITORY,
            "https://github.com/openai/codex.git"
        );
        assert_eq!(CODEX_UPSTREAM_RELEASE, "rust-v0.152.0");
        assert_eq!(
            CODEX_UPSTREAM_COMMIT,
            "316795b3cf2a45e90d121d9f46499d4658b2645c"
        );
        assert_eq!(
            CODEX_PROTOCOL_SCHEMA_HASH,
            "d8faa38d5f00aa7ddfe635a2d374ee5f871ffd217d4d175c72fbe7f009f4f669"
        );
    }

    #[test]
    fn profile_is_explicit_and_never_stock_codex_state() {
        let (_app_data, _workspace, profile) = test_profile();
        assert_eq!(profile.runtime_identity(), VITA_AGENT_RUNTIME_ID);
        assert_eq!(profile.provider_policy(), VitaProviderPolicy::NotConfigured);
        assert_eq!(profile.credential_policy(), VitaCredentialPolicy::NoLogin);
        assert_eq!(profile.network_policy(), VitaNetworkPolicy::Closed);
        assert_eq!(profile.vita_root(), &profile.app_data_root().join("agent"));
        assert_eq!(profile.kernel_home(), profile.vita_root().join("kernel"));
        assert_eq!(profile.state_root(), profile.vita_root().join("state"));
        assert_eq!(profile.runtime_root(), profile.vita_root().join("runtime"));
        assert_eq!(profile.config_root(), profile.vita_root().join("config"));
        assert_eq!(profile.tmp_root(), profile.vita_root().join("tmp"));
        assert_eq!(profile.runs_root(), profile.vita_root().join("runs"));
        assert!(!contains_stock_codex_state(profile.app_data_root()));
        assert!(contains_stock_codex_state(Path::new(
            r"C:\Users\TestUser\.codex"
        )));
        assert!(contains_stock_codex_state(Path::new(
            r"C:\ProgramData\OpenAI\Codex"
        )));

        let user_state_error = VitaAgentRuntimeProfile::from_explicit_app_data_root(
            PathBuf::from(r"C:\Users\TestUser\.codex"),
            profile.workspace_root().to_path_buf(),
        )
        .expect_err("stock user Codex state must be rejected");
        assert!(matches!(
            user_state_error,
            VitaAgentError::ForbiddenStockPath { .. }
        ));

        let workspace_state_error = VitaAgentRuntimeProfile::from_explicit_app_data_root(
            profile.app_data_root().to_path_buf(),
            PathBuf::from(r"C:\Users\TestUser\.codex"),
        )
        .expect_err("stock workspace Codex state must be rejected");
        assert!(matches!(
            workspace_state_error,
            VitaAgentError::ForbiddenStockPath {
                field: "workspace_root",
                ..
            }
        ));

        let system_state_error = VitaAgentRuntimeProfile::from_explicit_app_data_root(
            PathBuf::from(r"C:\ProgramData\OpenAI\Codex"),
            profile.workspace_root().to_path_buf(),
        )
        .expect_err("stock system Codex state must be rejected");
        assert!(matches!(
            system_state_error,
            VitaAgentError::ForbiddenStockPath { .. }
        ));
    }

    #[test]
    fn safe_vita_private_root_is_accepted_and_layout_is_owned() {
        let (_app_data, _workspace, profile) = test_profile();

        profile.validate_private_namespace().unwrap();
        profile.ensure_private_runtime_layout().unwrap();

        assert!(profile.vita_root().is_dir());
        assert!(profile.kernel_home().is_dir());
        assert!(profile.state_root().is_dir());
        assert!(profile.runtime_root().is_dir());
        assert!(profile.runtime_root().join("log").is_dir());
        assert!(profile.config_root().is_dir());
        assert!(profile.tmp_root().is_dir());
        assert!(profile.runs_root().is_dir());
        assert_eq!(
            std::fs::read(profile.ownership_marker_path()).unwrap(),
            ownership_marker_contents()
        );
    }

    #[cfg(windows)]
    #[test]
    fn junction_alias_into_forbidden_stock_state_is_rejected() {
        use std::process::Command;

        let app_data = tempdir().expect("app-data temp root");
        let workspace = tempdir().expect("workspace temp root");
        let forbidden = tempdir().expect("synthetic forbidden root");
        let synthetic_stock = forbidden.path().join(".codex");
        std::fs::create_dir_all(&synthetic_stock).expect("synthetic stock root");
        let alias = app_data.path().join("alias");

        let status = Command::new("cmd.exe")
            .args([
                "/d",
                "/c",
                "mklink",
                "/J",
                alias.to_str().expect("junction alias path"),
                synthetic_stock.to_str().expect("synthetic stock path"),
            ])
            .status()
            .expect("create synthetic junction");
        assert!(status.success(), "mklink /J must create the test alias");

        let error = VitaAgentRuntimeProfile::from_explicit_app_data_root(
            alias,
            workspace.path().to_path_buf(),
        )
        .expect_err("a reparse alias into stock state must fail closed");
        assert!(matches!(
            error,
            VitaAgentError::UnsafePath {
                field: "app_data_root",
                ..
            }
        ));
    }

    #[test]
    fn vita_layout_relationships_reject_stock_parent_and_child_aliases() {
        let (_app_data, _workspace, profile) = test_profile();
        assert!(is_strict_descendant(
            profile.vita_root(),
            profile.app_data_root()
        ));
        assert!(is_strict_descendant(
            profile.runs_root(),
            profile.vita_root()
        ));

        for stock_path in [
            PathBuf::from(r"C:\Users\TestUser\.codex\vita"),
            PathBuf::from(r"C:\ProgramData\OpenAI\Codex\vita"),
            PathBuf::from(r"C:\ProgramData\OpenAI\Codex\agent"),
        ] {
            let error = VitaAgentRuntimeProfile::from_explicit_app_data_root(
                stock_path,
                profile.workspace_root().to_path_buf(),
            )
            .expect_err("Vita root must not equal or nest under stock state");
            assert!(matches!(error, VitaAgentError::ForbiddenStockPath { .. }));
        }
    }

    #[test]
    fn loader_cannot_fall_back_to_host_config_sources() {
        let (_app_data, _workspace, profile) = test_profile();
        let overrides = profile.loader_overrides();
        assert!(overrides.ignore_user_config);
        assert!(overrides.ignore_project_config);
        assert!(overrides.ignore_managed_requirements);
        assert!(overrides.ignore_login_requirements);
        assert_eq!(
            overrides.system_config_path,
            Some(profile.system_config_path())
        );
        assert_eq!(
            overrides.system_requirements_path,
            Some(profile.system_requirements_path())
        );
        assert_eq!(
            overrides.managed_config_path,
            Some(profile.managed_config_path())
        );
        assert!(!contains_stock_codex_state(
            overrides.system_config_path.as_deref().unwrap()
        ));
        assert!(!contains_stock_codex_state(
            overrides.managed_config_path.as_deref().unwrap()
        ));
        assert!(!profile
            .cli_overrides()
            .iter()
            .any(|(_, value)| value.to_string().contains(".codex")));
    }

    #[test]
    fn provider_override_is_vita_owned_and_has_no_auth_source() {
        let (_app_data, _workspace, profile) = test_profile();
        let overrides = profile.cli_overrides();
        let provider_id = overrides
            .iter()
            .find(|(key, _)| key == "model_provider")
            .and_then(|(_, value)| value.as_str());
        assert_eq!(provider_id, Some(VITA_UNCONFIGURED_PROVIDER_ID));

        let model = overrides
            .iter()
            .find(|(key, _)| key == "model")
            .and_then(|(_, value)| value.as_str());
        assert_eq!(model, Some(VITA_PLACEHOLDER_MODEL_ID));

        let provider = overrides
            .iter()
            .find(|(key, _)| key == "model_providers")
            .and_then(|(_, value)| value.as_table())
            .and_then(|providers| providers.get(VITA_UNCONFIGURED_PROVIDER_ID))
            .and_then(TomlValue::as_table)
            .expect("Vita provider override");
        assert_eq!(
            provider.get("name").and_then(TomlValue::as_str),
            Some("Vita Unconfigured Provider")
        );
        assert_eq!(
            provider.get("base_url").and_then(TomlValue::as_str),
            Some(VITA_PLACEHOLDER_BASE_URL)
        );
        assert_eq!(
            provider.get("wire_api").and_then(TomlValue::as_str),
            Some("responses")
        );
        assert_eq!(
            provider
                .get("requires_openai_auth")
                .and_then(TomlValue::as_bool),
            Some(false)
        );
        for auth_key in ["env_key", "experimental_bearer_token", "auth", "aws"] {
            assert!(
                !provider.contains_key(auth_key),
                "provider must not contain {auth_key}"
            );
        }
    }

    #[tokio::test]
    async fn entrypoint_reuses_core_without_auth_or_network_side_effects() {
        let (_app_data, _workspace, profile) = test_profile();
        let entrypoint = VitaAgentEntrypoint::initialize(profile).await.unwrap();

        assert_eq!(entrypoint.profile().runtime_identity(), "vita-agent");
        assert_eq!(
            entrypoint.config().model_provider_id,
            VITA_UNCONFIGURED_PROVIDER_ID
        );
        assert_eq!(
            entrypoint.config().model.as_deref(),
            Some(VITA_PLACEHOLDER_MODEL_ID)
        );
        assert_eq!(
            entrypoint.config().model_provider.name,
            "Vita Unconfigured Provider"
        );
        assert_eq!(
            entrypoint.config().model_provider.base_url.as_deref(),
            Some(VITA_PLACEHOLDER_BASE_URL)
        );
        assert_eq!(
            entrypoint.config().model_provider.wire_api.to_string(),
            "responses"
        );
        assert!(!entrypoint.config().model_provider.requires_openai_auth);
        assert!(entrypoint.config().model_provider.env_key.is_none());
        assert!(entrypoint
            .config()
            .model_provider
            .experimental_bearer_token
            .is_none());
        assert!(entrypoint.config().model_provider.auth.is_none());
        assert!(entrypoint.config().model_provider.aws.is_none());
        assert!(!entrypoint.profile().system_config_path().exists());
        assert!(!entrypoint.profile().system_requirements_path().exists());
        assert!(!entrypoint.profile().managed_config_path().exists());
        assert!(!entrypoint
            .profile()
            .kernel_home()
            .join("auth.json")
            .exists());
        assert_eq!(
            entrypoint.config().codex_home.as_path(),
            entrypoint.profile().kernel_home()
        );
        assert_eq!(
            entrypoint.config().cwd.as_path(),
            entrypoint.profile().workspace_root()
        );
        assert!(!entrypoint.config().check_for_update_on_startup);
        assert_eq!(entrypoint.config().analytics_enabled, Some(false));
        assert!(!entrypoint.config().feedback_enabled);
        assert!(entrypoint.config().mcp_servers.is_empty());
        assert!(!entrypoint
            .config()
            .permissions
            .network_sandbox_policy()
            .is_enabled());
        assert_eq!(
            entrypoint.profile().network_policy(),
            VitaNetworkPolicy::Closed
        );
        assert_eq!(
            format!(
                "{:?}",
                entrypoint.config().permissions.network_sandbox_policy()
            ),
            "Restricted"
        );
        assert!(matches!(
            &entrypoint.config().experimental_thread_store,
            ThreadStoreConfig::InMemory { id } if id == VITA_AGENT_RUNTIME_ID
        ));
        assert!(entrypoint.profile().vita_root().is_dir());
        assert!(entrypoint.profile().tmp_root().is_dir());
        assert!(entrypoint.profile().runs_root().is_dir());
        assert_eq!(
            std::fs::read(entrypoint.profile().ownership_marker_path()).unwrap(),
            ownership_marker_contents()
        );
        assert_eq!(
            entrypoint.initialize_params().client_info.name,
            "vita-agent"
        );

        // The NotConfigured policy stops before StartThreadOptions is built;
        // no ThreadManager, model client, or real model turn can start here.
        let error = match entrypoint.prepare_thread_start() {
            Err(error) => error,
            Ok(_) => panic!("NotConfigured must not cross the execution fence"),
        };
        assert!(matches!(error, VitaAgentError::NotConfiguredProvider));
    }

    #[tokio::test]
    async fn unconfigured_provider_fence_does_not_construct_execution_options() {
        let (_app_data, _workspace, profile) = test_profile();
        let entrypoint = VitaAgentEntrypoint::initialize(profile).await.unwrap();

        let error = match entrypoint.prepare_thread_start() {
            Err(error) => error,
            Ok(_) => panic!("NotConfigured must fail before the model execution seam"),
        };
        assert!(matches!(error, VitaAgentError::NotConfiguredProvider));
    }

    #[tokio::test]
    async fn redirected_vita_config_source_fails_closed_without_reading_or_overwriting() {
        for file_name in [
            "system.config.toml",
            "system.requirements.toml",
            "managed.config.toml",
        ] {
            let app_data = tempdir().expect("app-data temp root");
            let workspace = tempdir().expect("workspace temp root");
            let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
                app_data.path().to_path_buf(),
                workspace.path().to_path_buf(),
            )
            .expect("valid explicit Vita profile");
            let source_path = profile.config_root().join(file_name);
            let original = b"not parsed by the C2 boundary\n";
            std::fs::create_dir_all(profile.config_root()).expect("config root");
            std::fs::write(&source_path, original).expect("sentinel config source");

            let result = VitaAgentEntrypoint::initialize(profile).await;
            match result {
                Err(VitaAgentError::UnexpectedVitaConfigSource { path }) => {
                    assert_eq!(path, source_path);
                }
                Err(_) => panic!("existing Vita config source must fail with the source error"),
                Ok(_) => panic!("existing Vita config source must fail closed"),
            }
            assert_eq!(
                std::fs::read(&source_path).expect("sentinel remains readable"),
                original
            );
        }
    }

    #[tokio::test]
    async fn preexisting_vita_auth_source_fails_closed_without_overwriting() {
        let app_data = tempdir().expect("app-data temp root");
        let workspace = tempdir().expect("workspace temp root");
        let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
            app_data.path().to_path_buf(),
            workspace.path().to_path_buf(),
        )
        .expect("valid explicit Vita profile");
        std::fs::create_dir_all(profile.kernel_home()).expect("kernel root");
        let auth_path = profile.kernel_home().join("auth.json");
        let original = b"must not be read or overwritten\n";
        std::fs::write(&auth_path, original).expect("sentinel auth source");

        let result = VitaAgentEntrypoint::initialize(profile).await;
        match result {
            Err(VitaAgentError::UnexpectedVitaAuthSource { path }) => {
                assert_eq!(path, auth_path);
            }
            Err(_) => panic!("existing Vita auth source must fail with the auth error"),
            Ok(_) => panic!("existing Vita auth source must fail closed"),
        }
        assert_eq!(std::fs::read(&auth_path).unwrap(), original);
    }

    #[test]
    fn host_codex_home_environment_is_not_an_input() {
        let (_app_data, _workspace, profile) = test_profile();
        // The constructor has no environment-derived branch: an inherited
        // CODEX_HOME cannot replace the explicit profile root.
        assert_eq!(profile.kernel_home(), profile.vita_root().join("kernel"));
        assert_ne!(profile.vita_root(), Path::new(r"C:\Users\TestUser\.codex"));
    }

    #[test]
    fn cleanup_requires_marker_and_vita_owned_descendant() {
        let (_app_data, _workspace, profile) = test_profile();
        profile.ensure_private_runtime_layout().unwrap();

        let owned_run = profile.runs_root().join("test-run");
        std::fs::create_dir(&owned_run).unwrap();
        profile.cleanup_owned_test_dir(&owned_run).unwrap();
        assert!(!owned_run.exists());

        let outside = profile.app_data_root().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let error = profile
            .cleanup_owned_test_dir(&outside)
            .expect_err("cleanup outside runs root must fail closed");
        assert!(matches!(error, VitaAgentError::CleanupRejected { .. }));
        std::fs::remove_dir(&outside).unwrap();
    }

    #[test]
    fn cleanup_rejects_missing_or_mismatched_marker() {
        let (_app_data, _workspace, profile) = test_profile();
        profile.ensure_private_runtime_layout().unwrap();
        let owned_run = profile.runs_root().join("test-run");
        std::fs::create_dir(&owned_run).unwrap();

        std::fs::remove_file(profile.ownership_marker_path()).unwrap();
        let missing_error = profile
            .cleanup_owned_test_dir(&owned_run)
            .expect_err("cleanup requires a present ownership marker");
        assert!(matches!(
            missing_error,
            VitaAgentError::OwnershipViolation { .. }
        ));

        std::fs::write(profile.ownership_marker_path(), b"runtime_id=other\n").unwrap();
        let mismatched_error = profile
            .cleanup_owned_test_dir(&owned_run)
            .expect_err("cleanup requires the matching ownership marker");
        assert!(matches!(
            mismatched_error,
            VitaAgentError::OwnershipViolation { .. }
        ));
    }

    #[test]
    fn profile_validation_never_mutates_parent_environment() {
        let before = std::env::vars_os().collect::<Vec<_>>();
        let (_app_data, _workspace, profile) = test_profile();
        profile.validate_private_namespace().unwrap();
        let after = std::env::vars_os().collect::<Vec<_>>();
        assert_eq!(before, after);
    }
}
