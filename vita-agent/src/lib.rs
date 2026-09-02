//! Digital Life-owned Vita Agent boundary over the pinned Codex execution kernel.
//!
//! D29-C2 establishes the source-kernel boundary and its isolation rules.  It
//! does not start a model turn, authenticate an account, expose tools, or add
//! a Tauri/frontend caller.  The public crate boundary is intentionally small:
//! a later Digital Life authority stage can supply a profile and ask for the
//! official Codex thread-start options.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use codex_app_server_protocol::{ClientInfo, InitializeCapabilities, InitializeParams};
use codex_config::LoaderOverrides;
use codex_core::config::{ConfigBuilder, ThreadStoreConfig};
use codex_core::StartThreadOptions;
use toml::map::Map;
use toml::Value as TomlValue;

pub const VITA_AGENT_RUNTIME_ID: &str = "vita-agent";
pub const CODEX_UPSTREAM_REPOSITORY: &str = "https://github.com/openai/codex.git";
pub const CODEX_UPSTREAM_RELEASE: &str = "rust-v0.152.0";
pub const CODEX_UPSTREAM_COMMIT: &str = "316795b3cf2a45e90d121d9f46499d4658b2645c";
pub const CODEX_PROTOCOL_SCHEMA_HASH: &str =
    "d8faa38d5f00aa7ddfe635a2d374ee5f871ffd217d4d175c72fbe7f009f4f669";

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
    kernel_home: PathBuf,
    state_root: PathBuf,
    runtime_root: PathBuf,
    config_root: PathBuf,
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
    /// is consulted here.  `workspace_root` may be an ordinary project that
    /// contains a `.codex` directory because the Codex project layer is later
    /// disabled by `loader_overrides`.
    pub fn from_explicit_app_data_root(
        app_data_root: PathBuf,
        workspace_root: PathBuf,
    ) -> Result<Self, VitaAgentError> {
        validate_absolute_root("app_data_root", &app_data_root)?;
        validate_absolute_root("workspace_root", &workspace_root)?;
        if contains_stock_codex_state(&app_data_root) {
            return Err(VitaAgentError::ForbiddenStockPath {
                field: "app_data_root",
                path: app_data_root,
            });
        }

        Ok(Self {
            kernel_home: app_data_root.join("kernel"),
            state_root: app_data_root.join("state"),
            runtime_root: app_data_root.join("runtime"),
            config_root: app_data_root.join("config"),
            app_data_root,
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

    fn system_config_path(&self) -> PathBuf {
        self.config_root.join("system.config.toml")
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

        vec![
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
}

#[derive(Debug)]
pub enum VitaAgentError {
    InvalidPath { field: &'static str, path: PathBuf },
    ForbiddenStockPath { field: &'static str, path: PathBuf },
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
    /// `prepare_thread_start` exposes the official Codex loop options for the
    /// next governed stage without starting a turn in D29-C2.
    pub async fn initialize(profile: VitaAgentRuntimeProfile) -> Result<Self, VitaAgentError> {
        let config = ConfigBuilder::default()
            .codex_home(profile.kernel_home().to_path_buf())
            .fallback_cwd(Some(profile.workspace_root().to_path_buf()))
            .cli_overrides(profile.cli_overrides())
            .loader_overrides(profile.loader_overrides())
            .strict_config(true)
            .build()
            .await
            .map_err(VitaAgentError::KernelConfig)?;

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

    /// Prepares an official Codex thread-loop boundary without starting it.
    pub fn prepare_thread_start(&self) -> StartThreadOptions {
        StartThreadOptions::new((*self.config).clone())
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

fn contains_stock_codex_state(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let has_dot_codex_component = path.components().any(|component| {
        matches!(component, Component::Normal(value) if value.eq_ignore_ascii_case(".codex"))
    });
    has_dot_codex_component
        || normalized.contains("/programdata/openai/codex")
        || normalized.ends_with("/openai/codex")
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
        assert_eq!(
            profile.kernel_home(),
            profile.app_data_root().join("kernel")
        );
        assert_eq!(profile.state_root(), profile.app_data_root().join("state"));
        assert_eq!(
            profile.runtime_root(),
            profile.app_data_root().join("runtime")
        );
        assert_eq!(
            profile.config_root(),
            profile.app_data_root().join("config")
        );
        assert!(!contains_stock_codex_state(profile.app_data_root()));
        assert!(contains_stock_codex_state(Path::new(
            r"C:\Users\zuo\.codex"
        )));
        assert!(contains_stock_codex_state(Path::new(
            r"C:\ProgramData\OpenAI\Codex"
        )));

        let user_state_error = VitaAgentRuntimeProfile::from_explicit_app_data_root(
            PathBuf::from(r"C:\Users\zuo\.codex"),
            profile.workspace_root().to_path_buf(),
        )
        .expect_err("stock user Codex state must be rejected");
        assert!(matches!(
            user_state_error,
            VitaAgentError::ForbiddenStockPath { .. }
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

    #[tokio::test]
    async fn entrypoint_reuses_core_without_auth_or_network_side_effects() {
        let (_app_data, _workspace, profile) = test_profile();
        let entrypoint = VitaAgentEntrypoint::initialize(profile).await.unwrap();

        assert_eq!(entrypoint.profile().runtime_identity(), "vita-agent");
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
            entrypoint.initialize_params().client_info.name,
            "vita-agent"
        );

        // Type-check and prepare the official agent-loop boundary, but do not
        // construct ThreadManager or start a real model turn in D29-C2.
        let options = entrypoint.prepare_thread_start();
        assert_eq!(
            options.config.codex_home.as_path(),
            entrypoint.profile().kernel_home()
        );
    }

    #[test]
    fn host_codex_home_environment_is_not_an_input() {
        let (_app_data, _workspace, profile) = test_profile();
        // The constructor has no environment-derived branch: an inherited
        // CODEX_HOME cannot replace the explicit profile root.
        assert_eq!(
            profile.kernel_home(),
            profile.app_data_root().join("kernel")
        );
        assert_ne!(profile.kernel_home(), Path::new(r"C:\Users\zuo\.codex"));
    }
}
