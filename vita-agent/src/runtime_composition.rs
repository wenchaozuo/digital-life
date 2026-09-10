//! Production composition of the Vita entrypoint with the pinned Codex
//! thread runtime.
//!
//! This module is compiled only in the Vita sidecar process.  The Tauri Host
//! has no dependency edge to this crate or to any Codex crate; it communicates
//! with the sidecar through `digital-life-vita-agent-protocol` instead.

use std::sync::Arc;
use std::time::Duration;

use codex_core_api::{
    AuthCredentialsStoreMode, AuthManager, CodexAppsToolsCache, EnvironmentManager,
    ExtensionRegistryBuilder, LoadUserInstructionsFuture, LoadedUserInstructions, SessionSource,
    ThreadManager, UserInstructionsProvider,
};
use codex_extension_api::ToolContributor;

use crate::{VitaAgentEntrypoint, VitaAgentError};

#[derive(Debug, Default)]
struct NoUserInstructions;

impl UserInstructionsProvider for NoUserInstructions {
    fn load_user_instructions(&self) -> LoadUserInstructionsFuture<'_> {
        Box::pin(async { LoadedUserInstructions::default() })
    }
}

/// One sidecar-owned pinned Codex runtime.  No Host SQLite or user Codex
/// configuration is reachable from this object.
pub struct VitaAgentRuntime {
    manager: Arc<ThreadManager>,
}

impl VitaAgentRuntime {
    pub async fn compose<C>(
        entrypoint: &VitaAgentEntrypoint,
        contributor: C,
    ) -> Result<Self, VitaAgentError>
    where
        C: ToolContributor + Send + Sync + 'static,
    {
        let config = entrypoint.config();
        let auth_config = config.auth_config();
        let auth_manager = Arc::new(
            AuthManager::new(
                config.codex_home.to_path_buf(),
                false,
                AuthCredentialsStoreMode::Ephemeral,
                auth_config.forced_chatgpt_workspace_id,
                auth_config.chatgpt_base_url,
                auth_config.keyring_backend_kind,
                auth_config.auth_route_config,
            )
            .await,
        );

        let mut extension_builder = ExtensionRegistryBuilder::<codex_core::config::Config>::new();
        extension_builder.tool_contributor(Arc::new(contributor));
        let extensions = Arc::new(extension_builder.build());
        let environment_manager = Arc::new(EnvironmentManager::without_environments(
            config.http_client_factory(),
        ));
        let manager = Arc::new(ThreadManager::new(
            config,
            Arc::clone(&auth_manager),
            codex_core_api::build_models_manager(config, Arc::clone(&auth_manager)),
            CodexAppsToolsCache::default(),
            SessionSource::Exec,
            environment_manager,
            extensions,
            Arc::new(NoUserInstructions),
            None,
            codex_core_api::thread_store_from_config(config, None),
            None,
            "digital-life-vita-sidecar".to_string(),
            None,
            None,
        ));
        Ok(Self { manager })
    }

    pub async fn shutdown(&self) {
        let _ = self
            .manager
            .shutdown_all_threads_bounded(Duration::from_secs(2))
            .await;
    }
}
