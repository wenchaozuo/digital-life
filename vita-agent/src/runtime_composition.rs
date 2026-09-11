//! Production composition of the Vita entrypoint with the pinned Codex
//! thread runtime.
//!
//! This module is compiled only in the Vita sidecar process.  The Tauri Host
//! has no dependency edge to this crate or to any Codex crate; it communicates
//! with the sidecar through `digital-life-vita-agent-protocol` instead.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use codex_core_api::{
    AuthCredentialsStoreMode, AuthManager, CodexAppsToolsCache, EnvironmentManager, EventMsg,
    ExtensionRegistryBuilder, LoadUserInstructionsFuture, LoadedUserInstructions, Op,
    SessionSource, StartThreadOptions, ThreadManager, TurnInputRequest, UserInput,
    UserInstructionsProvider,
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
    config: codex_core::config::Config,
    active: AtomicBool,
    active_thread: Mutex<Option<Arc<codex_core_api::CodexThread>>>,
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
        Ok(Self {
            manager,
            config: config.clone(),
            active: AtomicBool::new(false),
            active_thread: Mutex::new(None),
        })
    }

    /// Runs one bounded user turn on the single sidecar-owned Codex runtime.
    /// The caller owns the protocol lifecycle; this method deliberately
    /// returns only the bounded terminal assistant text and never exposes a
    /// raw Codex transcript or provider response.
    pub async fn run_turn(&self, prompt: String) -> Result<String, VitaAgentError> {
        if self.active.swap(true, Ordering::AcqRel) {
            return Err(VitaAgentError::GatewayProtocol(
                "another Vita turn is already active".to_string(),
            ));
        }

        let result = async {
            let new_thread = tokio::time::timeout(
                Duration::from_secs(30),
                self.manager
                    .start_thread(StartThreadOptions::new(self.config.clone())),
            )
            .await
            .map_err(|_| {
                VitaAgentError::GatewayProtocol("Vita turn startup timed out".to_string())
            })?
            .map_err(|error| {
                VitaAgentError::GatewayProtocol(format!("Vita turn startup failed: {error}"))
            })?;
            let thread = new_thread.thread;
            if let Ok(mut active_thread) = self.active_thread.lock() {
                *active_thread = Some(Arc::clone(&thread));
            }

            let submission = tokio::time::timeout(
                Duration::from_secs(30),
                thread.start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
                    text: prompt,
                    text_elements: Vec::new(),
                }])),
            )
            .await
            .map_err(|_| {
                VitaAgentError::GatewayProtocol("Vita turn submission timed out".to_string())
            })?
            .map_err(|error| {
                VitaAgentError::GatewayProtocol(format!("Vita turn submission failed: {error}"))
            })?;
            let _ = submission;

            let deadline = tokio::time::Instant::now() + Duration::from_secs(300);
            let mut assistant_text = String::new();
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    let _ = thread.submit(Op::Interrupt).await;
                    return Err(VitaAgentError::GatewayProtocol(
                        "Vita turn timed out".to_string(),
                    ));
                }
                let event = tokio::time::timeout(remaining, thread.next_event())
                    .await
                    .map_err(|_| {
                        VitaAgentError::GatewayProtocol("Vita turn timed out".to_string())
                    })?
                    .map_err(|error| {
                        VitaAgentError::GatewayProtocol(format!(
                            "Vita event stream failed: {error}"
                        ))
                    })?;
                match event.msg {
                    EventMsg::AgentMessage(message) => {
                        append_bounded_text(
                            &mut assistant_text,
                            &message.message,
                            vita_agent_protocol::MAX_TURN_OUTPUT_BYTES,
                        );
                    }
                    EventMsg::TurnComplete(complete) => {
                        if let Some(message) = complete.last_agent_message {
                            assistant_text =
                                bounded_text(&message, vita_agent_protocol::MAX_TURN_OUTPUT_BYTES);
                        }
                        if let Some(error) = complete.error {
                            return Err(VitaAgentError::GatewayProtocol(
                                error.message.chars().take(256).collect(),
                            ));
                        }
                        return Ok(assistant_text);
                    }
                    EventMsg::TurnAborted(_) => {
                        return Err(VitaAgentError::GatewayProtocol(
                            "Vita turn was cancelled".to_string(),
                        ));
                    }
                    _ => {}
                }
            }
        }
        .await;

        if let Ok(mut active_thread) = self.active_thread.lock() {
            active_thread.take();
        }
        self.active.store(false, Ordering::Release);
        result
    }

    /// Best-effort bounded interruption used by Host cancellation and sidecar
    /// retirement.  It never starts a replacement turn.
    pub async fn interrupt_active_turn(&self) -> bool {
        let thread = self
            .active_thread
            .lock()
            .ok()
            .and_then(|active| active.clone());
        let Some(thread) = thread else { return false };
        tokio::time::timeout(Duration::from_secs(2), thread.submit(Op::Interrupt))
            .await
            .is_ok_and(|result| result.is_ok())
    }

    pub async fn shutdown(&self) {
        let _ = self.interrupt_active_turn().await;
        let _ = self
            .manager
            .shutdown_all_threads_bounded(Duration::from_secs(2))
            .await;
    }
}

fn append_bounded_text(target: &mut String, value: &str, max_bytes: usize) {
    if target.len() >= max_bytes {
        return;
    }
    let remaining = max_bytes - target.len();
    if value.len() <= remaining {
        target.push_str(value);
        return;
    }
    let mut end = remaining;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    target.push_str(&value[..end]);
}

fn bounded_text(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}
