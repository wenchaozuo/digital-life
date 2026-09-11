//! D29-H8-R1 Host boundary for the process-isolated Vita sidecar.
//!
//! The Host owns the lifecycle, the D28 SQLite read, confirmation state, and
//! the short-lived grant ledger.  Vita receives only the bounded protocol
//! DTOs; no provider credential, SQLite handle, or Codex crate crosses this
//! module boundary.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};
use vita_agent_protocol as protocol;

#[cfg(windows)]
use crate::secrets::{SecretIdentifier, SecretStore, WindowsCredentialSecretStore};
use crate::{
    capability::CapabilityRegistry,
    model::profile::{credential_purpose, ModelProfileRepository, ModelProviderKind, ModelPurpose},
    storage::StorageService,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VitaSidecarStartRequest {
    pub life_id: String,
    pub task_id: String,
    pub workspace_path: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VitaSidecarStartResponse {
    pub session_id: String,
    pub ready: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VitaTurnStartRequest {
    pub prompt: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VitaTurnStartResponse {
    pub turn_id: String,
    pub accepted: bool,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VitaProviderReadiness {
    NoActiveProfile,
    CredentialMissing,
    IneligibleUrl,
    Ready,
    SidecarNotRunning,
    TurnActive,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VitaSidecarPendingSummary {
    pub pending_id: String,
    pub life_id: String,
    pub task_id: String,
    pub capability_id: String,
    pub workspace_summary: String,
    pub expires_at_unix_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VitaSidecarStatusResponse {
    pub running: bool,
    pub provider_readiness: VitaProviderReadiness,
    pub session_id: Option<String>,
    pub pending: Option<VitaSidecarPendingSummary>,
    pub active_turn_id: Option<String>,
    pub turn_phase: Option<protocol::TurnPhase>,
    pub assistant_text: Option<String>,
    pub turn_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VitaSidecarActionResponse {
    pub accepted: bool,
}

pub struct VitaSidecarCoordinator {
    authority_storage: Arc<StorageService>,
    registry: CapabilityRegistry,
    #[cfg(windows)]
    credential_store: WindowsCredentialSecretStore,
    #[cfg(windows)]
    inner: Mutex<WindowsCoordinatorState>,
    #[cfg(not(windows))]
    inner: Mutex<()>,
}

impl VitaSidecarCoordinator {
    pub(crate) fn new(
        authority_storage: Arc<StorageService>,
        registry: CapabilityRegistry,
    ) -> Self {
        Self {
            authority_storage,
            registry,
            #[cfg(windows)]
            credential_store: WindowsCredentialSecretStore::new(),
            #[cfg(windows)]
            inner: Mutex::new(WindowsCoordinatorState::default()),
            #[cfg(not(windows))]
            inner: Mutex::new(()),
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::capability::authorization::{
        evaluate_capability_authorization, CapabilityAuthorizationDecisionKind,
        RequestedCapabilityScope,
    };
    use crate::capability::descriptor::{
        CapabilityId, PRODUCTION_GIT_STATUS_CAPABILITY_ID, PRODUCTION_GIT_STATUS_PROFILE_ID,
        PRODUCTION_GIT_STATUS_TOOL_NAME,
    };
    use crate::execution_enclave::{CodexRuntimeError, VitaSidecarProcess};
    use protocol::{
        AuthorityEvaluate, AuthorityScopeReply, ConfirmationDecision, ConfirmationReply,
        ConfirmationRequired, GrantIssued, GrantRevalidated, HostMessage, InitializeSession,
        IssueGrant, ProcessBinding, ProcessGrant, RevalidateGrant, VitaMessage,
        CODEX_PROTOCOL_SCHEMA_HASH, CODEX_UPSTREAM_COMMIT, PROTOCOL_VERSION, RUNTIME_ID,
    };
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::ffi::OsString;
    use std::fs::{self, File};
    use std::io::{BufReader, BufWriter};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::sync::{Condvar, Weak};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tauri::{AppHandle, Manager, State};
    use vita_agent_protocol as protocol;

    // H7-C's fixed Git-status program identity is the profile identity.  The
    // generic H7 fixture program id is deliberately not accepted on this
    // production capability lane.
    const PROGRAM_ID: &str = PRODUCTION_GIT_STATUS_PROFILE_ID;
    const GRANT_LIFETIME_MS: u64 = 30_000;
    const HOST_CONFIRMATION_TTL_MS: u64 = 30_000;
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
    const READY_TIMEOUT: Duration = Duration::from_secs(20);
    const MAX_PENDING: usize = 1;
    // Active grants are bounded, but successful single-use grants are removed
    // immediately after final revalidation, so this is not a session lifetime
    // limit.
    const MAX_GRANTS: usize = 64;
    const REQUEST_REPLAY_WINDOW: usize = 128;
    const SIDECAR_RESOURCE_NAME: &str = "vita-agent.exe";
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    fn active_chat_provider_configuration(
        storage: &StorageService,
        secrets: &WindowsCredentialSecretStore,
    ) -> Result<Option<protocol::ProviderConfiguration>, String> {
        let Some(active) = storage
            .get_active_profile(ModelPurpose::Chat)
            .map_err(|error| error.message)?
        else {
            return Ok(None);
        };
        let Some(profile) = storage
            .get_profile(&active.profile_id)
            .map_err(|error| error.message)?
        else {
            return Ok(None);
        };
        if profile.purpose != ModelPurpose::Chat
            || profile.provider_kind != ModelProviderKind::OpenaiCompatible
        {
            return Ok(None);
        }
        let credential_ref =
            SecretIdentifier::new(credential_purpose(ModelPurpose::Chat), profile.id.clone())
                .map_err(|_| "Vita Chat credential identifier was invalid".to_string())?;
        if !secrets
            .has_secret(&credential_ref)
            .map_err(|_| "Vita Chat credential availability could not be checked".to_string())?
        {
            return Ok(None);
        }
        Ok(Some(protocol::ProviderConfiguration {
            profile_id: profile.id.clone(),
            purpose: profile.purpose.as_str().to_string(),
            provider_kind: profile.provider_kind.as_str().to_string(),
            base_url: profile.base_url.clone(),
            model: profile.model_name.clone(),
            credential_ref: profile.id.clone(),
            credential_destination: profile.base_url,
        }))
    }

    fn provider_readiness(
        storage: &StorageService,
        secrets: &WindowsCredentialSecretStore,
        running: bool,
        turn_active: bool,
    ) -> Result<VitaProviderReadiness, String> {
        let Some(active) = storage
            .get_active_profile(ModelPurpose::Chat)
            .map_err(|error| error.message)?
        else {
            return Ok(VitaProviderReadiness::NoActiveProfile);
        };
        let Some(profile) = storage
            .get_profile(&active.profile_id)
            .map_err(|error| error.message)?
        else {
            return Ok(VitaProviderReadiness::NoActiveProfile);
        };
        if profile.purpose != ModelPurpose::Chat
            || profile.provider_kind != ModelProviderKind::OpenaiCompatible
        {
            return Ok(VitaProviderReadiness::NoActiveProfile);
        }
        let identifier =
            SecretIdentifier::new(credential_purpose(ModelPurpose::Chat), profile.id.clone())
                .map_err(|_| "Vita Chat credential identifier was invalid".to_string())?;
        if !secrets
            .has_secret(&identifier)
            .map_err(|_| "Vita Chat credential availability could not be checked".to_string())?
        {
            return Ok(VitaProviderReadiness::CredentialMissing);
        }
        let url = reqwest::Url::parse(&profile.base_url)
            .map_err(|_| "Vita Chat provider URL was invalid".to_string())?;
        if url.scheme() != "https" {
            return Ok(VitaProviderReadiness::IneligibleUrl);
        }
        if !running {
            return Ok(VitaProviderReadiness::SidecarNotRunning);
        }
        if turn_active {
            return Ok(VitaProviderReadiness::TurnActive);
        }
        Ok(VitaProviderReadiness::Ready)
    }

    #[derive(Default)]
    pub(super) struct WindowsCoordinatorState {
        running: Option<RunningSidecar>,
        starting: bool,
    }

    pub(super) use self::WindowsCoordinatorState as StateType;

    struct RunningSidecar {
        session: Arc<HostSessionState>,
        process: VitaSidecarProcess,
        reader: Option<JoinHandle<()>>,
    }

    impl RunningSidecar {
        fn stop(mut self) {
            let _ = self
                .session
                .send(&HostMessage::Shutdown(protocol::Shutdown {
                    request_id: next_id("host-shutdown"),
                    session_id: self.session.session_id.clone(),
                }));
            self.session.retire();
            self.session.close_writer();
            let _ = self.process.shutdown();
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }

    struct HostSessionState {
        session_id: String,
        life_id: String,
        task_id: String,
        workspace_identity: String,
        provider: Option<protocol::ProviderConfiguration>,
        writer: Mutex<Option<BufWriter<File>>>,
        pending: Mutex<HashMap<String, PendingAction>>,
        approvals: Mutex<HashMap<String, ApprovedAction>>,
        grants: Mutex<HashMap<String, ProcessGrant>>,
        replay: Mutex<RequestReplayWindow>,
        expiry: Arc<ExpiryOwner>,
        closed: AtomicBool,
        active_turn_id: Mutex<Option<String>>,
        turn_phase: Mutex<Option<protocol::TurnPhase>>,
        assistant_text: Mutex<Option<String>>,
        turn_error: Mutex<Option<String>>,
        #[cfg(test)]
        test_outbound: Mutex<Option<mpsc::Sender<HostMessage>>>,
    }

    #[derive(Clone)]
    struct PendingAction {
        pending_id: String,
        request_id: String,
        life_id: String,
        task_id: String,
        capability_id: String,
        workspace_summary: String,
        expires_at_unix_ms: u64,
        binding: ProcessBinding,
    }

    struct ApprovedAction {
        binding: ProcessBinding,
        authorization_revision: i64,
        confirmation_id: String,
        expires_at_unix_ms: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct ExpiryTicket {
        session_id: String,
        pending_id: String,
        request_id: String,
        binding: ProcessBinding,
        expires_at_unix_ms: u64,
    }

    impl ExpiryTicket {
        fn for_pending(session_id: &str, pending: &PendingAction) -> Self {
            Self {
                session_id: session_id.to_string(),
                pending_id: pending.pending_id.clone(),
                request_id: pending.request_id.clone(),
                binding: pending.binding.clone(),
                expires_at_unix_ms: pending.expires_at_unix_ms,
            }
        }
    }

    struct ExpiryState {
        ticket: Option<ExpiryTicket>,
        stopped: bool,
    }

    struct ExpiryOwner {
        control: Arc<(Mutex<ExpiryState>, Condvar)>,
        worker: Mutex<Option<JoinHandle<()>>>,
    }

    impl ExpiryOwner {
        fn new() -> Self {
            Self {
                control: Arc::new((
                    Mutex::new(ExpiryState {
                        ticket: None,
                        stopped: false,
                    }),
                    Condvar::new(),
                )),
                worker: Mutex::new(None),
            }
        }

        fn start(&self, session: Weak<HostSessionState>) -> Result<(), String> {
            let control = Arc::clone(&self.control);
            let worker = thread::Builder::new()
                .name("vita-sidecar-confirmation-expiry".to_string())
                .spawn(move || expiry_loop(control, session))
                .map_err(|_| "Vita confirmation expiry worker could not start".to_string())?;
            let mut slot = self
                .worker
                .lock()
                .map_err(|_| "Vita expiry worker lock was poisoned".to_string())?;
            if slot.is_some() {
                return Err("Vita confirmation expiry worker was already started".to_string());
            }
            *slot = Some(worker);
            Ok(())
        }

        fn schedule(&self, ticket: ExpiryTicket) {
            let (state, wake) = &*self.control;
            if let Ok(mut state) = state.lock() {
                if !state.stopped {
                    state.ticket = Some(ticket);
                    wake.notify_one();
                }
            }
        }

        fn clear(&self, ticket: &ExpiryTicket) {
            let (state, wake) = &*self.control;
            if let Ok(mut state) = state.lock() {
                if state.ticket.as_ref() == Some(ticket) {
                    state.ticket = None;
                    wake.notify_one();
                }
            }
        }

        fn stop(&self) {
            let worker = {
                let (state, wake) = &*self.control;
                if let Ok(mut state) = state.lock() {
                    state.stopped = true;
                    state.ticket = None;
                    wake.notify_all();
                }
                self.worker.lock().ok().and_then(|mut slot| slot.take())
            };
            if let Some(worker) = worker {
                let _ = worker.join();
            }
        }
    }

    impl Drop for ExpiryOwner {
        fn drop(&mut self) {
            self.stop();
        }
    }

    #[derive(Default)]
    struct RequestReplayWindow {
        order: VecDeque<String>,
        seen: HashSet<String>,
    }

    impl RequestReplayWindow {
        fn accept(&mut self, request_id: &str) -> bool {
            if self.seen.contains(request_id) {
                return false;
            }
            self.seen.insert(request_id.to_string());
            self.order.push_back(request_id.to_string());
            while self.order.len() > REQUEST_REPLAY_WINDOW {
                if let Some(retired) = self.order.pop_front() {
                    self.seen.remove(&retired);
                }
            }
            true
        }

        fn clear(&mut self) {
            self.order.clear();
            self.seen.clear();
        }

        #[cfg(test)]
        fn len(&self) -> usize {
            self.order.len()
        }
    }

    impl HostSessionState {
        fn send(&self, message: &HostMessage) -> Result<(), String> {
            #[cfg(test)]
            if let Ok(hook) = self.test_outbound.lock() {
                if let Some(sender) = hook.as_ref() {
                    return sender
                        .send(message.clone())
                        .map_err(|_| "Vita test outbound channel was closed".to_string());
                }
            }
            let mut guard = self
                .writer
                .lock()
                .map_err(|_| "Vita Host writer lock was poisoned".to_string())?;
            let writer = guard
                .as_mut()
                .ok_or_else(|| "Vita Host sidecar writer is closed".to_string())?;
            if matches!(message, HostMessage::SensitiveCredentialReply(_)) {
                protocol::write_sensitive_frame(writer, message).map_err(|error| error.to_string())
            } else {
                protocol::write_frame(writer, message).map_err(|error| error.to_string())
            }
        }

        fn close_writer(&self) {
            if let Ok(mut writer) = self.writer.lock() {
                writer.take();
            }
        }

        fn pending_summary(&self) -> Option<VitaSidecarPendingSummary> {
            let pending = self.pending.lock().ok()?.values().next()?.clone();
            Some(VitaSidecarPendingSummary {
                pending_id: pending_key(&pending),
                life_id: pending.life_id,
                task_id: pending.task_id,
                capability_id: pending.capability_id,
                workspace_summary: pending.workspace_summary,
                expires_at_unix_ms: pending.expires_at_unix_ms,
            })
        }

        fn accept_request_id(&self, request_id: &str) -> bool {
            self.replay
                .lock()
                .map(|mut replay| replay.accept(request_id))
                .unwrap_or(false)
        }

        fn retire(&self) {
            self.closed.store(true, Ordering::Release);
            let pending = if let Ok(mut pending) = self.pending.lock() {
                pending.drain().map(|(_, value)| value).collect::<Vec<_>>()
            } else {
                Vec::new()
            };
            for pending in pending {
                let _ = self.send(&HostMessage::ConfirmationReply(ConfirmationReply {
                    request_id: pending.request_id,
                    session_id: self.session_id.clone(),
                    decision: ConfirmationDecision::Deny,
                    authorization_revision: None,
                }));
            }
            if let Ok(mut approvals) = self.approvals.lock() {
                approvals.clear();
            }
            if let Ok(mut grants) = self.grants.lock() {
                grants.clear();
            }
            if let Ok(mut replay) = self.replay.lock() {
                replay.clear();
            }
            self.expiry.stop();
            if let Ok(mut turn) = self.active_turn_id.lock() {
                turn.take();
            }
            if let Ok(mut phase) = self.turn_phase.lock() {
                *phase = Some(protocol::TurnPhase::Cancelled);
            }
        }
    }

    fn pending_key(pending: &PendingAction) -> String {
        pending.pending_id.clone()
    }

    fn expiry_loop(control: Arc<(Mutex<ExpiryState>, Condvar)>, session: Weak<HostSessionState>) {
        loop {
            let ticket = {
                let (state_lock, wake) = &*control;
                let mut state = match state_lock.lock() {
                    Ok(state) => state,
                    Err(_) => return,
                };
                loop {
                    if state.stopped {
                        return;
                    }
                    let Some(ticket) = state.ticket.clone() else {
                        state = match wake.wait(state) {
                            Ok(state) => state,
                            Err(_) => return,
                        };
                        continue;
                    };
                    let now = unix_millis();
                    if ticket.expires_at_unix_ms > now {
                        let wait_for =
                            Duration::from_millis(ticket.expires_at_unix_ms.saturating_sub(now));
                        state = match wake.wait_timeout(state, wait_for) {
                            Ok((state, _)) => state,
                            Err(_) => return,
                        };
                        continue;
                    }
                    // Retire this ticket before dropping the control lock.  A
                    // newer pending action can install a new ticket while the
                    // exact old ticket is being retired.
                    state.ticket = None;
                    break ticket;
                }
            };
            let Some(session) = session.upgrade() else {
                return;
            };
            session.expire_pending_ticket(&ticket);
        }
    }

    impl HostSessionState {
        fn expire_pending_ticket(&self, ticket: &ExpiryTicket) {
            if self.closed.load(Ordering::Acquire) || ticket.session_id != self.session_id {
                return;
            }
            let expired = if let Ok(mut pending) = self.pending.lock() {
                let key = pending.iter().find_map(|(key, value)| {
                    (value.pending_id == ticket.pending_id
                        && value.request_id == ticket.request_id
                        && value.binding == ticket.binding
                        && value.expires_at_unix_ms == ticket.expires_at_unix_ms
                        && value.expires_at_unix_ms <= unix_millis())
                    .then_some(key.clone())
                });
                key.and_then(|key| pending.remove(&key))
            } else {
                None
            };
            if let Some(pending) = expired {
                let _ = self.send(&HostMessage::ConfirmationReply(ConfirmationReply {
                    request_id: pending.request_id,
                    session_id: self.session_id.clone(),
                    decision: ConfirmationDecision::Deny,
                    authorization_revision: None,
                }));
            }
        }
    }

    impl VitaSidecarCoordinator {
        fn start(
            &self,
            app: &AppHandle,
            request: VitaSidecarStartRequest,
        ) -> Result<VitaSidecarStartResponse, String> {
            validate_id(&request.life_id)?;
            validate_id(&request.task_id)?;
            let life = self
                .authority_storage
                .get_life(&request.life_id)
                .map_err(|error| error.message)?
                .ok_or_else(|| "Vita life identity was not found".to_string())?;
            if life.id != request.life_id {
                return Err("Vita life identity binding was not exact".to_string());
            }

            {
                let mut guard = self
                    .inner
                    .lock()
                    .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
                if guard.starting {
                    return Err("Vita sidecar already has an active session".to_string());
                }
                if guard
                    .running
                    .as_ref()
                    .is_some_and(|running| running.session.closed.load(Ordering::Acquire))
                {
                    let retired = guard.running.take();
                    drop(guard);
                    if let Some(retired) = retired {
                        retired.stop();
                    }
                    guard = self
                        .inner
                        .lock()
                        .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
                }
                if guard.running.is_some() {
                    return Err("Vita sidecar already has an active session".to_string());
                }
                guard.starting = true;
            }

            let result = self.start_inner(app, request);
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
            guard.starting = false;
            if let Ok((running, response)) = result {
                guard.running = Some(running);
                Ok(response)
            } else {
                result.map(|(_, response)| response)
            }
        }

        fn start_inner(
            &self,
            app: &AppHandle,
            request: VitaSidecarStartRequest,
        ) -> Result<(RunningSidecar, VitaSidecarStartResponse), String> {
            let secrets = app.state::<WindowsCredentialSecretStore>().inner().clone();
            let provider = active_chat_provider_configuration(&self.authority_storage, &secrets)?;
            let workspace = fs::canonicalize(&request.workspace_path)
                .map_err(|_| "Vita workspace path could not be canonicalized".to_string())?;
            if !workspace.is_dir() {
                return Err("Vita workspace path is not a directory".to_string());
            }
            let sidecar_workspace = normalize_sidecar_local_path(&workspace)?;
            let app_data_root = app
                .path()
                .app_data_dir()
                .map_err(|error| format!("Vita app data root unavailable: {error}"))?;
            fs::create_dir_all(&app_data_root)
                .map_err(|_| "Vita app data root could not be created".to_string())?;
            let app_data_root = fs::canonicalize(&app_data_root)
                .map_err(|_| "Vita app data root could not be canonicalized".to_string())?;
            validate_private_app_data_root(&app_data_root)?;
            let sidecar_app_data_root = normalize_sidecar_local_path(&app_data_root)?;

            let sidecar_binding = app_owned_sidecar_path(app)?;
            let sidecar = sidecar_binding.path.clone();
            // The image authority retains the resource directory and image
            // handles through the final pre-CreateProcessW fence.  The path
            // below is only the app-owned resource lookup, not the authority.
            let image = VitaSidecarProcess::prepare_image(&sidecar, &sidecar_binding.resource_dir)
                .map_err(map_process_error)?;
            let process_root = app_data_root.join("vita-sidecar-process");
            fs::create_dir_all(&process_root)
                .map_err(|_| "Vita sidecar process root could not be created".to_string())?;
            let process_root = fs::canonicalize(&process_root)
                .map_err(|_| "Vita sidecar process root could not be canonicalized".to_string())?;
            let git_path = resolve_git_path()?;
            let sidecar_git_path = normalize_sidecar_local_path(&git_path)?;

            let mut process = VitaSidecarProcess::spawn_prepared(
                image,
                &[OsString::from("--serve-ipc")],
                &process_root,
            )
            .map_err(map_process_error)?;
            let stdout = process
                .take_stdout()
                .ok_or_else(|| "Vita sidecar stdout pipe was unavailable".to_string())?;
            let stdin = process
                .take_stdin()
                .ok_or_else(|| "Vita sidecar stdin pipe was unavailable".to_string())?;
            let _stderr = process
                .take_stderr()
                .ok_or_else(|| "Vita sidecar stderr pipe was unavailable".to_string())?;
            // Drain stderr in a bounded, detached reader so a diagnostic burst
            // can never block the sidecar's stdout protocol channel.
            spawn_stderr_drain(_stderr);

            let (message, reader) = receive_vita_message_with_timeout(
                BufReader::new(stdout),
                HANDSHAKE_TIMEOUT,
                "Vita sidecar handshake",
            )?;
            let handshake = match message {
                VitaMessage::Handshake(handshake) => handshake,
                _ => return Err("Vita sidecar first frame was not Handshake".to_string()),
            };
            validate_handshake(&handshake)?;
            let current_binding = app_owned_sidecar_path(app)?;
            if current_binding.path != sidecar
                || current_binding.resource_dir != sidecar_binding.resource_dir
            {
                return Err("Vita sidecar resource namespace changed during launch".to_string());
            }

            let session_id = secure_id("vita-session")?;
            let mut writer = BufWriter::new(stdin);
            let init = HostMessage::Initialize(InitializeSession {
                request_id: next_id("host-initialize"),
                protocol_version: PROTOCOL_VERSION.to_string(),
                session_id: session_id.clone(),
                life_id: request.life_id.clone(),
                task_id: request.task_id.clone(),
                app_data_root: sidecar_app_data_root.to_string_lossy().into_owned(),
                workspace_path: sidecar_workspace.to_string_lossy().into_owned(),
                git_path: sidecar_git_path.to_string_lossy().into_owned(),
                provider: provider.clone(),
            });
            protocol::write_frame(&mut writer, &init).map_err(|error| error.to_string())?;

            let (message, reader) =
                receive_vita_message_with_timeout(reader, READY_TIMEOUT, "Vita sidecar ready")?;
            let ready = match message {
                VitaMessage::Ready(ready) => ready,
                _ => return Err("Vita sidecar post-initialize frame was not Ready".to_string()),
            };
            validate_ready(&ready, &session_id, &request)?;
            let session = Arc::new(HostSessionState {
                session_id: session_id.clone(),
                life_id: request.life_id.clone(),
                task_id: request.task_id.clone(),
                workspace_identity: ready.workspace_identity,
                provider,
                writer: Mutex::new(Some(writer)),
                pending: Mutex::new(HashMap::new()),
                approvals: Mutex::new(HashMap::new()),
                grants: Mutex::new(HashMap::new()),
                replay: Mutex::new(RequestReplayWindow::default()),
                expiry: Arc::new(ExpiryOwner::new()),
                closed: AtomicBool::new(false),
                active_turn_id: Mutex::new(None),
                turn_phase: Mutex::new(None),
                assistant_text: Mutex::new(None),
                turn_error: Mutex::new(None),
                #[cfg(test)]
                test_outbound: Mutex::new(None),
            });
            let reader_session = Arc::clone(&session);
            let storage = Arc::clone(&self.authority_storage);
            let registry = self.registry.clone();
            session.expiry.start(Arc::downgrade(&session))?;
            let reader_handle = thread::Builder::new()
                .name("vita-sidecar-host-reader".to_string())
                .spawn(move || reader_loop(reader, reader_session, storage, registry, secrets))
                .map_err(|_| "Vita sidecar Host reader could not start".to_string())?;
            Ok((
                RunningSidecar {
                    session,
                    process,
                    reader: Some(reader_handle),
                },
                VitaSidecarStartResponse {
                    session_id,
                    ready: true,
                },
            ))
        }

        fn status(&self) -> Result<VitaSidecarStatusResponse, String> {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
            let Some(running) = guard.running.as_ref() else {
                return Ok(VitaSidecarStatusResponse {
                    running: false,
                    provider_readiness: provider_readiness(
                        &self.authority_storage,
                        &self.credential_store,
                        false,
                        false,
                    )?,
                    session_id: None,
                    pending: None,
                    active_turn_id: None,
                    turn_phase: None,
                    assistant_text: None,
                    turn_error: None,
                });
            };
            let active_turn = running
                .session
                .active_turn_id
                .lock()
                .ok()
                .is_some_and(|turn| turn.is_some());
            Ok(VitaSidecarStatusResponse {
                running: !running.session.closed.load(Ordering::Acquire),
                provider_readiness: provider_readiness(
                    &self.authority_storage,
                    &self.credential_store,
                    !running.session.closed.load(Ordering::Acquire),
                    active_turn,
                )?,
                session_id: Some(running.session.session_id.clone()),
                pending: running.session.pending_summary(),
                active_turn_id: running
                    .session
                    .active_turn_id
                    .lock()
                    .ok()
                    .and_then(|turn| turn.clone()),
                turn_phase: running
                    .session
                    .turn_phase
                    .lock()
                    .ok()
                    .and_then(|phase| *phase),
                assistant_text: running
                    .session
                    .assistant_text
                    .lock()
                    .ok()
                    .and_then(|text| text.clone()),
                turn_error: running
                    .session
                    .turn_error
                    .lock()
                    .ok()
                    .and_then(|error| error.clone()),
            })
        }

        fn confirm(&self, pending_id: String) -> Result<VitaSidecarActionResponse, String> {
            self.decide_pending(pending_id, ConfirmationDecision::Confirm)
        }

        fn deny(&self, pending_id: String) -> Result<VitaSidecarActionResponse, String> {
            self.decide_pending(pending_id, ConfirmationDecision::Deny)
        }

        fn decide_pending(
            &self,
            pending_id: String,
            decision: ConfirmationDecision,
        ) -> Result<VitaSidecarActionResponse, String> {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
            let running = guard
                .running
                .as_ref()
                .ok_or_else(|| "Vita sidecar is not running".to_string())?;
            expire_pending(&running.session);
            let pending = take_pending(&running.session, &pending_id)
                .ok_or_else(|| "Vita pending confirmation was not found".to_string())?;
            if pending.expires_at_unix_ms <= unix_millis() {
                let _ = send_confirmation_decision(
                    &running.session,
                    &pending,
                    ConfirmationDecision::Deny,
                    None,
                );
                return Err("Vita pending confirmation expired".to_string());
            }

            let mut revision = None;
            if decision == ConfirmationDecision::Confirm {
                revision = match current_workspace_revision(
                    &self.authority_storage,
                    &self.registry,
                    &running.session,
                    &pending.binding,
                ) {
                    Ok(revision) => Some(revision),
                    Err(error) => {
                        let _ = running.session.send(&HostMessage::ConfirmationReply(
                            ConfirmationReply {
                                request_id: pending.request_id.clone(),
                                session_id: running.session.session_id.clone(),
                                decision: ConfirmationDecision::Deny,
                                authorization_revision: None,
                            },
                        ));
                        return Err(error);
                    }
                };
                let confirmation_id = secure_id("vita-confirmation")?;
                running
                    .session
                    .approvals
                    .lock()
                    .map_err(|_| "Vita approval state lock was poisoned".to_string())?
                    .insert(
                        binding_key(&pending.binding),
                        ApprovedAction {
                            binding: pending.binding.clone(),
                            authorization_revision: revision.unwrap_or_default(),
                            confirmation_id,
                            expires_at_unix_ms: pending.expires_at_unix_ms,
                        },
                    );
            }
            if let Err(error) =
                send_confirmation_decision(&running.session, &pending, decision, revision)
            {
                if decision == ConfirmationDecision::Confirm {
                    if let Ok(mut approvals) = running.session.approvals.lock() {
                        approvals.remove(&binding_key(&pending.binding));
                    }
                }
                return Err(error);
            }
            Ok(VitaSidecarActionResponse { accepted: true })
        }

        fn cancel(&self) -> Result<VitaSidecarActionResponse, String> {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
            let running = guard
                .running
                .as_ref()
                .ok_or_else(|| "Vita sidecar is not running".to_string())?;
            expire_pending(&running.session);
            if let Some(pending) = take_any_pending(&running.session) {
                let decision = if pending.expires_at_unix_ms <= unix_millis() {
                    ConfirmationDecision::Deny
                } else {
                    ConfirmationDecision::Cancel
                };
                let _ = send_confirmation_decision(&running.session, &pending, decision, None);
            }
            running
                .session
                .send(&HostMessage::CancelAction(protocol::CancelAction {
                    request_id: next_id("host-cancel"),
                    session_id: running.session.session_id.clone(),
                }))?;
            if let Some(turn_id) = running
                .session
                .active_turn_id
                .lock()
                .map_err(|_| "Vita active turn state lock was poisoned".to_string())?
                .clone()
            {
                let _ = running
                    .session
                    .send(&HostMessage::CancelTurn(protocol::CancelTurn {
                        request_id: next_id("host-cancel-turn"),
                        session_id: running.session.session_id.clone(),
                        turn_id,
                    }));
            }
            Ok(VitaSidecarActionResponse { accepted: true })
        }

        fn start_turn(
            &self,
            request: VitaTurnStartRequest,
        ) -> Result<VitaTurnStartResponse, String> {
            if request.prompt.is_empty()
                || request.prompt.len() > protocol::MAX_PROMPT_BYTES
                || request.prompt.chars().any(|character| {
                    character.is_control() && !matches!(character, '\n' | '\r' | '\t')
                })
            {
                return Err("Vita turn prompt was empty, oversized, or malformed".to_string());
            }
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
            let running = guard
                .running
                .as_ref()
                .ok_or_else(|| "Vita sidecar is not running".to_string())?;
            let current = running
                .session
                .active_turn_id
                .lock()
                .map_err(|_| "Vita active turn state lock was poisoned".to_string())?;
            if current.is_some() {
                return Err("Vita turn is already active".to_string());
            }
            drop(current);
            let provider = running
                .session
                .provider
                .clone()
                .ok_or_else(|| "Vita Chat provider is not configured".to_string())?;
            let current_provider = active_chat_provider_configuration(
                &self.authority_storage,
                &self.credential_store,
            )?
            .ok_or_else(|| "Vita Chat provider is not ready".to_string())?;
            if current_provider != provider {
                return Err("Vita active Chat provider changed; restart the sidecar".to_string());
            }
            let turn_id = secure_id("vita-turn")?;
            let binding =
                protocol::ProviderBinding::derive(&running.session.session_id, &turn_id, &provider)
                    .map_err(|_| "Vita provider binding could not be derived".to_string())?;
            if let Ok(mut active) = running.session.active_turn_id.lock() {
                *active = Some(turn_id.clone());
            }
            if let Ok(mut phase) = running.session.turn_phase.lock() {
                *phase = Some(protocol::TurnPhase::Starting);
            }
            if let Ok(mut output) = running.session.assistant_text.lock() {
                output.take();
            }
            if let Ok(mut error) = running.session.turn_error.lock() {
                error.take();
            }
            let message = HostMessage::StartTurn(protocol::StartTurn {
                request_id: next_id("host-start-turn"),
                session_id: running.session.session_id.clone(),
                turn_id: turn_id.clone(),
                prompt: request.prompt,
                binding,
            });
            if let Err(error) = running.session.send(&message) {
                if let Ok(mut active) = running.session.active_turn_id.lock() {
                    active.take();
                }
                return Err(error);
            }
            Ok(VitaTurnStartResponse {
                turn_id,
                accepted: true,
            })
        }

        fn cancel_turn(&self) -> Result<VitaSidecarActionResponse, String> {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned".to_string())?;
            let running = guard
                .running
                .as_ref()
                .ok_or_else(|| "Vita sidecar is not running".to_string())?;
            let Some(turn_id) = running
                .session
                .active_turn_id
                .lock()
                .map_err(|_| "Vita active turn state lock was poisoned".to_string())?
                .clone()
            else {
                return Ok(VitaSidecarActionResponse { accepted: false });
            };
            expire_pending(&running.session);
            if let Some(pending) = take_any_pending(&running.session) {
                let decision = if pending.expires_at_unix_ms <= unix_millis() {
                    ConfirmationDecision::Deny
                } else {
                    ConfirmationDecision::Cancel
                };
                let _ = send_confirmation_decision(&running.session, &pending, decision, None);
            }
            // Cancel the governed H7 action and any pending H8 confirmation
            // before interrupting the Codex turn.  A turn-only interrupt is
            // not sufficient to retire a tool broker that is waiting on the
            // Host confirmation bridge.
            let _ = running
                .session
                .send(&HostMessage::CancelAction(protocol::CancelAction {
                    request_id: next_id("host-cancel-action"),
                    session_id: running.session.session_id.clone(),
                }));
            running
                .session
                .send(&HostMessage::CancelTurn(protocol::CancelTurn {
                    request_id: next_id("host-cancel-turn"),
                    session_id: running.session.session_id.clone(),
                    turn_id,
                }))?;
            Ok(VitaSidecarActionResponse { accepted: true })
        }

        fn stop(&self) -> Result<VitaSidecarActionResponse, String> {
            let running = self
                .inner
                .lock()
                .map_err(|_| "Vita sidecar coordinator lock was poisoned")?
                .running
                .take();
            if let Some(running) = running {
                running.stop();
            }
            Ok(VitaSidecarActionResponse { accepted: true })
        }
    }

    impl Drop for VitaSidecarCoordinator {
        fn drop(&mut self) {
            if let Ok(mut guard) = self.inner.lock() {
                if let Some(running) = guard.running.take() {
                    running.stop();
                }
            }
        }
    }

    fn reader_loop(
        mut reader: BufReader<File>,
        session: Arc<HostSessionState>,
        storage: Arc<StorageService>,
        registry: CapabilityRegistry,
        secrets: WindowsCredentialSecretStore,
    ) {
        loop {
            let body = match protocol::read_sensitive_frame(&mut reader) {
                Ok(Some(body)) => body,
                Ok(None) | Err(_) => break,
            };
            let message = match protocol::decode_frame::<VitaMessage>(&body) {
                Ok(message) => message,
                Err(_) => break,
            };
            let request_id = vita_request_id(&message);
            if request_id.is_empty()
                || request_id.len() > protocol::MAX_ID_BYTES
                || !session.accept_request_id(request_id)
            {
                break;
            }
            let result = match message {
                VitaMessage::AuthorityEvaluate(request) => {
                    handle_authority_evaluate(&session, &storage, &registry, request)
                }
                VitaMessage::ConfirmationRequired(request) => {
                    handle_confirmation_required(&session, request)
                }
                VitaMessage::IssueGrant(request) => {
                    handle_issue_grant(&session, &storage, &registry, request)
                }
                VitaMessage::RevalidateGrant(request) => {
                    handle_revalidate_grant(&session, &storage, &registry, request)
                }
                VitaMessage::CredentialRequired(request) => {
                    handle_credential_required(&session, &storage, &secrets, request)
                }
                VitaMessage::TurnState(message) => handle_turn_state(&session, message),
                VitaMessage::TurnCompleted(message) => handle_turn_completed(&session, message),
                VitaMessage::TurnFailed(message) => handle_turn_failed(&session, message),
                VitaMessage::ActionCancelled(message)
                    if message.session_id == session.session_id =>
                {
                    Ok(())
                }
                VitaMessage::ShutdownAck(message) if message.session_id == session.session_id => {
                    Ok(())
                }
                VitaMessage::Fatal(_) | VitaMessage::Handshake(_) | VitaMessage::Ready(_) => {
                    Err("Vita sidecar emitted an invalid Host-phase message".to_string())
                }
                VitaMessage::ActionCancelled(_) | VitaMessage::ShutdownAck(_) => {
                    Err("Vita sidecar lifecycle response session was not exact".to_string())
                }
            };
            if result.is_err() {
                break;
            }
        }
        session.retire();
        session.close_writer();
    }

    fn handle_turn_state(
        session: &Arc<HostSessionState>,
        message: protocol::TurnState,
    ) -> Result<(), String> {
        message
            .validate()
            .map_err(|_| "Vita turn state was malformed".to_string())?;
        if message.session_id != session.session_id {
            return Err("Vita turn state session was not exact".to_string());
        }
        if let Ok(mut turn) = session.active_turn_id.lock() {
            if turn
                .as_deref()
                .is_some_and(|active| active != message.turn_id.as_str())
            {
                // A late state from a retired turn must not mutate the next
                // turn.  It is safe to ignore it because the sidecar already
                // owns the authoritative cancellation/retirement state.
                return Ok(());
            }
            if turn.is_none() && !matches!(message.phase, protocol::TurnPhase::Starting) {
                return Ok(());
            }
            if matches!(
                message.phase,
                protocol::TurnPhase::Completed
                    | protocol::TurnPhase::Failed
                    | protocol::TurnPhase::Cancelled
                    | protocol::TurnPhase::TimedOut
            ) {
                turn.take();
            } else {
                *turn = Some(message.turn_id);
            }
        }
        if let Ok(mut phase) = session.turn_phase.lock() {
            *phase = Some(message.phase);
        }
        Ok(())
    }

    fn handle_turn_completed(
        session: &Arc<HostSessionState>,
        message: protocol::TurnCompleted,
    ) -> Result<(), String> {
        message
            .validate()
            .map_err(|_| "Vita turn result was malformed".to_string())?;
        if message.session_id != session.session_id {
            return Err("Vita turn result session was not exact".to_string());
        }
        if let Ok(mut turn) = session.active_turn_id.lock() {
            if turn
                .as_deref()
                .is_none_or(|active| active != message.turn_id.as_str())
            {
                return Ok(());
            }
            turn.take();
        }
        if let Ok(mut phase) = session.turn_phase.lock() {
            *phase = Some(protocol::TurnPhase::Completed);
        }
        if let Ok(mut output) = session.assistant_text.lock() {
            *output = Some(message.assistant_text);
        }
        if let Ok(mut error) = session.turn_error.lock() {
            error.take();
        }
        Ok(())
    }

    fn handle_turn_failed(
        session: &Arc<HostSessionState>,
        message: protocol::TurnFailed,
    ) -> Result<(), String> {
        message
            .validate()
            .map_err(|_| "Vita turn failure was malformed".to_string())?;
        if message.session_id != session.session_id {
            return Err("Vita turn failure session was not exact".to_string());
        }
        if let Ok(mut turn) = session.active_turn_id.lock() {
            if turn
                .as_deref()
                .is_none_or(|active| active != message.turn_id.as_str())
            {
                return Ok(());
            }
            turn.take();
        }
        if let Ok(mut phase) = session.turn_phase.lock() {
            *phase = Some(message.phase);
        }
        if let Ok(mut error) = session.turn_error.lock() {
            *error = Some(message.error_code);
        }
        Ok(())
    }

    fn handle_credential_required(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        secrets: &WindowsCredentialSecretStore,
        request: protocol::CredentialRequired,
    ) -> Result<(), String> {
        request
            .validate()
            .map_err(|_| "Vita credential request was malformed".to_string())?;
        let deny = |code: &str| {
            session.send(&HostMessage::SensitiveCredentialReply(
                protocol::SensitiveCredentialReply {
                    request_id: request.request_id.clone(),
                    session_id: session.session_id.clone(),
                    turn_id: request.turn_id.clone(),
                    binding_hash: request.binding.binding_hash.clone(),
                    credential_ref: request.binding.credential_ref.clone(),
                    credential: None,
                    error_code: Some(code.to_string()),
                },
            ))
        };
        if session.closed.load(Ordering::Acquire)
            || request.session_id != session.session_id
            || session
                .active_turn_id
                .lock()
                .ok()
                .is_none_or(|turn| turn.as_deref() != Some(request.turn_id.as_str()))
        {
            return deny("TURN_NOT_ACTIVE");
        }
        let Some(configuration) = active_chat_provider_configuration(storage, secrets)? else {
            return deny("CREDENTIAL_MISSING");
        };
        let expected = protocol::ProviderBinding::derive(
            &session.session_id,
            &request.turn_id,
            &configuration,
        )
        .map_err(|_| "provider binding could not be derived".to_string())?;
        if expected != request.binding {
            return deny("PROVIDER_BINDING_MISMATCH");
        }
        let identifier = SecretIdentifier::new(
            credential_purpose(ModelPurpose::Chat),
            configuration.credential_ref.clone(),
        )
        .map_err(|_| "credential identifier was invalid".to_string())?;
        let secret = match secrets.get_secret(&identifier) {
            Ok(secret) => secret,
            Err(_) => return deny("CREDENTIAL_MISSING"),
        };
        let credential = protocol::SensitiveCredential::new(secret.expose_secret().to_owned())
            .map_err(|_| "credential value was invalid".to_string())?;
        session.send(&HostMessage::SensitiveCredentialReply(
            protocol::SensitiveCredentialReply {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                turn_id: request.turn_id,
                binding_hash: request.binding.binding_hash,
                credential_ref: request.binding.credential_ref,
                credential: Some(credential),
                error_code: None,
            },
        ))
    }

    fn handle_authority_evaluate(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: AuthorityEvaluate,
    ) -> Result<(), String> {
        if request.session_id != session.session_id {
            return Err("Vita authority request session was not exact".to_string());
        }
        let (allowed, revision, error_code) =
            match current_workspace_revision(storage, registry, session, &request.binding) {
                Ok(revision) => (true, Some(revision), None),
                Err(error) => (false, None, Some(error_code(&error))),
            };
        session.send(&HostMessage::AuthorityScopeReply(AuthorityScopeReply {
            request_id: request.request_id,
            session_id: session.session_id.clone(),
            allowed,
            authorization_revision: revision,
            error_code,
        }))
    }

    fn handle_confirmation_required(
        session: &Arc<HostSessionState>,
        request: ConfirmationRequired,
    ) -> Result<(), String> {
        if session.closed.load(Ordering::Acquire) {
            return Err("Vita sidecar session was already retired".to_string());
        }
        if request.session_id != session.session_id
            || request.life_id != session.life_id
            || request.task_id != session.task_id
            || request.capability_id != PRODUCTION_GIT_STATUS_CAPABILITY_ID
            || request.binding.validate().is_err()
        {
            return Err("Vita confirmation binding was not exact".to_string());
        }
        validate_binding(session, &request.binding)?;
        let now = unix_millis();
        let Some(expires_at_unix_ms) =
            effective_confirmation_expiry(now, request.expires_at_unix_ms)
        else {
            session.send(&HostMessage::ConfirmationReply(ConfirmationReply {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                decision: ConfirmationDecision::Deny,
                authorization_revision: None,
            }))?;
            return Ok(());
        };
        // The active timer is authoritative; this opportunistic pass only
        // closes a just-expired slot before applying MAX_PENDING.
        expire_pending(session);
        let pending_id = format!("pending:{}", secure_id("vita")?);
        let pending_action = PendingAction {
            pending_id: pending_id.clone(),
            request_id: request.request_id,
            life_id: request.life_id,
            task_id: request.task_id,
            capability_id: request.capability_id,
            workspace_summary: request.workspace_summary,
            expires_at_unix_ms,
            binding: request.binding,
        };
        let mut pending = session
            .pending
            .lock()
            .map_err(|_| "Vita pending state lock was poisoned".to_string())?;
        if pending.len() >= MAX_PENDING {
            return Err("Vita pending confirmation capacity was exhausted".to_string());
        }
        let ticket = ExpiryTicket::for_pending(&session.session_id, &pending_action);
        pending.insert(pending_id, pending_action);
        drop(pending);
        session.expiry.schedule(ticket);
        Ok(())
    }

    fn handle_issue_grant(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: IssueGrant,
    ) -> Result<(), String> {
        if request.session_id != session.session_id {
            return Err("Vita grant request session was not exact".to_string());
        }
        expire_pending(session);
        let allowed = validate_binding(session, &request.binding).and_then(|_| {
            let revision =
                current_workspace_revision(storage, registry, session, &request.binding)?;
            if revision != request.authorization_revision {
                return Err("stale authorization revision".to_string());
            }
            let mut grants = session
                .grants
                .lock()
                .map_err(|_| "Vita grant state lock was poisoned".to_string())?;
            reap_expired_grants(&mut grants);
            if grants.len() >= MAX_GRANTS {
                return Err("Vita grant capacity was exhausted".to_string());
            }
            drop(grants);
            let mut approvals = session
                .approvals
                .lock()
                .map_err(|_| "Vita approval state lock was poisoned".to_string())?;
            let key = binding_key(&request.binding);
            let approval = approvals
                .remove(&key)
                .ok_or_else(|| "Vita confirmation was not approved".to_string())?;
            if approval.binding != request.binding
                || approval.authorization_revision != request.authorization_revision
                || approval.expires_at_unix_ms <= unix_millis()
            {
                return Err("Vita confirmation binding or revision was stale".to_string());
            }
            let grant = ProcessGrant {
                session_id: session.session_id.clone(),
                grant_id: secure_id("vita-grant")?,
                confirmation_id: approval.confirmation_id,
                binding: request.binding.clone(),
                authorization_revision: request.authorization_revision,
                issued_at_unix_ms: unix_millis(),
                expires_at_unix_ms: unix_millis().saturating_add(GRANT_LIFETIME_MS),
                single_use: true,
                used: false,
            };
            let mut grants = session
                .grants
                .lock()
                .map_err(|_| "Vita grant state lock was poisoned".to_string())?;
            if grants.len() >= MAX_GRANTS {
                return Err("Vita grant capacity was exhausted".to_string());
            }
            grants.insert(grant.grant_id.clone(), grant.clone());
            Ok(grant)
        });
        match allowed {
            Ok(grant) => session.send(&HostMessage::GrantIssued(GrantIssued {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: true,
                grant: Some(grant),
                error_code: None,
            })),
            Err(error) => session.send(&HostMessage::GrantIssued(GrantIssued {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                grant: None,
                error_code: Some(error_code(&error)),
            })),
        }
    }

    fn handle_revalidate_grant(
        session: &Arc<HostSessionState>,
        storage: &StorageService,
        registry: &CapabilityRegistry,
        request: RevalidateGrant,
    ) -> Result<(), String> {
        if request.session_id != session.session_id
            || request.grant.session_id != session.session_id
        {
            return Err("Vita revalidation request session was not exact".to_string());
        }
        let result = validate_binding(session, &request.binding).and_then(|_| {
            let revision =
                current_workspace_revision(storage, registry, session, &request.binding)?;
            let mut grants = session
                .grants
                .lock()
                .map_err(|_| "Vita grant state lock was poisoned".to_string())?;
            consume_active_grant(&mut grants, &request.grant, &request.binding, revision)
        });
        match result {
            Ok(grant) => session.send(&HostMessage::GrantRevalidated(GrantRevalidated {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: true,
                grant: Some(grant),
                error_code: None,
            })),
            Err(error) => session.send(&HostMessage::GrantRevalidated(GrantRevalidated {
                request_id: request.request_id,
                session_id: session.session_id.clone(),
                allowed: false,
                grant: None,
                error_code: Some(error_code(&error)),
            })),
        }
    }

    fn current_workspace_revision(
        storage: &StorageService,
        registry: &CapabilityRegistry,
        session: &HostSessionState,
        binding: &ProcessBinding,
    ) -> Result<i64, String> {
        validate_binding(session, binding)?;
        let capability_id = CapabilityId::try_from(binding.capability_id.as_str())
            .map_err(|_| "invalid capability identity".to_string())?;
        let decision = evaluate_capability_authorization(
            storage,
            registry,
            &session.life_id,
            &capability_id,
            RequestedCapabilityScope::Workspace,
        )
        .map_err(|error| error.message)?;
        if decision.outcome() != CapabilityAuthorizationDecisionKind::ScopeRequired {
            return Err(decision.decision_code().as_str().to_string());
        }
        decision
            .authorization_revision()
            .ok_or_else(|| "authorization revision was absent".to_string())
    }

    fn validate_binding(
        session: &HostSessionState,
        binding: &ProcessBinding,
    ) -> Result<(), String> {
        binding
            .validate()
            .map_err(|_| "Vita process binding was malformed".to_string())?;
        if binding.session_id != session.session_id
            || binding.life_id != session.life_id
            || binding.task_id != session.task_id
            || binding.capability_id != PRODUCTION_GIT_STATUS_CAPABILITY_ID
            || binding.program_id != PROGRAM_ID
            || binding.profile_id != PRODUCTION_GIT_STATUS_PROFILE_ID
            || binding.workspace_root_identity != session.workspace_identity
            || binding.git_metadata_fence_hash.len() != 64
            || !binding
                .git_metadata_fence_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("Vita process binding was not exact".to_string());
        }
        Ok(())
    }

    fn take_pending(session: &HostSessionState, pending_id: &str) -> Option<PendingAction> {
        let removed = session.pending.lock().ok().and_then(|mut pending| {
            pending
                .iter()
                .find_map(|(key, value)| (pending_key(value) == pending_id).then_some(key.clone()))
                .and_then(|key| pending.remove(&key))
        });
        if let Some(ref pending) = removed {
            session
                .expiry
                .clear(&ExpiryTicket::for_pending(&session.session_id, pending));
        }
        removed
    }

    fn take_any_pending(session: &HostSessionState) -> Option<PendingAction> {
        let removed = session.pending.lock().ok().and_then(|mut pending| {
            let key = pending.keys().next().cloned()?;
            pending.remove(&key)
        });
        if let Some(ref pending) = removed {
            session
                .expiry
                .clear(&ExpiryTicket::for_pending(&session.session_id, pending));
        }
        removed
    }

    fn send_confirmation_decision(
        session: &HostSessionState,
        pending: &PendingAction,
        decision: ConfirmationDecision,
        authorization_revision: Option<i64>,
    ) -> Result<(), String> {
        session.send(&HostMessage::ConfirmationReply(ConfirmationReply {
            request_id: pending.request_id.clone(),
            session_id: session.session_id.clone(),
            decision,
            authorization_revision,
        }))
    }

    fn expire_pending(session: &HostSessionState) {
        let now = unix_millis();
        let expired = if let Ok(mut pending) = session.pending.lock() {
            let mut expired = Vec::new();
            pending.retain(|_, value| {
                if value.expires_at_unix_ms <= now {
                    expired.push(value.clone());
                    false
                } else {
                    true
                }
            });
            expired
        } else {
            Vec::new()
        };
        for pending in expired {
            session
                .expiry
                .clear(&ExpiryTicket::for_pending(&session.session_id, &pending));
            let _ = send_confirmation_decision(session, &pending, ConfirmationDecision::Deny, None);
        }
    }

    fn reap_expired_grants(grants: &mut HashMap<String, ProcessGrant>) {
        let now = unix_millis();
        grants.retain(|_, grant| !grant.used && grant.expires_at_unix_ms > now);
    }

    fn consume_active_grant(
        grants: &mut HashMap<String, ProcessGrant>,
        requested: &ProcessGrant,
        binding: &ProcessBinding,
        authorization_revision: i64,
    ) -> Result<ProcessGrant, String> {
        let stored = grants
            .get(&requested.grant_id)
            .cloned()
            .ok_or_else(|| "Vita grant was not found".to_string())?;
        if stored != *requested
            || stored.used
            || !stored.single_use
            || stored.binding != *binding
            || stored.authorization_revision != authorization_revision
            || stored.expires_at_unix_ms <= unix_millis()
        {
            return Err("Vita grant revalidation was denied".to_string());
        }
        let mut consumed = grants
            .remove(&requested.grant_id)
            .ok_or_else(|| "Vita grant was not found".to_string())?;
        consumed.used = true;
        Ok(consumed)
    }

    fn effective_confirmation_expiry(now: u64, vita_expiry: u64) -> Option<u64> {
        let host_deadline = now.saturating_add(HOST_CONFIRMATION_TTL_MS);
        let effective = vita_expiry.min(host_deadline);
        (effective > now).then_some(effective)
    }

    fn binding_key(binding: &ProcessBinding) -> String {
        format!("{}:{}", binding.tool_call_id, binding.turn_id)
    }

    fn vita_request_id(message: &VitaMessage) -> &str {
        match message {
            VitaMessage::Handshake(message) => &message.request_id,
            VitaMessage::Ready(message) => &message.request_id,
            VitaMessage::AuthorityEvaluate(message) => &message.request_id,
            VitaMessage::ConfirmationRequired(message) => &message.request_id,
            VitaMessage::IssueGrant(message) => &message.request_id,
            VitaMessage::RevalidateGrant(message) => &message.request_id,
            VitaMessage::ActionCancelled(message) => &message.request_id,
            VitaMessage::CredentialRequired(message) => &message.request_id,
            VitaMessage::TurnState(message) => &message.request_id,
            VitaMessage::TurnCompleted(message) => &message.request_id,
            VitaMessage::TurnFailed(message) => &message.request_id,
            VitaMessage::ShutdownAck(message) => &message.request_id,
            VitaMessage::Fatal(message) => &message.request_id,
        }
    }

    fn validate_handshake(handshake: &protocol::Handshake) -> Result<(), String> {
        if handshake.protocol_version != PROTOCOL_VERSION
            || handshake.runtime != RUNTIME_ID
            || handshake.codex_commit != CODEX_UPSTREAM_COMMIT
            || handshake.codex_schema_hash != CODEX_PROTOCOL_SCHEMA_HASH
        {
            return Err("Vita sidecar handshake identity was not pinned".to_string());
        }
        Ok(())
    }

    fn validate_ready(
        ready: &protocol::Ready,
        session_id: &str,
        request: &VitaSidecarStartRequest,
    ) -> Result<(), String> {
        if ready.session_id != session_id
            || ready.life_id != request.life_id
            || ready.task_id != request.task_id
            || ready.capability_id != PRODUCTION_GIT_STATUS_CAPABILITY_ID
            || ready.profile_id != PRODUCTION_GIT_STATUS_PROFILE_ID
            || ready.tool_name != PRODUCTION_GIT_STATUS_TOOL_NAME
            || ready.workspace_identity.is_empty()
        {
            return Err("Vita sidecar ready identity was not exact".to_string());
        }
        Ok(())
    }

    fn receive_vita_message_with_timeout(
        mut reader: BufReader<File>,
        timeout: Duration,
        label: &'static str,
    ) -> Result<(VitaMessage, BufReader<File>), String> {
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name(format!("vita-sidecar-{label}"))
            .spawn(move || {
                let result = protocol::read_frame(&mut reader)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| format!("{label} channel closed"))
                    .and_then(|body| {
                        protocol::decode_frame::<VitaMessage>(&body).map_err(|e| e.to_string())
                    });
                let _ = sender.send(result.map(|value| (value, reader)));
                Ok::<(), String>(())
            })
            .map_err(|_| format!("{label} reader could not start"))?;
        match receiver.recv_timeout(timeout) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(format!("{label} failed: {error}")),
            Err(RecvTimeoutError::Timeout) => Err(format!("{label} timed out")),
            Err(RecvTimeoutError::Disconnected) => Err(format!("{label} reader failed")),
        }
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SidecarPathBinding {
        path: PathBuf,
        resource_dir: PathBuf,
    }

    fn app_owned_sidecar_path(app: &AppHandle) -> Result<SidecarPathBinding, String> {
        let resource_dir = app
            .path()
            .resource_dir()
            .map_err(|error| format!("Vita resource directory unavailable: {error}"))?;
        let resource_dir = fs::canonicalize(&resource_dir)
            .map_err(|_| "Vita resource directory could not be canonicalized".to_string())?;
        let candidate = fs::canonicalize(resource_dir.join(SIDECAR_RESOURCE_NAME))
            .map_err(|_| "Vita sidecar image is not installed".to_string())?;
        if !candidate.is_file() || candidate.parent() != Some(resource_dir.as_path()) {
            return Err(
                "Vita sidecar image is outside the app-owned resource directory".to_string(),
            );
        }
        Ok(SidecarPathBinding {
            path: candidate,
            resource_dir,
        })
    }

    fn resolve_git_path() -> Result<PathBuf, String> {
        // Absolute, fixed install locations only.  There is deliberately no
        // PATH lookup and no model/user-supplied executable path in this lane.
        let candidates = [
            PathBuf::from(r"C:\Program Files\Git\cmd\git.exe"),
            PathBuf::from(r"C:\Program Files\Git\bin\git.exe"),
            PathBuf::from(r"E:\Program Files\Git\cmd\git.exe"),
            PathBuf::from(r"E:\Program Files\Git\mingw64\bin\git.exe"),
        ];
        candidates
            .into_iter()
            .filter_map(|candidate| fs::canonicalize(candidate).ok())
            .find(|candidate| candidate.is_file())
            .ok_or_else(|| "No trusted absolute Git image is installed".to_string())
    }

    fn validate_private_app_data_root(path: &Path) -> Result<(), String> {
        if !path.is_absolute()
            || path.components().any(|component| {
                component
                    .as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(".codex")
            })
        {
            return Err(
                "Vita app data root is outside the private application namespace".to_string(),
            );
        }
        Ok(())
    }

    fn normalize_sidecar_local_path(path: &Path) -> Result<PathBuf, String> {
        let value = path.to_string_lossy().replace('/', "\\");
        let value = value.strip_prefix(r"\\?\").unwrap_or(&value);
        if value.starts_with(r"\\")
            || value.starts_with(r"\Device\")
            || value.starts_with(r"\GlobalRoot\")
        {
            return Err("Vita sidecar path was not a local drive path".to_string());
        }
        let normalized = PathBuf::from(value);
        if !normalized.is_absolute() {
            return Err("Vita sidecar path was not absolute".to_string());
        }
        Ok(normalized)
    }

    fn spawn_stderr_drain(mut stderr: File) {
        let _ = thread::Builder::new()
            .name("vita-sidecar-stderr-drain".to_string())
            .spawn(move || {
                let mut buffer = [0_u8; 4096];
                let mut total = 0_usize;
                loop {
                    match std::io::Read::read(&mut stderr, &mut buffer) {
                        Ok(0) | Err(_) => break,
                        Ok(read) => total = total.saturating_add(read.min(16 * 1024 - total)),
                    }
                    if total >= 16 * 1024 {
                        // Continue draining without retaining unbounded data.
                        total = 16 * 1024;
                    }
                }
            });
    }

    fn validate_id(value: &str) -> Result<(), String> {
        if value.is_empty()
            || value.len() > protocol::MAX_ID_BYTES
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || b"_-.".contains(&byte)))
        {
            return Err("Vita identity was invalid".to_string());
        }
        Ok(())
    }

    fn error_code(error: &str) -> String {
        if error.contains("revision") {
            "STALE_AUTHORIZATION_REVISION".to_string()
        } else if error.contains("binding") {
            "BINDING_MISMATCH".to_string()
        } else {
            "AUTHORITY_DENIED".to_string()
        }
    }

    fn map_process_error(error: CodexRuntimeError) -> String {
        format!("Vita sidecar process boundary failed: {error}")
    }

    fn next_id(prefix: &str) -> String {
        format!(
            "{prefix}-{}-{}",
            std::process::id(),
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        )
    }

    fn secure_id(prefix: &str) -> Result<String, String> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes)
            .map_err(|_| "Vita Host cryptographic identity generation failed".to_string())?;
        let suffix = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(format!("{prefix}-{suffix}"))
    }

    fn unix_millis() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| {
                duration.as_millis().min(u64::MAX as u128) as u64
            })
    }

    pub fn start_vita_sidecar(
        app: AppHandle,
        coordinator: State<'_, VitaSidecarCoordinator>,
        request: VitaSidecarStartRequest,
    ) -> Result<VitaSidecarStartResponse, String> {
        coordinator.start(&app, request)
    }

    pub fn get_vita_sidecar_status(
        coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarStatusResponse, String> {
        coordinator.status()
    }

    pub fn confirm_vita_sidecar(
        coordinator: State<'_, VitaSidecarCoordinator>,
        pending_id: String,
    ) -> Result<VitaSidecarActionResponse, String> {
        coordinator.confirm(pending_id)
    }

    pub fn deny_vita_sidecar(
        coordinator: State<'_, VitaSidecarCoordinator>,
        pending_id: String,
    ) -> Result<VitaSidecarActionResponse, String> {
        coordinator.deny(pending_id)
    }

    pub fn cancel_vita_sidecar(
        coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarActionResponse, String> {
        coordinator.cancel()
    }

    pub fn start_vita_turn(
        coordinator: State<'_, VitaSidecarCoordinator>,
        request: VitaTurnStartRequest,
    ) -> Result<VitaTurnStartResponse, String> {
        coordinator.start_turn(request)
    }

    pub fn cancel_vita_turn(
        coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarActionResponse, String> {
        coordinator.cancel_turn()
    }

    pub fn stop_vita_sidecar(
        coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarActionResponse, String> {
        coordinator.stop()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn test_binding(session_id: &str) -> ProcessBinding {
            ProcessBinding {
                session_id: session_id.to_string(),
                life_id: "life".to_string(),
                task_id: "task".to_string(),
                capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                program_id: PROGRAM_ID.to_string(),
                executable_identity: "v1f1".to_string(),
                executable_sha256: "0".repeat(64),
                argv_hash: "1".repeat(64),
                argv_count: 1,
                working_directory_identity: "v1f2".to_string(),
                environment_policy_hash: "2".repeat(64),
                stdout_bound: 1,
                stderr_bound: 1,
                timeout_ms: 1,
                tool_call_id: "call".to_string(),
                turn_id: "turn".to_string(),
                workspace_root_identity: "workspace".to_string(),
                profile_id: PRODUCTION_GIT_STATUS_PROFILE_ID.to_string(),
                git_metadata_fence_hash: "3".repeat(64),
            }
        }

        fn test_session() -> (Arc<HostSessionState>, mpsc::Receiver<HostMessage>) {
            let (sender, receiver) = mpsc::channel();
            let session = Arc::new(HostSessionState {
                session_id: "session-test".to_string(),
                life_id: "life".to_string(),
                task_id: "task".to_string(),
                workspace_identity: "workspace".to_string(),
                provider: None,
                writer: Mutex::new(None),
                pending: Mutex::new(HashMap::new()),
                approvals: Mutex::new(HashMap::new()),
                grants: Mutex::new(HashMap::new()),
                replay: Mutex::new(RequestReplayWindow::default()),
                expiry: Arc::new(ExpiryOwner::new()),
                closed: AtomicBool::new(false),
                active_turn_id: Mutex::new(None),
                turn_phase: Mutex::new(None),
                assistant_text: Mutex::new(None),
                turn_error: Mutex::new(None),
                test_outbound: Mutex::new(Some(sender)),
            });
            (session, receiver)
        }

        fn install_test_pending(
            session: &Arc<HostSessionState>,
            pending_id: &str,
            request_id: &str,
            expires_at_unix_ms: u64,
        ) {
            let pending = PendingAction {
                pending_id: pending_id.to_string(),
                request_id: request_id.to_string(),
                life_id: session.life_id.clone(),
                task_id: session.task_id.clone(),
                capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                workspace_summary: "workspace".to_string(),
                expires_at_unix_ms,
                binding: test_binding(&session.session_id),
            };
            let ticket = ExpiryTicket::for_pending(&session.session_id, &pending);
            session
                .pending
                .lock()
                .expect("pending lock")
                .insert(pending_id.to_string(), pending);
            session.expiry.schedule(ticket);
        }

        #[test]
        fn binding_key_is_not_a_frontend_grant_or_revision() {
            let binding = ProcessBinding {
                session_id: "s".to_string(),
                life_id: "l".to_string(),
                task_id: "t".to_string(),
                capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                program_id: PROGRAM_ID.to_string(),
                executable_identity: "v1f1".to_string(),
                executable_sha256: "0".repeat(64),
                argv_hash: "1".repeat(64),
                argv_count: 1,
                working_directory_identity: "v1f2".to_string(),
                environment_policy_hash: "2".repeat(64),
                stdout_bound: 1,
                stderr_bound: 1,
                timeout_ms: 1,
                tool_call_id: "call".to_string(),
                turn_id: "turn".to_string(),
                workspace_root_identity: "v1f3".to_string(),
                profile_id: PRODUCTION_GIT_STATUS_PROFILE_ID.to_string(),
                git_metadata_fence_hash: "3".repeat(64),
            };
            assert_eq!(binding_key(&binding), "call:turn");
        }

        #[test]
        fn host_confirmation_ttl_is_an_upper_bound() {
            assert_eq!(effective_confirmation_expiry(1_000, 90_000), Some(31_000));
            assert_eq!(effective_confirmation_expiry(1_000, 20_000), Some(20_000));
            assert_eq!(effective_confirmation_expiry(1_000, 1_000), None);
        }

        #[test]
        fn sidecar_paths_drop_verbatim_prefix_but_reject_unc() {
            let normalized = normalize_sidecar_local_path(Path::new(r"\\?\E:\vita\workspace"))
                .expect("verbatim local path");
            assert_eq!(normalized, PathBuf::from(r"E:\vita\workspace"));
            assert!(normalize_sidecar_local_path(Path::new(r"\\server\share\workspace")).is_err());
        }

        #[test]
        fn startup_frames_are_tagged_and_ordered() {
            let handshake = protocol::Handshake {
                request_id: "handshake".to_string(),
                protocol_version: PROTOCOL_VERSION.to_string(),
                runtime: RUNTIME_ID.to_string(),
                codex_commit: CODEX_UPSTREAM_COMMIT.to_string(),
                codex_schema_hash: CODEX_PROTOCOL_SCHEMA_HASH.to_string(),
            };
            let frame = protocol::encode_frame(&VitaMessage::Handshake(handshake.clone()))
                .expect("handshake frame");
            let decoded = protocol::decode_frame::<VitaMessage>(&frame[4..]).expect("tagged frame");
            assert!(matches!(decoded, VitaMessage::Handshake(value) if value == handshake));

            let ready = protocol::Ready {
                request_id: "ready".to_string(),
                session_id: "session".to_string(),
                life_id: "life".to_string(),
                task_id: "task".to_string(),
                workspace_identity: "workspace".to_string(),
                capability_id: PRODUCTION_GIT_STATUS_CAPABILITY_ID.to_string(),
                profile_id: PRODUCTION_GIT_STATUS_PROFILE_ID.to_string(),
                tool_name: PRODUCTION_GIT_STATUS_TOOL_NAME.to_string(),
            };
            let frame = protocol::encode_frame(&VitaMessage::Ready(ready)).expect("ready frame");
            let decoded = protocol::decode_frame::<VitaMessage>(&frame[4..]).expect("tagged frame");
            assert!(matches!(decoded, VitaMessage::Ready(_)));
        }

        #[test]
        fn bundle_resource_mapping_matches_runtime_name() {
            let config: serde_json::Value =
                serde_json::from_str(include_str!("../tauri.conf.json")).expect("tauri config");
            let resources = config["bundle"]["resources"]
                .as_object()
                .expect("explicit resource mapping");
            assert_eq!(
                resources
                    .get("../vita-agent/target/release/vita-agent.exe")
                    .and_then(serde_json::Value::as_str),
                Some(SIDECAR_RESOURCE_NAME)
            );
        }

        #[test]
        fn active_confirmation_expiry_denies_without_polling_and_releases_slot() {
            let (session, receiver) = test_session();
            session
                .expiry
                .start(Arc::downgrade(&session))
                .expect("expiry worker");
            install_test_pending(
                &session,
                "pending-old",
                "request-old",
                unix_millis().saturating_add(40),
            );

            let message = receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("automatic expiry denial");
            assert!(matches!(
                message,
                HostMessage::ConfirmationReply(ConfirmationReply {
                    request_id,
                    decision: ConfirmationDecision::Deny,
                    ..
                }) if request_id == "request-old"
            ));
            assert!(session.pending.lock().expect("pending lock").is_empty());

            install_test_pending(
                &session,
                "pending-new",
                "request-new",
                unix_millis().saturating_add(5_000),
            );
            assert_eq!(session.pending.lock().expect("pending lock").len(), 1);
            session.retire();
            assert!(session.pending.lock().expect("pending lock").is_empty());
        }

        #[test]
        fn confirmation_race_has_exactly_one_terminal_winner() {
            let (session, receiver) = test_session();
            install_test_pending(
                &session,
                "pending-race",
                "request-race",
                unix_millis().saturating_add(5_000),
            );
            let barrier = Arc::new(std::sync::Barrier::new(3));
            let first = {
                let session = Arc::clone(&session);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    take_pending(&session, "pending-race")
                })
            };
            let second = {
                let session = Arc::clone(&session);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    take_pending(&session, "pending-race")
                })
            };
            barrier.wait();
            let first = first.join().expect("first race worker");
            let second = second.join().expect("second race worker");
            assert!(first.is_some() ^ second.is_some());
            let winner = first.or(second).expect("one terminal winner");
            send_confirmation_decision(&session, &winner, ConfirmationDecision::Confirm, Some(0))
                .expect("winner reply");
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("one reply"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Confirm,
                    ..
                })
            ));
            assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
            session.retire();
        }

        #[test]
        fn deny_and_cancel_races_also_have_one_terminal_winner() {
            for decision in [ConfirmationDecision::Deny, ConfirmationDecision::Cancel] {
                let (session, receiver) = test_session();
                install_test_pending(
                    &session,
                    "pending-terminal-race",
                    "request-terminal-race",
                    unix_millis().saturating_add(5_000),
                );
                let barrier = Arc::new(std::sync::Barrier::new(3));
                let first = {
                    let session = Arc::clone(&session);
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();
                        take_pending(&session, "pending-terminal-race")
                    })
                };
                let second = {
                    let session = Arc::clone(&session);
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();
                        take_pending(&session, "pending-terminal-race")
                    })
                };
                barrier.wait();
                let winner = first
                    .join()
                    .expect("first terminal worker")
                    .or(second.join().expect("second terminal worker"))
                    .expect("one terminal winner");
                send_confirmation_decision(&session, &winner, decision, None)
                    .expect("terminal reply");
                assert!(matches!(
                    receiver
                        .recv_timeout(Duration::from_secs(1))
                        .expect("one terminal reply"),
                    HostMessage::ConfirmationReply(ConfirmationReply {
                        decision: actual,
                        ..
                    }) if actual == decision
                ));
                assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
                session.retire();
            }
        }

        #[test]
        fn late_confirmation_after_expiry_is_rejected() {
            let (session, receiver) = test_session();
            session
                .expiry
                .start(Arc::downgrade(&session))
                .expect("expiry worker");
            install_test_pending(
                &session,
                "pending-late",
                "request-late",
                unix_millis().saturating_add(30),
            );
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(2))
                    .expect("expiry reply"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Deny,
                    ..
                })
            ));
            assert!(take_pending(&session, "pending-late").is_none());
            assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
            session.retire();
        }

        #[test]
        fn stopped_expiry_owner_cannot_touch_a_fresh_session() {
            let (old_session, old_receiver) = test_session();
            old_session
                .expiry
                .start(Arc::downgrade(&old_session))
                .expect("old expiry worker");
            install_test_pending(
                &old_session,
                "pending-old-session",
                "request-old-session",
                unix_millis().saturating_add(40),
            );
            old_session.retire();
            assert!(matches!(
                old_receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("shutdown denial"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Deny,
                    ..
                })
            ));
            assert!(old_receiver
                .recv_timeout(Duration::from_millis(100))
                .is_err());

            let (new_session, new_receiver) = test_session();
            new_session
                .expiry
                .start(Arc::downgrade(&new_session))
                .expect("new expiry worker");
            install_test_pending(
                &new_session,
                "pending-new-session",
                "request-new-session",
                unix_millis().saturating_add(5_000),
            );
            assert_eq!(new_session.pending.lock().expect("pending lock").len(), 1);
            assert!(new_receiver
                .recv_timeout(Duration::from_millis(100))
                .is_err());
            new_session.retire();
        }

        #[test]
        fn session_retire_clears_all_authority_state_and_joins_expiry_owner() {
            let (session, receiver) = test_session();
            session
                .expiry
                .start(Arc::downgrade(&session))
                .expect("expiry worker");
            install_test_pending(
                &session,
                "pending-cleanup",
                "request-cleanup",
                unix_millis().saturating_add(5_000),
            );
            let binding = test_binding(&session.session_id);
            session.approvals.lock().expect("approval lock").insert(
                binding_key(&binding),
                ApprovedAction {
                    binding: binding.clone(),
                    authorization_revision: 7,
                    confirmation_id: "confirmation-cleanup".to_string(),
                    expires_at_unix_ms: unix_millis().saturating_add(5_000),
                },
            );
            session.grants.lock().expect("grant lock").insert(
                "grant-cleanup".to_string(),
                ProcessGrant {
                    session_id: session.session_id.clone(),
                    grant_id: "grant-cleanup".to_string(),
                    confirmation_id: "confirmation-cleanup".to_string(),
                    binding,
                    authorization_revision: 7,
                    issued_at_unix_ms: unix_millis(),
                    expires_at_unix_ms: unix_millis().saturating_add(5_000),
                    single_use: true,
                    used: false,
                },
            );
            session
                .replay
                .lock()
                .expect("replay lock")
                .accept("request-cleanup");

            session.retire();
            assert!(session.closed.load(Ordering::Acquire));
            assert!(session.pending.lock().expect("pending lock").is_empty());
            assert!(session.approvals.lock().expect("approval lock").is_empty());
            assert!(session.grants.lock().expect("grant lock").is_empty());
            assert_eq!(session.replay.lock().expect("replay lock").len(), 0);
            assert!(session
                .expiry
                .worker
                .lock()
                .expect("expiry worker lock")
                .is_none());
            assert!(matches!(
                receiver
                    .recv_timeout(Duration::from_secs(1))
                    .expect("cleanup denial"),
                HostMessage::ConfirmationReply(ConfirmationReply {
                    decision: ConfirmationDecision::Deny,
                    ..
                })
            ));
        }

        #[test]
        fn long_session_replay_window_and_grant_ledger_stay_bounded() {
            let mut replay = RequestReplayWindow::default();
            for index in 0..300 {
                assert!(replay.accept(&format!("request-{index}")));
            }
            assert_eq!(replay.len(), REQUEST_REPLAY_WINDOW);
            assert!(!replay.accept("request-299"));
            assert!(replay.accept("request-0"));

            let binding = test_binding("session-ledger");
            let mut grants = HashMap::new();
            grants.insert(
                "expired".to_string(),
                ProcessGrant {
                    session_id: "session-ledger".to_string(),
                    grant_id: "expired".to_string(),
                    confirmation_id: "expired-confirmation".to_string(),
                    binding: binding.clone(),
                    authorization_revision: 7,
                    issued_at_unix_ms: unix_millis().saturating_sub(10_000),
                    expires_at_unix_ms: unix_millis().saturating_sub(1),
                    single_use: true,
                    used: false,
                },
            );
            reap_expired_grants(&mut grants);
            assert!(grants.is_empty());
            for index in 0..160 {
                let grant = ProcessGrant {
                    session_id: "session-ledger".to_string(),
                    grant_id: format!("grant-{index}"),
                    confirmation_id: format!("confirmation-{index}"),
                    binding: binding.clone(),
                    authorization_revision: 7,
                    issued_at_unix_ms: unix_millis(),
                    expires_at_unix_ms: unix_millis().saturating_add(60_000),
                    single_use: true,
                    used: false,
                };
                grants.insert(grant.grant_id.clone(), grant.clone());
                assert!(grants.len() <= MAX_GRANTS);
                let consumed = consume_active_grant(&mut grants, &grant, &binding, 7)
                    .expect("single-use grant consumption");
                assert!(consumed.used);
                assert!(grants.is_empty());
                assert!(consume_active_grant(&mut grants, &grant, &binding, 7).is_err());
            }
        }

        #[cfg(windows)]
        #[test]
        fn production_shaped_sidecar_startup_canary_uses_tagged_frames() {
            let executable = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../vita-agent/target/release/vita-agent.exe");
            if !executable.is_file() {
                eprintln!(
                    "skipping production-shaped sidecar canary; release image is absent: {}",
                    executable.display()
                );
                return;
            }
            let git_path = match resolve_git_path() {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("skipping production-shaped sidecar canary: {error}");
                    return;
                }
            };
            let app_data = tempfile::tempdir().expect("sidecar app-data root");
            let process_root = tempfile::tempdir().expect("sidecar process root");
            let workspace = fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".."))
                .expect("repository workspace");
            let workspace_for_sidecar =
                normalize_sidecar_local_path(&workspace).expect("sidecar workspace path");
            let app_data_for_sidecar =
                normalize_sidecar_local_path(app_data.path()).expect("sidecar app-data path");
            let git_for_sidecar =
                normalize_sidecar_local_path(&git_path).expect("sidecar Git path");
            let canary_resource = tempfile::tempdir().expect("sidecar canary resource root");
            let canary_executable = canary_resource.path().join(SIDECAR_RESOURCE_NAME);
            fs::copy(&executable, &canary_executable).expect("copy canary sidecar image");
            let sidecar_binding =
                VitaSidecarProcess::prepare_image(&canary_executable, canary_resource.path())
                    .expect("prepared release sidecar image");
            let mut process = VitaSidecarProcess::spawn_prepared(
                sidecar_binding,
                &[OsString::from("--serve-ipc")],
                process_root.path(),
            )
            .expect("production-shaped sidecar process");
            let stdout = process.take_stdout().expect("sidecar stdout");
            let stdin = process.take_stdin().expect("sidecar stdin");
            let mut stderr = process.take_stderr().expect("sidecar stderr");

            let (message, reader) = receive_vita_message_with_timeout(
                BufReader::new(stdout),
                HANDSHAKE_TIMEOUT,
                "canary handshake",
            )
            .expect("tagged handshake");
            let handshake = match message {
                VitaMessage::Handshake(value) => value,
                other => panic!("unexpected canary first frame: {other:?}"),
            };
            validate_handshake(&handshake).expect("pinned canary handshake");

            let session_id = "session-canary".to_string();
            let request = VitaSidecarStartRequest {
                life_id: "life-canary".to_string(),
                task_id: "task-canary".to_string(),
                workspace_path: workspace_for_sidecar.to_string_lossy().into_owned(),
            };
            let mut writer = BufWriter::new(stdin);
            protocol::write_frame(
                &mut writer,
                &HostMessage::Initialize(InitializeSession {
                    request_id: "initialize-canary".to_string(),
                    protocol_version: PROTOCOL_VERSION.to_string(),
                    session_id: session_id.clone(),
                    life_id: request.life_id.clone(),
                    task_id: request.task_id.clone(),
                    app_data_root: app_data_for_sidecar.to_string_lossy().into_owned(),
                    workspace_path: request.workspace_path.clone(),
                    git_path: git_for_sidecar.to_string_lossy().into_owned(),
                    provider: None,
                }),
            )
            .expect("canary initialize");
            let ready_result =
                receive_vita_message_with_timeout(reader, READY_TIMEOUT, "canary ready");
            let (message, reader) = match ready_result {
                Ok(value) => value,
                Err(error) => {
                    let _ = process.shutdown();
                    let mut diagnostics = String::new();
                    let _ = std::io::Read::read_to_string(&mut stderr, &mut diagnostics);
                    panic!("tagged ready: {error}; sidecar stderr: {diagnostics}");
                }
            };
            let ready = match message {
                VitaMessage::Ready(value) => value,
                other => panic!("unexpected canary post-initialize frame: {other:?}"),
            };
            validate_ready(&ready, &session_id, &request).expect("exact canary ready identity");

            protocol::write_frame(
                &mut writer,
                &HostMessage::Shutdown(protocol::Shutdown {
                    request_id: "shutdown-canary".to_string(),
                    session_id: session_id.clone(),
                }),
            )
            .expect("canary shutdown");
            let (message, _reader) =
                receive_vita_message_with_timeout(reader, READY_TIMEOUT, "canary shutdown ack")
                    .expect("tagged shutdown ack");
            assert!(matches!(
                message,
                VitaMessage::ShutdownAck(protocol::ShutdownAck { session_id: ack_session, .. })
                    if ack_session == session_id
            ));
            drop(writer);
            process.shutdown().expect("canary process shutdown");
        }
    }
}

#[cfg(windows)]
use windows::StateType as WindowsCoordinatorState;

#[cfg(not(windows))]
mod non_windows {
    use super::*;
    use tauri::State;

    pub(super) fn start_vita_sidecar(
        _coordinator: State<'_, VitaSidecarCoordinator>,
        _request: VitaSidecarStartRequest,
    ) -> Result<VitaSidecarStartResponse, String> {
        Err("Vita sidecar production boundary is Windows-only".to_string())
    }

    pub(super) fn get_vita_sidecar_status(
        _coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarStatusResponse, String> {
        Ok(VitaSidecarStatusResponse {
            running: false,
            provider_readiness: VitaProviderReadiness::SidecarNotRunning,
            session_id: None,
            pending: None,
            active_turn_id: None,
            turn_phase: None,
            assistant_text: None,
            turn_error: None,
        })
    }

    pub(super) fn confirm_vita_sidecar(
        _coordinator: State<'_, VitaSidecarCoordinator>,
        _pending_id: String,
    ) -> Result<VitaSidecarActionResponse, String> {
        Err("Vita sidecar production boundary is Windows-only".to_string())
    }

    pub(super) fn deny_vita_sidecar(
        _coordinator: State<'_, VitaSidecarCoordinator>,
        _pending_id: String,
    ) -> Result<VitaSidecarActionResponse, String> {
        Err("Vita sidecar production boundary is Windows-only".to_string())
    }

    pub(super) fn cancel_vita_sidecar(
        _coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarActionResponse, String> {
        Err("Vita sidecar production boundary is Windows-only".to_string())
    }

    pub(super) fn start_vita_turn(
        _coordinator: State<'_, VitaSidecarCoordinator>,
        _request: VitaTurnStartRequest,
    ) -> Result<VitaTurnStartResponse, String> {
        Err("Vita sidecar production boundary is Windows-only".to_string())
    }

    pub(super) fn cancel_vita_turn(
        _coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarActionResponse, String> {
        Err("Vita sidecar production boundary is Windows-only".to_string())
    }

    pub(super) fn stop_vita_sidecar(
        _coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarActionResponse, String> {
        Ok(VitaSidecarActionResponse { accepted: true })
    }
}

#[tauri::command]
pub(crate) fn start_vita_sidecar(
    app: AppHandle,
    coordinator: State<'_, VitaSidecarCoordinator>,
    request: VitaSidecarStartRequest,
) -> Result<VitaSidecarStartResponse, String> {
    #[cfg(windows)]
    {
        windows::start_vita_sidecar(app, coordinator, request)
    }
    #[cfg(not(windows))]
    {
        let _ = app;
        non_windows::start_vita_sidecar(coordinator, request)
    }
}

#[tauri::command]
pub(crate) fn get_vita_sidecar_status(
    coordinator: State<'_, VitaSidecarCoordinator>,
) -> Result<VitaSidecarStatusResponse, String> {
    #[cfg(windows)]
    {
        windows::get_vita_sidecar_status(coordinator)
    }
    #[cfg(not(windows))]
    {
        non_windows::get_vita_sidecar_status(coordinator)
    }
}

#[tauri::command]
pub(crate) fn start_vita_turn(
    coordinator: State<'_, VitaSidecarCoordinator>,
    request: VitaTurnStartRequest,
) -> Result<VitaTurnStartResponse, String> {
    #[cfg(windows)]
    {
        windows::start_vita_turn(coordinator, request)
    }
    #[cfg(not(windows))]
    {
        non_windows::start_vita_turn(coordinator, request)
    }
}

#[tauri::command]
pub(crate) fn cancel_vita_turn(
    coordinator: State<'_, VitaSidecarCoordinator>,
) -> Result<VitaSidecarActionResponse, String> {
    #[cfg(windows)]
    {
        windows::cancel_vita_turn(coordinator)
    }
    #[cfg(not(windows))]
    {
        non_windows::cancel_vita_turn(coordinator)
    }
}

#[tauri::command]
pub(crate) fn confirm_vita_sidecar(
    coordinator: State<'_, VitaSidecarCoordinator>,
    pending_id: String,
) -> Result<VitaSidecarActionResponse, String> {
    #[cfg(windows)]
    {
        windows::confirm_vita_sidecar(coordinator, pending_id)
    }
    #[cfg(not(windows))]
    {
        non_windows::confirm_vita_sidecar(coordinator, pending_id)
    }
}

#[tauri::command]
pub(crate) fn deny_vita_sidecar(
    coordinator: State<'_, VitaSidecarCoordinator>,
    pending_id: String,
) -> Result<VitaSidecarActionResponse, String> {
    #[cfg(windows)]
    {
        windows::deny_vita_sidecar(coordinator, pending_id)
    }
    #[cfg(not(windows))]
    {
        non_windows::deny_vita_sidecar(coordinator, pending_id)
    }
}

#[tauri::command]
pub(crate) fn cancel_vita_sidecar(
    coordinator: State<'_, VitaSidecarCoordinator>,
) -> Result<VitaSidecarActionResponse, String> {
    #[cfg(windows)]
    {
        windows::cancel_vita_sidecar(coordinator)
    }
    #[cfg(not(windows))]
    {
        non_windows::cancel_vita_sidecar(coordinator)
    }
}

#[tauri::command]
pub(crate) fn stop_vita_sidecar(
    coordinator: State<'_, VitaSidecarCoordinator>,
) -> Result<VitaSidecarActionResponse, String> {
    #[cfg(windows)]
    {
        windows::stop_vita_sidecar(coordinator)
    }
    #[cfg(not(windows))]
    {
        non_windows::stop_vita_sidecar(coordinator)
    }
}
