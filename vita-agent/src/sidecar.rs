//! Process-isolated Vita sidecar entrypoint.
//!
//! The sidecar owns the native workspace capability, H7 supervisor, and the
//! pinned Codex composition. Authority decisions are RPCs to the Tauri Host;
//! this process never reads the Host SQLite database and never mints a grant.

use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Stdin, Stdout};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use protocol::{
    AuthorityEvaluate, ConfirmationDecision, ConfirmationRequired, GrantIssued, Handshake,
    HostMessage, InitializeSession, IssueGrant, ProcessBinding, ProcessGrant, RevalidateGrant,
    VitaMessage, CODEX_PROTOCOL_SCHEMA_HASH, CODEX_UPSTREAM_COMMIT, PROTOCOL_VERSION, RUNTIME_ID,
};
use vita_agent_protocol as protocol;

use crate::{
    H7ProcessBinding, H7ProcessGrant, VitaAgentEntrypoint, VitaAgentRuntime,
    VitaAgentRuntimeProfile, VitaExecutionContext, VitaGitStatusAuthority,
    VitaGitStatusPendingConfirmation, VitaGitStatusProduction,
    VITA_WORKSPACE_GIT_STATUS_CAPABILITY_ID, VITA_WORKSPACE_GIT_STATUS_PROFILE_ID,
    VITA_WORKSPACE_GIT_STATUS_TOOL_NAME,
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(35);
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

fn next_request_id(prefix: &str) -> String {
    let sequence = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{sequence}")
}

fn protocol_error(error: impl std::fmt::Display) -> String {
    format!("Vita sidecar protocol failure: {error}")
}

struct RouterInner {
    writer: Mutex<BufWriter<Stdout>>,
    replies: Mutex<HashMap<String, SyncSender<HostMessage>>>,
    commands: Mutex<Receiver<HostMessage>>,
    closed: AtomicBool,
}

#[derive(Clone)]
struct SidecarRouter {
    inner: Arc<RouterInner>,
}

impl SidecarRouter {
    fn start(reader: BufReader<Stdin>, writer: BufWriter<Stdout>) -> Self {
        let (command_sender, command_receiver) = mpsc::sync_channel(8);
        let inner = Arc::new(RouterInner {
            writer: Mutex::new(writer),
            replies: Mutex::new(HashMap::new()),
            commands: Mutex::new(command_receiver),
            closed: AtomicBool::new(false),
        });
        let thread_inner = Arc::clone(&inner);
        std::thread::Builder::new()
            .name("vita-sidecar-ipc-reader".to_string())
            .spawn(move || {
                let mut reader = reader;
                loop {
                    let body = match protocol::read_frame(&mut reader) {
                        Ok(Some(body)) => body,
                        Ok(None) | Err(_) => {
                            thread_inner.closed.store(true, Ordering::Release);
                            break;
                        }
                    };
                    let message = match protocol::decode_frame::<HostMessage>(&body) {
                        Ok(message) => message,
                        Err(_) => {
                            thread_inner.closed.store(true, Ordering::Release);
                            break;
                        }
                    };
                    let request_id = host_request_id(&message).to_string();
                    let reply = thread_inner
                        .replies
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .get(&request_id)
                        .cloned();
                    if let Some(reply) = reply {
                        if reply.send(message).is_err() {
                            thread_inner.closed.store(true, Ordering::Release);
                            break;
                        }
                    } else if command_sender.try_send(message).is_err() {
                        thread_inner.closed.store(true, Ordering::Release);
                        break;
                    }
                }
            })
            .expect("Vita sidecar IPC reader thread must start");
        Self { inner }
    }

    fn send(&self, message: &VitaMessage) -> Result<(), String> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err("Vita Host pipe is closed".to_string());
        }
        let mut writer = self
            .inner
            .writer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        protocol::write_frame(&mut *writer, message).map_err(protocol_error)
    }

    fn request(&self, message: VitaMessage) -> Result<HostMessage, String> {
        let request_id = vita_request_id(&message).to_string();
        let (sender, receiver) = mpsc::sync_channel(1);
        {
            let mut replies = self
                .inner
                .replies
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if replies.contains_key(&request_id) {
                return Err("duplicate Vita sidecar request ID".to_string());
            }
            if replies.len() >= 4 {
                return Err("Vita sidecar request bound is saturated".to_string());
            }
            replies.insert(request_id.clone(), sender);
        }
        let send_result = self.send(&message);
        let response = if send_result.is_ok() {
            receiver
                .recv_timeout(REQUEST_TIMEOUT)
                .map_err(|_| "Vita Host authority response timed out".to_string())
        } else {
            Err(send_result.unwrap_err())
        };
        self.inner
            .replies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&request_id);
        response
    }

    fn receive_command(&self) -> Result<Option<HostMessage>, String> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Ok(None);
        }
        let receiver = self
            .inner
            .commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match receiver.recv_timeout(REQUEST_TIMEOUT) {
            Ok(message) => Ok(Some(message)),
            Err(RecvTimeoutError::Timeout) => Err("Vita Host command timed out".to_string()),
            Err(RecvTimeoutError::Disconnected) => Ok(None),
        }
    }
}

fn host_request_id(message: &HostMessage) -> &str {
    match message {
        HostMessage::Initialize(message) => &message.request_id,
        HostMessage::AuthorityScopeReply(message) => &message.request_id,
        HostMessage::ConfirmationReply(message) => &message.request_id,
        HostMessage::GrantIssued(message) => &message.request_id,
        HostMessage::GrantRevalidated(message) => &message.request_id,
        HostMessage::CancelAction(message) => &message.request_id,
        HostMessage::Shutdown(message) => &message.request_id,
    }
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
        VitaMessage::ShutdownAck(message) => &message.request_id,
        VitaMessage::Fatal(message) => &message.request_id,
    }
}

pub async fn serve_ipc() -> Result<(), String> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut writer = BufWriter::new(stdout);

    protocol::write_frame(
        &mut writer,
        &VitaMessage::Handshake(Handshake {
            request_id: "vita-handshake-1".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            runtime: RUNTIME_ID.to_string(),
            codex_commit: CODEX_UPSTREAM_COMMIT.to_string(),
            codex_schema_hash: CODEX_PROTOCOL_SCHEMA_HASH.to_string(),
        }),
    )
    .map_err(protocol_error)?;

    let init_body = protocol::read_frame(&mut reader)
        .map_err(protocol_error)?
        .ok_or_else(|| "Vita Host closed before initialization".to_string())?;
    let init = match protocol::decode_frame::<HostMessage>(&init_body).map_err(protocol_error)? {
        HostMessage::Initialize(init) => init,
        _ => return Err("Vita sidecar expected Initialize as its first Host message".to_string()),
    };
    init.validate().map_err(protocol_error)?;

    let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
        PathBuf::from(&init.app_data_root),
        PathBuf::from(&init.workspace_path),
    )
    .map_err(|error| format!("Vita profile was rejected: {error}"))?;
    let workspace = profile
        .workspace_authority()
        .ok_or_else(|| "Vita workspace authority is unavailable".to_string())?
        .clone();
    let workspace_identity = workspace.identity().wire();
    let entrypoint = VitaAgentEntrypoint::initialize(profile)
        .await
        .map_err(|error| format!("Vita entrypoint initialization failed: {error}"))?;
    let context = VitaExecutionContext::try_new(init.life_id.clone(), init.task_id.clone())
        .map_err(|error| format!("Vita execution identity was invalid: {error:?}"))?;
    let router = SidecarRouter::start(reader, writer);
    let authority = Arc::new(SidecarHostAuthority {
        router: router.clone(),
        session_id: init.session_id.clone(),
    });
    let production = Arc::new(
        VitaGitStatusProduction::new(
            context,
            workspace,
            PathBuf::from(&init.git_path),
            Arc::clone(&authority) as Arc<dyn VitaGitStatusAuthority>,
        )
        .map_err(|error| format!("Vita H7-C production setup failed: {error}"))?,
    );
    let contributor = production.contributor();
    let runtime = Arc::new(
        VitaAgentRuntime::compose(&entrypoint, contributor)
            .await
            .map_err(|error| format!("Vita Codex composition failed: {error}"))?,
    );
    let receiver = production
        .take_confirmation_receiver()
        .ok_or_else(|| "Vita confirmation receiver was already consumed".to_string())?;

    router.send(&VitaMessage::Ready(protocol::Ready {
        request_id: next_request_id("vita-ready"),
        session_id: init.session_id.clone(),
        life_id: init.life_id.clone(),
        task_id: init.task_id.clone(),
        workspace_identity,
        capability_id: VITA_WORKSPACE_GIT_STATUS_CAPABILITY_ID.to_string(),
        profile_id: VITA_WORKSPACE_GIT_STATUS_PROFILE_ID.to_string(),
        tool_name: VITA_WORKSPACE_GIT_STATUS_TOOL_NAME.to_string(),
    }))?;
    spawn_confirmation_loop(router.clone(), init.clone(), receiver);

    loop {
        let command = tokio::task::spawn_blocking({
            let router = router.clone();
            move || router.receive_command()
        })
        .await
        .map_err(|_| "Vita sidecar command reader task failed".to_string())??;
        let Some(command) = command else {
            production.cancel();
            runtime.shutdown().await;
            return Err("Vita Host pipe closed".to_string());
        };
        match command {
            HostMessage::CancelAction(message) if message.session_id == init.session_id => {
                production.cancel();
                router.send(&VitaMessage::ActionCancelled(protocol::ActionCancelled {
                    request_id: message.request_id,
                    session_id: init.session_id.clone(),
                }))?;
            }
            HostMessage::Shutdown(message) if message.session_id == init.session_id => {
                production.cancel();
                runtime.shutdown().await;
                router.send(&VitaMessage::ShutdownAck(protocol::ShutdownAck {
                    request_id: message.request_id,
                    session_id: init.session_id.clone(),
                }))?;
                return Ok(());
            }
            _ => {
                production.cancel();
                runtime.shutdown().await;
                let _ = router.send(&VitaMessage::Fatal(protocol::FatalMessage {
                    request_id: next_request_id("vita-fatal"),
                    session_id: Some(init.session_id.clone()),
                    error_code: "SIDECAR_UNEXPECTED_HOST_MESSAGE".to_string(),
                }));
                return Err("Vita sidecar received an unexpected Host message".to_string());
            }
        }
    }
}

fn spawn_confirmation_loop(
    router: SidecarRouter,
    init: InitializeSession,
    mut receiver: tokio::sync::mpsc::Receiver<VitaGitStatusPendingConfirmation>,
) {
    tokio::spawn(async move {
        while let Some(action) = receiver.recv().await {
            let binding = action.binding();
            let wire_binding = binding_to_wire(&init.session_id, &binding);
            let request_id = next_request_id("vita-confirm");
            let response = tokio::task::spawn_blocking({
                let router = router.clone();
                let message = VitaMessage::ConfirmationRequired(ConfirmationRequired {
                    request_id,
                    session_id: init.session_id.clone(),
                    life_id: init.life_id.clone(),
                    task_id: init.task_id.clone(),
                    capability_id: VITA_WORKSPACE_GIT_STATUS_CAPABILITY_ID.to_string(),
                    workspace_summary: workspace_summary(&init.workspace_path),
                    expires_at_unix_ms: unix_millis().saturating_add(30_000),
                    binding: wire_binding,
                });
                move || router.request(message)
            })
            .await;
            let revision = match response {
                Ok(Ok(HostMessage::ConfirmationReply(reply)))
                    if reply.session_id == init.session_id
                        && reply.decision == ConfirmationDecision::Confirm
                        && reply.authorization_revision.is_some() =>
                {
                    reply.authorization_revision.unwrap_or(0)
                }
                _ => 0,
            };
            let _ = action.confirm(revision);
        }
    });
}

struct SidecarHostAuthority {
    router: SidecarRouter,
    session_id: String,
}

impl VitaGitStatusAuthority for SidecarHostAuthority {
    fn evaluate_workspace_scope(&self, binding: &H7ProcessBinding) -> Result<i64, String> {
        let request_id = next_request_id("vita-scope");
        let response = self
            .router
            .request(VitaMessage::AuthorityEvaluate(AuthorityEvaluate {
                request_id,
                session_id: self.session_id.clone(),
                binding: binding_to_wire(&self.session_id, binding),
            }))?;
        match response {
            HostMessage::AuthorityScopeReply(reply)
                if reply.session_id == self.session_id && reply.allowed =>
            {
                reply
                    .authorization_revision
                    .filter(|revision| *revision > 0)
                    .ok_or_else(|| "Host scope reply omitted a valid revision".to_string())
            }
            HostMessage::AuthorityScopeReply(reply) => Err(reply
                .error_code
                .unwrap_or_else(|| "Host denied workspace scope".to_string())),
            _ => Err("Host returned an unexpected scope response".to_string()),
        }
    }

    fn issue_process_grant(
        &self,
        binding: &H7ProcessBinding,
        authorization_revision: i64,
    ) -> Result<H7ProcessGrant, String> {
        let request_id = next_request_id("vita-grant");
        let expected_binding = binding_to_wire(&self.session_id, binding);
        let response = self.router.request(VitaMessage::IssueGrant(IssueGrant {
            request_id,
            session_id: self.session_id.clone(),
            binding: expected_binding.clone(),
            authorization_revision,
        }))?;
        let HostMessage::GrantIssued(GrantIssued {
            session_id,
            allowed,
            grant,
            error_code,
            ..
        }) = response
        else {
            return Err("Host returned an unexpected grant response".to_string());
        };
        if session_id != self.session_id || !allowed {
            return Err(error_code.unwrap_or_else(|| "Host denied ProcessGrant".to_string()));
        }
        let grant = grant.ok_or_else(|| "Host omitted ProcessGrant evidence".to_string())?;
        h7_grant_from_wire(&grant, &expected_binding, &self.session_id, false)
    }

    fn revalidate_process_grant(
        &self,
        binding: &H7ProcessBinding,
        grant: &mut H7ProcessGrant,
    ) -> Result<(), String> {
        let expected_binding = binding_to_wire(&self.session_id, binding);
        let request_id = next_request_id("vita-revalidate");
        let response = self
            .router
            .request(VitaMessage::RevalidateGrant(RevalidateGrant {
                request_id,
                session_id: self.session_id.clone(),
                binding: expected_binding.clone(),
                grant: grant_to_wire(&self.session_id, grant),
            }))?;
        let HostMessage::GrantRevalidated(protocol::GrantRevalidated {
            session_id,
            allowed,
            grant: returned,
            error_code,
            ..
        }) = response
        else {
            return Err("Host returned an unexpected revalidation response".to_string());
        };
        if session_id != self.session_id || !allowed {
            return Err(
                error_code.unwrap_or_else(|| "Host denied ProcessGrant revalidation".to_string())
            );
        }
        let returned = returned.ok_or_else(|| "Host omitted revalidated grant".to_string())?;
        let _ = h7_grant_from_wire(&returned, &expected_binding, &self.session_id, true)?;
        grant.mark_used_by_host();
        Ok(())
    }
}

fn binding_to_wire(session_id: &str, binding: &H7ProcessBinding) -> ProcessBinding {
    ProcessBinding {
        session_id: session_id.to_string(),
        life_id: binding.life_id().to_string(),
        task_id: binding.task_id().to_string(),
        capability_id: binding.capability_id().to_string(),
        program_id: binding.program_id().to_string(),
        executable_identity: binding.executable_identity().to_string(),
        executable_sha256: binding.executable_sha256().to_string(),
        argv_hash: binding.argv_hash().to_string(),
        argv_count: binding.argv_count().try_into().unwrap_or(u32::MAX),
        working_directory_identity: binding.working_directory_identity().to_string(),
        environment_policy_hash: binding.environment_policy_hash().to_string(),
        stdout_bound: binding.stdout_bound().try_into().unwrap_or(u32::MAX),
        stderr_bound: binding.stderr_bound().try_into().unwrap_or(u32::MAX),
        timeout_ms: binding.timeout_ms(),
        tool_call_id: binding.tool_call_id().to_string(),
        turn_id: binding.turn_id().to_string(),
        workspace_root_identity: binding
            .workspace_root_identity()
            .unwrap_or_default()
            .to_string(),
        profile_id: binding.profile_id().unwrap_or_default().to_string(),
        git_metadata_fence_hash: binding
            .git_metadata_fence_hash()
            .unwrap_or_default()
            .to_string(),
    }
}

fn h7_binding_from_wire(binding: &ProcessBinding) -> H7ProcessBinding {
    H7ProcessBinding::from_host_wire(
        binding.life_id.clone(),
        binding.task_id.clone(),
        binding.capability_id.clone(),
        binding.program_id.clone(),
        binding.executable_identity.clone(),
        binding.executable_sha256.clone(),
        binding.argv_hash.clone(),
        binding.argv_count as usize,
        binding.working_directory_identity.clone(),
        binding.environment_policy_hash.clone(),
        binding.stdout_bound as usize,
        binding.stderr_bound as usize,
        binding.timeout_ms,
        binding.tool_call_id.clone(),
        binding.turn_id.clone(),
        Some(binding.workspace_root_identity.clone()),
        Some(binding.profile_id.clone()),
        Some(binding.git_metadata_fence_hash.clone()),
    )
}

fn grant_to_wire(session_id: &str, grant: &H7ProcessGrant) -> ProcessGrant {
    ProcessGrant {
        session_id: session_id.to_string(),
        grant_id: grant.grant_id().to_string(),
        confirmation_id: grant.confirmation_id().to_string(),
        binding: binding_to_wire(session_id, grant.binding()),
        authorization_revision: grant.authorization_revision(),
        issued_at_unix_ms: grant.issued_at_unix_ms(),
        expires_at_unix_ms: grant.expires_at_unix_ms(),
        single_use: grant.single_use(),
        used: grant.is_used(),
    }
}

fn h7_grant_from_wire(
    grant: &ProcessGrant,
    expected_binding: &ProcessBinding,
    session_id: &str,
    require_used: bool,
) -> Result<H7ProcessGrant, String> {
    grant.validate().map_err(protocol_error)?;
    if grant.session_id != session_id
        || grant.binding != *expected_binding
        || grant.binding.capability_id != VITA_WORKSPACE_GIT_STATUS_CAPABILITY_ID
        || grant.binding.profile_id != VITA_WORKSPACE_GIT_STATUS_PROFILE_ID
        || grant.authorization_revision <= 0
        || (require_used && !grant.used)
        || (!require_used && grant.used)
    {
        return Err("Host ProcessGrant binding or lifecycle was invalid".to_string());
    }
    Ok(H7ProcessGrant::from_host_evidence(
        grant.grant_id.clone(),
        grant.confirmation_id.clone(),
        h7_binding_from_wire(&grant.binding),
        grant.authorization_revision,
        grant.issued_at_unix_ms,
        grant.expires_at_unix_ms,
        grant.single_use,
        grant.used,
    ))
}

fn workspace_summary(path: &str) -> String {
    Path::new(path)
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "selected workspace".to_string())
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u64::MAX as u128) as u64
        })
}
