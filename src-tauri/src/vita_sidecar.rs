//! D29-H8-R1 Host boundary for the process-isolated Vita sidecar.
//!
//! The Host owns the lifecycle, the D28 SQLite read, confirmation state, and
//! the short-lived grant ledger.  Vita receives only the bounded protocol
//! DTOs; no provider credential, SQLite handle, or Codex crate crosses this
//! module boundary.

use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};

use crate::{capability::CapabilityRegistry, storage::StorageService};

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
    pub session_id: Option<String>,
    pub pending: Option<VitaSidecarPendingSummary>,
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
        ConfirmationRequired, GrantIssued, GrantRevalidated, Handshake, HostMessage,
        InitializeSession, IssueGrant, ProcessBinding, ProcessGrant, RevalidateGrant, VitaMessage,
        CODEX_PROTOCOL_SCHEMA_HASH, CODEX_UPSTREAM_COMMIT, PROTOCOL_VERSION, RUNTIME_ID,
    };
    use serde::de::DeserializeOwned;
    use sha2::{Digest, Sha256};
    use std::collections::{HashMap, HashSet};
    use std::ffi::OsString;
    use std::fs::{self, File};
    use std::io::{BufReader, BufWriter};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use tauri::{AppHandle, Manager, State};
    use vita_agent_protocol as protocol;

    // H7-C's fixed Git-status program identity is the profile identity.  The
    // generic H7 fixture program id is deliberately not accepted on this
    // production capability lane.
    const PROGRAM_ID: &str = PRODUCTION_GIT_STATUS_PROFILE_ID;
    const GRANT_LIFETIME_MS: u64 = 30_000;
    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
    const READY_TIMEOUT: Duration = Duration::from_secs(20);
    const MAX_PENDING: usize = 1;
    const MAX_GRANTS: usize = 64;
    const MAX_SIDECAR_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

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
        writer: Mutex<Option<BufWriter<File>>>,
        pending: Mutex<HashMap<String, PendingAction>>,
        approvals: Mutex<HashMap<String, ApprovedAction>>,
        grants: Mutex<HashMap<String, ProcessGrant>>,
        closed: AtomicBool,
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

    impl HostSessionState {
        fn send(&self, message: &HostMessage) -> Result<(), String> {
            let mut guard = self
                .writer
                .lock()
                .map_err(|_| "Vita Host writer lock was poisoned".to_string())?;
            let writer = guard
                .as_mut()
                .ok_or_else(|| "Vita Host sidecar writer is closed".to_string())?;
            protocol::write_frame(writer, message).map_err(|error| error.to_string())
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
    }

    fn pending_key(pending: &PendingAction) -> String {
        pending.pending_id.clone()
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
            let workspace = fs::canonicalize(&request.workspace_path)
                .map_err(|_| "Vita workspace path could not be canonicalized".to_string())?;
            if !workspace.is_dir() {
                return Err("Vita workspace path is not a directory".to_string());
            }
            let app_data_root = app
                .path()
                .app_data_dir()
                .map_err(|error| format!("Vita app data root unavailable: {error}"))?;
            fs::create_dir_all(&app_data_root)
                .map_err(|_| "Vita app data root could not be created".to_string())?;
            let app_data_root = fs::canonicalize(&app_data_root)
                .map_err(|_| "Vita app data root could not be canonicalized".to_string())?;
            validate_private_app_data_root(&app_data_root)?;

            let sidecar_binding = app_owned_sidecar_path(app)?;
            let sidecar = sidecar_binding.path.clone();
            let sidecar_image_sha256 = sha256_file(&sidecar)?;
            let process_root = app_data_root.join("vita-sidecar-process");
            fs::create_dir_all(&process_root)
                .map_err(|_| "Vita sidecar process root could not be created".to_string())?;
            let process_root = fs::canonicalize(&process_root)
                .map_err(|_| "Vita sidecar process root could not be canonicalized".to_string())?;
            let git_path = resolve_git_path()?;

            let mut process = VitaSidecarProcess::spawn(
                &sidecar,
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

            let (handshake, reader) = receive_with_timeout::<Handshake>(
                BufReader::new(stdout),
                HANDSHAKE_TIMEOUT,
                "Vita sidecar handshake",
            )?;
            validate_handshake(&handshake)?;
            let current_binding = app_owned_sidecar_path(app)?;
            if current_binding.path != sidecar
                || current_binding.namespace != sidecar_binding.namespace
                || current_binding.image != sidecar_binding.image
                || sha256_file(&sidecar)? != sidecar_image_sha256
            {
                return Err("Vita sidecar image changed during launch".to_string());
            }

            let session_id = secure_id("vita-session")?;
            let mut writer = BufWriter::new(stdin);
            let init = HostMessage::Initialize(InitializeSession {
                request_id: next_id("host-initialize"),
                protocol_version: PROTOCOL_VERSION.to_string(),
                session_id: session_id.clone(),
                life_id: request.life_id.clone(),
                task_id: request.task_id.clone(),
                app_data_root: app_data_root.to_string_lossy().into_owned(),
                workspace_path: workspace.to_string_lossy().into_owned(),
                git_path: git_path.to_string_lossy().into_owned(),
            });
            protocol::write_frame(&mut writer, &init).map_err(|error| error.to_string())?;

            let (ready, reader) = receive_with_timeout::<protocol::Ready>(
                reader,
                READY_TIMEOUT,
                "Vita sidecar ready",
            )?;
            validate_ready(&ready, &session_id, &request)?;
            let session = Arc::new(HostSessionState {
                session_id: session_id.clone(),
                life_id: request.life_id.clone(),
                task_id: request.task_id.clone(),
                workspace_identity: ready.workspace_identity,
                writer: Mutex::new(Some(writer)),
                pending: Mutex::new(HashMap::new()),
                approvals: Mutex::new(HashMap::new()),
                grants: Mutex::new(HashMap::new()),
                closed: AtomicBool::new(false),
            });
            let reader_session = Arc::clone(&session);
            let storage = Arc::clone(&self.authority_storage);
            let registry = self.registry.clone();
            let reader_handle = thread::Builder::new()
                .name("vita-sidecar-host-reader".to_string())
                .spawn(move || reader_loop(reader, reader_session, storage, registry))
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
                    session_id: None,
                    pending: None,
                });
            };
            Ok(VitaSidecarStatusResponse {
                running: !running.session.closed.load(Ordering::Acquire),
                session_id: Some(running.session.session_id.clone()),
                pending: running.session.pending_summary(),
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
            let pending = {
                let pending_guard = running
                    .session
                    .pending
                    .lock()
                    .map_err(|_| "Vita pending state lock was poisoned".to_string())?;
                pending_guard
                    .values()
                    .find(|pending| pending_key(pending) == pending_id)
                    .cloned()
            }
            .ok_or_else(|| "Vita pending confirmation was not found".to_string())?;

            if pending.expires_at_unix_ms <= unix_millis() {
                let _ = running
                    .session
                    .send(&HostMessage::ConfirmationReply(ConfirmationReply {
                        request_id: pending.request_id.clone(),
                        session_id: running.session.session_id.clone(),
                        decision: ConfirmationDecision::Deny,
                        authorization_revision: None,
                    }));
                remove_pending(&running.session, &pending.request_id);
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
                        remove_pending(&running.session, &pending.request_id);
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
            running
                .session
                .send(&HostMessage::ConfirmationReply(ConfirmationReply {
                    request_id: pending.request_id.clone(),
                    session_id: running.session.session_id.clone(),
                    decision,
                    authorization_revision: revision,
                }))?;
            remove_pending(&running.session, &pending.request_id);
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
            if let Some(pending) = running
                .session
                .pending
                .lock()
                .map_err(|_| "Vita pending state lock was poisoned")?
                .values()
                .next()
                .cloned()
            {
                let _ = running
                    .session
                    .send(&HostMessage::ConfirmationReply(ConfirmationReply {
                        request_id: pending.request_id.clone(),
                        session_id: running.session.session_id.clone(),
                        decision: ConfirmationDecision::Cancel,
                        authorization_revision: None,
                    }));
                remove_pending(&running.session, &pending.request_id);
            }
            running
                .session
                .send(&HostMessage::CancelAction(protocol::CancelAction {
                    request_id: next_id("host-cancel"),
                    session_id: running.session.session_id.clone(),
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
    ) {
        const MAX_SEEN_REQUEST_IDS: usize = 128;
        let mut seen_request_ids = HashSet::new();
        loop {
            let body = match protocol::read_frame(&mut reader) {
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
                || !seen_request_ids.insert(request_id.to_string())
                || seen_request_ids.len() > MAX_SEEN_REQUEST_IDS
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
        session.closed.store(true, Ordering::Release);
        session.close_writer();
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
        if request.session_id != session.session_id
            || request.life_id != session.life_id
            || request.task_id != session.task_id
            || request.capability_id != PRODUCTION_GIT_STATUS_CAPABILITY_ID
            || request.expires_at_unix_ms <= unix_millis()
            || request.binding.validate().is_err()
        {
            return Err("Vita confirmation binding was not exact".to_string());
        }
        validate_binding(session, &request.binding)?;
        let mut pending = session
            .pending
            .lock()
            .map_err(|_| "Vita pending state lock was poisoned".to_string())?;
        if pending.len() >= MAX_PENDING {
            return Err("Vita pending confirmation capacity was exhausted".to_string());
        }
        let pending_id = format!("pending:{}", secure_id("vita")?);
        pending.insert(
            pending_id.clone(),
            PendingAction {
                pending_id,
                request_id: request.request_id,
                life_id: request.life_id,
                task_id: request.task_id,
                capability_id: request.capability_id,
                workspace_summary: request.workspace_summary,
                expires_at_unix_ms: request.expires_at_unix_ms,
                binding: request.binding,
            },
        );
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
        let allowed = validate_binding(session, &request.binding).and_then(|_| {
            let revision =
                current_workspace_revision(storage, registry, session, &request.binding)?;
            if revision != request.authorization_revision {
                return Err("stale authorization revision".to_string());
            }
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
            let stored = grants
                .get_mut(&request.grant.grant_id)
                .ok_or_else(|| "Vita grant was not found".to_string())?;
            if stored != &request.grant
                || stored.used
                || !stored.single_use
                || stored.binding != request.binding
                || stored.authorization_revision != revision
                || stored.expires_at_unix_ms <= unix_millis()
            {
                return Err("Vita grant revalidation was denied".to_string());
            }
            stored.used = true;
            Ok(stored.clone())
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

    fn remove_pending(session: &HostSessionState, request_id: &str) {
        if let Ok(mut pending) = session.pending.lock() {
            pending.retain(|_, value| value.request_id != request_id);
        }
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
            VitaMessage::ShutdownAck(message) => &message.request_id,
            VitaMessage::Fatal(message) => &message.request_id,
        }
    }

    fn validate_handshake(handshake: &Handshake) -> Result<(), String> {
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

    fn receive_with_timeout<T>(
        mut reader: BufReader<File>,
        timeout: Duration,
        label: &'static str,
    ) -> Result<(T, BufReader<File>), String>
    where
        T: DeserializeOwned + Send + 'static,
    {
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name(format!("vita-sidecar-{label}"))
            .spawn(move || {
                let result = protocol::read_frame(&mut reader)
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| format!("{label} channel closed"))
                    .and_then(|body| protocol::decode_frame::<T>(&body).map_err(|e| e.to_string()));
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
    struct FileIdentity {
        volume_serial: u32,
        file_index: u64,
        file_size: u64,
        reparse: bool,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct SidecarPathBinding {
        path: PathBuf,
        namespace: FileIdentity,
        image: FileIdentity,
    }

    fn app_owned_sidecar_path(app: &AppHandle) -> Result<SidecarPathBinding, String> {
        let resource_dir = app
            .path()
            .resource_dir()
            .map_err(|error| format!("Vita resource directory unavailable: {error}"))?;
        let resource_dir = fs::canonicalize(&resource_dir)
            .map_err(|_| "Vita resource directory could not be canonicalized".to_string())?;
        let candidate = fs::canonicalize(resource_dir.join("vita-agent.exe"))
            .map_err(|_| "Vita sidecar image is not installed".to_string())?;
        if !candidate.is_file() || !candidate.starts_with(&resource_dir) {
            return Err(
                "Vita sidecar image is outside the app-owned resource directory".to_string(),
            );
        }
        Ok(SidecarPathBinding {
            path: candidate.clone(),
            namespace: file_identity(&resource_dir, false)?,
            image: file_identity(&candidate, true)?,
        })
    }

    fn file_identity(path: &Path, expect_file: bool) -> Result<FileIdentity, String> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
            FILE_SHARE_WRITE, OPEN_EXISTING,
        };

        let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if wide.iter().any(|unit| *unit == 0) {
            return Err("Vita image identity path was malformed".to_string());
        }
        wide.push(0);
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err("Vita image identity handle could not be opened".to_string());
        }
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        let read = unsafe { GetFileInformationByHandle(handle, &mut information) != 0 };
        unsafe {
            let _ = CloseHandle(handle);
        }
        if !read {
            return Err("Vita image identity could not be read".to_string());
        }
        let directory = information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let reparse = information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        if reparse || (expect_file && directory) || (!expect_file && !directory) {
            return Err("Vita image identity was not a trusted non-reparse object".to_string());
        }
        Ok(FileIdentity {
            volume_serial: information.dwVolumeSerialNumber,
            file_index: (u64::from(information.nFileIndexHigh) << 32)
                | u64::from(information.nFileIndexLow),
            file_size: (u64::from(information.nFileSizeHigh) << 32)
                | u64::from(information.nFileSizeLow),
            reparse,
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

    fn sha256_file(path: &Path) -> Result<String, String> {
        let mut file =
            File::open(path).map_err(|_| "Vita image could not be opened".to_string())?;
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut total = 0_u64;
        loop {
            let read = std::io::Read::read(&mut file, &mut buffer)
                .map_err(|_| "Vita image hash read failed".to_string())?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(read as u64);
            if total > MAX_SIDECAR_IMAGE_BYTES {
                return Err("Vita sidecar image exceeded its hash bound".to_string());
            }
            digest.update(&buffer[..read]);
        }
        Ok(format!("{:x}", digest.finalize()))
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

    pub fn stop_vita_sidecar(
        coordinator: State<'_, VitaSidecarCoordinator>,
    ) -> Result<VitaSidecarActionResponse, String> {
        coordinator.stop()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

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
            session_id: None,
            pending: None,
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
