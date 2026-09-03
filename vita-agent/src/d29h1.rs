//! D29-H1 process-isolated canonical-authority proof.
//!
//! The Codex/Vita side of this test uses the pinned upstream execution graph.
//! Its only authority transport is a bounded stdin/stdout request to the
//! Host fixture, which is compiled in a separate process with the normal Host
//! dependency graph and the canonical D28 evaluator.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use codex_core_api::{
    CodexAppsToolsCache, CodexAuth, EnvironmentManager, EventMsg, Op, SessionSource,
    StartThreadOptions, ThreadId, ThreadManager, TurnInputRequest, UserInput,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};

use crate::{
    VitaAgentEntrypoint, VitaAgentRuntimeProfile, VitaAuthorityError, VitaAuthorityEvidenceSource,
    VitaAuthorityFuture, VitaAuthorityOutcome, VitaAuthorityReason, VitaAuthorityVerdict,
    VitaBrokerSnapshot, VitaExecutionContext, VitaToolAuthorityPort, VitaToolAuthorityRequest,
    VitaToolBroker, VitaToolContributor, VITA_GOVERNED_ACTION_TOOL_NAME,
};

use super::{ProviderCapabilities, ProviderProfile, ProviderProtocol, ProviderRetryPolicy};
use super::{VitaGatewayBinding, VitaProviderAuthority};

const D29_H1_MODEL: &str = "d29h1-local-responses-model";
const D29_H1_PROMPT: &str = "Submit the bounded Vita operation.";
const D29_H1_REPLY: &str = "VITA_D29H1_DENIED_OK";
const D29_H1_CALL_ID: &str = "call-d29h1-governed";
const D29_H1_PROVIDER_ID: &str = "d29h1-loopback-responses";
const D29_H1_TURN_TIMEOUT: Duration = Duration::from_secs(12);
const D29_H1_CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);
const D29_H1_HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const D29_H1_HTTP_MAX_BODY: usize = 2 * 1024 * 1024;
const D29_H1_HOST_IPC_TIMEOUT: Duration = Duration::from_secs(600);
const D29_H1_HOST_IPC_MAX_BODY: usize = 8 * 1024;
const D29_H1_TEST_STACK_SIZE: usize = 32 * 1024 * 1024;

#[derive(Clone, PartialEq, Eq)]
enum UserCodexFileState {
    Absent,
    Present {
        size: u64,
        modified: Option<SystemTime>,
    },
    Unavailable,
}

#[derive(Clone, PartialEq, Eq)]
struct UserCodexState {
    config: UserCodexFileState,
    auth: UserCodexFileState,
    global_state: UserCodexFileState,
}

#[derive(Clone, PartialEq, Eq)]
struct HostCanary {
    parent_environment_fingerprint: u64,
    user_codex_state: UserCodexState,
}

impl std::fmt::Debug for HostCanary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HostCanary(<metadata-only>)")
    }
}

fn host_canary() -> HostCanary {
    let mut environment = std::env::vars_os().collect::<Vec<_>>();
    environment.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = DefaultHasher::new();
    environment.hash(&mut hasher);
    HostCanary {
        parent_environment_fingerprint: hasher.finish(),
        user_codex_state: snapshot_user_codex_state(),
    }
}

fn snapshot_user_codex_state() -> UserCodexState {
    let root = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .map(|path| path.join(".codex"));
    UserCodexState {
        config: snapshot_user_codex_file(root.as_deref(), "config.toml"),
        auth: snapshot_user_codex_file(root.as_deref(), "auth.json"),
        global_state: snapshot_user_codex_file(root.as_deref(), ".codex-global-state.json"),
    }
}

fn snapshot_user_codex_file(root: Option<&Path>, file_name: &str) -> UserCodexFileState {
    let Some(root) = root else {
        return UserCodexFileState::Unavailable;
    };
    match std::fs::symlink_metadata(root.join(file_name)) {
        Ok(metadata) => UserCodexFileState::Present {
            size: metadata.len(),
            modified: metadata.modified().ok(),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => UserCodexFileState::Absent,
        Err(_) => UserCodexFileState::Unavailable,
    }
}

#[derive(Debug, Default, Clone)]
struct FixtureObservation {
    request_count: usize,
    first_request_had_h1_tool: bool,
    tool_result_delivered: bool,
    bounded_deny_result_delivered: bool,
    observed_call_id: Option<String>,
    error: Option<String>,
}

struct ResponsesFixture {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    observation: Arc<Mutex<FixtureObservation>>,
    join: Option<JoinHandle<()>>,
}

impl ResponsesFixture {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind D29-H1 Responses fixture");
        let address = listener
            .local_addr()
            .expect("read D29-H1 Responses fixture address");
        let stop = Arc::new(AtomicBool::new(false));
        let observation = Arc::new(Mutex::new(FixtureObservation::default()));
        let stop_for_thread = Arc::clone(&stop);
        let observation_for_thread = Arc::clone(&observation);
        let join = thread::spawn(move || {
            let mut response_index = 0usize;
            while !stop_for_thread.load(Ordering::Acquire) && response_index < 2 {
                let (mut stream, peer) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) => {
                        observation_for_thread
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .error = Some(format!("fixture accept failed: {error}"));
                        return;
                    }
                };
                if stop_for_thread.load(Ordering::Acquire) {
                    return;
                }
                let result = handle_fixture_request(&mut stream, peer, response_index);
                {
                    let mut observed = observation_for_thread
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    observed.request_count += 1;
                    if response_index == 0 {
                        if let Ok(body) = &result {
                            observed.first_request_had_h1_tool = request_has_h1_tool(body);
                        }
                    } else if let Ok(body) = &result {
                        observed.tool_result_delivered =
                            request_has_function_call_output(body, D29_H1_CALL_ID);
                        observed.bounded_deny_result_delivered =
                            request_has_bounded_h1_deny(body, D29_H1_CALL_ID);
                        observed.observed_call_id = function_call_output_id(body);
                    }
                    if let Err(error) = result {
                        observed.error = Some(error);
                    }
                }
                response_index += 1;
            }
        });
        Self {
            address,
            stop,
            observation,
            join: Some(join),
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.address.port())
    }

    fn shutdown(mut self) -> (FixtureObservation, bool) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        let joined = self
            .join
            .take()
            .map(|join| join.join().is_ok())
            .unwrap_or(true);
        let observation = self
            .observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        (observation, joined)
    }
}

impl Drop for ResponsesFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn request_has_h1_tool(body: &[u8]) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|body| body.get("tools").cloned())
        .and_then(|tools| tools.as_array().cloned())
        .is_some_and(|tools| {
            tools.iter().any(|tool| {
                tool.get("name").and_then(Value::as_str) == Some(VITA_GOVERNED_ACTION_TOOL_NAME)
            })
        })
}

fn request_has_function_call_output(body: &[u8], call_id: &str) -> bool {
    function_call_output_id(body).as_deref() == Some(call_id)
}

fn function_call_output_id(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|body| body.get("input").cloned())
        .and_then(|input| input.as_array().cloned())
        .and_then(|items| {
            items.into_iter().find_map(|item| {
                (item.get("type").and_then(Value::as_str) == Some("function_call_output"))
                    .then(|| item.get("call_id").and_then(Value::as_str))
                    .flatten()
                    .map(str::to_owned)
            })
        })
}

fn request_has_bounded_h1_deny(body: &[u8], call_id: &str) -> bool {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|body| body.get("input").cloned())
        .and_then(|input| input.as_array().cloned())
        .is_some_and(|items| {
            items.iter().any(|item| {
                let is_output = item.get("type").and_then(Value::as_str)
                    == Some("function_call_output")
                    && item.get("call_id").and_then(Value::as_str) == Some(call_id);
                let Some(output) = item.get("output").and_then(Value::as_str) else {
                    return false;
                };
                let Ok(output) = serde_json::from_str::<Value>(output) else {
                    return false;
                };
                is_output
                    && output.get("status").and_then(Value::as_str) == Some("denied")
                    && output.get("deny_classification").and_then(Value::as_str)
                        == Some("unknown_capability_descriptor")
                    && output.get("execution_started").and_then(Value::as_bool) == Some(false)
                    && output.get("side_effect_count").and_then(Value::as_u64) == Some(0)
            })
        })
}

fn handle_fixture_request(
    stream: &mut TcpStream,
    peer: SocketAddr,
    response_index: usize,
) -> Result<Vec<u8>, String> {
    if !peer.ip().is_loopback() {
        return Err("D29-H1 fixture received a non-loopback peer".to_string());
    }
    let body = read_http_request(stream)?;
    if response_index == 0 {
        write_sse_response(stream, first_response_events())?;
    } else {
        write_sse_response(stream, completion_response_events())?;
    }
    Ok(body)
}

fn first_response_events() -> Vec<Value> {
    vec![
        json!({
            "type": "response.created",
            "response": {"id": "resp-d29h1-1", "object": "response", "status": "in_progress", "model": D29_H1_MODEL}
        }),
        json!({
            "type": "response.output_item.done",
            "item": {"type": "function_call", "call_id": D29_H1_CALL_ID, "name": VITA_GOVERNED_ACTION_TOOL_NAME, "arguments": "{\"operation\":\"observe-only\",\"scope\":\"none\",\"resource\":\"loopback-fixture\"}"}
        }),
        json!({
            "type": "response.completed",
            "response": {"id": "resp-d29h1-1", "object": "response", "status": "completed", "model": D29_H1_MODEL}
        }),
    ]
}

fn completion_response_events() -> Vec<Value> {
    vec![
        json!({
            "type": "response.created",
            "response": {"id": "resp-d29h1-2", "object": "response", "status": "in_progress", "model": D29_H1_MODEL}
        }),
        json!({
            "type": "response.output_item.added",
            "item": {"type": "message", "id": "msg-d29h1", "role": "assistant", "status": "in_progress", "content": []}
        }),
        json!({"type": "response.content_part.added"}),
        json!({"type": "response.output_text.delta", "delta": D29_H1_REPLY}),
        json!({"type": "response.output_text.done", "text": D29_H1_REPLY}),
        json!({"type": "response.content_part.done"}),
        json!({
            "type": "response.output_item.done",
            "item": {"type": "message", "id": "msg-d29h1", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": D29_H1_REPLY}]}
        }),
        json!({
            "type": "response.completed",
            "response": {"id": "resp-d29h1-2", "object": "response", "status": "completed", "model": D29_H1_MODEL}
        }),
    ]
}

fn write_sse_response(stream: &mut TcpStream, events: Vec<Value>) -> Result<(), String> {
    let mut body = String::new();
    for event in events {
        let event_type = event
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| "D29-H1 fixture event omitted type".to_string())?;
        body.push_str("event: ");
        body.push_str(event_type);
        body.push_str("\ndata: ");
        body.push_str(
            &serde_json::to_string(&event)
                .map_err(|_| "D29-H1 fixture event serialization failed".to_string())?,
        );
        body.push_str("\n\n");
    }
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .set_write_timeout(Some(D29_H1_HTTP_TIMEOUT))
        .map_err(|_| "D29-H1 fixture write timeout setup failed".to_string())?;
    stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(body.as_bytes()))
        .map_err(|_| "D29-H1 fixture response write failed".to_string())
}

fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    stream
        .set_read_timeout(Some(D29_H1_HTTP_TIMEOUT))
        .map_err(|_| "D29-H1 fixture read timeout setup failed".to_string())?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|_| "D29-H1 fixture request read failed".to_string())?;
        if read == 0 {
            return Err("D29-H1 fixture request closed before headers".to_string());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > D29_H1_HTTP_MAX_BODY {
            return Err("D29-H1 fixture request exceeded bounded size".to_string());
        }
        if let Some(offset) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break offset + 4;
        }
    };
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "D29-H1 fixture request headers were not UTF-8".to_string())?;
    let content_length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .ok_or_else(|| "D29-H1 fixture request omitted content length".to_string())?;
    if content_length > D29_H1_HTTP_MAX_BODY {
        return Err("D29-H1 fixture content length exceeded bounded size".to_string());
    }
    while bytes.len() < header_end + content_length {
        let read = stream
            .read(&mut chunk)
            .map_err(|_| "D29-H1 fixture request body read failed".to_string())?;
        if read == 0 {
            return Err("D29-H1 fixture request closed before body".to_string());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > header_end + content_length {
            break;
        }
    }
    Ok(bytes[header_end..header_end + content_length].to_vec())
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostAuthorityResponse {
    canonical_evaluations: usize,
    production_registry_size: usize,
    authorization_row_reads: usize,
    result: String,
    life_id: String,
    capability_id: String,
    requested_scope: String,
}

struct ProcessIsolatedCanonicalAuthority {
    repo_root: PathBuf,
    observations: Arc<Mutex<Vec<HostAuthorityResponse>>>,
}

impl ProcessIsolatedCanonicalAuthority {
    fn new() -> Self {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("D29-H1 Vita manifest must have the repository root as its parent")
            .to_path_buf();
        Self {
            repo_root,
            observations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn snapshot(&self) -> Vec<HostAuthorityResponse> {
        self.observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl VitaToolAuthorityPort for ProcessIsolatedCanonicalAuthority {
    fn evaluate(&self, request: VitaToolAuthorityRequest) -> VitaAuthorityFuture {
        let repo_root = self.repo_root.clone();
        let observations = Arc::clone(&self.observations);
        Box::pin(async move {
            let context = request
                .context()
                .ok_or(VitaAuthorityError::InvalidRequest)?;
            let wire_request = json!({
                "life_id": context.life_id(),
                "capability_id": request.capability_id(),
                "requested_scope": request.requested_scope().as_str(),
            });
            let response = invoke_host_fixture(&repo_root, &wire_request)?;
            if response.canonical_evaluations != 1
                || response.production_registry_size != 0
                || response.authorization_row_reads != 0
                || response.result != "UnknownCapability"
                || response.life_id != context.life_id()
                || response.capability_id != request.capability_id()
                || response.requested_scope != request.requested_scope().as_str()
            {
                return Err(VitaAuthorityError::InvalidVerdict);
            }
            observations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(response);
            VitaAuthorityVerdict::from_request(
                &request,
                VitaAuthorityOutcome::Denied,
                VitaAuthorityReason::UnknownCapabilityDescriptor,
                None,
                VitaAuthorityEvidenceSource::HostCanonicalAuthority,
            )
        })
    }
}

fn invoke_host_fixture(
    repo_root: &Path,
    request: &Value,
) -> Result<HostAuthorityResponse, VitaAuthorityError> {
    let manifest = repo_root.join("src-tauri").join("Cargo.toml");
    let fixture_executable = repo_root
        .join("src-tauri")
        .join("target")
        .join("debug")
        .join(if cfg!(windows) {
            "d29h1-authority-fixture.exe"
        } else {
            "d29h1-authority-fixture"
        });
    let mut command = if fixture_executable.is_file() {
        Command::new(&fixture_executable)
    } else {
        let mut command = Command::new("cargo");
        command
            .current_dir(repo_root)
            .args(["run", "--quiet", "--locked", "--manifest-path"])
            .arg(&manifest)
            .args([
                "--bin",
                "d29h1-authority-fixture",
                "--features",
                "d29-h1-host-fixture",
            ]);
        command
    };
    let mut child = command
        .current_dir(repo_root)
        .env("CARGO_BUILD_JOBS", "1")
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_PROFILE_TEST_DEBUG", "0")
        .env("RUSTFLAGS", "-C debuginfo=0")
        .env("CARGO_TERM_COLOR", "never")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| VitaAuthorityError::Unavailable)?;

    let mut stdin = child.stdin.take().ok_or(VitaAuthorityError::Unavailable)?;
    serde_json::to_writer(&mut stdin, request).map_err(|_| VitaAuthorityError::Unavailable)?;
    stdin
        .write_all(b"\n")
        .map_err(|_| VitaAuthorityError::Unavailable)?;
    drop(stdin);

    let deadline = Instant::now() + D29_H1_HOST_IPC_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                // This waits for the bounded fixture process, not for worker
                // readiness.  The Host fixture itself has no worker loop.
                thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(VitaAuthorityError::Unavailable);
            }
        }
    };
    if !status.success() {
        return Err(VitaAuthorityError::Unavailable);
    }

    let mut output = Vec::new();
    child
        .stdout
        .take()
        .ok_or(VitaAuthorityError::Unavailable)?
        .take((D29_H1_HOST_IPC_MAX_BODY + 1) as u64)
        .read_to_end(&mut output)
        .map_err(|_| VitaAuthorityError::Unavailable)?;
    if output.len() > D29_H1_HOST_IPC_MAX_BODY {
        return Err(VitaAuthorityError::InvalidVerdict);
    }
    let output = std::str::from_utf8(&output).map_err(|_| VitaAuthorityError::InvalidVerdict)?;
    serde_json::from_str(output.trim()).map_err(|_| VitaAuthorityError::InvalidVerdict)
}

struct H1Runtime {
    _app_data: TempDir,
    _workspace: TempDir,
    manager: Arc<ThreadManager>,
    thread: Option<Arc<codex_core_api::CodexThread>>,
    thread_id: Option<ThreadId>,
    fixture: Option<ResponsesFixture>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownStatus {
    NotAttempted,
    Success,
    TimedOut,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CleanupEvidence {
    initial_shutdown: ShutdownStatus,
    final_shutdown: ShutdownStatus,
    manager_thread_count: usize,
    fixture_listener_joined: bool,
}

impl H1Runtime {
    async fn shutdown(mut self) -> Result<(CleanupEvidence, FixtureObservation), String> {
        let mut initial_shutdown = ShutdownStatus::NotAttempted;
        let mut final_shutdown = ShutdownStatus::NotAttempted;
        if let Some(thread) = self.thread.take() {
            initial_shutdown = shutdown_thread_once(&thread).await;
            if initial_shutdown != ShutdownStatus::Success {
                let _ = tokio::time::timeout(D29_H1_CLEANUP_TIMEOUT, thread.submit(Op::Interrupt))
                    .await;
            }
            final_shutdown = shutdown_thread_once(&thread).await;
            if final_shutdown == ShutdownStatus::Success {
                if let Some(thread_id) = self.thread_id.as_ref() {
                    let _ = self
                        .manager
                        .remove_thread_if_matches(thread_id, &thread)
                        .await;
                }
            }
        }
        let manager_thread_count = self.manager.list_thread_ids().await.len();
        let (fixture_observation, fixture_listener_joined) = match self.fixture.take() {
            Some(fixture) => fixture.shutdown(),
            None => (FixtureObservation::default(), true),
        };
        Ok((
            CleanupEvidence {
                initial_shutdown,
                final_shutdown,
                manager_thread_count,
                fixture_listener_joined,
            },
            fixture_observation,
        ))
    }
}

async fn shutdown_thread_once(thread: &Arc<codex_core_api::CodexThread>) -> ShutdownStatus {
    match tokio::time::timeout(D29_H1_CLEANUP_TIMEOUT, thread.shutdown_and_wait()).await {
        Ok(Ok(())) => ShutdownStatus::Success,
        Ok(Err(_)) => ShutdownStatus::Failed,
        Err(_) => ShutdownStatus::TimedOut,
    }
}

async fn start_runtime() -> Result<
    (
        H1Runtime,
        Arc<VitaToolBroker>,
        Arc<ProcessIsolatedCanonicalAuthority>,
        HostCanary,
    ),
    String,
> {
    let before = host_canary();
    let app_data = tempdir().map_err(|_| "create D29-H1 app data failed".to_string())?;
    let workspace = tempdir().map_err(|_| "create D29-H1 workspace failed".to_string())?;
    let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
        app_data.path().to_path_buf(),
        workspace.path().to_path_buf(),
    )
    .map_err(|error| format!("create D29-H1 profile: {error}"))?;

    let fixture = ResponsesFixture::start();
    let provider = ProviderProfile::new_for_test_localhost(
        D29_H1_PROVIDER_ID,
        "D29-H1 loopback Responses fixture",
        ProviderProtocol::OpenAiResponses,
        fixture.base_url(),
        D29_H1_MODEL,
        None,
        D29_H1_HTTP_TIMEOUT,
        ProviderRetryPolicy::default(),
        ProviderCapabilities {
            tools: true,
            ..ProviderCapabilities::none()
        },
    )
    .map_err(|error| format!("create D29-H1 provider profile: {error}"))?;
    let authority = VitaProviderAuthority::configure(provider)
        .map_err(|error| format!("configure D29-H1 provider: {error}"))?;
    let binding = VitaGatewayBinding::for_owned_private_listener(fixture.address.port())
        .map_err(|error| format!("create D29-H1 private binding: {error}"))?;
    let ready = authority
        .prepare_gateway(binding)
        .map_err(|error| format!("prepare D29-H1 gateway binding: {error}"))?;
    let entrypoint = VitaAgentEntrypoint::initialize_with_gateway_for_tests(profile, &ready)
        .await
        .map_err(|error| format!("compile D29-H1 Codex config: {error}"))?;
    let config = entrypoint.config().clone();

    let context = VitaExecutionContext::try_new("life-d29h1", "task-d29h1")
        .map_err(|error| format!("create D29-H1 execution context: {error:?}"))?;
    let canonical_authority = Arc::new(ProcessIsolatedCanonicalAuthority::new());
    let authority_port: Arc<dyn VitaToolAuthorityPort> = canonical_authority.clone();
    let broker = VitaToolBroker::new(context, authority_port);
    let mut extensions =
        codex_core_api::ExtensionRegistryBuilder::<codex_core::config::Config>::new();
    extensions.tool_contributor(Arc::new(VitaToolContributor::new(Arc::clone(&broker))));
    let extensions = Arc::new(extensions.build());
    let auth_manager = codex_core::test_support::auth_manager_from_auth_with_home(
        CodexAuth::from_api_key("d29h1-in-memory-kernel-auth"),
        config.codex_home.to_path_buf(),
    );
    let manager = Arc::new(ThreadManager::new(
        &config,
        Arc::clone(&auth_manager),
        codex_core_api::build_models_manager(&config, Arc::clone(&auth_manager)),
        CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(EnvironmentManager::default_for_tests()),
        extensions,
        Arc::new(codex_core::test_support::EmptyUserInstructionsProvider),
        None,
        codex_core_api::thread_store_from_config(&config, None),
        None,
        "d29h1-local-installation".to_string(),
        None,
        None,
    ));
    let new_thread = tokio::time::timeout(
        D29_H1_TURN_TIMEOUT,
        manager.start_thread(StartThreadOptions::new(config)),
    )
    .await
    .map_err(|_| "D29-H1 thread startup timed out".to_string())?
    .map_err(|error| format!("D29-H1 thread startup failed: {error}"))?;

    Ok((
        H1Runtime {
            _app_data: app_data,
            _workspace: workspace,
            manager,
            thread: Some(new_thread.thread),
            thread_id: Some(new_thread.thread_id),
            fixture: Some(fixture),
        },
        broker,
        canonical_authority,
        before,
    ))
}

async fn run_turn(
    thread: &Arc<codex_core_api::CodexThread>,
) -> Result<(Option<String>, Option<String>, usize), String> {
    tokio::time::timeout(
        D29_H1_TURN_TIMEOUT,
        thread.start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: D29_H1_PROMPT.to_string(),
            text_elements: Vec::new(),
        }])),
    )
    .await
    .map_err(|_| "D29-H1 turn submission timed out".to_string())?
    .map_err(|error| format!("D29-H1 turn submission failed: {error}"))?;

    let deadline = Instant::now() + D29_H1_TURN_TIMEOUT;
    let mut event_count = 0usize;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("D29-H1 turn did not reach a terminal event".to_string());
        }
        let event = tokio::time::timeout(remaining, thread.next_event())
            .await
            .map_err(|_| "D29-H1 event wait timed out".to_string())?
            .map_err(|error| format!("D29-H1 event stream failed: {error}"))?;
        event_count += 1;
        if let EventMsg::TurnComplete(complete) = event.msg {
            return Ok((
                complete.last_agent_message,
                complete.error.map(|error| error.message),
                event_count,
            ));
        }
    }
}

#[test]
fn d29h1_real_codex_tool_request_uses_isolated_host_authority() {
    thread::Builder::new()
        .name("d29h1-real-codex-tool".to_string())
        .stack_size(D29_H1_TEST_STACK_SIZE)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-H1 test runtime should build");
            runtime.block_on(d29h1_real_codex_tool_request_body());
        })
        .expect("D29-H1 test thread should start")
        .join()
        .expect("D29-H1 test thread should finish");
}

async fn d29h1_real_codex_tool_request_body() {
    let (runtime, broker, canonical_authority, before) =
        start_runtime().await.expect("D29-H1 runtime should start");
    let turn = run_turn(
        runtime
            .thread
            .as_ref()
            .expect("D29-H1 runtime should contain a thread"),
    )
    .await;
    let (terminal_message, terminal_error, event_count) =
        turn.expect("D29-H1 turn should reach TurnComplete");
    let (cleanup, fixture) = runtime.shutdown().await.expect("D29-H1 cleanup should run");
    let after = host_canary();
    assert_eq!(before, after, "D29-H1 host canary changed");

    assert_eq!(terminal_error, None);
    assert_eq!(terminal_message.as_deref(), Some(D29_H1_REPLY));
    assert!(event_count > 0);
    assert_eq!(cleanup.initial_shutdown, ShutdownStatus::Success);
    assert_eq!(cleanup.final_shutdown, ShutdownStatus::Success);
    assert_eq!(cleanup.manager_thread_count, 0);
    assert!(cleanup.fixture_listener_joined);
    assert_eq!(fixture.request_count, 2);
    assert!(fixture.first_request_had_h1_tool);
    assert!(fixture.tool_result_delivered);
    assert!(fixture.bounded_deny_result_delivered);
    assert_eq!(fixture.observed_call_id.as_deref(), Some(D29_H1_CALL_ID));
    assert_eq!(fixture.error, None);

    let snapshot: VitaBrokerSnapshot = broker.snapshot();
    assert_eq!(snapshot.attempted_requests, 1);
    assert_eq!(snapshot.authority_lookups, 1);
    assert_eq!(snapshot.execution_started, 0);
    assert_eq!(snapshot.side_effect_count, 0);
    assert_eq!(snapshot.max_active_authority, 1);

    let host_observations = canonical_authority.snapshot();
    assert_eq!(host_observations.len(), 1);
    let host = &host_observations[0];
    assert_eq!(host.canonical_evaluations, 1);
    assert_eq!(host.production_registry_size, 0);
    assert_eq!(host.authorization_row_reads, 0);
    assert_eq!(host.result, "UnknownCapability");
    assert_eq!(host.life_id, "life-d29h1");
    assert_eq!(host.capability_id, "vita.governed_action");
    assert_eq!(host.requested_scope, "none");
}
