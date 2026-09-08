//! D29-H5-C real pinned-Codex crash/recovery canary.
//!
//! This module is test-only and is intentionally kept outside the production
//! registry.  The full fixture and subprocess proof are added below the
//! certified H5 implementation boundary.

#![allow(dead_code)]

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use codex_core_api::{
    CodexAppsToolsCache, CodexAuth, EnvironmentManager, EventMsg, Op, SessionSource,
    StartThreadOptions, ThreadId, ThreadManager, TurnInputRequest, TurnInputSubmission, UserInput,
};
use serde_json::{json, Value};
use tempfile::tempdir;

use crate::d29h4::tests::ProcessIsolatedH4Authority;
use crate::d29h4::{
    VitaH4AuthorityPort, VitaWorkspaceReplaceBroker, VITA_WORKSPACE_REPLACE_TOOL_NAME,
};
use crate::d29h5::{
    tests::ProcessIsolatedH5RecoveryAuthority, H5RecoveryExecutor, RecoveryActionRequest,
    RecoveryAuthorityPort, RecoveryExecutionOutcome, VitaWorkspaceReplaceH5ToolContributor,
};
use crate::provider_gateway::{VitaGatewayBinding, VitaProviderAuthority};
use crate::recovery_journal::{RecoveryJournalStore, RecoveryTransactionState};
use crate::{
    sha256_hex, ProviderCapabilities, ProviderProfile, ProviderProtocol, ProviderRetryPolicy,
    VitaAgentEntrypoint, VitaAgentRuntimeProfile, VitaExecutionContext,
};

const LIFE_ID: &str = "life-d29h4-a";
const TASK_ID: &str = "task-d29h4-a";
const MODEL: &str = "d29h5-c-local-responses-model";
const PROMPT: &str = "Perform the exact bounded workspace replacement.";
const REPLY: &str = "D29-H5-C committed";
const CALL_ID: &str = "call-d29h5-c-replace";
const PROVIDER_ID: &str = "d29h5-c-loopback-responses";
const RELATIVE_PATH: &str = "replace-me.txt";
const ORIGINAL: &str = "VITA_D29_H5_C_ORIGINAL_界🙂";
const REPLACEMENT: &str = "VITA_D29_H5_C_REPLACEMENT";
const CRASH_ORIGINAL: &str = "A界B";
const CRASH_REPLACEMENT: &str = "XY";
const TURN_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_TIMEOUT: Duration = Duration::from_secs(3);
const HTTP_MAX_BODY: usize = 2 * 1024 * 1024;
const TEST_STACK_SIZE: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Default)]
struct H5FixtureObservation {
    request_count: usize,
    first_request_schema_exact: bool,
    initial_turn_id: Option<String>,
    function_call_output: Option<Value>,
    output_has_authority_facts: bool,
    error: Option<String>,
}

#[derive(Default)]
struct H5GateState {
    initial_turn_id: Option<String>,
    released: bool,
    error: Option<String>,
}

struct H5Gate {
    state: Mutex<H5GateState>,
    changed: Condvar,
}

impl H5Gate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(H5GateState::default()),
            changed: Condvar::new(),
        })
    }

    fn capture_turn_id(&self, body: &[u8]) -> Result<(), String> {
        let turn_id = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| value.get("client_metadata").cloned())
            .and_then(|value| value.get("turn_id").cloned())
            .and_then(|value| value.as_str().map(str::to_owned))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "D29-H5-C fixture request omitted client turn_id".to_string());
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = match turn_id {
            Ok(turn_id) => {
                state.initial_turn_id = Some(turn_id);
                Ok(())
            }
            Err(error) => {
                state.error = Some(error.clone());
                Err(error)
            }
        };
        self.changed.notify_all();
        result
    }

    fn wait_for_turn_id(&self) -> Result<String, String> {
        let deadline = Instant::now() + TURN_TIMEOUT;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if let Some(error) = state.error.clone() {
                return Err(error);
            }
            if let Some(turn_id) = state.initial_turn_id.clone() {
                return Ok(turn_id);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("D29-H5-C fixture turn-id wait timed out".to_string());
            }
            let (next, timeout) = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
            if timeout.timed_out() {
                return Err("D29-H5-C fixture turn-id wait timed out".to_string());
            }
        }
    }

    fn wait_until_released(&self) -> Result<(), String> {
        let deadline = Instant::now() + TURN_TIMEOUT;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !state.released {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("D29-H5-C fixture release wait timed out".to_string());
            }
            let (next, timeout) = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state = next;
            if timeout.timed_out() && !state.released {
                return Err("D29-H5-C fixture release wait timed out".to_string());
            }
        }
        Ok(())
    }

    fn release(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .released = true;
        self.changed.notify_all();
    }
}

struct H5ResponsesFixture {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    observation: Arc<Mutex<H5FixtureObservation>>,
    gate: Arc<H5Gate>,
    join: Option<JoinHandle<()>>,
}

impl H5ResponsesFixture {
    fn start() -> Self {
        Self::start_with_contents(ORIGINAL, REPLACEMENT)
    }

    fn start_with_contents(original: &str, replacement: &str) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind D29-H5-C fixture");
        let address = listener
            .local_addr()
            .expect("read D29-H5-C fixture address");
        let stop = Arc::new(AtomicBool::new(false));
        let observation = Arc::new(Mutex::new(H5FixtureObservation::default()));
        let gate = H5Gate::new();
        let stop_for_thread = Arc::clone(&stop);
        let observation_for_thread = Arc::clone(&observation);
        let gate_for_thread = Arc::clone(&gate);
        let original_for_thread = original.to_string();
        let replacement_for_thread = replacement.to_string();
        let join = thread::spawn(move || {
            let mut request_index = 0usize;
            while !stop_for_thread.load(Ordering::Acquire) && request_index < 2 {
                let (mut stream, peer) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(error) => {
                        observation_for_thread
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .error = Some(error.to_string());
                        return;
                    }
                };
                if stop_for_thread.load(Ordering::Acquire) {
                    break;
                }
                let result = handle_fixture_request(
                    &mut stream,
                    peer,
                    request_index,
                    &gate_for_thread,
                    &original_for_thread,
                    &replacement_for_thread,
                );
                let mut observed = observation_for_thread
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                observed.request_count += 1;
                if let Ok(body) = &result {
                    if request_index == 0 {
                        observed.first_request_schema_exact = exact_replace_tool_schema(body);
                        observed.initial_turn_id = extract_turn_id(body);
                    } else {
                        observed.function_call_output = function_call_output(body, CALL_ID);
                        observed.output_has_authority_facts = observed
                            .function_call_output
                            .as_ref()
                            .is_some_and(output_has_authority_facts);
                    }
                }
                if let Err(error) = result {
                    observed.error = Some(error);
                }
                request_index += 1;
            }
        });
        Self {
            address,
            stop,
            observation,
            gate,
            join: Some(join),
        }
    }

    fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.address.port())
    }

    async fn wait_for_turn_id(&self) -> Result<String, String> {
        let gate = Arc::clone(&self.gate);
        tokio::task::spawn_blocking(move || gate.wait_for_turn_id())
            .await
            .map_err(|_| "D29-H5-C turn-id wait task failed".to_string())?
    }

    fn release(&self) {
        self.gate.release();
    }

    fn shutdown(mut self) -> (H5FixtureObservation, bool) {
        self.stop.store(true, Ordering::Release);
        self.gate.release();
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

impl Drop for H5ResponsesFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.gate.release();
        let _ = TcpStream::connect(self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn handle_fixture_request(
    stream: &mut TcpStream,
    peer: SocketAddr,
    request_index: usize,
    gate: &H5Gate,
    original: &str,
    replacement: &str,
) -> Result<Vec<u8>, String> {
    if !peer.ip().is_loopback() {
        return Err("D29-H5-C fixture received a non-loopback peer".to_string());
    }
    let body = read_http_request(stream)?;
    if request_index == 0 {
        gate.capture_turn_id(&body)?;
        gate.wait_until_released()?;
        write_sse_response(stream, first_response_events(original, replacement))?;
    } else if request_index == 1 {
        write_sse_response(stream, completion_response_events())?;
    } else {
        return Err("D29-H5-C fixture received too many requests".to_string());
    }
    Ok(body)
}

fn first_response_events(original: &str, replacement: &str) -> Vec<Value> {
    let arguments = serde_json::to_string(&json!({
        "relative_path": RELATIVE_PATH,
        "expected_sha256": sha256_hex(original.as_bytes()),
        "replacement_content": replacement,
    }))
    .expect("D29-H5-C function arguments serialize");
    vec![
        json!({
            "type": "response.created",
            "response": {"id": "resp-d29h5-c-1", "object": "response", "status": "in_progress", "model": MODEL}
        }),
        json!({
            "type": "response.output_item.done",
            "item": {"type": "function_call", "call_id": CALL_ID, "name": VITA_WORKSPACE_REPLACE_TOOL_NAME, "arguments": arguments}
        }),
        json!({
            "type": "response.completed",
            "response": {"id": "resp-d29h5-c-1", "object": "response", "status": "completed", "model": MODEL}
        }),
    ]
}

fn completion_response_events() -> Vec<Value> {
    vec![
        json!({
            "type": "response.created",
            "response": {"id": "resp-d29h5-c-2", "object": "response", "status": "in_progress", "model": MODEL}
        }),
        json!({
            "type": "response.output_item.added",
            "item": {"type": "message", "id": "msg-d29h5-c", "role": "assistant", "status": "in_progress", "content": []}
        }),
        json!({"type": "response.content_part.added"}),
        json!({"type": "response.output_text.delta", "delta": REPLY}),
        json!({"type": "response.output_text.done", "text": REPLY}),
        json!({"type": "response.content_part.done"}),
        json!({
            "type": "response.output_item.done",
            "item": {"type": "message", "id": "msg-d29h5-c", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": REPLY}]}
        }),
        json!({
            "type": "response.completed",
            "response": {"id": "resp-d29h5-c-2", "object": "response", "status": "completed", "model": MODEL}
        }),
    ]
}

fn write_sse_response(stream: &mut TcpStream, events: Vec<Value>) -> Result<(), String> {
    let mut body = String::new();
    for event in events {
        let event_type = event
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| "D29-H5-C fixture event omitted type".to_string())?;
        body.push_str("event: ");
        body.push_str(event_type);
        body.push_str("\ndata: ");
        body.push_str(
            &serde_json::to_string(&event)
                .map_err(|_| "D29-H5-C fixture event serialization failed".to_string())?,
        );
        body.push_str("\n\n");
    }
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .set_write_timeout(Some(HTTP_TIMEOUT))
        .map_err(|_| "D29-H5-C fixture write timeout setup failed".to_string())?;
    stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(body.as_bytes()))
        .map_err(|_| "D29-H5-C fixture response write failed".to_string())
}

fn read_http_request(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    stream
        .set_read_timeout(Some(HTTP_TIMEOUT))
        .map_err(|_| "D29-H5-C fixture read timeout setup failed".to_string())?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8192];
    let header_end = loop {
        let read = stream
            .read(&mut chunk)
            .map_err(|_| "D29-H5-C fixture request read failed".to_string())?;
        if read == 0 {
            return Err("D29-H5-C fixture request closed before headers".to_string());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > HTTP_MAX_BODY {
            return Err("D29-H5-C fixture request exceeded bound".to_string());
        }
        if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8(bytes[..header_end].to_vec())
        .map_err(|_| "D29-H5-C fixture headers were not UTF-8".to_string())?;
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .ok_or_else(|| "D29-H5-C fixture request omitted content length".to_string())?;
    if content_length > HTTP_MAX_BODY || header_end + content_length > HTTP_MAX_BODY {
        return Err("D29-H5-C fixture content length exceeded bound".to_string());
    }
    while bytes.len() < header_end + content_length {
        let read = stream
            .read(&mut chunk)
            .map_err(|_| "D29-H5-C fixture body read failed".to_string())?;
        if read == 0 {
            return Err("D29-H5-C fixture request closed before body".to_string());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > HTTP_MAX_BODY {
            return Err("D29-H5-C fixture body exceeded bound".to_string());
        }
    }
    Ok(bytes[header_end..header_end + content_length].to_vec())
}

fn extract_turn_id(body: &[u8]) -> Option<String> {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.get("client_metadata").cloned())
        .and_then(|value| value.get("turn_id").cloned())
        .and_then(|value| value.as_str().map(str::to_owned))
}

fn function_call_output(body: &[u8], call_id: &str) -> Option<Value> {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.get("input").cloned())
        .and_then(|value| value.as_array().cloned())
        .and_then(|items| {
            items.into_iter().find_map(|item| {
                (item.get("type").and_then(Value::as_str) == Some("function_call_output")
                    && item.get("call_id").and_then(Value::as_str) == Some(call_id))
                .then(|| item.get("output").and_then(Value::as_str))
                .flatten()
                .and_then(|output| serde_json::from_str::<Value>(output).ok())
            })
        })
}

fn exact_replace_tool_schema(body: &[u8]) -> bool {
    let Some(tool) = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value.get("tools").cloned())
        .and_then(|value| value.as_array().cloned())
        .and_then(|tools| {
            tools.into_iter().find(|tool| {
                tool.get("name").and_then(Value::as_str) == Some(VITA_WORKSPACE_REPLACE_TOOL_NAME)
            })
        })
    else {
        return false;
    };
    let parameters = tool.get("parameters").or_else(|| {
        tool.get("function")
            .and_then(|function| function.get("parameters"))
    });
    let Some(parameters) = parameters else {
        return false;
    };
    let Some(properties) = parameters.get("properties").and_then(Value::as_object) else {
        return false;
    };
    let property_names = properties.keys().cloned().collect::<BTreeSet<_>>();
    let required = parameters
        .get("required")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        });
    property_names
        == BTreeSet::from([
            "expected_sha256".to_string(),
            "relative_path".to_string(),
            "replacement_content".to_string(),
        ])
        && required == Some(property_names)
        && parameters
            .get("additionalProperties")
            .and_then(Value::as_bool)
            == Some(false)
        && !output_has_authority_facts(&tool)
}

fn output_has_authority_facts(value: &Value) -> bool {
    const FORBIDDEN: &[&str] = &[
        "grant_id",
        "confirmation_id",
        "authorization_revision",
        "workspace_root_identity",
        "target_identity",
        "journal_integrity_hash",
        "transaction_id",
        "recovery_namespace_path",
        "raw_handle",
        "credentials",
        "raw_preimage",
    ];
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            FORBIDDEN.contains(&key.as_str()) || output_has_authority_facts(value)
        }),
        Value::Array(values) => values.iter().any(output_has_authority_facts),
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownStatus {
    NotAttempted,
    Success,
    TimedOut,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CleanupEvidence {
    initial_shutdown: ShutdownStatus,
    final_shutdown: ShutdownStatus,
    manager_thread_count: usize,
    fixture_listener_joined: bool,
}

struct H5Runtime {
    manager: Arc<ThreadManager>,
    thread: Option<Arc<codex_core_api::CodexThread>>,
    thread_id: Option<ThreadId>,
    fixture: Option<H5ResponsesFixture>,
}

impl H5Runtime {
    async fn shutdown(mut self) -> (CleanupEvidence, H5FixtureObservation) {
        let mut initial_shutdown = ShutdownStatus::NotAttempted;
        let mut final_shutdown = ShutdownStatus::NotAttempted;
        if let Some(thread) = self.thread.take() {
            initial_shutdown =
                match tokio::time::timeout(CLEANUP_TIMEOUT, thread.shutdown_and_wait()).await {
                    Ok(Ok(())) => ShutdownStatus::Success,
                    Ok(Err(_)) => ShutdownStatus::Failed,
                    Err(_) => ShutdownStatus::TimedOut,
                };
            if initial_shutdown != ShutdownStatus::Success {
                let _ = tokio::time::timeout(CLEANUP_TIMEOUT, thread.submit(Op::Interrupt)).await;
            }
            final_shutdown =
                match tokio::time::timeout(CLEANUP_TIMEOUT, thread.shutdown_and_wait()).await {
                    Ok(Ok(())) => ShutdownStatus::Success,
                    Ok(Err(_)) => ShutdownStatus::Failed,
                    Err(_) => ShutdownStatus::TimedOut,
                };
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
        let (observation, fixture_listener_joined) = self
            .fixture
            .take()
            .map(H5ResponsesFixture::shutdown)
            .unwrap_or_else(|| (H5FixtureObservation::default(), true));
        (
            CleanupEvidence {
                initial_shutdown,
                final_shutdown,
                manager_thread_count,
                fixture_listener_joined,
            },
            observation,
        )
    }
}

async fn start_h5_runtime(
    app_data_root: PathBuf,
    workspace_root: PathBuf,
    authority: Arc<dyn VitaH4AuthorityPort>,
    fixture: H5ResponsesFixture,
) -> Result<
    (
        H5Runtime,
        Arc<VitaWorkspaceReplaceBroker>,
        RecoveryJournalStore,
    ),
    String,
> {
    let profile =
        VitaAgentRuntimeProfile::from_explicit_app_data_root(app_data_root, workspace_root)
            .map_err(|error| format!("create D29-H5-C profile: {error}"))?;
    let provider = ProviderProfile::new_for_test_localhost(
        PROVIDER_ID,
        "D29-H5-C local Responses fixture",
        ProviderProtocol::OpenAiResponses,
        fixture.base_url(),
        MODEL,
        None,
        HTTP_TIMEOUT,
        ProviderRetryPolicy::default(),
        ProviderCapabilities {
            tools: true,
            ..ProviderCapabilities::none()
        },
    )
    .map_err(|error| format!("create D29-H5-C provider: {error}"))?;
    let provider_authority = VitaProviderAuthority::configure(provider)
        .map_err(|error| format!("configure D29-H5-C provider: {error}"))?;
    let binding = VitaGatewayBinding::for_owned_private_listener(fixture.address.port())
        .map_err(|error| format!("create D29-H5-C gateway binding: {error}"))?;
    let ready = provider_authority
        .prepare_gateway(binding)
        .map_err(|error| format!("prepare D29-H5-C gateway: {error}"))?;
    let entrypoint = VitaAgentEntrypoint::initialize_with_gateway_for_tests(profile, &ready)
        .await
        .map_err(|error| format!("initialize D29-H5-C Codex config: {error}"))?;
    let config = entrypoint.config().clone();
    let profile = entrypoint.profile().clone();
    let root = profile
        .workspace_authority()
        .cloned()
        .ok_or_else(|| "D29-H5-C requires Windows workspace authority".to_string())?;
    let store = RecoveryJournalStore::from_runtime_profile(&profile)
        .map_err(|error| format!("create D29-H5-C recovery store: {error}"))?;
    let context = VitaExecutionContext::try_new(LIFE_ID, TASK_ID)
        .map_err(|error| format!("create D29-H5-C context: {error:?}"))?;
    let broker = VitaWorkspaceReplaceBroker::new(context, root, authority);
    let mut extensions =
        codex_core_api::ExtensionRegistryBuilder::<codex_core::config::Config>::new();
    extensions.tool_contributor(Arc::new(VitaWorkspaceReplaceH5ToolContributor::new(
        Arc::clone(&broker),
        store.clone(),
    )));
    let extensions = Arc::new(extensions.build());
    let auth_manager = codex_core::test_support::auth_manager_from_auth_with_home(
        CodexAuth::from_api_key("d29h5-c-in-memory-kernel-auth"),
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
        "d29h5-c-local-installation".to_string(),
        None,
        None,
    ));
    let new_thread = tokio::time::timeout(
        TURN_TIMEOUT,
        manager.start_thread(StartThreadOptions::new(config)),
    )
    .await
    .map_err(|_| "D29-H5-C thread startup timed out".to_string())?
    .map_err(|error| format!("D29-H5-C thread startup failed: {error}"))?;
    Ok((
        H5Runtime {
            manager,
            thread: Some(new_thread.thread),
            thread_id: Some(new_thread.thread_id),
            fixture: Some(fixture),
        },
        broker,
        store,
    ))
}

async fn start_turn(thread: &Arc<codex_core_api::CodexThread>) -> Result<String, String> {
    let submission = tokio::time::timeout(
        TURN_TIMEOUT,
        thread.start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: PROMPT.to_string(),
            text_elements: Vec::new(),
        }])),
    )
    .await
    .map_err(|_| "D29-H5-C turn submission timed out".to_string())?
    .map_err(|error| format!("D29-H5-C turn submission failed: {error}"))?;
    match submission {
        TurnInputSubmission::Started { turn_id } | TurnInputSubmission::Steered { turn_id } => {
            Ok(turn_id)
        }
        TurnInputSubmission::NotSubmitted { reason } => {
            Err(format!("D29-H5-C turn was not submitted: {reason:?}"))
        }
    }
}

async fn wait_turn(
    thread: &Arc<codex_core_api::CodexThread>,
) -> Result<(Option<String>, Option<String>, usize), String> {
    let deadline = Instant::now() + TURN_TIMEOUT;
    let mut event_count = 0usize;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("D29-H5-C turn did not reach terminal event".to_string());
        }
        let event = tokio::time::timeout(remaining, thread.next_event())
            .await
            .map_err(|_| "D29-H5-C event wait timed out".to_string())?
            .map_err(|error| format!("D29-H5-C event stream failed: {error}"))?;
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

fn run_test_body<F>(body: F)
where
    F: FnOnce() + Send + 'static,
{
    thread::Builder::new()
        .name("d29h5-c-real-codex".to_string())
        .stack_size(TEST_STACK_SIZE)
        .spawn(body)
        .expect("D29-H5-C test thread should start")
        .join()
        .expect("D29-H5-C test thread should finish");
}

fn h4_confirmation_request(
    broker: &VitaWorkspaceReplaceBroker,
    turn_id: &str,
    original: &str,
    replacement: &str,
) -> Result<crate::d29h4::H4AuthorityRequest, String> {
    broker
        .h5_authority_request_for_test_intent(
            CALL_ID,
            turn_id,
            RELATIVE_PATH,
            &sha256_hex(original.as_bytes()),
            replacement,
        )
        .map_err(|classification| format!("H4 intent build denied: {}", classification.as_str()))
}

async fn real_codex_h5_positive_body() {
    let app_data = tempdir().expect("D29-H5-C app-data temp root");
    let workspace = tempdir().expect("D29-H5-C workspace temp root");
    let file_path = workspace.path().join(RELATIVE_PATH);
    fs::write(&file_path, ORIGINAL.as_bytes()).expect("D29-H5-C original file write");
    let root = crate::TrustedWorkspaceRoot::acquire(workspace.path())
        .expect("D29-H5-C workspace root acquisition");
    let authority = ProcessIsolatedH4Authority::new(root.identity())
        .expect("D29-H5-C ProcessIsolated H4 authority");
    drop(root);
    let fixture = H5ResponsesFixture::start();
    let (runtime, broker, store) = start_h5_runtime(
        app_data.path().to_path_buf(),
        workspace.path().to_path_buf(),
        Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>,
        fixture,
    )
    .await
    .expect("D29-H5-C runtime should start");
    let turn_id = start_turn(runtime.thread.as_ref().unwrap())
        .await
        .expect("D29-H5-C positive turn should start");
    let observed_turn_id = runtime
        .fixture
        .as_ref()
        .unwrap()
        .wait_for_turn_id()
        .await
        .expect("D29-H5-C fixture should expose turn id");
    assert_eq!(observed_turn_id, turn_id);
    let request = h4_confirmation_request(&broker, &turn_id, ORIGINAL, REPLACEMENT)
        .expect("D29-H5-C exact H4 intent");
    authority
        .provision_confirmation(&request)
        .expect("D29-H5-C independent H4 confirmation");
    runtime.fixture.as_ref().unwrap().release();
    let turn = wait_turn(runtime.thread.as_ref().unwrap())
        .await
        .expect("D29-H5-C positive turn should complete");
    let (cleanup, observation) = runtime.shutdown().await;
    assert!(authority.shutdown());

    assert_eq!(turn.1, None, "real Codex turn error");
    assert_eq!(turn.0.as_deref(), Some(REPLY));
    assert_eq!(fs::read(&file_path).unwrap(), REPLACEMENT.as_bytes());
    assert_eq!(observation.request_count, 2);
    assert!(observation.first_request_schema_exact);
    assert_eq!(
        observation.initial_turn_id.as_deref(),
        Some(turn_id.as_str())
    );
    let output = observation
        .function_call_output
        .as_ref()
        .expect("D29-H5-C function_call_output");
    assert_eq!(
        output.get("status").and_then(Value::as_str),
        Some("committed")
    );
    assert_eq!(
        output.get("mutation_performed").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        output.get("side_effect_count").and_then(Value::as_u64),
        Some(1)
    );
    assert!(!observation.output_has_authority_facts);
    assert!(
        observation.error.is_none(),
        "fixture error: {:?}",
        observation.error
    );
    assert_eq!(cleanup.initial_shutdown, ShutdownStatus::Success);
    assert_eq!(cleanup.final_shutdown, ShutdownStatus::Success);
    assert_eq!(cleanup.manager_thread_count, 0);
    assert!(cleanup.fixture_listener_joined);

    let scan = store.scan_transactions().expect("scan positive H5 journal");
    assert_eq!(scan.valid_transactions().count(), 1);
    assert_eq!(
        scan.valid_transactions().next().unwrap().state(),
        RecoveryTransactionState::CommittedTerminal
    );
    let snapshot = broker.snapshot();
    assert_eq!(snapshot.grants_issued, 1);
    assert_eq!(snapshot.confirmations_consumed, 1);
    assert_eq!(snapshot.automatic_mutation_retries, 0);
    assert_eq!(snapshot.external_network_requests, 0);
    assert_eq!(
        authority.observation_count(),
        2,
        "H4 issue plus final revalidation"
    );
    let provenance = authority.provenance_snapshot();
    assert_eq!(provenance.trusted_confirmations_provisioned, 1);
    assert_eq!(provenance.request_derived_confirmations, 0);
}

#[test]
fn real_codex_h5_committed_canary() {
    run_test_body(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("D29-H5-C runtime");
        runtime.block_on(real_codex_h5_positive_body());
    });
}

async fn real_codex_h5_without_confirmation_body() {
    let app_data = tempdir().expect("D29-H5-C negative app-data temp root");
    let workspace = tempdir().expect("D29-H5-C negative workspace temp root");
    let file_path = workspace.path().join(RELATIVE_PATH);
    fs::write(&file_path, ORIGINAL.as_bytes()).expect("D29-H5-C negative original file");
    let root =
        crate::TrustedWorkspaceRoot::acquire(workspace.path()).expect("D29-H5-C negative root");
    let authority = ProcessIsolatedH4Authority::new(root.identity())
        .expect("D29-H5-C negative ProcessIsolated H4 authority");
    drop(root);
    let fixture = H5ResponsesFixture::start();
    let (runtime, broker, store) = start_h5_runtime(
        app_data.path().to_path_buf(),
        workspace.path().to_path_buf(),
        Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>,
        fixture,
    )
    .await
    .expect("D29-H5-C negative runtime");
    let turn_id = start_turn(runtime.thread.as_ref().unwrap())
        .await
        .expect("D29-H5-C negative turn");
    let observed_turn_id = runtime
        .fixture
        .as_ref()
        .unwrap()
        .wait_for_turn_id()
        .await
        .unwrap();
    assert_eq!(observed_turn_id, turn_id);
    runtime.fixture.as_ref().unwrap().release();
    let turn = wait_turn(runtime.thread.as_ref().unwrap())
        .await
        .expect("D29-H5-C negative turn completion");
    let (cleanup, observation) = runtime.shutdown().await;
    assert!(authority.shutdown());

    assert_eq!(turn.1, None);
    assert_eq!(fs::read(&file_path).unwrap(), ORIGINAL.as_bytes());
    let output = observation.function_call_output.as_ref().unwrap();
    assert_eq!(output.get("status").and_then(Value::as_str), Some("denied"));
    assert_eq!(
        output.get("mutation_performed").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        output.get("side_effect_count").and_then(Value::as_u64),
        Some(0)
    );
    assert!(!observation.output_has_authority_facts);
    assert_eq!(broker.snapshot().grants_issued, 0);
    assert_eq!(
        store
            .scan_transactions()
            .unwrap()
            .valid_transactions()
            .count(),
        0
    );
    assert_eq!(cleanup.manager_thread_count, 0);
    assert!(cleanup.fixture_listener_joined);
    let provenance = authority.provenance_snapshot();
    assert_eq!(provenance.trusted_confirmations_provisioned, 0);
    assert_eq!(provenance.request_derived_confirmations, 0);
}

#[test]
fn real_codex_h5_without_confirmation_mutates_zero() {
    run_test_body(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("D29-H5-C negative runtime");
        runtime.block_on(real_codex_h5_without_confirmation_body());
    });
}

#[test]
fn real_codex_h5_cancellation_before_mutation_mutates_zero() {
    run_test_body(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("D29-H5-C cancellation runtime");
        runtime.block_on(async {
            let app_data = tempdir().expect("D29-H5-C cancellation app-data");
            let workspace = tempdir().expect("D29-H5-C cancellation workspace");
            let file_path = workspace.path().join(RELATIVE_PATH);
            fs::write(&file_path, ORIGINAL.as_bytes()).expect("D29-H5-C cancellation file");
            let root = crate::TrustedWorkspaceRoot::acquire(workspace.path())
                .expect("D29-H5-C cancellation root");
            let authority = ProcessIsolatedH4Authority::new(root.identity())
                .expect("D29-H5-C cancellation H4 authority");
            drop(root);
            let fixture = H5ResponsesFixture::start();
            let (runtime, broker, store) = start_h5_runtime(
                app_data.path().to_path_buf(),
                workspace.path().to_path_buf(),
                Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>,
                fixture,
            )
            .await
            .expect("D29-H5-C cancellation runtime");
            let turn_id = start_turn(runtime.thread.as_ref().unwrap())
                .await
                .expect("D29-H5-C cancellation turn");
            assert_eq!(
                runtime
                    .fixture
                    .as_ref()
                    .unwrap()
                    .wait_for_turn_id()
                    .await
                    .unwrap(),
                turn_id
            );
            broker.cancel();
            runtime.fixture.as_ref().unwrap().release();
            let turn = wait_turn(runtime.thread.as_ref().unwrap())
                .await
                .expect("D29-H5-C cancellation turn completion");
            let (cleanup, observation) = runtime.shutdown().await;
            assert!(authority.shutdown());
            assert_eq!(turn.1, None);
            assert_eq!(fs::read(&file_path).unwrap(), ORIGINAL.as_bytes());
            assert_eq!(
                observation.function_call_output.unwrap()["status"],
                "denied"
            );
            assert!(!observation.output_has_authority_facts);
            assert_eq!(
                store
                    .scan_transactions()
                    .unwrap()
                    .valid_transactions()
                    .count(),
                0
            );
            assert_eq!(broker.snapshot().filesystem_mutation_attempts, 0);
            assert_eq!(
                authority
                    .provenance_snapshot()
                    .trusted_confirmations_provisioned,
                0
            );
            assert_eq!(cleanup.manager_thread_count, 0);
            assert!(cleanup.fixture_listener_joined);
        });
    });
}

#[test]
fn real_codex_h5_output_exposes_no_authority_facts() {
    run_test_body(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("D29-H5-C output runtime");
        runtime.block_on(real_codex_h5_positive_body());
    });
}

#[test]
fn h5c_crash_child_entrypoint() {
    if std::env::var_os("D29_H5C_CRASH_POINT").is_none() {
        return;
    }
    run_test_body(|| {
        let app_data = PathBuf::from(
            std::env::var_os("D29_H5C_CRASH_APP_DATA").expect("D29-H5-C child app-data root"),
        );
        let workspace = PathBuf::from(
            std::env::var_os("D29_H5C_CRASH_WORKSPACE").expect("D29-H5-C child workspace root"),
        );
        fs::write(workspace.join(RELATIVE_PATH), CRASH_ORIGINAL.as_bytes())
            .expect("D29-H5-C child original file");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("D29-H5-C child runtime");
        runtime.block_on(async move {
            let root =
                crate::TrustedWorkspaceRoot::acquire(&workspace).expect("D29-H5-C child root");
            let authority = crate::d29h4::tests::TestHostAuthority::new(root.identity());
            drop(root);
            let fixture =
                H5ResponsesFixture::start_with_contents(CRASH_ORIGINAL, CRASH_REPLACEMENT);
            let (runtime, broker, _store) = start_h5_runtime(
                app_data,
                workspace,
                Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>,
                fixture,
            )
            .await
            .expect("D29-H5-C child runtime setup");
            let turn_id = start_turn(runtime.thread.as_ref().unwrap())
                .await
                .expect("D29-H5-C child turn");
            let observed_turn_id = runtime
                .fixture
                .as_ref()
                .unwrap()
                .wait_for_turn_id()
                .await
                .expect("D29-H5-C child fixture turn id");
            assert_eq!(observed_turn_id, turn_id);
            let request =
                h4_confirmation_request(&broker, &turn_id, CRASH_ORIGINAL, CRASH_REPLACEMENT)
                    .expect("D29-H5-C child exact H4 intent");
            authority.provision_trusted_confirmation(&request);
            runtime.fixture.as_ref().unwrap().release();
            let _ = wait_turn(runtime.thread.as_ref().unwrap()).await;
            std::process::abort();
        });
    });
}

fn restart_profile_and_store(
    app_data: &PathBuf,
    workspace: &PathBuf,
) -> (
    VitaAgentRuntimeProfile,
    RecoveryJournalStore,
    crate::TrustedWorkspaceRoot,
) {
    let profile =
        VitaAgentRuntimeProfile::from_explicit_app_data_root(app_data.clone(), workspace.clone())
            .expect("D29-H5-C fresh runtime profile");
    let root = profile
        .workspace_authority()
        .cloned()
        .expect("D29-H5-C fresh workspace authority");
    let store = RecoveryJournalStore::from_runtime_profile(&profile)
        .expect("D29-H5-C fresh RecoveryJournalStore");
    (profile, store, root)
}

fn recover_with_fresh_process_authority(
    store: RecoveryJournalStore,
    root: crate::TrustedWorkspaceRoot,
    snapshot: crate::recovery_journal::RecoveryTransactionSnapshot,
    current: &[u8],
) -> RecoveryExecutionOutcome {
    let action =
        RecoveryActionRequest::from_snapshot(&snapshot, current, "d29h5-c-fresh-recovery", 2);
    let single_use_authority =
        ProcessIsolatedH5RecoveryAuthority::new(root.identity(), LIFE_ID, TASK_ID)
            .expect("D29-H5-C ProcessIsolated H5 single-use authority");
    single_use_authority
        .provision_trusted_confirmation(&action)
        .expect("D29-H5-C single-use trusted confirmation");
    let grant = single_use_authority
        .issue_recovery_grant(&action)
        .expect("D29-H5-C fresh recovery grant");
    single_use_authority
        .revalidate_recovery_grant(&grant, &action)
        .expect("D29-H5-C first recovery grant use");
    let replay = single_use_authority.revalidate_recovery_grant(&grant, &action);
    assert!(
        replay.is_err(),
        "second recovery grant use was accepted: {replay:?}"
    );
    assert_eq!(single_use_authority.provenance(), (1, 0));
    assert!(single_use_authority.shutdown());

    let recovery_authority =
        ProcessIsolatedH5RecoveryAuthority::new(root.identity(), LIFE_ID, TASK_ID)
            .expect("D29-H5-C ProcessIsolated H5 recovery authority");
    recovery_authority
        .provision_trusted_confirmation(&action)
        .expect("D29-H5-C fresh trusted recovery confirmation");
    let executor = H5RecoveryExecutor::new(
        store,
        root,
        Arc::clone(&recovery_authority) as Arc<dyn RecoveryAuthorityPort>,
    );
    let result = executor.recover(action);
    assert_eq!(result.grant_issued, true);
    assert_eq!(result.mutation_count, 1);
    assert_eq!(result.marker_persisted, true);
    assert_eq!(recovery_authority.provenance(), (1, 0));
    assert!(recovery_authority.shutdown());
    result.outcome
}

fn assert_terminal_cannot_issue_recovery_grant(
    store: RecoveryJournalStore,
    root: crate::TrustedWorkspaceRoot,
    snapshot: crate::recovery_journal::RecoveryTransactionSnapshot,
    current: &[u8],
) {
    let action = RecoveryActionRequest::from_snapshot(
        &snapshot,
        current,
        "d29h5-c-terminal-recovery-attempt",
        2,
    );
    let authority = ProcessIsolatedH5RecoveryAuthority::new(root.identity(), LIFE_ID, TASK_ID)
        .expect("D29-H5-C terminal recovery authority");
    authority
        .provision_trusted_confirmation(&action)
        .expect("D29-H5-C terminal independent confirmation");
    let executor = H5RecoveryExecutor::new(
        store,
        root,
        Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
    );
    let result = executor.recover(action);
    assert!(!result.grant_issued);
    assert_eq!(result.mutation_count, 0);
    assert_eq!(result.marker_persisted, false);
    assert!(matches!(
        result.outcome,
        RecoveryExecutionOutcome::RecoveryDenied(_)
    ));
    assert_eq!(authority.provenance(), (1, 0));
    assert!(authority.shutdown());
}

fn run_h5c_crash_case(point: &str) {
    let app_data = tempdir().expect("D29-H5-C crash app-data temp root");
    let workspace = tempdir().expect("D29-H5-C crash workspace temp root");
    let status = Command::new(std::env::current_exe().expect("D29-H5-C current test executable"))
        .args([
            "--exact",
            "d29h5c::h5c_crash_child_entrypoint",
            "--nocapture",
        ])
        .env("D29_H5C_CRASH_POINT", point)
        .env("D29_H5C_CRASH_APP_DATA", app_data.path())
        .env("D29_H5C_CRASH_WORKSPACE", workspace.path())
        .status()
        .expect("spawn D29-H5-C crash child");
    assert!(!status.success(), "D29-H5-C crash point {point} must abort");

    let app_data_path = app_data.path().to_path_buf();
    let workspace_path = workspace.path().to_path_buf();
    let (_profile, store, root) = restart_profile_and_store(&app_data_path, &workspace_path);
    let file_path = workspace_path.join(RELATIVE_PATH);
    let before_scan = fs::read(&file_path).expect("D29-H5-C crash file after restart");
    let scan = store.scan_transactions().expect("D29-H5-C restart scan");
    let after_scan = fs::read(&file_path).expect("D29-H5-C file after restart scan");
    assert_eq!(
        before_scan, after_scan,
        "restart scan must not mutate workspace"
    );
    let snapshot = scan
        .valid_transactions()
        .next()
        .cloned()
        .expect("D29-H5-C crash should leave one valid journal");

    match point {
        "prepared" => {
            assert_eq!(snapshot.state(), RecoveryTransactionState::PreparedOnly);
            assert_eq!(before_scan, CRASH_ORIGINAL.as_bytes());
            assert_eq!(
                store
                    .scan_transactions()
                    .unwrap()
                    .actionable_recovery_transactions()
                    .count(),
                0
            );
        }
        "started" => {
            assert_eq!(snapshot.state(), RecoveryTransactionState::RecoveryRequired);
            assert_eq!(before_scan, CRASH_ORIGINAL.as_bytes());
            assert_eq!(
                store
                    .scan_transactions()
                    .unwrap()
                    .actionable_recovery_transactions()
                    .count(),
                1
            );
        }
        "first-mutation" => {
            assert_eq!(snapshot.state(), RecoveryTransactionState::RecoveryRequired);
            assert_ne!(before_scan, CRASH_ORIGINAL.as_bytes());
            assert!(std::str::from_utf8(&before_scan).is_err());
            let outcome = recover_with_fresh_process_authority(
                store.clone(),
                root.clone(),
                snapshot,
                &before_scan,
            );
            assert_eq!(outcome, RecoveryExecutionOutcome::Recovered);
            assert_eq!(fs::read(&file_path).unwrap(), CRASH_ORIGINAL.as_bytes());
            let recovered_scan = store.scan_transactions().unwrap();
            assert_eq!(
                recovered_scan.valid_transactions().next().unwrap().state(),
                RecoveryTransactionState::RecoveredTerminal
            );
            assert_eq!(recovered_scan.actionable_recovery_transactions().count(), 0);
        }
        "before-marker" => {
            assert_eq!(snapshot.state(), RecoveryTransactionState::RecoveryRequired);
            assert_eq!(before_scan, CRASH_REPLACEMENT.as_bytes());
            assert_eq!(
                store
                    .scan_transactions()
                    .unwrap()
                    .actionable_recovery_transactions()
                    .count(),
                1
            );
        }
        "after-marker" => {
            assert_eq!(
                snapshot.state(),
                RecoveryTransactionState::CommittedTerminal
            );
            assert_eq!(before_scan, CRASH_REPLACEMENT.as_bytes());
            assert_eq!(
                store
                    .scan_transactions()
                    .unwrap()
                    .actionable_recovery_transactions()
                    .count(),
                0
            );
            assert_terminal_cannot_issue_recovery_grant(
                store.clone(),
                root.clone(),
                snapshot,
                &before_scan,
            );
            assert_eq!(fs::read(&file_path).unwrap(), CRASH_REPLACEMENT.as_bytes());
        }
        other => panic!("unknown D29-H5-C crash point {other}"),
    }
}

#[test]
fn real_codex_crash_after_started_before_mutation_restart_safe() {
    run_h5c_crash_case("started");
}

#[test]
fn real_codex_crash_after_first_mutation_requires_fresh_recovery() {
    run_h5c_crash_case("first-mutation");
}

#[test]
fn real_codex_crash_invalid_utf8_partial_restores_exact_preimage() {
    run_h5c_crash_case("first-mutation");
}

#[test]
fn real_codex_crash_after_native_commit_before_marker_has_no_false_commit() {
    run_h5c_crash_case("before-marker");
}

#[test]
fn real_codex_crash_after_commit_marker_is_terminal() {
    run_h5c_crash_case("after-marker");
}

#[test]
fn real_codex_crash_after_prepared_is_not_actionable() {
    run_h5c_crash_case("prepared");
}

#[test]
fn restart_scan_never_auto_recovers() {
    run_h5c_crash_case("started");
}
