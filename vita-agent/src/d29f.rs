//! D29-F's first real pinned-Codex turn proof.
//!
//! This module is test-scoped on purpose.  It owns both loopback listeners,
//! compiles the D29-E derived provider into the upstream `Config`, and then
//! drives the public `ThreadManager`/`CodexThread` APIs.  There is no external
//! provider transport or production listener in this candidate.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
};

use codex_core_api::{
    CodexAppsToolsCache, CodexAuth, EnvironmentManager, EventMsg, Op, SessionSource,
    StartThreadOptions, ThreadId, ThreadManager, TurnInputRequest, UserInput,
};
use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};

use super::{
    CredentialRef, CredentialResolver, GatewayReadyProvider, ProviderCapabilities,
    ProviderEndpoint, ProviderGateway, ProviderProfile, ProviderProtocol, ProviderRequestTransport,
    ProviderRetryPolicy, VitaAgentError, VitaGatewayBinding, VitaMessage, VitaMessageRole,
    VitaProviderState, VitaResponsesRequest, VitaResponsesRequestOptions,
};

use crate::{
    VitaAgentEntrypoint, VitaAgentRuntimeProfile, VITA_AGENT_RUNTIME_ID, VITA_GATEWAY_PROVIDER_ID,
};

const D29F_MODEL: &str = "d29f-mock-model";
const D29F_PROMPT: &str = "Reply exactly with VITA_D29F_OK.";
const D29F_REPLY: &str = "VITA_D29F_OK";
const D29F_CREDENTIAL: &str = "d29f-in-memory-provider-credential";
const D29F_PROVIDER_ID: &str = "d29f-local-chat-mock";
const D29F_REQUEST_TIMEOUT: Duration = Duration::from_millis(250);
const D29F_TURN_TIMEOUT: Duration = Duration::from_secs(5);
const D29F_TRUE_TURN_DEADLINE: Duration = Duration::from_millis(900);
const D29F_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const D29F_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(100);
const D29F_HTTP_MAX_BODY: usize = 2 * 1024 * 1024;
const D29F_TEST_STACK_SIZE: usize = 32 * 1024 * 1024;

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
        formatter.write_str("HostCanary(<redacted>)")
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

fn canary_unchanged_result(before: &HostCanary, after: &HostCanary) -> Result<(), &'static str> {
    if before.parent_environment_fingerprint != after.parent_environment_fingerprint {
        return Err("parent environment changed");
    }
    if before.user_codex_state != after.user_codex_state {
        return Err("user Codex state changed");
    }
    Ok(())
}

fn assert_canary_unchanged(before: &HostCanary, after: &HostCanary) {
    if let Err(error) = canary_unchanged_result(before, after) {
        panic!("{error}");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponsesFieldHandling {
    Absent,
    EmptyObjectInert,
    DefaultSummaryAutoInert,
    SequentialCutoffInert,
}

impl Default for ResponsesFieldHandling {
    fn default() -> Self {
        Self::Absent
    }
}

impl ResponsesFieldHandling {
    fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::EmptyObjectInert => "empty-object-inert",
            Self::DefaultSummaryAutoInert => "default-summary-auto-inert",
            Self::SequentialCutoffInert => "sequential-cutoff-inert",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChatMockMode {
    Success,
    MalformedBody,
    UnexpectedToolCall,
    Delayed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GatewayResponseMode {
    Normal,
    HoldTerminalResponse,
}

#[derive(Debug, Default, Clone)]
struct HttpObservation {
    bind: Option<String>,
    request_count: usize,
    method: Option<String>,
    target: Option<String>,
    authorization_present: bool,
    authorization_matches: bool,
    body: Option<Value>,
    error: Option<String>,
}

#[derive(Debug, Default, Clone)]
struct GatewayObservation {
    bind: Option<String>,
    request_count: usize,
    peer_is_loopback: bool,
    method: Option<String>,
    target: Option<String>,
    codex_authorization_present: bool,
    request_model: Option<String>,
    input_item_types: Vec<String>,
    message_texts: Vec<String>,
    parallel_tool_calls: Option<bool>,
    reasoning_handling: ResponsesFieldHandling,
    stream_options_handling: ResponsesFieldHandling,
    text_handling: ResponsesFieldHandling,
    response_path: Option<String>,
    terminal_response_emitted: bool,
    bridge_error: Option<String>,
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

struct LocalChatMock {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    observation: Arc<Mutex<HttpObservation>>,
    join: Option<JoinHandle<()>>,
}

impl LocalChatMock {
    fn start(mode: ChatMockMode) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind D29-F Chat mock");
        let address = listener.local_addr().expect("Chat mock address");
        listener
            .set_nonblocking(true)
            .expect("set Chat mock listener nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let observation = Arc::new(Mutex::new(HttpObservation {
            bind: Some(format!("127.0.0.1:{}", address.port())),
            ..HttpObservation::default()
        }));
        let stop_for_thread = Arc::clone(&stop);
        let observation_for_thread = Arc::clone(&observation);

        let join = thread::spawn(move || {
            let deadline = Instant::now() + D29F_TURN_TIMEOUT;
            loop {
                if stop_for_thread.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return;
                }
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        let result = handle_chat_request(&mut stream, peer, mode);
                        let mut observed = observation_for_thread
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        observed.request_count = observed.request_count.saturating_add(1);
                        match result {
                            Ok(request) => {
                                let authorization_present =
                                    request.header("authorization").is_some();
                                let authorization_matches =
                                    request.header("authorization").is_some_and(|value| {
                                        value == format!("Bearer {D29F_CREDENTIAL}")
                                    });
                                observed.method = Some(request.method);
                                observed.target = Some(request.target);
                                observed.authorization_present = authorization_present;
                                observed.authorization_matches = authorization_matches;
                                observed.body = serde_json::from_slice(&request.body).ok();
                            }
                            Err(error) => observed.error = Some(error),
                        }
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => {
                        observation_for_thread
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .error = Some(format!("Chat mock accept failed: {error}"));
                        return;
                    }
                }
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

    fn shutdown(mut self) -> (HttpObservation, bool) {
        self.stop.store(true, Ordering::Release);
        wake_loopback_listener(self.address);
        let joined = match self.join.take() {
            Some(join) => join_listener_thread(join),
            None => true,
        };
        let observation = self
            .observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        (observation, joined)
    }
}

impl Drop for LocalChatMock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        wake_loopback_listener(self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct VitaGatewayServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    observation: Arc<Mutex<GatewayObservation>>,
    join: Option<JoinHandle<()>>,
}

impl VitaGatewayServer {
    fn start(
        listener: TcpListener,
        ready: GatewayReadyProvider,
        response_mode: GatewayResponseMode,
    ) -> Self {
        let address = listener.local_addr().expect("Vita gateway address");
        listener
            .set_nonblocking(true)
            .expect("set Vita gateway listener nonblocking");

        let stop = Arc::new(AtomicBool::new(false));
        let observation = Arc::new(Mutex::new(GatewayObservation {
            bind: Some(format!("127.0.0.1:{}", address.port())),
            ..GatewayObservation::default()
        }));
        let stop_for_thread = Arc::clone(&stop);
        let observation_for_thread = Arc::clone(&observation);
        let credential_reference = ready
            .profile()
            .credential_ref()
            .cloned()
            .expect("D29-F gateway profile credential reference");
        let gateway = ProviderGateway::new(
            ready,
            D29fCredentialResolver {
                reference: credential_reference,
            },
            D29fTcpLocalTransport,
        );

        let join = thread::spawn(move || {
            let deadline = Instant::now() + D29F_TURN_TIMEOUT;
            loop {
                if stop_for_thread.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return;
                }
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        let mut observed = observation_for_thread
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        observed.request_count = observed.request_count.saturating_add(1);
                        observed.peer_is_loopback = peer.ip().is_loopback();
                        drop(observed);

                        handle_gateway_request(
                            &mut stream,
                            peer,
                            &gateway,
                            &observation_for_thread,
                            response_mode,
                            &stop_for_thread,
                        );
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => {
                        observation_for_thread
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .bridge_error = Some(format!("Vita gateway accept failed: {error}"));
                        return;
                    }
                }
            }
        });

        Self {
            address,
            stop,
            observation,
            join: Some(join),
        }
    }

    fn shutdown(mut self) -> (GatewayObservation, bool) {
        self.stop.store(true, Ordering::Release);
        wake_loopback_listener(self.address);
        let joined = match self.join.take() {
            Some(join) => join_listener_thread(join),
            None => true,
        };
        let observation = self
            .observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        (observation, joined)
    }
}

impl Drop for VitaGatewayServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        wake_loopback_listener(self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[derive(Debug, Default, Clone)]
struct ParsedResponsesRequest {
    request: Option<VitaResponsesRequest>,
    model: Option<String>,
    input_item_types: Vec<String>,
    message_texts: Vec<String>,
    parallel_tool_calls: Option<bool>,
    reasoning_handling: ResponsesFieldHandling,
    stream_options_handling: ResponsesFieldHandling,
    text_handling: ResponsesFieldHandling,
}

fn handle_gateway_request(
    stream: &mut TcpStream,
    peer: SocketAddr,
    gateway: &ProviderGateway<D29fCredentialResolver, D29fTcpLocalTransport>,
    observation: &Arc<Mutex<GatewayObservation>>,
    response_mode: GatewayResponseMode,
    stop: &Arc<AtomicBool>,
) {
    let request = match read_http_request(stream) {
        Ok(request) => request,
        Err(error) => {
            set_gateway_error(observation, error);
            let _ = write_http_response(stream, "400 Bad Request", "text/plain", b"bad request");
            return;
        }
    };
    {
        let mut observed = observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        observed.method = Some(request.method.clone());
        observed.target = Some(request.target.clone());
        observed.codex_authorization_present = request.header("authorization").is_some();
    }

    if !peer.ip().is_loopback() {
        set_gateway_error(
            observation,
            "Vita gateway received a non-loopback peer".to_string(),
        );
        let _ = write_http_response(stream, "403 Forbidden", "text/plain", b"loopback only");
        return;
    }
    if request.method != "POST" || request.target != "/v1/responses" {
        set_gateway_error(
            observation,
            format!(
                "unexpected Vita gateway request target: {} {}",
                request.method, request.target
            ),
        );
        let _ = write_http_response(stream, "404 Not Found", "text/plain", b"unsupported path");
        return;
    }

    let parsed = match parse_codex_responses_request(&request.body) {
        Ok(parsed) => parsed,
        Err(error) => {
            set_gateway_error(observation, error.clone());
            let _ = write_failed_responses(stream, &error);
            return;
        }
    };
    {
        let mut observed = observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        observed.request_model = parsed.model.clone();
        observed.input_item_types = parsed.input_item_types.clone();
        observed.message_texts = parsed.message_texts.clone();
        observed.parallel_tool_calls = parsed.parallel_tool_calls;
        observed.reasoning_handling = parsed.reasoning_handling;
        observed.stream_options_handling = parsed.stream_options_handling;
        observed.text_handling = parsed.text_handling;
    }

    let Some(parsed_request) = parsed.request.as_ref() else {
        let error = "D29-F Responses request parser produced no request";
        set_gateway_error(observation, error.to_string());
        let _ = write_failed_responses(stream, error);
        return;
    };
    match gateway.execute_responses_request(parsed_request) {
        Ok(result) => {
            let response_path = match response_mode {
                GatewayResponseMode::Normal => "responses-sse",
                GatewayResponseMode::HoldTerminalResponse => "responses-sse-held",
            };
            set_gateway_response_path(observation, response_path);
            let response = match response_mode {
                GatewayResponseMode::Normal => write_success_responses(stream, &result),
                GatewayResponseMode::HoldTerminalResponse => {
                    write_held_responses(stream, &result, stop)
                }
            };
            if response.is_ok() && response_mode == GatewayResponseMode::Normal {
                set_gateway_terminal_response_emitted(observation, true);
            }
            if let Err(error) = response {
                set_gateway_error(observation, error);
            }
        }
        Err(error) => {
            let error_text = error.to_string();
            set_gateway_error(observation, error_text.clone());
            let _ = write_failed_responses(stream, &error_text);
        }
    }
}

fn handle_chat_request(
    stream: &mut TcpStream,
    peer: SocketAddr,
    mode: ChatMockMode,
) -> Result<HttpRequest, String> {
    if !peer.ip().is_loopback() {
        return Err("Chat mock received a non-loopback peer".to_string());
    }
    let request = read_http_request(stream)?;
    if request.method != "POST" || request.target != "/v1/chat/completions" {
        return Err(format!(
            "unexpected Chat mock request target: {} {}",
            request.method, request.target
        ));
    }

    match mode {
        ChatMockMode::MalformedBody => {
            write_http_response(stream, "200 OK", "application/json", b"not-json")?;
        }
        ChatMockMode::UnexpectedToolCall => {
            let body = serde_json::to_vec(&json!({
                "id": "chatcmpl-d29f-tool",
                "model": D29F_MODEL,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": "call-d29f",
                            "type": "function",
                            "function": {"name": "unexpected", "arguments": "{}"}
                        }]
                    },
                    "finish_reason": "tool_calls"
                }]
            }))
            .map_err(|error| format!("serialize tool-call mock response: {error}"))?;
            write_http_response(stream, "200 OK", "application/json", &body)?;
        }
        ChatMockMode::Success | ChatMockMode::Delayed => {
            if mode == ChatMockMode::Delayed {
                let deadline = Instant::now() + D29F_REQUEST_TIMEOUT + Duration::from_millis(300);
                while Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(10));
                }
            }
            let body = serde_json::to_vec(&json!({
                "id": "chatcmpl-d29f",
                "model": D29F_MODEL,
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": D29F_REPLY},
                    "finish_reason": "stop"
                }],
                "usage": {
                    "prompt_tokens": 7,
                    "completion_tokens": 1,
                    "total_tokens": 8
                }
            }))
            .map_err(|error| format!("serialize Chat mock response: {error}"))?;
            let _ = write_http_response(stream, "200 OK", "application/json", &body);
        }
    }
    Ok(request)
}

fn set_gateway_error(observation: &Arc<Mutex<GatewayObservation>>, error: String) {
    observation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .bridge_error = Some(error);
}

fn set_gateway_response_path(observation: &Arc<Mutex<GatewayObservation>>, path: &str) {
    observation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .response_path = Some(path.to_string());
}

fn set_gateway_terminal_response_emitted(
    observation: &Arc<Mutex<GatewayObservation>>,
    emitted: bool,
) {
    observation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .terminal_response_emitted = emitted;
}

fn parse_codex_responses_request(body: &[u8]) -> Result<ParsedResponsesRequest, String> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|error| format!("malformed Codex Responses request JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| "Codex Responses request must be a JSON object".to_string())?;

    const ALLOWED_FIELDS: &[&str] = &[
        "model",
        "instructions",
        "input",
        "tools",
        "tool_choice",
        "parallel_tool_calls",
        "reasoning",
        "store",
        "stream",
        "stream_options",
        "include",
        "service_tier",
        "prompt_cache_key",
        "text",
        "client_metadata",
        "access_programs",
    ];
    for key in object.keys() {
        if !ALLOWED_FIELDS.contains(&key.as_str()) {
            return Err(format!("unsupported Responses request field: {key}"));
        }
    }

    let model = object
        .get("model")
        .and_then(Value::as_str)
        .filter(|model| !model.trim().is_empty())
        .ok_or_else(|| "Responses request field model must be a non-empty string".to_string())?
        .to_string();
    if model != D29F_MODEL {
        return Err(format!(
            "wrong Responses request model: expected {D29F_MODEL}, got {model}"
        ));
    }

    let mut messages = Vec::new();
    let instructions = object
        .get("instructions")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| "Responses request field instructions must be a string".to_string())
        })
        .transpose()?;
    if let Some(instructions) = instructions.filter(|instructions| !instructions.is_empty()) {
        messages.push(VitaMessage::text(VitaMessageRole::System, instructions));
    }

    let input = object
        .get("input")
        .and_then(Value::as_array)
        .ok_or_else(|| "Responses request field input must be an array".to_string())?;
    let mut input_item_types = Vec::with_capacity(input.len());
    let mut message_texts = Vec::new();
    for (index, item) in input.iter().enumerate() {
        let item_object = item.as_object().ok_or_else(|| {
            format!("unsupported Responses input item at index {index}: expected object")
        })?;
        let item_type = item_object
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!("unsupported Responses input item at index {index}: missing type")
            })?;
        input_item_types.push(item_type.to_string());
        if item_type != "message" {
            return Err(format!(
                "unsupported Responses input item type at index {index}: {item_type}"
            ));
        }
        let role = item_object
            .get("role")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("Responses message item at index {index} has no role"))?;
        let role = match role {
            "system" => VitaMessageRole::System,
            "developer" => VitaMessageRole::Developer,
            "user" => VitaMessageRole::User,
            "assistant" => VitaMessageRole::Assistant,
            other => {
                return Err(format!(
                    "unsupported Responses message role at index {index}: {other}"
                ));
            }
        };
        let content = item_object
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                format!("Responses message item at index {index} content must be an array")
            })?;
        let mut text = String::new();
        for (content_index, content_item) in content.iter().enumerate() {
            let content_object = content_item.as_object().ok_or_else(|| {
                format!(
                    "unsupported Responses content item at {index}:{content_index}: expected object"
                )
            })?;
            let content_type = content_object
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "unsupported Responses content item at {index}:{content_index}: missing type"
                    )
                })?;
            if !matches!(content_type, "input_text" | "output_text") {
                return Err(format!(
                    "unsupported Responses content item type at {index}:{content_index}: {content_type}"
                ));
            }
            let part = content_object
                .get("text")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    format!(
                        "Responses text content at {index}:{content_index} must contain string text"
                    )
                })?;
            text.push_str(part);
        }
        message_texts.push(text.clone());
        messages.push(VitaMessage::text(role, text));
    }

    let tools = object.get("tools").unwrap_or(&Value::Null);
    if !tools.is_null() {
        let tools = tools
            .as_array()
            .ok_or_else(|| "Responses request field tools must be an array or null".to_string())?;
        if !tools.is_empty() {
            return Err(
                "unsupported Responses request field: tools (non-empty tool list)".to_string(),
            );
        }
    }
    let tool_choice = object
        .get("tool_choice")
        .and_then(Value::as_str)
        .unwrap_or("auto");
    if tool_choice != "auto" {
        return Err(format!(
            "unsupported Responses request field: tool_choice={tool_choice}"
        ));
    }
    let parallel_tool_calls = object
        .get("parallel_tool_calls")
        .filter(|value| !value.is_null())
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                "unsupported Responses request field: parallel_tool_calls (expected boolean)"
                    .to_string()
            })
        })
        .transpose()?;
    if object.get("stream").and_then(Value::as_bool) != Some(true) {
        return Err("D29-F requires Codex Responses streaming".to_string());
    }
    if object
        .get("store")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err("unsupported Responses request field: store=true".to_string());
    }

    let reasoning_handling = match object.get("reasoning") {
        None => ResponsesFieldHandling::Absent,
        Some(value) => validate_reasoning_control(value)?,
    };
    let stream_options_handling = match object.get("stream_options") {
        None => ResponsesFieldHandling::Absent,
        Some(value) => validate_stream_options(value)?,
    };
    validate_optional_string_field(object, "service_tier")?;
    validate_optional_string_field(object, "prompt_cache_key")?;
    if let Some(include) = object.get("include").filter(|value| !value.is_null()) {
        if !include
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string))
        {
            return Err(
                "unsupported Responses request field: include (expected string array)".to_string(),
            );
        }
    }
    if let Some(client_metadata) = object
        .get("client_metadata")
        .filter(|value| !value.is_null())
    {
        if !client_metadata
            .as_object()
            .is_some_and(|values| values.values().all(Value::is_string))
        {
            return Err(
                "unsupported Responses request field: client_metadata (expected string map)"
                    .to_string(),
            );
        }
    }
    let text_handling = match object.get("text") {
        None => ResponsesFieldHandling::Absent,
        Some(value) => validate_text_control(value)?,
    };
    if object
        .get("access_programs")
        .is_some_and(|value| !value.is_null())
    {
        return Err("unsupported Responses request field: access_programs".to_string());
    }

    Ok(ParsedResponsesRequest {
        request: Some(VitaResponsesRequest::new(
            model.clone(),
            messages,
            VitaResponsesRequestOptions {
                // This flag records the actual Codex request shape.  The
                // ProviderGateway owns the non-stream Chat conversion.
                stream: true,
                parallel_tools: parallel_tool_calls.unwrap_or(false),
                ..VitaResponsesRequestOptions::default()
            },
        )),
        model: Some(model),
        input_item_types,
        message_texts,
        parallel_tool_calls,
        reasoning_handling,
        stream_options_handling,
        text_handling,
    })
}

fn validate_reasoning_control(value: &Value) -> Result<ResponsesFieldHandling, String> {
    let object = value.as_object().ok_or_else(|| {
        "unsupported Responses reasoning control: expected exact empty object".to_string()
    })?;
    if object.is_empty() {
        // The pinned Codex client always serializes its Responses reasoning
        // struct, while unsupported/default model metadata leaves every
        // semantic member absent.  `{}` is therefore an inert shape here;
        // forwarding it to Chat would not add a meaningful control.
        return Ok(ResponsesFieldHandling::EmptyObjectInert);
    }
    if object.len() == 1 && object.get("summary").and_then(Value::as_str) == Some("auto") {
        // The pinned D29-F model metadata selects `auto` as its default
        // reasoning-summary mode.  This is an upstream default, not a Vita
        // caller control; there is no reasoning-summary event to translate
        // on this no-reasoning Chat proof, so it is inert at the gateway.
        return Ok(ResponsesFieldHandling::DefaultSummaryAutoInert);
    }
    for key in object.keys() {
        if matches!(key.as_str(), "effort" | "summary" | "context") {
            return Err(format!("unsupported Responses reasoning control: {key}"));
        }
        return Err(format!("unsupported Responses reasoning field: {key}"));
    }
    Err("unsupported Responses reasoning control: non-empty object".to_string())
}

fn validate_stream_options(value: &Value) -> Result<ResponsesFieldHandling, String> {
    let object = value.as_object().ok_or_else(|| {
        "unsupported Responses stream control: expected exact sequential-cutoff object".to_string()
    })?;
    if object.len() == 1
        && object
            .get("reasoning_summary_delivery")
            .and_then(Value::as_str)
            == Some("sequential_cutoff")
    {
        // This pinned option only changes delivery ordering for reasoning
        // summary events.  D29-F proves a no-reasoning text turn and Chat has
        // no equivalent control, so this exact shape is safe to ignore.
        return Ok(ResponsesFieldHandling::SequentialCutoffInert);
    }
    if object.contains_key("include_obfuscation") {
        return Err("unsupported Responses stream control: include_obfuscation".to_string());
    }
    Err("unsupported Responses stream control: unexpected shape".to_string())
}

fn validate_text_control(value: &Value) -> Result<ResponsesFieldHandling, String> {
    let object = value.as_object().ok_or_else(|| {
        "unsupported Responses text control: expected exact empty object".to_string()
    })?;
    if object.is_empty() {
        // An empty TextControls object contains neither verbosity nor an
        // output format.  There is no Chat-side semantic to preserve.
        return Ok(ResponsesFieldHandling::EmptyObjectInert);
    }
    for key in object.keys() {
        match key.as_str() {
            "verbosity" => return Err("unsupported Responses text control: verbosity".to_string()),
            "format" => {
                return Err(
                    "unsupported Responses text control: format (structured output)".to_string(),
                )
            }
            "strict" => return Err("unsupported Responses text control: strict".to_string()),
            _ => return Err(format!("unsupported Responses text field: {key}")),
        }
    }
    Err("unsupported Responses text control: non-empty object".to_string())
}

#[cfg(test)]
fn minimal_responses_request() -> Value {
    json!({
        "model": D29F_MODEL,
        "input": [{
            "type": "message",
            "role": "user",
            "content": [{"type": "input_text", "text": "hello"}]
        }],
        "tool_choice": "auto",
        "parallel_tool_calls": true,
        "store": false,
        "stream": true
    })
}

#[cfg(test)]
fn parse_request_with_field(field: &str, value: Value) -> Result<ParsedResponsesRequest, String> {
    let mut object = minimal_responses_request()
        .as_object()
        .cloned()
        .expect("minimal D29-F request object");
    object.insert(field.to_string(), value);
    parse_codex_responses_request(&Value::Object(object).to_string().into_bytes())
}

#[test]
fn responses_semantic_fields_accept_only_documented_inert_shapes() {
    let base = parse_codex_responses_request(&minimal_responses_request().to_string().into_bytes())
        .expect("minimal Responses request should parse");
    assert_eq!(base.reasoning_handling, ResponsesFieldHandling::Absent);
    assert_eq!(base.stream_options_handling, ResponsesFieldHandling::Absent);
    assert_eq!(base.text_handling, ResponsesFieldHandling::Absent);

    let empty_reasoning = parse_request_with_field("reasoning", json!({}))
        .expect("empty reasoning object should be accepted as inert");
    assert_eq!(
        empty_reasoning.reasoning_handling,
        ResponsesFieldHandling::EmptyObjectInert
    );
    let default_reasoning = parse_request_with_field("reasoning", json!({"summary": "auto"}))
        .expect("default auto reasoning summary should be accepted as inert");
    assert_eq!(
        default_reasoning.reasoning_handling,
        ResponsesFieldHandling::DefaultSummaryAutoInert
    );
    for value in [
        json!({"effort": "value"}),
        json!({"summary": "value"}),
        json!({"context": "value"}),
    ] {
        let error = parse_request_with_field("reasoning", value)
            .expect_err("effective reasoning control must fail closed");
        assert!(error.contains("unsupported Responses reasoning control"));
    }

    let empty_text = parse_request_with_field("text", json!({}))
        .expect("empty text object should be accepted as inert");
    assert_eq!(
        empty_text.text_handling,
        ResponsesFieldHandling::EmptyObjectInert
    );
    for value in [
        json!({"verbosity": "low"}),
        json!({"format": {"type": "json_schema", "strict": true, "name": "schema", "schema": {}}}),
        json!({"strict": true}),
    ] {
        let error = parse_request_with_field("text", value)
            .expect_err("effective text control must fail closed");
        assert!(error.contains("unsupported Responses text control"));
    }

    let sequential_cutoff = parse_request_with_field(
        "stream_options",
        json!({"reasoning_summary_delivery": "sequential_cutoff"}),
    )
    .expect("pinned sequential cutoff should be accepted as inert");
    assert_eq!(
        sequential_cutoff.stream_options_handling,
        ResponsesFieldHandling::SequentialCutoffInert
    );
    for value in [
        json!({"include_obfuscation": false}),
        json!({}),
        json!({"reasoning_summary_delivery": "other"}),
    ] {
        let error = parse_request_with_field("stream_options", value)
            .expect_err("unsupported stream control must fail closed");
        assert!(error.contains("unsupported Responses stream control"));
    }
}

fn validate_optional_string_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<(), String> {
    if let Some(value) = object.get(key).filter(|value| !value.is_null()) {
        if !value.is_string() {
            return Err(format!(
                "unsupported Responses request field: {key} (expected string)"
            ));
        }
    }
    Ok(())
}

fn write_success_responses(
    stream: &mut TcpStream,
    result: &super::VitaResponsesResult,
) -> Result<(), String> {
    let response_id = format!("resp-{}", result.id);
    let item = json!({
        "type": "message",
        "id": "msg-d29f",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": result.output_text}]
    });
    let response_stub = json!({
        "id": response_id,
        "object": "response",
        "status": "in_progress",
        "model": result.model
    });
    let usage = result.usage.as_ref().map(|usage| {
        json!({
            "input_tokens": usage.input_tokens,
            "output_tokens": usage.output_tokens,
            "total_tokens": usage.total_tokens
        })
    });
    let completed_response = json!({
        "id": response_stub["id"],
        "usage": usage,
        "end_turn": true
    });
    let events = [
        json!({"type": "response.created", "response": response_stub}),
        json!({
            "type": "response.output_item.added",
            "item": {"type": "message", "id": "msg-d29f", "role": "assistant", "status": "in_progress", "content": []}
        }),
        json!({"type": "response.content_part.added"}),
        json!({"type": "response.output_text.delta", "delta": result.output_text}),
        json!({"type": "response.output_text.done", "text": result.output_text}),
        json!({"type": "response.content_part.done"}),
        json!({"type": "response.output_item.done", "item": item}),
        json!({"type": "response.completed", "response": completed_response}),
    ];
    let mut body = String::new();
    for event in events {
        let event_type = event
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| "D29-F SSE event omitted type".to_string())?;
        body.push_str("event: ");
        body.push_str(event_type);
        body.push_str("\ndata: ");
        body.push_str(
            &serde_json::to_string(&event)
                .map_err(|error| format!("serialize D29-F SSE event: {error}"))?,
        );
        body.push_str("\n\n");
    }
    write_http_response(stream, "200 OK", "text/event-stream", body.as_bytes())
}

fn write_held_responses(
    stream: &mut TcpStream,
    result: &super::VitaResponsesResult,
    stop: &Arc<AtomicBool>,
) -> Result<(), String> {
    stream
        .set_write_timeout(Some(D29F_REQUEST_TIMEOUT))
        .map_err(|error| format!("set held Responses write timeout: {error}"))?;
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\n\r\n",
        )
        .map_err(|error| format!("write held Responses headers: {error}"))?;
    let created = json!({
        "type": "response.created",
        "response": {
            "id": format!("resp-{}", result.id),
            "object": "response",
            "status": "in_progress",
            "model": result.model
        }
    });
    write_sse_event(stream, &created)?;
    write_sse_event(
        stream,
        &json!({
            "type": "response.output_item.added",
            "item": {
                "type": "message",
                "id": "msg-d29f-held",
                "role": "assistant",
                "status": "in_progress",
                "content": []
            }
        }),
    )?;
    write_sse_event(stream, &json!({"type": "response.content_part.added"}))?;

    // Keep the connection active with empty, non-semantic delta events, but
    // never emit response.completed.  SSE comments are invisible to the
    // pinned event stream's `next()` idle timer; an empty delta keeps that
    // timer alive without changing assistant text.  The Codex turn deadline,
    // not this listener, is responsible for submitting the interrupt.
    let deadline = Instant::now() + D29F_TURN_TIMEOUT;
    while !stop.load(Ordering::Acquire) && Instant::now() < deadline {
        write_sse_event(
            stream,
            &json!({"type": "response.output_text.delta", "delta": ""}),
        )?;
        stream
            .flush()
            .map_err(|error| format!("flush held Responses heartbeat: {error}"))?;
        thread::sleep(D29F_HEARTBEAT_INTERVAL);
    }
    Ok(())
}

fn write_sse_event(stream: &mut TcpStream, event: &Value) -> Result<(), String> {
    let event_type = event
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "D29-F SSE event omitted type".to_string())?;
    let body = format!(
        "event: {event_type}\ndata: {}\n\n",
        serde_json::to_string(event)
            .map_err(|error| format!("serialize D29-F SSE event: {error}"))?
    );
    stream
        .write_all(body.as_bytes())
        .map_err(|error| format!("write D29-F SSE event: {error}"))
}

fn write_failed_responses(stream: &mut TcpStream, message: &str) -> Result<(), String> {
    let response_id = "resp-d29f-failed";
    let events = [
        json!({
            "type": "response.created",
            "response": {"id": response_id, "object": "response", "status": "in_progress", "model": D29F_MODEL}
        }),
        json!({
            "type": "response.failed",
            "response": {
                "id": response_id,
                "error": {"type": "invalid_request_error", "code": "invalid_prompt", "message": message}
            }
        }),
    ];
    let mut body = String::new();
    for event in events {
        let event_type = event
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| "D29-F failure SSE event omitted type".to_string())?;
        body.push_str("event: ");
        body.push_str(event_type);
        body.push_str("\ndata: ");
        body.push_str(
            &serde_json::to_string(&event)
                .map_err(|error| format!("serialize D29-F failure SSE event: {error}"))?,
        );
        body.push_str("\n\n");
    }
    write_http_response(stream, "200 OK", "text/event-stream", body.as_bytes())
}

fn write_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    stream
        .set_write_timeout(Some(D29F_REQUEST_TIMEOUT))
        .map_err(|error| format!("set HTTP write timeout: {error}"))?;
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|error| format!("write HTTP response: {error}"))
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    stream
        .set_read_timeout(Some(D29F_REQUEST_TIMEOUT))
        .map_err(|error| format!("set HTTP read timeout: {error}"))?;
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut buffer = [0_u8; 4096];
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("read HTTP headers: {error}"))?;
        if read == 0 {
            return Err("HTTP peer closed before headers".to_string());
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > D29F_HTTP_MAX_BODY {
            return Err("HTTP request exceeded D29-F size bound".to_string());
        }
        if let Some(end) = find_header_end(&bytes) {
            break end;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end])
        .map_err(|error| format!("HTTP headers were not UTF-8: {error}"))?;
    let mut lines = header_text.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "HTTP request omitted request line".to_string())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| "HTTP request omitted method".to_string())?
        .to_string();
    let target = request_parts
        .next()
        .ok_or_else(|| "HTTP request omitted target".to_string())?
        .to_string();
    let mut headers = Vec::new();
    let mut content_length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "HTTP header omitted colon".to_string())?;
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|error| format!("invalid HTTP content length: {error}"))?,
            );
        }
        headers.push((name.trim().to_string(), value));
    }
    let content_length =
        content_length.ok_or_else(|| "HTTP request omitted content length".to_string())?;
    if content_length > D29F_HTTP_MAX_BODY {
        return Err("HTTP request body exceeded D29-F size bound".to_string());
    }
    let body_start = header_end + 4;
    let total = body_start.saturating_add(content_length);
    while bytes.len() < total {
        let mut buffer = [0_u8; 4096];
        let read = stream
            .read(&mut buffer)
            .map_err(|error| format!("read HTTP body: {error}"))?;
        if read == 0 {
            return Err("HTTP peer closed before request body".to_string());
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > total {
            break;
        }
    }
    if bytes.len() < total {
        return Err("HTTP request body was truncated".to_string());
    }
    Ok(HttpRequest {
        method,
        target,
        headers,
        body: bytes[body_start..total].to_vec(),
    })
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}

fn join_listener_thread(join: JoinHandle<()>) -> bool {
    let started = Instant::now();
    let joined = join.join().is_ok();
    joined && started.elapsed() <= D29F_CLEANUP_TIMEOUT
}

fn wake_loopback_listener(address: SocketAddr) {
    let _ = TcpStream::connect_timeout(&address, Duration::from_millis(50));
}

struct D29fCredentialResolver {
    reference: CredentialRef,
}

impl CredentialResolver for D29fCredentialResolver {
    fn resolve(&self, credential_ref: &CredentialRef) -> Result<String, VitaAgentError> {
        if credential_ref != &self.reference {
            return Err(VitaAgentError::CredentialResolution(
                "D29-F credential reference was not found in the in-memory test store",
            ));
        }
        Ok(D29F_CREDENTIAL.to_string())
    }
}

struct D29fTcpLocalTransport;

impl ProviderRequestTransport for D29fTcpLocalTransport {
    fn post_json(
        &self,
        endpoint: &ProviderEndpoint,
        authorization: Option<&str>,
        body: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, VitaAgentError> {
        if !endpoint.is_test_localhost() {
            return Err(VitaAgentError::GatewayProtocol(
                "D29-F transport is authorized only for test-scoped loopback endpoints".to_string(),
            ));
        }
        let address = SocketAddr::from(([127, 0, 0, 1], endpoint.port));
        let mut stream = TcpStream::connect_timeout(&address, timeout)
            .map_err(VitaAgentError::GatewayTransport)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(VitaAgentError::GatewayTransport)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(VitaAgentError::GatewayTransport)?;
        let path = endpoint.request_path("chat/completions");
        let mut request = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
            endpoint.host_header(),
            body.len()
        )
        .into_bytes();
        if let Some(authorization) = authorization {
            request.extend_from_slice(format!("Authorization: {authorization}\r\n").as_bytes());
        }
        request.extend_from_slice(b"\r\n");
        request.extend_from_slice(body);
        stream
            .write_all(&request)
            .map_err(VitaAgentError::GatewayTransport)?;
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .map_err(map_d29f_downstream_io_error)?;
        let header_end = find_header_end(&response).ok_or_else(|| {
            VitaAgentError::GatewayProtocol("Chat mock omitted HTTP response headers".to_string())
        })?;
        let status_line = String::from_utf8_lossy(&response[..header_end]);
        if !status_line.starts_with("HTTP/1.1 200 ") {
            return Err(VitaAgentError::GatewayProtocol(
                "Chat mock returned a non-success status".to_string(),
            ));
        }
        Ok(response[header_end + 4..].to_vec())
    }
}

fn map_d29f_downstream_io_error(error: std::io::Error) -> VitaAgentError {
    if error.kind() == std::io::ErrorKind::TimedOut {
        VitaAgentError::GatewayProtocol(
            "D29-F downstream Chat request timed out within the test deadline".to_string(),
        )
    } else {
        VitaAgentError::GatewayTransport(error)
    }
}

struct CaseRuntime {
    _app_data: TempDir,
    _workspace: TempDir,
    manager: Arc<ThreadManager>,
    thread: Option<Arc<codex_core_api::CodexThread>>,
    thread_id: Option<ThreadId>,
    gateway: Option<VitaGatewayServer>,
    chat: Option<LocalChatMock>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownStatus {
    NotAttempted,
    Success,
    TimedOut,
    Failed,
}

impl ShutdownStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::NotAttempted => "not-attempted",
            Self::Success => "success",
            Self::TimedOut => "timed-out",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CleanupEvidence {
    initial_shutdown: ShutdownStatus,
    interrupt_submitted: bool,
    final_shutdown: ShutdownStatus,
    manager_thread_count: usize,
    gateway_listener_joined: Option<bool>,
    chat_listener_joined: Option<bool>,
}

#[derive(Debug)]
struct RuntimeShutdown {
    cleanup: CleanupEvidence,
    gateway: Option<GatewayObservation>,
    chat: Option<HttpObservation>,
}

impl CaseRuntime {
    async fn shutdown(mut self, turn_interrupt_submitted: bool) -> Result<RuntimeShutdown, String> {
        let mut initial_shutdown = ShutdownStatus::NotAttempted;
        let mut interrupt_submitted = turn_interrupt_submitted;
        let mut final_shutdown = ShutdownStatus::NotAttempted;

        if let Some(thread) = self.thread.take() {
            initial_shutdown = shutdown_thread_once(&thread).await;
            if initial_shutdown != ShutdownStatus::Success {
                // A turn deadline may already have submitted an interrupt.  A
                // second bounded submission here is intentional: cleanup
                // must independently prove that the thread can be stopped.
                interrupt_submitted |= submit_interrupt_bounded(&thread).await;
            }
            final_shutdown = shutdown_thread_once(&thread).await;

            // Do not remove a manager entry until the final shutdown result
            // is known.  The identity check also avoids removing a replacement
            // thread if a future manager implementation reuses an id.
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
        let (gateway, gateway_listener_joined) = match self.gateway.take() {
            Some(gateway) => {
                let (observation, joined) = gateway.shutdown();
                (Some(observation), Some(joined))
            }
            None => (None, None),
        };
        let (chat, chat_listener_joined) = match self.chat.take() {
            Some(chat) => {
                let (observation, joined) = chat.shutdown();
                (Some(observation), Some(joined))
            }
            None => (None, None),
        };
        let cleanup = CleanupEvidence {
            initial_shutdown,
            interrupt_submitted,
            final_shutdown,
            manager_thread_count,
            gateway_listener_joined,
            chat_listener_joined,
        };
        if cleanup.final_shutdown != ShutdownStatus::Success
            || cleanup.manager_thread_count != 0
            || cleanup.gateway_listener_joined == Some(false)
            || cleanup.chat_listener_joined == Some(false)
        {
            return Err("D29-F bounded cleanup failed".to_string());
        }
        Ok(RuntimeShutdown {
            cleanup,
            gateway,
            chat,
        })
    }
}

#[derive(Debug, Clone)]
struct TurnResult {
    elapsed: Duration,
    assistant_messages: Vec<String>,
    terminal_message: Option<String>,
    terminal_error: Option<String>,
    event_count: usize,
    turn_timed_out: bool,
    interrupt_submitted: bool,
}

async fn shutdown_thread_once(thread: &Arc<codex_core_api::CodexThread>) -> ShutdownStatus {
    match tokio::time::timeout(D29F_CLEANUP_TIMEOUT, thread.shutdown_and_wait()).await {
        Ok(Ok(())) => ShutdownStatus::Success,
        Ok(Err(_)) => ShutdownStatus::Failed,
        Err(_) => ShutdownStatus::TimedOut,
    }
}

async fn submit_interrupt_bounded(thread: &Arc<codex_core_api::CodexThread>) -> bool {
    matches!(
        tokio::time::timeout(D29F_CLEANUP_TIMEOUT, thread.submit(Op::Interrupt)).await,
        Ok(Ok(_))
    )
}

async fn collect_turn(
    thread: &Arc<codex_core_api::CodexThread>,
    turn_deadline: Duration,
) -> Result<TurnResult, String> {
    let start = Instant::now();
    let deadline = start + turn_deadline;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        let interrupt_submitted = submit_interrupt_bounded(thread).await;
        return Ok(TurnResult {
            elapsed: start.elapsed(),
            assistant_messages: Vec::new(),
            terminal_message: None,
            terminal_error: Some("D29-F turn deadline expired".to_string()),
            event_count: 0,
            turn_timed_out: true,
            interrupt_submitted,
        });
    }
    match tokio::time::timeout(
        remaining,
        thread.start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: D29F_PROMPT.to_string(),
            text_elements: Vec::new(),
        }])),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => return Err(format!("D29-F turn submission failed: {error}")),
        Err(_) => {
            let interrupt_submitted = submit_interrupt_bounded(thread).await;
            return Ok(TurnResult {
                elapsed: start.elapsed(),
                assistant_messages: Vec::new(),
                terminal_message: None,
                terminal_error: Some("D29-F turn deadline expired".to_string()),
                event_count: 0,
                turn_timed_out: true,
                interrupt_submitted,
            });
        }
    }

    let mut assistant_messages = Vec::new();
    let mut event_count = 0;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let interrupt_submitted = submit_interrupt_bounded(thread).await;
            return Ok(TurnResult {
                elapsed: start.elapsed(),
                assistant_messages,
                terminal_message: None,
                terminal_error: Some("D29-F turn deadline expired".to_string()),
                event_count,
                turn_timed_out: true,
                interrupt_submitted,
            });
        }
        let event = match tokio::time::timeout(remaining, thread.next_event()).await {
            Ok(Ok(event)) => event,
            Ok(Err(error)) => return Err(format!("D29-F event stream failed: {error}")),
            Err(_) => {
                let interrupt_submitted = submit_interrupt_bounded(thread).await;
                return Ok(TurnResult {
                    elapsed: start.elapsed(),
                    assistant_messages,
                    terminal_message: None,
                    terminal_error: Some("D29-F turn deadline expired".to_string()),
                    event_count,
                    turn_timed_out: true,
                    interrupt_submitted,
                });
            }
        };
        event_count += 1;
        match event.msg {
            EventMsg::AgentMessage(message) => assistant_messages.push(message.message),
            EventMsg::TurnComplete(complete) => {
                return Ok(TurnResult {
                    elapsed: start.elapsed(),
                    assistant_messages,
                    terminal_message: complete.last_agent_message,
                    terminal_error: complete.error.map(|error| error.message),
                    event_count,
                    turn_timed_out: false,
                    interrupt_submitted: false,
                });
            }
            _ => {}
        }
    }
}

async fn start_runtime(
    mode: Option<ChatMockMode>,
    listener_available: bool,
    response_mode: GatewayResponseMode,
) -> Result<(CaseRuntime, VitaAgentRuntimeProfile, HostCanary), String> {
    let app_data = tempdir().map_err(|error| format!("create Vita app-data temp root: {error}"))?;
    let workspace =
        tempdir().map_err(|error| format!("create Vita workspace temp root: {error}"))?;
    let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
        app_data.path().to_path_buf(),
        workspace.path().to_path_buf(),
    )
    .map_err(|error| format!("create Vita runtime profile: {error}"))?;

    // Keep the TempDir guards alive by nesting them in the returned runtime's
    // process scope.  The Codex thread only observes these roots for the case.
    let chat = mode.map(LocalChatMock::start);
    let chat_base_url = match chat.as_ref() {
        Some(chat) => chat.base_url(),
        None => unused_loopback_base_url(),
    };
    let credential = CredentialRef::new(D29F_PROVIDER_ID, D29F_PROVIDER_ID, &chat_base_url)
        .map_err(|error| format!("create D29-F credential reference: {error}"))?;
    let provider = ProviderProfile::new_for_test_localhost(
        D29F_PROVIDER_ID,
        "D29-F localhost Chat mock",
        ProviderProtocol::OpenAiChatCompletions,
        &chat_base_url,
        D29F_MODEL,
        Some(credential),
        D29F_REQUEST_TIMEOUT,
        ProviderRetryPolicy::default(),
        ProviderCapabilities {
            developer_role: true,
            ..ProviderCapabilities::none()
        },
    )
    .map_err(|error| format!("create D29-F provider profile: {error}"))?;
    let authority = super::VitaProviderAuthority::configure(provider)
        .map_err(|error| format!("configure D29-F provider: {error}"))?;

    // Reserve an ephemeral loopback port before deriving the provider.  When
    // listener_available is false, GatewayReady is still constructed and the
    // listener is then dropped; this is the separate transport-negative case.
    let reservation = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|error| format!("reserve D29-F gateway port: {error}"))?;
    let binding = VitaGatewayBinding::for_owned_private_listener(
        reservation
            .local_addr()
            .map_err(|error| format!("read D29-F gateway port: {error}"))?
            .port(),
    )
    .map_err(|error| format!("derive D29-F gateway binding: {error}"))?;
    let ready = authority
        .prepare_gateway(binding)
        .map_err(|error| format!("prepare D29-F gateway: {error}"))?;
    let gateway = if listener_available {
        Some(VitaGatewayServer::start(
            reservation,
            ready.clone(),
            response_mode,
        ))
    } else {
        drop(reservation);
        None
    };
    let entrypoint =
        VitaAgentEntrypoint::initialize_with_gateway_for_tests(profile.clone(), &ready)
            .await
            .map_err(|error| format!("compile D29-F provider into Codex config: {error}"))?;
    assert_gateway_config(&entrypoint, ready.derived_codex_provider())?;

    let config = entrypoint.config().clone();
    let auth_manager = codex_core::test_support::auth_manager_from_auth_with_home(
        CodexAuth::from_api_key("d29f-in-memory-kernel-auth"),
        config.codex_home.to_path_buf(),
    );
    let manager = Arc::new(ThreadManager::new(
        &config,
        Arc::clone(&auth_manager),
        codex_core_api::build_models_manager(&config, Arc::clone(&auth_manager)),
        CodexAppsToolsCache::default(),
        SessionSource::Exec,
        Arc::new(EnvironmentManager::default_for_tests()),
        codex_core_api::empty_extension_registry(),
        Arc::new(codex_core::test_support::EmptyUserInstructionsProvider),
        None,
        codex_core_api::thread_store_from_config(&config, None),
        None,
        "d29f-local-installation".to_string(),
        None,
        None,
    ));
    let new_thread = tokio::time::timeout(
        D29F_TURN_TIMEOUT,
        manager.start_thread(StartThreadOptions::new(config)),
    )
    .await
    .map_err(|_| "D29-F real thread startup timed out".to_string())?
    .map_err(|error| format!("D29-F real thread startup failed: {error}"))?;

    let canary = host_canary();
    Ok((
        CaseRuntime {
            _app_data: app_data,
            _workspace: workspace,
            manager,
            thread: Some(new_thread.thread),
            thread_id: Some(new_thread.thread_id),
            gateway,
            chat,
        },
        profile,
        canary,
    ))
}

fn assert_gateway_config(
    entrypoint: &VitaAgentEntrypoint,
    provider: &super::DerivedCodexProvider,
) -> Result<(), String> {
    let config = entrypoint.config();
    if config.model_provider_id != VITA_GATEWAY_PROVIDER_ID
        || config.model_provider_id != provider.model_provider_id()
        || config.model.as_deref() != Some(D29F_MODEL)
        || config.model.as_deref() != Some(provider.model())
        || config.model_provider.base_url.as_deref() != Some(provider.base_url())
        || config.model_provider.wire_api.to_string() != "responses"
        || config.model_provider.wire_api.to_string() != provider.wire_api()
        || config.model_provider.requires_openai_auth
        || config.model_provider.env_key.is_some()
        || config.model_provider.experimental_bearer_token.is_some()
        || config.model_provider.auth.is_some()
        || config.model_provider.aws.is_some()
        || config.model_provider.supports_websockets
    {
        return Err("D29-F actual Codex config did not match Vita gateway derivation".to_string());
    }
    if config.experimental_thread_store
        != (codex_core_api::ThreadStoreConfig::InMemory {
            id: VITA_AGENT_RUNTIME_ID.to_string(),
        })
        || config.check_for_update_on_startup
        || config.analytics_enabled != Some(false)
        || config.feedback_enabled
        || config.permissions.network_sandbox_policy().is_enabled()
    {
        return Err("D29-F actual Codex config escaped private Vita runtime".to_string());
    }
    Ok(())
}

fn unused_loopback_base_url() -> String {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve unused D29-F port");
    let port = listener
        .local_addr()
        .expect("unused D29-F port address")
        .port();
    drop(listener);
    format!("http://127.0.0.1:{port}/v1")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NotReadyEvidence {
    authority_state: VitaProviderState,
    gateway_ready_constructed: bool,
    codex_config_compiled: bool,
    real_turn_started: bool,
}

fn prove_configured_but_not_ready() -> Result<NotReadyEvidence, String> {
    let provider = ProviderProfile::new_for_test_localhost(
        D29F_PROVIDER_ID,
        "D29-F configured-only provider",
        ProviderProtocol::OpenAiChatCompletions,
        &unused_loopback_base_url(),
        D29F_MODEL,
        None,
        D29F_REQUEST_TIMEOUT,
        ProviderRetryPolicy::default(),
        ProviderCapabilities::none(),
    )
    .map_err(|error| format!("create configured-only provider: {error}"))?;
    let authority = super::VitaProviderAuthority::configure(provider)
        .map_err(|error| format!("configure configured-only provider: {error}"))?;
    if authority.state() != VitaProviderState::ConfiguredValidated {
        return Err("D29-F configured-only authority did not remain validated".to_string());
    }
    // Deliberately do not call prepare_gateway.  The test-only Codex config
    // compiler accepts GatewayReadyProvider, not DerivedCodexProvider, so this
    // state has no executable Codex-start seam by construction.
    Ok(NotReadyEvidence {
        authority_state: authority.state(),
        gateway_ready_constructed: false,
        codex_config_compiled: false,
        real_turn_started: false,
    })
}

async fn run_case(
    mode: Option<ChatMockMode>,
    listener_available: bool,
    response_mode: GatewayResponseMode,
    turn_deadline: Duration,
) -> Result<CaseReport, String> {
    let before = host_canary();
    let (runtime, profile, runtime_canary) =
        start_runtime(mode, listener_available, response_mode).await?;
    let turn = match runtime.thread.as_ref() {
        Some(thread) => collect_turn(thread, turn_deadline).await,
        None => Err("D29-F runtime did not contain a thread".to_string()),
    };
    let turn_interrupt_submitted = turn
        .as_ref()
        .ok()
        .is_some_and(|turn| turn.interrupt_submitted);
    let shutdown = runtime.shutdown(turn_interrupt_submitted).await?;
    let after = host_canary();
    canary_unchanged_result(&before, &runtime_canary)?;
    canary_unchanged_result(&before, &after)?;
    Ok(CaseReport {
        profile,
        turn,
        cleanup: shutdown.cleanup,
        gateway: shutdown.gateway,
        chat: shutdown.chat,
    })
}

#[derive(Debug)]
struct CaseReport {
    profile: VitaAgentRuntimeProfile,
    turn: Result<TurnResult, String>,
    cleanup: CleanupEvidence,
    gateway: Option<GatewayObservation>,
    chat: Option<HttpObservation>,
}

#[test]
fn d29f_first_real_codex_turn_and_bounded_negative_paths() {
    thread::Builder::new()
        .name("d29f-real-codex-turn".to_string())
        .stack_size(D29F_TEST_STACK_SIZE)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-F test runtime should build");
            runtime.block_on(d29f_first_real_codex_turn_and_bounded_negative_paths_body());
        })
        .expect("D29-F test thread should start")
        .join()
        .expect("D29-F test thread should finish");
}

async fn d29f_first_real_codex_turn_and_bounded_negative_paths_body() {
    let success = run_case(
        Some(ChatMockMode::Success),
        true,
        GatewayResponseMode::Normal,
        D29F_TURN_TIMEOUT,
    )
    .await
    .expect("D29-F success case should run");
    let success_turn = success.turn.expect("D29-F success turn should terminate");
    assert_eq!(success_turn.terminal_error, None);
    assert_eq!(success_turn.terminal_message.as_deref(), Some(D29F_REPLY));
    assert!(success_turn
        .assistant_messages
        .iter()
        .any(|message| message == D29F_REPLY));
    assert!(success_turn.elapsed < D29F_TURN_TIMEOUT);
    assert!(success_turn.event_count > 0);
    assert!(!success_turn.turn_timed_out);
    assert!(!success_turn.interrupt_submitted);
    assert_eq!(success.cleanup.initial_shutdown, ShutdownStatus::Success);
    assert_eq!(success.cleanup.final_shutdown, ShutdownStatus::Success);
    assert!(!success.cleanup.interrupt_submitted);
    assert_eq!(success.cleanup.manager_thread_count, 0);
    assert_eq!(success.cleanup.gateway_listener_joined, Some(true));
    assert_eq!(success.cleanup.chat_listener_joined, Some(true));
    let success_gateway = success.gateway.expect("D29-F success gateway evidence");
    let success_chat = success.chat.expect("D29-F success Chat evidence");
    assert_eq!(success_gateway.request_count, 1);
    assert!(success_gateway.peer_is_loopback);
    assert_eq!(success_gateway.method.as_deref(), Some("POST"));
    assert_eq!(success_gateway.target.as_deref(), Some("/v1/responses"));
    assert!(!success_gateway.codex_authorization_present);
    assert_eq!(success_gateway.request_model.as_deref(), Some(D29F_MODEL));
    assert_eq!(success_gateway.parallel_tool_calls, Some(true));
    assert_eq!(
        success_gateway.reasoning_handling,
        ResponsesFieldHandling::DefaultSummaryAutoInert
    );
    assert_eq!(
        success_gateway.stream_options_handling,
        ResponsesFieldHandling::Absent
    );
    assert_eq!(
        success_gateway.text_handling,
        ResponsesFieldHandling::Absent
    );
    assert_eq!(
        success_gateway.response_path.as_deref(),
        Some("responses-sse")
    );
    assert!(success_gateway.terminal_response_emitted);
    assert!(success_gateway.bridge_error.is_none());
    assert!(success_gateway
        .message_texts
        .iter()
        .any(|message| message.contains(D29F_PROMPT)));
    assert_eq!(success_chat.request_count, 1);
    assert_eq!(success_chat.method.as_deref(), Some("POST"));
    assert_eq!(success_chat.target.as_deref(), Some("/v1/chat/completions"));
    assert!(success_chat.authorization_present);
    assert!(success_chat.authorization_matches);
    assert_eq!(success_chat.error, None);
    assert_eq!(
        success_chat
            .body
            .as_ref()
            .and_then(|body| body.get("parallel_tool_calls"))
            .and_then(Value::as_bool),
        None
    );
    assert!(success_chat
        .body
        .as_ref()
        .and_then(|body| body.get("tools"))
        .is_none());
    println!(
        "D29-F PASS codex_gateway={} codex_path=/v1/responses chat_gateway={} chat_path=/v1/chat/completions codex_requests={} chat_requests={} selected_model={} terminal_output={} reasoning={} stream_options={} text={} terminal_response=emitted external_endpoint_calls=0 listeners_shutdown=true manager_threads=0 raw_canary_values=none",
        success_gateway
            .bind
            .as_deref()
            .unwrap_or("127.0.0.1:<unknown>"),
        success_chat
            .bind
            .as_deref()
            .unwrap_or("127.0.0.1:<unknown>"),
        success_gateway.request_count,
        success_chat.request_count,
        D29F_MODEL,
        D29F_REPLY,
        success_gateway.reasoning_handling.as_str(),
        success_gateway.stream_options_handling.as_str(),
        success_gateway.text_handling.as_str()
    );

    let malformed = run_case(
        Some(ChatMockMode::MalformedBody),
        true,
        GatewayResponseMode::Normal,
        D29F_TURN_TIMEOUT,
    )
    .await
    .expect("D29-F malformed case should run");
    assert_case_failed(&malformed, "invalid chat completion JSON");
    assert_eq!(malformed.gateway.as_ref().unwrap().request_count, 1);
    assert_eq!(malformed.chat.as_ref().unwrap().request_count, 1);

    let tool_call = run_case(
        Some(ChatMockMode::UnexpectedToolCall),
        true,
        GatewayResponseMode::Normal,
        D29F_TURN_TIMEOUT,
    )
    .await
    .expect("D29-F tool-call case should run");
    assert_case_failed(&tool_call, "tools");
    assert_eq!(tool_call.gateway.as_ref().unwrap().request_count, 1);
    assert_eq!(tool_call.chat.as_ref().unwrap().request_count, 1);

    let timeout_case = run_case(
        Some(ChatMockMode::Delayed),
        true,
        GatewayResponseMode::Normal,
        D29F_TURN_TIMEOUT,
    )
    .await
    .expect("D29-F timeout case should run");
    assert_case_failed(&timeout_case, "timed out");
    assert!(timeout_case.turn.as_ref().err().is_none());
    assert!(timeout_case.gateway.as_ref().unwrap().request_count <= 1);
    assert_eq!(timeout_case.chat.as_ref().unwrap().request_count, 1);

    let unavailable = run_case(None, true, GatewayResponseMode::Normal, D29F_TURN_TIMEOUT)
        .await
        .expect("D29-F unavailable-provider case should run");
    assert_case_failed(&unavailable, "transport error");
    assert_eq!(unavailable.gateway.as_ref().unwrap().request_count, 1);
    assert!(unavailable.chat.is_none());

    let listener_unavailable = run_case(
        Some(ChatMockMode::Success),
        false,
        GatewayResponseMode::Normal,
        D29F_TURN_TIMEOUT,
    )
    .await
    .expect("D29-F listener-unavailable case should run");
    assert_case_failed(&listener_unavailable, "503");
    assert!(listener_unavailable.gateway.is_none());
    assert_eq!(listener_unavailable.chat.as_ref().unwrap().request_count, 0);
    assert_eq!(
        listener_unavailable.cleanup.final_shutdown,
        ShutdownStatus::Success
    );
    assert_eq!(listener_unavailable.cleanup.manager_thread_count, 0);
    assert_eq!(listener_unavailable.cleanup.gateway_listener_joined, None);
    assert_eq!(
        listener_unavailable.cleanup.chat_listener_joined,
        Some(true)
    );

    let not_ready = prove_configured_but_not_ready().expect("D29-F not-ready proof should run");
    assert_eq!(
        not_ready.authority_state,
        VitaProviderState::ConfiguredValidated
    );
    assert!(!not_ready.gateway_ready_constructed);
    assert!(!not_ready.codex_config_compiled);
    assert!(!not_ready.real_turn_started);
    println!(
        "D29-F NOT-READY PASS authority_state={} gateway_ready=false codex_config=false real_turn=false",
        not_ready.authority_state
    );

    let true_timeout = run_case(
        Some(ChatMockMode::Success),
        true,
        GatewayResponseMode::HoldTerminalResponse,
        D29F_TRUE_TURN_DEADLINE,
    )
    .await
    .expect("D29-F true-timeout case should run");
    let true_timeout_turn = true_timeout
        .turn
        .as_ref()
        .expect("D29-F true-timeout turn should produce bounded evidence");
    assert!(true_timeout_turn.turn_timed_out);
    assert!(true_timeout_turn.interrupt_submitted);
    assert_case_failed(&true_timeout, "turn deadline expired");
    assert_eq!(true_timeout.gateway.as_ref().unwrap().request_count, 1);
    assert_eq!(
        true_timeout
            .gateway
            .as_ref()
            .unwrap()
            .response_path
            .as_deref(),
        Some("responses-sse-held")
    );
    assert!(
        !true_timeout
            .gateway
            .as_ref()
            .unwrap()
            .terminal_response_emitted
    );
    assert_eq!(true_timeout.chat.as_ref().unwrap().request_count, 1);
    assert_eq!(
        true_timeout.cleanup.initial_shutdown,
        ShutdownStatus::Success
    );
    assert!(true_timeout.cleanup.interrupt_submitted);
    assert_eq!(true_timeout.cleanup.final_shutdown, ShutdownStatus::Success);
    assert_eq!(true_timeout.cleanup.manager_thread_count, 0);
    assert_eq!(true_timeout.cleanup.gateway_listener_joined, Some(true));
    assert_eq!(true_timeout.cleanup.chat_listener_joined, Some(true));
    println!(
        "D29-F TIMEOUT PASS whole_turn_deadline_expired=true interrupt_submitted=true initial_shutdown={} final_shutdown={} manager_threads=0 gateway_listener=joined chat_listener=joined",
        true_timeout.cleanup.initial_shutdown.as_str(),
        true_timeout.cleanup.final_shutdown.as_str()
    );

    let authority = super::VitaProviderAuthority::not_configured();
    let binding = VitaGatewayBinding::for_owned_private_listener(1_234)
        .expect("D29-F not-configured binding");
    assert!(matches!(
        authority.prepare_gateway(binding),
        Err(VitaAgentError::NotConfiguredProvider)
    ));

    let wrong_model = ProviderProfile::new_for_test_localhost(
        "provider-one",
        "Provider One",
        ProviderProtocol::OpenAiChatCompletions,
        &unused_loopback_base_url(),
        "mock-model",
        None,
        Duration::from_secs(10),
        ProviderRetryPolicy::default(),
        ProviderCapabilities::none(),
    )
    .expect("valid wrong-model test-localhost profile");
    let wrong_authority = super::VitaProviderAuthority::configure(wrong_model).unwrap();
    let wrong_binding = VitaGatewayBinding::for_owned_private_listener(4_321).unwrap();
    let wrong_ready = wrong_authority.prepare_gateway(wrong_binding).unwrap();
    let wrong_gateway = ProviderGateway::new(
        wrong_ready,
        D29fNoCredentialResolver,
        D29fNoNetworkTransport,
    );
    let wrong_request = VitaResponsesRequest::new(
        "wrong-model",
        Vec::new(),
        VitaResponsesRequestOptions::default(),
    );
    assert!(matches!(
        wrong_gateway.execute_responses_request(&wrong_request),
        Err(VitaAgentError::GatewayProtocol(message)) if message.contains("request model")
    ));

    let canary_before = host_canary();
    let profile_app_data = tempdir().expect("D29-F A canary app-data");
    let profile_workspace = tempdir().expect("D29-F A canary workspace");
    let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
        profile_app_data.path().to_path_buf(),
        profile_workspace.path().to_path_buf(),
    )
    .expect("D29-F A profile");
    let entrypoint = VitaAgentEntrypoint::initialize(profile)
        .await
        .expect("D29-F A unconfigured entrypoint");
    assert!(matches!(
        entrypoint.prepare_thread_start(),
        Err(VitaAgentError::NotConfiguredProvider)
    ));
    assert_canary_unchanged(&canary_before, &host_canary());
    println!(
        "D29-F CANARY PASS parent_environment=unchanged user_codex_state=unchanged raw_values=none"
    );
}

fn assert_case_failed(case: &CaseReport, expected: &str) {
    let turn = case
        .turn
        .as_ref()
        .expect("negative D29-F turn should reach terminal event");
    assert!(turn.terminal_error.is_some(), "expected terminal error");
    assert!(
        turn.terminal_error
            .as_deref()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .contains(&expected.to_ascii_lowercase()),
        "terminal error did not contain {expected:?}: {:?}",
        turn.terminal_error
    );
    assert!(turn.elapsed < D29F_TURN_TIMEOUT);
}

struct D29fNoCredentialResolver;

impl CredentialResolver for D29fNoCredentialResolver {
    fn resolve(&self, _credential_ref: &CredentialRef) -> Result<String, VitaAgentError> {
        Err(VitaAgentError::CredentialResolution(
            "D29-F wrong-model test must fail before credential resolution",
        ))
    }
}

struct D29fNoNetworkTransport;

impl ProviderRequestTransport for D29fNoNetworkTransport {
    fn post_json(
        &self,
        _endpoint: &ProviderEndpoint,
        _authorization: Option<&str>,
        _body: &[u8],
        _timeout: Duration,
    ) -> Result<Vec<u8>, VitaAgentError> {
        Err(VitaAgentError::GatewayTransport(std::io::Error::new(
            std::io::ErrorKind::Other,
            "D29-F wrong-model test must fail before transport",
        )))
    }
}
