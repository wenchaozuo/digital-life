//! D29-F's first real pinned-Codex turn proof.
//!
//! This module is test-scoped on purpose.  It owns both loopback listeners,
//! compiles the D29-E derived provider into the upstream `Config`, and then
//! drives the public `ThreadManager`/`CodexThread` APIs.  There is no external
//! provider transport or production listener in this candidate.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use codex_core_api::{
    CodexAppsToolsCache, CodexAuth, EnvironmentManager, EventMsg, SessionSource,
    StartThreadOptions, ThreadManager, TurnInputRequest, UserInput,
};
use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};

use super::{
    CredentialRef, CredentialResolver, GatewayReadyProvider, ProviderCapabilities,
    ProviderEndpoint, ProviderGateway, ProviderProfile, ProviderProtocol, ProviderRequestTransport,
    ProviderRetryPolicy, VitaAgentError, VitaGatewayBinding, VitaMessage, VitaMessageRole,
    VitaResponsesRequest, VitaResponsesRequestOptions,
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
const D29F_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const D29F_HTTP_MAX_BODY: usize = 2 * 1024 * 1024;
const D29F_TEST_STACK_SIZE: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostCanary {
    environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    codex_directory_exists: bool,
}

fn host_canary() -> HostCanary {
    let mut environment = std::env::vars_os().collect::<Vec<_>>();
    environment.sort_by(|left, right| left.0.cmp(&right.0));
    HostCanary {
        environment,
        // Only the directory's existence is sampled.  No user Codex file is
        // opened, parsed, copied, or used as a runtime input.
        codex_directory_exists: Path::new(r"C:\Users\zuo\.codex").exists(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChatMockMode {
    Success,
    MalformedBody,
    UnexpectedToolCall,
    Delayed,
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
    reasoning_present: bool,
    response_path: Option<String>,
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

    fn shutdown(mut self) -> HttpObservation {
        self.stop.store(true, Ordering::Release);
        wake_loopback_listener(self.address);
        if let Some(join) = self.join.take() {
            join.join().expect("D29-F Chat mock thread join");
        }
        self.observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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
    fn start(listener: TcpListener, ready: GatewayReadyProvider) -> Self {
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

    fn binding(&self) -> VitaGatewayBinding {
        VitaGatewayBinding::for_owned_private_listener(self.address.port())
            .expect("D29-F gateway binding")
    }

    fn shutdown(mut self) -> GatewayObservation {
        self.stop.store(true, Ordering::Release);
        wake_loopback_listener(self.address);
        if let Some(join) = self.join.take() {
            join.join().expect("D29-F Vita gateway thread join");
        }
        self.observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
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
    reasoning_present: bool,
}

fn handle_gateway_request(
    stream: &mut TcpStream,
    peer: SocketAddr,
    gateway: &ProviderGateway<D29fCredentialResolver, D29fTcpLocalTransport>,
    observation: &Arc<Mutex<GatewayObservation>>,
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
        observed.reasoning_present = parsed.reasoning_present;
    }

    let Some(parsed_request) = parsed.request.as_ref() else {
        let error = "D29-F Responses request parser produced no request";
        set_gateway_error(observation, error.to_string());
        let _ = write_failed_responses(stream, error);
        return;
    };
    match gateway.execute_responses_request(parsed_request) {
        Ok(result) => {
            set_gateway_response_path(observation, "responses-sse");
            if let Err(error) = write_success_responses(stream, &result) {
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

    let reasoning_present = object
        .get("reasoning")
        .is_some_and(|value| !value.is_null());
    if let Some(reasoning) = object.get("reasoning").filter(|value| !value.is_null()) {
        validate_reasoning_control(reasoning)?;
    }
    if let Some(stream_options) = object
        .get("stream_options")
        .filter(|value| !value.is_null())
    {
        let stream_options = stream_options
            .as_object()
            .ok_or_else(|| "Responses request stream_options must be an object".to_string())?;
        let keys = stream_options.keys().collect::<Vec<_>>();
        if keys
            .iter()
            .any(|key| key.as_str() != "reasoning_summary_delivery")
            || stream_options
                .get("reasoning_summary_delivery")
                .and_then(Value::as_str)
                .is_none_or(|value| value != "sequential_cutoff")
        {
            return Err(
                "unsupported Responses request field: stream_options (unexpected shape)"
                    .to_string(),
            );
        }
    }
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
    if let Some(text) = object.get("text").filter(|value| !value.is_null()) {
        if !text.is_object() {
            return Err("unsupported Responses request field: text (expected object)".to_string());
        }
    }
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
        reasoning_present,
    })
}

fn validate_reasoning_control(value: &Value) -> Result<(), String> {
    let object = value.as_object().ok_or_else(|| {
        "unsupported Responses request field: reasoning (expected object)".to_string()
    })?;
    for key in object.keys() {
        if !matches!(key.as_str(), "effort" | "summary" | "context") {
            return Err(format!("unsupported Responses reasoning field: {key}"));
        }
    }
    for key in ["effort", "summary", "context"] {
        if let Some(value) = object.get(key).filter(|value| !value.is_null()) {
            if !value.is_string() {
                return Err(format!(
                    "unsupported Responses reasoning field: {key} must be a string"
                ));
            }
        }
    }
    Ok(())
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
    gateway: Option<VitaGatewayServer>,
    chat: Option<LocalChatMock>,
}

impl CaseRuntime {
    async fn shutdown(mut self) -> (Option<GatewayObservation>, Option<HttpObservation>) {
        if let Some(thread) = self.thread.take() {
            let shutdown =
                tokio::time::timeout(D29F_CLEANUP_TIMEOUT, thread.shutdown_and_wait()).await;
            if shutdown.is_err() {
                let _ = tokio::time::timeout(
                    D29F_CLEANUP_TIMEOUT,
                    thread.submit(codex_core_api::Op::Interrupt),
                )
                .await;
                let _ =
                    tokio::time::timeout(D29F_CLEANUP_TIMEOUT, thread.shutdown_and_wait()).await;
            }
            let thread_id = self.manager.list_thread_ids().await.into_iter().next();
            if let Some(thread_id) = thread_id {
                let _ = self.manager.remove_thread(&thread_id).await;
            }
        }
        let gateway = self.gateway.take().map(VitaGatewayServer::shutdown);
        let chat = self.chat.take().map(LocalChatMock::shutdown);
        (gateway, chat)
    }
}

#[derive(Debug, Clone)]
struct TurnResult {
    elapsed: Duration,
    assistant_messages: Vec<String>,
    terminal_message: Option<String>,
    terminal_error: Option<String>,
    event_count: usize,
}

async fn collect_turn(thread: &codex_core_api::CodexThread) -> Result<TurnResult, String> {
    let start = Instant::now();
    tokio::time::timeout(
        D29F_TURN_TIMEOUT,
        thread.start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: D29F_PROMPT.to_string(),
            text_elements: Vec::new(),
        }])),
    )
    .await
    .map_err(|_| "D29-F turn submission timed out".to_string())?
    .map_err(|error| format!("D29-F turn submission failed: {error}"))?;

    let mut assistant_messages = Vec::new();
    let mut event_count = 0;
    loop {
        let event = tokio::time::timeout(D29F_TURN_TIMEOUT, thread.next_event())
            .await
            .map_err(|_| "D29-F waiting for terminal turn event timed out".to_string())?
            .map_err(|error| format!("D29-F event stream failed: {error}"))?;
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
                });
            }
            _ => {}
        }
        if start.elapsed() >= D29F_TURN_TIMEOUT {
            return Err("D29-F turn exceeded its terminal deadline".to_string());
        }
    }
}

async fn start_runtime(
    mode: Option<ChatMockMode>,
    start_gateway: bool,
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
    // start_gateway is false the listener is intentionally dropped to prove a
    // not-ready gateway fails boundedly and never falls back to OpenAI.
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
    let gateway = if start_gateway {
        Some(VitaGatewayServer::start(reservation, ready.clone()))
    } else {
        drop(reservation);
        None
    };
    let entrypoint = VitaAgentEntrypoint::initialize_with_gateway_for_tests(
        profile.clone(),
        ready.derived_codex_provider(),
    )
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
    if config.codex_home.as_path() == Path::new(r"C:\Users\zuo\.codex")
        || config.experimental_thread_store
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

async fn run_case(mode: Option<ChatMockMode>, start_gateway: bool) -> Result<CaseReport, String> {
    let before = host_canary();
    let (runtime, profile, runtime_canary) = start_runtime(mode, start_gateway).await?;
    let turn = match runtime.thread.as_ref() {
        Some(thread) => collect_turn(thread).await,
        None => Err("D29-F runtime did not contain a thread".to_string()),
    };
    let (gateway, chat) = runtime.shutdown().await;
    let after = host_canary();
    if before != after || runtime_canary != before {
        return Err("D29-F parent environment or user Codex directory canary changed".to_string());
    }
    Ok(CaseReport {
        profile,
        turn,
        gateway,
        chat,
    })
}

#[derive(Debug)]
struct CaseReport {
    profile: VitaAgentRuntimeProfile,
    turn: Result<TurnResult, String>,
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
    let success = run_case(Some(ChatMockMode::Success), true)
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
        success_gateway.response_path.as_deref(),
        Some("responses-sse")
    );
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
        Some(true)
    );
    assert!(success_chat
        .body
        .as_ref()
        .and_then(|body| body.get("tools"))
        .is_none());
    println!(
        "D29-F PASS codex_gateway={} codex_path=/v1/responses chat_gateway={} chat_path=/v1/chat/completions codex_requests={} chat_requests={} selected_model={} terminal_output={} external_endpoint_calls=0 listeners_shutdown=true",
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
        D29F_REPLY
    );

    let malformed = run_case(Some(ChatMockMode::MalformedBody), true)
        .await
        .expect("D29-F malformed case should run");
    assert_case_failed(&malformed, "invalid chat completion JSON");
    assert_eq!(malformed.gateway.as_ref().unwrap().request_count, 1);
    assert_eq!(malformed.chat.as_ref().unwrap().request_count, 1);

    let tool_call = run_case(Some(ChatMockMode::UnexpectedToolCall), true)
        .await
        .expect("D29-F tool-call case should run");
    assert_case_failed(&tool_call, "tools");
    assert_eq!(tool_call.gateway.as_ref().unwrap().request_count, 1);
    assert_eq!(tool_call.chat.as_ref().unwrap().request_count, 1);

    let timeout_case = run_case(Some(ChatMockMode::Delayed), true)
        .await
        .expect("D29-F timeout case should run");
    assert_case_failed(&timeout_case, "timed out");
    assert!(timeout_case.turn.as_ref().err().is_none());
    assert!(timeout_case.gateway.as_ref().unwrap().request_count <= 1);
    assert_eq!(timeout_case.chat.as_ref().unwrap().request_count, 1);

    let unavailable = run_case(None, true)
        .await
        .expect("D29-F unavailable-provider case should run");
    assert_case_failed(&unavailable, "transport error");
    assert_eq!(unavailable.gateway.as_ref().unwrap().request_count, 1);
    assert!(unavailable.chat.is_none());

    let not_ready = run_case(Some(ChatMockMode::Success), false)
        .await
        .expect("D29-F not-ready gateway case should run");
    assert_case_failed(&not_ready, "503");
    assert!(not_ready.gateway.is_none());
    assert_eq!(not_ready.chat.as_ref().unwrap().request_count, 0);

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
    assert_eq!(canary_before, host_canary());
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
