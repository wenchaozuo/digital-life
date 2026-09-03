#![allow(dead_code)]

//! D29-G2's explicitly authorized real-provider smoke.
//!
//! This module is ignored by the ordinary deterministic test suite and is
//! executed only when the caller supplies the four explicit `VITA_D29G2_*`
//! inputs.  It owns the loopback Responses listener, drives the real pinned
//! Codex APIs, and uses the certified production HTTPS transport for exactly
//! one provider request.  It never reads ambient provider credentials or
//! Codex configuration.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use codex_core_api::{
    CodexAppsToolsCache, CodexAuth, EnvironmentManager, EventMsg, Op, SessionSource,
    StartThreadOptions, ThreadId, ThreadManager, TurnInputRequest, UserInput,
};
use serde_json::{json, Value};
use tempfile::{tempdir, TempDir};

use super::{
    production_transport::ProductionTransportObservation, CredentialRef, CredentialResolver,
    GatewayReadyProvider, ProviderCapabilities, ProviderGateway, ProviderInstructionRolePolicy,
    ProviderModelIdentityPolicy, ProviderProfile, ProviderProtocol, ProviderRequestTransport,
    ProviderRetryPolicy, ResolvedCredential, VitaAgentError, VitaGatewayBinding, VitaMessage,
    VitaMessageRole, VitaProviderState, VitaResponsesRequest, VitaResponsesRequestOptions,
};
use crate::{
    ProviderErrorDetail, VitaAgentEntrypoint, VitaAgentRuntimeProfile, VITA_AGENT_RUNTIME_ID,
    VITA_GATEWAY_PROVIDER_ID,
};

const D29G2_PROVIDER_ID_ENV: &str = "VITA_D29G2_PROVIDER_ID";
const D29G2_BASE_URL_ENV: &str = "VITA_D29G2_BASE_URL";
const D29G2_MODEL_ENV: &str = "VITA_D29G2_MODEL";
const D29G2_API_KEY_ENV: &str = "VITA_D29G2_API_KEY";
const D29G2_PROBE_PROMPT: &str = "Reply exactly with VITA_D29G2_PROBE_OK.";
const D29G2_ROLE_PROMPT: &str = "Reply exactly with VITA_D29G2_ROLE_OK.";
const D29G2_PROMPT: &str = "Reply exactly with VITA_D29G2_OK.";
const D29G2_REPLY: &str = "VITA_D29G2_OK";
const D29G2_PROVIDER_TIMEOUT: Duration = Duration::from_secs(30);
const D29G2_TURN_TIMEOUT: Duration = Duration::from_secs(45);
const D29G2_STARTUP_TIMEOUT: Duration = Duration::from_secs(15);
const D29G2_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const D29G2_HTTP_MAX_BODY: usize = 2 * 1024 * 1024;
const D29G2_TEST_STACK_SIZE: usize = 32 * 1024 * 1024;

#[derive(Debug)]
struct G2Inputs {
    provider_id: String,
    base_url: String,
    model: String,
    credential_ref: CredentialRef,
    credential: ResolvedCredential,
}

fn required_non_secret_input(name: &str) -> Result<String, String> {
    let value = std::env::var(name).map_err(|_| format!("explicit G2 input required: {name}"))?;
    if value.trim().is_empty() {
        return Err(format!("explicit G2 input required: {name}"));
    }
    Ok(value)
}

fn load_inputs() -> Result<G2Inputs, String> {
    let provider_id = required_non_secret_input(D29G2_PROVIDER_ID_ENV)?;
    let base_url = required_non_secret_input(D29G2_BASE_URL_ENV)?;
    let model = required_non_secret_input(D29G2_MODEL_ENV)?;
    let credential = std::env::var(D29G2_API_KEY_ENV)
        .map(ResolvedCredential::new)
        .map_err(|_| "EXPLICIT TEST KEY REQUIRED: VITA_D29G2_API_KEY".to_string())?;
    let credential_ref = CredentialRef::new("d29g2-temporary-runtime", &provider_id, &base_url)
        .map_err(|_| "explicit G2 credential binding is invalid".to_string())?;

    Ok(G2Inputs {
        provider_id,
        base_url,
        model,
        credential_ref,
        credential,
    })
}

#[derive(Clone, PartialEq, Eq)]
enum CodexFileState {
    Absent,
    Present {
        size: u64,
        modified: Option<SystemTime>,
    },
    Unavailable,
}

#[derive(Clone, PartialEq, Eq)]
struct UserCodexState {
    config: CodexFileState,
    auth: CodexFileState,
    global_state: CodexFileState,
}

#[derive(Clone, PartialEq, Eq)]
struct G2Canary {
    user_codex_state: UserCodexState,
    provider_id: Option<String>,
    base_url: Option<String>,
    model: Option<String>,
    key_present: bool,
}

impl std::fmt::Debug for G2Canary {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("G2Canary(<redacted>)")
    }
}

fn g2_canary() -> G2Canary {
    G2Canary {
        user_codex_state: snapshot_user_codex_state(),
        provider_id: std::env::var(D29G2_PROVIDER_ID_ENV).ok(),
        base_url: std::env::var(D29G2_BASE_URL_ENV).ok(),
        model: std::env::var(D29G2_MODEL_ENV).ok(),
        // Presence is enough to prove that the test did not remove or add the
        // temporary variable.  Its value is never copied into the canary.
        key_present: std::env::var_os(D29G2_API_KEY_ENV).is_some(),
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

fn snapshot_user_codex_file(root: Option<&Path>, file_name: &str) -> CodexFileState {
    let Some(root) = root else {
        return CodexFileState::Unavailable;
    };
    match std::fs::symlink_metadata(root.join(file_name)) {
        Ok(metadata) => CodexFileState::Present {
            size: metadata.len(),
            modified: metadata.modified().ok(),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => CodexFileState::Absent,
        Err(_) => CodexFileState::Unavailable,
    }
}

fn assert_canary_unchanged(before: &G2Canary, after: &G2Canary) -> Result<(), String> {
    if before != after {
        return Err(
            "G2 canary changed user Codex metadata or explicit G2 input presence".to_string(),
        );
    }
    Ok(())
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

#[derive(Debug, Default, Clone)]
struct GatewayObservation {
    bind: Option<String>,
    request_count: usize,
    peer_is_loopback: bool,
    method: Option<String>,
    target: Option<String>,
    codex_authorization_present: bool,
    request_model: Option<String>,
    input_item_count: usize,
    deterministic_prompt_seen: bool,
    developer_role_present: bool,
    parallel_tool_calls: Option<bool>,
    reasoning_handling: ResponsesFieldHandling,
    stream_options_handling: ResponsesFieldHandling,
    text_handling: ResponsesFieldHandling,
    response_path: Option<String>,
    terminal_response_emitted: bool,
    provider_output_expected: bool,
    provider_finish_reason: Option<String>,
    provider_usage: Option<UsageObservation>,
    provider_error_detail: Option<ProviderErrorDetail>,
    failure_class: Option<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UsageObservation {
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
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

struct G2GatewayServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    observation: Arc<Mutex<GatewayObservation>>,
    join: Option<JoinHandle<()>>,
}

impl G2GatewayServer {
    fn start<R, T>(
        listener: TcpListener,
        ready: GatewayReadyProvider,
        credential_resolver: R,
        transport: T,
        expected_model: String,
    ) -> Self
    where
        R: CredentialResolver + Send + 'static,
        T: ProviderRequestTransport + Send + 'static,
    {
        let address = listener.local_addr().expect("D29-G2 gateway address");
        listener
            .set_nonblocking(true)
            .expect("set D29-G2 gateway listener nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let observation = Arc::new(Mutex::new(GatewayObservation {
            bind: Some(format!("127.0.0.1:{}", address.port())),
            ..GatewayObservation::default()
        }));
        let stop_for_thread = Arc::clone(&stop);
        let observation_for_thread = Arc::clone(&observation);
        let gateway = ProviderGateway::new(ready, credential_resolver, transport);

        let join = thread::spawn(move || {
            let deadline = Instant::now() + D29G2_TURN_TIMEOUT;
            loop {
                if stop_for_thread.load(Ordering::Acquire) || Instant::now() >= deadline {
                    return;
                }
                match listener.accept() {
                    Ok((mut stream, peer)) => {
                        {
                            let mut observed = observation_for_thread
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            observed.request_count = observed.request_count.saturating_add(1);
                            observed.peer_is_loopback = peer.ip().is_loopback();
                        }
                        handle_gateway_request(
                            &mut stream,
                            peer,
                            &gateway,
                            &observation_for_thread,
                            &expected_model,
                        );
                        return;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => {
                        set_failure(&observation_for_thread, "OTHER");
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

impl Drop for G2GatewayServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        wake_loopback_listener(self.address);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[derive(Debug, Default)]
struct ParsedResponsesRequest {
    request: Option<VitaResponsesRequest>,
    model: Option<String>,
    input_item_count: usize,
    deterministic_prompt_seen: bool,
    developer_role_present: bool,
    parallel_tool_calls: Option<bool>,
    reasoning_handling: ResponsesFieldHandling,
    stream_options_handling: ResponsesFieldHandling,
    text_handling: ResponsesFieldHandling,
}

fn handle_gateway_request<T, R>(
    stream: &mut TcpStream,
    peer: SocketAddr,
    gateway: &ProviderGateway<R, T>,
    observation: &Arc<Mutex<GatewayObservation>>,
    expected_model: &str,
) where
    R: CredentialResolver,
    T: ProviderRequestTransport,
{
    let request = match read_http_request(stream) {
        Ok(request) => request,
        Err(_) => {
            set_failure(observation, "OTHER");
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
        set_failure(observation, "OTHER");
        let _ = write_http_response(stream, "403 Forbidden", "text/plain", b"loopback only");
        return;
    }
    if request.method != "POST" || request.target != "/v1/responses" {
        set_failure(observation, "OTHER");
        let _ = write_http_response(stream, "404 Not Found", "text/plain", b"unsupported path");
        return;
    }

    let parsed = match parse_codex_responses_request(&request.body, expected_model) {
        Ok(parsed) => parsed,
        Err(error) => {
            let failure_class = classify_parser_failure(&error);
            set_failure(observation, failure_class);
            let _ = write_failed_responses(stream, expected_model, b"Codex request rejected");
            return;
        }
    };
    {
        let mut observed = observation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        observed.request_model = parsed.model.clone();
        observed.input_item_count = parsed.input_item_count;
        observed.deterministic_prompt_seen = parsed.deterministic_prompt_seen;
        observed.developer_role_present = parsed.developer_role_present;
        observed.parallel_tool_calls = parsed.parallel_tool_calls;
        observed.reasoning_handling = parsed.reasoning_handling;
        observed.stream_options_handling = parsed.stream_options_handling;
        observed.text_handling = parsed.text_handling;
    }

    let Some(parsed_request) = parsed.request.as_ref() else {
        set_failure(observation, "OTHER");
        let _ = write_failed_responses(stream, expected_model, b"Codex request rejected");
        return;
    };
    match gateway.execute_responses_request(parsed_request) {
        Ok(result) => {
            if result.output_text != D29G2_REPLY {
                let mut observed = observation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                observed.provider_output_expected = false;
                observed.failure_class = Some("OTHER");
                drop(observed);
                let _ = write_failed_responses(
                    stream,
                    expected_model,
                    b"non-deterministic provider output",
                );
                return;
            }
            {
                let mut observed = observation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                observed.provider_output_expected = true;
                observed.provider_finish_reason = result.finish_reason.clone();
                observed.provider_usage = result.usage.as_ref().map(|usage| UsageObservation {
                    input_tokens: usage.input_tokens,
                    output_tokens: usage.output_tokens,
                    total_tokens: usage.total_tokens,
                });
                observed.response_path = Some("responses-sse".to_string());
            }
            if write_success_responses(stream, &result).is_ok() {
                observation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .terminal_response_emitted = true;
            }
        }
        Err(error) => {
            let failure_class = classify_provider_failure(&error);
            let provider_error_detail = match &error {
                VitaAgentError::ProviderHttpStatus { detail, .. } => detail.clone(),
                _ => None,
            };
            let mut observed = observation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            observed.provider_error_detail = provider_error_detail;
            observed.failure_class = Some(failure_class);
            drop(observed);
            let _ = write_failed_responses(stream, expected_model, b"provider smoke failed");
        }
    }
}

fn set_failure(observation: &Arc<Mutex<GatewayObservation>>, failure_class: &'static str) {
    observation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .failure_class = Some(failure_class);
}

fn classify_parser_failure(error: &str) -> &'static str {
    if error.contains("unsupported Responses") || error.contains("unsupported input") {
        "UNSUPPORTED_CODEX_SEMANTIC_FIELD"
    } else {
        "OTHER"
    }
}

fn classify_provider_failure(error: &VitaAgentError) -> &'static str {
    match error {
        VitaAgentError::ProviderHttpStatus { status: 401, .. } => "HTTP_401",
        VitaAgentError::ProviderHttpStatus { status: 403, .. } => "HTTP_403",
        VitaAgentError::ProviderHttpStatus { status: 404, .. } => "HTTP_404",
        VitaAgentError::ProviderHttpStatus { status: 408, .. } => "HTTP_408",
        VitaAgentError::ProviderHttpStatus { status: 429, .. } => "HTTP_429",
        VitaAgentError::ProviderHttpStatus { status, .. } if *status >= 500 => "HTTP_5XX",
        VitaAgentError::ProviderTransportTimeout { .. } => "TURN_TIMEOUT",
        VitaAgentError::CredentialResolution(_) => "CREDENTIAL_REJECTED",
        VitaAgentError::UnsupportedProviderCapability { .. }
        | VitaAgentError::UnsupportedGatewayCapability { .. } => "UNSUPPORTED_CODEX_SEMANTIC_FIELD",
        VitaAgentError::GatewayProtocol(message)
            if message.contains("invalid chat completion JSON") =>
        {
            "MALFORMED_RESPONSE"
        }
        VitaAgentError::GatewayProtocol(message)
            if message.contains("response model") || message.contains("exactly one choice") =>
        {
            "CHAT_COMPLETIONS_INCOMPATIBLE"
        }
        VitaAgentError::ProviderTransportRejected { reason }
            if reason.contains("DNS") || reason.contains("destination") =>
        {
            "DNS_POLICY_REJECTED"
        }
        _ => "OTHER",
    }
}

fn parse_codex_responses_request(
    body: &[u8],
    expected_model: &str,
) -> Result<ParsedResponsesRequest, String> {
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| "malformed Codex Responses request JSON".to_string())?;
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
        .ok_or_else(|| "Responses request model must be a non-empty string".to_string())?
        .to_string();
    if model != expected_model {
        return Err("Responses request model did not match explicit G2 model".to_string());
    }

    let mut messages = Vec::new();
    if let Some(instructions) = object.get("instructions") {
        let instructions = instructions
            .as_str()
            .ok_or_else(|| "Responses instructions must be a string".to_string())?;
        if !instructions.is_empty() {
            messages.push(VitaMessage::text(VitaMessageRole::System, instructions));
        }
    }

    let input = object
        .get("input")
        .and_then(Value::as_array)
        .ok_or_else(|| "Responses input must be an array".to_string())?;
    let mut deterministic_prompt_seen = false;
    let mut developer_role_present = false;
    for (index, item) in input.iter().enumerate() {
        let item_object = item
            .as_object()
            .ok_or_else(|| format!("unsupported input item at index {index}"))?;
        if item_object.get("type").and_then(Value::as_str) != Some("message") {
            return Err(format!("unsupported input item type at index {index}"));
        }
        let role = match item_object.get("role").and_then(Value::as_str) {
            Some("system") => VitaMessageRole::System,
            Some("developer") => {
                developer_role_present = true;
                VitaMessageRole::Developer
            }
            Some("user") => VitaMessageRole::User,
            Some("assistant") => VitaMessageRole::Assistant,
            _ => {
                return Err(format!(
                    "unsupported Responses message role at index {index}"
                ))
            }
        };
        let content = item_object
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                format!("Responses message content must be an array at index {index}")
            })?;
        let mut text = String::new();
        for content_item in content {
            let content_object = content_item
                .as_object()
                .ok_or_else(|| "unsupported Responses content item".to_string())?;
            let content_type = content_object
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| "Responses content item type is missing".to_string())?;
            if !matches!(content_type, "input_text" | "output_text") {
                return Err(format!(
                    "unsupported Responses content item type: {content_type}"
                ));
            }
            text.push_str(
                content_object
                    .get("text")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "Responses text content must be a string".to_string())?,
            );
        }
        deterministic_prompt_seen |= text == D29G2_PROMPT;
        messages.push(VitaMessage::text(role, text));
    }

    let tools = object.get("tools").unwrap_or(&Value::Null);
    if !tools.is_null() && !tools.as_array().is_some_and(|tools| tools.is_empty()) {
        return Err("unsupported Responses request field: tools".to_string());
    }
    let tool_choice = object
        .get("tool_choice")
        .and_then(Value::as_str)
        .unwrap_or("auto");
    if tool_choice != "auto" {
        return Err("unsupported Responses request field: tool_choice".to_string());
    }
    let parallel_tool_calls = object
        .get("parallel_tool_calls")
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| "unsupported parallel_tool_calls value".to_string())
        })
        .transpose()?;
    if object.get("stream").and_then(Value::as_bool) != Some(true) {
        return Err("G2 requires Codex Responses streaming".to_string());
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
            return Err("unsupported Responses request field: include".to_string());
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
            return Err("unsupported Responses request field: client_metadata".to_string());
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
                stream: true,
                parallel_tools: parallel_tool_calls.unwrap_or(false),
                ..VitaResponsesRequestOptions::default()
            },
        )),
        model: Some(model),
        input_item_count: input.len(),
        deterministic_prompt_seen,
        developer_role_present,
        parallel_tool_calls,
        reasoning_handling,
        stream_options_handling,
        text_handling,
    })
}

fn validate_reasoning_control(value: &Value) -> Result<ResponsesFieldHandling, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "unsupported Responses reasoning control".to_string())?;
    if object.is_empty() {
        return Ok(ResponsesFieldHandling::EmptyObjectInert);
    }
    // This is the one narrowly proven pinned-Codex default reused by G2.  It
    // carries no reasoning request for this text-only smoke, and the current
    // Chat adapter has no corresponding control to forward.
    if object.len() == 1 && object.get("summary").and_then(Value::as_str) == Some("auto") {
        return Ok(ResponsesFieldHandling::DefaultSummaryAutoInert);
    }
    Err("unsupported Responses reasoning control".to_string())
}

fn validate_stream_options(value: &Value) -> Result<ResponsesFieldHandling, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "unsupported Responses stream control".to_string())?;
    if object.len() == 1
        && object
            .get("reasoning_summary_delivery")
            .and_then(Value::as_str)
            == Some("sequential_cutoff")
    {
        return Ok(ResponsesFieldHandling::SequentialCutoffInert);
    }
    Err("unsupported Responses stream control".to_string())
}

fn validate_text_control(value: &Value) -> Result<ResponsesFieldHandling, String> {
    let object = value
        .as_object()
        .ok_or_else(|| "unsupported Responses text control".to_string())?;
    if object.is_empty() {
        return Ok(ResponsesFieldHandling::EmptyObjectInert);
    }
    Err("unsupported Responses text control".to_string())
}

fn validate_optional_string_field(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<(), String> {
    if let Some(value) = object.get(key).filter(|value| !value.is_null()) {
        if !value.is_string() {
            return Err(format!("unsupported Responses request field: {key}"));
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
        "id": "msg-d29g2",
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": D29G2_REPLY}]
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
            "item": {"type": "message", "id": "msg-d29g2", "role": "assistant", "status": "in_progress", "content": []}
        }),
        json!({"type": "response.content_part.added"}),
        json!({"type": "response.output_text.delta", "delta": D29G2_REPLY}),
        json!({"type": "response.output_text.done", "text": D29G2_REPLY}),
        json!({"type": "response.content_part.done"}),
        json!({"type": "response.output_item.done", "item": item}),
        json!({"type": "response.completed", "response": completed_response}),
    ];
    let mut body = String::new();
    for event in events {
        let event_type = event
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| "D29-G2 SSE event omitted type".to_string())?;
        body.push_str("event: ");
        body.push_str(event_type);
        body.push_str("\ndata: ");
        body.push_str(
            &serde_json::to_string(&event)
                .map_err(|_| "D29-G2 SSE event serialization failed".to_string())?,
        );
        body.push_str("\n\n");
    }
    write_http_response(stream, "200 OK", "text/event-stream", body.as_bytes())
}

fn write_failed_responses(
    stream: &mut TcpStream,
    model: &str,
    message: &[u8],
) -> Result<(), String> {
    let message = std::str::from_utf8(message).unwrap_or("G2 request failed");
    let events = [
        json!({
            "type": "response.created",
            "response": {"id": "resp-d29g2-failed", "object": "response", "status": "in_progress", "model": model}
        }),
        json!({
            "type": "response.failed",
            "response": {
                "id": "resp-d29g2-failed",
                "error": {"type": "invalid_request_error", "code": "invalid_prompt", "message": message}
            }
        }),
    ];
    let mut body = String::new();
    for event in events {
        let event_type = event
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| "D29-G2 failure SSE event omitted type".to_string())?;
        body.push_str("event: ");
        body.push_str(event_type);
        body.push_str("\ndata: ");
        body.push_str(
            &serde_json::to_string(&event)
                .map_err(|_| "D29-G2 failure SSE serialization failed".to_string())?,
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
        .set_write_timeout(Some(D29G2_CLEANUP_TIMEOUT))
        .map_err(|_| "D29-G2 HTTP write timeout setup failed".to_string())?;
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|_| "D29-G2 HTTP response write failed".to_string())
}

fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, String> {
    stream
        .set_read_timeout(Some(D29G2_CLEANUP_TIMEOUT))
        .map_err(|_| "D29-G2 HTTP read timeout setup failed".to_string())?;
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut buffer = [0_u8; 4096];
        let read = stream
            .read(&mut buffer)
            .map_err(|_| "D29-G2 HTTP header read failed".to_string())?;
        if read == 0 {
            return Err("D29-G2 HTTP peer closed before headers".to_string());
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > D29G2_HTTP_MAX_BODY {
            return Err("D29-G2 HTTP request exceeded size bound".to_string());
        }
        if let Some(end) = find_header_end(&bytes) {
            break end;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "D29-G2 HTTP headers were not UTF-8".to_string())?;
    let mut lines = header_text.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "D29-G2 HTTP request omitted request line".to_string())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| "D29-G2 HTTP request omitted method".to_string())?
        .to_string();
    let target = request_parts
        .next()
        .ok_or_else(|| "D29-G2 HTTP request omitted target".to_string())?
        .to_string();
    let mut headers = Vec::new();
    let mut content_length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "D29-G2 HTTP header omitted colon".to_string())?;
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| "D29-G2 HTTP content length was invalid".to_string())?,
            );
        }
        headers.push((name.trim().to_string(), value));
    }
    let content_length =
        content_length.ok_or_else(|| "D29-G2 HTTP request omitted content length".to_string())?;
    if content_length > D29G2_HTTP_MAX_BODY {
        return Err("D29-G2 HTTP request body exceeded size bound".to_string());
    }
    let body_start = header_end + 4;
    let total = body_start.saturating_add(content_length);
    while bytes.len() < total {
        let mut buffer = [0_u8; 4096];
        let read = stream
            .read(&mut buffer)
            .map_err(|_| "D29-G2 HTTP body read failed".to_string())?;
        if read == 0 {
            return Err("D29-G2 HTTP peer closed before request body".to_string());
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > total {
            break;
        }
    }
    if bytes.len() < total {
        return Err("D29-G2 HTTP request body was truncated".to_string());
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

fn join_listener_thread(join: JoinHandle<()>) -> bool {
    let started = Instant::now();
    let joined = join.join().is_ok();
    joined && started.elapsed() <= D29G2_CLEANUP_TIMEOUT
}

struct G2CredentialResolver {
    reference: CredentialRef,
    credential: ResolvedCredential,
}

impl CredentialResolver for G2CredentialResolver {
    fn resolve(
        &self,
        credential_ref: &CredentialRef,
    ) -> Result<ResolvedCredential, VitaAgentError> {
        if credential_ref != &self.reference {
            return Err(VitaAgentError::CredentialResolution(
                "explicit G2 credential binding was not found",
            ));
        }
        Ok(ResolvedCredential::new(self.credential.as_str()))
    }
}

struct G2Runtime {
    _app_data: TempDir,
    _workspace: TempDir,
    manager: Arc<ThreadManager>,
    thread: Option<Arc<codex_core_api::CodexThread>>,
    thread_id: Option<ThreadId>,
    gateway: Option<G2GatewayServer>,
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
    gateway_listener_joined: bool,
}

#[derive(Debug)]
struct RuntimeShutdown {
    cleanup: CleanupEvidence,
    gateway: GatewayObservation,
}

impl G2Runtime {
    async fn shutdown(mut self, turn_interrupt_submitted: bool) -> Result<RuntimeShutdown, String> {
        let mut initial_shutdown = ShutdownStatus::NotAttempted;
        let mut interrupt_submitted = turn_interrupt_submitted;
        let mut final_shutdown = ShutdownStatus::NotAttempted;

        if let Some(thread) = self.thread.take() {
            initial_shutdown = shutdown_thread_once(&thread).await;
            if initial_shutdown != ShutdownStatus::Success {
                interrupt_submitted |= submit_interrupt_bounded(&thread).await;
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
        let (gateway, gateway_listener_joined) = match self.gateway.take() {
            Some(gateway) => gateway.shutdown(),
            None => (GatewayObservation::default(), true),
        };
        let cleanup = CleanupEvidence {
            initial_shutdown,
            interrupt_submitted,
            final_shutdown,
            manager_thread_count,
            gateway_listener_joined,
        };
        if cleanup.final_shutdown != ShutdownStatus::Success
            || cleanup.manager_thread_count != 0
            || !cleanup.gateway_listener_joined
        {
            return Err("D29-G2 bounded cleanup failed".to_string());
        }
        Ok(RuntimeShutdown { cleanup, gateway })
    }
}

#[derive(Debug, Clone)]
struct TurnResult {
    elapsed: Duration,
    assistant_output_expected: bool,
    terminal_output_expected: bool,
    terminal_error_present: bool,
    event_count: usize,
    turn_timed_out: bool,
    interrupt_submitted: bool,
}

async fn shutdown_thread_once(thread: &Arc<codex_core_api::CodexThread>) -> ShutdownStatus {
    match tokio::time::timeout(D29G2_CLEANUP_TIMEOUT, thread.shutdown_and_wait()).await {
        Ok(Ok(())) => ShutdownStatus::Success,
        Ok(Err(_)) => ShutdownStatus::Failed,
        Err(_) => ShutdownStatus::TimedOut,
    }
}

async fn submit_interrupt_bounded(thread: &Arc<codex_core_api::CodexThread>) -> bool {
    matches!(
        tokio::time::timeout(D29G2_CLEANUP_TIMEOUT, thread.submit(Op::Interrupt)).await,
        Ok(Ok(_))
    )
}

async fn collect_turn(thread: &Arc<codex_core_api::CodexThread>) -> Result<TurnResult, String> {
    let start = Instant::now();
    let deadline = start + D29G2_TURN_TIMEOUT;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        let interrupt_submitted = submit_interrupt_bounded(thread).await;
        return Ok(TurnResult {
            elapsed: start.elapsed(),
            assistant_output_expected: false,
            terminal_output_expected: false,
            terminal_error_present: true,
            event_count: 0,
            turn_timed_out: true,
            interrupt_submitted,
        });
    }
    match tokio::time::timeout(
        remaining,
        thread.start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: D29G2_PROMPT.to_string(),
            text_elements: Vec::new(),
        }])),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(_)) => return Err("D29-G2 turn submission failed".to_string()),
        Err(_) => {
            let interrupt_submitted = submit_interrupt_bounded(thread).await;
            return Ok(TurnResult {
                elapsed: start.elapsed(),
                assistant_output_expected: false,
                terminal_output_expected: false,
                terminal_error_present: true,
                event_count: 0,
                turn_timed_out: true,
                interrupt_submitted,
            });
        }
    }

    let mut assistant_output_expected = false;
    let mut event_count = 0;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let interrupt_submitted = submit_interrupt_bounded(thread).await;
            return Ok(TurnResult {
                elapsed: start.elapsed(),
                assistant_output_expected,
                terminal_output_expected: false,
                terminal_error_present: true,
                event_count,
                turn_timed_out: true,
                interrupt_submitted,
            });
        }
        let event = match tokio::time::timeout(remaining, thread.next_event()).await {
            Ok(Ok(event)) => event,
            Ok(Err(_)) => return Err("D29-G2 event stream failed".to_string()),
            Err(_) => {
                let interrupt_submitted = submit_interrupt_bounded(thread).await;
                return Ok(TurnResult {
                    elapsed: start.elapsed(),
                    assistant_output_expected,
                    terminal_output_expected: false,
                    terminal_error_present: true,
                    event_count,
                    turn_timed_out: true,
                    interrupt_submitted,
                });
            }
        };
        event_count += 1;
        match event.msg {
            EventMsg::AgentMessage(message) => {
                assistant_output_expected |= message.message == D29G2_REPLY;
            }
            EventMsg::TurnComplete(complete) => {
                return Ok(TurnResult {
                    elapsed: start.elapsed(),
                    assistant_output_expected,
                    terminal_output_expected: complete.last_agent_message.as_deref()
                        == Some(D29G2_REPLY),
                    terminal_error_present: complete.error.is_some(),
                    event_count,
                    turn_timed_out: false,
                    interrupt_submitted: false,
                });
            }
            _ => {}
        }
    }
}

#[derive(Debug)]
struct MinimalProbeEvidence {
    provider_status: u16,
    provider_attempt_count: usize,
    response_is_valid_chat_completion: bool,
    provider_failure_class: Option<&'static str>,
    error_detail: Option<ProviderErrorDetail>,
}

fn run_minimal_provider_probe(inputs: &G2Inputs) -> Result<MinimalProbeEvidence, String> {
    let provider = ProviderProfile::new(
        inputs.provider_id.clone(),
        format!("D29-G2-R1 probe {}", inputs.provider_id),
        ProviderProtocol::OpenAiChatCompletions,
        &inputs.base_url,
        inputs.model.clone(),
        Some(inputs.credential_ref.clone()),
        D29G2_PROVIDER_TIMEOUT,
        ProviderRetryPolicy::default(),
        ProviderCapabilities::none(),
    )
    .map_err(|_| "minimal probe provider profile validation failed".to_string())?;
    let authority = super::VitaProviderAuthority::configure(provider)
        .map_err(|_| "minimal probe provider configuration failed".to_string())?;
    let reservation = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "minimal probe listener reservation failed".to_string())?;
    let binding = VitaGatewayBinding::for_owned_private_listener(
        reservation
            .local_addr()
            .map_err(|_| "minimal probe listener address failed".to_string())?
            .port(),
    )
    .map_err(|_| "minimal probe gateway binding failed".to_string())?;
    let ready = authority
        .prepare_gateway(binding)
        .map_err(|_| "minimal probe gateway preparation failed".to_string())?;
    drop(reservation);

    let (transport, transport_observation) = super::production_transport::new_for_d29g2()
        .map_err(|_| "minimal probe production transport creation failed".to_string())?;
    let gateway = ProviderGateway::new(
        ready,
        G2CredentialResolver {
            reference: inputs.credential_ref.clone(),
            credential: ResolvedCredential::new(inputs.credential.as_str()),
        },
        transport,
    );
    let request = VitaResponsesRequest::new(
        inputs.model.clone(),
        vec![VitaMessage::text(VitaMessageRole::User, D29G2_PROBE_PROMPT)],
        VitaResponsesRequestOptions::default(),
    );
    let result = gateway.execute_responses_request(&request);
    let error_detail = match &result {
        Err(VitaAgentError::ProviderHttpStatus { detail, .. }) => detail.clone(),
        _ => None,
    };
    let provider_failure_class = result.as_ref().err().map(classify_provider_failure);
    let provider_status = transport_observation.last_status.load(Ordering::Acquire);
    let provider_attempt_count = transport_observation.attempt_count.load(Ordering::Acquire);

    Ok(MinimalProbeEvidence {
        provider_status,
        provider_attempt_count,
        response_is_valid_chat_completion: result.is_ok(),
        provider_failure_class,
        error_detail,
    })
}

fn print_minimal_probe_report(evidence: &MinimalProbeEvidence) {
    let detail = evidence.error_detail.as_ref();
    println!(
        "D29-G2-R1 MINIMAL_PROVIDER_PROBE status={} provider_requests={} valid_chat_completion={} provider_failure_class={} provider_error_code={} provider_error_type={} provider_error_param={} provider_error_message={} raw_credential_logged=NO",
        evidence.provider_status,
        evidence.provider_attempt_count,
        evidence.response_is_valid_chat_completion,
        evidence.provider_failure_class.unwrap_or("none"),
        detail.and_then(ProviderErrorDetail::code).unwrap_or("none"),
        detail.and_then(ProviderErrorDetail::kind).unwrap_or("none"),
        detail.and_then(ProviderErrorDetail::param).unwrap_or("none"),
        detail.and_then(ProviderErrorDetail::message).unwrap_or("none"),
    );
}

#[derive(Debug)]
struct RoleDiagnosticEvidence {
    label: &'static str,
    provider_status: u16,
    provider_attempt_count: usize,
    error_detail: Option<ProviderErrorDetail>,
}

fn run_role_probe(
    inputs: &G2Inputs,
    label: &'static str,
    messages: Vec<VitaMessage>,
) -> Result<RoleDiagnosticEvidence, String> {
    let provider = ProviderProfile::new(
        inputs.provider_id.clone(),
        format!("D29-G2-R2 role matrix {}", inputs.provider_id),
        ProviderProtocol::OpenAiChatCompletions,
        &inputs.base_url,
        inputs.model.clone(),
        Some(inputs.credential_ref.clone()),
        D29G2_PROVIDER_TIMEOUT,
        ProviderRetryPolicy::default(),
        ProviderCapabilities {
            developer_role: true,
            ..ProviderCapabilities::none()
        },
    )
    .map_err(|_| "role matrix provider profile validation failed".to_string())?;
    let endpoint = provider.endpoint.clone();
    let request = VitaResponsesRequest::new(
        inputs.model.clone(),
        messages,
        VitaResponsesRequestOptions::default(),
    );
    let mapped = super::map_responses_request_to_chat(&request, &provider)
        .map_err(|_| format!("role matrix {label} request mapping failed"))?;
    let body = serde_json::to_vec(&mapped)
        .map_err(|_| format!("role matrix {label} request serialization failed"))?;
    let (transport, observation) = super::production_transport::new_for_d29g2()
        .map_err(|_| "role matrix production transport creation failed".to_string())?;
    let credential = G2CredentialResolver {
        reference: inputs.credential_ref.clone(),
        credential: ResolvedCredential::new(inputs.credential.as_str()),
    }
    .resolve(&inputs.credential_ref)
    .map_err(|_| "role matrix credential binding failed".to_string())?;
    let result = transport.post_json(
        &endpoint,
        Some(&credential),
        &body,
        provider.timeout(),
        provider.retry_policy(),
    );
    let error_detail = match &result {
        Err(VitaAgentError::ProviderHttpStatus { detail, .. }) => detail.clone(),
        _ => None,
    };
    drop(result);
    Ok(RoleDiagnosticEvidence {
        label,
        provider_status: observation.last_status.load(Ordering::Acquire),
        provider_attempt_count: observation.attempt_count.load(Ordering::Acquire),
        error_detail,
    })
}

fn run_role_matrix(inputs: &G2Inputs) -> Result<Vec<RoleDiagnosticEvidence>, String> {
    let system_and_user = run_role_probe(
        inputs,
        "system+user",
        vec![
            VitaMessage::text(VitaMessageRole::System, D29G2_ROLE_PROMPT),
            VitaMessage::text(VitaMessageRole::User, D29G2_ROLE_PROMPT),
        ],
    )?;
    let developer_and_user = run_role_probe(
        inputs,
        "developer+user",
        vec![
            VitaMessage::text(VitaMessageRole::Developer, D29G2_ROLE_PROMPT),
            VitaMessage::text(VitaMessageRole::User, D29G2_ROLE_PROMPT),
        ],
    )?;
    Ok(vec![system_and_user, developer_and_user])
}

fn print_role_matrix_report(evidence: &[RoleDiagnosticEvidence]) {
    for result in evidence {
        let detail = result.error_detail.as_ref();
        println!(
            "D29-G2-R2 ROLE_MATRIX roles={} status={} provider_requests={} code={} message={} raw_response_logged=NO",
            result.label,
            result.provider_status,
            result.provider_attempt_count,
            detail
                .and_then(ProviderErrorDetail::code)
                .unwrap_or("none"),
            detail
                .and_then(ProviderErrorDetail::message)
                .unwrap_or("none"),
        );
    }
}

const MAX_STRUCTURAL_TEXT_CHARS: usize = 4_096;
const MAX_STRUCTURAL_LIST_ITEMS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum StructuralJsonType {
    #[default]
    InvalidJson,
    Object,
    Array,
    String,
    Number,
    Boolean,
    Null,
}

impl StructuralJsonType {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid-json",
            Self::Object => "object",
            Self::Array => "array",
            Self::String => "string",
            Self::Number => "number",
            Self::Boolean => "boolean",
            Self::Null => "null",
        }
    }
}

fn structural_json_type(value: &Value) -> StructuralJsonType {
    match value {
        Value::Object(_) => StructuralJsonType::Object,
        Value::Array(_) => StructuralJsonType::Array,
        Value::String(_) => StructuralJsonType::String,
        Value::Number(_) => StructuralJsonType::Number,
        Value::Bool(_) => StructuralJsonType::Boolean,
        Value::Null => StructuralJsonType::Null,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct StructuralField {
    present: bool,
    value_type: Option<StructuralJsonType>,
}

impl StructuralField {
    fn from_object(object: Option<&serde_json::Map<String, Value>>, name: &str) -> Self {
        object
            .and_then(|object| object.get(name))
            .map(|value| Self {
                present: true,
                value_type: Some(structural_json_type(value)),
            })
            .unwrap_or_default()
    }

    fn label(self) -> &'static str {
        if !self.present {
            "absent"
        } else {
            self.value_type
                .map(StructuralJsonType::as_str)
                .unwrap_or("unknown")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ContentStructure {
    String {
        bounded_length: usize,
        capped: bool,
    },
    Array {
        bounded_item_count: usize,
        capped: bool,
    },
    Null,
    Other(StructuralJsonType),
}

fn content_structure(value: &Value) -> ContentStructure {
    match value {
        Value::String(value) => {
            let length = value.chars().count();
            ContentStructure::String {
                bounded_length: length.min(MAX_STRUCTURAL_TEXT_CHARS),
                capped: length > MAX_STRUCTURAL_TEXT_CHARS,
            }
        }
        Value::Array(value) => ContentStructure::Array {
            bounded_item_count: value.len().min(MAX_STRUCTURAL_LIST_ITEMS),
            capped: value.len() > MAX_STRUCTURAL_LIST_ITEMS,
        },
        Value::Null => ContentStructure::Null,
        value => ContentStructure::Other(structural_json_type(value)),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct MessageStructure {
    role: StructuralField,
    content: StructuralField,
    reasoning_content: StructuralField,
    reasoning: StructuralField,
    tool_calls: StructuralField,
    content_detail: Option<ContentStructure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ChoiceStructure {
    index: StructuralField,
    message: StructuralField,
    delta: StructuralField,
    finish_reason: StructuralField,
    message_detail: Option<MessageStructure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ChoicesStructure {
    field: StructuralField,
    is_array: bool,
    bounded_length: Option<usize>,
    length_capped: bool,
    first_value_type: Option<StructuralJsonType>,
    first: Option<ChoiceStructure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ResponseStructure {
    top_level_type: StructuralJsonType,
    id: StructuralField,
    object: StructuralField,
    created: StructuralField,
    model: StructuralField,
    choices: ChoicesStructure,
    usage: StructuralField,
    code: StructuralField,
    message: StructuralField,
    data: StructuralField,
    error: StructuralField,
}

fn describe_response_structure(value: &Value) -> ResponseStructure {
    let top_level_type = structural_json_type(value);
    let Some(root) = value.as_object() else {
        return ResponseStructure {
            top_level_type,
            ..ResponseStructure::default()
        };
    };

    let choices_value = root.get("choices");
    let choices_array = choices_value.and_then(Value::as_array);
    let choices = ChoicesStructure {
        field: StructuralField::from_object(Some(root), "choices"),
        is_array: choices_array.is_some(),
        bounded_length: choices_array.map(|choices| choices.len().min(MAX_STRUCTURAL_LIST_ITEMS)),
        length_capped: choices_array
            .is_some_and(|choices| choices.len() > MAX_STRUCTURAL_LIST_ITEMS),
        first_value_type: choices_array
            .and_then(|choices| choices.first())
            .map(structural_json_type),
        first: choices_array
            .and_then(|choices| choices.first())
            .and_then(Value::as_object)
            .map(|choice| {
                let message_detail =
                    choice
                        .get("message")
                        .and_then(Value::as_object)
                        .map(|message| MessageStructure {
                            role: StructuralField::from_object(Some(message), "role"),
                            content: StructuralField::from_object(Some(message), "content"),
                            reasoning_content: StructuralField::from_object(
                                Some(message),
                                "reasoning_content",
                            ),
                            reasoning: StructuralField::from_object(Some(message), "reasoning"),
                            tool_calls: StructuralField::from_object(Some(message), "tool_calls"),
                            content_detail: message.get("content").map(content_structure),
                        });
                ChoiceStructure {
                    index: StructuralField::from_object(Some(choice), "index"),
                    message: StructuralField::from_object(Some(choice), "message"),
                    delta: StructuralField::from_object(Some(choice), "delta"),
                    finish_reason: StructuralField::from_object(Some(choice), "finish_reason"),
                    message_detail,
                }
            }),
    };

    ResponseStructure {
        top_level_type,
        id: StructuralField::from_object(Some(root), "id"),
        object: StructuralField::from_object(Some(root), "object"),
        created: StructuralField::from_object(Some(root), "created"),
        model: StructuralField::from_object(Some(root), "model"),
        choices,
        usage: StructuralField::from_object(Some(root), "usage"),
        code: StructuralField::from_object(Some(root), "code"),
        message: StructuralField::from_object(Some(root), "message"),
        data: StructuralField::from_object(Some(root), "data"),
        error: StructuralField::from_object(Some(root), "error"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct SseChunkStructure {
    id: StructuralField,
    object: StructuralField,
    created: StructuralField,
    model: StructuralField,
    choices: StructuralField,
    first_choice_index: StructuralField,
    first_choice_delta: StructuralField,
    first_choice_finish_reason: StructuralField,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct SseStructure {
    event_names: Vec<String>,
    chunk_count: usize,
    data_done: bool,
    first_chunk: Option<SseChunkStructure>,
}

fn safe_structural_text(value: &str, credential: Option<&str>) -> String {
    if credential.is_some_and(|credential| !credential.is_empty() && value.contains(credential)) {
        return "[redacted]".to_string();
    }
    value
        .chars()
        .take(MAX_STRUCTURAL_TEXT_CHARS)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

fn describe_sse_chunk(value: &Value) -> Option<SseChunkStructure> {
    let root = value.as_object()?;
    let choices = root.get("choices").and_then(Value::as_array);
    let first = choices
        .and_then(|choices| choices.first())
        .and_then(Value::as_object);
    Some(SseChunkStructure {
        id: StructuralField::from_object(Some(root), "id"),
        object: StructuralField::from_object(Some(root), "object"),
        created: StructuralField::from_object(Some(root), "created"),
        model: StructuralField::from_object(Some(root), "model"),
        choices: StructuralField::from_object(Some(root), "choices"),
        first_choice_index: StructuralField::from_object(first, "index"),
        first_choice_delta: StructuralField::from_object(first, "delta"),
        first_choice_finish_reason: StructuralField::from_object(first, "finish_reason"),
    })
}

fn describe_sse_response(body: &[u8], credential: Option<&str>) -> SseStructure {
    let mut structure = SseStructure::default();
    let text = String::from_utf8_lossy(body);
    for line in text.lines() {
        if let Some(event_name) = line.strip_prefix("event:") {
            if structure.event_names.len() < MAX_STRUCTURAL_LIST_ITEMS {
                structure
                    .event_names
                    .push(safe_structural_text(event_name.trim(), credential));
            }
            continue;
        }
        let Some(data) = line.strip_prefix("data:").map(str::trim) else {
            continue;
        };
        if data == "[DONE]" {
            structure.data_done = true;
            continue;
        }
        structure.chunk_count = structure.chunk_count.saturating_add(1);
        if structure.first_chunk.is_none() {
            if let Ok(value) = serde_json::from_str::<Value>(data) {
                structure.first_chunk = describe_sse_chunk(&value);
            }
        }
    }
    structure
}

fn classify_chat_response_structure(
    value: &Value,
    requested_model: &str,
    model_identity_policy: ProviderModelIdentityPolicy,
) -> &'static str {
    let Some(root) = value.as_object() else {
        return "top-level JSON is not an object";
    };
    if !root.get("id").is_some_and(Value::is_string) {
        return "id missing or not a string";
    }
    let Some(returned_model) = root.get("model").and_then(Value::as_str) else {
        return "model missing or not a string";
    };
    if !model_identity_policy.matches(requested_model, returned_model) {
        return "response model differs from requested model";
    }
    let Some(choices) = root.get("choices").and_then(Value::as_array) else {
        return "choices missing or not an array";
    };
    if choices.len() != 1 {
        return "choices length is not exactly one";
    }
    let Some(choice) = choices[0].as_object() else {
        return "choices[0] is not an object";
    };
    let Some(index) = choice.get("index").and_then(Value::as_u64) else {
        return "choices[0].index missing or not an unsigned integer";
    };
    if index > u32::MAX as u64 {
        return "choices[0].index exceeds u32";
    }
    let Some(message) = choice.get("message").and_then(Value::as_object) else {
        return "choices[0].message missing or not an object";
    };
    let Some(role) = message.get("role").and_then(Value::as_str) else {
        return "choices[0].message.role missing or not a string";
    };
    if role != "assistant" {
        return "choices[0].message.role is not assistant";
    }
    if let Some(content) = message.get("content") {
        if !content.is_string() && !content.is_null() {
            return "choices[0].message.content has an unexpected type";
        }
        if content.is_null()
            && ["reasoning_content", "reasoning"]
                .iter()
                .any(|field| message.get(*field).is_some_and(|value| !value.is_null()))
        {
            return "choices[0].message.content is null with a reasoning output field present";
        }
    }
    if let Some(tool_calls) = message.get("tool_calls") {
        let Some(tool_calls) = tool_calls.as_array() else {
            return "choices[0].message.tool_calls has an unexpected type";
        };
        if !tool_calls.is_empty() {
            return "choices[0].message.tool_calls returned";
        }
    }
    if let Some(usage) = root.get("usage").filter(|usage| !usage.is_null()) {
        let Some(usage) = usage.as_object() else {
            return "usage is not an object";
        };
        for field in ["prompt_tokens", "completion_tokens", "total_tokens"] {
            if !usage.get(field).and_then(Value::as_u64).is_some() {
                return "usage token field missing or not an unsigned integer";
            }
        }
    }

    let response = match serde_json::from_value::<super::ChatCompletionsResponse>(value.clone()) {
        Ok(response) => response,
        Err(_) => return "other exact Chat Completion structural mismatch",
    };
    match super::map_chat_response_to_responses(response) {
        Ok(_) => "accepted",
        Err(VitaAgentError::UnsupportedProviderCapability { .. }) => {
            "choices[0].message.tool_calls returned"
        }
        Err(VitaAgentError::GatewayProtocol(message)) if message.contains("exactly one choice") => {
            "choices length is not exactly one"
        }
        Err(VitaAgentError::GatewayProtocol(message))
            if message.contains("role must be assistant") =>
        {
            "choices[0].message.role is not assistant"
        }
        Err(_) => "other exact Chat Completion structural mismatch",
    }
}

#[derive(Debug)]
struct StructuralDiagnosticEvidence {
    provider_status: u16,
    provider_attempt_count: usize,
    content_type: Option<String>,
    requested_model: String,
    returned_model: Option<String>,
    body_is_json: bool,
    response_structure: ResponseStructure,
    parser_failure: &'static str,
    sse_structure: Option<SseStructure>,
}

fn inspect_structural_response(
    body: &[u8],
    content_type: Option<String>,
    requested_model: &str,
    credential: Option<&str>,
) -> StructuralDiagnosticEvidence {
    let is_sse = content_type.as_deref().is_some_and(|content_type| {
        content_type
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("text/event-stream"))
    });
    if is_sse {
        return StructuralDiagnosticEvidence {
            provider_status: 0,
            provider_attempt_count: 0,
            content_type,
            requested_model: safe_structural_text(requested_model, credential),
            returned_model: None,
            body_is_json: false,
            response_structure: ResponseStructure::default(),
            parser_failure: "provider returned text/event-stream for the non-stream probe",
            sse_structure: Some(describe_sse_response(body, credential)),
        };
    }

    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return StructuralDiagnosticEvidence {
            provider_status: 0,
            provider_attempt_count: 0,
            content_type,
            requested_model: safe_structural_text(requested_model, credential),
            returned_model: None,
            body_is_json: false,
            response_structure: ResponseStructure::default(),
            parser_failure: "response body is not valid JSON",
            sse_structure: None,
        };
    };
    let response_structure = describe_response_structure(&value);
    let returned_model = value
        .as_object()
        .and_then(|root| root.get("model"))
        .and_then(Value::as_str)
        .map(|model| safe_structural_text(model, credential));
    let parser_failure = classify_chat_response_structure(
        &value,
        requested_model,
        ProviderModelIdentityPolicy::Exact,
    );
    StructuralDiagnosticEvidence {
        provider_status: 0,
        provider_attempt_count: 0,
        content_type,
        requested_model: safe_structural_text(requested_model, credential),
        returned_model,
        body_is_json: true,
        response_structure,
        parser_failure,
        sse_structure: None,
    }
}

fn model_identity_policy_for_provider(provider_id: &str) -> ProviderModelIdentityPolicy {
    if provider_id.eq_ignore_ascii_case("bigmodel") {
        ProviderModelIdentityPolicy::ProviderNormalized
    } else {
        ProviderModelIdentityPolicy::Exact
    }
}

fn instruction_role_policy_for_provider(provider_id: &str) -> ProviderInstructionRolePolicy {
    if provider_id.eq_ignore_ascii_case("bigmodel") {
        ProviderInstructionRolePolicy::DeveloperAsSystem
    } else {
        ProviderInstructionRolePolicy::NativeDeveloper
    }
}

fn safe_provider_error_summary(error: &VitaAgentError) -> String {
    match error {
        VitaAgentError::ProviderHttpStatus { status, detail } => {
            let detail = detail.as_ref();
            format!(
                "HTTP_{} code={} type={} param={} message={}",
                status,
                detail.and_then(ProviderErrorDetail::code).unwrap_or("none"),
                detail.and_then(ProviderErrorDetail::kind).unwrap_or("none"),
                detail
                    .and_then(ProviderErrorDetail::param)
                    .unwrap_or("none"),
                detail
                    .and_then(ProviderErrorDetail::message)
                    .unwrap_or("none"),
            )
        }
        _ => classify_provider_failure(error).to_string(),
    }
}

fn run_structural_diagnostic(inputs: &G2Inputs) -> Result<StructuralDiagnosticEvidence, String> {
    let provider = ProviderProfile::new(
        inputs.provider_id.clone(),
        format!("D29-G2-R2 structure {}", inputs.provider_id),
        ProviderProtocol::OpenAiChatCompletions,
        &inputs.base_url,
        inputs.model.clone(),
        Some(inputs.credential_ref.clone()),
        D29G2_PROVIDER_TIMEOUT,
        ProviderRetryPolicy::default(),
        ProviderCapabilities::none(),
    )
    .map_err(|_| "structural diagnostic provider profile validation failed".to_string())?;
    let endpoint = provider.endpoint.clone();
    let request = VitaResponsesRequest::new(
        inputs.model.clone(),
        vec![VitaMessage::text(VitaMessageRole::User, D29G2_PROBE_PROMPT)],
        VitaResponsesRequestOptions::default(),
    );
    let mapped = super::map_responses_request_to_chat(&request, &provider)
        .map_err(|_| "structural diagnostic request mapping failed".to_string())?;
    let body = serde_json::to_vec(&mapped)
        .map_err(|_| "structural diagnostic request serialization failed".to_string())?;
    let (transport, observation) = super::production_transport::new_for_d29g2()
        .map_err(|_| "structural diagnostic production transport creation failed".to_string())?;
    let credential = G2CredentialResolver {
        reference: inputs.credential_ref.clone(),
        credential: ResolvedCredential::new(inputs.credential.as_str()),
    }
    .resolve(&inputs.credential_ref)
    .map_err(|_| "structural diagnostic credential binding failed".to_string())?;
    let response = transport.post_json(
        &endpoint,
        Some(&credential),
        &body,
        provider.timeout(),
        provider.retry_policy(),
    );
    let provider_status = observation.last_status.load(Ordering::Acquire);
    let provider_attempt_count = observation.attempt_count.load(Ordering::Acquire);
    let content_type = observation.content_type();
    let response_body = response.map_err(|error| {
        format!(
            "structural diagnostic provider request failed: {}",
            safe_provider_error_summary(&error)
        )
    })?;
    let mut evidence = inspect_structural_response(
        &response_body,
        content_type,
        &inputs.model,
        Some(inputs.credential.as_str()),
    );
    evidence.provider_status = provider_status;
    evidence.provider_attempt_count = provider_attempt_count;
    Ok(evidence)
}

fn print_structural_diagnostic_report(evidence: &StructuralDiagnosticEvidence) {
    println!(
        "D29-G2-R2 STRUCTURAL_DIAGNOSTIC status={} provider_requests={} content_type={} body_is_json={} requested_model={} returned_model={} exact_parser_failure={} response_structure={:?} sse_structure={:?} raw_response_logged=NO",
        evidence.provider_status,
        evidence.provider_attempt_count,
        evidence.content_type.as_deref().unwrap_or("none"),
        evidence.body_is_json,
        evidence.requested_model,
        evidence.returned_model.as_deref().unwrap_or("none"),
        evidence.parser_failure,
        evidence.response_structure,
        evidence.sse_structure,
    );
}

async fn start_runtime(
    inputs: G2Inputs,
) -> Result<(G2Runtime, ProductionTransportObservationHandle, G2Canary), String> {
    let app_data = tempdir().map_err(|_| "create Vita app-data temp root failed".to_string())?;
    let workspace = tempdir().map_err(|_| "create Vita workspace temp root failed".to_string())?;
    let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
        app_data.path().to_path_buf(),
        workspace.path().to_path_buf(),
    )
    .map_err(|_| "create Vita runtime profile failed".to_string())?;
    let model_identity_policy = model_identity_policy_for_provider(&inputs.provider_id);
    let instruction_role_policy = instruction_role_policy_for_provider(&inputs.provider_id);

    let provider = ProviderProfile::new(
        inputs.provider_id.clone(),
        format!("D29-G2 {}", inputs.provider_id),
        ProviderProtocol::OpenAiChatCompletions,
        &inputs.base_url,
        inputs.model.clone(),
        Some(inputs.credential_ref.clone()),
        D29G2_PROVIDER_TIMEOUT,
        ProviderRetryPolicy::default(),
        // The first smoke is deliberately text-only and non-streaming
        // downstream.  BigModel's role matrix proved that its Coding Plan
        // endpoint rejects native developer but accepts system; the selected
        // profile policy preserves the instruction boundary without merging
        // messages.  No other optional capability is enabled, so
        // tools/reasoning controls still fail closed.
        ProviderCapabilities {
            developer_role: instruction_role_policy
                == ProviderInstructionRolePolicy::NativeDeveloper,
            ..ProviderCapabilities::none()
        },
    )
    .map_err(|_| "explicit G2 provider profile validation failed".to_string())?
    .with_model_identity_policy(model_identity_policy)
    .with_instruction_role_policy(instruction_role_policy);
    let authority = super::VitaProviderAuthority::configure(provider)
        .map_err(|_| "configure explicit G2 provider failed".to_string())?;
    if authority.state() != VitaProviderState::ConfiguredValidated {
        return Err("explicit G2 provider did not reach ConfiguredValidated".to_string());
    }

    let reservation = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "reserve D29-G2 gateway port failed".to_string())?;
    let binding = VitaGatewayBinding::for_owned_private_listener(
        reservation
            .local_addr()
            .map_err(|_| "read D29-G2 gateway port failed".to_string())?
            .port(),
    )
    .map_err(|_| "derive D29-G2 gateway binding failed".to_string())?;
    let ready = authority
        .prepare_gateway(binding)
        .map_err(|_| "prepare D29-G2 gateway failed".to_string())?;
    let (transport, transport_observation) = super::production_transport::new_for_d29g2()
        .map_err(|_| "create certified D29-G1 production transport failed".to_string())?;
    let gateway = G2GatewayServer::start(
        reservation,
        ready.clone(),
        G2CredentialResolver {
            reference: inputs.credential_ref,
            credential: inputs.credential,
        },
        transport,
        inputs.model.clone(),
    );

    let entrypoint =
        match VitaAgentEntrypoint::initialize_with_gateway_for_tests(profile.clone(), &ready).await
        {
            Ok(entrypoint) => entrypoint,
            Err(_) => {
                drop(gateway);
                return Err("compile explicit G2 provider into Codex config failed".to_string());
            }
        };
    assert_gateway_config(&entrypoint, ready.derived_codex_provider(), &inputs.model)?;

    let config = entrypoint.config().clone();
    let auth_manager = codex_core::test_support::auth_manager_from_auth_with_home(
        CodexAuth::from_api_key("d29g2-in-memory-kernel-placeholder"),
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
        "d29g2-local-installation".to_string(),
        None,
        None,
    ));
    let new_thread = match tokio::time::timeout(
        D29G2_STARTUP_TIMEOUT,
        manager.start_thread(StartThreadOptions::new(config)),
    )
    .await
    {
        Ok(Ok(new_thread)) => new_thread,
        _ => {
            drop(gateway);
            return Err("D29-G2 real Codex thread startup failed".to_string());
        }
    };

    Ok((
        G2Runtime {
            _app_data: app_data,
            _workspace: workspace,
            manager,
            thread: Some(new_thread.thread),
            thread_id: Some(new_thread.thread_id),
            gateway: Some(gateway),
        },
        ProductionTransportObservationHandle(transport_observation),
        g2_canary(),
    ))
}

// A small local wrapper keeps the production observer type out of the final
// evidence shape while retaining atomics until the listener has shut down.
#[derive(Clone)]
struct ProductionTransportObservationHandle(Arc<ProductionTransportObservation>);

fn assert_gateway_config(
    entrypoint: &VitaAgentEntrypoint,
    provider: &super::DerivedCodexProvider,
    expected_model: &str,
) -> Result<(), String> {
    let config = entrypoint.config();
    if config.model_provider_id != VITA_GATEWAY_PROVIDER_ID
        || config.model_provider_id != provider.model_provider_id()
        || config.model.as_deref() != Some(expected_model)
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
        return Err("D29-G2 Codex provider boundary did not remain Vita-owned".to_string());
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
        return Err("D29-G2 Codex runtime escaped the private Vita profile".to_string());
    }
    Ok(())
}

struct SmokeEvidence {
    provider_id: String,
    base_url: String,
    model: String,
    provider_host: String,
    provider_status: u16,
    provider_attempt_count: usize,
    gateway: GatewayObservation,
    turn: TurnResult,
    cleanup: CleanupEvidence,
    elapsed: Duration,
    canary_unchanged: bool,
    model_identity_policy: ProviderModelIdentityPolicy,
    instruction_role_policy: ProviderInstructionRolePolicy,
}

async fn run_smoke() -> Result<SmokeEvidence, String> {
    let before = g2_canary();
    let inputs = load_inputs()?;
    let provider_id = inputs.provider_id.clone();
    let base_url = inputs.base_url.clone();
    let model = inputs.model.clone();
    let model_identity_policy = model_identity_policy_for_provider(&provider_id);
    let instruction_role_policy = instruction_role_policy_for_provider(&provider_id);
    let provider_host = url::Url::parse(&base_url)
        .ok()
        .and_then(|url| url.host_str().map(str::to_string))
        .ok_or_else(|| "explicit G2 base URL did not contain a host".to_string())?;
    let started = Instant::now();
    let (runtime, transport_observation, after_start) = start_runtime(inputs).await?;
    assert_canary_unchanged(&before, &after_start)?;

    let turn_result = collect_turn(
        runtime
            .thread
            .as_ref()
            .ok_or_else(|| "D29-G2 runtime did not contain a Codex thread".to_string())?,
    )
    .await;
    let turn_interrupt_submitted = turn_result
        .as_ref()
        .ok()
        .is_some_and(|turn| turn.interrupt_submitted);
    let shutdown = runtime.shutdown(turn_interrupt_submitted).await?;
    let after = g2_canary();
    assert_canary_unchanged(&before, &after)?;
    let turn = turn_result?;
    let provider_status = transport_observation.0.last_status.load(Ordering::Acquire);
    let provider_attempt_count = transport_observation
        .0
        .attempt_count
        .load(Ordering::Acquire);

    Ok(SmokeEvidence {
        provider_id,
        base_url,
        model,
        provider_host,
        provider_status,
        provider_attempt_count,
        gateway: shutdown.gateway,
        turn,
        cleanup: shutdown.cleanup,
        elapsed: started.elapsed(),
        canary_unchanged: true,
        model_identity_policy,
        instruction_role_policy,
    })
}

fn assert_smoke_success(evidence: &SmokeEvidence) -> Result<(), String> {
    if evidence.provider_status != 200 {
        return Err(format!(
            "G2 provider HTTP status {}; provider_attempts={}; codex_to_vita_requests={}; gateway_failure_class={}; gateway_target={}; gateway_response_path={}",
            evidence.provider_status,
            evidence.provider_attempt_count,
            evidence.gateway.request_count,
            evidence.gateway.failure_class.unwrap_or("none"),
            evidence.gateway.target.as_deref().unwrap_or("none"),
            evidence.gateway.response_path.as_deref().unwrap_or("none"),
        ));
    }
    if evidence.provider_attempt_count != 1 {
        return Err(format!(
            "G2 provider request count was {}, expected 1",
            evidence.provider_attempt_count
        ));
    }
    if evidence.gateway.request_count != 1
        || !evidence.gateway.peer_is_loopback
        || evidence.gateway.method.as_deref() != Some("POST")
        || evidence.gateway.target.as_deref() != Some("/v1/responses")
        || evidence.gateway.codex_authorization_present
        || evidence.gateway.request_model.as_deref() != Some(evidence.model.as_str())
        || !evidence.gateway.deterministic_prompt_seen
        || !evidence.gateway.terminal_response_emitted
        || evidence.gateway.response_path.as_deref() != Some("responses-sse")
        || !evidence.gateway.provider_output_expected
        || evidence.gateway.failure_class.is_some()
    {
        return Err("D29-G2 Vita gateway evidence did not prove the required loop".to_string());
    }
    if evidence.turn.turn_timed_out
        || evidence.turn.terminal_error_present
        || !evidence.turn.assistant_output_expected
        || !evidence.turn.terminal_output_expected
    {
        return Err("D29-G2 Codex turn did not finish with the deterministic output".to_string());
    }
    if evidence.cleanup.final_shutdown != ShutdownStatus::Success
        || evidence.cleanup.manager_thread_count != 0
        || !evidence.cleanup.gateway_listener_joined
    {
        return Err("D29-G2 cleanup evidence was incomplete".to_string());
    }
    if !evidence.canary_unchanged {
        return Err("D29-G2 user Codex canary changed".to_string());
    }
    Ok(())
}

fn print_success_report(evidence: &SmokeEvidence) {
    let usage = evidence.gateway.provider_usage.as_ref();
    println!(
        "D29-G2 PASS provider={} endpoint={} model={} model_identity_policy={} instruction_role_policy={} protocol=openai-chat-completions provider_host={} provider_http_status={} provider_requests={} codex_to_vita_requests={} vita_to_provider_requests={} developer_role_present={} terminal_output={} finish_reason={} usage_input_tokens={} usage_output_tokens={} usage_total_tokens={} elapsed_ms={} redirect_followed=NO proxy_used=NO raw_credential_persisted=NO raw_credential_logged=NO openai_account_dependency=NONE codex_login_dependency=NONE user_codex=UNTOUCHED thread_manager_final_count={} listener=CLOSED/JOINED codex_upstream_source_modifications=0 reasoning={} stream_options={} text={} external_hosts=provider_only",
        evidence.provider_id,
        evidence.base_url,
        evidence.model,
        evidence.model_identity_policy,
        evidence.instruction_role_policy,
        evidence.provider_host,
        evidence.provider_status,
        evidence.provider_attempt_count,
        evidence.gateway.request_count,
        evidence.provider_attempt_count,
        evidence.gateway.developer_role_present,
        D29G2_REPLY,
        evidence
            .gateway
            .provider_finish_reason
            .as_deref()
            .unwrap_or("none"),
        usage.map_or(0, |usage| usage.input_tokens),
        usage.map_or(0, |usage| usage.output_tokens),
        usage.map_or(0, |usage| usage.total_tokens),
        evidence.elapsed.as_millis(),
        evidence.cleanup.manager_thread_count,
        evidence.gateway.reasoning_handling.as_str(),
        evidence.gateway.stream_options_handling.as_str(),
        evidence.gateway.text_handling.as_str(),
    );
}

fn print_blocked_report(evidence: &SmokeEvidence) {
    let detail = evidence.gateway.provider_error_detail.as_ref();
    println!(
        "D29-G2 BLOCKED provider={} endpoint={} model={} provider_host={} provider_http_status={} provider_requests={} codex_to_vita_requests={} developer_role_present={} gateway_failure_class={} gateway_target={} gateway_response_path={} provider_error_code={} provider_error_type={} provider_error_param={} provider_error_message={} user_codex=UNCHANGED raw_credential_logged=NO",
        evidence.provider_id,
        evidence.base_url,
        evidence.model,
        evidence.provider_host,
        evidence.provider_status,
        evidence.provider_attempt_count,
        evidence.gateway.request_count,
        evidence.gateway.developer_role_present,
        evidence.gateway.failure_class.unwrap_or("none"),
        evidence.gateway.target.as_deref().unwrap_or("none"),
        evidence.gateway.response_path.as_deref().unwrap_or("none"),
        detail.and_then(ProviderErrorDetail::code).unwrap_or("none"),
        detail.and_then(ProviderErrorDetail::kind).unwrap_or("none"),
        detail.and_then(ProviderErrorDetail::param).unwrap_or("none"),
        detail.and_then(ProviderErrorDetail::message).unwrap_or("none"),
    );
}

#[test]
#[ignore = "requires explicit user-authorized VITA_D29G2_* inputs and one real provider request"]
fn d29g2_real_provider_smoke() {
    thread::Builder::new()
        .name("d29g2-real-provider-smoke".to_string())
        .stack_size(D29G2_TEST_STACK_SIZE)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-G2 test runtime should build");
            let evidence = runtime
                .block_on(run_smoke())
                .unwrap_or_else(|error| panic!("D29-G2 BLOCKED: {error}"));
            if let Err(error) = assert_smoke_success(&evidence) {
                print_blocked_report(&evidence);
                panic!("D29-G2 BLOCKED: {error}");
            }
            print_success_report(&evidence);
        })
        .expect("D29-G2 test thread should start")
        .join()
        .expect("D29-G2 test thread should finish");
}

#[test]
#[ignore = "requires explicit user-authorized VITA_D29G2_* inputs and one real provider request"]
fn d29g2_r1_minimal_provider_probe() {
    thread::Builder::new()
        .name("d29g2-r1-minimal-provider-probe".to_string())
        .stack_size(D29G2_TEST_STACK_SIZE)
        .spawn(|| {
            let inputs = load_inputs().unwrap_or_else(|error| panic!("D29-G2-R1 BLOCKED: {error}"));
            let evidence = run_minimal_provider_probe(&inputs)
                .unwrap_or_else(|error| panic!("D29-G2-R1 BLOCKED: {error}"));
            print_minimal_probe_report(&evidence);
            assert_eq!(
                evidence.provider_attempt_count, 1,
                "D29-G2-R1 minimal probe must issue exactly one provider request"
            );
            assert!(
                (200..300).contains(&evidence.provider_status)
                    && evidence.response_is_valid_chat_completion,
                "D29-G2-R1 minimal provider probe failed"
            );
        })
        .expect("D29-G2-R1 probe thread should start")
        .join()
        .expect("D29-G2-R1 probe thread should finish");
}

#[test]
#[ignore = "requires explicit user-authorized VITA_D29G2_* inputs and one real provider request"]
fn d29g2_r2_structural_diagnostic() {
    thread::Builder::new()
        .name("d29g2-r2-structural-diagnostic".to_string())
        .stack_size(D29G2_TEST_STACK_SIZE)
        .spawn(|| {
            let inputs = load_inputs().unwrap_or_else(|error| panic!("D29-G2-R2 BLOCKED: {error}"));
            let evidence = run_structural_diagnostic(&inputs)
                .unwrap_or_else(|error| panic!("D29-G2-R2 BLOCKED: {error}"));
            print_structural_diagnostic_report(&evidence);
            assert_eq!(
                evidence.provider_attempt_count, 1,
                "D29-G2-R2 structural diagnostic must issue exactly one provider request"
            );
            assert_eq!(
                evidence.provider_status, 200,
                "D29-G2-R2 structural diagnostic expected HTTP 200"
            );
        })
        .expect("D29-G2-R2 diagnostic thread should start")
        .join()
        .expect("D29-G2-R2 diagnostic thread should finish");
}

#[test]
#[ignore = "requires explicit user-authorized VITA_D29G2_* inputs and two real provider requests"]
fn d29g2_r2_role_matrix() {
    thread::Builder::new()
        .name("d29g2-r2-role-matrix".to_string())
        .stack_size(D29G2_TEST_STACK_SIZE)
        .spawn(|| {
            let inputs = load_inputs().unwrap_or_else(|error| panic!("D29-G2-R2 BLOCKED: {error}"));
            let evidence = run_role_matrix(&inputs)
                .unwrap_or_else(|error| panic!("D29-G2-R2 BLOCKED: {error}"));
            print_role_matrix_report(&evidence);
            assert_eq!(
                evidence.len(),
                2,
                "D29-G2-R2 role matrix must issue exactly two provider requests"
            );
            for result in &evidence {
                assert_eq!(
                    result.provider_attempt_count, 1,
                    "D29-G2-R2 role matrix request must not retry"
                );
            }
            assert_eq!(evidence[0].label, "system+user");
            assert_eq!(evidence[0].provider_status, 200);
            assert_eq!(evidence[1].label, "developer+user");
            assert_eq!(evidence[1].provider_status, 400);
            assert_eq!(
                evidence[1]
                    .error_detail
                    .as_ref()
                    .and_then(ProviderErrorDetail::code),
                Some("1214")
            );
        })
        .expect("D29-G2-R2 role matrix thread should start")
        .join()
        .expect("D29-G2-R2 role matrix thread should finish");
}

#[test]
fn observed_bigmodel_response_requires_explicit_model_normalization_policy() {
    let response = json!({
        "id": "chatcmpl-case-normalized",
        "object": "chat.completion",
        "created": 1,
        "model": "glm-5.3-flash",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "bounded fixture output"
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 1,
            "completion_tokens": 1,
            "total_tokens": 2
        }
    });

    assert_eq!(
        classify_chat_response_structure(
            &response,
            "GLM-5.3-Flash",
            ProviderModelIdentityPolicy::Exact,
        ),
        "response model differs from requested model"
    );
    assert_eq!(
        classify_chat_response_structure(
            &response,
            "GLM-5.3-Flash",
            ProviderModelIdentityPolicy::ProviderNormalized,
        ),
        "accepted"
    );
    assert!(!ProviderModelIdentityPolicy::ProviderNormalized
        .matches("GLM-5.3-Flash", "glm-5.3-flash-1m"));

    let structure = describe_response_structure(&response);
    assert_eq!(structure.top_level_type, StructuralJsonType::Object);
    assert_eq!(structure.choices.bounded_length, Some(1));
    assert_eq!(
        structure
            .choices
            .first
            .as_ref()
            .and_then(|choice| choice.message_detail.as_ref())
            .and_then(|message| message.content_detail.as_ref()),
        Some(&ContentStructure::String {
            bounded_length: "bounded fixture output".chars().count(),
            capped: false,
        })
    );
}

#[test]
fn provider_model_identity_policy_defaults_to_exact_and_is_profile_selected() {
    let profile = ProviderProfile::new(
        "bigmodel",
        "BigModel Coding Plan",
        ProviderProtocol::OpenAiChatCompletions,
        "https://open.bigmodel.cn/api/coding/paas/v4",
        "GLM-5.3-Flash",
        None,
        D29G2_PROVIDER_TIMEOUT,
        ProviderRetryPolicy::default(),
        ProviderCapabilities::none(),
    )
    .expect("BigModel fixture profile");
    assert_eq!(
        profile.model_identity_policy(),
        ProviderModelIdentityPolicy::Exact
    );
    let normalized =
        profile.with_model_identity_policy(ProviderModelIdentityPolicy::ProviderNormalized);
    assert_eq!(
        normalized.model_identity_policy(),
        ProviderModelIdentityPolicy::ProviderNormalized
    );
    assert_eq!(
        model_identity_policy_for_provider("bigmodel"),
        ProviderModelIdentityPolicy::ProviderNormalized
    );
    assert_eq!(
        model_identity_policy_for_provider("commandcode"),
        ProviderModelIdentityPolicy::Exact
    );
}
