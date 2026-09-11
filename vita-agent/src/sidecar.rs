//! Process-isolated Vita sidecar entrypoint.
//!
//! The sidecar owns the native workspace capability, H7 supervisor, and the
//! pinned Codex composition. Authority decisions are RPCs to the Tauri Host;
//! this process never reads the Host SQLite database and never mints a grant.

use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Read, Stdin, Stdout, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
#[cfg(feature = "d29-h9-test-helper")]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use protocol::{
    AuthorityEvaluate, ConfirmationDecision, ConfirmationRequired, CredentialRequired, GrantIssued,
    Handshake, HostMessage, InitializeSession, IssueGrant, ProcessBinding, ProcessGrant,
    ProviderBinding, ProviderConfiguration, RevalidateGrant, StartTurn, TurnCompleted, TurnFailed,
    TurnPhase, TurnState, VitaMessage, CODEX_PROTOCOL_SCHEMA_HASH, CODEX_UPSTREAM_COMMIT,
    MAX_FRAME_BYTES, MAX_PROMPT_BYTES, MAX_TURN_OUTPUT_BYTES, PROTOCOL_VERSION, RUNTIME_ID,
    TOOL_NAME,
};
use vita_agent_protocol as protocol;

use crate::provider_gateway::{
    CredentialResolver, GatewayReadyProvider, GatewayToolDefinition, ProviderGateway,
    ProviderRequestIdentity, ResolvedCredential, VitaFunctionCall, VitaMessage as GatewayMessage,
    VitaMessageRole, VitaResponsesRequest, VitaResponsesRequestOptions, VitaToolOutput,
};
use crate::{
    H7ProcessBinding, H7ProcessGrant, VitaAgentEntrypoint, VitaAgentRuntime,
    VitaAgentRuntimeProfile, VitaExecutionContext, VitaGitStatusAuthority,
    VitaGitStatusPendingConfirmation, VitaGitStatusProduction,
    VITA_WORKSPACE_GIT_STATUS_CAPABILITY_ID, VITA_WORKSPACE_GIT_STATUS_PROFILE_ID,
    VITA_WORKSPACE_GIT_STATUS_TOOL_NAME,
};

const LOCAL_GATEWAY_HEADER_LIMIT: usize = 64 * 1024;
const LOCAL_GATEWAY_BODY_LIMIT: usize = MAX_FRAME_BYTES;
const LOCAL_GATEWAY_IO_TIMEOUT: Duration = Duration::from_secs(5);
const LOCAL_GATEWAY_PATH: &str = "/v1/responses";
const MAX_GATEWAY_TEXT_BYTES: usize = MAX_TURN_OUTPUT_BYTES;

enum SidecarGatewayTransport {
    Production,
    #[cfg(feature = "d29-h9-test-helper")]
    H9Canary(Arc<H9CanaryTransport>),
}

struct BorrowedProviderTransport<'a> {
    inner: &'a dyn crate::provider_gateway::ProviderRequestTransport,
}

impl crate::provider_gateway::ProviderRequestTransport for BorrowedProviderTransport<'_> {
    fn post_json(
        &self,
        endpoint: &crate::provider_gateway::ProviderEndpoint,
        authorization: Option<&ResolvedCredential>,
        body: &[u8],
        timeout: Duration,
        retry_policy: crate::provider_gateway::ProviderRetryPolicy,
    ) -> Result<Vec<u8>, crate::VitaAgentError> {
        self.inner
            .post_json(endpoint, authorization, body, timeout, retry_policy)
    }
}

/// Re-checks the sidecar turn generation immediately before the provider
/// transport is entered.  Credential resolution is deliberately not the last
/// authority check: cancellation may win after a credential reply but before
/// the HTTP attempt is constructed.
struct ActiveIdentityTransport<'a> {
    inner: &'a dyn crate::provider_gateway::ProviderRequestTransport,
    active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
    expected: ProviderRequestIdentity,
}

impl crate::provider_gateway::ProviderRequestTransport for ActiveIdentityTransport<'_> {
    fn post_json(
        &self,
        endpoint: &crate::provider_gateway::ProviderEndpoint,
        authorization: Option<&ResolvedCredential>,
        body: &[u8],
        timeout: Duration,
        retry_policy: crate::provider_gateway::ProviderRetryPolicy,
    ) -> Result<Vec<u8>, crate::VitaAgentError> {
        if !active_identity_matches(&self.active_identity, &self.expected) {
            return Err(crate::VitaAgentError::CredentialResolution(
                "Vita turn was cancelled before provider attempt",
            ));
        }
        self.inner
            .post_json(endpoint, authorization, body, timeout, retry_policy)
    }
}

#[cfg(feature = "d29-h9-test-helper")]
struct H9CanaryTransport {
    request_count: AtomicUsize,
}

#[cfg(feature = "d29-h9-test-helper")]
impl H9CanaryTransport {
    fn new() -> Self {
        Self {
            request_count: AtomicUsize::new(0),
        }
    }
}

#[cfg(feature = "d29-h9-test-helper")]
impl crate::provider_gateway::ProviderRequestTransport for H9CanaryTransport {
    fn post_json(
        &self,
        endpoint: &crate::provider_gateway::ProviderEndpoint,
        _authorization: Option<&ResolvedCredential>,
        _body: &[u8],
        _timeout: Duration,
        _retry_policy: crate::provider_gateway::ProviderRetryPolicy,
    ) -> Result<Vec<u8>, crate::VitaAgentError> {
        if !endpoint.is_test_localhost() {
            return Err(crate::VitaAgentError::GatewayProtocol(
                "H9 canary transport accepts only the test loopback endpoint".to_string(),
            ));
        }
        let request_number = self.request_count.fetch_add(1, Ordering::AcqRel) + 1;
        let response = if request_number == 1 {
            serde_json::json!({
                "id": "h9-canary-tool-call",
                "model": "h9-canary-model",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": "h9-canary-call-1",
                            "type": "function",
                            "function": {
                                "name": VITA_WORKSPACE_GIT_STATUS_TOOL_NAME,
                                "arguments": "{\"operation\":\"status\"}"
                            }
                        }]
                    },
                    "finish_reason": "tool_calls"
                }]
            })
        } else if request_number == 2 {
            serde_json::json!({
                "id": "h9-canary-final",
                "model": "h9-canary-model",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "D29-H9 process-isolated closure complete (provider_requests=2)"
                    },
                    "finish_reason": "stop"
                }]
            })
        } else {
            return Err(crate::VitaAgentError::GatewayProtocol(
                "H9 canary provider received an unexpected third request".to_string(),
            ));
        };
        serde_json::to_vec(&response).map_err(|_| {
            crate::VitaAgentError::GatewayProtocol(
                "H9 canary provider response could not be serialized".to_string(),
            )
        })
    }
}

#[derive(Clone)]
struct SidecarCredentialResolver {
    router: SidecarRouter,
    session_id: String,
    provider_configuration: ProviderConfiguration,
    ready: GatewayReadyProvider,
    active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
}

impl CredentialResolver for SidecarCredentialResolver {
    fn resolve(
        &self,
        _credential_ref: &crate::provider_gateway::CredentialRef,
    ) -> Result<ResolvedCredential, crate::VitaAgentError> {
        Err(crate::VitaAgentError::CredentialResolution(
            "request identity is required for Vita credential resolution",
        ))
    }

    fn resolve_for_request(
        &self,
        credential_ref: &crate::provider_gateway::CredentialRef,
        request: &ProviderRequestIdentity,
    ) -> Result<ResolvedCredential, crate::VitaAgentError> {
        let configuration = &self.provider_configuration;
        if configuration.credential_ref != credential_ref.reference_id()
            || configuration.model != self.ready.profile().model()
        {
            return Err(crate::VitaAgentError::CredentialResolution(
                "provider credential reference was stale",
            ));
        }
        let binding = ProviderBinding::derive(&self.session_id, &request.turn_id, configuration)
            .map_err(|_| {
                crate::VitaAgentError::CredentialResolution("provider binding was invalid")
            })?;
        if binding.binding_hash != request.binding_hash {
            return Err(crate::VitaAgentError::CredentialResolution(
                "provider binding was stale",
            ));
        }
        if !active_identity_matches(&self.active_identity, request) {
            return Err(crate::VitaAgentError::CredentialResolution(
                "Vita turn is no longer active",
            ));
        }
        let request_id = next_request_id("vita-credential");
        let reply = self
            .router
            .request(VitaMessage::CredentialRequired(CredentialRequired {
                request_id,
                session_id: self.session_id.clone(),
                turn_id: request.turn_id.clone(),
                binding: binding.clone(),
            }))
            .map_err(|_| {
                crate::VitaAgentError::CredentialResolution("Host credential authority unavailable")
            })?;
        let HostMessage::SensitiveCredentialReply(reply) = reply else {
            return Err(crate::VitaAgentError::CredentialResolution(
                "Host returned an unexpected credential response",
            ));
        };
        reply.validate().map_err(|_| {
            crate::VitaAgentError::CredentialResolution("Host credential response was malformed")
        })?;
        if reply.session_id != self.session_id
            || reply.turn_id != request.turn_id
            || reply.binding_hash != binding.binding_hash
            || reply.credential_ref != credential_ref.reference_id()
        {
            return Err(crate::VitaAgentError::CredentialResolution(
                "Host credential response binding was stale",
            ));
        }
        if !active_identity_matches(&self.active_identity, request) {
            return Err(crate::VitaAgentError::CredentialResolution(
                "Vita turn is no longer active",
            ));
        }
        let credential = reply
            .credential
            .ok_or(crate::VitaAgentError::CredentialResolution(
                "Host denied provider credential",
            ))?;
        let resolved = ResolvedCredential::new(credential.as_str().to_owned());
        resolved.validate_header_safety()?;
        Ok(resolved)
    }
}

fn active_identity_matches(
    active_identity: &Arc<Mutex<Option<ProviderRequestIdentity>>>,
    expected: &ProviderRequestIdentity,
) -> bool {
    active_identity
        .lock()
        .ok()
        .is_some_and(|active| active.as_ref() == Some(expected))
}

fn active_identity_snapshot(
    active_identity: &Arc<Mutex<Option<ProviderRequestIdentity>>>,
) -> Option<ProviderRequestIdentity> {
    active_identity
        .lock()
        .ok()
        .and_then(|active| active.clone())
}

struct VitaGatewayServer {
    stop: Arc<AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl VitaGatewayServer {
    fn start(
        listener: TcpListener,
        ready: GatewayReadyProvider,
        provider_configuration: ProviderConfiguration,
        router: SidecarRouter,
        session_id: String,
        active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
        transport: SidecarGatewayTransport,
    ) -> Result<Self, crate::VitaAgentError> {
        listener
            .set_nonblocking(true)
            .map_err(crate::VitaAgentError::GatewayTransport)?;
        let token = ready
            .binding()
            .session_token()
            .ok_or(crate::VitaAgentError::GatewayProtocol(
                "production Vita gateway is missing session authentication".to_string(),
            ))?
            .as_str()
            .to_string();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let provider_configuration_for_thread = provider_configuration;
        let transport_for_thread = transport;
        let join = std::thread::Builder::new()
            .name("vita-provider-gateway".to_string())
            .spawn(move || {
                while !stop_for_thread.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, peer)) => {
                            let _ = handle_gateway_connection(
                                stream,
                                peer,
                                &token,
                                &ready,
                                &provider_configuration_for_thread,
                                &router,
                                &session_id,
                                &active_identity,
                                &transport_for_thread,
                            );
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(crate::VitaAgentError::GatewayTransport)?;
        Ok(Self {
            stop,
            join: Some(join),
        })
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl Drop for VitaGatewayServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn handle_gateway_connection(
    mut stream: TcpStream,
    peer: std::net::SocketAddr,
    expected_token: &str,
    ready: &GatewayReadyProvider,
    provider_configuration: &ProviderConfiguration,
    router: &SidecarRouter,
    session_id: &str,
    active_identity: &Arc<Mutex<Option<ProviderRequestIdentity>>>,
    transport: &SidecarGatewayTransport,
) -> Result<(), String> {
    if !peer.ip().is_loopback() {
        return write_gateway_error(&mut stream, "403 Forbidden", "GATEWAY_PEER_DENIED");
    }
    stream
        .set_read_timeout(Some(LOCAL_GATEWAY_IO_TIMEOUT))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(LOCAL_GATEWAY_IO_TIMEOUT))
        .map_err(|error| error.to_string())?;
    let request = match read_gateway_http_request(&mut stream) {
        Ok(request) => request,
        Err(code) => return write_gateway_error(&mut stream, "400 Bad Request", code),
    };
    if let Err(code) = authorize_gateway_request(&request, expected_token) {
        let status = if code == "GATEWAY_AUTH_DENIED" {
            "401 Unauthorized"
        } else {
            "404 Not Found"
        };
        return write_gateway_error(&mut stream, status, code);
    }
    let identity = active_identity
        .lock()
        .map_err(|_| "active Vita turn state was poisoned".to_string())?
        .clone()
        .ok_or_else(|| "no active Vita turn".to_string());
    let identity = match identity {
        Ok(identity) => identity,
        Err(_) => return write_gateway_error(&mut stream, "409 Conflict", "TURN_NOT_ACTIVE"),
    };
    let request = match parse_gateway_responses_request(&request.body, ready.profile().model()) {
        Ok(request) => request,
        Err(_) => {
            return write_gateway_error(&mut stream, "400 Bad Request", "REQUEST_INVALID");
        }
    };
    let resolver = SidecarCredentialResolver {
        router: router.clone(),
        session_id: session_id.to_string(),
        provider_configuration: provider_configuration.clone(),
        ready: ready.clone(),
        active_identity: Arc::clone(active_identity),
    };
    let result = match transport {
        SidecarGatewayTransport::Production => {
            let transport = crate::provider_gateway::new_production_provider_transport()
                .map_err(|_| "provider transport unavailable".to_string())?;
            let guarded = ActiveIdentityTransport {
                inner: &transport,
                active_identity: Arc::clone(active_identity),
                expected: identity.clone(),
            };
            let gateway = ProviderGateway::new(ready.clone(), resolver, guarded);
            gateway.execute_responses_request_with_identity(&request, Some(&identity))
        }
        #[cfg(feature = "d29-h9-test-helper")]
        SidecarGatewayTransport::H9Canary(transport) => {
            let borrowed = BorrowedProviderTransport {
                inner: transport.as_ref(),
            };
            let guarded = ActiveIdentityTransport {
                inner: &borrowed,
                active_identity: Arc::clone(active_identity),
                expected: identity.clone(),
            };
            let gateway = ProviderGateway::new(ready.clone(), resolver, guarded);
            gateway.execute_responses_request_with_identity(&request, Some(&identity))
        }
    }
    .map_err(|_| "provider request failed".to_string())?;
    if !active_identity_matches(active_identity, &identity) {
        return write_gateway_error(&mut stream, "409 Conflict", "TURN_NOT_ACTIVE");
    }
    write_gateway_success(&mut stream, &result)
}

struct GatewayHttpRequest {
    method: String,
    path: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

fn authorize_gateway_request(
    request: &GatewayHttpRequest,
    expected_token: &str,
) -> Result<(), &'static str> {
    if request.method != "POST" || request.path != LOCAL_GATEWAY_PATH {
        return Err("GATEWAY_ROUTE_DENIED");
    }
    if request.authorization.as_deref() != Some(expected_token) {
        return Err("GATEWAY_AUTH_DENIED");
    }
    Ok(())
}

fn read_gateway_http_request(stream: &mut TcpStream) -> Result<GatewayHttpRequest, &'static str> {
    let mut bytes = Vec::with_capacity(4096);
    let mut header_end = None;
    let mut chunk = [0_u8; 4096];
    while bytes.len() <= LOCAL_GATEWAY_HEADER_LIMIT + LOCAL_GATEWAY_BODY_LIMIT {
        let count = stream.read(&mut chunk).map_err(|_| "GATEWAY_IO")?;
        if count == 0 {
            return Err("GATEWAY_TRUNCATED");
        }
        bytes.extend_from_slice(&chunk[..count]);
        if header_end.is_none() {
            header_end = bytes.windows(4).position(|window| window == b"\r\n\r\n");
            if header_end.is_some_and(|offset| offset > LOCAL_GATEWAY_HEADER_LIMIT) {
                return Err("GATEWAY_HEADERS_TOO_LARGE");
            }
        }
        let Some(offset) = header_end else { continue };
        let header_len = offset + 4;
        let header = std::str::from_utf8(&bytes[..offset]).map_err(|_| "GATEWAY_HEADERS")?;
        let mut lines = header.split("\r\n");
        let request_line = lines.next().ok_or("GATEWAY_REQUEST_LINE")?;
        let mut request_parts = request_line.split_ascii_whitespace();
        let method = request_parts.next().ok_or("GATEWAY_REQUEST_LINE")?;
        let path = request_parts.next().ok_or("GATEWAY_REQUEST_LINE")?;
        let version = request_parts.next().ok_or("GATEWAY_REQUEST_LINE")?;
        if version != "HTTP/1.1" || request_parts.next().is_some() {
            return Err("GATEWAY_REQUEST_LINE");
        }
        let mut content_length = None;
        let mut authorization = None;
        for line in lines {
            let Some((name, value)) = line.split_once(':') else {
                return Err("GATEWAY_HEADERS");
            };
            let value = value.trim();
            if name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some() {
                    return Err("GATEWAY_DUPLICATE_LENGTH");
                }
                content_length = Some(value.parse::<usize>().map_err(|_| "GATEWAY_LENGTH")?);
            } else if name.eq_ignore_ascii_case("authorization") {
                if authorization.is_some() {
                    return Err("GATEWAY_DUPLICATE_AUTH");
                }
                let Some(token) = value.strip_prefix("Bearer ") else {
                    return Err("GATEWAY_AUTH");
                };
                authorization = Some(token.to_string());
            } else if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err("GATEWAY_CHUNKED");
            }
        }
        let content_length = content_length.ok_or("GATEWAY_LENGTH")?;
        if content_length == 0 || content_length > LOCAL_GATEWAY_BODY_LIMIT {
            return Err("GATEWAY_BODY_TOO_LARGE");
        }
        let body_end = header_len.saturating_add(content_length);
        if body_end > bytes.len() {
            continue;
        }
        let body = bytes[header_len..body_end].to_vec();
        return Ok(GatewayHttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            authorization,
            body,
        });
    }
    Err("GATEWAY_BODY_TOO_LARGE")
}

fn write_gateway_error(stream: &mut TcpStream, status: &str, code: &str) -> Result<(), String> {
    let body = serde_json::json!({"error": {"code": code}}).to_string();
    write_gateway_http_response(stream, status, "application/json", body.as_bytes())
}

fn write_gateway_success(
    stream: &mut TcpStream,
    result: &crate::provider_gateway::VitaResponsesResult,
) -> Result<(), String> {
    let response_id = format!("resp-{}", result.id);
    let mut events = Vec::new();
    events.push(serde_json::json!({
        "type": "response.created",
        "response": {"id": response_id, "object": "response", "status": "in_progress", "model": result.model}
    }));
    if result.function_calls.is_empty() {
        let text = bounded_utf8_prefix(&result.output_text, MAX_GATEWAY_TEXT_BYTES);
        events.push(serde_json::json!({
            "type": "response.output_item.added",
            "item": {"type":"message","id":"msg-vita","role":"assistant","status":"in_progress","content":[]}
        }));
        events.push(serde_json::json!({"type":"response.content_part.added"}));
        events.push(serde_json::json!({"type":"response.output_text.delta","delta":text}));
        events.push(serde_json::json!({"type":"response.output_text.done","text":text}));
        events.push(serde_json::json!({"type":"response.content_part.done"}));
        events.push(serde_json::json!({
            "type": "response.output_item.done",
            "item": {"type":"message","id":"msg-vita","role":"assistant","status":"completed","content":[{"type":"output_text","text":text}]}
        }));
        events.push(serde_json::json!({"type":"response.completed","response":{"id":format!("resp-{}", result.id),"status":"completed","model":result.model,"usage":result.usage.as_ref().map(|usage| serde_json::json!({"input_tokens":usage.input_tokens,"output_tokens":usage.output_tokens,"total_tokens":usage.total_tokens})),"end_turn":true}}));
    } else {
        for call in &result.function_calls {
            events.push(serde_json::json!({"type":"response.output_item.added","item":{"type":"function_call","id":call.id,"call_id":call.id,"name":call.name,"arguments":"","status":"in_progress"}}));
            events.push(serde_json::json!({"type":"response.function_call_arguments.delta","item_id":call.id,"call_id":call.id,"delta":call.arguments}));
            events.push(serde_json::json!({"type":"response.function_call_arguments.done","item_id":call.id,"call_id":call.id,"arguments":call.arguments}));
            events.push(serde_json::json!({"type":"response.output_item.done","item":{"type":"function_call","id":call.id,"call_id":call.id,"name":call.name,"arguments":call.arguments,"status":"completed"}}));
        }
        events.push(serde_json::json!({"type":"response.completed","response":{"id":format!("resp-{}", result.id),"status":"completed","model":result.model,"usage":result.usage.as_ref().map(|usage| serde_json::json!({"input_tokens":usage.input_tokens,"output_tokens":usage.output_tokens,"total_tokens":usage.total_tokens})),"end_turn":false}}));
    }
    let mut body = String::new();
    for event in events {
        let kind = event
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("response.completed");
        body.push_str("event: ");
        body.push_str(kind);
        body.push_str("\ndata: ");
        body.push_str(
            &serde_json::to_string(&event).map_err(|_| "serialize gateway event".to_string())?,
        );
        body.push_str("\n\n");
    }
    if body.len() > LOCAL_GATEWAY_BODY_LIMIT {
        return write_gateway_error(stream, "502 Bad Gateway", "RESPONSE_TOO_LARGE");
    }
    write_gateway_http_response(stream, "200 OK", "text/event-stream", body.as_bytes())
}

fn write_gateway_http_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), String> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n",
        body.len()
    );
    stream
        .write_all(header.as_bytes())
        .and_then(|_| stream.write_all(body))
        .map_err(|_| "gateway response write failed".to_string())
}

fn parse_gateway_responses_request(
    body: &[u8],
    expected_model: &str,
) -> Result<VitaResponsesRequest, String> {
    if body.len() > LOCAL_GATEWAY_BODY_LIMIT {
        return Err("request too large".to_string());
    }
    let value: Value =
        serde_json::from_slice(body).map_err(|_| "invalid request json".to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "request must be an object".to_string())?;
    let model = object
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| "model missing".to_string())?;
    if model != expected_model || object.get("stream").and_then(Value::as_bool) != Some(true) {
        return Err("model or stream mismatch".to_string());
    }
    if object
        .get("store")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return Err("store is disabled".to_string());
    }
    // The pinned Codex Responses client advertises `parallel_tool_calls` as
    // true even when the registered contributor only emits one call.  The
    // Vita gateway keeps the stronger invariant at the parsed call boundary
    // (`ProviderGateway` rejects more than one call) and deliberately does
    // not forward this advisory flag to Chat providers.
    let mut messages = Vec::new();
    if let Some(instructions) = object.get("instructions").and_then(Value::as_str) {
        if !instructions.is_empty() {
            messages.push(GatewayMessage::text(
                VitaMessageRole::System,
                bounded_gateway_text(instructions)?,
            ));
        }
    }
    let mut tool_calls = Vec::new();
    let mut tool_outputs = Vec::new();
    for item in object
        .get("input")
        .and_then(Value::as_array)
        .ok_or_else(|| "input missing".to_string())?
    {
        let item = item
            .as_object()
            .ok_or_else(|| "input item invalid".to_string())?;
        match item.get("type").and_then(Value::as_str).unwrap_or_default() {
            "message" => {
                let role = match item.get("role").and_then(Value::as_str).unwrap_or_default() {
                    "system" => VitaMessageRole::System,
                    "developer" => VitaMessageRole::Developer,
                    "user" => VitaMessageRole::User,
                    "assistant" => VitaMessageRole::Assistant,
                    _ => return Err("message role invalid".to_string()),
                };
                let content = item
                    .get("content")
                    .ok_or_else(|| "message content missing".to_string())?;
                let mut text = String::new();
                if let Some(content) = content.as_str() {
                    text.push_str(content);
                } else {
                    for part in content
                        .as_array()
                        .ok_or_else(|| "message content invalid".to_string())?
                    {
                        let part = part
                            .as_object()
                            .ok_or_else(|| "message part invalid".to_string())?;
                        if !matches!(
                            part.get("type").and_then(Value::as_str),
                            Some("input_text" | "output_text")
                        ) {
                            return Err("message content type invalid".to_string());
                        }
                        text.push_str(
                            part.get("text")
                                .and_then(Value::as_str)
                                .ok_or_else(|| "message text missing".to_string())?,
                        );
                    }
                }
                messages.push(GatewayMessage::text(role, bounded_gateway_text(&text)?));
            }
            "function_call" => {
                let id = item
                    .get("call_id")
                    .or_else(|| item.get("id"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| "function call id missing".to_string())?;
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "function call name missing".to_string())?;
                if name != TOOL_NAME {
                    return Err("unknown tool call".to_string());
                }
                let arguments = item
                    .get("arguments")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "function call arguments missing".to_string())?;
                tool_calls.push(VitaFunctionCall {
                    id: bounded_gateway_id(id)?,
                    name: name.to_string(),
                    arguments: bounded_gateway_text(arguments)?,
                });
            }
            "function_call_output" => {
                let call_id = item
                    .get("call_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "function output id missing".to_string())?;
                let output = item
                    .get("output")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                    .or_else(|| item.get("output").map(Value::to_string))
                    .ok_or_else(|| "function output missing".to_string())?;
                tool_outputs.push(VitaToolOutput {
                    call_id: bounded_gateway_id(call_id)?,
                    output: bounded_gateway_text(&output)?,
                });
            }
            _ => return Err("unsupported Responses input item".to_string()),
        }
    }
    let mut options = VitaResponsesRequestOptions {
        stream: true,
        ..Default::default()
    };
    let mut advertised_tool = false;
    if let Some(tools) = object.get("tools") {
        for tool in tools
            .as_array()
            .ok_or_else(|| "tools invalid".to_string())?
        {
            let tool = tool.as_object().ok_or_else(|| "tool invalid".to_string())?;
            if tool.get("type").and_then(Value::as_str) != Some("function") {
                return Err("tool type invalid".to_string());
            }
            let name = tool
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| {
                    tool.get("function")
                        .and_then(Value::as_object)
                        .and_then(|function| function.get("name"))
                        .and_then(Value::as_str)
                })
                .ok_or_else(|| "tool name missing".to_string())?;
            if name != TOOL_NAME {
                return Err("unknown advertised tool".to_string());
            }
            if advertised_tool {
                return Err("duplicate advertised tool".to_string());
            }
            advertised_tool = true;
            let description = tool
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_string);
            let parameters = tool
                .get("parameters")
                .cloned()
                .or_else(|| {
                    tool.get("function")
                        .and_then(Value::as_object)
                        .and_then(|function| function.get("parameters"))
                        .cloned()
                })
                .ok_or_else(|| "tool parameters missing".to_string())?;
            options.tools.push(GatewayToolDefinition {
                name: name.to_string(),
                description,
                parameters,
            });
        }
    }
    Ok(VitaResponsesRequest {
        model: model.to_string(),
        messages,
        options,
        tool_calls,
        tool_outputs,
    })
}

fn bounded_gateway_text(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > MAX_PROMPT_BYTES
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    {
        return Err("gateway text exceeded its bound".to_string());
    }
    Ok(value.to_string())
}

fn bounded_gateway_id(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 128
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err("gateway identifier exceeded its bound".to_string());
    }
    Ok(value.to_string())
}

fn bounded_utf8_prefix(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn bounded_protocol_text(value: &str, max_bytes: usize) -> String {
    let mut output = String::new();
    for character in value.chars() {
        let character = if character.is_control() && !matches!(character, '\n' | '\r' | '\t') {
            ' '
        } else {
            character
        };
        let remaining = max_bytes.saturating_sub(output.len());
        if remaining == 0 || character.len_utf8() > remaining {
            break;
        }
        output.push(character);
    }
    output
}

const AUTHORITY_REQUEST_TIMEOUT: Duration = Duration::from_secs(35);
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
                    let body = match protocol::read_sensitive_frame(&mut reader) {
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
                .recv_timeout(AUTHORITY_REQUEST_TIMEOUT)
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
        receive_command_from(&receiver)
    }
}

fn receive_command_from(receiver: &Receiver<HostMessage>) -> Result<Option<HostMessage>, String> {
    Ok(receiver.recv().ok())
}

fn host_request_id(message: &HostMessage) -> &str {
    match message {
        HostMessage::Initialize(message) => &message.request_id,
        HostMessage::AuthorityScopeReply(message) => &message.request_id,
        HostMessage::ConfirmationReply(message) => &message.request_id,
        HostMessage::GrantIssued(message) => &message.request_id,
        HostMessage::GrantRevalidated(message) => &message.request_id,
        HostMessage::CancelAction(message) => &message.request_id,
        HostMessage::StartTurn(message) => &message.request_id,
        HostMessage::CancelTurn(message) => &message.request_id,
        HostMessage::SensitiveCredentialReply(message) => &message.request_id,
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
        VitaMessage::CredentialRequired(message) => &message.request_id,
        VitaMessage::TurnState(message) => &message.request_id,
        VitaMessage::TurnCompleted(message) => &message.request_id,
        VitaMessage::TurnFailed(message) => &message.request_id,
        VitaMessage::ShutdownAck(message) => &message.request_id,
        VitaMessage::Fatal(message) => &message.request_id,
    }
}

pub async fn serve_ipc(test_canary: bool) -> Result<(), String> {
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

    let router = SidecarRouter::start(reader, writer);
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
    let context = VitaExecutionContext::try_new(init.life_id.clone(), init.task_id.clone())
        .map_err(|error| format!("Vita execution identity was invalid: {error:?}"))?;
    let active_identity = Arc::new(Mutex::new(None::<ProviderRequestIdentity>));
    let authority = Arc::new(SidecarHostAuthority {
        router: router.clone(),
        session_id: init.session_id.clone(),
        active_identity: Arc::clone(&active_identity),
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
    let (entrypoint, mut gateway_server) = if let Some(provider_config) = init.provider.as_ref() {
        provider_config.validate().map_err(protocol_error)?;
        #[cfg(not(feature = "d29-h9-test-helper"))]
        if test_canary {
            return Err("H9 canary mode is not enabled in this sidecar image".to_string());
        }
        let provider = if test_canary {
            #[cfg(feature = "d29-h9-test-helper")]
            {
                crate::ProviderProfile::new_for_test_localhost(
                    provider_config.profile_id.clone(),
                    "D29-H9 deterministic local Chat provider",
                    crate::ProviderProtocol::OpenAiChatCompletions,
                    &provider_config.base_url,
                    provider_config.model.clone(),
                    None,
                    Duration::from_secs(30),
                    crate::ProviderRetryPolicy::default(),
                    crate::ProviderCapabilities {
                        streaming: true,
                        tools: true,
                        developer_role: true,
                        ..crate::ProviderCapabilities::none()
                    },
                )
            }
            #[cfg(not(feature = "d29-h9-test-helper"))]
            {
                unreachable!("test canary was rejected above")
            }
        } else {
            let credential = crate::CredentialRef::new(
                provider_config.credential_ref.clone(),
                provider_config.profile_id.clone(),
                &provider_config.base_url,
            )
            .map_err(|error| format!("Vita credential binding was rejected: {error}"))?;
            crate::ProviderProfile::new(
                provider_config.profile_id.clone(),
                "Digital Life active Chat provider",
                crate::ProviderProtocol::OpenAiChatCompletions,
                &provider_config.base_url,
                provider_config.model.clone(),
                Some(credential),
                Duration::from_secs(300),
                crate::ProviderRetryPolicy::default(),
                crate::ProviderCapabilities {
                    streaming: true,
                    tools: true,
                    developer_role: true,
                    ..crate::ProviderCapabilities::none()
                },
            )
        }
        .map_err(|error| format!("Vita provider was rejected: {error}"))?;
        let provider_authority =
            crate::provider_gateway::VitaProviderAuthority::configure(provider)
                .map_err(|error| format!("Vita provider authority was rejected: {error}"))?;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .map_err(|error| format!("Vita local gateway could not bind: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("Vita local gateway address unavailable: {error}"))?
            .port();
        let binding =
            crate::provider_gateway::VitaGatewayBinding::for_authenticated_private_listener(port)
                .map_err(|error| format!("Vita local gateway binding failed: {error}"))?;
        let ready = provider_authority
            .prepare_gateway(binding)
            .map_err(|error| format!("Vita provider gateway preparation failed: {error}"))?;
        let gateway_server = VitaGatewayServer::start(
            listener,
            ready.clone(),
            provider_config.clone(),
            router.clone(),
            init.session_id.clone(),
            Arc::clone(&active_identity),
            if test_canary {
                #[cfg(feature = "d29-h9-test-helper")]
                {
                    SidecarGatewayTransport::H9Canary(Arc::new(H9CanaryTransport::new()))
                }
                #[cfg(not(feature = "d29-h9-test-helper"))]
                {
                    unreachable!("test canary was rejected above")
                }
            } else {
                SidecarGatewayTransport::Production
            },
        )
        .map_err(|error| format!("Vita local gateway startup failed: {error}"))?;
        let entrypoint =
            VitaAgentEntrypoint::initialize_with_authenticated_gateway(profile, &ready)
                .await
                .map_err(|error| format!("Vita entrypoint initialization failed: {error}"))?;
        (entrypoint, Some(gateway_server))
    } else {
        let entrypoint = VitaAgentEntrypoint::initialize(profile)
            .await
            .map_err(|error| format!("Vita entrypoint initialization failed: {error}"))?;
        (entrypoint, None)
    };
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
    spawn_confirmation_loop(
        router.clone(),
        init.clone(),
        receiver,
        Arc::clone(&active_identity),
    );

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
            if let Some(gateway_server) = gateway_server.take() {
                gateway_server.stop();
            }
            return Err("Vita Host pipe closed".to_string());
        };
        match command {
            HostMessage::CancelAction(message) if message.session_id == init.session_id => {
                // Cancel only the current governed action.  The Host may
                // start a later turn after the exact Cancelled acknowledgement;
                // session-terminal teardown uses `production.cancel()` below.
                production.cancel_turn();
                router.send(&VitaMessage::ActionCancelled(protocol::ActionCancelled {
                    request_id: message.request_id,
                    session_id: init.session_id.clone(),
                }))?;
            }
            HostMessage::StartTurn(message) if message.session_id == init.session_id => {
                handle_start_turn(
                    message,
                    &init,
                    init.provider.as_ref(),
                    Arc::clone(&runtime),
                    Arc::clone(&production),
                    router.clone(),
                    Arc::clone(&active_identity),
                );
            }
            HostMessage::CancelTurn(message) if message.session_id == init.session_id => {
                handle_cancel_turn(
                    message,
                    &init,
                    Arc::clone(&runtime),
                    Arc::clone(&production),
                    router.clone(),
                    Arc::clone(&active_identity),
                );
            }
            HostMessage::Shutdown(message) if message.session_id == init.session_id => {
                production.cancel();
                runtime.shutdown().await;
                if let Some(gateway_server) = gateway_server.take() {
                    gateway_server.stop();
                }
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

fn handle_start_turn(
    message: StartTurn,
    init: &InitializeSession,
    provider_config: Option<&ProviderConfiguration>,
    runtime: Arc<VitaAgentRuntime>,
    production: Arc<VitaGitStatusProduction>,
    router: SidecarRouter,
    active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
) {
    let request_id = message.request_id.clone();
    let turn_id = message.turn_id.clone();
    let failed = |code: &str| {
        let _ = router.send(&VitaMessage::TurnFailed(TurnFailed {
            request_id: request_id.clone(),
            session_id: init.session_id.clone(),
            turn_id: turn_id.clone(),
            phase: TurnPhase::Failed,
            error_code: code.to_string(),
            message: "Vita turn was not started".to_string(),
        }));
    };
    if message.validate().is_err() {
        failed("TURN_REQUEST_INVALID");
        return;
    }
    let Some(provider_config) = provider_config else {
        failed("NOT_CONFIGURED");
        return;
    };
    let expected =
        match ProviderBinding::derive(&init.session_id, &message.turn_id, provider_config) {
            Ok(binding) => binding,
            Err(_) => {
                failed("PROVIDER_INELIGIBLE");
                return;
            }
        };
    if message.binding != expected {
        failed("PROVIDER_BINDING_MISMATCH");
        return;
    }
    let identity = ProviderRequestIdentity {
        turn_id: message.turn_id.clone(),
        binding_hash: message.binding.binding_hash.clone(),
    };
    {
        let Ok(mut active) = active_identity.lock() else {
            failed("TURN_STATE_UNAVAILABLE");
            return;
        };
        if active.is_some() {
            failed("BUSY");
            return;
        }
        *active = Some(identity.clone());
    }
    production.begin_turn();
    let _ = router.send(&VitaMessage::TurnState(TurnState {
        request_id: next_request_id("vita-turn-starting"),
        session_id: init.session_id.clone(),
        turn_id: turn_id.clone(),
        phase: TurnPhase::Starting,
    }));
    let _ = router.send(&VitaMessage::TurnState(TurnState {
        request_id: next_request_id("vita-turn-running"),
        session_id: init.session_id.clone(),
        turn_id: turn_id.clone(),
        phase: TurnPhase::Running,
    }));
    let session_id = init.session_id.clone();
    let model = provider_config.model.clone();
    let prompt = message.prompt;
    tokio::spawn(async move {
        let result = runtime.run_turn(prompt).await;
        let still_current = active_identity
            .lock()
            .ok()
            .is_some_and(|active| active.as_ref() == Some(&identity));
        if !still_current {
            return;
        }
        if let Ok(mut active) = active_identity.lock() {
            active.take();
        }
        match result {
            Ok(assistant_text) => {
                let text = if assistant_text.is_empty() {
                    "(Vita completed without assistant text)".to_string()
                } else {
                    bounded_protocol_text(&assistant_text, MAX_TURN_OUTPUT_BYTES)
                };
                let _ = router.send(&VitaMessage::TurnCompleted(TurnCompleted {
                    request_id: next_request_id("vita-turn-completed"),
                    session_id,
                    turn_id,
                    model,
                    assistant_text: text,
                }));
            }
            Err(error) => {
                let error_text = error.to_string();
                let cancelled = error_text.to_ascii_lowercase().contains("cancel");
                let _ = router.send(&VitaMessage::TurnFailed(TurnFailed {
                    request_id: next_request_id("vita-turn-failed"),
                    session_id,
                    turn_id,
                    phase: if cancelled {
                        TurnPhase::Cancelled
                    } else {
                        TurnPhase::Failed
                    },
                    error_code: if cancelled {
                        "CANCELLED"
                    } else {
                        "TURN_FAILED"
                    }
                    .to_string(),
                    message: bounded_protocol_text(&error_text, 256),
                }));
            }
        }
    });
}

fn handle_cancel_turn(
    message: protocol::CancelTurn,
    init: &InitializeSession,
    runtime: Arc<VitaAgentRuntime>,
    production: Arc<VitaGitStatusProduction>,
    router: SidecarRouter,
    active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
) {
    if message.validate().is_err() {
        return;
    }
    let matches = active_identity.lock().ok().is_some_and(|active| {
        active
            .as_ref()
            .is_some_and(|identity| identity.turn_id == message.turn_id)
    });
    if !matches {
        return;
    }
    if let Ok(mut active) = active_identity.lock() {
        active.take();
    }
    production.cancel_turn();
    let session_id = init.session_id.clone();
    let turn_id = message.turn_id;
    tokio::spawn(async move {
        // The acknowledgement is emitted only after the bounded Codex
        // interrupt attempt has completed.  Clearing the identity above
        // fences gateway credentials/tool continuations immediately; this
        // final frame is the Host-visible proof that the old lifecycle is
        // terminally fenced.
        let _ = runtime.interrupt_active_turn().await;
        let _ = router.send(&VitaMessage::TurnState(TurnState {
            request_id: next_request_id("vita-turn-cancelled"),
            session_id,
            turn_id,
            phase: TurnPhase::Cancelled,
        }));
    });
}

fn spawn_confirmation_loop(
    router: SidecarRouter,
    init: InitializeSession,
    mut receiver: tokio::sync::mpsc::Receiver<VitaGitStatusPendingConfirmation>,
    active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
) {
    tokio::spawn(async move {
        while let Some(action) = receiver.recv().await {
            if !action.is_current() {
                let _ = action.confirm(0);
                continue;
            }
            let binding = action.binding();
            let Some(active) = active_identity_snapshot(&active_identity) else {
                let _ = action.confirm(0);
                continue;
            };
            let host_turn_id = active.turn_id.clone();
            let _ = router.send(&VitaMessage::TurnState(TurnState {
                request_id: next_request_id("vita-turn-awaiting-confirmation"),
                session_id: init.session_id.clone(),
                turn_id: host_turn_id.clone(),
                phase: TurnPhase::WaitingForToolConfirmation,
            }));
            let wire_binding = binding_to_wire(&init.session_id, &binding);
            let request_id = next_request_id("vita-confirm");
            let response = tokio::task::spawn_blocking({
                let router = router.clone();
                let message = VitaMessage::ConfirmationRequired(ConfirmationRequired {
                    request_id,
                    session_id: init.session_id.clone(),
                    host_turn_id: host_turn_id.clone(),
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
            if !action.is_current() {
                let _ = action.confirm(0);
                continue;
            }
            let _ = action.confirm(revision);
            if active_identity_matches(&active_identity, &active) {
                let _ = router.send(&VitaMessage::TurnState(TurnState {
                    request_id: next_request_id("vita-turn-resumed"),
                    session_id: init.session_id.clone(),
                    turn_id: host_turn_id,
                    phase: TurnPhase::Running,
                }));
            }
        }
    });
}

struct SidecarHostAuthority {
    router: SidecarRouter,
    session_id: String,
    active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
}

impl SidecarHostAuthority {
    fn host_turn_id(&self) -> Result<String, String> {
        active_identity_snapshot(&self.active_identity)
            .map(|identity| identity.turn_id)
            .ok_or_else(|| "Vita Host turn is no longer active".to_string())
    }
}

impl VitaGitStatusAuthority for SidecarHostAuthority {
    fn evaluate_workspace_scope(&self, binding: &H7ProcessBinding) -> Result<i64, String> {
        let request_id = next_request_id("vita-scope");
        let host_turn_id = self.host_turn_id()?;
        let response = self
            .router
            .request(VitaMessage::AuthorityEvaluate(AuthorityEvaluate {
                request_id,
                session_id: self.session_id.clone(),
                host_turn_id,
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
        let host_turn_id = self.host_turn_id()?;
        let expected_binding = binding_to_wire(&self.session_id, binding);
        let response = self.router.request(VitaMessage::IssueGrant(IssueGrant {
            request_id,
            session_id: self.session_id.clone(),
            host_turn_id,
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
        let host_turn_id = self.host_turn_id()?;
        let response = self
            .router
            .request(VitaMessage::RevalidateGrant(RevalidateGrant {
                request_id,
                session_id: self.session_id.clone(),
                host_turn_id,
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn idle_command_receiver_blocks_until_command_without_timeout() {
        let (sender, receiver) = mpsc::sync_channel(0);
        let message = HostMessage::Shutdown(protocol::Shutdown {
            request_id: "shutdown".to_string(),
            session_id: "session".to_string(),
        });
        assert!(matches!(
            sender.try_send(message.clone()),
            Err(mpsc::TrySendError::Full(_))
        ));
        let worker = std::thread::spawn(move || receive_command_from(&receiver));
        sender.send(message).expect("command send");
        assert!(matches!(
            worker.join().expect("command receiver worker"),
            Ok(Some(HostMessage::Shutdown(_)))
        ));
    }

    #[test]
    fn command_receiver_reports_pipe_disconnect() {
        let (sender, receiver) = mpsc::sync_channel::<HostMessage>(1);
        drop(sender);
        assert_eq!(
            receive_command_from(&receiver).expect("disconnect result"),
            None
        );
    }

    #[test]
    fn local_gateway_requires_current_session_token_and_exact_route() {
        let request = |method: &str, path: &str, authorization: Option<&str>| GatewayHttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            authorization: authorization.map(str::to_string),
            body: Vec::new(),
        };
        assert_eq!(
            authorize_gateway_request(&request("POST", LOCAL_GATEWAY_PATH, None), "current"),
            Err("GATEWAY_AUTH_DENIED")
        );
        assert_eq!(
            authorize_gateway_request(&request("POST", LOCAL_GATEWAY_PATH, Some("old")), "current"),
            Err("GATEWAY_AUTH_DENIED")
        );
        assert_eq!(
            authorize_gateway_request(
                &request("GET", LOCAL_GATEWAY_PATH, Some("current")),
                "current"
            ),
            Err("GATEWAY_ROUTE_DENIED")
        );
        assert_eq!(
            authorize_gateway_request(&request("POST", "/v1/other", Some("current")), "current"),
            Err("GATEWAY_ROUTE_DENIED")
        );
        assert!(authorize_gateway_request(
            &request("POST", LOCAL_GATEWAY_PATH, Some("current")),
            "current"
        )
        .is_ok());
    }

    #[test]
    fn responses_request_parser_keeps_multiline_text_and_only_fixed_tool() {
        let body = serde_json::to_vec(&json!({
            "model": "model",
            "stream": true,
            "instructions": "line one\nline two",
            "input": [{
                "type": "message",
                "role": "user",
                "content": [{"type": "input_text", "text": "hello\nworld"}]
            }],
            "tools": [{
                "type": "function",
                "name": TOOL_NAME,
                "parameters": {"type": "object"}
            }]
        }))
        .unwrap();
        let request = parse_gateway_responses_request(&body, "model").unwrap();
        assert_eq!(request.messages.len(), 2);
        assert_eq!(request.options.tools.len(), 1);

        let unknown = serde_json::to_vec(&json!({
            "model": "model",
            "stream": true,
            "input": [{"type":"message","role":"user","content":"hello"}],
            "tools": [{"type":"function","name":"other","parameters":{}}]
        }))
        .unwrap();
        assert!(parse_gateway_responses_request(&unknown, "model").is_err());

        let invalid_id = serde_json::to_vec(&json!({
            "model": "model",
            "stream": true,
            "input": [{
                "type": "function_call",
                "call_id": "call\n1",
                "name": TOOL_NAME,
                "arguments": "{}"
            }]
        }))
        .unwrap();
        assert!(parse_gateway_responses_request(&invalid_id, "model").is_err());
    }
}
