//! Process-isolated Vita sidecar entrypoint.
//!
//! The sidecar owns the native workspace capability, H7 supervisor, and the
//! pinned Codex composition. Authority decisions are RPCs to the Tauri Host;
//! this process never reads the Host SQLite database and never mints a grant.

use codex_extension_api::ToolContributor;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::io::{BufReader, BufWriter, Read, Stdin, Stdout, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
#[cfg(feature = "d29-h9-test-helper")]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use zeroize::Zeroizing;

use protocol::{
    AuthorityEvaluate, ConfirmationDecision, ConfirmationRequired, CredentialRequired,
    ExecuteRecovery, GrantIssued, Handshake, HostMessage, InitializeSession, IssueGrant,
    ProcessBinding, ProcessGrant, ProviderBinding, ProviderConfiguration, RecoveryIssueGrant,
    RecoveryOutcome, RecoveryResult, RevalidateGrant, StartTurn, TurnCompleted, TurnFailed,
    TurnPhase, TurnState, VitaMessage, CODEX_PROTOCOL_SCHEMA_HASH, CODEX_UPSTREAM_COMMIT,
    MAX_FRAME_BYTES, MAX_PROMPT_BYTES, MAX_TURN_OUTPUT_BYTES, PROTOCOL_VERSION, RUNTIME_ID,
    TOOL_NAME,
};
use vita_agent_protocol as protocol;

use crate::d29h5::RecoveryExecutionOutcome;
use crate::provider_gateway::{
    CredentialResolver, GatewayReadyProvider, GatewayToolDefinition, ProviderGateway,
    ProviderRequestIdentity, ResolvedCredential, VitaFunctionCall, VitaMessage as GatewayMessage,
    VitaMessageRole, VitaResponsesRequest, VitaResponsesRequestOptions, VitaToolOutput,
};
use crate::recovery_journal::{RecoveryJournalStore, RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES};
use crate::{
    H3ApprovalFloor, H3AuthorityOperation, H3AuthorityRequest, H3CanonicalDecision,
    H3CanonicalDecisionCode, H3CanonicalOutcome, H3DisclosureRequest, H3HostAuthorityResponse,
    H3HostScopedGrantEvidence, H3ScopeRequirement, H4ApprovalFloor, H4AuthorityOperation,
    H4AuthorityRequest, H4CanonicalDecision, H4CanonicalDecisionCode, H4CanonicalOutcome,
    H4ConfirmationEvidenceSource, H4HostAuthorityResponse, H4HostReplaceGrantEvidence,
    H4ReplaceOperation, H4ScopeRequirement, H5RecoveryExecutor, H7ProcessBinding, H7ProcessGrant,
    HostExplicitActionConfirmationEvidence, PreparedWorkspaceTargetKind, RecoveryActionRequest,
    RecoveryAuthorityPort, RecoveryDenyReason, RecoveryGrantEvidence, TrustedWorkspaceRoot,
    VitaAgentEntrypoint, VitaAgentRuntime, VitaAgentRuntimeProfile, VitaCargoCheckProduction,
    VitaCargoCheckToolContributor, VitaExecutionContext, VitaGitStatusAuthority,
    VitaGitStatusPendingConfirmation, VitaGitStatusProduction, VitaGitStatusToolContributor,
    VitaH3AuthorityError, VitaH3AuthorityFuture, VitaH3AuthorityPort, VitaH3DisclosureFuture,
    VitaH4AuthorityError, VitaH4AuthorityFuture, VitaH4AuthorityPort,
    VitaWorkspacePatchToolContributor, VitaWorkspaceReadBroker, VitaWorkspaceReadToolContributor,
    VitaWorkspaceReplaceBroker, VitaWorkspaceReplaceH5ToolContributor, D32_CARGO_CAPABILITY_ID,
    D32_CARGO_NO_GIT_METADATA_FENCE, D32_CARGO_PROFILE_ID, D32_CARGO_TOOL_NAME,
    H5_RECOVER_REPLACE_CAPABILITY_ID, VITA_WORKSPACE_GIT_STATUS_CAPABILITY_ID,
    VITA_WORKSPACE_GIT_STATUS_PROFILE_ID, VITA_WORKSPACE_GIT_STATUS_TOOL_NAME,
    VITA_WORKSPACE_READ_CAPABILITY_ID, VITA_WORKSPACE_READ_TOOL_NAME,
    VITA_WORKSPACE_REPLACE_CAPABILITY_ID, VITA_WORKSPACE_REPLACE_TOOL_NAME,
};

use crate::VITA_WORKSPACE_PATCH_TOOL_NAME;

const LOCAL_GATEWAY_HEADER_LIMIT: usize = 64 * 1024;
const LOCAL_GATEWAY_BODY_LIMIT: usize = MAX_FRAME_BYTES;
const LOCAL_GATEWAY_IO_TIMEOUT: Duration = Duration::from_secs(5);
const LOCAL_GATEWAY_PATH: &str = "/v1/responses";
const MAX_GATEWAY_TEXT_BYTES: usize = MAX_TURN_OUTPUT_BYTES;

/// A loopback bearer credential scoped to one Host turn.  The previous
/// session-wide token authenticated the listener but could not distinguish a
/// late request from turn A after turn B had become active.
#[derive(Clone, PartialEq, Eq)]
struct TurnGatewayToken(Zeroizing<String>);

impl std::fmt::Debug for TurnGatewayToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TurnGatewayToken([REDACTED])")
    }
}

impl TurnGatewayToken {
    fn generate() -> Result<Self, String> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes)
            .map_err(|_| "Vita turn gateway credential could not be generated".to_string())?;
        let value = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Ok(Self(Zeroizing::new(value)))
    }

    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone)]
struct GatewayGeneration {
    generation: u64,
    identity: ProviderRequestIdentity,
    token: TurnGatewayToken,
}

struct GatewayAuthority {
    next_generation: AtomicU64,
    active: Mutex<Option<GatewayGeneration>>,
}

struct ActiveTurnTask {
    identity: ProviderRequestIdentity,
    gateway: GatewayGeneration,
    cancelled: Arc<AtomicBool>,
    cancel_notify: Arc<tokio::sync::Notify>,
    join: tokio::task::JoinHandle<Result<String, crate::VitaAgentError>>,
}

enum SidecarLoopEvent {
    Command(Result<Result<Option<HostMessage>, String>, tokio::task::JoinError>),
    Recovery(Result<Result<(), String>, tokio::task::JoinError>),
}

#[derive(Default)]
struct TurnOwner {
    active: Mutex<Option<ActiveTurnTask>>,
}

impl TurnOwner {
    fn install(&self, task: ActiveTurnTask) -> Result<(), String> {
        let mut active = self
            .active
            .lock()
            .map_err(|_| "Vita turn owner was poisoned".to_string())?;
        if active.is_some() {
            task.join.abort();
            return Err("Vita turn owner is already occupied".to_string());
        }
        *active = Some(task);
        Ok(())
    }

    fn take(&self, identity: &ProviderRequestIdentity) -> Option<ActiveTurnTask> {
        self.active.lock().ok().and_then(|mut active| {
            active
                .as_ref()
                .is_some_and(|task| task.identity == *identity)
                .then(|| active.take())
                .flatten()
        })
    }

    fn reap_finished(&self) {
        if let Ok(mut active) = self.active.lock() {
            if active.as_ref().is_some_and(|task| task.join.is_finished()) {
                active.take();
            }
        }
    }
}

impl GatewayAuthority {
    fn new() -> Self {
        Self {
            next_generation: AtomicU64::new(0),
            active: Mutex::new(None),
        }
    }

    fn activate(&self, identity: ProviderRequestIdentity) -> Result<GatewayGeneration, String> {
        let generation = self.next_generation.fetch_add(1, Ordering::AcqRel) + 1;
        let value = GatewayGeneration {
            generation,
            identity,
            token: TurnGatewayToken::generate()?,
        };
        let mut active = self
            .active
            .lock()
            .map_err(|_| "Vita gateway authority was poisoned".to_string())?;
        if active.is_some() {
            return Err("Vita gateway already has an active turn".to_string());
        }
        *active = Some(value.clone());
        Ok(value)
    }

    fn deactivate(&self, identity: &ProviderRequestIdentity) -> bool {
        let Ok(mut active) = self.active.lock() else {
            return false;
        };
        let Some(current) = active.as_ref() else {
            return false;
        };
        if current.identity != *identity {
            return false;
        }
        active.take();
        self.next_generation.fetch_add(1, Ordering::AcqRel);
        true
    }

    fn deactivate_generation(&self, expected: &GatewayGeneration) -> bool {
        let Ok(mut active) = self.active.lock() else {
            return false;
        };
        let Some(current) = active.as_ref() else {
            return false;
        };
        if current.generation != expected.generation
            || current.identity != expected.identity
            || current.token != expected.token
        {
            return false;
        }
        active.take();
        self.next_generation.fetch_add(1, Ordering::AcqRel);
        true
    }

    fn authorize(&self, token: &str) -> Option<GatewayGeneration> {
        self.active.lock().ok().and_then(|active| {
            active
                .as_ref()
                .filter(|generation| generation.token.as_str() == token)
                .cloned()
        })
    }

    fn is_current(&self, expected: &GatewayGeneration) -> bool {
        self.active.lock().ok().is_some_and(|active| {
            active.as_ref().is_some_and(|current| {
                current.generation == expected.generation
                    && current.identity == expected.identity
                    && current.token == expected.token
            })
        })
    }
}

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
    gateway_authority: Arc<GatewayAuthority>,
    expected: ProviderRequestIdentity,
    expected_gateway: GatewayGeneration,
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
        if !active_identity_matches(&self.active_identity, &self.expected)
            || !self.gateway_authority.is_current(&self.expected_gateway)
        {
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
    expected_workspace_path: String,
    read_mode: bool,
    negative_read_mode: bool,
    replace_mode: bool,
    negative_replace_mode: bool,
    patch_mode: bool,
    negative_patch_mode: bool,
    patch_conflict_mode: bool,
    cargo_mode: bool,
    negative_cargo_mode: bool,
    response_model: String,
}

#[cfg(feature = "d29-h9-test-helper")]
const D31_B_CANARY_CONTENT: &str = "D31-B bounded canary content\n";

#[cfg(feature = "d29-h9-test-helper")]
const D31_C_CANARY_CONTENT: &str = "D31-C original canary content\n";

#[cfg(feature = "d29-h9-test-helper")]
const D31_C_REPLACEMENT_CONTENT: &str = "D31-C replacement canary content\n";

#[cfg(feature = "d29-h9-test-helper")]
impl H9CanaryTransport {
    fn new(
        expected_workspace_path: impl Into<String>,
        read_mode: bool,
        negative_read_mode: bool,
        replace_mode: bool,
        negative_replace_mode: bool,
        patch_mode: bool,
        negative_patch_mode: bool,
        patch_conflict_mode: bool,
        cargo_mode: bool,
        negative_cargo_mode: bool,
        response_model: impl Into<String>,
    ) -> Self {
        Self {
            request_count: AtomicUsize::new(0),
            expected_workspace_path: expected_workspace_path.into(),
            read_mode,
            negative_read_mode,
            replace_mode,
            negative_replace_mode,
            patch_mode,
            negative_patch_mode,
            patch_conflict_mode,
            cargo_mode,
            negative_cargo_mode,
            response_model: response_model.into(),
        }
    }
}

#[cfg(feature = "d29-h9-test-helper")]
impl crate::provider_gateway::ProviderRequestTransport for H9CanaryTransport {
    fn post_json(
        &self,
        endpoint: &crate::provider_gateway::ProviderEndpoint,
        authorization: Option<&ResolvedCredential>,
        body: &[u8],
        _timeout: Duration,
        _retry_policy: crate::provider_gateway::ProviderRetryPolicy,
    ) -> Result<Vec<u8>, crate::VitaAgentError> {
        if !endpoint.is_test_localhost() {
            return Err(crate::VitaAgentError::GatewayProtocol(
                "H9 canary transport accepts only the test loopback endpoint".to_string(),
            ));
        }
        if authorization.map(ResolvedCredential::as_str) != Some("h9-canary-fake-credential") {
            return Err(crate::VitaAgentError::CredentialResolution(
                "H9 canary provider received the wrong credential",
            ));
        }
        let request_number = self.request_count.fetch_add(1, Ordering::AcqRel) + 1;
        let request: Value = serde_json::from_slice(body).map_err(|_| {
            crate::VitaAgentError::GatewayProtocol(
                "H9 canary provider request was not JSON".to_string(),
            )
        })?;
        let messages = request
            .get("messages")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                crate::VitaAgentError::GatewayProtocol(
                    "H9 canary provider request omitted messages".to_string(),
                )
            })?;
        match request_number {
            1 => {
                let tools = request
                    .get("tools")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        crate::VitaAgentError::GatewayProtocol(
                            "H9 canary first request omitted tools".to_string(),
                        )
                    })?;
                let mut names = tools
                    .iter()
                    .filter_map(|tool| {
                        tool.get("function")
                            .and_then(Value::as_object)
                            .and_then(|function| function.get("name"))
                            .and_then(Value::as_str)
                            .or_else(|| tool.get("name").and_then(Value::as_str))
                    })
                    .collect::<Vec<_>>();
                names.sort_unstable();
                let mut expected_names = vec![
                    VITA_WORKSPACE_GIT_STATUS_TOOL_NAME,
                    VITA_WORKSPACE_PATCH_TOOL_NAME,
                    VITA_WORKSPACE_READ_TOOL_NAME,
                    VITA_WORKSPACE_REPLACE_TOOL_NAME,
                ];
                if names.len() == 5 {
                    expected_names.push(D32_CARGO_TOOL_NAME);
                    expected_names.sort_unstable();
                }
                if names != expected_names {
                    return Err(crate::VitaAgentError::GatewayProtocol(
                        "H9 canary first request advertised an unexpected tool set".to_string(),
                    ));
                }
            }
            2 => {
                let tool_output = messages
                    .iter()
                    .find(|message| message.get("role").and_then(Value::as_str) == Some("tool"));
                let output = tool_output
                    .and_then(|message| message.get("content"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        crate::VitaAgentError::GatewayProtocol(
                            "H9 canary second request omitted the native tool output".to_string(),
                        )
                    })?;
                let result: Value = serde_json::from_str(output).map_err(|_| {
                    crate::VitaAgentError::GatewayProtocol(
                        "H9 canary native tool output was not JSON".to_string(),
                    )
                })?;
                let valid = if self.patch_mode {
                    let mutation = result.get("mutation_performed").and_then(Value::as_bool);
                    let side_effects = result.get("side_effect_count").and_then(Value::as_u64);
                    if self.patch_conflict_mode {
                        result.get("status").and_then(Value::as_str) == Some("conflict")
                            && result.get("reason").and_then(Value::as_str) == Some("base_changed")
                            && mutation == Some(false)
                            && side_effects == Some(0)
                    } else if self.negative_patch_mode {
                        result.get("status").and_then(Value::as_str) == Some("denied")
                            && mutation == Some(false)
                            && side_effects == Some(0)
                    } else {
                        result.get("status").and_then(Value::as_str) == Some("patch_applied")
                            && mutation == Some(true)
                            && side_effects == Some(1)
                    }
                } else if self.replace_mode {
                    let relative_path = result.get("relative_path").and_then(Value::as_str);
                    let replacement_hash = crate::sha256_hex(D31_C_REPLACEMENT_CONTENT.as_bytes());
                    let original_hash = crate::sha256_hex(D31_C_CANARY_CONTENT.as_bytes());
                    if self.negative_replace_mode {
                        result.get("status").and_then(Value::as_str) == Some("denied")
                            && relative_path == Some("canary.txt")
                            && result.get("mutation_performed").and_then(Value::as_bool)
                                == Some(false)
                            && result.get("side_effect_count").and_then(Value::as_u64) == Some(0)
                            && result.get("automatic_retry").and_then(Value::as_bool) == Some(false)
                            && result.get("recovery_required").and_then(Value::as_bool)
                                == Some(false)
                    } else {
                        result.get("status").and_then(Value::as_str) == Some("committed")
                            && relative_path == Some("canary.txt")
                            && result.get("before_sha256").and_then(Value::as_str)
                                == Some(original_hash.as_str())
                            && result.get("after_sha256").and_then(Value::as_str)
                                == Some(replacement_hash.as_str())
                            && result.get("bytes_written").and_then(Value::as_u64)
                                == Some(D31_C_REPLACEMENT_CONTENT.len() as u64)
                            && result.get("mutation_performed").and_then(Value::as_bool)
                                == Some(true)
                            && result.get("side_effect_count").and_then(Value::as_u64) == Some(1)
                            && result.get("automatic_retry").and_then(Value::as_bool) == Some(false)
                            && result.get("recovery_required").and_then(Value::as_bool)
                                == Some(false)
                    }
                } else if self.cargo_mode {
                    let status = result.get("status").and_then(Value::as_str);
                    let exit_code_ok = if self.negative_cargo_mode {
                        result.get("exit_code").is_some_and(Value::is_null)
                    } else {
                        result.get("exit_code").and_then(Value::as_i64) == Some(0)
                    };
                    let public_shape_ok = status
                        == Some(if self.negative_cargo_mode {
                            "denied"
                        } else {
                            "completed"
                        })
                        && exit_code_ok
                        && result.get("timed_out").and_then(Value::as_bool) == Some(false)
                        && result.get("stdout").and_then(Value::as_str).is_some()
                        && result.get("stderr").and_then(Value::as_str).is_some()
                        && result
                            .get("stdout_truncated")
                            .and_then(Value::as_bool)
                            .is_some()
                        && result
                            .get("stderr_truncated")
                            .and_then(Value::as_bool)
                            .is_some()
                        && result.get("process_created").is_none()
                        && result.get("user_code_started").is_none()
                        && result.get("process_tree_remaining").is_none()
                        && result.get("job_terminated").is_none();
                    #[cfg(feature = "d32-a-test-helper")]
                    let evidence_ok = crate::d32a::take_internal_evidence()
                        .map(|evidence| {
                            evidence.get("process_created").and_then(Value::as_bool)
                                == Some(!self.negative_cargo_mode)
                                && evidence.get("user_code_started").and_then(Value::as_bool)
                                    == Some(!self.negative_cargo_mode)
                                && evidence
                                    .get("process_tree_remaining")
                                    .and_then(Value::as_u64)
                                    == Some(0)
                        })
                        .unwrap_or(false);
                    #[cfg(not(feature = "d32-a-test-helper"))]
                    let evidence_ok = true;
                    public_shape_ok && evidence_ok
                } else if self.read_mode {
                    let content = result.get("content").and_then(Value::as_str);
                    let relative_path = result.get("relative_path").and_then(Value::as_str);
                    let bytes_read = result.get("bytes_read").and_then(Value::as_u64);
                    let max_bytes = result.get("max_bytes").and_then(Value::as_u64);
                    let expected_hash = crate::sha256_hex(D31_B_CANARY_CONTENT.as_bytes());
                    if self.negative_read_mode {
                        result.get("status").and_then(Value::as_str) == Some("denied")
                            && relative_path == Some("canary.txt")
                            && content.is_none()
                            && bytes_read == Some(0)
                            && max_bytes.is_some_and(|max| max <= 64 * 1024)
                            && result.get("content_sha256").is_some_and(Value::is_null)
                            && result.get("execution_started").and_then(Value::as_bool)
                                == Some(false)
                            && result.get("grant_issued").and_then(Value::as_bool) == Some(true)
                            && result.get("side_effect_count").and_then(Value::as_u64) == Some(0)
                    } else {
                        result.get("status").and_then(Value::as_str) == Some("success")
                            && relative_path == Some("canary.txt")
                            && content == Some(D31_B_CANARY_CONTENT)
                            && bytes_read == Some(D31_B_CANARY_CONTENT.len() as u64)
                            && max_bytes.is_some_and(|max| max <= 64 * 1024)
                            && result.get("content_sha256").and_then(Value::as_str)
                                == Some(expected_hash.as_str())
                            && result.get("execution_started").and_then(Value::as_bool)
                                == Some(true)
                            && result.get("grant_issued").and_then(Value::as_bool) == Some(true)
                            && result.get("side_effect_count").and_then(Value::as_u64) == Some(0)
                    }
                } else {
                    let entries =
                        result
                            .get("entries")
                            .and_then(Value::as_array)
                            .ok_or_else(|| {
                                crate::VitaAgentError::GatewayProtocol(
                                    "H9 canary native tool output omitted entries".to_string(),
                                )
                            })?;
                    let canary_seen = entries.iter().any(|entry| {
                        entry.get("path").and_then(Value::as_str) == Some("canary.txt")
                    });
                    let absolute_path_seen = entries.iter().any(|entry| {
                        let Some(path) = entry.get("path").and_then(Value::as_str) else {
                            return true;
                        };
                        Path::new(path).is_absolute()
                            || path.starts_with('/')
                            || path.starts_with('\\')
                            || path.contains(":\\")
                            || path.contains(":/")
                    });
                    result.get("status").and_then(Value::as_str) == Some("completed")
                        && canary_seen
                        && !absolute_path_seen
                };
                if !valid || output.contains(&self.expected_workspace_path) {
                    return Err(crate::VitaAgentError::GatewayProtocol(
                        if self.cargo_mode {
                            "D32-A canary second request did not contain exact bounded Cargo result"
                        } else if self.patch_mode {
                            "D31-D canary second request did not contain exact bounded patch result"
                        } else if self.read_mode {
                            "D31-B canary second request did not contain exact bounded read result"
                        } else if self.replace_mode {
                            "D31-C canary second request did not contain exact governed replace result"
                        } else {
                            "H9 canary second request did not contain a bounded relative Git result"
                        }
                        .to_string(),
                    ));
                }
            }
            _ => {
                return Err(crate::VitaAgentError::GatewayProtocol(
                    "H9 canary provider received an unexpected third request".to_string(),
                ));
            }
        }
        let response = if request_number == 1 {
            serde_json::json!({
                "id": "h9-canary-tool-call",
                "model": self.response_model.clone(),
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": "h9-canary-call-1",
                            "type": "function",
                            "function": {
                                "name": if self.cargo_mode {
                                    D32_CARGO_TOOL_NAME
                                } else if self.patch_mode {
                                    VITA_WORKSPACE_PATCH_TOOL_NAME
                                } else if self.replace_mode {
                                    VITA_WORKSPACE_REPLACE_TOOL_NAME
                                } else if self.read_mode {
                                    VITA_WORKSPACE_READ_TOOL_NAME
                                } else {
                                    VITA_WORKSPACE_GIT_STATUS_TOOL_NAME
                                },
                                "arguments": if self.cargo_mode {
                                    "{}".to_string()
                                } else if self.patch_mode {
                                    let expected_sha256 = if self.patch_conflict_mode {
                                        crate::sha256_hex(b"D31-D wrong base\n")
                                    } else {
                                        crate::sha256_hex(D31_C_CANARY_CONTENT.as_bytes())
                                    };
                                    serde_json::to_string(&serde_json::json!({
                                        "relative_path": "canary.txt",
                                        "expected_sha256": expected_sha256,
                                        "edits": [{
                                            "search": D31_C_CANARY_CONTENT,
                                            "replace": D31_C_REPLACEMENT_CONTENT,
                                        }],
                                    })).expect("D31-D canary patch arguments")
                                } else if self.replace_mode {
                                    serde_json::to_string(&serde_json::json!({
                                        "relative_path": "canary.txt",
                                        "expected_sha256": crate::sha256_hex(D31_C_CANARY_CONTENT.as_bytes()),
                                        "replacement_content": D31_C_REPLACEMENT_CONTENT,
                                    })).expect("D31-C canary replacement arguments")
                                } else if self.read_mode {
                                    "{\"relative_path\":\"canary.txt\",\"max_bytes\":64}".to_string()
                                } else {
                                    "{\"operation\":\"status\"}".to_string()
                                }
                            }
                        }]
                    },
                    "finish_reason": "tool_calls"
                }]
            })
        } else if request_number == 2 {
            serde_json::json!({
                "id": "h9-canary-final",
                "model": self.response_model.clone(),
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
            unreachable!("request count was checked above");
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
        gateway_authority: Arc<GatewayAuthority>,
        transport: SidecarGatewayTransport,
    ) -> Result<Self, crate::VitaAgentError> {
        listener
            .set_nonblocking(true)
            .map_err(crate::VitaAgentError::GatewayTransport)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let provider_configuration_for_thread = provider_configuration;
        let transport_for_thread = transport;
        let gateway_authority_for_thread = Arc::clone(&gateway_authority);
        let join = std::thread::Builder::new()
            .name("vita-provider-gateway".to_string())
            .spawn(move || {
                while !stop_for_thread.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, peer)) => {
                            let _ = handle_gateway_connection(
                                stream,
                                peer,
                                &ready,
                                &provider_configuration_for_thread,
                                &router,
                                &session_id,
                                &active_identity,
                                &gateway_authority_for_thread,
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
    ready: &GatewayReadyProvider,
    provider_configuration: &ProviderConfiguration,
    router: &SidecarRouter,
    session_id: &str,
    active_identity: &Arc<Mutex<Option<ProviderRequestIdentity>>>,
    gateway_authority: &Arc<GatewayAuthority>,
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
    if let Err(code) = authorize_gateway_request(&request) {
        let status = if code == "GATEWAY_AUTH_DENIED" {
            "401 Unauthorized"
        } else {
            "404 Not Found"
        };
        return write_gateway_error(&mut stream, status, code);
    }
    let gateway = request
        .authorization
        .as_deref()
        .and_then(|token| gateway_authority.authorize(token));
    let Some(gateway) = gateway else {
        return write_gateway_error(&mut stream, "401 Unauthorized", "GATEWAY_AUTH_DENIED");
    };
    let identity = active_identity
        .lock()
        .map_err(|_| "active Vita turn state was poisoned".to_string())?
        .clone()
        .ok_or_else(|| "no active Vita turn".to_string());
    let identity = match identity {
        Ok(identity) => identity,
        Err(_) => return write_gateway_error(&mut stream, "409 Conflict", "TURN_NOT_ACTIVE"),
    };
    if identity != gateway.identity {
        return write_gateway_error(&mut stream, "409 Conflict", "TURN_NOT_ACTIVE");
    }
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
                gateway_authority: Arc::clone(gateway_authority),
                expected: identity.clone(),
                expected_gateway: gateway.clone(),
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
                gateway_authority: Arc::clone(gateway_authority),
                expected: identity.clone(),
                expected_gateway: gateway.clone(),
            };
            let gateway = ProviderGateway::new(ready.clone(), resolver, guarded);
            gateway.execute_responses_request_with_identity(&request, Some(&identity))
        }
    }
    .map_err(|_| "provider request failed".to_string())?;
    if !active_identity_matches(active_identity, &identity)
        || !gateway_authority.is_current(&gateway)
    {
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

fn authorize_gateway_request(request: &GatewayHttpRequest) -> Result<(), &'static str> {
    if request.method != "POST" || request.path != LOCAL_GATEWAY_PATH {
        return Err("GATEWAY_ROUTE_DENIED");
    }
    if request.authorization.is_none() {
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
                if name != TOOL_NAME
                    && name != VITA_WORKSPACE_READ_TOOL_NAME
                    && name != VITA_WORKSPACE_REPLACE_TOOL_NAME
                    && name != VITA_WORKSPACE_PATCH_TOOL_NAME
                    && name != D32_CARGO_TOOL_NAME
                {
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
    let mut advertised_tools = HashSet::new();
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
            if name != TOOL_NAME
                && name != VITA_WORKSPACE_READ_TOOL_NAME
                && name != VITA_WORKSPACE_REPLACE_TOOL_NAME
                && name != VITA_WORKSPACE_PATCH_TOOL_NAME
                && name != D32_CARGO_TOOL_NAME
            {
                return Err("unknown advertised tool".to_string());
            }
            if !advertised_tools.insert(name.to_string()) {
                return Err("duplicate advertised tool".to_string());
            }
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
    if !options.tools.is_empty()
        && tool_calls
            .iter()
            .any(|call| !options.tools.iter().any(|tool| tool.name == call.name))
    {
        return Err("function call was not advertised in this request".to_string());
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
        HostMessage::WorkspaceReadAuthorityReply(message) => &message.request_id,
        HostMessage::WorkspaceReadConfirmationReply(message) => &message.request_id,
        HostMessage::WorkspaceReadGrantIssued(message) => &message.request_id,
        HostMessage::WorkspaceReadGrantRevalidated(message) => &message.request_id,
        HostMessage::WorkspaceReadReleaseChecked(message) => &message.request_id,
        HostMessage::WorkspaceReplaceAuthorityReply(message) => &message.request_id,
        HostMessage::WorkspaceReplaceConfirmationReply(message) => &message.request_id,
        HostMessage::WorkspaceReplaceGrantIssued(message) => &message.request_id,
        HostMessage::WorkspaceReplaceGrantRevalidated(message) => &message.request_id,
        HostMessage::RecoveryAuthorityReply(message) => &message.request_id,
        HostMessage::RecoveryConfirmationReply(message) => &message.request_id,
        HostMessage::RecoveryGrantIssued(message) => &message.request_id,
        HostMessage::RecoveryGrantRevalidated(message) => &message.request_id,
        HostMessage::ExecuteRecovery(message) => &message.request_id,
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
        VitaMessage::WorkspaceReadAuthorityEvaluate(message) => &message.request_id,
        VitaMessage::WorkspaceReadConfirmationRequired(message) => &message.request_id,
        VitaMessage::WorkspaceReadIssueGrant(message) => &message.request_id,
        VitaMessage::WorkspaceReadRevalidateGrant(message) => &message.request_id,
        VitaMessage::WorkspaceReadReleaseCheck(message) => &message.request_id,
        VitaMessage::WorkspaceReplaceAuthorityEvaluate(message) => &message.request_id,
        VitaMessage::WorkspaceReplaceConfirmationRequired(message) => &message.request_id,
        VitaMessage::WorkspaceReplaceIssueGrant(message) => &message.request_id,
        VitaMessage::WorkspaceReplaceRevalidateGrant(message) => &message.request_id,
        VitaMessage::RecoveryAuthorityEvaluate(message) => &message.request_id,
        VitaMessage::RecoveryConfirmationRequired(message) => &message.request_id,
        VitaMessage::RecoveryIssueGrant(message) => &message.request_id,
        VitaMessage::RecoveryRevalidateGrant(message) => &message.request_id,
        VitaMessage::RecoveryPending(message) => &message.request_id,
        VitaMessage::RecoveryResult(message) => &message.request_id,
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
    let require_real_canary =
        std::env::var("D32_A_REQUIRE_REAL_CANARY").ok().as_deref() == Some("1");
    if require_real_canary && !test_canary {
        return Err(
            "D32-A mandatory real canary requires the test-canary Host/Vita/Codex harness"
                .to_string(),
        );
    }
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
    if require_real_canary && init.provider.is_none() {
        return Err("D32-A mandatory real canary requires a pinned provider fixture".to_string());
    }

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
    let recovery_store = RecoveryJournalStore::from_runtime_profile(&profile)
        .map_err(|error| format!("Vita recovery journal store setup failed: {error}"))?;
    let context = VitaExecutionContext::try_new(init.life_id.clone(), init.task_id.clone())
        .map_err(|error| format!("Vita execution identity was invalid: {error:?}"))?;
    let active_identity = Arc::new(Mutex::new(None::<ProviderRequestIdentity>));
    let gateway_authority = Arc::new(GatewayAuthority::new());
    let turn_owner = Arc::new(TurnOwner::default());
    let authority = Arc::new(SidecarHostAuthority {
        router: router.clone(),
        session_id: init.session_id.clone(),
        active_identity: Arc::clone(&active_identity),
    });
    let read_authority = Arc::new(SidecarWorkspaceReadAuthority::new(
        router.clone(),
        &init,
        workspace_identity.clone(),
        Arc::clone(&active_identity),
    ));
    let read_broker = Arc::new(VitaWorkspaceReadBroker::new(
        context.clone(),
        workspace.clone(),
        Arc::clone(&read_authority) as Arc<dyn VitaH3AuthorityPort>,
    ));
    let replace_authority = Arc::new(SidecarWorkspaceReplaceAuthority::new(
        router.clone(),
        &init,
        workspace_identity.clone(),
        Arc::clone(&active_identity),
    ));
    let replace_broker = Arc::new(VitaWorkspaceReplaceBroker::new(
        context.clone(),
        workspace.clone(),
        Arc::clone(&replace_authority) as Arc<dyn VitaH4AuthorityPort>,
    ));
    let recovery_authority = Arc::new(SidecarRecoveryAuthority::new(
        router.clone(),
        &init,
        workspace_identity.clone(),
    ));
    let recovery_executor = Arc::new(H5RecoveryExecutor::new(
        recovery_store.clone(),
        workspace.clone(),
        Arc::clone(&recovery_authority) as Arc<dyn RecoveryAuthorityPort>,
    ));
    // Restart inspection is deliberately read-only.  Recovery actions are
    // only initiated by an explicit Host/user flow and are never automatic.
    let recovery_scan = recovery_executor
        .scan()
        .map_err(|error| format!("Vita recovery scan failed: {error}"))?;
    let recovery_pending = recovery_scan
        .actionable_recovery_transactions()
        .filter_map(|snapshot| {
            let journal = snapshot.journal();
            let target = workspace
                .prepare_target(journal.relative_path().as_path())
                .ok()?;
            if target.kind() != PreparedWorkspaceTargetKind::ExistingFile {
                return None;
            }
            let current = target
                .read_existing_file_raw_bounded(RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES)
                .ok()?;
            Some(protocol::RecoveryPending {
                request_id: next_request_id("vita-recovery-pending"),
                session_id: init.session_id.clone(),
                transaction_id: journal.transaction_id().as_str().to_string(),
                life_id: journal.life_id().to_string(),
                task_id: journal.task_id().to_string(),
                capability_id: H5_RECOVER_REPLACE_CAPABILITY_ID.to_string(),
                workspace_root_identity: journal.workspace_root_identity().wire(),
                relative_path: journal
                    .relative_path()
                    .as_path()
                    .to_string_lossy()
                    .into_owned(),
                target_identity: journal.target_identity().wire(),
                journal_integrity_hash: journal.integrity_hash(),
                current_sha256: crate::sha256_hex(&current),
                current_bytes: current.len() as u64,
                restore_sha256: journal.before_sha256(),
                restore_bytes: journal.before_bytes() as u64,
                original_replacement_sha256: journal.replacement_sha256(),
            })
        })
        .collect::<Vec<_>>();
    // The recovery action path reuses the same retained workspace capability
    // as H5, but is independently driven by a Host command and never by a
    // Codex turn.
    let recovery_root = workspace.clone();
    let patch_context = context.clone();
    let cargo_context = context.clone();
    let cargo_workspace = workspace.clone();
    let cargo_selection = resolve_cargo_selection(Path::new(&init.app_data_root)).ok();
    let cargo_path = cargo_selection
        .as_ref()
        .map(|selection| selection.cargo_path.clone());
    let cargo_toolchain_root = cargo_selection
        .as_ref()
        .map(|selection| selection.toolchain_root.clone());
    let cargo_toolchain_manifest_hash = cargo_selection
        .as_ref()
        .map(|selection| selection.toolchain_manifest_sha256.clone());
    let production = Arc::new(
        VitaGitStatusProduction::new(
            context,
            workspace,
            PathBuf::from(&init.git_path),
            Arc::clone(&authority) as Arc<dyn VitaGitStatusAuthority>,
        )
        .map_err(|error| format!("Vita H7-C production setup failed: {error}"))?,
    );
    let cargo_production = Arc::new(VitaCargoCheckProduction::new(
        cargo_context,
        cargo_workspace,
        PathBuf::from(&init.app_data_root),
        cargo_path.unwrap_or_else(|| PathBuf::from(r"C:\__digital_life_missing_cargo__.exe")),
        cargo_toolchain_root,
        cargo_toolchain_manifest_hash,
        Arc::clone(&authority) as Arc<dyn VitaGitStatusAuthority>,
        init.session_id.clone(),
    ));
    if require_real_canary && !cargo_production.is_available() {
        return Err(format!(
            "D32-A mandatory real canary prerequisites unavailable: {}",
            cargo_production
                .unavailable_reason()
                .unwrap_or("unknown blocker")
        ));
    }
    let contributor = VitaProductionContributors {
        git: production.contributor(),
        read: VitaWorkspaceReadToolContributor::new(Arc::clone(&read_broker)),
        replace: VitaWorkspaceReplaceH5ToolContributor::new(
            Arc::clone(&replace_broker),
            recovery_store.clone(),
        ),
        patch: VitaWorkspacePatchToolContributor::new(
            Arc::clone(&replace_broker),
            recovery_root.clone(),
            patch_context,
            recovery_store.clone(),
        ),
        cargo: cargo_production.contributor(),
    };
    let (entrypoint, mut gateway_server) = if let Some(provider_config) = init.provider.as_ref() {
        provider_config.validate().map_err(protocol_error)?;
        #[cfg(not(feature = "d29-h9-test-helper"))]
        if test_canary {
            return Err("H9 canary mode is not enabled in this sidecar image".to_string());
        }
        let provider = if test_canary {
            #[cfg(feature = "d29-h9-test-helper")]
            {
                let credential = crate::CredentialRef::new(
                    provider_config.credential_ref.clone(),
                    provider_config.profile_id.clone(),
                    &provider_config.base_url,
                )
                .map_err(|error| format!("H9 canary credential binding failed: {error}"))?;
                crate::ProviderProfile::new_for_test_localhost(
                    provider_config.profile_id.clone(),
                    "D29-H9 deterministic local Chat provider",
                    crate::ProviderProtocol::OpenAiChatCompletions,
                    &provider_config.base_url,
                    provider_config.model.clone(),
                    Some(credential),
                    // The real Cargo canary performs Host-side exact mirror
                    // revalidation before confirmation/grant consumption;
                    // keep the deterministic fixture bounded but long enough
                    // for that cold-machine evidence pass.
                    Duration::from_secs(180),
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
            Arc::clone(&gateway_authority),
            if test_canary {
                #[cfg(feature = "d29-h9-test-helper")]
                {
                    let negative_read_mode = provider_config.model == "d31-b-negative-canary-model";
                    let negative_replace_mode =
                        provider_config.model == "d31-c-negative-canary-model";
                    let negative_patch_mode =
                        provider_config.model == "d31-d-negative-canary-model";
                    let patch_conflict_mode =
                        provider_config.model == "d31-d-conflict-canary-model";
                    let negative_cargo_mode = provider_config.model.starts_with("d32-a-negative-");
                    let cargo_mode =
                        provider_config.model == "d32-a-canary-model" || negative_cargo_mode;
                    SidecarGatewayTransport::H9Canary(Arc::new(H9CanaryTransport::new(
                        &init.workspace_path,
                        provider_config.model == "d31-b-canary-model" || negative_read_mode,
                        negative_read_mode,
                        provider_config.model == "d31-c-canary-model" || negative_replace_mode,
                        negative_replace_mode,
                        provider_config.model == "d31-d-canary-model"
                            || negative_patch_mode
                            || patch_conflict_mode,
                        negative_patch_mode,
                        patch_conflict_mode,
                        cargo_mode,
                        negative_cargo_mode,
                        provider_config.model.clone(),
                    )))
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
    let cargo_receiver = cargo_production
        .take_confirmation_receiver()
        .ok_or_else(|| "D32 Cargo confirmation receiver was already consumed".to_string())?;
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
    for pending in recovery_pending {
        router.send(&VitaMessage::RecoveryPending(pending))?;
    }
    spawn_confirmation_loop(
        router.clone(),
        init.clone(),
        receiver,
        Arc::clone(&active_identity),
        VITA_WORKSPACE_GIT_STATUS_CAPABILITY_ID,
    );
    spawn_confirmation_loop(
        router.clone(),
        init.clone(),
        cargo_receiver,
        Arc::clone(&active_identity),
        D32_CARGO_CAPABILITY_ID,
    );

    // Keep command reception alive while an H5 recovery is running.  A
    // recovery is Host-owned rather than a model turn, but it is still a
    // bounded long-running operation and must observe CancelAction/Shutdown
    // without waiting for the filesystem executor to return first.
    let mut command_reader = tokio::task::spawn_blocking({
        let router = router.clone();
        move || router.receive_command()
    });
    let mut recovery_task: Option<tokio::task::JoinHandle<Result<(), String>>> = None;

    loop {
        let event = if let Some(task) = recovery_task.as_mut() {
            tokio::select! {
                result = task => SidecarLoopEvent::Recovery(result),
                result = &mut command_reader => SidecarLoopEvent::Command(result),
            }
        } else {
            SidecarLoopEvent::Command((&mut command_reader).await)
        };

        let result = match event {
            SidecarLoopEvent::Recovery(result) => {
                recovery_task = None;
                result.map_err(|_| "Vita sidecar recovery task failed".to_string())??;
                continue;
            }
            SidecarLoopEvent::Command(result) => result,
        };
        let command =
            result.map_err(|_| "Vita sidecar command reader task failed".to_string())??;
        let Some(command) = command else {
            production.cancel();
            cargo_production.cancel();
            read_broker.cancel();
            replace_broker.cancel();
            recovery_executor.cancel();
            if let Some(task) = recovery_task.take() {
                let _ = task.await;
            }
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
                cargo_production.cancel_turn();
                read_broker.cancel_turn();
                replace_broker.cancel_turn();
                recovery_executor.cancel();
                router.send(&VitaMessage::ActionCancelled(protocol::ActionCancelled {
                    request_id: message.request_id,
                    session_id: init.session_id.clone(),
                }))?;
            }
            HostMessage::ExecuteRecovery(message) if message.session_id == init.session_id => {
                if recovery_task.is_some() {
                    return Err("Vita sidecar recovery action is already running".to_string());
                }
                recovery_executor.begin_turn();
                let task_init = init.clone();
                let task_root = recovery_root.clone();
                let task_executor = Arc::clone(&recovery_executor);
                let task_router = router.clone();
                recovery_task = Some(tokio::spawn(async move {
                    handle_execute_recovery(
                        message,
                        &task_init,
                        task_root,
                        task_executor,
                        task_router,
                    )
                    .await
                }));
            }
            HostMessage::StartTurn(message) if message.session_id == init.session_id => {
                handle_start_turn(
                    message,
                    &init,
                    init.provider.as_ref(),
                    Arc::clone(&runtime),
                    Arc::clone(&production),
                    Arc::clone(&cargo_production),
                    Arc::clone(&read_broker),
                    Arc::clone(&read_authority),
                    Arc::clone(&replace_broker),
                    Arc::clone(&replace_authority),
                    router.clone(),
                    Arc::clone(&active_identity),
                    Arc::clone(&gateway_authority),
                    Arc::clone(&turn_owner),
                );
            }
            HostMessage::CancelTurn(message) if message.session_id == init.session_id => {
                handle_cancel_turn(
                    message,
                    &init,
                    Arc::clone(&runtime),
                    Arc::clone(&production),
                    Arc::clone(&cargo_production),
                    Arc::clone(&read_broker),
                    Arc::clone(&replace_broker),
                    router.clone(),
                    Arc::clone(&active_identity),
                    Arc::clone(&gateway_authority),
                    Arc::clone(&turn_owner),
                )
                .await?;
            }
            HostMessage::Shutdown(message) if message.session_id == init.session_id => {
                production.cancel();
                cargo_production.cancel();
                read_broker.cancel();
                replace_broker.cancel();
                recovery_executor.cancel();
                if let Some(task) = recovery_task.take() {
                    let _ = task.await;
                }
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
                read_broker.cancel();
                replace_broker.cancel();
                recovery_executor.cancel();
                if let Some(task) = recovery_task.take() {
                    let _ = task.await;
                }
                runtime.shutdown().await;
                let _ = router.send(&VitaMessage::Fatal(protocol::FatalMessage {
                    request_id: next_request_id("vita-fatal"),
                    session_id: Some(init.session_id.clone()),
                    error_code: "SIDECAR_UNEXPECTED_HOST_MESSAGE".to_string(),
                }));
                return Err("Vita sidecar received an unexpected Host message".to_string());
            }
        }

        command_reader = tokio::task::spawn_blocking({
            let router = router.clone();
            move || router.receive_command()
        });
    }
}

fn recovery_result_for(
    command: &ExecuteRecovery,
    result: crate::d29h5::RecoveryExecutionResult,
) -> RecoveryResult {
    let (outcome, error_code) = match result.outcome {
        RecoveryExecutionOutcome::RecoveryDenied(reason) => {
            let code = match reason {
                RecoveryDenyReason::ConfirmationMissing => "RECOVERY_CONFIRMATION_MISSING",
                RecoveryDenyReason::ConfirmationMismatch => "RECOVERY_CONFIRMATION_MISMATCH",
                RecoveryDenyReason::ConfirmationExpired => "RECOVERY_CONFIRMATION_EXPIRED",
                RecoveryDenyReason::AuthorizationDisabled => "CAPABILITY_ROOT_DISABLED",
                RecoveryDenyReason::StaleRevision => "CAPABILITY_AUTHORIZATION_REVISION_MISMATCH",
                RecoveryDenyReason::RecoveryGrantReplay => "RECOVERY_GRANT_REPLAY",
                RecoveryDenyReason::RecoveryStateInvalid => "RECOVERY_STATE_INVALID",
                RecoveryDenyReason::RecoveryBlocked => "RECOVERY_BLOCKED",
                RecoveryDenyReason::TargetMissing => "RECOVERY_TARGET_MISSING",
                RecoveryDenyReason::TargetIdentityChanged => "RECOVERY_TARGET_IDENTITY_CHANGED",
                RecoveryDenyReason::TargetBusy => "RECOVERY_TARGET_BUSY",
                RecoveryDenyReason::HardLinkAmbiguous => "RECOVERY_HARDLINK_AMBIGUOUS",
                RecoveryDenyReason::Cancellation => "RECOVERY_CANCELLED",
                RecoveryDenyReason::NativeFailure => "RECOVERY_NATIVE_FAILURE",
            };
            (RecoveryOutcome::Denied, Some(code.to_string()))
        }
        RecoveryExecutionOutcome::RecoveryConflict => (
            RecoveryOutcome::Conflict,
            Some("RECOVERY_CONFLICT".to_string()),
        ),
        RecoveryExecutionOutcome::RecoveredNoOp => (RecoveryOutcome::RecoveredNoOp, None),
        RecoveryExecutionOutcome::Recovered => (RecoveryOutcome::Recovered, None),
        RecoveryExecutionOutcome::RecoveryUnknown => (
            RecoveryOutcome::Unknown,
            Some("RECOVERY_OUTCOME_UNKNOWN".to_string()),
        ),
    };
    RecoveryResult {
        request_id: command.request_id.clone(),
        session_id: command.session_id.clone(),
        recovery_action_id: command.recovery_action_id.clone(),
        recovery_generation: command.recovery_generation.clone(),
        transaction_id: command.transaction_id.clone(),
        outcome,
        mutation_count: result.mutation_count as u64,
        marker_persisted: result.marker_persisted,
        error_code,
    }
}

fn denied_recovery_result(command: &ExecuteRecovery, error_code: &str) -> RecoveryResult {
    RecoveryResult {
        request_id: command.request_id.clone(),
        session_id: command.session_id.clone(),
        recovery_action_id: command.recovery_action_id.clone(),
        recovery_generation: command.recovery_generation.clone(),
        transaction_id: command.transaction_id.clone(),
        outcome: RecoveryOutcome::Denied,
        mutation_count: 0,
        marker_persisted: false,
        error_code: Some(error_code.to_string()),
    }
}

fn build_recovery_action(
    command: &ExecuteRecovery,
    init: &InitializeSession,
    root: &TrustedWorkspaceRoot,
    executor: &H5RecoveryExecutor,
) -> Result<RecoveryActionRequest, String> {
    let scan = executor
        .scan()
        .map_err(|_| "RECOVERY_SCAN_FAILED".to_string())?;
    let snapshot = scan
        .actionable_recovery_transactions()
        .find(|snapshot| snapshot.journal().transaction_id().as_str() == command.transaction_id)
        .ok_or_else(|| "RECOVERY_TRANSACTION_NOT_ACTIONABLE".to_string())?;
    let journal = snapshot.journal();
    if journal.life_id() != init.life_id || journal.task_id() != init.task_id {
        return Err("RECOVERY_BINDING_MISMATCH".to_string());
    }
    if journal.workspace_root_identity()
        != crate::recovery_journal::RecoveryJournalIdentity::from_workspace_identity(
            root.identity(),
        )
        .map_err(|_| "RECOVERY_BINDING_MISMATCH".to_string())?
    {
        return Err("RECOVERY_BINDING_MISMATCH".to_string());
    }
    root.verify_named_path_current()
        .map_err(|_| "RECOVERY_TARGET_IDENTITY_CHANGED".to_string())?;
    let target = root
        .prepare_target(journal.relative_path().as_path())
        .map_err(|_| "RECOVERY_TARGET_MISSING".to_string())?;
    if target.kind() != PreparedWorkspaceTargetKind::ExistingFile
        || target.target_identity().is_none()
    {
        return Err("RECOVERY_TARGET_IDENTITY_CHANGED".to_string());
    }
    let current = target
        .read_existing_file_raw_bounded(RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES)
        .map_err(|_| "RECOVERY_TARGET_MISSING".to_string())?;
    Ok(
        RecoveryActionRequest::from_snapshot(snapshot, &current, &command.recovery_action_id, 0)
            .with_recovery_generation(&command.recovery_generation),
    )
}

async fn handle_execute_recovery(
    command: ExecuteRecovery,
    init: &InitializeSession,
    root: TrustedWorkspaceRoot,
    executor: Arc<H5RecoveryExecutor>,
    router: SidecarRouter,
) -> Result<(), String> {
    command
        .validate()
        .map_err(|_| "RECOVERY_EXECUTE_REQUEST_INVALID".to_string())?;
    let action = match build_recovery_action(&command, init, &root, &executor) {
        Ok(action) => action,
        Err(error) => {
            let result = denied_recovery_result(&command, &error);
            result.validate().map_err(protocol_error)?;
            router.send(&VitaMessage::RecoveryResult(result))?;
            return Ok(());
        }
    };
    let result = tokio::task::spawn_blocking(move || executor.recover(action))
        .await
        .map_err(|_| "RECOVERY_EXECUTOR_TASK_FAILED".to_string())?;
    let message = recovery_result_for(&command, result);
    message.validate().map_err(protocol_error)?;
    router.send(&VitaMessage::RecoveryResult(message))
}

fn handle_start_turn(
    message: StartTurn,
    init: &InitializeSession,
    provider_config: Option<&ProviderConfiguration>,
    runtime: Arc<VitaAgentRuntime>,
    production: Arc<VitaGitStatusProduction>,
    cargo_production: Arc<VitaCargoCheckProduction>,
    read_broker: Arc<VitaWorkspaceReadBroker>,
    read_authority: Arc<SidecarWorkspaceReadAuthority>,
    replace_broker: Arc<VitaWorkspaceReplaceBroker>,
    replace_authority: Arc<SidecarWorkspaceReplaceAuthority>,
    router: SidecarRouter,
    active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
    gateway_authority: Arc<GatewayAuthority>,
    turn_owner: Arc<TurnOwner>,
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
    turn_owner.reap_finished();
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
    let gateway = match gateway_authority.activate(identity.clone()) {
        Ok(gateway) => gateway,
        Err(_) => {
            if let Ok(mut active) = active_identity.lock() {
                active.take();
            }
            failed("TURN_GATEWAY_BUSY");
            return;
        }
    };
    production.begin_turn();
    cargo_production.begin_turn();
    read_authority.begin_turn();
    read_broker.begin_turn();
    replace_authority.begin_turn();
    replace_broker.begin_turn();
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
    let cancelled = Arc::new(AtomicBool::new(false));
    let cancel_notify = Arc::new(tokio::sync::Notify::new());
    let gateway_for_task = gateway.clone();
    let gateway_for_install_error = gateway.clone();
    let gateway_token = gateway.token.clone();
    let active_identity_for_task = Arc::clone(&active_identity);
    let active_identity_for_error = Arc::clone(&active_identity);
    let gateway_authority_for_task = Arc::clone(&gateway_authority);
    let identity_for_task = identity.clone();
    let turn_id_for_task = turn_id.clone();
    let cancelled_for_task = Arc::clone(&cancelled);
    let cancel_notify_for_task = Arc::clone(&cancel_notify);
    let router_for_task = router.clone();
    let join = tokio::spawn(async move {
        let result = runtime
            .run_turn(
                prompt,
                gateway_token.as_str(),
                cancelled_for_task,
                cancel_notify_for_task,
            )
            .await;
        let still_current = active_identity_for_task
            .lock()
            .ok()
            .is_some_and(|active| active.as_ref() == Some(&identity_for_task))
            && gateway_authority_for_task.is_current(&gateway_for_task);
        if !still_current {
            return result;
        }
        if let Ok(mut active) = active_identity_for_task.lock() {
            active.take();
        }
        gateway_authority_for_task.deactivate(&gateway_for_task.identity);
        match &result {
            Ok(assistant_text) => {
                let text = if assistant_text.is_empty() {
                    "(Vita completed without assistant text)".to_string()
                } else {
                    bounded_protocol_text(assistant_text, MAX_TURN_OUTPUT_BYTES)
                };
                let _ = router_for_task.send(&VitaMessage::TurnCompleted(TurnCompleted {
                    request_id: next_request_id("vita-turn-completed"),
                    session_id: session_id.clone(),
                    turn_id: turn_id_for_task.clone(),
                    model: model.clone(),
                    assistant_text: text,
                }));
            }
            Err(error) => {
                let error_text = error.to_string();
                let cancelled = error_text.to_ascii_lowercase().contains("cancel");
                let _ = router_for_task.send(&VitaMessage::TurnFailed(TurnFailed {
                    request_id: next_request_id("vita-turn-failed"),
                    session_id,
                    turn_id: turn_id_for_task.clone(),
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
        result
    });
    if let Err(error) = turn_owner.install(ActiveTurnTask {
        identity: identity.clone(),
        gateway,
        cancelled,
        cancel_notify,
        join,
    }) {
        gateway_authority.deactivate_generation(&gateway_for_install_error);
        if let Ok(mut active) = active_identity_for_error.lock() {
            active.take();
        }
        let _ = router.send(&VitaMessage::TurnFailed(TurnFailed {
            request_id,
            session_id: init.session_id.clone(),
            turn_id,
            phase: TurnPhase::Failed,
            error_code: "TURN_OWNER_UNAVAILABLE".to_string(),
            message: bounded_protocol_text(&error, 256),
        }));
    }
}

async fn handle_cancel_turn(
    message: protocol::CancelTurn,
    init: &InitializeSession,
    runtime: Arc<VitaAgentRuntime>,
    production: Arc<VitaGitStatusProduction>,
    cargo_production: Arc<VitaCargoCheckProduction>,
    read_broker: Arc<VitaWorkspaceReadBroker>,
    replace_broker: Arc<VitaWorkspaceReplaceBroker>,
    router: SidecarRouter,
    active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
    gateway_authority: Arc<GatewayAuthority>,
    turn_owner: Arc<TurnOwner>,
) -> Result<(), String> {
    if message.validate().is_err() {
        return Ok(());
    }
    let identity = active_identity.lock().ok().and_then(|active| {
        active
            .as_ref()
            .filter(|identity| identity.turn_id == message.turn_id)
            .cloned()
    });
    let Some(identity) = identity else {
        return Ok(());
    };
    if let Ok(mut active) = active_identity.lock() {
        active.take();
    }
    production.cancel_turn();
    cargo_production.cancel_turn();
    read_broker.cancel_turn();
    replace_broker.cancel_turn();
    let Some(task) = turn_owner.take(&identity) else {
        gateway_authority.deactivate(&identity);
        return Err("Vita turn owner disappeared before cancellation proof".to_string());
    };
    gateway_authority.deactivate_generation(&task.gateway);
    task.cancelled.store(true, Ordering::Release);
    task.cancel_notify.notify_waiters();
    let session_id = init.session_id.clone();
    let turn_id = message.turn_id;
    // The acknowledgement is emitted only after the bounded Codex interrupt
    // and the actual run_turn future have both terminated.  Clearing the
    // identity and gateway authority above fences late requests immediately;
    // this join proves the old lifecycle cannot later mutate a new turn.
    let _ = runtime.interrupt_active_turn().await;
    let joined = tokio::time::timeout(Duration::from_secs(5), task.join)
        .await
        .map_err(|_| "Vita turn cancellation did not reach terminality".to_string())?
        .map_err(|_| "Vita turn cancellation task failed".to_string())?;
    let _ = joined;
    router.send(&VitaMessage::TurnState(TurnState {
        request_id: next_request_id("vita-turn-cancelled"),
        session_id,
        turn_id,
        phase: TurnPhase::Cancelled,
    }))?;
    Ok(())
}

fn spawn_confirmation_loop(
    router: SidecarRouter,
    init: InitializeSession,
    mut receiver: tokio::sync::mpsc::Receiver<VitaGitStatusPendingConfirmation>,
    active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
    capability_id: &'static str,
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
                    capability_id: capability_id.to_string(),
                    workspace_summary: workspace_summary(&init.workspace_path),
                    expires_at_unix_ms: unix_millis().saturating_add(
                        if capability_id == D32_CARGO_CAPABILITY_ID {
                            120_000
                        } else {
                            30_000
                        },
                    ),
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

/// The process-isolated adapter for the production D31-B read lane.  The
/// adapter is deliberately the only object that knows the D31 workspace-read
/// wire messages; the H2/H3 broker receives only typed Host evidence and the
/// retained workspace handle.
#[derive(Clone)]
struct SidecarWorkspaceReadAuthority {
    router: SidecarRouter,
    session_id: String,
    life_id: String,
    task_id: String,
    workspace_identity: String,
    workspace_summary: String,
    active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
    grants: Arc<Mutex<HashMap<String, protocol::WorkspaceReadGrant>>>,
}

impl SidecarWorkspaceReadAuthority {
    fn new(
        router: SidecarRouter,
        init: &InitializeSession,
        workspace_identity: String,
        active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
    ) -> Self {
        Self {
            router,
            session_id: init.session_id.clone(),
            life_id: init.life_id.clone(),
            task_id: init.task_id.clone(),
            workspace_identity,
            workspace_summary: workspace_summary(&init.workspace_path),
            active_identity,
            grants: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn begin_turn(&self) {
        if let Ok(mut grants) = self.grants.lock() {
            grants.clear();
        }
    }

    fn binding_for(
        &self,
        request: &H3AuthorityRequest,
    ) -> Result<(protocol::WorkspaceReadBinding, String), VitaH3AuthorityError> {
        if request.context.life_id() != self.life_id
            || request.context.task_id() != self.task_id
            || request.capability_id != VITA_WORKSPACE_READ_CAPABILITY_ID
            || request.target_kind != crate::PreparedWorkspaceTargetKind::ExistingFile
            || request.max_bytes == 0
            || request.max_bytes > protocol::MAX_WORKSPACE_READ_BYTES as usize
        {
            return Err(VitaH3AuthorityError::InvalidVerdict);
        }
        let active = active_identity_snapshot(&self.active_identity)
            .ok_or(VitaH3AuthorityError::Unavailable)?;
        let relative_path = request
            .relative_path
            .as_path()
            .to_str()
            .ok_or(VitaH3AuthorityError::InvalidVerdict)?
            .to_string();
        // The wire contract uses canonical forward-slash components.  A
        // backslash is rejected rather than normalized so the model cannot
        // obtain a second spelling for the same target.
        if relative_path.contains('\\') {
            return Err(VitaH3AuthorityError::InvalidVerdict);
        }
        let target_identity = request.target_identity.wire();
        let binding = protocol::WorkspaceReadBinding {
            session_id: self.session_id.clone(),
            life_id: self.life_id.clone(),
            task_id: self.task_id.clone(),
            capability_id: VITA_WORKSPACE_READ_CAPABILITY_ID.to_string(),
            tool_name: VITA_WORKSPACE_READ_TOOL_NAME.to_string(),
            workspace_root_identity: self.workspace_identity.clone(),
            relative_path,
            target_identity,
            target_kind: protocol::WorkspaceReadTargetKind::File,
            max_bytes: request.max_bytes as u64,
            tool_call_id: request.tool_call_id.clone(),
            codex_turn_id: request.turn_id.clone(),
            provider_binding_hash: active.binding_hash,
        };
        binding
            .validate()
            .map_err(|_| VitaH3AuthorityError::InvalidVerdict)?;
        Ok((binding, active.turn_id))
    }

    fn authority_reply(
        &self,
        request: &H3AuthorityRequest,
        binding: &protocol::WorkspaceReadBinding,
        host_turn_id: &str,
    ) -> Result<(i64, protocol::WorkspaceReadGrant), VitaH3AuthorityError> {
        let authority = self
            .router
            .request(VitaMessage::WorkspaceReadAuthorityEvaluate(
                protocol::WorkspaceReadAuthorityEvaluate {
                    request_id: next_request_id("vita-read-authority"),
                    session_id: self.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    binding: binding.clone(),
                },
            ))
            .map_err(|_| VitaH3AuthorityError::Unavailable)?;
        let protocol::WorkspaceReadAuthorityReply {
            session_id,
            allowed,
            authorization_revision,
            error_code,
            ..
        } = match authority {
            HostMessage::WorkspaceReadAuthorityReply(reply) => reply,
            _ => return Err(VitaH3AuthorityError::InvalidVerdict),
        };
        if session_id != self.session_id || !allowed {
            let _ = error_code;
            return Err(VitaH3AuthorityError::Unavailable);
        }
        let revision = authorization_revision.ok_or(VitaH3AuthorityError::InvalidVerdict)?;

        let confirmation = self
            .router
            .request(VitaMessage::WorkspaceReadConfirmationRequired(
                protocol::WorkspaceReadConfirmationRequired {
                    request_id: next_request_id("vita-read-confirm"),
                    session_id: self.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    workspace_summary: self.workspace_summary.clone(),
                    expires_at_unix_ms: unix_millis().saturating_add(30_000),
                    binding: binding.clone(),
                },
            ))
            .map_err(|_| VitaH3AuthorityError::Unavailable)?;
        let protocol::WorkspaceReadConfirmationReply {
            session_id,
            decision,
            authorization_revision,
            ..
        } = match confirmation {
            HostMessage::WorkspaceReadConfirmationReply(reply) => reply,
            _ => return Err(VitaH3AuthorityError::InvalidVerdict),
        };
        if session_id != self.session_id
            || decision != ConfirmationDecision::Confirm
            || authorization_revision != Some(revision)
        {
            return Err(VitaH3AuthorityError::Unavailable);
        }

        let issued = self
            .router
            .request(VitaMessage::WorkspaceReadIssueGrant(
                protocol::WorkspaceReadIssueGrant {
                    request_id: next_request_id("vita-read-issue"),
                    session_id: self.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    binding: binding.clone(),
                    authorization_revision: revision,
                },
            ))
            .map_err(|_| VitaH3AuthorityError::Unavailable)?;
        let protocol::WorkspaceReadGrantIssued {
            session_id,
            allowed,
            grant,
            error_code,
            ..
        } = match issued {
            HostMessage::WorkspaceReadGrantIssued(reply) => reply,
            _ => return Err(VitaH3AuthorityError::InvalidVerdict),
        };
        if session_id != self.session_id || !allowed {
            let _ = error_code;
            return Err(VitaH3AuthorityError::Unavailable);
        }
        let grant = grant.ok_or(VitaH3AuthorityError::InvalidVerdict)?;
        grant
            .validate()
            .map_err(|_| VitaH3AuthorityError::InvalidVerdict)?;
        if grant.session_id != self.session_id
            || grant.binding != *binding
            || grant.authorization_revision != revision
            || grant.used
            || !grant.single_use
        {
            return Err(VitaH3AuthorityError::InvalidVerdict);
        }
        self.grants
            .lock()
            .map_err(|_| VitaH3AuthorityError::Unavailable)?
            .insert(grant.grant_id.clone(), grant.clone());
        let _ = request;
        Ok((revision, grant))
    }

    fn revalidate(
        &self,
        request: &H3AuthorityRequest,
        binding: &protocol::WorkspaceReadBinding,
        host_turn_id: &str,
        grant_id: &str,
        revision: i64,
    ) -> Result<protocol::WorkspaceReadGrant, VitaH3AuthorityError> {
        let grant = self
            .grants
            .lock()
            .map_err(|_| VitaH3AuthorityError::Unavailable)?
            .get(grant_id)
            .cloned()
            .ok_or(VitaH3AuthorityError::Unavailable)?;
        if grant.binding != *binding
            || grant.authorization_revision != revision
            || grant.used
            || request.capability_id != VITA_WORKSPACE_READ_CAPABILITY_ID
        {
            return Err(VitaH3AuthorityError::InvalidVerdict);
        }
        let response = self
            .router
            .request(VitaMessage::WorkspaceReadRevalidateGrant(
                protocol::WorkspaceReadRevalidateGrant {
                    request_id: next_request_id("vita-read-revalidate"),
                    session_id: self.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    binding: binding.clone(),
                    grant: grant.clone(),
                },
            ));
        if response.is_err() {
            if let Ok(mut grants) = self.grants.lock() {
                grants.remove(grant_id);
            }
            return Err(VitaH3AuthorityError::Unavailable);
        }
        let response = response.expect("checked workspace read revalidation response");
        let protocol::WorkspaceReadGrantRevalidated {
            session_id,
            allowed,
            grant: returned,
            error_code,
            ..
        } = match response {
            HostMessage::WorkspaceReadGrantRevalidated(reply) => reply,
            _ => return Err(VitaH3AuthorityError::InvalidVerdict),
        };
        if session_id != self.session_id || !allowed {
            let _ = error_code;
            if let Ok(mut grants) = self.grants.lock() {
                grants.remove(grant_id);
            }
            return Err(VitaH3AuthorityError::Unavailable);
        }
        let returned = returned.ok_or(VitaH3AuthorityError::InvalidVerdict)?;
        returned
            .validate()
            .map_err(|_| VitaH3AuthorityError::InvalidVerdict)?;
        if returned.binding != *binding
            || returned.grant_id != grant_id
            || returned.authorization_revision != revision
            || !returned.used
        {
            return Err(VitaH3AuthorityError::InvalidVerdict);
        }
        self.grants
            .lock()
            .map_err(|_| VitaH3AuthorityError::Unavailable)?
            .insert(returned.grant_id.clone(), returned.clone());
        Ok(returned)
    }

    fn evidence(
        &self,
        request: &H3AuthorityRequest,
        binding: &protocol::WorkspaceReadBinding,
        grant: &protocol::WorkspaceReadGrant,
    ) -> H3HostScopedGrantEvidence {
        H3HostScopedGrantEvidence {
            grant_id: grant.grant_id.clone(),
            life_id: request.context.life_id().to_string(),
            task_id: request.context.task_id().to_string(),
            capability_id: VITA_WORKSPACE_READ_CAPABILITY_ID.to_string(),
            authorization_revision: grant.authorization_revision,
            scope: crate::VitaRequestedScope::Workspace,
            workspace_root_identity: request.workspace_root_identity,
            relative_path: request.relative_path.clone(),
            target_identity: request.target_identity,
            target_kind: request.target_kind,
            max_bytes: request.max_bytes,
            tool_call_id: binding.tool_call_id.clone(),
            turn_id: binding.codex_turn_id.clone(),
            issued_at_unix_ms: grant.issued_at_unix_ms,
            expires_at_unix_ms: grant.expires_at_unix_ms,
        }
    }

    fn canonical(&self, request: &H3AuthorityRequest, revision: i64) -> H3CanonicalDecision {
        H3CanonicalDecision {
            life_id: request.context.life_id().to_string(),
            capability_id: VITA_WORKSPACE_READ_CAPABILITY_ID.to_string(),
            outcome: H3CanonicalOutcome::ScopeRequired,
            decision_code: H3CanonicalDecisionCode::ScopeNotAvailable,
            scope_requirement: H3ScopeRequirement::WorkspaceRequired,
            // H3's scope-completion contract represents the canonical root
            // floor separately from the per-action confirmation that the
            // D31 adapter has just completed.
            approval_floor: H3ApprovalFloor::RootEnabled,
            authorization_revision: Some(revision),
        }
    }
}

impl VitaH3AuthorityPort for SidecarWorkspaceReadAuthority {
    fn evaluate(&self, request: H3AuthorityRequest) -> VitaH3AuthorityFuture {
        let authority = self.clone();
        Box::pin(async move {
            let (binding, host_turn_id) = authority.binding_for(&request)?;
            match request.operation.clone() {
                H3AuthorityOperation::IssueScopeGrant => {
                    let (revision, grant) =
                        authority.authority_reply(&request, &binding, &host_turn_id)?;
                    Ok(H3HostAuthorityResponse {
                        canonical: authority.canonical(&request, revision),
                        scope_grant: Some(authority.evidence(&request, &binding, &grant)),
                    })
                }
                H3AuthorityOperation::Revalidate {
                    grant_id,
                    authorization_revision,
                } => {
                    let grant = authority.revalidate(
                        &request,
                        &binding,
                        &host_turn_id,
                        &grant_id,
                        authorization_revision,
                    )?;
                    Ok(H3HostAuthorityResponse {
                        canonical: authority.canonical(&request, authorization_revision),
                        scope_grant: Some(authority.evidence(&request, &binding, &grant)),
                    })
                }
            }
        })
    }

    fn release(&self, request: H3DisclosureRequest) -> VitaH3DisclosureFuture {
        let authority = self.clone();
        Box::pin(async move {
            if request.context.life_id() != authority.life_id
                || request.context.task_id() != authority.task_id
                || request.capability_id != VITA_WORKSPACE_READ_CAPABILITY_ID
                || request.target_kind != crate::PreparedWorkspaceTargetKind::ExistingFile
                || request.max_bytes == 0
                || request.max_bytes > protocol::MAX_WORKSPACE_READ_BYTES as usize
            {
                return Err(VitaH3AuthorityError::InvalidVerdict);
            }
            let active = active_identity_snapshot(&authority.active_identity)
                .ok_or(VitaH3AuthorityError::Unavailable)?;
            let relative_path = request
                .relative_path
                .as_path()
                .to_str()
                .ok_or(VitaH3AuthorityError::InvalidVerdict)?
                .to_string();
            if relative_path.contains('\\') {
                return Err(VitaH3AuthorityError::InvalidVerdict);
            }
            let binding = protocol::WorkspaceReadBinding {
                session_id: authority.session_id.clone(),
                life_id: authority.life_id.clone(),
                task_id: authority.task_id.clone(),
                capability_id: VITA_WORKSPACE_READ_CAPABILITY_ID.to_string(),
                tool_name: VITA_WORKSPACE_READ_TOOL_NAME.to_string(),
                workspace_root_identity: authority.workspace_identity.clone(),
                relative_path,
                target_identity: request.target_identity.wire(),
                target_kind: protocol::WorkspaceReadTargetKind::File,
                max_bytes: request.max_bytes as u64,
                tool_call_id: request.tool_call_id.clone(),
                codex_turn_id: request.turn_id.clone(),
                provider_binding_hash: active.binding_hash,
            };
            binding
                .validate()
                .map_err(|_| VitaH3AuthorityError::InvalidVerdict)?;
            let grant = authority
                .grants
                .lock()
                .map_err(|_| VitaH3AuthorityError::Unavailable)?
                .get(&request.grant_id)
                .cloned()
                .ok_or(VitaH3AuthorityError::Unavailable)?;
            if grant.binding != binding
                || grant.authorization_revision != request.authorization_revision
                || !grant.used
            {
                return Err(VitaH3AuthorityError::InvalidVerdict);
            }
            let response = authority
                .router
                .request(VitaMessage::WorkspaceReadReleaseCheck(
                    protocol::WorkspaceReadReleaseCheck {
                        request_id: next_request_id("vita-read-release"),
                        session_id: authority.session_id.clone(),
                        host_turn_id: active.turn_id,
                        binding,
                        grant,
                        bytes_read: request.bytes_read as u64,
                        content_sha256: request.content_sha256.clone(),
                    },
                ));
            // A transport timeout or malformed Host response is terminal for
            // this local grant as well; retaining it would make a later
            // release retry a replay surface after the Host has already
            // linearized cancellation/revocation.
            if let Ok(mut grants) = authority.grants.lock() {
                grants.remove(&request.grant_id);
            }
            let response = response.map_err(|_| VitaH3AuthorityError::Unavailable)?;
            let protocol::WorkspaceReadReleaseChecked {
                session_id,
                allowed,
                error_code,
                ..
            } = match response {
                HostMessage::WorkspaceReadReleaseChecked(reply) => reply,
                _ => return Err(VitaH3AuthorityError::InvalidVerdict),
            };
            if session_id != authority.session_id || !allowed {
                let _ = error_code;
                return Err(VitaH3AuthorityError::Unavailable);
            }
            Ok(())
        })
    }
}

/// Process-isolated adapter for the production H4/H5 replacement lane.  All
/// authority facts in the returned H4 response are reconstructed from the
/// immutable request plus the Host-issued wire grant; the sidecar never
/// mints confirmation or grant identifiers.
#[derive(Clone)]
struct SidecarWorkspaceReplaceAuthority {
    router: SidecarRouter,
    session_id: String,
    life_id: String,
    task_id: String,
    workspace_identity: String,
    workspace_summary: String,
    active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
    grants: Arc<Mutex<HashMap<String, protocol::WorkspaceReplaceGrant>>>,
}

impl SidecarWorkspaceReplaceAuthority {
    fn new(
        router: SidecarRouter,
        init: &InitializeSession,
        workspace_identity: String,
        active_identity: Arc<Mutex<Option<ProviderRequestIdentity>>>,
    ) -> Self {
        Self {
            router,
            session_id: init.session_id.clone(),
            life_id: init.life_id.clone(),
            task_id: init.task_id.clone(),
            workspace_identity,
            workspace_summary: workspace_summary(&init.workspace_path),
            active_identity,
            grants: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn begin_turn(&self) {
        if let Ok(mut grants) = self.grants.lock() {
            grants.clear();
        }
    }

    fn binding_for(
        &self,
        request: &H4AuthorityRequest,
    ) -> Result<(protocol::WorkspaceReplaceBinding, String), VitaH4AuthorityError> {
        if request.context.life_id() != self.life_id
            || request.context.task_id() != self.task_id
            || request.capability_id != VITA_WORKSPACE_REPLACE_CAPABILITY_ID
            || request.target_kind != crate::PreparedWorkspaceTargetKind::ExistingFile
            || request.replacement_bytes > protocol::MAX_WORKSPACE_READ_BYTES as usize
        {
            return Err(VitaH4AuthorityError::InvalidVerdict);
        }
        let active = active_identity_snapshot(&self.active_identity)
            .ok_or(VitaH4AuthorityError::Unavailable)?;
        // The Host turn generation and Codex's independently-issued turn id
        // are intentionally distinct.  The Host binds the first Codex id to
        // this active generation during authority evaluation; subsequent
        // confirmation/grant messages must carry that same id.
        let relative_path = request
            .relative_path
            .as_path()
            .to_str()
            .ok_or(VitaH4AuthorityError::InvalidVerdict)?
            .to_string();
        if relative_path.contains('\\') {
            return Err(VitaH4AuthorityError::InvalidVerdict);
        }
        let binding = protocol::WorkspaceReplaceBinding {
            session_id: self.session_id.clone(),
            life_id: self.life_id.clone(),
            task_id: self.task_id.clone(),
            capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
            tool_name: VITA_WORKSPACE_REPLACE_TOOL_NAME.to_string(),
            workspace_root_identity: self.workspace_identity.clone(),
            relative_path,
            target_identity: request.target_identity.wire(),
            target_kind: protocol::WorkspaceReplaceTargetKind::File,
            expected_sha256: request.expected_sha256.clone(),
            replacement_sha256: request.replacement_sha256.clone(),
            replacement_bytes: request.replacement_bytes as u64,
            tool_call_id: request.tool_call_id.clone(),
            codex_turn_id: request.turn_id.clone(),
            provider_binding_hash: active.binding_hash,
        };
        binding
            .validate()
            .map_err(|_| VitaH4AuthorityError::InvalidVerdict)?;
        Ok((binding, active.turn_id))
    }

    fn canonical(&self, request: &H4AuthorityRequest, revision: i64) -> H4CanonicalDecision {
        H4CanonicalDecision {
            life_id: request.context.life_id().to_string(),
            capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
            outcome: H4CanonicalOutcome::ScopeRequired,
            decision_code: H4CanonicalDecisionCode::ScopeNotAvailable,
            scope_requirement: H4ScopeRequirement::WorkspaceRequired,
            approval_floor: H4ApprovalFloor::ExplicitPerAction,
            authorization_revision: Some(revision),
            workspace_scope_matches: true,
        }
    }

    fn evidence(
        &self,
        request: &H4AuthorityRequest,
        binding: &protocol::WorkspaceReplaceBinding,
        grant: &protocol::WorkspaceReplaceGrant,
    ) -> H4HostReplaceGrantEvidence {
        H4HostReplaceGrantEvidence {
            grant_id: grant.grant_id.clone(),
            life_id: request.context.life_id().to_string(),
            task_id: request.context.task_id().to_string(),
            capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
            authorization_revision: grant.authorization_revision,
            scope: crate::VitaRequestedScope::Workspace,
            workspace_root_identity: request.workspace_root_identity,
            relative_path: request.relative_path.clone(),
            target_identity: request.target_identity,
            target_kind: request.target_kind,
            operation: H4ReplaceOperation::ReplaceExistingUtf8File,
            expected_sha256: request.expected_sha256.clone(),
            replacement_sha256: request.replacement_sha256.clone(),
            replacement_bytes: request.replacement_bytes,
            tool_call_id: binding.tool_call_id.clone(),
            turn_id: binding.codex_turn_id.clone(),
            confirmation_id: grant.confirmation_id.clone(),
            issued_at_unix_ms: grant.issued_at_unix_ms,
            expires_at_unix_ms: grant.expires_at_unix_ms,
            single_use: grant.single_use,
        }
    }

    fn confirmation(
        &self,
        request: &H4AuthorityRequest,
        binding: &protocol::WorkspaceReplaceBinding,
        grant: &protocol::WorkspaceReplaceGrant,
    ) -> HostExplicitActionConfirmationEvidence {
        HostExplicitActionConfirmationEvidence {
            source: H4ConfirmationEvidenceSource::TrustedHost,
            confirmation_id: grant.confirmation_id.clone(),
            life_id: request.context.life_id().to_string(),
            task_id: request.context.task_id().to_string(),
            capability_id: VITA_WORKSPACE_REPLACE_CAPABILITY_ID.to_string(),
            authorization_revision: grant.authorization_revision,
            workspace_root_identity: request.workspace_root_identity,
            relative_path: request.relative_path.clone(),
            target_identity: request.target_identity,
            expected_sha256: request.expected_sha256.clone(),
            replacement_sha256: request.replacement_sha256.clone(),
            replacement_bytes: request.replacement_bytes,
            tool_call_id: binding.tool_call_id.clone(),
            turn_id: binding.codex_turn_id.clone(),
            issued_at_unix_ms: grant.issued_at_unix_ms,
            expires_at_unix_ms: grant.expires_at_unix_ms,
        }
    }

    fn issue(
        &self,
        request: &H4AuthorityRequest,
        binding: &protocol::WorkspaceReplaceBinding,
        host_turn_id: &str,
    ) -> Result<H4HostAuthorityResponse, VitaH4AuthorityError> {
        let authority = self
            .router
            .request(VitaMessage::WorkspaceReplaceAuthorityEvaluate(
                protocol::WorkspaceReplaceAuthorityEvaluate {
                    request_id: next_request_id("vita-replace-authority"),
                    session_id: self.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    binding: binding.clone(),
                },
            ))
            .map_err(|_| VitaH4AuthorityError::Unavailable)?;
        let reply = match authority {
            HostMessage::WorkspaceReplaceAuthorityReply(reply) => reply,
            _ => return Err(VitaH4AuthorityError::InvalidVerdict),
        };
        reply
            .validate()
            .map_err(|_| VitaH4AuthorityError::InvalidVerdict)?;
        if reply.session_id != self.session_id || !reply.allowed {
            return Err(VitaH4AuthorityError::Unavailable);
        }
        let revision = reply
            .authorization_revision
            .ok_or(VitaH4AuthorityError::InvalidVerdict)?;
        let confirmation = self
            .router
            .request(VitaMessage::WorkspaceReplaceConfirmationRequired(
                protocol::WorkspaceReplaceConfirmationRequired {
                    request_id: next_request_id("vita-replace-confirm"),
                    session_id: self.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    workspace_summary: self.workspace_summary.clone(),
                    expires_at_unix_ms: unix_millis().saturating_add(30_000),
                    binding: binding.clone(),
                },
            ))
            .map_err(|_| VitaH4AuthorityError::Unavailable)?;
        let confirmation = match confirmation {
            HostMessage::WorkspaceReplaceConfirmationReply(reply) => reply,
            _ => return Err(VitaH4AuthorityError::InvalidVerdict),
        };
        confirmation
            .validate()
            .map_err(|_| VitaH4AuthorityError::InvalidVerdict)?;
        if confirmation.session_id != self.session_id
            || confirmation.decision != protocol::ConfirmationDecision::Confirm
            || confirmation.authorization_revision != Some(revision)
        {
            return Err(VitaH4AuthorityError::Unavailable);
        }
        let issued = self
            .router
            .request(VitaMessage::WorkspaceReplaceIssueGrant(
                protocol::WorkspaceReplaceIssueGrant {
                    request_id: next_request_id("vita-replace-issue"),
                    session_id: self.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    binding: binding.clone(),
                    authorization_revision: revision,
                },
            ))
            .map_err(|_| VitaH4AuthorityError::Unavailable)?;
        let issued = match issued {
            HostMessage::WorkspaceReplaceGrantIssued(reply) => reply,
            _ => return Err(VitaH4AuthorityError::InvalidVerdict),
        };
        issued
            .validate()
            .map_err(|_| VitaH4AuthorityError::InvalidVerdict)?;
        if issued.session_id != self.session_id || !issued.allowed {
            return Err(VitaH4AuthorityError::Unavailable);
        }
        let grant = issued.grant.ok_or(VitaH4AuthorityError::InvalidVerdict)?;
        if grant.binding != *binding
            || grant.authorization_revision != revision
            || grant.used
            || !grant.single_use
        {
            return Err(VitaH4AuthorityError::InvalidVerdict);
        }
        self.grants
            .lock()
            .map_err(|_| VitaH4AuthorityError::Unavailable)?
            .insert(grant.grant_id.clone(), grant.clone());
        Ok(H4HostAuthorityResponse {
            status: crate::H4AuthorityResponseStatus::Ok,
            canonical: self.canonical(request, revision),
            confirmation: Some(self.confirmation(request, binding, &grant)),
            grant: Some(self.evidence(request, binding, &grant)),
            denial: None,
            confirmation_consumed: true,
        })
    }

    fn revalidate(
        &self,
        request: &H4AuthorityRequest,
        binding: &protocol::WorkspaceReplaceBinding,
        host_turn_id: &str,
        grant_id: &str,
        revision: i64,
    ) -> Result<H4HostAuthorityResponse, VitaH4AuthorityError> {
        let grant = self
            .grants
            .lock()
            .map_err(|_| VitaH4AuthorityError::Unavailable)?
            .get(grant_id)
            .cloned()
            .ok_or(VitaH4AuthorityError::Unavailable)?;
        if grant.binding != *binding || grant.authorization_revision != revision || grant.used {
            return Err(VitaH4AuthorityError::InvalidVerdict);
        }
        let response = self
            .router
            .request(VitaMessage::WorkspaceReplaceRevalidateGrant(
                protocol::WorkspaceReplaceRevalidateGrant {
                    request_id: next_request_id("vita-replace-revalidate"),
                    session_id: self.session_id.clone(),
                    host_turn_id: host_turn_id.to_string(),
                    binding: binding.clone(),
                    grant: grant.clone(),
                },
            ))
            .map_err(|_| VitaH4AuthorityError::Unavailable)?;
        let response = match response {
            HostMessage::WorkspaceReplaceGrantRevalidated(reply) => reply,
            _ => return Err(VitaH4AuthorityError::InvalidVerdict),
        };
        response
            .validate()
            .map_err(|_| VitaH4AuthorityError::InvalidVerdict)?;
        if response.session_id != self.session_id || !response.allowed {
            return Err(VitaH4AuthorityError::Unavailable);
        }
        let returned = response.grant.ok_or(VitaH4AuthorityError::InvalidVerdict)?;
        if returned.binding != *binding
            || returned.grant_id != grant_id
            || returned.authorization_revision != revision
            || !returned.used
        {
            return Err(VitaH4AuthorityError::InvalidVerdict);
        }
        if let Ok(mut grants) = self.grants.lock() {
            grants.remove(grant_id);
        }
        Ok(H4HostAuthorityResponse {
            status: crate::H4AuthorityResponseStatus::Ok,
            canonical: self.canonical(request, revision),
            confirmation: None,
            grant: Some(self.evidence(request, binding, &returned)),
            denial: None,
            confirmation_consumed: false,
        })
    }
}

impl VitaH4AuthorityPort for SidecarWorkspaceReplaceAuthority {
    fn evaluate(&self, request: H4AuthorityRequest) -> VitaH4AuthorityFuture {
        let authority = self.clone();
        Box::pin(async move {
            let (binding, host_turn_id) = match authority.binding_for(&request) {
                Ok(value) => value,
                Err(error) => {
                    #[cfg(feature = "d29-h9-test-helper")]
                    eprintln!("D31-C canary replace binding error: {error:?}");
                    return Err(error);
                }
            };
            match request.operation.clone() {
                H4AuthorityOperation::IssueReplaceGrant => {
                    authority.issue(&request, &binding, &host_turn_id)
                }
                H4AuthorityOperation::Revalidate {
                    grant_id,
                    authorization_revision,
                } => authority.revalidate(
                    &request,
                    &binding,
                    &host_turn_id,
                    &grant_id,
                    authorization_revision,
                ),
            }
        })
    }
}

/// Host-only recovery authority adapter.  It is intentionally not a
/// `ToolContributor`; only the recovery coordinator may call this trait.
#[derive(Clone)]
pub(crate) struct SidecarRecoveryAuthority {
    router: SidecarRouter,
    session_id: String,
    life_id: String,
    task_id: String,
    workspace_identity: String,
    workspace_summary: String,
    grants: Arc<Mutex<HashMap<String, protocol::RecoveryGrant>>>,
}

impl SidecarRecoveryAuthority {
    fn new(router: SidecarRouter, init: &InitializeSession, workspace_identity: String) -> Self {
        Self {
            router,
            session_id: init.session_id.clone(),
            life_id: init.life_id.clone(),
            task_id: init.task_id.clone(),
            workspace_identity,
            workspace_summary: workspace_summary(&init.workspace_path),
            grants: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn binding_for(
        &self,
        request: &RecoveryActionRequest,
    ) -> Result<protocol::RecoveryBinding, RecoveryDenyReason> {
        if request.life_id != self.life_id
            || request.task_id != self.task_id
            || request.capability_id != H5_RECOVER_REPLACE_CAPABILITY_ID
        {
            return Err(RecoveryDenyReason::ConfirmationMismatch);
        }
        if request.action_id.is_empty() {
            return Err(RecoveryDenyReason::RecoveryStateInvalid);
        }
        let binding = protocol::RecoveryBinding {
            session_id: self.session_id.clone(),
            life_id: self.life_id.clone(),
            task_id: self.task_id.clone(),
            capability_id: H5_RECOVER_REPLACE_CAPABILITY_ID.to_string(),
            workspace_root_identity: self.workspace_identity.clone(),
            relative_path: request
                .relative_path
                .as_path()
                .to_str()
                .ok_or(RecoveryDenyReason::ConfirmationMismatch)?
                .to_string(),
            target_identity: request.target_identity.wire(),
            transaction_id: request.transaction_id.as_str().to_string(),
            journal_integrity_hash: request.journal_integrity_hash.clone(),
            current_sha256: request.current_sha256.clone(),
            current_bytes: request.current_bytes as u64,
            restore_sha256: request.restore_sha256.clone(),
            restore_bytes: request.restore_bytes as u64,
            original_replacement_sha256: request.original_replacement_sha256.clone(),
            recovery_action_id: request.action_id.clone(),
            recovery_generation: request.recovery_generation.clone(),
        };
        binding
            .validate()
            .map_err(|_| RecoveryDenyReason::ConfirmationMismatch)?;
        Ok(binding)
    }

    fn issue(
        &self,
        request: &RecoveryActionRequest,
    ) -> Result<RecoveryGrantEvidence, RecoveryDenyReason> {
        let binding = self.binding_for(request)?;
        let authority = self
            .router
            .request(VitaMessage::RecoveryAuthorityEvaluate(
                protocol::RecoveryAuthorityEvaluate {
                    request_id: next_request_id("vita-recovery-authority"),
                    session_id: self.session_id.clone(),
                    recovery_action_id: request.action_id.clone(),
                    binding: binding.clone(),
                },
            ))
            .map_err(|_| RecoveryDenyReason::AuthorizationDisabled)?;
        let reply = match authority {
            HostMessage::RecoveryAuthorityReply(reply) => reply,
            _ => return Err(RecoveryDenyReason::RecoveryStateInvalid),
        };
        reply
            .validate()
            .map_err(|_| RecoveryDenyReason::RecoveryStateInvalid)?;
        if reply.session_id != self.session_id || !reply.allowed {
            return Err(RecoveryDenyReason::AuthorizationDisabled);
        }
        let revision = reply
            .authorization_revision
            .ok_or(RecoveryDenyReason::StaleRevision)?;
        let confirmation = self
            .router
            .request(VitaMessage::RecoveryConfirmationRequired(
                protocol::RecoveryConfirmationRequired {
                    request_id: next_request_id("vita-recovery-confirm"),
                    session_id: self.session_id.clone(),
                    recovery_action_id: request.action_id.clone(),
                    workspace_summary: self.workspace_summary.clone(),
                    expires_at_unix_ms: unix_millis().saturating_add(30_000),
                    binding: binding.clone(),
                },
            ))
            .map_err(|_| RecoveryDenyReason::AuthorizationDisabled)?;
        let confirmation = match confirmation {
            HostMessage::RecoveryConfirmationReply(reply) => reply,
            _ => return Err(RecoveryDenyReason::RecoveryStateInvalid),
        };
        confirmation
            .validate()
            .map_err(|_| RecoveryDenyReason::RecoveryStateInvalid)?;
        if confirmation.session_id != self.session_id
            || confirmation.decision != protocol::ConfirmationDecision::Confirm
            || confirmation.authorization_revision != Some(revision)
        {
            return Err(RecoveryDenyReason::ConfirmationMismatch);
        }
        let issued = self
            .router
            .request(VitaMessage::RecoveryIssueGrant(RecoveryIssueGrant {
                request_id: next_request_id("vita-recovery-issue"),
                session_id: self.session_id.clone(),
                recovery_action_id: request.action_id.clone(),
                binding: binding.clone(),
                authorization_revision: revision,
            }))
            .map_err(|_| RecoveryDenyReason::AuthorizationDisabled)?;
        let issued = match issued {
            HostMessage::RecoveryGrantIssued(reply) => reply,
            _ => return Err(RecoveryDenyReason::RecoveryStateInvalid),
        };
        issued
            .validate()
            .map_err(|_| RecoveryDenyReason::RecoveryStateInvalid)?;
        if issued.session_id != self.session_id || !issued.allowed {
            return Err(RecoveryDenyReason::AuthorizationDisabled);
        }
        let grant = issued
            .grant
            .ok_or(RecoveryDenyReason::RecoveryStateInvalid)?;
        if grant.binding != binding
            || grant.authorization_revision != revision
            || grant.used
            || !grant.single_use
        {
            return Err(RecoveryDenyReason::RecoveryStateInvalid);
        }
        let mut authorized_action = request.clone();
        authorized_action.authorization_revision = revision;
        self.grants
            .lock()
            .map_err(|_| RecoveryDenyReason::AuthorizationDisabled)?
            .insert(grant.grant_id.clone(), grant.clone());
        Ok(RecoveryGrantEvidence {
            grant_id: grant.grant_id,
            confirmation_id: grant.confirmation_id,
            action: authorized_action,
            issued_at_unix_ms: grant.issued_at_unix_ms,
            expires_at_unix_ms: grant.expires_at_unix_ms,
            single_use: grant.single_use,
            used: grant.used,
        })
    }
}

impl RecoveryAuthorityPort for SidecarRecoveryAuthority {
    fn issue_recovery_grant(
        &self,
        request: &RecoveryActionRequest,
    ) -> Result<RecoveryGrantEvidence, RecoveryDenyReason> {
        self.issue(request)
    }

    fn revalidate_recovery_grant(
        &self,
        grant: &RecoveryGrantEvidence,
        request: &RecoveryActionRequest,
    ) -> Result<(), RecoveryDenyReason> {
        let binding = self.binding_for(request)?;
        let wire_grant = self
            .grants
            .lock()
            .map_err(|_| RecoveryDenyReason::AuthorizationDisabled)?
            .get(&grant.grant_id)
            .cloned()
            .ok_or(RecoveryDenyReason::RecoveryGrantReplay)?;
        if wire_grant.binding != binding || wire_grant.used || grant.used {
            return Err(RecoveryDenyReason::RecoveryGrantReplay);
        }
        let response = self
            .router
            .request(VitaMessage::RecoveryRevalidateGrant(
                protocol::RecoveryRevalidateGrant {
                    request_id: next_request_id("vita-recovery-revalidate"),
                    session_id: self.session_id.clone(),
                    recovery_action_id: request.action_id.clone(),
                    binding,
                    grant: wire_grant,
                },
            ))
            .map_err(|_| RecoveryDenyReason::AuthorizationDisabled)?;
        let response = match response {
            HostMessage::RecoveryGrantRevalidated(reply) => reply,
            _ => return Err(RecoveryDenyReason::RecoveryStateInvalid),
        };
        response
            .validate()
            .map_err(|_| RecoveryDenyReason::RecoveryStateInvalid)?;
        if response.session_id != self.session_id || !response.allowed {
            return Err(RecoveryDenyReason::AuthorizationDisabled);
        }
        let returned = response
            .grant
            .ok_or(RecoveryDenyReason::RecoveryStateInvalid)?;
        if returned.grant_id != grant.grant_id || !returned.used {
            return Err(RecoveryDenyReason::RecoveryGrantReplay);
        }
        if let Ok(mut grants) = self.grants.lock() {
            grants.remove(&grant.grant_id);
        }
        Ok(())
    }
}

/// The production Codex extension registry is closed over these five exact
/// contributors.  Keeping the composition in one concrete contributor means
/// the pinned runtime never receives a generic plugin or filesystem surface.
struct VitaProductionContributors {
    git: VitaGitStatusToolContributor,
    read: VitaWorkspaceReadToolContributor,
    replace: VitaWorkspaceReplaceH5ToolContributor,
    patch: VitaWorkspacePatchToolContributor,
    cargo: VitaCargoCheckToolContributor,
}

impl ToolContributor for VitaProductionContributors {
    fn tools(
        &self,
        session_store: &codex_extension_api::ExtensionData,
        thread_store: &codex_extension_api::ExtensionData,
    ) -> Vec<
        Arc<dyn for<'call> codex_extension_api::ToolExecutor<codex_extension_api::ToolCall<'call>>>,
    > {
        let mut tools = self.git.tools(session_store, thread_store);
        tools.extend(self.read.tools(session_store, thread_store));
        tools.extend(self.replace.tools(session_store, thread_store));
        tools.extend(self.patch.tools(session_store, thread_store));
        tools.extend(self.cargo.tools(session_store, thread_store));
        tools
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
            .unwrap_or_else(|| {
                if binding.capability_id() == D32_CARGO_CAPABILITY_ID {
                    D32_CARGO_NO_GIT_METADATA_FENCE
                } else {
                    ""
                }
            })
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
    let is_git = grant.binding.capability_id == VITA_WORKSPACE_GIT_STATUS_CAPABILITY_ID
        && grant.binding.profile_id == VITA_WORKSPACE_GIT_STATUS_PROFILE_ID;
    let is_cargo = grant.binding.capability_id == D32_CARGO_CAPABILITY_ID
        && grant.binding.profile_id == D32_CARGO_PROFILE_ID
        && grant.binding.program_id == "cargo-check-v1";
    if grant.session_id != session_id
        || grant.binding != *expected_binding
        || (!is_git && !is_cargo)
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

const D32_CARGO_SELECTION_FILE_NAME: &str = ".d32-cargo-selection-v1.json";
const D32_CARGO_SELECTION_MAX_BYTES: usize = 16 * 1024;
const D32_CARGO_IMAGE_MAX_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SidecarCargoSelection {
    path: String,
    sha256: String,
    toolchain_path: String,
    toolchain_manifest_sha256: String,
}

struct ResolvedCargoSelection {
    cargo_path: PathBuf,
    toolchain_root: PathBuf,
    toolchain_manifest_sha256: String,
}

fn hash_cargo_image(path: &Path) -> Result<String, String> {
    let mut file = std::fs::File::open(path)
        .map_err(|_| "Host-selected Cargo image could not be opened".to_string())?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "Host-selected Cargo image could not be read".to_string())?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > D32_CARGO_IMAGE_MAX_BYTES {
            return Err("Host-selected Cargo image exceeded its bound".to_string());
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn resolve_cargo_selection(app_data_root: &Path) -> Result<ResolvedCargoSelection, String> {
    // The Host publishes this marker before starting Vita.  There is no PATH,
    // USERPROFILE, or model/provider fallback here: Vita can only consume the
    // exact image path and digest selected by the Host.
    if !app_data_root.is_absolute() {
        return Err("Host Cargo authority root was not absolute".to_string());
    }
    let root = std::fs::canonicalize(app_data_root)
        .map_err(|_| "Host Cargo authority root could not be canonicalized".to_string())?;
    let marker = root.join(D32_CARGO_SELECTION_FILE_NAME);
    let marker_metadata = std::fs::symlink_metadata(&marker)
        .map_err(|_| "Host Cargo authority marker was unavailable".to_string())?;
    if marker_metadata.file_type().is_symlink() || !marker_metadata.is_file() {
        return Err("Host Cargo authority marker was not a regular file".to_string());
    }
    let marker_canonical = std::fs::canonicalize(&marker)
        .map_err(|_| "Host Cargo authority marker could not be canonicalized".to_string())?;
    if marker_canonical != marker {
        return Err("Host Cargo authority marker escaped app data".to_string());
    }
    let mut bytes = Vec::new();
    std::fs::File::open(&marker)
        .map_err(|_| "Host Cargo authority marker could not be opened".to_string())?
        .take((D32_CARGO_SELECTION_MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "Host Cargo authority marker could not be read".to_string())?;
    if bytes.len() > D32_CARGO_SELECTION_MAX_BYTES {
        return Err("Host Cargo authority marker exceeded its bound".to_string());
    }
    let selection: SidecarCargoSelection = serde_json::from_slice(&bytes)
        .map_err(|_| "Host Cargo authority marker was malformed".to_string())?;
    if selection.sha256.len() != 64
        || selection
            .sha256
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit())
    {
        return Err("Host Cargo authority digest was malformed".to_string());
    }
    let selected = PathBuf::from(selection.path);
    if !selected.is_absolute() {
        return Err("Host Cargo authority image path was not absolute".to_string());
    }
    let canonical = std::fs::canonicalize(&selected)
        .map_err(|_| "Host Cargo authority image could not be canonicalized".to_string())?;
    if !canonical.is_file() {
        return Err("Host Cargo authority image was not a regular file".to_string());
    }
    let actual = hash_cargo_image(&canonical)?;
    if actual != selection.sha256 {
        return Err("Host Cargo authority image digest changed".to_string());
    }
    let toolchain = PathBuf::from(selection.toolchain_path);
    if !toolchain.is_absolute() {
        return Err("Host Cargo authority toolchain path was not absolute".to_string());
    }
    let toolchain = std::fs::canonicalize(&toolchain)
        .map_err(|_| "Host Cargo authority toolchain could not be canonicalized".to_string())?;
    let expected_cargo = std::fs::canonicalize(toolchain.join("bin/cargo.exe"))
        .map_err(|_| "Host Cargo authority toolchain Cargo image was unavailable".to_string())?;
    if !toolchain.is_dir()
        || expected_cargo != canonical
        || !toolchain.join("bin/rustc.exe").is_file()
        || !toolchain.join("bin/rustdoc.exe").is_file()
    {
        return Err("Host Cargo authority toolchain was incomplete".to_string());
    }
    if selection.toolchain_manifest_sha256.len() != 64
        || selection
            .toolchain_manifest_sha256
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit())
    {
        return Err("Host Cargo authority toolchain digest was malformed".to_string());
    }
    Ok(ResolvedCargoSelection {
        cargo_path: canonical,
        toolchain_root: toolchain,
        toolchain_manifest_sha256: selection.toolchain_manifest_sha256,
    })
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
    fn local_gateway_requires_bearer_header_and_exact_route() {
        let request = |method: &str, path: &str, authorization: Option<&str>| GatewayHttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            authorization: authorization.map(str::to_string),
            body: Vec::new(),
        };
        assert_eq!(
            authorize_gateway_request(&request("POST", LOCAL_GATEWAY_PATH, None)),
            Err("GATEWAY_AUTH_DENIED")
        );
        assert_eq!(
            authorize_gateway_request(&request("POST", LOCAL_GATEWAY_PATH, Some("old"))),
            Ok(())
        );
        assert_eq!(
            authorize_gateway_request(&request("GET", LOCAL_GATEWAY_PATH, Some("current"))),
            Err("GATEWAY_ROUTE_DENIED")
        );
        assert_eq!(
            authorize_gateway_request(&request("POST", "/v1/other", Some("current"))),
            Err("GATEWAY_ROUTE_DENIED")
        );
        assert!(
            authorize_gateway_request(&request("POST", LOCAL_GATEWAY_PATH, Some("current")))
                .is_ok()
        );
    }

    #[test]
    fn gateway_generation_rejects_old_turn_token_after_new_turn_activation() {
        let authority = GatewayAuthority::new();
        let identity_a = ProviderRequestIdentity {
            turn_id: "turn-a".to_string(),
            binding_hash: "binding-a".to_string(),
        };
        let generation_a = authority
            .activate(identity_a.clone())
            .expect("turn A gateway generation");
        assert!(authority.authorize(generation_a.token.as_str()).is_some());
        assert!(authority.deactivate_generation(&generation_a));

        let identity_b = ProviderRequestIdentity {
            turn_id: "turn-b".to_string(),
            binding_hash: "binding-b".to_string(),
        };
        let generation_b = authority
            .activate(identity_b.clone())
            .expect("turn B gateway generation");
        assert!(authority.authorize(generation_a.token.as_str()).is_none());
        assert!(!authority.is_current(&generation_a));
        assert!(authority.is_current(&generation_b));
        assert!(authority.authorize(generation_b.token.as_str()).is_some());
        assert_eq!(generation_b.identity, identity_b);
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
