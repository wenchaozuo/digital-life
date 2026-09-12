//! Tiny, dependency-light wire contract for the process-isolated Vita sidecar.
//!
//! This crate contains syntax and bounds only.  It deliberately has no
//! authority, filesystem, process, database, Tauri, Codex, or credential
//! dependency.  The Host and Vita processes validate the same DTOs at their
//! private inherited-handle boundary, while each process keeps its own
//! authority and runtime implementation.

use std::fmt;
use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Digital Life's private Host↔Vita wire version.  D31-A adds new workspace
/// read authority variants, so old and new sidecars must fail closed during
/// the initialization handshake instead of relying on serde compatibility.
pub const PROTOCOL_VERSION: &str = "d31-a.vita-sidecar.v3";
pub const RUNTIME_ID: &str = "vita-agent";
pub const CODEX_UPSTREAM_COMMIT: &str = "316795b3cf2a45e90d121d9f46499d4658b2645c";
pub const CODEX_PROTOCOL_SCHEMA_HASH: &str =
    "d8faa38d5f00aa7ddfe635a2d374ee5f871ffd217d4d175c72fbe7f009f4f669";
pub const MAX_FRAME_BYTES: usize = 512 * 1024;
pub const MAX_ID_BYTES: usize = 128;
pub const MAX_PATH_BYTES: usize = 32 * 1024;
pub const MAX_SUMMARY_BYTES: usize = 256;
pub const MAX_SHA256_BYTES: usize = 128;
pub const MAX_PROMPT_BYTES: usize = 64 * 1024;
pub const MAX_TURN_OUTPUT_BYTES: usize = 256 * 1024;
pub const MAX_PROVIDER_BINDING_BYTES: usize = 256;
pub const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
pub const MAX_WORKSPACE_READ_BYTES: u64 = 64 * 1024;
pub const MAX_WORKSPACE_READ_RELATIVE_PATH_BYTES: usize = 4 * 1024;

pub const CAPABILITY_ID: &str = "vita.process.workspace.git_status";
pub const PROFILE_ID: &str = "d29h7c.git.status.v1";
pub const TOOL_NAME: &str = "vita_workspace_git_status";

/// D31-A freezes this future lane's identities without registering it in the
/// production Host catalog.  These wire constants are not a tool exposure.
pub const WORKSPACE_READ_CAPABILITY_ID: &str = "vita.workspace.read_file";
pub const WORKSPACE_READ_PROFILE_ID: &str = "d31.workspace.read_file.v1";
pub const WORKSPACE_READ_TOOL_NAME: &str = "vita_workspace_read_file";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameError {
    Io,
    TruncatedLength,
    TruncatedBody,
    ZeroLength,
    TooLarge,
    InvalidUtf8,
    InvalidJson,
    InvalidField,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Io => "sidecar IPC I/O failed",
            Self::TruncatedLength => "sidecar IPC frame length was truncated",
            Self::TruncatedBody => "sidecar IPC frame body was truncated",
            Self::ZeroLength => "sidecar IPC frame length was zero",
            Self::TooLarge => "sidecar IPC frame exceeded its bound",
            Self::InvalidUtf8 => "sidecar IPC frame was not UTF-8",
            Self::InvalidJson => "sidecar IPC frame was not valid JSON",
            Self::InvalidField => "sidecar IPC field was outside its bound",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

pub fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, FrameError> {
    let body = serde_json::to_vec(value).map_err(|_| FrameError::InvalidJson)?;
    if body.is_empty() {
        return Err(FrameError::ZeroLength);
    }
    if body.len() > MAX_FRAME_BYTES || body.len() > u32::MAX as usize {
        return Err(FrameError::TooLarge);
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Encodes a credential-bearing frame into a zeroizing Digital Life-owned
/// buffer.  Ordinary protocol frames intentionally retain the existing
/// `Vec<u8>` API; this separate entry point makes it impossible for a caller
/// to accidentally use the ordinary buffer for sensitive replies.
pub fn encode_sensitive_frame<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>, FrameError> {
    let body = Zeroizing::new(serde_json::to_vec(value).map_err(|_| FrameError::InvalidJson)?);
    if body.is_empty() {
        return Err(FrameError::ZeroLength);
    }
    if body.len() > MAX_FRAME_BYTES || body.len() > u32::MAX as usize {
        return Err(FrameError::TooLarge);
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(4 + body.len()));
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

pub fn decode_frame<T: DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    if body.is_empty() {
        return Err(FrameError::ZeroLength);
    }
    if body.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    std::str::from_utf8(body).map_err(|_| FrameError::InvalidUtf8)?;
    serde_json::from_slice(body).map_err(|_| FrameError::InvalidJson)
}

/// Reads one bounded big-endian length-prefixed frame.  EOF before the first
/// length byte is a clean channel close; a partial length/body is a protocol
/// failure and must be treated as deny/retire by the caller.
pub fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, FrameError> {
    read_frame_owned(reader).map(|body| body.map(|body| body.to_vec()))
}

/// Reads a frame into a zeroizing owned buffer.  This is used by the mixed
/// Host/Vita reader loops so a credential reply does not leave a plaintext
/// JSON body in an ordinary heap allocation after dispatch.
pub fn read_sensitive_frame(
    reader: &mut impl Read,
) -> Result<Option<Zeroizing<Vec<u8>>>, FrameError> {
    read_frame_owned(reader)
}

fn read_frame_owned(reader: &mut impl Read) -> Result<Option<Zeroizing<Vec<u8>>>, FrameError> {
    let mut length_bytes = [0_u8; 4];
    match reader.read(&mut length_bytes[..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!(),
        Err(error) => return Err(error.into()),
    }
    reader
        .read_exact(&mut length_bytes[1..])
        .map_err(|_| FrameError::TruncatedLength)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 {
        return Err(FrameError::ZeroLength);
    }
    if length > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let mut body = Zeroizing::new(vec![0_u8; length]);
    reader
        .read_exact(&mut body)
        .map_err(|_| FrameError::TruncatedBody)?;
    std::str::from_utf8(&body).map_err(|_| FrameError::InvalidUtf8)?;
    Ok(Some(body))
}

pub fn write_frame<T: Serialize>(writer: &mut impl Write, value: &T) -> Result<(), FrameError> {
    let frame = encode_frame(value)?;
    writer.write_all(&frame).map_err(FrameError::from)?;
    writer.flush().map_err(FrameError::from)
}

pub fn write_sensitive_frame<T: Serialize>(
    writer: &mut impl Write,
    value: &T,
) -> Result<(), FrameError> {
    let frame = encode_sensitive_frame(value)?;
    writer.write_all(&frame).map_err(FrameError::from)?;
    writer.flush().map_err(FrameError::from)
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostMessage {
    Initialize(InitializeSession),
    AuthorityScopeReply(AuthorityScopeReply),
    ConfirmationReply(ConfirmationReply),
    GrantIssued(GrantIssued),
    GrantRevalidated(GrantRevalidated),
    WorkspaceReadAuthorityReply(WorkspaceReadAuthorityReply),
    WorkspaceReadConfirmationReply(WorkspaceReadConfirmationReply),
    WorkspaceReadGrantIssued(WorkspaceReadGrantIssued),
    WorkspaceReadGrantRevalidated(WorkspaceReadGrantRevalidated),
    WorkspaceReadReleaseChecked(WorkspaceReadReleaseChecked),
    CancelAction(CancelAction),
    StartTurn(StartTurn),
    CancelTurn(CancelTurn),
    SensitiveCredentialReply(SensitiveCredentialReply),
    Shutdown(Shutdown),
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum VitaMessage {
    Handshake(Handshake),
    Ready(Ready),
    AuthorityEvaluate(AuthorityEvaluate),
    ConfirmationRequired(ConfirmationRequired),
    IssueGrant(IssueGrant),
    RevalidateGrant(RevalidateGrant),
    WorkspaceReadAuthorityEvaluate(WorkspaceReadAuthorityEvaluate),
    WorkspaceReadConfirmationRequired(WorkspaceReadConfirmationRequired),
    WorkspaceReadIssueGrant(WorkspaceReadIssueGrant),
    WorkspaceReadRevalidateGrant(WorkspaceReadRevalidateGrant),
    WorkspaceReadReleaseCheck(WorkspaceReadReleaseCheck),
    ActionCancelled(ActionCancelled),
    CredentialRequired(CredentialRequired),
    TurnState(TurnState),
    TurnCompleted(TurnCompleted),
    TurnFailed(TurnFailed),
    ShutdownAck(ShutdownAck),
    Fatal(FatalMessage),
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InitializeSession {
    pub request_id: String,
    pub protocol_version: String,
    pub session_id: String,
    pub life_id: String,
    pub task_id: String,
    pub app_data_root: String,
    pub workspace_path: String,
    pub git_path: String,
    #[serde(default)]
    pub provider: Option<ProviderConfiguration>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfiguration {
    pub profile_id: String,
    pub purpose: String,
    pub provider_kind: String,
    pub base_url: String,
    pub model: String,
    pub credential_ref: String,
    pub credential_destination: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProviderBinding {
    pub session_id: String,
    pub turn_id: String,
    pub profile_id: String,
    pub purpose: String,
    pub provider_kind: String,
    pub base_url: String,
    pub model: String,
    pub credential_ref: String,
    pub credential_destination: String,
    pub binding_hash: String,
}

impl ProviderBinding {
    pub fn derive(
        session_id: &str,
        turn_id: &str,
        configuration: &ProviderConfiguration,
    ) -> Result<Self, FrameError> {
        let mut binding = Self {
            session_id: session_id.to_string(),
            turn_id: turn_id.to_string(),
            profile_id: configuration.profile_id.clone(),
            purpose: configuration.purpose.clone(),
            provider_kind: configuration.provider_kind.clone(),
            base_url: configuration.base_url.clone(),
            model: configuration.model.clone(),
            credential_ref: configuration.credential_ref.clone(),
            credential_destination: configuration.credential_destination.clone(),
            binding_hash: String::new(),
        };
        binding.validate_without_hash()?;
        binding.binding_hash = binding.expected_hash();
        Ok(binding)
    }

    pub fn expected_hash(&self) -> String {
        let canonical = [
            self.session_id.as_str(),
            self.turn_id.as_str(),
            self.profile_id.as_str(),
            self.purpose.as_str(),
            self.provider_kind.as_str(),
            self.base_url.as_str(),
            self.model.as_str(),
            self.credential_ref.as_str(),
            self.credential_destination.as_str(),
        ]
        .join("\u{1f}");
        format!("{:x}", Sha256::digest(canonical.as_bytes()))
    }

    fn validate_without_hash(&self) -> Result<(), FrameError> {
        for value in [
            &self.session_id,
            &self.turn_id,
            &self.profile_id,
            &self.purpose,
            &self.provider_kind,
            &self.base_url,
            &self.model,
            &self.credential_ref,
            &self.credential_destination,
        ] {
            valid_bounded_text(value, MAX_PROVIDER_BINDING_BYTES)?;
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), FrameError> {
        self.validate_without_hash()?;
        if self.binding_hash.len() != 64
            || !self
                .binding_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.binding_hash != self.expected_hash()
        {
            return Err(FrameError::InvalidField);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Handshake {
    pub request_id: String,
    pub protocol_version: String,
    pub runtime: String,
    pub codex_commit: String,
    pub codex_schema_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    pub request_id: String,
    pub session_id: String,
    pub life_id: String,
    pub task_id: String,
    pub workspace_identity: String,
    pub capability_id: String,
    pub profile_id: String,
    pub tool_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProcessBinding {
    pub session_id: String,
    pub life_id: String,
    pub task_id: String,
    pub capability_id: String,
    pub program_id: String,
    pub executable_identity: String,
    pub executable_sha256: String,
    pub argv_hash: String,
    pub argv_count: u32,
    pub working_directory_identity: String,
    pub environment_policy_hash: String,
    pub stdout_bound: u32,
    pub stderr_bound: u32,
    pub timeout_ms: u64,
    pub tool_call_id: String,
    pub turn_id: String,
    pub workspace_root_identity: String,
    pub profile_id: String,
    pub git_metadata_fence_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ProcessGrant {
    pub session_id: String,
    pub grant_id: String,
    pub confirmation_id: String,
    pub binding: ProcessBinding,
    pub authorization_revision: i64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub single_use: bool,
    pub used: bool,
}

/// Typed evidence for a future bounded workspace-file read.  This is
/// intentionally separate from `ProcessBinding`: it does not represent an
/// executable image, arguments, environment, or process authority.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceReadTargetKind {
    File,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadBinding {
    pub session_id: String,
    pub life_id: String,
    pub task_id: String,
    pub capability_id: String,
    pub tool_name: String,
    pub workspace_root_identity: String,
    pub relative_path: String,
    pub target_identity: String,
    pub target_kind: WorkspaceReadTargetKind,
    pub max_bytes: u64,
    pub tool_call_id: String,
    pub codex_turn_id: String,
    pub provider_binding_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadGrant {
    pub session_id: String,
    pub grant_id: String,
    pub confirmation_id: String,
    pub binding: WorkspaceReadBinding,
    pub authorization_revision: i64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub single_use: bool,
    pub used: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadAuthorityEvaluate {
    pub request_id: String,
    pub session_id: String,
    pub host_turn_id: String,
    pub binding: WorkspaceReadBinding,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadAuthorityReply {
    pub request_id: String,
    pub session_id: String,
    pub allowed: bool,
    pub authorization_revision: Option<i64>,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadConfirmationRequired {
    pub request_id: String,
    pub session_id: String,
    pub host_turn_id: String,
    pub workspace_summary: String,
    pub expires_at_unix_ms: u64,
    pub binding: WorkspaceReadBinding,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadConfirmationReply {
    pub request_id: String,
    pub session_id: String,
    pub decision: ConfirmationDecision,
    pub authorization_revision: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadIssueGrant {
    pub request_id: String,
    pub session_id: String,
    pub host_turn_id: String,
    pub binding: WorkspaceReadBinding,
    pub authorization_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadGrantIssued {
    pub request_id: String,
    pub session_id: String,
    pub allowed: bool,
    pub grant: Option<WorkspaceReadGrant>,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadRevalidateGrant {
    pub request_id: String,
    pub session_id: String,
    pub host_turn_id: String,
    pub binding: WorkspaceReadBinding,
    pub grant: WorkspaceReadGrant,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadGrantRevalidated {
    pub request_id: String,
    pub session_id: String,
    pub allowed: bool,
    pub grant: Option<WorkspaceReadGrant>,
    pub error_code: Option<String>,
}

/// The post-read disclosure fence.  A successful reply makes a confidential
/// Vita-owned buffer eligible for tool output; it is not a read grant itself.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadReleaseCheck {
    pub request_id: String,
    pub session_id: String,
    pub host_turn_id: String,
    pub binding: WorkspaceReadBinding,
    pub grant: WorkspaceReadGrant,
    pub bytes_read: u64,
    pub content_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceReadReleaseChecked {
    pub request_id: String,
    pub session_id: String,
    pub allowed: bool,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEvaluate {
    pub request_id: String,
    pub session_id: String,
    /// Host turn generation owning this governed action.  The process-local
    /// H7 binding has its own Codex turn id; this field prevents a late H7
    /// authority message from being accepted by a newer Host turn.
    pub host_turn_id: String,
    pub binding: ProcessBinding,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityScopeReply {
    pub request_id: String,
    pub session_id: String,
    pub allowed: bool,
    pub authorization_revision: Option<i64>,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationRequired {
    pub request_id: String,
    pub session_id: String,
    pub host_turn_id: String,
    pub life_id: String,
    pub task_id: String,
    pub capability_id: String,
    pub workspace_summary: String,
    pub expires_at_unix_ms: u64,
    pub binding: ProcessBinding,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationDecision {
    Confirm,
    Deny,
    Cancel,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ConfirmationReply {
    pub request_id: String,
    pub session_id: String,
    pub decision: ConfirmationDecision,
    pub authorization_revision: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IssueGrant {
    pub request_id: String,
    pub session_id: String,
    pub host_turn_id: String,
    pub binding: ProcessBinding,
    pub authorization_revision: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GrantIssued {
    pub request_id: String,
    pub session_id: String,
    pub allowed: bool,
    pub grant: Option<ProcessGrant>,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RevalidateGrant {
    pub request_id: String,
    pub session_id: String,
    pub host_turn_id: String,
    pub binding: ProcessBinding,
    pub grant: ProcessGrant,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GrantRevalidated {
    pub request_id: String,
    pub session_id: String,
    pub allowed: bool,
    pub grant: Option<ProcessGrant>,
    pub error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CancelAction {
    pub request_id: String,
    pub session_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ActionCancelled {
    pub request_id: String,
    pub session_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Shutdown {
    pub request_id: String,
    pub session_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ShutdownAck {
    pub request_id: String,
    pub session_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct StartTurn {
    pub request_id: String,
    pub session_id: String,
    pub turn_id: String,
    pub prompt: String,
    pub binding: ProviderBinding,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CancelTurn {
    pub request_id: String,
    pub session_id: String,
    pub turn_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CredentialRequired {
    pub request_id: String,
    pub session_id: String,
    pub turn_id: String,
    pub binding: ProviderBinding,
}

/// A request-scoped credential.  The custom Debug implementation and the
/// zeroizing owned allocation are deliberate: this type may cross only the
/// dedicated sensitive message path and must never become ordinary
/// diagnostics.
pub struct SensitiveCredential(Zeroizing<String>);

impl SensitiveCredential {
    pub fn new(value: String) -> Result<Self, FrameError> {
        if value.is_empty()
            || value.len() > MAX_CREDENTIAL_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(FrameError::InvalidField);
        }
        Ok(Self(Zeroizing::new(value)))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl Clone for SensitiveCredential {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(self.0.to_string()))
    }
}

impl PartialEq for SensitiveCredential {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

impl Eq for SensitiveCredential {}

impl fmt::Debug for SensitiveCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

impl Serialize for SensitiveCredential {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SensitiveCredential {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(|_| serde::de::Error::custom("invalid sensitive credential"))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SensitiveCredentialReply {
    pub request_id: String,
    pub session_id: String,
    pub turn_id: String,
    pub binding_hash: String,
    pub credential_ref: String,
    /// `None` is a deliberate deny response.  It lets the Host reject a
    /// stale/deleted profile without ever manufacturing placeholder secret
    /// material for the sidecar.
    pub credential: Option<SensitiveCredential>,
    pub error_code: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TurnPhase {
    Starting,
    Running,
    /// Host has won the cancellation authority race and is waiting for the
    /// sidecar's bounded interruption acknowledgement.  This is deliberately
    /// distinct from `Cancelled`: a cancellation request is not terminal
    /// until the sidecar has fenced its Codex/provider/tool lifecycle.
    Cancelling,
    WaitingForToolConfirmation,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TurnState {
    pub request_id: String,
    pub session_id: String,
    pub turn_id: String,
    pub phase: TurnPhase,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TurnCompleted {
    pub request_id: String,
    pub session_id: String,
    pub turn_id: String,
    pub model: String,
    pub assistant_text: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TurnFailed {
    pub request_id: String,
    pub session_id: String,
    pub turn_id: String,
    pub phase: TurnPhase,
    pub error_code: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FatalMessage {
    pub request_id: String,
    pub session_id: Option<String>,
    pub error_code: String,
}

impl InitializeSession {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(FrameError::InvalidField);
        }
        valid_id(&self.session_id)?;
        valid_id(&self.life_id)?;
        valid_id(&self.task_id)?;
        valid_path(&self.app_data_root)?;
        valid_path(&self.workspace_path)?;
        valid_path(&self.git_path)?;
        if let Some(provider) = &self.provider {
            provider.validate()?;
        }
        Ok(())
    }
}

impl ProviderConfiguration {
    pub fn validate(&self) -> Result<(), FrameError> {
        for value in [
            &self.profile_id,
            &self.purpose,
            &self.provider_kind,
            &self.base_url,
            &self.model,
            &self.credential_ref,
            &self.credential_destination,
        ] {
            valid_bounded_text(value, MAX_PROVIDER_BINDING_BYTES)?;
        }
        if self.purpose != "chat" || self.provider_kind != "openai_compatible" {
            return Err(FrameError::InvalidField);
        }
        Ok(())
    }
}

impl StartTurn {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.turn_id)?;
        if self.prompt.is_empty() || self.prompt.len() > MAX_PROMPT_BYTES {
            return Err(FrameError::InvalidField);
        }
        if self.prompt.chars().any(disallowed_text_control) {
            return Err(FrameError::InvalidField);
        }
        self.binding.validate()
    }
}

impl CancelTurn {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.turn_id)
    }
}

impl CredentialRequired {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.turn_id)?;
        self.binding.validate()
    }
}

impl AuthorityEvaluate {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.host_turn_id)?;
        self.binding.validate()
    }
}

impl ConfirmationRequired {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.host_turn_id)?;
        valid_id(&self.life_id)?;
        valid_id(&self.task_id)?;
        valid_id(&self.capability_id)?;
        valid_bounded_text(&self.workspace_summary, MAX_SUMMARY_BYTES)?;
        if self.expires_at_unix_ms == 0 {
            return Err(FrameError::InvalidField);
        }
        self.binding.validate()
    }
}

impl IssueGrant {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.host_turn_id)?;
        if self.authorization_revision <= 0 {
            return Err(FrameError::InvalidField);
        }
        self.binding.validate()
    }
}

impl RevalidateGrant {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.host_turn_id)?;
        self.binding.validate()?;
        self.grant.validate()
    }
}

impl WorkspaceReadBinding {
    pub fn validate(&self) -> Result<(), FrameError> {
        for value in [
            &self.session_id,
            &self.life_id,
            &self.task_id,
            &self.capability_id,
            &self.tool_name,
            &self.workspace_root_identity,
            &self.target_identity,
            &self.tool_call_id,
            &self.codex_turn_id,
        ] {
            valid_id(value)?;
        }
        if self.capability_id != WORKSPACE_READ_CAPABILITY_ID
            || self.tool_name != WORKSPACE_READ_TOOL_NAME
            || self.max_bytes == 0
            || self.max_bytes > MAX_WORKSPACE_READ_BYTES
        {
            return Err(FrameError::InvalidField);
        }
        valid_workspace_relative_path(&self.relative_path)?;
        valid_sha256(&self.provider_binding_hash)
    }
}

impl WorkspaceReadGrant {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.session_id)?;
        valid_id(&self.grant_id)?;
        valid_id(&self.confirmation_id)?;
        self.binding.validate()?;
        if self.session_id != self.binding.session_id
            || self.authorization_revision <= 0
            || self.issued_at_unix_ms > self.expires_at_unix_ms
            || !self.single_use
        {
            return Err(FrameError::InvalidField);
        }
        Ok(())
    }
}

impl WorkspaceReadAuthorityEvaluate {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.host_turn_id)?;
        self.binding.validate()?;
        if self.session_id != self.binding.session_id {
            return Err(FrameError::InvalidField);
        }
        Ok(())
    }
}

impl WorkspaceReadAuthorityReply {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_authority_reply(
            &self.request_id,
            &self.session_id,
            self.allowed,
            self.authorization_revision,
            self.error_code.as_deref(),
        )
    }
}

impl WorkspaceReadConfirmationRequired {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.host_turn_id)?;
        valid_bounded_text(&self.workspace_summary, MAX_SUMMARY_BYTES)?;
        if self.expires_at_unix_ms == 0 {
            return Err(FrameError::InvalidField);
        }
        self.binding.validate()?;
        if self.session_id != self.binding.session_id {
            return Err(FrameError::InvalidField);
        }
        Ok(())
    }
}

impl WorkspaceReadConfirmationReply {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_confirmation_reply(
            &self.request_id,
            &self.session_id,
            self.decision,
            self.authorization_revision,
        )
    }
}

impl WorkspaceReadIssueGrant {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.host_turn_id)?;
        self.binding.validate()?;
        if self.session_id != self.binding.session_id || self.authorization_revision <= 0 {
            return Err(FrameError::InvalidField);
        }
        Ok(())
    }
}

impl WorkspaceReadGrantIssued {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_grant_reply(
            &self.request_id,
            &self.session_id,
            self.allowed,
            self.grant.as_ref(),
            self.error_code.as_deref(),
        )
    }
}

impl WorkspaceReadRevalidateGrant {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.host_turn_id)?;
        self.binding.validate()?;
        self.grant.validate()?;
        if self.session_id != self.binding.session_id
            || self.binding != self.grant.binding
            || self.session_id != self.grant.session_id
        {
            return Err(FrameError::InvalidField);
        }
        Ok(())
    }
}

impl WorkspaceReadGrantRevalidated {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_grant_reply(
            &self.request_id,
            &self.session_id,
            self.allowed,
            self.grant.as_ref(),
            self.error_code.as_deref(),
        )
    }
}

impl WorkspaceReadReleaseCheck {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.host_turn_id)?;
        self.binding.validate()?;
        self.grant.validate()?;
        valid_sha256(&self.content_sha256)?;
        if self.session_id != self.binding.session_id
            || self.session_id != self.grant.session_id
            || self.binding != self.grant.binding
            || self.bytes_read > self.binding.max_bytes
        {
            return Err(FrameError::InvalidField);
        }
        Ok(())
    }
}

impl WorkspaceReadReleaseChecked {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        match (self.allowed, self.error_code.as_deref()) {
            (true, None) | (false, Some(_)) => {}
            _ => return Err(FrameError::InvalidField),
        }
        if let Some(error_code) = &self.error_code {
            valid_id(error_code)?;
        }
        Ok(())
    }
}

impl SensitiveCredentialReply {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.turn_id)?;
        valid_bounded_text(&self.binding_hash, 64)?;
        valid_bounded_text(&self.credential_ref, MAX_PROVIDER_BINDING_BYTES)?;
        if let Some(error_code) = &self.error_code {
            valid_id(error_code)?;
        }
        if self.credential.is_some() == self.error_code.is_some() {
            return Err(FrameError::InvalidField);
        }
        Ok(())
    }
}

impl TurnState {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.turn_id)
    }
}

impl TurnCompleted {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.turn_id)?;
        valid_bounded_text(&self.model, MAX_PROVIDER_BINDING_BYTES)?;
        if self.assistant_text.is_empty()
            || self.assistant_text.len() > MAX_TURN_OUTPUT_BYTES
            || self.assistant_text.chars().any(disallowed_text_control)
        {
            return Err(FrameError::InvalidField);
        }
        Ok(())
    }
}

impl TurnFailed {
    pub fn validate(&self) -> Result<(), FrameError> {
        valid_id(&self.request_id)?;
        valid_id(&self.session_id)?;
        valid_id(&self.turn_id)?;
        valid_id(&self.error_code)?;
        if !matches!(
            self.phase,
            TurnPhase::Failed | TurnPhase::Cancelled | TurnPhase::TimedOut
        ) {
            return Err(FrameError::InvalidField);
        }
        if self.message.is_empty()
            || self.message.len() > MAX_SUMMARY_BYTES
            || self.message.chars().any(disallowed_text_control)
        {
            return Err(FrameError::InvalidField);
        }
        Ok(())
    }
}

impl ProcessBinding {
    pub fn validate(&self) -> Result<(), FrameError> {
        for value in [
            &self.session_id,
            &self.life_id,
            &self.task_id,
            &self.capability_id,
            &self.program_id,
            &self.executable_identity,
            &self.argv_hash,
            &self.working_directory_identity,
            &self.environment_policy_hash,
            &self.tool_call_id,
            &self.turn_id,
            &self.workspace_root_identity,
            &self.profile_id,
            &self.git_metadata_fence_hash,
        ] {
            valid_id(value)?;
        }
        if self.executable_sha256.len() > MAX_SHA256_BYTES
            || self.executable_sha256.is_empty()
            || self.stdout_bound == 0
            || self.stderr_bound == 0
            || self.argv_count > 128
            || self.timeout_ms == 0
        {
            return Err(FrameError::InvalidField);
        }
        Ok(())
    }
}

impl ProcessGrant {
    pub fn validate(&self) -> Result<(), FrameError> {
        self.binding.validate()?;
        valid_id(&self.session_id)?;
        valid_id(&self.grant_id)?;
        valid_id(&self.confirmation_id)?;
        if self.authorization_revision <= 0
            || self.issued_at_unix_ms > self.expires_at_unix_ms
            || !self.single_use
        {
            return Err(FrameError::InvalidField);
        }
        Ok(())
    }
}

fn valid_authority_reply(
    request_id: &str,
    session_id: &str,
    allowed: bool,
    authorization_revision: Option<i64>,
    error_code: Option<&str>,
) -> Result<(), FrameError> {
    valid_id(request_id)?;
    valid_id(session_id)?;
    match (allowed, authorization_revision, error_code) {
        (true, Some(revision), None) if revision > 0 => Ok(()),
        (false, None, Some(code)) => valid_id(code),
        _ => Err(FrameError::InvalidField),
    }
}

fn valid_confirmation_reply(
    request_id: &str,
    session_id: &str,
    decision: ConfirmationDecision,
    authorization_revision: Option<i64>,
) -> Result<(), FrameError> {
    valid_id(request_id)?;
    valid_id(session_id)?;
    match (decision, authorization_revision) {
        (ConfirmationDecision::Confirm, Some(revision)) if revision > 0 => Ok(()),
        (ConfirmationDecision::Deny | ConfirmationDecision::Cancel, None) => Ok(()),
        _ => Err(FrameError::InvalidField),
    }
}

fn valid_grant_reply(
    request_id: &str,
    session_id: &str,
    allowed: bool,
    grant: Option<&WorkspaceReadGrant>,
    error_code: Option<&str>,
) -> Result<(), FrameError> {
    valid_id(request_id)?;
    valid_id(session_id)?;
    match (allowed, grant, error_code) {
        (true, Some(grant), None) if grant.session_id == session_id => grant.validate(),
        (false, None, Some(code)) => valid_id(code),
        _ => Err(FrameError::InvalidField),
    }
}

fn valid_id(value: &str) -> Result<(), FrameError> {
    if value.is_empty()
        || value.len() > MAX_ID_BYTES
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(FrameError::InvalidField);
    }
    Ok(())
}

fn valid_workspace_relative_path(value: &str) -> Result<(), FrameError> {
    if value.is_empty()
        || value.len() > MAX_WORKSPACE_READ_RELATIVE_PATH_BYTES
        || value.chars().any(char::is_control)
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.contains(':')
    {
        return Err(FrameError::InvalidField);
    }
    if value
        .split('/')
        .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(FrameError::InvalidField);
    }
    Ok(())
}

fn valid_sha256(value: &str) -> Result<(), FrameError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(FrameError::InvalidField);
    }
    Ok(())
}

fn valid_bounded_text(value: &str, max_bytes: usize) -> Result<(), FrameError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(FrameError::InvalidField);
    }
    Ok(())
}

fn disallowed_text_control(value: char) -> bool {
    value.is_control() && !matches!(value, '\n' | '\r' | '\t')
}

fn valid_path(value: &str) -> Result<(), FrameError> {
    if value.is_empty()
        || value.len() > MAX_PATH_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(FrameError::InvalidField);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn read_binding() -> WorkspaceReadBinding {
        WorkspaceReadBinding {
            session_id: "session".to_string(),
            life_id: "life".to_string(),
            task_id: "task".to_string(),
            capability_id: WORKSPACE_READ_CAPABILITY_ID.to_string(),
            tool_name: WORKSPACE_READ_TOOL_NAME.to_string(),
            workspace_root_identity: "root-identity".to_string(),
            relative_path: "notes/today.txt".to_string(),
            target_identity: "target-identity".to_string(),
            target_kind: WorkspaceReadTargetKind::File,
            max_bytes: 1024,
            tool_call_id: "call-1".to_string(),
            codex_turn_id: "codex-turn".to_string(),
            provider_binding_hash: "a".repeat(64),
        }
    }

    fn read_grant(binding: WorkspaceReadBinding) -> WorkspaceReadGrant {
        WorkspaceReadGrant {
            session_id: binding.session_id.clone(),
            grant_id: "grant-1".to_string(),
            confirmation_id: "confirmation-1".to_string(),
            binding,
            authorization_revision: 2,
            issued_at_unix_ms: 1,
            expires_at_unix_ms: 2,
            single_use: true,
            used: false,
        }
    }

    #[test]
    fn frame_round_trip_is_bounded() {
        let message = VitaMessage::Handshake(Handshake {
            request_id: "hello-1".to_string(),
            protocol_version: PROTOCOL_VERSION.to_string(),
            runtime: RUNTIME_ID.to_string(),
            codex_commit: CODEX_UPSTREAM_COMMIT.to_string(),
            codex_schema_hash: CODEX_PROTOCOL_SCHEMA_HASH.to_string(),
        });
        let frame = encode_frame(&message).expect("frame");
        let mut cursor = Cursor::new(frame);
        let body = read_frame(&mut cursor).expect("read").expect("body");
        let decoded: VitaMessage = decode_frame(&body).expect("decode");
        assert_eq!(decoded, message);
    }

    #[test]
    fn malformed_frame_inputs_fail_closed() {
        assert_eq!(
            decode_frame::<VitaMessage>(&[]),
            Err(FrameError::ZeroLength)
        );
        assert_eq!(
            read_frame(&mut Cursor::new([0, 0, 0, 0])),
            Err(FrameError::ZeroLength)
        );
        assert_eq!(
            read_frame(&mut Cursor::new([0, 0, 0, 2, b'{'])),
            Err(FrameError::TruncatedBody)
        );
        assert_eq!(
            read_frame(&mut Cursor::new([0, 1])),
            Err(FrameError::TruncatedLength)
        );
        let oversized = (MAX_FRAME_BYTES as u32 + 1).to_be_bytes();
        assert_eq!(
            read_frame(&mut Cursor::new(oversized)),
            Err(FrameError::TooLarge)
        );
        let invalid_utf8 = [0, 0, 0, 2, 0xff, 0xff];
        assert_eq!(
            read_frame(&mut Cursor::new(invalid_utf8)),
            Err(FrameError::InvalidUtf8)
        );
        assert_eq!(
            decode_frame::<VitaMessage>(br#"{\"type\":\"unknown_variant\"}"#),
            Err(FrameError::InvalidJson)
        );
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let body = br#"{"type":"handshake","request_id":"x","protocol_version":"d29-h8.vita-sidecar.v1","runtime":"vita-agent","codex_commit":"x","codex_schema_hash":"x","extra":1}"#;
        assert_eq!(
            decode_frame::<VitaMessage>(body),
            Err(FrameError::InvalidJson)
        );
    }

    #[test]
    fn sensitive_credential_debug_and_wire_buffer_are_redacted() {
        let credential = SensitiveCredential::new("secret-placeholder".to_string()).unwrap();
        assert_eq!(format!("{credential:?}"), "[REDACTED]");
        assert!(!format!("{credential:?}").contains("secret-placeholder"));
        let reply = HostMessage::SensitiveCredentialReply(SensitiveCredentialReply {
            request_id: "credential-request".to_string(),
            session_id: "session".to_string(),
            turn_id: "turn".to_string(),
            binding_hash: "a".repeat(64),
            credential_ref: "profile".to_string(),
            credential: Some(credential),
            error_code: None,
        });
        let frame = encode_sensitive_frame(&reply).expect("sensitive frame");
        assert!(frame
            .windows("secret-placeholder".len())
            .any(|window| { window == b"secret-placeholder" }));
        let decoded: HostMessage = decode_frame(&frame[4..]).expect("sensitive decode");
        assert!(matches!(decoded, HostMessage::SensitiveCredentialReply(_)));
    }

    #[test]
    fn provider_binding_hash_is_exact_and_secret_free() {
        let configuration = ProviderConfiguration {
            profile_id: "profile".to_string(),
            purpose: "chat".to_string(),
            provider_kind: "openai_compatible".to_string(),
            base_url: "https://provider.example/v1".to_string(),
            model: "model".to_string(),
            credential_ref: "profile".to_string(),
            credential_destination: "https://provider.example/v1".to_string(),
        };
        let binding = ProviderBinding::derive("session", "turn", &configuration).unwrap();
        assert_eq!(binding.binding_hash, binding.expected_hash());
        assert!(binding.validate().is_ok());
        let mut stale = binding.clone();
        stale.model = "other-model".to_string();
        assert!(stale.validate().is_err());
    }

    #[test]
    fn workspace_read_binding_round_trips_without_process_fields() {
        let binding = read_binding();
        assert!(binding.validate().is_ok());
        let grant = read_grant(binding.clone());
        let message = VitaMessage::WorkspaceReadReleaseCheck(WorkspaceReadReleaseCheck {
            request_id: "release-1".to_string(),
            session_id: binding.session_id.clone(),
            host_turn_id: "host-turn".to_string(),
            binding,
            grant,
            bytes_read: 42,
            content_sha256: "b".repeat(64),
        });
        let frame = encode_frame(&message).expect("read release frame");
        let decoded: VitaMessage = decode_frame(&frame[4..]).expect("read release decode");
        assert_eq!(decoded, message);
        if let VitaMessage::WorkspaceReadReleaseCheck(check) = decoded {
            assert!(check.validate().is_ok());
        } else {
            panic!("workspace read release variant was not preserved");
        }
    }

    #[test]
    fn workspace_read_binding_and_release_evidence_fail_closed() {
        let mut malformed_path = read_binding();
        malformed_path.relative_path = "../secret.txt".to_string();
        assert_eq!(malformed_path.validate(), Err(FrameError::InvalidField));
        let mut oversized = read_binding();
        oversized.max_bytes = MAX_WORKSPACE_READ_BYTES + 1;
        assert_eq!(oversized.validate(), Err(FrameError::InvalidField));
        let mut malformed_provider_hash = read_binding();
        malformed_provider_hash.provider_binding_hash = "A".repeat(64);
        assert_eq!(
            malformed_provider_hash.validate(),
            Err(FrameError::InvalidField)
        );

        let binding = read_binding();
        let mut grant = read_grant(binding.clone());
        grant.binding.relative_path = "other.txt".to_string();
        let mismatched = WorkspaceReadReleaseCheck {
            request_id: "release-2".to_string(),
            session_id: binding.session_id.clone(),
            host_turn_id: "host-turn".to_string(),
            binding: binding.clone(),
            grant,
            bytes_read: 1,
            content_sha256: "c".repeat(64),
        };
        assert_eq!(mismatched.validate(), Err(FrameError::InvalidField));
        let invalid_hash = WorkspaceReadReleaseCheck {
            request_id: "release-3".to_string(),
            session_id: binding.session_id.clone(),
            host_turn_id: "host-turn".to_string(),
            binding: binding.clone(),
            grant: read_grant(binding.clone()),
            bytes_read: 1,
            content_sha256: "not-a-sha".to_string(),
        };
        assert_eq!(invalid_hash.validate(), Err(FrameError::InvalidField));
    }

    #[test]
    fn workspace_read_unknown_fields_and_protocol_mismatches_are_denied() {
        let message = VitaMessage::WorkspaceReadAuthorityEvaluate(WorkspaceReadAuthorityEvaluate {
            request_id: "authority-1".to_string(),
            session_id: "session".to_string(),
            host_turn_id: "host-turn".to_string(),
            binding: read_binding(),
        });
        let mut value = serde_json::to_value(message).expect("wire value");
        value
            .as_object_mut()
            .expect("wire object")
            .insert("unexpected".to_string(), serde_json::json!(true));
        assert_eq!(
            decode_frame::<VitaMessage>(&serde_json::to_vec(&value).expect("wire bytes")),
            Err(FrameError::InvalidJson)
        );

        let mut init = InitializeSession {
            request_id: "init".to_string(),
            protocol_version: "d29-h9.vita-sidecar.v2".to_string(),
            session_id: "session".to_string(),
            life_id: "life".to_string(),
            task_id: "task".to_string(),
            app_data_root: "C:/app".to_string(),
            workspace_path: "C:/workspace".to_string(),
            git_path: "C:/git.exe".to_string(),
            provider: None,
        };
        assert_eq!(init.validate(), Err(FrameError::InvalidField));
        init.protocol_version = PROTOCOL_VERSION.to_string();
        assert!(init.validate().is_ok());
    }

    #[test]
    fn h7_authority_wire_variant_remains_process_specific() {
        let binding = ProcessBinding {
            session_id: "session".to_string(),
            life_id: "life".to_string(),
            task_id: "task".to_string(),
            capability_id: CAPABILITY_ID.to_string(),
            program_id: PROFILE_ID.to_string(),
            executable_identity: "image".to_string(),
            executable_sha256: "a".repeat(64),
            argv_hash: "argv".to_string(),
            argv_count: 1,
            working_directory_identity: "cwd".to_string(),
            environment_policy_hash: "environment".to_string(),
            stdout_bound: 1,
            stderr_bound: 1,
            timeout_ms: 1,
            tool_call_id: "call".to_string(),
            turn_id: "codex-turn".to_string(),
            workspace_root_identity: "root".to_string(),
            profile_id: PROFILE_ID.to_string(),
            git_metadata_fence_hash: "fence".to_string(),
        };
        let message = VitaMessage::AuthorityEvaluate(AuthorityEvaluate {
            request_id: "authority".to_string(),
            session_id: "session".to_string(),
            host_turn_id: "host-turn".to_string(),
            binding,
        });
        let frame = encode_frame(&message).expect("H7 frame");
        let decoded: VitaMessage = decode_frame(&frame[4..]).expect("H7 decode");
        assert_eq!(decoded, message);
    }
}
