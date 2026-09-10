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

pub const PROTOCOL_VERSION: &str = "d29-h8.vita-sidecar.v1";
pub const RUNTIME_ID: &str = "vita-agent";
pub const CODEX_UPSTREAM_COMMIT: &str = "316795b3cf2a45e90d121d9f46499d4658b2645c";
pub const CODEX_PROTOCOL_SCHEMA_HASH: &str =
    "d8faa38d5f00aa7ddfe635a2d374ee5f871ffd217d4d175c72fbe7f009f4f669";
pub const MAX_FRAME_BYTES: usize = 512 * 1024;
pub const MAX_ID_BYTES: usize = 128;
pub const MAX_PATH_BYTES: usize = 32 * 1024;
pub const MAX_SUMMARY_BYTES: usize = 256;
pub const MAX_SHA256_BYTES: usize = 128;

pub const CAPABILITY_ID: &str = "vita.process.workspace.git_status";
pub const PROFILE_ID: &str = "d29h7c.git.status.v1";
pub const TOOL_NAME: &str = "vita_workspace_git_status";

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
    let mut body = vec![0_u8; length];
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

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostMessage {
    Initialize(InitializeSession),
    AuthorityScopeReply(AuthorityScopeReply),
    ConfirmationReply(ConfirmationReply),
    GrantIssued(GrantIssued),
    GrantRevalidated(GrantRevalidated),
    CancelAction(CancelAction),
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
    ActionCancelled(ActionCancelled),
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

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AuthorityEvaluate {
    pub request_id: String,
    pub session_id: String,
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
        valid_path(&self.git_path)
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
}
