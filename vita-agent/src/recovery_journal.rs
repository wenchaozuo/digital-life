//! D29-H5-A recovery journal foundation.
//!
//! This module is deliberately an evidence-only boundary.  A journal records
//! a bounded, exact preimage and the trusted facts that would be needed by a
//! later recovery stage, but it never grants authority, proves a confirmation,
//! or performs a workspace mutation.  H5-B is the first stage allowed to
//! interpret a prepared record operationally.
//!
//! The on-disk format is a strict versioned binary frame rather than JSON.
//! It is bounded before allocation, uses create-new file creation, and binds
//! its canonical payload with SHA-256.  The digest is tamper evidence only;
//! it is not an authorization signature and is not a defense against a
//! malicious administrator who can rewrite the app-owned directory.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::workspace_capability::{AppOwnedRecoveryNamespace, WorkspaceReadError};
use crate::{
    PreparedWorkspaceTarget, PreparedWorkspaceTargetKind, VitaAgentError, VitaAgentRuntimeProfile,
    WorkspaceRelativePath, WorkspaceRootIdentity,
};

pub const RECOVERY_JOURNAL_FORMAT_VERSION: u16 = 1;
pub const RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES: usize = 64 * 1024;
pub const RECOVERY_JOURNAL_MAX_REPLACEMENT_BYTES: usize = 64 * 1024;
pub const RECOVERY_JOURNAL_MAX_SIZE: usize = 160 * 1024;
pub const RECOVERY_MARKER_FORMAT_VERSION: u16 = 1;
pub const RECOVERY_MARKER_MAX_SIZE: usize = 1024;

const MAGIC: &[u8; 4] = b"DLRJ";
const DOMAIN_SEPARATOR: &[u8] = b"DigitalLife.RecoveryJournalV1\0";
const HEADER_BYTES: usize = 4 + 2 + 4;
const INTEGRITY_HASH_BYTES: usize = 32;
const MAX_PAYLOAD_BYTES: usize = RECOVERY_JOURNAL_MAX_SIZE - HEADER_BYTES - INTEGRITY_HASH_BYTES;
const MAX_CONTEXT_FIELD_BYTES: usize = 512;
const MAX_RELATIVE_PATH_BYTES: usize = 96 * 1024;
const MAX_TRANSACTION_ID_BYTES: usize = 96;
const MAX_SCAN_ENTRIES: usize = 256;
const MAX_FILE_NAME_CHARS: usize = 256;
const RECOVERY_DIRECTORY_NAME: &str = "recovery";
const MARKER_MAGIC: &[u8; 4] = b"DLRM";
const MARKER_DOMAIN_SEPARATOR: &[u8] = b"DigitalLife.RecoveryMarkerV1\0";
const MARKER_HEADER_BYTES: usize = 4 + 2 + 4;
const MARKER_PAYLOAD_BYTES: usize =
    RECOVERY_MARKER_MAX_SIZE - MARKER_HEADER_BYTES - INTEGRITY_HASH_BYTES;

static NEXT_TRANSACTION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryTransactionBlockReason {
    RecoveryRequired,
    AmbiguousTarget,
    PoisonedTarget,
    ConcurrentAdmission,
}

/// Errors are intentionally typed so malformed or incomplete evidence never
/// gets silently treated as a prepared journal.
#[derive(Debug)]
pub enum RecoveryJournalError {
    Profile(VitaAgentError),
    Io {
        operation: &'static str,
        source: io::Error,
    },
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    UnsupportedPlatform,
    TargetBindingMismatch(&'static str),
    TargetNotExisting,
    TargetRead,
    PreimageConflict,
    TransactionBlocked(RecoveryTransactionBlockReason),
    Corrupt(&'static str),
    UnsupportedVersion(u16),
    Oversized {
        limit: usize,
    },
    DuplicateTransactionId,
    ScanLimitExceeded,
    ReopenVerificationFailed,
    InjectedFault(&'static str),
}

impl Display for RecoveryJournalError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Profile(error) => Display::fmt(error, formatter),
            Self::Io { operation, source } => {
                write!(formatter, "recovery journal {operation} failed: {source}")
            }
            Self::InvalidField { field, reason } => {
                write!(
                    formatter,
                    "recovery journal field {field} is invalid: {reason}"
                )
            }
            Self::UnsupportedPlatform => formatter
                .write_str("recovery journal requires the Windows workspace identity capability"),
            Self::TargetBindingMismatch(reason) => {
                write!(
                    formatter,
                    "recovery journal target binding denied: {reason}"
                )
            }
            Self::TargetNotExisting => {
                formatter.write_str("recovery journal requires an existing regular file")
            }
            Self::TargetRead => {
                formatter.write_str("recovery journal could not read the target preimage")
            }
            Self::PreimageConflict => formatter
                .write_str("recovery journal preimage does not match the H4 expected SHA-256"),
            Self::TransactionBlocked(reason) => {
                write!(
                    formatter,
                    "recovery journal target admission blocked: {reason:?}"
                )
            }
            Self::Corrupt(reason) => write!(formatter, "recovery journal is corrupt: {reason}"),
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "recovery journal version {version} is unsupported"
                )
            }
            Self::Oversized { limit } => {
                write!(formatter, "recovery journal exceeds the {limit}-byte limit")
            }
            Self::DuplicateTransactionId => {
                formatter.write_str("recovery journal transaction id already exists")
            }
            Self::ScanLimitExceeded => formatter.write_str("recovery journal scan limit exceeded"),
            Self::ReopenVerificationFailed => {
                formatter.write_str("recovery journal reopen verification failed")
            }
            Self::InjectedFault(point) => {
                write!(formatter, "injected recovery journal fault at {point}")
            }
        }
    }
}

impl std::error::Error for RecoveryJournalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Profile(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Stable identity evidence for a Windows volume/object pair.
///
/// This contains no raw HANDLE and has no authority methods.  It is used only
/// to compare the identity captured by H4 with the identity persisted in the
/// journal.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RecoveryJournalIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

impl RecoveryJournalIdentity {
    pub(crate) fn from_workspace_identity(
        identity: WorkspaceRootIdentity,
    ) -> Result<Self, RecoveryJournalError> {
        match (identity.volume_serial_number(), identity.file_id()) {
            (Some(volume_serial_number), Some(file_id)) => Ok(Self {
                volume_serial_number,
                file_id,
            }),
            _ => Err(RecoveryJournalError::UnsupportedPlatform),
        }
    }

    pub fn volume_serial_number(&self) -> u64 {
        self.volume_serial_number
    }

    pub fn file_id(&self) -> [u8; 16] {
        self.file_id
    }
}

/// Runtime-generated, filename-safe transaction identity.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RecoveryTransactionId(String);

impl RecoveryTransactionId {
    /// Parses an on-disk identity.  This parser is for strict validation; the
    /// normal creation path always generates the value locally.
    pub fn parse(value: &str) -> Result<Self, RecoveryJournalError> {
        if value.is_empty() || value.len() > MAX_TRANSACTION_ID_BYTES {
            return Err(RecoveryJournalError::InvalidField {
                field: "transaction_id",
                reason: "empty or oversized",
            });
        }
        if value == "." || value == ".." || value.ends_with('.') || value.ends_with(' ') {
            return Err(RecoveryJournalError::InvalidField {
                field: "transaction_id",
                reason: "traversal or ambiguous filename",
            });
        }
        if value.chars().any(|character| {
            character.is_control()
                || !character.is_ascii()
                || matches!(
                    character,
                    '/' | '\\' | ':' | '.' | '"' | '<' | '>' | '|' | '?' | '*'
                )
        }) {
            return Err(RecoveryJournalError::InvalidField {
                field: "transaction_id",
                reason: "not filename-safe",
            });
        }
        let device_name = value.to_ascii_uppercase();
        if matches!(
            device_name.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        ) {
            return Err(RecoveryJournalError::InvalidField {
                field: "transaction_id",
                reason: "reserved Windows device name",
            });
        }
        if !value
            .bytes()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, b'-' | b'_'))
        {
            return Err(RecoveryJournalError::InvalidField {
                field: "transaction_id",
                reason: "only ASCII letters, digits, hyphen, and underscore are allowed",
            });
        }
        Ok(Self(value.to_string()))
    }

    fn generate() -> Self {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis());
        let process = std::process::id();
        let counter = NEXT_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed);
        // All components are generated by trusted local code and are ASCII
        // filename-safe.  No caller/model value participates in the path.
        Self(format!("tx-{millis:x}-{process:x}-{counter:x}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The only durable lifecycle markers accepted by H5-B.  A marker is
/// tamper-evident transaction evidence, never a permission or recovery grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryMarkerState {
    Started,
    Committed,
    Recovered,
}

impl RecoveryMarkerState {
    fn encode(self) -> u8 {
        match self {
            Self::Started => 1,
            Self::Committed => 2,
            Self::Recovered => 3,
        }
    }

    fn decode(value: u8) -> Result<Self, RecoveryJournalError> {
        match value {
            1 => Ok(Self::Started),
            2 => Ok(Self::Committed),
            3 => Ok(Self::Recovered),
            _ => Err(RecoveryJournalError::Corrupt(
                "unknown recovery marker state",
            )),
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Committed => "committed",
            Self::Recovered => "recovered",
        }
    }
}

/// Strict, bounded, create-new H5-B sidecar evidence.
///
/// The frame binds one immutable H5-A journal by transaction id and journal
/// integrity hash.  It intentionally carries no grant, confirmation,
/// authorization revision, credential, raw HANDLE, or provider material.
#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryMarkerV1 {
    transaction_id: RecoveryTransactionId,
    journal_integrity_hash: [u8; 32],
    marker_state: RecoveryMarkerState,
    created_at_unix_ms: u64,
    marker_integrity_hash: [u8; 32],
}

impl fmt::Debug for RecoveryMarkerV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryMarkerV1")
            .field("transaction_id", &self.transaction_id)
            .field(
                "journal_integrity_hash",
                &hex_encode(&self.journal_integrity_hash),
            )
            .field("marker_state", &self.marker_state)
            .field("created_at_unix_ms", &self.created_at_unix_ms)
            .field(
                "marker_integrity_hash",
                &hex_encode(&self.marker_integrity_hash),
            )
            .finish()
    }
}

impl RecoveryMarkerV1 {
    pub(crate) fn new(
        transaction_id: RecoveryTransactionId,
        journal_integrity_hash: [u8; 32],
        marker_state: RecoveryMarkerState,
    ) -> Self {
        let created_at_unix_ms = current_unix_millis();
        let payload = marker_payload(
            &transaction_id,
            journal_integrity_hash,
            marker_state,
            created_at_unix_ms,
        )
        .expect("bounded local H5-B marker facts must encode");
        Self {
            transaction_id,
            journal_integrity_hash,
            marker_state,
            created_at_unix_ms,
            marker_integrity_hash: marker_integrity_hash(&payload),
        }
    }

    pub fn transaction_id(&self) -> &RecoveryTransactionId {
        &self.transaction_id
    }

    pub fn journal_integrity_hash(&self) -> String {
        hex_encode(&self.journal_integrity_hash)
    }

    pub fn marker_state(&self) -> RecoveryMarkerState {
        self.marker_state
    }

    pub fn created_at_unix_ms(&self) -> u64 {
        self.created_at_unix_ms
    }

    pub fn marker_integrity_hash(&self) -> String {
        hex_encode(&self.marker_integrity_hash)
    }

    fn journal_integrity_hash_bytes(&self) -> [u8; 32] {
        self.journal_integrity_hash
    }

    fn file_name(&self) -> String {
        marker_file_name(&self.transaction_id, self.marker_state)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, RecoveryJournalError> {
        let payload = marker_payload(
            &self.transaction_id,
            self.journal_integrity_hash,
            self.marker_state,
            self.created_at_unix_ms,
        )?;
        let expected_integrity = marker_integrity_hash(&payload);
        if expected_integrity != self.marker_integrity_hash {
            return Err(RecoveryJournalError::Corrupt(
                "marker integrity does not match canonical facts",
            ));
        }
        let payload_length =
            u32::try_from(payload.len()).map_err(|_| RecoveryJournalError::Oversized {
                limit: MARKER_PAYLOAD_BYTES,
            })?;
        let mut bytes =
            Vec::with_capacity(MARKER_HEADER_BYTES + payload.len() + INTEGRITY_HASH_BYTES);
        bytes.extend_from_slice(MARKER_MAGIC);
        bytes.extend_from_slice(&RECOVERY_MARKER_FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&payload_length.to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&expected_integrity);
        if bytes.len() > RECOVERY_MARKER_MAX_SIZE {
            return Err(RecoveryJournalError::Oversized {
                limit: RECOVERY_MARKER_MAX_SIZE,
            });
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecoveryJournalError> {
        if bytes.len() > RECOVERY_MARKER_MAX_SIZE {
            return Err(RecoveryJournalError::Oversized {
                limit: RECOVERY_MARKER_MAX_SIZE,
            });
        }
        if bytes.len() < MARKER_HEADER_BYTES + INTEGRITY_HASH_BYTES {
            return Err(RecoveryJournalError::Corrupt("truncated marker frame"));
        }
        if &bytes[..MARKER_MAGIC.len()] != MARKER_MAGIC {
            return Err(RecoveryJournalError::Corrupt("invalid marker magic"));
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != RECOVERY_MARKER_FORMAT_VERSION {
            return Err(RecoveryJournalError::UnsupportedVersion(version));
        }
        let payload_length = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
        if payload_length > MARKER_PAYLOAD_BYTES {
            return Err(RecoveryJournalError::Oversized {
                limit: MARKER_PAYLOAD_BYTES,
            });
        }
        let expected_length = MARKER_HEADER_BYTES
            .checked_add(payload_length)
            .and_then(|length| length.checked_add(INTEGRITY_HASH_BYTES))
            .ok_or(RecoveryJournalError::Oversized {
                limit: RECOVERY_MARKER_MAX_SIZE,
            })?;
        if bytes.len() < expected_length {
            return Err(RecoveryJournalError::Corrupt("truncated marker payload"));
        }
        if bytes.len() > expected_length {
            return Err(RecoveryJournalError::Corrupt("extra trailing marker bytes"));
        }
        let payload = &bytes[MARKER_HEADER_BYTES..MARKER_HEADER_BYTES + payload_length];
        let stored_integrity = &bytes[MARKER_HEADER_BYTES + payload_length..];
        let expected_integrity = marker_integrity_hash(payload);
        if stored_integrity != expected_integrity {
            return Err(RecoveryJournalError::Corrupt(
                "marker integrity hash mismatch",
            ));
        }
        let mut cursor = Cursor::new(payload);
        let transaction_text =
            cursor.string("marker_transaction_id", MAX_TRANSACTION_ID_BYTES, true)?;
        let transaction_id = RecoveryTransactionId::parse(&transaction_text)?;
        let journal_integrity_hash = cursor.hash("marker_journal_integrity_hash")?;
        let marker_state = RecoveryMarkerState::decode(cursor.u8("marker_state")?)?;
        let created_at_unix_ms = cursor.u64("marker_created_at")?;
        cursor.finish()?;
        let marker_integrity_hash = array_from_slice(&expected_integrity);
        Ok(Self {
            transaction_id,
            journal_integrity_hash,
            marker_state,
            created_at_unix_ms,
            marker_integrity_hash,
        })
    }
}

fn marker_payload(
    transaction_id: &RecoveryTransactionId,
    journal_integrity_hash: [u8; 32],
    marker_state: RecoveryMarkerState,
    created_at_unix_ms: u64,
) -> Result<Vec<u8>, RecoveryJournalError> {
    let mut payload = Vec::new();
    put_string(
        &mut payload,
        "marker_transaction_id",
        transaction_id.as_str(),
        MAX_TRANSACTION_ID_BYTES,
        true,
    )?;
    payload.extend_from_slice(&journal_integrity_hash);
    payload.push(marker_state.encode());
    payload.extend_from_slice(&created_at_unix_ms.to_le_bytes());
    if payload.len() > MARKER_PAYLOAD_BYTES {
        return Err(RecoveryJournalError::Oversized {
            limit: MARKER_PAYLOAD_BYTES,
        });
    }
    Ok(payload)
}

fn marker_integrity_hash(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(MARKER_DOMAIN_SEPARATOR);
    hasher.update(MARKER_MAGIC);
    hasher.update(RECOVERY_MARKER_FORMAT_VERSION.to_le_bytes());
    hasher.update((payload.len() as u32).to_le_bytes());
    hasher.update(payload);
    array_from_slice(&hasher.finalize())
}

/// Trusted transaction facts supplied by the host-side integration seam.
///
/// The context intentionally has no confirmation, grant, authorization,
/// credential, HANDLE, journal path, or replacement content field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryJournalContext {
    life_id: String,
    task_id: String,
    capability_id: String,
    replacement_sha256: [u8; 32],
    replacement_bytes: u32,
    tool_call_id: String,
    turn_id: String,
    created_at_unix_ms: u64,
}

impl RecoveryJournalContext {
    pub fn new(
        life_id: &str,
        task_id: &str,
        capability_id: &str,
        replacement_sha256: &str,
        replacement_bytes: usize,
        tool_call_id: &str,
        turn_id: &str,
    ) -> Result<Self, RecoveryJournalError> {
        Ok(Self {
            life_id: bounded_context_text("life_id", life_id)?,
            task_id: bounded_context_text("task_id", task_id)?,
            capability_id: bounded_context_text("capability_id", capability_id)?,
            replacement_sha256: decode_sha256_hex("replacement_sha256", replacement_sha256)?,
            replacement_bytes: bounded_bytes("replacement_bytes", replacement_bytes)?,
            tool_call_id: bounded_context_text("tool_call_id", tool_call_id)?,
            turn_id: bounded_context_text("turn_id", turn_id)?,
            created_at_unix_ms: current_unix_millis(),
        })
    }

    pub fn life_id(&self) -> &str {
        &self.life_id
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub fn replacement_sha256(&self) -> String {
        hex_encode(&self.replacement_sha256)
    }

    pub fn replacement_bytes(&self) -> usize {
        self.replacement_bytes as usize
    }

    pub fn tool_call_id(&self) -> &str {
        &self.tool_call_id
    }

    pub fn turn_id(&self) -> &str {
        &self.turn_id
    }
}

/// Extensible record state.  H5-A writes only `Prepared`; later states are
/// decoded so a restart scanner can remain forward-compatible without
/// treating an unknown state as safe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryJournalRecordState {
    Prepared,
    MutationStarted,
    Committed,
    RecoveryRequired,
    Recovered,
    Finalized,
}

impl RecoveryJournalRecordState {
    fn encode(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::MutationStarted => 2,
            Self::Committed => 3,
            Self::RecoveryRequired => 4,
            Self::Recovered => 5,
            Self::Finalized => 6,
        }
    }

    fn decode(value: u8) -> Result<Self, RecoveryJournalError> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::MutationStarted),
            3 => Ok(Self::Committed),
            4 => Ok(Self::RecoveryRequired),
            5 => Ok(Self::Recovered),
            6 => Ok(Self::Finalized),
            _ => Err(RecoveryJournalError::Corrupt("unknown record state")),
        }
    }
}

/// One complete H5-A record.  It is evidence, never an authority object.
#[derive(Clone, Eq, PartialEq)]
pub struct RecoveryJournalV1 {
    transaction_id: RecoveryTransactionId,
    life_id: String,
    task_id: String,
    capability_id: String,
    workspace_root_identity: RecoveryJournalIdentity,
    relative_path: WorkspaceRelativePath,
    target_identity: RecoveryJournalIdentity,
    before_sha256: [u8; 32],
    before_bytes: u32,
    before_content: String,
    replacement_sha256: [u8; 32],
    replacement_bytes: u32,
    tool_call_id: String,
    turn_id: String,
    created_at_unix_ms: u64,
    record_state: RecoveryJournalRecordState,
    integrity_hash: [u8; 32],
}

impl fmt::Debug for RecoveryJournalV1 {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryJournalV1")
            .field("transaction_id", &self.transaction_id)
            .field("life_id", &self.life_id)
            .field("task_id", &self.task_id)
            .field("capability_id", &self.capability_id)
            .field("workspace_root_identity", &self.workspace_root_identity)
            .field("relative_path", &self.relative_path)
            .field("target_identity", &self.target_identity)
            .field("before_sha256", &hex_encode(&self.before_sha256))
            .field("before_bytes", &self.before_bytes)
            .field("before_content_present", &true)
            .field("replacement_sha256", &hex_encode(&self.replacement_sha256))
            .field("replacement_bytes", &self.replacement_bytes)
            .field("tool_call_id", &self.tool_call_id)
            .field("turn_id", &self.turn_id)
            .field("created_at_unix_ms", &self.created_at_unix_ms)
            .field("record_state", &self.record_state)
            .field("integrity_hash", &hex_encode(&self.integrity_hash))
            .finish()
    }
}

impl RecoveryJournalV1 {
    pub fn transaction_id(&self) -> &RecoveryTransactionId {
        &self.transaction_id
    }

    pub fn life_id(&self) -> &str {
        &self.life_id
    }

    pub fn task_id(&self) -> &str {
        &self.task_id
    }

    pub fn capability_id(&self) -> &str {
        &self.capability_id
    }

    pub fn workspace_root_identity(&self) -> RecoveryJournalIdentity {
        self.workspace_root_identity
    }

    pub fn relative_path(&self) -> &WorkspaceRelativePath {
        &self.relative_path
    }

    pub fn target_identity(&self) -> RecoveryJournalIdentity {
        self.target_identity
    }

    pub fn before_sha256(&self) -> String {
        hex_encode(&self.before_sha256)
    }

    fn before_sha256_bytes(&self) -> [u8; 32] {
        self.before_sha256
    }

    pub fn before_bytes(&self) -> usize {
        self.before_bytes as usize
    }

    pub fn before_content(&self) -> &str {
        &self.before_content
    }

    pub fn replacement_sha256(&self) -> String {
        hex_encode(&self.replacement_sha256)
    }

    fn replacement_sha256_bytes(&self) -> [u8; 32] {
        self.replacement_sha256
    }

    pub fn replacement_bytes(&self) -> usize {
        self.replacement_bytes as usize
    }

    pub fn tool_call_id(&self) -> &str {
        &self.tool_call_id
    }

    pub fn turn_id(&self) -> &str {
        &self.turn_id
    }

    pub fn created_at_unix_ms(&self) -> u64 {
        self.created_at_unix_ms
    }

    pub fn record_state(&self) -> RecoveryJournalRecordState {
        self.record_state
    }

    pub fn integrity_hash(&self) -> String {
        hex_encode(&self.integrity_hash)
    }

    pub(crate) fn integrity_hash_bytes(&self) -> [u8; 32] {
        self.integrity_hash
    }

    /// Serializes the strict canonical frame.  It contains no replacement
    /// content and cannot create or modify a filesystem object.
    pub fn to_bytes(&self) -> Result<Vec<u8>, RecoveryJournalError> {
        if self.before_bytes as usize != self.before_content.len() {
            return Err(RecoveryJournalError::Corrupt(
                "record preimage length does not match before_bytes",
            ));
        }
        if digest(self.before_content.as_bytes()) != self.before_sha256 {
            return Err(RecoveryJournalError::Corrupt(
                "record preimage hash does not match before_content",
            ));
        }
        let payload = self.canonical_payload()?;
        let integrity_hash = integrity_hash(&payload);
        if integrity_hash != self.integrity_hash {
            return Err(RecoveryJournalError::Corrupt(
                "record integrity does not match canonical facts",
            ));
        }
        let payload_length =
            u32::try_from(payload.len()).map_err(|_| RecoveryJournalError::Oversized {
                limit: MAX_PAYLOAD_BYTES,
            })?;
        let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len() + INTEGRITY_HASH_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&RECOVERY_JOURNAL_FORMAT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&payload_length.to_le_bytes());
        bytes.extend_from_slice(&payload);
        bytes.extend_from_slice(&integrity_hash);
        if bytes.len() > RECOVERY_JOURNAL_MAX_SIZE {
            return Err(RecoveryJournalError::Oversized {
                limit: RECOVERY_JOURNAL_MAX_SIZE,
            });
        }
        Ok(bytes)
    }

    /// Parses and verifies one complete frame without any filesystem side
    /// effect.  Truncation, unknown versions, extra bytes, unknown states,
    /// oversized lengths, and digest mismatches all fail closed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RecoveryJournalError> {
        if bytes.len() > RECOVERY_JOURNAL_MAX_SIZE {
            return Err(RecoveryJournalError::Oversized {
                limit: RECOVERY_JOURNAL_MAX_SIZE,
            });
        }
        if bytes.len() < HEADER_BYTES + INTEGRITY_HASH_BYTES {
            return Err(RecoveryJournalError::Corrupt("truncated journal frame"));
        }
        if &bytes[..MAGIC.len()] != MAGIC {
            return Err(RecoveryJournalError::Corrupt("invalid journal magic"));
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != RECOVERY_JOURNAL_FORMAT_VERSION {
            return Err(RecoveryJournalError::UnsupportedVersion(version));
        }
        let payload_length = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]) as usize;
        if payload_length > MAX_PAYLOAD_BYTES {
            return Err(RecoveryJournalError::Oversized {
                limit: MAX_PAYLOAD_BYTES,
            });
        }
        let expected_length = HEADER_BYTES
            .checked_add(payload_length)
            .and_then(|length| length.checked_add(INTEGRITY_HASH_BYTES))
            .ok_or(RecoveryJournalError::Oversized {
                limit: RECOVERY_JOURNAL_MAX_SIZE,
            })?;
        if bytes.len() < expected_length {
            return Err(RecoveryJournalError::Corrupt("truncated journal payload"));
        }
        if bytes.len() > expected_length {
            return Err(RecoveryJournalError::Corrupt(
                "extra trailing journal bytes",
            ));
        }
        let payload = &bytes[HEADER_BYTES..HEADER_BYTES + payload_length];
        let stored_integrity = &bytes[HEADER_BYTES + payload_length..];
        let expected_integrity = integrity_hash(payload);
        if stored_integrity != expected_integrity {
            return Err(RecoveryJournalError::Corrupt("integrity hash mismatch"));
        }
        let mut cursor = Cursor::new(payload);
        let transaction_text = cursor.string("transaction_id", MAX_TRANSACTION_ID_BYTES, true)?;
        let transaction_id = RecoveryTransactionId::parse(&transaction_text)?;
        let life_id = cursor.string("life_id", MAX_CONTEXT_FIELD_BYTES, true)?;
        let task_id = cursor.string("task_id", MAX_CONTEXT_FIELD_BYTES, true)?;
        let capability_id = cursor.string("capability_id", MAX_CONTEXT_FIELD_BYTES, true)?;
        let workspace_root_identity = cursor.identity("workspace_root_identity")?;
        let relative_text = cursor.string("relative_path", MAX_RELATIVE_PATH_BYTES, true)?;
        let relative_path =
            WorkspaceRelativePath::parse(Path::new(&relative_text)).map_err(|_| {
                RecoveryJournalError::InvalidField {
                    field: "relative_path",
                    reason: "not a valid H4 relative path",
                }
            })?;
        let canonical_relative = canonical_relative_path(&relative_path)?;
        if canonical_relative != relative_text {
            return Err(RecoveryJournalError::Corrupt(
                "relative path is not canonical",
            ));
        }
        let target_identity = cursor.identity("target_identity")?;
        let before_sha256 = cursor.hash("before_sha256")?;
        let before_bytes = cursor.u32("before_bytes")?;
        if before_bytes as usize > RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES {
            return Err(RecoveryJournalError::Oversized {
                limit: RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES,
            });
        }
        let before_content_bytes =
            cursor.bytes("before_content", RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES)?;
        if before_content_bytes.len() != before_bytes as usize {
            return Err(RecoveryJournalError::Corrupt(
                "before byte count does not match preimage",
            ));
        }
        let before_content = String::from_utf8(before_content_bytes.to_vec())
            .map_err(|_| RecoveryJournalError::Corrupt("preimage is not valid UTF-8"))?;
        let replacement_sha256 = cursor.hash("replacement_sha256")?;
        let replacement_bytes = cursor.u32("replacement_bytes")?;
        if replacement_bytes as usize > RECOVERY_JOURNAL_MAX_REPLACEMENT_BYTES {
            return Err(RecoveryJournalError::Oversized {
                limit: RECOVERY_JOURNAL_MAX_REPLACEMENT_BYTES,
            });
        }
        let tool_call_id = cursor.string("tool_call_id", MAX_CONTEXT_FIELD_BYTES, true)?;
        let turn_id = cursor.string("turn_id", MAX_CONTEXT_FIELD_BYTES, true)?;
        let created_at_unix_ms = cursor.u64("created_at_unix_ms")?;
        let record_state = RecoveryJournalRecordState::decode(cursor.u8("record_state")?)?;
        cursor.finish()?;
        if digest(before_content.as_bytes()) != before_sha256 {
            return Err(RecoveryJournalError::Corrupt(
                "preimage hash does not match preimage bytes",
            ));
        }
        let integrity_hash = array_from_slice(&expected_integrity);
        Ok(Self {
            transaction_id,
            life_id,
            task_id,
            capability_id,
            workspace_root_identity,
            relative_path,
            target_identity,
            before_sha256,
            before_bytes,
            before_content,
            replacement_sha256,
            replacement_bytes,
            tool_call_id,
            turn_id,
            created_at_unix_ms,
            record_state,
            integrity_hash,
        })
    }

    fn from_preimage(
        transaction_id: RecoveryTransactionId,
        target: &PreparedWorkspaceTarget,
        context: RecoveryJournalContext,
        before_content: String,
    ) -> Result<Self, RecoveryJournalError> {
        let workspace_root_identity =
            RecoveryJournalIdentity::from_workspace_identity(target.root().identity())?;
        let target_identity = target
            .target_identity()
            .ok_or(RecoveryJournalError::TargetBindingMismatch(
                "target identity is unavailable",
            ))
            .and_then(RecoveryJournalIdentity::from_workspace_identity)?;
        let relative_path = canonical_relative_path_object(target.relative_path())?;
        let before_bytes = bounded_bytes("before_bytes", before_content.len())?;
        let before_sha256 = digest(before_content.as_bytes());
        let mut record = Self {
            transaction_id,
            life_id: context.life_id,
            task_id: context.task_id,
            capability_id: context.capability_id,
            workspace_root_identity,
            relative_path,
            target_identity,
            before_sha256,
            before_bytes,
            before_content,
            replacement_sha256: context.replacement_sha256,
            replacement_bytes: context.replacement_bytes,
            tool_call_id: context.tool_call_id,
            turn_id: context.turn_id,
            created_at_unix_ms: context.created_at_unix_ms,
            record_state: RecoveryJournalRecordState::Prepared,
            integrity_hash: [0; 32],
        };
        record.integrity_hash = integrity_hash(&record.canonical_payload()?);
        Ok(record)
    }

    fn canonical_payload(&self) -> Result<Vec<u8>, RecoveryJournalError> {
        let relative_path = canonical_relative_path(&self.relative_path)?;
        let mut payload = Vec::new();
        put_string(
            &mut payload,
            "transaction_id",
            self.transaction_id.as_str(),
            MAX_TRANSACTION_ID_BYTES,
            true,
        )?;
        put_string(
            &mut payload,
            "life_id",
            &self.life_id,
            MAX_CONTEXT_FIELD_BYTES,
            true,
        )?;
        put_string(
            &mut payload,
            "task_id",
            &self.task_id,
            MAX_CONTEXT_FIELD_BYTES,
            true,
        )?;
        put_string(
            &mut payload,
            "capability_id",
            &self.capability_id,
            MAX_CONTEXT_FIELD_BYTES,
            true,
        )?;
        put_identity(&mut payload, self.workspace_root_identity);
        put_string(
            &mut payload,
            "relative_path",
            &relative_path,
            MAX_RELATIVE_PATH_BYTES,
            true,
        )?;
        put_identity(&mut payload, self.target_identity);
        payload.extend_from_slice(&self.before_sha256);
        put_u32(&mut payload, self.before_bytes);
        put_bytes(
            &mut payload,
            "before_content",
            self.before_content.as_bytes(),
            RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES,
        )?;
        payload.extend_from_slice(&self.replacement_sha256);
        put_u32(&mut payload, self.replacement_bytes);
        put_string(
            &mut payload,
            "tool_call_id",
            &self.tool_call_id,
            MAX_CONTEXT_FIELD_BYTES,
            true,
        )?;
        put_string(
            &mut payload,
            "turn_id",
            &self.turn_id,
            MAX_CONTEXT_FIELD_BYTES,
            true,
        )?;
        payload.extend_from_slice(&self.created_at_unix_ms.to_le_bytes());
        payload.push(self.record_state.encode());
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(RecoveryJournalError::Oversized {
                limit: MAX_PAYLOAD_BYTES,
            });
        }
        Ok(payload)
    }
}

/// Canonical duplicate-detection key for one target.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RecoveryJournalTargetKey {
    workspace_root_identity: RecoveryJournalIdentity,
    relative_path: String,
    target_identity: RecoveryJournalIdentity,
}

impl RecoveryJournalTargetKey {
    pub fn workspace_root_identity(&self) -> RecoveryJournalIdentity {
        self.workspace_root_identity
    }

    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    pub fn target_identity(&self) -> RecoveryJournalIdentity {
        self.target_identity
    }
}

/// Operational identity for one mutable filesystem object.  Unlike the
/// journal/evidence key above, this key deliberately excludes the spelling of
/// the relative path so case aliases, renamed aliases, and hard-link aliases
/// arbitrate the same underlying target.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RecoveryMutationTargetKey {
    workspace_root_identity: RecoveryJournalIdentity,
    target_identity: RecoveryJournalIdentity,
}

impl RecoveryMutationTargetKey {
    pub fn workspace_root_identity(&self) -> RecoveryJournalIdentity {
        self.workspace_root_identity
    }

    pub fn target_identity(&self) -> RecoveryJournalIdentity {
        self.target_identity
    }
}

/// Read-only restart classification.  No scanner item authorizes recovery or
/// deletes a journal/workspace file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryJournalScanItem {
    ValidPreparedJournal(RecoveryJournalV1),
    KnownNonPreparedJournal(RecoveryJournalV1),
    CorruptJournal {
        file_name: String,
        reason: &'static str,
    },
    UnsupportedVersion {
        file_name: String,
        version: u16,
    },
    AmbiguousPendingRecovery {
        target: RecoveryJournalTargetKey,
        transactions: Vec<RecoveryTransactionId>,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveryJournalScan {
    items: Vec<RecoveryJournalScanItem>,
}

impl RecoveryJournalScan {
    pub fn items(&self) -> &[RecoveryJournalScanItem] {
        &self.items
    }

    pub fn valid_prepared_journals(&self) -> impl Iterator<Item = &RecoveryJournalV1> {
        self.items.iter().filter_map(|item| match item {
            RecoveryJournalScanItem::ValidPreparedJournal(journal) => Some(journal),
            _ => None,
        })
    }

    /// Returns only unambiguous Prepared evidence.  A target with more than
    /// one pending transaction is represented solely by
    /// `AmbiguousPendingRecovery` and never appears in this iterator.
    pub fn actionable_prepared_journals(&self) -> impl Iterator<Item = &RecoveryJournalV1> {
        self.valid_prepared_journals()
    }

    pub fn has_ambiguous_pending_recovery(&self) -> bool {
        self.items.iter().any(|item| {
            matches!(
                item,
                RecoveryJournalScanItem::AmbiguousPendingRecovery { .. }
            )
        })
    }

    pub fn ambiguous_pending_recoveries(
        &self,
    ) -> impl Iterator<Item = (&RecoveryJournalTargetKey, &[RecoveryTransactionId])> {
        self.items.iter().filter_map(|item| match item {
            RecoveryJournalScanItem::AmbiguousPendingRecovery {
                target,
                transactions,
            } => Some((target, transactions.as_slice())),
            _ => None,
        })
    }
}

/// The only four legal persistent H5-B transaction states.  The state is
/// derived from one valid immutable journal and its validated marker set; it
/// is never selected from current workspace bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryTransactionState {
    PreparedOnly,
    RecoveryRequired,
    CommittedTerminal,
    RecoveredTerminal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryTransactionSnapshot {
    journal: RecoveryJournalV1,
    started: Option<RecoveryMarkerV1>,
    committed: Option<RecoveryMarkerV1>,
    recovered: Option<RecoveryMarkerV1>,
    state: RecoveryTransactionState,
}

impl RecoveryTransactionSnapshot {
    pub fn journal(&self) -> &RecoveryJournalV1 {
        &self.journal
    }

    pub fn started(&self) -> Option<&RecoveryMarkerV1> {
        self.started.as_ref()
    }

    pub fn committed(&self) -> Option<&RecoveryMarkerV1> {
        self.committed.as_ref()
    }

    pub fn recovered(&self) -> Option<&RecoveryMarkerV1> {
        self.recovered.as_ref()
    }

    pub fn state(&self) -> RecoveryTransactionState {
        self.state
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryTransactionScanItem {
    Valid(RecoveryTransactionSnapshot),
    AmbiguousTarget {
        target: RecoveryMutationTargetKey,
        transactions: Vec<RecoveryTransactionId>,
    },
    PoisonedTarget {
        target: RecoveryMutationTargetKey,
        transactions: Vec<RecoveryTransactionId>,
        reason: &'static str,
    },
    CorruptArtifact {
        file_name: String,
        reason: &'static str,
    },
    OrphanedRecoveryMarker {
        file_name: String,
        transaction_id: RecoveryTransactionId,
        marker_state: RecoveryMarkerState,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryTargetLifecycle {
    Clear,
    RecoveryRequired,
    Ambiguous,
    Poisoned,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RecoveryTransactionScan {
    items: Vec<RecoveryTransactionScanItem>,
}

impl RecoveryTransactionScan {
    pub fn items(&self) -> &[RecoveryTransactionScanItem] {
        &self.items
    }

    pub fn valid_transactions(&self) -> impl Iterator<Item = &RecoveryTransactionSnapshot> {
        self.items.iter().filter_map(|item| match item {
            RecoveryTransactionScanItem::Valid(snapshot) => Some(snapshot),
            _ => None,
        })
    }

    pub fn actionable_recovery_transactions(
        &self,
    ) -> impl Iterator<Item = &RecoveryTransactionSnapshot> {
        self.valid_transactions().filter(|snapshot| {
            snapshot.state == RecoveryTransactionState::RecoveryRequired
                && self.target_lifecycle(&mutation_target_key(snapshot.journal()))
                    == RecoveryTargetLifecycle::RecoveryRequired
        })
    }

    pub fn has_ambiguous_target(&self) -> bool {
        self.items
            .iter()
            .any(|item| matches!(item, RecoveryTransactionScanItem::AmbiguousTarget { .. }))
    }

    pub fn target_lifecycle(&self, target: &RecoveryMutationTargetKey) -> RecoveryTargetLifecycle {
        self.target_lifecycle_excluding(target, None)
    }

    #[cfg(test)]
    pub(crate) fn target_lifecycle_for_journal(
        &self,
        journal: &RecoveryJournalV1,
    ) -> RecoveryTargetLifecycle {
        self.target_lifecycle(&mutation_target_key(journal))
    }

    pub(crate) fn target_lifecycle_excluding(
        &self,
        target: &RecoveryMutationTargetKey,
        excluded_transaction: Option<&RecoveryTransactionId>,
    ) -> RecoveryTargetLifecycle {
        if self.items.iter().any(|item| {
            matches!(
                item,
                RecoveryTransactionScanItem::PoisonedTarget {
                    target: item_target,
                    transactions,
                    ..
                } if item_target == target
                    && transactions.iter().any(|transaction_id| {
                        Some(transaction_id) != excluded_transaction
                    })
            )
        }) {
            return RecoveryTargetLifecycle::Poisoned;
        }

        if self.items.iter().any(|item| {
            matches!(
                item,
                RecoveryTransactionScanItem::AmbiguousTarget {
                    target: item_target,
                    transactions,
                } if item_target == target
                    && transactions.iter().any(|transaction_id| {
                        Some(transaction_id) != excluded_transaction
                    })
            )
        }) {
            return RecoveryTargetLifecycle::Ambiguous;
        }

        let recovery_required = self
            .valid_transactions()
            .filter(|snapshot| {
                mutation_target_key(snapshot.journal()) == *target
                    && snapshot.state() == RecoveryTransactionState::RecoveryRequired
                    && Some(snapshot.journal().transaction_id()) != excluded_transaction
            })
            .count();
        match recovery_required {
            0 => RecoveryTargetLifecycle::Clear,
            1 => RecoveryTargetLifecycle::RecoveryRequired,
            _ => RecoveryTargetLifecycle::Ambiguous,
        }
    }

    pub fn poisoned_targets(
        &self,
    ) -> impl Iterator<Item = (&RecoveryMutationTargetKey, &[RecoveryTransactionId])> {
        self.items.iter().filter_map(|item| match item {
            RecoveryTransactionScanItem::PoisonedTarget {
                target,
                transactions,
                ..
            } => Some((target, transactions.as_slice())),
            _ => None,
        })
    }
}

/// Current-state reconciliation is deliberately read-only and contains no
/// recovery action.  `AlreadyReplacement` is evidence only; it does not mark
/// a journal finalized, and no reconciliation result is recovery
/// authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryJournalReconciliation {
    StillBefore,
    AlreadyReplacement,
    Diverged,
    TargetMissing,
    TargetIdentityChanged,
}

/// A process-local capability to the one fixed Vita-owned recovery
/// namespace.  This is namespace authority only: it is not D28 authority,
/// does not contain a capability grant or confirmation, and cannot authorize
/// workspace recovery.
#[derive(Clone)]
pub struct RecoveryJournalRootAuthority {
    namespace: AppOwnedRecoveryNamespace,
}

impl fmt::Debug for RecoveryJournalRootAuthority {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryJournalRootAuthority")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl RecoveryJournalRootAuthority {
    fn acquire(profile: &VitaAgentRuntimeProfile) -> Result<Self, RecoveryJournalError> {
        profile
            .validate_private_namespace()
            .map_err(RecoveryJournalError::Profile)?;
        profile
            .verify_private_runtime_ownership()
            .map_err(RecoveryJournalError::Profile)?;

        #[cfg(windows)]
        {
            let namespace =
                AppOwnedRecoveryNamespace::acquire_vita_recovery_namespace(profile.vita_root())
                    .map_err(RecoveryJournalError::Profile)?;
            return Ok(Self { namespace });
        }
        #[cfg(not(windows))]
        {
            let _ = profile;
            Err(RecoveryJournalError::UnsupportedPlatform)
        }
    }

    fn create_new_file(
        &self,
        transaction_id: &RecoveryTransactionId,
        bytes: &[u8],
    ) -> Result<(), RecoveryJournalError> {
        let name = journal_file_name(transaction_id);
        #[cfg(windows)]
        {
            return self
                .namespace
                .create_new_journal(OsStr::new(&name), bytes)
                .map_err(|error| {
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        RecoveryJournalError::DuplicateTransactionId
                    } else {
                        io_error("create-new journal", error)
                    }
                });
        }
        #[cfg(not(windows))]
        {
            let _ = (transaction_id, bytes);
            Err(RecoveryJournalError::UnsupportedPlatform)
        }
    }

    fn create_new_marker(
        &self,
        marker: &RecoveryMarkerV1,
        bytes: &[u8],
    ) -> Result<(), RecoveryJournalError> {
        let name = marker.file_name();
        #[cfg(windows)]
        {
            return self
                .namespace
                .create_new_marker(OsStr::new(&name), bytes)
                .map_err(|error| {
                    if error.kind() == io::ErrorKind::AlreadyExists {
                        RecoveryJournalError::DuplicateTransactionId
                    } else {
                        io_error("create-new recovery marker", error)
                    }
                });
        }
        #[cfg(not(windows))]
        {
            let _ = (marker, bytes);
            Err(RecoveryJournalError::UnsupportedPlatform)
        }
    }

    fn read_file(&self, file_name: &OsStr) -> Result<Vec<u8>, RecoveryJournalError> {
        #[cfg(windows)]
        {
            return self
                .namespace
                .read_journal(file_name, RECOVERY_JOURNAL_MAX_SIZE)
                .map_err(|error| io_error("open/read journal", error));
        }
        #[cfg(not(windows))]
        {
            let _ = file_name;
            Err(RecoveryJournalError::UnsupportedPlatform)
        }
    }

    fn read_marker_file(&self, file_name: &OsStr) -> Result<Vec<u8>, RecoveryJournalError> {
        #[cfg(windows)]
        {
            return self
                .namespace
                .read_marker(file_name, RECOVERY_MARKER_MAX_SIZE)
                .map_err(|error| io_error("open/read recovery marker", error));
        }
        #[cfg(not(windows))]
        {
            let _ = file_name;
            Err(RecoveryJournalError::UnsupportedPlatform)
        }
    }

    fn enumerate(&self) -> Result<Vec<std::ffi::OsString>, RecoveryJournalError> {
        #[cfg(windows)]
        {
            return self
                .namespace
                .enumerate_journals()
                .map_err(|error| io_error("enumerate recovery root", error));
        }
        #[cfg(not(windows))]
        {
            Err(RecoveryJournalError::UnsupportedPlatform)
        }
    }
}

/// App-owned recovery journal store.  Its root is derived exclusively from an
/// explicit Vita runtime profile; there is no constructor accepting a model
/// path, transaction path, cwd, TEMP, `.codex`, or arbitrary environment.
#[derive(Clone)]
pub struct RecoveryJournalStore {
    profile: VitaAgentRuntimeProfile,
    recovery_root: PathBuf,
    namespace_authority: RecoveryJournalRootAuthority,
    workspace_root_identity: Option<RecoveryJournalIdentity>,
}

impl fmt::Debug for RecoveryJournalStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryJournalStore")
            .field("recovery_root", &self.recovery_root)
            .field("workspace_root_identity", &self.workspace_root_identity)
            .finish_non_exhaustive()
    }
}

impl RecoveryJournalStore {
    /// Binds the store to `%LOCALAPPDATA%\DigitalLife\agent\recovery` (or
    /// the equivalent explicit app-data root supplied by tests).  The path is
    /// derived from `VitaAgentRuntimeProfile`; callers cannot provide it.
    pub fn from_runtime_profile(
        profile: &VitaAgentRuntimeProfile,
    ) -> Result<Self, RecoveryJournalError> {
        profile
            .validate_private_namespace()
            .map_err(RecoveryJournalError::Profile)?;
        let namespace_authority = RecoveryJournalRootAuthority::acquire(profile)?;
        let workspace_root_identity = profile
            .workspace_authority()
            .map(|root| RecoveryJournalIdentity::from_workspace_identity(root.identity()))
            .transpose()?;
        let recovery_root = profile.vita_root().join(RECOVERY_DIRECTORY_NAME);
        if recovery_root.parent() != Some(profile.vita_root())
            || recovery_root.file_name().and_then(|name| name.to_str())
                != Some(RECOVERY_DIRECTORY_NAME)
        {
            return Err(RecoveryJournalError::TargetBindingMismatch(
                "recovery root is not the fixed Vita-owned child",
            ));
        }
        Ok(Self {
            profile: profile.clone(),
            recovery_root,
            namespace_authority,
            workspace_root_identity,
        })
    }

    pub fn recovery_root(&self) -> &Path {
        &self.recovery_root
    }

    pub fn expected_workspace_root_identity(&self) -> Option<RecoveryJournalIdentity> {
        self.workspace_root_identity
    }

    /// Captures the actual H4-prepared existing-file preimage and writes only
    /// a `Prepared` evidence record.  The transaction identity and journal
    /// path are generated internally.
    pub fn create_prepared(
        &self,
        target: &PreparedWorkspaceTarget,
        context: RecoveryJournalContext,
    ) -> Result<RecoveryJournalV1, RecoveryJournalError> {
        self.create_prepared_internal(target, context, RecoveryTransactionId::generate())
    }

    /// Captures and persists a Prepared record only when the exact bounded
    /// preimage is the same content state that H4 is authorized to replace.
    /// The expected SHA is validated before any journal create-new operation.
    pub(crate) fn create_prepared_for_expected_preimage(
        &self,
        target: &PreparedWorkspaceTarget,
        context: RecoveryJournalContext,
        expected_sha256: &str,
    ) -> Result<RecoveryJournalV1, RecoveryJournalError> {
        self.create_prepared_for_expected_preimage_internal(
            target,
            context,
            RecoveryTransactionId::generate(),
            expected_sha256,
        )
    }

    /// Performs a read-only restart scan of the fixed app-owned directory.
    /// Missing directories are treated as an empty scan; no directory or file
    /// is created, removed, retried, or modified by this method.
    pub fn scan(&self) -> Result<RecoveryJournalScan, RecoveryJournalError> {
        self.validate_scan_root()?;
        self.profile
            .verify_private_runtime_ownership()
            .map_err(RecoveryJournalError::Profile)?;
        let mut items = Vec::new();
        let entries = self.namespace_authority.enumerate()?;
        let mut entry_count = 0usize;
        for file_name in entries {
            entry_count += 1;
            if entry_count > MAX_SCAN_ENTRIES {
                return Err(RecoveryJournalError::ScanLimitExceeded);
            }
            if Path::new(&file_name)
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("dlrj")
            {
                continue;
            }
            let display_name = file_name
                .to_str()
                .map(|name| name.chars().take(MAX_FILE_NAME_CHARS).collect::<String>())
                .unwrap_or_else(|| "<non-utf8-file-name>".to_string());
            let transaction_id = match file_name
                .to_str()
                .and_then(|name| name.strip_suffix(".dlrj"))
                .map(RecoveryTransactionId::parse)
            {
                Some(Ok(transaction_id)) => transaction_id,
                _ => {
                    items.push(RecoveryJournalScanItem::CorruptJournal {
                        file_name: display_name,
                        reason: "invalid transaction filename",
                    });
                    continue;
                }
            };
            let bytes = match self.namespace_authority.read_file(&file_name) {
                Ok(bytes) => bytes,
                Err(error) => {
                    items.push(RecoveryJournalScanItem::CorruptJournal {
                        file_name: display_name,
                        reason: scan_error_reason(&error),
                    });
                    continue;
                }
            };
            match RecoveryJournalV1::from_bytes(&bytes) {
                Ok(journal) if journal.transaction_id() != &transaction_id => {
                    items.push(RecoveryJournalScanItem::CorruptJournal {
                        file_name: display_name,
                        reason: "filename and payload transaction ids differ",
                    });
                }
                Ok(journal) if journal.record_state() == RecoveryJournalRecordState::Prepared => {
                    items.push(RecoveryJournalScanItem::ValidPreparedJournal(journal));
                }
                Ok(journal) => {
                    items.push(RecoveryJournalScanItem::KnownNonPreparedJournal(journal));
                }
                Err(RecoveryJournalError::UnsupportedVersion(version)) => {
                    items.push(RecoveryJournalScanItem::UnsupportedVersion {
                        file_name: display_name,
                        version,
                    });
                }
                Err(error) => {
                    items.push(RecoveryJournalScanItem::CorruptJournal {
                        file_name: display_name,
                        reason: scan_error_reason(&error),
                    });
                }
            }
        }

        Ok(finalize_scan_items(items))
    }

    /// Scans the immutable H5-A journal set and H5-B sidecars as one strict
    /// transaction state machine.  Only `Valid` items are exposed to
    /// operational code; corrupt, orphaned, and ambiguous artifacts remain
    /// evidence that must be handled fail-closed.
    pub fn scan_transactions(&self) -> Result<RecoveryTransactionScan, RecoveryJournalError> {
        self.validate_scan_root()?;
        self.profile
            .verify_private_runtime_ownership()
            .map_err(RecoveryJournalError::Profile)?;

        let mut journals: HashMap<RecoveryTransactionId, RecoveryJournalV1> = HashMap::new();
        let mut markers: HashMap<RecoveryTransactionId, Vec<RecoveryMarkerV1>> = HashMap::new();
        let mut poisoned_transactions: HashSet<RecoveryTransactionId> = HashSet::new();
        let mut items = Vec::new();
        let mut entry_count = 0usize;

        for file_name in self.namespace_authority.enumerate()? {
            entry_count += 1;
            if entry_count > MAX_SCAN_ENTRIES {
                return Err(RecoveryJournalError::ScanLimitExceeded);
            }
            let Some(display_name) = file_name
                .to_str()
                .map(|name| name.chars().take(MAX_FILE_NAME_CHARS).collect::<String>())
            else {
                continue;
            };

            if let Some(transaction_text) = display_name.strip_suffix(".dlrj") {
                let transaction_id = match RecoveryTransactionId::parse(transaction_text) {
                    Ok(value) => value,
                    Err(_) => {
                        items.push(RecoveryTransactionScanItem::CorruptArtifact {
                            file_name: display_name,
                            reason: "invalid transaction filename",
                        });
                        continue;
                    }
                };
                let bytes = match self.namespace_authority.read_file(&file_name) {
                    Ok(bytes) => bytes,
                    Err(error) => {
                        items.push(RecoveryTransactionScanItem::CorruptArtifact {
                            file_name: display_name,
                            reason: scan_error_reason(&error),
                        });
                        continue;
                    }
                };
                match RecoveryJournalV1::from_bytes(&bytes) {
                    Ok(journal)
                        if journal.transaction_id() == &transaction_id
                            && journal.record_state() == RecoveryJournalRecordState::Prepared =>
                    {
                        if journals.insert(transaction_id, journal).is_some() {
                            items.push(RecoveryTransactionScanItem::CorruptArtifact {
                                file_name: display_name,
                                reason: "duplicate journal transaction record",
                            });
                        }
                    }
                    Ok(journal) if journal.transaction_id() != &transaction_id => {
                        items.push(RecoveryTransactionScanItem::CorruptArtifact {
                            file_name: display_name,
                            reason: "filename and payload transaction ids differ",
                        });
                    }
                    Ok(_) => {
                        items.push(RecoveryTransactionScanItem::CorruptArtifact {
                            file_name: display_name,
                            reason: "journal is not an immutable Prepared record",
                        });
                    }
                    Err(error) => {
                        items.push(RecoveryTransactionScanItem::CorruptArtifact {
                            file_name: display_name,
                            reason: scan_error_reason(&error),
                        });
                    }
                }
                continue;
            }

            let Some(marker_parts) = parse_marker_file_name(&display_name) else {
                continue;
            };
            let (transaction_id, marker_state) = match marker_parts {
                Ok(parts) => parts,
                Err(_) => {
                    items.push(RecoveryTransactionScanItem::CorruptArtifact {
                        file_name: display_name,
                        reason: "invalid marker transaction filename",
                    });
                    continue;
                }
            };
            let bytes = match self.namespace_authority.read_marker_file(&file_name) {
                Ok(bytes) => bytes,
                Err(error) => {
                    poisoned_transactions.insert(transaction_id.clone());
                    items.push(RecoveryTransactionScanItem::CorruptArtifact {
                        file_name: display_name,
                        reason: scan_marker_error_reason(&error),
                    });
                    continue;
                }
            };
            match RecoveryMarkerV1::from_bytes(&bytes) {
                Ok(marker)
                    if marker.transaction_id() == &transaction_id
                        && marker.marker_state() == marker_state =>
                {
                    markers.entry(transaction_id).or_default().push(marker);
                }
                Ok(_) => {
                    poisoned_transactions.insert(transaction_id.clone());
                    items.push(RecoveryTransactionScanItem::CorruptArtifact {
                        file_name: display_name,
                        reason: "marker filename and payload do not match",
                    });
                }
                Err(error) => {
                    poisoned_transactions.insert(transaction_id.clone());
                    items.push(RecoveryTransactionScanItem::CorruptArtifact {
                        file_name: display_name,
                        reason: scan_marker_error_reason(&error),
                    });
                }
            }
        }

        for (transaction_id, transaction_markers) in &markers {
            if !journals.contains_key(transaction_id) {
                for marker in transaction_markers {
                    items.push(RecoveryTransactionScanItem::OrphanedRecoveryMarker {
                        file_name: marker.file_name(),
                        transaction_id: transaction_id.clone(),
                        marker_state: marker.marker_state(),
                    });
                }
            }
        }

        let mut poisoned_targets: HashMap<RecoveryMutationTargetKey, Vec<RecoveryTransactionId>> =
            HashMap::new();
        let mut snapshots_by_target: HashMap<
            RecoveryMutationTargetKey,
            Vec<RecoveryTransactionSnapshot>,
        > = HashMap::new();

        // Build every transaction lifecycle before applying any target-level
        // ambiguity rule.  Immutable Prepared records are historical evidence;
        // only an unresolved Started lifecycle participates in active-target
        // ambiguity.
        for (transaction_id, journal) in &journals {
            if poisoned_transactions.contains(transaction_id) {
                items.push(RecoveryTransactionScanItem::CorruptArtifact {
                    file_name: journal_file_name(transaction_id),
                    reason: "transaction has corrupt lifecycle evidence",
                });
                poisoned_targets
                    .entry(mutation_target_key(journal))
                    .or_default()
                    .push(transaction_id.clone());
                continue;
            }
            let transaction_markers = markers.remove(transaction_id).unwrap_or_default();
            match build_transaction_snapshot(journal.clone(), transaction_markers) {
                Ok(snapshot) => {
                    snapshots_by_target
                        .entry(mutation_target_key(snapshot.journal()))
                        .or_default()
                        .push(snapshot);
                }
                Err(reason) => {
                    items.push(RecoveryTransactionScanItem::CorruptArtifact {
                        file_name: journal_file_name(transaction_id),
                        reason,
                    });
                    poisoned_targets
                        .entry(mutation_target_key(journal))
                        .or_default()
                        .push(transaction_id.clone());
                }
            }
        }

        for (target, mut transactions) in poisoned_targets {
            transactions.sort_by(|left, right| left.as_str().cmp(right.as_str()));
            items.push(RecoveryTransactionScanItem::PoisonedTarget {
                target,
                transactions,
                reason: "known target has poisoned lifecycle evidence",
            });
        }

        for (target, mut snapshots) in snapshots_by_target {
            snapshots.sort_by(|left, right| {
                left.journal()
                    .transaction_id()
                    .as_str()
                    .cmp(right.journal().transaction_id().as_str())
            });
            let active_transactions = snapshots
                .iter()
                .filter(|snapshot| snapshot.state() == RecoveryTransactionState::RecoveryRequired)
                .map(|snapshot| snapshot.journal().transaction_id().clone())
                .collect::<Vec<_>>();
            if active_transactions.len() > 1 {
                items.push(RecoveryTransactionScanItem::AmbiguousTarget {
                    target,
                    transactions: active_transactions,
                });
                for snapshot in snapshots {
                    if snapshot.state() != RecoveryTransactionState::RecoveryRequired {
                        items.push(RecoveryTransactionScanItem::Valid(snapshot));
                    }
                }
            } else {
                items.extend(
                    snapshots
                        .into_iter()
                        .map(RecoveryTransactionScanItem::Valid),
                );
            }
        }

        Ok(RecoveryTransactionScan { items })
    }

    /// Persists exactly one legal next marker using create-new semantics and
    /// verifies it through the retained recovery namespace before returning.
    pub(crate) fn persist_marker(
        &self,
        journal: &RecoveryJournalV1,
        marker_state: RecoveryMarkerState,
    ) -> Result<RecoveryMarkerV1, RecoveryJournalError> {
        self.persist_marker_with_test_fault(journal, marker_state, None)
    }

    #[cfg(test)]
    pub(crate) fn persist_started_with_test_fault(
        &self,
        journal: &RecoveryJournalV1,
        fault: RecoveryMarkerPersistenceTestFault,
    ) -> Result<RecoveryMarkerV1, RecoveryJournalError> {
        self.persist_marker_with_test_fault(journal, RecoveryMarkerState::Started, Some(fault))
    }

    fn persist_marker_with_test_fault(
        &self,
        journal: &RecoveryJournalV1,
        marker_state: RecoveryMarkerState,
        fault: Option<RecoveryMarkerPersistenceTestFault>,
    ) -> Result<RecoveryMarkerV1, RecoveryJournalError> {
        let scan = self.scan_transactions()?;
        let snapshot = scan
            .valid_transactions()
            .find(|candidate| candidate.journal.transaction_id() == journal.transaction_id())
            .cloned()
            .ok_or(RecoveryJournalError::TargetBindingMismatch(
                "transaction is not one unambiguous valid H5-B candidate",
            ))?;
        let target = mutation_target_key(journal);
        let other_target_lifecycle =
            scan.target_lifecycle_excluding(&target, Some(journal.transaction_id()));
        if other_target_lifecycle != RecoveryTargetLifecycle::Clear {
            return Err(RecoveryJournalError::TransactionBlocked(
                match other_target_lifecycle {
                    RecoveryTargetLifecycle::RecoveryRequired => {
                        RecoveryTransactionBlockReason::RecoveryRequired
                    }
                    RecoveryTargetLifecycle::Ambiguous => {
                        RecoveryTransactionBlockReason::AmbiguousTarget
                    }
                    RecoveryTargetLifecycle::Poisoned => {
                        RecoveryTransactionBlockReason::PoisonedTarget
                    }
                    RecoveryTargetLifecycle::Clear => unreachable!("clear lifecycle was checked"),
                },
            ));
        }
        let allowed = matches!(
            (snapshot.state, marker_state),
            (
                RecoveryTransactionState::PreparedOnly,
                RecoveryMarkerState::Started
            ) | (
                RecoveryTransactionState::RecoveryRequired,
                RecoveryMarkerState::Committed,
            ) | (
                RecoveryTransactionState::RecoveryRequired,
                RecoveryMarkerState::Recovered,
            )
        );
        if !allowed {
            return Err(RecoveryJournalError::TargetBindingMismatch(
                "recovery marker is not the legal next transaction state",
            ));
        }
        if snapshot.journal != *journal {
            return Err(RecoveryJournalError::TargetBindingMismatch(
                "marker journal binding does not match the retained Prepared record",
            ));
        }
        let marker = RecoveryMarkerV1::new(
            journal.transaction_id().clone(),
            journal.integrity_hash_bytes(),
            marker_state,
        );
        let bytes = marker.to_bytes()?;

        if fault == Some(RecoveryMarkerPersistenceTestFault::CreateBeforeArtifact) {
            return Err(RecoveryJournalError::InjectedFault(
                "Started marker create before artifact",
            ));
        }

        if fault == Some(RecoveryMarkerPersistenceTestFault::CorruptAfterCreate) {
            let corrupt_length = bytes.len().saturating_sub(1).max(1);
            self.namespace_authority
                .create_new_marker(&marker, &bytes[..corrupt_length])?;
            return Err(RecoveryJournalError::InjectedFault(
                "Started marker corrupt after create",
            ));
        }

        self.namespace_authority
            .create_new_marker(&marker, &bytes)?;

        if fault == Some(RecoveryMarkerPersistenceTestFault::FlushAfterCreate) {
            return Err(RecoveryJournalError::InjectedFault(
                "Started marker FlushFileBuffers",
            ));
        }
        if fault == Some(RecoveryMarkerPersistenceTestFault::ReopenAfterCreate) {
            return Err(RecoveryJournalError::InjectedFault(
                "Started marker reopen verification",
            ));
        }

        let reopened = RecoveryMarkerV1::from_bytes(
            &self
                .namespace_authority
                .read_marker_file(OsStr::new(&marker.file_name()))?,
        )
        .map_err(|_| RecoveryJournalError::ReopenVerificationFailed)?;
        if reopened != marker {
            return Err(RecoveryJournalError::ReopenVerificationFailed);
        }
        Ok(reopened)
    }

    pub(crate) fn persist_started(
        &self,
        journal: &RecoveryJournalV1,
    ) -> Result<RecoveryMarkerV1, RecoveryJournalError> {
        self.persist_marker(journal, RecoveryMarkerState::Started)
    }

    pub(crate) fn persist_committed(
        &self,
        journal: &RecoveryJournalV1,
    ) -> Result<RecoveryMarkerV1, RecoveryJournalError> {
        self.persist_marker(journal, RecoveryMarkerState::Committed)
    }

    pub(crate) fn persist_recovered(
        &self,
        journal: &RecoveryJournalV1,
    ) -> Result<RecoveryMarkerV1, RecoveryJournalError> {
        self.persist_marker(journal, RecoveryMarkerState::Recovered)
    }

    /// Reconciles the fixed workspace target against one prepared record
    /// without writing either the workspace or the journal directory.
    pub fn reconcile_prepared(
        &self,
        journal: &RecoveryJournalV1,
    ) -> Result<RecoveryJournalReconciliation, RecoveryJournalError> {
        if journal.record_state() != RecoveryJournalRecordState::Prepared {
            return Err(RecoveryJournalError::TargetBindingMismatch(
                "only Prepared records can be reconciled by H5-A",
            ));
        }
        let authority = self
            .profile
            .workspace_authority()
            .ok_or(RecoveryJournalError::UnsupportedPlatform)?;
        if authority.verify_named_path_current().is_err() {
            return Ok(RecoveryJournalReconciliation::TargetIdentityChanged);
        }
        let current_root = RecoveryJournalIdentity::from_workspace_identity(authority.identity())?;
        if Some(current_root) != self.workspace_root_identity
            || current_root != journal.workspace_root_identity()
        {
            return Ok(RecoveryJournalReconciliation::TargetIdentityChanged);
        }
        let prepared = match authority.prepare_target(journal.relative_path().as_path()) {
            Ok(prepared) => prepared,
            Err(_) => return Ok(RecoveryJournalReconciliation::TargetMissing),
        };
        if prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile {
            return Ok(RecoveryJournalReconciliation::TargetMissing);
        }
        let current_target = match prepared.target_identity() {
            Some(identity) => RecoveryJournalIdentity::from_workspace_identity(identity)?,
            None => return Ok(RecoveryJournalReconciliation::TargetIdentityChanged),
        };
        if current_target != journal.target_identity() {
            return Ok(RecoveryJournalReconciliation::TargetIdentityChanged);
        }
        let current =
            match prepared.read_existing_file_utf8_bounded(RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES) {
                Ok(current) => current,
                Err(WorkspaceReadError::InvalidTarget(_)) => {
                    return Ok(RecoveryJournalReconciliation::TargetMissing)
                }
                Err(_) => return Ok(RecoveryJournalReconciliation::Diverged),
            };
        let current_hash = digest(current.as_bytes());
        let current_bytes = current.len();
        if current_bytes == journal.before_bytes() && current_hash == journal.before_sha256_bytes()
        {
            Ok(RecoveryJournalReconciliation::StillBefore)
        } else if current_bytes == journal.replacement_bytes()
            && current_hash == journal.replacement_sha256_bytes()
        {
            Ok(RecoveryJournalReconciliation::AlreadyReplacement)
        } else {
            Ok(RecoveryJournalReconciliation::Diverged)
        }
    }

    fn create_prepared_internal(
        &self,
        target: &PreparedWorkspaceTarget,
        context: RecoveryJournalContext,
        transaction_id: RecoveryTransactionId,
    ) -> Result<RecoveryJournalV1, RecoveryJournalError> {
        self.create_prepared_internal_with_expected(target, context, transaction_id, None)
    }

    fn create_prepared_for_expected_preimage_internal(
        &self,
        target: &PreparedWorkspaceTarget,
        context: RecoveryJournalContext,
        transaction_id: RecoveryTransactionId,
        expected_sha256: &str,
    ) -> Result<RecoveryJournalV1, RecoveryJournalError> {
        self.create_prepared_internal_with_expected(
            target,
            context,
            transaction_id,
            Some(expected_sha256),
        )
    }

    fn create_prepared_internal_with_expected(
        &self,
        target: &PreparedWorkspaceTarget,
        context: RecoveryJournalContext,
        transaction_id: RecoveryTransactionId,
        expected_sha256: Option<&str>,
    ) -> Result<RecoveryJournalV1, RecoveryJournalError> {
        self.validate_target_binding(target)?;
        let before_content = target
            .read_existing_file_utf8_bounded(RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES)
            .map_err(|_| RecoveryJournalError::TargetRead)?;
        if before_content.len() > RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES {
            return Err(RecoveryJournalError::Oversized {
                limit: RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES,
            });
        }
        if let Some(expected_sha256) = expected_sha256 {
            let expected_sha256 = decode_sha256_hex("expected_sha256", expected_sha256)?;
            if digest(before_content.as_bytes()) != expected_sha256 {
                return Err(RecoveryJournalError::PreimageConflict);
            }
        }
        let record =
            RecoveryJournalV1::from_preimage(transaction_id, target, context, before_content)?;
        self.persist_prepared(&record)
    }

    fn validate_target_binding(
        &self,
        target: &PreparedWorkspaceTarget,
    ) -> Result<(), RecoveryJournalError> {
        let authority = self
            .profile
            .workspace_authority()
            .ok_or(RecoveryJournalError::UnsupportedPlatform)?;
        let expected_root = self
            .workspace_root_identity
            .ok_or(RecoveryJournalError::UnsupportedPlatform)?;
        let target_root =
            RecoveryJournalIdentity::from_workspace_identity(target.root().identity())?;
        if authority.identity() != target.root().identity() || target_root != expected_root {
            return Err(RecoveryJournalError::TargetBindingMismatch(
                "target is not bound to the explicit Host-owned workspace root",
            ));
        }
        if authority.verify_named_path_current().is_err() {
            return Err(RecoveryJournalError::TargetBindingMismatch(
                "workspace root name no longer denotes the acquired root",
            ));
        }
        if target.kind() != PreparedWorkspaceTargetKind::ExistingFile
            || target.target_identity().is_none()
        {
            return Err(RecoveryJournalError::TargetNotExisting);
        }
        Ok(())
    }

    fn persist_prepared(
        &self,
        record: &RecoveryJournalV1,
    ) -> Result<RecoveryJournalV1, RecoveryJournalError> {
        let bytes = record.to_bytes()?;
        self.namespace_authority
            .create_new_file(record.transaction_id(), &bytes)?;

        let file_name = journal_file_name(record.transaction_id());
        let verified = RecoveryJournalV1::from_bytes(
            &self.namespace_authority.read_file(OsStr::new(&file_name))?,
        )
        .map_err(|_| RecoveryJournalError::ReopenVerificationFailed)?;
        if verified.record_state() != RecoveryJournalRecordState::Prepared || verified != *record {
            return Err(RecoveryJournalError::ReopenVerificationFailed);
        }
        Ok(verified)
    }

    fn validate_scan_root(&self) -> Result<(), RecoveryJournalError> {
        self.profile
            .validate_private_namespace()
            .map_err(RecoveryJournalError::Profile)
    }

    #[cfg(test)]
    fn journal_path(&self, transaction_id: &RecoveryTransactionId) -> PathBuf {
        self.recovery_root.join(journal_file_name(transaction_id))
    }

    #[cfg(test)]
    pub(crate) fn create_prepared_with_transaction_id_for_test(
        &self,
        target: &PreparedWorkspaceTarget,
        context: RecoveryJournalContext,
        transaction_id: &str,
    ) -> Result<RecoveryJournalV1, RecoveryJournalError> {
        self.create_prepared_internal(
            target,
            context,
            RecoveryTransactionId::parse(transaction_id)?,
        )
    }

    #[cfg(test)]
    fn create_prepared_with_fault_for_test(
        &self,
        target: &PreparedWorkspaceTarget,
        context: RecoveryJournalContext,
        fault: RecoveryJournalTestFault,
    ) -> Result<RecoveryJournalV1, RecoveryJournalError> {
        self.validate_target_binding(target)?;
        let before_content = target
            .read_existing_file_utf8_bounded(RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES)
            .map_err(|_| RecoveryJournalError::TargetRead)?;
        let record = RecoveryJournalV1::from_preimage(
            RecoveryTransactionId::generate(),
            target,
            context,
            before_content,
        )?;
        self.persist_prepared_with_fault(&record, fault)
    }

    #[cfg(test)]
    fn persist_prepared_with_fault(
        &self,
        record: &RecoveryJournalV1,
        fault: RecoveryJournalTestFault,
    ) -> Result<RecoveryJournalV1, RecoveryJournalError> {
        let bytes = record.to_bytes()?;
        if fault == RecoveryJournalTestFault::Write {
            return Err(RecoveryJournalError::InjectedFault("write"));
        }
        if fault == RecoveryJournalTestFault::Truncate {
            self.namespace_authority
                .create_new_file(record.transaction_id(), &bytes[..bytes.len() / 2])?;
            return Err(RecoveryJournalError::InjectedFault("truncate"));
        }
        if fault == RecoveryJournalTestFault::Flush {
            return Err(RecoveryJournalError::InjectedFault("flush"));
        }
        if fault == RecoveryJournalTestFault::BadIntegrity {
            let mut invalid = bytes;
            let last = invalid.len() - 1;
            invalid[last] ^= 0xff;
            self.namespace_authority
                .create_new_file(record.transaction_id(), &invalid)?;
            return Err(RecoveryJournalError::InjectedFault("integrity"));
        }
        if fault == RecoveryJournalTestFault::Reopen {
            self.namespace_authority
                .create_new_file(record.transaction_id(), &[])?;
            return Err(RecoveryJournalError::InjectedFault("reopen"));
        }
        self.namespace_authority
            .create_new_file(record.transaction_id(), &bytes)?;
        let file_name = journal_file_name(record.transaction_id());
        let verified = RecoveryJournalV1::from_bytes(
            &self.namespace_authority.read_file(OsStr::new(&file_name))?,
        )
        .map_err(|_| RecoveryJournalError::ReopenVerificationFailed)?;
        if verified != *record {
            return Err(RecoveryJournalError::ReopenVerificationFailed);
        }
        Ok(verified)
    }
}

fn journal_file_name(transaction_id: &RecoveryTransactionId) -> String {
    format!("{}.dlrj", transaction_id.as_str())
}

fn marker_file_name(
    transaction_id: &RecoveryTransactionId,
    marker_state: RecoveryMarkerState,
) -> String {
    format!("{}.{}", transaction_id.as_str(), marker_state.suffix())
}

fn parse_marker_file_name(
    value: &str,
) -> Option<Result<(RecoveryTransactionId, RecoveryMarkerState), RecoveryJournalError>> {
    for (suffix, marker_state) in [
        (".started", RecoveryMarkerState::Started),
        (".committed", RecoveryMarkerState::Committed),
        (".recovered", RecoveryMarkerState::Recovered),
    ] {
        if let Some(transaction_text) = value.strip_suffix(suffix) {
            return Some(
                RecoveryTransactionId::parse(transaction_text)
                    .map(|transaction_id| (transaction_id, marker_state)),
            );
        }
    }
    None
}

fn build_transaction_snapshot(
    journal: RecoveryJournalV1,
    markers: Vec<RecoveryMarkerV1>,
) -> Result<RecoveryTransactionSnapshot, &'static str> {
    let mut started = None;
    let mut committed = None;
    let mut recovered = None;
    for marker in markers {
        if marker.transaction_id() != journal.transaction_id()
            || marker.journal_integrity_hash_bytes() != journal.integrity_hash_bytes()
        {
            return Err("marker does not bind the immutable journal");
        }
        match marker.marker_state() {
            RecoveryMarkerState::Started => {
                if started.replace(marker).is_some() {
                    return Err("duplicate Started marker records");
                }
            }
            RecoveryMarkerState::Committed => {
                if committed.replace(marker).is_some() {
                    return Err("duplicate Committed marker records");
                }
            }
            RecoveryMarkerState::Recovered => {
                if recovered.replace(marker).is_some() {
                    return Err("duplicate Recovered marker records");
                }
            }
        }
    }
    let state = match (started.is_some(), committed.is_some(), recovered.is_some()) {
        (false, false, false) => RecoveryTransactionState::PreparedOnly,
        (true, false, false) => RecoveryTransactionState::RecoveryRequired,
        (true, true, false) => RecoveryTransactionState::CommittedTerminal,
        (true, false, true) => RecoveryTransactionState::RecoveredTerminal,
        (false, true, false) => return Err("Committed marker has no Started marker"),
        (false, false, true) => return Err("Recovered marker has no Started marker"),
        (true, true, true) => return Err("Committed and Recovered markers coexist"),
        (false, true, true) => return Err("terminal markers have no Started marker"),
    };
    Ok(RecoveryTransactionSnapshot {
        journal,
        started,
        committed,
        recovered,
        state,
    })
}

fn finalize_scan_items(items: Vec<RecoveryJournalScanItem>) -> RecoveryJournalScan {
    let mut by_target: HashMap<RecoveryJournalTargetKey, Vec<RecoveryJournalV1>> = HashMap::new();
    let mut retained_items = Vec::with_capacity(items.len());
    for item in items {
        match item {
            RecoveryJournalScanItem::ValidPreparedJournal(journal) => {
                by_target
                    .entry(target_key(&journal))
                    .or_default()
                    .push(journal);
            }
            item => retained_items.push(item),
        }
    }
    for (target, mut journals) in by_target {
        journals.sort_by(|left, right| {
            left.transaction_id()
                .as_str()
                .cmp(right.transaction_id().as_str())
        });
        if journals.len() > 1 {
            let transactions = journals
                .iter()
                .map(|journal| journal.transaction_id().clone())
                .collect();
            retained_items.push(RecoveryJournalScanItem::AmbiguousPendingRecovery {
                target,
                transactions,
            });
        } else if let Some(journal) = journals.pop() {
            retained_items.push(RecoveryJournalScanItem::ValidPreparedJournal(journal));
        }
    }
    RecoveryJournalScan {
        items: retained_items,
    }
}

fn bounded_context_text(field: &'static str, value: &str) -> Result<String, RecoveryJournalError> {
    if value.is_empty() || value.len() > MAX_CONTEXT_FIELD_BYTES {
        return Err(RecoveryJournalError::InvalidField {
            field,
            reason: "empty or oversized",
        });
    }
    if value
        .chars()
        .any(|character| character == '\0' || character.is_control())
    {
        return Err(RecoveryJournalError::InvalidField {
            field,
            reason: "control characters are forbidden",
        });
    }
    Ok(value.to_string())
}

fn bounded_bytes(field: &'static str, value: usize) -> Result<u32, RecoveryJournalError> {
    if value > RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES {
        return Err(RecoveryJournalError::Oversized {
            limit: if field == "replacement_bytes" {
                RECOVERY_JOURNAL_MAX_REPLACEMENT_BYTES
            } else {
                RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES
            },
        });
    }
    u32::try_from(value).map_err(|_| RecoveryJournalError::Oversized {
        limit: RECOVERY_JOURNAL_MAX_SIZE,
    })
}

fn decode_sha256_hex(field: &'static str, value: &str) -> Result<[u8; 32], RecoveryJournalError> {
    if value.len() != 64 || !value.is_ascii() {
        return Err(RecoveryJournalError::InvalidField {
            field,
            reason: "SHA-256 must be exactly 64 ASCII hex characters",
        });
    }
    let mut result = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_digit(chunk[0]).ok_or(RecoveryJournalError::InvalidField {
            field,
            reason: "SHA-256 contains non-hex characters",
        })?;
        let low = hex_digit(chunk[1]).ok_or(RecoveryJournalError::InvalidField {
            field,
            reason: "SHA-256 contains non-hex characters",
        })?;
        result[index] = (high << 4) | low;
    }
    Ok(result)
}

fn hex_digit(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    array_from_slice(&digest)
}

fn integrity_hash(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEPARATOR);
    hasher.update(MAGIC);
    hasher.update(RECOVERY_JOURNAL_FORMAT_VERSION.to_le_bytes());
    hasher.update((payload.len() as u32).to_le_bytes());
    hasher.update(payload);
    array_from_slice(&hasher.finalize())
}

fn array_from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    result.copy_from_slice(bytes);
    result
}

fn array_from_slice_16(bytes: &[u8]) -> [u8; 16] {
    let mut result = [0u8; 16];
    result.copy_from_slice(bytes);
    result
}

fn canonical_relative_path_object(
    path: &WorkspaceRelativePath,
) -> Result<WorkspaceRelativePath, RecoveryJournalError> {
    let canonical = canonical_relative_path(path)?;
    WorkspaceRelativePath::parse(Path::new(&canonical)).map_err(|_| {
        RecoveryJournalError::InvalidField {
            field: "relative_path",
            reason: "canonical H4 relative path could not be parsed",
        }
    })
}

fn canonical_relative_path(path: &WorkspaceRelativePath) -> Result<String, RecoveryJournalError> {
    let mut components = Vec::new();
    for component in path.components() {
        let component = component
            .to_str()
            .ok_or(RecoveryJournalError::InvalidField {
                field: "relative_path",
                reason: "path component is not UTF-8",
            })?;
        components.push(component);
    }
    let canonical = components.join("\\");
    if canonical.is_empty() || canonical.len() > MAX_RELATIVE_PATH_BYTES {
        return Err(RecoveryJournalError::InvalidField {
            field: "relative_path",
            reason: "empty or oversized",
        });
    }
    Ok(canonical)
}

fn put_u32(payload: &mut Vec<u8>, value: u32) {
    payload.extend_from_slice(&value.to_le_bytes());
}

fn put_string(
    payload: &mut Vec<u8>,
    field: &'static str,
    value: &str,
    limit: usize,
    nonempty: bool,
) -> Result<(), RecoveryJournalError> {
    if value.len() > limit || (nonempty && value.is_empty()) {
        return Err(RecoveryJournalError::InvalidField {
            field,
            reason: "empty or oversized",
        });
    }
    if value
        .chars()
        .any(|character| character == '\0' || character.is_control())
    {
        return Err(RecoveryJournalError::InvalidField {
            field,
            reason: "control characters are forbidden",
        });
    }
    let length = u32::try_from(value.len()).map_err(|_| RecoveryJournalError::Oversized {
        limit: MAX_PAYLOAD_BYTES,
    })?;
    payload.extend_from_slice(&length.to_le_bytes());
    payload.extend_from_slice(value.as_bytes());
    Ok(())
}

fn put_bytes(
    payload: &mut Vec<u8>,
    field: &'static str,
    value: &[u8],
    limit: usize,
) -> Result<(), RecoveryJournalError> {
    if value.len() > limit {
        return Err(RecoveryJournalError::Oversized { limit });
    }
    let length = u32::try_from(value.len()).map_err(|_| RecoveryJournalError::Oversized {
        limit: MAX_PAYLOAD_BYTES,
    })?;
    let _ = field;
    payload.extend_from_slice(&length.to_le_bytes());
    payload.extend_from_slice(value);
    Ok(())
}

fn put_identity(payload: &mut Vec<u8>, identity: RecoveryJournalIdentity) {
    payload.extend_from_slice(&identity.volume_serial_number.to_le_bytes());
    payload.extend_from_slice(&identity.file_id);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RecoveryJournalError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RecoveryJournalError::Corrupt("payload length overflow"))?;
        if end > self.bytes.len() {
            return Err(RecoveryJournalError::Corrupt("truncated payload field"));
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn u8(&mut self, _field: &'static str) -> Result<u8, RecoveryJournalError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self, _field: &'static str) -> Result<u32, RecoveryJournalError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self, _field: &'static str) -> Result<u64, RecoveryJournalError> {
        let bytes = self.take(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn bytes(
        &mut self,
        field: &'static str,
        limit: usize,
    ) -> Result<&'a [u8], RecoveryJournalError> {
        let length = self.u32(field)? as usize;
        if length > limit {
            return Err(RecoveryJournalError::Oversized { limit });
        }
        self.take(length)
    }

    fn string(
        &mut self,
        field: &'static str,
        limit: usize,
        nonempty: bool,
    ) -> Result<String, RecoveryJournalError> {
        let bytes = self.bytes(field, limit)?;
        if nonempty && bytes.is_empty() {
            return Err(RecoveryJournalError::InvalidField {
                field,
                reason: "empty",
            });
        }
        let value = std::str::from_utf8(bytes)
            .map_err(|_| RecoveryJournalError::Corrupt("length-prefixed string is not UTF-8"))?;
        if value
            .chars()
            .any(|character| character == '\0' || character.is_control())
        {
            return Err(RecoveryJournalError::Corrupt(
                "string contains a control character",
            ));
        }
        Ok(value.to_string())
    }

    fn hash(&mut self, field: &'static str) -> Result<[u8; 32], RecoveryJournalError> {
        Ok(array_from_slice(self.take(32).map_err(|_| {
            RecoveryJournalError::Corrupt(match field {
                "before_sha256" => "truncated before hash",
                _ => "truncated replacement hash",
            })
        })?))
    }

    fn identity(
        &mut self,
        field: &'static str,
    ) -> Result<RecoveryJournalIdentity, RecoveryJournalError> {
        let volume_bytes = self.take(8).map_err(|_| {
            RecoveryJournalError::Corrupt(match field {
                "workspace_root_identity" => "truncated workspace root identity",
                _ => "truncated target identity",
            })
        })?;
        let file_id = self.take(16).map_err(|_| {
            RecoveryJournalError::Corrupt(match field {
                "workspace_root_identity" => "truncated workspace root file id",
                _ => "truncated target file id",
            })
        })?;
        Ok(RecoveryJournalIdentity {
            volume_serial_number: u64::from_le_bytes([
                volume_bytes[0],
                volume_bytes[1],
                volume_bytes[2],
                volume_bytes[3],
                volume_bytes[4],
                volume_bytes[5],
                volume_bytes[6],
                volume_bytes[7],
            ]),
            file_id: array_from_slice_16(file_id),
        })
    }

    fn finish(&self) -> Result<(), RecoveryJournalError> {
        if self.offset != self.bytes.len() {
            return Err(RecoveryJournalError::Corrupt(
                "payload has extra trailing fields",
            ));
        }
        Ok(())
    }
}

fn target_key(journal: &RecoveryJournalV1) -> RecoveryJournalTargetKey {
    RecoveryJournalTargetKey {
        workspace_root_identity: journal.workspace_root_identity,
        relative_path: canonical_relative_path(&journal.relative_path)
            .unwrap_or_else(|_| String::new()),
        target_identity: journal.target_identity,
    }
}

fn mutation_target_key(journal: &RecoveryJournalV1) -> RecoveryMutationTargetKey {
    RecoveryMutationTargetKey {
        workspace_root_identity: journal.workspace_root_identity,
        target_identity: journal.target_identity,
    }
}

#[cfg(test)]
pub(crate) fn mutation_target_key_for_prepared_target(
    target: &PreparedWorkspaceTarget,
) -> Result<RecoveryMutationTargetKey, RecoveryJournalError> {
    if target.kind() != PreparedWorkspaceTargetKind::ExistingFile {
        return Err(RecoveryJournalError::TargetNotExisting);
    }
    let target_identity = target
        .target_identity()
        .ok_or(RecoveryJournalError::TargetNotExisting)?;
    Ok(RecoveryMutationTargetKey {
        workspace_root_identity: RecoveryJournalIdentity::from_workspace_identity(
            target.root().identity(),
        )?,
        target_identity: RecoveryJournalIdentity::from_workspace_identity(target_identity)?,
    })
}

fn current_unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u64::MAX as u128) as u64
        })
}

fn io_error(operation: &'static str, source: io::Error) -> RecoveryJournalError {
    RecoveryJournalError::Io { operation, source }
}

fn scan_error_reason(error: &RecoveryJournalError) -> &'static str {
    match error {
        RecoveryJournalError::Oversized { .. } => "journal exceeds the hard size bound",
        RecoveryJournalError::UnsupportedVersion(_) => "unsupported journal version",
        RecoveryJournalError::Corrupt(reason) => reason,
        RecoveryJournalError::Io { .. } => "journal I/O failed",
        _ => "journal failed closed",
    }
}

fn scan_marker_error_reason(error: &RecoveryJournalError) -> &'static str {
    match error {
        RecoveryJournalError::Oversized { .. } => "marker exceeds the hard size bound",
        RecoveryJournalError::UnsupportedVersion(_) => "unsupported marker version",
        RecoveryJournalError::Corrupt(reason) => reason,
        RecoveryJournalError::Io { .. } => "marker I/O failed",
        _ => "marker failed closed",
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecoveryJournalTestFault {
    Write,
    Flush,
    Truncate,
    BadIntegrity,
    Reopen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum RecoveryMarkerPersistenceTestFault {
    CreateBeforeArtifact,
    FlushAfterCreate,
    ReopenAfterCreate,
    CorruptAfterCreate,
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::any::type_name;
    use std::fs;
    use tempfile::{tempdir, TempDir};

    use crate::workspace_capability::AppOwnedRecoveryNamespace;
    use crate::{contains_stock_codex_state, TrustedWorkspaceRoot, CODEX_UPSTREAM_COMMIT};

    struct Fixture {
        _app_data: TempDir,
        workspace: TempDir,
        profile: VitaAgentRuntimeProfile,
        store: RecoveryJournalStore,
    }

    impl Fixture {
        fn new() -> Self {
            let app_data = tempdir().expect("app-data temp root");
            let workspace = tempdir().expect("workspace temp root");
            let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
                app_data.path().to_path_buf(),
                workspace.path().to_path_buf(),
            )
            .expect("explicit Vita profile");
            profile
                .ensure_private_runtime_layout()
                .expect("Vita private layout");
            fs::write(workspace.path().join("target.txt"), "before\n").expect("workspace fixture");
            let store =
                RecoveryJournalStore::from_runtime_profile(&profile).expect("recovery store");
            Self {
                _app_data: app_data,
                workspace,
                profile,
                store,
            }
        }

        fn target(&self) -> PreparedWorkspaceTarget {
            self.target_named("target.txt")
        }

        fn target_named(&self, name: &str) -> PreparedWorkspaceTarget {
            self.profile
                .prepare_workspace_target(Path::new(name))
                .expect("prepared target")
        }

        fn create_target(&self, name: &str, contents: &[u8]) -> PreparedWorkspaceTarget {
            fs::write(self.workspace.path().join(name), contents).expect("workspace fixture");
            self.target_named(name)
        }

        fn context(&self, replacement: &[u8]) -> RecoveryJournalContext {
            RecoveryJournalContext::new(
                "life-1",
                "task-1",
                "workspace.replace",
                &hex_encode(&digest(replacement)),
                replacement.len(),
                "tool-call-1",
                "turn-1",
            )
            .expect("journal context")
        }

        fn path_for(&self, journal: &RecoveryJournalV1) -> PathBuf {
            self.store.journal_path(journal.transaction_id())
        }
    }

    struct RecoveryRootReplacement {
        original: PathBuf,
        moved: PathBuf,
        alias: PathBuf,
        _outside: TempDir,
    }

    impl Drop for RecoveryRootReplacement {
        fn drop(&mut self) {
            if self.alias.exists() {
                let _ = fs::remove_dir(&self.alias);
            }
            if self.moved.exists() && !self.original.exists() {
                let _ = fs::rename(&self.moved, &self.original);
            }
        }
    }

    fn replace_recovery_root_with_junction(fixture: &Fixture) -> RecoveryRootReplacement {
        use std::process::Command;

        let original = fixture.store.recovery_root().to_path_buf();
        let moved = fixture.profile.vita_root().join("recovery-original");
        let outside = tempdir().expect("outside recovery fixture");
        fs::rename(&original, &moved).expect("rename retained recovery root fixture");
        let status = Command::new("cmd.exe")
            .args([
                "/d",
                "/c",
                "mklink",
                "/J",
                original.to_str().expect("recovery junction path"),
                outside.path().to_str().expect("outside junction target"),
            ])
            .status()
            .expect("create recovery junction fixture");
        assert!(status.success(), "recovery junction fixture must succeed");
        RecoveryRootReplacement {
            original: original.clone(),
            moved,
            alias: original,
            _outside: outside,
        }
    }

    #[test]
    fn journal_v1_roundtrips_exact_preimage() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        assert_eq!(journal.record_state(), RecoveryJournalRecordState::Prepared);
        assert_eq!(journal.before_content(), "before\n");
        assert_eq!(journal.before_bytes(), "before\n".len());
        let parsed = RecoveryJournalV1::from_bytes(&journal.to_bytes().unwrap()).unwrap();
        assert_eq!(parsed, journal);
    }

    #[test]
    fn journal_binds_exact_target_identity() {
        let fixture = Fixture::new();
        let target = fixture.target();
        let journal = fixture
            .store
            .create_prepared(&target, fixture.context(b"after\n"))
            .expect("prepared journal");
        let target_identity = target.target_identity().unwrap();
        assert_eq!(
            journal.target_identity().volume_serial_number(),
            target_identity.volume_serial_number().unwrap()
        );
        assert_eq!(
            journal.target_identity().file_id(),
            target_identity.file_id().unwrap()
        );
        assert_eq!(
            journal.workspace_root_identity(),
            fixture.store.expected_workspace_root_identity().unwrap()
        );
    }

    #[test]
    fn journal_binds_before_and_replacement_hashes() {
        let fixture = Fixture::new();
        let replacement = b"after\n";
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(replacement))
            .expect("prepared journal");
        assert_eq!(journal.before_sha256(), hex_encode(&digest(b"before\n")));
        assert_eq!(
            journal.replacement_sha256(),
            hex_encode(&digest(replacement))
        );
        assert_eq!(journal.replacement_bytes(), replacement.len());
        assert!(!journal
            .to_bytes()
            .unwrap()
            .windows(replacement.len())
            .any(|window| window == replacement));
    }

    #[test]
    fn journal_is_not_authority() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared evidence");
        assert_eq!(journal.record_state(), RecoveryJournalRecordState::Prepared);
        let bytes = journal.to_bytes().unwrap();
        assert!(!bytes
            .windows(b"confirmation_id".len())
            .any(|window| window == b"confirmation_id"));
        assert!(!bytes
            .windows(b"grant_id".len())
            .any(|window| window == b"grant_id"));
    }

    #[test]
    fn journal_create_is_create_new_only() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        let original = fs::read(fixture.path_for(&journal)).unwrap();
        let error = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"replacement-2\n"),
                journal.transaction_id().as_str(),
            )
            .expect_err("existing transaction must fail closed");
        assert!(matches!(
            error,
            RecoveryJournalError::DuplicateTransactionId
        ));
        assert_eq!(fs::read(fixture.path_for(&journal)).unwrap(), original);
    }

    #[test]
    fn duplicate_transaction_id_cannot_overwrite() {
        let fixture = Fixture::new();
        let first = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after\n"),
                "tx-fixed",
            )
            .expect("first journal");
        let original = fs::read(fixture.path_for(&first)).unwrap();
        let result = fixture.store.create_prepared_with_transaction_id_for_test(
            &fixture.target(),
            fixture.context(b"different\n"),
            "tx-fixed",
        );
        assert!(matches!(
            result,
            Err(RecoveryJournalError::DuplicateTransactionId)
        ));
        assert_eq!(fs::read(fixture.path_for(&first)).unwrap(), original);
    }

    #[test]
    fn truncated_journal_fails_closed() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .unwrap();
        let bytes = journal.to_bytes().unwrap();
        assert!(matches!(
            RecoveryJournalV1::from_bytes(&bytes[..bytes.len() - 1]),
            Err(RecoveryJournalError::Corrupt(_))
        ));
    }

    #[test]
    fn oversized_journal_fails_closed() {
        assert!(matches!(
            RecoveryJournalV1::from_bytes(&vec![0; RECOVERY_JOURNAL_MAX_SIZE + 1]),
            Err(RecoveryJournalError::Oversized { .. })
        ));
    }

    #[test]
    fn unknown_version_fails_closed() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .unwrap();
        let mut bytes = journal.to_bytes().unwrap();
        bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            RecoveryJournalV1::from_bytes(&bytes),
            Err(RecoveryJournalError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn integrity_mismatch_fails_closed() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .unwrap();
        let mut bytes = journal.to_bytes().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        assert!(matches!(
            RecoveryJournalV1::from_bytes(&bytes),
            Err(RecoveryJournalError::Corrupt("integrity hash mismatch"))
        ));
    }

    #[test]
    fn extra_trailing_bytes_fail_closed() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .unwrap();
        let mut bytes = journal.to_bytes().unwrap();
        bytes.push(0);
        assert!(matches!(
            RecoveryJournalV1::from_bytes(&bytes),
            Err(RecoveryJournalError::Corrupt(
                "extra trailing journal bytes"
            ))
        ));
    }

    #[test]
    fn invalid_transaction_id_rejected() {
        for value in ["", ".", "..", "a/b", "a\\b", "a:b", "CON", "a.dlrj", "a?"] {
            assert!(RecoveryTransactionId::parse(value).is_err(), "{value:?}");
        }
        assert!(RecoveryTransactionId::parse("tx-valid_1").is_ok());
    }

    #[test]
    fn recovery_path_is_app_owned_not_model_supplied() {
        let fixture = Fixture::new();
        assert_eq!(
            fixture.store.recovery_root(),
            fixture.profile.vita_root().join("recovery").as_path()
        );
        assert!(fixture
            .store
            .recovery_root()
            .starts_with(fixture.profile.vita_root()));
        assert!(!contains_stock_codex_state(fixture.store.recovery_root()));
    }

    #[test]
    fn recovery_store_uses_retained_namespace_authority() {
        let fixture = Fixture::new();
        let authority = &fixture.store.namespace_authority;
        assert_eq!(
            authority.namespace.vita_root_path(),
            fixture.profile.vita_root()
        );
        assert_eq!(
            authority.namespace.recovery_root_path(),
            fixture.store.recovery_root()
        );
        assert_eq!(
            authority.namespace.recovery_root_identity().file_id(),
            Some(
                RecoveryJournalIdentity::from_workspace_identity(
                    authority.namespace.recovery_root_identity()
                )
                .unwrap()
                .file_id(),
            )
        );
        let debug = format!("{authority:?}");
        assert!(!debug.contains("HANDLE"));
    }

    #[test]
    fn trusted_workspace_root_remains_non_mutating_identity_capability() {
        let source = include_str!("workspace_capability.rs");
        let trusted_root_impl = source
            .split("impl TrustedWorkspaceRoot {")
            .nth(1)
            .and_then(|body| body.split("/// Identity-only preparation result").next())
            .expect("TrustedWorkspaceRoot impl surface");

        for (prefix, suffix) in [
            ("create_new_file_relative", "_for_namespace"),
            ("read_file_relative", "_for_namespace"),
            ("enumerate_children", "_for_namespace"),
            ("acquire_fixed_child_directory", "_for_namespace"),
        ] {
            let forbidden = format!("{prefix}{suffix}");
            assert!(
                !trusted_root_impl.contains(&forbidden),
                "TrustedWorkspaceRoot still exposes {forbidden}"
            );
        }
        assert!(trusted_root_impl.contains("pub fn prepare_target"));
    }

    #[test]
    fn recovery_namespace_is_distinct_from_workspace_root() {
        let fixture = Fixture::new();
        let namespace = &fixture.store.namespace_authority.namespace;

        assert_ne!(
            type_name::<AppOwnedRecoveryNamespace>(),
            type_name::<TrustedWorkspaceRoot>()
        );
        assert_eq!(namespace.vita_root_path(), fixture.profile.vita_root());
        assert_eq!(
            namespace.recovery_root_path(),
            fixture.store.recovery_root()
        );
        assert!(format!("{namespace:?}").contains("AppOwnedRecoveryNamespace"));
    }

    #[test]
    fn recovery_namespace_acquisition_is_fixed_to_vita_recovery() {
        let fixture = Fixture::new();
        let namespace = &fixture.store.namespace_authority.namespace;
        let expected_recovery_root = fixture.profile.vita_root().join(RECOVERY_DIRECTORY_NAME);

        assert_eq!(namespace.vita_root_path(), fixture.profile.vita_root());
        assert_eq!(namespace.recovery_root_path(), expected_recovery_root);

        let source = include_str!("workspace_capability.rs");
        assert!(source.contains("let recovery_name = OsStr::new(\"recovery\")"));
    }

    #[test]
    fn recovery_namespace_cannot_be_constructed_from_workspace_root() {
        let source = include_str!("workspace_capability.rs");
        let conversion = format!(
            "From<{}> for {}",
            "TrustedWorkspaceRoot", "AppOwnedRecoveryNamespace"
        );
        let from_root = format!("{}::from_{}", "AppOwnedRecoveryNamespace", "root");
        let from_trusted_workspace = ["from_trusted_workspace_", "root"].concat();

        assert!(!source.contains(&conversion));
        assert!(!source.contains(&from_root));
        assert!(!source.contains(&from_trusted_workspace));
    }

    #[test]
    fn recovery_journal_creation_cannot_receive_workspace_authority() {
        let source = include_str!("recovery_journal.rs");
        let persist_surface = source
            .split("fn persist_prepared(")
            .nth(1)
            .and_then(|body| body.split("fn validate_scan_root").next())
            .expect("H5-A journal persistence surface");

        assert!(persist_surface.contains("namespace_authority"));
        assert!(persist_surface.contains("create_new_file"));
        assert!(!persist_surface.contains("workspace_authority"));
        assert!(!persist_surface.contains("prepare_workspace_target"));
    }

    #[test]
    fn journal_create_is_handle_relative() {
        let fixture = Fixture::new();
        let replacement = replace_recovery_root_with_junction(&fixture);
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("handle-relative journal create");
        let name = journal_file_name(journal.transaction_id());
        assert!(replacement.moved.join(&name).is_file());
        assert!(!replacement._outside.path().join(&name).exists());
        assert!(!fixture.path_for(&journal).is_file());
    }

    #[test]
    fn journal_reopen_is_handle_relative() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        let replacement = replace_recovery_root_with_junction(&fixture);
        let name = journal_file_name(journal.transaction_id());
        let reopened = RecoveryJournalV1::from_bytes(
            &fixture
                .store
                .namespace_authority
                .read_file(OsStr::new(&name))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(reopened, journal);
        assert!(!replacement._outside.path().join(&name).exists());
        assert!(!fixture.path_for(&journal).is_file());
    }

    #[test]
    fn scanner_enumerates_retained_recovery_root() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        let replacement = replace_recovery_root_with_junction(&fixture);
        let name = std::ffi::OsString::from(journal_file_name(journal.transaction_id()));
        let names = fixture
            .store
            .namespace_authority
            .enumerate()
            .expect("retained root enumeration");
        assert!(names.iter().any(|candidate| candidate == &name));
        assert!(!replacement._outside.path().join(&name).exists());
    }

    fn create_marker_for_scan(
        fixture: &Fixture,
        transaction_id: RecoveryTransactionId,
        journal_integrity_hash: [u8; 32],
        marker_state: RecoveryMarkerState,
    ) -> RecoveryMarkerV1 {
        let marker = RecoveryMarkerV1::new(transaction_id, journal_integrity_hash, marker_state);
        let bytes = marker.to_bytes().expect("marker fixture bytes");
        fixture
            .store
            .namespace_authority
            .create_new_marker(&marker, &bytes)
            .expect("marker fixture create-new");
        marker
    }

    #[test]
    fn transaction_scanner_rejects_illegal_marker_combinations() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        create_marker_for_scan(
            &fixture,
            journal.transaction_id().clone(),
            journal.integrity_hash_bytes(),
            RecoveryMarkerState::Committed,
        );
        let scan = fixture.store.scan_transactions().expect("strict scan");
        assert!(scan.valid_transactions().next().is_none());
        assert!(scan.items().iter().any(|item| matches!(
            item,
            RecoveryTransactionScanItem::CorruptArtifact {
                reason: "Committed marker has no Started marker",
                ..
            }
        )));

        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        create_marker_for_scan(
            &fixture,
            journal.transaction_id().clone(),
            journal.integrity_hash_bytes(),
            RecoveryMarkerState::Started,
        );
        create_marker_for_scan(
            &fixture,
            journal.transaction_id().clone(),
            journal.integrity_hash_bytes(),
            RecoveryMarkerState::Committed,
        );
        create_marker_for_scan(
            &fixture,
            journal.transaction_id().clone(),
            journal.integrity_hash_bytes(),
            RecoveryMarkerState::Recovered,
        );
        let scan = fixture.store.scan_transactions().expect("strict scan");
        assert!(scan.valid_transactions().next().is_none());
        assert!(scan.items().iter().any(|item| matches!(
            item,
            RecoveryTransactionScanItem::CorruptArtifact {
                reason: "Committed and Recovered markers coexist",
                ..
            }
        )));
    }

    #[test]
    fn transaction_scanner_rejects_orphan_and_mismatched_markers() {
        let fixture = Fixture::new();
        create_marker_for_scan(
            &fixture,
            RecoveryTransactionId::parse("tx-orphan").unwrap(),
            [0x11; 32],
            RecoveryMarkerState::Started,
        );
        let scan = fixture.store.scan_transactions().expect("strict scan");
        assert!(scan.items().iter().any(|item| matches!(
            item,
            RecoveryTransactionScanItem::OrphanedRecoveryMarker {
                transaction_id,
                marker_state: RecoveryMarkerState::Started,
                ..
            } if transaction_id.as_str() == "tx-orphan"
        )));

        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        create_marker_for_scan(
            &fixture,
            journal.transaction_id().clone(),
            [0x22; 32],
            RecoveryMarkerState::Started,
        );
        let scan = fixture.store.scan_transactions().expect("strict scan");
        assert!(scan.valid_transactions().next().is_none());
        assert!(scan.items().iter().any(|item| matches!(
            item,
            RecoveryTransactionScanItem::CorruptArtifact {
                reason: "marker does not bind the immutable journal",
                ..
            }
        )));
    }

    #[test]
    fn committed_terminal_history_does_not_create_false_ambiguity() {
        let fixture = Fixture::new();
        let first = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-committed\n"),
                "tx-terminal-first",
            )
            .unwrap();
        fixture.store.persist_started(&first).unwrap();
        fixture.store.persist_committed(&first).unwrap();
        let second = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-new\n"),
                "tx-terminal-second",
            )
            .unwrap();

        let scan = fixture.store.scan_transactions().unwrap();
        assert!(!scan.has_ambiguous_target());
        assert_eq!(scan.actionable_recovery_transactions().count(), 0);
        assert_eq!(
            scan.valid_transactions()
                .find(|snapshot| snapshot.journal().transaction_id() == second.transaction_id())
                .unwrap()
                .state(),
            RecoveryTransactionState::PreparedOnly
        );
    }

    #[test]
    fn recovered_terminal_history_does_not_create_false_ambiguity() {
        let fixture = Fixture::new();
        let first = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-recovered\n"),
                "tx-recovered-first",
            )
            .unwrap();
        fixture.store.persist_started(&first).unwrap();
        fixture.store.persist_recovered(&first).unwrap();
        fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-new\n"),
                "tx-recovered-second",
            )
            .unwrap();

        let scan = fixture.store.scan_transactions().unwrap();
        assert!(!scan.has_ambiguous_target());
        assert_eq!(scan.actionable_recovery_transactions().count(), 0);
        assert_eq!(
            scan.valid_transactions()
                .filter(|snapshot| snapshot.state() == RecoveryTransactionState::RecoveredTerminal)
                .count(),
            1
        );
    }

    #[test]
    fn prepared_only_history_does_not_create_false_ambiguity() {
        let fixture = Fixture::new();
        fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-history\n"),
                "tx-prepared-history",
            )
            .unwrap();
        fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-new\n"),
                "tx-prepared-new",
            )
            .unwrap();

        let scan = fixture.store.scan_transactions().unwrap();
        assert!(!scan.has_ambiguous_target());
        assert_eq!(scan.actionable_recovery_transactions().count(), 0);
        assert_eq!(
            scan.valid_transactions()
                .filter(|snapshot| snapshot.state() == RecoveryTransactionState::PreparedOnly)
                .count(),
            2
        );
    }

    #[test]
    fn prepared_only_plus_recovery_required_keeps_one_actionable_recovery() {
        let fixture = Fixture::new();
        fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-history\n"),
                "tx-prepared-before-active",
            )
            .unwrap();
        let active = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-active\n"),
                "tx-active-after-prepared",
            )
            .unwrap();
        fixture.store.persist_started(&active).unwrap();

        let scan = fixture.store.scan_transactions().unwrap();
        assert!(!scan.has_ambiguous_target());
        assert_eq!(scan.actionable_recovery_transactions().count(), 1);
        assert_eq!(
            scan.valid_transactions()
                .find(|snapshot| snapshot.journal().transaction_id() == active.transaction_id())
                .unwrap()
                .state(),
            RecoveryTransactionState::RecoveryRequired
        );
    }

    #[test]
    fn committed_terminal_then_second_same_target_transaction_succeeds() {
        let fixture = Fixture::new();
        let first = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-committed-first\n"),
                "tx-committed-first",
            )
            .unwrap();
        fixture.store.persist_started(&first).unwrap();
        fixture.store.persist_committed(&first).unwrap();

        let second = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-committed-second\n"),
                "tx-committed-second",
            )
            .unwrap();
        fixture.store.persist_started(&second).unwrap();

        let scan = fixture.store.scan_transactions().unwrap();
        assert!(!scan.has_ambiguous_target());
        assert_eq!(scan.actionable_recovery_transactions().count(), 1);
        assert_eq!(
            scan.valid_transactions()
                .find(|snapshot| snapshot.journal().transaction_id() == first.transaction_id())
                .unwrap()
                .state(),
            RecoveryTransactionState::CommittedTerminal
        );
        assert_eq!(
            scan.valid_transactions()
                .find(|snapshot| snapshot.journal().transaction_id() == second.transaction_id())
                .unwrap()
                .state(),
            RecoveryTransactionState::RecoveryRequired
        );
    }

    #[test]
    fn recovered_terminal_then_second_same_target_transaction_succeeds() {
        let fixture = Fixture::new();
        let first = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-recovered-first\n"),
                "tx-recovered-first",
            )
            .unwrap();
        fixture.store.persist_started(&first).unwrap();
        fixture.store.persist_recovered(&first).unwrap();

        let second = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-recovered-second\n"),
                "tx-recovered-second",
            )
            .unwrap();
        fixture.store.persist_started(&second).unwrap();

        let scan = fixture.store.scan_transactions().unwrap();
        assert!(!scan.has_ambiguous_target());
        assert_eq!(scan.actionable_recovery_transactions().count(), 1);
        assert_eq!(
            scan.valid_transactions()
                .find(|snapshot| snapshot.journal().transaction_id() == first.transaction_id())
                .unwrap()
                .state(),
            RecoveryTransactionState::RecoveredTerminal
        );
        assert_eq!(
            scan.valid_transactions()
                .find(|snapshot| snapshot.journal().transaction_id() == second.transaction_id())
                .unwrap()
                .state(),
            RecoveryTransactionState::RecoveryRequired
        );
    }

    #[test]
    fn prepared_only_history_then_new_same_target_transaction_succeeds() {
        let fixture = Fixture::new();
        let first = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-prepared-first\n"),
                "tx-prepared-first",
            )
            .unwrap();
        assert_eq!(
            fixture
                .store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .find(|snapshot| snapshot.journal().transaction_id() == first.transaction_id())
                .unwrap()
                .state(),
            RecoveryTransactionState::PreparedOnly
        );

        let second = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-prepared-second\n"),
                "tx-prepared-second",
            )
            .unwrap();
        fixture.store.persist_started(&second).unwrap();

        let scan = fixture.store.scan_transactions().unwrap();
        assert!(!scan.has_ambiguous_target());
        assert_eq!(scan.actionable_recovery_transactions().count(), 1);
    }

    #[test]
    fn two_terminal_histories_then_new_same_target_transaction_succeeds() {
        let fixture = Fixture::new();
        let committed = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-terminal-committed\n"),
                "tx-terminal-committed",
            )
            .unwrap();
        fixture.store.persist_started(&committed).unwrap();
        fixture.store.persist_committed(&committed).unwrap();

        let recovered = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-terminal-recovered\n"),
                "tx-terminal-recovered",
            )
            .unwrap();
        fixture.store.persist_started(&recovered).unwrap();
        fixture.store.persist_recovered(&recovered).unwrap();

        let next = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-terminal-next\n"),
                "tx-terminal-next",
            )
            .unwrap();
        fixture.store.persist_started(&next).unwrap();

        let scan = fixture.store.scan_transactions().unwrap();
        assert!(!scan.has_ambiguous_target());
        assert_eq!(scan.actionable_recovery_transactions().count(), 1);
        assert_eq!(
            scan.valid_transactions()
                .find(|snapshot| snapshot.journal().transaction_id() == next.transaction_id())
                .unwrap()
                .state(),
            RecoveryTransactionState::RecoveryRequired
        );
    }

    #[test]
    fn committed_plus_recovery_required_keeps_one_actionable_recovery() {
        let fixture = Fixture::new();
        let terminal = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-terminal\n"),
                "tx-terminal-before-active",
            )
            .unwrap();
        fixture.store.persist_started(&terminal).unwrap();
        fixture.store.persist_committed(&terminal).unwrap();
        let active = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-active\n"),
                "tx-active-after-terminal",
            )
            .unwrap();
        fixture.store.persist_started(&active).unwrap();

        let scan = fixture.store.scan_transactions().unwrap();
        assert!(!scan.has_ambiguous_target());
        assert_eq!(scan.actionable_recovery_transactions().count(), 1);
        assert_eq!(
            scan.valid_transactions()
                .filter(|snapshot| snapshot.state() == RecoveryTransactionState::CommittedTerminal)
                .count(),
            1
        );
    }

    #[test]
    fn recovered_plus_recovery_required_keeps_one_actionable_recovery() {
        let fixture = Fixture::new();
        let terminal = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-terminal\n"),
                "tx-recovered-before-active",
            )
            .unwrap();
        fixture.store.persist_started(&terminal).unwrap();
        fixture.store.persist_recovered(&terminal).unwrap();
        let active = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-active\n"),
                "tx-active-after-recovered",
            )
            .unwrap();
        fixture.store.persist_started(&active).unwrap();

        let scan = fixture.store.scan_transactions().unwrap();
        assert!(!scan.has_ambiguous_target());
        assert_eq!(scan.actionable_recovery_transactions().count(), 1);
        assert_eq!(
            scan.valid_transactions()
                .filter(|snapshot| snapshot.state() == RecoveryTransactionState::RecoveredTerminal)
                .count(),
            1
        );
    }

    #[test]
    fn two_recovery_required_same_target_is_ambiguous_actionable_zero() {
        let fixture = Fixture::new();
        let first = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-first\n"),
                "tx-active-first",
            )
            .unwrap();
        fixture.store.persist_started(&first).unwrap();
        let second = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-second\n"),
                "tx-active-second",
            )
            .unwrap();
        create_marker_for_scan(
            &fixture,
            second.transaction_id().clone(),
            second.integrity_hash_bytes(),
            RecoveryMarkerState::Started,
        );

        let scan = fixture.store.scan_transactions().unwrap();
        assert!(scan.has_ambiguous_target());
        assert_eq!(scan.actionable_recovery_transactions().count(), 0);
        assert!(scan.items().iter().any(|item| matches!(
            item,
            RecoveryTransactionScanItem::AmbiguousTarget { transactions, .. }
                if transactions.len() == 2
        )));
    }

    #[test]
    fn poisoned_known_target_blocks_exact_target_only() {
        let fixture = Fixture::new();
        let target_a = fixture.target();
        let target_b = fixture.create_target("target-b.txt", b"before-b\n");
        let poisoned = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &target_a,
                fixture.context(b"after-poisoned\n"),
                "tx-poisoned-target",
            )
            .unwrap();
        create_marker_for_scan(
            &fixture,
            poisoned.transaction_id().clone(),
            [0x44; 32],
            RecoveryMarkerState::Started,
        );
        let valid = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &target_b,
                fixture.context(b"after-valid\n"),
                "tx-valid-target",
            )
            .unwrap();
        fixture.store.persist_started(&valid).unwrap();

        let scan = fixture.store.scan_transactions().unwrap();
        let target_a_key = mutation_target_key_for_prepared_target(&target_a).unwrap();
        let target_b_key = mutation_target_key_for_prepared_target(&target_b).unwrap();
        assert_eq!(
            scan.target_lifecycle(&target_a_key),
            RecoveryTargetLifecycle::Poisoned
        );
        assert_eq!(
            scan.target_lifecycle(&target_b_key),
            RecoveryTargetLifecycle::RecoveryRequired
        );
        assert_eq!(scan.actionable_recovery_transactions().count(), 1);
        assert_eq!(scan.poisoned_targets().count(), 1);
    }

    #[test]
    fn case_alias_pending_recovery_has_one_mutation_target_identity() {
        let fixture = Fixture::new();
        let original = fixture.target_named("target.txt");
        let alias = fixture.target_named("TARGET.TXT");
        let original_key = mutation_target_key_for_prepared_target(&original).unwrap();
        let alias_key = mutation_target_key_for_prepared_target(&alias).unwrap();
        assert_eq!(original_key, alias_key);
        let journal = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &original,
                fixture.context(b"case-alias-replacement\n"),
                "tx-case-alias",
            )
            .unwrap();
        fixture.store.persist_started(&journal).unwrap();
        let scan = fixture.store.scan_transactions().unwrap();
        assert_eq!(
            scan.target_lifecycle(&alias_key),
            RecoveryTargetLifecycle::RecoveryRequired
        );
    }

    #[test]
    fn rename_alias_pending_recovery_has_one_mutation_target_identity() {
        let fixture = Fixture::new();
        let original = fixture.target_named("target.txt");
        let original_key = mutation_target_key_for_prepared_target(&original).unwrap();
        let journal = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &original,
                fixture.context(b"rename-alias-replacement\n"),
                "tx-rename-alias",
            )
            .unwrap();
        fixture.store.persist_started(&journal).unwrap();
        fs::rename(
            fixture.workspace.path().join("target.txt"),
            fixture.workspace.path().join("renamed-target.txt"),
        )
        .unwrap();
        let renamed = fixture.target_named("renamed-target.txt");
        let renamed_key = mutation_target_key_for_prepared_target(&renamed).unwrap();
        assert_eq!(original_key, renamed_key);
        assert_eq!(
            fixture
                .store
                .scan_transactions()
                .unwrap()
                .target_lifecycle(&renamed_key),
            RecoveryTargetLifecycle::RecoveryRequired
        );
    }

    #[test]
    fn hardlink_alias_pending_recovery_has_one_mutation_target_identity() {
        let fixture = Fixture::new();
        let original = fixture.target_named("target.txt");
        fs::hard_link(
            fixture.workspace.path().join("target.txt"),
            fixture.workspace.path().join("hardlink-target.txt"),
        )
        .unwrap();
        let alias = fixture.target_named("hardlink-target.txt");
        let original_key = mutation_target_key_for_prepared_target(&original).unwrap();
        let alias_key = mutation_target_key_for_prepared_target(&alias).unwrap();
        assert_eq!(original_key, alias_key);
        let journal = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &original,
                fixture.context(b"hardlink-alias-replacement\n"),
                "tx-hardlink-alias",
            )
            .unwrap();
        create_marker_for_scan(
            &fixture,
            journal.transaction_id().clone(),
            journal.integrity_hash_bytes(),
            RecoveryMarkerState::Started,
        );
        let scan = fixture.store.scan_transactions().unwrap();
        assert_eq!(
            scan.target_lifecycle(&alias_key),
            RecoveryTargetLifecycle::RecoveryRequired
        );
    }

    #[test]
    fn alias_multiple_recovery_required_is_ambiguous() {
        let fixture = Fixture::new();
        let first_target = fixture.target_named("target.txt");
        let second_target = fixture.target_named("TARGET.TXT");
        let first = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &first_target,
                fixture.context(b"alias-first\n"),
                "tx-alias-first",
            )
            .unwrap();
        fixture.store.persist_started(&first).unwrap();
        let second = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &second_target,
                fixture.context(b"alias-second\n"),
                "tx-alias-second",
            )
            .unwrap();
        create_marker_for_scan(
            &fixture,
            second.transaction_id().clone(),
            second.integrity_hash_bytes(),
            RecoveryMarkerState::Started,
        );
        let key = mutation_target_key_for_prepared_target(&first_target).unwrap();
        let scan = fixture.store.scan_transactions().unwrap();
        assert_eq!(
            scan.target_lifecycle(&key),
            RecoveryTargetLifecycle::Ambiguous
        );
        assert_eq!(scan.actionable_recovery_transactions().count(), 0);
        assert!(scan.items().iter().any(|item| matches!(
            item,
            RecoveryTransactionScanItem::AmbiguousTarget { transactions, .. }
                if transactions.len() == 2
        )));
    }

    #[test]
    fn poisoned_target_plus_valid_recovery_is_not_actionable() {
        let fixture = Fixture::new();
        let poisoned_target = fixture.target_named("target.txt");
        let valid_alias = fixture.target_named("TARGET.TXT");
        let poisoned = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &poisoned_target,
                fixture.context(b"poisoned-alias\n"),
                "tx-poisoned-alias",
            )
            .unwrap();
        create_marker_for_scan(
            &fixture,
            poisoned.transaction_id().clone(),
            [0x55; 32],
            RecoveryMarkerState::Started,
        );
        let valid = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &valid_alias,
                fixture.context(b"valid-alias\n"),
                "tx-valid-alias",
            )
            .unwrap();
        create_marker_for_scan(
            &fixture,
            valid.transaction_id().clone(),
            valid.integrity_hash_bytes(),
            RecoveryMarkerState::Started,
        );
        let key = mutation_target_key_for_prepared_target(&poisoned_target).unwrap();
        let scan = fixture.store.scan_transactions().unwrap();
        assert_eq!(
            scan.target_lifecycle(&key),
            RecoveryTargetLifecycle::Poisoned
        );
        assert_eq!(scan.actionable_recovery_transactions().count(), 0);
        assert_eq!(scan.poisoned_targets().count(), 1);
    }

    #[test]
    fn transaction_scanner_rejects_tampered_marker_bytes() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        let marker = RecoveryMarkerV1::new(
            journal.transaction_id().clone(),
            journal.integrity_hash_bytes(),
            RecoveryMarkerState::Started,
        );
        let mut bytes = marker.to_bytes().expect("marker fixture bytes");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(
            fixture.store.recovery_root().join(marker.file_name()),
            bytes,
        )
        .expect("tampered marker fixture");

        let scan = fixture.store.scan_transactions().expect("strict scan");
        assert!(scan.valid_transactions().next().is_none());
        assert!(scan.actionable_recovery_transactions().next().is_none());
        assert!(scan.items().iter().any(|item| matches!(
            item,
            RecoveryTransactionScanItem::CorruptArtifact {
                reason: "marker integrity hash mismatch",
                ..
            }
        )));
    }

    #[test]
    fn unsupported_marker_version_poison_transaction() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        let marker = RecoveryMarkerV1::new(
            journal.transaction_id().clone(),
            journal.integrity_hash_bytes(),
            RecoveryMarkerState::Started,
        );
        let mut bytes = marker.to_bytes().expect("marker fixture bytes");
        bytes[4..6].copy_from_slice(&2_u16.to_le_bytes());
        fs::write(
            fixture
                .store
                .recovery_root()
                .join(format!("{}.started", journal.transaction_id().as_str())),
            bytes,
        )
        .expect("unsupported marker version fixture");

        let scan = fixture.store.scan_transactions().expect("strict scan");
        assert!(scan.valid_transactions().next().is_none());
        assert!(scan.actionable_recovery_transactions().next().is_none());
        assert!(scan.items().iter().any(|item| matches!(
            item,
            RecoveryTransactionScanItem::CorruptArtifact {
                reason: "unsupported marker version",
                ..
            }
        )));
    }

    #[test]
    fn marker_payload_transaction_mismatch_poison_filename_transaction() {
        let fixture = Fixture::new();
        let journal_a = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal A");
        let transaction_b = RecoveryTransactionId::parse("h5-marker-payload-b").unwrap();
        let marker_b = RecoveryMarkerV1::new(
            transaction_b,
            journal_a.integrity_hash_bytes(),
            RecoveryMarkerState::Started,
        );
        fs::write(
            fixture
                .store
                .recovery_root()
                .join(format!("{}.started", journal_a.transaction_id().as_str())),
            marker_b.to_bytes().expect("marker payload fixture bytes"),
        )
        .expect("mismatched marker filename fixture");

        let scan = fixture.store.scan_transactions().expect("strict scan");
        assert!(scan.valid_transactions().next().is_none());
        assert!(scan.actionable_recovery_transactions().next().is_none());
        assert!(scan.items().iter().any(|item| matches!(
            item,
            RecoveryTransactionScanItem::CorruptArtifact {
                reason: "transaction has corrupt lifecycle evidence",
                ..
            }
        )));
    }

    #[test]
    fn tampered_committed_marker_poison_transaction() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        fixture
            .store
            .persist_started(&journal)
            .expect("Started marker");
        let committed = fixture
            .store
            .persist_committed(&journal)
            .expect("Committed marker");
        let mut bytes = committed.to_bytes().expect("Committed marker bytes");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(
            fixture.store.recovery_root().join(committed.file_name()),
            bytes,
        )
        .expect("tampered Committed marker");

        let scan = fixture.store.scan_transactions().expect("strict scan");
        assert!(scan.valid_transactions().next().is_none());
        assert!(scan.actionable_recovery_transactions().next().is_none());
        assert!(scan.items().iter().any(|item| matches!(
            item,
            RecoveryTransactionScanItem::CorruptArtifact {
                reason: "transaction has corrupt lifecycle evidence",
                ..
            }
        )));
    }

    #[test]
    fn tampered_recovered_marker_poison_transaction() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        fixture
            .store
            .persist_started(&journal)
            .expect("Started marker");
        let recovered = fixture
            .store
            .persist_recovered(&journal)
            .expect("Recovered marker");
        let mut bytes = recovered.to_bytes().expect("Recovered marker bytes");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(
            fixture.store.recovery_root().join(recovered.file_name()),
            bytes,
        )
        .expect("tampered Recovered marker");

        let scan = fixture.store.scan_transactions().expect("strict scan");
        assert!(scan.valid_transactions().next().is_none());
        assert!(scan.actionable_recovery_transactions().next().is_none());
        assert!(scan.items().iter().any(|item| matches!(
            item,
            RecoveryTransactionScanItem::CorruptArtifact {
                reason: "transaction has corrupt lifecycle evidence",
                ..
            }
        )));
    }

    #[test]
    fn recognized_marker_read_failure_poison_transaction() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        let marker_name = format!("{}.started", journal.transaction_id().as_str());
        fs::create_dir(fixture.store.recovery_root().join(&marker_name))
            .expect("marker directory fixture");

        let scan = fixture.store.scan_transactions().expect("strict scan");
        assert!(scan.valid_transactions().next().is_none());
        assert!(scan.actionable_recovery_transactions().next().is_none());
        assert!(scan.items().iter().any(|item| matches!(
            item,
            RecoveryTransactionScanItem::CorruptArtifact { file_name, .. }
                if file_name == &marker_name
        )));
    }

    #[test]
    fn unrelated_valid_transaction_survives_other_transaction_corruption() {
        let fixture = Fixture::new();
        let a = fixture.create_target("a.txt", b"a-before\n");
        let b = fixture.create_target("b.txt", b"b-before\n");
        let journal_a = fixture
            .store
            .create_prepared(&a, fixture.context(b"a-after\n"))
            .expect("journal A");
        let journal_b = fixture
            .store
            .create_prepared(&b, fixture.context(b"b-after\n"))
            .expect("journal B");
        let marker_a = RecoveryMarkerV1::new(
            journal_a.transaction_id().clone(),
            journal_a.integrity_hash_bytes(),
            RecoveryMarkerState::Started,
        );
        let mut corrupt_a = marker_a.to_bytes().expect("marker A bytes");
        let last = corrupt_a.len() - 1;
        corrupt_a[last] ^= 0x01;
        fs::write(
            fixture.store.recovery_root().join(marker_a.file_name()),
            corrupt_a,
        )
        .expect("corrupt marker A");
        create_marker_for_scan(
            &fixture,
            journal_b.transaction_id().clone(),
            journal_b.integrity_hash_bytes(),
            RecoveryMarkerState::Started,
        );

        let scan = fixture.store.scan_transactions().expect("strict scan");
        let valid = scan.valid_transactions().collect::<Vec<_>>();
        assert_eq!(valid.len(), 1);
        assert_eq!(
            valid[0].journal().transaction_id(),
            journal_b.transaction_id()
        );
        assert_eq!(scan.actionable_recovery_transactions().count(), 1);
    }

    #[test]
    fn marker_create_and_reopen_stay_in_retained_recovery_namespace() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        let replacement = replace_recovery_root_with_junction(&fixture);
        fixture
            .store
            .persist_started(&journal)
            .expect("retained Started marker");
        fixture
            .store
            .persist_committed(&journal)
            .expect("retained Committed marker");
        let started_name = format!("{}.started", journal.transaction_id().as_str());
        let committed_name = format!("{}.committed", journal.transaction_id().as_str());
        assert!(replacement.moved.join(&started_name).is_file());
        assert!(replacement.moved.join(&committed_name).is_file());
        assert!(!replacement._outside.path().join(&started_name).exists());
        assert!(!replacement._outside.path().join(&committed_name).exists());

        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        fixture.store.persist_started(&journal).unwrap();
        let replacement = replace_recovery_root_with_junction(&fixture);
        fixture
            .store
            .persist_recovered(&journal)
            .expect("retained Recovered marker");
        let recovered_name = format!("{}.recovered", journal.transaction_id().as_str());
        assert!(replacement.moved.join(&recovered_name).is_file());
        assert!(!replacement._outside.path().join(&recovered_name).exists());
    }

    #[test]
    fn recovery_root_replacement_cannot_redirect_create() {
        let fixture = Fixture::new();
        let replacement = replace_recovery_root_with_junction(&fixture);
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("create must remain on original retained root");
        let name = journal_file_name(journal.transaction_id());
        assert!(replacement.moved.join(&name).is_file());
        assert!(!replacement._outside.path().join(&name).exists());
    }

    #[test]
    fn recovery_root_replacement_cannot_redirect_scan() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        let name = journal_file_name(journal.transaction_id());
        let replacement = replace_recovery_root_with_junction(&fixture);
        fs::write(
            replacement._outside.path().join(&name),
            journal.to_bytes().unwrap(),
        )
        .expect("outside forged journal fixture");
        let scan = fixture.store.scan().expect("retained root scan");
        assert_eq!(scan.actionable_prepared_journals().count(), 1);
        assert_eq!(scan.ambiguous_pending_recoveries().count(), 0);
    }

    #[test]
    fn recovery_parent_reparse_is_rejected_at_acquisition() {
        let fixture = Fixture::new();
        let _replacement = replace_recovery_root_with_junction(&fixture);
        let result = RecoveryJournalStore::from_runtime_profile(&fixture.profile);
        assert!(
            result.is_err(),
            "a reparse recovery parent must not become namespace authority"
        );
    }

    #[test]
    fn journal_child_reparse_is_not_followed() {
        use std::os::windows::fs::symlink_file;

        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .expect("prepared journal");
        let outside = tempdir().expect("outside child fixture");
        let outside_file = outside.path().join("outside.dlrj");
        fs::write(&outside_file, journal.to_bytes().unwrap()).expect("outside child payload");
        let child = fixture.store.recovery_root().join("tx-child.dlrj");
        symlink_file(&outside_file, &child).expect("create child reparse fixture");

        let scan = fixture.store.scan().expect("child reparse scan");
        assert_eq!(scan.actionable_prepared_journals().count(), 1);
        assert!(scan.items().iter().any(|item| matches!(
            item,
            RecoveryJournalScanItem::CorruptJournal { file_name, .. }
                if file_name == "tx-child.dlrj"
        )));
        assert_eq!(fs::read(outside_file).unwrap(), journal.to_bytes().unwrap());
    }

    #[test]
    fn prepared_requires_successful_flush_and_reopen_verify() {
        for fault in [
            RecoveryJournalTestFault::Write,
            RecoveryJournalTestFault::Flush,
            RecoveryJournalTestFault::Truncate,
            RecoveryJournalTestFault::BadIntegrity,
            RecoveryJournalTestFault::Reopen,
        ] {
            let fixture = Fixture::new();
            let result = fixture.store.create_prepared_with_fault_for_test(
                &fixture.target(),
                fixture.context(b"after\n"),
                fault,
            );
            assert!(result.is_err(), "fault {fault:?} must not produce Prepared");
            let scan = fixture.store.scan().unwrap();
            assert_eq!(scan.valid_prepared_journals().count(), 0, "fault {fault:?}");
        }
    }

    #[test]
    fn restart_scan_finds_valid_prepared_journal() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .unwrap();
        let restarted = RecoveryJournalStore::from_runtime_profile(&fixture.profile).unwrap();
        let scan = restarted.scan().unwrap();
        assert_eq!(scan.valid_prepared_journals().count(), 1);
        assert_eq!(scan.valid_prepared_journals().next(), Some(&journal));
    }

    #[test]
    fn restart_scan_does_not_mutate_workspace() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .unwrap();
        let workspace_path = fixture.workspace.path().join("target.txt");
        let before = fs::read(&workspace_path).unwrap();
        let metadata_before = fs::metadata(&workspace_path).unwrap();
        let _ = fixture.store.scan().unwrap();
        assert_eq!(fs::read(&workspace_path).unwrap(), before);
        assert_eq!(
            fs::metadata(&workspace_path).unwrap().len(),
            metadata_before.len()
        );
        assert!(fixture.path_for(&journal).is_file());
    }

    #[test]
    fn restart_scan_still_mutates_workspace_zero() {
        let fixture = Fixture::new();
        let workspace_path = fixture.workspace.path().join("target.txt");
        let before = fs::read(&workspace_path).unwrap();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .unwrap();
        let _scan = RecoveryJournalStore::from_runtime_profile(&fixture.profile)
            .unwrap()
            .scan()
            .unwrap();
        assert_eq!(fs::read(&workspace_path).unwrap(), before);
        assert!(fixture.path_for(&journal).is_file());
    }

    #[test]
    fn two_pending_journals_for_same_target_are_ambiguous() {
        let fixture = Fixture::new();
        fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-1\n"),
                "tx-one",
            )
            .unwrap();
        fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"after-2\n"),
                "tx-two",
            )
            .unwrap();
        let scan = fixture.store.scan().unwrap();
        assert!(scan.has_ambiguous_pending_recovery());
        assert_eq!(scan.actionable_prepared_journals().count(), 0);
        let ambiguity = scan.ambiguous_pending_recoveries().next().unwrap();
        assert_eq!(ambiguity.1.len(), 2);
    }

    #[test]
    fn two_pending_same_target_have_zero_actionable_candidates() {
        let fixture = Fixture::new();
        for (transaction_id, replacement) in [
            ("tx-two-a", b"after-a\n".as_slice()),
            ("tx-two-b", b"after-b\n"),
        ] {
            fixture
                .store
                .create_prepared_with_transaction_id_for_test(
                    &fixture.target(),
                    fixture.context(replacement),
                    transaction_id,
                )
                .unwrap();
        }
        let scan = fixture.store.scan().unwrap();
        assert_eq!(scan.actionable_prepared_journals().count(), 0);
        let ambiguity = scan.ambiguous_pending_recoveries().collect::<Vec<_>>();
        assert_eq!(ambiguity.len(), 1);
        assert_eq!(ambiguity[0].1.len(), 2);
    }

    #[test]
    fn three_pending_same_target_have_zero_actionable_candidates() {
        let fixture = Fixture::new();
        for (transaction_id, replacement) in [
            ("tx-three-a", b"after-a\n".as_slice()),
            ("tx-three-b", b"after-b\n"),
            ("tx-three-c", b"after-c\n"),
        ] {
            fixture
                .store
                .create_prepared_with_transaction_id_for_test(
                    &fixture.target(),
                    fixture.context(replacement),
                    transaction_id,
                )
                .unwrap();
        }
        let scan = fixture.store.scan().unwrap();
        assert_eq!(scan.actionable_prepared_journals().count(), 0);
        let ambiguity = scan.ambiguous_pending_recoveries().collect::<Vec<_>>();
        assert_eq!(ambiguity.len(), 1);
        assert_eq!(ambiguity[0].1.len(), 3);
    }

    #[test]
    fn unique_target_remains_actionable_beside_ambiguous_target() {
        let fixture = Fixture::new();
        let target_a = fixture.target();
        let target_b = fixture.create_target("target-b.txt", b"before-b\n");
        for (transaction_id, replacement) in [
            ("tx-ambiguous-a", b"after-a\n".as_slice()),
            ("tx-ambiguous-b", b"after-b\n"),
        ] {
            fixture
                .store
                .create_prepared_with_transaction_id_for_test(
                    &target_a,
                    fixture.context(replacement),
                    transaction_id,
                )
                .unwrap();
        }
        fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &target_b,
                fixture.context(b"unique-after\n"),
                "tx-unique",
            )
            .unwrap();

        let scan = fixture.store.scan().unwrap();
        let actionable = scan.actionable_prepared_journals().collect::<Vec<_>>();
        assert_eq!(actionable.len(), 1);
        assert_eq!(
            actionable[0].relative_path().as_path(),
            Path::new("target-b.txt")
        );
        let ambiguous = scan.ambiguous_pending_recoveries().collect::<Vec<_>>();
        assert_eq!(ambiguous.len(), 1);
        assert_eq!(ambiguous[0].0.relative_path(), "target.txt");
    }

    #[test]
    fn ambiguity_result_is_independent_of_enumeration_order() {
        let fixture = Fixture::new();
        let first = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"first\n"),
                "tx-order-a",
            )
            .unwrap();
        let second = fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"second\n"),
                "tx-order-b",
            )
            .unwrap();

        let forward = finalize_scan_items(vec![
            RecoveryJournalScanItem::ValidPreparedJournal(first.clone()),
            RecoveryJournalScanItem::ValidPreparedJournal(second.clone()),
        ]);
        let reverse = finalize_scan_items(vec![
            RecoveryJournalScanItem::ValidPreparedJournal(second),
            RecoveryJournalScanItem::ValidPreparedJournal(first),
        ]);
        assert_eq!(forward, reverse);
        assert_eq!(forward.actionable_prepared_journals().count(), 0);
        assert_eq!(reverse.actionable_prepared_journals().count(), 0);
    }

    #[test]
    fn ambiguous_pending_never_selects_first_or_newest() {
        let fixture = Fixture::new();
        fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"first\n"),
                "tx-first",
            )
            .unwrap();
        fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(b"newest\n"),
                "tx-newest",
            )
            .unwrap();

        let scan = fixture.store.scan().unwrap();
        assert_eq!(scan.valid_prepared_journals().count(), 0);
        assert_eq!(scan.actionable_prepared_journals().count(), 0);
        let transactions = scan
            .ambiguous_pending_recoveries()
            .next()
            .expect("ambiguous pending target")
            .1;
        assert_eq!(transactions.len(), 2);
        assert!(transactions.iter().any(|id| id.as_str() == "tx-first"));
        assert!(transactions.iter().any(|id| id.as_str() == "tx-newest"));
    }

    #[test]
    fn target_divergence_is_read_only_classification() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .unwrap();
        let workspace_path = fixture.workspace.path().join("target.txt");
        fs::write(&workspace_path, "diverged\n").unwrap();
        let result = fixture.store.reconcile_prepared(&journal).unwrap();
        assert_eq!(result, RecoveryJournalReconciliation::Diverged);
        assert_eq!(fs::read(&workspace_path).unwrap(), b"diverged\n");
    }

    #[test]
    fn h5a_workspace_mutation_count_is_zero() {
        let fixture = Fixture::new();
        let workspace_path = fixture.workspace.path().join("target.txt");
        let before = fs::read(&workspace_path).unwrap();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context(b"after\n"))
            .unwrap();
        let _ = fixture.store.reconcile_prepared(&journal).unwrap();
        let after = fs::read(&workspace_path).unwrap();
        assert_eq!(before, after);
        // The only H5-A workspace operation is the H4 bounded read; no create,
        // write, delete, rename, or replacement primitive is reachable here.
    }

    #[test]
    fn production_registry_contains_only_read_only_h7c() {
        let source = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .expect("Vita manifest has repository parent")
                .join("src-tauri/src/capability/descriptor.rs"),
        )
        .unwrap();
        assert!(source.contains("PRODUCTION_GIT_STATUS_CAPABILITY_ID"));
        assert!(!source.contains("vita.workspace.recover_replace"));
    }

    #[test]
    fn schema30_migration031_absent() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let connection =
            fs::read_to_string(manifest.join("../src-tauri/src/storage/connection.rs")).unwrap();
        let migration_dir = manifest.join("../src-tauri/src/storage/migrations");
        assert!(connection.contains("MAX_SUPPORTED_SCHEMA_VERSION: i64 = 30"));
        assert!(!connection.contains("Migration031"));
        assert!(!migration_dir.join("031_recovery_journal.sql").exists());
    }

    #[test]
    fn user_codex_untouched() {
        assert_eq!(
            CODEX_UPSTREAM_COMMIT,
            "316795b3cf2a45e90d121d9f46499d4658b2645c"
        );
        let fixture = Fixture::new();
        assert!(!contains_stock_codex_state(fixture.store.recovery_root()));
        assert!(!contains_stock_codex_state(fixture.profile.kernel_home()));
    }
}
