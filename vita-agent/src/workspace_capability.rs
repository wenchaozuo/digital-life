//! Capability-safe workspace path preparation.
//!
//! The H2 boundary is deliberately narrower than an executor.  It acquires
//! one trusted directory handle and can prepare a relative resource by
//! walking from that handle.  The result contains identity and lifetime
//! information only; it has no read, write, execute, or authorization API.

use std::ffi::{OsStr, OsString};
use std::fmt::{self, Display};
use std::io;
#[cfg(windows)]
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::{contains_stock_codex_state, VitaAgentError};

const TARGET_FIELD: &str = "workspace_target";
const ROOT_FIELD: &str = "workspace_root";
const MAX_COMPONENTS: usize = 256;
const MAX_UTF16_UNITS: usize = 32_767;

/// A validated, relative workspace name.
///
/// This type intentionally does not expose a filesystem operation.  It only
/// carries the component sequence that the capability walker is allowed to
/// resolve beneath an already acquired root handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkspaceRelativePath {
    path: PathBuf,
    components: Vec<OsString>,
}

impl WorkspaceRelativePath {
    pub fn parse(path: &Path) -> Result<Self, VitaAgentError> {
        let raw = path.to_string_lossy();
        if raw.is_empty() {
            return Err(unsafe_relative_path(path, "empty path is ambiguous"));
        }

        let mut previous_was_separator = false;
        let mut saw_separator = false;
        for character in raw.chars() {
            if character == '/' || character == '\\' {
                if previous_was_separator {
                    return Err(unsafe_relative_path(
                        path,
                        "repeated separators are ambiguous",
                    ));
                }
                previous_was_separator = true;
                saw_separator = true;
                continue;
            }
            previous_was_separator = false;
            if character == ':' {
                return Err(unsafe_relative_path(
                    path,
                    "alternate data streams and qualified paths are forbidden",
                ));
            }
            if character.is_control() || character == '\0' {
                return Err(unsafe_relative_path(
                    path,
                    "control characters are forbidden",
                ));
            }
            #[cfg(windows)]
            if matches!(character, '<' | '>' | '"' | '|' | '?' | '*') {
                return Err(unsafe_relative_path(
                    path,
                    "Windows-invalid filename characters are forbidden",
                ));
            }
        }

        if raw.starts_with('/') || raw.starts_with('\\') {
            return Err(unsafe_relative_path(
                path,
                "rooted, UNC, or device paths are forbidden",
            ));
        }
        if raw.ends_with('/') || raw.ends_with('\\') {
            return Err(unsafe_relative_path(
                path,
                "trailing separators are ambiguous",
            ));
        }

        let components = path
            .components()
            .map(|component| match component {
                Component::Normal(value) => Ok(value.to_os_string()),
                Component::Prefix(_) => Err(unsafe_relative_path(
                    path,
                    "drive-qualified, UNC, or device paths are forbidden",
                )),
                Component::RootDir => Err(unsafe_relative_path(
                    path,
                    "rooted, UNC, or device paths are forbidden",
                )),
                Component::CurDir => Err(unsafe_relative_path(
                    path,
                    "current-directory components are ambiguous",
                )),
                Component::ParentDir => {
                    Err(unsafe_relative_path(path, "parent traversal is forbidden"))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        if components.is_empty() {
            return Err(unsafe_relative_path(path, "path has no usable components"));
        }
        if components.len() > MAX_COMPONENTS {
            return Err(unsafe_relative_path(path, "too many path components"));
        }
        if !saw_separator && components.len() != 1 {
            return Err(unsafe_relative_path(
                path,
                "path component parsing is ambiguous",
            ));
        }

        for component in &components {
            validate_component(path, component)?;
        }

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;

            let utf16_units = path.as_os_str().encode_wide().count();
            if utf16_units > MAX_UTF16_UNITS {
                return Err(unsafe_relative_path(path, "path is too long"));
            }
        }

        Ok(Self {
            path: path.to_path_buf(),
            components,
        })
    }

    pub fn as_path(&self) -> &Path {
        &self.path
    }

    pub fn to_path_buf(&self) -> PathBuf {
        self.path.clone()
    }

    pub fn components(&self) -> impl ExactSizeIterator<Item = &OsStr> {
        self.components.iter().map(OsString::as_os_str)
    }
}

fn validate_component(path: &Path, component: &OsStr) -> Result<(), VitaAgentError> {
    if component.is_empty() {
        return Err(unsafe_relative_path(
            path,
            "empty path component is ambiguous",
        ));
    }

    let text = component.to_string_lossy();
    if text.ends_with('.') || text.ends_with(' ') {
        return Err(unsafe_relative_path(
            path,
            "trailing dots and spaces are forbidden",
        ));
    }

    let device_name = text
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
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
        return Err(unsafe_relative_path(
            path,
            "reserved Windows device names are forbidden",
        ));
    }

    Ok(())
}

fn unsafe_relative_path(path: &Path, reason: &'static str) -> VitaAgentError {
    VitaAgentError::UnsafePath {
        field: TARGET_FIELD,
        path: path.to_path_buf(),
        reason,
    }
}

/// Stable file identity captured from a verified handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WorkspaceRootIdentity {
    #[cfg(windows)]
    volume_serial_number: u64,
    #[cfg(windows)]
    file_id: [u8; 16],
    #[cfg(not(windows))]
    unavailable: (),
}

impl WorkspaceRootIdentity {
    #[cfg(windows)]
    fn windows(volume_serial_number: u64, file_id: [u8; 16]) -> Self {
        Self {
            volume_serial_number,
            file_id,
        }
    }

    #[cfg(not(windows))]
    fn unavailable() -> Self {
        Self { unavailable: () }
    }

    pub fn volume_serial_number(&self) -> Option<u64> {
        #[cfg(windows)]
        {
            Some(self.volume_serial_number)
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    pub fn file_id(&self) -> Option<[u8; 16]> {
        #[cfg(windows)]
        {
            Some(self.file_id)
        }
        #[cfg(not(windows))]
        {
            None
        }
    }
}

/// Classification of a prepared resource.  `Missing` is identity-only and
/// does not mean that any creation or mutation occurred.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreparedWorkspaceTargetKind {
    ExistingFile,
    ExistingDirectory,
    Missing,
}

/// The hard ceiling for the first governed workspace read.  The limit is a
/// kernel-side execution bound, not a hint supplied by the model.
pub(crate) const WORKSPACE_READ_HARD_MAX_BYTES: usize = 64 * 1024;

/// The hard ceiling for the H4-B in-place existing-file mutation primitive.
/// It is deliberately independent from any caller-supplied value.
#[allow(dead_code)]
pub(crate) const WORKSPACE_REPLACE_HARD_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub(crate) enum WorkspaceReadError {
    InvalidTarget(&'static str),
    TooLarge { limit: usize },
    InvalidUtf8,
    Kernel(VitaAgentError),
}

impl fmt::Display for WorkspaceReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTarget(reason) => write!(formatter, "workspace read denied: {reason}"),
            Self::TooLarge { limit } => {
                write!(
                    formatter,
                    "workspace file exceeds the {limit}-byte read limit"
                )
            }
            Self::InvalidUtf8 => formatter.write_str("workspace file is not valid UTF-8"),
            Self::Kernel(error) => Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for WorkspaceReadError {}

/// A final, execution-time decision made while the exclusive operation handle
/// is already verified and before the first modifying system call.
#[allow(dead_code)]
pub(crate) trait WorkspaceReplaceCommitFence {
    fn check(&mut self) -> Result<(), WorkspaceReplaceFenceError>;
}

impl<F> WorkspaceReplaceCommitFence for F
where
    F: FnMut() -> Result<(), WorkspaceReplaceFenceError>,
{
    fn check(&mut self) -> Result<(), WorkspaceReplaceFenceError> {
        self()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum WorkspaceReplaceFenceError {
    Denied,
    Cancelled,
    Stale,
    Error,
}

/// Cancellation is intentionally an observation only.  Once the first
/// modifying syscall starts, the primitive never consults it again.
#[allow(dead_code)]
pub(crate) trait WorkspaceReplaceCancellation {
    fn is_cancelled(&self) -> bool;
}

impl WorkspaceReplaceCancellation for AtomicBool {
    fn is_cancelled(&self) -> bool {
        self.load(Ordering::Acquire)
    }
}

#[allow(dead_code)]
struct NeverCancelled;

impl WorkspaceReplaceCancellation for NeverCancelled {
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum WorkspaceReplaceError {
    UnavailableOnThisPlatform,
    InvalidPreparedTarget,
    InvalidExpectedHash,
    ReplacementTooLarge,
    TargetMissing,
    TargetBusy,
    TargetIdentityChanged,
    ParentIdentityChanged,
    RootIdentityChanged,
    TargetOutsideRoot,
    ReparseTarget,
    ReparseParent,
    HardLinkAmbiguous,
    CurrentFileTooLarge,
    CurrentContentNotUtf8,
    OperationHandleIo,
    CommitFenceDenied,
    CommitFenceCancelled,
    CommitFenceStale,
    CommitFenceError,
    CommitFencePanic,
    NativePanicBeforeMutation,
    NativePanicAfterMutation,
    NativeWorkerJoin,
    CancellationBeforeMutation,
    FaultInjected,
    WriteFailed,
    ShortWrite,
    ZeroProgressWrite,
    SetEndOfFileFailed,
    FlushFailed,
    PostWriteVerificationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum WorkspaceReplaceEvidenceEvent {
    InitialHashCheck,
    CommitFence,
    PostFenceRootCheck,
    PostFenceParentCheck,
    PostFenceTargetCheck,
    PostFenceLinkCheck,
    PostFenceHashCheck,
    PostFenceCancellationCheck,
    FirstModifyingSyscall,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) struct WorkspaceReplaceEvidence {
    pub(crate) before_sha256: Option<String>,
    pub(crate) precommit_sha256: Option<String>,
    pub(crate) post_fence_sha256: Option<String>,
    pub(crate) after_sha256: Option<String>,
    pub(crate) bytes_before: Option<usize>,
    pub(crate) bytes_post_fence: Option<usize>,
    pub(crate) bytes_after: Option<usize>,
    pub(crate) mutation_attempted: bool,
    pub(crate) mutation_started: bool,
    pub(crate) modifying_syscalls: usize,
    pub(crate) committed_mutations: usize,
    pub(crate) commit_unknown: bool,
    pub(crate) fence_calls: usize,
    pub(crate) hard_link_count_after_open: Option<u32>,
    pub(crate) hard_link_count_before_fence: Option<u32>,
    pub(crate) post_fence_root_verified: bool,
    pub(crate) post_fence_parent_verified: bool,
    pub(crate) post_fence_target_verified: bool,
    pub(crate) hard_link_count_after_fence: Option<u32>,
    pub(crate) post_fence_content_verified: bool,
    pub(crate) post_fence_cancellation_checked: bool,
    pub(crate) write_calls: usize,
    pub(crate) operation_handle_open_count: usize,
    pub(crate) automatic_retries: usize,
    pub(crate) events: Vec<WorkspaceReplaceEvidenceEvent>,
}

/// Native replacement state owned by the mutation boundary.  The state is
/// deliberately not model-controlled: only the primitive advances it, and a
/// caller can inspect it after a native panic to preserve truthful outcome
/// semantics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum WorkspaceReplaceMutationPhase {
    #[default]
    NotStarted,
    Started,
    Committed,
}

#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct WorkspaceReplaceMutationTracker {
    phase: WorkspaceReplaceMutationPhase,
    operation_handle_opened: bool,
    fence_called: bool,
    mutation_attempted: bool,
}

impl WorkspaceReplaceMutationTracker {
    pub(crate) fn new() -> Self {
        Self {
            phase: WorkspaceReplaceMutationPhase::NotStarted,
            operation_handle_opened: false,
            fence_called: false,
            mutation_attempted: false,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn phase(&self) -> WorkspaceReplaceMutationPhase {
        self.phase
    }

    fn operation_handle_opened(&mut self) {
        self.operation_handle_opened = true;
    }

    fn fence_called(&mut self) {
        self.fence_called = true;
    }

    fn mutation_attempted(&mut self) {
        self.mutation_attempted = true;
    }

    fn mark_started(&mut self) {
        debug_assert_eq!(self.phase, WorkspaceReplaceMutationPhase::NotStarted);
        self.phase = WorkspaceReplaceMutationPhase::Started;
    }

    fn mark_committed(&mut self) {
        debug_assert_eq!(self.phase, WorkspaceReplaceMutationPhase::Started);
        self.phase = WorkspaceReplaceMutationPhase::Committed;
    }

    #[allow(dead_code)]
    pub(crate) fn evidence_after_panic(&self) -> WorkspaceReplaceEvidence {
        let started = matches!(
            self.phase,
            WorkspaceReplaceMutationPhase::Started | WorkspaceReplaceMutationPhase::Committed
        );
        let committed = self.phase == WorkspaceReplaceMutationPhase::Committed;
        WorkspaceReplaceEvidence {
            mutation_attempted: self.mutation_attempted,
            mutation_started: started,
            modifying_syscalls: usize::from(started),
            committed_mutations: usize::from(committed),
            commit_unknown: started && !committed,
            fence_calls: usize::from(self.fence_called),
            operation_handle_open_count: usize::from(self.operation_handle_opened),
            ..WorkspaceReplaceEvidence::default()
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum WorkspaceReplaceCommitOutcome {
    Denied {
        error: WorkspaceReplaceError,
        evidence: WorkspaceReplaceEvidence,
    },
    Conflict {
        evidence: WorkspaceReplaceEvidence,
    },
    Committed {
        evidence: WorkspaceReplaceEvidence,
    },
    CommitUnknown {
        error: WorkspaceReplaceError,
        evidence: WorkspaceReplaceEvidence,
    },
}

/// Same-handle raw-byte recovery outcome used by the test/integration H5-B
/// boundary.  It is separate from H4's UTF-8 replacement verdict so a
/// recovery request can observe a diverged or partially-written file without
/// attempting to decode it as text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum WorkspaceRecoveryCommitOutcome {
    Denied {
        error: WorkspaceReplaceError,
        evidence: WorkspaceReplaceEvidence,
    },
    Conflict {
        evidence: WorkspaceReplaceEvidence,
    },
    NoOp {
        evidence: WorkspaceReplaceEvidence,
    },
    Recovered {
        evidence: WorkspaceReplaceEvidence,
    },
    RecoveryUnknown {
        error: WorkspaceReplaceError,
        evidence: WorkspaceReplaceEvidence,
    },
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkspaceReplaceTestFault {
    AfterFirstWrite,
    AfterCommitFenceBeforePostFenceChecks,
    PostFenceHashMismatch,
    PanicBeforeFirstMutation,
    PanicAfterFirstMutation,
    AbortAfterFirstMutation,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkspaceRecoveryTestFault {
    AbortBeforeFirstMutation,
    AbortAfterFirstMutation,
}

/// A process-lifetime, OS-backed capability to one trusted workspace root.
#[derive(Clone)]
pub struct TrustedWorkspaceRoot {
    inner: Arc<TrustedWorkspaceRootInner>,
}

struct TrustedWorkspaceRootInner {
    requested_path: PathBuf,
    final_path: PathBuf,
    identity: WorkspaceRootIdentity,
    #[cfg(windows)]
    handle: Arc<platform::OwnedHandle>,
}

impl fmt::Debug for TrustedWorkspaceRoot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedWorkspaceRoot")
            .field("requested_path", &self.inner.requested_path)
            .field("final_path", &self.inner.final_path)
            .field("identity", &self.inner.identity)
            .finish_non_exhaustive()
    }
}

impl PartialEq for TrustedWorkspaceRoot {
    fn eq(&self, other: &Self) -> bool {
        self.inner.identity == other.inner.identity
            && normalize_path_for_comparison(&self.inner.final_path)
                == normalize_path_for_comparison(&other.inner.final_path)
    }
}

impl Eq for TrustedWorkspaceRoot {}

impl TrustedWorkspaceRoot {
    pub fn acquire(requested_path: &Path) -> Result<Self, VitaAgentError> {
        validate_explicit_root_path(requested_path)?;

        #[cfg(windows)]
        {
            return platform::acquire_root(requested_path);
        }
        #[cfg(not(windows))]
        {
            let _ = requested_path;
            Err(VitaAgentError::KernelInvariant(
                "workspace capability is unavailable on this platform",
            ))
        }
    }

    pub fn requested_path(&self) -> &Path {
        &self.inner.requested_path
    }

    pub fn final_path(&self) -> &Path {
        &self.inner.final_path
    }

    pub fn identity(&self) -> WorkspaceRootIdentity {
        self.inner.identity
    }

    /// Re-checks that the configured root name still denotes the originally
    /// acquired directory identity.  This catches rename/replacement of the
    /// root name without replacing the already-held capability.
    pub fn verify_named_path_current(&self) -> Result<(), VitaAgentError> {
        #[cfg(windows)]
        {
            platform::verify_root_name(self)
        }
        #[cfg(not(windows))]
        {
            Err(VitaAgentError::KernelInvariant(
                "workspace capability is unavailable on this platform",
            ))
        }
    }

    /// Resolves one relative target from the root handle and returns only
    /// resource identity and classification.  No later pathname reopen is
    /// implied by this API.
    pub fn prepare_target(
        &self,
        requested: &Path,
    ) -> Result<PreparedWorkspaceTarget, VitaAgentError> {
        let relative = WorkspaceRelativePath::parse(requested)?;

        #[cfg(windows)]
        {
            return platform::prepare_target(self, relative);
        }
        #[cfg(not(windows))]
        {
            let _ = relative;
            Err(VitaAgentError::KernelInvariant(
                "workspace capability is unavailable on this platform",
            ))
        }
    }

    #[cfg(windows)]
    fn from_platform(
        requested_path: PathBuf,
        final_path: PathBuf,
        identity: WorkspaceRootIdentity,
        handle: Arc<platform::OwnedHandle>,
    ) -> Self {
        Self {
            inner: Arc::new(TrustedWorkspaceRootInner {
                requested_path,
                final_path,
                identity,
                handle,
            }),
        }
    }
}

/// A crate-private capability to Vita's fixed, app-owned recovery namespace.
///
/// This is deliberately a different type from [`TrustedWorkspaceRoot`].  The
/// latter represents a user-selected workspace identity and retained
/// containment handle; this type owns only the process-lifetime handles needed
/// for DigitalLife's own `Vita/recovery` storage.  There is no constructor that
/// accepts an arbitrary child name or converts a workspace root into this
/// capability.
#[derive(Clone)]
pub(crate) struct AppOwnedRecoveryNamespace {
    #[cfg(windows)]
    inner: Arc<AppOwnedRecoveryNamespaceInner>,
}

#[cfg(windows)]
struct AppOwnedRecoveryNamespaceInner {
    vita_root_path: PathBuf,
    recovery_root_path: PathBuf,
    vita_root_identity: WorkspaceRootIdentity,
    recovery_root_identity: WorkspaceRootIdentity,
    // Retained so the recovery child capability never outlives its acquired
    // Vita root parent, even though journal operations use the child handle.
    #[allow(dead_code)]
    vita_root_handle: Arc<platform::OwnedHandle>,
    recovery_root_handle: Arc<platform::OwnedHandle>,
}

impl fmt::Debug for AppOwnedRecoveryNamespace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(windows)]
        {
            return formatter
                .debug_struct("AppOwnedRecoveryNamespace")
                .field("vita_root_path", &self.inner.vita_root_path)
                .field("recovery_root_path", &self.inner.recovery_root_path)
                .field("vita_root_identity", &self.inner.vita_root_identity)
                .field("recovery_root_identity", &self.inner.recovery_root_identity)
                .finish_non_exhaustive();
        }
        #[cfg(not(windows))]
        {
            formatter
                .debug_struct("AppOwnedRecoveryNamespace")
                .finish_non_exhaustive()
        }
    }
}

impl AppOwnedRecoveryNamespace {
    /// Acquires only the fixed `Vita/recovery` namespace.  The recovery child
    /// is selected inside the native implementation and cannot be supplied by
    /// a caller or model.
    #[cfg(windows)]
    pub(crate) fn acquire_vita_recovery_namespace(
        vita_root: &Path,
    ) -> Result<Self, VitaAgentError> {
        platform::acquire_vita_recovery_namespace(vita_root)
    }

    #[cfg(not(windows))]
    pub(crate) fn acquire_vita_recovery_namespace(
        _vita_root: &Path,
    ) -> Result<Self, VitaAgentError> {
        Err(VitaAgentError::KernelInvariant(
            "recovery namespace capability is unavailable on this platform",
        ))
    }

    #[cfg(windows)]
    fn from_platform(
        vita_root_path: PathBuf,
        vita_root_identity: WorkspaceRootIdentity,
        vita_root_handle: Arc<platform::OwnedHandle>,
        recovery_root_path: PathBuf,
        recovery_root_identity: WorkspaceRootIdentity,
        recovery_root_handle: Arc<platform::OwnedHandle>,
    ) -> Self {
        Self {
            inner: Arc::new(AppOwnedRecoveryNamespaceInner {
                vita_root_path,
                recovery_root_path,
                vita_root_identity,
                recovery_root_identity,
                vita_root_handle,
                recovery_root_handle,
            }),
        }
    }

    #[cfg(windows)]
    pub(crate) fn create_new_journal(&self, file_name: &OsStr, contents: &[u8]) -> io::Result<()> {
        platform::create_new_recovery_journal(self, file_name, contents)
    }

    /// Creates one immutable recovery marker in the same retained namespace
    /// as H5-A journals.  The marker name is supplied only by the
    /// crate-internal H5-B state machine; this capability never accepts a
    /// workspace path or follows a pathname from the model.
    #[cfg(windows)]
    pub(crate) fn create_new_marker(&self, file_name: &OsStr, contents: &[u8]) -> io::Result<()> {
        platform::create_new_recovery_journal(self, file_name, contents)
    }

    #[cfg(windows)]
    pub(crate) fn read_journal(&self, file_name: &OsStr, max_bytes: usize) -> io::Result<Vec<u8>> {
        platform::read_recovery_journal(self, file_name, max_bytes)
    }

    #[cfg(windows)]
    pub(crate) fn read_marker(&self, file_name: &OsStr, max_bytes: usize) -> io::Result<Vec<u8>> {
        platform::read_recovery_journal(self, file_name, max_bytes)
    }

    #[cfg(windows)]
    pub(crate) fn enumerate_journals(&self) -> io::Result<Vec<OsString>> {
        platform::enumerate_recovery_journals(self)
    }

    #[cfg(all(windows, test))]
    pub(crate) fn vita_root_path(&self) -> &Path {
        &self.inner.vita_root_path
    }

    #[cfg(all(windows, test))]
    pub(crate) fn recovery_root_path(&self) -> &Path {
        &self.inner.recovery_root_path
    }

    #[cfg(all(windows, test))]
    pub(crate) fn recovery_root_identity(&self) -> WorkspaceRootIdentity {
        self.inner.recovery_root_identity
    }
}

/// Identity-only preparation result.  Parent and target handles are retained
/// privately so a future creation primitive can remain anchored to the same
/// capability; no handle is exposed as an executable or readable object.
///
/// H3 existing-target operations must rebind the relative leaf through
/// `parent_handle` with `NtCreateFile(RootDirectory = parent_handle)` and
/// `OBJ_DONT_REPARSE`, request only the operation's access, inspect that same
/// returned handle, and compare its identity and kind with this preparation.
/// A mismatch or missing target must deny the operation.  The operation must
/// then use that inspected handle directly; it must never validate a pathname,
/// close the validation handle, and reopen the target by pathname before a
/// side effect.
pub struct PreparedWorkspaceTarget {
    root: TrustedWorkspaceRoot,
    relative_path: WorkspaceRelativePath,
    parent_identity: WorkspaceRootIdentity,
    target_identity: Option<WorkspaceRootIdentity>,
    final_path: Option<PathBuf>,
    kind: PreparedWorkspaceTargetKind,
    #[cfg(windows)]
    #[allow(dead_code)]
    parent_handle: Arc<platform::OwnedHandle>,
    #[cfg(windows)]
    #[allow(dead_code)]
    target_handle: Option<Arc<platform::OwnedHandle>>,
}

impl fmt::Debug for PreparedWorkspaceTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedWorkspaceTarget")
            .field("relative_path", &self.relative_path)
            .field("parent_identity", &self.parent_identity)
            .field("target_identity", &self.target_identity)
            .field("final_path", &self.final_path)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl PreparedWorkspaceTarget {
    pub fn root(&self) -> &TrustedWorkspaceRoot {
        &self.root
    }

    pub fn relative_path(&self) -> &WorkspaceRelativePath {
        &self.relative_path
    }

    pub fn parent_identity(&self) -> WorkspaceRootIdentity {
        self.parent_identity
    }

    pub fn target_identity(&self) -> Option<WorkspaceRootIdentity> {
        self.target_identity
    }

    pub fn final_path(&self) -> Option<&Path> {
        self.final_path.as_deref()
    }

    pub fn kind(&self) -> PreparedWorkspaceTargetKind {
        self.kind
    }

    /// Rebinds an existing regular file with the exact access needed by the
    /// first H3 read and reads that same verified operation handle.  This is
    /// intentionally crate-internal: callers receive text, never a raw
    /// Windows handle, and the H2 identity-only API remains unchanged.
    pub(crate) fn read_existing_file_utf8_bounded(
        &self,
        max_bytes: usize,
    ) -> Result<String, WorkspaceReadError> {
        #[cfg(windows)]
        {
            return platform::read_existing_file_utf8_bounded(self, max_bytes);
        }
        #[cfg(not(windows))]
        {
            let _ = max_bytes;
            Err(WorkspaceReadError::Kernel(VitaAgentError::KernelInvariant(
                "workspace read is unavailable on this platform",
            )))
        }
    }

    /// Reads bounded raw bytes from an existing regular target through a
    /// handle-relative operation handle.  H5-B uses this observation before
    /// issuing a fresh recovery grant so invalid UTF-8 is still represented by
    /// its exact byte count and SHA-256 digest.
    pub(crate) fn read_existing_file_raw_bounded(
        &self,
        max_bytes: usize,
    ) -> Result<Vec<u8>, WorkspaceReadError> {
        #[cfg(windows)]
        {
            return platform::read_existing_file_raw_bounded(self, max_bytes);
        }
        #[cfg(not(windows))]
        {
            let _ = max_bytes;
            Err(WorkspaceReadError::Kernel(VitaAgentError::KernelInvariant(
                "workspace raw read is unavailable on this platform",
            )))
        }
    }

    /// Restores an existing regular file from exact raw bytes using one
    /// exclusive handle acquired relative to the retained H2 parent handle.
    /// This is crate-internal H5-B infrastructure; it is not a model-facing
    /// workspace operation and never recreates a missing target.
    pub(crate) fn recover_existing_file_raw_bounded(
        self,
        expected_current_sha256: &str,
        expected_current_bytes: usize,
        preimage: &[u8],
        fence: &mut dyn WorkspaceReplaceCommitFence,
        cancellation: &dyn WorkspaceReplaceCancellation,
    ) -> WorkspaceRecoveryCommitOutcome {
        #[cfg(windows)]
        {
            return platform::recover_existing_file_raw_bounded(
                self,
                expected_current_sha256,
                expected_current_bytes,
                preimage,
                fence,
                cancellation,
                None,
                None,
            );
        }
        #[cfg(not(windows))]
        {
            let _ = (
                self,
                expected_current_sha256,
                expected_current_bytes,
                preimage,
                fence,
                cancellation,
            );
            WorkspaceRecoveryCommitOutcome::Denied {
                error: WorkspaceReplaceError::UnavailableOnThisPlatform,
                evidence: WorkspaceReplaceEvidence::default(),
            }
        }
    }

    #[cfg(all(test, windows))]
    pub(crate) fn recover_existing_file_raw_bounded_with_test_fault(
        self,
        expected_current_sha256: &str,
        expected_current_bytes: usize,
        preimage: &[u8],
        fence: &mut dyn WorkspaceReplaceCommitFence,
        cancellation: &dyn WorkspaceReplaceCancellation,
        fault: WorkspaceRecoveryTestFault,
    ) -> WorkspaceRecoveryCommitOutcome {
        platform::recover_existing_file_raw_bounded(
            self,
            expected_current_sha256,
            expected_current_bytes,
            preimage,
            fence,
            cancellation,
            Some(fault),
            None,
        )
    }

    #[cfg(all(test, windows))]
    pub(crate) fn recover_existing_file_raw_bounded_with_test_setup(
        self,
        expected_current_sha256: &str,
        expected_current_bytes: usize,
        preimage: &[u8],
        fence: &mut dyn WorkspaceReplaceCommitFence,
        cancellation: &dyn WorkspaceReplaceCancellation,
        setup: &dyn Fn(),
    ) -> WorkspaceRecoveryCommitOutcome {
        platform::recover_existing_file_raw_bounded(
            self,
            expected_current_sha256,
            expected_current_bytes,
            preimage,
            fence,
            cancellation,
            None,
            Some(setup),
        )
    }

    /// Replaces one already-existing regular UTF-8 file in place.  The
    /// prepared target is consumed so a caller cannot accidentally reuse a
    /// stale capability after the one-shot mutation attempt.
    #[allow(dead_code)]
    pub(crate) fn replace_existing_file_utf8_bounded(
        self,
        expected_sha256: &str,
        replacement_content: &str,
        fence: &mut dyn WorkspaceReplaceCommitFence,
    ) -> WorkspaceReplaceCommitOutcome {
        let cancellation = NeverCancelled;
        self.replace_existing_file_utf8_bounded_with_cancellation(
            expected_sha256,
            replacement_content,
            fence,
            &cancellation,
        )
    }

    /// Cancellation-aware form used by the future H4 execution bridge and by
    /// the native test harness.  Cancellation is checked before the commit
    /// fence and once again after post-fence revalidation, never after the
    /// first modifying syscall begins.
    #[allow(dead_code)]
    pub(crate) fn replace_existing_file_utf8_bounded_with_cancellation(
        self,
        expected_sha256: &str,
        replacement_content: &str,
        fence: &mut dyn WorkspaceReplaceCommitFence,
        cancellation: &dyn WorkspaceReplaceCancellation,
    ) -> WorkspaceReplaceCommitOutcome {
        let mut tracker = WorkspaceReplaceMutationTracker::new();
        self.replace_existing_file_utf8_bounded_with_cancellation_and_tracker(
            expected_sha256,
            replacement_content,
            fence,
            cancellation,
            &mut tracker,
        )
    }

    pub(crate) fn replace_existing_file_utf8_bounded_with_cancellation_and_tracker(
        self,
        expected_sha256: &str,
        replacement_content: &str,
        fence: &mut dyn WorkspaceReplaceCommitFence,
        cancellation: &dyn WorkspaceReplaceCancellation,
        tracker: &mut WorkspaceReplaceMutationTracker,
    ) -> WorkspaceReplaceCommitOutcome {
        #[cfg(windows)]
        {
            return platform::replace_existing_file_utf8_bounded(
                self,
                expected_sha256,
                replacement_content,
                fence,
                cancellation,
                tracker,
            );
        }
        #[cfg(not(windows))]
        {
            let _ = (
                self,
                expected_sha256,
                replacement_content,
                fence,
                cancellation,
            );
            WorkspaceReplaceCommitOutcome::Denied {
                error: WorkspaceReplaceError::UnavailableOnThisPlatform,
                evidence: WorkspaceReplaceEvidence::default(),
            }
        }
    }

    #[cfg(all(test, windows))]
    fn replace_existing_file_utf8_bounded_with_faults(
        self,
        expected_sha256: &str,
        replacement_content: &str,
        fence: &mut dyn WorkspaceReplaceCommitFence,
        cancellation: &dyn WorkspaceReplaceCancellation,
        faults: &mut platform::WorkspaceReplaceFaultPlan,
    ) -> WorkspaceReplaceCommitOutcome {
        let mut tracker = WorkspaceReplaceMutationTracker::new();
        self.replace_existing_file_utf8_bounded_with_faults_and_tracker(
            expected_sha256,
            replacement_content,
            fence,
            cancellation,
            &mut tracker,
            faults,
        )
    }

    #[cfg(all(test, windows))]
    fn replace_existing_file_utf8_bounded_with_faults_and_tracker(
        self,
        expected_sha256: &str,
        replacement_content: &str,
        fence: &mut dyn WorkspaceReplaceCommitFence,
        cancellation: &dyn WorkspaceReplaceCancellation,
        tracker: &mut WorkspaceReplaceMutationTracker,
        faults: &mut platform::WorkspaceReplaceFaultPlan,
    ) -> WorkspaceReplaceCommitOutcome {
        platform::replace_existing_file_utf8_bounded_with_faults(
            self,
            expected_sha256,
            replacement_content,
            fence,
            cancellation,
            tracker,
            faults,
        )
    }

    #[cfg(all(test, windows))]
    #[allow(dead_code)]
    pub(crate) fn replace_existing_file_utf8_bounded_with_test_fault(
        self,
        expected_sha256: &str,
        replacement_content: &str,
        fence: &mut dyn WorkspaceReplaceCommitFence,
        cancellation: &dyn WorkspaceReplaceCancellation,
        fault: WorkspaceReplaceTestFault,
    ) -> WorkspaceReplaceCommitOutcome {
        let mut tracker = WorkspaceReplaceMutationTracker::new();
        self.replace_existing_file_utf8_bounded_with_test_fault_and_tracker(
            expected_sha256,
            replacement_content,
            fence,
            cancellation,
            &mut tracker,
            fault,
        )
    }

    #[cfg(all(test, windows))]
    pub(crate) fn replace_existing_file_utf8_bounded_with_test_fault_and_tracker(
        self,
        expected_sha256: &str,
        replacement_content: &str,
        fence: &mut dyn WorkspaceReplaceCommitFence,
        cancellation: &dyn WorkspaceReplaceCancellation,
        tracker: &mut WorkspaceReplaceMutationTracker,
        fault: WorkspaceReplaceTestFault,
    ) -> WorkspaceReplaceCommitOutcome {
        let mut faults = match fault {
            WorkspaceReplaceTestFault::AfterFirstWrite => {
                platform::WorkspaceReplaceFaultPlan::once(
                    platform::WorkspaceReplaceFaultPoint::AfterFirstWrite,
                )
            }
            WorkspaceReplaceTestFault::AfterCommitFenceBeforePostFenceChecks => {
                platform::WorkspaceReplaceFaultPlan::once(
                    platform::WorkspaceReplaceFaultPoint::AfterCommitFenceBeforePostFenceChecks,
                )
            }
            WorkspaceReplaceTestFault::PostFenceHashMismatch => {
                platform::WorkspaceReplaceFaultPlan::post_fence_hash_mismatch()
            }
            WorkspaceReplaceTestFault::PanicBeforeFirstMutation => {
                platform::WorkspaceReplaceFaultPlan::once(
                    platform::WorkspaceReplaceFaultPoint::PanicBeforeFirstMutation,
                )
            }
            WorkspaceReplaceTestFault::PanicAfterFirstMutation => {
                platform::WorkspaceReplaceFaultPlan::once(
                    platform::WorkspaceReplaceFaultPoint::PanicAfterFirstMutation,
                )
            }
            WorkspaceReplaceTestFault::AbortAfterFirstMutation => {
                platform::WorkspaceReplaceFaultPlan::once(
                    platform::WorkspaceReplaceFaultPoint::AbortAfterFirstMutation,
                )
            }
        };
        platform::replace_existing_file_utf8_bounded_with_faults(
            self,
            expected_sha256,
            replacement_content,
            fence,
            cancellation,
            tracker,
            &mut faults,
        )
    }
}

fn validate_explicit_root_path(path: &Path) -> Result<(), VitaAgentError> {
    if path.as_os_str().is_empty() || !path.is_absolute() {
        return Err(VitaAgentError::InvalidPath {
            field: ROOT_FIELD,
            path: path.to_path_buf(),
        });
    }
    if contains_stock_codex_state(path) {
        return Err(VitaAgentError::ForbiddenStockPath {
            field: ROOT_FIELD,
            path: path.to_path_buf(),
        });
    }
    for component in path.components() {
        if matches!(component, Component::CurDir | Component::ParentDir) {
            return Err(VitaAgentError::UnsafePath {
                field: ROOT_FIELD,
                path: path.to_path_buf(),
                reason: "dot path components are ambiguous",
            });
        }
    }

    #[cfg(windows)]
    {
        use std::path::Prefix;

        match path.components().next() {
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)) => {}
            _ => {
                return Err(VitaAgentError::UnsafePath {
                    field: ROOT_FIELD,
                    path: path.to_path_buf(),
                    reason: "only an explicit local drive directory is allowed",
                })
            }
        }
        if path
            .to_string_lossy()
            .chars()
            .any(|character| character.is_control() || character == '\0')
        {
            return Err(VitaAgentError::UnsafePath {
                field: ROOT_FIELD,
                path: path.to_path_buf(),
                reason: "control characters are forbidden",
            });
        }
        for component in path.components() {
            if let Component::Normal(value) = component {
                if value.to_string_lossy().contains(':') {
                    return Err(VitaAgentError::UnsafePath {
                        field: ROOT_FIELD,
                        path: path.to_path_buf(),
                        reason: "alternate data streams are forbidden",
                    });
                }
            }
        }
    }

    Ok(())
}

fn normalize_path_for_comparison(path: &Path) -> String {
    let mut value = path.to_string_lossy().replace('/', "\\");
    if value.starts_with("\\\\?\\") {
        value.drain(..4);
    }
    while value.ends_with('\\') && value.len() > 3 {
        value.pop();
    }
    value.to_ascii_lowercase()
}

#[cfg(windows)]
#[allow(dead_code)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::io;
    use std::mem::size_of;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FileBothDirectoryInformation, NtCreateFile, NtQueryDirectoryFile,
        FILE_BOTH_DIR_INFORMATION, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
        FILE_OPEN, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
    };
    use windows_sys::Win32::Foundation::{
        CloseHandle, RtlNtStatusToDosError, HANDLE, INVALID_HANDLE_VALUE, NTSTATUS,
        OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, STATUS_NO_MORE_ENTRIES, STATUS_NO_MORE_FILES,
        STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
        STATUS_OBJECT_PATH_NOT_FOUND, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FileIdInfo, FlushFileBuffers, GetDriveTypeW, GetFileInformationByHandle,
        GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW, ReadFile,
        SetEndOfFile, SetFilePointerEx, WriteFile, BY_HANDLE_FILE_INFORMATION,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_BEGIN,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO,
        FILE_INFO_BY_HANDLE_CLASS, FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
        FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_NONE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_TRAVERSE, FILE_TYPE_DISK, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, OPEN_EXISTING,
        SYNCHRONIZE,
    };
    use windows_sys::Win32::System::WindowsProgramming::{
        DRIVE_FIXED, DRIVE_NO_ROOT_DIR, DRIVE_RAMDISK, DRIVE_REMOTE, DRIVE_REMOVABLE, DRIVE_UNKNOWN,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

    // FILE_TRAVERSE is retained only for directory RootDirectory traversal.
    // A regular target never receives FILE_TRAVERSE/FILE_EXECUTE.
    const OPEN_DIRECTORY_ACCESS: u32 = FILE_READ_ATTRIBUTES | FILE_TRAVERSE;
    const OPEN_TARGET_ACCESS: u32 = FILE_READ_ATTRIBUTES;
    const REPLACE_TARGET_ACCESS: u32 = FILE_READ_DATA
        | FILE_WRITE_DATA
        | FILE_READ_ATTRIBUTES
        | FILE_WRITE_ATTRIBUTES
        | SYNCHRONIZE;
    const REPLACE_SHARE_ACCESS: u32 = FILE_SHARE_NONE;
    const REPLACE_CREATE_OPTIONS: u32 =
        FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;

    pub(super) struct OwnedHandle(pub(super) HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    // A Windows kernel handle is process-local and is closed exactly once by
    // OwnedHandle.  Arc ensures all cloned capabilities share its lifetime.
    unsafe impl Send for OwnedHandle {}
    unsafe impl Sync for OwnedHandle {}

    impl fmt::Debug for OwnedHandle {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("OwnedHandle(<redacted>)")
        }
    }

    struct HandleDetails {
        identity: WorkspaceRootIdentity,
        final_path: PathBuf,
        is_directory: bool,
        is_reparse: bool,
        number_of_links: u32,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum WorkspaceReplaceFaultPoint {
        BeforeCommitFence,
        AfterCommitFenceBeforePostFenceChecks,
        AfterPostFenceIdentityCheck,
        AfterPostFenceHashCheck,
        AfterPostFenceCancellationCheck,
        AfterCommitFenceBeforeFirstWrite,
        PanicBeforeFirstMutation,
        AfterFirstWrite,
        PanicAfterFirstMutation,
        AbortAfterFirstMutation,
        BeforeSetEndOfFile,
        AfterSetEndOfFile,
        BeforeFlush,
        AfterFlushBeforeVerify,
        DuringPostVerify,
    }

    trait WorkspaceReplaceFaultInjector {
        fn fire(&mut self, point: WorkspaceReplaceFaultPoint) -> bool;

        fn write_chunk_limit(&mut self, requested: usize) -> usize {
            requested
        }

        fn force_zero_progress(&mut self) -> bool {
            false
        }

        fn after_first_modifying_syscall(&mut self) {}

        fn force_post_fence_hash_mismatch(&mut self) -> bool {
            false
        }
    }

    struct NoWorkspaceReplaceFaults;

    impl WorkspaceReplaceFaultInjector for NoWorkspaceReplaceFaults {
        fn fire(&mut self, _point: WorkspaceReplaceFaultPoint) -> bool {
            false
        }
    }

    #[cfg(test)]
    #[derive(Clone, Debug, Default)]
    pub(super) struct WorkspaceReplaceFaultPlan {
        point: Option<WorkspaceReplaceFaultPoint>,
        fired: bool,
        max_write_chunk: Option<usize>,
        zero_progress_on_write: bool,
        post_fence_hash_mismatch: bool,
        cancel_after_first_modifying_syscall: Option<Arc<AtomicBool>>,
    }

    #[cfg(test)]
    impl WorkspaceReplaceFaultPlan {
        pub(super) fn once(point: WorkspaceReplaceFaultPoint) -> Self {
            Self {
                point: Some(point),
                fired: false,
                ..Self::default()
            }
        }

        pub(super) fn with_max_write_chunk(max_write_chunk: usize) -> Self {
            Self {
                max_write_chunk: Some(max_write_chunk.max(1)),
                ..Self::default()
            }
        }

        pub(super) fn zero_progress_once() -> Self {
            Self {
                zero_progress_on_write: true,
                ..Self::default()
            }
        }

        pub(super) fn post_fence_hash_mismatch() -> Self {
            Self {
                post_fence_hash_mismatch: true,
                ..Self::default()
            }
        }

        pub(super) fn cancel_after_first_modifying_syscall(
            &mut self,
            cancellation: Arc<AtomicBool>,
        ) {
            self.cancel_after_first_modifying_syscall = Some(cancellation);
        }
    }

    #[cfg(test)]
    impl WorkspaceReplaceFaultInjector for WorkspaceReplaceFaultPlan {
        fn fire(&mut self, point: WorkspaceReplaceFaultPoint) -> bool {
            if self.fired || self.point != Some(point) {
                return false;
            }
            self.fired = true;
            true
        }

        fn write_chunk_limit(&mut self, requested: usize) -> usize {
            self.max_write_chunk
                .map(|limit| limit.min(requested).max(1))
                .unwrap_or(requested)
        }

        fn force_zero_progress(&mut self) -> bool {
            let should_force = self.zero_progress_on_write;
            self.zero_progress_on_write = false;
            should_force
        }

        fn after_first_modifying_syscall(&mut self) {
            if let Some(cancellation) = self.cancel_after_first_modifying_syscall.take() {
                cancellation.store(true, Ordering::Release);
            }
        }

        fn force_post_fence_hash_mismatch(&mut self) -> bool {
            let should_force = self.post_fence_hash_mismatch;
            self.post_fence_hash_mismatch = false;
            should_force
        }
    }

    pub(super) fn acquire_root(
        requested_path: &Path,
    ) -> Result<TrustedWorkspaceRoot, VitaAgentError> {
        acquire_root_impl(requested_path, || {})
    }

    #[cfg(test)]
    pub(super) fn acquire_root_with_hook<F>(
        requested_path: &Path,
        hook: F,
    ) -> Result<TrustedWorkspaceRoot, VitaAgentError>
    where
        F: FnMut(),
    {
        acquire_root_impl(requested_path, hook)
    }

    fn acquire_root_impl<F>(
        requested_path: &Path,
        after_drive_anchor: F,
    ) -> Result<TrustedWorkspaceRoot, VitaAgentError>
    where
        F: FnMut(),
    {
        let acquired = acquire_root_handle_impl(requested_path, after_drive_anchor)?;
        Ok(TrustedWorkspaceRoot::from_platform(
            acquired.requested_path,
            acquired.final_path,
            acquired.identity,
            acquired.handle,
        ))
    }

    struct AcquiredRootHandle {
        requested_path: PathBuf,
        final_path: PathBuf,
        identity: WorkspaceRootIdentity,
        handle: Arc<OwnedHandle>,
    }

    fn acquire_root_handle_impl<F>(
        requested_path: &Path,
        mut after_drive_anchor: F,
    ) -> Result<AcquiredRootHandle, VitaAgentError>
    where
        F: FnMut(),
    {
        // This is input validation only.  The authority decision below is
        // made by walking from the local-drive anchor, never by canonicalizing
        // and reopening the full user pathname.
        validate_explicit_root_path(requested_path)?;
        let components = root_components(requested_path)?;
        let (drive_anchor, anchor_details) = open_drive_anchor(requested_path)?;
        ensure_allowed_local_final_path(&anchor_details.final_path, requested_path)?;
        reject_resolved_stock_state(&anchor_details.final_path)?;

        // The drive root is the only full-name open in the authority path.  It
        // is derived from the validated local drive prefix and is itself the
        // trusted parent for every user-selected component below.
        after_drive_anchor();

        let anchor_final_path = anchor_details.final_path.clone();
        let mut parent_handle = Arc::new(drive_anchor);
        let mut final_details = anchor_details;
        for component in &components {
            let child = match open_relative(&parent_handle, component, true) {
                Ok(child) => child,
                Err(error) => return Err(relative_open_error(requested_path, error)),
            };
            let details = inspect_handle(&child, true)?;
            ensure_allowed_local_final_path(&details.final_path, requested_path)?;
            if !is_same_or_descendant_path(&anchor_final_path, &details.final_path) {
                return Err(unsafe_root_path(
                    &details.final_path,
                    "root component escaped the local drive anchor",
                ));
            }
            final_details = details;
            parent_handle = Arc::new(child);
        }

        if !is_same_or_descendant_path(&anchor_final_path, &final_details.final_path) {
            return Err(unsafe_root_path(
                &final_details.final_path,
                "resolved root is outside the local drive anchor",
            ));
        }
        reject_resolved_stock_state(&final_details.final_path)?;

        Ok(AcquiredRootHandle {
            requested_path: requested_path.to_path_buf(),
            final_path: final_details.final_path,
            identity: final_details.identity,
            handle: parent_handle,
        })
    }

    pub(super) fn acquire_vita_recovery_namespace(
        vita_root: &Path,
    ) -> Result<AppOwnedRecoveryNamespace, VitaAgentError> {
        let vita = acquire_root_handle_impl(vita_root, || {})?;

        // This is intentionally the only recovery child selection.  It is a
        // fixed app-owned namespace and never accepts a caller-provided name.
        let recovery_name = OsStr::new("recovery");
        let recovery = open_relative_with_options_and_share_disposition(
            &vita.handle,
            recovery_name,
            FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | FILE_TRAVERSE | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN_IF,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        .map_err(|error| relative_open_error(&vita.requested_path.join(recovery_name), error))?;
        let recovery_details = inspect_handle(&recovery, true)?;
        ensure_descendant_path(&vita.final_path, &recovery_details.final_path)?;

        let recovery_requested_path = vita.requested_path.join(recovery_name);
        Ok(AppOwnedRecoveryNamespace::from_platform(
            vita.requested_path,
            vita.identity,
            vita.handle,
            recovery_requested_path,
            recovery_details.identity,
            Arc::new(recovery),
        ))
    }

    pub(super) fn verify_root_name(root: &TrustedWorkspaceRoot) -> Result<(), VitaAgentError> {
        // Revalidation uses the same handle-relative, no-reparse acquisition
        // path as initial acquisition.  It never treats a full pathname open
        // or canonicalize result as the authority.
        let rebound = acquire_root(root.requested_path())?;
        if rebound.identity() != root.identity()
            || !same_path(root.final_path(), rebound.final_path())
        {
            return Err(unsafe_root_path(
                root.requested_path(),
                "root name no longer denotes the acquired directory",
            ));
        }
        Ok(())
    }

    pub(super) fn prepare_target(
        root: &TrustedWorkspaceRoot,
        relative: WorkspaceRelativePath,
    ) -> Result<PreparedWorkspaceTarget, VitaAgentError> {
        prepare_target_impl(root, relative, || {})
    }

    fn prepare_target_impl<F>(
        root: &TrustedWorkspaceRoot,
        relative: WorkspaceRelativePath,
        mut after_parent: F,
    ) -> Result<PreparedWorkspaceTarget, VitaAgentError>
    where
        F: FnMut(),
    {
        verify_root_name(root)?;

        let components = relative.components().collect::<Vec<_>>();
        let mut parent_handle = Arc::clone(&root.inner.handle);
        let mut parent_identity = root.identity();
        let mut parent_identities = vec![parent_identity];

        for component in components.iter().take(components.len().saturating_sub(1)) {
            let child = match open_relative(&parent_handle, component, true) {
                Ok(child) => child,
                Err(error) => return Err(relative_open_error(relative.as_path(), error)),
            };
            let details = inspect_handle(&child, true)?;
            ensure_descendant(root, &details.final_path)?;
            parent_identity = details.identity;
            parent_identities.push(parent_identity);
            parent_handle = Arc::new(child);
        }

        // Test-only race injection point: the parent capability has already
        // been acquired, so replacing its old pathname cannot redirect the
        // handle-relative final open.
        after_parent();

        let leaf = components
            .last()
            .expect("WorkspaceRelativePath always has one component");
        let target = match open_relative(&parent_handle, leaf, false) {
            Ok(handle) => {
                let details = inspect_handle(&handle, false)?;
                ensure_descendant(root, &details.final_path)?;
                let kind = if details.is_directory {
                    PreparedWorkspaceTargetKind::ExistingDirectory
                } else {
                    PreparedWorkspaceTargetKind::ExistingFile
                };
                (
                    kind,
                    Some(details.identity),
                    Some(details.final_path),
                    Some(Arc::new(handle)),
                )
            }
            Err(RelativeOpenError::Missing(status)) if is_missing_status(status) => {
                (PreparedWorkspaceTargetKind::Missing, None, None, None)
            }
            Err(RelativeOpenError::Missing(status)) => {
                return Err(relative_open_error(
                    relative.as_path(),
                    RelativeOpenError::Missing(status),
                ));
            }
            Err(RelativeOpenError::Status(status)) => {
                return Err(relative_open_error(
                    relative.as_path(),
                    RelativeOpenError::Status(status),
                ));
            }
        };

        verify_relative_parents(root, &components, &parent_identities, relative.as_path())?;
        verify_target_name_current(
            root,
            &parent_handle,
            leaf,
            target.1,
            target.0,
            relative.as_path(),
        )?;

        // The root name is checked again after all handle-relative stages.  A
        // root rename/replacement therefore fails closed even though the
        // original root handle remains stable and is never silently rebound.
        verify_root_name(root)?;

        Ok(PreparedWorkspaceTarget {
            root: root.clone(),
            relative_path: relative,
            parent_identity,
            target_identity: target.1,
            final_path: target.2,
            kind: target.0,
            parent_handle,
            target_handle: target.3,
        })
    }

    fn open_drive_anchor(
        requested_path: &Path,
    ) -> Result<(OwnedHandle, HandleDetails), VitaAgentError> {
        let drive_root = drive_root_path(requested_path)?;
        let drive_type = unsafe { GetDriveTypeW(nul_terminated(&drive_root).as_ptr()) };
        validate_drive_type(&drive_root, drive_type)?;

        let wide = nul_terminated(&drive_root);
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                OPEN_DIRECTORY_ACCESS,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if is_invalid_handle(handle) {
            return Err(VitaAgentError::KernelConfig(io::Error::last_os_error()));
        }
        let handle = OwnedHandle(handle);
        let details = inspect_handle(&handle, true)?;
        Ok((handle, details))
    }

    fn drive_root_path(path: &Path) -> Result<PathBuf, VitaAgentError> {
        use std::path::Prefix;

        match path.components().next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(letter) => Ok(PathBuf::from(format!("{}:\\", letter as char))),
                _ => Err(unsafe_root_path(
                    path,
                    "only a local disk drive can provide a workspace anchor",
                )),
            },
            _ => Err(unsafe_root_path(
                path,
                "workspace root has no explicit local drive anchor",
            )),
        }
    }

    fn root_components(path: &Path) -> Result<Vec<OsString>, VitaAgentError> {
        let mut components = Vec::new();
        for component in path.components() {
            if let Component::Normal(value) = component {
                components.push(value.to_os_string());
            }
        }
        Ok(components)
    }

    fn validate_drive_type(path: &Path, drive_type: u32) -> Result<(), VitaAgentError> {
        match drive_type {
            DRIVE_REMOTE => Err(unsafe_root_path(
                path,
                "mapped or remote drives are not allowed as workspace roots",
            )),
            DRIVE_FIXED | DRIVE_REMOVABLE | DRIVE_RAMDISK => Ok(()),
            DRIVE_UNKNOWN | DRIVE_NO_ROOT_DIR => {
                Err(unsafe_root_path(path, "drive type is indeterminate"))
            }
            _ => Err(unsafe_root_path(
                path,
                "drive type is not an allowed local filesystem",
            )),
        }
    }

    fn ensure_allowed_local_final_path(
        path: &Path,
        requested_path: &Path,
    ) -> Result<(), VitaAgentError> {
        let raw = path
            .to_string_lossy()
            .replace('/', "\\")
            .to_ascii_lowercase();
        let is_verbatim = raw.starts_with("\\\\?\\");
        let without_verbatim = raw.strip_prefix("\\\\?\\").unwrap_or(&raw);
        let is_unc = raw.starts_with("\\\\?\\unc\\") || (!is_verbatim && raw.starts_with("\\\\"));
        let is_device = raw.starts_with("\\device\\")
            || raw.starts_with("\\\\device\\")
            || raw.starts_with("\\\\.\\")
            || without_verbatim.starts_with("device\\")
            || without_verbatim.starts_with("globalroot\\device\\");
        if is_unc || is_device {
            return Err(unsafe_root_path(
                requested_path,
                "resolved workspace path is UNC or device namespace",
            ));
        }

        match without_verbatim.as_bytes() {
            [drive, b':', ..] if drive.is_ascii_alphabetic() => Ok(()),
            _ => Err(unsafe_root_path(
                requested_path,
                "resolved workspace path is not an allowed local drive path",
            )),
        }
    }

    fn reject_resolved_stock_state(path: &Path) -> Result<(), VitaAgentError> {
        if contains_stock_codex_state(path) {
            return Err(VitaAgentError::ForbiddenStockPath {
                field: ROOT_FIELD,
                path: path.to_path_buf(),
            });
        }
        Ok(())
    }

    fn open_relative(
        parent: &Arc<OwnedHandle>,
        component: &OsStr,
        directory: bool,
    ) -> Result<OwnedHandle, RelativeOpenError> {
        let create_options =
            FILE_OPEN_REPARSE_POINT | if directory { FILE_DIRECTORY_FILE } else { 0 };
        open_relative_with_options(
            parent,
            component,
            if directory {
                OPEN_DIRECTORY_ACCESS
            } else {
                OPEN_TARGET_ACCESS
            },
            create_options,
        )
    }

    fn open_read_relative(
        parent: &Arc<OwnedHandle>,
        component: &OsStr,
    ) -> Result<OwnedHandle, RelativeOpenError> {
        // The operation handle has only FILE_READ_DATA, FILE_READ_ATTRIBUTES,
        // and SYNCHRONIZE.  It deliberately has no write, delete, or execute
        // access, and omits FILE_SHARE_DELETE to keep the target namespace
        // stable for the duration of the read.
        open_relative_with_options(
            parent,
            component,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
    }

    fn open_relative_with_options(
        parent: &Arc<OwnedHandle>,
        component: &OsStr,
        desired_access: u32,
        create_options: u32,
    ) -> Result<OwnedHandle, RelativeOpenError> {
        open_relative_with_options_and_share(
            parent,
            component,
            desired_access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            create_options,
        )
    }

    fn open_exclusive_relative(
        parent: &Arc<OwnedHandle>,
        component: &OsStr,
    ) -> Result<OwnedHandle, RelativeOpenError> {
        // H4-B's operation handle is the only handle on which the mutation
        // path is allowed to operate.  ShareAccess=0 makes a competing open
        // fail closed instead of waiting or racing another writer.
        open_relative_with_options_and_share(
            parent,
            component,
            REPLACE_TARGET_ACCESS,
            REPLACE_SHARE_ACCESS,
            REPLACE_CREATE_OPTIONS,
        )
    }

    fn open_relative_with_options_and_share(
        parent: &Arc<OwnedHandle>,
        component: &OsStr,
        desired_access: u32,
        share_access: u32,
        create_options: u32,
    ) -> Result<OwnedHandle, RelativeOpenError> {
        open_relative_with_options_and_share_disposition(
            parent,
            component,
            desired_access,
            share_access,
            FILE_OPEN,
            create_options,
        )
    }

    fn open_relative_with_options_and_share_disposition(
        parent: &Arc<OwnedHandle>,
        component: &OsStr,
        desired_access: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
    ) -> Result<OwnedHandle, RelativeOpenError> {
        let mut name = component.encode_wide().collect::<Vec<_>>();
        let byte_length = name
            .len()
            .checked_mul(2)
            .ok_or_else(|| RelativeOpenError::Status(STATUS_OBJECT_NAME_NOT_FOUND))?;
        if byte_length > u16::MAX as usize {
            return Err(RelativeOpenError::Status(STATUS_OBJECT_NAME_NOT_FOUND));
        }
        let unicode_name = UNICODE_STRING {
            Length: byte_length as u16,
            MaximumLength: byte_length as u16,
            Buffer: name.as_mut_ptr(),
        };
        let object_attributes = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: parent.0,
            ObjectName: &unicode_name,
            Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            SecurityDescriptor: std::ptr::null(),
            SecurityQualityOfService: std::ptr::null(),
        };
        let mut status_block = IO_STATUS_BLOCK::default();
        let mut handle: HANDLE = std::ptr::null_mut();
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                desired_access,
                &object_attributes,
                &mut status_block,
                std::ptr::null(),
                0,
                share_access,
                create_disposition,
                create_options,
                std::ptr::null(),
                0,
            )
        };
        if status < 0 {
            if !is_invalid_handle(handle) {
                unsafe {
                    let _ = CloseHandle(handle);
                }
            }
            return Err(if is_missing_status(status) {
                RelativeOpenError::Missing(status)
            } else {
                RelativeOpenError::Status(status)
            });
        }
        if is_invalid_handle(handle) {
            return Err(RelativeOpenError::Status(status));
        }
        Ok(OwnedHandle(handle))
    }

    pub(super) fn create_new_recovery_journal(
        namespace: &AppOwnedRecoveryNamespace,
        component: &OsStr,
        contents: &[u8],
    ) -> io::Result<()> {
        validate_namespace_child_io(component)?;
        let handle = open_relative_with_options_and_share_disposition(
            &namespace.inner.recovery_root_handle,
            component,
            FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_CREATE,
            FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        .map_err(namespace_open_io_error)?;
        let details = inspect_handle(&handle, false).map_err(namespace_kernel_io_error)?;
        if details.is_directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "namespace child is a directory",
            ));
        }
        write_file_bytes(&handle, contents)?;
        if unsafe { FlushFileBuffers(handle.0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn read_recovery_journal(
        namespace: &AppOwnedRecoveryNamespace,
        component: &OsStr,
        max_bytes: usize,
    ) -> io::Result<Vec<u8>> {
        validate_namespace_child_io(component)?;
        let handle = open_relative_with_options_and_share_disposition(
            &namespace.inner.recovery_root_handle,
            component,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        )
        .map_err(namespace_open_io_error)?;
        let details = inspect_handle(&handle, false).map_err(namespace_kernel_io_error)?;
        if details.is_directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "namespace child is a directory",
            ));
        }
        read_file_bytes(&handle, max_bytes)
    }

    pub(super) fn enumerate_recovery_journals(
        namespace: &AppOwnedRecoveryNamespace,
    ) -> io::Result<Vec<OsString>> {
        inspect_handle(&namespace.inner.recovery_root_handle, true)
            .map_err(namespace_kernel_io_error)?;

        let mut names = Vec::new();
        let mut restart_scan = true;
        let mut buffer = vec![0_u64; 8 * 1024];
        let byte_buffer = unsafe {
            std::slice::from_raw_parts_mut(
                buffer.as_mut_ptr().cast::<u8>(),
                buffer.len() * size_of::<u64>(),
            )
        };
        loop {
            let mut status_block = IO_STATUS_BLOCK::default();
            let status = unsafe {
                NtQueryDirectoryFile(
                    namespace.inner.recovery_root_handle.0,
                    std::ptr::null_mut(),
                    None,
                    std::ptr::null(),
                    &mut status_block,
                    byte_buffer.as_mut_ptr().cast(),
                    byte_buffer.len() as u32,
                    FileBothDirectoryInformation,
                    false,
                    std::ptr::null(),
                    restart_scan,
                )
            };
            if status == STATUS_NO_MORE_FILES || status == STATUS_NO_MORE_ENTRIES {
                break;
            }
            if status < 0 {
                return Err(namespace_status_io_error(status));
            }
            let returned = usize::try_from(status_block.Information)
                .ok()
                .filter(|length| *length <= byte_buffer.len())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "directory enumeration returned an invalid byte count",
                    )
                })?;
            if returned == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory enumeration returned no entry bytes",
                ));
            }
            parse_directory_names(byte_buffer, returned, &mut names)?;
            restart_scan = false;
        }
        Ok(names)
    }

    fn validate_namespace_child(component: &OsStr) -> Result<(), VitaAgentError> {
        if component.is_empty()
            || component == OsStr::new(".")
            || component == OsStr::new("..")
            || component.to_string_lossy().chars().any(|character| {
                character == '/' || character == '\\' || character == ':' || character.is_control()
            })
        {
            return Err(VitaAgentError::UnsafePath {
                field: ROOT_FIELD,
                path: PathBuf::new(),
                reason: "namespace child is not one fixed component",
            });
        }
        Ok(())
    }

    fn validate_namespace_child_io(component: &OsStr) -> io::Result<()> {
        validate_namespace_child(component)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))
    }

    fn namespace_open_io_error(error: RelativeOpenError) -> io::Error {
        match error {
            RelativeOpenError::Missing(status) | RelativeOpenError::Status(status) => {
                namespace_status_io_error(status)
            }
        }
    }

    fn namespace_status_io_error(status: NTSTATUS) -> io::Error {
        if status == STATUS_OBJECT_NAME_COLLISION {
            return io::Error::new(
                io::ErrorKind::AlreadyExists,
                "namespace child already exists",
            );
        }
        let error_code = unsafe { RtlNtStatusToDosError(status) } as i32;
        if error_code == 0 {
            io::Error::other(format!(
                "native namespace operation failed with NTSTATUS {status:#x}"
            ))
        } else {
            io::Error::from_raw_os_error(error_code)
        }
    }

    fn namespace_kernel_io_error(error: VitaAgentError) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
    }

    fn write_file_bytes(handle: &OwnedHandle, contents: &[u8]) -> io::Result<()> {
        let mut offset = 0usize;
        while offset < contents.len() {
            let request = (contents.len() - offset).min(u32::MAX as usize) as u32;
            let mut written = 0_u32;
            let ok = unsafe {
                WriteFile(
                    handle.0,
                    contents[offset..].as_ptr(),
                    request,
                    &mut written,
                    std::ptr::null_mut(),
                )
            } != 0;
            if !ok {
                return Err(io::Error::last_os_error());
            }
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "native namespace write made no progress",
                ));
            }
            offset += written as usize;
        }
        Ok(())
    }

    fn read_file_bytes(handle: &OwnedHandle, max_bytes: usize) -> io::Result<Vec<u8>> {
        if max_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bounded namespace read requires a positive limit",
            ));
        }
        let mut bytes = Vec::with_capacity(max_bytes.min(8 * 1024));
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let remaining = max_bytes
                .checked_add(1)
                .and_then(|limit| limit.checked_sub(bytes.len()))
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "read bound overflow"))?;
            if remaining == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "namespace child exceeds its hard size bound",
                ));
            }
            let request = remaining.min(buffer.len()) as u32;
            let mut read = 0_u32;
            let ok = unsafe {
                ReadFile(
                    handle.0,
                    buffer.as_mut_ptr(),
                    request,
                    &mut read,
                    std::ptr::null_mut(),
                )
            } != 0;
            if !ok {
                return Err(io::Error::last_os_error());
            }
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read as usize]);
            if bytes.len() > max_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "namespace child exceeds its hard size bound",
                ));
            }
        }
        Ok(bytes)
    }

    fn parse_directory_names(
        buffer: &[u8],
        returned: usize,
        names: &mut Vec<OsString>,
    ) -> io::Result<()> {
        let header_bytes = size_of::<FILE_BOTH_DIR_INFORMATION>() - size_of::<u16>();
        let mut offset = 0usize;
        while offset < returned {
            if returned - offset < header_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory entry header is truncated",
                ));
            }
            let entry =
                unsafe { &*(buffer.as_ptr().add(offset) as *const FILE_BOTH_DIR_INFORMATION) };
            let name_length = usize::try_from(entry.FileNameLength).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "directory name length overflow")
            })?;
            if name_length % size_of::<u16>() != 0
                || name_length / size_of::<u16>() > MAX_UTF16_UNITS
                || header_bytes
                    .checked_add(name_length)
                    .and_then(|length| offset.checked_add(length))
                    .filter(|end| *end <= returned)
                    .is_none()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory entry name is outside the returned buffer",
                ));
            }
            let name = unsafe {
                std::slice::from_raw_parts(
                    (entry.FileName.as_ptr()).cast::<u8>().add(0).cast::<u16>(),
                    name_length / size_of::<u16>(),
                )
            };
            let name = OsString::from_wide(name);
            if name != OsStr::new(".") && name != OsStr::new("..") {
                names.push(name);
            }

            let next = usize::try_from(entry.NextEntryOffset).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory entry offset overflow",
                )
            })?;
            if next == 0 {
                break;
            }
            if next < header_bytes + name_length
                || offset
                    .checked_add(next)
                    .filter(|end| *end < returned)
                    .is_none()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "directory entry offset is invalid",
                ));
            }
            offset += next;
        }
        Ok(())
    }

    pub(super) fn read_existing_file_utf8_bounded(
        prepared: &PreparedWorkspaceTarget,
        max_bytes: usize,
    ) -> Result<String, WorkspaceReadError> {
        if max_bytes == 0 || max_bytes > WORKSPACE_READ_HARD_MAX_BYTES {
            return Err(WorkspaceReadError::TooLarge {
                limit: WORKSPACE_READ_HARD_MAX_BYTES,
            });
        }
        if prepared.kind != PreparedWorkspaceTargetKind::ExistingFile {
            return Err(WorkspaceReadError::InvalidTarget(
                "only an existing regular file may be read",
            ));
        }
        let expected_identity =
            prepared
                .target_identity
                .ok_or(WorkspaceReadError::InvalidTarget(
                    "prepared file has no stable identity",
                ))?;

        verify_root_name(&prepared.root).map_err(WorkspaceReadError::Kernel)?;
        let parent_details =
            inspect_handle(&prepared.parent_handle, true).map_err(WorkspaceReadError::Kernel)?;
        ensure_descendant(&prepared.root, &parent_details.final_path)
            .map_err(WorkspaceReadError::Kernel)?;
        if parent_details.identity != prepared.parent_identity {
            return Err(WorkspaceReadError::InvalidTarget(
                "workspace parent identity changed before read",
            ));
        }

        let leaf = prepared
            .relative_path
            .components()
            .last()
            .expect("WorkspaceRelativePath always has one component");
        let handle = match open_read_relative(&prepared.parent_handle, leaf) {
            Ok(handle) => handle,
            Err(RelativeOpenError::Missing(_)) => {
                return Err(WorkspaceReadError::InvalidTarget(
                    "workspace target disappeared before read",
                ));
            }
            Err(error) => {
                return Err(WorkspaceReadError::Kernel(relative_open_error(
                    prepared.relative_path.as_path(),
                    error,
                )))
            }
        };

        // These checks are deliberately performed on the exact operation
        // handle that will be consumed by read_utf8_bounded below.
        let details = inspect_handle(&handle, false).map_err(WorkspaceReadError::Kernel)?;
        ensure_descendant(&prepared.root, &details.final_path)
            .map_err(WorkspaceReadError::Kernel)?;
        if details.is_directory {
            return Err(WorkspaceReadError::InvalidTarget(
                "workspace target is a directory",
            ));
        }
        if details.identity != expected_identity {
            return Err(WorkspaceReadError::InvalidTarget(
                "workspace target identity changed before read",
            ));
        }
        verify_root_name(&prepared.root).map_err(WorkspaceReadError::Kernel)?;
        read_utf8_bounded(&handle, max_bytes)
    }

    pub(super) fn read_existing_file_raw_bounded(
        prepared: &PreparedWorkspaceTarget,
        max_bytes: usize,
    ) -> Result<Vec<u8>, WorkspaceReadError> {
        if max_bytes == 0 || max_bytes > WORKSPACE_REPLACE_HARD_MAX_BYTES {
            return Err(WorkspaceReadError::TooLarge {
                limit: WORKSPACE_REPLACE_HARD_MAX_BYTES,
            });
        }
        if prepared.kind != PreparedWorkspaceTargetKind::ExistingFile {
            return Err(WorkspaceReadError::InvalidTarget(
                "only an existing regular file may be read",
            ));
        }
        let expected_identity =
            prepared
                .target_identity
                .ok_or(WorkspaceReadError::InvalidTarget(
                    "prepared file has no stable identity",
                ))?;
        verify_root_name(&prepared.root).map_err(WorkspaceReadError::Kernel)?;
        if let Err(error) = verify_replace_parent(
            &prepared.root,
            &prepared.parent_handle,
            prepared.parent_identity,
        ) {
            return Err(WorkspaceReadError::Kernel(VitaAgentError::KernelInvariant(
                match error {
                    WorkspaceReplaceError::ReparseParent => "workspace parent is a reparse point",
                    WorkspaceReplaceError::ParentIdentityChanged => {
                        "workspace parent identity changed before raw read"
                    }
                    _ => "workspace parent is outside the acquired root",
                },
            )));
        }
        let leaf = prepared
            .relative_path
            .components()
            .last()
            .expect("WorkspaceRelativePath always has one component");
        let handle = match open_read_relative(&prepared.parent_handle, leaf) {
            Ok(handle) => handle,
            Err(RelativeOpenError::Missing(_)) => {
                return Err(WorkspaceReadError::InvalidTarget(
                    "workspace target disappeared before raw read",
                ));
            }
            Err(error) => {
                return Err(WorkspaceReadError::Kernel(relative_open_error(
                    prepared.relative_path.as_path(),
                    error,
                )));
            }
        };
        let details = inspect_handle(&handle, false).map_err(WorkspaceReadError::Kernel)?;
        if details.is_reparse || details.is_directory {
            return Err(WorkspaceReadError::InvalidTarget(
                "workspace raw target is not a regular non-reparse file",
            ));
        }
        if details.identity != expected_identity {
            return Err(WorkspaceReadError::InvalidTarget(
                "workspace target identity changed before raw read",
            ));
        }
        ensure_descendant(&prepared.root, &details.final_path)
            .map_err(WorkspaceReadError::Kernel)?;
        verify_root_name(&prepared.root).map_err(WorkspaceReadError::Kernel)?;
        if !set_file_pointer(&handle, 0) {
            return Err(WorkspaceReadError::Kernel(VitaAgentError::KernelConfig(
                io::Error::last_os_error(),
            )));
        }
        match read_raw_recovery_bounded(&handle) {
            Ok(bytes) if bytes.len() <= max_bytes => Ok(bytes),
            Ok(_) => Err(WorkspaceReadError::TooLarge { limit: max_bytes }),
            Err(RecoveryReadError::TooLarge) => {
                Err(WorkspaceReadError::TooLarge { limit: max_bytes })
            }
            Err(RecoveryReadError::Io) => Err(WorkspaceReadError::Kernel(
                VitaAgentError::KernelConfig(io::Error::last_os_error()),
            )),
        }
    }

    /// H5-B's dedicated raw-byte recovery primitive.  It deliberately shares
    /// H4's retained-parent and exclusive-handle helpers, but never decodes
    /// the current target as UTF-8 and never opens a missing target with a
    /// create disposition.
    pub(super) fn recover_existing_file_raw_bounded(
        prepared: PreparedWorkspaceTarget,
        expected_current_sha256: &str,
        expected_current_bytes: usize,
        preimage: &[u8],
        fence: &mut dyn WorkspaceReplaceCommitFence,
        cancellation: &dyn WorkspaceReplaceCancellation,
        fault: Option<WorkspaceRecoveryTestFault>,
        test_setup: Option<&dyn Fn()>,
    ) -> WorkspaceRecoveryCommitOutcome {
        let PreparedWorkspaceTarget {
            root,
            relative_path,
            parent_identity,
            target_identity,
            final_path: _,
            kind,
            parent_handle,
            target_handle,
        } = prepared;
        drop(target_handle);

        let mut evidence = WorkspaceReplaceEvidence::default();
        if cancellation.is_cancelled() {
            return recovery_denied(evidence, WorkspaceReplaceError::CancellationBeforeMutation);
        }
        if kind != PreparedWorkspaceTargetKind::ExistingFile {
            return recovery_denied(evidence, WorkspaceReplaceError::InvalidPreparedTarget);
        }
        let expected_identity = match target_identity {
            Some(identity) => identity,
            None => return recovery_denied(evidence, WorkspaceReplaceError::InvalidPreparedTarget),
        };
        let expected_current_sha256 = match normalized_sha256(expected_current_sha256) {
            Some(value) => value,
            None => return recovery_denied(evidence, WorkspaceReplaceError::InvalidExpectedHash),
        };
        if expected_current_bytes > WORKSPACE_REPLACE_HARD_MAX_BYTES
            || preimage.len() > WORKSPACE_REPLACE_HARD_MAX_BYTES
        {
            return recovery_denied(evidence, WorkspaceReplaceError::ReplacementTooLarge);
        }

        if verify_root_name(&root).is_err() {
            return recovery_denied(evidence, WorkspaceReplaceError::RootIdentityChanged);
        }
        if let Err(error) = verify_replace_parent(&root, &parent_handle, parent_identity) {
            return recovery_denied(evidence, error);
        }

        if let Some(setup) = test_setup {
            setup();
        }
        let leaf = relative_path
            .components()
            .last()
            .expect("WorkspaceRelativePath always has one component");
        let operation_handle = match open_exclusive_relative(&parent_handle, leaf) {
            Ok(handle) => handle,
            Err(RelativeOpenError::Missing(_)) => {
                return recovery_denied(evidence, WorkspaceReplaceError::TargetMissing)
            }
            Err(RelativeOpenError::Status(_)) => {
                return recovery_denied(evidence, WorkspaceReplaceError::TargetBusy)
            }
        };
        evidence.operation_handle_open_count = 1;

        let details =
            match verify_replace_operation_handle(&root, &operation_handle, expected_identity) {
                Ok(details) => details,
                Err(error) => return recovery_denied(evidence, error),
            };
        if details.number_of_links != 1 {
            return recovery_denied(evidence, WorkspaceReplaceError::HardLinkAmbiguous);
        }
        evidence.hard_link_count_after_open = Some(details.number_of_links);
        if verify_root_name(&root).is_err() {
            return recovery_denied(evidence, WorkspaceReplaceError::RootIdentityChanged);
        }
        if let Err(error) = verify_replace_parent(&root, &parent_handle, parent_identity) {
            return recovery_denied(evidence, error);
        }

        if !set_file_pointer(&operation_handle, 0) {
            return recovery_denied(evidence, WorkspaceReplaceError::OperationHandleIo);
        }
        let current_bytes = match read_raw_recovery_bounded(&operation_handle) {
            Ok(bytes) => bytes,
            Err(RecoveryReadError::TooLarge) => {
                return recovery_denied(evidence, WorkspaceReplaceError::CurrentFileTooLarge)
            }
            Err(RecoveryReadError::Io) => {
                return recovery_denied(evidence, WorkspaceReplaceError::OperationHandleIo)
            }
        };
        let current_hash = crate::sha256_hex(&current_bytes);
        evidence.bytes_before = Some(current_bytes.len());
        evidence.before_sha256 = Some(current_hash.clone());
        evidence.precommit_sha256 = Some(current_hash.clone());
        evidence.hard_link_count_before_fence = Some(details.number_of_links);
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::InitialHashCheck);
        if current_bytes.len() != expected_current_bytes || current_hash != expected_current_sha256
        {
            return WorkspaceRecoveryCommitOutcome::Conflict { evidence };
        }

        evidence.fence_calls = 1;
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::CommitFence);
        let fence_result = catch_unwind(AssertUnwindSafe(|| fence.check()));
        match fence_result {
            Ok(Ok(())) => {}
            Ok(Err(WorkspaceReplaceFenceError::Denied)) => {
                return recovery_denied(evidence, WorkspaceReplaceError::CommitFenceDenied)
            }
            Ok(Err(WorkspaceReplaceFenceError::Cancelled)) => {
                return recovery_denied(evidence, WorkspaceReplaceError::CommitFenceCancelled)
            }
            Ok(Err(WorkspaceReplaceFenceError::Stale)) => {
                return recovery_denied(evidence, WorkspaceReplaceError::CommitFenceStale)
            }
            Ok(Err(WorkspaceReplaceFenceError::Error)) => {
                return recovery_denied(evidence, WorkspaceReplaceError::CommitFenceError)
            }
            Err(_) => return recovery_denied(evidence, WorkspaceReplaceError::CommitFencePanic),
        }

        if verify_root_name(&root).is_err() {
            return recovery_denied(evidence, WorkspaceReplaceError::RootIdentityChanged);
        }
        evidence.post_fence_root_verified = true;
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::PostFenceRootCheck);
        if let Err(error) = verify_replace_parent(&root, &parent_handle, parent_identity) {
            return recovery_denied(evidence, error);
        }
        evidence.post_fence_parent_verified = true;
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::PostFenceParentCheck);
        let post_fence_details =
            match verify_replace_operation_handle(&root, &operation_handle, expected_identity) {
                Ok(details) => details,
                Err(error) => return recovery_denied(evidence, error),
            };
        evidence.post_fence_target_verified = true;
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::PostFenceTargetCheck);
        evidence.hard_link_count_after_fence = Some(post_fence_details.number_of_links);
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::PostFenceLinkCheck);
        if post_fence_details.number_of_links != 1 {
            return recovery_denied(evidence, WorkspaceReplaceError::HardLinkAmbiguous);
        }
        if !set_file_pointer(&operation_handle, 0) {
            return recovery_denied(evidence, WorkspaceReplaceError::OperationHandleIo);
        }
        let post_fence_bytes = match read_raw_recovery_bounded(&operation_handle) {
            Ok(bytes) => bytes,
            Err(RecoveryReadError::TooLarge) => {
                return recovery_denied(evidence, WorkspaceReplaceError::CurrentFileTooLarge)
            }
            Err(RecoveryReadError::Io) => {
                return recovery_denied(evidence, WorkspaceReplaceError::OperationHandleIo)
            }
        };
        let post_fence_hash = crate::sha256_hex(&post_fence_bytes);
        evidence.bytes_post_fence = Some(post_fence_bytes.len());
        evidence.post_fence_sha256 = Some(post_fence_hash.clone());
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::PostFenceHashCheck);
        if post_fence_bytes.len() != expected_current_bytes
            || post_fence_hash != expected_current_sha256
        {
            return WorkspaceRecoveryCommitOutcome::Conflict { evidence };
        }
        evidence.post_fence_content_verified = true;
        evidence.post_fence_cancellation_checked = true;
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::PostFenceCancellationCheck);
        if cancellation.is_cancelled() {
            return recovery_denied(evidence, WorkspaceReplaceError::CancellationBeforeMutation);
        }

        if post_fence_bytes == preimage {
            evidence.bytes_after = Some(preimage.len());
            evidence.after_sha256 = Some(crate::sha256_hex(preimage));
            return WorkspaceRecoveryCommitOutcome::NoOp { evidence };
        }
        if !set_file_pointer(&operation_handle, 0) {
            return recovery_denied(evidence, WorkspaceReplaceError::OperationHandleIo);
        }

        if preimage.is_empty() {
            recovery_abort_if_requested(
                fault,
                WorkspaceRecoveryTestFault::AbortBeforeFirstMutation,
            );
            evidence.mutation_attempted = true;
            evidence.mutation_started = true;
            evidence.modifying_syscalls += 1;
            evidence
                .events
                .push(WorkspaceReplaceEvidenceEvent::FirstModifyingSyscall);
            if !set_end_of_file(&operation_handle) {
                return recovery_unknown(evidence, WorkspaceReplaceError::SetEndOfFileFailed);
            }
            recovery_abort_if_requested(fault, WorkspaceRecoveryTestFault::AbortAfterFirstMutation);
        } else {
            let mut offset = 0usize;
            let mut first_write = true;
            while offset < preimage.len() {
                if first_write {
                    recovery_abort_if_requested(
                        fault,
                        WorkspaceRecoveryTestFault::AbortBeforeFirstMutation,
                    );
                    evidence
                        .events
                        .push(WorkspaceReplaceEvidenceEvent::FirstModifyingSyscall);
                    first_write = false;
                }
                evidence.mutation_attempted = true;
                evidence.mutation_started = true;
                evidence.modifying_syscalls += 1;
                evidence.write_calls += 1;
                let request_len = (preimage.len() - offset).min(u32::MAX as usize);
                let mut written = 0_u32;
                let write_ok = unsafe {
                    WriteFile(
                        operation_handle.0,
                        preimage[offset..].as_ptr(),
                        request_len as u32,
                        &mut written,
                        std::ptr::null_mut(),
                    ) != 0
                };
                if !write_ok {
                    return recovery_unknown(evidence, WorkspaceReplaceError::WriteFailed);
                }
                if written == 0 || written as usize > request_len {
                    return recovery_unknown(evidence, WorkspaceReplaceError::ZeroProgressWrite);
                }
                offset += written as usize;
                if evidence.write_calls == 1 {
                    recovery_abort_if_requested(
                        fault,
                        WorkspaceRecoveryTestFault::AbortAfterFirstMutation,
                    );
                }
            }
            if !set_file_pointer(&operation_handle, preimage.len() as i64) {
                return recovery_unknown(evidence, WorkspaceReplaceError::OperationHandleIo);
            }
            evidence.modifying_syscalls += 1;
            if !set_end_of_file(&operation_handle) {
                return recovery_unknown(evidence, WorkspaceReplaceError::SetEndOfFileFailed);
            }
        }

        evidence.modifying_syscalls += 1;
        if unsafe { FlushFileBuffers(operation_handle.0) } == 0 {
            return recovery_unknown(evidence, WorkspaceReplaceError::FlushFailed);
        }
        if !set_file_pointer(&operation_handle, 0) {
            return recovery_unknown(evidence, WorkspaceReplaceError::OperationHandleIo);
        }
        let after_bytes = match read_raw_recovery_bounded(&operation_handle) {
            Ok(bytes) => bytes,
            Err(_) => {
                return recovery_unknown(
                    evidence,
                    WorkspaceReplaceError::PostWriteVerificationFailed,
                )
            }
        };
        evidence.bytes_after = Some(after_bytes.len());
        evidence.after_sha256 = Some(crate::sha256_hex(&after_bytes));
        if after_bytes != preimage {
            return recovery_unknown(evidence, WorkspaceReplaceError::PostWriteVerificationFailed);
        }
        evidence.committed_mutations = 1;
        WorkspaceRecoveryCommitOutcome::Recovered { evidence }
    }

    fn recovery_abort_if_requested(
        fault: Option<WorkspaceRecoveryTestFault>,
        requested: WorkspaceRecoveryTestFault,
    ) {
        #[cfg(test)]
        if fault == Some(requested) {
            std::process::abort();
        }
        #[cfg(not(test))]
        let _ = (fault, requested);
    }

    enum RecoveryReadError {
        TooLarge,
        Io,
    }

    fn read_raw_recovery_bounded(handle: &OwnedHandle) -> Result<Vec<u8>, RecoveryReadError> {
        let mut bytes = Vec::with_capacity(WORKSPACE_REPLACE_HARD_MAX_BYTES + 1);
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let remaining = WORKSPACE_REPLACE_HARD_MAX_BYTES + 1 - bytes.len();
            if remaining == 0 {
                return Err(RecoveryReadError::TooLarge);
            }
            let request = remaining.min(buffer.len()) as u32;
            let mut read = 0_u32;
            let ok = unsafe {
                ReadFile(
                    handle.0,
                    buffer.as_mut_ptr(),
                    request,
                    &mut read,
                    std::ptr::null_mut(),
                ) != 0
            };
            if !ok || read > request {
                return Err(RecoveryReadError::Io);
            }
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read as usize]);
            if bytes.len() > WORKSPACE_REPLACE_HARD_MAX_BYTES {
                return Err(RecoveryReadError::TooLarge);
            }
        }
        Ok(bytes)
    }

    fn recovery_denied(
        evidence: WorkspaceReplaceEvidence,
        error: WorkspaceReplaceError,
    ) -> WorkspaceRecoveryCommitOutcome {
        WorkspaceRecoveryCommitOutcome::Denied { error, evidence }
    }

    fn recovery_unknown(
        mut evidence: WorkspaceReplaceEvidence,
        error: WorkspaceReplaceError,
    ) -> WorkspaceRecoveryCommitOutcome {
        evidence.commit_unknown = true;
        WorkspaceRecoveryCommitOutcome::RecoveryUnknown { error, evidence }
    }

    pub(super) fn replace_existing_file_utf8_bounded(
        prepared: PreparedWorkspaceTarget,
        expected_sha256: &str,
        replacement_content: &str,
        fence: &mut dyn WorkspaceReplaceCommitFence,
        cancellation: &dyn WorkspaceReplaceCancellation,
        tracker: &mut WorkspaceReplaceMutationTracker,
    ) -> WorkspaceReplaceCommitOutcome {
        let mut faults = NoWorkspaceReplaceFaults;
        replace_existing_file_utf8_bounded_impl(
            prepared,
            expected_sha256,
            replacement_content,
            fence,
            cancellation,
            tracker,
            &mut faults,
        )
    }

    #[cfg(test)]
    pub(super) fn replace_existing_file_utf8_bounded_with_faults(
        prepared: PreparedWorkspaceTarget,
        expected_sha256: &str,
        replacement_content: &str,
        fence: &mut dyn WorkspaceReplaceCommitFence,
        cancellation: &dyn WorkspaceReplaceCancellation,
        tracker: &mut WorkspaceReplaceMutationTracker,
        faults: &mut WorkspaceReplaceFaultPlan,
    ) -> WorkspaceReplaceCommitOutcome {
        replace_existing_file_utf8_bounded_impl(
            prepared,
            expected_sha256,
            replacement_content,
            fence,
            cancellation,
            tracker,
            faults,
        )
    }

    fn replace_existing_file_utf8_bounded_impl<F>(
        prepared: PreparedWorkspaceTarget,
        expected_sha256: &str,
        replacement_content: &str,
        fence: &mut dyn WorkspaceReplaceCommitFence,
        cancellation: &dyn WorkspaceReplaceCancellation,
        tracker: &mut WorkspaceReplaceMutationTracker,
        faults: &mut F,
    ) -> WorkspaceReplaceCommitOutcome
    where
        F: WorkspaceReplaceFaultInjector,
    {
        // The H2 metadata-only target handle is deliberately released before
        // the exclusive operation open.  Keeping it alive would make the
        // operation's ShareAccess=0 contract depend on H2's weaker sharing
        // mode and would not establish one authoritative mutation handle.
        let PreparedWorkspaceTarget {
            root,
            relative_path,
            parent_identity,
            target_identity,
            final_path: _,
            kind,
            parent_handle,
            target_handle,
        } = prepared;
        drop(target_handle);

        let mut evidence = WorkspaceReplaceEvidence::default();
        if cancellation.is_cancelled() {
            return replace_denied(evidence, WorkspaceReplaceError::CancellationBeforeMutation);
        }
        if kind != PreparedWorkspaceTargetKind::ExistingFile {
            return replace_denied(evidence, WorkspaceReplaceError::InvalidPreparedTarget);
        }
        let expected_identity = match target_identity {
            Some(identity) => identity,
            None => return replace_denied(evidence, WorkspaceReplaceError::InvalidPreparedTarget),
        };
        let expected_sha256 = match normalized_sha256(expected_sha256) {
            Some(value) => value,
            None => return replace_denied(evidence, WorkspaceReplaceError::InvalidExpectedHash),
        };
        let replacement_bytes = replacement_content.as_bytes();
        if replacement_bytes.len() > WORKSPACE_REPLACE_HARD_MAX_BYTES {
            return replace_denied(evidence, WorkspaceReplaceError::ReplacementTooLarge);
        }

        if verify_root_name(&root).is_err() {
            return replace_denied(evidence, WorkspaceReplaceError::RootIdentityChanged);
        }
        if let Err(error) = verify_replace_parent(&root, &parent_handle, parent_identity) {
            return replace_denied(evidence, error);
        }

        let leaf = relative_path
            .components()
            .last()
            .expect("WorkspaceRelativePath always has one component");
        let operation_handle = match open_exclusive_relative(&parent_handle, leaf) {
            Ok(handle) => handle,
            Err(RelativeOpenError::Missing(_)) => {
                return replace_denied(evidence, WorkspaceReplaceError::TargetMissing)
            }
            Err(RelativeOpenError::Status(_)) => {
                return replace_denied(evidence, WorkspaceReplaceError::TargetBusy)
            }
        };
        evidence.operation_handle_open_count = 1;
        tracker.operation_handle_opened();

        let details =
            match verify_replace_operation_handle(&root, &operation_handle, expected_identity) {
                Ok(details) => details,
                Err(error) => return replace_denied(evidence, error),
            };
        evidence.hard_link_count_after_open = Some(details.number_of_links);
        if details.number_of_links != 1 {
            return replace_denied(evidence, WorkspaceReplaceError::HardLinkAmbiguous);
        }
        if verify_root_name(&root).is_err() {
            return replace_denied(evidence, WorkspaceReplaceError::RootIdentityChanged);
        }
        if let Err(error) = verify_replace_parent(&root, &parent_handle, parent_identity) {
            return replace_denied(evidence, error);
        }

        if !set_file_pointer(&operation_handle, 0) {
            return replace_denied(evidence, WorkspaceReplaceError::OperationHandleIo);
        }
        let current_bytes = match read_replace_utf8_bounded(&operation_handle) {
            Ok(bytes) => bytes,
            Err(ReplaceReadError::TooLarge) => {
                return replace_denied(evidence, WorkspaceReplaceError::CurrentFileTooLarge)
            }
            Err(ReplaceReadError::InvalidUtf8) => {
                return replace_denied(evidence, WorkspaceReplaceError::CurrentContentNotUtf8)
            }
            Err(ReplaceReadError::Io) => {
                return replace_denied(evidence, WorkspaceReplaceError::OperationHandleIo)
            }
        };
        let current_hash = crate::sha256_hex(&current_bytes);
        evidence.bytes_before = Some(current_bytes.len());
        evidence.before_sha256 = Some(current_hash.clone());
        evidence.precommit_sha256 = Some(current_hash.clone());
        evidence.hard_link_count_before_fence = Some(details.number_of_links);
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::InitialHashCheck);
        if current_hash != expected_sha256 {
            return replace_conflict(evidence);
        }

        if faults.fire(WorkspaceReplaceFaultPoint::BeforeCommitFence) {
            return replace_denied(evidence, WorkspaceReplaceError::FaultInjected);
        }

        evidence.fence_calls = 1;
        tracker.fence_called();
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::CommitFence);
        let fence_result = catch_unwind(AssertUnwindSafe(|| fence.check()));
        match fence_result {
            Ok(Ok(())) => {}
            Ok(Err(WorkspaceReplaceFenceError::Denied)) => {
                return replace_denied(evidence, WorkspaceReplaceError::CommitFenceDenied)
            }
            Ok(Err(WorkspaceReplaceFenceError::Cancelled)) => {
                return replace_denied(evidence, WorkspaceReplaceError::CommitFenceCancelled)
            }
            Ok(Err(WorkspaceReplaceFenceError::Stale)) => {
                return replace_denied(evidence, WorkspaceReplaceError::CommitFenceStale)
            }
            Ok(Err(WorkspaceReplaceFenceError::Error)) => {
                return replace_denied(evidence, WorkspaceReplaceError::CommitFenceError)
            }
            Err(_) => return replace_denied(evidence, WorkspaceReplaceError::CommitFencePanic),
        }

        evidence.mutation_attempted = true;
        tracker.mutation_attempted();
        if faults.fire(WorkspaceReplaceFaultPoint::AfterCommitFenceBeforePostFenceChecks) {
            return replace_denied(evidence, WorkspaceReplaceError::FaultInjected);
        }
        if verify_root_name(&root).is_err() {
            return replace_denied(evidence, WorkspaceReplaceError::RootIdentityChanged);
        }
        evidence.post_fence_root_verified = true;
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::PostFenceRootCheck);
        if let Err(error) = verify_replace_parent(&root, &parent_handle, parent_identity) {
            return replace_denied(evidence, error);
        }
        evidence.post_fence_parent_verified = true;
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::PostFenceParentCheck);

        let post_fence_details =
            match verify_replace_operation_handle(&root, &operation_handle, expected_identity) {
                Ok(details) => details,
                Err(error) => return replace_denied(evidence, error),
            };
        evidence.post_fence_target_verified = true;
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::PostFenceTargetCheck);
        if faults.fire(WorkspaceReplaceFaultPoint::AfterPostFenceIdentityCheck) {
            return replace_denied(evidence, WorkspaceReplaceError::FaultInjected);
        }
        evidence.hard_link_count_after_fence = Some(post_fence_details.number_of_links);
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::PostFenceLinkCheck);
        if post_fence_details.number_of_links != 1 {
            return replace_denied(evidence, WorkspaceReplaceError::HardLinkAmbiguous);
        }

        if !set_file_pointer(&operation_handle, 0) {
            return replace_denied(evidence, WorkspaceReplaceError::OperationHandleIo);
        }
        let post_fence_bytes = match read_replace_utf8_bounded(&operation_handle) {
            Ok(bytes) => bytes,
            Err(ReplaceReadError::TooLarge) => {
                return replace_denied(evidence, WorkspaceReplaceError::CurrentFileTooLarge)
            }
            Err(ReplaceReadError::InvalidUtf8) => {
                return replace_denied(evidence, WorkspaceReplaceError::CurrentContentNotUtf8)
            }
            Err(ReplaceReadError::Io) => {
                return replace_denied(evidence, WorkspaceReplaceError::OperationHandleIo)
            }
        };
        let actual_post_fence_hash = crate::sha256_hex(&post_fence_bytes);
        let post_fence_hash = if faults.force_post_fence_hash_mismatch() {
            if expected_sha256 == "0".repeat(64) {
                "1".repeat(64)
            } else {
                "0".repeat(64)
            }
        } else {
            actual_post_fence_hash
        };
        evidence.bytes_post_fence = Some(post_fence_bytes.len());
        evidence.post_fence_sha256 = Some(post_fence_hash.clone());
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::PostFenceHashCheck);
        if post_fence_hash != expected_sha256 {
            return replace_conflict(evidence);
        }
        evidence.post_fence_content_verified = true;
        if faults.fire(WorkspaceReplaceFaultPoint::AfterPostFenceHashCheck) {
            return replace_denied(evidence, WorkspaceReplaceError::FaultInjected);
        }

        let post_fence_cancelled = cancellation.is_cancelled();
        evidence.post_fence_cancellation_checked = true;
        evidence
            .events
            .push(WorkspaceReplaceEvidenceEvent::PostFenceCancellationCheck);
        if post_fence_cancelled {
            return replace_denied(evidence, WorkspaceReplaceError::CancellationBeforeMutation);
        }
        if faults.fire(WorkspaceReplaceFaultPoint::AfterPostFenceCancellationCheck) {
            return replace_denied(evidence, WorkspaceReplaceError::FaultInjected);
        }
        if faults.fire(WorkspaceReplaceFaultPoint::AfterCommitFenceBeforeFirstWrite) {
            return replace_denied(evidence, WorkspaceReplaceError::FaultInjected);
        }
        if !set_file_pointer(&operation_handle, 0) {
            return replace_denied(evidence, WorkspaceReplaceError::OperationHandleIo);
        }
        if faults.fire(WorkspaceReplaceFaultPoint::PanicBeforeFirstMutation) {
            panic!("test-only native panic before first mutation");
        }

        if replacement_bytes.is_empty() {
            if faults.fire(WorkspaceReplaceFaultPoint::BeforeSetEndOfFile) {
                return replace_denied(evidence, WorkspaceReplaceError::FaultInjected);
            }
            tracker.mark_started();
            evidence.mutation_started = true;
            evidence.modifying_syscalls += 1;
            evidence
                .events
                .push(WorkspaceReplaceEvidenceEvent::FirstModifyingSyscall);
            if !set_end_of_file(&operation_handle) {
                return replace_unknown(evidence, WorkspaceReplaceError::SetEndOfFileFailed);
            }
            faults.after_first_modifying_syscall();
            if faults.fire(WorkspaceReplaceFaultPoint::AbortAfterFirstMutation) {
                #[cfg(test)]
                std::process::abort();
            }
            if faults.fire(WorkspaceReplaceFaultPoint::PanicAfterFirstMutation) {
                panic!("test-only native panic after first mutation");
            }
            if faults.fire(WorkspaceReplaceFaultPoint::AfterSetEndOfFile) {
                return replace_unknown(evidence, WorkspaceReplaceError::FaultInjected);
            }
        } else {
            // The operation handle is synchronous and its pointer was reset
            // immediately before the first modifying syscall.  A positive
            // short write continues from the same handle and current file
            // pointer; it never starts a second transaction.
            let mut offset = 0_usize;
            let mut first_write = true;
            while offset < replacement_bytes.len() {
                let remaining = replacement_bytes.len() - offset;
                let request_len = faults.write_chunk_limit(remaining).min(remaining).max(1);
                let mut written = 0_u32;
                if first_write {
                    tracker.mark_started();
                    evidence.mutation_started = true;
                }
                evidence.modifying_syscalls += 1;
                evidence.write_calls += 1;
                if first_write {
                    evidence
                        .events
                        .push(WorkspaceReplaceEvidenceEvent::FirstModifyingSyscall);
                }
                let write_ok = unsafe {
                    WriteFile(
                        operation_handle.0,
                        replacement_bytes[offset..].as_ptr(),
                        request_len as u32,
                        &mut written,
                        std::ptr::null_mut(),
                    ) != 0
                };
                if !write_ok {
                    return replace_unknown(evidence, WorkspaceReplaceError::WriteFailed);
                }
                let reported_written = if faults.force_zero_progress() {
                    0
                } else {
                    written as usize
                };
                if reported_written == 0 {
                    return replace_unknown(evidence, WorkspaceReplaceError::ZeroProgressWrite);
                }
                if reported_written > request_len {
                    return replace_unknown(evidence, WorkspaceReplaceError::ShortWrite);
                }
                offset += reported_written;
                if first_write {
                    first_write = false;
                    faults.after_first_modifying_syscall();
                    if faults.fire(WorkspaceReplaceFaultPoint::AbortAfterFirstMutation) {
                        #[cfg(test)]
                        std::process::abort();
                    }
                    if faults.fire(WorkspaceReplaceFaultPoint::PanicAfterFirstMutation) {
                        panic!("test-only native panic after first mutation");
                    }
                    if faults.fire(WorkspaceReplaceFaultPoint::AfterFirstWrite) {
                        return replace_unknown(evidence, WorkspaceReplaceError::FaultInjected);
                    }
                }
            }
            if faults.fire(WorkspaceReplaceFaultPoint::BeforeSetEndOfFile) {
                return replace_unknown(evidence, WorkspaceReplaceError::SetEndOfFileFailed);
            }
            if !set_file_pointer(&operation_handle, replacement_bytes.len() as i64) {
                return replace_unknown(evidence, WorkspaceReplaceError::OperationHandleIo);
            }
            evidence.modifying_syscalls += 1;
            if !set_end_of_file(&operation_handle) {
                return replace_unknown(evidence, WorkspaceReplaceError::SetEndOfFileFailed);
            }
            if faults.fire(WorkspaceReplaceFaultPoint::AfterSetEndOfFile) {
                return replace_unknown(evidence, WorkspaceReplaceError::FaultInjected);
            }
        }

        if faults.fire(WorkspaceReplaceFaultPoint::BeforeFlush) {
            return replace_unknown(evidence, WorkspaceReplaceError::FlushFailed);
        }
        evidence.modifying_syscalls += 1;
        if unsafe { FlushFileBuffers(operation_handle.0) == 0 } {
            return replace_unknown(evidence, WorkspaceReplaceError::FlushFailed);
        }
        if faults.fire(WorkspaceReplaceFaultPoint::AfterFlushBeforeVerify) {
            return replace_unknown(evidence, WorkspaceReplaceError::FaultInjected);
        }
        if !set_file_pointer(&operation_handle, 0) {
            return replace_unknown(evidence, WorkspaceReplaceError::OperationHandleIo);
        }
        if faults.fire(WorkspaceReplaceFaultPoint::DuringPostVerify) {
            return replace_unknown(evidence, WorkspaceReplaceError::PostWriteVerificationFailed);
        }
        let after_bytes = match read_replace_utf8_bounded(&operation_handle) {
            Ok(bytes) => bytes,
            Err(_) => {
                return replace_unknown(
                    evidence,
                    WorkspaceReplaceError::PostWriteVerificationFailed,
                )
            }
        };
        let after_hash = crate::sha256_hex(&after_bytes);
        evidence.bytes_after = Some(after_bytes.len());
        evidence.after_sha256 = Some(after_hash);
        if after_bytes != replacement_bytes {
            return replace_unknown(evidence, WorkspaceReplaceError::PostWriteVerificationFailed);
        }

        tracker.mark_committed();
        evidence.committed_mutations = 1;
        WorkspaceReplaceCommitOutcome::Committed { evidence }
    }

    fn normalized_sha256(value: &str) -> Option<String> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        Some(value.to_ascii_lowercase())
    }

    fn verify_replace_parent(
        root: &TrustedWorkspaceRoot,
        parent_handle: &Arc<OwnedHandle>,
        expected_identity: WorkspaceRootIdentity,
    ) -> Result<(), WorkspaceReplaceError> {
        let details = inspect_handle_metadata(parent_handle)
            .map_err(|_| WorkspaceReplaceError::OperationHandleIo)?;
        if details.is_reparse {
            return Err(WorkspaceReplaceError::ReparseParent);
        }
        if !details.is_directory || details.identity != expected_identity {
            return Err(WorkspaceReplaceError::ParentIdentityChanged);
        }
        ensure_descendant(root, &details.final_path)
            .map_err(|_| WorkspaceReplaceError::TargetOutsideRoot)
    }

    fn verify_replace_operation_handle(
        root: &TrustedWorkspaceRoot,
        operation_handle: &OwnedHandle,
        expected_identity: WorkspaceRootIdentity,
    ) -> Result<HandleDetails, WorkspaceReplaceError> {
        let details = inspect_handle_metadata(operation_handle)
            .map_err(|_| WorkspaceReplaceError::OperationHandleIo)?;
        if details.is_reparse {
            return Err(WorkspaceReplaceError::ReparseTarget);
        }
        if details.is_directory {
            return Err(WorkspaceReplaceError::InvalidPreparedTarget);
        }
        if details.identity != expected_identity {
            return Err(WorkspaceReplaceError::TargetIdentityChanged);
        }
        ensure_descendant(root, &details.final_path)
            .map_err(|_| WorkspaceReplaceError::TargetOutsideRoot)?;
        Ok(details)
    }

    enum ReplaceReadError {
        TooLarge,
        InvalidUtf8,
        Io,
    }

    fn read_replace_utf8_bounded(handle: &OwnedHandle) -> Result<Vec<u8>, ReplaceReadError> {
        let mut bytes = Vec::with_capacity(WORKSPACE_REPLACE_HARD_MAX_BYTES + 1);
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let remaining = WORKSPACE_REPLACE_HARD_MAX_BYTES + 1 - bytes.len();
            if remaining == 0 {
                return Err(ReplaceReadError::TooLarge);
            }
            let request = remaining.min(buffer.len()) as u32;
            let mut read = 0_u32;
            let ok = unsafe {
                ReadFile(
                    handle.0,
                    buffer.as_mut_ptr(),
                    request,
                    &mut read,
                    std::ptr::null_mut(),
                ) != 0
            };
            if !ok || read as usize > request as usize {
                return Err(ReplaceReadError::Io);
            }
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read as usize]);
            if bytes.len() > WORKSPACE_REPLACE_HARD_MAX_BYTES {
                return Err(ReplaceReadError::TooLarge);
            }
        }
        std::str::from_utf8(&bytes).map_err(|_| ReplaceReadError::InvalidUtf8)?;
        Ok(bytes)
    }

    fn set_file_pointer(handle: &OwnedHandle, position: i64) -> bool {
        let mut new_position = 0_i64;
        unsafe {
            SetFilePointerEx(handle.0, position, &mut new_position, FILE_BEGIN) != 0
                && new_position == position
        }
    }

    fn set_end_of_file(handle: &OwnedHandle) -> bool {
        unsafe { SetEndOfFile(handle.0) != 0 }
    }

    fn replace_denied(
        evidence: WorkspaceReplaceEvidence,
        error: WorkspaceReplaceError,
    ) -> WorkspaceReplaceCommitOutcome {
        WorkspaceReplaceCommitOutcome::Denied { error, evidence }
    }

    fn replace_conflict(evidence: WorkspaceReplaceEvidence) -> WorkspaceReplaceCommitOutcome {
        WorkspaceReplaceCommitOutcome::Conflict { evidence }
    }

    fn replace_unknown(
        mut evidence: WorkspaceReplaceEvidence,
        error: WorkspaceReplaceError,
    ) -> WorkspaceReplaceCommitOutcome {
        evidence.commit_unknown = true;
        WorkspaceReplaceCommitOutcome::CommitUnknown { error, evidence }
    }

    fn read_utf8_bounded(
        handle: &OwnedHandle,
        max_bytes: usize,
    ) -> Result<String, WorkspaceReadError> {
        let mut bytes = Vec::with_capacity(max_bytes + 1);
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            let remaining = max_bytes + 1 - bytes.len();
            if remaining == 0 {
                return Err(WorkspaceReadError::TooLarge { limit: max_bytes });
            }
            let request = remaining.min(buffer.len()) as u32;
            let mut read = 0_u32;
            let ok = unsafe {
                ReadFile(
                    handle.0,
                    buffer.as_mut_ptr(),
                    request,
                    &mut read,
                    std::ptr::null_mut(),
                )
            } != 0;
            if !ok {
                return Err(WorkspaceReadError::Kernel(VitaAgentError::KernelConfig(
                    io::Error::last_os_error(),
                )));
            }
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..read as usize]);
            if bytes.len() > max_bytes {
                return Err(WorkspaceReadError::TooLarge { limit: max_bytes });
            }
        }
        String::from_utf8(bytes).map_err(|_| WorkspaceReadError::InvalidUtf8)
    }

    fn inspect_handle(
        handle: &OwnedHandle,
        require_directory: bool,
    ) -> Result<HandleDetails, VitaAgentError> {
        let details = inspect_handle_metadata(handle)?;
        if details.is_reparse {
            return Err(VitaAgentError::UnsafePath {
                field: TARGET_FIELD,
                path: PathBuf::new(),
                reason: "reparse points are forbidden",
            });
        }
        if require_directory && !details.is_directory {
            return Err(VitaAgentError::UnsafePath {
                field: TARGET_FIELD,
                path: PathBuf::new(),
                reason: "workspace path component is not a directory",
            });
        }
        Ok(details)
    }

    fn inspect_handle_metadata(handle: &OwnedHandle) -> Result<HandleDetails, VitaAgentError> {
        let mut legacy = BY_HANDLE_FILE_INFORMATION::default();
        let ok = unsafe { GetFileInformationByHandle(handle.0, &mut legacy) } != 0;
        if !ok {
            return Err(VitaAgentError::KernelConfig(io::Error::last_os_error()));
        }
        let is_directory = legacy.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let is_reparse = legacy.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0;
        if unsafe { GetFileType(handle.0) } != FILE_TYPE_DISK {
            return Err(VitaAgentError::UnsafePath {
                field: TARGET_FIELD,
                path: PathBuf::new(),
                reason: "workspace handle is not a disk object",
            });
        }
        let identity = file_identity(handle, &legacy)?;
        let final_path = final_path_from_handle(handle)?;
        Ok(HandleDetails {
            identity,
            final_path,
            is_directory,
            is_reparse,
            number_of_links: legacy.nNumberOfLinks,
        })
    }

    fn file_identity(
        handle: &OwnedHandle,
        legacy: &BY_HANDLE_FILE_INFORMATION,
    ) -> Result<WorkspaceRootIdentity, VitaAgentError> {
        let mut info = FILE_ID_INFO::default();
        let modern = unsafe {
            GetFileInformationByHandleEx(
                handle.0,
                FileIdInfo as FILE_INFO_BY_HANDLE_CLASS,
                (&mut info as *mut FILE_ID_INFO).cast::<c_void>(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } != 0;
        if modern {
            return Ok(WorkspaceRootIdentity::windows(
                info.VolumeSerialNumber,
                info.FileId.Identifier,
            ));
        }

        let mut file_id = [0_u8; 16];
        file_id[..4].copy_from_slice(&legacy.nFileIndexLow.to_le_bytes());
        file_id[4..8].copy_from_slice(&legacy.nFileIndexHigh.to_le_bytes());
        Ok(WorkspaceRootIdentity::windows(
            legacy.dwVolumeSerialNumber as u64,
            file_id,
        ))
    }

    fn final_path_from_handle(handle: &OwnedHandle) -> Result<PathBuf, VitaAgentError> {
        let mut buffer = vec![0_u16; 32_768];
        let length = unsafe {
            GetFinalPathNameByHandleW(
                handle.0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED,
            )
        };
        if length == 0 || length >= buffer.len() as u32 {
            return Err(VitaAgentError::KernelConfig(io::Error::last_os_error()));
        }
        String::from_utf16(&buffer[..length as usize])
            .map(PathBuf::from)
            .map_err(|_| {
                VitaAgentError::KernelInvariant("Windows returned a non-UTF-16 final path")
            })
    }

    fn ensure_descendant(root: &TrustedWorkspaceRoot, path: &Path) -> Result<(), VitaAgentError> {
        ensure_descendant_path(root.final_path(), path)
    }

    fn ensure_descendant_path(root_path: &Path, path: &Path) -> Result<(), VitaAgentError> {
        let root_path = normalize_path_for_comparison(root_path);
        let child_path = normalize_path_for_comparison(path);
        let root_prefix = if root_path.ends_with('\\') {
            root_path.clone()
        } else {
            format!("{root_path}\\")
        };
        if child_path == root_path || child_path.starts_with(&root_prefix) {
            Ok(())
        } else {
            Err(unsafe_root_path(
                path,
                "handle-relative resolution escaped the trusted root",
            ))
        }
    }

    fn same_path(left: &Path, right: &Path) -> bool {
        normalize_path_for_comparison(left) == normalize_path_for_comparison(right)
    }

    fn is_same_or_descendant_path(parent: &Path, child: &Path) -> bool {
        let parent = normalize_path_for_comparison(parent);
        let child = normalize_path_for_comparison(child);
        let prefix = if parent.ends_with('\\') {
            parent.clone()
        } else {
            format!("{parent}\\")
        };
        child == parent || child.starts_with(&prefix)
    }

    fn verify_relative_parents(
        root: &TrustedWorkspaceRoot,
        components: &[&OsStr],
        expected_identities: &[WorkspaceRootIdentity],
        requested: &Path,
    ) -> Result<(), VitaAgentError> {
        let mut handle = Arc::clone(&root.inner.handle);
        for (index, component) in components
            .iter()
            .take(components.len().saturating_sub(1))
            .enumerate()
        {
            let child = match open_relative(&handle, component, true) {
                Ok(child) => child,
                Err(error) => return Err(relative_open_error(requested, error)),
            };
            let details = inspect_handle(&child, true)?;
            ensure_descendant(root, &details.final_path)?;
            if expected_identities.get(index + 1).copied() != Some(details.identity) {
                return Err(VitaAgentError::UnsafePath {
                    field: TARGET_FIELD,
                    path: requested.to_path_buf(),
                    reason: "workspace parent identity changed during preparation",
                });
            }
            handle = Arc::new(child);
        }
        Ok(())
    }

    #[cfg(test)]
    fn open_and_verify_existing_target(
        root: &TrustedWorkspaceRoot,
        parent: &Arc<OwnedHandle>,
        leaf: &OsStr,
        expected_identity: WorkspaceRootIdentity,
        expected_kind: PreparedWorkspaceTargetKind,
        requested: &Path,
    ) -> Result<(OwnedHandle, HandleDetails), VitaAgentError> {
        let handle = match open_relative(parent, leaf, false) {
            Ok(handle) => handle,
            Err(RelativeOpenError::Missing(_)) => {
                return Err(VitaAgentError::UnsafePath {
                    field: TARGET_FIELD,
                    path: requested.to_path_buf(),
                    reason: "workspace target disappeared during same-handle rebind",
                })
            }
            Err(error) => return Err(relative_open_error(requested, error)),
        };
        let details = inspect_handle(&handle, false)?;
        ensure_descendant(root, &details.final_path)?;
        let actual_kind = if details.is_directory {
            PreparedWorkspaceTargetKind::ExistingDirectory
        } else {
            PreparedWorkspaceTargetKind::ExistingFile
        };
        if details.identity != expected_identity || actual_kind != expected_kind {
            return Err(VitaAgentError::UnsafePath {
                field: TARGET_FIELD,
                path: requested.to_path_buf(),
                reason: "workspace target identity or kind changed during same-handle rebind",
            });
        }
        Ok((handle, details))
    }

    fn verify_target_name_current(
        root: &TrustedWorkspaceRoot,
        parent: &Arc<OwnedHandle>,
        leaf: &OsStr,
        expected_identity: Option<WorkspaceRootIdentity>,
        expected_kind: PreparedWorkspaceTargetKind,
        requested: &Path,
    ) -> Result<(), VitaAgentError> {
        match open_relative(parent, leaf, false) {
            Ok(handle) => {
                let details = inspect_handle(&handle, false)?;
                ensure_descendant(root, &details.final_path)?;
                let actual_kind = if details.is_directory {
                    PreparedWorkspaceTargetKind::ExistingDirectory
                } else {
                    PreparedWorkspaceTargetKind::ExistingFile
                };
                if expected_identity != Some(details.identity) || expected_kind != actual_kind {
                    return Err(VitaAgentError::UnsafePath {
                        field: TARGET_FIELD,
                        path: requested.to_path_buf(),
                        reason: "workspace target identity changed during preparation",
                    });
                }
            }
            Err(RelativeOpenError::Missing(status)) if is_missing_status(status) => {
                if expected_kind != PreparedWorkspaceTargetKind::Missing {
                    return Err(VitaAgentError::UnsafePath {
                        field: TARGET_FIELD,
                        path: requested.to_path_buf(),
                        reason: "workspace target disappeared during preparation",
                    });
                }
            }
            Err(error) => return Err(relative_open_error(requested, error)),
        }
        Ok(())
    }

    fn nul_terminated(path: &Path) -> Vec<u16> {
        let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        wide.push(0);
        wide
    }

    fn is_invalid_handle(handle: HANDLE) -> bool {
        handle.is_null() || handle == INVALID_HANDLE_VALUE
    }

    fn is_missing_status(status: NTSTATUS) -> bool {
        matches!(
            status,
            STATUS_NO_SUCH_FILE | STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND
        )
    }

    enum RelativeOpenError {
        Missing(NTSTATUS),
        Status(NTSTATUS),
    }

    fn relative_open_error(path: &Path, error: RelativeOpenError) -> VitaAgentError {
        let reason = match error {
            RelativeOpenError::Missing(_) => "required directory component is missing",
            RelativeOpenError::Status(_) => "handle-relative workspace open failed closed",
        };
        VitaAgentError::UnsafePath {
            field: TARGET_FIELD,
            path: path.to_path_buf(),
            reason,
        }
    }

    fn unsafe_root_path(path: &Path, reason: &'static str) -> VitaAgentError {
        VitaAgentError::UnsafePath {
            field: ROOT_FIELD,
            path: path.to_path_buf(),
            reason,
        }
    }

    #[cfg(test)]
    pub(super) fn prepare_target_with_hook<F>(
        root: &TrustedWorkspaceRoot,
        relative: WorkspaceRelativePath,
        hook: F,
    ) -> Result<PreparedWorkspaceTarget, VitaAgentError>
    where
        F: FnMut(),
    {
        prepare_target_impl(root, relative, hook)
    }

    #[cfg(test)]
    pub(super) fn root_with_requested_path_for_test(
        root: &TrustedWorkspaceRoot,
        requested_path: PathBuf,
    ) -> TrustedWorkspaceRoot {
        TrustedWorkspaceRoot {
            inner: Arc::new(TrustedWorkspaceRootInner {
                requested_path,
                final_path: root.inner.final_path.clone(),
                identity: root.inner.identity,
                handle: Arc::clone(&root.inner.handle),
            }),
        }
    }

    #[cfg(test)]
    pub(super) fn verify_parent_identities_for_test(
        root: &TrustedWorkspaceRoot,
        relative: &WorkspaceRelativePath,
        expected_identities: &[WorkspaceRootIdentity],
    ) -> Result<(), VitaAgentError> {
        let components = relative.components().collect::<Vec<_>>();
        verify_relative_parents(root, &components, expected_identities, relative.as_path())
    }

    #[cfg(test)]
    pub(super) fn verify_target_identity_for_test(
        root: &TrustedWorkspaceRoot,
        relative: &WorkspaceRelativePath,
        expected_identity: WorkspaceRootIdentity,
    ) -> Result<(), VitaAgentError> {
        let components = relative.components().collect::<Vec<_>>();
        let leaf = components
            .last()
            .expect("WorkspaceRelativePath always has one component");
        let mut parent_handle = Arc::clone(&root.inner.handle);
        for component in components.iter().take(components.len().saturating_sub(1)) {
            let child = match open_relative(&parent_handle, component, true) {
                Ok(child) => child,
                Err(error) => return Err(relative_open_error(relative.as_path(), error)),
            };
            let details = inspect_handle(&child, true)?;
            ensure_descendant(root, &details.final_path)?;
            parent_handle = Arc::new(child);
        }

        let handle = match open_relative(&parent_handle, leaf, false) {
            Ok(handle) => handle,
            Err(error) => return Err(relative_open_error(relative.as_path(), error)),
        };
        let details = inspect_handle(&handle, false)?;
        let kind = if details.is_directory {
            PreparedWorkspaceTargetKind::ExistingDirectory
        } else {
            PreparedWorkspaceTargetKind::ExistingFile
        };
        drop(handle);
        verify_target_name_current(
            root,
            &parent_handle,
            leaf,
            Some(expected_identity),
            kind,
            relative.as_path(),
        )
    }

    #[cfg(test)]
    pub(super) fn rebind_existing_target_for_test(
        prepared: &PreparedWorkspaceTarget,
    ) -> Result<WorkspaceRootIdentity, VitaAgentError> {
        let expected_identity = prepared.target_identity.ok_or(VitaAgentError::UnsafePath {
            field: TARGET_FIELD,
            path: prepared.relative_path.to_path_buf(),
            reason: "missing target has no existing identity to rebind",
        })?;
        if prepared.kind == PreparedWorkspaceTargetKind::Missing {
            return Err(VitaAgentError::UnsafePath {
                field: TARGET_FIELD,
                path: prepared.relative_path.to_path_buf(),
                reason: "missing target has no existing kind to rebind",
            });
        }

        let parent_details = inspect_handle(&prepared.parent_handle, true)?;
        ensure_descendant(&prepared.root, &parent_details.final_path)?;
        if parent_details.identity != prepared.parent_identity {
            return Err(VitaAgentError::UnsafePath {
                field: TARGET_FIELD,
                path: prepared.relative_path.to_path_buf(),
                reason: "workspace parent identity changed before same-handle rebind",
            });
        }
        let leaf = prepared
            .relative_path
            .components()
            .last()
            .expect("WorkspaceRelativePath always has one component");

        // This H2 test helper intentionally requests only the metadata access
        // available to H2.  A future H3 operation must replace this with the
        // exact access mask for its operation and continue using the returned
        // handle after these checks, without reopening the pathname.
        let (handle, details) = open_and_verify_existing_target(
            &prepared.root,
            &prepared.parent_handle,
            leaf,
            expected_identity,
            prepared.kind,
            prepared.relative_path.as_path(),
        )?;
        prepared.root.verify_named_path_current()?;
        let identity = details.identity;
        drop(handle);
        Ok(identity)
    }

    #[cfg(test)]
    pub(super) fn access_masks_for_test() -> (u32, u32) {
        (OPEN_DIRECTORY_ACCESS, OPEN_TARGET_ACCESS)
    }

    #[cfg(test)]
    pub(super) fn replacement_open_contract_for_test() -> (u32, u32, u32) {
        (
            REPLACE_TARGET_ACCESS,
            REPLACE_SHARE_ACCESS,
            REPLACE_CREATE_OPTIONS,
        )
    }

    #[cfg(test)]
    pub(super) fn validate_drive_type_for_test(drive_type: u32) -> Result<(), VitaAgentError> {
        validate_drive_type(Path::new("C:\\"), drive_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn relative_path_rejects_ambiguous_and_dangerous_forms() {
        for path in [
            "",
            "..",
            "../outside",
            "safe/../outside",
            "/absolute",
            "\\absolute",
            "C:\\absolute",
            "C:relative",
            "\\\\server\\share",
            "\\\\?\\C:\\device",
            "safe:file",
            "safe\\\\file",
            "safe//file",
            "safe/",
            ".\\file",
            "CON",
            "LPT1.txt",
            "safe.",
            "safe ",
        ] {
            let result = WorkspaceRelativePath::parse(Path::new(path));
            #[cfg(windows)]
            assert!(result.is_err(), "accepted unsafe relative path {path:?}");
            #[cfg(not(windows))]
            if path != "C:\\absolute" && path != "C:relative" && path != "LPT1.txt" {
                assert!(result.is_err(), "accepted unsafe relative path {path:?}");
            }
        }
        assert!(WorkspaceRelativePath::parse(Path::new("safe/file.txt")).is_ok());
    }

    #[cfg(windows)]
    fn native_symlink(link: &Path, target: &Path, directory: bool) {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateSymbolicLinkW, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE,
            SYMBOLIC_LINK_FLAG_DIRECTORY,
        };

        let mut link_wide = link.as_os_str().encode_wide().collect::<Vec<_>>();
        let mut target_wide = target.as_os_str().encode_wide().collect::<Vec<_>>();
        link_wide.push(0);
        target_wide.push(0);
        let created = unsafe {
            CreateSymbolicLinkW(
                link_wide.as_ptr(),
                target_wide.as_ptr(),
                SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
                    | if directory {
                        SYMBOLIC_LINK_FLAG_DIRECTORY
                    } else {
                        0
                    },
            )
        };
        assert!(created, "native symlink creation failed");
    }

    #[cfg(windows)]
    fn native_dir_symlink(link: &Path, target: &Path) {
        native_symlink(link, target, true);
    }

    #[cfg(windows)]
    fn native_file_symlink(link: &Path, target: &Path) {
        native_symlink(link, target, false);
    }

    #[cfg(windows)]
    #[test]
    fn directory_and_target_access_masks_are_identity_only() {
        use windows_sys::Win32::Storage::FileSystem::{FILE_READ_ATTRIBUTES, FILE_TRAVERSE};

        let (directory_access, target_access) = platform::access_masks_for_test();
        assert_eq!(
            directory_access,
            FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
            "directory handles may only inspect and traverse"
        );
        assert_eq!(
            target_access, FILE_READ_ATTRIBUTES,
            "regular targets must not receive traversal or execution access"
        );
    }

    #[cfg(windows)]
    #[test]
    fn indeterminate_and_remote_drive_types_fail_closed() {
        use windows_sys::Win32::System::WindowsProgramming::{
            DRIVE_FIXED, DRIVE_NO_ROOT_DIR, DRIVE_REMOTE, DRIVE_UNKNOWN,
        };

        assert!(platform::validate_drive_type_for_test(DRIVE_FIXED).is_ok());
        assert!(platform::validate_drive_type_for_test(DRIVE_REMOTE).is_err());
        assert!(platform::validate_drive_type_for_test(DRIVE_UNKNOWN).is_err());
        assert!(platform::validate_drive_type_for_test(DRIVE_NO_ROOT_DIR).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn fresh_root_has_stable_identity_and_prepares_missing_without_creation() {
        let directory = tempdir().expect("tempdir");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let identity = root.identity();
        assert!(identity.volume_serial_number().is_some());
        assert!(identity.file_id().is_some());
        let target = root
            .prepare_target(Path::new("new.txt"))
            .expect("missing target preparation");
        assert_eq!(target.kind(), PreparedWorkspaceTargetKind::Missing);
        assert_eq!(target.parent_identity(), identity);
        assert!(target.target_identity().is_none());
        assert!(!directory.path().join("new.txt").exists());
    }

    #[cfg(windows)]
    #[test]
    fn existing_file_and_directory_are_classified_by_handle() {
        let directory = tempdir().expect("tempdir");
        fs::create_dir(directory.path().join("nested")).expect("nested");
        fs::write(directory.path().join("file.txt"), b"fixture").expect("file");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let file = root
            .prepare_target(Path::new("file.txt"))
            .expect("file prepare");
        let nested = root
            .prepare_target(Path::new("nested"))
            .expect("directory prepare");
        assert_eq!(file.kind(), PreparedWorkspaceTargetKind::ExistingFile);
        assert_eq!(
            nested.kind(),
            PreparedWorkspaceTargetKind::ExistingDirectory
        );
        assert!(file.target_identity().is_some());
        assert!(nested.target_identity().is_some());
    }

    #[cfg(windows)]
    #[test]
    fn repeated_successful_preparations_do_not_report_spurious_busy_or_change_identity() {
        let directory = tempdir().expect("tempdir");
        fs::write(directory.path().join("file.txt"), b"fixture").expect("file");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let first = root
            .prepare_target(Path::new("file.txt"))
            .expect("first preparation");
        let identity = first.target_identity();
        for _ in 0..64 {
            let next = root
                .prepare_target(Path::new("file.txt"))
                .expect("back-to-back preparation");
            assert_eq!(next.kind(), PreparedWorkspaceTargetKind::ExistingFile);
            assert_eq!(next.target_identity(), identity);
        }
    }

    #[cfg(windows)]
    #[test]
    fn root_reparse_point_is_rejected() {
        let directory = tempdir().expect("tempdir");
        let outside = tempdir().expect("outside");
        let link = directory.path().join("root-link");
        native_dir_symlink(&link, outside.path());
        assert!(TrustedWorkspaceRoot::acquire(&link).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn acquisition_ancestor_replacement_race_fails_closed() {
        let directory = tempdir().expect("directory");
        let outside = tempdir().expect("outside");
        let parent = directory.path().join("parent");
        let requested = parent.join("workspace");
        let moved_parent = directory.path().join("parent-old");
        fs::create_dir(&parent).expect("parent");
        fs::create_dir(&requested).expect("workspace");

        let result = platform::acquire_root_with_hook(&requested, || {
            fs::rename(&parent, &moved_parent).expect("rename ancestor");
            native_dir_symlink(&parent, outside.path());
        });

        assert!(
            result.is_err(),
            "an ancestor replaced after anchor acquisition must not redirect the walk"
        );
    }

    #[cfg(windows)]
    #[test]
    fn intermediate_and_final_reparse_points_are_rejected() {
        let directory = tempdir().expect("tempdir");
        let outside = tempdir().expect("outside");
        fs::create_dir(directory.path().join("real")).expect("real");
        let intermediate = directory.path().join("intermediate-link");
        native_dir_symlink(&intermediate, outside.path());
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        assert!(root
            .prepare_target(Path::new("intermediate-link\\file.txt"))
            .is_err());

        let final_link = directory.path().join("final-link");
        native_dir_symlink(&final_link, outside.path());
        assert!(root.prepare_target(Path::new("final-link")).is_err());

        let outside_file = outside.path().join("outside.txt");
        fs::write(&outside_file, b"outside fixture").expect("outside file");
        let final_file_link = directory.path().join("final-file-link");
        native_file_symlink(&final_file_link, &outside_file);
        assert!(root.prepare_target(Path::new("final-file-link")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn case_normalization_is_allowed_for_same_identity() {
        let directory = tempdir().expect("tempdir");
        fs::write(directory.path().join("Case.txt"), b"fixture").expect("file");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let target = root
            .prepare_target(Path::new("case.TXT"))
            .expect("case-insensitive target");
        assert_eq!(target.kind(), PreparedWorkspaceTargetKind::ExistingFile);
    }

    #[cfg(windows)]
    #[test]
    fn root_rename_is_denied_until_root_capability_drops() {
        let directory = tempdir().expect("tempdir");
        let requested = directory.path().join("root");
        let replacement = directory.path().join("replacement");
        fs::create_dir(&requested).expect("root");
        let root = TrustedWorkspaceRoot::acquire(&requested).expect("acquire root");
        let identity = root.identity();
        let final_path = root.final_path().to_path_buf();
        assert!(
            fs::rename(&requested, &replacement).is_err(),
            "the retained root capability must block rename while alive"
        );
        assert!(root.verify_named_path_current().is_ok());
        assert_eq!(root.identity(), identity);
        assert_eq!(root.final_path(), final_path.as_path());

        drop(root);
        fs::rename(&requested, &replacement).expect("rename after root capability drop");
    }

    #[cfg(windows)]
    #[test]
    fn root_identity_mismatch_fails_closed() {
        let directory = tempdir().expect("directory");
        let requested = directory.path().join("root");
        let other = directory.path().join("other");
        fs::create_dir(&requested).expect("root");
        fs::create_dir(&other).expect("other");
        let root = TrustedWorkspaceRoot::acquire(&requested).expect("acquire root");
        let rebound = platform::root_with_requested_path_for_test(&root, other);

        assert!(
            rebound.verify_named_path_current().is_err(),
            "a different current name must not validate against the held identity"
        );
    }

    #[cfg(windows)]
    #[test]
    fn intermediate_replacement_cannot_escape_handle_walk() {
        let directory = tempdir().expect("tempdir");
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).expect("nested");
        fs::write(nested.join("secret.txt"), b"nested fixture").expect("nested fixture");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");

        let replacement = directory.path().join("nested-old");
        let prepared = platform::prepare_target_with_hook(
            &root,
            WorkspaceRelativePath::parse(Path::new("nested\\secret.txt")).expect("relative"),
            || {
                assert!(
                    fs::rename(&nested, &replacement).is_err(),
                    "the retained parent capability must block intermediate rename"
                );
            },
        )
        .expect("handle-relative preparation");
        assert_eq!(prepared.kind(), PreparedWorkspaceTargetKind::ExistingFile);

        drop(prepared);
        fs::rename(&nested, &replacement).expect("rename after parent capability drop");
        assert!(!directory.path().join("secret.txt").exists());
    }

    #[cfg(windows)]
    #[test]
    fn prepared_parent_rename_is_denied_until_preparation_drops() {
        let directory = tempdir().expect("directory");
        let nested = directory.path().join("nested");
        let moved = directory.path().join("nested-moved");
        fs::create_dir(&nested).expect("nested");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let prepared = root
            .prepare_target(Path::new("nested\\new.txt"))
            .expect("missing target preparation");

        assert!(
            fs::rename(&nested, &moved).is_err(),
            "the retained prepared parent must block rename while alive"
        );
        drop(prepared);
        fs::rename(&nested, &moved).expect("rename after prepared parent drop");
    }

    #[cfg(windows)]
    #[test]
    fn existing_target_metadata_capability_allows_external_rename() {
        let directory = tempdir().expect("directory");
        let target = directory.path().join("target.txt");
        let moved = directory.path().join("target-moved.txt");
        fs::write(&target, b"fixture").expect("target");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let prepared = root
            .prepare_target(Path::new("target.txt"))
            .expect("target preparation");

        fs::rename(&target, &moved).expect("metadata-only H2 handle permits rename");
        assert_eq!(prepared.kind(), PreparedWorkspaceTargetKind::ExistingFile);
        assert!(prepared.target_identity().is_some());
        drop(prepared);
        assert!(moved.exists());
    }

    #[cfg(windows)]
    #[test]
    fn existing_target_rebind_rejects_replacement_identity() {
        let directory = tempdir().expect("directory");
        let target = directory.path().join("a.txt");
        let moved = directory.path().join("old.txt");
        fs::write(&target, b"original").expect("original target");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let prepared = root
            .prepare_target(Path::new("a.txt"))
            .expect("target preparation");
        assert!(prepared.target_identity().is_some());

        fs::rename(&target, &moved).expect("rename original target");
        fs::write(&target, b"replacement").expect("replacement target");

        assert!(
            platform::rebind_existing_target_for_test(&prepared).is_err(),
            "a replacement at the same relative name must fail identity rebind"
        );
    }

    #[cfg(windows)]
    #[test]
    fn existing_target_rebind_rejects_renamed_away_name() {
        let directory = tempdir().expect("directory");
        let target = directory.path().join("a.txt");
        let moved = directory.path().join("old.txt");
        fs::write(&target, b"original").expect("original target");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let prepared = root
            .prepare_target(Path::new("a.txt"))
            .expect("target preparation");

        fs::rename(&target, &moved).expect("rename original target");

        assert!(
            platform::rebind_existing_target_for_test(&prepared).is_err(),
            "a renamed-away target must fail identity rebind as missing"
        );
    }

    #[cfg(windows)]
    #[test]
    fn existing_target_rebind_accepts_unchanged_identity() {
        let directory = tempdir().expect("directory");
        let target = directory.path().join("a.txt");
        fs::write(&target, b"original").expect("original target");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let prepared = root
            .prepare_target(Path::new("a.txt"))
            .expect("target preparation");
        let expected_identity = prepared.target_identity().expect("target identity");

        let rebound_identity =
            platform::rebind_existing_target_for_test(&prepared).expect("unchanged target rebind");
        assert_eq!(rebound_identity, expected_identity);
    }

    #[cfg(windows)]
    #[test]
    fn parent_identity_mismatch_fails_closed() {
        let directory = tempdir().expect("directory");
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).expect("nested");
        fs::write(nested.join("file.txt"), b"fixture").expect("file");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let relative =
            WorkspaceRelativePath::parse(Path::new("nested\\file.txt")).expect("relative");

        assert!(
            platform::verify_parent_identities_for_test(
                &root,
                &relative,
                &[root.identity(), root.identity()]
            )
            .is_err(),
            "a changed parent identity must fail closed"
        );
    }

    #[cfg(windows)]
    #[test]
    fn target_identity_mismatch_fails_closed() {
        let directory = tempdir().expect("directory");
        let target = directory.path().join("target.txt");
        fs::write(&target, b"fixture").expect("target");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let relative = WorkspaceRelativePath::parse(Path::new("target.txt")).expect("relative");

        assert!(
            platform::verify_target_identity_for_test(&root, &relative, root.identity()).is_err(),
            "a changed target identity must fail closed"
        );
    }

    #[cfg(windows)]
    #[test]
    fn hard_link_identity_is_explicitly_shared_inode_semantics() {
        let directory = tempdir().expect("tempdir");
        let inside = directory.path().join("inside.txt");
        let alias = directory.path().join("alias.txt");
        fs::write(&inside, b"fixture").expect("inside fixture");
        fs::hard_link(&inside, &alias).expect("hard link");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let prepared = root
            .prepare_target(Path::new("inside.txt"))
            .expect("prepare");
        assert_eq!(prepared.kind(), PreparedWorkspaceTargetKind::ExistingFile);
        assert!(prepared.target_identity().is_some());
        // H2 prevents reparse traversal, not a second hard-link pathname for
        // the same inode.  A future creation policy must address that alias
        // explicitly when it needs a new object rather than an identity.
    }

    #[cfg(windows)]
    fn prepared_fixture(
        initial: &[u8],
    ) -> (
        tempfile::TempDir,
        TrustedWorkspaceRoot,
        PreparedWorkspaceTarget,
    ) {
        let directory = tempdir().expect("tempdir");
        fs::write(directory.path().join("target.txt"), initial).expect("fixture file");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("acquire root");
        let prepared = root
            .prepare_target(Path::new("target.txt"))
            .expect("prepare target");
        (directory, root, prepared)
    }

    #[cfg(windows)]
    fn allow_fence() -> impl WorkspaceReplaceCommitFence {
        || Ok(())
    }

    #[cfg(windows)]
    fn run_fault(
        initial: &[u8],
        replacement: &str,
        point: platform::WorkspaceReplaceFaultPoint,
    ) -> (tempfile::TempDir, WorkspaceReplaceCommitOutcome) {
        let (directory, _root, prepared) = prepared_fixture(initial);
        let mut fence = allow_fence();
        let cancellation = std::sync::atomic::AtomicBool::new(false);
        let mut faults = platform::WorkspaceReplaceFaultPlan::once(point);
        let outcome = prepared.replace_existing_file_utf8_bounded_with_faults(
            &crate::sha256_hex(initial),
            replacement,
            &mut fence,
            &cancellation,
            &mut faults,
        );
        (directory, outcome)
    }

    #[cfg(windows)]
    #[test]
    fn replacement_open_contract_is_minimal_and_exclusive() {
        use windows_sys::Wdk::Storage::FileSystem::{
            FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_NONE, FILE_WRITE_ATTRIBUTES,
            FILE_WRITE_DATA, SYNCHRONIZE,
        };

        let (access, share, options) = platform::replacement_open_contract_for_test();
        assert_eq!(
            access,
            FILE_READ_DATA
                | FILE_WRITE_DATA
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | SYNCHRONIZE
        );
        assert_eq!(share, FILE_SHARE_NONE);
        assert_eq!(
            options,
            FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
        );
    }

    #[cfg(windows)]
    #[test]
    fn exclusive_same_handle_replace_succeeds() {
        let initial = b"VITA_H4B_ORIGINAL";
        let replacement = "VITA_H4B_REPLACEMENT";
        let (directory, root, prepared) = prepared_fixture(initial);
        let before_identity = prepared.target_identity().expect("target identity");
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            replacement,
            &mut fence,
        );

        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Committed { evidence } => evidence,
            other => panic!("expected committed outcome, got {other:?}"),
        };
        assert_eq!(
            evidence.before_sha256.as_deref(),
            Some(crate::sha256_hex(initial).as_str())
        );
        assert_eq!(
            evidence.after_sha256.as_deref(),
            Some(crate::sha256_hex(replacement.as_bytes()).as_str())
        );
        assert_eq!(evidence.bytes_before, Some(initial.len()));
        assert_eq!(evidence.bytes_after, Some(replacement.len()));
        assert!(evidence.mutation_attempted);
        assert!(evidence.mutation_started);
        assert_eq!(evidence.modifying_syscalls, 3);
        assert_eq!(evidence.committed_mutations, 1);
        assert!(!evidence.commit_unknown);
        assert_eq!(evidence.fence_calls, 1);
        assert_eq!(evidence.hard_link_count_after_open, Some(1));
        assert_eq!(evidence.hard_link_count_before_fence, Some(1));
        assert_eq!(
            fs::read(directory.path().join("target.txt")).expect("read target"),
            replacement.as_bytes()
        );
        let after_identity = root
            .prepare_target(Path::new("target.txt"))
            .expect("reprepare target")
            .target_identity()
            .expect("after identity");
        assert_eq!(before_identity, after_identity);
    }

    #[cfg(windows)]
    #[test]
    fn wrong_expected_hash_conflicts_without_mutation() {
        let initial = b"unchanged fixture";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let mut fence = allow_fence();
        let outcome =
            prepared.replace_existing_file_utf8_bounded(&"0".repeat(64), "replacement", &mut fence);
        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Conflict { evidence } => evidence,
            other => panic!("expected conflict, got {other:?}"),
        };
        assert_eq!(evidence.modifying_syscalls, 0);
        assert!(!evidence.mutation_started);
        assert_eq!(
            fs::read(directory.path().join("target.txt")).expect("read target"),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn commit_fence_denial_has_zero_mutation() {
        let initial = b"fence denial fixture";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_for_fence = std::sync::Arc::clone(&calls);
        let mut fence = move || {
            calls_for_fence.fetch_add(1, Ordering::SeqCst);
            Err(WorkspaceReplaceFenceError::Denied)
        };
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            "replacement",
            &mut fence,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::CommitFenceDenied);
                assert_eq!(evidence.fence_calls, 1);
                assert_eq!(evidence.modifying_syscalls, 0);
                assert!(!evidence.mutation_started);
            }
            other => panic!("expected denied outcome, got {other:?}"),
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn commit_fence_panic_has_zero_mutation() {
        let initial = b"fence panic fixture";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let mut fence =
            || -> Result<(), WorkspaceReplaceFenceError> { panic!("synthetic fence panic") };
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            "replacement",
            &mut fence,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::CommitFencePanic);
                assert_eq!(evidence.fence_calls, 1);
                assert_eq!(evidence.modifying_syscalls, 0);
            }
            other => panic!("expected denied outcome, got {other:?}"),
        }
        assert_eq!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn target_identity_change_denies() {
        let initial = b"original identity fixture";
        let (directory, _root, mut prepared) = prepared_fixture(initial);
        let target = directory.path().join("target.txt");
        let moved = directory.path().join("target-old.txt");
        // The H2 target handle is metadata-only.  Release it in this race
        // fixture so the namespace replacement is deterministic on filesystems
        // that enforce delete sharing on open handles.
        prepared.target_handle = None;
        fs::rename(&target, &moved).expect("move original target");
        fs::write(&target, b"replacement namespace object").expect("new target");

        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            "must not write replacement object",
            &mut fence,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::TargetIdentityChanged);
                assert_eq!(evidence.modifying_syscalls, 0);
            }
            other => panic!("expected identity denial, got {other:?}"),
        }
        assert_eq!(fs::read(&target).unwrap(), b"replacement namespace object");
        assert_eq!(fs::read(&moved).unwrap(), initial);
    }

    #[cfg(windows)]
    #[test]
    fn parent_identity_change_denies() {
        let directory = tempdir().expect("tempdir");
        let nested = directory.path().join("nested");
        fs::create_dir(&nested).expect("nested directory");
        let target = nested.join("target.txt");
        fs::write(&target, b"parent identity fixture").expect("target");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("root");
        let mut prepared = root
            .prepare_target(Path::new("nested\\target.txt"))
            .expect("prepare");
        prepared.parent_identity = root.identity();
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(b"parent identity fixture").as_str(),
            "must not mutate",
            &mut fence,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::ParentIdentityChanged);
                assert_eq!(evidence.modifying_syscalls, 0);
            }
            other => panic!("expected parent denial, got {other:?}"),
        }
        assert_eq!(fs::read(target).unwrap(), b"parent identity fixture");
    }

    #[cfg(windows)]
    struct BusyHandle(windows_sys::Win32::Foundation::HANDLE);

    #[cfg(windows)]
    impl Drop for BusyHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }

    #[cfg(windows)]
    fn open_busy_target(path: &Path) -> BusyHandle {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING,
        };

        let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        wide.push(0);
        let handle: HANDLE = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        assert!(
            !handle.is_null() && handle != INVALID_HANDLE_VALUE,
            "busy fixture open failed"
        );
        BusyHandle(handle)
    }

    #[cfg(windows)]
    #[test]
    fn busy_target_denies() {
        let initial = b"busy fixture";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let _busy = open_busy_target(&directory.path().join("target.txt"));
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            "must not mutate",
            &mut fence,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::TargetBusy);
                assert_eq!(evidence.modifying_syscalls, 0);
            }
            other => panic!("expected busy denial, got {other:?}"),
        }
        drop(_busy);
        assert_eq!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn hard_link_count_gt_one_denies() {
        let directory = tempdir().expect("tempdir");
        let target = directory.path().join("target.txt");
        let alias = directory.path().join("alias.txt");
        let initial = b"hard link fixture";
        fs::write(&target, initial).expect("target");
        fs::hard_link(&target, &alias).expect("hard link");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("root");
        let prepared = root
            .prepare_target(Path::new("target.txt"))
            .expect("prepare");
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            "must not mutate",
            &mut fence,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::HardLinkAmbiguous);
                assert_eq!(evidence.hard_link_count_after_open, Some(2));
                assert_eq!(evidence.hard_link_count_before_fence, None);
                assert_eq!(evidence.modifying_syscalls, 0);
            }
            other => panic!("expected hard-link denial, got {other:?}"),
        }
        assert_eq!(fs::read(&target).unwrap(), initial);
        assert_eq!(fs::read(&alias).unwrap(), initial);
    }

    #[cfg(windows)]
    #[test]
    fn reparse_target_denies() {
        let directory = tempdir().expect("directory");
        let outside = tempdir().expect("outside");
        let target = directory.path().join("target.txt");
        let moved = directory.path().join("target-old.txt");
        let outside_file = outside.path().join("outside.txt");
        fs::write(&target, b"reparse original").expect("target");
        fs::write(&outside_file, b"outside original").expect("outside");
        let root = TrustedWorkspaceRoot::acquire(directory.path()).expect("root");
        let mut prepared = root
            .prepare_target(Path::new("target.txt"))
            .expect("prepare");
        prepared.target_handle = None;
        fs::rename(&target, &moved).expect("move target");
        native_file_symlink(&target, &outside_file);

        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(b"reparse original").as_str(),
            "must not follow link",
            &mut fence,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::ReparseTarget);
                assert_eq!(evidence.modifying_syscalls, 0);
            }
            other => panic!("expected reparse denial, got {other:?}"),
        }
        assert_eq!(fs::read(&outside_file).unwrap(), b"outside original");
        assert_eq!(fs::read(&moved).unwrap(), b"reparse original");
    }

    #[cfg(windows)]
    #[test]
    fn current_file_oversize_denies() {
        let initial = vec![b'x'; WORKSPACE_REPLACE_HARD_MAX_BYTES + 1];
        let (directory, _root, prepared) = prepared_fixture(&initial);
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(&initial).as_str(),
            "small",
            &mut fence,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::CurrentFileTooLarge);
                assert_eq!(evidence.modifying_syscalls, 0);
            }
            other => panic!("expected oversize denial, got {other:?}"),
        }
        assert_eq!(
            fs::metadata(directory.path().join("target.txt"))
                .unwrap()
                .len(),
            65537
        );
    }

    #[cfg(windows)]
    #[test]
    fn replacement_oversize_denies() {
        let initial = b"small fixture";
        let replacement = "r".repeat(WORKSPACE_REPLACE_HARD_MAX_BYTES + 1);
        let (directory, _root, prepared) = prepared_fixture(initial);
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            &replacement,
            &mut fence,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::ReplacementTooLarge);
                assert_eq!(evidence.modifying_syscalls, 0);
            }
            other => panic!("expected replacement oversize denial, got {other:?}"),
        }
        assert_eq!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn invalid_current_utf8_denies() {
        let initial = [0xff, 0xfe, 0xfd];
        let (directory, _root, prepared) = prepared_fixture(&initial);
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(&initial).as_str(),
            "must not transcode",
            &mut fence,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::CurrentContentNotUtf8);
                assert_eq!(evidence.modifying_syscalls, 0);
            }
            other => panic!("expected UTF-8 denial, got {other:?}"),
        }
        assert_eq!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn shorter_replacement_sets_exact_eof() {
        let initial = b"long original fixture with tail";
        let replacement = "short";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            replacement,
            &mut fence,
        );
        assert!(matches!(
            outcome,
            WorkspaceReplaceCommitOutcome::Committed { .. }
        ));
        assert_eq!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            replacement.as_bytes()
        );
    }

    #[cfg(windows)]
    #[test]
    fn longer_replacement_sets_exact_length() {
        let initial = b"short";
        let replacement = "a longer replacement fixture";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            replacement,
            &mut fence,
        );
        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Committed { evidence } => evidence,
            other => panic!("expected committed outcome, got {other:?}"),
        };
        assert_eq!(evidence.bytes_after, Some(replacement.len()));
        assert_eq!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            replacement.as_bytes()
        );
    }

    #[cfg(windows)]
    #[test]
    fn empty_replacement_preserves_file_identity() {
        let initial = b"truncate me";
        let (directory, root, prepared) = prepared_fixture(initial);
        let before_identity = prepared.target_identity().expect("identity");
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            "",
            &mut fence,
        );
        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Committed { evidence } => evidence,
            other => panic!("expected committed outcome, got {other:?}"),
        };
        assert_eq!(evidence.modifying_syscalls, 2);
        assert_eq!(fs::read(directory.path().join("target.txt")).unwrap(), b"");
        let after_identity = root
            .prepare_target(Path::new("target.txt"))
            .expect("reprepare")
            .target_identity()
            .expect("after identity");
        assert_eq!(before_identity, after_identity);
    }

    #[cfg(windows)]
    #[test]
    fn exact_64k_replacement_succeeds() {
        let initial = b"small original";
        let replacement = "x".repeat(WORKSPACE_REPLACE_HARD_MAX_BYTES);
        let (directory, _root, prepared) = prepared_fixture(initial);
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            &replacement,
            &mut fence,
        );
        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Committed { evidence } => evidence,
            other => panic!("expected committed outcome, got {other:?}"),
        };
        assert_eq!(evidence.bytes_after, Some(WORKSPACE_REPLACE_HARD_MAX_BYTES));
        assert_eq!(
            evidence.after_sha256.as_deref(),
            Some(crate::sha256_hex(replacement.as_bytes()).as_str())
        );
        assert_eq!(
            fs::metadata(directory.path().join("target.txt"))
                .unwrap()
                .len(),
            WORKSPACE_REPLACE_HARD_MAX_BYTES as u64
        );
    }

    #[cfg(windows)]
    #[test]
    fn post_write_hash_matches() {
        let initial = b"hash before";
        let replacement = "hash after";
        let (_directory, _root, prepared) = prepared_fixture(initial);
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            replacement,
            &mut fence,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Committed { evidence } => {
                assert_eq!(evidence.before_sha256, Some(crate::sha256_hex(initial)));
                assert_eq!(
                    evidence.after_sha256,
                    Some(crate::sha256_hex(replacement.as_bytes()))
                );
                assert_eq!(evidence.bytes_after, Some(replacement.len()));
            }
            other => panic!("expected committed outcome, got {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn post_fence_root_parent_target_rechecks_run() {
        let initial = b"post-fence recheck fixture";
        let replacement = "post-fence replacement";
        let (_directory, _root, prepared) = prepared_fixture(initial);
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            replacement,
            &mut fence,
        );
        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Committed { evidence } => evidence,
            other => panic!("expected committed outcome, got {other:?}"),
        };
        assert!(evidence.post_fence_root_verified);
        assert!(evidence.post_fence_parent_verified);
        assert!(evidence.post_fence_target_verified);
        assert_eq!(evidence.hard_link_count_after_fence, Some(1));
        let event_position = |wanted| {
            evidence
                .events
                .iter()
                .position(|event| *event == wanted)
                .expect("evidence event")
        };
        assert!(
            event_position(WorkspaceReplaceEvidenceEvent::InitialHashCheck)
                < event_position(WorkspaceReplaceEvidenceEvent::CommitFence)
        );
        assert!(
            event_position(WorkspaceReplaceEvidenceEvent::CommitFence)
                < event_position(WorkspaceReplaceEvidenceEvent::PostFenceTargetCheck)
        );
        assert!(
            event_position(WorkspaceReplaceEvidenceEvent::PostFenceTargetCheck)
                < event_position(WorkspaceReplaceEvidenceEvent::PostFenceLinkCheck)
        );
        assert!(
            event_position(WorkspaceReplaceEvidenceEvent::PostFenceLinkCheck)
                < event_position(WorkspaceReplaceEvidenceEvent::PostFenceHashCheck)
        );
        assert!(
            event_position(WorkspaceReplaceEvidenceEvent::PostFenceHashCheck)
                < event_position(WorkspaceReplaceEvidenceEvent::PostFenceCancellationCheck)
        );
        assert!(
            event_position(WorkspaceReplaceEvidenceEvent::PostFenceCancellationCheck)
                < event_position(WorkspaceReplaceEvidenceEvent::FirstModifyingSyscall)
        );
    }

    #[cfg(windows)]
    #[test]
    fn post_fence_hard_link_recheck_is_one() {
        let initial = b"post-fence hard-link fixture";
        let (_directory, _root, prepared) = prepared_fixture(initial);
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            "replacement",
            &mut fence,
        );
        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Committed { evidence } => evidence,
            other => panic!("expected committed outcome, got {other:?}"),
        };
        assert_eq!(evidence.hard_link_count_after_fence, Some(1));
        assert_eq!(evidence.hard_link_count_after_open, Some(1));
        assert_eq!(evidence.hard_link_count_before_fence, Some(1));
    }

    #[cfg(windows)]
    #[test]
    fn post_fence_expected_hash_recheck_passes() {
        let initial = b"post-fence hash fixture";
        let (_directory, _root, prepared) = prepared_fixture(initial);
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(initial).as_str(),
            "replacement",
            &mut fence,
        );
        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Committed { evidence } => evidence,
            other => panic!("expected committed outcome, got {other:?}"),
        };
        let expected = crate::sha256_hex(initial);
        assert_eq!(evidence.before_sha256.as_deref(), Some(expected.as_str()));
        assert_eq!(
            evidence.precommit_sha256.as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(
            evidence.post_fence_sha256.as_deref(),
            Some(expected.as_str())
        );
        assert!(evidence.post_fence_content_verified);
    }

    #[cfg(windows)]
    #[test]
    fn post_fence_hash_mismatch_conflicts_without_mutation() {
        let initial = b"post-fence hash mismatch fixture";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let cancellation = std::sync::atomic::AtomicBool::new(false);
        let mut fence = allow_fence();
        let mut faults = platform::WorkspaceReplaceFaultPlan::post_fence_hash_mismatch();
        let outcome = prepared.replace_existing_file_utf8_bounded_with_faults(
            crate::sha256_hex(initial).as_str(),
            "must not mutate",
            &mut fence,
            &cancellation,
            &mut faults,
        );
        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Conflict { evidence } => evidence,
            other => panic!("expected post-fence conflict, got {other:?}"),
        };
        assert_ne!(
            evidence.post_fence_sha256.as_deref(),
            Some(crate::sha256_hex(initial).as_str())
        );
        assert!(!evidence.post_fence_content_verified);
        assert_eq!(evidence.modifying_syscalls, 0);
        assert!(!evidence.mutation_started);
        assert_eq!(
            fs::read(directory.path().join("target.txt")).expect("target"),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn forced_partial_writes_continue_on_same_handle() {
        let initial = b"partial original";
        let replacement = "0123456789abcdef";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let cancellation = std::sync::atomic::AtomicBool::new(false);
        let mut fence = allow_fence();
        let mut faults = platform::WorkspaceReplaceFaultPlan::with_max_write_chunk(3);
        let outcome = prepared.replace_existing_file_utf8_bounded_with_faults(
            crate::sha256_hex(initial).as_str(),
            replacement,
            &mut fence,
            &cancellation,
            &mut faults,
        );
        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Committed { evidence } => evidence,
            other => panic!("expected partial-write commit, got {other:?}"),
        };
        assert!(evidence.write_calls > 1);
        assert_eq!(evidence.operation_handle_open_count, 1);
        assert_eq!(evidence.automatic_retries, 0);
        assert_eq!(evidence.modifying_syscalls, evidence.write_calls + 2);
        assert_eq!(
            fs::read(directory.path().join("target.txt")).expect("target"),
            replacement.as_bytes()
        );
    }

    #[cfg(windows)]
    #[test]
    fn forced_partial_writes_commit_exact_bytes() {
        let initial = b"exact-byte original";
        let replacement = "partial writes preserve every byte";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let cancellation = std::sync::atomic::AtomicBool::new(false);
        let mut fence = allow_fence();
        let mut faults = platform::WorkspaceReplaceFaultPlan::with_max_write_chunk(3);
        let outcome = prepared.replace_existing_file_utf8_bounded_with_faults(
            crate::sha256_hex(initial).as_str(),
            replacement,
            &mut fence,
            &cancellation,
            &mut faults,
        );
        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Committed { evidence } => evidence,
            other => panic!("expected partial-write commit, got {other:?}"),
        };
        assert_eq!(evidence.bytes_after, Some(replacement.len()));
        assert_eq!(
            evidence.after_sha256.as_deref(),
            Some(crate::sha256_hex(replacement.as_bytes()).as_str())
        );
        assert_eq!(
            fs::read(directory.path().join("target.txt")).expect("target"),
            replacement.as_bytes()
        );
    }

    #[cfg(windows)]
    #[test]
    fn partial_write_continuation_is_not_transaction_retry() {
        let initial = b"partial retry distinction";
        let replacement = "abcdefghijklmno";
        let (_directory, _root, prepared) = prepared_fixture(initial);
        let cancellation = std::sync::atomic::AtomicBool::new(false);
        let mut fence = allow_fence();
        let mut faults = platform::WorkspaceReplaceFaultPlan::with_max_write_chunk(3);
        let outcome = prepared.replace_existing_file_utf8_bounded_with_faults(
            crate::sha256_hex(initial).as_str(),
            replacement,
            &mut fence,
            &cancellation,
            &mut faults,
        );
        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Committed { evidence } => evidence,
            other => panic!("expected partial-write commit, got {other:?}"),
        };
        assert_eq!(evidence.fence_calls, 1);
        assert_eq!(evidence.write_calls, replacement.len().div_ceil(3));
        assert_eq!(evidence.automatic_retries, 0);
    }

    #[cfg(windows)]
    #[test]
    fn same_handle_preserved_across_partial_write_loop() {
        let initial = b"same-handle original";
        let replacement = "same-handle partial replacement";
        let (_directory, _root, prepared) = prepared_fixture(initial);
        let cancellation = std::sync::atomic::AtomicBool::new(false);
        let mut fence = allow_fence();
        let mut faults = platform::WorkspaceReplaceFaultPlan::with_max_write_chunk(3);
        let outcome = prepared.replace_existing_file_utf8_bounded_with_faults(
            crate::sha256_hex(initial).as_str(),
            replacement,
            &mut fence,
            &cancellation,
            &mut faults,
        );
        let evidence = match outcome {
            WorkspaceReplaceCommitOutcome::Committed { evidence } => evidence,
            other => panic!("expected partial-write commit, got {other:?}"),
        };
        assert!(evidence.write_calls > 1);
        assert_eq!(evidence.operation_handle_open_count, 1);
        assert_eq!(
            evidence
                .events
                .iter()
                .filter(|event| **event == WorkspaceReplaceEvidenceEvent::FirstModifyingSyscall)
                .count(),
            1
        );
    }

    #[cfg(windows)]
    #[test]
    fn zero_progress_write_is_commit_unknown() {
        let initial = b"zero progress original";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let cancellation = std::sync::atomic::AtomicBool::new(false);
        let mut fence = allow_fence();
        let mut faults = platform::WorkspaceReplaceFaultPlan::zero_progress_once();
        let outcome = prepared.replace_existing_file_utf8_bounded_with_faults(
            crate::sha256_hex(initial).as_str(),
            "zero progress replacement",
            &mut fence,
            &cancellation,
            &mut faults,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::CommitUnknown { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::ZeroProgressWrite);
                assert!(evidence.commit_unknown);
                assert_eq!(evidence.write_calls, 1);
                assert_eq!(evidence.modifying_syscalls, 1);
                assert_eq!(evidence.automatic_retries, 0);
            }
            other => panic!("expected zero-progress unknown outcome, got {other:?}"),
        }
        assert_ne!(
            fs::read(directory.path().join("target.txt")).expect("target"),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn post_fence_faults_have_zero_mutation() {
        let points = [
            platform::WorkspaceReplaceFaultPoint::AfterCommitFenceBeforePostFenceChecks,
            platform::WorkspaceReplaceFaultPoint::AfterPostFenceIdentityCheck,
            platform::WorkspaceReplaceFaultPoint::AfterPostFenceHashCheck,
            platform::WorkspaceReplaceFaultPoint::AfterPostFenceCancellationCheck,
            platform::WorkspaceReplaceFaultPoint::AfterCommitFenceBeforeFirstWrite,
        ];
        for point in points {
            let initial = b"post-fence fault fixture";
            let (directory, outcome) = run_fault(initial, "must not mutate", point);
            match outcome {
                WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                    assert_eq!(error, WorkspaceReplaceError::FaultInjected);
                    assert_eq!(evidence.modifying_syscalls, 0);
                    assert!(!evidence.mutation_started);
                }
                other => panic!("expected post-fence denial for {point:?}, got {other:?}"),
            }
            assert_eq!(
                fs::read(directory.path().join("target.txt")).expect("target"),
                initial
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn after_commit_fence_before_first_write_has_zero_mutation() {
        let initial = b"after fence fixture";
        let (directory, outcome) = run_fault(
            initial,
            "replacement",
            platform::WorkspaceReplaceFaultPoint::AfterCommitFenceBeforeFirstWrite,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::FaultInjected);
                assert_eq!(evidence.fence_calls, 1);
                assert!(evidence.mutation_attempted);
                assert!(!evidence.mutation_started);
                assert_eq!(evidence.modifying_syscalls, 0);
            }
            other => panic!("expected pre-mutation denial, got {other:?}"),
        }
        assert_eq!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn before_commit_fence_has_zero_mutation() {
        let initial = b"before fence fixture";
        let (directory, outcome) = run_fault(
            initial,
            "replacement",
            platform::WorkspaceReplaceFaultPoint::BeforeCommitFence,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::FaultInjected);
                assert_eq!(evidence.fence_calls, 0);
                assert_eq!(evidence.modifying_syscalls, 0);
            }
            other => panic!("expected pre-fence denial, got {other:?}"),
        }
        assert_eq!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn failure_after_first_write_is_commit_unknown() {
        let initial = b"after write fixture";
        let (directory, outcome) = run_fault(
            initial,
            "replacement",
            platform::WorkspaceReplaceFaultPoint::AfterFirstWrite,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::CommitUnknown { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::FaultInjected);
                assert!(evidence.mutation_started);
                assert!(evidence.commit_unknown);
                assert_eq!(evidence.modifying_syscalls, 1);
            }
            other => panic!("expected unknown outcome, got {other:?}"),
        }
        assert_ne!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn set_eof_failure_is_commit_unknown() {
        let initial = b"set eof fixture with tail";
        let (directory, outcome) = run_fault(
            initial,
            "short",
            platform::WorkspaceReplaceFaultPoint::BeforeSetEndOfFile,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::CommitUnknown { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::SetEndOfFileFailed);
                assert!(evidence.commit_unknown);
                assert_eq!(evidence.modifying_syscalls, 1);
            }
            other => panic!("expected EOF unknown outcome, got {other:?}"),
        }
        assert_ne!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn after_set_eof_is_commit_unknown() {
        let initial = b"after EOF fixture with tail";
        let (directory, outcome) = run_fault(
            initial,
            "short",
            platform::WorkspaceReplaceFaultPoint::AfterSetEndOfFile,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::CommitUnknown { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::FaultInjected);
                assert!(evidence.commit_unknown);
                assert_eq!(evidence.modifying_syscalls, 2);
            }
            other => panic!("expected EOF unknown outcome, got {other:?}"),
        }
        assert_ne!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn flush_failure_is_commit_unknown() {
        let initial = b"flush fixture with tail";
        let (directory, outcome) = run_fault(
            initial,
            "short",
            platform::WorkspaceReplaceFaultPoint::BeforeFlush,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::CommitUnknown { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::FlushFailed);
                assert!(evidence.commit_unknown);
                assert_eq!(evidence.modifying_syscalls, 2);
            }
            other => panic!("expected flush unknown outcome, got {other:?}"),
        }
        assert_ne!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn after_flush_before_verify_is_commit_unknown() {
        let initial = b"after flush fixture";
        let (directory, outcome) = run_fault(
            initial,
            "replacement",
            platform::WorkspaceReplaceFaultPoint::AfterFlushBeforeVerify,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::CommitUnknown { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::FaultInjected);
                assert!(evidence.commit_unknown);
                assert_eq!(evidence.modifying_syscalls, 3);
            }
            other => panic!("expected post-flush unknown outcome, got {other:?}"),
        }
        assert_ne!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn post_verify_failure_is_commit_unknown() {
        let initial = b"post verify fixture";
        let (directory, outcome) = run_fault(
            initial,
            "replacement",
            platform::WorkspaceReplaceFaultPoint::DuringPostVerify,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::CommitUnknown { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::PostWriteVerificationFailed);
                assert!(evidence.commit_unknown);
                assert_eq!(evidence.modifying_syscalls, 3);
            }
            other => panic!("expected post-verify unknown outcome, got {other:?}"),
        }
        assert_ne!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn no_automatic_retry_after_commit_unknown() {
        let initial = b"no retry fixture";
        let (directory, outcome) = run_fault(
            initial,
            "replacement",
            platform::WorkspaceReplaceFaultPoint::AfterFirstWrite,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::CommitUnknown { evidence, .. } => {
                assert_eq!(evidence.fence_calls, 1);
                assert_eq!(evidence.modifying_syscalls, 1);
                assert_eq!(evidence.committed_mutations, 0);
            }
            other => panic!("expected unknown outcome, got {other:?}"),
        }
        assert_ne!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn cancellation_before_fence_has_zero_mutation() {
        let initial = b"cancel before fixture";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let cancellation = std::sync::atomic::AtomicBool::new(true);
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded_with_cancellation(
            crate::sha256_hex(initial).as_str(),
            "must not mutate",
            &mut fence,
            &cancellation,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::CancellationBeforeMutation);
                assert_eq!(evidence.fence_calls, 0);
                assert_eq!(evidence.modifying_syscalls, 0);
            }
            other => panic!("expected cancellation denial, got {other:?}"),
        }
        assert_eq!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn cancellation_at_fence_has_zero_mutation() {
        let initial = b"cancel at fence fixture";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let cancellation = std::sync::atomic::AtomicBool::new(false);
        let mut fence = || Err(WorkspaceReplaceFenceError::Cancelled);
        let outcome = prepared.replace_existing_file_utf8_bounded_with_cancellation(
            crate::sha256_hex(initial).as_str(),
            "must not mutate",
            &mut fence,
            &cancellation,
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::CommitFenceCancelled);
                assert_eq!(evidence.fence_calls, 1);
                assert_eq!(evidence.modifying_syscalls, 0);
            }
            other => panic!("expected fence cancellation, got {other:?}"),
        }
        assert_eq!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn cancellation_after_fence_before_first_mutation_has_zero_side_effect() {
        let initial = b"cancel after fence fixture";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let cancellation = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancellation_for_fence = std::sync::Arc::clone(&cancellation);
        let mut fence = move || {
            cancellation_for_fence.store(true, Ordering::Release);
            Ok(())
        };
        let outcome = prepared.replace_existing_file_utf8_bounded_with_cancellation(
            crate::sha256_hex(initial).as_str(),
            "must not mutate",
            &mut fence,
            cancellation.as_ref(),
        );
        match outcome {
            WorkspaceReplaceCommitOutcome::Denied { error, evidence } => {
                assert_eq!(error, WorkspaceReplaceError::CancellationBeforeMutation);
                assert_eq!(evidence.fence_calls, 1);
                assert!(evidence.post_fence_cancellation_checked);
                assert_eq!(evidence.modifying_syscalls, 0);
                assert!(!evidence.mutation_started);
            }
            other => panic!("expected post-fence cancellation denial, got {other:?}"),
        }
        assert_eq!(
            fs::read(directory.path().join("target.txt")).expect("target"),
            initial
        );
    }

    #[cfg(windows)]
    #[test]
    fn cancellation_after_actual_first_mutation_is_not_reported_as_denied() {
        let initial = b"cancel after fixture";
        let replacement = "replacement after cancellation";
        let (directory, _root, prepared) = prepared_fixture(initial);
        let cancellation = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut faults = platform::WorkspaceReplaceFaultPlan::default();
        faults.cancel_after_first_modifying_syscall(std::sync::Arc::clone(&cancellation));
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded_with_faults(
            crate::sha256_hex(initial).as_str(),
            replacement,
            &mut fence,
            cancellation.as_ref(),
            &mut faults,
        );
        assert!(matches!(
            outcome,
            WorkspaceReplaceCommitOutcome::Committed { .. }
                | WorkspaceReplaceCommitOutcome::CommitUnknown { .. }
        ));
        assert!(cancellation.load(Ordering::Acquire));
        assert_eq!(
            fs::read(directory.path().join("target.txt")).unwrap(),
            replacement.as_bytes()
        );
    }

    #[cfg(windows)]
    #[test]
    fn raw_handle_never_leaves_native_boundary() {
        let (_directory, _root, prepared) = prepared_fixture(b"raw handle fixture");
        let prepared_debug = format!("{prepared:?}");
        assert!(!prepared_debug.contains("OwnedHandle"));
        assert!(!prepared_debug.contains("HANDLE"));
        let mut fence = allow_fence();
        let outcome = prepared.replace_existing_file_utf8_bounded(
            crate::sha256_hex(b"raw handle fixture").as_str(),
            "replacement",
            &mut fence,
        );
        let outcome_debug = format!("{outcome:?}");
        assert!(!outcome_debug.contains("HANDLE"));
        assert!(!outcome_debug.contains("OwnedHandle"));
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_replace_fails_closed() {
        let path = PathBuf::from("/vita-h4b-test.txt");
        let root = TrustedWorkspaceRoot {
            inner: Arc::new(TrustedWorkspaceRootInner {
                requested_path: path.clone(),
                final_path: path,
                identity: WorkspaceRootIdentity::unavailable(),
            }),
        };
        let relative = WorkspaceRelativePath::parse(Path::new("target.txt")).expect("relative");
        let prepared = PreparedWorkspaceTarget {
            root: root.clone(),
            relative_path: relative,
            parent_identity: root.identity(),
            target_identity: Some(root.identity()),
            final_path: None,
            kind: PreparedWorkspaceTargetKind::ExistingFile,
        };
        let mut fence = || Ok(());
        let cancellation = std::sync::atomic::AtomicBool::new(false);
        let outcome = prepared.replace_existing_file_utf8_bounded_with_cancellation(
            &"0".repeat(64),
            "must not use std::fs::write",
            &mut fence,
            &cancellation,
        );
        assert!(matches!(
            outcome,
            WorkspaceReplaceCommitOutcome::Denied {
                error: WorkspaceReplaceError::UnavailableOnThisPlatform,
                ..
            }
        ));
    }
}
