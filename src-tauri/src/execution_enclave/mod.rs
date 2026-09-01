//! D29-B: private ephemeral Codex App Server thread/turn protocol foundation.
//!
//! This module deliberately has no production caller.  It records the exact
//! upstream contract and provides a private, testable process boundary for a
//! later governed execution stage.  In particular, this is not a capability,
//! autonomy, Chat, or Tauri command surface.

use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    ffi::OsString,
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    },
};

#[cfg(all(windows, test))]
use windows_sys::Win32::System::JobObjects::{IsProcessInJob, QueryInformationJobObject};

#[cfg(all(windows, test))]
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// The only upstream release accepted by this foundation.
pub(crate) const CODEX_UPSTREAM_REPOSITORY: &str = "https://github.com/openai/codex.git";
pub(crate) const CODEX_UPSTREAM_RELEASE: &str = "rust-v0.152.0";
/// The immutable upstream commit peeled from the release tag above.
pub(crate) const CODEX_UPSTREAM_COMMIT: &str = "316795b3cf2a45e90d121d9f46499d4658b2645c";
/// SHA-256 of the exact upstream combined JSON schema at the pinned commit.
pub(crate) const CODEX_PROTOCOL_SCHEMA_HASH: &str =
    "d8faa38d5f00aa7ddfe635a2d374ee5f871ffd217d4d175c72fbe7f009f4f669";
pub(crate) const CODEX_PROTOCOL_SCHEMA_SOURCE: &str =
    "codex-rs/app-server-protocol/schema/json/codex_app_server_protocol.schemas.json";
pub(crate) const CODEX_PROTOCOL_SCHEMA_VERSION: &str = "v1";
/// Digital Life's deliberately narrow client-side contract over the upstream
/// App Server protocol.
pub(crate) const CODEX_CLIENT_CONTRACT_VERSION: &str = "d29-b.codex-app-server.v2";

/// Exact upstream methods mapped by the private D29-B lifecycle contract.
pub(crate) const ALLOWED_CLIENT_REQUEST_METHODS: &[&str] =
    &["initialize", "thread/start", "turn/start", "turn/interrupt"];
pub(crate) const ALLOWED_CLIENT_NOTIFICATION_METHODS: &[&str] = &["initialized"];
/// No server request is trusted in D29-B.  Every server request is answered
/// with a protocol-level denial, never an approval.
pub(crate) const ALLOWED_SERVER_REQUEST_METHODS: &[&str] = &[];
/// Only bounded thread/turn/item lifecycle notifications are mapped.  `error`
/// remains informational.  All other server notifications are ignored.
pub(crate) const ALLOWED_SERVER_NOTIFICATION_METHODS: &[&str] = &[
    "error",
    "thread/started",
    "turn/started",
    "item/started",
    "item/completed",
    "turn/completed",
];

const MAX_PROTOCOL_FRAME_BYTES: usize = 64 * 1024;
const MAX_METHOD_BYTES: usize = 128;
const MAX_PROTOCOL_STRING_BYTES: usize = 1024;
const EVENT_QUEUE_CAPACITY: usize = 32;
const MAX_STDERR_CAPTURE_BYTES: usize = 16 * 1024;
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
const KILL_REAP_ATTEMPTS: usize = 2;
const DROP_CLEANUP_ATTEMPTS: usize = 2;
const KILL_REAP_RETRY_DELAY: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CodexUpstreamPin {
    release: &'static str,
    commit: &'static str,
    protocol_schema_hash: &'static str,
    client_contract_version: &'static str,
}

impl CodexUpstreamPin {
    pub(crate) const fn pinned() -> Self {
        Self {
            release: CODEX_UPSTREAM_RELEASE,
            commit: CODEX_UPSTREAM_COMMIT,
            protocol_schema_hash: CODEX_PROTOCOL_SCHEMA_HASH,
            client_contract_version: CODEX_CLIENT_CONTRACT_VERSION,
        }
    }

    pub(crate) const fn release(self) -> &'static str {
        self.release
    }

    pub(crate) const fn commit(self) -> &'static str {
        self.commit
    }

    pub(crate) const fn protocol_schema_hash(self) -> &'static str {
        self.protocol_schema_hash
    }

    pub(crate) const fn client_contract_version(self) -> &'static str {
        self.client_contract_version
    }

    fn accepts_identity(self, release: &str, commit: &str) -> bool {
        release == self.release && commit == self.commit
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexProcessStatus {
    Starting,
    Ready,
    Interrupting,
    ShuttingDown,
    CleanupFailed,
    Exited,
    Crashed,
    BrokenPipe,
}

impl CodexProcessStatus {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Exited | Self::Crashed | Self::BrokenPipe)
    }

    fn rejects_protocol_io(self) -> bool {
        self.is_terminal() || matches!(self, Self::CleanupFailed)
    }
}

#[derive(Debug, PartialEq)]
enum ChildControlObservation<S> {
    Running,
    Exited(S),
    Failed,
}

trait ProcessControl {
    type ExitStatus;

    fn try_wait_control(&mut self) -> ChildControlObservation<Self::ExitStatus>;
    fn kill_control(&mut self) -> bool;
}

impl ProcessControl for Child {
    type ExitStatus = ExitStatus;

    fn try_wait_control(&mut self) -> ChildControlObservation<Self::ExitStatus> {
        match self.try_wait() {
            Ok(Some(status)) => ChildControlObservation::Exited(status),
            Ok(None) => ChildControlObservation::Running,
            Err(_) => ChildControlObservation::Failed,
        }
    }

    fn kill_control(&mut self) -> bool {
        self.kill().is_ok()
    }
}

#[derive(Debug, PartialEq)]
enum ReapDecision<S> {
    Reaped(S),
    RetainOwnership,
}

/// Bounded process-control decision logic shared by the native Child path and
/// deterministic tests.  A kill error is never treated as proof that the
/// child is still alive: the child is observed first, then a short retry
/// window is used before ownership is retained with an error.
fn bounded_kill_reap<C: ProcessControl>(
    control: &mut C,
    max_attempts: usize,
) -> ReapDecision<C::ExitStatus> {
    bounded_kill_reap_with_delay(control, max_attempts, Duration::ZERO)
}

fn bounded_kill_reap_with_delay<C: ProcessControl>(
    control: &mut C,
    max_attempts: usize,
    retry_delay: Duration,
) -> ReapDecision<C::ExitStatus> {
    let attempts = max_attempts.max(1);
    for attempt in 0..attempts {
        let _kill_succeeded = control.kill_control();
        match control.try_wait_control() {
            ChildControlObservation::Exited(status) => return ReapDecision::Reaped(status),
            ChildControlObservation::Failed => return ReapDecision::RetainOwnership,
            ChildControlObservation::Running if attempt + 1 < attempts => {
                if !retry_delay.is_zero() {
                    thread::sleep(retry_delay);
                }
            }
            ChildControlObservation::Running => return ReapDecision::RetainOwnership,
        }
    }
    ReapDecision::RetainOwnership
}

/// A process is never exposed to the protocol client until this admission
/// result succeeds.  The cleanup and close callbacks deliberately run in
/// this order when assignment fails, so an assignment failure cannot return
/// an uncontained child to a caller.
fn fail_closed_containment_assignment(
    assignment: Result<(), ()>,
    terminate_and_reap_child: impl FnOnce() -> bool,
    close_containment: impl FnOnce(),
) -> Result<(), CodexRuntimeError> {
    if assignment.is_ok() {
        return Ok(());
    }

    let child_reaped = terminate_and_reap_child();
    close_containment();
    if child_reaped {
        Err(CodexRuntimeError::ContainmentAssignmentFailed)
    } else {
        Err(CodexRuntimeError::ContainmentAssignmentCleanupFailed)
    }
}

/// Assignment failure happens immediately after spawn, before protocol pipes
/// are handed to `CodexAppServerProcess`.  A direct kill followed by wait is
/// intentional here: an unassigned process cannot rely on Job Object close
/// for cleanup.
fn terminate_and_reap_spawned_child(child: &mut Child) -> bool {
    let _ = child.kill();
    child.wait().is_ok()
}

#[cfg(windows)]
#[derive(Debug)]
struct OwnedJobHandle {
    raw: HANDLE,
    #[cfg(test)]
    close_count: Arc<AtomicUsize>,
}

#[cfg(windows)]
impl OwnedJobHandle {
    fn new(raw: HANDLE) -> Option<Self> {
        if raw.is_null() {
            return None;
        }
        Some(Self {
            raw,
            #[cfg(test)]
            close_count: Arc::new(AtomicUsize::new(0)),
        })
    }
}

// SAFETY: a Windows HANDLE is a process-local kernel reference that can be
// moved between threads.  This type keeps the only owner of that reference;
// it is not Clone or Sync, so CloseHandle still has one serialized owner.
#[cfg(windows)]
unsafe impl Send for OwnedJobHandle {}

#[cfg(windows)]
impl Drop for OwnedJobHandle {
    fn drop(&mut self) {
        #[cfg(test)]
        self.close_count.fetch_add(1, Ordering::AcqRel);

        let raw = std::mem::replace(&mut self.raw, std::ptr::null_mut());
        if !raw.is_null() {
            unsafe {
                let _ = CloseHandle(raw);
            }
        }
    }
}

/// Private, process-local Windows containment.  The job handle is owned by
/// this type only; it is never cloned, serialized, persisted, sent over IPC,
/// or exposed as a raw handle outside this module.
#[cfg(windows)]
#[derive(Debug)]
struct CodexProcessContainment {
    job: Option<OwnedJobHandle>,
}

#[cfg(windows)]
impl CodexProcessContainment {
    fn create() -> Result<Self, CodexRuntimeError> {
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        let Some(job) = OwnedJobHandle::new(raw) else {
            return Err(CodexRuntimeError::ContainmentCreateFailed);
        };

        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job.raw,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) != 0
        };
        if !configured {
            return Err(CodexRuntimeError::ContainmentConfigurationFailed);
        }

        Ok(Self { job: Some(job) })
    }

    fn assign_child(&mut self, child: &Child) -> Result<(), ()> {
        let Some(job) = self.job.as_ref() else {
            return Err(());
        };
        let assigned = unsafe { AssignProcessToJobObject(job.raw, child.as_raw_handle()) != 0 };
        assigned.then_some(()).ok_or(())
    }

    fn close(&mut self) {
        self.job.take();
    }

    #[cfg(test)]
    fn close_counter_for_test(&self) -> Arc<AtomicUsize> {
        Arc::clone(
            &self
                .job
                .as_ref()
                .expect("test containment must own its job")
                .close_count,
        )
    }

    #[cfg(test)]
    fn has_kill_on_close_limit_for_test(&self) -> bool {
        let Some(job) = self.job.as_ref() else {
            return false;
        };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let mut returned_length = 0_u32;
        let queried = unsafe {
            QueryInformationJobObject(
                job.raw,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of_mut!(limits).cast(),
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                &mut returned_length,
            ) != 0
        };
        queried && limits.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0
    }

    #[cfg(test)]
    fn child_is_assigned_for_test(&self, child: &Child) -> bool {
        let Some(job) = self.job.as_ref() else {
            return false;
        };
        let mut is_in_job = 0_i32;
        let queried =
            unsafe { IsProcessInJob(child.as_raw_handle(), job.raw, &mut is_in_job) != 0 };
        queried && is_in_job != 0
    }
}

#[cfg(not(windows))]
#[derive(Debug)]
struct CodexProcessContainment;

#[cfg(not(windows))]
impl CodexProcessContainment {
    fn create() -> Result<Self, CodexRuntimeError> {
        Err(CodexRuntimeError::ContainmentUnavailable)
    }

    fn close(&mut self) {}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexRuntimeError {
    InvalidUpstreamPin,
    InvalidIsolationRoot,
    UntrustedExecutable,
    ContainmentUnavailable,
    ContainmentCreateFailed,
    ContainmentConfigurationFailed,
    ContainmentAssignmentFailed,
    ContainmentAssignmentCleanupFailed,
    SpawnFailed,
    MissingChildPipe,
    UnsupportedMethod,
    AlreadyInitialized,
    InitializeTimeout,
    ProtocolRequestTimeout,
    MalformedProtocol,
    ProtocolError,
    EventQueueSaturated,
    BrokenPipe,
    ChildExited,
    ShutdownFailed,
    ProtocolEncoding,
    ProtocolStateViolation,
    SessionRetired,
    RequestIdExhausted,
    InvalidTurnInput,
}

impl fmt::Display for CodexRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidUpstreamPin => "codex upstream identity is not the pinned release",
            Self::InvalidIsolationRoot => "codex runtime isolation root is not dedicated",
            Self::UntrustedExecutable => "codex runtime executable is outside the trusted boundary",
            Self::ContainmentUnavailable => {
                "codex app server process containment is unavailable on this platform"
            }
            Self::ContainmentCreateFailed => "codex app server Job Object could not be created",
            Self::ContainmentConfigurationFailed => {
                "codex app server Job Object could not be configured"
            }
            Self::ContainmentAssignmentFailed => {
                "codex app server process could not be assigned to its Job Object"
            }
            Self::ContainmentAssignmentCleanupFailed => {
                "codex app server process containment assignment cleanup failed"
            }
            Self::SpawnFailed => "codex app server process could not be started",
            Self::MissingChildPipe => "codex app server process did not expose required pipes",
            Self::UnsupportedMethod => "codex app server method is outside the mapped contract",
            Self::AlreadyInitialized => "codex app server protocol is already initialized",
            Self::InitializeTimeout => "codex app server initialize timed out",
            Self::ProtocolRequestTimeout => "codex app server protocol request timed out",
            Self::MalformedProtocol => "codex app server emitted malformed protocol",
            Self::ProtocolError => "codex app server returned a protocol error",
            Self::EventQueueSaturated => "codex app server event queue is saturated",
            Self::BrokenPipe => "codex app server pipe is closed",
            Self::ChildExited => "codex app server process exited before readiness",
            Self::ShutdownFailed => "codex app server process cleanup failed",
            Self::ProtocolEncoding => "codex app server protocol frame could not be encoded",
            Self::ProtocolStateViolation => {
                "codex app server lifecycle state rejected the operation"
            }
            Self::SessionRetired => "codex app server protocol session is retired",
            Self::RequestIdExhausted => "codex app server request id space is exhausted",
            Self::InvalidTurnInput => "codex app server turn input is not bounded text",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for CodexRuntimeError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodexInitializeResult {
    pub(crate) platform_family: String,
    pub(crate) platform_os: String,
    pub(crate) user_agent: String,
}

/// Runtime adapter carrying the immutable upstream pin.  Its process-launch
/// method is private; the module itself is private from the crate root, so no
/// current App/Life/Chat flow can reach this foundation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CodexRuntimeAdapter {
    pin: CodexUpstreamPin,
}

impl CodexRuntimeAdapter {
    pub(crate) const fn pinned() -> Self {
        Self {
            pin: CodexUpstreamPin::pinned(),
        }
    }

    pub(crate) const fn upstream_pin(self) -> CodexUpstreamPin {
        self.pin
    }

    fn spawn(&self, spec: CodexLaunchSpec) -> Result<CodexAppServerProcess, CodexRuntimeError> {
        #[cfg(not(windows))]
        {
            let _ = spec;
            return Err(CodexRuntimeError::ContainmentUnavailable);
        }

        #[cfg(windows)]
        {
            self.spawn_windows(spec)
        }
    }

    #[cfg(windows)]
    fn spawn_windows(
        &self,
        spec: CodexLaunchSpec,
    ) -> Result<CodexAppServerProcess, CodexRuntimeError> {
        if !self
            .pin
            .accepts_identity(&spec.upstream_release, &spec.upstream_commit)
        {
            return Err(CodexRuntimeError::InvalidUpstreamPin);
        }

        let executable =
            fs::canonicalize(&spec.executable).map_err(|_| CodexRuntimeError::SpawnFailed)?;
        if !executable.is_file() || is_inside_repository(&executable) {
            return Err(CodexRuntimeError::UntrustedExecutable);
        }

        let mut containment = CodexProcessContainment::create()?;

        let mut command = Command::new(&executable);
        command
            .args(&spec.args)
            .current_dir(spec.isolation_root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear()
            // These are protocol identity metadata, not credentials.  No
            // parent environment, API key, token, home, or workspace value is
            // inherited by the child.
            .env("CODEX_D29_UPSTREAM_COMMIT", self.pin.commit())
            .env(
                "CODEX_D29_CLIENT_CONTRACT_VERSION",
                self.pin.client_contract_version(),
            );

        let mut child = command
            .spawn()
            .map_err(|_| CodexRuntimeError::SpawnFailed)?;

        fail_closed_containment_assignment(
            containment.assign_child(&child),
            || terminate_and_reap_spawned_child(&mut child),
            || containment.close(),
        )?;

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let (stdin, stdout, stderr) = match (stdin, stdout, stderr) {
            (Some(stdin), Some(stdout), Some(stderr)) => (stdin, stdout, stderr),
            _ => {
                let _ = terminate_and_reap_spawned_child(&mut child);
                containment.close();
                return Err(CodexRuntimeError::MissingChildPipe);
            }
        };

        Ok(CodexAppServerProcess::new(
            child,
            stdin,
            stdout,
            stderr,
            containment,
            spec.isolation_root,
        ))
    }
}

#[derive(Debug)]
struct CodexLaunchSpec {
    executable: PathBuf,
    args: Vec<OsString>,
    isolation_root: IsolatedExecutionRoot,
    upstream_release: String,
    upstream_commit: String,
}

#[derive(Clone, Debug)]
struct IsolatedExecutionRoot {
    canonical_path: PathBuf,
}

impl IsolatedExecutionRoot {
    #[cfg(test)]
    fn from_dedicated_test_root(path: &Path) -> Result<Self, CodexRuntimeError> {
        let canonical_path =
            fs::canonicalize(path).map_err(|_| CodexRuntimeError::InvalidIsolationRoot)?;
        if !canonical_path.is_dir() || !has_dedicated_root_marker(&canonical_path) {
            return Err(CodexRuntimeError::InvalidIsolationRoot);
        }
        if is_forbidden_location(&canonical_path) {
            return Err(CodexRuntimeError::InvalidIsolationRoot);
        }
        Ok(Self { canonical_path })
    }

    fn path(&self) -> &Path {
        &self.canonical_path
    }
}

impl CodexLaunchSpec {
    #[cfg(test)]
    fn test(executable: &Path, args: &[&str], isolation_root: IsolatedExecutionRoot) -> Self {
        Self {
            executable: executable.to_path_buf(),
            args: args.iter().map(OsString::from).collect(),
            isolation_root,
            upstream_release: CODEX_UPSTREAM_RELEASE.to_owned(),
            upstream_commit: CODEX_UPSTREAM_COMMIT.to_owned(),
        }
    }

    #[cfg(test)]
    fn with_identity(
        executable: &Path,
        args: &[&str],
        isolation_root: IsolatedExecutionRoot,
        upstream_release: &str,
        upstream_commit: &str,
    ) -> Self {
        Self {
            executable: executable.to_path_buf(),
            args: args.iter().map(OsString::from).collect(),
            isolation_root,
            upstream_release: upstream_release.to_owned(),
            upstream_commit: upstream_commit.to_owned(),
        }
    }
}

#[derive(Debug)]
struct CodexAppServerProcess {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    containment: Option<CodexProcessContainment>,
    events: Receiver<ProcessEvent>,
    stop_readers: Arc<AtomicBool>,
    event_queue_overflowed: Arc<AtomicBool>,
    stderr_bytes: Arc<AtomicUsize>,
    stderr_truncated: Arc<AtomicBool>,
    stdout_reader: Option<JoinHandle<()>>,
    stderr_reader: Option<JoinHandle<()>>,
    _isolation_root: IsolatedExecutionRoot,
    status: CodexProcessStatus,
    child_exit_reported: bool,
}

trait ReapedProcessLifecycle {
    fn close_containment(&mut self);
    fn join_readers(&mut self);
    fn clear_child(&mut self);
}

fn finalize_reaped_process<T: ReapedProcessLifecycle>(process: &mut T) {
    process.close_containment();
    process.join_readers();
    process.clear_child();
}

impl ReapedProcessLifecycle for CodexAppServerProcess {
    fn close_containment(&mut self) {
        self.containment.take();
    }

    fn join_readers(&mut self) {
        self.stop_and_join_readers();
    }

    fn clear_child(&mut self) {
        self.child.take();
    }
}

impl CodexAppServerProcess {
    fn new(
        child: Child,
        stdin: ChildStdin,
        stdout: ChildStdout,
        stderr: ChildStderr,
        containment: CodexProcessContainment,
        isolation_root: IsolatedExecutionRoot,
    ) -> Self {
        let (event_sender, events) = mpsc::sync_channel(EVENT_QUEUE_CAPACITY);
        let stop_readers = Arc::new(AtomicBool::new(false));
        let event_queue_overflowed = Arc::new(AtomicBool::new(false));
        let stderr_bytes = Arc::new(AtomicUsize::new(0));
        let stderr_truncated = Arc::new(AtomicBool::new(false));

        let stdout_reader = Some(spawn_stdout_reader(
            stdout,
            event_sender.clone(),
            Arc::clone(&stop_readers),
            Arc::clone(&event_queue_overflowed),
        ));
        let stderr_reader = Some(spawn_stderr_reader(
            stderr,
            Arc::clone(&stop_readers),
            Arc::clone(&stderr_bytes),
            Arc::clone(&stderr_truncated),
        ));

        Self {
            child: Some(child),
            stdin: Some(stdin),
            containment: Some(containment),
            events,
            stop_readers,
            event_queue_overflowed,
            stderr_bytes,
            stderr_truncated,
            stdout_reader,
            stderr_reader,
            _isolation_root: isolation_root,
            status: CodexProcessStatus::Starting,
            child_exit_reported: false,
        }
    }

    fn status(&self) -> CodexProcessStatus {
        self.status
    }

    fn isolation_root_path(&self) -> &Path {
        self._isolation_root.path()
    }

    fn mark_ready(&mut self) {
        if !self.status.is_terminal() {
            self.status = CodexProcessStatus::Ready;
        }
    }

    fn write_json(&mut self, value: Value) -> Result<(), CodexRuntimeError> {
        if self.status.rejects_protocol_io() {
            return Err(CodexRuntimeError::BrokenPipe);
        }
        let encoded =
            serde_json::to_vec(&value).map_err(|_| CodexRuntimeError::ProtocolEncoding)?;
        if encoded.len() > MAX_PROTOCOL_FRAME_BYTES {
            return Err(CodexRuntimeError::ProtocolEncoding);
        }
        self.refresh_child_status();
        if self.status.rejects_protocol_io() {
            return Err(CodexRuntimeError::BrokenPipe);
        }
        let stdin = self.stdin.as_mut().ok_or(CodexRuntimeError::BrokenPipe)?;
        if stdin.write_all(&encoded).is_err() || stdin.write_all(b"\n").is_err() {
            self.stdin.take();
            self.status = CodexProcessStatus::BrokenPipe;
            return Err(CodexRuntimeError::BrokenPipe);
        }
        if stdin.flush().is_err() {
            self.stdin.take();
            self.status = CodexProcessStatus::BrokenPipe;
            return Err(CodexRuntimeError::BrokenPipe);
        }
        Ok(())
    }

    fn next_event(&mut self, timeout: Duration) -> Result<Option<ProcessEvent>, CodexRuntimeError> {
        if self.event_queue_overflowed.swap(false, Ordering::AcqRel) {
            return Err(CodexRuntimeError::EventQueueSaturated);
        }
        if let Some(event) = self.child_exit_event() {
            return Ok(Some(event));
        }
        match self.events.recv_timeout(timeout) {
            Ok(event) => {
                if matches!(event, ProcessEvent::OutputClosed) {
                    self.observe_output_closed();
                }
                Ok(Some(event))
            }
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                if let Some(event) = self.child_exit_event() {
                    Ok(Some(event))
                } else {
                    self.observe_output_closed();
                    Ok(Some(ProcessEvent::OutputClosed))
                }
            }
        }
    }

    fn observe_output_closed(&mut self) {
        self.refresh_child_status();
        if !self.status.is_terminal() {
            // A process that closes the protocol output while retaining a
            // live handle cannot make progress or be considered ready.
            self.stdin.take();
            self.status = CodexProcessStatus::Crashed;
        }
    }

    fn child_exit_event(&mut self) -> Option<ProcessEvent> {
        self.refresh_child_status();
        if self.child_exit_reported {
            return None;
        }
        if self.status.is_terminal() {
            self.child_exit_reported = true;
            return Some(ProcessEvent::ChildExited);
        }
        None
    }

    fn refresh_child_status(&mut self) {
        let Some(child) = self.child.as_mut() else {
            return;
        };
        match child.try_wait() {
            Ok(Some(exit_status)) => self.apply_exit_status(exit_status),
            Ok(None) => {}
            Err(_) => {
                self.stdin.take();
                self.status = CodexProcessStatus::BrokenPipe;
            }
        }
    }

    fn apply_exit_status(&mut self, exit_status: ExitStatus) {
        if matches!(
            self.status,
            CodexProcessStatus::Interrupting | CodexProcessStatus::ShuttingDown
        ) {
            self.status = CodexProcessStatus::Exited;
        } else if exit_status.success() {
            self.status = CodexProcessStatus::Exited;
        } else {
            self.status = CodexProcessStatus::Crashed;
        }
        self.stdin.take();
    }

    fn interrupt(&mut self) -> Result<(), CodexRuntimeError> {
        self.terminate(TerminationIntent::Interrupt)
    }

    fn shutdown(&mut self) -> Result<(), CodexRuntimeError> {
        self.terminate(TerminationIntent::Shutdown)
    }

    fn terminate(&mut self, intent: TerminationIntent) -> Result<(), CodexRuntimeError> {
        if self.child.is_none() {
            finalize_reaped_process(self);
            return Ok(());
        }

        if !self.status.is_terminal() {
            self.status = match intent {
                TerminationIntent::Interrupt => CodexProcessStatus::Interrupting,
                TerminationIntent::Shutdown => CodexProcessStatus::ShuttingDown,
            };
        }
        self.stdin.take();

        let deadline = Instant::now() + SHUTDOWN_GRACE;
        let mut exited = false;
        while Instant::now() < deadline {
            let wait_result = self
                .child
                .as_mut()
                .expect("child exists until reap")
                .try_wait();
            match wait_result {
                Ok(Some(exit_status)) => {
                    self.apply_exit_status(exit_status);
                    exited = true;
                    break;
                }
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(_) => break,
            }
        }

        if !exited {
            let reap_decision = {
                let child = self.child.as_mut().expect("child exists until reap");
                bounded_kill_reap_with_delay(child, KILL_REAP_ATTEMPTS, KILL_REAP_RETRY_DELAY)
            };
            match reap_decision {
                ReapDecision::Reaped(exit_status) => {
                    self.apply_exit_status(exit_status);
                }
                ReapDecision::RetainOwnership => {
                    self.status = CodexProcessStatus::CleanupFailed;
                    // The child and both reader handles remain owned by this
                    // object.  A caller may retry, and Drop retains the child
                    // until its final bounded cleanup and containment close.
                    return Err(CodexRuntimeError::ShutdownFailed);
                }
            }
        }

        finalize_reaped_process(self);
        Ok(())
    }

    fn stop_and_join_readers(&mut self) {
        self.stop_readers.store(true, Ordering::Release);
        if let Some(reader) = self.stdout_reader.take() {
            let _ = reader.join();
        }
        if let Some(reader) = self.stderr_reader.take() {
            let _ = reader.join();
        }
    }

    fn terminate_for_drop(&mut self) {
        for _ in 0..DROP_CLEANUP_ATTEMPTS {
            if self.terminate(TerminationIntent::Shutdown).is_ok() {
                return;
            }
        }

        if self.child.is_some() {
            // Keep Child owned while closing the Job Object.  The kernel's
            // KILL_ON_JOB_CLOSE rule is the final containment boundary; only
            // after it is closed do we make the short final wait/reap.
            self.containment.take();
            self.reap_after_containment_close();
        } else {
            self.containment.take();
        }
    }

    fn reap_after_containment_close(&mut self) {
        for attempt in 0..DROP_CLEANUP_ATTEMPTS {
            let wait_result = self
                .child
                .as_mut()
                .expect("child remains owned until final containment reap")
                .try_wait();
            match wait_result {
                Ok(Some(exit_status)) => {
                    self.apply_exit_status(exit_status);
                    finalize_reaped_process(self);
                    return;
                }
                Ok(None) if attempt + 1 < DROP_CLEANUP_ATTEMPTS => {
                    thread::sleep(KILL_REAP_RETRY_DELAY);
                }
                Ok(None) | Err(_) => break,
            }
        }

        // Do not turn a containment cleanup timeout into an Exited claim.  The
        // child remains locally owned until normal field destruction, but its
        // Job Object has already been closed and therefore remains kernel
        // contained during that destruction.
        self.status = CodexProcessStatus::CleanupFailed;
    }

    #[cfg(test)]
    fn wait_for_terminal(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while !self.status.is_terminal() && Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = self.next_event(remaining.min(Duration::from_millis(10)));
        }
        self.refresh_child_status();
        self.status.is_terminal()
    }

    #[cfg(test)]
    fn has_child(&self) -> bool {
        self.child.is_some()
    }

    #[cfg(test)]
    fn stderr_capture_state(&self) -> (usize, bool) {
        (
            self.stderr_bytes.load(Ordering::Acquire),
            self.stderr_truncated.load(Ordering::Acquire),
        )
    }
}

impl Drop for CodexAppServerProcess {
    fn drop(&mut self) {
        self.terminate_for_drop();
    }
}

#[derive(Clone, Copy)]
enum TerminationIntent {
    Interrupt,
    Shutdown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum CodexProtocolState {
    Uninitialized,
    Initialized,
    ThreadReady {
        thread_id: String,
    },
    TurnStarting {
        thread_id: String,
    },
    TurnRunning {
        thread_id: String,
        turn_id: String,
        started_event_seen: bool,
    },
    TurnCompleted {
        thread_id: String,
        turn_id: String,
    },
    TurnInterrupted {
        thread_id: String,
        turn_id: String,
    },
    TurnFailed {
        thread_id: String,
        turn_id: String,
    },
    Retired,
}

impl CodexProtocolState {
    fn thread_id(&self) -> Option<&str> {
        match self {
            Self::ThreadReady { thread_id }
            | Self::TurnStarting { thread_id }
            | Self::TurnRunning { thread_id, .. }
            | Self::TurnCompleted { thread_id, .. }
            | Self::TurnInterrupted { thread_id, .. }
            | Self::TurnFailed { thread_id, .. } => Some(thread_id),
            Self::Uninitialized | Self::Initialized | Self::Retired => None,
        }
    }

    fn active_turn(&self) -> Option<(&str, &str, bool)> {
        match self {
            Self::TurnRunning {
                thread_id,
                turn_id,
                started_event_seen,
            } => Some((thread_id, turn_id, *started_event_seen)),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodexThreadStartResult {
    pub(crate) thread_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CodexTurnStartResult {
    pub(crate) turn_id: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexTurnTerminal {
    Completed,
    Interrupted,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CodexLifecycleEvent {
    ThreadStarted {
        thread_id: String,
    },
    TurnStarted {
        thread_id: String,
        turn_id: String,
    },
    ItemStarted {
        thread_id: String,
        turn_id: String,
        item_id: String,
    },
    ItemCompleted {
        thread_id: String,
        turn_id: String,
        item_id: String,
    },
    TurnCompleted {
        thread_id: String,
        turn_id: String,
        terminal: CodexTurnTerminal,
    },
}

#[derive(Clone, Debug)]
enum ClientRequest {
    Initialize,
    ThreadStart { cwd: String },
    TurnStart { thread_id: String, text: String },
    TurnInterrupt { thread_id: String, turn_id: String },
}

impl ClientRequest {
    fn method(&self) -> &'static str {
        match self {
            Self::Initialize => "initialize",
            Self::ThreadStart { .. } => "thread/start",
            Self::TurnStart { .. } => "turn/start",
            Self::TurnInterrupt { .. } => "turn/interrupt",
        }
    }

    fn params(&self) -> Value {
        match self {
            Self::Initialize => json!({
                "clientInfo": {
                    "name": "digital-life-codex-enclave",
                    "version": CODEX_CLIENT_CONTRACT_VERSION,
                },
                "capabilities": {
                    "experimentalApi": false,
                    "mcpServerOpenaiFormElicitation": false,
                    "requestAttestation": false,
                },
            }),
            Self::ThreadStart { cwd } => json!({
                "cwd": cwd,
                "ephemeral": true,
            }),
            Self::TurnStart { thread_id, text } => json!({
                "threadId": thread_id,
                "input": [{
                    "type": "text",
                    "text": text,
                }],
            }),
            Self::TurnInterrupt { thread_id, turn_id } => json!({
                "threadId": thread_id,
                "turnId": turn_id,
            }),
        }
    }
}

struct CodexProtocolClient {
    process: CodexAppServerProcess,
    next_request_id: u64,
    state: CodexProtocolState,
    retired_turn_ids: VecDeque<String>,
    pending_lifecycle_events: VecDeque<CodexLifecycleEvent>,
}

impl CodexProtocolClient {
    fn new(process: CodexAppServerProcess) -> Self {
        Self {
            process,
            next_request_id: 1,
            state: CodexProtocolState::Uninitialized,
            retired_turn_ids: VecDeque::new(),
            pending_lifecycle_events: VecDeque::new(),
        }
    }

    fn next_process_event(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<ProcessEvent>, CodexRuntimeError> {
        match self.process.next_event(timeout) {
            Ok(event) => Ok(event),
            Err(error) => {
                self.state = CodexProtocolState::Retired;
                Err(error)
            }
        }
    }

    fn initialize(
        &mut self,
        timeout: Duration,
    ) -> Result<CodexInitializeResult, CodexRuntimeError> {
        match self.state {
            CodexProtocolState::Uninitialized => {}
            CodexProtocolState::Retired => return Err(CodexRuntimeError::SessionRetired),
            _ => return Err(CodexRuntimeError::AlreadyInitialized),
        }

        let request_id = self.allocate_request_id()?;
        if let Err(error) = self.send_client_request(request_id, ClientRequest::Initialize) {
            self.state = CodexProtocolState::Retired;
            return Err(error);
        }

        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(CodexRuntimeError::InitializeTimeout);
            }
            let event = self.next_process_event(remaining.min(Duration::from_millis(25)))?;
            let Some(event) = event else {
                continue;
            };
            match event {
                ProcessEvent::Message(ProtocolMessage::Response {
                    id,
                    initialize_result,
                    result_is_object,
                    error_code,
                    ..
                }) if id == RpcId::Number(request_id.into()) => {
                    if error_code.is_some() {
                        self.state = CodexProtocolState::Retired;
                        return Err(CodexRuntimeError::ProtocolError);
                    }
                    if !result_is_object {
                        self.state = CodexProtocolState::Retired;
                        return Err(CodexRuntimeError::MalformedProtocol);
                    }
                    let result = match initialize_result {
                        Some(result) => result,
                        None => {
                            self.state = CodexProtocolState::Retired;
                            return Err(CodexRuntimeError::MalformedProtocol);
                        }
                    };
                    if !result.codex_home_is_bounded_string {
                        self.state = CodexProtocolState::Retired;
                        return Err(CodexRuntimeError::MalformedProtocol);
                    }
                    let result = CodexInitializeResult {
                        platform_family: match result.platform_family {
                            Some(value) => value,
                            None => {
                                self.state = CodexProtocolState::Retired;
                                return Err(CodexRuntimeError::MalformedProtocol);
                            }
                        },
                        platform_os: match result.platform_os {
                            Some(value) => value,
                            None => {
                                self.state = CodexProtocolState::Retired;
                                return Err(CodexRuntimeError::MalformedProtocol);
                            }
                        },
                        user_agent: match result.user_agent {
                            Some(value) => value,
                            None => {
                                self.state = CodexProtocolState::Retired;
                                return Err(CodexRuntimeError::MalformedProtocol);
                            }
                        },
                    };
                    if let Err(error) = self.send_initialized_notification() {
                        self.state = CodexProtocolState::Retired;
                        return Err(error);
                    }
                    self.state = CodexProtocolState::Initialized;
                    self.process.mark_ready();
                    return Ok(result);
                }
                ProcessEvent::Message(ProtocolMessage::ServerRequest { id }) => {
                    self.deny_server_request(id)?;
                }
                ProcessEvent::Message(ProtocolMessage::Notification { notification }) => {
                    if let Some(event) = self.apply_notification(notification)? {
                        self.pending_lifecycle_events.push_back(event);
                    }
                }
                ProcessEvent::Message(ProtocolMessage::Response { .. }) => {}
                ProcessEvent::MalformedProtocol | ProcessEvent::FrameTooLarge => {
                    self.state = CodexProtocolState::Retired;
                    return Err(CodexRuntimeError::MalformedProtocol);
                }
                ProcessEvent::OutputClosed | ProcessEvent::ChildExited => {
                    self.retire_after_process_failure();
                    return Err(CodexRuntimeError::ChildExited);
                }
            }
        }
    }

    fn start_thread(
        &mut self,
        timeout: Duration,
    ) -> Result<CodexThreadStartResult, CodexRuntimeError> {
        match self.state {
            CodexProtocolState::Initialized => {}
            CodexProtocolState::Retired => return Err(CodexRuntimeError::SessionRetired),
            _ => return Err(CodexRuntimeError::ProtocolStateViolation),
        }

        let cwd = self
            .process
            .isolation_root_path()
            .to_str()
            .ok_or(CodexRuntimeError::InvalidIsolationRoot)?
            .to_owned();
        let request_id = self.allocate_request_id()?;
        if let Err(error) =
            self.send_client_request(request_id, ClientRequest::ThreadStart { cwd: cwd.clone() })
        {
            self.state = CodexProtocolState::Retired;
            return Err(error);
        }

        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(CodexRuntimeError::ProtocolRequestTimeout);
            }
            let event = self.next_process_event(remaining.min(Duration::from_millis(25)))?;
            let Some(event) = event else {
                continue;
            };
            match event {
                ProcessEvent::Message(ProtocolMessage::Response {
                    id,
                    thread_start_result,
                    error_code,
                    result_is_object,
                    ..
                }) if id == RpcId::Number(request_id.into()) => {
                    if error_code.is_some() {
                        self.state = CodexProtocolState::Retired;
                        return Err(CodexRuntimeError::ProtocolError);
                    }
                    if !result_is_object {
                        self.state = CodexProtocolState::Retired;
                        return Err(CodexRuntimeError::MalformedProtocol);
                    }
                    let result = match thread_start_result {
                        Some(result) if result.ephemeral && result.cwd == cwd => result,
                        _ => {
                            self.state = CodexProtocolState::Retired;
                            return Err(CodexRuntimeError::MalformedProtocol);
                        }
                    };
                    let thread_id = result.thread_id;
                    self.state = CodexProtocolState::ThreadReady {
                        thread_id: thread_id.clone(),
                    };
                    return Ok(CodexThreadStartResult { thread_id });
                }
                ProcessEvent::Message(ProtocolMessage::ServerRequest { id }) => {
                    self.deny_server_request(id)?;
                }
                ProcessEvent::Message(ProtocolMessage::Notification { notification }) => {
                    if let Some(event) = self.apply_notification(notification)? {
                        self.pending_lifecycle_events.push_back(event);
                    }
                }
                ProcessEvent::Message(ProtocolMessage::Response { .. }) => {}
                ProcessEvent::MalformedProtocol | ProcessEvent::FrameTooLarge => {
                    self.state = CodexProtocolState::Retired;
                    return Err(CodexRuntimeError::MalformedProtocol);
                }
                ProcessEvent::OutputClosed | ProcessEvent::ChildExited => {
                    self.retire_after_process_failure();
                    return Err(CodexRuntimeError::ChildExited);
                }
            }
        }
    }

    fn start_turn(
        &mut self,
        text: &str,
        timeout: Duration,
    ) -> Result<CodexTurnStartResult, CodexRuntimeError> {
        if text.is_empty() || text.len() > MAX_PROTOCOL_STRING_BYTES {
            return Err(CodexRuntimeError::InvalidTurnInput);
        }
        if text.chars().any(char::is_control) {
            return Err(CodexRuntimeError::InvalidTurnInput);
        }

        let thread_id = match &self.state {
            CodexProtocolState::ThreadReady { thread_id }
            | CodexProtocolState::TurnCompleted { thread_id, .. }
            | CodexProtocolState::TurnInterrupted { thread_id, .. }
            | CodexProtocolState::TurnFailed { thread_id, .. } => thread_id.clone(),
            CodexProtocolState::Retired => return Err(CodexRuntimeError::SessionRetired),
            CodexProtocolState::Uninitialized | CodexProtocolState::Initialized => {
                return Err(CodexRuntimeError::ProtocolStateViolation)
            }
            CodexProtocolState::TurnStarting { .. } | CodexProtocolState::TurnRunning { .. } => {
                return Err(CodexRuntimeError::ProtocolStateViolation)
            }
        };

        let request_id = self.allocate_request_id()?;
        self.state = CodexProtocolState::TurnStarting {
            thread_id: thread_id.clone(),
        };
        if let Err(error) = self.send_client_request(
            request_id,
            ClientRequest::TurnStart {
                thread_id: thread_id.clone(),
                text: text.to_owned(),
            },
        ) {
            self.state = CodexProtocolState::Retired;
            return Err(error);
        }

        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                self.state = CodexProtocolState::ThreadReady { thread_id };
                return Err(CodexRuntimeError::ProtocolRequestTimeout);
            }
            let event = self.next_process_event(remaining.min(Duration::from_millis(25)))?;
            let Some(event) = event else {
                continue;
            };
            match event {
                ProcessEvent::Message(ProtocolMessage::Response {
                    id,
                    turn_start_result,
                    error_code,
                    result_is_object,
                    ..
                }) if id == RpcId::Number(request_id.into()) => {
                    if error_code.is_some() {
                        self.state = CodexProtocolState::ThreadReady { thread_id };
                        return Err(CodexRuntimeError::ProtocolError);
                    }
                    if !result_is_object {
                        self.state = CodexProtocolState::Retired;
                        return Err(CodexRuntimeError::MalformedProtocol);
                    }
                    let result = match turn_start_result {
                        Some(result) if result.status == WireTurnStatus::InProgress => result,
                        _ => {
                            self.state = CodexProtocolState::Retired;
                            return Err(CodexRuntimeError::MalformedProtocol);
                        }
                    };
                    let turn_id = result.turn_id;
                    if self
                        .retired_turn_ids
                        .iter()
                        .any(|retired| retired == &turn_id)
                    {
                        self.state = CodexProtocolState::Retired;
                        return Err(CodexRuntimeError::MalformedProtocol);
                    }
                    self.state = CodexProtocolState::TurnRunning {
                        thread_id: thread_id.clone(),
                        turn_id: turn_id.clone(),
                        started_event_seen: false,
                    };
                    return Ok(CodexTurnStartResult { turn_id });
                }
                ProcessEvent::Message(ProtocolMessage::ServerRequest { id }) => {
                    self.deny_server_request(id)?;
                }
                ProcessEvent::Message(ProtocolMessage::Notification { notification }) => {
                    if let Some(event) = self.apply_notification(notification)? {
                        self.pending_lifecycle_events.push_back(event);
                    }
                }
                ProcessEvent::Message(ProtocolMessage::Response { .. }) => {}
                ProcessEvent::MalformedProtocol | ProcessEvent::FrameTooLarge => {
                    self.state = CodexProtocolState::Retired;
                    return Err(CodexRuntimeError::MalformedProtocol);
                }
                ProcessEvent::OutputClosed | ProcessEvent::ChildExited => {
                    self.retire_after_process_failure();
                    return Err(CodexRuntimeError::ChildExited);
                }
            }
        }
    }

    fn interrupt_turn(&mut self, timeout: Duration) -> Result<(), CodexRuntimeError> {
        let (thread_id, turn_id, started_event_seen) = self
            .state
            .active_turn()
            .map(|(thread_id, turn_id, started_event_seen)| {
                (thread_id.to_owned(), turn_id.to_owned(), started_event_seen)
            })
            .ok_or_else(|| {
                if self.state == CodexProtocolState::Retired {
                    CodexRuntimeError::SessionRetired
                } else {
                    CodexRuntimeError::ProtocolStateViolation
                }
            })?;
        if !started_event_seen {
            return Err(CodexRuntimeError::ProtocolStateViolation);
        }

        let request_id = self.allocate_request_id()?;
        if let Err(error) = self.send_client_request(
            request_id,
            ClientRequest::TurnInterrupt {
                thread_id: thread_id.clone(),
                turn_id: turn_id.clone(),
            },
        ) {
            self.state = CodexProtocolState::Retired;
            return Err(error);
        }

        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(CodexRuntimeError::ProtocolRequestTimeout);
            }
            let event = self.next_process_event(remaining.min(Duration::from_millis(25)))?;
            let Some(event) = event else {
                continue;
            };
            match event {
                ProcessEvent::Message(ProtocolMessage::Response {
                    id,
                    error_code,
                    result_is_object,
                    ..
                }) if id == RpcId::Number(request_id.into()) => {
                    if error_code.is_some() {
                        return Err(CodexRuntimeError::ProtocolError);
                    }
                    if !result_is_object {
                        self.state = CodexProtocolState::Retired;
                        return Err(CodexRuntimeError::MalformedProtocol);
                    }
                    return Ok(());
                }
                ProcessEvent::Message(ProtocolMessage::ServerRequest { id }) => {
                    self.deny_server_request(id)?;
                }
                ProcessEvent::Message(ProtocolMessage::Notification { notification }) => {
                    if let Some(event) = self.apply_notification(notification)? {
                        self.pending_lifecycle_events.push_back(event);
                    }
                }
                ProcessEvent::Message(ProtocolMessage::Response { .. }) => {}
                ProcessEvent::MalformedProtocol | ProcessEvent::FrameTooLarge => {
                    self.state = CodexProtocolState::Retired;
                    return Err(CodexRuntimeError::MalformedProtocol);
                }
                ProcessEvent::OutputClosed | ProcessEvent::ChildExited => {
                    self.retire_after_process_failure();
                    return Err(CodexRuntimeError::ChildExited);
                }
            }
        }
    }

    fn allocate_request_id(&mut self) -> Result<u64, CodexRuntimeError> {
        if self.next_request_id == u64::MAX {
            self.state = CodexProtocolState::Retired;
            return Err(CodexRuntimeError::RequestIdExhausted);
        }
        let request_id = self.next_request_id;
        self.next_request_id += 1;
        Ok(request_id)
    }

    fn send_client_request(
        &mut self,
        request_id: u64,
        request: ClientRequest,
    ) -> Result<(), CodexRuntimeError> {
        let method = request.method();
        if !ALLOWED_CLIENT_REQUEST_METHODS.contains(&method) {
            return Err(CodexRuntimeError::UnsupportedMethod);
        }
        self.process.write_json(json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": request.params(),
        }))
    }

    fn send_initialized_notification(&mut self) -> Result<(), CodexRuntimeError> {
        let method = "initialized";
        if !ALLOWED_CLIENT_NOTIFICATION_METHODS.contains(&method) {
            return Err(CodexRuntimeError::UnsupportedMethod);
        }
        self.process.write_json(json!({
            "jsonrpc": "2.0",
            "method": method,
        }))
    }

    fn deny_server_request(&mut self, id: RpcId) -> Result<(), CodexRuntimeError> {
        // No server request is ever treated as an approval.  The method name
        // and params are not retained or executed.
        self.process.write_json(json!({
            "jsonrpc": "2.0",
            "id": id.to_value(),
            "error": {
                "code": -32601,
                "message": "method not allowed",
            },
        }))
    }

    fn next_lifecycle_event(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<CodexLifecycleEvent>, CodexRuntimeError> {
        if let Some(event) = self.pending_lifecycle_events.pop_front() {
            return Ok(Some(event));
        }
        let event = self.next_process_event(timeout)?;
        let Some(event) = event else {
            return Ok(None);
        };
        self.consume_process_event(event)
    }

    fn pump_once(&mut self, timeout: Duration) -> Result<bool, CodexRuntimeError> {
        if self.pending_lifecycle_events.pop_front().is_some() {
            return Ok(true);
        }
        let event = self.next_process_event(timeout)?;
        let Some(event) = event else {
            return Ok(false);
        };
        self.consume_process_event(event)?;
        Ok(true)
    }

    fn consume_process_event(
        &mut self,
        event: ProcessEvent,
    ) -> Result<Option<CodexLifecycleEvent>, CodexRuntimeError> {
        match event {
            ProcessEvent::Message(ProtocolMessage::ServerRequest { id }) => {
                self.deny_server_request(id)?;
                Ok(None)
            }
            ProcessEvent::Message(ProtocolMessage::Notification { notification }) => {
                self.apply_notification(notification)
            }
            ProcessEvent::Message(ProtocolMessage::Response { .. }) => Ok(None),
            ProcessEvent::MalformedProtocol | ProcessEvent::FrameTooLarge => {
                self.state = CodexProtocolState::Retired;
                Err(CodexRuntimeError::MalformedProtocol)
            }
            ProcessEvent::OutputClosed | ProcessEvent::ChildExited => {
                self.retire_after_process_failure();
                Err(CodexRuntimeError::ChildExited)
            }
        }
    }

    fn apply_notification(
        &mut self,
        notification: ProtocolNotification,
    ) -> Result<Option<CodexLifecycleEvent>, CodexRuntimeError> {
        match notification {
            ProtocolNotification::Unknown | ProtocolNotification::Error => Ok(None),
            ProtocolNotification::ThreadStarted { thread_id } => match self.state.thread_id() {
                Some(current_thread_id) if current_thread_id == thread_id => {
                    Ok(Some(CodexLifecycleEvent::ThreadStarted { thread_id }))
                }
                Some(_) => {
                    self.state = CodexProtocolState::Retired;
                    Err(CodexRuntimeError::MalformedProtocol)
                }
                None => Ok(None),
            },
            ProtocolNotification::TurnStarted { thread_id, turn_id } => {
                let state = self.state.clone();
                match state {
                    CodexProtocolState::TurnRunning {
                        thread_id: current_thread_id,
                        turn_id: current_turn_id,
                        started_event_seen,
                    } if current_thread_id == thread_id && current_turn_id == turn_id => {
                        if started_event_seen {
                            return Ok(None);
                        }
                        if let CodexProtocolState::TurnRunning {
                            started_event_seen, ..
                        } = &mut self.state
                        {
                            *started_event_seen = true;
                        }
                        Ok(Some(CodexLifecycleEvent::TurnStarted {
                            thread_id,
                            turn_id,
                        }))
                    }
                    CodexProtocolState::TurnRunning { .. }
                    | CodexProtocolState::TurnCompleted { .. }
                    | CodexProtocolState::TurnInterrupted { .. }
                    | CodexProtocolState::TurnFailed { .. }
                        if self.is_stale_turn(&thread_id, &turn_id) =>
                    {
                        Ok(None)
                    }
                    CodexProtocolState::TurnStarting { .. } => {
                        self.state = CodexProtocolState::Retired;
                        Err(CodexRuntimeError::MalformedProtocol)
                    }
                    CodexProtocolState::ThreadReady { .. } => {
                        self.state = CodexProtocolState::Retired;
                        Err(CodexRuntimeError::MalformedProtocol)
                    }
                    CodexProtocolState::TurnRunning { .. }
                    | CodexProtocolState::TurnCompleted { .. }
                    | CodexProtocolState::TurnInterrupted { .. }
                    | CodexProtocolState::TurnFailed { .. } => {
                        self.state = CodexProtocolState::Retired;
                        Err(CodexRuntimeError::MalformedProtocol)
                    }
                    _ => Ok(None),
                }
            }
            ProtocolNotification::ItemStarted {
                thread_id,
                turn_id,
                item_id,
            } => self.apply_item_notification(true, thread_id, turn_id, item_id),
            ProtocolNotification::ItemCompleted {
                thread_id,
                turn_id,
                item_id,
            } => self.apply_item_notification(false, thread_id, turn_id, item_id),
            ProtocolNotification::TurnCompleted {
                thread_id,
                turn_id,
                status,
            } => {
                let state = self.state.clone();
                match state {
                    CodexProtocolState::TurnRunning {
                        thread_id: current_thread_id,
                        turn_id: current_turn_id,
                        started_event_seen,
                    } if current_thread_id == thread_id && current_turn_id == turn_id => {
                        if !started_event_seen {
                            self.state = CodexProtocolState::Retired;
                            return Err(CodexRuntimeError::MalformedProtocol);
                        }
                        self.remember_retired_turn(&turn_id);
                        self.state = match status {
                            WireTurnStatus::Completed => CodexProtocolState::TurnCompleted {
                                thread_id: thread_id.clone(),
                                turn_id: turn_id.clone(),
                            },
                            WireTurnStatus::Interrupted => CodexProtocolState::TurnInterrupted {
                                thread_id: thread_id.clone(),
                                turn_id: turn_id.clone(),
                            },
                            WireTurnStatus::Failed => CodexProtocolState::TurnFailed {
                                thread_id: thread_id.clone(),
                                turn_id: turn_id.clone(),
                            },
                            WireTurnStatus::InProgress => {
                                self.state = CodexProtocolState::Retired;
                                return Err(CodexRuntimeError::MalformedProtocol);
                            }
                        };
                        Ok(Some(CodexLifecycleEvent::TurnCompleted {
                            thread_id,
                            turn_id,
                            terminal: status.into_terminal().expect("checked terminal status"),
                        }))
                    }
                    CodexProtocolState::TurnCompleted {
                        thread_id: current_thread_id,
                        turn_id: current_turn_id,
                    }
                    | CodexProtocolState::TurnInterrupted {
                        thread_id: current_thread_id,
                        turn_id: current_turn_id,
                    }
                    | CodexProtocolState::TurnFailed {
                        thread_id: current_thread_id,
                        turn_id: current_turn_id,
                    } if current_thread_id == thread_id && current_turn_id == turn_id => {
                        // A repeated terminal notification is harmless but can
                        // never settle the same turn a second time.
                        Ok(None)
                    }
                    CodexProtocolState::TurnRunning { .. }
                    | CodexProtocolState::TurnCompleted { .. }
                    | CodexProtocolState::TurnInterrupted { .. }
                    | CodexProtocolState::TurnFailed { .. }
                        if self.is_stale_turn(&thread_id, &turn_id) =>
                    {
                        Ok(None)
                    }
                    CodexProtocolState::TurnStarting { .. } => {
                        self.state = CodexProtocolState::Retired;
                        Err(CodexRuntimeError::MalformedProtocol)
                    }
                    CodexProtocolState::ThreadReady { .. } => {
                        self.state = CodexProtocolState::Retired;
                        Err(CodexRuntimeError::MalformedProtocol)
                    }
                    CodexProtocolState::TurnRunning { .. }
                    | CodexProtocolState::TurnCompleted { .. }
                    | CodexProtocolState::TurnInterrupted { .. }
                    | CodexProtocolState::TurnFailed { .. } => {
                        self.state = CodexProtocolState::Retired;
                        Err(CodexRuntimeError::MalformedProtocol)
                    }
                    _ => Ok(None),
                }
            }
        }
    }

    fn apply_item_notification(
        &mut self,
        started: bool,
        thread_id: String,
        turn_id: String,
        item_id: String,
    ) -> Result<Option<CodexLifecycleEvent>, CodexRuntimeError> {
        match self.state.active_turn() {
            Some((current_thread_id, current_turn_id, true))
                if current_thread_id == thread_id && current_turn_id == turn_id =>
            {
                if started {
                    Ok(Some(CodexLifecycleEvent::ItemStarted {
                        thread_id,
                        turn_id,
                        item_id,
                    }))
                } else {
                    Ok(Some(CodexLifecycleEvent::ItemCompleted {
                        thread_id,
                        turn_id,
                        item_id,
                    }))
                }
            }
            Some(_) if self.is_stale_turn(&thread_id, &turn_id) => Ok(None),
            Some(_) => {
                self.state = CodexProtocolState::Retired;
                Err(CodexRuntimeError::MalformedProtocol)
            }
            None if self.is_stale_turn(&thread_id, &turn_id) => Ok(None),
            None if self.state.thread_id().is_none() => Ok(None),
            None => {
                self.state = CodexProtocolState::Retired;
                Err(CodexRuntimeError::MalformedProtocol)
            }
        }
    }

    fn is_stale_turn(&self, thread_id: &str, turn_id: &str) -> bool {
        self.state.thread_id() == Some(thread_id)
            && self
                .retired_turn_ids
                .iter()
                .any(|retired| retired == turn_id)
    }

    fn remember_retired_turn(&mut self, turn_id: &str) {
        if self
            .retired_turn_ids
            .iter()
            .any(|retired| retired == turn_id)
        {
            return;
        }
        self.retired_turn_ids.push_back(turn_id.to_owned());
        while self.retired_turn_ids.len() > 16 {
            let _ = self.retired_turn_ids.pop_front();
        }
    }

    fn retire_after_process_failure(&mut self) {
        self.process.refresh_child_status();
        self.state = CodexProtocolState::Retired;
    }

    fn interrupt(&mut self) -> Result<(), CodexRuntimeError> {
        self.process.interrupt()
    }

    fn shutdown(&mut self) -> Result<(), CodexRuntimeError> {
        self.process.shutdown()
    }

    fn status(&self) -> CodexProcessStatus {
        self.process.status()
    }

    #[cfg(test)]
    fn request_for_test(&mut self, method: &str) -> Result<(), CodexRuntimeError> {
        if ALLOWED_CLIENT_REQUEST_METHODS.contains(&method) {
            Err(CodexRuntimeError::ProtocolStateViolation)
        } else {
            Err(CodexRuntimeError::UnsupportedMethod)
        }
    }

    #[cfg(test)]
    fn send_allowed_notification_for_test(&mut self) -> Result<(), CodexRuntimeError> {
        self.send_initialized_notification()
    }

    #[cfg(test)]
    fn wait_for_terminal(&mut self, timeout: Duration) -> bool {
        self.process.wait_for_terminal(timeout)
    }

    #[cfg(test)]
    fn has_child(&self) -> bool {
        self.process.has_child()
    }

    #[cfg(test)]
    fn stderr_capture_state(&self) -> (usize, bool) {
        self.process.stderr_capture_state()
    }
}

#[derive(Clone, Debug)]
enum ProcessEvent {
    Message(ProtocolMessage),
    MalformedProtocol,
    FrameTooLarge,
    OutputClosed,
    ChildExited,
}

#[derive(Clone, Debug)]
enum ProtocolMessage {
    Response {
        id: RpcId,
        initialize_result: Option<InitializeWireResult>,
        thread_start_result: Option<ThreadStartWireResult>,
        turn_start_result: Option<TurnStartWireResult>,
        result_is_object: bool,
        error_code: Option<i64>,
    },
    Notification {
        notification: ProtocolNotification,
    },
    ServerRequest {
        id: RpcId,
    },
}

#[derive(Clone, Debug)]
enum ProtocolNotification {
    Unknown,
    Error,
    ThreadStarted {
        thread_id: String,
    },
    TurnStarted {
        thread_id: String,
        turn_id: String,
    },
    ItemStarted {
        thread_id: String,
        turn_id: String,
        item_id: String,
    },
    ItemCompleted {
        thread_id: String,
        turn_id: String,
        item_id: String,
    },
    TurnCompleted {
        thread_id: String,
        turn_id: String,
        status: WireTurnStatus,
    },
}

#[derive(Clone, Debug, PartialEq)]
enum RpcId {
    Number(serde_json::Number),
    String(String),
}

impl RpcId {
    fn to_value(&self) -> Value {
        match self {
            Self::Number(number) => Value::Number(number.clone()),
            Self::String(value) => Value::String(value.clone()),
        }
    }
}

#[derive(Clone, Debug)]
struct InitializeWireResult {
    codex_home_is_bounded_string: bool,
    platform_family: Option<String>,
    platform_os: Option<String>,
    user_agent: Option<String>,
}

#[derive(Clone, Debug)]
struct ThreadStartWireResult {
    thread_id: String,
    ephemeral: bool,
    cwd: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WireTurnStatus {
    Completed,
    Interrupted,
    Failed,
    InProgress,
}

impl WireTurnStatus {
    fn into_terminal(self) -> Option<CodexTurnTerminal> {
        match self {
            Self::Completed => Some(CodexTurnTerminal::Completed),
            Self::Interrupted => Some(CodexTurnTerminal::Interrupted),
            Self::Failed => Some(CodexTurnTerminal::Failed),
            Self::InProgress => None,
        }
    }
}

#[derive(Clone, Debug)]
struct TurnStartWireResult {
    turn_id: String,
    status: WireTurnStatus,
}

fn spawn_stdout_reader(
    mut stdout: ChildStdout,
    event_sender: SyncSender<ProcessEvent>,
    stop_readers: Arc<AtomicBool>,
    event_queue_overflowed: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut read_buffer = [0_u8; 4096];
        let mut frame = Vec::with_capacity(4096);
        let mut oversized = false;

        loop {
            if stop_readers.load(Ordering::Acquire) {
                break;
            }
            let bytes_read = match stdout.read(&mut read_buffer) {
                Ok(bytes_read) => bytes_read,
                Err(_) => {
                    send_event(
                        &event_sender,
                        &event_queue_overflowed,
                        ProcessEvent::OutputClosed,
                    );
                    break;
                }
            };
            if bytes_read == 0 {
                if !frame.is_empty() || oversized {
                    send_event(
                        &event_sender,
                        &event_queue_overflowed,
                        ProcessEvent::MalformedProtocol,
                    );
                }
                send_event(
                    &event_sender,
                    &event_queue_overflowed,
                    ProcessEvent::OutputClosed,
                );
                break;
            }

            for byte in &read_buffer[..bytes_read] {
                if *byte == b'\n' {
                    if oversized {
                        send_event(
                            &event_sender,
                            &event_queue_overflowed,
                            ProcessEvent::FrameTooLarge,
                        );
                    } else {
                        if frame.last() == Some(&b'\r') {
                            frame.pop();
                        }
                        let event = if frame.is_empty() {
                            ProcessEvent::MalformedProtocol
                        } else {
                            parse_protocol_frame(&frame)
                        };
                        send_event(&event_sender, &event_queue_overflowed, event);
                    }
                    frame.clear();
                    oversized = false;
                } else if !oversized {
                    if frame.len() < MAX_PROTOCOL_FRAME_BYTES {
                        frame.push(*byte);
                    } else {
                        // Keep only a one-bit overflow state.  The remaining
                        // bytes of an oversized line are drained but never
                        // retained in memory.
                        oversized = true;
                        frame.clear();
                    }
                }
            }
        }
    })
}

fn spawn_stderr_reader(
    mut stderr: ChildStderr,
    stop_readers: Arc<AtomicBool>,
    stderr_bytes: Arc<AtomicUsize>,
    stderr_truncated: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut read_buffer = [0_u8; 4096];
        loop {
            if stop_readers.load(Ordering::Acquire) {
                break;
            }
            let bytes_read = match stderr.read(&mut read_buffer) {
                Ok(0) | Err(_) => break,
                Ok(bytes_read) => bytes_read,
            };
            let previous = stderr_bytes.load(Ordering::Acquire);
            let available = MAX_STDERR_CAPTURE_BYTES.saturating_sub(previous);
            let retained = bytes_read.min(available);
            stderr_bytes.fetch_add(retained, Ordering::AcqRel);
            if retained < bytes_read || previous >= MAX_STDERR_CAPTURE_BYTES {
                stderr_truncated.store(true, Ordering::Release);
            }
        }
    })
}

fn send_event(
    event_sender: &SyncSender<ProcessEvent>,
    event_queue_overflowed: &AtomicBool,
    event: ProcessEvent,
) {
    match event_sender.try_send(event) {
        Ok(()) | Err(TrySendError::Disconnected(_)) => {}
        Err(TrySendError::Full(_)) => {
            event_queue_overflowed.store(true, Ordering::Release);
        }
    }
}

fn parse_protocol_frame(frame: &[u8]) -> ProcessEvent {
    let value = match serde_json::from_slice::<Value>(frame) {
        Ok(value) => value,
        Err(_) => return ProcessEvent::MalformedProtocol,
    };
    let Some(object) = value.as_object() else {
        return ProcessEvent::MalformedProtocol;
    };
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return ProcessEvent::MalformedProtocol;
    }

    let has_id = object.contains_key("id");
    let id = if has_id {
        match object.get("id").and_then(parse_rpc_id) {
            Some(id) => Some(id),
            None => return ProcessEvent::MalformedProtocol,
        }
    } else {
        None
    };

    if let Some(method_value) = object.get("method") {
        let Some(method) = bounded_string(method_value, MAX_METHOD_BYTES) else {
            return ProcessEvent::MalformedProtocol;
        };
        if let Some(id) = id {
            // Server requests are denied without retaining method or params.
            // This keeps approval, tool, MCP, auth, and permission surfaces
            // outside the typed D29-B client contract.
            return ProcessEvent::Message(ProtocolMessage::ServerRequest { id });
        }
        let Some(notification) = parse_protocol_notification(&method, object.get("params")) else {
            return ProcessEvent::MalformedProtocol;
        };
        return ProcessEvent::Message(ProtocolMessage::Notification { notification });
    }

    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    if id.is_none() || has_result == has_error {
        return ProcessEvent::MalformedProtocol;
    }

    if has_error {
        let Some(error_object) = object.get("error").and_then(Value::as_object) else {
            return ProcessEvent::MalformedProtocol;
        };
        let Some(error_code) = error_object.get("code").and_then(Value::as_i64) else {
            return ProcessEvent::MalformedProtocol;
        };
        return ProcessEvent::Message(ProtocolMessage::Response {
            id: id.expect("checked above"),
            initialize_result: None,
            thread_start_result: None,
            turn_start_result: None,
            result_is_object: false,
            error_code: Some(error_code),
        });
    }

    let result = object.get("result");
    ProcessEvent::Message(ProtocolMessage::Response {
        id: id.expect("checked above"),
        initialize_result: parse_initialize_wire_result(result),
        thread_start_result: parse_thread_start_wire_result(result),
        turn_start_result: parse_turn_start_wire_result(result),
        result_is_object: result.is_some_and(Value::is_object),
        error_code: None,
    })
}

fn parse_rpc_id(value: &Value) -> Option<RpcId> {
    match value {
        Value::Number(number) if number.as_i64().is_some() => Some(RpcId::Number(number.clone())),
        Value::String(value) if !value.is_empty() && value.len() <= MAX_PROTOCOL_STRING_BYTES => {
            Some(RpcId::String(value.clone()))
        }
        _ => None,
    }
}

fn parse_initialize_wire_result(value: Option<&Value>) -> Option<InitializeWireResult> {
    let object = value?.as_object()?;
    Some(InitializeWireResult {
        codex_home_is_bounded_string: bounded_string(
            object.get("codexHome")?,
            MAX_PROTOCOL_STRING_BYTES,
        )
        .is_some(),
        platform_family: bounded_string(object.get("platformFamily")?, MAX_PROTOCOL_STRING_BYTES),
        platform_os: bounded_string(object.get("platformOs")?, MAX_PROTOCOL_STRING_BYTES),
        user_agent: bounded_string(object.get("userAgent")?, MAX_PROTOCOL_STRING_BYTES),
    })
}

fn parse_thread_start_wire_result(value: Option<&Value>) -> Option<ThreadStartWireResult> {
    let object = value?.as_object()?;
    for required in [
        "approvalPolicy",
        "approvalsReviewer",
        "cwd",
        "model",
        "modelProvider",
        "sandbox",
    ] {
        if !object.contains_key(required) {
            return None;
        }
    }
    let response_cwd = bounded_string(object.get("cwd")?, MAX_PROTOCOL_STRING_BYTES)?;
    let thread = object.get("thread")?.as_object()?;
    let (thread_id, ephemeral, cwd) = parse_thread_wire_object(thread)?;
    if response_cwd != cwd {
        return None;
    }
    Some(ThreadStartWireResult {
        thread_id,
        ephemeral,
        cwd,
    })
}

fn parse_turn_start_wire_result(value: Option<&Value>) -> Option<TurnStartWireResult> {
    let object = value?.as_object()?;
    let turn = object.get("turn")?.as_object()?;
    let (turn_id, status) = parse_turn_wire_object(turn)?;
    Some(TurnStartWireResult { turn_id, status })
}

fn parse_thread_wire_object(
    object: &serde_json::Map<String, Value>,
) -> Option<(String, bool, String)> {
    for required in [
        "cliVersion",
        "createdAt",
        "cwd",
        "ephemeral",
        "id",
        "modelProvider",
        "preview",
        "projectId",
        "sessionId",
        "source",
        "status",
        "turns",
        "updatedAt",
    ] {
        if !object.contains_key(required) {
            return None;
        }
    }
    let thread_id = bounded_opaque_id(object.get("id")?)?;
    let ephemeral = object.get("ephemeral")?.as_bool()?;
    let cwd = bounded_string(object.get("cwd")?, MAX_PROTOCOL_STRING_BYTES)?;
    if object.get("cliVersion")?.as_str()?.len() > MAX_PROTOCOL_STRING_BYTES
        || object.get("modelProvider")?.as_str()?.len() > MAX_PROTOCOL_STRING_BYTES
        || object.get("preview")?.as_str()?.len() > MAX_PROTOCOL_STRING_BYTES
        || object.get("sessionId")?.as_str()?.len() > MAX_PROTOCOL_STRING_BYTES
        || object.get("createdAt")?.as_i64().is_none()
        || object.get("updatedAt")?.as_i64().is_none()
        || !object.get("turns")?.is_array()
        || !object.get("status")?.is_object()
    {
        return None;
    }
    Some((thread_id, ephemeral, cwd))
}

fn parse_turn_wire_object(
    object: &serde_json::Map<String, Value>,
) -> Option<(String, WireTurnStatus)> {
    if !object.get("items")?.is_array() {
        return None;
    }
    Some((
        bounded_opaque_id(object.get("id")?)?,
        parse_wire_turn_status(object.get("status")?)?,
    ))
}

fn parse_protocol_notification(
    method: &str,
    params: Option<&Value>,
) -> Option<ProtocolNotification> {
    if !ALLOWED_SERVER_NOTIFICATION_METHODS.contains(&method) {
        return Some(ProtocolNotification::Unknown);
    }

    match method {
        "error" => Some(ProtocolNotification::Error),
        "thread/started" => {
            let object = params?.as_object()?;
            let thread = object.get("thread")?.as_object()?;
            let (thread_id, _, _) = parse_thread_wire_object(thread)?;
            Some(ProtocolNotification::ThreadStarted { thread_id })
        }
        "turn/started" => {
            let object = params?.as_object()?;
            let thread_id = bounded_opaque_id(object.get("threadId")?)?;
            let turn = object.get("turn")?.as_object()?;
            let (turn_id, status) = parse_turn_wire_object(turn)?;
            if status != WireTurnStatus::InProgress {
                return None;
            }
            Some(ProtocolNotification::TurnStarted { thread_id, turn_id })
        }
        "item/started" | "item/completed" => {
            let object = params?.as_object()?;
            let thread_id = bounded_opaque_id(object.get("threadId")?)?;
            let turn_id = bounded_opaque_id(object.get("turnId")?)?;
            let item = object.get("item")?.as_object()?;
            let item_id = bounded_opaque_id(item.get("id")?)?;
            let _item_type = bounded_string(item.get("type")?, MAX_METHOD_BYTES)?;
            let timestamp_key = if method == "item/started" {
                "startedAtMs"
            } else {
                "completedAtMs"
            };
            if object.get(timestamp_key)?.as_i64().is_none() {
                return None;
            }
            if method == "item/started" {
                Some(ProtocolNotification::ItemStarted {
                    thread_id,
                    turn_id,
                    item_id,
                })
            } else {
                Some(ProtocolNotification::ItemCompleted {
                    thread_id,
                    turn_id,
                    item_id,
                })
            }
        }
        "turn/completed" => {
            let object = params?.as_object()?;
            let thread_id = bounded_opaque_id(object.get("threadId")?)?;
            let turn = object.get("turn")?.as_object()?;
            let (turn_id, status) = parse_turn_wire_object(turn)?;
            if status == WireTurnStatus::InProgress {
                return None;
            }
            Some(ProtocolNotification::TurnCompleted {
                thread_id,
                turn_id,
                status,
            })
        }
        _ => Some(ProtocolNotification::Unknown),
    }
}

fn parse_wire_turn_status(value: &Value) -> Option<WireTurnStatus> {
    match value.as_str()? {
        "completed" => Some(WireTurnStatus::Completed),
        "interrupted" => Some(WireTurnStatus::Interrupted),
        "failed" => Some(WireTurnStatus::Failed),
        "inProgress" => Some(WireTurnStatus::InProgress),
        _ => None,
    }
}

fn bounded_opaque_id(value: &Value) -> Option<String> {
    let value = bounded_string(value, MAX_PROTOCOL_STRING_BYTES)?;
    if value.is_empty() || value.chars().any(char::is_control) {
        return None;
    }
    Some(value)
}

fn bounded_string(value: &Value, max_bytes: usize) -> Option<String> {
    let value = value.as_str()?;
    if value.len() > max_bytes {
        return None;
    }
    Some(value.to_owned())
}

fn repository_root() -> Option<PathBuf> {
    fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")))
        .ok()
        .and_then(|manifest| manifest.parent().map(Path::to_path_buf))
}

fn is_inside_repository(path: &Path) -> bool {
    let Some(repository_root) = repository_root() else {
        return true;
    };
    path.starts_with(&repository_root)
}

fn is_forbidden_location(path: &Path) -> bool {
    let Some(repository_root) = repository_root() else {
        return true;
    };
    if path.starts_with(&repository_root) {
        return true;
    }

    let current_dir = match fs::canonicalize(std::env::current_dir().unwrap_or_default()) {
        Ok(current_dir) => current_dir,
        Err(_) => return true,
    };
    if path == current_dir || path.starts_with(&current_dir) || current_dir.starts_with(path) {
        return true;
    }

    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .and_then(|home| fs::canonicalize(home).ok());
    if home.as_deref() == Some(path) {
        return true;
    }

    path.components().any(|component| {
        let component = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        matches!(
            component.as_str(),
            ".ssh" | ".codex" | "credentials" | "credential" | "secrets"
        )
    })
}

#[cfg(test)]
fn has_dedicated_root_marker(path: &Path) -> bool {
    path.join(".d29-dedicated-root").is_file()
}

#[cfg(not(test))]
fn has_dedicated_root_marker(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        collections::VecDeque,
        fs,
        path::PathBuf,
        process::Command,
        rc::Rc,
        sync::{mpsc, OnceLock},
        thread,
        time::Duration,
    };

    #[cfg(windows)]
    static FAKE_EXECUTABLE: OnceLock<PathBuf> = OnceLock::new();

    #[cfg(windows)]
    fn fake_executable() -> PathBuf {
        FAKE_EXECUTABLE
            .get_or_init(|| {
                let directory = tempfile::tempdir().expect("fake fixture temp root");
                let source_path = directory.path().join("d29_fake_app_server.rs");
                let executable_path = directory.path().join(if cfg!(windows) {
                    "d29_fake_app_server.exe"
                } else {
                    "d29_fake_app_server"
                });
                fs::write(&source_path, include_str!("fake_app_server.rs"))
                    .expect("write fake fixture source");
                let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
                let status = Command::new(rustc)
                    .arg("--edition=2021")
                    .arg(&source_path)
                    .arg("-o")
                    .arg(&executable_path)
                    .status()
                    .expect("compile fake fixture");
                assert!(status.success(), "fake fixture must compile");
                let _keep_directory_alive = Box::leak(Box::new(directory));
                executable_path
            })
            .clone()
    }

    #[cfg(windows)]
    fn dedicated_root() -> (tempfile::TempDir, IsolatedExecutionRoot) {
        let directory = tempfile::tempdir().expect("dedicated test root");
        fs::write(directory.path().join(".d29-dedicated-root"), b"d29")
            .expect("mark dedicated test root");
        let root = IsolatedExecutionRoot::from_dedicated_test_root(directory.path())
            .expect("dedicated root must validate");
        (directory, root)
    }

    #[cfg(windows)]
    fn client_with_args(
        args: &[&str],
    ) -> (
        tempfile::TempDir,
        IsolatedExecutionRoot,
        CodexProtocolClient,
    ) {
        let (directory, root) = dedicated_root();
        let spec = CodexLaunchSpec::test(&fake_executable(), args, root.clone());
        let process = CodexRuntimeAdapter::pinned()
            .spawn(spec)
            .expect("fake app server must spawn");
        (directory, root, CodexProtocolClient::new(process))
    }

    #[cfg(windows)]
    fn initialize_and_start_thread(client: &mut CodexProtocolClient) -> String {
        client
            .initialize(Duration::from_secs(2))
            .expect("initialize succeeds");
        client
            .start_thread(Duration::from_secs(2))
            .expect("ephemeral thread starts")
            .thread_id
    }

    #[cfg(windows)]
    fn next_lifecycle_event(
        client: &mut CodexProtocolClient,
        timeout: Duration,
    ) -> CodexLifecycleEvent {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "expected a lifecycle event");
            if let Some(event) = client
                .next_lifecycle_event(remaining)
                .expect("lifecycle event remains well-formed")
            {
                return event;
            }
        }
    }

    #[cfg(windows)]
    fn next_lifecycle_event_or_none(
        client: &mut CodexProtocolClient,
        timeout: Duration,
    ) -> Option<CodexLifecycleEvent> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return None;
            }
            if let Some(event) = client
                .next_lifecycle_event(remaining)
                .expect("lifecycle stream remains well-formed")
            {
                return Some(event);
            }
        }
    }

    #[cfg(windows)]
    fn wait_for_descendant_pid(path: &Path, timeout: Duration) -> Option<u32> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(contents) = fs::read_to_string(path) {
                if let Ok(pid) = contents.trim().parse::<u32>() {
                    return Some(pid);
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(windows)]
    fn wait_for_direct_child_exit(client: &mut CodexProtocolClient, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            client.process.refresh_child_status();
            if client.status() == CodexProcessStatus::Exited {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[cfg(windows)]
    fn windows_process_is_alive(pid: u32) -> bool {
        let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if process.is_null() {
            return false;
        }

        let mut exit_code = 0_u32;
        let queried = unsafe { GetExitCodeProcess(process, &mut exit_code) != 0 };
        unsafe {
            let _ = CloseHandle(process);
        }
        queried && exit_code == 259
    }

    #[cfg(windows)]
    fn wait_for_process_exit(pid: u32, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !windows_process_is_alive(pid) {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        !windows_process_is_alive(pid)
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FakeExitStatus {
        success: bool,
    }

    #[derive(Debug)]
    enum FakeOperation {
        Kill { succeeds: bool },
        Observe(ChildControlObservation<FakeExitStatus>),
    }

    #[derive(Debug)]
    struct FakeProcessControl {
        operations: VecDeque<FakeOperation>,
        kill_calls: usize,
        observe_calls: usize,
    }

    impl FakeProcessControl {
        fn new(operations: impl IntoIterator<Item = FakeOperation>) -> Self {
            Self {
                operations: operations.into_iter().collect(),
                kill_calls: 0,
                observe_calls: 0,
            }
        }
    }

    impl ProcessControl for FakeProcessControl {
        type ExitStatus = FakeExitStatus;

        fn try_wait_control(&mut self) -> ChildControlObservation<Self::ExitStatus> {
            self.observe_calls += 1;
            match self.operations.pop_front() {
                Some(FakeOperation::Observe(observation)) => observation,
                _ => ChildControlObservation::Failed,
            }
        }

        fn kill_control(&mut self) -> bool {
            self.kill_calls += 1;
            match self.operations.pop_front() {
                Some(FakeOperation::Kill { succeeds }) => succeeds,
                _ => false,
            }
        }
    }

    #[derive(Debug, Default)]
    struct FakeContainment {
        close_calls: usize,
        closed: bool,
        closed_before_final_reap: bool,
    }

    impl FakeContainment {
        fn close(&mut self) {
            if !self.closed {
                self.closed = true;
                self.close_calls += 1;
            }
        }
    }

    #[derive(Debug, Default)]
    struct FakeReapedProcessLifecycle {
        events: Vec<&'static str>,
    }

    impl ReapedProcessLifecycle for FakeReapedProcessLifecycle {
        fn close_containment(&mut self) {
            self.events.push("containment-close");
        }

        fn join_readers(&mut self) {
            self.events.push("reader-join");
        }

        fn clear_child(&mut self) {
            self.events.push("child-clear");
        }
    }

    #[derive(Debug, PartialEq)]
    enum FakeOwnerStatus {
        Running,
        CleanupFailed,
        Exited,
    }

    #[derive(Debug)]
    struct FakeOwnedChild {
        control: FakeProcessControl,
        child_owned: bool,
        readers_joined: bool,
        status: FakeOwnerStatus,
        containment: FakeContainment,
    }

    impl FakeOwnedChild {
        fn new(operations: impl IntoIterator<Item = FakeOperation>) -> Self {
            Self {
                control: FakeProcessControl::new(operations),
                child_owned: true,
                readers_joined: false,
                status: FakeOwnerStatus::Running,
                containment: FakeContainment::default(),
            }
        }

        fn cleanup_once(&mut self) -> Result<(), CodexRuntimeError> {
            if !self.child_owned {
                return Ok(());
            }
            match bounded_kill_reap(&mut self.control, KILL_REAP_ATTEMPTS) {
                ReapDecision::Reaped(_) => {
                    self.child_owned = false;
                    self.readers_joined = true;
                    self.status = FakeOwnerStatus::Exited;
                    Ok(())
                }
                ReapDecision::RetainOwnership => {
                    self.status = FakeOwnerStatus::CleanupFailed;
                    Err(CodexRuntimeError::ShutdownFailed)
                }
            }
        }

        fn drop_cleanup(&mut self) {
            for _ in 0..DROP_CLEANUP_ATTEMPTS {
                if self.cleanup_once().is_ok() {
                    break;
                }
            }

            if self.child_owned {
                self.containment.close();
                self.containment.closed_before_final_reap = self.containment.closed;
                match self.control.try_wait_control() {
                    ChildControlObservation::Exited(_) => {
                        self.child_owned = false;
                        self.readers_joined = true;
                        self.status = FakeOwnerStatus::Exited;
                    }
                    ChildControlObservation::Running | ChildControlObservation::Failed => {
                        self.status = FakeOwnerStatus::CleanupFailed;
                    }
                }
            }
        }
    }

    #[test]
    fn containment_assignment_failure_reaps_and_closes_before_exposure() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let cleanup_events = Rc::clone(&events);
        let close_events = Rc::clone(&events);
        let result = fail_closed_containment_assignment(
            Err(()),
            || {
                cleanup_events.borrow_mut().push("terminate-and-reap-child");
                true
            },
            || close_events.borrow_mut().push("close-job-object"),
        );

        assert_eq!(result, Err(CodexRuntimeError::ContainmentAssignmentFailed));
        assert_eq!(
            *events.borrow(),
            vec!["terminate-and-reap-child", "close-job-object"]
        );
        // The helper returns an error, so the caller cannot construct or
        // expose a protocol process after a failed assignment.
        assert!(result.is_err());
    }

    #[test]
    fn containment_closes_before_reader_join_after_reap() {
        let mut lifecycle = FakeReapedProcessLifecycle::default();

        finalize_reaped_process(&mut lifecycle);

        assert_eq!(
            lifecycle.events,
            vec!["containment-close", "reader-join", "child-clear"]
        );
    }

    #[cfg(windows)]
    #[test]
    fn job_object_is_configured_to_kill_on_close() {
        let containment = CodexProcessContainment::create().expect("create containment job");
        assert!(containment.has_kill_on_close_limit_for_test());
    }

    #[cfg(windows)]
    #[test]
    fn child_is_assigned_before_process_is_exposed_to_protocol_client() {
        let (_directory, root) = dedicated_root();
        let spec = CodexLaunchSpec::test(&fake_executable(), &["success"], root);
        let mut process = CodexRuntimeAdapter::pinned()
            .spawn(spec)
            .expect("contained fake app server must spawn");
        let containment = process
            .containment
            .as_ref()
            .expect("exposed process retains containment");
        let child = process
            .child
            .as_ref()
            .expect("exposed process retains child");
        assert!(containment.child_is_assigned_for_test(child));
        process.shutdown().expect("assigned child cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn process_tree_shutdown_closes_containment_before_joining_readers() {
        let (directory, root, mut client) = client_with_args(&["descendant-retains-pipes"]);
        client
            .initialize(Duration::from_secs(2))
            .expect("root fake app server initializes");

        let descendant_pid_path = root.path().join("d29-descendant-pid.txt");
        let descendant_pid = wait_for_descendant_pid(&descendant_pid_path, Duration::from_secs(2))
            .expect("descendant pid is published before root exits");
        assert!(windows_process_is_alive(descendant_pid));
        assert!(wait_for_direct_child_exit(
            &mut client,
            Duration::from_secs(2)
        ));
        assert!(windows_process_is_alive(descendant_pid));

        let close_count = client
            .process
            .containment
            .as_ref()
            .expect("shutdown starts with live containment")
            .close_counter_for_test();
        let (done_sender, done_receiver) = mpsc::sync_channel(1);
        let _shutdown_worker = thread::spawn(move || {
            let result = client.shutdown();
            let _ = done_sender.send((result, client));
        });

        let (shutdown_result, client) = done_receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("process-tree shutdown must not block on inherited pipes");
        assert!(
            shutdown_result.is_ok(),
            "shutdown result: {shutdown_result:?}"
        );
        assert_eq!(close_count.load(Ordering::Acquire), 1);
        assert!(client.process.containment.is_none());
        assert!(!client.has_child());
        assert!(client.process.stdout_reader.is_none());
        assert!(client.process.stderr_reader.is_none());
        assert!(wait_for_process_exit(
            descendant_pid,
            Duration::from_secs(2)
        ));
        assert!(directory.path().join(".d29-dedicated-root").is_file());
    }

    #[cfg(windows)]
    #[test]
    fn job_containment_raii_closes_exactly_once() {
        let mut containment = CodexProcessContainment::create().expect("create containment job");
        let close_count = containment.close_counter_for_test();
        containment.close();
        assert_eq!(close_count.load(Ordering::Acquire), 1);
        drop(containment);
        assert_eq!(close_count.load(Ordering::Acquire), 1);
    }

    #[test]
    fn kill_error_then_child_already_exited_is_reaped() {
        let mut control = FakeProcessControl::new([
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Exited(FakeExitStatus {
                success: true,
            })),
        ]);
        assert_eq!(
            bounded_kill_reap(&mut control, KILL_REAP_ATTEMPTS),
            ReapDecision::Reaped(FakeExitStatus { success: true })
        );
        assert_eq!(control.kill_calls, 1);
        assert_eq!(control.observe_calls, 1);
    }

    #[test]
    fn kill_error_while_child_alive_does_not_abandon_child() {
        let mut owner = FakeOwnedChild::new([
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
        ]);
        assert_eq!(
            owner.cleanup_once().unwrap_err(),
            CodexRuntimeError::ShutdownFailed
        );
        assert!(owner.child_owned);
        assert!(!owner.readers_joined);
        assert_eq!(owner.status, FakeOwnerStatus::CleanupFailed);
    }

    #[test]
    fn failed_shutdown_retains_child_for_retry() {
        let mut owner = FakeOwnedChild::new([
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
        ]);
        let _ = owner.cleanup_once();
        assert!(owner.child_owned);
        assert!(!owner.readers_joined);
        assert_eq!(owner.control.kill_calls, KILL_REAP_ATTEMPTS);
    }

    #[test]
    fn retry_cleanup_eventually_clears_child_and_joins_readers() {
        let mut owner = FakeOwnedChild::new([
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
            FakeOperation::Kill { succeeds: true },
            FakeOperation::Observe(ChildControlObservation::Exited(FakeExitStatus {
                success: true,
            })),
        ]);
        assert_eq!(
            owner.cleanup_once().unwrap_err(),
            CodexRuntimeError::ShutdownFailed
        );
        owner.cleanup_once().expect("retry reaps child");
        assert!(!owner.child_owned);
        assert!(owner.readers_joined);
        assert_eq!(owner.status, FakeOwnerStatus::Exited);
    }

    #[test]
    fn drop_cleanup_uses_bounded_final_retry() {
        let mut owner = FakeOwnedChild::new([
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
        ]);
        owner.drop_cleanup();
        assert!(owner.child_owned);
        assert!(!owner.readers_joined);
        assert_eq!(owner.status, FakeOwnerStatus::CleanupFailed);
        assert_eq!(
            owner.control.kill_calls,
            DROP_CLEANUP_ATTEMPTS * KILL_REAP_ATTEMPTS
        );
        assert_eq!(
            owner.control.observe_calls,
            DROP_CLEANUP_ATTEMPTS * KILL_REAP_ATTEMPTS + 1
        );
        assert!(owner.containment.closed);
        assert_eq!(owner.containment.close_calls, 1);
    }

    #[test]
    fn drop_cleanup_exhausted_uses_os_containment() {
        let mut owner = FakeOwnedChild::new([
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
            FakeOperation::Kill { succeeds: false },
            FakeOperation::Observe(ChildControlObservation::Running),
            FakeOperation::Observe(ChildControlObservation::Exited(FakeExitStatus {
                success: false,
            })),
        ]);

        owner.drop_cleanup();

        assert!(owner.containment.closed_before_final_reap);
        assert_eq!(owner.containment.close_calls, 1);
        assert!(!owner.child_owned);
        assert!(owner.readers_joined);
        assert_eq!(owner.status, FakeOwnerStatus::Exited);
        assert_eq!(
            owner.control.kill_calls,
            DROP_CLEANUP_ATTEMPTS * KILL_REAP_ATTEMPTS
        );
    }

    #[test]
    fn pin_records_exact_upstream_contract_and_narrow_method_map() {
        let pin = CodexUpstreamPin::pinned();
        assert_eq!(pin.release(), "rust-v0.152.0");
        assert_eq!(pin.commit(), "316795b3cf2a45e90d121d9f46499d4658b2645c");
        assert_eq!(
            pin.protocol_schema_hash(),
            "d8faa38d5f00aa7ddfe635a2d374ee5f871ffd217d4d175c72fbe7f009f4f669"
        );
        assert_eq!(
            CODEX_PROTOCOL_SCHEMA_SOURCE,
            "codex-rs/app-server-protocol/schema/json/codex_app_server_protocol.schemas.json"
        );
        assert_eq!(CODEX_PROTOCOL_SCHEMA_VERSION, "v1");
        assert_eq!(
            CODEX_UPSTREAM_REPOSITORY,
            "https://github.com/openai/codex.git"
        );
        assert_eq!(pin.client_contract_version(), "d29-b.codex-app-server.v2");
        assert_eq!(CodexRuntimeAdapter::pinned().upstream_pin(), pin);
        assert_eq!(
            ALLOWED_CLIENT_REQUEST_METHODS,
            &["initialize", "thread/start", "turn/start", "turn/interrupt"]
        );
        assert_eq!(ALLOWED_CLIENT_NOTIFICATION_METHODS, &["initialized"]);
        assert!(ALLOWED_SERVER_REQUEST_METHODS.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn identity_and_executable_checks_fail_closed_before_spawn() {
        let (_directory, root) = dedicated_root();
        let fake = fake_executable();
        let adapter = CodexRuntimeAdapter::pinned();

        let wrong_identity = CodexLaunchSpec::with_identity(
            &fake,
            &["success"],
            root.clone(),
            CODEX_UPSTREAM_RELEASE,
            "wrong-commit",
        );
        assert_eq!(
            adapter.spawn(wrong_identity).unwrap_err(),
            CodexRuntimeError::InvalidUpstreamPin
        );

        let repository_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let untrusted_executable = CodexLaunchSpec::test(&repository_file, &["success"], root);
        assert_eq!(
            adapter.spawn(untrusted_executable).unwrap_err(),
            CodexRuntimeError::UntrustedExecutable
        );

        let (_directory, root) = dedicated_root();
        let missing = CodexLaunchSpec::test(
            &PathBuf::from("d29-definitely-missing-app-server"),
            &["success"],
            root,
        );
        assert_eq!(
            adapter.spawn(missing).unwrap_err(),
            CodexRuntimeError::SpawnFailed
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_launch_fails_closed_before_process_spawn() {
        let spec = CodexLaunchSpec::test(
            Path::new("d29-non-windows-launch-must-not-start"),
            &[],
            IsolatedExecutionRoot {
                canonical_path: PathBuf::from("."),
            },
        );
        assert_eq!(
            CodexRuntimeAdapter::pinned().spawn(spec).unwrap_err(),
            CodexRuntimeError::ContainmentUnavailable
        );
    }

    #[cfg(windows)]
    #[test]
    fn initialize_success_and_unknown_client_method_are_handled() {
        let (_directory, _root, mut client) = client_with_args(&["success"]);
        assert_eq!(
            client.request_for_test("thread/resume").unwrap_err(),
            CodexRuntimeError::UnsupportedMethod
        );
        let result = client
            .initialize(Duration::from_secs(2))
            .expect("initialize succeeds");
        assert_eq!(result.platform_family, "windows");
        assert_eq!(result.platform_os, "windows");
        assert_eq!(result.user_agent, "codex-d29-fake");
        assert_eq!(client.status(), CodexProcessStatus::Ready);
        client.shutdown().expect("first shutdown");
        client.shutdown().expect("double shutdown is idempotent");
        assert_eq!(client.status(), CodexProcessStatus::Exited);
        assert!(!client.has_child());
    }

    #[cfg(windows)]
    #[test]
    fn no_thread_before_initialize() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b"]);
        assert_eq!(
            client.start_thread(Duration::from_secs(2)).unwrap_err(),
            CodexRuntimeError::ProtocolStateViolation
        );
        client
            .initialize(Duration::from_secs(2))
            .expect("initialize remains the first protocol operation");
        client.shutdown().expect("state guard cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn thread_start_is_ephemeral_and_isolation_bound() {
        let (_directory, root, mut client) = client_with_args(&["d29-b"]);
        let thread_id = initialize_and_start_thread(&mut client);
        assert_eq!(thread_id, "thread-d29-ephemeral-1");
        let request = fs::read_to_string(root.path().join("d29-thread-start-request.txt"))
            .expect("fake records the typed thread/start request");
        assert!(request.contains("\"ephemeral\":true"));
        assert!(request.contains("\"cwd\":"));
        for forbidden in [
            "\"config\"",
            "\"dynamicTools\"",
            "\"projectId\"",
            "\"historyMode\"",
            "\"sandbox\"",
            "\"approvalPolicy\"",
        ] {
            assert!(
                !request.contains(forbidden),
                "unexpected thread field: {forbidden}"
            );
        }
        client.shutdown().expect("ephemeral thread cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn wrong_rpc_id_does_not_complete_thread_start() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b-wrong-thread-rpc-id"]);
        client
            .initialize(Duration::from_secs(2))
            .expect("initialize succeeds");
        let result = client
            .start_thread(Duration::from_secs(2))
            .expect("only the matching thread/start response completes the request");
        assert_eq!(result.thread_id, "thread-d29-ephemeral-1");
        assert!(matches!(
            client.state,
            CodexProtocolState::ThreadReady { .. }
        ));
        client.shutdown().expect("wrong response cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn request_id_exhaustion_fails_closed_without_collision() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b"]);
        client.next_request_id = u64::MAX;
        assert_eq!(
            client.initialize(Duration::from_secs(2)).unwrap_err(),
            CodexRuntimeError::RequestIdExhausted
        );
        assert_eq!(client.state, CodexProtocolState::Retired);
        client.shutdown().expect("request id exhaustion cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn no_turn_before_thread() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b"]);
        client
            .initialize(Duration::from_secs(2))
            .expect("initialize succeeds");
        assert_eq!(
            client
                .start_turn("bounded fixture", Duration::from_secs(2))
                .unwrap_err(),
            CodexRuntimeError::ProtocolStateViolation
        );
        client.shutdown().expect("no-turn state cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn turn_start_binds_current_thread() {
        let (_directory, root, mut client) = client_with_args(&["d29-b"]);
        let thread_id = initialize_and_start_thread(&mut client);
        assert_eq!(
            next_lifecycle_event(&mut client, Duration::from_secs(2)),
            CodexLifecycleEvent::ThreadStarted {
                thread_id: thread_id.clone()
            }
        );
        let turn_id = client
            .start_turn("bounded fixture", Duration::from_secs(2))
            .expect("turn starts only on the current thread")
            .turn_id;
        assert_eq!(
            client.state,
            CodexProtocolState::TurnRunning {
                thread_id: thread_id.clone(),
                turn_id: turn_id.clone(),
                started_event_seen: false,
            }
        );
        assert_eq!(
            client
                .start_turn("second active fixture", Duration::from_secs(2))
                .unwrap_err(),
            CodexRuntimeError::ProtocolStateViolation
        );
        assert_eq!(
            next_lifecycle_event(&mut client, Duration::from_secs(2)),
            CodexLifecycleEvent::TurnStarted {
                thread_id: thread_id.clone(),
                turn_id: turn_id.clone(),
            }
        );
        let request = fs::read_to_string(root.path().join("d29-turn-start-request.txt"))
            .expect("fake records the typed turn/start request");
        assert!(request.contains("\"threadId\":\"thread-d29-ephemeral-1\""));
        assert!(request.contains("\"input\":[{"));
        assert!(request.contains("\"type\":\"text\""));
        assert!(request.contains("\"text\":\"bounded fixture\""));
        for forbidden in [
            "\"cwd\"",
            "\"model\"",
            "\"sandboxPolicy\"",
            "\"approvalPolicy\"",
            "\"metadata\"",
            "\"toolOutput\"",
        ] {
            assert!(
                !request.contains(forbidden),
                "unexpected turn field: {forbidden}"
            );
        }
        client.shutdown().expect("turn binding cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn turn_started_binds_exact_turn() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b-wrong-binding"]);
        initialize_and_start_thread(&mut client);
        assert!(matches!(
            next_lifecycle_event(&mut client, Duration::from_secs(2)),
            CodexLifecycleEvent::ThreadStarted { .. }
        ));
        client
            .start_turn("bounded fixture", Duration::from_secs(2))
            .expect("turn start response succeeds");
        assert_eq!(
            client
                .next_lifecycle_event(Duration::from_secs(2))
                .unwrap_err(),
            CodexRuntimeError::MalformedProtocol
        );
        assert_eq!(client.state, CodexProtocolState::Retired);
        client.shutdown().expect("wrong binding cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn bounded_lifecycle_event_streaming() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b"]);
        let thread_id = initialize_and_start_thread(&mut client);
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        let turn_id = client
            .start_turn("bounded fixture", Duration::from_secs(2))
            .expect("turn start response succeeds")
            .turn_id;
        let events = [
            next_lifecycle_event(&mut client, Duration::from_secs(2)),
            next_lifecycle_event(&mut client, Duration::from_secs(2)),
            next_lifecycle_event(&mut client, Duration::from_secs(2)),
            next_lifecycle_event(&mut client, Duration::from_secs(2)),
        ];
        assert_eq!(
            events,
            [
                CodexLifecycleEvent::TurnStarted {
                    thread_id: thread_id.clone(),
                    turn_id: turn_id.clone(),
                },
                CodexLifecycleEvent::ItemStarted {
                    thread_id: thread_id.clone(),
                    turn_id: turn_id.clone(),
                    item_id: "item-d29-1".to_owned(),
                },
                CodexLifecycleEvent::ItemCompleted {
                    thread_id: thread_id.clone(),
                    turn_id: turn_id.clone(),
                    item_id: "item-d29-1".to_owned(),
                },
                CodexLifecycleEvent::TurnCompleted {
                    thread_id,
                    turn_id,
                    terminal: CodexTurnTerminal::Completed,
                },
            ]
        );
        assert!(!format!("{:?}", events).contains("fixture"));
        client.shutdown().expect("bounded lifecycle cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn turn_completed_terminal() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b"]);
        initialize_and_start_thread(&mut client);
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        let first_turn_id = client
            .start_turn("first fixture", Duration::from_secs(2))
            .expect("first turn starts")
            .turn_id;
        for _ in 0..4 {
            let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        }
        assert_eq!(
            client.state,
            CodexProtocolState::TurnCompleted {
                thread_id: "thread-d29-ephemeral-1".to_owned(),
                turn_id: first_turn_id,
            }
        );
        assert_eq!(
            client.interrupt_turn(Duration::from_secs(2)).unwrap_err(),
            CodexRuntimeError::ProtocolStateViolation
        );
        client.shutdown().expect("terminal turn cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn turn_interrupt_exact_binding() {
        let (_directory, root, mut client) = client_with_args(&["d29-b-interrupt"]);
        let thread_id = initialize_and_start_thread(&mut client);
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        let turn_id = client
            .start_turn("interrupt fixture", Duration::from_secs(2))
            .expect("interruptible turn starts")
            .turn_id;
        assert_eq!(
            next_lifecycle_event(&mut client, Duration::from_secs(2)),
            CodexLifecycleEvent::TurnStarted {
                thread_id: thread_id.clone(),
                turn_id: turn_id.clone(),
            }
        );
        client
            .interrupt_turn(Duration::from_secs(2))
            .expect("turn/interrupt uses the exact active binding");
        let request = fs::read_to_string(root.path().join("d29-turn-interrupt-request.txt"))
            .expect("fake records the typed turn/interrupt request");
        assert!(request.contains("\"threadId\":\"thread-d29-ephemeral-1\""));
        assert!(request.contains("\"turnId\":\"turn-d29-1\""));
        assert!(!request.contains("\"input\""));
        client.shutdown().expect("interrupt request cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn interrupted_terminal() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b-interrupt"]);
        initialize_and_start_thread(&mut client);
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        let turn_id = client
            .start_turn("interrupt fixture", Duration::from_secs(2))
            .expect("interruptible turn starts")
            .turn_id;
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        client
            .interrupt_turn(Duration::from_secs(2))
            .expect("interrupt response succeeds");
        assert_eq!(
            next_lifecycle_event(&mut client, Duration::from_secs(2)),
            CodexLifecycleEvent::TurnCompleted {
                thread_id: "thread-d29-ephemeral-1".to_owned(),
                turn_id: turn_id.clone(),
                terminal: CodexTurnTerminal::Interrupted,
            }
        );
        assert_eq!(
            client.state,
            CodexProtocolState::TurnInterrupted {
                thread_id: "thread-d29-ephemeral-1".to_owned(),
                turn_id,
            }
        );
        client.shutdown().expect("interrupted turn cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn duplicate_terminal_no_double_settlement() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b-duplicate-terminal"]);
        initialize_and_start_thread(&mut client);
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        client
            .start_turn("duplicate fixture", Duration::from_secs(2))
            .expect("turn starts");
        for _ in 0..3 {
            let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        }
        let terminal = next_lifecycle_event(&mut client, Duration::from_secs(2));
        assert!(matches!(
            terminal,
            CodexLifecycleEvent::TurnCompleted {
                terminal: CodexTurnTerminal::Completed,
                ..
            }
        ));
        assert!(next_lifecycle_event_or_none(&mut client, Duration::from_millis(100)).is_none());
        assert!(matches!(
            client.state,
            CodexProtocolState::TurnCompleted { .. }
        ));
        client.shutdown().expect("duplicate terminal cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn stale_old_turn_event_does_not_mutate_new_turn() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b-stale-old-turn-event"]);
        initialize_and_start_thread(&mut client);
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        client
            .start_turn("first fixture", Duration::from_secs(2))
            .expect("first turn starts");
        for _ in 0..4 {
            let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        }
        client
            .start_turn("second fixture", Duration::from_secs(2))
            .expect("new turn starts on the same ephemeral thread");
        assert_eq!(
            next_lifecycle_event(&mut client, Duration::from_secs(2)),
            CodexLifecycleEvent::TurnStarted {
                thread_id: "thread-d29-ephemeral-1".to_owned(),
                turn_id: "turn-d29-2".to_owned(),
            }
        );
        assert_eq!(
            next_lifecycle_event(&mut client, Duration::from_secs(2)),
            CodexLifecycleEvent::TurnCompleted {
                thread_id: "thread-d29-ephemeral-1".to_owned(),
                turn_id: "turn-d29-2".to_owned(),
                terminal: CodexTurnTerminal::Completed,
            }
        );
        assert!(matches!(
            client.state,
            CodexProtocolState::TurnCompleted { ref turn_id, .. } if turn_id == "turn-d29-2"
        ));
        client.shutdown().expect("stale event cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn server_request_during_turn_denied() {
        let (directory, _root, mut client) = client_with_args(&["d29-b-server-request"]);
        initialize_and_start_thread(&mut client);
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        client
            .start_turn("server request fixture", Duration::from_secs(2))
            .expect("turn starts");
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        let terminal = next_lifecycle_event(&mut client, Duration::from_secs(2));
        assert!(matches!(
            terminal,
            CodexLifecycleEvent::TurnCompleted {
                terminal: CodexTurnTerminal::Completed,
                ..
            }
        ));
        assert!(directory
            .path()
            .join("d29-server-request-denied.txt")
            .is_file());
        client.shutdown().expect("denied server request cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn unknown_notification_has_no_authority_effect() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b-unknown-notification"]);
        initialize_and_start_thread(&mut client);
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        client
            .start_turn("unknown notification fixture", Duration::from_secs(2))
            .expect("turn starts");
        assert!(matches!(
            next_lifecycle_event(&mut client, Duration::from_secs(2)),
            CodexLifecycleEvent::TurnStarted { .. }
        ));
        assert!(matches!(
            next_lifecycle_event(&mut client, Duration::from_secs(2)),
            CodexLifecycleEvent::TurnCompleted {
                terminal: CodexTurnTerminal::Completed,
                ..
            }
        ));
        assert!(matches!(
            client.state,
            CodexProtocolState::TurnCompleted { .. }
        ));
        client.shutdown().expect("unknown notification cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn malformed_lifecycle_fails_closed() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b-malformed-lifecycle"]);
        initialize_and_start_thread(&mut client);
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        client
            .start_turn("malformed fixture", Duration::from_secs(2))
            .expect("turn start response succeeds before lifecycle failure");
        assert_eq!(
            client
                .next_lifecycle_event(Duration::from_secs(2))
                .unwrap_err(),
            CodexRuntimeError::MalformedProtocol
        );
        assert_eq!(client.state, CodexProtocolState::Retired);
        client.shutdown().expect("malformed lifecycle cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn out_of_order_event_fails_closed() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b-out-of-order"]);
        initialize_and_start_thread(&mut client);
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        client
            .start_turn("out of order fixture", Duration::from_secs(2))
            .expect("turn start response succeeds before ordering failure");
        assert_eq!(
            client
                .next_lifecycle_event(Duration::from_secs(2))
                .unwrap_err(),
            CodexRuntimeError::MalformedProtocol
        );
        assert_eq!(client.state, CodexProtocolState::Retired);
        client.shutdown().expect("out-of-order cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn crash_retires_thread_and_turn() {
        let (_directory, _root, mut client) = client_with_args(&["d29-b-crash-during-turn"]);
        initialize_and_start_thread(&mut client);
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        client
            .start_turn("crash fixture", Duration::from_secs(2))
            .expect("turn start response is observed before process crash");
        assert_eq!(
            client
                .next_lifecycle_event(Duration::from_secs(2))
                .unwrap_err(),
            CodexRuntimeError::ChildExited
        );
        assert_eq!(client.state, CodexProtocolState::Retired);
        assert_eq!(
            client.start_thread(Duration::from_secs(2)).unwrap_err(),
            CodexRuntimeError::SessionRetired
        );
        client.shutdown().expect("crashed turn cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn restart_requires_new_initialize_and_thread() {
        let (_directory, _root, mut crashed) = client_with_args(&["d29-b-crash-during-turn"]);
        initialize_and_start_thread(&mut crashed);
        let _ = next_lifecycle_event(&mut crashed, Duration::from_secs(2));
        crashed
            .start_turn("crash fixture", Duration::from_secs(2))
            .expect("turn starts before crash");
        let _ = crashed.next_lifecycle_event(Duration::from_secs(2));
        assert_eq!(crashed.state, CodexProtocolState::Retired);
        crashed.shutdown().expect("retired process cleanup");

        let (_directory, _root, mut restarted) = client_with_args(&["d29-b"]);
        assert_eq!(
            restarted.start_thread(Duration::from_secs(2)).unwrap_err(),
            CodexRuntimeError::ProtocolStateViolation
        );
        let new_thread_id = initialize_and_start_thread(&mut restarted);
        assert_eq!(new_thread_id, "thread-d29-ephemeral-1");
        restarted.shutdown().expect("new process cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn no_durable_state_or_files_outside_test_root() {
        let (directory, root, mut client) = client_with_args(&["d29-b"]);
        initialize_and_start_thread(&mut client);
        let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        client
            .start_turn("ephemeral fixture", Duration::from_secs(2))
            .expect("turn starts");
        for _ in 0..4 {
            let _ = next_lifecycle_event(&mut client, Duration::from_secs(2));
        }
        client.shutdown().expect("no-durable-state cleanup");

        let names = fs::read_dir(root.path())
            .expect("isolated root remains readable")
            .map(|entry| entry.expect("root entry").file_name())
            .collect::<Vec<_>>();
        assert!(names.iter().any(|name| name == ".d29-dedicated-root"));
        assert!(names
            .iter()
            .any(|name| name == "d29-thread-start-request.txt"));
        assert!(names
            .iter()
            .any(|name| name == "d29-turn-start-request.txt"));
        for forbidden in [
            "d29-thread-history",
            "d29-session.json",
            "codex-home",
            "conversation.db",
        ] {
            assert!(
                !names.iter().any(|name| name == forbidden),
                "durable artifact: {forbidden}"
            );
            assert!(!Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(forbidden)
                .exists());
        }
        assert!(directory.path().join(".d29-dedicated-root").is_file());
    }

    #[cfg(windows)]
    #[test]
    fn initialize_timeout_can_be_interrupted_without_orphaning_child() {
        let (_directory, _root, mut client) = client_with_args(&["timeout"]);
        assert_eq!(
            client.initialize(Duration::from_millis(40)).unwrap_err(),
            CodexRuntimeError::InitializeTimeout
        );
        client.interrupt().expect("interrupt timeout child");
        assert_eq!(client.status(), CodexProcessStatus::Exited);
        assert!(!client.has_child());
    }

    #[cfg(windows)]
    #[test]
    fn malformed_json_is_rejected_and_can_be_cleaned_up() {
        let (_directory, _root, mut client) = client_with_args(&["malformed"]);
        assert_eq!(
            client.initialize(Duration::from_secs(2)).unwrap_err(),
            CodexRuntimeError::MalformedProtocol
        );
        client.shutdown().expect("malformed child cleanup");
        assert!(!client.has_child());
    }

    #[cfg(windows)]
    #[test]
    fn server_request_is_denied_without_auto_approval() {
        let (directory, _root, mut client) = client_with_args(&["server-request"]);
        client
            .initialize(Duration::from_secs(2))
            .expect("initialize succeeds after denied server request");
        client.shutdown().expect("server request cleanup");
        assert!(directory
            .path()
            .join("d29-server-request-denied.txt")
            .is_file());
    }

    #[cfg(windows)]
    #[test]
    fn unknown_server_request_is_denied_without_auto_approval() {
        let (directory, _root, mut client) = client_with_args(&["unknown-server-request"]);
        client
            .initialize(Duration::from_secs(2))
            .expect("initialize succeeds after unknown request denial");
        client.shutdown().expect("unknown request cleanup");
        assert!(directory
            .path()
            .join("d29-server-request-denied.txt")
            .is_file());
    }

    #[cfg(windows)]
    #[test]
    fn unknown_server_notification_is_ignored_without_authority_effect() {
        let (_directory, _root, mut client) = client_with_args(&["unknown-notification"]);
        client
            .initialize(Duration::from_secs(2))
            .expect("unknown notification does not block initialize");
        client.shutdown().expect("unknown notification cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn server_request_after_ready_is_still_denied() {
        let (directory, _root, mut client) = client_with_args(&["server-request-after-init"]);
        client
            .initialize(Duration::from_secs(2))
            .expect("initialize succeeds before post-ready request");
        assert!(client
            .pump_once(Duration::from_secs(2))
            .expect("post-ready request is handled"));
        client.shutdown().expect("post-ready request cleanup");
        assert!(directory
            .path()
            .join("d29-server-request-denied.txt")
            .is_file());
    }

    #[cfg(windows)]
    #[test]
    fn stdout_frame_is_bounded() {
        let (_directory, _root, mut client) = client_with_args(&["oversized"]);
        assert_eq!(
            client.initialize(Duration::from_secs(2)).unwrap_err(),
            CodexRuntimeError::MalformedProtocol
        );
        client.shutdown().expect("oversized frame cleanup");
    }

    #[test]
    fn event_queue_is_bounded_and_reports_saturation() {
        let (sender, receiver) = mpsc::sync_channel(EVENT_QUEUE_CAPACITY);
        let overflowed = AtomicBool::new(false);
        for _ in 0..(EVENT_QUEUE_CAPACITY + 1) {
            send_event(
                &sender,
                &overflowed,
                ProcessEvent::Message(ProtocolMessage::Notification {
                    notification: ProtocolNotification::Unknown,
                }),
            );
        }
        assert_eq!(receiver.try_iter().count(), EVENT_QUEUE_CAPACITY);
        assert!(overflowed.load(Ordering::Acquire));
    }

    #[cfg(windows)]
    #[test]
    fn crash_and_broken_pipe_reach_terminal_states() {
        let (_directory, _root, mut crashed) = client_with_args(&["crash"]);
        assert_eq!(
            crashed.initialize(Duration::from_secs(2)).unwrap_err(),
            CodexRuntimeError::ChildExited
        );
        assert_eq!(crashed.status(), CodexProcessStatus::Crashed);
        crashed.shutdown().expect("crash cleanup");
        assert!(!crashed.has_child());

        let (_directory, _root, mut closed) = client_with_args(&["close-after-init"]);
        closed
            .initialize(Duration::from_secs(2))
            .expect("initialize before clean close");
        assert!(closed.wait_for_terminal(Duration::from_secs(2)));
        assert_eq!(
            closed.send_allowed_notification_for_test().unwrap_err(),
            CodexRuntimeError::BrokenPipe
        );
        closed.shutdown().expect("closed child cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn working_directory_and_environment_are_isolated_and_stderr_is_bounded() {
        let (directory, root, mut writer) =
            client_with_args(&["write-probe", "d29-child-working-directory-probe.txt"]);
        writer
            .initialize(Duration::from_secs(2))
            .expect("write probe initialize");
        writer.shutdown().expect("write probe cleanup");
        assert!(root
            .path()
            .join("d29-child-working-directory-probe.txt")
            .is_file());
        assert!(!Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("d29-child-working-directory-probe.txt")
            .exists());
        assert!(directory.path().join(".d29-dedicated-root").is_file());

        let (_directory, root, mut env_probe) = client_with_args(&["env-probe"]);
        env_probe
            .initialize(Duration::from_secs(2))
            .expect("environment probe initialize");
        env_probe.shutdown().expect("environment probe cleanup");
        let report =
            fs::read_to_string(root.path().join("d29-env-report.txt")).expect("environment report");
        for key in [
            "PATH=false",
            "HOME=false",
            "USERPROFILE=false",
            "CODEX_HOME=false",
            "D29_SECRET_LOOKING=false",
            "D29_TOKEN_LOOKING=false",
            "CODEX_D29_UPSTREAM_COMMIT=true",
            "CODEX_D29_CLIENT_CONTRACT_VERSION=true",
        ] {
            assert!(report.contains(key), "missing environment assertion: {key}");
        }

        let (_directory, _root, mut stderr_probe) = client_with_args(&["stderr-burst"]);
        stderr_probe
            .initialize(Duration::from_secs(2))
            .expect("stderr probe initialize");
        stderr_probe.shutdown().expect("stderr probe cleanup");
        let (captured, truncated) = stderr_probe.stderr_capture_state();
        assert_eq!(captured, MAX_STDERR_CAPTURE_BYTES);
        assert!(truncated);
    }

    #[cfg(windows)]
    #[test]
    fn dedicated_root_rejects_repository_root_and_drop_reaps_child() {
        let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(
            IsolatedExecutionRoot::from_dedicated_test_root(repository_root).unwrap_err(),
            CodexRuntimeError::InvalidIsolationRoot
        );

        let (directory, root, mut client) = client_with_args(&["drop-observe"]);
        client
            .initialize(Duration::from_secs(2))
            .expect("drop probe initialize");
        drop(client);
        for _ in 0..40 {
            if root.path().join("d29-drop-observed.txt").is_file() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(root.path().join("d29-drop-observed.txt").is_file());
        assert!(directory.path().join(".d29-dedicated-root").is_file());
    }
}
