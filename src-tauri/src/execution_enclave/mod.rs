//! D29-A: isolated Codex App Server protocol/process foundation.
//!
//! This module deliberately has no production caller.  It records the exact
//! upstream contract and provides a private, testable process boundary for a
//! later governed execution stage.  In particular, this is not a capability,
//! autonomy, Chat, or Tauri command surface.

use serde_json::{json, Value};
use std::{
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
pub(crate) const CODEX_CLIENT_CONTRACT_VERSION: &str = "d29-a.codex-app-server.v1";

/// Exact upstream methods mapped by the initial lifecycle contract.
pub(crate) const ALLOWED_CLIENT_REQUEST_METHODS: &[&str] = &["initialize"];
pub(crate) const ALLOWED_CLIENT_NOTIFICATION_METHODS: &[&str] = &["initialized"];
/// No server request is trusted in D29-A.  Every server request is answered
/// with a protocol-level denial, never an approval.
pub(crate) const ALLOWED_SERVER_REQUEST_METHODS: &[&str] = &[];
/// `error` is retained only as bounded operational metadata; it never invokes
/// a tool or changes authority.  All other server notifications are ignored.
pub(crate) const ALLOWED_SERVER_NOTIFICATION_METHODS: &[&str] = &["error"];

const MAX_PROTOCOL_FRAME_BYTES: usize = 64 * 1024;
const MAX_METHOD_BYTES: usize = 128;
const MAX_PROTOCOL_STRING_BYTES: usize = 1024;
const EVENT_QUEUE_CAPACITY: usize = 32;
const MAX_STDERR_CAPTURE_BYTES: usize = 16 * 1024;
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);

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
    Exited,
    Crashed,
    BrokenPipe,
}

impl CodexProcessStatus {
    fn is_terminal(self) -> bool {
        matches!(self, Self::Exited | Self::Crashed | Self::BrokenPipe)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CodexRuntimeError {
    InvalidUpstreamPin,
    InvalidIsolationRoot,
    UntrustedExecutable,
    SpawnFailed,
    MissingChildPipe,
    UnsupportedMethod,
    AlreadyInitialized,
    InitializeTimeout,
    MalformedProtocol,
    ProtocolError,
    EventQueueSaturated,
    BrokenPipe,
    ChildExited,
    ShutdownFailed,
    ProtocolEncoding,
}

impl fmt::Display for CodexRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidUpstreamPin => "codex upstream identity is not the pinned release",
            Self::InvalidIsolationRoot => "codex runtime isolation root is not dedicated",
            Self::UntrustedExecutable => "codex runtime executable is outside the trusted boundary",
            Self::SpawnFailed => "codex app server process could not be started",
            Self::MissingChildPipe => "codex app server process did not expose required pipes",
            Self::UnsupportedMethod => "codex app server method is outside the mapped contract",
            Self::AlreadyInitialized => "codex app server protocol is already initialized",
            Self::InitializeTimeout => "codex app server initialize timed out",
            Self::MalformedProtocol => "codex app server emitted malformed protocol",
            Self::ProtocolError => "codex app server returned a protocol error",
            Self::EventQueueSaturated => "codex app server event queue is saturated",
            Self::BrokenPipe => "codex app server pipe is closed",
            Self::ChildExited => "codex app server process exited before readiness",
            Self::ShutdownFailed => "codex app server process cleanup failed",
            Self::ProtocolEncoding => "codex app server protocol frame could not be encoded",
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
        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let (stdin, stdout, stderr) = match (stdin, stdout, stderr) {
            (Some(stdin), Some(stdout), Some(stderr)) => (stdin, stdout, stderr),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CodexRuntimeError::MissingChildPipe);
            }
        };

        Ok(CodexAppServerProcess::new(
            child,
            stdin,
            stdout,
            stderr,
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

impl CodexAppServerProcess {
    fn new(
        child: Child,
        stdin: ChildStdin,
        stdout: ChildStdout,
        stderr: ChildStderr,
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

    fn mark_ready(&mut self) {
        if !self.status.is_terminal() {
            self.status = CodexProcessStatus::Ready;
        }
    }

    fn write_json(&mut self, value: Value) -> Result<(), CodexRuntimeError> {
        if self.status.is_terminal() {
            return Err(CodexRuntimeError::BrokenPipe);
        }
        let encoded =
            serde_json::to_vec(&value).map_err(|_| CodexRuntimeError::ProtocolEncoding)?;
        if encoded.len() > MAX_PROTOCOL_FRAME_BYTES {
            return Err(CodexRuntimeError::ProtocolEncoding);
        }
        self.refresh_child_status();
        if self.status.is_terminal() {
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
            self.stop_and_join_readers();
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
            let child = self.child.as_mut().expect("child exists until reap");
            if child.kill().is_err() {
                return Err(CodexRuntimeError::ShutdownFailed);
            }
            if child.wait().is_err() {
                return Err(CodexRuntimeError::ShutdownFailed);
            }
            if !matches!(
                self.status,
                CodexProcessStatus::Crashed | CodexProcessStatus::BrokenPipe
            ) {
                self.status = CodexProcessStatus::Exited;
            }
        }

        self.child.take();
        self.stop_and_join_readers();
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
        let _ = self.terminate(TerminationIntent::Shutdown);
    }
}

#[derive(Clone, Copy)]
enum TerminationIntent {
    Interrupt,
    Shutdown,
}

struct CodexProtocolClient {
    process: CodexAppServerProcess,
    next_request_id: u64,
    initialized: bool,
}

impl CodexProtocolClient {
    fn new(process: CodexAppServerProcess) -> Self {
        Self {
            process,
            next_request_id: 1,
            initialized: false,
        }
    }

    fn initialize(
        &mut self,
        timeout: Duration,
    ) -> Result<CodexInitializeResult, CodexRuntimeError> {
        if self.initialized {
            return Err(CodexRuntimeError::AlreadyInitialized);
        }

        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        let params = json!({
            "clientInfo": {
                "name": "digital-life-codex-enclave",
                "version": CODEX_CLIENT_CONTRACT_VERSION,
            },
            "capabilities": {
                "experimentalApi": false,
                "mcpServerOpenaiFormElicitation": false,
                "requestAttestation": false,
            },
        });
        self.send_request(request_id, "initialize", params)?;

        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(CodexRuntimeError::InitializeTimeout);
            }
            let event = self
                .process
                .next_event(remaining.min(Duration::from_millis(25)))?;
            let Some(event) = event else {
                continue;
            };
            match event {
                ProcessEvent::Message(ProtocolMessage::Response {
                    id,
                    initialize_result,
                    error_code,
                }) if id == RpcId::Number(request_id.into()) => {
                    if error_code.is_some() {
                        return Err(CodexRuntimeError::ProtocolError);
                    }
                    let result = initialize_result.ok_or(CodexRuntimeError::MalformedProtocol)?;
                    if !result.codex_home_is_bounded_string {
                        return Err(CodexRuntimeError::MalformedProtocol);
                    }
                    let result = CodexInitializeResult {
                        platform_family: result
                            .platform_family
                            .ok_or(CodexRuntimeError::MalformedProtocol)?,
                        platform_os: result
                            .platform_os
                            .ok_or(CodexRuntimeError::MalformedProtocol)?,
                        user_agent: result
                            .user_agent
                            .ok_or(CodexRuntimeError::MalformedProtocol)?,
                    };
                    self.send_notification("initialized")?;
                    self.initialized = true;
                    self.process.mark_ready();
                    return Ok(result);
                }
                ProcessEvent::Message(ProtocolMessage::ServerRequest { id }) => {
                    self.deny_server_request(id)?;
                }
                ProcessEvent::Message(ProtocolMessage::Notification { method }) => {
                    // `error` is informational only.  Unknown notifications
                    // are not authority and are intentionally discarded.
                    let _ = ALLOWED_SERVER_NOTIFICATION_METHODS.contains(&method.as_str());
                }
                ProcessEvent::Message(ProtocolMessage::Response { .. }) => {}
                ProcessEvent::MalformedProtocol | ProcessEvent::FrameTooLarge => {
                    return Err(CodexRuntimeError::MalformedProtocol);
                }
                ProcessEvent::OutputClosed | ProcessEvent::ChildExited => {
                    self.process.refresh_child_status();
                    return Err(CodexRuntimeError::ChildExited);
                }
            }
        }
    }

    fn send_request(
        &mut self,
        request_id: u64,
        method: &str,
        params: Value,
    ) -> Result<(), CodexRuntimeError> {
        if !ALLOWED_CLIENT_REQUEST_METHODS.contains(&method) {
            return Err(CodexRuntimeError::UnsupportedMethod);
        }
        self.process.write_json(json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        }))
    }

    fn send_notification(&mut self, method: &str) -> Result<(), CodexRuntimeError> {
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

    fn pump_once(&mut self, timeout: Duration) -> Result<bool, CodexRuntimeError> {
        let Some(event) = self.process.next_event(timeout)? else {
            return Ok(false);
        };
        match event {
            ProcessEvent::Message(ProtocolMessage::ServerRequest { id }) => {
                self.deny_server_request(id)?;
                Ok(true)
            }
            ProcessEvent::Message(ProtocolMessage::Notification { method }) => {
                let _ = ALLOWED_SERVER_NOTIFICATION_METHODS.contains(&method.as_str());
                Ok(true)
            }
            ProcessEvent::Message(ProtocolMessage::Response { .. }) => Ok(true),
            ProcessEvent::MalformedProtocol | ProcessEvent::FrameTooLarge => {
                Err(CodexRuntimeError::MalformedProtocol)
            }
            ProcessEvent::OutputClosed | ProcessEvent::ChildExited => {
                self.process.refresh_child_status();
                Err(CodexRuntimeError::ChildExited)
            }
        }
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
        self.send_request(99, method, json!({}))
    }

    #[cfg(test)]
    fn send_allowed_notification_for_test(&mut self) -> Result<(), CodexRuntimeError> {
        self.send_notification("initialized")
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
        error_code: Option<i64>,
    },
    Notification {
        method: String,
    },
    ServerRequest {
        id: RpcId,
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
            let _ = method;
            return ProcessEvent::Message(ProtocolMessage::ServerRequest { id });
        }
        return ProcessEvent::Message(ProtocolMessage::Notification { method });
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
            error_code: Some(error_code),
        });
    }

    ProcessEvent::Message(ProtocolMessage::Response {
        id: id.expect("checked above"),
        initialize_result: parse_initialize_wire_result(object.get("result")),
        error_code: None,
    })
}

fn parse_rpc_id(value: &Value) -> Option<RpcId> {
    match value {
        Value::Number(number) => Some(RpcId::Number(number.clone())),
        Value::String(value) if value.len() <= MAX_PROTOCOL_STRING_BYTES => {
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
    use std::{fs, path::PathBuf, process::Command, sync::OnceLock, thread, time::Duration};

    static FAKE_EXECUTABLE: OnceLock<PathBuf> = OnceLock::new();

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

    fn dedicated_root() -> (tempfile::TempDir, IsolatedExecutionRoot) {
        let directory = tempfile::tempdir().expect("dedicated test root");
        fs::write(directory.path().join(".d29-dedicated-root"), b"d29")
            .expect("mark dedicated test root");
        let root = IsolatedExecutionRoot::from_dedicated_test_root(directory.path())
            .expect("dedicated root must validate");
        (directory, root)
    }

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
        assert_eq!(pin.client_contract_version(), "d29-a.codex-app-server.v1");
        assert_eq!(CodexRuntimeAdapter::pinned().upstream_pin(), pin);
        assert_eq!(ALLOWED_CLIENT_REQUEST_METHODS, &["initialize"]);
        assert_eq!(ALLOWED_CLIENT_NOTIFICATION_METHODS, &["initialized"]);
        assert!(ALLOWED_SERVER_REQUEST_METHODS.is_empty());
    }

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

    #[test]
    fn initialize_success_and_unknown_client_method_are_handled() {
        let (_directory, _root, mut client) = client_with_args(&["success"]);
        assert_eq!(
            client.request_for_test("thread/start").unwrap_err(),
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

    #[test]
    fn unknown_server_notification_is_ignored_without_authority_effect() {
        let (_directory, _root, mut client) = client_with_args(&["unknown-notification"]);
        client
            .initialize(Duration::from_secs(2))
            .expect("unknown notification does not block initialize");
        client.shutdown().expect("unknown notification cleanup");
    }

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
                    method: "unknown/notification".to_owned(),
                }),
            );
        }
        assert_eq!(receiver.try_iter().count(), EVENT_QUEUE_CAPACITY);
        assert!(overflowed.load(Ordering::Acquire));
    }

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
