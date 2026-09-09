//! D29-H6's bounded exact-literal patch frontend.
//!
//! This module is test/integration-only.  It compiles a model-facing patch
//! request into one opaque replacement proof and then delegates the side
//! effect to the already-frozen H4/H5 replace path.  It intentionally adds no
//! production capability, registry entry, or native mutation primitive.

#![allow(dead_code, private_interfaces)]

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use codex_core_api::{
    CodexAppsToolsCache, CodexAuth, EnvironmentManager, EventMsg, Op, SessionSource,
    StartThreadOptions, ThreadId, ThreadManager, TurnInputRequest, TurnInputSubmission, UserInput,
};
use codex_extension_api::{
    parse_tool_input_schema, JsonToolOutput, ResponsesApiTool, ToolCall, ToolContributor,
    ToolExecutor, ToolExecutorFuture, ToolName, ToolOutput, ToolSpec,
};
use serde::Deserialize;
use serde_json::{json, Value};
use tempfile::tempdir;

use crate::d29h4::tests::ProcessIsolatedH4Authority;
use crate::d29h4::{
    H4AuthorityRequest, H4DenyClassification, VitaH4AuthorityPort, VitaWorkspaceReplaceBroker,
};
use crate::d29h5::tests::ProcessIsolatedH5RecoveryAuthority;
use crate::d29h5::{
    execute_governed_h5_replace, H5AuthorizedReplaceAction, H5RecoveryExecutor,
    H5ReplaceTransactionOutcome, RecoveryActionRequest, RecoveryAuthorityPort,
    RecoveryExecutionOutcome,
};
use crate::provider_gateway::{VitaGatewayBinding, VitaProviderAuthority};
use crate::recovery_journal::{RecoveryJournalStore, RecoveryTransactionState};
use crate::workspace_capability::{
    PreparedWorkspaceTargetKind, WorkspaceReadError, WorkspaceRelativePath, WorkspaceRootIdentity,
};
use crate::{
    sha256_hex, ProviderCapabilities, ProviderProfile, ProviderProtocol, ProviderRetryPolicy,
    TrustedWorkspaceRoot, VitaAgentEntrypoint, VitaAgentRuntimeProfile, VitaExecutionContext,
};

pub(crate) const VITA_WORKSPACE_PATCH_TOOL_NAME: &str = "vita_workspace_patch_file";
const H6_MAX_PATH_CHARS: usize = 256;
const H6_MAX_EDITS: usize = 16;
const H6_MAX_EDIT_TEXT_BYTES: usize = 64 * 1024;
const H6_MAX_RESULT_BYTES: usize = 64 * 1024;
const H6_MAX_ID_CHARS: usize = 128;
const H6_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(2);

// The frozen process-isolated H4 harness owns this test identity pair.  H6
// deliberately binds to it when composing the existing H4/H5 proof path.
const LIFE_ID: &str = "life-d29h4-a";
const TASK_ID: &str = "task-d29h4-a";
const MODEL: &str = "d29h6-local-responses-model";
const PROVIDER_ID: &str = "d29h6-loopback-responses";
const RELATIVE_PATH: &str = "patch-me.txt";
const CALL_ID: &str = "call-d29h6-patch";
const PROMPT: &str = "Apply the exact bounded workspace patch.";
const REPLY: &str = "D29-H6 patch applied";
const ORIGINAL: &str = "first=old-first\nsecond=old-second\n";
const CRASH_ORIGINAL: &str = "A界B";
const CRASH_REPLACEMENT: &str = "XY";
const TURN_TIMEOUT: Duration = Duration::from_secs(30);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_TIMEOUT: Duration = Duration::from_secs(3);
const HTTP_MAX_BODY: usize = 2 * 1024 * 1024;
const TEST_STACK_SIZE: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
struct H6PatchEdit {
    search: String,
    replace: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct H6PatchEditArguments {
    search: String,
    replace: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct H6PatchArguments {
    relative_path: String,
    expected_sha256: String,
    edits: Vec<H6PatchEditArguments>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct H6PatchRequest {
    tool_call_id: String,
    turn_id: String,
    relative_path: WorkspaceRelativePath,
    expected_sha256: String,
    edits: Vec<H6PatchEdit>,
}

impl H6PatchRequest {
    fn from_codex_call(call: &ToolCall<'_>) -> Result<Self, H6PatchConflict> {
        if call.tool_name.name != VITA_WORKSPACE_PATCH_TOOL_NAME
            || !call.tool_name.is_default_namespace()
        {
            return Err(H6PatchConflict::InvalidRequest);
        }
        let tool_call_id = bounded_identifier(&call.call_id, H6_MAX_ID_CHARS)
            .ok_or(H6PatchConflict::InvalidRequest)?;
        let turn_id = bounded_identifier(&call.turn_id, H6_MAX_ID_CHARS)
            .ok_or(H6PatchConflict::InvalidRequest)?;
        let arguments = call
            .function_arguments()
            .map_err(|_| H6PatchConflict::InvalidRequest)?;
        let arguments: H6PatchArguments =
            serde_json::from_str(arguments).map_err(|_| H6PatchConflict::InvalidRequest)?;
        Self::from_arguments(tool_call_id, turn_id, arguments)
    }

    fn from_arguments(
        tool_call_id: String,
        turn_id: String,
        arguments: H6PatchArguments,
    ) -> Result<Self, H6PatchConflict> {
        if arguments.relative_path.chars().count() > H6_MAX_PATH_CHARS
            || arguments.edits.is_empty()
            || arguments.edits.len() > H6_MAX_EDITS
            || !is_lower_sha256(&arguments.expected_sha256)
        {
            return Err(H6PatchConflict::InvalidRequest);
        }
        let relative_path = WorkspaceRelativePath::parse(Path::new(&arguments.relative_path))
            .map_err(|_| H6PatchConflict::InvalidRequest)?;
        let mut edits = Vec::with_capacity(arguments.edits.len());
        for edit in arguments.edits {
            if edit.search.is_empty()
                || edit.search.as_bytes().len() > H6_MAX_EDIT_TEXT_BYTES
                || edit.replace.as_bytes().len() > H6_MAX_EDIT_TEXT_BYTES
            {
                return Err(H6PatchConflict::InvalidRequest);
            }
            edits.push(H6PatchEdit {
                search: edit.search,
                replace: edit.replace,
            });
        }
        Ok(Self {
            tool_call_id,
            turn_id,
            relative_path,
            expected_sha256: arguments.expected_sha256,
            edits,
        })
    }

    fn synthetic(
        call_id: &str,
        turn_id: &str,
        relative_path: &str,
        expected_sha256: &str,
        edits: &[(&str, &str)],
    ) -> Self {
        Self {
            tool_call_id: call_id.to_string(),
            turn_id: turn_id.to_string(),
            relative_path: WorkspaceRelativePath::parse(Path::new(relative_path))
                .expect("H6 synthetic path must be valid"),
            expected_sha256: expected_sha256.to_string(),
            edits: edits
                .iter()
                .map(|(search, replace)| H6PatchEdit {
                    search: (*search).to_string(),
                    replace: (*replace).to_string(),
                })
                .collect(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum H6PatchConflict {
    InvalidRequest,
    TargetMissing,
    TargetRejected,
    BaseTooLarge,
    InvalidUtf8,
    BaseChanged,
    SearchMissing,
    SearchAmbiguous,
    OverlappingEdits,
    ResultTooLarge,
}

impl H6PatchConflict {
    fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::TargetMissing => "target_missing",
            Self::TargetRejected => "target_rejected",
            Self::BaseTooLarge => "base_too_large",
            Self::InvalidUtf8 => "invalid_utf8",
            Self::BaseChanged => "base_changed",
            Self::SearchMissing => "search_missing",
            Self::SearchAmbiguous => "search_ambiguous",
            Self::OverlappingEdits => "overlapping_edits",
            Self::ResultTooLarge => "result_too_large",
        }
    }
}

#[derive(Debug)]
enum H6CompileOutcome {
    NoEffect,
    Compiled(H6CompiledPatch),
}

/// The only authority-bearing H6 value.  Its fields are private, it is not
/// serializable, and it is deliberately non-Clone.  H4 accepts this exact
/// type instead of an arbitrary path/hash/replacement tuple.
#[derive(Debug)]
pub(crate) struct H6CompiledPatch {
    context: VitaExecutionContext,
    tool_call_id: String,
    turn_id: String,
    relative_path: WorkspaceRelativePath,
    expected_sha256: String,
    workspace_root_identity: WorkspaceRootIdentity,
    target_identity: WorkspaceRootIdentity,
    target_kind: PreparedWorkspaceTargetKind,
    replacement: Vec<u8>,
    replacement_sha256: String,
    derived_replacement_bytes: usize,
}

pub(crate) struct H6CompiledPatchParts {
    pub(crate) context: VitaExecutionContext,
    pub(crate) tool_call_id: String,
    pub(crate) turn_id: String,
    pub(crate) relative_path: WorkspaceRelativePath,
    pub(crate) expected_sha256: String,
    pub(crate) workspace_root_identity: WorkspaceRootIdentity,
    pub(crate) target_identity: WorkspaceRootIdentity,
    pub(crate) target_kind: PreparedWorkspaceTargetKind,
    pub(crate) replacement_bytes: Vec<u8>,
    pub(crate) replacement_sha256: String,
    pub(crate) derived_replacement_bytes: usize,
}

impl H6CompiledPatch {
    fn from_compiler(
        context: &VitaExecutionContext,
        request: H6PatchRequest,
        prepared: &crate::PreparedWorkspaceTarget,
        expected_sha256: String,
        replacement: Vec<u8>,
    ) -> Self {
        let replacement_sha256 = sha256_hex(&replacement);
        let derived_replacement_bytes = replacement.len();
        Self {
            context: context.clone(),
            tool_call_id: request.tool_call_id,
            turn_id: request.turn_id,
            relative_path: request.relative_path,
            expected_sha256,
            workspace_root_identity: prepared.root().identity(),
            target_identity: prepared
                .target_identity()
                .expect("H6 compiler only accepts an existing file"),
            target_kind: prepared.kind(),
            replacement,
            replacement_sha256,
            derived_replacement_bytes,
        }
    }

    pub(crate) fn context(&self) -> &VitaExecutionContext {
        &self.context
    }

    pub(crate) fn tool_call_id(&self) -> &str {
        &self.tool_call_id
    }

    pub(crate) fn turn_id(&self) -> &str {
        &self.turn_id
    }

    pub(crate) fn relative_path(&self) -> &WorkspaceRelativePath {
        &self.relative_path
    }

    pub(crate) fn expected_sha256(&self) -> &str {
        &self.expected_sha256
    }

    pub(crate) fn workspace_root_identity(&self) -> WorkspaceRootIdentity {
        self.workspace_root_identity
    }

    pub(crate) fn target_identity(&self) -> WorkspaceRootIdentity {
        self.target_identity
    }

    pub(crate) fn target_kind(&self) -> PreparedWorkspaceTargetKind {
        self.target_kind
    }

    pub(crate) fn replacement_bytes(&self) -> &[u8] {
        &self.replacement
    }

    pub(crate) fn replacement_sha256(&self) -> &str {
        &self.replacement_sha256
    }

    pub(crate) fn derived_replacement_bytes(&self) -> usize {
        self.derived_replacement_bytes
    }

    pub(crate) fn into_h4_parts(self) -> H6CompiledPatchParts {
        H6CompiledPatchParts {
            context: self.context,
            tool_call_id: self.tool_call_id,
            turn_id: self.turn_id,
            relative_path: self.relative_path,
            expected_sha256: self.expected_sha256,
            workspace_root_identity: self.workspace_root_identity,
            target_identity: self.target_identity,
            target_kind: self.target_kind,
            replacement_bytes: self.replacement,
            replacement_sha256: self.replacement_sha256,
            derived_replacement_bytes: self.derived_replacement_bytes,
        }
    }
}

fn compile_patch(
    request: H6PatchRequest,
    context: &VitaExecutionContext,
    root: &TrustedWorkspaceRoot,
) -> Result<H6CompileOutcome, H6PatchConflict> {
    if request.edits.is_empty()
        || request.edits.len() > H6_MAX_EDITS
        || !is_lower_sha256(&request.expected_sha256)
    {
        return Err(H6PatchConflict::InvalidRequest);
    }
    if request.edits.iter().any(|edit| {
        edit.search.is_empty()
            || edit.search.as_bytes().len() > H6_MAX_EDIT_TEXT_BYTES
            || edit.replace.as_bytes().len() > H6_MAX_EDIT_TEXT_BYTES
    }) {
        return Err(H6PatchConflict::InvalidRequest);
    }
    let prepared = root
        .prepare_target(request.relative_path.as_path())
        .map_err(|_| H6PatchConflict::TargetRejected)?;
    if prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile
        || prepared.target_identity().is_none()
    {
        return Err(if prepared.kind() == PreparedWorkspaceTargetKind::Missing {
            H6PatchConflict::TargetMissing
        } else {
            H6PatchConflict::TargetRejected
        });
    }
    let current = prepared
        .read_existing_file_utf8_bounded(H6_MAX_RESULT_BYTES)
        .map_err(|error| match error {
            WorkspaceReadError::TooLarge { .. } => H6PatchConflict::BaseTooLarge,
            WorkspaceReadError::InvalidUtf8 => H6PatchConflict::InvalidUtf8,
            WorkspaceReadError::InvalidTarget(_) | WorkspaceReadError::Kernel(_) => {
                H6PatchConflict::TargetRejected
            }
        })?;
    let original = current.into_bytes();
    if sha256_hex(&original) != request.expected_sha256 {
        return Err(H6PatchConflict::BaseChanged);
    }

    let mut matched = Vec::with_capacity(request.edits.len());
    for (index, edit) in request.edits.iter().enumerate() {
        if edit.search.is_empty() {
            return Err(H6PatchConflict::InvalidRequest);
        }
        let search = edit.search.as_bytes();
        let starts = original
            .windows(search.len())
            .enumerate()
            .filter_map(|(start, candidate)| (candidate == search).then_some(start))
            .collect::<Vec<_>>();
        match starts.as_slice() {
            [] => return Err(H6PatchConflict::SearchMissing),
            [_] => matched.push((starts[0], starts[0] + search.len(), index)),
            _ => return Err(H6PatchConflict::SearchAmbiguous),
        }
    }

    matched.sort_by_key(|(start, _, index)| (*start, *index));
    for pair in matched.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(H6PatchConflict::OverlappingEdits);
        }
    }

    let mut replacement = Vec::with_capacity(original.len());
    let mut cursor = 0usize;
    for (start, end, index) in matched {
        replacement.extend_from_slice(&original[cursor..start]);
        replacement.extend_from_slice(request.edits[index].replace.as_bytes());
        cursor = end;
    }
    replacement.extend_from_slice(&original[cursor..]);
    if replacement.len() > H6_MAX_RESULT_BYTES {
        return Err(H6PatchConflict::ResultTooLarge);
    }
    if String::from_utf8(replacement.clone()).is_err() {
        return Err(H6PatchConflict::InvalidUtf8);
    }
    if replacement == original {
        return Ok(H6CompileOutcome::NoEffect);
    }
    Ok(H6CompileOutcome::Compiled(H6CompiledPatch::from_compiler(
        context,
        request,
        &prepared,
        sha256_hex(&original),
        replacement,
    )))
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn bounded_identifier(value: &str, max_chars: usize) -> Option<String> {
    (!value.is_empty() && value.chars().count() <= max_chars).then(|| value.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct H6ToolResult {
    status: &'static str,
    mutation_performed: bool,
    side_effect_count: usize,
}

impl H6ToolResult {
    fn value(self) -> Value {
        json!({
            "status": self.status,
            "mutation_performed": self.mutation_performed,
            "side_effect_count": self.side_effect_count,
        })
    }
}

fn h6_conflict_value(_conflict: H6PatchConflict) -> H6ToolResult {
    H6ToolResult {
        status: "conflict",
        mutation_performed: false,
        side_effect_count: 0,
    }
}

fn h6_denied_value() -> H6ToolResult {
    H6ToolResult {
        status: "denied",
        mutation_performed: false,
        side_effect_count: 0,
    }
}

struct H6PendingConfirmation {
    intent: H4AuthorityRequest,
    response: tokio::sync::oneshot::Sender<()>,
}

#[derive(Clone)]
struct H6PendingConfirmationBridge {
    sender: tokio::sync::mpsc::Sender<H6PendingConfirmation>,
    cancelled: Arc<AtomicBool>,
    cancelled_notify: Arc<tokio::sync::Notify>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H6BridgeFailure {
    Cancelled,
    TimedOut,
    Closed,
}

impl H6PendingConfirmationBridge {
    fn new() -> (
        Arc<Self>,
        tokio::sync::mpsc::Receiver<H6PendingConfirmation>,
    ) {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        (
            Arc::new(Self {
                sender,
                cancelled: Arc::new(AtomicBool::new(false)),
                cancelled_notify: Arc::new(tokio::sync::Notify::new()),
            }),
            receiver,
        )
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.cancelled_notify.notify_waiters();
    }

    async fn await_trusted_confirmation(
        &self,
        intent: H4AuthorityRequest,
    ) -> Result<(), H6BridgeFailure> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(H6BridgeFailure::Cancelled);
        }
        let (response, receiver) = tokio::sync::oneshot::channel();
        let pending = H6PendingConfirmation { intent, response };
        let send = self.sender.send(pending);
        tokio::pin!(send);
        tokio::select! {
            result = &mut send => result.map_err(|_| H6BridgeFailure::Closed)?,
            _ = self.cancelled_notify.notified() => return Err(H6BridgeFailure::Cancelled),
            _ = tokio::time::sleep(H6_CONFIRMATION_TIMEOUT) => return Err(H6BridgeFailure::TimedOut),
        }
        tokio::select! {
            result = tokio::time::timeout(H6_CONFIRMATION_TIMEOUT, receiver) => {
                result.map_err(|_| H6BridgeFailure::TimedOut)?
                    .map_err(|_| H6BridgeFailure::Closed)?;
            }
            _ = self.cancelled_notify.notified() => return Err(H6BridgeFailure::Cancelled),
        }
        if self.cancelled.load(Ordering::Acquire) {
            return Err(H6BridgeFailure::Cancelled);
        }
        Ok(())
    }
}

async fn execute_compiled_patch(
    broker: &VitaWorkspaceReplaceBroker,
    store: RecoveryJournalStore,
    bridge: &H6PendingConfirmationBridge,
    mut patch: H6CompiledPatch,
    tamper_replacement: bool,
) -> H6ToolResult {
    let intent = match broker.h6_authority_request_for_compiled_patch(&patch) {
        Ok(intent) => intent,
        Err(_) => return h6_denied_value(),
    };
    if bridge.await_trusted_confirmation(intent).await.is_err() {
        return h6_denied_value();
    }
    if tamper_replacement {
        patch.replacement.push(b'!');
    }
    let (grant, replacement) = match broker
        .issue_h5_authorized_replace_action_from_h6_patch(patch)
        .await
    {
        Ok(value) => value,
        Err(_) => return h6_denied_value(),
    };
    match execute_governed_h5_replace(
        H5AuthorizedReplaceAction::from_h4_grant(grant),
        replacement,
        store,
        broker.cancellation_token(),
    )
    .await
    {
        Ok(result) => match result.transaction_outcome {
            H5ReplaceTransactionOutcome::Committed => H6ToolResult {
                status: "patch_applied",
                mutation_performed: true,
                side_effect_count: 1,
            },
            H5ReplaceTransactionOutcome::Conflict { .. } => H6ToolResult {
                status: "conflict",
                mutation_performed: false,
                side_effect_count: 0,
            },
            H5ReplaceTransactionOutcome::Denied { .. } => h6_denied_value(),
            H5ReplaceTransactionOutcome::CommitUnknown { .. } => H6ToolResult {
                status: "commit_outcome_unknown",
                mutation_performed: true,
                side_effect_count: 1,
            },
            H5ReplaceTransactionOutcome::LifecycleUnknown {
                workspace_mutation_started,
            } => H6ToolResult {
                status: if workspace_mutation_started {
                    "recovery_required"
                } else {
                    "denied"
                },
                mutation_performed: workspace_mutation_started,
                side_effect_count: usize::from(workspace_mutation_started),
            },
        },
        Err(_) => h6_denied_value(),
    }
}

pub(crate) struct VitaWorkspacePatchToolContributor {
    broker: Arc<VitaWorkspaceReplaceBroker>,
    root: TrustedWorkspaceRoot,
    context: VitaExecutionContext,
    store: RecoveryJournalStore,
    bridge: Arc<H6PendingConfirmationBridge>,
    tamper_replacement: bool,
    tool_call_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl VitaWorkspacePatchToolContributor {
    fn new(
        broker: Arc<VitaWorkspaceReplaceBroker>,
        root: TrustedWorkspaceRoot,
        context: VitaExecutionContext,
        store: RecoveryJournalStore,
        bridge: Arc<H6PendingConfirmationBridge>,
    ) -> Self {
        Self {
            broker,
            root,
            context,
            store,
            bridge,
            tamper_replacement: false,
            tool_call_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    fn with_tamper_replacement(mut self) -> Self {
        self.tamper_replacement = true;
        self
    }

    fn with_tool_call_count(
        mut self,
        tool_call_count: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        self.tool_call_count = tool_call_count;
        self
    }
}

impl ToolContributor for VitaWorkspacePatchToolContributor {
    fn tools(
        &self,
        _session_store: &codex_extension_api::ExtensionData,
        _thread_store: &codex_extension_api::ExtensionData,
    ) -> Vec<Arc<dyn for<'call> ToolExecutor<ToolCall<'call>>>> {
        vec![Arc::new(VitaWorkspacePatchTool {
            broker: Arc::clone(&self.broker),
            root: self.root.clone(),
            context: self.context.clone(),
            store: self.store.clone(),
            bridge: Arc::clone(&self.bridge),
            tamper_replacement: self.tamper_replacement,
            tool_call_count: Arc::clone(&self.tool_call_count),
        })]
    }
}

struct VitaWorkspacePatchTool {
    broker: Arc<VitaWorkspaceReplaceBroker>,
    root: TrustedWorkspaceRoot,
    context: VitaExecutionContext,
    store: RecoveryJournalStore,
    bridge: Arc<H6PendingConfirmationBridge>,
    tamper_replacement: bool,
    tool_call_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl<'call> ToolExecutor<ToolCall<'call>> for VitaWorkspacePatchTool {
    fn tool_name(&self) -> ToolName {
        ToolName::plain(VITA_WORKSPACE_PATCH_TOOL_NAME)
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::Function(ResponsesApiTool {
            name: VITA_WORKSPACE_PATCH_TOOL_NAME.to_string(),
            description: "Apply bounded exact-literal edits to one existing UTF-8 workspace file through governed replace authority.".to_string(),
            strict: true,
            defer_loading: None,
            parameters: parse_tool_input_schema(&h6_patch_schema_contract())
            .expect("D29-H6 patch schema is static and valid"),
            output_schema: None,
        })
    }

    fn supports_parallel_tool_calls(&self) -> bool {
        false
    }

    fn handle<'a>(&'a self, call: ToolCall<'call>) -> ToolExecutorFuture<'a>
    where
        'call: 'a,
    {
        let broker = Arc::clone(&self.broker);
        let root = self.root.clone();
        let context = self.context.clone();
        let store = self.store.clone();
        let bridge = Arc::clone(&self.bridge);
        let tamper_replacement = self.tamper_replacement;
        self.tool_call_count.fetch_add(1, Ordering::AcqRel);
        Box::pin(async move {
            let value = match H6PatchRequest::from_codex_call(&call)
                .and_then(|request| compile_patch(request, &context, &root))
            {
                Err(conflict) => h6_conflict_value(conflict),
                Ok(H6CompileOutcome::NoEffect) => H6ToolResult {
                    status: "no_effect",
                    mutation_performed: false,
                    side_effect_count: 0,
                },
                Ok(H6CompileOutcome::Compiled(patch)) => {
                    execute_compiled_patch(&broker, store, &bridge, patch, tamper_replacement).await
                }
            };
            Ok(
                Box::new(JsonToolOutput::with_success(value.value(), Some(false)))
                    as Box<dyn ToolOutput>,
            )
        })
    }
}

fn h6_patch_schema_contract() -> Value {
    json!({
        "type": "object",
        "properties": {
            "relative_path": {"type": "string"},
            "expected_sha256": {
                "type": "string",
                "pattern": "^[a-f0-9]{64}$"
            },
            "edits": {
                "type": "array",
                "minItems": 1,
                "maxItems": 16,
                "items": {
                    "type": "object",
                    "properties": {
                        "search": {"type": "string", "minLength": 1},
                        "replace": {"type": "string"}
                    },
                    "required": ["search", "replace"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["relative_path", "expected_sha256", "edits"],
        "additionalProperties": false
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::d29h4::tests::TestHostAuthority;
    use crate::d29h4::{VitaH4AuthorityError, VitaH4AuthorityFuture};
    const H4_REVISION: i64 = 2;

    struct H6WorkspaceFixture {
        _app_data: tempfile::TempDir,
        workspace: tempfile::TempDir,
        _profile: VitaAgentRuntimeProfile,
        store: RecoveryJournalStore,
        root: TrustedWorkspaceRoot,
    }

    impl H6WorkspaceFixture {
        fn new(content: &[u8]) -> Self {
            let app_data = tempdir().expect("H6 app-data root");
            let workspace = tempdir().expect("H6 workspace root");
            fs::write(workspace.path().join(RELATIVE_PATH), content)
                .expect("H6 fixture file write");
            let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
                app_data.path().to_path_buf(),
                workspace.path().to_path_buf(),
            )
            .expect("H6 fixture profile");
            profile
                .ensure_private_runtime_layout()
                .expect("H6 fixture private layout");
            let store = RecoveryJournalStore::from_runtime_profile(&profile)
                .expect("H6 fixture recovery store");
            let root = profile
                .workspace_authority()
                .cloned()
                .expect("H6 fixture workspace authority");
            Self {
                _app_data: app_data,
                workspace,
                _profile: profile,
                store,
                root,
            }
        }

        fn file_path(&self) -> PathBuf {
            self.workspace.path().join(RELATIVE_PATH)
        }
    }

    struct H6TestFixture {
        workspace: H6WorkspaceFixture,
        authority: Arc<TestHostAuthority>,
        broker: Arc<VitaWorkspaceReplaceBroker>,
    }

    impl H6TestFixture {
        fn new(content: &[u8]) -> Self {
            let workspace = H6WorkspaceFixture::new(content);
            let context = VitaExecutionContext::try_new(LIFE_ID, TASK_ID)
                .expect("H6 fixture execution context");
            let authority = TestHostAuthority::new(workspace.root.identity());
            let broker = VitaWorkspaceReplaceBroker::new(
                context,
                workspace.root.clone(),
                Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>,
            );
            Self {
                workspace,
                authority,
                broker,
            }
        }

        fn compile(
            &self,
            original: &[u8],
            edits: &[(&str, &str)],
        ) -> Result<H6CompileOutcome, H6PatchConflict> {
            let request = H6PatchRequest::synthetic(
                CALL_ID,
                "turn-d29h6-test",
                RELATIVE_PATH,
                &sha256_hex(original),
                edits,
            );
            compile_patch(
                request,
                &VitaExecutionContext::try_new(LIFE_ID, TASK_ID).unwrap(),
                &self.workspace.root,
            )
        }

        fn assert_no_side_effects(&self, expected: &[u8]) {
            assert_eq!(fs::read(self.workspace.file_path()).unwrap(), expected);
            assert_eq!(self.broker.snapshot().grants_issued, 0);
            assert_eq!(self.broker.snapshot().filesystem_mutation_attempts, 0);
            assert_eq!(
                self.workspace
                    .store
                    .scan_transactions()
                    .unwrap()
                    .valid_transactions()
                    .count(),
                0
            );
            let provenance = self.authority.provenance_snapshot();
            assert_eq!(provenance.trusted_confirmations_provisioned, 0);
            assert_eq!(provenance.request_derived_confirmations, 0);
        }
    }

    fn compiled_patch(
        fixture: &H6TestFixture,
        original: &[u8],
        edits: &[(&str, &str)],
    ) -> H6CompiledPatch {
        match fixture
            .compile(original, edits)
            .expect("H6 patch compilation")
        {
            H6CompileOutcome::Compiled(patch) => patch,
            H6CompileOutcome::NoEffect => panic!("expected an effective H6 patch"),
        }
    }

    async fn approve_one(
        fixture: &H6TestFixture,
        bridge: Arc<H6PendingConfirmationBridge>,
        mut receiver: tokio::sync::mpsc::Receiver<H6PendingConfirmation>,
        patch: H6CompiledPatch,
        tamper_replacement: bool,
    ) -> H6ToolResult {
        let broker = Arc::clone(&fixture.broker);
        let store = fixture.workspace.store.clone();
        let task = tokio::spawn(async move {
            execute_compiled_patch(&broker, store, &bridge, patch, tamper_replacement).await
        });
        let pending = receiver.recv().await.expect("H6 pending confirmation");
        fixture
            .authority
            .provision_trusted_confirmation(&pending.intent);
        pending.response.send(()).expect("H6 confirmation response");
        task.await.expect("H6 pipeline task")
    }

    #[test]
    fn h6_two_non_overlapping_edits_compile_exactly() {
        let fixture = H6TestFixture::new(ORIGINAL.as_bytes());
        let outcome = fixture
            .compile(
                ORIGINAL.as_bytes(),
                &[("old-first", "new-first"), ("old-second", "new-second")],
            )
            .unwrap();
        let H6CompileOutcome::Compiled(patch) = outcome else {
            panic!("two edits must compile");
        };
        let expected = b"first=new-first\nsecond=new-second\n";
        assert_eq!(patch.replacement_bytes(), expected);
        assert_eq!(patch.replacement_sha256(), sha256_hex(expected));
        assert_eq!(patch.derived_replacement_bytes(), expected.len());
        assert_eq!(patch.expected_sha256(), sha256_hex(ORIGINAL.as_bytes()));
        fixture.assert_no_side_effects(ORIGINAL.as_bytes());
    }

    #[test]
    fn h6_search_missing_mutates_zero() {
        let fixture = H6TestFixture::new(ORIGINAL.as_bytes());
        let error = fixture
            .compile(ORIGINAL.as_bytes(), &[("absent", "new")])
            .unwrap_err();
        assert_eq!(error, H6PatchConflict::SearchMissing);
        fixture.assert_no_side_effects(ORIGINAL.as_bytes());
    }

    #[test]
    fn h6_search_ambiguous_mutates_zero() {
        let original = b"repeat repeat\n";
        let fixture = H6TestFixture::new(original);
        let error = fixture.compile(original, &[("repeat", "new")]).unwrap_err();
        assert_eq!(error, H6PatchConflict::SearchAmbiguous);
        fixture.assert_no_side_effects(original);
    }

    #[test]
    fn h6_overlapping_edits_mutate_zero() {
        let original = b"abcdef\n";
        let fixture = H6TestFixture::new(original);
        let error = fixture
            .compile(original, &[("abc", "x"), ("bc", "y")])
            .unwrap_err();
        assert_eq!(error, H6PatchConflict::OverlappingEdits);
        fixture.assert_no_side_effects(original);
    }

    #[test]
    fn h6_stale_base_mutates_zero() {
        let fixture = H6TestFixture::new(ORIGINAL.as_bytes());
        let request = H6PatchRequest::synthetic(
            CALL_ID,
            "turn-d29h6-stale",
            RELATIVE_PATH,
            &sha256_hex(b"stale base"),
            &[("old-first", "new-first")],
        );
        let error = compile_patch(
            request,
            &VitaExecutionContext::try_new(LIFE_ID, TASK_ID).unwrap(),
            &fixture.workspace.root,
        )
        .unwrap_err();
        assert_eq!(error, H6PatchConflict::BaseChanged);
        fixture.assert_no_side_effects(ORIGINAL.as_bytes());
    }

    #[test]
    fn h6_result_too_large_mutates_zero() {
        let original = b"abcdefghijklmnop";
        let fixture = H6TestFixture::new(original);
        let oversized = "x".repeat(4097);
        let edits = [
            ("a", oversized.as_str()),
            ("b", oversized.as_str()),
            ("c", oversized.as_str()),
            ("d", oversized.as_str()),
            ("e", oversized.as_str()),
            ("f", oversized.as_str()),
            ("g", oversized.as_str()),
            ("h", oversized.as_str()),
            ("i", oversized.as_str()),
            ("j", oversized.as_str()),
            ("k", oversized.as_str()),
            ("l", oversized.as_str()),
            ("m", oversized.as_str()),
            ("n", oversized.as_str()),
            ("o", oversized.as_str()),
            ("p", oversized.as_str()),
        ];
        let error = fixture.compile(original, &edits).unwrap_err();
        assert_eq!(error, H6PatchConflict::ResultTooLarge);
        fixture.assert_no_side_effects(original);
    }

    #[test]
    fn h6_no_effect_mutates_zero() {
        let fixture = H6TestFixture::new(ORIGINAL.as_bytes());
        let outcome = fixture
            .compile(ORIGINAL.as_bytes(), &[("old-first", "old-first")])
            .unwrap();
        assert!(matches!(outcome, H6CompileOutcome::NoEffect));
        fixture.assert_no_side_effects(ORIGINAL.as_bytes());
    }

    #[tokio::test]
    async fn h6_tampered_compiled_replacement_mutates_zero() {
        let fixture = H6TestFixture::new(ORIGINAL.as_bytes());
        let patch = compiled_patch(&fixture, ORIGINAL.as_bytes(), &[("old-first", "new-first")]);
        let (bridge, receiver) = H6PendingConfirmationBridge::new();
        let result = approve_one(&fixture, bridge, receiver, patch, true).await;
        assert_eq!(result, h6_denied_value());
        assert_eq!(
            fs::read(fixture.workspace.file_path()).unwrap(),
            ORIGINAL.as_bytes()
        );
        assert_eq!(fixture.broker.snapshot().filesystem_mutation_attempts, 0);
        assert_eq!(
            fixture
                .workspace
                .store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .count(),
            0
        );
        assert_eq!(fixture.broker.snapshot().grants_issued, 0);
        assert_eq!(
            fixture
                .authority
                .provenance_snapshot()
                .trusted_confirmations_provisioned,
            1
        );
        assert_eq!(
            fixture
                .authority
                .provenance_snapshot()
                .request_derived_confirmations,
            0
        );
    }

    #[test]
    fn h6_target_identity_change_mutates_zero() {
        let fixture = H6TestFixture::new(ORIGINAL.as_bytes());
        let patch = compiled_patch(&fixture, ORIGINAL.as_bytes(), &[("old-first", "new-first")]);
        let moved_path = fixture.workspace.workspace.path().join("moved-target.txt");
        fs::rename(fixture.workspace.file_path(), &moved_path).unwrap();
        fs::write(fixture.workspace.file_path(), ORIGINAL.as_bytes()).unwrap();
        let error = fixture
            .broker
            .h6_authority_request_for_compiled_patch(&patch)
            .unwrap_err();
        assert_eq!(error, H4DenyClassification::TargetRejected);
        assert_eq!(fixture.broker.snapshot().grants_issued, 0);
        assert_eq!(
            fixture
                .workspace
                .store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .count(),
            0
        );
        assert_eq!(
            fixture
                .authority
                .provenance_snapshot()
                .trusted_confirmations_provisioned,
            0
        );
    }

    #[tokio::test]
    async fn h6_confirmation_timeout_mutates_zero() {
        let fixture = H6TestFixture::new(ORIGINAL.as_bytes());
        let patch = compiled_patch(&fixture, ORIGINAL.as_bytes(), &[("old-first", "new-first")]);
        let (bridge, _receiver) = H6PendingConfirmationBridge::new();
        let result = tokio::time::timeout(
            H6_CONFIRMATION_TIMEOUT + Duration::from_secs(2),
            execute_compiled_patch(
                &fixture.broker,
                fixture.workspace.store.clone(),
                &bridge,
                patch,
                false,
            ),
        )
        .await
        .expect("H6 confirmation bridge must be bounded");
        assert_eq!(result, h6_denied_value());
        fixture.assert_no_side_effects(ORIGINAL.as_bytes());
    }

    #[tokio::test]
    async fn h6_late_confirmation_after_cancel_mutates_zero() {
        let fixture = H6TestFixture::new(ORIGINAL.as_bytes());
        let patch = compiled_patch(&fixture, ORIGINAL.as_bytes(), &[("old-first", "new-first")]);
        let (bridge, mut receiver) = H6PendingConfirmationBridge::new();
        let bridge_for_task = Arc::clone(&bridge);
        let broker = Arc::clone(&fixture.broker);
        let store = fixture.workspace.store.clone();
        let task = tokio::spawn(async move {
            execute_compiled_patch(&broker, store, &bridge_for_task, patch, false).await
        });
        let pending = receiver
            .recv()
            .await
            .expect("H6 pending cancellation intent");
        bridge.cancel();
        fixture.broker.cancel();
        let _ = pending.response.send(());
        assert_eq!(task.await.unwrap(), h6_denied_value());
        fixture.assert_no_side_effects(ORIGINAL.as_bytes());
    }

    struct H6ProcessRevokingAuthority {
        inner: Arc<ProcessIsolatedH4Authority>,
        revoked: AtomicBool,
    }

    impl VitaH4AuthorityPort for H6ProcessRevokingAuthority {
        fn evaluate(&self, request: H4AuthorityRequest) -> VitaH4AuthorityFuture {
            let inner = Arc::clone(&self.inner);
            if request.is_revalidation() && !self.revoked.swap(true, Ordering::AcqRel) {
                Box::pin(async move {
                    let inner_for_disable = Arc::clone(&inner);
                    tokio::task::spawn_blocking(move || {
                        inner_for_disable.disable_authorization_for_test(H4_REVISION)
                    })
                    .await
                    .map_err(|_| VitaH4AuthorityError::Unavailable)?
                    .map_err(|_| VitaH4AuthorityError::Unavailable)?;
                    inner.evaluate(request).await
                })
            } else {
                inner.evaluate(request)
            }
        }
    }

    #[tokio::test]
    async fn h6_real_sqlite_rev2_to_rev3_final_fence_mutates_zero() {
        let workspace = H6WorkspaceFixture::new(ORIGINAL.as_bytes());
        let authority = ProcessIsolatedH4Authority::new(workspace.root.identity())
            .expect("H6 ProcessIsolated H4 authority");
        let revoking = Arc::new(H6ProcessRevokingAuthority {
            inner: Arc::clone(&authority),
            revoked: AtomicBool::new(false),
        });
        let context = VitaExecutionContext::try_new(LIFE_ID, TASK_ID).unwrap();
        let broker = VitaWorkspaceReplaceBroker::new(
            context,
            workspace.root.clone(),
            Arc::clone(&revoking) as Arc<dyn VitaH4AuthorityPort>,
        );
        let request = H6PatchRequest::synthetic(
            CALL_ID,
            "turn-d29h6-revocation",
            RELATIVE_PATH,
            &sha256_hex(ORIGINAL.as_bytes()),
            &[("old-first", "new-first")],
        );
        let patch = match compile_patch(
            request,
            &VitaExecutionContext::try_new(LIFE_ID, TASK_ID).unwrap(),
            &workspace.root,
        )
        .unwrap()
        {
            H6CompileOutcome::Compiled(patch) => patch,
            H6CompileOutcome::NoEffect => panic!("H6 revocation patch must be effective"),
        };
        let (bridge, mut receiver) = H6PendingConfirmationBridge::new();
        let task = tokio::spawn({
            let broker = Arc::clone(&broker);
            let store = workspace.store.clone();
            let bridge = Arc::clone(&bridge);
            async move { execute_compiled_patch(&broker, store, &bridge, patch, false).await }
        });
        let pending = receiver.recv().await.expect("H6 revocation intent");
        authority
            .provision_confirmation(&pending.intent)
            .expect("H6 revocation trusted confirmation");
        pending.response.send(()).unwrap();
        assert_eq!(task.await.unwrap(), h6_denied_value());
        assert_eq!(
            fs::read(workspace.file_path()).unwrap(),
            ORIGINAL.as_bytes()
        );
        let scan = workspace.store.scan_transactions().unwrap();
        assert_eq!(scan.valid_transactions().count(), 1);
        assert_eq!(
            scan.valid_transactions().next().unwrap().state(),
            RecoveryTransactionState::PreparedOnly
        );
        assert_eq!(broker.snapshot().filesystem_mutation_attempts, 0);
        assert!(authority.shutdown());
    }

    #[derive(Clone, Debug, Default)]
    struct H6FixtureObservation {
        request_count: usize,
        first_request_schema_exact: bool,
        initial_turn_id: Option<String>,
        function_call_output: Option<Value>,
        output_has_authority_facts: bool,
        error: Option<String>,
    }

    #[derive(Default)]
    struct H6GateState {
        initial_turn_id: Option<String>,
        released: bool,
        error: Option<String>,
    }

    struct H6Gate {
        state: Mutex<H6GateState>,
        changed: Condvar,
    }

    impl H6Gate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(H6GateState::default()),
                changed: Condvar::new(),
            })
        }

        fn capture_turn_id(&self, body: &[u8]) -> Result<(), String> {
            let turn_id = extract_h6_turn_id(body)
                .ok_or_else(|| "D29-H6 fixture request omitted client turn_id".to_string());
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match turn_id {
                Ok(turn_id) => {
                    state.initial_turn_id = Some(turn_id);
                    self.changed.notify_all();
                    Ok(())
                }
                Err(error) => {
                    state.error = Some(error.clone());
                    self.changed.notify_all();
                    Err(error)
                }
            }
        }

        fn wait_for_turn_id(&self) -> Result<String, String> {
            let deadline = Instant::now() + TURN_TIMEOUT;
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            loop {
                if let Some(error) = state.error.clone() {
                    return Err(error);
                }
                if let Some(turn_id) = state.initial_turn_id.clone() {
                    return Ok(turn_id);
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err("D29-H6 fixture turn-id wait timed out".to_string());
                }
                let (next, timeout) = self
                    .changed
                    .wait_timeout(state, remaining)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state = next;
                if timeout.timed_out() {
                    return Err("D29-H6 fixture turn-id wait timed out".to_string());
                }
            }
        }

        fn wait_until_released(&self) -> Result<(), String> {
            let deadline = Instant::now() + TURN_TIMEOUT;
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !state.released {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err("D29-H6 fixture release wait timed out".to_string());
                }
                let (next, timeout) = self
                    .changed
                    .wait_timeout(state, remaining)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state = next;
                if timeout.timed_out() && !state.released {
                    return Err("D29-H6 fixture release wait timed out".to_string());
                }
            }
            Ok(())
        }

        fn release(&self) {
            self.state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .released = true;
            self.changed.notify_all();
        }
    }

    struct H6ResponsesFixture {
        address: SocketAddr,
        stop: Arc<AtomicBool>,
        observation: Arc<Mutex<H6FixtureObservation>>,
        gate: Arc<H6Gate>,
        join: Option<JoinHandle<()>>,
    }

    impl H6ResponsesFixture {
        fn start() -> Self {
            Self::start_with_edits(
                ORIGINAL,
                &[("old-first", "new-first"), ("old-second", "new-second")],
            )
        }

        fn start_crash() -> Self {
            Self::start_with_edits(CRASH_ORIGINAL, &[(CRASH_ORIGINAL, CRASH_REPLACEMENT)])
        }

        fn start_with_edits(original: &str, edits: &[(&str, &str)]) -> Self {
            let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind D29-H6 fixture");
            let address = listener.local_addr().expect("read D29-H6 fixture address");
            let stop = Arc::new(AtomicBool::new(false));
            let observation = Arc::new(Mutex::new(H6FixtureObservation::default()));
            let gate = H6Gate::new();
            let stop_for_thread = Arc::clone(&stop);
            let observation_for_thread = Arc::clone(&observation);
            let gate_for_thread = Arc::clone(&gate);
            let original_for_thread = original.to_string();
            let edits_for_thread = edits
                .iter()
                .map(|(search, replace)| ((*search).to_string(), (*replace).to_string()))
                .collect::<Vec<_>>();
            let join = thread::spawn(move || {
                let mut request_index = 0usize;
                while !stop_for_thread.load(Ordering::Acquire) && request_index < 2 {
                    let (mut stream, peer) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(error) => {
                            observation_for_thread
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner)
                                .error = Some(error.to_string());
                            return;
                        }
                    };
                    if stop_for_thread.load(Ordering::Acquire) {
                        break;
                    }
                    let result = handle_h6_fixture_request(
                        &mut stream,
                        peer,
                        request_index,
                        &gate_for_thread,
                        &original_for_thread,
                        &edits_for_thread,
                    );
                    let mut observed = observation_for_thread
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    observed.request_count += 1;
                    if let Ok(body) = &result {
                        if request_index == 0 {
                            observed.first_request_schema_exact = exact_h6_patch_tool_schema(body);
                            observed.initial_turn_id = extract_h6_turn_id(body);
                        } else {
                            observed.function_call_output = h6_function_call_output(body, CALL_ID);
                            observed.output_has_authority_facts = observed
                                .function_call_output
                                .as_ref()
                                .is_some_and(h6_output_has_authority_facts);
                        }
                    }
                    if let Err(error) = result {
                        observed.error = Some(error);
                    }
                    request_index += 1;
                }
            });
            Self {
                address,
                stop,
                observation,
                gate,
                join: Some(join),
            }
        }

        fn base_url(&self) -> String {
            format!("http://127.0.0.1:{}/v1", self.address.port())
        }

        async fn wait_for_turn_id(&self) -> Result<String, String> {
            let gate = Arc::clone(&self.gate);
            tokio::task::spawn_blocking(move || gate.wait_for_turn_id())
                .await
                .map_err(|_| "D29-H6 turn-id wait task failed".to_string())?
        }

        fn release(&self) {
            self.gate.release();
        }

        fn shutdown(mut self) -> (H6FixtureObservation, bool) {
            self.stop.store(true, Ordering::Release);
            self.gate.release();
            let _ = TcpStream::connect(self.address);
            let joined = self
                .join
                .take()
                .map(|join| join.join().is_ok())
                .unwrap_or(true);
            let observation = self
                .observation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            (observation, joined)
        }
    }

    impl Drop for H6ResponsesFixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            self.gate.release();
            let _ = TcpStream::connect(self.address);
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    fn handle_h6_fixture_request(
        stream: &mut TcpStream,
        peer: SocketAddr,
        request_index: usize,
        gate: &H6Gate,
        original: &str,
        edits: &[(String, String)],
    ) -> Result<Vec<u8>, String> {
        if !peer.ip().is_loopback() {
            return Err("D29-H6 fixture received a non-loopback peer".to_string());
        }
        let body = read_h6_http_request(stream)?;
        if request_index == 0 {
            gate.capture_turn_id(&body)?;
            gate.wait_until_released()?;
            write_h6_sse_response(stream, h6_first_response_events(original, edits))?;
        } else if request_index == 1 {
            write_h6_sse_response(stream, h6_completion_response_events())?;
        } else {
            return Err("D29-H6 fixture received too many requests".to_string());
        }
        Ok(body)
    }

    fn h6_first_response_events(original: &str, edits: &[(String, String)]) -> Vec<Value> {
        let arguments = serde_json::to_string(&json!({
            "relative_path": RELATIVE_PATH,
            "expected_sha256": sha256_hex(original.as_bytes()),
            "edits": edits
                .iter()
                .map(|(search, replace)| json!({"search": search, "replace": replace}))
                .collect::<Vec<_>>(),
        }))
        .expect("D29-H6 function arguments serialize");
        vec![
            json!({
                "type": "response.created",
                "response": {"id": "resp-d29h6-1", "object": "response", "status": "in_progress", "model": MODEL}
            }),
            json!({
                "type": "response.output_item.done",
                "item": {"type": "function_call", "call_id": CALL_ID, "name": VITA_WORKSPACE_PATCH_TOOL_NAME, "arguments": arguments}
            }),
            json!({
                "type": "response.completed",
                "response": {"id": "resp-d29h6-1", "object": "response", "status": "completed", "model": MODEL}
            }),
        ]
    }

    fn h6_completion_response_events() -> Vec<Value> {
        vec![
            json!({
                "type": "response.created",
                "response": {"id": "resp-d29h6-2", "object": "response", "status": "in_progress", "model": MODEL}
            }),
            json!({
                "type": "response.output_item.added",
                "item": {"type": "message", "id": "msg-d29h6", "role": "assistant", "status": "in_progress", "content": []}
            }),
            json!({"type": "response.content_part.added"}),
            json!({"type": "response.output_text.delta", "delta": REPLY}),
            json!({"type": "response.output_text.done", "text": REPLY}),
            json!({"type": "response.content_part.done"}),
            json!({
                "type": "response.output_item.done",
                "item": {"type": "message", "id": "msg-d29h6", "role": "assistant", "status": "completed", "content": [{"type": "output_text", "text": REPLY}]}
            }),
            json!({
                "type": "response.completed",
                "response": {"id": "resp-d29h6-2", "object": "response", "status": "completed", "model": MODEL}
            }),
        ]
    }

    fn write_h6_sse_response(stream: &mut TcpStream, events: Vec<Value>) -> Result<(), String> {
        let mut body = String::new();
        for event in events {
            let event_type = event
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| "D29-H6 fixture event omitted type".to_string())?;
            body.push_str("event: ");
            body.push_str(event_type);
            body.push_str("\ndata: ");
            body.push_str(
                &serde_json::to_string(&event)
                    .map_err(|_| "D29-H6 fixture event serialization failed".to_string())?,
            );
            body.push_str("\n\n");
        }
        let header = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream
            .set_write_timeout(Some(HTTP_TIMEOUT))
            .map_err(|_| "D29-H6 fixture write timeout setup failed".to_string())?;
        stream
            .write_all(header.as_bytes())
            .and_then(|_| stream.write_all(body.as_bytes()))
            .map_err(|_| "D29-H6 fixture response write failed".to_string())
    }

    fn read_h6_http_request(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
        stream
            .set_read_timeout(Some(HTTP_TIMEOUT))
            .map_err(|_| "D29-H6 fixture read timeout setup failed".to_string())?;
        let mut bytes = Vec::new();
        let mut chunk = [0_u8; 8192];
        let header_end = loop {
            let read = stream
                .read(&mut chunk)
                .map_err(|_| "D29-H6 fixture request read failed".to_string())?;
            if read == 0 {
                return Err("D29-H6 fixture request closed before headers".to_string());
            }
            bytes.extend_from_slice(&chunk[..read]);
            if bytes.len() > HTTP_MAX_BODY {
                return Err("D29-H6 fixture request exceeded bound".to_string());
            }
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let headers = String::from_utf8(bytes[..header_end].to_vec())
            .map_err(|_| "D29-H6 fixture headers were not UTF-8".to_string())?;
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .ok_or_else(|| "D29-H6 fixture request omitted content length".to_string())?;
        if content_length > HTTP_MAX_BODY || header_end + content_length > HTTP_MAX_BODY {
            return Err("D29-H6 fixture content length exceeded bound".to_string());
        }
        while bytes.len() < header_end + content_length {
            let read = stream
                .read(&mut chunk)
                .map_err(|_| "D29-H6 fixture body read failed".to_string())?;
            if read == 0 {
                return Err("D29-H6 fixture request closed before body".to_string());
            }
            bytes.extend_from_slice(&chunk[..read]);
            if bytes.len() > HTTP_MAX_BODY {
                return Err("D29-H6 fixture body exceeded bound".to_string());
            }
        }
        Ok(bytes[header_end..header_end + content_length].to_vec())
    }

    fn extract_h6_turn_id(body: &[u8]) -> Option<String> {
        serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| value.get("client_metadata").cloned())
            .and_then(|value| value.get("turn_id").cloned())
            .and_then(|value| value.as_str().map(str::to_owned))
    }

    fn h6_function_call_output(body: &[u8], call_id: &str) -> Option<Value> {
        serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| value.get("input").cloned())
            .and_then(|value| value.as_array().cloned())
            .and_then(|items| {
                items.into_iter().find_map(|item| {
                    (item.get("type").and_then(Value::as_str) == Some("function_call_output")
                        && item.get("call_id").and_then(Value::as_str) == Some(call_id))
                    .then(|| item.get("output").and_then(Value::as_str))
                    .flatten()
                    .and_then(|output| serde_json::from_str::<Value>(output).ok())
                })
            })
    }

    fn exact_h6_patch_tool_schema(body: &[u8]) -> bool {
        let Some(tool) = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|value| value.get("tools").cloned())
            .and_then(|value| value.as_array().cloned())
            .and_then(|tools| {
                tools.into_iter().find(|tool| {
                    tool.get("name").and_then(Value::as_str) == Some(VITA_WORKSPACE_PATCH_TOOL_NAME)
                })
            })
        else {
            return false;
        };
        let parameters = tool.get("parameters").or_else(|| {
            tool.get("function")
                .and_then(|function| function.get("parameters"))
        });
        let Some(parameters) = parameters else {
            return false;
        };
        let Some(properties) = parameters.get("properties").and_then(Value::as_object) else {
            return false;
        };
        let property_names = properties.keys().cloned().collect::<BTreeSet<_>>();
        let required = parameters
            .get("required")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
            });
        let Some(edits) = properties.get("edits") else {
            return false;
        };
        let Some(item) = edits.get("items") else {
            return false;
        };
        let Some(item_properties) = item.get("properties").and_then(Value::as_object) else {
            return false;
        };
        let item_property_names = item_properties.keys().cloned().collect::<BTreeSet<_>>();
        let item_required = item
            .get("required")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>()
            });
        property_names
            == BTreeSet::from([
                "edits".to_string(),
                "expected_sha256".to_string(),
                "relative_path".to_string(),
            ])
            && required == Some(property_names.clone())
            && parameters
                .get("additionalProperties")
                .and_then(Value::as_bool)
                == Some(false)
            && tool.get("strict").and_then(Value::as_bool) == Some(true)
            && properties
                .get("relative_path")
                .and_then(|value| value.get("type"))
                .and_then(Value::as_str)
                == Some("string")
            && properties
                .get("expected_sha256")
                .and_then(|value| value.get("type"))
                .and_then(Value::as_str)
                == Some("string")
            && edits.get("type").and_then(Value::as_str) == Some("array")
            && item.get("type").and_then(Value::as_str) == Some("object")
            && item_property_names == BTreeSet::from(["replace".to_string(), "search".to_string()])
            && item_required == Some(item_property_names)
            && item.get("additionalProperties").and_then(Value::as_bool) == Some(false)
            && item_properties
                .get("search")
                .and_then(|value| value.get("type"))
                .and_then(Value::as_str)
                == Some("string")
            && item_properties
                .get("replace")
                .and_then(|value| value.get("type"))
                .and_then(Value::as_str)
                == Some("string")
            && !h6_output_has_authority_facts(&tool)
    }

    fn h6_output_has_authority_facts(value: &Value) -> bool {
        const FORBIDDEN: &[&str] = &[
            "grant_id",
            "confirmation_id",
            "authorization_revision",
            "workspace_root_identity",
            "target_identity",
            "journal_integrity_hash",
            "transaction_id",
            "recovery_namespace_path",
            "raw_handle",
            "credentials",
            "raw_preimage",
            "full_recovery_path",
            "replacement_content",
        ];
        match value {
            Value::Object(object) => object.iter().any(|(key, value)| {
                FORBIDDEN.contains(&key.as_str()) || h6_output_has_authority_facts(value)
            }),
            Value::Array(values) => values.iter().any(h6_output_has_authority_facts),
            _ => false,
        }
    }

    #[test]
    fn h6_patch_schema_contract_is_exact() {
        let schema = h6_patch_schema_contract();
        assert_eq!(schema.get("type").and_then(Value::as_str), Some("object"));
        assert_eq!(
            schema.get("additionalProperties").and_then(Value::as_bool),
            Some(false)
        );
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .expect("H6 schema properties");
        assert_eq!(
            properties.keys().cloned().collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "edits".to_string(),
                "expected_sha256".to_string(),
                "relative_path".to_string(),
            ])
        );
        assert_eq!(
            schema
                .get("required")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["edits", "expected_sha256", "relative_path"])
        );
        assert_eq!(
            properties["relative_path"]
                .get("type")
                .and_then(Value::as_str),
            Some("string")
        );
        assert_eq!(
            properties["expected_sha256"]
                .get("type")
                .and_then(Value::as_str),
            Some("string")
        );
        assert_eq!(
            properties["expected_sha256"]
                .get("pattern")
                .and_then(Value::as_str),
            Some("^[a-f0-9]{64}$")
        );
        let edits = &properties["edits"];
        assert_eq!(edits.get("type").and_then(Value::as_str), Some("array"));
        assert_eq!(edits.get("minItems").and_then(Value::as_u64), Some(1));
        assert_eq!(edits.get("maxItems").and_then(Value::as_u64), Some(16));
        let item = edits.get("items").expect("H6 edit item schema");
        assert_eq!(item.get("type").and_then(Value::as_str), Some("object"));
        assert_eq!(
            item.get("additionalProperties").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            item.get("properties")
                .and_then(Value::as_object)
                .unwrap()
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["replace".to_string(), "search".to_string()])
        );
        assert_eq!(
            item["properties"]["search"]
                .get("type")
                .and_then(Value::as_str),
            Some("string")
        );
        assert_eq!(
            item["properties"]["search"]
                .get("minLength")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            item["properties"]["replace"]
                .get("type")
                .and_then(Value::as_str),
            Some("string")
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum H6ShutdownStatus {
        NotAttempted,
        Success,
        TimedOut,
        Failed,
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct H6CleanupEvidence {
        initial_shutdown: H6ShutdownStatus,
        final_shutdown: H6ShutdownStatus,
        manager_thread_count: usize,
        fixture_listener_joined: bool,
    }

    struct H6Runtime {
        manager: Arc<ThreadManager>,
        thread: Option<Arc<codex_core_api::CodexThread>>,
        thread_id: Option<ThreadId>,
        fixture: Option<H6ResponsesFixture>,
        patch_tool_call_count: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl H6Runtime {
        async fn shutdown(mut self) -> (H6CleanupEvidence, H6FixtureObservation, usize) {
            let mut initial_shutdown = H6ShutdownStatus::NotAttempted;
            let mut final_shutdown = H6ShutdownStatus::NotAttempted;
            if let Some(thread) = self.thread.take() {
                initial_shutdown =
                    match tokio::time::timeout(CLEANUP_TIMEOUT, thread.shutdown_and_wait()).await {
                        Ok(Ok(())) => H6ShutdownStatus::Success,
                        Ok(Err(_)) => H6ShutdownStatus::Failed,
                        Err(_) => H6ShutdownStatus::TimedOut,
                    };
                if initial_shutdown != H6ShutdownStatus::Success {
                    let _ =
                        tokio::time::timeout(CLEANUP_TIMEOUT, thread.submit(Op::Interrupt)).await;
                }
                final_shutdown =
                    match tokio::time::timeout(CLEANUP_TIMEOUT, thread.shutdown_and_wait()).await {
                        Ok(Ok(())) => H6ShutdownStatus::Success,
                        Ok(Err(_)) => H6ShutdownStatus::Failed,
                        Err(_) => H6ShutdownStatus::TimedOut,
                    };
                if final_shutdown == H6ShutdownStatus::Success {
                    if let Some(thread_id) = self.thread_id.as_ref() {
                        let _ = self
                            .manager
                            .remove_thread_if_matches(thread_id, &thread)
                            .await;
                    }
                }
            }
            let manager_thread_count = self.manager.list_thread_ids().await.len();
            let (observation, fixture_listener_joined) = self
                .fixture
                .take()
                .map(H6ResponsesFixture::shutdown)
                .unwrap_or_else(|| (H6FixtureObservation::default(), true));
            (
                H6CleanupEvidence {
                    initial_shutdown,
                    final_shutdown,
                    manager_thread_count,
                    fixture_listener_joined,
                },
                observation,
                self.patch_tool_call_count.load(Ordering::Acquire),
            )
        }
    }

    async fn start_h6_runtime(
        app_data_root: PathBuf,
        workspace_root: PathBuf,
        authority: Arc<dyn VitaH4AuthorityPort>,
        fixture: H6ResponsesFixture,
        bridge: Arc<H6PendingConfirmationBridge>,
        tamper_replacement: bool,
    ) -> Result<
        (
            H6Runtime,
            Arc<VitaWorkspaceReplaceBroker>,
            RecoveryJournalStore,
        ),
        String,
    > {
        let profile =
            VitaAgentRuntimeProfile::from_explicit_app_data_root(app_data_root, workspace_root)
                .map_err(|error| format!("create D29-H6 profile: {error}"))?;
        let provider = ProviderProfile::new_for_test_localhost(
            PROVIDER_ID,
            "D29-H6 local Responses fixture",
            ProviderProtocol::OpenAiResponses,
            fixture.base_url(),
            MODEL,
            None,
            HTTP_TIMEOUT,
            ProviderRetryPolicy::default(),
            ProviderCapabilities {
                tools: true,
                ..ProviderCapabilities::none()
            },
        )
        .map_err(|error| format!("create D29-H6 provider: {error}"))?;
        let provider_authority = VitaProviderAuthority::configure(provider)
            .map_err(|error| format!("configure D29-H6 provider: {error}"))?;
        let binding = VitaGatewayBinding::for_owned_private_listener(fixture.address.port())
            .map_err(|error| format!("create D29-H6 gateway binding: {error}"))?;
        let ready = provider_authority
            .prepare_gateway(binding)
            .map_err(|error| format!("prepare D29-H6 gateway: {error}"))?;
        let entrypoint = VitaAgentEntrypoint::initialize_with_gateway_for_tests(profile, &ready)
            .await
            .map_err(|error| format!("initialize D29-H6 Codex config: {error}"))?;
        let config = entrypoint.config().clone();
        let profile = entrypoint.profile().clone();
        let root = profile
            .workspace_authority()
            .cloned()
            .ok_or_else(|| "D29-H6 requires Windows workspace authority".to_string())?;
        let store = RecoveryJournalStore::from_runtime_profile(&profile)
            .map_err(|error| format!("create D29-H6 recovery store: {error}"))?;
        let context = VitaExecutionContext::try_new(LIFE_ID, TASK_ID)
            .map_err(|error| format!("create D29-H6 context: {error:?}"))?;
        let broker = VitaWorkspaceReplaceBroker::new(context.clone(), root.clone(), authority);
        let patch_tool_call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let contributor = VitaWorkspacePatchToolContributor::new(
            Arc::clone(&broker),
            root,
            context,
            store.clone(),
            bridge,
        )
        .with_tool_call_count(Arc::clone(&patch_tool_call_count));
        let contributor = if tamper_replacement {
            contributor.with_tamper_replacement()
        } else {
            contributor
        };
        let mut extensions =
            codex_core_api::ExtensionRegistryBuilder::<codex_core::config::Config>::new();
        extensions.tool_contributor(Arc::new(contributor));
        let extensions = Arc::new(extensions.build());
        let auth_manager = codex_core::test_support::auth_manager_from_auth_with_home(
            CodexAuth::from_api_key("d29h6-in-memory-kernel-auth"),
            config.codex_home.to_path_buf(),
        );
        let manager = Arc::new(ThreadManager::new(
            &config,
            Arc::clone(&auth_manager),
            codex_core_api::build_models_manager(&config, Arc::clone(&auth_manager)),
            CodexAppsToolsCache::default(),
            SessionSource::Exec,
            Arc::new(EnvironmentManager::default_for_tests()),
            extensions,
            Arc::new(codex_core::test_support::EmptyUserInstructionsProvider),
            None,
            codex_core_api::thread_store_from_config(&config, None),
            None,
            "d29h6-local-installation".to_string(),
            None,
            None,
        ));
        let new_thread = tokio::time::timeout(
            TURN_TIMEOUT,
            manager.start_thread(StartThreadOptions::new(config)),
        )
        .await
        .map_err(|_| "D29-H6 thread startup timed out".to_string())?
        .map_err(|error| format!("D29-H6 thread startup failed: {error}"))?;
        Ok((
            H6Runtime {
                manager,
                thread: Some(new_thread.thread),
                thread_id: Some(new_thread.thread_id),
                fixture: Some(fixture),
                patch_tool_call_count,
            },
            broker,
            store,
        ))
    }

    async fn start_h6_turn(thread: &Arc<codex_core_api::CodexThread>) -> Result<String, String> {
        let submission = tokio::time::timeout(
            TURN_TIMEOUT,
            thread.start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
                text: PROMPT.to_string(),
                text_elements: Vec::new(),
            }])),
        )
        .await
        .map_err(|_| "D29-H6 turn submission timed out".to_string())?
        .map_err(|error| format!("D29-H6 turn submission failed: {error}"))?;
        match submission {
            TurnInputSubmission::Started { turn_id } | TurnInputSubmission::Steered { turn_id } => {
                Ok(turn_id)
            }
            TurnInputSubmission::NotSubmitted { reason } => {
                Err(format!("D29-H6 turn was not submitted: {reason:?}"))
            }
        }
    }

    async fn wait_h6_turn(
        thread: &Arc<codex_core_api::CodexThread>,
    ) -> Result<(Option<String>, Option<String>, usize), String> {
        let deadline = Instant::now() + TURN_TIMEOUT;
        let mut event_count = 0usize;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("D29-H6 turn did not reach terminal event".to_string());
            }
            let event = tokio::time::timeout(remaining, thread.next_event())
                .await
                .map_err(|_| "D29-H6 event wait timed out".to_string())?
                .map_err(|error| format!("D29-H6 event stream failed: {error}"))?;
            event_count += 1;
            if let EventMsg::TurnComplete(complete) = event.msg {
                return Ok((
                    complete.last_agent_message,
                    complete.error.map(|error| error.message),
                    event_count,
                ));
            }
        }
    }

    fn run_h6_test_body<F>(body: F)
    where
        F: FnOnce() + Send + 'static,
    {
        thread::Builder::new()
            .name("d29h6-real-codex".to_string())
            .stack_size(TEST_STACK_SIZE)
            .spawn(body)
            .expect("D29-H6 test thread should start")
            .join()
            .expect("D29-H6 test thread should finish");
    }

    async fn real_codex_h6_positive_body() {
        let app_data = tempdir().expect("D29-H6 app-data temp root");
        let workspace = tempdir().expect("D29-H6 workspace temp root");
        let file_path = workspace.path().join(RELATIVE_PATH);
        fs::write(&file_path, ORIGINAL.as_bytes()).expect("D29-H6 original file write");
        let root = TrustedWorkspaceRoot::acquire(workspace.path())
            .expect("D29-H6 workspace root acquisition");
        let authority = ProcessIsolatedH4Authority::new(root.identity())
            .expect("D29-H6 ProcessIsolated H4 authority");
        drop(root);
        let fixture = H6ResponsesFixture::start();
        let (bridge, mut receiver) = H6PendingConfirmationBridge::new();
        let (runtime, broker, store) = start_h6_runtime(
            app_data.path().to_path_buf(),
            workspace.path().to_path_buf(),
            Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>,
            fixture,
            bridge,
            false,
        )
        .await
        .expect("D29-H6 runtime should start");
        let turn_id = start_h6_turn(runtime.thread.as_ref().unwrap())
            .await
            .expect("D29-H6 canary turn should start");
        let observed_turn_id = runtime
            .fixture
            .as_ref()
            .unwrap()
            .wait_for_turn_id()
            .await
            .expect("D29-H6 fixture should expose turn id");
        assert_eq!(observed_turn_id, turn_id);
        runtime.fixture.as_ref().unwrap().release();
        let pending = tokio::time::timeout(TURN_TIMEOUT, receiver.recv())
            .await
            .expect("D29-H6 pending confirmation wait")
            .expect("D29-H6 pending confirmation intent");
        authority
            .provision_confirmation(&pending.intent)
            .expect("D29-H6 trusted H4 confirmation");
        pending
            .response
            .send(())
            .expect("D29-H6 confirmation response");
        let turn = wait_h6_turn(runtime.thread.as_ref().unwrap())
            .await
            .expect("D29-H6 canary turn should complete");
        let (cleanup, observation, patch_tool_calls) = runtime.shutdown().await;
        assert!(authority.shutdown());

        assert_eq!(turn.1, None, "D29-H6 real Codex turn error");
        assert_eq!(turn.0.as_deref(), Some(REPLY));
        assert_eq!(
            fs::read(&file_path).unwrap(),
            b"first=new-first\nsecond=new-second\n"
        );
        assert_eq!(observation.request_count, 2);
        assert!(observation.first_request_schema_exact);
        assert_eq!(
            observation.initial_turn_id.as_deref(),
            Some(turn_id.as_str())
        );
        let output = observation
            .function_call_output
            .as_ref()
            .expect("D29-H6 function_call_output");
        assert_eq!(
            output.get("status").and_then(Value::as_str),
            Some("patch_applied")
        );
        assert_eq!(
            output.get("mutation_performed").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            output.get("side_effect_count").and_then(Value::as_u64),
            Some(1)
        );
        assert!(!observation.output_has_authority_facts);
        assert!(
            observation.error.is_none(),
            "fixture error: {:?}",
            observation.error
        );
        assert_eq!(patch_tool_calls, 1, "one actual H6 patch ToolCall");
        assert_eq!(cleanup.initial_shutdown, H6ShutdownStatus::Success);
        assert_eq!(cleanup.final_shutdown, H6ShutdownStatus::Success);
        assert_eq!(cleanup.manager_thread_count, 0);
        assert!(cleanup.fixture_listener_joined);

        let scan = store.scan_transactions().expect("scan D29-H6 journal");
        assert_eq!(scan.valid_transactions().count(), 1);
        assert_eq!(
            scan.valid_transactions().next().unwrap().state(),
            RecoveryTransactionState::CommittedTerminal
        );
        let snapshot = broker.snapshot();
        assert_eq!(snapshot.grants_issued, 1);
        assert_eq!(snapshot.confirmations_consumed, 1);
        assert_eq!(snapshot.automatic_mutation_retries, 0);
        assert_eq!(snapshot.external_network_requests, 0);
        assert_eq!(authority.observation_count(), 2);
        let provenance = authority.provenance_snapshot();
        assert_eq!(provenance.trusted_confirmations_provisioned, 1);
        assert_eq!(provenance.request_derived_confirmations, 0);
    }

    #[test]
    fn real_codex_h6_patch_committed_canary() {
        run_h6_test_body(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-H6 real Codex runtime");
            runtime.block_on(real_codex_h6_positive_body());
        });
    }

    #[test]
    fn real_codex_h6_output_has_no_authority_facts() {
        run_h6_test_body(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-H6 output runtime");
            runtime.block_on(real_codex_h6_positive_body());
        });
    }

    #[test]
    fn h6_crash_child_entrypoint() {
        if std::env::var_os("D29_H6_CRASH_POINT").is_none() {
            return;
        }
        run_h6_test_body(|| {
            let app_data = PathBuf::from(
                std::env::var_os("D29_H6_CRASH_APP_DATA").expect("D29-H6 child app-data root"),
            );
            let workspace = PathBuf::from(
                std::env::var_os("D29_H6_CRASH_WORKSPACE").expect("D29-H6 child workspace root"),
            );
            fs::write(workspace.join(RELATIVE_PATH), CRASH_ORIGINAL.as_bytes())
                .expect("D29-H6 child original file");
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("D29-H6 child runtime");
            runtime.block_on(async move {
                let root =
                    TrustedWorkspaceRoot::acquire(&workspace).expect("D29-H6 child workspace root");
                let authority = TestHostAuthority::new(root.identity());
                drop(root);
                let fixture = H6ResponsesFixture::start_crash();
                let (bridge, mut receiver) = H6PendingConfirmationBridge::new();
                let (runtime, _broker, _store) = start_h6_runtime(
                    app_data,
                    workspace,
                    Arc::clone(&authority) as Arc<dyn VitaH4AuthorityPort>,
                    fixture,
                    bridge,
                    false,
                )
                .await
                .expect("D29-H6 child runtime setup");
                let turn_id = start_h6_turn(runtime.thread.as_ref().unwrap())
                    .await
                    .expect("D29-H6 child turn");
                let observed_turn_id = runtime
                    .fixture
                    .as_ref()
                    .unwrap()
                    .wait_for_turn_id()
                    .await
                    .expect("D29-H6 child fixture turn id");
                assert_eq!(observed_turn_id, turn_id);
                runtime.fixture.as_ref().unwrap().release();
                let pending = tokio::time::timeout(TURN_TIMEOUT, receiver.recv())
                    .await
                    .expect("D29-H6 child pending confirmation wait")
                    .expect("D29-H6 child pending confirmation");
                authority.provision_trusted_confirmation(&pending.intent);
                pending
                    .response
                    .send(())
                    .expect("D29-H6 child confirmation response");
                let _ = wait_h6_turn(runtime.thread.as_ref().unwrap()).await;
                panic!("D29-H6 child must abort at H5 first mutation");
            });
        });
    }

    fn restart_h6_profile_and_store(
        app_data: &Path,
        workspace: &Path,
    ) -> (
        VitaAgentRuntimeProfile,
        RecoveryJournalStore,
        TrustedWorkspaceRoot,
    ) {
        let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
            app_data.to_path_buf(),
            workspace.to_path_buf(),
        )
        .expect("D29-H6 fresh runtime profile");
        let root = profile
            .workspace_authority()
            .cloned()
            .expect("D29-H6 fresh workspace authority");
        let store = RecoveryJournalStore::from_runtime_profile(&profile)
            .expect("D29-H6 fresh RecoveryJournalStore");
        (profile, store, root)
    }

    #[test]
    fn real_codex_h6_crash_after_first_mutation_fresh_recovery() {
        let app_data = tempdir().expect("D29-H6 crash app-data temp root");
        let workspace = tempdir().expect("D29-H6 crash workspace temp root");
        let status = Command::new(std::env::current_exe().expect("D29-H6 test executable"))
            .args([
                "--exact",
                "d29h6::tests::h6_crash_child_entrypoint",
                "--nocapture",
            ])
            .env("D29_H6_CRASH_POINT", "first-mutation")
            .env("D29_H6_CRASH_APP_DATA", app_data.path())
            .env("D29_H6_CRASH_WORKSPACE", workspace.path())
            .env("D29_H5C_CRASH_POINT", "first-mutation")
            .status()
            .expect("spawn D29-H6 crash child");
        assert!(!status.success(), "D29-H6 first-mutation child must abort");

        let (_profile, store, root) =
            restart_h6_profile_and_store(app_data.path(), workspace.path());
        let file_path = workspace.path().join(RELATIVE_PATH);
        let before_scan = fs::read(&file_path).expect("D29-H6 crash file after restart");
        let scan = store.scan_transactions().expect("D29-H6 restart scan");
        let after_scan = fs::read(&file_path).expect("D29-H6 file after restart scan");
        assert_eq!(
            before_scan, after_scan,
            "D29-H6 restart scan must not mutate workspace"
        );
        let snapshot = scan
            .valid_transactions()
            .next()
            .cloned()
            .expect("D29-H6 crash should leave one valid journal");
        assert_eq!(snapshot.state(), RecoveryTransactionState::RecoveryRequired);
        assert_ne!(before_scan, CRASH_ORIGINAL.as_bytes());
        assert!(std::str::from_utf8(&before_scan).is_err());
        assert_eq!(
            store
                .scan_transactions()
                .unwrap()
                .actionable_recovery_transactions()
                .count(),
            1
        );

        let action = RecoveryActionRequest::from_snapshot(
            &snapshot,
            &before_scan,
            "d29h6-fresh-recovery",
            2,
        );
        let authority = ProcessIsolatedH5RecoveryAuthority::new(root.identity(), LIFE_ID, TASK_ID)
            .expect("D29-H6 fresh ProcessIsolated H5 recovery authority");
        authority
            .provision_trusted_confirmation(&action)
            .expect("D29-H6 fresh recovery confirmation");
        let executor = H5RecoveryExecutor::new(
            store.clone(),
            root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(result.outcome, RecoveryExecutionOutcome::Recovered);
        assert_eq!(result.grant_issued, true);
        assert_eq!(result.mutation_count, 1);
        assert_eq!(result.marker_persisted, true);
        assert_eq!(fs::read(&file_path).unwrap(), CRASH_ORIGINAL.as_bytes());
        let recovered_scan = store.scan_transactions().unwrap();
        assert_eq!(
            recovered_scan.valid_transactions().next().unwrap().state(),
            RecoveryTransactionState::RecoveredTerminal
        );
        assert_eq!(recovered_scan.actionable_recovery_transactions().count(), 0);
        assert_eq!(authority.provenance(), (1, 0));
        assert!(authority.shutdown());
    }
}
